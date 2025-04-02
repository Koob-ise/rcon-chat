import configparser
import socket
import struct
import time
import threading
import disnake
from disnake.ext import commands
from aiogram import Bot, Dispatcher, types
from aiogram import F
import asyncio
import os
import re

config = configparser.ConfigParser()
config.read('config-bot.cfg')

debugging = config.get('DEFAULT', 'debugging')

d = config.getboolean('DEFAULT', 'discord')
dtoken = config.get('DEFAULT', 'discord-token')
dserver_id = int(config.get('DEFAULT', 'discord-server-id'))
dchannel_id = int(config.get('DEFAULT', 'discord-channel-id'))

t = config.getboolean('DEFAULT', 'telegram')
ttoken = config.get('DEFAULT', 'telegram-token')
tchat_id = int(config.get('DEFAULT', 'telegram-channel-id'))

LOG_FILE = config.get('DEFAULT', 'log-file', fallback='logs/latest.log')
log_content = ""
chat_log = []

MESSAGE_COOLDOWN = 1.0
last_discord_msg_time = 0
last_telegram_msg_time = 0

def escape_md(text):
    escape_chars = '_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{char}' if char in escape_chars else char for char in text)

class MinecraftRCON:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password
        self.request_id = 0
        self.socket = None
        self._debug = True

    def _debug_log(self, message):
        if self._debug:
            print(f"[RCON DEBUG] {message}")

    def connect(self):
        try:
            self._debug_log(f"Connecting to {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self._debug_log("Connection established")
            
            if not self.authenticate():
                raise Exception("Authentication failed: Wrong password")
            self._debug_log("Authentication successful")
        except Exception as e:
            self._debug_log(f"Connection error: {e}")
            raise

    def authenticate(self):
        try:
            response_id, response = self.send_packet(3, self.password)
            self._debug_log(f"Auth response: ID={response_id}, Response={response}")
            return response_id != -1
        except Exception as e:
            self._debug_log(f"Auth error: {e}")
            return False

    def send_command(self, command):
        try:
            self._debug_log(f"Sending command: {command}")
            _, response = self.send_packet(2, command)
            self._debug_log(f"Server response: {response}")
            return response
        except Exception as e:
            self._debug_log(f"Command error: {e}")
            return None

    def send_packet(self, packet_type, payload):
        self.request_id += 1
        payload_utf8 = payload.encode('utf-8')
        
        packet = struct.pack(
            '<iii',
            10 + len(payload_utf8),
            self.request_id,
            packet_type
        ) + payload_utf8 + b'\x00\x00'

        self._debug_log(f"Sending packet: ID={self.request_id}, Type={packet_type}, Size={10 + len(payload_utf8)}")
        
        try:
            self.socket.sendall(packet)
        except Exception as e:
            self._debug_log(f"Packet error: {e}")
            raise

        return self._receive_response()

    def _receive_response(self):
        try:
            length_data = self.socket.recv(4)
            if not length_data:
                raise Exception("Empty server response")
            
            length = struct.unpack('<i', length_data)[0]
            self._debug_log(f"Received response length: {length} bytes")

            response_data = b""
            while len(response_data) < length:
                chunk = self.socket.recv(length - len(response_data))
                if not chunk:
                    raise Exception("Connection interrupted")
                response_data += chunk

            response_id, packet_type = struct.unpack('<ii', response_data[:8])
            payload = response_data[8:-2].decode('utf-8', errors='replace')
            
            self._debug_log(f"Full response: ID={response_id}, Type={packet_type}, Data={payload}")
            return response_id, payload
            
        except Exception as e:
            self._debug_log(f"Response error: {e}")
            raise

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
                self._debug_log("Connection closed")
            except:
                pass
            finally:
                self.socket = None

def debug_log_reading():
    try:
        print(f"\n=== Debug: Log check ===")
        print(f"Log file: {LOG_FILE}")
        print(f"File size: {os.path.getsize(LOG_FILE)} bytes")
        print(f"Last 5 lines:")
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines[-5:]:
                print(line.strip())
        
        print("\nSearching for chat messages:")
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f.readlines()[-20:]:
                if '[Server thread/INFO] [minecraft/MinecraftServer]: <' in line:
                    print(line.strip())
        print("============================\n")
    except Exception as e:
        print(f"Log debug error: {e}")

def update_log_content():
    global log_content
    last_size = 0
    while True:
        try:
            current_size = os.path.getsize(LOG_FILE)
            if current_size > last_size:
                with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_size)
                    new_content = f.read(current_size - last_size)
                    last_size = current_size
                    if new_content:
                        process_log_changes(new_content)
            elif current_size < last_size:
                last_size = 0
        except Exception as e:
            print(f'Log read error: {e}')
        time.sleep(0.5)

def process_log_changes(new_content):
    try:
        for line in new_content.splitlines():
            if re.search(r'^\[\d{2}:\d{2}:\d{2}\] \[Server thread/INFO\]: <([^>]+)> (.+)', line):
                try:
                    match = re.search(r'^\[\d{2}:\d{2}:\d{2}\] \[Server thread/INFO\]: <([^>]+)> (.+)', line)
                    username = match.group(1)
                    message = match.group(2).strip()
                    
                    print(f"Found message: {username}: {message}")
                    
                    if d and discord_bot:
                        asyncio.run_coroutine_threadsafe(
                            send_discord_message(f"**{username}**: {message}"),
                            discord_bot.loop
                        )
                        
                    if t and telegram_bot:
                        asyncio.run_coroutine_threadsafe(
                            send_telegram_message(f"{username}: {message}"),
                            telegram_loop
                        )
                except Exception as e:
                    print(f"Parse error: {e}\nLine: {line}")
    except Exception as e:
        print(f'Log processing error: {e}')

if d:
    discord_bot = commands.Bot(command_prefix="!", intents=disnake.Intents.all())

    async def send_discord_message(text):
        global last_discord_msg_time
        
        current_time = time.time()
        if current_time - last_discord_msg_time < MESSAGE_COOLDOWN:
            print(f"[Discord] Cooldown: Too fast! Waiting...")
            await asyncio.sleep(MESSAGE_COOLDOWN - (current_time - last_discord_msg_time))
        
        try:
            guild = discord_bot.get_guild(dserver_id)
            if not guild:
                print(f"Discord server {dserver_id} not found!")
                return
            
            channel = guild.get_channel(dchannel_id)
            if channel:
                await channel.send(text)
                last_discord_msg_time = time.time()  # Обновляем время последнего сообщения
                print(f"Sent to Discord: {text}")
            else:
                print(f"Discord channel {dchannel_id} not found on server {guild.name}")
        except Exception as e:
            print(f"Discord error: {e}")

    @discord_bot.event
    async def on_message(message):
        if message.author == discord_bot.user:
            return
            
        if message.guild and message.guild.id == dserver_id and message.channel.id == dchannel_id:
            try:
                safe_msg = message.content.replace('"', '\\"')
                cmd = f'tellraw @a ["",{{"text":"[Discord] ","color":"blue"}},{{"text":"{message.author.display_name}: {safe_msg}","color":"white"}}]'
                rcon.send_command(cmd)
                
                if t and telegram_bot:
                    asyncio.run_coroutine_threadsafe(
                        send_telegram_message(f"Discord | {message.author.display_name}: {message.content}"),
                        telegram_loop
                    )
            except Exception as e:
                print(f"Discord processing error: {e}")

if t:
    telegram_bot = Bot(token=ttoken)
    dp = Dispatcher()
    telegram_loop = asyncio.new_event_loop()

    async def send_telegram_message(text):
        global last_telegram_msg_time
        
        current_time = time.time()
        if current_time - last_telegram_msg_time < MESSAGE_COOLDOWN:
            print(f"[Telegram] Cooldown: Too fast! Waiting...")
            await asyncio.sleep(MESSAGE_COOLDOWN - (current_time - last_telegram_msg_time))
        
        try:
            await telegram_bot.send_message(
                chat_id=tchat_id,
                text=text,
                parse_mode=None
            )
            last_telegram_msg_time = time.time()  # Обновляем время последнего сообщения
            print(f"Sent to Telegram: {text}")
        except Exception as e:
            print(f"Telegram error: {e}")

    @dp.message(F.chat.id == tchat_id)
    async def handle_telegram_message(message: types.Message):
        try:
            safe_msg = message.text.replace('"', '\\"')
            cmd = f'tellraw @a ["",{{"text":"[Telegram] ","color":"green"}},{{"text":"{message.from_user.username}: {safe_msg}","color":"white"}}]'
            rcon.send_command(cmd)
            
            if d and discord_bot:
                guild = discord_bot.get_guild(dserver_id)
                if guild:
                    channel = guild.get_channel(dchannel_id)
                    if channel:
                        await channel.send(f"**Telegram**: {message.from_user.username}: {message.text}")
        except Exception as e:
            print(f"Telegram processing error: {e}")

    def run_telegram_bot():
        asyncio.set_event_loop(telegram_loop)
        telegram_loop.run_until_complete(dp.start_polling(telegram_bot))

def main():
    if debugging:
        debug_log_reading()
    print("\nConfiguration check:")
    print(f"Discord: {'Enabled' if d else 'Disabled'}")
    print(f"Telegram: {'Enabled' if t else 'Disabled'}")
    print(f"Log path: {LOG_FILE}")
        
    global rcon
    rcon = MinecraftRCON(
        host=config.get('DEFAULT', 'rcon-host'),
        port=int(config.get('DEFAULT', 'rcon-port')),
        password=config.get('DEFAULT', 'rcon-password')
    )
    rcon.connect()

    log_thread = threading.Thread(target=update_log_content, daemon=True)
    log_thread.start()

    try:
        if d:
            discord_thread = threading.Thread(
                target=discord_bot.run,
                args=(dtoken,),
                daemon=True
            )
            discord_thread.start()
        
        if t:
            telegram_thread = threading.Thread(
                target=run_telegram_bot,
                daemon=True
            )
            telegram_thread.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        rcon.disconnect()

if __name__ == "__main__":
    main()
