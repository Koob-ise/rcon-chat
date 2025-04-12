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
import signal
from functools import wraps

config = configparser.ConfigParser()
try:
    with open('config-bot.cfg', 'r', encoding='utf-8') as f:
        config.read_file(f)
except Exception as e:
    print(f"Error reading config file: {e}")
    exit(1)

DEBUG_LEVEL = config.getint('DEFAULT', 'debug_level', fallback=1)
LOG_FORMAT = config.get('DEFAULT', 'log_format', fallback='[{time}] [{thread}/INFO]: {message}')
CHAT_FORMAT = config.get('DEFAULT', 'chat_format', fallback='<{username}> {message}')
JOIN_FORMAT = config.get('DEFAULT', 'join_format', fallback='{username} joined the game')
LEAVE_FORMAT = config.get('DEFAULT', 'leave_format', fallback='{username} left the game')
MESSAGE_COOLDOWN = config.getfloat('DEFAULT', 'message_cooldown', fallback=5.0)

d = config.getboolean('DEFAULT', 'discord')
dtoken = config.get('DEFAULT', 'discord-token')
dserver_id = int(config.get('DEFAULT', 'discord-server-id'))
dchannel_id = int(config.get('DEFAULT', 'discord-channel-id'))

t = config.getboolean('DEFAULT', 'telegram')
ttoken = config.get('DEFAULT', 'telegram-token')
tchat_id = int(config.get('DEFAULT', 'telegram-channel-id'))

LOG_FILE = config.get('DEFAULT', 'log-file', fallback='logs/latest.log')

last_discord_msg_time = 0
last_telegram_msg_time = 0
cooldown_lock = threading.Lock()

def debug_log(message, level=1):
    if DEBUG_LEVEL >= level:
        colors = {
            1: '\033[91m',
            2: '\033[94m',
            3: '\033[92m',
            4: '\033[95m'
        }
        color = colors.get(min(level, 4), '\033[0m')
        print(f"{color}[DEBUG {level}] {message}\033[0m")

def send_config_settings():
    """Отправляет текущие настройки конфига в лог (уровень debug 4)"""
    if DEBUG_LEVEL < 4:
        return
        
    debug_log("\nCurrent configuration settings:", 4)
    debug_log("="*40, 4)
    
    debug_log("[General Settings]", 4)
    debug_log(f"Debug Level: {DEBUG_LEVEL}", 4)
    debug_log(f"Log Format: {LOG_FORMAT}", 4)
    debug_log(f"Chat Format: {CHAT_FORMAT}", 4)
    debug_log(f"Join Format: {JOIN_FORMAT}", 4)
    debug_log(f"Leave Format: {LEAVE_FORMAT}", 4)
    debug_log(f"Message Cooldown: {MESSAGE_COOLDOWN} sec", 4)
    debug_log(f"Log File: {LOG_FILE}", 4)
    
    debug_log("\n[Discord Settings]", 4)
    debug_log(f"Enabled: {d}", 4)
    if d:
        debug_log(f"Token: {'*'*len(dtoken) if dtoken else 'Not set'}", 4)
        debug_log(f"Server ID: {dserver_id}", 4)
        debug_log(f"Channel ID: {dchannel_id}", 4)
    
    debug_log("\n[Telegram Settings]", 4)
    debug_log(f"Enabled: {t}", 4)
    if t:
        debug_log(f"Token: {'*'*len(ttoken) if ttoken else 'Not set'}", 4)
        debug_log(f"Chat ID: {tchat_id}", 4)
    
    debug_log("\n[RCON Settings]", 4)
    rcon_host = config.get('DEFAULT', 'rcon-host', fallback='Not set')
    rcon_port = config.get('DEFAULT', 'rcon-port', fallback='Not set')
    debug_log(f"Host: {rcon_host}", 4)
    debug_log(f"Port: {rcon_port}", 4)
    debug_log(f"Password: {'*'*len(config.get('DEFAULT', 'rcon-password', fallback='')) if config.get('DEFAULT', 'rcon-password', fallback=None) else 'Not set'}", 4)
    
    debug_log("="*40 + "\n", 4)

class MinecraftRCON:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password
        self.request_id = 0
        self.socket = None
        self.MAX_PAYLOAD_LENGTH = 1446
        self._connection_lock = threading.Lock()
        self._reconnect_attempts = 0
        self.MAX_RECONNECT_ATTEMPTS = 5
        self.RECONNECT_DELAY = 5

    def connect(self):
        with self._connection_lock:
            try:
                debug_log(f"Connecting to {self.host}:{self.port}...", 3)
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.host, self.port))
                debug_log("Connection established", 3)
                
                if not self.authenticate():
                    raise Exception("Authentication failed: Wrong password")
                debug_log("Authentication successful", 3)
                self._reconnect_attempts = 0
                return True
            except Exception as e:
                debug_log(f"Connection error: {e}", 1)
                self.disconnect()
                return False

    def authenticate(self):
        try:
            response_id, response = self.send_packet(3, self.password)
            debug_log(f"Auth response: ID={response_id}, Response={response}", 3)
            return response_id != -1
        except Exception as e:
            debug_log(f"Auth error: {e}", 1)
            return False

    def _ensure_connection(self):
        with self._connection_lock:
            if self.socket is None:
                debug_log("Connection not established, attempting to connect...", 3)
                return self._reconnect()
            
            try:
                self.socket.settimeout(1)
                self.socket.sendall(b'')
                return True
            except (socket.error, OSError):
                debug_log("Connection check failed, attempting to reconnect...", 3)
                return self._reconnect()
    
    def _reconnect(self):
        if self._reconnect_attempts >= self.MAX_RECONNECT_ATTEMPTS:
            debug_log("Max reconnect attempts reached, giving up.", 1)
            return False
            
        try:
            self.disconnect()
            time.sleep(self.RECONNECT_DELAY * (self._reconnect_attempts + 1))
            
            debug_log(f"Attempting to reconnect (attempt {self._reconnect_attempts + 1})...", 3)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            
            if not self.authenticate():
                raise Exception("Authentication failed after reconnect")
                
            self._reconnect_attempts = 0
            debug_log("Reconnection successful", 3)
            return True
        except Exception as e:
            self._reconnect_attempts += 1
            debug_log(f"Reconnection attempt {self._reconnect_attempts} failed: {e}", 1)
            return False

    def send_command(self, command, max_retries=3):
        for attempt in range(max_retries):
            if not self._ensure_connection():
                debug_log("No active connection, cannot send command", 1)
                return None
                
            try:
                if len(command.encode('utf-8')) > self.MAX_PAYLOAD_LENGTH:
                    debug_log("Command too long, cannot send", 1)
                    return "Error: Command exceeds maximum allowed length"
                    
                debug_log(f"Sending command: {command}", 3)
                _, response = self.send_packet(2, command)
                debug_log(f"Server response: {response}", 3)
                return response
            except Exception as e:
                debug_log(f"Command error (attempt {attempt + 1}): {e}", 1)
                if attempt == max_retries - 1:
                    return None
                time.sleep(1)

    def send_packet(self, packet_type, payload):
        if len(payload.encode('utf-8')) > self.MAX_PAYLOAD_LENGTH:
            raise Exception("Payload exceeds maximum allowed length")

        self.request_id += 1
        payload_utf8 = payload.encode('utf-8')
        
        packet = struct.pack(
            '<iii',
            10 + len(payload_utf8),
            self.request_id,
            packet_type
        ) + payload_utf8 + b'\x00\x00'

        debug_log(f"Sending packet: ID={self.request_id}, Type={packet_type}, Size={10 + len(payload_utf8)}", 3)
        
        try:
            self.socket.sendall(packet)
        except Exception as e:
            debug_log(f"Packet error: {e}", 1)
            self.disconnect()
            raise

        return self._receive_response()

    def _receive_response(self):
        try:
            length_data = self.socket.recv(4)
            if not length_data:
                raise Exception("Empty server response")
            
            length = struct.unpack('<i', length_data)[0]
            debug_log(f"Received response length: {length} bytes", 3)

            response_data = b""
            while len(response_data) < length:
                chunk = self.socket.recv(length - len(response_data))
                if not chunk:
                    raise Exception("Connection interrupted")
                response_data += chunk

            response_id, packet_type = struct.unpack('<ii', response_data[:8])
            payload = response_data[8:-2].decode('utf-8', errors='replace')
            
            debug_log(f"Full response: ID={response_id}, Type={packet_type}, Data={payload}", 3)
            return response_id, payload
            
        except Exception as e:
            debug_log(f"Response error: {e}", 1)
            self.disconnect()
            raise

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
                debug_log("Connection closed", 3)
            except Exception as e:
                debug_log(f"Error while disconnecting: {e}", 1)
            finally:
                self.socket = None

def update_log_content():
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
            debug_log(f'Log read error: {e}', 1)
        time.sleep(0.5)

def process_log_changes(new_content):
    try:
        chat_regex = re.compile(
            LOG_FORMAT.replace('{time}', r'(\d{2}:\d{2}:\d{2})')
                     .replace('{thread}', r'([^]]+)')
                     .replace('{message}', CHAT_FORMAT.replace('{username}', r'([^>]+)').replace('{message}', r'(.+)'))
        )
        
        join_regex = re.compile(
            LOG_FORMAT.replace('{time}', r'(\d{2}:\d{2}:\d{2})')
                     .replace('{thread}', r'([^]]+)')
                     .replace('{message}', JOIN_FORMAT.replace('{username}', r'(.+)'))
        )
        
        leave_regex = re.compile(
            LOG_FORMAT.replace('{time}', r'(\d{2}:\d{2}:\d{2})')
                     .replace('{thread}', r'([^]]+)')
                     .replace('{message}', LEAVE_FORMAT.replace('{username}', r'(.+)'))
        )

        for line in new_content.splitlines():
            chat_match = chat_regex.search(line)
            if chat_match:
                username = chat_match.group(3)
                message = chat_match.group(4).strip()
                debug_log(f"Chat message: {username}: {message}", 2)
                
                if d and discord_ready:
                    future = asyncio.run_coroutine_threadsafe(
                        discord_send_message(f"**{username}**: {message}"),
                        discord_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Discord send error: {str(e)}", 1)

                if t:
                    future = asyncio.run_coroutine_threadsafe(
                        telegram_send_message(f"{username}: {message}"),
                        telegram_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Telegram send error: {str(e)}", 1)
            
            join_match = join_regex.search(line)
            if join_match:
                username = join_match.group(3)
                debug_log(f"Player joined: {username}", 2)
                
                if d and discord_ready:
                    future = asyncio.run_coroutine_threadsafe(
                        discord_send_message(f"**{username} joined the server**"),
                        discord_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Discord send error: {str(e)}", 1)
                
                if t:
                    future = asyncio.run_coroutine_threadsafe(
                        telegram_send_message(f"{username} joined the server"),
                        telegram_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Telegram send error: {str(e)}", 1)
            
            leave_match = leave_regex.search(line)
            if leave_match:
                username = leave_match.group(3)
                debug_log(f"Player left: {username}", 2)
                
                if d and discord_ready:
                    future = asyncio.run_coroutine_threadsafe(
                        discord_send_message(f"**{username} left the server**"),
                        discord_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Discord send error: {str(e)}", 1)
                
                if t:
                    future = asyncio.run_coroutine_threadsafe(
                        telegram_send_message(f"{username} left the server"),
                        telegram_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Telegram send error: {str(e)}", 1)
                    
    except Exception as e:
        debug_log(f'Log processing error: {e}', 1)

def handle_shutdown(signum, frame):
    debug_log("Received shutdown signal, cleaning up...", 1)
    if 'rcon' in globals():
        rcon.disconnect()
    os._exit(0)

signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

# Discord Bot
if d:
    intents = disnake.Intents.default()
    intents.members = True
    intents.message_content = True
    
    discord_bot = commands.Bot(
        command_prefix="!",
        intents=intents)

    discord_ready = False
    discord_loop = asyncio.new_event_loop()

    async def discord_send_message(text):
        global last_discord_msg_time
        
        with cooldown_lock:
            current_time = time.time()
            elapsed = current_time - last_discord_msg_time
            if elapsed < MESSAGE_COOLDOWN:
                wait_time = MESSAGE_COOLDOWN - elapsed
                debug_log(f"[Discord] Waiting {wait_time:.1f}s cooldown...", 3)
                await asyncio.sleep(wait_time)
            
            try:
                channel = discord_bot.get_channel(dchannel_id)
                if not channel:
                    debug_log("Discord channel not found!", 1)
                    return False
                    
                await channel.send(text)
                last_discord_msg_time = time.time()
                debug_log(f"Sent to Discord: {text[:50]}...", 2)
                return True
            except Exception as e:
                debug_log(f"Discord send error: {str(e)}", 1)
                return False

    @discord_bot.event
    async def on_ready():
        global discord_ready
        discord_ready = True
        debug_log(f"Discord bot connected as {discord_bot.user}", 2)
        
        guild = discord_bot.get_guild(dserver_id)
        if guild:
            debug_log(f"Found guild: {guild.name}", 2)
            channel = guild.get_channel(dchannel_id)
            if channel:
                debug_log(f"Found channel: {channel.name}", 2)
            else:
                debug_log("Configured channel not found!", 1)
        else:
            debug_log("Configured guild not found!", 1)

    @discord_bot.event
    async def on_message(message):
        if message.author == discord_bot.user:
            return
            
        if message.channel.id == dchannel_id:
            try:
                safe_msg = message.content.replace('"', '\\"')
                cmd = f'tellraw @a ["",{{"text":"[Discord] ","color":"blue"}},{{"text":"{message.author.display_name}: {safe_msg}","color":"white"}}]'
                rcon.send_command(cmd)
                
                if t:
                    future = asyncio.run_coroutine_threadsafe(
                        telegram_send_message(f"Discord | {message.author.display_name}: {message.content}"),
                        telegram_loop
                    )
                    try:
                        future.result(timeout=10)
                    except Exception as e:
                        debug_log(f"Telegram send error: {str(e)}", 1)
            except Exception as e:
                debug_log(f"Discord processing error: {e}", 1)

    def run_discord_bot():
        asyncio.set_event_loop(discord_loop)
        try:
            discord_loop.run_until_complete(discord_bot.start(dtoken))
        except Exception as e:
            debug_log(f"Discord error: {e}", 1)
        finally:
            discord_loop.close()

    discord_thread = threading.Thread(target=run_discord_bot, daemon=True)
    discord_thread.start()

if t:
    telegram_bot = Bot(token=ttoken)
    dp = Dispatcher()
    telegram_loop = asyncio.new_event_loop()

    async def telegram_send_message(text):
        global last_telegram_msg_time
        
        with cooldown_lock:
            current_time = time.time()
            elapsed = current_time - last_telegram_msg_time
            if elapsed < MESSAGE_COOLDOWN:
                wait_time = MESSAGE_COOLDOWN - elapsed
                debug_log(f"[Telegram] Waiting {wait_time:.1f}s cooldown...", 3)
                await asyncio.sleep(wait_time)
            
            try:
                await telegram_bot.send_message(
                    chat_id=tchat_id,
                    text=text,
                    parse_mode=None
                )
                last_telegram_msg_time = time.time()
                debug_log(f"Sent to Telegram: {text}", 2)
                return True
            except Exception as e:
                debug_log(f"Telegram send error: {str(e)}", 1)
                return False

    @dp.message(F.chat.id == tchat_id)
    async def handle_telegram_message(message: types.Message):
        try:
            safe_msg = message.text.replace('"', '\\"')
            username = message.from_user.username or message.from_user.first_name
            cmd = f'tellraw @a ["",{{"text":"[Telegram] ","color":"green"}},{{"text":"{username}: {safe_msg}","color":"white"}}]'
            rcon.send_command(cmd)

            if d and discord_ready:
                future = asyncio.run_coroutine_threadsafe(
                    discord_send_message(f"Telegram | **{username}**: {safe_msg}"),
                    discord_loop
                )
                try:
                    future.result(timeout=10)
                except Exception as e:
                    debug_log(f"Discord send error: {str(e)}", 1)
        except Exception as e:
            debug_log(f"Telegram processing error: {e}", 1)

    def run_telegram_bot():
        asyncio.set_event_loop(telegram_loop)
        try:
            telegram_loop.run_until_complete(dp.start_polling(telegram_bot))
        except Exception as e:
            debug_log(f"Telegram error: {e}", 1)
        finally:
            telegram_loop.close()

    telegram_thread = threading.Thread(target=run_telegram_bot, daemon=True)
    telegram_thread.start()

def main():
    debug_log("\nStarting bot...", 1)

    send_config_settings()
    
    global rcon
    rcon = MinecraftRCON(
        host=config.get('DEFAULT', 'rcon-host'),
        port=int(config.get('DEFAULT', 'rcon-port')),
        password=config.get('DEFAULT', 'rcon-password')
    )
    
    if not rcon.connect():
        debug_log("Failed to connect to RCON", 1)
        return

    log_thread = threading.Thread(target=update_log_content, daemon=True)
    log_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        debug_log("\nStopping...", 1)
    finally:
        rcon.disconnect()

if __name__ == "__main__":
    main()
