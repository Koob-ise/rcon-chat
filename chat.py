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

# Конфигурация
config = configparser.ConfigParser()
config.read('config-bot.cfg')

debugging = config.get('DEFAULT', 'debugging')

# Настройки Discord
d = config.getboolean('DEFAULT', 'discord')
dtoken = config.get('DEFAULT', 'discord-token')
dserver_id = int(config.get('DEFAULT', 'discord-server-id'))  # ID сервера Discord
dchannel_id = int(config.get('DEFAULT', 'discord-channel-id'))  # ID канала Discord

# Настройки Telegram
t = config.getboolean('DEFAULT', 'telegram')
ttoken = config.get('DEFAULT', 'telegram-token')
tchat_id = int(config.get('DEFAULT', 'telegram-channel-id'))  # ID чата Telegram

# Настройки Minecraft
LOG_FILE = config.get('DEFAULT', 'log-file', fallback='logs/latest.log')
log_content = ""
chat_log = []

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
        self._debug = True  # Включить отладочный вывод

    def _debug_log(self, message):
        if self._debug:
            print(f"[RCON DEBUG] {message}")

    def connect(self):
        """Установить соединение с сервером."""
        try:
            self._debug_log(f"Подключение к {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self._debug_log("Соединение установлено")
            
            if not self.authenticate():
                raise Exception("Ошибка аутентификации: Неверный пароль")
            self._debug_log("Аутентификация успешна")
        except Exception as e:
            self._debug_log(f"Ошибка подключения: {e}")
            raise

    def authenticate(self):
        """Авторизация на сервере RCON."""
        try:
            response_id, response = self.send_packet(3, self.password)
            self._debug_log(f"Ответ аутентификации: ID={response_id}, Response={response}")
            return response_id != -1
        except Exception as e:
            self._debug_log(f"Ошибка аутентификации: {e}")
            return False

    def send_command(self, command):
        """Отправить команду на сервер и получить ответ."""
        try:
            self._debug_log(f"Отправка команды: {command}")
            _, response = self.send_packet(2, command)
            self._debug_log(f"Ответ сервера: {response}")
            return response
        except Exception as e:
            self._debug_log(f"Ошибка отправки команды: {e}")
            return None

    def send_packet(self, packet_type, payload):
        """Отправить пакет на сервер RCON."""
        self.request_id += 1
        payload_utf8 = payload.encode('utf-8')
        
        # Формируем пакет согласно протоколу RCON
        packet = struct.pack(
            '<iii',
            10 + len(payload_utf8),  # Длина пакета
            self.request_id,         # ID запроса
            packet_type              # Тип пакета (2=команда, 3=аутентификация)
        ) + payload_utf8 + b'\x00\x00'  # Данные + нулевые байты

        self._debug_log(f"Отправка пакета: ID={self.request_id}, Type={packet_type}, Size={10 + len(payload_utf8)}")
        
        try:
            self.socket.sendall(packet)
        except Exception as e:
            self._debug_log(f"Ошибка отправки пакета: {e}")
            raise

        return self._receive_response()

    def _receive_response(self):
        """Получить ответ от сервера RCON."""
        try:
            # Читаем длину пакета (4 байта)
            length_data = self.socket.recv(4)
            if not length_data:
                raise Exception("Пустой ответ от сервера")
            
            length = struct.unpack('<i', length_data)[0]
            self._debug_log(f"Получен ответ длиной {length} байт")

            # Читаем оставшиеся данные
            response_data = b""
            while len(response_data) < length:
                chunk = self.socket.recv(length - len(response_data))
                if not chunk:
                    raise Exception("Соединение прервано")
                response_data += chunk

            # Распаковываем заголовок пакета
            response_id, packet_type = struct.unpack('<ii', response_data[:8])
            
            # Извлекаем полезную нагрузку (пропускаем 8 байт заголовка и 2 нулевых байта в конце)
            payload = response_data[8:-2].decode('utf-8', errors='replace')
            
            self._debug_log(f"Полный ответ: ID={response_id}, Type={packet_type}, Data={payload}")
            return response_id, payload
            
        except Exception as e:
            self._debug_log(f"Ошибка получения ответа: {e}")
            raise

    def disconnect(self):
        """Закрыть соединение."""
        if self.socket:
            try:
                self.socket.close()
                self._debug_log("Соединение закрыто")
            except:
                pass
            finally:
                self.socket = None

def debug_log_reading():
    """Функция для отладки чтения логов"""
    try:
        print(f"\n=== Debug: Проверка логов ===")
        print(f"Файл логов: {LOG_FILE}")
        print(f"Размер файла: {os.path.getsize(LOG_FILE)} байт")
        print(f"Последние 5 строк:")
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines[-5:]:
                print(line.strip())
        
        # Проверка наличия чат-сообщений в логах
        print("\nПоиск чат-сообщений в логах:")
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f.readlines()[-20:]:
                if '[Server thread/INFO] [minecraft/MinecraftServer]: <' in line:
                    print(line.strip())
        print("============================\n")
    except Exception as e:
        print(f"Ошибка при отладке логов: {e}")

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
                last_size = 0  # Файл был перезаписан (ротация логов)
        except Exception as e:
            print(f'Ошибка чтения логов: {e}')
        time.sleep(0.5)

def process_log_changes(new_content):
    global chat_log
    try:
        for line in new_content.splitlines():
            # Ищем сообщения в формате: [12:09:32] [Server thread/INFO]: <KooB_ise> sosal
            if re.search(r'^\[\d{2}:\d{2}:\d{2}\] \[Server thread/INFO\]: <([^>]+)> (.+)', line):
                try:
                    match = re.search(r'^\[\d{2}:\d{2}:\d{2}\] \[Server thread/INFO\]: <([^>]+)> (.+)', line)
                    username = match.group(1)
                    message = match.group(2).strip()
                    
                    # Проверка на дубликаты
                    msg_id = f"{username}:{message}"
                    if msg_id not in chat_log:
                        chat_log.append(msg_id)
                        print(f"Найдено сообщение: {username}: {message}")
                        
                        # Отправка в Discord
                        if d and discord_bot:
                            asyncio.run_coroutine_threadsafe(
                                send_discord_message(f"**{username}**: {message}"),
                                discord_bot.loop
                            )
                            
                        # Отправка в Telegram
                        if t and telegram_bot:
                            asyncio.run_coroutine_threadsafe(
                                send_telegram_message(f"{username}: {message}"),
                                telegram_loop
                            )
                except Exception as e:
                    print(f"Ошибка парсинга: {e}\nСтрока: {line}")
                    
        # Очистка старых сообщений
        if len(chat_log) > 1000:
            chat_log = chat_log[-1000:]
    except Exception as e:
        print(f'Ошибка обработки логов: {e}')

# Discord Bot
if d:
    discord_bot = commands.Bot(command_prefix="!", intents=disnake.Intents.all())

    async def send_discord_message(text):
        try:
            guild = discord_bot.get_guild(dserver_id)  # Получаем сервер по ID
            if not guild:
                print(f"Сервер Discord {dserver_id} не найден!")
                return
            
            channel = guild.get_channel(dchannel_id)  # Получаем канал по ID
            if channel:
                await channel.send(text)
                print(f"Отправлено в Discord: {text}")
            else:
                print(f"Канал Discord {dchannel_id} не найден на сервере {guild.name}")
        except Exception as e:
            print(f"Ошибка Discord: {e}")

    @discord_bot.event
    async def on_ready():
        print(f'Discord Bot подключен как {discord_bot.user}')

    @discord_bot.event
    async def on_message(message):
        if message.author == discord_bot.user:
            return
            
        # Проверяем, что сообщение из нужного сервера и канала
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
                print(f"Ошибка обработки Discord: {e}")

# Telegram Bot
if t:
    telegram_bot = Bot(token=ttoken)
    dp = Dispatcher()
    telegram_loop = asyncio.new_event_loop()

    async def send_telegram_message(text):
        try:
            await telegram_bot.send_message(
                chat_id=tchat_id,
                text=text,
                parse_mode=None
            )
            print(f"Отправлено в Telegram: {text}")
        except Exception as e:
            print(f"Ошибка Telegram: {e}")

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
            print(f"Ошибка обработки Telegram: {e}")

    def run_telegram_bot():
        asyncio.set_event_loop(telegram_loop)
        telegram_loop.run_until_complete(dp.start_polling(telegram_bot))

def main():
    if debugging:
        debug_log_reading()
    print("\nПроверка конфигурации:")
    print(f"Discord: {'Включен' if d else 'Отключен'}")
    print(f"Telegram: {'Включен' if t else 'Отключен'}")
    print(f"Путь к логам: {LOG_FILE}")
        
    global rcon
    rcon = MinecraftRCON(
        host=config.get('DEFAULT', 'rcon-host'),
        port=int(config.get('DEFAULT', 'rcon-port')),
        password=config.get('DEFAULT', 'rcon-password')
    )
    rcon.connect()

    # Запуск мониторинга логов
    log_thread = threading.Thread(target=update_log_content, daemon=True)
    log_thread.start()

    # Запуск ботов
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
        print("\nОстановка...")
    finally:
        rcon.disconnect()

if __name__ == "__main__":
    main()
