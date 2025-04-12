Minecraft-Discord-Telegram Bridge Bot

This bot bridges communication between Minecraft in-game chat, Discord, and Telegram, allowing seamless message synchronization across all platforms.
Key Features:

    Full Trio Integration: Connect Minecraft + Discord + Telegram together with two-way chat synchronization.

    Pairwise Modes: Use only the integrations you need:

        Minecraft ↔ Discord

        Minecraft ↔ Telegram

        (Discord ↔ Telegram also possible)

    Customizable Log Parsing: Minecraft messages are read from server logs. The log format is configurable to support different server types (Vanilla, Paper, Spigot, etc.).

    Rich Minecraft Messages: Uses tellraw for message delivery, supporting colors, hover text, and clickable links in Minecraft chat.

    Cooldown Control: Prevent spam with adjustable message delay settings.

    Easy Setup: Configure via a simple config-bot.cfg file.

How It Works:

    From Minecraft: Detects player chat/join/leave events via server logs → forwards to Discord/Telegram.

    To Minecraft: Discord/Telegram messages are sent via RCON using tellraw for formatted in-game display.

    Cross-Platform: Discord ↔ Telegram messages are mirrored if both are enabled.


Бот для связи Minecraft, Discord и Telegram

Этот бот синхронизирует чат между игровым чатом Minecraft, Discord и Telegram, позволяя общаться между платформами.
Основные возможности:

    Полная интеграция: Связка Minecraft + Discord + Telegram с двусторонней пересылкой сообщений.

    Парные режимы: Можно использовать только нужные направления:

        Minecraft ↔ Discord

        Minecraft ↔ Telegram

        (Discord ↔ Telegram также поддерживается)

    Гибкий формат логов: Сообщения из Minecraft считываются из логов сервера. Формат логов настраивается под любые серверы (Vanilla, Paper, Spigot и др.).

    Красивые сообщения: Использует tellraw для отправки в Minecraft, с поддержкой цветов, всплывающего текста и кликабельных ссылок.

    Защита от спама: Настраиваемая задержка между сообщениями.

    Простая настройка: Все параметры задаются в файле config-bot.cfg.

Принцип работы:

    Из Minecraft: Бот анализирует логи сервера (чат, вход/выход игроков) → пересылает в Discord/Telegram.

    В Minecraft: Сообщения из Discord/Telegram отправляются через RCON командой tellraw с форматированием.

    Между платформами: Сообщения зеркалируются между Discord и Telegram, если оба канала активны.