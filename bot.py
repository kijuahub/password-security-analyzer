import hashlib
import requests
import telebot
from bs4 import BeautifulSoup
import secrets
import os
import string

API_URL = "https://api.pwnedpasswords.com/range/"
TOKEN = os.environ["BOT_TOKEN"]

DEFAULT_LENGTH = 20
MIN_LENGTH, MAX_LENGTH = 12, 64
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

bot = telebot.TeleBot(TOKEN)


def check_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    response = requests.get(
        API_URL + prefix,
        headers={"Add-Padding": "true"},
        timeout=10,
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    for line in soup.get_text().splitlines():
        if ":" not in line:
            continue
        hash_suffix, count = line.strip().split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def format_report(count: int) -> str:
    if count == 0:
        return (
            "Пароль не найден в известных утечках"
        )
    if count < 100:
        level = "Пароль встречался в утечках, замените его!"
    else:
        level = "Пароль был скомпрометирован. срочно замените его!"
    return f"{level}\n\nНайден в утечках раз: {count:,}".replace(",", " ")

def generate_password(length: int = DEFAULT_LENGTH) -> str:
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    alphabet = "".join(groups)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in group for ch in password) for group in groups):
            return password

@bot.message_handler(commands=["generate"])
def generate(message):
    length = DEFAULT_LENGTH
    parts = message.text.split()
    if len(parts) > 1:
        try:
            length = int(parts[1])
        except ValueError:
            bot.reply_to(message, "Длина не является числом! \nДолжно быть например: /generate 24")
            return

    note = ""
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        length = max(MIN_LENGTH, min(length, MAX_LENGTH))
        note = f"\n(Длина должна быть {MIN_LENGTH}–{MAX_LENGTH}!)"

    password = generate_password(length)

    bot.send_message(
        message.chat.id,
        f"🔐 Ваш новый пароль ({length} символов): {password}"
    )

@bot.message_handler(commands=["start", "help"])
def start(message):
    bot.reply_to(
        message,
        "👋 Привет! Я проверяю не попадал ли пароль в публичные утечки данных\n"
             "Просто отправь мне пароль, и я проверю его на безопасность!\n\n"
             "🔐 /generate — сгенерировать надёжный пароль (например: /generate 32).\n\n"
    )


@bot.message_handler(content_types=["text"], func=lambda m: not m.text.startswith("/"))
def handle_password(message):
    password = message.text

    try:
        count = check_pwned(password)
        report = format_report(count)
    except requests.RequestException:
        report = "Не удалось связаться с сервисом проверки. Попробуйте позже."

    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        report += "\n\n(Не удалось удалить твоё сообщение — удали его вручную.)"

    bot.send_message(message.chat.id, report)


if __name__ == "__main__":
    bot.infinity_polling()
