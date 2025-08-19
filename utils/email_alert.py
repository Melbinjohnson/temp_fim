import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from utils.config_loader import load_config

config = load_config()

load_dotenv()

def send_email_alert(message):
    sender = os.getenv("EMAIL_SENDER")
    receiver = os.getenv("EMAIL_RECEIVER")
    subject = os.getenv("EMAIL_SUBJECT", "FIM Alert")
    password = os.getenv("EMAIL_PASSWORD")
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    use_tls = os.getenv("USE_TLS", "True").lower() == "true"

    if not (sender and receiver and password):
        print("❌ Missing email credentials in .env")
        return

    msg = MIMEText(message)
    msg["From"] = sender
    msg["To"] = receiver
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        if use_tls:
            server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        print("📧 Email alert sent!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def play_beep(config=None):
    """Play a beep sound using aplay if enabled in settings."""
    if config is None:
        config = load_config()

    if config.get("beep_on_change", False):
        sound_file = config.get("beep_sound_file", "alert.wav")
        if os.path.isfile(sound_file):
            os.system(f"aplay {sound_file} >/dev/null 2>&1")
        else:
            print(f" Sound file not found: {sound_file}")
