from colorama import Fore, Style
import smtplib
from email.message import EmailMessage

#coloured aletrs
def console_alert(message, level="INFO"):
    color = {
        "INFO": Fore.CYAN,
        "WARN": Fore.YELLOW,
        "ALERT": Fore.RED
    }.get(level, Fore.WHITE)
    print(f"{color}[{level}] {message}{Style.RESET_ALL}")

#email alert to the network owner regarding the detected spam
def send_alert_email(alert_type, src_ip, dst_ip, timestamp):
    FROM_EMAIL = "Togmail@gmail.com"
    TO_EMAIL = "yourgmail@gmail.com"
    APP_PASSWORD = "xyz"   # Gmail App Password

    subject = f"[ALERT] Suspicious Network Activity Detected!"
    body = (
        f" ALERT TYPE: {alert_type}\n"
        f" Source IP: {src_ip}\n"
        f" Destination IP: {dst_ip}\n"
        f" Timestamp: {timestamp}\n\n"
        "Please review this network event immediately."
    )

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = FROM_EMAIL
    msg['To'] = TO_EMAIL
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(FROM_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
            console_alert(f" Email alert sent to {TO_EMAIL}", "INFO")
    except Exception as e:
        console_alert(f" Failed to send email: {e}", "ALERT")
