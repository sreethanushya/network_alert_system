import os
import json
from datetime import datetime
from crypto_utils import generate_key, encrypt_message, decrypt_message, generate_and_print_key
from db_store import init_db, save_encrypted_alert, fetch_all_alerts
from notifier import send_alert_email

from detector import Detector, start_sniff

# Network interface (set manually if not found automatically)
INTERFACE = os.environ.get("CAPTURE_IFACE", None)
ATTACHMENT_NAME = "alert_encrypted.json"

# ================================================================
# ALERT CALLBACK FUNCTION
# ================================================================
def alert_callback_factory(conn, key):
    """
    Creates a callback function to handle detected alerts:
    1. Encrypts the alert message using AES.
    2. Saves the encrypted alert in the database.
    3. Sends an alert email with the encrypted data as an attachment.
    """
    def _callback(alert_obj):
        ts = datetime.utcfromtimestamp(alert_obj["timestamp"]).isoformat() + "Z"
        src = alert_obj.get("src")
        dst = alert_obj.get("dst")
        reason = alert_obj.get("reason")
        meta = alert_obj.get("meta")

        print(f"\n⚠️ [ALERT DETECTED] {ts} | {src} → {dst} | Reason: {reason}")

        # Convert alert object to JSON string
        alert_json = json.dumps(alert_obj, indent=2)

        # Encrypt the alert message using AES
        encrypted_alert = encrypt_message(alert_json, key)

        # Save the encrypted alert in the database
        save_encrypted_alert(conn, ts, src, dst, reason, encrypted_alert)

        # Prepare email content
        subject = f"🚨 Network Alert: {reason}"
        body = (
            f"Alert detected at {ts}\n"
            f"Source: {src}\n"
            f"Destination: {dst}\n"
            f"Reason: {reason}\n\n"
            "An encrypted version of this alert is attached."
        )

        attachment_bytes = encrypted_alert.encode()  # convert string to bytes for attachment

        # Try sending the email
        try:
            send_alert_email(subject, body, attachment_bytes, ATTACHMENT_NAME)
            print("📧 Alert email successfully sent!")
        except Exception as e:
            print(f"[main] ⚠️ Could not send email: {e}")

    return _callback

# ================================================================
# DECRYPTION DISPLAY FUNCTION
# ================================================================
def list_and_decrypt(conn, key, count=5):
    """
    Fetch and decrypt the last few alerts stored in the database.
    """
    alerts = fetch_all_alerts(conn)
    print(f"\n📜 [main] Total {len(alerts)} alerts in database.")
    if len(alerts) == 0:
        print("No alerts stored yet.")
        return

    print(f"Showing last {min(count, len(alerts))} decrypted alerts:")
    for a in alerts[:count]:
        try:
            decrypted_text = decrypt_message(a["ciphertext"], key)
            print("\n✅ Decrypted Alert:")
            print(json.dumps(json.loads(decrypted_text), indent=2))
        except Exception as e:
            print(f"[main] ❌ Decrypt failed for id {a['id']}:", e)

# ================================================================
# MAIN PROGRAM START
# ================================================================
if __name__ == "__main__":
    print("\n🚀 Starting Network Alert System with AES Encryption...")

    # Initialize AES key
    try:
        # Try to load an existing key from file
        if os.path.exists("aes_key.bin"):
            with open("aes_key.bin", "rb") as f:
                key = f.read()
            print("🔑 Loaded AES key from aes_key.bin")
        else:
            print("🆕 No key found, generating a new AES key...")
            key = generate_and_print_key()
            with open("aes_key.bin", "wb") as f:
                f.write(key)
                print("💾 Saved new AES key to aes_key.bin")
    except Exception as e:
        print(f"[main] ⚠️ Error initializing AES key: {e}")
        key = generate_and_print_key()

    # Initialize database
    conn = init_db()

    # Create detector and callback handler
    detector = Detector(alert_callback_factory(conn, key))

    # Start packet sniffing
    try:
        print("\n📡 Starting packet capture... Press Ctrl+C to stop.")
        start_sniff(detector, iface=INTERFACE)
    except KeyboardInterrupt:
        print("\n🛑 Packet capture stopped by user.")
        list_and_decrypt(conn, key)
