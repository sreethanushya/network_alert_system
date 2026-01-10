# Network Alert System for Suspicious Activity

A lightweight real-time network monitoring and alert system developed in Python to detect suspicious network behavior such as TCP SYN scans, ICMP flooding, and unknown traffic patterns.

This project focuses on packet-level inspection, secure alert generation, and encryption, making it suitable for academic, learning, and small-scale security environments.

---

## Key Features
- Real-time packet sniffing and analysis
- Detection of suspicious activities:
  - TCP SYN scan attempts
  - ICMP ping flood behavior
  - Unknown or abnormal traffic patterns
- Secure alert generation and notification
- AES-based encryption for alert data
- Modular and easy-to-extend codebase

---

## Security and Privacy Considerations

This repository follows secure coding and open-source safety practices.

### Masked Credentials
- Email addresses and credentials in `notifier.py` are intentionally masked using placeholder values such as `youremail@example.com`
- No real credentials, passwords, or personal information are stored or committed

### Ignored Sensitive Files
The following files are intentionally excluded using `.gitignore`:
- `aes_key.bin` – runtime-generated encryption key
- `alerts.db` – generated alert database
- `__pycache__/` – Python cache files

These files are generated locally at runtime and should not be committed to a public repository.

---

## Technologies Used
- Python 3
- Scapy
- Cryptography (AES encryption using CBC mode)
- SMTP for email notifications
- Colorama for console output
- TCP/IP and ICMP networking concepts

---

## System Workflow
1. Capture live network packets
2. Analyze packet headers and traffic behavior
3. Detect suspicious patterns using rule-based logic
4. Encrypt alert messages using AES
5. Trigger console and email alerts
6. Log alerts securely on the local system

---

## How to Run the Project
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
