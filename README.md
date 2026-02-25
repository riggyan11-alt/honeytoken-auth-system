# 🔐 Enhanced Honeytoken Authentication System

A Python desktop application combining honeytoken intrusion detection,
TOTP two-factor authentication, and Fernet-encrypted storage.
Built for BSc. Ethical Hacking and Cybersecurity — ST4017CMD.

---

## Features

- Honeytoken credential traps — fake accounts that silently catch intruders
- TOTP two-factor authentication — 6-digit codes that expire every 30 seconds
- Fernet encrypted storage — all data files encrypted with AES-128-CBC
- Session timeout — automatic logout after configurable idle period
- Intrusion logging — every honeytoken trigger logged with timestamp and IP
- Login history — full audit trail of all login attempts
- CSV export — export reports for analysis

---

## Requirements

- Python 3.8 or above
- cryptography library

---

## How to Run

Step 1 — Install the dependency:

    pip install cryptography

Step 2 — Run the application:

    python honeytoken_auth.py

---

## How to Use

**Register a user**
- Click Register on the main screen
- Enter a username and password
- The strength bar shows feedback in real time

**Log in**
- Enter credentials and click Login
- Click Show My OTP Code to see your 6-digit code
- Enter the code to complete login

**Set a honeytoken trap**
- Click Manage Honeytokens
- Enter a fake username like admin and any password
- Click Create Honeytoken
- Any login attempt using that username triggers a security alert

**View intrusions**
- Log in and go to Dashboard
- Click Intrusion Log to see all recorded events

---

## Project Structure

    honeytoken-auth-system/
    ├── honeytoken_auth.py     Main application
    ├── requirements.txt       Dependencies
    ├── .gitignore             Git exclusions
    ├── CHANGELOG.md           Version history
    ├── README.md              This file
    ├── screenshots/           Application and code screenshots
    └── docs/                  Project report PDF

---

## Security Notes

- master.key is auto-generated on first run — never share this file
- All .enc files are encrypted app data — excluded from GitHub
- intrusion_log.txt contains IP addresses — excluded from GitHub

---

## Module Information

| Field | Detail |
|-------|--------|
| Student Name | Your Name Here |
| Student ID | Your ID Here |
| Module | Introduction to Programming ST4017CMD |
| Programme | BSc Hons Ethical Hacking and Cybersecurity |
| College | Softwarica College of IT and E-Commerce |
| Partner | Coventry University |
| Lecturer | Abishek Bimali |
| Submission | 1st March 2026 |
```

---

# ACTION 4 — Create new file `.gitignore`

In VS Code Explorer panel — right-click on empty space in the file list → click **New File** → type `.gitignore` → press **Enter** → the file opens blank → paste exactly this → press **Ctrl+S**
```
# Encryption key — never upload
master.key

# Encrypted data files
*.enc

# Intrusion log contains IP addresses
intrusion_log.txt

# Python cache
__pycache__/
*.pyc
*.pyo

# Virtual environment
venv/

# OS junk files
.DS_Store
Thumbs.db
desktop.ini

# Exported CSV reports
*.csv