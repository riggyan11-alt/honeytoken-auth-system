# Changelog — Enhanced Honeytoken Authentication System

---

## Version 1.4 — 2026-02-25
### Final Submission
- All screenshots added to screenshots folder
- Project report PDF added to docs folder
- README updated with correct student details

### Bug Fixes
- Fixed Unicode encoding error on Windows when writing emoji characters to intrusion log
- All file operations on intrusion_log.txt now explicitly use encoding="utf-8"
- Honeytoken detection now triggers on username match alone, not password match
- Trigger count now increments correctly on each honeytoken activation
- Username and password fields both cleared after honeytoken alert is dismissed

---

## Version 1.2 — 2026-02-24

### Improvements
- Added section divider comments throughout source code
- Inline algorithm documentation added to OTP, hashing and intrusion functions
- Author and student ID header added to top of source file

---

## Version 1.1 — 2026-02-23

### Added
- Intrusion log viewer accessible from user dashboard
- System statistics screen showing totals for all tracked events
- CSV export for login history, intrusion log and full system report
- Settings screen for configuring session timeout
- Real-time password strength indicator on registration screen
- Session timeout auto-logout using Tkinter after() scheduler

---

## Version 1.0 — 2026-02-20 — Initial Release

### Added
- User registration with PBKDF2-SHA256 password hashing and random salt
- Honeytoken credential manager for creating fake credential traps
- Honeytoken detection on login with red security alert popup
- TOTP two-factor authentication using HMAC-SHA1 with 30-second windows
- Fernet symmetric encryption for all stored data files
- Auto-generated master encryption key on first run
- Tkinter GUI with dark Catppuccin colour theme
- Login history recording for all successful and failed attempts