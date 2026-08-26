# Password-Vault
A simple Python based, Password Vault that runs offline with a GUI.

# LocalVault 2.0

Local Windows GUI password manager.

## New in version 2.0

- Quick unlock using a 6-8 digit PIN or the master password
- No forced 12-character master-password rule
- Master password authorization for add, edit, delete, backup and settings
- Configurable inactivity auto-lock, including Disable
- Persistent theme, timer and window-state settings
- Dark and light modes

## Install

1. Install Python 3.11 or newer.
2. Run `pip install -r requirements.txt`
3. Run `python localvault_v2.py`

Data and app settings are stored in `%LOCALAPPDATA%\LocalVault\vault.db`.

## Security model

A random data-encryption key encrypts vault fields with AES-GCM. That key is wrapped separately by keys derived from the master password and PIN. The PIN is intentionally less resistant to offline guessing than a strong master password, so protect the PC and encrypted database backup. Major database changes require the master password.

Existing version 1 databases use a different metadata layout. Preserve a backup before moving to version 2. For a clean test, rename `%LOCALAPPDATA%\LocalVault` before starting v2.

## Note
Use the windows batch file named as "Locker.bat" and create it's shortcut on desktop and change the icon to desired symbol. This would make it almost function as a windows executable program while running on python.
