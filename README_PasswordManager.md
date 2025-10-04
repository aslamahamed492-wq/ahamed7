# 🔐 CLI Password Manager (AES-256-GCM Encrypted Vault)

## 📖 Description
This is a **Command-Line Password Manager** that securely stores, retrieves, and manages passwords locally using **AES-256-GCM encryption**.  
It provides a simple interface to add, view, delete, and list credentials while protecting all data with a **master password**.

The vault is stored as a **JSON file (`vault.json`)**, and encryption keys are derived from your master password using **PBKDF2-HMAC (SHA256)**.

---

## 🚀 Features
- 🔒 AES-256-GCM encryption for strong security  
- 🔑 Master password protection (never stored)  
- 🧂 Salted key derivation using PBKDF2  
- 🧰 CLI commands for `add`, `get`, `list`, `delete`, and `change-master`  
- 🚫 Auto-lock after repeated failed attempts  
- ✅ Atomic writes to prevent data corruption  
- 🧾 All data stored locally — no cloud or external storage

---

## 🛠 Requirements
- Python **3.7+**
- `cryptography` package  
  Install with:
  ```bash
  pip install cryptography
  ```

---

## ⚡ Usage

### 1️⃣ Add a New Password
```bash
python password_manager.py add
```
- Prompts for master password (creates vault if missing)
- Asks for site, username, password, and an optional note

### 2️⃣ Retrieve a Password
```bash
python password_manager.py get --site example.com
```

### 3️⃣ List All Stored Sites
```bash
python password_manager.py list
```

### 4️⃣ Delete an Entry
```bash
python password_manager.py delete --site example.com
```

### 5️⃣ Change Master Password
```bash
python password_manager.py change-master
```

---

## 🗂 Vault File (`vault.json`)
A simplified example of the encrypted vault structure:
```json
{
  "salt": "abcd1234base64==",
  "iterations": 480000,
  "check": { "nonce": "...", "ciphertext": "..." },
  "entries": {
    "example.com": {
      "nonce": "base64string",
      "ciphertext": "base64string"
    }
  }
}
```

---

## ⚠️ Security Notes
- Master password **is never saved** — losing it means losing access to all stored credentials.
- The vault auto-locks after **5 failed attempts** for 5 minutes.
- Keep your `vault.json` file safe and back it up securely.

---

## 🧠 Learning Highlights
- AES-GCM symmetric encryption  
- Password-based key derivation (PBKDF2)  
- Secure JSON file handling and atomic writes  
- CLI design using `argparse`  
- Error handling and safe user interaction in terminal

---

## 👨‍💻 Author
Developed as part of a **Python Security & Encryption Project** to demonstrate secure password management from the command line.

---

## 📜 License
This project is open-source and available for educational use.
