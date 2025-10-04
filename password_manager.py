#!/usr/bin/env python3
\"\"\"CLI Password Manager (AES-256-GCM encrypted vault)

Usage (examples):
    python password_manager.py add
    python password_manager.py get --site example.com
    python password_manager.py list
    python password_manager.py delete --site example.com
    python password_manager.py change-master

Notes:
- Requires `cryptography` package: pip install cryptography
- Vault file: vault.json (stored in the current working directory)
\"\"\"

import argparse
import base64
import getpass
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "vault.json"
DEFAULT_ITERATIONS = 480000
MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION_SECONDS = 300  # 5 minutes lock after too many failed attempts

# -------------------- Utilities --------------------
def b64(e: bytes) -> str:
    return base64.b64encode(e).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def atomic_write(path: Path, data: str):
    temp_fd, temp_path = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(temp_path, str(path))
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

# -------------------- Crypto --------------------
def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_bytes(key: bytes, plaintext: bytes) -> Dict[str, str]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return {"nonce": b64(nonce), "ciphertext": b64(ct)}

def decrypt_bytes(key: bytes, nonce_b64: str, ct_b64: str) -> bytes:
    aesgcm = AESGCM(key)
    nonce = ub64(nonce_b64)
    ct = ub64(ct_b64)
    return aesgcm.decrypt(nonce, ct, None)

# -------------------- Vault Handling --------------------
def vault_exists(path: Path) -> bool:
    return path.exists()

def create_new_vault(path: Path, master_password: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    iterations = DEFAULT_ITERATIONS
    key = derive_key(master_password, salt, iterations)
    # Create a "check" ciphertext to verify master password later
    check_plain = b"vault-check"
    enc = encrypt_bytes(key, check_plain)
    vault = {
        "salt": b64(salt),
        "iterations": iterations,
        "check": enc,  # used to validate master password
        "entries": {},
        "failed_attempts": 0,
        "lock_until": None
    }
    save_vault(path, vault)
    return vault

def load_vault(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_vault(path: Path, vault: Dict[str, Any]):
    s = json.dumps(vault, indent=2)
    atomic_write(path, s)

def is_locked(vault: Dict[str, Any]) -> bool:
    lock = vault.get("lock_until")
    if not lock:
        return False
    try:
        return time.time() < float(lock)
    except Exception:
        return False

def record_failed_attempt(vault: Dict[str, Any], path: Path):
    vault["failed_attempts"] = vault.get("failed_attempts", 0) + 1
    if vault["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        vault["lock_until"] = time.time() + LOCK_DURATION_SECONDS
        print(f"Too many failed attempts. Vault locked for {LOCK_DURATION_SECONDS} seconds.")
    save_vault(path, vault)

def reset_failed_attempts(vault: Dict[str, Any], path: Path):
    vault["failed_attempts"] = 0
    vault["lock_until"] = None
    save_vault(path, vault)

# -------------------- High-level operations --------------------
def verify_master_password(vault: Dict[str, Any], master_password: str) -> bytes:
    salt = ub64(vault["salt"])
    iterations = int(vault.get("iterations", DEFAULT_ITERATIONS))
    key = derive_key(master_password, salt, iterations)
    try:
        # Try decrypting the check value
        check = vault["check"]
        _ = decrypt_bytes(key, check["nonce"], check["ciphertext"])
        return key
    except Exception:
        raise ValueError("Invalid master password or vault corrupted.")

def add_entry(vault_path: Path, master_password: str):
    if not vault_exists(vault_path):
        print("Vault not found. Creating a new vault...")
        vault = create_new_vault(vault_path, master_password)
        key = derive_key(master_password, ub64(vault["salt"]), vault["iterations"])
    else:
        vault = load_vault(vault_path)
        if is_locked(vault):
            print("Vault is temporarily locked due to previous failed attempts. Try later.")
            return
        try:
            key = verify_master_password(vault, master_password)
            reset_failed_attempts(vault, vault_path)
        except ValueError as e:
            print(str(e))
            record_failed_attempt(vault, vault_path)
            return

    site = input("Website (site key): ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password (input hidden): ").strip()
    note = input("Note (optional): ").strip()

    entry_plain = json.dumps({"username": username, "password": password, "note": note}).encode('utf-8')
    enc = encrypt_bytes(key, entry_plain)
    vault["entries"][site] = enc
    save_vault(vault_path, vault)
    print(f"Entry for '{site}' added/updated.")

def get_entry(vault_path: Path, master_password: str, site: str):
    if not vault_exists(vault_path):
        print("Vault not found.")
        return
    vault = load_vault(vault_path)
    if is_locked(vault):
        print("Vault is temporarily locked due to previous failed attempts. Try later.")
        return
    try:
        key = verify_master_password(vault, master_password)
        reset_failed_attempts(vault, vault_path)
    except ValueError as e:
        print(str(e))
        record_failed_attempt(vault, vault_path)
        return

    entry = vault.get("entries", {}).get(site)
    if not entry:
        print(f"No entry found for '{site}'.")
        return
    try:
        pt = decrypt_bytes(key, entry["nonce"], entry["ciphertext"])
        data = json.loads(pt.decode('utf-8'))
        print(f"Site: {site}")
        print(f"Username: {data.get('username')}")
        print(f"Password: {data.get('password')}")
        note = data.get('note')
        if note:
            print(f"Note: {note}")
    except Exception as e:
        print("Failed to decrypt entry. Data may be corrupted.")
        return

def list_entries(vault_path: Path, master_password: str):
    if not vault_exists(vault_path):
        print("Vault not found.")
        return
    vault = load_vault(vault_path)
    if is_locked(vault):
        print("Vault is temporarily locked due to previous failed attempts. Try later.")
        return
    try:
        key = verify_master_password(vault, master_password)
        reset_failed_attempts(vault, vault_path)
    except ValueError as e:
        print(str(e))
        record_failed_attempt(vault, vault_path)
        return

    sites = sorted(vault.get("entries", {}).keys())
    if not sites:
        print("No entries in vault.")
        return
    print("Stored sites:")
    for s in sites:
        print(f" - {s}")

def delete_entry(vault_path: Path, master_password: str, site: str):
    if not vault_exists(vault_path):
        print("Vault not found.")
        return
    vault = load_vault(vault_path)
    if is_locked(vault):
        print("Vault is temporarily locked due to previous failed attempts. Try later.")
        return
    try:
        key = verify_master_password(vault, master_password)
        reset_failed_attempts(vault, vault_path)
    except ValueError as e:
        print(str(e))
        record_failed_attempt(vault, vault_path)
        return

    if site in vault.get("entries", {}):
        confirm = input(f"Delete entry for '{site}'? (y/N): ").strip().lower()
        if confirm == "y":
            vault["entries"].pop(site, None)
            save_vault(vault_path, vault)
            print(f"Deleted entry for '{site}'.")
        else:
            print("Aborted.")
    else:
        print(f"No entry found for '{site}'.")

def change_master_password(vault_path: Path, old_master: str):
    if not vault_exists(vault_path):
        print("Vault not found.")
        return
    vault = load_vault(vault_path)
    if is_locked(vault):
        print("Vault is temporarily locked due to previous failed attempts. Try later.")
        return
    try:
        old_key = verify_master_password(vault, old_master)
    except ValueError as e:
        print(str(e))
        record_failed_attempt(vault, vault_path)
        return

    # Ask for new master password
    new_master = getpass.getpass("New master password: ")
    new_master2 = getpass.getpass("Confirm new master password: ")
    if new_master != new_master2:
        print("Passwords do not match. Aborting.")
        return
    if not new_master:
        print("Empty password not allowed.")
        return

    # Decrypt all entries using old_key, then re-encrypt with new key+salt
    try:
        all_entries = vault.get("entries", {})
        decrypted_entries = {}
        for site, enc in all_entries.items():
            pt = decrypt_bytes(old_key, enc["nonce"], enc["ciphertext"])
            decrypted_entries[site] = pt  # keep plaintext bytes

        # Create new salt and key
        new_salt = os.urandom(16)
        new_iterations = DEFAULT_ITERATIONS
        new_key = derive_key(new_master, new_salt, new_iterations)

        # Re-encrypt entries
        new_entries = {}
        for site, pt in decrypted_entries.items():
            enc = encrypt_bytes(new_key, pt)
            new_entries[site] = enc

        # Update vault metadata
        new_check = encrypt_bytes(new_key, b"vault-check")
        vault["salt"] = b64(new_salt)
        vault["iterations"] = new_iterations
        vault["check"] = new_check
        vault["entries"] = new_entries
        reset_failed_attempts(vault, vault_path)
        save_vault(vault_path, vault)
        print("Master password changed successfully.")
    except Exception as e:
        print("Failed to re-encrypt vault. Aborting. Error:", str(e))
        return

# -------------------- CLI --------------------
def main():
    parser = argparse.ArgumentParser(description="Secure CLI Password Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_add = subparsers.add_parser("add", help="Add or update an entry")
    p_get = subparsers.add_parser("get", help="Retrieve an entry")
    p_get.add_argument("--site", required=True, help="Site key to retrieve")
    p_list = subparsers.add_parser("list", help="List all stored sites")
    p_delete = subparsers.add_parser("delete", help="Delete an entry")
    p_delete.add_argument("--site", required=True, help="Site key to delete")
    p_change = subparsers.add_parser("change-master", help="Change master password")

    args = parser.parse_args()
    vault_path = Path(VAULT_FILE)

    # Commands requiring master password: prompt interactively (hidden)
    if args.command in ("add", "get", "list", "delete", "change-master"):
        # For change-master we need old master; for others, master to unlock
        master = getpass.getpass("Master Password: ")
        if args.command == "add":
            add_entry(vault_path, master)
        elif args.command == "get":
            get_entry(vault_path, master, args.site)
        elif args.command == "list":
            list_entries(vault_path, master)
        elif args.command == "delete":
            delete_entry(vault_path, master, args.site)
        elif args.command == "change-master":
            change_master_password(vault_path, master)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
