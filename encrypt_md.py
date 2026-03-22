#!/usr/bin/env python3
"""
encrypt_md.py  —  Encrypt a single post's markdown using its root flag.

Usage:
    python3 encrypt_md.py _posts/your-post.md "root-flag-here"

Example:
    python3 encrypt_md.py _posts/2026-03-21-hackthebox-cctv.md "8f680a1118cd22d81afbda7af9bea42d"

What happens:
    1. The entire .md file is encrypted with AES-256-CBC + PBKDF2 + HMAC-SHA256.
    2. The file is replaced with an encrypted YAML blob.
    3. A backup of the original is saved to _backups/.
    4. Only the encrypted version should be pushed to GitHub.

When the machine retires:
    python3 decrypt_md.py _posts/your-post.md "root-flag-here"

Requires:
    pip install cryptography pyyaml
"""

import os
import sys
import yaml
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def aes_encrypt(password: bytes, plaintext: bytes) -> dict:
    salt = os.urandom(16)
    key  = derive_key(password, salt)
    iv   = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    digest = h.finalize()

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv":         base64.b64encode(iv).decode(),
        "salt":       base64.b64encode(salt).decode(),
        "hmac":       base64.b64encode(digest).decode(),
    }


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 encrypt_md.py <post.md> <root_flag>")
        sys.exit(1)

    path = Path(sys.argv[1])
    flag = sys.argv[2].strip().encode()

    if not path.exists():
        print(f"Error: file not found → {path}")
        sys.exit(1)

    text = path.read_text(encoding="utf-8")

    # Don't double-encrypt
    if text.strip().startswith("ciphertext:"):
        print(f"Already encrypted: {path}")
        sys.exit(0)

    # Backup original to _backups/
    backup_dir = path.parent.parent / "_backups"
    backup_dir.mkdir(exist_ok=True)
    backup_path = backup_dir / path.name.replace(".md", ".bak")
    backup_path.write_text(text, encoding="utf-8")
    print(f"✓ Backup saved  →  {backup_path}")

    # Encrypt
    encrypted = aes_encrypt(flag, text.encode("utf-8"))

    # Write encrypted YAML blob back to the .md file
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(encrypted, f, sort_keys=False)

    print(f"✓ Encrypted     →  {path}")
    print(f"  Flag used: {sys.argv[2]}")
    print()
    print("Push the encrypted file — the raw markdown is safe in _backups/ locally.")
    print(f"To restore: python3 decrypt_md.py {path} \"{sys.argv[2]}\"")


if __name__ == "__main__":
    main()