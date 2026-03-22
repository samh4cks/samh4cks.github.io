#!/usr/bin/env python3
"""
decrypt_md.py  —  Restore a post to original markdown after machine retires.

Usage:
    python3 decrypt_md.py _posts/your-post.md "root-flag-here"

Example:
    python3 decrypt_md.py _posts/2026-03-21-hackthebox-cctv.md "8f680a1118cd22d81afbda7af9bea42d"

Requires:
    pip install pyyaml
"""

import sys
from pathlib import Path


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 decrypt_md.py <post.md> <root_flag>")
        sys.exit(1)

    path = Path(sys.argv[1])

    backup_dir  = path.parent.parent / "_backups"
    backup_path = backup_dir / path.name.replace(".md", ".bak")

    if not backup_path.exists():
        print(f"Error: No backup found at {backup_path}")
        print("       Was this post encrypted with encrypt_md.py?")
        sys.exit(1)

    original = backup_path.read_text(encoding="utf-8")
    path.write_text(original, encoding="utf-8")

    print(f"✓ Restored      →  {path}")
    print(f"  From backup   →  {backup_path}")
    print()
    print("Commit and push the restored file.")


if __name__ == "__main__":
    main()