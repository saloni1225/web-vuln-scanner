#!/usr/bin/env python3
"""
scripts/rotate_jwt_secret.py

Generates a new secure JWT secret and updates the .env file.

Usage:
    python scripts/rotate_jwt_secret.py            # Updates .env in place
    python scripts/rotate_jwt_secret.py --print    # Just prints the new secret

WARNING: Rotating the JWT secret invalidates ALL active sessions.
All logged-in users will be required to log in again.
"""
import argparse
import os
import secrets
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"


def generate_secret(length: int = 64) -> str:
    """Generate a cryptographically secure hex secret."""
    return secrets.token_hex(length)


def update_env_file(new_secret: str, env_path: Path) -> None:
    """Update ADAPTIVESCAN_JWT_SECRET in the .env file."""
    if not env_path.exists():
        print(f"[warn] {env_path} does not exist. Creating it with the new secret.")
        env_path.write_text(f"ADAPTIVESCAN_JWT_SECRET={new_secret}\n", encoding="utf-8")
        print(f"[ok] Created {env_path}")
        return

    content = env_path.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    updated = False
    new_lines = []

    for line in lines:
        if line.startswith("ADAPTIVESCAN_JWT_SECRET="):
            new_lines.append(f"ADAPTIVESCAN_JWT_SECRET={new_secret}\n")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(f"ADAPTIVESCAN_JWT_SECRET={new_secret}\n")

    env_path.write_text("".join(new_lines), encoding="utf-8")
    print(f"[ok] Updated ADAPTIVESCAN_JWT_SECRET in {env_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rotate the AdaptiveScan JWT secret.")
    parser.add_argument("--print", action="store_true", help="Only print the new secret, do not write to .env")
    parser.add_argument("--length", type=int, default=64, help="Secret byte length (default: 64)")
    args = parser.parse_args()

    new_secret = generate_secret(args.length)
    print(f"New JWT secret ({args.length * 2} hex chars):")
    print(f"  {new_secret}")

    if args.print:
        return

    print()
    confirm = input("Rotating the secret invalidates ALL active sessions. Continue? [y/N] ").strip().lower()
    if confirm != "y":
        print("[abort] Secret rotation cancelled.")
        return

    update_env_file(new_secret, ENV_FILE)
    print()
    print("[!] IMPORTANT: Restart your backend server for the new secret to take effect.")
    print("[!] All currently logged-in users will need to log in again.")


if __name__ == "__main__":
    main()
