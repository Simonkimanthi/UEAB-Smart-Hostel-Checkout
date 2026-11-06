"""
Create an administrator account for the UEAB Smart Hostel Checkout System.

This utility is intended for use by an authorized system operator.
"""

import getpass
import os
import re
import sqlite3
import sys

from werkzeug.security import generate_password_hash


# Add the project root to the Python import path.
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
sys.path.insert(0, PROJECT_ROOT)

from app import app
from database import get_db


def main():
    """Collect administrator details and create the account securely."""

    print("\nUEAB SMART HOSTEL CHECKOUT")
    print("ADMINISTRATOR ACCOUNT CREATION\n")

    # Collect administrator details without displaying passwords.
    try:
        full_name = input("Administrator full name: ").strip()
        username = input("Username: ").strip().lower()
        password = getpass.getpass("Password (minimum 12 characters): ")
        confirm = getpass.getpass("Confirm password: ")

    except (EOFError, KeyboardInterrupt):
        print("\nAccount creation cancelled.")
        return 1

    # Validate required fields and enforce input length limits.
    if not full_name or not username:
        print("Name and username are required.")
        return 1

    if len(full_name) > 100:
        print("Full name must not exceed 100 characters.")
        return 1

    # Enforce the username format used by staff management.
    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
        print(
            "Username must be 3–40 characters and contain only "
            "lowercase letters, numbers, dots, underscores or hyphens."
        )
        return 1

    # Enforce password length and confirmation.
    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return 1

    if password != confirm:
        print("Passwords do not match.")
        return 1

    try:
        # Establish the Flask application context for database access.
        with app.app_context():
            db = get_db()

            # Prevent creation of duplicate administrator usernames.
            existing = db.execute(
                "SELECT id FROM staff WHERE username = ?",
                (username,)
            ).fetchone()

            if existing:
                print("That username already exists.")
                return 1

            # Hash the password before storing it in the database.
            password_hash = generate_password_hash(password)

            # Insert the administrator account using parameterized SQL.
            db.execute(
                """
                INSERT INTO staff (
                    full_name,
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?, 'admin')
                """,
                (full_name, username, password_hash)
            )

            # Save the new administrator account.
            db.commit()

            print("\nAdministrator account created successfully.")
            return 0

    except sqlite3.IntegrityError:
        print("Account creation failed due to a database constraint.")
        return 1

    except sqlite3.Error:
        print("A database error prevented account creation.")
        return 1

    except (OSError, RuntimeError):
        print("An unexpected error prevented account creation.")
        return 1


# Run the account creation utility when executed directly.
if __name__ == "__main__":
    sys.exit(main())