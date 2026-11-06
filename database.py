
"""
Database connection management and schema initialization.
"""

import os
import sqlite3

from flask import current_app, g


# SQLite connection settings.
CONNECTION_TIMEOUT = 30
BUSY_TIMEOUT_MS = 30000


def get_db():
    """Return the database connection for the current application context."""

    if "db" not in g:
        path = os.fspath(current_app.config["DATABASE"])

        # Create the database directory when using a file-based database.
        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)

        g.db = sqlite3.connect(
            path,
            timeout=CONNECTION_TIMEOUT
        )

        g.db.row_factory = sqlite3.Row

        # Enforce relationships and improve concurrent access handling.
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")

    return g.db


def close_db(_error=None):
    """Close the database connection when the application context ends."""

    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    """Create missing database tables and indexes without deleting records."""

    db = get_db()

    # Create tables only when they do not already exist.
    db.executescript("""
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
                CHECK(role IN ('admin', 'dean', 'security')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS checkout_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT NOT NULL UNIQUE,
            student_name TEXT NOT NULL,
            registration_number TEXT NOT NULL,
            phone TEXT NOT NULL,
            hostel TEXT NOT NULL,
            room_number TEXT NOT NULL,
            destination TEXT NOT NULL,
            departure_date TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'submitted',
            key_status TEXT NOT NULL DEFAULT 'pending',
            key_handled_by INTEGER,
            key_handled_at TEXT,
            payment_status TEXT,
            payment_reference TEXT,
            payment_due_date TEXT,
            key_remarks TEXT,
            exception_reason TEXT,
            approved_by INTEGER,
            approved_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(key_handled_by)
                REFERENCES staff(id),

            FOREIGN KEY(approved_by)
                REFERENCES staff(id)
        );

        CREATE TABLE IF NOT EXISTS gate_passes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL UNIQUE,
            token TEXT NOT NULL UNIQUE,
            issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            used_at TEXT,
            used_by INTEGER,
            revoked INTEGER NOT NULL DEFAULT 0,

            FOREIGN KEY(request_id)
                REFERENCES checkout_requests(id),

            FOREIGN KEY(used_by)
                REFERENCES staff(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(staff_id)
                REFERENCES staff(id)
        );

        -- Indexes for frequently used lookups and dashboard queries.
        CREATE INDEX IF NOT EXISTS idx_staff_role_active
            ON staff(role, active);

        CREATE INDEX IF NOT EXISTS idx_checkout_status_created
            ON checkout_requests(status, created_at);

        CREATE INDEX IF NOT EXISTS idx_checkout_registration
            ON checkout_requests(registration_number);

        CREATE INDEX IF NOT EXISTS idx_gate_pass_used_at
            ON gate_passes(used_at);

        CREATE INDEX IF NOT EXISTS idx_gate_pass_revoked
            ON gate_passes(revoked);

        CREATE INDEX IF NOT EXISTS idx_audit_created_at
            ON audit_logs(created_at);
    """)

    db.commit()
