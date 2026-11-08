import importlib
import re
import sqlite3
import unittest
from unittest.mock import patch

import database
from werkzeug.security import generate_password_hash


with patch.object(database, "init_db"):
    app_module = importlib.import_module("app")


class SessionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self._create_schema()

        for staff_id, username, role in (
            (1, "dean_user", "dean"),
            (2, "security_user", "security"),
        ):
            self.db.execute(
                """
                INSERT INTO staff (
                    id, full_name, username, password_hash, role, active
                )
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (
                    staff_id,
                    f"{role.title()} User",
                    username,
                    generate_password_hash("test-password-123"),
                    role,
                ),
            )
        self.db.commit()

        self.original_config = app_module.app.config.copy()
        app_module.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret",
            SESSION_COOKIE_SECURE=False,
        )
        self.get_db_patcher = patch.object(
            app_module,
            "get_db",
            return_value=self.db,
        )
        self.get_db_patcher.start()
        app_module._rate_limit_data.clear()

        self.dean = app_module.app.test_client()
        self.security = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patcher.stop()
        app_module.app.config.clear()
        app_module.app.config.update(self.original_config)
        self.db.close()

    def _create_schema(self):
        self.db.executescript(
            """
            CREATE TABLE staff (
                id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL
            );
            CREATE TABLE checkout_requests (
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE gate_passes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL UNIQUE,
                token TEXT NOT NULL UNIQUE,
                issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                used_at TEXT,
                used_by INTEGER,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                staff_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

    @staticmethod
    def _csrf_token(response):
        match = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            response.get_data(as_text=True),
        )
        if match is None:
            raise AssertionError("Response did not contain a CSRF token.")
        return match.group(1)

    def _login(self, client, username, dashboard_path):
        login_page = client.get("/login")
        response = client.post(
            "/login",
            data={
                "csrf_token": self._csrf_token(login_page),
                "username": username,
                "password": "test-password-123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(dashboard_path, response.request.path)
        return login_page

    def _submit_student_request(self):
        page = self.dean.get("/student/submit")
        response = self.dean.post(
            "/student/submit",
            data={
                "csrf_token": self._csrf_token(page),
                "student_name": "Test Student",
                "registration_number": "UEAB/123/26",
                "phone": "+254700000000",
                "hostel": "New Men's Hostel",
                "room_number": "A-12",
                "destination": "Nairobi",
                "departure_date": "2026-12-01",
                "reason": "Test workflow",
            },
        )
        self.assertEqual(response.status_code, 200)
        record = self.db.execute(
            "SELECT id, reference FROM checkout_requests"
        ).fetchone()
        self.assertIsNotNone(record)

        tracking_page = self.dean.get("/student/track")
        tracked = self.dean.post(
            "/student/track",
            data={
                "csrf_token": self._csrf_token(tracking_page),
                "reference": record["reference"],
            },
        )
        self.assertIn("Test Student", tracked.get_data(as_text=True))
        return record

    def test_staff_session_survives_refresh_and_dashboard_is_fresh(self):
        login_page = self.dean.get("/login")
        old_token = self._csrf_token(login_page)
        response = self.dean.post(
            "/login",
            data={
                "csrf_token": old_token,
                "username": "dean_user",
                "password": "test-password-123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.request.path, "/dean")

        with self.dean.session_transaction() as staff_session:
            self.assertTrue(staff_session.permanent)
            self.assertEqual(staff_session["role"], "dean")

        self.db.execute(
            """
            INSERT INTO checkout_requests (
                reference, student_name, registration_number, phone,
                hostel, room_number, destination, departure_date
            )
            VALUES (
                'fresh-reference', 'New Request Student', 'UEAB/456/26',
                '07000000000', 'Box Hostel', 'B-1', 'Kisumu', '2026-12-02'
            )
            """
        )
        self.db.commit()

        refreshed = self.dean.get("/dean")
        self.assertEqual(refreshed.status_code, 200)
        self.assertIn("New Request Student", refreshed.get_data(as_text=True))
        self.assertEqual(
            refreshed.headers["Cache-Control"],
            "no-store, private",
        )

        stale_form = self.dean.post(
            "/logout",
            data={"csrf_token": old_token},
        )
        self.assertEqual(stale_form.status_code, 400)
        self.assertIn(
            "Reload the page and submit again",
            stale_form.get_data(as_text=True),
        )

    def test_student_to_dean_approval_and_security_departure(self):
        record = self._submit_student_request()

        self._login(self.dean, "dean_user", "/dean")
        dashboard = self.dean.get("/dean")
        self.assertIn(
            "Test Student",
            dashboard.get_data(as_text=True),
        )

        details = self.dean.get(f"/dean/request/{record['id']}")
        key_update = self.dean.post(
            f"/dean/request/{record['id']}",
            data={
                "csrf_token": self._csrf_token(details),
                "action": "key",
                "key_status": "returned",
            },
        )
        self.assertEqual(key_update.status_code, 302)

        details = self.dean.get(f"/dean/request/{record['id']}")
        approval = self.dean.post(
            f"/dean/request/{record['id']}",
            data={
                "csrf_token": self._csrf_token(details),
                "action": "approve",
            },
        )
        self.assertEqual(approval.status_code, 302)

        gate_pass = self.db.execute(
            "SELECT id, token FROM gate_passes WHERE request_id = ?",
            (record["id"],),
        ).fetchone()
        self.assertIsNotNone(gate_pass)

        qr_page = self.dean.get(f"/dean/gate-pass/{record['id']}")
        self.assertEqual(qr_page.status_code, 200)
        self.assertIn("data:image/png;base64,", qr_page.get_data(as_text=True))

        public_pass = self.dean.get(f"/pass/{gate_pass['token']}")
        self.assertEqual(public_pass.status_code, 200)
        self.assertIn(
            "data:image/png;base64,",
            public_pass.get_data(as_text=True),
        )

        self._login(self.security, "security_user", "/security")
        verification = self.security.get(
            f"/security/verify?token={gate_pass['token']}"
        )
        departure = self.security.post(
            f"/security/departure/{gate_pass['id']}",
            data={"csrf_token": self._csrf_token(verification)},
        )
        self.assertEqual(departure.status_code, 302)

        used_pass = self.db.execute(
            "SELECT used_at FROM gate_passes WHERE id = ?",
            (gate_pass["id"],),
        ).fetchone()
        self.assertIsNotNone(used_pass["used_at"])

    def test_wrong_role_shows_specific_forbidden_reason(self):
        self._login(self.security, "security_user", "/security")

        response = self.security.get("/dean")

        self.assertEqual(response.status_code, 403)
        self.assertIn(
            "Your account does not have permission",
            response.get_data(as_text=True),
        )


if __name__ == "__main__":
    unittest.main()
