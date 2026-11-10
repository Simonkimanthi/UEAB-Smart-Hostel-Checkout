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
            (3, "admin_user", "admin"),
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
        self.admin = app_module.app.test_client()

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
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
            CREATE TABLE staff_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                staff_id INTEGER NOT NULL,
                permission TEXT NOT NULL,
                allowed BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (staff_id) REFERENCES staff(id) ON DELETE CASCADE,
                UNIQUE (staff_id, permission)
            );
            CREATE TABLE staff_hostel_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                staff_id INTEGER NOT NULL,
                hostel TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (staff_id) REFERENCES staff(id) ON DELETE CASCADE,
                UNIQUE (staff_id, hostel)
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

    def _grant_permission(self, staff_id, permission):
        self.db.execute(
            """
            INSERT INTO staff_permissions (staff_id, permission, allowed)
            VALUES (?, ?, TRUE)
            ON CONFLICT (staff_id, permission) DO UPDATE SET allowed = TRUE
            """,
            (staff_id, permission),
        )
        self.db.commit()

    def _assign_hostel(self, staff_id, hostel):
        self.db.execute(
            """
            INSERT INTO staff_hostel_access (staff_id, hostel)
            VALUES (?, ?)
            ON CONFLICT (staff_id, hostel) DO NOTHING
            """,
            (staff_id, hostel),
        )
        self.db.commit()

    def _create_request(self, reference, hostel):
        cursor = self.db.execute(
            """
            INSERT INTO checkout_requests (
                reference, student_name, registration_number, phone,
                hostel, room_number, destination, departure_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reference,
                f"Student {reference}",
                f"UEAB/{reference}/26",
                "07000000000",
                hostel,
                "A-1",
                "Nairobi",
                "2026-12-01",
            ),
        )
        self.db.commit()
        return cursor.lastrowid

    def test_staff_session_survives_refresh_and_dashboard_is_fresh(self):
        self._grant_permission(1, "requests.view")
        self._assign_hostel(1, "New Men's Hostel")
        self._assign_hostel(1, "Box Hostel")
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
        for permission in (
            "requests.view",
            "keys.manage",
            "requests.approve",
            "passes.view",
        ):
            self._grant_permission(1, permission)
        self._assign_hostel(1, "New Men's Hostel")

        for permission in (
            "passes.view",
            "passes.verify",
            "departures.record",
        ):
            self._grant_permission(2, permission)

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
        self._grant_permission(2, "passes.view")
        self._login(self.security, "security_user", "/security")

        response = self.security.get("/dean")

        self.assertEqual(response.status_code, 403)
        self.assertIn(
            "Your account does not have permission",
            response.get_data(as_text=True),
        )

    def test_dean_is_scoped_on_dashboard_and_direct_urls(self):
        self._grant_permission(1, "requests.view")
        new_mens = self._create_request("mens", "New Men's Hostel")
        old_mens = self._create_request("old-mens", "Old Men's Hostel")
        self._grant_permission(1, "passes.view")
        self.db.execute(
            "UPDATE checkout_requests SET status = 'approved' WHERE id = ?",
            (old_mens,),
        )
        self.db.execute(
            "INSERT INTO gate_passes (request_id, token) VALUES (?, ?)",
            (old_mens, "outside-dean-pass"),
        )
        self.db.commit()
        self._login(self.dean, "dean_user", "/dean")

        dashboard = self.dean.get("/dean")
        self.assertNotIn("Student mens", dashboard.get_data(as_text=True))
        self.assertNotIn("Student old-mens", dashboard.get_data(as_text=True))
        self.assertEqual(self.dean.get(f"/dean/request/{new_mens}").status_code, 403)
        self.assertEqual(self.dean.get(f"/dean/request/{old_mens}").status_code, 403)
        self.assertEqual(self.dean.get(f"/dean/gate-pass/{old_mens}").status_code, 403)

        self._assign_hostel(1, "New Men's Hostel")
        dashboard = self.dean.get("/dean")
        self.assertIn("Student mens", dashboard.get_data(as_text=True))
        self.assertNotIn("Student old-mens", dashboard.get_data(as_text=True))
        self.assertEqual(self.dean.get(f"/dean/request/{old_mens}").status_code, 403)
        self.assertEqual(self.dean.get(f"/dean/gate-pass/{old_mens}").status_code, 403)

        self.assertEqual(self.dean.get(f"/dean/request/{new_mens}").status_code, 200)
        detail = self.dean.get(f"/dean/request/{new_mens}")
        for action in ("key", "approve"):
            denied_action = self.dean.post(
                f"/dean/request/{new_mens}",
                data={
                    "csrf_token": self._csrf_token(detail),
                    "action": action,
                },
            )
            self.assertEqual(denied_action.status_code, 403)

        self._assign_hostel(1, "Old Men's Hostel")
        dashboard = self.dean.get("/dean")
        self.assertIn("Student mens", dashboard.get_data(as_text=True))
        self.assertIn("Student old-mens", dashboard.get_data(as_text=True))
        self.assertEqual(self.dean.get(f"/dean/request/{old_mens}").status_code, 200)
        self.assertEqual(self.dean.get(f"/dean/gate-pass/{old_mens}").status_code, 200)

    def test_new_dean_has_no_hostel_access_until_assigned(self):
        self.db.execute(
            """
            INSERT INTO staff (
                id, full_name, username, password_hash, role, active
            )
            VALUES (4, 'New Dean', 'new_dean', ?, 'dean', 1)
            """,
            (generate_password_hash("test-password-123"),),
        )
        request_id = self._create_request("new-dean", "Box Hostel")
        self._grant_permission(4, "requests.view")
        self.db.commit()

        client = app_module.app.test_client()
        self._login(client, "new_dean", "/dean")
        self.assertNotIn("Student new-dean", client.get("/dean").get_data(as_text=True))
        self.assertEqual(client.get(f"/dean/request/{request_id}").status_code, 403)

        self._assign_hostel(4, "Box Hostel")
        self.assertIn("Student new-dean", client.get("/dean").get_data(as_text=True))
        self.assertEqual(client.get(f"/dean/request/{request_id}").status_code, 200)

    def test_security_can_view_passes_for_all_hostels_but_needs_permissions(self):
        self._grant_permission(2, "passes.view")
        pass_ids = []
        token = "security-token"

        for index, hostel in enumerate((
            "New Men's Hostel",
            "Old Men's Hostel",
            "Box Hostel",
            "Annex Hostel",
        )):
            request_id = self._create_request(f"security-{index}", hostel)
            cursor = self.db.execute(
                """
                INSERT INTO gate_passes (request_id, token)
                VALUES (?, ?)
                """,
                (request_id, f"{token}-{index}"),
            )
            self.db.commit()
            pass_ids.append(cursor.lastrowid)

        self._login(self.security, "security_user", "/security")
        dashboard = self.security.get("/security")
        dashboard_text = dashboard.get_data(as_text=True).replace("&#39;", "'")
        for hostel in (
            "New Men's Hostel",
            "Old Men's Hostel",
            "Box Hostel",
            "Annex Hostel",
        ):
            self.assertIn(hostel, dashboard_text)

        self.assertEqual(
            self.security.get(f"/security/verify?token={token}-0").status_code,
            403,
        )
        verification = self.security.get("/security/verify")
        self.assertEqual(
            self.security.post(
                f"/security/departure/{pass_ids[0]}",
                data={"csrf_token": self._csrf_token(verification)},
            ).status_code,
            403,
        )

        self._grant_permission(2, "passes.verify")
        self.assertEqual(
            self.security.get(f"/security/verify?token={token}-0").status_code,
            200,
        )

    def test_admin_has_unrestricted_access_without_explicit_grants(self):
        request_ids = [
            self._create_request(f"admin-{index}", hostel)
            for index, hostel in enumerate((
                "New Men's Hostel",
                "Old Men's Hostel",
                "Box Hostel",
                "Annex Hostel",
            ))
        ]
        self._login(self.admin, "admin_user", "/admin")

        dashboard = self.admin.get("/dean")
        for index in range(4):
            self.assertIn(f"Student admin-{index}", dashboard.get_data(as_text=True))
        self.assertEqual(
            self.admin.get(f"/dean/request/{request_ids[0]}").status_code,
            200,
        )

        access_page = self.admin.get("/admin")
        self.assertEqual(access_page.status_code, 200)
        self.assertIn("Full Access", access_page.get_data(as_text=True))

    def test_admin_access_changes_apply_immediately_and_are_audited(self):
        request_id = self._create_request("managed", "Annex Hostel")
        self._grant_permission(1, "requests.view")
        self._login(self.dean, "dean_user", "/dean")
        self.assertEqual(self.dean.get(f"/dean/request/{request_id}").status_code, 403)

        self._login(self.admin, "admin_user", "/admin")
        access_page = self.admin.get("/admin")
        response = self.admin.post(
            "/admin/staff/1/access",
            data={
                "csrf_token": self._csrf_token(access_page),
                "permissions": ["requests.view"],
                "hostels": ["Annex Hostel"],
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.dean.get(f"/dean/request/{request_id}").status_code, 200)

        log = self.db.execute(
            """
            SELECT staff_id, action, details
            FROM audit_logs
            WHERE action = 'staff_access_updated'
            """
        ).fetchone()
        self.assertEqual(log["staff_id"], 3)
        self.assertIn("Annex Hostel", log["details"])

        access_page = self.admin.get("/admin")
        self.admin.post(
            "/admin/staff/1/access",
            data={"csrf_token": self._csrf_token(access_page)},
        )
        self.assertEqual(self.dean.get(f"/dean/request/{request_id}").status_code, 403)


if __name__ == "__main__":
    unittest.main()
