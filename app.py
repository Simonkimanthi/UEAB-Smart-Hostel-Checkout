
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import date
from functools import wraps
from io import BytesIO
from base64 import b64encode

import qrcode
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import get_db, close_db, init_db


# ---------------------------------------------------------
# Application configuration and initialization
# ---------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

app.teardown_appcontext(close_db)

with app.app_context():
    init_db()


# ---------------------------------------------------------
# Basic security and request protection
# ---------------------------------------------------------

def csrf_token():
    """Create or retrieve the CSRF token for the current session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_forms():
    """Reject POST requests that do not contain a valid CSRF token."""
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")

        if (
            not submitted
            or not expected
            or not secrets.compare_digest(submitted, expected)
        ):
            abort(400, "Invalid or expired form security token.")


@app.after_request
def prevent_sensitive_page_caching(response):
    """Prevent browsers and intermediary caches from storing sensitive pages."""
    if request.endpoint in {
        "student_track",
        "login",
        "gate_pass",
        "public_gate_pass",
        "security_verify",
    }:
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"

    return response


# ---------------------------------------------------------
# In-memory rate limiting
# ---------------------------------------------------------

# These limits protect login and tracking endpoints from
# repeated automated requests within a single application process.
# For multiple production workers, use a shared rate-limit store.

_rate_limit_data = defaultdict(deque)
_rate_limit_lock = threading.Lock()

RATE_LIMITS = {
    "login": (5, 900),       # 5 attempts per 15 minutes
    "tracking": (10, 600),  # 10 attempts per 10 minutes
}


def check_rate_limit(action, identity):
    """Return True when the request is within its configured limit."""
    limit, window = RATE_LIMITS[action]
    now = time.monotonic()
    key = (action, identity)

    with _rate_limit_lock:
        attempts = _rate_limit_data[key]

        while attempts and now - attempts[0] >= window:
            attempts.popleft()

        if len(attempts) >= limit:
            return False

        attempts.append(now)

        # Remove expired entries to prevent unbounded memory growth.
        if len(_rate_limit_data) > 10000:
            expired_keys = [
                stored_key
                for stored_key, stored_attempts in _rate_limit_data.items()
                if not stored_attempts
                or now - stored_attempts[-1] >= window
            ]

            for stored_key in expired_keys:
                _rate_limit_data.pop(stored_key, None)

        return True


def client_identity():
    """Obtain the direct client address for request limiting."""
    return request.remote_addr or "unknown"


# ---------------------------------------------------------
# Database audit logging
# ---------------------------------------------------------

def audit(action, details="", commit=True):
    """
    Record an administrative or operational event.

    Set commit=False when the audit entry must be committed
    together with another database transaction.
    """
    db = get_db()

    db.execute(
        """
        INSERT INTO audit_logs (staff_id, action, details)
        VALUES (?, ?, ?)
        """,
        (
            session.get("staff_id"),
            action,
            details,
        ),
    )

    if commit:
        db.commit()


# ---------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------

def login_required(*roles):
    """Require an active staff account and optionally restrict its role."""

    def decorator(function):

        @wraps(function)
        def wrapped(*args, **kwargs):
            staff_id = session.get("staff_id")

            if not staff_id:
                return redirect(url_for("login"))

            staff = get_db().execute(
                """
                SELECT id, full_name, username, role, active
                FROM staff
                WHERE id = ?
                """,
                (staff_id,),
            ).fetchone()

            if staff is None or not staff["active"]:
                session.clear()

                flash(
                    "Your staff account is inactive or no longer exists. "
                    "Please sign in again.",
                    "error",
                )

                return redirect(url_for("login"))

            # Refresh account details from the database instead of
            # trusting potentially outdated session information.
            session["full_name"] = staff["full_name"]
            session["username"] = staff["username"]
            session["role"] = staff["role"]

            if roles and staff["role"] not in roles:
                abort(403)

            return function(*args, **kwargs)

        return wrapped

    return decorator


# ---------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------

def valid_text(value, maximum):
    """Check that a required text value is present and within its length."""
    return bool(value and len(value) <= maximum)


def valid_optional_text(value, maximum):
    """Check an optional text value without accepting excessive input."""
    return len(value) <= maximum


def valid_iso_date(value):
    """Validate a date supplied in ISO YYYY-MM-DD format."""
    try:
        date.fromisoformat(value)
        return True
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------
# Checkout clearance rules
# ---------------------------------------------------------

def clearance_eligible(record):
    """
    Determine whether a request meets the key-clearance requirements.

    A lost key marked as paid must have a recorded paid status
    and a payment reference before approval.
    """
    if record["key_status"] == "returned":
        return True

    if record["key_status"] == "lost_paid":
        return (
            record["payment_status"] == "paid"
            and bool(record["payment_reference"])
        )

    if record["key_status"] == "lost_agreed":
        return (
            record["payment_status"] == "agreed"
            and bool(record["payment_due_date"])
            and valid_iso_date(record["payment_due_date"])
        )

    if record["key_status"] == "exception":
        return bool(record["exception_reason"])

    return False


# ---------------------------------------------------------
# Public home page
# ---------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------
# Student checkout submission
# ---------------------------------------------------------

@app.route("/student/submit", methods=["GET", "POST"])
def student_submit():

    if request.method == "POST":

        fields = {
            "student_name": request.form.get("student_name", "").strip(),
            "registration_number": request.form.get(
                "registration_number", ""
            ).strip(),
            "phone": request.form.get("phone", "").strip(),
            "hostel": request.form.get("hostel", "").strip(),
            "room_number": request.form.get("room_number", "").strip(),
            "destination": request.form.get("destination", "").strip(),
            "departure_date": request.form.get(
                "departure_date", ""
            ).strip(),
            "reason": request.form.get("reason", "").strip(),
        }

        required_fields = (
            "student_name",
            "registration_number",
            "phone",
            "hostel",
            "room_number",
            "destination",
            "departure_date",
        )

        if any(not fields[field] for field in required_fields):
            flash("Please complete all required fields.", "error")
            return render_template("student/submit.html")

        # Enforce reasonable field lengths on the server.
        maximum_lengths = {
            "student_name": 100,
            "registration_number": 40,
            "phone": 30,
            "hostel": 60,
            "room_number": 30,
            "destination": 150,
            "departure_date": 10,
            "reason": 1000,
        }

        if any(
            not valid_optional_text(fields[field], maximum)
            for field, maximum in maximum_lengths.items()
        ):
            flash("One or more fields exceed the allowed length.", "error")
            return render_template("student/submit.html")

        if fields["hostel"] not in (
            "New Men's Hostel",
            "Old Men's Hostel",
            "Box Hostel",
            "Annex Hostel",
        ):
            flash("Please select a valid hostel.", "error")
            return render_template("student/submit.html")

        if not re.fullmatch(r"[0-9+().\-\s]{7,30}", fields["phone"]):
            flash("Please enter a valid phone number.", "error")
            return render_template("student/submit.html")

        if not valid_iso_date(fields["departure_date"]):
            flash("Please enter a valid departure date.", "error")
            return render_template("student/submit.html")

        # Generate a high-entropy private tracking reference.
        reference = secrets.token_urlsafe(24).upper()

        db = get_db()

        try:
            db.execute(
                """
                INSERT INTO checkout_requests (
                    reference,
                    student_name,
                    registration_number,
                    phone,
                    hostel,
                    room_number,
                    destination,
                    departure_date,
                    reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reference,
                    fields["student_name"],
                    fields["registration_number"],
                    fields["phone"],
                    fields["hostel"],
                    fields["room_number"],
                    fields["destination"],
                    fields["departure_date"],
                    fields["reason"],
                ),
            )

            db.commit()

        except sqlite3.Error:
            db.rollback()
            app.logger.exception("Checkout request submission failed.")

            flash(
                "Your request could not be submitted. Please try again.",
                "error",
            )

            return render_template("student/submit.html")

        return render_template(
            "student/success.html",
            reference=reference,
        )

    return render_template("student/submit.html")


# ---------------------------------------------------------
# Student request tracking
# ---------------------------------------------------------

@app.route("/student/track", methods=["GET", "POST"])
def student_track():
    record = None

    if request.method == "POST":

        if not check_rate_limit("tracking", client_identity()):
            abort(429, "Too many tracking attempts. Please try again later.")

        reference = request.form.get("reference", "").strip().upper()

        if not reference or len(reference) > 100:
            flash("Please enter a valid tracking reference.", "error")
            return render_template("student/track.html", record=None)

        # Retrieve only the information required by the student tracking page.
        record = get_db().execute(
            """
            SELECT
                reference,
                student_name,
                registration_number,
                hostel,
                room_number,
                departure_date,
                status,
                key_status
            FROM checkout_requests
            WHERE reference = ?
            """,
            (reference,),
        ).fetchone()

        if record is None:
            flash(
                "No request was found with that tracking reference.",
                "error",
            )

    return render_template("student/track.html", record=record)


# ---------------------------------------------------------
# Staff login
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        identity = f"{client_identity()}:{username}"

        if not check_rate_limit("login", identity):
            abort(429, "Too many login attempts. Please try again later.")

        if len(username) > 40 or len(password) > 1024:
            flash("Invalid username or password.", "error")
            return render_template("auth/login.html")

        staff = get_db().execute(
            """
            SELECT *
            FROM staff
            WHERE username = ? AND active = 1
            """,
            (username,),
        ).fetchone()

        if staff and check_password_hash(
            staff["password_hash"],
            password,
        ):
            # Clear the previous session to prevent session fixation.
            session.clear()

            session["staff_id"] = staff["id"]
            session["full_name"] = staff["full_name"]
            session["username"] = staff["username"]
            session["role"] = staff["role"]

            csrf_token()

            audit("staff_login", staff["username"])

            if staff["role"] == "security":
                return redirect(url_for("security_dashboard"))

            if staff["role"] == "dean":
                return redirect(url_for("dean_dashboard"))

            if staff["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            session.clear()
            flash("Your account has an invalid staff role.", "error")

        else:
            flash("Invalid username or password.", "error")

    return render_template("auth/login.html")


# ---------------------------------------------------------
# Staff logout
# ---------------------------------------------------------

@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    audit("staff_logout")

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# ---------------------------------------------------------
# Dean's Office dashboard
# ---------------------------------------------------------

@app.route("/dean")
@login_required("dean", "admin")
def dean_dashboard():

    records = get_db().execute(
        """
        SELECT *
        FROM checkout_requests
        ORDER BY created_at DESC
        """
    ).fetchall()

    return render_template(
        "dean/dashboard.html",
        records=records,
    )


# ---------------------------------------------------------
# Dean's Office request review and approval
# ---------------------------------------------------------

@app.route("/dean/request/<int:request_id>", methods=["GET", "POST"])
@login_required("dean", "admin")
def request_detail(request_id):

    db = get_db()

    record = db.execute(
        """
        SELECT *
        FROM checkout_requests
        WHERE id = ?
        """,
        (request_id,),
    ).fetchone()

    if record is None:
        abort(404)

    if request.method == "POST":

        action = request.form.get("action", "")

        # ---------------------------------------------
        # Record key disposition
        # ---------------------------------------------

        if action == "key":

            key_status = request.form.get("key_status", "").strip()
            payment_status = request.form.get(
                "payment_status", ""
            ).strip().lower()
            payment_reference = request.form.get(
                "payment_reference", ""
            ).strip()
            payment_due_date = request.form.get(
                "payment_due_date", ""
            ).strip()
            remarks = request.form.get("key_remarks", "").strip()
            exception_reason = request.form.get(
                "exception_reason", ""
            ).strip()

            allowed = (
                "returned",
                "lost_paid",
                "lost_agreed",
                "lost_unpaid",
                "exception",
            )

            if key_status not in allowed:
                flash("Invalid key disposition.", "error")
                return redirect(
                    url_for("request_detail", request_id=request_id)
                )

            if (
                not valid_optional_text(payment_reference, 100)
                or not valid_optional_text(payment_due_date, 10)
                or not valid_optional_text(remarks, 1000)
                or not valid_optional_text(exception_reason, 1000)
            ):
                flash("One or more fields exceed the allowed length.", "error")
                return redirect(
                    url_for("request_detail", request_id=request_id)
                )

            if record["status"] == "approved":
                flash(
                    "Key clearance cannot be changed after approval.",
                    "error",
                )
                return redirect(
                    url_for("request_detail", request_id=request_id)
                )

            if key_status == "lost_paid":
                if payment_status != "paid" or not payment_reference:
                    flash(
                        "A confirmed paid status and payment reference "
                        "are required for a lost key.",
                        "error",
                    )
                    return redirect(
                        url_for("request_detail", request_id=request_id)
                    )

            if key_status == "lost_agreed":
                if (
                    payment_status != "agreed"
                    or not payment_due_date
                    or not valid_iso_date(payment_due_date)
                ):
                    flash(
                        "A valid payment agreement and due date are required.",
                        "error",
                    )
                    return redirect(
                        url_for("request_detail", request_id=request_id)
                    )

            if key_status == "exception" and not exception_reason:
                flash(
                    "An explanation is required for an exception.",
                    "error",
                )
                return redirect(
                    url_for("request_detail", request_id=request_id)
                )

            try:
                db.execute("BEGIN IMMEDIATE")

                db.execute(
                    """
                    UPDATE checkout_requests
                    SET
                        key_status = ?,
                        key_handled_by = ?,
                        key_handled_at = CURRENT_TIMESTAMP,
                        payment_status = ?,
                        payment_reference = ?,
                        payment_due_date = ?,
                        key_remarks = ?,
                        exception_reason = ?
                    WHERE id = ?
                      AND status != 'approved'
                    """,
                    (
                        key_status,
                        session["staff_id"],
                        payment_status,
                        payment_reference,
                        payment_due_date or None,
                        remarks,
                        exception_reason,
                        request_id,
                    ),
                )

                if db.execute("SELECT changes()").fetchone()[0] != 1:
                    db.rollback()
                    flash(
                        "The request could not be updated. Refresh and try again.",
                        "error",
                    )
                    return redirect(
                        url_for("request_detail", request_id=request_id)
                    )

                audit(
                    "key_disposition_recorded",
                    f"Request {request_id}: {key_status}",
                    commit=False,
                )

                db.commit()

            except sqlite3.Error:
                db.rollback()
                app.logger.exception("Key clearance update failed.")

                flash(
                    "The key clearance could not be saved.",
                    "error",
                )

                return redirect(
                    url_for("request_detail", request_id=request_id)
                )

            flash("Key disposition recorded.", "success")

        # ---------------------------------------------
        # Approve request and issue gate pass
        # ---------------------------------------------

        elif action == "approve":

            try:
                db.execute("BEGIN IMMEDIATE")

                current = db.execute(
                    """
                    SELECT *
                    FROM checkout_requests
                    WHERE id = ?
                    """,
                    (request_id,),
                ).fetchone()

                if current is None:
                    db.rollback()
                    abort(404)

                if current["status"] == "approved":
                    db.rollback()
                    flash(
                        "This request has already been approved.",
                        "error",
                    )
                    return redirect(
                        url_for("request_detail", request_id=request_id)
                    )

                if current["status"] == "rejected":
                    db.rollback()
                    flash(
                        "A rejected request cannot be approved.",
                        "error",
                    )
                    return redirect(
                        url_for("request_detail", request_id=request_id)
                    )

                if not clearance_eligible(current):
                    db.rollback()
                    flash(
                        "Clearance cannot be approved until the key is "
                        "returned, payment is confirmed, or an authorized "
                        "exception or payment agreement is recorded.",
                        "error",
                    )
                    return redirect(
                        url_for("request_detail", request_id=request_id)
                    )

                # Generate a cryptographically secure gate pass token.
                token = secrets.token_urlsafe(32)

                db.execute(
                    """
                    UPDATE checkout_requests
                    SET
                        status = 'approved',
                        approved_by = ?,
                        approved_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        session["staff_id"],
                        request_id,
                    ),
                )

                db.execute(
                    """
                    INSERT INTO gate_passes (request_id, token)
                    VALUES (?, ?)
                    """,
                    (request_id, token),
                )

                audit(
                    "checkout_approved_and_pass_issued",
                    f"Request {request_id}",
                    commit=False,
                )

                db.commit()

            except sqlite3.Error:
                db.rollback()
                app.logger.exception("Checkout approval failed.")

                flash(
                    "Approval could not be completed. Please try again.",
                    "error",
                )

                return redirect(
                    url_for("request_detail", request_id=request_id)
                )

            flash(
                "Clearance approved and gate pass issued.",
                "success",
            )

        else:
            abort(400)

        return redirect(
            url_for("request_detail", request_id=request_id)
        )

    return render_template(
        "dean/request_detail.html",
        record=record,
    )


# ---------------------------------------------------------
# Generate and display an official gate pass
# ---------------------------------------------------------

@app.route("/dean/gate-pass/<int:request_id>")
@login_required("dean", "admin")
def gate_pass(request_id):

    record = get_db().execute(
        """
        SELECT
            r.*,
            p.token,
            p.issued_at,
            p.used_at,
            p.revoked
        FROM checkout_requests r
        JOIN gate_passes p ON p.request_id = r.id
        WHERE r.id = ?
          AND r.status = 'approved'
        """,
        (request_id,),
    ).fetchone()

    if record is None:
        abort(404)

    verify_url = url_for(
        "public_gate_pass",
        token=record["token"],
        _external=True,
    )

    qr = qrcode.make(verify_url)

    buffer = BytesIO()
    qr.save(buffer, format="PNG")

    qr_image = b64encode(buffer.getvalue()).decode("ascii")

    return render_template(
        "dean/gate_pass.html",
        record=record,
        qr_image=qr_image,
        public_view=False,
    )


# ---------------------------------------------------------
# Public read-only gate pass verification page
# ---------------------------------------------------------

@app.route("/pass/<token>")
def public_gate_pass(token):
    """Display a read-only gate pass using its private QR token."""

    if not token or len(token) > 200:
        abort(404)

    record = get_db().execute(
        """
        SELECT
            p.*,
            r.student_name,
            r.registration_number,
            r.hostel,
            r.room_number,
            r.destination,
            r.departure_date,
            r.status
        FROM gate_passes p
        JOIN checkout_requests r ON r.id = p.request_id
        WHERE p.token = ?
        """,
        (token,),
    ).fetchone()

    if record is None:
        abort(404)

    verify_url = url_for(
        "public_gate_pass",
        token=token,
        _external=True,
    )

    qr = qrcode.make(verify_url)

    buffer = BytesIO()
    qr.save(buffer, format="PNG")

    qr_image = b64encode(buffer.getvalue()).decode("ascii")

    return render_template(
        "dean/gate_pass.html",
        record=record,
        qr_image=qr_image,
        public_view=True,
    )


# ---------------------------------------------------------
# Campus Security dashboard
# ---------------------------------------------------------

@app.route("/security")
@login_required("security", "admin")
def security_dashboard():

    db = get_db()

    passes = db.execute(
        """
        SELECT
            p.*,
            r.student_name,
            r.registration_number,
            r.hostel,
            r.room_number,
            r.departure_date,
            r.status
        FROM gate_passes p
        JOIN checkout_requests r ON r.id = p.request_id
        ORDER BY p.issued_at DESC
        """
    ).fetchall()

    return render_template(
        "security/dashboard.html",
        passes=passes,
    )


# ---------------------------------------------------------
# Security gate pass verification
# ---------------------------------------------------------

@app.route("/security/verify", methods=["GET"])
@login_required("security", "admin")
def security_verify():

    token = request.args.get("token", "").strip()
    record = None

    if token and len(token) <= 200:

        record = get_db().execute(
            """
            SELECT
                p.*,
                r.student_name,
                r.registration_number,
                r.hostel,
                r.room_number,
                r.departure_date,
                r.status
            FROM gate_passes p
            JOIN checkout_requests r ON r.id = p.request_id
            WHERE p.token = ?
            """,
            (token,),
        ).fetchone()

    return render_template(
        "security/verify.html",
        token=token,
        record=record,
    )


# ---------------------------------------------------------
# Security departure recording
# ---------------------------------------------------------

@app.route("/security/departure/<int:pass_id>", methods=["POST"])
@login_required("security", "admin")
def record_departure(pass_id):

    db = get_db()
    record = None

    try:
        db.execute("BEGIN IMMEDIATE")

        # The conditional update prevents a revoked, previously used,
        # or unapproved pass from being used to record a departure.
        result = db.execute(
            """
            UPDATE gate_passes
            SET
                used_at = CURRENT_TIMESTAMP,
                used_by = ?
            WHERE
                id = ?
                AND revoked = 0
                AND used_at IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM checkout_requests r
                    WHERE r.id = gate_passes.request_id
                      AND r.status = 'approved'
                )
            """,
            (
                session["staff_id"],
                pass_id,
            ),
        )

        if result.rowcount == 1:

            audit(
                "student_departure_recorded",
                f"Gate pass ID {pass_id}",
                commit=False,
            )

            db.commit()

            flash(
                "Student departure successfully recorded.",
                "success",
            )

            return redirect(
                url_for("security_dashboard")
            )

        db.rollback()

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Departure recording failed.")

        flash(
            "Departure could not be recorded. Please try again.",
            "error",
        )

        return redirect(
            url_for("security_dashboard")
        )

    # Retrieve the pass after the failed conditional update so that
    # Security receives an accurate explanation of its current state.
    record = db.execute(
        """
        SELECT
            p.token,
            p.revoked,
            p.used_at,
            r.status
        FROM gate_passes p
        JOIN checkout_requests r ON r.id = p.request_id
        WHERE p.id = ?
        """,
        (pass_id,),
    ).fetchone()

    if record is None:
        abort(404)

    if record["revoked"]:
        flash("This gate pass has been revoked.", "error")

    elif record["used_at"]:
        flash(
            "Departure has already been recorded for this pass.",
            "error",
        )

    else:
        flash(
            "This pass is not approved for departure.",
            "error",
        )

    return redirect(
        url_for(
            "security_verify",
            token=record["token"],
        )
    )


# ---------------------------------------------------------
# Administration: create staff accounts
# ---------------------------------------------------------

@app.route("/admin/staff/create", methods=["POST"])
@login_required("admin")
def create_staff():

    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()

    if not valid_text(full_name, 100):
        flash("Enter a valid full name.", "error")
        return redirect(url_for("admin_dashboard"))

    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
        flash(
            "Username must be 3–40 characters using letters, numbers, "
            "dots, underscores or hyphens.",
            "error",
        )
        return redirect(url_for("admin_dashboard"))

    if len(password) < 12 or len(password) > 1024:
        flash(
            "Temporary passwords must contain 12–1024 characters.",
            "error",
        )
        return redirect(url_for("admin_dashboard"))

    if role not in ("admin", "dean", "security"):
        abort(400, "Invalid staff role.")

    db = get_db()

    try:
        db.execute("BEGIN IMMEDIATE")

        exists = db.execute(
            """
            SELECT id
            FROM staff
            WHERE lower(username) = ?
            """,
            (username,),
        ).fetchone()

        if exists:
            db.rollback()
            flash("That username is already in use.", "error")
            return redirect(url_for("admin_dashboard"))

        db.execute(
            """
            INSERT INTO staff (
                full_name,
                username,
                password_hash,
                role,
                active
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                full_name,
                username,
                generate_password_hash(password),
                role,
            ),
        )

        audit(
            "staff_created",
            f"Created {role} account: {username}",
            commit=False,
        )

        db.commit()

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Staff account creation failed.")

        flash(
            "The staff account could not be created.",
            "error",
        )

        return redirect(url_for("admin_dashboard"))

    flash("Staff account created successfully.", "success")

    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------
# Administration: update staff details
# ---------------------------------------------------------

@app.route("/admin/staff/<int:staff_id>/update", methods=["POST"])
@login_required("admin")
def update_staff(staff_id):

    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "").strip()

    if not valid_text(full_name, 100):
        flash("Enter a valid full name.", "error")
        return redirect(url_for("admin_dashboard"))

    if role not in ("admin", "dean", "security"):
        abort(400, "Invalid staff role.")

    db = get_db()

    try:
        db.execute("BEGIN IMMEDIATE")

        member = db.execute(
            """
            SELECT *
            FROM staff
            WHERE id = ?
            """,
            (staff_id,),
        ).fetchone()

        if member is None:
            db.rollback()
            abort(404)

        if (
            staff_id == session.get("staff_id")
            and role != member["role"]
        ):
            db.rollback()
            flash(
                "You cannot change your own administrator role.",
                "error",
            )
            return redirect(url_for("admin_dashboard"))

        if (
            member["active"]
            and member["role"] == "admin"
            and role != "admin"
        ):
            active_admins = db.execute(
                """
                SELECT COUNT(*)
                FROM staff
                WHERE role = 'admin' AND active = 1
                """
            ).fetchone()[0]

            if active_admins <= 1:
                db.rollback()
                flash(
                    "The last active administrator cannot be demoted.",
                    "error",
                )
                return redirect(url_for("admin_dashboard"))

        db.execute(
            """
            UPDATE staff
            SET full_name = ?, role = ?
            WHERE id = ?
            """,
            (
                full_name,
                role,
                staff_id,
            ),
        )

        audit(
            "staff_updated",
            f"Updated staff account ID {staff_id}",
            commit=False,
        )

        db.commit()

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Staff account update failed.")

        flash(
            "Staff details could not be updated.",
            "error",
        )

        return redirect(url_for("admin_dashboard"))

    flash("Staff details updated.", "success")

    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------
# Administration: reset staff passwords
# ---------------------------------------------------------

@app.route(
    "/admin/staff/<int:staff_id>/reset-password",
    methods=["POST"],
)
@login_required("admin")
def reset_staff_password(staff_id):

    password = request.form.get("new_password", "")
    confirmation = request.form.get("confirm_password", "")

    if len(password) < 12 or len(password) > 1024:
        flash(
            "Passwords must contain 12–1024 characters.",
            "error",
        )
        return redirect(url_for("admin_dashboard"))

    if password != confirmation:
        flash(
            "The password confirmation does not match.",
            "error",
        )
        return redirect(url_for("admin_dashboard"))

    db = get_db()

    try:
        db.execute("BEGIN IMMEDIATE")

        member = db.execute(
            """
            SELECT id, username
            FROM staff
            WHERE id = ?
            """,
            (staff_id,),
        ).fetchone()

        if member is None:
            db.rollback()
            abort(404)

        db.execute(
            """
            UPDATE staff
            SET password_hash = ?
            WHERE id = ?
            """,
            (
                generate_password_hash(password),
                staff_id,
            ),
        )

        audit(
            "staff_password_reset",
            f"Password reset for account: {member['username']}",
            commit=False,
        )

        db.commit()

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Staff password reset failed.")

        flash(
            "The password could not be reset.",
            "error",
        )

        return redirect(url_for("admin_dashboard"))

    flash("Staff password reset successfully.", "success")

    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------
# Administration: activate or deactivate staff accounts
# ---------------------------------------------------------

@app.route(
    "/admin/staff/<int:staff_id>/toggle",
    methods=["POST"],
)
@login_required("admin")
def toggle_staff(staff_id):

    db = get_db()

    try:
        db.execute("BEGIN IMMEDIATE")

        member = db.execute(
            """
            SELECT id, username, role, active
            FROM staff
            WHERE id = ?
            """,
            (staff_id,),
        ).fetchone()

        if member is None:
            db.rollback()
            abort(404)

        if (
            staff_id == session.get("staff_id")
            and member["active"]
        ):
            db.rollback()
            flash(
                "You cannot deactivate your own account.",
                "error",
            )
            return redirect(url_for("admin_dashboard"))

        new_status = 0 if member["active"] else 1

        if member["active"] and member["role"] == "admin":

            active_admins = db.execute(
                """
                SELECT COUNT(*)
                FROM staff
                WHERE role = 'admin' AND active = 1
                """
            ).fetchone()[0]

            if active_admins <= 1:
                db.rollback()
                flash(
                    "The last active administrator cannot be deactivated.",
                    "error",
                )
                return redirect(url_for("admin_dashboard"))

        db.execute(
            """
            UPDATE staff
            SET active = ?
            WHERE id = ?
            """,
            (
                new_status,
                staff_id,
            ),
        )

        action = (
            "staff_deactivated"
            if not new_status
            else "staff_activated"
        )

        audit(
            action,
            f"Account: {member['username']}",
            commit=False,
        )

        db.commit()

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Staff account status update failed.")

        flash(
            "Staff account status could not be updated.",
            "error",
        )

        return redirect(url_for("admin_dashboard"))

    flash("Staff account status updated.", "success")

    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------
# Administration dashboard
# ---------------------------------------------------------

@app.route("/admin")
@login_required("admin")
def admin_dashboard():

    db = get_db()

    stats = {
        "total_requests": db.execute(
            """
            SELECT COUNT(*)
            FROM checkout_requests
            """
        ).fetchone()[0],

        "pending_requests": db.execute(
            """
            SELECT COUNT(*)
            FROM checkout_requests
            WHERE status IN ('submitted', 'in_review', 'pending')
            """
        ).fetchone()[0],

        "approved_requests": db.execute(
            """
            SELECT COUNT(*)
            FROM checkout_requests
            WHERE status = 'approved'
            """
        ).fetchone()[0],

        "active_staff": db.execute(
            """
            SELECT COUNT(*)
            FROM staff
            WHERE active = 1
            """
        ).fetchone()[0],

        "issued_passes": db.execute(
            """
            SELECT COUNT(*)
            FROM gate_passes
            """
        ).fetchone()[0],

        "departed_passes": db.execute(
            """
            SELECT COUNT(*)
            FROM gate_passes
            WHERE used_at IS NOT NULL
            """
        ).fetchone()[0],
    }

    staff = db.execute(
        """
        SELECT
            id,
            full_name,
            username,
            role,
            active,
            created_at
        FROM staff
        ORDER BY role, full_name
        """
    ).fetchall()

    departures = db.execute(
        """
        SELECT
            r.student_name,
            r.registration_number,
            r.hostel,
            r.room_number,
            p.used_at,
            s.full_name AS officer
        FROM gate_passes p
        JOIN checkout_requests r ON r.id = p.request_id
        LEFT JOIN staff s ON s.id = p.used_by
        WHERE p.used_at IS NOT NULL
        ORDER BY p.used_at DESC
        LIMIT 10
        """
    ).fetchall()

    outstanding = db.execute(
        """
        SELECT
            student_name,
            registration_number,
            key_status,
            payment_due_date,
            payment_reference
        FROM checkout_requests
        WHERE key_status IN ('lost_unpaid', 'lost_agreed')
        ORDER BY created_at DESC
        LIMIT 20
        """
    ).fetchall()

    logs = db.execute(
        """
        SELECT
            a.created_at,
            a.action,
            a.details,
            s.full_name
        FROM audit_logs a
        LEFT JOIN staff s ON s.id = a.staff_id
        ORDER BY a.created_at DESC
        LIMIT 100
        """
    ).fetchall()

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        staff=staff,
        departures=departures,
        outstanding=outstanding,
        logs=logs,
    )


# ---------------------------------------------------------
# Administration activity and audit history
# ---------------------------------------------------------

@app.route("/admin/activity")
@login_required("admin")
def admin_activity():

    db = get_db()

    departures = db.execute(
        """
        SELECT
            r.student_name,
            r.registration_number,
            r.hostel,
            r.room_number,
            r.destination,
            p.issued_at,
            p.used_at,
            p.revoked,
            s.full_name AS officer
        FROM gate_passes p
        JOIN checkout_requests r ON r.id = p.request_id
        LEFT JOIN staff s ON s.id = p.used_by
        ORDER BY p.issued_at DESC
        """
    ).fetchall()

    logs = db.execute(
        """
        SELECT
            a.*,
            s.full_name,
            s.username
        FROM audit_logs a
        LEFT JOIN staff s ON s.id = a.staff_id
        ORDER BY a.created_at DESC
        LIMIT 200
        """
    ).fetchall()

    return render_template(
        "admin/activity.html",
        departures=departures,
        logs=logs,
    )


# ---------------------------------------------------------
# Development entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run()
