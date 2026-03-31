import os
import os
import secrets
import shutil
import sqlite3
from io import BytesIO
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
from urllib.parse import quote

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, send_from_directory, jsonify, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional Postgres support
POSTGRES_ENABLED = False
try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_ENABLED = True
except Exception:
    POSTGRES_ENABLED = False

# Optional Google Sheets sync
GOOGLE_SHEETS_ENABLED = False
try:
    import gspread
    from google.oauth2.service_account import Credentials
    GOOGLE_SHEETS_ENABLED = True
except Exception:
    GOOGLE_SHEETS_ENABLED = False

# =========================
# CONFIG
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
PERSISTENT_DISK_PATH = os.environ.get("RENDER_DISK_PATH", "").strip()
DEFAULT_SQLITE_DATABASE = os.path.join(BASE_DIR, "attendance.db")
SQLITE_DATABASE = os.environ.get("SQLITE_DATABASE_PATH", "").strip() or (
    os.path.join(PERSISTENT_DISK_PATH, "attendance.db") if PERSISTENT_DISK_PATH else DEFAULT_SQLITE_DATABASE
)
DEFAULT_BACKUP_FOLDER = os.path.join(BASE_DIR, "backups")
BACKUP_FOLDER = os.environ.get("BACKUP_FOLDER", "").strip() or (
    os.path.join(PERSISTENT_DISK_PATH, "backups") if PERSISTENT_DISK_PATH else DEFAULT_BACKUP_FOLDER
)
DEFAULT_UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "").strip() or (
    os.path.join(PERSISTENT_DISK_PATH, "uploads") if PERSISTENT_DISK_PATH else DEFAULT_UPLOAD_FOLDER
)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "webp"}

GOOGLE_CREDENTIALS_FILE = os.path.join(BASE_DIR, "attendance-credentials.json")
GOOGLE_SHEET_NAME = "Attendance Tracker"
GOOGLE_SHEET_TAB = "Attendance Logs"

APP_TIMEZONE = ZoneInfo("America/New_York")
DEFAULT_SHIFT_START = "09:00"
DEFAULT_SHIFT_END = "18:00"
DEFAULT_SCHEDULE_DAYS = "Mon,Tue,Wed,Thu,Fri"
DEFAULT_BREAK_WINDOW_START = "12:00"
DEFAULT_BREAK_WINDOW_END = "12:15"
WEEKDAY_OPTIONS = [
    ("Mon", "Monday"),
    ("Tue", "Tuesday"),
    ("Wed", "Wednesday"),
    ("Thu", "Thursday"),
    ("Fri", "Friday"),
    ("Sat", "Saturday"),
    ("Sun", "Sunday"),
]
LATE_GRACE_MINUTES = 1
BREAK_LIMIT_MINUTES = 15
INCIDENT_ACTION_STATUSES = ("Coaching", "Suspension", "NTE")
DISCIPLINARY_ACTION_TYPES = ("Coaching", "NTE", "Suspension")
ATTENDANCE_REQUEST_TYPES = {
    "Missed Time In",
    "Missed Time Out",
    "Wrong Break",
    "Wrong Proof",
    "Undertime",
    "Sick Leave",
    "Paid Leave",
    "Other",
}
LEAVE_REQUEST_TYPES = {"Sick Leave", "Paid Leave"}
DEFAULT_SICK_LEAVE_DAYS = 7
DEFAULT_PAID_LEAVE_DAYS = 7

DEFAULT_SECRET_KEY = "dev-secret-key"


def is_production_environment():
    return any([
        os.environ.get("RENDER"),
        os.environ.get("RENDER_EXTERNAL_URL"),
        os.environ.get("DATABASE_URL"),
        os.environ.get("FLASK_ENV") == "production",
    ])


def get_configured_secret_key():
    secret_key = os.environ.get("SECRET_KEY", DEFAULT_SECRET_KEY).strip() or DEFAULT_SECRET_KEY
    if secret_key == DEFAULT_SECRET_KEY and is_production_environment():
        raise RuntimeError(
            "SECRET_KEY must be set to a strong random value in production before the app can start."
        )
    return secret_key


app = Flask(__name__)
app.secret_key = get_configured_secret_key()
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = is_production_environment()


# =========================
# TIME HELPERS
# =========================
def now_dt():
    return datetime.now(APP_TIMEZONE)


def now_str():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return now_dt().strftime("%Y-%m-%d")


def now_timestamp():
    return int(now_dt().timestamp())


def ensure_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": ensure_csrf_token()}


@app.before_request
def verify_csrf_token():
    if request.method != "POST":
        return None

    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token", "")
    if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
        flash("Your session expired or the form is no longer valid. Please try again.", "danger")
        return redirect(request.referrer or url_for("login"))

    return None


# =========================
# DATABASE HELPERS
# =========================
def using_postgres():
    return bool(DATABASE_URL) and POSTGRES_ENABLED


def get_db():
    if "db" not in g:
        if using_postgres():
            g.db = psycopg2.connect(DATABASE_URL)
        else:
            g.db = sqlite3.connect(SQLITE_DATABASE)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def convert_query(query: str) -> str:
    return query.replace("?", "%s")


def fetchone(query, params=()):
    db = get_db()
    if using_postgres():
        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(convert_query(query), params)
            return cur.fetchone()
    cur = db.execute(query, params)
    return cur.fetchone()


def fetchall(query, params=()):
    db = get_db()
    if using_postgres():
        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(convert_query(query), params)
            return cur.fetchall()
    cur = db.execute(query, params)
    return cur.fetchall()


def execute_db(query, params=(), commit=False):
    db = get_db()
    if using_postgres():
        with db.cursor() as cur:
            cur.execute(convert_query(query), params)
        if commit:
            db.commit()
    else:
        db.execute(query, params)
        if commit:
            db.commit()


# =========================
# BASIC HELPERS
# =========================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_image(filename):
    if not filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    return ext in {"png", "jpg", "jpeg", "gif", "webp"}


def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))

            user = get_user_by_id(session["user_id"])
            if not user:
                session.clear()
                flash("Your session expired. Please log in again.", "warning")
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash("Access denied.", "danger")
                if session.get("role") == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# =========================
# DATABASE INIT / MIGRATION
# =========================
def init_db():
    if using_postgres():
        init_postgres_db()
    else:
        init_sqlite_db()


def init_sqlite_db():
    db = sqlite3.connect(SQLITE_DATABASE)
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee',
            profile_image TEXT,
            department TEXT DEFAULT 'Stellar Seats',
            position TEXT DEFAULT 'Employee',
            emergency_contact_name TEXT,
            emergency_contact_phone TEXT,
            id_issue_date TEXT,
            id_expiration_date TEXT,
            barcode_id TEXT,
            hourly_rate REAL NOT NULL DEFAULT 0,
            sick_leave_days INTEGER NOT NULL DEFAULT 7,
            paid_leave_days INTEGER NOT NULL DEFAULT 7,
            sick_leave_used_manual INTEGER NOT NULL DEFAULT 0,
            paid_leave_used_manual INTEGER NOT NULL DEFAULT 0,
            whatsapp_number TEXT,
            schedule_days TEXT DEFAULT 'Mon,Tue,Wed,Thu,Fri',
            shift_start TEXT DEFAULT '09:00',
            shift_end TEXT DEFAULT '18:00',
            break_window_start TEXT DEFAULT '12:00',
            break_window_end TEXT DEFAULT '12:15',
            break_limit_minutes INTEGER NOT NULL DEFAULT 15,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            employee_name TEXT,
            report_department TEXT,
            error_type TEXT NOT NULL,
            incident_action TEXT DEFAULT 'Coaching',
            incident_date TEXT,
            report_date TEXT NOT NULL,
            message TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            admin_note TEXT,
            created_by INTEGER,
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            work_date TEXT NOT NULL,
            time_in TEXT,
            time_out TEXT,
            status TEXT DEFAULT 'Offline',
            proof_file TEXT,
            notes TEXT,
            late_flag INTEGER NOT NULL DEFAULT 0,
            late_minutes INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS breaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            attendance_id INTEGER,
            work_date TEXT NOT NULL,
            break_start TEXT,
            break_end TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (attendance_id) REFERENCES attendance (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS disciplinary_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            action_date TEXT NOT NULL,
            duration_days INTEGER NOT NULL DEFAULT 1,
            end_date TEXT,
            details TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            id_signatory_name TEXT,
            id_signatory_title TEXT,
            id_signature_file TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS correction_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            request_type TEXT NOT NULL,
            work_date TEXT NOT NULL,
            end_work_date TEXT,
            message TEXT,
            requested_time_in TEXT,
            requested_break_start TEXT,
            requested_break_end TEXT,
            requested_time_out TEXT,
            applied_changes TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            admin_note TEXT,
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # users migration
    existing_cols_users = [row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
    if "department" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN department TEXT DEFAULT 'Stellar Seats'")
    if "position" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN position TEXT DEFAULT 'Employee'")
    if "emergency_contact_name" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN emergency_contact_name TEXT")
    if "emergency_contact_phone" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN emergency_contact_phone TEXT")
    if "id_issue_date" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN id_issue_date TEXT")
    if "id_expiration_date" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN id_expiration_date TEXT")
    if "barcode_id" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN barcode_id TEXT")
    if "hourly_rate" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN hourly_rate REAL NOT NULL DEFAULT 0")
    if "sick_leave_days" not in existing_cols_users:
        cursor.execute(f"ALTER TABLE users ADD COLUMN sick_leave_days INTEGER NOT NULL DEFAULT {DEFAULT_SICK_LEAVE_DAYS}")
    if "paid_leave_days" not in existing_cols_users:
        cursor.execute(f"ALTER TABLE users ADD COLUMN paid_leave_days INTEGER NOT NULL DEFAULT {DEFAULT_PAID_LEAVE_DAYS}")
    if "sick_leave_used_manual" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN sick_leave_used_manual INTEGER NOT NULL DEFAULT 0")
    if "paid_leave_used_manual" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN paid_leave_used_manual INTEGER NOT NULL DEFAULT 0")
    if "whatsapp_number" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN whatsapp_number TEXT")
    if "schedule_days" not in existing_cols_users:
        cursor.execute(f"ALTER TABLE users ADD COLUMN schedule_days TEXT DEFAULT '{DEFAULT_SCHEDULE_DAYS}'")
    if "shift_start" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN shift_start TEXT DEFAULT '09:00'")
    if "shift_end" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN shift_end TEXT DEFAULT '18:00'")
    if "break_window_start" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN break_window_start TEXT DEFAULT '12:00'")
    if "break_window_end" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN break_window_end TEXT DEFAULT '12:15'")
    if "break_limit_minutes" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN break_limit_minutes INTEGER NOT NULL DEFAULT 15")
    if "is_active" not in existing_cols_users:
        cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

    existing_cols_company_settings = [row[1] for row in cursor.execute("PRAGMA table_info(company_settings)").fetchall()]
    if not existing_cols_company_settings:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS company_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                id_signatory_name TEXT,
                id_signatory_title TEXT,
                id_signature_file TEXT
            )
        """)
        existing_cols_company_settings = [row[1] for row in cursor.execute("PRAGMA table_info(company_settings)").fetchall()]
    if "id_signatory_name" not in existing_cols_company_settings:
        cursor.execute("ALTER TABLE company_settings ADD COLUMN id_signatory_name TEXT")
    if "id_signatory_title" not in existing_cols_company_settings:
        cursor.execute("ALTER TABLE company_settings ADD COLUMN id_signatory_title TEXT")
    if "id_signature_file" not in existing_cols_company_settings:
        cursor.execute("ALTER TABLE company_settings ADD COLUMN id_signature_file TEXT")
    cursor.execute("""
        INSERT OR IGNORE INTO company_settings (id, id_signatory_name, id_signatory_title, id_signature_file)
        VALUES (1, 'Kirk Danny Fernandez', 'Head Of Operations', NULL)
    """)

    # attendance migration
    existing_cols_att = [row[1] for row in cursor.execute("PRAGMA table_info(attendance)").fetchall()]
    if "late_flag" not in existing_cols_att:
        cursor.execute("ALTER TABLE attendance ADD COLUMN late_flag INTEGER NOT NULL DEFAULT 0")
    if "late_minutes" not in existing_cols_att:
        cursor.execute("ALTER TABLE attendance ADD COLUMN late_minutes INTEGER NOT NULL DEFAULT 0")

    # incident reports migration (this fixes your current error)
    existing_cols_incident = [row[1] for row in cursor.execute("PRAGMA table_info(incident_reports)").fetchall()]
    if existing_cols_incident:
        if "error_type" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN error_type TEXT")
        if "report_date" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN report_date TEXT")
        if "message" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN message TEXT")
        if "employee_name" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN employee_name TEXT")
        if "report_department" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN report_department TEXT")
        if "incident_action" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN incident_action TEXT DEFAULT 'Coaching'")
        if "incident_date" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN incident_date TEXT")
        if "status" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN status TEXT NOT NULL DEFAULT 'Open'")
        if "admin_note" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN admin_note TEXT")
        if "created_by" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN created_by INTEGER")
        if "reviewed_by" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN reviewed_by INTEGER")
        if "reviewed_at" not in existing_cols_incident:
            cursor.execute("ALTER TABLE incident_reports ADD COLUMN reviewed_at TEXT")
    if "created_at" not in existing_cols_incident:
        cursor.execute("ALTER TABLE incident_reports ADD COLUMN created_at TEXT")

    existing_cols_disciplinary = [row[1] for row in cursor.execute("PRAGMA table_info(disciplinary_actions)").fetchall()]
    if existing_cols_disciplinary:
        if "duration_days" not in existing_cols_disciplinary:
            cursor.execute("ALTER TABLE disciplinary_actions ADD COLUMN duration_days INTEGER NOT NULL DEFAULT 1")
        if "end_date" not in existing_cols_disciplinary:
            cursor.execute("ALTER TABLE disciplinary_actions ADD COLUMN end_date TEXT")
        if "details" not in existing_cols_disciplinary:
            cursor.execute("ALTER TABLE disciplinary_actions ADD COLUMN details TEXT")
        if "created_by" not in existing_cols_disciplinary:
            cursor.execute("ALTER TABLE disciplinary_actions ADD COLUMN created_by INTEGER")
        if "created_at" not in existing_cols_disciplinary:
            cursor.execute("ALTER TABLE disciplinary_actions ADD COLUMN created_at TEXT")

    existing_cols_corrections = [row[1] for row in cursor.execute("PRAGMA table_info(correction_requests)").fetchall()]
    if existing_cols_corrections:
        if "end_work_date" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN end_work_date TEXT")
        if "requested_time_in" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN requested_time_in TEXT")
        if "requested_break_start" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN requested_break_start TEXT")
        if "requested_break_end" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN requested_break_end TEXT")
        if "requested_time_out" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN requested_time_out TEXT")
        if "applied_changes" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN applied_changes TEXT")
        if "status" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN status TEXT NOT NULL DEFAULT 'Pending'")
        if "admin_note" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN admin_note TEXT")
        if "reviewed_by" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN reviewed_by INTEGER")
        if "reviewed_at" not in existing_cols_corrections:
            cursor.execute("ALTER TABLE correction_requests ADD COLUMN reviewed_at TEXT")

    db.commit()

    admin = cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        cursor.execute("""
            INSERT INTO users (
                full_name, username, password_hash, role,
                profile_image, department, position, shift_start, is_active, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Administrator",
            "admin",
            generate_password_hash("admin123"),
            "admin",
            None,
            "Stellar Seats",
            "Administrator",
            DEFAULT_SHIFT_START,
            1,
            now_str()
        ))
        db.commit()

    db.close()


def init_postgres_db():
    db = get_db()
    with db.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incident_reports (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                employee_name TEXT,
                report_department TEXT,
                error_type TEXT NOT NULL,
                incident_action TEXT DEFAULT 'Coaching',
                incident_date TEXT,
                report_date TEXT NOT NULL,
                message TEXT,
                status TEXT NOT NULL DEFAULT 'Open',
                admin_note TEXT,
                created_by INTEGER,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS disciplinary_actions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                action_date TEXT NOT NULL,
                duration_days INTEGER NOT NULL DEFAULT 1,
                end_date TEXT,
                details TEXT,
                created_by INTEGER,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS employee_name TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS report_department TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS incident_action TEXT DEFAULT 'Coaching'")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS incident_date TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Open'")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS admin_note TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS reviewed_by INTEGER")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS reviewed_at TEXT")
        cur.execute("ALTER TABLE disciplinary_actions ADD COLUMN IF NOT EXISTS duration_days INTEGER NOT NULL DEFAULT 1")
        cur.execute("ALTER TABLE disciplinary_actions ADD COLUMN IF NOT EXISTS end_date TEXT")
        cur.execute("ALTER TABLE disciplinary_actions ADD COLUMN IF NOT EXISTS details TEXT")
        cur.execute("ALTER TABLE disciplinary_actions ADD COLUMN IF NOT EXISTS created_by INTEGER")
        cur.execute("ALTER TABLE disciplinary_actions ADD COLUMN IF NOT EXISTS created_at TEXT")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'employee',
                profile_image TEXT,
                department TEXT DEFAULT 'Stellar Seats',
                position TEXT DEFAULT 'Employee',
                emergency_contact_name TEXT,
                emergency_contact_phone TEXT,
                id_issue_date TEXT,
                id_expiration_date TEXT,
                barcode_id TEXT,
                hourly_rate NUMERIC(12, 2) NOT NULL DEFAULT 0,
                sick_leave_days INTEGER NOT NULL DEFAULT 7,
                paid_leave_days INTEGER NOT NULL DEFAULT 7,
                sick_leave_used_manual INTEGER NOT NULL DEFAULT 0,
                paid_leave_used_manual INTEGER NOT NULL DEFAULT 0,
                whatsapp_number TEXT,
                schedule_days TEXT DEFAULT 'Mon,Tue,Wed,Thu,Fri',
                shift_start TEXT DEFAULT '09:00',
                shift_end TEXT DEFAULT '18:00',
                break_window_start TEXT DEFAULT '12:00',
                break_window_end TEXT DEFAULT '12:15',
                break_limit_minutes INTEGER NOT NULL DEFAULT 15,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp_number TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_name TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS emergency_contact_phone TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS id_issue_date TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS id_expiration_date TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS barcode_id TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS hourly_rate NUMERIC(12, 2) NOT NULL DEFAULT 0")
        cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS sick_leave_days INTEGER NOT NULL DEFAULT {DEFAULT_SICK_LEAVE_DAYS}")
        cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS paid_leave_days INTEGER NOT NULL DEFAULT {DEFAULT_PAID_LEAVE_DAYS}")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS sick_leave_used_manual INTEGER NOT NULL DEFAULT 0")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS paid_leave_used_manual INTEGER NOT NULL DEFAULT 0")
        cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS schedule_days TEXT DEFAULT '{DEFAULT_SCHEDULE_DAYS}'")
        cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS shift_end TEXT DEFAULT '{DEFAULT_SHIFT_END}'")
        cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS break_window_start TEXT DEFAULT '{DEFAULT_BREAK_WINDOW_START}'")
        cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS break_window_end TEXT DEFAULT '{DEFAULT_BREAK_WINDOW_END}'")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS break_limit_minutes INTEGER NOT NULL DEFAULT 15")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                work_date TEXT NOT NULL,
                time_in TEXT,
                time_out TEXT,
                status TEXT DEFAULT 'Offline',
                proof_file TEXT,
                notes TEXT,
                late_flag INTEGER NOT NULL DEFAULT 0,
                late_minutes INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS breaks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                attendance_id INTEGER,
                work_date TEXT NOT NULL,
                break_start TEXT,
                break_end TEXT,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS correction_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                request_type TEXT NOT NULL,
                work_date TEXT NOT NULL,
                end_work_date TEXT,
                message TEXT,
                requested_time_in TEXT,
                requested_break_start TEXT,
                requested_break_end TEXT,
                requested_time_out TEXT,
                applied_changes TEXT,
                status TEXT NOT NULL DEFAULT 'Pending',
                admin_note TEXT,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS end_work_date TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_time_in TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_break_start TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_break_end TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_time_out TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS applied_changes TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Pending'")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS admin_note TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS reviewed_by INTEGER")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS reviewed_at TEXT")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS company_settings (
                id INTEGER PRIMARY KEY,
                id_signatory_name TEXT,
                id_signatory_title TEXT,
                id_signature_file TEXT
            )
        """)
        cur.execute("ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS id_signatory_name TEXT")
        cur.execute("ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS id_signatory_title TEXT")
        cur.execute("ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS id_signature_file TEXT")
        cur.execute("""
            INSERT INTO company_settings (id, id_signatory_name, id_signatory_title, id_signature_file)
            VALUES (1, 'Kirk Danny Fernandez', 'Head Of Operations', NULL)
            ON CONFLICT (id) DO NOTHING
        """)

    db.commit()

    admin = fetchone("SELECT * FROM users WHERE username = ?", ("admin",))
    if not admin:
        execute_db("""
            INSERT INTO users (
                full_name, username, password_hash, role,
                profile_image, department, position, shift_start, break_limit_minutes, is_active, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Administrator",
            "admin",
            generate_password_hash("admin123"),
            "admin",
            None,
            "Stellar Seats",
            "Administrator",
            DEFAULT_SHIFT_START,
            BREAK_LIMIT_MINUTES,
            1,
            now_str()
        ), commit=True)


os.makedirs(os.path.dirname(SQLITE_DATABASE), exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
with app.app_context():
    init_db()


# =========================
# APP HELPERS
# =========================
def create_notification(user_id, title, message):
    execute_db("""
        INSERT INTO notifications (user_id, title, message, created_at, is_read)
        VALUES (?, ?, ?, ?, 0)
    """, (user_id, title, message, now_str()), commit=True)


def create_incident(user_id, error_type, report_date, message, admin_id, incident_action, report_department):
    user = get_user_by_id(user_id)

    execute_db("""
        INSERT INTO incident_reports (
            user_id,
            employee_name,
            report_department,
            error_type,
            incident_action,
            incident_date,
            report_date,
            message,
            status,
            admin_note,
            created_by,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', NULL, ?, ?)
    """, (
        user_id,
        user["full_name"] if user else "",
        report_department,
        error_type,
        incident_action,
        report_date,
        report_date,
        message,
        admin_id,
        now_str()
    ), commit=True)


def calculate_suspension_end_date(action_date, duration_days):
    try:
        start_date = datetime.strptime(action_date, "%Y-%m-%d").date()
    except Exception:
        return ""
    total_days = max(int(duration_days or 1), 1)
    return (start_date + timedelta(days=total_days - 1)).strftime("%Y-%m-%d")


def create_disciplinary_action(user_id, action_type, action_date, details, created_by, duration_days=1):
    duration_days = max(int(duration_days or 1), 1)
    end_date = calculate_suspension_end_date(action_date, duration_days) if action_type == "Suspension" else action_date
    execute_db("""
        INSERT INTO disciplinary_actions (
            user_id, action_type, action_date, duration_days, end_date, details, created_by, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        action_type,
        action_date,
        duration_days,
        end_date,
        details,
        created_by,
        now_str()
    ), commit=True)


def get_disciplinary_action_by_id(action_id):
    return fetchone("""
        SELECT *
        FROM disciplinary_actions
        WHERE id = ?
    """, (action_id,))


def log_activity(user_id, action, details=""):
    execute_db("""
        INSERT INTO activity_logs (user_id, action, details, created_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, action, details, now_str()), commit=True)


def get_user_by_id(user_id):
    return fetchone("SELECT * FROM users WHERE id = ?", (user_id,))


def get_user_by_barcode(barcode_id):
    cleaned = (barcode_id or "").strip()
    if not cleaned:
        return None
    return fetchone("""
        SELECT *
        FROM users
        WHERE role = 'employee' AND TRIM(COALESCE(barcode_id, '')) = ?
        ORDER BY id DESC LIMIT 1
    """, (cleaned,))


def get_company_settings():
    settings = fetchone("SELECT * FROM company_settings WHERE id = 1")
    if settings:
        return settings
    return {
        "id": 1,
        "id_signatory_name": "Kirk Danny Fernandez",
        "id_signatory_title": "Head Of Operations",
        "id_signature_file": None,
    }


def get_attendance_by_id(attendance_id):
    return fetchone("SELECT * FROM attendance WHERE id = ?", (attendance_id,))


def get_today_attendance(user_id):
    return fetchone("""
        SELECT * FROM attendance
        WHERE user_id = ? AND work_date = ?
        ORDER BY id DESC LIMIT 1
    """, (user_id, today_str()))


def get_active_attendance(user_id):
    return fetchone("""
        SELECT * FROM attendance
        WHERE user_id = ? AND time_in IS NOT NULL AND time_out IS NULL
        ORDER BY work_date DESC, id DESC LIMIT 1
    """, (user_id,))


def get_current_attendance(user_id):
    active_attendance = get_active_attendance(user_id)
    if active_attendance:
        return active_attendance
    return get_today_attendance(user_id)


def get_open_break_for_attendance(attendance_id):
    return fetchone("""
        SELECT * FROM breaks
        WHERE attendance_id = ? AND break_end IS NULL
        ORDER BY id DESC LIMIT 1
    """, (attendance_id,))


def get_open_break(user_id, attendance_row=None):
    attendance = attendance_row or get_current_attendance(user_id)
    if not attendance:
        return None
    return get_open_break_for_attendance(attendance["id"])


def perform_attendance_action(user_id, action_type, actor_id=None, source_label="System"):
    user = get_user_by_id(user_id)
    if not user or user["role"] != "employee":
        return False, "Employee not found.", None

    if user["is_active"] != 1:
        return False, "Employee account is inactive.", user

    override_status = get_employee_override_status_for_date(user_id, today_str())
    if override_status and override_status["type"] == "Suspension":
        return False, f"Employee is suspended until {override_status['end_date']}.", user

    attendance = get_current_attendance(user_id)
    open_break = get_open_break(user_id, attendance)
    action_key = (action_type or "").strip().lower()

    if action_key == "time_in":
        if attendance and attendance["time_in"] and not attendance["time_out"]:
            return False, "Employee is already timed in.", user

        execute_db("""
            INSERT INTO attendance (
                user_id, work_date, time_in, time_out, status, proof_file, notes,
                late_flag, late_minutes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            today_str(),
            now_str(),
            None,
            "Timed In",
            None,
            f"{source_label} action",
            *calculate_late_info(now_str(), parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START)),
            now_str(),
            now_str()
        ), commit=True)

        latest_attendance = get_current_attendance(user_id)
        shift_start = parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START)
        if latest_attendance and latest_attendance["late_flag"]:
            create_notification(
                user_id,
                "Late Time-In",
                f"You timed in late by {latest_attendance['late_minutes']} minute(s). Shift start: {shift_start} ET."
            )
        else:
            create_notification(user_id, "Timed In", f"You timed in at {now_str()} ET.")
        log_activity(actor_id or user_id, "KIOSK TIME IN", f"{source_label} time in for {user['full_name']}")
        return True, "Time in successful.", user

    if action_key == "start_break":
        if not attendance or not attendance["time_in"] or attendance["time_out"]:
            return False, "Employee must be timed in first.", user
        if open_break:
            return False, "Employee is already on break.", user

        break_limit_minutes = get_employee_break_limit(user)
        used_break_minutes = total_break_minutes(attendance["id"])
        if used_break_minutes >= break_limit_minutes:
            return False, f"Daily break limit already used ({break_limit_minutes} minutes).", user

        execute_db("""
            INSERT INTO breaks (user_id, attendance_id, work_date, break_start, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, attendance["id"], attendance["work_date"], now_str(), now_str()), commit=True)
        execute_db("""
            UPDATE attendance
            SET status = ?, updated_at = ?
            WHERE id = ?
        """, ("On Break", now_str(), attendance["id"]), commit=True)
        remaining_break = max(break_limit_minutes - used_break_minutes, 0)
        create_notification(user_id, "Break Started", f"You started break at {now_str()} ET. Remaining break allowance: {remaining_break} minute(s).")
        log_activity(actor_id or user_id, "KIOSK BREAK START", f"{source_label} break start for {user['full_name']}")
        return True, "Break started.", user

    if action_key == "end_break":
        if not open_break:
            return False, "No active break found.", user

        execute_db("""
            UPDATE breaks
            SET break_end = ?
            WHERE id = ?
        """, (now_str(), open_break["id"]), commit=True)

        if attendance:
            execute_db("""
                UPDATE attendance
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, ("Timed In", now_str(), attendance["id"]), commit=True)

        total_break = total_break_minutes(attendance["id"]) if attendance else 0
        break_limit_minutes = get_employee_break_limit(user)
        create_notification(user_id, "Break Ended", f"You ended break at {now_str()} ET.")
        if attendance and is_overbreak(total_break, break_limit_minutes):
            create_notification(
                user_id,
                "Break Limit Exceeded",
                f"Your total break time for today is {minutes_to_hm(total_break)}, which is over your {break_limit_minutes} minute limit."
            )
        log_activity(actor_id or user_id, "KIOSK BREAK END", f"{source_label} break end for {user['full_name']}")
        return True, "Break ended.", user

    if action_key == "time_out":
        if not attendance or not attendance["time_in"]:
            return False, "Employee is not timed in.", user
        if attendance["time_out"]:
            return False, "Employee is already timed out.", user

        if open_break:
            execute_db("""
                UPDATE breaks
                SET break_end = ?
                WHERE id = ?
            """, (now_str(), open_break["id"]), commit=True)

        execute_db("""
            UPDATE attendance
            SET time_out = ?, status = ?, updated_at = ?
            WHERE id = ?
        """, (now_str(), "Timed Out", now_str(), attendance["id"]), commit=True)

        updated_attendance = get_attendance_by_id(attendance["id"])
        ok, msg = append_attendance_to_google_sheet(user, updated_attendance)
        create_notification(user_id, "Timed Out", f"You timed out at {now_str()} ET.")
        log_activity(actor_id or user_id, "KIOSK TIME OUT", f"{source_label} time out for {user['full_name']}. Sheets sync: {msg if ok else 'Skipped/Failed'}")
        return True, "Time out successful.", user

    return False, "Invalid attendance action.", user


def get_user_live_status(user_id):
    attendance = get_current_attendance(user_id)
    open_break = get_open_break(user_id, attendance)

    if not attendance:
        return "Offline"

    if attendance["time_in"] and not attendance["time_out"]:
        if open_break:
            return "On Break"
        return "Timed In"

    if attendance["time_out"]:
        return "Timed Out"

    return "Offline"


def parse_shift_start(shift_start):
    shift_value = (shift_start or DEFAULT_SHIFT_START).strip()
    try:
        datetime.strptime(shift_value, "%H:%M")
        return shift_value
    except ValueError:
        return DEFAULT_SHIFT_START


def parse_shift_end(shift_end):
    shift_value = (shift_end or DEFAULT_SHIFT_END).strip()
    try:
        datetime.strptime(shift_value, "%H:%M")
        return shift_value
    except ValueError:
        return DEFAULT_SHIFT_END


def parse_optional_schedule_time(value, fallback=""):
    raw_value = (value or "").strip()
    if not raw_value:
        return fallback
    try:
        return datetime.strptime(raw_value, "%H:%M").strftime("%H:%M")
    except ValueError:
        return fallback


def normalize_schedule_days(values):
    if isinstance(values, str):
        raw_values = [v.strip() for v in values.split(",")]
    else:
        raw_values = [str(v).strip() for v in (values or [])]

    valid_codes = [code for code, _ in WEEKDAY_OPTIONS]
    selected = [code for code in valid_codes if code in raw_values]
    return ",".join(selected) if selected else DEFAULT_SCHEDULE_DAYS


def get_schedule_day_codes(schedule_days):
    return normalize_schedule_days(schedule_days).split(",")


def get_schedule_summary(schedule_days):
    codes = get_schedule_day_codes(schedule_days)
    labels = {code: label for code, label in WEEKDAY_OPTIONS}
    return ", ".join(labels[code] for code in codes if code in labels)


def get_schedule_window_summary(user_row):
    if not user_row:
        return f"{DEFAULT_SHIFT_START} - {DEFAULT_SHIFT_END}"

    shift_start = parse_shift_start(user_row["shift_start"] if user_row["shift_start"] else DEFAULT_SHIFT_START)
    shift_end = parse_shift_end(user_row["shift_end"] if user_row["shift_end"] else DEFAULT_SHIFT_END)
    return f"{shift_start} - {shift_end}"


def get_today_schedule_code():
    return WEEKDAY_OPTIONS[now_dt().weekday()][0]


def get_schedule_code_for_date(date_str):
    try:
        parsed = datetime.strptime(date_str, "%Y-%m-%d")
        return WEEKDAY_OPTIONS[parsed.weekday()][0]
    except Exception:
        return ""


def is_scheduled_on_date(user_row, date_str):
    return get_schedule_code_for_date(date_str) in get_schedule_day_codes(
        user_row["schedule_days"] if user_row else DEFAULT_SCHEDULE_DAYS
    )


def is_scheduled_today(user_row):
    return get_today_schedule_code() in get_schedule_day_codes(user_row["schedule_days"] if user_row else DEFAULT_SCHEDULE_DAYS)


def get_approved_leave_for_date(user_id, work_date):
    if not user_id or not work_date:
        return None
    return fetchone("""
        SELECT *
        FROM correction_requests
        WHERE user_id = ?
          AND work_date <= ?
          AND COALESCE(end_work_date, work_date) >= ?
          AND status = 'Approved'
          AND request_type IN ('Sick Leave', 'Paid Leave')
        ORDER BY id DESC LIMIT 1
    """, (user_id, work_date, work_date))


def get_employee_override_status_for_date(user_id, work_date):
    suspension = get_suspension_for_date(user_id, work_date)
    if suspension:
        return {
            "type": "Suspension",
            "label": "Suspended",
            "details": suspension.get("details") or "",
            "end_date": suspension.get("end_date") or suspension.get("action_date") or work_date,
        }
    leave = get_approved_leave_for_date(user_id, work_date)
    if leave:
        return {
            "type": leave["request_type"],
            "label": leave["request_type"],
            "details": leave.get("message") or leave.get("admin_note") or "",
            "end_date": leave.get("end_work_date") or leave["work_date"],
        }
    return None


def get_shift_bounds_for_work_date(user_row, work_date):
    shift_start = parse_shift_start(user_row["shift_start"] if user_row else DEFAULT_SHIFT_START)
    shift_end = parse_shift_end(user_row["shift_end"] if user_row else DEFAULT_SHIFT_END)
    shift_start_dt = datetime.strptime(
        f"{work_date} {shift_start}:00",
        "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=APP_TIMEZONE)
    shift_end_dt = datetime.strptime(
        f"{work_date} {shift_end}:00",
        "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=APP_TIMEZONE)
    if shift_end_dt <= shift_start_dt:
        shift_end_dt += timedelta(days=1)
    return shift_start_dt, shift_end_dt


def is_absent_today(user_row, attendance_row):
    if not user_row or user_row["is_active"] != 1 or attendance_row:
        return False
    if not is_scheduled_today(user_row):
        return False
    if get_approved_leave_for_date(user_row["id"], today_str()):
        return False
    if get_suspension_for_date(user_row["id"], today_str()):
        return False

    shift_dt, _ = get_shift_bounds_for_work_date(user_row, today_str())
    return now_dt() >= (shift_dt + timedelta(minutes=LATE_GRACE_MINUTES))


def is_missing_timeout_today(user_row, attendance_row):
    if not user_row or user_row["is_active"] != 1 or not attendance_row:
        return False
    if not attendance_row["time_in"] or attendance_row["time_out"]:
        return False

    _, shift_end_dt = get_shift_bounds_for_work_date(user_row, attendance_row["work_date"])
    return now_dt() >= (shift_end_dt + timedelta(minutes=LATE_GRACE_MINUTES))


def is_undertime_record(user_row, attendance_row):
    if not user_row or not attendance_row:
        return False
    if not attendance_row.get("time_in") or not attendance_row.get("time_out"):
        return False
    if attendance_row.get("source_type") != "attendance":
        return False

    actual_time_in = parse_db_datetime(attendance_row.get("time_in"))
    actual_time_out = parse_db_datetime(attendance_row.get("time_out"))
    if not actual_time_in or not actual_time_out:
        return False

    shift_start_dt, shift_end_dt = get_shift_bounds_for_work_date(user_row, attendance_row["work_date"])
    shift_start_naive = shift_start_dt.replace(tzinfo=None)
    shift_end_naive = shift_end_dt.replace(tzinfo=None)
    worked_minutes = max(int((actual_time_out - actual_time_in).total_seconds() // 60), 0)
    scheduled_minutes = max(int((shift_end_naive - shift_start_naive).total_seconds() // 60), 0)
    if worked_minutes <= 0 or scheduled_minutes <= 0:
        return False
    if worked_minutes > scheduled_minutes:
        return False
    return shift_start_naive <= actual_time_out < shift_end_naive


def get_scheduled_shift_minutes(user_row, work_date):
    shift_start_dt, shift_end_dt = get_shift_bounds_for_work_date(user_row, work_date)
    return max(int((shift_end_dt - shift_start_dt).total_seconds() // 60), 0)


def is_suspicious_work_duration(user_row, attendance_row):
    if not user_row or not attendance_row:
        return False
    if not attendance_row.get("time_in") or not attendance_row.get("time_out"):
        return False

    time_in_dt = parse_db_datetime(attendance_row.get("time_in"))
    time_out_dt = parse_db_datetime(attendance_row.get("time_out"))
    if not time_in_dt or not time_out_dt or time_out_dt < time_in_dt:
        return True

    worked_minutes = max(int((time_out_dt - time_in_dt).total_seconds() // 60), 0)
    scheduled_minutes = get_scheduled_shift_minutes(user_row, attendance_row["work_date"])

    if worked_minutes > (18 * 60):
        return True
    if scheduled_minutes > 0 and worked_minutes > (scheduled_minutes + 240):
        return True
    return False


def collect_attendance_diagnostics(user_row, attendance_row):
    issues = []
    warnings = []
    if not user_row or not attendance_row:
        return issues, warnings

    time_in_dt = parse_db_datetime(attendance_row.get("time_in"))
    time_out_dt = parse_db_datetime(attendance_row.get("time_out"))
    break_rows = get_break_rows(attendance_row.get("id"))

    if attendance_row.get("time_in") and not time_in_dt:
        issues.append("Invalid time in format")
    if attendance_row.get("time_out") and not time_out_dt:
        issues.append("Invalid time out format")
    if time_in_dt and time_out_dt and time_out_dt < time_in_dt:
        issues.append("Time out earlier than time in")
    if is_suspicious_work_duration(user_row, attendance_row):
        issues.append("Suspicious work duration")

    for index, break_row in enumerate(break_rows, start=1):
        break_start_dt = parse_db_datetime(break_row.get("break_start"))
        break_end_dt = parse_db_datetime(break_row.get("break_end"))
        label = f"Break {index}"
        if break_row.get("break_start") and not break_start_dt:
            issues.append(f"{label} has invalid start")
        if break_row.get("break_end") and not break_end_dt:
            issues.append(f"{label} has invalid end")
        if break_start_dt and break_end_dt and break_end_dt < break_start_dt:
            issues.append(f"{label} ends before it starts")
        if time_in_dt and break_start_dt and break_start_dt < time_in_dt:
            issues.append(f"{label} starts before time in")
        if time_out_dt and break_end_dt and break_end_dt > time_out_dt:
            issues.append(f"{label} ends after time out")

    if len(break_rows) > 1:
        warnings.append(f"{len(break_rows)} break rows attached")

    return issues, warnings


def parse_break_limit_minutes(value):
    try:
        minutes = int(str(value).strip())
        return minutes if minutes > 0 else BREAK_LIMIT_MINUTES
    except Exception:
        return BREAK_LIMIT_MINUTES


def normalize_optional_clock_time(value):
    raw_value = (value or "").strip()
    if not raw_value:
        return ""
    try:
        return datetime.strptime(raw_value, "%H:%M").strftime("%H:%M")
    except ValueError:
        raise ValueError("Use HH:MM format for correction times.")


def parse_db_datetime(datetime_str):
    if not datetime_str:
        return None
    try:
        return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def combine_work_date_and_time(work_date, clock_time, not_before=None):
    if not clock_time:
        return None
    candidate_dt = datetime.strptime(f"{work_date} {clock_time}:00", "%Y-%m-%d %H:%M:%S")
    reference_dt = parse_db_datetime(not_before) if isinstance(not_before, str) else not_before
    if reference_dt and candidate_dt < reference_dt:
        candidate_dt += timedelta(days=1)
    return candidate_dt.strftime("%Y-%m-%d %H:%M:%S")


def extract_clock_time(value):
    parsed_dt = parse_db_datetime(value)
    if parsed_dt:
        return parsed_dt.strftime("%H:%M")
    raw_value = (value or "").strip()
    if not raw_value:
        return ""
    try:
        return datetime.strptime(raw_value, "%H:%M").strftime("%H:%M")
    except ValueError:
        return ""


def get_attendance_context(user_id, work_date):
    attendance = fetchone("""
        SELECT *
        FROM attendance
        WHERE user_id = ? AND work_date = ?
        ORDER BY id DESC LIMIT 1
    """, (user_id, work_date))

    break_row = None
    if attendance:
        break_row = fetchone("""
            SELECT *
            FROM breaks
            WHERE attendance_id = ?
            ORDER BY id ASC LIMIT 1
        """, (attendance["id"],))

    return attendance, break_row


def get_attendance_context_by_row(attendance):
    if not attendance:
        return None, None
    break_row = fetchone("""
        SELECT *
        FROM breaks
        WHERE attendance_id = ?
        ORDER BY id ASC LIMIT 1
    """, (attendance["id"],))
    return attendance, break_row


def get_matching_attendance_context_for_request(user_id, work_date, request_type="", requested_time_out=None):
    attendance, break_row = get_attendance_context(user_id, work_date)
    if request_type != "Undertime":
        return attendance, break_row
    requested_clock_time = extract_clock_time(requested_time_out)
    user_row = get_user_by_id(user_id)
    candidate_rows = fetchall("""
        SELECT *
        FROM attendance
        WHERE user_id = ?
        ORDER BY work_date DESC, id DESC
        LIMIT 10
    """, (user_id,))
    if attendance and not any(candidate["id"] == attendance["id"] for candidate in candidate_rows):
        candidate_rows.insert(0, attendance)

    best_candidate = None
    best_score = None
    for candidate in candidate_rows:
        start_dt = parse_db_datetime(candidate["time_in"])
        if not start_dt:
            continue
        candidate_time_out = combine_work_date_and_time(candidate["work_date"], requested_clock_time, not_before=candidate["time_in"]) if requested_clock_time else None
        candidate_time_out_dt = parse_db_datetime(candidate_time_out)
        if not candidate_time_out_dt:
            continue
        _, shift_end_dt = get_shift_bounds_for_work_date(user_row, candidate["work_date"])
        shift_end_naive = shift_end_dt.replace(tzinfo=None)
        existing_time_out_dt = parse_db_datetime(candidate["time_out"]) or shift_end_naive
        if candidate_time_out_dt < start_dt or candidate_time_out_dt > shift_end_naive:
            continue
        if existing_time_out_dt and candidate_time_out_dt > existing_time_out_dt:
            continue

        score = abs(int((existing_time_out_dt - candidate_time_out_dt).total_seconds())) if existing_time_out_dt else 0
        if best_score is None or score < best_score:
            best_candidate = candidate
            best_score = score

    if best_candidate:
        return get_attendance_context_by_row(best_candidate)
    if attendance:
        return attendance, break_row
    return None, None


def resolve_correction_datetimes(
    work_date,
    time_in_value="",
    break_start_value="",
    break_end_value="",
    time_out_value="",
    existing_time_in=None,
    existing_break_start=None,
    existing_break_end=None,
    existing_time_out=None,
    use_existing_values=True
):
    final_time_in = combine_work_date_and_time(work_date, time_in_value) if time_in_value else None
    resolved_time_in = final_time_in if time_in_value else (existing_time_in if use_existing_values else None)

    break_start_reference = resolved_time_in or existing_break_start
    final_break_start = (
        combine_work_date_and_time(work_date, break_start_value, not_before=break_start_reference)
        if break_start_value else None
    )
    resolved_break_start = final_break_start if break_start_value else (existing_break_start if use_existing_values else None)

    break_end_reference = resolved_break_start or existing_break_end or break_start_reference
    final_break_end = (
        combine_work_date_and_time(work_date, break_end_value, not_before=break_end_reference)
        if break_end_value else None
    )
    resolved_break_end = final_break_end if break_end_value else (existing_break_end if use_existing_values else None)

    time_out_reference = resolved_break_end or resolved_break_start or resolved_time_in or existing_time_out
    final_time_out = (
        combine_work_date_and_time(work_date, time_out_value, not_before=time_out_reference)
        if time_out_value else None
    )
    resolved_time_out = final_time_out if time_out_value else (existing_time_out if use_existing_values else None)

    return resolved_time_in, resolved_break_start, resolved_break_end, resolved_time_out


def split_datetime_to_time(datetime_str):
    if not datetime_str:
        return ""
    try:
        return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
    except Exception:
        return ""


def build_correction_change_summary(before_values, after_values):
    labels = [
        ("time_in", "Time In"),
        ("break_start", "Break Start"),
        ("break_end", "Break End"),
        ("time_out", "Time Out"),
    ]
    parts = []
    for key, label in labels:
        before_text = split_datetime_to_time(before_values.get(key)) or "-"
        after_text = split_datetime_to_time(after_values.get(key)) or "-"
        if before_text != after_text:
            parts.append(f"{label}: {before_text} -> {after_text}")
    return "; ".join(parts) if parts else "No attendance times changed."


def describe_request_review_result(request_type, work_date, requested_time_out=""):
    if request_type in LEAVE_REQUEST_TYPES:
        return f"{request_type} approved for {work_date}."
    if request_type == "Undertime":
        return f"Undertime request approved for {work_date}" + (f" at {requested_time_out}." if requested_time_out else ".")
    return ""


def calculate_late_info(time_in_str, shift_start):
    if not time_in_str:
        return 0, 0

    shift_start = parse_shift_start(shift_start)
    time_in_dt = datetime.strptime(time_in_str, "%Y-%m-%d %H:%M:%S")
    shift_dt = datetime.strptime(
        f"{time_in_dt.strftime('%Y-%m-%d')} {shift_start}:00",
        "%Y-%m-%d %H:%M:%S"
    )

    late_threshold = shift_dt + timedelta(minutes=LATE_GRACE_MINUTES)

    if time_in_dt >= late_threshold:
        late_minutes = int((time_in_dt - shift_dt).total_seconds() // 60)
        return 1, late_minutes

    return 0, 0


def total_break_minutes(attendance_id, include_open=False):
    breaks_rows = get_break_rows(attendance_id)

    total_minutes = 0
    for br in breaks_rows:
        if br["break_start"] and (br["break_end"] or include_open):
            start = datetime.strptime(br["break_start"], "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(br["break_end"] or now_str(), "%Y-%m-%d %H:%M:%S")
            total_minutes += int((end - start).total_seconds() // 60)
    return total_minutes


def get_break_rows(attendance_id):
    if not attendance_id:
        return []
    return [
        dict(row) for row in fetchall("""
            SELECT * FROM breaks
            WHERE attendance_id = ?
            ORDER BY id ASC
        """, (attendance_id,))
    ]


def build_break_sessions(attendance_id):
    sessions = []
    for br in get_break_rows(attendance_id):
        sessions.append({
            "start": br.get("break_start"),
            "end": br.get("break_end"),
            "start_display": format_datetime_12h(br.get("break_start")) if br.get("break_start") else "-",
            "end_display": format_datetime_12h(br.get("break_end")) if br.get("break_end") else "Open",
        })
    return sessions


def summarize_break_sessions(break_sessions):
    if not break_sessions:
        return "No break sessions recorded."
    parts = []
    for index, session in enumerate(break_sessions, start=1):
        parts.append(f"Break {index}: {session['start_display']} -> {session['end_display']}")
    return " | ".join(parts)


def get_backup_files(limit=15):
    if not os.path.isdir(BACKUP_FOLDER):
        return []
    entries = []
    for name in os.listdir(BACKUP_FOLDER):
        full_path = os.path.join(BACKUP_FOLDER, name)
        if not os.path.isfile(full_path):
            continue
        stat = os.stat(full_path)
        entries.append({
            "name": name,
            "path": full_path,
            "size_bytes": stat.st_size,
            "size_kb": round(stat.st_size / 1024, 1),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    entries.sort(key=lambda item: item["modified_at"], reverse=True)
    return entries[:limit]


def create_sqlite_backup():
    if using_postgres():
        raise ValueError("Automatic backup copy is only available for SQLite right now.")
    if not os.path.exists(SQLITE_DATABASE):
        raise ValueError("SQLite database file was not found.")
    backup_name = f"attendance-backup-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}.db"
    backup_path = os.path.join(BACKUP_FOLDER, backup_name)
    shutil.copy2(SQLITE_DATABASE, backup_path)
    return backup_path


def remove_orphaned_proof_uploads():
    if not os.path.isdir(app.config["UPLOAD_FOLDER"]):
        return 0

    protected_files = {
        row["profile_image"]
        for row in fetchall("""
            SELECT profile_image
            FROM users
            WHERE profile_image IS NOT NULL AND TRIM(profile_image) != ''
        """)
    }
    removed = 0
    for name in os.listdir(app.config["UPLOAD_FOLDER"]):
        full_path = os.path.join(app.config["UPLOAD_FOLDER"], name)
        if not os.path.isfile(full_path):
            continue
        if name in protected_files:
            continue
        try:
            os.remove(full_path)
            removed += 1
        except OSError:
            continue
    return removed


def perform_go_live_reset():
    backup_path = None
    if not using_postgres():
        backup_path = create_sqlite_backup()

    db = get_db()
    if using_postgres():
        with db.cursor() as cur:
            cur.execute("""
                TRUNCATE TABLE
                    breaks,
                    attendance,
                    correction_requests,
                    notifications,
                    activity_logs,
                    incident_reports,
                    disciplinary_actions
                RESTART IDENTITY
            """)
        db.commit()
    else:
        cur = db.cursor()
        for table_name in [
            "breaks",
            "attendance",
            "correction_requests",
            "notifications",
            "activity_logs",
            "incident_reports",
            "disciplinary_actions",
        ]:
            cur.execute(f"DELETE FROM {table_name}")
        try:
            cur.execute("""
                DELETE FROM sqlite_sequence
                WHERE name IN ('breaks', 'attendance', 'correction_requests', 'notifications', 'activity_logs', 'incident_reports', 'disciplinary_actions')
            """)
        except sqlite3.OperationalError:
            pass
        db.commit()

    removed_uploads = remove_orphaned_proof_uploads()
    return {
        "backup_path": backup_path,
        "removed_uploads": removed_uploads,
    }


def get_employee_break_limit(user_row):
    if not user_row:
        return BREAK_LIMIT_MINUTES
    return parse_break_limit_minutes(user_row["break_limit_minutes"])


def get_overbreak_minutes(break_minutes, break_limit_minutes=BREAK_LIMIT_MINUTES):
    return max(break_minutes - parse_break_limit_minutes(break_limit_minutes), 0)


def is_overbreak(break_minutes, break_limit_minutes=BREAK_LIMIT_MINUTES):
    return get_overbreak_minutes(break_minutes, break_limit_minutes) > 0


def total_work_minutes(attendance_row):
    if not attendance_row or not attendance_row["time_in"] or not attendance_row["time_out"]:
        return 0

    start = datetime.strptime(attendance_row["time_in"], "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(attendance_row["time_out"], "%Y-%m-%d %H:%M:%S")
    return max(int((end - start).total_seconds() // 60), 0)


def minutes_to_hm(minutes):
    h = minutes // 60
    m = minutes % 60
    return f"{h}h {m}m"


def minutes_to_decimal_hours(minutes):
    return round((minutes or 0) / 60, 2)


def parse_datetime_local_input(value):
    raw_value = (value or "").strip()
    if not raw_value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw_value, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    raise ValueError("Use a valid date and time when fixing attendance data.")


def format_datetime_12h(datetime_str):
    if not datetime_str:
        return ""
    try:
        dt = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %I:%M:%S %p")
    except Exception:
        return datetime_str


def format_time_12h(datetime_str):
    if not datetime_str:
        return ""
    try:
        dt = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%I:%M:%S %p")
    except Exception:
        return datetime_str


def save_uploaded_file(file_obj, prefix="file"):
    if not file_obj or not file_obj.filename:
        return None
    if not allowed_file(file_obj.filename):
        return None

    safe_name = secure_filename(file_obj.filename)
    filename = f"{prefix}_{now_timestamp()}_{safe_name}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file_obj.save(filepath)
    return filename


def uploaded_file_exists(filename):
    if not filename:
        return False
    return os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], filename))


def static_file_exists(filename):
    if not filename:
        return False
    return os.path.exists(os.path.join(app.static_folder, filename))


def can_access_uploaded_file(user_row, filename):
    if not user_row or not filename:
        return False
    if user_row["role"] == "admin":
        return True
    if user_row["profile_image"] == filename:
        return True

    proof_row = fetchone("""
        SELECT id
        FROM attendance
        WHERE user_id = ? AND proof_file = ?
        ORDER BY id DESC LIMIT 1
    """, (user_row["id"], filename))
    return bool(proof_row)


def get_avatar_initials(name):
    parts = [part.strip() for part in (name or "").split() if part.strip()]
    if not parts:
        return "U"
    initials = "".join(part[0] for part in parts[:2]).upper()
    return initials or "U"


def get_employee_card_number(user_row):
    if not user_row:
        return ""
    barcode_value = user_row["barcode_id"] if "barcode_id" in user_row.keys() else ""
    if barcode_value and str(barcode_value).strip():
        return str(barcode_value).strip()
    user_id = user_row["id"] if "id" in user_row.keys() else 0
    return f"EMP-{int(user_id or 0):04d}"


CODE128_PATTERNS = [
    "212222", "222122", "222221", "121223", "121322", "131222", "122213", "122312", "132212", "221213",
    "221312", "231212", "112232", "122132", "122231", "113222", "123122", "123221", "223211", "221132",
    "221231", "213212", "223112", "312131", "311222", "321122", "321221", "312212", "322112", "322211",
    "212123", "212321", "232121", "111323", "131123", "131321", "112313", "132113", "132311", "211313",
    "231113", "231311", "112133", "112331", "132131", "113123", "113321", "133121", "313121", "211331",
    "231131", "213113", "213311", "213131", "311123", "311321", "331121", "312113", "312311", "332111",
    "314111", "221411", "431111", "111224", "111422", "121124", "121421", "141122", "141221", "112214",
    "112412", "122114", "122411", "142112", "142211", "241211", "221114", "413111", "241112", "134111",
    "111242", "121142", "121241", "114212", "124112", "124211", "411212", "421112", "421211", "212141",
    "214121", "412121", "111143", "111341", "131141", "114113", "114311", "411113", "411311", "113141",
    "114131", "311141", "411131", "211412", "211214", "211232", "2331112"
]


def generate_code128_svg_data_uri(value, module_width=2, height=88):
    raw_value = str(value or "").strip()
    if not raw_value:
        return ""
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in raw_value):
        return ""

    code_values = [104] + [ord(ch) - 32 for ch in raw_value]
    checksum_total = 104
    for index, code in enumerate(code_values[1:], start=1):
        checksum_total += code * index
    code_values.append(checksum_total % 103)
    code_values.append(106)

    quiet_zone = 10 * module_width
    x = quiet_zone
    rects = []
    for code in code_values:
        pattern = CODE128_PATTERNS[code]
        for idx, width_char in enumerate(pattern):
            segment_width = int(width_char) * module_width
            if idx % 2 == 0:
                rects.append(f'<rect x="{x}" y="0" width="{segment_width}" height="{height}" fill="#0f172a" />')
            x += segment_width
    total_width = x + quiet_zone
    text_y = height + 18
    safe_label = (
        raw_value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height + 26}" '
        f'viewBox="0 0 {total_width} {height + 26}" role="img" aria-label="Barcode {safe_label}">'
        f'<rect width="{total_width}" height="{height + 26}" fill="#ffffff" rx="8" ry="8" />'
        + "".join(rects) +
        f'<text x="{total_width / 2}" y="{text_y}" text-anchor="middle" font-family="Inter, Arial, sans-serif" '
        f'font-size="14" font-weight="700" fill="#0f172a">{safe_label}</text>'
        '</svg>'
    )
    return f"data:image/svg+xml;charset=utf-8,{quote(svg)}"


def get_department_options():
    return fetchall("""
        SELECT DISTINCT department
        FROM users
        WHERE role = 'employee' AND department IS NOT NULL AND TRIM(department) != ''
        ORDER BY department ASC
    """)


def get_employee_options():
    return fetchall("""
        SELECT id, full_name
        FROM users
        WHERE role = 'employee'
        ORDER BY full_name ASC
    """)


def get_leave_usage_rows(user_id=None, year=None, department=""):
    target_year = int(year or now_dt().year)
    sql = """
        SELECT c.user_id, c.request_type, c.work_date, c.end_work_date, u.full_name, u.username, u.department,
               u.sick_leave_days, u.paid_leave_days
        FROM correction_requests c
        JOIN users u ON u.id = c.user_id
        WHERE c.status = 'Approved'
          AND c.request_type IN ('Sick Leave', 'Paid Leave')
    """
    params = []
    if user_id:
        sql += " AND c.user_id = ?"
        params.append(user_id)
    if department:
        sql += " AND COALESCE(u.department, '') = ?"
        params.append(department)
    sql += " ORDER BY c.work_date DESC, c.id DESC"
    rows = []
    for row in fetchall(sql, params):
        item = dict(row)
        for leave_date in expand_request_dates(item["work_date"], item.get("end_work_date")):
            parsed_date = parse_iso_date(leave_date)
            if parsed_date and parsed_date.year == target_year:
                expanded = dict(item)
                expanded["leave_date"] = leave_date
                expanded["work_date"] = leave_date
                rows.append(expanded)
    return rows


def normalize_request_date_range(work_date, end_work_date=""):
    start_date = parse_iso_date(work_date)
    end_date = parse_iso_date(end_work_date, start_date)
    if not start_date:
        raise ValueError("Please choose a valid leave date.")
    if not end_date:
        end_date = start_date
    if end_date < start_date:
        start_date, end_date = end_date, start_date
    return start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")


def expand_request_dates(work_date, end_work_date=""):
    start_str, end_str = normalize_request_date_range(work_date, end_work_date)
    start_date = parse_iso_date(start_str)
    end_date = parse_iso_date(end_str, start_date)
    total_days = (end_date - start_date).days
    return [(start_date + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(total_days + 1)]


def get_request_day_count(row_or_work_date, end_work_date=""):
    if isinstance(row_or_work_date, dict):
        return len(expand_request_dates(row_or_work_date.get("work_date"), row_or_work_date.get("end_work_date")))
    return len(expand_request_dates(row_or_work_date, end_work_date))


def format_request_date_range(work_date, end_work_date=""):
    start_str, end_str = normalize_request_date_range(work_date, end_work_date)
    return start_str if start_str == end_str else f"{start_str} to {end_str}"


def has_overlapping_leave_request(user_id, request_type, work_date, end_work_date, exclude_id=None):
    start_str, end_str = normalize_request_date_range(work_date, end_work_date)
    sql = """
        SELECT id
        FROM correction_requests
        WHERE user_id = ?
          AND request_type = ?
          AND status IN ('Pending', 'Approved')
          AND work_date <= ?
          AND COALESCE(end_work_date, work_date) >= ?
    """
    params = [user_id, request_type, end_str, start_str]
    if exclude_id:
        sql += " AND id != ?"
        params.append(exclude_id)
    sql += " ORDER BY id DESC LIMIT 1"
    return fetchone(sql, params)


def get_overlap_days(start_a, end_a, start_b, end_b):
    left = max(start_a, start_b)
    right = min(end_a, end_b)
    if right < left:
        return []
    total_days = (right - left).days
    return [(left + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(total_days + 1)]


def find_conflicting_disciplinary_action(user_id, action_type, action_date, duration_days=1, exclude_id=None):
    target_start = parse_iso_date(action_date)
    target_end = parse_iso_date(
        calculate_suspension_end_date(action_date, duration_days) if action_type == "Suspension" else action_date,
        target_start
    )
    if not target_start or not target_end:
        return None

    sql = """
        SELECT *
        FROM disciplinary_actions
        WHERE user_id = ?
    """
    params = [user_id]
    if exclude_id:
        sql += " AND id != ?"
        params.append(exclude_id)
    sql += " ORDER BY action_date DESC, id DESC"

    for row in fetchall(sql, params):
        item = dict(row)
        row_start = parse_iso_date(item["action_date"])
        row_end = parse_iso_date(item.get("end_date") or item["action_date"], row_start)
        if not row_start or not row_end:
            continue
        overlapping_days = get_overlap_days(target_start, target_end, row_start, row_end)
        if item["action_type"] == "Suspension" and action_type == "Suspension" and overlapping_days:
            item["conflict_reason"] = f"Overlaps existing suspension on {format_request_date_range(overlapping_days[0], overlapping_days[-1])}."
            return item
        if item["action_date"] == action_date:
            item["conflict_reason"] = f"{item['action_type']} already exists on {action_date}."
            return item
    return None


def get_disciplinary_actions(action_type="", user_id="", department="", date_from="", date_to=""):
    sql = """
        SELECT d.*, u.full_name, u.username, u.department, u.break_limit_minutes, creator.full_name AS created_by_name
        FROM disciplinary_actions d
        JOIN users u ON u.id = d.user_id
        LEFT JOIN users creator ON creator.id = d.created_by
        WHERE 1=1
    """
    params = []
    if action_type:
        sql += " AND d.action_type = ?"
        params.append(action_type)
    if user_id:
        sql += " AND d.user_id = ?"
        params.append(user_id)
    if department:
        sql += " AND COALESCE(u.department, '') = ?"
        params.append(department)
    if date_from:
        sql += " AND COALESCE(d.end_date, d.action_date) >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND d.action_date <= ?"
        params.append(date_to)
    sql += " ORDER BY d.action_date DESC, d.id DESC"

    rows = [dict(row) for row in fetchall(sql, params)]
    today = today_str()
    for row in rows:
        if row["action_type"] == "Suspension":
            action_end = row["end_date"] or row["action_date"]
            if today < row["action_date"]:
                row["status_label"] = "Upcoming"
            elif row["action_date"] <= today <= action_end:
                row["status_label"] = "Active"
            else:
                row["status_label"] = "Completed"
        else:
            row["status_label"] = "Logged"
    return rows


def get_suspension_for_date(user_id, work_date):
    if not user_id or not work_date:
        return None
    return fetchone("""
        SELECT *
        FROM disciplinary_actions
        WHERE user_id = ?
          AND action_type = 'Suspension'
          AND action_date <= ?
          AND COALESCE(end_date, action_date) >= ?
        ORDER BY id DESC LIMIT 1
    """, (user_id, work_date, work_date))


def expand_suspension_dates(row):
    if not row or row.get("action_type") != "Suspension":
        return []
    try:
        start_date = datetime.strptime(row["action_date"], "%Y-%m-%d").date()
        end_date = datetime.strptime((row.get("end_date") or row["action_date"]), "%Y-%m-%d").date()
    except Exception:
        return []
    if end_date < start_date:
        end_date = start_date
    total_days = (end_date - start_date).days
    return [(start_date + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(total_days + 1)]


def get_pending_leave_requests(user_id=None, department="", year=None):
    sql = """
        SELECT c.*, u.full_name, u.username, u.department
        FROM correction_requests c
        JOIN users u ON u.id = c.user_id
        WHERE c.status = 'Pending'
          AND c.request_type IN ('Sick Leave', 'Paid Leave')
    """
    params = []
    if user_id:
        sql += " AND c.user_id = ?"
        params.append(user_id)
    if department:
        sql += " AND COALESCE(u.department, '') = ?"
        params.append(department)
    if year:
        sql += " AND c.work_date <= ? AND COALESCE(c.end_work_date, c.work_date) >= ?"
        params.extend([f"{int(year)}-12-31", f"{int(year)}-01-01"])
    sql += " ORDER BY c.work_date ASC, c.id ASC"
    rows = []
    for row in fetchall(sql, params):
        item = dict(row)
        item["requested_days"] = get_request_day_count(item)
        item["display_date_range"] = format_request_date_range(item["work_date"], item.get("end_work_date"))
        try:
            created_date = datetime.strptime((item.get("created_at") or now_str())[:19], "%Y-%m-%d %H:%M:%S").date()
            item["age_days"] = max((now_dt().date() - created_date).days, 0)
        except Exception:
            item["age_days"] = 0
        rows.append(item)
    return rows


def get_leave_balance_summary(user_row, year=None):
    if not user_row:
        return {
            "year": now_dt().year,
            "sick_total": DEFAULT_SICK_LEAVE_DAYS,
            "sick_used": 0,
            "sick_remaining": DEFAULT_SICK_LEAVE_DAYS,
            "paid_total": DEFAULT_PAID_LEAVE_DAYS,
            "paid_used": 0,
            "paid_remaining": DEFAULT_PAID_LEAVE_DAYS,
        }

    target_year = int(year or now_dt().year)
    approved_rows = get_leave_usage_rows(user_id=user_row["id"], year=target_year)
    sick_used_in_app = len([row for row in approved_rows if row["request_type"] == "Sick Leave"])
    paid_used_in_app = len([row for row in approved_rows if row["request_type"] == "Paid Leave"])
    sick_used_manual = int(user_row["sick_leave_used_manual"] if user_row["sick_leave_used_manual"] is not None else 0)
    paid_used_manual = int(user_row["paid_leave_used_manual"] if user_row["paid_leave_used_manual"] is not None else 0)
    sick_total = int(user_row["sick_leave_days"] if user_row["sick_leave_days"] is not None else DEFAULT_SICK_LEAVE_DAYS)
    paid_total = int(user_row["paid_leave_days"] if user_row["paid_leave_days"] is not None else DEFAULT_PAID_LEAVE_DAYS)
    sick_used = sick_used_manual + sick_used_in_app
    paid_used = paid_used_manual + paid_used_in_app

    return {
        "year": target_year,
        "sick_total": sick_total,
        "sick_used": sick_used,
        "sick_remaining": max(sick_total - sick_used, 0),
        "paid_total": paid_total,
        "paid_used": paid_used,
        "paid_remaining": max(paid_total - paid_used, 0),
        "sick_used_manual": sick_used_manual,
        "paid_used_manual": paid_used_manual,
        "sick_used_in_app": sick_used_in_app,
        "paid_used_in_app": paid_used_in_app,
    }


def build_leave_dashboard_rows(year=None, department=""):
    target_year = int(year or now_dt().year)
    employees_sql = """
        SELECT *
        FROM users
        WHERE role = 'employee'
    """
    params = []
    if department:
        employees_sql += " AND COALESCE(department, '') = ?"
        params.append(department)
    employees_sql += " ORDER BY full_name ASC"
    employees = fetchall(employees_sql, params)

    approved_rows = get_leave_usage_rows(year=target_year, department=department)
    pending_rows = get_pending_leave_requests(department=department, year=target_year)
    approved_map = {}
    pending_map = {}

    for row in approved_rows:
        stats = approved_map.setdefault(row["user_id"], {"Sick Leave": 0, "Paid Leave": 0})
        stats[row["request_type"]] = stats.get(row["request_type"], 0) + 1

    for row in pending_rows:
        stats = pending_map.setdefault(row["user_id"], {"Sick Leave": 0, "Paid Leave": 0})
        stats[row["request_type"]] = stats.get(row["request_type"], 0) + int(row.get("requested_days") or 0)

    rows = []
    for employee in employees:
        approved = approved_map.get(employee["id"], {})
        pending = pending_map.get(employee["id"], {})
        sick_total = int(employee["sick_leave_days"] if employee["sick_leave_days"] is not None else DEFAULT_SICK_LEAVE_DAYS)
        paid_total = int(employee["paid_leave_days"] if employee["paid_leave_days"] is not None else DEFAULT_PAID_LEAVE_DAYS)
        sick_used_manual = int(employee["sick_leave_used_manual"] if employee["sick_leave_used_manual"] is not None else 0)
        paid_used_manual = int(employee["paid_leave_used_manual"] if employee["paid_leave_used_manual"] is not None else 0)
        sick_used_in_app = approved.get("Sick Leave", 0)
        paid_used_in_app = approved.get("Paid Leave", 0)
        sick_used = sick_used_manual + sick_used_in_app
        paid_used = paid_used_manual + paid_used_in_app
        rows.append({
            "user_id": employee["id"],
            "full_name": employee["full_name"],
            "username": employee["username"],
            "department": employee["department"] or "",
            "position": employee["position"] or "",
            "sick_total": sick_total,
            "sick_used": sick_used,
            "sick_remaining": max(sick_total - sick_used, 0),
            "paid_total": paid_total,
            "paid_used": paid_used,
            "paid_remaining": max(paid_total - paid_used, 0),
            "sick_used_manual": sick_used_manual,
            "paid_used_manual": paid_used_manual,
            "sick_used_in_app": sick_used_in_app,
            "paid_used_in_app": paid_used_in_app,
            "pending_sick": pending.get("Sick Leave", 0),
            "pending_paid": pending.get("Paid Leave", 0),
            "pending_total": pending.get("Sick Leave", 0) + pending.get("Paid Leave", 0),
        })

    return rows


def parse_positive_int(value, default):
    try:
        parsed = int(str(value).strip())
        return parsed if parsed > 0 else default
    except Exception:
        return default


def parse_non_negative_int(value, default):
    try:
        parsed = int(str(value).strip())
        return parsed if parsed >= 0 else default
    except Exception:
        return default


def parse_money_value(value, default=0.0):
    try:
        cleaned = str(value).strip().replace(",", "")
        if cleaned == "":
            return default
        parsed = round(float(cleaned), 2)
        return parsed if parsed >= 0 else default
    except Exception:
        return default


def format_currency(value):
    try:
        return f"PHP {float(value or 0):,.2f}"
    except Exception:
        return "PHP 0.00"


def notify_admins_for_leave_and_disciplinary_events():
    leave_rows = build_leave_dashboard_rows(year=now_dt().year)
    for row in leave_rows:
        if row["sick_remaining"] <= 0:
            create_admin_alert_once(
                "Sick Leave Exhausted",
                f"{row['full_name']} has no sick leave remaining for {now_dt().year}."
            )
        if row["paid_remaining"] <= 0:
            create_admin_alert_once(
                "Paid Leave Exhausted",
                f"{row['full_name']} has no paid leave remaining for {now_dt().year}."
            )

    for row in get_pending_leave_requests():
        if int(row.get("age_days") or 0) >= 3:
            create_admin_alert_once(
                "Pending Leave Aging",
                f"{row['full_name']}'s {row['request_type']} request ({row['display_date_range']}) has been pending for {row['age_days']} day(s)."
            )

    for row in get_disciplinary_actions(action_type="Suspension", date_from=today_str(), date_to=today_str()):
        create_admin_alert_once(
            "Suspension Starts Today",
            f"{row['full_name']}'s suspension starts today and runs through {row.get('end_date') or row['action_date']}."
        )


def summarize_employee_admin_changes(before_row, after_values):
    if not before_row:
        return "Created employee record."
    labels = {
        "department": "Department",
        "position": "Position",
        "emergency_contact_name": "Emergency Contact Name",
        "emergency_contact_phone": "Emergency Contact Number",
        "id_issue_date": "ID Issue Date",
        "id_expiration_date": "ID Expiration Date",
        "barcode_id": "Barcode ID",
        "hourly_rate": "Hourly Rate",
        "sick_leave_days": "Sick Leave Allotment",
        "paid_leave_days": "Paid Leave Allotment",
        "sick_leave_used_manual": "Sick Leave Already Used",
        "paid_leave_used_manual": "Paid Leave Already Used",
        "shift_start": "Shift Start",
        "shift_end": "Shift End",
        "break_limit_minutes": "Break Limit",
        "is_active": "Account Status",
    }
    changes = []
    for key, label in labels.items():
        before = before_row[key] if key in before_row.keys() else None
        after = after_values.get(key)
        if str(before) != str(after):
            changes.append(f"{label}: {before} -> {after}")
    return "; ".join(changes) if changes else "No tracked employee settings changed."


def parse_iso_date(value, fallback=None):
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except Exception:
        return fallback


def get_payroll_period_dates(period, date_from_value="", date_to_value=""):
    today = now_dt().date()
    if period == "last_month":
        first_this_month = today.replace(day=1)
        date_to = first_this_month - timedelta(days=1)
        date_from = date_to.replace(day=1)
        return date_from, date_to
    if period == "last_14_days":
        return today - timedelta(days=13), today
    if period == "custom":
        date_from = parse_iso_date(date_from_value, today.replace(day=1))
        date_to = parse_iso_date(date_to_value, today)
        if date_from > date_to:
            date_from, date_to = date_to, date_from
        return date_from, date_to
    return today.replace(day=1), today


def paginate_items(items, page, page_size):
    total = len(items)
    page_size = page_size if page_size in {10, 25, 50, 100} else 25
    total_pages = max((total + page_size - 1) // page_size, 1)
    page = max(min(page, total_pages), 1)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": items[start:end],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "start_index": start + 1 if total else 0,
        "end_index": min(end, total),
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def get_admin_users():
    return fetchall("""
        SELECT id, full_name
        FROM users
        WHERE role = 'admin' AND is_active = 1
        ORDER BY full_name ASC
    """)


def create_admin_alert_once(title, message):
    today_start = f"{today_str()} 00:00:00"
    for admin in get_admin_users():
        existing = fetchone("""
            SELECT id
            FROM notifications
            WHERE user_id = ? AND title = ? AND message = ? AND created_at >= ?
            ORDER BY id DESC LIMIT 1
        """, (admin["id"], title, message, today_start))
        if not existing:
            create_notification(admin["id"], title, message)


def build_payroll_rows(date_from, date_to, department_filter="", employee_filter=""):
    employees_sql = """
        SELECT *
        FROM users
        WHERE role = 'employee'
    """
    params = []
    if department_filter:
        employees_sql += " AND department = ?"
        params.append(department_filter)
    if employee_filter:
        employees_sql += " AND id = ?"
        params.append(employee_filter)
    employees_sql += " ORDER BY full_name ASC"

    employees = fetchall(employees_sql, params)
    employee_map = {}
    for employee in employees:
        employee_map[employee["id"]] = {
            "user_id": employee["id"],
            "full_name": employee["full_name"],
            "username": employee["username"],
            "department": employee["department"] or "",
            "position": employee["position"] or "",
            "hourly_rate": float(employee["hourly_rate"] or 0),
            "days_worked": 0,
            "total_minutes": 0,
            "late_minutes": 0,
            "break_minutes": 0,
            "gross_pay": 0,
            "suspension_days": 0,
            "suspension_hours": 0,
            "suspension_pay": 0,
            "has_rate": 1 if float(employee["hourly_rate"] or 0) > 0 else 0,
            "is_active": employee["is_active"],
            "schedule_days": employee["schedule_days"] or DEFAULT_SCHEDULE_DAYS,
            "shift_start": employee["shift_start"] or DEFAULT_SHIFT_START,
            "shift_end": employee["shift_end"] or DEFAULT_SHIFT_END,
        }

    attendance_rows = fetchall("""
        SELECT a.*, u.department
        FROM attendance a
        JOIN users u ON u.id = a.user_id
        WHERE u.role = 'employee'
          AND a.work_date BETWEEN ? AND ?
          AND a.time_in IS NOT NULL
          AND a.time_out IS NOT NULL
        ORDER BY a.work_date ASC, a.id ASC
    """, (date_from.strftime("%Y-%m-%d"), date_to.strftime("%Y-%m-%d")))

    for attendance in attendance_rows:
        summary = employee_map.get(attendance["user_id"])
        if not summary:
            continue
        minutes_worked = max(total_work_minutes(attendance), 0)
        summary["days_worked"] += 1
        summary["total_minutes"] += minutes_worked
        summary["late_minutes"] += int(attendance["late_minutes"] or 0)
        summary["break_minutes"] += total_break_minutes(attendance["id"])

    suspension_rows = fetchall("""
        SELECT *
        FROM disciplinary_actions
        WHERE action_type = 'Suspension'
          AND action_date <= ?
          AND COALESCE(end_date, action_date) >= ?
    """, (date_to.strftime("%Y-%m-%d"), date_from.strftime("%Y-%m-%d")))
    for suspension in suspension_rows:
        summary = employee_map.get(suspension["user_id"])
        if not summary:
            continue
        for suspension_date in expand_suspension_dates(suspension):
            if suspension_date < date_from.strftime("%Y-%m-%d") or suspension_date > date_to.strftime("%Y-%m-%d"):
                continue
            employee_stub = {
                "schedule_days": summary["schedule_days"],
                "shift_start": summary["shift_start"],
                "shift_end": summary["shift_end"],
            }
            if not is_scheduled_on_date(employee_stub, suspension_date):
                continue
            shift_minutes = get_scheduled_shift_minutes(employee_stub, suspension_date)
            summary["suspension_days"] += 1
            summary["suspension_hours"] += round(shift_minutes / 60, 2)

    for summary in employee_map.values():
        summary["total_hours"] = round(summary["total_minutes"] / 60, 2)
        summary["gross_pay"] = round(summary["total_hours"] * summary["hourly_rate"], 2)
        summary["suspension_hours"] = round(summary["suspension_hours"], 2)
        summary["suspension_pay"] = round(summary["suspension_hours"] * summary["hourly_rate"], 2)
        summary["status_label"] = "Ready" if summary["has_rate"] else "Missing Rate"

    return sorted(employee_map.values(), key=lambda item: (-item["gross_pay"], item["full_name"].lower()))


# =========================
# GOOGLE SHEETS SYNC (OPTIONAL)
# =========================
def append_attendance_to_google_sheet(user_row, attendance_row):
    if not GOOGLE_SHEETS_ENABLED:
        return False, "Google Sheets libraries not installed."

    if not os.path.exists(GOOGLE_CREDENTIALS_FILE):
        return False, "attendance-credentials.json not found."

    try:
        scopes = [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive"
        ]
        creds = Credentials.from_service_account_file(GOOGLE_CREDENTIALS_FILE, scopes=scopes)
        client = gspread.authorize(creds)
        sheet = client.open(GOOGLE_SHEET_NAME)

        try:
            ws = sheet.worksheet(GOOGLE_SHEET_TAB)
        except Exception:
            ws = sheet.add_worksheet(title=GOOGLE_SHEET_TAB, rows=1000, cols=20)

        values = ws.get_all_values()
        if not values:
            ws.append_row([
                "Employee ID", "Full Name", "Username", "Department", "Position", "Shift Start",
                "Work Date", "Time In", "Time Out", "Status",
                "Late", "Late Minutes", "Break Minutes", "Work Minutes",
                "Notes", "Proof File"
            ])

        ws.append_row([
            user_row["id"],
            user_row["full_name"],
            user_row["username"],
            user_row["department"] or "",
            user_row["position"] or "",
            user_row["shift_start"] or DEFAULT_SHIFT_START,
            attendance_row["work_date"] or "",
            attendance_row["time_in"] or "",
            attendance_row["time_out"] or "",
            attendance_row["status"] or "",
            "YES" if attendance_row["late_flag"] else "NO",
            attendance_row["late_minutes"] or 0,
            total_break_minutes(attendance_row["id"]),
            total_work_minutes(attendance_row),
            attendance_row["notes"] or "",
            attendance_row["proof_file"] or ""
        ])
        return True, "Synced to Google Sheets."
    except Exception as e:
        return False, str(e)


# =========================
# TEMPLATE GLOBALS
# =========================
@app.context_processor
def inject_globals():
    user = None
    unread_count = 0
    latest_notifications = []

    if session.get("user_id"):
        user = get_user_by_id(session["user_id"])
        if user:
            unread = fetchone("""
                SELECT COUNT(*) AS cnt FROM notifications
                WHERE user_id = ? AND is_read = 0
            """, (session["user_id"],))
            unread_count = unread["cnt"] if unread else 0
            latest_notifications = fetchall("""
                SELECT *
                FROM notifications
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 6
            """, (session["user_id"],))

    return dict(
        current_user=user,
        unread_count=unread_count,
        latest_notifications=latest_notifications,
        is_image=is_image,
        static_file_exists=static_file_exists,
        uploaded_file_exists=uploaded_file_exists,
        get_avatar_initials=get_avatar_initials,
        get_employee_card_number=get_employee_card_number,
        generate_code128_svg_data_uri=generate_code128_svg_data_uri,
        format_datetime_12h=format_datetime_12h,
        format_time_12h=format_time_12h,
        format_currency=format_currency
    )


# =========================
# AUTH / HOME
# =========================
@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": now_str()}), 200


@app.route("/")
def home():
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            return redirect(url_for("login"))

        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = fetchone("""
            SELECT * FROM users
            WHERE username = ? AND is_active = 1
        """, (username,))

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]

            log_activity(user["id"], "LOGIN", f"{user['full_name']} logged in")

            if user["role"] == "admin":
                flash("Welcome Admin.", "success")
                return redirect(url_for("admin_dashboard"))

            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_activity(user_id, "LOGOUT", "User logged out")
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# =========================
# EMPLOYEE
# =========================
@app.route("/dashboard")
@login_required(role="employee")
def dashboard():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    today_attendance = get_current_attendance(user["id"])
    open_break = get_open_break(user["id"], today_attendance)

    notifications = fetchall("""
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
    """, (user["id"],))

    logs = fetchall("""
        SELECT * FROM activity_logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
    """, (user["id"],))

    current_status = get_user_live_status(user["id"])
    override_status = get_employee_override_status_for_date(user["id"], today_str())
    if override_status:
        current_status = override_status["label"]
    todays_break_minutes = total_break_minutes(today_attendance["id"], include_open=True) if today_attendance else 0
    todays_work_minutes = total_work_minutes(today_attendance) if today_attendance else 0
    todays_break_sessions = build_break_sessions(today_attendance["id"]) if today_attendance else []
    break_limit_minutes = get_employee_break_limit(user)
    over_break_minutes = get_overbreak_minutes(todays_break_minutes, break_limit_minutes)
    leave_summary = get_leave_balance_summary(user)

    return render_template(
        "employee_dashboard.html",
        user=user,
        today_attendance=today_attendance,
        notifications=notifications,
        current_status=current_status,
        override_status=override_status,
        todays_break_minutes=todays_break_minutes,
        todays_work_minutes=todays_work_minutes,
        todays_break_sessions=todays_break_sessions,
        leave_summary=leave_summary,
        break_limit_minutes=break_limit_minutes,
        over_break_minutes=over_break_minutes,
        minutes_to_hm=minutes_to_hm
    )


@app.route("/actions")
@login_required(role="employee")
def employee_actions():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    return render_template("employee_actions.html", user=user)


@app.route("/activity")
@login_required(role="employee")
def employee_activity():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    logs = fetchall("""
        SELECT * FROM activity_logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
    """, (user["id"],))

    return render_template("employee_activity.html", user=user, logs=logs)


@app.route("/notifications")
@login_required()
def notifications_page():
    user = get_user_by_id(session["user_id"])
    notifications = fetchall("""
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
    """, (session["user_id"],))

    return render_template(
        "notifications.html",
        user=user,
        notifications=notifications
    )


@app.route("/history")
@login_required(role="employee")
def employee_history():
    user = get_user_by_id(session["user_id"])
    records = build_employee_history_records(user, limit=60)
    return render_template("employee_history.html", records=records, minutes_to_hm=minutes_to_hm)


@app.route("/profile", methods=["GET", "POST"])
@login_required(role="employee")
def employee_profile():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        if not full_name:
            flash("Full name is required.", "danger")
            return redirect(url_for("employee_profile"))

        password = request.form.get("password", "").strip()

        profile_image = user["profile_image"]
        file = request.files.get("profile_image")
        if file and file.filename:
            saved = save_uploaded_file(file, prefix=f"profile_{user['id']}")
            if not saved:
                flash("Invalid profile image type.", "danger")
                return redirect(url_for("employee_profile"))
            profile_image = saved

        if password:
            execute_db("""
                UPDATE users
                SET full_name = ?, password_hash = ?, profile_image = ?
                WHERE id = ?
            """, (full_name, generate_password_hash(password), profile_image, user["id"]), commit=True)
        else:
            execute_db("""
                UPDATE users
                SET full_name = ?, profile_image = ?
                WHERE id = ?
            """, (full_name, profile_image, user["id"]), commit=True)

        session["full_name"] = full_name
        log_activity(user["id"], "UPDATE PROFILE", "Employee updated profile")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("employee_profile"))

    return render_template("employee_profile.html", user=user)


@app.route("/admin/profile", methods=["GET", "POST"])
@login_required(role="admin")
def admin_profile():
    user = get_user_by_id(session["user_id"])
    if not user or user["role"] != "admin":
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        if not full_name:
            flash("Full name is required.", "danger")
            return redirect(url_for("admin_profile"))

        password = request.form.get("password", "").strip()

        profile_image = user["profile_image"]
        file = request.files.get("profile_image")
        if file and file.filename:
            saved = save_uploaded_file(file, prefix=f"profile_{user['id']}")
            if not saved:
                flash("Invalid profile image type.", "danger")
                return redirect(url_for("admin_profile"))
            profile_image = saved

        if password:
            execute_db("""
                UPDATE users
                SET full_name = ?, password_hash = ?, profile_image = ?
                WHERE id = ?
            """, (full_name, generate_password_hash(password), profile_image, user["id"]), commit=True)
            log_activity(user["id"], "UPDATE ADMIN PROFILE", "Admin updated profile and password")
        else:
            execute_db("""
                UPDATE users
                SET full_name = ?, profile_image = ?
                WHERE id = ?
            """, (full_name, profile_image, user["id"]), commit=True)
            log_activity(user["id"], "UPDATE ADMIN PROFILE", "Admin updated profile")

        session["full_name"] = full_name
        flash("Admin profile updated successfully.", "success")
        return redirect(url_for("admin_profile"))

    return render_template("admin_profile.html", user=user)


@app.route("/corrections", methods=["GET", "POST"])
@login_required(role="employee")
def employee_corrections():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        request_type = request.form.get("request_type", "").strip()
        work_date = request.form.get("work_date", "").strip()
        end_work_date = request.form.get("end_work_date", "").strip()
        message = request.form.get("message", "").strip()
        requested_time_in = request.form.get("requested_time_in", "")
        requested_break_start = request.form.get("requested_break_start", "")
        requested_break_end = request.form.get("requested_break_end", "")
        requested_time_out = request.form.get("requested_time_out", "")

        if request_type not in ATTENDANCE_REQUEST_TYPES:
            flash("Please choose a valid correction type.", "danger")
            return redirect(url_for("employee_corrections"))

        if not work_date or not message:
            flash("Work date and details are required.", "danger")
            return redirect(url_for("employee_corrections"))

        try:
            requested_time_in = normalize_optional_clock_time(requested_time_in)
            requested_break_start = normalize_optional_clock_time(requested_break_start)
            requested_break_end = normalize_optional_clock_time(requested_break_end)
            requested_time_out = normalize_optional_clock_time(requested_time_out)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("employee_corrections"))

        if request_type == "Undertime" and not requested_time_out:
            flash("Requested time out is required for undertime requests.", "danger")
            return redirect(url_for("employee_corrections"))

        if request_type in LEAVE_REQUEST_TYPES:
            try:
                work_date, end_work_date = normalize_request_date_range(work_date, end_work_date or work_date)
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("employee_corrections"))
            requested_time_in = ""
            requested_break_start = ""
            requested_break_end = ""
            requested_time_out = ""

            existing_leave = has_overlapping_leave_request(user["id"], request_type, work_date, end_work_date)
            if existing_leave:
                flash(f"A {request_type.lower()} request already exists in that date range.", "warning")
                return redirect(url_for("employee_corrections"))
        else:
            end_work_date = work_date

        attendance, break_row = get_attendance_context(user["id"], work_date)
        requested_time_in_dt, requested_break_start_dt, requested_break_end_dt, requested_time_out_dt = resolve_correction_datetimes(
            work_date,
            time_in_value=requested_time_in,
            break_start_value=requested_break_start,
            break_end_value=requested_break_end,
            time_out_value=requested_time_out,
            existing_time_in=attendance["time_in"] if attendance else None,
            existing_break_start=break_row["break_start"] if break_row else None,
            existing_break_end=break_row["break_end"] if break_row else None,
            existing_time_out=attendance["time_out"] if attendance else None,
            use_existing_values=False
        )

        execute_db("""
            INSERT INTO correction_requests (
                user_id, request_type, work_date, end_work_date, message,
                requested_time_in, requested_break_start, requested_break_end, requested_time_out,
                status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
        """, (
            user["id"],
            request_type,
            work_date,
            end_work_date,
            message,
            requested_time_in_dt,
            requested_break_start_dt,
            requested_break_end_dt,
            requested_time_out_dt,
            now_str()
        ), commit=True)

        log_activity(user["id"], "CORRECTION REQUEST", f"Submitted {request_type} request for {format_request_date_range(work_date, end_work_date)}")
        flash("Correction request submitted.", "success")
        return redirect(url_for("employee_corrections"))

    requests = get_correction_requests(user_id=user["id"])
    leave_summary = get_leave_balance_summary(user)
    return render_template("employee_corrections.html", requests=requests, leave_summary=leave_summary)


@app.route("/time-in", methods=["POST"])
@login_required(role="employee")
def time_in():
    user_id = session["user_id"]
    user = get_user_by_id(user_id)

    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    override_status = get_employee_override_status_for_date(user_id, today_str())
    if override_status and override_status["type"] == "Suspension":
        flash(f"You cannot time in while suspended. Suspension ends on {override_status['end_date']}.", "danger")
        return redirect(url_for("dashboard"))

    existing = get_current_attendance(user_id)
    if existing and existing["time_in"] and not existing["time_out"]:
        flash("You are already timed in.", "warning")
        return redirect(url_for("dashboard"))

    file = request.files.get("proof_file")
    proof_filename = None

    if file and file.filename:
        proof_filename = save_uploaded_file(file, prefix=f"proof_{user_id}")
        if not proof_filename:
            flash("Invalid upload file type.", "danger")
            return redirect(url_for("dashboard"))

    execute_db("""
        INSERT INTO attendance (
            user_id, work_date, time_in, time_out, status, proof_file, notes,
            late_flag, late_minutes, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        today_str(),
        now_str(),
        None,
        "Timed In",
        proof_filename,
        request.form.get("notes", "").strip(),
        *calculate_late_info(now_str(), parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START)),
        now_str(),
        now_str()
    ), commit=True)

    shift_start = parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START)
    latest_attendance = get_current_attendance(user_id)

    if latest_attendance and latest_attendance["late_flag"]:
        create_notification(
            user_id,
            "Late Time-In",
            f"You timed in late by {latest_attendance['late_minutes']} minute(s). Shift start: {shift_start} ET."
        )
    else:
        create_notification(user_id, "Timed In", f"You timed in at {now_str()} ET.")

    log_activity(user_id, "TIME IN", f"Employee timed in. Shift: {shift_start}")
    flash("Time in successful.", "success")
    return redirect(url_for("dashboard"))


@app.route("/start-break", methods=["POST"])
@login_required(role="employee")
def start_break():
    user_id = session["user_id"]
    override_status = get_employee_override_status_for_date(user_id, today_str())
    if override_status and override_status["type"] == "Suspension":
        flash(f"You cannot start a break while suspended. Suspension ends on {override_status['end_date']}.", "danger")
        return redirect(url_for("dashboard"))
    user = get_user_by_id(user_id)
    attendance = get_current_attendance(user_id)

    if not attendance or not attendance["time_in"] or attendance["time_out"]:
        flash("You must be timed in first.", "danger")
        return redirect(url_for("dashboard"))

    open_break = get_open_break(user_id, attendance)
    if open_break:
        flash("You are already on break.", "warning")
        return redirect(url_for("dashboard"))

    break_limit_minutes = get_employee_break_limit(user)
    used_break_minutes = total_break_minutes(attendance["id"])
    if used_break_minutes >= break_limit_minutes:
        flash(f"Your daily break limit of {break_limit_minutes} minutes has already been used.", "warning")
        return redirect(url_for("dashboard"))

    execute_db("""
        INSERT INTO breaks (user_id, attendance_id, work_date, break_start, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, attendance["id"], attendance["work_date"], now_str(), now_str()), commit=True)

    execute_db("""
        UPDATE attendance
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, ("On Break", now_str(), attendance["id"]), commit=True)

    remaining_break = max(break_limit_minutes - used_break_minutes, 0)
    create_notification(user_id, "Break Started", f"You started break at {now_str()} ET. Remaining break allowance: {remaining_break} minute(s).")
    log_activity(user_id, "BREAK START", "Employee started break")
    flash("Break started.", "info")
    return redirect(url_for("dashboard"))


@app.route("/end-break", methods=["POST"])
@login_required(role="employee")
def end_break():
    user_id = session["user_id"]
    override_status = get_employee_override_status_for_date(user_id, today_str())
    if override_status and override_status["type"] == "Suspension":
        flash(f"You cannot end a break while suspended. Suspension ends on {override_status['end_date']}.", "danger")
        return redirect(url_for("dashboard"))
    attendance = get_current_attendance(user_id)
    open_break = get_open_break(user_id, attendance)

    if not open_break:
        flash("No active break found.", "warning")
        return redirect(url_for("dashboard"))

    execute_db("""
        UPDATE breaks
        SET break_end = ?
        WHERE id = ?
    """, (now_str(), open_break["id"]), commit=True)

    if attendance:
        execute_db("""
            UPDATE attendance
            SET status = ?, updated_at = ?
            WHERE id = ?
    """, ("Timed In", now_str(), attendance["id"]), commit=True)

    create_notification(user_id, "Break Ended", f"You ended break at {now_str()} ET.")
    user = get_user_by_id(user_id)
    if attendance:
        total_break = total_break_minutes(attendance["id"])
        break_limit_minutes = get_employee_break_limit(user)
        if is_overbreak(total_break, break_limit_minutes):
            create_notification(
                user_id,
                "Break Limit Exceeded",
                f"Your total break time for today is {minutes_to_hm(total_break)}, which is over your {break_limit_minutes} minute limit."
            )
    log_activity(user_id, "BREAK END", "Employee ended break")
    flash("Break ended.", "success")
    return redirect(url_for("dashboard"))


@app.route("/time-out", methods=["POST"])
@login_required(role="employee")
def time_out():
    user_id = session["user_id"]
    override_status = get_employee_override_status_for_date(user_id, today_str())
    if override_status and override_status["type"] == "Suspension":
        flash(f"You cannot time out while suspended. Suspension ends on {override_status['end_date']}.", "danger")
        return redirect(url_for("dashboard"))
    attendance = get_current_attendance(user_id)

    if not attendance or not attendance["time_in"]:
        flash("You are not timed in.", "danger")
        return redirect(url_for("dashboard"))

    if attendance["time_out"]:
        flash("You are already timed out.", "warning")
        return redirect(url_for("dashboard"))

    open_break = get_open_break(user_id, attendance)
    if open_break:
        execute_db("""
            UPDATE breaks
            SET break_end = ?
            WHERE id = ?
        """, (now_str(), open_break["id"]), commit=True)

    execute_db("""
        UPDATE attendance
        SET time_out = ?, status = ?, updated_at = ?
        WHERE id = ?
    """, (now_str(), "Timed Out", now_str(), attendance["id"]), commit=True)

    user_row = get_user_by_id(user_id)
    updated_attendance = get_attendance_by_id(attendance["id"])
    ok, msg = append_attendance_to_google_sheet(user_row, updated_attendance)

    create_notification(user_id, "Timed Out", f"You timed out at {now_str()} ET.")
    log_activity(user_id, "TIME OUT", f"Employee timed out. Sheets sync: {msg if ok else 'Skipped/Failed'}")
    flash("Time out successful.", "success")
    return redirect(url_for("dashboard"))


@app.route("/notifications/read/<int:notif_id>", methods=["POST"])
@login_required()
def read_notification(notif_id):
    execute_db("""
        UPDATE notifications
        SET is_read = 1
        WHERE id = ? AND user_id = ?
    """, (notif_id, session["user_id"]), commit=True)

    if session.get("role") == "admin":
        return redirect(request.referrer or url_for("admin_dashboard"))
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/notifications/read-all", methods=["POST"])
@login_required()
def read_all_notifications():
    execute_db("""
        UPDATE notifications
        SET is_read = 1
        WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],), commit=True)

    flash("All notifications marked as read.", "success")
    return redirect(request.referrer or url_for("notifications_page"))


@app.route("/uploads/<path:filename>")
@login_required()
def uploaded_file(filename):
    user = get_user_by_id(session["user_id"])
    if not can_access_uploaded_file(user, filename):
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# =========================
# ADMIN
# =========================
def get_admin_employee_rows(status_filter="", search="", department_filter="", over_break_only=""):
    users = fetchall("""
        SELECT * FROM users
        WHERE role = 'employee'
        ORDER BY full_name ASC
    """)

    employees = []
    for user in users:
        live_status = get_user_live_status(user["id"])
        attendance = get_current_attendance(user["id"])
        scheduled_today = is_scheduled_today(user)
        suspension_today = get_suspension_for_date(user["id"], today_str())
        absent_today = is_absent_today(user, attendance)
        missing_timeout_today = is_missing_timeout_today(user, attendance)
        undertime_today = 1 if is_undertime_record(
            user,
            {**dict(attendance), "source_type": "attendance"} if attendance else None
        ) else 0
        status_display = live_status

        if user["is_active"] != 1:
            status_display = "Inactive"
        elif suspension_today:
            status_display = "Suspended"
        elif absent_today:
            status_display = "Absent"
        elif missing_timeout_today:
            status_display = "Missing Time Out"
        elif undertime_today:
            status_display = "Undertime"
        elif not scheduled_today and live_status == "Offline":
            status_display = "Off Day"

        row = {
            "id": user["id"],
            "full_name": user["full_name"],
            "username": user["username"],
            "department": user["department"],
            "position": user["position"],
            "schedule_days": user["schedule_days"] or DEFAULT_SCHEDULE_DAYS,
            "schedule_summary": get_schedule_summary(user["schedule_days"] or DEFAULT_SCHEDULE_DAYS),
            "scheduled_today": 1 if scheduled_today else 0,
            "absent_flag": 1 if absent_today else 0,
            "suspension_flag": 1 if suspension_today else 0,
            "shift_start": user["shift_start"] or DEFAULT_SHIFT_START,
            "shift_end": user["shift_end"] or DEFAULT_SHIFT_END,
            "break_window_start": user["break_window_start"] or DEFAULT_BREAK_WINDOW_START,
            "break_window_end": user["break_window_end"] or DEFAULT_BREAK_WINDOW_END,
            "schedule_window_summary": get_schedule_window_summary(user),
            "break_limit_minutes": get_employee_break_limit(user),
            "profile_image": user["profile_image"],
            "profile_image_available": 1 if uploaded_file_exists(user["profile_image"]) else 0,
            "is_active": user["is_active"],
            "status": live_status,
            "status_display": status_display,
            "time_in": attendance["time_in"] if attendance else None,
            "time_out": attendance["time_out"] if attendance else None,
            "proof_file": attendance["proof_file"] if attendance else None,
            "proof_file_available": 1 if attendance and uploaded_file_exists(attendance["proof_file"]) else 0,
            "late_flag": attendance["late_flag"] if attendance else 0,
            "late_minutes": attendance["late_minutes"] if attendance else 0,
            "break_minutes": total_break_minutes(attendance["id"], include_open=True) if attendance else 0
        }
        row["over_break_minutes"] = get_overbreak_minutes(row["break_minutes"], row["break_limit_minutes"])
        row["over_break_flag"] = 1 if row["over_break_minutes"] > 0 else 0
        row["missing_timeout_flag"] = 1 if missing_timeout_today else 0
        row["undertime_flag"] = undertime_today
        row["avatar_initials"] = get_avatar_initials(user["full_name"])
        row["attention_score"] = int(row["absent_flag"]) + int(row["late_flag"]) + int(row["over_break_flag"]) + int(row["missing_timeout_flag"]) + int(row["undertime_flag"])

        if status_filter and row["status_display"] != status_filter:
            continue

        if over_break_only == "1" and row["over_break_flag"] != 1:
            continue

        if search:
            s = search.lower()
            hay = f"{row['full_name']} {row['username']} {row['department']} {row['position']} {row['shift_start']} {row['schedule_summary']}".lower()
            if s not in hay:
                continue

        if department_filter and (row["department"] or "").strip() != department_filter:
            continue

        employees.append(row)

    return employees


def get_incident_reports(report_employee="", report_department="", report_type="", report_date_from="", report_date_to=""):
    report_sql = """
        SELECT r.*, u.full_name, u.department, reviewer.full_name AS reviewed_by_name
        FROM incident_reports r
        LEFT JOIN users u ON u.id = r.user_id
        LEFT JOIN users reviewer ON reviewer.id = r.reviewed_by
        WHERE 1=1
    """
    report_params = []

    if report_employee:
        report_sql += " AND r.user_id = ?"
        report_params.append(report_employee)

    if report_department:
        report_sql += " AND COALESCE(r.report_department, u.department, '') = ?"
        report_params.append(report_department)

    if report_type:
        report_sql += " AND LOWER(r.error_type) = ?"
        report_params.append(report_type.lower())

    if report_date_from:
        report_sql += " AND COALESCE(r.report_date, r.incident_date) >= ?"
        report_params.append(report_date_from)

    if report_date_to:
        report_sql += " AND COALESCE(r.report_date, r.incident_date) <= ?"
        report_params.append(report_date_to)

    report_sql += " ORDER BY r.id DESC LIMIT 100"
    return fetchall(report_sql, report_params)


def get_exception_collections(employee_rows):
    absent = [row for row in employee_rows if row["absent_flag"] == 1]
    late = [row for row in employee_rows if row["late_flag"] == 1]
    over_break = [row for row in employee_rows if row["over_break_flag"] == 1]
    missing_timeout = [row for row in employee_rows if row["missing_timeout_flag"] == 1]
    undertime = [row for row in employee_rows if row["undertime_flag"] == 1]

    return {
        "absent": sorted(absent, key=lambda row: (row["department"] or "", row["full_name"] or "")),
        "late": sorted(late, key=lambda row: (-row["late_minutes"], row["full_name"] or "")),
        "over_break": sorted(over_break, key=lambda row: (-row["over_break_minutes"], row["full_name"] or "")),
        "missing_timeout": sorted(missing_timeout, key=lambda row: (row["shift_end"] or "", row["full_name"] or "")),
        "undertime": sorted(undertime, key=lambda row: (row["shift_end"] or "", row["full_name"] or "")),
    }


def get_suspicious_attendance_records(search="", limit=50):
    rows = fetchall("""
        SELECT a.*, u.full_name, u.username, u.department, u.position, u.shift_start, u.shift_end, u.break_limit_minutes
        FROM attendance a
        JOIN users u ON u.id = a.user_id
        WHERE u.role = 'employee'
        ORDER BY a.work_date DESC, a.id DESC
        LIMIT 300
    """)

    candidates = []
    for row in rows:
        item = dict(row)
        if search:
            hay = f"{item['full_name']} {item['username']} {item['work_date']}".lower()
            if search.lower() not in hay:
                continue
        issues, warnings = collect_attendance_diagnostics(item, item)
        if not issues and not warnings:
            continue
        break_rows = get_break_rows(item["id"])
        item["issue_summary"] = "; ".join(issues) if issues else "Needs review"
        item["issues"] = issues
        item["warnings"] = warnings
        item["severity"] = "error" if issues else "warning"
        item["warning_summary"] = "; ".join(warnings)
        item["break_count"] = len(break_rows)
        item["raw_work_minutes"] = total_work_minutes(item)
        item["break_summary"] = summarize_break_sessions(build_break_sessions(item["id"])) if break_rows else "No break sessions recorded."
        item["time_in_input"] = item["time_in"].replace(" ", "T")[:16] if item.get("time_in") else ""
        item["time_out_input"] = item["time_out"].replace(" ", "T")[:16] if item.get("time_out") else ""
        candidates.append(item)
        if len(candidates) >= limit:
            break
    return candidates


def update_attendance_record_by_admin(attendance_id, time_in_value="", time_out_value="", clear_breaks=False):
    attendance = get_attendance_by_id(attendance_id)
    if not attendance:
        raise ValueError("Attendance record not found.")

    user = get_user_by_id(attendance["user_id"])
    final_time_in = parse_datetime_local_input(time_in_value) if time_in_value else attendance["time_in"]
    final_time_out = parse_datetime_local_input(time_out_value) if time_out_value else attendance["time_out"]

    if final_time_in and final_time_out and final_time_out < final_time_in:
        shift_start = parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START)
        shift_end = parse_shift_end(user["shift_end"] if user else DEFAULT_SHIFT_END)
        overnight_shift = shift_end <= shift_start
        if overnight_shift:
            adjusted_time_out = parse_db_datetime(final_time_out) + timedelta(days=1)
            final_time_out = adjusted_time_out.strftime("%Y-%m-%d %H:%M:%S")

    if final_time_in and final_time_out and final_time_out < final_time_in:
        raise ValueError("Time out cannot be earlier than time in.")

    late_flag, late_minutes = calculate_late_info(final_time_in, parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START))
    open_break = get_open_break_for_attendance(attendance_id)
    if final_time_out:
        final_status = "Timed Out"
    elif open_break:
        final_status = "On Break"
    elif final_time_in:
        final_status = "Timed In"
    else:
        final_status = "Offline"

    execute_db("""
        UPDATE attendance
        SET time_in = ?, time_out = ?, status = ?, late_flag = ?, late_minutes = ?, updated_at = ?
        WHERE id = ?
    """, (
        final_time_in,
        final_time_out,
        final_status,
        late_flag,
        late_minutes,
        now_str(),
        attendance_id
    ), commit=True)

    if clear_breaks:
        execute_db("DELETE FROM breaks WHERE attendance_id = ?", (attendance_id,), commit=True)

    if final_time_out:
        execute_db("""
            UPDATE breaks
            SET break_end = CASE
                WHEN break_end IS NULL OR break_end > ? THEN ?
                ELSE break_end
            END
            WHERE attendance_id = ?
        """, (final_time_out, final_time_out, attendance_id), commit=True)

    return get_attendance_by_id(attendance_id)


def notify_admins_for_exceptions(exception_groups):
    for row in exception_groups["absent"]:
        create_admin_alert_once(
            "Absent Today",
            f"{row['full_name']} is scheduled for today in {row['department'] or 'Unassigned'} and has not timed in yet."
        )

    for row in exception_groups["missing_timeout"]:
        create_admin_alert_once(
            "Missing Time Out",
            f"{row['full_name']} reached the scheduled shift end at {row['shift_end']} without timing out."
        )


def get_correction_requests(user_id=None, status="", date_from="", date_to=""):
    sql = """
        SELECT c.*, u.full_name, u.username, reviewer.full_name AS reviewed_by_name
        FROM correction_requests c
        JOIN users u ON u.id = c.user_id
        LEFT JOIN users reviewer ON reviewer.id = c.reviewed_by
        WHERE 1=1
    """
    params = []

    if user_id:
        sql += " AND c.user_id = ?"
        params.append(user_id)

    if status:
        sql += " AND c.status = ?"
        params.append(status)

    if date_from:
        sql += " AND COALESCE(c.end_work_date, c.work_date) >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND c.work_date <= ?"
        params.append(date_to)

    sql += " ORDER BY c.id DESC LIMIT 200"
    rows = fetchall(sql, params)
    enriched_rows = []

    for row in rows:
        item = dict(row)
        item["display_date_range"] = format_request_date_range(item["work_date"], item.get("end_work_date"))
        item["requested_days"] = get_request_day_count(item)
        attendance = fetchone("""
            SELECT *
            FROM attendance
            WHERE user_id = ? AND work_date = ?
            ORDER BY id DESC LIMIT 1
        """, (item["user_id"], item["work_date"]))
        break_row = None

        if attendance:
            break_row = fetchone("""
                SELECT *
                FROM breaks
                WHERE attendance_id = ?
                ORDER BY id ASC LIMIT 1
            """, (attendance["id"],))

        item["current_time_in"] = attendance["time_in"] if attendance else None
        item["current_time_out"] = attendance["time_out"] if attendance else None
        item["current_break_start"] = break_row["break_start"] if break_row else None
        item["current_break_end"] = break_row["break_end"] if break_row else None
        item["requested_time_in_input"] = split_datetime_to_time(item.get("requested_time_in"))
        item["requested_break_start_input"] = split_datetime_to_time(item.get("requested_break_start"))
        item["requested_break_end_input"] = split_datetime_to_time(item.get("requested_break_end"))
        item["requested_time_out_input"] = split_datetime_to_time(item.get("requested_time_out"))
        item["current_time_in_input"] = split_datetime_to_time(item.get("current_time_in"))
        item["current_break_start_input"] = split_datetime_to_time(item.get("current_break_start"))
        item["current_break_end_input"] = split_datetime_to_time(item.get("current_break_end"))
        item["current_time_out_input"] = split_datetime_to_time(item.get("current_time_out"))
        enriched_rows.append(item)

    return enriched_rows


def get_approved_special_requests(user_id=None, search="", department="", date_from="", date_to=""):
    sql = """
        SELECT c.*, u.full_name, u.username, u.break_limit_minutes
        FROM correction_requests c
        JOIN users u ON u.id = c.user_id
        WHERE c.status = 'Approved' AND c.request_type IN ('Undertime', 'Sick Leave', 'Paid Leave')
    """
    params = []

    if user_id:
        sql += " AND c.user_id = ?"
        params.append(user_id)

    if search:
        sql += " AND (LOWER(u.full_name) LIKE ? OR LOWER(u.username) LIKE ?)"
        s = f"%{search.lower()}%"
        params.extend([s, s])

    if department:
        sql += " AND COALESCE(u.department, '') = ?"
        params.append(department)

    if date_from:
        sql += " AND COALESCE(c.end_work_date, c.work_date) >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND c.work_date <= ?"
        params.append(date_to)

    sql += " ORDER BY c.work_date DESC, c.id DESC"
    return fetchall(sql, params)


def enrich_history_record(row, break_limit_minutes, employee_row=None):
    record_type = row.get("request_type") or "Attendance"
    is_attendance = row.get("source_type", "attendance") == "attendance"
    break_minutes = total_break_minutes(row["id"]) if is_attendance and row.get("id") else 0
    work_row = dict(row)
    if record_type == "Undertime" and row.get("requested_time_out"):
        work_row["time_out"] = row.get("requested_time_out")
        row["time_out"] = row.get("requested_time_out")
    suspicious_work_flag = 1 if is_suspicious_work_duration(employee_row, work_row) else 0
    raw_work_minutes = total_work_minutes(work_row) if is_attendance else 0
    work_minutes = 0 if suspicious_work_flag else raw_work_minutes
    over_break_minutes = get_overbreak_minutes(break_minutes, break_limit_minutes)
    break_sessions = build_break_sessions(row["id"]) if is_attendance and row.get("id") else []
    undertime_flag = 1 if not suspicious_work_flag and is_undertime_record(employee_row, work_row) else 0
    if record_type == "Attendance" and undertime_flag:
        record_type = "Undertime"
    display_status = row.get("status") or ""
    if undertime_flag and is_attendance and row.get("time_out"):
        display_status = "Undertime"
    data_issue_note = "Suspicious work duration hidden. Please review this record." if suspicious_work_flag else ""

    return {
        "row": row,
        "break_minutes": break_minutes,
        "break_sessions": break_sessions,
        "break_sessions_summary": summarize_break_sessions(break_sessions),
        "work_minutes": work_minutes,
        "raw_work_minutes": raw_work_minutes,
        "over_break_minutes": over_break_minutes,
        "undertime_flag": undertime_flag,
        "suspicious_work_flag": suspicious_work_flag,
        "data_issue_note": data_issue_note,
        "display_status": display_status,
        "absent_flag": 1 if employee_row and is_attendance and is_absent_today(employee_row, row) else 0,
        "record_type": record_type,
        "request_note": " | ".join(part for part in [row.get("admin_note") or row.get("message") or "", data_issue_note] if part),
    }


def build_employee_history_records(user_row, limit=60):
    attendance_rows = [
        dict(row) for row in fetchall("""
            SELECT * FROM attendance
            WHERE user_id = ?
            ORDER BY work_date DESC, id DESC
            LIMIT ?
        """, (user_row["id"], limit))
    ]
    special_requests = [dict(row) for row in get_approved_special_requests(user_id=user_row["id"])]
    suspension_rows = [dict(row) for row in get_disciplinary_actions(action_type="Suspension", user_id=user_row["id"])]
    request_map = {}
    for row in special_requests:
        request_dates = expand_request_dates(row["work_date"], row.get("end_work_date")) if row["request_type"] in LEAVE_REQUEST_TYPES else [row["work_date"]]
        for request_work_date in request_dates:
            matched_attendance, _ = get_matching_attendance_context_for_request(
                row["user_id"],
                request_work_date,
                request_type=row["request_type"],
                requested_time_out=row.get("requested_time_out")
            )
            target_work_date = matched_attendance["work_date"] if matched_attendance else request_work_date
            request_map[(row["user_id"], target_work_date)] = row

    combined = []
    seen_keys = set()

    for row in attendance_rows:
        key = (row["user_id"], row["work_date"])
        special_request = request_map.get(key)
        row["source_type"] = "attendance"
        row["request_type"] = special_request["request_type"] if special_request else ""
        row["admin_note"] = special_request["admin_note"] if special_request else ""
        row["message"] = special_request["message"] if special_request else ""
        row["requested_time_out"] = special_request["requested_time_out"] if special_request else ""
        combined.append(enrich_history_record(row, get_employee_break_limit(user_row), employee_row=user_row))
        seen_keys.add(key)

    for row in special_requests:
        request_dates = expand_request_dates(row["work_date"], row.get("end_work_date")) if row["request_type"] in LEAVE_REQUEST_TYPES else [row["work_date"]]
        for request_work_date in request_dates:
            matched_attendance, _ = get_matching_attendance_context_for_request(
                row["user_id"],
                request_work_date,
                request_type=row["request_type"],
                requested_time_out=row.get("requested_time_out")
            )
            target_work_date = matched_attendance["work_date"] if matched_attendance else request_work_date
            key = (row["user_id"], target_work_date)
            if key in seen_keys or row["request_type"] not in (LEAVE_REQUEST_TYPES | {"Undertime"}):
                continue
            is_leave_request = row["request_type"] in LEAVE_REQUEST_TYPES
            synthetic_row = {
                "id": None,
                "user_id": row["user_id"],
                "work_date": target_work_date,
                "time_in": None,
                "time_out": None if is_leave_request else row.get("requested_time_out"),
                "status": row["request_type"] if is_leave_request else "Approved Undertime",
                "proof_file": None,
                "late_flag": 0,
                "late_minutes": 0,
                "request_type": row["request_type"],
                "admin_note": row["admin_note"],
                "message": row["message"],
                "source_type": "request",
            }
            combined.append(enrich_history_record(synthetic_row, get_employee_break_limit(user_row), employee_row=user_row))

    suspension_dates = set()
    for row in suspension_rows:
        for work_date in expand_suspension_dates(row):
            if (row["user_id"], work_date) in seen_keys:
                continue
            suspension_dates.add((row["user_id"], work_date))
            synthetic_row = {
                "id": None,
                "user_id": row["user_id"],
                "work_date": work_date,
                "time_in": None,
                "time_out": None,
                "status": "Suspension",
                "proof_file": None,
                "late_flag": 0,
                "late_minutes": 0,
                "request_type": "Suspension",
                "admin_note": row.get("details") or "",
                "message": row.get("details") or "",
                "source_type": "request",
            }
            combined.append(enrich_history_record(synthetic_row, get_employee_break_limit(user_row), employee_row=user_row))

    combined.sort(key=lambda item: (item["row"]["work_date"] or "", item["row"].get("id") or 0), reverse=True)
    return combined[:limit]


def build_admin_history_records(search="", department="", type_filter="", late_only="", absent_only="", over_break_only="", date_from="", date_to="", limit=200):
    sql = """
        SELECT a.*, u.full_name, u.username, u.break_limit_minutes
        FROM attendance a
        JOIN users u ON u.id = a.user_id
        WHERE 1=1
    """
    params = []

    if search:
        sql += " AND (LOWER(u.full_name) LIKE ? OR LOWER(u.username) LIKE ?)"
        s = f"%{search.lower()}%"
        params.extend([s, s])

    if department:
        sql += " AND COALESCE(u.department, '') = ?"
        params.append(department)

    if late_only == "1":
        sql += " AND a.late_flag = 1"

    if date_from:
        sql += " AND a.work_date >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND a.work_date <= ?"
        params.append(date_to)

    sql += " ORDER BY a.work_date DESC, a.id DESC LIMIT ?"
    params.append(limit)

    attendance_rows = [dict(row) for row in fetchall(sql, params)]
    special_requests = [dict(row) for row in get_approved_special_requests(
        search=search,
        department=department,
        date_from=date_from,
        date_to=date_to
    )]
    suspension_rows = [dict(row) for row in get_disciplinary_actions(
        action_type="Suspension",
        department=department
    )]
    request_map = {}
    for row in special_requests:
        request_dates = expand_request_dates(row["work_date"], row.get("end_work_date")) if row["request_type"] in LEAVE_REQUEST_TYPES else [row["work_date"]]
        for request_work_date in request_dates:
            matched_attendance, _ = get_matching_attendance_context_for_request(
                row["user_id"],
                request_work_date,
                request_type=row["request_type"],
                requested_time_out=row.get("requested_time_out")
            )
            target_work_date = matched_attendance["work_date"] if matched_attendance else request_work_date
            request_map[(row["user_id"], target_work_date)] = row
    attendance_key_map = {(row["user_id"], row["work_date"]): row for row in attendance_rows}

    enriched = []
    seen_keys = set()

    for row in attendance_rows:
        employee = get_user_by_id(row["user_id"])
        key = (row["user_id"], row["work_date"])
        special_request = request_map.get(key)
        row["source_type"] = "attendance"
        row["request_type"] = special_request["request_type"] if special_request else ""
        row["admin_note"] = special_request["admin_note"] if special_request else ""
        row["message"] = special_request["message"] if special_request else ""
        row["requested_time_out"] = special_request["requested_time_out"] if special_request else ""

        item = enrich_history_record(row, parse_break_limit_minutes(row["break_limit_minutes"]), employee_row=employee)
        if type_filter and item["record_type"] != type_filter:
            continue
        if absent_only == "1" and item["absent_flag"] != 1:
            continue
        if over_break_only == "1" and item["over_break_minutes"] <= 0:
            continue
        enriched.append(item)
        seen_keys.add(key)

    for row in special_requests:
        request_dates = expand_request_dates(row["work_date"], row.get("end_work_date")) if row["request_type"] in LEAVE_REQUEST_TYPES else [row["work_date"]]
        for request_work_date in request_dates:
            matched_attendance, _ = get_matching_attendance_context_for_request(
                row["user_id"],
                request_work_date,
                request_type=row["request_type"],
                requested_time_out=row.get("requested_time_out")
            )
            target_work_date = matched_attendance["work_date"] if matched_attendance else request_work_date
            key = (row["user_id"], target_work_date)
            if key in seen_keys or row["request_type"] not in (LEAVE_REQUEST_TYPES | {"Undertime"}):
                continue
            is_leave_request = row["request_type"] in LEAVE_REQUEST_TYPES
            synthetic_row = {
                "id": None,
                "user_id": row["user_id"],
                "full_name": row["full_name"],
                "username": row["username"],
                "break_limit_minutes": row["break_limit_minutes"],
                "work_date": target_work_date,
                "time_in": None,
                "time_out": None if is_leave_request else row.get("requested_time_out"),
                "status": row["request_type"] if is_leave_request else "Approved Undertime",
                "proof_file": None,
                "late_flag": 0,
                "late_minutes": 0,
                "request_type": row["request_type"],
                "admin_note": row["admin_note"],
                "message": row["message"],
                "source_type": "request",
            }
            item = enrich_history_record(synthetic_row, parse_break_limit_minutes(row["break_limit_minutes"]))
            if type_filter and item["record_type"] != type_filter:
                continue
            enriched.append(item)

    suspension_date_keys = set()
    for row in suspension_rows:
        if search:
            hay = f"{row.get('full_name', '')} {row.get('username', '')}".lower()
            if search.lower() not in hay:
                continue
        for work_date in expand_suspension_dates(row):
            key = (row["user_id"], work_date)
            if key in seen_keys:
                continue
            if date_from and work_date < date_from:
                continue
            if date_to and work_date > date_to:
                continue
            suspension_date_keys.add(key)
            synthetic_row = {
                "id": None,
                "user_id": row["user_id"],
                "full_name": row["full_name"],
                "username": row["username"],
                "break_limit_minutes": row.get("break_limit_minutes", BREAK_LIMIT_MINUTES),
                "work_date": work_date,
                "time_in": None,
                "time_out": None,
                "status": "Suspension",
                "proof_file": None,
                "late_flag": 0,
                "late_minutes": 0,
                "request_type": "Suspension",
                "admin_note": row.get("details") or "",
                "message": row.get("details") or "",
                "source_type": "request",
            }
            item = enrich_history_record(synthetic_row, parse_break_limit_minutes(row.get("break_limit_minutes", BREAK_LIMIT_MINUTES)))
            if type_filter and item["record_type"] != type_filter:
                continue
            enriched.append(item)

    candidate_dates = []
    if date_from or date_to:
        try:
            start_date = datetime.strptime(date_from or date_to, "%Y-%m-%d").date()
            end_date = datetime.strptime(date_to or date_from, "%Y-%m-%d").date()
            if start_date <= end_date:
                total_days = (end_date - start_date).days
                if total_days <= 60:
                    candidate_dates = [
                        (start_date + timedelta(days=offset)).strftime("%Y-%m-%d")
                        for offset in range(total_days + 1)
                    ]
        except Exception:
            candidate_dates = []
    else:
        candidate_dates = [today_str()]

    if candidate_dates and (not type_filter or type_filter == "Absent"):
        employee_sql = """
            SELECT *
            FROM users
            WHERE role = 'employee'
        """
        employee_params = []

        if search:
            employee_sql += " AND (LOWER(full_name) LIKE ? OR LOWER(username) LIKE ?)"
            s = f"%{search.lower()}%"
            employee_params.extend([s, s])

        if department:
            employee_sql += " AND COALESCE(department, '') = ?"
            employee_params.append(department)

        employee_sql += " ORDER BY full_name ASC"
        employees = fetchall(employee_sql, employee_params)

        for employee in employees:
            if employee["is_active"] != 1:
                continue
            for work_date in candidate_dates:
                key = (employee["id"], work_date)
                special_request = request_map.get(key)
                if key in attendance_key_map:
                    continue
                if key in suspension_date_keys:
                    continue
                if special_request and special_request["request_type"] in LEAVE_REQUEST_TYPES:
                    continue
                if not is_scheduled_on_date(employee, work_date):
                    continue

                synthetic_row = {
                    "id": None,
                    "user_id": employee["id"],
                    "full_name": employee["full_name"],
                    "username": employee["username"],
                    "break_limit_minutes": employee["break_limit_minutes"],
                    "work_date": work_date,
                    "time_in": None,
                    "time_out": None,
                    "status": "Absent",
                    "proof_file": None,
                    "late_flag": 0,
                    "late_minutes": 0,
                    "request_type": "Absent",
                    "admin_note": "",
                    "message": "",
                    "source_type": "request",
                }
                item = enrich_history_record(synthetic_row, parse_break_limit_minutes(employee["break_limit_minutes"]))
                if type_filter and item["record_type"] != type_filter:
                    continue
                if over_break_only == "1":
                    continue
                enriched.append(item)

    enriched.sort(key=lambda item: (item["row"]["work_date"] or "", item["row"].get("id") or 0), reverse=True)
    return enriched[:limit]


def apply_attendance_correction(user_id, work_date, time_in_value="", break_start_value="", break_end_value="", time_out_value=""):
    undertime_only_adjustment = bool(time_out_value and not (time_in_value or break_start_value or break_end_value))
    attendance, break_row = get_matching_attendance_context_for_request(
        user_id,
        work_date,
        request_type="Undertime" if undertime_only_adjustment else "",
        requested_time_out=combine_work_date_and_time(work_date, time_out_value) if time_out_value else None
    )
    target_work_date = attendance["work_date"] if attendance else work_date

    before_values = {
        "time_in": attendance["time_in"] if attendance else None,
        "break_start": break_row["break_start"] if break_row else None,
        "break_end": break_row["break_end"] if break_row else None,
        "time_out": attendance["time_out"] if attendance else None,
    }

    final_time_in, final_break_start, final_break_end, final_time_out = resolve_correction_datetimes(
        target_work_date,
        time_in_value=time_in_value,
        break_start_value=break_start_value,
        break_end_value=break_end_value,
        time_out_value=time_out_value,
        existing_time_in=attendance["time_in"] if attendance else None,
        existing_break_start=break_row["break_start"] if break_row else None,
        existing_break_end=break_row["break_end"] if break_row else None,
        existing_time_out=attendance["time_out"] if attendance else None
    )

    if undertime_only_adjustment and final_time_out:
        if final_break_start and final_break_start > final_time_out:
            final_break_start = None
            final_break_end = None
        elif final_break_end and final_break_end > final_time_out:
            final_break_end = final_time_out

    if (time_in_value or (attendance and attendance["time_in"])) and final_time_in and final_time_out:
        if final_time_out < final_time_in:
            raise ValueError("Time out cannot be earlier than time in.")

    if (break_start_value or break_end_value or break_row) and not final_time_in:
        raise ValueError("Set time in before saving break corrections.")

    if final_break_start and final_break_end and final_break_end < final_break_start:
        raise ValueError("Break end cannot be earlier than break start.")

    if final_break_start and final_time_in and final_break_start < final_time_in:
        raise ValueError("Break start cannot be earlier than time in.")

    if final_break_end and final_time_out and final_break_end > final_time_out:
        raise ValueError("Break end cannot be later than time out.")

    user = get_user_by_id(user_id)
    late_flag, late_minutes = calculate_late_info(final_time_in, parse_shift_start(user["shift_start"] if user else DEFAULT_SHIFT_START))

    if final_time_out:
        final_status = "Timed Out"
    elif final_break_start and not final_break_end:
        final_status = "On Break"
    elif final_time_in:
        final_status = "Timed In"
    else:
        final_status = "Offline"

    if attendance:
        execute_db("""
            UPDATE attendance
            SET time_in = ?, time_out = ?, status = ?, late_flag = ?, late_minutes = ?, updated_at = ?
            WHERE id = ?
        """, (
            final_time_in,
            final_time_out,
            final_status,
            late_flag,
            late_minutes,
            now_str(),
            attendance["id"]
        ), commit=True)
    elif final_time_in or final_time_out or final_break_start or final_break_end:
        execute_db("""
            INSERT INTO attendance (
                user_id, work_date, time_in, time_out, status, proof_file, notes,
                late_flag, late_minutes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            target_work_date,
            final_time_in,
            final_time_out,
            final_status,
            None,
            "Updated through correction request",
            late_flag,
            late_minutes,
            now_str(),
            now_str()
        ), commit=True)
        attendance = fetchone("""
            SELECT *
            FROM attendance
            WHERE user_id = ? AND work_date = ?
            ORDER BY id DESC LIMIT 1
        """, (user_id, target_work_date))

    if not attendance:
        return

    if break_row and (break_start_value or break_end_value):
        execute_db("""
            UPDATE breaks
            SET break_start = ?, break_end = ?
            WHERE id = ?
        """, (final_break_start, final_break_end, break_row["id"]), commit=True)
    elif not break_row and (break_start_value or break_end_value):
        execute_db("""
            INSERT INTO breaks (user_id, attendance_id, work_date, break_start, break_end, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, attendance["id"], target_work_date, final_break_start, final_break_end, now_str()), commit=True)

    after_values = {
        "time_in": final_time_in,
        "break_start": final_break_start,
        "break_end": final_break_end,
        "time_out": final_time_out,
    }
    return build_correction_change_summary(before_values, after_values)


@app.route("/admin")
@login_required(role="admin")
def admin_dashboard():
    current_admin = get_user_by_id(session["user_id"])
    if not current_admin:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    status_filter = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()
    department_filter = request.args.get("department", "").strip()
    over_break_only = request.args.get("over_break_only", "").strip()
    page = parse_positive_int(request.args.get("page", "1"), 1)
    page_size = parse_positive_int(request.args.get("page_size", "25"), 25)

    filtered_rows = get_admin_employee_rows(
        status_filter=status_filter,
        search=search,
        department_filter=department_filter,
        over_break_only=over_break_only
    )
    all_employee_rows = get_admin_employee_rows()
    pagination = paginate_items(filtered_rows, page, page_size)
    employees = pagination["items"]
    all_users = fetchall("""
        SELECT * FROM users
        WHERE role = 'employee'
        ORDER BY full_name ASC
    """)
    departments = get_department_options()

    logs = fetchall("""
        SELECT a.*, u.full_name
        FROM activity_logs a
        JOIN users u ON u.id = a.user_id
        ORDER BY a.id DESC
        LIMIT 25
    """)

    late_today_row = fetchone("""
        SELECT COUNT(*) AS cnt
        FROM attendance
        WHERE work_date = ? AND late_flag = 1
    """, (today_str(),))
    late_today = late_today_row["cnt"] if late_today_row else 0
    active_users = [user for user in all_users if user["is_active"] == 1]
    exception_groups = get_exception_collections(all_employee_rows)
    notify_admins_for_exceptions(exception_groups)
    notify_admins_for_leave_and_disciplinary_events()
    admin_notifications = fetchall("""
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 8
    """, (session["user_id"],))

    stats = {
        "total_employees": len(active_users),
        "scheduled_today": len([emp for emp in all_employee_rows if emp["scheduled_today"] == 1 and emp["is_active"] == 1]),
        "absent_today": len(exception_groups["absent"]),
        "timed_in": len([emp for emp in all_employee_rows if emp["status_display"] == "Timed In"]),
        "on_break": len([emp for emp in all_employee_rows if emp["status_display"] == "On Break"]),
        "timed_out": len([emp for emp in all_employee_rows if emp["status_display"] == "Timed Out"]),
        "late_today": late_today,
        "over_break_today": len(exception_groups["over_break"]),
        "missing_timeout": len(exception_groups["missing_timeout"]),
        "undertime_today": len(exception_groups["undertime"])
    }

    return render_template(
        "admin_dashboard.html",
        employees=employees,
        pagination=pagination,
        logs=logs,
        stats=stats,
        break_limit_minutes=BREAK_LIMIT_MINUTES,
        status_filter=status_filter,
        search=search,
        department_filter=department_filter,
        departments=departments,
        over_break_only=over_break_only,
        today_schedule_code=get_today_schedule_code(),
        exception_groups=exception_groups,
        admin_notifications=admin_notifications
    )


@app.route("/admin/live-status")
@login_required(role="admin")
def admin_live_status():
    page = parse_positive_int(request.args.get("page", "1"), 1)
    page_size = parse_positive_int(request.args.get("page_size", "25"), 25)
    rows = get_admin_employee_rows(
        status_filter=request.args.get("status", "").strip(),
        search=request.args.get("search", "").strip(),
        department_filter=request.args.get("department", "").strip(),
        over_break_only=request.args.get("over_break_only", "").strip()
    )
    pagination = paginate_items(rows, page, page_size)
    return jsonify({
        "rows": pagination["items"],
        "pagination": {
            "page": pagination["page"],
            "page_size": pagination["page_size"],
            "total": pagination["total"],
            "total_pages": pagination["total_pages"],
            "has_prev": pagination["has_prev"],
            "has_next": pagination["has_next"],
            "start_index": pagination["start_index"],
            "end_index": pagination["end_index"],
        }
    })


@app.route("/admin/payroll")
@login_required(role="admin")
def admin_payroll():
    period = request.args.get("period", "this_month").strip() or "this_month"
    department_filter = request.args.get("department", "").strip()
    employee_filter = request.args.get("employee_id", "").strip()
    date_from, date_to = get_payroll_period_dates(
        period,
        request.args.get("date_from", "").strip(),
        request.args.get("date_to", "").strip()
    )
    departments = get_department_options()
    employees = get_employee_options()
    payroll_rows = build_payroll_rows(
        date_from,
        date_to,
        department_filter=department_filter,
        employee_filter=employee_filter
    )

    stats = {
        "employees": len(payroll_rows),
        "paid_employees": len([row for row in payroll_rows if row["gross_pay"] > 0]),
        "missing_rates": len([row for row in payroll_rows if row["has_rate"] == 0]),
        "total_hours": round(sum(row["total_hours"] for row in payroll_rows), 2),
        "total_gross": round(sum(row["gross_pay"] for row in payroll_rows), 2),
        "suspension_days": sum(row["suspension_days"] for row in payroll_rows),
        "suspension_pay": round(sum(row["suspension_pay"] for row in payroll_rows), 2),
    }

    return render_template(
        "admin_payroll.html",
        payroll_rows=payroll_rows,
        departments=departments,
        employees=employees,
        department_filter=department_filter,
        employee_filter=employee_filter,
        period=period,
        date_from=date_from.strftime("%Y-%m-%d"),
        date_to=date_to.strftime("%Y-%m-%d"),
        stats=stats
    )


@app.route("/admin/leave")
@login_required(role="admin")
def admin_leave_dashboard():
    year = parse_positive_int(request.args.get("year", str(now_dt().year)), now_dt().year)
    department = request.args.get("department", "").strip()
    departments = get_department_options()
    leave_rows = build_leave_dashboard_rows(year=year, department=department)
    pending_requests = get_pending_leave_requests(department=department, year=year)

    stats = {
        "employees": len(leave_rows),
        "sick_used": sum(row["sick_used"] for row in leave_rows),
        "paid_used": sum(row["paid_used"] for row in leave_rows),
        "sick_remaining": sum(row["sick_remaining"] for row in leave_rows),
        "paid_remaining": sum(row["paid_remaining"] for row in leave_rows),
        "pending_total": sum(row["pending_total"] for row in leave_rows),
        "sick_exhausted": len([row for row in leave_rows if row["sick_remaining"] <= 0]),
        "paid_exhausted": len([row for row in leave_rows if row["paid_remaining"] <= 0]),
        "overdue_pending": len([row for row in pending_requests if int(row.get("age_days") or 0) >= 3]),
    }

    return render_template(
        "admin_leave_dashboard.html",
        leave_rows=leave_rows,
        pending_requests=pending_requests,
        departments=departments,
        department=department,
        year=year,
        stats=stats
    )


@app.route("/admin/leave/export.xlsx")
@login_required(role="admin")
def export_admin_leave_dashboard_excel():
    year = parse_positive_int(request.args.get("year", str(now_dt().year)), now_dt().year)
    department = request.args.get("department", "").strip()
    leave_rows = build_leave_dashboard_rows(year=year, department=department)

    try:
        from openpyxl import Workbook
    except Exception:
        flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
        return redirect(url_for("admin_leave_dashboard", year=year, department=department))

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Leave Dashboard"
    sheet.append([
        "Employee", "Username", "Department", "Sick Allotment", "Sick Used", "Sick Remaining",
        "Paid Allotment", "Paid Used", "Paid Remaining", "Pending Sick", "Pending Paid",
        "Manual Sick Used", "Manual Paid Used", "Approved Sick Used", "Approved Paid Used"
    ])
    for row in leave_rows:
        sheet.append([
            row["full_name"], row["username"], row["department"], row["sick_total"], row["sick_used"], row["sick_remaining"],
            row["paid_total"], row["paid_used"], row["paid_remaining"], row["pending_sick"], row["pending_paid"],
            row["sick_used_manual"], row["paid_used_manual"], row["sick_used_in_app"], row["paid_used_in_app"]
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="leave-dashboard-{year}.xlsx"'}
    )


@app.route("/admin/history")
@login_required(role="admin")
def admin_history():
    search = request.args.get("search", "").strip()
    department = request.args.get("department", "").strip()
    type_filter = request.args.get("type_filter", "").strip()
    late_only = request.args.get("late_only", "").strip()
    absent_only = request.args.get("absent_only", "").strip()
    over_break_only = request.args.get("over_break_only", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    departments = get_department_options()
    enriched = build_admin_history_records(
        search=search,
        department=department,
        type_filter=type_filter,
        late_only=late_only,
        absent_only=absent_only,
        over_break_only=over_break_only,
        date_from=date_from,
        date_to=date_to,
        limit=200
    )

    return render_template(
        "admin_history.html",
        records=enriched,
        search=search,
        department=department,
        type_filter=type_filter,
        departments=departments,
        late_only=late_only,
        absent_only=absent_only,
        over_break_only=over_break_only,
        date_from=date_from,
        date_to=date_to,
        minutes_to_hm=minutes_to_hm
    )


@app.route("/admin/data-tools", methods=["GET", "POST"])
@login_required(role="admin")
def admin_data_tools():
    search = request.args.get("search", "").strip()

    if request.method == "POST":
        action = request.form.get("action", "").strip()
        if action == "create_backup":
            try:
                backup_path = create_sqlite_backup()
                log_activity(session["user_id"], "CREATE BACKUP", f"Created SQLite backup at {backup_path}")
                flash(f"Backup created: {os.path.basename(backup_path)}", "success")
            except ValueError as exc:
                flash(str(exc), "danger")
            return redirect(url_for("admin_data_tools", search=search))
        if action == "go_live_reset":
            confirmation = request.form.get("confirmation_text", "").strip().upper()
            if confirmation != "RESET":
                flash("Type RESET exactly before running the go-live reset.", "danger")
                return redirect(url_for("admin_data_tools", search=search))
            try:
                result = perform_go_live_reset()
                backup_note = f" Backup: {os.path.basename(result['backup_path'])}." if result.get("backup_path") else ""
                upload_note = f" Removed {result['removed_uploads']} orphaned proof uploads." if result.get("removed_uploads") else ""
                log_activity(session["user_id"], "GO-LIVE RESET", "Cleared operational attendance data for go-live.")
                flash(f"Go-live reset completed.{backup_note}{upload_note}", "success")
            except ValueError as exc:
                flash(str(exc), "danger")
            return redirect(url_for("admin_data_tools", search=search))

        attendance_id = request.form.get("attendance_id", "").strip()
        if not attendance_id:
            flash("Attendance record is required.", "danger")
            return redirect(url_for("admin_data_tools", search=search))

        try:
            updated_row = update_attendance_record_by_admin(
                attendance_id=int(attendance_id),
                time_in_value=request.form.get("time_in", "").strip(),
                time_out_value=request.form.get("time_out", "").strip(),
                clear_breaks=request.form.get("clear_breaks", "").strip() == "1",
            )
            employee = get_user_by_id(updated_row["user_id"]) if updated_row else None
            employee_name = employee["full_name"] if employee else f"Attendance #{attendance_id}"
            log_activity(session["user_id"], "FIX ATTENDANCE", f"Updated suspicious row #{attendance_id} for {employee_name}")
            flash("Attendance record updated.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")

        return redirect(url_for("admin_data_tools", search=search))

    candidates = get_suspicious_attendance_records(search=search, limit=60)
    backups = get_backup_files(limit=12)
    return render_template(
        "admin_data_tools.html",
        candidates=candidates,
        backups=backups,
        search=search,
        format_datetime_12h=format_datetime_12h,
        minutes_to_hm=minutes_to_hm
    )


@app.route("/admin/exceptions/export.xlsx")
@login_required(role="admin")
def export_admin_exceptions_excel():
    exception_type = request.args.get("type", "absent").strip().lower()
    department = request.args.get("department", "").strip()

    exception_groups = get_exception_collections(get_admin_employee_rows(department_filter=department))
    selected_rows = exception_groups.get(exception_type, [])
    titles = {
        "absent": "Absent Today",
        "late": "Late Today",
        "over_break": "Over Break",
        "missing_timeout": "Missing Time Out",
        "undertime": "Undertime Today",
    }

    try:
        from openpyxl import Workbook
    except Exception:
        flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
        return redirect(url_for("admin_dashboard", department=department))

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = titles.get(exception_type, "Exceptions")
    sheet.append([
        "Employee",
        "Username",
        "Department",
        "Position",
        "Schedule",
        "Shift Start",
        "Shift End",
        "Status",
        "Time In",
        "Time Out",
        "Late Minutes",
        "Break Minutes",
        "Over Break Minutes"
    ])

    for row in selected_rows:
        sheet.append([
            row["full_name"] or "",
            row["username"] or "",
            row["department"] or "",
            row["position"] or "",
            row["schedule_summary"] or "",
            row["shift_start"] or "",
            row["shift_end"] or "",
            row["status_display"] or "",
            row["time_in"] or "",
            row["time_out"] or "",
            row["late_minutes"] if row["late_flag"] else 0,
            row["break_minutes"] or 0,
            row["over_break_minutes"] or 0,
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{exception_type}-exceptions-{today_str()}.xlsx"'}
    )


@app.route("/admin/corrections")
@login_required(role="admin")
def admin_corrections():
    status = request.args.get("status", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    requests = get_correction_requests(status=status, date_from=date_from, date_to=date_to)

    return render_template(
        "admin_corrections.html",
        requests=requests,
        status=status,
        date_from=date_from,
        date_to=date_to
    )


@app.route("/admin/corrections/<int:request_id>/update", methods=["POST"])
@login_required(role="admin")
def update_correction_request(request_id):
    status = request.form.get("status", "").strip()
    admin_note = request.form.get("admin_note", "").strip()
    requested_time_in = request.form.get("requested_time_in", "")
    requested_break_start = request.form.get("requested_break_start", "")
    requested_break_end = request.form.get("requested_break_end", "")
    requested_time_out = request.form.get("requested_time_out", "")

    if status not in {"Pending", "Approved", "Rejected"}:
        flash("Invalid correction status.", "danger")
        return redirect(url_for("admin_corrections"))

    correction = fetchone("""
        SELECT c.*, u.full_name
        FROM correction_requests c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = ?
    """, (request_id,))

    if not correction:
        flash("Correction request not found.", "danger")
        return redirect(url_for("admin_corrections"))

    applied_changes = correction["applied_changes"] if "applied_changes" in correction.keys() else None

    try:
        requested_time_in = normalize_optional_clock_time(requested_time_in)
        requested_break_start = normalize_optional_clock_time(requested_break_start)
        requested_break_end = normalize_optional_clock_time(requested_break_end)
        requested_time_out = normalize_optional_clock_time(requested_time_out)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("admin_corrections"))

    if correction["request_type"] in LEAVE_REQUEST_TYPES:
        requested_time_in = ""
        requested_break_start = ""
        requested_break_end = ""
        requested_time_out = ""
    elif correction["request_type"] == "Undertime" and status == "Approved" and not requested_time_out:
        flash("Requested time out is required to approve an undertime request.", "danger")
        return redirect(url_for("admin_corrections"))

    if status == "Approved":
        if correction["request_type"] in (LEAVE_REQUEST_TYPES | {"Undertime"}):
            requested_time_out_dt = combine_work_date_and_time(correction["work_date"], requested_time_out) if requested_time_out else None
            attendance, _ = get_matching_attendance_context_for_request(
                correction["user_id"],
                correction["work_date"],
                request_type=correction["request_type"],
                requested_time_out=requested_time_out_dt
            )
            if correction["request_type"] == "Undertime" and attendance and requested_time_out:
                try:
                    applied_changes = apply_attendance_correction(
                        correction["user_id"],
                        attendance["work_date"],
                        time_out_value=requested_time_out
                    )
                except ValueError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("admin_corrections"))
            else:
                applied_changes = describe_request_review_result(
                    correction["request_type"],
                    format_request_date_range(correction["work_date"], correction.get("end_work_date")),
                    requested_time_out
                )
        else:
            try:
                applied_changes = apply_attendance_correction(
                    correction["user_id"],
                    correction["work_date"],
                    time_in_value=requested_time_in,
                    break_start_value=requested_break_start,
                    break_end_value=requested_break_end,
                    time_out_value=requested_time_out
                )
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("admin_corrections"))

        reviewed_at = now_str() if status in {"Approved", "Rejected"} else None
    reviewed_by = session["user_id"] if status in {"Approved", "Rejected"} else None

    preview_request_type = correction["request_type"] if correction["request_type"] == "Undertime" else ""
    preview_requested_time_out = combine_work_date_and_time(correction["work_date"], requested_time_out) if requested_time_out else None
    attendance, break_row = get_matching_attendance_context_for_request(
        correction["user_id"],
        correction["work_date"],
        request_type=preview_request_type,
        requested_time_out=preview_requested_time_out
    )
    preview_work_date = attendance["work_date"] if attendance and correction["request_type"] == "Undertime" else correction["work_date"]

    if correction["request_type"] == "Undertime":
        requested_break_start = ""
        requested_break_end = ""

    requested_time_in_dt, requested_break_start_dt, requested_break_end_dt, requested_time_out_dt = resolve_correction_datetimes(
        preview_work_date,
        time_in_value=requested_time_in,
        break_start_value=requested_break_start,
        break_end_value=requested_break_end,
        time_out_value=requested_time_out,
        existing_time_in=attendance["time_in"] if attendance else None,
        existing_break_start=break_row["break_start"] if break_row else None,
        existing_break_end=break_row["break_end"] if break_row else None,
        existing_time_out=attendance["time_out"] if attendance else None,
        use_existing_values=False
    )

    execute_db("""
        UPDATE correction_requests
        SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = ?,
            requested_time_in = ?, requested_break_start = ?, requested_break_end = ?, requested_time_out = ?,
            applied_changes = ?
        WHERE id = ?
    """, (
        status,
        admin_note,
        reviewed_by,
        reviewed_at,
        requested_time_in_dt,
        requested_break_start_dt,
        requested_break_end_dt,
        requested_time_out_dt,
        applied_changes if status == "Approved" else None,
        request_id
    ), commit=True)

    notification_message = f"Your {correction['request_type']} request for {correction['work_date']} is now {status}."
    if correction["request_type"] in LEAVE_REQUEST_TYPES:
        notification_message = f"Your {correction['request_type']} request for {format_request_date_range(correction['work_date'], correction.get('end_work_date'))} is now {status}."
    if status == "Approved" and applied_changes:
        notification_message = f"{notification_message} Applied: {applied_changes}"

    create_notification(
        correction["user_id"],
        "Correction Request Updated",
        notification_message
    )
    log_details = f"{status} correction request #{request_id} for {correction['full_name']}"
    if status == "Approved" and applied_changes:
        log_details = f"{log_details} | {applied_changes}"
    log_activity(session["user_id"], "REVIEW CORRECTION", log_details)
    flash("Correction request updated.", "success")
    return redirect(url_for("admin_corrections"))


@app.route("/admin/history/export.xlsx")
@login_required(role="admin")
def export_admin_history_excel():
    search = request.args.get("search", "").strip()
    department = request.args.get("department", "").strip()
    type_filter = request.args.get("type_filter", "").strip()
    late_only = request.args.get("late_only", "").strip()
    absent_only = request.args.get("absent_only", "").strip()
    over_break_only = request.args.get("over_break_only", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    records = build_admin_history_records(
        search=search,
        department=department,
        type_filter=type_filter,
        late_only=late_only,
        absent_only=absent_only,
        over_break_only=over_break_only,
        date_from=date_from,
        date_to=date_to,
        limit=500
    )

    try:
        from openpyxl import Workbook
    except Exception:
        flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
        return redirect(url_for(
            "admin_history",
            search=search,
            department=department,
            type_filter=type_filter,
            late_only=late_only,
            absent_only=absent_only,
            over_break_only=over_break_only,
            date_from=date_from,
            date_to=date_to
        ))

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Attendance History"
    sheet.append([
        "Employee",
        "Username",
        "Work Date",
        "Record Type",
        "Time In",
        "Time Out",
        "Status",
        "Late Minutes",
        "Break Limit",
        "Break Minutes",
        "Overbreak Minutes",
        "Work Hours",
        "Proof File",
        "Admin Note"
    ])

    for item in records:
        row = item["row"]
        sheet.append([
            row["full_name"] or "",
            row["username"] or "",
            row["work_date"] or "",
            item["record_type"] or "Attendance",
            row["time_in"] or "",
            row["time_out"] or "",
            item["display_status"] or row["status"] or "",
            row["late_minutes"] if row["late_flag"] else 0,
            parse_break_limit_minutes(row["break_limit_minutes"]) if row.get("break_limit_minutes") is not None else 0,
            item["break_minutes"],
            item["over_break_minutes"],
            minutes_to_decimal_hours(item["work_minutes"]),
            row["proof_file"] or "",
            item["request_note"]
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename=\"attendance-history-{today_str()}.xlsx\"'}
    )


@app.route("/admin/error-reports")
@login_required(role="admin")
def admin_error_reports():
    report_employee = request.args.get("report_employee", "").strip()
    report_department = request.args.get("report_department", "").strip()
    report_type = request.args.get("report_type", "").strip()
    report_date_from = request.args.get("report_date_from", "").strip()
    report_date_to = request.args.get("report_date_to", "").strip()

    employees = get_employee_options()
    departments = get_department_options()
    reports = get_incident_reports(
        report_employee=report_employee,
        report_department=report_department,
        report_type=report_type,
        report_date_from=report_date_from,
        report_date_to=report_date_to
    )

    return render_template(
        "admin_error_reports.html",
        employees=employees,
        departments=departments,
        reports=reports,
        report_employee=report_employee,
        report_department=report_department,
        report_type=report_type,
        report_date_from=report_date_from,
        report_date_to=report_date_to
    )


@app.route("/admin/error-reports/export.xlsx")
@login_required(role="admin")
def export_admin_error_reports_excel():
    report_employee = request.args.get("report_employee", "").strip()
    report_department = request.args.get("report_department", "").strip()
    report_type = request.args.get("report_type", "").strip()
    report_date_from = request.args.get("report_date_from", "").strip()
    report_date_to = request.args.get("report_date_to", "").strip()

    reports = get_incident_reports(
        report_employee=report_employee,
        report_department=report_department,
        report_type=report_type,
        report_date_from=report_date_from,
        report_date_to=report_date_to
    )

    try:
        from openpyxl import Workbook
    except Exception:
        flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
        return redirect(url_for(
            "admin_error_reports",
            report_employee=report_employee,
            report_department=report_department,
            report_type=report_type,
            report_date_from=report_date_from,
            report_date_to=report_date_to
        ))

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Error Reports"
    sheet.append([
        "Employee",
        "Department",
        "Error Type",
        "Report Date",
        "Message",
        "Status",
        "Admin Note",
        "Created At",
        "Reviewed At",
        "Reviewed By"
    ])

    for report in reports:
        sheet.append([
            report["full_name"] if report["full_name"] else report["employee_name"] if report["employee_name"] else "Unknown",
            report["report_department"] or report["department"] or "",
            report["error_type"] or "",
            report["report_date"] if report["report_date"] else report["incident_date"] if report["incident_date"] else "",
            report["message"] or "",
            report["status"] or "Open",
            report["admin_note"] or "",
            report["created_at"] or "",
            report["reviewed_at"] or "",
            report["reviewed_by_name"] or ""
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="error-reports-{today_str()}.xlsx"'}
    )


@app.route("/admin/incident-report")
@login_required(role="admin")
def admin_incident_report():
    employees = fetchall("""
        SELECT id, full_name
        FROM users
        WHERE role = 'employee'
        ORDER BY full_name ASC
    """)
    return render_template("admin_incident_report.html", employees=employees)


@app.route("/admin/disciplinary")
@login_required(role="admin")
def admin_disciplinary_dashboard():
    action_type = request.args.get("action_type", "").strip()
    user_id = request.args.get("user_id", "").strip()
    department = request.args.get("department", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    employees = get_employee_options()
    departments = get_department_options()
    actions = get_disciplinary_actions(
        action_type=action_type,
        user_id=user_id,
        department=department,
        date_from=date_from,
        date_to=date_to
    )

    summary = {
        "coaching": len([row for row in actions if row["action_type"] == "Coaching"]),
        "nte": len([row for row in actions if row["action_type"] == "NTE"]),
        "suspension": len([row for row in actions if row["action_type"] == "Suspension"]),
        "active_suspensions": len([row for row in actions if row["action_type"] == "Suspension" and row["status_label"] == "Active"]),
        "upcoming_suspensions": len([row for row in actions if row["action_type"] == "Suspension" and row["status_label"] == "Upcoming"]),
        "starts_today": len([row for row in actions if row["action_type"] == "Suspension" and row["action_date"] == today_str()]),
    }

    return render_template(
        "admin_disciplinary_dashboard.html",
        employees=employees,
        departments=departments,
        disciplinary_types=DISCIPLINARY_ACTION_TYPES,
        actions=actions,
        action_type=action_type,
        user_id=user_id,
        department=department,
        date_from=date_from,
        date_to=date_to,
        summary=summary
    )


@app.route("/admin/disciplinary/export.xlsx")
@login_required(role="admin")
def export_admin_disciplinary_excel():
    action_type = request.args.get("action_type", "").strip()
    user_id = request.args.get("user_id", "").strip()
    department = request.args.get("department", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    actions = get_disciplinary_actions(
        action_type=action_type,
        user_id=user_id,
        department=department,
        date_from=date_from,
        date_to=date_to
    )

    try:
        from openpyxl import Workbook
    except Exception:
        flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
        return redirect(url_for(
            "admin_disciplinary_dashboard",
            action_type=action_type,
            user_id=user_id,
            department=department,
            date_from=date_from,
            date_to=date_to
        ))

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Disciplinary"
    sheet.append(["Employee", "Username", "Department", "Type", "Start Date", "Duration Days", "End Date", "Status", "Details"])
    for row in actions:
        sheet.append([
            row["full_name"], row["username"], row["department"], row["action_type"], row["action_date"],
            row["duration_days"], row["end_date"] or row["action_date"], row["status_label"], row["details"] or ""
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="disciplinary-records-{today_str()}.xlsx"'}
    )


@app.route("/admin/error-reports/<int:report_id>/update", methods=["POST"])
@login_required(role="admin")
def update_incident_report(report_id):
    status = request.form.get("status", "").strip()
    admin_note = request.form.get("admin_note", "").strip()

    if status not in {"Open", "Reviewed", "Resolved"}:
        flash("Invalid report status.", "danger")
        return redirect(url_for("admin_error_reports"))

    report = fetchone("""
        SELECT r.*, u.full_name
        FROM incident_reports r
        LEFT JOIN users u ON u.id = r.user_id
        WHERE r.id = ?
    """, (report_id,))

    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for("admin_error_reports"))

    reviewed_at = now_str() if status in {"Reviewed", "Resolved"} else None
    reviewed_by = session["user_id"] if status in {"Reviewed", "Resolved"} else None

    execute_db("""
        UPDATE incident_reports
        SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
    """, (status, admin_note, reviewed_by, reviewed_at, report_id), commit=True)

    employee_name = report["full_name"] if report["full_name"] else report["employee_name"] or f"User {report['user_id']}"
    log_activity(
        session["user_id"],
        "UPDATE INCIDENT",
        f"Incident #{report_id} for {employee_name} marked as {status}"
    )

    flash("Incident report updated.", "success")
    return redirect(url_for("admin_error_reports"))


@app.route("/admin/error-reports/<int:report_id>/edit", methods=["POST"])
@login_required(role="admin")
def edit_incident_report(report_id):
    report = fetchone("""
        SELECT *
        FROM incident_reports
        WHERE id = ?
    """, (report_id,))
    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for("admin_error_reports"))

    error_type = request.form.get("error_type", "").strip()
    report_date = request.form.get("report_date", "").strip()
    report_department = request.form.get("report_department", "").strip()
    message = request.form.get("message", "").strip()

    if not error_type or not report_date:
        flash("Error type and report date are required.", "danger")
        return redirect(url_for("admin_error_reports"))

    execute_db("""
        UPDATE incident_reports
        SET error_type = ?, report_date = ?, incident_date = ?, report_department = ?, message = ?
        WHERE id = ?
    """, (error_type, report_date, report_date, report_department, message, report_id), commit=True)

    employee = get_user_by_id(report["user_id"])
    employee_name = employee["full_name"] if employee else report.get("employee_name") or f"User {report['user_id']}"
    log_activity(session["user_id"], "EDIT INCIDENT", f"Edited incident #{report_id} for {employee_name}")
    flash("Incident report updated.", "success")
    return redirect(url_for("admin_error_reports"))


@app.route("/admin/error-reports/<int:report_id>/delete", methods=["POST"])
@login_required(role="admin")
def delete_incident_report(report_id):
    report = fetchone("""
        SELECT *
        FROM incident_reports
        WHERE id = ?
    """, (report_id,))
    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for("admin_error_reports"))

    employee = get_user_by_id(report["user_id"])
    employee_name = employee["full_name"] if employee else report.get("employee_name") or f"User {report['user_id']}"
    execute_db("DELETE FROM incident_reports WHERE id = ?", (report_id,), commit=True)
    log_activity(session["user_id"], "DELETE INCIDENT", f"Deleted incident #{report_id} for {employee_name}")
    flash("Incident report deleted.", "info")
    return redirect(url_for("admin_error_reports"))


def normalize_employee_id_dates(id_issue_date_raw, id_expiration_date_raw):
    id_issue_date = (id_issue_date_raw or "").strip()
    id_expiration_date = (id_expiration_date_raw or "").strip()

    issue_date_obj = None
    expiration_date_obj = None

    if id_issue_date:
        try:
            issue_date_obj = datetime.strptime(id_issue_date, "%Y-%m-%d").date()
            id_issue_date = issue_date_obj.strftime("%Y-%m-%d")
        except ValueError:
            return None, None, "ID Issue Date must be a valid date."

    if id_expiration_date:
        try:
            expiration_date_obj = datetime.strptime(id_expiration_date, "%Y-%m-%d").date()
            id_expiration_date = expiration_date_obj.strftime("%Y-%m-%d")
        except ValueError:
            return None, None, "ID Expiration Date must be a valid date."

    if issue_date_obj and expiration_date_obj and expiration_date_obj < issue_date_obj:
        return None, None, "ID Expiration Date cannot be earlier than ID Issue Date."

    return id_issue_date, id_expiration_date, None


@app.route("/admin/employees", methods=["GET", "POST"])
@login_required(role="admin")
def manage_employees():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        department = request.form.get("department", "").strip() or "Stellar Seats"
        position = request.form.get("position", "").strip() or "Employee"
        emergency_contact_name = request.form.get("emergency_contact_name", "").strip()
        emergency_contact_phone = request.form.get("emergency_contact_phone", "").strip()
        id_issue_date, id_expiration_date, id_date_error = normalize_employee_id_dates(
            request.form.get("id_issue_date", ""),
            request.form.get("id_expiration_date", "")
        )
        barcode_id = request.form.get("barcode_id", "").strip()
        hourly_rate = parse_money_value(request.form.get("hourly_rate", "0"))
        sick_leave_days = parse_non_negative_int(request.form.get("sick_leave_days", DEFAULT_SICK_LEAVE_DAYS), DEFAULT_SICK_LEAVE_DAYS)
        paid_leave_days = parse_non_negative_int(request.form.get("paid_leave_days", DEFAULT_PAID_LEAVE_DAYS), DEFAULT_PAID_LEAVE_DAYS)
        sick_leave_used_manual = parse_non_negative_int(request.form.get("sick_leave_used_manual", "0"), 0)
        paid_leave_used_manual = parse_non_negative_int(request.form.get("paid_leave_used_manual", "0"), 0)
        schedule_days = normalize_schedule_days(request.form.getlist("schedule_days"))
        shift_start = parse_shift_start(request.form.get("shift_start", DEFAULT_SHIFT_START))
        shift_end = parse_shift_end(request.form.get("shift_end", DEFAULT_SHIFT_END))
        break_limit_minutes = parse_break_limit_minutes(request.form.get("break_limit_minutes", BREAK_LIMIT_MINUTES))

        if not full_name or not username or not password:
            flash("Full name, username, and password are required.", "danger")
            return redirect(url_for("manage_employees"))

        existing = fetchone("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            flash("Username already exists.", "warning")
            return redirect(url_for("manage_employees"))

        if id_date_error:
            flash(id_date_error, "danger")
            return redirect(url_for("manage_employees"))

        if barcode_id:
            existing_barcode = fetchone("SELECT id FROM users WHERE TRIM(COALESCE(barcode_id, '')) = ?", (barcode_id,))
            if existing_barcode:
                flash("Barcode ID already exists.", "warning")
                return redirect(url_for("manage_employees"))

        profile_image = None
        file = request.files.get("profile_image")
        if file and file.filename:
            profile_image = save_uploaded_file(file, prefix="profile")
            if not profile_image:
                flash("Invalid profile image file type.", "danger")
                return redirect(url_for("manage_employees"))

        execute_db("""
            INSERT INTO users (
                full_name, username, password_hash, role, profile_image,
                department, position, emergency_contact_name, emergency_contact_phone, id_issue_date, id_expiration_date, barcode_id, hourly_rate, sick_leave_days, paid_leave_days, sick_leave_used_manual, paid_leave_used_manual, schedule_days, shift_start, shift_end, break_window_start, break_window_end, break_limit_minutes, is_active, created_at
            )
            VALUES (?, ?, ?, 'employee', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            full_name,
            username,
            generate_password_hash(password),
            profile_image,
            department,
            position,
            emergency_contact_name,
            emergency_contact_phone,
            id_issue_date,
            id_expiration_date,
            barcode_id,
            hourly_rate,
            sick_leave_days,
            paid_leave_days,
            sick_leave_used_manual,
            paid_leave_used_manual,
            schedule_days,
            shift_start,
            shift_end,
            DEFAULT_BREAK_WINDOW_START,
            DEFAULT_BREAK_WINDOW_END,
            break_limit_minutes,
            now_str()
        ), commit=True)

        new_user = fetchone("SELECT id FROM users WHERE username = ?", (username,))
        if new_user:
            create_notification(new_user["id"], "Account Created", "Your account has been created by admin.")
            log_activity(
                session["user_id"],
                "ADD EMPLOYEE",
                f"Added employee: {full_name} | " + summarize_employee_admin_changes(None, {
                    "department": department,
                    "position": position,
                    "emergency_contact_name": emergency_contact_name or "(not set)",
                    "emergency_contact_phone": emergency_contact_phone or "(not set)",
                    "id_issue_date": id_issue_date or "(auto)",
                    "id_expiration_date": id_expiration_date or "(auto)",
                    "barcode_id": barcode_id or "(not set)",
                    "hourly_rate": hourly_rate,
                    "sick_leave_days": sick_leave_days,
                    "paid_leave_days": paid_leave_days,
                    "sick_leave_used_manual": sick_leave_used_manual,
                    "paid_leave_used_manual": paid_leave_used_manual,
                    "shift_start": shift_start,
                    "shift_end": shift_end,
                    "break_limit_minutes": break_limit_minutes,
                    "is_active": 1,
                })
            )

        flash("Employee added successfully.", "success")
        return redirect(url_for("manage_employees"))

    employee_search = request.args.get("search", "").strip()
    sql = """
        SELECT * FROM users
        WHERE role = 'employee'
    """
    params = []

    if employee_search:
        sql += """
            AND (
                LOWER(full_name) LIKE ?
                OR LOWER(username) LIKE ?
                OR LOWER(COALESCE(department, '')) LIKE ?
                OR LOWER(COALESCE(position, '')) LIKE ?
            )
        """
        search_like = f"%{employee_search.lower()}%"
        params.extend([search_like, search_like, search_like, search_like])

    sql += " ORDER BY id DESC"
    employees = fetchall(sql, params)

    return render_template(
        "manage_employees.html",
        employees=employees,
        weekday_options=WEEKDAY_OPTIONS,
        employee_search=employee_search
    )


@app.route("/admin/edit-employee/<int:user_id>", methods=["GET", "POST"])
@login_required(role="admin")
def edit_employee(user_id):
    user = fetchone("""
        SELECT * FROM users
        WHERE id = ? AND role = 'employee'
    """, (user_id,))

    if not user:
        flash("Employee not found.", "danger")
        return redirect(url_for("manage_employees"))

    if request.method == "POST":
        original_user = user
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        department = request.form.get("department", "").strip() or "Stellar Seats"
        position = request.form.get("position", "").strip() or "Employee"
        emergency_contact_name = request.form.get("emergency_contact_name", "").strip()
        emergency_contact_phone = request.form.get("emergency_contact_phone", "").strip()
        id_issue_date, id_expiration_date, id_date_error = normalize_employee_id_dates(
            request.form.get("id_issue_date", ""),
            request.form.get("id_expiration_date", "")
        )
        barcode_id = request.form.get("barcode_id", "").strip()
        hourly_rate = parse_money_value(request.form.get("hourly_rate", user["hourly_rate"] or 0))
        sick_leave_days = parse_non_negative_int(request.form.get("sick_leave_days", user["sick_leave_days"] if user["sick_leave_days"] is not None else DEFAULT_SICK_LEAVE_DAYS), DEFAULT_SICK_LEAVE_DAYS)
        paid_leave_days = parse_non_negative_int(request.form.get("paid_leave_days", user["paid_leave_days"] if user["paid_leave_days"] is not None else DEFAULT_PAID_LEAVE_DAYS), DEFAULT_PAID_LEAVE_DAYS)
        sick_leave_used_manual = parse_non_negative_int(request.form.get("sick_leave_used_manual", user["sick_leave_used_manual"] if user["sick_leave_used_manual"] is not None else 0), 0)
        paid_leave_used_manual = parse_non_negative_int(request.form.get("paid_leave_used_manual", user["paid_leave_used_manual"] if user["paid_leave_used_manual"] is not None else 0), 0)
        schedule_days = normalize_schedule_days(request.form.getlist("schedule_days"))
        shift_start = parse_shift_start(request.form.get("shift_start", user["shift_start"] or DEFAULT_SHIFT_START))
        shift_end = parse_shift_end(request.form.get("shift_end", user["shift_end"] or DEFAULT_SHIFT_END))
        break_limit_minutes = parse_break_limit_minutes(request.form.get("break_limit_minutes", user["break_limit_minutes"]))
        is_active = 1 if request.form.get("is_active") == "1" else 0
        password = request.form.get("password", "").strip()

        if not full_name or not username:
            flash("Full name and username are required.", "danger")
            return redirect(url_for("edit_employee", user_id=user_id))

        existing = fetchone("""
            SELECT id FROM users
            WHERE username = ? AND id != ?
        """, (username, user_id))

        if existing:
            flash("Username already used by another employee.", "warning")
            return redirect(url_for("edit_employee", user_id=user_id))

        if id_date_error:
            flash(id_date_error, "danger")
            return redirect(url_for("edit_employee", user_id=user_id))

        if barcode_id:
            existing_barcode = fetchone("""
                SELECT id FROM users
                WHERE TRIM(COALESCE(barcode_id, '')) = ? AND id != ?
            """, (barcode_id, user_id))
            if existing_barcode:
                flash("Barcode ID already used by another employee.", "warning")
                return redirect(url_for("edit_employee", user_id=user_id))

        profile_image = user["profile_image"]
        file = request.files.get("profile_image")
        if file and file.filename:
            saved = save_uploaded_file(file, prefix=f"profile_{user_id}")
            if not saved:
                flash("Invalid profile image file type.", "danger")
                return redirect(url_for("edit_employee", user_id=user_id))
            profile_image = saved

        if password:
            execute_db("""
                UPDATE users
                SET full_name = ?, username = ?, password_hash = ?, profile_image = ?,
                    department = ?, position = ?, emergency_contact_name = ?, emergency_contact_phone = ?, id_issue_date = ?, id_expiration_date = ?, barcode_id = ?, hourly_rate = ?, sick_leave_days = ?, paid_leave_days = ?, sick_leave_used_manual = ?, paid_leave_used_manual = ?, schedule_days = ?, shift_start = ?, shift_end = ?, break_window_start = ?, break_window_end = ?, break_limit_minutes = ?, is_active = ?
                WHERE id = ?
            """, (
                full_name, username, generate_password_hash(password), profile_image,
                department, position, emergency_contact_name, emergency_contact_phone, id_issue_date, id_expiration_date, barcode_id, hourly_rate, sick_leave_days, paid_leave_days, sick_leave_used_manual, paid_leave_used_manual, schedule_days, shift_start, shift_end, user["break_window_start"] or DEFAULT_BREAK_WINDOW_START, user["break_window_end"] or DEFAULT_BREAK_WINDOW_END, break_limit_minutes, is_active, user_id
            ), commit=True)
        else:
            execute_db("""
                UPDATE users
                SET full_name = ?, username = ?, profile_image = ?,
                    department = ?, position = ?, emergency_contact_name = ?, emergency_contact_phone = ?, id_issue_date = ?, id_expiration_date = ?, barcode_id = ?, hourly_rate = ?, sick_leave_days = ?, paid_leave_days = ?, sick_leave_used_manual = ?, paid_leave_used_manual = ?, schedule_days = ?, shift_start = ?, shift_end = ?, break_window_start = ?, break_window_end = ?, break_limit_minutes = ?, is_active = ?
                WHERE id = ?
            """, (
                full_name, username, profile_image,
                department, position, emergency_contact_name, emergency_contact_phone, id_issue_date, id_expiration_date, barcode_id, hourly_rate, sick_leave_days, paid_leave_days, sick_leave_used_manual, paid_leave_used_manual, schedule_days, shift_start, shift_end, user["break_window_start"] or DEFAULT_BREAK_WINDOW_START, user["break_window_end"] or DEFAULT_BREAK_WINDOW_END, break_limit_minutes, is_active, user_id
            ), commit=True)

        log_activity(
            session["user_id"],
            "EDIT EMPLOYEE",
            f"Edited employee: {full_name} | " + summarize_employee_admin_changes(original_user, {
                "department": department,
                "position": position,
                "emergency_contact_name": emergency_contact_name or "(not set)",
                "emergency_contact_phone": emergency_contact_phone or "(not set)",
                "id_issue_date": id_issue_date or "(auto)",
                "id_expiration_date": id_expiration_date or "(auto)",
                "barcode_id": barcode_id or "(not set)",
                "hourly_rate": hourly_rate,
                "sick_leave_days": sick_leave_days,
                "paid_leave_days": paid_leave_days,
                "sick_leave_used_manual": sick_leave_used_manual,
                "paid_leave_used_manual": paid_leave_used_manual,
                "shift_start": shift_start,
                "shift_end": shift_end,
                "break_limit_minutes": break_limit_minutes,
                "is_active": is_active,
            })
        )
        flash("Employee updated successfully.", "success")
        return redirect(url_for("manage_employees"))

    return render_template("edit_employee.html", employee=user, weekday_options=WEEKDAY_OPTIONS, employee_schedule_days=get_schedule_day_codes(user["schedule_days"] if user["schedule_days"] else DEFAULT_SCHEDULE_DAYS))


@app.route("/admin/employee-id/<int:user_id>")
@login_required(role="admin")
def print_employee_id(user_id):
    employee = fetchone("""
        SELECT *
        FROM users
        WHERE id = ? AND role = 'employee'
    """, (user_id,))

    if not employee:
        flash("Employee not found.", "danger")
        return redirect(url_for("manage_employees"))
    employee = dict(employee)

    card_number = get_employee_card_number(employee)
    barcode_value = (employee["barcode_id"] or card_number).strip()
    company_settings = get_company_settings()
    if employee["id_issue_date"]:
        issue_date_value = employee["id_issue_date"]
    else:
        try:
            issue_dt = datetime.strptime((employee["created_at"] or now_str())[:19], "%Y-%m-%d %H:%M:%S").date()
        except Exception:
            issue_dt = now_dt().date()
        issue_date_value = issue_dt.strftime("%Y-%m-%d")

    if employee["id_expiration_date"]:
        expiration_date_value = employee["id_expiration_date"]
    else:
        try:
            base_issue_dt = datetime.strptime(issue_date_value, "%Y-%m-%d").date()
        except Exception:
            base_issue_dt = now_dt().date()
        expiration_date_value = (base_issue_dt + timedelta(days=365)).strftime("%Y-%m-%d")

    try:
        formatted_issue_date = datetime.strptime(issue_date_value, "%Y-%m-%d").strftime("%m/%d/%Y")
    except Exception:
        formatted_issue_date = issue_date_value
    try:
        formatted_expiration_date = datetime.strptime(expiration_date_value, "%Y-%m-%d").strftime("%m/%d/%Y")
    except Exception:
        formatted_expiration_date = expiration_date_value
    return render_template(
        "admin_employee_id_card.html",
        employee=employee,
        card_number=card_number,
        barcode_value=barcode_value,
        company_settings=company_settings,
        issue_date=formatted_issue_date,
        expiration_date=formatted_expiration_date
    )


@app.route("/admin/employee-id/signatory", methods=["POST"])
@login_required(role="admin")
def update_employee_id_signatory():
    signatory_name = request.form.get("id_signatory_name", "").strip() or "Kirk Danny Fernandez"
    signatory_title = request.form.get("id_signatory_title", "").strip() or "Head Of Operations"
    current_settings = get_company_settings()
    signature_file = current_settings["id_signature_file"] if current_settings else None

    file = request.files.get("id_signature_file")
    if file and file.filename:
        saved = save_uploaded_file(file, prefix="id_signature")
        if not saved:
            flash("Invalid signature image file type.", "danger")
            employee_id = request.form.get("employee_id", "").strip()
            if employee_id:
                return redirect(url_for("print_employee_id", user_id=employee_id))
            return redirect(url_for("manage_employees"))
        signature_file = saved

    execute_db("""
        INSERT INTO company_settings (id, id_signatory_name, id_signatory_title, id_signature_file)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            id_signatory_name = excluded.id_signatory_name,
            id_signatory_title = excluded.id_signatory_title,
            id_signature_file = excluded.id_signature_file
    """, (signatory_name, signatory_title, signature_file), commit=True)

    log_activity(session["user_id"], "UPDATE ID SIGNATORY", f"Updated ID signatory to {signatory_name} | {signatory_title}")
    flash("ID signatory details updated.", "success")
    employee_id = request.form.get("employee_id", "").strip()
    if employee_id:
        return redirect(url_for("print_employee_id", user_id=employee_id))
    return redirect(url_for("manage_employees"))


@app.route("/admin/delete-employee/<int:user_id>", methods=["POST"])
@login_required(role="admin")
def delete_employee(user_id):
    user = fetchone("""
        SELECT * FROM users
        WHERE id = ? AND role = 'employee'
    """, (user_id,))

    if not user:
        flash("Employee not found.", "danger")
        return redirect(url_for("manage_employees"))

    execute_db("DELETE FROM notifications WHERE user_id = ?", (user_id,), commit=True)
    execute_db("DELETE FROM breaks WHERE user_id = ?", (user_id,), commit=True)
    execute_db("DELETE FROM attendance WHERE user_id = ?", (user_id,), commit=True)
    execute_db("DELETE FROM activity_logs WHERE user_id = ?", (user_id,), commit=True)
    execute_db("DELETE FROM incident_reports WHERE user_id = ?", (user_id,), commit=True)
    execute_db("DELETE FROM disciplinary_actions WHERE user_id = ?", (user_id,), commit=True)
    execute_db("DELETE FROM users WHERE id = ?", (user_id,), commit=True)

    log_activity(session["user_id"], "DELETE EMPLOYEE", f"Deleted employee: {user['full_name']}")
    flash("Employee deleted successfully.", "info")
    return redirect(url_for("manage_employees"))


@app.route("/admin/send-notification", methods=["POST"])
@login_required(role="admin")
def send_admin_notification():
    user_id = request.form.get("user_id")
    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()

    if not user_id or not title or not message:
        flash("All notification fields are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    create_notification(user_id, title, message)
    log_activity(session["user_id"], "SEND NOTIFICATION", f"Sent notification to user ID {user_id}")
    flash("Notification sent successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/create-incident", methods=["POST"])
@login_required(role="admin")
def create_incident_route():
    user_id = request.form.get("user_id")
    error_type = request.form.get("error_type", "").strip()
    report_date = request.form.get("report_date", "").strip()
    message = request.form.get("message", "").strip()

    if not user_id or not error_type or not report_date:
        flash("All fields are required.", "danger")
        return redirect(url_for("admin_incident_report"))

    employee = get_user_by_id(user_id)

    create_incident(
        user_id=user_id,
        error_type=error_type,
        report_date=report_date,
        message=message,
        admin_id=session["user_id"],
        incident_action="",
        report_department=employee["department"] if employee else ""
    )

    employee_name = employee["full_name"] if employee else f"User {user_id}"
    log_activity(
        session["user_id"],
        "CREATE INCIDENT",
        f"{error_type} report created for {employee_name}"
    )

    flash("Incident report created.", "success")
    return redirect(url_for("admin_incident_report"))


@app.route("/admin/disciplinary/create", methods=["POST"])
@login_required(role="admin")
def create_disciplinary_action_route():
    user_id = request.form.get("user_id", "").strip()
    action_type = request.form.get("action_type", "").strip()
    action_date = request.form.get("action_date", "").strip()
    duration_days = parse_non_negative_int(request.form.get("duration_days", "1"), 1)
    details = request.form.get("details", "").strip()

    if not user_id or not action_type or not action_date:
        flash("Employee, action type, and action date are required.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))

    if action_type not in DISCIPLINARY_ACTION_TYPES:
        flash("Invalid disciplinary action type.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))

    if action_type == "Suspension" and duration_days <= 0:
        flash("Suspension days must be at least 1.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))

    if action_type != "Suspension":
        duration_days = 1

    employee = get_user_by_id(user_id)
    conflict = find_conflicting_disciplinary_action(user_id, action_type, action_date, duration_days)
    if conflict:
        flash(conflict["conflict_reason"], "warning")
        return redirect(url_for("admin_disciplinary_dashboard"))
    create_disciplinary_action(
        user_id=user_id,
        action_type=action_type,
        action_date=action_date,
        details=details,
        created_by=session["user_id"],
        duration_days=duration_days
    )

    employee_name = employee["full_name"] if employee else f"User {user_id}"
    log_activity(
        session["user_id"],
        "CREATE DISCIPLINARY ACTION",
        f"{action_type} created for {employee_name}" + (f" for {duration_days} day(s)" if action_type == "Suspension" else "")
    )
    flash(f"{action_type} record created.", "success")
    return redirect(url_for("admin_disciplinary_dashboard"))


@app.route("/admin/disciplinary/<int:action_id>/update", methods=["POST"])
@login_required(role="admin")
def update_disciplinary_action_route(action_id):
    action = get_disciplinary_action_by_id(action_id)
    if not action:
        flash("Disciplinary record not found.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))

    action_type = request.form.get("action_type", "").strip()
    action_date = request.form.get("action_date", "").strip()
    duration_days = parse_non_negative_int(request.form.get("duration_days", "1"), 1)
    details = request.form.get("details", "").strip()

    if not action_type or not action_date:
        flash("Action type and action date are required.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))
    if action_type not in DISCIPLINARY_ACTION_TYPES:
        flash("Invalid disciplinary action type.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))

    if action_type != "Suspension":
        duration_days = 1
    conflict = find_conflicting_disciplinary_action(action["user_id"], action_type, action_date, duration_days, exclude_id=action_id)
    if conflict:
        flash(conflict["conflict_reason"], "warning")
        return redirect(url_for("admin_disciplinary_dashboard"))
    end_date = calculate_suspension_end_date(action_date, duration_days) if action_type == "Suspension" else action_date

    execute_db("""
        UPDATE disciplinary_actions
        SET action_type = ?, action_date = ?, duration_days = ?, end_date = ?, details = ?
        WHERE id = ?
    """, (action_type, action_date, duration_days, end_date, details, action_id), commit=True)

    employee = get_user_by_id(action["user_id"])
    employee_name = employee["full_name"] if employee else f"User {action['user_id']}"
    log_activity(session["user_id"], "UPDATE DISCIPLINARY ACTION", f"Updated {action_type} for {employee_name}")
    flash("Disciplinary record updated.", "success")
    return redirect(url_for("admin_disciplinary_dashboard"))


@app.route("/admin/disciplinary/<int:action_id>/delete", methods=["POST"])
@login_required(role="admin")
def delete_disciplinary_action_route(action_id):
    action = get_disciplinary_action_by_id(action_id)
    if not action:
        flash("Disciplinary record not found.", "danger")
        return redirect(url_for("admin_disciplinary_dashboard"))

    employee = get_user_by_id(action["user_id"])
    employee_name = employee["full_name"] if employee else f"User {action['user_id']}"
    execute_db("DELETE FROM disciplinary_actions WHERE id = ?", (action_id,), commit=True)
    log_activity(session["user_id"], "DELETE DISCIPLINARY ACTION", f"Deleted {action['action_type']} for {employee_name}")
    flash("Disciplinary record deleted.", "info")
    return redirect(url_for("admin_disciplinary_dashboard"))


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").strip() == "1"
    )
