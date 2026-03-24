import os
import sqlite3
from io import BytesIO
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, send_from_directory, jsonify, Response
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

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB


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
            error_type TEXT NOT NULL,
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
        CREATE TABLE IF NOT EXISTS correction_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            request_type TEXT NOT NULL,
            work_date TEXT NOT NULL,
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

    existing_cols_corrections = [row[1] for row in cursor.execute("PRAGMA table_info(correction_requests)").fetchall()]
    if existing_cols_corrections:
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
                error_type TEXT NOT NULL,
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

        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS employee_name TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS incident_date TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Open'")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS admin_note TEXT")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS reviewed_by INTEGER")
        cur.execute("ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS reviewed_at TEXT")

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
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_time_in TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_break_start TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_break_end TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS requested_time_out TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS applied_changes TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Pending'")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS admin_note TEXT")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS reviewed_by INTEGER")
        cur.execute("ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS reviewed_at TEXT")

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


def create_incident(user_id, error_type, report_date, message, admin_id):
    user = get_user_by_id(user_id)

    execute_db("""
        INSERT INTO incident_reports (
            user_id,
            employee_name,
            error_type,
            incident_date,
            report_date,
            message,
            status,
            admin_note,
            created_by,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'Open', NULL, ?, ?)
    """, (
        user_id,
        user["full_name"] if user else "",
        error_type,
        report_date,
        report_date,
        message,
        admin_id,
        now_str()
    ), commit=True)


def log_activity(user_id, action, details=""):
    execute_db("""
        INSERT INTO activity_logs (user_id, action, details, created_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, action, details, now_str()), commit=True)


def get_user_by_id(user_id):
    return fetchone("SELECT * FROM users WHERE id = ?", (user_id,))


def get_today_attendance(user_id):
    return fetchone("""
        SELECT * FROM attendance
        WHERE user_id = ? AND work_date = ?
        ORDER BY id DESC LIMIT 1
    """, (user_id, today_str()))


def get_open_break(user_id):
    return fetchone("""
        SELECT * FROM breaks
        WHERE user_id = ? AND work_date = ? AND break_end IS NULL
        ORDER BY id DESC LIMIT 1
    """, (user_id, today_str()))


def get_user_live_status(user_id):
    attendance = get_today_attendance(user_id)
    open_break = get_open_break(user_id)

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
    break_start = parse_optional_schedule_time(user_row["break_window_start"], DEFAULT_BREAK_WINDOW_START)
    break_end = parse_optional_schedule_time(user_row["break_window_end"], DEFAULT_BREAK_WINDOW_END)
    return f"{shift_start} - {shift_end} | Break {break_start} - {break_end}"


def get_today_schedule_code():
    return WEEKDAY_OPTIONS[now_dt().weekday()][0]


def is_scheduled_today(user_row):
    return get_today_schedule_code() in get_schedule_day_codes(user_row["schedule_days"] if user_row else DEFAULT_SCHEDULE_DAYS)


def is_absent_today(user_row, attendance_row):
    if not user_row or user_row["is_active"] != 1 or attendance_row:
        return False
    if not is_scheduled_today(user_row):
        return False

    shift_start = parse_shift_start(user_row["shift_start"] if user_row else DEFAULT_SHIFT_START)
    shift_dt = datetime.strptime(
        f"{today_str()} {shift_start}:00",
        "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=APP_TIMEZONE)
    return now_dt() >= (shift_dt + timedelta(minutes=LATE_GRACE_MINUTES))


def is_missing_timeout_today(user_row, attendance_row):
    if not user_row or user_row["is_active"] != 1 or not attendance_row:
        return False
    if not attendance_row["time_in"] or attendance_row["time_out"]:
        return False
    if not is_scheduled_today(user_row):
        return False

    shift_end = parse_shift_end(user_row["shift_end"] if user_row else DEFAULT_SHIFT_END)
    shift_end_dt = datetime.strptime(
        f"{today_str()} {shift_end}:00",
        "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=APP_TIMEZONE)
    return now_dt() >= (shift_end_dt + timedelta(minutes=LATE_GRACE_MINUTES))


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
    breaks_rows = fetchall("""
        SELECT * FROM breaks
        WHERE attendance_id = ?
        ORDER BY id ASC
    """, (attendance_id,))

    total_minutes = 0
    for br in breaks_rows:
        if br["break_start"] and (br["break_end"] or include_open):
            start = datetime.strptime(br["break_start"], "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(br["break_end"] or now_str(), "%Y-%m-%d %H:%M:%S")
            total_minutes += int((end - start).total_seconds() // 60)
    return total_minutes


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


def get_avatar_initials(name):
    parts = [part.strip() for part in (name or "").split() if part.strip()]
    if not parts:
        return "U"
    initials = "".join(part[0] for part in parts[:2]).upper()
    return initials or "U"


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


def parse_positive_int(value, default):
    try:
        parsed = int(str(value).strip())
        return parsed if parsed > 0 else default
    except Exception:
        return default


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
        uploaded_file_exists=uploaded_file_exists,
        get_avatar_initials=get_avatar_initials,
        format_datetime_12h=format_datetime_12h,
        format_time_12h=format_time_12h
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

    today_attendance = get_today_attendance(user["id"])
    open_break = get_open_break(user["id"])

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
    todays_break_minutes = total_break_minutes(today_attendance["id"], include_open=True) if today_attendance else 0
    todays_work_minutes = total_work_minutes(today_attendance) if today_attendance else 0
    break_limit_minutes = get_employee_break_limit(user)
    over_break_minutes = get_overbreak_minutes(todays_break_minutes, break_limit_minutes)

    return render_template(
        "employee_dashboard.html",
        user=user,
        today_attendance=today_attendance,
        notifications=notifications,
        current_status=current_status,
        todays_break_minutes=todays_break_minutes,
        todays_work_minutes=todays_work_minutes,
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
    break_limit_minutes = get_employee_break_limit(user)
    records = fetchall("""
        SELECT * FROM attendance
        WHERE user_id = ?
        ORDER BY work_date DESC, id DESC
        LIMIT 60
    """, (session["user_id"],))

    enriched = []
    for row in records:
        enriched.append({
            "row": row,
            "break_minutes": total_break_minutes(row["id"]),
            "work_minutes": total_work_minutes(row),
            "over_break_minutes": get_overbreak_minutes(total_break_minutes(row["id"]), break_limit_minutes)
        })

    return render_template("employee_history.html", records=enriched, minutes_to_hm=minutes_to_hm)


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
        message = request.form.get("message", "").strip()
        requested_time_in = request.form.get("requested_time_in", "")
        requested_break_start = request.form.get("requested_break_start", "")
        requested_break_end = request.form.get("requested_break_end", "")
        requested_time_out = request.form.get("requested_time_out", "")

        if request_type not in {"Missed Time In", "Missed Time Out", "Wrong Break", "Wrong Proof", "Other"}:
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
                user_id, request_type, work_date, message,
                requested_time_in, requested_break_start, requested_break_end, requested_time_out,
                status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
        """, (
            user["id"],
            request_type,
            work_date,
            message,
            requested_time_in_dt,
            requested_break_start_dt,
            requested_break_end_dt,
            requested_time_out_dt,
            now_str()
        ), commit=True)

        log_activity(user["id"], "CORRECTION REQUEST", f"Submitted {request_type} request for {work_date}")
        flash("Correction request submitted.", "success")
        return redirect(url_for("employee_corrections"))

    requests = get_correction_requests(user_id=user["id"])
    return render_template("employee_corrections.html", requests=requests)


@app.route("/time-in", methods=["POST"])
@login_required(role="employee")
def time_in():
    user_id = session["user_id"]
    user = get_user_by_id(user_id)

    if not user:
        session.clear()
        flash("Your session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    existing = get_today_attendance(user_id)
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
    latest_attendance = get_today_attendance(user_id)

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
    attendance = get_today_attendance(user_id)

    if not attendance or not attendance["time_in"] or attendance["time_out"]:
        flash("You must be timed in first.", "danger")
        return redirect(url_for("dashboard"))

    open_break = get_open_break(user_id)
    if open_break:
        flash("You are already on break.", "warning")
        return redirect(url_for("dashboard"))

    execute_db("""
        INSERT INTO breaks (user_id, attendance_id, work_date, break_start, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, attendance["id"], today_str(), now_str(), now_str()), commit=True)

    execute_db("""
        UPDATE attendance
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, ("On Break", now_str(), attendance["id"]), commit=True)

    create_notification(user_id, "Break Started", f"You started break at {now_str()} ET.")
    log_activity(user_id, "BREAK START", "Employee started break")
    flash("Break started.", "info")
    return redirect(url_for("dashboard"))


@app.route("/end-break", methods=["POST"])
@login_required(role="employee")
def end_break():
    user_id = session["user_id"]
    open_break = get_open_break(user_id)
    attendance = get_today_attendance(user_id)

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
    attendance = get_today_attendance(user_id)

    if not attendance or not attendance["time_in"]:
        flash("You are not timed in.", "danger")
        return redirect(url_for("dashboard"))

    if attendance["time_out"]:
        flash("You are already timed out.", "warning")
        return redirect(url_for("dashboard"))

    open_break = get_open_break(user_id)
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
    updated_attendance = get_today_attendance(user_id)
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
        attendance = get_today_attendance(user["id"])
        scheduled_today = is_scheduled_today(user)
        absent_today = is_absent_today(user, attendance)
        missing_timeout_today = is_missing_timeout_today(user, attendance)
        status_display = live_status

        if user["is_active"] != 1:
            status_display = "Inactive"
        elif absent_today:
            status_display = "Absent"
        elif missing_timeout_today:
            status_display = "Missing Time Out"
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
        row["avatar_initials"] = get_avatar_initials(user["full_name"])
        row["attention_score"] = int(row["absent_flag"]) + int(row["late_flag"]) + int(row["over_break_flag"]) + int(row["missing_timeout_flag"])

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
        report_sql += " AND COALESCE(u.department, '') = ?"
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

    return {
        "absent": sorted(absent, key=lambda row: (row["department"] or "", row["full_name"] or "")),
        "late": sorted(late, key=lambda row: (-row["late_minutes"], row["full_name"] or "")),
        "over_break": sorted(over_break, key=lambda row: (-row["over_break_minutes"], row["full_name"] or "")),
        "missing_timeout": sorted(missing_timeout, key=lambda row: (row["shift_end"] or "", row["full_name"] or "")),
    }


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
        sql += " AND c.work_date >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND c.work_date <= ?"
        params.append(date_to)

    sql += " ORDER BY c.id DESC LIMIT 200"
    rows = fetchall(sql, params)
    enriched_rows = []

    for row in rows:
        item = dict(row)
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


def apply_attendance_correction(user_id, work_date, time_in_value="", break_start_value="", break_end_value="", time_out_value=""):
    attendance, break_row = get_attendance_context(user_id, work_date)

    before_values = {
        "time_in": attendance["time_in"] if attendance else None,
        "break_start": break_row["break_start"] if break_row else None,
        "break_end": break_row["break_end"] if break_row else None,
        "time_out": attendance["time_out"] if attendance else None,
    }

    final_time_in, final_break_start, final_break_end, final_time_out = resolve_correction_datetimes(
        work_date,
        time_in_value=time_in_value,
        break_start_value=break_start_value,
        break_end_value=break_end_value,
        time_out_value=time_out_value,
        existing_time_in=attendance["time_in"] if attendance else None,
        existing_break_start=break_row["break_start"] if break_row else None,
        existing_break_end=break_row["break_end"] if break_row else None,
        existing_time_out=attendance["time_out"] if attendance else None
    )

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
            work_date,
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
        """, (user_id, work_date))

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
        """, (user_id, attendance["id"], work_date, final_break_start, final_break_end, now_str()), commit=True)

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
        "missing_timeout": len(exception_groups["missing_timeout"])
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


@app.route("/admin/history")
@login_required(role="admin")
def admin_history():
    search = request.args.get("search", "").strip()
    department = request.args.get("department", "").strip()
    late_only = request.args.get("late_only", "").strip()
    absent_only = request.args.get("absent_only", "").strip()
    over_break_only = request.args.get("over_break_only", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

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

    sql += " ORDER BY a.work_date DESC, a.id DESC LIMIT 200"

    rows = fetchall(sql, params)
    departments = get_department_options()

    enriched = []
    for row in rows:
        employee = get_user_by_id(row["user_id"])
        item = {
            "row": row,
            "break_minutes": total_break_minutes(row["id"]),
            "work_minutes": total_work_minutes(row),
            "over_break_minutes": get_overbreak_minutes(total_break_minutes(row["id"]), row["break_limit_minutes"]),
            "absent_flag": 1 if is_absent_today(employee, row) else 0
        }
        if absent_only == "1" and item["absent_flag"] != 1:
            continue
        if over_break_only == "1" and item["over_break_minutes"] <= 0:
            continue
        enriched.append(item)

    return render_template(
        "admin_history.html",
        records=enriched,
        search=search,
        department=department,
        departments=departments,
        late_only=late_only,
        absent_only=absent_only,
        over_break_only=over_break_only,
        date_from=date_from,
        date_to=date_to,
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

    if status == "Approved":
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

    attendance, break_row = get_attendance_context(correction["user_id"], correction["work_date"])
    requested_time_in_dt, requested_break_start_dt, requested_break_end_dt, requested_time_out_dt = resolve_correction_datetimes(
        correction["work_date"],
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
    late_only = request.args.get("late_only", "").strip()
    absent_only = request.args.get("absent_only", "").strip()
    over_break_only = request.args.get("over_break_only", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

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

    sql += " ORDER BY a.work_date DESC, a.id DESC LIMIT 500"
    rows = fetchall(sql, params)

    try:
        from openpyxl import Workbook
    except Exception:
        flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
        return redirect(url_for(
            "admin_history",
            search=search,
            department=department,
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
        "Time In",
        "Time Out",
        "Status",
        "Late Minutes",
        "Break Limit",
        "Break Minutes",
        "Overbreak Minutes",
        "Work Minutes",
        "Proof File"
    ])

    for row in rows:
        break_minutes = total_break_minutes(row["id"])
        over_break_minutes = get_overbreak_minutes(break_minutes, row["break_limit_minutes"])
        employee = get_user_by_id(row["user_id"])
        if absent_only == "1" and not is_absent_today(employee, row):
            continue
        if over_break_only == "1" and over_break_minutes <= 0:
            continue

        sheet.append([
            row["full_name"] or "",
            row["username"] or "",
            row["work_date"] or "",
            row["time_in"] or "",
            row["time_out"] or "",
            row["status"] or "",
            row["late_minutes"] if row["late_flag"] else 0,
            parse_break_limit_minutes(row["break_limit_minutes"]),
            break_minutes,
            over_break_minutes,
            total_work_minutes(row),
            row["proof_file"] or ""
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
            report["department"] or "",
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


@app.route("/admin/employees", methods=["GET", "POST"])
@login_required(role="admin")
def manage_employees():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        department = request.form.get("department", "").strip() or "Stellar Seats"
        position = request.form.get("position", "").strip() or "Employee"
        schedule_days = normalize_schedule_days(request.form.getlist("schedule_days"))
        shift_start = parse_shift_start(request.form.get("shift_start", DEFAULT_SHIFT_START))
        shift_end = parse_shift_end(request.form.get("shift_end", DEFAULT_SHIFT_END))
        break_window_start = parse_optional_schedule_time(request.form.get("break_window_start", DEFAULT_BREAK_WINDOW_START), DEFAULT_BREAK_WINDOW_START)
        break_window_end = parse_optional_schedule_time(request.form.get("break_window_end", DEFAULT_BREAK_WINDOW_END), DEFAULT_BREAK_WINDOW_END)
        break_limit_minutes = parse_break_limit_minutes(request.form.get("break_limit_minutes", BREAK_LIMIT_MINUTES))

        if not full_name or not username or not password:
            flash("Full name, username, and password are required.", "danger")
            return redirect(url_for("manage_employees"))

        existing = fetchone("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            flash("Username already exists.", "warning")
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
                department, position, schedule_days, shift_start, shift_end, break_window_start, break_window_end, break_limit_minutes, is_active, created_at
            )
            VALUES (?, ?, ?, 'employee', ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            full_name,
            username,
            generate_password_hash(password),
            profile_image,
            department,
            position,
            schedule_days,
            shift_start,
            shift_end,
            break_window_start,
            break_window_end,
            break_limit_minutes,
            now_str()
        ), commit=True)

        new_user = fetchone("SELECT id FROM users WHERE username = ?", (username,))
        if new_user:
            create_notification(new_user["id"], "Account Created", "Your account has been created by admin.")
            log_activity(session["user_id"], "ADD EMPLOYEE", f"Added employee: {full_name} | Shift: {shift_start}-{shift_end} | Break Window: {break_window_start}-{break_window_end} | Schedule: {schedule_days} | Break Limit: {break_limit_minutes}m")

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
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        department = request.form.get("department", "").strip() or "Stellar Seats"
        position = request.form.get("position", "").strip() or "Employee"
        schedule_days = normalize_schedule_days(request.form.getlist("schedule_days"))
        shift_start = parse_shift_start(request.form.get("shift_start", user["shift_start"] or DEFAULT_SHIFT_START))
        shift_end = parse_shift_end(request.form.get("shift_end", user["shift_end"] or DEFAULT_SHIFT_END))
        break_window_start = parse_optional_schedule_time(request.form.get("break_window_start", user["break_window_start"] or DEFAULT_BREAK_WINDOW_START), DEFAULT_BREAK_WINDOW_START)
        break_window_end = parse_optional_schedule_time(request.form.get("break_window_end", user["break_window_end"] or DEFAULT_BREAK_WINDOW_END), DEFAULT_BREAK_WINDOW_END)
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
                    department = ?, position = ?, schedule_days = ?, shift_start = ?, shift_end = ?, break_window_start = ?, break_window_end = ?, break_limit_minutes = ?, is_active = ?
                WHERE id = ?
            """, (
                full_name, username, generate_password_hash(password), profile_image,
                department, position, schedule_days, shift_start, shift_end, break_window_start, break_window_end, break_limit_minutes, is_active, user_id
            ), commit=True)
        else:
            execute_db("""
                UPDATE users
                SET full_name = ?, username = ?, profile_image = ?,
                    department = ?, position = ?, schedule_days = ?, shift_start = ?, shift_end = ?, break_window_start = ?, break_window_end = ?, break_limit_minutes = ?, is_active = ?
                WHERE id = ?
            """, (
                full_name, username, profile_image,
                department, position, schedule_days, shift_start, shift_end, break_window_start, break_window_end, break_limit_minutes, is_active, user_id
            ), commit=True)

        log_activity(session["user_id"], "EDIT EMPLOYEE", f"Edited employee: {full_name} | Shift: {shift_start}-{shift_end} | Break Window: {break_window_start}-{break_window_end} | Schedule: {schedule_days} | Break Limit: {break_limit_minutes}m")
        flash("Employee updated successfully.", "success")
        return redirect(url_for("manage_employees"))

    return render_template("edit_employee.html", employee=user, weekday_options=WEEKDAY_OPTIONS, employee_schedule_days=get_schedule_day_codes(user["schedule_days"] if user["schedule_days"] else DEFAULT_SCHEDULE_DAYS))


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
        admin_id=session["user_id"]
    )

    employee_name = employee["full_name"] if employee else f"User {user_id}"
    log_activity(
        session["user_id"],
        "CREATE INCIDENT",
        f"{error_type} report created for {employee_name}"
    )

    flash("Incident report created.", "success")
    return redirect(url_for("admin_incident_report"))


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").strip() == "1"
    )
