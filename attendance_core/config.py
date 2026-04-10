import os
from zoneinfo import ZoneInfo


BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
RENDER_DEFAULT_DISK_PATH = "/var/data"


def resolve_persistent_disk_path():
    configured_path = os.environ.get("RENDER_DISK_PATH", "").strip()
    if configured_path:
        return configured_path
    if os.environ.get("RENDER") and os.path.isdir(RENDER_DEFAULT_DISK_PATH):
        return RENDER_DEFAULT_DISK_PATH
    return ""


PERSISTENT_DISK_PATH = resolve_persistent_disk_path()
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
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
DOCUMENT_EXTENSIONS = {"pdf"}
ALLOWED_EXTENSIONS = IMAGE_EXTENSIONS | DOCUMENT_EXTENSIONS

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
ADMIN_PERMISSION_OPTIONS = [
    ("dashboard", "Dashboard"),
    ("employees", "Employees"),
    ("attendance", "Attendance"),
    ("workflows", "Workflows"),
    ("payroll", "Payroll"),
    ("reports", "Reports"),
    ("settings", "Settings"),
]
ADMIN_PERMISSION_CODES = {code for code, _ in ADMIN_PERMISSION_OPTIONS}
ADMIN_PERMISSION_LABELS = {code: label for code, label in ADMIN_PERMISSION_OPTIONS}
ADMIN_ROLE_PRESET_OPTIONS = [
    ("full_admin", "Full Admin", "All modules and settings access.", ["dashboard", "employees", "attendance", "workflows", "payroll", "reports", "settings"]),
    ("attendance_supervisor", "Attendance Supervisor", "Monitor live attendance, scanner activity, corrections, and operational exceptions without employee or payroll access.", ["dashboard", "attendance", "reports"]),
    ("people_ops", "HR", "Manage employees, leave, incidents, and disciplinary workflows without payroll or settings access.", ["dashboard", "employees", "workflows", "reports"]),
    ("payroll_officer", "Payroll", "Build payroll, manage recurring pay rules, and review payroll reports without employee-admin settings access.", ["dashboard", "payroll", "reports"]),
    ("reports_viewer", "Viewer / Report-Only", "Read-only access to dashboard summaries and the reporting center.", ["dashboard", "reports"]),
]
ADMIN_ROLE_PRESETS = {
    code: {
        "code": code,
        "label": label,
        "description": description,
        "permissions": tuple(permissions),
    }
    for code, label, description, permissions in ADMIN_ROLE_PRESET_OPTIONS
}
SCHEDULE_SPECIAL_RULE_OPTIONS = [
    ("holiday", "Holiday"),
    ("rest_day", "Rest Day"),
]
SCHEDULE_SPECIAL_RULE_LABELS = {code: label for code, label in SCHEDULE_SPECIAL_RULE_OPTIONS}
ADMIN_STATUS_CACHE_TTL_SECONDS = 12
OPTION_CACHE_TTL_SECONDS = 60
REPORT_CACHE_TTL_SECONDS = 90
SCHEDULE_CHANGE_APPLY_TTL_SECONDS = 60
ADMIN_ALERT_SCAN_TTL_SECONDS = 45

DEFAULT_SECRET_KEY = "dev-secret-key"
LOGIN_WINDOW_MINUTES = 15
LOGIN_MAX_ATTEMPTS = 10


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
