from flask import Flask, render_template, request, redirect, session, flash, send_from_directory
import json
import os
import datetime
from zoneinfo import ZoneInfo
import gspread
from google.oauth2.service_account import Credentials
from werkzeug.utils import secure_filename


def is_render():
    return os.environ.get("RENDER") == "true"


app = Flask(__name__)
app.secret_key = "attendance_secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
LOCAL_CREDENTIALS_FILE = os.path.join(BASE_DIR, "attendance-credentials.json")
SPREADSHEET_URL = "https://docs.google.com/spreadsheets/d/1j6TLjNOSifsVxHFHyLVvevyqyOza1RUq0-dt2dWcQ5g/edit"
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

COMPANY_NAME = "Stellar Seats"

ATTENDANCE_TIMEZONE = "America/New_York"
ATTENDANCE_TZ = ZoneInfo(ATTENDANCE_TIMEZONE)

DEFAULT_SHIFT_START = "21:00"
DEFAULT_SHIFT_END = "06:00"
DEFAULT_GRACE_MINUTES = 5
DEFAULT_ALLOWED_BREAK_MINUTES = 60

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

HISTORY_CACHE = {}
CACHE_TTL_SECONDS = 60

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def now_et():
    return datetime.datetime.now(ATTENDANCE_TZ)


def today_et_str():
    return now_et().strftime("%Y-%m-%d")


def current_timestamp_for_filename():
    return now_et().strftime("%Y%m%d%H%M%S")


def parse_hhmm(value, default_value):
    try:
        if not value:
            value = default_value
        hour, minute = value.split(":")
        hour = int(hour)
        minute = int(minute)
        if 0 <= hour <= 23 and 0 <= minute <= 59:
            return f"{hour:02d}:{minute:02d}"
    except Exception:
        pass
    return default_value


def hhmm_to_display(value):
    try:
        hour, minute = map(int, value.split(":"))
        dt = datetime.datetime(2000, 1, 1, hour, minute)
        return dt.strftime("%I:%M %p")
    except Exception:
        return value


def parse_sheet_datetime(date_str, time_str):
    try:
        naive = datetime.datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %I:%M:%S %p")
        return naive.replace(tzinfo=ATTENDANCE_TZ)
    except Exception:
        return None


def get_google_credentials():
    env_creds = os.environ.get("GOOGLE_CREDENTIALS", "").strip()
    if env_creds:
        try:
            google_creds = json.loads(env_creds)
            return Credentials.from_service_account_info(google_creds, scopes=SCOPES)
        except Exception as e:
            raise RuntimeError(f"Invalid GOOGLE_CREDENTIALS environment variable: {e}")

    if os.path.exists(LOCAL_CREDENTIALS_FILE):
        try:
            return Credentials.from_service_account_file(
                LOCAL_CREDENTIALS_FILE,
                scopes=SCOPES
            )
        except Exception as e:
            raise RuntimeError(f"Local credentials file could not be read: {e}")

    raise RuntimeError(
        "Google credentials not found. Set GOOGLE_CREDENTIALS in environment variables or place "
        "'attendance-credentials.json' in the project folder."
    )


_gc = None
_spreadsheet = None
_google_init_error = None


def get_spreadsheet():
    global _gc, _spreadsheet, _google_init_error

    if _spreadsheet is not None:
        return _spreadsheet

    if _google_init_error is not None:
        raise RuntimeError(_google_init_error)

    try:
        creds = get_google_credentials()
        _gc = gspread.authorize(creds)
        _spreadsheet = _gc.open_by_url(SPREADSHEET_URL)
        return _spreadsheet
    except Exception as e:
        _google_init_error = str(e)
        raise RuntimeError(_google_init_error)


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    return {
        "Henry": {
            "password": "1234",
            "profile_picture": "",
            "shift_start": DEFAULT_SHIFT_START,
            "shift_end": DEFAULT_SHIFT_END,
            "grace_minutes": DEFAULT_GRACE_MINUTES,
            "allowed_break_minutes": DEFAULT_ALLOWED_BREAK_MINUTES
        },
        "Admin": {
            "password": "admin123",
            "profile_picture": "",
            "shift_start": DEFAULT_SHIFT_START,
            "shift_end": DEFAULT_SHIFT_END,
            "grace_minutes": DEFAULT_GRACE_MINUTES,
            "allowed_break_minutes": DEFAULT_ALLOWED_BREAK_MINUTES
        }
    }


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


def normalize_users(users):
    normalized = {}
    for name, value in users.items():
        if isinstance(value, str):
            normalized[name] = {
                "password": value,
                "profile_picture": "",
                "shift_start": DEFAULT_SHIFT_START,
                "shift_end": DEFAULT_SHIFT_END,
                "grace_minutes": DEFAULT_GRACE_MINUTES,
                "allowed_break_minutes": DEFAULT_ALLOWED_BREAK_MINUTES
            }
        else:
            normalized[name] = {
                "password": value.get("password", ""),
                "profile_picture": value.get("profile_picture", ""),
                "shift_start": parse_hhmm(value.get("shift_start", DEFAULT_SHIFT_START), DEFAULT_SHIFT_START),
                "shift_end": parse_hhmm(value.get("shift_end", DEFAULT_SHIFT_END), DEFAULT_SHIFT_END),
                "grace_minutes": int(value.get("grace_minutes", DEFAULT_GRACE_MINUTES)),
                "allowed_break_minutes": int(value.get("allowed_break_minutes", DEFAULT_ALLOWED_BREAK_MINUTES))
            }
    return normalized


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_or_create_user_sheet(name):
    spreadsheet = get_spreadsheet()
    sheet_name = name.replace(" ", "_")
    try:
        ws = spreadsheet.worksheet(sheet_name)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=sheet_name, rows=1000, cols=8)
        ws.append_row(["Name", "Date", "Time", "Action", "Remarks", "Shift Start", "Shift End", "Timezone"])
    return ws


def ensure_sheet_headers(ws):
    expected_headers = ["Name", "Date", "Time", "Action", "Remarks", "Shift Start", "Shift End", "Timezone"]
    current_headers = ws.row_values(1)
    if current_headers[:len(expected_headers)] != expected_headers:
        ws.update("A1:H1", [expected_headers])


def fetch_history_from_sheet(name):
    ws = get_or_create_user_sheet(name)
    ensure_sheet_headers(ws)
    records = ws.get_all_values()
    history = []

    for row in records[1:]:
        history.append({
            "name": row[0] if len(row) > 0 else "",
            "date": row[1] if len(row) > 1 else "",
            "time": row[2] if len(row) > 2 else "",
            "action": row[3] if len(row) > 3 else "",
            "remarks": row[4] if len(row) > 4 else "",
            "shift_start": row[5] if len(row) > 5 else "",
            "shift_end": row[6] if len(row) > 6 else "",
            "timezone": row[7] if len(row) > 7 else ATTENDANCE_TIMEZONE
        })

    return history


def get_history(name, force_refresh=False):
    now_ts = datetime.datetime.now().timestamp()

    if not force_refresh and name in HISTORY_CACHE:
        cached = HISTORY_CACHE[name]
        if now_ts - cached["timestamp"] < CACHE_TTL_SECONDS:
            return cached["data"]

    history = fetch_history_from_sheet(name)
    HISTORY_CACHE[name] = {
        "timestamp": now_ts,
        "data": history
    }
    return history


def clear_employee_cache(name=None):
    if name is None:
        HISTORY_CACHE.clear()
    else:
        HISTORY_CACHE.pop(name, None)


def get_last_action(name):
    history = get_history(name)
    if history:
        return history[-1]["action"]
    return None


def get_today_history(name):
    today = today_et_str()
    history = get_history(name)
    return [item for item in history if item["date"] == today]


def has_action_today(name, action_name):
    today_history = get_today_history(name)
    return any(item["action"] == action_name for item in today_history)


def get_today_status(name):
    today_history = get_today_history(name)
    if today_history:
        return today_history[-1]
    return None


def get_today_timein_record(name):
    today_history = get_today_history(name)
    for item in today_history:
        if item["action"] == "Time In":
            return item
    return None


def get_user_schedule(name):
    users_data = normalize_users(load_users())
    user = users_data.get(name, {})
    return {
        "shift_start": parse_hhmm(user.get("shift_start", DEFAULT_SHIFT_START), DEFAULT_SHIFT_START),
        "shift_end": parse_hhmm(user.get("shift_end", DEFAULT_SHIFT_END), DEFAULT_SHIFT_END),
        "grace_minutes": int(user.get("grace_minutes", DEFAULT_GRACE_MINUTES)),
        "allowed_break_minutes": int(user.get("allowed_break_minutes", DEFAULT_ALLOWED_BREAK_MINUTES))
    }


def is_late_timein(now_value, username):
    schedule = get_user_schedule(username)
    shift_start = schedule["shift_start"]
    grace_minutes = schedule["grace_minutes"]

    shift_hour, shift_minute = map(int, shift_start.split(":"))
    shift_time = now_value.replace(
        hour=shift_hour,
        minute=shift_minute,
        second=0,
        microsecond=0
    )

    allowed_latest_time = shift_time + datetime.timedelta(minutes=grace_minutes)
    return now_value > allowed_latest_time


def get_attendance_remark(name):
    timein_record = get_today_timein_record(name)
    if not timein_record:
        return "No Time In Yet"
    return timein_record["remarks"] if timein_record["remarks"] else "On Time"


def is_action_allowed(last_action, new_action):
    if last_action is None:
        if new_action == "Time In":
            return True, ""
        return False, "First action must be Time In."

    rules = {
        "Time In": ["Break Start", "Time Out", "Overtime Start"],
        "Break Start": ["Break End"],
        "Break End": ["Break Start", "Time Out", "Overtime Start"],
        "Time Out": ["Overtime Start"],
        "Overtime Start": ["Overtime End"],
        "Overtime End": []
    }

    allowed_actions = rules.get(last_action, [])
    if new_action in allowed_actions:
        return True, ""

    return False, f"Action not allowed after '{last_action}'."


def is_duplicate_daily_action(name, action_name):
    one_time_daily_actions = ["Time In", "Time Out", "Overtime Start", "Overtime End"]
    return action_name in one_time_daily_actions and has_action_today(name, action_name)


def get_status_label(last_action):
    if last_action == "Time In":
        return "Timed In"
    if last_action == "Break Start":
        return "On Break"
    if last_action == "Break End":
        return "Back From Break"
    if last_action == "Time Out":
        return "Timed Out"
    if last_action == "Overtime Start":
        return "In Overtime"
    if last_action == "Overtime End":
        return "Overtime Finished"
    return "No Activity"


def calculate_employee_metrics(name):
    history = get_history(name)

    metrics = {
        "late_count": 0,
        "over_break_count": 0,
        "break_count": 0,
        "total_break_minutes": 0,
        "overtime_sessions": 0,
        "time_in_count": 0,
        "time_out_count": 0
    }

    schedule = get_user_schedule(name)
    allowed_break_minutes = schedule["allowed_break_minutes"]

    active_break_start = None

    for row in history:
        action = row["action"]

        if action == "Time In":
            metrics["time_in_count"] += 1
            if row["remarks"] == "Late":
                metrics["late_count"] += 1

        elif action == "Time Out":
            metrics["time_out_count"] += 1

        elif action == "Overtime Start":
            metrics["overtime_sessions"] += 1

        elif action == "Break Start":
            active_break_start = parse_sheet_datetime(row["date"], row["time"])

        elif action == "Break End":
            break_end_dt = parse_sheet_datetime(row["date"], row["time"])
            if active_break_start and break_end_dt:
                minutes = int((break_end_dt - active_break_start).total_seconds() // 60)
                if minutes < 0:
                    minutes = 0
                metrics["break_count"] += 1
                metrics["total_break_minutes"] += minutes
                if minutes > allowed_break_minutes:
                    metrics["over_break_count"] += 1
            active_break_start = None

    return metrics


users = normalize_users(load_users())
save_users(users)


@app.route("/", methods=["GET", "POST"])
def login():
    global users
    users = normalize_users(load_users())

    if request.method == "POST":
        session.clear()

        name = request.form["name"].strip()
        password = request.form["password"].strip()

        if name in users and users[name]["password"] == password:
            session["user"] = name
            if name == "Admin":
                return redirect("/admin")
            return redirect("/dashboard")

        flash("Invalid name or password.", "error")

    return render_template("login.html", company_name=COMPANY_NAME)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    if session["user"] == "Admin":
        return redirect("/admin")

    try:
        username = session["user"]
        users_data = normalize_users(load_users())
        history = get_history(username)
        last_action = get_last_action(username)
        today_status = get_today_status(username)
        profile_picture = users_data.get(username, {}).get("profile_picture", "")
        attendance_remark = get_attendance_remark(username)
        schedule = get_user_schedule(username)
        metrics = calculate_employee_metrics(username)

        return render_template(
            "dashboard.html",
            username=username,
            history=history,
            last_action=last_action,
            today_status=today_status,
            profile_picture=profile_picture,
            attendance_remark=attendance_remark,
            timezone_name=ATTENDANCE_TIMEZONE,
            current_et=now_et().strftime("%Y-%m-%d %I:%M:%S %p"),
            schedule=schedule,
            schedule_display_start=hhmm_to_display(schedule["shift_start"]),
            schedule_display_end=hhmm_to_display(schedule["shift_end"]),
            metrics=metrics,
            uploads_enabled=not is_render()
        )
    except Exception as e:
        flash(f"Google Sheets error: {e}", "error")
        fallback_schedule = get_user_schedule(session["user"])
        return render_template(
            "dashboard.html",
            username=session["user"],
            history=[],
            last_action=None,
            today_status=None,
            profile_picture="",
            attendance_remark="Unavailable",
            timezone_name=ATTENDANCE_TIMEZONE,
            current_et=now_et().strftime("%Y-%m-%d %I:%M:%S %p"),
            schedule=fallback_schedule,
            schedule_display_start=hhmm_to_display(fallback_schedule["shift_start"]),
            schedule_display_end=hhmm_to_display(fallback_schedule["shift_end"]),
            metrics={
                "late_count": 0,
                "over_break_count": 0,
                "break_count": 0,
                "total_break_minutes": 0,
                "overtime_sessions": 0,
                "time_in_count": 0,
                "time_out_count": 0
            },
            uploads_enabled=not is_render()
        )


@app.route("/upload_profile", methods=["POST"])
def upload_profile():
    if is_render():
        flash("Profile upload is disabled on live app.", "error")
        return redirect("/dashboard")

    if "user" not in session:
        return redirect("/")

    username = session["user"]

    if username == "Admin":
        return redirect("/admin")

    if "profile_picture" not in request.files:
        flash("No file selected.", "error")
        return redirect("/dashboard")

    file = request.files["profile_picture"]

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect("/dashboard")

    if not allowed_file(file.filename):
        flash("Invalid file type. Use png, jpg, jpeg, or gif.", "error")
        return redirect("/dashboard")

    filename = secure_filename(file.filename)
    extension = filename.rsplit(".", 1)[1].lower()
    timestamp = current_timestamp_for_filename()
    new_filename = f"{username.replace(' ', '_').lower()}_{timestamp}.{extension}"

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
    file.save(filepath)

    users_data = normalize_users(load_users())

    old_picture = users_data[username].get("profile_picture", "")
    if old_picture:
        old_path = os.path.join(app.config["UPLOAD_FOLDER"], old_picture)
        if os.path.exists(old_path):
            os.remove(old_path)

    users_data[username]["profile_picture"] = new_filename
    save_users(users_data)

    flash("Profile picture uploaded successfully.", "success")
    return redirect("/dashboard")


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    global users
    users = normalize_users(load_users())

    if "user" not in session or session["user"] != "Admin":
        return redirect("/")

    try:
        if request.method == "POST":
            action_type = request.form.get("form_type", "").strip()

            if action_type == "add_employee":
                new_name = request.form["name"].strip()
                new_password = request.form["password"].strip()
                shift_start = parse_hhmm(request.form.get("shift_start", DEFAULT_SHIFT_START), DEFAULT_SHIFT_START)
                shift_end = parse_hhmm(request.form.get("shift_end", DEFAULT_SHIFT_END), DEFAULT_SHIFT_END)

                try:
                    grace_minutes = int(request.form.get("grace_minutes", DEFAULT_GRACE_MINUTES))
                except ValueError:
                    grace_minutes = DEFAULT_GRACE_MINUTES

                try:
                    allowed_break_minutes = int(request.form.get("allowed_break_minutes", DEFAULT_ALLOWED_BREAK_MINUTES))
                except ValueError:
                    allowed_break_minutes = DEFAULT_ALLOWED_BREAK_MINUTES

                if not new_name or not new_password:
                    flash("Please fill in both name and password.", "error")
                elif new_name in users:
                    flash("Employee already exists.", "error")
                else:
                    users[new_name] = {
                        "password": new_password,
                        "profile_picture": "",
                        "shift_start": shift_start,
                        "shift_end": shift_end,
                        "grace_minutes": grace_minutes,
                        "allowed_break_minutes": allowed_break_minutes
                    }
                    save_users(users)
                    clear_employee_cache(new_name)
                    get_or_create_user_sheet(new_name)
                    flash(f"Employee '{new_name}' added successfully.", "success")
                    return redirect("/admin")

            elif action_type == "update_schedule":
                employee_name = request.form["employee_name"].strip()

                if employee_name in users and employee_name != "Admin":
                    users[employee_name]["shift_start"] = parse_hhmm(
                        request.form.get("shift_start", DEFAULT_SHIFT_START),
                        DEFAULT_SHIFT_START
                    )
                    users[employee_name]["shift_end"] = parse_hhmm(
                        request.form.get("shift_end", DEFAULT_SHIFT_END),
                        DEFAULT_SHIFT_END
                    )

                    try:
                        users[employee_name]["grace_minutes"] = int(
                            request.form.get("grace_minutes", DEFAULT_GRACE_MINUTES)
                        )
                    except ValueError:
                        users[employee_name]["grace_minutes"] = DEFAULT_GRACE_MINUTES

                    try:
                        users[employee_name]["allowed_break_minutes"] = int(
                            request.form.get("allowed_break_minutes", DEFAULT_ALLOWED_BREAK_MINUTES)
                        )
                    except ValueError:
                        users[employee_name]["allowed_break_minutes"] = DEFAULT_ALLOWED_BREAK_MINUTES

                    save_users(users)
                    clear_employee_cache(employee_name)
                    flash(f"Schedule updated for {employee_name}.", "success")
                    return redirect("/admin")
                else:
                    flash("Employee not found.", "error")

        # ===============================
        # DASHBOARD DATA (OPTIMIZED)
        # ===============================

        employee_cards = []
        chart_labels = []
        late_chart_data = []
        over_break_chart_data = []
        break_minutes_chart_data = []

        total_employees = 0
        timed_in_count = 0
        on_break_count = 0
        timed_out_count = 0
        overtime_count = 0
        no_timein_yet_count = 0
        late_count = 0
        total_over_break = 0
        total_breaks = 0

        today = today_et_str()

        for name, info in users.items():
            if name == "Admin":
                continue

            total_employees += 1

            # 🔥 ONLY ONE GOOGLE SHEETS READ PER EMPLOYEE
            history = get_history(name)

            today_history = [h for h in history if h["date"] == today]
            last_action = today_history[-1]["action"] if today_history else None

            attendance_remark = "No Time In Yet"
            for item in today_history:
                if item["action"] == "Time In":
                    attendance_remark = item["remarks"] or "On Time"
                    break

            schedule = get_user_schedule(name)
            allowed_break_minutes = schedule["allowed_break_minutes"]

            metrics = {
                "late_count": 0,
                "over_break_count": 0,
                "break_count": 0,
                "total_break_minutes": 0,
                "overtime_sessions": 0,
                "time_in_count": 0,
                "time_out_count": 0
            }

            active_break_start = None

            for row in history:
                action = row["action"]

                if action == "Time In":
                    metrics["time_in_count"] += 1
                    if row["remarks"] == "Late":
                        metrics["late_count"] += 1

                elif action == "Time Out":
                    metrics["time_out_count"] += 1

                elif action == "Overtime Start":
                    metrics["overtime_sessions"] += 1

                elif action == "Break Start":
                    active_break_start = parse_sheet_datetime(row["date"], row["time"])

                elif action == "Break End":
                    break_end = parse_sheet_datetime(row["date"], row["time"])
                    if active_break_start and break_end:
                        minutes = int((break_end - active_break_start).total_seconds() // 60)
                        if minutes < 0:
                            minutes = 0
                        metrics["break_count"] += 1
                        metrics["total_break_minutes"] += minutes
                        if minutes > allowed_break_minutes:
                            metrics["over_break_count"] += 1
                    active_break_start = None

            status = get_status_label(last_action)
            timed_in_today = any(h["action"] == "Time In" for h in today_history)

            if status == "Timed In":
                timed_in_count += 1
            if status == "On Break":
                on_break_count += 1
            if status == "Timed Out":
                timed_out_count += 1
            if status == "In Overtime":
                overtime_count += 1
            if not timed_in_today:
                no_timein_yet_count += 1
            if attendance_remark == "Late":
                late_count += 1

            total_over_break += metrics["over_break_count"]
            total_breaks += metrics["break_count"]

            employee_cards.append({
                "name": name,
                "status": status,
                "profile_picture": info.get("profile_picture", ""),
                "attendance_remark": attendance_remark,
                "shift_start": info.get("shift_start"),
                "shift_end": info.get("shift_end"),
                "grace_minutes": info.get("grace_minutes"),
                "allowed_break_minutes": info.get("allowed_break_minutes"),
                "metrics": metrics
            })

            chart_labels.append(name)
            late_chart_data.append(metrics["late_count"])
            over_break_chart_data.append(metrics["over_break_count"])
            break_minutes_chart_data.append(metrics["total_break_minutes"])

        return render_template(
            "admin.html",
            employees=employee_cards,
            total_employees=total_employees,
            timed_in_count=timed_in_count,
            on_break_count=on_break_count,
            timed_out_count=timed_out_count,
            overtime_count=overtime_count,
            no_timein_yet_count=no_timein_yet_count,
            late_count=late_count,
            total_over_break=total_over_break,
            total_breaks=total_breaks,
            timezone_name=ATTENDANCE_TIMEZONE,
            current_et=now_et().strftime("%Y-%m-%d %I:%M:%S %p"),
            chart_labels=chart_labels,
            late_chart_data=late_chart_data,
            over_break_chart_data=over_break_chart_data,
            break_minutes_chart_data=break_minutes_chart_data
        )

    except Exception as e:
        flash(f"Google Sheets error: {e}", "error")
        return render_template(
            "admin.html",
            employees=[],
            total_employees=0,
            timed_in_count=0,
            on_break_count=0,
            timed_out_count=0,
            overtime_count=0,
            no_timein_yet_count=0,
            late_count=0,
            total_over_break=0,
            total_breaks=0,
            timezone_name=ATTENDANCE_TIMEZONE,
            current_et=now_et().strftime("%Y-%m-%d %I:%M:%S %p"),
            chart_labels=[],
            late_chart_data=[],
            over_break_chart_data=[],
            break_minutes_chart_data=[]
        )

@app.route("/reset_password/<name>")
def reset_password(name):
    if "user" not in session or session["user"] != "Admin":
        return redirect("/")

    users_data = normalize_users(load_users())

    if name in users_data:
        users_data[name]["password"] = "1234"
        save_users(users_data)
        flash(f"{name}'s password reset to 1234.", "success")
    else:
        flash("Employee not found.", "error")

    return redirect("/admin#employees")


@app.route("/delete_employee/<name>")
def delete_employee(name):
    if "user" not in session or session["user"] != "Admin":
        return redirect("/")

    users_data = normalize_users(load_users())

    if name in users_data:
        if name == "Admin":
            flash("Admin account cannot be deleted.", "error")
            return redirect("/admin#employees")

        profile_picture = users_data[name].get("profile_picture", "")
        if profile_picture:
            profile_path = os.path.join(app.config["UPLOAD_FOLDER"], profile_picture)
            if os.path.exists(profile_path):
                os.remove(profile_path)

        del users_data[name]
        clear_employee_cache(name)
        save_users(users_data)
        flash(f"{name} deleted successfully.", "success")
    else:
        flash("Employee not found.", "error")

    return redirect("/admin#employees")


@app.route("/record/<action>")
def record(action):
    if "user" not in session:
        return redirect("/")

    username = session["user"]
    if username == "Admin":
        return redirect("/admin")

    action_map = {
        "timein": "Time In",
        "timeout": "Time Out",
        "breakstart": "Break Start",
        "breakend": "Break End",
        "overtimestart": "Overtime Start",
        "overtimeend": "Overtime End"
    }

    if action not in action_map:
        flash("Invalid action.", "error")
        return redirect("/dashboard")

    final_action = action_map[action]

    try:
        if is_duplicate_daily_action(username, final_action):
            flash(f"{final_action} has already been recorded today.", "error")
            return redirect("/dashboard")

        last_action = get_last_action(username)
        allowed, message = is_action_allowed(last_action, final_action)

        if not allowed:
            flash(message, "error")
            return redirect("/dashboard")

        now_value = now_et()
        date = now_value.strftime("%Y-%m-%d")
        time = now_value.strftime("%I:%M:%S %p")
        remarks = ""

        schedule = get_user_schedule(username)

        if final_action == "Time In":
            remarks = "Late" if is_late_timein(now_value, username) else "On Time"

        ws = get_or_create_user_sheet(username)
        ensure_sheet_headers(ws)
        ws.append_row([
            username,
            date,
            time,
            final_action,
            remarks,
            schedule["shift_start"],
            schedule["shift_end"],
            ATTENDANCE_TIMEZONE
        ])

        clear_employee_cache(username)

        if remarks:
            flash(f"{final_action} recorded successfully. Status: {remarks}", "success")
        else:
            flash(f"{final_action} recorded successfully.", "success")

    except Exception as e:
        flash(f"Failed to record attendance: {e}", "error")

    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)