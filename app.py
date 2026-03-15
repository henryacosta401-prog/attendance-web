from flask import Flask, render_template, request, redirect, session, flash, send_from_directory
import json
import os
import datetime
import gspread
from google.oauth2.service_account import Credentials
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "attendance_secret"

USERS_FILE = "users.json"
SPREADSHEET_URL = "https://docs.google.com/spreadsheets/d/1j6TLjNOSifsVxHFHyLVvevyqyOza1RUq0-dt2dWcQ5g/edit"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

SHIFT_START_HOUR = 9
SHIFT_START_MINUTE = 0

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_google_credentials():
    if "GOOGLE_CREDENTIALS" in os.environ:
        google_creds = json.loads(os.environ["GOOGLE_CREDENTIALS"])
        return Credentials.from_service_account_info(
            google_creds,
            scopes=SCOPES
        )

    return Credentials.from_service_account_file(
    "attendanceapp-490202-b94b8f64d45f.json",
    scopes=SCOPES
)


creds = get_google_credentials()
gc = gspread.authorize(creds)
spreadsheet = gc.open_by_url(SPREADSHEET_URL)


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    return {
        "Henry": {
            "password": "1234",
            "profile_picture": ""
        },
        "Admin": {
            "password": "admin123",
            "profile_picture": ""
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
                "profile_picture": ""
            }
        else:
            normalized[name] = {
                "password": value.get("password", ""),
                "profile_picture": value.get("profile_picture", "")
            }
    return normalized


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_or_create_user_sheet(name):
    sheet_name = name.replace(" ", "_")
    try:
        ws = spreadsheet.worksheet(sheet_name)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=sheet_name, rows=1000, cols=5)
        ws.append_row(["Name", "Date", "Time", "Action", "Remarks"])
    return ws


def get_history(name):
    ws = get_or_create_user_sheet(name)
    records = ws.get_all_values()
    history = []

    for row in records[1:]:
        history.append({
            "name": row[0] if len(row) > 0 else "",
            "date": row[1] if len(row) > 1 else "",
            "time": row[2] if len(row) > 2 else "",
            "action": row[3] if len(row) > 3 else "",
            "remarks": row[4] if len(row) > 4 else ""
        })

    return history


def get_last_action(name):
    history = get_history(name)
    if history:
        return history[-1]["action"]
    return None


def get_today_history(name):
    today = datetime.datetime.now().strftime("%Y-%m-%d")
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


def is_late_timein(now):
    shift_time = now.replace(
        hour=SHIFT_START_HOUR,
        minute=SHIFT_START_MINUTE,
        second=0,
        microsecond=0
    )
    return now > shift_time


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

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    if session["user"] == "Admin":
        return redirect("/admin")

    username = session["user"]
    users_data = normalize_users(load_users())
    history = get_history(username)
    last_action = get_last_action(username)
    today_status = get_today_status(username)
    profile_picture = users_data.get(username, {}).get("profile_picture", "")
    attendance_remark = get_attendance_remark(username)

    return render_template(
        "dashboard.html",
        username=username,
        history=history,
        last_action=last_action,
        today_status=today_status,
        profile_picture=profile_picture,
        attendance_remark=attendance_remark
    )


@app.route("/upload_profile", methods=["POST"])
def upload_profile():
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

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        extension = filename.rsplit(".", 1)[1].lower()
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
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

    flash("Invalid file type. Use png, jpg, jpeg, or gif.", "error")
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

    if request.method == "POST":
        new_name = request.form["name"].strip()
        new_password = request.form["password"].strip()

        if not new_name or not new_password:
            flash("Please fill in both name and password.", "error")
        elif new_name in users:
            flash("Employee already exists.", "error")
        else:
            users[new_name] = {
                "password": new_password,
                "profile_picture": ""
            }
            save_users(users)
            get_or_create_user_sheet(new_name)
            flash(f"Employee '{new_name}' added successfully.", "success")

    employee_cards = []
    for name, info in users.items():
        if name == "Admin":
            continue

        today_history = get_today_history(name)
        last_action = today_history[-1]["action"] if today_history else None
        today_status = today_history[-1] if today_history else None
        attendance_remark = get_attendance_remark(name)

        employee_cards.append({
            "name": name,
            "status": get_status_label(last_action),
            "today_status": today_status,
            "profile_picture": info.get("profile_picture", ""),
            "timed_in_today": has_action_today(name, "Time In"),
            "attendance_remark": attendance_remark
        })

    total_employees = len(employee_cards)
    timed_in_count = sum(1 for emp in employee_cards if emp["status"] == "Timed In")
    on_break_count = sum(1 for emp in employee_cards if emp["status"] == "On Break")
    timed_out_count = sum(1 for emp in employee_cards if emp["status"] == "Timed Out")
    overtime_count = sum(1 for emp in employee_cards if emp["status"] == "In Overtime")
    no_timein_yet_count = sum(1 for emp in employee_cards if not emp["timed_in_today"])
    late_count = sum(1 for emp in employee_cards if emp["attendance_remark"] == "Late")

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
        shift_start=f"{SHIFT_START_HOUR:02d}:{SHIFT_START_MINUTE:02d}"
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

    return redirect("/admin")


@app.route("/delete_employee/<name>")
def delete_employee(name):
    if "user" not in session or session["user"] != "Admin":
        return redirect("/")

    users_data = normalize_users(load_users())

    if name in users_data:
        if name == "Admin":
            flash("Admin account cannot be deleted.", "error")
            return redirect("/admin")

        profile_picture = users_data[name].get("profile_picture", "")
        if profile_picture:
            profile_path = os.path.join(app.config["UPLOAD_FOLDER"], profile_picture)
            if os.path.exists(profile_path):
                os.remove(profile_path)

        del users_data[name]
        save_users(users_data)
        flash(f"{name} deleted successfully.", "success")
    else:
        flash("Employee not found.", "error")

    return redirect("/admin")


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

    if is_duplicate_daily_action(username, final_action):
        flash(f"{final_action} has already been recorded today.", "error")
        return redirect("/dashboard")

    last_action = get_last_action(username)
    allowed, message = is_action_allowed(last_action, final_action)

    if not allowed:
        flash(message, "error")
        return redirect("/dashboard")

    now = datetime.datetime.now()
    date = now.strftime("%Y-%m-%d")
    time = now.strftime("%I:%M:%S %p")
    remarks = ""

    if final_action == "Time In":
        remarks = "Late" if is_late_timein(now) else "On Time"

    ws = get_or_create_user_sheet(username)
    ws.append_row([username, date, time, final_action, remarks])

    if remarks:
        flash(f"{final_action} recorded successfully. Status: {remarks}", "success")
    else:
        flash(f"{final_action} recorded successfully.", "success")

    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)