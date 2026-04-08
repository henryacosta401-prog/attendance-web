from datetime import datetime, timedelta

from attendance_core.config import (
    APP_TIMEZONE,
    BREAK_LIMIT_MINUTES,
    DEFAULT_SCHEDULE_DAYS,
    DEFAULT_SHIFT_END,
    DEFAULT_SHIFT_START,
    WEEKDAY_OPTIONS,
)


def normalize_history_reference(reference_datetime=None, reference_date=""):
    if isinstance(reference_datetime, datetime):
        return reference_datetime.strftime("%Y-%m-%d %H:%M:%S")
    raw_datetime = str(reference_datetime or "").strip()
    if raw_datetime:
        return raw_datetime[:19] if len(raw_datetime) >= 19 else f"{raw_datetime} 23:59:59"
    raw_date = str(reference_date or "").strip()
    if raw_date:
        return f"{raw_date} 23:59:59"
    return datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")


def get_attendance_reference_datetime(attendance_row):
    if not attendance_row:
        return datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    if hasattr(attendance_row, "get"):
        return (
            attendance_row.get("time_in")
            or attendance_row.get("created_at")
            or normalize_history_reference(reference_date=attendance_row.get("work_date"))
        )
    return (
        attendance_row["time_in"]
        or attendance_row["created_at"]
        or normalize_history_reference(reference_date=attendance_row["work_date"])
    )


def get_overtime_reference_datetime(overtime_row):
    if not overtime_row:
        return datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    if hasattr(overtime_row, "get"):
        return (
            overtime_row.get("overtime_start")
            or overtime_row.get("created_at")
            or normalize_history_reference(reference_date=overtime_row.get("work_date"))
        )
    return (
        overtime_row["overtime_start"]
        or overtime_row["created_at"]
        or normalize_history_reference(reference_date=overtime_row["work_date"])
    )


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


def get_schedule_code_for_date(date_str):
    try:
        parsed = datetime.strptime(date_str, "%Y-%m-%d")
        return WEEKDAY_OPTIONS[parsed.weekday()][0]
    except Exception:
        return ""


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
