from datetime import datetime, timedelta

from attendance_core.config import (
    APP_TIMEZONE,
    BREAK_LIMIT_MINUTES,
    DEFAULT_SCHEDULE_DAYS,
    DEFAULT_SHIFT_END,
    DEFAULT_SHIFT_START,
    LATE_GRACE_MINUTES,
    OVERTIME_BREAK_BONUS_MINUTES_PER_HOUR,
    TARDINESS_POLICY_STEP_ONE_BREAK_DEDUCTION_MINUTES,
    TARDINESS_POLICY_STEP_ONE_MAX_MINUTES,
    TARDINESS_POLICY_STEP_ONE_SHIFT_DEDUCTION_MINUTES,
    TARDINESS_POLICY_STEP_THREE_MAX_MINUTES,
    TARDINESS_POLICY_STEP_THREE_SHIFT_DEDUCTION_MINUTES,
    TARDINESS_POLICY_STEP_TWO_MAX_MINUTES,
    TARDINESS_POLICY_STEP_TWO_SHIFT_DEDUCTION_MINUTES,
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


def parse_non_negative_minutes(value, fallback=0):
    try:
        minutes = int(str(value).strip())
        return minutes if minutes >= 0 else fallback
    except Exception:
        return fallback


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


def get_effective_break_limit_minutes(record_row=None, fallback_break_limit_minutes=BREAK_LIMIT_MINUTES):
    fallback_limit = parse_non_negative_minutes(fallback_break_limit_minutes, fallback=BREAK_LIMIT_MINUTES)
    if record_row and hasattr(record_row, "get"):
        override_limit = record_row.get("effective_break_limit_minutes")
        if override_limit is not None:
            return parse_non_negative_minutes(override_limit, fallback=fallback_limit)
    return fallback_limit


def get_overtime_break_bonus_minutes(
    overtime_minutes,
    minutes_per_hour=OVERTIME_BREAK_BONUS_MINUTES_PER_HOUR,
):
    total_overtime_minutes = parse_non_negative_minutes(overtime_minutes, fallback=0)
    bonus_minutes_per_hour = parse_non_negative_minutes(minutes_per_hour, fallback=0)
    if total_overtime_minutes < 60 or bonus_minutes_per_hour <= 0:
        return 0
    return (total_overtime_minutes // 60) * bonus_minutes_per_hour


def get_break_limit_with_overtime_bonus(
    base_break_limit_minutes,
    overtime_minutes,
    minutes_per_hour=OVERTIME_BREAK_BONUS_MINUTES_PER_HOUR,
):
    base_break_limit = parse_non_negative_minutes(base_break_limit_minutes, fallback=BREAK_LIMIT_MINUTES)
    if base_break_limit <= 0:
        return 0
    return base_break_limit + get_overtime_break_bonus_minutes(
        overtime_minutes,
        minutes_per_hour=minutes_per_hour,
    )


def get_tardiness_policy_adjustment(
    time_in_str,
    shift_start,
    base_break_limit_minutes=BREAK_LIMIT_MINUTES,
    policy_enabled=False,
):
    base_break_limit = parse_non_negative_minutes(base_break_limit_minutes, fallback=BREAK_LIMIT_MINUTES)
    late_flag, late_minutes = calculate_late_info(time_in_str, shift_start)
    result = {
        "actual_time_in": time_in_str,
        "recorded_time_in": time_in_str,
        "late_flag": late_flag,
        "late_minutes": late_minutes,
        "effective_break_limit_minutes": base_break_limit,
        "policy_applied": 0,
        "policy_deduction_minutes": 0,
        "no_breaks_allowed": 0,
    }
    if not policy_enabled or not late_flag or not time_in_str:
        return result

    time_in_dt = datetime.strptime(time_in_str, "%Y-%m-%d %H:%M:%S")
    shift_dt = datetime.strptime(
        f"{time_in_dt.strftime('%Y-%m-%d')} {parse_shift_start(shift_start)}:00",
        "%Y-%m-%d %H:%M:%S"
    )

    if late_minutes <= TARDINESS_POLICY_STEP_ONE_MAX_MINUTES:
        minimum_recorded_dt = shift_dt + timedelta(minutes=TARDINESS_POLICY_STEP_ONE_SHIFT_DEDUCTION_MINUTES)
        effective_break_limit_minutes = max(
            base_break_limit - TARDINESS_POLICY_STEP_ONE_BREAK_DEDUCTION_MINUTES,
            0,
        )
        no_breaks_allowed = 0
    elif late_minutes <= TARDINESS_POLICY_STEP_TWO_MAX_MINUTES:
        minimum_recorded_dt = shift_dt + timedelta(minutes=TARDINESS_POLICY_STEP_TWO_SHIFT_DEDUCTION_MINUTES)
        effective_break_limit_minutes = 0
        no_breaks_allowed = 1
    elif late_minutes <= TARDINESS_POLICY_STEP_THREE_MAX_MINUTES:
        minimum_recorded_dt = shift_dt + timedelta(minutes=TARDINESS_POLICY_STEP_THREE_SHIFT_DEDUCTION_MINUTES)
        effective_break_limit_minutes = 0
        no_breaks_allowed = 1
    else:
        minimum_recorded_dt = shift_dt + timedelta(minutes=TARDINESS_POLICY_STEP_THREE_SHIFT_DEDUCTION_MINUTES)
        effective_break_limit_minutes = 0
        no_breaks_allowed = 1

    recorded_dt = max(time_in_dt, minimum_recorded_dt)
    result["recorded_time_in"] = recorded_dt.strftime("%Y-%m-%d %H:%M:%S")
    result["effective_break_limit_minutes"] = effective_break_limit_minutes
    result["policy_applied"] = 1 if result["recorded_time_in"] != time_in_str or effective_break_limit_minutes != base_break_limit else 0
    result["policy_deduction_minutes"] = max(int((recorded_dt - shift_dt).total_seconds() // 60), 0)
    result["no_breaks_allowed"] = no_breaks_allowed
    return result


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
    limit_minutes = parse_non_negative_minutes(break_limit_minutes, fallback=BREAK_LIMIT_MINUTES)
    return max(parse_non_negative_minutes(break_minutes, fallback=0) - limit_minutes, 0)


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
