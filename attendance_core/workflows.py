from datetime import datetime, timedelta

from attendance_core.attendance import combine_work_date_and_time
from attendance_core.config import LEAVE_REQUEST_TYPES, SCHEDULE_SPECIAL_RULE_LABELS
from attendance_core.date_ranges import parse_iso_date


def calculate_suspension_end_date(action_date, duration_days):
    try:
        start_date = datetime.strptime(action_date, "%Y-%m-%d").date()
    except Exception:
        return ""
    total_days = max(int(duration_days or 1), 1)
    return (start_date + timedelta(days=total_days - 1)).strftime("%Y-%m-%d")


def normalize_schedule_special_rule_type(rule_type):
    raw_value = (rule_type or "").strip().lower()
    return raw_value if raw_value in SCHEDULE_SPECIAL_RULE_LABELS else "holiday"


def build_schedule_special_rule_label(rule_type, custom_label=""):
    default_label = SCHEDULE_SPECIAL_RULE_LABELS[normalize_schedule_special_rule_type(rule_type)]
    custom_text = (custom_label or "").strip()
    return custom_text or default_label


def schedule_preset_matches_department(preset, department_name):
    if not preset:
        return True
    if hasattr(preset, "get"):
        scope = (preset.get("department_scope") or "").strip().lower()
    else:
        scope = str(preset["department_scope"] or "").strip().lower()
    if not scope:
        return True
    return scope == (department_name or "").strip().lower()


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
    use_existing_values=True,
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


def format_request_date_range(work_date, end_work_date=""):
    start_str, end_str = normalize_request_date_range(work_date, end_work_date)
    return start_str if start_str == end_str else f"{start_str} to {end_str}"


def expand_suspension_dates(row):
    if not row:
        return []
    row = dict(row)
    if row.get("action_type") != "Suspension":
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
