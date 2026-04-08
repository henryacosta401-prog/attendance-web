from datetime import datetime, timedelta

from attendance_core.config import APP_TIMEZONE


def parse_iso_date(value, fallback=None):
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except Exception:
        return fallback


def get_admin_report_period_dates(period_value="", date_from_value="", date_to_value="", today=None):
    today = today or datetime.now(APP_TIMEZONE).date()
    selected_period = (period_value or "").strip().lower()
    if selected_period == "last_month":
        first_this_month = today.replace(day=1)
        date_to = first_this_month - timedelta(days=1)
        date_from = date_to.replace(day=1)
    elif selected_period == "last_14_days":
        date_from = today - timedelta(days=13)
        date_to = today
    elif selected_period == "custom":
        default_from = today.replace(day=1)
        date_from = parse_iso_date(date_from_value, default_from)
        date_to = parse_iso_date(date_to_value, today)
    else:
        selected_period = "this_month"
        date_from = today.replace(day=1)
        date_to = today
    if date_to < date_from:
        date_from, date_to = date_to, date_from
    return selected_period, date_from, date_to


def normalize_admin_report_filters(date_from_value="", date_to_value="", department_filter="", period_value="", today=None):
    selected_period, date_from, date_to = get_admin_report_period_dates(
        period_value,
        date_from_value,
        date_to_value,
        today=today
    )
    period_label_map = {
        "this_month": "This Month",
        "last_14_days": "Last 14 Days",
        "last_month": "Last Month",
        "custom": "Custom Range",
    }
    return {
        "period": selected_period,
        "period_label": period_label_map.get(selected_period, "Custom Range"),
        "date_from": date_from,
        "date_to": date_to,
        "date_from_text": date_from.strftime("%Y-%m-%d"),
        "date_to_text": date_to.strftime("%Y-%m-%d"),
        "range_days": max((date_to - date_from).days + 1, 1),
        "department_filter": (department_filter or "").strip(),
    }


def get_payroll_period_dates(period, date_from_value="", date_to_value="", today=None):
    today = today or datetime.now(APP_TIMEZONE).date()
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


def payroll_date_text(value):
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")
    return str(value or "").strip()
