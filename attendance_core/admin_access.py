from attendance_core.config import (
    ADMIN_PERMISSION_CODES,
    ADMIN_PERMISSION_LABELS,
    ADMIN_PERMISSION_OPTIONS,
    ADMIN_ROLE_PRESETS,
)


def normalize_admin_permissions(values):
    if isinstance(values, str):
        raw_values = values.split(",")
    else:
        raw_values = values or []
    cleaned = []
    seen = set()
    for raw_value in raw_values:
        code = str(raw_value or "").strip().lower()
        if code not in ADMIN_PERMISSION_CODES or code in seen:
            continue
        seen.add(code)
        cleaned.append(code)
    return ",".join(cleaned)


def row_get(row, key, default=None):
    if row is None:
        return default
    if hasattr(row, "get"):
        return row.get(key, default)
    try:
        if hasattr(row, "keys"):
            return row[key] if key in row.keys() else default
        return row[key]
    except Exception:
        return default


def normalize_admin_role_preset(value):
    code = str(value or "").strip().lower()
    return code if code in ADMIN_ROLE_PRESETS else ""


def infer_admin_role_preset(permission_values):
    if isinstance(permission_values, str):
        normalized_codes = set(normalize_admin_permissions(permission_values).split(",")) if permission_values else set()
    else:
        normalized_codes = set()
        for code in permission_values or []:
            normalized = str(code or "").strip().lower()
            if normalized in ADMIN_PERMISSION_CODES:
                normalized_codes.add(normalized)
    for preset_code, preset in ADMIN_ROLE_PRESETS.items():
        if set(preset["permissions"]) == normalized_codes:
            return preset_code
    return ""


def sync_admin_role_preset(role_preset, permissions_csv):
    normalized_role_preset = normalize_admin_role_preset(role_preset)
    normalized_permissions = normalize_admin_permissions(permissions_csv)
    if normalized_role_preset and set(ADMIN_ROLE_PRESETS[normalized_role_preset]["permissions"]) == set(
        part for part in normalized_permissions.split(",") if part
    ):
        return normalized_role_preset, normalized_permissions
    inferred_preset = infer_admin_role_preset(normalized_permissions)
    return inferred_preset, normalized_permissions


def get_admin_permission_codes(user_row):
    if not user_row or row_get(user_row, "role") != "admin":
        return set()
    raw_permissions = (row_get(user_row, "admin_permissions") or "").strip()
    if not raw_permissions:
        return set(ADMIN_PERMISSION_CODES)
    return set(part for part in raw_permissions.split(",") if part in ADMIN_PERMISSION_CODES)


def admin_has_permission(user_row, permission_code):
    if permission_code not in ADMIN_PERMISSION_CODES:
        return True
    return permission_code in get_admin_permission_codes(user_row)


def describe_admin_permissions(user_row):
    codes = get_admin_permission_codes(user_row)
    if not codes:
        return "No Access"
    if codes == ADMIN_PERMISSION_CODES:
        return "Full Access"
    return ", ".join(ADMIN_PERMISSION_LABELS[code] for code, _ in ADMIN_PERMISSION_OPTIONS if code in codes)


def get_admin_role_preset_meta(user_row=None, preset_code=None, permission_values=None):
    if user_row:
        raw_permissions = ""
        if hasattr(user_row, "get"):
            raw_permissions = (user_row.get("admin_permissions") or "").strip()
            if not raw_permissions and user_row.get("role") == "admin":
                return dict(ADMIN_ROLE_PRESETS["full_admin"])
        elif hasattr(user_row, "keys") and "admin_permissions" in user_row.keys():
            raw_permissions = (user_row["admin_permissions"] or "").strip()
            if not raw_permissions and "role" in user_row.keys() and user_row["role"] == "admin":
                return dict(ADMIN_ROLE_PRESETS["full_admin"])
    resolved_preset = normalize_admin_role_preset(
        preset_code if preset_code is not None else (
            user_row.get("admin_role_preset") if user_row and hasattr(user_row, "get") else (
                user_row["admin_role_preset"] if user_row and hasattr(user_row, "keys") and "admin_role_preset" in user_row.keys() else ""
            )
        )
    )
    if not resolved_preset:
        permission_source = permission_values
        if permission_source is None and user_row:
            permission_source = user_row.get("admin_permissions") if hasattr(user_row, "get") else user_row["admin_permissions"]
        resolved_preset = infer_admin_role_preset(permission_source or "")
    if resolved_preset:
        return dict(ADMIN_ROLE_PRESETS[resolved_preset])
    if permission_values is None and user_row:
        if hasattr(user_row, "get"):
            permission_values = user_row.get("admin_permissions")
        elif hasattr(user_row, "keys") and "admin_permissions" in user_row.keys():
            permission_values = user_row["admin_permissions"]
    return {
        "code": "",
        "label": "Custom Access",
        "description": "A custom mix of permissions that does not match a saved preset exactly.",
        "permissions": tuple(part for part in normalize_admin_permissions(permission_values or "").split(",") if part),
    }


def get_admin_home_endpoint(user_row):
    for permission_code, endpoint_name in [
        ("dashboard", "admin_dashboard"),
        ("employees", "manage_employees"),
        ("attendance", "admin_corrections"),
        ("workflows", "admin_leave_dashboard"),
        ("payroll", "admin_payroll"),
        ("reports", "admin_reports"),
        ("settings", "admin_profile"),
    ]:
        if admin_has_permission(user_row, permission_code):
            return endpoint_name
    return "logout"


def get_home_endpoint_for_role(role_name):
    if role_name == "admin":
        return "admin_dashboard"
    if role_name == "scanner":
        return "scanner_kiosk"
    return "dashboard"


def get_home_endpoint_for_user(user_row):
    if not user_row:
        return "login"
    role_name = row_get(user_row, "role")
    if role_name == "admin":
        endpoint_name = get_admin_home_endpoint(user_row)
        if endpoint_name == "logout":
            return "login"
        return endpoint_name
    return get_home_endpoint_for_role(role_name)


ADMIN_ENDPOINT_PERMISSIONS = {
    "admin_dashboard": "dashboard",
    "admin_live_status": "dashboard",
    "export_admin_exceptions_excel": "dashboard",
    "send_admin_notification": "settings",
    "manage_employees": "employees",
    "edit_employee": "employees",
    "print_employee_id": "employees",
    "delete_employee": "employees",
    "delete_future_schedule_change": "employees",
    "admin_corrections": "attendance",
    "update_correction_request": "attendance",
    "admin_history": "attendance",
    "export_admin_history_excel": "attendance",
    "admin_attendance_audit": "attendance",
    "admin_scanner_logs": "attendance",
    "scanner_kiosk_unlock": "attendance",
    "scanner_kiosk_scan": "attendance",
    "admin_leave_dashboard": "workflows",
    "export_admin_leave_dashboard_excel": "workflows",
    "admin_error_reports": "workflows",
    "export_admin_error_reports_excel": "workflows",
    "admin_disciplinary_dashboard": "workflows",
    "export_admin_disciplinary_excel": "workflows",
    "admin_incident_report": "workflows",
    "create_incident_route": "workflows",
    "create_disciplinary_action_route": "workflows",
    "update_disciplinary_action_route": "workflows",
    "delete_disciplinary_action_route": "workflows",
    "update_incident_report": "workflows",
    "edit_incident_report": "workflows",
    "delete_incident_report": "workflows",
    "admin_payroll": "payroll",
    "add_payroll_adjustment": "payroll",
    "delete_payroll_adjustment": "payroll",
    "save_payroll_recurring_rule": "payroll",
    "toggle_payroll_recurring_rule": "payroll",
    "delete_payroll_recurring_rule": "payroll",
    "save_payroll_run": "payroll",
    "delete_payroll_run": "payroll",
    "bulk_release_payroll_runs": "payroll",
    "admin_payroll_download_requests_panel": "payroll",
    "review_payslip_download_request_route": "payroll",
    "export_admin_payroll_excel": "payroll",
    "print_admin_payroll": "payroll",
    "admin_reports": "reports",
    "export_admin_reports_excel": "reports",
    "admin_data_tools": "settings",
    "download_recovery_pack": "settings",
    "update_employee_id_signatory": "settings",
}
