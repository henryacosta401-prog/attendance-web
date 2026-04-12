EMPLOYEE_CODE_PREFIX = "ID-"


def normalize_employee_code(raw_value):
    cleaned = "".join(str(raw_value or "").strip().upper().split())
    return cleaned


def build_default_employee_code(user_id):
    try:
        numeric_id = int(user_id or 0)
    except Exception:
        numeric_id = 0
    return f"{EMPLOYEE_CODE_PREFIX}{numeric_id:04d}"


def get_employee_card_number(user_row):
    if not user_row:
        return ""

    try:
        if "employee_code" in user_row.keys():
            employee_code = normalize_employee_code(user_row["employee_code"])
            if employee_code:
                return employee_code
    except Exception:
        employee_code = normalize_employee_code(getattr(user_row, "employee_code", ""))
        if employee_code:
            return employee_code

    try:
        user_id = user_row["id"] if "id" in user_row.keys() else 0
    except Exception:
        user_id = getattr(user_row, "id", 0)
    return build_default_employee_code(user_id)
