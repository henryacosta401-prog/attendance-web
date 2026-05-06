from datetime import timedelta

from attendance_core.config import DEFAULT_INCIDENT_ERROR_TYPES, INCIDENT_DISCIPLINARY_POLICY
from attendance_core.date_ranges import parse_iso_date
from attendance_core.workflows import calculate_suspension_end_date, format_request_date_range

fetchone = None
fetchall = None
execute_db = None
get_user_by_id = None
create_notification = None
now_str = None
today_str = None


def configure_incident_services(deps):
    global fetchone, fetchall, execute_db, get_user_by_id, create_notification, now_str, today_str
    fetchone = deps["fetchone"]
    fetchall = deps["fetchall"]
    execute_db = deps["execute_db"]
    get_user_by_id = deps["get_user_by_id"]
    create_notification = deps["create_notification"]
    now_str = deps["now_str"]
    today_str = deps["today_str"]


def get_employee_error_record_summary(user_id):
    summary_row = fetchone("""
        SELECT
            COUNT(*) AS total_errors,
            SUM(CASE WHEN COALESCE(status, 'Open') = 'Resolved' THEN 0 ELSE 1 END) AS active_errors,
            COUNT(DISTINCT LOWER(TRIM(COALESCE(error_type, '')))) AS error_type_count
        FROM incident_reports
        WHERE user_id = ?
    """, (user_id,))
    breakdown = fetchall("""
        SELECT
            COALESCE(NULLIF(TRIM(error_type), ''), 'Uncategorized') AS error_type,
            COUNT(*) AS total_count,
            SUM(CASE WHEN COALESCE(status, 'Open') = 'Resolved' THEN 0 ELSE 1 END) AS active_count,
            MAX(report_date) AS latest_report_date
        FROM incident_reports
        WHERE user_id = ?
        GROUP BY COALESCE(NULLIF(TRIM(error_type), ''), 'Uncategorized')
        ORDER BY active_count DESC, total_count DESC, error_type ASC
    """, (user_id,))
    return {
        "total_errors": int(summary_row["total_errors"] or 0) if summary_row else 0,
        "active_errors": int(summary_row["active_errors"] or 0) if summary_row else 0,
        "error_type_count": int(summary_row["error_type_count"] or 0) if summary_row else 0,
        "breakdown": [
            {
                "error_type": row["error_type"],
                "total_count": int(row["total_count"] or 0),
                "active_count": int(row["active_count"] or 0),
                "latest_report_date": row.get("latest_report_date") or "",
            }
            for row in breakdown
        ],
    }


def normalize_incident_error_type(error_type, new_error_type=""):
    raw_value = (error_type or "").strip()
    custom_value = " ".join((new_error_type or "").strip().split())
    if raw_value == "__new__":
        return custom_value
    return " ".join(raw_value.split())


def get_incident_error_type_options():
    saved_types = [
        row["error_type"]
        for row in fetchall("""
            SELECT DISTINCT TRIM(error_type) AS error_type
            FROM incident_reports
            WHERE error_type IS NOT NULL AND TRIM(error_type) != ''
            ORDER BY TRIM(error_type)
        """)
    ]
    options = []
    seen = set()
    for error_type in [*DEFAULT_INCIDENT_ERROR_TYPES, *saved_types]:
        normalized = " ".join((error_type or "").strip().split())
        key = normalized.lower()
        if not normalized or key in seen:
            continue
        seen.add(key)
        options.append(normalized)
    return options


def count_repeated_incidents(user_id, error_type):
    normalized_error_type = (error_type or "").strip().lower()
    if not user_id or not normalized_error_type:
        return 0
    row = fetchone("""
        SELECT COUNT(*) AS cnt
        FROM incident_reports
        WHERE user_id = ?
          AND LOWER(TRIM(COALESCE(error_type, ''))) = ?
    """, (user_id, normalized_error_type))
    return int(row["cnt"] or 0) if row else 0


def get_incident_policy_action(incident_count, *, exact_threshold=True):
    try:
        count = int(incident_count or 0)
    except (TypeError, ValueError):
        count = 0
    if exact_threshold:
        return INCIDENT_DISCIPLINARY_POLICY.get(count, "")
    if count >= 5:
        return INCIDENT_DISCIPLINARY_POLICY[5]
    return INCIDENT_DISCIPLINARY_POLICY.get(count, "")


def build_incident_policy_details(report, incident_count, policy_action):
    error_type = report["error_type"] if report else ""
    report_date = report["report_date"] or report["incident_date"] if report else ""
    message = (report["message"] or "").strip() if report else ""
    parts = [
        f"Policy trigger: {incident_count} repeated {error_type} incident(s).",
        f"Source incident #{report['id']} dated {report_date}.",
    ]
    if policy_action == "Termination":
        parts.append("This logs the termination policy step only; process final HR/account action separately.")
    if message:
        parts.append(f"Incident details: {message}")
    return " ".join(parts)


def create_incident(user_id, error_type, report_date, message, admin_id, incident_action, report_department):
    user = get_user_by_id(user_id)
    created_at = now_str()

    execute_db("""
        INSERT INTO incident_reports (
            user_id,
            employee_name,
            report_department,
            error_type,
            incident_action,
            incident_date,
            report_date,
            message,
            status,
            admin_note,
            created_by,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', NULL, ?, ?)
    """, (
        user_id,
        user["full_name"] if user else "",
        report_department,
        error_type,
        incident_action,
        report_date,
        report_date,
        message,
        admin_id,
        created_at
    ), commit=True)
    return fetchone("""
        SELECT *
        FROM incident_reports
        WHERE user_id = ? AND created_by = ? AND created_at = ?
        ORDER BY id DESC
        LIMIT 1
    """, (user_id, admin_id, created_at))


def create_disciplinary_action(user_id, action_type, action_date, details, created_by, duration_days=1, incident_report_id=None, error_type=""):
    duration_days = max(int(duration_days or 1), 1)
    end_date = calculate_suspension_end_date(action_date, duration_days) if action_type == "Suspension" else action_date
    created_at = now_str()
    execute_db("""
        INSERT INTO disciplinary_actions (
            user_id, action_type, action_date, duration_days, end_date, details,
            incident_report_id, error_type, created_by, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        action_type,
        action_date,
        duration_days,
        end_date,
        details,
        incident_report_id,
        error_type,
        created_by,
        created_at
    ), commit=True)
    return fetchone("""
        SELECT *
        FROM disciplinary_actions
        WHERE user_id = ? AND created_by = ? AND created_at = ?
        ORDER BY id DESC
        LIMIT 1
    """, (user_id, created_by, created_at))


def sync_incident_policy(report_id, actor_id, allow_create=True):
    report = fetchone("""
        SELECT r.*, u.full_name, u.department
        FROM incident_reports r
        LEFT JOIN users u ON u.id = r.user_id
        WHERE r.id = ?
    """, (report_id,))
    if not report:
        return {"created_action": None, "policy_action": "", "incident_count": 0, "message": "Incident not found."}

    incident_count = count_repeated_incidents(report["user_id"], report["error_type"])
    policy_action = get_incident_policy_action(incident_count, exact_threshold=True)
    display_policy_action = policy_action or get_incident_policy_action(incident_count, exact_threshold=False)
    execute_db("""
        UPDATE incident_reports
        SET policy_incident_count = ?, incident_action = ?
        WHERE id = ?
    """, (incident_count, display_policy_action, report_id), commit=True)

    if not allow_create or not policy_action:
        return {
            "created_action": None,
            "policy_action": display_policy_action,
            "incident_count": incident_count,
            "message": "",
        }

    if report["disciplinary_action_id"]:
        return {
            "created_action": get_disciplinary_action_by_id(report["disciplinary_action_id"]),
            "policy_action": policy_action,
            "incident_count": incident_count,
            "message": "Incident already has a linked disciplinary action.",
        }

    action_date = report["report_date"] or report["incident_date"] or today_str()
    duration_days = 1
    conflict = find_conflicting_disciplinary_action(report["user_id"], policy_action, action_date, duration_days)
    if conflict:
        return {
            "created_action": None,
            "policy_action": policy_action,
            "incident_count": incident_count,
            "message": conflict["conflict_reason"],
        }

    created_action = create_disciplinary_action(
        user_id=report["user_id"],
        action_type=policy_action,
        action_date=action_date,
        details=build_incident_policy_details(report, incident_count, policy_action),
        created_by=actor_id,
        duration_days=duration_days,
        incident_report_id=report_id,
        error_type=report["error_type"],
    )
    if created_action:
        execute_db("""
            UPDATE incident_reports
            SET disciplinary_action_id = ?
            WHERE id = ?
        """, (created_action["id"], report_id), commit=True)
        create_notification(
            report["user_id"],
            "Incident Policy Step Logged",
            f"{policy_action} was logged after {incident_count} repeated {report['error_type']} incident(s)."
        )
    return {
        "created_action": created_action,
        "policy_action": policy_action,
        "incident_count": incident_count,
        "message": "",
    }


def get_disciplinary_action_by_id(action_id):
    return fetchone("""
        SELECT *
        FROM disciplinary_actions
        WHERE id = ?
    """, (action_id,))

def get_overlap_days(start_a, end_a, start_b, end_b):
    left = max(start_a, start_b)
    right = min(end_a, end_b)
    if right < left:
        return []
    total_days = (right - left).days
    return [(left + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(total_days + 1)]


def find_conflicting_disciplinary_action(user_id, action_type, action_date, duration_days=1, exclude_id=None):
    target_start = parse_iso_date(action_date)
    target_end = parse_iso_date(
        calculate_suspension_end_date(action_date, duration_days) if action_type == "Suspension" else action_date,
        target_start
    )
    if not target_start or not target_end:
        return None

    sql = """
        SELECT *
        FROM disciplinary_actions
        WHERE user_id = ?
    """
    params = [user_id]
    if exclude_id:
        sql += " AND id != ?"
        params.append(exclude_id)
    sql += " ORDER BY action_date DESC, id DESC"

    for row in fetchall(sql, params):
        item = dict(row)
        row_start = parse_iso_date(item["action_date"])
        row_end = parse_iso_date(item.get("end_date") or item["action_date"], row_start)
        if not row_start or not row_end:
            continue
        overlapping_days = get_overlap_days(target_start, target_end, row_start, row_end)
        if item["action_type"] == "Suspension" and action_type == "Suspension" and overlapping_days:
            item["conflict_reason"] = f"Overlaps existing suspension on {format_request_date_range(overlapping_days[0], overlapping_days[-1])}."
            return item
        if item["action_date"] == action_date and item["action_type"] == action_type:
            item["conflict_reason"] = f"{item['action_type']} already exists on {action_date}."
            return item
    return None


def get_disciplinary_actions(action_type="", user_id="", department="", date_from="", date_to=""):
    sql = """
        SELECT d.*, u.full_name, u.username, u.department, u.break_limit_minutes,
               creator.full_name AS created_by_name,
               incident.error_type AS incident_error_type,
               incident.policy_incident_count AS linked_incident_count
        FROM disciplinary_actions d
        JOIN users u ON u.id = d.user_id
        LEFT JOIN users creator ON creator.id = d.created_by
        LEFT JOIN incident_reports incident ON incident.id = d.incident_report_id
        WHERE 1=1
    """
    params = []
    if action_type:
        sql += " AND d.action_type = ?"
        params.append(action_type)
    if user_id:
        sql += " AND d.user_id = ?"
        params.append(user_id)
    if department:
        sql += " AND COALESCE(u.department, '') = ?"
        params.append(department)
    if date_from:
        sql += " AND COALESCE(d.end_date, d.action_date) >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND d.action_date <= ?"
        params.append(date_to)
    sql += " ORDER BY d.action_date DESC, d.id DESC"

    rows = [dict(row) for row in fetchall(sql, params)]
    today = today_str()
    for row in rows:
        if row["action_type"] == "Suspension":
            action_end = row["end_date"] or row["action_date"]
            if today < row["action_date"]:
                row["status_label"] = "Upcoming"
            elif row["action_date"] <= today <= action_end:
                row["status_label"] = "Active"
            else:
                row["status_label"] = "Completed"
        else:
            row["status_label"] = "Logged"
    return rows


def get_suspension_for_date(user_id, work_date):
    if not user_id or not work_date:
        return None
    return fetchone("""
        SELECT *
        FROM disciplinary_actions
        WHERE user_id = ?
          AND action_type = 'Suspension'
          AND action_date <= ?
          AND COALESCE(end_date, action_date) >= ?
        ORDER BY id DESC LIMIT 1
    """, (user_id, work_date, work_date))
