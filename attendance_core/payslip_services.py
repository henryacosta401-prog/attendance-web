from attendance_core.admin_access import admin_has_permission
from attendance_core.attendance import format_datetime_12h
from attendance_core.payroll import format_payroll_period_label, get_payroll_scope_label

fetchone = None
fetchall = None
execute_db = None
create_notification = None
log_activity = None
now_str = None


def configure_payslip_services(deps):
    global fetchone, fetchall, execute_db, create_notification, log_activity, now_str
    fetchone = deps["fetchone"]
    fetchall = deps["fetchall"]
    execute_db = deps["execute_db"]
    create_notification = deps["create_notification"]
    log_activity = deps["log_activity"]
    now_str = deps["now_str"]


PAYSLIP_DOWNLOAD_REQUEST_STATUSES = {"Pending", "Approved", "Rejected"}


def enrich_payslip_download_request(row):
    if not row:
        return None
    item = dict(row)
    status = (item.get("status") or "Pending").strip().title()
    if status not in PAYSLIP_DOWNLOAD_REQUEST_STATUSES:
        status = "Pending"
    item["status"] = status
    item["requested_display"] = format_datetime_12h(item.get("requested_at")) if item.get("requested_at") else ""
    item["reviewed_display"] = format_datetime_12h(item.get("reviewed_at")) if item.get("reviewed_at") else ""
    item["is_pending"] = status == "Pending"
    item["is_approved"] = status == "Approved"
    item["is_rejected"] = status == "Rejected"
    item["status_badge_class"] = {
        "Pending": "status-yellow",
        "Approved": "status-green",
        "Rejected": "status-red",
    }.get(status, "status-gray")
    item["status_chip_class"] = {
        "Pending": "employee-status-yellow",
        "Approved": "employee-status-green",
        "Rejected": "employee-status-red",
    }.get(status, "employee-status-gray")
    item["status_copy"] = {
        "Pending": "Waiting for payroll admin approval before PDF download is unlocked.",
        "Approved": "Approved by admin. PDF download is now available for this released payslip.",
        "Rejected": "The last PDF download request was rejected. You can submit a new request after checking the admin note.",
    }.get(status, "")
    return item


def get_payslip_download_request(user_id, payroll_run_id):
    row = fetchone("""
        SELECT
            req.*,
            reviewer.full_name AS reviewed_by_name
        FROM payslip_download_requests req
        LEFT JOIN users reviewer ON reviewer.id = req.reviewed_by
        WHERE req.user_id = ? AND req.payroll_run_id = ?
        LIMIT 1
    """, (user_id, payroll_run_id))
    return enrich_payslip_download_request(row)


def get_payslip_download_request_map(user_id, payroll_run_ids):
    normalized_ids = []
    for payroll_run_id in payroll_run_ids:
        try:
            normalized_ids.append(int(payroll_run_id))
        except (TypeError, ValueError):
            continue
    if not normalized_ids:
        return {}
    placeholders = ", ".join(["?"] * len(normalized_ids))
    rows = fetchall(f"""
        SELECT
            req.*,
            reviewer.full_name AS reviewed_by_name
        FROM payslip_download_requests req
        LEFT JOIN users reviewer ON reviewer.id = req.reviewed_by
        WHERE req.user_id = ?
          AND req.payroll_run_id IN ({placeholders})
    """, (user_id, *normalized_ids))
    return {
        int(row["payroll_run_id"]): enrich_payslip_download_request(row)
        for row in rows
    }


def attach_payslip_download_requests(payroll_items, user_id):
    request_map = get_payslip_download_request_map(
        user_id,
        [item.get("payroll_run_id") for item in payroll_items],
    )
    for item in payroll_items:
        request_info = request_map.get(int(item["payroll_run_id"])) if item.get("payroll_run_id") else None
        item["download_request"] = request_info
        item["can_download_pdf"] = bool(request_info and request_info["is_approved"])
        item["download_request_status"] = request_info["status"] if request_info else "Not Requested"
    return payroll_items


def get_recent_payslip_download_requests(limit=12):
    rows = fetchall("""
        SELECT
            req.*,
            employee.full_name AS employee_name,
            employee.department AS employee_department,
            employee.username AS employee_username,
            reviewer.full_name AS reviewed_by_name,
            pr.date_from,
            pr.date_to,
            pr.department_filter,
            pr.employee_filter,
            pr.status AS payroll_status
        FROM payslip_download_requests req
        JOIN users employee ON employee.id = req.user_id
        JOIN payroll_runs pr ON pr.id = req.payroll_run_id
        LEFT JOIN users reviewer ON reviewer.id = req.reviewed_by
        ORDER BY
            CASE req.status
                WHEN 'Pending' THEN 0
                WHEN 'Rejected' THEN 1
                ELSE 2
            END,
            req.requested_at DESC,
            req.id DESC
        LIMIT ?
    """, (limit,))
    enriched = []
    for row in rows:
        item = enrich_payslip_download_request(row)
        item["period_label"] = format_payroll_period_label(item.get("date_from"), item.get("date_to"))
        item["employee_scope_label"] = get_payroll_scope_label(
            employee_filter=item.get("employee_filter"),
            department_filter=item.get("department_filter"),
            current_user_id=item.get("user_id"),
        )
        enriched.append(item)
    return enriched


def get_payslip_download_request_summary():
    summary = {
        "pending": 0,
        "approved": 0,
        "rejected": 0,
        "total": 0,
    }
    rows = fetchall("""
        SELECT status, COUNT(*) AS total
        FROM payslip_download_requests
        GROUP BY status
    """)
    for row in rows:
        status = (row.get("status") or "").strip().title()
        total = int(row.get("total") or 0)
        if status == "Pending":
            summary["pending"] = total
        elif status == "Approved":
            summary["approved"] = total
        elif status == "Rejected":
            summary["rejected"] = total
    summary["total"] = summary["pending"] + summary["approved"] + summary["rejected"]
    return summary


def get_payroll_admin_recipients():
    admins = fetchall("""
        SELECT *
        FROM users
        WHERE role = 'admin' AND COALESCE(is_active, 1) = 1
        ORDER BY full_name ASC, id ASC
    """)
    payroll_admins = [admin for admin in admins if admin_has_permission(admin, "payroll")]
    return payroll_admins or admins


def submit_payslip_download_request(user_row, payslip):
    existing = get_payslip_download_request(user_row["id"], payslip["payroll_run_id"])
    if existing and existing["is_approved"]:
        return existing, "approved"
    if existing and existing["is_pending"]:
        return existing, "pending"

    request_time = now_str()
    if existing:
        execute_db("""
            UPDATE payslip_download_requests
            SET status = 'Pending',
                requested_at = ?,
                reviewed_at = NULL,
                reviewed_by = NULL,
                admin_note = NULL
            WHERE id = ?
        """, (request_time, existing["id"]), commit=True)
        action = "resubmitted"
    else:
        execute_db("""
            INSERT INTO payslip_download_requests (
                payroll_run_id, user_id, status, requested_at, reviewed_at, reviewed_by, admin_note
            )
            VALUES (?, ?, 'Pending', ?, NULL, NULL, NULL)
        """, (
            payslip["payroll_run_id"],
            user_row["id"],
            request_time,
        ), commit=True)
        action = "created"

    request_row = get_payslip_download_request(user_row["id"], payslip["payroll_run_id"])
    employee_name = user_row.get("full_name") or user_row.get("username") or f"Employee #{user_row['id']}"
    for admin_user in get_payroll_admin_recipients():
        create_notification(
            admin_user["id"],
            "Payslip Download Approval Needed",
            f"{employee_name} requested approval to download the payslip for {payslip.get('period_label')}. Open Payroll to review it."
        )

    create_notification(
        user_row["id"],
        "Payslip PDF Request Sent",
        f"Your request to download the payslip for {payslip.get('period_label')} is now pending payroll admin approval."
    )
    log_activity(
        user_row["id"],
        "REQUEST PAYSLIP PDF",
        f"Submitted PDF approval request for {payslip.get('period_label')}",
        target_user_id=user_row["id"],
    )
    return request_row, action


def get_payslip_download_request_by_id(request_id):
    row = fetchone("""
        SELECT
            req.*,
            employee.full_name AS employee_name,
            employee.department AS employee_department,
            employee.username AS employee_username,
            reviewer.full_name AS reviewed_by_name,
            pr.date_from,
            pr.date_to,
            pr.department_filter,
            pr.employee_filter
        FROM payslip_download_requests req
        JOIN users employee ON employee.id = req.user_id
        JOIN payroll_runs pr ON pr.id = req.payroll_run_id
        LEFT JOIN users reviewer ON reviewer.id = req.reviewed_by
        WHERE req.id = ?
        LIMIT 1
    """, (request_id,))
    if not row:
        return None
    item = enrich_payslip_download_request(row)
    item["period_label"] = format_payroll_period_label(item.get("date_from"), item.get("date_to"))
    return item


def review_payslip_download_request(request_id, reviewer_user_id, decision, admin_note=""):
    request_row = get_payslip_download_request_by_id(request_id)
    if not request_row:
        return None

    status = "Approved" if (decision or "").strip().lower() == "approve" else "Rejected"
    cleaned_note = " ".join((admin_note or "").strip().split())
    execute_db("""
        UPDATE payslip_download_requests
        SET status = ?, reviewed_at = ?, reviewed_by = ?, admin_note = ?
        WHERE id = ?
    """, (
        status,
        now_str(),
        reviewer_user_id,
        cleaned_note or None,
        request_id,
    ), commit=True)

    updated = get_payslip_download_request_by_id(request_id)
    if not updated:
        return None

    if status == "Approved":
        message = f"Your payslip PDF request for {updated.get('period_label')} was approved. You can now download the official PDF."
        action = "APPROVE PAYSLIP PDF"
    else:
        message = f"Your payslip PDF request for {updated.get('period_label')} was rejected. Review the admin note and submit a new request if needed."
        action = "REJECT PAYSLIP PDF"
    if cleaned_note:
        message = f"{message} Note: {cleaned_note}"

    create_notification(
        updated["user_id"],
        f"Payslip PDF Request {status}",
        message,
    )
    log_activity(
        reviewer_user_id,
        action,
        f"{status} payslip PDF request for {updated.get('employee_name')} ({updated.get('period_label')})",
        target_user_id=updated["user_id"],
    )
    return updated
