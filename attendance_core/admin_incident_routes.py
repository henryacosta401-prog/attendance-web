def register_admin_incident_routes(app, deps):
    BytesIO = deps["BytesIO"]
    DISCIPLINARY_ACTION_TYPES = deps["DISCIPLINARY_ACTION_TYPES"]
    INCIDENT_DISCIPLINARY_POLICY = deps["INCIDENT_DISCIPLINARY_POLICY"]
    Response = deps["Response"]
    calculate_suspension_end_date = deps["calculate_suspension_end_date"]
    create_disciplinary_action = deps["create_disciplinary_action"]
    create_incident = deps["create_incident"]
    execute_db = deps["execute_db"]
    fetchall = deps["fetchall"]
    fetchone = deps["fetchone"]
    find_conflicting_disciplinary_action = deps["find_conflicting_disciplinary_action"]
    flash = deps["flash"]
    get_department_options = deps["get_department_options"]
    get_disciplinary_action_by_id = deps["get_disciplinary_action_by_id"]
    get_disciplinary_actions = deps["get_disciplinary_actions"]
    get_employee_options = deps["get_employee_options"]
    get_incident_error_type_options = deps["get_incident_error_type_options"]
    get_incident_reports = deps["get_incident_reports"]
    get_user_by_id = deps["get_user_by_id"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    normalize_incident_error_type = deps["normalize_incident_error_type"]
    now_str = deps["now_str"]
    parse_non_negative_int = deps["parse_non_negative_int"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    session = deps["session"]
    sync_incident_policy = deps["sync_incident_policy"]
    today_str = deps["today_str"]
    url_for = deps["url_for"]

    @app.route("/admin/error-reports")
    @login_required(role="admin")
    def admin_error_reports():
        report_employee = request.args.get("report_employee", "").strip()
        report_department = request.args.get("report_department", "").strip()
        report_type = request.args.get("report_type", "").strip()
        report_date_from = request.args.get("report_date_from", "").strip()
        report_date_to = request.args.get("report_date_to", "").strip()

        employees = get_employee_options()
        departments = get_department_options()
        error_types = get_incident_error_type_options()
        reports = get_incident_reports(
            report_employee=report_employee,
            report_department=report_department,
            report_type=report_type,
            report_date_from=report_date_from,
            report_date_to=report_date_to
        )

        return render_template(
            "admin_error_reports.html",
            employees=employees,
            departments=departments,
            reports=reports,
            report_employee=report_employee,
            report_department=report_department,
            report_type=report_type,
            report_date_from=report_date_from,
            report_date_to=report_date_to,
            error_types=error_types
        )


    @app.route("/admin/error-reports/export.xlsx")
    @login_required(role="admin")
    def export_admin_error_reports_excel():
        report_employee = request.args.get("report_employee", "").strip()
        report_department = request.args.get("report_department", "").strip()
        report_type = request.args.get("report_type", "").strip()
        report_date_from = request.args.get("report_date_from", "").strip()
        report_date_to = request.args.get("report_date_to", "").strip()

        reports = get_incident_reports(
            report_employee=report_employee,
            report_department=report_department,
            report_type=report_type,
            report_date_from=report_date_from,
            report_date_to=report_date_to
        )

        try:
            from openpyxl import Workbook
        except Exception:
            flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
            return redirect(url_for(
                "admin_error_reports",
                report_employee=report_employee,
                report_department=report_department,
                report_type=report_type,
                report_date_from=report_date_from,
                report_date_to=report_date_to
            ))

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Error Reports"
        sheet.append([
            "Employee",
            "Department",
            "Error Type",
            "Report Date",
            "Message",
            "Status",
            "Policy Count",
            "Policy Step",
            "Linked Disciplinary",
            "Admin Note",
            "Created At",
            "Reviewed At",
            "Reviewed By"
        ])

        for report in reports:
            sheet.append([
                report["full_name"] if report["full_name"] else report["employee_name"] if report["employee_name"] else "Unknown",
                report["report_department"] or report["department"] or "",
                report["error_type"] or "",
                report["report_date"] if report["report_date"] else report["incident_date"] if report["incident_date"] else "",
                report["message"] or "",
                report["status"] or "Open",
                report["policy_incident_count"] or "",
                report["incident_action"] or "",
                f"#{report['disciplinary_action_id']} {report['linked_action_type']}" if report.get("disciplinary_action_id") else "",
                report["admin_note"] or "",
                report["created_at"] or "",
                report["reviewed_at"] or "",
                report["reviewed_by_name"] or ""
            ])

        output = BytesIO()
        workbook.save(output)
        output.seek(0)

        return Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="error-reports-{today_str()}.xlsx"'}
        )


    @app.route("/admin/incident-report")
    @login_required(role="admin")
    def admin_incident_report():
        employees = fetchall("""
            SELECT id, full_name
            FROM users
            WHERE role = 'employee'
            ORDER BY full_name ASC
        """)
        return render_template(
            "admin_incident_report.html",
            employees=employees,
            error_types=get_incident_error_type_options(),
            incident_policy=INCIDENT_DISCIPLINARY_POLICY
        )


    @app.route("/admin/disciplinary")
    @login_required(role="admin")
    def admin_disciplinary_dashboard():
        action_type = request.args.get("action_type", "").strip()
        user_id = request.args.get("user_id", "").strip()
        department = request.args.get("department", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        employees = get_employee_options()
        departments = get_department_options()
        actions = get_disciplinary_actions(
            action_type=action_type,
            user_id=user_id,
            department=department,
            date_from=date_from,
            date_to=date_to
        )

        summary = {
            "coaching": len([row for row in actions if row["action_type"] == "Coaching"]),
            "nte": len([row for row in actions if row["action_type"] == "NTE"]),
            "suspension": len([row for row in actions if row["action_type"] == "Suspension"]),
            "termination": len([row for row in actions if row["action_type"] == "Termination"]),
            "active_suspensions": len([row for row in actions if row["action_type"] == "Suspension" and row["status_label"] == "Active"]),
            "upcoming_suspensions": len([row for row in actions if row["action_type"] == "Suspension" and row["status_label"] == "Upcoming"]),
            "starts_today": len([row for row in actions if row["action_type"] == "Suspension" and row["action_date"] == today_str()]),
        }

        return render_template(
            "admin_disciplinary_dashboard.html",
            employees=employees,
            departments=departments,
            disciplinary_types=DISCIPLINARY_ACTION_TYPES,
            actions=actions,
            action_type=action_type,
            user_id=user_id,
            department=department,
            date_from=date_from,
            date_to=date_to,
            summary=summary
        )


    @app.route("/admin/disciplinary/export.xlsx")
    @login_required(role="admin")
    def export_admin_disciplinary_excel():
        action_type = request.args.get("action_type", "").strip()
        user_id = request.args.get("user_id", "").strip()
        department = request.args.get("department", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()
        actions = get_disciplinary_actions(
            action_type=action_type,
            user_id=user_id,
            department=department,
            date_from=date_from,
            date_to=date_to
        )

        try:
            from openpyxl import Workbook
        except Exception:
            flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
            return redirect(url_for(
                "admin_disciplinary_dashboard",
                action_type=action_type,
                user_id=user_id,
                department=department,
                date_from=date_from,
                date_to=date_to
            ))

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Disciplinary"
        sheet.append(["Employee", "Username", "Department", "Type", "Start Date", "Duration Days", "End Date", "Status", "Incident #", "Error Type", "Details"])
        for row in actions:
            sheet.append([
                row["full_name"], row["username"], row["department"], row["action_type"], row["action_date"],
                row["duration_days"] if row["action_type"] == "Suspension" else "",
                row["end_date"] or row["action_date"], row["status_label"],
                row.get("incident_report_id") or "",
                row.get("error_type") or row.get("incident_error_type") or "",
                row["details"] or ""
            ])

        output = BytesIO()
        workbook.save(output)
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="disciplinary-records-{today_str()}.xlsx"'}
        )


    @app.route("/admin/error-reports/<int:report_id>/update", methods=["POST"])
    @login_required(role="admin")
    def update_incident_report(report_id):
        status = request.form.get("status", "").strip()
        admin_note = request.form.get("admin_note", "").strip()

        if status not in {"Open", "Reviewed", "Resolved"}:
            flash("Invalid report status.", "danger")
            return redirect(url_for("admin_error_reports"))

        report = fetchone("""
            SELECT r.*, u.full_name
            FROM incident_reports r
            LEFT JOIN users u ON u.id = r.user_id
            WHERE r.id = ?
        """, (report_id,))

        if not report:
            flash("Report not found.", "danger")
            return redirect(url_for("admin_error_reports"))

        reviewed_at = now_str() if status in {"Reviewed", "Resolved"} else None
        reviewed_by = session["user_id"] if status in {"Reviewed", "Resolved"} else None

        execute_db("""
            UPDATE incident_reports
            SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = ?
            WHERE id = ?
        """, (status, admin_note, reviewed_by, reviewed_at, report_id), commit=True)

        employee_name = report["full_name"] if report["full_name"] else report["employee_name"] or f"User {report['user_id']}"
        log_activity(
            session["user_id"],
            "UPDATE INCIDENT",
            f"Incident #{report_id} for {employee_name} marked as {status}"
        )

        flash("Incident report updated.", "success")
        return redirect(url_for("admin_error_reports"))


    @app.route("/admin/error-reports/<int:report_id>/edit", methods=["POST"])
    @login_required(role="admin")
    def edit_incident_report(report_id):
        report = fetchone("""
            SELECT *
            FROM incident_reports
            WHERE id = ?
        """, (report_id,))
        if not report:
            flash("Report not found.", "danger")
            return redirect(url_for("admin_error_reports"))

        error_type = normalize_incident_error_type(
            request.form.get("error_type", ""),
            request.form.get("new_error_type", "")
        )
        report_date = request.form.get("report_date", "").strip()
        report_department = request.form.get("report_department", "").strip()
        message = request.form.get("message", "").strip()

        if not error_type or not report_date:
            flash("Error type and report date are required.", "danger")
            return redirect(url_for("admin_error_reports"))

        execute_db("""
            UPDATE incident_reports
            SET error_type = ?, report_date = ?, incident_date = ?, report_department = ?, message = ?,
                policy_incident_count = 0
            WHERE id = ?
        """, (error_type, report_date, report_date, report_department, message, report_id), commit=True)
        sync_result = sync_incident_policy(report_id, session["user_id"], allow_create=not bool(report["disciplinary_action_id"]))

        employee = get_user_by_id(report["user_id"])
        employee_name = employee["full_name"] if employee else report.get("employee_name") or f"User {report['user_id']}"
        log_activity(session["user_id"], "EDIT INCIDENT", f"Edited incident #{report_id} for {employee_name}")
        if sync_result.get("created_action"):
            flash(f"Incident report updated. Linked {sync_result['policy_action']} record created.", "success")
        else:
            flash("Incident report updated.", "success")
        return redirect(url_for("admin_error_reports"))


    @app.route("/admin/error-reports/<int:report_id>/delete", methods=["POST"])
    @login_required(role="admin")
    def delete_incident_report(report_id):
        report = fetchone("""
            SELECT *
            FROM incident_reports
            WHERE id = ?
        """, (report_id,))
        if not report:
            flash("Report not found.", "danger")
            return redirect(url_for("admin_error_reports"))

        employee = get_user_by_id(report["user_id"])
        employee_name = employee["full_name"] if employee else report.get("employee_name") or f"User {report['user_id']}"
        execute_db("DELETE FROM incident_reports WHERE id = ?", (report_id,), commit=True)
        log_activity(session["user_id"], "DELETE INCIDENT", f"Deleted incident #{report_id} for {employee_name}")
        flash("Incident report deleted.", "info")
        return redirect(url_for("admin_error_reports"))

    @app.route("/admin/create-incident", methods=["POST"])
    @login_required(role="admin")
    def create_incident_route():
        user_id = request.form.get("user_id")
        error_type = normalize_incident_error_type(
            request.form.get("error_type", ""),
            request.form.get("new_error_type", "")
        )
        report_date = request.form.get("report_date", "").strip()
        message = request.form.get("message", "").strip()

        if not user_id or not error_type or not report_date:
            flash("All fields are required.", "danger")
            return redirect(url_for("admin_incident_report"))

        employee = get_user_by_id(user_id)

        incident = create_incident(
            user_id=user_id,
            error_type=error_type,
            report_date=report_date,
            message=message,
            admin_id=session["user_id"],
            incident_action="",
            report_department=employee["department"] if employee else ""
        )
        sync_result = sync_incident_policy(incident["id"], session["user_id"]) if incident else {}

        employee_name = employee["full_name"] if employee else f"User {user_id}"
        log_activity(
            session["user_id"],
            "CREATE INCIDENT",
            f"{error_type} report created for {employee_name}"
        )

        if sync_result.get("created_action"):
            flash(
                f"Incident report created. Policy step #{sync_result['incident_count']} created a linked {sync_result['policy_action']} record.",
                "success"
            )
        elif sync_result.get("policy_action") and sync_result.get("message"):
            flash(
                f"Incident report created. Policy recommends {sync_result['policy_action']}, but no disciplinary record was auto-created: {sync_result['message']}",
                "warning"
            )
        else:
            flash("Incident report created.", "success")
        return redirect(url_for("admin_incident_report"))


    @app.route("/admin/disciplinary/create", methods=["POST"])
    @login_required(role="admin")
    def create_disciplinary_action_route():
        user_id = request.form.get("user_id", "").strip()
        action_type = request.form.get("action_type", "").strip()
        action_date = request.form.get("action_date", "").strip()
        duration_days = parse_non_negative_int(request.form.get("duration_days", "1"), 1)
        details = request.form.get("details", "").strip()

        if not user_id or not action_type or not action_date:
            flash("Employee, action type, and action date are required.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))

        if action_type not in DISCIPLINARY_ACTION_TYPES:
            flash("Invalid disciplinary action type.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))

        if action_type == "Suspension" and duration_days <= 0:
            flash("Suspension days must be at least 1.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))

        if action_type != "Suspension":
            duration_days = 1

        employee = get_user_by_id(user_id)
        conflict = find_conflicting_disciplinary_action(user_id, action_type, action_date, duration_days)
        if conflict:
            flash(conflict["conflict_reason"], "warning")
            return redirect(url_for("admin_disciplinary_dashboard"))
        create_disciplinary_action(
            user_id=user_id,
            action_type=action_type,
            action_date=action_date,
            details=details,
            created_by=session["user_id"],
            duration_days=duration_days
        )

        employee_name = employee["full_name"] if employee else f"User {user_id}"
        log_activity(
            session["user_id"],
            "CREATE DISCIPLINARY ACTION",
            f"{action_type} created for {employee_name}" + (f" for {duration_days} day(s)" if action_type == "Suspension" else "")
        )
        flash(f"{action_type} record created.", "success")
        return redirect(url_for("admin_disciplinary_dashboard"))


    @app.route("/admin/disciplinary/<int:action_id>/update", methods=["POST"])
    @login_required(role="admin")
    def update_disciplinary_action_route(action_id):
        action = get_disciplinary_action_by_id(action_id)
        if not action:
            flash("Disciplinary record not found.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))

        action_type = request.form.get("action_type", "").strip()
        action_date = request.form.get("action_date", "").strip()
        duration_days = parse_non_negative_int(request.form.get("duration_days", "1"), 1)
        details = request.form.get("details", "").strip()

        if not action_type or not action_date:
            flash("Action type and action date are required.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))
        if action_type not in DISCIPLINARY_ACTION_TYPES:
            flash("Invalid disciplinary action type.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))

        if action_type != "Suspension":
            duration_days = 1
        conflict = find_conflicting_disciplinary_action(action["user_id"], action_type, action_date, duration_days, exclude_id=action_id)
        if conflict:
            flash(conflict["conflict_reason"], "warning")
            return redirect(url_for("admin_disciplinary_dashboard"))
        end_date = calculate_suspension_end_date(action_date, duration_days) if action_type == "Suspension" else action_date

        execute_db("""
            UPDATE disciplinary_actions
            SET action_type = ?, action_date = ?, duration_days = ?, end_date = ?, details = ?
            WHERE id = ?
        """, (action_type, action_date, duration_days, end_date, details, action_id), commit=True)

        employee = get_user_by_id(action["user_id"])
        employee_name = employee["full_name"] if employee else f"User {action['user_id']}"
        log_activity(session["user_id"], "UPDATE DISCIPLINARY ACTION", f"Updated {action_type} for {employee_name}")
        flash("Disciplinary record updated.", "success")
        return redirect(url_for("admin_disciplinary_dashboard"))


    @app.route("/admin/disciplinary/<int:action_id>/delete", methods=["POST"])
    @login_required(role="admin")
    def delete_disciplinary_action_route(action_id):
        action = get_disciplinary_action_by_id(action_id)
        if not action:
            flash("Disciplinary record not found.", "danger")
            return redirect(url_for("admin_disciplinary_dashboard"))

        employee = get_user_by_id(action["user_id"])
        employee_name = employee["full_name"] if employee else f"User {action['user_id']}"
        execute_db("DELETE FROM disciplinary_actions WHERE id = ?", (action_id,), commit=True)
        log_activity(session["user_id"], "DELETE DISCIPLINARY ACTION", f"Deleted {action['action_type']} for {employee_name}")
        flash("Disciplinary record deleted.", "info")
        return redirect(url_for("admin_disciplinary_dashboard"))
