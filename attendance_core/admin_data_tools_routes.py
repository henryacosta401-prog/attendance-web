def register_admin_data_tools_routes(app, deps):
    BytesIO = deps["BytesIO"]
    Response = deps["Response"]
    build_recovery_pack_workbook = deps["build_recovery_pack_workbook"]
    build_upload_storage_audit = deps["build_upload_storage_audit"]
    create_sqlite_backup = deps["create_sqlite_backup"]
    flash = deps["flash"]
    format_datetime_12h = deps["format_datetime_12h"]
    get_admin_employee_rows = deps["get_admin_employee_rows"]
    get_backup_files = deps["get_backup_files"]
    get_backup_recovery_snapshot = deps["get_backup_recovery_snapshot"]
    get_exception_collections = deps["get_exception_collections"]
    get_log_cleanup_summary = deps["get_log_cleanup_summary"]
    get_suspicious_attendance_records = deps["get_suspicious_attendance_records"]
    get_user_by_id = deps["get_user_by_id"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    minutes_to_hm = deps["minutes_to_hm"]
    os = deps["os"]
    perform_go_live_reset = deps["perform_go_live_reset"]
    perform_log_cleanup_for_date_range = deps["perform_log_cleanup_for_date_range"]
    perform_log_retention_cleanup = deps["perform_log_retention_cleanup"]
    record_external_backup_marker = deps["record_external_backup_marker"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    session = deps["session"]
    today_str = deps["today_str"]
    update_attendance_record_by_admin = deps["update_attendance_record_by_admin"]
    url_for = deps["url_for"]
    using_postgres = deps["using_postgres"]
    workbook_to_response = deps["workbook_to_response"]

    @app.route("/admin/data-tools", methods=["GET", "POST"])
    @login_required(role="admin")
    def admin_data_tools():
        search = request.args.get("search", "").strip()
        cleanup_from = request.args.get("cleanup_from", "").strip()
        cleanup_to = request.args.get("cleanup_to", "").strip()

        if request.method == "POST":
            action = request.form.get("action", "").strip()
            if action == "create_backup":
                try:
                    backup_path = create_sqlite_backup()
                    log_activity(session["user_id"], "CREATE BACKUP", f"Created SQLite backup at {backup_path}")
                    flash(f"Backup created: {os.path.basename(backup_path)}", "success")
                except ValueError as exc:
                    flash(str(exc), "danger")
                return redirect(url_for("admin_data_tools", search=search))
            if action == "record_external_backup":
                result = record_external_backup_marker(
                    note=request.form.get("external_backup_note", ""),
                    actor_id=session.get("user_id"),
                )
                log_activity(
                    session["user_id"],
                    "RECORD EXTERNAL BACKUP",
                    f"Marked external provider backup verified at {result['backup_at']}."
                )
                flash("External Render/Postgres backup note saved. You now have a visible reminder before reset or cleanup.", "success")
                return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))
            if action in {"cleanup_logs_weekly", "cleanup_logs_monthly"}:
                retention_days = 7 if action == "cleanup_logs_weekly" else 30
                try:
                    result = perform_log_retention_cleanup(retention_days)
                    log_activity(
                        session["user_id"],
                        "CLEANUP LOGS",
                        f"Removed {result['total_removed']} old log row(s) older than {retention_days} day(s)."
                    )
                    flash(
                        "Cleanup completed. Removed "
                        f"{result['activity_logs']} activity log(s), "
                        f"{result['scanner_logs']} scanner log(s), "
                        f"{result['login_attempts']} login attempt row(s), and "
                        f"{result['read_notifications']} read notification(s) older than {retention_days} day(s).",
                        "success"
                    )
                except ValueError as exc:
                    flash(str(exc), "danger")
                return redirect(url_for("admin_data_tools", search=search))
            if action == "cleanup_logs_custom":
                cleanup_from = request.form.get("cleanup_from", "").strip()
                cleanup_to = request.form.get("cleanup_to", "").strip()
                try:
                    result = perform_log_cleanup_for_date_range(cleanup_from, cleanup_to)
                    log_activity(
                        session["user_id"],
                        "CLEANUP LOGS",
                        f"Removed {result['total_removed']} log row(s) for {result['date_from']} to {result['date_to']}."
                    )
                    flash(
                        "Cleanup completed for "
                        f"{result['date_from']} to {result['date_to']}. Removed "
                        f"{result['activity_logs']} activity log(s), "
                        f"{result['scanner_logs']} scanner log(s), "
                        f"{result['login_attempts']} login attempt row(s), and "
                        f"{result['read_notifications']} read notification(s).",
                        "success"
                    )
                    cleanup_from = result["date_from"]
                    cleanup_to = result["date_to"]
                except ValueError as exc:
                    flash(str(exc), "danger")
                return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))
            if action == "go_live_reset":
                confirmation = request.form.get("confirmation_text", "").strip().upper()
                if confirmation != "RESET":
                    flash("Type RESET exactly before running the go-live reset.", "danger")
                    return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))
                if using_postgres() and request.form.get("confirm_no_backup") != "1":
                    flash("On Postgres/Render, no automatic database backup is created by this reset. Confirm that you understand before continuing.", "danger")
                    return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))
                try:
                    result = perform_go_live_reset()
                    backup_note = f" Backup: {os.path.basename(result['backup_path'])}." if result.get("backup_path") else ""
                    if not result.get("backup_supported"):
                        backup_note = " No automatic database backup was created for this Postgres reset."
                    upload_note = f" Removed {result['removed_uploads']} orphaned proof uploads." if result.get("removed_uploads") else ""
                    log_activity(session["user_id"], "GO-LIVE RESET", "Cleared operational attendance data for go-live.")
                    flash(f"Go-live reset completed.{backup_note}{upload_note}", "success")
                except ValueError as exc:
                    flash(str(exc), "danger")
                return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))

            attendance_id = request.form.get("attendance_id", "").strip()
            if not attendance_id:
                flash("Attendance record is required.", "danger")
                return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))

            try:
                updated_row = update_attendance_record_by_admin(
                    attendance_id=int(attendance_id),
                    time_in_value=request.form.get("time_in", "").strip(),
                    time_out_value=request.form.get("time_out", "").strip(),
                    clear_breaks=request.form.get("clear_breaks", "").strip() == "1",
                )
                employee = get_user_by_id(updated_row["user_id"]) if updated_row else None
                employee_name = employee["full_name"] if employee else f"Attendance #{attendance_id}"
                log_activity(session["user_id"], "FIX ATTENDANCE", f"Updated suspicious row #{attendance_id} for {employee_name}")
                flash("Attendance record updated.", "success")
            except ValueError as exc:
                flash(str(exc), "danger")

            return redirect(url_for("admin_data_tools", search=search, cleanup_from=cleanup_from, cleanup_to=cleanup_to))

        candidates = get_suspicious_attendance_records(search=search, limit=60)
        backups = get_backup_files(limit=12)
        cleanup_summary = get_log_cleanup_summary()
        recovery_snapshot = get_backup_recovery_snapshot()
        storage_audit = build_upload_storage_audit()
        return render_template(
            "admin_data_tools.html",
            candidates=candidates,
            backups=backups,
            search=search,
            cleanup_from=cleanup_from,
            cleanup_to=cleanup_to,
            cleanup_summary=cleanup_summary,
            recovery_snapshot=recovery_snapshot,
            storage_audit=storage_audit,
            using_postgres_reset=using_postgres(),
            format_datetime_12h=format_datetime_12h,
            minutes_to_hm=minutes_to_hm
        )


    @app.route("/admin/data-tools/recovery-pack.xlsx")
    @login_required(role="admin")
    def download_recovery_pack():
        try:
            workbook = build_recovery_pack_workbook()
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("admin_data_tools"))
        log_activity(session["user_id"], "DOWNLOAD RECOVERY PACK", "Downloaded the operational recovery workbook.")
        return workbook_to_response(workbook, f"recovery-pack-{today_str()}.xlsx")


    @app.route("/admin/exceptions/export.xlsx")
    @login_required(role="admin")
    def export_admin_exceptions_excel():
        exception_type = request.args.get("type", "absent").strip().lower()
        department = request.args.get("department", "").strip()

        exception_groups = get_exception_collections(get_admin_employee_rows(department_filter=department))
        selected_rows = exception_groups.get(exception_type, [])
        titles = {
            "absent": "Not Timed In Today",
            "late": "Late Today",
            "over_break": "Over Break",
            "missing_timeout": "Missing Time Out",
            "undertime": "Undertime Today",
        }

        try:
            from openpyxl import Workbook
        except Exception:
            flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
            return redirect(url_for("admin_dashboard", department=department))

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = titles.get(exception_type, "Exceptions")
        sheet.append([
            "Employee",
            "Username",
            "Department",
            "Position",
            "Schedule",
            "Shift Start",
            "Shift End",
            "Status",
            "Time In",
            "Time Out",
            "Late Minutes",
            "Break Minutes",
            "Over Break Minutes"
        ])

        for row in selected_rows:
            sheet.append([
                row["full_name"] or "",
                row["username"] or "",
                row["department"] or "",
                row["position"] or "",
                row["schedule_summary"] or "",
                row["shift_start"] or "",
                row["shift_end"] or "",
                row["status_display"] or "",
                row["time_in"] or "",
                row["time_out"] or "",
                row["late_minutes"] if row["late_flag"] else 0,
                row["break_minutes"] or 0,
                row["over_break_minutes"] or 0,
            ])

        output = BytesIO()
        workbook.save(output)
        output.seek(0)

        return Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{exception_type}-exceptions-{today_str()}.xlsx"'}
        )
