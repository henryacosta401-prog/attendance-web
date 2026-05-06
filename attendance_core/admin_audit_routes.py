def register_admin_audit_routes(app, deps):
    build_attendance_audit_rows = deps["build_attendance_audit_rows"]
    datetime = deps["datetime"]
    fetchall = deps["fetchall"]
    login_required = deps["login_required"]
    render_template = deps["render_template"]
    request = deps["request"]

    @app.route("/admin/attendance-audit")
    @login_required(role="admin")
    def admin_attendance_audit():
        date_from = (request.args.get("date_from", "") or "").strip()
        date_to = (request.args.get("date_to", "") or "").strip()
        employee_id = (request.args.get("employee_id", "") or "").strip()
        source_filter = (request.args.get("source", "") or "").strip()

        if date_from and date_to:
            try:
                start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
                end_date = datetime.strptime(date_to, "%Y-%m-%d").date()
                if start_date > end_date:
                    date_from, date_to = date_to, date_from
            except ValueError:
                pass

        rows = build_attendance_audit_rows(
            date_from=date_from,
            date_to=date_to,
            employee_id=employee_id,
            source_filter=source_filter
        )
        employees = fetchall("""
            SELECT id, full_name, department
            FROM users
            WHERE role = 'employee'
            ORDER BY full_name
        """)
        return render_template(
            "admin_attendance_audit.html",
            audit_rows=rows,
            date_from=date_from,
            date_to=date_to,
            employee_id=employee_id,
            source_filter=source_filter,
            employees=employees
        )
