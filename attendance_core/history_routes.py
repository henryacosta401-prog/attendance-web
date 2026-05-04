def register_history_routes(app, deps):
    BytesIO = deps["BytesIO"]
    Response = deps["Response"]
    build_admin_history_records = deps["build_admin_history_records"]
    flash = deps["flash"]
    get_department_options = deps["get_department_options"]
    login_required = deps["login_required"]
    minutes_to_decimal_hours = deps["minutes_to_decimal_hours"]
    minutes_to_hm = deps["minutes_to_hm"]
    parse_break_limit_minutes = deps["parse_break_limit_minutes"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    today_str = deps["today_str"]
    url_for = deps["url_for"]

    @app.route("/admin/history")
    @login_required(role="admin")
    def admin_history():
        search = request.args.get("search", "").strip()
        department = request.args.get("department", "").strip()
        type_filter = request.args.get("type_filter", "").strip()
        late_only = request.args.get("late_only", "").strip()
        absent_only = request.args.get("absent_only", "").strip()
        over_break_only = request.args.get("over_break_only", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        departments = get_department_options()
        enriched = build_admin_history_records(
            search=search,
            department=department,
            type_filter=type_filter,
            late_only=late_only,
            absent_only=absent_only,
            over_break_only=over_break_only,
            date_from=date_from,
            date_to=date_to,
            limit=200
        )

        return render_template(
            "admin_history.html",
            records=enriched,
            search=search,
            department=department,
            type_filter=type_filter,
            departments=departments,
            late_only=late_only,
            absent_only=absent_only,
            over_break_only=over_break_only,
            date_from=date_from,
            date_to=date_to,
            minutes_to_hm=minutes_to_hm
        )


    @app.route("/admin/history/export.xlsx")
    @login_required(role="admin")
    def export_admin_history_excel():
        search = request.args.get("search", "").strip()
        department = request.args.get("department", "").strip()
        type_filter = request.args.get("type_filter", "").strip()
        late_only = request.args.get("late_only", "").strip()
        absent_only = request.args.get("absent_only", "").strip()
        over_break_only = request.args.get("over_break_only", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        records = build_admin_history_records(
            search=search,
            department=department,
            type_filter=type_filter,
            late_only=late_only,
            absent_only=absent_only,
            over_break_only=over_break_only,
            date_from=date_from,
            date_to=date_to,
            limit=500
        )

        try:
            from openpyxl import Workbook
        except Exception:
            flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
            return redirect(url_for(
                "admin_history",
                search=search,
                department=department,
                type_filter=type_filter,
                late_only=late_only,
                absent_only=absent_only,
                over_break_only=over_break_only,
                date_from=date_from,
                date_to=date_to
            ))

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Attendance History"
        sheet.append([
            "Employee",
            "Username",
            "Work Date",
            "Record Type",
            "Time In",
            "Time Out",
            "Status",
            "Late Minutes",
            "Break Limit",
            "Break Minutes",
            "Overbreak Minutes",
            "Work Hours",
            "Proof File",
            "Admin Note"
        ])

        for item in records:
            row = item["row"]
            sheet.append([
                row["full_name"] or "",
                row["username"] or "",
                row["work_date"] or "",
                item["record_type"] or "Attendance",
                row["time_in"] or "",
                row["time_out"] or "",
                item["display_status"] or row["status"] or "",
                row["late_minutes"] if row["late_flag"] else 0,
                parse_break_limit_minutes(row["break_limit_minutes"]) if row.get("break_limit_minutes") is not None else 0,
                item["break_minutes"],
                item["over_break_minutes"],
                minutes_to_decimal_hours(item["work_minutes"]),
                row["proof_file"] or "",
                item["request_note"]
            ])

        output = BytesIO()
        workbook.save(output)
        output.seek(0)

        return Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename=\"attendance-history-{today_str()}.xlsx\"'}
        )
