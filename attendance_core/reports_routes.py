def register_reports_routes(app, deps):
    append_workbook_rows = deps["append_workbook_rows"]
    autosize_workbook_sheet = deps["autosize_workbook_sheet"]
    flash = deps["flash"]
    get_cached_admin_reports_data = deps["get_cached_admin_reports_data"]
    get_department_options = deps["get_department_options"]
    login_required = deps["login_required"]
    minutes_to_hm = deps["minutes_to_hm"]
    normalize_admin_report_filters = deps["normalize_admin_report_filters"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    url_for = deps["url_for"]
    workbook_to_response = deps["workbook_to_response"]

    @app.route("/admin/reports")
    @login_required(role="admin")
    def admin_reports():
        filters = normalize_admin_report_filters(
            request.args.get("date_from", "").strip(),
            request.args.get("date_to", "").strip(),
            request.args.get("department", "").strip(),
            request.args.get("period", "").strip()
        )
        report_data = get_cached_admin_reports_data(
            filters["date_from"],
            filters["date_to"],
            department_filter=filters["department_filter"]
        )
        return render_template(
            "admin_reports.html",
            departments=get_department_options(),
            period=filters["period"],
            period_label=filters["period_label"],
            date_from=filters["date_from_text"],
            date_to=filters["date_to_text"],
            department_filter=filters["department_filter"],
            report_data=report_data,
            minutes_to_hm=minutes_to_hm
        )


    @app.route("/admin/reports/export.xlsx")
    @login_required(role="admin")
    def export_admin_reports_excel():
        filters = normalize_admin_report_filters(
            request.args.get("date_from", "").strip(),
            request.args.get("date_to", "").strip(),
            request.args.get("department", "").strip(),
            request.args.get("period", "").strip()
        )
        report_data = get_cached_admin_reports_data(
            filters["date_from"],
            filters["date_to"],
            department_filter=filters["department_filter"]
        )
        try:
            from openpyxl import Workbook
        except Exception:
            flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
            return redirect(url_for(
                "admin_reports",
                period=filters["period"],
                date_from=filters["date_from_text"],
                date_to=filters["date_to_text"],
                department=filters["department_filter"]
            ))

        workbook = Workbook()
        summary_sheet = workbook.active
        summary_sheet.title = "Summary"
        summary_sheet.append(["Date From", filters["date_from_text"]])
        summary_sheet.append(["Date To", filters["date_to_text"]])
        summary_sheet.append(["Preset", filters["period_label"]])
        summary_sheet.append(["Department", filters["department_filter"] or "All Departments"])
        summary_sheet.append([])
        summary_sheet.append(["Metric", "Value"])
        for label, value in [
            ("Employees in scope", report_data["summary"]["employee_count"]),
            ("Attendance days", report_data["summary"]["attendance_days"]),
            ("Attendance hours", report_data["summary"]["attendance_hours"]),
            ("Average hours per active day", report_data["summary"]["avg_hours_per_day"]),
            ("Average hours per employee", report_data["summary"]["avg_hours_per_employee"]),
            ("Late punches", report_data["summary"]["late_punches"]),
            ("Late rate percent", report_data["summary"]["late_rate_percent"]),
            ("Overtime hours", report_data["summary"]["overtime_hours"]),
            ("Overtime share percent", report_data["summary"]["overtime_share_percent"]),
            ("Break minutes", report_data["summary"]["break_minutes"]),
            ("Leave requests", report_data["summary"]["leave_requests"]),
            ("Incident follow-ups", report_data["summary"]["incident_follow_ups"]),
            ("Pending corrections", report_data["summary"]["pending_corrections"]),
            ("Incident reports", report_data["summary"]["incident_reports"]),
            ("Released payroll runs", report_data["summary"]["released_payroll_runs"]),
            ("Released payroll rows", report_data["summary"]["released_payroll_rows"]),
            ("Released payroll total", report_data["summary"]["released_payroll_total"]),
        ]:
            summary_sheet.append([label, value])
        autosize_workbook_sheet(summary_sheet)

        append_workbook_rows(workbook, "Trend Highlights", report_data["trend_highlights"])
        append_workbook_rows(workbook, "Department Highlights", report_data["department_highlights"])
        append_workbook_rows(workbook, "Case Summary", report_data["case_rows"])
        append_workbook_rows(workbook, "Department Summary", report_data["department_rows"])
        append_workbook_rows(workbook, "Daily Trend", report_data["daily_rows"])
        append_workbook_rows(workbook, "Leave Summary", report_data["leave_rows"])
        append_workbook_rows(workbook, "Correction Summary", report_data["correction_rows"])
        append_workbook_rows(workbook, "Incident Summary", report_data["incident_rows"])
        append_workbook_rows(workbook, "Employee Leaders", report_data["top_employee_rows"])
        append_workbook_rows(workbook, "Payroll Summary", report_data["payroll_department_rows"])
        append_workbook_rows(workbook, "Released Payroll", report_data["released_runs"])
        filename = f"admin-reports-{filters['date_from_text']}-to-{filters['date_to_text']}.xlsx"
        return workbook_to_response(workbook, filename)
