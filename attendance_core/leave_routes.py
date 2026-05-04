def register_leave_routes(app, deps):
    BytesIO = deps["BytesIO"]
    Response = deps["Response"]
    build_leave_dashboard_rows = deps["build_leave_dashboard_rows"]
    flash = deps["flash"]
    get_department_options = deps["get_department_options"]
    get_employee_options = deps["get_employee_options"]
    get_pending_leave_requests = deps["get_pending_leave_requests"]
    login_required = deps["login_required"]
    now_dt = deps["now_dt"]
    parse_positive_int = deps["parse_positive_int"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    url_for = deps["url_for"]

    @app.route("/admin/leave")
    @login_required(role="admin")
    def admin_leave_dashboard():
        year = parse_positive_int(request.args.get("year", str(now_dt().year)), now_dt().year)
        department = request.args.get("department", "").strip()
        employee_id = request.args.get("employee_id", "").strip()
        departments = get_department_options()
        employee_options = get_employee_options()
        if department:
            employee_options = [row for row in employee_options if (row.get("department") or "") == department]
        leave_rows = build_leave_dashboard_rows(year=year, department=department, user_id=employee_id or None)
        pending_requests = get_pending_leave_requests(user_id=employee_id or None, department=department, year=year)

        stats = {
            "employees": len(leave_rows),
            "sick_used": sum(row["sick_used"] for row in leave_rows),
            "paid_used": sum(row["paid_used"] for row in leave_rows),
            "sick_remaining": sum(row["sick_remaining"] for row in leave_rows),
            "paid_remaining": sum(row["paid_remaining"] for row in leave_rows),
            "pending_total": sum(row["pending_total"] for row in leave_rows),
            "sick_exhausted": len([row for row in leave_rows if row["sick_remaining"] <= 0]),
            "paid_exhausted": len([row for row in leave_rows if row["paid_remaining"] <= 0]),
            "overdue_pending": len([row for row in pending_requests if int(row.get("age_days") or 0) >= 3]),
        }

        return render_template(
            "admin_leave_dashboard.html",
            leave_rows=leave_rows,
            pending_requests=pending_requests,
            departments=departments,
            employees=employee_options,
            department=department,
            employee_id=employee_id,
            year=year,
            stats=stats
        )


    @app.route("/admin/leave/export.xlsx")
    @login_required(role="admin")
    def export_admin_leave_dashboard_excel():
        year = parse_positive_int(request.args.get("year", str(now_dt().year)), now_dt().year)
        department = request.args.get("department", "").strip()
        employee_id = request.args.get("employee_id", "").strip()
        leave_rows = build_leave_dashboard_rows(year=year, department=department, user_id=employee_id or None)

        try:
            from openpyxl import Workbook
        except Exception:
            flash("Excel export requires openpyxl. Install dependencies and try again.", "danger")
            return redirect(url_for("admin_leave_dashboard", year=year, department=department, employee_id=employee_id))

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Leave Dashboard"
        selected_employee_name = ""
        if employee_id:
            selected_employee = next((row for row in get_employee_options() if str(row["id"]) == employee_id), None)
            selected_employee_name = selected_employee["full_name"] if selected_employee else employee_id
        sheet.append(["Year", year])
        sheet.append(["Department", department or "All Departments"])
        sheet.append(["Employee", selected_employee_name or "All Employees"])
        sheet.append([])
        sheet.append([
            "Employee", "Username", "Department", "Sick Allotment", "Sick Used", "Sick Remaining",
            "Paid Allotment", "Paid Used", "Paid Remaining", "Pending Sick", "Pending Paid",
            "Manual Sick Used", "Manual Paid Used", "Approved Sick Used", "Approved Paid Used"
        ])
        for row in leave_rows:
            sheet.append([
                row["full_name"], row["username"], row["department"], row["sick_total"], row["sick_used"], row["sick_remaining"],
                row["paid_total"], row["paid_used"], row["paid_remaining"], row["pending_sick"], row["pending_paid"],
                row["sick_used_manual"], row["paid_used_manual"], row["sick_used_in_app"], row["paid_used_in_app"]
            ])

        output = BytesIO()
        workbook.save(output)
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="leave-dashboard-{year}.xlsx"'}
        )
