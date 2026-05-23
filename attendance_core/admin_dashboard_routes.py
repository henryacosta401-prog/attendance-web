def register_admin_dashboard_routes(app, deps):
    BREAK_LIMIT_MINUTES = deps["BREAK_LIMIT_MINUTES"]
    build_admin_live_status_payload = deps["build_admin_live_status_payload"]
    fetchall = deps["fetchall"]
    fetchone = deps["fetchone"]
    filter_admin_employee_rows = deps["filter_admin_employee_rows"]
    flash = deps["flash"]
    get_admin_employee_rows = deps["get_admin_employee_rows"]
    get_department_options = deps["get_department_options"]
    get_exception_collections = deps["get_exception_collections"]
    get_today_schedule_code = deps["get_today_schedule_code"]
    get_user_by_id = deps["get_user_by_id"]
    jsonify = deps["jsonify"]
    login_required = deps["login_required"]
    notify_admins_for_exceptions = deps["notify_admins_for_exceptions"]
    notify_admins_for_leave_and_disciplinary_events = deps["notify_admins_for_leave_and_disciplinary_events"]
    now_str = deps["now_str"]
    paginate_items = deps["paginate_items"]
    parse_positive_int = deps["parse_positive_int"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    session = deps["session"]
    today_str = deps["today_str"]
    url_for = deps["url_for"]

    @app.route("/admin")
    @login_required(role="admin")
    def admin_dashboard():
        current_admin = get_user_by_id(session["user_id"])
        if not current_admin:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        status_filter = request.args.get("status", "").strip()
        search = request.args.get("search", "").strip()
        department_filter = request.args.get("department", "").strip()
        over_break_only = request.args.get("over_break_only", "").strip()
        page = parse_positive_int(request.args.get("page", "1"), 1)
        page_size = parse_positive_int(request.args.get("page_size", "25"), 25)

        all_employee_rows = get_admin_employee_rows()
        filtered_rows = filter_admin_employee_rows(
            all_employee_rows,
            status_filter=status_filter,
            search=search,
            department_filter=department_filter,
            over_break_only=over_break_only
        )
        pagination = paginate_items(filtered_rows, page, page_size)
        employees = pagination["items"]
        departments = get_department_options()

        logs = fetchall("""
            SELECT a.*, u.full_name
            FROM activity_logs a
            JOIN users u ON u.id = a.user_id
            ORDER BY a.id DESC
            LIMIT 25
        """)

        late_today_row = fetchone("""
            SELECT COUNT(*) AS cnt
            FROM attendance
            WHERE work_date = ? AND late_flag = 1
        """, (today_str(),))
        late_today = late_today_row["cnt"] if late_today_row else 0
        active_users = [row for row in all_employee_rows if row["is_active"] == 1]
        exception_groups = get_exception_collections(all_employee_rows)
        notify_admins_for_exceptions(exception_groups)
        notify_admins_for_leave_and_disciplinary_events()
        admin_notifications = fetchall("""
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 8
        """, (session["user_id"],))

        break_statuses = {"On Break", "On Paid Break", "On Power Nap Break", "On POWER NAP BREAK"}
        stats = {
            "total_employees": len(active_users),
            "scheduled_today": len([emp for emp in all_employee_rows if emp["scheduled_today"] == 1 and emp["is_active"] == 1]),
            "absent_today": len(exception_groups["absent"]),
            "timed_in": len([emp for emp in all_employee_rows if emp["status_display"] == "Timed In"]),
            "on_break": len([emp for emp in all_employee_rows if emp["status_display"] in break_statuses]),
            "timed_out": len([emp for emp in all_employee_rows if emp["status_display"] == "Timed Out"]),
            "late_today": late_today,
            "over_break_today": len(exception_groups["over_break"]),
            "missing_timeout": len(exception_groups["missing_timeout"]),
            "undertime_today": len(exception_groups["undertime"])
        }

        return render_template(
            "admin_dashboard.html",
            employees=employees,
            pagination=pagination,
            logs=logs,
            stats=stats,
            break_limit_minutes=BREAK_LIMIT_MINUTES,
            status_filter=status_filter,
            search=search,
            department_filter=department_filter,
            departments=departments,
            over_break_only=over_break_only,
            today_schedule_code=get_today_schedule_code(),
            exception_groups=exception_groups,
            admin_notifications=admin_notifications
        )


    @app.route("/admin/live-status")
    @login_required(role="admin")
    def admin_live_status():
        page = parse_positive_int(request.args.get("page", "1"), 1)
        page_size = parse_positive_int(request.args.get("page_size", "25"), 25)
        rows = get_admin_employee_rows(
            status_filter=request.args.get("status", "").strip(),
            search=request.args.get("search", "").strip(),
            department_filter=request.args.get("department", "").strip(),
            over_break_only=request.args.get("over_break_only", "").strip()
        )
        pagination = paginate_items(rows, page, page_size)
        return jsonify({
            "rows": build_admin_live_status_payload(pagination["items"]),
            "pagination": {
                "page": pagination["page"],
                "page_size": pagination["page_size"],
                "total": pagination["total"],
                "total_pages": pagination["total_pages"],
                "has_prev": pagination["has_prev"],
                "has_next": pagination["has_next"],
                "start_index": pagination["start_index"],
                "end_index": pagination["end_index"],
            },
            "generated_at": now_str(),
        })
