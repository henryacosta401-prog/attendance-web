def register_employee_portal_routes(app, deps):
    IMAGE_EXTENSIONS = deps["IMAGE_EXTENSIONS"]
    build_break_sessions = deps["build_break_sessions"]
    build_employee_attendance_calendar = deps["build_employee_attendance_calendar"]
    build_employee_history_records = deps["build_employee_history_records"]
    clear_resolved_break_limit_notifications = deps["clear_resolved_break_limit_notifications"]
    execute_db = deps["execute_db"]
    fetchall = deps["fetchall"]
    flash = deps["flash"]
    generate_password_hash = deps["generate_password_hash"]
    get_employee_break_limit = deps["get_employee_break_limit"]
    get_employee_error_record_summary = deps["get_employee_error_record_summary"]
    get_employee_override_status_for_date = deps["get_employee_override_status_for_date"]
    get_employee_released_payroll_runs = deps["get_employee_released_payroll_runs"]
    get_leave_balance_summary = deps["get_leave_balance_summary"]
    get_live_attendance_context = deps["get_live_attendance_context"]
    get_manual_attendance_block_message = deps["get_manual_attendance_block_message"]
    get_open_break = deps["get_open_break"]
    get_open_overtime_session = deps["get_open_overtime_session"]
    get_overbreak_minutes = deps["get_overbreak_minutes"]
    get_user_by_id = deps["get_user_by_id"]
    get_user_live_status = deps["get_user_live_status"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    make_response = deps["make_response"]
    minutes_to_hm = deps["minutes_to_hm"]
    now_dt = deps["now_dt"]
    parse_calendar_month = deps["parse_calendar_month"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    save_uploaded_file = deps["save_uploaded_file"]
    session = deps["session"]
    today_str = deps["today_str"]
    total_break_minutes = deps["total_break_minutes"]
    total_work_minutes = deps["total_work_minutes"]
    url_for = deps["url_for"]

    @app.route("/dashboard")
    @login_required(role="employee")
    def dashboard():
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        open_overtime = get_open_overtime_session(
            user["id"],
            actor_id=user["id"],
            source_label="Employee dashboard",
        )
        today_attendance = get_live_attendance_context(
            user["id"],
            overtime_row=open_overtime,
            source_label="Employee dashboard",
        )
        open_break = get_open_break(user["id"], today_attendance)
        clear_resolved_break_limit_notifications(
            user,
            attendance_row=today_attendance,
            include_open_overtime=True,
        )

        notifications = fetchall("""
            SELECT * FROM notifications
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
        """, (user["id"],))

        logs = fetchall("""
            SELECT * FROM activity_logs
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
        """, (user["id"],))

        current_status = "On Overtime" if open_overtime else get_user_live_status(user["id"])
        override_status = get_employee_override_status_for_date(user["id"], today_str())
        if override_status:
            current_status = override_status["label"]
        todays_break_minutes = total_break_minutes(today_attendance["id"], include_open=True) if today_attendance else 0
        todays_work_minutes = total_work_minutes(today_attendance) if today_attendance else 0
        todays_break_sessions = build_break_sessions(today_attendance["id"]) if today_attendance else []
        break_limit_minutes = get_employee_break_limit(
            today_attendance or user,
            reference_datetime=today_attendance.get("time_in") if today_attendance else None,
            reference_date=today_attendance.get("work_date") if today_attendance else today_str(),
            include_open_overtime=True,
        )
        over_break_minutes = get_overbreak_minutes(todays_break_minutes, break_limit_minutes)
        leave_summary = get_leave_balance_summary(user)
        error_record_summary = get_employee_error_record_summary(user["id"])
        latest_payslip = None
        released_runs = get_employee_released_payroll_runs(user["id"], limit=1)
        if released_runs:
            latest_payslip = released_runs[0]

        return render_template(
            "employee_dashboard.html",
            user=user,
            today_attendance=today_attendance,
            notifications=notifications,
            current_status=current_status,
            override_status=override_status,
            todays_break_minutes=todays_break_minutes,
            todays_work_minutes=todays_work_minutes,
            todays_break_sessions=todays_break_sessions,
            leave_summary=leave_summary,
            break_limit_minutes=break_limit_minutes,
            over_break_minutes=over_break_minutes,
            minutes_to_hm=minutes_to_hm,
            latest_payslip=latest_payslip,
            error_record_summary=error_record_summary,
            current_calendar_year=now_dt().year,
            current_calendar_month=now_dt().month,
            current_calendar_label=now_dt().strftime("%B %Y")
        )


    @app.route("/actions")
    @login_required(role="employee")
    def employee_actions():
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        manual_attendance_block_message = get_manual_attendance_block_message()
        if manual_attendance_block_message:
            flash(manual_attendance_block_message, "info")
            return redirect(url_for("dashboard"))

        return render_template(
            "employee_actions.html",
            user=user,
            manual_attendance_block_message=manual_attendance_block_message
        )


    @app.route("/activity")
    @login_required(role="employee")
    def employee_activity():
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        logs = fetchall("""
            SELECT * FROM activity_logs
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 50
        """, (user["id"],))

        return render_template("employee_activity.html", user=user, logs=logs)


    @app.route("/history")
    @login_required(role="employee")
    def employee_history():
        user = get_user_by_id(session["user_id"])
        records = build_employee_history_records(user, limit=60)
        return render_template("employee_history.html", records=records, minutes_to_hm=minutes_to_hm)


    @app.route("/attendance-calendar")
    @login_required(role="employee")
    def employee_attendance_calendar():
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        year, month = parse_calendar_month(
            request.args.get("year", ""),
            request.args.get("month", "")
        )
        calendar_data = build_employee_attendance_calendar(user, year, month)
        response = make_response(render_template(
            "employee_attendance_calendar.html",
            user=user,
            calendar_data=calendar_data,
            auto_refresh_interval_seconds=45,
        ))
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


    @app.route("/profile", methods=["GET", "POST"])
    @login_required(role="employee")
    def employee_profile():
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            if not full_name:
                flash("Full name is required.", "danger")
                return redirect(url_for("employee_profile"))

            password = request.form.get("password", "").strip()

            profile_image = user["profile_image"]
            file = request.files.get("profile_image")
            if file and file.filename:
                try:
                    saved = save_uploaded_file(file, prefix=f"profile_{user['id']}", allowed_exts=IMAGE_EXTENSIONS)
                except RuntimeError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("employee_profile"))
                if not saved:
                    flash("Invalid profile image type.", "danger")
                    return redirect(url_for("employee_profile"))
                profile_image = saved

            if password:
                execute_db("""
                    UPDATE users
                    SET full_name = ?, password_hash = ?, profile_image = ?
                    WHERE id = ?
                """, (full_name, generate_password_hash(password), profile_image, user["id"]), commit=True)
            else:
                execute_db("""
                    UPDATE users
                    SET full_name = ?, profile_image = ?
                    WHERE id = ?
                """, (full_name, profile_image, user["id"]), commit=True)

            session["full_name"] = full_name
            log_activity(user["id"], "UPDATE PROFILE", "Employee updated profile")
            flash("Profile updated successfully.", "success")
            return redirect(url_for("employee_profile"))

        return render_template("employee_profile.html", user=user)
