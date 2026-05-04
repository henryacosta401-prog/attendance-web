def register_employee_attendance_routes(app, deps):
    DOCUMENT_EXTENSIONS = deps["DOCUMENT_EXTENSIONS"]
    IMAGE_EXTENSIONS = deps["IMAGE_EXTENSIONS"]
    append_attendance_to_google_sheet = deps["append_attendance_to_google_sheet"]
    auto_close_stale_attendance = deps["auto_close_stale_attendance"]
    create_notification = deps["create_notification"]
    describe_tardiness_policy_adjustment = deps["describe_tardiness_policy_adjustment"]
    execute_db = deps["execute_db"]
    flash = deps["flash"]
    get_attendance_by_id = deps["get_attendance_by_id"]
    get_attendance_override_block_message = deps["get_attendance_override_block_message"]
    get_current_attendance = deps["get_current_attendance"]
    get_employee_break_limit = deps["get_employee_break_limit"]
    get_employee_override_status_for_date = deps["get_employee_override_status_for_date"]
    get_manual_attendance_block_message = deps["get_manual_attendance_block_message"]
    get_open_break = deps["get_open_break"]
    get_user_by_id = deps["get_user_by_id"]
    invalidate_admin_employee_rows_cache = deps["invalidate_admin_employee_rows_cache"]
    is_overbreak = deps["is_overbreak"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    minutes_to_hm = deps["minutes_to_hm"]
    now_str = deps["now_str"]
    redirect = deps["redirect"]
    request = deps["request"]
    resolve_attendance_time_in_details = deps["resolve_attendance_time_in_details"]
    save_uploaded_file = deps["save_uploaded_file"]
    session = deps["session"]
    today_str = deps["today_str"]
    total_break_minutes = deps["total_break_minutes"]
    url_for = deps["url_for"]

    @app.route("/time-in", methods=["POST"])
    @login_required(role="employee")
    def time_in():
        user_id = session["user_id"]
        user = get_user_by_id(user_id)

        manual_attendance_block_message = get_manual_attendance_block_message()
        if manual_attendance_block_message:
            flash(manual_attendance_block_message, "warning")
            return redirect(url_for("employee_actions"))

        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        existing = auto_close_stale_attendance(user, get_current_attendance(user_id), actor_id=user_id, source_label="Employee portal")
        override_status = get_employee_override_status_for_date(user_id, today_str())
        override_block_message = get_attendance_override_block_message(override_status, "time_in", existing)
        if override_block_message:
            flash(override_block_message, "danger")
            return redirect(url_for("dashboard"))

        if existing and existing["time_in"] and not existing["time_out"]:
            flash("You are already timed in.", "warning")
            return redirect(url_for("dashboard"))

        file = request.files.get("proof_file")
        proof_filename = None

        if file and file.filename:
            try:
                proof_filename = save_uploaded_file(file, prefix=f"proof_{user_id}", allowed_exts=IMAGE_EXTENSIONS | DOCUMENT_EXTENSIONS)
            except RuntimeError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("dashboard"))
            if not proof_filename:
                flash("Invalid upload file type.", "danger")
                return redirect(url_for("dashboard"))

        action_timestamp = now_str()
        action_work_date = action_timestamp[:10]
        time_in_details = resolve_attendance_time_in_details(
            user_row=user,
            actual_time_in=action_timestamp,
            work_date=action_work_date,
        )
        recorded_time_in = time_in_details["recorded_time_in"] or action_timestamp
        policy_note = describe_tardiness_policy_adjustment(time_in_details)

        execute_db("""
            INSERT INTO attendance (
                user_id, work_date, time_in, actual_time_in, time_out, status, proof_file, notes,
                late_flag, late_minutes, effective_break_limit_minutes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            action_work_date,
            recorded_time_in,
            action_timestamp,
            None,
            "Timed In",
            proof_filename,
            request.form.get("notes", "").strip(),
            time_in_details["late_flag"],
            time_in_details["late_minutes"],
            time_in_details["effective_break_limit_minutes"],
            action_timestamp,
            action_timestamp
        ), commit=True)

        latest_attendance = get_current_attendance(user_id)

        if latest_attendance and latest_attendance["late_flag"]:
            late_message = (
                f"You timed in late by {latest_attendance['late_minutes']} minute(s). "
                f"Shift start: {time_in_details['shift_start']} ET."
            )
            if policy_note:
                late_message = f"{late_message} {policy_note}"
            create_notification(
                user_id,
                "Late Time-In",
                late_message
            )
        else:
            create_notification(user_id, "Timed In", f"You timed in at {recorded_time_in} ET.")

        log_activity(user_id, "TIME IN", f"Employee timed in. Shift: {time_in_details['shift_start']}")
        invalidate_admin_employee_rows_cache()
        success_message = "Time in successful."
        if policy_note:
            success_message = f"{success_message} {policy_note}"
        flash(success_message, "success")
        return redirect(url_for("dashboard"))


    @app.route("/start-break", methods=["POST"])
    @login_required(role="employee")
    def start_break():
        user_id = session["user_id"]
        user = get_user_by_id(user_id)
        manual_attendance_block_message = get_manual_attendance_block_message()
        if manual_attendance_block_message:
            flash(manual_attendance_block_message, "warning")
            return redirect(url_for("employee_actions"))
        attendance = auto_close_stale_attendance(user, get_current_attendance(user_id), actor_id=user_id, source_label="Employee portal")
        override_status = get_employee_override_status_for_date(user_id, today_str())
        override_block_message = get_attendance_override_block_message(override_status, "start_break", attendance)
        if override_block_message:
            flash(override_block_message, "danger")
            return redirect(url_for("dashboard"))

        if not attendance or not attendance["time_in"] or attendance["time_out"]:
            flash("You must be timed in first.", "danger")
            return redirect(url_for("dashboard"))

        open_break = get_open_break(user_id, attendance)
        if open_break:
            flash("You are already on break.", "warning")
            return redirect(url_for("dashboard"))

        break_limit_minutes = get_employee_break_limit(
            attendance,
            reference_datetime=attendance.get("time_in"),
            reference_date=attendance.get("work_date"),
        )
        if break_limit_minutes <= 0:
            flash("Breaks are not allowed for this shift under the tardiness policy.", "warning")
            return redirect(url_for("dashboard"))
        used_break_minutes = total_break_minutes(attendance["id"])
        if used_break_minutes >= break_limit_minutes:
            flash(f"Your daily break limit of {break_limit_minutes} minutes has already been used.", "warning")
            return redirect(url_for("dashboard"))

        action_timestamp = now_str()
        execute_db("""
            INSERT INTO breaks (user_id, attendance_id, work_date, break_start, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, attendance["id"], attendance["work_date"], action_timestamp, action_timestamp), commit=True)

        execute_db("""
            UPDATE attendance
            SET status = ?, updated_at = ?
            WHERE id = ?
        """, ("On Break", action_timestamp, attendance["id"]), commit=True)

        remaining_break = max(break_limit_minutes - used_break_minutes, 0)
        create_notification(user_id, "Break Started", f"You started break at {action_timestamp} ET. Remaining break allowance: {remaining_break} minute(s).")
        log_activity(user_id, "BREAK START", "Employee started break")
        invalidate_admin_employee_rows_cache()
        flash("Break started.", "info")
        return redirect(url_for("dashboard"))


    @app.route("/end-break", methods=["POST"])
    @login_required(role="employee")
    def end_break():
        user_id = session["user_id"]
        user = get_user_by_id(user_id)
        manual_attendance_block_message = get_manual_attendance_block_message()
        if manual_attendance_block_message:
            flash(manual_attendance_block_message, "warning")
            return redirect(url_for("employee_actions"))
        attendance = auto_close_stale_attendance(user, get_current_attendance(user_id), actor_id=user_id, source_label="Employee portal")
        override_status = get_employee_override_status_for_date(user_id, today_str())
        override_block_message = get_attendance_override_block_message(override_status, "end_break", attendance)
        if override_block_message:
            flash(override_block_message, "danger")
            return redirect(url_for("dashboard"))
        open_break = get_open_break(user_id, attendance)

        if not open_break:
            flash("No active break found.", "warning")
            return redirect(url_for("dashboard"))

        action_timestamp = now_str()
        execute_db("""
            UPDATE breaks
            SET break_end = ?
            WHERE id = ?
        """, (action_timestamp, open_break["id"]), commit=True)

        if attendance:
            execute_db("""
                UPDATE attendance
                SET status = ?, updated_at = ?
                WHERE id = ?
        """, ("Timed In", action_timestamp, attendance["id"]), commit=True)

        create_notification(user_id, "Break Ended", f"You ended break at {action_timestamp} ET.")
        if attendance:
            total_break = total_break_minutes(attendance["id"])
            break_limit_minutes = get_employee_break_limit(
                attendance,
                reference_datetime=attendance.get("time_in"),
                reference_date=attendance.get("work_date"),
            )
            if is_overbreak(total_break, break_limit_minutes):
                create_notification(
                    user_id,
                    "Break Limit Exceeded",
                    f"Your total break time for today is {minutes_to_hm(total_break)}, which is over your {break_limit_minutes} minute limit."
                )
        log_activity(user_id, "BREAK END", "Employee ended break")
        invalidate_admin_employee_rows_cache()
        flash("Break ended.", "success")
        return redirect(url_for("dashboard"))


    @app.route("/time-out", methods=["POST"])
    @login_required(role="employee")
    def time_out():
        user_id = session["user_id"]
        user = get_user_by_id(user_id)
        manual_attendance_block_message = get_manual_attendance_block_message()
        if manual_attendance_block_message:
            flash(manual_attendance_block_message, "warning")
            return redirect(url_for("employee_actions"))
        attendance = auto_close_stale_attendance(user, get_current_attendance(user_id), actor_id=user_id, source_label="Employee portal")
        override_status = get_employee_override_status_for_date(user_id, today_str())
        override_block_message = get_attendance_override_block_message(override_status, "time_out", attendance)
        if override_block_message:
            flash(override_block_message, "danger")
            return redirect(url_for("dashboard"))

        if not attendance or not attendance["time_in"]:
            flash("You are not timed in.", "danger")
            return redirect(url_for("dashboard"))

        if attendance["time_out"]:
            flash("You are already timed out.", "warning")
            return redirect(url_for("dashboard"))

        open_break = get_open_break(user_id, attendance)
        action_timestamp = now_str()
        if open_break:
            execute_db("""
                UPDATE breaks
                SET break_end = ?
                WHERE id = ?
            """, (action_timestamp, open_break["id"]), commit=True)

        execute_db("""
            UPDATE attendance
            SET time_out = ?, status = ?, updated_at = ?
            WHERE id = ?
        """, (action_timestamp, "Timed Out", action_timestamp, attendance["id"]), commit=True)

        total_break = total_break_minutes(attendance["id"])
        user_row = get_user_by_id(user_id)
        updated_attendance = get_attendance_by_id(attendance["id"])
        break_limit_minutes = get_employee_break_limit(
            updated_attendance,
            reference_datetime=updated_attendance.get("time_in") if updated_attendance else None,
            reference_date=updated_attendance.get("work_date") if updated_attendance else "",
        )
        ok, msg = append_attendance_to_google_sheet(user_row, updated_attendance)

        create_notification(user_id, "Timed Out", f"You timed out at {action_timestamp} ET.")
        if attendance and is_overbreak(total_break, break_limit_minutes):
            create_notification(
                user_id,
                "Break Limit Exceeded",
                f"Your total break time for today is {minutes_to_hm(total_break)}, which is over your {break_limit_minutes} minute limit."
            )
        log_activity(user_id, "TIME OUT", f"Employee timed out. Sheets sync: {msg if ok else 'Skipped/Failed'}")
        invalidate_admin_employee_rows_cache()
        flash("Time out successful.", "success")
        return redirect(url_for("dashboard"))
