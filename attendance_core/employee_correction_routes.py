def register_employee_correction_routes(app, deps):
    ABSENT_REQUEST_TYPES = deps["ABSENT_REQUEST_TYPES"]
    ATTENDANCE_REQUEST_TYPES = deps["ATTENDANCE_REQUEST_TYPES"]
    DATE_RANGE_REQUEST_TYPES = deps["DATE_RANGE_REQUEST_TYPES"]
    build_correction_request_summary = deps["build_correction_request_summary"]
    execute_db = deps["execute_db"]
    find_overlapping_date_range_request = deps["find_overlapping_date_range_request"]
    flash = deps["flash"]
    format_request_date_range = deps["format_request_date_range"]
    get_attendance_context = deps["get_attendance_context"]
    get_attendance_dates_in_request_range = deps["get_attendance_dates_in_request_range"]
    get_correction_requests = deps["get_correction_requests"]
    get_leave_balance_summary = deps["get_leave_balance_summary"]
    get_user_by_id = deps["get_user_by_id"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    normalize_optional_clock_time = deps["normalize_optional_clock_time"]
    normalize_request_date_range = deps["normalize_request_date_range"]
    now_str = deps["now_str"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    resolve_correction_datetimes = deps["resolve_correction_datetimes"]
    session = deps["session"]
    url_for = deps["url_for"]

    @app.route("/corrections", methods=["GET", "POST"])
    @login_required(role="employee")
    def employee_corrections():
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        if request.method == "POST":
            request_type = request.form.get("request_type", "").strip()
            work_date = request.form.get("work_date", "").strip()
            end_work_date = request.form.get("end_work_date", "").strip()
            message = request.form.get("message", "").strip()
            requested_time_in = request.form.get("requested_time_in", "")
            requested_break_start = request.form.get("requested_break_start", "")
            requested_break_end = request.form.get("requested_break_end", "")
            requested_time_out = request.form.get("requested_time_out", "")

            if request_type not in ATTENDANCE_REQUEST_TYPES:
                flash("Please choose a valid correction type.", "danger")
                return redirect(url_for("employee_corrections"))

            if not work_date or not message:
                flash("Work date and details are required.", "danger")
                return redirect(url_for("employee_corrections"))

            try:
                requested_time_in = normalize_optional_clock_time(requested_time_in)
                requested_break_start = normalize_optional_clock_time(requested_break_start)
                requested_break_end = normalize_optional_clock_time(requested_break_end)
                requested_time_out = normalize_optional_clock_time(requested_time_out)
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("employee_corrections"))

            if request_type == "Undertime" and not requested_time_out:
                flash("Requested time out is required for undertime requests.", "danger")
                return redirect(url_for("employee_corrections"))

            if request_type in DATE_RANGE_REQUEST_TYPES:
                try:
                    work_date, end_work_date = normalize_request_date_range(work_date, end_work_date or work_date)
                except ValueError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("employee_corrections"))
                requested_time_in = ""
                requested_break_start = ""
                requested_break_end = ""
                requested_time_out = ""

                existing_request = find_overlapping_date_range_request(user["id"], work_date, end_work_date)
                if existing_request:
                    flash(
                        f"An approved or pending {existing_request['request_type'].lower()} request already covers that date range.",
                        "warning",
                    )
                    return redirect(url_for("employee_corrections"))

                if request_type in ABSENT_REQUEST_TYPES:
                    attendance_conflict_dates = get_attendance_dates_in_request_range(user["id"], work_date, end_work_date)
                    if attendance_conflict_dates:
                        flash(
                            "Absent requests can only be used for dates without attendance records. "
                            f"Existing attendance was found on {format_request_date_range(attendance_conflict_dates[0], attendance_conflict_dates[-1])}.",
                            "warning",
                        )
                        return redirect(url_for("employee_corrections"))
            else:
                end_work_date = work_date

            attendance, break_row = get_attendance_context(user["id"], work_date)
            requested_time_in_dt, requested_break_start_dt, requested_break_end_dt, requested_time_out_dt = resolve_correction_datetimes(
                work_date,
                time_in_value=requested_time_in,
                break_start_value=requested_break_start,
                break_end_value=requested_break_end,
                time_out_value=requested_time_out,
                existing_time_in=attendance["time_in"] if attendance else None,
                existing_break_start=break_row["break_start"] if break_row else None,
                existing_break_end=break_row["break_end"] if break_row else None,
                existing_time_out=attendance["time_out"] if attendance else None,
                use_existing_values=False
            )

            execute_db("""
                INSERT INTO correction_requests (
                    user_id, request_type, work_date, end_work_date, message,
                    requested_time_in, requested_break_start, requested_break_end, requested_time_out,
                    status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
            """, (
                user["id"],
                request_type,
                work_date,
                end_work_date,
                message,
                requested_time_in_dt,
                requested_break_start_dt,
                requested_break_end_dt,
                requested_time_out_dt,
                now_str()
            ), commit=True)

            log_activity(user["id"], "CORRECTION REQUEST", f"Submitted {request_type} request for {format_request_date_range(work_date, end_work_date)}")
            flash("Correction request submitted.", "success")
            return redirect(url_for("employee_corrections"))

        requests = get_correction_requests(user_id=user["id"])
        leave_summary = get_leave_balance_summary(user)
        request_summary = build_correction_request_summary(requests)
        return render_template(
            "employee_corrections.html",
            user=user,
            requests=requests,
            leave_summary=leave_summary,
            request_summary=request_summary
        )
