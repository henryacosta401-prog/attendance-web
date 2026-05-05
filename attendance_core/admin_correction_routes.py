def register_admin_correction_routes(app, deps):
    ABSENT_REQUEST_TYPES = deps["ABSENT_REQUEST_TYPES"]
    APPROVED_SPECIAL_REQUEST_TYPES = deps["APPROVED_SPECIAL_REQUEST_TYPES"]
    DATE_RANGE_REQUEST_TYPES = deps["DATE_RANGE_REQUEST_TYPES"]
    NO_TIMESTAMP_REQUEST_TYPES = deps["NO_TIMESTAMP_REQUEST_TYPES"]
    apply_attendance_correction = deps["apply_attendance_correction"]
    combine_work_date_and_time = deps["combine_work_date_and_time"]
    create_notification = deps["create_notification"]
    describe_request_review_result = deps["describe_request_review_result"]
    execute_db = deps["execute_db"]
    fetchone = deps["fetchone"]
    find_overlapping_date_range_request = deps["find_overlapping_date_range_request"]
    flash = deps["flash"]
    format_request_date_range = deps["format_request_date_range"]
    get_attendance_dates_in_request_range = deps["get_attendance_dates_in_request_range"]
    get_correction_requests = deps["get_correction_requests"]
    get_matching_attendance_context_for_request = deps["get_matching_attendance_context_for_request"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    normalize_optional_clock_time = deps["normalize_optional_clock_time"]
    now_str = deps["now_str"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    resolve_correction_datetimes = deps["resolve_correction_datetimes"]
    session = deps["session"]
    url_for = deps["url_for"]

    @app.route("/admin/corrections")
    @login_required(role="admin")
    def admin_corrections():
        status = request.args.get("status", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()
        requests = get_correction_requests(status=status, date_from=date_from, date_to=date_to)

        return render_template(
            "admin_corrections.html",
            requests=requests,
            status=status,
            date_from=date_from,
            date_to=date_to
        )


    @app.route("/admin/corrections/<int:request_id>/update", methods=["POST"])
    @login_required(role="admin")
    def update_correction_request(request_id):
        status = request.form.get("status", "").strip()
        admin_note = request.form.get("admin_note", "").strip()
        requested_time_in = request.form.get("requested_time_in", "")
        requested_break_start = request.form.get("requested_break_start", "")
        requested_break_end = request.form.get("requested_break_end", "")
        requested_time_out = request.form.get("requested_time_out", "")

        if status not in {"Pending", "Approved", "Rejected"}:
            flash("Invalid correction status.", "danger")
            return redirect(url_for("admin_corrections"))

        correction = fetchone("""
            SELECT c.*, u.full_name
            FROM correction_requests c
            JOIN users u ON u.id = c.user_id
            WHERE c.id = ?
        """, (request_id,))

        if not correction:
            flash("Correction request not found.", "danger")
            return redirect(url_for("admin_corrections"))

        current_status = (correction["status"] or "").strip()
        review_locked = current_status in {"Approved", "Rejected"}
        if review_locked and status != current_status:
            flash(
                f"This correction request is already {current_status.lower()}. "
                "Update the note only, or create a new request if another correction is needed.",
                "warning",
            )
            return redirect(url_for("admin_corrections"))

        if review_locked:
            execute_db("""
                UPDATE correction_requests
                SET admin_note = ?
                WHERE id = ?
            """, (
                admin_note,
                request_id
            ), commit=True)
            flash("Reviewed correction note updated.", "success")
            return redirect(url_for("admin_corrections"))

        applied_changes = correction["applied_changes"] if "applied_changes" in correction.keys() else None

        try:
            requested_time_in = normalize_optional_clock_time(requested_time_in)
            requested_break_start = normalize_optional_clock_time(requested_break_start)
            requested_break_end = normalize_optional_clock_time(requested_break_end)
            requested_time_out = normalize_optional_clock_time(requested_time_out)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("admin_corrections"))

        if correction["request_type"] in NO_TIMESTAMP_REQUEST_TYPES:
            requested_time_in = ""
            requested_break_start = ""
            requested_break_end = ""
            requested_time_out = ""
        elif correction["request_type"] == "Undertime" and status == "Approved" and not requested_time_out:
            flash("Requested time out is required to approve an undertime request.", "danger")
            return redirect(url_for("admin_corrections"))

        reviewed_at = now_str() if status in {"Approved", "Rejected"} else None
        reviewed_by = session["user_id"] if status in {"Approved", "Rejected"} else None

        if status == "Approved":
            if correction["request_type"] in DATE_RANGE_REQUEST_TYPES:
                overlapping_request = find_overlapping_date_range_request(
                    correction["user_id"],
                    correction["work_date"],
                    correction.get("end_work_date") or correction["work_date"],
                    exclude_id=request_id,
                )
                if overlapping_request:
                    flash(
                        f"An approved or pending {overlapping_request['request_type'].lower()} request already covers that date range.",
                        "warning",
                    )
                    return redirect(url_for("admin_corrections"))
            if correction["request_type"] in ABSENT_REQUEST_TYPES:
                attendance_conflict_dates = get_attendance_dates_in_request_range(
                    correction["user_id"],
                    correction["work_date"],
                    correction.get("end_work_date") or correction["work_date"],
                )
                if attendance_conflict_dates:
                    flash(
                        "Absent requests can only be approved for dates without attendance records. "
                        f"Existing attendance was found on {format_request_date_range(attendance_conflict_dates[0], attendance_conflict_dates[-1])}.",
                        "warning",
                    )
                    return redirect(url_for("admin_corrections"))

            if correction["request_type"] in APPROVED_SPECIAL_REQUEST_TYPES:
                if correction["request_type"] == "Undertime":
                    requested_time_out_dt = combine_work_date_and_time(correction["work_date"], requested_time_out) if requested_time_out else None
                    attendance, _ = get_matching_attendance_context_for_request(
                        correction["user_id"],
                        correction["work_date"],
                        request_type=correction["request_type"],
                        requested_time_out=requested_time_out_dt
                    )
                else:
                    attendance = None
                if correction["request_type"] == "Undertime" and attendance and requested_time_out:
                    try:
                        applied_changes = apply_attendance_correction(
                            correction["user_id"],
                            attendance["work_date"],
                            time_out_value=requested_time_out
                        )
                    except ValueError as exc:
                        flash(str(exc), "danger")
                        return redirect(url_for("admin_corrections"))
                else:
                    applied_changes = describe_request_review_result(
                        correction["request_type"],
                        format_request_date_range(correction["work_date"], correction.get("end_work_date")),
                        requested_time_out
                    )
            else:
                try:
                    applied_changes = apply_attendance_correction(
                        correction["user_id"],
                        correction["work_date"],
                        time_in_value=requested_time_in,
                        break_start_value=requested_break_start,
                        break_end_value=requested_break_end,
                        time_out_value=requested_time_out
                    )
                except ValueError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("admin_corrections"))

        preview_request_type = correction["request_type"] if correction["request_type"] == "Undertime" else ""
        preview_requested_time_out = combine_work_date_and_time(correction["work_date"], requested_time_out) if requested_time_out else None
        attendance, break_row = get_matching_attendance_context_for_request(
            correction["user_id"],
            correction["work_date"],
            request_type=preview_request_type,
            requested_time_out=preview_requested_time_out
        )
        preview_work_date = attendance["work_date"] if attendance and correction["request_type"] == "Undertime" else correction["work_date"]

        if correction["request_type"] == "Undertime":
            requested_break_start = ""
            requested_break_end = ""
        elif correction["request_type"] in NO_TIMESTAMP_REQUEST_TYPES:
            requested_time_in = ""
            requested_break_start = ""
            requested_break_end = ""
            requested_time_out = ""

        requested_time_in_dt, requested_break_start_dt, requested_break_end_dt, requested_time_out_dt = resolve_correction_datetimes(
            preview_work_date,
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
            UPDATE correction_requests
            SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = ?,
                requested_time_in = ?, requested_break_start = ?, requested_break_end = ?, requested_time_out = ?,
                applied_changes = ?
            WHERE id = ?
        """, (
            status,
            admin_note,
            reviewed_by,
            reviewed_at,
            requested_time_in_dt,
            requested_break_start_dt,
            requested_break_end_dt,
            requested_time_out_dt,
            applied_changes if status == "Approved" else None,
            request_id
        ), commit=True)

        notification_message = f"Your {correction['request_type']} request for {correction['work_date']} is now {status}."
        if correction["request_type"] in DATE_RANGE_REQUEST_TYPES:
            notification_message = f"Your {correction['request_type']} request for {format_request_date_range(correction['work_date'], correction.get('end_work_date'))} is now {status}."
        if status == "Approved" and applied_changes:
            notification_message = f"{notification_message} Applied: {applied_changes}"

        create_notification(
            correction["user_id"],
            "Correction Request Updated",
            notification_message
        )
        log_details = f"{status} correction request #{request_id} for {correction['full_name']}"
        if status == "Approved" and applied_changes:
            log_details = f"{log_details} | {applied_changes}"
        log_activity(session["user_id"], "REVIEW CORRECTION", log_details, target_user_id=correction["user_id"])
        flash("Correction request updated.", "success")
        return redirect(url_for("admin_corrections"))
