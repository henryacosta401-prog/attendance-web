def register_scanner_routes(app, deps):
    login_required = deps["login_required"]

    @app.route("/scanner")
    @login_required(role="scanner")
    def scanner_kiosk():
        return deps["render_template"]("scanner.html")

    @app.route("/scanner/unlock", methods=["POST"])
    @login_required(role="scanner")
    def scanner_kiosk_unlock():
        pin_value = (deps["request"].form.get("pin", "") or "").strip()
        if not deps["has_scanner_exit_pin"]():
            return deps["jsonify"]({"ok": True, "message": "Scanner unlocked."})
        if deps["verify_scanner_exit_pin"](pin_value):
            return deps["jsonify"]({"ok": True, "message": "Scanner unlocked."})
        return deps["jsonify"]({"ok": False, "message": "Incorrect kiosk PIN."}), 403

    @app.route("/admin/scanner-logs")
    @login_required(role="admin")
    def admin_scanner_logs():
        request = deps["request"]
        date_from = (request.args.get("date_from", "") or "").strip()
        date_to = (request.args.get("date_to", "") or "").strip()
        action_type = (request.args.get("action_type", "") or "").strip()
        result_status = (request.args.get("result_status", "") or "").strip()
        employee_id = (request.args.get("employee_id", "") or "").strip()

        if date_from and date_to:
            try:
                start_date = deps["datetime"].strptime(date_from, "%Y-%m-%d").date()
                end_date = deps["datetime"].strptime(date_to, "%Y-%m-%d").date()
                if start_date > end_date:
                    date_from, date_to = date_to, date_from
            except ValueError:
                pass

        where_clauses = []
        params = []

        if date_from:
            where_clauses.append("sl.created_at >= ?")
            params.append(f"{date_from} 00:00:00")
        if date_to:
            where_clauses.append("sl.created_at <= ?")
            params.append(f"{date_to} 23:59:59")
        if action_type:
            where_clauses.append("sl.action_type = ?")
            params.append(action_type)
        if result_status:
            where_clauses.append("sl.result_status = ?")
            params.append(result_status)
        if employee_id.isdigit():
            where_clauses.append("sl.employee_user_id = ?")
            params.append(int(employee_id))

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        scanner_exprs = deps["get_scanner_log_select_expressions"]()

        rows = deps["fetchall"](f"""
            SELECT
                sl.*,
                {scanner_exprs['scanner_name']} AS scanner_name,
                {scanner_exprs['scanner_username']} AS scanner_username,
                {scanner_exprs['employee_name']} AS employee_name,
                {scanner_exprs['employee_department']} AS employee_department,
                {scanner_exprs['employee_position']} AS employee_position
            FROM scanner_logs sl
            LEFT JOIN users scanner ON scanner.id = sl.scanner_user_id
            LEFT JOIN users employee ON employee.id = sl.employee_user_id
            {where_sql}
            ORDER BY sl.created_at DESC, sl.id DESC
            LIMIT 300
        """, tuple(params))

        stats = deps["fetchone"](f"""
            SELECT
                SUM(COALESCE(sl.repeat_count, 1)) AS total_scans,
                SUM(CASE WHEN sl.result_status = 'success' THEN COALESCE(sl.repeat_count, 1) ELSE 0 END) AS success_count,
                SUM(CASE WHEN sl.result_status = 'error' THEN COALESCE(sl.repeat_count, 1) ELSE 0 END) AS error_count,
                SUM(CASE WHEN substr(sl.created_at, 1, 10) = ? THEN COALESCE(sl.repeat_count, 1) ELSE 0 END) AS today_count
            FROM scanner_logs sl
            {where_sql}
        """, tuple([deps["today_str"](), *params])) or {}

        employees = deps["fetchall"]("""
            SELECT id, full_name, department
            FROM users
            WHERE role = 'employee'
            ORDER BY full_name
        """)

        return deps["render_template"](
            "admin_scanner_logs.html",
            scanner_logs=rows,
            stats=stats,
            date_from=date_from,
            date_to=date_to,
            action_type=action_type,
            result_status=result_status,
            employee_id=employee_id,
            employees=employees
        )

    @app.route("/scanner/scan", methods=["POST"])
    @login_required(role="scanner")
    def scanner_kiosk_scan():
        request = deps["request"]
        action_type = (request.form.get("action_type", "") or "").strip()
        barcode_value = (request.form.get("barcode_value", "") or "").strip()
        scanner_user_id = deps["session"].get("user_id")
        scanner_user = deps["get_user_by_id"](scanner_user_id)
        source_label = "Tablet kiosk"
        device_label = "Tablet camera kiosk"
        ip_address = deps["get_client_ip"]()
        user_agent = request.headers.get("User-Agent", "")
        scanner_log_kwargs = {
            "source_label": source_label,
            "device_label": device_label,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "scanner_name_snapshot": deps["row_get"](scanner_user, "full_name"),
            "scanner_username_snapshot": deps["row_get"](scanner_user, "username"),
        }

        if action_type not in {"time_in", "start_break", "end_break", "time_out", "overtime_start", "overtime_end"}:
            deps["log_scanner_activity"](
                scanner_user_id, action_type, barcode_value, "error",
                "Please choose a valid attendance action.",
                **scanner_log_kwargs
            )
            return deps["jsonify"]({"ok": False, "message": "Please choose a valid attendance action."}), 400

        if not barcode_value:
            deps["log_scanner_activity"](
                scanner_user_id, action_type, barcode_value, "error",
                "Scan or enter a Barcode ID first.",
                **scanner_log_kwargs
            )
            return deps["jsonify"]({"ok": False, "message": "Scan or enter a Barcode ID first."}), 400

        barcode_lookup = deps["find_employee_barcode_matches"](barcode_value)
        if barcode_lookup["is_duplicate"]:
            deps["log_scanner_activity"](
                scanner_user_id, action_type, barcode_value, "error",
                "This Barcode ID matches multiple employees. Fix the Barcode ID records first.",
                **scanner_log_kwargs
            )
            return deps["jsonify"]({
                "ok": False,
                "message": "This Barcode ID matches multiple employees. Fix the Barcode ID records first."
            }), 409

        employee = barcode_lookup["matches"][0] if barcode_lookup["matches"] else None
        if not employee:
            deps["log_scanner_activity"](
                scanner_user_id, action_type, barcode_value, "error",
                "No employee matched that Barcode ID. Check the Barcode ID first.",
                **scanner_log_kwargs
            )
            return deps["jsonify"]({"ok": False, "message": "No employee matched that Barcode ID. Check the Barcode ID first."}), 404

        ok, message, employee_row = deps["perform_attendance_action"](
            employee["id"],
            action_type,
            actor_id=scanner_user_id,
            source_label=source_label
        )
        employee_for_payload = employee_row or employee
        attendance = deps["get_current_attendance"](employee["id"])
        overtime_session = deps["get_open_overtime_session"](employee["id"])
        break_minutes = deps["total_break_minutes"](attendance["id"], include_open=True) if attendance else 0
        deps["log_scanner_activity"](
            scanner_user_id,
            action_type,
            barcode_value,
            "success" if ok else "error",
            message,
            employee_user_id=employee["id"],
            employee_name_snapshot=deps["row_get"](employee_for_payload, "full_name"),
            employee_department_snapshot=deps["row_get"](employee_for_payload, "department"),
            employee_position_snapshot=deps["row_get"](employee_for_payload, "position"),
            **scanner_log_kwargs
        )

        profile_image_url = None
        if employee_for_payload["profile_image"] and deps["uploaded_file_exists"](employee_for_payload["profile_image"]):
            profile_image_url = deps["url_for"]("uploaded_file", filename=employee_for_payload["profile_image"])

        return deps["jsonify"]({
            "ok": ok,
            "message": message,
            "employee_name": employee_for_payload["full_name"],
            "department": employee_for_payload["department"] or "",
            "position": employee_for_payload["position"] or "",
            "avatar_initials": deps["get_avatar_initials"](employee_for_payload["full_name"]),
            "profile_image_url": profile_image_url,
            "barcode_value": barcode_value,
            "barcode_id": employee_for_payload["barcode_id"] or barcode_value,
            "match_type": barcode_lookup["match_type"],
            "status": "On Overtime" if overtime_session else (attendance["status"] if attendance else "Offline"),
            "time_in": attendance["time_in"] if attendance else None,
            "time_out": attendance["time_out"] if attendance else None,
            "break_minutes": break_minutes,
            "action_type": action_type
        }), (200 if ok else 400)
