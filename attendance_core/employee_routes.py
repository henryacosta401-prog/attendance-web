def register_employee_routes(app, deps):
    globals().update(deps)
    login_required = deps["login_required"]

    @app.route("/admin/employees", methods=["GET", "POST"])
    @login_required(role="admin")
    def manage_employees():
        employee_search = request.values.get("search", "").strip()

        if request.method == "POST":
            form_action = (request.form.get("form_action", "add_employee") or "add_employee").strip()

            if form_action == "save_schedule_special_rule":
                special_date = (request.form.get("special_date", "") or "").strip()
                rule_type = normalize_schedule_special_rule_type(request.form.get("rule_type", "holiday"))
                label = build_schedule_special_rule_label(rule_type, request.form.get("special_rule_label", ""))
                notes = (request.form.get("special_rule_notes", "") or "").strip()
                special_date_value = parse_iso_date(special_date)
                if not special_date_value:
                    flash("Choose a valid holiday or rest-day date.", "danger")
                    return redirect(url_for("manage_employees", search=employee_search))
                if special_date_value < now_dt().date():
                    flash("Holiday and rest-day rules can only be created for today or future dates.", "danger")
                    return redirect(url_for("manage_employees", search=employee_search))

                existing_rule = fetchone("""
                    SELECT id
                    FROM schedule_special_dates
                    WHERE special_date = ?
                    LIMIT 1
                """, (special_date_value.strftime("%Y-%m-%d"),))
                if existing_rule:
                    execute_db("""
                        UPDATE schedule_special_dates
                        SET rule_type = ?, label = ?, notes = ?, created_by = ?, updated_at = ?
                        WHERE id = ?
                    """, (
                        rule_type,
                        label,
                        notes or None,
                        session["user_id"],
                        now_str(),
                        existing_rule["id"]
                    ), commit=True)
                    log_activity(session["user_id"], "UPDATE SCHEDULE RULE", f"Updated {SCHEDULE_SPECIAL_RULE_LABELS[rule_type]} rule for {special_date_value.strftime('%Y-%m-%d')}.")
                    flash(f"Updated the {SCHEDULE_SPECIAL_RULE_LABELS[rule_type].lower()} rule for {special_date_value.strftime('%Y-%m-%d')}.", "success")
                else:
                    execute_db("""
                        INSERT INTO schedule_special_dates (
                            special_date, rule_type, label, notes, created_by, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        special_date_value.strftime("%Y-%m-%d"),
                        rule_type,
                        label,
                        notes or None,
                        session["user_id"],
                        now_str(),
                        now_str()
                    ), commit=True)
                    log_activity(session["user_id"], "CREATE SCHEDULE RULE", f"Created {SCHEDULE_SPECIAL_RULE_LABELS[rule_type]} rule for {special_date_value.strftime('%Y-%m-%d')}.")
                    flash(f"Saved the {SCHEDULE_SPECIAL_RULE_LABELS[rule_type].lower()} rule for {special_date_value.strftime('%Y-%m-%d')}.", "success")

                invalidate_schedule_special_rule_cache()
                invalidate_admin_employee_rows_cache()
                invalidate_reports_cache()
                return redirect(url_for("manage_employees", search=employee_search))

            if form_action == "delete_schedule_special_rule":
                raw_rule_id = (request.form.get("schedule_special_rule_id", "") or "").strip()
                if not raw_rule_id.isdigit():
                    flash("Schedule rule not found.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))
                existing_rule = fetchone("""
                    SELECT *
                    FROM schedule_special_dates
                    WHERE id = ?
                    LIMIT 1
                """, (int(raw_rule_id),))
                if not existing_rule:
                    flash("Schedule rule not found.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))
                existing_rule = dict(existing_rule)
                execute_db("DELETE FROM schedule_special_dates WHERE id = ?", (int(raw_rule_id),), commit=True)
                invalidate_schedule_special_rule_cache()
                invalidate_admin_employee_rows_cache()
                invalidate_reports_cache()
                log_activity(session["user_id"], "DELETE SCHEDULE RULE", f"Deleted {build_schedule_special_rule_label(existing_rule.get('rule_type'), existing_rule.get('label'))} on {existing_rule.get('special_date')}.")
                flash("Schedule rule deleted.", "info")
                return redirect(url_for("manage_employees", search=employee_search))

            if form_action == "create_schedule_preset":
                preset_name = (request.form.get("preset_name", "") or "").strip()
                department_scope = (request.form.get("preset_department_scope", "") or "").strip()
                notes = (request.form.get("preset_notes", "") or "").strip()
                schedule_days = normalize_schedule_days(request.form.getlist("preset_schedule_days"))
                shift_start = parse_shift_start(request.form.get("preset_shift_start", DEFAULT_SHIFT_START))
                shift_end = parse_shift_end(request.form.get("preset_shift_end", DEFAULT_SHIFT_END))
                break_limit_minutes = parse_break_limit_minutes(request.form.get("preset_break_limit_minutes", BREAK_LIMIT_MINUTES))

                if not preset_name:
                    flash("Schedule preset name is required.", "danger")
                    return redirect(url_for("manage_employees", search=employee_search))

                existing_preset = fetchone("SELECT id FROM schedule_presets WHERE LOWER(name) = LOWER(?)", (preset_name,))
                if existing_preset:
                    flash("A schedule preset with that name already exists.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))

                execute_db("""
                    INSERT INTO schedule_presets (
                        name, department_scope, schedule_days, shift_start, shift_end,
                        break_limit_minutes, notes, created_by, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    preset_name,
                    department_scope or None,
                    schedule_days,
                    shift_start,
                    shift_end,
                    break_limit_minutes,
                    notes or None,
                    session["user_id"],
                    now_str(),
                    now_str()
                ), commit=True)
                log_activity(session["user_id"], "CREATE SCHEDULE PRESET", f"Created preset {preset_name} ({schedule_days} | {shift_start}-{shift_end} | break {break_limit_minutes}m)")
                flash("Schedule preset created.", "success")
                return redirect(url_for("manage_employees", search=employee_search))

            if form_action == "delete_schedule_preset":
                preset = get_schedule_preset(request.form.get("schedule_preset_id", ""))
                if not preset:
                    flash("Schedule preset not found.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))

                affected_employees = [
                    dict(row)
                    for row in fetchall(
                        "SELECT * FROM users WHERE role = 'employee' AND schedule_preset_id = ?",
                        (preset["id"],)
                    )
                ]

                db = get_db()
                try:
                    execute_db("UPDATE users SET schedule_preset_id = NULL WHERE schedule_preset_id = ?", (preset["id"],))
                    for employee in affected_employees:
                        employee["schedule_preset_id"] = None
                        record_employee_schedule_history(employee, actor_id=session["user_id"])
                    execute_db("DELETE FROM schedule_presets WHERE id = ?", (preset["id"],))
                    db.commit()
                except Exception:
                    db.rollback()
                    raise

                log_activity(session["user_id"], "DELETE SCHEDULE PRESET", f"Deleted preset {preset['name']}")
                flash("Schedule preset deleted. Employees keep their last saved schedule values.", "info")
                return redirect(url_for("manage_employees", search=employee_search))

            if form_action == "apply_schedule_preset_bulk":
                preset = get_schedule_preset(request.form.get("bulk_schedule_preset_id", ""))
                effective_date = (request.form.get("bulk_effective_date", "") or "").strip()
                change_notes = (request.form.get("bulk_schedule_notes", "") or "").strip()
                employee_ids = []
                for raw_id in request.form.getlist("employee_ids"):
                    raw_text = str(raw_id or "").strip()
                    if raw_text.isdigit():
                        employee_ids.append(int(raw_text))
                employee_ids = sorted(set(employee_ids))

                if not preset:
                    flash("Choose a valid schedule preset to apply.", "danger")
                    return redirect(url_for("manage_employees", search=employee_search))
                if not employee_ids:
                    flash("Select at least one employee before applying a schedule preset.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))

                placeholders = ", ".join(["?"] * len(employee_ids))
                existing_ids = [
                    int(row["id"])
                    for row in fetchall(
                        f"SELECT id FROM users WHERE role = 'employee' AND id IN ({placeholders})",
                        tuple(employee_ids)
                    )
                ]
                if not existing_ids:
                    flash("No valid employees were selected.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))

                update_placeholders = ", ".join(["?"] * len(existing_ids))
                selected_employees = [
                    dict(row)
                    for row in fetchall(
                        f"SELECT * FROM users WHERE role = 'employee' AND id IN ({update_placeholders})",
                        tuple(existing_ids)
                    )
                ]
                scope_conflicts = [
                    employee["full_name"]
                    for employee in selected_employees
                    if not schedule_preset_matches_department(preset, employee.get("department"))
                ]
                if scope_conflicts:
                    flash(
                        f"Preset {preset['name']} is scoped to {preset['department_scope']} and cannot be applied to: {', '.join(scope_conflicts[:3])}" +
                        ("..." if len(scope_conflicts) > 3 else ""),
                        "danger"
                    )
                    return redirect(url_for("manage_employees", search=employee_search))

                effective_date_value = parse_iso_date(effective_date) if effective_date else None
                if effective_date and not effective_date_value:
                    flash("Choose a valid effective date for the bulk schedule change.", "danger")
                    return redirect(url_for("manage_employees", search=employee_search))
                if effective_date_value and effective_date_value <= now_dt().date():
                    flash("Leave Effective Date blank to apply immediately, or choose a future date to queue the rollout.", "warning")
                    return redirect(url_for("manage_employees", search=employee_search))

                if effective_date_value:
                    db = get_db()
                    queued_count = 0
                    try:
                        for employee in selected_employees:
                            queue_future_schedule_change(
                                employee,
                                {
                                    "schedule_preset_id": preset["id"],
                                    "schedule_days": preset["schedule_days"],
                                    "shift_start": preset["shift_start"],
                                    "shift_end": preset["shift_end"],
                                    "break_limit_minutes": preset["break_limit_minutes"],
                                },
                                effective_date_value.strftime("%Y-%m-%d"),
                                actor_id=session["user_id"],
                                notes=change_notes
                            )
                            queued_count += 1
                        db.commit()
                    except Exception:
                        db.rollback()
                        raise

                    invalidate_reports_cache()
                    log_activity(
                        session["user_id"],
                        "QUEUE SCHEDULE PRESET",
                        f"Queued preset {preset['name']} for {queued_count} employee(s) effective {effective_date_value.strftime('%Y-%m-%d')}"
                    )
                    flash(
                        f"Queued {preset['name']} for {queued_count} employee(s) starting {effective_date_value.strftime('%Y-%m-%d')}.",
                        "success"
                    )
                    return redirect(url_for("manage_employees", search=employee_search))

                db = get_db()
                try:
                    execute_db(f"""
                        UPDATE users
                        SET schedule_preset_id = ?,
                            schedule_days = ?,
                            shift_start = ?,
                            shift_end = ?,
                            break_limit_minutes = ?
                        WHERE role = 'employee' AND id IN ({update_placeholders})
                    """, (
                        preset["id"],
                        preset["schedule_days"],
                        preset["shift_start"],
                        preset["shift_end"],
                        preset["break_limit_minutes"],
                        *existing_ids
                    ))
                    for employee in selected_employees:
                        employee["schedule_preset_id"] = preset["id"]
                        employee["schedule_days"] = preset["schedule_days"]
                        employee["shift_start"] = preset["shift_start"]
                        employee["shift_end"] = preset["shift_end"]
                        employee["break_limit_minutes"] = preset["break_limit_minutes"]
                        record_employee_schedule_history(employee, actor_id=session["user_id"])
                    db.commit()
                except Exception:
                    db.rollback()
                    raise

                invalidate_admin_employee_rows_cache()
                invalidate_reports_cache()
                log_activity(session["user_id"], "BULK APPLY SCHEDULE PRESET", f"Applied preset {preset['name']} to {len(existing_ids)} employee(s)")
                flash(f"Applied {preset['name']} to {len(existing_ids)} employee(s).", "success")
                return redirect(url_for("manage_employees", search=employee_search))

            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            department = request.form.get("department", "").strip() or "Stellar Seats"
            position = request.form.get("position", "").strip() or "Employee"
            emergency_contact_name = ""
            emergency_contact_phone = ""
            id_issue_date = ""
            id_expiration_date = ""
            employee_code = ""
            barcode_id = request.form.get("barcode_id", "").strip()
            hourly_rate = parse_money_value(request.form.get("hourly_rate", "0"))
            sick_leave_days = parse_non_negative_int(request.form.get("sick_leave_days", DEFAULT_SICK_LEAVE_DAYS), DEFAULT_SICK_LEAVE_DAYS)
            paid_leave_days = parse_non_negative_int(request.form.get("paid_leave_days", DEFAULT_PAID_LEAVE_DAYS), DEFAULT_PAID_LEAVE_DAYS)
            sick_leave_used_manual = parse_non_negative_int(request.form.get("sick_leave_used_manual", "0"), 0)
            paid_leave_used_manual = parse_non_negative_int(request.form.get("paid_leave_used_manual", "0"), 0)
            schedule_assignment = resolve_schedule_assignment(request.form)
            schedule_days = schedule_assignment["schedule_days"]
            shift_start = schedule_assignment["shift_start"]
            shift_end = schedule_assignment["shift_end"]
            break_limit_minutes = schedule_assignment["break_limit_minutes"]
            schedule_preset_id = schedule_assignment["schedule_preset_id"]
            selected_preset = get_schedule_preset(schedule_preset_id) if schedule_preset_id else None

            if not full_name or not username or not password:
                flash("Full name, username, and password are required.", "danger")
                return redirect(url_for("manage_employees"))

            existing = fetchone("SELECT id FROM users WHERE username = ?", (username,))
            if existing:
                flash("Username already exists.", "warning")
                return redirect(url_for("manage_employees"))

            if selected_preset and not schedule_preset_matches_department(selected_preset, department):
                flash(f"Preset {selected_preset['name']} is scoped to {selected_preset['department_scope']}. Choose a matching department or use a custom schedule.", "danger")
                return redirect(url_for("manage_employees"))

            if barcode_id:
                existing_barcode = find_employee_identifier_conflict(barcode_id)
                if existing_barcode:
                    flash("Barcode ID already exists.", "warning")
                    return redirect(url_for("manage_employees"))

            profile_image = None
            file = request.files.get("profile_image")
            if file and file.filename:
                try:
                    profile_image = save_uploaded_file(file, prefix="profile", allowed_exts=IMAGE_EXTENSIONS)
                except RuntimeError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("manage_employees"))
                if not profile_image:
                    flash("Invalid profile image file type.", "danger")
                    return redirect(url_for("manage_employees"))

            execute_db("""
                INSERT INTO users (
                    full_name, username, password_hash, role, profile_image,
                    department, position, emergency_contact_name, emergency_contact_phone, id_issue_date, id_expiration_date, employee_code, barcode_id, hourly_rate, sick_leave_days, paid_leave_days, sick_leave_used_manual, paid_leave_used_manual, schedule_days, shift_start, shift_end, schedule_preset_id, break_window_start, break_window_end, break_limit_minutes, is_active, created_at
                )
                VALUES (?, ?, ?, 'employee', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """, (
                full_name,
                username,
                generate_password_hash(password),
                profile_image,
                department,
                position,
                emergency_contact_name,
                emergency_contact_phone,
                id_issue_date,
                id_expiration_date,
                employee_code or None,
                barcode_id,
                hourly_rate,
                sick_leave_days,
                paid_leave_days,
                sick_leave_used_manual,
                paid_leave_used_manual,
                schedule_days,
                shift_start,
                shift_end,
                schedule_preset_id,
                DEFAULT_BREAK_WINDOW_START,
                DEFAULT_BREAK_WINDOW_END,
                break_limit_minutes,
                now_str()
            ), commit=True)

            new_user = fetchone("SELECT id FROM users WHERE username = ?", (username,))
            if new_user:
                created_employee = get_user_by_id(new_user["id"])
                if created_employee:
                    record_employee_schedule_history(
                        created_employee,
                        actor_id=session["user_id"],
                        effective_at=created_employee["created_at"] if created_employee["created_at"] else now_str(),
                        commit=True
                    )
                create_notification(new_user["id"], "Account Created", "Your account has been created by admin.")
                log_activity(
                    session["user_id"],
                    "ADD EMPLOYEE",
                    f"Added employee: {full_name} | " + summarize_employee_admin_changes(None, {
                        "department": department,
                        "position": position,
                        "barcode_id": barcode_id or "(not set)",
                        "hourly_rate": hourly_rate,
                        "sick_leave_days": sick_leave_days,
                        "paid_leave_days": paid_leave_days,
                        "sick_leave_used_manual": sick_leave_used_manual,
                            "paid_leave_used_manual": paid_leave_used_manual,
                            "shift_start": shift_start,
                            "shift_end": shift_end,
                            "schedule_preset_id": schedule_preset_id or "(custom)",
                            "break_limit_minutes": break_limit_minutes,
                            "is_active": 1,
                        })
                    )

            invalidate_admin_employee_rows_cache()
            invalidate_reports_cache()
            flash("Employee added successfully.", "success")
            return redirect(url_for("manage_employees"))

        sql = """
            SELECT u.*, sp.name AS schedule_preset_name
            FROM users u
            LEFT JOIN schedule_presets sp ON sp.id = u.schedule_preset_id
            WHERE role = 'employee'
        """
        params = []

        if employee_search:
            sql += """
                AND (
                    LOWER(full_name) LIKE ?
                    OR LOWER(username) LIKE ?
                    OR LOWER(COALESCE(department, '')) LIKE ?
                    OR LOWER(COALESCE(position, '')) LIKE ?
                    OR LOWER(COALESCE(barcode_id, '')) LIKE ?
                )
            """
            search_like = f"%{employee_search.lower()}%"
            params.extend([search_like, search_like, search_like, search_like, search_like])

        sql += " ORDER BY u.id DESC"
        employees = fetchall(sql, params)
        schedule_presets = []
        preset_assignment_counts = {}
        for row in fetchall("""
            SELECT schedule_preset_id, COUNT(*) AS cnt
            FROM users
            WHERE role = 'employee' AND schedule_preset_id IS NOT NULL
            GROUP BY schedule_preset_id
        """):
            preset_assignment_counts[int(row["schedule_preset_id"])] = int(row["cnt"] or 0)
        for preset in get_schedule_presets():
            item = dict(preset)
            item["schedule_summary"] = get_schedule_summary(item["schedule_days"] or DEFAULT_SCHEDULE_DAYS)
            item["window_summary"] = f"{item['shift_start'] or DEFAULT_SHIFT_START} - {item['shift_end'] or DEFAULT_SHIFT_END}"
            item["assigned_count"] = preset_assignment_counts.get(int(item["id"]), 0)
            schedule_presets.append(item)
        future_schedule_changes = get_future_schedule_changes(limit=18)
        employee_future_change_map = build_future_schedule_change_map([int(emp["id"]) for emp in employees])
        future_schedule_summary = {
            "queued_total": len(future_schedule_changes),
            "employee_count": len({int(change["user_id"]) for change in future_schedule_changes}),
            "next_effective_date": future_schedule_changes[0]["effective_date"] if future_schedule_changes else "",
        }
        schedule_special_rules = get_schedule_special_dates(limit=18)
        schedule_special_rule_summary = {
            "total": len(schedule_special_rules),
            "holiday_count": len([rule for rule in schedule_special_rules if rule["rule_type"] == "holiday"]),
            "rest_day_count": len([rule for rule in schedule_special_rules if rule["rule_type"] == "rest_day"]),
            "next_date": schedule_special_rules[0]["special_date"] if schedule_special_rules else "",
        }

        return render_template(
            "manage_employees.html",
            employees=employees,
            weekday_options=WEEKDAY_OPTIONS,
            employee_search=employee_search,
            schedule_presets=schedule_presets,
            future_schedule_changes=future_schedule_changes,
            future_schedule_summary=future_schedule_summary,
            employee_future_change_map=employee_future_change_map,
            schedule_special_rules=schedule_special_rules,
            schedule_special_rule_summary=schedule_special_rule_summary,
            schedule_special_rule_options=SCHEDULE_SPECIAL_RULE_OPTIONS,
            today_date=today_str(),
            tomorrow_date=(now_dt().date() + timedelta(days=1)).strftime("%Y-%m-%d")
        )


    @app.route("/admin/future-schedule-changes/<int:change_id>/delete", methods=["POST"])
    @login_required(role="admin")
    def delete_future_schedule_change(change_id):
        change = fetchone("""
            SELECT fsc.*, u.full_name
            FROM employee_future_schedule_changes fsc
            LEFT JOIN users u ON u.id = fsc.user_id
            WHERE fsc.id = ?
        """, (change_id,))
        if not change:
            flash("Queued schedule change not found.", "warning")
            return redirect(request.referrer or url_for("manage_employees"))
        change = dict(change)
        if change.get("applied_at"):
            flash("This schedule change has already been applied and can no longer be deleted.", "danger")
            return redirect(request.referrer or url_for("manage_employees"))

        execute_db("DELETE FROM employee_future_schedule_changes WHERE id = ?", (change_id,), commit=True)
        invalidate_schedule_change_apply_state()
        invalidate_reports_cache()
        employee_label = change.get("full_name") or f"User {change['user_id']}"
        log_activity(
            session["user_id"],
            "DELETE FUTURE SCHEDULE CHANGE",
            f"Removed queued schedule change for {employee_label} effective {change['effective_date']}."
        )
        flash("Queued schedule change deleted.", "info")
        return redirect(request.referrer or url_for("manage_employees"))


    @app.route("/admin/edit-employee/<int:user_id>", methods=["GET", "POST"])
    @login_required(role="admin")
    def edit_employee(user_id):
        user = fetchone("""
            SELECT * FROM users
            WHERE id = ? AND role = 'employee'
        """, (user_id,))

        if not user:
            flash("Employee not found.", "danger")
            return redirect(url_for("manage_employees"))

        if request.method == "POST":
            form_action = (request.form.get("form_action", "edit_employee") or "edit_employee").strip()
            if form_action == "schedule_future_change":
                effective_date = (request.form.get("effective_date", "") or "").strip()
                change_notes = (request.form.get("future_schedule_notes", "") or "").strip()
                schedule_assignment = resolve_schedule_assignment(request.form, fallback_user=user)
                selected_preset = get_schedule_preset(schedule_assignment["schedule_preset_id"]) if schedule_assignment["schedule_preset_id"] else None
                if selected_preset and not schedule_preset_matches_department(selected_preset, user["department"]):
                    flash(f"Preset {selected_preset['name']} is scoped to {selected_preset['department_scope']}. Choose a matching department or use a custom schedule.", "danger")
                    return redirect(url_for("edit_employee", user_id=user_id))
                try:
                    queue_future_schedule_change(
                        user,
                        schedule_assignment,
                        effective_date,
                        actor_id=session["user_id"],
                        notes=change_notes
                    )
                    get_db().commit()
                except ValueError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("edit_employee", user_id=user_id))

                invalidate_reports_cache()
                log_activity(
                    session["user_id"],
                    "QUEUE EMPLOYEE SCHEDULE CHANGE",
                    f"Queued a schedule change for {user['full_name']} effective {effective_date}."
                )
                flash(f"Future schedule change queued for {user['full_name']} starting {effective_date}.", "success")
                return redirect(url_for("edit_employee", user_id=user_id))

            original_user = user
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            department = request.form.get("department", "").strip() or "Stellar Seats"
            position = request.form.get("position", "").strip() or "Employee"
            emergency_contact_name = user["emergency_contact_name"] or ""
            emergency_contact_phone = user["emergency_contact_phone"] or ""
            id_issue_date = user["id_issue_date"] or ""
            id_expiration_date = user["id_expiration_date"] or ""
            employee_code = user["employee_code"]
            barcode_id = request.form.get("barcode_id", "").strip()
            hourly_rate = parse_money_value(request.form.get("hourly_rate", user["hourly_rate"] or 0))
            sick_leave_days = parse_non_negative_int(request.form.get("sick_leave_days", user["sick_leave_days"] if user["sick_leave_days"] is not None else DEFAULT_SICK_LEAVE_DAYS), DEFAULT_SICK_LEAVE_DAYS)
            paid_leave_days = parse_non_negative_int(request.form.get("paid_leave_days", user["paid_leave_days"] if user["paid_leave_days"] is not None else DEFAULT_PAID_LEAVE_DAYS), DEFAULT_PAID_LEAVE_DAYS)
            sick_leave_used_manual = parse_non_negative_int(request.form.get("sick_leave_used_manual", user["sick_leave_used_manual"] if user["sick_leave_used_manual"] is not None else 0), 0)
            paid_leave_used_manual = parse_non_negative_int(request.form.get("paid_leave_used_manual", user["paid_leave_used_manual"] if user["paid_leave_used_manual"] is not None else 0), 0)
            schedule_assignment = resolve_schedule_assignment(request.form, fallback_user=user)
            schedule_days = schedule_assignment["schedule_days"]
            shift_start = schedule_assignment["shift_start"]
            shift_end = schedule_assignment["shift_end"]
            break_limit_minutes = schedule_assignment["break_limit_minutes"]
            schedule_preset_id = schedule_assignment["schedule_preset_id"]
            selected_preset = get_schedule_preset(schedule_preset_id) if schedule_preset_id else None
            is_active = 1 if request.form.get("is_active") == "1" else 0
            password = request.form.get("password", "").strip()

            if not full_name or not username:
                flash("Full name and username are required.", "danger")
                return redirect(url_for("edit_employee", user_id=user_id))

            existing = fetchone("""
                SELECT id FROM users
                WHERE username = ? AND id != ?
            """, (username, user_id))

            if existing:
                flash("Username already used by another employee.", "warning")
                return redirect(url_for("edit_employee", user_id=user_id))

            if selected_preset and not schedule_preset_matches_department(selected_preset, department):
                flash(f"Preset {selected_preset['name']} is scoped to {selected_preset['department_scope']}. Choose a matching department or use a custom schedule.", "danger")
                return redirect(url_for("edit_employee", user_id=user_id))

            if barcode_id:
                existing_barcode = find_employee_identifier_conflict(barcode_id, exclude_user_id=user_id)
                if existing_barcode:
                    flash("Barcode ID already used.", "warning")
                    return redirect(url_for("edit_employee", user_id=user_id))

            profile_image = user["profile_image"]
            file = request.files.get("profile_image")
            if file and file.filename:
                try:
                    saved = save_uploaded_file(file, prefix=f"profile_{user_id}", allowed_exts=IMAGE_EXTENSIONS)
                except RuntimeError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("edit_employee", user_id=user_id))
                if not saved:
                    flash("Invalid profile image file type.", "danger")
                    return redirect(url_for("edit_employee", user_id=user_id))
                profile_image = saved

            if password:
                execute_db("""
                    UPDATE users
                    SET full_name = ?, username = ?, password_hash = ?, profile_image = ?,
                        department = ?, position = ?, emergency_contact_name = ?, emergency_contact_phone = ?, id_issue_date = ?, id_expiration_date = ?, employee_code = ?, barcode_id = ?, hourly_rate = ?, sick_leave_days = ?, paid_leave_days = ?, sick_leave_used_manual = ?, paid_leave_used_manual = ?, schedule_days = ?, shift_start = ?, shift_end = ?, schedule_preset_id = ?, break_window_start = ?, break_window_end = ?, break_limit_minutes = ?, is_active = ?
                    WHERE id = ?
                """, (
                    full_name, username, generate_password_hash(password), profile_image,
                    department, position, emergency_contact_name, emergency_contact_phone, id_issue_date, id_expiration_date, employee_code, barcode_id, hourly_rate, sick_leave_days, paid_leave_days, sick_leave_used_manual, paid_leave_used_manual, schedule_days, shift_start, shift_end, schedule_preset_id, user["break_window_start"] or DEFAULT_BREAK_WINDOW_START, user["break_window_end"] or DEFAULT_BREAK_WINDOW_END, break_limit_minutes, is_active, user_id
                ), commit=True)
            else:
                execute_db("""
                    UPDATE users
                    SET full_name = ?, username = ?, profile_image = ?,
                        department = ?, position = ?, emergency_contact_name = ?, emergency_contact_phone = ?, id_issue_date = ?, id_expiration_date = ?, employee_code = ?, barcode_id = ?, hourly_rate = ?, sick_leave_days = ?, paid_leave_days = ?, sick_leave_used_manual = ?, paid_leave_used_manual = ?, schedule_days = ?, shift_start = ?, shift_end = ?, schedule_preset_id = ?, break_window_start = ?, break_window_end = ?, break_limit_minutes = ?, is_active = ?
                    WHERE id = ?
                """, (
                    full_name, username, profile_image,
                    department, position, emergency_contact_name, emergency_contact_phone, id_issue_date, id_expiration_date, employee_code, barcode_id, hourly_rate, sick_leave_days, paid_leave_days, sick_leave_used_manual, paid_leave_used_manual, schedule_days, shift_start, shift_end, schedule_preset_id, user["break_window_start"] or DEFAULT_BREAK_WINDOW_START, user["break_window_end"] or DEFAULT_BREAK_WINDOW_END, break_limit_minutes, is_active, user_id
                ), commit=True)

            log_activity(
                session["user_id"],
                "EDIT EMPLOYEE",
                f"Edited employee: {full_name} | " + summarize_employee_admin_changes(original_user, {
                    "department": department,
                    "position": position,
                    "barcode_id": barcode_id or "(not set)",
                    "hourly_rate": hourly_rate,
                    "sick_leave_days": sick_leave_days,
                    "paid_leave_days": paid_leave_days,
                    "sick_leave_used_manual": sick_leave_used_manual,
                    "paid_leave_used_manual": paid_leave_used_manual,
                    "shift_start": shift_start,
                    "shift_end": shift_end,
                    "schedule_preset_id": schedule_preset_id or "(custom)",
                    "break_limit_minutes": break_limit_minutes,
                    "is_active": is_active,
                })
            )
            updated_user = get_user_by_id(user_id)
            if updated_user:
                record_employee_schedule_history(updated_user, actor_id=session["user_id"], commit=True)
            invalidate_admin_employee_rows_cache()
            invalidate_reports_cache()
            flash("Employee updated successfully.", "success")
            return redirect(url_for("manage_employees"))

        return render_template(
            "edit_employee.html",
            employee=user,
            weekday_options=WEEKDAY_OPTIONS,
            employee_schedule_days=get_schedule_day_codes(user["schedule_days"] if user["schedule_days"] else DEFAULT_SCHEDULE_DAYS),
            schedule_presets=get_schedule_presets(),
            schedule_history_rows=get_recent_employee_schedule_history(user_id, limit=8),
            future_schedule_changes=get_future_schedule_changes(user_id=user_id, limit=8),
            tomorrow_date=(now_dt().date() + timedelta(days=1)).strftime("%Y-%m-%d")
        )


    @app.route("/admin/employees/<int:user_id>/barcode")
    @login_required(role="admin")
    def download_employee_barcode(user_id):
        employee = fetchone("""
            SELECT *
            FROM users
            WHERE id = ? AND role = 'employee'
        """, (user_id,))

        if not employee:
            flash("Employee not found.", "danger")
            return redirect(url_for("manage_employees"))
        employee = dict(employee)

        barcode_value = (employee["barcode_id"] or "").strip()
        svg_markup = generate_code128_svg_markup(barcode_value)
        if not svg_markup:
            flash("Barcode is not available for this employee yet.", "warning")
            return redirect(url_for("manage_employees"))

        safe_name = secure_filename(employee.get("full_name") or f"employee-{user_id}") or f"employee-{user_id}"
        return Response(
            svg_markup,
            mimetype="image/svg+xml",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}-barcode.svg"'
            },
        )


    @app.route("/admin/employee-id/<int:user_id>/barcode")
    @login_required(role="admin")
    def legacy_download_employee_barcode(user_id):
        return redirect(url_for("download_employee_barcode", user_id=user_id))


    @app.route("/admin/delete-employee/<int:user_id>", methods=["POST"])
    @login_required(role="admin")
    def delete_employee(user_id):
        user = fetchone("""
            SELECT * FROM users
            WHERE id = ? AND role = 'employee'
        """, (user_id,))

        if not user:
            flash("Employee not found.", "danger")
            return redirect(url_for("manage_employees"))

        upload_filenames = []
        if user["profile_image"]:
            upload_filenames.append(user["profile_image"])
        upload_filenames.extend([
            row["proof_file"]
            for row in fetchall("""
                SELECT proof_file
                FROM attendance
                WHERE user_id = ? AND proof_file IS NOT NULL AND TRIM(proof_file) != ''
            """, (user_id,))
        ])

        def count_rows(query, params):
            row = fetchone(query, params)
            if not row:
                return 0
            return int(row["cnt"] or 0)

        protected_history_counts = {
            "attendance": count_rows("SELECT COUNT(*) AS cnt FROM attendance WHERE user_id = ?", (user_id,)),
            "scanner_logs": count_rows("SELECT COUNT(*) AS cnt FROM scanner_logs WHERE employee_user_id = ? OR scanner_user_id = ?", (user_id, user_id)),
            "payroll_items": count_rows("SELECT COUNT(*) AS cnt FROM payroll_run_items WHERE user_id = ?", (user_id,)),
            "overtime": count_rows("SELECT COUNT(*) AS cnt FROM overtime_sessions WHERE user_id = ?", (user_id,)),
            "corrections": count_rows("SELECT COUNT(*) AS cnt FROM correction_requests WHERE user_id = ?", (user_id,)),
            "incidents": count_rows("SELECT COUNT(*) AS cnt FROM incident_reports WHERE user_id = ?", (user_id,)),
            "disciplinary": count_rows("SELECT COUNT(*) AS cnt FROM disciplinary_actions WHERE user_id = ?", (user_id,)),
        }
        if any(protected_history_counts.values()):
            flash("This employee has historical attendance, payroll, or audit records. Deactivate the account instead of deleting it.", "warning")
            return redirect(url_for("manage_employees"))

        db = get_db()
        try:
            execute_db("DELETE FROM notifications WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM payslip_download_requests WHERE user_id = ? OR reviewed_by = ?", (user_id, user_id))
            execute_db("DELETE FROM employee_future_schedule_changes WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM employee_schedule_history WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM breaks WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM attendance WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM overtime_sessions WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM activity_logs WHERE user_id = ? OR target_user_id = ?", (user_id, user_id))
            execute_db("DELETE FROM correction_requests WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM scanner_logs WHERE employee_user_id = ? OR scanner_user_id = ?", (user_id, user_id))
            execute_db("DELETE FROM payroll_adjustments WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM payroll_recurring_rules WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM payroll_run_item_adjustments WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM incident_reports WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM disciplinary_actions WHERE user_id = ?", (user_id,))
            execute_db("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        except Exception:
            db.rollback()
            raise

        for filename in upload_filenames:
            delete_uploaded_file_if_unused(filename)

        log_activity(session["user_id"], "DELETE EMPLOYEE", f"Deleted employee: {user['full_name']}")
        invalidate_admin_employee_rows_cache()
        flash("Employee deleted successfully.", "info")
        return redirect(url_for("manage_employees"))
