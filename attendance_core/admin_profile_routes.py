def register_admin_profile_routes(app, deps):
    ADMIN_ROLE_PRESETS = deps["ADMIN_ROLE_PRESETS"]
    BREAK_LIMIT_MINUTES = deps["BREAK_LIMIT_MINUTES"]
    DEFAULT_SHIFT_START = deps["DEFAULT_SHIFT_START"]
    IMAGE_EXTENSIONS = deps["IMAGE_EXTENSIONS"]
    admin_has_permission = deps["admin_has_permission"]
    execute_db = deps["execute_db"]
    fetchone = deps["fetchone"]
    flash = deps["flash"]
    generate_password_hash = deps["generate_password_hash"]
    get_admin_accounts = deps["get_admin_accounts"]
    get_admin_role_preset_meta = deps["get_admin_role_preset_meta"]
    get_company_settings = deps["get_company_settings"]
    get_scanner_account = deps["get_scanner_account"]
    get_user_by_id = deps["get_user_by_id"]
    has_scanner_exit_pin = deps["has_scanner_exit_pin"]
    login_required = deps["login_required"]
    log_activity = deps["log_activity"]
    normalize_admin_role_preset = deps["normalize_admin_role_preset"]
    now_str = deps["now_str"]
    parse_positive_int = deps["parse_positive_int"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    save_uploaded_file = deps["save_uploaded_file"]
    session = deps["session"]
    sync_admin_role_preset = deps["sync_admin_role_preset"]
    url_for = deps["url_for"]

    @app.route("/admin/profile", methods=["GET", "POST"])
    @login_required(role="admin")
    def admin_profile():
        user = get_user_by_id(session["user_id"])
        if not user or user["role"] != "admin":
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        if request.method == "POST":
            form_action = request.form.get("form_action", "admin_profile").strip()

            if form_action == "create_admin_account":
                if not admin_has_permission(user, "settings"):
                    flash("Your admin account cannot manage other admin accounts.", "danger")
                    return redirect(url_for("admin_profile"))
                admin_full_name = (request.form.get("admin_full_name", "") or "").strip()
                admin_username = (request.form.get("admin_username", "") or "").strip()
                admin_password = (request.form.get("admin_password", "") or "").strip()
                admin_role_preset = normalize_admin_role_preset(request.form.get("admin_role_preset", ""))
                admin_permission_values = request.form.getlist("admin_permissions")
                if not admin_permission_values and admin_role_preset:
                    admin_permission_values = list(ADMIN_ROLE_PRESETS[admin_role_preset]["permissions"])
                admin_role_preset, admin_permissions = sync_admin_role_preset(admin_role_preset, admin_permission_values)

                if not admin_full_name or not admin_username or not admin_password:
                    flash("Admin name, username, and password are required.", "danger")
                    return redirect(url_for("admin_profile"))
                if not admin_permissions:
                    flash("Choose at least one permission for the new admin account.", "danger")
                    return redirect(url_for("admin_profile"))
                if fetchone("SELECT id FROM users WHERE username = ?", (admin_username,)):
                    flash("That username is already in use.", "warning")
                    return redirect(url_for("admin_profile"))

                execute_db("""
                    INSERT INTO users (
                        full_name, username, password_hash, role, department, position,
                        admin_permissions, admin_role_preset, shift_start, break_limit_minutes, is_active, created_at
                    )
                    VALUES (?, ?, ?, 'admin', ?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    admin_full_name,
                    admin_username,
                    generate_password_hash(admin_password),
                    "Stellar Seats",
                    "Operations Admin",
                    admin_permissions,
                    admin_role_preset or None,
                    DEFAULT_SHIFT_START,
                    BREAK_LIMIT_MINUTES,
                    now_str()
                ), commit=True)
                preset_meta = get_admin_role_preset_meta(preset_code=admin_role_preset, permission_values=admin_permissions)
                log_activity(session["user_id"], "CREATE ADMIN ACCOUNT", f"Created admin account {admin_username} with {preset_meta['label']} ({admin_permissions})")
                flash("Admin account created.", "success")
                return redirect(url_for("admin_profile"))

            if form_action == "update_admin_account":
                if not admin_has_permission(user, "settings"):
                    flash("Your admin account cannot manage other admin accounts.", "danger")
                    return redirect(url_for("admin_profile"))
                admin_id_raw = (request.form.get("admin_id", "") or "").strip()
                if not admin_id_raw.isdigit():
                    flash("Admin account not found.", "warning")
                    return redirect(url_for("admin_profile"))

                target_admin = fetchone("SELECT * FROM users WHERE id = ? AND role = 'admin'", (int(admin_id_raw),))
                if not target_admin:
                    flash("Admin account not found.", "warning")
                    return redirect(url_for("admin_profile"))

                if int(target_admin["id"]) == int(session["user_id"]):
                    flash("Use the profile form above to update your own main account details.", "info")
                    return redirect(url_for("admin_profile"))

                admin_full_name = (request.form.get("admin_full_name", "") or "").strip()
                admin_username = (request.form.get("admin_username", "") or "").strip()
                admin_password = (request.form.get("admin_password", "") or "").strip()
                admin_role_preset = normalize_admin_role_preset(request.form.get("admin_role_preset", ""))
                admin_permission_values = request.form.getlist("admin_permissions")
                if not admin_permission_values and admin_role_preset:
                    admin_permission_values = list(ADMIN_ROLE_PRESETS[admin_role_preset]["permissions"])
                admin_role_preset, admin_permissions = sync_admin_role_preset(admin_role_preset, admin_permission_values)
                is_active = 1 if request.form.get("is_active") == "1" else 0

                if not admin_full_name or not admin_username:
                    flash("Admin name and username are required.", "danger")
                    return redirect(url_for("admin_profile"))
                if not admin_permissions:
                    flash("Choose at least one permission for the admin account.", "danger")
                    return redirect(url_for("admin_profile"))

                username_owner = fetchone("SELECT id FROM users WHERE username = ? AND id != ?", (admin_username, target_admin["id"]))
                if username_owner:
                    flash("That username is already in use by another account.", "warning")
                    return redirect(url_for("admin_profile"))

                if admin_password:
                    execute_db("""
                        UPDATE users
                        SET full_name = ?, username = ?, password_hash = ?, admin_permissions = ?, admin_role_preset = ?, is_active = ?
                        WHERE id = ?
                    """, (
                        admin_full_name,
                        admin_username,
                        generate_password_hash(admin_password),
                        admin_permissions,
                        admin_role_preset or None,
                        is_active,
                        target_admin["id"]
                    ), commit=True)
                else:
                    execute_db("""
                        UPDATE users
                        SET full_name = ?, username = ?, admin_permissions = ?, admin_role_preset = ?, is_active = ?
                        WHERE id = ?
                    """, (
                        admin_full_name,
                        admin_username,
                        admin_permissions,
                        admin_role_preset or None,
                        is_active,
                        target_admin["id"]
                    ), commit=True)
                preset_meta = get_admin_role_preset_meta(preset_code=admin_role_preset, permission_values=admin_permissions)
                log_activity(session["user_id"], "UPDATE ADMIN ACCOUNT", f"Updated admin account {admin_username} with {preset_meta['label']} ({admin_permissions})")
                flash("Admin account updated.", "success")
                return redirect(url_for("admin_profile"))

            if form_action == "scanner_account":
                if not admin_has_permission(user, "settings"):
                    flash("Your admin account cannot change scanner settings.", "danger")
                    return redirect(url_for("admin_profile"))
                scanner_full_name = request.form.get("scanner_full_name", "").strip() or "Scanner Kiosk"
                scanner_username = request.form.get("scanner_username", "").strip()
                scanner_password = request.form.get("scanner_password", "").strip()

                if not scanner_username:
                    flash("Scanner username is required.", "danger")
                    return redirect(url_for("admin_profile"))

                existing_scanner = get_scanner_account()
                username_owner = fetchone("SELECT id, role FROM users WHERE username = ?", (scanner_username,))
                if username_owner and (not existing_scanner or username_owner["id"] != existing_scanner["id"]):
                    flash("That scanner username is already in use.", "warning")
                    return redirect(url_for("admin_profile"))

                if existing_scanner:
                    if scanner_password:
                        execute_db("""
                            UPDATE users
                            SET full_name = ?, username = ?, password_hash = ?
                            WHERE id = ?
                        """, (scanner_full_name, scanner_username, generate_password_hash(scanner_password), existing_scanner["id"]), commit=True)
                        log_activity(session["user_id"], "UPDATE SCANNER ACCOUNT", f"Updated scanner account {scanner_username} and reset password")
                    else:
                        execute_db("""
                            UPDATE users
                            SET full_name = ?, username = ?
                            WHERE id = ?
                        """, (scanner_full_name, scanner_username, existing_scanner["id"]), commit=True)
                        log_activity(session["user_id"], "UPDATE SCANNER ACCOUNT", f"Updated scanner account {scanner_username}")
                    flash("Scanner account updated.", "success")
                else:
                    if not scanner_password:
                        flash("Scanner password is required when creating the scanner account.", "danger")
                        return redirect(url_for("admin_profile"))
                    execute_db("""
                        INSERT INTO users (
                            full_name, username, password_hash, role, department, position,
                            break_limit_minutes, is_active, created_at
                        )
                        VALUES (?, ?, ?, 'scanner', ?, ?, ?, 1, ?)
                    """, (
                        scanner_full_name,
                        scanner_username,
                        generate_password_hash(scanner_password),
                        "Kiosk",
                        "Scanner Only",
                        BREAK_LIMIT_MINUTES,
                        now_str()
                    ), commit=True)
                    log_activity(session["user_id"], "CREATE SCANNER ACCOUNT", f"Created scanner account {scanner_username}")
                    flash("Scanner account created.", "success")
                return redirect(url_for("admin_profile"))

            if form_action == "attendance_settings":
                if not admin_has_permission(user, "settings"):
                    flash("Your admin account cannot change attendance settings.", "danger")
                    return redirect(url_for("admin_profile"))
                scanner_attendance_mode = 1 if request.form.get("scanner_attendance_mode") == "1" else 0
                tardiness_policy_enabled = 1 if request.form.get("tardiness_policy_enabled") == "1" else 0
                scanner_lock_timeout_seconds = parse_positive_int(request.form.get("scanner_lock_timeout_seconds", "90"), 90)
                scanner_lock_timeout_seconds = max(min(scanner_lock_timeout_seconds, 900), 15)
                overtime_multiplier_raw = (request.form.get("overtime_multiplier", "") or "").strip()
                try:
                    overtime_multiplier = float(overtime_multiplier_raw or 1.25)
                except ValueError:
                    flash("Overtime multiplier must be a valid number.", "danger")
                    return redirect(url_for("admin_profile"))
                overtime_multiplier = max(min(overtime_multiplier, 5.0), 1.0)

                scanner_exit_pin = (request.form.get("scanner_exit_pin", "") or "").strip()
                current_settings = get_company_settings()
                scanner_exit_pin_hash = current_settings.get("scanner_exit_pin_hash")
                if scanner_exit_pin:
                    if len(scanner_exit_pin) < 4:
                        flash("Scanner kiosk PIN must be at least 4 characters.", "danger")
                        return redirect(url_for("admin_profile"))
                    scanner_exit_pin_hash = generate_password_hash(scanner_exit_pin)
                elif request.form.get("clear_scanner_exit_pin") == "1":
                    scanner_exit_pin_hash = None

                execute_db("""
                    INSERT INTO company_settings (
                        id, scanner_attendance_mode, scanner_lock_timeout_seconds, scanner_exit_pin_hash,
                        overtime_multiplier, tardiness_policy_enabled
                    )
                    VALUES (1, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        scanner_attendance_mode = excluded.scanner_attendance_mode,
                        scanner_lock_timeout_seconds = excluded.scanner_lock_timeout_seconds,
                        scanner_exit_pin_hash = excluded.scanner_exit_pin_hash,
                        overtime_multiplier = excluded.overtime_multiplier,
                        tardiness_policy_enabled = excluded.tardiness_policy_enabled
                """, (
                    scanner_attendance_mode,
                    scanner_lock_timeout_seconds,
                    scanner_exit_pin_hash,
                    overtime_multiplier,
                    tardiness_policy_enabled,
                ), commit=True)
                log_activity(
                    session["user_id"],
                    "UPDATE ATTENDANCE SETTINGS",
                    f"Scanner mode {'enabled' if scanner_attendance_mode else 'disabled'}, "
                    f"tardiness policy {'enabled' if tardiness_policy_enabled else 'disabled'}, "
                    f"kiosk timeout {scanner_lock_timeout_seconds}s, overtime multiplier {overtime_multiplier:.2f}x"
                )
                flash("Attendance and kiosk settings updated.", "success")
                return redirect(url_for("admin_profile"))

            full_name = request.form.get("full_name", "").strip()
            if not full_name:
                flash("Full name is required.", "danger")
                return redirect(url_for("admin_profile"))

            password = request.form.get("password", "").strip()

            profile_image = user["profile_image"]
            file = request.files.get("profile_image")
            if file and file.filename:
                try:
                    saved = save_uploaded_file(file, prefix=f"profile_{user['id']}", allowed_exts=IMAGE_EXTENSIONS)
                except RuntimeError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("admin_profile"))
                if not saved:
                    flash("Invalid profile image type.", "danger")
                    return redirect(url_for("admin_profile"))
                profile_image = saved

            if password:
                execute_db("""
                    UPDATE users
                    SET full_name = ?, password_hash = ?, profile_image = ?
                    WHERE id = ?
                """, (full_name, generate_password_hash(password), profile_image, user["id"]), commit=True)
                log_activity(user["id"], "UPDATE ADMIN PROFILE", "Admin updated profile and password")
            else:
                execute_db("""
                    UPDATE users
                    SET full_name = ?, profile_image = ?
                    WHERE id = ?
                """, (full_name, profile_image, user["id"]), commit=True)
                log_activity(user["id"], "UPDATE ADMIN PROFILE", "Admin updated profile")

            session["full_name"] = full_name
            flash("Admin profile updated successfully.", "success")
            return redirect(url_for("admin_profile"))

        return render_template(
            "admin_profile.html",
            user=user,
            admin_accounts=get_admin_accounts(),
            scanner_account=get_scanner_account(),
            company_settings=get_company_settings(),
            scanner_exit_pin_configured=has_scanner_exit_pin()
        )
