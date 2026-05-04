def register_notification_routes(app, deps):
    build_notification_preview_rows = deps["build_notification_preview_rows"]
    clear_resolved_break_limit_notifications = deps["clear_resolved_break_limit_notifications"]
    create_notification = deps["create_notification"]
    execute_db = deps["execute_db"]
    flash = deps["flash"]
    format_datetime_12h = deps["format_datetime_12h"]
    get_latest_notifications = deps["get_latest_notifications"]
    get_unread_notification_count = deps["get_unread_notification_count"]
    get_user_by_id = deps["get_user_by_id"]
    jsonify = deps["jsonify"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    session = deps["session"]
    url_for = deps["url_for"]

    @app.route("/notifications")
    @login_required()
    def notifications_page():
        user = get_user_by_id(session["user_id"])
        notifications = get_latest_notifications(session["user_id"], limit=100)

        return render_template(
            "notifications.html",
            user=user,
            notifications=notifications
        )


    @app.route("/notifications/preview")
    @login_required()
    def notifications_preview():
        current_user = get_user_by_id(session["user_id"])
        if current_user and current_user.get("role") == "employee":
            clear_resolved_break_limit_notifications(
                current_user,
                include_open_overtime=True,
            )
        unread_count = get_unread_notification_count(session["user_id"])
        preview_rows = build_notification_preview_rows(
            get_latest_notifications(session["user_id"], limit=6),
            format_datetime_12h,
        )
        return jsonify({"unread_count": unread_count, "items": preview_rows})


    @app.route("/notifications/read/<int:notif_id>", methods=["POST"])
    @login_required()
    def read_notification(notif_id):
        execute_db("""
            UPDATE notifications
            SET is_read = 1
            WHERE id = ? AND user_id = ?
        """, (notif_id, session["user_id"]), commit=True)

        if session.get("role") == "admin":
            return redirect(request.referrer or url_for("admin_dashboard"))
        return redirect(request.referrer or url_for("dashboard"))


    @app.route("/notifications/read-all", methods=["POST"])
    @login_required()
    def read_all_notifications():
        execute_db("""
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = ? AND is_read = 0
        """, (session["user_id"],), commit=True)

        flash("All notifications marked as read.", "success")
        return redirect(request.referrer or url_for("notifications_page"))


    @app.route("/admin/send-notification", methods=["POST"])
    @login_required(role="admin")
    def send_admin_notification():
        user_id = request.form.get("user_id")
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()

        if not user_id or not title or not message:
            flash("All notification fields are required.", "danger")
            return redirect(url_for("admin_dashboard"))

        create_notification(user_id, title, message)
        log_activity(session["user_id"], "SEND NOTIFICATION", f"Sent notification to user ID {user_id}")
        flash("Notification sent successfully.", "success")
        return redirect(url_for("admin_dashboard"))
