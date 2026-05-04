def register_auth_routes(app, deps):
    LOGIN_WINDOW_MINUTES = deps["LOGIN_WINDOW_MINUTES"]
    check_password_hash = deps["check_password_hash"]
    clear_login_failures = deps["clear_login_failures"]
    fetchone = deps["fetchone"]
    flash = deps["flash"]
    get_client_ip = deps["get_client_ip"]
    get_home_route_for_user = deps["get_home_route_for_user"]
    get_user_by_id = deps["get_user_by_id"]
    is_login_rate_limited = deps["is_login_rate_limited"]
    jsonify = deps["jsonify"]
    log_activity = deps["log_activity"]
    login_required = deps["login_required"]
    now_str = deps["now_str"]
    redirect = deps["redirect"]
    register_login_failure = deps["register_login_failure"]
    render_template = deps["render_template"]
    request = deps["request"]
    session = deps["session"]
    url_for = deps["url_for"]

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "time": now_str()}), 200


    @app.route("/")
    def home():
        if "user_id" in session:
            user = get_user_by_id(session["user_id"])
            if not user:
                session.clear()
                return redirect(url_for("login"))
            return redirect(get_home_route_for_user(user))
        return redirect(url_for("login"))


    @app.route("/login", methods=["GET", "POST"])
    def login():
        existing_user_id = session.get("user_id")
        if existing_user_id:
            existing_user = get_user_by_id(existing_user_id)
            if existing_user and int(existing_user["is_active"] or 0) == 1:
                session["role"] = existing_user["role"]
                session["full_name"] = existing_user["full_name"]
                return redirect(get_home_route_for_user(existing_user))
            session.clear()

        if request.method == "POST":
            client_ip = get_client_ip()
            if is_login_rate_limited(client_ip):
                flash(f"Too many login attempts. Please wait {LOGIN_WINDOW_MINUTES} minutes and try again.", "danger")
                return render_template("login.html"), 429

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            user = fetchone("""
                SELECT * FROM users
                WHERE username = ? AND is_active = 1
            """, (username,))

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["full_name"] = user["full_name"]
                clear_login_failures(client_ip)

                log_activity(user["id"], "LOGIN", f"{user['full_name']} logged in")

                if user["role"] == "admin":
                    flash("Welcome Admin.", "success")
                    return redirect(get_home_route_for_user(user))

                if user["role"] == "scanner":
                    flash("Scanner kiosk ready.", "success")
                    return redirect(url_for("scanner_kiosk"))

                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))

            register_login_failure(client_ip)
            flash("Invalid username or password.", "danger")

        return render_template("login.html")


    @app.route("/logout", methods=["POST"])
    @login_required()
    def logout():
        user_id = session.get("user_id")
        if user_id:
            log_activity(user_id, "LOGOUT", "User logged out")
        session.clear()
        flash("Logged out successfully.", "info")
        return redirect(url_for("login"))
