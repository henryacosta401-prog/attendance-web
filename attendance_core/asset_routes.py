def register_asset_routes(app, deps):
    Response = deps["Response"]
    abort = deps["abort"]
    build_cloudinary_asset_url = deps["build_cloudinary_asset_url"]
    can_access_uploaded_file = deps["can_access_uploaded_file"]
    get_user_by_id = deps["get_user_by_id"]
    is_cloudinary_reference = deps["is_cloudinary_reference"]
    login_required = deps["login_required"]
    os = deps["os"]
    redirect = deps["redirect"]
    send_from_directory = deps["send_from_directory"]
    session = deps["session"]

    @app.route("/uploads/<path:filename>")
    @login_required()
    def uploaded_file(filename):
        user = get_user_by_id(session["user_id"])
        if not can_access_uploaded_file(user, filename):
            abort(403)
        if is_cloudinary_reference(filename):
            asset_url = build_cloudinary_asset_url(filename)
            if not asset_url:
                abort(404)
            return redirect(asset_url)
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


    @app.route("/manifest.webmanifest")
    def web_manifest():
        manifest_path = os.path.join(app.static_folder, "manifest.webmanifest")
        with open(manifest_path, "r", encoding="utf-8") as manifest_file:
            payload = manifest_file.read()
        response = Response(payload, mimetype="application/manifest+json")
        response.headers["Cache-Control"] = "no-cache"
        return response


    @app.route("/service-worker.js")
    def service_worker():
        response = send_from_directory(app.static_folder, "service-worker.js")
        response.headers["Cache-Control"] = "no-cache"
        return response
