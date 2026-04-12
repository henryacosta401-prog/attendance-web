def build_unread_notification_counter(fetchone):
    def get_unread_notification_count(user_id):
        unread = fetchone("""
            SELECT COUNT(*) AS cnt
            FROM notifications
            WHERE user_id = ? AND is_read = 0
        """, (user_id,))
        return int(unread["cnt"] or 0) if unread else 0

    return get_unread_notification_count


def build_latest_notifications_loader(fetchall):
    def get_latest_notifications(user_id, limit=6):
        safe_limit = max(1, int(limit or 6))
        return fetchall("""
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (user_id, safe_limit))

    return get_latest_notifications


def build_notification_preview_rows(notification_rows, format_datetime_12h):
    preview_rows = []
    for row in notification_rows:
        item = dict(row)
        preview_rows.append({
            "title": item.get("title") or "",
            "message": item.get("message") or "",
            "is_unread": int(item.get("is_read") or 0) == 0,
            "created_display": format_datetime_12h(item.get("created_at")),
        })
    return preview_rows
