def resolve_client_ip(remote_addr=""):
    return (remote_addr or "").strip() or "unknown"


def build_employee_identifier_conflict_finder(fetchone):
    def find_employee_identifier_conflict(identifier_value, exclude_user_id=None):
        barcode_value = (identifier_value or "").strip()
        if not barcode_value:
            return None

        sql = """
            SELECT id, full_name, employee_code, barcode_id
            FROM users
            WHERE role = 'employee'
              AND TRIM(COALESCE(barcode_id, '')) = ?
        """
        params = [barcode_value]
        if exclude_user_id is not None:
            sql += " AND id != ?"
            params.append(int(exclude_user_id))
        sql += " ORDER BY id ASC LIMIT 1"
        return fetchone(sql, params)

    return find_employee_identifier_conflict


def build_employee_scan_match_finder(fetchall, fetchone):
    def find_employee_barcode_matches(barcode_id):
        cleaned = (barcode_id or "").strip()
        result = {
            "cleaned": cleaned,
            "matches": [],
            "is_duplicate": False,
            "match_type": "none",
        }
        if not cleaned:
            return result

        direct_matches = fetchall("""
            SELECT *
            FROM users
            WHERE role = 'employee' AND TRIM(COALESCE(barcode_id, '')) = ?
            ORDER BY id ASC
            LIMIT 2
        """, (cleaned,))
        if direct_matches:
            result["matches"] = direct_matches
            result["is_duplicate"] = len(direct_matches) > 1
            result["match_type"] = "barcode"
            return result

        return result

    return find_employee_barcode_matches
