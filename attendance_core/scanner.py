from attendance_core.employee_ids import normalize_employee_code


def resolve_client_ip(remote_addr=""):
    return (remote_addr or "").strip() or "unknown"


def build_employee_identifier_conflict_finder(fetchone, employee_code_normalizer=normalize_employee_code):
    def find_employee_identifier_conflict(identifier_value, exclude_user_id=None):
        barcode_value = (identifier_value or "").strip()
        employee_code_value = employee_code_normalizer(identifier_value)
        if not barcode_value and not employee_code_value:
            return None

        sql = """
            SELECT id, full_name, employee_code, barcode_id
            FROM users
            WHERE role = 'employee'
              AND (
                  TRIM(COALESCE(barcode_id, '')) = ?
                  OR TRIM(COALESCE(employee_code, '')) = ?
              )
        """
        params = [barcode_value, employee_code_value]
        if exclude_user_id is not None:
            sql += " AND id != ?"
            params.append(int(exclude_user_id))
        sql += " ORDER BY id ASC LIMIT 1"
        return fetchone(sql, params)

    return find_employee_identifier_conflict


def build_employee_scan_match_finder(fetchall, fetchone, employee_code_normalizer=normalize_employee_code):
    def find_employee_barcode_matches(barcode_id):
        cleaned = (barcode_id or "").strip()
        normalized_employee_code = employee_code_normalizer(cleaned)
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

        employee_code_matches = fetchall("""
            SELECT *
            FROM users
            WHERE role = 'employee' AND TRIM(COALESCE(employee_code, '')) = ?
            ORDER BY id ASC
            LIMIT 2
        """, (normalized_employee_code,))
        if employee_code_matches:
            result["matches"] = employee_code_matches
            result["is_duplicate"] = len(employee_code_matches) > 1
            result["match_type"] = "employee_code"
            return result

        if cleaned.upper().startswith("EMP-"):
            suffix = cleaned[4:].strip()
            if suffix.isdigit():
                employee = fetchone("""
                    SELECT *
                    FROM users
                    WHERE role = 'employee' AND id = ?
                    ORDER BY id DESC LIMIT 1
                """, (int(suffix),))
                if employee:
                    result["matches"] = [employee]
                    result["match_type"] = "employee_id"
        return result

    return find_employee_barcode_matches
