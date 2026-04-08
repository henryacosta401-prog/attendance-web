def build_highlight_card(title, row, primary_value, secondary_text, empty_text):
    if not row:
        return {
            "title": title,
            "label": "No data",
            "primary_value": "0",
            "secondary_text": empty_text,
        }
    return {
        "title": title,
        "label": row.get("work_date") or row.get("department") or "No data",
        "primary_value": primary_value,
        "secondary_text": secondary_text,
    }


def build_report_highlights(daily_rows, department_rows):
    peak_attendance_day = max(daily_rows, key=lambda item: (item["attendance_days"], item["attendance_hours"], item["work_date"])) if daily_rows else None
    peak_overtime_day = max(daily_rows, key=lambda item: (item["overtime_hours"], item["attendance_days"], item["work_date"])) if daily_rows else None
    highest_late_day = max(daily_rows, key=lambda item: (item["late_punches"], item["attendance_days"], item["work_date"])) if daily_rows else None
    attendance_department_leader = max(department_rows, key=lambda item: (item["attendance_hours"], item["attendance_days"], item["department"])) if department_rows else None
    overtime_department_leader = max(department_rows, key=lambda item: (item["overtime_hours"], item["attendance_hours"], item["department"])) if department_rows else None
    late_department_leader = max(department_rows, key=lambda item: (item["late_punches"], item["attendance_days"], item["department"])) if department_rows else None

    trend_highlights = [
        build_highlight_card(
            "Peak Attendance Day",
            peak_attendance_day,
            str(int(peak_attendance_day["attendance_days"])) if peak_attendance_day else "0",
            f"{peak_attendance_day['attendance_hours']:.2f} attendance hours logged" if peak_attendance_day else "No attendance rows in this range.",
            "No attendance rows in this range."
        ),
        build_highlight_card(
            "Peak Overtime Day",
            peak_overtime_day,
            f"{peak_overtime_day['overtime_hours']:.2f}" if peak_overtime_day else "0.00",
            f"{peak_overtime_day['attendance_days']} attendance row(s) also closed that day" if peak_overtime_day else "No overtime sessions in this range.",
            "No overtime sessions in this range."
        ),
        build_highlight_card(
            "Highest Late Punch Day",
            highest_late_day,
            str(int(highest_late_day["late_punches"])) if highest_late_day else "0",
            f"{highest_late_day['attendance_days']} attendance row(s) recorded" if highest_late_day else "No late punches in this range.",
            "No late punches in this range."
        ),
    ]
    department_highlights = [
        build_highlight_card(
            "Attendance Leader",
            attendance_department_leader,
            f"{attendance_department_leader['attendance_hours']:.2f}" if attendance_department_leader else "0.00",
            f"{attendance_department_leader['attendance_days']} attendance day(s) in scope" if attendance_department_leader else "No department activity in this range.",
            "No department activity in this range."
        ),
        build_highlight_card(
            "Overtime Leader",
            overtime_department_leader,
            f"{overtime_department_leader['overtime_hours']:.2f}" if overtime_department_leader else "0.00",
            f"{overtime_department_leader['attendance_hours']:.2f} attendance hours in the same range" if overtime_department_leader else "No overtime activity in this range.",
            "No overtime activity in this range."
        ),
        build_highlight_card(
            "Most Late Punches",
            late_department_leader,
            str(int(late_department_leader["late_punches"])) if late_department_leader else "0",
            f"{late_department_leader['attendance_days']} attendance day(s) affected" if late_department_leader else "No late punches in this range.",
            "No late punches in this range."
        ),
    ]
    return trend_highlights, department_highlights


def build_case_rows(
    pending_leave_requests,
    leave_requests_total,
    pending_corrections_count,
    correction_requests_total,
    incident_follow_up_count,
    incident_resolved_count,
    incident_total_count,
):
    return [
        {
            "area": "Leave Requests",
            "action_needed": pending_leave_requests,
            "closed_count": max(leave_requests_total - pending_leave_requests, 0),
            "total_count": leave_requests_total,
        },
        {
            "area": "Correction Requests",
            "action_needed": pending_corrections_count,
            "closed_count": max(correction_requests_total - pending_corrections_count, 0),
            "total_count": correction_requests_total,
        },
        {
            "area": "Incident Reports",
            "action_needed": incident_follow_up_count,
            "closed_count": incident_resolved_count,
            "total_count": incident_total_count,
        },
    ]
