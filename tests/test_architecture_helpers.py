import unittest
from datetime import date
from unittest.mock import patch

from attendance_core.config import (
    APP_TIMEZONE,
    DEFAULT_SECRET_KEY,
    get_configured_secret_key,
    is_production_environment,
)
from attendance_core.attendance import (
    combine_work_date_and_time,
    format_datetime_12h,
    format_time_12h,
    get_attendance_reference_datetime,
    get_overbreak_minutes,
    get_schedule_code_for_date,
    get_schedule_day_codes,
    get_schedule_summary,
    get_shift_bounds_for_work_date,
    normalize_history_reference,
    normalize_optional_clock_time,
    normalize_schedule_days,
    parse_break_limit_minutes,
    parse_datetime_local_input,
    parse_db_datetime,
    parse_optional_schedule_time,
    parse_shift_end,
    parse_shift_start,
    total_work_minutes,
)
from attendance_core.date_ranges import (
    get_admin_report_period_dates,
    get_payroll_period_dates,
    normalize_admin_report_filters,
    parse_iso_date,
    payroll_date_text,
)
from attendance_core.formatters import (
    format_currency,
    minutes_to_decimal_hours,
    minutes_to_hm,
)
from attendance_core.payroll import (
    build_employee_payslip_pdf_bytes,
    build_employee_payslip_pdf_filename,
    format_payroll_period_label,
    get_payroll_scope_label,
    recurring_rule_applies_to_period,
)
from attendance_core.reporting import (
    build_case_rows,
    build_highlight_card,
    build_report_highlights,
)
from attendance_core.scanner import resolve_client_ip
from attendance_core.workflows import (
    build_correction_change_summary,
    build_schedule_special_rule_label,
    calculate_suspension_end_date,
    describe_request_review_result,
    expand_request_dates,
    expand_suspension_dates,
    format_request_date_range,
    normalize_request_date_range,
    normalize_schedule_special_rule_type,
    resolve_correction_datetimes,
    schedule_preset_matches_department,
    split_datetime_to_time,
)


class ArchitectureHelpersTestCase(unittest.TestCase):
    def test_minutes_to_hm_handles_none(self):
        self.assertEqual(minutes_to_hm(None), "0h 0m")

    def test_minutes_to_hm_formats_hours_and_minutes(self):
        self.assertEqual(minutes_to_hm(130), "2h 10m")

    def test_minutes_to_decimal_hours(self):
        self.assertEqual(minutes_to_decimal_hours(135), 2.25)

    def test_format_currency_defaults_to_zero(self):
        self.assertEqual(format_currency(None), "PHP 0.00")

    def test_format_currency_formats_numeric_values(self):
        self.assertEqual(format_currency(1234.5), "PHP 1,234.50")

    def test_parse_iso_date_returns_fallback_for_invalid_input(self):
        fallback = date(2026, 4, 1)
        self.assertEqual(parse_iso_date("not-a-date", fallback), fallback)

    def test_report_period_last_14_days(self):
        period, date_from, date_to = get_admin_report_period_dates(
            "last_14_days",
            today=date(2026, 4, 7),
        )
        self.assertEqual(period, "last_14_days")
        self.assertEqual(date_from, date(2026, 3, 25))
        self.assertEqual(date_to, date(2026, 4, 7))

    def test_report_filters_normalize_reversed_custom_dates(self):
        filters = normalize_admin_report_filters(
            date_from_value="2026-04-10",
            date_to_value="2026-04-01",
            department_filter="Ops",
            period_value="custom",
            today=date(2026, 4, 7),
        )
        self.assertEqual(filters["date_from"], date(2026, 4, 1))
        self.assertEqual(filters["date_to"], date(2026, 4, 10))
        self.assertEqual(filters["range_days"], 10)
        self.assertEqual(filters["department_filter"], "Ops")

    def test_payroll_period_last_month(self):
        date_from, date_to = get_payroll_period_dates(
            "last_month",
            today=date(2026, 4, 7),
        )
        self.assertEqual(date_from, date(2026, 3, 1))
        self.assertEqual(date_to, date(2026, 3, 31))

    def test_payroll_date_text_uses_iso_format(self):
        self.assertEqual(payroll_date_text(date(2026, 4, 7)), "2026-04-07")

    def test_format_payroll_period_label_for_same_month(self):
        self.assertEqual(
            format_payroll_period_label("2026-04-01", "2026-04-15"),
            "Apr 01 - 15, 2026",
        )

    def test_get_payroll_scope_label_for_employee_release(self):
        self.assertEqual(
            get_payroll_scope_label(employee_filter="8", current_user_id=8),
            "Employee-only release",
        )

    def test_get_payroll_scope_label_for_department_release(self):
        self.assertEqual(
            get_payroll_scope_label(department_filter="Ops"),
            "Ops release",
        )

    def test_recurring_rule_applies_to_every_payroll(self):
        self.assertTrue(
            recurring_rule_applies_to_period(
                {"is_active": 1, "recurrence_type": "Every Payroll", "start_date": "", "end_date": ""},
                date(2026, 4, 1),
                date(2026, 4, 15),
            )
        )

    def test_recurring_rule_monthly_anchor_outside_period(self):
        self.assertFalse(
            recurring_rule_applies_to_period(
                {"is_active": 1, "recurrence_type": "Monthly", "start_date": "2026-04-30", "end_date": ""},
                date(2026, 4, 1),
                date(2026, 4, 15),
            )
        )

    def test_build_employee_payslip_pdf_filename_sanitizes_text(self):
        filename = build_employee_payslip_pdf_filename({
            "full_name": "Henry/Acosta",
            "date_from": "2026-04-01",
            "date_to": "2026-04-15",
        })
        self.assertTrue(filename.endswith(".pdf"))
        self.assertNotIn("/", filename)

    def test_build_employee_payslip_pdf_bytes_returns_pdf(self):
        pdf_bytes = build_employee_payslip_pdf_bytes(
            {
                "period_label": "Apr 01 - 15, 2026",
                "date_from": "2026-04-01",
                "date_to": "2026-04-15",
                "full_name": "Henry Acosta",
                "department": "Ops",
                "position": "Lead",
                "hourly_rate": 156.25,
                "days_worked": 10,
                "total_hours": 80,
                "overtime_hours": 2,
                "late_minutes": 3,
                "break_minutes": 40,
                "suspension_days": 0,
                "suspension_pay": 0,
                "gross_pay": 12500,
                "overtime_pay": 390.62,
                "allowances": 500,
                "deductions": 250,
                "adjustment_balance": 250,
                "final_pay": 13140.62,
                "scope_label": "Company-wide release",
                "released_display": "2026-04-07 10:30 PM",
                "created_by_name": "Administrator",
                "notes": "Released payroll snapshot.",
                "adjustment_entries": [],
                "missing_adjustment_detail": False,
            },
            printed_at_text="2026-04-07 10:35 PM",
        )
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_build_highlight_card_handles_empty_row(self):
        card = build_highlight_card("Peak Attendance Day", None, "0", "Empty", "No attendance rows in this range.")
        self.assertEqual(card["label"], "No data")
        self.assertEqual(card["primary_value"], "0")

    def test_build_report_highlights_and_case_rows(self):
        daily_rows = [
            {"work_date": "2026-04-01", "attendance_days": 4, "attendance_hours": 32.0, "late_punches": 1, "overtime_hours": 1.5},
            {"work_date": "2026-04-02", "attendance_days": 6, "attendance_hours": 48.0, "late_punches": 2, "overtime_hours": 3.0},
        ]
        department_rows = [
            {"department": "Ops", "attendance_days": 6, "attendance_hours": 48.0, "late_punches": 2, "overtime_hours": 3.0},
            {"department": "HR", "attendance_days": 2, "attendance_hours": 16.0, "late_punches": 0, "overtime_hours": 0.0},
        ]
        trend_highlights, department_highlights = build_report_highlights(daily_rows, department_rows)
        case_rows = build_case_rows(2, 5, 1, 4, 3, 7, 10)

        self.assertEqual(trend_highlights[0]["label"], "2026-04-02")
        self.assertEqual(department_highlights[0]["label"], "Ops")
        self.assertEqual(case_rows[0]["action_needed"], 2)
        self.assertEqual(case_rows[2]["closed_count"], 7)

    def test_parse_shift_start_and_end_defaults(self):
        self.assertEqual(parse_shift_start("bad"), "09:00")
        self.assertEqual(parse_shift_end(""), "18:00")

    def test_parse_optional_schedule_time(self):
        self.assertEqual(parse_optional_schedule_time("8:30", fallback="09:00"), "08:30")
        self.assertEqual(parse_optional_schedule_time("08:30"), "08:30")

    def test_normalize_schedule_days_and_summary(self):
        normalized = normalize_schedule_days(["Wed", "Mon", "Sun", "bad"])
        self.assertEqual(normalized, "Mon,Wed,Sun")
        self.assertEqual(get_schedule_day_codes(normalized), ["Mon", "Wed", "Sun"])
        self.assertEqual(get_schedule_summary(normalized), "Monday, Wednesday, Sunday")

    def test_get_schedule_code_for_date(self):
        self.assertEqual(get_schedule_code_for_date("2026-04-07"), "Tue")

    def test_normalize_history_reference(self):
        self.assertEqual(
            normalize_history_reference(reference_date="2026-04-07"),
            "2026-04-07 23:59:59",
        )

    def test_get_attendance_reference_datetime_prefers_time_in(self):
        self.assertEqual(
            get_attendance_reference_datetime({
                "time_in": "2026-04-07 09:00:00",
                "created_at": "2026-04-07 08:55:00",
                "work_date": "2026-04-07",
            }),
            "2026-04-07 09:00:00",
        )

    def test_parse_break_limit_minutes_and_overbreak(self):
        self.assertEqual(parse_break_limit_minutes("20"), 20)
        self.assertEqual(parse_break_limit_minutes("bad"), 15)
        self.assertEqual(get_overbreak_minutes(35, 20), 15)

    def test_parse_db_datetime_and_formatters(self):
        parsed = parse_db_datetime("2026-04-07 21:30:15")
        self.assertIsNotNone(parsed)
        self.assertEqual(format_datetime_12h("2026-04-07 21:30:15"), "2026-04-07 09:30:15 PM")
        self.assertEqual(format_time_12h("2026-04-07 21:30:15"), "09:30:15 PM")

    def test_combine_work_date_and_time_rolls_overnight(self):
        self.assertEqual(
            combine_work_date_and_time("2026-04-07", "00:00", not_before="2026-04-07 16:00:00"),
            "2026-04-08 00:00:00",
        )

    def test_normalize_optional_clock_time_and_parse_datetime_local_input(self):
        self.assertEqual(normalize_optional_clock_time("7:45"), "07:45")
        self.assertEqual(parse_datetime_local_input("2026-04-07T09:15"), "2026-04-07 09:15:00")

    def test_get_shift_bounds_for_work_date_handles_overnight(self):
        start_dt, end_dt = get_shift_bounds_for_work_date(
            {"shift_start": "16:00", "shift_end": "00:00"},
            "2026-04-07",
        )
        self.assertEqual(start_dt.tzinfo, APP_TIMEZONE)
        self.assertEqual(start_dt.strftime("%Y-%m-%d %H:%M:%S"), "2026-04-07 16:00:00")
        self.assertEqual(end_dt.strftime("%Y-%m-%d %H:%M:%S"), "2026-04-08 00:00:00")

    def test_total_work_minutes(self):
        self.assertEqual(
            total_work_minutes({
                "time_in": "2026-04-07 09:00:00",
                "time_out": "2026-04-07 17:30:00",
            }),
            510,
        )

    def test_resolve_client_ip(self):
        self.assertEqual(resolve_client_ip(" 127.0.0.1 "), "127.0.0.1")
        self.assertEqual(resolve_client_ip(""), "unknown")

    def test_schedule_special_rule_helpers(self):
        self.assertEqual(normalize_schedule_special_rule_type("rest_day"), "rest_day")
        self.assertEqual(normalize_schedule_special_rule_type("bad"), "holiday")
        self.assertEqual(build_schedule_special_rule_label("holiday", " Company Holiday "), "Company Holiday")

    def test_schedule_preset_matches_department(self):
        self.assertTrue(schedule_preset_matches_department({"department_scope": ""}, "Ops"))
        self.assertTrue(schedule_preset_matches_department({"department_scope": "ops"}, "Ops"))
        self.assertFalse(schedule_preset_matches_department({"department_scope": "HR"}, "Ops"))

    def test_request_date_helpers(self):
        self.assertEqual(
            normalize_request_date_range("2026-04-10", "2026-04-08"),
            ("2026-04-08", "2026-04-10"),
        )
        self.assertEqual(
            expand_request_dates("2026-04-08", "2026-04-10"),
            ["2026-04-08", "2026-04-09", "2026-04-10"],
        )
        self.assertEqual(
            format_request_date_range("2026-04-08", "2026-04-10"),
            "2026-04-08 to 2026-04-10",
        )

    def test_calculate_and_expand_suspension_dates(self):
        self.assertEqual(calculate_suspension_end_date("2026-04-08", 3), "2026-04-10")
        self.assertEqual(
            expand_suspension_dates(
                {"action_type": "Suspension", "action_date": "2026-04-08", "end_date": "2026-04-10"}
            ),
            ["2026-04-08", "2026-04-09", "2026-04-10"],
        )

    def test_correction_workflow_helpers(self):
        resolved = resolve_correction_datetimes(
            "2026-04-07",
            time_in_value="16:00",
            break_start_value="20:00",
            break_end_value="20:15",
            time_out_value="00:00",
        )
        self.assertEqual(
            resolved,
            (
                "2026-04-07 16:00:00",
                "2026-04-07 20:00:00",
                "2026-04-07 20:15:00",
                "2026-04-08 00:00:00",
            ),
        )
        self.assertEqual(split_datetime_to_time("2026-04-07 16:00:00"), "16:00")
        self.assertEqual(
            build_correction_change_summary(
                {"time_in": "2026-04-07 16:00:00", "time_out": "2026-04-08 00:00:00"},
                {"time_in": "2026-04-07 17:00:00", "time_out": "2026-04-08 01:00:00"},
            ),
            "Time In: 16:00 -> 17:00; Time Out: 00:00 -> 01:00",
        )
        self.assertEqual(
            describe_request_review_result("Paid Leave", "2026-04-08"),
            "Paid Leave approved for 2026-04-08.",
        )

    def test_is_production_environment_detects_render(self):
        with patch.dict("os.environ", {"RENDER": "true"}, clear=True):
            self.assertTrue(is_production_environment())

    def test_get_configured_secret_key_returns_custom_value(self):
        with patch.dict("os.environ", {"SECRET_KEY": "custom-secret"}, clear=True):
            self.assertEqual(get_configured_secret_key(), "custom-secret")

    def test_get_configured_secret_key_rejects_default_in_production(self):
        with patch.dict("os.environ", {"DATABASE_URL": "postgres://example"}, clear=True):
            with self.assertRaises(RuntimeError):
                get_configured_secret_key()

    def test_default_secret_key_constant_is_exposed(self):
        self.assertEqual(DEFAULT_SECRET_KEY, "dev-secret-key")


if __name__ == "__main__":
    unittest.main()
