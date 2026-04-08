import unittest
from datetime import date
from unittest.mock import patch

from attendance_core.config import (
    DEFAULT_SECRET_KEY,
    get_configured_secret_key,
    is_production_environment,
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
