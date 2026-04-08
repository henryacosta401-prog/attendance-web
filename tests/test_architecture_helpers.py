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
