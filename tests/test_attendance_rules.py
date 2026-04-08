import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import app as attendance_app


class AttendanceRulesTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="attendance-tests-")
        self.db_path = os.path.join(self.temp_dir, "attendance-test.db")
        self.upload_dir = os.path.join(self.temp_dir, "uploads")
        self.backup_dir = os.path.join(self.temp_dir, "backups")
        os.makedirs(self.upload_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

        attendance_app.SQLITE_DATABASE = self.db_path
        attendance_app.UPLOAD_FOLDER = self.upload_dir
        attendance_app.BACKUP_FOLDER = self.backup_dir
        attendance_app.app.config["UPLOAD_FOLDER"] = self.upload_dir
        attendance_app.app.config["TESTING"] = True

        with attendance_app.app.app_context():
            attendance_app.close_db()
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            attendance_app.init_sqlite_db()

    def tearDown(self):
        with attendance_app.app.app_context():
            attendance_app.close_db()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_employee(self, username="worker", shift_start="16:00", shift_end="00:00", schedule_days="Mon,Tue,Wed,Thu,Fri", break_limit=20):
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                """
                INSERT INTO users (
                    full_name, username, password_hash, role, department, position,
                    schedule_days, shift_start, shift_end, break_limit_minutes, is_active, created_at
                )
                VALUES (?, ?, ?, 'employee', 'Ops', 'Agent', ?, ?, ?, ?, 1, ?)
                """,
                (
                    f"User {username}",
                    username,
                    "hash",
                    schedule_days,
                    shift_start,
                    shift_end,
                    break_limit,
                    attendance_app.now_str(),
                ),
                commit=True,
            )
            return attendance_app.fetchone("SELECT * FROM users WHERE username = ?", (username,))

    def create_attendance(self, user_id, work_date, time_in, time_out=None, status="Timed In"):
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                """
                INSERT INTO attendance (
                    user_id, work_date, time_in, time_out, status, proof_file, notes,
                    late_flag, late_minutes, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, NULL, '', 0, 0, ?, ?)
                """,
                (user_id, work_date, time_in, time_out, status, attendance_app.now_str(), attendance_app.now_str()),
                commit=True,
            )
            return attendance_app.fetchone(
                "SELECT * FROM attendance WHERE user_id = ? AND work_date = ? ORDER BY id DESC LIMIT 1",
                (user_id, work_date),
            )

    def create_break(self, user_id, attendance_id, work_date, break_start, break_end=None):
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                """
                INSERT INTO breaks (user_id, attendance_id, work_date, break_start, break_end, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, attendance_id, work_date, break_start, break_end, attendance_app.now_str()),
                commit=True,
            )

    def test_overnight_timeout_rolls_to_next_day(self):
        final_dt = attendance_app.combine_work_date_and_time("2026-03-26", "00:00", not_before="2026-03-26 16:00:00")
        self.assertEqual(final_dt, "2026-03-27 00:00:00")

    def test_undertime_request_matches_correct_overnight_row(self):
        user = self.create_employee(username="nicole")
        self.create_attendance(user["id"], "2026-03-25", "2026-03-25 16:00:00", "2026-03-26 00:00:00", status="Timed Out")
        self.create_attendance(user["id"], "2026-03-26", "2026-03-26 16:00:00", "2026-03-26 22:18:30", status="Timed Out")

        with attendance_app.app.app_context():
            attendance, _ = attendance_app.get_matching_attendance_context_for_request(
                user["id"],
                "2026-03-26",
                request_type="Undertime",
                requested_time_out="2026-03-26 22:00:00",
            )

        self.assertIsNotNone(attendance)
        self.assertEqual(attendance["work_date"], "2026-03-26")

    def test_break_correction_trims_break_end_for_undertime(self):
        user = self.create_employee(username="amy")
        attendance = self.create_attendance(user["id"], "2026-03-26", "2026-03-26 16:00:00", "2026-03-27 00:00:00", status="Timed Out")
        self.create_break(user["id"], attendance["id"], "2026-03-26", "2026-03-26 19:25:00", "2026-03-26 22:18:00")

        with attendance_app.app.app_context():
            attendance_app.apply_attendance_correction(user["id"], "2026-03-26", time_out_value="22:00")
            break_row = attendance_app.fetchone("SELECT * FROM breaks WHERE attendance_id = ?", (attendance["id"],))
            updated = attendance_app.get_attendance_by_id(attendance["id"])

        self.assertEqual(updated["time_out"], "2026-03-26 22:00:00")
        self.assertEqual(break_row["break_end"], "2026-03-26 22:00:00")

    def test_missing_timeout_detects_overnight_shift_after_end(self):
        user = self.create_employee(username="nightshift")
        attendance = self.create_attendance(user["id"], "2026-03-26", "2026-03-26 16:00:00", None, status="Timed In")

        fake_now = attendance_app.datetime(2026, 3, 27, 0, 5, tzinfo=attendance_app.APP_TIMEZONE)
        with patch.object(attendance_app, "now_dt", return_value=fake_now):
            result = attendance_app.is_missing_timeout_today(user, attendance)

        self.assertTrue(result)

    def test_absent_detection_after_shift_start(self):
        user = self.create_employee(username="absent-user", schedule_days="Thu")
        fake_now = attendance_app.datetime(2026, 3, 26, 16, 5, tzinfo=attendance_app.APP_TIMEZONE)
        with patch.object(attendance_app, "now_dt", return_value=fake_now):
            result = attendance_app.is_absent_today(user, None)

        self.assertTrue(result)

    def test_get_home_route_for_user_accepts_sqlite_rows_via_fetchone(self):
        self.create_employee(username="home-user")

        with attendance_app.app.app_context():
            user = attendance_app.fetchone("SELECT * FROM users WHERE username = ?", ("home-user",))

        with attendance_app.app.test_request_context("/"):
            self.assertEqual(attendance_app.get_home_route_for_user(user), "/dashboard")


if __name__ == "__main__":
    unittest.main()
