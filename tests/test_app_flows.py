import os
import shutil
import tempfile
import unittest
from datetime import date, datetime
from unittest.mock import patch

import app as attendance_app


class AppFlowsTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="attendance-flow-tests-")
        self.db_path = os.path.join(self.temp_dir, "attendance-flow-test.db")
        self.upload_dir = os.path.join(self.temp_dir, "uploads")
        self.backup_dir = os.path.join(self.temp_dir, "backups")
        os.makedirs(self.upload_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

        attendance_app.SQLITE_DATABASE = self.db_path
        attendance_app.UPLOAD_FOLDER = self.upload_dir
        attendance_app.BACKUP_FOLDER = self.backup_dir
        attendance_app.app.config["UPLOAD_FOLDER"] = self.upload_dir
        attendance_app.app.config["TESTING"] = True
        self.client = attendance_app.app.test_client()

        with attendance_app.app.app_context():
            attendance_app.close_db()
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            attendance_app.init_sqlite_db()

    def tearDown(self):
        with attendance_app.app.app_context():
            attendance_app.close_db()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_user(
        self,
        username,
        role="employee",
        full_name=None,
        department="Ops",
        position="Agent",
        barcode_id="",
        hourly_rate=0,
        admin_permissions=None,
        admin_role_preset="",
        shift_start="09:00",
        shift_end="18:00",
        schedule_days="Mon,Tue,Wed,Thu,Fri",
        break_limit=15,
        is_active=1,
    ):
        full_name = full_name or f"User {username}"
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                """
                INSERT INTO users (
                    full_name, username, password_hash, role, department, position,
                    barcode_id, hourly_rate, schedule_days, shift_start, shift_end,
                    admin_permissions, admin_role_preset, break_limit_minutes,
                    is_active, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    full_name,
                    username,
                    "hash",
                    role,
                    department,
                    position,
                    barcode_id or None,
                    hourly_rate,
                    schedule_days,
                    shift_start,
                    shift_end,
                    admin_permissions,
                    admin_role_preset,
                    break_limit,
                    is_active,
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

    def create_overtime_session(self, user_id, work_date, overtime_start, overtime_end=None, attendance_id=None):
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                """
                INSERT INTO overtime_sessions (
                    user_id, attendance_id, work_date, overtime_start, overtime_end, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    attendance_id,
                    work_date,
                    overtime_start,
                    overtime_end,
                    attendance_app.now_str(),
                ),
                commit=True,
            )
            return attendance_app.fetchone(
                "SELECT * FROM overtime_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            )

    def create_correction_request(self, user_id, request_type="Paid Leave", work_date="2026-04-08", end_work_date="2026-04-09"):
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                """
                INSERT INTO correction_requests (
                    user_id, request_type, work_date, end_work_date, message,
                    requested_time_in, requested_break_start, requested_break_end, requested_time_out,
                    applied_changes, status, admin_note, reviewed_by, reviewed_at, created_at
                )
                VALUES (?, ?, ?, ?, '', NULL, NULL, NULL, NULL, NULL, 'Pending', NULL, NULL, NULL, ?)
                """,
                (user_id, request_type, work_date, end_work_date, attendance_app.now_str()),
                commit=True,
            )
            return attendance_app.fetchone("SELECT * FROM correction_requests WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))

    def set_session_user(self, user, csrf_token="test-csrf-token"):
        with self.client.session_transaction() as session_state:
            session_state["user_id"] = user["id"]
            session_state["role"] = user["role"]
            session_state["full_name"] = user["full_name"]
            session_state["_csrf_token"] = csrf_token
        return csrf_token

    def test_reports_admin_can_access_reports_but_not_payroll(self):
        admin = self.create_user(
            "reports-admin",
            role="admin",
            admin_permissions="dashboard,reports",
            admin_role_preset="reports_viewer",
            position="Viewer",
        )
        self.set_session_user(admin)

        reports_response = self.client.get("/admin/reports")
        payroll_response = self.client.get("/admin/payroll", follow_redirects=False)

        self.assertEqual(reports_response.status_code, 200)
        self.assertEqual(payroll_response.status_code, 302)
        self.assertIn("/admin", payroll_response.headers.get("Location", ""))

    def test_scanner_scan_time_in_creates_attendance_and_log(self):
        scanner = self.create_user("scanner-user", role="scanner", position="Scanner")
        employee = self.create_user(
            "barcode-employee",
            role="employee",
            full_name="Henry Scanner",
            barcode_id="ABC123",
            shift_start="16:00",
            shift_end="00:00",
            break_limit=20,
        )
        csrf_token = self.set_session_user(scanner)

        response = self.client.post(
            "/scanner/scan",
            data={
                "csrf_token": csrf_token,
                "action_type": "time_in",
                "barcode_value": "ABC123",
            },
            headers={"User-Agent": "Codex Test Scanner"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])

        with attendance_app.app.app_context():
            attendance = attendance_app.fetchone(
                "SELECT * FROM attendance WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (employee["id"],),
            )
            scanner_log = attendance_app.fetchone(
                "SELECT * FROM scanner_logs WHERE employee_user_id = ? ORDER BY id DESC LIMIT 1",
                (employee["id"],),
            )

        self.assertIsNotNone(attendance)
        self.assertIsNotNone(attendance["time_in"])
        self.assertEqual(scanner_log["action_type"], "time_in")
        self.assertEqual(scanner_log["result_status"], "success")
        self.assertEqual(scanner_log["employee_name_snapshot"], "Henry Scanner")

    def test_released_payroll_snapshot_cannot_be_saved_back_to_draft(self):
        admin = self.create_user("payroll-admin", role="admin", admin_permissions="dashboard,payroll,reports")
        employee = self.create_user("payroll-employee", role="employee", hourly_rate=100)
        self.create_attendance(
            employee["id"],
            "2026-04-07",
            "2026-04-07 09:00:00",
            "2026-04-07 18:00:00",
            status="Timed Out",
        )

        with attendance_app.app.app_context():
            attendance_app.save_payroll_run_snapshot(
                date(2026, 4, 7),
                date(2026, 4, 7),
                employee_filter=str(employee["id"]),
                status="Released",
                actor_id=admin["id"],
            )
            with self.assertRaises(ValueError):
                attendance_app.save_payroll_run_snapshot(
                    date(2026, 4, 7),
                    date(2026, 4, 7),
                    employee_filter=str(employee["id"]),
                    status="Draft",
                    actor_id=admin["id"],
                )
            payroll_run = attendance_app.get_payroll_run("2026-04-07", "2026-04-07", "", str(employee["id"]))

        self.assertEqual(payroll_run["status"], "Released")

    def test_releasing_same_payroll_scope_twice_preserves_prior_release_snapshot(self):
        admin = self.create_user("payroll-release-admin", role="admin", admin_permissions="dashboard,payroll,reports")
        employee = self.create_user("released-payroll-employee", role="employee", hourly_rate=100)
        self.create_attendance(
            employee["id"],
            "2026-04-07",
            "2026-04-07 09:00:00",
            "2026-04-07 18:00:00",
            status="Timed Out",
        )

        with attendance_app.app.app_context():
            first_run, _ = attendance_app.save_payroll_run_snapshot(
                date(2026, 4, 7),
                date(2026, 4, 7),
                employee_filter=str(employee["id"]),
                status="Released",
                notes="First release",
                actor_id=admin["id"],
            )
            second_run, _ = attendance_app.save_payroll_run_snapshot(
                date(2026, 4, 7),
                date(2026, 4, 7),
                employee_filter=str(employee["id"]),
                status="Released",
                notes="Second release",
                actor_id=admin["id"],
            )
            release_count = attendance_app.fetchone(
                """
                SELECT COUNT(*) AS total
                FROM payroll_runs
                WHERE date_from = ? AND date_to = ? AND employee_filter = ? AND status = 'Released'
                """,
                ("2026-04-07", "2026-04-07", str(employee["id"])),
            )["total"]

        self.assertNotEqual(first_run["id"], second_run["id"])
        self.assertEqual(release_count, 2)

    def test_approving_leave_correction_updates_status_and_notification(self):
        admin = self.create_user(
            "correction-admin",
            role="admin",
            admin_permissions="dashboard,attendance",
            admin_role_preset="attendance_supervisor",
        )
        employee = self.create_user("leave-employee", role="employee")
        correction = self.create_correction_request(employee["id"])
        csrf_token = self.set_session_user(admin)

        response = self.client.post(
            f"/admin/corrections/{correction['id']}/update",
            data={
                "csrf_token": csrf_token,
                "status": "Approved",
                "admin_note": "Approved for payroll period.",
                "requested_time_in": "",
                "requested_break_start": "",
                "requested_break_end": "",
                "requested_time_out": "",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)

        with attendance_app.app.app_context():
            updated = attendance_app.fetchone("SELECT * FROM correction_requests WHERE id = ?", (correction["id"],))
            notification = attendance_app.fetchone(
                "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (employee["id"],),
            )

        self.assertEqual(updated["status"], "Approved")
        self.assertIn("Paid Leave approved", updated["applied_changes"] or "")
        self.assertEqual(notification["title"], "Correction Request Updated")
        self.assertIn("Approved", notification["message"])

    def test_reviewed_correction_cannot_be_moved_back_to_rejected(self):
        admin = self.create_user(
            "locked-correction-admin",
            role="admin",
            admin_permissions="dashboard,attendance",
            admin_role_preset="attendance_supervisor",
        )
        employee = self.create_user("locked-correction-employee", role="employee")
        correction = self.create_correction_request(employee["id"])
        csrf_token = self.set_session_user(admin)

        first_response = self.client.post(
            f"/admin/corrections/{correction['id']}/update",
            data={
                "csrf_token": csrf_token,
                "status": "Approved",
                "admin_note": "Initial approval.",
                "requested_time_in": "",
                "requested_break_start": "",
                "requested_break_end": "",
                "requested_time_out": "",
            },
            follow_redirects=False,
        )
        self.assertEqual(first_response.status_code, 302)

        second_response = self.client.post(
            f"/admin/corrections/{correction['id']}/update",
            data={
                "csrf_token": csrf_token,
                "status": "Rejected",
                "admin_note": "Trying to change it after approval.",
                "requested_time_in": "",
                "requested_break_start": "",
                "requested_break_end": "",
                "requested_time_out": "",
            },
            follow_redirects=False,
        )
        self.assertEqual(second_response.status_code, 302)

        with attendance_app.app.app_context():
            updated = attendance_app.fetchone("SELECT * FROM correction_requests WHERE id = ?", (correction["id"],))

        self.assertEqual(updated["status"], "Approved")
        self.assertEqual(updated["admin_note"], "Initial approval.")
        self.assertIn("Paid Leave approved", updated["applied_changes"] or "")

    def test_inactive_employee_session_is_redirected_to_login(self):
        inactive_employee = self.create_user("inactive-employee", role="employee", is_active=0)
        self.set_session_user(inactive_employee)

        response = self.client.get("/dashboard", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers.get("Location", ""))

    def test_login_route_redirects_active_session_to_home(self):
        admin = self.create_user(
            "login-redirect-admin",
            role="admin",
            admin_permissions="dashboard",
            admin_role_preset="viewer",
        )
        self.set_session_user(admin)

        response = self.client.get("/login", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin", response.headers.get("Location", ""))

    def test_stale_csrf_redirect_does_not_render_login_form_inside_admin_shell(self):
        admin = self.create_user(
            "csrf-admin",
            role="admin",
            admin_permissions="dashboard",
            admin_role_preset="viewer",
        )
        self.set_session_user(admin, csrf_token="fresh-token")

        response = self.client.post(
            "/logout",
            data={"csrf_token": "stale-token"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your session expired or the form is no longer valid", response.data)
        self.assertIn(b"Logout", response.data)
        self.assertNotIn(b"Welcome Back", response.data)

    def test_overtime_end_after_midnight_keeps_valid_open_session(self):
        employee = self.create_user(
            "overnight-overtime-employee",
            role="employee",
            shift_start="09:00",
            shift_end="18:00",
        )
        self.create_overtime_session(
            employee["id"],
            "2026-04-07",
            "2026-04-07 23:30:00",
        )
        fake_now = datetime(2026, 4, 8, 0, 30, tzinfo=attendance_app.APP_TIMEZONE)

        with patch.object(attendance_app, "now_dt", return_value=fake_now):
            with attendance_app.app.app_context():
                success, message, _ = attendance_app.perform_attendance_action(
                    employee["id"],
                    "overtime_end",
                    actor_id=employee["id"],
                    source_label="Test",
                )
                session_row = attendance_app.fetchone(
                    "SELECT * FROM overtime_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                    (employee["id"],),
                )

        self.assertTrue(success)
        self.assertEqual(message, "Overtime ended.")
        self.assertEqual(session_row["overtime_end"], "2026-04-08 00:30:00")


if __name__ == "__main__":
    unittest.main()
