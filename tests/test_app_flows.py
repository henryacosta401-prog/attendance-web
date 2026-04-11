import os
import re
import shutil
import tempfile
import unittest
from datetime import date, datetime
from io import BytesIO
from urllib.parse import quote
from unittest.mock import patch

import app as attendance_app
from werkzeug.datastructures import FileStorage


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
            attendance_app.invalidate_admin_employee_rows_cache()

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

    def create_incident_report(self, user_id, error_type="Wrong Costing", report_date="2026-04-08", status="Open", message="Test incident"):
        with attendance_app.app.app_context():
            employee = attendance_app.get_user_by_id(user_id)
            attendance_app.execute_db(
                """
                INSERT INTO incident_reports (
                    user_id, employee_name, report_department, error_type, incident_action,
                    incident_date, report_date, message, status, admin_note, created_by, created_at
                )
                VALUES (?, ?, ?, ?, 'Monitoring', ?, ?, ?, ?, NULL, NULL, ?)
                """,
                (
                    user_id,
                    employee["full_name"] if employee else f"User {user_id}",
                    employee["department"] if employee else "",
                    error_type,
                    report_date,
                    report_date,
                    message,
                    status,
                    attendance_app.now_str(),
                ),
                commit=True,
            )
            return attendance_app.fetchone(
                "SELECT * FROM incident_reports WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            )

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

    def test_employee_payslip_pdf_requires_admin_approval_first(self):
        admin = self.create_user(
            "payslip-approval-admin",
            role="admin",
            admin_permissions="dashboard,payroll",
            admin_role_preset="custom",
        )
        employee = self.create_user(
            "payslip-approval-employee",
            role="employee",
            full_name="Henry Acosta",
            hourly_rate=100,
        )
        self.create_attendance(
            employee["id"],
            "2026-04-07",
            "2026-04-07 09:00:00",
            "2026-04-07 18:00:00",
            status="Timed Out",
        )

        with attendance_app.app.app_context():
            payroll_run, _ = attendance_app.save_payroll_run_snapshot(
                date(2026, 4, 7),
                date(2026, 4, 7),
                employee_filter=str(employee["id"]),
                status="Released",
                actor_id=admin["id"],
            )

        employee_csrf = self.set_session_user(employee, csrf_token="employee-payroll-csrf")
        payslip_response = self.client.get(f"/my-payroll/{payroll_run['id']}")
        self.assertEqual(payslip_response.status_code, 200)
        self.assertIn(b"Request PDF Approval", payslip_response.data)

        request_response = self.client.post(
            f"/my-payroll/{payroll_run['id']}/request-download",
            data={"csrf_token": employee_csrf},
            follow_redirects=False,
        )
        self.assertEqual(request_response.status_code, 302)

        with attendance_app.app.app_context():
            request_row = attendance_app.fetchone(
                "SELECT * FROM payslip_download_requests WHERE user_id = ? AND payroll_run_id = ?",
                (employee["id"], payroll_run["id"]),
            )
            admin_notification = attendance_app.fetchone(
                "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (admin["id"],),
            )

        self.assertEqual(request_row["status"], "Pending")
        self.assertEqual(admin_notification["title"], "Payslip Download Approval Needed")

        blocked_download = self.client.get(
            f"/my-payroll/{payroll_run['id']}/download.pdf",
            follow_redirects=False,
        )
        self.assertEqual(blocked_download.status_code, 302)
        self.assertIn(f"/my-payroll/{payroll_run['id']}", blocked_download.headers.get("Location", ""))

        admin_csrf = self.set_session_user(admin, csrf_token="admin-payroll-csrf")
        review_response = self.client.post(
            f"/admin/payroll/download-requests/{request_row['id']}/review",
            data={
                "csrf_token": admin_csrf,
                "decision": "approve",
                "admin_note": "Approved for official employee copy.",
                "period": "custom",
                "date_from": "2026-04-07",
                "date_to": "2026-04-07",
                "department": "",
                "employee_id": str(employee["id"]),
            },
            follow_redirects=False,
        )
        self.assertEqual(review_response.status_code, 302)

        self.set_session_user(employee, csrf_token="employee-payroll-csrf-2")
        approved_payslip_response = self.client.get(f"/my-payroll/{payroll_run['id']}")
        self.assertEqual(approved_payslip_response.status_code, 200)
        self.assertIn(b"Approved", approved_payslip_response.data)
        self.assertIn(b"Download PDF", approved_payslip_response.data)

        pdf_response = self.client.get(f"/my-payroll/{payroll_run['id']}/download.pdf")
        self.assertEqual(pdf_response.status_code, 200)
        self.assertEqual(pdf_response.mimetype, "application/pdf")
        self.assertIn(b"%PDF", pdf_response.data[:10])

        with attendance_app.app.app_context():
            updated_request = attendance_app.fetchone(
                "SELECT * FROM payslip_download_requests WHERE id = ?",
                (request_row["id"],),
            )
            employee_notification = attendance_app.fetchone(
                "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (employee["id"],),
            )

        self.assertEqual(updated_request["status"], "Approved")
        self.assertEqual(employee_notification["title"], "Payslip PDF Request Approved")
        self.assertIn("Approved for official employee copy", employee_notification["message"])

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

    def test_rejecting_pending_leave_correction_updates_status_and_notification(self):
        admin = self.create_user(
            "reject-correction-admin",
            role="admin",
            admin_permissions="dashboard,attendance",
            admin_role_preset="attendance_supervisor",
        )
        employee = self.create_user("reject-leave-employee", role="employee")
        correction = self.create_correction_request(employee["id"])
        csrf_token = self.set_session_user(admin)

        response = self.client.post(
            f"/admin/corrections/{correction['id']}/update",
            data={
                "csrf_token": csrf_token,
                "status": "Rejected",
                "admin_note": "The submitted dates do not match the approved leave period.",
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

        self.assertEqual(updated["status"], "Rejected")
        self.assertEqual(updated["admin_note"], "The submitted dates do not match the approved leave period.")
        self.assertEqual(updated["reviewed_by"], admin["id"])
        self.assertTrue(updated["reviewed_at"])
        self.assertFalse(updated["applied_changes"])
        self.assertEqual(notification["title"], "Correction Request Updated")
        self.assertIn("Rejected", notification["message"])

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

    def test_employee_dashboard_shows_error_record_summary(self):
        employee = self.create_user(
            "dashboard-error-employee",
            role="employee",
            full_name="Error Dashboard Employee",
        )
        self.create_incident_report(employee["id"], error_type="Wrong Costing", report_date="2026-04-01", status="Open")
        self.create_incident_report(employee["id"], error_type="Wrong Costing", report_date="2026-04-02", status="Resolved")
        self.create_incident_report(employee["id"], error_type="Wrong Pricing", report_date="2026-04-03", status="Reviewed")

        with attendance_app.app.app_context():
            summary = attendance_app.get_employee_error_record_summary(employee["id"])

        self.assertEqual(summary["total_errors"], 3)
        self.assertEqual(summary["active_errors"], 2)
        self.assertEqual(summary["error_type_count"], 2)

        self.set_session_user(employee)
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Error Record Summary", response.data)
        self.assertIn(b"Wrong Costing", response.data)
        self.assertIn(b"Wrong Pricing", response.data)

    def test_admin_live_status_returns_lightweight_payload(self):
        admin = self.create_user(
            "live-status-admin",
            role="admin",
            admin_permissions="dashboard",
            admin_role_preset="viewer",
        )
        employee = self.create_user(
            "ajax-employee",
            role="employee",
            full_name="Aivo <Test>",
            department="Stellar Spec",
            position="Checker",
        )
        image_name = "profile-test.png"
        with open(os.path.join(self.upload_dir, image_name), "wb") as image_file:
            image_file.write(b"test-image")
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                "UPDATE users SET profile_image = ? WHERE id = ?",
                (image_name, employee["id"]),
                commit=True,
            )
            attendance_app.invalidate_admin_employee_rows_cache()
        self.set_session_user(admin)

        response = self.client.get("/admin/live-status?page_size=25")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["pagination"]["page_size"], 25)
        row = next(item for item in payload["rows"] if item["username"] == "ajax-employee")
        self.assertEqual(row["full_name"], "Aivo <Test>")
        self.assertIn("/uploads/profile-test.png", row["profile_image_url"])
        self.assertIn("row_signature", row)
        self.assertNotIn("password_hash", row)
        self.assertNotIn("admin_permissions", row)

    def test_save_uploaded_file_uses_cloudinary_storage_when_available(self):
        test_file = FileStorage(stream=BytesIO(b"cloudinary-test"), filename="avatar.png")
        with patch.object(attendance_app, "cloudinary_storage_enabled", return_value=True), patch.object(
            attendance_app,
            "upload_file_to_cloudinary",
            return_value="cld:image:stellar-seats/avatar:png",
        ) as mocked_upload:
            saved = attendance_app.save_uploaded_file(
                test_file,
                prefix="profile_1",
                allowed_exts=attendance_app.IMAGE_EXTENSIONS,
            )

        self.assertEqual(saved, "cld:image:stellar-seats/avatar:png")
        mocked_upload.assert_called_once()

    def test_scanner_can_open_cloudinary_profile_image_reference(self):
        scanner = self.create_user("remote-scanner", role="scanner", position="Scanner")
        employee = self.create_user("remote-image-employee", role="employee", full_name="Remote Image Employee")
        cloudinary_ref = "cld:image:stellar-seats/profile-test:png"
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                "UPDATE users SET profile_image = ? WHERE id = ?",
                (cloudinary_ref, employee["id"]),
                commit=True,
            )

        self.set_session_user(scanner)
        with patch.object(attendance_app, "CLOUDINARY_CLOUD_NAME", "demo-cloud"):
            response = self.client.get(f"/uploads/{quote(cloudinary_ref, safe='')}", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "https://res.cloudinary.com/demo-cloud/image/upload/stellar-seats/profile-test.png",
            response.headers.get("Location", ""),
        )

    def test_data_tools_shows_backup_clarity_and_records_external_marker(self):
        admin = self.create_user(
            "backup-admin",
            role="admin",
            admin_permissions="dashboard,settings",
            admin_role_preset="custom",
        )
        csrf_token = self.set_session_user(admin)

        page_response = self.client.get("/admin/data-tools")
        self.assertEqual(page_response.status_code, 200)
        self.assertIn(b"Last External Render/Postgres Backup Noted", page_response.data)
        self.assertIn(b"not a one-click database restore", page_response.data)

        response = self.client.post(
            "/admin/data-tools",
            data={
                "csrf_token": csrf_token,
                "action": "record_external_backup",
                "external_backup_note": "Render snapshot checked before cleanup",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"External Render/Postgres backup note saved", response.data)
        self.assertIn(b"Render snapshot checked before cleanup", response.data)
        with attendance_app.app.app_context():
            settings = attendance_app.get_company_settings()

        self.assertIsNotNone(settings["last_external_backup_at"])
        self.assertEqual(int(settings["last_external_backup_by"]), admin["id"])
        self.assertEqual(settings["last_external_backup_note"], "Render snapshot checked before cleanup")

    def test_employee_id_signatory_update_supports_hr_manager(self):
        admin = self.create_user(
            "id-admin",
            role="admin",
            admin_permissions="dashboard,settings,employees",
            admin_role_preset="custom",
        )
        employee = self.create_user(
            "id-employee",
            role="employee",
            full_name="Deo Dame Saligumba",
            department="People Operations",
            position="Human Resources Manager",
        )
        with attendance_app.app.app_context():
            attendance_app.execute_db(
                "UPDATE users SET emergency_contact_name = ?, emergency_contact_phone = ? WHERE id = ?",
                ("Shiela Mae Saligumba", "+63 975 355 1397", employee["id"]),
                commit=True,
            )
        csrf_token = self.set_session_user(admin)

        response = self.client.post(
            "/admin/employee-id/signatory",
            data={
                "csrf_token": csrf_token,
                "employee_id": str(employee["id"]),
                "id_signatory_name": "Kirk Danny Fernandez",
                "id_signatory_title": "Director of Operations",
                "hr_signatory_name": "Deo Dame M. Saligumba",
                "hr_signatory_title": "Human Resources Manager",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/admin/employee-id/{employee['id']}", response.headers.get("Location", ""))
        with attendance_app.app.app_context():
            settings = attendance_app.get_company_settings()

        self.assertEqual(settings["id_signatory_title"], "Director of Operations")
        self.assertEqual(settings["hr_signatory_name"], "Deo Dame M. Saligumba")
        self.assertEqual(settings["hr_signatory_title"], "Human Resources Manager")

        page_response = self.client.get(f"/admin/employee-id/{employee['id']}")
        self.assertEqual(page_response.status_code, 200)
        self.assertIn(b"Portrait ID", page_response.data)
        self.assertIn(b"Human Resources Manager", page_response.data)
        self.assertIn(b"Director of Operations", page_response.data)
        self.assertIn(b"Global ID Signatories", page_response.data)

    def test_admin_can_download_employee_barcode_svg(self):
        admin = self.create_user(
            "barcode-export-admin",
            role="admin",
            admin_permissions="dashboard,employees",
            admin_role_preset="custom",
        )
        employee = self.create_user(
            "barcode-export-employee",
            role="employee",
            full_name="Henry Acosta",
            barcode_id="SS-2023-0001",
        )
        self.set_session_user(admin)

        response = self.client.get(f"/admin/employee-id/{employee['id']}/barcode")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/svg+xml")
        self.assertIn("attachment;", response.headers.get("Content-Disposition", ""))
        self.assertIn("Henry_Acosta-barcode.svg", response.headers.get("Content-Disposition", ""))
        self.assertIn(b"<svg", response.data)
        self.assertIn(b"SS-2023-0001", response.data)

    def test_leave_dashboard_supports_employee_name_filter(self):
        admin = self.create_user("leave-filter-admin", role="admin")
        employee_one = self.create_user(
            "leave-filter-1",
            role="employee",
            full_name="Aira Santos",
            department="Human Resources",
        )
        employee_two = self.create_user(
            "leave-filter-2",
            role="employee",
            full_name="Brian Cruz",
            department="Operations",
        )
        self.create_correction_request(
            employee_one["id"],
            request_type="Paid Leave",
            work_date="2026-04-08",
            end_work_date="2026-04-08",
        )
        self.create_correction_request(
            employee_two["id"],
            request_type="Sick Leave",
            work_date="2026-04-09",
            end_work_date="2026-04-09",
        )
        self.set_session_user(admin)

        response = self.client.get(f"/admin/leave?year=2026&department=Human+Resources&employee_id={employee_one['id']}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Aira Santos", response.data)
        self.assertNotIn(b"Brian Cruz", response.data)
        self.assertIn(f"employee_id={employee_one['id']}".encode(), response.data)

    def test_disciplinary_dashboard_hides_suspension_days_for_coaching(self):
        admin = self.create_user("discipline-admin", role="admin")
        employee = self.create_user(
            "discipline-employee",
            role="employee",
            full_name="Henry Acosta",
            department="Operations",
        )
        with attendance_app.app.app_context():
            attendance_app.create_disciplinary_action(
                user_id=employee["id"],
                action_type="Coaching",
                action_date="2026-04-10",
                details="Coaching note",
                created_by=admin["id"],
                duration_days=1,
            )
        self.set_session_user(admin)

        response = self.client.get("/admin/disciplinary")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Only used for Suspension records.", response.data)
        self.assertRegex(
            response.data.decode("utf-8"),
            r"<td>Coaching</td>\s*<td>2026-04-10</td>\s*<td>-</td>",
        )

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

    def test_incident_policy_creates_linked_disciplinary_steps(self):
        admin = self.create_user("incident-admin", role="admin")
        employee = self.create_user("incident-employee", role="employee", full_name="Incident Employee")
        csrf_token = self.set_session_user(admin)

        for index, report_date in enumerate(
            ["2026-04-01", "2026-04-02", "2026-04-03", "2026-04-04", "2026-04-05"],
            start=1,
        ):
            response = self.client.post(
                "/admin/create-incident",
                data={
                    "csrf_token": csrf_token,
                    "user_id": str(employee["id"]),
                    "error_type": "Wrong Costing",
                    "report_date": report_date,
                    "message": f"Wrong costing #{index}",
                },
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)

        with attendance_app.app.app_context():
            reports = attendance_app.fetchall(
                "SELECT * FROM incident_reports WHERE user_id = ? ORDER BY id ASC",
                (employee["id"],),
            )
            actions = attendance_app.fetchall(
                "SELECT * FROM disciplinary_actions WHERE user_id = ? ORDER BY id ASC",
                (employee["id"],),
            )
            still_active = attendance_app.get_user_by_id(employee["id"])

        self.assertEqual([row["policy_incident_count"] for row in reports], [1, 2, 3, 4, 5])
        self.assertEqual([row["action_type"] for row in actions], ["Coaching", "NTE", "Suspension", "Termination"])
        self.assertEqual(actions[0]["incident_report_id"], reports[1]["id"])
        self.assertEqual(actions[-1]["incident_report_id"], reports[-1]["id"])
        self.assertEqual(actions[-1]["error_type"], "Wrong Costing")
        self.assertEqual(still_active["is_active"], 1)

        error_reports_response = self.client.get("/admin/error-reports")
        disciplinary_response = self.client.get("/admin/disciplinary")
        self.assertEqual(error_reports_response.status_code, 200)
        self.assertEqual(disciplinary_response.status_code, 200)
        self.assertIn(b"Termination", disciplinary_response.data)

    def test_incident_custom_error_type_is_saved_as_option(self):
        admin = self.create_user("custom-error-admin", role="admin")
        employee = self.create_user("custom-error-employee", role="employee")
        csrf_token = self.set_session_user(admin)

        response = self.client.post(
            "/admin/create-incident",
            data={
                "csrf_token": csrf_token,
                "user_id": str(employee["id"]),
                "error_type": "__new__",
                "new_error_type": "Wrong Inventory Tag",
                "report_date": "2026-04-06",
                "message": "Custom error type test",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        with attendance_app.app.app_context():
            report = attendance_app.fetchone(
                "SELECT * FROM incident_reports WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (employee["id"],),
            )
            options = attendance_app.get_incident_error_type_options()

        self.assertEqual(report["error_type"], "Wrong Inventory Tag")
        self.assertIn("Wrong Inventory Tag", options)


if __name__ == "__main__":
    unittest.main()
