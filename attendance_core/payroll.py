import calendar
import textwrap
from io import BytesIO

from werkzeug.utils import secure_filename

from attendance_core.date_ranges import parse_iso_date
from attendance_core.formatters import format_currency


def recurring_rule_applies_to_period(rule_row, period_from, period_to):
    if int(rule_row.get("is_active") or 0) != 1:
        return False

    start_date = parse_iso_date(rule_row.get("start_date"))
    end_date = parse_iso_date(rule_row.get("end_date"))
    if start_date and period_to < start_date:
        return False
    if end_date and period_from > end_date:
        return False

    recurrence_type = (rule_row.get("recurrence_type") or "Every Payroll").strip() or "Every Payroll"
    if recurrence_type != "Monthly":
        return True

    anchor_source = start_date or period_from.replace(day=1)
    anchor_day = anchor_source.day
    month_cursor = period_from.replace(day=1)
    final_month = period_to.replace(day=1)
    while month_cursor <= final_month:
        days_in_month = calendar.monthrange(month_cursor.year, month_cursor.month)[1]
        candidate_day = min(anchor_day, days_in_month)
        candidate_date = month_cursor.replace(day=candidate_day)
        if start_date and candidate_date < start_date:
            candidate_date = start_date if start_date.year == month_cursor.year and start_date.month == month_cursor.month else candidate_date
        if end_date and candidate_date > end_date:
            pass
        elif period_from <= candidate_date <= period_to:
            return True

        if month_cursor.month == 12:
            month_cursor = month_cursor.replace(year=month_cursor.year + 1, month=1)
        else:
            month_cursor = month_cursor.replace(month=month_cursor.month + 1)
    return False


def format_payroll_period_label(date_from, date_to):
    start_date = parse_iso_date(date_from)
    end_date = parse_iso_date(date_to, start_date)
    if not start_date or not end_date:
        return f"{date_from} to {date_to}"
    if start_date.year == end_date.year and start_date.month == end_date.month:
        return f"{start_date.strftime('%b %d')} - {end_date.strftime('%d, %Y')}"
    return f"{start_date.strftime('%b %d, %Y')} - {end_date.strftime('%b %d, %Y')}"


def get_payroll_scope_label(employee_filter="", department_filter="", current_user_id=None):
    employee_filter_value = str(employee_filter or "").strip()
    if employee_filter_value.isdigit():
        if current_user_id and int(employee_filter_value) == int(current_user_id):
            return "Employee-only release"
        return "Filtered employee release"
    if department_filter:
        return f"{department_filter} release"
    return "Company-wide release"


def pdf_escape_text(value):
    text = str(value or "")
    text = text.replace("\r", " ").replace("\n", " ")
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf_wrap_lines(value, width):
    text = str(value or "").strip()
    if not text:
        return [""]
    return textwrap.wrap(text, width=width) or [text]


def build_employee_payslip_pdf_filename(payslip):
    base_name = secure_filename(
        f"{payslip.get('full_name', 'employee')}_{payslip.get('date_from', '')}_{payslip.get('date_to', '')}_payslip.pdf"
    )
    return base_name or "employee_payslip.pdf"


def build_employee_payslip_pdf_bytes(payslip, printed_at_text=""):
    page_width = 612
    page_height = 792
    margin = 42
    content_width = page_width - (margin * 2)

    commands = []

    def add_fill_color(r, g, b):
        commands.append(f"{r:.3f} {g:.3f} {b:.3f} rg")

    def add_stroke_color(r, g, b):
        commands.append(f"{r:.3f} {g:.3f} {b:.3f} RG")

    def add_rect(x, y, width, height, fill_rgb=None, stroke_rgb=None, line_width=1):
        if fill_rgb:
            add_fill_color(*fill_rgb)
        if stroke_rgb:
            add_stroke_color(*stroke_rgb)
            commands.append(f"{line_width:.2f} w")
        commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re")
        if fill_rgb and stroke_rgb:
            commands.append("B")
        elif fill_rgb:
            commands.append("f")
        else:
            commands.append("S")

    def add_text(x, y, text, size=11, font="F1", rgb=(0.12, 0.16, 0.25)):
        safe_text = pdf_escape_text(text)
        add_fill_color(*rgb)
        commands.append(f"BT /{font} {size:.2f} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm ({safe_text}) Tj ET")

    def add_wrapped_text(x, y, text, width_chars, size=10, font="F1", rgb=(0.12, 0.16, 0.25), leading=13, max_lines=None):
        lines = pdf_wrap_lines(text, width_chars)
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines]
            lines[-1] = lines[-1].rstrip(". ") + "..."
        current_y = y
        for line in lines:
            add_text(x, current_y, line, size=size, font=font, rgb=rgb)
            current_y -= leading
        return current_y

    def add_circle(cx, cy, radius, fill_rgb=None, stroke_rgb=None, line_width=1):
        kappa = 0.552284749831 * radius
        if fill_rgb:
            add_fill_color(*fill_rgb)
        if stroke_rgb:
            add_stroke_color(*stroke_rgb)
            commands.append(f"{line_width:.2f} w")
        commands.append(f"{cx + radius:.2f} {cy:.2f} m")
        commands.append(f"{cx + radius:.2f} {cy + kappa:.2f} {cx + kappa:.2f} {cy + radius:.2f} {cx:.2f} {cy + radius:.2f} c")
        commands.append(f"{cx - kappa:.2f} {cy + radius:.2f} {cx - radius:.2f} {cy + kappa:.2f} {cx - radius:.2f} {cy:.2f} c")
        commands.append(f"{cx - radius:.2f} {cy - kappa:.2f} {cx - kappa:.2f} {cy - radius:.2f} {cx:.2f} {cy - radius:.2f} c")
        commands.append(f"{cx + kappa:.2f} {cy - radius:.2f} {cx + radius:.2f} {cy - kappa:.2f} {cx + radius:.2f} {cy:.2f} c")
        if fill_rgb and stroke_rgb:
            commands.append("B")
        elif fill_rgb:
            commands.append("f")
        else:
            commands.append("S")

    def add_line(x1, y1, x2, y2, stroke_rgb=(0, 0, 0), line_width=1, line_cap=0):
        add_stroke_color(*stroke_rgb)
        commands.append(f"{line_width:.2f} w")
        commands.append(f"{line_cap} J")
        commands.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def add_polyline(points, stroke_rgb=(0, 0, 0), line_width=1, line_cap=1, line_join=1):
        if not points or len(points) < 2:
            return
        add_stroke_color(*stroke_rgb)
        commands.append(f"{line_width:.2f} w")
        commands.append(f"{line_cap} J")
        commands.append(f"{line_join} j")
        start_x, start_y = points[0]
        commands.append(f"{start_x:.2f} {start_y:.2f} m")
        for point_x, point_y in points[1:]:
            commands.append(f"{point_x:.2f} {point_y:.2f} l")
        commands.append("S")

    def add_brand_logo(x, y, size=36):
        scale = size / 256.0

        def map_point(svg_x, svg_y):
            return (x + (svg_x * scale), y + ((256 - svg_y) * scale))

        circle_cx, circle_cy = map_point(128, 128)
        add_circle(
            circle_cx,
            circle_cy,
            92 * scale,
            fill_rgb=(0.06, 0.09, 0.17),
            stroke_rgb=(0.20, 0.27, 0.36),
            line_width=max(size * 0.0085, 0.45),
        )

        white = (0.97, 0.98, 0.99)
        stroke_width = max(size * (7 / 256.0), 0.95)
        logo_paths = [
            [(80, 93), (80, 154), (68, 174), (68, 204)],
            [(98, 78), (98, 155), (87, 174), (87, 210)],
            [(116, 63), (116, 157), (107, 174), (107, 214)],
            [(128, 56), (128, 162)],
            [(140, 63), (140, 157), (149, 174), (149, 214)],
            [(158, 78), (158, 155), (169, 174), (169, 210)],
            [(176, 93), (176, 154), (188, 174), (188, 204)],
        ]

        for path in logo_paths:
            add_polyline(
                [map_point(point_x, point_y) for point_x, point_y in path],
                stroke_rgb=white,
                line_width=stroke_width,
                line_cap=1,
                line_join=1,
            )

    brand_blue = (0.10, 0.20, 0.42)
    panel_fill = (0.95, 0.97, 0.99)
    panel_border = (0.83, 0.87, 0.93)
    label_color = (0.37, 0.47, 0.62)
    body_color = (0.12, 0.16, 0.25)
    brand_gold = (1.0, 0.93, 0.55)
    brand_accent = (0.58, 0.72, 1.0)

    add_rect(margin, page_height - 92, content_width, 50, fill_rgb=brand_blue)
    add_rect(margin, page_height - 46, content_width, 2.5, fill_rgb=brand_accent)
    add_brand_logo(margin + 14, page_height - 84, size=34)
    add_text(margin + 58, page_height - 64, "STELLAR SEATS", size=20, font="F2", rgb=(1, 1, 1))
    add_text(margin + 58, page_height - 80, "Official Employee Payslip", size=10, font="F1", rgb=(0.87, 0.92, 1))
    add_text(margin + content_width - 190, page_height - 64, payslip.get("period_label", "Payroll Period"), size=11, font="F2", rgb=brand_gold)
    add_text(margin + content_width - 190, page_height - 80, f"{payslip.get('date_from', '')} to {payslip.get('date_to', '')}", size=9, font="F1", rgb=(0.87, 0.92, 1))

    card_gap = 10
    card_width = (content_width - (card_gap * 3)) / 4
    card_y = page_height - 180
    summary_cards = [
        ("Final Pay", format_currency(payslip.get("final_pay"))),
        ("Regular Pay", format_currency(payslip.get("gross_pay"))),
        ("Overtime Pay", format_currency(payslip.get("overtime_pay"))),
        ("Adjustments", format_currency(payslip.get("adjustment_balance"))),
    ]
    for index, (label, value) in enumerate(summary_cards):
        card_x = margin + index * (card_width + card_gap)
        add_rect(card_x, card_y, card_width, 64, fill_rgb=panel_fill, stroke_rgb=panel_border)
        add_text(card_x + 12, card_y + 45, label.upper(), size=8.5, font="F2", rgb=label_color)
        add_text(card_x + 12, card_y + 20, value, size=16, font="F2", rgb=body_color)

    left_x = margin
    left_width = 326
    gap = 14
    right_x = left_x + left_width + gap
    right_width = content_width - left_width - gap
    panel_top = card_y - 18
    left_height = 290
    right_height = 230

    add_rect(left_x, panel_top - left_height, left_width, left_height, fill_rgb=panel_fill, stroke_rgb=panel_border)
    add_rect(right_x, panel_top - right_height, right_width, right_height, fill_rgb=panel_fill, stroke_rgb=panel_border)

    add_text(left_x + 16, panel_top - 24, "Payroll Details", size=13, font="F2", rgb=body_color)
    add_text(right_x + 16, panel_top - 24, "Pay Breakdown", size=13, font="F2", rgb=body_color)

    detail_rows = [
        ("Employee", payslip.get("full_name")),
        ("Department / Position", f"{payslip.get('department', '')} | {payslip.get('position', '')}".strip(" |")),
        ("Hourly Rate", format_currency(payslip.get("hourly_rate"))),
        ("Days Worked", payslip.get("days_worked", 0)),
        ("Regular Hours", f"{float(payslip.get('total_hours') or 0):.2f}"),
        ("Overtime Hours", f"{float(payslip.get('overtime_hours') or 0):.2f}"),
        ("Late Minutes", payslip.get("late_minutes", 0)),
        ("Break Minutes", payslip.get("break_minutes", 0)),
        ("Suspension Days", payslip.get("suspension_days", 0)),
        ("Suspension Loss", format_currency(payslip.get("suspension_pay"))),
        ("Release Scope", payslip.get("scope_label")),
        ("Released", payslip.get("released_display") or "Released"),
        ("Prepared By", payslip.get("created_by_name")),
    ]

    current_y = panel_top - 48
    for label, value in detail_rows:
        add_text(left_x + 16, current_y, label.upper(), size=8, font="F2", rgb=label_color)
        lines = pdf_wrap_lines(value, 30)
        add_text(left_x + 145, current_y, lines[0], size=9.5, font="F1", rgb=body_color)
        extra_y = current_y
        for extra_line in lines[1:2]:
            extra_y -= 11
            add_text(left_x + 145, extra_y, extra_line, size=9.5, font="F1", rgb=body_color)
        current_y -= 19 if len(lines) == 1 else 28

    breakdown_rows = [
        ("Regular Pay", "Base pay from recorded shift hours", format_currency(payslip.get("gross_pay"))),
        ("Overtime Pay", f"{float(payslip.get('overtime_hours') or 0):.2f} overtime hours included", format_currency(payslip.get("overtime_pay"))),
        ("Allowances", "Manual additions saved in payroll", format_currency(payslip.get("allowances"))),
        ("Deductions", "Manual deductions saved in payroll", format_currency(payslip.get("deductions"))),
        ("Final Pay", "Released total for this pay period", format_currency(payslip.get("final_pay"))),
    ]
    current_y = panel_top - 52
    for index, (label, sub_label, value) in enumerate(breakdown_rows):
        add_text(right_x + 16, current_y, label, size=10.5, font="F2", rgb=body_color)
        add_wrapped_text(right_x + 16, current_y - 12, sub_label, width_chars=26, size=8, font="F1", rgb=label_color, leading=10, max_lines=2)
        add_text(right_x + right_width - 100, current_y - 2, value, size=10.5 if index < len(breakdown_rows) - 1 else 12.5, font="F2", rgb=body_color)
        current_y -= 42

    notes_y = panel_top - left_height - 18
    add_rect(margin, notes_y - 114, content_width, 114, fill_rgb=panel_fill, stroke_rgb=panel_border)
    adjustment_entries = payslip.get("adjustment_entries") or []
    missing_adjustment_detail = bool(payslip.get("missing_adjustment_detail"))
    if adjustment_entries:
        notes_title = "Adjustment Reasons"
        detail_lines = []
        for entry in adjustment_entries:
            amount_text = format_currency(entry.get("amount"))
            prefix = "Deduction" if entry.get("adjustment_type") == "Deduction" else "Allowance"
            source_text = entry.get("source_kind") or "Manual"
            if entry.get("recurrence_type"):
                source_text = f"{source_text} / {entry.get('recurrence_type')}"
            detail_lines.append(f"{prefix} - {entry.get('label')} ({source_text}): {amount_text}")
            if entry.get("notes"):
                detail_lines.append(f"Reason: {entry.get('notes')}")
    elif missing_adjustment_detail:
        notes_title = "Adjustment Reasons"
        detail_lines = [
            "This released payroll includes an allowance or deduction total,",
            "but the line-by-line reason was not stored in this older snapshot."
        ]
    else:
        notes_title = "Notes"
        detail_lines = pdf_wrap_lines(
            payslip.get("notes") or "This downloadable copy reflects the released payroll snapshot stored by Stellar Seats for your account.",
            92
        )
    add_text(margin + 16, notes_y - 22, notes_title, size=12, font="F2", rgb=body_color)
    add_wrapped_text(
        margin + 16,
        notes_y - 42,
        " ".join(detail_lines),
        width_chars=92,
        size=9.5,
        font="F1",
        rgb=body_color,
        leading=12,
        max_lines=6
    )

    footer_y = 56
    add_text(margin, footer_y, "Generated by Stellar Seats Attendance Dashboard", size=8.5, font="F1", rgb=label_color)
    add_text(page_width - 190, footer_y, f"Printed {printed_at_text}", size=8.5, font="F1", rgb=label_color)

    content_stream = "\n".join(commands).encode("latin-1", "replace")

    objects = []

    def add_object(payload):
        objects.append(payload)
        return len(objects)

    font_regular_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    font_bold_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    content_id = add_object(
        f"<< /Length {len(content_stream)} >>\nstream\n".encode("latin-1") + content_stream + b"\nendstream"
    )
    page_id = add_object(
        f"<< /Type /Page /Parent 5 0 R /MediaBox [0 0 {page_width} {page_height}] "
        f"/Resources << /Font << /F1 {font_regular_id} 0 R /F2 {font_bold_id} 0 R >> >> "
        f"/Contents {content_id} 0 R >>"
    )
    pages_id = add_object(f"<< /Type /Pages /Kids [{page_id} 0 R] /Count 1 >>")
    catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

    pdf = BytesIO()
    pdf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj_id, payload in enumerate(objects, start=1):
        offsets.append(pdf.tell())
        pdf.write(f"{obj_id} 0 obj\n".encode("latin-1"))
        if isinstance(payload, bytes):
            pdf.write(payload)
        else:
            pdf.write(str(payload).encode("latin-1"))
        pdf.write(b"\nendobj\n")
    xref_offset = pdf.tell()
    pdf.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode(
            "latin-1"
        )
    )
    return pdf.getvalue()
