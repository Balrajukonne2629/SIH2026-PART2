"""Tamper-Evident PDF Report Generator with QR Code & Embedded Audit Hash (PRD Addendum Section 4 Step 5).
Generates publication-quality audit certificates showing:
1. Device identification & audit metadata
2. Full compliance results table with visually distinct Pass/Fail/Unknown status badges
3. Remediation commands, static conflict warnings, and AI explanations for failed controls
4. Embedded cryptographic audit log entryHash and verification QR Code.
5. verify_report_hash() to independently validate PDF authenticity against SQLite audit_ledger.
"""
import json
import pathlib
import re
from typing import Optional, Tuple

import pypdf
from reportlab.graphics.barcode import qr
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BASE = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_PDF_FILE = BASE / "cisco_compliance_report.pdf"
DEFAULT_LOG_FILE = BASE / "data" / "audit_log.jsonl"

def generate_pdf_report(csm: dict,
                        evals: dict,
                        audit_entry: dict,
                        remediation_data: Optional[dict] = None,
                        output_path: pathlib.Path = DEFAULT_PDF_FILE) -> str:
    """Renders comprehensive PDF report with embedded hash and QR verification code."""
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title="Network Security Compliance Audit Report",
        author="NTRO Compliance Engine",
        subject=f"AuditEntryHash:{audit_entry.get('entryHash', '')}"
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155")
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a")
    )
    code_block_style = ParagraphStyle(
        "CodeBlock",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("NETWORK COMPLIANCE AUDIT CERTIFICATE", title_style))
    story.append(Paragraph("Automated Deterministic Verification & Tamper-Evident Audit Report | NTRO PS 26155", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # 2. Metadata Table
    host = csm.get("device", {}).get("hostname", "UNKNOWN")
    platform = csm.get("device", {}).get("platform", "IOS-XE")
    entry_id = audit_entry.get("entry_id", "N/A")
    entry_hash = audit_entry.get("entryHash", "N/A")
    config_hash = audit_entry.get("config_file_hash", "N/A")
    timestamp = audit_entry.get("timestamp", "N/A")

    meta_data = [
        [Paragraph("<b>Target Device:</b>", body_style), Paragraph(f"{host} ({platform})", body_style),
         Paragraph("<b>Audit Date:</b>", body_style), Paragraph(timestamp[:19] + " UTC", body_style)],
        [Paragraph("<b>Audit Entry ID:</b>", body_style), Paragraph(entry_id, body_style),
         Paragraph("<b>Config Hash:</b>", body_style), Paragraph(f"{config_hash[:16]}...", mono_style)],
        [Paragraph("<b>Chain Entry Hash:</b>", body_style), Paragraph(f"{entry_hash[:20]}...", mono_style),
         Paragraph("<b>Verification:</b>", body_style), Paragraph("<font color='#16a34a'><b>TAMPER-EVIDENT</b></font>", body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[95, 175, 95, 175])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # 3. Compliance Summary Metric Bar
    pass_cnt = sum(1 for v in evals.values() if v["status"] == "Pass")
    fail_cnt = sum(1 for v in evals.values() if v["status"] == "Fail")
    unk_cnt = sum(1 for v in evals.values() if v["status"] == "Unknown")
    total_cnt = len(evals)

    stat_data = [
        [Paragraph(f"<b>Total Controls:</b> {total_cnt}", body_style),
         Paragraph(f"<font color='#166534'><b>PASS:</b> {pass_cnt}</font>", body_style),
         Paragraph(f"<font color='#991b1b'><b>FAIL:</b> {fail_cnt}</font>", body_style),
         Paragraph(f"<font color='#854d0e'><b>UNKNOWN:</b> {unk_cnt}</font>", body_style)]
    ]
    stat_table = Table(stat_data, colWidths=[135, 135, 135, 135])
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 10))

    # 4. Detailed Evaluation Results Table
    story.append(Paragraph("1. Control Evaluation Results", h2_style))
    table_rows = [
        [Paragraph("<b>Rule ID</b>", body_style),
         Paragraph("<b>Control Focus</b>", body_style),
         Paragraph("<b>Status</b>", body_style),
         Paragraph("<b>Evidence Found</b>", body_style)]
    ]

    for rid in sorted(evals.keys()):
        item = evals[rid]
        st = item["status"]
        if st == "Pass":
            badge_html = "<font color='#166534'><b>[PASS] COMPLIANT</b></font>"
            row_bg = colors.HexColor("#f0fdf4")
        elif st == "Fail":
            badge_html = "<font color='#991b1b'><b>[FAIL] NON-COMPLIANT</b></font>"
            row_bg = colors.HexColor("#fef2f2")
        else:
            badge_html = "<font color='#854d0e'><b>[?] UNKNOWN</b></font>"
            row_bg = colors.HexColor("#fefce8")

        ev_text = ", ".join(item.get("evidence_found", [])) if item.get("evidence_found") else "None detected"
        table_rows.append([
            Paragraph(f"<b>{rid}</b>", mono_style),
            Paragraph(item["focus"], body_style),
            Paragraph(badge_html, body_style),
            Paragraph(ev_text, mono_style)
        ])

    rule_table = Table(table_rows, colWidths=[110, 180, 105, 145])
    ts_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]
    for idx, rid in enumerate(sorted(evals.keys()), 1):
        st = evals[rid]["status"]
        if st == "Pass":
            ts_cmds.append(("BACKGROUND", (2, idx), (2, idx), colors.HexColor("#dcfce7")))
        elif st == "Fail":
            ts_cmds.append(("BACKGROUND", (2, idx), (2, idx), colors.HexColor("#fee2e2")))
        else:
            ts_cmds.append(("BACKGROUND", (2, idx), (2, idx), colors.HexColor("#fef9c3")))

    rule_table.setStyle(TableStyle(ts_cmds))
    story.append(rule_table)
    story.append(Spacer(1, 10))

    # 5. Failed Control Remediation, Conflict Analysis & AI Explanation
    if remediation_data:
        story.append(Paragraph("2. Remediation & Conflict Analysis (Failed Control)", h2_style))
        rem_rule = remediation_data.get("rule_id", "CISCO-NTP-001")
        rem_cmd = remediation_data.get("remediation_cmd", "")
        why = remediation_data.get("why_it_failed", "")
        what = remediation_data.get("what_remediation_does", "")
        conflicts = remediation_data.get("conflicts", [])

        # AI explanation callout
        ai_box_data = [
            [Paragraph("<b>AI Security Analysis (Root Cause):</b>", body_style)],
            [Paragraph(why, body_style)],
            [Paragraph("<b>Remediation Action & Safety:</b>", body_style)],
            [Paragraph(what, body_style)]
        ]
        ai_box = Table(ai_box_data, colWidths=[540])
        ai_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(ai_box)
        story.append(Spacer(1, 6))

        # Remediation Commands Box (Display-only)
        story.append(Paragraph("<b>Recommended Remediation Commands (Manual Review Required - Never Auto-Executed):</b>", body_style))
        cmd_formatted = "<br/>".join(rem_cmd.splitlines())
        story.append(Paragraph(cmd_formatted, code_block_style))

        # Static Conflict Warnings
        if conflicts:
            conf_rows = [[Paragraph("<b>Static Conflict Analysis: Warnings Detected</b>", body_style)]]
            for c in conflicts:
                conf_rows.append([
                    Paragraph(f"<font color='#b91c1c'><b>[{c['severity']}] {c['title']}:</b></font> {c['description']}<br/><i>Mitigation: {c['mitigation']}</i>", body_style)
                ])
            conf_table = Table(conf_rows, colWidths=[540])
            conf_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff1f2")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fca5a5")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(conf_table)
            story.append(Spacer(1, 8))

    # 6. Cryptographic Chain & QR Code Verification Section
    story.append(Paragraph("3. Cryptographic Authenticity & Verification", h2_style))
    qr_code = qr.QrCodeWidget(f"urn:audit:{entry_hash}")
    qr_code.barWidth = 70
    qr_code.barHeight = 70
    qr_drawing = Drawing(75, 75)
    qr_drawing.add(qr_code)

    crypto_text = (
        f"<b>Audit Log SHA256 Hash:</b><br/>"
        f"<font name='Courier' size='7'>{entry_hash}</font><br/><br/>"
        f"<b>Previous Chain Hash:</b><br/>"
        f"<font name='Courier' size='7'>{audit_entry.get('prevEntryHash', '0'*64)}</font><br/><br/>"
        f"Scan the QR code or run <code>python -c \"import report_generator; report_generator.verify_report_hash('{output_path.name}')\"</code> "
        f"to verify this report against the append-only audit ledger."
    )

    cert_data = [
        [Paragraph(crypto_text, body_style), qr_drawing]
    ]
    cert_table = Table(cert_data, colWidths=[460, 80])
    cert_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#0284c7")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cert_table)

    doc.build(story)
    return str(output_path)

def verify_report_hash(pdf_path: pathlib.Path = DEFAULT_PDF_FILE,
                       logfile: pathlib.Path = DEFAULT_LOG_FILE) -> Tuple[bool, str]:
    """Reads embedded hash from PDF document and validates against audit_log.jsonl."""
    if not pdf_path.exists():
        return False, f"PDF report '{pdf_path}' not found."

    reader = pypdf.PdfReader(str(pdf_path))
    meta_subject = reader.metadata.get("/Subject", "") if reader.metadata else ""

    embedded_hash = None
    if meta_subject and "AuditEntryHash:" in meta_subject:
        embedded_hash = meta_subject.split("AuditEntryHash:")[-1].strip()

    if not embedded_hash:
        full_text = "".join(page.extract_text() or "" for page in reader.pages)
        match = re.search(r"Audit Log SHA256 Hash:\s*([a-fA-F0-9]{64})", full_text)
        if match:
            embedded_hash = match.group(1)

    if not embedded_hash:
        return False, "Failed to extract audit entryHash from PDF document."

    import src.database as database
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM audit_ledger WHERE entryHash = ?', (embedded_hash,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, f"Extracted hash '{embedded_hash[:16]}...' does NOT exist in audit log."

    matching_entry = {
        "entry_id": row["entry_id"],
        "timestamp": row["timestamp"],
        "device_hostname": row["device_hostname"],
        "config_file_hash": row["config_file_hash"],
        "audit_results": json.loads(row["audit_results"]) if row["audit_results"] else {},
        "remediation_summary": json.loads(row["remediation_summary"]) if row["remediation_summary"] else None,
        "prevEntryHash": row["prevEntryHash"],
        "entryHash": row["entryHash"]
    }

    # Validate integrity of the matching log entry
    from src.audit_log import compute_entry_hash
    recomputed = compute_entry_hash(matching_entry)
    if recomputed != embedded_hash:
        return False, f"Tamper detected in audit log: entry {matching_entry.get('entry_id')} hash mismatch."

    return True, f"Verified: Embedded PDF hash '{embedded_hash[:16]}...' cryptographically matches audit log entry '{matching_entry['entry_id']}'."
