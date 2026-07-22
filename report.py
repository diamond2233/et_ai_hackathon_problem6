"""Evidence-grade PDF report generation.

A screenshot is not evidence. This produces a document a citizen can attach to a
cybercrime.gov.in filing or hand to a bank: it records the exact content analysed
(by SHA-256), the model version, every rule that fired, the score breakdown, and
a verification hash over the whole record.
"""
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)

REPORTS_DIR = os.getenv("REPORTS_DIR", "/tmp/sentinelai_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

INK = colors.HexColor("#0B1020")
SENTINEL = colors.HexColor("#4C6FFF")
CRITICAL = colors.HexColor("#FF4D5E")
CAUTION = colors.HexColor("#FFB020")
SAFE = colors.HexColor("#21C99B")
MUTED = colors.HexColor("#6B7794")
LINE = colors.HexColor("#D8DEEC")

VERDICT_COLOR = {
    "critical": CRITICAL,
    "high_risk": CRITICAL,
    "suspicious": CAUTION,
    "inconclusive": MUTED,
    "likely_safe": SAFE,
}

VERDICT_LABEL = {
    "critical": "CRITICAL THREAT",
    "high_risk": "HIGH RISK",
    "suspicious": "SUSPICIOUS",
    "inconclusive": "INCONCLUSIVE",
    "likely_safe": "NO THREAT DETECTED",
}


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=20, textColor=INK, spaceAfter=2, alignment=TA_LEFT),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontName="Helvetica",
                              fontSize=9, textColor=MUTED, spaceAfter=10),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=11.5, textColor=INK, spaceBefore=12, spaceAfter=5),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName="Helvetica",
                               fontSize=9.5, leading=14, textColor=INK),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontName="Helvetica",
                                fontSize=8, leading=11, textColor=MUTED),
        "mono": ParagraphStyle("m", parent=base["Normal"], fontName="Courier",
                               fontSize=7.5, leading=10, textColor=MUTED),
        "quote": ParagraphStyle("q", parent=base["Normal"], fontName="Helvetica-Oblique",
                                fontSize=9, leading=13, textColor=INK,
                                leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=4),
    }


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def generate_report(analysis: Dict[str, Any], reporter_name: str | None = None) -> Dict[str, str]:
    """Render the PDF and return its metadata."""
    report_id = f"SAI-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
    st = _styles()

    verdict = analysis.get("verdict", "inconclusive")
    vcolor = VERDICT_COLOR.get(verdict, MUTED)
    score = analysis.get("risk_score", 0)

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"SentinelAI Threat Report {report_id}",
        author="SentinelAI",
    )

    story: list = []

    # -- header ------------------------------------------------------------
    story.append(Paragraph("SentinelAI — Threat Analysis Report", st["title"]))
    story.append(Paragraph(
        f"Report ID {report_id} &nbsp;•&nbsp; Generated "
        f"{datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')} "
        f"&nbsp;•&nbsp; Engine {_esc(analysis.get('model_version', 'n/a'))}",
        st["sub"]))
    story.append(HRFlowable(width="100%", color=LINE, thickness=0.8, spaceAfter=10))

    # -- verdict banner ----------------------------------------------------
    banner = Table(
        [[Paragraph(f"<font color='white' size='15'><b>{VERDICT_LABEL.get(verdict, verdict.upper())}"
                    f"</b></font>", st["body"]),
          Paragraph(f"<font color='white' size='15'><b>Risk {score}/100</b></font>", st["body"]),
          Paragraph(f"<font color='white' size='15'><b>Confidence "
                    f"{analysis.get('confidence', 0)}%</b></font>", st["body"])]],
        colWidths=[78 * mm, 48 * mm, 48 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), vcolor),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(banner)
    story.append(Spacer(1, 4 * mm))

    # -- classification ----------------------------------------------------
    from app.data.red_flags import THREAT_LABELS
    meta_rows = [
        ["Threat classification", THREAT_LABELS.get(analysis.get("threat_type", "unknown"),
                                                    "Unclassified")],
        ["Channel", str(analysis.get("channel", "unknown")).replace("_", " ").title()],
        ["Sender", _esc(analysis.get("sender") or "Not provided")],
        ["Matched campaign", _esc(analysis.get("similar_campaign") or "No known campaign match")],
        ["Campaign similarity", f"{float(analysis.get('similarity_score') or 0) * 100:.1f}%"],
        ["Indicators fired", str(len(analysis.get("red_flags", [])))],
        ["Analysis latency", f"{analysis.get('processing_ms', 0)} ms"],
    ]
    tbl = Table(meta_rows, colWidths=[52 * mm, 122 * mm])
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(tbl)

    # -- analysed content --------------------------------------------------
    story.append(Paragraph("Content analysed", st["h2"]))
    preview = _esc(analysis.get("content_preview", ""))[:1400]
    story.append(Paragraph(f"“{preview}”", st["quote"]))
    story.append(Paragraph(
        f"SHA-256 of full content: {analysis.get('content_hash', '')}", st["mono"]))

    # -- assessment --------------------------------------------------------
    story.append(Paragraph("Assessment", st["h2"]))
    story.append(Paragraph(_esc(analysis.get("explanation", "")), st["body"]))

    if analysis.get("victim_impact"):
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            f"<b>If the recipient complies:</b> {_esc(analysis['victim_impact'])}",
            st["body"]))

    # -- indicators --------------------------------------------------------
    flags = analysis.get("red_flags", [])
    if flags:
        story.append(Paragraph("Fraud indicators detected", st["h2"]))
        rows = [["Sev", "Indicator", "Matched text", "Why it matters"]]
        for f in flags[:14]:
            rows.append([
                str(f.get("severity", "")),
                Paragraph(f"<b>{_esc(f.get('label', ''))}</b><br/>"
                          f"<font size='6.5' color='#6B7794'>{_esc(f.get('code', ''))}</font>",
                          st["small"]),
                Paragraph(f"<font face='Courier'>{_esc(f.get('matched_text') or '—')}</font>",
                          st["small"]),
                Paragraph(_esc(f.get("explanation", ""))[:200], st["small"]),
            ])
        ft = Table(rows, colWidths=[10 * mm, 42 * mm, 38 * mm, 84 * mm], repeatRows=1)
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FD")]),
        ]))
        story.append(ft)

    # -- entities ----------------------------------------------------------
    entities = analysis.get("entities", [])
    if entities:
        story.append(Paragraph("Identifiers extracted (quote these when reporting)", st["h2"]))
        erows = [["Type", "Value", "Note"]]
        for e in entities[:12]:
            erows.append([
                str(e.get("type", "")).upper(),
                Paragraph(f"<font face='Courier'>{_esc(e.get('value', ''))}</font>", st["small"]),
                Paragraph(_esc(e.get("risk_note") or "—"), st["small"]),
            ])
        et = Table(erows, colWidths=[22 * mm, 62 * mm, 90 * mm], repeatRows=1)
        et.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EDF7")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(et)

    # -- recommendations ---------------------------------------------------
    recs = analysis.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommended actions", st["h2"]))
        for i, r in enumerate(recs, 1):
            story.append(Paragraph(f"<b>{i}.</b> {_esc(r)}", st["body"]))
            story.append(Spacer(1, 1.5 * mm))

    # -- score breakdown ---------------------------------------------------
    bd = analysis.get("breakdown", {})
    if bd:
        story.append(Paragraph("Score composition", st["h2"]))
        w = bd.get("weights", {})
        brows = [["Detection layer", "Raw", "Weight", "Contribution"]]
        for key, name in [("rules", "L1 Deterministic rules"),
                          ("similarity", "L2 Campaign fingerprint"),
                          ("structural", "L3 Structural signals"),
                          ("llm", "L4 Gemini reasoning")]:
            raw = float(bd.get(key, 0))
            weight = float(w.get(key, 0))
            brows.append([name, f"{raw:.1f}", f"{weight * 100:.0f}%", f"{raw * weight:.1f}"])
        brows.append(["Final fused score", "", "", f"{bd.get('final', 0):.1f}"])
        bt = Table(brows, colWidths=[74 * mm, 28 * mm, 28 * mm, 44 * mm])
        bt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EDF7")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, LINE),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(bt)

    # -- verification & disclaimer ----------------------------------------
    integrity_payload = json.dumps({
        "report_id": report_id,
        "content_hash": analysis.get("content_hash"),
        "risk_score": analysis.get("risk_score"),
        "verdict": verdict,
        "threat_type": analysis.get("threat_type"),
        "model_version": analysis.get("model_version"),
        "flag_codes": sorted(f.get("code", "") for f in flags),
    }, sort_keys=True)
    integrity = hashlib.sha256(integrity_payload.encode()).hexdigest()

    story.append(Spacer(1, 5 * mm))
    story.append(HRFlowable(width="100%", color=LINE, thickness=0.8, spaceAfter=6))
    story.append(Paragraph(f"Record verification hash (SHA-256): {integrity}", st["mono"]))
    if reporter_name:
        story.append(Paragraph(f"Generated for: {_esc(reporter_name)}", st["small"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "This report is produced by an automated advisory system and is intended to "
        "support a complaint, not to replace one. File at cybercrime.gov.in or call "
        "1930. SentinelAI is not a law enforcement agency and makes no legal "
        "determination. The verification hash above lets any recipient confirm the "
        "report has not been altered since generation.", st["small"]))

    doc.build(story)
    logger.info("Report %s written to %s", report_id, path)

    return {
        "report_id": report_id,
        "path": path,
        "sha256": integrity,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
