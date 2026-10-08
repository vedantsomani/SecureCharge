"""Render measured manuscript to Markdown and an inspected, reproducible PDF.

Install requirements-paper.txt in the project environment. Run after generating
artifacts/final and artifacts/validation.xml. No research values are invented.
"""

from __future__ import annotations
import argparse
import html
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent


def measured_values(results: dict, validation: Path, results_dir: Path) -> dict[str, str]:
    suite = ET.parse(validation).getroot()
    if suite.tag == "testsuites":
        suite = suite.find("testsuite")
    tests, failures, errors = [int(suite.attrib.get(k, "0")) for k in ("tests", "failures", "errors")]
    if failures or errors:
        raise ValueError("cannot build a paper claiming successful validation from failing tests")
    if int(suite.attrib.get("skipped", "0")):
        raise ValueError("report skipped tests explicitly before building this all-tests-pass manuscript")
    total = results["pipeline_summary"]["total_ns"]
    env, c = results["environment"], results["collision"]
    import csv

    pipeline = results_dir / "pipeline_samples.csv"
    with pipeline.open(newline="", encoding="utf-8") as stream:
        first = next(csv.DictReader(stream))
    values = {
        "tests": tests,
        "failures": failures,
        "errors": errors,
        "samples": results["methods"]["samples"],
        "median_ms": f"{total['median_ns'] / 1e6:.3f}",
        "p95_ms": f"{total['p95_ns'] / 1e6:.3f}",
        "p99_ms": f"{total['p99_ns'] / 1e6:.3f}",
        "ci_low_ms": f"{total['median_ci95_ns'][0] / 1e6:.3f}",
        "ci_high_ms": f"{total['median_ci95_ns'][1] / 1e6:.3f}",
        "overhead": results["message_overhead_bytes"],
        "allocation": results["python_allocation_peak_bytes"],
        "python": env["python"],
        "platform": env["platform"],
        "machine": env["machine"],
        "openssl": env["openssl"],
        "board": env["board_model"],
        "hardware": env["hardware_class"],
        "measured_at": env["measured_at_utc"],
        "storage": results["methods"]["pipeline_storage"],
        "collision_md5": c["pinned_md5"],
        "counter_a": c["honest_meter_stop"],
        "counter_b": c["substituted_meter_stop"],
        "collision_honest_bill": f"{c['honest_bill_paise'] / 100:.2f}",
        "collision_forged_bill": f"{c['substituted_bill_paise'] / 100:.2f}",
        "ocpp_bytes": first["ocpp_bytes"],
        "envelope_bytes": first["envelope_bytes"],
    }
    return {k: str(v) for k, v in values.items()}


def _inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", text)
    return text


def create_pdf(markdown: str, output: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font = Path("C:/Windows/Fonts/times.ttf")
    if font.exists():
        pdfmetrics.registerFont(TTFont("PaperText", str(font)))
        pdfmetrics.registerFont(TTFont("PaperBold", "C:/Windows/Fonts/timesbd.ttf"))
    else:
        font = Path("/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf")
        if font.exists():
            pdfmetrics.registerFont(TTFont("PaperText", str(font)))
            pdfmetrics.registerFont(TTFont("PaperBold", "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf"))
    regular = "PaperText" if "PaperText" in pdfmetrics.getRegisteredFontNames() else "Times-Roman"
    bold = "PaperBold" if "PaperBold" in pdfmetrics.getRegisteredFontNames() else "Times-Bold"
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle("Paper", fontName=regular, fontSize=10.8, leading=14.8, alignment=TA_JUSTIFY, spaceAfter=8)
    )
    styles.add(ParagraphStyle("PaperTitle", fontName=bold, fontSize=19, leading=22, alignment=TA_CENTER, spaceAfter=12))
    styles.add(
        ParagraphStyle(
            "Section", fontName=bold, fontSize=13, leading=17, spaceBefore=14, spaceAfter=7, keepWithNext=True
        )
    )
    styles.add(
        ParagraphStyle(
            "Subsection", fontName=bold, fontSize=11.5, leading=15, spaceBefore=8, spaceAfter=6, keepWithNext=True
        )
    )
    styles.add(ParagraphStyle("Caption", fontName=regular, fontSize=9, leading=12, spaceAfter=9))
    styles.add(ParagraphStyle("Cell", fontName=regular, fontSize=9, leading=11.5))
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output),
        pagesize=(8.27 * inch, 11.69 * inch),
        rightMargin=0.8 * inch,
        leftMargin=0.8 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Evaluating an Authenticated SHA-3 Retrofit for Legacy EV Charging",
        author="SecureCharge project team",
    )
    story = []
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line:
            index += 1
            continue
        if line.startswith("# "):
            story.append(Paragraph(_inline(line[2:]), styles["PaperTitle"]))
            index += 1
        elif line.startswith("## "):
            story.append(Paragraph(_inline(line[3:]), styles["Section"]))
            index += 1
        elif line.startswith("### "):
            story.append(Paragraph(_inline(line[4:]), styles["Subsection"]))
            index += 1
        elif line.startswith("!["):
            name = re.search(r"\]\((.+)\)", line).group(1)
            path = (ROOT / "docs" / name).resolve()
            width, height = ImageReader(str(path)).getSize()
            image = Image(str(path), width=doc.width, height=doc.width * height / width)
            story.extend([Spacer(1, 6), image, Spacer(1, 6)])
            index += 1
        elif line.startswith("|"):
            rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
                if not all(re.fullmatch(r"[-: ]+", cell) for cell in cells):
                    rows.append([Paragraph(_inline(cell), styles["Cell"]) for cell in cells])
                index += 1
            table = Table(rows, colWidths=[doc.width * 0.46, doc.width * 0.54], repeatRows=1, hAlign="LEFT")
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e4edf5")),
                        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c5cf")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 7),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.extend([table, Spacer(1, 10)])
        else:
            paragraph = []
            while index < len(lines) and lines[index].strip() and not lines[index].startswith(("#", "![", "|")):
                paragraph.append(lines[index].strip())
                index += 1
            text = " ".join(paragraph)
            style = styles["Caption"] if text.startswith("Figure ") else styles["Paper"]
            story.append(Paragraph(_inline(text), style))

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(
            doc.leftMargin, 0.35 * inch, "SecureCharge | Research prototype / paper draft | revised 6 October 2026"
        )
        canvas.drawRightString(8.27 * inch - doc.rightMargin, 0.35 * inch, str(doc.page))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=ROOT / "artifacts/final/results.json")
    parser.add_argument("--validation", type=Path, default=ROOT / "artifacts/validation.xml")
    parser.add_argument("--pilot", type=Path, default=ROOT / "artifacts/pilot-final/pilot-results.json")
    args = parser.parse_args()
    values = measured_values(json.loads(args.results.read_text(encoding="utf-8")), args.validation, args.results.parent)
    pilot = json.loads(args.pilot.read_text(encoding="utf-8"))
    checks = [
        "outage_retains_pending_without_success_ack",
        "restart_recovered_authenticated_receipt",
        "retry_uses_same_cached_response",
        "tampered_custody_record_rejected_at_startup",
        "external_anchor_verified",
    ]
    if not all(pilot.get(key) is True for key in checks) or pilot.get("ledger_rows_after_recovery") != 1:
        raise ValueError("pilot invariants are not supported by the recorded experiment")
    values.update(
        {
            "pilot_events": str(pilot["journal_events"]),
            "pilot_bills": str(pilot["ledger_rows_after_recovery"]),
            "pilot_host": pilot["environment"]["platform"],
            "pilot_date": pilot["environment"]["measured_at_utc"],
        }
    )
    text = (ROOT / "docs/PAPER_TEMPLATE.md").read_text(encoding="utf-8")
    figure_dir = os.path.relpath(args.results.parent.resolve(), ROOT / "docs").replace("\\", "/")
    text = text.replace("../artifacts/final/", figure_dir + "/")
    for name, value in values.items():
        text = text.replace("{{" + name + "}}", value)
    if re.search(r"\{\{.+?\}\}", text):
        raise ValueError("unresolved manuscript value")
    (ROOT / "docs/PAPER.md").write_text(text, encoding="utf-8")
    output = ROOT / "output/pdf/SecureCharge_Research_Paper.pdf"
    create_pdf(text, output)
    import pymupdf

    rendered = ROOT / "tmp/paper"
    rendered.mkdir(parents=True, exist_ok=True)
    pdf = pymupdf.open(output)
    for i, page in enumerate(pdf):
        page.get_pixmap(matrix=pymupdf.Matrix(1.2, 1.2)).save(rendered / f"page-{i + 1:02d}.png")
    print(f"Created {output} ({len(pdf)} pages) and docs/PAPER.md; rendered all pages for inspection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
