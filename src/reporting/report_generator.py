from __future__ import annotations

import io
import json
from importlib import import_module
from datetime import datetime, timezone
from pathlib import Path

try:
    colors = import_module("reportlab.lib.colors")
    TA_CENTER = import_module("reportlab.lib.enums").TA_CENTER
    A4 = import_module("reportlab.lib.pagesizes").A4
    styles = import_module("reportlab.lib.styles")
    getSampleStyleSheet = styles.getSampleStyleSheet
    ParagraphStyle = styles.ParagraphStyle
    mm = import_module("reportlab.lib.units").mm
    platypus = import_module("reportlab.platypus")
    Paragraph = platypus.Paragraph
    SimpleDocTemplate = platypus.SimpleDocTemplate
    Spacer = platypus.Spacer
    Table = platypus.Table
    TableStyle = platypus.TableStyle
except ModuleNotFoundError:  # pragma: no cover - optional export dependency
    colors = None
    TA_CENTER = None
    A4 = None
    getSampleStyleSheet = None
    ParagraphStyle = None
    mm = 1
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None
    Table = None
    TableStyle = None

import pandas as pd
from src.analysis.traffic_analyzer import analyze_traffic


def _require_reportlab():
    if (
        colors is None
        or TA_CENTER is None
        or A4 is None
        or getSampleStyleSheet is None
        or ParagraphStyle is None
        or mm is None
        or Paragraph is None
        or SimpleDocTemplate is None
        or Spacer is None
        or Table is None
        or TableStyle is None
    ):
        raise ModuleNotFoundError(
            "reportlab is required for PDF report generation. "
            "Install it with: pip install reportlab"
        )

def build_report(filename, records, alerts):
    stats=analyze_traffic(records)
    return {'capture_filename':Path(filename).name,'analysis_timestamp':datetime.now(timezone.utc).isoformat(),'packet_count':stats['packet_count'],'total_bytes':stats['total_bytes'],'protocol_distribution':stats['protocol_distribution'],'important_source_ips':stats['top_source_ips'],'important_destination_ips':stats['top_destination_ips'],'alerts':alerts,'detection_explanations':{a['detection_id']:a['description'] for a in alerts},'investigation_limitations':['Offline packet metadata analysis only; payloads are not stored.','Heuristics can produce false positives and absence of alerts does not prove a capture is safe.','Encrypted content and context outside the capture are not evaluated.']}

def export_csv(output_dir, filename, records, alerts):
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True); stem=Path(filename).stem
    pd.DataFrame([r.to_dict() if hasattr(r,'to_dict') else r for r in records]).to_csv(out/f'{stem}_packets.csv',index=False)
    pd.DataFrame(alerts).to_csv(out/f'{stem}_alerts.csv',index=False)
    pd.DataFrame([build_report(filename,records,alerts)]).to_csv(out/f'{stem}_traffic_statistics.csv',index=False)
    return [out/f'{stem}_packets.csv',out/f'{stem}_alerts.csv',out/f'{stem}_traffic_statistics.csv']

def export_json(output_dir, filename, records, alerts):
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True); target=out/f'{Path(filename).stem}_investigation.json'; target.write_text(json.dumps(build_report(filename,records,alerts),indent=2,default=str),encoding='utf-8'); return target

def build_pdf_bytes(filename, records, alerts):
    report = build_report(filename, list(records), alerts)

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"NetSentry Investigation Report - {filename}",
        author="NetSentry",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#12304A"),
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#145A7A"),
    )

    story = [
        Paragraph("NetSentry Investigation Report", title_style),
        Paragraph(
            f"Capture: {report['capture_filename']}",
            styles["BodyText"],
        ),
        Paragraph(
            f"Analysis time: {report['analysis_timestamp']}",
            styles["BodyText"],
        ),
        Spacer(1, 10),
        Paragraph("Analysis Summary", heading_style),
    ]

    summary_data = [
        ["Metric", "Value"],
        ["Packet count", str(report["packet_count"])],
        ["Total bytes", str(report["total_bytes"])],
        ["Alert count", str(len(report["alerts"]))],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[60 * mm, 100 * mm],
    )

    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#145A7A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Protocol Distribution", heading_style))

    protocol_data = [["Protocol", "Packets"]]

    for protocol, count in report["protocol_distribution"].items():
        protocol_data.append([str(protocol), str(count)])

    protocol_table = Table(
        protocol_data,
        colWidths=[60 * mm, 100 * mm],
    )

    protocol_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#145A7A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(protocol_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Detection Alerts", heading_style))

    if report["alerts"]:
        for alert in report["alerts"]:
            story.append(
                Paragraph(
                    f"<b>{alert.get('detection_id', 'Alert')} - "
                    f"{alert.get('detection_name', 'Detection')}</b>",
                    styles["BodyText"],
                )
            )

            story.append(
                Paragraph(
                    f"Severity: {alert.get('severity', 'Unknown')}<br/>"
                    f"Description: {alert.get('description', '')}<br/>"
                    f"Observed value: {alert.get('observed_value', '')}<br/>"
                    f"Evidence: {alert.get('supporting_evidence', '')}",
                    styles["BodyText"],
                )
            )

            story.append(Spacer(1, 6))
    else:
        story.append(
            Paragraph(
                "No alerts were generated. This does not prove that the capture is safe.",
                styles["BodyText"],
            )
        )

    story.append(Paragraph("Investigation Limitations", heading_style))

    for limitation in report["investigation_limitations"]:
        story.append(
            Paragraph(
                f"• {limitation}",
                styles["BodyText"],
            )
        )

    document.build(story)

    return buffer.getvalue()


def export_pdf(output_dir, filename, records, alerts):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    target = output_dir / f"{Path(filename).stem}_investigation.pdf"

    target.write_bytes(
        build_pdf_bytes(
            filename,
            records,
            alerts,
        )
    )

    return target
