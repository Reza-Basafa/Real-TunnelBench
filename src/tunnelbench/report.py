"""Rendering of the PDF report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .geo import class_label
from .models import BenchReport
from .probe import ERROR_CATEGORIES
from .scoring import DEFAULT_WEIGHTS

INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
ACCENT = colors.HexColor("#0f766e")
ACCENT_SOFT = colors.HexColor("#ccfbf1")
DANGER = colors.HexColor("#b91c1c")
WARN = colors.HexColor("#b45309")
PANEL = colors.HexColor("#f8fafc")
BORDER = colors.HexColor("#d1d5db")
HEADER_BG = colors.HexColor("#1f2937")

PAGE_WIDTH, PAGE_HEIGHT = A4


def _escape(value: object) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _truncate(value: str, length: int) -> str:
    text = str(value)
    if len(text) <= length:
        return text
    return text[: max(0, length - 1)] + "…"


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "rtbTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=30,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "rtbSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=12,
            leading=16,
            textColor=MUTED,
        ),
        "h1": ParagraphStyle(
            "rtbH1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=INK,
            spaceBefore=6,
            spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "rtbH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=ACCENT,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "rtbBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=INK,
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "rtbSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.6,
            leading=10,
            textColor=MUTED,
        ),
        "cell": ParagraphStyle(
            "rtbCell",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.4,
            leading=9.6,
            textColor=INK,
        ),
        "cell_bold": ParagraphStyle(
            "rtbCellBold",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.4,
            leading=9.6,
            textColor=INK,
        ),
        "cell_right": ParagraphStyle(
            "rtbCellRight",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.4,
            leading=9.6,
            textColor=INK,
            alignment=2,
        ),
        "cell_header": ParagraphStyle(
            "rtbCellHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.6,
            leading=9.8,
            textColor=colors.white,
        ),
        "kpi_value": ParagraphStyle(
            "rtbKpiValue",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=23,
            textColor=INK,
            alignment=TA_CENTER,
        ),
        "kpi_label": ParagraphStyle(
            "rtbKpiLabel",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.6,
            leading=10,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
    }


_STYLES_CACHE: dict[str, ParagraphStyle] = {}


def _get_styles() -> dict[str, ParagraphStyle]:
    global _STYLES_CACHE
    if not _STYLES_CACHE:
        _STYLES_CACHE = _styles()
    return _STYLES_CACHE


def _table(data, widths, header=True, align_right=()) -> Table:
    styles = _get_styles()
    converted = []
    for row_index, row in enumerate(data):
        converted_row = []
        for column_index, cell in enumerate(row):
            if isinstance(cell, Flowable):
                converted_row.append(cell)
                continue
            if header and row_index == 0:
                style = styles["cell_header"]
            elif column_index in align_right:
                style = styles["cell_right"]
            else:
                style = styles["cell"]
            converted_row.append(Paragraph(_escape(cell), style))
        converted.append(converted_row)
    data = converted
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
    ]
    if header:
        style.extend(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 7.6),
            ]
        )
    for column in align_right:
        style.append(("ALIGN", (column, 1), (column, -1), "RIGHT"))
    table.setStyle(TableStyle(style))
    return table


def _kpi_row(items: list[tuple[str, str]], styles) -> Table:
    cells = []
    for value, label in items:
        cells.append(
            [
                Paragraph(_escape(value), styles["kpi_value"]),
                Paragraph(_escape(label), styles["kpi_label"]),
            ]
        )
    table = Table([cells], colWidths=[(PAGE_WIDTH - 36 * mm) / len(items)] * len(items))
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return table


def _speed_chart(results, styles, limit: int = 18) -> Drawing:
    entries = [result for result in results if result.download_mbps > 0][:limit]
    if not entries:
        drawing = Drawing(PAGE_WIDTH - 36 * mm, 30 * mm)
        drawing.add(String(0, 12, "No throughput measurement available", fontSize=9))
        return drawing

    names = [_truncate(result.config.display_name, 28) for result in entries]
    values = [round(result.download_mbps, 2) for result in entries]

    height = max(70 * mm, (len(entries) + 1) * 5.2 * mm)
    drawing = Drawing(PAGE_WIDTH - 36 * mm, height)

    chart = HorizontalBarChart()
    chart.x = 30 * mm
    chart.y = 6 * mm
    chart.width = PAGE_WIDTH - 36 * mm - 42 * mm
    chart.height = height - 14 * mm
    chart.data = [values]
    chart.categoryAxis.categoryNames = names
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 6.4
    chart.categoryAxis.labels.dx = 2
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values) * 1.15
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 6.4
    chart.valueAxis.valueStep = max(1, int(max(values) / 4) or 1)
    chart.bars[0].fillColor = ACCENT
    chart.bars[0].strokeColor = None
    chart.barWidth = 5
    chart.groupSpacing = 3
    drawing.add(chart)
    drawing.add(
        String(
            30 * mm,
            height - 9 * mm,
            "Download throughput (Mbps) measured through the tunnel",
            fontSize=7.4,
            fillColor=MUTED,
        )
    )
    return drawing


def build_pdf(report: BenchReport, path: Path) -> Path:
    """Render the full PDF report and return the written path."""
    styles = _styles()
    path.parent.mkdir(parents=True, exist_ok=True)

    doc = BaseDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="Real-TunnelBench report",
        author="Real-TunnelBench",
        subject="Live proxy configuration benchmark",
    )

    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="main",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )

    def decorate(canvas, document) -> None:
        canvas.saveState()
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, PAGE_HEIGHT - 13 * mm, PAGE_WIDTH - doc.rightMargin, PAGE_HEIGHT - 13 * mm)
        canvas.setFont("Helvetica", 7.2)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, PAGE_HEIGHT - 11 * mm, "Real-TunnelBench - live configuration benchmark")
        canvas.drawRightString(
            PAGE_WIDTH - doc.rightMargin,
            9 * mm,
            f"page {document.page}",
        )
        canvas.restoreState()

    def cover(canvas, document) -> None:
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0f172a"))
        canvas.rect(0, PAGE_HEIGHT - 62 * mm, PAGE_WIDTH, 62 * mm, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_HEIGHT - 64 * mm, PAGE_WIDTH, 2 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 26)
        canvas.drawString(doc.leftMargin, PAGE_HEIGHT - 34 * mm, "Real-TunnelBench")
        canvas.setFont("Helvetica", 12)
        canvas.setFillColor(colors.HexColor("#cbd5e1"))
        canvas.drawString(
            doc.leftMargin,
            PAGE_HEIGHT - 43 * mm,
            "Live proxy benchmark with Iran-focused analysis",
        )
        canvas.setFont("Helvetica", 8.6)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(
            doc.leftMargin,
            PAGE_HEIGHT - 53 * mm,
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        )
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, 14 * mm, PAGE_WIDTH - doc.rightMargin, 14 * mm)
        canvas.setFont("Helvetica", 7.2)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, 10 * mm, "Real-TunnelBench")
        canvas.drawRightString(PAGE_WIDTH - doc.rightMargin, 10 * mm, f"page {document.page}")
        canvas.restoreState()

    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame], onPage=cover),
            PageTemplate(id="content", frames=[frame], onPage=decorate),
        ]
    )

    story: list = []
    settings = report.settings

    # ------------------------------------------------------------------ cover
    story.append(Spacer(1, 46 * mm))
    story.append(
        Paragraph(
            "Every configuration of the source list was parsed, launched inside a real "
            "proxy core and measured. The report ranks the working ones, explains why "
            "they are expected to behave well for Iranian users and lists the reasons "
            "every other configuration failed.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6 * mm))
    story.append(
        _kpi_row(
            [
                (str(report.tested), "TESTED"),
                (str(report.alive), "ALIVE"),
                (str(len(report.selected)), "SELECTED"),
                (f"{report.best_mbps:.1f}", "BEST Mbps"),
                (f"{report.median_latency_ms:.0f}", "MEDIAN ms"),
            ],
            styles,
        )
    )
    story.append(Spacer(1, 8 * mm))
    cover_data = [
        ["Source", _escape(settings.source_url)],
        ["Format", "base64 subscription" if report.source_encoded else "plain text"],
        ["Source size", f"{report.source_bytes:,} bytes / {report.source_lines} lines"],
        ["Parsed / duplicates", f"{report.parsed} unique / {report.duplicates} duplicates"],
        ["Rejected", str(report.rejected)],
        ["Runner", _escape(report.runner)],
        ["Proxy core", f"sing-box {report.core_version}"],
        ["Iran vantage points", _escape(report.iran_probe_message or "not used")],
        ["Duration", f"{report.duration_s:.1f} s"],
    ]
    story.append(
        _table(
            [["Field", "Value"]]
            + [[row[0], Paragraph(_escape(row[1]), styles["cell"])] for row in cover_data],
            [42 * mm, PAGE_WIDTH - 36 * mm - 42 * mm],
        )
    )
    story.append(Spacer(1, 6 * mm))

    if report.selected:
        story.append(Paragraph("Best configurations of this run", styles["h2"]))
        preview = [["#", "Name", "Protocol", "Endpoint", "Latency", "Speed", "Iran score"]]
        for rank, result in enumerate(report.selected[:5], start=1):
            preview.append(
                [
                    str(rank),
                    Paragraph(_escape(_truncate(result.config.display_name, 36)), styles["cell"]),
                    result.config.scheme,
                    _escape(result.config.endpoint),
                    f"{result.latency_ms:.0f} ms",
                    f"{result.download_mbps:.1f} Mbps",
                    f"{result.iran_score:.0f}",
                ]
            )
        story.append(
            _table(
                preview,
                [7 * mm, 52 * mm, 18 * mm, 42 * mm, 20 * mm, 22 * mm, 18 * mm],
                align_right=(4, 5, 6),
            )
        )
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # ------------------------------------------------------------- methodology
    story.append(Paragraph("1. What was done", styles["h1"]))
    story.append(
        Paragraph(
            "The pipeline has six stages. Each stage is described in the table below; "
            "the raw numbers of every stage are reported in section 2.",
            styles["body"],
        )
    )
    stages = [
        ["Stage", "Description"],
        ["1. Fetch", "The source URL is downloaded (plain text or base64 subscription) with a size limit and SSRF protection."],
        ["2. Parse", "Every line is parsed into a typed configuration (vless, vmess, trojan, ss, hysteria2, tuic, socks, http) and deduplicated."],
        ["3. Validate", "Each configuration is rendered into a sing-box outbound and checked by the core itself; invalid entries are dropped."],
        ["4. Measure", "A sing-box instance exposes one SOCKS inbound per configuration. Latency, throughput and the exit address are measured through the tunnel."],
        ["5. Enrich", "Entry addresses are geolocated and classified (Iranian host, Iranian CDN, Cloudflare, global CDN, datacenter)."],
        ["6. Score", "Performance, latency, stability and Iran affinity are combined into the final ranking."],
    ]
    story.append(
        _table(
            [stages[0]] + [[row[0], Paragraph(_escape(row[1]), styles["cell"])] for row in stages[1:]],
            [30 * mm, PAGE_WIDTH - 36 * mm - 30 * mm],
        )
    )
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("2. Scoring model", styles["h1"]))
    weights = dict(DEFAULT_WEIGHTS)
    if settings.weights:
        weights.update(settings.weights)
    weight_rows = [["Axis", "Weight", "Meaning"]]
    meanings = {
        "speed": "sustained download throughput (logarithmic, 50 Mbps = full score)",
        "latency": "round trip time of a small request through the tunnel",
        "iran": "Iran affinity: entry location, TLS/REALITY shape and Iranian vantage point results",
        "stability": "jitter of the latency samples",
    }
    for key, value in weights.items():
        weight_rows.append(
            [key, f"{value:.0%}", Paragraph(_escape(meanings.get(key, "")), styles["cell"])]
        )
    story.append(_table(weight_rows, [26 * mm, 18 * mm, PAGE_WIDTH - 36 * mm - 44 * mm]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("3. Results overview", styles["h1"]))
    overview = [
        ["Metric", "Value"],
        ["Source lines", str(report.source_lines)],
        ["Configurations parsed", str(report.parsed)],
        ["Duplicates removed", str(report.duplicates)],
        ["Rejected by the parser / core", str(report.rejected)],
        ["Configurations tested", str(report.tested)],
        ["Alive configurations", str(report.alive)],
        ["Passed the quality thresholds", str(len(report.selected))],
        ["Best download speed", f"{report.best_mbps:.2f} Mbps"],
        ["Median latency of alive configurations", f"{report.median_latency_ms:.0f} ms"],
    ]
    story.append(_table(overview, [80 * mm, PAGE_WIDTH - 36 * mm - 80 * mm]))
    story.append(Spacer(1, 5 * mm))

    if report.protocol_counts:
        story.append(Paragraph("Protocol distribution", styles["h2"]))
        rows = [["Protocol", "Count", "Share"]]
        total = sum(report.protocol_counts.values()) or 1
        for name, count in report.protocol_counts.items():
            rows.append([name, str(count), f"{count / total:.1%}"])
        story.append(_table(rows, [50 * mm, 25 * mm, 25 * mm], align_right=(1, 2)))
        story.append(Spacer(1, 4 * mm))

    if report.transport_counts:
        story.append(Paragraph("Transport distribution", styles["h2"]))
        rows = [["Transport", "Count", "Share"]]
        total = sum(report.transport_counts.values()) or 1
        for name, count in report.transport_counts.items():
            rows.append([name, str(count), f"{count / total:.1%}"])
        story.append(_table(rows, [50 * mm, 25 * mm, 25 * mm], align_right=(1, 2)))

    story.append(Spacer(1, 5 * mm))

    # ----------------------------------------------------------------- ranking
    story.append(Paragraph("4. Ranking", styles["h1"]))
    if report.selected:
        story.append(
            Paragraph(
                f"The {len(report.selected)} configuration(s) below are the ones that are alive "
                f"and match the quality thresholds "
                f"({settings.min_download_mbps:.2f} Mbps minimum speed, "
                f"{settings.max_latency_ms:.0f} ms maximum latency).",
                styles["body"],
            )
        )
        rows = [["#", "Name", "Proto", "Endpoint", "Latency", "Speed", "Iran", "Score"]]
        for rank, result in enumerate(report.selected[:40], start=1):
            rows.append(
                [
                    str(rank),
                    Paragraph(_escape(_truncate(result.config.display_name, 34)), styles["cell"]),
                    result.config.scheme,
                    _escape(result.config.endpoint),
                    f"{result.latency_ms:.0f} ms",
                    f"{result.download_mbps:.1f}",
                    f"{result.iran_score:.0f}",
                    Paragraph(f"{result.final_score:.1f}", styles["cell_bold"]),
                ]
            )
        story.append(
            _table(
                rows,
                [
                    7 * mm,
                    52 * mm,
                    15 * mm,
                    38 * mm,
                    18 * mm,
                    16 * mm,
                    12 * mm,
                    16 * mm,
                ],
                align_right=(4, 5, 6, 7),
            )
        )
    else:
        story.append(
            Paragraph(
                "No configuration passed the quality thresholds. "
                "Lower the minimum speed or the maximum latency to keep the alive configurations.",
                styles["body"],
            )
        )
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("5. Throughput of the best configurations", styles["h1"]))
    story.append(_speed_chart(report.results, styles))
    story.append(Spacer(1, 5 * mm))

    # --------------------------------------------------------------- failures
    story.append(Paragraph("6. Failure analysis", styles["h1"]))
    if report.error_counts:
        rows = [["Failure category", "Count", "Share of the tested set"]]
        total = sum(report.error_counts.values()) or 1
        for name, count in report.error_counts.items():
            rows.append(
                [
                    ERROR_CATEGORIES.get(name, name),
                    str(count),
                    f"{count / total:.1%}",
                ]
            )
        story.append(_table(rows, [70 * mm, 25 * mm, 45 * mm], align_right=(1, 2)))
        story.append(Spacer(1, 3 * mm))
        story.append(
            Paragraph(
                "Handshake failures are dominated by dead servers, wrong credentials and "
                "expired subscriptions; they are not a property of the protocol itself.",
                styles["small"],
            )
        )
    else:
        story.append(Paragraph("Every tested configuration was alive.", styles["body"]))
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("7. Iran affinity", styles["h1"]))
    story.append(
        Paragraph(
            "Iran affinity combines where the entry server is hosted with the shape of the "
            "connection. REALITY with uTLS, TLS on a standard port and a CDN fronted entry "
            "point are the characteristics that survive Iranian DPI the most often. "
            + (
                "Configurations were additionally probed from real Iranian vantage points."
                if report.iran_probe_available
                else "No Iranian vantage point was reachable during this run, so the score is "
                "based on the static analysis only."
            ),
            styles["body"],
        )
    )
    if report.iran_class_counts:
        rows = [["Entry class", "Alive configurations", "Share"]]
        total = sum(report.iran_class_counts.values()) or 1
        for name, count in report.iran_class_counts.items():
            rows.append([class_label(name), str(count), f"{count / total:.1%}"])
        story.append(_table(rows, [70 * mm, 30 * mm, 30 * mm], align_right=(1, 2)))
        story.append(Spacer(1, 4 * mm))

    explained = [result for result in report.results if result.alive and result.iran_reasons][:10]
    if explained:
        story.append(Paragraph("Why the best candidates score well for Iran", styles["h2"]))
        rows = [["Endpoint", "Iran score", "Reasoning"]]
        for result in explained:
            rows.append(
                [
                    _escape(result.config.endpoint),
                    f"{result.iran_score:.0f}",
                    Paragraph(_escape("; ".join(result.iran_reasons)), styles["cell"]),
                ]
            )
        story.append(
            _table(rows, [38 * mm, 18 * mm, PAGE_WIDTH - 36 * mm - 56 * mm], align_right=(1,))
        )
        story.append(Spacer(1, 4 * mm))

    probed = [result for result in report.results if result.iran_probe.available]
    if probed:
        rows = [["Endpoint", "Reachable from Iran", "RTT", "Probes", "Detail"]]
        for result in probed[:25]:
            rows.append(
                [
                    _escape(result.config.endpoint),
                    "yes" if result.iran_probe.reachable else "no",
                    f"{result.iran_probe.rtt_ms:.0f} ms" if result.iran_probe.rtt_ms else "-",
                    str(result.iran_probe.probes),
                    Paragraph(_escape(_truncate(result.iran_probe.detail, 46)), styles["cell"]),
                ]
            )
        story.append(
            _table(rows, [40 * mm, 30 * mm, 18 * mm, 14 * mm, PAGE_WIDTH - 36 * mm - 102 * mm])
        )
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("8. Limitations", styles["h1"]))
    limitations = [
        "The measurement runs on a GitHub Actions runner outside Iran; the throughput therefore "
        "reflects the runner's network, not an Iranian one. Use the Iran affinity score and the "
        "Iranian vantage point results to judge the local experience.",
        "A configuration that is alive during the run can still be rate limited or blocked later; "
        "free public configurations expire quickly.",
        "Only the protocols supported by sing-box can be tested; unknown schemes are reported as "
        "rejected lines.",
        "The Iranian vantage points come from a public measurement network and are subject to its "
        "availability and rate limits.",
    ]
    for item in limitations:
        story.append(Paragraph(f"• {_escape(item)}", styles["body"]))

    story.append(Spacer(1, 4 * mm))

    # ---------------------------------------------------------------- appendix
    story.append(Paragraph("Appendix A - every measured configuration", styles["h1"]))
    rows = [["#", "Name", "Proto", "Trans", "Endpoint", "Latency", "Speed", "Exit", "Class", "Score"]]
    for rank, result in enumerate(report.results, start=1):
        rows.append(
            [
                str(rank),
                Paragraph(_escape(_truncate(result.config.display_name, 30)), styles["cell"]),
                result.config.scheme,
                result.config.transport or "tcp",
                _escape(result.config.endpoint),
                f"{result.latency_ms:.0f}" if result.alive else "-",
                f"{result.download_mbps:.1f}" if result.alive else "-",
                result.exit_geo.country_code or "-",
                class_label(result.iran_class).split(" (")[0],
                f"{result.final_score:.1f}",
            ]
        )
    if len(rows) == 1:
        rows.append(["-", "no configuration was measured", "-", "-", "-", "-", "-", "-", "-", "-"])
    story.append(
        _table(
            rows,
            [
                7 * mm,
                44 * mm,
                14 * mm,
                15 * mm,
                34 * mm,
                14 * mm,
                13 * mm,
                12 * mm,
                25 * mm,
                14 * mm,
            ],
            align_right=(5, 6, 9),
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            "The machine readable version of this report (results.json) contains the "
            "untruncated URIs of every configuration together with all measurements.",
            styles["small"],
        )
    )

    doc.build(story)
    return path
