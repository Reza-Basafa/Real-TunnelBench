
from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

MAX_BYTES = 5 * 1024 * 1024
TIMEOUT_SECONDS = 20

SUPPORTED_SCHEMES = {
    "vmess", "vless", "trojan", "ss",
    "socks", "socks5", "http", "https",
    "hysteria2", "tuic"
}


def is_public_http_url(url: str) -> bool:
    """Allow public HTTP(S) URLs; reject localhost/private destinations."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False

        host = parsed.hostname.lower()
        if host == "localhost" or host.endswith(".localhost"):
            return False

        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    host, parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM
                )
            }

        return bool(addresses) and all(
            address.is_global for address in addresses
        )
    except (ValueError, OSError, socket.gaierror):
        return False


def download_text(url: str) -> str:
    if not is_public_http_url(url):
        raise ValueError("URL must point to a public HTTP(S) resource.")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Real-TunnelBench-StaticAnalyzer/1.0"}
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        final_url = response.geturl()
        if not is_public_http_url(final_url):
            raise ValueError("Redirect destination is not a public URL.")

        content = response.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise ValueError("Input file exceeds the 5 MB limit.")

        charset = response.headers.get_content_charset() or "utf-8"
        return content.decode(charset, errors="replace")


def classify_line(line: str) -> str | None:
    candidate = line.strip()
    if not candidate or candidate.startswith("#"):
        return None

    if "://" not in candidate:
        return None

    scheme = candidate.split("://", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        return None

    remainder = candidate.split("://", 1)[1].strip()
    if not remainder:
        return None

    return scheme


def analyze(text: str):
    seen = set()
    accepted = []
    rejected = []
    counts = Counter()
    duplicates = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        scheme = classify_line(line)
        if scheme is None:
            rejected.append(line)
            continue

        if line in seen:
            duplicates += 1
            continue

        seen.add(line)
        accepted.append(line)
        counts[scheme] += 1

    return accepted, rejected, counts, duplicates


def write_pdf(path: Path, source: str, accepted, rejected, counts, duplicates):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    total = len(accepted) + len(rejected) + duplicates
    story = [
        Paragraph("Real-TunnelBench", styles["Title"]),
        Paragraph("Static Configuration Analysis Report", styles["Heading2"]),
        Spacer(1, 5 * mm),
        Paragraph(
            "Generated: " + datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            ),
            styles["Normal"]
        ),
        Spacer(1, 3 * mm),
        Paragraph("Source: " + source.replace("&", "&amp;").replace("<", "&lt;"),
                  styles["BodyText"]),
        Spacer(1, 5 * mm),
        Paragraph("Summary", styles["Heading2"]),
    ]

    summary = [
        ["Metric", "Count"],
        ["Unique recognized-format lines", str(len(accepted))],
        ["Unrecognized or malformed lines", str(len(rejected))],
        ["Duplicate lines removed", str(duplicates)],
        ["Non-comment input lines", str(total)],
    ]

    table = Table(summary, colWidths=[105 * mm, 45 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.extend([table, Spacer(1, 5 * mm)])
    story.append(Paragraph("Recognized schemes", styles["Heading2"]))

    scheme_rows = [["Scheme", "Count"]]
    scheme_rows.extend(
        [[scheme, str(count)] for scheme, count in sorted(counts.items())]
        or [["None", "0"]]
    )
    scheme_table = Table(scheme_rows, colWidths=[105 * mm, 45 * mm])
    scheme_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(scheme_table)
    story.extend([
        Spacer(1, 6 * mm),
        Paragraph(
            "Important: This report checks text structure only. "
            "It does not connect to endpoints, test availability, "
            "measure speed, or verify whether a configuration works.",
            styles["BodyText"]
        ),
    ])
    doc.build(story)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze configuration text without connecting to endpoints."
    )
    parser.add_argument("--url", required=True, help="Public HTTP(S) text URL")
    parser.add_argument("--output-dir", default="output")
    args = parser.parse_args()

    try:
        text = download_text(args.url)
        accepted, rejected, counts, duplicates = analyze(text)

        output = Path(args.output_dir)
        output.mkdir(parents=True, exist_ok=True)

        (output / "accepted_configs.txt").write_text(
            "\n".join(accepted) + ("\n" if accepted else ""),
            encoding="utf-8"
        )
        (output / "rejected_lines.txt").write_text(
            "\n".join(rejected) + ("\n" if rejected else ""),
            encoding="utf-8"
        )

        write_pdf(
            output / "report.pdf", args.url,
            accepted, rejected, counts, duplicates
        )

        print(f"Recognized unique lines: {len(accepted)}")
        print(f"Rejected lines: {len(rejected)}")
        print(f"Duplicates removed: {duplicates}")
        print(f"Output directory: {output.resolve()}")

    except (ValueError, OSError, urllib.error.URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
