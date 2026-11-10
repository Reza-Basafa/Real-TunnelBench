"""Command line interface of the benchmark."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__
from .models import BenchSettings
from .pipeline import run_benchmark
from .report import build_pdf


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tunnelbench",
        description=(
            "Download a list of proxy configurations, test every entry with a real proxy "
            "core, rank the working ones for Iranian users and export a v2ray ready "
            "subscription plus a PDF report."
        ),
    )
    parser.add_argument("--url", required=True, help="Public HTTP(S) URL of the configuration list")
    parser.add_argument("--output-dir", default="output", help="Directory for the generated files")
    parser.add_argument("--max-configs", type=int, default=400, help="Maximum number of configurations to test")
    parser.add_argument("--concurrency", type=int, default=12, help="Number of parallel measurements")
    parser.add_argument("--timeout-minutes", type=int, default=45, help="Overall time budget")
    parser.add_argument("--min-speed-mbps", type=float, default=0.5, help="Minimum download speed of a usable configuration")
    parser.add_argument("--max-latency-ms", type=float, default=2000.0, help="Maximum latency of a usable configuration")
    parser.add_argument("--latency-samples", type=int, default=3, help="Latency samples per configuration")
    parser.add_argument("--speed-test-bytes", type=int, default=5_000_000, help="Download size used for the speed test")
    parser.add_argument("--speed-test-url", default="", help="Custom speed test URL ({bytes} is replaced)")
    parser.add_argument("--latency-url", default="", help="Custom latency probe URL")
    parser.add_argument("--exit-ip-url", default="", help="Custom exit address lookup URL")
    parser.add_argument("--iran-probe", choices=["auto", "on", "off"], default="auto", help="Iranian vantage point measurements")
    parser.add_argument("--iran-probe-limit", type=int, default=25, help="How many candidates are probed from Iran")
    parser.add_argument("--core-version", default="1.14.4", help="sing-box release to use")
    parser.add_argument("--core-path", default="", help="Path of an existing sing-box binary")
    parser.add_argument(
        "--core-sha256",
        default=os.environ.get("TUNNELBENCH_CORE_SHA256", ""),
        help="Expected SHA-256 of the downloaded core archive",
    )
    parser.add_argument("--no-geo", action="store_true", help="Disable geolocation lookups")
    parser.add_argument("--dry-run", action="store_true", help="Only parse the list, do not test anything")
    parser.add_argument("--include-failed", action="store_true", help="Also export the configurations that failed")
    parser.add_argument("--keep-all-tested", action="store_true", help="Export every alive configuration")
    parser.add_argument("--max-output", type=int, default=0, help="Limit the number of exported configurations")
    parser.add_argument("--weight-speed", type=float, default=0.50)
    parser.add_argument("--weight-latency", type=float, default=0.20)
    parser.add_argument("--weight-iran", type=float, default=0.22)
    parser.add_argument("--weight-stability", type=float, default=0.08)
    parser.add_argument("--no-pdf", action="store_true", help="Skip the PDF report")
    parser.add_argument("--version", action="version", version=f"Real-TunnelBench {__version__}")
    return parser


def settings_from_args(args: argparse.Namespace) -> BenchSettings:
    return BenchSettings(
        source_url=args.url,
        output_dir=args.output_dir,
        max_configs=args.max_configs,
        concurrency=args.concurrency,
        timeout_minutes=args.timeout_minutes,
        min_download_mbps=args.min_speed_mbps,
        max_latency_ms=args.max_latency_ms,
        latency_samples=args.latency_samples,
        speed_test_bytes=args.speed_test_bytes,
        speed_test_url=args.speed_test_url,
        latency_url=args.latency_url,
        exit_ip_url=args.exit_ip_url,
        iran_probe=args.iran_probe,
        iran_probe_limit=args.iran_probe_limit,
        core_version=args.core_version,
        core_sha256=args.core_sha256,
        core_path=args.core_path,
        geo_lookup=not args.no_geo,
        dry_run=args.dry_run,
        include_failed=args.include_failed,
        keep_all_tested=args.keep_all_tested,
        max_output=args.max_output,
        weights={
            "speed": args.weight_speed,
            "latency": args.weight_latency,
            "iran": args.weight_iran,
            "stability": args.weight_stability,
        },
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = settings_from_args(args)

    started = time.perf_counter()
    try:
        report = run_benchmark(settings)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output_dir = Path(settings.output_dir)
    if not args.no_pdf:
        try:
            build_pdf(report, output_dir / "report.pdf")
            print(f"PDF report: {(output_dir / 'report.pdf').resolve()}")
        except Exception as exc:
            print(f"WARNING: the PDF report could not be created ({exc})", file=sys.stderr)

    print("")
    print("=" * 68)
    print(f"Source            : {settings.source_url}")
    print(f"Configurations    : {report.parsed} parsed / {report.tested} tested")
    print(f"Alive             : {report.alive}")
    print(f"Exported          : {len(report.selected)}")
    print(f"Best speed        : {report.best_mbps:.2f} Mbps")
    print(f"Median latency    : {report.median_latency_ms:.0f} ms")
    print(f"Duration          : {time.perf_counter() - started:.0f} s")
    print("=" * 68)
    print(f"Subscription      : {(output_dir / 'working_configs.txt').resolve()}")
    print(f"Plain list        : {(output_dir / 'working_configs_plain.txt').resolve()}")
    print(f"Ranking (csv)     : {(output_dir / 'configs_ranked.csv').resolve()}")
    print(f"Summary           : {(output_dir / 'summary.md').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
