"""End to end orchestration of a benchmark run."""

from __future__ import annotations

import base64
import csv
import json
import platform
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from . import uris
from .core import CoreError, CoreProcess, provision_core
from .fetch import FetchError, fetch
from .geo import CLASS_UNKNOWN, GeoResolver, classify
from .iran import IranAssessment, IranVantage, apply_iran_probe, assess_static
from .models import BenchReport, BenchSettings, ProbeResult, ProxyConfig
from .probe import Prober
from .scoring import apply_scores

BASE_PORT = 20800
CHUNK_SIZE = 100

Logger = Callable[[str], None]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _log(logger: Logger, message: str) -> None:
    logger(message)
    print(message, flush=True)


def _runner_description() -> str:
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    return f"{platform.system()} {platform.release()} ({platform.machine()}) on {hostname}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _select_candidates(
    configs: list[ProxyConfig], limit: int, resolver: GeoResolver, logger: Logger
) -> list[ProxyConfig]:
    """Pick the configurations that should be tested.

    When the list is longer than ``limit`` the candidates are ranked by their
    static Iran affinity so that the budget is spent on the configurations
    that are most likely to be usable.
    """
    if limit <= 0 or len(configs) <= limit:
        return configs

    # Phase 1: a cheap pre-score that needs no network access.
    prescore = [
        (assess_static(cfg, CLASS_UNKNOWN).score, cfg.index, cfg) for cfg in configs
    ]
    prescore.sort(key=lambda item: (-item[0], item[1]))
    shortlist = prescore[: min(len(prescore), max(limit * 2, limit + 50))]

    # Phase 2: geolocate the shortlist in batches - the providers accept 100
    # addresses per call but rate limit the number of calls.
    addresses: dict[int, list[str]] = {}
    for _, index, cfg in shortlist:
        if uris.is_ip_address(cfg.server):
            addresses[index] = [cfg.server]
        else:
            addresses[index] = _safe_resolve(cfg.server)
    lookup = resolver.lookup_many([ip for ips in addresses.values() for ip in ips])

    scored = []
    for _, index, cfg in shortlist:
        entry_class = CLASS_UNKNOWN
        for address in addresses.get(index, []):
            geo = lookup.get(address)
            if geo is not None and geo.source != "unavailable":
                entry_class = classify(geo)
                break
        scored.append((assess_static(cfg, entry_class).score, index, cfg))

    scored.sort(key=lambda item: (-item[0], item[1]))
    selected = [item[2] for item in scored[:limit]]
    selected.sort(key=lambda cfg: cfg.index)
    _log(
        logger,
        f"Selected {len(selected)} of {len(configs)} configurations for testing "
        f"(Iran-affinity pre-ranking)",
    )
    return selected


def _safe_resolve(host: str) -> list[str]:
    try:
        addresses = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return list(dict.fromkeys(info[4][0] for info in addresses))


def _validate_with_core(binary: Path, configs: list[ProxyConfig], logger: Logger) -> tuple[list[ProxyConfig], list[tuple[ProxyConfig, str]]]:
    """Ask sing-box to validate every configuration on its own."""
    import json as _json
    import subprocess
    import tempfile

    from .singbox import build_document

    valid: list[ProxyConfig] = []
    rejected: list[tuple[ProxyConfig, str]] = []
    workdir = Path(tempfile.mkdtemp(prefix="rtb-check-"))

    def check(cfg: ProxyConfig) -> tuple[ProxyConfig, str]:
        document = build_document([cfg], base_port=BASE_PORT)
        path = workdir / f"check-{cfg.index}.json"
        path.write_text(_json.dumps(document), encoding="utf-8")
        try:
            result = subprocess.run(
                [str(binary), "check", "-c", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return cfg, f"validation failed: {exc}"
        finally:
            path.unlink(missing_ok=True)
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "invalid configuration").strip()
            message = message.splitlines()[-1] if message else "invalid configuration"
            return cfg, message
        return cfg, ""

    with ThreadPoolExecutor(max_workers=8) as pool:
        for cfg, message in pool.map(check, configs):
            if message:
                rejected.append((cfg, message))
            else:
                valid.append(cfg)

    if rejected:
        _log(logger, f"sing-box rejected {len(rejected)} configuration(s) during validation")
    return valid, rejected


def _chunk(items: list, size: int) -> Iterable[list]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


# ---------------------------------------------------------------------------
# main pipeline
# ---------------------------------------------------------------------------


def run_benchmark(settings: BenchSettings, logger: Logger | None = None) -> BenchReport:
    """Execute a full benchmark run and write every artefact."""
    log = logger or (lambda message: None)
    report = BenchReport(settings=settings)
    report.started_at = _now()
    started = time.perf_counter()
    report.runner = _runner_description()

    output_dir = Path(settings.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ fetch
    _log(log, f"Downloading {settings.source_url}")
    try:
        fetched = fetch(settings.source_url)
    except FetchError as exc:
        raise RuntimeError(f"cannot download the source list: {exc}") from exc

    report.source_bytes = fetched.raw_bytes
    report.source_lines = len([line for line in fetched.lines if line.strip()])
    report.source_encoded = fetched.encoded
    _log(
        log,
        f"Fetched {fetched.raw_bytes} bytes "
        f"({'base64 subscription' if fetched.encoded else 'plain text'}), "
        f"{report.source_lines} non-empty lines",
    )

    # ------------------------------------------------------------------ parse
    configs, rejected_lines, duplicates = uris.parse_all(fetched.lines)
    report.parsed = len(configs)
    report.rejected = len(rejected_lines)
    report.duplicates = duplicates
    report.rejected_lines = rejected_lines
    _log(
        log,
        f"Parsed {len(configs)} unique configurations "
        f"({duplicates} duplicates, {len(rejected_lines)} rejected)",
    )
    if not configs:
        raise RuntimeError("no usable configuration was found in the source list")

    report.protocol_counts = _count(configs, lambda cfg: cfg.scheme)
    report.transport_counts = _count(configs, lambda cfg: cfg.transport or "tcp")

    resolver = GeoResolver(enabled=settings.geo_lookup)

    if settings.dry_run:
        _log(log, "Dry run: skipping the live measurement")
        report.finished_at = _now()
        report.duration_s = time.perf_counter() - started
        _write_outputs(report, output_dir)
        return report

    # ------------------------------------------------------------------ limit
    candidates = _select_candidates(configs, settings.max_configs, resolver, log)

    # ------------------------------------------------------------------ core
    core_binary = Path(settings.core_path) if settings.core_path else output_dir / ".core" / "sing-box"
    try:
        core = provision_core(
            core_binary,
            settings.core_version,
            expected_sha256=settings.core_sha256,
        )
    except CoreError as exc:
        raise RuntimeError(f"cannot provision the sing-box core: {exc}") from exc
    report.core_version = core.version
    _log(log, f"Using {core.describe()} (utls={'yes' if core.supports_utls else 'no'})")

    valid, invalid = _validate_with_core(core.path, candidates, log)
    for cfg, message in invalid:
        rejected_lines.append(f"{cfg.raw}  (core rejected: {message})")
    report.rejected += len(invalid)
    report.rejected_lines = rejected_lines
    if not valid:
        raise RuntimeError("every configuration was rejected by the sing-box core")

    # ------------------------------------------------------------------ probe
    results: list[ProbeResult] = []
    prober = Prober(
        base_port=BASE_PORT,
        latency_url=settings.latency_url,
        latency_samples=settings.latency_samples,
        speed_bytes=settings.speed_test_bytes,
        speed_url=settings.speed_test_url,
        exit_url=settings.exit_ip_url,
    )

    for chunk_number, chunk in enumerate(_chunk(valid, CHUNK_SIZE), start=1):
        if time.perf_counter() - started > settings.timeout_minutes * 60:
            _log(log, "Time budget exhausted - the remaining configurations are skipped")
            break
        _log(
            log,
            f"Testing chunk {chunk_number}: {len(chunk)} configuration(s) "
            f"with {settings.concurrency} workers",
        )
        results.extend(_probe_chunk(chunk, prober, settings, core, output_dir, log))

    report.results = results
    report.tested = len(results)
    report.alive = sum(1 for result in results if result.alive)

    # ------------------------------------------------------------------ geo
    if settings.geo_lookup:
        _enrich_geography(results, resolver, log)

    # ------------------------------------------------------------------ iran
    _score_iran(results, log)

    # -------------------------------------------------------------- iran probe
    if settings.iran_probe in {"auto", "on"}:
        _run_iran_probes(results, settings, report, log)

    # ------------------------------------------------------------------ score
    for result in results:
        apply_scores(result, settings.weights)

    results.sort(key=lambda item: (-item.final_score, -item.download_mbps, item.latency_ms))

    report.best_mbps = max((result.download_mbps for result in results), default=0.0)
    alive_latencies = [result.latency_ms for result in results if result.alive]
    report.median_latency_ms = _median(alive_latencies)
    report.error_counts = _count(
        [result for result in results if not result.alive],
        lambda result: result.error or "unknown",
    )
    report.iran_class_counts = _count(
        [result for result in results if result.alive],
        lambda result: result.iran_class,
    )
    report.selected = _select_working(results, settings)

    _log(
        log,
        f"Tested {report.tested} configuration(s): {report.alive} alive, "
        f"{len(report.selected)} passed the quality thresholds",
    )

    report.finished_at = _now()
    report.duration_s = time.perf_counter() - started
    _write_outputs(report, output_dir)
    return report


def _count(items: Iterable, key) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = key(item)
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _probe_chunk(
    chunk: list[ProxyConfig],
    prober: Prober,
    settings: BenchSettings,
    core,
    output_dir: Path,
    log: Logger,
) -> list[ProbeResult]:
    """Start sing-box for one chunk and measure every configuration."""
    from .singbox import build_document

    document = build_document(chunk, base_port=BASE_PORT)
    config_path = output_dir / ".core" / f"chunk-{chunk[0].index}.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    process = CoreProcess(core.path, config_path, output_dir / ".core" / "sing-box.log")
    try:
        process.start()
        ports = [BASE_PORT + position for position in range(len(chunk))]
        process.wait_for_ports(ports, timeout=30.0)
    except CoreError as exc:
        log(f"  ! sing-box failed to start for this chunk: {exc}")
        process.stop()
        return [
            ProbeResult(index=cfg.index, config=cfg, alive=False, error="handshake-failed")
            for cfg in chunk
        ]

    results: list[ProbeResult] = []
    try:
        with ThreadPoolExecutor(max_workers=max(1, settings.concurrency)) as pool:
            futures = {
                pool.submit(prober.test, cfg, position): (cfg, position)
                for position, cfg in enumerate(chunk)
            }
            done = 0
            for future in as_completed(futures):
                cfg, position = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    results.append(
                        ProbeResult(
                            index=cfg.index,
                            config=cfg,
                            alive=False,
                            error="handshake-failed",
                            duration_s=0.0,
                        )
                    )
                    log(f"  ! {cfg.display_name}: probe crashed ({exc})")
                done += 1
                if done % 25 == 0:
                    log(f"  ... {done}/{len(chunk)} measured")
    finally:
        process.stop()

    return results


def _enrich_geography(results: list[ProbeResult], resolver: GeoResolver, log: Logger) -> None:
    ips: list[str] = []
    for result in results:
        if result.config.server and not uris.is_ip_address(result.config.server):
            try:
                addresses = socket.getaddrinfo(
                    result.config.server, None, proto=socket.IPPROTO_TCP
                )
            except (socket.gaierror, UnicodeError, OSError):
                addresses = []
            result.entry_ips = list(dict.fromkeys(info[4][0] for info in addresses))
        elif result.config.server:
            result.entry_ips = [result.config.server]
        ips.extend(result.entry_ips)

    if not ips:
        return

    _log(log, f"Looking up {len(set(ips))} entry address(es)")
    lookup = resolver.lookup_many(list(dict.fromkeys(ips)))
    for result in results:
        for address in result.entry_ips:
            info = lookup.get(address)
            if info is not None:
                result.entry_geo = info
                break


def _score_iran(results: list[ProbeResult], log: Logger) -> None:
    for result in results:
        entry_class = classify(result.entry_geo) if result.entry_geo.source != "unavailable" else CLASS_UNKNOWN
        if result.exit_geo.source != "unavailable":
            exit_class = classify(result.exit_geo)
            if entry_class == CLASS_UNKNOWN and exit_class in {
                "iran-host",
                "iran-cdn",
            }:
                entry_class = exit_class
        assessment: IranAssessment = assess_static(result.config, entry_class)
        result.iran_class = entry_class
        result.iran_score = assessment.score
        result.iran_reasons = list(assessment.reasons)


def _run_iran_probes(
    results: list[ProbeResult],
    settings: BenchSettings,
    report: BenchReport,
    log: Logger,
) -> None:
    candidates = [result for result in results if result.alive][: settings.iran_probe_limit]
    if not candidates:
        report.iran_probe_message = "no alive configuration to probe from Iran"
        return

    vantage = IranVantage(timeout=settings.iran_probe_timeout)
    _log(log, f"Probing {len(candidates)} configuration(s) from Iranian vantage points")

    def probe(result: ProbeResult) -> ProbeResult:
        try:
            result.iran_probe = vantage.probe(result.config.server, result.config.port)
        except Exception as exc:  # pragma: no cover - defensive
            result.iran_probe.detail = f"error: {exc}"
        return result

    with ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(probe, candidates):
            assessment = IranAssessment(
                score=result.iran_score,
                entry_class=result.iran_class,
                reasons=list(result.iran_reasons),
            )
            apply_iran_probe(assessment, result.iran_probe)
            result.iran_score = assessment.score
            result.iran_reasons = list(assessment.reasons)
            state = "reachable" if result.iran_probe.reachable else "unreachable"
            _log(
                log,
                f"  {result.config.endpoint}: {state}"
                + (f" ({result.iran_probe.rtt_ms:.0f} ms)" if result.iran_probe.rtt_ms else ""),
            )

    report.iran_probe_available = bool(vantage.available)
    report.iran_probe_message = vantage.message or "Iranian vantage points were used"


def _select_working(results: list[ProbeResult], settings: BenchSettings) -> list[ProbeResult]:
    selected: list[ProbeResult] = []
    for result in results:
        if not result.alive:
            if settings.include_failed:
                selected.append(result)
            continue
        if settings.keep_all_tested:
            selected.append(result)
            continue
        if (
            result.download_mbps >= settings.min_download_mbps
            and result.latency_ms <= settings.max_latency_ms
        ):
            selected.append(result)

    if settings.max_output > 0:
        selected = selected[: settings.max_output]
    return selected


# ---------------------------------------------------------------------------
# artefacts
# ---------------------------------------------------------------------------


def _write_outputs(report: BenchReport, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    uris_selected = [result.config.raw for result in report.selected]
    plain = "\n".join(uris_selected) + ("\n" if uris_selected else "")
    (output_dir / "working_configs_plain.txt").write_text(plain, encoding="utf-8")

    subscription = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    (output_dir / "working_configs.txt").write_text(subscription + "\n", encoding="utf-8")

    all_alive = [result for result in report.results if result.alive]
    alive_plain = "\n".join(result.config.raw for result in all_alive) + ("\n" if all_alive else "")
    (output_dir / "alive_configs.txt").write_text(alive_plain, encoding="utf-8")

    (output_dir / "rejected_lines.txt").write_text(
        "\n".join(report.rejected_lines) + ("\n" if report.rejected_lines else ""),
        encoding="utf-8",
    )

    with (output_dir / "configs_ranked.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "rank",
                "name",
                "scheme",
                "transport",
                "server",
                "port",
                "latency_ms",
                "jitter_ms",
                "download_mbps",
                "exit_ip",
                "exit_country",
                "entry_class",
                "iran_score",
                "final_score",
                "uri",
            ]
        )
        for rank, result in enumerate(report.results, start=1):
            writer.writerow(
                [
                    rank,
                    result.config.display_name,
                    result.config.scheme,
                    result.config.transport or "tcp",
                    result.config.server,
                    result.config.port,
                    f"{result.latency_ms:.0f}",
                    f"{result.jitter_ms:.0f}",
                    f"{result.download_mbps:.2f}",
                    result.exit_ip,
                    result.exit_geo.country_code or "",
                    result.iran_class,
                    f"{result.iran_score:.1f}",
                    f"{result.final_score:.1f}",
                    result.config.raw,
                ]
            )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_url": report.settings.source_url,
        "duration_s": round(report.duration_s, 1),
        "runner": report.runner,
        "core_version": report.core_version,
        "counts": {
            "source_lines": report.source_lines,
            "parsed": report.parsed,
            "duplicates": report.duplicates,
            "rejected": report.rejected,
            "tested": report.tested,
            "alive": report.alive,
            "selected": len(report.selected),
        },
        "results": [
            {
                **result.config.describe(),
                "alive": result.alive,
                "latency_ms": round(result.latency_ms, 1),
                "jitter_ms": round(result.jitter_ms, 1),
                "download_mbps": round(result.download_mbps, 2),
                "entry_tcp_ms": round(result.entry_tcp_ms, 1),
                "exit_ip": result.exit_ip,
                "exit_country": result.exit_geo.country_code,
                "entry_class": result.iran_class,
                "iran_score": round(result.iran_score, 1),
                "final_score": round(result.final_score, 1),
                "error": result.error,
                "iran_probe": {
                    "available": result.iran_probe.available,
                    "reachable": result.iran_probe.reachable,
                    "rtt_ms": round(result.iran_probe.rtt_ms, 1),
                    "detail": result.iran_probe.detail,
                },
                "uri": result.config.raw,
            }
            for result in report.results
        ],
    }
    (output_dir / "results.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    (output_dir / "summary.md").write_text(build_markdown_summary(report), encoding="utf-8")

    try:
        from .report import build_pdf

        build_pdf(report, output_dir / "report.pdf")
    except Exception as exc:  # pragma: no cover - the report must never break a run
        report.notes.append(f"the PDF report could not be created: {exc}")


def build_markdown_summary(report: BenchReport) -> str:
    """Bilingual markdown summary of the run."""
    settings = report.settings
    lines: list[str] = []
    lines.append("# Real-TunnelBench report")
    lines.append("")
    lines.append(f"**Source:** {settings.source_url}")
    lines.append(f"**Generated:** {report.finished_at}")
    lines.append(f"**Runner:** {report.runner}")
    lines.append(f"**Core:** sing-box {report.core_version}")
    lines.append("")
    lines.append("## نتیجه خلاصه")
    lines.append("")
    lines.append("| سنجه | مقدار |")
    lines.append("| --- | --- |")
    lines.append(f"| کانفیگ‌های دریافتی | {report.source_lines} |")
    lines.append(f"| کانفیگ‌های معتبر | {report.parsed} |")
    lines.append(f"| کانفیگ‌های تست‌شده | {report.tested} |")
    lines.append(f"| کانفیگ‌های سالم | {report.alive} |")
    lines.append(f"| کانفیگ‌های نهایی | {len(report.selected)} |")
    lines.append(f"| بهترین سرعت | {report.best_mbps:.2f} Mbps |")
    lines.append(f"| میانه تأخیر | {report.median_latency_ms:.0f} ms |")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"{report.alive} of {report.tested} tested configurations are alive, "
        f"{len(report.selected)} of them passed the quality thresholds."
    )
    lines.append("")

    if report.selected:
        lines.append("## Top configurations")
        lines.append("")
        lines.append("| # | Name | Protocol | Endpoint | Latency | Speed | Iran score |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for rank, result in enumerate(report.selected[:15], start=1):
            lines.append(
                f"| {rank} | {result.config.display_name[:42]} | {result.config.scheme} | "
                f"{result.config.endpoint} | {result.latency_ms:.0f} ms | "
                f"{result.download_mbps:.2f} Mbps | {result.iran_score:.0f} |"
            )
        lines.append("")

    if report.iran_probe_message:
        lines.append(f"**Iran vantage points:** {report.iran_probe_message}")
        lines.append("")

    lines.append("## Artefacts")
    lines.append("")
    lines.append("- `working_configs.txt` - base64 subscription for v2ray clients")
    lines.append("- `working_configs_plain.txt` - plain list of the selected URIs")
    lines.append("- `configs_ranked.csv` - every measured configuration with metrics")
    lines.append("- `results.json` - machine readable results")
    lines.append("- `report.pdf` - the full PDF report")
    lines.append("")
    return "\n".join(lines)
