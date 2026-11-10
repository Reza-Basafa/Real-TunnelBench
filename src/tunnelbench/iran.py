"""Iran specific scoring and Iranian vantage point measurements.

A configuration that is fast from a GitHub Actions runner in the United
States is not necessarily usable from Iran: the entry server has to be
reachable from Iranian networks and it should survive Iranian DPI.

Two independent signals are combined:

* static affinity  - where the entry server lives and how the connection is
  shaped (REALITY, TLS, CDN fronting, port choice),
* active affinity  - measurements performed from real Iranian vantage points
  (Globalping probes located in Iran) which prove reachability and give the
  round trip time an Iranian client would see.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .geo import (
    CLASS_CLOUDFLARE,
    CLASS_DATACENTER,
    CLASS_GLOBAL_CDN,
    CLASS_IRAN_CDN,
    CLASS_IRAN_HOST,
    CLASS_RESIDENTIAL,
    CLASS_UNKNOWN,
)
from .models import IranProbe, ProxyConfig

USER_AGENT = "Real-TunnelBench/2.0 (+https://github.com/Reza-Basafa/Real-TunnelBench)"
GLOBALPING_API = "https://api.globalping.io/v1/measurements"

CDN_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 2082, 2086, 2095}


# ---------------------------------------------------------------------------
# static affinity
# ---------------------------------------------------------------------------

CLASS_BASE_SCORE = {
    CLASS_IRAN_HOST: 100.0,
    CLASS_IRAN_CDN: 90.0,
    CLASS_CLOUDFLARE: 62.0,
    CLASS_GLOBAL_CDN: 44.0,
    CLASS_RESIDENTIAL: 36.0,
    CLASS_DATACENTER: 30.0,
    CLASS_UNKNOWN: 18.0,
}


@dataclass
class IranAssessment:
    score: float = 0.0
    reasons: list[str] = None  # type: ignore[assignment]
    entry_class: str = CLASS_UNKNOWN

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []


def assess_static(cfg: ProxyConfig, entry_class: str) -> IranAssessment:
    """Score how friendly a configuration is for Iranian users."""
    assessment = IranAssessment(entry_class=entry_class)
    score = CLASS_BASE_SCORE.get(entry_class, CLASS_BASE_SCORE[CLASS_UNKNOWN])
    assessment.reasons.append(f"entry class: {entry_class} ({score:.0f})")

    host = (cfg.server or "").lower()
    if host.endswith(".ir"):
        score += 12
        assessment.reasons.append("Iranian domain (.ir)")

    if cfg.security == "reality":
        score += 12
        assessment.reasons.append("REALITY fingerprinting (strong against Iranian DPI)")
    elif cfg.security == "tls":
        score += 6
        assessment.reasons.append("TLS encrypted")
    else:
        score -= 14
        assessment.reasons.append("no TLS - likely filtered in Iran")

    if cfg.transport in {"ws", "grpc", "http", "httpupgrade"} and entry_class in {
        CLASS_CLOUDFLARE,
        CLASS_GLOBAL_CDN,
        CLASS_IRAN_CDN,
    }:
        score += 8
        assessment.reasons.append(f"{cfg.transport.upper()} transport behind a CDN")

    if cfg.port in CDN_PORTS:
        score += 6
        assessment.reasons.append(f"standard HTTPS port {cfg.port}")
    elif cfg.port in {80, 8080, 8880, 2052, 2082}:
        score -= 4
        assessment.reasons.append(f"non standard TLS port {cfg.port}")
    else:
        score -= 2

    if cfg.scheme in {"hysteria2", "tuic"}:
        score += 5
        assessment.reasons.append("QUIC/UDP based - resilient when TCP is throttled")

    if cfg.is_udp_native and entry_class in {CLASS_IRAN_HOST, CLASS_IRAN_CDN}:
        score += 4
        assessment.reasons.append("UDP path to an Iranian operator")

    assessment.score = max(0.0, min(100.0, score))
    return assessment


def apply_iran_probe(assessment: IranAssessment, probe: IranProbe) -> None:
    """Fold the result of an Iranian vantage point into the score."""
    if not probe.available:
        return
    if probe.reachable:
        bonus = 25.0 if probe.rtt_ms <= 120 else max(6.0, 25.0 - (probe.rtt_ms - 120) / 12.0)
        assessment.score = min(100.0, assessment.score + bonus)
        assessment.reasons.append(
            f"reachable from an Iranian probe ({probe.rtt_ms:.0f} ms, {probe.probes} probe(s))"
        )
    else:
        assessment.score = max(0.0, assessment.score - 42.0)
        assessment.reasons.append("not reachable from Iranian vantage points")


# ---------------------------------------------------------------------------
# Globalping based Iranian vantage points
# ---------------------------------------------------------------------------


class GlobalpingError(RuntimeError):
    pass


class IranVantage:
    """Measures reachability from probes located in Iran."""

    def __init__(self, timeout: float = 45.0, limit: int = 3, pause: float = 0.8):
        self.timeout = timeout
        self.limit = limit
        self.pause = pause
        self.available: bool | None = None
        self.message: str = ""
        self._api_key = ""

    # -- low level ---------------------------------------------------------

    def _request(self, url: str, payload: dict | None = None) -> dict:
        data = None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
        return json.loads(body) if body else {}

    def _measure(self, payload: dict) -> dict:
        created = self._request(GLOBALPING_API, payload)
        measurement_id = created.get("id")
        if not measurement_id:
            raise GlobalpingError(f"unexpected globalping response: {str(created)[:200]}")

        deadline = time.time() + self.timeout
        results: list[dict] = []
        status: dict = {}
        while time.time() < deadline:
            time.sleep(self.pause)
            status = self._request(f"{GLOBALPING_API}/{measurement_id}")
            state = str(status.get("status") or "")
            if state in {"finished", "failed", "in-progress"} and status.get("results") is not None:
                results = status.get("results") or []
                if state == "finished" or (results and state != "in-progress"):
                    break
        return {"id": measurement_id, "status": status.get("status"), "results": results}

    # -- public API --------------------------------------------------------

    def probe(self, host: str, port: int) -> IranProbe:
        """Measure whether ``host:port`` is reachable from Iran.

        A TCP ping is used on purpose: it opens the very port the client
        would use, so the result reflects what an Iranian user experiences.
        """
        result = IranProbe(host=host, port=port, source="globalping")
        payload = {
            "type": "ping",
            "target": host,
            "locations": [{"country": "IR"}],
            "limit": self.limit,
            "measurementOptions": {"protocol": "TCP", "port": port, "packets": 3},
        }
        try:
            measurement = self._measure(payload)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, GlobalpingError) as exc:
            result.detail = f"globalping error: {exc}"
            self.available = False
            self.message = result.detail
            return result

        probes = measurement.get("results") or []
        if not probes:
            result.available = False
            result.detail = "no Iranian probe was available"
            self.available = False
            self.message = result.detail
            return result

        result.available = True
        self.available = True

        rtt_values: list[float] = []
        reachable = False
        details: list[str] = []
        for entry in probes:
            probe_info = entry.get("probe") or {}
            measurement_result = entry.get("result") or {}
            city = probe_info.get("city") or probe_info.get("country") or "IR"
            status = str(measurement_result.get("status") or "")
            if status == "finished":
                reachable = True
                value = _extract_rtt(measurement_result)
                if value:
                    rtt_values.append(value)
                details.append(f"{city}: ok")
            else:
                details.append(f"{city}: {status or 'failed'}")

        result.probes = len(probes)
        result.reachable = reachable
        result.rtt_ms = sum(rtt_values) / len(rtt_values) if rtt_values else 0.0
        result.detail = "; ".join(details)
        if self.pause:
            time.sleep(self.pause)
        return result


def _extract_rtt(result: dict) -> float:
    """Read the round trip time out of a ping result."""
    timings = result.get("timings") or {}
    for key in ("avg", "total", "min"):
        value = timings.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    stats = result.get("stats") or {}
    for key in ("avg", "total", "min"):
        value = stats.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return _parse_rtt(str(result.get("rawOutput") or ""))


_RTT_PATTERN = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)


def _parse_rtt(raw: str) -> float:
    match = _RTT_PATTERN.search(raw or "")
    if not match:
        return 0.0
    try:
        return float(match.group(1))
    except ValueError:
        return 0.0
