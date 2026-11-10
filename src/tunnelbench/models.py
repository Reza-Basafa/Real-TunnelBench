"""Data structures shared by the whole pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ProxyConfig:
    """A single parsed proxy configuration."""

    index: int
    scheme: str
    raw: str
    name: str = ""
    server: str = ""
    port: int = 0

    # credentials
    uuid: str = ""
    password: str = ""
    method: str = ""

    # transport / TLS
    security: str = ""  # "", "tls", "reality", "none"
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    fingerprint: str = ""
    public_key: str = ""
    short_id: str = ""
    allow_insecure: bool = False
    transport: str = ""  # "", "ws", "grpc", "http", "httpupgrade", "quic"
    path: str = ""
    host: str = ""
    service_name: str = ""
    header_type: str = ""
    flow: str = ""
    packet_encoding: str = ""
    early_data: int = 0
    early_data_header: str = ""

    # hysteria2 / tuic specifics
    obfs: str = ""
    obfs_password: str = ""
    congestion_control: str = ""
    up_mbps: int = 0
    down_mbps: int = 0

    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identity of the configuration (ignores the display name)."""
        payload = "|".join(
            [
                self.scheme,
                self.server.lower(),
                str(self.port),
                self.uuid,
                self.password,
                self.method,
                self.security,
                self.sni,
                self.transport,
                self.path,
                self.host,
                self.service_name,
                self.public_key,
                self.short_id,
                self.flow,
                self.obfs,
                self.obfs_password,
            ]
        )
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]

    @property
    def endpoint(self) -> str:
        return f"{self.server}:{self.port}"

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        return f"{self.scheme}-{self.server}:{self.port}"

    @property
    def tls_enabled(self) -> bool:
        return self.security in {"tls", "reality"}

    @property
    def is_udp_native(self) -> bool:
        """Hysteria2 / TUIC run over QUIC, so they need UDP reachability."""
        return self.scheme in {"hysteria2", "hy2", "tuic"}

    def describe(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "scheme": self.scheme,
            "name": self.display_name,
            "server": self.server,
            "port": self.port,
            "security": self.security or "none",
            "transport": self.transport or "tcp",
            "sni": self.sni,
            "flow": self.flow,
            "key": self.key,
        }


# ---------------------------------------------------------------------------
# Probe results
# ---------------------------------------------------------------------------


@dataclass
class GeoInfo:
    """Geolocation / ASN information for an IP address."""

    ip: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""
    as_name: str = ""
    hosting: bool = False
    proxy: bool = False
    source: str = ""

    @property
    def is_iran(self) -> bool:
        return self.country_code.upper() == "IR"

    @property
    def is_cdn(self) -> bool:
        return self.asn.upper().startswith("AS13335") or "cloudflare" in self.as_name.lower()

    def summary(self) -> str:
        parts = [self.country_code or "??", self.asn or "?"]
        return " / ".join(parts)


@dataclass
class IranProbe:
    """Result of an Iranian vantage point measurement."""

    host: str = ""
    port: int = 0
    available: bool = False
    reachable: bool = False
    rtt_ms: float = 0.0
    probes: int = 0
    detail: str = ""
    source: str = ""


@dataclass
class ProbeResult:
    """Outcome of the live test of one configuration."""

    index: int
    config: ProxyConfig
    alive: bool = False
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    ttfb_ms: float = 0.0
    download_mbps: float = 0.0
    bytes_downloaded: int = 0
    entry_tcp_ms: float = 0.0
    exit_ip: str = ""
    exit_geo: GeoInfo = field(default_factory=GeoInfo)
    entry_geo: GeoInfo = field(default_factory=GeoInfo)
    entry_ips: list[str] = field(default_factory=list)
    iran_probe: IranProbe = field(default_factory=IranProbe)
    error: str = ""
    detail: str = ""
    relaxed: bool = False
    duration_s: float = 0.0
    speed_endpoint: str = ""
    latency_samples: list[float] = field(default_factory=list)

    # filled by the scoring stage
    perf_score: float = 0.0
    iran_score: float = 0.0
    final_score: float = 0.0
    iran_class: str = "unknown"
    iran_reasons: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.alive:
            return "alive"
        if self.error:
            return self.error
        return "unknown"


@dataclass
class BenchSettings:
    """Everything the pipeline can be tuned with."""

    source_url: str = ""
    output_dir: str = "output"
    max_configs: int = 400
    concurrency: int = 12
    timeout_minutes: int = 45
    min_download_mbps: float = 0.5
    max_latency_ms: float = 2000.0
    latency_samples: int = 3
    speed_test_bytes: int = 5_000_000
    speed_test_url: str = ""
    latency_url: str = ""
    exit_ip_url: str = ""
    iran_probe: str = "auto"
    iran_probe_limit: int = 25
    iran_probe_timeout: float = 45.0
    core_version: str = "1.14.4"
    core_sha256: str = ""
    core_path: str = ""
    geo_lookup: bool = True
    dry_run: bool = False
    include_failed: bool = False
    keep_all_tested: bool = False
    max_output: int = 0
    weights: dict[str, float] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)


@dataclass
class BenchReport:
    """Aggregated result of a full run."""

    settings: BenchSettings
    started_at: str = ""
    finished_at: str = ""
    duration_s: float = 0.0
    source_bytes: int = 0
    source_lines: int = 0
    source_encoded: bool = False
    parsed: int = 0
    rejected: int = 0
    duplicates: int = 0
    tested: int = 0
    alive: int = 0
    fast: int = 0
    results: list[ProbeResult] = field(default_factory=list)
    rejected_lines: list[str] = field(default_factory=list)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    transport_counts: dict[str, int] = field(default_factory=dict)
    error_counts: dict[str, int] = field(default_factory=dict)
    iran_class_counts: dict[str, int] = field(default_factory=dict)
    iran_probe_available: bool = False
    iran_probe_message: str = ""
    core_version: str = ""
    runner: str = ""
    best_mbps: float = 0.0
    median_latency_ms: float = 0.0
    selected: list[ProbeResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
