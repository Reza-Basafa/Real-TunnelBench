"""Live measurement of the configurations through a local SOCKS inbound."""

from __future__ import annotations

import time
from dataclasses import dataclass

from .httpclient import HttpError, http_fetch, tcp_connect_ms
from .models import GeoInfo, ProbeResult, ProxyConfig

DEFAULT_LATENCY_URL = "http://cp.cloudflare.com/generate_204"
DEFAULT_LATENCY_FALLBACKS = (
    "https://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
)
DEFAULT_SPEED_URLS = (
    "https://speed.cloudflare.com/__down?bytes={bytes}",
    "https://proof.ovh.net/files/10Mb.dat",
    "http://speedtest.wdc01.softlayer.com/downloads/test10.zip",
    "http://speedtest.tele2.net/10MB.zip",
)
DEFAULT_EXIT_URLS = (
    # ipwho.is has no hard rate limit for the free tier and returns the
    # country, the ASN and the ISP of the calling address in one request.
    "https://ipwho.is/",
    "http://ip-api.com/json/?fields=status,message,query,country,countryCode,city,isp,as,asname,hosting,proxy",
    "http://api.ipify.org?format=json",
)

ERROR_CATEGORIES = {
    "entry-unreachable": "Entry server unreachable",
    "handshake-failed": "Proxy handshake failed",
    "timeout": "Timed out",
    "tls-error": "TLS negotiation failed",
    "dns-error": "DNS resolution failed",
    "http-error": "HTTP error",
    "no-speed": "No usable speed test endpoint",
    "unknown": "Unknown error",
}


@dataclass
class Endpoint:
    url: str
    timeout: float = 12.0


class Prober:
    """Measures latency, throughput and the exit address of a configuration."""

    def __init__(
        self,
        base_port: int = 20800,
        latency_url: str = "",
        latency_samples: int = 3,
        speed_bytes: int = 5_000_000,
        speed_url: str = "",
        exit_url: str = "",
        entry_timeout: float = 6.0,
        latency_timeout: float = 12.0,
        speed_timeout: float = 30.0,
    ):
        self.base_port = base_port
        self.latency_samples = max(1, latency_samples)
        self.speed_bytes = speed_bytes
        self.entry_timeout = entry_timeout
        self.latency_timeout = latency_timeout
        self.speed_timeout = speed_timeout

        self.latency_endpoints = self._latency_endpoints(latency_url)
        self.speed_endpoints = self._speed_endpoints(speed_url)
        self.exit_endpoints = (
            [Endpoint(exit_url)] if exit_url else [Endpoint(url) for url in DEFAULT_EXIT_URLS]
        )

    # -- endpoint handling -------------------------------------------------

    @staticmethod
    def _latency_endpoints(custom: str) -> list[Endpoint]:
        if custom:
            return [Endpoint(custom, timeout=12.0)]
        return [Endpoint(url, timeout=12.0) for url in DEFAULT_LATENCY_FALLBACKS]

    def _speed_endpoints(self, custom: str) -> list[Endpoint]:
        if custom:
            return [Endpoint(custom.format(bytes=self.speed_bytes) if "{bytes}" in custom else custom)]
        urls = [
            url.format(bytes=self.speed_bytes) if "{bytes}" in url else url
            for url in DEFAULT_SPEED_URLS
        ]
        return [Endpoint(url, timeout=self.speed_timeout) for url in urls]

    # -- measurement -------------------------------------------------------

    def test(self, cfg: ProxyConfig, index: int) -> ProbeResult:
        result = ProbeResult(index=index, config=cfg)
        started = time.perf_counter()
        proxy = ("127.0.0.1", self.base_port + index)

        # 1. is the entry server reachable at all?
        try:
            result.entry_tcp_ms = tcp_connect_ms(
                cfg.server, cfg.port, timeout=self.entry_timeout
            )
        except HttpError:
            result.entry_tcp_ms = 0.0

        # 2. latency samples through the tunnel
        samples: list[float] = []
        last_error = ""
        for endpoint in self.latency_endpoints:
            endpoint_samples: list[float] = []
            for _ in range(self.latency_samples):
                try:
                    response = http_fetch(
                        endpoint.url,
                        proxy=proxy,
                        timeout=self.latency_timeout,
                        max_bytes=4096,
                        read_body=False,
                    )
                except HttpError as exc:
                    last_error = str(exc)
                    break
                if response.status in {204, 200, 301, 302, 404}:
                    endpoint_samples.append(response.total_ms)
                else:
                    last_error = f"HTTP {response.status}"
                    break
            if endpoint_samples:
                samples = endpoint_samples
                break

        if not samples:
            result.alive = False
            result.error = _classify_error(last_error, result.entry_tcp_ms)
            result.duration_s = time.perf_counter() - started
            return result

        result.alive = True
        result.latency_samples = samples
        result.latency_ms = sum(samples) / len(samples)
        result.jitter_ms = (
            max(samples) - min(samples) if len(samples) > 1 else 0.0
        )
        result.ttfb_ms = result.latency_ms

        # 3. sustained download throughput
        speed_error = ""
        for endpoint in self.speed_endpoints:
            try:
                response = http_fetch(
                    endpoint.url,
                    proxy=proxy,
                    timeout=endpoint.timeout,
                    max_bytes=self.speed_bytes,
                )
            except HttpError as exc:
                speed_error = str(exc)
                continue
            if response.status != 200 or not response.body:
                speed_error = f"HTTP {response.status}"
                continue
            transfer_ms = max(1.0, response.total_ms - response.ttfb_ms)
            mbps = (len(response.body) * 8.0) / (transfer_ms / 1000.0) / 1_000_000.0
            result.download_mbps = mbps
            result.bytes_downloaded = len(response.body)
            result.speed_endpoint = endpoint.url
            break

        if result.download_mbps <= 0:
            result.error = "no-speed" if not speed_error else _classify_error(speed_error, result.entry_tcp_ms)

        # 4. exit address and its geolocation
        self._lookup_exit(result, proxy)

        result.duration_s = time.perf_counter() - started
        return result

    def _lookup_exit(self, result: ProbeResult, proxy: tuple[str, int]) -> None:
        for endpoint in self.exit_endpoints:
            try:
                response = http_fetch(
                    endpoint.url,
                    proxy=proxy,
                    timeout=12.0,
                    max_bytes=8192,
                )
            except HttpError:
                continue
            if response.status != 200:
                continue
            try:
                import json

                payload = json.loads(response.body.decode("utf-8", errors="replace"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            info = _parse_exit_payload(payload)
            if info is None:
                continue
            result.exit_ip = info.ip
            result.exit_geo = info
            return


def _parse_exit_payload(payload: dict) -> GeoInfo | None:
    """Read the different answer formats of the exit address providers."""
    if payload.get("success") is False:
        return None

    # ipwho.is
    if "ip" in payload and "country_code" in payload:
        connection = payload.get("connection") or {}
        asn = connection.get("asn")
        return GeoInfo(
            ip=str(payload.get("ip") or ""),
            country=str(payload.get("country") or ""),
            country_code=str(payload.get("country_code") or ""),
            city=str(payload.get("city") or ""),
            isp=str(connection.get("isp") or connection.get("org") or ""),
            asn=f"AS{asn}" if isinstance(asn, int) else str(asn or ""),
            as_name=str(connection.get("org") or ""),
            hosting=bool((payload.get("security") or {}).get("hosting")),
            proxy=bool((payload.get("security") or {}).get("proxy")),
            source="ipwho.is",
        )

    # ip-api.com
    if "query" in payload:
        as_field = str(payload.get("as") or "")
        asn, _, as_name = as_field.partition(" ")
        return GeoInfo(
            ip=str(payload.get("query") or ""),
            country=str(payload.get("country") or ""),
            country_code=str(payload.get("countryCode") or ""),
            city=str(payload.get("city") or ""),
            isp=str(payload.get("isp") or ""),
            asn=asn.upper(),
            as_name=as_name or str(payload.get("asname") or ""),
            hosting=bool(payload.get("hosting")),
            proxy=bool(payload.get("proxy")),
            source="ip-api.com",
        )

    # api.ipify.org
    if "ip" in payload:
        return GeoInfo(ip=str(payload.get("ip") or ""), source="ipify.org")

    return None


def _classify_error(message: str, entry_tcp_ms: float) -> str:
    text = (message or "").lower()
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "tls" in text or "ssl" in text or "certificate" in text:
        return "tls-error"
    if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text:
        return "dns-error"
    if "http " in text and text.strip().startswith("http"):
        return "http-error"
    if entry_tcp_ms <= 0 and text:
        return "entry-unreachable"
    if "closed" in text or "reset" in text or "refused" in text:
        return "handshake-failed"
    return "handshake-failed" if text else "unknown"
