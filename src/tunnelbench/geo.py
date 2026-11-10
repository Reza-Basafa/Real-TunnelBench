"""IP geolocation, ASN classification and Iran-oriented enrichment."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

from .models import GeoInfo

USER_AGENT = "Real-TunnelBench/2.0 (+https://github.com/Reza-Basafa/Real-TunnelBench)"

# --- classification helpers -------------------------------------------------

CLOUDFLARE_ASNS = {"AS13335"}

IRANIAN_ASNS = {
    "AS58224",   # ArvanCloud
    "AS199473",  # ArvanCloud (Iran) Cloud Network
    "AS58927",   # ParsPack
    "AS39093",   # Shabakeh Gostareh Ertebatat
    "AS131279",  # Dadeh Gostar
    "AS135006",  # Fanavari Ertebatat
    "AS442129",  # Iran Telecommunication Company
    "AS15755",  # Shahrashed Mobin Ertebatat
}

IRANIAN_KEYWORDS = (
    "arvan",
    "parspack",
    "pars network",
    "shabakeh",
    "shahid dedicated",
    "fanavari",
    "host.ir",
    "irancell",
    "mci ",
    "mobile communication iran",
    "afarantel",
    "pishgaman",
    "hamrah",
    "zamai",
    "parsit",
    "tadiran",
    "dorna",
    "netgaz",
    "gostaresh",
    "iranshahr",
    "tehran ",
    "iranian internet",
    "asiatech",
    "shabrnet",
)

CDN_KEYWORDS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "amazon",
    "google llc",
    "google cloud",
    "microsoft corporation",
    "bunny",
    "stackpath",
    "keycdn",
    "gcore",
    "edgecast",
    "cdn77",
    "arvancloud",
    "suqol",
)

HOSTING_KEYWORDS = (
    "hosting",
    "data center",
    "datacenter",
    "cloud",
    "vps",
    "server",
    "digitalocean",
    "hetzner",
    "ovh",
    "contabo",
    "linode",
    "vultr",
    "leaseweb",
    "m247",
    "choopa",
    "hostwinds",
)

RESIDENTIAL_KEYWORDS = (
    "broadband",
    "residential",
    "isp",
    "telecom",
    "communications",
    "internet service",
    "wireless",
    "mobile",
)

# Entry classes used by the Iran scoring stage.
CLASS_IRAN_HOST = "iran-host"
CLASS_IRAN_CDN = "iran-cdn"
CLASS_CLOUDFLARE = "cloudflare"
CLASS_GLOBAL_CDN = "global-cdn"
CLASS_DATACENTER = "datacenter"
CLASS_RESIDENTIAL = "residential"
CLASS_UNKNOWN = "unknown"

CLASS_LABELS = {
    CLASS_IRAN_HOST: "Hosted inside Iran",
    CLASS_IRAN_CDN: "Iranian CDN / operator",
    CLASS_CLOUDFLARE: "Cloudflare anycast",
    CLASS_GLOBAL_CDN: "Global CDN",
    CLASS_DATACENTER: "Datacenter / VPS",
    CLASS_RESIDENTIAL: "Residential / ISP",
    CLASS_UNKNOWN: "Unknown",
}


def _norm(value: str) -> str:
    return (value or "").strip().lower()


@dataclass
class _BatchRecord:
    ip: str
    status: str
    country: str
    country_code: str
    city: str
    isp: str
    asn: str
    as_name: str
    hosting: bool
    proxy: bool


def _record_from_ip_api(item: dict) -> _BatchRecord:
    as_field = str(item.get("as") or "")
    asn, _, as_name = as_field.partition(" ")
    return _BatchRecord(
        ip=str(item.get("query") or ""),
        status=str(item.get("status") or ""),
        country=str(item.get("country") or ""),
        country_code=str(item.get("countryCode") or ""),
        city=str(item.get("city") or ""),
        isp=str(item.get("isp") or ""),
        asn=asn.upper(),
        as_name=as_name or str(item.get("asname") or ""),
        hosting=bool(item.get("hosting")),
        proxy=bool(item.get("proxy")),
    )


def _record_from_ipwhois(item: dict) -> _BatchRecord:
    connection = item.get("connection") or {}
    asn = str(connection.get("asn") or "")
    return _BatchRecord(
        ip=str(item.get("ip") or ""),
        status="success",
        country=str(item.get("country") or ""),
        country_code=str(item.get("country_code") or ""),
        city=str(item.get("city") or ""),
        isp=str(connection.get("isp") or item.get("isp") or ""),
        asn=asn.upper(),
        as_name=str(connection.get("org") or ""),
        hosting=bool(item.get("hosting")),
        proxy=bool(item.get("proxy")),
    )


def resolve_host(host: str) -> list[str]:
    """Resolve a hostname into its IP addresses (best effort)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    seen: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    return seen


class GeoResolver:
    """Resolves IP addresses to geolocation information with caching."""

    def __init__(self, enabled: bool = True, timeout: float = 12.0):
        self.enabled = enabled
        self.timeout = timeout
        self._cache: dict[str, GeoInfo] = {}

    # -- public API --------------------------------------------------------

    def lookup(self, ip: str) -> GeoInfo:
        if not self.enabled:
            return GeoInfo(ip=ip, source="disabled")
        if ip in self._cache:
            return self._cache[ip]
        info = self._lookup_single(ip)
        self._cache[ip] = info
        return info

    def lookup_many(self, ips: list[str]) -> dict[str, GeoInfo]:
        pending = [ip for ip in dict.fromkeys(ips) if ip and ip not in self._cache]
        if self.enabled and pending:
            for chunk_start in range(0, len(pending), 100):
                chunk = pending[chunk_start : chunk_start + 100]
                self._cache.update(self._lookup_batch(chunk))
        return {ip: self.lookup(ip) for ip in ips}

    # -- providers ---------------------------------------------------------

    def _lookup_single(self, ip: str) -> GeoInfo:
        for provider in (self._lookup_ipwhois, self._lookup_ipinfo):
            try:
                info = provider(ip)
            except Exception:
                continue
            if info and info.source:
                return info
        return GeoInfo(ip=ip, source="unavailable")

    def _lookup_batch(self, ips: list[str]) -> dict[str, GeoInfo]:
        try:
            payload = json.dumps(list(ips)).encode("utf-8")
            request = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,message,query,country,countryCode,"
                "city,isp,org,as,asname,hosting,proxy",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                items = json.loads(response.read().decode("utf-8"))
            result: dict[str, GeoInfo] = {}
            for item in items:
                record = _record_from_ip_api(item)
                if not record.ip:
                    continue
                result[record.ip] = GeoInfo(
                    ip=record.ip,
                    country=record.country,
                    country_code=record.country_code,
                    city=record.city,
                    isp=record.isp,
                    asn=record.asn,
                    as_name=record.as_name,
                    hosting=record.hosting,
                    proxy=record.proxy,
                    source="ip-api.com",
                )
            if result:
                return result
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            pass

        result = {}
        for ip in ips:
            info = self._lookup_single(ip)
            if info.source != "unavailable":
                result[ip] = info
        return result

    def _lookup_ipwhois(self, ip: str) -> GeoInfo:
        request = urllib.request.Request(
            f"https://ipwho.is/{ip}", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            item = json.loads(response.read().decode("utf-8"))
        record = _record_from_ipwhois(item)
        if not record.ip:
            return GeoInfo(ip=ip, source="unavailable")
        return GeoInfo(
            ip=record.ip,
            country=record.country,
            country_code=record.country_code,
            city=record.city,
            isp=record.isp,
            asn=record.asn,
            as_name=record.as_name,
            hosting=record.hosting,
            proxy=record.proxy,
            source="ipwho.is",
        )

    def _lookup_ipinfo(self, ip: str) -> GeoInfo:
        request = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            item = json.loads(response.read().decode("utf-8"))
        if "ip" not in item:
            return GeoInfo(ip=ip, source="unavailable")
        org = str(item.get("org") or "")
        asn, _, as_name = org.partition(" ")
        return GeoInfo(
            ip=str(item.get("ip") or ip),
            country=str(item.get("country") or ""),
            country_code=str(item.get("country") or "").upper(),
            city=str(item.get("city") or ""),
            isp=str(item.get("org") or ""),
            asn=asn.upper(),
            as_name=as_name,
            hosting="hosting" in _norm(item.get("type") or ""),
            source="ipinfo.io",
        )

    # -- classification ----------------------------------------------------

    @staticmethod
    def classify(geo: GeoInfo) -> str:
        if not geo or not geo.source or geo.source == "unavailable":
            return CLASS_UNKNOWN

        haystack = " ".join(
            [_norm(geo.isp), _norm(geo.as_name), _norm(geo.country), _norm(geo.city)]
        )
        asn = (geo.asn or "").upper()

        if geo.country_code.upper() == "IR":
            if any(keyword in haystack for keyword in CDN_KEYWORDS):
                return CLASS_IRAN_CDN
            return CLASS_IRAN_HOST

        if asn in IRANIAN_ASNS or any(keyword in haystack for keyword in IRANIAN_KEYWORDS):
            return CLASS_IRAN_CDN

        if asn in CLOUDFLARE_ASNS or "cloudflare" in haystack:
            return CLASS_CLOUDFLARE

        if any(keyword in haystack for keyword in CDN_KEYWORDS):
            return CLASS_GLOBAL_CDN

        if geo.hosting or any(keyword in haystack for keyword in HOSTING_KEYWORDS):
            return CLASS_DATACENTER

        if any(keyword in haystack for keyword in RESIDENTIAL_KEYWORDS):
            return CLASS_RESIDENTIAL

        return CLASS_UNKNOWN


def classify(geo: GeoInfo) -> str:
    """Classify a geolocation record (see :class:`GeoResolver`)."""
    return GeoResolver.classify(geo)


def class_label(value: str) -> str:
    return CLASS_LABELS.get(value, value)
