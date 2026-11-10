"""Parsers for the proxy URI formats used by v2ray / sing-box clients.

Supported schemes: vless, vmess, trojan, ss, hysteria2 (hy2), tuic, socks,
socks5 and http/https proxies.  Every parser returns a :class:`ProxyConfig`
or raises :class:`UriError` with a human readable reason.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Any

from .models import ProxyConfig

SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "hy2",
    "tuic",
    "socks",
    "socks5",
    "http",
    "https",
}

TRANSPORTS = {"ws", "grpc", "http", "httpupgrade", "quic", "tcp", "http/2", "h2"}
TRANSPORT_ALIASES = {"raw": "tcp", "h2": "http", "http/2": "http", "tcp": "tcp", "none": "tcp"}
SUPPORTED_TRANSPORTS = ("ws", "grpc", "http", "httpupgrade", "quic", "tcp")
SECURITY = {"tls", "reality", "none", ""}


class UriError(ValueError):
    """Raised when a line cannot be turned into a usable configuration."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def b64decode(value: str) -> bytes:
    """Decode base64 payloads that may be url-safe and/or unpadded."""
    payload = value.strip().replace("\n", "").replace("\r", "")
    if not payload:
        raise UriError("empty base64 payload")
    payload = payload.replace("-", "+").replace("_", "/")
    payload += "=" * (-len(payload) % 4)
    try:
        return base64.b64decode(payload, validate=False)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive
        raise UriError(f"invalid base64 payload: {exc}") from exc


def b64decode_text(value: str) -> str:
    try:
        return b64decode(value).decode("utf-8", errors="replace")
    except UriError:
        return ""


def _first(params: dict[str, str], *names: str, default: str = "") -> str:
    for name in names:
        value = params.get(name)
        if value not in (None, ""):
            return value.strip()
    return default


def _flag(params: dict[str, str], *names: str, default: bool = False) -> bool:
    raw = _first(params, *names)
    if raw == "":
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _split_host_port(netloc: str, default_port: int = 0) -> tuple[str, int]:
    """Split ``host:port`` keeping IPv6 literals intact."""
    netloc = netloc.strip()
    if not netloc:
        raise UriError("missing host")
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise UriError("malformed IPv6 host")
        host = netloc[1:end]
        rest = netloc[end + 1 :]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return host, port
    if netloc.count(":") > 1:
        # bare IPv6 without brackets
        return netloc, default_port
    if ":" in netloc:
        host, _, port_text = netloc.rpartition(":")
        if port_text:
            try:
                return host, int(port_text)
            except ValueError as exc:
                raise UriError(f"invalid port {port_text!r}") from exc
        return host, default_port
    return netloc, default_port


def _parse_query(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for chunk in urllib.parse.parse_qsl(query, keep_blank_values=True):
        key, value = chunk
        params[key.lower()] = value
    return params


def _apply_transport(cfg: ProxyConfig, params: dict[str, str]) -> None:
    transport = _first(params, "type", "net", "network").lower()
    transport = TRANSPORT_ALIASES.get(transport, transport)
    if transport in {"", "tcp", "none"}:
        transport = ""
    if transport and transport not in TRANSPORTS:
        raise UriError(
            f"unsupported transport {transport!r} "
            f"(the core supports {', '.join(SUPPORTED_TRANSPORTS)})"
        )
    cfg.transport = transport

    cfg.path = _first(params, "path")
    cfg.host = _first(params, "host", "sni-host")
    cfg.service_name = _first(params, "servicename", "service_name")
    cfg.header_type = _first(params, "headertype", "header_type")
    if transport == "grpc" and not cfg.service_name:
        # some providers put the service name in the path
        cfg.service_name = cfg.path
    if transport == "http" and not cfg.path:
        cfg.path = "/"
    if transport == "ws" and not cfg.path:
        cfg.path = "/"

    early = _first(params, "ed", "earlydata")
    if early.isdigit():
        cfg.early_data = int(early)
    cfg.early_data_header = _first(params, "eh", "early_data_header_name")


def _valid_public_key(value: str) -> bool:
    """A REALITY public key is 32 bytes of base64url encoded data."""
    payload = value.strip().replace("-", "+").replace("_", "/")
    payload += "=" * (-len(payload) % 4)
    try:
        return len(base64.b64decode(payload, validate=False)) == 32
    except (binascii.Error, ValueError):
        return False


def _apply_tls(cfg: ProxyConfig, params: dict[str, str]) -> None:
    security = _first(params, "security").lower()
    if security not in SECURITY:
        security = ""
    cfg.security = security

    cfg.sni = _first(params, "sni", "peer", "servername")
    cfg.fingerprint = _first(params, "fp", "fingerprint")
    cfg.public_key = _first(params, "pbk", "publickey")
    cfg.short_id = _first(params, "sid", "shortid")
    cfg.allow_insecure = _flag(params, "allowinsecure", "insecure", "allow_insecure", "skip-cert-verify")

    alpn = _first(params, "alpn")
    if alpn:
        cfg.alpn = [item.strip() for item in alpn.split(",") if item.strip()]

    if cfg.security == "reality":
        if not cfg.public_key:
            raise UriError("reality configuration without a public key (pbk)")
        if not _valid_public_key(cfg.public_key):
            raise UriError("reality configuration with a malformed public key (pbk)")
        if not cfg.sni:
            # sing-box falls back to the server address when no SNI is given
            cfg.sni = _first(params, "host", default="")
    elif cfg.security == "" and (cfg.sni or cfg.public_key):
        # some links omit `security` but still carry TLS material
        cfg.security = "reality" if cfg.public_key else "tls"


# ---------------------------------------------------------------------------
# per scheme parsers
# ---------------------------------------------------------------------------


def _parse_vless(uri: str, parsed: urllib.parse.ParseResult, index: int) -> ProxyConfig:
    uuid = parsed.username or ""
    if not uuid:
        raise UriError("missing uuid")
    host, port = _split_host_port(parsed.netloc.rsplit("@", 1)[-1] if "@" in parsed.netloc else parsed.netloc)
    params = _parse_query(parsed.query)

    cfg = ProxyConfig(index=index, scheme="vless", raw=uri, name=urllib.parse.unquote(parsed.fragment or ""))
    cfg.uuid = uuid
    cfg.server = host
    cfg.port = port
    cfg.flow = _first(params, "flow")
    cfg.packet_encoding = _first(params, "packetencoding", "packet_encoding")
    _apply_transport(cfg, params)
    _apply_tls(cfg, params)
    if not cfg.port:
        raise UriError("missing port")
    return cfg


def _parse_vmess(uri: str, index: int) -> ProxyConfig:
    payload = uri[len("vmess://") :].split("#", 1)[0].strip()
    decoded = b64decode_text(payload)
    if not decoded.startswith("{"):
        raise UriError("vmess payload is not a base64 JSON object")
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise UriError(f"invalid vmess json: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise UriError("invalid vmess json payload")

    cfg = ProxyConfig(index=index, scheme="vmess", raw=uri)
    cfg.name = str(data.get("ps") or data.get("remark") or "").strip()
    cfg.server = str(data.get("add") or "").strip()
    try:
        cfg.port = int(data.get("port") or 0)
    except (TypeError, ValueError):
        cfg.port = 0
    cfg.uuid = str(data.get("id") or "").strip()
    cfg.method = str(data.get("scy") or data.get("security") or "auto").strip() or "auto"

    net = str(data.get("net") or "").lower()
    if net in {"h2", "http/2"}:
        net = "http"
    if net in {"", "tcp"}:
        net = ""
    if net and net not in TRANSPORTS:
        raise UriError(f"unsupported vmess transport {net!r}")
    cfg.transport = net

    host = str(data.get("host") or "").strip()
    cfg.host = host.split(",")[0].strip() if host else ""
    cfg.path = str(data.get("path") or "").strip()
    if cfg.transport == "grpc" and not cfg.service_name:
        cfg.service_name = cfg.path
    if cfg.transport == "ws" and not cfg.path:
        cfg.path = "/"

    tls_flag = str(data.get("tls") or "").lower()
    if tls_flag in {"tls", "reality", "xtls"}:
        cfg.security = "tls"
    if str(data.get("tls") or "").lower() == "reality":
        cfg.security = "reality"
    cfg.sni = str(data.get("sni") or "").strip()
    cfg.fingerprint = str(data.get("fp") or "").strip()
    cfg.allow_insecure = str(data.get("allowInsecure") or data.get("skip-cert-verify") or "").lower() in {"1", "true"}
    alpn = data.get("alpn")
    if alpn:
        cfg.alpn = [item.strip() for item in str(alpn).split(",") if item.strip()]
    if str(data.get("tls") or "").lower() == "reality" or data.get("pbk"):
        cfg.public_key = str(data.get("pbk") or "").strip()
        cfg.short_id = str(data.get("sid") or "").strip()
        if cfg.public_key:
            cfg.security = "reality"
    try:
        cfg.early_data = int(data.get("ed") or 0)
    except (TypeError, ValueError):
        cfg.early_data = 0
    cfg.early_data_header = str(data.get("eh") or "").strip()

    if not cfg.server:
        raise UriError("missing server")
    if not cfg.port:
        raise UriError("missing port")
    if not cfg.uuid:
        raise UriError("missing uuid")
    return cfg


def _parse_trojan(uri: str, parsed: urllib.parse.ParseResult, index: int) -> ProxyConfig:
    password = urllib.parse.unquote(parsed.username or "")
    if not password:
        raise UriError("missing password")
    netloc = parsed.netloc.rsplit("@", 1)[-1] if "@" in parsed.netloc else parsed.netloc
    host, port = _split_host_port(netloc)
    params = _parse_query(parsed.query)

    cfg = ProxyConfig(index=index, scheme="trojan", raw=uri, name=urllib.parse.unquote(parsed.fragment or ""))
    cfg.password = password
    cfg.server = host
    cfg.port = port
    _apply_transport(cfg, params)
    _apply_tls(cfg, params)
    if not cfg.security:
        cfg.security = "tls"
    if not cfg.port:
        raise UriError("missing port")
    return cfg


def _parse_shadowsocks(uri: str, parsed: urllib.parse.ParseResult, index: int) -> ProxyConfig:
    payload = parsed.netloc
    name = urllib.parse.unquote(parsed.fragment or "")

    method = ""
    password = ""
    host = ""
    port = 0

    if "@" in payload:
        userinfo, _, hostport = payload.rpartition("@")
        userinfo = urllib.parse.unquote(userinfo)
        host, port = _split_host_port(hostport)
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            decoded = b64decode_text(userinfo)
            if ":" in decoded:
                method, _, password = decoded.partition(":")
            else:
                method = decoded
    else:
        body = payload.split("#", 1)[0]
        decoded = b64decode_text(body)
        if "@" not in decoded:
            raise UriError("invalid shadowsocks payload")
        userinfo, _, hostport = decoded.rpartition("@")
        method, _, password = userinfo.partition(":")
        host, port = _split_host_port(hostport)

    method = method.strip()
    password = password.strip()
    if not method or not password:
        raise UriError("missing shadowsocks method or password")
    if not host:
        raise UriError("missing host")
    if not port:
        raise UriError("missing port")

    cfg = ProxyConfig(index=index, scheme="ss", raw=uri, name=name)
    cfg.method = method
    cfg.password = password
    cfg.server = host
    cfg.port = port
    return cfg


def _parse_hysteria2(uri: str, parsed: urllib.parse.ParseResult, index: int) -> ProxyConfig:
    auth = urllib.parse.unquote(parsed.username or "")
    netloc = parsed.netloc.rsplit("@", 1)[-1] if "@" in parsed.netloc else parsed.netloc
    host, port = _split_host_port(netloc)
    params = _parse_query(parsed.query)

    cfg = ProxyConfig(index=index, scheme="hysteria2", raw=uri, name=urllib.parse.unquote(parsed.fragment or ""))
    cfg.password = auth
    cfg.server = host
    cfg.port = port
    cfg.obfs = _first(params, "obfs").lower()
    cfg.obfs_password = _first(params, "obfs-password", "obfspassword", "obfs_password")
    cfg.up_mbps = int(_first(params, "uplink", "up", "up_mbps", default="0") or 0)
    cfg.down_mbps = int(_first(params, "downlink", "down", "down_mbps", default="0") or 0)
    cfg.sni = _first(params, "sni", "peer")
    cfg.alpn = [item.strip() for item in _first(params, "alpn").split(",") if item.strip()]
    cfg.allow_insecure = _flag(params, "insecure", "allowinsecure", "allow_insecure")
    cfg.security = "tls"

    if not cfg.server:
        raise UriError("missing host")
    if not cfg.port:
        raise UriError("missing port")
    if cfg.obfs and cfg.obfs != "salamander":
        raise UriError(f"unsupported hysteria2 obfs {cfg.obfs!r}")
    if cfg.obfs and not cfg.obfs_password:
        raise UriError("hysteria2 obfs without password")
    return cfg


def _parse_tuic(uri: str, parsed: urllib.parse.ParseResult, index: int) -> ProxyConfig:
    userinfo, _, hostport = parsed.netloc.rpartition("@")
    userinfo = urllib.parse.unquote(userinfo)
    host, port = _split_host_port(hostport)
    params = _parse_query(parsed.query)

    uuid, _, password = userinfo.partition(":")
    cfg = ProxyConfig(index=index, scheme="tuic", raw=uri, name=urllib.parse.unquote(parsed.fragment or ""))
    cfg.uuid = uuid.strip()
    cfg.password = password.strip()
    cfg.server = host
    cfg.port = port
    cfg.congestion_control = _first(params, "congestion_control", "congestion-control", default="bbr").lower()
    cfg.sni = _first(params, "sni", "peer")
    cfg.alpn = [item.strip() for item in _first(params, "alpn").split(",") if item.strip()]
    cfg.allow_insecure = _flag(params, "insecure", "allowinsecure", "allow_insecure")
    cfg.security = "tls"
    cfg.up_mbps = int(_first(params, "uplink", "up", default="0") or 0)
    cfg.down_mbps = int(_first(params, "downlink", "down", default="0") or 0)

    if not cfg.server:
        raise UriError("missing host")
    if not cfg.port:
        raise UriError("missing port")
    if not cfg.uuid and not cfg.password:
        raise UriError("missing tuic credentials")
    return cfg


def _parse_socks_or_http(uri: str, parsed: urllib.parse.ParseResult, index: int) -> ProxyConfig:
    scheme = parsed.scheme.lower()
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    netloc = parsed.netloc.rsplit("@", 1)[-1] if "@" in parsed.netloc else parsed.netloc
    host, port = _split_host_port(netloc)

    if username and not password:
        decoded = b64decode_text(username)
        if ":" in decoded:
            username, _, password = decoded.partition(":")

    cfg = ProxyConfig(index=index, scheme="socks" if scheme.startswith("socks") else "http", raw=uri)
    cfg.name = urllib.parse.unquote(parsed.fragment or "")
    cfg.uuid = username
    cfg.password = password
    cfg.server = host
    cfg.port = port
    if scheme == "https":
        cfg.security = "tls"
    if not cfg.server:
        raise UriError("missing host")
    if not cfg.port:
        raise UriError("missing port")
    return cfg


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def parse_uri(uri: str, index: int = 0) -> ProxyConfig:
    """Parse a single proxy URI into a :class:`ProxyConfig`."""
    candidate = uri.strip()
    if not candidate or candidate.startswith("#") or candidate.startswith("//"):
        raise UriError("empty or comment line")
    if "://" not in candidate:
        raise UriError("no scheme")

    scheme = candidate.split("://", 1)[0].lower()
    if scheme not in SCHEMES:
        raise UriError(f"unsupported scheme {scheme!r}")

    if scheme == "vmess":
        return _parse_vmess(candidate, index)

    parsed = urllib.parse.urlparse(candidate)
    if scheme == "vless":
        return _parse_vless(candidate, parsed, index)
    if scheme == "trojan":
        return _parse_trojan(candidate, parsed, index)
    if scheme == "ss":
        return _parse_shadowsocks(candidate, parsed, index)
    if scheme in {"hysteria2", "hy2"}:
        cfg = _parse_hysteria2(candidate, parsed, index)
        cfg.scheme = "hysteria2"
        return cfg
    if scheme == "tuic":
        return _parse_tuic(candidate, parsed, index)
    return _parse_socks_or_http(candidate, parsed, index)


def looks_like_config(line: str) -> bool:
    candidate = line.strip()
    if not candidate or candidate.startswith("#"):
        return False
    if "://" not in candidate:
        return False
    scheme = candidate.split("://", 1)[0].lower()
    return scheme in SCHEMES


def parse_all(lines: list[str]) -> tuple[list[ProxyConfig], list[str], int]:
    """Parse a list of lines.

    Returns ``(configs, rejected_lines, duplicate_count)``.
    """
    configs: list[ProxyConfig] = []
    rejected: list[str] = []
    duplicates = 0
    seen: set[str] = set()

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            cfg = parse_uri(line, index=len(configs))
        except UriError as exc:
            rejected.append(f"{line}  ({exc})")
            continue
        except Exception as exc:  # pragma: no cover - defensive
            rejected.append(f"{line}  ({type(exc).__name__}: {exc})")
            continue

        if cfg.key in seen:
            duplicates += 1
            continue
        seen.add(cfg.key)
        cfg.index = len(configs)
        configs.append(cfg)

    return configs, rejected, duplicates


_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip_address(host: str) -> bool:
    if _IPV4_RE.match(host):
        return True
    return ":" in host and all(part in "0123456789abcdefABCDEF:" for part in host)


def sanitize_for_display(value: Any) -> str:
    """Escape a value so it can be embedded in the PDF report."""
    text = str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
