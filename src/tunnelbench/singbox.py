"""Translation of :class:`ProxyConfig` objects into sing-box outbounds.

The generated document is validated against the pinned sing-box release, so
every field below follows the 1.12+ schema (TLS as a container object, route
rules with explicit actions, ``default_domain_resolver`` and friends).
"""

from __future__ import annotations

from typing import Any

from .models import ProxyConfig

SING_BOX_SCHEMA = "sing-box-1.12+"

#: uTLS fingerprints understood by sing-box.
SUPPORTED_FINGERPRINTS = {
    "chrome",
    "chrome_psk",
    "chrome_psk_shuffle",
    "chrome_padding_psk_shuffle",
    "chrome_pq",
    "chrome_pq_psk",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
}

#: Fingerprints that only exist in Xray and are mapped to their equivalent.
FINGERPRINT_ALIASES = {
    "unsafe": "chrome",
    "randomize": "randomized",
    "safari_ios": "ios",
    "safari_ios2": "ios",
    "chrome_android": "android",
}

#: Flows that only exist in Xray.
FLOW_ALIASES = {
    "xtls-rprx-vision-udp443": "xtls-rprx-vision",
    "xtls-rprx-vision-udp443-quic": "xtls-rprx-vision",
}


def normalize_fingerprint(fingerprint: str, security: str = "") -> str:
    """Map a fingerprint onto the set the core accepts.

    REALITY clients always need uTLS, so an empty fingerprint falls back to
    ``chrome`` - the same default that v2rayN and Xray use.
    """
    value = (fingerprint or "").strip().lower()
    value = FINGERPRINT_ALIASES.get(value, value)
    if value and value not in SUPPORTED_FINGERPRINTS:
        value = "chrome"
    if not value and security == "reality":
        value = "chrome"
    return value


def normalize_flow(flow: str) -> str:
    value = (flow or "").strip().lower()
    value = FLOW_ALIASES.get(value, value)
    if value and value not in {"xtls-rprx-vision"}:
        value = ""
    return value


def normalize_short_id(short_id: str) -> str:
    """Keep only a valid REALITY short id (even length hex, max 16 chars)."""
    value = (short_id or "").strip().lower()
    if not value:
        return ""
    if len(value) % 2 != 0 or len(value) > 16:
        return ""
    try:
        bytes.fromhex(value)
    except ValueError:
        return ""
    return value


def _tls_block(cfg: ProxyConfig, force_insecure: bool = False) -> dict[str, Any]:
    tls: dict[str, Any] = {"enabled": True}

    server_name = cfg.sni or cfg.host or cfg.server
    if server_name:
        tls["server_name"] = server_name
    if cfg.allow_insecure or force_insecure:
        tls["insecure"] = True
    if cfg.alpn:
        tls["alpn"] = list(cfg.alpn)

    if cfg.security == "reality":
        reality: dict[str, Any] = {"enabled": True, "public_key": cfg.public_key}
        short_id = normalize_short_id(cfg.short_id)
        if short_id:
            reality["short_id"] = short_id
        tls["reality"] = reality

    fingerprint = normalize_fingerprint(cfg.fingerprint, cfg.security)
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    return tls


def _transport_block(cfg: ProxyConfig) -> dict[str, Any] | None:
    if not cfg.transport:
        return None

    if cfg.transport == "ws":
        transport: dict[str, Any] = {"type": "ws"}
        if cfg.path:
            transport["path"] = cfg.path
        if cfg.host:
            transport["headers"] = {"Host": cfg.host}
        if cfg.early_data:
            transport["max_early_data"] = cfg.early_data
        if cfg.early_data_header:
            transport["early_data_header_name"] = cfg.early_data_header
        return transport

    if cfg.transport == "grpc":
        transport = {"type": "grpc"}
        if cfg.service_name:
            transport["service_name"] = cfg.service_name
        return transport

    if cfg.transport == "http":
        transport = {"type": "http"}
        hosts = [item.strip() for item in cfg.host.split(",") if item.strip()]
        if hosts:
            transport["host"] = hosts
        if cfg.path:
            transport["path"] = cfg.path
        return transport

    if cfg.transport == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if cfg.host:
            transport["host"] = cfg.host
        if cfg.path:
            transport["path"] = cfg.path
        return transport

    if cfg.transport == "quic":
        return {"type": "quic"}

    return None


def build_outbound(cfg: ProxyConfig, tag: str, force_insecure: bool = False) -> dict[str, Any]:
    """Build a sing-box outbound object for a single configuration.

    ``force_insecure`` disables the certificate verification.  It is used for
    the second measurement pass: many public configurations rely on SNI
    fronting, where the certificate of the entry server does not match the
    requested server name.
    """
    outbound: dict[str, Any] = {
        "type": _OUTBOUND_TYPES.get(cfg.scheme, cfg.scheme),
        "tag": tag,
        "server": cfg.server,
        "server_port": cfg.port,
    }

    if cfg.scheme == "vless":
        outbound["uuid"] = cfg.uuid
        flow = normalize_flow(cfg.flow)
        if flow:
            outbound["flow"] = flow
        outbound["packet_encoding"] = "packetaddr" if normalize_flow(cfg.flow) else "xudp"

    elif cfg.scheme == "vmess":
        outbound["uuid"] = cfg.uuid
        outbound["security"] = cfg.method or "auto"
        outbound["alter_id"] = 0
        outbound["packet_encoding"] = "xudp"

    elif cfg.scheme == "trojan":
        outbound["password"] = cfg.password

    elif cfg.scheme == "ss":
        outbound["method"] = cfg.method
        outbound["password"] = cfg.password

    elif cfg.scheme == "hysteria2":
        outbound["password"] = cfg.password
        if cfg.up_mbps:
            outbound["up_mbps"] = cfg.up_mbps
        if cfg.down_mbps:
            outbound["down_mbps"] = cfg.down_mbps
        if cfg.obfs:
            outbound["obfs"] = {"type": "salamander", "password": cfg.obfs_password}

    elif cfg.scheme == "tuic":
        if cfg.uuid:
            outbound["uuid"] = cfg.uuid
        if cfg.password:
            outbound["password"] = cfg.password
        outbound["congestion_control"] = cfg.congestion_control or "bbr"

    elif cfg.scheme == "socks":
        outbound["version"] = "5"
        if cfg.uuid:
            outbound["username"] = cfg.uuid
        if cfg.password:
            outbound["password"] = cfg.password

    elif cfg.scheme == "http":
        if cfg.uuid:
            outbound["username"] = cfg.uuid
        if cfg.password:
            outbound["password"] = cfg.password

    if cfg.scheme in {"hysteria2", "tuic"}:
        outbound["tls"] = _tls_block(cfg, force_insecure)
    elif cfg.tls_enabled:
        outbound["tls"] = _tls_block(cfg, force_insecure)

    transport = _transport_block(cfg)
    if transport is not None:
        outbound["transport"] = transport

    return outbound


_OUTBOUND_TYPES = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
    "socks": "socks",
    "http": "http",
}


def inbound_tag(index: int) -> str:
    return f"in-{index}"


def outbound_tag(index: int) -> str:
    return f"out-{index}"


def build_document(
    configs: list[ProxyConfig],
    base_port: int = 20800,
    dns_tag: str = "local",
    force_insecure: bool = False,
) -> dict[str, Any]:
    """Build a complete sing-box document with one SOCKS inbound per config.

    ``force_insecure`` disables the certificate verification for every
    outbound of the document.
    """
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []

    for offset, cfg in enumerate(configs):
        port = base_port + offset
        inbounds.append(
            {
                "type": "socks",
                "tag": inbound_tag(offset),
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )
        outbounds.append(build_outbound(cfg, outbound_tag(offset), force_insecure))
        rules.append(
            {
                "inbound": [inbound_tag(offset)],
                "action": "route",
                "outbound": outbound_tag(offset),
            }
        )

    document: dict[str, Any] = {
        "log": {"level": "error", "timestamp": False},
        "dns": {
            "servers": [{"type": "local", "tag": dns_tag}],
            "final": dns_tag,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": outbound_tag(0) if outbounds else None,
            "default_domain_resolver": {"server": dns_tag},
        },
    }

    if document["route"]["final"] is None:
        del document["route"]["final"]

    return document


def port_for(index: int, base_port: int = 20800) -> int:
    return base_port + index
