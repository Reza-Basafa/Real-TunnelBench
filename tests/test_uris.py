"""Tests for the URI parsers."""

from __future__ import annotations

import base64
import json

import pytest

from tunnelbench import uris

REALITY_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


def test_vless_reality_websocket():
    cfg = uris.parse_uri(
        "vless://uuid-1234@cdn.example.com:443?encryption=none&security=reality"
        "&sni=www.microsoft.com&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=ab&type=ws&path=%2Fws"
        "&host=cdn.example.com#My%20Node"
    )
    assert cfg.scheme == "vless"
    assert cfg.server == "cdn.example.com"
    assert cfg.port == 443
    assert cfg.uuid == "uuid-1234"
    assert cfg.security == "reality"
    assert cfg.sni == "www.microsoft.com"
    assert cfg.fingerprint == "chrome"
    assert cfg.public_key == REALITY_KEY
    assert cfg.short_id == "ab"
    assert cfg.transport == "ws"
    assert cfg.path == "/ws"
    assert cfg.host == "cdn.example.com"
    assert cfg.name == "My Node"


def test_vmess_json_payload():
    payload = {
        "v": "2",
        "ps": "Node",
        "add": "1.2.3.4",
        "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "example.com",
        "path": "/path",
        "tls": "tls",
        "sni": "example.com",
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    cfg = uris.parse_uri(f"vmess://{encoded}")
    assert cfg.scheme == "vmess"
    assert cfg.server == "1.2.3.4"
    assert cfg.port == 443
    assert cfg.method == "auto"
    assert cfg.transport == "ws"
    assert cfg.security == "tls"
    assert cfg.path == "/path"


def test_trojan_grpc():
    cfg = uris.parse_uri(
        "trojan://secret@trojan.example.net:443?sni=trojan.example.net"
        "&type=grpc&serviceName=grpcsvc#Trojan"
    )
    assert cfg.scheme == "trojan"
    assert cfg.password == "secret"
    assert cfg.transport == "grpc"
    assert cfg.service_name == "grpcsvc"
    assert cfg.security == "tls"


def test_shadowsocks_sip002_and_legacy():
    payload = base64.b64encode(b"aes-256-gcm:secret").decode()
    cfg = uris.parse_uri(f"ss://{payload}@1.2.3.4:8388#SS")
    assert cfg.method == "aes-256-gcm"
    assert cfg.password == "secret"
    assert cfg.port == 8388

    legacy = base64.b64encode(b"rc4-md5:pw@5.6.7.8:1234").decode()
    cfg = uris.parse_uri(f"ss://{legacy}#Legacy")
    assert cfg.method == "rc4-md5"
    assert cfg.server == "5.6.7.8"
    assert cfg.port == 1234


def test_hysteria2_and_tuic():
    cfg = uris.parse_uri(
        "hysteria2://pass@h2.example.org:443?sni=h2.example.org&insecure=1"
        "&obfs=salamander&obfs-password=obfs#HY2"
    )
    assert cfg.scheme == "hysteria2"
    assert cfg.password == "pass"
    assert cfg.obfs == "salamander"
    assert cfg.obfs_password == "obfs"
    assert cfg.allow_insecure is True

    cfg = uris.parse_uri(
        "tuic://uuid-1:password@tuic.example.org:443?congestion_control=bbr&alpn=h3#TUIC"
    )
    assert cfg.scheme == "tuic"
    assert cfg.uuid == "uuid-1"
    assert cfg.password == "password"
    assert cfg.alpn == ["h3"]


def test_socks_with_base64_credentials():
    payload = base64.b64encode(b"user:pass").decode()
    cfg = uris.parse_uri(f"socks://{payload}@127.0.0.1:1080#SOCKS")
    assert cfg.scheme == "socks"
    assert cfg.uuid == "user"
    assert cfg.password == "pass"
    assert cfg.port == 1080


def test_ipv6_endpoint():
    cfg = uris.parse_uri("trojan://pw@[2001:db8::1]:443?sni=x.example#v6")
    assert cfg.server == "2001:db8::1"
    assert cfg.port == 443


@pytest.mark.parametrize(
    "line",
    [
        "",
        "# comment",
        "not a uri",
        "unknown://abc",
        "vless://",
        "trojan://@host",
        "vmess://not-base64!!",
    ],
)
def test_invalid_lines_are_rejected(line):
    with pytest.raises(uris.UriError):
        uris.parse_uri(line)


def test_parse_all_deduplicates():
    uri = "trojan://secret@trojan.example.net:443?sni=trojan.example.net#Trojan"
    other = "trojan://secret@trojan.example.net:443?sni=trojan.example.net#Trojan renamed"
    configs, rejected, duplicates = uris.parse_all([uri, other, "garbage"])
    assert len(configs) == 1
    assert duplicates == 1
    assert len(rejected) == 1
