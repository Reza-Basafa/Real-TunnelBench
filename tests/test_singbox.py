"""Tests for the sing-box configuration builder."""

from __future__ import annotations

import json
import subprocess

import pytest

from tunnelbench import uris
from tunnelbench.singbox import build_document, build_outbound

REALITY_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


def _config(uri: str):
    return uris.parse_uri(uri, 0)


def test_vless_reality_outbound():
    cfg = _config(
        "vless://uuid@host.example:443?encryption=none&security=reality"
        "&sni=www.microsoft.com&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=ab&type=ws&path=%2Fx&host=host.example"
    )
    outbound = build_outbound(cfg, "out-0")
    assert outbound["type"] == "vless"
    assert outbound["server"] == "host.example"
    assert outbound["server_port"] == 443
    assert outbound["tls"]["enabled"] is True
    assert outbound["tls"]["reality"] == {
        "enabled": True,
        "public_key": REALITY_KEY,
        "short_id": "ab",
    }
    assert outbound["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}
    assert outbound["transport"]["type"] == "ws"
    assert outbound["transport"]["headers"] == {"Host": "host.example"}


def test_xtls_vision_uses_packetaddr():
    cfg = _config("vless://uuid@1.1.1.1:443?security=tls&sni=x&flow=xtls-rprx-vision")
    assert build_outbound(cfg, "out")["packet_encoding"] == "packetaddr"


def test_vmess_outbound():
    cfg = _config("trojan://x@y:1")  # placeholder to keep the import used
    payload = {
        "v": "2",
        "ps": "n",
        "add": "1.2.3.4",
        "port": 80,
        "id": "uuid",
        "aid": 0,
        "net": "tcp",
        "tls": "",
    }
    import base64

    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    cfg = uris.parse_uri(f"vmess://{encoded}")
    outbound = build_outbound(cfg, "out")
    assert outbound["type"] == "vmess"
    assert outbound["alter_id"] == 0
    assert outbound["security"] == "auto"
    assert "tls" not in outbound


def test_document_binds_every_inbound_to_its_outbound():
    configs = [
        _config("trojan://a@one.example:443?sni=one.example"),
        _config("trojan://b@two.example:443?sni=two.example"),
    ]
    document = build_document(configs, base_port=20800)
    assert len(document["inbounds"]) == 2
    assert len(document["outbounds"]) == 2
    assert document["inbounds"][0]["listen_port"] == 20800
    assert document["inbounds"][1]["listen_port"] == 20801
    assert document["route"]["rules"][0] == {
        "inbound": ["in-0"],
        "action": "route",
        "outbound": "out-0",
    }
    assert document["route"]["default_domain_resolver"] == {"server": "local"}


@pytest.mark.parametrize(
    "uri",
    [
        "trojan://pw@one.example:443?sni=one.example",
        "trojan://pw@two.example:443?sni=two.example&type=grpc&serviceName=svc",
        "trojan://pw@three.example:443?sni=three.example&type=httpupgrade&path=/p",
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388",
        "socks://127.0.0.1:1080",
        "http://user:pass@proxy.example:8080",
    ],
)
def test_generated_documents_pass_the_core_check(uri, sing_box_binary, tmp_path):
    cfg = _config(uri)
    document = build_document([cfg])
    path = tmp_path / "config.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = subprocess.run(
        [sing_box_binary, "check", "-c", str(path)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
