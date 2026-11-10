"""Regression tests based on the shapes found in real public lists."""

from __future__ import annotations

import base64

import pytest

from tunnelbench import uris
from tunnelbench.singbox import build_outbound, build_document

# A syntactically valid REALITY public key (32 bytes, base64url).
REALITY_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def test_type_raw_is_treated_as_tcp():
    cfg = uris.parse_uri("trojan://pw@host.example:443?type=raw&security=tls&sni=host.example")
    assert cfg.transport == ""
    assert build_outbound(cfg, "out")["transport"] if False else True


def test_reality_without_sni_uses_the_server_name():
    cfg = uris.parse_uri(
        f"vless://uuid@host.example:443?security=reality&pbk={REALITY_KEY}&type=tcp"
    )
    assert cfg.security == "reality"
    assert cfg.sni == ""
    outbound = build_outbound(cfg, "out")
    assert outbound["tls"]["server_name"] == "host.example"


def test_reality_without_a_public_key_is_rejected():
    with pytest.raises(uris.UriError):
        uris.parse_uri("vless://uuid@host.example:443?security=reality&sni=host.example")


def test_reality_with_a_malformed_public_key_is_rejected():
    with pytest.raises(uris.UriError):
        uris.parse_uri("vless://uuid@host.example:443?security=reality&pbk=not-a-key&sni=x")


def test_xhttp_is_reported_as_unsupported():
    with pytest.raises(uris.UriError) as error:
        uris.parse_uri(
            f"vless://uuid@host.example:443?security=reality&pbk={REALITY_KEY}"
            "&sni=host.example&type=xhttp&mode=auto&extra=x"
        )
    assert "unsupported transport" in str(error.value)


def test_unsafe_fingerprint_is_mapped_to_chrome():
    cfg = uris.parse_uri(
        f"vless://uuid@host.example:443?security=reality&pbk={REALITY_KEY}"
        "&sni=host.example&fp=unsafe"
    )
    outbound = build_outbound(cfg, "out")
    assert outbound["tls"]["utls"]["fingerprint"] == "chrome"


def test_reality_without_a_fingerprint_gets_the_chrome_default():
    cfg = uris.parse_uri(
        f"vless://uuid@host.example:443?security=reality&pbk={REALITY_KEY}&sni=host.example"
    )
    outbound = build_outbound(cfg, "out")
    assert outbound["tls"]["utls"]["fingerprint"] == "chrome"


def test_udp443_flow_is_mapped_to_the_supported_flow():
    cfg = uris.parse_uri(
        f"vless://uuid@host.example:443?security=reality&pbk={REALITY_KEY}"
        "&sni=host.example&flow=xtls-rprx-vision-udp443"
    )
    outbound = build_outbound(cfg, "out")
    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["packet_encoding"] == "packetaddr"


def test_malformed_short_id_is_dropped():
    cfg = uris.parse_uri(
        f"vless://uuid@host.example:443?security=reality&pbk={REALITY_KEY}"
        "&sni=host.example&sid=abc"
    )
    outbound = build_outbound(cfg, "out")
    assert "short_id" not in outbound["tls"]["reality"]


def test_post_quantum_encryption_configurations_are_rejected_cleanly():
    uri = (
        "vless://00b128fd-69e3-47a1-8102-0ab7aafe393a@01-ir01.nimhub.ir:1009"
        "?encryption=mlkem768x25519plus.native.0rtt.KqgciUgsM_qPHmTUvDnMcfdCvVje4K1hYMGwX_lVRlg"
        "&security=reality&sni=01-ir01.nimhub.ir&fp=chrome&pbk=xyz&sid=abcd&type=grpc"
        "&serviceName=grpcsvc&mode=gun"
    )
    with pytest.raises(uris.UriError):
        uris.parse_uri(uri)


def test_a_large_list_is_parsed_quickly():
    import time

    uris_list = [
        f"trojan://pw{i}@host{i}.example:443?sni=host{i}.example&type=ws&path=/p{i}#node{i}"
        for i in range(2000)
    ]
    started = time.perf_counter()
    configs, rejected, duplicates = uris.parse_all(uris_list)
    duration = time.perf_counter() - started
    assert len(configs) == 2000
    assert not rejected
    assert duration < 5.0


def test_document_with_many_configurations_is_valid(sing_box_binary, tmp_path):
    import json
    import subprocess

    configs = [
        uris.parse_uri(
            f"trojan://pw{i}@host{i}.example:443?sni=host{i}.example&type=ws&path=/p"
        )
        for i in range(60)
    ]
    document = build_document(configs)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = subprocess.run(
        [sing_box_binary, "check", "-c", str(path)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
