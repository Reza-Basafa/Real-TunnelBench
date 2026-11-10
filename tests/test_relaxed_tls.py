"""Tests for the failure diagnosis and the relaxed TLS second pass.

Many public configurations use SNI fronting: the entry server presents a
certificate that belongs to a CDN and does not match the requested server
name.  A strict verification makes those configurations look dead, so they
are measured a second time without the certificate verification.
"""

from __future__ import annotations

import pytest

from tunnelbench.core import parse_log_details
from tunnelbench.models import ProxyConfig
from tunnelbench.pipeline import _is_certificate_error
from tunnelbench.singbox import build_document, build_outbound

SAMPLE_LOG = """
FATAL[0000] router: process route: open connection to 1.1.1.1:443 using outbound/vless[out-0]: tls: failed to verify certificate: x509: certificate is valid for default.ssl.fastly.net, not firefox.com
FATAL[0000] router: process route: open connection to 1.1.1.1:443 using outbound/vless[out-2]: unexpected HTTP response status: 403
FATAL[0000] router: process route: open connection to 1.1.1.1:443 using outbound/vless[out-3]: remote error: tls: handshake failure
"""


def test_parse_log_details_maps_every_outbound():
    details = parse_log_details(SAMPLE_LOG)
    assert set(details) == {"out-0", "out-2", "out-3"}
    assert "x509" in details["out-0"]
    assert "403" in details["out-2"]
    assert "handshake failure" in details["out-3"]


def test_parse_log_details_ignores_unrelated_lines():
    assert parse_log_details("INFO[0000] router: loaded rule_set") == {}
    assert parse_log_details("") == {}


def test_certificate_errors_are_detected():
    assert _is_certificate_error("tls: failed to verify certificate: x509: ...")
    assert _is_certificate_error("x509: certificate signed by unknown authority")
    assert not _is_certificate_error("unexpected HTTP response status: 403")
    assert not _is_certificate_error("")


def _config() -> ProxyConfig:
    return ProxyConfig(
        index=0,
        scheme="vless",
        server="example.com",
        port=443,
        uuid="00000000-0000-0000-0000-000000000000",
        security="tls",
        sni="example.com",
        raw="vless://00000000-0000-0000-0000-000000000000@example.com:443",
    )


def test_outbound_relaxes_the_certificate_on_demand():
    strict = build_outbound(_config(), "out-0")
    relaxed = build_outbound(_config(), "out-0", force_insecure=True)
    assert "insecure" not in strict.get("tls", {})
    assert relaxed["tls"]["insecure"] is True


def test_document_relaxes_every_outbound():
    configs = [_config(), _config()]
    document = build_document(configs, base_port=20800, force_insecure=True)
    outbounds = [o for o in document["outbounds"] if o.get("type") != "direct"]
    assert outbounds
    assert all(o["tls"]["insecure"] is True for o in outbounds)


@pytest.mark.parametrize(
    "message,expected",
    [
        (
            "tls: failed to verify certificate: x509: certificate is valid for a, not b",
            "TLS certificate does not match the requested server name",
        ),
        (
            "unexpected HTTP response status: 500",
            "the entry server rejected the request (HTTP status mismatch)",
        ),
        (
            "remote error: tls: handshake failure",
            "the entry server aborted the TLS handshake",
        ),
    ],
)
def test_report_groups_the_core_messages(message, expected):
    from tunnelbench.report import _normalise_detail

    assert _normalise_detail(message) == expected
