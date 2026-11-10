"""Tests for the scoring and the Iran affinity model."""

from __future__ import annotations

REALITY_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

from tunnelbench.geo import (
    CLASS_CLOUDFLARE,
    CLASS_DATACENTER,
    CLASS_IRAN_CDN,
    CLASS_IRAN_HOST,
    CLASS_UNKNOWN,
    GeoResolver,
)
from tunnelbench.iran import apply_iran_probe, assess_static
from tunnelbench.models import GeoInfo, IranProbe, ProbeResult
from tunnelbench.scoring import apply_scores, latency_score, speed_score


def test_speed_score_is_logarithmic():
    assert speed_score(0) == 0
    assert speed_score(50) == 100
    assert 0 < speed_score(5) < 50
    assert speed_score(500) == 100


def test_latency_score():
    assert latency_score(50) == 100
    assert latency_score(100) == 100
    assert latency_score(1000) < 60
    assert latency_score(2000) == 0
    assert latency_score(5000) == 0


def _result(**kwargs) -> ProbeResult:
    from tunnelbench.models import ProxyConfig

    config = ProxyConfig(index=0, scheme="vless", raw="vless://x@y:443", server="y", port=443)
    return ProbeResult(index=0, config=config, **kwargs)


def test_apply_scores_blends_the_axes():
    result = _result(
        alive=True,
        download_mbps=25.0,
        latency_ms=120.0,
        latency_samples=[118.0, 121.0, 119.0],
    )
    result.iran_score = 80.0
    apply_scores(result)
    assert 0 < result.perf_score <= 100
    assert 0 < result.final_score <= 100
    assert result.final_score > result.perf_score * 0.5


def test_iran_host_beats_unknown_host():
    from tunnelbench import uris

    cfg = uris.parse_uri("trojan://pw@host.example:443?sni=host.example")
    iran = assess_static(cfg, CLASS_IRAN_HOST)
    unknown = assess_static(cfg, CLASS_UNKNOWN)
    assert iran.score > unknown.score


def test_reality_scores_higher_than_plain_tcp():
    from tunnelbench import uris

    reality = uris.parse_uri(
        "vless://uuid@host.example:443?security=reality&sni=s&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&type=ws&path=/p"
    )
    plain = uris.parse_uri("trojan://pw@host.example:443?sni=host.example")
    assert assess_static(reality, CLASS_CLOUDFLARE).score > assess_static(plain, CLASS_CLOUDFLARE).score


def test_iran_probe_adjusts_the_score():
    from tunnelbench import uris

    cfg = uris.parse_uri("trojan://pw@host.example:443?sni=host.example")
    assessment = assess_static(cfg, CLASS_CLOUDFLARE)
    baseline = assessment.score

    apply_iran_probe(assessment, IranProbe(available=True, reachable=True, rtt_ms=60, probes=2))
    assert assessment.score > baseline

    apply_iran_probe(assessment, IranProbe(available=True, reachable=False))
    assert assessment.score < baseline


def test_geo_classification():
    resolver = GeoResolver(enabled=False)

    iran = GeoInfo(ip="1.1.1.1", country_code="IR", country="Iran", asn="AS58224", source="ip-api.com")
    assert resolver.classify(iran) == CLASS_IRAN_HOST

    arvan = GeoInfo(ip="2.2.2.2", country_code="IR", country="Iran", isp="ArvanCloud", asn="AS58224", source="ip-api.com")
    assert resolver.classify(arvan) == CLASS_IRAN_CDN

    cloudflare = GeoInfo(ip="3.3.3.3", country_code="US", asn="AS13335", as_name="CLOUDFLARENET", source="ip-api.com")
    assert resolver.classify(cloudflare) == CLASS_CLOUDFLARE

    hosting = GeoInfo(ip="4.4.4.4", country_code="DE", isp="Hetzner Online GmbH", asn="AS24940", hosting=True, source="ip-api.com")
    assert resolver.classify(hosting) == CLASS_DATACENTER

    unknown = GeoInfo(ip="5.5.5.5", source="unavailable")
    assert resolver.classify(unknown) == CLASS_UNKNOWN
