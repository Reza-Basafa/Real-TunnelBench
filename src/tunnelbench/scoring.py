"""Composite scoring of the benchmark results.

The final score blends four independent axes:

``speed``      sustained download throughput of the tunnel,
``latency``    round trip time of a small request through the tunnel,
``iran``       how likely the configuration is to work well from Iran,
``stability``  jitter of the latency samples.

The weights are configurable so the ranking can be tuned for a different
target audience (for example pure throughput instead of Iran affinity).
"""

from __future__ import annotations

import math

from .models import ProbeResult

DEFAULT_WEIGHTS = {
    "speed": 0.50,
    "latency": 0.20,
    "iran": 0.22,
    "stability": 0.08,
}


def speed_score(mbps: float) -> float:
    if mbps <= 0:
        return 0.0
    return min(100.0, 100.0 * math.log10(1 + mbps) / math.log10(1 + 50.0))


def latency_score(latency_ms: float) -> float:
    if latency_ms <= 0:
        return 0.0
    if latency_ms <= 100:
        return 100.0
    return max(0.0, 100.0 * (1.0 - (latency_ms - 100.0) / 1900.0))


def stability_score(samples: list[float]) -> float:
    if len(samples) >= 2:
        average = sum(samples) / len(samples)
        deviation = sum(abs(value - average) for value in samples) / len(samples)
        jitter_ratio = deviation / average if average else 1.0
        return max(0.0, 100.0 * (1.0 - min(1.0, jitter_ratio * 2.0)))
    return 60.0


def apply_scores(result: ProbeResult, weights: dict[str, float] | None = None) -> None:
    """Compute the performance, Iran and final score of a single result."""
    active = dict(DEFAULT_WEIGHTS)
    if weights:
        active.update({key: float(value) for key, value in weights.items() if key in active})

    speed = speed_score(result.download_mbps)
    latency = latency_score(result.latency_ms)
    stability = stability_score(result.latency_samples or [])

    performance_weight = active["speed"] + active["latency"] + active["stability"]
    result.perf_score = (
        active["speed"] * speed + active["latency"] * latency + active["stability"] * stability
    ) / (performance_weight or 1.0)

    total_weight = sum(active.values()) or 1.0
    result.final_score = (
        active["speed"] * speed
        + active["latency"] * latency
        + active["iran"] * result.iran_score
        + active["stability"] * stability
    ) / total_weight
