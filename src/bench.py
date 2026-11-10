#!/usr/bin/env python3
"""Entry point of the Real-TunnelBench benchmark.

Usage:
    python src/bench.py --url https://example.com/configs.txt --output-dir output
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tunnelbench.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
