"""Downloading of the configuration list.

Supports plain text lists as well as base64 encoded subscriptions, which is
what most public providers publish.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import ipaddress
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field

MAX_BYTES = 10 * 1024 * 1024
TIMEOUT_SECONDS = 30
USER_AGENT = "Real-TunnelBench/2.0 (+https://github.com/Reza-Basafa/Real-TunnelBench)"


class FetchError(RuntimeError):
    """Raised when the source cannot be downloaded."""


@dataclass
class FetchResult:
    url: str
    text: str = ""
    raw_bytes: int = 0
    encoded: bool = False
    lines: list[str] = field(default_factory=list)
    final_url: str = ""


def is_public_http_url(url: str) -> bool:
    """Only public HTTP(S) destinations are allowed (SSRF protection).

    ``TUNNELBENCH_ALLOW_PRIVATE_URLS=1`` disables the check; it only exists so
    the test-suite can point the pipeline at a local server.
    """
    if os.environ.get("TUNNELBENCH_ALLOW_PRIVATE_URLS", "").strip().lower() in {"1", "true", "yes"}:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False

        host = parsed.hostname.lower()
        if host == "localhost" or host.endswith(".localhost"):
            return False

        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    host,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            }

        return bool(addresses) and all(address.is_global for address in addresses)
    except (ValueError, OSError, socket.gaierror):
        return False


def _decompress(payload: bytes, encoding: str) -> bytes:
    encoding = (encoding or "").lower()
    try:
        if encoding == "gzip":
            return gzip.decompress(payload)
        if encoding == "deflate":
            return zlib.decompress(payload, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return payload
    return payload


def normalize_source_url(url: str) -> str:
    """Turn a GitHub *blob* page into the URL of the raw file.

    ``https://github.com/owner/repo/blob/main/file.txt`` returns an HTML
    page; the benchmark needs the plain file, so the URL is rewritten to
    ``https://raw.githubusercontent.com/owner/repo/main/file.txt``.
    """
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if host not in {"github.com", "www.github.com"}:
        return url

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 4 and parts[2] in {"blob", "raw"}:
        owner, repo, _, ref = parts[0], parts[1], parts[2], parts[3]
        path = "/".join(parts[4:])
        if not path:
            return url
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"

    return url


def _looks_like_html(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def fetch(url: str, max_bytes: int = MAX_BYTES, timeout: float = TIMEOUT_SECONDS) -> FetchResult:
    """Download the configuration list and normalise it into lines."""
    url = normalize_source_url(url)

    if not is_public_http_url(url):
        raise FetchError("the source URL must point to a public HTTP(S) resource")

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            if not is_public_http_url(final_url):
                raise FetchError("the redirect destination is not a public URL")
            payload = response.read(max_bytes + 1)
            encoding = response.headers.get("Content-Encoding", "")
    except FetchError:
        raise
    except (urllib.error.URLError, OSError, socket.timeout) as exc:
        raise FetchError(f"download failed: {exc}") from exc

    if len(payload) > max_bytes:
        raise FetchError("the source file exceeds the size limit")

    payload = _decompress(payload, encoding)
    charset = "utf-8"
    try:
        text = payload.decode(charset)
    except UnicodeDecodeError:
        text = payload.decode("utf-8", errors="replace")

    if _looks_like_html(text):
        raise FetchError(
            "the URL returned an HTML page instead of a configuration list - "
            "use the raw file URL (for GitHub: .../blob/<branch>/<file> is "
            "converted automatically, but a rendered page is not usable)"
        )

    lines = [line for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    encoded = False

    stripped = "".join(line.strip() for line in lines)
    if stripped and "://" not in stripped:
        decoded = _try_base64(text)
        if decoded is not None:
            text = decoded
            lines = [line for line in text.replace("\r\n", "\n").split("\n")]
            encoded = True

    return FetchResult(
        url=url,
        text=text,
        raw_bytes=len(payload),
        encoded=encoded,
        lines=lines,
        final_url=final_url,
    )


def _try_base64(text: str) -> str | None:
    payload = "".join(text.split())
    if not payload or len(payload) < 16:
        return None
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        result = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "://" not in result:
        return None
    return result
