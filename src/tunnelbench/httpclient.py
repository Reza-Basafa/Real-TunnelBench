"""A tiny, dependency free HTTP client with SOCKS5 support.

The benchmark needs very precise timings (time to first byte, sustained
throughput) and must be able to tunnel HTTP and HTTPS through a local SOCKS
inbound of sing-box.  ``requests`` cannot give us that granularity without
extra packages, so the client is implemented directly on top of ``socket``.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field

DEFAULT_USER_AGENT = "Real-TunnelBench/2.0 (+https://github.com/Reza-Basafa/Real-TunnelBench)"
MAX_HEADER_BYTES = 64 * 1024


class HttpError(Exception):
    """Raised for transport level failures."""


@dataclass
class HttpResponse:
    url: str
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    ttfb_ms: float = 0.0
    total_ms: float = 0.0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


# ---------------------------------------------------------------------------
# SOCKS5
# ---------------------------------------------------------------------------


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
) -> socket.socket:
    """Open a SOCKS5 tunnel to ``dest_host:dest_port``.

    The destination is always requested as a domain name so that DNS
    resolution happens at the exit node - exactly what a real client does and
    what makes the exit-IP lookup meaningful.
    """
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except OSError as exc:
        raise HttpError(f"socks connect failed: {exc}") from exc

    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting[0:1] != b"\x05":
            raise HttpError("invalid SOCKS version")
        if greeting[1:2] != b"\x00":
            raise HttpError("SOCKS5 authentication required")

        host_bytes = dest_host.encode("idna") if not _is_ip(dest_host) else dest_host.encode()
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes
        request += bytes([(dest_port >> 8) & 0xFF, dest_port & 0xFF])
        sock.sendall(request)

        header = _recv_exact(sock, 4)
        if header[1:2] != b"\x00":
            raise HttpError(f"SOCKS5 error {header[1]:02x}")
        atyp = header[3:4]
        if atyp == b"\x01":
            _recv_exact(sock, 4)
        elif atyp == b"\x03":
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        elif atyp == b"\x04":
            _recv_exact(sock, 16)
        else:
            raise HttpError("unknown SOCKS5 address type")
        _recv_exact(sock, 2)
        return sock
    except HttpError:
        sock.close()
        raise
    except (OSError, socket.timeout) as exc:
        sock.close()
        raise HttpError(f"socks handshake failed: {exc}") from exc


def _is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return ":" in value and all(c in "0123456789abcdefABCDEF:." for c in value)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise HttpError("connection closed unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


# ---------------------------------------------------------------------------
# direct TCP
# ---------------------------------------------------------------------------


def tcp_connect_ms(host: str, port: int, timeout: float = 5.0) -> float:
    """Return the TCP handshake time in milliseconds (raises on failure)."""
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise HttpError(str(exc)) from exc
    elapsed = (time.perf_counter() - start) * 1000.0
    sock.close()
    return elapsed


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _build_request(method: str, url: str, headers: dict[str, str]) -> tuple[bytes, str, int, bool]:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    secure = parsed.scheme == "https"
    port = parsed.port or (443 if secure else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    host_header = host if port in {80, 443} else f"{host}:{port}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
    lines.append(f"User-Agent: {headers.get('User-Agent', DEFAULT_USER_AGENT)}")
    lines.append("Accept: */*")
    lines.append("Accept-Encoding: identity")
    for key, value in headers.items():
        if key.lower() in {"user-agent", "accept", "accept-encoding", "host"}:
            continue
        lines.append(f"{key}: {value}")
    lines.append("Connection: close")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
    return request, host, port, secure


def http_fetch(
    url: str,
    proxy: tuple[str, int] | None = None,
    timeout: float = 15.0,
    max_bytes: int = 1024 * 1024,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    read_body: bool = True,
) -> HttpResponse:
    """Perform a single HTTP request and return the measured response."""
    request, host, port, secure = _build_request(method, url, headers or {})
    start = time.perf_counter()

    if proxy is not None:
        sock = socks5_connect(proxy[0], proxy[1], host, port, timeout=timeout)
    else:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise HttpError(f"connect failed: {exc}") from exc

    try:
        sock.settimeout(timeout)
        if secure:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            try:
                sock = context.wrap_socket(sock, server_hostname=host)
            except (ssl.SSLError, OSError) as exc:
                raise HttpError(f"tls handshake failed: {exc}") from exc

        sock.sendall(request)

        buffer = b""
        header_end = -1
        while header_end == -1:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
            header_end = buffer.find(b"\r\n\r\n")
            if len(buffer) > MAX_HEADER_BYTES:
                raise HttpError("response headers too large")
        if header_end == -1:
            raise HttpError("incomplete response headers")

        ttfb = (time.perf_counter() - start) * 1000.0
        head = buffer[:header_end].decode("latin-1", errors="replace")
        body_start = header_end + 4

        lines = head.split("\r\n")
        status_line = lines[0] if lines else ""
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""

        parsed_headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            parsed_headers[key.strip().lower()] = value.strip()

        body = buffer[body_start:]
        truncated = False
        if read_body:
            body, truncated = _read_body(sock, body, parsed_headers, max_bytes)
        else:
            truncated = True
            body = b""

        total = (time.perf_counter() - start) * 1000.0
        return HttpResponse(
            url=url,
            status=status,
            reason=reason,
            headers=parsed_headers,
            body=body,
            ttfb_ms=ttfb,
            total_ms=total,
            truncated=truncated,
        )
    except socket.timeout as exc:
        raise HttpError("timeout") from exc
    except ssl.SSLError as exc:
        raise HttpError(f"tls error: {exc}") from exc
    except OSError as exc:
        raise HttpError(str(exc)) from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _read_body(
    sock: socket.socket,
    initial: bytes,
    headers: dict[str, str],
    max_bytes: int,
) -> tuple[bytes, bool]:
    body = bytearray(initial)
    truncated = False

    if headers.get("transfer-encoding", "").lower() == "chunked":
        return _read_chunked(sock, body, max_bytes)

    length_text = headers.get("content-length")
    if length_text and length_text.isdigit():
        expected = int(length_text)
        while len(body) < min(expected, max_bytes):
            try:
                chunk = sock.recv(min(65536, max_bytes - len(body)))
            except socket.timeout:
                break
            if not chunk:
                break
            body.extend(chunk)
        if len(body) >= max_bytes:
            truncated = True
            body = body[:max_bytes]
        return bytes(body), truncated

    while len(body) < max_bytes:
        try:
            chunk = sock.recv(min(65536, max_bytes - len(body)))
        except socket.timeout:
            break
        if not chunk:
            break
        body.extend(chunk)
    if len(body) >= max_bytes:
        truncated = True
        body = body[:max_bytes]
    return bytes(body), truncated


def _read_chunked(sock: socket.socket, initial: bytes, max_bytes: int) -> tuple[bytes, bool]:
    buffer = bytearray(initial)
    body = bytearray()
    truncated = False

    while True:
        while b"\r\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                return bytes(body), truncated
            buffer.extend(chunk)
        line, _, rest = bytes(buffer).partition(b"\r\n")
        buffer = bytearray(rest)
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return bytes(body), truncated
        if size == 0:
            return bytes(body), truncated
        while len(buffer) < size + 2:
            chunk = sock.recv(65536)
            if not chunk:
                return bytes(body), truncated
            buffer.extend(chunk)
        body.extend(buffer[:size])
        del buffer[: size + 2]
        if len(body) >= max_bytes:
            truncated = True
            return bytes(body[:max_bytes]), truncated
