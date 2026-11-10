"""A tiny local network used by the test-suite.

It provides

* an HTTP server that serves a configuration list, a latency target, a
  download target and a fake ``ip-api`` answer,
* a SOCKS5 proxy that forwards to the HTTP server, so the real sing-box core
  can be exercised without touching the internet.
"""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import threading
from pathlib import Path


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    config_text: str = ""
    payload_size: int = 512 * 1024

    def log_message(self, *args) -> None:  # silence the server
        return

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/octet-stream") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = self.path.split("?", 1)[0]
        if path == "/configs.txt":
            self._send(200, self.config_text.encode("utf-8"), "text/plain")
        elif path == "/generate_204":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/speed":
            self._send(200, b"0" * self.payload_size)
        elif path == "/ip-api":
            payload = {
                "status": "success",
                "query": "203.0.113.7",
                "country": "Netherlands",
                "countryCode": "NL",
                "city": "Amsterdam",
                "isp": "Mock Transit",
                "as": "AS64496 Example ISP",
                "hosting": True,
                "proxy": False,
            }
            self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


class _ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _SocksHandler(socketserver.BaseRequestHandler):
    """A minimal but standards compliant SOCKS5 proxy (CONNECT only)."""

    def handle(self) -> None:
        client = self.request
        try:
            greeting = self._recv_exact(client, 2)
            if len(greeting) < 2 or greeting[0] != 5:
                return
            method_count = greeting[1]
            if method_count:
                self._recv_exact(client, method_count)
            client.sendall(b"\x05\x00")

            header = self._recv_exact(client, 4)
            if len(header) < 4 or header[1] != 1:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            atyp = header[3]
            if atyp == 1:
                host = socket.inet_ntoa(self._recv_exact(client, 4))
            elif atyp == 3:
                length = self._recv_exact(client, 1)[0]
                host = self._recv_exact(client, length).decode("utf-8")
            else:
                host = socket.inet_ntop(socket.AF_INET6, self._recv_exact(client, 16))
            port = int.from_bytes(self._recv_exact(client, 2), "big")

            upstream = socket.create_connection((host, port), timeout=10)
            client.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + port.to_bytes(2, "big"))

            self._relay(client, upstream)
        except OSError:
            return

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        buffer = b""
        while len(buffer) < size:
            chunk = sock.recv(size - len(buffer))
            if not chunk:
                return buffer
            buffer += chunk
        return buffer

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket) -> None:
        def copy(source: socket.socket, sink: socket.socket) -> None:
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threads = [
            threading.Thread(target=copy, args=(a, b), daemon=True),
            threading.Thread(target=copy, args=(b, a), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)


class _ThreadedSocks(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockNetwork:
    """Starts the HTTP and the SOCKS5 server on free ports."""

    def __init__(self, config_text: str = "", payload_size: int = 512 * 1024):
        handler = type("BoundHandler", (_Handler,), {"config_text": config_text, "payload_size": payload_size})
        self.http = _ThreadedHTTP(("127.0.0.1", 0), handler)
        self.socks = _ThreadedSocks(("127.0.0.1", 0), _SocksHandler)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.socks_thread = threading.Thread(target=self.socks.serve_forever, daemon=True)
        self.http_thread.start()
        self.socks_thread.start()

    @property
    def http_port(self) -> int:
        return self.http.server_address[1]

    @property
    def socks_port(self) -> int:
        return self.socks.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def config_text(self) -> str:
        return self.http.RequestHandlerClass.config_text  # type: ignore[attr-defined]

    @config_text.setter
    def config_text(self, value: str) -> None:
        self.http.RequestHandlerClass.config_text = value  # type: ignore[attr-defined]

    def stop(self) -> None:
        self.http.shutdown()
        self.socks.shutdown()
        self.http.server_close()
        self.socks.server_close()


def write_config_list(directory: Path, uris: list[str]) -> Path:
    path = Path(directory) / "configs.txt"
    path.write_text("\n".join(uris) + "\n", encoding="utf-8")
    return path
