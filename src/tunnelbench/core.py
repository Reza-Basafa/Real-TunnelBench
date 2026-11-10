"""Provisioning and supervision of the sing-box core.

The core is the component that actually speaks the proxy protocols, so the
whole benchmark depends on it.  It is downloaded from the official GitHub
release (which is built with ``with_utls`` and therefore supports REALITY
fingerprinting), optionally verified against a pinned SHA-256 digest.
"""

from __future__ import annotations

import hashlib
import os
import re
import platform
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

RELEASE_URL = "https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}.tar.gz"
RELEASE_URL_GLIBC = "https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}-glibc.tar.gz"
PYPI_PACKAGE = "sing-box-bin"

USER_AGENT = "Real-TunnelBench/2.0"


class CoreError(RuntimeError):
    """Raised when the sing-box core cannot be provisioned or started."""


@dataclass
class CoreBinary:
    path: Path
    version: str
    source: str
    sha256: str = ""
    supports_utls: bool = False

    def describe(self) -> str:
        return f"sing-box {self.version} ({self.source})"


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    if machine in {"armv7l", "armv7"}:
        return "armv7"
    if machine in {"i386", "i686"}:
        return "386"
    raise CoreError(f"unsupported architecture {machine!r}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path, timeout: float = 180.0) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with destination.open("wb") as handle:
                shutil.copyfileobj(response, handle)
    except (urllib.error.URLError, OSError) as exc:
        raise CoreError(f"failed to download {url}: {exc}") from exc


def _binary_version(path: Path) -> str:
    try:
        output = subprocess.run(
            [str(path), "version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CoreError(f"cannot execute {path}: {exc}") from exc
    text = (output.stdout or "") + (output.stderr or "")
    for token in text.split():
        if token.startswith("1."):
            return token
    return "unknown"


def _supports_utls(path: Path) -> bool:
    try:
        output = subprocess.run(
            [str(path), "version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "with_utls" in (output.stdout or "") + (output.stderr or "")


def _extract_tarball(tarball: Path, target: Path) -> Path:
    with tarfile.open(tarball, "r:gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith("/sing-box")]
        if not members:
            members = [m for m in archive.getmembers() if m.isfile() and os.path.basename(m.name) == "sing-box"]
        if not members:
            raise CoreError("sing-box binary not found inside the release archive")
        member = members[0]
        member.name = "sing-box"
        archive.extract(member, path=target)
    extracted = target / "sing-box"
    extracted.chmod(0o755)
    return extracted


def _install_from_pypi(target: Path) -> Path:
    """Fallback: the ``sing-box-bin`` wheel ships prebuilt binaries."""
    try:
        import sing_box_bin  # type: ignore
    except ImportError as exc:
        raise CoreError(
            "the sing-box core could not be downloaded and the optional PyPI "
            f"package {PYPI_PACKAGE!r} is not installed"
        ) from exc

    package_dir = Path(sing_box_bin.__file__).parent
    candidates = sorted((package_dir / "bin").glob(f"sing-box-linux-{_arch()}*"))
    if not candidates:
        raise CoreError(f"no sing-box binary for linux-{_arch()} inside {PYPI_PACKAGE}")
    source = candidates[0]
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(0o755)
    return target


def provision_core(
    destination: Path,
    version: str = "1.14.4",
    expected_sha256: str = "",
    allow_pypi_fallback: bool = True,
) -> CoreBinary:
    """Make sure a usable sing-box binary exists and return its description."""
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and os.access(destination, os.X_OK):
        found = _binary_version(destination)
        if found != "unknown":
            return CoreBinary(
                path=destination,
                version=found,
                source="preinstalled",
                sha256=_sha256(destination),
                supports_utls=_supports_utls(destination),
            )

    url_candidates = [
        RELEASE_URL.format(version=version, arch=_arch()),
        RELEASE_URL_GLIBC.format(version=version, arch=_arch()),
    ]

    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="rtb-core-") as tmp:
        tmp_path = Path(tmp)
        tarball = tmp_path / "sing-box.tar.gz"
        for url in url_candidates:
            try:
                _download(url, tarball)
            except CoreError as exc:
                errors.append(str(exc))
                continue

            digest = _sha256(tarball)
            if expected_sha256 and digest.lower() != expected_sha256.lower():
                raise CoreError(
                    f"checksum mismatch for {url}: expected {expected_sha256}, got {digest}"
                )

            try:
                extracted = _extract_tarball(tarball, tmp_path / "extracted")
            except (CoreError, tarfile.TarError) as exc:
                errors.append(str(exc))
                continue

            shutil.copy2(extracted, destination)
            destination.chmod(0o755)
            return CoreBinary(
                path=destination,
                version=_binary_version(destination),
                source="github release",
                sha256=digest,
                supports_utls=_supports_utls(destination),
            )

    if allow_pypi_fallback:
        try:
            _install_from_pypi(destination)
        except CoreError as exc:
            errors.append(str(exc))
        else:
            return CoreBinary(
                path=destination,
                version=_binary_version(destination),
                source=f"pypi {PYPI_PACKAGE}",
                sha256=_sha256(destination),
                supports_utls=_supports_utls(destination),
            )

    raise CoreError("unable to provision the sing-box core: " + "; ".join(errors))


class CoreProcess:
    """A running sing-box instance."""

    def __init__(self, binary: Path, config_path: Path, log_path: Path):
        self.binary = binary
        self.config_path = config_path
        self.log_path = log_path
        self.process: subprocess.Popen[bytes] | None = None
        self._log_handle = None

    def start(self) -> None:
        self._log_handle = self.log_path.open("wb")
        self.process = subprocess.Popen(
            [str(self.binary), "run", "-c", str(self.config_path)],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )

    def wait_for_ports(self, ports: list[int], timeout: float = 20.0) -> None:
        deadline = time.time() + timeout
        pending = list(ports)
        while pending and time.time() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise CoreError(self.read_log() or "sing-box exited during start-up")
            still: list[int] = []
            for port in pending:
                if _port_open(port):
                    continue
                still.append(port)
            pending = still
            if pending:
                time.sleep(0.1)
        if pending:
            raise CoreError(
                "sing-box did not open the expected inbound ports: "
                + ", ".join(str(port) for port in pending[:10])
            )

    def read_log(self, limit: int = 4000) -> str:
        try:
            data = self.log_path.read_bytes()
        except OSError:
            return ""
        return data[-limit:].decode("utf-8", errors="replace")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def __enter__(self) -> "CoreProcess":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


_LOG_PATTERN = re.compile(r"outbound/[a-z_]+\[(out-\d+)\]:\s*(.+)")


def parse_log_details(text: str) -> dict[str, str]:
    """Map the outbound tags of the core log to their last error message.

    sing-box writes lines such as
    ``open connection to host:443 using outbound/vless[out-3]: tls: ...``
    which makes it possible to tell the user *why* a configuration failed.
    """
    details: dict[str, str] = {}
    for line in (text or "").splitlines():
        match = _LOG_PATTERN.search(line)
        if match:
            details[match.group(1)] = match.group(2).strip()
    return details


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_local_binary() -> str:
    """Return a sing-box binary found on ``PATH`` (used by the test-suite)."""
    return shutil.which("sing-box") or ""
