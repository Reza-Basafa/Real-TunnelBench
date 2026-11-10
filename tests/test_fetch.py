"""Tests for the source download."""

from __future__ import annotations

from tunnelbench.fetch import FetchError, _looks_like_html, fetch, normalize_source_url


def test_github_blob_urls_are_rewritten_to_raw_urls():
    assert (
        normalize_source_url(
            "https://github.com/barry-far/V2ray-Config/blob/main/Splitted-By-Protocol/vless.txt"
        )
        == "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt"
    )


def test_github_raw_urls_are_rewritten_to_raw_urls():
    assert (
        normalize_source_url("https://github.com/owner/repo/raw/main/list.txt")
        == "https://raw.githubusercontent.com/owner/repo/main/list.txt"
    )


def test_other_urls_are_untouched():
    for url in (
        "https://example.com/list.txt",
        "https://raw.githubusercontent.com/owner/repo/main/list.txt",
        "https://gist.githubusercontent.com/user/id/raw/list.txt",
    ):
        assert normalize_source_url(url) == url


def test_html_detection():
    assert _looks_like_html("<!DOCTYPE html><html><body>hi</body></html>")
    assert _looks_like_html("<html lang=\"en\">")
    assert not _looks_like_html("vless://uuid@host:443#node")


def test_private_urls_are_rejected():
    try:
        fetch("http://127.0.0.1/configs.txt")
    except FetchError as exc:
        assert "public" in str(exc)
    else:  # pragma: no cover - the sandbox flag must not be set here
        raise AssertionError("a private URL must be rejected")
