"""Static URL validation, including SSRF-relevant rejections."""

from __future__ import annotations

import pytest

from jussiai_scanner.config import Settings
from jussiai_scanner.security.errors import TargetValidationError
from jussiai_scanner.security.url_validation import validate_target_url
from tests.conftest import build_settings


@pytest.fixture
def settings() -> Settings:
    return build_settings()


def test_bare_hostname_defaults_to_https(settings: Settings) -> None:
    target = validate_target_url("example.com", settings)
    assert target.url == "https://example.com/"
    assert target.scheme == "https"
    assert target.port == 443
    assert not target.is_ip_literal


def test_path_and_query_are_preserved(settings: Settings) -> None:
    target = validate_target_url("https://example.com/a/b?x=1#frag", settings)
    assert target.url == "https://example.com/a/b?x=1"


def test_hostname_is_lowercased_and_trailing_dot_removed(settings: Settings) -> None:
    assert validate_target_url("https://EXAMPLE.COM./", settings).host == "example.com"


def test_internationalized_domain_is_idna_encoded(settings: Settings) -> None:
    assert validate_target_url("https://bücher.de/", settings).host == "xn--bcher-kva.de"


def test_public_ip_literal_is_accepted(settings: Settings) -> None:
    target = validate_target_url("http://1.1.1.1/", settings)
    assert target.is_ip_literal
    assert target.host == "1.1.1.1"


def test_public_ipv6_literal_keeps_brackets_in_url(settings: Settings) -> None:
    target = validate_target_url("https://[2606:4700:4700::1111]/", settings)
    assert target.url == "https://[2606:4700:4700::1111]/"
    assert target.host == "2606:4700:4700::1111"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "not a url",
        "https://",
        "https:///path",
        "http://exa mple.com",
        "https://example.com/\r\nHost: evil.test",
        "https://exam\rple.com",
        "https://example.com:notaport/",
        "https://.com/",
        "https://-bad.example/",
        "https://example..com/",
    ],
)
def test_malformed_urls_are_rejected(url: str, settings: Settings) -> None:
    with pytest.raises(TargetValidationError):
        validate_target_url(url, settings)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/",
        "gopher://example.com/",
        "javascript:alert(1)",
        "data:text/html,<h1>x</h1>",
        "dict://example.com:11211/",
    ],
)
def test_non_http_schemes_are_rejected(url: str, settings: Settings) -> None:
    with pytest.raises(TargetValidationError, match="only http and https"):
        validate_target_url(url, settings)


def test_embedded_credentials_are_rejected(settings: Settings) -> None:
    with pytest.raises(TargetValidationError, match="credentials"):
        validate_target_url("https://user:pass@example.com/", settings)


def test_credentials_cannot_mask_an_internal_host(settings: Settings) -> None:
    """``https://example.com@127.0.0.1/`` actually targets 127.0.0.1."""
    with pytest.raises(TargetValidationError):
        validate_target_url("https://example.com@127.0.0.1/", settings)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://localhost:80/",
        "http://LOCALHOST/",
        "http://localhost.localdomain/",
        "http://intranet/",
        "http://db.internal/",
        "http://printer.local/",
        "http://wiki.corp/",
        "http://metadata.google.internal/",
        "http://foo.onion/",
    ],
)
def test_internal_hostnames_are_rejected(url: str, settings: Settings) -> None:
    with pytest.raises(TargetValidationError):
        validate_target_url(url, settings)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "http://192.168.0.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fd00:ec2::254]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[2002:7f00:1::]/",
        "http://0.0.0.0/",
        "http://100.100.100.200/",
    ],
)
def test_internal_ip_literals_are_rejected(url: str, settings: Settings) -> None:
    with pytest.raises(TargetValidationError):
        validate_target_url(url, settings)


def test_disallowed_port_is_rejected(settings: Settings) -> None:
    with pytest.raises(TargetValidationError, match="port 8080 is not allowed"):
        validate_target_url("http://example.com:8080/", settings)


def test_allowed_ports_are_configurable() -> None:
    permissive = build_settings(allowed_ports=frozenset({80, 443, 8080}))
    target = validate_target_url("http://example.com:8080/", permissive)
    assert target.url == "http://example.com:8080/"
    assert target.port == 8080


def test_overlong_url_is_rejected(settings: Settings) -> None:
    with pytest.raises(TargetValidationError, match="too long"):
        validate_target_url("https://example.com/" + "a" * settings.max_url_length, settings)


def test_numeric_tld_is_rejected(settings: Settings) -> None:
    """Guards against decimal/octal IP forms that survive hostname parsing."""
    with pytest.raises(TargetValidationError):
        validate_target_url("http://2130706433/", settings)
