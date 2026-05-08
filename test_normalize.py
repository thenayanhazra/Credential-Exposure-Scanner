"""Tests for input normalization."""
from __future__ import annotations

import pytest

from credscan.models import TargetKind
from credscan.normalize import NormalizeError, normalize


class TestEmailNormalization:
    def test_plain_email(self):
        t = normalize("user@example.com")
        assert t.kind == TargetKind.EMAIL
        assert t.value == "user@example.com"
        assert t.domain == "example.com"

    def test_uppercase_lowercased(self):
        t = normalize("USER@Example.COM")
        assert t.value == "user@example.com"
        assert t.domain == "example.com"

    def test_plus_tag_stripped(self):
        t = normalize("user+filter@example.com")
        assert t.value == "user@example.com"

    def test_leading_trailing_whitespace(self):
        t = normalize("   user@example.com  ")
        assert t.value == "user@example.com"

    def test_plus_only_local_part_rejected(self):
        with pytest.raises(NormalizeError):
            normalize("+tag@example.com")

    def test_subdomain_email(self):
        t = normalize("dev@mail.corp.example.com")
        assert t.domain == "mail.corp.example.com"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "@example.com",
            "user@",
            "user@@example.com",
            "user@localhost",  # no TLD
            "user@example",    # no TLD
            "not-an-email",
        ],
    )
    def test_invalid_emails(self, bad):
        with pytest.raises(NormalizeError):
            normalize(bad)


class TestDomainNormalization:
    def test_plain_domain(self):
        t = normalize("example.com")
        assert t.kind == TargetKind.DOMAIN
        assert t.value == "example.com"
        assert t.domain == "example.com"

    def test_uppercase_lowercased(self):
        t = normalize("EXAMPLE.COM")
        assert t.value == "example.com"

    def test_url_stripped_to_domain(self):
        assert normalize("https://example.com/some/path").value == "example.com"
        assert normalize("http://example.com").value == "example.com"
        assert normalize("example.com:8080").value == "example.com"
        assert normalize("https://example.com:443/a?b=c").value == "example.com"

    def test_non_http_scheme_rejected(self):
        with pytest.raises(NormalizeError):
            normalize("ftp://example.com/file.txt")

    def test_trailing_dot_stripped(self):
        assert normalize("example.com.").value == "example.com"

    def test_subdomain(self):
        t = normalize("api.corp.example.com")
        assert t.value == "api.corp.example.com"
        assert t.domain == "api.corp.example.com"

    def test_hyphenated_domain(self):
        assert normalize("my-company.co.uk").value == "my-company.co.uk"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "localhost",
            "192.168.1.1",  # numeric-only TLD
            "-leading.com",
            "trailing-.com",
            "no_underscores.com",
            ".example.com",
            "example.",
            "a" * 300 + ".com",
        ],
    )
    def test_invalid_domains(self, bad):
        with pytest.raises(NormalizeError):
            normalize(bad)
