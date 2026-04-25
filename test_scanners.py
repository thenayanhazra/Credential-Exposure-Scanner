"""Tests for scanner implementations with mocked HTTP."""
from __future__ import annotations

import httpx
import respx

from credscan.models import Severity, Target, TargetKind
from credscan.scanners.crtsh import CrtShScanner
from credscan.scanners.exact_email_search import ExactEmailSearchScanner
from credscan.scanners.github_search import GitHubSearchScanner
from credscan.scanners.hibp import HIBPScanner
from credscan.scanners.lead_fetch import LeadFetchScanner


def _domain(v: str = "example.com") -> Target:
    return Target(kind=TargetKind.DOMAIN, value=v, domain=v)


def _email(v: str = "user@example.com") -> Target:
    return Target(kind=TargetKind.EMAIL, value=v, domain=v.split("@", 1)[1])


async def _collect(scanner, target):
    return [f async for f in scanner.scan(target)]


class TestCrtShScanner:
    def test_supports_domain_only(self):
        s = CrtShScanner()
        assert s.supports(_domain()) is True
        assert s.supports(_email()) is False

    @respx.mock
    async def test_parses_subdomains(self):
        payload = [
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "other.com"},  # should be filtered
        ]
        respx.get("https://crt.sh/").mock(
            return_value=httpx.Response(200, json=payload)
        )
        findings = await _collect(CrtShScanner(), _domain())
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "crtsh"
        assert f.severity == Severity.INFO
        subs = f.raw["subdomains"]
        assert "api.example.com" in subs
        assert "www.example.com" in subs
        assert "mail.example.com" in subs
        assert "example.com" in subs  # from wildcard entry
        assert "other.com" not in subs

    @respx.mock
    async def test_empty_response_yields_nothing(self):
        respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
        assert await _collect(CrtShScanner(), _domain()) == []

    @respx.mock
    async def test_http_error_yields_nothing(self):
        respx.get("https://crt.sh/").mock(return_value=httpx.Response(500))
        assert await _collect(CrtShScanner(), _domain()) == []

    @respx.mock
    async def test_invalid_json_yields_nothing(self):
        respx.get("https://crt.sh/").mock(
            return_value=httpx.Response(200, text="<html>not json</html>")
        )
        assert await _collect(CrtShScanner(), _domain()) == []


class TestGitHubSearchScanner:
    def test_disabled_without_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        assert GitHubSearchScanner().enabled() is False

    def test_enabled_with_env_token(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "xxx")
        assert GitHubSearchScanner().enabled() is True

    def test_enabled_with_config_token(self):
        assert GitHubSearchScanner({"token": "xxx"}).enabled() is True

    @respx.mock
    async def test_finds_aws_key_with_domain_in_context(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "html_url": "https://github.com/acme/app/blob/main/config.py",
                            "path": "config.py",
                            "repository": {"full_name": "acme/app"},
                        }
                    ]
                },
            )
        )
        raw_content = (
            "# acme deployment config for example.com\n"
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
            "# endpoint: https://api.example.com\n"
        )
        respx.get("https://raw.githubusercontent.com/acme/app/HEAD/config.py").mock(
            return_value=httpx.Response(200, text=raw_content)
        )

        scanner = GitHubSearchScanner({"token": "test"})
        findings = await _collect(scanner, _domain())
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == "exposed_aws_access_key"
        assert f.severity == Severity.CRITICAL
        assert "acme/app" in f.title

    @respx.mock
    async def test_ignores_match_when_domain_not_in_context(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "html_url": "https://github.com/x/y/blob/main/f",
                            "path": "f",
                            "repository": {"full_name": "x/y"},
                        }
                    ]
                },
            )
        )
        # An AWS key, but example.com only appears far away at the end
        content = (
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
            + ("padding line\n" * 200)
            + "# example.com appears only here at the bottom\n"
        )
        respx.get("https://raw.githubusercontent.com/x/y/HEAD/f").mock(
            return_value=httpx.Response(200, text=content)
        )
        findings = await _collect(GitHubSearchScanner({"token": "t"}), _domain())
        assert findings == []

    @respx.mock
    async def test_no_search_results(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        findings = await _collect(GitHubSearchScanner({"token": "t"}), _domain())
        assert findings == []


class TestHIBPScanner:
    def test_disabled_without_key(self):
        assert HIBPScanner().enabled() is False

    def test_enabled_with_key(self):
        assert HIBPScanner({"api_key": "x"}).enabled() is True

    def test_supports_email_only(self):
        s = HIBPScanner({"api_key": "x"})
        assert s.supports(_email()) is True
        assert s.supports(_domain()) is False

    @respx.mock
    async def test_parses_breaches(self):
        respx.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com"
        ).mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"Name": "SomeSite", "DataClasses": ["Emails", "Passwords"]},
                    {"Name": "OtherSite", "DataClasses": ["Emails"]},
                ],
            )
        )
        findings = await _collect(HIBPScanner({"api_key": "k"}), _email())
        assert len(findings) == 2
        # Breach with password → HIGH; without → MEDIUM
        sevs = {f.raw["breach"]["Name"]: f.severity for f in findings}
        assert sevs["SomeSite"] == Severity.HIGH
        assert sevs["OtherSite"] == Severity.MEDIUM

    @respx.mock
    async def test_404_means_no_breaches(self):
        respx.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com"
        ).mock(return_value=httpx.Response(404))
        findings = await _collect(HIBPScanner({"api_key": "k"}), _email())
        assert findings == []


class TestExactEmailSearchScanner:
    def test_disabled_without_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        assert ExactEmailSearchScanner().enabled() is False

    def test_disabled_by_config_flag(self):
        assert ExactEmailSearchScanner({"enabled": False, "token": "x"}).enabled() is False

    def test_enabled_with_token(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "xxx")
        assert ExactEmailSearchScanner().enabled() is True

    def test_supports_email_only(self):
        s = ExactEmailSearchScanner({"token": "x"})
        assert s.supports(_email()) is True
        assert s.supports(_domain()) is False

    @respx.mock
    async def test_finds_email_in_env_file(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "html_url": "https://github.com/acme/app/blob/main/.env",
                            "path": ".env",
                            "repository": {"full_name": "acme/app"},
                        }
                    ]
                },
            )
        )
        respx.get("https://raw.githubusercontent.com/acme/app/HEAD/.env").mock(
            return_value=httpx.Response(200, text="EMAIL=user@example.com\n")
        )
        findings = await _collect(ExactEmailSearchScanner({"token": "t"}), _email())
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].kind == "email_in_public_code"

    @respx.mock
    async def test_finds_email_in_regular_file(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "html_url": "https://github.com/acme/app/blob/main/readme.md",
                            "path": "readme.md",
                            "repository": {"full_name": "acme/app"},
                        }
                    ]
                },
            )
        )
        respx.get("https://raw.githubusercontent.com/acme/app/HEAD/readme.md").mock(
            return_value=httpx.Response(200, text="Contact user@example.com for support.\n")
        )
        findings = await _collect(ExactEmailSearchScanner({"token": "t"}), _email())
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].kind == "email_in_public_code"

    @respx.mock
    async def test_empty_results_yields_nothing(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        assert await _collect(ExactEmailSearchScanner({"token": "t"}), _email()) == []

    @respx.mock
    async def test_http_error_yields_nothing(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(403)
        )
        assert await _collect(ExactEmailSearchScanner({"token": "t"}), _email()) == []


class TestLeadFetchScanner:
    def test_disabled_without_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        assert LeadFetchScanner().enabled() is False

    def test_disabled_by_config_flag(self):
        assert LeadFetchScanner({"enabled": False, "token": "x"}).enabled() is False

    def test_enabled_with_token(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "xxx")
        assert LeadFetchScanner().enabled() is True

    def test_supports_domain_and_email(self):
        s = LeadFetchScanner({"token": "x"})
        assert s.supports(_domain()) is True
        assert s.supports(_email()) is True

    @respx.mock
    async def test_finds_secret_in_sensitive_file(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "html_url": "https://github.com/acme/app/blob/main/deploy.env",
                            "path": "deploy.env",
                            "repository": {"full_name": "acme/app"},
                        }
                    ]
                },
            )
        )
        raw_content = "DOMAIN=example.com\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        respx.get("https://raw.githubusercontent.com/acme/app/HEAD/deploy.env").mock(
            return_value=httpx.Response(200, text=raw_content)
        )
        findings = await _collect(
            LeadFetchScanner({"token": "t", "max_pages": 1}), _domain()
        )
        assert len(findings) == 1
        assert findings[0].kind == "exposed_aws_access_key"
        assert findings[0].severity == Severity.CRITICAL

    @respx.mock
    async def test_no_results_yields_nothing(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        assert await _collect(LeadFetchScanner({"token": "t"}), _domain()) == []

    @respx.mock
    async def test_http_error_yields_nothing(self):
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(503)
        )
        assert await _collect(LeadFetchScanner({"token": "t"}), _domain()) == []
