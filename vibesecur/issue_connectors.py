"""Small, synchronous issue creation adapters for Linear and Jira Cloud.

Connection status is configuration-only; it does not probe a provider. No
provider request is made until create_issue is called with complete config.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit


DEFAULT_TIMEOUT_SECONDS = 10
_PROVIDERS = {"linear", "jira"}
_LINEAR_NATIVE_FIELDS = {
    "assigneeId",
    "cycleId",
    "labelIds",
    "priority",
    "projectId",
    "stateId",
}
_JIRA_RESERVED_FIELDS = {"project", "summary", "description", "issuetype"}
_ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*-[1-9][0-9]*$")


class IssueConnectorError(Exception):
    """A safe provider error; messages never include response bodies or tokens."""

    def __init__(self, code: str, message: str, *, provider: str, status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.provider = provider
        self.status_code = status_code


@dataclass(frozen=True)
class _Config:
    provider: str
    values: Mapping[str, str]
    missing: tuple[str, ...]

    @property
    def connected(self) -> bool:
        return not self.missing


def _config(provider: str, environ: Mapping[str, str] | None = None) -> _Config:
    provider = _provider(provider)
    env = os.environ if environ is None else environ
    required = {
        "linear": {
            "api_key": "LINEAR_API_KEY",
            "team_id": "LINEAR_TEAM_ID",
        },
        "jira": {
            "base_url": "JIRA_BASE_URL",
            "email": "JIRA_EMAIL",
            "api_token": "JIRA_API_TOKEN",
            "project_key": "JIRA_PROJECT_KEY",
            "issue_type": "JIRA_ISSUE_TYPE",
        },
    }[provider]
    values = {key: str(env.get(name, "")).strip() for key, name in required.items()}
    missing = tuple(name for key, name in required.items() if not values[key])
    return _Config(provider, values, missing)


def _provider(provider: str) -> str:
    if not isinstance(provider, str) or provider.lower() not in _PROVIDERS:
        raise IssueConnectorError("unsupported_provider", "Provider must be 'linear' or 'jira'.", provider=str(provider))
    return provider.lower()


def connection_status(provider: str, *, environ: Mapping[str, str] | None = None) -> dict:
    """Return configuration readiness without making a network request."""
    config = _config(provider, environ)
    return {
        "provider": config.provider,
        "configured": config.connected,
        # Kept for compatibility: this reports complete local configuration,
        # not a successful authentication or provider health check.
        "connected": config.connected,
        "missing": list(config.missing),
    }


def create_issue(
    provider: str,
    issue: Mapping,
    *,
    environ: Mapping[str, str] | None = None,
    transport: Callable | None = None,
) -> dict:
    """Create one issue and return {provider,id,key,title,url}.

    ``issue`` requires non-empty string ``title`` and string ``description``.
    Optional ``nativeFields`` carries a provider-specific object: Linear accepts
    assigneeId/cycleId/labelIds/priority/projectId/stateId; Jira accepts
    non-reserved issue fields in Jira's native ``fields`` shape.

    ``transport(url, headers, body, timeout_seconds)`` may be injected for
    deterministic local tests. It returns ``(status_code, response_bytes)``.
    """
    config = _config(provider, environ)
    if not config.connected:
        raise IssueConnectorError(
            "not_connected",
            "Issue provider is not configured.",
            provider=config.provider,
        )
    if not isinstance(issue, Mapping):
        raise IssueConnectorError("invalid_issue", "Issue must be an object.", provider=config.provider)
    title = issue.get("title")
    description = issue.get("description")
    if not isinstance(title, str) or not title.strip() or len(title) > 500:
        raise IssueConnectorError("invalid_issue", "Title must be a non-empty string of at most 500 characters.", provider=config.provider)
    if not isinstance(description, str):
        raise IssueConnectorError("invalid_issue", "Description must be a string.", provider=config.provider)
    native = issue.get("nativeFields", {})
    if not isinstance(native, Mapping):
        raise IssueConnectorError("invalid_issue", "nativeFields must be an object.", provider=config.provider)

    if config.provider == "linear":
        url, headers, body = _linear_request(config, title.strip(), description, native)
    else:
        url, headers, body = _jira_request(config, title.strip(), description, native)

    try:
        response_status, response_body = (transport or _http_transport)(url, headers, body, DEFAULT_TIMEOUT_SECONDS)
    except Exception:
        # Transport exceptions can contain request details; expose only the
        # stable adapter-level failure code and provider name.
        raise IssueConnectorError("provider_unavailable", "Issue provider could not be reached.", provider=config.provider)
    if not isinstance(response_status, int) or not isinstance(response_body, bytes):
        raise IssueConnectorError("invalid_transport_response", "Issue provider returned an invalid response.", provider=config.provider)
    if not 200 <= response_status < 300:
        raise IssueConnectorError(
            "provider_error",
            "Issue provider rejected the request.",
            provider=config.provider,
            status_code=response_status,
        )
    try:
        decoded = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        raise IssueConnectorError("invalid_provider_response", "Issue provider returned an invalid response.", provider=config.provider)
    if config.provider == "linear":
        return _linear_result(decoded, provider=config.provider)
    return _jira_result(decoded, config.values["base_url"], title=title.strip(), provider=config.provider)


def _linear_request(config: _Config, title: str, description: str, native: Mapping):
    unknown = set(native) - _LINEAR_NATIVE_FIELDS
    if unknown:
        raise IssueConnectorError("invalid_native_fields", "Unsupported Linear native field.", provider="linear")
    input_fields = {"teamId": config.values["team_id"], "title": title, "description": description}
    input_fields.update(native)
    query = (
        "mutation CreateIssue($input: IssueCreateInput!) { issueCreate(input: $input) { "
        "success issue { id identifier title url } } }"
    )
    body = json.dumps({"query": query, "variables": {"input": input_fields}}, separators=(",", ":")).encode()
    return "https://api.linear.app/graphql", {
        "Authorization": config.values["api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json",
    }, body


def _jira_request(config: _Config, title: str, description: str, native: Mapping):
    base_url = config.values["base_url"].rstrip("/")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IssueConnectorError("invalid_configuration", "JIRA_BASE_URL must be a clean HTTPS URL.", provider="jira")
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        raise IssueConnectorError("invalid_configuration", "JIRA_BASE_URL contains an invalid path.", provider="jira")
    if _JIRA_RESERVED_FIELDS.intersection(native):
        raise IssueConnectorError("invalid_native_fields", "nativeFields cannot override required Jira fields.", provider="jira")
    # Treat caller text as plain text and encode it as the ADF document expected
    # by Jira REST v3 rather than interpreting it as markup.
    fields = {
        "project": {"key": config.values["project_key"]},
        "issuetype": {"name": config.values["issue_type"]},
        "summary": title,
        "description": {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}] if description else [],
        },
    }
    fields.update(native)
    body = json.dumps({"fields": fields}, separators=(",", ":")).encode()
    basic = base64.b64encode(f"{config.values['email']}:{config.values['api_token']}".encode()).decode("ascii")
    return f"{base_url}/rest/api/3/issue", {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }, body


def _linear_result(payload, *, provider: str) -> dict:
    try:
        if payload.get("errors"):
            raise ValueError
        result = payload["data"]["issueCreate"]
        item = result["issue"]
        if result.get("success") is not True or not all(isinstance(item.get(k), str) and item[k] for k in ("id", "identifier", "title", "url")):
            raise ValueError
        return {"provider": provider, "id": item["id"], "key": item["identifier"], "title": item["title"], "url": item["url"]}
    except (AttributeError, KeyError, TypeError, ValueError):
        raise IssueConnectorError("creation_unconfirmed", "Linear did not confirm issue creation.", provider=provider)


def _jira_result(payload, base_url: str, *, title: str, provider: str) -> dict:
    try:
        key = payload["key"]
        issue_id = payload["id"]
        if not isinstance(key, str) or not _ISSUE_KEY.fullmatch(key) or not isinstance(issue_id, str) or not issue_id:
            raise ValueError
        return {"provider": provider, "id": issue_id, "key": key, "title": title, "url": f"{base_url.rstrip('/')}/browse/{key}"}
    except (AttributeError, KeyError, TypeError, ValueError):
        raise IssueConnectorError("creation_unconfirmed", "Jira did not confirm issue creation.", provider=provider)


def _http_transport(url: str, headers: Mapping[str, str], body: bytes, timeout_seconds: int):
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.status, response.read(1_000_001)
    except urllib.error.HTTPError as error:
        # Do not surface provider bodies: they can echo request data.
        return error.code, b""
    except (urllib.error.URLError, TimeoutError, OSError):
        raise IssueConnectorError("provider_unavailable", "Issue provider could not be reached.", provider="provider")
