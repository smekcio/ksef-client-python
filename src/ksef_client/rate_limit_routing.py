"""Canonical KSeF API endpoint groups, independent of current quota values.

Routes follow the checked-in API 2.9 OpenAPI snapshot. Protected ``other``
endpoints have individual counters; their keys contain templates, never IDs,
query strings, credentials or request bodies. Global/anonymous keys require
IP-wide accounting in the budget, while protected counters additionally use
an application context identity.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import SplitResult, unquote, urlsplit

# Keep this table aligned with operation 429 group descriptions in the snapshot.
_ROUTE_GROUPS: tuple[tuple[str, str, str], ...] = (
    ("DELETE", "/auth/sessions/current", "other"),
    ("DELETE", "/testdata/limits/context/session", "other"),
    ("DELETE", "/testdata/limits/subject/certificate", "other"),
    ("DELETE", "/testdata/rate-limits", "other"),
    ("GET", "/auth/sessions", "other"),
    ("GET", "/certificates/enrollments/data", "other"),
    ("GET", "/certificates/limits", "other"),
    ("GET", "/limits/context", "other"),
    ("GET", "/limits/subject", "other"),
    ("GET", "/peppol/query", "anonymous"),
    ("GET", "/permissions/attachments/status", "other"),
    ("GET", "/permissions/query/entities/roles", "other"),
    ("GET", "/rate-limits", "other"),
    ("GET", "/security/public-key-certificates", "anonymous"),
    ("GET", "/sessions", "sessionList"),
    ("GET", "/tokens", "other"),
    ("POST", "/auth/challenge", "anonymous"),
    ("POST", "/auth/ksef-token", "anonymous"),
    ("POST", "/auth/token/redeem", "anonymous"),
    ("POST", "/auth/token/refresh", "anonymous"),
    ("POST", "/auth/xades-signature", "anonymous"),
    ("POST", "/certificates/enrollments", "other"),
    ("POST", "/certificates/query", "other"),
    ("POST", "/certificates/retrieve", "other"),
    ("POST", "/collective-identifiers", "collectiveIdentifier"),
    ("POST", "/collective-identifiers/invoices", "collectiveIdentifier"),
    ("POST", "/collective-identifiers/query", "collectiveIdentifier"),
    ("POST", "/invoices/exports", "invoiceExport"),
    ("POST", "/invoices/query/metadata", "invoiceMetadata"),
    ("POST", "/permissions/authorizations/grants", "other"),
    ("POST", "/permissions/entities/grants", "other"),
    ("POST", "/permissions/eu-entities/administration/grants", "other"),
    ("POST", "/permissions/eu-entities/grants", "other"),
    ("POST", "/permissions/indirect/grants", "other"),
    ("POST", "/permissions/persons/grants", "other"),
    ("POST", "/permissions/query/authorizations/grants", "other"),
    ("POST", "/permissions/query/entities/grants", "other"),
    ("POST", "/permissions/query/eu-entities/grants", "other"),
    ("POST", "/permissions/query/personal/grants", "other"),
    ("POST", "/permissions/query/persons/grants", "other"),
    ("POST", "/permissions/query/subordinate-entities/roles", "other"),
    ("POST", "/permissions/query/subunits/grants", "other"),
    ("POST", "/permissions/subunits/grants", "other"),
    ("POST", "/sessions/batch", "batchSession"),
    ("POST", "/sessions/online", "onlineSession"),
    ("POST", "/testdata/attachment", "anonymous"),
    ("POST", "/testdata/attachment/revoke", "anonymous"),
    ("POST", "/testdata/context/block", "other"),
    ("POST", "/testdata/context/unblock", "other"),
    ("POST", "/testdata/limits/context/session", "other"),
    ("POST", "/testdata/limits/subject/certificate", "other"),
    ("POST", "/testdata/permissions", "anonymous"),
    ("POST", "/testdata/permissions/revoke", "anonymous"),
    ("POST", "/testdata/person", "anonymous"),
    ("POST", "/testdata/person/remove", "anonymous"),
    ("POST", "/testdata/rate-limits", "other"),
    ("POST", "/testdata/rate-limits/production", "other"),
    ("POST", "/testdata/subject", "anonymous"),
    ("POST", "/testdata/subject/remove", "anonymous"),
    ("POST", "/tokens", "other"),
    ("DELETE", "/auth/sessions/{referenceNumber}", "other"),
    ("DELETE", "/permissions/authorizations/grants/{permissionId}", "other"),
    ("DELETE", "/permissions/common/grants/{permissionId}", "other"),
    ("DELETE", "/tokens/{referenceNumber}", "other"),
    ("GET", "/auth/{referenceNumber}", "anonymous"),
    ("GET", "/certificates/enrollments/{referenceNumber}", "other"),
    ("GET", "/collective-identifiers/ksef/{ksefNumber}", "collectiveIdentifier"),
    ("GET", "/invoices/exports/{referenceNumber}", "invoiceExportStatus"),
    ("GET", "/invoices/ksef/{ksefNumber}", "invoiceDownload"),
    ("GET", "/permissions/operations/{referenceNumber}", "other"),
    ("GET", "/sessions/{referenceNumber}", "sessionMisc"),
    ("GET", "/sessions/{referenceNumber}/invoices", "sessionInvoiceList"),
    ("GET", "/sessions/{referenceNumber}/invoices/failed", "sessionInvoiceList"),
    ("GET", "/tokens/{referenceNumber}", "other"),
    ("POST", "/certificates/{certificateSerialNumber}/revoke", "other"),
    ("POST", "/sessions/batch/{referenceNumber}/close", "batchSessionClose"),
    ("POST", "/sessions/online/{referenceNumber}/close", "onlineSessionClose"),
    ("POST", "/sessions/online/{referenceNumber}/invoices", "invoiceSend"),
    ("PUT", "/testdata/certificates/{serialNumber}", "other"),
    ("GET", "/sessions/{referenceNumber}/invoices/ksef/{ksefNumber}/upo", "sessionMisc"),
    ("GET", "/sessions/{referenceNumber}/invoices/{invoiceReferenceNumber}", "invoiceStatus"),
    ("GET", "/sessions/{referenceNumber}/invoices/{invoiceReferenceNumber}/upo", "sessionMisc"),
    ("GET", "/sessions/{referenceNumber}/upo/{upoReferenceNumber}", "sessionMisc"),
)


def _compile_template(template: str) -> re.Pattern[str]:
    return re.compile(
        "^"
        + "/".join(
            "[^/]+" if part.startswith("{") else re.escape(part) for part in template.split("/")
        )
        + "$",
        re.IGNORECASE,
    )


_COMPILED_ROUTES = tuple(
    (method, _compile_template(template), template, group)
    for method, template, group in _ROUTE_GROUPS
)


def _origin(url: SplitResult) -> tuple[str, str, int]:
    scheme = url.scheme.lower()
    if scheme not in {"http", "https"} or not url.hostname:
        raise ValueError("Invalid API origin for rate limit classification")
    try:
        port = url.port
        if port is None:
            port = 443 if scheme == "https" else 80
    except ValueError:
        raise ValueError("Invalid API port for rate limit classification") from None
    return scheme, url.hostname.encode("idna").decode("ascii").lower().rstrip("."), port


def _clean_path(path: str) -> str:
    # Decode once to match URL routing; encoded resource names must not fall
    # into a different budget. Canonicalization never escapes the API origin.
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError:
        raise ValueError("Invalid API path encoding for rate limit classification") from None
    return posixpath.normpath("/" + decoded.lstrip("/")).rstrip("/") or "/"


def canonical_rate_limit_environment(base_url: str) -> str:
    """Return a credential-free origin identity for shared API/IP accounting.

    Path aliases and proxy prefixes on the same origin conservatively share
    one environment. Context and known egress-IP labels remain separate keys
    in the budget. A changed URL spelling must never create additional quota.
    """
    scheme, host, port = _origin(urlsplit(base_url))
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def classify_rate_limit_groups(
    method: str,
    path: str,
    base_url: str,
    *,
    skip_auth: bool = False,
) -> tuple[str, ...] | None:
    """Return global and endpoint budget keys, or None for non-API traffic.

    ``base_url`` accepts the client's configured root or normalized API URL.
    Absolute URLs must use the same origin AND the exact configured API path
    prefix. Storage and Lighthouse are separate services and do not consume
    this API budget. ``skip_auth`` intentionally does not bypass accounting:
    public certificate/auth routes also use it, and have anonymous quotas.
    Unknown API routes share a conservative ``other`` bucket, preventing
    caller-provided path IDs from creating unbounded budget keys.
    """
    base = urlsplit(base_url)
    origin = _origin(base)
    prefix = _clean_path(base.path)
    if not prefix.lower().endswith("/v2"):
        prefix = prefix.rstrip("/") + "/v2"
    requested = urlsplit(path)
    clean = _clean_path(requested.path)
    if requested.scheme or requested.netloc:
        if _origin(requested) != origin:
            return None
        if clean.lower() == prefix.lower():
            clean = "/"
        elif clean.lower().startswith(prefix.lower() + "/"):
            clean = clean[len(prefix) :]
        else:
            return None
    else:
        # Relative client paths normally omit /v2. Also accept already
        # normalized API paths without treating /v2-other as that prefix.
        for candidate in (prefix, "/api/v2", "/v2"):
            if clean.lower() == candidate.lower():
                clean = "/"
                break
            if clean.lower().startswith(candidate.lower() + "/"):
                clean = clean[len(candidate) :]
                break
    method = method.strip().upper()
    for route_method, pattern, template, group in _COMPILED_ROUTES:
        if method == route_method and pattern.fullmatch(clean):
            key = (
                f"other:{method} {template}"
                if group == "other"
                else re.sub(r"(?<!^)(?=[A-Z])", "_", group).lower()
            )
            return "global", key
    return "global", "other"


__all__ = ["canonical_rate_limit_environment", "classify_rate_limit_groups"]
