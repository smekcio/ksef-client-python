"""Evidence for ordinary FA(3) sales and purchase invoice access in the login context."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from . import models as m


class InvoicePermissionOperation(str, Enum):
    SEND_ONLINE = "send-online"
    DOWNLOAD_PURCHASES = "download-purchases"


_Reasons = Literal[
    "owner_grant",
    "personal_grant",
    "scope_uncertain",
    "owner_scopes_unreported",
    "specialised_scope",
    "no_applicable_grant",
]
_EXPLANATIONS = {
    "owner_grant": "KSeF reported the required owner permission in this login context.",
    "personal_grant": "An active personal grant covers this login context.",
    "scope_uncertain": "The reported grant's state, holder or target could not be established.",
    "owner_scopes_unreported": "KSeF did not report owner permissions.",
    "specialised_scope": "A specialised online-session scope requires a separate invoice context.",
    "no_applicable_grant": "KSeF reported no applicable active grant for this operation.",
}


@dataclass(frozen=True)
class OperationPermissionReport:
    operation: InvoicePermissionOperation
    required_scope: str
    status: Literal["grant_found", "grant_not_found", "indeterminate"]
    reason: _Reasons
    grant_id: str | None = None

    @property
    def explanation(self) -> str:
        return _EXPLANATIONS[self.reason]

    def to_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation.value,
            "requiredScope": self.required_scope,
            "status": self.status,
            "reason": self.reason,
            "explanation": self.explanation,
            "grantId": self.grant_id,
            "tokenScopeChecked": False,
        }


def _covers_context(grant: m.PersonalPermission, context_key: str) -> bool | None:
    # The endpoint includes indirect grants for both the intermediary and its clients.
    target = grant.target_identifier
    if target is not None:
        if target.type.value not in {"Nip", "InternalId"}:
            return None  # AllPartners requires knowing the intermediary's partners.
        if target.type.value != context_key.partition(":")[0]:
            return None  # Related NIP and subunit contexts need extra evidence.
        if f"{target.type.value}:{target.value}" != context_key:
            return False
    elif grant.context_identifier is not None:
        grantor = grant.context_identifier
        if f"{grantor.type.value}:{grantor.value}" != context_key:
            return None  # A parent unit may have granted the permission.
    # An explicit authorised identifier denotes a holder other than the authenticated client.
    # The profile's context ID is not that client's identity.
    if grant.authorized_identifier is not None:
        return None
    return True


def _evaluate_operation(
    operation: InvoicePermissionOperation,
    context_key: str,
    page: m.QueryPersonalPermissionsResponse,
) -> OperationPermissionReport:
    sending = operation is InvoicePermissionOperation.SEND_ONLINE
    required = "InvoiceWrite" if sending else "InvoiceRead"
    owners = {item.value for item in page.owner_permissions or []}
    if required in owners:
        return OperationPermissionReport(operation, required, "grant_found", "owner_grant")

    special = {"PefInvoiceWrite", "EnforcementOperations"} if sending else set()
    specialised = bool(owners & special)
    uncertain = False
    for grant in page.permissions:
        scope = grant.permission_scope.value
        if grant.permission_state == m.PermissionState.INACTIVE:
            continue
        if scope != required and scope not in special:
            continue
        covers = _covers_context(grant, context_key)
        if covers is False:
            continue
        if scope in special:
            specialised = True
        elif covers and grant.permission_state == m.PermissionState.ACTIVE:
            return OperationPermissionReport(
                operation, required, "grant_found", "personal_grant", grant.id
            )
        else:
            uncertain = True

    if uncertain:
        return OperationPermissionReport(operation, required, "indeterminate", "scope_uncertain")
    if specialised:
        return OperationPermissionReport(operation, required, "indeterminate", "specialised_scope")
    if page.owner_permissions is None:
        return OperationPermissionReport(
            operation, required, "indeterminate", "owner_scopes_unreported"
        )
    return OperationPermissionReport(operation, required, "grant_not_found", "no_applicable_grant")
