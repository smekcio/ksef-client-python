import pytest

from ksef_client import models as m
from ksef_client._offline_invoice_state import (
    OfflineInvoiceProgress,
    OfflineInvoiceStatus,
    offline_invoice_hash,
)
from ksef_client.exceptions import KsefDocumentValidationError

NUMBER = "5555555555-20250828-010080615740-E4"
HASH = offline_invoice_hash(b"<invoice/>")


def remote_invoice(code, *, invoice_hash=HASH, reference="invoice-1", number=None):
    return m.SessionInvoiceStatusResponse(
        status=m.StatusInfo(code, ""),
        invoice_hash=invoice_hash,
        reference_number=reference,
        ksef_number=number,
    )


def test_lost_submission_response_is_reconciled_without_a_new_send():
    pending = OfflineInvoiceProgress(HASH).open_session("session-1").begin_submission()
    assert pending.status is OfflineInvoiceStatus.SUBMISSION_UNKNOWN
    with pytest.raises(ValueError, match="cannot be submitted again"):
        pending.begin_submission()
    submitted = pending.observe(remote_invoice(150))
    accepted = submitted.observe(remote_invoice(200, number=NUMBER))
    assert accepted.ksef_number == NUMBER
    assert accepted.confirm_upo().status is OfflineInvoiceStatus.COMPLETE
    assert HASH not in repr(accepted)
    assert NUMBER not in repr(accepted)


@pytest.mark.parametrize(
    "result",
    [
        remote_invoice(200),
        remote_invoice(200, number=NUMBER, invoice_hash=offline_invoice_hash(b"<other/>")),
        remote_invoice(200, number=NUMBER, reference="other-ref"),
        remote_invoice(429),
    ],
)
def test_ambiguous_or_mismatched_result_cannot_advance(result):
    state = (
        OfflineInvoiceProgress(HASH)
        .open_session("session-1")
        .begin_submission()
        .confirm_reference("invoice-1")
    )
    with pytest.raises(KsefDocumentValidationError):
        state.observe(result)


def test_rejection_preserves_reference_for_technical_correction():
    state = OfflineInvoiceProgress(HASH).open_session("session-1").begin_submission()
    rejected = state.observe(remote_invoice(450))
    assert rejected.status is OfflineInvoiceStatus.REJECTED
    assert rejected.ksef_status == 450
    assert rejected.invoice_hash == HASH
    with pytest.raises(ValueError, match="has not been accepted"):
        rejected.confirm_upo()
