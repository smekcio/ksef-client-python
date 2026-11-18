from rich.console import Console
from rich.table import Table
from rich.text import Text

_LABELS = {
    "local_id": "Invoice ID",
    "status": "Status",
    "ksef_status": "KSeF status",
    "ksef_number": "KSeF number",
    "invoice_ref": "Invoice reference",
    "session_ref": "Session reference",
    "revision": "Saved revision",
    "upo_path": "UPO file",
    "saved": "UPO file",
    "event_id": "Event ID",
    "consumer": "Consumer",
    "expires_at": "Reservation expires (UTC)",
    "xml": "Invoice XML",
    "metadata": "Metadata file",
    "receipt": "Receipt file",
    "delay_seconds": "Retry delay (seconds)",
}

_ONLINE_ACTIONS = {
    "queued": "Use ksef online run to open the session.",
    "session_open": "Use ksef online run to submit the registered XML.",
    "submission_unknown": "Use ksef online run to check whether KSeF received this invoice.",
    "submitted": "Use ksef online run to check the result.",
    "accepted": "Use ksef online run to retrieve the individual UPO.",
    "complete": "Use ksef online upo --out FILE to save the verified UPO.",
    "retryable": "KSeF confirmed cancellation. Use ksef online retry-cancelled to requeue it.",
    "duplicate": "KSeF reported a duplicate. Check the original invoice.",
    "rejected": "Review the KSeF status and correct the invoice before submitting a new XML.",
}


def _literal(value: object) -> str:
    return "".join(char if char.isprintable() else "?" for char in str(value))


def render_invoice_workflow(console: Console, command: str, data: dict) -> bool:
    if command == "session.batch.report":
        console.print(
            Text(f"Session {_literal(data['session_ref'])} (KSeF {data['session_status']})")
        )
        if not data["complete"]:
            console.print("Partial report. Check unresolved invoices again later.")
        table = Table()
        for label in ("Invoice file", "Outcome", "Code", "KSeF number", "Next action"):
            table.add_column(label, overflow="fold")
        retry = set(data["retry_candidates"])
        correct = set(data["correction_candidates"])
        for invoice in data["invoices"]:
            name = invoice["file_name"]
            action = "Review XML" if name in correct else "May retry" if name in retry else ""
            table.add_row(
                Text(_literal(name)),
                Text(_literal(invoice["disposition"])),
                str(invoice["status_code"] or "—"),
                Text(_literal(invoice["ksef_number"] or "—")),
                action,
            )
        console.print(table)
    elif command == "archive.next" and not data["available"]:
        console.print("No purchase invoice is available for this consumer.")
    elif (
        (command == "send.online" and "local_id" in data)
        or command.startswith("online.")
        or command
        in {
            "archive.next",
            "archive.ack",
            "archive.retry",
        }
    ):
        for key, label in _LABELS.items():
            if data.get(key) is not None:
                console.print(Text(f"{label}: {_literal(data[key])}"))
        if command == "archive.next":
            console.print(
                "After processing, use ksef archive ack --receipt FILE with this receipt."
            )
        elif command == "archive.ack":
            console.print("Delivery acknowledged.")
        elif command == "archive.retry":
            console.print("Delivery released for another attempt.")
        elif "local_id" in data and "upo_path" not in data:
            console.print(_ONLINE_ACTIONS[data["status"]])
    else:
        return False
    return True
