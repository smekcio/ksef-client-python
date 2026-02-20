from __future__ import annotations

from rich.console import Console
from rich.table import Table


class HumanRenderer:
    def __init__(self, *, no_color: bool = False) -> None:
        self._console = Console(no_color=no_color)

    def info(self, message: str, *, command: str | None = None) -> None:
        prefix = f"[{command}] " if command else ""
        self._console.print(f"{prefix}{message}")

    def success(
        self,
        *,
        command: str,
        profile: str,
        data: dict | None = None,
        message: str | None = None,
    ) -> None:
        title = message or "OK"
        self._console.print(f"[green]{title}[/green] ({command}, profile={profile})")
        if command == "invoice.list":
            self._render_invoice_list(data or {})
            return
        if data:
            for key, value in data.items():
                if key == "response":
                    continue
                self._console.print(f"- {key}: {value}")

    def error(
        self,
        *,
        command: str,
        profile: str,
        code: str,
        message: str,
        hint: str | None = None,
    ) -> None:
        self._console.print(f"[red]{code}[/red] {message} ({command}, profile={profile})")
        if hint:
            self._console.print(f"Hint: {hint}")

    def _render_invoice_list(self, data: dict) -> None:
        items = data.get("items")
        if not isinstance(items, list) or not items:
            for key, value in data.items():
                self._console.print(f"- {key}: {value}")
            return

        table = Table(title="Invoices")
        table.add_column("#", justify="right")
        table.add_column("KSeF Number")
        table.add_column("Invoice Number")
        table.add_column("Issue Date")
        table.add_column("Gross")

        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            ksef_number = str(item.get("ksefNumber") or item.get("ksefReferenceNumber") or "")
            invoice_number = str(item.get("invoiceNumber") or "")
            issue_date = str(item.get("issueDate") or "")
            gross = str(item.get("grossAmount") or "")
            table.add_row(str(idx), ksef_number, invoice_number, issue_date, gross)

        self._console.print(table)
        for key in ("count", "from", "to", "continuation_token"):
            if key in data:
                self._console.print(f"- {key}: {data[key]}")
