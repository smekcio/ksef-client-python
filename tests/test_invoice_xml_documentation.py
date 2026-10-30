from __future__ import annotations

import ast
import asyncio
import re
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from docs.examples import invoice_sync_documents as example

from tests.test_invoice_xml_sync import environment


def test_readme_and_complete_script_execute_with_real_sdk_adapters(tmp_path, monkeypatch, capsys):
    async def run():
        async with environment(tmp_path, False) as (initial, _, __, server):

            class Connection:
                def __enter__(self):
                    def documents(**kwargs):
                        return initial.xml.client.sync_documents(context_key="Nip:test", **kwargs)

                    return SimpleNamespace(invoices=SimpleNamespace(sync_documents=documents))

                def __exit__(self, *exc):
                    return False

            monkeypatch.setenv("KSEF_NIP", "test")
            monkeypatch.setenv("KSEF_TOKEN", "test-token-not-a-secret")
            monkeypatch.setattr(example.Ksef, "connect", lambda **kwargs: Connection())
            monkeypatch.chdir(tmp_path)
            report = example.synchronize_once(tmp_path / "archive")
            assert report.complete and report.xml.ready == 1
            assert example.synchronize_once(tmp_path / "archive").complete
            assert server.downloads == 1
            readme = Path(__file__).resolve().parents[1] / "README.md"
            text = readme.read_text(encoding="utf-8")
            section = text.split("### Synchronizacja metadanych i XML", 1)[1]
            match = re.search(r"```python\n(.*?)\n```", section, re.S)
            assert match is not None
            code = match.group(1)
            exec(compile(ast.parse(code), str(readme), "exec"), {})
            assert (tmp_path / "private/invoices.db").exists()
            assert len(list((tmp_path / "private/xml").glob("*.xml"))) == 1
            for value in (
                report,
                replace(report, xml=replace(report.xml, blocked=1, ready=0)),
                replace(report, xml=replace(report.xml, pending=1, ready=0)),
            ):
                monkeypatch.setattr(
                    example, "synchronize_once", lambda directory, value=value: value
                )
                example.main()
            assert "test-token-not-a-secret" not in capsys.readouterr().out

    asyncio.run(run())
