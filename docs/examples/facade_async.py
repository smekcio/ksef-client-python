"""Async TEST online example: KSEF_NIP/KSEF_TOKEN environment and XML file argument."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from ksef_client import AsyncKsef, KsefClientOptions, KsefEnvironment, TokenCredentials


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml", type=Path)
    args = parser.parse_args()
    xml = await asyncio.to_thread(args.xml.read_bytes)
    client = await AsyncKsef.connect(
        options=KsefClientOptions(base_url=KsefEnvironment.TEST.value),
        context_type="nip",
        context_value=os.environ["KSEF_NIP"],
        credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
    )
    async with client:
        session = await client.online_session()
        async with session:
            invoice = await (await session.send_invoice(xml)).wait()
            print(invoice.ksef_number)
        await session.wait()
        print(len((await session.upo().wait()).pages))


if __name__ == "__main__":
    asyncio.run(main())
