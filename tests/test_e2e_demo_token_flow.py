from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from ksef_client import KsefClient, KsefClientOptions
from ksef_client.exceptions import KsefRateLimitError
from ksef_client.services import AuthCoordinator, OnlineSessionWorkflow


def _env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing env var: {name}")
    return value


def _select_cert(certs: list[dict], usage_name: str) -> str:
    for cert in certs:
        if usage_name in (cert.get("usage") or []):
            return cert["certificate"]
    raise RuntimeError(f"Missing public cert usage: {usage_name}")


@pytest.mark.e2e
def test_e2e_token_send_and_list_session_invoices() -> None:
    if os.getenv("KSEF_E2E") not in {"1", "true", "yes"}:
        pytest.skip("Set KSEF_E2E=1 to enable this test.")

    token = _env("KSEF_TOKEN")
    context_type = _env("KSEF_CONTEXT_TYPE")
    context_value = _env("KSEF_CONTEXT_VALUE")
    base_url = _env("KSEF_BASE_URL")

    options = KsefClientOptions(base_url=base_url)
    with KsefClient(options) as client:
        certs = client.security.get_public_key_certificates()
        token_cert = _select_cert(certs, "KsefTokenEncryption")
        symmetric_cert = _select_cert(certs, "SymmetricKeyEncryption")

        access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
            token=token,
            public_certificate=token_cert,
            context_identifier_type=context_type,
            context_identifier_value=context_value,
            max_attempts=90,
            poll_interval_seconds=2.0,
        ).tokens.access_token.token

        workflow = OnlineSessionWorkflow(client.sessions)
        session = workflow.open_session(
            form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
            public_certificate=symmetric_cert,
            access_token=access_token,
        )

        now = datetime.now(timezone.utc).replace(microsecond=0)
        invoice_xml = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<Faktura xmlns:etd=\"http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/\" "
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
            "xmlns=\"http://crd.gov.pl/wzor/2025/06/25/13775/\">"
            "<Naglowek>"
            "<KodFormularza kodSystemowy=\"FA (3)\" wersjaSchemy=\"1-0E\">FA</KodFormularza>"
            "<WariantFormularza>3</WariantFormularza>"
            f"<DataWytworzeniaFa>{now.strftime('%Y-%m-%dT%H:%M:%SZ')}</DataWytworzeniaFa>"
            "<SystemInfo>pytest</SystemInfo>"
            "</Naglowek>"
            "<Podmiot1><DaneIdentyfikacyjne>"
            f"<NIP>{context_value}</NIP><Nazwa>pytest seller</Nazwa>"
            "</DaneIdentyfikacyjne><Adres><KodKraju>PL</KodKraju><AdresL1>x</AdresL1><AdresL2>x</AdresL2></Adres>"
            "</Podmiot1>"
            "<Podmiot2>"
            "<DaneIdentyfikacyjne><NIP>1111111111</NIP><Nazwa>pytest buyer</Nazwa></DaneIdentyfikacyjne>"
            "<Adres><KodKraju>PL</KodKraju><AdresL1>x</AdresL1><AdresL2>x</AdresL2></Adres>"
            "<DaneKontaktowe><Email>buyer@example.com</Email><Telefon>555777999</Telefon></DaneKontaktowe>"
            "<NrKlienta>99999999</NrKlienta><JST>2</JST><GV>2</GV>"
            "</Podmiot2>"
            "<Fa>"
            "<KodWaluty>PLN</KodWaluty>"
            f"<P_1>{now.date().isoformat()}</P_1><P_1M>x</P_1M>"
            f"<P_2>FA/PYTEST/{now:%m}/{now:%Y}</P_2>"
            "<OkresFa>"
            f"<P_6_Od>{now.date().replace(day=1).isoformat()}</P_6_Od>"
            f"<P_6_Do>{(now.date()+timedelta(days=14)).isoformat()}</P_6_Do>"
            "</OkresFa>"
            "<P_13_1>1.00</P_13_1><P_14_1>0.23</P_14_1><P_15>1.23</P_15>"
            "<Adnotacje><P_16>2</P_16><P_17>2</P_17><P_18>2</P_18><P_18A>2</P_18A>"
            "<Zwolnienie><P_19N>1</P_19N></Zwolnienie><NoweSrodkiTransportu><P_22N>1</P_22N></NoweSrodkiTransportu>"
            "<P_23>2</P_23><PMarzy><P_PMarzyN>1</P_PMarzyN></PMarzy></Adnotacje>"
            "<RodzajFaktury>VAT</RodzajFaktury>"
            "<FaWiersz><NrWierszaFa>1</NrWierszaFa><P_7>x</P_7><P_8A>szt</P_8A><P_8B>1.00</P_8B>"
            "<P_9A>1.00</P_9A><P_11>1.00</P_11><P_12>23</P_12></FaWiersz>"
            "<Rozliczenie><Obciazenia><Kwota>0.00</Kwota><Powod>x</Powod></Obciazenia><SumaObciazen>0.00</SumaObciazen>"
            "<Odliczenia><Kwota>0.00</Kwota><Powod>x</Powod></Odliczenia><SumaOdliczen>0.00</SumaOdliczen>"
            "<DoZaplaty>1.23</DoZaplaty></Rozliczenie>"
            "<Platnosc><TerminPlatnosci><Termin>"
            f"{(now.date()+timedelta(days=14)).isoformat()}"
            "</Termin></TerminPlatnosci><FormaPlatnosci>6</FormaPlatnosci>"
            "<RachunekBankowy><NrRB>73111111111111111111111111</NrRB><NazwaBanku>x</NazwaBanku><OpisRachunku>PLN</OpisRachunku></RachunekBankowy>"
            "</Platnosc>"
            "</Fa>"
            "</Faktura>"
        ).encode("utf-8")

        send_result = workflow.send_invoice(
            session_reference_number=session.session_reference_number,
            invoice_xml=invoice_xml,
            encryption_data=session.encryption_data,
            access_token=access_token,
        )
        invoice_reference_number = send_result["referenceNumber"]

        ksef_number = None
        for _ in range(90):
            status = client.sessions.get_session_invoice_status(
                session.session_reference_number,
                invoice_reference_number,
                access_token=access_token,
            )
            code = int(status.get("status", {}).get("code", 0))
            if code == 200:
                ksef_number = status.get("ksefNumber")
                break
            if code not in {100, 150}:
                raise AssertionError(status)
            time.sleep(2)

        assert ksef_number, "Expected ksefNumber in invoice status"

        try:
            listed = client.sessions.get_session_invoices(
                session.session_reference_number,
                access_token=access_token,
                page_size=10,
            )
        except KsefRateLimitError:
            time.sleep(5)
            listed = client.sessions.get_session_invoices(
                session.session_reference_number,
                access_token=access_token,
                page_size=10,
            )

        invoices = listed.get("invoices") or []
        assert any(inv.get("ksefNumber") == ksef_number for inv in invoices)
