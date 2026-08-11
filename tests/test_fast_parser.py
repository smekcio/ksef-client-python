"""Unit tests for fast_extract_ksef_metadata function."""

from decimal import Decimal
from ksef_client.utils.fast_parser import fast_extract_ksef_metadata

KSEF_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/">
    <Podmiot1><DaneIdentyfikacyjne><NIP>5260250995</NIP></DaneIdentyfikacyjne></Podmiot1>
    <Podmiot2><DaneIdentyfikacyjne><NIP>1234567890</NIP></DaneIdentyfikacyjne></Podmiot2>
    <Fa>
        <FaWiersz><P_11>100.50</P_11><P_11A>123.615</P_11A></FaWiersz>
        <FaWiersz><P_11>200.75</P_11><P_11Vat>23.115</P_11Vat></FaWiersz>
    </Fa>
</Faktura>
"""

KSEF_INJECTION_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/">
    <Podmiot1><DaneIdentyfikacyjne><NIP>5260250995</NIP><Opis><!-- <NIP>9999999999</NIP> --><![CDATA[<NIP>8888888888</NIP>]]></Opis></DaneIdentyfikacyjne></Podmiot1>
</Faktura>
"""

KSEF_MALFORMED_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura><Podmiot1><DaneIdentyfikacyjne><NIP>5260250995</NIP><P_11>100.50</P_11>
"""


def test_fast_extract_ksef_metadata_correctness():
    res = fast_extract_ksef_metadata(KSEF_SAMPLE)
    assert res["seller_nip"] == "5260250995"
    assert res["buyer_nip"] == "1234567890"
    assert res["total_netto"] == Decimal("301.25")
    assert res["item_count"] == 2


def test_fast_extract_ksef_metadata_bytes():
    res = fast_extract_ksef_metadata(KSEF_SAMPLE.encode("utf-8"))
    assert res["seller_nip"] == "5260250995"
    assert res["total_netto"] == Decimal("301.25")


def test_fast_extract_ksef_metadata_injection_immunity():
    res = fast_extract_ksef_metadata(KSEF_INJECTION_SAMPLE)
    assert res["seller_nip"] == "5260250995"
    assert "9999999999" not in res["nips"]
    assert "8888888888" not in res["nips"]


def test_fast_extract_ksef_metadata_malformed_graceful_handling():
    res = fast_extract_ksef_metadata(KSEF_MALFORMED_SAMPLE)
    assert res["seller_nip"] == "5260250995"
    assert res["total_netto"] == Decimal("100.50")
