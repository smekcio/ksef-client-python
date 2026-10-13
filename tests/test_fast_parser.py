"""Unit tests for fast_extract_ksef_metadata function."""

import xml.etree.ElementTree as ET
from decimal import Decimal

import pytest

from ksef_client.utils.fast_parser import fast_extract_ksef_metadata

KSEF_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/">
    <Podmiot1><DaneIdentyfikacyjne><NIP>5260250995</NIP></DaneIdentyfikacyjne></Podmiot1>
    <Podmiot2><DaneIdentyfikacyjne><NIP>1234567890</NIP></DaneIdentyfikacyjne></Podmiot2>
    <Fa>
        <FaWiersz><P_11>100.50</P_11><P_11A>123.615</P_11A></FaWiersz>
        <FaWiersz><P_11>200.75</P_11><P_11Vat>23.115</P_11Vat></FaWiersz>
        <FaWiersz><P_11>invalid</P_11></FaWiersz>
    </Fa>
</Faktura>
"""

KSEF_INJECTION_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/">
    <Podmiot1>
        <DaneIdentyfikacyjne><NIP>5260250995</NIP></DaneIdentyfikacyjne>
        <!-- <NIP>9999999999</NIP> --><![CDATA[<NIP>8888888888</NIP>]]>
    </Podmiot1>
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
    with pytest.raises(ET.ParseError):
        fast_extract_ksef_metadata(KSEF_MALFORMED_SAMPLE)


def test_fast_extract_ksef_metadata_empty_stream():
    with pytest.raises(ET.ParseError):
        fast_extract_ksef_metadata("")


def test_fast_extract_ksef_metadata_buffered_io():
    import io
    stream = io.BytesIO(KSEF_SAMPLE.encode("utf-8"))
    res = fast_extract_ksef_metadata(stream)
    assert res["seller_nip"] == "5260250995"
    assert res["total_netto"] == Decimal("301.25")


def test_fast_extract_ksef_metadata_too_long_p11():
    xml = '<Faktura><Fa><FaWiersz><P_11>' + '1' * 35 + '</P_11></FaWiersz></Fa></Faktura>'
    with pytest.raises(ValueError, match="zbyt długa"):
        fast_extract_ksef_metadata(xml)


KSEF_P_11A_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura><Fa>
  <FaWiersz><P_8B>1</P_8B><P_11A>2000</P_11A><P_12>23</P_12></FaWiersz>
  <FaWiersz><P_8B>1</P_8B><P_11A>1000</P_11A><P_12>23</P_12></FaWiersz>
</Fa></Faktura>
"""

KSEF_KOR_ROZ_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Faktura><Fa>
  <FaWiersz><NrWierszaFa>1</NrWierszaFa><P_11>307500</P_11><StanPrzed>1</StanPrzed></FaWiersz>
  <FaWiersz><NrWierszaFa>1</NrWierszaFa><P_11>307500</P_11></FaWiersz>
  <FaWiersz><NrWierszaFa>2</NrWierszaFa><P_11>4500</P_11><StanPrzed>1</StanPrzed></FaWiersz>
  <FaWiersz><NrWierszaFa>2</NrWierszaFa><P_11>4500</P_11></FaWiersz>
</Fa></Faktura>
"""


def test_fast_extract_ksef_metadata_handles_gross_only_lines():
    """Faktury z art. 106e ust. 7 i 8 mają `P_11A`, a nie `P_11`.

    Wcześniej parser dopasowywał wyłącznie `P_11` (dokładne porównanie), więc dla
    takich dokumentów zwracał `total_netto=0.00` i `item_count=0` bez sygnału.
    """
    res = fast_extract_ksef_metadata(KSEF_P_11A_SAMPLE)
    assert res["item_count"] == 2
    assert res["total_brutto"] == Decimal("3000")
    assert res["total_netto"] == Decimal("0.00")


def test_fast_extract_ksef_metadata_skips_before_correction_rows():
    """`StanPrzed` to stan przed korektą — nie może wchodzić do sumy.

    Wcześniej korekta (KOR_ROZ) liczyła oba stany, więc `total_netto` był
    podwojony (624000 zamiast 312000) i sprzeczny z podsumowaniem dokumentu.
    """
    res = fast_extract_ksef_metadata(KSEF_KOR_ROZ_SAMPLE)
    assert res["total_netto"] == Decimal("312000")
    assert res["item_count"] == 4
    assert res["stan_przed_item_count"] == 2
