"""Jawne mapy ścieżek schematu FA(3), których nie da się wyprowadzić z kodu.

Moduł istnieje po to, by audyt (`xsd_audit`) miał gdzie zapisać ŚWIADOMĄ decyzję
o ścieżce, której nie opisuje ani obecność znacznika w serializatorze, ani dowód
z testów. Dwie mapy są puste i — zgodnie z pomiarem na schemacie FA(3) v1-0E —
puste pozostają, bo SDK nie ma takich ścieżek:

* ``RAW_EXTENSION_PATHS`` — ścieżki przekazywane bez interpretacji. Typowane SDK
  odrzuca surowy XML: ``RawXmlExtension`` (domain.py) trafia do ``raw_extensions``
  faktury, ale ``FA3Invoice.validate`` zwraca dla niego błąd „RawXmlExtension nie
  jest wspierany w typed FA(3) SDK", a ``xml.py`` w ogóle nie czyta tego pola —
  serializer nie ma więc żadnego przejścia typu pass-through.
* ``UNSUPPORTED_PATHS`` — ścieżki, których serializer nie potrafi wypisać. Audyt
  rozpoznaje to sam: znacznik nieobecny w `xml.py` dostaje status ``unsupported``
  (xsd_audit._emitted_tags). Na obecnym schemacie wszystkie 288 nazw elementów ma
  miejsce emisji, więc ręcznych wyjątków nie ma; mapa jest miejscem na wyjątek,
  gdyby jakiś element schematu świadomie zostawał nieobsługiwany.

Dopóki mapy są puste, gałęzie ``raw_extension`` i ``unsupported`` w audycie
(test `test_xsd_audit_covers_raw_extension_unsupported_and_notes`) są ćwiczone
przez monkeypatch tych dwóch nazw — inaczej nie dałoby się ich przetestować.
Gdy mapa przestanie być pusta, test `test_section_factories_xsd_map_and_audit_edges`
wymaga aktualizacji (asercja ``RAW_EXTENSION_PATHS == {}``).
"""

from __future__ import annotations

#: Historyczna mapa „ścieżka -> opis", której audyt już NIE używa: miała jeden wpis
#: ``/Faktura`` dopasowywany prefiksem, więc obejmowała cały dokument i każdy
#: element — także wymyślony — wychodził jako pokryty. Zostaje, bo importują ją
#: testy; audyt bierze pokrycie z rzeczywistych miejsc emisji (`xsd_audit`).
SUPPORTED_BUILDER_PATHS: dict[str, str] = {
    "/Faktura": "full typed FA(3) SDK coverage generated from XSD",
}

#: Ścieżki przekazywane bez interpretacji — patrz docstring modułu (pusta: brak
#: mechanizmu pass-through w SDK).
RAW_EXTENSION_PATHS: dict[str, str] = {}

#: Ścieżki świadomie nieobsługiwane — patrz docstring modułu (pusta: serializer
#: wypisuje każdy znacznik schematu, a braki wykrywa `xsd_audit._emitted_tags`).
UNSUPPORTED_PATHS: dict[str, str] = {}


__all__ = ["RAW_EXTENSION_PATHS", "SUPPORTED_BUILDER_PATHS", "UNSUPPORTED_PATHS"]
