"""Walidacja biznesowa XML FA(3) wobec kontraktu schematu.

Pakiet dostarcza jedno miejsce, w którym sprawdzane są ograniczenia pól FA(3)
wynikające ze schematu `schemat_FA(3)_v1-0E.xsd`:

* :mod:`~ksef_client.documents.fa3.validation.facets` — deklaratywna tabela
  ograniczeń (typy, długości, precyzje, słowniki, liczności),
* :mod:`~ksef_client.documents.fa3.validation.engine` — generyczny silnik
  walidujący wygenerowane drzewo XML.

Walidacja jest uruchamiana przez `to_xml(validate=True)` i zwraca komunikaty
wskazujące ścieżkę elementu, zamiast surowego błędu `SCHEMAV_CVC_*`. Pełna
walidacja XSD (`xsd_validate=True`) pozostaje dostępna jako ostateczny arbiter.
"""

from __future__ import annotations

from .engine import FacetIssue, validate_xml_facets
from .facets import (
    ELEMENT_FACETS,
    OCCURRENCE_LIMITS,
    REQUIRED_IN_PARENT,
    ElementFacet,
    Facet,
    FacetKind,
    facet_for,
    occurrence_limit,
)

__all__ = [
    "ELEMENT_FACETS",
    "OCCURRENCE_LIMITS",
    "REQUIRED_IN_PARENT",
    "ElementFacet",
    "Facet",
    "FacetIssue",
    "FacetKind",
    "facet_for",
    "occurrence_limit",
    "validate_xml_facets",
]
