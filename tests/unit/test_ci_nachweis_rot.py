"""Absichtlich fehlschlagender Test: Nachweis, dass build-test rot wird (KAN-11)."""


def test_ci_nachweis_fehlschlag() -> None:
    ergebnis = 1 + 1
    assert ergebnis == 3, "absichtlicher Fehlschlag fuer KAN-11-Nachweis"
