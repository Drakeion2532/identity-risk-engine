# Copyright (c) 2026 Shubhan Punde · https://github.com/Drakeion2532/identity-risk-engine · MIT licence · sp2532-568b979deb29
"""Keeps the authorship metadata intact (see LICENSE)."""
import irisk


def test_authorship_metadata():
    assert irisk.__author__ == "Shubhan Punde"
    assert irisk.__provenance__ == "sp2532-568b979deb29"
