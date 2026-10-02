# -*- encoding: utf-8 -*-
"""
tests.core.test_harden_pather

Regression tests for census finding A-17 (Cluster 4a): Pather._resolve walks a
SAD following a caller-supplied path and raised raw KeyError / ValueError /
TypeError on a hostile path, and recursed with no depth cap.  These escape every
`except KeriError` guard.  Narrow them to kering.InvalidValueError (the error
Pather construction already uses) and cap the path depth.

Seeded from hardening/probes/probe_part_a.py (A-17a/b/c/d).
"""
import pytest

from keri import kering
from keri.core import coring
from keri.core.coring import Pather


def test_pather_nondigit_list_index_raises_keri_error():
    """A-17a: non-digit index into a list (was raw ValueError @coring:3182)."""
    with pytest.raises(kering.KeriError):
        Pather(path=["a", "notanint"]).resolve({"a": [1, 2, 3]})


def test_pather_missing_key_raises_keri_error():
    """A-17b: missing dict key (was raw KeyError @coring:3179)."""
    with pytest.raises(kering.KeriError):
        Pather(path=["nope"]).resolve({"a": 1})


def test_pather_scalar_where_container_expected_raises_keri_error():
    """A-17c: traverse into a scalar (was raw KeyError @coring:3189)."""
    with pytest.raises(kering.KeriError):
        Pather(path=["a", "b"]).resolve({"a": 5})


def test_pather_deep_path_raises_keri_error():
    """A-17d: pathological path depth is capped, not run to RecursionError."""
    with pytest.raises(kering.KeriError):
        Pather(path=["a"] * 5000).resolve({"a": 1})


def test_pather_nonutf8_raw_accessors_raise_invalid_value_error():
    """P1: a Pather whose code is not in BexDex (here Salt_128 '0A') carries
    arbitrary raw bytes; .path/.parts/.rparts did a bare self.raw.decode() and
    raised raw UnicodeDecodeError before _resolve ran.  Narrow to
    InvalidValueError (Pather's own convention)."""
    pather = Pather(qb64="0AD_____________________")  # 0xff... raw, non-UTF-8

    with pytest.raises(kering.InvalidValueError):
        pather.path
    with pytest.raises(kering.InvalidValueError):
        pather.parts
    with pytest.raises(kering.InvalidValueError):
        pather.rparts
    # resolve() reaches the raw decode through .rparts, so it too is narrowed
    with pytest.raises(kering.InvalidValueError):
        pather.resolve({"a": 1})


def test_pather_valid_resolution_unchanged():
    """Narrowing proof: valid path resolution is unchanged."""
    sad = {"a": {"b": {"c": "test"}}}
    assert Pather(path=["a", "b", "c"]).resolve(sad) == "test"
    assert Pather(path=["a", "b"]).resolve(sad) == {"c": "test"}

    # digit index into a dict selects the nth key; into a list selects element
    assert Pather(path=["0"]).resolve({"x": 1, "y": 2}) == 1
    assert Pather(path=["a", "1"]).resolve({"a": [10, 20, 30]}) == 20

    # empty relative path returns the whole component
    assert Pather(path=[]).resolve(sad) == sad
