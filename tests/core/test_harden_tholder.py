# -*- encoding: utf-8 -*-
"""
tests.core.test_harden_tholder

Regression tests for census Cluster 3 (findings A-26, A-27, and Experiment 3's
NEG/IF/FR families): Tholder is the most defect-dense surface in the study.

Two problems:
  1. Hostile `sith` produced RAW Python exceptions that escape `except KeriError`
     -- ZeroDivisionError ("1/0"), OverflowError ("inf"), TypeError (float sith),
     and ValueError (negative, out-of-range, non-numeric, empty, sum<1, huge
     fraction). These are narrowed to kering.ValidationError.
  2. Some pathological-but-not-crashing thresholds were accepted silently
     (thousands of clauses / weights). A sane clause/weight count is enforced.

Tholder raises kering.ValidationError (an existing KeriError subclass) for
these failures, so hostile input no longer escapes `except KeriError`.

Seeded from hardening/probes/probe_part_a.py and probe_numeric_size.py.
"""
import pytest

from keri import kering
from keri.core import coring
from keri.core.coring import Tholder


# ---- raw-exception cases now narrowed to ValidationError --------------------

@pytest.mark.parametrize("sith, cid", [
    (["1/0"], "FR-1/A-26a zero denominator (was ZeroDivisionError)"),
    ([["1/2", "1/0"]], "A-26b zero denominator nested (was ZeroDivisionError)"),
    (["1/" + "9" * 400], "A-26c huge-int fraction (was ValueError)"),
    ([f"{7**200}/{3**300}"], "FR-3 coprime giants (was ValueError)"),
    (["inf"], "FR-9 non-finite inf (was OverflowError)"),
    (["nan/1"], "FR-10 nan (was ValueError)"),
    (["1/4", "1/4"], "FR-7 weights sum < 1 (was ValueError)"),
    ({"a": 1}, "A-27a wrong datatype dict (was ValueError)"),
    ("-1", "A-27b/NEG-3 negative hex (was ValueError)"),
    ([], "A-27c empty list (was ValueError)"),
    ([[]], "A-27d empty clause (was ValueError)"),
    (["-1/2", "1/2"], "NEG-4 negative fraction (was ValueError)"),
    (2.0, "IF-4 integer given as float (was TypeError)"),
    ("2.0", "IF-5 float-shaped hex string (was ValueError)"),
    ([0.5, 0.5], "IF-6 float weight (was ValueError)"),
])
def test_tholder_hostile_sith_raises_keri_error(sith, cid):
    with pytest.raises(kering.ValidationError):
        Tholder(sith=sith)


def test_tholder_hostile_sith_is_keri_error():
    """The narrowed error is a ValidationError, hence a KeriError, so it is
    caught by every `except KeriError` guard (P6: no longer a builtin
    ValueError subclass)."""
    with pytest.raises(kering.KeriError):
        Tholder(sith=["1/0"])


def test_tholder_deep_json_sith_rejected():
    """P3: a deeply-nested sith string overflowed the C stack inside json.loads
    (raw RecursionError); the length is bounded before json.loads runs."""
    with pytest.raises(kering.ValidationError):
        Tholder(sith="[" * 100000)


def test_tholder_weight_product_blowup_rejected():
    """P4: Limit bounds clause count and per-clause weight count independently
    but not their product; [["1/1000"]*1000]*1000 (~10 MB, ~1e6 Fractions) was
    accepted.  A cap on the total leaf/weight count across all clauses rejects
    it before any Fraction is built."""
    with pytest.raises(kering.ValidationError):
        Tholder(sith=[["1/1000"] * 1000] * 1000)


def test_tholder_large_but_reasonable_still_accepted():
    """P4 narrowing proof: a legitimately large multisig threshold (well under
    the total-leaf cap) is still accepted."""
    tholder = Tholder(sith=["1/100"] * 100)  # 100 signers, sums to 1
    assert tholder.weighted
    assert tholder.size == 100


# ---- silently-accepted pathological thresholds now bounded ------------------

def test_tholder_too_many_weights_rejected():
    """FR-4: thousands of weighted clauses were accepted silently."""
    with pytest.raises(kering.ValidationError):
        Tholder(sith=["1/1000"] * 5000)


def test_tholder_too_many_clauses_rejected():
    """FR-5: thousands of nested clauses were accepted silently."""
    with pytest.raises(kering.ValidationError):
        Tholder(sith=[["1/2", "1/2"]] * 2000)


# ---- narrowing proof: valid input is UNCHANGED ------------------------------

def test_tholder_valid_weighted_unchanged():
    """Valid weighted threshold produces identical thold/size/limen."""
    from fractions import Fraction
    tholder = Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4"])
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.thold == [[Fraction(1, 2), Fraction(1, 2),
                              Fraction(1, 4), Fraction(1, 4), Fraction(1, 4)]]
    assert tholder.limen == b'4AAFA1s2c1s2c1s4c1s4c1s4'


def test_tholder_valid_numeric_unchanged():
    """Valid numeric thresholds behave exactly as before."""
    tholder = Tholder(sith="b")
    assert not tholder.weighted
    assert tholder.thold == 11
    assert tholder.limen == b'MAAL'

    tholder = Tholder(sith=2)
    assert not tholder.weighted
    assert tholder.thold == 2


def test_tholder_sum_over_one_still_legal():
    """Weights summing to > 1 (e.g. 3/4 + 3/4) are legal KERI weighted-threshold
    semantics ('both signatures required'); they must remain ACCEPTED."""
    from fractions import Fraction
    tholder = Tholder(sith=["3/4", "3/4"])
    assert tholder.weighted
    assert tholder.thold == [[Fraction(3, 4), Fraction(3, 4)]]
    # only both together satisfy (3/4 alone < 1); either alone does not
    assert tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[0])
