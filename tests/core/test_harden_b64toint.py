# -*- encoding: utf-8 -*-
"""
tests.core.test_harden_b64toint

Regression tests for census finding A-53/A-06/A-11/A-32 (Cluster 1):
helping.b64ToInt is the choke point for the soft/count/index numeric fields of
Matter/Counter/Indexer.  On any character outside the Base64 alphabet it raised
a raw KeyError, and on non-UTF-8 bytes a raw UnicodeDecodeError -- both escape
every `except KeriError` guard in the codebase.  These tests assert the desired
narrowing to a keri.kering error, and prove valid input is unchanged.

Seeded from hardening/probes/probe_part_a.py (A-53a/b, A-06, A-11, A-32).
"""
import pytest

from keri import kering
from keri.core import coring, counting, indexing
from keri.help import helping


def test_b64toint_nonb64_char_raises_keri_error():
    """A-53a: char outside the Base64 alphabet -> keri error, not raw KeyError."""
    with pytest.raises(kering.KeriError):
        helping.b64ToInt("!!")


def test_b64toint_nonutf8_bytes_raises_keri_error():
    """A-53b: non-UTF-8 bytes -> keri error, not raw UnicodeDecodeError."""
    with pytest.raises(kering.KeriError):
        helping.b64ToInt(b"\xff\xfe")


def test_matter_nonb64_soft_raises_keri_error():
    """A-11: Matter variable-size soft part with non-B64 chars."""
    with pytest.raises(kering.KeriError):
        coring.Matter(qb64b=b"4A!!" + b"A" * 40)


def test_counter_nonb64_count_raises_keri_error():
    """A-06: Counter count field with non-B64 chars."""
    with pytest.raises(kering.KeriError):
        counting.Counter(qb64b=b"-A!!")


def test_indexer_nonb64_index_raises_keri_error():
    """A-32: Indexer index field with non-B64 chars."""
    with pytest.raises(kering.KeriError):
        indexing.Indexer(qb64b=b"A!!" + b"A" * 85)


def test_b64toint_valid_input_unchanged():
    """Narrowing proof: every valid Base64 input converts to the same int."""
    # single and multi-char, str and bytes, must be identical to prior behavior
    assert helping.b64ToInt("A") == 0
    assert helping.b64ToInt("B") == 1
    assert helping.b64ToInt("BA") == 64
    assert helping.b64ToInt("__") == 4095
    assert helping.b64ToInt(b"BA") == 64
    # round-trip against intToB64 across a range
    for i in range(0, 5000, 7):
        assert helping.b64ToInt(helping.intToB64(i)) == i
