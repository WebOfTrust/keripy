# -*- encoding: utf-8 -*-
"""
tests.core.test_harden_decode

Regression tests for census Cluster 2: hard-coded `.decode()` on attacker bytes
and the error-handler double-decode.

Two decode families escaped `except KeriError` on hostile input:
  1. UnicodeDecodeError from `.decode("utf-8")` on non-UTF-8 selector/soft/count/
     index bytes (A-10 coring:1354, A-05 counting:1183, A-31 indexing:534,
     A-15 coring:2682) and from the error handlers that re-decode the binary body
     they are reporting on (A-13 coring:145, A-40 serdering:1285/1292).
  2. binascii.Error from urlsafe_b64decode on a value region whose surviving
     Base64 length is not decodable (coring:1416, indexing:611/621).

Seeded from hardening/probes/probe_part_a.py.
"""
import pytest

from keri import kering
from keri.core import coring, counting, indexing, serdering


# ---- family 1: UnicodeDecodeError from .decode() on the code selector -------

def test_matter_nonutf8_selector_raises_keri_error():
    """A-10: Matter._exfil hard-code decode, non-UTF8 selector (coring:1354)."""
    with pytest.raises(kering.KeriError):
        coring.Matter(qb64b=b"\xff" + b"A" * 43)


def test_counter_nonutf8_selector_raises_keri_error():
    """A-05: Counter._exfil hard-code decode, non-UTF8 selector (counting:1183)."""
    with pytest.raises(kering.KeriError):
        counting.Counter(qb64b=b"\xff\xff" + b"AA")


def test_indexer_nonutf8_selector_raises_keri_error():
    """A-31: Indexer._exfil hard-code decode, non-UTF8 selector (indexing:534)."""
    with pytest.raises(kering.KeriError):
        indexing.Indexer(qb64b=b"\xff" + b"A" * 90)


def test_texter_text_nonutf8_raises_keri_error():
    """A-15: Texter.text accessor decodes raw without guard (coring:2682)."""
    with pytest.raises(kering.KeriError):
        coring.Texter(raw=b"\xff\xfe\xfd").text


def test_labeler_label_nonutf8_raises_conversion_error():
    """P5: Labeler.label else-branch (code not in TagDex/BexDex, e.g. Label1)
    did a bare self.raw.decode() (coring:3333) and raised raw UnicodeDecodeError
    on non-UTF-8 raw -- the same unfixed neighbour as Texter (A-15).  Narrow via
    decodeUtf8 to ConversionError."""
    lab = coring.Labeler(raw=b"\xff", code=coring.LabelDex.Label1)
    with pytest.raises(kering.ConversionError):
        lab.label


def test_labeler_text_nonutf8_raises_conversion_error():
    """P5: Labeler.text else-branch (coring:3354), same defect."""
    lab = coring.Labeler(raw=b"\xff", code=coring.LabelDex.Label1)
    with pytest.raises(kering.ConversionError):
        lab.text


# ---- family 1: error-handler double-decode ----------------------------------

def test_coring_loads_nonutf8_json_raises_deserialize_error():
    """A-13: coring.loads JSON error handler must not itself re-decode & throw."""
    with pytest.raises(kering.DeserializeError):
        coring.loads(b"\xff\xfe{bad", kind=kering.Kinds.json)


def _cbor_body():
    sad = dict(v="", t="icp", d="", i="EA" + "A" * 42, s="0", kt="1",
               k=["DA" + "A" * 42], nt="0", n=[], bt="0", b=[], c=[], a=[])
    raw = coring.dumps(sad, kind=kering.Kinds.cbor)
    sad["v"] = kering.versify(proto=kering.Protocols.keri, pvrsn=kering.Vrsn_1_0,
                              kind=kering.Kinds.cbor, size=len(raw))
    return coring.dumps(sad, kind=kering.Kinds.cbor)


def _mgpk_body():
    sad = dict(v="", t="icp", d="", i="EA" + "A" * 42, s="0", kt="1",
               k=["DA" + "A" * 42], nt="0", n=[], bt="0", b=[], c=[], a=[])
    raw = coring.dumps(sad, kind=kering.Kinds.mgpk)
    sad["v"] = kering.versify(proto=kering.Protocols.keri, pvrsn=kering.Vrsn_1_0,
                              kind=kering.Kinds.mgpk, size=len(raw))
    return coring.dumps(sad, kind=kering.Kinds.mgpk)


def test_serder_cbor_body_handler_no_double_decode():
    """A-40-cbor: the CBOR DeserializeError handler must not re-decode binary."""
    with pytest.raises(kering.KeriError):
        serdering.SerderKERI(raw=_cbor_body())


def test_serder_mgpk_body_handler_no_double_decode():
    """A-40-mgpk: the MsgPack DeserializeError handler must not re-decode binary."""
    with pytest.raises(kering.KeriError):
        serdering.SerderKERI(raw=_mgpk_body())


# ---- family 2: binascii.Error from urlsafe_b64decode ------------------------

def test_matter_bad_base64_value_raises_keri_error():
    """binascii.Error @coring:1416 -- value region not Base64-decodable."""
    with pytest.raises(kering.KeriError):
        coring.Matter(qb64b="B" + "=" * 43)


def test_indexer_bad_base64_value_raises_keri_error():
    """binascii.Error @indexing:611 -- value region not Base64-decodable."""
    with pytest.raises(kering.KeriError):
        indexing.Indexer(qb64b="A" + "A" + "A" + "!" * 85)


# ---- narrowing proof: valid input unchanged ---------------------------------

def test_valid_decode_paths_unchanged():
    """Valid primitives still round-trip identically after the narrowing."""
    m = coring.Matter(raw=b"\x00" * 32, code=coring.MtrDex.Ed25519_Seed)
    assert coring.Matter(qb64=m.qb64).raw == m.raw
    assert coring.Matter(qb64=m.qb64).code == m.code

    c = counting.Counter(count=3, code=counting.Codens.ControllerIdxSigs)
    assert counting.Counter(qb64=c.qb64).count == 3

    t = coring.Texter(text="hello world")
    assert t.text == "hello world"

    # Labeler with valid UTF-8 label/text still decodes identically
    lab = coring.Labeler(label="field_1")
    assert lab.label == "field_1"
    assert coring.Labeler(text="hi").text == "hi"

    # valid JSON body round-trips through loads
    raw = coring.dumps(dict(a=1, b="x"), kind=kering.Kinds.json)
    assert coring.loads(raw, kind=kering.Kinds.json) == dict(a=1, b="x")
