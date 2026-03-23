# -*- encoding: utf-8 -*-
"""
tests.db.test_webdbing module

"""

import asyncio
from dataclasses import asdict, dataclass
from typing import Any
import json

import pytest

try:
    from keri.db.webdbing import (
        WebDBer,
        _META_KEY,
        _RECORDS_KEY,
        _deserialize_meta,
        _deserialize_records,
        _serialize_meta,
        _serialize_records,
        onKey,
        splitOnKey,
        WebBaser,
    )
    from keri.db import webdbing as webdbing_module
except ImportError:
    from keri.db.webdbing import (  # standalone import for Pyodide
        WebDBer,
        _META_KEY,
        _RECORDS_KEY,
        _deserialize_meta,
        _deserialize_records,
        _serialize_meta,
        _serialize_records,
        onKey,
        splitOnKey,
    )
    import keri.db.webdbing as webdbing_module

try:
    from keri.db import subing, koming, dgKey, snKey
except ImportError:
    subing = None
    koming = None

try:
    from keri.core import serdering, coring, signing, indexing
    from keri import versify, Kinds
    from keri.recording import EventSourceRecord
    from keri import core
except ImportError:
    # Pyodide fallback
    from keri.core import serdering

needskeri = pytest.mark.skipif(subing is None, reason="requires full keri (lmdb)")


class FakeStorageHandle:
    """Async storage handle with local writes and explicit sync commit."""

    def __init__(self, backend, namespace):
        self.backend = backend
        self.namespace = namespace
        self._local = dict(self.backend.persisted.get(namespace, {}))

    def get(self, key, default=None):
        return self._local.get(key, default)

    def __getitem__(self, key):
        return self._local[key]

    def __setitem__(self, key, value):
        self._local[key] = value

    def clear(self):
        """Remove all keys from the local storage buffer."""
        self._local.clear()

    async def sync(self):
        self.backend.persisted[self.namespace] = dict(self._local)


class FakeStorageBackend:
    """Minimal async opener that mimics PyScript storage commit semantics."""

    def __init__(self):
        self.persisted = {}

    async def open(self, namespace):
        return FakeStorageHandle(self, namespace)


async def _open_fake_dber(*, name="test-webdber", stores=None,
                          clear=False, backend=None):
    if backend is None:
        backend = FakeStorageBackend()
    dber = await WebDBer.open(
        name=name,
        stores=stores or ["bags.", "docs.", "beep.", "pugs."],
        clear=clear,
        storageOpener=backend.open,
    )
    return dber, backend


def test_open_declares_stores_and_clear():
    """Test open() store declaration, persisted reload, and clear reset."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(
            name="open-clear", stores=["bags.", "docs."],
            clear=True, backend=backend,
        )
        assert dber.name == "open-clear"
        assert dber.stores == ["bags.", "docs."]

        bags = dber.env.open_db(b"bags.")
        docs = dber.env.open_db("docs.")
        assert bags.namespace == "open-clear:bags."
        assert docs.namespace == "open-clear:docs."
        assert dber.cntAll(bags) == 0
        assert dber.cntAll(docs) == 0
        assert await dber.flush() == 2

        assert dber.setVal(docs, b"alpha", b"one") is True
        assert await dber.flush() == 1

        reopened, _ = await _open_fake_dber(
            name="open-clear", stores=["bags.", "docs."], backend=backend,
        )
        docs_reopened = reopened.env.open_db("docs.")
        assert reopened.getVal(docs_reopened, b"alpha") == b"one"

        cleared, _ = await _open_fake_dber(
            name="open-clear", stores=["bags.", "docs."],
            clear=True, backend=backend,
        )
        docs_cleared = cleared.env.open_db("docs.")
        assert cleared.getVal(docs_cleared, b"alpha") is None
        assert cleared.cntAll(docs_cleared) == 0

    asyncio.run(_go())


def test_open_requires_storage_backend():
    """Test open() fails without storage backend."""
    async def _go():
        original = webdbing_module.storage
        webdbing_module.storage = None
        try:
            with pytest.raises(RuntimeError, match="pyscript.storage is unavailable"):
                await WebDBer.open(name="missing-storage", stores=["docs."])
        finally:
            webdbing_module.storage = original

    asyncio.run(_go())


def test_open_db_flag_persistence():
    """Test dupsort latching is stable in-process and persists across reopen."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(stores=["bags.", "docs."],
                                        clear=True, backend=backend)

        bags = dber.env.open_db(b"bags.", dupsort=False)
        assert bags.flags()["dupsort"] is False
        assert bags.dirty is True

        same = dber.env.open_db("bags.", dupsort=True)
        assert same is bags
        assert same.flags()["dupsort"] is False

        docs = dber.env.open_db("docs.", dupsort=True)
        assert docs.flags()["dupsort"] is True
        assert await dber.flush() == 2

        reopened, _ = await _open_fake_dber(stores=["bags.", "docs."],
                                            backend=backend)
        bags_reopened = reopened.env.open_db("bags.", dupsort=True)
        docs_reopened = reopened.env.open_db("docs.", dupsort=False)
        assert bags_reopened.flags()["dupsort"] is False
        assert docs_reopened.flags()["dupsort"] is True

    asyncio.run(_go())


def test_open_db_metadata_only_flush():
    """Test first-open dupsort metadata flushes even before any record writes."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(name="meta-only", stores=["docs."],
                                        clear=True, backend=backend)

        docs = dber.env.open_db("docs.", dupsort=True)
        assert docs.flags()["dupsort"] is True
        assert docs.dirty is True
        assert await dber.flush() == 1
        assert docs.dirty is False
        assert _deserialize_meta(
            backend.persisted["meta-only:docs."][_META_KEY]) == {"dupsort": True}
        assert _deserialize_records(
            backend.persisted["meta-only:docs."][_RECORDS_KEY]) == {}

        reopened, _ = await _open_fake_dber(name="meta-only", stores=["docs."],
                                            backend=backend)
        docs_reopened = reopened.env.open_db("docs.", dupsort=False)
        assert docs_reopened.flags()["dupsort"] is True

    asyncio.run(_go())


def test_clear_resets_metadata():
    """Test clear=True drops persisted dupsort metadata and allows relatching."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(name="clear-meta", stores=["docs."],
                                        clear=True, backend=backend)

        docs = dber.env.open_db("docs.", dupsort=True)
        assert await dber.flush() == 1

        cleared, _ = await _open_fake_dber(name="clear-meta", stores=["docs."],
                                           clear=True, backend=backend)
        docs_cleared = cleared.env.open_db("docs.", dupsort=False)
        assert docs_cleared.flags()["dupsort"] is False
        assert await cleared.flush() == 1

        reopened, _ = await _open_fake_dber(name="clear-meta", stores=["docs."],
                                            backend=backend)
        docs_reopened = reopened.env.open_db("docs.", dupsort=True)
        assert docs_reopened.flags()["dupsort"] is False

    asyncio.run(_go())


def test_open_rejects_missing_metadata():
    """Test open() fails on non-empty stores missing flag metadata."""
    async def _go():
        backend = FakeStorageBackend()
        backend.persisted["legacy:docs."] = {
            _RECORDS_KEY: _serialize_records({b"alpha": b"one"}),
        }

        with pytest.raises(ValueError, match="Persisted store metadata missing"):
            await WebDBer.open(
                name="legacy", stores=["docs."],
                storageOpener=backend.open,
            )

    asyncio.run(_go())


def test_open_db_rejects_unconfigured():
    """Test open_db rejects stores not declared at open time."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["bags."], clear=True)

        with pytest.raises(KeyError, match="Store not configured"):
            dber.env.open_db("docs.")

    asyncio.run(_go())


def test_storify():
    """Test store-handle normalization."""
    assert WebDBer._storify("docs.") == "docs."
    assert WebDBer._storify(b"bags.") == "bags."

    with pytest.raises(TypeError, match="Unsupported store handle type"):
        WebDBer._storify(lambda: None)


def test_serialize_deserialize():
    """Test record and metadata serialization helpers."""
    records = {b"b": b"\x02", b"a": b"\x01"}
    serialized = _serialize_records(records)
    assert serialized == '{"61": "01", "62": "02"}'
    meta = {"dupsort": True}
    serialized_meta = _serialize_meta(meta)
    assert serialized_meta == '{"dupsort": true}'

    assert _deserialize_records(None) == {}
    assert _deserialize_records("") == {}
    assert _deserialize_records(serialized) == {b"a": b"\x01", b"b": b"\x02"}
    assert _deserialize_records(serialized.encode("utf-8")) == {b"a": b"\x01", b"b": b"\x02"}
    assert _deserialize_records(memoryview(serialized.encode("utf-8"))) == {
        b"a": b"\x01", b"b": b"\x02",
    }
    assert _deserialize_records({"61": "31"}) == {b"a": b"1"}
    assert _deserialize_meta(None) == {}
    assert _deserialize_meta("") == {}
    assert _deserialize_meta(serialized_meta) == meta
    assert _deserialize_meta(serialized_meta.encode("utf-8")) == meta
    assert _deserialize_meta(memoryview(serialized_meta.encode("utf-8"))) == meta
    assert _deserialize_meta(meta) == meta

    with pytest.raises(TypeError, match="Unsupported persisted record payload type"):
        _deserialize_records(42)
    with pytest.raises(TypeError, match="Unsupported persisted metadata payload type"):
        _deserialize_meta(42)


def test_val_crud():
    """Test Val CRUD semantics and dirty flags."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["docs."], clear=True)
        docs = dber.env.open_db("docs.")

        assert docs.dirty is True
        assert await dber.flush() == 1
        assert docs.dirty is False
        assert dber.getVal(docs, b"alpha") is None
        assert docs.dirty is False
        assert dber.remVal(docs, b"alpha") is False
        assert docs.dirty is False

        assert dber.putVal(docs, b"alpha", b"one") is True
        assert docs.dirty is True
        assert dber.getVal(docs, b"alpha") == b"one"
        assert await dber.flush() == 1
        assert docs.dirty is False

        assert dber.putVal(docs, b"alpha", b"shadow") is False
        assert docs.dirty is False

        assert dber.setVal(docs, b"\xff\x00", b"\x01\x02") is True
        assert docs.dirty is True
        assert dber.getVal(docs, b"\xff\x00") == b"\x01\x02"
        assert await dber.flush() == 1
        assert docs.dirty is False

        assert dber.setVal(docs, b"alpha", b"two") is True
        assert docs.dirty is True
        assert dber.getVal(docs, b"alpha") == b"two"
        assert await dber.flush() == 1
        assert docs.dirty is False

        assert dber.remVal(docs, b"alpha") is True
        assert docs.dirty is True
        assert dber.getVal(docs, b"alpha") is None
        assert await dber.flush() == 1
        assert docs.dirty is False

        assert dber.remVal(docs, b"alpha") is False
        assert docs.dirty is False

    asyncio.run(_go())


def test_empty_key_errors():
    """Test LMDB-compatible empty-key validation."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["docs."], clear=True)
        docs = dber.env.open_db("docs.")

        with pytest.raises(KeyError, match="empty"):
            dber.putVal(docs, b"", b"val")
        with pytest.raises(KeyError, match="empty"):
            dber.setVal(docs, b"", b"val")
        with pytest.raises(KeyError, match="empty"):
            dber.getVal(docs, b"")

        assert dber.remVal(docs, b"") is False

    asyncio.run(_go())


def test_prefix_iteration():
    """Test lexical prefix iteration and whole-store count."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["docs."], clear=True)
        docs = dber.env.open_db("docs.")

        assert dber.setVal(docs, b"a.1", b"blue") is True
        assert dber.setVal(docs, b"a.2", b"green") is True
        assert dber.setVal(docs, b"ac.4", b"white") is True
        assert dber.setVal(docs, b"b.1", b"red") is True
        assert dber.setVal(docs, b"bc.3", b"black") is True

        assert list(dber.getTopItemIter(docs)) == [
            (b"a.1", b"blue"),
            (b"a.2", b"green"),
            (b"ac.4", b"white"),
            (b"b.1", b"red"),
            (b"bc.3", b"black"),
        ]
        assert list(dber.getTopItemIter(docs, b"a.")) == [
            (b"a.1", b"blue"),
            (b"a.2", b"green"),
        ]
        assert list(dber.getTopItemIter(docs, b"ac")) == [(b"ac.4", b"white")]
        assert list(dber.getTopItemIter(docs, b"z")) == []
        assert dber.cntAll(docs) == 5

    asyncio.run(_go())


def test_del_top():
    """Test prefix and whole-store deletion semantics."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["docs."], clear=True)
        docs = dber.env.open_db("docs.")

        assert dber.setVal(docs, b"a.1", b"blue") is True
        assert dber.setVal(docs, b"a.2", b"green") is True
        assert dber.setVal(docs, b"b.1", b"red") is True
        assert await dber.flush() == 1
        assert docs.dirty is False

        assert dber.delTop(docs, b"z.") is False
        assert docs.dirty is False

        assert dber.delTop(docs, b"a.") is True
        assert docs.dirty is True
        assert list(dber.getTopItemIter(docs)) == [(b"b.1", b"red")]
        assert await dber.flush() == 1

        assert dber.delTop(docs) is True
        assert list(dber.getTopItemIter(docs)) == []
        assert await dber.flush() == 1

        assert dber.delTop(docs) is False
        assert docs.dirty is False

    asyncio.run(_go())


def test_flush_persistence():
    """Test unsynced vs synced reopen visibility."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(name="flush-sem", stores=["docs."],
                                        clear=True, backend=backend)
        docs = dber.env.open_db("docs.")

        assert await dber.flush() == 1
        assert await dber.flush() == 0

        assert dber.setVal(docs, b"alpha", b"one") is True

        reopened_before, _ = await _open_fake_dber(
            name="flush-sem", stores=["docs."], backend=backend,
        )
        docs_before = reopened_before.env.open_db("docs.")
        assert reopened_before.getVal(docs_before, b"alpha") is None

        assert await dber.flush() == 1
        assert await dber.flush() == 0

        assert dber.setVal(docs, b"alpha", b"two") is True
        reopened_unsynced, _ = await _open_fake_dber(
            name="flush-sem", stores=["docs."], backend=backend,
        )
        docs_unsynced = reopened_unsynced.env.open_db("docs.")
        assert reopened_unsynced.getVal(docs_unsynced, b"alpha") == b"one"

        assert await dber.flush() == 1
        reopened_after, _ = await _open_fake_dber(
            name="flush-sem", stores=["docs."], backend=backend,
        )
        docs_after = reopened_after.env.open_db("docs.")
        assert reopened_after.getVal(docs_after, b"alpha") == b"two"

    asyncio.run(_go())


def test_flush_dirty_counting():
    """Test flush counts only dirty stores."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["bags.", "docs.", "pugs."],
                                        clear=True)
        bags = dber.env.open_db("bags.")
        docs = dber.env.open_db("docs.")
        pugs = dber.env.open_db("pugs.")
        assert await dber.flush() == 3

        assert dber.setVal(bags, b"bag.1", b"blue") is True
        assert dber.setVal(docs, b"doc.1", b"green") is True
        assert await dber.flush() == 2

        assert dber.putVal(docs, b"doc.1", b"shadow") is False
        assert dber.remVal(pugs, b"missing") is False
        assert dber.getVal(bags, b"bag.1") == b"blue"
        assert await dber.flush() == 0

        assert dber.setVal(docs, b"doc.2", b"white") is True
        assert await dber.flush() == 1
        assert await dber.flush() == 0

    asyncio.run(_go())


@pytest.mark.skip(reason="Requires hio>=0.7.20 Doist.ado() for async task integration")
def test_flush_with_hio_ado():
    """Test flush completion under hio Doist.ado() scheduling."""
    pass


@pytest.mark.skip(reason="Requires hio>=0.7.20 Doist.ado() for async task integration")
def test_flush_with_hio_ado_when_clean():
    """Test hio Doist.ado() flush when no stores are dirty."""
    pass


def test_ordinal_key_helpers():
    """Test onKey/splitOnKey from dbing.py for WebDBer use cases."""
    pre = b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"

    assert onKey(pre, 0) == pre + b"." + b"%032x" % 0
    assert onKey(pre, 1) == pre + b"." + b"%032x" % 1
    assert onKey(pre, 15) == pre + b"." + b"%032x" % 15

    assert onKey(pre, 0, sep=b"|") == pre + b"|" + b"%032x" % 0
    assert onKey(pre, 4, sep=b"|") == pre + b"|" + b"%032x" % 4

    okey = onKey(pre, 0)
    assert splitOnKey(okey) == (pre, 0)
    okey = onKey(pre, 1)
    assert splitOnKey(okey) == (pre, 1)
    okey = onKey(pre, 15)
    assert splitOnKey(okey) == (pre, 15)

    okey = onKey(pre, 0, sep=b"|")
    assert splitOnKey(okey, sep=b"|") == (pre, 0)
    okey = onKey(pre, 15, sep=b"|")
    assert splitOnKey(okey, sep=b"|") == (pre, 15)

    pre_str = "BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"

    assert onKey(pre_str, 0) == b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000000"
    assert onKey(pre_str, 15, sep=b"|") == b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc|0000000000000000000000000000000f"

    okey = onKey(pre_str, 0).decode("utf-8")
    assert splitOnKey(okey) == (pre_str, 0)
    okey = onKey(pre_str, 15).decode("utf-8")
    assert splitOnKey(okey) == (pre_str, 15)

    pre = b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
    okey = memoryview(onKey(pre, 15))
    assert splitOnKey(okey) == (pre, 15)
    okey = memoryview(onKey(pre, 15, sep=b"|"))
    assert splitOnKey(okey, sep=b"|") == (pre, 15)


def test_on_item_empty_value():
    """Test getOnItem returns triple even for empty-bytes value."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["seen."], clear=True)
        sdb = dber.env.open_db(key=b"seen.")

        pre = b"BBKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"
        assert dber.putOnVal(sdb, pre, 0, val=b"") is True
        assert dber.getOnVal(sdb, pre, 0) == b""
        assert dber.getOnItem(sdb, pre, 0) == (pre, 0, b"")

    asyncio.run(_go())


def test_on_val_contract():
    """Test ordinal CRUD, count, and remove block."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["seen."], clear=True)
        sdb = dber.env.open_db(key=b"seen.")

        preA = b"BBKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"
        preB = b"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w"

        keyA0 = onKey(preA, 0)

        digA = b"EA73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw"
        digU = b"EB73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw"
        digV = b"EC4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY"
        digW = b"EDAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w"
        digX = b"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o"
        digY = b"EFrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk"
        digC = b"EG5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w"

        assert dber.getVal(sdb, keyA0) is None
        assert dber.remVal(sdb, keyA0) is False
        assert dber.putVal(sdb, keyA0, val=digA) is True
        assert dber.getVal(sdb, keyA0) == digA
        assert dber.putVal(sdb, keyA0, val=digA) is False
        assert dber.setVal(sdb, keyA0, val=digA) is True
        assert dber.getVal(sdb, keyA0) == digA
        assert dber.getOnVal(sdb, preA, 0) == digA
        assert dber.remVal(sdb, keyA0) is True
        assert dber.getVal(sdb, keyA0) is None
        assert dber.getOnVal(sdb, preA, 0) is None

        assert dber.putOnVal(sdb, preA, 0, val=digA) is True
        assert dber.getOnVal(sdb, preA, 0) == digA
        assert dber.getOnItem(sdb, preA, 0) == (preA, 0, digA)
        assert dber.putOnVal(sdb, preA, 0, val=digA) is False
        assert dber.pinOnVal(sdb, preA, 0, val=digA) is True
        assert dber.getOnVal(sdb, preA, 0) == digA
        assert dber.getOnItem(sdb, preA, 0) == (preA, 0, digA)
        assert dber.remOn(sdb, preA, 0) is True
        assert dber.getOnVal(sdb, preA, 0) is None
        assert dber.getOnItem(sdb, preA, 0) is None

        assert dber.putOnVal(sdb, preA, 0, val=digA) is True
        assert dber.putOnVal(sdb, preA, 1, val=digC) is True
        assert dber.putOnVal(sdb, preA, 2, val=digU) is True
        assert dber.putOnVal(sdb, preA, 3, val=digV) is True
        assert dber.putOnVal(sdb, preA, 4, val=digW) is True
        assert dber.putOnVal(sdb, preB, 0, val=digX) is True
        assert dber.putOnVal(sdb, preB, 1, val=digY) is True

        assert dber.cntOnAll(sdb, preA) == 5
        assert dber.cntOnAll(sdb, preB) == 2
        assert dber.cntOnAll(sdb) == 7

        assert dber.remOnAll(sdb, preA, on=3) is True
        assert dber.cntOnAll(sdb, preA) == 3
        assert dber.cntOnAll(sdb, preB) == 2

        assert dber.remOnAll(sdb, preA) is True
        assert dber.cntOnAll(sdb, preA) == 0
        assert dber.cntOnAll(sdb, preB) == 2

        assert dber.remOnAll(sdb) is True
        assert dber.cntOnAll(sdb) == 0

    asyncio.run(_go())


def test_append_on_iter_contract():
    """Test append and iterator block."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["seen."], clear=True)
        sdb = dber.env.open_db(key=b"seen.")

        preA = b"BBKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"
        preB = b"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w"
        preC = b"EIDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg"
        preD = b"EAYC49i5zY_qrIZIicQgIDA1n-WiBA0A8YOqnKrB-wWQ"

        keyA0 = onKey(preA, 0)
        keyB0 = onKey(preB, 0)
        keyB1 = onKey(preB, 1)
        keyB2 = onKey(preB, 2)
        keyB3 = onKey(preB, 3)
        keyB4 = onKey(preB, 4)
        keyC0 = onKey(preC, 0)

        digA = b"EA73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw"
        digU = b"EB73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw"
        digV = b"EC4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY"
        digW = b"EDAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w"
        digX = b"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o"
        digY = b"EFrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk"
        digC = b"EG5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w"

        assert dber.getVal(sdb, keyB0) is None
        assert dber.appendOnVal(sdb, preB, digU) == 0
        assert dber.getVal(sdb, keyB0) == digU
        assert dber.remVal(sdb, keyB0) is True
        assert dber.getVal(sdb, keyB0) is None

        assert dber.putVal(sdb, keyA0, val=digA) is True
        assert dber.appendOnVal(sdb, preB, digU) == 0
        assert dber.getVal(sdb, keyB0) == digU
        assert dber.remVal(sdb, keyB0) is True

        assert dber.putVal(sdb, keyC0, val=digC) is True
        assert dber.appendOnVal(sdb, preB, digU) == 0
        assert dber.getVal(sdb, keyB0) == digU
        assert dber.remVal(sdb, keyB0) is True

        assert dber.remVal(sdb, keyA0) is True
        assert dber.getVal(sdb, keyC0) == digC
        assert dber.appendOnVal(sdb, preB, digU) == 0
        assert dber.getVal(sdb, keyB0) == digU

        assert dber.putVal(sdb, keyA0, val=digA) is True
        assert dber.appendOnVal(sdb, preB, digV) == 1
        assert dber.getVal(sdb, keyB1) == digV

        assert dber.remVal(sdb, keyA0) is True
        assert dber.remVal(sdb, keyC0) is True
        assert dber.appendOnVal(sdb, preB, digW) == 2
        assert dber.getVal(sdb, keyB2) == digW
        assert dber.appendOnVal(sdb, preB, digX) == 3
        assert dber.getVal(sdb, keyB3) == digX
        assert dber.appendOnVal(sdb, preB, digY) == 4
        assert dber.getVal(sdb, keyB4) == digY

        assert dber.appendOnVal(sdb, preD, digY) == 0

        assert dber.cntOnAll(sdb, key=preB) == 5
        assert dber.cntOnAll(sdb, key=b"") == 6
        assert dber.cntOnAll(sdb) == 6
        assert dber.cntAll(sdb) == 6

        assert list(dber.getOnAllItemIter(sdb, preB)) == [
            (preB, 0, digU), (preB, 1, digV), (preB, 2, digW),
            (preB, 3, digX), (preB, 4, digY),
        ]
        assert list(dber.getOnAllItemIter(sdb, preB, on=3)) == [
            (preB, 3, digX), (preB, 4, digY),
        ]
        assert list(dber.getOnAllItemIter(sdb, preB, on=5)) == []

        assert dber.putVal(sdb, keyA0, val=digA) is True
        assert dber.putVal(sdb, keyC0, val=digC) is True

        assert list(dber.getOnTopItemIter(sdb, top=preB)) == [
            (preB, 0, digU), (preB, 1, digV), (preB, 2, digW),
            (preB, 3, digX), (preB, 4, digY),
        ]
        assert list(dber.getOnTopItemIter(sdb)) == [
            (preA, 0, digA), (preD, 0, digY),
            (preB, 0, digU), (preB, 1, digV), (preB, 2, digW),
            (preB, 3, digX), (preB, 4, digY),
            (preC, 0, digC),
        ]
        assert list(dber.getOnAllItemIter(sdb, key=b"")) == [
            (preA, 0, digA), (preD, 0, digY),
            (preB, 0, digU), (preB, 1, digV), (preB, 2, digW),
            (preB, 3, digX), (preB, 4, digY),
            (preC, 0, digC),
        ]

        top, on = splitOnKey(keyB2)
        assert list(dber.getOnAllItemIter(sdb, key=top, on=on)) == [
            (top, 2, digW), (top, 3, digX), (top, 4, digY),
        ]
        assert list(dber.getOnAllItemIter(sdb, key=preC, on=1)) == []

        assert dber.remOn(sdb, key=preB) is True
        assert dber.remOn(sdb, key=preB, on=0) is False
        assert dber.remOn(sdb, key=preB, on=1) is True
        assert dber.remOn(sdb, key=preB, on=1) is False
        assert list(dber.getOnAllItemIter(sdb, key=preB)) == [
            (top, 2, digW), (top, 3, digX), (top, 4, digY),
        ]
        assert dber.remOn(sdb, key=b"") is False

    asyncio.run(_go())


def test_on_val_flush_persistence():
    """Test dirty flags and reopen persistence for ordinal methods."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(
            name="on-flush", stores=["ords."], clear=True, backend=backend,
        )
        ords = dber.env.open_db("ords.")

        assert await dber.flush() == 1
        assert await dber.flush() == 0

        assert dber.putOnVal(ords, b"evt", 0, b"icp") is True
        assert ords.dirty is True
        assert await dber.flush() == 1
        assert ords.dirty is False

        assert dber.putOnVal(ords, b"evt", 0, b"dup") is False
        assert ords.dirty is False

        assert dber.pinOnVal(ords, b"evt", 0, b"rot") is True
        assert ords.dirty is True
        assert await dber.flush() == 1
        assert ords.dirty is False

        assert dber.remOn(ords, b"evt", 1) is False
        assert ords.dirty is False

        assert dber.appendOnVal(ords, b"evt", b"ixn") == 1
        assert ords.dirty is True
        assert await dber.flush() == 1
        assert ords.dirty is False

        reopened, _ = await _open_fake_dber(
            name="on-flush", stores=["ords."], backend=backend,
        )
        ords_reopened = reopened.env.open_db("ords.")
        assert reopened.getOnVal(ords_reopened, b"evt", 0) == b"rot"
        assert reopened.getOnVal(ords_reopened, b"evt", 1) == b"ixn"
        assert list(reopened.getOnAllItemIter(ords_reopened, b"evt")) == [
            (b"evt", 0, b"rot"), (b"evt", 1, b"ixn"),
        ]

    asyncio.run(_go())


def test_on_val_empty_key():
    """Test ordinal empty-key behavior."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["ords."], clear=True)
        ords = dber.env.open_db("ords.")

        assert dber.putOnVal(ords, b"evt", 0, b"icp") is True
        assert dber.putOnVal(ords, b"\xff", 1, b"\x01\x02") is True
        assert dber.getOnVal(ords, b"evt", 0) == b"icp"
        assert dber.getOnVal(ords, b"\xff", 1) == b"\x01\x02"
        assert dber.getOnItem(ords, b"\xff", 1) == (b"\xff", 1, b"\x01\x02")
        assert list(dber.getOnTopItemIter(ords, b"\xff")) == [
            (b"\xff", 1, b"\x01\x02"),
        ]

        assert dber.putOnVal(ords, b"", 0, b"root") is True
        assert dber.getVal(ords, onKey(b"", 0)) == b"root"
        assert dber.getOnVal(ords, b"", 0) is None
        assert dber.getOnItem(ords, b"", 0) is None
        assert dber.pinOnVal(ords, b"", 0, b"shadow") is False
        assert dber.remOn(ords, b"", 0) is False

        with pytest.raises(ValueError, match="Bad append parameter"):
            dber.appendOnVal(ords, b"", b"bad")

        assert dber.remOnAll(ords, b"", 0) is True
        assert dber.cntAll(ords) == 0
        assert dber.remOnAll(ords, b"", 0) is False

    asyncio.run(_go())


def test_append_on_val_put_fails():
    """Test appendOnVal fails closed when final insert does not succeed."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["ords."], clear=True)
        ords = dber.env.open_db("ords.")

        assert dber.putOnVal(ords, b"evt", 0, b"icp") is True

        putVal = dber.putVal

        def reject_next_on(*, db, key, val):
            if key == onKey(b"evt", 1):
                return False
            return putVal(db=db, key=key, val=val)

        dber.putVal = reject_next_on
        try:
            with pytest.raises(ValueError, match="Failed appending"):
                dber.appendOnVal(ords, b"evt", b"rot")
        finally:
            dber.putVal = putVal

    asyncio.run(_go())


def test_append_on_val_max_overflow():
    """Test appendOnVal rejects append after MaxON."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["ords."], clear=True)
        ords = dber.env.open_db("ords.")
        maxon = int("f" * 32, 16)

        assert dber.putOnVal(ords, b"evt", maxon, b"last") is True
        with pytest.raises(ValueError, match="exceeds maximum size"):
            dber.appendOnVal(ords, b"evt", b"overflow")

    asyncio.run(_go())


def test_webdber_core_contract():
    """Test WebDBer core LMDBer method contract."""
    async def _go():
        dber, _ = await _open_fake_dber(stores=["beep."], clear=True)
        sdb = dber.env.open_db(key=b"beep.")

        key = b"A"
        val = b"whatever"
        assert dber.getVal(sdb, key) is None
        assert dber.remVal(sdb, key) is False
        assert dber.putVal(sdb, key, val) is True
        assert dber.putVal(sdb, key, val) is False
        assert dber.setVal(sdb, key, val) is True
        assert dber.getVal(sdb, key) == val
        assert dber.remVal(sdb, key) is True
        assert dber.getVal(sdb, key) is None

        assert dber.putVal(sdb, b"a.1", b"wow") is True
        assert dber.putVal(sdb, b"a.2", b"wee") is True
        assert dber.putVal(sdb, b"b.1", b"woo") is True

        assert list(dber.getTopItemIter(sdb)) == [
            (b"a.1", b"wow"), (b"a.2", b"wee"), (b"b.1", b"woo"),
        ]
        assert list(dber.getTopItemIter(sdb, b"a.")) == [
            (b"a.1", b"wow"), (b"a.2", b"wee"),
        ]
        assert dber.cntAll(sdb) == 3
        assert dber.delTop(sdb, b"a.") is True
        assert list(dber.getTopItemIter(sdb)) == [(b"b.1", b"woo")]

    asyncio.run(_go())


@needskeri
def test_suber_contract():
    """Test Suber wrapper operating against WebDBer."""
    async def _go():
        backend = FakeStorageBackend()
        dber, _ = await _open_fake_dber(
            name="suber-contract", stores=["bags.", "pugs."],
            clear=True, backend=backend,
        )

        bags = subing.Suber(db=dber, subkey="bags.")
        assert bags.sdb.flags()["dupsort"] is False

        assert bags.put(("test_key", "0001"), "Hello sailer!") is True
        assert bags.get(("test_key", "0001")) == "Hello sailer!"
        assert bags.put(("test_key", "0001"), "shadow") is False
        assert bags.pin(("test_key", "0001"), "Hey gorgeous!") is True
        assert bags.get(("test_key", "0001")) == "Hey gorgeous!"
        assert bags.rem(("test_key", "0001")) is True
        assert bags.get(("test_key", "0001")) is None

        assert bags.put((b"test_key", b"0002"), "Hello sailer!") is True
        assert bags.get((b"test_key", b"0002")) == "Hello sailer!"
        assert bags.put((b"test_key", "0003"), "Hello sailer!") is True
        assert bags.get((b"test_key", "0003")) == "Hello sailer!"

        assert bags.put("keystr", "Shove off!") is True
        assert bags.get("keystr") == "Shove off!"
        assert bags.pin("keystr", "Go away.") is True
        assert bags.get("keystr") == "Go away."

        pugs = subing.Suber(db=dber, subkey="pugs.")
        assert pugs.put(("a", "1"), "Blue dog") is True
        assert pugs.put(("a", "2"), "Green tree") is True
        assert pugs.put(("a", "3"), "Red apple") is True
        assert pugs.put(("a", "4"), "White snow") is True
        assert pugs.put(("b", "1"), "Blue dog") is True
        assert pugs.put(("b", "2"), "Green tree") is True
        assert pugs.put(("bc", "3"), "Red apple") is True
        assert pugs.put(("ac", "4"), "White snow") is True
        assert pugs.cnt() == 8

        assert list(pugs.getTopItemIter()) == [
            (("a", "1"), "Blue dog"), (("a", "2"), "Green tree"),
            (("a", "3"), "Red apple"), (("a", "4"), "White snow"),
            (("ac", "4"), "White snow"), (("b", "1"), "Blue dog"),
            (("b", "2"), "Green tree"), (("bc", "3"), "Red apple"),
        ]
        assert list(pugs.getTopItemIter(keys=("b", ""))) == [
            (("b", "1"), "Blue dog"), (("b", "2"), "Green tree"),
        ]
        assert list(pugs.getTopItemIter(keys=("a",), topive=True)) == [
            (("a", "1"), "Blue dog"), (("a", "2"), "Green tree"),
            (("a", "3"), "Red apple"), (("a", "4"), "White snow"),
        ]

        assert pugs.trim(keys=("b", "")) is True
        assert pugs.trim(keys=("a",), topive=True) is True
        assert list(pugs.getTopItemIter()) == [
            (("ac", "4"), "White snow"), (("bc", "3"), "Red apple"),
        ]

        assert bags.pin(("persist", "bag"), "kept") is True
        assert pugs.pin(("persist", "leaf"), "saved") is True
        assert await dber.flush() == 2

        reopened = await WebDBer.open(
            name="suber-contract", stores=["bags.", "pugs."],
            storageOpener=backend.open,
        )
        bags_reloaded = subing.Suber(db=reopened, subkey="bags.")
        pugs_reloaded = subing.Suber(db=reopened, subkey="pugs.")
        assert bags_reloaded.get(("persist", "bag")) == "kept"
        assert pugs_reloaded.get(("persist", "leaf")) == "saved"

    asyncio.run(_go())


@needskeri
def test_on_suber_contract():
    """Test OnSuber wrapper operating against WebDBer."""
    async def _go():
        dber, _ = await _open_fake_dber(
            name="onsuber-contract", stores=["bags."], clear=True,
        )

        onsuber = subing.OnSuber(db=dber, subkey="bags.")
        assert onsuber.sdb.flags()["dupsort"] is False

        w = "Blue dog"
        x = "Green tree"
        y = "Red apple"
        z = "White snow"

        assert onsuber.append(keys=("a",), val=w) == 0
        assert onsuber.append(keys=("a",), val=x) == 1
        assert onsuber.append(keys=("a",), val=y) == 2
        assert onsuber.append(keys=("a",), val=z) == 3

        assert onsuber.cntAll(keys=("a",)) == 4
        assert onsuber.cntAll(keys=("a",), on=2) == 2
        assert onsuber.cntAll(keys=("a",), on=4) == 0
        assert onsuber.cntAll() == 4
        assert onsuber.cnt() == 0
        assert onsuber.cnt(keys="a") == 4

        assert list(onsuber.getTopItemIter()) == [
            (("a",), 0, w), (("a",), 1, x), (("a",), 2, y), (("a",), 3, z),
        ]
        assert list(onsuber.getAllItemIter()) == [
            (("a",), 0, w), (("a",), 1, x), (("a",), 2, y), (("a",), 3, z),
        ]
        assert list(onsuber.getAllItemIter(keys="a", on=2)) == [
            (("a",), 2, y), (("a",), 3, z),
        ]
        assert list(onsuber.getAllIter()) == [w, x, y, z]
        assert list(onsuber.getAllIter(keys="a", on=2)) == [y, z]

        assert onsuber.append(keys=("b",), val=w) == 0
        assert onsuber.append(keys=("b",), val=x) == 1
        assert onsuber.append(keys=("bc",), val=y) == 0
        assert onsuber.append(keys=("ac",), val=z) == 0

        assert onsuber.cntAll(keys=("b",)) == 2
        assert onsuber.cntAll(keys="") == 8

        assert list(onsuber.getTopItemIter(keys="b")) == [
            (("b",), 0, w), (("b",), 1, x), (("bc",), 0, y),
        ]
        assert list(onsuber.getAllItemIter(keys="b")) == [
            (("b",), 0, w), (("b",), 1, x),
        ]
        assert list(onsuber.getAllItemIter(keys=("b", ""))) == []

        assert onsuber.rem(keys="a", on=1) is True
        assert onsuber.rem(keys="a", on=1) is False
        assert onsuber.rem(keys="a", on=3) is True
        assert onsuber.cntAll(keys=("a",)) == 2
        assert onsuber.cntAll() == 6

        assert onsuber.put(keys="d", on=0, val="moon") is True
        assert onsuber.get(keys="d", on=0) == "moon"
        assert onsuber.getItem(keys="d", on=0) == (("d",), 0, "moon")
        assert onsuber.put(keys="d", on=0, val="moon") is False
        assert onsuber.pin(keys="d", on=0, val="sun") is True
        assert onsuber.get(keys="d", on=0) == "sun"
        assert onsuber.rem(keys="d", on=0) is True
        assert onsuber.get(keys="d", on=0) is None

        assert onsuber.put(keys="d", on=0, val="moon") is True
        assert onsuber.put(keys="d", on=1, val="sun") is True
        assert onsuber.put(keys="d", on=2, val="stars") is True
        assert onsuber.put(keys="e", on=0, val="stars") is True
        assert onsuber.put(keys="e", on=1, val="moon") is True
        assert onsuber.put(keys="e", on=2, val="sun") is True

        assert onsuber.remAll(keys="d", on=1) is True
        assert onsuber.cntAll(keys="d") == 1
        assert onsuber.remAll(keys="d") is True
        assert onsuber.cntAll(keys="d") == 0
        assert onsuber.remAll() is True
        assert onsuber.cntAll() == 0

    asyncio.run(_go())


@needskeri
def test_komer_contract():
    """Test Komer wrapper operating against WebDBer."""
    async def _go():
        backend = FakeStorageBackend()

        @dataclass
        class Record:
            first: str
            last: str
            street: str
            city: str
            state: str
            zip: int

            def __iter__(self):
                return iter(asdict(self))

        dber, _ = await _open_fake_dber(
            name="komer-contract", stores=["records."],
            clear=True, backend=backend,
        )

        mydb = koming.Komer(db=dber, klas=Record, subkey="records.")
        assert mydb.sdb.flags()["dupsort"] is False
        assert mydb.sep == mydb.Sep == "."

        sue = Record(first="Susan", last="Black", street="100 Main Street",
                     city="Riverton", state="UT", zip=84058)
        kip = Record(first="Kip", last="Thorne", street="200 Center Street",
                     city="Bluffdale", state="UT", zip=84043)
        bob = Record(first="Bob", last="Brown", street="100 Center Street",
                     city="Bluffdale", state="UT", zip=84043)

        keys = ("test_key", "0001")
        key = mydb._tokey(keys)
        assert key == b"test_key.0001"
        assert mydb._tokeys(key) == keys

        assert mydb.put(keys=keys, val=sue) is True
        assert mydb.get(keys=keys) == sue
        assert mydb.put(keys=keys, val=kip) is False
        assert mydb.getDict(keys=keys) == asdict(sue)

        assert mydb.pin(keys=keys, val=kip) is True
        assert mydb.get(keys=keys) == kip

        assert mydb.rem(keys) is True
        assert mydb.get(keys=keys) is None

        assert mydb.put(keys="keystr", val=bob) is True
        assert mydb.get(keys="keystr") == bob
        assert mydb.pin(keys="keystr", val=sue) is True
        assert mydb.get(keys="keystr") == sue

        assert mydb.pin(keys=("persist", "0001"), val=kip) is True
        assert await dber.flush() == 1

        reopened, _ = await _open_fake_dber(
            name="komer-contract", stores=["records."], backend=backend,
        )
        reloaded = koming.Komer(db=reopened, klas=Record, subkey="records.")
        assert reloaded.get(keys="keystr") == sue
        assert reloaded.get(keys=("persist", "0001")) == kip

    asyncio.run(_go())


@needskeri
def test_komer_iter_and_trim():
    """Test Komer getTopItemIter and trim."""
    async def _go():
        @dataclass
        class Stuff:
            a: str
            b: str

            def __iter__(self):
                return iter(asdict(self))

        dber, _ = await _open_fake_dber(
            name="komer-items", stores=["recs."], clear=True,
        )
        mydb = koming.Komer(db=dber, klas=Stuff, subkey="recs.")

        w = Stuff(a="Big", b="Blue")
        x = Stuff(a="Tall", b="Red")
        y = Stuff(a="Fat", b="Green")
        z = Stuff(a="Eat", b="White")

        assert mydb.put(keys=("a", "1"), val=w) is True
        assert mydb.put(keys=("a", "2"), val=x) is True
        assert mydb.put(keys=("a", "3"), val=y) is True
        assert mydb.put(keys=("a", "4"), val=z) is True
        assert mydb.put(keys=("b", "1"), val=w) is True
        assert mydb.put(keys=("b", "2"), val=x) is True
        assert mydb.put(keys=("bc", "3"), val=y) is True
        assert mydb.put(keys=("bc", "4"), val=z) is True

        assert [(k, asdict(d)) for k, d in mydb.getTopItemIter(keys=("b", ""))] == [
            (("b", "1"), {"a": "Big", "b": "Blue"}),
            (("b", "2"), {"a": "Tall", "b": "Red"}),
        ]

        assert mydb.cnt() == 8
        assert mydb.trim(keys=("b", "")) is True
        assert mydb.cnt() == 6
        assert mydb.trim() is True
        assert list(mydb.getTopItemIter()) == []

    asyncio.run(_go())


@needskeri
def test_komer_serialization():
    """Test Komer klas validation and custom serializers."""
    async def _go():
        from keri.core.coring import Kinds

        backend = FakeStorageBackend()

        @dataclass
        class Record:
            first: str
            last: str
            street: str
            city: str
            state: str
            zip: int

            def __iter__(self):
                return iter(asdict(self))

        @dataclass
        class AnotherClass:
            age: int

        @dataclass
        class CustomRecord:
            first: str
            last: str
            street: str
            city: str
            state: str
            zip: int

            @staticmethod
            def _der(d):
                name = d["name"].split()
                city, state, zip_code = d["address2"].split()
                return CustomRecord(
                    first=name[0], last=name[1], street=d["address1"],
                    city=city, state=state, zip=int(zip_code, 10),
                )

            def _ser(self):
                return {
                    "name": f"{self.first} {self.last}",
                    "address1": self.street,
                    "address2": f"{self.city} {self.state} {self.zip}",
                }

        dber, _ = await _open_fake_dber(
            name="komer-serde", stores=["records.", "custom."],
            clear=True, backend=backend,
        )

        records = koming.Komer(db=dber, klas=Record, subkey="records.")
        invalid = koming.Komer(db=dber, klas=AnotherClass, subkey="records.")
        custom = koming.Komer(db=dber, klas=CustomRecord, subkey="custom.")

        sue = Record(first="Susan", last="Black", street="100 Main Street",
                     city="Riverton", state="UT", zip=84058)
        keys = ("test_key", "0001")

        with pytest.raises(ValueError):
            invalid.put(keys=keys, val=sue)

        assert records.put(keys=keys, val=sue) is True

        with pytest.raises(ValueError):
            invalid.get(keys)

        jim = Record(first="Jim", last="Black", street="100 Main Street",
                     city="Riverton", state="UT", zip=84058)

        mgpk = b"\x86\xa5first\xa3Jim\xa4last\xa5Black\xa6street\xaf100 Main Street\xa4city\xa8Riverton\xa5state\xa2UT\xa3zip\xce\x00\x01HZ"
        cbor = b"\xa6efirstcJimdlasteBlackfstreeto100 Main StreetdcityhRivertonestatebUTczip\x1a\x00\x01HZ"
        jsn = b'{"first":"Jim","last":"Black","street":"100 Main Street","city":"Riverton","state":"UT","zip":84058}'
        jsn_pretty = b'{"first": "Jim", "last": "Black", "street": "100 Main Street", "city": "Riverton", "state": "UT", "zip": 84058}'

        assert records._serializer(Kinds.json)(jim) == jsn
        assert records._serializer(Kinds.mgpk)(jim) == mgpk
        assert records._serializer(Kinds.cbor)(jim) == cbor
        assert records._deserializer(Kinds.mgpk)(mgpk) == jim
        assert records._deserializer(Kinds.cbor)(cbor) == jim
        assert records._deserializer(Kinds.json)(jsn_pretty) == jim

        custom_keys = ("custom", "0001")
        custom_jim = CustomRecord(first="Jim", last="Black",
                                  street="100 Main Street",
                                  city="Riverton", state="UT", zip=84058)
        assert custom.put(keys=custom_keys, val=custom_jim) is True
        assert custom.get(keys=custom_keys) == custom_jim
        assert dber.getVal(custom.sdb, custom._tokey(custom_keys)) == (
            b'{"name":"Jim Black","address1":"100 Main Street","address2":"Riverton UT 84058"}'
        )

        assert await dber.flush() == 2

        reopened, _ = await _open_fake_dber(
            name="komer-serde", stores=["records.", "custom."],
            backend=backend,
        )
        reloaded = koming.Komer(db=reopened, klas=CustomRecord, subkey="custom.")
        assert reloaded.get(keys=custom_keys) == custom_jim

    asyncio.run(_go())


def test_putIoSetVals():
    """
    Comprehensive tests for WebDBer.putIoSetVals.

    This test exercises all LMDB‑equivalent invariants that
    putIoSetVals must preserve when emulating insertion‑ordered
    set semantics using ordinal‑suffixed keys inside a SortedDict.

    1. Insert into an empty store:
       - First insertion under an apparent key must allocate
         ordinals starting at 0 and preserve input order.

    2. Skip existing values and append only new ones:
       - Existing values must not be duplicated.
       - New values must be appended at the next available ordinal.

    3. No‑op when all values already exist:
       - No new ordinal keys may be created.
       - The SubDb must not be marked dirty.

    4. Ordinal gap handling:
       - Missing ordinals (e.g. .1) must not be reused.
       - New values must always append after the maximum existing
         ordinal, matching LMDB cursor.set_range() behavior.

    5. Prefix isolation:
       - putIoSetVals must only operate on keys sharing the same
         apparent prefix; other keyspaces must remain untouched.

    6. Input order preservation:
       - When inserting multiple new values, their relative order
         must be preserved in the ordinal‑suffixed keyspace.

    7. Dirty‑flag correctness:
       - The SubDb must be marked dirty only when a mutation occurs,
         and must remain clean on no‑op calls.
    """

    async def _go():
        # Fresh DB
        dber, _ = await _open_fake_dber(
            name="putio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # 1. Insert into empty store
        
        result = dber.putIoSetVals(db, b"alpha", [b"v1", b"v2"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000001": b"v2",
        }
        assert db.dirty is True

        # Reset dirty for next scenario
        db.dirty = False


        # 2. Skip existing values, append new ones        
        result = dber.putIoSetVals(db, b"alpha", [b"v2", b"v3"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000001": b"v2",
            b"alpha.00000000000000000000000000000002": b"v3",
        }

        # Reset dirty
        db.dirty = False


        # 3. All existing so no-op
        result = dber.putIoSetVals(db, b"alpha", [b"v1", b"v2", b"v3"])
        assert result is False
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000001": b"v2",
            b"alpha.00000000000000000000000000000002": b"v3",
        }
        assert db.dirty is False


        # 4. Handle gaps
        # Create a gap by deleting alpha.1
        del db.items[b"alpha.00000000000000000000000000000001"]
        db.dirty = False

        # Now items are: alpha.0, alpha.2
        result = dber.putIoSetVals(db, b"alpha", [b"v4"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000002": b"v3",
            b"alpha.00000000000000000000000000000003": b"v4",
        }

        # Reset dirty
        db.dirty = False


        # 5. Prefix isolation
        db.items[b"beta.00000000000000000000000000000000"] = b"b1"
        db.dirty = False

        dber.putIoSetVals(db, b"alpha", [b"v5"])
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000002": b"v3",
            b"alpha.00000000000000000000000000000003": b"v4",
            b"alpha.00000000000000000000000000000004": b"v5",
            b"beta.00000000000000000000000000000000": b"b1",
        }


        # Reset dirty
        db.dirty = False

        # 6. Input order preserved
        dber.putIoSetVals(db, b"gamma", [b"v3", b"v1", b"v2"])
        assert list(db.items.values())[-3:] == [b"v3", b"v1", b"v2"]

        # Reset dirty
        db.dirty = False


        # 7. Dirty flag correctness
        assert dber.putIoSetVals(db, b"delta", [b"x"]) is True
        assert db.dirty is True

        db.dirty = False
        assert dber.putIoSetVals(db, b"delta", [b"x"]) is False
        assert db.dirty is False

    asyncio.run(_go())


def test_addIoSetVal():
    """
    Contract test for WebDBer.addIoSetVal validating all LMDB‑equivalent
    insertion‑ordered set semantics in a single end‑to‑end scenario.

    This test exercises the following behaviors:

    1. Insert into an empty store:
       The first value under an apparent key must be stored at ordinal 0.

    2. Skip existing value (no‑op):
       If the value is already present under the apparent key, no new
       ordinal key may be created and the SubDb must remain clean.

    3. Append new value at max ordinal + 1:
       New values must always be appended after the highest existing
       ordinal, preserving insertion order.

    4. Handle ordinal gaps:
       Missing ordinals (e.g., .1) must not be reused. The next value
       must always be inserted at max_ordinal + 1, matching LMDB cursor
       behavior.

    5. Prefix isolation:
       Only keys sharing the same apparent prefix may be modified.
       Values stored under other prefixes must remain untouched.

    6. No‑op on empty key or None value:
       Empty keys or missing values must not mutate the store.

    7. Dirty‑flag correctness:
       The SubDb must be marked dirty only when a new ordinal key is
       inserted, and must remain clean on no‑op calls.
    """

    async def _go():
        dber, _ = await _open_fake_dber(
            name="addio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # 1. Insert into empty store
        result = dber.addIoSetVal(db, b"alpha", b"v1")
        assert result is True
        assert db.items == {b"alpha.00000000000000000000000000000000": b"v1"}
        assert db.dirty is True

        db.dirty = False

        # 2. Skip existing value (no‑op)
        result = dber.addIoSetVal(db, b"alpha", b"v1")
        assert result is False
        assert db.items == {b"alpha.00000000000000000000000000000000": b"v1"}
        assert db.dirty is False

        # 3. Append new value at next ordinal
        result = dber.addIoSetVal(db, b"alpha", b"v2")
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000001": b"v2",
        }

        db.dirty = False

        # 4. Handle gaps: missing ordinal .1 should NOT be reused
        del db.items[b"alpha.00000000000000000000000000000001"]
        db.items[b"alpha.00000000000000000000000000000003"] = b"v3"
        db.dirty = False

        result = dber.addIoSetVal(db, b"alpha", b"v4")
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000003": b"v3",
            b"alpha.00000000000000000000000000000004": b"v4",
        }

        db.dirty = False

        # 5. Prefix isolation
        db.items[b"beta.00000000000000000000000000000000"] = b"b1"
        db.dirty = False

        dber.addIoSetVal(db, b"alpha", b"v5")
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000003": b"v3",
            b"alpha.00000000000000000000000000000004": b"v4",
            b"alpha.00000000000000000000000000000005": b"v5",
            b"beta.00000000000000000000000000000000": b"b1",
        }

        db.dirty = False

        # 6. No‑op on empty key or None value
        assert dber.addIoSetVal(db, b"", b"x") is False
        assert dber.addIoSetVal(db, None, b"x") is False
        assert dber.addIoSetVal(db, b"alpha", None) is False
        assert db.dirty is False

        # 7. Dirty flag correctness
        assert dber.addIoSetVal(db, b"gamma", b"g1") is True
        assert db.dirty is True

        db.dirty = False
        assert dber.addIoSetVal(db, b"gamma", b"g1") is False
        assert db.dirty is False

    asyncio.run(_go())


def test_pinIoSetVals():
    """
    Contract test for WebDBer.pinIoSetVals validating LMDB‑equivalent
    replacement semantics for insertion‑ordered sets.

    This test exercises the following behaviors:

    1. Replace values in an empty store:
       pinIoSetVals must insert the provided values at ordinals 0..N‑1.

    2. Replace existing values:
       All existing key.* entries must be removed before inserting the new set.

    3. Input order preserved:
       Values must be stored in the exact order provided.

    4. Prefix isolation:
       Only entries with the given apparent key prefix may be removed or replaced.

    5. No‑op on empty key or empty/None vals:
       The store must remain unchanged and the SubDb must remain clean.

    6. Dirty‑flag correctness:
       The SubDb must be marked dirty only when replacement actually occurs.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="pinio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # 1. Replace values in an empty store
        result = dber.pinIoSetVals(db, b"alpha", [b"v1", b"v2"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000001": b"v2",
        }
        assert db.dirty is True

        db.dirty = False

        # 2. Replace existing values
        result = dber.pinIoSetVals(db, b"alpha", [b"x", b"y", b"z"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"x",
            b"alpha.00000000000000000000000000000001": b"y",
            b"alpha.00000000000000000000000000000002": b"z",
        }
        assert db.dirty is True

        db.dirty = False

        # 3. Input order preserved
        result = dber.pinIoSetVals(db, b"alpha", [b"c", b"a", b"b"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"c",
            b"alpha.00000000000000000000000000000001": b"a",
            b"alpha.00000000000000000000000000000002": b"b",
        }

        db.dirty = False

        # 4. Prefix isolation
        db.items[b"beta.00000000000000000000000000000000"] = b"b1"
        db.items[b"beta.00000000000000000000000000000001"] = b"b2"
        db.dirty = False

        result = dber.pinIoSetVals(db, b"alpha", [b"m"])
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"m",
            b"beta.00000000000000000000000000000000": b"b1",
            b"beta.00000000000000000000000000000001": b"b2",
        }

        db.dirty = False

        # 5. No‑op on empty key or empty/None vals
        assert dber.pinIoSetVals(db, b"", [b"x"]) is False
        assert dber.pinIoSetVals(db, None, [b"x"]) is False
        assert dber.pinIoSetVals(db, b"alpha", []) is False
        assert dber.pinIoSetVals(db, b"alpha", None) is False
        assert db.dirty is False

        # 6. Dirty‑flag correctness
        assert dber.pinIoSetVals(db, b"gamma", [b"g1"]) is True
        assert db.dirty is True

        db.dirty = False
        assert dber.pinIoSetVals(db, b"gamma", [b"g1"]) is True
        # Replacement still counts as mutation even if values are identical
        assert db.dirty is True

    asyncio.run(_go())


def test_remIoSet():
    """
    Contract test for WebDBer.remIoSet validating LMDB‑equivalent
    deletion semantics for removing all values under an apparent key.

    This test checks the following behaviors:

    1. Remove all values under a key:
       All key.* entries must be deleted.

    2. No‑op when key does not exist:
       The store must remain unchanged and the SubDb must remain clean.

    3. Prefix isolation:
       Only entries with the given apparent key prefix may be removed.

    4. Handle gaps:
       All matching key.* entries must be removed regardless of ordinal gaps.

    5. No‑op on empty key:
       Empty keys must not mutate the store.

    6. Dirty‑flag correctness:
       Dirty must be set only when deletions actually occur.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="remio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # Initial population
        db.items[b"alpha.00000000000000000000000000000000"] = b"v1"
        db.items[b"alpha.00000000000000000000000000000001"] = b"v2"
        db.items[b"alpha.00000000000000000000000000000002"] = b"v3"
        db.dirty = False

        # 1. Remove all values under a key
        result = dber.remIoSet(db, b"alpha")
        assert result is True
        assert db.items == {}
        assert db.dirty is True

        db.dirty = False

        # Rebuild for next scenarios
        db.items[b"alpha.00000000000000000000000000000000"] = b"a1"
        db.items[b"alpha.00000000000000000000000000000002"] = b"a2"   # gap at .1
        db.items[b"beta.00000000000000000000000000000000"] = b"b1"
        db.dirty = False

        # 2. No‑op when key does not exist
        result = dber.remIoSet(db, b"gamma")
        assert result is False
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"a1",
            b"alpha.00000000000000000000000000000002": b"a2",
            b"beta.00000000000000000000000000000000": b"b1",
        }
        assert db.dirty is False

        # 3. Prefix isolation
        result = dber.remIoSet(db, b"alpha")
        assert result is True
        assert db.items == {
            b"beta.00000000000000000000000000000000": b"b1",
        }
        assert db.dirty is True

        db.dirty = False

        # Rebuild for gap test
        db.items[b"alpha.00000000000000000000000000000000"] = b"x"
        db.items[b"alpha.00000000000000000000000000000005"] = b"y"   # large gap
        db.items[b"alpha.00000000000000000000000000000009"] = b"z"
        db.dirty = False

        # 4. Handle gaps
        result = dber.remIoSet(db, b"alpha")
        assert result is True
        assert db.items == {
            b"beta.00000000000000000000000000000000": b"b1",
        }
        assert db.dirty is True

        db.dirty = False

        # 5. No‑op on empty key
        assert dber.remIoSet(db, b"") is False
        assert db.dirty is False

        # 6. Dirty‑flag correctness
        assert dber.remIoSet(db, b"beta") is True
        assert db.dirty is True

        db.dirty = False
        assert dber.remIoSet(db, b"beta") is False
        assert db.dirty is False

    asyncio.run(_go())


def test_remIoSetVal():
    """
    Contract test for WebDBer.remIoSetVal validating LMDB‑equivalent
    deletion semantics for insertion‑ordered sets.

    This test checks the following behaviors:

    1. Remove a specific value:
       Only the matching value under the apparent key must be deleted.

    2. Remove all values when val=None:
       All key.* entries must be removed, but other prefixes must remain.

    3. No‑op when value does not exist:
       The store must remain unchanged and the SubDb must remain clean.

    4. Prefix isolation:
       Only entries with the given apparent key prefix may be removed.

    5. Handle gaps:
       Deleting a value must not affect unrelated ordinals.

    6. No‑op on empty key:
       Empty keys must not mutate the store.

    7. Dirty‑flag correctness:
       Dirty must be set only when a deletion actually occurs.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="remio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # Initial population
        db.items[b"alpha.00000000000000000000000000000000"] = b"v1"
        db.items[b"alpha.00000000000000000000000000000001"] = b"v2"
        db.items[b"alpha.00000000000000000000000000000002"] = b"v3"
        db.dirty = False

        # 1. Remove a specific value
        result = dber.remIoSetVal(db, b"alpha", b"v2")
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"v1",
            b"alpha.00000000000000000000000000000002": b"v3",
        }
        assert db.dirty is True

        db.dirty = False

        # 2. Remove all values when val=None
        result = dber.remIoSetVal(db, b"alpha", None)
        assert result is True
        assert db.items == {}
        assert db.dirty is True

        db.dirty = False

        # Rebuild for next scenarios
        db.items[b"alpha.00000000000000000000000000000000"] = b"a1"
        db.items[b"alpha.00000000000000000000000000000001"] = b"a2"
        db.items[b"beta.00000000000000000000000000000000"] = b"b1"
        db.dirty = False

        # 3. No‑op when value does not exist
        result = dber.remIoSetVal(db, b"alpha", b"zzz")
        assert result is False
        assert db.items == {
            b"alpha.00000000000000000000000000000000": b"a1",
            b"alpha.00000000000000000000000000000001": b"a2",
            b"beta.00000000000000000000000000000000": b"b1",
        }
        assert db.dirty is False

        # 4. Prefix isolation
        result = dber.remIoSetVal(db, b"alpha", b"a1")
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000001": b"a2",
            b"beta.00000000000000000000000000000000": b"b1",
        }
        assert db.dirty is True

        db.dirty = False

        # 5. Handle gaps
        db.items[b"alpha.00000000000000000000000000000003"] = b"a3"   # create a gap at .2
        db.dirty = False

        result = dber.remIoSetVal(db, b"alpha", b"a3")
        assert result is True
        assert db.items == {
            b"alpha.00000000000000000000000000000001": b"a2",
            b"beta.00000000000000000000000000000000": b"b1",
        }

        db.dirty = False

        # 6. No‑op on empty key
        assert dber.remIoSetVal(db, b"", b"a2") is False
        assert db.dirty is False

        # 7. Dirty‑flag correctness
        assert dber.remIoSetVal(db, b"alpha", b"a2") is True
        assert db.dirty is True

        db.dirty = False
        assert dber.remIoSetVal(db, b"alpha", b"a2") is False
        assert db.dirty is False

    asyncio.run(_go())


def test_cntIoSet():
    """
    Tests for WebDBer.cntIoSet validating LMDB‑equivalent
    counting semantics for insertion‑ordered sets.

    This test checks the following behaviors:

    1. Count all values under a key:
       cntIoSet(key) must return the number of key.* entries.

    2. Count starting at a non‑zero ordinal:
       Counting must begin at the specified ordinal, skipping earlier ones.

    3. Handle gaps:
       Ordinal gaps must not affect counting; only prefix matches matter.

    4. Prefix isolation:
       Only entries with the given apparent key prefix may be counted.

    5. No‑op on empty key:
       Empty keys must return 0.

    6. No‑op when key does not exist:
       Nonexistent keys must return 0.

    7. Dirty‑flag correctness:
       Counting must never mutate the store.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="cntio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # Initial population
        db.items[b"alpha.00000000000000000000000000000000"] = b"v1"
        db.items[b"alpha.00000000000000000000000000000001"] = b"v2"
        db.items[b"alpha.00000000000000000000000000000002"] = b"v3"
        db.items[b"beta.00000000000000000000000000000000"] = b"b1"
        db.dirty = False

        # 1. Count all values under a key
        assert dber.cntIoSet(db, b"alpha") == 3
        assert db.dirty is False

        # 2. Count starting at a non‑zero ordinal
        assert dber.cntIoSet(db, b"alpha", ion=0) == 3
        assert dber.cntIoSet(db, b"alpha", ion=1) == 2
        assert dber.cntIoSet(db, b"alpha", ion=2) == 1
        assert dber.cntIoSet(db, b"alpha", ion=3) == 0
        assert db.dirty is False

        # 3. Handle gaps
        del db.items[b"alpha.00000000000000000000000000000001"]  # gap at .1
        db.items[b"alpha.00000000000000000000000000000005"] = b"v5"
        assert dber.cntIoSet(db, b"alpha") == 3   # .0, .2, .5
        assert dber.cntIoSet(db, b"alpha", ion=2) == 2
        assert dber.cntIoSet(db, b"alpha", ion=4) == 1
        assert dber.cntIoSet(db, b"alpha", ion=6) == 0
        assert db.dirty is False

        # 4. Prefix isolation
        assert dber.cntIoSet(db, b"beta") == 1
        assert dber.cntIoSet(db, b"gamma") == 0
        assert db.dirty is False

        # 5. No‑op on empty key
        assert dber.cntIoSet(db, b"") == 0
        assert db.dirty is False

        # 6. No‑op when key does not exist
        assert dber.cntIoSet(db, b"zzz") == 0
        assert db.dirty is False

        # 7. Dirty‑flag correctness
        before = dict(db.items)
        _ = dber.cntIoSet(db, b"alpha")
        assert db.items == before
        assert db.dirty is False

    asyncio.run(_go())


def test_getIoSetItemIter():
    """
    Contract test for WebDBer.getIoSetItemIter validating LMDB‑equivalent
    iteration semantics for insertion‑ordered sets.

    This test checks the following behaviors:

    1. Iterate all values under a key:
       getIoSetItemIter must yield (iokey, value) in ordinal order.

    2. Start iteration at a non‑zero ordinal:
       Iteration must begin at the specified insertion ordinal.

    3. Handle gaps:
       Ordinal gaps must not break iteration; only prefix matches matter.

    4. Prefix isolation:
       Only entries with the given apparent key prefix may be returned.

    5. Empty key returns empty iterator:
       No iteration must occur when key is empty.

    6. Dirty‑flag correctness:
       Iteration must never mutate the store.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="getio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # Populate alpha.* set
        db.items[b"alpha.00000000000000000000000000000000"] = b"v0"
        db.items[b"alpha.00000000000000000000000000000001"] = b"v1"
        db.items[b"alpha.00000000000000000000000000000002"] = b"v2"

        # Add unrelated prefixes
        db.items[b"beta.00000000000000000000000000000000"] = b"b0"
        db.items[b"alphaX.00000000000000000000000000000000"] = b"x0"
        db.dirty = False

        # 1. Iterate all values under alpha
        out = list(dber.getIoSetItemIter(db, b"alpha"))
        assert out == [
            (b"alpha", b"v0"),
            (b"alpha", b"v1"),
            (b"alpha", b"v2"),
        ]
        assert db.dirty is False

        # 2. Start iteration at non‑zero ordinal
        out = list(dber.getIoSetItemIter(db, b"alpha", ion=1))
        assert out == [
            (b"alpha", b"v1"),
            (b"alpha", b"v2"),
        ]
        assert db.dirty is False

        # 3. Handle gaps
        del db.items[b"alpha.00000000000000000000000000000001"]
        db.items[b"alpha.00000000000000000000000000000005"] = b"v5"
        out = list(dber.getIoSetItemIter(db, b"alpha"))
        assert out == [
            (b"alpha", b"v0"),
            (b"alpha", b"v2"),
            (b"alpha", b"v5"),
        ]
        assert db.dirty is False

        # 4. Prefix isolation
        out = list(dber.getIoSetItemIter(db, b"alpha"))
        assert all(base == b"alpha" for (base, _) in out)
        assert db.dirty is False

        # 5. Empty key returns empty iterator
        out = list(dber.getIoSetItemIter(db, b""))
        assert out == []
        assert db.dirty is False

        # 6. Dirty‑flag correctness
        before = dict(db.items)
        _ = list(dber.getIoSetItemIter(db, b"alpha"))
        assert db.items == before
        assert db.dirty is False

    asyncio.run(_go())


def test_getIoSetLastItem():
    """
    Contract test for WebDBer.getIoSetLastItem validating LMDB‑equivalent
    semantics for retrieving the last (highest‑ordinal) IoSet entry.

    This test checks the following behaviors:

    1. Return the last item under a key:
       getIoSetLastItem must return (key, value) for the highest ordinal.

    2. Handle gaps:
       Ordinal gaps must not affect correctness; the highest existing ordinal
       determines the last item.

    3. Prefix isolation:
       Only entries with the given apparent key prefix may be considered.

    4. No entries under key:
       Must return empty tuple.

    5. Empty key:
       Must return empty tuple.

    6. Dirty‑flag correctness:
       Reading must never mutate the store.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="getlastio-all",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # Populate alpha.* set
        db.items[b"alpha.00000000000000000000000000000000"] = b"v0"
        db.items[b"alpha.00000000000000000000000000000001"] = b"v1"
        db.items[b"alpha.00000000000000000000000000000002"] = b"v2"

        # Add unrelated prefixes
        db.items[b"beta.00000000000000000000000000000000"] = b"b0"
        db.items[b"alphaX.00000000000000000000000000000000"] = b"x0"
        db.dirty = False

        # 1. Return the last item under alpha
        out = dber.getIoSetLastItem(db, b"alpha")
        assert out == (b"alpha", b"v2")
        assert db.dirty is False

        # 2. Handle gaps
        del db.items[b"alpha.00000000000000000000000000000002"]
        db.items[b"alpha.00000000000000000000000000000007"] = b"v7"
        out = dber.getIoSetLastItem(db, b"alpha")
        assert out == (b"alpha", b"v7")
        assert db.dirty is False

        # 3. Prefix isolation
        # Only alpha.* entries should be considered
        out = dber.getIoSetLastItem(db, b"alpha")
        assert out[0] == b"alpha"
        assert db.dirty is False

        # 4. No entries under key
        del db.items[b"alpha.00000000000000000000000000000000"]
        del db.items[b"alpha.00000000000000000000000000000001"]
        del db.items[b"alpha.00000000000000000000000000000007"]
        out = dber.getIoSetLastItem(db, b"alpha")
        assert out == ()
        assert db.dirty is False

        # 5. Empty key returns empty tuple
        out = dber.getIoSetLastItem(db, b"")
        assert out == ()
        assert db.dirty is False

        # 6. Dirty‑flag correctness
        before = dict(db.items)
        _ = dber.getIoSetLastItem(db, b"beta")
        assert db.items == before
        assert db.dirty is False

    asyncio.run(_go())


def test_getIoSetLastItemIterAll():
    """
    Contract test for WebDBer.getIoSetLastItemIterAll validating LMDB‑equivalent
    semantics for retrieving the last IoSet entry for every effective key.

    This test checks the following behaviors:

    1. Iterate all effective keys:
       Must yield exactly one (key, value) per apparent key.

    2. Handle gaps:
       Highest ordinal determines the last item, even with missing ordinals.

    3. Prefix isolation:
       Starting from a given key must skip all earlier keys.

    4. Empty key:
       Must iterate over the entire DB.

    5. Empty DB:
       Must yield nothing.

    6. Dirty‑flag correctness:
       Iteration must never mutate the store.
    """
    async def _go():
        dber, _ = await _open_fake_dber(
            name="getlastallio",
            stores=["vals."],
            clear=True,
        )
        db = dber.env.open_db("vals.")

        # Populate multiple IoSets
        db.items[b"alpha.00000000000000000000000000000000"] = b"a0"
        db.items[b"alpha.00000000000000000000000000000002"] = b"a2"   # gap at .1

        db.items[b"beta.00000000000000000000000000000000"] = b"b0"
        db.items[b"beta.00000000000000000000000000000005"] = b"b5"   # gap at .1–.4

        db.items[b"gamma.00000000000000000000000000000001"] = b"g1"
        db.items[b"gamma.00000000000000000000000000000009"] = b"g9"

        db.dirty = False

        # 1. Iterate all effective keys (empty key returns the full DB)
        out = list(dber.getIoSetLastItemIterAll(db))
        assert out == [
            (b"alpha", b"a2"),
            (b"beta",  b"b5"),
            (b"gamma", b"g9"),
        ]
        assert db.dirty is False

        # 2. Handle gaps (already validated above)
        # alpha last = a2, beta last = b5, gamma last = g9

        # 3. Prefix isolation: start at "beta"
        out = list(dber.getIoSetLastItemIterAll(db, b"beta"))
        assert out == [
            (b"beta",  b"b5"),
            (b"gamma", b"g9"),
        ]
        assert db.dirty is False

        # 4. Starting at "gamma"
        out = list(dber.getIoSetLastItemIterAll(db, b"gamma"))
        assert out == [
            (b"gamma", b"g9"),
        ]
        assert db.dirty is False

        # 5. Starting past all keys → empty
        out = list(dber.getIoSetLastItemIterAll(db, b"zzz"))
        assert out == []
        assert db.dirty is False

        # 6. Empty DB → empty iterator
        db.items.clear()
        out = list(dber.getIoSetLastItemIterAll(db))
        assert out == []
        assert db.dirty is False

        # 7. Dirty‑flag correctness
        db.items[b"alpha.00000000000000000000000000000000"] = b"x"
        db.dirty = False
        before = dict(db.items)
        _ = list(dber.getIoSetLastItemIterAll(db))
        assert db.items == before
        assert db.dirty is False

    asyncio.run(_go())


@needskeri
def test_ioset_suber_contract():
    """Test IoSetSuber wrapper operating against WebDBer."""
    async def _go():
        dber, _ = await _open_fake_dber(
            name="ioset-suber-contract",
            stores=["vals."],
            clear=True,
        )

        ios = subing.IoSetSuber(db=dber, subkey="vals.")
        assert ios.sdb.flags()["dupsort"] is False

        # Basic append semantics
        a0 = "red"
        a1 = "green"
        a2 = "blue"
        a3 = "yellow"

        assert ios.add(keys=b"alpha", val=a0) == True
        assert ios.add(keys=b"alpha", val=a1) == True
        assert ios.add(keys=b"alpha", val=a2) == True
        assert ios.add(keys=b"alpha", val=a3) == True

        assert ios.cnt(keys=b"alpha") == 4
        assert ios.cnt(keys=b"alpha", ion=2) == 2
        assert ios.cnt(keys=b"alpha", ion=4) == 0

        # Iteration semantics
        assert list(ios.getItemIter(keys=b"alpha")) == [
            (("alpha",), a0),
            (("alpha",), a1),
            (("alpha",), a2),
            (("alpha",), a3),
        ]

        assert list(ios.getItemIter(keys=b"alpha", ion=2)) == [
            (("alpha",), a2),
            (("alpha",), a3),
        ]

        # Last item
        assert ios.getLastItem(keys=b"alpha") == (('alpha',), a3)

        # put — append only missing values
        assert ios.put(keys=b"alpha", vals=[a3, b"cyan"]) is True
        assert list(ios.getItemIter(keys=b"alpha")) == [
            (('alpha',), a0),
            (('alpha',), a1),
            (('alpha',), a2),
            (('alpha',), a3),
            (('alpha',), "cyan"),
        ]

        # pin — replace entire set
        assert ios.pin(keys=b"alpha", vals=[b"x", b"y"]) is True
        assert list(ios.getItemIter(keys=b"alpha")) == [
            (("alpha",), "x"),
            (("alpha",), "y"),
        ]

        # rem — remove a specific value
        assert ios.rem(keys=b"alpha", val=b"x") is True
        assert list(ios.getItemIter(keys=b"alpha")) == [
            (("alpha",), "y"),
        ]

        # No‑op when value missing
        assert ios.rem(keys=b"alpha", val=b"zzz") is False

        # rem — remove all values under keys
        assert ios.rem(keys=b"alpha") is True
        assert list(ios.getItemIter(keys=b"alpha")) == []

        # No‑op when keys missing
        assert ios.rem(keys=b"alpha") is False

        # Multi‑key scenario for last‑item‑iter‑all
        db = ios.sdb  # convenience
        db.items.clear()

        db.items[b"alpha.00000000000000000000000000000000"] = b"a0"
        db.items[b"alpha.00000000000000000000000000000002"] = b"a2"
        db.items[b"beta.00000000000000000000000000000000"] = b"b0"
        db.items[b"beta.00000000000000000000000000000005"] = b"b5"
        db.items[b"gamma.00000000000000000000000000000001"] = b"g1"
        db.items[b"gamma.00000000000000000000000000000009"] = b"g9"
        db.dirty = False

        assert list(ios.getLastItemIter()) == [
            (("alpha",), "a2"),
            (("beta",),  "b5"),
            (("gamma",), "g9"),
        ]

        assert list(ios.getLastItemIter(keys=b"beta")) == [
            (("beta",), "b5"),
            (("gamma",), "g9"),
        ]

        assert list(ios.getLastItemIter(keys=b"zzz")) == []

        # Dirty‑flag correctness across all operations
        before = dict(db.items)
        _ = list(ios.getItemIter(keys=b"alpha"))
        _ = ios.cnt(keys=b"alpha")
        _ = ios.getLastItem(keys=b"alpha")
        _ = list(ios.getLastItemIter())
        assert db.items == before
        assert db.dirty is False

        db.items.clear()

        # Test suite taken from test_ioset_suber in test_subing.py 
        # test empty keys
        assert ios.cntAll() == 0
        assert ios.cnt(keys="") == 0
        assert ios.get(keys="") == []
        assert [val for val in ios.getIter(keys="")] == []
        assert ios.getLastItem(keys=()) == ()
        assert ios.getLast(keys=()) == None
        assert ios.getLastItem(keys="") == ()
        assert ios.getLast(keys="") == None

        sue = "Hello sailer!"
        sal = "Not my type."
        sam = "A real charmer!"
        zoe = "See ya later."
        zia = "Hey gorgeous!"
        zul = "get lost"
        bob = "Shove off!"

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")
        keys2 = "keystr"

        vals0 = [sue, sal, sam]
        vals1 = [zoe, zia, zul]

        # fill database
        assert ios.put(keys=keys0, vals=vals0)
        assert ios.put(keys=keys1, vals=vals1)

        assert ios.cntAll() == 6
        assert ios.cnt(keys="") == 6

        assert ios.cnt(keys=keys0) == 3
        assert ios.cnt(keys=keys1) == 3

        # keys0
        # ion default 0
        assert [val for val in ios.getIter(keys=keys0)] == vals0
        assert [(key, val) for key, val in ios.getItemIter(keys=keys0)] == \
        [
            (('test_key', '0001'), 'Hello sailer!'),
            (('test_key', '0001'), 'Not my type.'),
            (('test_key', '0001'), 'A real charmer!')
        ]
        assert ios.get(keys=keys0) == vals0
        assert ios.cnt(keys=keys0) == 3
        assert ios.getLastItem(keys=keys0) == (keys0, sam)
        assert ios.getLast(keys=keys0) == sam

        # ion = 0
        assert [val for val in ios.getIter(keys=keys0, ion=0)] == [sue, sal, sam]
        assert [(key, val) for key, val in ios.getItemIter(keys=keys0, ion=0)] == \
        [
            (('test_key', '0001'), 'Hello sailer!'),
            (('test_key', '0001'), 'Not my type.'),
            (('test_key', '0001'), 'A real charmer!')
        ]
        assert ios.get(keys=keys0, ion=0) == [sue, sal, sam]
        assert ios.cnt(keys=keys0, ion=0) == 3

        # ion = 1
        assert [val for val in ios.getIter(keys=keys0, ion=1)] == [sal, sam]
        assert [(key, val) for key, val in ios.getItemIter(keys=keys0, ion=1)] == \
        [
            (('test_key', '0001'), 'Not my type.'),
            (('test_key', '0001'), 'A real charmer!')
        ]
        assert ios.get(keys=keys0, ion=1) == [sal, sam]
        assert ios.cnt(keys=keys0, ion=1) == 2

        # ion = 2
        assert [val for val in ios.getIter(keys=keys0, ion=2)] == [sam]
        assert ios.get(keys=keys0, ion=2) == [sam]
        assert ios.cnt(keys=keys0, ion=2) == 1

        # ion = 3  past end of keys0 set
        assert [val for val in ios.getIter(keys=keys0, ion=3)] == []
        assert [(key, val) for key, val in ios.getItemIter(keys=keys0, ion=3)] == []
        assert ios.get(keys=keys0, ion=3) == []
        assert ios.cnt(keys=keys0, ion=3) == 0

        # keys1
        # ion default 0
        assert [val for val in ios.getIter(keys=keys1)] == vals1
        assert ios.get(keys=keys1) == vals1
        assert ios.cnt(keys=keys1) == 3
        assert ios.getLastItem(keys=keys1) == (keys1, zul)
        assert ios.getLast(keys=keys1) == zul

        # ion = 0
        assert [val for val in ios.getIter(keys=keys1, ion=0)] == [zoe, zia, zul]
        assert ios.get(keys=keys1, ion=0) == [zoe, zia, zul]
        assert ios.cnt(keys=keys1, ion=0) == 3

        # ion = 1
        assert [val for val in ios.getIter(keys=keys1, ion=1)] == [zia, zul]
        assert ios.get(keys=keys1, ion=1) == [zia, zul]
        assert ios.cnt(keys=keys1, ion=1) == 2

        # ion = 2
        assert [val for val in ios.getIter(keys=keys1, ion=2)] == [zul]
        assert ios.get(keys=keys1, ion=2) == [zul]
        assert ios.cnt(keys=keys1, ion=2) == 1

        # ion = 3  past end of keys1 set
        assert [val for val in ios.getIter(keys=keys1, ion=3)] == []
        assert ios.get(keys=keys0, ion=3) == []
        assert ios.cnt(keys=keys0, ion=3) == 0

        # keys0 make gap keys0
        assert ios.rem(keys=keys0, val=sal)

        # ion default 0
        assert [val for val in ios.getIter(keys=keys0)] == [sue, sam]
        assert ios.get(keys=keys0) == [sue, sam]
        assert ios.cnt(keys=keys0) == 2
        assert ios.getLastItem(keys=keys0) == (keys0, sam)
        assert ios.getLast(keys=keys0) == sam

        # ion = 0
        assert [val for val in ios.getIter(keys=keys0, ion=0)] == [sue, sam]
        assert ios.get(keys=keys0, ion=0) == [sue, sam]
        assert ios.cnt(keys=keys0, ion=0) == 2

        # ion = 1
        assert [val for val in ios.getIter(keys=keys0, ion=1)] == [ sam]
        assert ios.get(keys=keys0, ion=1) == [sam]
        assert ios.cnt(keys=keys0, ion=1) == 1

        # ion = 2
        assert [val for val in ios.getIter(keys=keys0, ion=2)] == [sam]
        assert ios.get(keys=keys0, ion=2) == [sam]
        assert ios.cnt(keys=keys0, ion=2) == 1

        # ion = 3  past end of keys0 set
        assert [val for val in ios.getIter(keys=keys0, ion=3)] == []
        assert ios.get(keys=keys0, ion=3) == []
        assert ios.cnt(keys=keys0, ion=3) == 0

        # keys1 make gap keys1
        assert ios.rem(keys=keys1, val=zoe)

        # ion default 0
        assert [val for val in ios.getIter(keys=keys1)] == [zia, zul]
        assert ios.get(keys=keys1) == [zia, zul]
        assert ios.cnt(keys=keys1) == 2
        assert ios.getLastItem(keys=keys1) == (keys1, zul)
        assert ios.getLast(keys=keys1) == zul

        # ion = 0
        assert [val for val in ios.getIter(keys=keys1, ion=0)] == [zia, zul]
        assert ios.get(keys=keys1, ion=0) == [zia, zul]
        assert ios.cnt(keys=keys1, ion=0) == 2

        # ion = 1
        assert [val for val in ios.getIter(keys=keys1, ion=1)] == [zia, zul]
        assert ios.get(keys=keys1, ion=1) == [zia, zul]
        assert ios.cnt(keys=keys1, ion=1) == 2

        # ion = 2
        assert [val for val in ios.getIter(keys=keys1, ion=2)] == [zul]
        assert ios.get(keys=keys1, ion=2) == [zul]
        assert ios.cnt(keys=keys1, ion=2) == 1

        # ion = 3  past end of keys1 set
        assert [val for val in ios.getIter(keys=keys1, ion=3)] == []
        assert ios.get(keys=keys1, ion=3) == []
        assert ios.cnt(keys=keys1, ion=3) == 0

        # clear db
        assert ios.rem(keys=keys0)
        assert ios.rem(keys=keys1)
        assert ios.cntAll() == 0
        assert ios.cnt() == 0


        # more tests
        assert ios.put(keys=keys0, vals=[sal, sue])
        assert ios.get(keys=keys0) == [sal, sue]  # insertion order not lexicographic
        assert ios.cnt(keys0) == 2
        assert ios.getLastItem(keys=keys0) == (keys0, sue)
        assert ios.getLast(keys=keys0) == sue

        assert ios.rem(keys0)
        assert ios.get(keys=keys0) == []
        assert ios.cnt(keys0) == 0

        assert ios.put(keys=keys0, vals=[sue, sal])
        actuals = ios.get(keys=keys0)
        assert actuals == [sue, sal]  # insertion order
        assert ios.getLastItem(keys=keys0) == (keys0, sal)
        assert ios.getLast(keys=keys0) == sal

        result = ios.add(keys=keys0, val=sam)
        assert result
        actuals = ios.get(keys=keys0)
        assert actuals == [sue, sal, sam]   # insertion order

        result = ios.pin(keys=keys0, vals=[zoe, zia])
        assert result
        actuals = ios.get(keys=keys0)
        assert actuals == [zoe, zia]  # insertion order

        assert ios.put(keys=keys1, vals=[sal, sue, sam])
        actuals = ios.get(keys=keys1)
        assert actuals == [sal, sue, sam]

        for i, val in enumerate(ios.getIter(keys=keys1)):
            assert val == actuals[i]

        items = [(keys, val) for keys, val in ios.getTopItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'A real charmer!')]

        items = [(keys, val) for keys, val in ios.getLastItemIter()]
        assert items == [(('test_key', '0001'), 'Hey gorgeous!'),
                         (('test_key', '0002'), 'A real charmer!')]

        lasts = [val for val in ios.getLastIter()]
        assert lasts == ['Hey gorgeous!', 'A real charmer!']

        items = list(ios.getFullItemIter())
        assert items ==  [(('test_key', '0001', '00000000000000000000000000000000'), 'See ya later.'),
                        (('test_key', '0001', '00000000000000000000000000000001'), 'Hey gorgeous!'),
                        (('test_key', '0002', '00000000000000000000000000000000'), 'Not my type.'),
                        (('test_key', '0002', '00000000000000000000000000000001'), 'Hello sailer!'),
                        (('test_key', '0002', '00000000000000000000000000000002'), 'A real charmer!')]


        items = [(keys, val) for keys,  val in  ios.getTopItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                         (('test_key', '0001'), 'Hey gorgeous!')]

        items = [(keys, val) for keys, val in ios.getLastItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), 'Hey gorgeous!'),
                         (('test_key', '0002'), 'A real charmer!')]

        lasts = [val for val in ios.getLastIter(keys=keys0)]
        assert lasts == ['Hey gorgeous!', 'A real charmer!']

        items = [(keys, val) for keys,  val in ios.getTopItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'A real charmer!')]

        items = [(keys, val) for keys, val in ios.getLastItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), 'A real charmer!')]

        lasts = [val for val in ios.getLastIter(keys=keys1)]
        assert lasts == ['A real charmer!']


        # Test with top keys
        assert ios.put(keys=("test", "pop"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in ios.getTopItemIter(keys=topkeys)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        # test with top parameter
        keys = ("test", )
        items = [(keys, val) for keys, val in ios.getTopItemIter(keys=keys, topive=True)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        # IoItems
        items = list(ios.getFullItemIter(keys=topkeys))
        assert items == [(('test', 'pop', '00000000000000000000000000000000'), 'Not my type.'),
                         (('test', 'pop', '00000000000000000000000000000001'), 'Hello sailer!'),
                         (('test', 'pop', '00000000000000000000000000000002'), 'A real charmer!')]

        # test remove with a specific val
        assert ios.rem(keys=("test_key", "0002"), val=sue)
        items = [(keys, val) for keys, val in ios.getTopItemIter()]
        assert items == [(('test', 'pop'), 'Not my type.'),
                        (('test', 'pop'), 'Hello sailer!'),
                        (('test', 'pop'), 'A real charmer!'),
                        (('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'A real charmer!')]

        assert ios.trim(keys=("test", ""))
        items = [(keys, val) for keys, val in ios.getTopItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'A real charmer!')]

        assert ios.put(keys=keys0, vals=vals0)
        assert ios.put(keys=keys1, vals=vals1)
        assert ios.cnt() == 10
        assert ios.cnt(keys=keys0) == 5
        assert ios.cnt(keys=keys1) == 5
        assert ios.rem(keys=keys0)
        assert ios.cnt(keys=keys0) == 0
        assert ios.trim()  # removes whole db
        assert ios.cnt() == 0


        # test with keys as string not tuple
        keys2 = "keystr"
        bob = "Shove off!"
        assert ios.put(keys=keys2, vals=[bob])
        actuals = ios.get(keys=keys2)
        assert actuals == [bob]
        assert ios.cnt(keys2) == 1
        assert ios.rem(keys2)
        actuals = ios.get(keys=keys2)
        assert actuals == []
        assert ios.cnt(keys2) == 0

        assert ios.put(keys=keys2, vals=[bob])
        actuals = ios.get(keys=keys2)
        assert actuals == [bob]

        bil = "Go away."
        assert ios.pin(keys=keys2, vals=[bil])
        actuals = ios.get(keys=keys2)
        assert actuals == [bil]

        assert ios.add(keys=keys2, val=bob)
        actuals = ios.get(keys=keys2)
        assert actuals == [bil, bob]

        # Test trim and append
        assert ios.trim()  # default trims whole database
        assert ios.put(keys=keys1, vals=[bob, bil])
        assert ios.get(keys=keys1) == [bob, bil]


    asyncio.run(_go())


@needskeri
def test_on_ioset_suber_contract():
    """Test IoSetSuber wrapper operating against WebDBer."""
    async def _go():
        dber, _ = await _open_fake_dber(
            name="ioset-suber-contract",
            stores=["vals."],
            clear=True,
        )

        onios = subing.OnIoSetSuber(db=dber, subkey="vals.")
        assert onios.sdb.flags()["dupsort"] is False

        # test empty keys
        assert onios.cntAll() == 0
        assert onios.cnt(keys="") == 0
        assert onios.cntAll(keys="") == 0
        assert onios.get(keys="") == []
        assert [val for val in onios.getIter(keys="")] == []
        assert onios.getLastItem(keys=()) == ()
        assert onios.getLast(keys=()) == None
        assert onios.getLastItem(keys="") == ()
        assert onios.getLast(keys="") == None

        keys0 = ('A', 'B')
        keys1 = ('B', 'C')
        keys2 = ('C', 'D')
        keys3 = ('E', 'F')
        keys4 = ('Z', 'Z')
        keys5 = ('A', 'A')

        vals0 = ["z", "m", "x", "a"]
        vals1 = ["w", "n", "y", "d"]
        vals2 = ["p", "o", "h", "f"]
        vals3 = ["k", "j", "l"]

        # fill database
        assert onios.put(keys=keys0, vals=vals0)  # default on = 0
        assert onios.put(keys=keys1, vals=vals1)  # default on = 0
        assert onios.put(keys=keys2, vals=vals2)  # default on = 0

        assert onios.cntAll() == 12
        assert onios.cntAll(keys="") == 12
        assert onios.cntAll(keys1) == 4
        assert onios.cntAll(keys1, on=2) == 0
        assert onios.cnt(keys='') == 0
        assert onios.cnt(keys=keys0) == 4
        assert onios.cnt(keys=keys0, on=0, ion=2) == 2
        assert onios.cnt(keys=keys1) == 4
        assert onios.cnt(keys=keys2) == 4

        # keys0
        # ion default 0
        assert [val for val in onios.getIter(keys=keys0)] == vals0
        assert onios.get(keys=keys0) == vals0
        assert onios.getItem(keys=keys0) == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]
        assert onios.cnt(keys=keys0) == 4
        assert onios.getLastItem(keys=keys0) == (keys0, 0, "a")
        assert onios.getLast(keys=keys0) == "a"

        # ion = 0
        assert [val for val in onios.getIter(keys=keys0, ion=0)] == vals0
        assert onios.get(keys=keys0, ion=0) == vals0
        assert onios.getItem(keys=keys0, ion=0) == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]
        assert onios.cnt(keys=keys0, ion=0) == 4

        # ion = 1
        assert [val for val in onios.getIter(keys=keys0, ion=1)] == ["m", "x", "a"]
        assert onios.get(keys=keys0, ion=1) == ["m", "x", "a"]
        assert onios.getItem(keys=keys0, ion=1) == \
        [
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]
        assert onios.cnt(keys=keys0, ion=1) == 3

        # ion = 2
        assert [val for val in onios.getIter(keys=keys0, ion=2)] == ["x", "a"]
        assert onios.get(keys=keys0, ion=2) == ["x", "a"]
        assert onios.cnt(keys=keys0, ion=2) == 2

        # ion = 3
        assert [val for val in onios.getIter(keys=keys0, ion=3)] == ["a"]
        assert onios.get(keys=keys0, ion=3) == ["a"]
        assert onios.cnt(keys=keys0, ion=3) == 1

        # ion = 4  past end of keys0 set
        assert [val for val in onios.getIter(keys=keys0, ion=4)] == []
        assert onios.get(keys=keys0, ion=4) == []
        assert onios.cnt(keys=keys0, ion=4) == 0

        # keys1
        # ion default 0
        assert [val for val in onios.getIter(keys=keys1)] == vals1
        assert onios.get(keys=keys1) == vals1
        assert onios.cnt(keys=keys1) == 4
        assert onios.getLastItem(keys=keys1) == (keys1, 0, "d")
        assert onios.getLast(keys=keys1) == "d"

        # ion = 2
        assert [val for val in onios.getIter(keys=keys1, ion=2)] == ["y", "d"]
        assert onios.get(keys=keys1, ion=2) == ["y", "d"]
        assert onios.cnt(keys=keys1, ion=2) == 2

        # keys0 make gap keys0
        assert onios.rem(keys=keys0, val="m")

        # ion default 0, on default 0
        assert [val for val in onios.getIter(keys=keys0)] == ["z", "x", "a"]
        assert onios.get(keys=keys0) == ["z", "x", "a"]
        assert onios.cnt(keys=keys0) == 3
        assert onios.getLastItem(keys=keys0) == (keys0, 0, "a")
        assert onios.getLast(keys=keys0) == "a"

        # ion = 1
        assert [val for val in onios.getIter(keys=keys0, on=0, ion=1)] == ["x", "a"]
        assert onios.get(keys=keys0,on=0, ion=1) == ["x", "a"]
        assert onios.cnt(keys=keys0, on=0, ion=1) == 2

        # clear keys0 and keys1
        assert onios.rem(keys=keys0) # default on = 0
        assert onios.rem(keys=keys1, on=0)
        assert onios.cnt(keys=keys0) == 0
        assert onios.cnt(keys=keys1) == 0

        # restore key0, keys1 using add
        for val in vals0:
            assert onios.add(keys0, val=val)  # default on=0
        assert onios.get(keys0, on=0) == vals0

        for val in vals1:
            assert onios.add(keys1, on=0, val=val)
        assert onios.get(keys1, on=0) == vals1

        # test pinOn and appendOn
        assert not onios.get(keys3, on=0)
        assert onios.put(keys3, vals=vals3)  # default on = 0
        assert onios.get(keys3, on=0) == vals3
        assert not onios.add(keys3, val='k')  # idempotent wont add if already there
        assert onios.get(keys3, on=0) == vals3
        assert onios.add(keys3, on=0, val='g')
        assert onios.get(keys3, on=0) == ['k', 'j', 'l', 'g']
        assert onios.pin(keys3, vals=vals3)  # default on=0
        assert onios.get(keys3, on=0) == vals3

        assert onios.add(keys3, on=1, val='z')
        assert onios.add(keys3, on=1, val='y')
        assert onios.put(keys3, on=2, vals=["x", "w"])
        assert onios.append(keys3, vals=["v", "u"]) == 3  # on = 3
        assert onios.append(keys3, vals="t") == 4  # on = 4

        assert onios.cntAll(keys3, on=0) == 10
        assert onios.cntAll(keys3, on=2) == 5

        assert [item for item in onios.getAllItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [item for item in onios.getAllItemIter(keys3, on=3)] == \
        [
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        # getOnItemIter
        with pytest.raises(TypeError):
            [item for item in onios.getItemIter()]

        assert [item for item in onios.getItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
        ]

        assert [item for item in onios.getItemIter(keys3, on=3)] == \
        [
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
        ]

        assert onios.remAll(keys3, on=2)

        assert [item for item in onios.getItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
        ]

        assert onios.remAll(keys3, on=0)
        assert [item for item in onios.getAllItemIter(keys3)] == []

        assert onios.put(keys3, vals=vals3)  # default on = 0
        assert onios.put(keys3, on=1, vals=['z', 'y'])
        assert onios.put(keys3, on=2, vals=["x", "w"])
        assert onios.append(keys3, vals=["v", "u"]) == 3  # on = 3
        assert onios.append(keys3, vals="t") == 4  # on = 4

        assert [item for item in onios.getAllItemIter()] == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a'),
            (('B', 'C'), 0, 'w'),
            (('B', 'C'), 0, 'n'),
            (('B', 'C'), 0, 'y'),
            (('B', 'C'), 0, 'd'),
            (('C', 'D'), 0, 'p'),
            (('C', 'D'), 0, 'o'),
            (('C', 'D'), 0, 'h'),
            (('C', 'D'), 0, 'f'),
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in onios.getAllIter()] == \
        ['z','m','x','a','w','n','y','d','p','o','h','f','k','j','l','z','y','x','w','v','u','t']

        assert [item for item in onios.getAllItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in onios.getAllIter(keys3)] == \
        ['k', 'j', 'l', 'z', 'y', 'x', 'w', 'v', 'u', 't']

        assert [item for item in onios.getAllItemIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in onios.getAllIter(keys3, on=2)] == \
        ['x', 'w', 'v', 'u', 't']


        assert [item for item in onios.getTopItemIter()] == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a'),
            (('B', 'C'), 0, 'w'),
            (('B', 'C'), 0, 'n'),
            (('B', 'C'), 0, 'y'),
            (('B', 'C'), 0, 'd'),
            (('C', 'D'), 0, 'p'),
            (('C', 'D'), 0, 'o'),
            (('C', 'D'), 0, 'h'),
            (('C', 'D'), 0, 'f'),
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [item for item in onios.getTopItemIter(keys=("A", ))] == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]

        # Test last iter   getOnAllLastItemIter
        # whole db
        assert [item for item in onios.getAllLastItemIter()] == \
        [
            (('A', 'B'), 0, 'a'),
            (('B', 'C'), 0, 'd'),
            (('C', 'D'), 0, 'f'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in onios.getAllLastIter()] == \
        ['a', 'd', 'f', 'l', 'y', 'w', 'u', 't']

        # all on for keys3
        assert [item for item in onios.getAllLastItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in onios.getAllLastIter(keys3)] == \
        ['l', 'y', 'w', 'u', 't']

        # all on>=2 for keys3
        assert [item for item in onios.getAllLastItemIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in onios.getAllLastIter(keys3, on=2)] == \
        ['w', 'u', 't']


        # Test back iter
        # whole db
        assert [item for item in onios.getAllItemBackIter()] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'k'),
            (('C', 'D'), 0, 'f'),
            (('C', 'D'), 0, 'h'),
            (('C', 'D'), 0, 'o'),
            (('C', 'D'), 0, 'p'),
            (('B', 'C'), 0, 'd'),
            (('B', 'C'), 0, 'y'),
            (('B', 'C'), 0, 'n'),
            (('B', 'C'), 0, 'w'),
            (('A', 'B'), 0, 'a'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'z')
        ]

        assert [val for val in onios.getAllBackIter()] == \
        ['t','u','v','w','x','y','z','l','j','k','f','h','o','p','d','y','n','w','a','x','m','z']

        # keys3  all on
        assert [item for item in onios.getAllItemBackIter(keys3)] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'k'),
        ]

        assert [val for val in onios.getAllBackIter(keys3)] == \
        ['t','u','v','w','x','y','z','l','j','k']

        # keys3  on <= 2
        assert [item for item in onios.getAllItemBackIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'k'),
        ]

        assert [val for val in onios.getAllBackIter(keys3, on=2)] == \
        ['w','x','y','z','l','j','k']


        # Test last back iter
        # whole db
        assert [item for item in onios.getAllLastItemBackIter()] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 0, 'l'),
            (('C', 'D'), 0, 'f'),
            (('B', 'C'), 0, 'd'),
            (('A', 'B'), 0, 'a')
        ]

        assert [val for val in onios.getAllLastBackIter()] == \
        ['t', 'u', 'w', 'y', 'l', 'f', 'd', 'a']

        # keys3  all on
        assert [item for item in onios.getAllLastItemBackIter(keys3)] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 0, 'l')
        ]

        assert [val for val in onios.getAllLastBackIter(keys3)] == \
        ['t', 'u', 'w', 'y', 'l']

        # keys3  on <= 2
        assert [item for item in onios.getAllLastItemBackIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 0, 'l')
        ]

        assert [val for val in onios.getAllLastBackIter(keys3, on=2)] == \
        ['w', 'y', 'l']


        """Done Test"""
    
    asyncio.run(_go())


@needskeri
def test_webdb_baser():
    """Test WebBaser class."""
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        assert baser.opened
        assert baser.name == "main"

        assert isinstance(baser.evts, subing.SerderSuber)
        assert isinstance(baser.sigs, subing.CesrIoSetSuber)
        assert isinstance(baser.dtss, subing.CesrSuber)
        assert isinstance(baser.rcts, subing.CatCesrIoSetSuber)
        assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
        assert isinstance(baser.kels, subing.OnIoSetSuber)
        assert isinstance(baser.ooes, subing.OnIoSetSuber)
        assert isinstance(baser.pses, subing.OnIoSetSuber)
        assert isinstance(baser.dels, subing.OnIoSetSuber)
        assert isinstance(baser.ldes, subing.OnIoSetSuber)
        assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
        assert isinstance(baser.esrs, koming.Komer)
        assert isinstance(baser.states, koming.Komer)
        assert isinstance(baser.habs, koming.Komer)
        assert isinstance(baser.names, subing.Suber)
        assert isinstance(baser.imgs, subing.CesrSuber)
        assert isinstance(baser.iimgs, subing.CesrSuber)

        await baser.close(clear=True)
        assert not baser.opened

        # test not opened on init
        baser = WebBaser(reopen=False)
        assert isinstance(baser, WebBaser)
        assert baser.name == "main"
        assert baser.opened == False

        await baser.reopen(storageOpener=backend.open)
        assert baser.opened

        assert isinstance(baser.evts, subing.SerderSuber)
        assert isinstance(baser.sigs, subing.CesrIoSetSuber)
        assert isinstance(baser.dtss, subing.CesrSuber)
        assert isinstance(baser.rcts, subing.CatCesrIoSetSuber)
        assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
        assert isinstance(baser.kels, subing.OnIoSetSuber)
        assert isinstance(baser.ooes, subing.OnIoSetSuber)
        assert isinstance(baser.pses, subing.OnIoSetSuber)
        assert isinstance(baser.dels, subing.OnIoSetSuber)
        assert isinstance(baser.ldes, subing.OnIoSetSuber)
        assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
        assert isinstance(baser.esrs, koming.Komer)
        assert isinstance(baser.states, koming.Komer)
        assert isinstance(baser.habs, koming.Komer)
        assert isinstance(baser.names, subing.Suber)
        assert isinstance(baser.imgs, subing.CesrSuber)
        assert isinstance(baser.iimgs, subing.CesrSuber)

        await baser.close(clear=True)
        assert not baser.opened

        backend = FakeStorageBackend()
        baser = WebBaser(name="test")

        # Open WebBaser using the fake async storage backend
        await baser.reopen(storageOpener=backend.open)

        # Basic identity checks
        assert baser.opened is True
        assert baser.env is not None

        # Subdb type checks (WebDB-safe versions)
        assert isinstance(baser.evts, subing.SerderSuber)
        assert isinstance(baser.sigs, subing.CesrIoSetSuber)
        assert isinstance(baser.dtss, subing.CesrSuber)
        assert isinstance(baser.rcts, subing.CatCesrIoSetSuber)
        assert isinstance(baser.ures, subing.CatCesrIoSetSuber)

        # All dupsort subdbs become IoSet/OnIoSet
        assert isinstance(baser.ooes, subing.OnIoSetSuber)
        assert isinstance(baser.pses, subing.OnIoSetSuber)
        assert isinstance(baser.dels, subing.OnIoSetSuber)
        assert isinstance(baser.ldes, subing.OnIoSetSuber)

        # Komers
        assert isinstance(baser.esrs, koming.Komer)
        assert isinstance(baser.states, koming.Komer)
        assert isinstance(baser.habs, koming.Komer)

        # ---- Begin functional tests ----

        preb = 'DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
        digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
        sn = 3

        ked = dict(v=versify(kind=Kinds.json, size=0), t="rot", d=digb.decode("utf-8"),
               i=preb.decode("utf-8"), s="{:x}".format(sn), p=preb.decode("utf-8"),
               kt="0", k=[], nt="0", n=[], bt="0", br=[], ba=[], a=[])
        skedb = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        while True:
            ked["v"] = versify(kind=Kinds.json, size=len(skedb))
            next_skedb = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(next_skedb) == len(skedb):
                skedb = next_skedb
                break
            skedb = next_skedb

        sig0b = 'ABz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ'.encode("utf-8")
        sig1b = 'AA_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z'.encode("utf-8")

        wit0b = 'BBuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT'.encode("utf-8")
        wit1b = 'BAhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT'.encode("utf-8")
        wsig0b = '0BATimrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9'.encode("utf-8")
        wsig1b = '0BBIRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z'.encode("utf-8")

        valb = 'EAzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEH'.encode("utf-8")
        vdigb = 'EBiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-'.encode("utf-8")
        vsig0b = 'AAKAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe81Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1yQJmiu5AzJ9'.encode("utf-8")
        vsig1b = 'ABAKAV2zJ91Timrykocna6Z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz'.encode("utf-8")


        key = dgKey(preb, digb)
        assert key == f"{preb.decode()}.{digb.decode()}".encode()

        # Build minimal Serder
        sked = serdering.SerderKERI(raw=skedb, verify=False)

        # .evts tests
        assert baser.evts.get(keys=(preb, digb)) is None
        assert baser.evts.rem(keys=(preb, digb)) is False

        assert baser.evts.put(keys=(preb, digb), val=sked) is True
        assert baser.evts.get(keys=(preb, digb)).raw == skedb

        # put again should not overwrite
        assert baser.evts.put(keys=(preb, digb), val=sked) is False

        # pin should overwrite
        assert baser.evts.pin(keys=(preb, digb), val=sked) is True
        assert baser.evts.get(keys=(preb, digb)).raw == skedb

        # remove
        assert baser.evts.rem(keys=(preb, digb)) is True
        assert baser.evts.get(keys=(preb, digb)) is None

        # ---- EventSourceRecord tests ----

        record = EventSourceRecord()

        assert baser.esrs.get(key) is None
        assert baser.esrs.put(key, record) is True

        actual = baser.esrs.get(key)
        assert actual == record

        # modify record, ensure put does not overwrite
        record.local = False
        assert baser.esrs.put(key, record) is False

        actual = baser.esrs.get(key)
        assert actual.local != record.local
        assert actual != record

        # pin overwrites
        assert baser.esrs.pin(key, record) is True
        actual = baser.esrs.get(key)
        assert actual.local == record.local
        assert actual == record

        # test first seen event log .fels sub db
        preA = b'BAKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'
        preB = b'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'
        preC = b'EIDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'

        digA = b'EA73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'
        digU = b'EB73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'
        digV = b'EC4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY'
        digW = b'EDAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w'
        digX = b'EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o'
        digY = b'EFrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk'

        digC = b'EG5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w'

        assert baser.fels.get(keys=preA, on=0) is None
        assert baser.fels.rem(keys=preA, on=0) == False
        assert baser.fels.put(keys=preA, on=0, val=digA) == True
        assert baser.fels.get(keys=preA, on=0) == digA.decode("utf-8")
        assert baser.fels.put(keys=preA, on=0, val=digA) == False
        assert baser.fels.pin(keys=preA, on=0, val=digA) == True
        assert baser.fels.get(keys=preA, on=0) == digA.decode("utf-8")
        assert baser.fels.rem(keys=preA, on=0) == True
        assert baser.fels.get(keys=preA, on=0) is None

        # test appendOn
        # empty database
        assert baser.fels.get(keys=preB, on=0) is None
        on = baser.fels.append(keys=preB, val=digU)
        assert on == 0
        assert baser.fels.get(keys=preB, on=0) == digU.decode("utf-8")
        assert baser.fels.rem(keys=preB, on=0) == True
        assert baser.fels.get(keys=preB, on=0) is None

        # earlier pre in database only
        assert baser.fels.put(keys=preA, on=0, val=digA) == True
        on = baser.fels.append(keys=preB, val=digU)
        assert on == 0
        assert baser.fels.get(keys=preB, on=0) == digU.decode("utf-8")
        assert baser.fels.rem(keys=preB, on=0) == True
        assert baser.fels.get(keys=preB, on=0) is None

        # earlier and later pre in baser but not same pre
        assert baser.fels.get(keys=preA, on=0) == digA.decode("utf-8")
        assert baser.fels.put(keys=preC, on=0, val=digC) == True
        on = baser.fels.append(keys=preB, val=digU)
        assert on == 0
        assert baser.fels.get(keys=preB, on=0) == digU.decode("utf-8")
        assert baser.fels.rem(keys=preB, on=0) == True
        assert baser.fels.get(keys=preB, on=0) is None

        # later pre only
        assert baser.fels.rem(keys=preA, on=0) == True
        assert baser.fels.get(keys=preA, on=0) is None
        assert baser.fels.get(keys=preC, on=0) == digC.decode("utf-8")
        on = baser.fels.append(keys=preB, val=digU)
        assert on == 0
        assert baser.fels.get(keys=preB, on=0) == digU.decode("utf-8")

        # earlier pre and later pre and earlier entry for same pre
        assert baser.fels.put(keys=preA, on=0, val=digA) == True
        on = baser.fels.append(keys=preB, val=digV)
        assert on == 1
        assert baser.fels.get(keys=preB, on=1) == digV.decode("utf-8")

        # earlier entry for same pre but only same pre
        assert baser.fels.rem(keys=preA, on=0) == True
        assert baser.fels.get(keys=preA, on=0) is None
        assert baser.fels.rem(keys=preC, on=0) == True
        assert baser.fels.get(keys=preC, on=0) is None
        # another value for preB
        on = baser.fels.append(keys=preB, val=digW)
        assert on == 2
        assert baser.fels.get(keys=preB, on=2) == digW.decode("utf-8")
        # yet another value for preB
        on = baser.fels.append(keys=preB, val=digX)
        assert on == 3
        assert baser.fels.get(keys=preB, on=3) == digX.decode("utf-8")
        # yet another value for preB
        on = baser.fels.append(keys=preB, val=digY)
        assert on == 4
        assert baser.fels.get(keys=preB, on=4) == digY.decode("utf-8")

         # replay preB events in database
        _pre = lambda k: k[0].encode() if isinstance(k[0], str) else k[0]
        items = [(_pre(keys), on, val) for keys, on, val in baser.fels.getAllItemIter(keys=preB)]
        assert items == [(preB, 0, digU.decode("utf-8")), (preB, 1, digV.decode("utf-8")), (preB, 2, digW.decode("utf-8")), (preB, 3, digX.decode("utf-8")), (preB, 4, digY.decode("utf-8"))]

        # resume replay preB events at on = 3
        items = [(_pre(keys), on, val) for keys, on, val in baser.fels.getAllItemIter(keys=preB, on=3)]
        assert items == [(preB, 3, digX.decode("utf-8")), (preB, 4, digY.decode("utf-8"))]

        # resume replay preB events at on = 5
        items = [(_pre(keys), on, val) for keys, on, val in baser.fels.getAllItemIter(keys=preB, on=5)]
        assert items == []

        # replay all events in database with pre events before and after
        assert baser.fels.put(keys=preA, on=0, val=digA) == True
        assert baser.fels.put(keys=preC, on=0, val=digC) == True

        # replay all pres in first-seen order (keys=b'', on=0)
        items = [(_pre(keys), on, val) for keys, on, val in baser.fels.getAllItemIter(keys=b'', on=0)]
        assert items == [
            (preA, 0, digA.decode("utf-8")),
            (preB, 0, digU.decode("utf-8")),
            (preB, 1, digV.decode("utf-8")),
            (preB, 2, digW.decode("utf-8")),
            (preB, 3, digX.decode("utf-8")),
            (preB, 4, digY.decode("utf-8")),
            (preC, 0, digC.decode("utf-8")),
        ]

        # Test .dtss datetime stamps
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # test .dtss sub db methods - now returns Dater objects
        dater1 = coring.Dater(dts='2020-08-22T17:50:09.988921+00:00')
        dater2 = coring.Dater(dts='2020-08-22T17:50:10.000000+00:00')

        assert baser.dtss.get(keys=key) is None
        assert baser.dtss.rem(keys=key) == False
        assert baser.dtss.put(keys=key, val=dater1) == True
        result = baser.dtss.get(keys=key)
        assert isinstance(result, coring.Dater)
        assert result.dts == dater1.dts
        assert baser.dtss.put(keys=key, val=dater2) == False  # idempotent
        result = baser.dtss.get(keys=key)
        assert result.dts == dater1.dts  # still original
        assert baser.dtss.pin(keys=key, val=dater2) == True  # overwrites
        result = baser.dtss.get(keys=key)
        assert result.dts == dater2.dts
        assert baser.dtss.rem(keys=key) == True
        assert baser.dtss.get(keys=key) is None

        
        # Test .aess authorizing event source seal couples
        # test .aess sub db methods
        ssnu1 = b'0AAAAAAAAAAAAAAAAAAAAAAB'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        ssnu2 = b'0AAAAAAAAAAAAAAAAAAAAAAC'
        sdig2 = b'EBYYJRCCpAGO7WjjsLhtHVR37Pawv67kveIFUPvt38x0'
        number1 = coring.Number(qb64b=ssnu1)
        diger1 = coring.Diger(qb64b=sdig1)
        number2 = coring.Number(qb64b=ssnu2)
        diger2 = coring.Diger(qb64b=sdig2)
        val1 = (number1, diger1)
        val2 = (number2, diger2)

        assert baser.aess.get(keys=(preb, digb)) == None
        assert baser.aess.rem(keys=(preb, digb)) == False
        assert baser.aess.put(keys=(preb, digb), val=val1) == True
        result = baser.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber1, rdiger1 = result
        assert rnumber1.qb64b == number1.qb64b
        assert rdiger1.qb64b == diger1.qb64b
        assert baser.aess.put(keys=(preb, digb), val=val2) == False
        result = baser.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber1, rdiger1 = result
        assert rnumber1.qb64b == number1.qb64b
        assert rdiger1.qb64b == diger1.qb64b
        assert baser.aess.pin(keys=(preb, digb), val=val2) == True
        result = baser.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber2, rdiger2 = result
        assert rnumber2.qb64b == number2.qb64b
        assert rdiger2.qb64b == diger2.qb64b
        assert baser.aess.rem(keys=(preb, digb)) == True
        assert baser.aess.get(keys=(preb, digb)) == None
        
        # test .sigs sub db methods
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        assert baser.sigs.get(keys=key) == []
        assert baser.sigs.cnt(keys=key) == 0
        assert baser.sigs.rem(keys=key) == False

        # Create valid test signatures
        signer0 = signing.Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = signing.Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)

        siger0 = indexing.Siger(raw=cigar0.raw, code=indexing.IdrDex.Ed25519_Sig, index=0)
        siger1 = indexing.Siger(raw=cigar1.raw, code=indexing.IdrDex.Ed25519_Sig, index=1)

        assert baser.sigs.put(keys=key, vals=[siger0]) == True
        assert [s.qb64b for s in baser.sigs.get(keys=key)] == [siger0.qb64b]
        assert baser.sigs.cnt(keys=key) == 1
        assert baser.sigs.put(keys=key, vals=[siger0]) == False  # duplicate, idempotent
        assert [s.qb64b for s in baser.sigs.get(keys=key)] == [siger0.qb64b]
        assert baser.sigs.add(keys=key, val=siger1) == True
        assert [s.qb64b for s in baser.sigs.get(keys=key)] == [siger0.qb64b, siger1.qb64b]
        assert [val.qb64b for val in baser.sigs.getIter(keys=key)] == [siger0.qb64b, siger1.qb64b]
        assert baser.sigs.rem(keys=key) == True
        assert baser.sigs.get(keys=key) == []
        assert baser.sigs.put(keys=key, vals=[siger0, siger1]) == True
        for val in [siger0, siger1]:
            assert baser.sigs.rem(keys=key, val=val) == True
        assert baser.sigs.get(keys=key) == []
        assert baser.sigs.put(keys=key, vals=[siger0, siger1]) == True
        for val in baser.sigs.getIter(keys=key):
            assert baser.sigs.rem(keys=key, val=val) == True
        assert baser.sigs.get(keys=key) == []

        assert baser.sigs.put(keys=key, vals=[siger0]) == True
        assert [s.qb64b for s in baser.sigs.get(keys=key)] == [siger0.qb64b]
        assert baser.sigs.put(keys=key, vals=[siger1]) == True
        assert [s.qb64b for s in baser.sigs.get(keys=key)] == [siger0.qb64b, siger1.qb64b]
        assert baser.sigs.rem(keys=key) == True
        assert baser.sigs.put(keys=key, vals=[siger1, siger0]) == True
        assert [s.qb64b for s in baser.sigs.get(keys=key)] == [siger1.qb64b, siger0.qb64b]
        assert baser.sigs.rem(keys=key) == True
        assert baser.sigs.get(keys=key) == []
        assert baser.sigs.put(keys=key, vals=[siger0, siger1]) == True

        # test .wigs sub db methods (witness indexed sigs)
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # Create valid test signatures
        signer0 = signing.Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = signing.Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)

        siger0 = indexing.Siger(raw=cigar0.raw, code=indexing.IdrDex.Ed25519_Sig, index=0)
        siger1 = indexing.Siger(raw=cigar1.raw, code=indexing.IdrDex.Ed25519_Sig, index=1)

        # Use siger objects for testing
        wig0 = siger0
        wig1 = siger1

        # Test empty state
        assert baser.wigs.get(keys=key) == []
        assert baser.wigs.cnt(keys=key) == 0
        assert baser.wigs.rem(keys=key) == False

        # Test pin with multiple values
        assert baser.wigs.pin(keys=key, vals=[wig1, wig0]) == True
        result = baser.wigs.get(keys=key)
        assert len(result) == 2
        # Just verify both are present (don't test exact order)
        result_bytes = set(w.qb64b for w in result)
        assert result_bytes == {wig0.qb64b, wig1.qb64b}
        assert baser.wigs.cnt(keys=key) == 2

        # Test pin overwrites
        assert baser.wigs.pin(keys=key, vals=[wig0]) == True
        result = baser.wigs.get(keys=key)
        assert len(result) == 1
        assert result[0].qb64b == wig0.qb64b

        # Reset to both
        assert baser.wigs.pin(keys=key, vals=[wig1, wig0]) == True
        assert baser.wigs.cnt(keys=key) == 2

        # Test add, duplicate should return False
        assert baser.wigs.add(keys=key, val=wig0) == False  # duplicate
        assert baser.wigs.add(keys=key, val=wig1) == False  # duplicate
        assert baser.wigs.cnt(keys=key) == 2

        # Test getIter, returns just values
        result_list = list(baser.wigs.getIter(keys=key))
        assert len(result_list) == 2
        assert set(w.qb64b for w in result_list) == {wig0.qb64b, wig1.qb64b}

        # Test remove all
        assert baser.wigs.rem(keys=key) == True
        assert baser.wigs.get(keys=key) == []
        assert baser.wigs.cnt(keys=key) == 0

        # Test individual removal by value
        vals = [wig0, wig1]
        assert baser.wigs.pin(keys=key, vals=vals) == True
        for val in vals:
            assert baser.wigs.rem(keys=key, val=val) == True
        assert baser.wigs.get(keys=key) == []

        # Test removal while iterating
        assert baser.wigs.pin(keys=key, vals=vals) == True
        for val in baser.wigs.getIter(keys=key):
            assert baser.wigs.rem(keys=key, val=val) == True
        assert baser.wigs.get(keys=key) == []

        # Test sequence with individual pins
        assert baser.wigs.pin(keys=key, vals=[wig0]) == True
        result = baser.wigs.get(keys=key)
        assert len(result) == 1
        assert result[0].qb64b == wig0.qb64b

        assert baser.wigs.pin(keys=key, vals=[wig1]) == True
        result = baser.wigs.get(keys=key)
        assert len(result) == 1
        assert result[0].qb64b == wig1.qb64b

        assert baser.wigs.pin(keys=key, vals=[wig1, wig0]) == True
        result = baser.wigs.get(keys=key)
        assert len(result) == 2
        assert set(w.qb64b for w in result) == {wig0.qb64b, wig1.qb64b}

        assert baser.wigs.rem(keys=key) == True
        assert baser.wigs.get(keys=key) == []

        # test .rcts

        # Create test prefixes and cigars
        wit0 = coring.Prefixer(qb64=wit0b.decode('utf-8'))  # Convert from qb64 string
        wit1 = coring.Prefixer(qb64=wit1b.decode('utf-8'))

        # Create cigars (non-indexed signatures)
        cigar0 = coring.Cigar(qb64=wsig0b.decode('utf-8'))
        cigar1 = coring.Cigar(qb64=wsig1b.decode('utf-8'))

        # Test with CESR tuples (insertion order)
        assert baser.rcts.put(key, vals=[(wit0, cigar0), (wit1, cigar1)]) == True
        result = baser.rcts.get(key)
        assert len(result) == 2
        # Check insertion order: wit0 inserted first, wit1 second
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        assert result[1][0].qb64 == wit1.qb64
        assert result[1][1].qb64 == cigar1.qb64

        # Test duplicate (should not add)
        assert baser.rcts.put(key, vals=[(wit0, cigar0)]) == False
        result = baser.rcts.get(key)
        assert len(result) == 2
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        assert result[1][0].qb64 == wit1.qb64
        assert result[1][1].qb64 == cigar1.qb64

        # Test adding new item
        wit2 = coring.Prefixer(qb64='BNewTestPrefix000000000000000000000000000000')
        cigar2 = coring.Cigar(qb64='BNewTestSignature00000000000000000000000000000000000000000000000000000000000000000000000')
        assert baser.rcts.add(key, (wit2, cigar2)) == True
        result = baser.rcts.get(key)
        assert len(result) == 3
        # Insertion order: wit0, wit1, wit2
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        assert result[1][0].qb64 == wit1.qb64
        assert result[1][1].qb64 == cigar1.qb64
        assert result[2][0].qb64 == wit2.qb64
        assert result[2][1].qb64 == cigar2.qb64

        # Test duplicate add returns False
        assert baser.rcts.add(key, (wit0, cigar0)) == False

        # Test getIter maintains insertion order
        iter_result = [val for val in baser.rcts.getIter(key)]
        assert len(iter_result) == 3
        assert iter_result[0][0].qb64 == wit0.qb64
        assert iter_result[0][1].qb64 == cigar0.qb64
        assert iter_result[1][0].qb64 == wit1.qb64
        assert iter_result[1][1].qb64 == cigar1.qb64
        assert iter_result[2][0].qb64 == wit2.qb64
        assert iter_result[2][1].qb64 == cigar2.qb64

        # Test removal
        assert baser.rcts.rem(key) == True
        assert baser.rcts.get(key) == []

        # Test insertion order preserved when inserting in different order
        vals = [(wit1, cigar1), (wit0, cigar0)]
        assert baser.rcts.put(key, vals) == True
        result = baser.rcts.get(key)
        assert len(result) == 2
        # Should maintain insertion order: wit1 first, wit0 second
        assert result[0][0].qb64 == wit1.qb64
        assert result[0][1].qb64 == cigar1.qb64
        assert result[1][0].qb64 == wit0.qb64
        assert result[1][1].qb64 == cigar0.qb64

        # Test individual removal
        assert baser.rcts.rem(key, (wit1, cigar1)) == True
        result = baser.rcts.get(key)
        assert len(result) == 1
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64

        assert baser.rcts.rem(key) == True
        assert baser.rcts.get(key) == []

        # Unverified Receipt Escrows
        # test .ures insertion order dup methods.  dup vals are insertion order

        # Setup CESR test values
        diger0 = coring.Diger(ser=b"event0")
        diger1 = coring.Diger(ser=b"event1")
        diger2 = coring.Diger(ser=b"event2")
        diger3 = coring.Diger(ser=b"event3")
        diger4 = coring.Diger(ser=b"event4")

        pre0 = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        signer0 = signing.Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = signing.Signer(transferable=False, seed=b'abcdef0123456789abcdef0123456789')
        signer2 = signing.Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')
        signer3 = signing.Signer(transferable=False, seed=b'0011223344556677889900112233445566')
        signer4 = signing.Signer(transferable=False, seed=b'ffeeddccbbaa99887766554433221100')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)
        cigar2 = signer2.sign(ser=test_data)
        cigar3 = signer3.sign(ser=test_data)
        cigar4 = signer4.sign(ser=test_data)

        pre1 = coring.Prefixer(qb64=signer0.verfer.qb64)
        pre2 = coring.Prefixer(qb64=signer1.verfer.qb64)
        pre3 = coring.Prefixer(qb64=signer2.verfer.qb64)
        pre4 = coring.Prefixer(qb64=signer3.verfer.qb64)

        key = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=0).qb64)

        cesrVal = (diger0, pre0, cigar0)
        cesrVals = [cesrVal]

        assert baser.ures.get(key) == []
        assert baser.ures.getLast(keys=key) is None
        assert baser.ures.cnt(key) == 0
        assert baser.ures.rem(key) == False

        assert baser.ures.put(keys=key, vals=cesrVals) == True
        stored = baser.ures.get(key)
        assert len(stored) == 1
        diger_s, pre_s, cigar_s = stored[0]
        assert diger_s.qb64 == diger0.qb64
        assert pre_s.qb64 == pre0.qb64
        assert cigar_s.qb64b == cigar0.qb64b

        result = baser.ures.getLast(keys=key)
        assert result is not None
        diger_l, pre_l, cigar_l = result
        assert diger_l.qb64 == diger0.qb64
        assert pre_l.qb64 == pre0.qb64
        assert cigar_l.qb64b == cigar0.qb64b

        assert baser.ures.put(keys=key, vals=[(diger0, pre0, cigar0)]) == False  # duplicate, no change
        result = baser.ures.get(key)
        assert len(result) == 1
        d, p, c = result[0]
        assert d.qb64 == diger0.qb64
        assert p.qb64 == pre0.qb64
        assert c.qb64b == cigar0.qb64b

        assert baser.ures.add(key, (diger0, pre0, cigar0)) == False   # duplicate
        assert baser.ures.add(key, (diger1, pre1, cigar1)) == True

        result = baser.ures.get(key)
        assert len(result) == 2
        d0, p0, c0 = result[0]
        assert d0.qb64 == diger0.qb64
        assert p0.qb64 == pre0.qb64
        assert c0.qb64b == cigar0.qb64b
        d1, p1, c1 = result[1]
        assert d1.qb64 == diger1.qb64
        assert p1.qb64 == pre1.qb64
        assert c1.qb64b == cigar1.qb64b

        result_iter = [val for val in baser.ures.getIter(key)]
        assert len(result_iter) == 2
        d0, p0, c0 = result_iter[0]
        assert d0.qb64 == diger0.qb64
        assert p0.qb64 == pre0.qb64
        assert c0.qb64b == cigar0.qb64b
        d1, p1, c1 = result_iter[1]
        assert d1.qb64 == diger1.qb64
        assert p1.qb64 == pre1.qb64
        assert c1.qb64b == cigar1.qb64b

        assert baser.ures.rem(key) == True
        assert baser.ures.get(key) == []

        # Setup multi-key tests for getTopItemIter
        aKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=1).qb64)
        aVals = [(diger0, pre0, cigar0), (diger1, pre1, cigar1), (diger2, pre2, cigar2)]
        bKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=2).qb64)
        bVals = [(diger1, pre1, cigar1), (diger2, pre2, cigar2), (diger3, pre3, cigar3)]
        cKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=4).qb64)
        cVals = [(diger2, pre2, cigar2), (diger3, pre3, cigar3)]
        dKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=7).qb64)
        dVals = [(diger3, pre3, cigar3), (diger4, pre4, cigar4)]

        assert baser.ures.put(keys=aKey, vals=aVals)
        assert baser.ures.put(keys=bKey, vals=bVals)
        assert baser.ures.put(keys=cKey, vals=cVals)
        assert baser.ures.put(keys=dKey, vals=dVals)

        # Test getTopItemIter with no key
        items = [(keys, val) for keys, val in baser.ures.getTopItemIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == aKey
        # Verify total count
        assert len(items) == len(aVals) + len(bVals) + len(cVals) + len(dVals)

        # aVals — iterate at aKey only
        items = [(keys, val) for keys, val in baser.ures.getTopItemIter(keys=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == aKey
        assert len(items) == len(aVals)  # only aKey items

        # bVals — iterate at bKey, remove each
        items = [(keys, val) for keys, val in baser.ures.getTopItemIter(keys=bKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == bKey
        assert len(items) == len(bVals)  # only bKey items
        for ikeys, val in baser.ures.getTopItemIter(keys=bKey):
            assert baser.ures.rem(bKey, val) == True

        # cVals — iterate at cKey, remove each
        items = [(keys, val) for keys, val in baser.ures.getTopItemIter(keys=cKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == cKey
        assert len(items) == len(cVals)  # only cKey items
        for ikeys, val in baser.ures.getTopItemIter(keys=cKey):
            assert baser.ures.rem(cKey, val) == True

        # dVals — iterate at dKey, remove each
        items = [(keys, val) for keys, val in baser.ures.getTopItemIter(keys=dKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == dKey
        assert len(items) == len(dVals)
        for ikeys, val in baser.ures.getTopItemIter(keys=dKey):
            assert baser.ures.rem(dKey, val) == True

        # aVals should still be intact, others removed
        result_a = baser.ures.get(aKey)
        assert len(result_a) == len(aVals)
        for i, (d_expected, p_expected, c_expected) in enumerate(aVals):
            d, p, c = result_a[i]
            assert d.qb64 == d_expected.qb64
            assert p.qb64 == p_expected.qb64
            assert c.qb64b == c_expected.qb64b

        assert baser.ures.get(bKey) == []
        assert baser.ures.get(cKey) == []
        assert baser.ures.get(dKey) == []


        # Validator (transferable) Receipts
        # test .vrcs sub db methods dgkey
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        p1 = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # fake prefix
        n1 = core.Number(num=1)
        e1 = coring.Diger(ser=b"est1")    # digest of est event
        s1 = core.Siger(raw=b"\x00" * 64)  # 64‑byte fake signature

        cesrVal = (p1, n1, e1, s1)
        cesrVal = [cesrVal]

        assert baser.vrcs.get(key) == []
        assert baser.vrcs.cnt(key) == 0
        assert baser.vrcs.rem(key) == False

        assert baser.vrcs.put(key, cesrVal) is True

        stored = baser.vrcs.get(key)
        assert len(stored) == 1
        sp1, sn1, se1, ss1 = stored[0]

        assert sp1.qb64 == p1.qb64
        assert sn1.num == n1.num
        assert se1.qb64 == e1.qb64
        assert ss1.raw == s1.raw

        assert baser.vrcs.rem(key) == True

        # # dup vals are lexocographic
        # Build several distinct typed CESR quadruples
        pA = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        pB = coring.Prefixer(qb64="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        pC = coring.Prefixer(qb64="BCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
        pD = coring.Prefixer(qb64="BDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")

        nA = core.Number(num=1)
        nB = core.Number(num=2)
        nC = core.Number(num=3)
        nD = core.Number(num=4)

        eA = coring.Diger(ser=b"estA")
        eB = coring.Diger(ser=b"estB")
        eC = coring.Diger(ser=b"estC")
        eD = coring.Diger(ser=b"estD")

        sA = core.Siger(raw=b"\x00" * 64)
        sB = core.Siger(raw=b"\x01" * 64)
        sC = core.Siger(raw=b"\x02" * 64)
        sD = core.Siger(raw=b"\x03" * 64)

        quadA = (pA, nA, eA, sA)
        quadB = (pB, nB, eB, sB)
        quadC = (pC, nC, eC, sC)
        quadD = (pD, nD, eD, sD)

        vals = [quadD, quadB, quadC, quadA]   # intentionally out of order

        # Initially empty
        assert baser.vrcs.get(key) == []
        assert baser.vrcs.cnt(key) == 0

        # Insert multiple typed tuples
        assert baser.vrcs.put(key, vals) is True

        # Insertion order is preserved
        stored = baser.vrcs.get(key)
        assert len(stored) == len(vals)
        for (sp, sn, se, ss), (ep, en, ee, es) in zip(stored, vals):
            assert sp.qb64 == ep.qb64
            assert sn.num == en.num
            assert se.qb64 == ee.qb64
            assert ss.raw == es.raw

        assert baser.vrcs.cnt(key) == 4

        # Duplicate insertion should not add new entries
        assert baser.vrcs.put(key, [quadA]) == False
        assert baser.vrcs.put(key, [quadB]) == False   # quadB already present → no change
        assert baser.vrcs.put(key, [quadD]) == False   # quadD already present → no change
        assert baser.vrcs.put(key, [quadC]) == False   # quadC already present → no change

        # Iteration returns the same tuples in insertion order
        itered = list(baser.vrcs.getIter(key))
        for (sp, sn, se, ss), (ep, en, ee, es) in zip(itered, vals):
            assert sp.qb64 == ep.qb64
            assert sn.num == en.num
            assert se.qb64 == ee.qb64
            assert ss.raw == es.raw

        # Remove individual tuples
        for quad in vals:
            assert baser.vrcs.rem(key, quad) == True

        assert baser.vrcs.get(key) == []
        assert baser.vrcs.cnt(key) == 0

         # Unverified Validator (transferable) Receipt Escrows
        # test .vres insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        d1 = coring.Diger(ser=b"event1")  # digest of event
        p1 = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # fake prefix
        n1 = core.Number(num=1)
        e1 = coring.Diger(ser=b"est1")    # digest of est event
        s1 = core.Siger(raw=b"\x00" * 64)  # 64‑byte fake signature

        cesrVal = (d1, p1, n1, e1, s1)
        cesrVal = [cesrVal]

        assert baser.vres.get(key) == []
        assert baser.vres.getLast(keys=key) == None
        assert baser.vres.cnt(key) == 0
        assert baser.vres.rem(key) == False

        assert baser.vres.put(keys=key, vals=cesrVal) is True

        stored = baser.vres.get(key)
        assert len(stored) == 1
        sd1, sp1, sn1, se1, ss1 = stored[0]

        assert sd1.qb64 == d1.qb64
        assert sp1.qb64 == p1.qb64
        assert sn1.num == n1.num
        assert se1.qb64 == e1.qb64
        assert ss1.raw == s1.raw


        # assert baser.putVres(key, vals) == True
        # assert baser.vres.get(key) == vals  # preserved insertion order
        # assert baser.cntVres(key) == len(vals) == 4
        # assert baser.getVreLast(key) == vals[-1]
        # assert baser.putVres(key, vals=[b'a']) == False   # duplicate
        # assert baser.vres.get(key) == vals  #  no change
        # assert baser.addVre(key, b'a') == False   # duplicate
        # assert baser.addVre(key, b'b') == True
        # assert baser.vres.get(key) == [b"z", b"m", b"x", b"a", b"b"]
        # assert [val for val in baser.vres.getIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        # assert baser.delVres(key) == True
        # assert baser.vres.get(key) == []

        # # Setup Tests for getVresNext and getVresNextIter
        # aKey = snKey(pre=b'A', sn=1)
        # aVals = [b"z", b"m", b"x"]
        # bKey = snKey(pre=b'A', sn=2)
        # bVals = [b"o", b"r", b"z"]
        # cKey = snKey(pre=b'A', sn=4)
        # cVals = [b"h", b"n"]
        # dKey = snKey(pre=b'A', sn=7)
        # dVals = [b"k", b"b"]

        # assert baser.putVres(key=aKey, vals=aVals)
        # assert baser.putVres(key=bKey, vals=bVals)
        # assert baser.putVres(key=cKey, vals=cVals)
        # assert baser.putVres(key=dKey, vals=dVals)


        # # Test getVreItemsNextIter(key=b"")
        # #  get dups at first key in database
        # # aVals
        # items = [item for item in baser.getVreItemIter()]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == aKey
        # vals = [val for  key, val in items]
        # assert vals == aVals + bVals + cVals + dVals

        # items = [item for item in baser.getVreItemIter(key=aKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == aKey
        # vals = [val for  key, val in items]
        # assert vals == aVals

        # # bVals
        # items = [item for item in baser.getVreItemIter(key=bKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == bKey
        # vals = [val for key, val in items]
        # assert vals == bVals
        # for key, val in items:
        #     assert baser.delVre(ikey, val) == True

        # # cVals
        # items = [item for item in baser.getVreItemIter(key=cKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == cKey
        # vals = [val for key, val in items]
        # assert vals == cVals
        # for key, val in items:
        #     assert baser.delVre(ikey, val) == True

        # # dVals
        # items = [item for item in baser.getVreItemIter(key=dKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == dKey
        # vals = [val for key, val in items]
        # assert vals == dVals
        # for key, val in items:
        #     assert baser.delVre(ikey, val) == True

    asyncio.run(_go())