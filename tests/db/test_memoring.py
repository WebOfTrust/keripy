# -*- encoding: utf-8 -*-
"""
tests.db.test_memoring module

Tests for in-memory database backend (MemoryDber).
Validates behavioral equivalence with LMDB for all storage families.
"""
import pytest

from keri.db.memoring import MemoryDber, SubDb
from keri.db.dbing import onKey, snKey, dgKey, suffix, unsuffix


class TestMemoryDberLifecycle:
    """Test basic lifecycle: open, close, reopen."""

    def test_init_opens_by_default(self):
        db = MemoryDber(name="test", temp=True)
        assert db.opened is True
        assert db.name == "test"
        assert db.temp is True

    def test_close_and_reopen(self):
        db = MemoryDber(name="test", temp=True)
        assert db.opened is True
        db.close()
        assert db.opened is False
        db.reopen()
        assert db.opened is True

    def test_close_clear_removes_data(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        db.setVal(sdb, b"key", b"val")
        db.close(clear=True)
        db.reopen()
        sdb = db.open_sub(subkey="test.", dupsort=False)
        assert db.getVal(sdb, b"key") is None

    def test_open_sub_returns_descriptor(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="evts.", dupsort=False)
        assert isinstance(sdb, SubDb)
        assert sdb.dupsort is False

    def test_open_sub_dupsort(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="sigs.", dupsort=True)
        assert sdb.dupsort is True

    def test_open_sub_idempotent(self):
        db = MemoryDber(name="test", temp=True)
        sdb1 = db.open_sub(subkey="test.", dupsort=False)
        sdb2 = db.open_sub(subkey="test.", dupsort=False)
        assert sdb1 is sdb2


class TestValFamily:
    """Test single value per key (dupsort==False)."""

    def setup_method(self):
        self.db = MemoryDber(name="test", temp=True)
        self.sdb = self.db.open_sub(subkey="vals.", dupsort=False)

    def test_put_and_get(self):
        assert self.db.putVal(self.sdb, b"key1", b"val1") is True
        assert bytes(self.db.getVal(self.sdb, b"key1")) == b"val1"

    def test_put_no_overwrite(self):
        self.db.putVal(self.sdb, b"key1", b"val1")
        assert self.db.putVal(self.sdb, b"key1", b"val2") is False
        assert bytes(self.db.getVal(self.sdb, b"key1")) == b"val1"

    def test_set_overwrites(self):
        self.db.setVal(self.sdb, b"key1", b"val1")
        self.db.setVal(self.sdb, b"key1", b"val2")
        assert bytes(self.db.getVal(self.sdb, b"key1")) == b"val2"

    def test_get_missing_returns_none(self):
        assert self.db.getVal(self.sdb, b"missing") is None

    def test_del_existing(self):
        self.db.setVal(self.sdb, b"key1", b"val1")
        assert self.db.delVal(self.sdb, b"key1") is True
        assert self.db.getVal(self.sdb, b"key1") is None

    def test_del_missing(self):
        assert self.db.delVal(self.sdb, b"missing") is False


class TestOnValFamily:
    """Test ordinal-keyed values."""

    def setup_method(self):
        self.db = MemoryDber(name="test", temp=True)
        self.sdb = self.db.open_sub(subkey="ons.", dupsort=False)

    def test_put_and_get_on(self):
        key = b"pre1"
        assert self.db.putOnVal(self.sdb, key, on=0, val=b"evt0") is True
        assert bytes(self.db.getOnVal(self.sdb, key, on=0)) == b"evt0"

    def test_append_on(self):
        key = b"pre1"
        on0 = self.db.appendOnVal(self.sdb, key, b"evt0")
        assert on0 == 0
        on1 = self.db.appendOnVal(self.sdb, key, b"evt1")
        assert on1 == 1
        on2 = self.db.appendOnVal(self.sdb, key, b"evt2")
        assert on2 == 2

        assert bytes(self.db.getOnVal(self.sdb, key, on=0)) == b"evt0"
        assert bytes(self.db.getOnVal(self.sdb, key, on=1)) == b"evt1"
        assert bytes(self.db.getOnVal(self.sdb, key, on=2)) == b"evt2"

    def test_cnt_on_all(self):
        key = b"pre1"
        self.db.appendOnVal(self.sdb, key, b"evt0")
        self.db.appendOnVal(self.sdb, key, b"evt1")
        self.db.appendOnVal(self.sdb, key, b"evt2")
        assert self.db.cntOnAll(self.sdb, key) == 3
        assert self.db.cntOnAll(self.sdb, key, on=1) == 2

    def test_get_on_item_iter_all(self):
        key = b"pre1"
        self.db.appendOnVal(self.sdb, key, b"evt0")
        self.db.appendOnVal(self.sdb, key, b"evt1")

        items = list(self.db.getOnItemIterAll(self.sdb, key=key))
        assert len(items) == 2
        assert items[0] == (key, 0, b"evt0")
        assert items[1] == (key, 1, b"evt1")

    def test_del_on_val(self):
        key = b"pre1"
        self.db.appendOnVal(self.sdb, key, b"evt0")
        assert self.db.delOnVal(self.sdb, key, on=0) is True
        assert self.db.getOnVal(self.sdb, key, on=0) is None


class TestIoSetFamily:
    """Test insertion-ordered sets (dupsort==False with hidden suffix)."""

    def setup_method(self):
        self.db = MemoryDber(name="test", temp=True)
        self.sdb = self.db.open_sub(subkey="ioset.", dupsort=False)

    def test_add_and_get(self):
        key = b"key1"
        assert self.db.addIoSetVal(self.sdb, key, b"val1") is True
        assert self.db.addIoSetVal(self.sdb, key, b"val2") is True
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 2
        assert bytes(vals[0]) == b"val1"
        assert bytes(vals[1]) == b"val2"

    def test_add_idempotent(self):
        key = b"key1"
        self.db.addIoSetVal(self.sdb, key, b"val1")
        assert self.db.addIoSetVal(self.sdb, key, b"val1") is False
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 1

    def test_put_io_set_vals(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b", b"c"])
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 3
        assert bytes(vals[0]) == b"a"
        assert bytes(vals[1]) == b"b"
        assert bytes(vals[2]) == b"c"

    def test_put_io_set_vals_no_dups(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b"])
        self.db.putIoSetVals(self.sdb, key, [b"b", b"c"])
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 3

    def test_pin_io_set_vals(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b"])
        self.db.pinIoSetVals(self.sdb, key, [b"x", b"y"])
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 2
        assert bytes(vals[0]) == b"x"
        assert bytes(vals[1]) == b"y"

    def test_get_io_set_iter(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b", b"c"])
        vals = list(self.db.getIoSetIter(self.sdb, key))
        assert len(vals) == 3

    def test_get_io_set_last(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b", b"c"])
        last = self.db.getIoSetLast(self.sdb, key)
        assert bytes(last) == b"c"

    def test_del_io_set(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b"])
        assert self.db.delIoSet(self.sdb, key) is True
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 0

    def test_del_io_set_val(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b", b"c"])
        assert self.db.delIoSetVal(self.sdb, key, b"b") is True
        vals = self.db.getIoSet(self.sdb, key)
        assert len(vals) == 2

    def test_cnt_io_set(self):
        key = b"key1"
        self.db.putIoSetVals(self.sdb, key, [b"a", b"b", b"c"])
        assert self.db.cntIoSet(self.sdb, key) == 3

    def test_empty_key_returns_empty(self):
        assert self.db.getIoSet(self.sdb, b"") == []
        assert self.db.addIoSetVal(self.sdb, b"", b"val") is False


class TestDupFamily:
    """Test multiple values per key (dupsort==True)."""

    def setup_method(self):
        self.db = MemoryDber(name="test", temp=True)
        self.sdb = self.db.open_sub(subkey="dups.", dupsort=True)

    def test_put_vals(self):
        self.db.putVals(self.sdb, b"key1", [b"a", b"b", b"c"])
        vals = self.db.getVals(self.sdb, b"key1")
        assert len(vals) == 3
        # lexicographic order
        assert vals == [b"a", b"b", b"c"]

    def test_add_val_idempotent(self):
        self.db.addVal(self.sdb, b"key1", b"val1")
        assert self.db.addVal(self.sdb, b"key1", b"val1") is False
        assert self.db.cntVals(self.sdb, b"key1") == 1

    def test_get_val_last(self):
        self.db.putVals(self.sdb, b"key1", [b"a", b"c", b"b"])
        last = self.db.getValLast(self.sdb, b"key1")
        assert bytes(last) == b"c"  # lexicographic last

    def test_del_vals_all(self):
        self.db.putVals(self.sdb, b"key1", [b"a", b"b"])
        assert self.db.delVals(self.sdb, b"key1") is True
        assert self.db.getVals(self.sdb, b"key1") == []

    def test_del_vals_specific(self):
        self.db.putVals(self.sdb, b"key1", [b"a", b"b", b"c"])
        assert self.db.delVals(self.sdb, b"key1", b"b") is True
        vals = self.db.getVals(self.sdb, b"key1")
        assert len(vals) == 2

    def test_cnt_vals(self):
        self.db.putVals(self.sdb, b"key1", [b"a", b"b", b"c"])
        assert self.db.cntVals(self.sdb, b"key1") == 3


class TestIoDupFamily:
    """Test insertion-ordered duplicates (dupsort==True with proem)."""

    def setup_method(self):
        self.db = MemoryDber(name="test", temp=True)
        self.sdb = self.db.open_sub(subkey="iodups.", dupsort=True)

    def test_put_and_get_io_dup_vals(self):
        self.db.putIoDupVals(self.sdb, b"key1", [b"first", b"second", b"third"])
        vals = self.db.getIoDupVals(self.sdb, b"key1")
        assert len(vals) == 3
        assert bytes(vals[0]) == b"first"
        assert bytes(vals[1]) == b"second"
        assert bytes(vals[2]) == b"third"

    def test_add_io_dup_val_idempotent(self):
        self.db.addIoDupVal(self.sdb, b"key1", b"val1")
        assert self.db.addIoDupVal(self.sdb, b"key1", b"val1") is False
        assert self.db.cntIoDups(self.sdb, b"key1") == 1

    def test_get_io_dup_val_last(self):
        self.db.putIoDupVals(self.sdb, b"key1", [b"first", b"second", b"third"])
        last = self.db.getIoDupValLast(self.sdb, b"key1")
        assert bytes(last) == b"third"

    def test_del_io_dup_vals(self):
        self.db.putIoDupVals(self.sdb, b"key1", [b"a", b"b"])
        assert self.db.delIoDupVals(self.sdb, b"key1") is True
        assert self.db.getIoDupVals(self.sdb, b"key1") == []

    def test_del_io_dup_val(self):
        self.db.putIoDupVals(self.sdb, b"key1", [b"a", b"b", b"c"])
        assert self.db.delIoDupVal(self.sdb, b"key1", b"b") is True
        vals = self.db.getIoDupVals(self.sdb, b"key1")
        assert len(vals) == 2
        assert b"b" not in [bytes(v) for v in vals]

    def test_get_io_dup_vals_iter(self):
        self.db.putIoDupVals(self.sdb, b"key1", [b"x", b"y", b"z"])
        vals = list(self.db.getIoDupValsIter(self.sdb, b"key1"))
        assert len(vals) == 3
        assert bytes(vals[0]) == b"x"


class TestUniversalMethods:
    """Test delTop, cntAll, getTopItemIter."""

    def test_del_top(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        db.setVal(sdb, b"abc.001", b"v1")
        db.setVal(sdb, b"abc.002", b"v2")
        db.setVal(sdb, b"def.001", b"v3")
        assert db.delTop(sdb, b"abc") is True
        assert db.getVal(sdb, b"abc.001") is None
        assert db.getVal(sdb, b"abc.002") is None
        assert bytes(db.getVal(sdb, b"def.001")) == b"v3"

    def test_cnt_all(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        db.setVal(sdb, b"k1", b"v1")
        db.setVal(sdb, b"k2", b"v2")
        assert db.cntAll(sdb) == 2

    def test_get_top_item_iter(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        db.setVal(sdb, b"abc.001", b"v1")
        db.setVal(sdb, b"abc.002", b"v2")
        db.setVal(sdb, b"def.001", b"v3")
        items = list(db.getTopItemIter(sdb, b"abc"))
        assert len(items) == 2

    def test_get_top_item_iter_all(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        db.setVal(sdb, b"abc.001", b"v1")
        db.setVal(sdb, b"abc.002", b"v2")
        db.setVal(sdb, b"def.001", b"v3")
        items = list(db.getTopItemIter(sdb, b""))
        assert len(items) == 3


class TestTopIoSetItemIter:
    """Test getTopIoSetItemIter."""

    def test_top_io_set_item_iter(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        key1 = b"pre1"
        key2 = b"pre2"
        db.addIoSetVal(sdb, key1, b"a")
        db.addIoSetVal(sdb, key1, b"b")
        db.addIoSetVal(sdb, key2, b"c")

        items = list(db.getTopIoSetItemIter(sdb, top=b""))
        assert len(items) == 3
        # All items should have the effective key (suffix stripped)
        keys = [item[0] for item in items]
        assert key1 in keys
        assert key2 in keys


class TestOnIoSetComposite:
    """Test OnIoSet composite methods."""

    def test_put_and_get_on_io_set(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        key = b"pre1"
        db.putOnIoSetVals(sdb, key, on=0, vals=[b"a", b"b"])
        vals = db.getOnIoSet(sdb, key, on=0)
        assert len(vals) == 2

    def test_get_on_io_set_last(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        key = b"pre1"
        db.putOnIoSetVals(sdb, key, on=0, vals=[b"a", b"b", b"c"])
        last = db.getOnIoSetLast(sdb, key, on=0)
        assert bytes(last) == b"c"

    def test_del_on_io_set(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=False)
        key = b"pre1"
        db.putOnIoSetVals(sdb, key, on=0, vals=[b"a", b"b"])
        assert db.delOnIoSet(sdb, key, on=0) is True
        assert db.getOnIoSet(sdb, key, on=0) == []


class TestOnIoDupComposite:
    """Test OnIoDup composite methods."""

    def test_put_and_get_on_io_dup(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=True)
        key = b"pre1"
        db.putOnIoDupVals(sdb, key, on=0, vals=[b"x", b"y"])
        vals = db.getOnIoDupVals(sdb, key, on=0)
        assert len(vals) == 2
        assert bytes(vals[0]) == b"x"
        assert bytes(vals[1]) == b"y"

    def test_get_on_io_dup_last(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=True)
        key = b"pre1"
        db.putOnIoDupVals(sdb, key, on=0, vals=[b"x", b"y", b"z"])
        last = db.getOnIoDupLast(sdb, key, on=0)
        assert bytes(last) == b"z"

    def test_del_on_io_dups(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=True)
        key = b"pre1"
        db.putOnIoDupVals(sdb, key, on=0, vals=[b"a", b"b"])
        assert db.delOnIoDups(sdb, key, on=0) is True
        assert db.getOnIoDupVals(sdb, key, on=0) == []

    def test_cnt_on_io_dups(self):
        db = MemoryDber(name="test", temp=True)
        sdb = db.open_sub(subkey="test.", dupsort=True)
        key = b"pre1"
        db.putOnIoDupVals(sdb, key, on=0, vals=[b"a", b"b", b"c"])
        assert db.cntOnIoDups(sdb, key, on=0) == 3
