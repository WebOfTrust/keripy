# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import pytest

import os
import json
import datetime

import lmdb
from  ordered_set import OrderedSet as oset

from hio.base import doing

from keri.db import dbing
from keri.db.dbing import clearDatabaserDir, openLMDB
from keri.db.dbing import (dgKey, onKey, fnKey, snKey, dtKey, splitKey,
                           splitKeyON, splitKeyFN, splitKeySN, splitKeyDT)
from keri.db.dbing import LMDBer
from keri.db import basing
from keri.db.basing import openDB, Baser
from keri.core.coring import Signer, Nexter, Prefixer, Serder
from keri.core.coring import MtrDex, MtrDex, MtrDex
from keri.core.coring import Serials, Vstrings, versify

from keri.core.eventing import incept, rotate, interact, Kever, Kevery
from keri.help import helping

def test_key_funcs():
    """
    Test key utility functions
    """
    # Bytes
    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3
    dts = b'2021-02-13T19:16:50.750302+00:00'

    assert snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    assert splitKey(snKey(pre, sn)) == (pre, b'%032x' % sn)
    assert splitKeySN(snKey(pre, sn)) == (pre, sn)

    assert dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    assert splitKey(dgKey(pre, dig)) == (pre, dig)

    assert dtKey(pre, dts) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'|2021-02-13T19:16:50.750302+00:00')

    assert splitKey(dtKey(pre, dts), sep=b'|') == (pre, dts)
    assert splitKeyDT(dtKey(pre, dts)) == (pre, helping.fromIso8601(dts.decode("utf-8")))

    #  Str
    pre = 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    dts = '2021-02-13T19:16:50.750302+00:00'

    assert snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    assert splitKey(snKey(pre, sn).decode("utf-8")) == (pre, '%032x' % sn)
    assert splitKeySN(snKey(pre, sn).decode("utf-8")) == (pre, sn)

    assert dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    assert splitKey(dgKey(pre, dig).decode("utf-8")) == (pre, dig)

    assert dtKey(pre, dts) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                b'|2021-02-13T19:16:50.750302+00:00')

    assert splitKey(dtKey(pre, dts).decode("utf-8"), sep=b'|') == (pre, dts)
    assert splitKeyDT(dtKey(pre, dts).decode("utf-8")) == (pre, helping.fromIso8601(dts))


    with pytest.raises(TypeError):
        snKey(pre, sn='3')

    with pytest.raises(ValueError):
        splitKey(pre)

    with pytest.raises(ValueError):
        splitKey(dgKey(pre, dgKey(pre, dig)))

    # memoryview
    # Bytes
    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3
    dts = b'2021-02-13T19:16:50.750302+00:00'

    key = memoryview(snKey(pre, sn))
    assert splitKey(key) == (pre, b'%032x' % sn)
    assert splitKeySN(key) == (pre, sn)

    key = memoryview(dgKey(pre, dig))
    assert splitKey(key) == (pre, dig)

    key = memoryview(dtKey(pre, dts))
    assert splitKey(key, sep=b'|') == (pre, dts)
    assert splitKeyDT(key) == (pre, helping.fromIso8601(dts.decode("utf-8")))

    """Done Test"""


def test_suffix():
    """
    Test suffix unsuffix stuff
    """
    assert dbing.SuffixSize == 32
    assert dbing.MaxSuffix ==  340282366920938463463374607431768211455
    assert dbing.MaxSuffix >= dbing.MaxON

    key = "ABCDEFG.FFFFFF"
    keyb = b"ABCDEFG.FFFFFF"

    ion = 0
    iokey = dbing.suffix(key, ion)
    assert iokey == b'ABCDEFG.FFFFFF.00000000000000000000000000000000'
    k, i = dbing.unsuffix(iokey)
    assert k == keyb
    assert i == ion

    ion = 64
    iokey = dbing.suffix(keyb, ion)
    assert iokey == b'ABCDEFG.FFFFFF.00000000000000000000000000000040'
    k, i = dbing.unsuffix(iokey)
    assert k == keyb
    assert i == ion

    iokey = dbing.suffix(key, dbing.MaxSuffix)
    assert iokey ==  b'ABCDEFG.FFFFFF.ffffffffffffffffffffffffffffffff'
    k, i = dbing.unsuffix(iokey)
    assert k == keyb
    assert i == dbing.MaxSuffix


    """Done Test"""

def test_opendatabaser():
    """
    test contextmanager decorator for test databases
    """
    with openLMDB() as databaser:
        assert isinstance(databaser, LMDBer)
        assert databaser.name == "test"
        assert isinstance(databaser.env, lmdb.Environment)
        assert databaser.path.startswith("/tmp/keri_lmdb_")
        assert databaser.path.endswith("_test/keri/db/test")
        assert databaser.env.path() == databaser.path
        assert os.path.exists(databaser.path)
        assert databaser.opened

    assert not os.path.exists(databaser.path)
    assert not databaser.opened

    with openLMDB(name="blue") as databaser:
        assert isinstance(databaser, LMDBer)
        assert databaser.name == "blue"
        assert isinstance(databaser.env, lmdb.Environment)
        assert databaser.path.startswith("/tmp/keri_lmdb_")
        assert databaser.path.endswith("_test/keri/db/blue")
        assert databaser.env.path() == databaser.path
        assert os.path.exists(databaser.path)
        assert databaser.opened

    assert not os.path.exists(databaser.path)
    assert not databaser.opened

    with openLMDB(name="red") as redbaser, openLMDB(name="tan") as tanbaser:
        assert isinstance(redbaser, LMDBer)
        assert redbaser.name == "red"
        assert redbaser.env.path() == redbaser.path
        assert os.path.exists(redbaser.path)
        assert redbaser.opened

        assert isinstance(tanbaser, LMDBer)
        assert tanbaser.name == "tan"
        assert tanbaser.env.path() == tanbaser.path
        assert os.path.exists(tanbaser.path)
        assert tanbaser.opened

    assert not os.path.exists(redbaser.path)
    assert not redbaser.opened
    assert not os.path.exists(tanbaser.path)
    assert not tanbaser.opened

    """ End Test """

def test_lmdber():
    """
    Test LMDBer creation
    """
    databaser = LMDBer()
    assert isinstance(databaser, LMDBer)
    assert databaser.name == "main"
    assert databaser.temp == False
    assert isinstance(databaser.env, lmdb.Environment)
    assert databaser.path.endswith("keri/db/main")
    assert databaser.env.path() == databaser.path
    assert os.path.exists(databaser.path)
    assert databaser.opened

    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3

    assert snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')
    assert dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    databaser.close(clear=True)
    assert not os.path.exists(databaser.path)
    assert not databaser.opened

    # test not opened on init
    databaser = LMDBer(reopen=False)
    assert isinstance(databaser, LMDBer)
    assert databaser.name == "main"
    assert databaser.temp == False
    assert databaser.opened == False
    assert databaser.path == None
    assert databaser.env == None

    databaser.reopen()
    assert databaser.opened
    assert isinstance(databaser.env, lmdb.Environment)
    assert databaser.path.endswith("keri/db/main")
    assert databaser.env.path() == databaser.path
    assert os.path.exists(databaser.path)

    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3

    assert snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')
    assert dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    databaser.close(clear=True)
    assert not os.path.exists(databaser.path)
    assert not databaser.opened

    with openLMDB() as dber:
        assert dber.temp == True
        #test Val methods
        key = b'A'
        val = b'whatever'
        db = dber.env.open_db(key=b'beep.')

        assert dber.getVal(db, key) == None
        assert dber.delVal(db, key) == False
        assert dber.putVal(db, key, val) == True
        assert dber.putVal(db, key, val) == False
        assert dber.setVal(db, key, val) == True
        assert dber.getVal(db, key) == val
        assert dber.delVal(db, key) == True
        assert dber.getVal(db, key) == None

        # Test getAllItemIter(self, db, key=b'', split=True, sep=b'.')
        key = b"a.1"
        val = b"wow"
        assert dber.putVal(db, key, val) == True
        key = b"a.2"
        val = b"wee"
        assert dber.putVal(db, key, val) == True
        key = b"b.1"
        val = b"woo"
        assert dber.putVal(db, key, val) == True
        assert [(bytes(pre), bytes(num), bytes(val)) for pre, num, val
                     in dber.getAllItemIter(db=db)] == [(b'a', b'1', b'wow'),
                                                        (b'a', b'2', b'wee'),
                                                        (b'b', b'1', b'woo')]

        assert dber.delTopVal(db, key=b"a.")
        items = [ (key, bytes(val)) for key, val in dber.getTopItemIter(db=db )]
        assert items == [(b'b.1', b'woo')]

        # test OrdVal OrdItem ordinal numbered event sub db
        db = dber.env.open_db(key=b'seen.')

        preA = b'B8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'
        preB = b'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'
        preC = b'EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'

        keyA0 = onKey(preA, 0)

        keyB0 = onKey(preB, 0)
        keyB1 = onKey(preB, 1)
        keyB2 = onKey(preB, 2)
        keyB3 = onKey(preB, 3)
        keyB4 = onKey(preB, 4)

        keyC0 = onKey(preC, 0)

        digA = b'ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'

        digU = b'ER73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'
        digV = b'EA4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY'
        digW = b'EyAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w'
        digX = b'EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o'
        digY = b'Enrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk'

        digC = b'E-5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w'

        assert dber.getVal(db, keyA0) == None
        assert dber.delVal(db, keyA0) == False
        assert dber.putVal(db, keyA0, val=digA) == True
        assert dber.getVal(db, keyA0) == digA
        assert dber.putVal(db, keyA0, val=digA) == False
        assert dber.setVal(db, keyA0, val=digA) == True
        assert dber.getVal(db, keyA0) == digA
        assert dber.delVal(db, keyA0) == True
        assert dber.getVal(db, keyA0) == None

        #  test appendOrdValPre
        # empty database
        assert dber.getVal(db, keyB0) == None
        on = dber.appendOrdValPre(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU
        assert dber.delVal(db, keyB0) == True
        assert dber.getVal(db, keyB0) == None

        # earlier pre in database only
        assert dber.putVal(db, keyA0, val=digA) == True
        on = dber.appendOrdValPre(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU
        assert dber.delVal(db, keyB0) == True
        assert dber.getVal(db, keyB0) == None

        # earlier and later pre in db but not same pre
        assert dber.getVal(db, keyA0) == digA
        assert dber.putVal(db, keyC0, val=digC) == True
        on = dber.appendOrdValPre(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU
        assert dber.delVal(db, keyB0) == True
        assert dber.getVal(db, keyB0) == None

        # later pre only
        assert dber.delVal(db, keyA0) == True
        assert dber.getVal(db, keyA0) == None
        assert dber.getVal(db, keyC0) == digC
        on = dber.appendOrdValPre(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU

        # earlier pre and later pre and earlier entry for same pre
        assert dber.putVal(db, keyA0, val=digA) == True
        on = dber.appendOrdValPre(db, preB, digV)
        assert on == 1
        assert dber.getVal(db, keyB1) == digV

        # earlier entry for same pre but only same pre
        assert dber.delVal(db, keyA0) == True
        assert dber.getVal(db, keyA0) == None
        assert dber.delVal(db, keyC0) == True
        assert dber.getVal(db, keyC0) == None
        # another value for preB
        on = dber.appendOrdValPre(db, preB, digW)
        assert on == 2
        assert dber.getVal(db, keyB2) == digW
        # yet another value for preB
        on = dber.appendOrdValPre(db, preB, digX)
        assert on == 3
        assert dber.getVal(db, keyB3) == digX
        # yet another value for preB
        on = dber.appendOrdValPre(db, preB, digY )
        assert on == 4
        assert dber.getVal(db, keyB4) == digY

        assert dber.cntValsAllPre(db, preB) == 5

        # replay preB events in database
        items = [item for item in dber.getAllOrdItemPreIter(db, preB)]
        assert items == [(0, digU), (1, digV), (2, digW), (3, digX), (4, digY)]

        # resume replay preB events at on = 3
        items = [item for item in dber.getAllOrdItemPreIter(db, preB, on=3)]
        assert items == [(3, digX), (4, digY)]

        # resume replay preB events at on = 5
        items = [item for item in dber.getAllOrdItemPreIter(db, preB, on=5)]
        assert items == []

        # replay all events in database with pre events before and after
        assert dber.putVal(db, keyA0, val=digA) == True
        assert dber.putVal(db, keyC0, val=digC) == True

        items = [item  for item in dber.getAllOrdItemAllPreIter(db)]
        assert items == [(preA, 0, digA), (preB, 0, digU), (preB, 1, digV),
                         (preB, 2, digW), (preB, 3, digX), (preB, 4, digY),
                         (preC, 0, digC)]


        # resume replay all starting at preB on=2
        items = [item for item in dber.getAllOrdItemAllPreIter(db, key=keyB2)]
        assert items == [(preB, 2, digW), (preB, 3, digX), (preB, 4, digY),
                             (preC, 0, digC)]

        # resume replay all starting at preC on=1
        items = [item for item in dber.getAllOrdItemAllPreIter(db, key=onKey(preC, 1))]
        assert items == []


        # test Vals dup methods.  dup vals are lexocographic
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        db = dber.env.open_db(key=b'boop.', dupsort=True)

        assert dber.getVals(db, key) == []
        assert dber.delVals(db, key) == False
        assert dber.cntVals(db, key) == 0
        assert dber.putVals(db, key, vals) == True
        assert dber.getVals(db, key) == [b'a', b'm', b'x', b'z']  #  lexocographic order
        assert dber.cntVals(db, key) == len(vals) == 4
        assert dber.putVals(db, key, vals=[b'a']) == True   # duplicate
        assert dber.getVals(db, key) == [b'a', b'm', b'x', b'z']  #  no change
        assert dber.addVal(db, key, val=b'a') == False  # duplicate
        assert dber.addVal(db, key, val=b'b') == True
        assert dber.getVals(db, key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in dber.getValsIter(db, key)] == [b'a', b'b', b'm', b'x', b'z']
        assert dber.delVals(db, key) == True
        assert dber.getVals(db, key) == []
        assert dber.putVals(db, key, vals) == True
        for val in vals:
            assert dber.delVals(db, key, val)
        assert dber.getVals(db, key) == []
        assert dber.putVals(db, key, vals) == True
        for val in dber.getValsIter(db, key):
            assert dber.delVals(db, key, val)  # allows delete fo dup while iter over dups
        assert dber.getVals(db, key) == []


        # test IoVals insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        db = dber.env.open_db(key=b'peep.', dupsort=True)

        assert dber.getIoVals(db, key) == []
        assert dber.getIoValLast(db, key) == None
        assert dber.cntIoVals(db, key) == 0
        assert dber.delIoVals(db, key) == False
        assert dber.putIoVals(db, key, vals) == True
        assert dber.getIoVals(db, key) == vals  # preserved insertion order
        assert dber.cntIoVals(db, key) == len(vals) == 4
        assert dber.getIoValLast(db, key) == vals[-1]
        assert dber.putIoVals(db, key, vals=[b'a']) == False   # duplicate
        assert dber.getIoVals(db, key) == vals  #  no change
        assert dber.addIoVal(db, key, val=b'b') == True
        assert dber.addIoVal(db, key, val=b'a') == False
        assert dber.getIoVals(db, key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in dber.getIoValsIter(db, key)] == [b"z", b"m", b"x", b"a", b'b']
        assert dber.delIoVals(db, key) == True
        assert dber.getIoVals(db, key) == []
        assert dber.putIoVals(db, key, vals) == True
        for val in vals:
            assert dber.delIoVal(db, key, val)
        assert dber.getIoVals(db, key) == []
        assert dber.putIoVals(db, key, vals) == True
        for val in sorted(vals):
            assert dber.delIoVal(db, key, val)
        assert dber.getIoVals(db, key) == []
        #delete and add in odd order
        assert dber.putIoVals(db, key, vals) == True
        assert dber.delIoVal(db, key, vals[2])
        assert dber.addIoVal(db, key, b'w')
        assert dber.delIoVal(db, key, vals[0])
        assert dber.addIoVal(db, key, b'e')
        assert dber.getIoVals(db, key) == [b'm', b'a', b'w', b'e']

        # Test getIoValsAllPreIter(self, db, pre)
        vals0 = [b"gamma", b"beta"]
        sn = 0
        key = snKey(pre, sn)
        assert dber.addIoVal(db, key, vals0[0]) == True
        assert dber.addIoVal(db, key, vals0[1]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(pre, sn)
        assert dber.putIoVals(db, key, vals1) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        key = snKey(pre, sn)
        assert dber.putIoVals(db, key, vals2) == True

        vals = [bytes(val) for val in dber.getIoValsAllPreIter(db, pre)]
        allvals = vals0 + vals1 + vals2
        assert vals == allvals

        # Test getIoValsLastAllPreIter(self, db, pre)
        pre = b'B4ejWzwQPYGGwTmuupUhPx5_yZ-Wk1xEHHzq7K0gzhcc'
        vals0 = [b"gamma", b"beta"]
        sn = 0
        key = snKey(pre, sn)
        assert dber.addIoVal(db, key, vals0[0]) == True
        assert dber.addIoVal(db, key, vals0[1]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(pre, sn)
        assert dber.putIoVals(db, key, vals1) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        key = snKey(pre, sn)
        assert dber.putIoVals(db, key, vals2) == True

        vals = [bytes(val) for val in dber.getIoValLastAllPreIter(db, pre)]
        lastvals = [vals0[-1], vals1[-1], vals2[-1]]
        assert vals == lastvals

        # Test getIoValsAnyPreIter(self, db, pre)
        pre = b'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcc'
        vals0 = [b"gamma", b"beta"]
        sn = 1  # not start at zero
        key = snKey(pre, sn)
        assert dber.addIoVal(db, key, vals0[0]) == True
        assert dber.addIoVal(db, key, vals0[1]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(pre, sn)
        assert dber.putIoVals(db, key, vals1) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 2  # gap
        key = snKey(pre, sn)
        assert dber.putIoVals(db, key, vals2) == True

        vals = [bytes(val) for val in dber.getIoValsAnyPreIter(db, pre)]
        allvals = vals0 + vals1 + vals2
        assert vals == allvals

        # Setup Tests for getIoItemsNext and getIoItemsNextIter
        edb = dber.env.open_db(key=b'escrow.', dupsort=True)
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert dber.putIoVals(edb, key=aKey, vals=aVals)
        assert dber.putIoVals(edb, key=bKey, vals=bVals)
        assert dber.putIoVals(edb, key=cKey, vals=cVals)
        assert dber.putIoVals(edb, key=dKey, vals=dVals)

        # Test getIoItemsNext(self, db, key=b"")
        # aVals
        items = dber.getIoItemsNext(edb)  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = dber.getIoItemsNext(edb, key=aKey, skip=False)  # get aKey in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = dber.getIoItemsNext(edb, key=aKey)  # get bKey in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = dber.getIoItemsNext(edb, key=b'', skip=False)  # get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = dber.getIoItemsNext(edb, key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = dber.getIoItemsNext(edb, key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = dber.getIoItemsNext(edb, key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = dber.getIoItemsNext(edb, key=ikey)
        assert items == []  # empty
        assert not items

        # Test getIoItemsNextIter(self, db, key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in dber.getIoItemsNextIter(edb)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in dber.getIoItemsNextIter(edb, key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in dber.getIoItemsNextIter(edb, key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in dber.getIoItemsNextIter(edb, key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert dber.delIoVal(edb, ikey, val) == True

        # bVals
        items = [item for item in dber.getIoItemsNextIter(edb, key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert dber.delIoVal(edb, ikey, val) == True

        # cVals
        items = [item for item in dber.getIoItemsNextIter(edb, key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert dber.delIoVal(edb, ikey, val) == True

        # dVals
        items = [item for item in dber.getIoItemsNext(edb, key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert dber.delIoVal(edb, ikey, val) == True

        # none
        items = [item for item in dber.getIoItemsNext(edb, key=ikey)]
        assert items == []  # empty
        assert not items

        # test IoSetVals insertion order set of vals methods.
        key0 = b'ABC.ZYX'
        key1 = b'DEF.WVU'
        key2 = b'GHI.TSR'

        vals0 = [b"z", b"m", b"x", b"a"]
        vals1 = [b"w", b"n", b"y", b"d"]
        vals2 = [b"p", b"o", b"h", b"f"]

        db = dber.env.open_db(key=b'ioset.', dupsort=False)

        """
        putIoSetVals
        addIoSetVal
        setIoSetVals
        appendIoSetVal

        getIoSetVals
        getIoSetValsIter
        getIoSetValLast

        cntIoSetVals

        delIoSetVals
        delIoSetVal

        getIoSetItems
        getIoSetItemsIter

        delIoSetIokey
        """

        assert dber.getIoSetVals(db, key0) == oset()
        assert dber.getIoSetValLast(db, key0) == None
        assert dber.cntIoSetVals(db, key0) == 0
        assert dber.delIoSetVals(db, key0) == False

        assert dber.putIoSetVals(db, key0, vals0) == True
        assert dber.getIoSetVals(db, key0) == vals0  # preserved insertion order
        assert dber.cntIoSetVals(db, key0) == len(vals0) == 4
        assert dber.getIoSetValLast(db, key0) == vals0[-1] == vals0[-1]

        assert dber.putIoSetVals(db, key0, vals=[b'a']) == False   # duplicate
        assert dber.getIoSetVals(db, key0) == vals0  #  no change
        assert dber.putIoSetVals(db, key0, vals=[b'f']) == True
        assert dber.getIoSetVals(db, key0) == [b"z", b"m", b"x", b"a", b"f"]
        assert dber.addIoSetVal(db, key0, val=b'b') == True
        assert dber.addIoSetVal(db, key0, val=b'a') == False
        assert dber.getIoSetVals(db, key0) == [b"z", b"m", b"x", b"a", b"f", b"b"]

        assert [val for val in dber.getIoSetValsIter(db, key0)] == [b"z", b"m", b"x", b"a", b"f", b"b"]
        assert dber.delIoSetVals(db, key0) == True
        assert dber.getIoSetVals(db, key0) == []

        assert dber.putIoSetVals(db, key0, vals0) == True
        for val in vals0:
            assert dber.delIoSetVal(db, key0, val)
        assert dber.getIoSetVals(db, key0) == oset()
        assert dber.putIoSetVals(db, key0, vals0) == True
        for val in sorted(vals0):  # test deletion out of order
            assert dber.delIoSetVal(db, key0, val)
        assert dber.getIoSetVals(db, key0) == []

        #delete and add in odd order
        assert dber.putIoSetVals(db, key0, vals0) == True
        assert dber.delIoSetVal(db, key0, vals0[2])
        assert dber.addIoSetVal(db, key0, b'w')
        assert dber.delIoSetVal(db, key0, vals0[0])
        assert dber.addIoSetVal(db, key0, b'e')
        assert dber.getIoSetVals(db, key0) == [b'm', b'a', b'w', b'e']

        assert dber.delIoSetVals(db, key0) == True
        assert dber.getIoSetVals(db, key0) == oset()

        assert dber.putIoSetVals(db, key0, vals0) == True
        assert dber.putIoSetVals(db, key1, vals1) == True
        assert dber.putIoSetVals(db, key2, vals2) == True
        assert dber.getIoSetVals(db, key0) == vals0
        assert dber.getIoSetVals(db, key1) == vals1
        assert dber.getIoSetVals(db, key2) == vals2

        assert dber.appendIoSetVal(db, key1, val=b"k") == 4
        assert dber.getIoSetVals(db, key1) == [b"w", b"n", b"y", b"d", b"k"]

        assert dber.getIoSetItems(db, key0) == [(b'ABC.ZYX.00000000000000000000000000000000', b'z'),
                                                (b'ABC.ZYX.00000000000000000000000000000001', b'm'),
                                                (b'ABC.ZYX.00000000000000000000000000000002', b'x'),
                                                (b'ABC.ZYX.00000000000000000000000000000003', b'a')]

        assert ([(bytes(iokey), bytes(val)) for iokey, val in dber.getIoSetItemsIter(db, key0)] ==
                [(b'ABC.ZYX.00000000000000000000000000000000', b'z'),
                (b'ABC.ZYX.00000000000000000000000000000001', b'm'),
                (b'ABC.ZYX.00000000000000000000000000000002', b'x'),
                (b'ABC.ZYX.00000000000000000000000000000003', b'a')])

        for iokey, val in dber.getIoSetItemsIter(db, key0):
            assert dber.delIoSetIokey(db, iokey)
        assert dber.getIoSetVals(db, key0) == []

        vals3 = [b"q", b"e"]
        assert dber.setIoSetVals(db, key2, vals3)
        assert dber.getIoSetVals(db, key2) == vals3

    assert not os.path.exists(dber.path)

    """ End Test """


if __name__ == "__main__":
    test_lmdber()
