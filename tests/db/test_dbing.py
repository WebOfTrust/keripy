# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import pytest

import os

import lmdb
from  ordered_set import OrderedSet as oset

from keri.app import configing
from keri.db import dbing
from keri.db.dbing import openLMDB
from keri.db.dbing import (dgKey, onKey, snKey, dtKey, splitKey,
                           splitOnKey, splitSnKey, splitKeyDT)
from keri.db.dbing import LMDBer



from keri.core.eventing import incept, rotate, interact, Kever, Kevery
from keri.help import helping

def test_key_funcs():
    """
    Test key utility functions
    """
    # Bytes
    pre = b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3
    dts = b'2021-02-13T19:16:50.750302+00:00'


    # test onKey generator of key from top key and trailing ordinal number
    assert onKey(pre, 0) == pre + b'.' + b"%032x" % 0
    assert onKey(pre, 1) == pre + b'.' + b"%032x" % 1
    assert onKey(pre, 2) == pre + b'.' + b"%032x" % 2
    assert onKey(pre, 3) == pre + b'.' + b"%032x" % 3
    assert onKey(pre, 4) == pre + b'.' + b"%032x" % 4

    assert onKey(pre, 0, sep=b'|') == pre + b'|' + b"%032x" % 0
    assert onKey(pre, 4, sep=b'|') == pre + b'|' + b"%032x" % 4

    assert (onkey := onKey(top=pre, on=0)) == pre + b'.' + b"%032x" % 0
    assert splitKey(key=onkey) == (pre, b"%032x" % 0)
    assert splitOnKey(onkey) == (pre, 0)
    assert (onkey := onKey(top=pre, on=1)) == pre + b'.' + b"%032x" % 1
    assert splitKey(key=onkey) == (pre, b"%032x" % 1)
    assert splitOnKey(onkey) == (pre, 1)
    assert (onkey := onKey(top=pre, on=15)) == pre + b'.' + b"%032x" % 15
    assert splitKey(key=onkey) == (pre, b"%032x" % 15)
    assert splitOnKey(onkey) == (pre, 15)

    assert (onkey := onKey(top=pre, on=0, sep=b'|')) == pre + b'|' + b"%032x" % 0
    assert splitKey(key=onkey, sep=b'|') == (pre, b"%032x" % 0)
    assert splitOnKey(onkey, sep=b'|') == (pre, 0)
    assert (onkey := onKey(top=pre, on=15, sep=b'|')) == pre + b'|' + b"%032x" % 15
    assert splitKey(key=onkey, sep=b'|') == (pre, b"%032x" % 15)
    assert splitOnKey(onkey, sep=b'|') == (pre, 15)


    # test snKey
    assert snKey(pre, sn) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    assert splitKey(snKey(pre, sn)) == (pre, b'%032x' % sn)
    assert splitSnKey(snKey(pre, sn)) == (pre, sn)

    assert dgKey(pre, dig) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    #assert dgkey == f'{pre.decode("utf-8")}.{dig.decode("utf-8")}'.encode("utf-8")

    assert splitKey(dgKey(pre, dig)) == (pre, dig)

    assert dtKey(pre, dts) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'|2021-02-13T19:16:50.750302+00:00')

    assert splitKey(dtKey(pre, dts), sep=b'|') == (pre, dts)
    assert splitKeyDT(dtKey(pre, dts)) == (pre, helping.fromIso8601(dts.decode("utf-8")))

    #  Str
    pre = 'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    dts = '2021-02-13T19:16:50.750302+00:00'

    assert snKey(pre, sn) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    assert splitKey(snKey(pre, sn).decode("utf-8")) == (pre, '%032x' % sn)
    assert splitSnKey(snKey(pre, sn).decode("utf-8")) == (pre, sn)

    assert dgKey(pre, dig) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    assert splitKey(dgKey(pre, dig).decode("utf-8")) == (pre, dig)

    assert dtKey(pre, dts) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                b'|2021-02-13T19:16:50.750302+00:00')

    assert splitKey(dtKey(pre, dts).decode("utf-8"), sep=b'|') == (pre, dts)
    assert splitKeyDT(dtKey(pre, dts).decode("utf-8")) == (pre, helping.fromIso8601(dts))


    with pytest.raises(TypeError):
        snKey(pre, sn='3')

    with pytest.raises(ValueError):
        splitKey(pre)

    assert splitKey(dgKey(pre, dgKey(pre, dig)))  # rsplit on gets trailing part

    # memoryview
    # Bytes
    pre = b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3
    dts = b'2021-02-13T19:16:50.750302+00:00'

    key = memoryview(snKey(pre, sn))
    assert splitKey(key) == (pre, b'%032x' % sn)
    assert splitSnKey(key) == (pre, sn)

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

    pre = b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3

    assert snKey(pre, sn) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')
    assert dgKey(pre, dig) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
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

    pre = b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3

    assert snKey(pre, sn) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')
    assert dgKey(pre, dig) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
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

        # Test getTopItemIter
        key = b"a.1"
        val = b"wow"
        assert dber.putVal(db, key, val) == True
        key = b"a.2"
        val = b"wee"
        assert dber.putVal(db, key, val) == True
        key = b"b.1"
        val = b"woo"
        assert dber.putVal(db, key, val) == True
        assert [(bytes(key), bytes(val)) for key, val
                     in dber.getTopItemIter(db=db)] == [(b'a.1', b'wow'),
                                                        (b'a.2', b'wee'),
                                                        (b'b.1', b'woo')]

        assert dber.delTopVal(db, top=b"a.")
        items = [ (key, bytes(val)) for key, val in dber.getTopItemIter(db=db )]
        assert items == [(b'b.1', b'woo')]

        # test Ordinal Numbered ON keyed value methods
        db = dber.env.open_db(key=b'seen.')

        preA = b'BBKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'
        preB = b'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'
        preC = b'EIDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'
        preD = b'EAYC49i5zY_qrIZIicQgIDA1n-WiBA0A8YOqnKrB-wWQ'

        keyA0 = onKey(preA, 0)

        keyB0 = onKey(preB, 0)
        keyB1 = onKey(preB, 1)
        keyB2 = onKey(preB, 2)
        keyB3 = onKey(preB, 3)
        keyB4 = onKey(preB, 4)

        keyC0 = onKey(preC, 0)

        digA = b'EA73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'

        digU = b'EB73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'
        digV = b'EC4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY'
        digW = b'EDAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w'
        digX = b'EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o'
        digY = b'EFrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk'

        digC = b'EG5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w'

        assert dber.getVal(db, keyA0) == None
        assert dber.delVal(db, keyA0) == False
        assert dber.putVal(db, keyA0, val=digA) == True
        assert dber.getVal(db, keyA0) == digA
        assert dber.putVal(db, keyA0, val=digA) == False
        assert dber.setVal(db, keyA0, val=digA) == True
        assert dber.getVal(db, keyA0) == digA
        assert dber.getOnVal(db, preA, 0) == digA
        assert dber.delVal(db, keyA0) == True
        assert dber.getVal(db, keyA0) == None
        assert dber.getOnVal(db, preA, 0) == None

        assert dber.putOnVal(db, preA, 0, val=digA) == True
        assert dber.getOnVal(db, preA, 0) == digA
        assert dber.putOnVal(db, preA, 0, val=digA) == False
        assert dber.setOnVal(db, preA, 0, val=digA) == True
        assert dber.getOnVal(db, preA, 0) == digA
        assert dber.delOnVal(db, preA, 0) == True
        assert dber.getOnVal(db, preA, 0) == None

        #  test appendOnValPre
        # empty database
        assert dber.getVal(db, keyB0) == None
        on = dber.appendOnVal(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU
        assert dber.delVal(db, keyB0) == True
        assert dber.getVal(db, keyB0) == None

        # earlier pre in database only
        assert dber.putVal(db, keyA0, val=digA) == True
        on = dber.appendOnVal(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU
        assert dber.delVal(db, keyB0) == True
        assert dber.getVal(db, keyB0) == None

        # earlier and later pre in db but not same pre
        assert dber.getVal(db, keyA0) == digA
        assert dber.putVal(db, keyC0, val=digC) == True
        on = dber.appendOnVal(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU
        assert dber.delVal(db, keyB0) == True
        assert dber.getVal(db, keyB0) == None

        # later pre only
        assert dber.delVal(db, keyA0) == True
        assert dber.getVal(db, keyA0) == None
        assert dber.getVal(db, keyC0) == digC
        on = dber.appendOnVal(db, preB, digU)
        assert on == 0
        assert dber.getVal(db, keyB0) == digU

        # earlier pre and later pre and earlier entry for same pre
        assert dber.putVal(db, keyA0, val=digA) == True
        on = dber.appendOnVal(db, preB, digV)
        assert on == 1
        assert dber.getVal(db, keyB1) == digV

        # earlier entry for same pre but only same pre
        assert dber.delVal(db, keyA0) == True
        assert dber.getVal(db, keyA0) == None
        assert dber.delVal(db, keyC0) == True
        assert dber.getVal(db, keyC0) == None
        # another value for preB
        on = dber.appendOnVal(db, preB, digW)
        assert on == 2
        assert dber.getVal(db, keyB2) == digW
        # yet another value for preB
        on = dber.appendOnVal(db, preB, digX)
        assert on == 3
        assert dber.getVal(db, keyB3) == digX
        # yet another value for preB
        on = dber.appendOnVal(db, preB, digY )
        assert on == 4
        assert dber.getVal(db, keyB4) == digY

        assert dber.appendOnVal(db, preD, digY ) == 0

        assert dber.cntOnVals(db, key=preB) == 5
        assert dber.cntOnVals(db, key=b'') == 6  # all keys
        assert dber.cntOnVals(db) == 6  # all keys

        # iter replay
        # replay preB event items in database
        items = [item for item in dber.getOnItemIter(db, preB)]
        assert items == [(preB, 0, digU), (preB, 1, digV), (preB, 2, digW),
                         (preB, 3, digX), (preB, 4, digY)]

        # resume replay preB events at on = 3
        items = [item for item in dber.getOnItemIter(db, preB, on=3)]
        assert items == [(preB, 3, digX), (preB, 4, digY)]

        # resume replay preB events at on = 5
        items = [item for item in dber.getOnItemIter(db, preB, on=5)]
        assert items == []

        # replay all events in database with pre events before and after
        assert dber.putVal(db, keyA0, val=digA) == True
        assert dber.putVal(db, keyC0, val=digC) == True

        items = [item  for item in dber.getOnItemIter(db, key=b'')]
        assert items == [(preA, 0, digA),
                         (preD, 0, digY),
                         (preB, 0, digU),
                         (preB, 1, digV),
                         (preB, 2, digW),
                         (preB, 3, digX),
                         (preB, 4, digY),
                         (preC, 0, digC)]

        items = [item  for item in dber.getOnItemIter(db)]
        assert items == [(preA, 0, digA),
                         (preD, 0, digY),
                         (preB, 0, digU),
                         (preB, 1, digV),
                         (preB, 2, digW),
                         (preB, 3, digX),
                         (preB, 4, digY),
                         (preC, 0, digC)]

        # resume replay all starting at preB on=2
        top, on = splitOnKey(keyB2)
        items = [item for item in dber.getOnItemIter(db, key=top, on=on)]
        assert items == [(top, 2, digW), (top, 3, digX), (top, 4, digY)]

        # resume replay all starting at preC on=1
        items = [item for item in dber.getOnItemIter(db, key=preC, on=1)]
        assert items == []

        # val replay
        # replay preB event vals in database
        vals = [val for val in dber.getOnValIter(db, preB)]
        assert vals == [digU, digV, digW, digX, digY]

        # resume replay preB events at on = 3
        vals = [val for val in dber.getOnValIter(db, preB, on=3)]
        assert vals == [digX, digY]

        # resume replay preB events at on = 5
        vals = [val for val in dber.getOnValIter(db, preB, on=5)]
        assert vals == []

        vals = [val  for val in dber.getOnValIter(db, key=b'')]
        assert vals == [digA,
                        digY,
                        digU,
                        digV,
                        digW,
                        digX,
                        digY,
                        digC]

        vals = [val  for val in dber.getOnValIter(db)]
        assert vals == [digA,
                        digY,
                        digU,
                        digV,
                        digW,
                        digX,
                        digY,
                        digC]

        # resume replay all starting at preB on=2
        top, on = splitOnKey(keyB2)
        vals = [val for val in dber.getOnValIter(db, key=top, on=on)]
        assert vals == [digW, digX, digY]

        # resume replay all starting at preC on=1
        vals = [val for val in dber.getOnValIter(db, key=preC, on=1)]
        assert vals == []


        # test delOnVal
        assert dber.delOnVal(db, key=preB)  # default on=0
        assert not dber.delOnVal(db, key=preB, on=0)
        assert dber.delOnVal(db, key=preB, on=1)
        assert not dber.delOnVal(db, key=preB, on=1)

        items = [item for item in dber.getOnItemIter(db, key=preB)]
        assert items == [(top, 2, digW), (top, 3, digX), (top, 4, digY)]

        with pytest.raises(KeyError):
            assert dber.delOnVal(db, key=b'')  #  empty key


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

        assert dber.getIoDupVals(db, key) == []
        assert dber.getIoDupValLast(db, key) == None
        assert dber.cntIoDupVals(db, key) == 0
        assert dber.delIoDupVals(db, key) == False
        assert dber.putIoDupVals(db, key, vals) == True
        assert dber.getIoDupVals(db, key) == vals  # preserved insertion order
        assert dber.cntIoDupVals(db, key) == len(vals) == 4
        assert dber.getIoDupValLast(db, key) == vals[-1]
        assert dber.putIoDupVals(db, key, vals=[b'a']) == False   # duplicate
        assert dber.getIoDupVals(db, key) == vals  #  no change
        assert dber.addIoDupVal(db, key, val=b'b') == True
        assert dber.addIoDupVal(db, key, val=b'a') == False
        assert dber.getIoDupVals(db, key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in dber.getIoDupValsIter(db, key)] == [b"z", b"m", b"x", b"a", b'b']
        assert dber.delIoDupVals(db, key) == True
        assert dber.getIoDupVals(db, key) == []
        assert dber.putIoDupVals(db, key, vals) == True
        for val in vals:
            assert dber.delIoDupVal(db, key, val)
        assert dber.getIoDupVals(db, key) == []
        assert dber.putIoDupVals(db, key, vals) == True
        for val in sorted(vals):
            assert dber.delIoDupVal(db, key, val)
        assert dber.getIoDupVals(db, key) == []
        #delete and add in odd order
        assert dber.putIoDupVals(db, key, vals) == True
        assert dber.delIoDupVal(db, key, vals[2])
        assert dber.addIoDupVal(db, key, b'w')
        assert dber.delIoDupVal(db, key, vals[0])
        assert dber.addIoDupVal(db, key, b'e')
        assert dber.getIoDupVals(db, key) == [b'm', b'a', b'w', b'e']


        # Test TopIoDupItemIter(self, db, pre)
        pre = b'BBPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcc'
        vals0 = [b"gamma", b"beta"]
        sn = 1  # not start at zero
        key = snKey(pre, sn)
        assert dber.addIoDupVal(db, key, vals0[0]) == True
        assert dber.addIoDupVal(db, key, vals0[1]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(pre, sn)
        assert dber.putIoDupVals(db, key, vals1) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 2  # gap
        key = snKey(pre, sn)
        assert dber.putIoDupVals(db, key, vals2) == True

        allvals = vals0 + vals1 + vals2
        vals = [bytes(val) for key, val in dber.getTopIoDupItemIter(db, pre)]
        # dber.getTopIoDupItemIter()
        assert vals == allvals



        # Setup Tests for TopIoDupItemsIter
        edb = dber.env.open_db(key=b'escrow.', dupsort=True)
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]


        # Test  variousItemIter
        assert dber.putIoDupVals(edb, key=aKey, vals=aVals)
        assert dber.putIoDupVals(edb, key=bKey, vals=bVals)
        assert dber.putIoDupVals(edb, key=cKey, vals=cVals)
        assert dber.putIoDupVals(edb, key=dKey, vals=dVals)

        # test getTopIoDupItemIter
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb)]  # default all
        assert items == [(b'A.00000000000000000000000000000001', b'z'),
                        (b'A.00000000000000000000000000000001', b'm'),
                        (b'A.00000000000000000000000000000001', b'x'),
                        (b'A.00000000000000000000000000000002', b'o'),
                        (b'A.00000000000000000000000000000002', b'r'),
                        (b'A.00000000000000000000000000000002', b'z'),
                        (b'A.00000000000000000000000000000004', b'h'),
                        (b'A.00000000000000000000000000000004', b'n'),
                        (b'A.00000000000000000000000000000007', b'k'),
                        (b'A.00000000000000000000000000000007', b'b')]

        # dups at aKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=aKey)]
        assert items == [(b'A.00000000000000000000000000000001', b'z'),
                        (b'A.00000000000000000000000000000001', b'm'),
                        (b'A.00000000000000000000000000000001', b'x')]

        # dups at bKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=bKey)]
        assert items == [(b'A.00000000000000000000000000000002', b'o'),
                        (b'A.00000000000000000000000000000002', b'r'),
                        (b'A.00000000000000000000000000000002', b'z')]

        # dups at cKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=cKey)]
        assert items == [(b'A.00000000000000000000000000000004', b'h'),
                         (b'A.00000000000000000000000000000004', b'n')]

        # dups at dKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=dKey)]
        assert items == [(b'A.00000000000000000000000000000007', b'k'),
                         (b'A.00000000000000000000000000000007', b'b')]

        # dups at missing key
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=b"B.")]
        assert not items


        # test getIoDupItemIter
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb)]  # default all
        assert items == [(b'A.00000000000000000000000000000001', b'z'),
                        (b'A.00000000000000000000000000000001', b'm'),
                        (b'A.00000000000000000000000000000001', b'x'),
                        (b'A.00000000000000000000000000000002', b'o'),
                        (b'A.00000000000000000000000000000002', b'r'),
                        (b'A.00000000000000000000000000000002', b'z'),
                        (b'A.00000000000000000000000000000004', b'h'),
                        (b'A.00000000000000000000000000000004', b'n'),
                        (b'A.00000000000000000000000000000007', b'k'),
                        (b'A.00000000000000000000000000000007', b'b')]


        # dups at aKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=aKey)]
        assert items == [(b'A.00000000000000000000000000000001', b'z'),
                        (b'A.00000000000000000000000000000001', b'm'),
                        (b'A.00000000000000000000000000000001', b'x')]
        # dups at bKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=bKey)]
        assert items == [(b'A.00000000000000000000000000000002', b'o'),
                        (b'A.00000000000000000000000000000002', b'r'),
                        (b'A.00000000000000000000000000000002', b'z')]

        # dups at cKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=cKey)]
        assert items == [(b'A.00000000000000000000000000000004', b'h'),
                        (b'A.00000000000000000000000000000004', b'n')]

        # dups at dKey
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=dKey)]
        assert items == [(b'A.00000000000000000000000000000007', b'k'),
                         (b'A.00000000000000000000000000000007', b'b')]

        # dups at missing key
        items = [(ikey, bytes(ival)) for ikey, ival in dber.getTopIoDupItemIter(edb, top=b"B.")]
        assert not items


        # test OnIoDup methods
        ldb = dber.env.open_db(key=b'log.', dupsort=True)
        # first pre
        sn = 0
        key = snKey(preA, sn)
        valsA0 = [b"echo", b"bravo"]
        itemsA0 = [
                    (preA, sn, valsA0[0]),
                    (preA, sn, valsA0[1])
                 ]
        assert dber.addIoDupVal(ldb, key, valsA0[0]) == True
        assert dber.addIoDupVal(ldb, key, valsA0[1]) == True

        sn += 1
        key = snKey(preA, sn)
        valsA1 = [b"sue", b"bob", b"val", b"zoe"]
        itemsA1 = [
                   (preA, sn, valsA1[0]),
                   (preA, sn, valsA1[1]),
                   (preA, sn, valsA1[2]),
                   (preA, sn, valsA1[3]),
                 ]
        assert dber.putIoDupVals(ldb, key, valsA1) == True

        sn += 1
        key = snKey(preA, sn)
        valsA2 = [b"fish", b"bat", b"snail"]
        itemsA2 = [
                   (preA, sn, valsA2[0]),
                   (preA, sn, valsA2[1]),
                   (preA, sn, valsA2[2]),
                 ]
        assert dber.putIoDupVals(ldb, key, valsA2) == True

        # second pre
        sn = 0
        key = snKey(preB, sn)
        valsB0 = [b"gamma", b"beta"]
        itemsB0 = [
                    (preB, sn, valsB0[0]),
                    (preB, sn, valsB0[1])
                 ]
        assert dber.addIoDupVal(ldb, key, valsB0[0]) == True
        assert dber.addIoDupVal(ldb, key, valsB0[1]) == True

        sn += 1
        key = snKey(preB, sn)
        valsB1 = [b"mary", b"peter", b"john", b"paul"]
        itemsB1 = [
                   (preB, sn, valsB1[0]),
                   (preB, sn, valsB1[1]),
                   (preB, sn, valsB1[2]),
                   (preB, sn, valsB1[3]),
                 ]
        assert dber.putIoDupVals(ldb, key, valsB1) == True


        sn += 1
        key = snKey(preB, sn)
        valsB2 = [b"dog", b"cat", b"bird"]
        itemsB2 = [
                   (preB, sn, valsB2[0]),
                   (preB, sn, valsB2[1]),
                   (preB, sn, valsB2[2]),
                 ]
        assert dber.putIoDupVals(ldb, key, valsB2) == True


        items = [(key, on, bytes(val)) for key, on, val in dber.getOnIoDupLastItemIter(ldb, preA)]
        lastitems = [itemsA0[-1], itemsA1[-1], itemsA2[-1]]
        assert items == lastitems

        items = [(key, on, bytes(val)) for key, on, val in dber.getOnIoDupLastItemIter(ldb, preA, on=1)]
        lastitems = [itemsA1[-1], itemsA2[-1]]
        assert items == lastitems

        vals = [bytes(val) for val in dber.getOnIoDupLastValIter(ldb, preA)]
        lastvals = [valsA0[-1], valsA1[-1], valsA2[-1]]
        assert vals == lastvals

        vals = [bytes(val) for val in dber.getOnIoDupLastValIter(ldb, preA, on=1)]
        lastvals = [valsA1[-1], valsA2[-1]]
        assert vals == lastvals


        items = [(key, on, bytes(val)) for key, on, val in dber.getOnIoDupLastItemIter(ldb, preB)]
        lastitems = [itemsB0[-1], itemsB1[-1], itemsB2[-1]]
        assert items == lastitems

        vals = [bytes(val) for val in dber.getOnIoDupLastValIter(ldb, preB)]
        lastvals = [valsB0[-1], valsB1[-1], valsB2[-1]]
        assert vals == lastvals

        items = [(key, on, bytes(val)) for key, on, val in dber.getOnIoDupLastItemIter(ldb)]
        lastitems = [itemsA0[-1], itemsA1[-1], itemsA2[-1], itemsB0[-1], itemsB1[-1], itemsB2[-1]]
        assert items == lastitems

        vals = [bytes(val) for val in dber.getOnIoDupLastValIter(ldb)]
        lastvals = [valsA0[-1], valsA1[-1], valsA2[-1], valsB0[-1], valsB1[-1], valsB2[-1]]
        assert vals == lastvals

        # test back iter

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=preB, on=3)]
        assert items ==[(preB, 2, b'bird'),
                        (preB, 2, b'cat'),
                        (preB, 2, b'dog'),
                        (preB, 1, b'paul'),
                        (preB, 1, b'john'),
                        (preB, 1, b'peter'),
                        (preB, 1, b'mary'),
                        (preB, 0, b'beta'),
                        (preB, 0, b'gamma')]


        vals = [ bytes(val) for val in dber.getOnIoDupValBackIter(ldb, key=preB, on=3)]
        assert vals ==[
                        b'bird',
                        b'cat',
                        b'dog',
                        b'paul',
                        b'john',
                        b'peter',
                        b'mary',
                        b'beta',
                        b'gamma'
                      ]

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=preB, on=1)]
        assert items ==[
                        (preB, 1, b'paul'),
                        (preB, 1, b'john'),
                        (preB, 1, b'peter'),
                        (preB, 1, b'mary'),
                        (preB, 0, b'beta'),
                        (preB, 0, b'gamma')
                       ]

        vals = [ bytes(val) for val in dber.getOnIoDupValBackIter(ldb, key=preB, on=1)]
        assert vals ==[
                        b'paul',
                        b'john',
                        b'peter',
                        b'mary',
                        b'beta',
                        b'gamma'
                      ]

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=preA, on=5)]
        assert items ==[(preA, 2, b'snail'),
                        (preA, 2, b'bat'),
                        (preA, 2, b'fish'),
                        (preA, 1, b'zoe'),
                        (preA, 1, b'val'),
                        (preA, 1, b'bob'),
                        (preA, 1, b'sue'),
                        (preA, 0, b'bravo'),
                        (preA, 0, b'echo')]

        vals = [ bytes(val) for val in dber.getOnIoDupValBackIter(ldb, key=preA, on=5)]
        assert vals ==[
                        b'snail',
                        b'bat',
                        b'fish',
                        b'zoe',
                        b'val',
                        b'bob',
                        b'sue',
                        b'bravo',
                        b'echo'
                      ]

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=preA, on=0)]
        assert items ==[
                        (preA, 0, b'bravo'),
                        (preA, 0, b'echo')]

        vals = [ bytes(val) for val in dber.getOnIoDupValBackIter(ldb, key=preA, on=0)]
        assert vals ==[
                        b'bravo',
                        b'echo'
                      ]

        # all items from last to first
        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb)]
        assert items ==[
                        (preB, 2, b'bird'),
                        (preB, 2, b'cat'),
                        (preB, 2, b'dog'),
                        (preB, 1, b'paul'),
                        (preB, 1, b'john'),
                        (preB, 1, b'peter'),
                        (preB, 1, b'mary'),
                        (preB, 0, b'beta'),
                        (preB, 0, b'gamma'),
                        (preA, 2, b'snail'),
                        (preA, 2, b'bat'),
                        (preA, 2, b'fish'),
                        (preA, 1, b'zoe'),
                        (preA, 1, b'val'),
                        (preA, 1, b'bob'),
                        (preA, 1, b'sue'),
                        (preA, 0, b'bravo'),
                        (preA, 0, b'echo'),
                       ]

        vals = [ bytes(val) for val in dber.getOnIoDupValBackIter(ldb)]
        assert vals ==[
                        b'bird',
                        b'cat',
                        b'dog',
                        b'paul',
                        b'john',
                        b'peter',
                        b'mary',
                        b'beta',
                        b'gamma',
                        b'snail',
                        b'bat',
                        b'fish',
                        b'zoe',
                        b'val',
                        b'bob',
                        b'sue',
                        b'bravo',
                        b'echo'
                      ]


        # test OnIoDup methods
        key = b'Z'
        assert 0 == dber.appendOnIoDupVal(ldb, key, val=b'k')
        assert 1 == dber.appendOnIoDupVal(ldb, key, val=b'l')
        assert 2 == dber.appendOnIoDupVal(ldb, key, val=b'm')
        assert 3 == dber.appendOnIoDupVal(ldb, key, val=b'n')

        assert dber.cntOnVals(ldb, key) == 4

        vals = [ bytes(val) for val in dber.getOnIoDupValIter(ldb, key=key)]
        assert vals == [b'k', b'l', b'm', b'n']

        vals = [ bytes(val) for val in dber.getOnIoDupValIter(ldb, key=key, on=2)]
        assert vals == [ b'm', b'n']


        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemIter(ldb, key=key)]
        assert items == [(b'Z', 0, b'k'),
                         (b'Z', 1, b'l'),
                         (b'Z', 2, b'm'),
                         (b'Z', 3, b'n')]

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemIter(ldb, key=key, on=2)]
        assert items == [
                         (b'Z', 2, b'm'),
                         (b'Z', 3, b'n')]

        # test back iter

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=key, on=3)]
        assert items ==[(b'Z', 3, b'n'),
                        (b'Z', 2, b'm'),
                        (b'Z', 1, b'l'),
                        (b'Z', 0, b'k')]

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=key, on=4)]
        assert items ==[(b'Z', 3, b'n'),
                        (b'Z', 2, b'm'),
                        (b'Z', 1, b'l'),
                        (b'Z', 0, b'k')]

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemBackIter(ldb, key=key, on=2)]
        assert items == [(b'Z', 2, b'm'),
                         (b'Z', 1, b'l'),
                         (b'Z', 0, b'k')]

        key = b'Y'
        assert dber.addOnIoDupVal(ldb, key, on=0, val=b'r')
        assert dber.addOnIoDupVal(ldb, key, on=0, val=b's')
        assert dber.addOnIoDupVal(ldb, key, on=1, val=b't')
        assert dber.addOnIoDupVal(ldb, key, on=1, val=b'u')

        assert dber.cntOnVals(ldb, key) == 4

        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemIter(ldb, key=key)]
        assert items == [(b'Y', 0, b'r'),
                         (b'Y', 0, b's'),
                         (b'Y', 1, b't'),
                         (b'Y', 1, b'u')]

        assert dber.delOnIoDupVal(ldb, key, on=0, val=b's')
        assert dber.delOnIoDupVals(ldb, key, on=1)
        items = [ (key, on, bytes(val)) for key, on, val in dber.getOnIoDupItemIter(ldb, key=key)]
        assert items == [(b'Y', 0, b'r')]

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


        vals3 = [b"q", b"e"]
        assert dber.setIoSetVals(db, key2, vals3)
        assert dber.getIoSetVals(db, key2) == vals3

        # Empty keys cause lmdb.BalValsizeError so LMDBer now throws a KeyError
        # if it catches this kind of thing in the various places where it gets
        # thrown
        empty_key = ''.encode('utf8')
        some_value = 'foo'.encode('utf8')
        with pytest.raises(KeyError):
            dber.putVal(db, empty_key, some_value)
        with pytest.raises(KeyError):
            dber.setVal(db, empty_key, some_value)
        with pytest.raises(KeyError):
            dber.getVal(db, empty_key)
        with pytest.raises(KeyError):
            dber.delVal(db, empty_key)
        dber.putIoSetVals(db, empty_key, [some_value])
        dber.addIoSetVal(db, empty_key, some_value)
        dber.setIoSetVals(db, empty_key, [some_value])
        dber.getIoSetVals(db, empty_key)
        [_ for _ in dber.getIoSetValsIter(db, empty_key)]
        dber.getIoSetValLast(db, empty_key)
        dber.cntIoSetVals(db, empty_key)
        dber.delIoSetVals(db, empty_key)
        dber.delIoSetVal(db, empty_key, some_value)
        with pytest.raises(KeyError):
            dber.putVals(db, empty_key, [some_value])
        with pytest.raises(KeyError):
            dber.addVal(db, empty_key, some_value)
        with pytest.raises(KeyError):
            dber.getVals(db, empty_key)
        with pytest.raises(KeyError):
            dber.getValLast(db, empty_key)
        with pytest.raises(KeyError):
            [_ for _ in dber.getValsIter(db, empty_key)]
        with pytest.raises(KeyError):
            dber.cntVals(db, empty_key)
        with pytest.raises(KeyError):
            dber.delVals(db, empty_key)
        with pytest.raises(KeyError):
            dber.putIoDupVals(db, empty_key, [some_value])
        with pytest.raises(KeyError):
            dber.addIoDupVal(db, empty_key, some_value)
        with pytest.raises(KeyError):
            dber.getIoDupVals(db, empty_key)
        with pytest.raises(KeyError):
            [_ for _ in dber.getIoDupValsIter(db, empty_key)]
        with pytest.raises(KeyError):
            dber.getIoDupValLast(db, empty_key)
        with pytest.raises(KeyError):
            dber.cntIoDupVals(db, empty_key)
        with pytest.raises(KeyError):
            dber.delIoDupVals(db, empty_key)
        with pytest.raises(KeyError):
            dber.delIoDupVal(db, empty_key, some_value)

    assert not os.path.exists(dber.path)

    """ End Test """


def test_lmdber_config_with_file():
    cf = configing.Configer()
    configDict = dict(
        lmdber=dict(
            mapSize="1_073_741_824"
        )
    )
    cf.put(configDict)

    databaser = LMDBer(cf=cf)
    assert databaser.mapSize == 1_073_741_824, "Map Size should be 1GB"  # 1024*1024*1024 = 1GB

    badConfigStr = dict(
        lmdber=dict(
            mapSize="somestr"
        )
    )
    cf.put(badConfigStr)
    with pytest.raises(ValueError):
        LMDBer(cf=cf)

    badConfigNone = dict(
        lmdber=dict(
            mapSize=None
        )
    )
    cf.put(badConfigNone)
    with pytest.raises(ValueError):
        LMDBer(cf=cf)

    badConfigNeg = dict(
        lmdber=dict(
            mapSize=-1
        )
    )
    cf.put(badConfigNeg)
    with pytest.raises(ValueError):
        LMDBer(cf=cf)


if __name__ == "__main__":
    test_key_funcs()
    test_suffix()
    test_lmdber()
    test_opendatabaser()
