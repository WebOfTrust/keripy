# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import pytest

import os
import json

import lmdb

from keri.db.dbing import clearDatabaserDir, openLMDB, openDB
from keri.db.dbing import dgKey, snKey, splitKey, splitKeySn, LMDBer, Baser

from keri.core.coring import Signer, Nexter, Prefixer, Serder
from keri.core.coring import CryCntDex, CryOneDex, CryTwoDex, CryFourDex
from keri.core.coring import Serials, Vstrings, Versify

from keri.core.eventing import incept, rotate, interact, Kever, Kevery

from keri.help.helping import nowIso8601, toIso8601, fromIso8601


def test_key_funcs():
    """
    Test key utility functions
    """
    # Bytes
    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    sn = 3

    assert snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    assert splitKey(snKey(pre, sn)) == (pre, b'%032x' % sn)
    assert splitKeySn(snKey(pre, sn)) == (pre, sn)

    assert dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    assert splitKey(dgKey(pre, dig)) == (pre, dig)

    #  Str
    pre = 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    dig = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'

    assert snKey(pre, sn) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    assert splitKey(snKey(pre, sn).decode("utf-8")) == (pre, '%032x' % sn)
    assert splitKeySn(snKey(pre, sn).decode("utf-8")) == (pre, sn)

    assert dgKey(pre, dig) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                         b'.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

    assert splitKey(dgKey(pre, dig).decode("utf-8")) == (pre, dig)

    with pytest.raises(TypeError):
        snKey(pre, sn='3')

    with pytest.raises(ValueError):
        splitKey(pre)

    with pytest.raises(ValueError):
        splitKey(dgKey(pre, dgKey(pre, dig)))

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


    assert not os.path.exists(dber.path)

    """ End Test """


def test_baser():
    """
    Test Baser class
    """
    baser = Baser()
    assert isinstance(baser, Baser)
    assert baser.name == "main"
    assert baser.temp == False
    assert isinstance(baser.env, lmdb.Environment)
    assert baser.path.endswith("keri/db/main")
    assert baser.env.path() == baser.path
    assert os.path.exists(baser.path)

    assert isinstance(baser.evts, lmdb._Database)
    assert isinstance(baser.sigs, lmdb._Database)
    assert isinstance(baser.dtss, lmdb._Database)
    assert isinstance(baser.rcts, lmdb._Database)
    assert isinstance(baser.ures, lmdb._Database)
    assert isinstance(baser.kels, lmdb._Database)
    assert isinstance(baser.ooes, lmdb._Database)
    assert isinstance(baser.pses, lmdb._Database)
    assert isinstance(baser.dels, lmdb._Database)
    assert isinstance(baser.ldes, lmdb._Database)

    baser.close(clear=True)
    assert not os.path.exists(baser.path)
    assert not baser.opened

    # test not opened on init
    baser = Baser(reopen=False)
    assert isinstance(baser, Baser)
    assert baser.name == "main"
    assert baser.temp == False
    assert baser.opened == False
    assert baser.path == None
    assert baser.env == None

    baser.reopen()
    assert baser.opened
    assert isinstance(baser.env, lmdb.Environment)
    assert baser.path.endswith("keri/db/main")
    assert baser.env.path() == baser.path
    assert os.path.exists(baser.path)

    assert isinstance(baser.evts, lmdb._Database)
    assert isinstance(baser.sigs, lmdb._Database)
    assert isinstance(baser.dtss, lmdb._Database)
    assert isinstance(baser.rcts, lmdb._Database)
    assert isinstance(baser.ures, lmdb._Database)
    assert isinstance(baser.kels, lmdb._Database)
    assert isinstance(baser.ooes, lmdb._Database)
    assert isinstance(baser.pses, lmdb._Database)
    assert isinstance(baser.dels, lmdb._Database)
    assert isinstance(baser.ldes, lmdb._Database)

    baser.close(clear=True)
    assert not os.path.exists(baser.path)
    assert not baser.opened



    # Test using context manager
    with openLMDB(cls=Baser) as baser:
        assert isinstance(baser, Baser)
        assert baser.name == "test"
        assert baser.temp == True
        assert isinstance(baser.env, lmdb.Environment)
        assert baser.path.startswith("/tmp/keri_lmdb_")
        assert baser.path.endswith("_test/keri/db/test")
        assert baser.env.path() == baser.path
        assert os.path.exists(baser.path)

        assert isinstance(baser.evts, lmdb._Database)
        assert isinstance(baser.sigs, lmdb._Database)
        assert isinstance(baser.dtss, lmdb._Database)
        assert isinstance(baser.rcts, lmdb._Database)
        assert isinstance(baser.ures, lmdb._Database)
        assert isinstance(baser.kels, lmdb._Database)
        assert isinstance(baser.ooes, lmdb._Database)
        assert isinstance(baser.pses, lmdb._Database)
        assert isinstance(baser.dels, lmdb._Database)
        assert isinstance(baser.ldes, lmdb._Database)


    assert not os.path.exists(baser.path)

    preb = 'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
    digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
    sn = 3
    vs = Versify(kind=Serials.json, size=20)
    assert vs == 'KERI10JSON000014_'

    ked = dict(vs=vs, pre=preb.decode("utf-8"),
               sn="{:x}".format(sn),
               ilk="rot",
               dig=digb.decode("utf-8"))
    skedb = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert skedb == (b'{"vs":"KERI10JSON000014_","pre":"DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                     b'c","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"'
                     b'}')

    sig0b = 'AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ'.encode("utf-8")
    sig1b = 'AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z'.encode("utf-8")

    wit0b = 'BmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT'.encode("utf-8")
    wit1b = 'BjhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT'.encode("utf-8")
    wsig0b = '0B1Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9'.encode("utf-8")
    wsig1b = '0B5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z'.encode("utf-8")

    valb = 'EHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEH'.encode("utf-8")
    vdigb = 'EQiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-'.encode("utf-8")
    vsig0b = 'AAKAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe81Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1yQJmiu5AzJ9'.encode("utf-8")
    vsig1b = 'AB1KAV2zJ91Timrykocna6Z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz'.encode("utf-8")



    with openDB() as db:
        key = dgKey(preb, digb)
        assert key == (b'DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.'
                       b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')

        #  test .evts sub db methods
        assert db.getEvt(key) == None
        assert db.delEvt(key) == False
        assert db.putEvt(key, val=skedb) == True
        assert db.getEvt(key) == skedb
        assert db.putEvt(key, val=skedb) == False
        assert db.setEvt(key, val=skedb) == True
        assert db.getEvt(key) == skedb
        assert db.delEvt(key) == True
        assert db.getEvt(key) == None

        # test .dtss sub db methods
        val1 = b'2020-08-22T17:50:09.988921+00:00'
        val2 = b'2020-08-22T17:50:09.988921+00:00'

        assert db.getDts(key) == None
        assert db.delDts(key) == False
        assert db.putDts(key, val1) == True
        assert db.getDts(key) == val1
        assert db.putDts(key, val2) == False
        assert db.getDts(key) == val1
        assert db.setDts(key, val2) == True
        assert db.getDts(key) == val2
        assert db.delDts(key) == True
        assert db.getDts(key) == None

        # test .sigs sub db methods
        assert db.getSigs(key) == []
        assert db.cntSigs(key) == 0
        assert db.delSigs(key) == False

        # dup vals are lexocographic
        assert db.putSigs(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert db.getSigs(key) == [b'a', b'm', b'x', b'z']
        assert db.cntSigs(key) == 4
        assert db.putSigs(key, vals=[b'a']) == True   # duplicate but True
        assert db.getSigs(key) == [b'a', b'm', b'x', b'z']
        assert db.addSig(key, b'a') == False   # duplicate
        assert db.addSig(key, b'b') == True
        assert db.getSigs(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in db.getSigsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert db.delSigs(key) == True
        assert db.getSigs(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert db.putSigs(key, vals) == True
        for val in vals:
            assert db.delSigs(key, val) == True
        assert db.getSigs(key) == []
        assert db.putSigs(key, vals) == True
        for val in db.getSigsIter(key):
            assert db.delSigs(key, val) == True
        assert db.getSigs(key) == []

        assert db.putSigs(key, vals=[sig0b]) == True
        assert db.getSigs(key) == [sig0b]
        assert db.putSigs(key, vals=[sig1b]) == True
        assert db.getSigs(key) == [sig0b, sig1b]
        assert db.delSigs(key) == True
        assert db.putSigs(key, vals=[sig1b, sig0b]) == True
        assert db.getSigs(key) == [sig0b, sig1b]
        assert db.delSigs(key) == True
        assert db.getSigs(key) == []

        # test .rcts sub db methods dgkey
        assert db.getRcts(key) == []
        assert db.cntRcts(key) == 0
        assert db.delRcts(key) == False

        # dup vals are lexocographic
        assert db.putRcts(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert db.getRcts(key) == [b'a', b'm', b'x', b'z']
        assert db.cntRcts(key) == 4
        assert db.putRcts(key, vals=[b'a']) == True   # duplicate
        assert db.getRcts(key) == [b'a', b'm', b'x', b'z']
        assert db.addRct(key, b'a') == False   # duplicate
        assert db.addRct(key, b'b') == True
        assert db.getRcts(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in db.getRctsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert db.delRcts(key) == True
        assert db.getRcts(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert db.putRcts(key, vals) == True
        for val in vals:
            assert db.delRcts(key, val) == True
        assert db.getRcts(key) == []
        assert db.putRcts(key, vals) == True
        for val in db.getRctsIter(key):
            assert db.delRcts(key, val) == True
        assert db.getRcts(key) == []

        assert db.putRcts(key, vals=[wit0b + wsig0b, wit1b + wsig1b]) == True
        assert db.getRcts(key) == [wit1b + wsig1b, wit0b + wsig0b]  #  lex order
        assert db.putRcts(key, vals=[wit1b + wsig1b]) == True
        assert db.getRcts(key) == [wit1b + wsig1b, wit0b + wsig0b]  #  lex order
        assert db.delRcts(key) == True
        assert db.putRcts(key, vals=[wit1b + wsig1b, wit0b + wsig0b]) == True
        assert db.getRcts(key) == [wit1b + wsig1b, wit0b + wsig0b]  # lex order
        assert db.delRcts(key) == True
        assert db.getRcts(key) == []

        # test .ures sub db methods dgKey
        assert db.getUres(key) == []
        assert db.cntUres(key) == 0
        assert db.delUres(key) == False

        # dup vals are lexocographic
        assert db.putUres(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert db.getUres(key) == [b'a', b'm', b'x', b'z']
        assert db.cntUres(key) == 4
        assert db.putUres(key, vals=[b'a']) == True   # duplicate
        assert db.getUres(key) == [b'a', b'm', b'x', b'z']
        assert db.addUre(key, b'a') == False   # duplicate
        assert db.addUre(key, b'b') == True
        assert db.getUres(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in db.getUresIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert db.delUres(key) == True
        assert db.getUres(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert db.putUres(key, vals) == True
        for val in vals:
            assert db.delUres(key, val) == True
        assert db.getUres(key) == []
        assert db.putUres(key, vals) == True
        for val in db.getUresIter(key):
            assert db.delUres(key, val) == True
        assert db.getUres(key) == []

        assert db.putUres(key, vals=[wit0b + wsig0b, wit1b + wsig1b]) == True
        assert db.getUres(key) == [wit1b + wsig1b, wit0b + wsig0b]  #  lex order
        assert db.putUres(key, vals=[wit1b + wsig1b]) == True
        assert db.getUres(key) == [wit1b + wsig1b, wit0b + wsig0b]  #  lex order
        assert db.delUres(key) == True
        assert db.putUres(key, vals=[wit1b + wsig1b, wit0b + wsig0b]) == True
        assert db.getUres(key) == [wit1b + wsig1b, wit0b + wsig0b]  #  lex order
        assert db.delUres(key) == True
        assert db.getUres(key) == []

        # test .vrcs sub db methods dgkey
        assert db.getVrcs(key) == []
        assert db.cntVrcs(key) == 0
        assert db.delVrcs(key) == False

        # dup vals are lexocographic
        assert db.putVrcs(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert db.getVrcs(key) == [b'a', b'm', b'x', b'z']
        assert db.cntVrcs(key) == 4
        assert db.putVrcs(key, vals=[b'a']) == True   # duplicate
        assert db.getVrcs(key) == [b'a', b'm', b'x', b'z']
        assert db.addVrc(key, b'a') == False   # duplicate
        assert db.addVrc(key, b'b') == True
        assert db.getVrcs(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in db.getVrcsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert db.delVrcs(key) == True
        assert db.getVrcs(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert db.putVrcs(key, vals) == True
        for val in vals:
            assert db.delVrcs(key, val) == True
        assert db.getVrcs(key) == []
        assert db.putVrcs(key, vals) == True
        for val in db.getVrcsIter(key):
            assert db.delVrcs(key, val) == True
        assert db.getVrcs(key) == []

        assert db.putVrcs(key, vals=[valb + vdigb + vsig0b, valb + vdigb + vsig1b]) == True
        assert db.getVrcs(key) == [valb + vdigb + vsig0b, valb + vdigb + vsig1b]  #  lex order
        assert db.putVrcs(key, vals=[valb + vdigb + vsig1b]) == True
        assert db.getVrcs(key) == [valb + vdigb + vsig0b, valb + vdigb + vsig1b]  #  lex order
        assert db.delVrcs(key) == True
        assert db.putVrcs(key, vals=[ valb + vdigb + vsig1b, valb + vdigb + vsig0b]) == True
        assert db.getVrcs(key) == [valb + vdigb + vsig0b, valb + vdigb + vsig1b]  #  lex order
        assert db.delVrcs(key) == True
        assert db.getVrcs(key) == []

        # test .vres sub db methods dgKey
        assert db.getVres(key) == []
        assert db.cntVres(key) == 0
        assert db.delVres(key) == False

        # dup vals are lexocographic
        assert db.putVres(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert db.getVres(key) == [b'a', b'm', b'x', b'z']
        assert db.cntVres(key) == 4
        assert db.putVres(key, vals=[b'a']) == True   # duplicate
        assert db.getVres(key) == [b'a', b'm', b'x', b'z']
        assert db.addVre(key, b'a') == False   # duplicate
        assert db.addVre(key, b'b') == True
        assert db.getVres(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in db.getVresIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert db.delVres(key) == True
        assert db.getVres(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert db.putVres(key, vals) == True
        for val in vals:
            assert db.delVres(key, val) == True
        assert db.getVres(key) == []
        assert db.putVres(key, vals) == True
        for val in db.getVresIter(key):
            assert db.delVres(key, val) == True
        assert db.getVres(key) == []

        assert db.putVres(key, vals=[valb + vdigb + vsig0b, valb + vdigb + vsig1b]) == True
        assert db.getVres(key) == [valb + vdigb + vsig0b, valb + vdigb + vsig1b]  #  lex order
        assert db.putVres(key, vals=[valb + vdigb + vsig1b]) == True
        assert db.getVres(key) == [valb + vdigb + vsig0b, valb + vdigb + vsig1b]  #  lex order
        assert db.delVres(key) == True
        assert db.putVres(key, vals=[ valb + vdigb + vsig1b, valb + vdigb + vsig0b]) == True
        assert db.getVres(key) == [valb + vdigb + vsig0b, valb + vdigb + vsig1b]  #  lex order
        assert db.delVres(key) == True
        assert db.getVres(key) == []


        # test .kels insertion order dup methods.  dup vals are insertion order
        key = snKey(preb, 0)
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getKes(key) == []
        assert db.getKeLast(key) == None
        assert db.cntKes(key) == 0
        assert db.delKes(key) == False
        assert db.putKes(key, vals) == True
        assert db.getKes(key) == vals  # preserved insertion order
        assert db.cntKes(key) == len(vals) == 4
        assert db.getKeLast(key) == vals[-1]
        assert db.putKes(key, vals=[b'a']) == False   # duplicate
        assert db.getKes(key) == vals  #  no change
        assert db.addKe(key, b'a') == False   # duplicate
        assert db.addKe(key, b'b') == True
        assert db.getKes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delKes(key) == True
        assert db.getKes(key) == []

        # test .pses insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getPses(key) == []
        assert db.getPseLast(key) == None
        assert db.cntPses(key) == 0
        assert db.delPses(key) == False
        assert db.putPses(key, vals) == True
        assert db.getPses(key) == vals  # preserved insertion order
        assert db.cntPses(key) == len(vals) == 4
        assert db.getPseLast(key) == vals[-1]
        assert db.putPses(key, vals=[b'a']) == False   # duplicate
        assert db.getPses(key) == vals  #  no change
        assert db.addPse(key, b'a') == False   # duplicate
        assert db.addPse(key, b'b') == True
        assert db.getPses(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in db.getPsesIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delPses(key) == True
        assert db.getPses(key) == []

        # Setup Tests for getPsesNext and getPsesNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putPses(key=aKey, vals=aVals)
        assert db.putPses(key=bKey, vals=bVals)
        assert db.putPses(key=cKey, vals=cVals)
        assert db.putPses(key=dKey, vals=dVals)

        # Test getPseItemsNext( key=b"")
        # aVals
        items = db.getPseItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getPseItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getPseItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getPseItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getPseItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getPseItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getPseItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getPseItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getPseItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getPseItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getPseItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getPseItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getPseItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delPse(ikey, val) == True

        # bVals
        items = [item for item in db.getPseItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delPse(ikey, val) == True

        # cVals
        items = [item for item in db.getPseItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delPse(ikey, val) == True

        # dVals
        items = [item for item in db.getPseItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delPse(ikey, val) == True

        # none
        items = [item for item in db.getPseItemsNext(key=ikey)]
        assert items == []  # empty
        assert not items


        # test .ooes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getOoes(key) == []
        assert db.getOoeLast(key) == None
        assert db.cntOoes(key) == 0
        assert db.delOoes(key) == False
        assert db.putOoes(key, vals) == True
        assert db.getOoes(key) == vals  # preserved insertion order
        assert db.cntOoes(key) == len(vals) == 4
        assert db.getOoeLast(key) == vals[-1]
        assert db.putOoes(key, vals=[b'a']) == False   # duplicate
        assert db.getOoes(key) == vals  #  no change
        assert db.addOoe(key, b'a') == False   # duplicate
        assert db.addOoe(key, b'b') == True
        assert db.getOoes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delOoes(key) == True
        assert db.getOoes(key) == []

        # Setup Tests for getOoeItemsNext and getOoeItemsNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putOoes(key=aKey, vals=aVals)
        assert db.putOoes(key=bKey, vals=bVals)
        assert db.putOoes(key=cKey, vals=cVals)
        assert db.putOoes(key=dKey, vals=dVals)

        # Test getOoeItemsNext( key=b"")
        # aVals
        items = db.getOoeItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getOoeItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getOoeItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getOoeItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getOoeItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getOoeItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getOoeItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getOoeItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getOoeItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getOoeItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getOoeItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getOoeItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getOoeItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delOoe(ikey, val) == True

        # bVals
        items = [item for item in db.getOoeItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delOoe(ikey, val) == True

        # cVals
        items = [item for item in db.getOoeItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delOoe(ikey, val) == True

        # dVals
        items = [item for item in db.getOoeItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delOoe(ikey, val) == True

        # none
        items = [item for item in db.getOoeItemsNext(key=ikey)]
        assert items == []  # empty
        assert not items


        # test .dels insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getDes(key) == []
        assert db.getDeLast(key) == None
        assert db.cntDes(key) == 0
        assert db.delDes(key) == False
        assert db.putDes(key, vals) == True
        assert db.getDes(key) == vals  # preserved insertion order
        assert db.cntDes(key) == len(vals) == 4
        assert db.getDeLast(key) == vals[-1]
        assert db.putDes(key, vals=[b'a']) == False   # duplicate
        assert db.getDes(key) == vals  #  no change
        assert db.addDe(key, b'a') == False   # duplicate
        assert db.addDe(key, b'b') == True
        assert db.getDes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delDes(key) == True
        assert db.getDes(key) == []

        # test .ldes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getLdes(key) == []
        assert db.getLdeLast(key) == None
        assert db.cntLdes(key) == 0
        assert db.delLdes(key) == False
        assert db.putLdes(key, vals) == True
        assert db.getLdes(key) == vals  # preserved insertion order
        assert db.cntLdes(key) == len(vals) == 4
        assert db.getLdeLast(key) == vals[-1]
        assert db.putLdes(key, vals=[b'a']) == False   # duplicate
        assert db.getLdes(key) == vals  #  no change
        assert db.delLdes(key) == True
        assert db.getLdes(key) == []


    assert not os.path.exists(db.path)

    """ End Test """

def test_fetchkeldel():
    """
    Test fetching full KEL and full DEL from Baser
    """
    # Test using context manager
    preb = 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
    digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
    sn = 3
    vs = Versify(kind=Serials.json, size=20)
    assert vs == 'KERI10JSON000014_'

    ked = dict(vs=vs, pre=preb.decode("utf-8"),
               sn="{:x}".format(sn),
               ilk="rot",
               dig=digb.decode("utf-8"))
    skedb = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert skedb == (b'{"vs":"KERI10JSON000014_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                     b'c","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"'
                     b'}')


    sig0b = 'AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ'.encode("utf-8")
    sig1b = 'AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z'.encode("utf-8")

    wit0b = 'BmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT'.encode("utf-8")
    wit1b = 'BjhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT'.encode("utf-8")
    wsig0b = '0A1Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9'.encode("utf-8")
    wsig1b = '0A5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z'.encode("utf-8")

    with openDB() as db:
        # test getKelIter
        sn = 0
        key = snKey(preb, sn)
        assert key == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.'
                       b'00000000000000000000000000000000')
        vals0 = [skedb]
        assert db.addKe(key, vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(preb, sn)
        for val in vals1:
            assert db.addKe(key, val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        key = snKey(preb, sn)
        for val in vals2:
            assert db.addKe(key, val) == True

        vals = [bytes(val) for val in db.getKelIter(preb)]
        allvals = vals0 + vals1 + vals2
        assert vals == allvals

        # test getKelEstIter
        preb = 'B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x'.encode("utf-8")
        sn = 0
        key = snKey(preb, sn)
        assert key == (b'B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x.'
                       b'00000000000000000000000000000000')
        vals0 = [skedb]
        assert db.addKe(key, vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(preb, sn)
        for val in vals1:
            assert db.addKe(key, val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        key = snKey(preb, sn)
        for val in vals2:
            assert db.addKe(key, val) == True

        vals = [bytes(val) for val in db.getKelEstIter(preb)]
        lastvals = [vals0[-1], vals1[-1], vals2[-1]]
        assert vals == lastvals


        # test getDelIter
        preb = 'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw'.encode("utf-8")
        sn = 1  # do not start at zero
        key = snKey(preb, sn)
        assert key == (b'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw.'
                       b'00000000000000000000000000000001')
        vals0 = [skedb]
        assert db.addDe(key, vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        key = snKey(preb, sn)
        for val in vals1:
            assert db.addDe(key, val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 3  # skip make gap in SN
        key = snKey(preb, sn)
        for val in vals2:
            assert db.addDe(key, val) == True

        vals = [bytes(val) for val in db.getDelIter(preb)]
        allvals = vals0 + vals1 + vals2
        assert vals == allvals

    assert not os.path.exists(db.path)
    """ End Test """



def test_usebaser():
    """
    Test using Baser
    """
    # Some secrets to use on the events
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    #  create signers from the secrets
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [siger.qb64 for siger in signers] == secrets



    with openDB() as db:
        # Event 0  Inception Transferable (nxt digest not empty) 2 0f 3 multisig
        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        count = len(keys)
        nxtkeys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        sith = "2"
        code = CryOneDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        sith=sith,
                        nxt=Nexter(keys=nxtkeys).qb64)


        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i) for i in range(count)]
        # create key event verifier state
        kever = Kever(serder=serder, sigers=sigers, baser=db)

        # Event 1 Rotation Transferable
        keys = nxtkeys
        nxtkeys = [signers[5].verfer.qb64, signers[6].verfer.qb64, signers[7].verfer.qb64]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        sith=sith,
                        dig=kever.serder.diger.qb64,
                        nxt=Nexter(keys=nxtkeys).qb64,
                        sn=1)

        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)


        # Event 2 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.diger.qb64,
                          sn=2)

        # sign serialization  (keys don't change for signing)
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)

    assert not os.path.exists(db.path)

    """ End Test """

if __name__ == "__main__":
    test_baser()
