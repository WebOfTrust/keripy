# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import json
import os
from dataclasses import dataclass, asdict

import lmdb
import pytest
from hio.base import doing

from tests.app import openMultiSig
from keri.kering import Versionage
from keri.app import habbing
from keri.core import coring, eventing, serdering
from keri.core.coring import MtrDex
from keri.core.coring import Serials, versify
from keri.core.coring import Salter
from keri.core.eventing import incept, rotate, interact, Kever
from keri.db import basing
from keri.db import dbing
from keri.db.basing import openDB, Baser, KeyStateRecord
from keri.db.dbing import (dgKey, onKey, snKey)
from keri.db.dbing import openLMDB
from keri.help.helping import datify, dictify


def test_baser():
    """
    Test Baser class
    """
    baser = Baser(reopen=True)  # default is to not reopen
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

    preb = 'DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
    digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
    sn = 3
    vs = versify(kind=Serials.json, size=20)
    assert vs == 'KERI10JSON000014_'

    ked = dict(vs=vs, pre=preb.decode("utf-8"),
               sn="{:x}".format(sn),
               ilk="rot",
               dig=digb.decode("utf-8"))
    skedb = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert skedb == (b'{"vs":"KERI10JSON000014_","pre":"DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                     b'c","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"'
                     b'}')

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



    with openDB() as db:
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

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

        # test eventsourcerecords .srcs
        record = basing.EventSourceRecord()
        assert db.esrs.get(key) == None
        assert db.esrs.put(key, record) == True
        actual = db.esrs.get(key)
        assert actual == record
        record.local = False
        # put does not overwrite must pin
        assert db.esrs.put(key, record) == False
        actual = db.esrs.get(key)
        assert actual.local != record.local
        assert actual != record
        assert not db.esrs.get(key) == record
        assert db.esrs.pin(key, record) == True
        actual = db.esrs.get(key)
        assert actual.local == record.local
        assert db.esrs.get(key) == record




        # test first seen event log .fels sub db
        preA = b'BAKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc'
        preB = b'EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w'
        preC = b'EIDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg'

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

        assert db.getFe(keyA0) == None
        assert db.delFe(keyA0) == False
        assert db.putFe(keyA0, val=digA) == True
        assert db.getFe(keyA0) == digA
        assert db.putFe(keyA0, val=digA) == False
        assert db.setFe(keyA0, val=digA) == True
        assert db.getFe(keyA0) == digA
        assert db.delFe(keyA0) == True
        assert db.getFe(keyA0) == None

        #  test appendFe
        # empty database
        assert db.getFe(keyB0) == None
        on = db.appendFe(preB, digU)
        assert on == 0
        assert db.getFe(keyB0) == digU
        assert db.delFe(keyB0) == True
        assert db.getFe(keyB0) == None

        # earlier pre in database only
        assert db.putFe(keyA0, val=digA) == True
        on = db.appendFe(preB, digU)
        assert on == 0
        assert db.getFe(keyB0) == digU
        assert db.delFe(keyB0) == True
        assert db.getFe(keyB0) == None

        # earlier and later pre in db but not same pre
        assert db.getFe(keyA0) == digA
        assert db.putFe(keyC0, val=digC) == True
        on = db.appendFe(preB, digU)
        assert on == 0
        assert db.getFe(keyB0) == digU
        assert db.delFe(keyB0) == True
        assert db.getFe(keyB0) == None

        # later pre only
        assert db.delFe(keyA0) == True
        assert db.getFe(keyA0) == None
        assert db.getFe(keyC0) == digC
        on = db.appendFe(preB, digU)
        assert on == 0
        assert db.getFe(keyB0) == digU

        # earlier pre and later pre and earlier entry for same pre
        assert db.putFe(keyA0, val=digA) == True
        on = db.appendFe(preB, digV)
        assert on == 1
        assert db.getFe(keyB1) == digV

        # earlier entry for same pre but only same pre
        assert db.delFe(keyA0) == True
        assert db.getFe(keyA0) == None
        assert db.delFe(keyC0) == True
        assert db.getFe(keyC0) == None
        # another value for preB
        on = db.appendFe(preB, digW)
        assert on == 2
        assert db.getFe(keyB2) == digW
        # yet another value for preB
        on = db.appendFe(preB, digX)
        assert on == 3
        assert db.getFe(keyB3) == digX
        # yet another value for preB
        on = db.appendFe(preB, digY )
        assert on == 4
        assert db.getFe(keyB4) == digY

        # replay preB events in database
        items = [item for item in db.getFelItemPreIter(preB)]
        assert items == [(0, digU), (1, digV), (2, digW), (3, digX), (4, digY)]

        # resume replay preB events at on = 3
        items = [item for item in db.getFelItemPreIter(preB, fn=3)]
        assert items == [(3, digX), (4, digY)]

        # resume replay preB events at on = 5
        items = [item for item in db.getFelItemPreIter(preB, fn=5)]
        assert items == []

        # replay all events in database with pre events before and after
        assert db.putFe(keyA0, val=digA) == True
        assert db.putFe(keyC0, val=digC) == True

        # Test .dtss datetime stamps
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

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

        # Test .aess authorizing event source seal couples
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # test .aess sub db methods
        ssnu1 = b'0AAAAAAAAAAAAAAAAAAAAAAB'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        ssnu2 = b'0AAAAAAAAAAAAAAAAAAAAAAC'
        sdig2 = b'EBYYJRCCpAGO7WjjsLhtHVR37Pawv67kveIFUPvt38x0'
        val1 = ssnu1 + sdig1
        val2 = ssnu2 + sdig2

        assert db.getAes(key) == None
        assert db.delAes(key) == False
        assert db.putAes(key, val1) == True
        assert db.getAes(key) == val1
        assert db.putAes(key, val2) == False
        assert db.getAes(key) == val1
        assert db.setAes(key, val2) == True
        assert db.getAes(key) == val2
        assert db.delAes(key) == True
        assert db.getAes(key) == None

        # test .sigs sub db methods
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

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
        assert db.getSigs(key) == [sig1b,  sig0b]  # lex order
        assert db.delSigs(key) == True
        assert db.putSigs(key, vals=[sig1b, sig0b]) == True
        assert db.getSigs(key) == [sig1b, sig0b]  # lex order
        assert db.delSigs(key) == True
        assert db.getSigs(key) == []

        # test .wiss sub db methods (witness indexed sigs)
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        assert db.getWigs(key) == []
        assert db.cntWigs(key) == 0
        assert db.delWigs(key) == False

        # dup vals are lexocographic
        assert db.putWigs(key, vals=[b"z", b"m", b"x", b"a"]) == True
        assert db.getWigs(key) == [b'a', b'm', b'x', b'z']
        assert db.cntWigs(key) == 4
        assert db.putWigs(key, vals=[b'a']) == True   # duplicate but True
        assert db.getWigs(key) == [b'a', b'm', b'x', b'z']
        assert db.addWig(key, b'a') == False   # duplicate
        assert db.addWig(key, b'b') == True
        assert db.getWigs(key) == [b'a', b'b', b'm', b'x', b'z']
        assert [val for val in db.getWigsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
        assert db.delWigs(key) == True
        assert db.getWigs(key) == []
        vals = [b"z", b"m", b"x", b"a"]
        assert db.putWigs(key, vals) == True
        for val in vals:
            assert db.delWigs(key, val) == True
        assert db.getWigs(key) == []
        assert db.putWigs(key, vals) == True
        for val in db.getWigsIter(key):
            assert db.delWigs(key, val) == True
        assert db.getWigs(key) == []

        assert db.putWigs(key, vals=[sig0b]) == True
        assert db.getWigs(key) == [sig0b]
        assert db.putWigs(key, vals=[sig1b]) == True
        assert db.getWigs(key) == [sig1b, sig0b]  # lex order
        assert db.putWigs(key, vals=[sig1b, sig0b]) == True
        assert db.getWigs(key) == [sig1b, sig0b]  # lex order
        assert db.delWigs(key) == True
        assert db.getWigs(key) == []

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

        # Unverified Receipt Escrows
        # test .ures insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getUres(key) == []
        assert db.getUreLast(key) == None
        assert db.cntUres(key) == 0
        assert db.delUres(key) == False
        assert db.putUres(key, vals) == True
        assert db.getUres(key) == vals  # preserved insertion order
        assert db.cntUres(key) == len(vals) == 4
        assert db.getUreLast(key) == vals[-1]
        assert db.putUres(key, vals=[b'a']) == False   # duplicate
        assert db.getUres(key) == vals  #  no change
        assert db.addUre(key, b'a') == False   # duplicate
        assert db.addUre(key, b'b') == True
        assert db.getUres(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in db.getUresIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delUres(key) == True
        assert db.getUres(key) == []

        # Setup Tests for getUreItemsNext and getUreItemsNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putUres(key=aKey, vals=aVals)
        assert db.putUres(key=bKey, vals=bVals)
        assert db.putUres(key=cKey, vals=cVals)
        assert db.putUres(key=dKey, vals=dVals)

        # Test getUreItemsNext( key=b"")
        # aVals
        items = db.getUreItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getUreItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getUreItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getUreItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getUreItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getUreItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getUreItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getUreItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getUreItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getUreItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getUreItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getUreItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getUreItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delUre(ikey, val) == True

        # bVals
        items = [item for item in db.getUreItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delUre(ikey, val) == True

        # cVals
        items = [item for item in db.getUreItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delUre(ikey, val) == True

        # dVals
        items = [item for item in db.getUreItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delUre(ikey, val) == True

        # none
        items = [item for item in db.getUreItemsNext(key=ikey)]
        assert items == []  # empty
        assert not items

        # Validator (transferable) Receipts
        # test .vrcs sub db methods dgkey
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")


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


        # Unverified Validator (transferable) Receipt Escrows
        # test .vres insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getVres(key) == []
        assert db.getVreLast(key) == None
        assert db.cntVres(key) == 0
        assert db.delVres(key) == False
        assert db.putVres(key, vals) == True
        assert db.getVres(key) == vals  # preserved insertion order
        assert db.cntVres(key) == len(vals) == 4
        assert db.getVreLast(key) == vals[-1]
        assert db.putVres(key, vals=[b'a']) == False   # duplicate
        assert db.getVres(key) == vals  #  no change
        assert db.addVre(key, b'a') == False   # duplicate
        assert db.addVre(key, b'b') == True
        assert db.getVres(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in db.getVresIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delVres(key) == True
        assert db.getVres(key) == []

        # Setup Tests for getPsesNext and getPsesNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putVres(key=aKey, vals=aVals)
        assert db.putVres(key=bKey, vals=bVals)
        assert db.putVres(key=cKey, vals=cVals)
        assert db.putVres(key=dKey, vals=dVals)

        # Test getVreItemsNext( key=b"")
        # aVals
        items = db.getVreItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getVreItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getVreItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getVreItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getVreItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getVreItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getVreItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getVreItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getVreItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getVreItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getVreItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getVreItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getVreItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delVre(ikey, val) == True

        # bVals
        items = [item for item in db.getVreItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delVre(ikey, val) == True

        # cVals
        items = [item for item in db.getVreItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delVre(ikey, val) == True

        # dVals
        items = [item for item in db.getVreItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delVre(ikey, val) == True

        # none
        items = [item for item in db.getVreItemsNext(key=ikey)]
        assert items == []  # empty
        assert not items


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

        # Partially Signed Escrow Events
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

        # Test .pdes partial delegated escrow seal source couples
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # test .pdes sub db methods
        ssnu1 = b'0AAAAAAAAAAAAAAAAAAAAAAB'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        ssnu2 = b'0AAAAAAAAAAAAAAAAAAAAAAC'
        sdig2 = b'EBYYJRCCpAGO7WjjsLhtHVR37Pawv67kveIFUPvt38x0'
        val1 = ssnu1 + sdig1
        val2 = ssnu2 + sdig2

        assert db.getPde(key) == None
        assert db.delPde(key) == False
        assert db.putPde(key, val1) == True
        assert db.getPde(key) == val1
        assert db.putPde(key, val2) == False
        assert db.getPde(key) == val1
        assert db.setPde(key, val2) == True
        assert db.getPde(key) == val2
        assert db.delPde(key) == True
        assert db.getPde(key) == None

        # Partially Witnessed Escrow Events
        # test .pwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getPwes(key) == []
        assert db.getPweLast(key) == None
        assert db.cntPwes(key) == 0
        assert db.delPwes(key) == False
        assert db.putPwes(key, vals) == True
        assert db.getPwes(key) == vals  # preserved insertion order
        assert db.cntPwes(key) == len(vals) == 4
        assert db.getPweLast(key) == vals[-1]
        assert db.putPwes(key, vals=[b'a']) == False   # duplicate
        assert db.getPwes(key) == vals  #  no change
        assert db.addPwe(key, b'a') == False   # duplicate
        assert db.addPwe(key, b'b') == True
        assert db.getPwes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in db.getPwesIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delPwes(key) == True
        assert db.getPwes(key) == []

        # Setup Tests for getPwesNext and getPwesNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putPwes(key=aKey, vals=aVals)
        assert db.putPwes(key=bKey, vals=bVals)
        assert db.putPwes(key=cKey, vals=cVals)
        assert db.putPwes(key=dKey, vals=dVals)

        # Test getPweItemsNext( key=b"")
        # aVals
        items = db.getPweItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getPweItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getPweItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getPweItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getPweItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getPweItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getPweItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getPweItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getPweItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getPweItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getPweItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getPweItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getPweItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delPwe(ikey, val) == True

        # bVals
        items = [item for item in db.getPweItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delPwe(ikey, val) == True

        # cVals
        items = [item for item in db.getPweItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delPwe(ikey, val) == True

        # dVals
        items = [item for item in db.getPweItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delPwe(ikey, val) == True

        # none
        items = [item for item in db.getPweItemsNext(key=ikey)]
        assert items == []  # empty
        assert not items

        # Unverified Witness Receipt Escrows
        # test .uwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.getUwes(key) == []
        assert db.getUweLast(key) == None
        assert db.cntUwes(key) == 0
        assert db.delUwes(key) == False
        assert db.putUwes(key, vals) == True
        assert db.getUwes(key) == vals  # preserved insertion order
        assert db.cntUwes(key) == len(vals) == 4
        assert db.getUweLast(key) == vals[-1]
        assert db.putUwes(key, vals=[b'a']) == False   # duplicate
        assert db.getUwes(key) == vals  #  no change
        assert db.addUwe(key, b'a') == False   # duplicate
        assert db.addUwe(key, b'b') == True
        assert db.getUwes(key) == [b"z", b"m", b"x", b"a", b"b"]
        assert [val for val in db.getUwesIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        assert db.delUwes(key) == True
        assert db.getUwes(key) == []

        # Setup Tests for getUweItemsNext and getUweItemsNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putUwes(key=aKey, vals=aVals)
        assert db.putUwes(key=bKey, vals=bVals)
        assert db.putUwes(key=cKey, vals=cVals)
        assert db.putUwes(key=dKey, vals=dVals)

        # Test getUweItemsNext( key=b"")
        # aVals
        items = db.getUweItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getUweItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getUweItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getUweItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getUweItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getUweItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getUweItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getUweItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getUweItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getUweItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getUweItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getUweItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getUweItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delUwe(ikey, val) == True

        # bVals
        items = [item for item in db.getUweItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delUwe(ikey, val) == True

        # cVals
        items = [item for item in db.getUweItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delUwe(ikey, val) == True

        # dVals
        items = [item for item in db.getUweItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delUwe(ikey, val) == True

        # none
        items = [item for item in db.getUweItemsNext(key=ikey)]
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

        # Setup Tests for getLdeItemsNext and getLdeItemsNextIter
        aKey = snKey(pre=b'A', sn=1)
        aVals = [b"z", b"m", b"x"]
        bKey = snKey(pre=b'A', sn=2)
        bVals = [b"o", b"r", b"z"]
        cKey = snKey(pre=b'A', sn=4)
        cVals = [b"h", b"n"]
        dKey = snKey(pre=b'A', sn=7)
        dVals = [b"k", b"b"]

        assert db.putLdes(key=aKey, vals=aVals)
        assert db.putLdes(key=bKey, vals=bVals)
        assert db.putLdes(key=cKey, vals=cVals)
        assert db.putLdes(key=dKey, vals=dVals)

        # Test getOoeItemsNext( key=b"")
        # aVals
        items = db.getLdeItemsNext()  #  get first key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getLdeItemsNext(key=aKey, skip=False)  #  get aKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = db.getLdeItemsNext(key=aKey)  #  get bKey  in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = db.getLdeItemsNext(key=b'', skip=False)  #  get frist key in database
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = db.getLdeItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals

        # cVals
        items = db.getLdeItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals

        # dVals
        items = db.getLdeItemsNext(key=ikey)
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals

        # none
        items = db.getLdeItemsNext(key=ikey)
        assert items == []  # empty
        assert not items

        # Test getLdeItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.getLdeItemsNextIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getLdeItemsNextIter(key=aKey, skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        items = [item for item in db.getLdeItemsNextIter(key=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for  key, val in items]
        assert vals == bVals

        items = [item for item in db.getLdeItemsNextIter(key=b'', skip=False)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals
        for key, val in items:
            assert db.delLde(ikey, val) == True

        # bVals
        items = [item for item in db.getLdeItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.delLde(ikey, val) == True

        # cVals
        items = [item for item in db.getLdeItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.delLde(ikey, val) == True

        # dVals
        items = [item for item in db.getLdeItemsNextIter(key=ikey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.delLde(ikey, val) == True

        # none
        items = [item for item in db.getLdeItemsNext(key=ikey)]
        assert items == []  # empty
        assert not items



    assert not os.path.exists(db.path)

    """ End Test """


def test_clean_baser():
    """
    Test Baser db clean clone method
    """
    name = "nat"
    # with basing.openDB(name="nat") as natDB, keeping.openKS(name="nat") as natKS:
    with habbing.openHby(name=name, salt=coring.Salter(raw=b'0123456789abcdef').qb64) as hby:  # default is temp=True
        natHab = hby.makeHab(name=name, isith='2', icount=3)  # default Hab
        # setup Nat's habitat using default salt multisig already incepts
        #natHab = habbing.Habitat(name='nat', ks=natKS, db=natDB,
                                #isith='2', icount=3, temp=True)
        assert natHab.name == 'nat'
        assert natHab.ks == hby.ks # natKS
        assert natHab.db == hby.db # natDB
        assert natHab.kever.prefixer.transferable
        assert natHab.db.opened
        assert natHab.pre in natHab.kevers
        assert natHab.pre in natHab.prefixes
        assert natHab.db.path.endswith("/keri/db/nat")
        path = natHab.db.path  # save for later

        # Create series of events for Nat
        natHab.interact()
        natHab.rotate()
        natHab.interact()
        natHab.interact()
        natHab.interact()
        natHab.interact()

        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        natsaid = 'EA3QbTpV15MvLSXHSedm4lRYdQhmYXqXafsD4i75B_yo'
        assert natHab.kever.serder.said == natsaid
        ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
        assert ldig == natHab.kever.serder.saidb
        serder = serdering.SerderKERI(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
        assert serder.said == natHab.kever.serder.said
        state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
        assert state.s == '6'
        assert state.f == '6'
        assert natHab.db.env.stat()['entries'] <= 96 #68

        # test reopenDB with reuse  (because temp)
        with basing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
            assert ldig == natHab.kever.serder.saidb
            serder = serdering.SerderKERI(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
            assert serder.said == natHab.kever.serder.said
            assert natHab.db.env.stat()['entries'] <= 96 #68

            # verify name pre kom in db
            data = natHab.db.habs.get(keys=natHab.name)
            assert data.hid == natHab.pre

            # add garbage event to corrupt database
            badsrdr = eventing.rotate(pre=natHab.pre,
                                      keys=[verfer.qb64 for verfer in natHab.kever.verfers],
                                      dig=natHab.kever.serder.said,
                                      sn=natHab.kever.sn+1,
                                      isith='2',
                                      ndigs=[diger.qb64 for diger in natHab.kever.ndigers])
            fn, dts = natHab.kever.logEvent(serder=badsrdr, first=True)
            natHab.db.states.pin(keys=natHab.pre,
                                 val=datify(KeyStateRecord,
                                            natHab.kever.state()))

            assert fn == 7
            # verify garbage event in database
            assert natHab.db.getEvt(dbing.dgKey(natHab.pre, badsrdr.said))
            assert natHab.db.getFe(dbing.fnKey(natHab.pre, 7))


        # test openDB copy db with clean
        with basing.openDB(name=natHab.db.name,
                          temp=natHab.db.temp,
                          headDirPath=natHab.db.headDirPath,
                          perm=natHab.db.perm,
                          clean=True) as copy:
            assert copy.path.endswith("/keri/clean/db/nat")
            assert copy.env.stat()['entries'] >= 18

        # Nat's kever and the signatory kever
        assert len(natHab.kevers) == 2
        # now clean it
        natHab.db.clean()

        # see if kevers dict is back to what it was before
        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.said == natsaid
        assert natHab.pre in natHab.prefixes
        assert natHab.pre in natHab.kevers

        # see if database is back where it belongs
        with basing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
            assert ldig == natHab.kever.serder.saidb
            serder = serdering.SerderKERI(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
            assert serder.said == natHab.kever.serder.said
            assert natHab.db.env.stat()['entries'] >= 18

            # confirm bad event missing from database
            assert not natHab.db.getEvt(dbing.dgKey(natHab.pre, badsrdr.said))
            assert not natHab.db.getFe(dbing.fnKey(natHab.pre, 7))
            state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
            assert state.s == '6'
            assert state.f == '6'

            # verify name pre kom in db
            data = natHab.db.habs.get(keys=natHab.name)
            assert data.hid == natHab.pre


    assert not os.path.exists(hby.ks.path)
    assert not os.path.exists(hby.db.path)

    """End Test"""


def test_fetchkeldel():
    """
    Test fetching full KEL and full DEL from Baser
    """
    # Test using context manager
    preb = 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
    digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
    sn = 3
    vs = versify(kind=Serials.json, size=20)
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

        vals = [bytes(val) for val in db.getKelLastIter(preb)]
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
    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = Salter(raw=raw)

    #  create coe's signers
    signers = salter.signers(count=8, path='db', temp=True)


    with openDB() as db:
        # Event 0  Inception Transferable (nxt digest not empty) 2 0f 3 multisig
        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        count = len(keys)
        nxtkeys = [signers[3].verfer.qb64b, signers[4].verfer.qb64b, signers[5].verfer.qb64b]
        sith = "2"
        code = MtrDex.Blake3_256  # Blake3 digest of incepting data
        serder = incept(keys=keys,
                        code=code,
                        isith=sith,
                        ndigs=[coring.Diger(ser=key).qb64 for key in nxtkeys])


        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i) for i in range(count)]
        # create key event verifier state
        kever = Kever(serder=serder, sigers=sigers, db=db)

        # Event 1 Rotation Transferable
        keys = [signers[3].verfer.qb64, signers[4].verfer.qb64, signers[5].verfer.qb64]
        nxtkeys = [signers[5].verfer.qb64b, signers[6].verfer.qb64b, signers[7].verfer.qb64b]
        serder = rotate(pre=kever.prefixer.qb64,
                        keys=keys,
                        isith=sith,
                        dig=kever.serder.said,
                        ndigs=[coring.Diger(ser=key).qb64 for key in nxtkeys],
                        sn=1)

        # sign serialization
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)


        # Event 2 Interaction
        serder = interact(pre=kever.prefixer.qb64,
                          dig=kever.serder.said,
                          sn=2)

        # sign serialization  (keys don't change for signing)
        sigers = [signers[i].sign(serder.raw, index=i-count) for i in range(count, count+count)]
        # update key event verifier state
        kever.update(serder=serder, sigers=sigers)

    assert not os.path.exists(db.path)

    """ End Test """


def test_rawrecord():
    """
    Test RawRecord dataclass
    """
    @dataclass
    class TestRecord(basing.RawRecord):
        x: str = ""
        y: int = 0

    record = TestRecord()

    assert isinstance(record, TestRecord)
    assert isinstance(record, basing.RawRecord)

    assert "x" in record
    assert "y" in record

    assert record.x == ''
    assert record.y == 0

    record = TestRecord(x="hi", y=3)

    assert record.x == 'hi'
    assert record.y == 3

    assert record._asdict() == {'x': 'hi', 'y': 3}
    assert record._asjson() == b'{"x":"hi","y":3}'
    assert record._ascbor() == b'\xa2axbhiay\x03'
    assert record._asmgpk() == b'\x82\xa1x\xa2hi\xa1y\x03'

    """End Test"""



def test_keystaterecord():
    """
    Test KeyStateRecord dataclass
    """
    seer = basing.StateEERecord()
    assert seer.s == '0'
    assert seer.d == ''
    assert seer._asdict() == {'s': '0', 'd': '', 'br': [], 'ba': []}

    ksr = basing.KeyStateRecord()

    assert isinstance(ksr, basing.KeyStateRecord)
    assert ksr.i == ''

    ksn = asdict(ksr)  # key state notice dict
    assert ksn == {'vn': [],
                    'i': '',
                    's': '0',
                    'p': '',
                    'd': '',
                    'f': '0',
                    'dt': '',
                    'et': '',
                    'kt': '0',
                    'k': [],
                    'nt': '0',
                    'n': [],
                    'bt': '0',
                    'b': [],
                    'c': [],
                    'ee': {'s': '0', 'd': '', 'br': [], 'ba': []},
                    'di': ''}

    assert ksr._asdict() == ksn
    assert ksr._asjson() == (b'{"vn":[],"i":"","s":"0","p":"","d":"","f":"0","dt":"","et":"","kt":"0","k":['
                        b'],"nt":"0","n":[],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"","br":[],"ba":['
                        b']},"di":""}')

    assert ksr._ascbor() == (b'\xb1bvn\x80ai`asa0ap`ad`afa0bdt`bet`bkta0ak\x80bnta0an\x80bbta0ab\x80ac'
                             b'\x80bee\xa4asa0ad`bbr\x80bba\x80bdi`')

    assert ksr._asmgpk() == (b'\xde\x00\x11\xa2vn\x90\xa1i\xa0\xa1s\xa10\xa1p\xa0\xa1d\xa0\xa1f\xa10'
                            b'\xa2dt\xa0\xa2et\xa0\xa2kt\xa10\xa1k\x90\xa2nt\xa10\xa1n\x90\xa2bt\xa1'
                            b'0\xa1b\x90\xa1c\x90\xa2ee\x84\xa1s\xa10\xa1d\xa0\xa2br\x90\xa2ba\x90\xa2d'
                            b'i\xa0')


    assert str(ksr) == repr(ksr) == ("KeyStateRecord(vn=[], i='', s='0', p='', d='', f='0', dt='', et='', kt='0', "
                                     "k=[], nt='0', n=[], bt='0', b=[], c=[], ee=StateEERecord(s='0', d='', br=[], "
                                     "ba=[]), di='')")

    dksn = dictify(ksr)
    assert dksn == ksn

    dksr = datify(basing.KeyStateRecord, ksn)
    assert dksr == ksr

    nksr = basing.KeyStateRecord._fromdict(ksn)
    assert nksr == ksr
    assert nksr._asdict() == ksn


    """End Test"""

def test_eventsourcerecord():
    """
    Test EventSourceRecord dataclass
    """
    record = basing.EventSourceRecord()  # default local is True
    assert isinstance(record, basing.EventSourceRecord)
    assert record.local is True
    assert record.local
    assert "local" in record  # asdict means in is against the keys (labels)
    assert (asdict(record)) == {'local': True}

    record.local = False
    assert record.local is False
    assert not record.local
    assert (asdict(record)) == {'local': False}

    record = basing.EventSourceRecord(local=False)
    assert isinstance(record, basing.EventSourceRecord)
    assert record.local is False
    assert not record.local
    assert "local" in record  # asdict means in is against the keys (labels)
    assert (asdict(record)) == {'local': False}

    record = basing.EventSourceRecord(local=None)
    assert isinstance(record, basing.EventSourceRecord)
    assert record.local is None
    assert not record.local
    assert "local" in record  # asdict means in is against the keys (labels)
    assert (asdict(record)) == {'local': None}



    """End Test"""


def test_dbdict():
    """
    Test custom dbdict subclass of dict
    """
    dbd = basing.dbdict(a=1, b=2, c=3)  # init in memory so never acesses db
    assert dbd.db == None
    assert 'a' in dbd
    assert 'b' in dbd
    assert 'c' in dbd
    assert [(k, v) for k, v in dbd.items()] == [('a', 1), ('b', 2), ('c', 3)]
    assert list(dbd.keys()) == ['a', 'b', 'c']
    assert list(dbd.values()) == [1, 2, 3]

    assert dbd.get('a') == 1
    assert dbd['a'] == 1

    dbd.clear()
    assert not dbd

    with basing.openDB(name="nat") as db:
        dbd.db = db
        assert dbd.db == db
        assert not dbd

        dbd['a'] = 1
        dbd['b'] = 2
        dbd['c'] = 3
        assert dbd
        assert dbd.get('a') == 1
        assert dbd['a'] == 1

        assert [(k, v) for k, v in dbd.items()] == [('a', 1), ('b', 2), ('c', 3)]

        assert 'd' not in dbd
        assert dbd.get('d') is None

        with pytest.raises(KeyError):
            x = dbd['d']

        dbd.clear()
        pre = 'DApYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'

        assert pre not in dbd
        dig = 'EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30'
        serder = eventing.interact(pre=pre,
                                   dig=dig,
                                   sn=4)

        eevt = eventing.StateEstEvent(s='3',
                                      d=dig,
                                      br=[],
                                      ba=[])

        state = eventing.state(pre=pre,
                               sn=4,
                               pig=dig,
                               dig=serder.said,
                               fn=4,
                               eilk=coring.Ilks.ixn,
                               keys=[pre],
                               eevt=eevt,
                               )

        dgkey = eventing.dgKey(pre=pre, dig=serder.said)
        db.putEvt(key=dgkey, val=serder.raw)
        assert db.getEvt(key=dgkey) is not None

        db.states.pin(keys=pre, val=state)  # put state in database
        dbstate = db.states.get(keys=pre)
        assert dbstate is not None
        assert dbstate == state

        kever = eventing.Kever(state=state, db=db)
        assert kever.state() == state

        dkever = dbd[pre]  # read through cache works here
        dstate = dkever.state()
        assert  dstate == state

        del dbd[pre]  # not in dbd memory
        assert pre in dbd  #  read through cache works
        dkever = dbd[pre]
        dstate = dkever.state()
        assert  dstate == state

        db.states.rem(keys=pre)
        assert pre in dbd  # still in memory
        del dbd[pre]
        assert pre not in dbd  # not in memory or db so read through cache misses


    assert not os.path.exists(db.path)





    """End Test"""


def test_baserdoer():
    """
    Test BaserDoer


    """
    db0 = basing.Baser(name='test0', temp=True, reopen=False)
    assert db0.opened == False
    assert db0.path == None
    assert db0.env == None

    dbDoer0 = basing.BaserDoer(baser=db0)
    assert dbDoer0.baser == db0
    assert dbDoer0.baser.opened == False

    db1 = basing.Baser(name='test1', temp=True, reopen=False)
    assert db1.opened == False
    assert db1.path == None
    assert db1.env == None

    dbDoer1 = basing.BaserDoer(baser=db1)
    assert dbDoer1.baser == db1
    assert dbDoer1.baser.opened == False

    limit = 0.25
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock)

    doers = [dbDoer0, dbDoer1]

    doist.doers = doers
    doist.enter()
    assert len(doist.deeds) == 2
    assert [val[1] for val in doist.deeds] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer.baser.opened
        assert "_test/keri/db/test" in doer.baser.path

    doist.recur()
    assert doist.tyme == 0.03125  # on next cycle
    assert len(doist.deeds) == 2
    for doer in doers:
        assert doer.baser.opened == True

    for dog, retyme, index in doist.deeds:
        dog.close()

    for doer in doers:
        assert doer.baser.opened == False
        assert doer.baser.env == None
        assert not os.path.exists(doer.baser.path)

    # start over
    doist.tyme = 0.0
    doist.do(doers=doers)
    assert doist.tyme == limit
    for doer in doers:
        assert doer.baser.opened is False
        assert doer.baser.env is None
        assert not os.path.exists(doer.baser.path)

    """End Test"""


def test_group_members():
    with openMultiSig(prefix="test") as ((hby1, ghab1), (hby2, ghab2), (hby3, ghab3)):
        keys = hby1.db.signingMembers(pre=ghab1.pre)
        assert len(keys) == 3
        assert ghab1.mhab.pre in keys
        assert ghab2.mhab.pre in keys
        assert ghab3.mhab.pre in keys

        keys = hby2.db.signingMembers(pre=ghab1.pre)
        assert len(keys) == 3
        assert ghab1.mhab.pre in keys
        assert ghab2.mhab.pre in keys
        assert ghab3.mhab.pre in keys

        keys = hby3.db.signingMembers(pre=ghab1.pre)
        assert len(keys) == 3
        assert ghab1.mhab.pre in keys
        assert ghab2.mhab.pre in keys
        assert ghab3.mhab.pre in keys

        keys = hby1.db.rotationMembers(pre=ghab1.pre)
        assert len(keys) == 3
        assert ghab1.mhab.pre in keys
        assert ghab2.mhab.pre in keys
        assert ghab3.mhab.pre in keys

        keys = hby2.db.rotationMembers(pre=ghab1.pre)
        assert len(keys) == 3
        assert ghab1.mhab.pre in keys
        assert ghab2.mhab.pre in keys
        assert ghab3.mhab.pre in keys

        keys = hby3.db.rotationMembers(pre=ghab1.pre)
        assert len(keys) == 3
        assert ghab1.mhab.pre in keys
        assert ghab2.mhab.pre in keys
        assert ghab3.mhab.pre in keys


    """End Test"""


if __name__ == "__main__":
    test_baser()
    test_clean_baser()
    test_fetchkeldel()
    test_usebaser()
    test_dbdict()
    test_baserdoer()
