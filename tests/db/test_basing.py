# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import json
import os
import platform
import tempfile
from dataclasses import dataclass, asdict
import subprocess

import pytest

import lmdb
from hio.base import doing
from keri import core
from keri.app import habbing
from keri.core import coring, eventing, serdering, signing, indexing
from keri.core.coring import Kinds, versify, Seqner, Diger, Number, NumDex
from keri.core.eventing import incept, rotate, interact, Kever
from keri.core.serdering import Serder
from keri.core.signing import Signer
from keri.db import basing
from keri.db import dbing
from keri.db import subing
from keri.db.basing import openDB, Baser, KeyStateRecord, OobiRecord
from keri.db.dbing import (dgKey, onKey, snKey)
from keri.db.dbing import openLMDB
from keri.help.helping import datify, dictify
# this breaks when running as __main__ better to do a custom import call to
# walk the directory tree and import explicity rather than depend on it
# being a known package. Works with pytest because pytest contructs a path
# its test runner and imports the tests explicity
from tests.app import openMultiSig  # this breaks when running as __main__


def test_baser():
    """
    Test Baser class
    """
    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()
    baser = Baser(reopen=True)  # default is to not reopen
    assert isinstance(baser, Baser)
    assert baser.name == "main"
    assert baser.temp == False
    assert isinstance(baser.env, lmdb.Environment)
    assert baser.path.endswith(os.path.join("keri", "db", "main"))
    assert baser.env.path() == baser.path
    assert os.path.exists(baser.path)

    assert isinstance(baser.evts, subing.SerderSuber)
    assert isinstance(baser.sigs, subing.CesrIoSetSuber)
    assert isinstance(baser.dtss, subing.CesrSuber)
    assert isinstance(baser.rcts, subing.CatCesrIoSetSuber)
    assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
    assert isinstance(baser.kels, subing.OnIoDupSuber)
    assert isinstance(baser.ooes, subing.IoDupSuber)
    assert isinstance(baser.pses, subing.IoDupSuber)
    assert isinstance(baser.dels, subing.OnIoDupSuber)
    assert isinstance(baser.ldes, subing.OnIoDupSuber)

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
    assert baser.path.endswith(os.path.join("keri", "db", "main"))
    assert baser.env.path() == baser.path
    assert os.path.exists(baser.path)

    assert isinstance(baser.evts, subing.SerderSuber)
    assert isinstance(baser.sigs, subing.CesrIoSetSuber)
    assert isinstance(baser.dtss, subing.CesrSuber)
    assert isinstance(baser.rcts, subing.CatCesrIoSetSuber)
    assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
    assert isinstance(baser.ooes, subing.IoDupSuber)
    assert isinstance(baser.pses, subing.IoDupSuber)
    assert isinstance(baser.dels, subing.OnIoDupSuber)
    assert isinstance(baser.ldes, subing.OnIoDupSuber)

    baser.close(clear=True)
    assert not os.path.exists(baser.path)
    assert not baser.opened



    # Test using context manager
    with openLMDB(cls=Baser) as baser:
        assert isinstance(baser, Baser)
        assert baser.name == "test"
        assert baser.temp == True
        assert isinstance(baser.env, lmdb.Environment)
        assert baser.path.startswith(os.path.join(tempDirPath, "keri_lmdb_"))
        assert baser.path.endswith(os.path.join("_test", "keri", "db", "test"))
        assert baser.env.path() == baser.path
        assert os.path.exists(baser.path)

        assert isinstance(baser.evts, subing.SerderSuber)
        assert isinstance(baser.sigs, subing.CesrIoSetSuber)
        assert isinstance(baser.dtss, subing.CesrSuber)
        assert isinstance(baser.rcts, subing.CatCesrIoSetSuber)
        assert isinstance(baser.ures, subing.CatCesrIoSetSuber)
        assert isinstance(baser.ooes, subing.IoDupSuber)
        assert isinstance(baser.pses, subing.IoDupSuber)
        assert isinstance(baser.dels, subing.OnIoDupSuber)
        assert isinstance(baser.ldes, subing.OnIoDupSuber)


    assert not os.path.exists(baser.path)

    preb = 'DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8")
    digb = 'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8")
    sn = 3
    # Build minimal rot event (KERI field names: i, s, d, p, t, etc.)
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



    with openDB() as db:
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        #  test .evts sub db methods (verify=False for minimal test event)
        sked = serdering.SerderKERI(raw=skedb, verify=False)
        assert db.evts.get(keys=(preb, digb)) is None
        assert db.evts.rem(keys=(preb, digb)) is False
        assert db.evts.put(keys=(preb, digb), val=sked) is True
        assert db.evts.get(keys=(preb, digb)).raw == skedb
        assert db.evts.put(keys=(preb, digb), val=sked) is False
        assert db.evts.pin(keys=(preb, digb), val=sked) is True
        assert db.evts.get(keys=(preb, digb)).raw == skedb
        assert db.evts.rem(keys=(preb, digb)) is True
        assert db.evts.get(keys=(preb, digb)) is None

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

        digA = b'EA73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'
        digU = b'EB73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw'
        digV = b'EC4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY'
        digW = b'EDAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w'
        digX = b'EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o'
        digY = b'EFrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk'

        digC = b'EG5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w'

        assert db.fels.getOn(keys=preA, on=0) is None
        assert db.fels.remOn(keys=preA, on=0) == False
        assert db.fels.putOn(keys=preA, on=0, val=digA) == True
        assert db.fels.getOn(keys=preA, on=0) == digA.decode("utf-8")
        assert db.fels.putOn(keys=preA, on=0, val=digA) == False
        assert db.fels.pinOn(keys=preA, on=0, val=digA) == True
        assert db.fels.getOn(keys=preA, on=0) == digA.decode("utf-8")
        assert db.fels.remOn(keys=preA, on=0) == True
        assert db.fels.getOn(keys=preA, on=0) is None

        # test appendOn
        # empty database
        assert db.fels.getOn(keys=preB, on=0) is None
        on = db.fels.appendOn(keys=preB, val=digU)
        assert on == 0
        assert db.fels.getOn(keys=preB, on=0) == digU.decode("utf-8")
        assert db.fels.remOn(keys=preB, on=0) == True
        assert db.fels.getOn(keys=preB, on=0) is None

        # earlier pre in database only
        assert db.fels.putOn(keys=preA, on=0, val=digA) == True
        on = db.fels.appendOn(keys=preB, val=digU)
        assert on == 0
        assert db.fels.getOn(keys=preB, on=0) == digU.decode("utf-8")
        assert db.fels.remOn(keys=preB, on=0) == True
        assert db.fels.getOn(keys=preB, on=0) is None

        # earlier and later pre in db but not same pre
        assert db.fels.getOn(keys=preA, on=0) == digA.decode("utf-8")
        assert db.fels.putOn(keys=preC, on=0, val=digC) == True
        on = db.fels.appendOn(keys=preB, val=digU)
        assert on == 0
        assert db.fels.getOn(keys=preB, on=0) == digU.decode("utf-8")
        assert db.fels.remOn(keys=preB, on=0) == True
        assert db.fels.getOn(keys=preB, on=0) is None

        # later pre only
        assert db.fels.remOn(keys=preA, on=0) == True
        assert db.fels.getOn(keys=preA, on=0) is None
        assert db.fels.getOn(keys=preC, on=0) == digC.decode("utf-8")
        on = db.fels.appendOn(keys=preB, val=digU)
        assert on == 0
        assert db.fels.getOn(keys=preB, on=0) == digU.decode("utf-8")

        # earlier pre and later pre and earlier entry for same pre
        assert db.fels.putOn(keys=preA, on=0, val=digA) == True
        on = db.fels.appendOn(keys=preB, val=digV)
        assert on == 1
        assert db.fels.getOn(keys=preB, on=1) == digV.decode("utf-8")

        # earlier entry for same pre but only same pre
        assert db.fels.remOn(keys=preA, on=0) == True
        assert db.fels.getOn(keys=preA, on=0) is None
        assert db.fels.remOn(keys=preC, on=0) == True
        assert db.fels.getOn(keys=preC, on=0) is None
        # another value for preB
        on = db.fels.appendOn(keys=preB, val=digW)
        assert on == 2
        assert db.fels.getOn(keys=preB, on=2) == digW.decode("utf-8")
        # yet another value for preB
        on = db.fels.appendOn(keys=preB, val=digX)
        assert on == 3
        assert db.fels.getOn(keys=preB, on=3) == digX.decode("utf-8")
        # yet another value for preB
        on = db.fels.appendOn(keys=preB, val=digY)
        assert on == 4
        assert db.fels.getOn(keys=preB, on=4) == digY.decode("utf-8")

        # replay preB events in database
        _pre = lambda k: k[0].encode() if isinstance(k[0], str) else k[0]
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getOnItemIterAll(keys=preB)]
        assert items == [(preB, 0, digU.decode("utf-8")), (preB, 1, digV.decode("utf-8")), (preB, 2, digW.decode("utf-8")), (preB, 3, digX.decode("utf-8")), (preB, 4, digY.decode("utf-8"))]

        # resume replay preB events at on = 3
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getOnItemIterAll(keys=preB, on=3)]
        assert items == [(preB, 3, digX.decode("utf-8")), (preB, 4, digY.decode("utf-8"))]

        # resume replay preB events at on = 5
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getOnItemIterAll(keys=preB, on=5)]
        assert items == []

        # replay all events in database with pre events before and after
        assert db.fels.putOn(keys=preA, on=0, val=digA) == True
        assert db.fels.putOn(keys=preC, on=0, val=digC) == True

        # replay all pres in first-seen order (keys=b'', on=0)
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getOnItemIterAll(keys=b'', on=0)]
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

        assert db.dtss.get(keys=key) is None
        assert db.dtss.rem(keys=key) == False
        assert db.dtss.put(keys=key, val=dater1) == True
        result = db.dtss.get(keys=key)
        assert isinstance(result, coring.Dater)
        assert result.dts == dater1.dts
        assert db.dtss.put(keys=key, val=dater2) == False  # idempotent
        result = db.dtss.get(keys=key)
        assert result.dts == dater1.dts  # still original
        assert db.dtss.pin(keys=key, val=dater2) == True  # overwrites
        result = db.dtss.get(keys=key)
        assert result.dts == dater2.dts
        assert db.dtss.rem(keys=key) == True
        assert db.dtss.get(keys=key) is None

        # Test .aess authorizing event source seal couples
        # test .aess sub db methods
        ssnu1 = b'0AAAAAAAAAAAAAAAAAAAAAAB'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        ssnu2 = b'0AAAAAAAAAAAAAAAAAAAAAAC'
        sdig2 = b'EBYYJRCCpAGO7WjjsLhtHVR37Pawv67kveIFUPvt38x0'
        number1 = coring.Number(qb64b=ssnu1)
        saider1 = coring.Diger(qb64b=sdig1)
        number2 = coring.Number(qb64b=ssnu2)
        saider2 = coring.Diger(qb64b=sdig2)
        val1 = (number1, saider1)
        val2 = (number2, saider2)

        assert db.aess.get(keys=(preb, digb)) == None
        assert db.aess.rem(keys=(preb, digb)) == False
        assert db.aess.put(keys=(preb, digb), val=val1) == True
        result = db.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber1, rsaider1 = result
        assert rnumber1.qb64b == number1.qb64b
        assert rsaider1.qb64b == saider1.qb64b
        assert db.aess.put(keys=(preb, digb), val=val2) == False
        result = db.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber1, rsaider1 = result
        assert rnumber1.qb64b == number1.qb64b
        assert rsaider1.qb64b == saider1.qb64b
        assert db.aess.pin(keys=(preb, digb), val=val2) == True
        result = db.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber2, rsaider2 = result
        assert rnumber2.qb64b == number2.qb64b
        assert rsaider2.qb64b == saider2.qb64b
        assert db.aess.rem(keys=(preb, digb)) == True
        assert db.aess.get(keys=(preb, digb)) == None

        # test .sigs sub db methods
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        assert db.sigs.get(keys=key) == []
        assert db.sigs.cnt(keys=key) == 0
        assert db.sigs.rem(keys=key) == False

        # Create valid test signatures
        signer0 = signing.Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = signing.Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)

        siger0 = indexing.Siger(raw=cigar0.raw, code=indexing.IdrDex.Ed25519_Sig, index=0)
        siger1 = indexing.Siger(raw=cigar1.raw, code=indexing.IdrDex.Ed25519_Sig, index=1)

        assert db.sigs.put(keys=key, vals=[siger0]) == True
        assert [s.qb64b for s in db.sigs.get(keys=key)] == [siger0.qb64b]
        assert db.sigs.cnt(keys=key) == 1
        assert db.sigs.put(keys=key, vals=[siger0]) == False  # duplicate, idempotent
        assert [s.qb64b for s in db.sigs.get(keys=key)] == [siger0.qb64b]
        assert db.sigs.add(keys=key, val=siger1) == True
        assert [s.qb64b for s in db.sigs.get(keys=key)] == [siger0.qb64b, siger1.qb64b]
        assert [val.qb64b for val in db.sigs.getIter(keys=key)] == [siger0.qb64b, siger1.qb64b]
        assert db.sigs.rem(keys=key) == True
        assert db.sigs.get(keys=key) == []
        assert db.sigs.put(keys=key, vals=[siger0, siger1]) == True
        for val in [siger0, siger1]:
            assert db.sigs.rem(keys=key, val=val) == True
        assert db.sigs.get(keys=key) == []
        assert db.sigs.put(keys=key, vals=[siger0, siger1]) == True
        for val in db.sigs.getIter(keys=key):
            assert db.sigs.rem(keys=key, val=val) == True
        assert db.sigs.get(keys=key) == []
        
        assert db.sigs.put(keys=key, vals=[siger0]) == True
        assert [s.qb64b for s in db.sigs.get(keys=key)] == [siger0.qb64b]
        assert db.sigs.put(keys=key, vals=[siger1]) == True
        assert [s.qb64b for s in db.sigs.get(keys=key)] == [siger0.qb64b, siger1.qb64b]
        assert db.sigs.rem(keys=key) == True
        assert db.sigs.put(keys=key, vals=[siger1, siger0]) == True
        assert [s.qb64b for s in db.sigs.get(keys=key)] == [siger1.qb64b, siger0.qb64b]
        assert db.sigs.rem(keys=key) == True
        assert db.sigs.get(keys=key) == []
        assert db.sigs.put(keys=key, vals=[siger0, siger1]) == True

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
        assert db.wigs.get(keys=key) == []
        assert db.wigs.cnt(keys=key) == 0
        assert db.wigs.rem(keys=key) == False

        # Test pin with multiple values
        assert db.wigs.pin(keys=key, vals=[wig1, wig0]) == True
        result = db.wigs.get(keys=key)
        assert len(result) == 2
        # Just verify both are present (don't test exact order)
        result_bytes = set(w.qb64b for w in result)
        assert result_bytes == {wig0.qb64b, wig1.qb64b}
        assert db.wigs.cnt(keys=key) == 2

        # Test pin overwrites
        assert db.wigs.pin(keys=key, vals=[wig0]) == True
        result = db.wigs.get(keys=key)
        assert len(result) == 1
        assert result[0].qb64b == wig0.qb64b

        # Reset to both
        assert db.wigs.pin(keys=key, vals=[wig1, wig0]) == True
        assert db.wigs.cnt(keys=key) == 2

        # Test add, duplicate should return False
        assert db.wigs.add(keys=key, val=wig0) == False  # duplicate
        assert db.wigs.add(keys=key, val=wig1) == False  # duplicate
        assert db.wigs.cnt(keys=key) == 2

        # Test getIter, returns just values
        result_list = list(db.wigs.getIter(keys=key))
        assert len(result_list) == 2
        assert set(w.qb64b for w in result_list) == {wig0.qb64b, wig1.qb64b}

        # Test remove all
        assert db.wigs.rem(keys=key) == True
        assert db.wigs.get(keys=key) == []
        assert db.wigs.cnt(keys=key) == 0

        # Test individual removal by value
        vals = [wig0, wig1]
        assert db.wigs.pin(keys=key, vals=vals) == True
        for val in vals:
            assert db.wigs.rem(keys=key, val=val) == True
        assert db.wigs.get(keys=key) == []

        # Test removal while iterating
        assert db.wigs.pin(keys=key, vals=vals) == True
        for val in db.wigs.getIter(keys=key):
            assert db.wigs.rem(keys=key, val=val) == True
        assert db.wigs.get(keys=key) == []

        # Test sequence with individual pins
        assert db.wigs.pin(keys=key, vals=[wig0]) == True
        result = db.wigs.get(keys=key)
        assert len(result) == 1
        assert result[0].qb64b == wig0.qb64b

        assert db.wigs.pin(keys=key, vals=[wig1]) == True
        result = db.wigs.get(keys=key)
        assert len(result) == 1
        assert result[0].qb64b == wig1.qb64b

        assert db.wigs.pin(keys=key, vals=[wig1, wig0]) == True
        result = db.wigs.get(keys=key)
        assert len(result) == 2
        assert set(w.qb64b for w in result) == {wig0.qb64b, wig1.qb64b}

        assert db.wigs.rem(keys=key) == True
        assert db.wigs.get(keys=key) == []

        # test .rcts
   
        # Create test prefixes and cigars
        wit0 = coring.Prefixer(qb64=wit0b.decode('utf-8'))  # Convert from qb64 string
        wit1 = coring.Prefixer(qb64=wit1b.decode('utf-8'))
        
        # Create cigars (non-indexed signatures)
        cigar0 = coring.Cigar(qb64=wsig0b.decode('utf-8'))
        cigar1 = coring.Cigar(qb64=wsig1b.decode('utf-8'))
        
        # Test with CESR tuples (insertion order)
        assert db.rcts.put(key, vals=[(wit0, cigar0), (wit1, cigar1)]) == True
        result = db.rcts.get(key)
        assert len(result) == 2
        # Check insertion order: wit0 inserted first, wit1 second
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        assert result[1][0].qb64 == wit1.qb64
        assert result[1][1].qb64 == cigar1.qb64
        
        # Test duplicate (should not add)
        assert db.rcts.put(key, vals=[(wit0, cigar0)]) == False
        result = db.rcts.get(key)
        assert len(result) == 2
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        assert result[1][0].qb64 == wit1.qb64
        assert result[1][1].qb64 == cigar1.qb64
        
        # Test adding new item
        wit2 = coring.Prefixer(qb64='BNewTestPrefix000000000000000000000000000000')
        cigar2 = coring.Cigar(qb64='BNewTestSignature00000000000000000000000000000000000000000000000000000000000000000000000')
        assert db.rcts.add(key, (wit2, cigar2)) == True
        result = db.rcts.get(key)
        assert len(result) == 3
        # Insertion order: wit0, wit1, wit2
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        assert result[1][0].qb64 == wit1.qb64
        assert result[1][1].qb64 == cigar1.qb64
        assert result[2][0].qb64 == wit2.qb64
        assert result[2][1].qb64 == cigar2.qb64
        
        # Test duplicate add returns False
        assert db.rcts.add(key, (wit0, cigar0)) == False
        
        # Test getIter maintains insertion order
        iter_result = [val for val in db.rcts.getIter(key)]
        assert len(iter_result) == 3
        assert iter_result[0][0].qb64 == wit0.qb64
        assert iter_result[0][1].qb64 == cigar0.qb64
        assert iter_result[1][0].qb64 == wit1.qb64
        assert iter_result[1][1].qb64 == cigar1.qb64
        assert iter_result[2][0].qb64 == wit2.qb64
        assert iter_result[2][1].qb64 == cigar2.qb64
        
        # Test removal
        assert db.rcts.rem(key) == True
        assert db.rcts.get(key) == []
        
        # Test insertion order preserved when inserting in different order
        vals = [(wit1, cigar1), (wit0, cigar0)]
        assert db.rcts.put(key, vals) == True
        result = db.rcts.get(key)
        assert len(result) == 2
        # Should maintain insertion order: wit1 first, wit0 second
        assert result[0][0].qb64 == wit1.qb64
        assert result[0][1].qb64 == cigar1.qb64
        assert result[1][0].qb64 == wit0.qb64
        assert result[1][1].qb64 == cigar0.qb64
        
        # Test individual removal
        assert db.rcts.rem(key, (wit1, cigar1)) == True
        result = db.rcts.get(key)
        assert len(result) == 1
        assert result[0][0].qb64 == wit0.qb64
        assert result[0][1].qb64 == cigar0.qb64
        
        assert db.rcts.rem(key) == True
        assert db.rcts.get(key) == []

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

        assert db.ures.get(key) == []
        assert db.ures.getLast(keys=key) is None
        assert db.ures.cnt(key) == 0
        assert db.ures.rem(key) == False

        assert db.ures.put(keys=key, vals=cesrVals) == True
        stored = db.ures.get(key)
        assert len(stored) == 1
        diger_s, pre_s, cigar_s = stored[0]
        assert diger_s.qb64 == diger0.qb64
        assert pre_s.qb64 == pre0.qb64
        assert cigar_s.qb64b == cigar0.qb64b

        result = db.ures.getLast(keys=key)
        assert result is not None
        diger_l, pre_l, cigar_l = result
        assert diger_l.qb64 == diger0.qb64
        assert pre_l.qb64 == pre0.qb64
        assert cigar_l.qb64b == cigar0.qb64b

        assert db.ures.put(keys=key, vals=[(diger0, pre0, cigar0)]) == False  # duplicate, no change
        result = db.ures.get(key)
        assert len(result) == 1
        d, p, c = result[0]
        assert d.qb64 == diger0.qb64
        assert p.qb64 == pre0.qb64
        assert c.qb64b == cigar0.qb64b

        assert db.ures.add(key, (diger0, pre0, cigar0)) == False   # duplicate
        assert db.ures.add(key, (diger1, pre1, cigar1)) == True

        result = db.ures.get(key)
        assert len(result) == 2
        d0, p0, c0 = result[0]
        assert d0.qb64 == diger0.qb64
        assert p0.qb64 == pre0.qb64
        assert c0.qb64b == cigar0.qb64b
        d1, p1, c1 = result[1]
        assert d1.qb64 == diger1.qb64
        assert p1.qb64 == pre1.qb64
        assert c1.qb64b == cigar1.qb64b

        result_iter = [val for val in db.ures.getIter(key)]
        assert len(result_iter) == 2
        d0, p0, c0 = result_iter[0]
        assert d0.qb64 == diger0.qb64
        assert p0.qb64 == pre0.qb64
        assert c0.qb64b == cigar0.qb64b
        d1, p1, c1 = result_iter[1]
        assert d1.qb64 == diger1.qb64
        assert p1.qb64 == pre1.qb64
        assert c1.qb64b == cigar1.qb64b

        assert db.ures.rem(key) == True
        assert db.ures.get(key) == []

        # Setup multi-key tests for getItemIter
        aKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=1).qb64)
        aVals = [(diger0, pre0, cigar0), (diger1, pre1, cigar1), (diger2, pre2, cigar2)]
        bKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=2).qb64)
        bVals = [(diger1, pre1, cigar1), (diger2, pre2, cigar2), (diger3, pre3, cigar3)]
        cKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=4).qb64)
        cVals = [(diger2, pre2, cigar2), (diger3, pre3, cigar3)]
        dKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", coring.Seqner(sn=7).qb64)
        dVals = [(diger3, pre3, cigar3), (diger4, pre4, cigar4)]

        assert db.ures.put(keys=aKey, vals=aVals)
        assert db.ures.put(keys=bKey, vals=bVals)
        assert db.ures.put(keys=cKey, vals=cVals)
        assert db.ures.put(keys=dKey, vals=dVals)

        # Test getItemIter with no key
        items = [(keys, val) for keys, val in db.ures.getItemIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == aKey
        # Verify total count
        assert len(items) == len(aVals) + len(bVals) + len(cVals) + len(dVals)

        # aVals — iterate at aKey only
        items = [(keys, val) for keys, val in db.ures.getItemIter(keys=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == aKey
        assert len(items) == len(aVals)  # only aKey items

        # bVals — iterate at bKey, remove each
        items = [(keys, val) for keys, val in db.ures.getItemIter(keys=bKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == bKey
        assert len(items) == len(bVals)  # only bKey items
        for ikeys, val in db.ures.getItemIter(keys=bKey):
            assert db.ures.rem(bKey, val) == True

        # cVals — iterate at cKey, remove each
        items = [(keys, val) for keys, val in db.ures.getItemIter(keys=cKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == cKey
        assert len(items) == len(cVals)  # only cKey items
        for ikeys, val in db.ures.getItemIter(keys=cKey):
            assert db.ures.rem(cKey, val) == True

        # dVals — iterate at dKey, remove each
        items = [(keys, val) for keys, val in db.ures.getItemIter(keys=dKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == dKey
        assert len(items) == len(dVals)
        for ikeys, val in db.ures.getItemIter(keys=dKey):
            assert db.ures.rem(dKey, val) == True

        # aVals should still be intact, others removed
        result_a = db.ures.get(aKey)
        assert len(result_a) == len(aVals)
        for i, (d_expected, p_expected, c_expected) in enumerate(aVals):
            d, p, c = result_a[i]
            assert d.qb64 == d_expected.qb64
            assert p.qb64 == p_expected.qb64
            assert c.qb64b == c_expected.qb64b

        assert db.ures.get(bKey) == []
        assert db.ures.get(cKey) == []
        assert db.ures.get(dKey) == []

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
        
        assert db.vrcs.get(key) == []
        assert db.vrcs.cnt(key) == 0
        assert db.vrcs.rem(key) == False

        assert db.vrcs.put(key, cesrVal) is True

        stored = db.vrcs.get(key)
        assert len(stored) == 1
        sp1, sn1, se1, ss1 = stored[0]

        assert sp1.qb64 == p1.qb64
        assert sn1.num == n1.num
        assert se1.qb64 == e1.qb64
        assert ss1.raw == s1.raw

        assert db.vrcs.rem(key) == True

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
        assert db.vrcs.get(key) == []
        assert db.vrcs.cnt(key) == 0

        # Insert multiple typed tuples
        assert db.vrcs.put(key, vals) is True

        # Insertion order is preserved
        stored = db.vrcs.get(key)
        assert len(stored) == len(vals)
        for (sp, sn, se, ss), (ep, en, ee, es) in zip(stored, vals):
            assert sp.qb64 == ep.qb64
            assert sn.num == en.num
            assert se.qb64 == ee.qb64
            assert ss.raw == es.raw

        assert db.vrcs.cnt(key) == 4

        # Duplicate insertion should not add new entries
        assert db.vrcs.put(key, [quadA]) == False
        assert db.vrcs.put(key, [quadB]) == False   # quadB already present → no change
        assert db.vrcs.put(key, [quadD]) == False   # quadD already present → no change
        assert db.vrcs.put(key, [quadC]) == False   # quadC already present → no change

        # Iteration returns the same tuples in insertion order
        itered = list(db.vrcs.getIter(key))
        for (sp, sn, se, ss), (ep, en, ee, es) in zip(itered, vals):
            assert sp.qb64 == ep.qb64
            assert sn.num == en.num
            assert se.qb64 == ee.qb64
            assert ss.raw == es.raw

        # Remove individual tuples
        for quad in vals:
            assert db.vrcs.rem(key, quad) == True

        assert db.vrcs.get(key) == []
        assert db.vrcs.cnt(key) == 0


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
        
        assert db.vres.get(key) == []
        assert db.vres.getLast(keys=key) == None
        assert db.vres.cnt(key) == 0
        assert db.vres.rem(key) == False

        assert db.vres.put(keys=key, vals=cesrVal) is True

        stored = db.vres.get(key)
        assert len(stored) == 1
        sd1, sp1, sn1, se1, ss1 = stored[0]

        assert sd1.qb64 == d1.qb64
        assert sp1.qb64 == p1.qb64
        assert sn1.num == n1.num
        assert se1.qb64 == e1.qb64
        assert ss1.raw == s1.raw


        # assert db.putVres(key, vals) == True
        # assert db.vres.get(key) == vals  # preserved insertion order
        # assert db.cntVres(key) == len(vals) == 4
        # assert db.getVreLast(key) == vals[-1]
        # assert db.putVres(key, vals=[b'a']) == False   # duplicate
        # assert db.vres.get(key) == vals  #  no change
        # assert db.addVre(key, b'a') == False   # duplicate
        # assert db.addVre(key, b'b') == True
        # assert db.vres.get(key) == [b"z", b"m", b"x", b"a", b"b"]
        # assert [val for val in db.vres.getIter(key)] == [b"z", b"m", b"x", b"a", b"b"]
        # assert db.delVres(key) == True
        # assert db.vres.get(key) == []

        # # Setup Tests for getVresNext and getVresNextIter
        # aKey = snKey(pre=b'A', sn=1)
        # aVals = [b"z", b"m", b"x"]
        # bKey = snKey(pre=b'A', sn=2)
        # bVals = [b"o", b"r", b"z"]
        # cKey = snKey(pre=b'A', sn=4)
        # cVals = [b"h", b"n"]
        # dKey = snKey(pre=b'A', sn=7)
        # dVals = [b"k", b"b"]

        # assert db.putVres(key=aKey, vals=aVals)
        # assert db.putVres(key=bKey, vals=bVals)
        # assert db.putVres(key=cKey, vals=cVals)
        # assert db.putVres(key=dKey, vals=dVals)


        # # Test getVreItemsNextIter(key=b"")
        # #  get dups at first key in database
        # # aVals
        # items = [item for item in db.getVreItemIter()]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == aKey
        # vals = [val for  key, val in items]
        # assert vals == aVals + bVals + cVals + dVals

        # items = [item for item in db.getVreItemIter(key=aKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == aKey
        # vals = [val for  key, val in items]
        # assert vals == aVals

        # # bVals
        # items = [item for item in db.getVreItemIter(key=bKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == bKey
        # vals = [val for key, val in items]
        # assert vals == bVals
        # for key, val in items:
        #     assert db.delVre(ikey, val) == True

        # # cVals
        # items = [item for item in db.getVreItemIter(key=cKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == cKey
        # vals = [val for key, val in items]
        # assert vals == cVals
        # for key, val in items:
        #     assert db.delVre(ikey, val) == True

        # # dVals
        # items = [item for item in db.getVreItemIter(key=dKey)]
        # assert items  # not empty
        # ikey = items[0][0]
        # assert  ikey == dKey
        # vals = [val for key, val in items]
        # assert vals == dVals
        # for key, val in items:
        #     assert db.delVre(ikey, val) == True



        # test .kels insertion order dup methods.  dup vals are insertion order
        key = snKey(preb, 0)
        vals = [b"z", b"m", b"x", b"a"]
        deserializedVals = ["z", "m", "x", "a"]

        assert db.kels.getOn(keys=key) == []
        assert db.kels.getOnLast(keys=key)== None
        assert db.kels.cntOnAll(keys=key) == 0
        assert db.kels.remOn(key) == False
        assert db.kels.putOn(keys=key, vals=vals) == True
        assert db.kels.getOn(keys=key) == deserializedVals  # preserved insertion order
        assert db.kels.cntOnAll(keys=key) == len(vals) == 4
        assert db.kels.getOnLast(keys=key) == deserializedVals[-1]
        assert db.kels.putOn(keys=key, vals=[b'a']) == False   # duplicate
        assert db.kels.getOn(keys=key) == deserializedVals  #  no change
        assert db.kels.addOn(keys=key, val=b'a') == False   # duplicate
        assert db.kels.addOn(keys=key, val=b'b') == True
        assert db.kels.getOn(keys=key) == deserializedVals + ['b']
        assert db.kels.remOn(key) == True
        assert db.kels.getOn(keys=key) == []

        # Partially Signed Escrow Events
        # test .pses insertion order dup methods.  dup vals are insertion order
        pre = b'A'
        sn = 0
        key = snKey(pre, sn)
        vals = [b"z", b"m", b"x", b"a"]
        deserialized_vals = [db.pses._des(val) for val in vals] # deserialize for assertion
        
        # core insertion
        assert db.pses.getOn(keys=key) == []
        assert db.pses.getOnLast(keys=pre, on=sn) == None
        assert db.pses.cntOnAll(keys=key) == 0
        assert db.pses.remOn(keys=key) == False
        
        # initial insertion
        assert db.pses.putOn(keys=key, vals=vals) == True
        assert db.pses.getOn(keys=key) == deserialized_vals    #sanity check

        # duplication insertion behavior
        assert db.pses.putOn(keys=key, vals=[b'd', b'k']) == True
        assert db.pses.putOn(keys=key, vals=[b'd']) == False  # duplicate
        assert db.pses.putOn(keys=key, vals=[b'k']) == False  # duplicate
        assert db.pses.putOn(keys=key, vals=[b'k',b'd',b'k']) == False   
        assert db.pses.addOn(keys=key, val=b'd') == False  # duplicate
        assert db.pses.addOn(keys=key, val=b'k') == False  
        assert db.pses.getOn(keys=key) == deserialized_vals + ['d', 'k']

        # mixed insertion behavior
        assert db.pses.putOn(keys=key, vals=[b'k', b'c']) == True  # True because 'c' is new
        assert db.pses.getOn(keys=key) == deserialized_vals + ['d', 'k', 'c']

        # insertion after deletion
        assert db.pses.remOn(keys=key, val=b'd') == True   # remove a specific val
        assert db.pses.getOn(keys=key) == deserialized_vals + ['k', 'c']   # d removed
        assert db.pses.addOn(keys=key, val=b'd') == True   # add d back
        assert db.pses.getOn(keys=key) == deserialized_vals + ['k', 'c', 'd']   # d added back

        # empty insertion
        assert db.pses.putOn(keys=key, vals=[]) == False # no vals to add
        assert db.pses.getOn(keys=key) == deserialized_vals + ['k', 'c', 'd'] # no change

        assert db.pses.addOn(keys=key, val=b'') == True  # empty val is allowed
        assert db.pses.getOn(key) == deserialized_vals + ['k', 'c', 'd',''] # empty val added
        
        # clean up
        assert db.pses.remOn(keys=key) == True
        assert db.pses.getOn(keys=key) == []

        # different key types insertion
        assert db.pses.putOn(keys='B', vals=[b'1', b'2']) == True   # key as str
        assert db.pses.addOn(keys='B', val=b'3') == True   
        assert db.pses.putOn(keys=['B'], vals=b'4') == True  # key as list
        assert db.pses.addOn(keys=['B'], val=b'5') == True 
        assert db.pses.putOn(keys=("B"), vals=b'6') == True # key as tuple
        assert db.pses.addOn(keys=("B"), val=b'7') == True
        assert db.pses.putOn(keys=memoryview(b'B'), vals=b'8') == True  # key as memoryview
        assert db.pses.addOn(keys=memoryview(b'B'), val=b'9') == True
        assert db.pses.getOn(keys=b'B') == ['1', '2', '3', '4', '5', '6', '7', '8', '9']

        # clean up
        assert db.pses.remOn(keys=b'B') == True
        assert db.pses.getOn(keys=b'B') == []

        # edge case: add different types of vals
        assert db.pses.putOn(keys=key, vals=[b'a','a']) == True
        assert db.pses.getOn(keys=key) == ['a', 'a'] # both value added because _ser produces different bytes

        assert db.pses.remOn(keys=key) == True
        assert db.pses.getOn(keys=key) == []


        # test .pses retrieval behavior methods
        # insertion order preserved
        assert db.pses.putOn(keys=pre, on=sn, vals=vals) == True
        assert db.pses.getOn(keys=pre, on=sn) == deserialized_vals
        assert list(db.pses.getOnIter(keys=pre, on=sn)) == deserialized_vals
        assert db.pses.getOnLast(keys=pre, on=sn) == deserialized_vals[-1]
        assert db.pses.cntOnAll(keys=pre, on=sn) == len(vals) == 4

        # retrieval on empty list
        assert db.pses.getOn(keys=b'X') == []  
        assert list(db.pses.getIter(b'X')) == []
        assert db.pses.getOnLast(keys=b'X') == None
        assert db.pses.cntOnAll(keys=b'X') == 0
        items = db.pses.getItemIter(keys=b'X')
        assert list(items) == []

        # getItemIter retrieval of (key, val) pairs in lexicographic key order
        items = list(db.pses.getOnItemIterAll())
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]  # Insertion order preserved for vals
        assert db.pses.putOn(keys=[b'B', b'C'], vals=[b'1', b'2', b'3']) == True
        items = list(db.pses.getItemIter(keys=key))
        assert all(k[0] == 'A' for k, v in items)

        # retrieval with different key types, A is the key used above where key = b'A'
        assert db.pses.getOn(keys=b'A') == deserialized_vals  # key as bytes
        assert db.pses.getOn(keys='A') == deserialized_vals  # key as str
        assert db.pses.getOn(keys=['A']) == deserialized_vals  # key as list
        assert db.pses.getOn(keys=('A',)) == deserialized_vals  # key as tuple
        assert db.pses.getOn(keys=memoryview(b'A')) == deserialized_vals  # key as memoryview

        # retrieval afterd deletion of specific val
        assert db.pses.getOnLast(keys=pre, on=sn) == 'a'              # vals = [b"z", b"m", b"x", b"a"]
        assert db.pses.remOn(keys=pre, on=sn, val=b'a') == True           # vals = [b"z", b"m", b"x"]
        assert db.pses.getOn(keys=pre, on=sn) == ['z', 'm', 'x']
        assert db.pses.getOnLast(keys=pre, on=sn) == 'x'
        assert db.pses.cntOnAll(keys=pre, on=sn) == 3
        
        # clean up
        assert db.pses.remOn(keys=pre, on=sn) == True  


        # test .pses pinning behavior method
        # start clean
        assert db.pses.getOn(keys=key) == []
        assert db.pses.putOn(keys=key, vals=vals) == True
        assert db.pses.getOn(keys=key) == deserialized_vals
        assert db.pses.pinOn(keys=key, vals=[b'a', b'b', b'c']) == True
        assert db.pses.getOn(keys=key) == ['a', 'b', 'c']  # exact overwrite

        # pin with a different list
        assert db.pses.pinOn(keys=key, vals=[b'x', b'y']) == True
        assert db.pses.getOn(keys=key) == ['x', 'y']  # previous values removed

        # pin with empty list (valid use case)
        assert db.pses.pinOn(keys=key, vals=[]) == False  # nothing to pin
        assert db.pses.getOn(keys=key) == []  # key cleared

        # pin after normal insertion
        assert db.pses.putOn(keys=key, vals=[b'1', b'2']) == True
        assert db.pses.getOn(keys=key) == ['1', '2']
        assert db.pses.pinOn(keys=key, vals=[b'Q']) == True
        assert db.pses.getOn(keys=key) == ['Q']  # overwritten

        # edge case: pin with mixed types
        assert db.pses.pinOn(keys=key, vals=[b'A', 'A', memoryview(b'A')]) == True
        assert db.pses.getOn(keys=key) == ['A', 'A', 'A']  

        # cleanup
        assert db.pses.remOn(keys=key) == True
        assert db.pses.getOn(keys=key) == []


        # test .pses deletion methods
        # delete specific val
        assert db.pses.putOn(keys=key, vals=vals) == True   
        assert db.pses.remOn(keys=key, val=b'm') == True
        assert db.pses.getOn(keys=key) == ['z', 'x', 'a']

        # delete non existing val
        assert db.pses.remOn(keys=key, val=b'y') == False
        assert db.pses.getOn(keys=key) == ['z', 'x', 'a']

        # delete all vals
        assert db.pses.remOn(keys=key) == True
        assert db.pses.getOn(keys=key) == []
        assert db.pses.cntOnAll(keys=key) == 0 # all vals deleted

        # delete non existing key
        assert db.pses.remOn(keys=b'X') == False

        # insert other keys to ensure only specified key is deleted
        assert db.pses.putOn(keys=b'A', vals=[b'1']) == True
        assert db.pses.putOn(keys=b'B', vals=[b'2']) == True
        assert db.pses.remOn(keys=b'A') == True
        assert db.pses.getOn(keys=b'B') == ['2']

        # clean up all entries
        for k, sn, v in list(db.pses.getOnItemIterAll()):
            assert db.pses.remOn(keys=k, on=sn, val=v) == True

        # Setup Tests for getPsesNext and getPsesNextIter
        pre = b"A"
        aSn = 1
        aKey = snKey(pre=pre, sn=aSn)
        aVals = [b"z", b"m", b"x"]
        bSn = 2
        bKey = snKey(pre=pre, sn=bSn)
        bVals = [b"o", b"r", b"z"]
        cSn = 4
        cKey = snKey(pre=pre, sn=cSn)
        cVals = [b"h", b"n"]
        dSn = 7
        dKey = snKey(pre=pre, sn=dSn)
        dVals = [b"k", b"b"]

        assert db.pses.putOn(keys=pre, on=1, vals=aVals)
        assert db.pses.putOn(keys=pre, on=2, vals=bVals)
        assert db.pses.putOn(keys=pre, on=4, vals=cVals)
        assert db.pses.putOn(keys=pre, on=7, vals=dVals)



        # Test getPseItemsNextIter(key=b"")
        # vals are in bytes, assertion is done after serializing

        # aVals
        items = [item for item in db.pses.getItemIter()]
        assert items  # not empty
        ikey = db.pses._tokey(items[0][0])
        assert  ikey == aKey
        vals = [db.pses._ser(val) for key, val in items]
        assert vals ==  aVals + bVals + cVals + dVals

        items = [item for item in db.pses.getItemIter(keys=aKey)]
        assert items  # not empty
        ikey = db.pses._tokey(items[0][0])
        assert  ikey == aKey
        vals = [db.pses._ser(val) for key, val in items]
        assert vals == aVals

        # bVals
        items = [item for item in db.pses.getItemIter(keys=bKey)]
        assert items  # not empty
        ikey = db.pses._tokey(items[0][0])
        assert  ikey == bKey
        vals = [db.pses._ser(val) for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.pses.remOn(keys=pre, on=bSn, val=val) == True

        # cVals
        items = [item for item in db.pses.getItemIter(keys=cKey)]
        assert items  # not empty
        ikey = db.pses._tokey(items[0][0])
        assert  ikey == cKey
        vals = [db.pses._ser(val) for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.pses.remOn(keys=pre, on=cSn, val=val) == True

        # dVals
        items = [item for item in db.pses.getItemIter(keys=dKey)]
        assert items  # not empty
        ikey = db.pses._tokey(items[0][0])
        assert  ikey == dKey
        vals = [db.pses._ser(val) for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.pses.remOn(keys=pre, on=dSn, val=val) == True

        # clean up all entries
        for k, sn, v in list(db.pses.getOnItemIterAll()):
            db.pses.remOn(keys=k)

        # test _tokey and _tokeys
        t = db.ooes._tokey(aKey)
        assert db.ooes._tokeys(t) == ("A", "00000000000000000000000000000001")


        # Test .udes partial delegated escrow seal source couples
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # test .pdes SerderIoSetSuber methods
        assert isinstance(db.pdes, subing.OnIoDupSuber)


        # test .udes CatCesrSuber sub db methods
        assert isinstance(db.udes, subing.CatCesrSuber)
        assert db.udes.klas == (core.Number, coring.Diger)

        ssnu1 = b'0AAAAAAAAAAAAAAAAAAAAAAB'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        ssnu2 = b'0AAAAAAAAAAAAAAAAAAAAAAC'
        sdig2 = b'EBYYJRCCpAGO7WjjsLhtHVR37Pawv67kveIFUPvt38x0'
        val1 = ssnu1 + sdig1
        num1 = coring.Number(qb64b=ssnu1)
        val2 = ssnu2 + sdig2
        num2 = coring.Number(qb64b=ssnu2)
        diger1 = coring.Diger(qb64b=sdig1)
        diger2 = coring.Diger(qb64b=sdig2)

        assert db.udes.get(keys=key) == None
        assert db.udes.rem(keys=key) == False
        assert db.udes.put(keys=key, val=(num1, diger1)) == True
        num, diger = db.udes.get(keys=key)
        assert num.qb64b + diger.qb64b == val1
        assert db.udes.put(keys=key, val=(num2, diger2)) == False
        num, diger = db.udes.get(keys=key)
        assert num.qb64b + diger.qb64b == val1
        assert db.udes.pin(keys=key, val=(num2, diger2)) == True
        num, diger = db.udes.get(keys=key)
        assert num.qb64b + diger.qb64b == val2
        assert db.udes.rem(keys=key) == True
        assert db.udes.get(keys=key) == None




        # Partially Witnessed Escrow Events
        # test .pwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        deserializedVals = ["z", "m", "x", "a"]

        assert db.pwes.getOn(key) == []
        assert db.pwes.cntOnAll(key) == 0
        assert db.pwes.remOn(key) == False
        assert db.pwes.putOn(keys=key, vals=vals) == True
        assert db.pwes.getOn(key) == deserializedVals  # preserved insertion order
        assert db.pwes.cntOnAll(key) == len(vals) == 4
        assert list(db.pwes.getOnLastIter(key))[0] == deserializedVals[-1]
        assert db.pwes.putOn(key, vals=[b'a']) == False   # duplicate
        assert db.pwes.getOn(key) == deserializedVals  #  no change
        assert db.pwes.addOn(keys=key, val=b"a") == False   # duplicate
        assert db.pwes.addOn(keys=key, val=b"b") == True
        assert db.pwes.getOn(key) == deserializedVals + ['b']
        assert [val for val in db.pwes.getOnIter(key)] == deserializedVals + ['b']
        assert db.pwes.remOn(key) == True
        assert db.pwes.getOn(key) == []

        # Setup Tests for getPwesNext and getPwesNextIter
        pre = b"A"
        aSn = 1
        aKey = snKey(pre=pre, sn=aSn)
        aVals = [b"z", b"m", b"x"]
        bSn = 2
        bKey = snKey(pre=pre, sn=bSn)
        bVals = [b"o", b"r", b"z"]
        cSn = 4
        cKey = snKey(pre=pre, sn=cSn)
        cVals = [b"h", b"n"]
        dSn = 7
        dKey = snKey(pre=pre, sn=dSn)
        dVals = [b"k", b"b"]

        assert db.pwes.putOn(keys=pre, on=aSn, vals=aVals)
        assert db.pwes.putOn(keys=pre, on=bSn, vals=bVals)
        assert db.pwes.putOn(keys=pre, on=cSn, vals=cVals)
        assert db.pwes.putOn(keys=pre, on=dSn, vals=dVals)


        # Test getOnItemIterAll()
        #  get dups at first key in database
        # aVals
        items = [item for item in db.pwes.getOnItemIterAll()]
        assert items  # not empty
        ikey = snKey(items[0][0][0], items[0][1])
        assert  ikey == aKey
        vals = [db.pwes._ser(val) for  key, sn, val in items]
        assert vals ==  aVals + bVals + cVals + dVals

        items = [item for item in db.pwes.getItemIter(keys=aKey)]
        assert items  # not empty
        ikey = db.pwes._tokey(items[0][0])
        assert  ikey == aKey
        vals = [db.pwes._ser(val) for  key, val in items]
        assert vals == aVals

        # bVals
        items = [item for item in db.pwes.getItemIter(keys=bKey)]
        assert items  # not empty
        ikey = db.pwes._tokey(items[0][0])
        assert  ikey == bKey
        vals = [db.pwes._ser(val) for  key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.pwes.remOn(keys=pre, on=bSn, val=val) == True

        # cVals
        items = [item for item in db.pwes.getItemIter(keys=cKey)]
        assert items  # not empty
        ikey = db.pwes._tokey(items[0][0])
        assert  ikey == cKey
        vals = [db.pwes._ser(val) for  key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.pwes.remOn(keys=pre, on=cSn, val=val) == True

        # dVals
        items = [item for item in db.pwes.getItemIter(keys=dKey)]
        assert items  # not empty
        ikey = db.pwes._tokey(items[0][0])
        assert  ikey == dKey
        vals = [db.pwes._ser(val) for  key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.pwes.remOn(keys=pre, on=dSn, val=val) == True


        # Unverified Witness Receipt Escrows
        # test .uwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [('z',), ('m',), ('x',), ('a',)]

        assert db.uwes.get(key) == []
        assert db.uwes.getLast(key) == None
        assert db.uwes.cnt(key) == 0
        assert db.uwes.rem(key) == False
        assert db.uwes.put(key, vals) == True
        assert db.uwes.get(key) == vals # preserved insertion order
        assert db.uwes.cnt(key) == len(vals) == 4
        assert db.uwes.getLast(key) == vals[-1]
        assert db.uwes.put(key, vals=[b'a']) == False   # duplicate
        assert db.uwes.get(key) == vals  #  no change
        assert db.uwes.add(key, b'a') == False   # duplicate
        assert db.uwes.add(key, b'b') == True
        assert db.uwes.get(key) == [('z',), ('m',), ('x',), ('a',), ('b',)]
        assert [val for key, val in db.uwes.getItemIter(key)] == [('z',), ('m',), ('x',), ('a',), ('b',)]
        assert db.uwes.rem(key) == True
        assert db.uwes.get(key) == []

        # Setup Tests for getUweItemsNext and getUweItemsNextIter
        aKey = ('A', '00000000000000000000000000000001')
        aVals = [('z',), ('m',), ('x',)]
        bKey = ('A', '00000000000000000000000000000002')
        bVals = [('o',), ('r',), ('z',)]
        cKey = ('A', '00000000000000000000000000000004')
        cVals = [('h',), ('n',)]
        dKey = ('A', '00000000000000000000000000000007')
        dVals = [('k',), ('b',)]

        assert db.uwes.put(keys=aKey, vals=aVals)
        assert db.uwes.put(keys=bKey, vals=bVals)
        assert db.uwes.put(keys=cKey, vals=cVals)
        assert db.uwes.put(keys=dKey, vals=dVals)


        # Test getUweItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals
        items = [item for item in db.uwes.getItemIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals ==  aVals + bVals + cVals + dVals

        items = [item for item in db.uwes.getItemIter(keys=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == aKey
        vals = [val for  key, val in items]
        assert vals == aVals

        # bVals
        items = [item for item in db.uwes.getItemIter(keys=bKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == bKey
        vals = [val for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.uwes.rem(ikey, val) == True

        # cVals
        items = [item for item in db.uwes.getItemIter(keys=cKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == cKey
        vals = [val for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.uwes.rem(ikey, val) == True

        # dVals
        items = [item for item in db.uwes.getItemIter(keys=dKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert  ikey == dKey
        vals = [val for key, val in items]
        assert vals == dVals
        for key, val in items:
            assert db.uwes.rem(ikey, val) == True


        # Ooes tests 
        # test .ooes insertion behavior methods. 
        pre = 'A'
        sn = 0
        key = snKey(pre, sn)
        vals = [b"z", b"m", b"x", b"a"]
        deserialized_vals = [db.ooes._des(val) for val in vals] # deserialize for assertion
        
        # core insertion
        assert db.ooes.getOn(keys=key) == []
        assert db.ooes.cntOnAll(key) == 0
        assert db.ooes.remOn(key) == False
        
        # initial insertion
        assert db.ooes.putOn(keys=key, vals=vals) == True
        assert db.ooes.getOn(key) == deserialized_vals    #sanity check

        # duplication insertion behavior
        assert db.ooes.putOn(keys=key,vals=[b'd', b'k']) == True
        assert db.ooes.putOn(keys=key,vals=[b'd']) == False  # duplicate
        assert db.ooes.putOn(keys=key,vals=[b'k']) == False  # duplicate
        assert db.ooes.putOn(keys=key,vals=[b'k',b'd',b'k']) == False   
        assert db.ooes.addOn(keys=key, val=b'd') == False  # duplicate
        assert db.ooes.addOn(keys=key, val=b'k') == False  
        assert db.ooes.getOn(keys=key) == deserialized_vals + ['d', 'k']

        # mixed insertion behavior
        assert db.ooes.putOn(keys=key,vals=[b'k', b'c']) == True  # True because 'c' is new
        assert db.ooes.getOn(keys=key) == deserialized_vals + ['d', 'k', 'c']

        # insertion after deletion
        assert db.ooes.remOn(keys=key, val=b'd') == True   # remove a specific val
        assert db.ooes.getOn(keys=key) == deserialized_vals + ['k', 'c']   # d removed
        assert db.ooes.addOn(keys=key,val=b'd') == True   # add d back
        assert db.ooes.getOn(keys=key) == deserialized_vals + ['k', 'c', 'd']   # d added back

        # empty insertion
        assert db.ooes.putOn(keys=key, vals=[]) == False # no vals to add
        assert db.ooes.getOn(keys=key) == deserialized_vals + ['k', 'c', 'd'] # no change

        assert db.ooes.addOn(keys=key, val=b'') == True  # empty val is allowed
        assert db.ooes.getOn(keys=key) == deserialized_vals + ['k', 'c', 'd',''] # empty val added
        
        # clean up
        assert db.ooes.remOn(key) == True
        assert db.ooes.getOn(keys=key) == []

        # different key types insertion
        assert db.ooes.putOn(keys='B', vals=[b'1', b'2']) == True   # key as str
        assert db.ooes.addOn(keys='B', val=b'3') == True   
        assert db.ooes.putOn(['B'], vals=b'4') == True  # key as list
        assert db.ooes.addOn(keys=['B'], val=b'5') == True 
        assert db.ooes.putOn(("B"), vals=b'6') == True # key as tuple
        assert db.ooes.addOn(keys=("B"), val=b'7') == True
        assert db.ooes.putOn(memoryview(b'B'),vals= b'8') == True  # key as memoryview
        assert db.ooes.addOn(keys=memoryview(b'B'), val=b'9') == True
        assert db.ooes.getOn(keys=b'B') == ['1', '2', '3', '4', '5', '6', '7', '8', '9']

        # clean up
        assert db.ooes.remOn(b'B') == True
        assert db.ooes.getOn(keys=b'B') == []

        # edge case: add different types of vals
        assert db.ooes.putOn(key,vals=[b'a','a']) == True
        assert db.ooes.getOn(keys=key) == ['a', 'a'] # both value added because _ser produces different bytes

        assert db.ooes.remOn(key) == True
        assert db.ooes.getOn(keys=key) == []
    
        
        # test .ooes retrieval behavior methods
        # insertion order preserved
        assert db.ooes.putOn(keys=pre,on=sn, vals=vals) == True
        assert db.ooes.getOn(keys=pre,on=sn) == deserialized_vals
        assert list(db.ooes.getOnIterAll(pre,on=sn)) == deserialized_vals
        assert db.ooes.getOnLast(keys=pre, on=sn) == deserialized_vals[-1]
        assert db.ooes.cntOnAll(pre,on=sn) == len(vals) == 4

        # retrieval on empty list
        assert db.ooes.getOn(keys=b'X') == []  
        assert list(db.ooes.getOnIterAll(b'X')) == []
        assert db.ooes.getOnLast(keys=b'X') == None
        assert db.ooes.cntOnAll(b'X') == 0
        items = db.ooes.getOnItemIterAll(keys=b'X')
        assert list(items) == []

        # getItemIter retrieval of (key, val) pairs in lexicographic key order
        items = list(db.ooes.getOnItemIterAll())
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]  # Insertion order preserved for vals
        assert db.ooes.putOn(keys=[b'B', b'C'], vals=[b'1', b'2', b'3']) == True
        items = list(db.ooes.getOnItemIterAll(keys=key))
        assert all(k[0] == 'A' for k, sn, v in items)

        # retrieval with different key types, A is the key used above where key = b'A'
        assert db.ooes.getOn(keys=b'A') == deserialized_vals  # key as bytes
        assert db.ooes.getOn(keys='A') == deserialized_vals  # key as str
        assert db.ooes.getOn(keys=['A']) == deserialized_vals  # key as list
        assert db.ooes.getOn(keys=('A',)) == deserialized_vals  # key as tuple
        assert db.ooes.getOn(keys=memoryview(b'A')) == deserialized_vals  # key as memoryview

        # retrieval afterd deletion of specific val
        assert db.ooes.getOnLast(keys=pre, on=sn) == 'a'              # vals = [b"z", b"m", b"x", b"a"]
        assert db.ooes.remOn(keys=pre,on=sn, val=b'a') == True           # vals = [b"z", b"m", b"x"]
        assert db.ooes.getOn(keys=pre,on=sn,) == ['z', 'm', 'x']
        assert db.ooes.getOnLast(keys=pre, on=sn) == 'x'
        assert db.ooes.cntOnAll(pre,on=sn) == 3
        
        # clean up
        assert db.ooes.remOn(pre,on=sn) == True  


        # test .ooes pinning behavior method
        # start clean
        assert db.ooes.getOn(keys=key) == []
        assert db.ooes.putOn(keys=key, vals=vals) == True
        assert db.ooes.getOn(keys=key) == deserialized_vals
        assert db.ooes.pinOn(keys=key, vals=[b'a', b'b', b'c']) == True
        assert db.ooes.getOn(keys=key) == ['a', 'b', 'c']  # exact overwrite

        # pin with a different list
        assert db.ooes.pinOn(keys=key, vals=[b'x', b'y']) == True
        assert db.ooes.getOn(keys=key) == ['x', 'y']  # previous values removed

        # pin with empty list (valid use case)
        assert db.ooes.pinOn(keys=key, vals=[]) == False  # nothing to pin
        assert db.ooes.getOn(keys=key) == []  # key cleared

        # pin after normal insertion
        assert db.ooes.putOn(keys=key, vals=[b'1', b'2']) == True
        assert db.ooes.getOn(keys=key) == ['1', '2']
        assert db.ooes.pinOn(keys=key, vals=[b'Q']) == True
        assert db.ooes.getOn(keys=key) == ['Q']  # overwritten

        # edge case: pin with mixed types
        assert db.ooes.pinOn(keys=key, vals=[b'A', 'A', memoryview(b'A')]) == True
        assert db.ooes.getOn(keys=key) == ['A', 'A', 'A']  

        # cleanup
        assert db.ooes.remOn(key) == True
        assert db.ooes.getOn(keys=key) == []


        # test .ooes deletion methods
        # delete specific val
        assert db.ooes.putOn(key, vals=vals) == True   
        assert db.ooes.remOn(key, val=b'm') == True
        assert db.ooes.getOn(keys=key) == ['z', 'x', 'a']

        # delete non existing val
        assert db.ooes.remOn(key, val=b'y') == False
        assert db.ooes.getOn(keys=key) == ['z', 'x', 'a']

        # delete all vals
        assert db.ooes.remOn(key) == True
        assert db.ooes.getOn(keys=key) == []
        assert db.ooes.cntOnAll(key) == 0 # all vals deleted

        # delete non existing key
        assert db.ooes.remOn(b'X') == False

        # insert other keys to ensure only specified key is deleted
        assert db.ooes.putOn(b'A', vals=[b'1']) == True
        assert db.ooes.putOn(b'B', vals=[b'2']) == True
        assert db.ooes.remOn(b'A') == True
        assert db.ooes.getOn(keys=b'B') == ['2']

        # clean up all entries
        for k, sn, v in list(db.ooes.getOnItemIterAll()):
            assert db.ooes.remOn(keys=k, on=sn, val=v) == True


        # Setup Tests for getOoeItemsNext and getOoeItemsNextIter
        # vals are in bytes, assertion is done after serializing
        pre = b"A"
        aSn = 1
        aKey = snKey(pre=pre, sn=aSn)
        aVals = [b"z", b"m", b"x"]
        bSn = 2
        bKey = snKey(pre=pre, sn=bSn)
        bVals = [b"o", b"r", b"z"]
        cSn = 4
        cKey = snKey(pre=pre, sn=cSn)
        cVals = [b"h", b"n"]
        dSn = 7
        dKey = snKey(pre=pre, sn=dSn)
        dVals = [b"k", b"b"]

        assert db.ooes.putOn(keys=pre, on=1, vals=aVals)
        assert db.ooes.putOn(keys=pre, on=2, vals=bVals)
        assert db.ooes.putOn(keys=pre, on=4, vals=cVals)
        assert db.ooes.putOn(keys=pre, on=7, vals=dVals)

        # Test getOoeItemsNextIter(key=b"")
        #  get dups at first key in database
        # aVals

        items = [item for item in db.ooes.getItemIter()]
        assert items  # not empty
        ikey = db.ooes._tokey(items[0][0])
        assert  ikey == aKey
        vals = [db.ooes._ser(val) for  key, val in items]
        assert vals ==  aVals + bVals + cVals + dVals

        items = [item for item in db.ooes.getItemIter(keys=aKey)]
        assert items  # not empty
        ikey = db.ooes._tokey(items[0][0])
        assert  ikey == aKey
        vals = [db.ooes._ser(val) for  key, val in items]
        assert vals == aVals

        # bVals
        items = [item for item in db.ooes.getItemIter(keys=bKey)]
        assert items  # not empty
        ikey = db.ooes._tokey(items[0][0])
        assert  ikey == bKey
        vals = [db.ooes._ser(val) for key, val in items]
        assert vals == bVals
        for key, val in items:
            assert db.ooes.remOn(pre, bSn, val) == True

        # cVals
        items = [item for item in db.ooes.getItemIter(keys=cKey)]
        assert items  # not empty
        ikey = db.ooes._tokey(items[0][0])
        assert  ikey == cKey
        vals = [db.ooes._ser(val) for key, val in items]
        assert vals == cVals
        for key, val in items:
            assert db.ooes.remOn(pre, cSn, val) == True

        # dVals
        items = [item for item in db.ooes.getItemIter(keys=dKey)]
        assert items  # not empty
        ikey = db.ooes._tokey(items[0][0])
        assert  ikey == dKey
        vals = [db.ooes._ser(val) for key, val in items]
        assert vals == dVals

        # clean up all entries
        for k, sn, v in list(db.pses.getOnItemIterAll()):
            db.ooes.remOn(keys=k)
        
        # test _tokey and _tokeys
        t = db.ooes._tokey(aKey)
        assert db.ooes._tokeys(t) == ("A", "00000000000000000000000000000001")


        # test .dels insertion order dup methods.  dup vals are insertion order
        keys = b'A'
        on = 0
        vals = ["z", "m", "x", "a"]

        assert db.dels.getOn(keys=keys, on=on) == []
        result = db.dels.getOn(keys=keys, on=on)
        assert (result[-1] if result else None) == None
        assert len(db.dels.getOn(keys=keys, on=on)) == 0
        assert db.dels.remOn(keys=keys, on=on) == False
        for val in vals:
            db.dels.addOn(keys=keys, on=on, val=val)
        assert db.dels.getOn(keys=keys, on=on) == vals  # preserved insertion order
        assert len(db.dels.getOn(keys=keys, on=on)) == len(vals) == 4
        result = db.dels.getOn(keys=keys, on=on)
        assert result[-1] == vals[-1]
        assert db.dels.addOn(keys=keys, on=on, val='a') == False   # duplicate
        assert db.dels.getOn(keys=keys, on=on) == vals  #  no change
        assert db.dels.addOn(keys=keys, on=on, val='a') == False   # duplicate
        assert db.dels.addOn(keys=keys, on=on, val='b') == True
        assert db.dels.getOn(keys=keys, on=on) == ["z", "m", "x", "a", "b"]
        assert db.dels.remOn(keys=keys, on=on) == True
        assert db.dels.getOn(keys=keys, on=on) == []

        # test .ldes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.ldes.get(keys=key) == []
        assert db.ldes.getLast(keys=key) == None
        assert db.ldes.cnt(keys=key) == 0
        assert db.ldes.rem(keys=key) == False
        # put is not fully compatible with putLdes because putLdes took list of vals
        # and IoDupSuber.put takes iterable of vals.
        assert db.ldes.put(keys=key, vals=vals) == True
        # OnIoDupSuber decodes bytes to utf-8 strings
        assert db.ldes.get(keys=key) == [v.decode("utf-8") for v in vals]
        assert db.ldes.cnt(keys=key) == len(vals) == 4
        assert db.ldes.getLast(keys=key) == vals[-1].decode("utf-8")
        assert db.ldes.put(keys=key, vals=[b'a']) == False   # duplicate
        assert db.ldes.get(keys=key) == [v.decode("utf-8") for v in vals] #  no change
        assert db.ldes.rem(keys=key) == True
        assert db.ldes.get(keys=key) == []

        # Setup Tests for getOnItemIter with proper OnIoDupSuber API
        # Use addOn with explicit ordinal instead of snKey
        aVals = [b"z", b"m", b"x"]
        bVals = [b"o", b"r", b"z"]
        cVals = [b"h", b"n"]
        dVals = [b"k", b"b"]

        for val in aVals:
            assert db.ldes.addOn(keys=b'A', on=1, val=val) == True
        for val in bVals:
            assert db.ldes.addOn(keys=b'A', on=2, val=val) == True
        for val in cVals:
            assert db.ldes.addOn(keys=b'A', on=4, val=val) == True
        for val in dVals:
            assert db.ldes.addOn(keys=b'A', on=7, val=val) == True

        # Test getOnItemIterAll - iterate all items for prefix b'A'
        items = [item for item in db.ldes.getOnItemIterAll(keys=b'A')]
        assert items  # not empty
        # item is (keys, on, val)
        vals = [val for pre, sn, val in items]
        allVals = aVals + bVals + cVals + dVals
        assert vals == [v.decode("utf-8") for v in allVals]

        # Iterate starting from specific ordinal (sn=1)
        items = [item for item in db.ldes.getOnItemIterAll(keys=b'A', on=1)]
        assert items
        pre, sn, val = items[0]
        assert sn == 1
        assert val == aVals[0].decode("utf-8")

        # Verify vals at sn=1
        vals = [val for p, s, val in items if s == 1]
        assert vals == [v.decode("utf-8") for v in aVals]

        # bVals at sn=2
        items = [item for item in db.ldes.getOnItemIterAll(keys=b'A', on=2)]
        vals = [val for p, s, val in items if s == 2]
        assert vals == [v.decode("utf-8") for v in bVals]
        # Remove bVals using remOn
        for p, s, val in items:
            if s == 2:
                assert db.ldes.remOn(keys=b'A', on=s, val=val) == True

        # cVals at sn=4
        items = [item for item in db.ldes.getOnItemIterAll(keys=b'A', on=4)]
        vals = [val for p, s, val in items if s == 4]
        assert vals == [v.decode("utf-8") for v in cVals]
        for p, s, val in items:
            if s == 4:
                assert db.ldes.remOn(keys=b'A', on=s, val=val) == True

        # dVals at sn=7
        items = [item for item in db.ldes.getOnItemIterAll(keys=b'A', on=7)]
        vals = [val for p, s, val in items if s == 7]
        assert vals == [v.decode("utf-8") for v in dVals]
        for p, s, val in items:
            if s == 7:
                assert db.ldes.remOn(keys=b'A', on=s, val=val) == True


    assert not os.path.exists(db.path)

    """ End Test """


def test_baser_clone_all_pre_iter():
    """
    Test cloneAllPreIter yields first-seen event messages for all identifier
    prefixes in the database (fels getOnItemIterAll(keys=b'', on=0) path).
    """
    with habbing.openHby(name="test", base="test", temp=True) as hby:
        hab1 = hby.makeHab(name="alice", isith="1", icount=1)
        hab2 = hby.makeHab(name="bob", isith="1", icount=1)
        # Single shared db now has fels (and evts, sigs) for both identifiers
        msgs = list(hby.db.cloneAllPreIter())
        assert len(msgs) >= 2
        pres = set()
        for msg in msgs:
            serder = serdering.SerderKERI(raw=bytes(msg))
            pres.add(serder.pre)
        assert hab1.pre in pres
        assert hab2.pre in pres


def test_clean_baser():
    """
    Test Baser db clean clone method
    """
    name = "nat"
    # with basing.openDB(name="nat") as natDB, keeping.openKS(name="nat") as natKS:
    with habbing.openHby(name=name, salt=core.Salter(raw=b'0123456789abcdef').qb64) as hby:  # default is temp=True
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
        assert natHab.db.path.endswith(os.path.join(os.path.sep, "keri", "db", "nat"))
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
        ldig = natHab.db.kels.getOnLast(keys=natHab.pre, on=natHab.kever.sn)
        ldig = ldig.encode("utf-8")
        assert ldig == natHab.kever.serder.saidb
        serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
        assert serder.said == natHab.kever.serder.said
        state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
        assert state.s == '6'
        assert state.f == '6'
        assert natHab.db.env.stat()['entries'] <= 96 #68

        # test reopenDB with reuse  (because temp)
        with basing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = natHab.db.kels.getOnLast(keys=natHab.pre, on=natHab.kever.sn)
            ldig = ldig.encode("utf-8")
            assert ldig == natHab.kever.serder.saidb
            serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
            assert serder.said == natHab.kever.serder.said
            assert natHab.db.env.stat()['entries'] <= 96 #68

            # verify name pre kom in db
            data = natHab.db.habs.get(keys=natHab.pre)
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
            assert natHab.db.evts.get(keys=(natHab.pre, badsrdr.said))
            assert natHab.db.fels.getOn(keys=natHab.pre, on=7)


        # test openDB copy db with clean
        with basing.openDB(name=natHab.db.name,
                          temp=natHab.db.temp,
                          headDirPath=natHab.db.headDirPath,
                          perm=natHab.db.perm,
                          clean=True) as copy:
            assert copy.path.endswith(os.path.join(os.path.sep, "keri", "clean", "db", "nat"))
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
            ldig = natHab.db.kels.getOnLast(keys=natHab.pre, on=natHab.kever.sn)
            ldig = ldig.encode("utf-8")
            assert ldig == natHab.kever.serder.saidb
            serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
            assert serder.said == natHab.kever.serder.said
            assert natHab.db.env.stat()['entries'] >= 18

            # confirm bad event missing from database
            assert not natHab.db.evts.get(keys=(natHab.pre, badsrdr.said))
            assert not natHab.db.fels.getOn(keys=natHab.pre, on=7)
            state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
            assert state.s == '6'
            assert state.f == '6'

            # verify name pre kom in db
            data = natHab.db.habs.get(keys=natHab.pre)
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
    vs = versify(kind=Kinds.json, size=20)
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
        vals0 = [skedb]
        assert db.kels.addOn(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert db.kels.addOn(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        for val in vals2:
            assert db.kels.addOn(keys=preb, on=sn, val=val) == True

        vals = list(db.kels.getOnIterAll(keys=preb))
        allvals = [v.decode("utf-8") for v in (vals0 + vals1 + vals2)]
        assert vals == allvals

        # test getKelEstIter
        preb = 'B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x'.encode("utf-8")
        sn = 0

        vals0 = [skedb]
        assert db.kels.addOn(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert db.kels.addOn(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        for val in vals2:
            assert db.kels.addOn(keys=preb, on=sn, val=val) == True

        vals = list(db.kels.getOnLastIter(keys=preb))
        lastvals = [v.decode("utf-8") for v in (vals0[-1], vals1[-1], vals2[-1])]
        assert vals == lastvals


        # test getDelItemIter
        preb = 'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw'.encode("utf-8")
        sn = 1  # do not start at zero
        key = snKey(preb, sn)
        assert key == (b'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw.'
                       b'00000000000000000000000000000001')
        vals0 = [skedb]
        assert db.dels.addOn(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert db.dels.addOn(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 3  # skip make gap in SN
        for val in vals2:
            assert db.dels.addOn(keys=preb, on=sn, val=val) == True

        allvals = vals0 + vals1 + vals2
        vals = [(val.encode("utf-8") if isinstance(val, str) else bytes(val))
            for keys, on, val in db.dels.getOnItemIterAll(keys=preb)]
        assert vals == allvals

    assert not os.path.exists(db.path)
    """ End Test """



def test_usebaser():
    """
    Test using Baser
    """
    raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    salter = core.Salter(raw=raw)

    #  create coe's signers
    signers = salter.signers(count=8, path='db', temp=True)


    with openDB() as db:
        # Event 0  Inception Transferable (nxt digest not empty) 2 0f 3 multisig
        keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
        count = len(keys)
        nxtkeys = [signers[3].verfer.qb64b, signers[4].verfer.qb64b, signers[5].verfer.qb64b]
        sith = "2"
        code = core.MtrDex.Blake3_256  # Blake3 digest of incepting data
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

        db.evts.put(keys=(pre, serder.said), val=serder)
        assert db.evts.get(keys=(pre, serder.said)) is not None

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
        assert os.path.join("_test", "keri", "db", "test") in doer.baser.path

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

def test_KERI_BASER_MAP_SIZE_handles_bad_values(caplog):
    # Base case works because of above tests, they will all break if happy path
    # is broken.  We'll just test some unhappy values.

    # Pytest will fail if any exceptions raised here.
    os.environ["KERI_BASER_MAP_SIZE"] = "foo" # Not an int
    err_msg = "KERI_BASER_MAP_SIZE must be an integer value > 1!"
    with pytest.raises(ValueError):
        Baser(reopen=False, temp=True)
        assert err_msg in caplog.messages
    os.environ["KERI_BASER_MAP_SIZE"] = "1.0" # Not an int
    with pytest.raises(ValueError):
        Baser(reopen=False, temp=True)
        assert err_msg in caplog.messages
    os.environ.pop("KERI_BASER_MAP_SIZE")


def test_clear_escrows():
    with openDB() as db:
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        d1 = coring.Diger(ser=b"event1")                     # event digest
        p1 = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        n1 = core.Number(num=1)
        e1 = coring.Diger(ser=b"est1")                       # est event digest
        s1 = core.Siger(raw=b"\x00" * 64)                    # fake sig
        res_vals = [(d1, p1, n1, e1, s1)]

        db.ures.put(keys=key, vals=res_vals)
        db.vres.put(keys=key, vals=res_vals)
        db.pses.putOn(keys=key, vals=vals)
        for v in vals:
            db.pwes.addOn(keys=key, on=0, val=v)
        for v in vals:
            db.ooes.addOn(keys=key, on=0, val=v)
        # putLdes was list based, db.ldes.put is iterable based
        db.ldes.put(keys=key, vals=vals)

        pre = b'k'
        snh = b'snh'
        saidb = b'saidb'

        db.uwes.add(keys=(pre, snh), val=saidb)
        assert db.uwes.cnt(keys=(pre, snh)) == 1

        db.qnfs.add(keys=(pre, saidb), val=b"z")
        assert db.qnfs.cnt(keys=(pre, saidb)) == 1

        db.misfits.add(keys=(pre, snh), val=saidb)
        assert db.misfits.cnt(keys=(pre, snh)) == 1

        db.delegables.add(snKey(pre, 0), saidb)
        assert db.delegables.cnt(keys=snKey(pre, 0)) == 1

        db.pdes.addOn(keys=pre, on=0, val=saidb)
        assert db.pdes.cnt(keys=snKey(pre, 0)) == 1

        udesKey = ('DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8"),
                    'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8"))
        db.udes.put(keys=udesKey, val=(coring.Number(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'),
                                   coring.Diger(qb64b=b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E')))
        assert db.udes.get(keys=udesKey) is not None

        saider = coring.Saider(qb64b='EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')
        db.rpes.put(keys=('route',), vals=[saider])
        assert db.rpes.cnt(keys=('route',)) == 1

        db.epsd.put(keys=('DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',), val=coring.Dater())
        assert db.epsd.get(keys=('DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',)) is not None

        db.eoobi.pin(keys=('url',), val=OobiRecord())
        assert db.eoobi.cnt() == 1

        serder = Serder(raw=b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EG8WAmM29ZBdoXbnb87yiPxQw4Y7gcQjqZS74vBAKsRm","i":"DApYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0","s":"4","p":"EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","a":[]}')
        db.dpub.put(keys=(pre, 'said'), val=serder)
        assert db.dpub.get(keys=(pre, 'said')) is not None

        db.gpwe.add(keys=(pre,), val=(coring.Seqner(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'), saider))
        assert db.gpwe.cnt(keys=(pre,)) == 1

        db.gdee.add(keys=(pre,), val=(coring.Seqner(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'), saider))
        assert db.gdee.cnt(keys=(pre,)) == 1

        db.dpwe.pin(keys=(pre, 'said'), val=serder)
        assert db.dpwe.get(keys=(pre, 'said')) is not None

        db.gpse.add(keys=('qb64',), val=(coring.Seqner(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'), saider))
        assert db.gpse.cnt(keys=('qb64',)) == 1

        db.epse.put(keys=('dig',), val=serder)
        assert db.epse.get(keys=('dig',)) is not None

        db.dune.pin(keys=(pre, 'said'), val=serder)
        assert db.dune.get(keys=(pre, 'said')) is not None

        db.clearEscrows()

        assert db.ures.get(key) == []
        assert db.vres.get(key) == []
        assert db.pses.getOn(keys=key) == []
        assert db.pwes.getOn(key) == []
        assert db.uwes.get(key) == []
        assert db.ooes.getOn(keys=key) == []
        assert db.ldes.get(keys=key) == []
        assert db.qnfs.cntAll() == 0
        assert db.pdes.cntAll() == 0
        assert db.rpes.cntAll() == 0
        assert db.eoobi.cnt() == 0
        assert db.gpwe.cntAll() == 0
        assert db.gdee.cntAll() == 0
        assert db.dpwe.cntAll() == 0
        assert db.gpse.cntAll() == 0
        assert db.epse.cntAll() == 0
        assert db.dune.cntAll() == 0
        assert db.misfits.cntAll() == 0
        assert db.delegables.cntAll() == 0
        assert db.udes.cntAll() == 0
        assert db.epsd.cntAll() == 0
        assert db.dpub.cntAll() == 0

def test_db_keyspace_end_to_end_migration():
    """
    End-to-end test for DB keyspace migration from Seqner.qb64 to Number with Huge code.

    Asserts:
    - Correct DB writes using Number (Huge)
    - Correct DB reads using Number (Huge)
    - Backward compatibility with old Seqner.qb64 keys
    - Round-trip correctness for Number (Huge)
    - Lexicographic ordering == numeric ordering (for NEW keys)
    - Mixed encodings do not break iteration
    """

    sns = [0, 1, 2, 10, 100, 999999, 2**40, 2**80]

    with openDB() as db:
        # Build a valid Cigar + Prefixer once, reuse in all values
        signer = Signer()                     # ephemeral keypair
        cigar = signer.sign(b"test")          # Cigar
        pre = cigar.verfer.qb64               # non-transferable prefix

        # old encoding (Seqner.qb64) – backward compatibility
        for sn in sns:
            old_key = Seqner(sn=sn).qb64
            dig = Diger(raw=b"\x00" * 32)     # valid 32-byte raw
            val = (dig, coring.Prefixer(qb64=pre), cigar)
            db.ures.add(keys=("OLD", old_key), val=val)

        # new encoding (Number with Huge code)
        for sn in sns:
            new_key = Number(num=sn, code=coring.NumDex.Huge).qb64
            dig = Diger(raw=b"\x01" * 32)     # distinguishable but valid
            val = (dig, coring.Prefixer(qb64=pre), cigar)
            db.ures.add(keys=("NEW", new_key), val=val)

        # round-trip correctness for Number with Huge code
        for sn in sns:
            enc = Number(num=sn, code=coring.NumDex.Huge).qb64
            parsed = Number(qb64=enc)
            assert parsed.num == sn

        # read back old and new keys (existence + type)
        for sn in sns:
            old_key = Seqner(sn=sn).qb64
            new_key = Number(num=sn, code=coring.NumDex.Huge).qb64

            old_vals = db.ures.get(keys=("OLD", old_key))
            new_vals = db.ures.get(keys=("NEW", new_key))

            assert len(old_vals) == 1
            assert len(new_vals) == 1

            odig, opre, ocig = old_vals[0]
            ndig, npre, ncig = new_vals[0]

            assert isinstance(odig, Diger)
            assert isinstance(opre, coring.Prefixer)
            assert isinstance(ncig, type(cigar))
            assert isinstance(ndig, Diger)
            assert isinstance(npre, coring.Prefixer)

        # lexicographic ordering must match numeric ordering for NEW keys
        ordered_sns = []
        for (pre_key, key), vals in db.ures.getItemIter():
            if pre_key == "NEW":
                n = Number(qb64=key)
                ordered_sns.append(n.num)

        assert ordered_sns == sns


if __name__ == "__main__":
    test_baser()
    test_clean_baser()
    test_fetchkeldel()
    test_usebaser()
    test_dbdict()
    test_baserdoer()
    test_db_keyspace_end_to_end_migration()
