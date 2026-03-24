# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import json
import os
import platform
import tempfile
from dataclasses import dataclass, asdict

import pytest

import lmdb
from hio.base import doing

from keri.kering import Kinds, Ilks, versify
from keri.app import openHby
from keri.core import (Seqner, Diger, Number, Kever, Serder,
                       Signer, Siger, Salter, Dater, Prefixer,
                       Cigar, Seqner, Saider, Noncer, Labeler,
                       Texter, SerderKERI, StateEstEvent,
                       IdrDex, MtrDex, NumDex,
                       incept, rotate, interact, rotate)

from keri.core import state as eventState
from keri.db import (Baser, BaserDoer, Baser, SerderSuber,
                     CesrIoSetSuber, CesrSuber, CatCesrIoSetSuber,
                     OnIoDupSuber, IoDupSuber, CatCesrSuber, statedict,
                     openDB, dgKey, snKey, openLMDB, openDB, reopenDB)

from keri.help import datify, dictify
from keri.recording import (EventSourceRecord, KeyStateRecord,
                            OobiRecord, RawRecord, StateEERecord)
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

    assert isinstance(baser.evts, SerderSuber)
    assert isinstance(baser.sigs, CesrIoSetSuber)
    assert isinstance(baser.dtss, CesrSuber)
    assert isinstance(baser.rcts, CatCesrIoSetSuber)
    assert isinstance(baser.ures, CatCesrIoSetSuber)
    assert isinstance(baser.kels, OnIoDupSuber)
    assert isinstance(baser.ooes, IoDupSuber)
    assert isinstance(baser.pses, IoDupSuber)
    assert isinstance(baser.dels, OnIoDupSuber)
    assert isinstance(baser.ldes, OnIoDupSuber)

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

    assert isinstance(baser.evts, SerderSuber)
    assert isinstance(baser.sigs, CesrIoSetSuber)
    assert isinstance(baser.dtss, CesrSuber)
    assert isinstance(baser.rcts, CatCesrIoSetSuber)
    assert isinstance(baser.ures, CatCesrIoSetSuber)
    assert isinstance(baser.ooes, IoDupSuber)
    assert isinstance(baser.pses, IoDupSuber)
    assert isinstance(baser.dels, OnIoDupSuber)
    assert isinstance(baser.ldes, OnIoDupSuber)

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

        assert isinstance(baser.evts, SerderSuber)
        assert isinstance(baser.sigs, CesrIoSetSuber)
        assert isinstance(baser.dtss, CesrSuber)
        assert isinstance(baser.rcts, CatCesrIoSetSuber)
        assert isinstance(baser.ures, CatCesrIoSetSuber)
        assert isinstance(baser.ooes, IoDupSuber)
        assert isinstance(baser.pses, IoDupSuber)
        assert isinstance(baser.dels, OnIoDupSuber)
        assert isinstance(baser.ldes, OnIoDupSuber)


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
        sked = SerderKERI(raw=skedb, verify=False)
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
        record = EventSourceRecord()
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

        assert db.fels.get(keys=preA, on=0) is None
        assert db.fels.rem(keys=preA, on=0) == False
        assert db.fels.put(keys=preA, on=0, val=digA) == True
        assert db.fels.get(keys=preA, on=0) == digA.decode("utf-8")
        assert db.fels.put(keys=preA, on=0, val=digA) == False
        assert db.fels.pin(keys=preA, on=0, val=digA) == True
        assert db.fels.get(keys=preA, on=0) == digA.decode("utf-8")
        assert db.fels.rem(keys=preA, on=0) == True
        assert db.fels.get(keys=preA, on=0) is None

        # test appendOn
        # empty database
        assert db.fels.get(keys=preB, on=0) is None
        on = db.fels.append(keys=preB, val=digU)
        assert on == 0
        assert db.fels.get(keys=preB, on=0) == digU.decode("utf-8")
        assert db.fels.rem(keys=preB, on=0) == True
        assert db.fels.get(keys=preB, on=0) is None

        # earlier pre in database only
        assert db.fels.put(keys=preA, on=0, val=digA) == True
        on = db.fels.append(keys=preB, val=digU)
        assert on == 0
        assert db.fels.get(keys=preB, on=0) == digU.decode("utf-8")
        assert db.fels.rem(keys=preB, on=0) == True
        assert db.fels.get(keys=preB, on=0) is None

        # earlier and later pre in db but not same pre
        assert db.fels.get(keys=preA, on=0) == digA.decode("utf-8")
        assert db.fels.put(keys=preC, on=0, val=digC) == True
        on = db.fels.append(keys=preB, val=digU)
        assert on == 0
        assert db.fels.get(keys=preB, on=0) == digU.decode("utf-8")
        assert db.fels.rem(keys=preB, on=0) == True
        assert db.fels.get(keys=preB, on=0) is None

        # later pre only
        assert db.fels.rem(keys=preA, on=0) == True
        assert db.fels.get(keys=preA, on=0) is None
        assert db.fels.get(keys=preC, on=0) == digC.decode("utf-8")
        on = db.fels.append(keys=preB, val=digU)
        assert on == 0
        assert db.fels.get(keys=preB, on=0) == digU.decode("utf-8")

        # earlier pre and later pre and earlier entry for same pre
        assert db.fels.put(keys=preA, on=0, val=digA) == True
        on = db.fels.append(keys=preB, val=digV)
        assert on == 1
        assert db.fels.get(keys=preB, on=1) == digV.decode("utf-8")

        # earlier entry for same pre but only same pre
        assert db.fels.rem(keys=preA, on=0) == True
        assert db.fels.get(keys=preA, on=0) is None
        assert db.fels.rem(keys=preC, on=0) == True
        assert db.fels.get(keys=preC, on=0) is None
        # another value for preB
        on = db.fels.append(keys=preB, val=digW)
        assert on == 2
        assert db.fels.get(keys=preB, on=2) == digW.decode("utf-8")
        # yet another value for preB
        on = db.fels.append(keys=preB, val=digX)
        assert on == 3
        assert db.fels.get(keys=preB, on=3) == digX.decode("utf-8")
        # yet another value for preB
        on = db.fels.append(keys=preB, val=digY)
        assert on == 4
        assert db.fels.get(keys=preB, on=4) == digY.decode("utf-8")

        # replay preB events in database
        _pre = lambda k: k[0].encode() if isinstance(k[0], str) else k[0]
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getAllItemIter(keys=preB)]
        assert items == [(preB, 0, digU.decode("utf-8")), (preB, 1, digV.decode("utf-8")), (preB, 2, digW.decode("utf-8")), (preB, 3, digX.decode("utf-8")), (preB, 4, digY.decode("utf-8"))]

        # resume replay preB events at on = 3
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getAllItemIter(keys=preB, on=3)]
        assert items == [(preB, 3, digX.decode("utf-8")), (preB, 4, digY.decode("utf-8"))]

        # resume replay preB events at on = 5
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getAllItemIter(keys=preB, on=5)]
        assert items == []

        # replay all events in database with pre events before and after
        assert db.fels.put(keys=preA, on=0, val=digA) == True
        assert db.fels.put(keys=preC, on=0, val=digC) == True

        # replay all pres in first-seen order (keys=b'', on=0)
        items = [(_pre(keys), on, val) for keys, on, val in db.fels.getAllItemIter(keys=b'', on=0)]
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
        dater1 = Dater(dts='2020-08-22T17:50:09.988921+00:00')
        dater2 = Dater(dts='2020-08-22T17:50:10.000000+00:00')

        assert db.dtss.get(keys=key) is None
        assert db.dtss.rem(keys=key) == False
        assert db.dtss.put(keys=key, val=dater1) == True
        result = db.dtss.get(keys=key)
        assert isinstance(result, Dater)
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
        number1 = Number(qb64b=ssnu1)
        diger1 = Diger(qb64b=sdig1)
        number2 = Number(qb64b=ssnu2)
        diger2 = Diger(qb64b=sdig2)
        val1 = (number1, diger1)
        val2 = (number2, diger2)

        assert db.aess.get(keys=(preb, digb)) == None
        assert db.aess.rem(keys=(preb, digb)) == False
        assert db.aess.put(keys=(preb, digb), val=val1) == True
        result = db.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber1, rdiger1 = result
        assert rnumber1.qb64b == number1.qb64b
        assert rdiger1.qb64b == diger1.qb64b
        assert db.aess.put(keys=(preb, digb), val=val2) == False
        result = db.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber1, rdiger1 = result
        assert rnumber1.qb64b == number1.qb64b
        assert rdiger1.qb64b == diger1.qb64b
        assert db.aess.pin(keys=(preb, digb), val=val2) == True
        result = db.aess.get(keys=(preb, digb))
        assert result is not None
        rnumber2, rdiger2 = result
        assert rnumber2.qb64b == number2.qb64b
        assert rdiger2.qb64b == diger2.qb64b
        assert db.aess.rem(keys=(preb, digb)) == True
        assert db.aess.get(keys=(preb, digb)) == None

        # test .sigs sub db methods
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        assert db.sigs.get(keys=key) == []
        assert db.sigs.cnt(keys=key) == 0
        assert db.sigs.rem(keys=key) == False

        # Create valid test signatures
        signer0 = Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)

        siger0 = Siger(raw=cigar0.raw, code=IdrDex.Ed25519_Sig, index=0)
        siger1 = Siger(raw=cigar1.raw, code=IdrDex.Ed25519_Sig, index=1)

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
        signer0 = Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)

        siger0 = Siger(raw=cigar0.raw, code=IdrDex.Ed25519_Sig, index=0)
        siger1 = Siger(raw=cigar1.raw, code=IdrDex.Ed25519_Sig, index=1)

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
        wit0 = Prefixer(qb64=wit0b.decode('utf-8'))  # Convert from qb64 string
        wit1 = Prefixer(qb64=wit1b.decode('utf-8'))

        # Create cigars (non-indexed signatures)
        cigar0 = Cigar(qb64=wsig0b.decode('utf-8'))
        cigar1 = Cigar(qb64=wsig1b.decode('utf-8'))

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
        wit2 = Prefixer(qb64='BNewTestPrefix000000000000000000000000000000')
        cigar2 = Cigar(qb64='BNewTestSignature00000000000000000000000000000000000000000000000000000000000000000000000')
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
        diger0 = Diger(ser=b"event0")
        diger1 = Diger(ser=b"event1")
        diger2 = Diger(ser=b"event2")
        diger3 = Diger(ser=b"event3")
        diger4 = Diger(ser=b"event4")

        pre0 = Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        signer0 = Signer(transferable=False, seed=b'0123456789abcdef0123456789abcdef')
        signer1 = Signer(transferable=False, seed=b'abcdef0123456789abcdef0123456789')
        signer2 = Signer(transferable=False, seed=b'fedcba9876543210fedcba9876543210')
        signer3 = Signer(transferable=False, seed=b'0011223344556677889900112233445566')
        signer4 = Signer(transferable=False, seed=b'ffeeddccbbaa99887766554433221100')

        test_data = b"test witness signatures"
        cigar0 = signer0.sign(ser=test_data)
        cigar1 = signer1.sign(ser=test_data)
        cigar2 = signer2.sign(ser=test_data)
        cigar3 = signer3.sign(ser=test_data)
        cigar4 = signer4.sign(ser=test_data)

        pre1 = Prefixer(qb64=signer0.verfer.qb64)
        pre2 = Prefixer(qb64=signer1.verfer.qb64)
        pre3 = Prefixer(qb64=signer2.verfer.qb64)
        pre4 = Prefixer(qb64=signer3.verfer.qb64)

        key = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Seqner(sn=0).qb64)

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

        # Setup multi-key tests for getTopItemIter
        aKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Seqner(sn=1).qb64)
        aVals = [(diger0, pre0, cigar0), (diger1, pre1, cigar1), (diger2, pre2, cigar2)]
        bKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Seqner(sn=2).qb64)
        bVals = [(diger1, pre1, cigar1), (diger2, pre2, cigar2), (diger3, pre3, cigar3)]
        cKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Seqner(sn=4).qb64)
        cVals = [(diger2, pre2, cigar2), (diger3, pre3, cigar3)]
        dKey = ("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Seqner(sn=7).qb64)
        dVals = [(diger3, pre3, cigar3), (diger4, pre4, cigar4)]

        assert db.ures.put(keys=aKey, vals=aVals)
        assert db.ures.put(keys=bKey, vals=bVals)
        assert db.ures.put(keys=cKey, vals=cVals)
        assert db.ures.put(keys=dKey, vals=dVals)

        # Test getTopItemIter with no key
        items = [(keys, val) for keys, val in db.ures.getTopItemIter()]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == aKey
        # Verify total count
        assert len(items) == len(aVals) + len(bVals) + len(cVals) + len(dVals)

        # aVals — iterate at aKey only
        items = [(keys, val) for keys, val in db.ures.getTopItemIter(keys=aKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == aKey
        assert len(items) == len(aVals)  # only aKey items

        # bVals — iterate at bKey, remove each
        items = [(keys, val) for keys, val in db.ures.getTopItemIter(keys=bKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == bKey
        assert len(items) == len(bVals)  # only bKey items
        for ikeys, val in db.ures.getTopItemIter(keys=bKey):
            assert db.ures.rem(bKey, val) == True

        # cVals — iterate at cKey, remove each
        items = [(keys, val) for keys, val in db.ures.getTopItemIter(keys=cKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == cKey
        assert len(items) == len(cVals)  # only cKey items
        for ikeys, val in db.ures.getTopItemIter(keys=cKey):
            assert db.ures.rem(cKey, val) == True

        # dVals — iterate at dKey, remove each
        items = [(keys, val) for keys, val in db.ures.getTopItemIter(keys=dKey)]
        assert items  # not empty
        ikey = items[0][0]
        assert ikey == dKey
        assert len(items) == len(dVals)
        for ikeys, val in db.ures.getTopItemIter(keys=dKey):
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

        p1 = Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # fake prefix
        n1 = Number(num=1)
        e1 = Diger(ser=b"est1")    # digest of est event
        s1 = Siger(raw=b"\x00" * 64)  # 64‑byte fake signature

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
        pA = Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        pB = Prefixer(qb64="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        pC = Prefixer(qb64="BCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
        pD = Prefixer(qb64="BDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")

        nA = Number(num=1)
        nB = Number(num=2)
        nC = Number(num=3)
        nD = Number(num=4)

        eA = Diger(ser=b"estA")
        eB = Diger(ser=b"estB")
        eC = Diger(ser=b"estC")
        eD = Diger(ser=b"estD")

        sA = Siger(raw=b"\x00" * 64)
        sB = Siger(raw=b"\x01" * 64)
        sC = Siger(raw=b"\x02" * 64)
        sD = Siger(raw=b"\x03" * 64)

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

        d1 = Diger(ser=b"event1")  # digest of event
        p1 = Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  # fake prefix
        n1 = Number(num=1)
        e1 = Diger(ser=b"est1")    # digest of est event
        s1 = Siger(raw=b"\x00" * 64)  # 64‑byte fake signature

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

        assert db.kels.get(keys=key) == []
        assert db.kels.getLast(keys=key)== None
        assert db.kels.cntAll(keys=key) == 0
        assert db.kels.rem(key) == False
        assert db.kels.put(keys=key, vals=vals) == True
        assert db.kels.get(keys=key) == deserializedVals  # preserved insertion order
        assert db.kels.cntAll(keys=key) == len(vals) == 4
        assert db.kels.getLast(keys=key) == deserializedVals[-1]
        assert db.kels.put(keys=key, vals=[b'a']) == False   # duplicate
        assert db.kels.get(keys=key) == deserializedVals  #  no change
        assert db.kels.add(keys=key, val=b'a') == False   # duplicate
        assert db.kels.add(keys=key, val=b'b') == True
        assert db.kels.get(keys=key) == deserializedVals + ['b']
        assert db.kels.rem(key) == True
        assert db.kels.get(keys=key) == []

        # Partially Signed Escrow Events
        # test .pses insertion order dup methods.  dup vals are insertion order
        pre = b'A'
        sn = 0
        key = snKey(pre, sn)
        vals = [b"z", b"m", b"x", b"a"]
        deserialized_vals = [db.pses._des(val) for val in vals] # deserialize for assertion

        # core insertion
        assert db.pses.get(keys=key) == []
        assert db.pses.getLast(keys=pre, on=sn) == None
        assert db.pses.cntAll(keys=key) == 0
        assert db.pses.rem(keys=key) == False

        # initial insertion
        assert db.pses.put(keys=key, vals=vals) == True
        assert db.pses.get(keys=key) == deserialized_vals    #sanity check

        # duplication insertion behavior
        assert db.pses.put(keys=key, vals=[b'd', b'k']) == True
        assert db.pses.put(keys=key, vals=[b'd']) == False  # duplicate
        assert db.pses.put(keys=key, vals=[b'k']) == False  # duplicate
        assert db.pses.put(keys=key, vals=[b'k',b'd',b'k']) == False
        assert db.pses.add(keys=key, val=b'd') == False  # duplicate
        assert db.pses.add(keys=key, val=b'k') == False
        assert db.pses.get(keys=key) == deserialized_vals + ['d', 'k']

        # mixed insertion behavior
        assert db.pses.put(keys=key, vals=[b'k', b'c']) == True  # True because 'c' is new
        assert db.pses.get(keys=key) == deserialized_vals + ['d', 'k', 'c']

        # insertion after deletion
        assert db.pses.rem(keys=key, val=b'd') == True   # remove a specific val
        assert db.pses.get(keys=key) == deserialized_vals + ['k', 'c']   # d removed
        assert db.pses.add(keys=key, val=b'd') == True   # add d back
        assert db.pses.get(keys=key) == deserialized_vals + ['k', 'c', 'd']   # d added back

        # empty insertion
        assert db.pses.put(keys=key, vals=[]) == False # no vals to add
        assert db.pses.get(keys=key) == deserialized_vals + ['k', 'c', 'd'] # no change

        assert db.pses.add(keys=key, val=b'') == True  # empty val is allowed
        assert db.pses.get(key) == deserialized_vals + ['k', 'c', 'd',''] # empty val added

        # clean up
        assert db.pses.rem(keys=key) == True
        assert db.pses.get(keys=key) == []

        # different key types insertion
        assert db.pses.put(keys='B', vals=[b'1', b'2']) == True   # key as str
        assert db.pses.add(keys='B', val=b'3') == True
        assert db.pses.put(keys=['B'], vals=b'4') == True  # key as list
        assert db.pses.add(keys=['B'], val=b'5') == True
        assert db.pses.put(keys=("B"), vals=b'6') == True # key as tuple
        assert db.pses.add(keys=("B"), val=b'7') == True
        assert db.pses.put(keys=memoryview(b'B'), vals=b'8') == True  # key as memoryview
        assert db.pses.add(keys=memoryview(b'B'), val=b'9') == True
        assert db.pses.get(keys=b'B') == ['1', '2', '3', '4', '5', '6', '7', '8', '9']

        # clean up
        assert db.pses.rem(keys=b'B') == True
        assert db.pses.get(keys=b'B') == []

        # edge case: add different types of vals
        assert db.pses.put(keys=key, vals=[b'a','a']) == True
        assert db.pses.get(keys=key) == ['a', 'a'] # both value added because _ser produces different bytes

        assert db.pses.rem(keys=key) == True
        assert db.pses.get(keys=key) == []


        # test .pses retrieval behavior methods
        # insertion order preserved
        assert db.pses.put(keys=pre, on=sn, vals=vals) == True
        assert db.pses.get(keys=pre, on=sn) == deserialized_vals
        assert list(db.pses.getIter(keys=pre, on=sn)) == deserialized_vals
        assert db.pses.getLast(keys=pre, on=sn) == deserialized_vals[-1]
        assert db.pses.cntAll(keys=pre, on=sn) == len(vals) == 4

        # retrieval on empty list
        assert db.pses.get(keys=b'X') == []
        assert list(db.pses.getIter(b'X')) == []
        assert db.pses.getLast(keys=b'X') == None
        assert db.pses.cntAll(keys=b'X') == 0
        items = db.pses.getTopItemIter(keys=b'X')
        assert list(items) == []

        # getTopItemIter retrieval of (key, val) pairs in lexicographic key order
        items = list(db.pses.getAllItemIter())
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]  # Insertion order preserved for vals
        items = list(db.pses.getTopItemIter(keys=key))
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]
        keysB = (b'B', b'C')
        assert db.pses.put(keys=keysB, vals=[b'1', b'2', b'3']) == True
        items = list(db.pses.getTopItemIter(keys=keysB))
        assert items == [(('B', 'C'), 0, '1'), (('B', 'C'), 0, '2'), (('B', 'C'), 0, '3')]
        items = list(db.pses.getTopItemIter(keys=keysB[0]))  # top key first element
        assert items == [(('B', 'C'), 0, '1'), (('B', 'C'), 0, '2'), (('B', 'C'), 0, '3')]


        # retrieval with different key types, A is the key used above where key = b'A'
        assert db.pses.get(keys=b'A') == deserialized_vals  # key as bytes
        assert db.pses.get(keys='A') == deserialized_vals  # key as str
        assert db.pses.get(keys=['A']) == deserialized_vals  # key as list
        assert db.pses.get(keys=('A',)) == deserialized_vals  # key as tuple
        assert db.pses.get(keys=memoryview(b'A')) == deserialized_vals  # key as memoryview

        # retrieval afterd deletion of specific val
        assert db.pses.getLast(keys=pre, on=sn) == 'a'              # vals = [b"z", b"m", b"x", b"a"]
        assert db.pses.rem(keys=pre, on=sn, val=b'a') == True           # vals = [b"z", b"m", b"x"]
        assert db.pses.get(keys=pre, on=sn) == ['z', 'm', 'x']
        assert db.pses.getLast(keys=pre, on=sn) == 'x'
        assert db.pses.cntAll(keys=pre, on=sn) == 3

        # clean up
        assert db.pses.rem(keys=pre, on=sn) == True


        # test .pses pinning behavior method
        # start clean
        assert db.pses.get(keys=key) == []
        assert db.pses.put(keys=key, vals=vals) == True
        assert db.pses.get(keys=key) == deserialized_vals
        assert db.pses.pin(keys=key, vals=[b'a', b'b', b'c']) == True
        assert db.pses.get(keys=key) == ['a', 'b', 'c']  # exact overwrite

        # pin with a different list
        assert db.pses.pin(keys=key, vals=[b'x', b'y']) == True
        assert db.pses.get(keys=key) == ['x', 'y']  # previous values removed

        # pin with empty list (valid use case)
        assert db.pses.pin(keys=key, vals=[]) == False  # nothing to pin
        assert db.pses.get(keys=key) == []  # key cleared

        # pin after normal insertion
        assert db.pses.put(keys=key, vals=[b'1', b'2']) == True
        assert db.pses.get(keys=key) == ['1', '2']
        assert db.pses.pin(keys=key, vals=[b'Q']) == True
        assert db.pses.get(keys=key) == ['Q']  # overwritten

        # edge case: pin with mixed types
        assert db.pses.pin(keys=key, vals=[b'A', 'A', memoryview(b'A')]) == True
        assert db.pses.get(keys=key) == ['A', 'A', 'A']

        # cleanup
        assert db.pses.rem(keys=key) == True
        assert db.pses.get(keys=key) == []


        # test .pses deletion methods
        # delete specific val
        assert db.pses.put(keys=key, vals=vals) == True
        assert db.pses.rem(keys=key, val=b'm') == True
        assert db.pses.get(keys=key) == ['z', 'x', 'a']

        # delete non existing val
        assert db.pses.rem(keys=key, val=b'y') == False
        assert db.pses.get(keys=key) == ['z', 'x', 'a']

        # delete all vals
        assert db.pses.rem(keys=key) == True
        assert db.pses.get(keys=key) == []
        assert db.pses.cntAll(keys=key) == 0 # all vals deleted

        # delete non existing key
        assert db.pses.rem(keys=b'X') == False

        # insert other keys to ensure only specified key is deleted
        assert db.pses.put(keys=b'A', vals=[b'1']) == True
        assert db.pses.put(keys=b'B', vals=[b'2']) == True
        assert db.pses.rem(keys=b'A') == True
        assert db.pses.get(keys=b'B') == ['2']

        # clean up all entries
        for k, sn, v in list(db.pses.getAllItemIter()):
            assert db.pses.rem(keys=k, on=sn, val=v) == True

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

        assert db.pses.put(keys=pre, on=1, vals=aVals)
        assert db.pses.put(keys=pre, on=2, vals=bVals)
        assert db.pses.put(keys=pre, on=4, vals=cVals)
        assert db.pses.put(keys=pre, on=7, vals=dVals)

        # Test getPseItemsNextIter(key=b"")
        # vals are in bytes, assertion is done after serializing

        # aVals
        items = [item for item in db.pses.getTopItemIter()]
        assert items == \
        [
            (('A',), 1, 'z'),
            (('A',), 1, 'm'),
            (('A',), 1, 'x'),
            (('A',), 2, 'o'),
            (('A',), 2, 'r'),
            (('A',), 2, 'z'),
            (('A',), 4, 'h'),
            (('A',), 4, 'n'),
            (('A',), 7, 'k'),
            (('A',), 7, 'b')
        ]

        # avals
        items = [item for item in db.pses.getTopItemIter(keys=aKey)]
        assert items == [(('A',), 1, 'z'), (('A',), 1, 'm'), (('A',), 1, 'x')]

        # bVals
        items = [item for item in db.pses.getTopItemIter(keys=bKey)]
        assert items  == [(('A',), 2, 'o'), (('A',), 2, 'r'), (('A',), 2, 'z')]
        for keys, on, val in items:
            assert db.pses.rem(keys=keys, on=on, val=val) == True

        # cVals
        items = [item for item in db.pses.getTopItemIter(keys=cKey)]
        assert items == [(('A',), 4, 'h'), (('A',), 4, 'n')]
        for keys, on, val in items:
            assert db.pses.rem(keys=keys, on=on, val=val) == True

        # dVals
        items = [item for item in db.pses.getTopItemIter(keys=dKey)]
        assert items == [(('A',), 7, 'k'), (('A',), 7, 'b')]
        for keys, on, val in items:
            assert db.pses.rem(keys=keys, on=on, val=val) == True

        # clean up all entries
        for k, sn, v in list(db.pses.getAllItemIter()):
            db.pses.rem(keys=k)

        # test _tokey and _tokeys
        t = db.ooes._tokey(aKey)
        assert db.ooes._tokeys(t) == ("A", "00000000000000000000000000000001")


        # Test .udes partial delegated escrow seal source couples
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # test .pdes methods
        assert isinstance(db.pdes, OnIoDupSuber)


        # test .udes CatCesrSuber sub db methods
        assert isinstance(db.udes, CatCesrSuber)
        assert db.udes.klas == (Number, Diger)

        ssnu1 = b'0AAAAAAAAAAAAAAAAAAAAAAB'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        ssnu2 = b'0AAAAAAAAAAAAAAAAAAAAAAC'
        sdig2 = b'EBYYJRCCpAGO7WjjsLhtHVR37Pawv67kveIFUPvt38x0'
        val1 = ssnu1 + sdig1
        num1 = Number(qb64b=ssnu1)
        val2 = ssnu2 + sdig2
        num2 = Number(qb64b=ssnu2)
        diger1 = Diger(qb64b=sdig1)
        diger2 = Diger(qb64b=sdig2)

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

        assert db.pwes.get(key) == []
        assert db.pwes.cntAll(key) == 0
        assert db.pwes.rem(key) == False
        assert db.pwes.put(keys=key, vals=vals) == True
        assert db.pwes.get(key) == deserializedVals  # preserved insertion order
        assert db.pwes.cntAll(key) == len(vals) == 4
        assert list(db.pwes.getLastIter(key))[0] == deserializedVals[-1]
        assert db.pwes.put(key, vals=[b'a']) == False   # duplicate
        assert db.pwes.get(key) == deserializedVals  #  no change
        assert db.pwes.add(keys=key, val=b"a") == False   # duplicate
        assert db.pwes.add(keys=key, val=b"b") == True
        assert db.pwes.get(key) == deserializedVals + ['b']
        assert [val for val in db.pwes.getIter(key)] == deserializedVals + ['b']
        assert db.pwes.rem(key) == True
        assert db.pwes.get(key) == []

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

        assert db.pwes.put(keys=pre, on=aSn, vals=aVals)
        assert db.pwes.put(keys=pre, on=bSn, vals=bVals)
        assert db.pwes.put(keys=pre, on=cSn, vals=cVals)
        assert db.pwes.put(keys=pre, on=dSn, vals=dVals)


        # Test getOnItemIterAll()
        #  get dups at first key in database
        # aVals
        items = [item for item in db.pwes.getAllItemIter()]
        assert items  # not empty
        ikey = snKey(items[0][0][0], items[0][1])
        assert  ikey == aKey
        vals = [db.pwes._ser(val) for  key, sn, val in items]
        assert vals ==  aVals + bVals + cVals + dVals

        items = [item for item in db.pwes.getTopItemIter()]
        assert items == \
        [
            (('A',), 1, 'z'),
            (('A',), 1, 'm'),
            (('A',), 1, 'x'),
            (('A',), 2, 'o'),
            (('A',), 2, 'r'),
            (('A',), 2, 'z'),
            (('A',), 4, 'h'),
            (('A',), 4, 'n'),
            (('A',), 7, 'k'),
            (('A',), 7, 'b')
        ]

        # avals
        items = [item for item in db.pwes.getTopItemIter(keys=aKey)]
        assert items == [(('A',), 1, 'z'), (('A',), 1, 'm'), (('A',), 1, 'x')]

        # bVals
        items = [item for item in db.pwes.getTopItemIter(keys=bKey)]
        assert items  == [(('A',), 2, 'o'), (('A',), 2, 'r'), (('A',), 2, 'z')]
        for keys, on, val in items:
            assert db.pwes.rem(keys=keys, on=on, val=val) == True

        # cVals
        items = [item for item in db.pwes.getTopItemIter(keys=cKey)]
        assert items == [(('A',), 4, 'h'), (('A',), 4, 'n')]
        for keys, on, val in items:
            assert db.pwes.rem(keys=keys, on=on, val=val) == True

        # dVals
        items = [item for item in db.pwes.getTopItemIter(keys=dKey)]
        assert items == [(('A',), 7, 'k'), (('A',), 7, 'b')]
        for keys, on, val in items:
            assert db.pwes.rem(keys=keys, on=on, val=val) == True


        # Unverified Witness Receipt Escrows
        # test .uwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [('z',), ('m',), ('x',), ('a',)]

        assert db.uwes.get(key) == []  # default on = 0
        assert db.uwes.getLast(key) == None
        assert db.uwes.cnt(key) == 0
        assert db.uwes.rem(key) == False
        assert db.uwes.put(key, on=0, vals=vals) == True
        assert db.uwes.get(key, 0) == vals # preserved insertion order
        assert db.uwes.cnt(key, 0) == len(vals) == 4
        assert db.uwes.getLast(key, 0) == vals[-1]
        assert db.uwes.put(key, 0, vals=[b'a']) == False   # duplicate
        assert db.uwes.get(key, 0) == vals  #  no change
        assert db.uwes.add(key, 0, b'a') == False   # duplicate
        assert db.uwes.add(key, 0, b'b') == True
        assert db.uwes.get(key, 0) == [('z',), ('m',), ('x',), ('a',), ('b',)]
        assert [val for key, on, val in db.uwes.getTopItemIter(key)] == \
        [('z',), ('m',), ('x',), ('a',), ('b',)]
        assert db.uwes.rem(key, 0) == True
        assert db.uwes.get(key, 0) == []

        # Setup Tests
        keys = ("A", )
        assert db.uwes.put(keys=keys, on=1, vals=aVals)
        assert db.uwes.put(keys=keys, on=2, vals=bVals)
        assert db.uwes.put(keys=keys, on=4, vals=cVals)
        assert db.uwes.put(keys=keys, on=7, vals=dVals)

        items = [item for item in db.uwes.getTopItemIter()]
        assert items == \
        [
            (('A',), 1, ('z',)),
            (('A',), 1, ('m',)),
            (('A',), 1, ('x',)),
            (('A',), 2, ('o',)),
            (('A',), 2, ('r',)),
            (('A',), 2, ('z',)),
            (('A',), 4, ('h',)),
            (('A',), 4, ('n',)),
            (('A',), 7, ('k',)),
            (('A',), 7, ('b',))
        ]



        # Ooes tests
        # test .ooes insertion behavior methods.
        pre = 'A'
        sn = 0
        key = snKey(pre, sn)
        vals = [b"z", b"m", b"x", b"a"]
        deserialized_vals = [db.ooes._des(val) for val in vals] # deserialize for assertion

        # core insertion
        assert db.ooes.get(keys=key) == []
        assert db.ooes.cntAll(key) == 0
        assert db.ooes.rem(key) == False

        # initial insertion
        assert db.ooes.put(keys=key, vals=vals) == True
        assert db.ooes.get(key) == deserialized_vals    #sanity check

        # duplication insertion behavior
        assert db.ooes.put(keys=key,vals=[b'd', b'k']) == True
        assert db.ooes.put(keys=key,vals=[b'd']) == False  # duplicate
        assert db.ooes.put(keys=key,vals=[b'k']) == False  # duplicate
        assert db.ooes.put(keys=key,vals=[b'k',b'd',b'k']) == False
        assert db.ooes.add(keys=key, val=b'd') == False  # duplicate
        assert db.ooes.add(keys=key, val=b'k') == False
        assert db.ooes.get(keys=key) == deserialized_vals + ['d', 'k']

        # mixed insertion behavior
        assert db.ooes.put(keys=key,vals=[b'k', b'c']) == True  # True because 'c' is new
        assert db.ooes.get(keys=key) == deserialized_vals + ['d', 'k', 'c']

        # insertion after deletion
        assert db.ooes.rem(keys=key, val=b'd') == True   # remove a specific val
        assert db.ooes.get(keys=key) == deserialized_vals + ['k', 'c']   # d removed
        assert db.ooes.add(keys=key,val=b'd') == True   # add d back
        assert db.ooes.get(keys=key) == deserialized_vals + ['k', 'c', 'd']   # d added back

        # empty insertion
        assert db.ooes.put(keys=key, vals=[]) == False # no vals to add
        assert db.ooes.get(keys=key) == deserialized_vals + ['k', 'c', 'd'] # no change

        assert db.ooes.add(keys=key, val=b'') == True  # empty val is allowed
        assert db.ooes.get(keys=key) == deserialized_vals + ['k', 'c', 'd',''] # empty val added

        # clean up
        assert db.ooes.rem(key) == True
        assert db.ooes.get(keys=key) == []

        # different key types insertion
        assert db.ooes.put(keys='B', vals=[b'1', b'2']) == True   # key as str
        assert db.ooes.add(keys='B', val=b'3') == True
        assert db.ooes.put(['B'], vals=b'4') == True  # key as list
        assert db.ooes.add(keys=['B'], val=b'5') == True
        assert db.ooes.put(("B"), vals=b'6') == True # key as tuple
        assert db.ooes.add(keys=("B"), val=b'7') == True
        assert db.ooes.put(memoryview(b'B'),vals= b'8') == True  # key as memoryview
        assert db.ooes.add(keys=memoryview(b'B'), val=b'9') == True
        assert db.ooes.get(keys=b'B') == ['1', '2', '3', '4', '5', '6', '7', '8', '9']

        # clean up
        assert db.ooes.rem(b'B') == True
        assert db.ooes.get(keys=b'B') == []

        # edge case: add different types of vals
        assert db.ooes.put(key,vals=[b'a','a']) == True
        assert db.ooes.get(keys=key) == ['a', 'a'] # both value added because _ser produces different bytes

        assert db.ooes.rem(key) == True
        assert db.ooes.get(keys=key) == []


        # test .ooes retrieval behavior methods
        # insertion order preserved
        assert db.ooes.put(keys=pre,on=sn, vals=vals) == True
        assert db.ooes.get(keys=pre,on=sn) == deserialized_vals
        assert list(db.ooes.getAllIter(pre,on=sn)) == deserialized_vals
        assert db.ooes.getLast(keys=pre, on=sn) == deserialized_vals[-1]
        assert db.ooes.cntAll(pre,on=sn) == len(vals) == 4

        # retrieval on empty list
        assert db.ooes.get(keys=b'X') == []
        assert list(db.ooes.getAllIter(b'X')) == []
        assert db.ooes.getLast(keys=b'X') == None
        assert db.ooes.cntAll(b'X') == 0
        items = db.ooes.getAllItemIter(keys=b'X')
        assert list(items) == []

        # getTopItemIter retrieval of (key, val) pairs in lexicographic key order
        items = list(db.ooes.getAllItemIter())
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]  # Insertion order preserved for vals
        assert db.ooes.put(keys=[b'B', b'C'], vals=[b'1', b'2', b'3']) == True
        items = list(db.ooes.getAllItemIter(keys=key))
        assert all(k[0] == 'A' for k, sn, v in items)

        # retrieval with different key types, A is the key used above where key = b'A'
        assert db.ooes.get(keys=b'A') == deserialized_vals  # key as bytes
        assert db.ooes.get(keys='A') == deserialized_vals  # key as str
        assert db.ooes.get(keys=['A']) == deserialized_vals  # key as list
        assert db.ooes.get(keys=('A',)) == deserialized_vals  # key as tuple
        assert db.ooes.get(keys=memoryview(b'A')) == deserialized_vals  # key as memoryview

        # retrieval afterd deletion of specific val
        assert db.ooes.getLast(keys=pre, on=sn) == 'a'              # vals = [b"z", b"m", b"x", b"a"]
        assert db.ooes.rem(keys=pre,on=sn, val=b'a') == True           # vals = [b"z", b"m", b"x"]
        assert db.ooes.get(keys=pre,on=sn,) == ['z', 'm', 'x']
        assert db.ooes.getLast(keys=pre, on=sn) == 'x'
        assert db.ooes.cntAll(pre,on=sn) == 3

        # clean up
        assert db.ooes.rem(pre,on=sn) == True


        # test .ooes pinning behavior method
        # start clean
        assert db.ooes.get(keys=key) == []
        assert db.ooes.put(keys=key, vals=vals) == True
        assert db.ooes.get(keys=key) == deserialized_vals
        assert db.ooes.pin(keys=key, vals=[b'a', b'b', b'c']) == True
        assert db.ooes.get(keys=key) == ['a', 'b', 'c']  # exact overwrite

        # pin with a different list
        assert db.ooes.pin(keys=key, vals=[b'x', b'y']) == True
        assert db.ooes.get(keys=key) == ['x', 'y']  # previous values removed

        # pin with empty list (valid use case)
        assert db.ooes.pin(keys=key, vals=[]) == False  # nothing to pin
        assert db.ooes.get(keys=key) == []  # key cleared

        # pin after normal insertion
        assert db.ooes.put(keys=key, vals=[b'1', b'2']) == True
        assert db.ooes.get(keys=key) == ['1', '2']
        assert db.ooes.pin(keys=key, vals=[b'Q']) == True
        assert db.ooes.get(keys=key) == ['Q']  # overwritten

        # edge case: pin with mixed types
        assert db.ooes.pin(keys=key, vals=[b'A', 'A', memoryview(b'A')]) == True
        assert db.ooes.get(keys=key) == ['A', 'A', 'A']

        # cleanup
        assert db.ooes.rem(key) == True
        assert db.ooes.get(keys=key) == []


        # test .ooes deletion methods
        # delete specific val
        assert db.ooes.put(key, vals=vals) == True
        assert db.ooes.rem(key, val=b'm') == True
        assert db.ooes.get(keys=key) == ['z', 'x', 'a']

        # delete non existing val
        assert db.ooes.rem(key, val=b'y') == False
        assert db.ooes.get(keys=key) == ['z', 'x', 'a']

        # delete all vals
        assert db.ooes.rem(key) == True
        assert db.ooes.get(keys=key) == []
        assert db.ooes.cntAll(key) == 0 # all vals deleted

        # delete non existing key
        assert db.ooes.rem(b'X') == False

        # insert other keys to ensure only specified key is deleted
        assert db.ooes.put(b'A', vals=[b'1']) == True
        assert db.ooes.put(b'B', vals=[b'2']) == True
        assert db.ooes.rem(b'A') == True
        assert db.ooes.get(keys=b'B') == ['2']

        # clean up all entries
        for k, sn, v in list(db.ooes.getAllItemIter()):
            assert db.ooes.rem(keys=k, on=sn, val=v) == True


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

        assert db.ooes.put(keys=pre, on=1, vals=aVals)
        assert db.ooes.put(keys=pre, on=2, vals=bVals)
        assert db.ooes.put(keys=pre, on=4, vals=cVals)
        assert db.ooes.put(keys=pre, on=7, vals=dVals)



        # avals
        items = [item for item in db.ooes.getTopItemIter(keys=aKey)]
        assert items == [(('A',), 1, 'z'), (('A',), 1, 'm'), (('A',), 1, 'x')]

        # bVals
        items = [item for item in db.ooes.getTopItemIter(keys=bKey)]
        assert items  == [(('A',), 2, 'o'), (('A',), 2, 'r'), (('A',), 2, 'z')]
        for keys, on, val in items:
            assert db.ooes.rem(keys=keys, on=on, val=val) == True

        # cVals
        items = [item for item in db.ooes.getTopItemIter(keys=cKey)]
        assert items == [(('A',), 4, 'h'), (('A',), 4, 'n')]
        for keys, on, val in items:
            assert db.ooes.rem(keys=keys, on=on, val=val) == True

        # dVals
        items = [item for item in db.ooes.getTopItemIter(keys=dKey)]
        assert items == [(('A',), 7, 'k'), (('A',), 7, 'b')]
        for keys, on, val in items:
            assert db.ooes.rem(keys=keys, on=on, val=val) == True

        # clean up all entries
        for k, sn, v in list(db.pses.getAllItemIter()):
            db.ooes.rem(keys=k)

        # test _tokey and _tokeys
        t = db.ooes._tokey(aKey)
        assert db.ooes._tokeys(t) == ("A", "00000000000000000000000000000001")


        # test .dels insertion order dup methods.  dup vals are insertion order
        keys = b'A'
        on = 0
        vals = ["z", "m", "x", "a"]

        assert db.dels.get(keys=keys, on=on) == []
        result = db.dels.get(keys=keys, on=on)
        assert (result[-1] if result else None) == None
        assert len(db.dels.get(keys=keys, on=on)) == 0
        assert db.dels.rem(keys=keys, on=on) == False
        for val in vals:
            db.dels.add(keys=keys, on=on, val=val)
        assert db.dels.get(keys=keys, on=on) == vals  # preserved insertion order
        assert len(db.dels.get(keys=keys, on=on)) == len(vals) == 4
        result = db.dels.get(keys=keys, on=on)
        assert result[-1] == vals[-1]
        assert db.dels.add(keys=keys, on=on, val='a') == False   # duplicate
        assert db.dels.get(keys=keys, on=on) == vals  #  no change
        assert db.dels.add(keys=keys, on=on, val='a') == False   # duplicate
        assert db.dels.add(keys=keys, on=on, val='b') == True
        assert db.dels.get(keys=keys, on=on) == ["z", "m", "x", "a", "b"]
        assert db.dels.rem(keys=keys, on=on) == True
        assert db.dels.get(keys=keys, on=on) == []

        # test .ldes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert db.ldes.get(keys=key) == []
        assert db.ldes.getLast(keys=key) == None
        assert db.ldes.cnt(keys=key) == 0
        assert db.ldes.rem(keys=key) == False
        # put is not fully compatible with putLdes because putLdes took list of vals
        # and IoDupSuber.put takes iterable of vals.
        assert db.ldes.put(keys=key, on=0, vals=vals) == True
        # OnIoDupSuber decodes bytes to utf-8 strings
        assert db.ldes.get(keys=key) == [v.decode("utf-8") for v in vals]
        assert db.ldes.cnt(keys=key) == len(vals) == 4
        assert db.ldes.getLast(keys=key) == vals[-1].decode("utf-8")
        assert db.ldes.put(keys=key, on=0, vals=[b'a']) == False   # duplicate
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
            assert db.ldes.add(keys=b'A', on=1, val=val) == True
        for val in bVals:
            assert db.ldes.add(keys=b'A', on=2, val=val) == True
        for val in cVals:
            assert db.ldes.add(keys=b'A', on=4, val=val) == True
        for val in dVals:
            assert db.ldes.add(keys=b'A', on=7, val=val) == True

        # Test getOnItemIterAll - iterate all items for prefix b'A'
        items = [item for item in db.ldes.getAllItemIter(keys=b'A')]
        assert items  # not empty
        # item is (keys, on, val)
        vals = [val for pre, sn, val in items]
        allVals = aVals + bVals + cVals + dVals
        assert vals == [v.decode("utf-8") for v in allVals]

        # Iterate starting from specific ordinal (sn=1)
        items = [item for item in db.ldes.getAllItemIter(keys=b'A', on=1)]
        assert items
        pre, sn, val = items[0]
        assert sn == 1
        assert val == aVals[0].decode("utf-8")

        # Verify vals at sn=1
        vals = [val for p, s, val in items if s == 1]
        assert vals == [v.decode("utf-8") for v in aVals]

        # bVals at sn=2
        items = [item for item in db.ldes.getAllItemIter(keys=b'A', on=2)]
        vals = [val for p, s, val in items if s == 2]
        assert vals == [v.decode("utf-8") for v in bVals]
        # Remove bVals using remOn
        for p, s, val in items:
            if s == 2:
                assert db.ldes.rem(keys=b'A', on=s, val=val) == True

        # cVals at sn=4
        items = [item for item in db.ldes.getAllItemIter(keys=b'A', on=4)]
        vals = [val for p, s, val in items if s == 4]
        assert vals == [v.decode("utf-8") for v in cVals]
        for p, s, val in items:
            if s == 4:
                assert db.ldes.rem(keys=b'A', on=s, val=val) == True

        # dVals at sn=7
        items = [item for item in db.ldes.getAllItemIter(keys=b'A', on=7)]
        vals = [val for p, s, val in items if s == 7]
        assert vals == [v.decode("utf-8") for v in dVals]
        for p, s, val in items:
            if s == 7:
                assert db.ldes.rem(keys=b'A', on=s, val=val) == True

        # Test for gpse
        key = b'a'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        number = Number(num=0)
        diger = Diger(qb64=sdig1)

        assert db.gpse.get(key) == []   # gpse is empty
        assert db.gpse.add(keys=key, val=(number, diger)) == True   # add new entry with val as a tuple of number and diger

        val = db.gpse.get(key)  # returns Cesr tuple of (number, diger)
        num, dig = val[0]
        assert isinstance(num, Number)
        assert isinstance(dig, Diger)
        assert num.num == number.num
        assert dig.qb64 == diger.qb64

        assert db.gpse.rem(key) == True
        assert db.gpse.get(key) == []   # gpse is empty again

        # Saider and Seqner instead of Diger and Number
        seqner = Seqner(num=0)
        saider = Saider(qb64=sdig1)
        assert db.gpse.add(keys=key, val=(seqner, saider)) == True # val is not using Number and Diger type
        val = db.gpse.get(key)                                     # but it still gets validated
        assert val is not None
        seq, dig = val[0]   # returns Cesr tuple of (number, diger)

        assert isinstance(seq, Number) # Seqner gets converted to Number on read
        assert isinstance(dig, Diger)   # Saider gets converted to Diger on read
        assert seq.num == seqner.sn
        assert dig.qb64 == saider.qb64

        # test .imgs  CatCesrSuber with TypeMedia (Noncer, Noncer, Labeler, Texter)
        said_nonce = Noncer()  # random SAID nonce
        uuid_nonce = Noncer()  # random UUID blinding nonce
        mime_label = Labeler(label="image_png")  # MIME type label
        img_data = Texter(text="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk")

        img_key = "BIFKYlgMQk78iSSYjE5CWVeLj9UKgBfdfQRos5PK38Yp"
        assert db.imgs.get(keys=img_key) is None  # empty
        assert db.imgs.put(keys=img_key, val=(said_nonce, uuid_nonce, mime_label, img_data)) == True
        result = db.imgs.get(keys=img_key)
        assert result is not None
        rsaid, ruuid, rmime, rdata = result
        assert isinstance(rsaid, Noncer)
        assert isinstance(ruuid, Noncer)
        assert isinstance(rmime, Labeler)
        assert isinstance(rdata, Texter)
        assert rsaid.qb64 == said_nonce.qb64
        assert ruuid.qb64 == uuid_nonce.qb64
        assert rdata.text == img_data.text

        # overwrite with pin
        new_data = Texter(text="newdata")
        assert db.imgs.pin(keys=img_key, val=(said_nonce, uuid_nonce, mime_label, new_data)) == True
        result = db.imgs.get(keys=img_key)
        _, _, _, rdata2 = result
        assert rdata2.text == "newdata"

        assert db.imgs.rem(keys=img_key) == True
        assert db.imgs.get(keys=img_key) is None

        # test .iimgs  same format for local identifiers
        assert db.iimgs.put(keys=img_key, val=(said_nonce, uuid_nonce, mime_label, img_data)) == True
        result = db.iimgs.get(keys=img_key)
        assert result is not None
        rsaid, ruuid, rmime, rdata = result
        assert isinstance(rsaid, Noncer)
        assert isinstance(rdata, Texter)
        assert db.iimgs.rem(keys=img_key) == True
        assert db.iimgs.get(keys=img_key) is None

    assert not os.path.exists(db.path)

    """ End Test """


def test_baser_clone_all_pre_iter():
    """
    Test cloneAllPreIter yields first-seen event messages for all identifier
    prefixes in the database (fels getOnItemIterAll(keys=b'', on=0) path).
    """
    with openHby(name="test", base="test", temp=True) as hby:
        hab1 = hby.makeHab(name="alice", isith="1", icount=1)
        hab2 = hby.makeHab(name="bob", isith="1", icount=1)
        # Single shared db now has fels (and evts, sigs) for both identifiers
        msgs = list(hby.db.cloneAllPreIter())
        assert len(msgs) >= 2
        pres = set()
        for msg in msgs:
            serder = SerderKERI(raw=bytes(msg))
            pres.add(serder.pre)
        assert hab1.pre in pres
        assert hab2.pre in pres


def test_clean_baser():
    """
    Test Baser db clean clone method
    """
    name = "nat"
    # with openDB(name="nat") as natDB, keeping.openKS(name="nat") as natKS:
    with openHby(name=name, salt=Salter(raw=b'0123456789abcdef').qb64) as hby:  # default is temp=True
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
        ldig = natHab.db.kels.getLast(keys=natHab.pre, on=natHab.kever.sn)
        ldig = ldig.encode("utf-8")
        assert ldig == natHab.kever.serder.saidb
        serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
        assert serder.said == natHab.kever.serder.said
        state = natHab.db.states.get(keys=natHab.pre)  # Serder instance
        assert state.s == '6'
        assert state.f == '6'
        assert natHab.db.env.stat()['entries'] <= 101 #68

        # test reopenDB with reuse  (because temp)
        with reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = natHab.db.kels.getLast(keys=natHab.pre, on=natHab.kever.sn)
            ldig = ldig.encode("utf-8")
            assert ldig == natHab.kever.serder.saidb
            serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
            assert serder.said == natHab.kever.serder.said
            assert natHab.db.env.stat()['entries'] <= 101 #68

            # verify name pre kom in db
            data = natHab.db.habs.get(keys=natHab.pre)
            assert data.hid == natHab.pre

            # add garbage event to corrupt database
            badsrdr = rotate(pre=natHab.pre,
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
            assert natHab.db.fels.get(keys=natHab.pre, on=7)


        # test openDB copy db with clean
        with openDB(name=natHab.db.name,
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
        with reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = natHab.db.kels.getLast(keys=natHab.pre, on=natHab.kever.sn)
            ldig = ldig.encode("utf-8")
            assert ldig == natHab.kever.serder.saidb
            serder = natHab.db.evts.get(keys=(natHab.pre, ldig))
            assert serder.said == natHab.kever.serder.said
            assert natHab.db.env.stat()['entries'] >= 18

            # confirm bad event missing from database
            assert not natHab.db.evts.get(keys=(natHab.pre, badsrdr.said))
            assert not natHab.db.fels.get(keys=natHab.pre, on=7)
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
        assert db.kels.add(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert db.kels.add(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        for val in vals2:
            assert db.kels.add(keys=preb, on=sn, val=val) == True

        vals = list(db.kels.getAllIter(keys=preb))
        allvals = [v.decode("utf-8") for v in (vals0 + vals1 + vals2)]
        assert vals == allvals

        # test getKelEstIter
        preb = 'B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x'.encode("utf-8")
        sn = 0

        vals0 = [skedb]
        assert db.kels.add(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert db.kels.add(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        for val in vals2:
            assert db.kels.add(keys=preb, on=sn, val=val) == True

        vals = list(db.kels.getLastIter(keys=preb))
        lastvals = [v.decode("utf-8") for v in (vals0[-1], vals1[-1], vals2[-1])]
        assert vals == lastvals


        # test getDelItemIter
        preb = 'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw'.encode("utf-8")
        sn = 1  # do not start at zero
        key = snKey(preb, sn)
        assert key == (b'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw.'
                       b'00000000000000000000000000000001')
        vals0 = [skedb]
        assert db.dels.add(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert db.dels.add(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 3  # skip make gap in SN
        for val in vals2:
            assert db.dels.add(keys=preb, on=sn, val=val) == True

        allvals = vals0 + vals1 + vals2
        vals = [(val.encode("utf-8") if isinstance(val, str) else bytes(val))
            for keys, on, val in db.dels.getAllItemIter(keys=preb)]
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
                        ndigs=[Diger(ser=key).qb64 for key in nxtkeys])


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
                        ndigs=[Diger(ser=key).qb64 for key in nxtkeys],
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
    class TestRecord(RawRecord):
        x: str = ""
        y: int = 0

    record = TestRecord()

    assert isinstance(record, TestRecord)
    assert isinstance(record, RawRecord)

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
    seer = StateEERecord()
    assert seer.s == '0'
    assert seer.d == ''
    assert seer._asdict() == {'s': '0', 'd': '', 'br': [], 'ba': []}

    ksr = KeyStateRecord()

    assert isinstance(ksr, KeyStateRecord)
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

    dksr = datify(KeyStateRecord, ksn)
    assert dksr == ksr

    nksr = KeyStateRecord._fromdict(ksn)
    assert nksr == ksr
    assert nksr._asdict() == ksn


    """End Test"""

def test_eventsourcerecord():
    """
    Test EventSourceRecord dataclass
    """
    record = EventSourceRecord()  # default local is True
    assert isinstance(record, EventSourceRecord)
    assert record.local is True
    assert record.local
    assert "local" in record  # asdict means in is against the keys (labels)
    assert (asdict(record)) == {'local': True}

    record.local = False
    assert record.local is False
    assert not record.local
    assert (asdict(record)) == {'local': False}

    record = EventSourceRecord(local=False)
    assert isinstance(record, EventSourceRecord)
    assert record.local is False
    assert not record.local
    assert "local" in record  # asdict means in is against the keys (labels)
    assert (asdict(record)) == {'local': False}

    record = EventSourceRecord(local=None)
    assert isinstance(record, EventSourceRecord)
    assert record.local is None
    assert not record.local
    assert "local" in record  # asdict means in is against the keys (labels)
    assert (asdict(record)) == {'local': None}



    """End Test"""


def test_statedict():
    """
    Test custom statedict subclass of dict
    """
    dbd = statedict(a=1, b=2, c=3)  # init in memory so never acesses db
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

    with openDB(name="nat") as db:
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
        serder = interact(pre=pre, dig=dig, sn=4)

        eevt = StateEstEvent(s='3', d=dig, br=[], ba=[])

        state = eventState(pre=pre,
                           sn=4,
                           pig=dig,
                           dig=serder.said,
                           fn=4,
                           eilk=Ilks.ixn,
                           keys=[pre],
                           eevt=eevt,
                           )

        db.evts.put(keys=(pre, serder.said), val=serder)
        assert db.evts.get(keys=(pre, serder.said)) is not None

        db.states.pin(keys=pre, val=state)  # put state in database
        dbstate = db.states.get(keys=pre)
        assert dbstate is not None
        assert dbstate == state

        kever = Kever(state=state, db=db)
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
    db0 = Baser(name='test0', temp=True, reopen=False)
    assert db0.opened == False
    assert db0.path == None
    assert db0.env == None

    dbDoer0 = BaserDoer(baser=db0)
    assert dbDoer0.baser == db0
    assert dbDoer0.baser.opened == False

    db1 = Baser(name='test1', temp=True, reopen=False)
    assert db1.opened == False
    assert db1.path == None
    assert db1.env == None

    dbDoer1 = BaserDoer(baser=db1)
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
        d1 = Diger(ser=b"event1")                     # event digest
        p1 = Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        n1 = Number(num=1)
        e1 = Diger(ser=b"est1")                       # est event digest
        s1 = Siger(raw=b"\x00" * 64)                    # fake sig
        res_vals = [(d1, p1, n1, e1, s1)]

        db.ures.put(keys=key, vals=res_vals)
        db.vres.put(keys=key, vals=res_vals)
        db.pses.put(keys=key, vals=vals)
        for v in vals:
            db.pwes.add(keys=key, on=0, val=v)
        for v in vals:
            db.ooes.add(keys=key, on=0, val=v)

        db.ldes.put(keys=key, on=0, vals=vals)

        pre = b'k'
        sn = 0
        snh = b"%032x" % sn
        saidb = b'saidb'

        db.uwes.add(keys=pre, on=sn, val=saidb)
        assert db.uwes.cnt(keys=pre, on=sn) == 1

        db.qnfs.add(keys=(pre, saidb), val=b"z")
        assert db.qnfs.cnt(keys=(pre, saidb)) == 1

        db.misfits.add(keys=(pre, snh), val=saidb)
        assert db.misfits.cnt(keys=(pre, snh)) == 1

        db.delegables.add(snKey(pre, 0), saidb)
        assert db.delegables.cnt(keys=snKey(pre, 0)) == 1

        db.pdes.add(keys=pre, on=0, val=saidb)
        assert db.pdes.cnt(keys=pre, on=0) == 1

        udesKey = ('DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'.encode("utf-8"),
                    'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'.encode("utf-8"))
        db.udes.put(keys=udesKey, val=(Number(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'),
                                   Diger(qb64b=b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E')))
        assert db.udes.get(keys=udesKey) is not None

        diger = Diger(qb64b='EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4')
        db.rpes.put(keys=('route',), vals=[diger])
        assert db.rpes.cnt(keys=('route',)) == 1

        db.epsd.put(keys=('DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',), val=Dater())
        assert db.epsd.get(keys=('DAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',)) is not None

        db.eoobi.pin(keys=('url',), val=OobiRecord())
        assert db.eoobi.cnt() == 1

        serder = Serder(raw=b'{"v":"KERI10JSON0000cb_","t":"ixn","d":"EG8WAmM29ZBdoXbnb87yiPxQw4Y7gcQjqZS74vBAKsRm","i":"DApYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0","s":"4","p":"EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30","a":[]}')
        db.dpub.put(keys=(pre, 'said'), val=serder)
        assert db.dpub.get(keys=(pre, 'said')) is not None

        db.gpwe.add(keys=(pre,), val=(Seqner(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'), diger))
        assert db.gpwe.cnt(keys=(pre,)) == 1

        db.gdee.add(keys=(pre,), val=(Seqner(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'), diger))
        assert db.gdee.cnt(keys=(pre,)) == 1

        db.dpwe.pin(keys=(pre, 'said'), val=serder)
        assert db.dpwe.get(keys=(pre, 'said')) is not None

        db.gpse.add(keys=('qb64',), val=(Number(qb64b=b'0AAAAAAAAAAAAAAAAAAAAAAB'), diger))
        assert db.gpse.cnt(keys=('qb64',)) == 1

        db.epse.put(keys=('dig',), val=serder)
        assert db.epse.get(keys=('dig',)) is not None

        db.dune.pin(keys=(pre, 'said'), val=serder)
        assert db.dune.get(keys=(pre, 'said')) is not None

        db.clearEscrows()

        for escrow in [db.ures, db.vres, db.pses, db.pwes, db.ooes,
                       db.qnfs, db.uwes,
                       db.qnfs, db.misfits, db.delegables, db.pdes,
                       db.udes, db.rpes, db.ldes, db.epsd, db.eoobi,
                       db.dpub, db.gpwe, db.gdee, db.dpwe, db.gpse,
                       db.epse, db.dune]:
            assert escrow.cntAll() == 0



def test_trim_all_escrows_during_migration():
    """Regression test for issue #863: old qnfs key format crashes migration.

    When upgrading from keripy <1.2.0, qnfs entries lack the insertion-order
    suffix (e.g. 'PRE.SAID' instead of 'PRE.SAID.00000000'). The high-level
    iterators in clearEscrows() call unsuffix() which does int(SAID, 16) and
    crashes with ValueError.

    _trimAllEscrows() uses low-level .trim() which bypasses key parsing,
    safely clearing all escrow databases regardless of key format.
    """
    with openDB() as db:
        # Populate escrow databases with test data
        pre = b'k'
        saidb = b'saidb'
        vals = [b"z", b"m", b"x"]

        db.qnfs.add(keys=(pre, saidb), val=b"z")
        assert db.qnfs.cnt(keys=(pre, saidb)) == 1

        db.pses.put(keys=pre, vals=vals)
        assert db.pses.cnt(keys=pre) == 3

        ooes_key = (snKey(pre, 0),)
        db.ooes.put(keys=ooes_key, vals=vals)
        assert db.ooes.cntAll() > 0

        db.misfits.add(keys=(pre, b'snh'), val=saidb)
        assert db.misfits.cnt(keys=(pre, b'snh')) == 1

        # _trimAllEscrows clears everything via .trim()
        db._trimAllEscrows()

        assert db.qnfs.cntAll() == 0
        assert db.pses.cntAll() == 0
        assert db.ooes.cntAll() == 0
        assert db.misfits.cntAll() == 0
        assert db.ures.cntAll() == 0
        assert db.vres.cntAll() == 0
        assert db.pwes.cntAll() == 0
        assert db.uwes.cntAll() == 0
        assert db.delegables.cntAll() == 0
        assert db.pdes.cntAll() == 0
        assert db.udes.cntAll() == 0
        assert db.rpes.cntAll() == 0
        assert db.ldes.cntAll() == 0
        assert db.epsd.cntAll() == 0
        assert db.eoobi.cnt() == 0
        assert db.dpub.cntAll() == 0
        assert db.gpwe.cntAll() == 0
        assert db.gdee.cntAll() == 0
        assert db.dpwe.cntAll() == 0
        assert db.gpse.cntAll() == 0
        assert db.epse.cntAll() == 0
        assert db.dune.cntAll() == 0


def test_trim_all_escrows_old_key_format():
    """Regression test for issue #863: simulate old qnfs key format.

    Injects a raw LMDB entry with the old key format (no insertion-order
    suffix) directly into the qnfs sub-database, then verifies that
    _trimAllEscrows() clears it without crashing.
    """
    with openDB() as db:
        # Simulate an old-format qnfs key by writing directly to LMDB.
        # Old format: 'PRE.SAID' (no '.00000000' suffix)
        # New format: 'PRE.SAID.00000000'
        old_key = b'EBMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt.EBMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt'
        old_val = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        with db.env.begin(db=db.qnfs.sdb, write=True) as txn:
            txn.put(old_key, old_val)

        # Verify the entry exists
        with db.env.begin(db=db.qnfs.sdb) as txn:
            assert txn.get(old_key) == old_val

        # _trimAllEscrows must not crash on old key format
        db._trimAllEscrows()

        # Verify it was cleared
        with db.env.begin(db=db.qnfs.sdb) as txn:
            assert txn.get(old_key) is None
        assert db.qnfs.cntAll() == 0


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
            val = (dig, Prefixer(qb64=pre), cigar)
            db.ures.add(keys=("OLD", old_key), val=val)

        # new encoding (Number with Huge code)
        for sn in sns:
            new_key = Number(num=sn, code=NumDex.Huge).qb64
            dig = Diger(raw=b"\x01" * 32)     # distinguishable but valid
            val = (dig, Prefixer(qb64=pre), cigar)
            db.ures.add(keys=("NEW", new_key), val=val)

        # round-trip correctness for Number with Huge code
        for sn in sns:
            enc = Number(num=sn, code=NumDex.Huge).qb64
            parsed = Number(qb64=enc)
            assert parsed.num == sn

        # read back old and new keys (existence + type)
        for sn in sns:
            old_key = Seqner(sn=sn).qb64
            new_key = Number(num=sn, code=NumDex.Huge).qb64

            old_vals = db.ures.get(keys=("OLD", old_key))
            new_vals = db.ures.get(keys=("NEW", new_key))

            assert len(old_vals) == 1
            assert len(new_vals) == 1

            odig, opre, ocig = old_vals[0]
            ndig, npre, ncig = new_vals[0]

            assert isinstance(odig, Diger)
            assert isinstance(opre, Prefixer)
            assert isinstance(ncig, type(cigar))
            assert isinstance(ndig, Diger)
            assert isinstance(npre, Prefixer)

        # lexicographic ordering must match numeric ordering for NEW keys
        ordered_sns = []
        for (pre_key, key), vals in db.ures.getTopItemIter():
            if pre_key == "NEW":
                n = Number(qb64=key)
                ordered_sns.append(n.num)

        assert ordered_sns == sns


def test_semver_dev_tag_comparison():
    """Regression test for issue #820: semver dev tag lexicographic comparison.

    semver compares alphanumeric prerelease identifiers lexicographically,
    so 'dev4' > 'dev10' (because '4' > '1'). The _strip_prerelease helper
    normalizes version strings so dev releases within the same cycle compare
    correctly in migrate(), current, and complete().
    """
    import semver
    from keri.db.basing import _strip_prerelease

    # Core bug: dev4 should be LESS than dev10, but semver says otherwise
    assert semver.compare("1.2.0-dev4", "1.2.0-dev10") == 1  # broken by design
    assert semver.compare("1.2.0-dev10", "1.2.0-dev4") == -1  # broken by design

    # _strip_prerelease removes prerelease so both normalize to same base
    assert _strip_prerelease("1.2.0-dev4") == "1.2.0"
    assert _strip_prerelease("1.2.0-dev10") == "1.2.0"
    assert _strip_prerelease("1.2.0") == "1.2.0"
    assert _strip_prerelease("0.6.8") == "0.6.8"
    assert _strip_prerelease("1.2.0-rc1") == "1.2.0"
    assert _strip_prerelease("2.0.0-dev5+build42") == "2.0.0"

    # After stripping, migration version vs DB version compares correctly
    # Scenario: DB at 1.2.0-dev4, migration version 1.2.0
    #   Should skip (migration already within this cycle)
    db_ver = _strip_prerelease("1.2.0-dev4")
    assert semver.compare("1.2.0", db_ver) == 0  # equal, so skip

    # Scenario: DB at 1.0.0, migration version 1.2.0
    #   Should run (migration is newer)
    db_ver = _strip_prerelease("1.0.0")
    assert semver.compare("1.2.0", db_ver) == 1  # newer, so run

    # Scenario: DB at 1.2.0-dev10, checking if DB is ahead of lib 1.2.0-dev4
    #   Should NOT raise (same release cycle)
    db_stripped = _strip_prerelease("1.2.0-dev10")
    lib_stripped = _strip_prerelease("1.2.0-dev4")
    assert semver.compare(db_stripped, lib_stripped) == 0  # same cycle

    # Scenario: DB at 1.3.0-dev1, lib at 1.2.0 — DB IS ahead
    db_stripped = _strip_prerelease("1.3.0-dev1")
    assert semver.compare(db_stripped, "1.2.0") == 1  # correctly ahead

    # Scenario: complete() should list 1.2.0 migrations when DB is at 1.2.0-dev4
    db_ver = _strip_prerelease("1.2.0-dev4")
    assert semver.compare("1.2.0", db_ver) <= 0  # 0 <= 0, so list it


if __name__ == "__main__":
    test_baser()
    test_clean_baser()
    test_fetchkeldel()
    test_usebaser()
    test_statedict()
    test_baserdoer()
    test_db_keyspace_end_to_end_migration()
    test_trim_all_escrows_during_migration()
    test_trim_all_escrows_old_key_format()
    test_semver_dev_tag_comparison()
