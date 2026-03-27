# -*- encoding: utf-8 -*-
"""
tests.db.test_webbasing module

"""

import asyncio
import json

import pytest

from keri.db.webbasing import WebBaser, WebBaserDoer, _strip_prerelease

try:
    from keri.db import subing, koming, dgKey, snKey, statedict
except ImportError:
    subing = None
    koming = None

try:
    from keri.core import (serdering, coring, signing, Noncer, Labeler, Parser,
                        indexing, Number, Diger, Seqner, Saider, Texter, StateEstEvent,
                        SerderKERI, Salter, rotate, MtrDex, incept, interact,
                        Kever, Prefixer, Siger, Dater, Serder, Signer, NumDex, Kevery)
    from keri import versify, Kinds, Ilks
    from keri.recording import (EventSourceRecord, HabitatRecord, KeyStateRecord,
                            OobiRecord, RawRecord, StateEERecord)
except ImportError:
    # Pyodide fallback
    from keri.core import serdering

from keri.kering import Vrsn_1_0
from keri.core import state as eventState
from keri.app import openHby
from keri.help import datify, dictify
                            
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
        assert isinstance(baser.imgs, subing.CatCesrSuber)
        assert isinstance(baser.iimgs, subing.CatCesrSuber)

        await baser.aclose(clear=True)
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
        assert isinstance(baser.imgs, subing.CatCesrSuber)
        assert isinstance(baser.iimgs, subing.CatCesrSuber)

        await baser.aclose(clear=True)
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

        # test .kels insertion order dup methods.  dup vals are insertion order
        key = snKey(preb, 0)
        vals = [b"z", b"m", b"x", b"a"]
        deserializedVals = ["z", "m", "x", "a"]

        assert baser.kels.get(keys=key) == []
        assert baser.kels.getLast(keys=key)== None
        assert baser.kels.cntAll(keys=key) == 0
        assert baser.kels.rem(key) == False
        assert baser.kels.put(keys=key, vals=vals) == True
        assert baser.kels.get(keys=key) == deserializedVals  # preserved insertion order
        assert baser.kels.cntAll(keys=key) == len(vals) == 4
        assert baser.kels.getLast(keys=key) == deserializedVals[-1]
        assert baser.kels.put(keys=key, vals=[b'a']) == False   # duplicate
        assert baser.kels.get(keys=key) == deserializedVals  #  no change
        assert baser.kels.add(keys=key, val=b'a') == False   # duplicate
        assert baser.kels.add(keys=key, val=b'b') == True
        assert baser.kels.get(keys=key) == deserializedVals + ['b']
        assert baser.kels.rem(key) == True
        assert baser.kels.get(keys=key) == []

         # Partially Signed Escrow Events
        # test .pses insertion order dup methods.  dup vals are insertion order
        pre = b'A'
        sn = 0
        key = snKey(pre, sn)
        vals = [b"z", b"m", b"x", b"a"]
        deserialized_vals = [baser.pses._des(val) for val in vals] # deserialize for assertion

        # core insertion
        assert baser.pses.get(keys=key) == []
        assert baser.pses.getLast(keys=pre, on=sn) == None
        assert baser.pses.cntAll(keys=key) == 0
        assert baser.pses.rem(keys=key) == False

        # initial insertion
        assert baser.pses.put(keys=key, vals=vals) == True
        assert baser.pses.get(keys=key) == deserialized_vals    #sanity check

        # duplication insertion behavior
        assert baser.pses.put(keys=key, vals=[b'd', b'k']) == True
        assert baser.pses.put(keys=key, vals=[b'd']) == False  # duplicate
        assert baser.pses.put(keys=key, vals=[b'k']) == False  # duplicate
        assert baser.pses.put(keys=key, vals=[b'k',b'd',b'k']) == False
        assert baser.pses.add(keys=key, val=b'd') == False  # duplicate
        assert baser.pses.add(keys=key, val=b'k') == False
        assert baser.pses.get(keys=key) == deserialized_vals + ['d', 'k']

        # mixed insertion behavior
        assert baser.pses.put(keys=key, vals=[b'k', b'c']) == True  # True because 'c' is new
        assert baser.pses.get(keys=key) == deserialized_vals + ['d', 'k', 'c']

        # insertion after deletion
        assert baser.pses.rem(keys=key, val=b'd') == True   # remove a specific val
        assert baser.pses.get(keys=key) == deserialized_vals + ['k', 'c']   # d removed
        assert baser.pses.add(keys=key, val=b'd') == True   # add d back
        assert baser.pses.get(keys=key) == deserialized_vals + ['k', 'c', 'd']   # d added back

        # empty insertion
        assert baser.pses.put(keys=key, vals=[]) == False # no vals to add
        assert baser.pses.get(keys=key) == deserialized_vals + ['k', 'c', 'd'] # no change

        assert baser.pses.add(keys=key, val=b'') == True  # empty val is allowed
        assert baser.pses.get(key) == deserialized_vals + ['k', 'c', 'd',''] # empty val added

        # clean up
        assert baser.pses.rem(keys=key) == True
        assert baser.pses.get(keys=key) == []

        # different key types insertion
        assert baser.pses.put(keys='B', vals=[b'1', b'2']) == True   # key as str
        assert baser.pses.add(keys='B', val=b'3') == True
        assert baser.pses.put(keys=['B'], vals=b'4') == True  # key as list
        assert baser.pses.add(keys=['B'], val=b'5') == True
        assert baser.pses.put(keys=("B"), vals=b'6') == True # key as tuple
        assert baser.pses.add(keys=("B"), val=b'7') == True
        assert baser.pses.put(keys=memoryview(b'B'), vals=b'8') == True  # key as memoryview
        assert baser.pses.add(keys=memoryview(b'B'), val=b'9') == True
        assert baser.pses.get(keys=b'B') == ['1', '2', '3', '4', '5', '6', '7', '8', '9']

        # clean up
        assert baser.pses.rem(keys=b'B') == True
        assert baser.pses.get(keys=b'B') == []

        # edge case: add different types of vals
        assert baser.pses.put(keys=key, vals=[b'a','a']) == True
        assert baser.pses.get(keys=key) == ['a'] # only 1 value added

        assert baser.pses.rem(keys=key) == True
        assert baser.pses.get(keys=key) == []


        # test .pses retrieval behavior methods
        # insertion order preserved
        assert baser.pses.put(keys=pre, on=sn, vals=vals) == True
        assert baser.pses.get(keys=pre, on=sn) == deserialized_vals
        assert list(baser.pses.getIter(keys=pre, on=sn)) == deserialized_vals
        assert baser.pses.getLast(keys=pre, on=sn) == deserialized_vals[-1]
        assert baser.pses.cntAll(keys=pre, on=sn) == len(vals) == 4

        # retrieval on empty list
        assert baser.pses.get(keys=b'X') == []
        assert list(baser.pses.getIter(b'X')) == []
        assert baser.pses.getLast(keys=b'X') == None
        assert baser.pses.cntAll(keys=b'X') == 0
        items = baser.pses.getTopItemIter(keys=b'X')
        assert list(items) == []

        # getTopItemIter retrieval of (key, val) pairs in lexicographic key order
        items = list(baser.pses.getAllItemIter())
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]  # Insertion order preserved for vals
        items = list(baser.pses.getTopItemIter(keys=key))
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]
        keysB = (b'B', b'C')
        assert baser.pses.put(keys=keysB, vals=[b'1', b'2', b'3']) == True
        items = list(baser.pses.getTopItemIter(keys=keysB))
        assert items == [(('B', 'C'), 0, '1'), (('B', 'C'), 0, '2'), (('B', 'C'), 0, '3')]
        items = list(baser.pses.getTopItemIter(keys=keysB[0]))  # top key first element
        assert items == [(('B', 'C'), 0, '1'), (('B', 'C'), 0, '2'), (('B', 'C'), 0, '3')]


        # retrieval with different key types, A is the key used above where key = b'A'
        assert baser.pses.get(keys=b'A') == deserialized_vals  # key as bytes
        assert baser.pses.get(keys='A') == deserialized_vals  # key as str
        assert baser.pses.get(keys=['A']) == deserialized_vals  # key as list
        assert baser.pses.get(keys=('A',)) == deserialized_vals  # key as tuple
        assert baser.pses.get(keys=memoryview(b'A')) == deserialized_vals  # key as memoryview

        # retrieval afterd deletion of specific val
        assert baser.pses.getLast(keys=pre, on=sn) == 'a'              # vals = [b"z", b"m", b"x", b"a"]
        assert baser.pses.rem(keys=pre, on=sn, val=b'a') == True           # vals = [b"z", b"m", b"x"]
        assert baser.pses.get(keys=pre, on=sn) == ['z', 'm', 'x']
        assert baser.pses.getLast(keys=pre, on=sn) == 'x'
        assert baser.pses.cntAll(keys=pre, on=sn) == 3

        # clean up
        assert baser.pses.rem(keys=pre, on=sn) == True


        # test .pses pinning behavior method
        # start clean
        assert baser.pses.get(keys=key) == []
        assert baser.pses.put(keys=key, vals=vals) == True
        assert baser.pses.get(keys=key) == deserialized_vals
        assert baser.pses.pin(keys=key, vals=[b'a', b'b', b'c']) == True
        assert baser.pses.get(keys=key) == ['a', 'b', 'c']  # exact overwrite

        # pin with a different list
        assert baser.pses.pin(keys=key, vals=[b'x', b'y']) == True
        assert baser.pses.get(keys=key) == ['x', 'y']  # previous values removed

        # pin with empty list (valid use case)
        assert baser.pses.pin(keys=key, vals=[]) == False  # nothing to pin
        assert baser.pses.get(keys=key) == ['x', 'y']  # previous values are still here
        assert baser.pses.rem(keys=key) == True

        # pin after normal insertion
        assert baser.pses.put(keys=key, vals=[b'1', b'2']) == True
        assert baser.pses.get(keys=key) == ['1', '2']
        assert baser.pses.pin(keys=key, vals=[b'Q']) == True
        assert baser.pses.get(keys=key) == ['Q']  # overwritten

        # edge case: pin with mixed types
        assert baser.pses.pin(keys=key, vals=[b'A', 'A', memoryview(b'A')]) == True
        assert baser.pses.get(keys=key) == ['A'] # only one value gets added

        # cleanup
        assert baser.pses.rem(keys=key) == True
        assert baser.pses.get(keys=key) == []


        # test .pses deletion methods
        # delete specific val
        assert baser.pses.put(keys=key, vals=vals) == True
        assert baser.pses.rem(keys=key, val=b'm') == True
        assert baser.pses.get(keys=key) == ['z', 'x', 'a']

        # delete non existing val
        assert baser.pses.rem(keys=key, val=b'y') == False
        assert baser.pses.get(keys=key) == ['z', 'x', 'a']

        # delete all vals
        assert baser.pses.rem(keys=key) == True
        assert baser.pses.get(keys=key) == []
        assert baser.pses.cntAll(keys=key) == 0 # all vals deleted

        # delete non existing key
        assert baser.pses.rem(keys=b'X') == False

        # insert other keys to ensure only specified key is deleted
        assert baser.pses.put(keys=b'A', vals=[b'1']) == True
        assert baser.pses.put(keys=b'B', vals=[b'2']) == True
        assert baser.pses.rem(keys=b'A') == True
        assert baser.pses.get(keys=b'B') == ['2']

        # clean up all entries
        for k, sn, v in list(baser.pses.getAllItemIter()):
            assert baser.pses.rem(keys=k, on=sn, val=v) == True

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

        assert baser.pses.put(keys=pre, on=1, vals=aVals)
        assert baser.pses.put(keys=pre, on=2, vals=bVals)
        assert baser.pses.put(keys=pre, on=4, vals=cVals)
        assert baser.pses.put(keys=pre, on=7, vals=dVals)

        # Test getPseItemsNextIter(key=b"")
        # vals are in bytes, assertion is done after serializing

        # aVals
        items = [item for item in baser.pses.getTopItemIter()]
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
        items = [item for item in baser.pses.getTopItemIter(keys=aKey)]
        assert items == [(('A',), 1, 'z'), (('A',), 1, 'm'), (('A',), 1, 'x')]

        # bVals
        items = [item for item in baser.pses.getTopItemIter(keys=bKey)]
        assert items  == [(('A',), 2, 'o'), (('A',), 2, 'r'), (('A',), 2, 'z')]
        for keys, on, val in items:
            assert baser.pses.rem(keys=keys, on=on, val=val) == True

        # cVals
        items = [item for item in baser.pses.getTopItemIter(keys=cKey)]
        assert items == [(('A',), 4, 'h'), (('A',), 4, 'n')]
        for keys, on, val in items:
            assert baser.pses.rem(keys=keys, on=on, val=val) == True

        # dVals
        items = [item for item in baser.pses.getTopItemIter(keys=dKey)]
        assert items == [(('A',), 7, 'k'), (('A',), 7, 'b')]
        for keys, on, val in items:
            assert baser.pses.rem(keys=keys, on=on, val=val) == True

        # clean up all entries
        for k, sn, v in list(baser.pses.getAllItemIter()):
            baser.pses.rem(keys=k)

        # test _tokey and _tokeys
        t = baser.ooes._tokey(aKey)
        assert baser.ooes._tokeys(t) == ("A", "00000000000000000000000000000001")


        # Test .udes partial delegated escrow seal source couples
        key = dgKey(preb, digb)
        assert key == f'{preb.decode("utf-8")}.{digb.decode("utf-8")}'.encode("utf-8")

        # test .pdes methods
        assert isinstance(baser.pdes, subing.OnIoSetSuber)


        # test .udes CatCesrSuber sub baser methods
        assert isinstance(baser.udes, subing.CatCesrSuber)
        assert baser.udes.klas == (core.Number, coring.Diger)

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

        assert baser.udes.get(keys=key) == None
        assert baser.udes.rem(keys=key) == False
        assert baser.udes.put(keys=key, val=(num1, diger1)) == True
        num, diger = baser.udes.get(keys=key)
        assert num.qb64b + diger.qb64b == val1
        assert baser.udes.put(keys=key, val=(num2, diger2)) == False
        num, diger = baser.udes.get(keys=key)
        assert num.qb64b + diger.qb64b == val1
        assert baser.udes.pin(keys=key, val=(num2, diger2)) == True
        num, diger = baser.udes.get(keys=key)
        assert num.qb64b + diger.qb64b == val2
        assert baser.udes.rem(keys=key) == True
        assert baser.udes.get(keys=key) == None


        # Partially Witnessed Escrow Events
        # test .pwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]
        deserializedVals = ["z", "m", "x", "a"]

        assert baser.pwes.get(key) == []
        assert baser.pwes.cntAll(key) == 0
        assert baser.pwes.rem(key) == False
        assert baser.pwes.put(keys=key, vals=vals) == True
        assert baser.pwes.get(key) == deserializedVals  # preserved insertion order
        assert baser.pwes.cntAll(key) == len(vals) == 4
        assert list(baser.pwes.getLastIter(key))[0] == deserializedVals[-1]
        assert baser.pwes.put(key, vals=[b'a']) == False   # duplicate
        assert baser.pwes.get(key) == deserializedVals  #  no change
        assert baser.pwes.add(keys=key, val=b"a") == False   # duplicate
        assert baser.pwes.add(keys=key, val=b"b") == True
        assert baser.pwes.get(key) == deserializedVals + ['b']
        assert [val for val in baser.pwes.getIter(key)] == deserializedVals + ['b']
        assert baser.pwes.rem(key) == True
        assert baser.pwes.get(key) == []

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

        assert baser.pwes.put(keys=pre, on=aSn, vals=aVals)
        assert baser.pwes.put(keys=pre, on=bSn, vals=bVals)
        assert baser.pwes.put(keys=pre, on=cSn, vals=cVals)
        assert baser.pwes.put(keys=pre, on=dSn, vals=dVals)


        # Test getOnItemIterAll()
        #  get dups at first key in database
        # aVals
        items = [item for item in baser.pwes.getAllItemIter()]
        assert items  # not empty
        ikey = snKey(items[0][0][0], items[0][1])
        assert  ikey == aKey
        vals = [baser.pwes._ser(val) for  key, sn, val in items]
        assert vals ==  aVals + bVals + cVals + dVals

        items = [item for item in baser.pwes.getTopItemIter()]
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
        items = [item for item in baser.pwes.getTopItemIter(keys=aKey)]
        assert items == [(('A',), 1, 'z'), (('A',), 1, 'm'), (('A',), 1, 'x')]

        # bVals
        items = [item for item in baser.pwes.getTopItemIter(keys=bKey)]
        assert items  == [(('A',), 2, 'o'), (('A',), 2, 'r'), (('A',), 2, 'z')]
        for keys, on, val in items:
            assert baser.pwes.rem(keys=keys, on=on, val=val) == True

        # cVals
        items = [item for item in baser.pwes.getTopItemIter(keys=cKey)]
        assert items == [(('A',), 4, 'h'), (('A',), 4, 'n')]
        for keys, on, val in items:
            assert baser.pwes.rem(keys=keys, on=on, val=val) == True

        # dVals
        items = [item for item in baser.pwes.getTopItemIter(keys=dKey)]
        assert items == [(('A',), 7, 'k'), (('A',), 7, 'b')]
        for keys, on, val in items:
            assert baser.pwes.rem(keys=keys, on=on, val=val) == True

        
         # Unverified Witness Receipt Escrows
        # test .uwes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [('z',), ('m',), ('x',), ('a',)]

        assert baser.uwes.get(key) == []  # default on = 0
        assert baser.uwes.getLast(key) == None
        assert baser.uwes.cnt(key) == 0
        assert baser.uwes.rem(key) == False
        assert baser.uwes.put(key, on=0, vals=vals) == True
        assert baser.uwes.get(key, 0) == vals # preserved insertion order
        assert baser.uwes.cnt(key, 0) == len(vals) == 4
        assert baser.uwes.getLast(key, 0) == vals[-1]
        assert baser.uwes.put(key, 0, vals=[b'a']) == False   # duplicate
        assert baser.uwes.get(key, 0) == vals  #  no change
        assert baser.uwes.add(key, 0, b'a') == False   # duplicate
        assert baser.uwes.add(key, 0, b'b') == True
        assert baser.uwes.get(key, 0) == [('z',), ('m',), ('x',), ('a',), ('b',)]
        assert [val for key, on, val in baser.uwes.getTopItemIter(key)] == \
        [('z',), ('m',), ('x',), ('a',), ('b',)]
        assert baser.uwes.rem(key, 0) == True
        assert baser.uwes.get(key, 0) == []

        # Setup Tests
        keys = ("A", )
        assert baser.uwes.put(keys=keys, on=1, vals=aVals)
        assert baser.uwes.put(keys=keys, on=2, vals=bVals)
        assert baser.uwes.put(keys=keys, on=4, vals=cVals)
        assert baser.uwes.put(keys=keys, on=7, vals=dVals)

        items = [item for item in baser.uwes.getTopItemIter()]
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
        deserialized_vals = [baser.ooes._des(val) for val in vals] # deserialize for assertion

        # core insertion
        assert baser.ooes.get(keys=key) == []
        assert baser.ooes.cntAll(key) == 0
        assert baser.ooes.rem(key) == False

        # initial insertion
        assert baser.ooes.put(keys=key, vals=vals) == True
        assert baser.ooes.get(key) == deserialized_vals    #sanity check

        # duplication insertion behavior
        assert baser.ooes.put(keys=key,vals=[b'd', b'k']) == True
        assert baser.ooes.put(keys=key,vals=[b'd']) == False  # duplicate
        assert baser.ooes.put(keys=key,vals=[b'k']) == False  # duplicate
        assert baser.ooes.put(keys=key,vals=[b'k',b'd',b'k']) == False
        assert baser.ooes.add(keys=key, val=b'd') == False  # duplicate
        assert baser.ooes.add(keys=key, val=b'k') == False
        assert baser.ooes.get(keys=key) == deserialized_vals + ['d', 'k']

        # mixed insertion behavior
        assert baser.ooes.put(keys=key,vals=[b'k', b'c']) == True  # True because 'c' is new
        assert baser.ooes.get(keys=key) == deserialized_vals + ['d', 'k', 'c']

        # insertion after deletion
        assert baser.ooes.rem(keys=key, val=b'd') == True   # remove a specific val
        assert baser.ooes.get(keys=key) == deserialized_vals + ['k', 'c']   # d removed
        assert baser.ooes.add(keys=key,val=b'd') == True   # add d back
        assert baser.ooes.get(keys=key) == deserialized_vals + ['k', 'c', 'd']   # d added back

        # empty insertion
        assert baser.ooes.put(keys=key, vals=[]) == False # no vals to add
        assert baser.ooes.get(keys=key) == deserialized_vals + ['k', 'c', 'd'] # no change

        assert baser.ooes.add(keys=key, val=b'') == True  # empty val is allowed
        assert baser.ooes.get(keys=key) == deserialized_vals + ['k', 'c', 'd',''] # empty val added

        # clean up
        assert baser.ooes.rem(key) == True
        assert baser.ooes.get(keys=key) == []

        # different key types insertion
        assert baser.ooes.put(keys='B', vals=[b'1', b'2']) == True   # key as str
        assert baser.ooes.add(keys='B', val=b'3') == True
        assert baser.ooes.put(['B'], vals=b'4') == True  # key as list
        assert baser.ooes.add(keys=['B'], val=b'5') == True
        assert baser.ooes.put(("B"), vals=b'6') == True # key as tuple
        assert baser.ooes.add(keys=("B"), val=b'7') == True
        assert baser.ooes.put(memoryview(b'B'),vals= b'8') == True  # key as memoryview
        assert baser.ooes.add(keys=memoryview(b'B'), val=b'9') == True
        assert baser.ooes.get(keys=b'B') == ['1', '2', '3', '4', '5', '6', '7', '8', '9']

        # clean up
        assert baser.ooes.rem(b'B') == True
        assert baser.ooes.get(keys=b'B') == []

        # edge case: add different types of vals
        assert baser.ooes.put(key,vals=[b'a','a']) == True
        assert baser.ooes.get(keys=key) == ['a'] # only 1 value added

        assert baser.ooes.rem(key) == True
        assert baser.ooes.get(keys=key) == []


        # test .ooes retrieval behavior methods
        # insertion order preserved
        assert baser.ooes.put(keys=pre,on=sn, vals=vals) == True
        assert baser.ooes.get(keys=pre,on=sn) == deserialized_vals
        assert list(baser.ooes.getAllIter(pre,on=sn)) == deserialized_vals
        assert baser.ooes.getLast(keys=pre, on=sn) == deserialized_vals[-1]
        assert baser.ooes.cntAll(pre,on=sn) == len(vals) == 4

        # retrieval on empty list
        assert baser.ooes.get(keys=b'X') == []
        assert list(baser.ooes.getAllIter(b'X')) == []
        assert baser.ooes.getLast(keys=b'X') == None
        assert baser.ooes.cntAll(b'X') == 0
        items = baser.ooes.getAllItemIter(keys=b'X')
        assert list(items) == []

        # getTopItemIter retrieval of (key, val) pairs in lexicographic key order
        items = list(baser.ooes.getAllItemIter())
        assert items == [(('A',), 0, 'z'), (('A',), 0, 'm'), (('A',), 0, 'x'), (('A',), 0, 'a')]  # Insertion order preserved for vals
        assert baser.ooes.put(keys=[b'B', b'C'], vals=[b'1', b'2', b'3']) == True
        items = list(baser.ooes.getAllItemIter(keys=key))
        assert all(k[0] == 'A' for k, sn, v in items)

        # retrieval with different key types, A is the key used above where key = b'A'
        assert baser.ooes.get(keys=b'A') == deserialized_vals  # key as bytes
        assert baser.ooes.get(keys='A') == deserialized_vals  # key as str
        assert baser.ooes.get(keys=['A']) == deserialized_vals  # key as list
        assert baser.ooes.get(keys=('A',)) == deserialized_vals  # key as tuple
        assert baser.ooes.get(keys=memoryview(b'A')) == deserialized_vals  # key as memoryview

        # retrieval afterd deletion of specific val
        assert baser.ooes.getLast(keys=pre, on=sn) == 'a'              # vals = [b"z", b"m", b"x", b"a"]
        assert baser.ooes.rem(keys=pre,on=sn, val=b'a') == True           # vals = [b"z", b"m", b"x"]
        assert baser.ooes.get(keys=pre,on=sn,) == ['z', 'm', 'x']
        assert baser.ooes.getLast(keys=pre, on=sn) == 'x'
        assert baser.ooes.cntAll(pre,on=sn) == 3

        # clean up
        assert baser.ooes.rem(pre,on=sn) == True


        # test .ooes pinning behavior method
        # start clean
        assert baser.ooes.get(keys=key) == []
        assert baser.ooes.put(keys=key, vals=vals) == True
        assert baser.ooes.get(keys=key) == deserialized_vals
        assert baser.ooes.pin(keys=key, vals=[b'a', b'b', b'c']) == True
        assert baser.ooes.get(keys=key) == ['a', 'b', 'c']  # exact overwrite

        # pin with a different list
        assert baser.ooes.pin(keys=key, vals=[b'x', b'y']) == True
        assert baser.ooes.get(keys=key) == ['x', 'y']  # previous values removed

        # pin with empty list (valid use case)
        assert baser.ooes.pin(keys=key, vals=[]) == False  # nothing to pin
        assert baser.ooes.get(keys=key) == ['x', 'y']  # previous values are still here
        assert baser.ooes.rem(key) == True

        # pin after normal insertion
        assert baser.ooes.put(keys=key, vals=[b'1', b'2']) == True
        assert baser.ooes.get(keys=key) == ['1', '2']
        assert baser.ooes.pin(keys=key, vals=[b'Q']) == True
        assert baser.ooes.get(keys=key) == ['Q']  # overwritten

        # edge case: pin with mixed types
        assert baser.ooes.pin(keys=key, vals=[b'A', 'A', memoryview(b'A')]) == True
        assert baser.ooes.get(keys=key) == ['A'] # Only 1 value added

        # cleanup
        assert baser.ooes.rem(key) == True
        assert baser.ooes.get(keys=key) == []


        # test .ooes deletion methods
        # delete specific val
        assert baser.ooes.put(key, vals=vals) == True
        assert baser.ooes.rem(key, val=b'm') == True
        assert baser.ooes.get(keys=key) == ['z', 'x', 'a']

        # delete non existing val
        assert baser.ooes.rem(key, val=b'y') == False
        assert baser.ooes.get(keys=key) == ['z', 'x', 'a']

        # delete all vals
        assert baser.ooes.rem(key) == True
        assert baser.ooes.get(keys=key) == []
        assert baser.ooes.cntAll(key) == 0 # all vals deleted

        # delete non existing key
        assert baser.ooes.rem(b'X') == False

        # insert other keys to ensure only specified key is deleted
        assert baser.ooes.put(b'A', vals=[b'1']) == True
        assert baser.ooes.put(b'B', vals=[b'2']) == True
        assert baser.ooes.rem(b'A') == True
        assert baser.ooes.get(keys=b'B') == ['2']

        # clean up all entries
        for k, sn, v in list(baser.ooes.getAllItemIter()):
            assert baser.ooes.rem(keys=k, on=sn, val=v) == True


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

        assert baser.ooes.put(keys=pre, on=1, vals=aVals)
        assert baser.ooes.put(keys=pre, on=2, vals=bVals)
        assert baser.ooes.put(keys=pre, on=4, vals=cVals)
        assert baser.ooes.put(keys=pre, on=7, vals=dVals)



        # avals
        items = [item for item in baser.ooes.getTopItemIter(keys=aKey)]
        assert items == [(('A',), 1, 'z'), (('A',), 1, 'm'), (('A',), 1, 'x')]

        # bVals
        items = [item for item in baser.ooes.getTopItemIter(keys=bKey)]
        assert items  == [(('A',), 2, 'o'), (('A',), 2, 'r'), (('A',), 2, 'z')]
        for keys, on, val in items:
            assert baser.ooes.rem(keys=keys, on=on, val=val) == True

        # cVals
        items = [item for item in baser.ooes.getTopItemIter(keys=cKey)]
        assert items == [(('A',), 4, 'h'), (('A',), 4, 'n')]
        for keys, on, val in items:
            assert baser.ooes.rem(keys=keys, on=on, val=val) == True

        # dVals
        items = [item for item in baser.ooes.getTopItemIter(keys=dKey)]
        assert items == [(('A',), 7, 'k'), (('A',), 7, 'b')]
        for keys, on, val in items:
            assert baser.ooes.rem(keys=keys, on=on, val=val) == True

        # clean up all entries
        for k, sn, v in list(baser.pses.getAllItemIter()):
            baser.ooes.rem(keys=k)

        # test _tokey and _tokeys
        t = baser.ooes._tokey(aKey)
        assert baser.ooes._tokeys(t) == ("A", "00000000000000000000000000000001")


         # test .dels insertion order dup methods.  dup vals are insertion order
        keys = b'A'
        on = 0
        vals = ["z", "m", "x", "a"]

        assert baser.dels.get(keys=keys, on=on) == []
        result = baser.dels.get(keys=keys, on=on)
        assert (result[-1] if result else None) == None
        assert len(baser.dels.get(keys=keys, on=on)) == 0
        assert baser.dels.rem(keys=keys, on=on) == False
        for val in vals:
            baser.dels.add(keys=keys, on=on, val=val)
        assert baser.dels.get(keys=keys, on=on) == vals  # preserved insertion order
        assert len(baser.dels.get(keys=keys, on=on)) == len(vals) == 4
        result = baser.dels.get(keys=keys, on=on)
        assert result[-1] == vals[-1]
        assert baser.dels.add(keys=keys, on=on, val='a') == False   # duplicate
        assert baser.dels.get(keys=keys, on=on) == vals  #  no change
        assert baser.dels.add(keys=keys, on=on, val='a') == False   # duplicate
        assert baser.dels.add(keys=keys, on=on, val='b') == True
        assert baser.dels.get(keys=keys, on=on) == ["z", "m", "x", "a", "b"]
        assert baser.dels.rem(keys=keys, on=on) == True
        assert baser.dels.get(keys=keys, on=on) == []


        # test .ldes insertion order dup methods.  dup vals are insertion order
        key = b'A'
        vals = [b"z", b"m", b"x", b"a"]

        assert baser.ldes.get(keys=key) == []
        assert baser.ldes.getLast(keys=key) == None
        assert baser.ldes.cnt(keys=key) == 0
        assert baser.ldes.rem(keys=key) == False
        # put is not fully compatible with putLdes because putLdes took list of vals
        # and IoDupSuber.put takes iterable of vals.
        assert baser.ldes.put(keys=key, on=0, vals=vals) == True
        # OnIoDupSuber decodes bytes to utf-8 strings
        assert baser.ldes.get(keys=key) == [v.decode("utf-8") for v in vals]
        assert baser.ldes.cnt(keys=key) == len(vals) == 4
        assert baser.ldes.getLast(keys=key) == vals[-1].decode("utf-8")
        assert baser.ldes.put(keys=key, on=0, vals=[b'a']) == False   # duplicate
        assert baser.ldes.get(keys=key) == [v.decode("utf-8") for v in vals] #  no change
        assert baser.ldes.rem(keys=key) == True
        assert baser.ldes.get(keys=key) == []

        # Setup Tests for getOnItemIter with proper OnIoDupSuber API
        # Use addOn with explicit ordinal instead of snKey
        aVals = [b"z", b"m", b"x"]
        bVals = [b"o", b"r", b"z"]
        cVals = [b"h", b"n"]
        dVals = [b"k", b"b"]

        for val in aVals:
            assert baser.ldes.add(keys=b'A', on=1, val=val) == True
        for val in bVals:
            assert baser.ldes.add(keys=b'A', on=2, val=val) == True
        for val in cVals:
            assert baser.ldes.add(keys=b'A', on=4, val=val) == True
        for val in dVals:
            assert baser.ldes.add(keys=b'A', on=7, val=val) == True

        # Test getOnItemIterAll - iterate all items for prefix b'A'
        items = [item for item in baser.ldes.getAllItemIter(keys=b'A')]
        assert items  # not empty
        # item is (keys, on, val)
        vals = [val for pre, sn, val in items]
        allVals = aVals + bVals + cVals + dVals
        assert vals == [v.decode("utf-8") for v in allVals]

        # Iterate starting from specific ordinal (sn=1)
        items = [item for item in baser.ldes.getAllItemIter(keys=b'A', on=1)]
        assert items
        pre, sn, val = items[0]
        assert sn == 1
        assert val == aVals[0].decode("utf-8")

        # Verify vals at sn=1
        vals = [val for p, s, val in items if s == 1]
        assert vals == [v.decode("utf-8") for v in aVals]

        # bVals at sn=2
        items = [item for item in baser.ldes.getAllItemIter(keys=b'A', on=2)]
        vals = [val for p, s, val in items if s == 2]
        assert vals == [v.decode("utf-8") for v in bVals]
        # Remove bVals using remOn
        for p, s, val in items:
            if s == 2:
                assert baser.ldes.rem(keys=b'A', on=s, val=val) == True

        # cVals at sn=4
        items = [item for item in baser.ldes.getAllItemIter(keys=b'A', on=4)]
        vals = [val for p, s, val in items if s == 4]
        assert vals == [v.decode("utf-8") for v in cVals]
        for p, s, val in items:
            if s == 4:
                assert baser.ldes.rem(keys=b'A', on=s, val=val) == True

        # dVals at sn=7
        items = [item for item in baser.ldes.getAllItemIter(keys=b'A', on=7)]
        vals = [val for p, s, val in items if s == 7]
        assert vals == [v.decode("utf-8") for v in dVals]
        for p, s, val in items:
            if s == 7:
                assert baser.ldes.rem(keys=b'A', on=s, val=val) == True


        # Test for gpse
        key = b'a'
        sdig1 = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        number = Number(num=0)
        diger = Diger(qb64=sdig1)

        assert baser.gpse.get(key) == []   # gpse is empty
        assert baser.gpse.add(keys=key, val=(number, diger)) == True   # add new entry with val as a tuple of number and diger

        val = baser.gpse.get(key)  # returns Cesr tuple of (number, diger)
        num, dig = val[0]
        assert isinstance(num, Number)
        assert isinstance(dig, Diger)
        assert num.num == number.num
        assert dig.qb64 == diger.qb64

        assert baser.gpse.rem(key) == True
        assert baser.gpse.get(key) == []   # gpse is empty again


         # Saider and Seqner instead of Diger and Number
        seqner = Seqner(num=0)
        saider = Saider(qb64=sdig1)
        assert baser.gpse.add(keys=key, val=(seqner, saider)) == True # val is not using Number and Diger type
        val = baser.gpse.get(key)                                     # but it still gets validated
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
        assert baser.imgs.get(keys=img_key) is None  # empty
        assert baser.imgs.put(keys=img_key, val=(said_nonce, uuid_nonce, mime_label, img_data)) == True
        result = baser.imgs.get(keys=img_key)
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
        assert baser.imgs.pin(keys=img_key, val=(said_nonce, uuid_nonce, mime_label, new_data)) == True
        result = baser.imgs.get(keys=img_key)
        _, _, _, rdata2 = result
        assert rdata2.text == "newdata"

        assert baser.imgs.rem(keys=img_key) == True
        assert baser.imgs.get(keys=img_key) is None

        # test .iimgs  same format for local identifiers
        assert baser.iimgs.put(keys=img_key, val=(said_nonce, uuid_nonce, mime_label, img_data)) == True
        result = baser.iimgs.get(keys=img_key)
        assert result is not None
        rsaid, ruuid, rmime, rdata = result
        assert isinstance(rsaid, Noncer)
        assert isinstance(rdata, Texter)
        assert baser.iimgs.rem(keys=img_key) == True
        assert baser.iimgs.get(keys=img_key) is None


    asyncio.run(_go())


@needskeri
def test_fetchkeldel():
    """
    Test fetching full KEL and full DEL from Baser
    """
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        assert baser.opened
        assert baser.name == "main"


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

        # test kels getAllIter
        sn = 0
        vals0 = [skedb]
        assert baser.kels.add(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert baser.kels.add(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        for val in vals2:
            assert baser.kels.add(keys=preb, on=sn, val=val) == True

        vals = list(baser.kels.getAllIter(keys=preb))
        allvals = [v.decode("utf-8") for v in (vals0 + vals1 + vals2)]
        assert vals == allvals

        # test kels getLastIter
        preb = 'B4ejhccWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x'.encode("utf-8")
        sn = 0
        
        vals0 = [skedb]
        assert baser.kels.add(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert baser.kels.add(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 1
        for val in vals2:
            assert baser.kels.add(keys=preb, on=sn, val=val) == True
        vals = list(baser.kels.getLastIter(keys=preb))
        # Kels being an IoSetSuber, getLastIter calls getIoSetLastItemIterAll 
        # which Iterates over every last added ioset entry at every effective key
        # starting at key greater or equal to key so the values from the previous tests are 
        # yielded here too.

        # Because lexicographically BWzwEHH > B4ejhcc
        # when getLastIter iterates, we get B4ejhcc's values first then BWzweHH
        lastvals = ['{"vs":"KERI10JSON000014_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"}', 'paul', 'bird', 
                    '{"vs":"KERI10JSON000014_","pre":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc","sn":"3","ilk":"rot","dig":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4"}', 'paul', 'bird']

        assert vals == lastvals


        # test getDelItemIter
        preb = 'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw'.encode("utf-8")
        sn = 1  # do not start at zero
        key = snKey(preb, sn)
        assert key == (b'BTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGw.'
                        b'00000000000000000000000000000001')
        vals0 = [skedb]
        assert baser.dels.add(keys=preb, on=sn, val=vals0[0]) == True

        vals1 = [b"mary", b"peter", b"john", b"paul"]
        sn += 1
        for val in vals1:
            assert baser.dels.add(keys=preb, on=sn, val=val) == True

        vals2 = [b"dog", b"cat", b"bird"]
        sn += 3  # skip make gap in SN
        for val in vals2:
            assert baser.dels.add(keys=preb, on=sn, val=val) == True

        allvals = vals0 + vals1 + vals2
        vals = [(val.encode("utf-8") if isinstance(val, str) else bytes(val))
            for keys, on, val in baser.dels.getAllItemIter(keys=preb)]
        assert vals == allvals

    asyncio.run(_go())


@needskeri
def test_usebaser():
    """
    Test using Baser
    """

    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        assert baser.opened

        raw = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
        salter = Salter(raw=raw)

        #  create coe's signers
        signers = salter.signers(count=8, path='db', temp=True)

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
        kever = Kever(serder=serder, sigers=sigers, db=baser)

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

    asyncio.run(_go())


def test_clear_escrows():
    async def _go():
        backend = FakeStorageBackend()
        db = WebBaser()

        await db.reopen(storageOpener=backend.open)

        assert db.opened

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

    asyncio.run(_go())


@needskeri
def test_trim_all_escrows_during_migration():
    """Regression test for issue #863: old qnfs key format crashes migration.

    When upgrading from keripy <1.2.0, qnfs entries lack the insertion-order
    suffix (e.g. 'PRE.SAID' instead of 'PRE.SAID.00000000'). The high-level
    iterators in clearEscrows() call unsuffix() which does int(SAID, 16) and
    crashes with ValueError.

    _trimAllEscrows() uses low-level .trim() which bypasses key parsing,
    safely clearing all escrow databases regardless of key format.
    """
    async def _go(): 

        backend = FakeStorageBackend()
        db = WebBaser()

        await db.reopen(storageOpener=backend.open)

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

    asyncio.run(_go())


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


    async def _go():
        backend = FakeStorageBackend()
        db = WebBaser()

        await db.reopen(storageOpener=backend.open)

        assert db.opened

        sns = [0, 1, 2, 10, 100, 999999, 2**40, 2**80]

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

    asyncio.run(_go())


def test_statedict():
    """
    Test custom statedict subclass of dict
    """
    

    async def _go():

        backend = FakeStorageBackend()
        db = WebBaser()

        await db.reopen(storageOpener=backend.open)

        assert db.opened

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

    asyncio.run(_go())


@needskeri
def test_close_clear_persistence():
    """Test that close(clear=False) preserves data and close(clear=True) wipes it."""
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)
        assert baser.opened

        # Write data
        baser.oobis.put(keys=("test_cid",), val=OobiRecord(cid="test_cid"))
        assert baser.oobis.get(keys=("test_cid",)) is not None

        # close(clear=False) should preserve data across reopen
        await baser.aclose(clear=False)
        assert not baser.opened
        assert baser.db is None

        await baser.reopen(storageOpener=backend.open)
        assert baser.oobis.get(keys=("test_cid",)) is not None

        # close(clear=True) should wipe data
        await baser.aclose(clear=True)
        await baser.reopen(storageOpener=backend.open)
        assert baser.oobis.get(keys=("test_cid",)) is None

        # After close, baser.db is None and baser.opened is False
        await baser.aclose()
        assert baser.db is None
        assert not baser.opened

    asyncio.run(_go())


@needskeri
def test_reload_orphan_cleanup():
    """Test that reload() removes orphan habs, keeps valid/group habs, and
    handles MissingEntryError (state exists but event missing)."""
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        # --- Build a valid hab with key state ---
        pre = 'DApYGFaqnrALTyejaJaGAVhNpSCtqyerPqWVK9ZBNZk0'
        dig = 'EAskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30'
        serder = interact(pre=pre, dig=dig, sn=4)
        eevt = StateEstEvent(s='3', d=dig, br=[], ba=[])
        state = eventState(pre=pre, sn=4, pig=dig, dig=serder.said,
                           fn=4, eilk=Ilks.ixn, keys=[pre], eevt=eevt)

        baser.evts.put(keys=(pre, serder.said), val=serder)
        baser.states.pin(keys=pre, val=state)
        baser.habs.put(keys=pre, val=HabitatRecord(hid=pre, name="valid"))

        # --- Orphan hab: no key state, mid=None ---
        orphan_pre = 'DBMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt'
        baser.habs.put(keys=orphan_pre,
                       val=HabitatRecord(hid=orphan_pre, name="orphan", mid=None))

        # --- Group hab stub: no key state, but mid is set ---
        group_pre = 'DCMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt'
        group_mid = 'DDMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt'
        baser.habs.put(keys=group_pre,
                       val=HabitatRecord(hid=group_pre, name="group", mid=group_mid))

        # --- Corrupt hab: state exists but event missing from evts ---
        # Kever(state=ksr, db=baser) will raise MissingEntryError when it
        # looks up db.evts.get(keys=(pre, state.d)) and gets None.
        corrupt_pre = 'DEMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt'
        corrupt_dig = 'EFskHI462CuIMS_gNkcl_QewzrRSKH2p9zHQIO132Z30'
        corrupt_serder = interact(pre=corrupt_pre, dig=corrupt_dig, sn=1)
        corrupt_eevt = StateEstEvent(s='0', d=corrupt_dig, br=[], ba=[])
        corrupt_state = eventState(pre=corrupt_pre, sn=1, pig=corrupt_dig,
                                   dig=corrupt_serder.said, fn=1,
                                   eilk=Ilks.ixn, keys=[corrupt_pre],
                                   eevt=corrupt_eevt)
        baser.states.pin(keys=corrupt_pre, val=corrupt_state)
        # Deliberately do NOT put the event into baser.evts
        baser.habs.put(keys=corrupt_pre,
                       val=HabitatRecord(hid=corrupt_pre, name="corrupt"))

        # reload should clean up orphans and corrupt habs
        baser.reload()

        # Valid hab should be in kevers and prefixes
        assert pre in baser.prefixes
        assert pre in baser.kevers

        # Orphan should be removed
        assert baser.habs.get(keys=orphan_pre) is None

        # Corrupt hab should be removed (MissingEntryError path)
        assert baser.habs.get(keys=corrupt_pre) is None

        # Group hab should remain (mid is set, so not an orphan)
        assert baser.habs.get(keys=group_pre) is not None

    asyncio.run(_go())


@needskeri
def test_clean_subdb_swap():
    """Test that clean() copies unsecured and sets-type subdbs, wipes others."""
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        # Write to an "unsecured" SubDb that clean() copies via .put()
        baser.oobis.put(keys=("test_cid",), val=OobiRecord(cid="test_cid"))
        assert baser.oobis.get(keys=("test_cid",)) is not None

        # Write to a "sets" SubDb that clean() copies via .add()
        # chas is CesrIoSetSuber(klas=Diger) in the sets list at webbasing.py:924
        test_diger = Diger(ser=b"test-challenge-response")
        baser.chas.add(keys=("challenge_pre",), val=test_diger)
        assert baser.chas.get(keys=("challenge_pre",))

        # Write to a SubDb NOT in the unsecured/sets lists
        baser.names.put(keys=("", "myname"), val="somepre")
        assert baser.names.get(keys=("", "myname")) is not None

        await baser.clean()

        # oobis data should survive (unsecured copy via .put())
        assert baser.oobis.get(keys=("test_cid",)) is not None

        # chas data should survive (sets copy via .add())
        chas_vals = baser.chas.get(keys=("challenge_pre",))
        assert chas_vals
        assert test_diger.qb64 in [v.qb64 for v in chas_vals]

        # names data should be gone (not copied to clone)
        assert baser.names.get(keys=("", "myname")) is None

        assert baser.opened

    asyncio.run(_go())


@needskeri
def test_web_baser_doer():
    """Test WebBaserDoer lifecycle: enter requires opened baser, exit closes sync."""
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        # enter() on un-opened baser should raise
        doer = WebBaserDoer(baser=baser)
        with pytest.raises(RuntimeError, match="must be opened"):
            doer.enter()

        # Open baser, enter() should succeed
        await baser.reopen(storageOpener=backend.open)
        assert baser.opened
        doer.enter()  # no error

        # exit() calls sync close() — baser is closed immediately
        doer.exit()
        assert not baser.opened
        # Let fire-and-forget flush task complete before reopen
        await asyncio.sleep(0)

        # Test with temp=True to verify clear=True path
        await baser.reopen(storageOpener=backend.open)
        baser.temp = True
        baser.oobis.put(keys=("x",), val=OobiRecord(cid="x"))

        doer2 = WebBaserDoer(baser=baser)
        doer2.enter()
        doer2.exit()
        assert not baser.opened
        # Let fire-and-forget flush persist the cleared state
        await asyncio.sleep(0)

        # Reopen and verify data was cleared (temp=True -> clear=True)
        await baser.reopen(storageOpener=backend.open)
        assert baser.oobis.get(keys=("x",)) is None

    asyncio.run(_go())


def test_strip_prerelease_webbasing():
    """Test the locally-duplicated _strip_prerelease in webbasing.py."""
    import semver

    # Core bug that _strip_prerelease fixes: dev4 > dev10 lexicographically
    assert semver.compare("1.2.0-dev4", "1.2.0-dev10") == 1

    # _strip_prerelease normalizes by removing prerelease/build metadata
    assert _strip_prerelease("1.2.0-dev4") == "1.2.0"
    assert _strip_prerelease("1.2.0-dev10") == "1.2.0"
    assert _strip_prerelease("1.2.0") == "1.2.0"
    assert _strip_prerelease("0.6.8") == "0.6.8"
    assert _strip_prerelease("1.2.0-rc1") == "1.2.0"
    assert _strip_prerelease("2.0.0-dev5+build42") == "2.0.0"

    # After stripping, migration version comparisons work correctly
    db_ver = _strip_prerelease("1.2.0-dev4")
    assert semver.compare("1.2.0", db_ver) == 0  # same cycle, skip

    db_ver = _strip_prerelease("1.0.0")
    assert semver.compare("1.2.0", db_ver) == 1  # newer, run migration


@needskeri
def test_trim_all_escrows_web():
    """Test _trimAllEscrows clears all escrow subdbs via trim().

    trim() with empty keys uses startswith(b"") which matches every key,
    so all entries are removed regardless of key format.
    """
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        # Inject old-format key directly into qnfs SubDb's SortedDict.
        # Old format: PRE.SAID (no .00000000 insertion-order suffix)
        old_key = (b'EBMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt.'
                   b'EBMbr7Z-pd4KJwzxuptSmCYqxrBnE2xKVO-MnjYkeUrt')
        baser.qnfs.sdb.items[old_key] = b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
        baser.qnfs.sdb.dirty = True

        assert baser.qnfs.cntAll() > 0

        # _trimAllEscrows uses .trim() which bypasses key parsing
        baser._trimAllEscrows()

        assert baser.qnfs.cntAll() == 0

    asyncio.run(_go())


@needskeri
def test_webbaser_clone_all_pre_iter():
    """
    Test cloneAllPreIter yields first-seen event messages for all identifier
    prefixes in the database.
    """
    async def _go():
        backend = FakeStorageBackend()
        baser = WebBaser()

        await baser.reopen(storageOpener=backend.open)

        kwa = dict(db=baser)

        with openHby(name="test", base="test", **kwa) as hby:
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

            hab1.rotate()
            hab2.rotate()

            msgs = list(hby.db.cloneAllPreIter())
            assert len(msgs) >= 4  # two icps + two rots

            sn_by_pre = {}
            for msg in msgs:
                ser = SerderKERI(raw=bytes(msg))
                sn = ser.sn
                sn_by_pre.setdefault(ser.pre, []).append(sn)

            for pre, sns in sn_by_pre.items():
                assert sns == sorted(sns)

    asyncio.run(_go())
