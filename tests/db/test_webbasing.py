# -*- encoding: utf-8 -*-
"""
tests.db.test_webbasing module

"""

import asyncio
import json

import pytest

from keri.db.webbasing import WebBaser

try:
    from keri.db import subing, koming, dgKey
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

    asyncio.run(_go())
