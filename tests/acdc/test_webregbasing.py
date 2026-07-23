# -*- encoding: utf-8 -*-
"""
tests.acdc.test_webregbasing module

"""

import asyncio

from keri.acdc import messaging, webregbasing
from keri.core import coring, serdering
from keri.db import subing


class FakeStorageHandle:
    """Storage handle with explicit async persistence."""

    def __init__(self, backend, namespace):
        self.backend = backend
        self.namespace = namespace
        self.local = dict(backend.persisted.get(namespace, {}))

    def get(self, key, default=None):
        return self.local.get(key, default)

    def __setitem__(self, key, value):
        self.local[key] = value

    async def sync(self):
        self.backend.persisted[self.namespace] = dict(self.local)


class FakeStorageBackend:
    """Storage opener that records namespace declaration order."""

    def __init__(self):
        self.persisted = {}
        self.opened = []

    async def open(self, namespace):
        self.opened.append(namespace)
        return FakeStorageHandle(self, namespace)


def test_webregbaser_store_contract_and_persistence():
    """Test browser store parity, namespace isolation, and persistence."""

    async def run():
        backend = FakeStorageBackend()
        baser = webregbasing.WebRegBaser(name="observer")
        await baser.reopen(
            clear=True,
            storageOpener=backend.open,
        )

        expectedSubDbNames = [
            "evts.",
            "ancs.",
            "tels.",
            "heads.",
            "maes.",
            "ooes.",
        ]
        expected = [
            f"acdc-reg:observer:{name}"
            for name in (*expectedSubDbNames, "__meta__")
        ]
        assert backend.opened == expected
        assert baser.SubDbNames == expectedSubDbNames
        assert isinstance(baser.evts, subing.SerderSuber)
        assert baser.evts.klas is serdering.SerderACDC
        assert isinstance(baser.ancs, subing.CatCesrSuber)
        assert baser.ancs.klas == (coring.Number, coring.Diger)
        assert isinstance(baser.tels, subing.CesrOnSuber)
        assert baser.tels.klas is coring.Saider
        assert isinstance(baser.heads, subing.CesrSuber)
        assert baser.heads.klas is coring.Saider
        assert isinstance(baser.maes, subing.B64OnIoSetSuber)
        assert isinstance(baser.ooes, subing.B64OnIoSetSuber)

        for name in ("evts", "ancs", "tels", "heads", "maes", "ooes"):
            assert getattr(baser, name).sdb.flags()["dupsort"] is False

        issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
        serder = messaging.regcept(
            israid=issuer,
            uuid="0AAxyHwW6htOZ_rANOaZb2N2",
            stamp="2020-08-22T17:50:09.988921+00:00",
        )
        saider = coring.Saider(qb64=serder.said)
        source = (coring.Number(num=3), coring.Diger(qb64=serder.said))

        assert baser.evts.put(keys=serder.said, val=serder)
        assert baser.ancs.put(keys=serder.said, val=source)
        assert baser.tels.put(keys=serder.said, on=0, val=saider)
        assert baser.heads.put(keys=serder.said, val=saider)
        assert baser.maes.add(keys=serder.said, on=1, val=serder.said)
        assert baser.ooes.add(keys=serder.said, on=1, val=serder.said)

        await baser.aclose()
        assert baser.opened is False
        assert baser.db is None
        assert baser.env is None
        for name in ("evts", "ancs", "tels", "heads", "maes", "ooes"):
            assert not hasattr(baser, name)

        reopened = webregbasing.WebRegBaser(name="observer")
        await reopened.reopen(storageOpener=backend.open)
        assert reopened.evts.get(keys=serder.said).raw == serder.raw
        assert reopened.ancs.get(keys=serder.said)[0].num == 3
        assert reopened.ancs.get(keys=serder.said)[1].qb64 == serder.said
        assert reopened.tels.get(keys=serder.said, on=0).qb64 == serder.said
        assert reopened.heads.get(keys=serder.said).qb64 == serder.said
        assert reopened.maes.get(keys=serder.said, on=1) == [(serder.said,)]
        assert reopened.ooes.get(keys=serder.said, on=1) == [(serder.said,)]

        syncSaid = coring.Diger(ser=b"sync close candidate").qb64
        assert reopened.ooes.add(keys=serder.said, on=2, val=syncSaid)
        reopened.close()
        assert reopened.opened is False
        assert reopened.db is None
        assert reopened.env is None
        await asyncio.sleep(0)

        closed = webregbasing.WebRegBaser(name="observer")
        await closed.reopen(storageOpener=backend.open)
        assert closed.ooes.get(keys=serder.said, on=2) == [(syncSaid,)]
        await closed.aclose()

    asyncio.run(run())
