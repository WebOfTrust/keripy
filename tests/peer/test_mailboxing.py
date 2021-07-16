# -*- encoding: utf-8 -*-
"""
tests.peer.mailboxing

"""
import os

import lmdb
import pytest

from keri.app import habbing, keeping
from keri.core import coring
from keri.db import dbing, subing, basing
from keri.kering import MissingSignatureError, MissingDestinationError
from keri.peer import exchanging
from keri.peer.exchanging import Mailboxer


def test_mailboxing():
    """
    Test Mailboxer Class
    """
    mber = Mailboxer()

    assert isinstance(mber, Mailboxer)
    assert mber.name == "main"
    assert mber.temp is False
    assert isinstance(mber.env, lmdb.Environment)
    assert mber.path.endswith("keri/mbx/main")
    assert mber.env.path() == mber.path
    assert os.path.exists(mber.path)

    assert isinstance(mber.fels, lmdb._Database)

    mber.close(clear=True)
    assert not os.path.exists(mber.path)
    assert not mber.opened

    mber = Mailboxer(reopen=False)
    assert isinstance(mber, Mailboxer)
    assert mber.name == "main"
    assert mber.temp is False
    assert mber.opened is False
    assert mber.path is None
    assert mber.env is None

    mber.reopen()
    assert mber.opened
    assert mber.path is not None
    assert isinstance(mber.env, lmdb.Environment)
    assert mber.path.endswith("keri/mbx/main")
    assert mber.env.path() == mber.path
    assert os.path.exists(mber.path)

    mber.close(clear=True)
    assert not os.path.exists(mber.path)
    assert not mber.opened

    assert isinstance(mber.exns, subing.SerderSuber)

    with dbing.openLMDB(cls=Mailboxer) as mber:
        assert isinstance(mber, Mailboxer)

        msg = bytearray(
            b'{"v":"KERI10JSON0000ac_","t":"exn","i":"E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I",'
            b'"dt":"2021-07-15T13:01:37.624492+00:00","r":"/credential/issue","q":{"a":"b",'
            b'"b":123}}-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E'
            b'-AABAAMKEkKlqSYcAbOHfNXQ_D0Rbj9bQD5FqhFqckAlDnOFozRKOIPrCWaszRzSUN20UBj80tO5ozN35KrQp9m7Z1AA')

        dest = coring.Prefixer(qb64="E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        source = coring.Prefixer(qb64="E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E")
        siger = coring.Siger(
            qb64="AAMKEkKlqSYcAbOHfNXQ_D0Rbj9bQD5FqhFqckAlDnOFozRKOIPrCWaszRzSUN20UBj80tO5ozN35KrQp9m7Z1AA")

        d = dict(a="b", b=123)
        exn = exchanging.exchange("/credential/issue", payload=d,
                                  recipient=dest.qb64, date="2021-07-15T13:01:37.624492+00:00")
        mber.storeEvent(serder=exn, source=source, dest=dest, sigers=[siger])

        actual = mber.cloneEvtMsg(dig=exn.digb)
        assert actual == msg

    assert not os.path.exists(mber.path)

    with dbing.openLMDB(cls=Mailboxer) as mber, \
            basing.openDB(name="test") as db, \
            keeping.openKS(name="test") as ks:

        salt = coring.Salter(raw=b'0123456789abcdef').qb64
        hab = habbing.Habitat(ks=ks, db=db, salt=salt, temp=True)

        for idx in range(10):
            d = dict(a="b", b=idx)
            dest = coring.Prefixer(qb64="E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
            source = coring.Prefixer(qb64="E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E")

            exn = exchanging.exchange("/credential/issue", payload=d,
                                      recipient=dest.qb64, date="2021-07-15T13:01:37.624492+00:00")
            sigers = hab.mgr.sign(ser=exn.raw, verfers=hab.kever.verfers)
            mber.storeEvent(serder=exn, source=source, dest=dest, sigers=sigers)

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=0):
            msgs.append(msg)

        assert(len(msgs)) == 10

        for idx, msg in enumerate(msgs):
            exn = coring.Serder(msg)
            d = exn.ked["q"]
            assert d["b"] == idx

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=10):
            msgs.append(msg)

        assert(len(msgs)) == 0

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=4):
            msgs.append(msg)

        assert(len(msgs)) == 6


def test_store_exchanger():
    with dbing.openLMDB(cls=Mailboxer) as mber, \
            basing.openDB(name="test") as db, \
            keeping.openKS(name="test") as ks:

        salt = coring.Salter(raw=b'0123456789abcdef').qb64
        hab = habbing.Habitat(ks=ks, db=db, salt=salt, temp=True)
        exchr = exchanging.StoreExchanger(hab=hab, db=mber)

        source = coring.Prefixer(qb64="E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E")
        siger = coring.Siger(
            qb64="AAMKEkKlqSYcAbOHfNXQ_D0Rbj9bQD5FqhFqckAlDnOFozRKOIPrCWaszRzSUN20UBj80tO5ozN35KrQp9m7Z1AA")

        d = dict(a="b", b=123)
        exn = exchanging.exchange("/credential/issue", payload=d, date="2021-07-15T13:01:37.624492+00:00")
        with pytest.raises(MissingSignatureError):
            exchr.processEvent(serder=exn, source=source, sigers=[siger])


        sigers = hab.mgr.sign(ser=exn.raw, verfers=hab.kever.verfers)
        with pytest.raises(MissingDestinationError):
            exchr.processEvent(serder=exn, source=source, sigers=sigers)

        for idx in range(10):
            d = dict(a="b", b=idx)
            dest = coring.Prefixer(qb64="E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
            source = coring.Prefixer(qb64="E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E")

            exn = exchanging.exchange("/credential/issue", payload=d,
                                      recipient=dest.qb64, date="2021-07-15T13:01:37.624492+00:00")
            sigers = hab.mgr.sign(ser=exn.raw, verfers=hab.kever.verfers)
            exchr.processEvent(serder=exn, source=source, sigers=sigers)

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=0):
            msgs.append(msg)

        assert(len(msgs)) == 10

        for idx, msg in enumerate(msgs):
            exn = coring.Serder(msg)
            d = exn.ked["q"]
            assert d["b"] == idx

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=10):
            msgs.append(msg)

        assert(len(msgs)) == 0

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=4):
            msgs.append(msg)

        assert(len(msgs)) == 6


if __name__ == '__main__':
    test_mailboxing()
    test_store_exchanger()
