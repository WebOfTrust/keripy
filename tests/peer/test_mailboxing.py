# -*- encoding: utf-8 -*-
"""
tests.peer.mailboxing

"""
import os

import lmdb
import pytest

from keri.app import habbing, keeping
from keri.core import coring, eventing, parsing
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

    assert isinstance(mber.msgs, subing.Suber)

    with dbing.openLMDB(cls=Mailboxer) as mber:
        assert isinstance(mber, Mailboxer)

        msg = (
            b'{"v":"KERI10JSON0000ac_","t":"exn","i":"E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I",'
            b'"dt":"2021-07-15T13:01:37.624492+00:00","r":"/credential/issue","q":{"a":"b",'
            b'"b":123}}-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E'
            b'-AABAAMKEkKlqSYcAbOHfNXQ_D0Rbj9bQD5FqhFqckAlDnOFozRKOIPrCWaszRzSUN20UBj80tO5ozN35KrQp9m7Z1AA')

        dest = coring.Prefixer(qb64="E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        mber.storeMsg(dest=dest.qb64b, msg=msg)

        digb = coring.Diger(ser=msg).qb64b
        actual = mber.msgs.get(keys=digb)
        assert actual == msg.decode("utf-8")

    assert not os.path.exists(mber.path)

    with dbing.openLMDB(cls=Mailboxer) as mber, \
            basing.openDB(name="test") as db, \
            keeping.openKS(name="test") as ks:

        salt = coring.Salter(raw=b'0123456789abcdef').qb64
        hab = habbing.Habitat(ks=ks, db=db, salt=salt, temp=True)

        for idx in range(10):
            d = dict(a="b", b=idx)
            dest = coring.Prefixer(qb64="E4D919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")

            exn = exchanging.exchange("/credential/issue", payload=d,
                                      recipient=dest.qb64, date="2021-07-15T13:01:37.624492+00:00")
            mber.storeMsg(dest=dest.qb64b, msg=exn.raw)

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=0):
            msgs.append(msg)

        assert(len(msgs)) == 10

        for idx, msg in msgs:
            exn = coring.Serder(msg.encode("utf-8"))
            d = exn.ked["d"]
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
            basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
            basing.openDB(name="test") as db, \
            keeping.openKS(name="test") as ks:

        salt = coring.Salter(raw=b'0123456789abcdef').qb64

        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1,
                                 salt=salt, transferable=False, temp=True)
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        assert wesHab.ks == wesKS
        assert wesHab.db == wesDB
        assert not wesHab.kever.prefixer.transferable

        hab = habbing.Habitat(ks=ks, db=db, salt=salt, temp=True, wits=[wesHab.pre])

        icpMsg = hab.makeOwnInception()
        parsing.Parser().parse(ims=bytearray(icpMsg), kvy=wesKvy)
        assert hab.pre in wesKvy.kevers


        exchr = exchanging.StoreExchanger(hab=wesHab, mbx=mber)

        source = coring.Prefixer(qb64=hab.pre)
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
            source = coring.Prefixer(qb64=hab.pre)

            exn = exchanging.exchange("/credential/issue", payload=d,
                                      recipient=dest.qb64, date="2021-07-15T13:01:37.624492+00:00")
            sigers = hab.mgr.sign(ser=exn.raw, verfers=hab.kever.verfers)
            exchr.processEvent(serder=exn, source=source, sigers=sigers)

        msgs = []
        for msg in mber.clonePreIter(pre=dest.qb64b, fn=0):
            msgs.append(msg)

        assert(len(msgs)) == 10

        for idx, msg in msgs:
            exn = coring.Serder(raw=msg.encode("utf-8"))
            d = exn.ked["d"]
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
