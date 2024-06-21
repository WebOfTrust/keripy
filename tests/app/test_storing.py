# -*- encoding: utf-8 -*-
"""
tests.app.storing

"""
import os

import lmdb

from keri.app import keeping
from keri.core import coring, serdering
from keri.db import dbing, basing
from keri.peer import exchanging
from keri.app.storing import Mailboxer


def test_mailboxing():
    """
    Test Mailboxer Class
    """
    mber = Mailboxer()

    assert isinstance(mber, Mailboxer)
    assert mber.name == "mbx"
    assert mber.temp is False
    assert isinstance(mber.env, lmdb.Environment)
    assert mber.path.endswith("keri/mbx/mbx")
    assert mber.env.path() == mber.path
    assert os.path.exists(mber.path)

    assert isinstance(mber.tpcs, lmdb._Database)

    mber.close(clear=True)
    assert not os.path.exists(mber.path)
    assert not mber.opened

    mber = Mailboxer(reopen=False)
    assert isinstance(mber, Mailboxer)
    assert mber.name == "mbx"
    assert mber.temp is False
    assert mber.opened is False
    assert mber.path is None
    assert mber.env is None

    mber.reopen()
    assert mber.opened
    assert mber.path is not None
    assert isinstance(mber.env, lmdb.Environment)
    assert mber.path.endswith("keri/mbx/mbx")
    assert mber.env.path() == mber.path
    assert os.path.exists(mber.path)

    mber.close(clear=True)
    assert not os.path.exists(mber.path)
    assert not mber.opened

    with dbing.openLMDB(cls=Mailboxer) as mber:
        assert isinstance(mber, Mailboxer)

        msg = (
            b'{"v":"KERI10JSON0000ac_","t":"exn","i":"EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I",'
            b'"dt":"2021-07-15T13:01:37.624492+00:00","r":"/credential/issue","q":{"a":"b",'
            b'"b":123}}-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E'
            b'-AABAAMKEkKlqSYcAbOHfNXQ_D0Rbj9bQD5FqhFqckAlDnOFozRKOIPrCWaszRzSUN20UBj80tO5ozN35KrQp9m7Z1AA')

        dest = coring.Prefixer(qb64="EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        saved = mber.storeMsg(topic=dest.qb64b, msg=msg)
        assert saved is True

        actual = mber.getTopicMsgs(topic=dest.qb64)
        assert actual[0] == msg

    assert not os.path.exists(mber.path)

    with dbing.openLMDB(cls=Mailboxer) as mber, \
            basing.openDB(name="test") as db, \
            keeping.openKS(name="test") as ks:

        for idx in range(10):
            d = dict(a="b", b=idx)
            dest = coring.Prefixer(qb64="EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")

            exn, _ = exchanging.exchange("/credential/issue", payload=d,
                                      date="2021-07-15T13:01:37.624492+00:00", sender=dest.qb64)
            mber.storeMsg(topic=dest.qb64b, msg=exn.raw)

        msgs = []
        for fn, topic, msg in mber.cloneTopicIter(topic=dest.qb64b, fn=0):
            msgs.append((fn, msg))

        assert(len(msgs)) == 10

        for idx, msg in msgs:
            exn = serdering.SerderKERI(raw=msg)
            d = exn.ked["a"]
            assert d["b"] == idx

        msgs = []
        for fn, topic, msg in mber.cloneTopicIter(topic=dest.qb64b, fn=10):
            msgs.append(msg)

        assert(len(msgs)) == 0

        msgs = []
        for tn, topic, msg in mber.cloneTopicIter(topic=dest.qb64b, fn=4):
            msgs.append((tn, msg))

        assert(len(msgs)) == 6
        assert msgs[0][0] == 4



if __name__ == '__main__':
    test_mailboxing()
