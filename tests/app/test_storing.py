# -*- encoding: utf-8 -*-
"""
tests.app.storing

"""
import os
from types import SimpleNamespace

import lmdb
from hio.base import doing
from hio.help import decking

from keri.app import Mailboxer, Respondant, openKS
from keri.kering import Kinds
from keri.core import Prefixer, SerderKERI, exchange
from keri.db import OnSuber, openLMDB, openDB



def test_mailboxing():
    """
    Test Mailboxer Class
    """
    mber = Mailboxer(temp=True)

    assert isinstance(mber, Mailboxer)
    assert mber.name == "mbx"
    #assert mber.temp is False
    assert mber.temp
    assert isinstance(mber.env, lmdb.Environment)
    assert mber.path.endswith(os.path.join("keri", "mbx", "mbx"))
    assert mber.env.path() == mber.path
    assert os.path.exists(mber.path)

    #assert isinstance(mber.tpcs, lmdb._Database)
    assert isinstance(mber.tpcs, OnSuber)

    mber.close(clear=True)
    assert not os.path.exists(mber.path)
    assert not mber.opened

    mber = Mailboxer(reopen=False, temp=True)
    assert isinstance(mber, Mailboxer)
    assert mber.name == "mbx"
    assert mber.temp
    #assert mber.temp is False
    assert mber.opened is False
    assert mber.path is None
    assert mber.env is None

    mber.reopen()
    assert mber.opened
    assert mber.path is not None
    assert isinstance(mber.env, lmdb.Environment)
    assert mber.path.endswith(os.path.join("keri", "mbx", "mbx"))
    assert mber.env.path() == mber.path
    assert os.path.exists(mber.path)

    mber.close(clear=True)
    assert not os.path.exists(mber.path)
    assert not mber.opened

    with openLMDB(cls=Mailboxer) as mber:
        assert isinstance(mber, Mailboxer)

        msg = (
            b'{"v":"KERICAACAAJSONAAD-.","t":"exn","d":"EK8rUMKMlBIKGBXWs7SCXxrYZ9TCqL2ATY-GHnTrC67k",'
            b'"i":"EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I","ri":"","x":"","p":"",'
            b'"dt":"2021-07-15T13:01:37.624492+00:00","r":"/credential/issue","q":{},'
            b'"a":{"a":"b","b":123}}')

        dest = Prefixer(qb64="EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")
        saved = mber.storeMsg(topic=dest.qb64b, msg=msg)
        assert saved is True

        actual = mber.getTopicMsgs(topic=dest.qb64)
        assert actual[0] == msg

    assert not os.path.exists(mber.path)

    with openLMDB(cls=Mailboxer) as mber, \
            openDB(name="test") as db, \
            openKS(name="test") as ks:

        for idx in range(10):
            d = dict(a="b", b=idx)
            dest = Prefixer(qb64="EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I")

            exn = exchange(route="/credential/issue",
                              attributes=d,
                              stamp="2021-07-15T13:01:37.624492+00:00",
                              sender=dest.qb64,
                              kind=Kinds.json)
            mber.storeMsg(topic=dest.qb64b, msg=exn.raw)

        msgs = []
        for fn, topic, msg in mber.cloneTopicIter(topic=dest.qb64b):
            msgs.append((fn, msg))

        assert(len(msgs)) == 10

        for idx, msg in msgs:
            exn = SerderKERI(raw=msg)
            d = exn.ked["a"]
            assert d["b"] == idx

        #msgs = []
        #for fn, topic, msg in mber.cloneTopicIter(topic=dest.qb64b, fn=10):
            #msgs.append(msg)

        #assert(len(msgs)) == 0

        #msgs = []
        #for tn, topic, msg in mber.cloneTopicIter(topic=dest.qb64b, fn=4):
            #msgs.append((tn, msg))

        #assert(len(msgs)) == 6
        #assert msgs[0][0] == 4


def test_respondant_discards_unhandled_cues():
    class CountingDeck(decking.Deck):
        def __init__(self, *args):
            super(CountingDeck, self).__init__(*args)
            self.pulls = 0

        def pull(self, emptive=True):
            cue = super(CountingDeck, self).pull(emptive=emptive)
            self.pulls += cue is not None
            return cue

    cue = dict(kin="query")
    cues = CountingDeck([cue])
    rep = Respondant(hby=SimpleNamespace(name="test"), cues=cues, mbx=object())
    doist = doing.Doist(real=False, tock=0.1)
    doer = rep.cueDo(tymth=doist.tymen(), tock=0.1)

    next(doer)
    next(doer)

    assert not cues

    next(doer)
    assert cues.pulls == 1

    doer.close()


def test_respondant_processes_supported_cues():
    source = "EAD919wF4oiG7ck6mnBWTRD_Z-Io0wZKCxL0zjx5je9I"
    dest = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    serder = exchange(route="/test", attributes={}, sender=source, kind=Kinds.json)
    hab = SimpleNamespace(
        receipt=lambda *args, **kwa: bytearray(serder.raw),
        endorse=lambda *args, **kwa: bytearray(serder.raw),
    )
    hby = SimpleNamespace(
        name="test",
        kevers={serder.pre: SimpleNamespace(wits=[source]), dest: object()},
        prefixes=[source],
        habByPre=lambda pre: hab,
    )
    cues = decking.Deck([
        dict(kin="receipt", serder=serder),
        dict(kin="replay", src=source, dest=dest, msgs=[serder.raw]),
        dict(kin="reply", src=source, dest=dest, serder=serder),
    ])
    rep = Respondant(hby=hby, cues=cues, mbx=object())
    sent = []
    rep.postman.send = lambda *args, **kwa: sent.append(kwa["topic"])
    doist = doing.Doist(real=False, tock=0.1)
    doer = rep.cueDo(tymth=doist.tymen(), tock=0.1)

    next(doer)
    for _ in range(3):
        next(doer)

    assert sent == ["receipt", "replay", "reply"]
    assert not cues

    doer.close()



if __name__ == '__main__':
    test_mailboxing()
