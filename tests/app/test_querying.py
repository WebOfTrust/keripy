# -*- encoding: utf-8 -*-
"""
keri.app.querying module

"""
from hio.base import doing

from keri.kering import Vrsn_1_0
from keri.app import (QueryDoer, KeyStateNoticer, LogQuerier,
                      SeqNoQuerier, AnchorQuerier, openHby)

from keri.core import SerderKERI, Parser, reply
from keri.db import dgKey


def test_querying():
    with openHby() as hby, \
            openHby() as hby1:
        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre)

        icp = subHab.msgOwnInception(framed=True)
        Parser(version=Vrsn_1_0).parseOne(ims=bytearray(icp), kvy=inqHab.kvy)

        assert qdoer is not None

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)

        # doist.do(doers=doers)
        deeds = doist.enter(doers=[qdoer])

        assert len(qdoer.doers) == 1
        ksnDoer = qdoer.doers[0]
        assert isinstance(ksnDoer, KeyStateNoticer)
        assert len(ksnDoer.witq.msgs) == 1
        msg = ksnDoer.witq.msgs.popleft()
        assert msg["src"] == inqHab.pre
        assert msg["pre"] == subHab.pre
        assert msg["r"] == "ksn"
        assert msg["q"] == {'fn': '0', 's': '0'}
        assert msg["wits"] is None

        doist.recur(deeds=deeds)

        # Cue up a saved key state equal to the one we have
        hby.kvy.cues.clear()
        ksr = subHab.kever.state()
        rpy = reply(route="/ksn", data=ksr._asdict())
        cue = dict(kin="keyStateSaved", ksn=ksr._asdict())
        hby.kvy.cues.append(cue)

        doist.recur(deeds=deeds)

        # We already have up to date key state so loaded will be true
        assert qdoer.done is True
        assert len(hby.kvy.cues) == 0

        # create a new query doer
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre)
        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)

        # rotate AID and submit as a new keyStateSave
        rot = subHab.rotate(framed=True)
        ksr = subHab.kever.state()
        rpy = reply(route="/ksn", data=ksr._asdict())
        cue = dict(kin="keyStateSaved", ksn=ksr._asdict())
        hby.kvy.cues.append(cue)
        deeds = doist.enter(doers=[qdoer])
        doist.recur(deeds=deeds)

        # We are behind in key state, so we aren't done and have queried for the logs
        assert qdoer.done is False
        assert len(qdoer.doers) == 1
        ksnDoer = qdoer.doers[0]
        assert isinstance(ksnDoer, KeyStateNoticer)
        assert len(ksnDoer.witq.msgs) == 1

        assert len(ksnDoer.doers) == 1
        logDoer = ksnDoer.doers[0]
        assert isinstance(logDoer, LogQuerier)
        assert len(hby.kvy.cues) == 0

        Parser(version=Vrsn_1_0).parseOne(ims=bytearray(rot), kvy=inqHab.kvy)
        doist.recur(deeds=deeds)

        assert qdoer.done is True

        # Test sequence querier
        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre=subHab.pre, sn=5)
        assert len(sdoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[sdoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 0

        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre=subHab.pre, sn=1)
        assert len(sdoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[sdoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 1

        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre=subHab.pre, fn=2, sn=4)
        assert len(sdoer.witq.msgs) == 1
        msg = sdoer.witq.msgs.pull()
        query = msg['q']
        assert query == {'fn': '2', 's': '4'}

        # Test with originally unknown AID
        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre="ExxCHAI9bkl50F5SCKl2AWQbFGKeJtz0uxM2diTMxMQA", sn=1)
        assert len(sdoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[sdoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 1

        # Test anchor querier
        adoer = AnchorQuerier(hby=hby, hab=inqHab, pre=subHab.pre, anchor={'s': '5'})
        assert len(adoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[adoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 1

        # Test with originally unknown AID
        adoer = AnchorQuerier(hby=hby, hab=inqHab, pre="ExxCHAI9bkl50F5SCKl2AWQbFGKeJtz0uxM2diTMxMQA",
                              anchor={'s': '5'})
        assert len(adoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[adoer])
        doist.recur(deeds=deeds)
        assert len(adoer.witq.msgs) == 1

def test_query_not_found_escrow():
    with openHby() as hby, \
            openHby() as hby1:
        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")

        icp = inqHab.msgOwnInception(framed=True)
        subHab.psr.parseOne(ims=icp)
        assert inqHab.pre in subHab.kevers

        qry = inqHab.query(subHab.pre, route="/foo", src=inqHab.pre)
        serder = SerderKERI(raw=qry)
        dgkey = dgKey(inqHab.pre, serder.saidb)

        subHab.db.evts.put(keys=(inqHab.pre, serder.saidb), val=serder)
        subHab.db.qnfs.add(keys=(inqHab.pre, serder.said), val=serder.saidb)

        subHab.kvy.processQueryNotFound()
        assert subHab.db.qnfs.get(dgkey) == []


def test_query_not_found_escrow_is_idempotent():
    """A qry the node cannot answer is re-processed on every loop pass; escrowing it must
    be idempotent so the loop does not re-write (and re-fsync) an unchanged escrow each
    pass. Once escrowed, re-processing performs NO further escrow writes, the entry and its
    first-seen datetime are untouched, and a later-arriving KEL still resolves it."""
    with openHby() as hby, openHby() as hby1, openHby() as hby2:
        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")
        tgtHab = hby2.makeHab(name="target")  # an AID the subject does NOT have

        # subject must know the inquisitor's KEL to verify the query's source signature
        subHab.psr.parseOne(ims=inqHab.msgOwnInception(framed=True))
        assert inqHab.pre in subHab.kevers
        assert tgtHab.pre not in subHab.kevers  # so the query is genuinely unanswerable

        # drive the real query path: keripy parks it via escrowQueryNotFoundEvent
        qry = inqHab.query(tgtHab.pre, route="ksn", src=inqHab.pre)
        serder = SerderKERI(raw=qry)
        dgkey = dgKey(inqHab.pre, serder.saidb)
        qkeys = (inqHab.pre, serder.said)
        subHab.psr.parseOne(ims=bytearray(qry))
        assert subHab.db.qnfs.get(keys=qkeys)  # keripy parked it
        dt0 = subHab.db.dtss.get(keys=dgkey)
        assert dt0 is not None

        # Spy on the escrow datetime write: re-processing an already-escrowed entry must
        # not write it again. Without the idempotency guard, escrowQueryNotFoundEvent re-runs
        # every pass and re-issues dtss.put (a no-op overwrite=False put, but still a write
        # transaction that commits+fsyncs) -- the churn this fix removes.
        writes = []
        orig_put = subHab.db.dtss.put
        subHab.db.dtss.put = lambda *a, **k: (writes.append(1), orig_put(*a, **k))[1]
        try:
            for _ in range(5):
                subHab.kvy.processQueryNotFound()
        finally:
            subHab.db.dtss.put = orig_put
        assert writes == []  # no re-write of the already-escrowed entry across 5 passes
        assert subHab.db.qnfs.get(keys=qkeys)                   # entry still parked
        assert subHab.db.dtss.get(keys=dgkey).qb64 == dt0.qb64  # datetime untouched

        # once the queried KEL arrives, the escrow still resolves and is removed
        subHab.psr.parseOne(ims=tgtHab.msgOwnInception(framed=True))
        assert tgtHab.pre in subHab.kevers
        subHab.kvy.processQueryNotFound()
        assert subHab.db.qnfs.get(keys=qkeys) == []
