# -*- encoding: utf-8 -*-
"""
keri.app.querying module

"""
from hio.base import doing

from keri.kering import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.app import (QueryDoer, KeyStateNoticer, LogQuerier,
                      SeqNoQuerier, AnchorQuerier, openHby)

from keri.core import SerderKERI, Parser, Kevery, reply
from keri.db import dgKey

from tests.common import CUE_KWA, KWA


def test_querying():
    with openHby(version=Vrsn_1_0) as hby, \
            openHby(version=Vrsn_1_0) as hby1:
        inqHab = hby.makeHab(name="inquisitor", **KWA)
        subHab = hby1.makeHab(name="subject", **KWA)
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre)

        icp = subHab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)
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
        rpy = reply(route="/ksn", data=ksr._asdict(), **KWA)
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
        rot = subHab.rotate(framed=True, **CUE_KWA)
        ksr = subHab.kever.state()
        rpy = reply(route="/ksn", data=ksr._asdict(), **KWA)
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


def test_querying_v2():
    with openHby(version=Vrsn_2_0) as hby, \
            openHby(version=Vrsn_2_0) as hby1:
        inqHab = hby.makeHab(name="inquisitor", version=Vrsn_2_0, kind=Kinds.cesr)
        subHab = hby1.makeHab(name="subject", version=Vrsn_2_0, kind=Kinds.cesr)
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre,
                          version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)

        icp = subHab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(icp), kvy=inqHab.kvy)

        assert qdoer is not None

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)

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
        assert msg["kwa"]["version"] == Vrsn_2_0
        assert msg["kwa"]["kind"] == Kinds.cesr
        assert msg["kwa"]["gvrsn"] == Vrsn_2_0

        doist.recur(deeds=deeds)

        # Cue up a saved key state equal to the one we have
        hby.kvy.cues.clear()
        ksr = subHab.kever.state()
        cue = dict(kin="keyStateSaved", ksn=ksr._asdict())
        hby.kvy.cues.append(cue)

        doist.recur(deeds=deeds)

        # We already have up to date key state so loaded will be true
        assert qdoer.done is True
        assert len(hby.kvy.cues) == 0

        # create a new query doer
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre,
                          version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)

        # rotate AID and submit as a new keyStateSave
        rot = subHab.rotate(framed=True, version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        ksr = subHab.kever.state()
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

        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(rot), kvy=inqHab.kvy)
        doist.recur(deeds=deeds)

        assert qdoer.done is True

        # Test sequence querier
        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre=subHab.pre, sn=5,
                              version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        assert len(sdoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[sdoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 0

        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre=subHab.pre, sn=1,
                              version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        assert len(sdoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[sdoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 1

        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre=subHab.pre, fn=2, sn=4,
                              version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        assert len(sdoer.witq.msgs) == 1
        msg = sdoer.witq.msgs.pull()
        query = msg['q']
        assert query == {'fn': '2', 's': '4'}
        assert msg["kwa"]["version"] == Vrsn_2_0
        assert msg["kwa"]["kind"] == Kinds.cesr
        assert msg["kwa"]["gvrsn"] == Vrsn_2_0

        # Test with originally unknown AID
        sdoer = SeqNoQuerier(hby=hby, hab=inqHab, pre="ExxCHAI9bkl50F5SCKl2AWQbFGKeJtz0uxM2diTMxMQA",
                              sn=1, version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        assert len(sdoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[sdoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 1

        # Test anchor querier
        adoer = AnchorQuerier(hby=hby, hab=inqHab, pre=subHab.pre, anchor={'s': '5'},
                              version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        assert len(adoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[adoer])
        doist.recur(deeds=deeds)
        assert len(sdoer.witq.msgs) == 1

        # Test with originally unknown AID
        adoer = AnchorQuerier(hby=hby, hab=inqHab, pre="ExxCHAI9bkl50F5SCKl2AWQbFGKeJtz0uxM2diTMxMQA",
                              anchor={'s': '5'}, version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        assert len(adoer.witq.msgs) == 1

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[adoer])
        doist.recur(deeds=deeds)
        assert len(adoer.witq.msgs) == 1

        # KRAM assertions for a v2 query parsed by the receiver
        icp = inqHab.msgOwnInception(framed=True, gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parseOne(ims=bytearray(icp), kvy=hby1.kvy)
        assert inqHab.pre in hby1.kevers

        qry = inqHab.query(subHab.pre, route="ksn", src=inqHab.pre,
                           version=Vrsn_2_0, kind=Kinds.cesr, gvrsn=Vrsn_2_0)
        serder = SerderKERI(raw=qry)
        assert serder.pvrsn == Vrsn_2_0
        assert serder.gvrsn == Vrsn_2_0
        assert serder.kind == Kinds.cesr

        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        hby1.cf.put(cf)
        kvy = Kevery(db=hby1.db, cf=hby1.cf, enableKram=True, lax=False, local=False)
        assert kvy.kramer.enabled is True

        Parser(version=Vrsn_2_0).parse(ims=bytearray(qry), kvy=kvy)
        cache = hby1.db.kramMSGC.get(keys=(inqHab.pre, serder.said))
        assert cache is not None
        assert cache.mdt == serder.stamp
        assert cache.d == 1000


def test_query_not_found_escrow():
    with openHby(version=Vrsn_1_0) as hby, \
            openHby(version=Vrsn_1_0) as hby1:
        inqHab = hby.makeHab(name="inquisitor", **KWA)
        subHab = hby1.makeHab(name="subject", **KWA)

        icp = inqHab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)
        subHab.psr.parseOne(ims=icp)
        assert inqHab.pre in subHab.kevers

        qry = inqHab.query(subHab.pre, route="/foo", src=inqHab.pre, **CUE_KWA)
        serder = SerderKERI(raw=qry)
        dgkey = dgKey(inqHab.pre, serder.saidb)

        subHab.db.evts.put(keys=(inqHab.pre, serder.saidb), val=serder)
        subHab.db.qnfs.add(keys=(inqHab.pre, serder.said), val=serder.saidb)

        subHab.kvy.processQueryNotFound()
        assert subHab.db.qnfs.get(dgkey) == []
