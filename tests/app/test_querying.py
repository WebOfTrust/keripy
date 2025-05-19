# -*- encoding: utf-8 -*-
"""
keri.app.querying module

"""
from hio.base import doing

from keri.kering import Vrsn_1_0, Vrsn_2_0
from keri.app import habbing
from keri.app.querying import QueryDoer, KeyStateNoticer, LogQuerier, SeqNoQuerier, AnchorQuerier
from keri.core import parsing, eventing, serdering
from keri.db.dbing import dgKey


def test_querying():
    with habbing.openHby() as hby, \
            habbing.openHby() as hby1:
        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre)

        icp = subHab.makeOwnInception()
        parsing.Parser(version=Vrsn_1_0).parseOne(ims=bytearray(icp), kvy=inqHab.kvy)

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
        rpy = eventing.reply(route="/ksn", data=ksr._asdict())
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
        rot = subHab.rotate()
        ksr = subHab.kever.state()
        rpy = eventing.reply(route="/ksn", data=ksr._asdict())
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

        parsing.Parser(version=Vrsn_1_0).parseOne(ims=bytearray(rot), kvy=inqHab.kvy)
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
    with habbing.openHby() as hby, \
            habbing.openHby() as hby1:
        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")

        icp = inqHab.makeOwnInception()
        subHab.psr.parseOne(ims=icp)
        assert inqHab.pre in subHab.kevers

        qry = inqHab.query(subHab.pre, route="/foo", src=inqHab.pre)
        serder = serdering.SerderKERI(raw=qry)
        dgkey = dgKey(inqHab.pre, serder.saidb)

        subHab.db.putEvt(dgkey, serder.raw)
        subHab.db.qnfs.add(keys=(inqHab.pre, serder.said), val=serder.saidb)

        subHab.kvy.processQueryNotFound()
        assert subHab.db.qnfs.get(dgkey) == []
