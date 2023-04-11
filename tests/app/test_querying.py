# -*- encoding: utf-8 -*-
"""
keri.app.querying module

"""
from hio.base import doing

from keri.app import habbing
from keri.app.querying import QueryDoer
from keri.core import parsing


def test_querying():
    with habbing.openHby() as hby, \
            habbing.openHby() as hby1:
        print()
        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre)

        icp = subHab.makeOwnInception()
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=inqHab.kvy)

        assert qdoer is not None

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)

        # doist.do(doers=doers)
        deeds = doist.enter(doers=[qdoer])
        doist.recur(deeds=deeds)

        assert len(qdoer.witq.msgs) == 1
        msg = qdoer.witq.msgs.popleft()
        assert msg["src"] == inqHab.pre
        assert msg["pre"] == subHab.pre
        assert msg["r"] == "ksn"
        assert msg["q"] == {'s': 0}
        assert msg["wits"] is None

        # Cue up a saved key state equal to the one we have
        hby.kvy.cues.clear()
        ksn = subHab.kever.state()
        cue = dict(kin="keyStateSaved", serder=ksn)
        hby.kvy.cues.append(cue)

        doist.recur(deeds=deeds)

        # We already have up to date key state so loaded will be true
        assert qdoer.loaded is True
        assert len(hby.kvy.cues) == 0

        # create a new query doer
        qdoer = QueryDoer(hby=hby, hab=inqHab, kvy=hby.kvy, pre=subHab.pre)
        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)

        # rotate AID and submit as a new keyStateSave
        subHab.rotate()
        ksn = subHab.kever.state()
        cue = dict(kin="keyStateSaved", serder=ksn)
        hby.kvy.cues.append(cue)

        deeds = doist.enter(doers=[qdoer])
        doist.recur(deeds=deeds)

        # We are behind in key state, so we aren't done and have queried for the logs
        assert qdoer.loaded is False
        assert len(qdoer.witq.msgs) == 2
        msg = qdoer.witq.msgs[0]
        assert msg["src"] == inqHab.pre
        assert msg["pre"] == subHab.pre
        assert msg["r"] == "logs"
        assert msg["q"] == {'s': 0}
        assert msg["wits"] is None

        icp = subHab.makeOwnEvent(sn=1)
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=inqHab.kvy)
        doist.recur(deeds=deeds)
        assert qdoer.loaded is True
