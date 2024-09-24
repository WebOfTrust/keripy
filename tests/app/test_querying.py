# -*- encoding: utf-8 -*-
"""
keri.app.querying module

"""
from hio.base import doing

from keri import kering
from keri.app import habbing
from keri.app.querying import (QueryDoer, KeyStateNoticer, LogQuerier, SeqNoQuerier, AnchorQuerier,
                               TelStateNoticer, RegistryLogQuerier, VcLogQuerier)
from keri.core import parsing, eventing, serdering, coring, scheming, Counter, Codens
from keri.vdr import credentialing, verifying, eventing as teventing
from keri.vc.proving import credential
from keri.db.dbing import dgKey


def test_querying():
    with habbing.openHby() as hby, \
            habbing.openHby() as hby1:
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

        parsing.Parser().parseOne(ims=bytearray(rot), kvy=inqHab.kvy)
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


def test_tel_querying(seeder):
    with habbing.openHby() as hby, \
            habbing.openHby() as hby1:
        seeder.seedSchema(hby.db)
        seeder.seedSchema(hby1.db)

        inqHab = hby.makeHab(name="inquisitor")
        subHab = hby1.makeHab(name="subject")

        icp = subHab.makeOwnInception()
        parsing.Parser().parseOne(ims=bytearray(icp), kvy=inqHab.kvy)

        subRgy = credentialing.Regery(hby=hby1, temp=True)
        subVer = verifying.Verifier(hby=hby1, reger=subRgy.reger)

        inqTvy = teventing.Tevery(db=hby.db, lax=True)

        # create management registry
        issuer = subRgy.makeRegistry(prefix=subHab.pre, name="subject")
        rseal = eventing.SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        subHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=subHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=subHab.kever.serder.said))
        subRgy.processEscrows()

        # tsn against management registry
        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvy, pre=subHab.pre, ri=issuer.regk)

        tock = 0.03125
        limit = 1.0
        doist = doing.Doist(limit=limit, tock=tock, real=True)
        deeds = doist.enter(doers=[tsnDoer])
        tever = subVer.reger.tevers.get(issuer.regk)
        rsr = tever.state()

        # first wrong registry
        rsr.i = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
        cue = dict(kin="txnStateSaved", record=rsr)
        inqTvy.cues.append(cue)
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        assert tsnDoer.done is False

        # now correct
        inqTvy.cues.clear()
        rsr = tever.state()
        cue = dict(kin="txnStateSaved", record=rsr)
        inqTvy.cues.append(cue)

        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        regLogDoer = tsnDoer.doers[0]
        assert isinstance(regLogDoer, RegistryLogQuerier)
        assert tsnDoer.done is True
        assert len(regLogDoer.doers) == 1

        anc = subHab.makeOwnEvent(1)
        parsing.Parser().parseOne(ims=bytearray(anc), kvy=inqHab.kvy)

        for msg in subRgy.reger.clonePreIter(pre=issuer.regk, fn=0):
            parsing.Parser().parseOne(ims=msg, tvy=inqTvy)

        deeds = doist.enter(doers=[regLogDoer])
        doist.recur(deeds=deeds)
        assert len(regLogDoer.doers) == 0
        assert regLogDoer.done is True

        # tsn against management regsitry - no update needed
        inqTvy.cues.append(cue)
        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvy, pre=subHab.pre, ri=issuer.regk)
        deeds = doist.enter(doers=[tsnDoer])
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 0
        assert tsnDoer.done is True

        # issue credential in registry
        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
        credSubject = dict(
            d="",
            i=subHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Saids.d)

        creder = credential(issuer=subHab.pre,
                            schema=schema,
                            data=d,
                            status=issuer.regk)

        iss = issuer.issue(said=creder.said)
        rseal = eventing.SealEvent(iss.pre, "0", iss.said)._asdict()
        subHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=subHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=coring.Saider(qb64=subHab.kever.serder.said))
        subRgy.processEscrows()

        msg = creder.raw
        atc = bytearray(msg)
        atc.extend(Counter(Codens.SealSourceTriples, count=1, gvrsn=kering.Vrsn_1_0).qb64b)
        atc.extend(coring.Prefixer(qb64=iss.pre).qb64b)
        atc.extend(coring.Seqner(sn=0).qb64b)
        atc.extend(iss.saidb)
        parsing.Parser().parseOne(ims=bytes(atc), vry=subVer)

        assert subVer.reger.saved.get(keys=(creder.said,)) is not None

        # tsn against vc
        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvy, pre=subHab.pre, ri=issuer.regk, i=iss.pre)
        deeds = doist.enter(doers=[tsnDoer])

        vsr = tever.vcState(iss.pre)

        # wrong ri
        vsr.ri = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
        cue = dict(kin="txnStateSaved", record=vsr)
        inqTvy.cues.append(cue)
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        assert tsnDoer.done is False

        # wrong i
        inqTvy.cues.clear()
        vsr = tever.vcState(iss.pre)
        vsr.i = "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
        cue = dict(kin="txnStateSaved", record=vsr)
        inqTvy.cues.append(cue)
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        assert tsnDoer.done is False

        # now correct
        inqTvy.cues.clear()
        vsr = tever.vcState(iss.pre)
        cue = dict(kin="txnStateSaved", record=vsr)
        inqTvy.cues.append(cue)

        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        vcLogDoer = tsnDoer.doers[0]
        assert isinstance(vcLogDoer, VcLogQuerier)
        assert tsnDoer.done is True
        assert len(vcLogDoer.doers) == 1

        # receive vc updates
        anc = subHab.makeOwnEvent(2)
        parsing.Parser().parseOne(ims=bytearray(anc), kvy=inqHab.kvy)

        for msg in subRgy.reger.clonePreIter(pre=creder.said, fn=0):
            parsing.Parser().parseOne(ims=msg, tvy=inqTvy)

        deeds = doist.enter(doers=[vcLogDoer])
        doist.recur(deeds=deeds)
        assert len(vcLogDoer.doers) == 0
        assert vcLogDoer.done is True

        # vc update against querier without i
        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvy, pre=subHab.pre, ri=issuer.regk)
        deeds = doist.enter(doers=[tsnDoer])
        inqTvy.cues.clear()
        vsr = tever.vcState(iss.pre)
        cue = dict(kin="txnStateSaved", record=vsr)
        inqTvy.cues.append(cue)
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        assert tsnDoer.done is False

        # now do a revocation
        rev = issuer.revoke(said=creder.said)
        rseal = eventing.SealEvent(rev.pre, "1", rev.said)._asdict()
        subHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=subHab.kever.sn)
        issuer.anchorMsg(pre=rev.pre,
                         regd=rev.said,
                         seqner=seqner,
                         saider=coring.Saider(qb64=subHab.kever.serder.said))
        subRgy.processEscrows()

        msg = creder.raw
        atc = bytearray(msg)
        atc.extend(Counter(Codens.SealSourceTriples, count=1, gvrsn=kering.Vrsn_1_0).qb64b)
        atc.extend(coring.Prefixer(qb64=rev.pre).qb64b)
        atc.extend(coring.Seqner(sn=1).qb64b)
        atc.extend(rev.saidb)
        parsing.Parser().parseOne(ims=bytes(atc), vry=subVer)

        assert tever.vcState(vci=creder.said).et == coring.Ilks.rev

        # tsn with rev
        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvy, pre=subHab.pre, ri=issuer.regk, i=iss.pre)
        deeds = doist.enter(doers=[tsnDoer])
        inqTvy.cues.clear()
        vsr = tever.vcState(iss.pre)
        cue = dict(kin="txnStateSaved", record=vsr)
        inqTvy.cues.append(cue)
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        vcLogDoer = tsnDoer.doers[0]
        assert isinstance(vcLogDoer, VcLogQuerier)
        assert tsnDoer.done is True

        # receive vc updates
        anc = subHab.makeOwnEvent(3)
        parsing.Parser().parseOne(ims=bytearray(anc), kvy=inqHab.kvy)

        for msg in subRgy.reger.clonePreIter(pre=creder.said, fn=0):
            parsing.Parser().parseOne(ims=msg, tvy=inqTvy)

        deeds = doist.enter(doers=[vcLogDoer])
        doist.recur(deeds=deeds)
        assert len(vcLogDoer.doers) == 0
        assert vcLogDoer.done is True

        # tsn against vc - no update needed
        inqTvy.cues.clear()
        inqTvy.cues.append(cue)
        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvy, pre=subHab.pre, ri=issuer.regk, i=iss.pre)
        deeds = doist.enter(doers=[tsnDoer])
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 0
        assert tsnDoer.done is True

        # tsn with vc if management registry does not exist
        inqTvyEmpty = teventing.Tevery(db=hby.db, lax=True)
        inqTvyEmpty.cues.append(cue)

        tsnDoer = TelStateNoticer(hby=hby, hab=inqHab, tvy=inqTvyEmpty, pre=subHab.pre, ri=issuer.regk, i=iss.pre)
        deeds = doist.enter(doers=[tsnDoer])
        doist.recur(deeds=deeds)
        assert len(tsnDoer.doers) == 1
        vcLogDoer = tsnDoer.doers[0]
        assert isinstance(vcLogDoer, VcLogQuerier)
        assert tsnDoer.done is True
