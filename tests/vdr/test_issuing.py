# -*- encoding: utf-8 -*-
"""
tests.vdr.issuing module

"""
import pytest

from keri.kering import Ilks

from keri.app import openKS
from keri.core import SealEvent, Seqner, Diger
from keri.db import openDB
from keri.vc import credential as provingCredential
from keri.vdr import Regery

from tests.vdr import buildHab


def credential(hab, regk):
    """
    Generate test credential from with Habitat as issuer

    Parameters:
        hab (Habitat): issuer environment
        regk (str) qb64 of registry

    """
    credSubject = dict(
        d="",
        i="EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",
        LEI="254900OPPU84GM83MG36",
    )

    creder = provingCredential(issuer=hab.pre,
                        schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                        data=credSubject,
                        status=regk)

    return creder


def events(issuer):
    assert len(issuer.cues) == 2
    cue = issuer.cues.popleft()
    assert cue["kin"] == "kevt"
    kevt = cue["msg"]
    cue = issuer.cues.popleft()
    assert cue["kin"] == "send"
    tevt = cue["msg"]

    return kevt, tevt


def test_issuer(mockHelpingNowUTC):
    with openDB(name="bob") as db, openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)
        # setup issuer with defaults for allowBackers, backers and estOnly
        regery = Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        res = issuer.rotate(adds=["BAFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        assert res is not None

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rev.pre,
                         regd=rev.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()

        with openDB(name="bob") as db, openKS(name="bob") as kpr:
            hby, hab = buildHab(db, kpr)
            # issuer, not allowed to issue backers
            regery = Regery(hby=hby, name="bob", temp=True)
            issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True)
            rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
            hab.interact(data=[rseal])
            seqner = Seqner(sn=hab.kever.sn)
            diger = Diger(qb64=hab.kever.serder.said)
            issuer.anchorMsg(pre=issuer.regk,
                             regd=issuer.regd,
                             seqner=seqner,
                             saider=diger)
            regery.processEscrows()
            assert issuer.regk in regery.reger.tevers

            with pytest.raises(ValueError):
                issuer.rotate(adds=["EBoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        with openDB(name="bob") as db, openKS(name="bob") as kpr:
            hby, hab = buildHab(db, kpr)
            regery = Regery(hby=hby, name="bob", temp=True)
            issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True)
            rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
            hab.interact(data=[rseal])
            seqner = Seqner(sn=hab.kever.sn)
            diger = Diger(qb64=hab.kever.serder.said)
            issuer.anchorMsg(pre=issuer.regk,
                             regd=issuer.regd,
                             seqner=seqner,
                             saider=diger)
            regery.processEscrows()
            assert issuer.regk in regery.reger.tevers

            creder = credential(hab=hab, regk=issuer.regk)

            iss = issuer.issue(said=creder.said)
            rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
            hab.interact(data=[rseal])
            seqner = Seqner(sn=hab.kever.sn)
            diger = Diger(qb64=hab.kever.serder.said)
            issuer.anchorMsg(pre=iss.pre,
                             regd=iss.said,
                             seqner=seqner,
                             saider=diger)
            regery.processEscrows()
            state = issuer.tever.vcState(vci=creder.said)
            assert state.et == Ilks.iss

            rev = issuer.revoke(said=creder.said)
            rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
            hab.interact(data=[rseal])
            seqner = Seqner(sn=hab.kever.sn)
            diger = Diger(qb64=hab.kever.serder.said)
            issuer.anchorMsg(pre=rev.pre,
                             regd=rev.said,
                             seqner=seqner,
                             saider=diger)
            regery.processEscrows()
            state = issuer.tever.vcState(vci=creder.said)
            assert state.et == Ilks.rev

    with openDB(name="bob") as db, openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        regery = Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False,
                                     baks=["BAFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.et == Ilks.bis

        rot = issuer.rotate(adds=["BCDfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                  "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        rseq = Seqner(sn=rot.sn)
        rseal = SealEvent(rot.pre, rseq.snh, rot.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rot.pre,
                         regd=rot.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.state()
        assert state.et == Ilks.vrt

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rev.pre,
                         regd=rev.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.et == Ilks.brv

    with openDB(name="bob") as db, openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        regery = Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True, estOnly=True)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.et == Ilks.iss

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rev.pre,
                         regd=rev.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.et == Ilks.rev

        with pytest.raises(ValueError):
            issuer.rotate(adds=["BAFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])

    with openDB(name="bob") as db, openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, backers allowed, initial backer, establishment events only
        regery = Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False,
                                     baks=["BAFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], estOnly=True)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.rotate(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        rot = issuer.rotate(toad=3, adds=["BADfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                          "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        rseq = Seqner(sn=rot.sn)
        rseal = SealEvent(rot.pre, rseq.snh, rot.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rot.pre,
                         regd=rot.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.state()
        assert state.et == Ilks.vrt

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.et == Ilks.bis

        # rotate to 2 backers
        rot = issuer.rotate(toad=2, cuts=["BAFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        rseq = Seqner(sn=rot.sn)
        rseal = SealEvent(rot.pre, rseq.snh, rot.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rot.pre,
                         regd=rot.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.state()
        assert state.et == Ilks.vrt

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        diger = Diger(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=rev.pre,
                         regd=rev.said,
                         seqner=seqner,
                         saider=diger)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.et == Ilks.brv

    """ End Test """



if __name__ == "__main__":
    pytest.main(['-vv', 'test_issuing.py::test_issuer'])
    # test_issuer()
