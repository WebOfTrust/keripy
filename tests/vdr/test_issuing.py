# -*- encoding: utf-8 -*-
"""
tests.vdr.issuing module

"""
import pytest

from keri.app import habbing, keeping
from keri.core import coring
from keri.core.eventing import SealEvent
from keri.db import basing
from keri.vc import proving
from keri.vdr import credentialing


def test_issuer(mockHelpingNowUTC):
    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)
        # setup issuer with defaults for allowBackers, backers and estOnly
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        res = issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        assert res is not None

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rev.pre, regd=rev.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
            hby, hab = buildHab(db, kpr)
            # issuer, not allowed to issue backers
            regery = credentialing.Regery(hby=hby, name="bob", temp=True)
            issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True)
            rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
            hab.interact(data=[rseal])
            seqner = coring.Seqner(sn=hab.kever.sn)
            issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
            regery.processEscrows()
            assert issuer.regk in regery.reger.tevers

            with pytest.raises(ValueError):
                issuer.rotate(adds=["EqoNZAX5Lu8RuHzwwyn5tCZTe-mDBq5zusCrRo5TDugs"])

        with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
            hby, hab = buildHab(db, kpr)
            regery = credentialing.Regery(hby=hby, name="bob", temp=True)
            issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True)
            rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
            hab.interact(data=[rseal])
            seqner = coring.Seqner(sn=hab.kever.sn)
            issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
            regery.processEscrows()
            assert issuer.regk in regery.reger.tevers

            creder = credential(hab=hab, regk=issuer.regk)

            iss = issuer.issue(said=creder.said)
            rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
            hab.interact(data=[rseal])
            seqner = coring.Seqner(sn=hab.kever.sn)
            issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
            regery.processEscrows()
            state = issuer.tever.vcState(vci=creder.said)
            assert state.ked["et"] == coring.Ilks.iss

            rev = issuer.revoke(said=creder.said)
            rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
            hab.interact(data=[rseal])
            seqner = coring.Seqner(sn=hab.kever.sn)
            issuer.anchorMsg(pre=rev.pre, regd=rev.said, seqner=seqner, saider=hab.kever.serder.saider)
            regery.processEscrows()
            state = issuer.tever.vcState(vci=creder.said)
            assert state.ked["et"] == coring.Ilks.rev

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, allowed backers, initial set of backers
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False,
                                     baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.ked["et"] == coring.Ilks.bis

        rot = issuer.rotate(adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                  "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        rseq = coring.Seqner(sn=rot.sn)
        rseal = SealEvent(rot.pre, rseq.snh, rot.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rot.pre, regd=rot.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.state()
        assert state.ked["et"] == coring.Ilks.vrt

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rev.pre, regd=rev.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.ked["et"] == coring.Ilks.brv

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, no backers allowed, establishment events only
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=True, estOnly=True)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.ked["et"] == coring.Ilks.iss

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rev.pre, regd=rev.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.ked["et"] == coring.Ilks.rev

        with pytest.raises(ValueError):
            issuer.rotate(adds=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])

    with basing.openDB(name="bob") as db, keeping.openKS(name="bob") as kpr:
        hby, hab = buildHab(db, kpr)

        # issuer, backers allowed, initial backer, establishment events only
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="bob", noBackers=False,
                                     baks=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"], estOnly=True)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.rotate(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        assert issuer.regk in regery.reger.tevers

        rot = issuer.rotate(toad=3, adds=["B9DfgIp33muOuCI0L8db_TldMJXv892UmW8yfpUuKzkw",
                                          "BBC_BBLMeVwKFbfYSWU7aATS9itLSrGtIFQzCkfoKnjk"])
        rseq = coring.Seqner(sn=rot.sn)
        rseal = SealEvent(rot.pre, rseq.snh, rot.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rot.pre, regd=rot.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.state()
        assert state.ked["et"] == coring.Ilks.vrt

        creder = credential(hab=hab, regk=issuer.regk)
        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.ked["et"] == coring.Ilks.bis

        # rotate to 2 backers
        rot = issuer.rotate(toad=2, cuts=["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"])
        rseq = coring.Seqner(sn=rot.sn)
        rseal = SealEvent(rot.pre, rseq.snh, rot.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rot.pre, regd=rot.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.state()
        assert state.ked["et"] == coring.Ilks.vrt

        rev = issuer.revoke(said=creder.said)
        rseal = SealEvent(rev.pre, "1", rev.said)._asdict()
        hab.rotate(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=rev.pre, regd=rev.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()
        state = issuer.tever.vcState(vci=creder.said)
        assert state.ked["et"] == coring.Ilks.brv

    """ End Test """


def buildHab(db, ks, name="test"):
    """Utility to setup Habery and Hab for testing purposes
    Returns:
       tuple (Habery, Hab):
    """
    secrets = [
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
    ]
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])
    # setup hab
    hby = habbing.Habery(name=name, temp=True, ks=ks, db=db)
    hab = hby.makeHab(name=name, secrecies=secrecies)
    # hab = habbing.Habitat(ks=ks, db=db, secrecies=secrecies, temp=True)
    return (hby, hab)


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

    creder = proving.credential(issuer=hab.pre,
                                schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                                subject=credSubject,
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


if __name__ == "__main__":
    pytest.main(['-vv', 'test_issuing.py::test_issuer'])
    # test_issuer()
