from keri.app import habbing, delegating, keeping
from keri.core import eventing, parsing, coring
from keri.db import basing


def test_delegating():
    # Dan is the delegator
    # Deb is the delegatee, or the entity "requesting" delegation of an identifier
    with habbing.openHab(name="dan", salt=b'0123456789abcdef', transferable=True, temp=True) as danHab:
        # delegatee
        ks = keeping.Keeper(name="deb", temp=True)
        ks.reopen()
        db = basing.Baser(name="deb", temp=True)
        db.reopen()

        # start delegation
        delegatey = delegating.Delegatey(name="deb", db=db, ks=ks)
        msg = dict(
            delpre=danHab.pre,
            salt="0123456789abcdef",
            transferable=True,
            icount=1,
            ncount=1,
            isith=1,
            nsith=1,
        )
        # results in processing of delcept
        delegatey.processMessage(msg)
        debHab = delegatey.hab

        assert delegatey.hab.name == "deb"

        danpre = danHab.pre
        debpre = debHab.pre
        assert danpre == "EqueYwA9skz3SLqOYe8Lu4vzYDIJZSU984yrK3l1bEvw"
        assert debpre == "Exd3lO6YoAhP7CP2zCu2h1thLzl1_ux7IzuUrAbCIvoc"

        delsrdr = delegatey.posts[0]["srdr"]
        delsigers = delegatey.posts[0]["sigers"]

        assert delsrdr.ked["t"] == "dip"
        assert delsrdr.ked["i"] == debpre
        assert delsrdr.ked["di"] == danpre

        assert debHab.kvy.cues[0]["kin"] == "delegatage"
        assert debHab.kvy.cues[0]["delpre"] == danpre

        # delegator
        dankvy = eventing.Kevery(db=danHab.db, lax=False, local=False)
        evt = eventing.messagize(serder=delsrdr, sigers=delsigers)

        # process an incoming delcept
        parsing.Parser().parse(ims=evt, kvy=dankvy)
        srdr = dankvy.cues[0]["serder"]
        assert dankvy.cues[0]["kin"] == "delegating"
        assert srdr.ked["t"] == "dip"
        assert srdr.ked["i"] == debpre
        assert srdr.ked["di"] == danpre

        # business logic outstanding, approve delegation automagically with interact
        msg = danHab.interact(data=[
            dict(i=srdr.pre, s=srdr.ked["s"], d=srdr.dig)
        ])

        isrdr = coring.Serder(raw=msg)
        assert isrdr.ked["i"] == danpre
        assert isrdr.ked["t"] == "ixn"
        assert isrdr.ked["a"][0]["i"] == debpre
        assert isrdr.ked["a"][0]["s"] == "0"
        assert isrdr.ked["a"][0]["d"] == "EXYtHVmEoXMboHOBfaZ-BEsStcQ9E2YQ8zqR6CSaCpK4"

        danHab.kvy.processEscrows()
        # after process interact and escrow, ensure we have the out of escrow event
        assert danHab.kvy.cues[2]["kin"] == "psUnescrow"
        assert danHab.kvy.cues[2]["serder"].ked["i"] == debpre
        assert danHab.kvy.cues[2]["serder"].ked["di"] == danpre

        # process dan's (delegator) events with kvy for deb (delegatee)
        debkvy = eventing.Kevery(db=debHab.db, lax=False, local=False)
        parsing.Parser().parse(ims=danHab.makeOwnEvent(sn=0), kvy=debkvy)
        parsing.Parser().parse(ims=msg, kvy=debkvy)

        debHab.kvy.processEscrows()
        # after process interact and escrow, ensure we have the out of escrow event
        assert debHab.kvy.cues[2]["kin"] == "psUnescrow"
        assert danHab.kvy.cues[2]["serder"].ked["i"] == debpre

        # finally ensure we can accept the delegation
        debHab.delegationAccepted()

        assert debHab.accepted is True
        # happy delegation
