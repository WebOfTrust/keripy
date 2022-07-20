# -*- encoding: utf-8 -*-
"""
tests.core.test_keystate module

Test key state notification reply messages
routes: /ksn

"""
from keri.app import keeping, habbing
from keri.core import coring, eventing, parsing, routing
from keri.db import basing


def test_keystate(mockHelpingNowUTC):
    """
        {
          "v": "KERI10JSON000301_",
          "t": "rpy",
          "d": "E_9aLcmV9aEVEm7mXvEY3V_CmbyvG7Ahj6HCq-D48meM",
          "dt": "2021-11-04T12:57:59.823350+00:00",
          "r": "/ksn/EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg",
          "a": {
            "v": "KERI10JSON000274_",
            "i": "EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg",
            "s": "1",
            "t": "ksn",
            "p": "ESORkffLV3qHZljOcnijzhCyRT0aXM2XHGVoyd5ST-Iw",
            "d": "EtgNGVxYd6W0LViISr7RSn6ul8Yn92uyj2kiWzt51mHc",
            "f": "1",
            "dt": "2021-11-04T12:55:14.480038+00:00",
            "et": "ixn",
            "kt": "1",
            "k": [
              "DTH0PwWwsrcO_4zGe7bUR-LJX_ZGBTRsmP-ZeJ7fVg_4"
            ],
            "n": "E6qpfz7HeczuU3dAd1O9gPPS6-h_dCxZGYhU8UaDY2pc",
            "bt": "3",
            "b": [
              "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
              "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
              "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            "c": [],
            "ee": {
              "s": "0",
              "d": "ESORkffLV3qHZljOcnijzhCyRT0aXM2XHGVoyd5ST-Iw",
              "br": [],
              "ba": []
            },
            "di": ""
          }
        }

    """
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes

    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby, \
         habbing.openHby(name="wes", base="test", salt=salt) as wesHby:

        # setup Wes's habitat nontrans
        #wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 #isith='1', icount=1,
                                 #salt=salt, transferable=False, temp=True)
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        #bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith='1', icount=1, transferable=True,
                                 #wits=[wesHab.pre], temp=True)
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True,
                                wits=[wesHab.pre],)
        assert bobHab.pre == "EGaV8sWx4qxaWgad0Teaj0VZLlblc8vFMpMUR1WhfYBs"

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesHby.db, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers
        iserder = coring.Serder(raw=bytearray(bobIcp))
        wesHab.receipt(serder=iserder)

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said


        # Get ksn from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksn = bobKeverFromWes.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = eventing.Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamKvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, rvy=bamRvy)

        assert len(bamKvy.cues) == 1
        cue = bamKvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue["q"]["pre"] == bobHab.pre

        msgs = bytearray()  # outgoing messages
        for msg in wesHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy)
        bamKvy.processEscrows()

        keys = (bobHab.pre, wesHab.pre)
        saider = bamHby.db.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.said

    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is Bam's watcher

    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby, \
         habbing.openHby(name="wes", base="test",  salt=salt) as wesHby:

        # setup Wes's habitat nontrans
        #wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 #isith='1', icount=1,
                                 #salt=salt, transferable=False, temp=True)
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        #bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1,
                                 #transferable=True, temp=True)
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)
        assert bobHab.pre == "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0"

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesHby.db, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said


        # Get ksn from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksn = bobKeverFromWes.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksn.ked)

        #bamHab = habbing.Habitat(name="bam", ks=bamKS, db=bamDB, isith='1', icount=1,
                                 #transferable=True, temp=True)
        bamHab = bamHby.makeHab(name="bam", isith='1', icount=1, transferable=True)

        # Set Wes has Bam's watcher
        habr = bamHab.db.habs.get("bam")
        habr.watchers = [wesHab.pre]
        bamHab.db.habs.pin("bam", habr)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = eventing.Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamKvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, rvy=bamRvy)

        assert len(bamKvy.cues) == 1
        cue = bamKvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue["q"]["pre"] == bobHab.pre

        msgs = bytearray()  # outgoing messages
        for msg in wesHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy)
        bamKvy.processEscrows()

        keys = (bobHab.pre, wesHab.pre)
        saider = bamHby.db.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.said


    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    #with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         #basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         #basing.openDB(name="bam") as bamDB, keeping.openKS(name="bam") as bamKS:

    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby, \
         habbing.openHby(name="wes", base="test",  salt=salt) as wesHby:

        # setup Wes's habitat nontrans
        #wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 #isith='1', icount=1,
                                 #salt=salt, transferable=False, temp=True)
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        #bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith='1', icount=1,
                                 #transferable=True, temp=True)
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)
        assert bobHab.pre == "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0"

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesHby.db, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said

        # Get ksn from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksn = bobKeverFromWes.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksn.ked)

        bamKvy = eventing.Kevery(db=bamHby.db, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        assert len(bamKvy.cues) == 0
        saider = bamHby.db.knas.get(keys=keys)
        assert saider is None

    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    #with basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         #basing.openDB(name="bam") as bamDB:

    with habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHby(name="bam", base="test") as bamHby:

        #bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith='1', icount=1,
                                 #transferable=True,
                                 #wits=[], temp=True)
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)
        assert bobHab.pre == "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0"

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.said

        for _ in range(3):
            bobHab.rotate()

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 3
        assert ksn.ked["d"] == bobHab.kever.serder.said

        staleKsn = bobHab.reply(route="/ksn/" + bobHab.pre, data=ksn.ked)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = eventing.Kevery(db=bamHby.db, lax=False, local=False, rvy=bamRvy)
        bamKvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(staleKsn), kvy=bamKvy, rvy=bamRvy)

        for _ in range(5):
            bobHab.rotate()

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 8
        assert ksn.ked["d"] == bobHab.kever.serder.said

        liveKsn = bobHab.reply(route="/ksn/" + bobHab.pre, data=ksn.ked)
        parsing.Parser().parse(ims=bytearray(liveKsn), kvy=bamKvy, rvy=bamRvy)

        msgs = bytearray()  # outgoing messages
        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy)

        assert bobHab.pre in bamKvy.kevers

        bamRvy.processEscrowReply()
        bamKvy.processEscrows()

        keys = (bobHab.pre, bobHab.pre)
        saider = bamHby.db.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.said
        latest = bamHby.db.ksns.get(keys=(saider.qb64,))
        assert latest.sn == 8

    """End Test"""
