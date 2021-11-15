# -*- encoding: utf-8 -*-
"""
tests.core.test_keystate module

Test key state notification reply messages
routes: /ksn

"""
from keri.app import keeping, habbing
from keri.core import coring, eventing, parsing
from keri.db import basing


def test_keystate(mockHelpingNowUTC):
    """
        {
          "v": "KERI10JSON000301_",
          "t": "rpy",
          "d": "E_9aLcmV9aEVEm7mXvEY3V_CmbyvG7Ahj6HCq-D48meM",
          "dt": "2021-11-04T12:57:59.823350+00:00",
          "r": "ksn",
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
    print()
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes
    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         basing.openDB(name="bam") as bamDB:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1,
                                 salt=salt, transferable=False, temp=True)

        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[wesHab.pre], temp=True)
        assert bobHab.pre == "E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4"

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesDB, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers
        iserder = coring.Serder(raw=bytearray(bobIcp))
        wesHab.receipt(serder=iserder)

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig


        # Get ksn from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksn = bobKeverFromWes.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksn.ked)

        bamKvy = eventing.Kevery(db=bamDB, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        assert len(bamKvy.cues) == 1
        cue = bamKvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue["q"]["pre"] == bobHab.pre

        msgs = bytearray()  # outgoing messages
        for msg in wesDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy)
        bamKvy.processEscrows()

        keys = (bobHab.pre, wesHab.pre)
        saider = bamDB.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.dig

    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is Bam's watcher
    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         basing.openDB(name="bam") as bamDB, keeping.openKS(name="bam") as bamKS:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1,
                                 salt=salt, transferable=False, temp=True)

        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True, temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesDB, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig


        # Get ksn from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksn = bobKeverFromWes.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksn.ked)

        bamHab = habbing.Habitat(name="bam", ks=bamKS, db=bamDB, isith=1, icount=1, transferable=True, temp=True)

        # Set Wes has Bam's watcher
        habr = bamHab.db.habs.get("bam")
        habr.watchers = [wesHab.pre]
        bamHab.db.habs.pin("bam", habr)

        bamKvy = eventing.Kevery(db=bamDB, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        assert len(bamKvy.cues) == 1
        cue = bamKvy.cues.popleft()
        assert cue["kin"] == "query"
        assert cue["q"]["pre"] == bobHab.pre

        msgs = bytearray()  # outgoing messages
        for msg in wesDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy)
        bamKvy.processEscrows()

        keys = (bobHab.pre, wesHab.pre)
        saider = bamDB.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.dig


    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one
    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         basing.openDB(name="bam") as bamDB, keeping.openKS(name="bam") as bamKS:

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 isith=1, icount=1,
                                 salt=salt, transferable=False, temp=True)

        assert wesHab.pre == "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True, temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesDB, lax=False, local=False)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy)
        assert bobHab.pre in wesHab.kevers

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        # Get ksn from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksn = bobKeverFromWes.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksn.ked)

        bamKvy = eventing.Kevery(db=bamDB, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy)

        assert len(bamKvy.cues) == 0
        saider = bamDB.knas.get(keys=keys)
        assert saider is None

    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way
    with basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS, \
         basing.openDB(name="bam") as bamDB:

        bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith=1, icount=1, transferable=True,
                                 wits=[], temp=True)
        assert bobHab.pre == "Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 0
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        for _ in range(3):
            bobHab.rotate()

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 3
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        staleKsn = bobHab.reply(route="/ksn/" + bobHab.pre, data=ksn.ked)
        bamKvy = eventing.Kevery(db=bamDB, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(staleKsn), kvy=bamKvy)

        for _ in range(5):
            bobHab.rotate()

        # Get ksn from Bob and verify
        ksn = bobHab.kever.state()
        assert ksn.pre == bobHab.pre
        assert ksn.sn == 8
        assert ksn.ked["d"] == bobHab.kever.serder.dig

        liveKsn = bobHab.reply(route="/ksn/" + bobHab.pre, data=ksn.ked)
        parsing.Parser().parse(ims=bytearray(liveKsn), kvy=bamKvy)

        msgs = bytearray()  # outgoing messages
        for msg in bobDB.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy)

        assert bobHab.pre in bamKvy.kevers

        bamKvy.processEscrows()

        keys = (bobHab.pre, bobHab.pre)
        saider = bamDB.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.dig
        latest = bamDB.ksns.get(keys=(saider.qb64,))
        assert latest.sn == 8

    """End Test"""
