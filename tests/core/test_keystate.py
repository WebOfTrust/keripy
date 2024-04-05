# -*- encoding: utf-8 -*-
"""
tests.core.test_keystate module

Test key state notification reply messages
routes: /ksn

"""
from keri.app import habbing
from keri.core import coring, eventing, parsing, routing, serdering


def test_keystate(mockHelpingNowUTC):
    """
        {
          "v": "KERI10JSON000301_",
          "vn": (1,0),
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
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'

    default_salt = coring.Salter(raw=b'0123456789abcdef').qb64

    # Bob is the controller
    # Wes is his witness
    # Bam is verifying the key state for Bob from Wes

    # default for openHby temp = True
    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
         habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby,
         habbing.openHby(name="wes", base="test", salt=salt) as wesHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == 'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True,
                                wits=[wesHab.pre],)
        assert bobHab.pre == 'EDotK23orLtF8GAU61_fNXRyFBTg49X50W0OUlP14YAK'

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesHby.db)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy, local=True)
        assert bobHab.pre in wesHab.kevers
        iserder = serdering.SerderKERI(raw=bytearray(bobIcp))
        wesHab.receipt(serder=iserder)

        # Get key state record (ksr) from Bob and verify
        ksr = bobHab.kever.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said


        # Get key state record (ksr) from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksr = bobKeverFromWes.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksr._asdict())

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = eventing.Kevery(db=bamHby.db, rvy=bamRvy)
        bamKvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, rvy=bamRvy, local=True)

        assert len(bamKvy.cues) == 1
        cue = bamKvy.cues.popleft()
        assert cue["kin"] == "keyStateSaved"
        assert cue["ksn"]["i"] == bobHab.pre

        msgs = bytearray()  # outgoing messages
        for msg in wesHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, local=True)
        bamKvy.processEscrows()

        keys = (bobHab.pre, wesHab.pre)
        saider = bamHby.db.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.said

    # Bob is the controller without a witness
    # Bam is verifying the key state for Bob from Wes
    # Wes is Bam's watcher

    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
         habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby,
         habbing.openHby(name="wes", base="test",  salt=salt) as wesHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == 'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)
        bobpre = 'EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH'
        assert bobHab.pre == bobpre


        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesHby.db)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy, local=True)
        assert bobHab.pre in wesHab.kevers

        # Get ksr key state record from Bob and verify
        ksr = bobHab.kever.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said

        # Get ksr key state record from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksr = bobKeverFromWes.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksr._asdict())

        bamHab = bamHby.makeHab(name="bam", isith='1', icount=1, transferable=True)

        # Set Wes has Bam's watcher
        habr = bamHab.db.habs.get(bamHab.pre)
        habr.watchers = [wesHab.pre]
        bamHab.db.habs.pin(bamHab.pre, habr)

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = eventing.Kevery(db=bamHby.db, rvy=bamRvy)
        bamKvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, rvy=bamRvy, local=True)

        assert len(bamKvy.cues) == 1
        cue = bamKvy.cues.popleft()
        assert cue["kin"] == "keyStateSaved"
        assert cue["ksn"]["i"] == bobHab.pre

        msgs = bytearray()  # outgoing messages
        for msg in wesHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, local=True)
        bamKvy.processEscrows()

        keys = (bobHab.pre, wesHab.pre)
        saider = bamHby.db.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.said


    # Bob is the controller
    # Bam is verifying the key state for Bob from Wes
    # Wes is no one

    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
         habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby,
         habbing.openHby(name="wes", base="test",  salt=salt) as wesHby):

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False,)
        assert wesHab.pre == 'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)
        assert bobHab.pre == bobpre

        # Create Bob's icp, pass to Wes.
        wesKvy = eventing.Kevery(db=wesHby.db)
        bobIcp = bobHab.makeOwnEvent(sn=0)
        parsing.Parser().parse(ims=bytearray(bobIcp), kvy=wesKvy, local=True)
        assert bobHab.pre in wesHab.kevers

        # Get ksr key state record from Bob and verify
        ksr = bobHab.kever.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said

        # Get ksr key state record from Wes and verify
        bobKeverFromWes = wesHab.kevers[bobHab.pre]
        ksr = bobKeverFromWes.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said

        msg = wesHab.reply(route="/ksn/" + wesHab.pre, data=ksr._asdict())

        bamKvy = eventing.Kevery(db=bamHby.db)
        parsing.Parser().parse(ims=bytearray(msg), kvy=bamKvy, local=True)

        assert len(bamKvy.cues) == 0
        saider = bamHby.db.knas.get(keys=keys)
        assert saider is None

    # Bob is the controller
    # Bam is verifying the key state for Bob with a stale key state in the way

    with (habbing.openHby(name="bob", base="test", salt=default_salt) as bobHby,
         habbing.openHby(name="bam", base="test", salt=default_salt) as bamHby):

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)
        assert bobHab.pre == bobpre

        # Get ksr key state record from Bob and verify
        ksr = bobHab.kever.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '0'
        assert ksr.d == bobHab.kever.serder.said

        for _ in range(3):
            bobHab.rotate()

        # Get ksr key state record from Bob and verify
        ksr = bobHab.kever.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '3'
        assert ksr.d == bobHab.kever.serder.said

        staleKsn = bobHab.reply(route="/ksn/" + bobHab.pre, data=ksr._asdict())

        bamRtr = routing.Router()
        bamRvy = routing.Revery(db=bamHby.db, rtr=bamRtr)
        bamKvy = eventing.Kevery(db=bamHby.db, rvy=bamRvy)
        bamKvy.registerReplyRoutes(router=bamRtr)
        parsing.Parser().parse(ims=bytearray(staleKsn), kvy=bamKvy, rvy=bamRvy, local=True)

        for _ in range(5):
            bobHab.rotate()

        # Get ksn from Bob and verify
        ksr = bobHab.kever.state()
        assert ksr.i == bobHab.pre
        assert ksr.s == '8'
        assert ksr.d == bobHab.kever.serder.said

        liveKsn = bobHab.reply(route="/ksn/" + bobHab.pre, data=ksr._asdict())
        parsing.Parser().parse(ims=bytearray(liveKsn), kvy=bamKvy, rvy=bamRvy, local=True)

        msgs = bytearray()  # outgoing messages
        for msg in bobHby.db.clonePreIter(pre=bobHab.pre, fn=0):
            msgs.extend(msg)

        parsing.Parser().parse(ims=msgs, kvy=bamKvy, rvy=bamRvy, local=True)

        assert bobHab.pre in bamKvy.kevers

        bamRvy.processEscrowReply()
        bamKvy.processEscrows()

        keys = (bobHab.pre, bobHab.pre)
        saider = bamHby.db.knas.get(keys=keys)
        assert saider.qb64 == bobHab.kever.serder.said
        latest = bamHby.db.ksns.get(keys=(saider.qb64,))
        assert latest.s == '8'

    """End Test"""
