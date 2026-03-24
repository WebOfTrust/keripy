# -*- encoding: utf-8 -*-
"""
tests.app.agenting module

"""
import time

from hio.base import doing, tyming

from keri.kering import Schemes
from keri.core import Salter
from keri.app import (WitnessReceiptor, WitnessPublisher, WitnessInquisitor,
                      runController, openHby, setupWitness)
from keri.help import nowIso8601


def test_withness_receiptor(seeder):
    with openHby(name="wan1", salt=Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            openHby(name="wil1", salt=Salter(raw=b'will-the-witness').qb64) as wilHby, \
            openHby(name="wes1", salt=Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            openHby(name="pal1", salt=Salter(raw=b'0123456789abcdef').qb64) as palHby:

        wanDoers = setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[Schemes.tcp])

        rctDoer = ReceiptDoer(hby=palHby, wanHab=wanHab, wilHab=wilHab, wesHab=wesHab)

        limit = 5.0
        tock = 0.03125
        doers = wanDoers + wilDoers + wesDoers + [rctDoer]
        doist = doing.Doist(limit=limit, tock=tock, doers=doers)
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not (rctDoer.done or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        doist.exit()

        assert rctDoer.done is True


class ReceiptDoer(doing.DoDoer):
    """ Test scenario of witness receipts. """

    def __init__(self, hby, wanHab, wilHab, wesHab):
        self.hby = hby
        self.wanHab = wanHab
        self.wilHab = wilHab
        self.wesHab = wesHab

        super(ReceiptDoer, self).__init__(doers=[doing.doify(self.testDo)])

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Execute a series of kli commands for this test scenario """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        palHab = self.hby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre], transferable=True)

        witDoer = WitnessReceiptor(hby=self.hby)
        witDoer.msgs.append(dict(pre=palHab.pre))
        self.extend([witDoer])

        kev = palHab.kever
        ser = kev.serder

        while True:
            wilWigs = self.wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            wanWigs = self.wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            if len(wilWigs) == 2 and len(wanWigs) == 2:
                break
            yield self.tock

        # Controller should send endpoints between witnesses.  Check for Endpoints for each other:
        keys = (self.wanHab.pre, Schemes.tcp)
        said = self.wilHab.db.lans.get(keys=keys)
        assert said is not None
        keys = (self.wilHab.pre, Schemes.tcp)
        said = self.wanHab.db.lans.get(keys=keys)
        assert said is not None

        palHab.rotate(adds=[self.wesHab.pre])

        witDoer.msgs.append(dict(pre=palHab.pre, sn=1))

        kev = palHab.kever
        ser = kev.serder

        while True:
            wilWigs = self.wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            wanWigs = self.wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            wesWigs = self.wesHab.db.wigs.get(keys=(ser.preb, ser.saidb))
            if len(wilWigs) == 3 and len(wanWigs) == 3 and len(wesWigs) == 3:
                break
            yield self.tock

        self.remove([witDoer])
        return True


def test_witness_sender(seeder):
    with openHby(name="wan2", salt=Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            openHby(name="wil2", salt=Salter(raw=b'will-the-witness').qb64) as wilHby, \
            openHby(name="wes2", salt=Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            openHby(name="pal2", salt=Salter(raw=b'0123456789abcdef').qb64) as palHby:

        # looks like bad magic value in seeder is causing this to fail
        pdoer = PublishDoer(wanHby, wilHby, wesHby, palHby, seeder)
        runController(doers=[pdoer], expire=15.0)
        assert pdoer.done is True


class PublishDoer(doing.DoDoer):

    def __init__(self, wanHby, wilHby, wesHby, palHby, seeder):
        wanDoers = setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        self.wanHab = wanHby.habByName(name="wan")
        self.wilHab = wilHby.habByName(name="wil")
        self.wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[self.wanHab, self.wilHab, self.wesHab], protocols=[Schemes.tcp])

        self.palHab = palHby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre, self.wesHab.pre], transferable=True)

        self.witDoer = WitnessPublisher(hby=palHby)
        doers = wanDoers + wilDoers + wesDoers + [self.witDoer]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(PublishDoer, self).__init__(doers=doers)

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Run the test and exit and remove all child doers when done """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        msg = self.palHab.makeOwnEvent(sn=0)
        self.witDoer.msgs.append(dict(pre=self.palHab.pre, msg=msg))

        for hab in [self.wanHab, self.wilHab, self.wesHab]:
            while True:
                if self.palHab.pre in hab.kevers:
                    break
                yield self.tock

        self.remove(self.toRemove)
        return True


def test_witness_inquisitor(mockHelpingNowUTC, seeder):
    with openHby(name="wan3", salt=Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            openHby(name="wil3", salt=Salter(raw=b'will-the-witness').qb64) as wilHby, \
            openHby(name="wes3", salt=Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            openHby(name="pal3", salt=Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            openHby(name="qin3", salt=Salter(raw=b'abcdef0123456789').qb64) as qinHby:
        wanDoers = setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[Schemes.tcp])
        seeder.seedWitEnds(qinHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[Schemes.tcp])

        palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)
        qinHab = qinHby.makeHab(name="qin", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)

        palWitDoer = WitnessReceiptor(hby=palHby)
        palWitDoer.msgs.append(dict(pre=palHab.pre))
        qinWitDoer = WitnessReceiptor(hby=qinHby)
        qinWitDoer.msgs.append(dict(pre=qinHab.pre))

        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist = doing.Doist(doers=doers)
        doist.enter()
        doist.recur()

        while True:
            wigers = []
            for hab in [palHab, qinHab]:
                kev = hab.kever
                ser = kev.serder
                wigers.extend(wanHab.db.wigs.get(keys=(ser.preb, ser.saidb)))
                wigers.extend(wilHab.db.wigs.get(keys=(ser.preb, ser.saidb)))
                wigers.extend(wesHab.db.wigs.get(keys=(ser.preb, ser.saidb)))

            if len(wigers) == 18:
                break

            doist.recur()

        kev = qinHab.kever
        ser = kev.serder

        wigers = wanHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3
        wigers = wilHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3
        wigers = wesHab.db.wigs.get(keys=(ser.preb, ser.saidb))
        assert len(wigers) == 3

        qinWitq = WitnessInquisitor(hby=qinHby)
        stamp = nowIso8601()
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)

        palWitq = WitnessInquisitor(hby=palHby)
        palWitq.query(src=palHab.pre, pre=qinHab.pre, stamp=stamp, wits=qinHab.kever.wits)

        doist.extend([qinWitq, palWitq])
        while True:
            if palHab.pre in qinHab.kevers and qinHab.pre in palHab.kevers:
                break
            doist.recur()

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers

        doist.exit()


def test_messenger_prefers_https():
    """Verify messengerFrom and streamMessengerFrom prefer HTTPS over HTTP.

    Regression test for https://github.com/WebOfTrust/keripy/issues/1008
    """
    from unittest.mock import MagicMock, patch
    from keri.app.agenting import messengerFrom, streamMessengerFrom

    hab = MagicMock()
    pre = "EtyPSuUjLyLdXAtGMrsTt0-ELyWeU8fJcymHiGOfuaSA"

    # Both HTTP and HTTPS available
    urls = {
        Schemes.http: "http://example.com:5632",
        Schemes.https: "https://example.com:5643",
    }

    with patch("keri.app.agenting.HTTPMessenger") as MockHTTP:
        messengerFrom(hab, pre, urls)
        MockHTTP.assert_called_once()
        call_url = MockHTTP.call_args[1]["url"]
        assert call_url == "https://example.com:5643", f"Expected HTTPS URL, got {call_url}"

    with patch("keri.app.agenting.HTTPStreamMessenger") as MockStream:
        streamMessengerFrom(hab, pre, urls, msg=b"test")
        MockStream.assert_called_once()
        call_url = MockStream.call_args[1]["url"]
        assert call_url == "https://example.com:5643", f"Expected HTTPS URL, got {call_url}"

    # Only HTTP available - should still work
    http_only = {Schemes.http: "http://example.com:5632"}

    with patch("keri.app.agenting.HTTPMessenger") as MockHTTP:
        messengerFrom(hab, pre, http_only)
        call_url = MockHTTP.call_args[1]["url"]
        assert call_url == "http://example.com:5632"

    # Only HTTPS available - should still work
    https_only = {Schemes.https: "https://example.com:5643"}

    with patch("keri.app.agenting.HTTPStreamMessenger") as MockStream:
        streamMessengerFrom(hab, pre, https_only, msg=b"test")
        call_url = MockStream.call_args[1]["url"]
        assert call_url == "https://example.com:5643"


def test_telquery_uses_pre_not_wits():
    """Test that WitnessInquisitor.telquery queues a message with `pre` parameter
    for endpoint resolution instead of `wits`, matching KERIA behavior.

    Regression test for issue #1160: kli admit fails when issuer has no witness
    because telquery was called with wits=[] (empty list) instead of pre=issr.
    When wits is an empty list, random.choice([]) raises IndexError.
    When pre is provided, WitnessInquisitor.msgDo resolves endpoints via
    hab.endsFor(pre=pre) which works for issuers with or without witnesses.
    """
    with openHby(name="test", temp=True) as hby:
        hab = hby.makeHab(name="test")
        witq = WitnessInquisitor(hby=hby)

        issr_pre = hab.pre  # use hab's own prefix as a stand-in issuer
        ri = "EAbcdefghijklmnopqrstuvwxyz012345678901234567"
        acdc_said = "EBcdefghijklmnopqrstuvwxyz0123456789012345678"

        # Call telquery with pre= (the fix) instead of wits=
        witq.telquery(src=hab.pre, pre=issr_pre, ri=ri, i=acdc_said)

        assert len(witq.msgs) == 1
        msg = witq.msgs[0]

        # Verify pre is set for endpoint resolution
        assert msg["pre"] == issr_pre
        # Verify wits is None (endpoint resolution path, not random witness path)
        assert msg["wits"] is None
        # Verify other fields
        assert msg["src"] == hab.pre
        assert msg["target"] == acdc_said
        assert msg["q"]["ri"] == ri
