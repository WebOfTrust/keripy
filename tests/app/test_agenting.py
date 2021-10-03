# -*- encoding: utf-8 -*-
"""
tests.app.agenting module

"""

from hio.base import doing

from keri.app import habbing, indirecting, agenting
from keri.core.eventing import SealSource
from keri.db import dbing
from keri.vdr import eventing, viring, issuing


def test_withness_receiptor(mockGetWitnessByPrefix):
    with habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False) as wanHab, \
            habbing.openHab(name="wil", salt=b'will-the-witness', transferable=False) as wilHab, \
            habbing.openHab(name="wes", salt=b'wess-the-witness', transferable=False) as wesHab, \
            habbing.openHab(name="pal", salt=b'0123456789abcdef', transferable=True,
                            wits=[wanHab.pre, wilHab.pre, wesHab.pre]) as palHab:
        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=True, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=True, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=True, tcpPort=5634, httpPort=5644)

        witDoer = agenting.WitnessReceiptor(hab=palHab, klas=agenting.TCPWitnesser)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [witDoer]
        doist.do(doers=doers)

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.digb)

        wigs = wanHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigs = wilHab.db.getWigs(dgkey)
        assert len(wigs) == 3
        wigs = wesHab.db.getWigs(dgkey)
        assert len(wigs) == 3


def test_witness_sender(mockGetWitnessByPrefix):
    with habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False) as wanHab, \
            habbing.openHab(name="wil", salt=b'will-the-witness', transferable=False) as wilHab, \
            habbing.openHab(name="wes", salt=b'wess-the-witness', transferable=False) as wesHab, \
            habbing.openHab(name="pal", salt=b'0123456789abcdef', transferable=True,
                            wits=[wanHab.pre, wilHab.pre, wesHab.pre]) as palHab:
        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=True, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=True, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=True, tcpPort=5634, httpPort=5644)

        serder = eventing.issue(vcdig="Ekb-iNmnXnOYIAlZ9vzK6RV9slYiKQSyQvAO-k0HMOI8",
                                regk="EbA1o_bItVC9i6YB3hr2C3I_Gtqvz02vCmavJNoBA3Jg")
        seal = SealSource(s=palHab.kever.sn, d=palHab.kever.serder.dig)
        msg = issuing.Issuer.messagize(serder=serder, seal=seal)

        witDoer = agenting.WitnessPublisher(hab=palHab, msg=msg, klas=agenting.TCPWitnesser)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [witDoer]
        doist.do(doers=doers)

        assert witDoer.done is True

        for name in ["wes", "wil", "wan"]:
            reger = viring.Registry(name=name)
            raw = reger.getTvt(dbing.dgKey(serder.preb, serder.digb))
            assert raw is None
            # found = coring.Serder(raw=bytes(raw))
            # assert serder.pre == found.pre


def test_witness_inquisitor(mockGetWitnessByPrefix):
    with habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False) as wanHab, \
            habbing.openHab(name="wil", salt=b'will-the-witness', transferable=False) as wilHab, \
            habbing.openHab(name="wes", salt=b'wess-the-witness', transferable=False) as wesHab, \
            habbing.openHab(name="pal", salt=b'0123456789abcdef', transferable=True,
                            wits=[wanHab.pre, wilHab.pre, wesHab.pre]) as palHab, \
            habbing.openHab(name="qin", salt=b'abcdef0123456789', transferable=True,
                            wits=[wanHab.pre, wilHab.pre, wesHab.pre]) as qinHab:
        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=True, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=True, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=True, tcpPort=5634, httpPort=5644)

        palWitDoer = agenting.WitnessReceiptor(hab=palHab, klas=agenting.TCPWitnesser)
        qinWitDoer = agenting.WitnessReceiptor(hab=qinHab, klas=agenting.TCPWitnesser)
        qinWitq = agenting.WitnessInquisitor(hab=qinHab, klas=agenting.TCPWitnesser)

        # query up a few to make sure it still works
        qinWitq.query(pre=palHab.pre)
        qinWitq.query(pre=palHab.pre)
        qinWitq.query(pre=palHab.pre)
        palWitq = agenting.WitnessInquisitor(hab=palHab, klas=agenting.TCPWitnesser)
        palWitq.query(pre=qinHab.pre)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist.do(doers=doers)

        for hab in [palHab, qinHab]:
            kev = hab.kever
            ser = kev.serder
            dgkey = dbing.dgKey(ser.preb, ser.digb)

            wigs = wanHab.db.getWigs(dgkey)
            assert len(wigs) == 3
            wigs = wilHab.db.getWigs(dgkey)
            assert len(wigs) == 3
            wigs = wesHab.db.getWigs(dgkey)
            assert len(wigs) == 3

        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [qinWitq, palWitq]
        doist.do(doers=doers)

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers


def test_witness_inquisitor_dedupe(mockGetWitnessByPrefix):
    with habbing.openHab(name="pal", salt=b'0123456789abcdef', transferable=True,
                         wits=[]) as palHab, \
            habbing.openHab(name="qin", salt=b'abcdef0123456789', transferable=True,
                            wits=[]) as qinHab:
        witq = agenting.WitnessInquisitor(hab=qinHab, klas=agenting.TCPWitnesser)

        # query up a few to make sure it still works
        witq.query(pre=palHab.pre)
        witq.query(pre=palHab.pre)
        witq.query(pre=palHab.pre)

        assert len(witq.smsgs) == 0
        assert len(witq.msgs) == 3

        msgDo = witq.msgDo()

        next(msgDo)
        next(msgDo)
        assert len(witq.msgs) == 0
        assert len(witq.smsgs) == 1

        witq.query(pre=palHab.pre)
        witq.query(pre=palHab.pre)
        witq.query(pre=qinHab.pre)
        next(msgDo)
        assert len(witq.msgs) == 0
        assert len(witq.smsgs) == 2

        smsg = witq.smsgs.pop()
        assert smsg == (b'{"v":"KERI10JSON000067_","t":"req","r":"logs","q":{"i":"EGhub0DVJ1LdJ-n_rPxR'
                        b'qFuttSGZa_pLwC8G4X1qL7JA"}}-HABEGhub0DVJ1LdJ-n_rPxRqFuttSGZa_pLwC8G4X1qL7JA-'
                        b'AABAA98K_G_MASsS6rmTnQvNxeMhRTPgZg83NSJla1edSxN43RPXsZIxHdrMqRKx8-6BSjqyMNNS'
                        b'D1iBWywvyHCcmDw')
