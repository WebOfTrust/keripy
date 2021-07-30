from contextlib import contextmanager

from hio.base import doing

from keri.app import keeping, habbing, indirecting, agenting
from keri.core import coring
from keri.core.eventing import SealSource
from keri.db import basing, dbing
from keri.vdr import eventing, viring, issuing


def test_withness_receiptor(mockGetWitnessByPrefix):

    with openHab(name="wan", salt=b'wann-the-witness', transferable=False) as wanHab, \
            openHab(name="wil", salt=b'will-the-witness', transferable=False) as wilHab, \
            openHab(name="wes", salt=b'wess-the-witness', transferable=False) as wesHab, \
            openHab(name="pal", salt=b'0123456789abcdef', transferable=True,
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
    with openHab(name="wan", salt=b'wann-the-witness', transferable=False) as wanHab, \
            openHab(name="wil", salt=b'will-the-witness', transferable=False) as wilHab, \
            openHab(name="wes", salt=b'wess-the-witness', transferable=False) as wesHab, \
            openHab(name="pal", salt=b'0123456789abcdef', transferable=True,
                    wits=[wanHab.pre, wilHab.pre, wesHab.pre]) as palHab:

        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=True, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(name="wil", hab=wilHab, temp=True, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(name="wes", hab=wesHab, temp=True, tcpPort=5634, httpPort=5644)

        serder = eventing.issue(vcdig="Ekb-iNmnXnOYIAlZ9vzK6RV9slYiKQSyQvAO-k0HMOI8",
                                regk="EbA1o_bItVC9i6YB3hr2C3I_Gtqvz02vCmavJNoBA3Jg")
        seal = SealSource(s=palHab.kever.sn, d=palHab.kever.serder.dig)
        msg = issuing.Issuer.messagize(serder=serder, seal=seal)

        witDoer = agenting.WitnessSender(hab=palHab, msg=msg, klas=agenting.TCPWitnesser)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [witDoer]
        doist.do(doers=doers)

        assert witDoer.done is True

        for name in ["wes", "wil", "wan"]:
            reger = viring.Registry(name=name)
            raw = reger.getTvt(dbing.dgKey(serder.preb, serder.digb))
            found = coring.Serder(raw=bytes(raw))
            assert serder.pre == found.pre


@contextmanager
def openHab(name="test", salt=b'0123456789abcdef', **kwa):
    with basing.openDB(name=name, temp=True) as db, \
            keeping.openKS(name=name, temp=True) as ks:

        salt = coring.Salter(raw=salt).qb64
        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=True, salt=salt,
                              icount=1, isith=1, ncount=1, nsith=1, **kwa)

        yield hab

