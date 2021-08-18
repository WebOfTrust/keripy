import time

from hio.base import doing, tyming

from keri.app import habbing, indirecting, agenting
from keri.core import coring
from keri.core.eventing import SealSource
from keri.db import dbing
from keri.peer import exchanging
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
        witq = agenting.WitnessInquisitor(hab=qinHab, klas=agenting.TCPWitnesser)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer, witq]
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

        # witq.query(pre=palHab.pre)


def test_credential_handlers(mockHelpingNowUTC):
    with habbing.openHab(name="test", transferable=True) as hab:
        reger = viring.Registry(name=hab.name, temp=True)
        issuer = issuing.Issuer(hab=hab, name=hab.name, reger=reger, noBackers=True)
        issuerDoer = issuing.IssuerDoer(issuer=issuer)

        issueHandler = agenting.CredentialIssueHandler(hab=hab, issuer=issuer)
        revokeHandler = agenting.CredentialRevokeHandler(hab=hab, issuer=issueHandler.issuer)
        handlers = [issueHandler, revokeHandler]

        exchanger = exchanging.Exchanger(hab=hab, handlers=handlers)

        payload = dict(
            recipient=hab.pre,
            data=dict(LEI="1234567890abcdefg"),
            schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4"
        )

        exn = exchanging.exchange("/cmd/credential/issue", payload=payload)
        sigers = hab.mgr.sign(exn.raw, verfers=hab.kever.verfers, indexed=True)
        exchanger.processEvent(serder=exn, source=hab.kever.prefixer, sigers=sigers)

        said = "EAPngnAg5B0g_fV1BxFuHuewuOaXF69HFfhF21pb5dTI"
        payload = dict(
            said=said,
            regk=issuer.regk
        )

        exn = exchanging.exchange("/cmd/credential/revoke", payload=payload)
        sigers = hab.mgr.sign(exn.raw, verfers=hab.kever.verfers, indexed=True)
        exchanger.processEvent(serder=exn, source=hab.kever.prefixer, sigers=sigers)

        limit = 2.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[issuerDoer, exchanger, issueHandler, revokeHandler])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)
        # doist.do(doers=doers)

        assert doist.limit == limit

        regkb = b'E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38'
        digb = b'EzQTt6mn97jGXC4yG5eBMXksAFFYw1yxDjdrpF7hB8wU'
        vcp = b'{"v":"KERI10JSON0000ad_","i":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38",' \
              b'"ii":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","s":"0","t":"vcp","c":["NB"],"bt":"0","b":[]}'
        credpb = b'E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38:EAPngnAg5B0g_fV1BxFuHuewuOaXF69HFfhF21pb5dTI'
        creddigb = b'E_hwTTuhIxpAl1GrlxLZEYdl7OfJPJgIWkvSyvREpuBs'
        iss = b'{"v":"KERI10JSON0000ba_","i":"EAPngnAg5B0g_fV1BxFuHuewuOaXF69HFfhF21pb5dTI","s":"0","t":"iss",' \
              b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38","dt":"2021-01-01T00:00:00.000000+00:00"}'

        revdigb = b'EoR4Vm7XJNCM8dolzpjDqYwA9Zd4lrS7kL3IshAdWVaA'
        rev = (
            b'{"v":"KERI10JSON0000ed_","i":"EAPngnAg5B0g_fV1BxFuHuewuOaXF69HFfhF21pb5dTI","s":"1","t":"rev",'
            b'"ri":"E3Eqm8wGRsW_Fxtq1ypXyQZj2c15PEcJ7f9ejHjJMC38","p":"E_hwTTuhIxpAl1GrlxLZEYdl7OfJPJgIWkvSyvREpuBs",'
            b'"dt":"2021-01-01T00:00:00.000000+00:00"}')

        # Check for the Registry inception
        tkey = dbing.snKey(regkb, 0)
        ekey = dbing.dgKey(regkb, digb)

        tel = reger.getTel(tkey)
        assert bytes(tel) == digb

        evt = reger.getTvt(ekey)
        assert bytes(evt) == vcp

        # Check for the issuance event
        tkey = dbing.snKey(credpb, 0)
        ekey = dbing.dgKey(credpb, creddigb)

        tel = reger.getTel(tkey)
        assert bytes(tel) == creddigb

        evt = reger.getTvt(ekey)
        assert bytes(evt) == iss

        # Check for the revocation event
        tkey = dbing.snKey(credpb, 1)
        ekey = dbing.dgKey(credpb, revdigb)

        tel = reger.getTel(tkey)
        assert bytes(tel) == revdigb

        evt = reger.getTvt(ekey)
        assert bytes(evt) == rev
