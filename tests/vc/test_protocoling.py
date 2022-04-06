# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""
from hio.base import doing

from keri.app import habbing, indirecting, signing, storing
from keri.core import coring, scheming, eventing, parsing
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vc.protocoling import IssueHandler, PresentationRequestHandler
from keri.vc.proving import credential
from keri.vc.walleting import Wallet
from keri.vdr import verifying, credentialing


def test_issuing(seeder):
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    wanSalt = coring.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0Ad2Fubi10aGUtd2l0bmVzcw'

    with habbing.openHby(name="red", base="test") as redHby, \
            habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby, \
            habbing.openHby(name="wan", base="test", salt=wanSalt) as wanHby:
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)

        seeder.seedSchema(redHby.db)
        seeder.seedSchema(sidHby.db)
        seeder.seedSchema(wanHby.db)

        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        sidHab = sidHby.makeHab(name="test",
                                wits=["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"])
        sidPre = sidHab.pre
        assert sidPre == "EWVYH1T4J09x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE"

        redKvy = eventing.Kevery(db=redHby.db)
        redRgy = credentialing.Regery(hby=redHby, name="red", temp=True)
        redVer = verifying.Verifier(hby=redHby, reger=redRgy.reger)

        sidRgy = credentialing.Regery(hby=sidHby, name="bob", temp=True)
        sidVer = verifying.Verifier(hby=sidHby, reger=sidRgy.reger)

        sidMbx = storing.Mailboxer(temp=True)
        issuer = sidRgy.makeRegistry(prefix=sidHab.pre, name="sid")

        # Create Red's wallet and Issue Handler for receiving the credential
        redIssueHandler = IssueHandler(hby=sidHby, rgy=sidRgy, mbx=sidMbx, controller=sidHab.pre)
        redExc = exchanging.Exchanger(hby=sidHby, tymth=doist.tymen(), handlers=[redIssueHandler])

        schema = "ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI"

        # Build the credential subject and then the Creder for the full credential
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=d,
                            status=issuer.regk)

        assert creder.said == "E7DT3Vo5f9t3vgfeYlZbpwAvrumP4wZz5UipjEMGWYmg"

        issuer.issue(creder=creder)
        msg = signing.ratify(sidHab, serder=creder, pipelined=True)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"E7DT3Vo5f9t3vgfeYlZbpwAvrumP4wZz5U'
                       b'ipjEMGWYmg","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                       b'i":"EWVYH1T4J09x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE","a":{"d":"E24I'
                       b'f3y9Voz-1sXgkBCeNG6pbCqMTa56kCvj47NgOgLg","i":"EWVYH1T4J09x5RePL'
                       b'fVyTfno3aHzJ-YqnL9Bm0Kyx6UE","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EUFmYfQn31KHudwM'
                       b'PoSgnrBZOrc8PUcLDKsLXmYyV9WU"}-VA3-JAB6AABAAA--FABEWVYH1T4J09x5R'
                       b'ePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE0AAAAAAAAAAAAAAAAAAAAAAAEWVYH1T4J0'
                       b'9x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE-AABAAEdHUgtz8EaTo4bd_jrNbAOMX'
                       b'hSvxFE5hL80GJH5qyAFAt7jszFij4cjHnB-toPkMsZOo-z30X6ypKkqFMRE6DQ')

        # Create the `exn` message for issue credential
        sidExcSrdr, atc = protocoling.credentialIssueExn(hab=sidHab, schema=creder.schema, said=creder.said)
        excMsg = bytearray(sidExcSrdr.raw)
        excMsg.extend(atc)
        # Parse the exn issue credential message on Red's side

        parsing.Parser().parse(ims=bytearray(msg), vry=sidVer)

        parsing.Parser().parse(ims=bytearray(msg), kvy=redKvy, exc=redExc, vry=redVer)
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)
        doers = wanDoers + [redExc]
        doist.do(doers=doers)
        assert doist.tyme == limit

        ser = (b'{"v":"ACDC10JSON00019e_","d":"E7DT3Vo5f9t3vgfeYlZbpwAvrumP4wZz5UipjEMGWYmg",'
               b'"s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","i":"EWVYH1T4J09x5RePLfVy'
               b'Tfno3aHzJ-YqnL9Bm0Kyx6UE","a":{"d":"E24If3y9Voz-1sXgkBCeNG6pbCqMTa56kCvj47Ng'
               b'OgLg","i":"EWVYH1T4J09x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EUFmYfQn31KH'
               b'udwMPoSgnrBZOrc8PUcLDKsLXmYyV9WU"}')
        sig0 = (b'AAEdHUgtz8EaTo4bd_jrNbAOMXhSvxFE5hL80GJH5qyAFAt7jszFij4cjHnB-toPkMsZOo-z30X6'
                b'ypKkqFMRE6DQ')

        # verify we can load serialized VC by SAID
        creder, sadsigers, sadcigars = sidRgy.reger.cloneCred(said=creder.said)
        assert creder.raw == ser

        # verify the signature
        assert len(sadsigers) == 1
        (_, _, _, _, sigers) = sadsigers[0]
        assert sigers[0].qb64b == sig0
        assert len(sadcigars) == 0

        # verify we can look up credential by Schema SAID
        schema = sidRgy.reger.schms.get(schema)
        assert len(schema) == 1
        assert schema[0].qb64 == creder.said


def test_proving(seeder):
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    hanSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    vicSalt = coring.Salter(raw=b'fedcba9876543210').qb64

    with habbing.openHby(name="han", base="test", salt=hanSalt) as hanHby, \
            habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby, \
            habbing.openHby(name="vic", base="test", salt=vicSalt) as vicHby:
        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)
        seeder.seedSchema(db=hanHby.db)
        seeder.seedSchema(db=sidHby.db)
        seeder.seedSchema(db=vicHby.db)

        # sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        sidHab = sidHby.makeHab(name="test")
        assert sidHab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"
        sidIcpMsg = sidHab.makeOwnInception()

        hanKvy = eventing.Kevery(db=hanHby.db)
        parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[sidHab.pre].sn == 0  # accepted event

        # hanHab = habbing.Habitat(ks=hanKS, db=hanDB, salt=hanSalt, temp=True)
        hanHab = hanHby.makeHab(name="test")
        assert hanHab.pre == "EJcjV4DalEqAtaOdlEcjNvo75HCs0lN5K3BbQwJ5kN6o"
        hanIcpMsg = hanHab.makeOwnInception()

        vicKvy = eventing.Kevery(db=vicHby.db)
        parsing.Parser().parse(ims=bytearray(hanIcpMsg), kvy=vicKvy)
        assert vicKvy.kevers[hanHab.pre].sn == 0  # accepted event

        # vicHab = habbing.Habitat(ks=vicKS, db=vicDB, salt=vicSalt, temp=True)
        vicHab = vicHby.makeHab(name="test")
        assert vicHab.pre == "ET9X4cK2jPatbfYzEprxjdYLKazxZ7Rufj_jY10NC-t8"
        vicIcpMsg = vicHab.makeOwnInception()

        parsing.Parser().parse(ims=bytearray(vicIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[vicHab.pre].sn == 0  # accepted event

        schema = "ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI"
        credSubject = dict(
            d="",
            i=hanHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        hanReg = credentialing.Regery(hby=hanHby, name="han", temp=True)
        issuer = hanReg.makeRegistry(prefix=hanHab.pre, name="han")

        verifier = verifying.Verifier(hby=hanHby, reger=hanReg.reger)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=d,
                            status=issuer.regk,
                            )

        assert creder.said == "EGIvo3cL_suCKlo2AAX9_e35clbr1nkaA-r8KRERVyy8"

        msg = signing.ratify(sidHab, serder=creder)
        hanWallet = Wallet(reger=hanReg.reger)

        issuer.issue(creder=creder)
        parsing.Parser().parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert hanReg.reger.creds.get(key) is not None

        # Create Red's wallet and Issue Handler for receiving the credential
        hanRequestHandler = PresentationRequestHandler(hby=hanHby, wallet=hanWallet)
        hanExc = exchanging.Exchanger(hby=hanHby, tymth=doist.tymen(), handlers=[hanRequestHandler])

        # Create the issue credential payload
        pl = dict(
            input_descriptors=[
                dict(s=schema)
            ]
        )

        # Create the `exn` message for presentation request
        vicExcSrdr = exchanging.exchange(route="/presentation/request", payload=pl)
        excMsg = bytearray(vicExcSrdr.raw)
        excMsg.extend(vicHab.endorse(vicExcSrdr, last=True))

        # Parse the exn presentation request message on Han's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=hanKvy, exc=hanExc)
        doist.do(doers=[hanExc])
        assert doist.tyme == limit

        resp = hanRequestHandler.cues.popleft()
        assert resp is not None

        respSer = coring.Serder(raw=resp["rep"].raw)
        assert respSer.ked['t'] == coring.Ilks.exn
        assert respSer.ked['r'] == "/presentation/proof"
        data = respSer.ked['a']
        assert "presentation_submission" in data

        pe = data["presentation_submission"]
        assert "descriptor_map" in pe

        dm = pe["descriptor_map"]
        assert len(dm) == 1
        assert dm[0]["id"] == schema

        assert "verifiableCredential" in data
        vcs = data["verifiableCredential"]
        assert len(vcs) == 1

        assert vcs[0] == "EGIvo3cL_suCKlo2AAX9_e35clbr1nkaA-r8KRERVyy8"
