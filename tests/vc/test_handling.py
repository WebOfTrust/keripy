# -*- encoding: utf-8 -*-
"""
tests.vc.handling module

"""
from hio.base import doing

from keri.app import habbing, indirecting, signing
from keri.core import coring, scheming, eventing, parsing
from keri.peer import exchanging
from keri.vc.handling import IssueHandler, envelope, RequestHandler
from keri.vc.proving import credential
from keri.vc.walleting import Wallet
from keri.vdr import viring, verifying, issuing


def test_issuing(seeder):
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    wanSalt = coring.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0Ad2Fubi10aGUtd2l0bmVzcw'

    with viring.openReg(name="red") as redPDB, \
            habbing.openHby(name="red", base="test") as redHby, \
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

        verifier = verifying.Verifier(hby=sidHby, reger=redPDB)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)

        # Create Red's wallet and Issue Handler for receiving the credential
        redIssueHandler = IssueHandler(hby=sidHby, verifier=verifier)
        redExc = exchanging.Exchanger(hby=sidHby, tymth=doist.tymen(), handlers=[redIssueHandler])

        schema = "ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI"

        # Build the credential subject and then the Credentialer for the full credential
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

        assert creder.said == "EzucsqkRDx69MHfroAwzNrARf_erW2j9y2-hQdUvRBLs"

        issuer.issue(creder=creder)
        msg = signing.ratify(sidHab, serder=creder, pipelined=True)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"EzucsqkRDx69MHfroAwzNrARf_erW2j9y2'
                       b'-hQdUvRBLs","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                       b'i":"EWVYH1T4J09x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE","a":{"d":"E24I'
                       b'f3y9Voz-1sXgkBCeNG6pbCqMTa56kCvj47NgOgLg","i":"EWVYH1T4J09x5RePL'
                       b'fVyTfno3aHzJ-YqnL9Bm0Kyx6UE","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EScaN0EobGIzPq-3'
                       b'S05vY2FjBOeXBQ_7wTR9ChFUGUOU"}-VA3-JAB6AABAAA--FABEWVYH1T4J09x5R'
                       b'ePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE0AAAAAAAAAAAAAAAAAAAAAAAEWVYH1T4J0'
                       b'9x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE-AABAAC6mt9p5YASFnQsWpU2x47cNv'
                       b'15PKXJpg806KZNj3mtDGJfiCG9eU-WTwUN4Ghv7pPjHiPyBElrphD594IhSWCA')

        # Create the issue credential payload
        pl = dict(
            vc=[envelope(msg=msg)]
        )

        # Create the `exn` message for issue credential
        sidExcSrdr = exchanging.exchange(route="/credential/issue", payload=pl)
        excMsg = bytearray()
        excMsg.extend(sidHab.endorse(sidExcSrdr, last=True))

        # Parse the exn issue credential message on Red's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)
        doers = wanDoers + [redExc]
        doist.do(doers=doers)
        assert doist.tyme == limit

        ser = (b'{"v":"ACDC10JSON00019e_","d":"EzucsqkRDx69MHfroAwzNrARf_erW2j9y2-hQdUvRBLs",'
               b'"s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","i":"EWVYH1T4J09x5RePLfVy'
               b'Tfno3aHzJ-YqnL9Bm0Kyx6UE","a":{"d":"E24If3y9Voz-1sXgkBCeNG6pbCqMTa56kCvj47Ng'
               b'OgLg","i":"EWVYH1T4J09x5RePLfVyTfno3aHzJ-YqnL9Bm0Kyx6UE","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EScaN0EobGIz'
               b'Pq-3S05vY2FjBOeXBQ_7wTR9ChFUGUOU"}')
        sig0 = (b'AAC6mt9p5YASFnQsWpU2x47cNv15PKXJpg806KZNj3mtDGJfiCG9eU-WTwUN4Ghv7pPjHiPyBElr'
                b'phD594IhSWCA')

        # verify we can load serialized VC by SAID
        creder, sadsigers, sadcigars = redPDB.cloneCred(said=creder.said)
        assert creder.raw == ser

        # verify the signature
        assert len(sadsigers) == 1
        (_, _, _, _, sigers) = sadsigers[0]
        assert sigers[0].qb64b == sig0
        assert len(sadcigars) == 0

        # verify we can look up credential by Schema SAID
        schema = redPDB.schms.get(schema)
        assert len(schema) == 1
        assert schema[0].qb64 == creder.said


def test_proving(seeder):
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    hanSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    vicSalt = coring.Salter(raw=b'fedcba9876543210').qb64

    with viring.openReg(name="han") as hanPDB, \
            habbing.openHby(name="han", base="test", salt=hanSalt) as hanHby, \
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

        verifier = verifying.Verifier(hby=hanHby, reger=hanPDB)
        issuer = issuing.Issuer(hab=hanHab, reger=hanPDB)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=d,
                            status=issuer.regk,
                            )

        assert creder.said == "EDmtVUrmHL69-BbKeEpy5kcI-AfiATvOmVZqvYJ04wAM"

        msg = signing.ratify(sidHab, serder=creder)
        hanWallet = Wallet(reger=hanPDB)

        issuer.issue(creder=creder)
        parsing.Parser().parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert hanPDB.creds.get(key) is not None

        # Create Red's wallet and Issue Handler for receiving the credential
        hanRequestHandler = RequestHandler(hby=hanHby, wallet=hanWallet)
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

        proof = (
            '-JAB6AABAAA--FABECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc0AAAAAAAAAAAAAAAAAAAAAAAECtWlHS2Wbx5M2Rg6nm69'
            'PCtzwb1veiRNvDpBGF9Z1Pc-AABAAMXOxuGRr7Pu8Om_CviaojysYn28ClhWzIYZiZ42ePnTqzEW4u-c_seM-gT-gNI9BNztivzOUeMgVm'
            '8MYXLpRDQ')

        assert vcs[0]["proof"] == proof


if __name__ == '__main__':
    test_issuing()
    test_proving()
