# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""
from hio.base import doing

from keri.app import habbing, indirecting, signing, storing, notifying
from keri.core import coring, scheming, eventing, parsing
from keri.core.eventing import SealEvent
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vc.protocoling import IssueHandler, PresentationRequestHandler, PresentationProofHandler, \
    presentationExchangeExn
from keri.vc.proving import credential
from keri.vdr import verifying, credentialing


def test_issuing(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    """ Test Issuing ACDC """


    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
    wanSalt = coring.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0AB3YW5uLXRoZS13aXRuZXNz'

    with (habbing.openHby(name="red", base="test") as redHby,
          habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby,
          habbing.openHby(name="wan", base="test", salt=wanSalt) as wanHby):


        # setup wan's Hab and doers
        wanDoers = indirecting.setupWitness(alias="wan",
                                            hby=wanHby,
                                            tcpPort=5632,
                                            httpPort=5642)

        wanHab = wanHby.habByName(name="wan")
        wanPre = wanHab.pre
        assert wanPre == 'BOigXdxpp1r43JhO--czUTwrCXzoWrIwW8i41KWDlr8s'

        seeder.seedSchema(redHby.db)
        seeder.seedSchema(sidHby.db)
        seeder.seedSchema(wanHby.db)

        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        sidHab = sidHby.makeHab(name="test",
                                wits=[wanHab.pre])
        sidPre = sidHab.pre
        assert sidPre == "EELPMtVeoAMwq-cEvyqQkPlVlHHj86nNxpb-77KcM3DZ"

        redKvy = eventing.Kevery(db=redHby.db)
        redRgy = credentialing.Regery(hby=redHby, name="red", temp=True)
        redVer = verifying.Verifier(hby=redHby, reger=redRgy.reger)

        sidRgy = credentialing.Regery(hby=sidHby, name="bob", temp=True)
        sidVer = verifying.Verifier(hby=sidHby, reger=sidRgy.reger)

        notifier = notifying.Notifier(hby=sidHby)
        issuer = sidRgy.makeRegistry(prefix=sidHab.pre, name="sid")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidRgy.processEscrows()

        # Create Red's wallet and Issue Handler for receiving the credential
        redIssueHandler = IssueHandler(hby=sidHby, rgy=sidRgy, notifier=notifier)
        redExc = exchanging.Exchanger(db=sidHby.db, tymth=doist.tymen(), handlers=[redIssueHandler])

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"

        # Build the credential subject and then the Creder for the full credential
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Saids.d)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            data=d,
                            status=issuer.regk)

        assert creder.said == "EIanW-Icbisj1noOeOJDfPIsIy0QZUB-smfTu0bOvN-a"

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidRgy.processEscrows()

        msg = signing.ratify(sidHab, serder=creder, pipelined=True)
        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EIanW-Icbisj1noOeOJDfPIsIy0QZUB-sm'
                       b'fTu0bOvN-a","i":"EELPMtVeoAMwq-cEvyqQkPlVlHHj86nNxpb-77KcM3DZ","'
                       b'ri":"EPzhcSAxNzgx-TgD_IJ59xJB7tAFCjIBWLzB9ZWesacD","s":"EMQWEcCn'
                       b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EOM45RCy4W3Kt6-U'
                       b'_oUhaK4SYvRp-9MbLwBmlkn-wY1_","dt":"2021-06-27T21:26:21.233257+0'
                       b'0:00","i":"EELPMtVeoAMwq-cEvyqQkPlVlHHj86nNxpb-77KcM3DZ","LEI":"'
                       b'254900OPPU84GM83MG36"}}-VA3-JAB6AABAAA--FABEELPMtVeoAMwq-cEvyqQk'
                       b'PlVlHHj86nNxpb-77KcM3DZ0AAAAAAAAAAAAAAAAAAAAAAAEELPMtVeoAMwq-cEv'
                       b'yqQkPlVlHHj86nNxpb-77KcM3DZ-AABAADx-hk7PsYCG3M5qyg2SZPV30BOpV2Wy'
                       b'7nVq7s90TlvrHnGA5KY9NNB25_Be1vyO7WKepIXD7LkGGG8sBNm1Q8B')

        # Create the `exn` message for issue credential
        sidExcSrdr, atc = protocoling.credentialIssueExn(hab=sidHab, issuer=sidHab.pre, schema=creder.schema,
                                                         said=creder.said)
        excMsg = bytearray(sidExcSrdr.raw)
        excMsg.extend(atc)
        # Parse the exn issue credential message on Red's side

        parsing.Parser().parse(ims=bytearray(msg), vry=sidVer)

        parsing.Parser().parse(ims=bytearray(msg), kvy=redKvy, exc=redExc, vry=redVer)
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)
        doers = wanDoers + [redExc]
        doist.do(doers=doers)
        assert doist.tyme == limit

        ser = (b'{"v":"ACDC10JSON000197_","d":"EIanW-Icbisj1noOeOJDfPIsIy0QZUB-smfTu0bOvN-a",'
               b'"i":"EELPMtVeoAMwq-cEvyqQkPlVlHHj86nNxpb-77KcM3DZ","ri":"EPzhcSAxNzgx-TgD_IJ'
               b'59xJB7tAFCjIBWLzB9ZWesacD","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
               b'","a":{"d":"EOM45RCy4W3Kt6-U_oUhaK4SYvRp-9MbLwBmlkn-wY1_","dt":"2021-06-27T2'
               b'1:26:21.233257+00:00","i":"EELPMtVeoAMwq-cEvyqQkPlVlHHj86nNxpb-77KcM3DZ","LE'
               b'I":"254900OPPU84GM83MG36"}}')
        sig0 = (b'AADx-hk7PsYCG3M5qyg2SZPV30BOpV2Wy7nVq7s90TlvrHnGA5KY9NNB25_Be1vyO7WKepIXD7Lk'
                b'GGG8sBNm1Q8B')

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


def test_proving(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
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
        assert sidHab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"
        sidIcpMsg = sidHab.makeOwnInception()

        hanKvy = eventing.Kevery(db=hanHby.db)
        parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[sidHab.pre].sn == 0  # accepted event

        # hanHab = habbing.Habitat(ks=hanKS, db=hanDB, salt=hanSalt, temp=True)
        hanHab = hanHby.makeHab(name="test")
        assert hanHab.pre == "EKiRAvVAoSwdTxOpHZZXojpY3RxVIYQffLUF7ITQDKT6"
        hanIcpMsg = hanHab.makeOwnInception()

        vicKvy = eventing.Kevery(db=vicHby.db)
        parsing.Parser().parse(ims=bytearray(hanIcpMsg), kvy=vicKvy)
        assert vicKvy.kevers[hanHab.pre].sn == 0  # accepted event

        # vicHab = habbing.Habitat(ks=vicKS, db=vicDB, salt=vicSalt, temp=True)
        vicHab = vicHby.makeHab(name="test")
        assert vicHab.pre == "EFWujxD_N6DKo4Heaq-vSmv9a5RV09gbJUt68wBFIdAo"
        vicIcpMsg = vicHab.makeOwnInception()

        parsing.Parser().parse(ims=bytearray(vicIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[vicHab.pre].sn == 0  # accepted event

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"

        hanReg = credentialing.Regery(hby=hanHby, name="han", temp=True)
        issuer = hanReg.makeRegistry(prefix=hanHab.pre, name="han")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hanHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hanHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hanHab.kever.serder.saider)
        hanReg.processEscrows()

        verifier = verifying.Verifier(hby=hanHby, reger=hanReg.reger)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            recipient=hanHab.pre,
                            data=dict(
                                LEI="254900OPPU84GM83MG36",
                            ),
                            status=issuer.regk,
                            )
        assert creder.said == "EEO1aft5aKWawxAIuN4_x0b2oeajvAikyR_w0sADoiXv"

        msg = signing.ratify(sidHab, serder=creder)

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hanHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hanHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hanHab.kever.serder.saider)
        hanReg.processEscrows()

        parsing.Parser().parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert hanReg.reger.creds.get(key) is not None

        # Create Red's wallet and Issue Handler for receiving the credential
        notifier = notifying.Notifier(hby=hanHby)
        hanRequestHandler = PresentationRequestHandler(hby=hanHby, notifier=notifier)
        hanPresentHandler = PresentationProofHandler(notifier=notifier)
        hanExc = exchanging.Exchanger(db=hanHby.db, tymth=doist.tymen(), handlers=[hanRequestHandler,
                                                                                   hanPresentHandler])

        # Create the issue credential payload
        pl = dict(
            s=schema
        )

        # Create the `exn` message for presentation request
        vicExcSrdr = exchanging.exchange(route="/presentation/request", payload=pl)
        excMsg = bytearray(vicExcSrdr.raw)
        excMsg.extend(vicHab.endorse(vicExcSrdr, last=True))

        # Parse the exn presentation request message on Han's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=hanKvy, exc=hanExc)
        doist.do(doers=[hanExc])
        assert doist.tyme == limit

        resp = notifier.signaler.signals.popleft()
        assert resp is not None
        notifier.noter.rem(resp.rid)

        note = resp.attrs["note"]
        a = note["a"]
        assert a["schema"] == dict(
            n=schema
        )

        exn, atc = presentationExchangeExn(hanHab, reger=hanReg.reger, said=creder.said)
        assert exn.ked['r'] == "/presentation"
        assert atc == bytearray(b'-HABEKiRAvVAoSwdTxOpHZZXojpY3RxVIYQffLUF7ITQDKT6-AABAADqyvceNUq0'
                                b'utmXQ6fFtE6juYK9B9lszFHgtM09FX5VCc5aESYM5lqgwHqOgaBjU11qfSMkIQ9K'
                                b'OrBRPNu_PMIP')

        msg = bytearray(exn.raw)
        msg.extend(atc)
        parsing.Parser().parse(ims=msg, kvy=hanKvy, exc=hanExc)
        doist.do(doers=[hanExc])
        assert doist.tyme == limit * 2

        resp = notifier.signaler.signals.popleft()
        assert resp is not None
        note = resp.attrs["note"]
        a = note["a"]
        assert a == {'credential': {'n': 'EEO1aft5aKWawxAIuN4_x0b2oeajvAikyR_w0sADoiXv'},
                     'issuer': {'i': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'},
                     'r': '/presentation',
                     'schema': {'n': 'EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'}}
