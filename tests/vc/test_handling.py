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


def test_issuing():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    wanSalt = coring.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0Ad2Fubi10aGUtd2l0bmVzcw'

    with viring.openReg(name="red") as redPDB, \
         habbing.openHby(name="red", base="test") as redHby, \
         habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby, \
         habbing.openHby(name="wan", base="test", salt=wanSalt) as wanHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)

        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        sidHab = sidHby.makeHab(name="test",
                                wits=["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"])
        sidPre = sidHab.pre
        assert sidPre == "EeBZcaNdy0ZkuquN367PMj4Plg1201MSevpLREfB3Pxs"

        redKvy = eventing.Kevery(db=redHby.db)

        verifier = verifying.Verifier(hby=sidHby, reger=redPDB)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)

        # Create Red's wallet and Issue Handler for receiving the credential
        redIssueHandler = IssueHandler(hby=sidHby, verifier=verifier)
        redExc = exchanging.Exchanger(hby=sidHby, tymth=doist.tymen(), handlers=[redIssueHandler])

        schema = "EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg"

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

        assert creder.said == "EA8Uibg-dQsaMQvDQbMNqj2pBEW2iz6DzXn7ocm0lb9A"

        issuer.issue(creder=creder)
        msg = signing.ratify(sidHab, serder=creder, pipelined=True)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"EA8Uibg-dQsaMQvDQbMNqj2pBEW2iz6DzX'
                       b'n7ocm0lb9A","s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","'
                       b'i":"EeBZcaNdy0ZkuquN367PMj4Plg1201MSevpLREfB3Pxs","a":{"d":"Ec6X'
                       b'brY7znoeIUhxj5Xqk6sOby9MtCcUJGHolM-a6-Vc","i":"EeBZcaNdy0ZkuquN3'
                       b'67PMj4Plg1201MSevpLREfB3Pxs","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","ri":"ETxWu1_j6teP1VYBjRerXG3S'
                       b'91Xs2ESrLgtBPlXkrQfw"},"p":[]}-VA3-JAB6AABAAA--FABEeBZcaNdy0Zkuq'
                       b'uN367PMj4Plg1201MSevpLREfB3Pxs0AAAAAAAAAAAAAAAAAAAAAAAEeBZcaNdy0'
                       b'ZkuquN367PMj4Plg1201MSevpLREfB3Pxs-AABAAh8MqB8-SlX1AkYHyMIaJ54Xv'
                       b'cUkx-daOLsnyRbbBRZ5uZdfNUP_rpidW-r4f10jEUSFccI8x1IH_DGMOl_y2Dw')

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

        ser = (b'{"v":"ACDC10JSON00019e_","d":"EA8Uibg-dQsaMQvDQbMNqj2pBEW2iz6DzXn7ocm0lb9A",'
               b'"s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","i":"EeBZcaNdy0ZkuquN367P'
               b'Mj4Plg1201MSevpLREfB3Pxs","a":{"d":"Ec6XbrY7znoeIUhxj5Xqk6sOby9MtCcUJGHolM-a'
               b'6-Vc","i":"EeBZcaNdy0ZkuquN367PMj4Plg1201MSevpLREfB3Pxs","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","ri":"ETxWu1_j6teP1VYBjRer'
               b'XG3S91Xs2ESrLgtBPlXkrQfw"},"p":[]}')
        sig0 = (b'AAh8MqB8-SlX1AkYHyMIaJ54XvcUkx-daOLsnyRbbBRZ5uZdfNUP_rpidW-r4f10jEUSFccI8x1I'
                b'H_DGMOl_y2Dw')

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


def test_proving():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    hanSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    vicSalt = coring.Salter(raw=b'fedcba9876543210').qb64

    #with basing.openDB(name="sid") as sidDB, \
            #keeping.openKS(name="sid") as sidKS, \
            #basing.openDB(name="vic") as vicDB, \
            #keeping.openKS(name="vic") as vicKS, \
            #basing.openDB(name="han") as hanDB, \
            #keeping.openKS(name="han") as hanKS, \
            #viring.openReg(name="han") as hanPDB:

    with viring.openReg(name="han") as hanPDB, \
         habbing.openHby(name="han", base="test", salt=hanSalt) as hanHby, \
         habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby, \
         habbing.openHby(name="vic", base="test", salt=vicSalt) as vicHby:

        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        # sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        sidHab = sidHby.makeHab(name="test")
        assert sidHab.pre == "EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc"
        sidIcpMsg = sidHab.makeOwnInception()

        hanKvy = eventing.Kevery(db=hanHby.db)
        parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[sidHab.pre].sn == 0  # accepted event

        # hanHab = habbing.Habitat(ks=hanKS, db=hanDB, salt=hanSalt, temp=True)
        hanHab = hanHby.makeHab(name="test")
        assert hanHab.pre == "EXs465M4avETtnmCD2cd02CDwE5K-1vyTnyfk15_PRPs"
        hanIcpMsg = hanHab.makeOwnInception()

        vicKvy = eventing.Kevery(db=vicHby.db)
        parsing.Parser().parse(ims=bytearray(hanIcpMsg), kvy=vicKvy)
        assert vicKvy.kevers[hanHab.pre].sn == 0  # accepted event

        # vicHab = habbing.Habitat(ks=vicKS, db=vicDB, salt=vicSalt, temp=True)
        vicHab = vicHby.makeHab(name="test")
        assert vicHab.pre == "EvOnXBWyrNJbR4wf__Qn79YAf-u3GynE3ychvkuiGnEI"
        vicIcpMsg = vicHab.makeOwnInception()

        parsing.Parser().parse(ims=bytearray(vicIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[vicHab.pre].sn == 0  # accepted event

        schema = "EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg"
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

        assert creder.said == "EkHBr-04I1Id_bXI4luPZsASLVJ4ZOsI3a5ChZgE0iug"

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
            "-JAB6AABAAA--FABEPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc0AAAAAAAAAAAAAAAAAAAAAAAEPmpiN6bEM8EI0Mctny"
            "-6AfglVOKnJje8-vqyKTlh0nc-AABAA6W18DO1EXT8Qeu_kaPqEQBPIlQQE_EoLDzxJb_M71EqQEC"
            "-lA1lsW4R9lWTkj55jSvWIuTbTkXoTJVCyzKSTBA")

        assert vcs[0]["proof"] == proof


if __name__ == '__main__':
    test_issuing()
    test_proving()
