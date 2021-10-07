# -*- encoding: utf-8 -*-
"""
tests.vc.handling module

"""
from hio.base import doing

from keri.app import keeping, habbing, indirecting
from keri.core import coring, scheming, eventing, parsing
from keri.db import basing
from keri.peer import exchanging
from keri.vc.handling import IssueHandler, envelope, RequestHandler
from keri.vc.proving import credential, parseCredential
from keri.vc.walleting import Wallet
from keri.vdr import viring, verifying, issuing


def test_issuing():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS, \
            basing.openDB(name="red") as redDB, \
            habbing.openHab(name="wan", salt=b'wann-the-witness', transferable=False) as wanHab, \
            viring.openReg(name="red") as redPDB:
        wanDoers = indirecting.setupWitness(name="wan", hab=wanHab, temp=True, tcpPort=5632, httpPort=5642)

        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True,
                                 wits=["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"])
        sidPre = sidHab.pre
        assert sidPre == "EWJuxKtF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU_sAqM"

        redKvy = eventing.Kevery(db=redDB)

        verifier = verifying.Verifier(hab=sidHab, reger=redPDB)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)

        # Create Red's wallet and Issue Handler for receiving the credential
        redIssueHandler = IssueHandler(hab=sidHab, verifier=verifier)
        redExc = exchanging.Exchanger(hab=sidHab, tymth=doist.tymen(), handlers=[redIssueHandler])

        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"

        # Build the credential subject and then the Credentialer for the full credential
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
            t=["VerifiableCredential", "GLEIFvLEICredential"]
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=d,
                            status=issuer.regk)

        assert creder.said == "EUxHbA_hU7vtde9a8GXrEvpoVaUdd2-FXh_jBZbM-3gM"

        issuer.issue(creder=creder)
        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON0001d1_","d":"EUxHbA_hU7vtde9a8GXrEvpoVaUdd2-FXh'
                       b'_jBZbM-3gM","s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","'
                       b'i":"EWJuxKtF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU_sAqM","a":{"d":"EFUJ'
                       b'YK-w1tyryZOihzQHH18AzHpkCIvaeEmMtwXHIzSk","i":"EWJuxKtF-w3DD9RuH'
                       b'IO0zcIo7eakSkcUT6XBfGU_sAqM","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","t":["VerifiableCredential","G'
                       b'LEIFvLEICredential"],"ri":"EQNgVMXpmIWmPLoNgPxj1-xCMTm0-K8f3sBlU'
                       b'ckNZSTY"},"p":[]}-VA0-FABEWJuxKtF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU'
                       b'_sAqM0AAAAAAAAAAAAAAAAAAAAAAAEK29DLvJwcxTSkPvaBJttJkuzZ3NUgBKyx_'
                       b'eV2k7bcZs-AABAA6DYmVaPqvZC3IuVkpDbyhKjI8ljl1gWQZvQf-NDOaeKyzQISR'
                       b'dQ0AKXFtHpg6CVf3fThzZ5l_Tme0L7aWN99CQ')

        # Create the issue credential payload
        pl = dict(
            vc=[envelope(msg)]
        )

        # Create the `exn` message for issue credential
        sidExcSrdr = exchanging.exchange(route="/credential/issue", payload=pl)
        excMsg = bytearray(sidExcSrdr.raw)
        excMsg.extend(sidHab.endorse(sidExcSrdr, last=True))

        # Parse the exn issue credential message on Red's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)
        doers = wanDoers + [redExc]
        doist.do(doers=doers)
        assert doist.tyme == limit

        ser = (b'{"v":"KERI10JSON0001d1_","d":"EUxHbA_hU7vtde9a8GXrEvpoVaUdd2-FXh_jBZbM-3gM",'
               b'"s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","i":"EWJuxKtF-w3DD9RuHIO0'
               b'zcIo7eakSkcUT6XBfGU_sAqM","a":{"d":"EFUJYK-w1tyryZOihzQHH18AzHpkCIvaeEmMtwXH'
               b'IzSk","i":"EWJuxKtF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU_sAqM","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","t":["VerifiableCredential'
               b'","GLEIFvLEICredential"],"ri":"EQNgVMXpmIWmPLoNgPxj1-xCMTm0-K8f3sBlUckNZSTY"'
               b'},"p":[]}')
        sig0 = (b'AA6DYmVaPqvZC3IuVkpDbyhKjI8ljl1gWQZvQf-NDOaeKyzQISRdQ0AKXFtHpg6CVf3fThzZ5l_T'
                b'me0L7aWN99CQ')

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert redPDB.creds.get(key).raw == ser

        # verify the signature
        seals = redPDB.seals.get(key)
        sigs = [sig for (_, _, _, sig) in seals]
        assert len(sigs) == 1
        assert sigs[0].qb64b == sig0

        # verify we can look up credential by Schema SAID
        schema = redPDB.schms.get(schema)
        assert len(schema) == 1
        assert schema[0].qb64b == key


def test_proving():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    hanSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    vicSalt = coring.Salter(raw=b'fedcba9876543210').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS, \
            basing.openDB(name="vic") as vicDB, \
            keeping.openKS(name="vic") as vicKS, \
            basing.openDB(name="han") as hanDB, \
            keeping.openKS(name="han") as hanKS, \
            viring.openReg(name="han") as hanPDB:
        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        assert sidHab.pre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"
        sidIcpMsg = sidHab.makeOwnInception()

        hanKvy = eventing.Kevery(db=hanDB)
        parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[sidHab.pre].sn == 0  # accepted event

        hanHab = habbing.Habitat(ks=hanKS, db=hanDB, salt=hanSalt, temp=True)
        assert hanHab.pre == "EKDWzykRd45o5UQyprm_9e8UcltXGo1tZCrdfGBTA8tc"
        hanIcpMsg = hanHab.makeOwnInception()

        vicKvy = eventing.Kevery(db=vicDB)
        parsing.Parser().parse(ims=bytearray(hanIcpMsg), kvy=vicKvy)
        assert vicKvy.kevers[hanHab.pre].sn == 0  # accepted event

        vicHab = habbing.Habitat(ks=vicKS, db=vicDB, salt=vicSalt, temp=True)
        assert vicHab.pre == "E8HQASAgOnZnQ4T7rv3dcvj0-UydrTTtyCprhEASk__o"
        vicIcpMsg = vicHab.makeOwnInception()

        parsing.Parser().parse(ims=bytearray(vicIcpMsg), kvy=hanKvy)
        assert hanKvy.kevers[vicHab.pre].sn == 0  # accepted event

        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
        credSubject = dict(
            d="",
            i=hanHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
            t=["VerifiableCredential", "GLEIFvLEICredential"]
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        verifier = verifying.Verifier(hab=hanHab, reger=hanPDB)
        issuer = issuing.Issuer(hab=hanHab, reger=hanPDB)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=d,
                            status=issuer.regk,
                            )

        assert creder.said == "E8sY-Bf_kmJ1ducVjMXrvfoyxgw1zmst-h-dUswjZ_rg"

        msg = sidHab.endorse(serder=creder)
        hanWallet = Wallet(db=hanPDB)

        issuer.issue(creder=creder)
        parseCredential(ims=msg,
                        verifier=verifier)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert hanPDB.creds.get(key) is not None

        # Create Red's wallet and Issue Handler for receiving the credential
        hanRequestHandler = RequestHandler(wallet=hanWallet)
        hanExc = exchanging.Exchanger(hab=hanHab, tymth=doist.tymen(), handlers=[hanRequestHandler])

        # Create the issue credential payload
        pl = dict(
            input_descriptors=[
                dict(x=schema)
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
        data = respSer.ked['d']
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
            "-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw"
            "-AxDNI7_ZmaI-AABAA0pFYDPH3jqvS4z-6lSefLLg-Zr7-IABhP69VruJUFK3SwP_x0ksPzknQq6Q4kV8bR9lyxb8pHFQyFAonj_agAA"
        )

        assert vcs[0]["proof"] == proof


if __name__ == '__main__':
    test_issuing()
    test_proving()
