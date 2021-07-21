# -*- encoding: utf-8 -*-
"""
tests.vc.handling module

"""
from hio.base import doing

from keri.app import keeping, habbing
from keri.core import coring, scheming, eventing, parsing
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.peer import exchanging
from keri.vc.handling import IssueHandler, envelope, RequestHandler
from keri.vc.proving import credential
from keri.vc.walleting import Wallet, openPocket, parseCredential


def test_issuing():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS, \
            basing.openDB(name="red") as redDB, \
            openPocket(name="red") as redPDB:
        limit = 1.0
        tock = 1.0
        doist = doing.Doist(limit=limit, tock=tock)

        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        sidPre = sidHab.pre
        assert sidPre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"

        sidIcpMsg = sidHab.makeOwnInception()

        redKvy = eventing.Kevery(db=redDB)
        parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=redKvy)
        assert redKvy.kevers[sidPre].sn == 0  # accepted event

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(
            type="object",
            properties=dict(
                id=dict(
                    type="string"
                ),
                lei=dict(
                    type="string"
                )
            )
        ))

        schemer = scheming.Schemer(sed=sed, code=coring.MtrDex.Blake3_256)
        assert schemer.said == "EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY"

        cache = scheming.CacheResolver()
        cache.add(schemer.said, schemer.raw)
        jsonSchema = JSONSchema(resolver=cache)

        # Create Red's wallet and Issue Handler for receiving the credential
        redWallet = Wallet(hab=sidHab, db=redPDB)
        redIssueHandler = IssueHandler(wallet=redWallet, typ=jsonSchema)
        redExc = exchanging.Exchanger(hab=sidHab, tymth=doist.tymen(), handlers=[redIssueHandler])

        # Build the credential subject and then the Credentialer for the full credential
        credSubject = dict(
            id="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            typ=jsonSchema)

        assert creder.said == "EgaaYOPdG7vootT99cmClvwOoM-hjUIpv5Xl6hFuTcyM"

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000136_","i":"EgaaYOPdG7vootT99cmClvwOoM-hjUIpv5Xl6hFuTcyM",'
            b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY","ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00"}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
            b'-AABAA0pXbQllgzXr88IczAnsPrdhgFKs9wNQvfSfzyrtcvbTwq-U1DmBluAklntCqH1AbBL6TWLZIDGi83BHLWJ82CA')

        # Create the issue credential payload
        pl = dict(
            vc=[envelope(msg, typ=jsonSchema)]
        )

        # Create the `exn` message for issue credential
        sidExcSrdr = exchanging.exchange(route="/credential/issue", payload=pl)
        excMsg = sidHab.sanction(sidExcSrdr)

        # Parse the exn issue credential message on Red's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)
        doist.do(doers=[redExc])
        assert doist.tyme == limit

        ser = (
            b'{"v":"KERI10JSON000136_","i":"EgaaYOPdG7vootT99cmClvwOoM-hjUIpv5Xl6hFuTcyM",'
            b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY","ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00"}}')
        sig0 = (
            b'AA0pXbQllgzXr88IczAnsPrdhgFKs9wNQvfSfzyrtcvbTwq-U1DmBluAklntCqH1AbBL6TWLZIDGi83BHLWJ82CA'
        )

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert redPDB.getSers(key) == ser

        # verify the signature
        sigs = redPDB.getSigs(key)
        assert len(sigs) == 1
        assert sigs[0] == sig0

        # verify we can look up credential by Schema SAID
        schema = redPDB.getSchms(schemer.saider.qb64b)
        assert len(schema) == 1
        assert schema[0] == key


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
            openPocket(name="han") as hanPDB:
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

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(
            type="object",
            properties=dict(
                id=dict(
                    type="string"
                ),
                lei=dict(
                    type="string"
                )
            )
        ))

        schemer = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)
        jsonSchema = JSONSchema(resolver=cache)

        credSubject = dict(
            id="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            typ=JSONSchema(resolver=cache))

        assert creder.said == "EgaaYOPdG7vootT99cmClvwOoM-hjUIpv5Xl6hFuTcyM"

        msg = sidHab.endorse(serder=creder)
        hanWallet = Wallet(hab=hanHab, db=hanPDB)

        parseCredential(ims=msg, wallet=hanWallet, typ=JSONSchema(resolver=cache))

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert hanPDB.getSers(key) is not None

        # Create Red's wallet and Issue Handler for receiving the credential
        hanRequestHandler = RequestHandler(wallet=hanWallet, typ=jsonSchema)
        hanExc = exchanging.Exchanger(hab=hanHab, tymth=doist.tymen(), handlers=[hanRequestHandler])

        # Create the issue credential payload
        pl = dict(
            input_descriptors=[
                dict(x=schemer.said)
            ]
        )

        # Create the `exn` message for presentation request
        vicExcSrdr = exchanging.exchange(route="/presentation/request", payload=pl)
        excMsg = vicHab.sanction(vicExcSrdr)

        # Parse the exn presentation request message on Han's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=hanKvy, exc=hanExc)
        doist.do(doers=[hanExc])
        assert doist.tyme == limit

        resp = hanRequestHandler.cues.popleft()
        assert resp is not None

        respSer = coring.Serder(raw=resp.raw)
        assert respSer.ked['t'] == coring.Ilks.exn
        assert respSer.ked['r'] == "/presentation/proof"
        data = respSer.ked['q']
        assert "presentation_submission" in data

        pe = data["presentation_submission"]
        assert "descriptor_map" in pe

        dm = pe["descriptor_map"]
        assert len(dm) == 1
        assert dm[0]["id"] == schemer.said

        assert "verifiableCredential" in data
        vcs = data["verifiableCredential"]
        assert len(vcs) == 1

        proof = (
            "-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw"
            "-AxDNI7_ZmaI-AABAA0pXbQllgzXr88IczAnsPrdhgFKs9wNQvfSfzyrtcvbTwq-U1DmBluAklntCqH1AbBL6TWLZIDGi83BHLWJ82CA")
        assert vcs[0]["proof"] == proof


if __name__ == '__main__':
    test_issuing()
    test_proving()
