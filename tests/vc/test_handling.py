# -*- encoding: utf-8 -*-
"""
tests.vc.handling module

"""
from hio.base import doing

from keri.app import keeping, habbing, indirecting
from keri.core import coring, scheming, eventing, parsing
from keri.core.scheming import CacheResolver, JSONSchema
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

        # sidIcpMsg = sidHab.makeOwnInception()
        #
        redKvy = eventing.Kevery(db=redDB)
        # parsing.Parser().parse(ims=bytearray(sidIcpMsg), kvy=redKvy)
        # assert redKvy.kevers[sidPre].sn == 0  # accepted event

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(
            type="object",
            properties=dict(
                i=dict(
                    type="string"
                ),
                lei=dict(
                    type="string"
                ),
            )
        ))

        verifier = verifying.Verifier(hab=sidHab, reger=redPDB)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)
        schemer = scheming.Schemer(sed=sed, code=coring.MtrDex.Blake3_256)
        assert schemer.said == "EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438"

        cache = scheming.CacheResolver()
        cache.add(schemer.said, schemer.raw)
        jsonSchema = JSONSchema(resolver=cache)

        # Create Red's wallet and Issue Handler for receiving the credential
        redIssueHandler = IssueHandler(hab=sidHab, verifier=verifier, typ=jsonSchema)
        redExc = exchanging.Exchanger(hab=sidHab, tymth=doist.tymen(), handlers=[redIssueHandler])

        # Build the credential subject and then the Credentialer for the full credential
        credSubject = dict(
            i="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
            si=sidHab.pre,
        )

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            status=issuer.regk,
                            typ=jsonSchema)

        assert creder.said == "EQ6QvRIRCB5xIs5JxGYOL2TI-oOYpEC8y5w-QlPwgjH4"

        issuer.issue(creder=creder)
        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON00019d_","i":"EQ6QvRIRCB5xIs5JxGYOL2TI-oOYpEC8y5'
                       b'w-QlPwgjH4","x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","'
                       b'ti":"EWJuxKtF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU_sAqM","d":{"i":"did'
                       b':keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36'
                       b'","issuanceDate":"2021-06-27T21:26:21.233257+00:00","si":"EWJuxK'
                       b'tF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU_sAqM"},"ri":"EQNgVMXpmIWmPLoNg'
                       b'Pxj1-xCMTm0-K8f3sBlUckNZSTY"}-VA0-FABEWJuxKtF-w3DD9RuHIO0zcIo7ea'
                       b'kSkcUT6XBfGU_sAqM0AAAAAAAAAAAAAAAAAAAAAAAEK29DLvJwcxTSkPvaBJttJk'
                       b'uzZ3NUgBKyx_eV2k7bcZs-AABAAjppmEaJJC4LsGdyaFOi2sS1lf83Oe7gxTEchZ'
                       b'eL1Ep836nhwblFfk4kMEzAC_B_T4XPrjedFyN6gyMFPPHePCA')

        # Create the issue credential payload
        pl = dict(
            vc=[envelope(msg, typ=jsonSchema)]
        )

        # Create the `exn` message for issue credential
        sidExcSrdr = exchanging.exchange(route="/credential/issue", payload=pl)
        excMsg = bytearray(sidExcSrdr.raw)
        excMsg.extend(sidHab.sanction(sidExcSrdr))

        # Parse the exn issue credential message on Red's side
        parsing.Parser().parse(ims=bytearray(excMsg), kvy=redKvy, exc=redExc)
        doers = wanDoers + [redExc]
        doist.do(doers=doers)
        assert doist.tyme == limit

        ser = (b'{"v":"KERI10JSON00019d_","i":"EQ6QvRIRCB5xIs5JxGYOL2TI-oOYpEC8y5w-QlPwgjH4",'
               b'"x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","ti":"EWJuxKtF-w3DD9RuHIO'
               b'0zcIo7eakSkcUT6XBfGU_sAqM","d":{"i":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v"'
               b',"lei":"254900OPPU84GM83MG36","issuanceDate":"2021-06-27T21:26:21.233257+00:'
               b'00","si":"EWJuxKtF-w3DD9RuHIO0zcIo7eakSkcUT6XBfGU_sAqM"},"ri":"EQNgVMXpmIWmP'
               b'LoNgPxj1-xCMTm0-K8f3sBlUckNZSTY"}')
        sig0 = (b'AAjppmEaJJC4LsGdyaFOi2sS1lf83Oe7gxTEchZeL1Ep836nhwblFfk4kMEzAC_B_T4XPrjedFyN'
                b'6gyMFPPHePCA')

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert redPDB.creds.get(key).raw == ser

        # verify the signature
        seals = redPDB.seals.get(key)
        sigs = [sig for (_, _, _, sig) in seals]
        assert len(sigs) == 1
        assert sigs[0].qb64b == sig0

        # verify we can look up credential by Schema SAID
        schema = redPDB.schms.get(schemer.saider.qb64b)
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

        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(
            type="object",
            properties=dict(
                i=dict(
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
            i="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            si=hanHab.pre,
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        verifier = verifying.Verifier(hab=hanHab, reger=hanPDB)
        issuer = issuing.Issuer(hab=hanHab, reger=hanPDB)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            status=issuer.regk,
                            typ=JSONSchema(resolver=cache),
                            )

        assert creder.said == "EmQSuvSzEkfdi62_obUFRqWrbWkEq7VHpHA5tECO8JQc"

        msg = sidHab.endorse(serder=creder)
        hanWallet = Wallet(db=hanPDB)

        issuer.issue(creder=creder)
        parseCredential(ims=msg,
                        verifier=verifier,
                        typ=JSONSchema(resolver=cache))

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert hanPDB.creds.get(key) is not None

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
        excMsg = bytearray(vicExcSrdr.raw)
        excMsg.extend(vicHab.sanction(vicExcSrdr))

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
        assert dm[0]["id"] == schemer.said

        assert "verifiableCredential" in data
        vcs = data["verifiableCredential"]
        assert len(vcs) == 1

        proof = (
            "-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw"
            "-AxDNI7_ZmaI-AABAAQlH125aHYBnKH2shx6b0V2TFXfND1Omm8QonlDXJwhLDowNACRFBjpU9H1BKc5tqlWzrdgsR9r5S4YQEEioBCw"
        )

        assert vcs[0]["proof"] == proof


if __name__ == '__main__':
    test_issuing()
    test_proving()
