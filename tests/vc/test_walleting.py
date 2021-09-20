# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.vc.proving import credential, parseCredential
from keri.vc.walleting import Wallet, openPocket
from keri.vdr import verifying


def test_wallet():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS, \
            openPocket(name="sid") as sidPDB:
        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        assert sidHab.pre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"

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
        credSubject = dict(
            i="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            status="ExZ1DwY7cH7dmU9JOMRlPc1GtCPfH93inM5Z_A5LpgO4",
                            typ=JSONSchema(resolver=cache))
        assert creder.said == "EUl89Yt0yhlFQCSEZkj1SRu3feeZNVlBh9efrZYu8FQI"

        msg = sidHab.endorse(serder=creder)
        print(msg)
        assert msg == (
            b'{"v":"KERI10JSON000169_","i":"EUl89Yt0yhlFQCSEZkj1SRu3feeZNVlBh9efrZYu8FQI",'
            b'"x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"d":{"i":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00"},'
            b'"ri":"ExZ1DwY7cH7dmU9JOMRlPc1GtCPfH93inM5Z_A5LpgO4"}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
            b'-AABAAfo38WK3jqUq74PdamFhEBgXDQ7QEx8sFhRM8m6TXskNRJLlMiMh-ZYYYHf0VdRGYu3TRXBJAMJ6e1CX4YTwdDg')

        ser = (
        b'{"v":"KERI10JSON000135_","i":"Eo_1yYIr2fb1dNx_0NBu7_cXt5S9uksUd7'
        b'8W0WD8DFS4","x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","'
        b'ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","d":{"i":"did'
        b':keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36'
        b'","issuanceDate":"2021-06-27T21:26:21.233257+00:00"}}')
        seal = (
        b'E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw'
        b'-AxDNI7_ZmaI')

        sig0 = (
        b'AA9JGgHDciYtbWJsWfv_vOulGL4yfg4EKBlqLaay9xS1C163mff9X-Z-6PD9pUM7'b'KZeghQmU1y-xjBNg1kY010CQ')

        verifier = verifying.Verifier(hab=sidHab)
        sidWallet = Wallet(verifier=verifier, db=sidPDB)

        parseCredential(ims=msg, verifier=sidWallet, typ=JSONSchema(resolver=cache))

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert sidPDB.creds.get(key).raw == ser

        # verify the signature
        seals = sidPDB.seals.get(keys=key)
        assert len(seals) == 1
        (prefixer, seqner, diger, siger) = seals[0]

        assert bytearray(siger.qb64b) == sig0
        # verify the seal
        print(prefixer.qb64b)
        print(seqner.qb64b)
        print(diger.qb64b)
        # assert sl == seal

        # verify we can look up credential by Schema SAID
        schema = sidPDB.schms.get(schemer.saider.qb64b)
        assert len(schema) == 1
        assert schema[0].qb64b == key

        if __name__ == '__main__':
            test_wallet()
