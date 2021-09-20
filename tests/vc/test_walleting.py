# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.vc.proving import credential, parseCredential
from keri.vc.walleting import Wallet
from keri.vdr import verifying, issuing


def test_wallet():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS:
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
            si=sidHab.pre,
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        verifier = verifying.Verifier(hab=sidHab)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)
        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            status=issuer.regk,
                            typ=JSONSchema(resolver=cache))
        assert creder.said == "Ex0ZAYFw-qxq2bu6VKONQ_HAuCIqQ9A1Xg_KHpp4QPJA"

        issuer.issue(creder=creder)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON00019d_","i":"Ex0ZAYFw-qxq2bu6VKONQ_HAuCIqQ9A1Xg'
                       b'_KHpp4QPJA","x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","'
                       b'ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","d":{"i":"did'
                       b':keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36'
                       b'","issuanceDate":"2021-06-27T21:26:21.233257+00:00","si":"E4YPqs'
                       b'EOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"},"ri":"EGZHiBoV8v5tWAt7y'
                       b'eTTln-CuefIGPhajTT78Tt2r9M4"}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-'
                       b'c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBb'
                       b'UNTBYzLYw-AxDNI7_ZmaI-AABAA8oHIocMqPToMOis7nNGq6w2RLToxduHjcuqo9'
                       b'MNmRMGzSrvAAFZ4dDc0pmM5btB5E_3Th1zanT12vAZHMgatDA')

        ser = (b'{"v":"KERI10JSON00019d_","i":"Ex0ZAYFw-qxq2bu6VKONQ_HAuCIqQ9A1Xg_KHpp4QPJA",'
               b'"x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","ti":"E4YPqsEOaPNaZxVIbY-'
               b'Gx2bJgP-c7AH_K7pEE-YfcI9E","d":{"i":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v"'
               b',"lei":"254900OPPU84GM83MG36","issuanceDate":"2021-06-27T21:26:21.233257+00:'
               b'00","si":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"},"ri":"EGZHiBoV8v5tW'
               b'At7yeTTln-CuefIGPhajTT78Tt2r9M4"}')

        sig0 = (b'AA8oHIocMqPToMOis7nNGq6w2RLToxduHjcuqo9MNmRMGzSrvAAFZ4dDc0pmM5bt'
                b'B5E_3Th1zanT12vAZHMgatDA')

        parseCredential(ims=msg, verifier=verifier, typ=JSONSchema(resolver=cache))

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert verifier.reger.creds.get(key).raw == ser

        # verify the signature
        seals = verifier.reger.seals.get(keys=key)
        assert len(seals) == 1
        (prefixer, seqner, diger, siger) = seals[0]

        assert bytearray(siger.qb64b) == sig0
        # verify the seal
        print(prefixer.qb64b)
        print(seqner.qb64b)
        print(diger.qb64b)
        # assert sl == seal

        # verify we can look up credential by Schema SAID
        schema = verifier.reger.schms.get(schemer.saider.qb64b)
        assert len(schema) == 1
        assert schema[0].qb64b == key

        if __name__ == '__main__':
            test_wallet()
