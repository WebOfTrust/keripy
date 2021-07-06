# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.vc.proving import credential
from keri.vc.walleting import Wallet, parseCredential, openPocket


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
                id=dict(
                    type="string"
                ),
                lei=dict(
                    type="string"
                )
            )
        ))

        schemer = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        credSubject = dict(
            id="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36"
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            issuance="2021-06-27T21:26:21.233257+00:00",
                            typ=JSONSchema(resolver=cache))

        assert creder.said == "EvK-hjgQCltc-jk_FZPOj4f3S6yEuNRpQcrVTfk1UsCQ"

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000189_","x":"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o",'
            b'"d":{"id":"EvK-hjgQCltc-jk_FZPOj4f3S6yEuNRpQcrVTfk1UsCQ","type":['
            b'"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o"],'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00","credentialSubject":{'
            b'"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
            b'"lei":"254900OPPU84GM83MG36"}}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAAsPhz4tfZGgoV'
            b'-1gYtvI1QfzSxwItp5JvguLhKnZE27px5q9fcKGPC0GkMlMBaRyfC47Db4zEWG6ceQ98g6dWDA')

        ser = (
            b'{"v":"KERI10JSON000189_","x":"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o",'
            b'"d":{"id":"EvK-hjgQCltc-jk_FZPOj4f3S6yEuNRpQcrVTfk1UsCQ","type":['
            b'"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o"],'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00","credentialSubject":{'
            b'"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
            b'"lei":"254900OPPU84GM83MG36"}}}')
        sig0 = (
            b'E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw'
            b'-AxDNI7_ZmaIAAsPhz4tfZGgoV-1gYtvI1QfzSxwItp5JvguLhKnZE27px5q9fcKGPC0GkMlMBaRyfC47Db4zEWG6ceQ98g6dWDA')
        sidWallet = Wallet(hab=sidHab, db=sidPDB)

        parseCredential(ims=msg, wallet=sidWallet, resolver=cache)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert sidPDB.getSers(key) == ser

        # verify the signature
        sigs = sidPDB.getSigs(key)
        assert len(sigs) == 1
        assert sigs[0] == sig0

        # verify we can look up credential by Schema SAID
        schema = sidPDB.getSchms(schemer.saider.qb64b)
        assert len(schema) == 1
        assert schema[0] == key


if __name__ == '__main__':
    test_wallet()
