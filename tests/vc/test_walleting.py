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
                            typ=JSONSchema(resolver=cache))
        assert creder.said == "Eo_1yYIr2fb1dNx_0NBu7_cXt5S9uksUd78W0WD8DFS4"

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000135_","i":"Eo_1yYIr2fb1dNx_0NBu7_cXt5S9uksUd7'
            b'8W0WD8DFS4","x":"EBd67C13qqQcsJVxvBBOdasGIALYUIofv6xoedUj-438","'
            b'ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","d":{"i":"did'
            b':keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36'
            b'","issuanceDate":"2021-06-27T21:26:21.233257+00:00"}}-VA0-FABE4Y'
            b'PqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAA'
            b'AElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAA9JGgHDciYtbWJ'
            b'sWfv_vOulGL4yfg4EKBlqLaay9xS1C163mff9X-Z-6PD9pUM7KZeghQmU1y-xjBN'
            b'g1kY010CQ')
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

        sidWallet = Wallet(hab=sidHab, db=sidPDB)

        parseCredential(ims=msg, wallet=sidWallet, typ=JSONSchema(resolver=cache))

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert bytearray(sidPDB.getSers(key)) == ser

        # verify the signature
        sigs = sidPDB.getSigs(key)
        assert len(sigs) == 1
        assert bytearray(sigs[0]) == sig0

        # verify the seal
        sl = sidPDB.getSeals(key)
        assert sl == seal

        # verify we can look up credential by Schema SAID
        schema = sidPDB.getSchms(schemer.saider.qb64b)
        assert len(schema) == 1
        assert schema[0] == key


if __name__ == '__main__':
    test_wallet()
