# -*- encoding: utf-8 -*-
"""
tests.vc.proving module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.coring import Serials
from keri.db import basing
from keri.help import helping
from keri.vc.proving import Credentialer, Credential


def test_proving():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS:
        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)

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

        schemer = scheming.Schemer(sed=sed, kind=scheming.SchemaTyps.JSONSchema, code=coring.MtrDex.Blake3_256)
        credSubject = dict(
            id="did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36"
        )

        cred = Credential(pre=sidHab.pre,
                          regk="",
                          schemer=schemer,
                          subject=credSubject,
                          issuance=helping.fromIso8601("2021-06-27T21:26:21.233257+00:00"))

        creder = Credentialer(crd=cred, kind=Serials.json)

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"vs":"KERI10JSON0001d0_","x":"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o",'
            b'"d":{"id":"ENnzo7pia_HZqlLhvtx7GDvj-_gzTcm9zXMZmvpka3qA","type":['
            b'"Et75h-slZaxkez1YDNpOxM6AF2YFMgcFL4C1ziAeFe3o"],'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00","credentialSubject":{'
            b'"id":"did:keri:did:keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36"},'
            b'"credentialStatus":{"id":"",'
            b'"type":"KERICredentialRegistry"}}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAATVGMCIJd'
            b'-VMSXRPD9_CtdWaKnUZ--wNxXqlN1lxFSohvMl1iWZl7EUdmR3pSAyLhmOgV0_xVqgsoxqBGZbZPAg')


if __name__ == '__main__':
    test_proving()
