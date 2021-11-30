# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.db import basing
from keri.vc.proving import credential, parseCredential
from keri.vdr import verifying, issuing


def test_wallet():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS:
        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        assert sidHab.pre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"

        schema = "EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg"
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        verifier = verifying.Verifier(hab=sidHab)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)
        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=credSubject,
                            status=issuer.regk)
        assert creder.said == "EdVcIiMggOn14NQGaZos_jpE2pXxer-AvKpMLlwDxIls"

        issuer.issue(creder=creder)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON00019e_","d":"EdVcIiMggOn14NQGaZos_jpE2pXxer-AvK'
                       b'pMLlwDxIls","s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","'
                       b'i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"ENVs'
                       b'WQ93HnvS7G4fIQiA_fR8DNGu66v8fqSdJw_PYcF0","i":"E4YPqsEOaPNaZxVIb'
                       b'Y-Gx2bJgP-c7AH_K7pEE-YfcI9E","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","ri":"EGZHiBoV8v5tWAt7yeTTln-C'
                       b'uefIGPhajTT78Tt2r9M4"},"p":[]}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP'
                       b'-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNB'
                       b'bUNTBYzLYw-AxDNI7_ZmaI-AABAAwt0BCpOWyDsP34Gz6cGDpaPho7QOSP4wo7yA'
                       b'JLUEfGGltGqI__wsyvJtGUyNod8bxKFwIXJKGzgLI9-7ZGVrAQ')

        ser = (b'{"v":"KERI10JSON00019e_","d":"EdVcIiMggOn14NQGaZos_jpE2pXxer-AvKpMLlwDxIls",'
               b'"s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","i":"E4YPqsEOaPNaZxVIbY-G'
               b'x2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"ENVsWQ93HnvS7G4fIQiA_fR8DNGu66v8fqSdJw_P'
               b'YcF0","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","ri":"EGZHiBoV8v5tWAt7yeTT'
               b'ln-CuefIGPhajTT78Tt2r9M4"},"p":[]}')

        sig0 = (b'AAwt0BCpOWyDsP34Gz6cGDpaPho7QOSP4wo7yAJLUEfGGltGqI__wsyvJtGUyNod'
                b'8bxKFwIXJKGzgLI9-7ZGVrAQ')

        parseCredential(ims=msg, verifier=verifier)

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert verifier.reger.creds.get(key).raw == ser

        # verify the signature
        seals = verifier.reger.seals.get(keys=key)
        assert len(seals) == 1
        (prefixer, seqner, diger, siger) = seals[0]

        assert bytearray(siger.qb64b) == sig0
        # verify the seal
        # assert sl == seal

        # verify we can look up credential by Schema SAID
        schema = verifier.reger.schms.get(schema)
        assert len(schema) == 1
        assert schema[0].qb64b == key

        if __name__ == '__main__':
            test_wallet()
