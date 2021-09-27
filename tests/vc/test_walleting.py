# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.scheming import CacheResolver
from keri.db import basing
from keri.vc.proving import credential, parseCredential
from keri.vdr import verifying, issuing


def test_wallet():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS:
        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        assert sidHab.pre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"

        schema = "ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc"
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
            t=["VerifiableCredential", "GLEIFvLEICredential"]
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        verifier = verifying.Verifier(hab=sidHab)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)
        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=credSubject,
                            status=issuer.regk)
        assert creder.said == "EMAXNLGlyrwxhoO13a338ckhzDeXh2RAUWrghN3Kgj-o"

        issuer.issue(creder=creder)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON0001a5_","d":"EMAXNLGlyrwxhoO13a338ckhzDeXh2RAUW'
                       b'rghN3Kgj-o","s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","'
                       b'i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"","i'
                       b'":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","dt":"2021-06-2'
                       b'7T21:26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","t":["Veri'
                       b'fiableCredential","GLEIFvLEICredential"],"ri":"EGZHiBoV8v5tWAt7y'
                       b'eTTln-CuefIGPhajTT78Tt2r9M4"},"p":[]}-VA0-FABE4YPqsEOaPNaZxVIbY-'
                       b'Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2'
                       b'Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAA4GWiwgyf5lD2ihQuxYXu5MjMGQj9G'
                       b'KQ0W_yuq0T6BwzuwgncvYkh4baGS73zGHPhbHzV7M1Q8s92Cy56mco4Dw')

        ser = (b'{"v":"KERI10JSON0001a5_","d":"EMAXNLGlyrwxhoO13a338ckhzDeXh2RAUWrghN3Kgj-o",'
               b'"s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","i":"E4YPqsEOaPNaZxVIbY-G'
               b'x2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K'
               b'7pEE-YfcI9E","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"254900OPPU84GM83'
               b'MG36","t":["VerifiableCredential","GLEIFvLEICredential"],"ri":"EGZHiBoV8v5tW'
               b'At7yeTTln-CuefIGPhajTT78Tt2r9M4"},"p":[]}')

        sig0 = (b'AA4GWiwgyf5lD2ihQuxYXu5MjMGQj9GKQ0W_yuq0T6BwzuwgncvYkh4baGS73zGH'
                b'PhbHzV7M1Q8s92Cy56mco4Dw')

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
        print(prefixer.qb64b)
        print(seqner.qb64b)
        print(diger.qb64b)
        # assert sl == seal

        # verify we can look up credential by Schema SAID
        schema = verifier.reger.schms.get(schema)
        assert len(schema) == 1
        assert schema[0].qb64b == key

        if __name__ == '__main__':
            test_wallet()
