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
        assert creder.said == "EXiDN1cDrhCa0e0X6HqvRyJzsY3kvOgFgvPgGLX3kzWU"

        issuer.issue(creder=creder)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON0001d1_","d":"EXiDN1cDrhCa0e0X6HqvRyJzsY3kvOgFgv'
                       b'PgGLX3kzWU","s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","'
                       b'i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"Ee3U'
                       b'KTz6rAIG_tkvDl1V0ZKtrm-b8ettPH-3CZNYX4dI","i":"E4YPqsEOaPNaZxVIb'
                       b'Y-Gx2bJgP-c7AH_K7pEE-YfcI9E","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","t":["VerifiableCredential","G'
                       b'LEIFvLEICredential"],"ri":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78'
                       b'Tt2r9M4"},"p":[]}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-Y'
                       b'fcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-Ax'
                       b'DNI7_ZmaI-AABAATwkSDRzoQHlIIUwNg8OXSekA1yDZj9xVljzPSnUp0JXMgDsCj'
                       b'mG15IHGk_G0yRZU72NISiF8szGHbrzFhEmFDg')

        ser = (b'{"v":"KERI10JSON0001d1_","d":"EXiDN1cDrhCa0e0X6HqvRyJzsY3kvOgFgvPgGLX3kzWU",'
               b'"s":"ES63gXI-FmM6yQ7ISVIH__hOEhyE6W6-Ev0cArldsxuc","i":"E4YPqsEOaPNaZxVIbY-G'
               b'x2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"Ee3UKTz6rAIG_tkvDl1V0ZKtrm-b8ettPH-3CZNY'
               b'X4dI","i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","t":["VerifiableCredential'
               b'","GLEIFvLEICredential"],"ri":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4"'
               b'},"p":[]}')

        sig0 = (b'AATwkSDRzoQHlIIUwNg8OXSekA1yDZj9xVljzPSnUp0JXMgDsCjmG15IHGk_G0yR'
                b'ZU72NISiF8szGHbrzFhEmFDg')

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
