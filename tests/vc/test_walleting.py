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
        assert sidHab.pre == "EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc"

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
        assert creder.said == "EGB4nGODlCPWJ2hKNwf7OowxNkotRZMZ3XaN0GGw-aVQ"

        issuer.issue(creder=creder)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON00019e_","d":"EGB4nGODlCPWJ2hKNwf7OowxNkotRZMZ3X'
                       b'aN0GGw-aVQ","s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","'
                       b'i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","a":{"d":"EKEo'
                       b'g6cZnQv8kcaWJ02670LEKGVTIMzXdXYlXRc2B3Ws","i":"EPmpiN6bEM8EI0Mct'
                       b'ny-6AfglVOKnJje8-vqyKTlh0nc","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","ri":"ERAY2VjFALVZAAuC3GDM-36q'
                       b'KD8ZhUaKF55MWtITBFnc"},"p":[]}-VA0-FABEPmpiN6bEM8EI0Mctny-6AfglV'
                       b'OKnJje8-vqyKTlh0nc0AAAAAAAAAAAAAAAAAAAAAAAEPmpiN6bEM8EI0Mctny-6A'
                       b'fglVOKnJje8-vqyKTlh0nc-AABAAaAW_sKvkNqYRtJjTPr3CdaTULDufko1ScBEp'
                       b'H2WO14Xu5zZisw9cgJV5ZIAaJx3JJ-zMd8sLpkKXYyrZQuB4Dg')

        ser = (b'{"v":"KERI10JSON00019e_","d":"EGB4nGODlCPWJ2hKNwf7OowxNkotRZMZ3XaN0GGw-aVQ",'
               b'"s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","i":"EPmpiN6bEM8EI0Mctny-'
               b'6AfglVOKnJje8-vqyKTlh0nc","a":{"d":"EKEog6cZnQv8kcaWJ02670LEKGVTIMzXdXYlXRc2'
               b'B3Ws","i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","ri":"ERAY2VjFALVZAAuC3GDM'
               b'-36qKD8ZhUaKF55MWtITBFnc"},"p":[]}')

        sig0 = (b'AAaAW_sKvkNqYRtJjTPr3CdaTULDufko1ScBEpH2WO14Xu5zZisw9cgJV5ZIAaJx'
                b'3JJ-zMd8sLpkKXYyrZQuB4Dg')

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
