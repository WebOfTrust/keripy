# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import keeping, habbing, signing
from keri.core import coring, scheming, parsing
from keri.db import basing
from keri.vc.proving import credential
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
        assert creder.said == "EQ7QPgGGZOKQHYCGp9Phm_EQzKHK1xMv_T9UwPhRwMBE"

        issuer.issue(creder=creder)

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"EQ7QPgGGZOKQHYCGp9Phm_EQzKHK1xMv_T'
                       b'9UwPhRwMBE","s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","'
                       b'i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","a":{"d":"EKEo'
                       b'g6cZnQv8kcaWJ02670LEKGVTIMzXdXYlXRc2B3Ws","i":"EPmpiN6bEM8EI0Mct'
                       b'ny-6AfglVOKnJje8-vqyKTlh0nc","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","ri":"ERAY2VjFALVZAAuC3GDM-36q'
                       b'KD8ZhUaKF55MWtITBFnc"},"p":[]}-JAB6AABAAA--FABEPmpiN6bEM8EI0Mctn'
                       b'y-6AfglVOKnJje8-vqyKTlh0nc0AAAAAAAAAAAAAAAAAAAAAAAEPmpiN6bEM8EI0'
                       b'Mctny-6AfglVOKnJje8-vqyKTlh0nc-AABAArws9pEH-d7eDwd847W2TzFrxCfuc'
                       b'rVxPC0AsEKpdcT4oWg3chxmdxydMNndFDFqSPSOnvsetBSLz_qYdPkG6Ag')

        ser = (b'{"v":"ACDC10JSON00019e_","d":"EQ7QPgGGZOKQHYCGp9Phm_EQzKHK1xMv_T9UwPhRwMBE",'
               b'"s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","i":"EPmpiN6bEM8EI0Mctny-'
               b'6AfglVOKnJje8-vqyKTlh0nc","a":{"d":"EKEog6cZnQv8kcaWJ02670LEKGVTIMzXdXYlXRc2'
               b'B3Ws","i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","ri":"ERAY2VjFALVZAAuC3GDM'
               b'-36qKD8ZhUaKF55MWtITBFnc"},"p":[]}')

        sig0 = (b'AArws9pEH-d7eDwd847W2TzFrxCfucrVxPC0AsEKpdcT4oWg3chxmdxydMNndFDFqSPSOnvsetBS'
                b'Lz_qYdPkG6Ag')

        parsing.Parser().parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        creder, sadsigers, sadcigars = verifier.reger.cloneCred(said=creder.said)
        assert creder.raw == ser

        # verify the signature
        assert len(sadsigers) == 1
        (_, _, _, _, sigers) = sadsigers[0]
        assert sigers[0].qb64b == sig0
        assert len(sadcigars) == 0

        # verify we can look up credential by Schema SAID
        schema = verifier.reger.schms.get(schema)
        assert len(schema) == 1
        assert schema[0].qb64 == creder.said

        if __name__ == '__main__':
            test_wallet()
