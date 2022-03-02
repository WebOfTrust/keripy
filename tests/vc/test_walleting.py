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

    with habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby:
        sidHab = sidHby.makeHab(name="test")
        assert sidHab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        schema = "EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg"
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)

        verifier = verifying.Verifier(hby=sidHby)
        issuer = issuing.Issuer(hab=sidHab, reger=verifier.reger)
        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=credSubject,
                            status=issuer.regk)
        assert creder.said == "EyKc0_j73el3U8NhgFSV79g1K7MBOriOGyNNd_gu5Usw"

        issuer.issue(creder=creder)

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"EyKc0_j73el3U8NhgFSV79g1K7MBOriOGy'
                       b'NNd_gu5Usw","s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","'
                       b'i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"Ep8Q'
                       b'YVg3peYovtbtg-wVsA2bwV7qYpYjt3CsLY49Kqw4","i":"ECtWlHS2Wbx5M2Rg6'
                       b'nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36","ri":"EAZj_M7DRVHIYEnvkCwo20w_'
                       b'ZrjKR_ScNxHXO25Qus9s"},"p":[]}-JAB6AABAAA--FABECtWlHS2Wbx5M2Rg6n'
                       b'm69PCtzwb1veiRNvDpBGF9Z1Pc0AAAAAAAAAAAAAAAAAAAAAAAECtWlHS2Wbx5M2'
                       b'Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAApJuHxb31AX6fBwobpzt-0MjhPhI3'
                       b'Ert3Sqkwi3Xym0YArZi_2VL2-Fuw4rZpJegnpGMRaQcuY0Is4G4L79cnAg')

        ser = (b'{"v":"ACDC10JSON00019e_","d":"EyKc0_j73el3U8NhgFSV79g1K7MBOriOGyNNd_gu5Usw",'
               b'"s":"EIZPo6FxMZvZkX-463o9Og3a2NEKEJa-E9J5BXOsdpVg","i":"ECtWlHS2Wbx5M2Rg6nm6'
               b'9PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"Ep8QYVg3peYovtbtg-wVsA2bwV7qYpYjt3CsLY49'
               b'Kqw4","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","ri":"EAZj_M7DRVHIYEnvkCwo'
               b'20w_ZrjKR_ScNxHXO25Qus9s"},"p":[]}')

        sig0 = (b'AApJuHxb31AX6fBwobpzt-0MjhPhI3Ert3Sqkwi3Xym0YArZi_2VL2-Fuw4rZpJegnpGMRaQcuY0'
                b'Is4G4L79cnAg')

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
