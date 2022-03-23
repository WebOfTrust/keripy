# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import habbing, signing
from keri.core import coring, scheming, parsing
from keri.vc.proving import credential
from keri.vdr import verifying, issuing


def test_wallet(seeder):
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby:
        sidHab = sidHby.makeHab(name="test")
        seeder.seedSchema(db=sidHby.db)
        assert sidHab.pre == "ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc"

        schema = "ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI"
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
        assert creder.said == "EQs_g_jNSWpMahPxekWx_JybJIB_38UR81-ZdpeJffSQ"

        issuer.issue(creder=creder)

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"EQs_g_jNSWpMahPxekWx_JybJIB_38UR81'
                       b'-ZdpeJffSQ","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                       b'i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"Esxx'
                       b'FocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGOVakc","i":"ECtWlHS2Wbx5M2Rg6'
                       b'nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EAZj_M7DRVHIYEnv'
                       b'kCwo20w_ZrjKR_ScNxHXO25Qus9s"}-JAB6AABAAA--FABECtWlHS2Wbx5M2Rg6n'
                       b'm69PCtzwb1veiRNvDpBGF9Z1Pc0AAAAAAAAAAAAAAAAAAAAAAAECtWlHS2Wbx5M2'
                       b'Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAPcSjtmSlf1xQYHOofy_4YQ8sqnfj'
                       b'jiy15Hgn4if5H7dE4SL8cAoOWcCkPwlmtA0SnH-jkYu86hfbt1usYft8Dw')

        ser = (b'{"v":"ACDC10JSON00019e_","d":"EQs_g_jNSWpMahPxekWx_JybJIB_38UR81-ZdpeJffSQ",'
               b'"s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","i":"ECtWlHS2Wbx5M2Rg6nm6'
               b'9PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"EsxxFocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGO'
               b'Vakc","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EAZj_M7DRVHI'
               b'YEnvkCwo20w_ZrjKR_ScNxHXO25Qus9s"}')

        sig0 = (b'AAPcSjtmSlf1xQYHOofy_4YQ8sqnfjjiy15Hgn4if5H7dE4SL8cAoOWcCkPwlmtA0SnH-jkYu86h'
                b'fbt1usYft8Dw')

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
