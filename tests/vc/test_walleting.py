# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import habbing, signing
from keri.core import coring, scheming, parsing
from keri.vc.proving import credential
from keri.vdr import verifying, credentialing


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

        sidReg = credentialing.Regery(hby=sidHby, name="bob", temp=True)
        verifier = verifying.Verifier(hby=sidHby, reger=sidReg.reger)
        issuer = sidReg.makeRegistry(prefix=sidHab.pre, name="bob")

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=credSubject,
                            status=issuer.regk)
        assert creder.said == "ExSVOeBWj2tyveO82NuNRtdO-Q_vP9IPMIbG6XHI2maU"

        issuer.issue(creder=creder)

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"ExSVOeBWj2tyveO82NuNRtdO-Q_vP9IPMI'
                       b'bG6XHI2maU","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                       b'i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"Esxx'
                       b'FocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGOVakc","i":"ECtWlHS2Wbx5M2Rg6'
                       b'nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EjPXk1a_MtWR3a0q'
                       b'rZiJ34c971FxiHyCZSRo6482KPDs"}-JAB6AABAAA--FABECtWlHS2Wbx5M2Rg6n'
                       b'm69PCtzwb1veiRNvDpBGF9Z1Pc0AAAAAAAAAAAAAAAAAAAAAAAECtWlHS2Wbx5M2'
                       b'Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAaqEfopwPfH7YvoomsVdH_skpryE2'
                       b'jcgngirS4p8ysWjt9kB0UF34hofJfxSqNezjtQ34a_qc-B-U9jrtVvx1Bw')

        ser = (b'{"v":"ACDC10JSON00019e_","d":"ExSVOeBWj2tyveO82NuNRtdO-Q_vP9IPMIbG6XHI2maU",'
               b'"s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","i":"ECtWlHS2Wbx5M2Rg6nm6'
               b'9PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"EsxxFocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGO'
               b'Vakc","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EjPXk1a_MtWR'
               b'3a0qrZiJ34c971FxiHyCZSRo6482KPDs"}')

        sig0 = (b'AAaqEfopwPfH7YvoomsVdH_skpryE2jcgngirS4p8ysWjt9kB0UF34hofJfxSqNezjtQ34a_qc-B'
                b'-U9jrtVvx1Bw')

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
