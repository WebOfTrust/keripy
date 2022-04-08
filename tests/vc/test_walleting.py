# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import habbing, signing
from keri.core import coring, scheming, parsing
from keri.core.eventing import SealEvent
from keri.vc.proving import credential
from keri.vdr import verifying, credentialing


def test_wallet(seeder, mockCoringRandomNonce):
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
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidReg.processEscrows()

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            subject=credSubject,
                            status=issuer.regk)
        assert creder.said == "ERI5wqoIen5LnXvoSWMPuuy2xBQaKLJc9icDlqwboD0U"

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidReg.processEscrows()

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"ERI5wqoIen5LnXvoSWMPuuy2xBQaKLJc9i'
                       b'cDlqwboD0U","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                       b'i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"Esxx'
                       b'FocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGOVakc","i":"ECtWlHS2Wbx5M2Rg6'
                       b'nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21:26:21.233257+00'
                       b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"E2c3V7uJMRWNg13J'
                       b't1wwbwdutqozJF2m-Y3vd-cvIFfQ"}-JAB6AABAAA--FABECtWlHS2Wbx5M2Rg6n'
                       b'm69PCtzwb1veiRNvDpBGF9Z1Pc0AAAAAAAAAAAAAAAAAAAAAAAECtWlHS2Wbx5M2'
                       b'Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAbJ3URQNQ12x8mtr3OdhvaVlvloA_'
                       b'DrExLKjBj-RwWk4WLQZQntIn5hHvcK1Lgs5w8Ba9hXvUPds-PCgS1WHoBQ')

        ser = (b'{"v":"ACDC10JSON00019e_","d":"ERI5wqoIen5LnXvoSWMPuuy2xBQaKLJc9icDlqwboD0U",'
               b'"s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","i":"ECtWlHS2Wbx5M2Rg6nm6'
               b'9PCtzwb1veiRNvDpBGF9Z1Pc","a":{"d":"EsxxFocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGO'
               b'Vakc","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21'
               b':26:21.233257+00:00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"E2c3V7uJMRWN'
               b'g13Jt1wwbwdutqozJF2m-Y3vd-cvIFfQ"}')

        sig0 = (b'AAbJ3URQNQ12x8mtr3OdhvaVlvloA_DrExLKjBj-RwWk4WLQZQntIn5hHvcK1Lgs5w8Ba9hXvUPd'
                b's-PCgS1WHoBQ')

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
