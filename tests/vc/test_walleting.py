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
        assert creder.said == "E7z6kZDSxfg5InC9jOjUMtGi21ZM51o9TJ6cGmVjDngo"

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidReg.processEscrows()

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON00019e_","d":"E7z6kZDSxfg5InC9jOjUMtGi21ZM51o9TJ'
                       b'6cGmVjDngo","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","'
                       b'ri":"E2c3V7uJMRWNg13Jt1wwbwdutqozJF2m-Y3vd-cvIFfQ","s":"ExBYRwKd'
                       b'VGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","a":{"d":"EsxxFocfzQDzMX7F'
                       b'YU0jIbsacY0r3-7Ueve9reGOVakc","i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1v'
                       b'eiRNvDpBGF9Z1Pc","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"'
                       b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--FABECtWlHS2Wbx5M2Rg6n'
                       b'm69PCtzwb1veiRNvDpBGF9Z1Pc0AAAAAAAAAAAAAAAAAAAAAAAECtWlHS2Wbx5M2'
                       b'Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc-AABAAuTABhuLXGU8PwKoc5G9yH7yu2Uwa'
                       b'1OL3ln9e9IeorVS6Nyp7qVjADpZDCOCaFd5LNzgg_8CjsSQztJ7Zzjf1Bg')

        ser = (b'{"v":"ACDC10JSON00019e_","d":"E7z6kZDSxfg5InC9jOjUMtGi21ZM51o9TJ6cGmVjDngo",'
               b'"i":"ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","ri":"E2c3V7uJMRWNg13Jt1w'
               b'wbwdutqozJF2m-Y3vd-cvIFfQ","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI'
               b'","a":{"d":"EsxxFocfzQDzMX7FYU0jIbsacY0r3-7Ueve9reGOVakc","i":"ECtWlHS2Wbx5M'
               b'2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc","dt":"2021-06-27T21:26:21.233257+00:00","LE'
               b'I":"254900OPPU84GM83MG36"},"e":{}}')

        sig0 = (b'AAuTABhuLXGU8PwKoc5G9yH7yu2Uwa1OL3ln9e9IeorVS6Nyp7qVjADpZDCOCaFd5LNzgg_8CjsS'
                b'QztJ7Zzjf1Bg')

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
