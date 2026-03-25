# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""
from keri.core import (Salter, Counter, Seqner, Diger, Prefixer,
                       Parser, SealEvent, Codens)
from keri.kering import Vrsn_1_0
from keri.app import openHby

from keri.vc import credential
from keri.vdr import Verifier, Regery


def test_wallet(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    sidSalt = Salter(raw=b'0123456789abcdef').qb64

    with openHby(name="sid", base="test", salt=sidSalt) as sidHby:
        sidHab = sidHby.makeHab(name="test")
        seeder.seedSchema(db=sidHby.db)
        assert sidHab.pre == "EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
        credSubject = dict(
            LEI="254900OPPU84GM83MG36",
        )

        sidReg = Regery(hby=sidHby, name="bob", temp=True)
        verifier = Verifier(hby=sidHby, reger=sidReg.reger)
        issuer = sidReg.makeRegistry(prefix=sidHab.pre, name="bob")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal])
        seqner = Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=Diger(qb64=sidHab.kever.serder.said))
        sidReg.processEscrows()

        creder = credential(issuer=sidHab.pre,
                            recipient=sidHab.pre,
                            schema=schema,
                            data=credSubject,
                            status=issuer.regk)
        assert creder.said == "EAP1MTFwoSZ7P9Ym9yIqBvihjqZYpilpFpZj2oPTc7vM"

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal])
        seqner = Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=Diger(qb64=sidHab.kever.serder.said))
        sidReg.processEscrows()

        msg = bytearray(creder.raw)
        msg.extend(Counter(Codens.SealSourceTriples, count=1,
                                version=Vrsn_1_0).qb64b)
        msg.extend(Prefixer(qb64=iss.pre).qb64b)
        msg.extend(Seqner(sn=0).qb64b)
        msg.extend(iss.saidb)

        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EAP1MTFwoSZ7P9Ym9yIqBvihjqZYpilpFp'
                       b'Zj2oPTc7vM","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","'
                       b'ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCn'
                       b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EMyHBc5ZujkNFm9t'
                       b'nrwBU2nmp_qodcV4aDW28pwbDdgb","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ov'
                       b'vn9Xya8AN-tiUbl","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"'
                       b'254900OPPU84GM83MG36"}}-IABEAP1MTFwoSZ7P9Ym9yIqBvihjqZYpilpFpZj2'
                       b'oPTc7vM0AAAAAAAAAAAAAAAAAAAAAAAEAOV3Ie3yAvGU1MwbIHr816qewYzRLlvX'
                       b'NreKmXtJShe')

        ser = (b'{"v":"ACDC10JSON000197_","d":"EAP1MTFwoSZ7P9Ym9yIqBvihjqZYpilpFpZj2oPTc7vM",'
               b'"i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJo'
               b'AVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
               b'","a":{"d":"EMyHBc5ZujkNFm9tnrwBU2nmp_qodcV4aDW28pwbDdgb","i":"EMl4RhuR_Jxpi'
               b'Md1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","dt":"2021-06-27T21:26:21.233257+00:00","LE'
               b'I":"254900OPPU84GM83MG36"}}')

        Parser(version=Vrsn_1_0).parse(ims=msg, vry=verifier)

        # verify we can load serialized VC by SAID
        creder, *_ = verifier.reger.cloneCred(said=creder.said)
        assert creder.raw == ser
