# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""

from keri.app import habbing, signing
from keri.core import coring, parsing
from keri.core.eventing import SealEvent
from keri.vc.proving import credential
from keri.vdr import verifying, credentialing


def test_wallet(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby:
        sidHab = sidHby.makeHab(name="test")
        seeder.seedSchema(db=sidHby.db)
        assert sidHab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
        credSubject = dict(
            LEI="254900OPPU84GM83MG36",
        )

        sidReg = credentialing.Regery(hby=sidHby, name="bob", temp=True)
        verifier = verifying.Verifier(hby=sidHby, reger=sidReg.reger)
        issuer = sidReg.makeRegistry(prefix=sidHab.pre, name="bob")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidReg.processEscrows()

        creder = credential(issuer=sidHab.pre,
                            recipient=sidHab.pre,
                            schema=schema,
                            data=credSubject,
                            status=issuer.regk)
        assert creder.said == "EOavcpdGvk4sTXjOQiNxHeNf3HYMjMINMhar4R5a3OfB"

        iss = issuer.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidReg.processEscrows()

        msg = signing.ratify(sidHab, serder=creder)
        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EOavcpdGvk4sTXjOQiNxHeNf3HYMjMINMh'
                       b'ar4R5a3OfB","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","'
                       b'ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCn'
                       b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFKsAdq9CZF_w9yv'
                       b'ia8RiRdDeXLMjR6q7Lp7FKKIgJx-","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIy'
                       b'ge6mBl2QV8dDjI3","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"'
                       b'254900OPPU84GM83MG36"}}-JAB6AABAAA--FABEIaGMMWJFPmtXznY1IIiKDIrg'
                       b'-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1IIiK'
                       b'DIrg-vIyge6mBl2QV8dDjI3-AABAABrPJSGOU5oUGZjYHvgTo6dblTHX0yNq-SAC'
                       b'Uc3mgg68RspLkw2rCmXGpZuxnKN0spAzU3Wj0UN2C98Yrab1uYA')

        ser = (b'{"v":"ACDC10JSON000197_","d":"EOavcpdGvk4sTXjOQiNxHeNf3HYMjMINMhar4R5a3OfB",'
               b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYSITak'
               b'YpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
               b'","a":{"d":"EFKsAdq9CZF_w9yvia8RiRdDeXLMjR6q7Lp7FKKIgJx-","i":"EIaGMMWJFPmtX'
               b'znY1IIiKDIrg-vIyge6mBl2QV8dDjI3","dt":"2021-06-27T21:26:21.233257+00:00","LE'
               b'I":"254900OPPU84GM83MG36"}}')

        sig0 = (b'AABrPJSGOU5oUGZjYHvgTo6dblTHX0yNq-SACUc3mgg68RspLkw2rCmXGpZuxnKN0spAzU3Wj0UN'
                b'2C98Yrab1uYA')

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
