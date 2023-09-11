# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""

from keri.app import habbing, signing, notifying
from keri.core import coring, scheming, eventing
from keri.core.eventing import SealEvent
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vc.proving import credential
from keri.vdr import verifying, credentialing


def test_ipex(seeder, mockCoringRandomNonce, mockHelpingNowIso8601, mockHelpingNowUTC):
    """ Test IPEX exchange protocol """

    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
    wanSalt = coring.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0AB3YW5uLXRoZS13aXRuZXNz'

    with (habbing.openHby(name="red", base="test") as redHby,
          habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby):

        seeder.seedSchema(redHby.db)
        seeder.seedSchema(sidHby.db)

        sidHab = sidHby.makeHab(name="test")
        sidPre = sidHab.pre
        assert sidPre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        redHab = redHby.makeHab(name="test")
        redPre = redHab.pre
        assert redPre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        redKvy = eventing.Kevery(db=redHby.db)
        redRgy = credentialing.Regery(hby=redHby, name="red", temp=True)
        redVer = verifying.Verifier(hby=redHby, reger=redRgy.reger)

        sidRgy = credentialing.Regery(hby=sidHby, name="bob", temp=True)
        sidVer = verifying.Verifier(hby=sidHby, reger=sidRgy.reger)

        notifier = notifying.Notifier(hby=sidHby)
        issuer = sidRgy.makeRegistry(prefix=sidHab.pre, name="sid")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidRgy.processEscrows()

        redExc = exchanging.Exchanger(hby=redHby, handlers=[])
        protocoling.loadHandlers(hby=redHby, exc=redExc, rgy=redRgy, notifier=notifier)

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"

        # Build the credential subject and then the Creder for the full credential
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36",
        )
        _, d = scheming.Saider.saidify(sad=credSubject, code=coring.MtrDex.Blake3_256, label=scheming.Saids.d)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            data=d,
                            status=issuer.regk)

        assert creder.said == "EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG"

        iss = issuer.issue(said=creder.said)
        assert iss.raw == (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afq'
                           b'dCIZjMy3","i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0","ri":"E'
                           b'O0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","dt":"2021-06-27T21:26:21.23325'
                           b'7+00:00"}')
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=sidHab.kever.serder.saider)
        sidRgy.processEscrows()

        msg = signing.ratify(sidHab, serder=creder, pipelined=True)
        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qw'
                       b'vHdlvgfOyG","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","'
                       b'ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCn'
                       b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EF2__B6DiLQHpdJZ'
                       b'_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T21:26:21.233257+0'
                       b'0:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"'
                       b'254900OPPU84GM83MG36"}}-VA3-JAB6AABAAA--FABEIaGMMWJFPmtXznY1IIiK'
                       b'DIrg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1'
                       b'IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAAV9Rag13NGlWcPLxwDLRCXGpPVt80L8'
                       b'ocwi7op4rRPYkRv3XN8tX88N630cdR2ndQu74xScCcb0reEh33dwvkB')

        ipexhan = protocoling.IpexHandler(resource="/ipex/apply", hby=sidHby, rgy=sidRgy, notifier=notifier)

        apply, atc0 = protocoling.ipexApplyExn(sidHab, "Please give me a credential", schema=schema, attrs={})
        assert apply.raw == (b'{"v":"KERI10JSON00013a_","t":"exn","d":"ELTsAF3uujMxAsMaDuK_fovjTf6uhD7TDay4'
                             b'FYeF1HyS","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"","dt":"20'
                             b'21-06-27T21:26:21.233257+00:00","r":"/ipex/apply","q":{},"a":{"m":"Please gi'
                             b've me a credential","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{'
                             b'}},"e":{}}')

        assert ipexhan.verify(serder=apply) is True

        offer, atc1 = protocoling.ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply)
        assert offer.raw == (b'{"v":"KERI10JSON0002f0_","t":"exn","d":"EGoyRJ3CwXu_1npugrPb2RF19TfshnXfhM8y'
                             b'kAuEwIf5","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"ELTsAF3uuj'
                             b'MxAsMaDuK_fovjTf6uhD7TDay4FYeF1HyS","dt":"2021-06-27T21:26:21.233257+00:00",'
                             b'"r":"/ipex/offer","q":{},"a":{"m":"How about this"},"e":{"acdc":{"v":"ACDC10'
                             b'JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","i":"EIaGMMW'
                             b'JFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGs'
                             b'jaXFOaO_kCfS4","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"'
                             b'EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T21:26:21.2332'
                             b'57+00:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OP'
                             b'PU84GM83MG36"}},"d":"EOVRKHUAEjvfyWzQ8IL4icBiaVuy_CSTse_W_AssaAeE"}}')




