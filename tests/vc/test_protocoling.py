# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""

from keri.app import habbing, signing, notifying
from keri.core import coring, scheming, eventing, parsing
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

        sidExc = exchanging.Exchanger(hby=sidHby, handlers=[])
        protocoling.loadHandlers(hby=sidHby, exc=sidExc, rgy=sidRgy, notifier=notifier)

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

        apply0, apply0atc = protocoling.ipexApplyExn(sidHab, "Please give me a credential", schema=schema, attrs={})
        assert apply0.raw == (b'{"v":"KERI10JSON00013a_","t":"exn","d":"ELTsAF3uujMxAsMaDuK_fovjTf6uhD7TDay4'
                              b'FYeF1HyS","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/apply","q":{},"a":{"m":"Please gi'
                              b've me a credential","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{'
                              b'}},"e":{}}')

        # No requirements for apply, except that its first, no `p`
        assert ipexhan.verify(serder=apply0) is True

        offer0, offer0atc = protocoling.ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply0)
        assert offer0.raw == (b'{"v":"KERI10JSON0002f0_","t":"exn","d":"EGoyRJ3CwXu_1npugrPb2RF19TfshnXfhM8y'
                              b'kAuEwIf5","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"ELTsAF3uuj'
                              b'MxAsMaDuK_fovjTf6uhD7TDay4FYeF1HyS","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/offer","q":{},"a":{"m":"How about this"},"e":{"acdc":{"v":"ACDC10'
                              b'JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","i":"EIaGMMW'
                              b'JFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGs'
                              b'jaXFOaO_kCfS4","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"'
                              b'EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T21:26:21.2332'
                              b'57+00:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OP'
                              b'PU84GM83MG36"}},"d":"EOVRKHUAEjvfyWzQ8IL4icBiaVuy_CSTse_W_AssaAeE"}}')

        # This should fail because it is not first and the apply isn't persisted yet
        assert ipexhan.verify(serder=offer0) is False

        # Now try to parse the offer before the apply, watch it fail
        omsg = bytearray(offer0.raw)
        omsg.extend(offer0atc)

        parsing.Parser().parse(ims=bytes(omsg), exc=sidExc)

        # Not saved because no apply
        assert sidHby.db.exns.get(keys=(offer0.said,)) is None

        amsg = bytearray(apply0.raw)
        amsg.extend(apply0atc)

        # Now parse both messages in order and both will save
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(apply0.said,))
        assert serder.ked == apply0.ked
        parsing.Parser().parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer0.said,))
        assert serder.ked == offer0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn0, spurn0atc = protocoling.ipexSpurnExn(sidHab, "I reject you", spurned=apply0)
        assert spurn0.raw == (b'{"v":"KERI10JSON00011d_","t":"exn","d":"EN6BXnp402214Uc_Q5AyjXHr-Rm2eUw0RWyO'
                              b'qZtIip4-","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"ELTsAF3uuj'
                              b'MxAsMaDuK_fovjTf6uhD7TDay4FYeF1HyS","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')

        # This will fail, we've already responded with an offer
        assert ipexhan.verify(spurn0) is False

        # Now lets try an offer without a pointer back to a reply
        offer1, offer1atc = protocoling.ipexOfferExn(sidHab, "Here a credential offer", acdc=creder.raw)
        assert offer1.raw == (b'{"v":"KERI10JSON0002cd_","t":"exn","d":"EMEmoi4k9gxWu4uZyYuEK3MvFPn-5B0LHnNx'
                              b'uQ4vRqRA","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/offer","q":{},"a":{"m":"Here a cr'
                              b'edential offer"},"e":{"acdc":{"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpem'
                              b'h_6xkaGNuoDsRU3qwvHdlvgfOyG","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDj'
                              b'I3","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCnVRk1hat'
                              b'TNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwch'
                              b'O9yylr3xx","dt":"2021-06-27T21:26:21.233257+00:00","i":"EIaGMMWJFPmtXznY1IIi'
                              b'KDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},"d":"EOVRKHUAEjvfyW'
                              b'zQ8IL4icBiaVuy_CSTse_W_AssaAeE"}}')

        # Will work because it is starting a new conversation
        assert ipexhan.verify(serder=offer1) is True

        omsg = bytearray(offer1.raw)
        omsg.extend(offer1atc)
        parsing.Parser().parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer1.said,))
        assert serder.ked == offer1.ked

        agree, argeeAtc = protocoling.ipexAgreeExn(sidHab, "I'll accept that offer", offer=offer0)
        assert agree.raw == (b'{"v":"KERI10JSON000127_","t":"exn","d":"ECDIZYM_le19AYxRef_jfkfHsdrlsiLWofA7'
                             b'LHrpFR43","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EGoyRJ3CwX'
                             b'u_1npugrPb2RF19TfshnXfhM8ykAuEwIf5","dt":"2021-06-27T21:26:21.233257+00:00",'
                             b'"r":"/ipex/agree","q":{},"a":{"m":"I\'ll accept that offer"},"e":{}}')

        # Can not create an agree without an offer, so this will pass since it has an offer that has no response
        assert ipexhan.verify(serder=agree) is True

        amsg = bytearray(agree.raw)
        amsg.extend(argeeAtc)
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(agree.said,))
        assert serder.ked == agree.ked

        # First try a bare grant (no prior agree)
        anc = sidHab.makeOwnEvent(sn=2)
        grant0, grant0atc = protocoling.ipexGrantExn(sidHab, "Here's a credential", acdc=msg, iss=iss.raw, anc=anc)
        assert grant0.raw == (b'{"v":"KERI10JSON0004fe_","t":"exn","d":"EE6csOli0VeioLJH5YtmU8U3fGIT4Id0J9xF'
                              b'NPZ4oURv","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a":{"m":"Here\''
                              b's a credential"},"e":{"acdc":{"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpem'
                              b'h_6xkaGNuoDsRU3qwvHdlvgfOyG","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDj'
                              b'I3","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCnVRk1hat'
                              b'TNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwch'
                              b'O9yylr3xx","dt":"2021-06-27T21:26:21.233257+00:00","i":"EIaGMMWJFPmtXznY1IIi'
                              b'KDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},"iss":{"v":"KERI10J'
                              b'SON0000ed_","t":"iss","d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3","i"'
                              b':"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0","ri":"EO0_SyqPS1-EVY'
                              b'SITakYpUHaUZZpZGsjaXFOaO_kCfS4","dt":"2021-06-27T21:26:21.233257+00:00"},"an'
                              b'c":{"v":"KERI10JSON00013a_","t":"ixn","d":"EOjAxp-AMLzicGz2h-DxvMK9kicajpZEw'
                              b'dN8-8k54hvz","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"2","p":'
                              b'"EGKglEgIpdHuhuwl-IiSDG9x094gMrRxVaXGgXvCzCYM","a":[{"i":"EDkftEwWBpohjTpemh'
                              b'_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0","d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9af'
                              b'qdCIZjMy3"}]},"d":"EI5mZXZ84Su4DrEUOxtl-NaUURQtTJeAn12xf146beg3"}}')

        assert ipexhan.verify(serder=grant0) is True

        # Lets save this bare offer so we can test full spurn workflow
        gmsg = bytearray(grant0.raw)
        gmsg.extend(grant0atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant0.said,))
        assert serder.ked == grant0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn1, spurn1atc = protocoling.ipexSpurnExn(sidHab, "I reject you", spurned=grant0)
        assert spurn1.raw == (b'{"v":"KERI10JSON00011d_","t":"exn","d":"EIIYc4NMfFjConU2eacUDljTxsKJ77biwkMw'
                              b'AfzkF_Yr","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EE6csOli0V'
                              b'eioLJH5YtmU8U3fGIT4Id0J9xFNPZ4oURv","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')
        smsg = bytearray(spurn1.raw)
        smsg.extend(spurn1atc)
        parsing.Parser().parse(ims=smsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(spurn1.said,))
        assert serder.ked == spurn1.ked  # This credential grant has been spurned and not accepted into database

        # Now we'll run a grant pointing back to the agree all the way to the database
        grant1, grant1atc = protocoling.ipexGrantExn(sidHab, "Here's a credential", acdc=msg, iss=iss.raw, anc=anc,
                                                     agree=agree)
        assert grant1.raw == (b'{"v":"KERI10JSON00052a_","t":"exn","d":"EKn9k1v27ZK8TyS-kEMzHNfpbRV1d-tUMbaZ'
                              b'Mtmx0aeF","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"ECDIZYM_le'
                              b'19AYxRef_jfkfHsdrlsiLWofA7LHrpFR43","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/grant","q":{},"a":{"m":"Here\'s a credential"},"e":{"acdc":{"v'
                              b'":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","i"'
                              b':"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYSITakYpU'
                              b'HaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","'
                              b'a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T21:2'
                              b'6:21.233257+00:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":'
                              b'"254900OPPU84GM83MG36"}},"iss":{"v":"KERI10JSON0000ed_","t":"iss","d":"EK2Wx'
                              b'cpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3","i":"EDkftEwWBpohjTpemh_6xkaGNuoDsR'
                              b'U3qwvHdlvgfOyG","s":"0","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERI10JSON00013a_","t":'
                              b'"ixn","d":"EOjAxp-AMLzicGz2h-DxvMK9kicajpZEwdN8-8k54hvz","i":"EIaGMMWJFPmtXz'
                              b'nY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"2","p":"EGKglEgIpdHuhuwl-IiSDG9x094gMrR'
                              b'xVaXGgXvCzCYM","a":[{"i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":'
                              b'"0","d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3"}]},"d":"EI5mZXZ84Su4D'
                              b'rEUOxtl-NaUURQtTJeAn12xf146beg3"}}')
        assert ipexhan.verify(serder=grant1) is True

        gmsg = bytearray(grant1.raw)
        gmsg.extend(grant1atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant1.said,))
        assert serder.ked == grant1.ked

        # And now the last... admit the granted credential to complete the full flow
        admit0, admit0atc = protocoling.ipexAdmitExn(sidHab, "Thanks for the credential", grant=grant1)
        assert admit0.raw == (b'{"v":"KERI10JSON00012a_","t":"exn","d":"EHdoJ4nxDPOcOPKkEvo5DO7zMECsnPcdw9iB'
                              b'uwh9YVNN","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EKn9k1v27Z'
                              b'K8TyS-kEMzHNfpbRV1d-tUMbaZMtmx0aeF","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/admit","q":{},"a":{"m":"Thanks for the credential"},"e":{}}')
        assert ipexhan.verify(serder=admit0) is True

        amsg = bytearray(admit0.raw)
        amsg.extend(admit0atc)
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(admit0.said,))
        assert serder.ked == admit0.ked


