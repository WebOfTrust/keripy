# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""

from keri import core
from keri.core import coring, scheming, parsing
from keri.core.eventing import SealEvent

from keri.peer import exchanging
from keri.vc import protocoling
from keri.vc.proving import credential
from keri.vdr import credentialing, verifying
from keri.app import habbing, notifying


def test_ipex(seeder, mockCoringRandomNonce, mockHelpingNowIso8601, mockHelpingNowUTC):
    """ Test IPEX exchange protocol """

    sidSalt = core.Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
    wanSalt = core.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0AB3YW5uLXRoZS13aXRuZXNz'

    default_salt = core.Salter(raw=b'0123456789abcdef').qb64

    with (habbing.openHby(name="red", base="test", salt=default_salt) as redHby,
          habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby):
        seeder.seedSchema(redHby.db)
        seeder.seedSchema(sidHby.db)

        sidHab = sidHby.makeHab(name="test")
        sidPre = sidHab.pre
        assert sidPre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        redHab = redHby.makeHab(name="test")
        redPre = redHab.pre
        assert redPre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"

        sidRgy = credentialing.Regery(hby=sidHby, name="bob", temp=True)
        sidVer = verifying.Verifier(hby=sidHby, reger=sidRgy.reger)

        notifier = notifying.Notifier(hby=sidHby)
        issuer = sidRgy.makeRegistry(prefix=sidHab.pre, name="sid")
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal])
        seqner = coring.Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=sidHab.kever.serder.said))
        sidRgy.processEscrows()

        sidExc = exchanging.Exchanger(hby=sidHby, handlers=[])
        protocoling.loadHandlers(hby=sidHby, exc=sidExc, notifier=notifier)

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
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=coring.Saider(qb64=sidHab.kever.serder.said))
        sidRgy.processEscrows()

        msg = creder.raw
        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG",'
                       b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYSITak'
                       b'YpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
                       b'","a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T2'
                       b'1:26:21.233257+00:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LE'
                       b'I":"254900OPPU84GM83MG36"}}')

        atc = bytearray(msg)
        atc.extend(coring.Counter(coring.CtrDex.SealSourceTriples, count=1).qb64b)
        atc.extend(coring.Prefixer(qb64=iss.pre).qb64b)
        atc.extend(coring.Seqner(sn=0).qb64b)
        atc.extend(iss.saidb)

        assert atc == (b'{"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qw'
                       b'vHdlvgfOyG","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","'
                       b'ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCn'
                       b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EF2__B6DiLQHpdJZ'
                       b'_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T21:26:21.233257+0'
                       b'0:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"'
                       b'254900OPPU84GM83MG36"}}-IABEDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHd'
                       b'lvgfOyG0AAAAAAAAAAAAAAAAAAAAAAAEK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9'
                       b'afqdCIZjMy3')
        parsing.Parser().parseOne(ims=bytes(atc), vry=sidVer)

        # Successfully parsed credential is now saved in database.
        assert sidVer.reger.saved.get(keys=(creder.said,)) is not None

        ipexhan = protocoling.IpexHandler(resource="/ipex/apply", hby=sidHby, notifier=notifier)

        apply0, apply0atc = protocoling.ipexApplyExn(sidHab, message="Please give me a credential", schema=schema,
                                                     recp=redPre, attrs={})

        assert apply0.raw == (b'{"v":"KERI10JSON00016d_","t":"exn","d":"EI1MnUrT0aUprMN97FabgJdxVQtoCPqamVUp'
                              b'3iFgnDBE","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/apply","q":{},"a":{"m":"Please gi'
                              b've me a credential","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{'
                              b'},"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"},"e":{}}')

        # No requirements for apply, except that its first, no `p`
        assert ipexhan.verify(serder=apply0) is True

        offer0, offer0atc = protocoling.ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply0)
        assert offer0.raw == (b'{"v":"KERI10JSON0002f0_","t":"exn","d":"EO_wiH5ZEikfLQb8rKBjPATnjiSOHGBvvN3m'
                              b'F0LDvaIC","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EI1MnUrT0a'
                              b'UprMN97FabgJdxVQtoCPqamVUp3iFgnDBE","dt":"2021-06-27T21:26:21.233257+00:00",'
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
        assert spurn0.raw == (b'{"v":"KERI10JSON00011d_","t":"exn","d":"EKvtmxPkOklgRNgWxLj-1ZW4Zb0MwZIUloWx'
                              b'A_dam95r","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EI1MnUrT0a'
                              b'UprMN97FabgJdxVQtoCPqamVUp3iFgnDBE","dt":"2021-06-27T21:26:21.233257+00:00",'
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
        assert agree.raw == (b'{"v":"KERI10JSON000127_","t":"exn","d":"EGpJ9S0TqIVHkRmDsbgP59NC8ZLCaSUirslB'
                             b'KDeYKOR7","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EO_wiH5ZEi'
                             b'kfLQb8rKBjPATnjiSOHGBvvN3mF0LDvaIC","dt":"2021-06-27T21:26:21.233257+00:00",'
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
        grant0, grant0atc = protocoling.ipexGrantExn(sidHab, message="Here's a credential", recp=sidHab.pre,
                                                     acdc=msg, iss=iss.raw, anc=anc)
        assert grant0.raw == (b'{"v":"KERI10JSON000531_","t":"exn","d":"EJxM3em5fSpAIQsyXYovrr0UjblWLtmbTnFp'
                              b'xAUqnwG-","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a":{"m":"Here\''
                              b's a credential","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"},"e":{"ac'
                              b'dc":{"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfO'
                              b'yG","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYS'
                              b'ITakYpUHaUZZpZGsjaXFOaO_kCfS4","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gk'
                              b'k1kC","a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-'
                              b'27T21:26:21.233257+00:00","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"'
                              b',"LEI":"254900OPPU84GM83MG36"}},"iss":{"v":"KERI10JSON0000ed_","t":"iss","d"'
                              b':"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3","i":"EDkftEwWBpohjTpemh_6xka'
                              b'GNuoDsRU3qwvHdlvgfOyG","s":"0","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_'
                              b'kCfS4","dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERI10JSON00013a'
                              b'_","t":"ixn","d":"EOjAxp-AMLzicGz2h-DxvMK9kicajpZEwdN8-8k54hvz","i":"EIaGMMW'
                              b'JFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"2","p":"EGKglEgIpdHuhuwl-IiSDG9x'
                              b'094gMrRxVaXGgXvCzCYM","a":[{"i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOy'
                              b'G","s":"0","d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3"}]},"d":"EI5mZX'
                              b'Z84Su4DrEUOxtl-NaUURQtTJeAn12xf146beg3"}}')

        assert ipexhan.verify(serder=grant0) is True

        # Lets save this bare offer so we can test full spurn workflow
        gmsg = bytearray(grant0.raw)
        gmsg.extend(grant0atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant0.said,))
        assert serder.ked == grant0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn1, spurn1atc = protocoling.ipexSpurnExn(sidHab, "I reject you", spurned=grant0)
        assert spurn1.raw == (b'{"v":"KERI10JSON00011d_","t":"exn","d":"EEs0bIGplWsjSOw5BMhAdFmgv-jm3-4nPgcK'
                              b'-LDv8tdB","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EJxM3em5fS'
                              b'pAIQsyXYovrr0UjblWLtmbTnFpxAUqnwG-","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')
        smsg = bytearray(spurn1.raw)
        smsg.extend(spurn1atc)
        parsing.Parser().parse(ims=smsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(spurn1.said,))
        assert serder.ked == spurn1.ked  # This credential grant has been spurned and not accepted into database

        # Now we'll run a grant pointing back to the agree all the way to the database
        grant1, grant1atc = protocoling.ipexGrantExn(sidHab, message="Here's a credential", acdc=msg, iss=iss.raw,
                                                     recp=sidHab.pre, anc=anc, agree=agree)
        assert grant1.raw == (b'{"v":"KERI10JSON00055d_","t":"exn","d":"EIqh-L9GnnVSdNLeqwmx-vpE9V1DvOQAlVWf'
                              b'wENpm8sW","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EGpJ9S0TqI'
                              b'VHkRmDsbgP59NC8ZLCaSUirslBKDeYKOR7","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/grant","q":{},"a":{"m":"Here\'s a credential","i":"EIaGMMWJFPm'
                              b'tXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"},"e":{"acdc":{"v":"ACDC10JSON000197_","d"'
                              b':"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","i":"EIaGMMWJFPmtXznY1IIiKDI'
                              b'rg-vIyge6mBl2QV8dDjI3","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","'
                              b's":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EF2__B6DiLQHpdJZ'
                              b'_C0bddxy2o6nXIHEwchO9yylr3xx","dt":"2021-06-27T21:26:21.233257+00:00","i":"E'
                              b'IaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},'
                              b'"iss":{"v":"KERI10JSON0000ed_","t":"iss","d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYh'
                              b'JL9afqdCIZjMy3","i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0","'
                              b'ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4","dt":"2021-06-27T21:26:21'
                              b'.233257+00:00"},"anc":{"v":"KERI10JSON00013a_","t":"ixn","d":"EOjAxp-AMLzicG'
                              b'z2h-DxvMK9kicajpZEwdN8-8k54hvz","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8'
                              b'dDjI3","s":"2","p":"EGKglEgIpdHuhuwl-IiSDG9x094gMrRxVaXGgXvCzCYM","a":[{"i":'
                              b'"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0","d":"EK2WxcpF3oL1yqS3'
                              b'Z8i08WDYkHDcYhJL9afqdCIZjMy3"}]},"d":"EI5mZXZ84Su4DrEUOxtl-NaUURQtTJeAn12xf1'
                              b'46beg3"}}')
        assert ipexhan.verify(serder=grant1) is True

        gmsg = bytearray(grant1.raw)
        gmsg.extend(grant1atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant1.said,))
        assert serder.ked == grant1.ked

        # And now the last... admit the granted credential to complete the full flow
        admit0, admit0atc = protocoling.ipexAdmitExn(sidHab, "Thanks for the credential", grant=grant1)
        assert admit0.raw == (b'{"v":"KERI10JSON00012a_","t":"exn","d":"ELNz82kqV94vlbT7lJulVFWtf6_jhGRgH556'
                              b'Z-xYRaGY","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","p":"EIqh-L9Gnn'
                              b'VSdNLeqwmx-vpE9V1DvOQAlVWfwENpm8sW","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/admit","q":{},"a":{"m":"Thanks for the credential"},"e":{}}')
        assert ipexhan.verify(serder=admit0) is True

        amsg = bytearray(admit0.raw)
        amsg.extend(admit0atc)
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(admit0.said,))
        assert serder.ked == admit0.ked
