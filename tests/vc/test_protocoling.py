# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""

from keri.app import habbing, notifying
from keri.core import coring, scheming, parsing
from keri.core.eventing import SealEvent
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vc.proving import credential
from keri.vdr import credentialing, verifying


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

        assert apply0.raw == (b'{"v":"KERI10JSON000175_","t":"exn","d":"EK9Q7n1y-Rlf-A7-T0uWSKuOlHZHBy_4zVaNp60GxXEr",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"","p":"",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/apply","q":{},"a":{"m":"Please '
                              b'give me a credential","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{},'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"},"e":{}}')

        # No requirements for apply, except that its first, no `p`
        assert ipexhan.verify(serder=apply0) is True

        offer0, offer0atc = protocoling.ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply0)
        assert offer0.raw == (b'{"v":"KERI10JSON0002f8_","t":"exn","d":"ED-uXbt7hRH3cmQY9vtwmcPOGvdmPEq_bnQ4sgQK9KhB",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"",'
                              b'"p":"EK9Q7n1y-Rlf-A7-T0uWSKuOlHZHBy_4zVaNp60GxXEr",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/offer","q":{},"a":{"m":"How about '
                              b'this"},"e":{"acdc":{"v":"ACDC10JSON000197_",'
                              b'"d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3",'
                              b'"ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",'
                              b'"a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},'
                              b'"d":"EOVRKHUAEjvfyWzQ8IL4icBiaVuy_CSTse_W_AssaAeE"}}')

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
        assert spurn0.raw == (b'{"v":"KERI10JSON000125_","t":"exn","d":"EP9mGfCLrVs-A2KiSwruQ8bdQVlPIiIFZ2t4f6Dj4gnc",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"",'
                              b'"p":"EK9Q7n1y-Rlf-A7-T0uWSKuOlHZHBy_4zVaNp60GxXEr",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/spurn","q":{},"a":{"m":"I reject '
                              b'you"},"e":{}}')

        # This will fail, we've already responded with an offer
        assert ipexhan.verify(spurn0) is False

        # Now lets try an offer without a pointer back to a reply
        offer1, offer1atc = protocoling.ipexOfferExn(sidHab, "Here a credential offer", acdc=creder.raw)
        assert offer1.raw == (b'{"v":"KERI10JSON0002d5_","t":"exn","d":"EJC9_GH0TeYJ3_cyutkS1gZfcgaGUQnk3v7F_gwJShVM",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"","p":"",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/offer","q":{},"a":{"m":"Here a '
                              b'credential offer"},"e":{"acdc":{"v":"ACDC10JSON000197_",'
                              b'"d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3",'
                              b'"ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",'
                              b'"a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},'
                              b'"d":"EOVRKHUAEjvfyWzQ8IL4icBiaVuy_CSTse_W_AssaAeE"}}')

        # Will work because it is starting a new conversation
        assert ipexhan.verify(serder=offer1) is True

        omsg = bytearray(offer1.raw)
        omsg.extend(offer1atc)
        parsing.Parser().parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer1.said,))
        assert serder.ked == offer1.ked

        agree, argeeAtc = protocoling.ipexAgreeExn(sidHab, "I'll accept that offer", offer=offer0)
        assert agree.raw == (b'{"v":"KERI10JSON00012f_","t":"exn","d":"ELLFpKUv8qt6UKaNFj2_s-3Hs1vFeRgWdq_LIQm2HEER",'
                             b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"",'
                             b'"p":"ED-uXbt7hRH3cmQY9vtwmcPOGvdmPEq_bnQ4sgQK9KhB",'
                             b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/agree","q":{},"a":{"m":"I\'ll '
                             b'accept that offer"},"e":{}}')

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
        assert grant0.raw == (b'{"v":"KERI10JSON000539_","t":"exn","d":"EBXaaGfKREvo3UbvNEtgTiZySHe71tTU4-ZmcFETVdn8",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"","p":"",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a":{"m":"Here\'s a '
                              b'credential","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"},"e":{"acdc":{'
                              b'"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3",'
                              b'"ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",'
                              b'"a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},'
                              b'"iss":{"v":"KERI10JSON0000ed_","t":"iss",'
                              b'"d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3",'
                              b'"i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0",'
                              b'"ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERI10JSON00013a_","t":"ixn",'
                              b'"d":"EOjAxp-AMLzicGz2h-DxvMK9kicajpZEwdN8-8k54hvz",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"2",'
                              b'"p":"EGKglEgIpdHuhuwl-IiSDG9x094gMrRxVaXGgXvCzCYM",'
                              b'"a":[{"i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0",'
                              b'"d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3"}]},'
                              b'"d":"EI5mZXZ84Su4DrEUOxtl-NaUURQtTJeAn12xf146beg3"}}')

        assert ipexhan.verify(serder=grant0) is True

        # Lets save this bare offer so we can test full spurn workflow
        gmsg = bytearray(grant0.raw)
        gmsg.extend(grant0atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant0.said,))
        assert serder.ked == grant0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn1, spurn1atc = protocoling.ipexSpurnExn(sidHab, "I reject you", spurned=grant0)
        assert spurn1.raw == (b'{"v":"KERI10JSON000125_","t":"exn","d":"EIoMDwEvyR4j43W5Hh9CyJ4ttwNHlrmABwyUvKHhF9mp",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"",'
                              b'"p":"EBXaaGfKREvo3UbvNEtgTiZySHe71tTU4-ZmcFETVdn8",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/spurn","q":{},"a":{"m":"I reject '
                              b'you"},"e":{}}')
        smsg = bytearray(spurn1.raw)
        smsg.extend(spurn1atc)
        parsing.Parser().parse(ims=smsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(spurn1.said,))
        assert serder.ked == spurn1.ked  # This credential grant has been spurned and not accepted into database

        # Now we'll run a grant pointing back to the agree all the way to the database
        grant1, grant1atc = protocoling.ipexGrantExn(sidHab, message="Here's a credential", acdc=msg, iss=iss.raw,
                                                     recp=sidHab.pre, anc=anc, agree=agree)
        assert grant1.raw == (b'{"v":"KERI10JSON000565_","t":"exn","d":"ENy1ktZHowD73mn0vJL-xpTzCDpa4RuISZldAZImiKD_",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"",'
                              b'"p":"ELLFpKUv8qt6UKaNFj2_s-3Hs1vFeRgWdq_LIQm2HEER",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a":{"m":"Here\'s a '
                              b'credential","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"},"e":{"acdc":{'
                              b'"v":"ACDC10JSON000197_","d":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3",'
                              b'"ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",'
                              b'"a":{"d":"EF2__B6DiLQHpdJZ_C0bddxy2o6nXIHEwchO9yylr3xx",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","LEI":"254900OPPU84GM83MG36"}},'
                              b'"iss":{"v":"KERI10JSON0000ed_","t":"iss",'
                              b'"d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3",'
                              b'"i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0",'
                              b'"ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERI10JSON00013a_","t":"ixn",'
                              b'"d":"EOjAxp-AMLzicGz2h-DxvMK9kicajpZEwdN8-8k54hvz",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","s":"2",'
                              b'"p":"EGKglEgIpdHuhuwl-IiSDG9x094gMrRxVaXGgXvCzCYM",'
                              b'"a":[{"i":"EDkftEwWBpohjTpemh_6xkaGNuoDsRU3qwvHdlvgfOyG","s":"0",'
                              b'"d":"EK2WxcpF3oL1yqS3Z8i08WDYkHDcYhJL9afqdCIZjMy3"}]},'
                              b'"d":"EI5mZXZ84Su4DrEUOxtl-NaUURQtTJeAn12xf146beg3"}}')
        assert ipexhan.verify(serder=grant1) is True

        gmsg = bytearray(grant1.raw)
        gmsg.extend(grant1atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant1.said,))
        assert serder.ked == grant1.ked

        # And now the last... admit the granted credential to complete the full flow
        admit0, admit0atc = protocoling.ipexAdmitExn(sidHab, "Thanks for the credential", grant=grant1)
        assert admit0.raw == (b'{"v":"KERI10JSON000132_","t":"exn","d":"EAnQEaL-jSGK22VSbPN7WAUWVcxJ9LV8S5fORVAqVQzN",'
                              b'"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","rp":"",'
                              b'"p":"ENy1ktZHowD73mn0vJL-xpTzCDpa4RuISZldAZImiKD_",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/admit","q":{},"a":{"m":"Thanks for '
                              b'the credential"},"e":{}}')
        assert ipexhan.verify(serder=admit0) is True

        amsg = bytearray(admit0.raw)
        amsg.extend(admit0atc)
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(admit0.said,))
        assert serder.ked == admit0.ked
