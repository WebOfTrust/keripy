# -*- encoding: utf-8 -*-
"""
tests.vc.protocoling module

"""
import pytest

from keri.kering import Vrsn_2_0, Vrsn_1_0, Kinds
from keri.core import (Salter, Counter, SealEvent, Seqner,
                       Diger, Prefixer, Saider, Parser,
                       Saids, MtrDex, Codens)

from keri.peer import Exchanger
from keri.vc import (IpexHandler, ipexAdmitExn, ipexOfferExn,
                     credential, loadHandlers, ipexApplyExn,
                     ipexSpurnExn, ipexAgreeExn, ipexGrantExn)

from keri.vdr import Regery, Verifier
from keri.app import Notifier, openHby



def test_ipex_version_overrides():
    with openHby(name="sid", base="test", salt=Salter(raw=b'0123456789abcdef').qb64,
                 version=Vrsn_1_0) as sidHby:
        sidHab = sidHby.makeHab(name="test", version=Vrsn_1_0, kind=Kinds.json)

        apply_v1, _ = ipexApplyExn(sidHab, recp=sidHab.pre, message="Please", schema="schema", attrs={})
        assert apply_v1.pvrsn == Vrsn_1_0
        assert "rp" in apply_v1.ked
        assert "ri" not in apply_v1.ked

        apply_v2, _ = ipexApplyExn(sidHab, recp=sidHab.pre, message="Please", schema="schema", attrs={},
                                   version=Vrsn_2_0)
        assert apply_v2.pvrsn == Vrsn_2_0
        assert "ri" in apply_v2.ked
        assert "rp" not in apply_v2.ked

        spurn_v2, _ = ipexSpurnExn(sidHab, "No thanks", spurned=apply_v2, version=Vrsn_2_0)
        assert spurn_v2.pvrsn == Vrsn_2_0
        assert "ri" in spurn_v2.ked
        assert "rp" not in spurn_v2.ked

        with pytest.raises(ValueError, match="version and pvrsn must match"):
            ipexApplyExn(sidHab, recp=sidHab.pre, message="Please", schema="schema", attrs={},
                         version=Vrsn_2_0, pvrsn=Vrsn_1_0)


def test_ipex_embedded_helpers_reject_v2_override():
    with openHby(name="sid", base="test", salt=Salter(raw=b'0123456789abcdef').qb64,
                 version=Vrsn_1_0) as sidHby:
        sidHab = sidHby.makeHab(name="test", version=Vrsn_1_0, kind=Kinds.json)

        with pytest.raises(ValueError, match="not supported in version 2 exchange"):
            ipexOfferExn(sidHab, "How about this", acdc=b"", version=Vrsn_2_0)

        with pytest.raises(ValueError, match="not supported in version 2 exchange"):
            ipexGrantExn(sidHab, recp=sidHab.pre, message="Here's a credential", acdc=b"",
                         version=Vrsn_2_0)


def test_ipex(seeder, mockCoringRandomNonce, mockHelpingNowIso8601, mockHelpingNowUTC):
    """ Test IPEX exchange protocol """

    sidSalt = Salter(raw=b'0123456789abcdef').qb64
    assert sidSalt == '0AAUiJMii_rPXXCiLTEEaDT7'
    wanSalt = Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0AAUiJMii_rPXXCiLTEEaDT7'

    default_salt = Salter(raw=b'0123456789abcdef').qb64

    with (openHby(name="red", base="test", salt=default_salt) as redHby,
          openHby(name="sid", base="test", salt=sidSalt) as sidHby):
        seeder.seedSchema(redHby.db)
        seeder.seedSchema(sidHby.db)

        sidHab = sidHby.makeHab(name="test")
        sidPre = sidHab.pre
        assert sidPre == "ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU"

        redHab = redHby.makeHab(name="test")
        redPre = redHab.pre
        assert redPre == "ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU"

        sidRgy = Regery(hby=sidHby, name="bob", temp=True)
        sidVer = Verifier(hby=sidHby, reger=sidRgy.reger)

        notifier = Notifier(hby=sidHby)
        issuer = sidRgy.makeRegistry(prefix=sidHab.pre, name="sid", version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        sidHab.interact(data=[rseal], framed=True)
        seqner = Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=Diger(qb64=sidHab.kever.serder.said))
        sidRgy.processEscrows()

        sidExc = Exchanger(hby=sidHby, handlers=[])
        loadHandlers(hby=sidHby, exc=sidExc, notifier=notifier)

        schema = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"

        # Build the credential subject and then the Creder for the full credential
        credSubject = dict(
            d="",
            i=sidHab.pre,
            dt="2021-06-27T21:26:21.233257+00:00",
            LEI="254900OPPU84GM83MG36"
        )
        _, d = Saider.saidify(sad=credSubject, code=MtrDex.Blake3_256, label=Saids.d)

        creder = credential(issuer=sidHab.pre,
                            schema=schema,
                            data=d,
                            status=issuer.regk,
                            version=Vrsn_1_0, kind=Kinds.json)

        assert creder.said == "EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT"

        iss = issuer.issue(said=creder.said)
        assert iss.raw == (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EODwJLBPj9PuHNOdDUu5dW8mij'
                           b'LIy6clX3S4z9M1QHMs","i":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al'
                           b'2wT","s":"0","ri":"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","'
                           b'dt":"2021-06-27T21:26:21.233257+00:00"}')
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        sidHab.interact(data=[rseal], framed=True)
        seqner = Seqner(sn=sidHab.kever.sn)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=Diger(qb64=sidHab.kever.serder.said))
        sidRgy.processEscrows()

        msg = creder.raw
        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97C'
                       b'NU_Al2wT","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri":'
                       b'"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1ha'
                       b'tTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EDn0F4rhEIzt_XMHdxGrGItX'
                       b'yLIJcZbShrU08k_l6F6C","dt":"2021-06-27T21:26:21.233257+00:00","i":'
                       b'"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","LEI":"254900OPPU84'
                       b'GM83MG36"}}')

        atc = bytearray(msg)
        atc.extend(Counter(Codens.SealSourceTriples, count=1, version=Vrsn_1_0).qb64b)
        atc.extend(Prefixer(qb64=iss.pre).qb64b)
        atc.extend(Seqner(sn=0).qb64b)
        atc.extend(iss.saidb)

        assert atc == (b'{"v":"ACDC10JSON000197_","d":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97C'
                       b'NU_Al2wT","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri":'
                       b'"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1ha'
                       b'tTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EDn0F4rhEIzt_XMHdxGrGItX'
                       b'yLIJcZbShrU08k_l6F6C","dt":"2021-06-27T21:26:21.233257+00:00","i":'
                       b'"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","LEI":"254900OPPU84'
                       b'GM83MG36"}}-IABEEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT0AAAAAA'
                       b'AAAAAAAAAAAAAAAAAEODwJLBPj9PuHNOdDUu5dW8mijLIy6clX3S4z9M1QHMs')
        Parser(version=Vrsn_1_0).parseOne(ims=bytes(atc), vry=sidVer)

        # Successfully parsed credential is now saved in database.
        assert sidVer.reger.saved.get(keys=(creder.said,)) is not None

        ipexhan = IpexHandler(resource="/ipex/apply", hby=sidHby, notifier=notifier)

        apply0, apply0atc = ipexApplyExn(sidHab, message="Please give me a credential", schema=schema,
                                                     recp=redPre, attrs={}, version=Vrsn_1_0)

        assert apply0.raw == (b'{"v":"KERI10JSON000175_","t":"exn","d":"EMbSyL0qygJ1YHq0aALzpPS0wS'
                              b'UkdYwN3kmSzcJEEQ6G","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"","dt":"2021-06-27T21:26:21.233257+00:00","r":"/'
                              b'ipex/apply","q":{},"a":{"m":"Please give me a credential","s":"EMQ'
                              b'WEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{},"i":"ELjNc3Rl8qO'
                              b'ewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU"},"e":{}}')

        # No requirements for apply, except that its first, no `p`
        assert ipexhan.verify(serder=apply0) is True

        offer0, offer0atc = ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply0,
                                                     version=Vrsn_1_0)
        assert offer0.raw == (b'{"v":"KERI10JSON0002f8_","t":"exn","d":"EEQ4H3BIHRpUeJmnF6G-McpLAx'
                              b'XREN0Cl2VjTUwYboW7","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"EMbSyL0qygJ1YHq0aALzpPS0wSUkdYwN3kmSzcJEEQ6G","d'
                              b't":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/offer","q":{},"a"'
                              b':{"m":"How about this"},"e":{"acdc":{"v":"ACDC10JSON000197_","d":"'
                              b'EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT","i":"ELjNc3Rl8qOewog'
                              b'6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri":"ELoFaRls3EQEXlGoUP-TAWtyKdTGY'
                              b'rPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
                              b'","a":{"d":"EDn0F4rhEIzt_XMHdxGrGItXyLIJcZbShrU08k_l6F6C","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGk'
                              b'pY93yvZ8n-EoJzU","LEI":"254900OPPU84GM83MG36"}},"d":"EMb9WKwwcn0qm'
                              b'TpKPjr5136Vj3hSsBa14-gLtZAjWvSF"}}')

        # This should fail because it is not first and the apply isn't persisted yet
        assert ipexhan.verify(serder=offer0) is False

        # Now try to parse the offer before the apply, watch it fail
        omsg = bytearray(offer0.raw)
        omsg.extend(offer0atc)

        Parser(version=Vrsn_1_0).parse(ims=bytes(omsg), exc=sidExc)

        # Not saved because no apply
        assert sidHby.db.exns.get(keys=(offer0.said,)) is None

        amsg = bytearray(apply0.raw)
        amsg.extend(apply0atc)

        # Now parse both messages in order and both will save
        Parser(version=Vrsn_1_0).parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(apply0.said,))
        assert serder.ked == apply0.ked
        Parser(version=Vrsn_1_0).parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer0.said,))
        assert serder.ked == offer0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn0, spurn0atc = ipexSpurnExn(sidHab, "I reject you", spurned=apply0, version=Vrsn_1_0)
        assert spurn0.raw == (b'{"v":"KERI10JSON000125_","t":"exn","d":"ENR5HIfRTLNL8JNCPfVSTYTbTi'
                              b'Q6_EA3kXq6s97GbE0r","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"EMbSyL0qygJ1YHq0aALzpPS0wSUkdYwN3kmSzcJEEQ6G","d'
                              b't":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/spurn","q":{},"a"'
                              b':{"m":"I reject you"},"e":{}}')

        # This will fail, we've already responded with an offer
        assert ipexhan.verify(spurn0) is False

        # Now lets try an offer without a pointer back to a reply
        offer1, offer1atc = ipexOfferExn(sidHab, "Here a credential offer", acdc=creder.raw,
                                                     version=Vrsn_1_0)
        assert offer1.raw == (b'{"v":"KERI10JSON0002d5_","t":"exn","d":"EIZWQLUy1g9rftMGlpZOxCv1zZ'
                              b'kVTm6u0IHbZ8FQfmQn","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"","dt":"2021-06-27T21:26:21.233257+00:00","r":"/'
                              b'ipex/offer","q":{},"a":{"m":"Here a credential offer"},"e":{"acdc"'
                              b':{"v":"ACDC10JSON000197_","d":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97'
                              b'CNU_Al2wT","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri"'
                              b':"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1h'
                              b'atTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EDn0F4rhEIzt_XMHdxGrGIt'
                              b'XyLIJcZbShrU08k_l6F6C","dt":"2021-06-27T21:26:21.233257+00:00","i"'
                              b':"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","LEI":"254900OPPU8'
                              b'4GM83MG36"}},"d":"EMb9WKwwcn0qmTpKPjr5136Vj3hSsBa14-gLtZAjWvSF"}}')

        # Will work because it is starting a new conversation
        assert ipexhan.verify(serder=offer1) is True

        omsg = bytearray(offer1.raw)
        omsg.extend(offer1atc)
        Parser(version=Vrsn_1_0).parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer1.said,))
        assert serder.ked == offer1.ked

        agree, argeeAtc = ipexAgreeExn(sidHab, "I'll accept that offer", offer=offer0,
                                                     version=Vrsn_1_0)
        assert agree.raw == (b'{"v":"KERI10JSON00012f_","t":"exn","d":"ECtn3Fs87PXIpFfMBfq2lIbBRX'
                             b'2aTdfe57jF7GsIsJkc","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                             b'JzU","rp":"","p":"EEQ4H3BIHRpUeJmnF6G-McpLAxXREN0Cl2VjTUwYboW7","d'
                             b't":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/agree","q":{},"a"'
                             b':{"m":"I\'ll accept that offer"},"e":{}}')

        # Can not create an agree without an offer, so this will pass since it has an offer that has no response
        assert ipexhan.verify(serder=agree) is True

        amsg = bytearray(agree.raw)
        amsg.extend(argeeAtc)
        Parser(version=Vrsn_1_0).parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(agree.said,))
        assert serder.ked == agree.ked

        # First try a bare grant (no prior agree)
        anc = sidHab.msgOwnEvent(sn=2, framed=True, gvrsn=Vrsn_1_0)
        grant0, grant0atc = ipexGrantExn(sidHab, message="Here's a credential", recp=sidHab.pre,
                                                     acdc=msg, iss=iss.raw, anc=anc, version=Vrsn_1_0)
        assert grant0.raw == (b'{"v":"KERI10JSON00053b_","t":"exn","d":"EEvdBb3bSXLChzPHYeFXwTcsbS'
                              b'j7qSiW74YlmuelEMH0","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"","dt":"2021-06-27T21:26:21.233257+00:00","r":"/'
                              b'ipex/grant","q":{},"a":{"m":"Here\'s a credential","i":"ELjNc3Rl8qO'
                              b'ewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU"},"e":{"acdc":{"v":"ACDC10JSON00'
                              b'0197_","d":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT","i":"ELj'
                              b'Nc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","ri":"ELoFaRls3EQEXlGoU'
                              b'P-TAWtyKdTGYrPsxnzPIuBTAhRD","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvaf'
                              b'X3bHQ9Gkk1kC","a":{"d":"EDn0F4rhEIzt_XMHdxGrGItXyLIJcZbShrU08k_l6F'
                              b'6C","dt":"2021-06-27T21:26:21.233257+00:00","i":"ELjNc3Rl8qOewog6W'
                              b'qqGuxFNziqGkpY93yvZ8n-EoJzU","LEI":"254900OPPU84GM83MG36"}},"iss":'
                              b'{"v":"KERI10JSON0000ed_","t":"iss","d":"EODwJLBPj9PuHNOdDUu5dW8mij'
                              b'LIy6clX3S4z9M1QHMs","i":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al'
                              b'2wT","s":"0","ri":"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","'
                              b'dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERICAACAAJSON'
                              b'AAE8.","t":"ixn","d":"EE1egcMCC-1_ntvVlCVrpCWXVc4DcsnXOW6ASXFZZZYB'
                              b'","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-EoJzU","s":"2","p":"'
                              b'EJ9ge2iXcEOSIpPwGuuTBNw72r55jvaXGMQKd4KS8rv0","a":[{"i":"EEWV8_6Cr'
                              b'lb0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT","s":"0","d":"EODwJLBPj9PuHNOd'
                              b'DUu5dW8mijLIy6clX3S4z9M1QHMs"}]},"d":"EFtAru-cgiPlJNPL0XbRpm9IVFoq'
                              b'q7BsYVZA6oQjEfwL"}}')

        assert ipexhan.verify(serder=grant0) is True

        # Lets save this bare offer so we can test full spurn workflow
        gmsg = bytearray(grant0.raw)
        gmsg.extend(grant0atc)
        Parser(version=Vrsn_1_0).parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant0.said,))
        assert serder.ked == grant0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn1, spurn1atc = ipexSpurnExn(sidHab, "I reject you", spurned=grant0, version=Vrsn_1_0)
        assert spurn1.raw == (b'{"v":"KERI10JSON000125_","t":"exn","d":"EEBEv85dHfSylM5gOMXU1LrtPY'
                              b'AHQLo0a_lPkaTByGVp","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"EEvdBb3bSXLChzPHYeFXwTcsbSj7qSiW74YlmuelEMH0","d'
                              b't":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/spurn","q":{},"a"'
                              b':{"m":"I reject you"},"e":{}}')
        smsg = bytearray(spurn1.raw)
        smsg.extend(spurn1atc)
        Parser(version=Vrsn_1_0).parse(ims=smsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(spurn1.said,))
        assert serder.ked == spurn1.ked  # This credential grant has been spurned and not accepted into database

        # Now we'll run a grant pointing back to the agree all the way to the database
        grant1, grant1atc = ipexGrantExn(sidHab, message="Here's a credential", acdc=msg, iss=iss.raw,
                                                     recp=sidHab.pre, anc=anc, agree=agree,
                                                     version=Vrsn_1_0)
        assert grant1.raw == (b'{"v":"KERI10JSON000567_","t":"exn","d":"ELUi1bAXcKPTxK-xnc15P8-CGs'
                              b'AIARki2v0XUvYiqCMi","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"ECtn3Fs87PXIpFfMBfq2lIbBRX2aTdfe57jF7GsIsJkc","d'
                              b't":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a"'
                              b':{"m":"Here\'s a credential","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93'
                              b'yvZ8n-EoJzU"},"e":{"acdc":{"v":"ACDC10JSON000197_","d":"EEWV8_6Crl'
                              b'b0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT","i":"ELjNc3Rl8qOewog6WqqGuxFNz'
                              b'iqGkpY93yvZ8n-EoJzU","ri":"ELoFaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuB'
                              b'TAhRD","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d"'
                              b':"EDn0F4rhEIzt_XMHdxGrGItXyLIJcZbShrU08k_l6F6C","dt":"2021-06-27T2'
                              b'1:26:21.233257+00:00","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-'
                              b'EoJzU","LEI":"254900OPPU84GM83MG36"}},"iss":{"v":"KERI10JSON0000ed'
                              b'_","t":"iss","d":"EODwJLBPj9PuHNOdDUu5dW8mijLIy6clX3S4z9M1QHMs","i'
                              b'":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZafk97CNU_Al2wT","s":"0","ri":"ELo'
                              b'FaRls3EQEXlGoUP-TAWtyKdTGYrPsxnzPIuBTAhRD","dt":"2021-06-27T21:26:'
                              b'21.233257+00:00"},"anc":{"v":"KERICAACAAJSONAAE8.","t":"ixn","d":"'
                              b'EE1egcMCC-1_ntvVlCVrpCWXVc4DcsnXOW6ASXFZZZYB","i":"ELjNc3Rl8qOewog'
                              b'6WqqGuxFNziqGkpY93yvZ8n-EoJzU","s":"2","p":"EJ9ge2iXcEOSIpPwGuuTBN'
                              b'w72r55jvaXGMQKd4KS8rv0","a":[{"i":"EEWV8_6Crlb0ysD9CDSoaCD0qIoQvZa'
                              b'fk97CNU_Al2wT","s":"0","d":"EODwJLBPj9PuHNOdDUu5dW8mijLIy6clX3S4z9'
                              b'M1QHMs"}]},"d":"EFtAru-cgiPlJNPL0XbRpm9IVFoqq7BsYVZA6oQjEfwL"}}')
        assert ipexhan.verify(serder=grant1) is True

        gmsg = bytearray(grant1.raw)
        gmsg.extend(grant1atc)
        Parser(version=Vrsn_1_0).parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant1.said,))
        assert serder.ked == grant1.ked

        # And now the last... admit the granted credential to complete the full flow
        admit0, admit0atc = ipexAdmitExn(sidHab, "Thanks for the credential", grant=grant1,
                                                     version=Vrsn_1_0)
        assert admit0.raw == (b'{"v":"KERI10JSON000132_","t":"exn","d":"EFq3bV9N1Dp4r6FPMRB5vi44pA'
                              b'uj8n-8CPMB7fgG8e4I","i":"ELjNc3Rl8qOewog6WqqGuxFNziqGkpY93yvZ8n-Eo'
                              b'JzU","rp":"","p":"ELUi1bAXcKPTxK-xnc15P8-CGsAIARki2v0XUvYiqCMi","d'
                              b't":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/admit","q":{},"a"'
                              b':{"m":"Thanks for the credential"},"e":{}}')
        assert ipexhan.verify(serder=admit0) is True

        amsg = bytearray(admit0.raw)
        amsg.extend(admit0atc)
        Parser(version=Vrsn_1_0).parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(admit0.said,))
        assert serder.ked == admit0.ked
