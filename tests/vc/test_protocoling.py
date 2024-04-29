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
    assert sidSalt == '0AAUiJMii_rPXXCiLTEEaDT7'
    wanSalt = core.Salter(raw=b'wann-the-witness').qb64
    assert wanSalt == '0AAUiJMii_rPXXCiLTEEaDT7'

    default_salt = core.Salter(raw=b'0123456789abcdef').qb64

    with (habbing.openHby(name="red", base="test", salt=default_salt) as redHby,
          habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby):
        seeder.seedSchema(redHby.db)
        seeder.seedSchema(sidHby.db)

        sidHab = sidHby.makeHab(name="test")
        sidPre = sidHab.pre
        assert sidPre == "EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"

        redHab = redHby.makeHab(name="test")
        redPre = redHab.pre
        assert redPre == "EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"

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

        assert creder.said == "EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH"

        iss = issuer.issue(said=creder.said)
        assert iss.raw == (b'{"v":"KERI10JSON0000ed_","t":"iss","d":"ECUw7AdWEE3fvr7dgbFDXj0CEZuJTTa_H8-i'
                           b'LLAmIUPO","i":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","s":"0","ri":"E'
                           b'B-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","dt":"2021-06-27T21:26:21.23325'
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
        assert msg == (b'{"v":"ACDC10JSON000197_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH",'
                       b'"i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJo'
                       b'AVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
                       b'","a":{"d":"EO9_6NattzsFiO8Fw1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-27T2'
                       b'1:26:21.233257+00:00","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LE'
                       b'I":"254900OPPU84GM83MG36"}}')

        atc = bytearray(msg)
        atc.extend(coring.Counter(coring.CtrDex.SealSourceTriples, count=1).qb64b)
        atc.extend(coring.Prefixer(qb64=iss.pre).qb64b)
        atc.extend(coring.Seqner(sn=0).qb64b)
        atc.extend(iss.saidb)

        assert atc == (b'{"v":"ACDC10JSON000197_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103'
                       b'V3-4E-ClXH","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","'
                       b'ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCn'
                       b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EO9_6NattzsFiO8F'
                       b'w1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-27T21:26:21.233257+0'
                       b'0:00","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"'
                       b'254900OPPU84GM83MG36"}}-IABEElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-'
                       b'4E-ClXH0AAAAAAAAAAAAAAAAAAAAAAAECUw7AdWEE3fvr7dgbFDXj0CEZuJTTa_H'
                       b'8-iLLAmIUPO')
        parsing.Parser().parseOne(ims=bytes(atc), vry=sidVer)

        # Successfully parsed credential is now saved in database.
        assert sidVer.reger.saved.get(keys=(creder.said,)) is not None

        ipexhan = protocoling.IpexHandler(resource="/ipex/apply", hby=sidHby, notifier=notifier)

        apply0, apply0atc = protocoling.ipexApplyExn(sidHab, message="Please give me a credential", schema=schema,
                                                     recp=redPre, attrs={})

        assert apply0.raw == (b'{"v":"KERI10JSON00016d_","t":"exn","d":"EIPeVB3u7L-mEKjhY6zIu5M7LErPwlUccxIN'
                              b'ddwhcFrH","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/apply","q":{},"a":{"m":"Please gi'
                              b've me a credential","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{'
                              b'},"i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"},"e":{}}')

        # No requirements for apply, except that its first, no `p`
        assert ipexhan.verify(serder=apply0) is True

        offer0, offer0atc = protocoling.ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply0)
        assert offer0.raw == (b'{"v":"KERI10JSON0002f0_","t":"exn","d":"EO4NXvOU-UpwwAR67txzKrFBHGAtDu9ehg8g'
                              b'Ic5haJy3","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"EIPeVB3u7L'
                              b'-mEKjhY6zIu5M7LErPwlUccxINddwhcFrH","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/offer","q":{},"a":{"m":"How about this"},"e":{"acdc":{"v":"ACDC10'
                              b'JSON000197_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","i":"EMl4Rhu'
                              b'R_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXe'
                              b'w8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"'
                              b'EO9_6NattzsFiO8Fw1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-27T21:26:21.2332'
                              b'57+00:00","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"254900OP'
                              b'PU84GM83MG36"}},"d":"EOG-KWyllXlb2HVIuewN1YJAOT304PaSczyt3V5Z878S"}}')

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
        assert spurn0.raw == (b'{"v":"KERI10JSON00011d_","t":"exn","d":"ENWl0Dd-9idlgrpkFL2aA0wfnuGHzvT4bHCN'
                              b'G6C0WBZk","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"EIPeVB3u7L'
                              b'-mEKjhY6zIu5M7LErPwlUccxINddwhcFrH","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')

        # This will fail, we've already responded with an offer
        assert ipexhan.verify(spurn0) is False

        # Now lets try an offer without a pointer back to a reply
        offer1, offer1atc = protocoling.ipexOfferExn(sidHab, "Here a credential offer", acdc=creder.raw)
        assert offer1.raw == (b'{"v":"KERI10JSON0002cd_","t":"exn","d":"ELnRdb-cA_rLckt9jwlSY-1nnPKwzRc4Up_7'
                              b'tCdzI12n","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/offer","q":{},"a":{"m":"Here a cr'
                              b'edential offer"},"e":{"acdc":{"v":"ACDC10JSON000197_","d":"EElymNmgs1u0mSaoC'
                              b'eOtSsNOROLuqOz103V3-4E-ClXH","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiU'
                              b'bl","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hat'
                              b'TNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EO9_6NattzsFiO8Fw1cxjYmDjOsKKSbootn'
                              b'-wXn9S3iB","dt":"2021-06-27T21:26:21.233257+00:00","i":"EMl4RhuR_JxpiMd1N8DE'
                              b'JEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"254900OPPU84GM83MG36"}},"d":"EOG-KWyllXlb2H'
                              b'VIuewN1YJAOT304PaSczyt3V5Z878S"}}')

        # Will work because it is starting a new conversation
        assert ipexhan.verify(serder=offer1) is True

        omsg = bytearray(offer1.raw)
        omsg.extend(offer1atc)
        parsing.Parser().parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer1.said,))
        assert serder.ked == offer1.ked

        agree, argeeAtc = protocoling.ipexAgreeExn(sidHab, "I'll accept that offer", offer=offer0)
        assert agree.raw == (b'{"v":"KERI10JSON000127_","t":"exn","d":"EEtu1OAPj03IdbhMwsQtgbJJaWgG2tdYLJ_3'
                             b'BuJQekdP","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"EO4NXvOU-U'
                             b'pwwAR67txzKrFBHGAtDu9ehg8gIc5haJy3","dt":"2021-06-27T21:26:21.233257+00:00",'
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
        assert grant0.raw == (b'{"v":"KERI10JSON000531_","t":"exn","d":"EC-EsfvXD2cNw4GNgCFp9UTl7_DgWUgk9Rnw'
                              b'eCxocaG-","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"","dt":"20'
                              b'21-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a":{"m":"Here\''
                              b's a credential","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"},"e":{"ac'
                              b'dc":{"v":"ACDC10JSON000197_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-Cl'
                              b'XH","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8'
                              b'PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gk'
                              b'k1kC","a":{"d":"EO9_6NattzsFiO8Fw1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-'
                              b'27T21:26:21.233257+00:00","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"'
                              b',"LEI":"254900OPPU84GM83MG36"}},"iss":{"v":"KERI10JSON0000ed_","t":"iss","d"'
                              b':"ECUw7AdWEE3fvr7dgbFDXj0CEZuJTTa_H8-iLLAmIUPO","i":"EElymNmgs1u0mSaoCeOtSsN'
                              b'OROLuqOz103V3-4E-ClXH","s":"0","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w'
                              b'9mQUQ","dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERI10JSON00013a'
                              b'_","t":"ixn","d":"EGhSHKIV5-nkeirdkqzqsvmeF1FXw_yH8NvPSAY1Rgyd","i":"EMl4Rhu'
                              b'R_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","s":"2","p":"ED1kkh5_ECYriK-j2gSv6Zjr'
                              b'5way88XVhwRCxk5zoTRG","a":[{"i":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClX'
                              b'H","s":"0","d":"ECUw7AdWEE3fvr7dgbFDXj0CEZuJTTa_H8-iLLAmIUPO"}]},"d":"EJ4-dl'
                              b'S9ktlb9HDWPYc0IJ2hS2NbvnCQBhUsFSkEPwIo"}}')

        assert ipexhan.verify(serder=grant0) is True

        # Lets save this bare offer so we can test full spurn workflow
        gmsg = bytearray(grant0.raw)
        gmsg.extend(grant0atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant0.said,))
        assert serder.ked == grant0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn1, spurn1atc = protocoling.ipexSpurnExn(sidHab, "I reject you", spurned=grant0)
        assert spurn1.raw == (b'{"v":"KERI10JSON00011d_","t":"exn","d":"EJA0LVnMxOdrOEArWudVtdonorCUa4nCIRgX'
                              b'vibhxdp3","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"EC-EsfvXD2'
                              b'cNw4GNgCFp9UTl7_DgWUgk9RnweCxocaG-","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')
        smsg = bytearray(spurn1.raw)
        smsg.extend(spurn1atc)
        parsing.Parser().parse(ims=smsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(spurn1.said,))
        assert serder.ked == spurn1.ked  # This credential grant has been spurned and not accepted into database

        # Now we'll run a grant pointing back to the agree all the way to the database
        grant1, grant1atc = protocoling.ipexGrantExn(sidHab, message="Here's a credential", acdc=msg, iss=iss.raw,
                                                     recp=sidHab.pre, anc=anc, agree=agree)
        assert grant1.raw == (b'{"v":"KERI10JSON00055d_","t":"exn","d":"EBAhSTTx3--xDZZRoCIemBzxybFV_FoicvPf'
                              b'4hSfeyAJ","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"EEtu1OAPj0'
                              b'3IdbhMwsQtgbJJaWgG2tdYLJ_3BuJQekdP","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/grant","q":{},"a":{"m":"Here\'s a credential","i":"EMl4RhuR_Jx'
                              b'piMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"},"e":{"acdc":{"v":"ACDC10JSON000197_","d"'
                              b':"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","i":"EMl4RhuR_JxpiMd1N8DEJEh'
                              b'TxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","'
                              b's":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EO9_6NattzsFiO8F'
                              b'w1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-27T21:26:21.233257+00:00","i":"E'
                              b'Ml4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"254900OPPU84GM83MG36"}},'
                              b'"iss":{"v":"KERI10JSON0000ed_","t":"iss","d":"ECUw7AdWEE3fvr7dgbFDXj0CEZuJTT'
                              b'a_H8-iLLAmIUPO","i":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","s":"0","'
                              b'ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","dt":"2021-06-27T21:26:21'
                              b'.233257+00:00"},"anc":{"v":"KERI10JSON00013a_","t":"ixn","d":"EGhSHKIV5-nkei'
                              b'rdkqzqsvmeF1FXw_yH8NvPSAY1Rgyd","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-'
                              b'tiUbl","s":"2","p":"ED1kkh5_ECYriK-j2gSv6Zjr5way88XVhwRCxk5zoTRG","a":[{"i":'
                              b'"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","s":"0","d":"ECUw7AdWEE3fvr7d'
                              b'gbFDXj0CEZuJTTa_H8-iLLAmIUPO"}]},"d":"EJ4-dlS9ktlb9HDWPYc0IJ2hS2NbvnCQBhUsFS'
                              b'kEPwIo"}}')
        assert ipexhan.verify(serder=grant1) is True

        gmsg = bytearray(grant1.raw)
        gmsg.extend(grant1atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant1.said,))
        assert serder.ked == grant1.ked

        # And now the last... admit the granted credential to complete the full flow
        admit0, admit0atc = protocoling.ipexAdmitExn(sidHab, "Thanks for the credential", grant=grant1)
        assert admit0.raw == (b'{"v":"KERI10JSON00012a_","t":"exn","d":"EDkQZpUOKKOzsQ50yoZxzLz8tDaChAid_llr'
                              b'QNvKVAdO","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","p":"EBAhSTTx3-'
                              b'-xDZZRoCIemBzxybFV_FoicvPf4hSfeyAJ","dt":"2021-06-27T21:26:21.233257+00:00",'
                              b'"r":"/ipex/admit","q":{},"a":{"m":"Thanks for the credential"},"e":{}}')
        assert ipexhan.verify(serder=admit0) is True

        amsg = bytearray(admit0.raw)
        amsg.extend(admit0atc)
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(admit0.said,))
        assert serder.ked == admit0.ked
