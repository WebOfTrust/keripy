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

        assert apply0.raw == (b'{"v":"KERI10JSON000175_","t":"exn","d":"EHVK5cO32UQJCkpK9RqRP_ONViK8u3JNXn73'
                              b'nJ8hdmXr","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/apply","q":{},"a":{"m":"P'
                              b'lease give me a credential","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1k'
                              b'C","a":{},"i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"},"e":{}}')

        # No requirements for apply, except that its first, no `p`
        assert ipexhan.verify(serder=apply0) is True

        offer0, offer0atc = protocoling.ipexOfferExn(sidHab, "How about this", acdc=creder.raw, apply=apply0)
        assert offer0.raw == (b'{"v":"KERI10JSON0002f8_","t":"exn","d":"ENdVOCsP5Xz57qs1xa_msznozvBs6Ii0_JRo'
                              b'i6tp2NBu","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"EH'
                              b'VK5cO32UQJCkpK9RqRP_ONViK8u3JNXn73nJ8hdmXr","dt":"2021-06-27T21:26:21.233257'
                              b'+00:00","r":"/ipex/offer","q":{},"a":{"m":"How about this"},"e":{"acdc":{"v"'
                              b':"ACDC10JSON000197_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","i":'
                              b'"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJoAVHv'
                              b'5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a'
                              b'":{"d":"EO9_6NattzsFiO8Fw1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-27T21:26'
                              b':21.233257+00:00","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"'
                              b'254900OPPU84GM83MG36"}},"d":"EOG-KWyllXlb2HVIuewN1YJAOT304PaSczyt3V5Z878S"}}')

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
        assert spurn0.raw == (b'{"v":"KERI10JSON000125_","t":"exn","d":"EHijfrof83z7JeFR-wJO9Ptgl-PieQHhKC-F'
                              b'bZIDvGvM","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"EH'
                              b'VK5cO32UQJCkpK9RqRP_ONViK8u3JNXn73nJ8hdmXr","dt":"2021-06-27T21:26:21.233257'
                              b'+00:00","r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')

        # This will fail, we've already responded with an offer
        assert ipexhan.verify(spurn0) is False

        # Now lets try an offer without a pointer back to a reply
        offer1, offer1atc = protocoling.ipexOfferExn(sidHab, "Here a credential offer", acdc=creder.raw)
        assert offer1.raw == (b'{"v":"KERI10JSON0002d5_","t":"exn","d":"EC8fiu3IoCex-7uhTskkEodJOiQYQpO61l3Y'
                              b'HCXWuuFi","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/offer","q":{},"a":{"m":"H'
                              b'ere a credential offer"},"e":{"acdc":{"v":"ACDC10JSON000197_","d":"EElymNmgs'
                              b'1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xy'
                              b'a8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcC'
                              b'nVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EO9_6NattzsFiO8Fw1cxjYmDjOs'
                              b'KKSbootn-wXn9S3iB","dt":"2021-06-27T21:26:21.233257+00:00","i":"EMl4RhuR_Jxp'
                              b'iMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"254900OPPU84GM83MG36"}},"d":"EOG-KW'
                              b'yllXlb2HVIuewN1YJAOT304PaSczyt3V5Z878S"}}')

        # Will work because it is starting a new conversation
        assert ipexhan.verify(serder=offer1) is True

        omsg = bytearray(offer1.raw)
        omsg.extend(offer1atc)
        parsing.Parser().parse(ims=omsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(offer1.said,))
        assert serder.ked == offer1.ked

        agree, argeeAtc = protocoling.ipexAgreeExn(sidHab, "I'll accept that offer", offer=offer0)
        assert agree.raw == (b'{"v":"KERI10JSON00012f_","t":"exn","d":"ECU3UjnSY1_6Wl3aYEW19jaGiKuyFh_chIQQ'
                             b'w48bcT_X","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"EN'
                             b'dVOCsP5Xz57qs1xa_msznozvBs6Ii0_JRoi6tp2NBu","dt":"2021-06-27T21:26:21.233257'
                             b'+00:00","r":"/ipex/agree","q":{},"a":{"m":"I\'ll accept that offer"},"e":'
                             b'{}}')

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
        assert grant0.raw == (b'{"v":"KERI10JSON000539_","t":"exn","d":"ELnjKvzdgO57JZwG3giIScoOeTB0rLuevniv'
                              b'zRE5DbTE","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"",'
                              b'"dt":"2021-06-27T21:26:21.233257+00:00","r":"/ipex/grant","q":{},"a":{"m":"H'
                              b'ere\'s a credential","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"},'
                              b'"e":{"acdc":{"v":"ACDC10JSON000197_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103'
                              b'V3-4E-ClXH","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VA'
                              b'F7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvaf'
                              b'X3bHQ9Gkk1kC","a":{"d":"EO9_6NattzsFiO8Fw1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"'
                              b'2021-06-27T21:26:21.233257+00:00","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8A'
                              b'N-tiUbl","LEI":"254900OPPU84GM83MG36"}},"iss":{"v":"KERI10JSON0000ed_","t":"'
                              b'iss","d":"ECUw7AdWEE3fvr7dgbFDXj0CEZuJTTa_H8-iLLAmIUPO","i":"EElymNmgs1u0mSa'
                              b'oCeOtSsNOROLuqOz103V3-4E-ClXH","s":"0","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXe'
                              b'w8Yo6Z3w9mQUQ","dt":"2021-06-27T21:26:21.233257+00:00"},"anc":{"v":"KERI10JS'
                              b'ON00013a_","t":"ixn","d":"EGhSHKIV5-nkeirdkqzqsvmeF1FXw_yH8NvPSAY1Rgyd","i":'
                              b'"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","s":"2","p":"ED1kkh5_ECYriK-j'
                              b'2gSv6Zjr5way88XVhwRCxk5zoTRG","a":[{"i":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V'
                              b'3-4E-ClXH","s":"0","d":"ECUw7AdWEE3fvr7dgbFDXj0CEZuJTTa_H8-iLLAmIUPO"}]},"d"'
                              b':"EJ4-dlS9ktlb9HDWPYc0IJ2hS2NbvnCQBhUsFSkEPwIo"}}')

        assert ipexhan.verify(serder=grant0) is True

        # Lets save this bare offer so we can test full spurn workflow
        gmsg = bytearray(grant0.raw)
        gmsg.extend(grant0atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant0.said,))
        assert serder.ked == grant0.ked

        # Let's see if we can spurn a message we previously accepted.
        spurn1, spurn1atc = protocoling.ipexSpurnExn(sidHab, "I reject you", spurned=grant0)
        assert spurn1.raw == (b'{"v":"KERI10JSON000125_","t":"exn","d":"ELHFilyCgYvVq6vczgPQc7ZuRMs7Cv10U_h-'
                              b'2LIvJ1-Z","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"EL'
                              b'njKvzdgO57JZwG3giIScoOeTB0rLuevnivzRE5DbTE","dt":"2021-06-27T21:26:21.233257'
                              b'+00:00","r":"/ipex/spurn","q":{},"a":{"m":"I reject you"},"e":{}}')
        smsg = bytearray(spurn1.raw)
        smsg.extend(spurn1atc)
        parsing.Parser().parse(ims=smsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(spurn1.said,))
        assert serder.ked == spurn1.ked  # This credential grant has been spurned and not accepted into database

        # Now we'll run a grant pointing back to the agree all the way to the database
        grant1, grant1atc = protocoling.ipexGrantExn(sidHab, message="Here's a credential", acdc=msg, iss=iss.raw,
                                                     recp=sidHab.pre, anc=anc, agree=agree)
        assert grant1.raw == (b'{"v":"KERI10JSON000565_","t":"exn","d":"EHAY_L6Ig4k_5qIw6uH-QZwBswWLfwVzCqaG'
                              b'sjtdnubK","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"EC'
                              b'U3UjnSY1_6Wl3aYEW19jaGiKuyFh_chIQQw48bcT_X","dt":"2021-06-27T21:26:21.233257'
                              b'+00:00","r":"/ipex/grant","q":{},"a":{"m":"Here\'s a credential","i":"EMl'
                              b'4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl"},"e":{"acdc":{"v":"ACDC10JSON0001'
                              b'97_","d":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","i":"EMl4RhuR_JxpiMd'
                              b'1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w'
                              b'9mQUQ","s":"EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EO9_6Nat'
                              b'tzsFiO8Fw1cxjYmDjOsKKSbootn-wXn9S3iB","dt":"2021-06-27T21:26:21.233257+00:00'
                              b'","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","LEI":"254900OPPU84GM83'
                              b'MG36"}},"iss":{"v":"KERI10JSON0000ed_","t":"iss","d":"ECUw7AdWEE3fvr7dgbFDXj'
                              b'0CEZuJTTa_H8-iLLAmIUPO","i":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","'
                              b's":"0","ri":"EB-u4VAF7A7_GR8PXJoAVHv5X9vjtXew8Yo6Z3w9mQUQ","dt":"2021-06-27T'
                              b'21:26:21.233257+00:00"},"anc":{"v":"KERI10JSON00013a_","t":"ixn","d":"EGhSHK'
                              b'IV5-nkeirdkqzqsvmeF1FXw_yH8NvPSAY1Rgyd","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn'
                              b'9Xya8AN-tiUbl","s":"2","p":"ED1kkh5_ECYriK-j2gSv6Zjr5way88XVhwRCxk5zoTRG","a'
                              b'":[{"i":"EElymNmgs1u0mSaoCeOtSsNOROLuqOz103V3-4E-ClXH","s":"0","d":"ECUw7AdW'
                              b'EE3fvr7dgbFDXj0CEZuJTTa_H8-iLLAmIUPO"}]},"d":"EJ4-dlS9ktlb9HDWPYc0IJ2hS2Nbvn'
                              b'CQBhUsFSkEPwIo"}}')
        assert ipexhan.verify(serder=grant1) is True

        gmsg = bytearray(grant1.raw)
        gmsg.extend(grant1atc)
        parsing.Parser().parse(ims=gmsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(grant1.said,))
        assert serder.ked == grant1.ked

        # And now the last... admit the granted credential to complete the full flow
        admit0, admit0atc = protocoling.ipexAdmitExn(sidHab, "Thanks for the credential", grant=grant1)
        assert admit0.raw == (b'{"v":"KERI10JSON000132_","t":"exn","d":"EMxU5rfeqKnZzrbqnL7weXQGaC8Zum4qowj2'
                              b'eiL6GxqL","i":"EMl4RhuR_JxpiMd1N8DEJEhTxM3Ovvn9Xya8AN-tiUbl","rp":"","p":"EH'
                              b'AY_L6Ig4k_5qIw6uH-QZwBswWLfwVzCqaGsjtdnubK","dt":"2021-06-27T21:26:21.233257'
                              b'+00:00","r":"/ipex/admit","q":{},"a":{"m":"Thanks for the credential"},"e":{'
                              b'}}')
        assert ipexhan.verify(serder=admit0) is True

        amsg = bytearray(admit0.raw)
        amsg.extend(admit0atc)
        parsing.Parser().parse(ims=amsg, exc=sidExc)
        serder = sidHby.db.exns.get(keys=(admit0.said,))
        assert serder.ked == admit0.ked
