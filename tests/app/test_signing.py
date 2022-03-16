# -*- encoding: utf-8 -*-
"""
tests.app.signing module

"""

from keri.app import habbing, configing
from keri.app import signing
from keri.core import coring, parsing, eventing
from keri.peer import exchanging
from keri.vc import proving
from keri.vdr import verifying, issuing


def test_sad_signature():
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (sigHby, sidHab), \
            habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab):
        personal = dict(
            d="",
            n="Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY",
            personLegalName="Anna Jones",
            engagementContextRole="Project Manager",
        )

        _, sad = coring.Saider.saidify(sad=personal, label=coring.Ids.d)

        d = dict(
            d="",
            i="EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
            dt="2021-06-09T17:35:54.169967+00:00",
            ri="EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
            LEI="254900OPPU84GM83MG36",
            personal=sad,
        )

        # test source chaining with labeled edge
        s = [
            dict(qualifiedvLEIIssuervLEICredential="EGtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD")
        ]

        cred = proving.credential(schema="EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                                  issuer="EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                                  subject=d, source=s, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")
        paths = [[], ["a"], ["a", "personal"]]

        # Sign with non-transferable identifier, default to entire SAD
        sig0 = signing.ratify(wanHab, cred)
        assert sig0 == (b'{"v":"ACDC10JSON0002af_","d":"E25eYAS69RFUAJSaTf_hjYNx-IZJdv--FJ'
                        b'fNIaW7RkL0","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"Ecea'
                        b'O4431cYvUZLLAM_ImtSS8XISjNHuyaBuwHzovd94","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","LEI":"'
                        b'254900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8'
                        b'NgD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bO'
                        b'IHUjY","personLegalName":"Anna Jones","engagementContextRole":"P'
                        b'roject Manager"}},"p":[{"qualifiedvLEIIssuervLEICredential":"EGt'
                        b'yThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--CABB'
                        b'BtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480B-EmK-iwW0gMYKY6Yw5v'
                        b'EjAXvxy9MvIlR0MR6XOrBWWnBoNGHCYbyK3Olxoq1T9MjCBlQNIK-q8vUbltKzEJ'
                        b'RDQ')

        # sign with non-trans identifer with a specific set of paths
        sig1 = signing.ratify(wanHab, cred, paths=paths)
        assert sig1 == (b'{"v":"ACDC10JSON0002af_","d":"E25eYAS69RFUAJSaTf_hjYNx-IZJdv--FJ'
                        b'fNIaW7RkL0","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"Ecea'
                        b'O4431cYvUZLLAM_ImtSS8XISjNHuyaBuwHzovd94","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","LEI":"'
                        b'254900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8'
                        b'NgD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bO'
                        b'IHUjY","personLegalName":"Anna Jones","engagementContextRole":"P'
                        b'roject Manager"}},"p":[{"qualifiedvLEIIssuervLEICredential":"EGt'
                        b'yThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6'
                        b'AABAAA--CADBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480B-EmK-iw'
                        b'W0gMYKY6Yw5vEjAXvxy9MvIlR0MR6XOrBWWnBoNGHCYbyK3Olxoq1T9MjCBlQNIK'
                        b'-q8vUbltKzEJRDQ-JAB5AABAA-a-CADBBtKPeN9p4lum6qDRa28fDfVShFk6c39F'
                        b'lBgHBsCq1480BBDoK0wCjjNsq-ozd7JETJ3Un2qR2FB83yPF5eNURQxJAUpt1QiC'
                        b'EDkh_lXPIdCv2ElXEx856_XMpT08e8dCMCQ-JAB4AADA-a-personal-CADBBtKP'
                        b'eN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480BJdTjYZ2A0kXZX7tLxKgju6Z'
                        b'P31-21J5Pl_VUmE-QGtl1h_GJb-aUox-UQLx_rum18xWhHi9zLSqFv5lY39FfBw')

        # Sign with transferable identifier defaults to single signature on entire SAD
        sig2 = signing.ratify(sidHab, cred)
        assert sig2 == (b'{"v":"ACDC10JSON0002af_","d":"E25eYAS69RFUAJSaTf_hjYNx-IZJdv--FJ'
                        b'fNIaW7RkL0","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"Ecea'
                        b'O4431cYvUZLLAM_ImtSS8XISjNHuyaBuwHzovd94","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","LEI":"'
                        b'254900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8'
                        b'NgD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bO'
                        b'IHUjY","personLegalName":"Anna Jones","engagementContextRole":"P'
                        b'roject Manager"}},"p":[{"qualifiedvLEIIssuervLEICredential":"EGt'
                        b'yThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--FABE'
                        b'rO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAA'
                        b'AAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAA7iGoMHHAZf1'
                        b'UnqzTQF_r35WgwcmtfM-U5vbJapBX3lZlLd_bZr1bSLV7CTnQ8GMXLp5ocx1boO0'
                        b'mn81roT8XDg')

        # Sign with transferable identifier with specific set of paths
        sig3 = signing.ratify(sidHab, cred, paths=paths)
        assert sig3 == (b'{"v":"ACDC10JSON0002af_","d":"E25eYAS69RFUAJSaTf_hjYNx-IZJdv--FJ'
                        b'fNIaW7RkL0","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"Ecea'
                        b'O4431cYvUZLLAM_ImtSS8XISjNHuyaBuwHzovd94","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","LEI":"'
                        b'254900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8'
                        b'NgD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bO'
                        b'IHUjY","personLegalName":"Anna Jones","engagementContextRole":"P'
                        b'roject Manager"}},"p":[{"qualifiedvLEIIssuervLEICredential":"EGt'
                        b'yThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6'
                        b'AABAAA--FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAA'
                        b'AAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABA'
                        b'A7iGoMHHAZf1UnqzTQF_r35WgwcmtfM-U5vbJapBX3lZlLd_bZr1bSLV7CTnQ8GM'
                        b'XLp5ocx1boO0mn81roT8XDg-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUy'
                        b'rV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN'
                        b'4tUyrV9dMd2VEt7SdG0wh50-AABAAJqM8t5rLscoH7hq5LXeU8f_k3qPzvXEaZDn'
                        b'T9hqK2KQY82-Jmt1Wwn7kuSLpBsGZNFA20IeROzQxS8EpJC_XBA-JAB4AADA-a-p'
                        b'ersonal-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAA'
                        b'AAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABA'
                        b'AzwL1MASfBplH3RRW-l51-RS8H0ahSNmQMCZlb0CxX2VNrvkqePjjNv3tIocjapf'
                        b'5pHx8Y7TNUKsQFjK6-qxACA')

    # Test multisig identifier
    with configing.openCF(name="mel", base="mel", temp=True) as cf, \
        habbing.openHby(name="mel", temp=True, salt=coring.Salter(raw=b'0123456789abcdef').qb64b,
                        base="mel", cf=cf) as hby:
        hab = hby.makeHab(name="mel", icount=3, isith=3, ncount=3, nsith=3)

        md = dict(
            d="",
            i="EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
            dt="2021-06-09T17:35:54.169967+00:00",
            LEI="254900OPPU84GM83MG36"
        )
        verifier = verifying.Verifier(hby=hby)
        issuer = issuing.Issuer(hab=hab, reger=verifier.reger)

        cred = proving.credential(schema="ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo",
                                  issuer=hab.pre, subject=md, source=[], status=issuer.regk)

        # Sign with multisig transferable identifier defaults to single signature on entire SAD
        sig1 = signing.ratify(hab=hab, serder=cred)
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EsvsOCKSvF_yoBscffaD4u1cCoefDG7Cc9'
                        b'VyjZPEcNPc","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"EJOvY0hgm0Pfw2dg39rwuhGh7B0t3J8JIZkLIk5R-rPs","a":{"d":"E3vN'
                        b'Pl0m0nSLXPuXcPwbYUZkO_F4Q0YWfnSPMlfdQyS0","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"EqHRzdfr0HuRYDZx4xmyFHnQ'
                        b'_U1n3z54SO7tu02ebn3c"},"p":[]}-JAB6AABAAA--FABEJOvY0hgm0Pfw2dg39'
                        b'rwuhGh7B0t3J8JIZkLIk5R-rPs0AAAAAAAAAAAAAAAAAAAAAAAEJOvY0hgm0Pfw2'
                        b'dg39rwuhGh7B0t3J8JIZkLIk5R-rPs-AADAAQTcCdPEHU6Og_435H0k1s6TwZ0Vs'
                        b'YcoawqmtEalppUdbA1WjyPVk5uYR6rMy4qOLVsDqCXYnnuU7hvhXKUJ-CgABAB86'
                        b'KkYoIUplPRTPvBBc436X_Wm7hN-odm8XqW2VpTnQRJzDirI_-NYxxlymB_yi6Fbh'
                        b'ef2cZ_8sDZ7v8VN3AQAC5_zQlmZmkeYRz_JQCUF2Y-GrcDR_Y7D6T2blGw_2a7Te'
                        b'kBbMMrdf9kszFliQEZhbQfm_hkw31e8jtzlVe0XrBw')

        issuer.issue(creder=cred)
        parsing.Parser().parse(ims=sig1, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

    """End Test"""


def test_signature_transposition():
    d = dict(
        d="",
        i="EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
        dt="2021-06-09T17:35:54.169967+00:00",
        LEI="254900OPPU84GM83MG36"
    )

    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        verifier = verifying.Verifier(hby=hby)
        issuer = issuing.Issuer(hab=hab, reger=verifier.reger)

        cred = proving.credential(schema="ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo",
                                  issuer=hab.pre, subject=d, source=[], status=issuer.regk)

        # Sign with non-transferable identifier, defaults to single signature on entire SAD
        sig0 = signing.ratify(hab=hab, serder=cred)
        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"E6GIzcFURqWyu_GDtbbrkvuiAFKc_h9NG4'
                        b'qcJtJkctU8","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","a":{"d":"EnKO'
                        b'URQiDR4frA0G1ELi_FsXqI3aBx_u74xct5-NllXg","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"EYzrBEAQFwt_X-BJ3aOcwHwa'
                        b'cdwysMSWnMr5qDaiE7Ow"},"p":[]}-JAB6AABAAA--FABErO8qhYftaJsAbCb6H'
                        b'UrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAMzaTTgZl2t8CKZIXjsAuW2yzhU1W'
                        b'86e2cXxL3enAOaxHZ0DkQhTkhMLTeoqBO3U-G1X8EdJEMOcchn-ZlzudAw')

        issuer.issue(creder=cred)
        parsing.Parser().parse(ims=sig0, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said)
        assert scre.raw == cred.raw
        assert len(sadcigars) == 0
        assert len(sadsigers) == 1

        (pather, prefixer, seqner, saider, sigers) = sadsigers[0]
        assert pather.text == "-"
        assert prefixer.qb64 == hab.pre
        assert seqner.sn == 0
        assert saider.qb64 == hab.kever.lastEst.d
        assert len(sigers) == 1
        assert sigers[0].qb64b == (b'AAMzaTTgZl2t8CKZIXjsAuW2yzhU1W86e2cXxL3enAOaxHZ0DkQhTkhMLTeoqBO3U-G1X8EdJEMO'
                                   b'cchn-ZlzudAw')

        # Transpose the signature to a new root
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a", "b", "c"]))
        assert scre.raw == cred.raw
        assert len(sadcigars) == 0
        assert len(sadsigers) == 1

        (pather, prefixer, seqner, saider, sigers) = sadsigers[0]
        assert pather.text == "-a-b-c"  # new emdded location
        assert prefixer.qb64 == hab.pre
        assert seqner.sn == 0
        assert saider.qb64 == hab.kever.lastEst.d
        assert len(sigers) == 1
        assert sigers[0].qb64b == (b'AAMzaTTgZl2t8CKZIXjsAuW2yzhU1W86e2cXxL3enAOaxHZ0DkQhTkhMLTeoqBO3U-G1X8EdJEMO'
                                   b'cchn-ZlzudAw')

        # embed the credential in an exn and transpose the signature
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a"]))
        exn = exchanging.exchange(route="/credential/issue", payload=scre.crd, date="2022-01-04T11:58:55.154502+00:00")
        msg = hab.endorse(serder=exn)
        msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars))

        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"Em0V2Doo4pJ29J11dCOXIqEt'
                       b'YO-IDpJQIvwjRUzlonCo","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"E6GIzcFU'
                       b'RqWyu_GDtbbrkvuiAFKc_h9NG4qcJtJkctU8","s":"ESAItgWbOyCvcNAqkJFBZ'
                       b'qxG2-h69fOkw7Rzk0gAqkqo","i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VE'
                       b't7SdG0wh50","a":{"d":"EnKOURQiDR4frA0G1ELi_FsXqI3aBx_u74xct5-Nll'
                       b'Xg","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"202'
                       b'1-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM83MG36","ri"'
                       b':"EYzrBEAQFwt_X-BJ3aOcwHwacdwysMSWnMr5qDaiE7Ow"},"p":[]}}-VA0-FA'
                       b'BErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAA'
                       b'AAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAKVAqXhPpD'
                       b'5O3YLL9OBvsYkgeZX0kmBGyxb6s22IgoZ54SHfIfKipZ3dDRaD3U5YOarxVELgzQ'
                       b'd4aLpF9STsUDw-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt'
                       b'7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd'
                       b'2VEt7SdG0wh50-AABAAMzaTTgZl2t8CKZIXjsAuW2yzhU1W86e2cXxL3enAOaxHZ'
                       b'0DkQhTkhMLTeoqBO3U-G1X8EdJEMOcchn-ZlzudAw')

        # issue the credential
        issuer.issue(creder=cred)

        # parse the credential and verify it is saved in the credential store
        parsing.Parser().parse(ims=sig0, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

    # multiple path sigs
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        verifier = verifying.Verifier(hby=hby)
        issuer = issuing.Issuer(hab=hab, reger=verifier.reger)

        cred = proving.credential(schema="ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo",
                                  issuer=hab.pre, subject=d, source=[], status=issuer.regk)

        # sign with single sig transferable identfier with multiple specified paths
        sig1 = signing.ratify(hab=hab, serder=cred, paths=[[], ["a"], ["a", "ri"]])
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"E6GIzcFURqWyu_GDtbbrkvuiAFKc_h9NG4'
                        b'qcJtJkctU8","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","a":{"d":"EnKO'
                        b'URQiDR4frA0G1ELi_FsXqI3aBx_u74xct5-NllXg","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"EYzrBEAQFwt_X-BJ3aOcwHwa'
                        b'cdwysMSWnMr5qDaiE7Ow"},"p":[]}-KAD6AABAAA--JAB6AABAAA--FABErO8qh'
                        b'YftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAEr'
                        b'O8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAMzaTTgZl2t8CKZIX'
                        b'jsAuW2yzhU1W86e2cXxL3enAOaxHZ0DkQhTkhMLTeoqBO3U-G1X8EdJEMOcchn-Z'
                        b'lzudAw-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh'
                        b'500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7Sd'
                        b'G0wh50-AABAAfVchR1X0_mHOv_OgPFO_wX9JeMlq5wrqZv50y5-wTxhLwPZFLITv'
                        b'cK588Bnit11C0ZrfqtiO9rkKTSpZLdwnDQ-JAB6AACAAA-a-ri-FABErO8qhYfta'
                        b'JsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qh'
                        b'YftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAATMtLZlPsNYWOkc0G8-hA'
                        b'h5YuBvv1h11AdyWS9tskUOrI3k31OjYOFheIRacNhzZKSjbUREN46SykJx1vDd1FCg')

        # Issue the credential and parse into credential store
        issuer.issue(creder=cred)
        parsing.Parser().parse(ims=sig1, vry=verifier)

        # verify the credential is saved
        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

        # cloneCred tales a root parameter for transposing the signatures to a base path
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a"]))
        assert len(sadsigers) == 3

        # create a new exn message with the credential as the payload
        exn = exchanging.exchange(route="/credential/issue", payload=scre.crd, date="2022-01-04T11:58:55.154502+00:00")

        # sign the exn message
        msg = hab.endorse(serder=exn)

        # attach the transposed signatures for the embedded credential
        msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars))
        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"Em0V2Doo4pJ29J11dCOXIqEt'
                       b'YO-IDpJQIvwjRUzlonCo","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"E6GIzcFU'
                       b'RqWyu_GDtbbrkvuiAFKc_h9NG4qcJtJkctU8","s":"ESAItgWbOyCvcNAqkJFBZ'
                       b'qxG2-h69fOkw7Rzk0gAqkqo","i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VE'
                       b't7SdG0wh50","a":{"d":"EnKOURQiDR4frA0G1ELi_FsXqI3aBx_u74xct5-Nll'
                       b'Xg","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"202'
                       b'1-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM83MG36","ri"'
                       b':"EYzrBEAQFwt_X-BJ3aOcwHwacdwysMSWnMr5qDaiE7Ow"},"p":[]}}-VA0-FA'
                       b'BErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAA'
                       b'AAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAKVAqXhPpD'
                       b'5O3YLL9OBvsYkgeZX0kmBGyxb6s22IgoZ54SHfIfKipZ3dDRaD3U5YOarxVELgzQ'
                       b'd4aLpF9STsUDw-KAD6AABAAA--JAB4AAB-a-a-FABErO8qhYftaJsAbCb6HUrN4t'
                       b'UyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HU'
                       b'rN4tUyrV9dMd2VEt7SdG0wh50-AABAAfVchR1X0_mHOv_OgPFO_wX9JeMlq5wrqZ'
                       b'v50y5-wTxhLwPZFLITvcK588Bnit11C0ZrfqtiO9rkKTSpZLdwnDQ-JAB5AABAA-'
                       b'a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAA'
                       b'AAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAMzaTT'
                       b'gZl2t8CKZIXjsAuW2yzhU1W86e2cXxL3enAOaxHZ0DkQhTkhMLTeoqBO3U-G1X8E'
                       b'dJEMOcchn-ZlzudAw-JAB4AACA-a-a-ri-FABErO8qhYftaJsAbCb6HUrN4tUyrV'
                       b'9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4t'
                       b'UyrV9dMd2VEt7SdG0wh50-AABAATMtLZlPsNYWOkc0G8-hAh5YuBvv1h11AdyWS9'
                       b'tskUOrI3k31OjYOFheIRacNhzZKSjbUREN46SykJx1vDd1FCg')

    # signing SAD with non-transferable identifier
    with habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (hby, hab):
        cred = proving.credential(schema="ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo",
                                  issuer=hab.pre, subject=d, source=[],
                                  status="Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE")

        # Sign with non-transferable identifier
        sig0 = signing.ratify(hab=hab, serder=cred)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"ElSJrRhwdpPb6qvLt7Zc14A3gOW6_D-cP-'
                        b'noEdwjDWNM","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"BBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq148","a":{"d":"E0kF'
                        b'tfbyhIbjbzVnyHoNTkb64Zk-Wqjj77AjYEJBMGAc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"Eg1H4eN7P5ndJAWtcymq3ZrY'
                        b'ZwQsBRYd3-VuZ6wMAwxE"},"p":[]}-JAB6AABAAA--CABBBtKPeN9p4lum6qDRa'
                        b'28fDfVShFk6c39FlBgHBsCq1480Blo8IXKRuRnMxHwf62V7_UZEqBPQx_HwsKDVF'
                        b'a22pnSWfwEjyYcv2pK6SKLgnGFcQCc2xqK94E8GHUTow3tHZAw')

        pather = coring.Pather(path=["a", "b", "c"])
        cigars = hab.sign(ser=cred.raw,
                              verfers=hab.kever.verfers,
                              indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsC'
                      b'q1480Blo8IXKRuRnMxHwf62V7_UZEqBPQx_HwsKDVFa22pnSWfwEjyYcv2pK6SKL'
                      b'gnGFcQCc2xqK94E8GHUTow3tHZAw')

    """End Test"""

