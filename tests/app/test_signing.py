# -*- encoding: utf-8 -*-
"""
tests.app.signing module

"""

from keri.app import habbing, keeping, configing
from keri.app import signing
from keri.core import coring, parsing, eventing
from keri.db import basing
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
                        b'tjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAA'
                        b'AAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAA7iGoMHHAZf1'
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
                        b'AABAAA--FABEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAA'
                        b'AAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABA'
                        b'A7iGoMHHAZf1UnqzTQF_r35WgwcmtfM-U5vbJapBX3lZlLd_bZr1bSLV7CTnQ8GM'
                        b'XLp5ocx1boO0mn81roT8XDg-JAB5AABAA-a-FABEtjehgJ3LiIcPUKIQy28zge56'
                        b'_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy28z'
                        b'ge56_B2lzdGGLwLpuRBkZ8w-AABAAJqM8t5rLscoH7hq5LXeU8f_k3qPzvXEaZDn'
                        b'T9hqK2KQY82-Jmt1Wwn7kuSLpBsGZNFA20IeROzQxS8EpJC_XBA-JAB4AADA-a-p'
                        b'ersonal-FABEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAA'
                        b'AAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABA'
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
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"ElnunisdNcMdaIypzfn3_9l2E8rsLk_2Q1'
                        b'Mrdqb8igFA","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"EsZsrhSSwVZF62GzoINWF5NveSQTwgn2tHSmMKGDNGZg","a":{"d":"EtLL'
                        b'Edd6k46Zk5Yxni8p9bZlfOk5fPRl41UPJvz4af-0","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"EnZLgDCpgBbtLdyvrVBCoawO'
                        b'jRfGcag-uYEqYTHqyhUs"},"p":[]}-JAB6AABAAA--FABEsZsrhSSwVZF62GzoI'
                        b'NWF5NveSQTwgn2tHSmMKGDNGZg0AAAAAAAAAAAAAAAAAAAAAAAEsZsrhSSwVZF62'
                        b'GzoINWF5NveSQTwgn2tHSmMKGDNGZg-AADAAR8EhWkTy6qFgyz7afoA1PPvXQQGz'
                        b'GhJjCP7HeBEm4Z-phNiA3NSpMf0jsOJDOaM7EZ5xeUajZxlG02_P5pzNDAABh6mU'
                        b'ZuJEo0HVmoAd6cCqqVceZeg3nfwjANlortQp2egedZ_XPXEVVjRco2pNzDz7HIGA'
                        b'8qNSBEAiQfvEQNO_CAACY5SlzCTKzRnCMGVJFmvHdU0Szcl4nHZYiFGPrTkXBxrj'
                        b'Ylz09FJ4yzYZwY-7f2iG1HN4_LOow6I288vuwdxfBg')

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
        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"E1x9hWR5ypCrhgqMaIUlALI1Id_Y8IgDli'
                        b'PbP0h11tOs","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"EtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w","a":{"d":"E0kF'
                        b'tfbyhIbjbzVnyHoNTkb64Zk-Wqjj77AjYEJBMGAc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"Eg1H4eN7P5ndJAWtcymq3ZrY'
                        b'ZwQsBRYd3-VuZ6wMAwxE"},"p":[]}-JAB6AABAAA--FABEtjehgJ3LiIcPUKIQy'
                        b'28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehgJ3LiIcPU'
                        b'KIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAADe5tx0Jxn2kpwoiZh47Wkoez4lOg'
                        b'oG-E6lvjn_IXDIF4o7Oan_fNC22k6WzQKj8mewUcvhhvw-6mmzno2eR4DQ')

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
        assert sigers[0].qb64b == (b'AADe5tx0Jxn2kpwoiZh47Wkoez4lOgoG-E6lvjn_IXDIF4o7Oan_fNC22k6WzQKj8mewUcvhhvw-'
                                   b'6mmzno2eR4DQ')

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
        assert sigers[0].qb64b == (b'AADe5tx0Jxn2kpwoiZh47Wkoez4lOgoG-E6lvjn_IXDIF4o7Oan_fNC22k6WzQKj8mewUcvhhvw-'
                                   b'6mmzno2eR4DQ')

        # embed the credential in an exn and transpose the signature
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a"]))
        exn = exchanging.exchange(route="/credential/issue", payload=scre.crd, date="2022-01-04T11:58:55.154502+00:00")
        msg = hab.endorse(serder=exn)
        msg.extend(eventing.proofize(sadsigers=sadsigers, sadcigars=sadcigars))

        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"ELiFf9jptP0iYqy16cStp9W3'
                       b'plaGIj3cqX8g8JtWKzmI","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"E1x9hWR5'
                       b'ypCrhgqMaIUlALI1Id_Y8IgDliPbP0h11tOs","s":"ESAItgWbOyCvcNAqkJFBZ'
                       b'qxG2-h69fOkw7Rzk0gAqkqo","i":"EtjehgJ3LiIcPUKIQy28zge56_B2lzdGGL'
                       b'wLpuRBkZ8w","a":{"d":"E0kFtfbyhIbjbzVnyHoNTkb64Zk-Wqjj77AjYEJBMG'
                       b'Ac","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"202'
                       b'1-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM83MG36","ri"'
                       b':"Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE"},"p":[]}}-VA0-FA'
                       b'BEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAA'
                       b'AAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAAiXFJ1sG9K'
                       b'ZHkAKNPLoOZiz9jhzgIv2lknmmIKa2bHoDubNELBaM9Pli-8A202hbbnAg2tNGQq'
                       b'73tT9nuCx9VDA-JAB5AABAA-a-FABEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLw'
                       b'LpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzd'
                       b'GGLwLpuRBkZ8w-AABAADe5tx0Jxn2kpwoiZh47Wkoez4lOgoG-E6lvjn_IXDIF4o'
                       b'7Oan_fNC22k6WzQKj8mewUcvhhvw-6mmzno2eR4DQ')

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
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"E1x9hWR5ypCrhgqMaIUlALI1Id_Y8IgDli'
                        b'PbP0h11tOs","s":"ESAItgWbOyCvcNAqkJFBZqxG2-h69fOkw7Rzk0gAqkqo","'
                        b'i":"EtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w","a":{"d":"E0kF'
                        b'tfbyhIbjbzVnyHoNTkb64Zk-Wqjj77AjYEJBMGAc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36","ri":"Eg1H4eN7P5ndJAWtcymq3ZrY'
                        b'ZwQsBRYd3-VuZ6wMAwxE"},"p":[]}-KAD6AABAAA--JAB6AABAAA--FABEtjehg'
                        b'J3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEt'
                        b'jehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAADe5tx0Jxn2kpwoiZ'
                        b'h47Wkoez4lOgoG-E6lvjn_IXDIF4o7Oan_fNC22k6WzQKj8mewUcvhhvw-6mmzno'
                        b'2eR4DQ-JAB5AABAA-a-FABEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ'
                        b'8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpu'
                        b'RBkZ8w-AABAA_XSmslk9G08DoUO2S-AT5v1sfASpBzr-tBmFcTpjsjFVPbQVeCfT'
                        b'YM5qw6N9rA_06Vgmk0wSWvZrTgD3ly-XDg-JAB6AACAAA-a-ri-FABEtjehgJ3Li'
                        b'IcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehg'
                        b'J3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAAMww_ANw37teZaMDD69pY'
                        b'1370mw5q0JnBEadHs1n2svQeydApgrvB0ofb2XWeFXquwkzj7fitH2M2nvivNm9tBA')

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
        msg.extend(eventing.proofize(sadsigers=sadsigers, sadcigars=sadcigars))
        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"ELiFf9jptP0iYqy16cStp9W3'
                       b'plaGIj3cqX8g8JtWKzmI","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"E1x9hWR5'
                       b'ypCrhgqMaIUlALI1Id_Y8IgDliPbP0h11tOs","s":"ESAItgWbOyCvcNAqkJFBZ'
                       b'qxG2-h69fOkw7Rzk0gAqkqo","i":"EtjehgJ3LiIcPUKIQy28zge56_B2lzdGGL'
                       b'wLpuRBkZ8w","a":{"d":"E0kFtfbyhIbjbzVnyHoNTkb64Zk-Wqjj77AjYEJBMG'
                       b'Ac","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"202'
                       b'1-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM83MG36","ri"'
                       b':"Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE"},"p":[]}}-VA0-FA'
                       b'BEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAA'
                       b'AAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAAiXFJ1sG9K'
                       b'ZHkAKNPLoOZiz9jhzgIv2lknmmIKa2bHoDubNELBaM9Pli-8A202hbbnAg2tNGQq'
                       b'73tT9nuCx9VDA-KAD6AABAAA--JAB4AAB-a-a-FABEtjehgJ3LiIcPUKIQy28zge'
                       b'56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy2'
                       b'8zge56_B2lzdGGLwLpuRBkZ8w-AABAA_XSmslk9G08DoUO2S-AT5v1sfASpBzr-t'
                       b'BmFcTpjsjFVPbQVeCfTYM5qw6N9rA_06Vgmk0wSWvZrTgD3ly-XDg-JAB5AABAA-'
                       b'a-FABEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAA'
                       b'AAAAAAAAAEtjehgJ3LiIcPUKIQy28zge56_B2lzdGGLwLpuRBkZ8w-AABAADe5tx'
                       b'0Jxn2kpwoiZh47Wkoez4lOgoG-E6lvjn_IXDIF4o7Oan_fNC22k6WzQKj8mewUcv'
                       b'hhvw-6mmzno2eR4DQ-JAB4AACA-a-a-ri-FABEtjehgJ3LiIcPUKIQy28zge56_B'
                       b'2lzdGGLwLpuRBkZ8w0AAAAAAAAAAAAAAAAAAAAAAAEtjehgJ3LiIcPUKIQy28zge'
                       b'56_B2lzdGGLwLpuRBkZ8w-AABAAMww_ANw37teZaMDD69pY1370mw5q0JnBEadHs'
                       b'1n2svQeydApgrvB0ofb2XWeFXquwkzj7fitH2M2nvivNm9tBA')

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
        cigars = hab.mgr.sign(ser=cred.raw,
                              verfers=hab.kever.verfers,
                              indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsC'
                      b'q1480Blo8IXKRuRnMxHwf62V7_UZEqBPQx_HwsKDVFa22pnSWfwEjyYcv2pK6SKL'
                      b'gnGFcQCc2xqK94E8GHUTow3tHZAw')

    """End Test"""

