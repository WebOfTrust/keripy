# -*- encoding: utf-8 -*-
"""
tests.app.signing module

"""

from keri.app import habbing, configing
from keri.app import signing
from keri.core import coring, parsing, eventing
from keri.core.eventing import SealEvent
from keri.peer import exchanging
from keri.vc import proving
from keri.vdr import verifying, credentialing


def test_sad_signature(seeder, mockCoringRandomNonce):
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
        assert sig0 == (b'{"v":"ACDC10JSON0002e2_","d":"EcrRkKPunSlppq42NkHfZxyE3xOLGvvtu8'
                        b'-gUErzIgRg","i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EZllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EH-Po1gxypl7l4Ki'
                        b'l8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                        b'ymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8NgD8dDHLgazBx'
                        b'Tqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--CABBBtKPeN9p4lum6'
                        b'qDRa28fDfVShFk6c39FlBgHBsCq1480BxkrxBL3Dp4p_-qkGX1eqyy188thD9Pf4'
                        b'kik6BiJoAVL4jgGmT-VFd_JqQLVsViVwyajdYlCgF_G4hosURhBeBQ')

        # sign with non-trans identifer with a specific set of paths
        sig1 = signing.ratify(wanHab, cred, paths=paths)
        assert sig1 == (b'{"v":"ACDC10JSON0002e2_","d":"EcrRkKPunSlppq42NkHfZxyE3xOLGvvtu8'
                        b'-gUErzIgRg","i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EZllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EH-Po1gxypl7l4Ki'
                        b'l8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                        b'ymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8NgD8dDHLgazBx'
                        b'Tqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--CADBB'
                        b'tKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480BxkrxBL3Dp4p_-qkGX1eq'
                        b'yy188thD9Pf4kik6BiJoAVL4jgGmT-VFd_JqQLVsViVwyajdYlCgF_G4hosURhBe'
                        b'BQ-JAB5AABAA-a-CADBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480B'
                        b'LYDoLPoyUfH1n7t_bcP4ZmaseBXlWbmnbFCpylGyzttBTqUzI9iiHWAfyLkKMOvm'
                        b'_Qpz5ysS6IlNhEmPT5HfDQ-JAB4AADA-a-personal-CADBBtKPeN9p4lum6qDRa'
                        b'28fDfVShFk6c39FlBgHBsCq1480BJdTjYZ2A0kXZX7tLxKgju6ZP31-21J5Pl_VU'
                        b'mE-QGtl1h_GJb-aUox-UQLx_rum18xWhHi9zLSqFv5lY39FfBw')

        # Sign with transferable identifier defaults to single signature on entire SAD
        sig2 = signing.ratify(sidHab, cred)
        assert sig2 == (b'{"v":"ACDC10JSON0002e2_","d":"EcrRkKPunSlppq42NkHfZxyE3xOLGvvtu8'
                        b'-gUErzIgRg","i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EZllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EH-Po1gxypl7l4Ki'
                        b'l8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                        b'ymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8NgD8dDHLgazBx'
                        b'Tqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--FABErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYfta'
                        b'JsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAIsxxjXbQudWCGExAQuam77Bd'
                        b'VglElupgAbUIBxJi5p0gx1t_2JJ509n7QJshyAEDSa1pmO4UPmpA0b2Sgwk0AQ')

        # Sign with transferable identifier with specific set of paths
        sig3 = signing.ratify(sidHab, cred, paths=paths)
        assert sig3 == (b'{"v":"ACDC10JSON0002e2_","d":"EcrRkKPunSlppq42NkHfZxyE3xOLGvvtu8'
                        b'-gUErzIgRg","i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EZllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EH-Po1gxypl7l4Ki'
                        b'l8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                        b'ymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8NgD8dDHLgazBx'
                        b'Tqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--FABEr'
                        b'O8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAA'
                        b'AAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAIsxxjXbQudWC'
                        b'GExAQuam77BdVglElupgAbUIBxJi5p0gx1t_2JJ509n7QJshyAEDSa1pmO4UPmpA'
                        b'0b2Sgwk0AQ-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7Sd'
                        b'G0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VE'
                        b't7SdG0wh50-AABAAQsMW1jWrBOHO7-x6qWn9afdQP_bsbZ5nKLPC02MRmVmAu5ex'
                        b'al2FgC0Tn4OTSzzMZu0-0a2vk0I7R-7riPUnCA-JAB4AADA-a-personal-FABEr'
                        b'O8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAA'
                        b'AAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAzwL1MASfBplH'
                        b'3RRW-l51-RS8H0ahSNmQMCZlb0CxX2VNrvkqePjjNv3tIocjapf5pHx8Y7TNUKsQ'
                        b'FjK6-qxACA')

    # Test multisig identifier
    with configing.openCF(name="mel", base="mel", temp=True) as cf, \
            habbing.openHby(name="mel", temp=True, salt=coring.Salter(raw=b'0123456789abcdef').qb64b,
                            base="mel", cf=cf) as hby:
        hab = hby.makeHab(name="mel", icount=3, isith=3, ncount=3, nsith=3)
        seeder.seedSchema(hby.db)

        md = dict(
            d="",
            i="EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
            dt="2021-06-09T17:35:54.169967+00:00",
            LEI="254900OPPU84GM83MG36"
        )
        regery = credentialing.Regery(hby=hby, name="bob", temp=True)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=md, source={}, status=issuer.regk)

        # Sign with multisig transferable identifier defaults to single signature on entire SAD
        sig1 = signing.ratify(hab=hab, serder=cred)
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EPh3AoEaI6TZlwosOhZ1x92k6IgF_EXQhr'
                        b'fDhdlusFck","i":"EJOvY0hgm0Pfw2dg39rwuhGh7B0t3J8JIZkLIk5R-rPs","'
                        b'ri":"EcR468W4Lf7ARMRJxmvWPkhxl5KJV2uUkfsO2TfK9tfg","s":"ExBYRwKd'
                        b'VGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","a":{"d":"EleCRONxsoQpnG82'
                        b'kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--FABEJOvY0hgm0Pfw2dg39'
                        b'rwuhGh7B0t3J8JIZkLIk5R-rPs0AAAAAAAAAAAAAAAAAAAAAAAEJOvY0hgm0Pfw2'
                        b'dg39rwuhGh7B0t3J8JIZkLIk5R-rPs-AADAAbO4bWIxQmIZaBK0kwvLUn3wcAmEo'
                        b'VGNrJcFQQMNeX5CXmpA2u09qqK8VQBFr9A2Ce_KPc1p9fpVP_1FCyGEXAQABveCU'
                        b'_g8dZ-QptbRey0eKVZ6h06RAVHpWlIQrEYBP-UBEamD9rP5M7LgScxCBvcNUCbZw'
                        b'qLJLnxAs72fn2av0AgAC9s53t3EQN8SHI73Jj8XTVlvMsT-PVOGoIaaluNpsNb3o'
                        b'jo4UKiK7XJ2lKNTY0gR6-5cIgB6xs9IxS6uaKMD-Bw')

        iss = issuer.issue(said=cred.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

        parsing.Parser().parse(ims=sig1, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

    """End Test"""


def test_signature_transposition(seeder, mockCoringRandomNonce):
    d = dict(
        d="",
        i="EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
        dt="2021-06-09T17:35:54.169967+00:00",
        LEI="254900OPPU84GM83MG36"
    )

    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        seeder.seedSchema(db=hby.db)
        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=d, source={}, status=issuer.regk)

        # Sign with non-transferable identifier, defaults to single signature on entire SAD
        sig0 = signing.ratify(hab=hab, serder=cred)
        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EEkeSkBARQU5Lt_gi-GUlEx3LJ7OZdfW5n'
                        b'Y-y9KX3QVk","i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","'
                        b'ri":"Es6mQyppwSSN8ZpgGc0wV1iYLsqinZ11I56iHxWUzUuw","s":"ExBYRwKd'
                        b'VGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","a":{"d":"EleCRONxsoQpnG82'
                        b'kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--FABErO8qhYftaJsAbCb6H'
                        b'UrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAA-TcfdDgPVs9IeC7X2YZO1JFtQFVA'
                        b'qM_UFafLwWW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlxRyJ8UEn4ffAQ')

        iss = issuer.issue(said=cred.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

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
        assert sigers[0].qb64b == (b'AA-TcfdDgPVs9IeC7X2YZO1JFtQFVAqM_UFafLwWW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlx'
                                   b'RyJ8UEn4ffAQ')

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
        assert sigers[0].qb64b == (b'AA-TcfdDgPVs9IeC7X2YZO1JFtQFVAqM_UFafLwWW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlx'
                                   b'RyJ8UEn4ffAQ')

        # embed the credential in an exn and transpose the signature
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a"]))
        exn = exchanging.exchange(route="/credential/issue", payload=scre.crd, date="2022-01-04T11:58:55.154502+00:00")
        msg = hab.endorse(serder=exn)
        msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars))

        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"E7wllQ4Ywe58X6MtVG4PrZtQ'
                       b'Xt6G03fMiiqGMtrNbyjg","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"EEkeSkBA'
                       b'RQU5Lt_gi-GUlEx3LJ7OZdfW5nY-y9KX3QVk","i":"ErO8qhYftaJsAbCb6HUrN'
                       b'4tUyrV9dMd2VEt7SdG0wh50","ri":"Es6mQyppwSSN8ZpgGc0wV1iYLsqinZ11I'
                       b'56iHxWUzUuw","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",'
                       b'"a":{"d":"EleCRONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"Ehw'
                       b'C_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:3'
                       b'5:54.169967+00:00","LEI":"254900OPPU84GM83MG36"},"e":{}}}-VA0-FA'
                       b'BErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAA'
                       b'AAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAbxVvMOA-Y'
                       b'_9JAEKBzcQyEk_TIimGzTKlHg2QTETrGEArLig2YfsJnWxEN6dNKEDE2wCtnWxxX'
                       b'z9nDMuMFNYqDw-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt'
                       b'7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd'
                       b'2VEt7SdG0wh50-AABAA-TcfdDgPVs9IeC7X2YZO1JFtQFVAqM_UFafLwWW_Bogu0'
                       b'wy0qPtXSHfOOzPfWsfUBixvJhgGlxRyJ8UEn4ffAQ')

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

    # multiple path sigs
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        seeder.seedSchema(db=hby.db)
        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=d, source={}, status=issuer.regk)

        # sign with single sig transferable identfier with multiple specified paths
        sig1 = signing.ratify(hab=hab, serder=cred, paths=[[], ["a"], ["a", "i"]])
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EEkeSkBARQU5Lt_gi-GUlEx3LJ7OZdfW5n'
                        b'Y-y9KX3QVk","i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","'
                        b'ri":"Es6mQyppwSSN8ZpgGc0wV1iYLsqinZ11I56iHxWUzUuw","s":"ExBYRwKd'
                        b'VGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","a":{"d":"EleCRONxsoQpnG82'
                        b'kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-KAD6AABAAA--JAB6AABAAA--FABErO8qh'
                        b'YftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAEr'
                        b'O8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAA-TcfdDgPVs9IeC7X'
                        b'2YZO1JFtQFVAqM_UFafLwWW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlxRyJ8UE'
                        b'n4ffAQ-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh'
                        b'500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7Sd'
                        b'G0wh50-AABAAljDTBx1Dboc1O1YSBYzdiAXH0Vj50MDTdNEf71q8qFbip5gjH9el'
                        b'vVIB6jDeEWY_iTG6Dc9D0zd3NO0QeQJzDg-JAB4AAB-a-i-FABErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYfta'
                        b'JsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAASkVgGSxVHfa9d1OaV7W9VCs6'
                        b'3H3AqAiQOtj-fJRUIAcHR4hrVgQtGyGl-WOisK97zqrrXxoDXh-8AJ9gSulnDQ')

        # Issue the credential and parse into credential store
        iss = issuer.issue(said=cred.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre, regd=iss.said, seqner=seqner, saider=hab.kever.serder.saider)
        regery.processEscrows()

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
        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"E7wllQ4Ywe58X6MtVG4PrZtQ'
                       b'Xt6G03fMiiqGMtrNbyjg","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"EEkeSkBA'
                       b'RQU5Lt_gi-GUlEx3LJ7OZdfW5nY-y9KX3QVk","i":"ErO8qhYftaJsAbCb6HUrN'
                       b'4tUyrV9dMd2VEt7SdG0wh50","ri":"Es6mQyppwSSN8ZpgGc0wV1iYLsqinZ11I'
                       b'56iHxWUzUuw","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",'
                       b'"a":{"d":"EleCRONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"Ehw'
                       b'C_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:3'
                       b'5:54.169967+00:00","LEI":"254900OPPU84GM83MG36"},"e":{}}}-VA0-FA'
                       b'BErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAA'
                       b'AAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAbxVvMOA-Y'
                       b'_9JAEKBzcQyEk_TIimGzTKlHg2QTETrGEArLig2YfsJnWxEN6dNKEDE2wCtnWxxX'
                       b'z9nDMuMFNYqDw-KAD6AABAAA--JAB5AACAA-a-a-i-FABErO8qhYftaJsAbCb6HU'
                       b'rN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbC'
                       b'b6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAASkVgGSxVHfa9d1OaV7W9VCs63H3Aq'
                       b'AiQOtj-fJRUIAcHR4hrVgQtGyGl-WOisK97zqrrXxoDXh-8AJ9gSulnDQ-JAB4AA'
                       b'B-a-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAA'
                       b'AAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAl'
                       b'jDTBx1Dboc1O1YSBYzdiAXH0Vj50MDTdNEf71q8qFbip5gjH9elvVIB6jDeEWY_i'
                       b'TG6Dc9D0zd3NO0QeQJzDg-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV'
                       b'9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4t'
                       b'UyrV9dMd2VEt7SdG0wh50-AABAA-TcfdDgPVs9IeC7X2YZO1JFtQFVAqM_UFafLw'
                       b'WW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlxRyJ8UEn4ffAQ')

    # signing SAD with non-transferable identifier
    with habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (hby, hab):
        seeder.seedSchema(db=hby.db)
        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=d, source={},
                                  status="Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE")

        # Sign with non-transferable identifier
        sig0 = signing.ratify(hab=hab, serder=cred)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EN_INhi3ROn4wCMP7IEW6pL9oeSvDf79EQ'
                        b'nWUZijJluo","i":"BBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq148","'
                        b'ri":"Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE","s":"ExBYRwKd'
                        b'VGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","a":{"d":"EleCRONxsoQpnG82'
                        b'kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--CABBBtKPeN9p4lum6qDRa'
                        b'28fDfVShFk6c39FlBgHBsCq1480B3qBqHAenL-XeNQPAT_e7fJV5I6UvqM2JKPQ8'
                        b'WwxkpVaPWA0EWRmchQB4aHRLWK992DftQ5FDQVGF4xRUrUJhAQ')

        pather = coring.Pather(path=["a", "b", "c"])
        cigars = hab.sign(ser=cred.raw,
                          verfers=hab.kever.verfers,
                          indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsC'
                      b'q1480B3qBqHAenL-XeNQPAT_e7fJV5I6UvqM2JKPQ8WwxkpVaPWA0EWRmchQB4aH'
                      b'RLWK992DftQ5FDQVGF4xRUrUJhAQ')

    """End Test"""
