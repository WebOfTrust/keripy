# -*- encoding: utf-8 -*-
"""
tests.app.signing module

"""

from keri.app import habbing, configing, keeping
from keri.app import signing
from keri.core import coring, parsing, eventing
from keri.core.eventing import SealEvent
from keri.db import basing
from keri.peer import exchanging
from keri.vc import proving
from keri.vdr import verifying, credentialing


def test_sad_signature(seeder, mockCoringRandomNonce):
    with (habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (sigHby, sidHab),
          habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):

        personal = dict(
            d="",
            n="Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY",
            personLegalName="Anna Jones",
            engagementContextRole="Project Manager",
        )

        _, sad = coring.Saider.saidify(sad=personal, label=coring.Ids.d)

        d = dict(
            d="",
            i="EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
            dt="2021-06-09T17:35:54.169967+00:00",
            ri="EBmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
            LEI="254900OPPU84GM83MG36",
            personal=sad,
        )

        # test source chaining with labeled edge
        s = [
            dict(qualifiedvLEIIssuervLEICredential="EAtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD")
        ]

        cred = proving.credential(schema="EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                                  issuer="EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                                  subject=d, source=s, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")
        paths = [[], ["a"], ["a", "personal"]]

        # Sign with non-transferable identifier, default to entire SAD
        sig0 = signing.ratify(wanHab, cred)
        assert sig0 == (b'{"v":"ACDC10JSON0002e2_","d":"EDpPbpTHDuKjCrU3sicPh4ROouX002CEym'
                    b'CynU6JzAcP","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                    b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                    b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EJguR7eLTEotOzb7'
                    b'G5lH9MX2qSPNtwk3N9KexelSa46O","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                    b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                    b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                    b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                    b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                    b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                    b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                    b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--CABBAbSj3jfaeJbpu'
                    b'qg0WtvHw31UoRZOnN_RZQYBwbAqteP0BCr7FQW6XYhF8qApskG0wiGwYUdQModn6'
                    b'Esgz42IXJkR-qFwbDhtdMvvetMbgjIHeq0X1z3vCdmsQ94JUMJVnYD')

        # sign with non-trans identifer with a specific set of paths
        sig1 = signing.ratify(wanHab, cred, paths=paths)
        assert sig1 == (b'{"v":"ACDC10JSON0002e2_","d":"EDpPbpTHDuKjCrU3sicPh4ROouX002CEym'
                    b'CynU6JzAcP","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                    b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                    b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EJguR7eLTEotOzb7'
                    b'G5lH9MX2qSPNtwk3N9KexelSa46O","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                    b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                    b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                    b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                    b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                    b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                    b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                    b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--CADBA'
                    b'bSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP0BCr7FQW6XYhF8qApskG0w'
                    b'iGwYUdQModn6Esgz42IXJkR-qFwbDhtdMvvetMbgjIHeq0X1z3vCdmsQ94JUMJVn'
                    b'YD-JAB5AABAA-a-CADBAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP0B'
                    b'C5u61NVldB8t-w6YMdjPpCDMhyRNE8H2mw6W-U106atufGpy7bvHSZn6yWbRmsc5'
                    b'bEt1n9__4Abb0aIKtmYhsN-JAB4AADA-a-personal-CADBAbSj3jfaeJbpuqg0W'
                    b'tvHw31UoRZOnN_RZQYBwbAqteP0BAPZ92lw8F2_Ap81vFpyQsuTU9l7tOLI2Zmqa'
                    b'nKOMVd2ar-m16JjA38PPH_mBFasyadIQgyun410RpxCUvsIBAH')

        # Sign with transferable identifier defaults to single signature on entire SAD
        sig2 = signing.ratify(sidHab, cred)
        assert sig2 == (b'{"v":"ACDC10JSON0002e2_","d":"EDpPbpTHDuKjCrU3sicPh4ROouX002CEym'
                    b'CynU6JzAcP","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                    b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                    b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EJguR7eLTEotOzb7'
                    b'G5lH9MX2qSPNtwk3N9KexelSa46O","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                    b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                    b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                    b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                    b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                    b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                    b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                    b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--FABEKC8085pwSwzLw'
                    b'UGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwS'
                    b'wzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAAAlVqBLoin0EyBZolKtqAAgts'
                    b'793dPyuMVgWLsLUo0bUxkUsDMUYjWxPJ8LmxGKIByT_MDYeZO2iQxq3Y9vRswP')

        # Sign with transferable identifier with specific set of paths
        sig3 = signing.ratify(sidHab, cred, paths=paths)
        assert sig3 == (b'{"v":"ACDC10JSON0002e2_","d":"EDpPbpTHDuKjCrU3sicPh4ROouX002CEym'
                    b'CynU6JzAcP","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                    b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                    b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EJguR7eLTEotOzb7'
                    b'G5lH9MX2qSPNtwk3N9KexelSa46O","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                    b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","ri":"E'
                    b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                    b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                    b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                    b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                    b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                    b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--FABEK'
                    b'C8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAA'
                    b'AAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAAAlVqBLoin0Ey'
                    b'BZolKtqAAgts793dPyuMVgWLsLUo0bUxkUsDMUYjWxPJ8LmxGKIByT_MDYeZO2iQ'
                    b'xq3Y9vRswP-JAB5AABAA-a-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5a'
                    b'tdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27b'
                    b'Vp5atdMT9o-AABAACrTwe8c_gE1UPvmHYiOkV0c6jCLRirreLx5zdBtR34wfDbCI'
                    b'0v8hDGOU4aeoFz3wmXlrXkZQcPFd7eFY1iH20E-JAB4AADA-a-personal-FABEK'
                    b'C8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAA'
                    b'AAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAACUs3V7O3fRGm'
                    b'i_-X8xo8UFw7rGEQ0CYyfK7U1URYBwtW546a1pVJZ_c1wzcTXWLDj7OPPNrAQx2e'
                    b'm5sNrOMPcH')

    # Test multisig identifier
    with configing.openCF(name="mel", base="mel", temp=True) as cf, \
            habbing.openHby(name="mel", temp=True, salt=coring.Salter(raw=b'0123456789abcdef').qb64b,
                            base="mel", cf=cf) as hby:
        hab = hby.makeHab(name="mel", icount=3, isith='3', ncount=3, nsith='3')
        seeder.seedSchema(hby.db)

        md = dict(
            d="",
            i="EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
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

        cred = proving.credential(schema="EABYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
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
        assert pather.bext == "-"
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
        assert pather.bext == "-a-b-c"  # new emdded location
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

        assert msg == (b'{"v":"KERI10JSON000211_","t":"exn","d":"E7DVj7iNeIAGO-XqXFLqOisv'
                       b'RyDw9ut0EiVNkyr6NEFI","r":"/credential/issue","a":{"v":"ACDC10JS'
                       b'ON00019e_","d":"EEkeSkBARQU5Lt_gi-GUlEx3LJ7OZdfW5nY-y9KX3QVk","i'
                       b'":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","ri":"Es6mQyppw'
                       b'SSN8ZpgGc0wV1iYLsqinZ11I56iHxWUzUuw","s":"ExBYRwKdVGTWFq1M3Irewj'
                       b'KRhKusW9p9fdsdD0aSTWQI","a":{"d":"EleCRONxsoQpnG82kdu68VfQjvdbsc'
                       b'IlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c'
                       b'0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM'
                       b'83MG36"},"e":{}}}-VA0-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG'
                       b'0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt'
                       b'7SdG0wh50-AABAAPT2XjJ7ZfUVnuIsWegl1XJnOA0udZzaFpzM491u2GYNyp3V_c'
                       b'JLCcRjth3FOb37yCZLGhwmquyPZWMsroKpKAg-JAB5AABAA-a-FABErO8qhYftaJ'
                       b'sAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhY'
                       b'ftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAA-TcfdDgPVs9IeC7X2YZO1'
                       b'JFtQFVAqM_UFafLwWW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlxRyJ8UEn4ffAQ')

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
        assert msg == (b'{"v":"KERI10JSON000211_","t":"exn","d":"E7DVj7iNeIAGO-XqXFLqOisv'
                       b'RyDw9ut0EiVNkyr6NEFI","r":"/credential/issue","a":{"v":"ACDC10JS'
                       b'ON00019e_","d":"EEkeSkBARQU5Lt_gi-GUlEx3LJ7OZdfW5nY-y9KX3QVk","i'
                       b'":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","ri":"Es6mQyppw'
                       b'SSN8ZpgGc0wV1iYLsqinZ11I56iHxWUzUuw","s":"ExBYRwKdVGTWFq1M3Irewj'
                       b'KRhKusW9p9fdsdD0aSTWQI","a":{"d":"EleCRONxsoQpnG82kdu68VfQjvdbsc'
                       b'IlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c'
                       b'0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM'
                       b'83MG36"},"e":{}}}-VA0-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG'
                       b'0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt'
                       b'7SdG0wh50-AABAAPT2XjJ7ZfUVnuIsWegl1XJnOA0udZzaFpzM491u2GYNyp3V_c'
                       b'JLCcRjth3FOb37yCZLGhwmquyPZWMsroKpKAg-KAD6AABAAA--JAB5AACAA-a-a-'
                       b'i-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAA'
                       b'AAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAASkVgG'
                       b'SxVHfa9d1OaV7W9VCs63H3AqAiQOtj-fJRUIAcHR4hrVgQtGyGl-WOisK97zqrrX'
                       b'xoDXh-8AJ9gSulnDQ-JAB4AAB-a-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd'
                       b'2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV'
                       b'9dMd2VEt7SdG0wh50-AABAAljDTBx1Dboc1O1YSBYzdiAXH0Vj50MDTdNEf71q8q'
                       b'Fbip5gjH9elvVIB6jDeEWY_iTG6Dc9D0zd3NO0QeQJzDg-JAB5AABAA-a-FABErO'
                       b'8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAA'
                       b'AErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAA-TcfdDgPVs9Ie'
                       b'C7X2YZO1JFtQFVAqM_UFafLwWW_Bogu0wy0qPtXSHfOOzPfWsfUBixvJhgGlxRyJ'
                       b'8UEn4ffAQ')

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


def test_signatory():
    salt = coring.Salter(raw=b'0123456789abcdef')  # init sig Salter

    with basing.openDB(name="sig") as db, keeping.openKS(name="sig") as ks, \
            habbing.openHab(name="sig", salt=salt.raw) as (sigHby, sigHab):
        # Init signatory
        signer = sigHby.signator

        assert signer.pre == 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
        assert signer._hab.kever.verfers[0].qb64b == b'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
        spre = signer.db.hbys .get(habbing.SIGNER)
        assert spre == signer.pre

        raw = b'this is the raw data'
        cig = signer.sign(ser=raw)
        assert cig.qb64b == (b'0BBcREN6U3eyPXDnRaDrRBgA7JECxr8fAqTHvbLY8RzMBIQr1'
                             b'Qoz9H5d0aPM1EbKFP1DcT1zadxb'
                             b'eEQciT0lkysL')

        assert signer.verify(ser=raw, cigar=cig) is True

        bad = b'0BAh1y8Dq7Pj7xbEj6Ja-ew9nzu-bX5_wQKu5Yw3472-ghptsrEFDyD6o4Lk0L7Ym9oWCuGj_UAc-ltI9p7F9999'
        badcig = coring.Cigar(qb64b=bad)
        assert signer.verify(ser=raw, cigar=badcig) is False

        verfer = coring.Verfer(qb64=spre)
        assert verfer.verify(cig.raw, raw) is True

        # Create a second, should have the same key
        mgr = keeping.Manager(ks=ks, salt=salt.qb64)
        kvy = eventing.Kevery(db=db)
        sig2 = habbing.Signator(db=db, temp=True, ks=ks, mgr=mgr, cf=sigHab.cf, rtr=None,
                                rvy=None, kvy=kvy, psr=None)
        assert sig2._hab.pre == spre
        assert sig2._hab.kever.verfers[0].qb64b == spre.encode("utf-8")
        assert sig2.verify(ser=raw, cigar=cig) is True
        cig2 = sig2.sign(ser=raw)
        assert cig2.qb64b == cig2.qb64b
        assert signer.verify(ser=raw, cigar=cig2) is True

        raw2 = b'second text to sign that is a little longer'
        cig3 = sig2.sign(ser=raw2)
        assert cig3.qb64b == (b'0BD9VxJWhKcaTxMwKMFmtXPwf-ABW8bpqiCjBozfrBBm637'
                              b'dk81yqgr_kvD7aaKmi4Dw7wgmmLXx'
                              b'i0nhP08Jpo0B')
        assert signer.verify(ser=raw2, cigar=cig3) is True

