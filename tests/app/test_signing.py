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

        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, subject=md, source={}, status=issuer.regk)

        # Sign with multisig transferable identifier defaults to single signature on entire SAD
        sig1 = signing.ratify(hab=hab, serder=cred)
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EJMGaIVWoVNSPDUFUjXy5dDMPCPSawGW42'
                        b'KtDCmBlWXF","i":"EKMHlh4epBApuYP-3-A_ZldeImCa6WxLe8Nmzhy-SvWB","'
                        b'ri":"ELIc0Va2OSemOpuiD2Fxfzd2yXg6CWibjOCJY3vNFLb9","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EEpkgFjaZEvmXRri'
                        b'kXjKZ9MjYumQEoornorJjFOm40z_","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--FABEKMHlh4epBApuYP-3-'
                        b'A_ZldeImCa6WxLe8Nmzhy-SvWB0AAAAAAAAAAAAAAAAAAAAAAAEKMHlh4epBApuY'
                        b'P-3-A_ZldeImCa6WxLe8Nmzhy-SvWB-AADAADl71ALjV2CRm8d8SKIXnxV67y1wS'
                        b'BTxkItOMqH73DCTsKLHx9G7ZoQUIoB-cCEgNwOsEVFU2PARWyyKBEUFqgCABAc75'
                        b'4TEeNOb5wkRNvNe1IVtdwJUztl6tEZIGnXGVUrjt82VXY7b9hH7RCYka5KnNd7BL'
                        b'J2G4usjRGn9PcoiYcCACB-icSPzASxUr1bFLZUnppz-n-WWI1saED11_rjzviyFk'
                        b'0-Yw6sJH05JiFMpYY6_OES3_zd2a7iyBHLNBQqzDcG')

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

        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, subject=d, source={}, status=issuer.regk)

        # Sign with non-transferable identifier, defaults to single signature on entire SAD
        sig0 = signing.ratify(hab=hab, serder=cred)
        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EBEjsD3UnYOfqMwmoevTuNW5Il5OXnDRcZ'
                        b'jgAV7Z48F_","i":"EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o","'
                        b'ri":"ENzh5cyGjFhQYuIXuheXV2wkKp23rkxYI7wbEBQIyqhP","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EJXgkTjcbKEKZxvN'
                        b'pHbuvFX0I73W7HCJQLkIgzo3XEeL","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--FABEKC8085pwSwzLwUGzh'
                        b'-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLw'
                        b'UGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAADVXzDmQ1xYBj6VorSsRBNow-gO7_'
                        b'jmfQzkT2_1VgQkY31pnkaxv6_IJRkEt__S2GZKyQPdpxgz9idVw7ZFZJEB')

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
        assert sigers[0].qb64b == (b'AADVXzDmQ1xYBj6VorSsRBNow-gO7_jmfQzkT2_1VgQkY31pnkaxv6_IJRkEt__S2GZKyQPdpxgz'
                                   b'9idVw7ZFZJEB')

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
        assert sigers[0].qb64b == (b'AADVXzDmQ1xYBj6VorSsRBNow-gO7_jmfQzkT2_1VgQkY31pnkaxv6_IJRkEt__S2GZKyQPdpxgz'
                                   b'9idVw7ZFZJEB')

        # embed the credential in an exn and transpose the signature
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a"]))
        exn = exchanging.exchange(route="/credential/issue", payload=scre.crd, date="2022-01-04T11:58:55.154502+00:00")
        msg = hab.endorse(serder=exn)
        msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars))

        assert msg == (b'{"v":"KERI10JSON000211_","t":"exn","d":"EJgkXFsu2JsR6AmxxbhsI-Bp'
                       b'0lGicINL7Vx0zdjd80kL","r":"/credential/issue","a":{"v":"ACDC10JS'
                       b'ON00019e_","d":"EBEjsD3UnYOfqMwmoevTuNW5Il5OXnDRcZjgAV7Z48F_","i'
                       b'":"EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o","ri":"ENzh5cyGj'
                       b'FhQYuIXuheXV2wkKp23rkxYI7wbEBQIyqhP","s":"EMQWEcCnVRk1hatTNyK3sI'
                       b'ykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EJXgkTjcbKEKZxvNpHbuvFX0I73W7H'
                       b'CJQLkIgzo3XEeL","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c'
                       b'0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM'
                       b'83MG36"},"e":{}}}-VA0-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5at'
                       b'dMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bV'
                       b'p5atdMT9o-AABAAC7sujPT1BiHBnB9zo5ncKLOV5xej5u-3Mkm8zYvq5YT-0e_j1'
                       b'xblbUOQeQPJUrCz8yl6Lj_YFTCJfLp4Dh1aoH-JAB5AABAA-a-FABEKC8085pwSw'
                       b'zLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085'
                       b'pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAADVXzDmQ1xYBj6VorSsRBN'
                       b'ow-gO7_jmfQzkT2_1VgQkY31pnkaxv6_IJRkEt__S2GZKyQPdpxgz9idVw7ZFZJEB')

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

        # where is this schema to be found?
        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, subject=d, source={}, status=issuer.regk)

        # sign with single sig transferable identfier with multiple specified paths
        # Bad magic values here but can't figure out where looks like Sadder Said seeder
        # is using a bad magic value
        sig1 = signing.ratify(hab=hab, serder=cred, paths=[[], ["a"], ["a", "i"]])
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EBEjsD3UnYOfqMwmoevTuNW5Il5OXnDRcZ'
                        b'jgAV7Z48F_","i":"EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o","'
                        b'ri":"ENzh5cyGjFhQYuIXuheXV2wkKp23rkxYI7wbEBQIyqhP","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EJXgkTjcbKEKZxvN'
                        b'pHbuvFX0I73W7HCJQLkIgzo3XEeL","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-KAD6AABAAA--JAB6AABAAA--FABEKC808'
                        b'5pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEK'
                        b'C8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAADVXzDmQ1xYBj6Vor'
                        b'SsRBNow-gO7_jmfQzkT2_1VgQkY31pnkaxv6_IJRkEt__S2GZKyQPdpxgz9idVw7'
                        b'ZFZJEB-JAB5AABAA-a-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT'
                        b'9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5a'
                        b'tdMT9o-AABAADT5lxcXQQ-p1dYbKYMTRCFg_mereYc0tlgggcz2U9At68GM9oUT-'
                        b'ukw4bB_cB-buBeHJbMgf7r6zyDYPCbL_AN-JAB4AAB-a-i-FABEKC8085pwSwzLw'
                        b'UGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwS'
                        b'wzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAAA1YtySryE-T91d8BW7tgsKpd'
                        b'ujDNg1eAXeBu89gQSKOmKpCuFPGxsvzgxfQIWC7hRG9cSZ0NeuMOE8E6cZ4osE')

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
        assert msg == (b'{"v":"KERI10JSON000211_","t":"exn","d":"EJgkXFsu2JsR6AmxxbhsI-Bp'
                       b'0lGicINL7Vx0zdjd80kL","r":"/credential/issue","a":{"v":"ACDC10JS'
                       b'ON00019e_","d":"EBEjsD3UnYOfqMwmoevTuNW5Il5OXnDRcZjgAV7Z48F_","i'
                       b'":"EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o","ri":"ENzh5cyGj'
                       b'FhQYuIXuheXV2wkKp23rkxYI7wbEBQIyqhP","s":"EMQWEcCnVRk1hatTNyK3sI'
                       b'ykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EJXgkTjcbKEKZxvNpHbuvFX0I73W7H'
                       b'CJQLkIgzo3XEeL","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c'
                       b'0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM'
                       b'83MG36"},"e":{}}}-VA0-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5at'
                       b'dMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bV'
                       b'p5atdMT9o-AABAAC7sujPT1BiHBnB9zo5ncKLOV5xej5u-3Mkm8zYvq5YT-0e_j1'
                       b'xblbUOQeQPJUrCz8yl6Lj_YFTCJfLp4Dh1aoH-KAD6AABAAA--JAB5AACAA-a-a-'
                       b'i-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAA'
                       b'AAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAAA1Yty'
                       b'SryE-T91d8BW7tgsKpdujDNg1eAXeBu89gQSKOmKpCuFPGxsvzgxfQIWC7hRG9cS'
                       b'Z0NeuMOE8E6cZ4osE-JAB4AAB-a-a-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq'
                       b'27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZ'
                       b'nCJq27bVp5atdMT9o-AABAADT5lxcXQQ-p1dYbKYMTRCFg_mereYc0tlgggcz2U9'
                       b'At68GM9oUT-ukw4bB_cB-buBeHJbMgf7r6zyDYPCbL_AN-JAB5AABAA-a-FABEKC'
                       b'8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAA'
                       b'AEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAADVXzDmQ1xYBj6'
                       b'VorSsRBNow-gO7_jmfQzkT2_1VgQkY31pnkaxv6_IJRkEt__S2GZKyQPdpxgz9id'
                       b'Vw7ZFZJEB')

    # signing SAD with non-transferable identifier
    with habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (hby, hab):
        seeder.seedSchema(db=hby.db)
        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, subject=d, source={},
                                  status="Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE")

        # Sign with non-transferable identifier
        sig0 = signing.ratify(hab=hab, serder=cred)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EAB52mRhH-NrEijXMv7I3I6cljI6k6bMFZ'
                        b'T1cKUfOMU6","i":"BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP","'
                        b'ri":"Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EJXgkTjcbKEKZxvN'
                        b'pHbuvFX0I73W7HCJQLkIgzo3XEeL","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00:00","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--CABBAbSj3jfaeJbpuqg0W'
                        b'tvHw31UoRZOnN_RZQYBwbAqteP0BD_BCAVawYlw1uTXRpD6Q208UV_Ll8YPVf71M'
                        b'ick0z6vnIYgRJbTEatfN1JBiTWvGnz_cOxTVyAJMAp59AaFbIC')

        pather = coring.Pather(path=["a", "b", "c"])
        cigars = hab.sign(ser=cred.raw,
                          verfers=hab.kever.verfers,
                          indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbA'
                      b'qteP0BD_BCAVawYlw1uTXRpD6Q208UV_Ll8YPVf71Mick0z6vnIYgRJbTEatfN1J'
                      b'BiTWvGnz_cOxTVyAJMAp59AaFbIC')
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

