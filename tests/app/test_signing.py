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


def test_sad_signature(seeder):
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
        assert sig0 == (b'{"v":"ACDC10JSON0002e2_","d":"EPzhywjModRy9A8gD0qmw85A0iGucR8Uab'
                        b'2zPRLzkSuI","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"EH-P'
                        b'o1gxypl7l4Kil8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"2'
                        b'54900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8N'
                        b'gD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOI'
                        b'HUjY","personLegalName":"Anna Jones","engagementContextRole":"Pr'
                        b'oject Manager"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGty'
                        b'ThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}],"ri":"ETQoH02zJRCT'
                        b'Nz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M"}-JAB6AABAAA--CABBBtKPeN9p4lum6'
                        b'qDRa28fDfVShFk6c39FlBgHBsCq1480BWviNb9MbWbh9mwJ2VO2u71fLVR1CaGu5'
                        b'fzOQVcwYv8tQE9aQz6kj0rvXvikcxF5XG9ShoSihExV-u7SCA60-Cw')

        # sign with non-trans identifer with a specific set of paths
        sig1 = signing.ratify(wanHab, cred, paths=paths)
        assert sig1 == (b'{"v":"ACDC10JSON0002e2_","d":"EPzhywjModRy9A8gD0qmw85A0iGucR8Uab'
                        b'2zPRLzkSuI","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"EH-P'
                        b'o1gxypl7l4Kil8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"2'
                        b'54900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8N'
                        b'gD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOI'
                        b'HUjY","personLegalName":"Anna Jones","engagementContextRole":"Pr'
                        b'oject Manager"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGty'
                        b'ThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}],"ri":"ETQoH02zJRCT'
                        b'Nz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M"}-KAD6AABAAA--JAB6AABAAA--CADBB'
                        b'tKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480BWviNb9MbWbh9mwJ2VO2u'
                        b'71fLVR1CaGu5fzOQVcwYv8tQE9aQz6kj0rvXvikcxF5XG9ShoSihExV-u7SCA60-'
                        b'Cw-JAB5AABAA-a-CADBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq1480B'
                        b'LYDoLPoyUfH1n7t_bcP4ZmaseBXlWbmnbFCpylGyzttBTqUzI9iiHWAfyLkKMOvm'
                        b'_Qpz5ysS6IlNhEmPT5HfDQ-JAB4AADA-a-personal-CADBBtKPeN9p4lum6qDRa'
                        b'28fDfVShFk6c39FlBgHBsCq1480BJdTjYZ2A0kXZX7tLxKgju6ZP31-21J5Pl_VU'
                        b'mE-QGtl1h_GJb-aUox-UQLx_rum18xWhHi9zLSqFv5lY39FfBw')

        # Sign with transferable identifier defaults to single signature on entire SAD
        sig2 = signing.ratify(sidHab, cred)
        assert sig2 == (b'{"v":"ACDC10JSON0002e2_","d":"EPzhywjModRy9A8gD0qmw85A0iGucR8Uab'
                        b'2zPRLzkSuI","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"EH-P'
                        b'o1gxypl7l4Kil8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"2'
                        b'54900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8N'
                        b'gD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOI'
                        b'HUjY","personLegalName":"Anna Jones","engagementContextRole":"Pr'
                        b'oject Manager"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGty'
                        b'ThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}],"ri":"ETQoH02zJRCT'
                        b'Nz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M"}-JAB6AABAAA--FABErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYfta'
                        b'JsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAgl7hMZ0llrE5AABHTkiJFK65'
                        b'eSeliF7DEnkp_C0j3oBLlpbZcRwsGXiQZzRmtePTXzEJOND0y1TWpncUbSFyBA')

        # Sign with transferable identifier with specific set of paths
        sig3 = signing.ratify(sidHab, cred, paths=paths)
        assert sig3 == (b'{"v":"ACDC10JSON0002e2_","d":"EPzhywjModRy9A8gD0qmw85A0iGucR8Uab'
                        b'2zPRLzkSuI","s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","'
                        b'i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"EH-P'
                        b'o1gxypl7l4Kil8OxOS7jiEtWZh_sCYWBN0REFTLc","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","ri":"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"2'
                        b'54900OPPU84GM83MG36","personal":{"d":"ExSxzzsvGlhO6W0O1_-k5Api8N'
                        b'gD8dDHLgazBxTqi_z4","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOI'
                        b'HUjY","personLegalName":"Anna Jones","engagementContextRole":"Pr'
                        b'oject Manager"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EGty'
                        b'ThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}],"ri":"ETQoH02zJRCT'
                        b'Nz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M"}-KAD6AABAAA--JAB6AABAAA--FABEr'
                        b'O8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAA'
                        b'AAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAgl7hMZ0llrE5'
                        b'AABHTkiJFK65eSeliF7DEnkp_C0j3oBLlpbZcRwsGXiQZzRmtePTXzEJOND0y1TW'
                        b'pncUbSFyBA-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7Sd'
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
        verifier = verifying.Verifier(hby=hby)
        issuer = issuing.Issuer(hab=hab, reger=verifier.reger)

        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=md, source={}, status=issuer.regk)

        # Sign with multisig transferable identifier defaults to single signature on entire SAD
        sig1 = signing.ratify(hab=hab, serder=cred)
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EZADKHPCWLRwSuuuB7q4d0TywasW0CqStW'
                        b'AhQvlRvKlw","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                        b'i":"EJOvY0hgm0Pfw2dg39rwuhGh7B0t3J8JIZkLIk5R-rPs","a":{"d":"EleC'
                        b'RONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EqHRzdfr0HuRYDZx'
                        b'4xmyFHnQ_U1n3z54SO7tu02ebn3c"}-JAB6AABAAA--FABEJOvY0hgm0Pfw2dg39'
                        b'rwuhGh7B0t3J8JIZkLIk5R-rPs0AAAAAAAAAAAAAAAAAAAAAAAEJOvY0hgm0Pfw2'
                        b'dg39rwuhGh7B0t3J8JIZkLIk5R-rPs-AADAAHjs0y94XBmtTR7JuCpRrvbuNCFWl'
                        b'8mnI1VTDhxtAb1tLrtuq1kd47u-ZRfR9pa7WzSzOWf8SNUfn0VJYw0uhBQABSDSc'
                        b'9lrqeEC_IxGaA59E5ne8-Js2rGMKfp7SN1nFmeO7LFy6x9SBrDgO-lc56bnbImw-'
                        b'vSj7vHJui9mkJJ44BgACE8WS2sF1xBMfcKHdib2A5xjKYPJz_wUU4DkvtLVI9LoX'
                        b'om_q7VBsu7onxmRTarjzAmNg9OY93W_d1IUF4RVgAA')

        issuer.issue(creder=cred)
        parsing.Parser().parse(ims=sig1, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

    """End Test"""


def test_signature_transposition(seeder):
    d = dict(
        d="",
        i="EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
        dt="2021-06-09T17:35:54.169967+00:00",
        LEI="254900OPPU84GM83MG36"
    )

    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        seeder.seedSchema(db=hby.db)
        verifier = verifying.Verifier(hby=hby)
        issuer = issuing.Issuer(hab=hab, reger=verifier.reger)

        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=d, source={}, status=issuer.regk)

        # Sign with non-transferable identifier, defaults to single signature on entire SAD
        sig0 = signing.ratify(hab=hab, serder=cred)
        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EL8u7YWAv1TfVkSqKFCBZIiXyDWhIm6IBH'
                        b'qkI9yoEFuU","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                        b'i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","a":{"d":"EleC'
                        b'RONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EYzrBEAQFwt_X-BJ'
                        b'3aOcwHwacdwysMSWnMr5qDaiE7Ow"}-JAB6AABAAA--FABErO8qhYftaJsAbCb6H'
                        b'UrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAiK3dXF8AhwJuJmmsO3gTz4WDZAHZ'
                        b'lBCeKsukT8iPRLSKa2LtxU2MVjIScjOC4cVN54Kg1niMdOdAwMuwnPa_CQ')

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
        assert sigers[0].qb64b == (b'AAiK3dXF8AhwJuJmmsO3gTz4WDZAHZlBCeKsukT8iPRLSKa2LtxU2MVjIScjOC4cVN54Kg1niMdO'
                                   b'dAwMuwnPa_CQ')

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
        assert sigers[0].qb64b == (b'AAiK3dXF8AhwJuJmmsO3gTz4WDZAHZlBCeKsukT8iPRLSKa2LtxU2MVjIScjOC4cVN54Kg1niMdO'
                                   b'dAwMuwnPa_CQ')

        # embed the credential in an exn and transpose the signature
        scre, sadsigers, sadcigars = verifier.reger.cloneCred(said=cred.said, root=coring.Pather(path=["a"]))
        exn = exchanging.exchange(route="/credential/issue", payload=scre.crd, date="2022-01-04T11:58:55.154502+00:00")
        msg = hab.endorse(serder=exn)
        msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars))

        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"EpNjY-HFHATW-r1y1G3uzjdG'
                       b'Te4_QUgPhuQmnL5AyDc8","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"EL8u7YWA'
                       b'v1TfVkSqKFCBZIiXyDWhIm6IBHqkI9yoEFuU","s":"ExBYRwKdVGTWFq1M3Irew'
                       b'jKRhKusW9p9fdsdD0aSTWQI","i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VE'
                       b't7SdG0wh50","a":{"d":"EleCRONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR'
                       b'4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"202'
                       b'1-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM83MG36"},"e"'
                       b':{},"ri":"EYzrBEAQFwt_X-BJ3aOcwHwacdwysMSWnMr5qDaiE7Ow"}}-VA0-FA'
                       b'BErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAA'
                       b'AAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAW-52rDvrM'
                       b'8GNp6eSmOpOLoDl4rvPn-hYEjLWZ4fQgPcrIYtGlvIcyoesILWAc6wHHvADLTzgo'
                       b'Fj927KOY3VwCg-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt'
                       b'7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd'
                       b'2VEt7SdG0wh50-AABAAiK3dXF8AhwJuJmmsO3gTz4WDZAHZlBCeKsukT8iPRLSKa'
                       b'2LtxU2MVjIScjOC4cVN54Kg1niMdOdAwMuwnPa_CQ')

        # issue the credential
        issuer.issue(creder=cred)

        # parse the credential and verify it is saved in the credential store
        parsing.Parser().parse(ims=sig0, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

    # multiple path sigs
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        seeder.seedSchema(db=hby.db)
        verifier = verifying.Verifier(hby=hby)
        issuer = issuing.Issuer(hab=hab, reger=verifier.reger)

        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=d, source={}, status=issuer.regk)

        # sign with single sig transferable identfier with multiple specified paths
        sig1 = signing.ratify(hab=hab, serder=cred, paths=[[], ["a"], ["a", "i"]])
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EL8u7YWAv1TfVkSqKFCBZIiXyDWhIm6IBH'
                        b'qkI9yoEFuU","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                        b'i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50","a":{"d":"EleC'
                        b'RONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"EYzrBEAQFwt_X-BJ'
                        b'3aOcwHwacdwysMSWnMr5qDaiE7Ow"}-KAD6AABAAA--JAB6AABAAA--FABErO8qh'
                        b'YftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAEr'
                        b'O8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAiK3dXF8AhwJuJmms'
                        b'O3gTz4WDZAHZlBCeKsukT8iPRLSKa2LtxU2MVjIScjOC4cVN54Kg1niMdOdAwMuw'
                        b'nPa_CQ-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh'
                        b'500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7Sd'
                        b'G0wh50-AABAAljDTBx1Dboc1O1YSBYzdiAXH0Vj50MDTdNEf71q8qFbip5gjH9el'
                        b'vVIB6jDeEWY_iTG6Dc9D0zd3NO0QeQJzDg-JAB4AAB-a-i-FABErO8qhYftaJsAb'
                        b'Cb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYfta'
                        b'JsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAASkVgGSxVHfa9d1OaV7W9VCs6'
                        b'3H3AqAiQOtj-fJRUIAcHR4hrVgQtGyGl-WOisK97zqrrXxoDXh-8AJ9gSulnDQ')

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
        assert msg == (b'{"v":"KERI10JSON000239_","t":"exn","d":"EpNjY-HFHATW-r1y1G3uzjdG'
                       b'Te4_QUgPhuQmnL5AyDc8","dt":"2022-01-04T11:58:55.154502+00:00","r'
                       b'":"/credential/issue","a":{"v":"ACDC10JSON00019e_","d":"EL8u7YWA'
                       b'v1TfVkSqKFCBZIiXyDWhIm6IBHqkI9yoEFuU","s":"ExBYRwKdVGTWFq1M3Irew'
                       b'jKRhKusW9p9fdsdD0aSTWQI","i":"ErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VE'
                       b't7SdG0wh50","a":{"d":"EleCRONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR'
                       b'4s","i":"EhwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"202'
                       b'1-06-09T17:35:54.169967+00:00","LEI":"254900OPPU84GM83MG36"},"e"'
                       b':{},"ri":"EYzrBEAQFwt_X-BJ3aOcwHwacdwysMSWnMr5qDaiE7Ow"}}-VA0-FA'
                       b'BErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAA'
                       b'AAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAW-52rDvrM'
                       b'8GNp6eSmOpOLoDl4rvPn-hYEjLWZ4fQgPcrIYtGlvIcyoesILWAc6wHHvADLTzgo'
                       b'Fj927KOY3VwCg-KAD6AABAAA--JAB5AACAA-a-a-i-FABErO8qhYftaJsAbCb6HU'
                       b'rN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbC'
                       b'b6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAASkVgGSxVHfa9d1OaV7W9VCs63H3Aq'
                       b'AiQOtj-fJRUIAcHR4hrVgQtGyGl-WOisK97zqrrXxoDXh-8AJ9gSulnDQ-JAB4AA'
                       b'B-a-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh500AAAAAAAAAA'
                       b'AAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4tUyrV9dMd2VEt7SdG0wh50-AABAAl'
                       b'jDTBx1Dboc1O1YSBYzdiAXH0Vj50MDTdNEf71q8qFbip5gjH9elvVIB6jDeEWY_i'
                       b'TG6Dc9D0zd3NO0QeQJzDg-JAB5AABAA-a-FABErO8qhYftaJsAbCb6HUrN4tUyrV'
                       b'9dMd2VEt7SdG0wh500AAAAAAAAAAAAAAAAAAAAAAAErO8qhYftaJsAbCb6HUrN4t'
                       b'UyrV9dMd2VEt7SdG0wh50-AABAAiK3dXF8AhwJuJmmsO3gTz4WDZAHZlBCeKsukT'
                       b'8iPRLSKa2LtxU2MVjIScjOC4cVN54Kg1niMdOdAwMuwnPa_CQ')

    # signing SAD with non-transferable identifier
    with habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (hby, hab):
        seeder.seedSchema(db=hby.db)
        cred = proving.credential(schema="ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI",
                                  issuer=hab.pre, subject=d, source={},
                                  status="Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE")

        # Sign with non-transferable identifier
        sig0 = signing.ratify(hab=hab, serder=cred)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"ExQiUc0S5SwfN8MA03T_7v_gYdguE-UuvT'
                        b'NXvtRFoW14","s":"ExBYRwKdVGTWFq1M3IrewjKRhKusW9p9fdsdD0aSTWQI","'
                        b'i":"BBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsCq148","a":{"d":"EleC'
                        b'RONxsoQpnG82kdu68VfQjvdbscIlAuQiDOjdcR4s","i":"EhwC_-ISX9helBDUS'
                        b'KU5j_VEU3G0Jp6ZFRD9dTb4-5c0","dt":"2021-06-09T17:35:54.169967+00'
                        b':00","LEI":"254900OPPU84GM83MG36"},"e":{},"ri":"Eg1H4eN7P5ndJAWt'
                        b'cymq3ZrYZwQsBRYd3-VuZ6wMAwxE"}-JAB6AABAAA--CABBBtKPeN9p4lum6qDRa'
                        b'28fDfVShFk6c39FlBgHBsCq1480BLtqJi259nMS2SG9lkiTspkIbTiJXAEJJv5s6'
                        b'vk7_KMZVYpt8Db7IkNWnekbT_J-X3VB2XfX4U5HOXSxiqei6Cw')

        pather = coring.Pather(path=["a", "b", "c"])
        cigars = hab.sign(ser=cred.raw,
                              verfers=hab.kever.verfers,
                              indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBBtKPeN9p4lum6qDRa28fDfVShFk6c39FlBgHBsC'
                      b'q1480BLtqJi259nMS2SG9lkiTspkIbTiJXAEJJv5s6vk7_KMZVYpt8Db7IkNWnek'
                      b'bT_J-X3VB2XfX4U5HOXSxiqei6Cw')

    """End Test"""

