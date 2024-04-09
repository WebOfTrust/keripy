# -*- encoding: utf-8 -*-
"""
tests.app.signing module

"""
from keri import core
from keri.core import coring, parsing, eventing
from keri.core.eventing import SealEvent

from keri.app import habbing, configing, keeping
from keri.app import signing

from keri.db import basing
from keri.vc import proving
from keri.vdr import verifying, credentialing


def test_sad_signature(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    with (habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (sigHby, sidHab),
          habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (wanHby, wanHab)):
        personal = dict(
            d="",
            n="Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY",
            personLegalName="Anna Jones",
            engagementContextRole="Project Manager",
        )

        _, sad = coring.Saider.saidify(sad=personal, label=coring.Saids.d)

        d = dict(
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
                                  recipient="EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0",
                                  data=d, source=s, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")
        paths = [[], ["a"], ["a", "personal"]]

        # Sign with non-transferable identifier, default to entire SAD
        sig0 = signing.ratify(wanHab, cred)
        assert sig0 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtSKl'
                        b'DJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","ri":'
                        b'"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1rLBSMZ'
                        b'_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQzDXg39j1b'
                        b'7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb'
                        b'4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"EBmRy7xMwsxUe'
                        b'lUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36","pers'
                        b'onal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4GswcU6ov8-","n":"Q8r'
                        b'NaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","personLegalName":"Anna '
                        b'Jones","engagementContextRole":"Project Manager"}},"e":[{"qualifie'
                        b'dvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU'
                        b'5sHYTGFD"}]}-JAB6AABAAA--CABBAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBw'
                        b'bAqteP0BApbos85syKE_VgfuNTtVRYkAlw5fwb_4ZWN-V-FFO_MrSGt71luX0rt-9e'
                        b'hNZFPHV1EuPc1YDQvZJ1XqPumewN')

        # sign with non-trans identifier with a specific set of paths
        sig1 = signing.ratify(wanHab, cred, paths=paths)
        assert sig1 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtSK'
                        b'lDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","ri'
                        b'":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1rLB'
                        b'SMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQzDXg3'
                        b'9j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFR'
                        b'D9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"EBmRy7x'
                        b'MwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36'
                        b'","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4GswcU6ov8-",'
                        b'"n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","personLegalNam'
                        b'e":"Anna Jones","engagementContextRole":"Project Manager"}},"e":['
                        b'{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_ozM1uAnFvSfC'
                        b'0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--CADBAbSj3jfaeJbpu'
                        b'qg0WtvHw31UoRZOnN_RZQYBwbAqteP0BApbos85syKE_VgfuNTtVRYkAlw5fwb_4Z'
                        b'WN-V-FFO_MrSGt71luX0rt-9ehNZFPHV1EuPc1YDQvZJ1XqPumewN-JAB5AABAA-a'
                        b'-CADBAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP0BC1HB3w11jDft8De'
                        b'EhpuRVWZknabe5omZZA0s4QqX2o1O3gSM-PrjYr6lXlvnQ4TU_PaeF70kSo--LA22'
                        b'kL2csA-JAB4AADA-a-personal-CADBAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQ'
                        b'YBwbAqteP0BAPZ92lw8F2_Ap81vFpyQsuTU9l7tOLI2ZmqanKOMVd2ar-m16JjA38'
                        b'PPH_mBFasyadIQgyun410RpxCUvsIBAH')

        # Sign with transferable identifier defaults to single signature on entire SAD
        sig2 = signing.ratify(sidHab, cred)
        assert sig2 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtSK'
                        b'lDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","ri'
                        b'":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1rLB'
                        b'SMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQzDXg3'
                        b'9j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFR'
                        b'D9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"EBmRy7x'
                        b'MwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36'
                        b'","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4GswcU6ov8-",'
                        b'"n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","personLegalNam'
                        b'e":"Anna Jones","engagementContextRole":"Project Manager"}},"e":['
                        b'{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_ozM1uAnFvSfC'
                        b'0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--FABEKC8085pwSwzLwUGzh-HrEoFDw'
                        b'ZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEo'
                        b'FDwZnCJq27bVp5atdMT9o-AABAABf42ZzPJkYp6fm6yMhqYqSOg9IAf8dmxpBRq22'
                        b'GNZTQaalCJIuAxCVT2GRiqs7z7Z5kIPy5yhR3DYVx2Y_Rj8N')

        # Sign with transferable identifier with specific set of paths
        sig3 = signing.ratify(sidHab, cred, paths=paths)
        assert sig3 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtSK'
                        b'lDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","ri'
                        b'":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1rLB'
                        b'SMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQzDXg3'
                        b'9j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFR'
                        b'D9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"EBmRy7x'
                        b'MwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36'
                        b'","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4GswcU6ov8-",'
                        b'"n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","personLegalNam'
                        b'e":"Anna Jones","engagementContextRole":"Project Manager"}},"e":['
                        b'{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_ozM1uAnFvSfC'
                        b'0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--FABEKC8085pwSwzLw'
                        b'UGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSw'
                        b'zLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAABf42ZzPJkYp6fm6yMhqYqSOg9I'
                        b'Af8dmxpBRq22GNZTQaalCJIuAxCVT2GRiqs7z7Z5kIPy5yhR3DYVx2Y_Rj8N-JAB5'
                        b'AABAA-a-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAA'
                        b'AAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAAB'
                        b'B5IVZOhEfcH4TBQgOCyMgyQrJujtBBjT8K_zTPk0-FLMtTZuBgXV7jnLw6fDe6FWt'
                        b'zshh2HGCL_H_j4i1b9kF-JAB4AADA-a-personal-FABEKC8085pwSwzLwUGzh-Hr'
                        b'EoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh'
                        b'-HrEoFDwZnCJq27bVp5atdMT9o-AABAACUs3V7O3fRGmi_-X8xo8UFw7rGEQ0CYyf'
                        b'K7U1URYBwtW546a1pVJZ_c1wzcTXWLDj7OPPNrAQx2em5sNrOMPcH')

    # Test multisig identifier
    with configing.openCF(name="mel", base="mel", temp=True) as cf, \
            habbing.openHby(name="mel", temp=True, salt=core.Salter(raw=b'0123456789abcdef').qb64b,
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
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=hab.kever.serder.said))
        regery.processEscrows()

        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, data=md, source={}, status=issuer.regk)

        # Sign with multisig transferable identifier defaults to single signature on entire SAD
        sig1 = signing.ratify(hab=hab, serder=cred)
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EFnCQiKLTr37bhuFrvbE88GhWyQ-LUryYNiDjO4'
                        b'cW1Nt","i":"EKMHlh4epBApuYP-3-A_ZldeImCa6WxLe8Nmzhy-SvWB","ri":"ELIc0'
                        b'Va2OSemOpuiD2Fxfzd2yXg6CWibjOCJY3vNFLb9","s":"EMQWEcCnVRk1hatTNyK3sIy'
                        b'kYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EEBT5231zltSwAzucatIlavzJyE43F3op2l6'
                        b'aB6or1FP","dt":"2021-06-09T17:35:54.169967+00:00","i":"EAwC_-ISX9helB'
                        b'DUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","LEI":"254900OPPU84GM83MG36"},"e":{}}'
                        b'-JAB6AABAAA--FABEKMHlh4epBApuYP-3-A_ZldeImCa6WxLe8Nmzhy-SvWB0AAAAAAAA'
                        b'AAAAAAAAAAAAAAAEKMHlh4epBApuYP-3-A_ZldeImCa6WxLe8Nmzhy-SvWB-AADAADV_a'
                        b'TlO9rV3bxKCiSr4zqqu0Jg1Q3u6Fk2pWxrctkXepRRlDCfKeKmlMQHnNJ8r6vRQp8Eslv'
                        b'h33uSBdS_MlIPABC--losKLa_YfcwGBIabsq8g5VABrsmnXkZMT7eB-jqK6bdB4Zs_863'
                        b'la0mm_DeMwS1KXomLb_j1zCmgZ3RJPAPACA539yer3U8JQlcgXrdbPlR-1kADcFA4bsN_'
                        b'klRSu7p61y-Z2CS5d7Aitrc7yq00YIG_u-v7OToChDC3TsVCR4D')

    """End Test"""


def test_signature_transposition(seeder, mockCoringRandomNonce, mockHelpingNowIso8601):
    seed = (b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR'
            b'\xc9\xbd\x04\x9d\x85)~\x93')
    seed1 = (b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015'
             b'\x98Y\xdd\xe8')

    signer0 = core.Signer(raw=seed, transferable=True)  # original signing keypair non transferable
    signer1 = core.Signer(raw=seed1)  # next signing keypair transferable is default
    keys0 = [signer0.verfer.qb64]
    nxt1 = [coring.Diger(ser=signer1.verfer.qb64b).qb64]  # dfault sith is 1
    serder = eventing.incept(keys=keys0, ndigs=nxt1, code=coring.MtrDex.Blake3_256, intive=True)
    assert serder.pre == "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL"
    d = dict(
        d="",
        i=serder.pre,
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
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=hab.kever.serder.said))
        regery.processEscrows()

        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, data=d, source={}, status=issuer.regk)

        # Sign with non-transferable identifier, defaults to single signature on entire SAD
        sig0 = bytearray(cred.raw)
        sig0.extend(coring.Counter(coring.CtrDex.SealSourceTriples, count=1).qb64b)
        sig0.extend(coring.Prefixer(qb64=issuer.regk).qb64b)
        sig0.extend(seqner.qb64b)
        sig0.extend(coring.Saider(qb64=issuer.regd).qb64b)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EK88fyN65bfA63o1jgeOGKeIxw6sTJEwwU'
                        b'3ycpjdtCUD","i":"EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o","'
                        b'ri":"ENzh5cyGjFhQYuIXuheXV2wkKp23rkxYI7wbEBQIyqhP","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFyxk35e1r5G9pcu'
                        b'vv8j5F4FWRHD8xlZ_E4rWPdlVASI","dt":"2021-06-09T17:35:54.169967+0'
                        b'0:00","i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-IABENzh5cyGjFhQYuIXuheXV2wkKp23rk'
                        b'xYI7wbEBQIyqhP0AAAAAAAAAAAAAAAAAAAAAABENzh5cyGjFhQYuIXuheXV2wkKp'
                        b'23rkxYI7wbEBQIyqhP')

        iss = issuer.issue(said=cred.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=iss.pre,
                         regd=iss.said,
                         seqner=seqner,
                         saider=coring.Saider(qb64=hab.kever.serder.said))
        regery.processEscrows()

        parsing.Parser().parse(ims=sig0, vry=verifier)

        saider = verifier.reger.saved.get(keys=cred.said)
        assert saider is not None

        scre, *_ = verifier.reger.cloneCred(said=cred.said)
        assert scre.raw == cred.raw

    # multiple path sigs
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):
        seeder.seedSchema(db=hby.db)
        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        saider = coring.Saider(qb64=hab.kever.serder.said)
        issuer.anchorMsg(pre=issuer.regk, regd=issuer.regd, seqner=seqner, saider=saider)
        regery.processEscrows()

        # where is this schema to be found?
        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, data=d, source={}, status=issuer.regk)

        # sign with single sig transferable identifier with multiple specified paths
        # Bad magic values here but can't figure out where looks like Sadder Said seeder
        # is using a bad magic value
        sig1 = signing.ratify(hab=hab, serder=cred, paths=[[], ["a"], ["a", "i"]])
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EK88fyN65bfA63o1jgeOGKeIxw6sTJEwwU3y'
                        b'cpjdtCUD","i":"EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o","ri":'
                        b'"ENzh5cyGjFhQYuIXuheXV2wkKp23rkxYI7wbEBQIyqhP","s":"EMQWEcCnVRk1ha'
                        b'tTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFyxk35e1r5G9pcuvv8j5F4F'
                        b'WRHD8xlZ_E4rWPdlVASI","dt":"2021-06-09T17:35:54.169967+00:00","i":'
                        b'"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","LEI":"254900OPPU84'
                        b'GM83MG36"},"e":{}}-KAD6AABAAA--JAB6AABAAA--FABEKC8085pwSwzLwUGzh-H'
                        b'rEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh'
                        b'-HrEoFDwZnCJq27bVp5atdMT9o-AABAACIRDrYzCyMB5jBHY9jwfT4KEb7kx_vYgHJ'
                        b'7LDsiQRD-Roj5bGfJXj6PAo5TS36t4kWmiBhpvqLgb2l9vUhpiUK-JAB5AABAA-a-F'
                        b'ABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAA'
                        b'AAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAAB80PrmAUGj_i'
                        b'ATyLY-kzdpI6omm5X05EsdkRZGymwVn62-1nijoSh0dlUo6rGOoywUQWu-eZ0i5PuH'
                        b'skgV9nwP-JAB4AAB-a-i-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT'
                        b'9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atd'
                        b'MT9o-AABAABsIw-EgCMnex1m7Qm8RkU4jMGAV3wNGyD_CxfetmMp-iGBLhZ5wArAw6'
                        b'_Qdg75K_NMTKVV4hv7bWw3OvJnNY8A')

    # signing SAD with non-transferable identifier
    with habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (hby, hab):
        seeder.seedSchema(db=hby.db)
        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, data=d, source={},
                                  status="Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE")

        # Sign with non-transferable identifier
        sig0 = signing.ratify(hab=hab, serder=cred)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EBFPlqNJ4FovUoaGiDg3TWAlabvbUv2OnV'
                        b'wF8zPuaey7","i":"BAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP","'
                        b'ri":"Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFyxk35e1r5G9pcu'
                        b'vv8j5F4FWRHD8xlZ_E4rWPdlVASI","dt":"2021-06-09T17:35:54.169967+0'
                        b'0:00","i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--CABBAbSj3jfaeJbpuqg0W'
                        b'tvHw31UoRZOnN_RZQYBwbAqteP0BD1mbdIQtZtdLvSdR7in7XOt-d2ALjyOTvVbQ'
                        b'6AMLcyd5H7m-rPM8RshHoREehbr5S82w7b844-ykD5yJHyqhIG')

        pather = coring.Pather(path=["a", "b", "c"])
        cigars = hab.sign(ser=cred.raw,
                          verfers=hab.kever.verfers,
                          indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBAbSj3jfaeJbpuqg0WtvHw31UoRZOnN_RZQYBwbAqteP'
                      b'0BD1mbdIQtZtdLvSdR7in7XOt-d2ALjyOTvVbQ6AMLcyd5H7m-rPM8RshHoREehbr5S'
                      b'82w7b844-ykD5yJHyqhIG')
    """End Test"""


def test_signatory():
    salt = core.Salter(raw=b'0123456789abcdef')  # init sig Salter

    with basing.openDB(name="sig") as db, keeping.openKS(name="sig") as ks, \
            habbing.openHab(name="sig", salt=salt.raw) as (sigHby, sigHab):
        # Init signatory
        signer = sigHby.signator

        assert signer.pre == 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
        assert signer._hab.kever.verfers[0].qb64b == b'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
        spre = signer.db.hbys.get(habbing.SIGNER)
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
