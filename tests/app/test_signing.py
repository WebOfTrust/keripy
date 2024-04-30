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
        assert sig0 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtS'
                        b'KlDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQz'
                        b'DXg39j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"E'
                        b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                        b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--CABBEByXTm1zJZ1oI'
                        b'uvnad6hppC3iBrUmQLb0a7iXSaRK4p0BCCKuUzhtasI04dqYQY4x7AqHMLP7Cbn2'
                        b'nqKFrR34_4zjJvT3HARSLhL_iUOSyoHMVv2-9mgtWuuW0oF4XS3n0C')

        # sign with non-trans identifier with a specific set of paths
        sig1 = signing.ratify(wanHab, cred, paths=paths)
        assert sig1 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtS'
                        b'KlDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQz'
                        b'DXg39j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"E'
                        b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                        b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--CADBE'
                        b'ByXTm1zJZ1oIuvnad6hppC3iBrUmQLb0a7iXSaRK4p0BCCKuUzhtasI04dqYQY4x'
                        b'7AqHMLP7Cbn2nqKFrR34_4zjJvT3HARSLhL_iUOSyoHMVv2-9mgtWuuW0oF4XS3n'
                        b'0C-JAB5AABAA-a-CADBEByXTm1zJZ1oIuvnad6hppC3iBrUmQLb0a7iXSaRK4p0B'
                        b'A0YOvEHllXmhlmv7ec_MShdDf2eZ3OvMDKE_zhfQsrFvU2ip1g-z04HZ097hN66r'
                        b'Lo5nqglvdCkxXJcYBqe8kD-JAB4AADA-a-personal-CADBEByXTm1zJZ1oIuvna'
                        b'd6hppC3iBrUmQLb0a7iXSaRK4p0BBjkD40acCOcdFuAM9d5FAgnfXqkZyI9haUTe'
                        b'VDO9vhPqgnRIXAUcTMxkY3eAfhX0ggy7n99sosla1nyVyBE_cK')

        # Sign with transferable identifier defaults to single signature on entire SAD
        sig2 = signing.ratify(sidHab, cred)
        assert sig2 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtS'
                        b'KlDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQz'
                        b'DXg39j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"E'
                        b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                        b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-JAB6AABAAA--FABEDT4jW7VYWenu1'
                        b'MrgJJEZWB0ScqZdVmDQw0RUdxKLWax0AAAAAAAAAAAAAAAAAAAAAAAEDT4jW7VYW'
                        b'enu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax-AABAAA5PVjmjZFG-1meySYd8YrYhV'
                        b'XubpZd9DXRDJ1uIeFxjKiy_XbJAG7Yl00KxVAcObWDmBStuWLn-qoOI1YcFYoB')

        # Sign with transferable identifier with specific set of paths
        sig3 = signing.ratify(sidHab, cred, paths=paths)
        assert sig3 == (b'{"v":"ACDC10JSON0002e2_","d":"EIEbtplUZZrV3-jVAnOUcH-xcxOCuiJqtS'
                        b'KlDJSxUJLW","i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","'
                        b'ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1'
                        b'rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EHpYRwyyu23jcGQz'
                        b'DXg39j1b7U4_VB8sW5_YsqD6YNpY","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0J'
                        b'p6ZFRD9dTb4-5c0","dt":"2021-06-27T21:26:21.233257+00:00","ri":"E'
                        b'BmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84G'
                        b'M83MG36","personal":{"d":"EMUsc87LxpYTultDtf_pOQKYvDYA_HQxy4Gswc'
                        b'U6ov8-","n":"Q8rNaKITBLLA96Euh5M5v4o3fRl1Bc54xdM-bOIHUjY","perso'
                        b'nLegalName":"Anna Jones","engagementContextRole":"Project Manage'
                        b'r"}},"e":[{"qualifiedvLEIIssuervLEICredential":"EAtyThM1rLBSMZ_o'
                        b'zM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}-KAD6AABAAA--JAB6AABAAA--FABED'
                        b'T4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax0AAAAAAAAAAAAAAAAAAAAA'
                        b'AAEDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax-AABAAA5PVjmjZFG-1'
                        b'meySYd8YrYhVXubpZd9DXRDJ1uIeFxjKiy_XbJAG7Yl00KxVAcObWDmBStuWLn-q'
                        b'oOI1YcFYoB-JAB5AABAA-a-FABEDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUd'
                        b'xKLWax0AAAAAAAAAAAAAAAAAAAAAAAEDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw'
                        b'0RUdxKLWax-AABAABYXrbXx0VXn_qs1AVUzVqJ19lfnN1aBoxaLjlcgHaCgCOaY_'
                        b'AUPOuEyE9EFgA_VLCHnPi7TdZhbXyG09Due24P-JAB4AADA-a-personal-FABED'
                        b'T4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax0AAAAAAAAAAAAAAAAAAAAA'
                        b'AAEDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax-AABAACNv9Bg6Gg9oi'
                        b'pvuArddJgY1uNfp7uFO8ifkwKHhQargXScvQuvYIV7-VZM4Xu0vNOWaKA-mDmfei'
                        b'sRYanh_gEJ')

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
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EPA-T12T4d8sHaj2IyvK2ReIs5KREYN24W'
                        b'tJbYL-d2HQ","i":"ELqU3H49LwniPBMVMGqWjSfh_8mFRntbXVlBQirijKMi","'
                        b'ri":"ENw4eVQH4l7uHSYa50yWh1AW8Wj22V77KHL7Wg55F5gB","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EEBT5231zltSwAzu'
                        b'catIlavzJyE43F3op2l6aB6or1FP","dt":"2021-06-09T17:35:54.169967+0'
                        b'0:00","i":"EAwC_-ISX9helBDUSKU5j_VEU3G0Jp6ZFRD9dTb4-5c0","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--FABELqU3H49LwniPBMVMG'
                        b'qWjSfh_8mFRntbXVlBQirijKMi0AAAAAAAAAAAAAAAAAAAAAAAELqU3H49LwniPB'
                        b'MVMGqWjSfh_8mFRntbXVlBQirijKMi-AADAAB7s8EP1DushDLnCeo3xcud-y_fXm'
                        b'X4AL93H8hUAFDv4o2x-5_GHmpUWC9lt86DW_sUX1rJA1OsPGaCYXiFFOoHABD3bW'
                        b'HcN4gL4tgtN9kl8737NzW18wIIE2GEEvKh2Z45Ai5sIynHzU0q6mCD3LTIRb5DfA'
                        b'aazZfDFlqgLYtyBVIPACDpAkl7FGW7pQ5ZLW6rCLTBYUfM_bagl7Fwo_GJhYNAiR'
                        b'3D52Y6QFhqQDn-F_FJZSAlQUZZGmT0ZJeIEHg5qwwH')

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

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EEs1BzDdw0h5VMhg5KUo904UyCdaMT1ut_'
                        b'_vN5G879pP","i":"EDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax","'
                        b'ri":"ECBNRQkp71gi2mTqZu2cp-xe6CrWlvJ5pRoBIBnRQbGp","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFyxk35e1r5G9pcu'
                        b'vv8j5F4FWRHD8xlZ_E4rWPdlVASI","dt":"2021-06-09T17:35:54.169967+0'
                        b'0:00","i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-IABECBNRQkp71gi2mTqZu2cp-xe6CrWlv'
                        b'J5pRoBIBnRQbGp0AAAAAAAAAAAAAAAAAAAAAABECBNRQkp71gi2mTqZu2cp-xe6C'
                        b'rWlvJ5pRoBIBnRQbGp')

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
        assert sig1 == (b'{"v":"ACDC10JSON00019e_","d":"EEs1BzDdw0h5VMhg5KUo904UyCdaMT1ut_'
                        b'_vN5G879pP","i":"EDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax","'
                        b'ri":"ECBNRQkp71gi2mTqZu2cp-xe6CrWlvJ5pRoBIBnRQbGp","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFyxk35e1r5G9pcu'
                        b'vv8j5F4FWRHD8xlZ_E4rWPdlVASI","dt":"2021-06-09T17:35:54.169967+0'
                        b'0:00","i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-KAD6AABAAA--JAB6AABAAA--FABEDT4jW'
                        b'7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax0AAAAAAAAAAAAAAAAAAAAAAAED'
                        b'T4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax-AABAAA0vjmyMr3yp2DPHG'
                        b'fWczKx3rTd0EQndtntndKMEucbuUBh9B-KOIifWpzfpvvdOl4seK_nkfLsYt1NXx'
                        b'EMLqIC-JAB5AABAA-a-FABEDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUdxKLW'
                        b'ax0AAAAAAAAAAAAAAAAAAAAAAAEDT4jW7VYWenu1MrgJJEZWB0ScqZdVmDQw0RUd'
                        b'xKLWax-AABAAAMSXJBtyWP60AH_SPThf2kW7J7VNudUEwTX6fvD-EhE-DypJogi-'
                        b'SAm-eJ7kyo5v1zbgeacUDo2lYK3BZ1POcE-JAB4AAB-a-i-FABEDT4jW7VYWenu1'
                        b'MrgJJEZWB0ScqZdVmDQw0RUdxKLWax0AAAAAAAAAAAAAAAAAAAAAAAEDT4jW7VYW'
                        b'enu1MrgJJEZWB0ScqZdVmDQw0RUdxKLWax-AABAADvLjrNYsoHiYyrSzaFIrPd88'
                        b'gqaTIWqwnsVK_HfmR27PJgLXv36zqT4lNDTHyTjFWcA7tBghCkG_7aBsDkW38P')

    # signing SAD with non-transferable identifier
    with habbing.openHab(name="wan", temp=True, salt=b'0123456789abcdef', transferable=False) as (hby, hab):
        seeder.seedSchema(db=hby.db)
        cred = proving.credential(schema="EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC",
                                  issuer=hab.pre, data=d, source={},
                                  status="Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE")

        # Sign with non-transferable identifier
        sig0 = signing.ratify(hab=hab, serder=cred)

        assert sig0 == (b'{"v":"ACDC10JSON00019e_","d":"EDvgu38Hmuprln_wc57VYkeJ9Dh0PlcOon'
                        b'qHhXjh6Yql","i":"BEByXTm1zJZ1oIuvnad6hppC3iBrUmQLb0a7iXSaRK4p","'
                        b'ri":"Eg1H4eN7P5ndJAWtcymq3ZrYZwQsBRYd3-VuZ6wMAwxE","s":"EMQWEcCn'
                        b'VRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC","a":{"d":"EFyxk35e1r5G9pcu'
                        b'vv8j5F4FWRHD8xlZ_E4rWPdlVASI","dt":"2021-06-09T17:35:54.169967+0'
                        b'0:00","i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","LEI":"'
                        b'254900OPPU84GM83MG36"},"e":{}}-JAB6AABAAA--CABBEByXTm1zJZ1oIuvna'
                        b'd6hppC3iBrUmQLb0a7iXSaRK4p0BBfvm3yAoWIysgYFm4nQ7zQY6_Obo50YHKRVZ'
                        b'0aqphSHLn4H0YuZK-0dQEsUjAOZuvPK6TkR8w1hWxOE-lXug8C')

        pather = coring.Pather(path=["a", "b", "c"])
        cigars = hab.sign(ser=cred.raw,
                          verfers=hab.kever.verfers,
                          indexed=False)
        sadcigars = [(pather, cigars)]

        tp = eventing.proofize(sadcigars=sadcigars, pipelined=True)
        assert tp == (b'-VAm-JAB5AACAA-a-b-c-CABBEByXTm1zJZ1oIuvnad6hppC3iBrUmQLb0a7iXSa'
                      b'RK4p0BBfvm3yAoWIysgYFm4nQ7zQY6_Obo50YHKRVZ0aqphSHLn4H0YuZK-0dQEs'
                      b'UjAOZuvPK6TkR8w1hWxOE-lXug8C')
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
