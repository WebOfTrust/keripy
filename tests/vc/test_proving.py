# -*- encoding: utf-8 -*-
"""
tests.vc.proving module

"""
import pytest

from keri.app import habbing
from keri.core import coring, scheming, parsing
from keri.core.coring import Serials, Counter, CtrDex, Prefixer, Seqner, Diger, Siger
from keri.core.scheming import CacheResolver
from keri.kering import Versionage
from keri.vc.proving import Creder, credential
from keri.vdr import verifying, credentialing


def test_proving():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with habbing.openHby(name="sid", base="test", salt=sidSalt) as sidHby:

        sidHab = sidHby.makeHab(name="test", )
        assert sidHab.pre == 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'
        sed = dict()
        sed["$id"] = ""
        sed["$schema"] = "http://json-schema.org/draft-07/schema#"
        sed.update(dict(
            type="object",
            properties=dict(
                id=dict(
                    type="string"
                ),
                lei=dict(
                    type="string"
                )
            )
        ))

        schemer = scheming.Schemer(sed=sed,
                                   typ=scheming.JSONSchema(),
                                   code=coring.MtrDex.Blake3_256)
        credSubject = dict(
            d="",
            i="EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh0nc",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        cache = CacheResolver(db=sidHby.db)
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"ACDC10JSON000174_","d":"EB9BVzL6-iIy9EO_l1AgqxhAxn3o5yOOyP'
                    b'33HKop8Dmj","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","'
                    b's":"EHggmYtUecR1JYbMkDZv-za1EExCmR-T_bwaJp3PQIoW","a":{"d":"EOsC'
                    b'KF1Fa1LBZuKRwBQzGy5aJ4gzbxFosxzvATT8HMgQ","i":"EPmpiN6bEM8EI0Mct'
                    b'ny-6AfglVOKnJje8-vqyKTlh0nc","lei":"254900OPPU84GM83MG36","issua'
                    b'nceDate":"2021-06-27T21:26:21.233257+00:00"},"e":{}}-VA0-FABEIaG'
                    b'MMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAA'
                    b'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAADMQcCQikV3BBRa'
                    b'vt_f8txYvZX3TQeepFTnBmobPDOEis_gMVnxSRuDSZrKifw7r6N38sw2PGxurCn8'
                    b'iNamZdIB')

        creder = Creder(raw=msg)
        proof = msg[creder.size:]

        ctr = Counter(qb64b=proof, strip=True)
        assert ctr.code == CtrDex.AttachedMaterialQuadlets
        assert ctr.count == 52

        pags = ctr.count * 4
        assert len(proof) == pags

        ctr = Counter(qb64b=proof, strip=True)
        assert ctr.code == CtrDex.TransIdxSigGroups
        assert ctr.count == 1

        prefixer = Prefixer(qb64b=proof, strip=True)
        assert prefixer.qb64 == sidHab.pre

        seqner = Seqner(qb64b=proof, strip=True)
        assert seqner.sn == sidHab.kever.sn

        diger = Diger(qb64b=proof, strip=True)
        assert diger.qb64 == sidHab.kever.serder.said

        ictr = Counter(qb64b=proof, strip=True)
        assert ictr.code == CtrDex.ControllerIdxSigs

        isigers = []
        for i in range(ictr.count):
            isiger = Siger(qb64b=proof, strip=True)
            isiger.verfer = sidHab.kever.serder.verfers[i]
            isigers.append(isiger)
        assert len(isigers) == 1

        siger = isigers[0]
        assert siger.verfer.verify(siger.raw, creder.raw) is True


def test_credentialer():
    with pytest.raises(ValueError):
        Creder()
    sub = dict(a=123, b="abc", issuanceDate="2021-06-27T21:26:21.233257+00:00")
    d = dict(
        v=coring.versify(ident=coring.Idents.acdc, kind=Serials.json, size=0),
        d="",
        s="abc",
        i="i",
        a=sub
    )
    _, d = coring.Saider.saidify(sad=d)

    said = 'EF6maPM_d5ZN7U3NRFC1-6TM7k_EKDz-8AG9YyLA4uWi'  # creder.said

    creder = Creder(ked=d)
    assert creder.said == said
    assert creder.kind == Serials.json
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.crd == d
    assert creder.size == 168
    assert creder.size == len(creder.raw)
    assert creder.raw == (b'{"v":"ACDC10JSON0000a8_","d":"EF6maPM_d5ZN7U3NRFC1-6TM7k_EKDz-8AG9YyLA4uWi",'
                          b'"s":"abc","i":"i","a":{"a":123,"b":"abc","issuanceDate":"2021-06-27T21:26:21'
                          b'.233257+00:00"}}')


    raw1, idt1, knd1, ked1, ver1 = creder._exhale(ked=d)
    assert raw1 == creder.raw
    assert knd1 == Serials.json
    assert ked1 == d
    assert ver1 == Versionage(major=1, minor=0)

    creder = Creder(raw=raw1)
    assert creder.kind == Serials.json
    assert creder.issuer == "i"
    assert creder.crd == d
    assert creder.size == 168

    d2 = dict(d)
    d2["v"] = coring.versify(ident=coring.Idents.acdc, kind=Serials.cbor, size=0)
    creder = Creder(ked=d2)
    assert creder.said == said  #shouldnt this be different here?
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.size == len(creder.raw)
    assert creder.crd == d2
    assert creder.raw == (b'\xa5avqACDC10CBOR00008b_adx,EF6maPM_d5ZN7U3NRFC1-6TM7k_EKDz-8AG9YyLA4uWiasc'
                          b'abcaiaiaa\xa3aa\x18{abcabclissuanceDatex 2021-06-27T21:26:21.233257+00:00')

    raw2 = bytes(creder.raw)
    creder = Creder(raw=raw2)
    assert creder.said == said
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.size == len(creder.raw)
    assert creder.crd == d2

    d3 = dict(d)
    d3["v"] = coring.versify(ident=coring.Idents.acdc, kind=Serials.mgpk, size=0)
    creder = Creder(ked=d3)

    assert creder.said == said  # shouldn't this be different here
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 138
    assert creder.size == len(creder.raw)
    assert creder.crd == d3
    assert creder.raw == (b'\x85\xa1v\xb1ACDC10MGPK00008a_\xa1d\xd9,EF6maPM_d5ZN7U3NRFC1-6TM7k_EKDz-8AG'
                          b'9YyLA4uWi\xa1s\xa3abc\xa1i\xa1i\xa1a\x83\xa1a{\xa1b\xa3abc\xacissuanceDate'
                          b'\xd9 2021-06-27T21:26:21.233257+00:00')

    raw3 = bytes(creder.raw)
    creder = Creder(raw=raw3)
    assert creder.said == said
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 138
    assert creder.size == len(creder.raw)
    assert creder.crd == d3


def test_credential():
    d = dict(
        d="",
        issuanceDate="2021-06-27T21:26:21.233257+00:00",
        personLegalName="John Doe",
        engagementContextRole="Project Manager",
        credentialStatus="EAmRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
        LEI="254900OPPU84GM83MG36"
    )

    # test source chaining with labeled edge
    s = [
        dict(qualifiedvLEIIssuervLEICredential="EGtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD")
    ]

    saider = coring.Saider(sad=d, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)
    assert saider.qb64 == 'EFyC729bNI11tkKduIgFT7yoq3ebYuMJzzhZl-ckXxa8'
    d["i"] = saider.qb64

    cred = credential(schema="EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      issuer="EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      subject=d, source=s, status="ECQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    assert cred.size == len(cred.raw)
    assert cred.raw == (b'{"v":"ACDC10JSON000286_","d":"EAeSzBILdc9X6G5sBRx7BYQTF8t6ywdMuNZOX0e51KUd",'
                        b'"i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","ri":"ECQoH02zJRCTNz-Wl3n'
                        b'nkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q'
                        b'","a":{"d":"EGAyHGcfzb3SIAjvF11jaEgYx7NOg9-ixhfLR6RQe6iG","issuanceDate":"20'
                        b'21-06-27T21:26:21.233257+00:00","personLegalName":"John Doe","engagementCont'
                        b'extRole":"Project Manager","credentialStatus":"EAmRy7xMwsxUelUauaXtMxTfPAMPA'
                        b'I6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36","i":"EFyC729bNI11tkKduIgFT7yoq3'
                        b'ebYuMJzzhZl-ckXxa8"},"e":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLBS'
                        b'MZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}')


def test_privacy_preserving_credential():
    d = dict(
        d="",
        u="",
        issuanceDate="2021-06-27T21:26:21.233257+00:00",
        personLegalName="John Doe",
        engagementContextRole="Project Manager",
        credentialStatus="EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
        LEI="254900OPPU84GM83MG36"
    )

    saider = coring.Saider(sad=d, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)
    assert saider.qb64 == "EmrOM6iYA8p5aEu9XL9e7MTnrDcwH3_VO7vN_QjKtSJo"
    d["i"] = saider.qb64

    cred = credential(schema="EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      issuer="EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      subject=d, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    salt = coring.Salter(raw=b'0123456789abcdef').qb64
    cred = credential(schema="EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      private=True,
                      salt=salt,
                      issuer="EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      subject=d, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    assert cred.size == len(cred.raw)
    assert "u" in cred.ked
    assert cred.raw == (b'{"v":"ACDC10JSON00026e_","d":"ECM8MA5SAMRkrAcGYYiXfwOnXnWRJOpAv4bTVSnc2nCg",'
                        b'"u":"0AMDEyMzQ1Njc4OWFiY2RlZg","i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",'
                        b'"ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M",'
                        b'"s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",'
                        b'"a":{"d":"Elovxn5cR5hzcn5lvumGHiAXqzrV8HneaDL0l8PjWhZg","u":"0AMDEyMzQ1Njc4OWFiY2RlZg",'
                        b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00","personLegalName":"John Doe",'
                        b'"engagementContextRole":"Project Manager",'
                        b'"credentialStatus":"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",'
                        b'"LEI":"254900OPPU84GM83MG36","i":"EmrOM6iYA8p5aEu9XL9e7MTnrDcwH3_VO7vN_QjKtSJo"},"e":{}}')



def test_credential_parsator():
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as (hby, hab):

        assert hab.pre == 'EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o'

        regery = credentialing.Regery(hby=hby, name="sid", temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name="sid", noBackers=True, estOnly=True)

        credSubject = dict(
            d="",
            LEI="254900OPPU84GM83MG36",
        )

        creder = credential(issuer=hab.pre,
                            schema="EAbrwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                            subject=credSubject,
                            status=issuer.regk)

        msg = hab.endorse(serder=creder)

        verifier = verifying.Verifier(hby=hby)
        parsing.Parser().parse(ims=msg, vry=verifier)

        assert len(verifier.cues) == 1
        cue = verifier.cues.popleft()
        assert cue['kin'] == "telquery"
        q = cue["q"]
        assert q["ri"] == issuer.regk


if __name__ == '__main__':
    test_proving()
    test_credentialer()
    test_credential()
