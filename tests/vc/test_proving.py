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


def test_proving(mockHelpingNowIso8601):
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
                            data=credSubject)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"ACDC10JSON000195_","d":"EPVHgaM_Yad1b5VHs6SIZyqF72m_byxSYU'
                       b'w3VNx5Ubqt","i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","'
                       b's":"EHggmYtUecR1JYbMkDZv-za1EExCmR-T_bwaJp3PQIoW","a":{"d":"EO-m'
                       b'lywujxMkv1yLxir1m5c0p-fZLuprOrgZAIohJdmQ","dt":"2021-06-27T21:26'
                       b':21.233257+00:00","i":"EPmpiN6bEM8EI0Mctny-6AfglVOKnJje8-vqyKTlh'
                       b'0nc","lei":"254900OPPU84GM83MG36","issuanceDate":"2021-06-27T21:'
                       b'26:21.233257+00:00"}}-VA0-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl'
                       b'2QV8dDjI30AAAAAAAAAAAAAAAAAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge'
                       b'6mBl2QV8dDjI3-AABAAAmfpF4BjMS3b4kzvPdOpkSlH3PiVx7MSySulPyKFxtaS3'
                       b'oxH45Y3kIvZg67u2DyxtUqVixVzRhOOTnMAB_SowI')

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
        v=coring.versify(proto=coring.Protos.acdc, kind=Serials.json, size=0),
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
    d2["v"] = coring.versify(proto=coring.Protos.acdc, kind=Serials.cbor, size=0)
    creder = Creder(ked=d2)
    assert creder.said == said  # shouldnt this be different here?
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
    d3["v"] = coring.versify(proto=coring.Protos.acdc, kind=Serials.mgpk, size=0)
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


def test_credential(mockHelpingNowIso8601):
    d = dict(
        d="",
        LEI="254900OPPU84GM83MG36",
        personLegalName="John Doe",
        engagementContextRole="Project Manager",
    )

    # test source chaining with labeled edge
    s = [
        dict(qualifiedvLEIIssuervLEICredential="EGtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD")
    ]

    saider = coring.Saider(sad=d, code=coring.MtrDex.Blake3_256, label=scheming.Saids.d)
    assert saider.qb64 == 'EM_S2MdMaKgP6P2Yyno6-flV6GqrwPencTIw8tCMR7iB'
    d["i"] = saider.qb64

    cred = credential(schema="EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      issuer="EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      data=d, source=s, status="ECQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    assert cred.size == len(cred.raw)
    assert cred.raw == (b'{"v":"ACDC10JSON00023b_","d":"EFyT2QGVlx0zL4ft1WNDzEeBh9lHN-vfcjL18V8h-zn1",'
                        b'"i":"EBNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM","ri":"ECQoH02zJRCTNz-Wl3n'
                        b'nkUD_RVSzSwcoNvmfa18AWt3M","s":"EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q'
                        b'","a":{"d":"EE3G84sadzx_QCOLYBjdjgLa9E8tT5iWWwN2hzkmk3wZ","dt":"2021-06-27T2'
                        b'1:26:21.233257+00:00","LEI":"254900OPPU84GM83MG36","personLegalName":"John D'
                        b'oe","engagementContextRole":"Project Manager","i":"EM_S2MdMaKgP6P2Yyno6-flV6'
                        b'GqrwPencTIw8tCMR7iB"},"e":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLB'
                        b'SMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}')


def test_privacy_preserving_credential(mockHelpingNowIso8601):
    d = dict(
        LEI="254900OPPU84GM83MG36",
        personLegalName="John Doe",
        engagementContextRole="Project Manager",
    )

    salt = coring.Salter(raw=b'0123456789abcdef').qb64
    cred = credential(schema="EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      recipient="EM_S2MdMaKgP6P2Yyno6-flV6GqrwPencTIw8tCMR7iB",
                      private=True,
                      salt=salt,
                      issuer="EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      data=d, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    assert cred.size == len(cred.raw)
    assert "u" in cred.ked
    print(cred.raw)
    assert cred.raw == (b'{"v":"ACDC10JSON00021c_","d":"EKwDvF8_PWMlw7X1Lb1fiilLIMiK4yTXUdmBasZWb0sF",'
                        b'"u":"0AAwMTIzNDU2Nzg5YWJjZGVm","i":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPP'
                        b'NBnM","ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M","s":"EZllThM1rLBSM'
                        b'Z_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","a":{"d":"EFwWs1d_fe_VeLZ0vQQKO-gkRvGrpfWAR'
                        b'bI4e9tzcqlV","u":"0AAwMTIzNDU2Nzg5YWJjZGVm","i":"EM_S2MdMaKgP6P2Yyno6-flV6Gq'
                        b'rwPencTIw8tCMR7iB","dt":"2021-06-27T21:26:21.233257+00:00","LEI":"254900OPPU'
                        b'84GM83MG36","personLegalName":"John Doe","engagementContextRole":"Project Ma'
                        b'nager"}}')


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
                            data=credSubject,
                            status=issuer.regk)

        msg = bytearray(creder.raw)
        msg.extend(coring.Counter(coring.CtrDex.SealSourceTriples, count=1).qb64b)
        msg.extend(hab.kever.prefixer.qb64b)
        msg.extend(coring.Seqner(sn=hab.kever.sn).qb64b)
        msg.extend(hab.kever.serder.saider.qb64b)

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
