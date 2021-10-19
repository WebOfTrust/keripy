# -*- encoding: utf-8 -*-
"""
tests.vc.proving module

"""
import pytest

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.coring import Serials, Counter, CtrDex, Prefixer, Seqner, Diger, Siger, Vstrings
from keri.core.scheming import CacheResolver
from keri.db import basing
from keri.kering import Versionage, ExtractionError, ColdStartError
from keri.vc import proving
from keri.vc.proving import Credentialer, credential, parseProof
from keri.vdr import verifying, issuing, viring


def test_proving():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS:
        sidHab = habbing.Habitat(ks=sidKS, db=sidDB, salt=sidSalt, temp=True)
        assert sidHab.pre == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"
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

        schemer = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
        credSubject = dict(
            d="",
            i="E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject)

        msg = sidHab.endorse(serder=creder)
        assert msg == (b'{"v":"KERI10JSON000174_","d":"EID77B8V8O60IHFCiB6R93BisHHQ-L9CC_'
                       b'Et2w1Zb1Ww","s":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY","'
                       b'i":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","a":{"d":"Evfz'
                       b'9lXZM_uFnNM1wJhdmyjt4lbtyt5ulmPwNvtL2w6A","i":"E4YPqsEOaPNaZxVIb'
                       b'Y-Gx2bJgP-c7AH_K7pEE-YfcI9E","lei":"254900OPPU84GM83MG36","issua'
                       b'nceDate":"2021-06-27T21:26:21.233257+00:00"},"p":[]}-VA0-FABE4YP'
                       b'qsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAA'
                       b'ElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAAk9ST4uE4G1lIVB'
                       b'UiTDal2v-xa2E_vB2UUbXSueLl470LAkum9L6E4s4rt-3XprStZceTchjmJ_FRTI'
                       b'-Q1wrPAQ')

        creder = Credentialer(raw=msg)
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
        assert diger.qb64 == sidHab.kever.serder.dig

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
        Credentialer()
    sub = dict(a=123, b="abc", issuanceDate="2021-06-27T21:26:21.233257+00:00")
    d = dict(
        v=Vstrings.json,
        d="",
        s="abc",
        i="i",
        a=sub
    )

    creder = Credentialer(crd=d)
    assert creder.said == "EComc-6OTBmeghbNLAAiZqTpQKdMDmmLaZ3khGi0QqM8"
    assert creder.kind == Serials.json
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.crd == d
    assert creder.size == 168
    assert creder.size == len(creder.raw)
    assert creder.raw == (
        b'{"v":"KERI10JSON0000a8_","d":"EComc-6OTBmeghbNLAAiZqTpQKdMDmmLaZ3khGi0QqM8",'
        b'"s":"abc","i":"i","a":{"a":123,"b":"abc","issuanceDate":"2021-06-27T21:26:21'
        b'.233257+00:00"}}')

    raw1, knd1, ked1, ver1, saider = creder._exhale(crd=d)
    assert raw1 == creder.raw
    assert knd1 == Serials.json
    assert ked1 == d
    assert ver1 == Versionage(major=1, minor=0)
    assert saider.qb64 == creder.said

    creder = Credentialer(raw=raw1)
    assert creder.kind == Serials.json
    assert creder.issuer == "i"
    assert creder.crd == d
    assert creder.size == 168

    d2 = dict(d)
    d2["v"] = Vstrings.cbor
    creder = Credentialer(crd=d2)
    assert creder.said == "Eszz-fXDUwmYeM0GhRLYLZKl2xFA8FEqtJYk_3nlpSmc"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.size == len(creder.raw)
    assert creder.crd == d2
    assert creder.raw == (b'\xa5avqKERI10CBOR00008b_adx,Eszz-fXDUwmYeM0GhRLYLZKl2xFA8FEqtJYk_3nlpSmcasc'
                          b'abcaiaiaa\xa3aa\x18{abcabclissuanceDatex 2021-06-27T21:26:21.233257+00:00')

    raw2 = bytes(creder.raw)
    creder = Credentialer(raw=raw2)
    assert creder.said == "Eszz-fXDUwmYeM0GhRLYLZKl2xFA8FEqtJYk_3nlpSmc"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.size == len(creder.raw)
    assert creder.crd == d2

    d3 = dict(d)
    d3["v"] = Vstrings.mgpk
    creder = Credentialer(crd=d3)

    assert creder.said == "E3XRqG03kBX9EM-gbPSlIY7iISe6CFdiZzN56P1WBPa8"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 138
    assert creder.size == len(creder.raw)
    assert creder.crd == d3
    assert creder.raw == (b'\x85\xa1v\xb1KERI10MGPK00008a_\xa1d\xd9,E3XRqG03kBX9EM-gbPSlIY7iISe6CFdiZzN'
                          b'56P1WBPa8\xa1s\xa3abc\xa1i\xa1i\xa1a\x83\xa1a{\xa1b\xa3abc\xacissuanceDate'
                          b'\xd9 2021-06-27T21:26:21.233257+00:00')

    raw3 = bytes(creder.raw)
    creder = Credentialer(raw=raw3)
    assert creder.said == "E3XRqG03kBX9EM-gbPSlIY7iISe6CFdiZzN56P1WBPa8"
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
        type=["VerifiablePresentation",
              "LegalEntityEngagementContextRolevLEICredential"],
        personLegalName="John Doe",
        engagementContextRole="Project Manager",
        credentialStatus="EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
        LEI="254900OPPU84GM83MG36"
    )

    # test source chaining with labeled edge
    s = [
        dict(qualifiedvLEIIssuervLEICredential="EGtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD")
    ]

    saider = coring.Saider(sad=d, code=coring.MtrDex.Blake3_256, label=scheming.Ids.d)
    assert saider.qb64 == "Ee-sbdl62ON0uzObBPf9fbvnnaJ_Lf39Av4_XSHWQ4QY"
    d["i"] = saider.qb64

    cred = credential(schema="EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      issuer="EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      subject=d, source=s, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    assert cred.size == len(cred.raw)
    assert cred.raw == (
        b'{"v":"KERI10JSON0002d9_","d":"EMRnP1k-86yYMTON-NrDJOi3P31kcbXckg2tj8QCzBEM",'
        b'"s":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","i":"EYNHFK056fqNSG_MDE7d'
        b'_Eqk0bazefvd4eeQLMPPNBnM","a":{"d":"El9mrwBT9Zeq7rtuQF5VXHsHDUa9YCGEKsq1drBS'
        b'OOvc","issuanceDate":"2021-06-27T21:26:21.233257+00:00","type":["VerifiableP'
        b'resentation","LegalEntityEngagementContextRolevLEICredential"],"personLegalN'
        b'ame":"John Doe","engagementContextRole":"Project Manager","credentialStatus"'
        b':"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36",'
        b'"i":"Ee-sbdl62ON0uzObBPf9fbvnnaJ_Lf39Av4_XSHWQ4QY","ri":"ETQoH02zJRCTNz-Wl3n'
        b'nkUD_RVSzSwcoNvmfa18AWt3M"},"p":[{"qualifiedvLEIIssuervLEICredential":"EGtyT'
        b'hM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}]}')


def test_parse_proof():
    proof = bytearray(b'-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
                      b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
                      b'-AABAAVgLJOmUNlMZpSGV0hr'
                      b'-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg')

    prefixer, seqner, diger, isigers = parseProof(proof)
    assert prefixer.code == coring.MtrDex.Blake3_256
    assert prefixer.qb64 == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"

    assert seqner.sn == 0
    assert diger.qb64 == "ElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI"

    assert len(isigers) == 1
    assert isigers[0].qb64 == "AAVgLJOmUNlMZpSGV0hr-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg"

    #  pipelined attachment start
    proof = bytearray(b'-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
                      b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
                      b'-AABAAVgLJOmUNlMZpSGV0hr'
                      b'-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg')

    prefixer, seqner, diger, isigers = parseProof(proof)
    assert prefixer.qb64 == "E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E"
    assert seqner.sn == 0
    assert diger.qb64 == "ElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI"
    assert len(isigers) == 1

    # Invalid, can't process a message
    proof = bytearray(b'{{"v":"KERI10JSON000136_","i":"Eq1XfsuS1WNK2uLnAwfJ2SwGz8MhPUDnL0Mi1yNvTQnY",'
                      b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY",'
                      b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
                      b'"issuance":"2021-06-27T21:26:21.233257+00:00",'
                      b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
                      b'"lei":"254900OPPU84GM83MG36"}}')

    with pytest.raises(ColdStartError):
        parseProof(proof)


def test_credential_parsator():
    with habbing.openHab(name="sid", temp=True, salt=b'0123456789abcdef') as hab, \
            viring.openReg() as reg:
        assert hab.pre == "ELfzj-TkiKYWsNKk2WE8F8VEgbu3P-_HComVHcKrvGmY"

        issuer = issuing.Issuer(hab=hab, reger=reg, noBackers=True, estOnly=True, temp=True)

        credSubject = dict(
            d="",
            LEI="254900OPPU84GM83MG36",
        )

        creder = credential(issuer=hab.pre,
                            schema="E7brwlefuH-F_KU_FPWAZR78A3pmSVDlnfJUqnm8Lhr4",
                            subject=credSubject,
                            status=issuer.regk)

        msg = hab.endorse(serder=creder)

        verifier = verifying.Verifier(hab=hab, name="verifier")
        proving.parseCredential(ims=msg, verifier=verifier)

        assert len(verifier.cues) == 2
        cue = verifier.cues.popleft()
        print(cue)
        assert cue['kin'] == "query"
        q = cue["q"]
        assert q["pre"] == hab.pre


if __name__ == '__main__':
    test_proving()
    test_credentialer()
    test_credential()
    test_parse_proof()
