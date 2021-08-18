# -*- encoding: utf-8 -*-
"""
tests.vc.proving module

"""
import pytest

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.coring import Serials, Counter, CtrDex, Prefixer, Seqner, Diger, Siger, Vstrings
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.kering import Versionage, ExtractionError, ColdStartError
from keri.vc.proving import Credentialer, credential, parseProof, buildProof


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
            id="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            typ=JSONSchema(resolver=cache))

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000136_","i":"EgaaYOPdG7vootT99cmClvwOoM-hjUIpv5Xl6hFuTcyM",'
            b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY","ti":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
            b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v","lei":"254900OPPU84GM83MG36",'
            b'"issuanceDate":"2021-06-27T21:26:21.233257+00:00"}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
            b'-AABAA0pXbQllgzXr88IczAnsPrdhgFKs9wNQvfSfzyrtcvbTwq-U1DmBluAklntCqH1AbBL6TWLZIDGi83BHLWJ82CA')

        creder = Credentialer(raw=msg, typ=JSONSchema(resolver=cache))
        proof = msg[creder.size:]

        ctr = Counter(qb64b=proof, strip=True)
        assert ctr.code == CtrDex.AttachedMaterialQuadlets
        assert ctr.count == 52

        pags = ctr.count * 4
        assert len(proof) == pags

        ctr = Counter(qb64b=proof, strip=True)
        assert ctr.code == CtrDex.TransIndexedSigGroups
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
        i="",
        x="abc",
        ti="i",
        d=sub
    )

    creder = Credentialer(crd=d)
    assert creder.said == "EeFdv935UXIkVl3QGMLTMz5OQHHW650WsOHE0cF3q9f4"
    assert creder.kind == Serials.json
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.crd == d
    assert creder.size == 169
    assert creder.size == len(creder.raw)
    assert creder.raw == (
        b'{"v":"KERI10JSON0000a9_","i":"EeFdv935UXIkVl3QGMLTMz5OQHHW650WsOHE0cF3q9f4","x":"abc","ti":"i",'
        b'"d":{"a":123,"b":"abc","issuanceDate":"2021-06-27T21:26:21.233257+00:00"}}')

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
    assert creder.size == 169

    d2 = dict(d)
    d2["v"] = Vstrings.cbor
    creder = Credentialer(crd=d2)
    assert creder.said == "EUoO89lNIr0K-W6-3rtyYgucAc1Jx0gKNryqYtd1aJMg"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 140
    assert creder.size == len(creder.raw)
    assert creder.crd == d2
    assert creder.raw == (
        b'\xa5avqKERI10CBOR00008c_aix,EUoO89lNIr0K-W6-3rtyYgucAc1Jx0gKNryqYtd1aJMgaxcabcbtiaiad\xa3aa\x18{'
        b'abcabclissuanceDatex 2021-06-27T21:26:21.233257+00:00')

    raw2 = bytes(creder.raw)
    creder = Credentialer(raw=raw2)
    assert creder.said == "EUoO89lNIr0K-W6-3rtyYgucAc1Jx0gKNryqYtd1aJMg"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 140
    assert creder.size == len(creder.raw)
    assert creder.crd == d2

    d3 = dict(d)
    d3["v"] = Vstrings.mgpk
    creder = Credentialer(crd=d3)

    assert creder.said == "Ef7Mu7jak-tFu2FJhzF4JAyWkymBokHkv6SFh84Wuxok"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.size == len(creder.raw)
    assert creder.crd == d3
    assert creder.raw == (
        b'\x85\xa1v\xb1KERI10MGPK00008b_\xa1i\xd9,'
        b'Ef7Mu7jak-tFu2FJhzF4JAyWkymBokHkv6SFh84Wuxok\xa1x\xa3abc\xa2ti\xa1i\xa1d\x83\xa1a{'
        b'\xa1b\xa3abc\xacissuanceDate\xd9 2021-06-27T21:26:21.233257+00:00')

    raw3 = bytes(creder.raw)
    creder = Credentialer(raw=raw3)
    assert creder.said == "Ef7Mu7jak-tFu2FJhzF4JAyWkymBokHkv6SFh84Wuxok"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.size == len(creder.raw)
    assert creder.crd == d3


def test_credential():
    d = dict(
        i="",
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

    saider = scheming.Saider(sed=d, code=coring.MtrDex.Blake3_256, idder=scheming.Ids.i)
    assert saider.qb64 == "ESRs5eTGniYdVFwPtHYtZ4vMxrgJOaK_5HH9wEmT6rq8"
    d["i"] = saider.qb64

    cred = credential(schema="EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                      issuer="EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",
                      subject=d, source=s, status="ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M")

    assert cred.size == len(cred.raw)
    print(cred.raw)
    assert cred.raw == (
        b'{"v":"KERI10JSON0002a7_","i":"E-LcFxJ_mwwT6aGipuwfp5WUp1g777UvX8EAE4qhP6ec",'
        b'"x":"EZllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q","ti":"EYNHFK056fqNSG_MDE7d_Eqk0bazefvd4eeQLMPPNBnM",'
        b'"d":{"i":"ESRs5eTGniYdVFwPtHYtZ4vMxrgJOaK_5HH9wEmT6rq8","issuanceDate":"2021-06-27T21:26:21.233257+00:00",'
        b'"type":["VerifiablePresentation","LegalEntityEngagementContextRolevLEICredential"],"personLegalName":"John '
        b'Doe","engagementContextRole":"Project Manager",'
        b'"credentialStatus":"EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt","LEI":"254900OPPU84GM83MG36"},'
        b'"s":[{"qualifiedvLEIIssuervLEICredential":"EGtyThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sHYTGFD"}],'
        b'"ri":"ETQoH02zJRCTNz-Wl3nnkUD_RVSzSwcoNvmfa18AWt3M"}')


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

    #  Invalid attachment start
    proof = bytearray(b'-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
                      b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI'
                      b'-AABAAVgLJOmUNlMZpSGV0hr'
                      b'-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg')

    with pytest.raises(ExtractionError):
        parseProof(proof)

    # Invalid, can't process a message
    proof = bytearray(b'{{"v":"KERI10JSON000136_","i":"Eq1XfsuS1WNK2uLnAwfJ2SwGz8MhPUDnL0Mi1yNvTQnY",'
                      b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY",'
                      b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E",'
                      b'"issuance":"2021-06-27T21:26:21.233257+00:00",'
                      b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
                      b'"lei":"254900OPPU84GM83MG36"}}')

    with pytest.raises(ColdStartError):
        parseProof(proof)


def test_build_proof():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sigDB, \
            keeping.openKS(name="sid") as sigKS:
        sigHab = habbing.Habitat(ks=sigKS, db=sigDB, salt=sidSalt, icount=3, ncount=3, temp=True)

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
            id="did:keri:Efaavv0oadfghasdfn443fhbyyr4v",  # this needs to be generated from a KEL
            lei="254900OPPU84GM83MG36",
            issuanceDate="2021-06-27T21:26:21.233257+00:00",
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sigHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            typ=JSONSchema(resolver=cache))

        sigHab.rotate()
        sigHab.rotate()
        sigHab.rotate()
        sigHab.rotate()

        prefixer = coring.Prefixer(qb64=sigHab.kever.prefixer.qb64)
        seqner = coring.Seqner(sn=sigHab.kever.lastEst.s)
        diger = coring.Diger(qb64=sigHab.kever.lastEst.d)

        sigers = sigHab.mgr.sign(ser=creder.raw, verfers=sigHab.kever.verfers, indexed=True)

        proof = buildProof(prefixer, seqner, diger, sigers)
        assert proof == (
            b'-FABEiRjCnZfca8gUZqecerjGpjkiY8dIkGudP6GfapWi5MU0AAAAAAAAAAAAAAAAAAAAABAECc96yX1sYswnD6LXEcoNuJ0e'
            b'hi8gkFMEGedqURhXMBU-AADAAGcSUhma16SY3MiKU7n6mK3JzWS2oAiBRB-jeycIDrQ2Z-36QHrMorzRAO9Iw7FvIKrneaLZP'
            b'whz6DFFiXM4oBgAB1g2CudOfOFd9BqesyAIlCDRAkxAQynrED4_ot1MkhKwjmK71XUx1Xer25iWtHMa9sny07AsTO-KE3vu9e'
            b'qTPDQAClDQMXWg3I8qeVEjA6JA9xBW2uESMtMzNVQ8lH31UCizqYVjXort--QEJTsfIt_b0Qq1JOCtaj7Y6U-DWHoulBA')

        prefixer, seqner, diger, isigers = parseProof(proof)
        assert prefixer.qb64 == sigHab.pre
        assert diger.qb64 == sigHab.kever.lastEst.d
        assert seqner.sn == 4
        assert len(isigers) == 3


if __name__ == '__main__':
    test_proving()
    test_credentialer()
    test_credential()
    test_build_proof()
    test_parse_proof()
