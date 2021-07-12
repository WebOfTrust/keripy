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
from keri.kering import Versionage
from keri.vc.proving import Credentialer, credential


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
            lei="254900OPPU84GM83MG36"
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sidHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            issuance="2021-06-27T21:26:21.233257+00:00",
                            typ=JSONSchema(resolver=cache))

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000136_","i":"Eq1XfsuS1WNK2uLnAwfJ2SwGz8MhPUDnL0Mi1yNvTQnY",'
            b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY",'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","issuance":"2021-06-27T21:26:21.233257+00:00",'
            b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
            b'"lei":"254900OPPU84GM83MG36"}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAAVgLJOmUNlMZpSGV0hr'
            b'-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg')

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
    sub = dict(a=123, b="abc")
    d = dict(
        v=Vstrings.json,
        i="",
        x="abc",
        issuer="i",
        issuance="2021-06-27T21:26:21.233257+00:00",
        d=sub
    )

    creder = Credentialer(crd=d)
    assert creder.said == "EASVjcsdqrobngAG0RfGEkeOjdOO0zotPmc7O3Oi8ZWk"
    assert creder.kind == Serials.json
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.crd == d
    assert creder.size == 169
    assert creder.raw == b'{"v":"KERI10JSON0000a9_","i":"EASVjcsdqrobngAG0RfGEkeOjdOO0zotPmc7O3Oi8ZWk","x":"abc",' \
                         b'"issuer":"i","issuance":"2021-06-27T21:26:21.233257+00:00","d":{"a":123,"b":"abc"}}'

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
    assert creder.said == "EsxmFcwFuAoBiOOSc2LHDqWpSHdSbDoBB1NMFpAScY6c"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 140
    assert creder.crd == d2
    assert creder.raw == b'\xa6avqKERI10CBOR00008c_aix,' \
                         b'EsxmFcwFuAoBiOOSc2LHDqWpSHdSbDoBB1NMFpAScY6caxcabcfissueraihissuancex ' \
                         b'2021-06-27T21:26:21.233257+00:00ad\xa2aa\x18{abcabc'

    raw2 = bytes(creder.raw)
    creder = Credentialer(raw=raw2)
    assert creder.said == "EsxmFcwFuAoBiOOSc2LHDqWpSHdSbDoBB1NMFpAScY6c"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 140
    assert creder.crd == d2

    d3 = dict(d)
    d3["v"] = Vstrings.mgpk
    creder = Credentialer(crd=d3)

    assert creder.said == "EYQei3JduKN6aSbmcodvf_VOK0xttPKDewm1OKzSBrUM"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.crd == d3
    assert creder.raw == b'\x86\xa1v\xb1KERI10MGPK00008b_\xa1i\xd9,' \
                         b'EYQei3JduKN6aSbmcodvf_VOK0xttPKDewm1OKzSBrUM\xa1x\xa3abc\xa6issuer\xa1i\xa8issuance\xd9 ' \
                         b'2021-06-27T21:26:21.233257+00:00\xa1d\x82\xa1a{\xa1b\xa3abc'

    raw3 = bytes(creder.raw)
    creder = Credentialer(raw=raw3)
    assert creder.said == "EYQei3JduKN6aSbmcodvf_VOK0xttPKDewm1OKzSBrUM"
    assert creder.issuer == "i"
    assert creder.schema == "abc"
    assert creder.subject == sub
    assert creder.size == 139
    assert creder.crd == d3


if __name__ == '__main__':
    test_proving()
    test_credentialer()
