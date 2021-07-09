# -*- encoding: utf-8 -*-
"""
tests.vc.walleting module

"""
import pytest

from keri.app import keeping, habbing
from keri.core import coring, scheming
from keri.core.scheming import CacheResolver, JSONSchema
from keri.db import basing
from keri.kering import ExtractionError, ColdStartError
from keri.vc.proving import credential
from keri.vc.walleting import Wallet, parseCredential, openPocket, parseProof, buildProof


def test_wallet():
    sidSalt = coring.Salter(raw=b'0123456789abcdef').qb64

    with basing.openDB(name="sid") as sidDB, \
            keeping.openKS(name="sid") as sidKS, \
            openPocket(name="sid") as sidPDB:
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
        assert creder.said == "Eq1XfsuS1WNK2uLnAwfJ2SwGz8MhPUDnL0Mi1yNvTQnY"

        msg = sidHab.endorse(serder=creder)
        assert msg == (
            b'{"v":"KERI10JSON000136_","i":"Eq1XfsuS1WNK2uLnAwfJ2SwGz8MhPUDnL0Mi1yNvTQnY",'
            b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY",'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","issuance":"2021-06-27T21:26:21.233257+00:00",'
            b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
            b'"lei":"254900OPPU84GM83MG36"}}-VA0-FABE4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE'
            b'-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw-AxDNI7_ZmaI-AABAAVgLJOmUNlMZpSGV0hr'
            b'-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg')

        ser = (
            b'{"v":"KERI10JSON000136_","i":"Eq1XfsuS1WNK2uLnAwfJ2SwGz8MhPUDnL0Mi1yNvTQnY",'
            b'"x":"EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY",'
            b'"issuer":"E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E","issuance":"2021-06-27T21:26:21.233257+00:00",'
            b'"d":{"id":"did:keri:Efaavv0oadfghasdfn443fhbyyr4v",'
            b'"lei":"254900OPPU84GM83MG36"}}')
        seal = (
            b'E4YPqsEOaPNaZxVIbY-Gx2bJgP-c7AH_K7pEE-YfcI9E0AAAAAAAAAAAAAAAAAAAAAAAElHzHwX3V6itsD2Ksg_CNBbUNTBYzLYw'
            b'-AxDNI7_ZmaI')

        sig0 = (
            b'AAVgLJOmUNlMZpSGV0hr-KddJmmEByoxfDdvkW161VsZO2_gjYf5OODwjyA3oSThfXGnj5Jhk5iszNuT2ZSsTMBg'
        )

        sidWallet = Wallet(hab=sidHab, db=sidPDB)

        parseCredential(ims=msg, wallet=sidWallet, typ=JSONSchema(resolver=cache))

        # verify we can load serialized VC by SAID
        key = creder.said.encode("utf-8")
        assert sidPDB.getSers(key) == ser

        # verify the signature
        sigs = sidPDB.getSigs(key)
        assert len(sigs) == 1
        assert sigs[0] == sig0

        # verify the seal
        sl = sidPDB.getSeals(key)
        assert sl == seal

        # verify we can look up credential by Schema SAID
        schema = sidPDB.getSchms(schemer.saider.qb64b)
        assert len(schema) == 1
        assert schema[0] == key


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
            lei="254900OPPU84GM83MG36"
        )

        cache = CacheResolver()
        cache.add(schemer.said, schemer.raw)

        creder = credential(issuer=sigHab.pre,
                            schema=schemer.said,
                            subject=credSubject,
                            issuance="2021-06-27T21:26:21.233257+00:00",
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
        assert proof == (b'-FABEiRjCnZfca8gUZqecerjGpjkiY8dIkGudP6GfapWi5MU0AAAAAAAAAAAAAAAAAAAAABAECc96yX1sYswnD6LXE'
                         b'coNuJ0ehi8gkFMEGedqURhXMBU-AADAAarmUESbxAsy42qOTYN_ChWWgHT7HlM6_qTunFZeuTf9ozrGmvJ-RSjh2r4'
                         b'cbaID5eKe7mU3PTziJ2YjNlDB1DwAByOIg2T3S2bb8KnI40e0P5Ucllxt-5ZvxX2_2XfrCp6s8DjodXvVhZqqsQVyN'
                         b'jOvg9MM_fh5s02NKYJ4s9UXgDgACC3_hfvm_H77YuE4IndBvm2DdB2p_wgN9K-VOefzv11e4SLX4W8_Ns4hiaMm3ul'
                         b'm8f4RAaoJEICDax-xomO1mCA')

        prefixer, seqner, diger, isigers = parseProof(proof)
        assert prefixer.qb64 == sigHab.pre
        assert diger.qb64 == sigHab.kever.lastEst.d
        assert seqner.sn == 4
        assert len(isigers) == 3



if __name__ == '__main__':
    test_wallet()
    test_build_proof()
    test_parse_proof()
