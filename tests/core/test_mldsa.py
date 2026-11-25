# -*- encoding: utf-8 -*-
"""
tests.core.test_mldsa module

ML-DSA (FIPS 204) signing and verification.

The master table codes are the ones proposed in trustoverip/kswg-cesr-specification#185
and the indexed codes the ones proposed in #186. Neither is merged yet. #186 puts every
post-quantum indexed signature in an eight-character scheme with a three-character index and
ondex, and picks the selector from the raw signature size modulo 3. ML-DSA-65 (3309 bytes,
0 mod 3) uses the existing selector "3". ML-DSA-44 (2420 bytes, 2 mod 3) uses a new selector
"8" with one lead byte, and ML-DSA-87 (4627 bytes, 1 mod 3) a new selector "9" with two.
"""
import os

import pytest

from cryptography.hazmat.primitives.asymmetric import mldsa

from keri.kering import (Vrsn_1_0, Vrsn_2_0, Kinds, InvalidVarIndexError, InvalidSizeError,
                         ValidationError)
from keri.core import (Matter, Indexer, Signer, Verfer, Cigar, Siger, Diger,
                       Counter, Codens, Kever, Kevery, Parser, MtrDex, IdrDex,
                       Encrypter, Decrypter, SeedCodes, SeedCodeByVerferCode,
                       incept, rotate, messagize)
from keri.db import openDB


# (seed code, verfer code, sig code, dual indexed code, current-only indexed code,
#  cryptography private key class, raw verkey size, raw sig size)
PARAMS = [
    (MtrDex.ML_DSA_44_Seed, MtrDex.ML_DSA_44, MtrDex.ML_DSA_44_Sig,
     IdrDex.ML_DSA_44_Big_Sig, IdrDex.ML_DSA_44_Big_Crt_Sig,
     mldsa.MLDSA44PrivateKey, 1312, 2420),
    (MtrDex.ML_DSA_65_Seed, MtrDex.ML_DSA_65, MtrDex.ML_DSA_65_Sig,
     IdrDex.ML_DSA_65_Big_Sig, IdrDex.ML_DSA_65_Big_Crt_Sig,
     mldsa.MLDSA65PrivateKey, 1952, 3309),
    (MtrDex.ML_DSA_87_Seed, MtrDex.ML_DSA_87, MtrDex.ML_DSA_87_Sig,
     IdrDex.ML_DSA_87_Big_Sig, IdrDex.ML_DSA_87_Big_Crt_Sig,
     mldsa.MLDSA87PrivateKey, 2592, 4627),
]


def test_mldsa_matter_codes_match_cesr_185():
    """Codes and full sizes are the rows #185 adds to the master table."""
    expected = {
        # code: (name, total qb64 chars from the #185 table)
        '3AAA': ('ML_DSA_44', 1756),
        '2AAA': ('ML_DSA_44_Sig', 3232),
        '2AAB': ('ML_DSA_44_Seed', 48),
        '2AAC': ('ML_DSA_65', 2608),
        '1AAQ': ('ML_DSA_65_Sig', 4416),
        '2AAD': ('ML_DSA_65_Seed', 48),
        '1AAR': ('ML_DSA_87', 3460),
        '3AAB': ('ML_DSA_87_Sig', 6176),
        '2AAE': ('ML_DSA_87_Seed', 48),
    }
    for code, (name, fs) in expected.items():
        assert getattr(MtrDex, name) == code
        assert Matter.Codes[name] == code
        assert Matter.Sizes[code].fs == fs
        assert Matter.Sizes[code].hs == 4
        assert Matter.Sizes[code].ss == 0
        assert Matter.Sizes[code].ls == int(code[0]) - 1  # selector 1, 2, 3 lead 0, 1, 2

    for _, vcode, scode, _, _, _, vsize, ssize in PARAMS:
        assert Matter._rawSize(vcode) == vsize
        assert Matter._rawSize(scode) == ssize
    for seed_code in (MtrDex.ML_DSA_44_Seed, MtrDex.ML_DSA_65_Seed, MtrDex.ML_DSA_87_Seed):
        assert Matter._rawSize(seed_code) == 32  # FIPS 204 seed xi

    # each fixed code round trips through qb64 and qb2 at its raw size
    for code in expected:
        raw = os.urandom(Matter._rawSize(code))
        matter = Matter(raw=raw, code=code)
        assert len(matter.qb64) == Matter.Sizes[code].fs
        assert Matter(qb64=matter.qb64).raw == raw
        assert Matter(qb2=matter.qb2).raw == raw


def test_mldsa_indexer_codes():
    """Indexed codes and full sizes are the rows #186 adds to the indexed code table."""
    expected = {
        '8A': ('ML_DSA_44_Big_Sig', 3236),
        '8B': ('ML_DSA_44_Big_Crt_Sig', 3236),
        '3C': ('ML_DSA_65_Big_Sig', 4420),
        '3D': ('ML_DSA_65_Big_Crt_Sig', 4420),
        '9A': ('ML_DSA_87_Big_Sig', 6180),
        '9B': ('ML_DSA_87_Big_Crt_Sig', 6180),
    }
    for code, (name, fs) in expected.items():
        assert getattr(IdrDex, name) == code
        assert Indexer.Codes[name] == code
        assert Indexer.Sizes[code].fs == fs

    # every ML-DSA indexed code is eight characters with a three character index and ondex,
    # and its lead size is what the raw signature size modulo 3 requires
    for selector, ls in (('3', 0), ('8', 1), ('9', 2)):
        assert Indexer.Hards[selector] == 2
    for code, (_, fs) in expected.items():
        hs, ss, os_, fs, ls = Indexer.Sizes[code]
        assert (hs, ss, os_) == (2, 6, 3)
        assert ls == {'3': 0, '8': 1, '9': 2}[code[0]]
        assert (Indexer._rawSize(code) + ls) % 3 == 0

    assert Indexer._rawSize('8A') == 2420
    assert Indexer._rawSize('3C') == 3309
    assert Indexer._rawSize('9A') == 4627


@pytest.mark.parametrize("both,crt,rawsize,ls", [
    (IdrDex.ML_DSA_44_Big_Sig, IdrDex.ML_DSA_44_Big_Crt_Sig, 2420, 1),
    (IdrDex.ML_DSA_87_Big_Sig, IdrDex.ML_DSA_87_Big_Crt_Sig, 4627, 2),
])
def test_indexer_lead_byte_selector_round_trip(both, crt, rawsize, ls):
    """Selector 8 carries one lead byte and selector 9 two, which Indexer must add on the way
    out and strip on the way back, in both text and binary domains."""
    fs = Indexer.Sizes[both].fs
    raw = os.urandom(rawsize)
    for index, ondex in ((0, 0), (5, 9), (262143, 262143)):
        idx = Indexer(raw=raw, code=both, index=index, ondex=ondex)
        assert len(idx.qb64) == fs
        assert len(idx.qb2) == fs * 3 // 4
        assert idx.qb64.startswith(both)

        back = Indexer(qb64=idx.qb64)
        assert (back.code, back.index, back.ondex, back.raw) == (both, index, ondex, raw)

        back = Indexer(qb2=idx.qb2)
        assert (back.code, back.index, back.ondex, back.raw) == (both, index, ondex, raw)

    idx = Indexer(raw=raw, code=crt, index=7)
    assert idx.ondex is None
    back = Indexer(qb64=idx.qb64)
    assert back.index == 7 and back.ondex is None and back.raw == raw

    # a raw of the wrong size is rejected rather than silently truncated or padded
    with pytest.raises(Exception):
        Indexer(raw=raw[:-1], code=both, index=0)

    # stripping from a stream consumes exactly one primitive
    stream = bytearray(idx.qb64b + b'trailing')
    Indexer(qb64b=stream, strip=True)
    assert stream == bytearray(b'trailing')
    stream = bytearray(idx.qb2 + b'trailing')
    Indexer(qb2=stream, strip=True)
    assert stream == bytearray(b'trailing')

    # a non-zero lead byte is malformed, in either position when there are two
    for at in range(ls):
        qb2 = bytearray(idx.qb2)
        qb2[6 + at] = 0x01  # lead bytes follow the 8 char (6 byte) code
        with pytest.raises(ValueError):
            Indexer(qb2=bytes(qb2))


@pytest.mark.parametrize("seed_code,vcode,scode,both,crt,klas,vsize,ssize", PARAMS)
def test_mldsa_signer(seed_code, vcode, scode, both, crt, klas, vsize, ssize):
    """Signer makes FIPS 204 key pairs from a 32 byte seed and signs with pure ML-DSA."""
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    signer = Signer(code=seed_code)  # random seed
    assert signer.code == seed_code
    assert len(signer.raw) == 32
    assert signer.verfer.code == vcode
    assert len(signer.verfer.raw) == vsize
    assert signer.verfer.transferable

    # the public key is the one FIPS 204 KeyGen derives from the seed
    seed = bytes(range(32))
    signer = Signer(raw=seed, code=seed_code)
    lib = klas.from_seed_bytes(seed)
    assert signer.verfer.raw == lib.public_key().public_bytes_raw()
    assert Signer(qb64=signer.qb64).verfer.qb64 == signer.verfer.qb64

    cigar = signer.sign(ser)
    assert isinstance(cigar, Cigar)
    assert cigar.code == scode
    assert len(cigar.raw) == ssize
    assert signer.verfer.verify(cigar.raw, ser)
    assert not signer.verfer.verify(cigar.raw, ser + b'x')
    assert not signer.verfer.verify(cigar.raw[:-1] + bytes([cigar.raw[-1] ^ 1]), ser)
    assert not signer.verfer.verify(cigar.raw[:-1], ser)  # wrong size is False not raise

    # a Verfer rebuilt from qb64 verifies
    assert Verfer(qb64=signer.verfer.qb64).verify(cigar.raw, ser)

    # signatures are pure ML-DSA with an empty context string, so any FIPS 204 verifier
    # using the default context accepts them and one using another context does not
    pub = lib.public_key()
    pub.verify(cigar.raw, ser)
    pub.verify(cigar.raw, ser, context=b'')
    with pytest.raises(Exception):
        pub.verify(cigar.raw, ser, context=b'keri')

    # and the verifier accepts signatures the library made
    assert signer.verfer.verify(lib.sign(ser), ser)
    assert not signer.verfer.verify(lib.sign(ser, context=b'keri'), ser)

    # another key does not verify
    other = Signer(code=seed_code)
    assert not other.verfer.verify(cigar.raw, ser)

    # indexed, both lists
    siger = signer.sign(ser, index=0)
    assert isinstance(siger, Siger)
    assert siger.code == both
    assert (siger.index, siger.ondex) == (0, 0)
    assert len(siger.raw) == ssize
    assert siger.verfer.qb64 == signer.verfer.qb64
    assert signer.verfer.verify(siger.raw, ser)
    back = Siger(qb64=siger.qb64)
    assert back.code == both and back.raw == siger.raw
    assert signer.verfer.verify(back.raw, ser)
    back = Siger(qb2=siger.qb2)
    assert back.code == both and back.raw == siger.raw

    siger = signer.sign(ser, index=3, ondex=1)
    assert siger.code == both
    assert (siger.index, siger.ondex) == (3, 1)
    back = Siger(qb64=siger.qb64)
    assert (back.index, back.ondex) == (3, 1)

    # indexed, current list only
    siger = signer.sign(ser, index=2, only=True)
    assert siger.code == crt
    assert (siger.index, siger.ondex) == (2, None)
    back = Siger(qb64=siger.qb64)
    assert back.code == crt and (back.index, back.ondex) == (2, None)
    assert signer.verfer.verify(back.raw, ser)

    # no small indexed code exists for ML-DSA, so a small index still gets the big code
    assert signer.sign(ser, index=0, only=True).code == crt


@pytest.mark.parametrize("seed_code", [p[0] for p in PARAMS])
def test_mldsa_index_limit(seed_code):
    """Every ML-DSA indexed code has a three character index and ondex, so the largest of
    either is 64**3 - 1."""
    signer = Signer(code=seed_code)
    ser = b'event'
    assert signer.sign(ser, index=262143).index == 262143
    assert signer.sign(ser, index=0, ondex=262143).ondex == 262143
    with pytest.raises(InvalidVarIndexError):
        signer.sign(ser, index=262144)
    with pytest.raises(InvalidVarIndexError):
        signer.sign(ser, index=0, ondex=262144)


@pytest.mark.parametrize("seed_code", [p[0] for p in PARAMS])
def test_mldsa_signer_has_no_non_transferable_form(seed_code):
    """#185 defines one verification key code per ML-DSA parameter set and no
    non-transferable variant, so asking for one is an error and not a silent upgrade."""
    with pytest.raises(ValueError):
        Signer(code=seed_code, transferable=False)


def test_mldsa_seed_codes_registered():
    """Rotation carries the algorithm forward and the encrypted key store wraps the seed."""
    for seed_code, vcode, *_ in PARAMS:
        assert SeedCodeByVerferCode[vcode] == seed_code
        assert seed_code in SeedCodes

    keypair = Signer(code=MtrDex.Ed25519_Seed)
    encrypter = Encrypter(verkey=keypair.verfer.qb64b)
    decrypter = Decrypter(seed=keypair.qb64b)
    for seed_code, *_ in PARAMS:
        signer = Signer(code=seed_code)
        cipher = encrypter.encrypt(prim=signer)
        recovered = decrypter.decrypt(cipher=cipher, transferable=True)
        assert recovered.code == seed_code
        assert recovered.qb64 == signer.qb64
        assert recovered.verfer.qb64 == signer.verfer.qb64
        recovered = decrypter.decrypt(qb64=cipher.qb64, transferable=True)
        assert recovered.qb64 == signer.qb64


@pytest.mark.parametrize("seed_code", [p[0] for p in PARAMS])
def test_mldsa_kel_validates(seed_code):
    """A Kevery that has never seen the controller accepts an ML-DSA key event log:
    inception with two keys on a 2 of 2 threshold, then a rotation to the pre-rotated keys."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = [Signer(raw=bytes([i]) * 32, code=seed_code) for i in range(4)]

    with openDB(name="controller") as conlgr, openDB(name="validator") as vallgr:
        msgs = bytearray()

        # an ML-DSA key is too large to be a basic prefix, so the prefix is a digest
        serder = incept(keys=[s.verfer.qb64 for s in signers[:2]],
                        isith="2",
                        ndigs=[Diger(ser=s.verfer.qb64b).qb64 for s in signers[2:]],
                        nsith="2",
                        code=MtrDex.Blake3_256, **kwa)
        sigers = [s.sign(serder.raw, index=i) for i, s in enumerate(signers[:2])]
        kever = Kever(serder=serder, sigers=sigers, db=conlgr)
        msgs.extend(serder.raw)
        msgs.extend(Counter(Codens.ControllerIdxSigs, count=len(sigers),
                            version=Vrsn_1_0).qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

        serder = rotate(pre=kever.prefixer.qb64,
                        keys=[s.verfer.qb64 for s in signers[2:]],
                        isith="2",
                        dig=kever.serder.said,
                        ndigs=[Diger(ser=signers[0].verfer.qb64b).qb64],
                        sn=1, **kwa)
        sigers = [s.sign(serder.raw, index=i) for i, s in enumerate(signers[2:])]
        kever.update(serder=serder, sigers=sigers)
        msgs.extend(serder.raw)
        msgs.extend(Counter(Codens.ControllerIdxSigs, count=len(sigers),
                            version=Vrsn_1_0).qb64b)
        for siger in sigers:
            msgs.extend(siger.qb64b)

        kevery = Kevery(db=vallgr)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(msgs), kvy=kevery)

        pre = kever.prefixer.qb64
        assert pre in kevery.kevers
        vkever = kevery.kevers[pre]
        assert vkever.sn == 1
        assert [v.qb64 for v in vkever.verfers] == [s.verfer.qb64 for s in signers[2:]]
        assert vkever.serder.said == kever.serder.said


def test_mldsa_kel_rejects_forged_signature():
    """One signature that does not verify leaves a 2 of 2 inception unaccepted."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = [Signer(code=MtrDex.ML_DSA_87_Seed) for _ in range(3)]

    with openDB(name="validator") as vallgr:
        serder = incept(keys=[s.verfer.qb64 for s in signers[:2]],
                        isith="2",
                        ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                        code=MtrDex.Blake3_256, **kwa)
        good = signers[0].sign(serder.raw, index=0)
        forged = signers[2].sign(serder.raw, index=1)  # key not in the event
        msgs = bytearray(serder.raw)
        msgs.extend(Counter(Codens.ControllerIdxSigs, count=2, version=Vrsn_1_0).qb64b)
        msgs.extend(good.qb64b)
        msgs.extend(forged.qb64b)

        kevery = Kevery(db=vallgr)
        Parser(version=Vrsn_1_0).parse(ims=msgs, kvy=kevery)
        assert serder.pre not in kevery.kevers


@pytest.mark.parametrize("vrsn", [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize("framed", [False, True])
def test_mldsa_87_three_signatures_overflow_small_counters(vrsn, framed):
    """Three ML-DSA-87 signatures are 4632 quadlets, past the 4095 a small counter can
    count. messagize must promote to the big counter and Kevery must accept the result."""
    signers = [Signer(raw=bytes([i]) * 32, code=MtrDex.ML_DSA_87_Seed) for i in range(4)]
    serder = incept(keys=[s.verfer.qb64 for s in signers[:3]], isith="3",
                    ndigs=[Diger(ser=signers[3].verfer.qb64b).qb64],
                    code=MtrDex.Blake3_256, version=vrsn, kind=Kinds.json)
    sigers = [s.sign(serder.raw, index=i) for i, s in enumerate(signers[:3])]
    assert sum(len(siger.qb64) for siger in sigers) // 4 > 4095

    msg = messagize(serder, sigers=sigers, framed=framed, gvrsn=vrsn)

    with openDB(name="validator") as vallgr:
        kevery = Kevery(db=vallgr)
        Parser(version=vrsn).parse(ims=bytearray(msg), kvy=kevery)
        assert serder.pre in kevery.kevers
        assert len(kevery.kevers[serder.pre].verfers) == 3


def test_fixed_seed_cipher_code_refuses_a_longer_seed():
    """X25519_Cipher_Seed holds a 44 char seed. Forcing it on a 48 char ML-DSA seed used to
    truncate the sealed box silently, which made the stored key unrecoverable."""
    keypair = Signer(code=MtrDex.Ed25519_Seed)
    encrypter = Encrypter(verkey=keypair.verfer.qb64b)
    signer = Signer(code=MtrDex.ML_DSA_87_Seed)
    with pytest.raises(InvalidSizeError):
        encrypter.encrypt(prim=signer, code=MtrDex.X25519_Cipher_Seed)


@pytest.mark.parametrize("seed_code", [p[0] for p in PARAMS])
def test_mldsa_key_is_not_a_basic_prefix(seed_code):
    """No ML-DSA public key code is in PreDex, so a one-key inception without a digest code,
    which would otherwise make the key itself the prefix, is rejected rather than accepted
    with a prefix no validator could use."""
    signer = Signer(code=seed_code)
    with pytest.raises(ValidationError):
        incept(keys=[signer.verfer.qb64])
    serder = incept(keys=[signer.verfer.qb64], code=MtrDex.Blake3_256)
    assert serder.pre.startswith(MtrDex.Blake3_256)
