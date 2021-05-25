# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
import pytest

import pysodium
import blake3
import json
import hashlib
import dataclasses

import msgpack
import cbor2 as cbor

from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from fractions import Fraction

from keri.kering import Version, Versionage
from keri.kering import (EmptyMaterialError,  RawMaterialError, DerivationError,
                         ValidationError, ShortageError)
from keri.help.helping import sceil

from keri.core.coring import Sizage, MtrDex, Matter, IdrDex, Indexer, CtrDex, Counter
from keri.core.coring import (Verfer, Cigar, Signer, Salter,
                              Diger, Nexter, Prefixer)
from keri.core.coring import generateSigners,  generateSecrets
from keri.core.coring import intToB64, intToB64b, b64ToInt, b64ToB2, b2ToB64, nabSextets
from keri.core.coring import Seqner, Siger, Dater
from keri.core.coring import Serialage, Serials, Mimes, Vstrings
from keri.core.coring import Versify, Deversify, Rever, VERFULLSIZE, MINSNIFFSIZE
from keri.core.coring import Serder, Tholder
from keri.core.coring import Ilkage, Ilks


def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
                          rct='rct', ksn='ksn', vcp='vcp', vrt='vrt',
                          iss='iss', rev='rev', bis='bis', brv='brv', req="req")

    assert isinstance(Ilks, Ilkage)

    assert 'icp' in Ilks
    assert Ilks.icp == 'icp'
    assert 'rot' in Ilks
    assert Ilks.rot == 'rot'
    assert 'ixn' in Ilks
    assert Ilks.ixn == 'ixn'
    assert 'dip' in Ilks
    assert Ilks.dip == 'dip'
    assert 'drt' in Ilks
    assert Ilks.drt == 'drt'
    assert 'rct' in Ilks
    assert Ilks.rct == 'rct'
    assert 'ksn' in Ilks
    assert Ilks.ksn == 'ksn'

    assert 'vcp' in Ilks
    assert Ilks.vcp == 'vcp'
    assert 'vrt' in Ilks
    assert Ilks.vrt == 'vrt'
    assert 'iss' in Ilks
    assert Ilks.iss == 'iss'
    assert 'rev' in Ilks
    assert Ilks.rev == 'rev'
    assert 'bis' in Ilks
    assert Ilks.bis == 'bis'
    assert 'brv' in Ilks
    assert Ilks.brv == 'brv'

    """End Test """


def test_b64_conversions():
    """
    Test Base64 conversion utility routines
    """

    cs = intToB64(0)
    assert cs == "A"
    i = b64ToInt(cs)
    assert i == 0

    cs = intToB64b(0)
    assert cs == b"A"
    i = b64ToInt(cs)
    assert i == 0

    cs = intToB64(27)
    assert cs == "b"
    i = b64ToInt(cs)
    assert i == 27

    cs = intToB64b(27)
    assert cs == b"b"
    i = b64ToInt(cs)
    assert i == 27

    cs = intToB64(27, l=2)
    assert cs == "Ab"
    i = b64ToInt(cs)
    assert i == 27

    cs = intToB64b(27, l=2)
    assert cs == b"Ab"
    i = b64ToInt(cs)
    assert i == 27

    cs = intToB64(80)
    assert cs == "BQ"
    i = b64ToInt(cs)
    assert i == 80

    cs = intToB64b(80)
    assert cs == b"BQ"
    i = b64ToInt(cs)
    assert i == 80

    cs = intToB64(4095)
    assert cs == '__'
    i = b64ToInt(cs)
    assert i == 4095

    cs = intToB64b(4095)
    assert cs == b'__'
    i = b64ToInt(cs)
    assert i == 4095

    cs = intToB64(4096)
    assert cs == 'BAA'
    i = b64ToInt(cs)
    assert i == 4096

    cs = intToB64b(4096)
    assert cs == b'BAA'
    i = b64ToInt(cs)
    assert i == 4096

    cs = intToB64(6011)
    assert cs == "Bd7"
    i = b64ToInt(cs)
    assert i == 6011

    cs = intToB64b(6011)
    assert cs == b"Bd7"
    i = b64ToInt(cs)
    assert i == 6011

    s = "-BAC"
    b = b64ToB2(s[:])
    assert len(b) == 3
    assert b == b'\xf8\x10\x02'
    t = b2ToB64(b, 4)
    assert t == s[:]
    i = int.from_bytes(b, 'big')
    assert i == 0o76010002
    i >>= 2 *  (len(s) % 4)
    assert i == 0o76010002
    p = nabSextets(b, 4)
    assert p == b'\xf8\x10\x02'

    b = b64ToB2(s[:3])
    assert len(b) == 3
    assert b == b'\xf8\x10\x00'
    t = b2ToB64(b, 3)
    assert t == s[:3]
    i = int.from_bytes(b, 'big')
    assert i == 0o76010000
    i >>= 2 * (len(s[:3]) % 4)
    assert i ==0o760100
    p = nabSextets(b, 3)
    assert p == b'\xf8\x10\x00'

    b = b64ToB2(s[:2])
    assert len(b) == 2
    assert b == b'\xf8\x10'
    t = b2ToB64(b, 2)
    assert t == s[:2]
    i = int.from_bytes(b, 'big')
    assert i == 0o174020
    i >>= 2 * (len(s[:2]) % 4)
    assert i == 0o7601
    p = nabSextets(b, 2)
    assert p == b'\xf8\x10'

    b = b64ToB2(s[:1])
    assert len(b) == 1
    assert b == b'\xf8'
    t = b2ToB64(b, 1)
    assert t == s[:1]
    i = int.from_bytes(b, 'big')
    assert i == 0o370
    i >>= 2 * (len(s[:1]) % 4)
    assert i == 0o76
    p = nabSextets(b, 1)
    assert p == b'\xf8'

    """End Test"""


def test_matter():
    """
    Test Matter class
    """
    assert dataclasses.asdict(MtrDex) == {
                                            'Ed25519_Seed': 'A',
                                            'Ed25519N': 'B',
                                            'X25519': 'C',
                                            'Ed25519': 'D',
                                            'Blake3_256': 'E',
                                            'Blake2b_256': 'F',
                                            'Blake2s_256': 'G',
                                            'SHA3_256': 'H',
                                            'SHA2_256': 'I',
                                            'ECDSA_256k1_Seed': 'J',
                                            'Ed448_Seed': 'K',
                                            'X448': 'L',
                                            'Short': 'M',
                                            'Salt_128': '0A',
                                            'Ed25519_Sig': '0B',
                                            'ECDSA_256k1_Sig': '0C',
                                            'Blake3_512': '0D',
                                            'Blake2b_512': '0E',
                                            'SHA3_512': '0F',
                                            'SHA2_512': '0G',
                                            'Long': '0H',
                                            'ECDSA_256k1N': '1AAA',
                                            'ECDSA_256k1': '1AAB',
                                            'Ed448N': '1AAC',
                                            'Ed448': '1AAD',
                                            'Ed448_Sig': '1AAE',
                                            'Tag': '1AAF',
                                            'DateTime': '1AAG',
                                            'GPG': '9A',
                                         }

    assert Matter.Codex == MtrDex

    # first character of code with hard size of code
    assert Matter.Sizes == {
        'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
        'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1 ,'Q': 1, 'R': 1,
        'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
        'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
        'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
        's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
        '0': 2, '1': 4, '2': 5, '3': 6, '4': 8, '5': 9, '6': 10, '9': 2,
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Matter.Codes == {
                            'A': Sizage(hs=1, ss=0, fs=44),
                            'B': Sizage(hs=1, ss=0, fs=44),
                            'C': Sizage(hs=1, ss=0, fs=44),
                            'D': Sizage(hs=1, ss=0, fs=44),
                            'E': Sizage(hs=1, ss=0, fs=44),
                            'F': Sizage(hs=1, ss=0, fs=44),
                            'G': Sizage(hs=1, ss=0, fs=44),
                            'H': Sizage(hs=1, ss=0, fs=44),
                            'I': Sizage(hs=1, ss=0, fs=44),
                            'J': Sizage(hs=1, ss=0, fs=44),
                            'K': Sizage(hs=1, ss=0, fs=76),
                            'L': Sizage(hs=1, ss=0, fs=76),
                            'M': Sizage(hs=1, ss=0, fs=4),
                            '0A': Sizage(hs=2, ss=0, fs=24),
                            '0B': Sizage(hs=2, ss=0, fs=88),
                            '0C': Sizage(hs=2, ss=0, fs=88),
                            '0D': Sizage(hs=2, ss=0, fs=88),
                            '0E': Sizage(hs=2, ss=0, fs=88),
                            '0F': Sizage(hs=2, ss=0, fs=88),
                            '0G': Sizage(hs=2, ss=0, fs=88),
                            '0H': Sizage(hs=2, ss=0, fs=8),
                            '1AAA': Sizage(hs=4, ss=0, fs=48),
                            '1AAB': Sizage(hs=4, ss=0, fs=48),
                            '1AAC': Sizage(hs=4, ss=0, fs=80),
                            '1AAD': Sizage(hs=4, ss=0, fs=80),
                            '1AAE': Sizage(hs=4, ss=0, fs=56),
                            '1AAF': Sizage(hs=4, ss=0, fs=8),
                            '1AAG': Sizage(hs=4, ss=0, fs=36),
                            '9A': Sizage(hs=2, ss=2, fs=None),
                        }

    assert Matter.Codes['A'].hs == 1  # hard size
    assert Matter.Codes['A'].ss == 0  # soft size
    assert Matter.Codes['A'].fs == 44  # full size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Matter.Codes.keys():
        assert Matter.Sizes[ckey[0]] == Matter.Codes[ckey].hs

    #  verify all Codes have ss == 0 and not fs % 4 and hs > 0 and fs > hs
    #  if fs is not None else not (hs + ss) % 4
    for val in Matter.Codes.values():
        if val.fs is not None:
            assert val.ss == 0 and not val.fs % 4 and  val.hs > 0 and  val.fs > val.hs
        else:
            assert not (val.hs + val.ss) % 4

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Matter.Sizes.items():
        ckey = b64ToB2(skey)
        assert Matter.Bizes[ckey] == sval

    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'  #  str
    prefixb = prefix.encode("utf-8")  # bytes
    prebin = (b'\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1f'
              b'IS\xf3\x874\xbao\x90\x8c')  # pure base 2 binary qb2

    with pytest.raises(EmptyMaterialError):
        matter = Matter()

    with pytest.raises(EmptyMaterialError):
        matter = Matter(raw=verkey, code=None)

    with pytest.raises(EmptyMaterialError):
        matter = Matter(raw=verkey, code='')

    matter = Matter(raw=verkey)
    assert matter.raw == verkey
    assert matter.code == MtrDex.Ed25519N
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(prefixb)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64b=prefixb)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64=prefix)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    matter = Matter(qb64=prefixb)  #  works for either
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # test truncates extra bytes from qb64 parameter
    longprefix = prefix + "ABCD"  # extra bytes in size
    matter = Matter(qb64=longprefix)
    assert len(matter.qb64) == Matter.Codes[matter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortprefix = prefix[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        matter = Matter(qb64=shortprefix)

    matter = Matter(qb2=prebin)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # test truncates extra bytes from qb2 parameter
    longprebin = prebin + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    matter = Matter(qb2=longprebin)
    assert len(matter.qb64) == Matter.Codes[matter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortprebin = prebin[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        matter = Matter(qb2=shortprebin)

    matter = Matter(qb64=prefix.encode("utf-8"))  # test bytes not str
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb64b == prefix.encode("utf-8")

    # test truncates extra bytes from raw parameter
    longverkey = verkey + bytes([10, 11, 12])  # extra bytes
    matter = Matter(raw=longverkey)

    # test raises ShortageError if not enough bytes in raw parameter
    shortverkey =  verkey[:-3]  # not enough bytes
    with pytest.raises(RawMaterialError):
        matter = Matter(raw=shortverkey)

    # test prefix on full identifier
    full = prefix + ":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64=full)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False

    # test nongreedy prefixb on full identifier
    full = prefixb + b":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64b=full)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False

    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64b = encodeB64(sig)
    assert sig64b == b'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='
    sig64 =  sig64b.decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = b'0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsigB2 = (b'\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    matter = Matter(raw=sig, code=MtrDex.Ed25519_Sig)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qsig64b)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qsig64)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qsigB2)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False

    # test short
    val = int("F77F", 16)
    assert val == 63359
    raw = val.to_bytes(2, 'big')
    assert raw == b'\xf7\x7f'
    txt = encodeB64(raw)
    assert txt == b'938='
    qb64b = MtrDex.Short.encode("utf-8") + txt[:-1]
    assert qb64b == b'M938'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'3\xdd\xfc'

    matter = Matter(raw=raw, code=MtrDex.Short)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test long
    val = int("F7F33F7F", 16)
    assert val == 4159913855
    raw = val.to_bytes(4, 'big')
    assert raw ==b'\xf7\xf3?\x7f'
    txt = encodeB64(raw)
    assert txt == b'9_M_fw=='
    qb64b = MtrDex.Long.encode("utf-8") + txt[:-2]
    assert qb64b == b'0H9_M_fw'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'\xd0\x7f\x7f3\xf7\xf0'

    matter = Matter(raw=raw, code=MtrDex.Long)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test tag as number
    val = int("F89CFF", 16)
    assert val == 16293119
    raw = val.to_bytes(3, 'big')
    assert raw == b'\xf8\x9c\xff'
    txt = encodeB64(raw)
    assert txt == b'-Jz_'
    qb64b = MtrDex.Tag.encode("utf-8") + txt
    assert qb64b ==b'1AAF-Jz_'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'\xd4\x00\x05\xf8\x9c\xff'

    matter = Matter(raw=raw, code=MtrDex.Tag)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test tag as chars
    txt = b'icp_'
    raw = decodeB64(txt)
    assert raw == b'\x89\xca\x7f'
    val = int.from_bytes(raw, 'big')
    assert val == 9030271
    qb64b = MtrDex.Tag.encode("utf-8") + txt
    assert qb64b ==b'1AAFicp_'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'\xd4\x00\x05\x89\xca\x7f'

    matter = Matter(raw=raw, code=MtrDex.Tag)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tag
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # Test ._bexfil
    matter = Matter(qb64=prefix)  #
    raw = matter.raw
    code = matter.code
    qb2 = matter.qb2
    matter._bexfil(qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == prefix
    assert matter.qb2 == qb2

    # Test ._binfil
    test = matter._binfil()
    assert test == qb2

    # Test strip
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'BaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'  #  str
    prefixb = prefix.encode("utf-8")  # bytes
    prebin = (b'\x05\xa5:%\x1d\xa7\x9b\x0c\x99\xfa-\x1d\xf0\x96@\xa13Y\x1fu\x0b\xbd\x80\x1f'
              b'IS\xf3\x874\xbao\x90\x8c')  # pure base 2 binary qb2

    # strip ignored if qb64
    matter = Matter(qb64=prefix, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False

    ims = bytearray(prefixb)  # strip from ims qb64b
    matter = Matter(qb64b=ims, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert not ims  # stripped

    ims = bytearray(prebin)
    matter = Matter(qb2=ims, strip=True)  #  strip from ims qb2
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert not ims  # stripped

    # test strip with extra q64b
    extra = bytearray(b"ABCD")
    ims = bytearray(prefixb) + extra
    matter = Matter(qb64b=ims, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert ims == extra   # stripped not include extra

    # test strip with extra qb2
    extra = bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    ims = bytearray(prebin) + extra
    matter = Matter(qb2=ims, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert ims == extra   # stripped not include extra
    """ Done Test """


def test_indexer():
    """
    Test Indexer class
    """
    assert dataclasses.asdict(IdrDex) == {
                                           'Ed25519_Sig': 'A',
                                           'ECDSA_256k1_Sig': 'B',
                                           'Ed448_Sig': '0A',
                                           'Label': '0B'
                                         }


    assert IdrDex.Ed25519_Sig ==  'A'  # Ed25519 signature.
    assert IdrDex.ECDSA_256k1_Sig == 'B'  # ECDSA secp256k1 signature.

    assert Indexer.Codex == IdrDex

    # first character of code with hard size of code
    assert Indexer.Sizes == {
       'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
       'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
       'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
       'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
       'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
       's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
       '0': 2, '1': 2, '2': 2, '3': 2, '4': 3, '5': 4
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Indexer.Codes == {
                                'A': Sizage(hs=1, ss=1, fs=88),
                                'B': Sizage(hs=1, ss=1, fs=88),
                                '0A': Sizage(hs=2, ss=2, fs=156),
                                '0B': Sizage(hs=2, ss=2, fs=None)
                            }

    assert Indexer.Codes['A'].hs == 1  # hard size
    assert Indexer.Codes['A'].ss == 1  # soft size
    assert Indexer.Codes['A'].fs == 88  # full size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Indexer.Codes.keys():
        assert Indexer.Sizes[ckey[0]] == Indexer.Codes[ckey].hs

    # verify all Codes have hs > 0 and ss > 0 and fs >= hs + ss if fs is not None
    for val in Indexer.Codes.values():
        assert val.hs > 0 and val.ss > 0
        if val.fs is not None:
            assert val.fs >= val.hs + val.ss

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Indexer.Sizes.items():
        ckey = b64ToB2(skey)
        assert Indexer.Bizes[ckey] == sval


    with pytest.raises(EmptyMaterialError):
        indexer = Indexer()

    # Test signatures
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    sig64b = encodeB64(sig)
    sig64 = sig64b.decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    # replace pad "==" with code "AA"
    qsc = IdrDex.Ed25519_Sig + intToB64(0, l=1)
    assert qsc == 'AA'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[:-2]
    assert qsig64 == 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = decodeB64(qsig64b)
    assert len(qsig2b) == 66
    assert qsig2b == (b'\x00\t\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
                    b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
                    b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')


    indexer = Indexer(raw=sig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb2 == qsig2b

    # test wrong size of raw
    longsig = sig + bytes([10, 11, 12])
    indexer = Indexer(raw=longsig)

    shortsig = sig[:-3]
    with pytest.raises(RawMaterialError):
        indexer = Indexer(raw=shortsig)

    indexer = Indexer(qb64b=qsig64b)  # test with bytes not str
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)  # test with str not bytes
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test truncates extra bytes from qb64 parameter
    longqsig64 = qsig64 + "ABCD"
    indexer = Indexer(qb64=longqsig64)
    assert len(indexer.qb64) == Indexer.Codes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsig64 = qsig64[:-4]  # too short
    with pytest.raises(ShortageError):
        indexer = Indexer(qb64=shortqsig64)

    indexer = Indexer(qb2=qsig2b)  #  test with qb2
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test truncates extra bytes from qb2 parameter
    longqsig2b = qsig2b + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    indexer = Indexer(qb2=longqsig2b)
    assert indexer.qb2 == qsig2b
    assert len(indexer.qb64) == Indexer.Codes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqsig2b = qsig2b[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        indexer = Indexer(qb2=shortqsig2b)

    # test with non-zero index=5
    # replace pad "==" with code "AF"
    qsc = IdrDex.Ed25519_Sig + intToB64(5, l=1)
    assert qsc == 'AF'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[:-2]
    assert qsig64 == 'AFmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = (b'\x00Y\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
            b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
            b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb2=qsig2b)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    #  Label Code (variable length)
    label = b'Hello_World_Peep'
    index = len(label) // 4
    assert not len(label) % 4
    assert index == 4
    lraw = decodeB64(label)
    assert len(lraw) == len(label) * 3 // 4
    assert lraw == b'\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'
    ltext = encodeB64(lraw)
    assert ltext == b'Hello_World_Peep' == label
    qsc = IdrDex.Label + intToB64(index, l=2)
    assert qsc == '0BAE'
    qscb = qsc.encode("utf-8")
    lq64b = qscb + label
    assert lq64b == b"0BAEHello_World_Peep"
    lq64 = lq64b.decode("utf-8")

    indexer = Indexer(raw=lraw, code=IdrDex.Label, index=index)
    assert indexer.raw == lraw
    assert indexer.code == IdrDex.Label
    assert indexer.index == index
    assert indexer.qb64b == lq64b
    assert indexer.qb64 == lq64
    assert indexer.qb2 == b'\xd0\x10\x04\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'

    # index zero for empty label
    indexer = Indexer(raw=lraw, code=IdrDex.Label, index=0)
    assert indexer.raw == b''
    assert indexer.code == IdrDex.Label
    assert indexer.index == 0
    assert indexer.qb64b == b'0BAA'
    assert indexer.qb64 == '0BAA'
    assert indexer.qb2 == b'\xd0\x10\x00'

    # Test ._bexfil
    indexer = Indexer(qb64=qsig64)  #
    raw = indexer.raw
    code = indexer.code
    index = indexer.index
    qb2 = indexer.qb2
    indexer._bexfil(qb2)
    assert indexer.raw == raw
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.qb64 == qsig64
    assert indexer.qb2 == qb2

    # Test ._binfil
    test = indexer._binfil()
    assert test == qb2

    # test strip ims
    # strip ignored if qb64
    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    ims = bytearray(qsig64b)
    indexer = Indexer(qb64b=ims, strip=True)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert not ims

    ims = bytearray(qsig2b)
    indexer = Indexer(qb2=ims, strip=True)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert not ims

    # test extra bytes in ims qb64b
    extra = bytearray(b"ABCD")
    ims = bytearray(qsig64b) + extra
    indexer = Indexer(qb64b=ims, strip=True)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert ims == extra

    # test extra bytes in ims qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qsig2b) + extra
    indexer = Indexer(qb2=ims, strip=True)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert ims == extra
    """ Done Test """


def test_counter():
    """
    Test Counter class
    """
    assert dataclasses.asdict(CtrDex) == {
                                            'ControllerIdxSigs': '-A',
                                            'WitnessIdxSigs': '-B',
                                            'NonTransReceiptCouples': '-C',
                                            'TransReceiptQuadruples': '-D',
                                            'FirstSeenReplayCouples': '-E',
                                            'TransIndexedSigGroups': '-F',
                                            'SealSourceCouples':  '-G',
                                            'MessageDataGroups': '-U',
                                            'AttachedMaterialQuadlets': '-V',
                                            'MessageDataMaterialQuadlets': '-W',
                                            'CombinedMaterialQuadlets': '-X',
                                            'MaterialGroups': '-Y',
                                            'MaterialQuadlets': '-Z',
                                            'AnchorSealGroups': '-a',
                                            'ConfigTraits': '-c',
                                            'DigestSealQuadlets': '-d',
                                            'EventSealQuadlets': '-e',
                                            'Keys': '-k',
                                            'LocationSealQuadlets': '-l',
                                            'RootDigestSealQuadlets': '-r',
                                            'Witnesses': '-w',
                                            'BigMessageDataGroups': '-0U',
                                            'BigAttachedMaterialQuadlets': '-0V',
                                            'BigMessageDataMaterialQuadlets': '-0W',
                                            'BigCombinedMaterialQuadlets': '-0X',
                                            'BigMaterialGroups': '-0Y',
                                            'BigMaterialQuadlets': '-0Z'
                                         }

    assert CtrDex.ControllerIdxSigs ==  '-A'
    assert CtrDex.WitnessIdxSigs == '-B'

    assert Counter.Codex == CtrDex

    # first character of code with hard size of code
    assert Counter.Sizes == {
       '-A': 2, '-B': 2, '-C': 2, '-D': 2, '-E': 2, '-F': 2, '-G': 2, '-H': 2, '-I': 2,
       '-J': 2, '-K': 2, '-L': 2, '-M': 2, '-N': 2, '-O': 2, '-P': 2, '-Q': 2, '-R': 2,
       '-S': 2, '-T': 2, '-U': 2, '-V': 2, '-W': 2, '-X': 2, '-Y': 2, '-Z': 2,
       '-a': 2, '-b': 2, '-c': 2, '-d': 2, '-e': 2, '-f': 2, '-g': 2, '-h': 2, '-i': 2,
       '-j': 2, '-k': 2, '-l': 2, '-m': 2, '-n': 2, '-o': 2, '-p': 2, '-q': 2, '-r': 2,
       '-s': 2, '-t': 2, '-u': 2, '-v': 2, '-w': 2, '-x': 2, '-y': 2, '-z': 2,
       '-0': 3
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Counter.Codes == {
                                '-A': Sizage(hs=2, ss=2, fs=4),
                                '-B': Sizage(hs=2, ss=2, fs=4),
                                '-C': Sizage(hs=2, ss=2, fs=4),
                                '-D': Sizage(hs=2, ss=2, fs=4),
                                '-E': Sizage(hs=2, ss=2, fs=4),
                                '-F': Sizage(hs=2, ss=2, fs=4),
                                '-G': Sizage(hs=2, ss=2, fs=4),
                                '-U': Sizage(hs=2, ss=2, fs=4),
                                '-V': Sizage(hs=2, ss=2, fs=4),
                                '-W': Sizage(hs=2, ss=2, fs=4),
                                '-X': Sizage(hs=2, ss=2, fs=4),
                                '-Y': Sizage(hs=2, ss=2, fs=4),
                                '-Z': Sizage(hs=2, ss=2, fs=4),
                                '-a': Sizage(hs=2, ss=2, fs=4),
                                '-c': Sizage(hs=2, ss=2, fs=4),
                                '-d': Sizage(hs=2, ss=2, fs=4),
                                '-e': Sizage(hs=2, ss=2, fs=4),
                                '-k': Sizage(hs=2, ss=2, fs=4),
                                '-l': Sizage(hs=2, ss=2, fs=4),
                                '-r': Sizage(hs=2, ss=2, fs=4),
                                '-w': Sizage(hs=2, ss=2, fs=4),
                                '-0U': Sizage(hs=3, ss=5, fs=8),
                                '-0V': Sizage(hs=3, ss=5, fs=8),
                                '-0W': Sizage(hs=3, ss=5, fs=8),
                                '-0X': Sizage(hs=3, ss=5, fs=8),
                                '-0Y': Sizage(hs=3, ss=5, fs=8),
                                '-0Z': Sizage(hs=3, ss=5, fs=8)
                             }


    assert Counter.Codes['-A'].hs == 2  # hard size
    assert Counter.Codes['-A'].ss == 2  # soft size
    assert Counter.Codes['-A'].fs == 4  # full size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Counter.Codes.keys():
        assert Counter.Sizes[ckey[:2]] == Counter.Codes[ckey].hs

    #  verify all Codes have hs > 0 and ss > 0 and fs = hs + ss and not fs % 4
    for val in Counter.Codes.values():
        assert val.hs > 0 and val.ss > 0 and val.hs + val.ss == val.fs and not val.fs % 4

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Counter.Sizes.items():
        ckey = b64ToB2(skey)
        assert Counter.Bizes[ckey] == sval


    with pytest.raises(EmptyMaterialError):
        counter = Counter()

    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.ControllerIdxSigs)  #  default count = 1
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  #  test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64)
    assert len(counter.qb64) == Counter.Codes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(ShortageError):
        counter = Counter(qb64=shortqsc64)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == Counter.Codes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        counter = Counter(qb2=shortqscb2)

    # test with non-zero count=5
    count =  5
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  #  test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigMessageDataGroups + intToB64(count, l=5)
    assert qsc == '-0UAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigMessageDataGroups, count=count)
    assert counter.code == CtrDex.BigMessageDataGroups
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.BigMessageDataGroups
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.BigMessageDataGroups
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  #  test with qb2
    assert counter.code == CtrDex.BigMessageDataGroups
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # Test ._bexfil
    counter = Counter(qb64=qsc)  #
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.count == count
    assert counter.qb64 == qsc
    assert counter.qb2 == qb2

    # Test ._binfil
    test = counter._binfil()
    assert test == qb2

    # Test with strip
    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # strip ignored if qb64
    counter = Counter(qb64=qsc, strip=True)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    ims = bytearray(qscb2) #  test with qb2
    counter = Counter(qb2=ims, strip=True)
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with longer ims for qb64b
    extra = b"ABCD"
    ims = bytearray( qscb + b"ABCD")
    counter = Counter(qb64b=ims, strip=True)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == Counter.Codes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra =bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == Counter.Codes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True)  # strip

    ims = bytes(qscb2) #  test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True)


    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigMessageDataGroups + intToB64(count, l=5)
    assert qsc == '-0UAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True)  # test with bytes not str
    assert counter.code == CtrDex.BigMessageDataGroups
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True)  #  test with qb2
    assert counter.code == CtrDex.BigMessageDataGroups
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    """ Done Test """



def test_seqner():
    """
    Test Seqner sequence number subclass of CryMat
    """
    number = Seqner()  #  defaults to zero
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAAAA'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAAA'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    snraw = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    snqb64b = b'0AAAAAAAAAAAAAAAAAAAAAAA'
    snqb64 = '0AAAAAAAAAAAAAAAAAAAAAAA'
    snqb2 = b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    with pytest.raises(RawMaterialError):
        number = Seqner(raw=b'')

    number = Seqner(qb64b=snqb64b)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb64=snqb64)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb2=snqb2)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(raw=snraw)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    # test priority lower for sn and snh
    number = Seqner(qb64b=snqb64b, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb64=snqb64, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb2=snqb2, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(raw=snraw, sn=5, snh='a')
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 0
    assert number.snh == '0'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(sn=5, snh='a')
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    assert number.code == MtrDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAABQ'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAABQ'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P'

    number = Seqner(snh='a')
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
    assert number.code == MtrDex.Salt_128
    assert number.sn == 10
    assert number.snh == 'a'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAACg'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAACg'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0'

    # More tests
    snraw = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    snqb64b = b'0AAAAAAAAAAAAAAAAAAAAABQ'
    snqb64 = '0AAAAAAAAAAAAAAAAAAAAABQ'
    snqb2 = b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P'

    number = Seqner(qb64b=snqb64b)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb64=snqb64)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(qb2=snqb2, sn=5)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    number = Seqner(raw=snraw, sn=5)
    assert number.raw == snraw
    assert number.code == MtrDex.Salt_128
    assert number.sn == 5
    assert number.snh == '5'
    assert number.qb64 == snqb64
    assert number.qb64b == snqb64b
    assert number.qb2 == snqb2

    """ Done Test """


def test_dater():
    """
    Test Dater date time subclass of Matter
    """
    dater = Dater()  # defaults to now
    assert dater.code == MtrDex.DateTime
    assert len(dater.raw) == 24
    assert len(dater.qb64) == 36
    assert len(dater.qb2) == 27
    assert len(dater.dts) == 32

    dts1 = '2020-08-22T17:50:09.988921+00:00'
    dts1b = b'2020-08-22T17:50:09.988921+00:00'
    dt1raw = b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    dt1qb64 = '1AAG2020-08-22T17c50c09d988921p00c00'
    dt1qb64b = b'1AAG2020-08-22T17c50c09d988921p00c00'
    dt1qb2 = b'\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'

    dater = Dater(dts=dts1)
    assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts1
    assert dater.dtsb == dts1b
    assert dater.raw == dt1raw
    assert dater.qb64 == dt1qb64
    assert dater.qb64b == dt1qb64b
    assert dater.qb2 == dt1qb2

    dater = Dater(dts=dts1b)
    assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts1
    assert dater.dtsb == dts1b
    assert dater.raw == dt1raw
    assert dater.qb64 == dt1qb64
    assert dater.qb64b == dt1qb64b
    assert dater.qb2 == dt1qb2

    dts2 = '2020-08-22T17:50:09.988921-01:00'
    dts2b = b'2020-08-22T17:50:09.988921-01:00'
    dt2raw = b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4'
    dt2qb64 = '1AAG2020-08-22T17c50c09d988921-01c00'
    dt2qb64b = b'1AAG2020-08-22T17c50c09d988921-01c00'
    dt2qb2 = b'\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4'

    dater = Dater(dts=dts2)
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts2
    assert dater.dtsb == dts2b
    assert dater.raw == dt2raw
    assert dater.qb64 == dt2qb64
    assert dater.qb64b == dt2qb64b
    assert dater.qb2 == dt2qb2

    dater = Dater(dts=dts2b)
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts2
    assert dater.dtsb == dts2b
    assert dater.raw == dt2raw
    assert dater.qb64 == dt2qb64
    assert dater.qb64b == dt2qb64b
    assert dater.qb2 == dt2qb2

    dater = Dater(raw=dt1raw, code=MtrDex.DateTime)
    assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts1
    assert dater.dtsb == dts1b
    assert dater.raw == dt1raw
    assert dater.qb64 == dt1qb64
    assert dater.qb64b == dt1qb64b
    assert dater.qb2 == dt1qb2

    dater = Dater(qb64=dt1qb64)
    assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts1
    assert dater.dtsb == dts1b
    assert dater.raw == dt1raw
    assert dater.qb64 == dt1qb64
    assert dater.qb64b == dt1qb64b
    assert dater.qb2 == dt1qb2

    dater = Dater(qb64b=dt1qb64b)
    assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts1
    assert dater.dtsb == dts1b
    assert dater.raw == dt1raw
    assert dater.qb64 == dt1qb64
    assert dater.qb64b == dt1qb64b
    assert dater.qb2 == dt1qb2

    dater = Dater(qb2=dt1qb2)
    assert dater.raw == b'\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4'
    assert dater.code == MtrDex.DateTime
    assert dater.dts == dts1
    assert dater.dtsb == dts1b
    assert dater.raw == dt1raw
    assert dater.qb64 == dt1qb64
    assert dater.qb64b == dt1qb64b
    assert dater.qb2 == dt1qb2

    """ Done Test """



def test_verfer():
    """
    Test the support functionality for verifier subclass of crymat
    """
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)

    with pytest.raises(EmptyMaterialError):
        verfer = Verfer()

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    assert verfer.raw == verkey
    assert verfer.code == MtrDex.Ed25519N

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    sig = pysodium.crypto_sign_detached(ser, seed + verkey)  # sigkey = seed + verkey

    result = verfer.verify(sig, ser)
    assert result == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    assert verfer.raw == verkey
    assert verfer.code == MtrDex.Ed25519

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    sig = pysodium.crypto_sign_detached(ser, seed + verkey)  # sigkey = seed + verkey

    result = verfer.verify(sig, ser)
    assert result == True

    with pytest.raises(ValueError):
        verfer = Verfer(raw=verkey, code=MtrDex.Blake3_256)
    """ Done Test """

def test_cigar():
    """
    Test Cigar subclass of CryMat
    """
    with pytest.raises(EmptyMaterialError):
        cigar = Cigar()

    qsig64 = '0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    cigar = Cigar(qb64=qsig64)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert cigar.qb64 == qsig64
    assert cigar.verfer == None

    verkey,  sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    cigar.verfer = verfer
    assert  cigar.verfer == verfer

    cigar = Cigar(qb64=qsig64, verfer=verfer)
    assert  cigar.verfer == verfer
    """ Done Test """


def test_signer():
    """
    Test the support functionality for signer subclass of crymat
    """
    signer = Signer()  # defaults provide Ed25519 signer Ed25519 verfer
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    crymat = signer.sign(ser)
    assert crymat.code == MtrDex.Ed25519_Sig
    assert len(crymat.raw) == Matter._rawSize(crymat.code)
    result = signer.verfer.verify(crymat.raw, ser)
    assert result == True

    sigmat = signer.sign(ser, index=0)
    assert sigmat.code == IdrDex.Ed25519_Sig
    assert len(sigmat.raw) == Indexer._rawSize(sigmat.code)
    assert sigmat.index == 0
    result = signer.verfer.verify(sigmat.raw, ser)
    assert result == True
    result = signer.verfer.verify(sigmat.raw, ser + b'ABCDEFG')
    assert result == False

    assert crymat.raw == sigmat.raw

    signer = Signer(transferable=False)  # Ed25519N verifier
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519N
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    #create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    crymat = signer.sign(ser)
    assert crymat.code == MtrDex.Ed25519_Sig
    assert len(crymat.raw) == Matter._rawSize(crymat.code)
    result = signer.verfer.verify(crymat.raw, ser)
    assert result == True

    sigmat = signer.sign(ser, index=0)
    assert sigmat.code == IdrDex.Ed25519_Sig
    assert len(sigmat.raw) == Indexer._rawSize(sigmat.code)
    assert sigmat.index == 0
    result = signer.verfer.verify(sigmat.raw, ser)
    assert result == True
    result = signer.verfer.verify(sigmat.raw, ser + b'ABCDEFG')
    assert result == False


    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    signer = Signer(raw=seed, code=MtrDex.Ed25519_Seed)
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    crymat = signer.sign(ser)
    assert crymat.code == MtrDex.Ed25519_Sig
    assert len(crymat.raw) == Matter._rawSize(crymat.code)
    result = signer.verfer.verify(crymat.raw, ser)
    assert result == True

    sigmat = signer.sign(ser, index=1)
    assert sigmat.code == IdrDex.Ed25519_Sig
    assert len(sigmat.raw) == Indexer._rawSize(sigmat.code)
    assert sigmat.index == 1
    result = signer.verfer.verify(sigmat.raw, ser)
    assert result == True

    assert crymat.raw == sigmat.raw

    with pytest.raises(ValueError):  #  use invalid code not SEED
        signer = Signer(raw=seed, code=MtrDex.Ed25519N)

    with pytest.raises(ValueError):  #  use invalid code not SEED
        signer = Signer(code=MtrDex.Ed25519N)
    """ Done Test """


def test_salter():
    """
    Test the support functionality for salter subclass of crymat
    """
    salter = Salter()  # defaults to CryTwoDex.Salt_128
    assert salter.code == MtrDex.Salt_128
    assert len(salter.raw) == Matter._rawSize(salter.code) == 16

    raw = b'0123456789abcdef'

    salter = Salter(raw=raw)
    assert salter.raw == raw
    assert salter.qb64 == '0AMDEyMzQ1Njc4OWFiY2RlZg'

    signer = salter.signer(path="01", temp=True)  # defaults to Ed25519
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) ==  Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) ==  Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'Aw-yoFnFZ21ikGGtacpiK3AVrvuz3TZD6dfew9POqzRE'
    assert signer.verfer.qb64 == 'DVgXBkk4w3LcWScQIvy1RpBlEFTJD3EK_oXxyQb5QKsI'

    signer = salter.signer(path="01")  # defaults to Ed25519 temp = False level="low"
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) ==  Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) ==  Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'ASSpCI1N7FYH19MumAmn-Vdbre0WVP5jT-aBDDDij50I'
    assert signer.verfer.qb64 == 'D8kbIf0fUz9JRJ_XxHNfw6p3KHETJkmkqbkSbQ-emxZ0'

    salter = Salter(qb64='0AMDEyMzQ1Njc4OWFiY2RlZg')
    assert salter.raw == raw
    assert salter.qb64 == '0AMDEyMzQ1Njc4OWFiY2RlZg'

    with pytest.raises(ShortageError):
        salter = Salter(qb64='')


    """ Done Test """


def test_generatesigners():
    """
    Test the support function genSigners

    """
    signers = generateSigners(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert signer.verfer.code == MtrDex.Ed25519N

    # root = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    root = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    assert len(root) == 16
    signers = generateSigners(salt=root, count=4)  # default is transferable
    assert len(signers) == 4
    for signer in signers:
        assert signer.code == MtrDex.Ed25519_Seed
        assert signer.verfer.code == MtrDex.Ed25519

    sigkeys = [signer.qb64 for signer in signers]
    assert sigkeys == ['ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                       'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                       'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                       'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8']

    secrets = generateSecrets(salt=root, count=4)
    assert secrets == sigkeys

    """ End Test """


def test_diger():
    """
    Test the support functionality for Diger subclass of CryMat
    """
    with pytest.raises(EmptyMaterialError):
        diger = Diger()

    #create something to digest and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    dig = blake3.blake3(ser).digest()
    with pytest.raises(ValueError):
        diger = Diger(raw=dig, code=MtrDex.Ed25519)

    with pytest.raises(ValueError):
        diger = Diger(ser=ser, code=MtrDex.Ed25519)

    diger = Diger(raw=dig)  # defaults provide Blake3_256 digester
    assert diger.code == MtrDex.Blake3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)
    assert not diger.verify(ser=ser+b'ABCDEF')

    diger = Diger(raw=dig, code=MtrDex.Blake3_256)
    assert diger.code == MtrDex.Blake3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser)  # default code is  Blake3_256
    assert diger.code == MtrDex.Blake3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)
    assert diger.qb64b == b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'

    digb = b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    dig =  'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    diger = Diger(qb64b=digb)
    assert diger.qb64b == digb
    assert diger.qb64 == dig
    assert diger.code == MtrDex.Blake3_256

    diger = Diger(qb64=dig)
    assert diger.qb64 == dig
    assert diger.qb64b == digb
    assert diger.code == MtrDex.Blake3_256

    pig = b'sLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E='
    raw = decodeB64(pig)
    assert pig == encodeB64(raw)

    dig = hashlib.blake2b(ser, digest_size=32).digest()
    diger = Diger(raw=dig, code=MtrDex.Blake2b_256)
    assert diger.code == MtrDex.Blake2b_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=MtrDex.Blake2b_256)
    assert diger.code == MtrDex.Blake2b_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    dig = hashlib.blake2s(ser, digest_size=32).digest()
    diger = Diger(raw=dig, code=MtrDex.Blake2s_256)
    assert diger.code == MtrDex.Blake2s_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=MtrDex.Blake2s_256)
    assert diger.code == MtrDex.Blake2s_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    dig = hashlib.sha3_256(ser).digest()
    diger = Diger(raw=dig, code=MtrDex.SHA3_256)
    assert diger.code == MtrDex.SHA3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=MtrDex.SHA3_256)
    assert diger.code == MtrDex.SHA3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    dig = hashlib.sha256(ser).digest()
    diger = Diger(raw=dig, code=MtrDex.SHA2_256)
    assert diger.code == MtrDex.SHA2_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser, code=MtrDex.SHA2_256)
    assert diger.code == MtrDex.SHA2_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    diger0 = Diger(ser=ser) # default code
    diger1 = Diger(ser=ser, code=MtrDex.SHA3_256)
    diger2 = Diger(ser=ser, code=MtrDex.Blake2b_256)

    assert diger0.compare(ser=ser, diger=diger1)
    assert diger0.compare(ser=ser, diger=diger2)
    assert diger1.compare(ser=ser, diger=diger2)

    assert diger0.compare(ser=ser, dig=diger1.qb64)
    assert diger0.compare(ser=ser, dig=diger2.qb64b)
    assert diger1.compare(ser=ser, dig=diger2.qb64)

    ser1 = b'ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789'

    assert not diger0.compare(ser=ser, diger=Diger(ser=ser1))  # codes match
    assert not diger0.compare(ser=ser, dig=Diger(ser=ser1).qb64)  # codes match
    assert not diger0.compare(ser=ser,  # codes not match
                              diger=Diger(ser=ser1, code=MtrDex.SHA3_256))
    assert not diger0.compare(ser=ser,  # codes not match
                              dig=Diger(ser=ser1, code=MtrDex.SHA3_256).qb64b)

    """ Done Test """


def test_nexter():
    """
    Test the support functionality for Nexter subclass of Diger
    """
    with pytest.raises(EmptyMaterialError):
        nexter = Nexter()

    #create something to digest and verify
    # verkey, sigkey = pysodium.crypto_sign_keypair()
    # verfer = Verfer(raw=verkey)
    # assert verfer.qb64 == 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    sith = "{:x}".format(2)
    sithdig = blake3.blake3(sith.encode("utf-8")).digest()
    assert sithdig == b"\x81>\x9br\x91A\xe7\xf3\x85\xaf\xa0\xa2\xd0\xdf>l7\x89\xe4'\xff\xe4\xae\xefVjV[\xc8\xf2\xfe="

    sithdiger = Diger(raw=sithdig, code=MtrDex.Blake3_256)
    assert sithdiger.qb64 == 'EgT6bcpFB5_OFr6Ci0N8-bDeJ5Cf_5K7vVmpWW8jy_j0'

    keys = ['BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE',
            'BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk',
            'B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw']

    keydigs = [blake3.blake3(key.encode("utf-8")).digest() for key in keys]
    assert keydigs == [b'\x98\x1d\xba\xc8\xcc\xeb\xa0\x80\xa1\xfa\x8aJ5\xd9\x18\xc8\xfd4\xd2L\x1e\xbdM|Y\x02=\xe4\x96\x89\x0e6',
                       b';\x80\x97\xa7\xc8,\xd3"`\xd5\xf1a$\xbb9\x84~\xa7z\xa2p\x84Q\x18\xee\xfa\xc9\x11\xd3\xde\xf3\xb2',
                       b'-e\x99\x13 i\x8e\xb7\xcc\xd5E4\x9f}J#"\x17\x96Z\xc2\xa0\xb1\x0e#\x95\x07\x0f\xdc{[\x12']

    digers = [Diger(raw=keydig, code=MtrDex.Blake3_256) for keydig in keydigs]
    digs = [diger.qb64 for diger in digers]

    assert digs == ['EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                    'EO4CXp8gs0yJg1fFhJLs5hH6neqJwhFEY7vrJEdPe87I',
                    'ELWWZEyBpjrfM1UU0n31KIyIXllrCoLEOI5UHD9x7WxI']

    kints = [int.from_bytes(diger.raw,'big') for diger in digers]
    sint = int.from_bytes(sithdiger.raw, 'big')
    for kint in kints:
        sint ^= kint  # xor together

    raw = sint.to_bytes( Matter._rawSize(MtrDex.Blake3_256), 'big')
    assert raw == (b'\x0f\xc6/\x0e\xb5\xef\x1a\xe6\x88U\x9e\xbd^\xc0U\x03\x96\r\xda\x93S}\x03\x85\xc2\x07\xa5\xa1Q\xdeX\xab')

    nexter = Nexter(raw=raw)  # defaults provide Blake3_256 digest
    assert nexter.code == MtrDex.Blake3_256
    assert nexter.qb64 == 'ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs'
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(raw=raw)
    assert nexter.verify(raw=raw+b'ABCDEF') == False

    with pytest.raises(ValueError):  # bad code
        nexter = Nexter(raw=raw, code=MtrDex.Ed25519)

    #  defaults provide Blake3_256 digester
    nexter = Nexter(digs=digs)  # compute limen/sith from digs
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(digs=digs)
    assert nexter.verify(raw=raw)

    nexter = Nexter(keys=keys)  # compute limen/sith from keys
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(keys=keys)
    assert nexter.verify(raw=raw)
    assert nexter.verify(raw=raw+b'ABCDEF') == False

    with pytest.raises(EmptyMaterialError):
        nexter = Nexter(sith=sith)

    nexter = Nexter(sith=1, keys=keys)  # compute sith from int
    raw1 = nexter.raw
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(sith=1, keys=keys)
    assert nexter.verify(raw=raw1)

    nexter = Nexter(sith=1, digs=digs)
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(sith=1, digs=digs)
    assert nexter.verify(raw=raw1)

    nexter = Nexter(limen='1', digs=digs)
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(limen='1', digs=digs)
    assert nexter.verify(raw=raw1)

    nexter = Nexter(limen="1", keys=keys)
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(limen="1", keys=keys)
    assert nexter.verify(raw=raw1)

    ked = dict(kt=sith, k=keys)  #  subsequent event
    nexter = Nexter(ked=ked)
    assert nexter.code == MtrDex.Blake3_256
    assert len(nexter.raw) == Matter._rawSize(nexter.code)
    assert nexter.verify(ked=ked)
    assert nexter.verify(raw=raw)

    """ Done Test """


def test_prefixer():
    """
    Test the support functionality for prefixer subclass of crymat
    """
    preN = 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
    pre = 'DrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = (b'\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0='
              b'`\xf7\xbf\x8a\x18\x8a`q')
    verfer = Verfer(raw=verkey )
    assert verfer.qb64 == 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    nxtkey = (b"\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2"
              b'\xc4_\xf6\x00')
    nxtfer = Verfer(raw=nxtkey, code=MtrDex.Ed25519)
    assert nxtfer.qb64 == 'Dpl-JNEryNVTBgyMGmEym7xqzaOpBOngn2gSIssRf9gA'

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer()

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(raw=verkey, code=None)

    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(raw=verkey, code='')

    with pytest.raises(ValueError):
        prefixer = Prefixer(raw=verkey, code=MtrDex.SHA2_256)

    # test creation given raw and code no derivation
    prefixer = Prefixer(raw=verkey, code=MtrDex.Ed25519N)  # default code is None
    assert prefixer.code == MtrDex.Ed25519N
    assert len(prefixer.raw) == Matter._rawSize(prefixer.code)
    assert len(prefixer.qb64) == Matter.Codes[prefixer.code].fs

    ked = dict(k=[prefixer.qb64], n="", t="icp")
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(k=[prefixer.qb64], n="ABC", t="icp")
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    prefixer = Prefixer(raw=verkey, code=MtrDex.Ed25519)  # defaults provide Ed25519N prefixer
    assert prefixer.code == MtrDex.Ed25519
    assert len(prefixer.raw) == Matter._rawSize(prefixer.code)
    assert len(prefixer.qb64) == Matter.Codes[prefixer.code].fs

    ked = dict(k=[prefixer.qb64], t="icp")
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    prefixer = Prefixer(raw=verfer.raw, code=MtrDex.Ed25519N)
    assert prefixer.code == MtrDex.Ed25519N
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # Test basic derivation from ked
    ked = dict(k=[verfer.qb64], n="",  t="icp")
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519)
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(k=[verfer.qb64], n="",  t="icp")  #  ked without prefix
    with pytest.raises(EmptyMaterialError):  # no code and no pre in ked
        prefixer = Prefixer(ked=ked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)  # verfer code not match pre code
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=preN)
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=pre)
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519N)  # verfer code not match code

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=pre)
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519N)  # verfer code match code but not pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=preN)
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519N)  # verfer code match code and pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp", i=preN)
    prefixer = Prefixer(ked=ked)  # verfer code match pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="",  t="icp")
    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(ked=ked)

    ked = dict(k=[verfer.qb64], n="ABCD",  t="icp")
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519)

    # Test digest derivation from inception ked
    vs = Versify(version=Version, kind=Serials.json, size=0)
    sn = 0
    ilk = Ilks.icp
    sith = "1"
    keys = [Prefixer(raw=verkey, code=MtrDex.Ed25519).qb64]
    nxt = ""
    toad = 0
    wits = []
    cnfg = []

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'E_P7GKEdbet8OudlQvqILlGn7Fll5q6zfddiSXc-XY5Y'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with Nexter
    nexter = Nexter(keys=[nxtfer.qb64])
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'E7iQvEO7xsRE8UfBB0DCWnksY8ju-9madY3jJ1Y-eYPE'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with fractionally weighted sith
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]


    # create signers from secrets
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [siger.qb64 for siger in signers] == secrets
    # each signer has verfer for keys

    # Test with sith with one clause
    keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
    sith = [["1/2", "1/2", "1"]]
    nexter = Nexter(keys=[signers[3].verfer.qb64])  # default limen/sith
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer1 = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer1.qb64 == 'En6Ks1QPlek3GMHFTDlr-ufdZzQyHay_E2k5wTNB_MHM'
    assert prefixer1.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # now test with different sith but same weights in two clauses
    sith = [["1/2", "1/2"], ["1"]]
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer2 = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer2.qb64 == 'EITG4HqxAlyOrQBYW9utR7W_iJmq4NmOI9IrPicZfK5E'
    assert prefixer2.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False
    assert prefixer2.qb64 !=  prefixer1.qb64  # semantic diff -> syntactic diff

    sith = "1"
    seal = dict(i='EkbeB57LYWRYNqg4xarckyfd_LsaH0J350WmOdvMwU_Q',
                s='2',
                t=Ilks.ixn,
                d='E03rxRmMcP2-I2Gd0sUhlYwjk8KEz5gNGxPwPg-sGJds')

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=Ilks.dip,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nexter.qb64,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               da=seal
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EZHlPj5b4zrbJgd72n2sg3v5GYlam_BiX7Sl58mPRP84'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with allows
    with pytest.raises(ValueError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256,
                            allows=[MtrDex.Ed25519N, MtrDex.Ed25519])

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256,
                        allows=[MtrDex.Blake3_256, MtrDex.Ed25519])
    assert prefixer.qb64 == 'EZHlPj5b4zrbJgd72n2sg3v5GYlam_BiX7Sl58mPRP84'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    """ Done Test """



def test_siger():
    """
    Test Siger subclass of Sigmat
    """
    with pytest.raises(EmptyMaterialError):
        siger = Siger()

    qsig64 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = qsig64.encode("utf-8")
    assert qsig64b == b'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    siger = Siger(qb64b=qsig64b)
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    siger = Siger(qb64=qsig64)
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None

    siger = Siger(qb64=qsig64b)  #  also bytes
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None

    verkey,  sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    siger.verfer = verfer
    assert  siger.verfer == verfer

    siger = Siger(qb64=qsig64, verfer=verfer)
    assert  siger.verfer == verfer
    """ Done Test """


def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """
    assert Version == Versionage(major=1, minor=0)

    assert isinstance(Serials, Serialage)

    assert Serials.json == 'JSON'
    assert Serials.mgpk == 'MGPK'
    assert Serials.cbor == 'CBOR'

    assert 'JSON' in Serials
    assert 'MGPK' in Serials
    assert 'CBOR' in Serials

    assert Mimes.json == 'application/keri+json'
    assert Mimes.mgpk == 'application/keri+msgpack'
    assert Mimes.cbor == 'application/keri+cbor'

    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'


    icp = dict(vs = Vstrings.json,
              pre = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'icp',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              nxt = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              wits = [],
              cnfg = [],
             )

    rot = dict(vs = Vstrings.json,
              pre = 'AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
              sn = '0001',
              ilk = 'rot',
              dig = 'DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
              sith = 1,
              keys = ['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
              nxt = 'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
              toad = 0,
              cuts = [],
              adds = [],
              data = [],
             )

    icps = json.dumps(icp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(icps) == 303
    assert icps == (b'{"vs":"KERI10JSON000000_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"icp","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"nxt":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"wits":[],"cnfg":[]}')

    match = Rever.search(icps)
    assert match.group() == Vstrings.json.encode("utf-8")

    rots = json.dumps(rot, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(rots) == 313
    assert rots == (b'{"vs":"KERI10JSON000000_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"rot","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"nxt":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"cuts":[],"adds":[],"'
                    b'data":[]}')

    match = Rever.search(rots)
    assert match.group() == Vstrings.json.encode("utf-8")

    icp["vs"] = Vstrings.mgpk
    icps = msgpack.dumps(icp)
    assert len(icps) == 264
    assert icps == (b'\x8b\xa2vs\xb1KERI10MGPK000000_\xa3pre\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'SVPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3icp\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwy'
                    b'Z-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZ'
                    b'H3ULvYAfSVPzhzS6b5CM\xa3nxt\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4wits\x90\xa4cnfg\x90')


    match = Rever.search(icps)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    rot["vs"] = Vstrings.mgpk
    rots = msgpack.dumps(rot)
    assert len(rots) == 270
    assert rots == (b'\x8c\xa2vs\xb1KERI10MGPK000000_\xa3pre\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'SVPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3rot\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwy'
                    b'Z-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZ'
                    b'H3ULvYAfSVPzhzS6b5CM\xa3nxt\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4cuts\x90\xa4adds\x90\xa4data\x90')



    match = Rever.search(rots)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    icp["vs"] = Vstrings.cbor
    icps = cbor.dumps(icp)
    assert len(icps) == 264
    assert icps == (b'\xabbvsqKERI10CBOR000000_cprex,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'bsnd0001cilkcicpcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01'
                    b'dkeys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMcnxtx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dwits\x80dcnfg\x80')



    match = Rever.search(icps)
    assert match.group() == Vstrings.cbor.encode("utf-8")

    rot["vs"] = Vstrings.cbor
    rots = cbor.dumps(rot)
    assert len(rots) == 270
    assert rots == (b'\xacbvsqKERI10CBOR000000_cprex,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'bsnd0001cilkcrotcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01'
                    b'dkeys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMcnxtx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dcuts\x80dadds\x80ddata\x80')

    match = Rever.search(rots)
    assert match.group() == Vstrings.cbor.encode("utf-8")
    """Done Test"""

def test_versify():
    """
    Test Versify support
    """
    vs = Versify(kind=Serials.json, size=0)
    assert vs == "KERI10JSON000000_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.json
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.json, size=65)
    assert vs == "KERI10JSON000041_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.json
    assert version == Version
    assert size == 65

    vs = Versify(kind=Serials.mgpk, size=0)
    assert vs == "KERI10MGPK000000_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 65

    vs = Versify(kind=Serials.cbor, size=0)
    assert vs == "KERI10CBOR000000_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.cbor
    assert version == Version
    assert size == 0

    vs = Versify(kind=Serials.cbor, size=65)
    assert vs == "KERI10CBOR000041_"
    assert len(vs) == VERFULLSIZE
    kind, version, size = Deversify(vs)
    assert kind == Serials.cbor
    assert version == Version
    assert size == 65
    """End Test"""


def test_serder():
    """
    Test the support functionality for Serder key event serialization deserialization
    """
    with pytest.raises(ValueError):
        serder = Serder()

    e1 = dict(v=Vstrings.json,
              i="ABCDEFG",
              s="0001",
              t="rot")
    serder = Serder(ked=e1)
    assert serder.ked == e1
    assert serder.kind == Serials.json
    assert serder.version == Versionage(major=1, minor=0)
    assert serder.dig == 'E4z66CxKHEo-6YCbIbpd1SqeXKVkLdh3j8CwUq31XA4o'
    assert serder.digb == b'E4z66CxKHEo-6YCbIbpd1SqeXKVkLdh3j8CwUq31XA4o'
    assert serder.size == 60
    assert serder.verfers == []
    assert serder.raw == b'{"v":"KERI10JSON00003c_","i":"ABCDEFG","s":"0001","t":"rot"}'
    assert serder.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert e1s == b'{"v":"KERI10JSON00003c_","i":"ABCDEFG","s":"0001","t":"rot"}'
    vs = Versify(kind=Serials.json, size=len(e1s))  # use real length
    assert vs == 'KERI10JSON00003c_'
    e1["v"] = vs  # has real length
    pretty = serder.pretty()
    assert pretty == '{\n "v": "KERI10JSON00003c_",\n "i": "ABCDEFG",\n "s": "0001",\n "t": "rot"\n}'

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(ShortageError):  # test too short
        kind1, vers1, size1 = serder._sniff(e1s[:VERFULLSIZE])

    kind1, vers1, size1 = serder._sniff(e1s[:MINSNIFFSIZE])
    assert kind1 == Serials.json
    assert size1 == 60

    kind1, vers1, size1 = serder._sniff(e1s)
    assert kind1 == Serials.json
    assert size1 == 60
    e1ss = e1s + b'extra attached at the end.'
    ked1, knd1, vrs1, siz1 = serder._inhale(e1ss)
    assert ked1 == e1
    assert knd1 == kind1
    assert vrs1 == vers1
    assert siz1 == size1

    with pytest.raises(ShortageError):  # test too short
        ked1, knd1, vrs1, siz1 = serder._inhale(e1ss[:size1-1])

    raw1, knd1, ked1, ver1 = serder._exhale(ked=e1)
    assert raw1 == e1s
    assert knd1 == kind1
    assert ked1 == e1
    assert vrs1 == vers1

    e2 = dict(e1)
    e2["v"] = Vstrings.mgpk
    e2s = msgpack.dumps(e2)
    assert e2s == b'\x84\xa1v\xb1KERI10MGPK000000_\xa1i\xa7ABCDEFG\xa1s\xa40001\xa1t\xa3rot'
    vs = Versify(kind=Serials.mgpk, size=len(e2s))  # use real length
    assert vs == 'KERI10MGPK00002c_'
    e2["v"] = vs  # has real length
    e2s = msgpack.dumps(e2)

    with pytest.raises(ShortageError):  # test too short
        kind2, vers2, size2 = serder._sniff(e2s[:VERFULLSIZE])

    kind2, vers2, size2 = serder._sniff(e2s[:MINSNIFFSIZE])
    assert kind2 == Serials.mgpk
    assert size2 == 44

    kind2, vers2, size2 = serder._sniff(e2s)
    assert kind2 == Serials.mgpk
    assert size2 == 44
    e2ss = e2s + b'extra attached  at the end.'
    ked2, knd2, vrs2, siz2 = serder._inhale(e2ss)
    assert ked2 == e2
    assert knd2 == kind2
    assert vrs2 == vers2
    assert siz2 == size2

    with pytest.raises(ShortageError):  # test too short
        ked2, knd2, vrs2, siz2 = serder._inhale(e2ss[:size2-1])

    raw2, knd2, ked2, ver2 = serder._exhale(ked=e2)
    assert raw2 == e2s
    assert knd2 == kind2
    assert ked2 == e2
    assert vrs2 == vers2

    e3 = dict(e1)
    e3["v"] = Vstrings.cbor
    e3s = cbor.dumps(e3)
    assert e3s == b'\xa4avqKERI10CBOR000000_aigABCDEFGasd0001atcrot'
    vs = Versify(kind=Serials.cbor, size=len(e3s))  # use real length
    assert vs == 'KERI10CBOR00002c_'
    e3["v"] = vs  # has real length
    e3s = cbor.dumps(e3)

    with pytest.raises(ShortageError):  # test too short
        kind3, vers3, size3 = serder._sniff(e3s[:VERFULLSIZE])

    kind3, vers3, size3 = serder._sniff(e3s[:MINSNIFFSIZE])
    assert kind3 == Serials.cbor
    assert size3 == 44

    kind3, vers3, size3 = serder._sniff(e3s)
    assert kind3 == Serials.cbor
    assert size3 == 44
    e3ss = e3s + b'extra attached  at the end.'
    ked3, knd3, vrs3, siz3 = serder._inhale(e3ss)
    assert ked3 == e3
    assert knd3 == kind3
    assert vrs3 == vers3
    assert siz3 == size3

    with pytest.raises(ShortageError):  # test too short
        ked3, knd3, vrs3, siz3 = serder._inhale(e3ss[:size3-1])

    raw3, knd3, ked3, ver3 = serder._exhale(ked=e3)
    assert raw3 == e3s
    assert knd3 == kind3
    assert ked3 == e3
    assert vrs3 == vers3

    evt1 = Serder(raw=e1ss)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1
    assert evt1.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    # test digest properties .diger and .dig
    assert evt1.diger.qb64 == evt1.dig
    assert evt1.diger.code == MtrDex.Blake3_256
    assert len(evt1.diger.raw) == 32
    assert len(evt1.dig) == 44
    assert len(evt1.dig) == Matter.Codes[MtrDex.Blake3_256].fs
    assert evt1.dig == 'E4z66CxKHEo-6YCbIbpd1SqeXKVkLdh3j8CwUq31XA4o'
    assert evt1.diger.verify(evt1.raw)

    evt1 = Serder(ked=ked1)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1
    assert evt1.diger.code == MtrDex.Blake3_256
    assert serder.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    evt2 = Serder(raw=e2ss)
    assert evt2.kind == kind2
    assert evt2.raw == e2s
    assert evt2.ked == ked2
    assert evt2.version == vers2

    evt2 = Serder(ked=ked2)
    assert evt2.kind == kind2
    assert evt2.raw == e2s
    assert evt2.ked == ked2
    assert evt2.size == size2
    assert evt2.raw == e2ss[:size2]
    assert evt2.version == vers2

    evt3 = Serder(raw=e3ss)
    assert evt3.kind == kind3
    assert evt3.raw == e3s
    assert evt3.ked == ked3
    assert evt3.version == vers3

    evt3 = Serder(ked=ked3)
    assert evt3.kind == kind3
    assert evt3.raw == e3s
    assert evt3.ked == ked3
    assert evt3.size == size3
    assert evt3.raw == e3ss[:size3]
    assert evt3.version == vers3

    #  round trip
    evt2 = Serder(ked=evt1.ked)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2

    # Test change in kind by Serder
    evt1 = Serder(ked=ked1, kind=Serials.mgpk)  # ked is json but kind mgpk
    assert evt1.kind == kind2
    assert evt1.raw == e2s
    assert evt1.ked == ked2
    assert evt1.size == size2
    assert evt1.raw == e2ss[:size2]
    assert evt1.version == vers1
    assert evt1.dig == 'EbUOh76KAyZRbHsi9_uixhnX3zkcmN2bkIh-enCOmPRU'
    assert evt1.diger.verify(evt1.raw)

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2


    evt1 = Serder(ked=ked1, kind=Serials.cbor)  # ked is json but kind mgpk
    assert evt1.kind == kind3
    assert evt1.raw == e3s
    assert evt1.ked == ked3
    assert evt1.size == size3
    assert evt1.raw == e3ss[:size3]
    assert evt1.version == vers1

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2

    # use kind setter property
    assert evt2.kind == Serials.cbor
    evt2.kind = Serials.json
    assert evt2.kind == Serials.json
    knd, version, size = Deversify(evt2.ked["v"])
    assert knd == Serials.json

    #  Test diger code
    ked = {'vs': 'KERI10JSON000042_', 'pre': 'ABCDEFG', 'sn': '0001', 'ilk': 'rot'}
    raw = b'{"vs":"KERI10JSON000042_","pre":"ABCDEFG","sn":"0001","ilk":"rot"}'
    srdr = Serder(raw=raw, code=MtrDex.SHA3_256)
    assert srdr.kind == 'JSON'
    assert srdr.raw == raw
    assert srdr.ked == ked
    assert srdr.diger.code == MtrDex.SHA3_256

    #  Test compare
    ked = {'vs': 'KERI10JSON000042_', 'pre': 'ABCDEFG', 'sn': '0001', 'ilk': 'rot'}
    raw = b'{"vs":"KERI10JSON000042_","pre":"ABCDEFG","sn":"0001","ilk":"rot"}'
    srdr = Serder(raw=raw)
    assert srdr.kind == 'JSON'
    assert srdr.raw == raw
    assert srdr.ked == ked
    assert srdr.diger.code == MtrDex.Blake3_256

    diger0 = Diger(ser=srdr.raw) # default code
    diger1 = Diger(ser=srdr.raw, code=MtrDex.SHA3_256)
    diger2 = Diger(ser=srdr.raw, code=MtrDex.Blake2b_256)

    # test Serder.compare
    assert srdr.compare(diger=diger0)
    assert srdr.compare(diger=diger1)
    assert srdr.compare(diger=diger2)

    assert srdr.compare(dig=diger0.qb64)
    assert srdr.compare(dig=diger1.qb64b)
    assert srdr.compare(dig=diger2.qb64)

    ser1 = b'ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789'

    assert not srdr.compare(diger=Diger(ser=ser1))  # codes match
    assert not srdr.compare(dig=Diger(ser=ser1).qb64)  # codes match
    assert not srdr.compare(diger=Diger(ser=ser1, code=MtrDex.SHA3_256)) # codes not match
    assert not srdr.compare(dig=Diger(ser=ser1, code=MtrDex.SHA2_256).qb64b)     # codes not match
    """Done Test """


def test_tholder():
    """
    Test Tholder signing threshold satisfier class
    """

    #test classmethod .fromLimen()

    limen = '2'
    sith = Tholder.fromLimen(limen=limen)
    assert sith == '2'
    assert Tholder(sith=sith).limen == limen

    limen = '1/2,1/2,1/4,1/4,1/4&1,1'
    sith = Tholder.fromLimen(limen=limen)
    assert sith == [['1/2', '1/2', '1/4', '1/4', '1/4'], ['1', '1']]
    assert Tholder(sith=sith).limen == limen

    limen = '1/1'
    sith = Tholder.fromLimen(limen=limen)
    assert sith == [['1/1']]
    assert Tholder(sith=sith).limen == limen

    with pytest.raises(ValueError):
        tholder = Tholder()

    tholder = Tholder(sith="b")
    assert tholder.sith == "b"
    assert tholder.thold == 11
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))
    assert tholder.limen == "b"

    tholder = Tholder(sith=15)
    assert tholder.sith == "f"
    assert tholder.thold == 15
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))
    assert tholder.limen == "f"


    with pytest.raises(ValueError):
        tholder = Tholder(sith=-1)

    with pytest.raises(ValueError):
        tholder = Tholder(sith="-1")

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=["1/3", "1/2", []])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=["1/3", "1/2"])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[[], []])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[["1/3", "1/2"], ["1"]])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[["1/3", "1/2"], []])

    with pytest.raises(TypeError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2"], [[], "1"]])

    tholder = Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4"])
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4"]
    assert tholder.thold == [[Fraction(1, 2),
                            Fraction(1, 2),
                            Fraction(1, 4),
                            Fraction(1, 4),
                            Fraction(1, 4)]]
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.limen == '1/2,1/2,1/4,1/4,1/4'
    assert tholder.satisfy(indices=[0, 2, 4])
    assert tholder.satisfy(indices=[0, 1])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])

    tholder = Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"]])
    assert tholder.sith == [["1/2", "1/2", "1/4", "1/4", "1/4"]]
    assert tholder.thold == [[Fraction(1, 2),
                            Fraction(1, 2),
                            Fraction(1, 4),
                            Fraction(1, 4),
                            Fraction(1, 4)]]
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.limen == '1/2,1/2,1/4,1/4,1/4'
    assert tholder.satisfy(indices=[1, 2, 3])
    assert tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1, 4, 4])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])


    tholder = Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]])
    assert tholder.sith ==  [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
    assert tholder.thold == [[Fraction(1, 2),
                            Fraction(1, 2),
                            Fraction(1, 4),
                            Fraction(1, 4),
                            Fraction(1, 4)],
                           [Fraction(1, 1), Fraction(1, 1)]]
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.limen == '1/2,1/2,1/4,1/4,1/4&1,1'
    assert tholder.satisfy(indices=[1, 2, 3, 5])
    assert tholder.satisfy(indices=[0, 1, 6])
    assert not tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[5, 6])
    assert not tholder.satisfy(indices=[2, 3, 4])
    assert not tholder.satisfy(indices=[])


    """ Done Test """



if __name__ == "__main__":
    test_ilks()
