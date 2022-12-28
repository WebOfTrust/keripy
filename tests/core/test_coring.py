# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
import dataclasses
import hashlib
import json
from base64 import urlsafe_b64decode as decodeB64
from base64 import urlsafe_b64encode as encodeB64
from fractions import Fraction
from builtins import OverflowError
from math import ceil

import blake3
import cbor2 as cbor
import msgpack
import pysodium
import pytest

from keri.core import coring
from keri.core import eventing
from keri.core.coring import Ilkage, Ilks, Ids, Idents, Sadder
from keri.core.coring import Seqner, NumDex, Number, Siger, Dater, Bexter
from keri.core.coring import Serder, Tholder
from keri.core.coring import Serialage, Serials, Vstrings
from keri.core.coring import (Sizage, MtrDex, Matter, Xizage, IdrDex, IdxSigDex,
                              IdxCrtSigDex, IdxBthSigDex, Indexer,
                              CtrDex, Counter, sniff, ProDex)
from keri.core.coring import (Verfer, Cigar, Signer, Salter, Saider, DigDex,
                              Diger, Prefixer, Cipher, Encrypter, Decrypter)
from keri.core.coring import versify, deversify, Rever, VERFULLSIZE, MINSNIFFSIZE
from keri.core.coring import generateSigners, generatePrivates
from keri.core.coring import (intToB64, intToB64b, b64ToInt, codeB64ToB2, codeB2ToB64,
                              B64_CHARS, Reb64, nabSextets)
from keri.help import helping
from keri.kering import (EmptyMaterialError, RawMaterialError, DerivationError,
                         ShortageError, InvalidCodeSizeError, InvalidVarIndexError,
                         InvalidValueError)
from keri.kering import Version, Versionage


def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
                          rct='rct', ksn='ksn', qry='qry', rpy='rpy',
                          exn='exn', pro='pro', bar='bar',
                          vcp='vcp', vrt='vrt',
                          iss='iss', rev='rev', bis='bis', brv='brv', )

    assert isinstance(Ilks, Ilkage)

    for fld in Ilks._fields:
        assert fld == getattr(Ilks, fld)

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
    assert 'qry' in Ilks
    assert Ilks.qry == 'qry'
    assert 'rpy' in Ilks
    assert Ilks.rpy == 'rpy'
    assert 'exn' in Ilks
    assert Ilks.exn == 'exn'


    assert 'pro' in Ilks
    assert Ilks.pro == 'pro'
    assert 'bar' in Ilks
    assert Ilks.bar == 'bar'


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

    cs = intToB64(0, l=0)
    assert cs == ""
    with pytest.raises(ValueError):
        i = b64ToInt(cs)

    cs = intToB64(None, l=0)
    assert cs == ""
    with pytest.raises(ValueError):
        i = b64ToInt(cs)

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
    b = codeB64ToB2(s[:])
    assert len(b) == 3
    assert b == b'\xf8\x10\x02'
    t = codeB2ToB64(b, 4)
    assert t == s[:]
    i = int.from_bytes(b, 'big')
    assert i == 0o76010002
    i >>= 2 * (len(s) % 4)
    assert i == 0o76010002
    p = nabSextets(b, 4)
    assert p == b'\xf8\x10\x02'

    b = codeB64ToB2(s[:3])
    assert len(b) == 3
    assert b == b'\xf8\x10\x00'
    t = codeB2ToB64(b, 3)
    assert t == s[:3]
    i = int.from_bytes(b, 'big')
    assert i == 0o76010000
    i >>= 2 * (len(s[:3]) % 4)
    assert i == 0o760100
    p = nabSextets(b, 3)
    assert p == b'\xf8\x10\x00'

    b = codeB64ToB2(s[:2])
    assert len(b) == 2
    assert b == b'\xf8\x10'
    t = codeB2ToB64(b, 2)
    assert t == s[:2]
    i = int.from_bytes(b, 'big')
    assert i == 0o174020
    i >>= 2 * (len(s[:2]) % 4)
    assert i == 0o7601
    p = nabSextets(b, 2)
    assert p == b'\xf8\x10'

    b = codeB64ToB2(s[:1])
    assert len(b) == 1
    assert b == b'\xf8'
    t = codeB2ToB64(b, 1)
    assert t == s[:1]
    i = int.from_bytes(b, 'big')
    assert i == 0o370
    i >>= 2 * (len(s[:1]) % 4)
    assert i == 0o76
    p = nabSextets(b, 1)
    assert p == b'\xf8'

    assert B64_CHARS == ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                         'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                         'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                         'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                         '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_')
    assert '@' not in B64_CHARS
    assert 'A' in B64_CHARS

    text = b"-A-Bg-1-3-cd"
    match = Reb64.match(text)
    assert match
    assert match is not None

    text = b''
    match = Reb64.match(text)
    assert match
    assert match is not None

    text = b'123#$'
    match = Reb64.match(text)
    assert not match
    assert match is None

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
        'Big': 'N',
        'X25519_Private': 'O',
        'X25519_Cipher_Seed': 'P',
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
        'Tern': '1AAF',
        'DateTime': '1AAG',
        'X25519_Cipher_Salt': '1AAH',
        'TBD1': '2AAA',
        'TBD2': '3AAA',
        'StrB64_L0': '4A',
        'StrB64_L1': '5A',
        'StrB64_L2': '6A',
        'StrB64_Big_L0': '7AAA',
        'StrB64_Big_L1': '8AAA',
        'StrB64_Big_L2': '9AAA',
        'Bytes_L0': '4B',
        'Bytes_L1': '5B',
        'Bytes_L2': '6B',
        'Bytes_Big_L0': '7AAB',
        'Bytes_Big_L1': '8AAB',
        'Bytes_Big_L2': '9AAB',
    }

    assert Matter.Codex == MtrDex

    # first character of code with hard size of code
    assert Matter.Hards == {
        'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
        'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
        'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
        'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
        'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
        's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
        '0': 2, '1': 4, '2': 4, '3': 4, '4': 2, '5': 2, '6': 2, '7': 4,
        '8': 4, '9': 4,
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Matter.Sizes == {
        'A': Sizage(hs=1, ss=0, fs=44, ls=0),
        'B': Sizage(hs=1, ss=0, fs=44, ls=0),
        'C': Sizage(hs=1, ss=0, fs=44, ls=0),
        'D': Sizage(hs=1, ss=0, fs=44, ls=0),
        'E': Sizage(hs=1, ss=0, fs=44, ls=0),
        'F': Sizage(hs=1, ss=0, fs=44, ls=0),
        'G': Sizage(hs=1, ss=0, fs=44, ls=0),
        'H': Sizage(hs=1, ss=0, fs=44, ls=0),
        'I': Sizage(hs=1, ss=0, fs=44, ls=0),
        'J': Sizage(hs=1, ss=0, fs=44, ls=0),
        'K': Sizage(hs=1, ss=0, fs=76, ls=0),
        'L': Sizage(hs=1, ss=0, fs=76, ls=0),
        'M': Sizage(hs=1, ss=0, fs=4, ls=0),
        'N': Sizage(hs=1, ss=0, fs=12, ls=0),
        'O': Sizage(hs=1, ss=0, fs=44, ls=0),
        'P': Sizage(hs=1, ss=0, fs=124, ls=0),
        '0A': Sizage(hs=2, ss=0, fs=24, ls=0),
        '0B': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0C': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0D': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0E': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0F': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0G': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0H': Sizage(hs=2, ss=0, fs=8, ls=0),
        '1AAA': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAB': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAC': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAD': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAE': Sizage(hs=4, ss=0, fs=56, ls=0),
        '1AAF': Sizage(hs=4, ss=0, fs=8, ls=0),
        '1AAG': Sizage(hs=4, ss=0, fs=36, ls=0),
        '1AAH': Sizage(hs=4, ss=0, fs=100, ls=0),
        '2AAA': Sizage(hs=4, ss=0, fs=8, ls=1),
        '3AAA': Sizage(hs=4, ss=0, fs=8, ls=2),
        '4A': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5A': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6A': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAA': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAA': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAA': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4B': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5B': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6B': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAB': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAB': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAB': Sizage(hs=4, ss=4, fs=None, ls=2),
    }

    assert Matter.Sizes['A'].hs == 1  # hard size
    assert Matter.Sizes['A'].ss == 0  # soft size
    assert Matter.Sizes['A'].fs == 44  # full size
    assert Matter.Sizes['A'].ls == 0  # lead size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Matter.Sizes.keys():
        assert Matter.Hards[ckey[0]] == Matter.Sizes[ckey].hs

    #  verify all Codes have ss == 0 and not fs % 4 and hs > 0 and fs > hs
    #  if fs is not None else not (hs + ss) % 4
    for val in Matter.Sizes.values():
        if val.fs is not None:
            assert val.ss == 0 and not val.fs % 4 and val.hs > 0 and val.fs > val.hs
        else:
            assert not (val.hs + val.ss) % 4

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Matter.Hards.items():
        ckey = codeB64ToB2(skey)
        assert Matter.Bards[ckey] == sval

    assert Matter._rawSize(MtrDex.Ed25519) == 32
    assert Matter._leadSize(MtrDex.Ed25519) == 0

    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = b'iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#'
    prefix = 'BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj'  # str
    prefixb = prefix.encode("utf-8")  # bytes
    prebin = (b'\x04iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1'
              b'\xcd.\x9b\xe4#')


    with pytest.raises(EmptyMaterialError):
        matter = Matter()

    with pytest.raises(EmptyMaterialError):
        matter = Matter(raw=verkey, code=None)

    with pytest.raises(EmptyMaterialError):
        matter = Matter(raw=verkey, code='')

    # test from raw
    matter = Matter(raw=verkey)  # default code is MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.code == MtrDex.Ed25519N
    assert matter.both == MtrDex.Ed25519N
    assert matter.size == None
    assert matter.fullSize == 44
    assert matter.qb64 == prefix
    matter._exfil(prefixb)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb2 == prebin
    matter._bexfil(prebin)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.transferable == False
    assert matter.digestive == False
    # test round trip
    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    # Test from qb64b
    matter = Matter(qb64b=prefixb)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # Test from qb64b as str
    matter = Matter(qb64b=prefix)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # Test from qb64
    matter = Matter(qb64=prefix)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # Test from qb64 as bytes
    matter = Matter(qb64=prefixb)  # works for either
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # test non-zero pad bits in qb64 init ps == 1
    badprefix1 = 'B_AAY2RlZmdoaWprbG1ub3BxcnN0dXYwMTIzNDU2Nzg5'
    with pytest.raises(ValueError) as ex:
        matter = Matter(qb64=badprefix1)
    assert str(ex.value) == "Non zeroed prepad bits = 110000 in b'_'."

    # test non-zero pad bits in qb64 init ps == 2
    badprefix2 = '0A_wMTIzNDU2Nzg5YWJjZGVm'
    with pytest.raises(ValueError) as ex:
        matter = Matter(qb64=badprefix2)
    assert str(ex.value) == "Non zeroed prepad bits = 111100 in b'_'."

    # test truncates extra bytes from qb64 parameter
    longprefix = prefix + "ABCD"  # extra bytes in size
    matter = Matter(qb64=longprefix)
    assert len(matter.qb64) == Matter.Sizes[matter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortprefix = prefix[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        matter = Matter(qb64=shortprefix)

    # test from qb2
    matter = Matter(qb2=prebin)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey

    # test truncates extra bytes from qb2 parameter
    longprebin = prebin + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    matter = Matter(qb2=longprebin)
    assert len(matter.qb64) == Matter.Sizes[matter.code].fs
    assert isinstance(matter.raw, bytes)

    # test non-zero pad bits in qb2 init ps ==1
    badprebin1 = decodeB64(badprefix1)  # b'\x07\xf0\x00cdefghijklmnopqrstuv0123456789'
    with pytest.raises(ValueError) as ex:
        matter = Matter(qb2=badprebin1)
    assert str(ex.value) == 'Non zeroed pad bits = 00000011 in 0x07.'

    # test non-zero pad bits in qb2 init ps ==2
    badprebin2 = decodeB64(badprefix2)  # b'\xd0\x0f\xf0123456789abcdef'
    with pytest.raises(ValueError) as ex:
        matter = Matter(qb2=badprebin2)
    assert str(ex.value) == 'Non zeroed pad bits = 00001111 in 0x0f.'


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
    shortverkey = verkey[:-3]  # not enough bytes
    with pytest.raises(RawMaterialError):
        matter = Matter(raw=shortverkey)

    # test prefix on full identifier
    both = prefix + ":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64=both)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False

    # test nongreedy prefixb on full identifier
    both = prefixb + b":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64b=both)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
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
    prefix = 'BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj'  # str
    prefixb = prefix.encode("utf-8")  # bytes
    prebin = (b'\x04iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1'
              b'\xcd.\x9b\xe4#')

    # strip ignored if qb64
    matter = Matter(qb64=prefix, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert isinstance(matter.raw, bytes)
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False

    ims = bytearray(prefixb)  # strip from ims qb64b
    matter = Matter(qb64b=ims, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert isinstance(matter.raw, bytes)
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert not ims  # stripped

    ims = bytearray(prebin)
    matter = Matter(qb2=ims, strip=True)  # strip from ims qb2
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert isinstance(matter.raw, bytes)
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
    assert isinstance(matter.raw, bytes)
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert ims == extra  # stripped not include extra

    # test strip with extra qb2
    extra = bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    ims = bytearray(prebin) + extra
    matter = Matter(qb2=ims, strip=True)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert isinstance(matter.raw, bytes)
    assert matter.qb64b == prefixb
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert ims == extra  # stripped not include extra

    # test fix sized with leader 1
    # TBD1 = '2AAA'  # Testing purposes only fixed with lead size 1

    code = MtrDex.TBD1  # '2AAA'
    assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 1
    raw = b'ab'
    qb64 = '2AAAAGFi'  # '2AAA' + encodeB64(b'\x00ab').decode("utf-8")
    qb2 = decodeB64(qb64)  # b'\xd8\x00\x00\x00ab'
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == code
    assert matter.size == None
    assert matter.fullSize == 8
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb64b=qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64)
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64.encode("utf-8"))  # works for either
    assert matter.code == code
    assert matter.raw == raw

    # Test ._bexfil
    matter._bexfil(qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb2=qb2)
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64b == qb64.encode("utf-8")
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == code
    assert matter.size == None
    assert matter.fullSize == 8
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test with bad pad or lead
    badqb64 = '2AAA_2Fi'  # '2AAA' + encodeB64(b'\xffab').decode("utf-8")
    badqb2 = decodeB64(badqb64)  # b'\xd8\x00\x00\xffab'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb64=badqb64)
    assert str(ex.value) ==  'Non zeroed lead byte = 0xff.'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb2=badqb2)
    assert str(ex.value) == 'Non zeroed lead byte = 0xff.'


    # test fix sized with leader 2
    # TBD2 = '3AAA'  # Testing purposes only of fixed with lead size 2
    code = MtrDex.TBD2  # '3AAA'
    assert Matter._rawSize(code) == 1
    assert Matter._leadSize(code) == 2
    raw = b'z'
    qb64 = '3AAAAAB6'
    qb2 = b'\xdc\x00\x00\x00\x00z'
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == code
    assert matter.size == None
    assert matter.fullSize == 8
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64b=qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64)
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64.encode("utf-8"))  # works for either
    assert matter.code == code
    assert matter.raw == raw

    # Test ._bexfil
    matter._bexfil(qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb2=qb2)
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64b == qb64.encode("utf-8")
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test with bad pad or lead
    badqb64 = '3AAA__96'  # '3AAA' + encodeB64(b'\xff\xffz').decode("utf-8")
    badqb2 = decodeB64(badqb64)  #b'\xdc\x00\x00\xff\xffz'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb64=badqb64)
    assert str(ex.value) ==  'Non zeroed lead bytes = 0xffff.'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb2=badqb2)
    assert str(ex.value) == 'Non zeroed lead bytes = 0xffff.'

    # test variable sized with leader 1
    code = MtrDex.Bytes_L1
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 1
    raw = b'abcde'  # 5 bytes two triplets with lead 1
    both = '5BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '5BACAGFiY2Rl'
    qb2 = b'\xe4\x10\x02\x00abcde'
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable is True
    assert matter.digestive is False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb64=qb64)
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64.encode("utf-8"))  # works for either
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64b=qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64b=qb64)  # works for either
    assert matter.code == code
    assert matter.raw == raw

    # test strip
    matter = Matter(qb64b=bytearray(qb64.encode("utf-8")), strip=True)
    assert matter.code == code
    assert matter.raw == raw

    # Test ._bexfil
    matter._bexfil(qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb2=qb2)
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64b == qb64.encode("utf-8")
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test strip
    matter = Matter(qb2=bytearray(qb2), strip=True)
    assert matter.code == code
    assert matter.raw == raw

    # test with bad lead 1
    # 5 bytes with lead 1 = two triplets = b'\xffabcde'
    badqb64 = '5BAC_2FiY2Rl'  # '5BAC' + encodeB64(b'\xffabcde').decode("utf-8")
    badqb2 = decodeB64(badqb64)  # b'\xe4\x10\x02\xffabcde'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb64=badqb64)
    assert str(ex.value) ==  'Non zeroed lead byte = 0xff.'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb2=badqb2)
    assert str(ex.value) == 'Non zeroed lead byte = 0xff.'

    # test variable sized with leader 1 with code replacement
    code0 = MtrDex.Bytes_L0  # use leader 0 code but with lead size 1 raw
    code = MtrDex.Bytes_L1
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 1
    raw = b'abcde'  # 5 bytes two triplets with lead 1
    both = '5BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '5BACAGFiY2Rl'
    qb2 = b'\xe4\x10\x02\x00abcde'
    matter = Matter(raw=raw, code=code0)
    assert matter.raw == raw
    assert matter.code == code  # replaced
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test variable sized with leader 1 with code replacement
    code2 = MtrDex.Bytes_L2  # use leader 0 code but with lead size 1 raw
    code = MtrDex.Bytes_L1
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 1
    raw = b'abcde'  # 5 bytes two triplets with lead 1
    both = '5BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '5BACAGFiY2Rl'
    qb2 = b'\xe4\x10\x02\x00abcde'
    matter = Matter(raw=raw, code=code2)
    assert matter.raw == raw
    assert matter.code == code  # replaced
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test rize parameter to extract portion of raw passed in
    raw = b'abcdefghijk'  # extra bytes in raw
    both = '5BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '5BACAGFiY2Rl'
    qb2 = b'\xe4\x10\x02\x00abcde'
    matter = Matter(raw=raw, code=code, rize=5)
    assert matter.raw == raw[:5]
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test variable sized with leader 2
    code = MtrDex.Bytes_L2
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 2
    raw = b'abcd'  # 4 bytes two triplets with lead 2
    both = '6BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '6BACAABhYmNk'
    qb2 = b'\xe8\x10\x02\x00\x00abcd'
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb64b=qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64)
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64.encode("utf-8"))  # works for either
    assert matter.code == code
    assert matter.raw == raw

    # Test ._bexfil
    matter._bexfil(qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb2=qb2)
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64b == qb64.encode("utf-8")
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test with bad lead 2
    # 4 bytes with lead 2 = two triplets = b'\xff\xffabcd'
    badqb64 = '6BAC__9hYmNk'  # '5BAC' + encodeB64(b'\xff\xffabcd').decode("utf-8")
    badqb2 = decodeB64(badqb64)  # b'\xe8\x10\x02\xff\xffabcd'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb64=badqb64)
    assert str(ex.value) ==  'Non zeroed lead bytes = 0xffff.'

    with pytest.raises(ValueError) as  ex:
        matter = Matter(qb2=badqb2)
    assert str(ex.value) == 'Non zeroed lead bytes = 0xffff.'

    # test variable sized with leader 2 with code replacement
    code0 = MtrDex.Bytes_L0  # use leader 0 code but with lead size 2 raw
    code = MtrDex.Bytes_L2
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 2
    raw = b'abcd'  # 4 bytes two triplets with lead 2
    both = '6BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '6BACAABhYmNk'
    qb2 = b'\xe8\x10\x02\x00\x00abcd'
    matter = Matter(raw=raw, code=code0)
    assert matter.raw == raw
    assert matter.code == code  # replaced
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test variable sized with leader 2 with code replacement
    code1 = MtrDex.Bytes_L1  # use leader 1 code but with lead size 2 raw
    code = MtrDex.Bytes_L2
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 2
    raw = b'abcd'  # 6 bytes two triplets with lead 2
    both = '6BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '6BACAABhYmNk'
    qb2 = b'\xe8\x10\x02\x00\x00abcd'
    matter = Matter(raw=raw, code=code1)
    assert matter.raw == raw
    assert matter.code == code  # replaced
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test rize parameter to extract portion of raw passed in
    raw = b'abcdefghijk'  # extra bytes in raw
    both = '6BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '6BACAABhYmNk'
    qb2 = b'\xe8\x10\x02\x00\x00abcd'
    matter = Matter(raw=raw, code=code, rize=4)
    assert matter.raw == raw[:4]
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test variable sized with leader 0
    code = MtrDex.Bytes_L0
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 0
    assert Matter._leadSize(code) == 0
    raw = b'abcdef'  # 6 bytes two triplets with lead 0
    both = '4BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '4BACYWJjZGVm'
    qb2 = b'\xe0\x10\x02abcdef'
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))

    matter._exfil(qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64b=qb64.encode("utf-8"))
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64)
    assert matter.code == code
    assert matter.raw == raw

    matter = Matter(qb64=qb64.encode("utf-8"))  # works for either
    assert matter.code == code
    assert matter.raw == raw

    # Test ._bexfil
    matter._bexfil(qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2

    matter = Matter(qb2=qb2)
    assert matter.code == code
    assert matter.raw == raw
    assert matter.qb64b == qb64.encode("utf-8")
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test variable sized with leader 0 with code replacement
    code1 = MtrDex.Bytes_L1  # use leader 1 code but with lead size 0 raw
    code = MtrDex.Bytes_L0
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 0
    raw = b'abcdef'  # 6 bytes two triplets with lead 0
    both = '4BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '4BACYWJjZGVm'
    qb2 = b'\xe0\x10\x02abcdef'
    matter = Matter(raw=raw, code=code0)
    assert matter.raw == raw
    assert matter.code == code  # replaced
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test variable sized with leader 0 with code replacement
    code1 = MtrDex.Bytes_L2  # use leader 2 code but with lead size 0 raw
    code = MtrDex.Bytes_L0
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 0
    raw = b'abcdef'  # 6 bytes two triplets with lead 0
    both = '4BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '4BACYWJjZGVm'
    qb2 = b'\xe0\x10\x02abcdef'
    matter = Matter(raw=raw, code=code1)
    assert matter.raw == raw
    assert matter.code == code  # replaced
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # test rize parameter to extract portion of raw passed in
    raw = b'abcdefghijk'  # extra bytes in raw
    both = '4BAC'  # full code both hard and soft parts two quadlets/triplets
    qb64 = '4BACYWJjZGVm'
    qb2 = b'\xe0\x10\x02abcdef'
    matter = Matter(raw=raw, code=code, rize=6)
    assert matter.raw == raw[:6]
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 2  # quadlets
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    # text big code substitution for size bigger than 4095  4k
    code0 = MtrDex.Bytes_L0
    code = MtrDex.Bytes_Big_L0
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 0
    raw = b'ABCDEFGHIJKLMNOPabcdefghijklmnop' * 129 * 3
    assert len(raw) == 32 * 129 * 3 == 12384
    assert len(raw) > (64 ** 2 - 1) * 3  # 12282
    assert not len(raw) % 3
    both = '7AABABAg'  # full code both hard and soft parts two quadlets/triplets
    matter = Matter(raw=raw, code=code0)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 4128 == len(raw) / 3  # quadlets
    assert matter.fullSize == 16520  # chars

    # text big code substitution for size bigger than 4095  4k replacement
    code1 = MtrDex.Bytes_L1
    code = MtrDex.Bytes_Big_L0
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 0
    matter = Matter(raw=raw, code=code1)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 4128 == len(raw) / 3  # quadlets
    assert matter.fullSize == 16520  # chars

    # text big code substitution for size bigger than 4095  4k
    code2 = MtrDex.Bytes_L2
    code = MtrDex.Bytes_Big_L0
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 0
    matter = Matter(raw=raw, code=code2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.both == both
    assert matter.size == 4128 == len(raw) / 3  # quadlets
    assert matter.fullSize == 16520  # chars

    #  add crypt for encrypted x25519

    # test other codes
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    sig64b = encodeB64(sig)
    assert sig64b == b'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='
    sig64 = sig64b.decode("utf-8")
    assert sig64 == 'mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ=='

    qsig64 = '0BCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    #'0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = qsig64.encode("utf-8")
    #b'0BmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsigB2 = (b"\xd0\x10\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
              b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
              b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    #(b'\xd0\x19\x9d#\xc3\x92BC\t\xf6\xbf\xb1\x8a\x08\xc4\x07!#"\xe6\xbb,q\xf7'
              #b'\x00\xe2v\xd8\xf4\n\xaaX\xcc\x86\xe8\\\x82\x1fg\x19\x17\n\x9e\xcc'
              #b'\xf9*\xf2\x9d\xec\xaf\xc7\xf7\xedv\xf7\xc1x!\xddC\xc6\xf2(\x12`\x90')

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
    cs = len(MtrDex.Short)
    assert cs == 1
    ps = cs % 4
    assert ps == 1
    txt = encodeB64(bytes([0]*ps) + raw)
    assert txt == b'APd_'  # b'938='
    qb64b = MtrDex.Short.encode("utf-8") + txt[ps:]
    assert qb64b == b'MPd_'  # b'M938'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'0\xf7\x7f'  # b'3\xdd\xfc'
    bs = ceil((cs * 3) / 4)
    assert qb2[bs:] == raw  # stable value in qb2
    assert encodeB64(qb2) == qb64b

    matter = Matter(raw=raw, code=MtrDex.Short)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Short
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    # test long
    val = int("F7F33F7F", 16)
    assert val == 4159913855
    raw = val.to_bytes(4, 'big')
    assert raw == b'\xf7\xf3?\x7f'
    cs = len(MtrDex.Long)
    assert cs == 2
    ps = cs % 4
    assert ps == 2
    txt = encodeB64(bytes([0]*ps) + raw)
    assert txt == b'AAD38z9_'  # b'9_M_fw=='
    qb64b = MtrDex.Long.encode("utf-8") + txt[ps:]
    assert qb64b == b'0HD38z9_'  # b'0H9_M_fw'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'\xd0p\xf7\xf3?\x7f'  # b'\xd0\x7f\x7f3\xf7\xf0'
    bs = ceil((cs * 3) / 4)
    assert qb2[cs:] == raw  # stable value in qb2
    assert encodeB64(qb2) == qb64b

    matter = Matter(raw=raw, code=MtrDex.Long)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Long
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    # test Tern as number
    val = int("F89CFF", 16)
    assert val == 16293119
    raw = val.to_bytes(3, 'big')
    assert raw == b'\xf8\x9c\xff'
    cs = len(MtrDex.Tern)
    assert cs == 4
    ps = cs % 4
    assert ps == 0
    txt = encodeB64(bytes([0]*ps) + raw)
    assert txt == b'-Jz_'
    qb64b = MtrDex.Tern.encode("utf-8") + txt[ps:]
    assert qb64b == b'1AAF-Jz_'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'\xd4\x00\x05\xf8\x9c\xff'
    bs = ceil((cs * 3) / 4)
    assert qb2[bs:] == raw  # stable value in qb2
    assert encodeB64(qb2) == qb64b

    matter = Matter(raw=raw, code=MtrDex.Tern)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    # test Tern as chars
    txt = b'icp_'
    raw = decodeB64(txt)
    assert raw == b'\x89\xca\x7f'
    val = int.from_bytes(raw, 'big')
    assert val == 9030271
    cs = len(MtrDex.Tern)
    assert cs == 4
    ps = cs % 4
    assert ps == 0
    txt = encodeB64(bytes([0]*ps) + raw)
    qb64b = MtrDex.Tern.encode("utf-8") + txt
    assert qb64b == b'1AAFicp_'
    qb64 = qb64b.decode("utf-8")
    qb2 = decodeB64(qb64b)
    assert qb2 == b'\xd4\x00\x05\x89\xca\x7f'
    bs = ceil((cs * 3) / 4)
    assert qb2[bs:] == raw  # stable value in qb2
    assert encodeB64(qb2) == qb64b

    matter = Matter(raw=raw, code=MtrDex.Tern)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == MtrDex.Tern
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    bs = ceil((len(matter.code) * 3) / 4)
    assert matter.qb2[bs:] == matter.raw
    assert matter.transferable == True
    assert matter.digestive == False

    """ Done Test """


def test_indexer():
    """
    Test Indexer class
    """
    assert Indexer.Codex == IdrDex

    assert dataclasses.asdict(IdrDex) == {
        'Ed25519_Sig': 'A',
        'Ed25519_Crt_Sig': 'B',
        'ECDSA_256k1_Sig': 'C',
        'ECDSA_256k1_Crt_Sig': 'D',
        'Ed448_Sig': '0A',
        'Ed448_Crt_Sig': '0B',
        'Ed25519_Big_Sig': '2A',
        'Ed25519_Big_Crt_Sig': '2B',
        'ECDSA_256k1_Big_Sig': '2C',
        'ECDSA_256k1_Big_Crt_Sig': '2D',
        'Ed448_Big_Sig': '3A',
        'Ed448_Big_Crt_Sig': '3B',
        'TBD0': '0z',
        'TBD1': '1z',
        'TBD4': '4z',
    }

    assert IdrDex.Ed25519_Sig == 'A'
    assert IdrDex.Ed25519_Crt_Sig == 'B'
    assert IdrDex.ECDSA_256k1_Sig == 'C'
    assert IdrDex.ECDSA_256k1_Crt_Sig == 'D'
    assert IdrDex.Ed448_Sig == '0A'
    assert IdrDex.Ed448_Crt_Sig == '0B'
    assert IdrDex.Ed25519_Big_Sig == '2A'
    assert IdrDex.Ed25519_Big_Crt_Sig == '2B'
    assert IdrDex.ECDSA_256k1_Big_Sig == '2C'
    assert IdrDex.ECDSA_256k1_Big_Crt_Sig == '2D'
    assert IdrDex.Ed448_Big_Sig == '3A'
    assert IdrDex.Ed448_Big_Crt_Sig == '3B'
    assert IdrDex.TBD0 == '0z'
    assert IdrDex.TBD1 == '1z'
    assert IdrDex.TBD4 == '4z'

    assert dataclasses.asdict(IdxSigDex) == {
        'Ed25519_Sig': 'A',
        'Ed25519_Crt_Sig': 'B',
        'ECDSA_256k1_Sig': 'C',
        'ECDSA_256k1_Crt_Sig': 'D',
        'Ed448_Sig': '0A',
        'Ed448_Crt_Sig': '0B',
        'Ed25519_Big_Sig': '2A',
        'Ed25519_Big_Crt_Sig': '2B',
        'ECDSA_256k1_Big_Sig': '2C',
        'ECDSA_256k1_Big_Crt_Sig': '2D',
        'Ed448_Big_Sig': '3A',
        'Ed448_Big_Crt_Sig': '3B',
    }

    assert IdxSigDex.Ed25519_Sig == 'A'
    assert IdxSigDex.Ed25519_Crt_Sig == 'B'
    assert IdxSigDex.ECDSA_256k1_Sig == 'C'
    assert IdxSigDex.ECDSA_256k1_Crt_Sig == 'D'
    assert IdxSigDex.Ed448_Sig == '0A'
    assert IdxSigDex.Ed448_Crt_Sig == '0B'
    assert IdxSigDex.Ed25519_Big_Sig == '2A'
    assert IdxSigDex.Ed25519_Big_Crt_Sig == '2B'
    assert IdxSigDex.ECDSA_256k1_Big_Sig == '2C'
    assert IdxSigDex.ECDSA_256k1_Big_Crt_Sig == '2D'
    assert IdxSigDex.Ed448_Big_Sig == '3A'
    assert IdxSigDex.Ed448_Big_Crt_Sig == '3B'


    assert dataclasses.asdict(IdxCrtSigDex) == {
        'Ed25519_Crt_Sig': 'B',
        'ECDSA_256k1_Crt_Sig': 'D',
        'Ed448_Crt_Sig': '0B',
        'Ed25519_Big_Crt_Sig': '2B',
        'ECDSA_256k1_Big_Crt_Sig': '2D',
        'Ed448_Big_Crt_Sig': '3B',
    }

    assert IdxCrtSigDex.Ed25519_Crt_Sig == 'B'
    assert IdxCrtSigDex.ECDSA_256k1_Crt_Sig == 'D'
    assert IdxCrtSigDex.Ed448_Crt_Sig == '0B'
    assert IdxCrtSigDex.Ed25519_Big_Crt_Sig == '2B'
    assert IdxCrtSigDex.ECDSA_256k1_Big_Crt_Sig == '2D'
    assert IdxCrtSigDex.Ed448_Big_Crt_Sig == '3B'


    assert dataclasses.asdict(IdxBthSigDex) == {
        'Ed25519_Sig': 'A',
        'ECDSA_256k1_Sig': 'C',
        'Ed448_Sig': '0A',
        'Ed25519_Big_Sig': '2A',
        'ECDSA_256k1_Big_Sig': '2C',
        'Ed448_Big_Sig': '3A',
    }

    assert IdxBthSigDex.Ed25519_Sig == 'A'
    assert IdxBthSigDex.ECDSA_256k1_Sig == 'C'
    assert IdxBthSigDex.Ed448_Sig == '0A'
    assert IdxBthSigDex.Ed25519_Big_Sig == '2A'
    assert IdxBthSigDex.ECDSA_256k1_Big_Sig == '2C'
    assert IdxBthSigDex.Ed448_Big_Sig == '3A'


    # first character of code with hard size of code
    assert Indexer.Hards == {
        'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
        'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
        'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
        'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
        'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
        's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
        '0': 2, '1': 2, '2': 2, '3': 2, '4': 2,
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Indexer.Sizes == {
        'A': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'B': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'C': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'D': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        '0A': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '0B': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '2A': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2B': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2C': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2D': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '3A': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '3B': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '0z': Xizage(hs=2, ss=2, os=0, fs=None, ls=0),
        '1z': Xizage(hs=2, ss=2, os=1, fs=76, ls=1),
        '4z': Xizage(hs=2, ss=6, os=3, fs=80, ls=1),
    }

    assert Indexer.Sizes['A'].hs == 1  # hard size
    assert Indexer.Sizes['A'].ss == 1  # soft size
    assert Indexer.Sizes['A'].os == 0  # other size
    assert Indexer.Sizes['A'].fs == 88  # full size
    assert Indexer.Sizes['A'].ls == 0  # lead size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Indexer.Sizes.keys():
        assert Indexer.Hards[ckey[0]] == Indexer.Sizes[ckey].hs

    # verify all Codes have hs > 0 and ss > 0 and fs >= hs + ss if fs is not None
    # verify os is part of ss
    for val in Indexer.Sizes.values():
        assert val.hs > 0 and val.ss > 0
        assert val.os >= 0 and val.os < val.ss
        if val.os:
            assert val.os == val.ss // 2
        if val.fs is not None:
            assert val.fs >= val.hs + val.ss
            assert val.fs % 4 == 0

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Indexer.Hards.items():
        ckey = codeB64ToB2(skey)
        assert Indexer.Bards[ckey] == sval

    with pytest.raises(EmptyMaterialError):
        indexer = Indexer()

    # Test signatures
    sig = (b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@"
           b'\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca'
           b'\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    assert len(sig) == 64

    ps = (3 - (len(sig) % 3)) % 3  # same pad size char and lead size bytes
    sig64b = encodeB64(bytes([0]* ps) +  sig)  # prepad with ps bytes of zeros
    sig64 = sig64b.decode("utf-8")
    assert len(sig64) == 88
    assert sig64 == ('AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwq'
                     'ezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')

    # replace prepad  with code "A" plus index 0 == "A"
    qsc = IdrDex.Ed25519_Sig + intToB64(0, l=1)
    assert qsc == 'AA'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[ps:]  # replace prepad chars with clause
    assert qsig64 == ('AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFw'
                      'qezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = decodeB64(qsig64b)
    assert len(qsig2b) == 66
    assert qsig2b == (b"\x00\x00\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
                      b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
                      b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64

    indexer._exfil(qsig64b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer._bexfil(qsig2b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test wrong size of raw
    longsig = sig + bytes([10, 11, 12])
    indexer = Indexer(raw=longsig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0

    shortsig = sig[:-3]
    with pytest.raises(RawMaterialError):
        indexer = Indexer(raw=shortsig)

    indexer = Indexer(qb64b=qsig64b)  # test with bytes not str
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)  # test with str not bytes
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test non-zero pad bits in qb64 init ps == 2
    badq64sig2= ('AA_Z0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFw'
                      'qezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')
    with pytest.raises(ValueError) as ex:
        indexer = Indexer(qb64=badq64sig2)
    assert str(ex.value) == "Non zeroed prepad bits = 111100 in b'_'."

    # test truncates extra bytes from qb64 parameter
    longqsig64 = qsig64 + "ABCD"
    indexer = Indexer(qb64=longqsig64)
    assert len(indexer.qb64) == Indexer.Sizes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsig64 = qsig64[:-4]  # too short
    with pytest.raises(ShortageError):
        indexer = Indexer(qb64=shortqsig64)

    indexer = Indexer(qb2=qsig2b)  # test with qb2
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0
    assert indexer.ondex == 0
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    # test non-zero pad bits in qb2 init ps ==2
    badq2sig2= decodeB64(badq64sig2)
    with pytest.raises(ValueError) as ex:
        indexer = Indexer(qb2=badq2sig2)
    assert str(ex.value) == 'Non zeroed pad bits = 00001111 in 0x0f.'

    # test truncates extra bytes from qb2 parameter
    longqsig2b = qsig2b + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    indexer = Indexer(qb2=longqsig2b)
    assert isinstance(indexer.raw, bytes)
    assert indexer.qb2 == qsig2b
    assert len(indexer.qb64) == Indexer.Sizes[indexer.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqsig2b = qsig2b[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        indexer = Indexer(qb2=shortqsig2b)

    # test with non-zero index=5
    # replace pad "==" with code "AF"
    qsc = IdrDex.Ed25519_Sig + intToB64(5, l=1)
    assert qsc == 'AF'
    qscb = qsc.encode("utf-8")
    qsig64 = qsc + sig64[ps:]  # replace prepad chars with code
    assert qsig64 == ('AFCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZF'
                      'wqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ')
    assert len(qsig64) == 88
    qsig64b = qsig64.encode("utf-8")

    qsig2b = decodeB64(qsig64b)
    assert len(qsig2b) == 66
    qsig2b = (b"\x00P\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
              b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
              b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    indexer._exfil(qsig64b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    indexer._bexfil(qsig2b)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.raw == sig
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5, ondex=5)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5, ondex=0)

    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=5, ondex=64)

    indexer = Indexer(raw=sig)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 0  #default index is zero
    assert indexer.ondex == 0
    assert indexer.qb64 != qsig64
    assert indexer.qb2 != qsig2b

    indexer = Indexer(qb2=qsig2b)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

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
    assert indexer.ondex == index
    assert indexer.qb64 == qsig64
    assert indexer.qb2 == qb2

    # Test ._binfil
    test = indexer._binfil()
    assert test == qb2

    # test ondex not None and not match index for not os
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=code, index=index, ondex=0)


    # test strip ims
    # strip ignored if qb64
    indexer = Indexer(qb64=qsig64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b

    ims = bytearray(qsig64b)
    indexer = Indexer(qb64b=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert not ims

    ims = bytearray(qsig2b)
    indexer = Indexer(qb2=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert not ims

    # test extra bytes in ims qb64b
    extra = bytearray(b"ABCD")
    ims = bytearray(qsig64b) + extra
    indexer = Indexer(qb64b=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert ims == extra

    # test extra bytes in ims qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qsig2b) + extra
    indexer = Indexer(qb2=ims, strip=True)
    assert indexer.raw == sig
    assert isinstance(indexer.raw, bytes)
    assert indexer.code == IdrDex.Ed25519_Sig
    assert indexer.index == 5
    assert indexer.ondex == 5
    assert indexer.qb64 == qsig64
    assert indexer.qb64b == qsig64b
    assert indexer.qb2 == qsig2b
    assert ims == extra


    # test index too big
    index = 65
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=index)

    # test negative index
    index = -1
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=index)

    # test non integer index
    index = 3.5
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Sig, index=index)

    # test big code both different and same
    index = 67

    qb64 = '2ABDBDCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b'\xd8\x00C\x040\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp'
           b"\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde"
           b'\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Big_Sig, index=index)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Big_Sig, index=index, ondex=index)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == index
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    index = 90
    ondex = 65
    qb64 = '2ABaBBCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b'\xd8\x00Z\x04\x10\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp'
           b"\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde"
           b'\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=IdrDex.Ed25519_Big_Sig, index=index, ondex=ondex)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == ondex
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == ondex
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == IdrDex.Ed25519_Big_Sig
    assert indexer.index == index
    assert indexer.ondex == ondex
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    # test Crt only code
    index =  3
    code = IdrDex.Ed25519_Crt_Sig
    qb64 = 'BDCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b"\x040\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm"
           b'\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)'
           b'\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=code, index=index)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2


    # test ondex error conditions
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index)

    with pytest.raises(InvalidVarIndexError):  # non None ondex
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index+2)


    # test big code current only
    index =  68
    code = IdrDex.Ed25519_Big_Crt_Sig
    qb64 = '2BBEAACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ'
    qb2 = (b'\xd8\x10D\x00\x00\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp'
           b"\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde"
           b'\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o"\x81&\t')

    indexer = Indexer(raw=sig, code=code, index=index)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb64=qb64)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    indexer = Indexer(qb2=qb2)
    assert indexer.raw == sig
    assert indexer.code == code
    assert indexer.index == index
    assert indexer.ondex == None
    assert indexer.qb64 == qb64
    assert indexer.qb2 == qb2

    # test ondex error conditions
    with pytest.raises(InvalidVarIndexError):
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index)

    with pytest.raises(InvalidVarIndexError):  # non None ondex
        indexer = Indexer(raw=sig, code=code, index=index, ondex=index+2)


    # Test of TBD Label Code (variable length)
    label = b'Hello_World_Peep'
    index = len(label) // 4
    assert not len(label) % 4
    assert index == 4
    lraw = decodeB64(label)
    assert len(lraw) == len(label) * 3 // 4
    assert lraw == b'\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'
    ltext = encodeB64(lraw)
    assert ltext == b'Hello_World_Peep' == label
    qsc = IdrDex.TBD0 + intToB64(index, l=2)
    assert qsc == '0zAE'
    qscb = qsc.encode("utf-8")
    lq64b = qscb + label
    assert lq64b == b'0zAEHello_World_Peep'
    lq64 = lq64b.decode("utf-8")

    # label from raw
    indexer = Indexer(raw=lraw, code=IdrDex.TBD0, index=index)
    assert indexer.raw == lraw
    assert indexer.code == IdrDex.TBD0
    assert indexer.index == index
    assert indexer.qb64b == lq64b
    assert indexer.qb64 == lq64
    assert indexer.qb2 == b'\xd30\x04\x1d\xe9e\xa3\xf5\xa8\xaeW\x7f=\xe7\xa9'

    # index zero for empty label
    indexer = Indexer(raw=lraw, code=IdrDex.TBD0, index=0)
    assert indexer.raw == b''
    assert indexer.code == IdrDex.TBD0
    assert indexer.index == 0
    assert indexer.qb64b == b'0zAA'
    assert indexer.qb64 == '0zAA'
    assert indexer.qb2 == b'\xd30\x00'
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
        'TransIdxSigGroups': '-F',
        'SealSourceCouples': '-G',
        'TransLastIdxSigGroups': '-H',
        'SealSourceTriples': '-I',
        'SadPathSig': '-J',
        'SadPathSigGroup': '-K',
        'PathedMaterialQuadlets': '-L',
        'AttachedMaterialQuadlets': '-V',
        'BigAttachedMaterialQuadlets': '-0V',
        'KERIProtocolStack': '--AAA',
    }

    #assert dataclasses.asdict(CtrDex) == {
        #'ControllerIdxSigs': '-A',
        #'WitnessIdxSigs': '-B',
        #'NonTransReceiptCouples': '-C',
        #'TransReceiptQuadruples': '-D',
        #'FirstSeenReplayCouples': '-E',
        #'TransIdxSigGroups': '-F',
        #'SealSourceCouples': '-G',
        #'TransLastIdxSigGroups': '-H',
        #'SealSourceTriples': '-I',
        #'SadPathSig': '-J',
        #'SadPathSigGroup': '-K',
        #'PathedMaterialQuadlets': '-L',
        #'MessageDataGroups': '-U',
        #'AttachedMaterialQuadlets': '-V',
        #'MessageDataMaterialQuadlets': '-W',
        #'CombinedMaterialQuadlets': '-X',
        #'MaterialGroups': '-Y',
        #'MaterialQuadlets': '-Z',
        #'BigMessageDataGroups': '-0U',
        #'BigAttachedMaterialQuadlets': '-0V',
        #'BigMessageDataMaterialQuadlets': '-0W',
        #'BigCombinedMaterialQuadlets': '-0X',
        #'BigMaterialGroups': '-0Y',
        #'BigMaterialQuadlets': '-0Z'
    #}

    assert CtrDex.ControllerIdxSigs == '-A'
    assert CtrDex.WitnessIdxSigs == '-B'

    assert Counter.Codex == CtrDex

    # first character of code with hard size of code
    assert Counter.Hards == {
        '-A': 2, '-B': 2, '-C': 2, '-D': 2, '-E': 2, '-F': 2, '-G': 2, '-H': 2, '-I': 2,
        '-J': 2, '-K': 2, '-L': 2, '-M': 2, '-N': 2, '-O': 2, '-P': 2, '-Q': 2, '-R': 2,
        '-S': 2, '-T': 2, '-U': 2, '-V': 2, '-W': 2, '-X': 2, '-Y': 2, '-Z': 2,
        '-a': 2, '-b': 2, '-c': 2, '-d': 2, '-e': 2, '-f': 2, '-g': 2, '-h': 2, '-i': 2,
        '-j': 2, '-k': 2, '-l': 2, '-m': 2, '-n': 2, '-o': 2, '-p': 2, '-q': 2, '-r': 2,
        '-s': 2, '-t': 2, '-u': 2, '-v': 2, '-w': 2, '-x': 2, '-y': 2, '-z': 2,
        '-0': 3, '--': 5,
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Counter.Sizes == {
        '-A': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-B': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-C': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-D': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-E': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-F': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-G': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-H': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-I': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-J': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-K': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-L': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-0V': Sizage(hs=3, ss=5, fs=8, ls=0),
        '--AAA': Sizage(hs=5, ss=3, fs=8, ls=0)
    }

    assert Counter.Sizes['-A'].hs == 2  # hard size
    assert Counter.Sizes['-A'].ss == 2  # soft size
    assert Counter.Sizes['-A'].fs == 4  # full size
    assert Counter.Sizes['-A'].ls == 0  # lead size

    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Counter.Sizes.keys():
        assert Counter.Hards[ckey[:2]] == Counter.Sizes[ckey].hs

    #  verify all Codes have hs > 0 and ss > 0 and fs = hs + ss and not fs % 4
    for val in Counter.Sizes.values():
        assert val.hs > 0 and val.ss > 0 and val.hs + val.ss == val.fs and not val.fs % 4

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Counter.Hards.items():
        ckey = codeB64ToB2(skey)
        assert Counter.Bards[ckey] == sval

    with pytest.raises(EmptyMaterialError):
        counter = Counter()

    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.ControllerIdxSigs)  # default count = 1
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

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64)
    assert len(counter.qb64) == Counter.Sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(ShortageError):
        counter = Counter(qb64=shortqsc64)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == Counter.Sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(ShortageError):
        counter = Counter(qb2=shortqscb2)

    # test with non-zero count=5
    count = 5
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

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachedMaterialQuadlets + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigAttachedMaterialQuadlets, count=count)
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
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

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True)
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with longer ims for qb64b
    extra = b"ABCD"
    ims = bytearray(qscb + b"ABCD")
    counter = Counter(qb64b=ims, strip=True)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == Counter.Sizes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == Counter.Sizes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True)  # strip

    ims = bytes(qscb2)  # test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True)

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachedMaterialQuadlets + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True)  # test with qb2
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    #test protocol genus with CESR version
    # test with big codes index=1024
    verint = 0
    version = intToB64(verint, l=3)
    assert version == 'AAA'
    assert verint == b64ToInt(version)
    qsc = CtrDex.KERIProtocolStack + version
    assert qsc == '--AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIProtocolStack, count=verint)
    assert counter.code == CtrDex.KERIProtocolStack
    assert counter.count == verint
    assert counter.countToB64(l=3) == version
    assert counter.countToB64() == version  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(code=CtrDex.KERIProtocolStack, countB64=version)
    assert counter.code == CtrDex.KERIProtocolStack
    assert counter.count == verint
    assert counter.countToB64(l=3) == version
    assert counter.countToB64() == version  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    assert Counter.semVerToB64("1.2.3") == "BCD"
    assert Counter.semVerToB64() == "AAA"
    assert Counter.semVerToB64(major=1) == "BAA"
    assert Counter.semVerToB64(minor=1) == "ABA"
    assert Counter.semVerToB64(patch=1) == "AAB"
    assert Counter.semVerToB64(major=3, minor=4, patch=5) == "DEF"

    # test defaults for missing parts in string version
    assert Counter.semVerToB64(version="1.1") == "BBA"
    assert Counter.semVerToB64(version="1.") == "BAA"
    assert Counter.semVerToB64(version="1") == "BAA"
    assert Counter.semVerToB64(version="1.2.") == "BCA"
    assert Counter.semVerToB64(version="..") == "AAA"
    assert Counter.semVerToB64(version="1..3") == "BAD"
    assert Counter.semVerToB64(version="4", major=1, minor=2, patch=3) == "ECD"

    with pytest.raises(ValueError):
        Counter.semVerToB64(version="64.0.1")
    with pytest.raises(ValueError):
        Counter.semVerToB64(version="-1.0.1")
    with pytest.raises(ValueError):
        Counter.semVerToB64(version="0.0.64")
    with pytest.raises(ValueError):
        Counter.semVerToB64(major=64)
    with pytest.raises(ValueError):
        Counter.semVerToB64(minor=-1)
    with pytest.raises(ValueError):
        Counter.semVerToB64(patch=-1)

    """ Done Test """

def test_prodex():
    """
    Test ProtocolGenusCodex
    """
    assert dataclasses.asdict(ProDex) == {
        'KERI': '--AAA',
    }

    """ Done Test """


def test_seqner():
    """
    Test Seqner sequence number subclass of CryMat
    """
    number = Seqner()  # defaults to zero
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
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAAAF'  # '0AAAAAAAAAAAAAAAAAAAAABQ'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAAF'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    # b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P'

    number = Seqner(snh='a')
    assert number.raw == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
    assert number.code == MtrDex.Salt_128
    assert number.sn == 10
    assert number.snh == 'a'
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAAAK'  # '0AAAAAAAAAAAAAAAAAAAAACg'
    assert number.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAAK'
    assert number.qb2 == b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
    # b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0'

    # More tests
    snraw = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    snqb64b = b'0AAAAAAAAAAAAAAAAAAAAAAF'  # b'0AAAAAAAAAAAAAAAAAAAAABQ'
    snqb64 = '0AAAAAAAAAAAAAAAAAAAAAAF'  # '0AAAAAAAAAAAAAAAAAAAAABQ'
    snqb2 = b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05'
    #b'\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P'

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

def test_number():
    """
    Test Number subclass of Matter
    """
    with pytest.raises(RawMaterialError):
        number = Number(raw=b'')

    number = Number()  # test None defaults to zero
    assert number.code == NumDex.Short
    assert number.raw == b'\x00\x00'
    assert number.qb64 == 'MAAA'
    assert number.qb64b == b'MAAA'
    assert number.qb2 == b'0\x00\x00'
    assert number.num == 0
    assert number.numh == '0'
    assert not number.positive
    assert hex(int.from_bytes(number.qb2, 'big')) == '0x300000'

    # test num as empty string defaults to 0
    number = Number(num='')
    assert number.num == 0

    # test numh as empty string defaults to 0
    number = Number(numh='')
    assert number.num == 0

    # test negative  error
    with pytest.raises(InvalidValueError):
        number = Number(num=-5)

    # test not integer
    with pytest.raises(InvalidValueError):
        number = Number(num=0.0)

    with pytest.raises(InvalidValueError):
        number = Number(num=1.0)

    with pytest.raises(InvalidValueError):
        number = Number(num=1.5)

    with pytest.raises(InvalidValueError):
        number = Number(num=-2.0)

    with pytest.raises(InvalidValueError):
        number = Number(num=" :")

    # test hex number string too long > 32 characters
    #with pytest.raises(InvalidValueError):
        #number = Number(numh="0"*33)

    #with pytest.raises(InvalidValueError):
        #number = Number(num="0"*33)


    num = (256 ** 2 - 1)
    assert num == 65535
    numh = f"{num:x}"
    assert numh == 'ffff'
    code = NumDex.Short
    raw = b'\xff\xff'
    nqb64 = 'MP__'  # 'M__8'
    nqb2 = b'0\xff\xff'  # b'3\xff\xfc'
    assert hex(int.from_bytes(nqb2, 'big')) == '0x30ffff'

    number = Number(num=num)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw


    number = Number(num=numh)  # num can be hext str too
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw


    number = Number(numh=numh)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb64=nqb64)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb2=nqb2)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(raw=raw, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    num = (256 ** 4 - 1)
    assert num == 4294967295
    numh = f"{num:x}"
    assert numh == 'ffffffff'
    raw = b'\xff\xff\xff\xff'
    code = NumDex.Long
    nqb64 = '0HD_____'  # '0H_____w'
    nqb2 = b'\xd0p\xff\xff\xff\xff'  # b'\xd0\x7f\xff\xff\xff\xf0'

    number = Number(num=num)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(numh=numh)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb64=nqb64)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb2=nqb2)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive

    number = Number(raw=raw, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    num = (256 ** 8 - 1)
    assert num == 18446744073709551615
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Big
    nqb64 = 'NP__________'  # 'N__________8'
    nqb2 = b'4\xff\xff\xff\xff\xff\xff\xff\xff'  # b'7\xff\xff\xff\xff\xff\xff\xff\xfc'

    number = Number(num=num)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(numh=numh)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb64=nqb64)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb2=nqb2)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(raw=raw, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    num = (256 ** 16 - 1)
    assert num == 340282366920938463463374607431768211455
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Huge
    nqb64 = '0AD_____________________'  # '0A_____________________w'
    nqb2 = b'\xd0\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    #b'\xd0\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf0'

    number = Number(num=num)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(numh=numh)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb64=nqb64)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    number = Number(qb2=nqb2)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw


    number = Number(raw=raw, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    # tests with wrong size raw for code short
    num = (256 ** 2 - 1)
    assert num == 65535
    numh = f"{num:x}"
    assert numh == 'ffff'
    raw = b'\xff\xff'
    code = NumDex.Short
    nqb64 = 'MP__'  # 'M__8'
    nqb2 = b'0\xff\xff'  # b'3\xff\xfc'

    # raw to large for code, then truncates
    raw2bad = b'\xff\xff\xff\xff'
    assert raw != raw2bad
    assert len(raw2bad) > len(raw)

    number = Number(raw=raw2bad, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    # raw to small for code raises error
    raw2bad = b'\xff'
    assert raw != raw2bad
    assert len(raw2bad) < len(raw)

    with pytest.raises(RawMaterialError):
        number = Number(raw=raw2bad, code=code)

    # tests with wrong size raw for code long
    num = (256 ** 4 - 1)
    assert num == 4294967295
    numh = f"{num:x}"
    assert numh == 'ffffffff'
    raw = b'\xff\xff\xff\xff'
    code = NumDex.Long
    nqb64 = '0HD_____'  # '0H_____w'
    nqb2 = b'\xd0p\xff\xff\xff\xff'  # b'\xd0\x7f\xff\xff\xff\xf0'

    # raw to large for code, then truncates
    raw2bad = b'\xff\xff\xff\xff\xff'
    assert raw != raw2bad
    assert len(raw2bad) > len(raw)

    number = Number(raw=raw2bad, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    # raw to small for code raises error
    raw2bad = b'\xff'
    assert raw != raw2bad
    assert len(raw2bad) < len(raw)

    with pytest.raises(RawMaterialError):
        number = Number(raw=raw2bad, code=code)

    # tests with wrong size raw for code big
    num = (256 ** 8 - 1)
    assert num == 18446744073709551615
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Big
    nqb64 = 'NP__________'  #'N__________8'
    nqb2 = b'4\xff\xff\xff\xff\xff\xff\xff\xff' # b'7\xff\xff\xff\xff\xff\xff\xff\xfc'


    # raw to large for code, then truncates
    raw2bad = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    assert raw != raw2bad
    assert len(raw2bad) > len(raw)

    number = Number(raw=raw2bad, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    # raw to small for code raises error
    raw2bad = b'\xff'
    assert raw != raw2bad
    assert len(raw2bad) < len(raw)

    with pytest.raises(RawMaterialError):
        number = Number(raw=raw2bad, code=code)

    # tests with wrong size raw for code huge
    num = (256 ** 16 - 1)
    assert num == 340282366920938463463374607431768211455
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Huge
    nqb64 = '0AD_____________________'  # '0A_____________________w'
    nqb2 = b'\xd0\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    #b'\xd0\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf0'

    # raw to large for code, then truncates
    raw2bad = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    assert raw != raw2bad
    assert len(raw2bad) > len(raw)

    number = Number(raw=raw2bad, code=code)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw

    # raw to small for code raises error
    raw2bad = b'\xff'
    assert raw != raw2bad
    assert len(raw2bad) < len(raw)

    with pytest.raises(RawMaterialError):
        number = Number(raw=raw2bad, code=code)

    num = 1
    numh = f"{num:x}"
    assert numh == '1'
    code = NumDex.Short
    raw = b'\x00\x01'
    nqb64 = 'MAAB'  # 'MAAE'
    nqb2 = b'0\x00\x01'  # b'0\x00\x04'
    assert hex(int.from_bytes(nqb2, 'big')) == '0x300001'

    number = Number(num=num)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw


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

    # datetime property and datetime math
    dater1 = Dater(dts=dts1)
    dater2 = Dater(dts=dts2)
    dater3 = Dater(dts=helping.DTS_BASE_0)
    dater4 = Dater(dts=helping.DTS_BASE_1)

    assert dater1.datetime < dater2.datetime
    assert dater4.datetime > dater3.datetime

    """ Done Test """


def test_bexter():
    """
    Test Bexter variable sized Base64 text subclass of Matter
    """
    with pytest.raises(EmptyMaterialError):
        bexter = Bexter()

    bext = "@!"
    with pytest.raises(ValueError):
        bexter = Bexter(bext=bext)

    bext = ""
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAA'
    assert bexter.raw == b''
    assert bexter.qb64 == '4AAA'
    assert bexter.qb2 == b'\xe0\x00\x00'
    assert bexter.bext == bext

    bext = "-"
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L2
    assert bexter.both == '6AAB'
    assert bexter.raw == b'>'
    assert bexter.qb64 == '6AABAAA-'
    assert bexter.qb2 == b'\xe8\x00\x01\x00\x00>'
    assert bexter.bext == bext

    bext = "-A"
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L1
    assert bexter.both == '5AAB'
    assert bexter.raw == b'\x0f\x80'
    assert bexter.qb64 == '5AABAA-A'
    assert bexter.qb2 == b'\xe4\x00\x01\x00\x0f\x80'
    assert bexter.bext == bext

    bext = "-A-"
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\x03\xe0>'
    assert bexter.qb64 == '4AABA-A-'
    assert bexter.qb2 == b'\xe0\x00\x01\x03\xe0>'
    assert bexter.bext == bext

    bext = "-A-B"
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\xf8\x0f\x81'
    assert bexter.qb64 == '4AAB-A-B'
    assert bexter.qb2 == b'\xe0\x00\x01\xf8\x0f\x81'
    assert bexter.bext == bext



    bext = "A"
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L2
    assert bexter.both == '6AAB'
    assert bexter.raw == b'\x00'
    assert bexter.qb64 == '6AABAAAA'
    assert bexter.qb2 == b'\xe8\x00\x01\x00\x00\x00'
    assert bexter.bext == bext

    bext = "AA"
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L1
    assert bexter.both == '5AAB'
    assert bexter.raw == b'\x00\x00'
    assert bexter.qb64 == '5AABAAAA'
    assert bexter.qb2 ==b'\xe4\x00\x01\x00\x00\x00'
    assert bexter.bext == bext

    # test of ambiguity with bext that starts with "A" and is multiple of 3 or 4
    bext = "AAA"  # multiple of three
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\x00\x00\x00'
    assert bexter.qb64 == '4AABAAAA'
    assert bexter.qb2 == b'\xe0\x00\x01\x00\x00\x00'
    assert bexter.bext == bext

    bext = "AAAA"  # multiple of four loses leading 'A' for round trip of bext
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\x00\x00\x00'
    assert bexter.qb64 == '4AABAAAA'
    assert bexter.qb2 == b'\xe0\x00\x01\x00\x00\x00'
    assert bexter.bext == 'AAA' != bext

    bext = "ABB"  # multiple of three
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\x00\x00A'
    assert bexter.qb64 == '4AABAABB'
    assert bexter.qb2 == b'\xe0\x00\x01\x00\x00A'
    assert bexter.bext == bext

    bext = "BBB"  # multiple of three
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\x00\x10A'
    assert bexter.qb64 == '4AABABBB'
    assert bexter.qb2 == b'\xe0\x00\x01\x00\x10A'
    assert bexter.bext == bext

    bext = "ABBB"  # multiple of four loses leading 'A' for round trip of bext
    bexter = Bexter(bext=bext)
    assert bexter.code == MtrDex.StrB64_L0
    assert bexter.both == '4AAB'
    assert bexter.raw == b'\x00\x10A'
    assert bexter.qb64 == '4AABABBB'
    assert bexter.qb2 == b'\xe0\x00\x01\x00\x10A'
    assert bexter.bext == 'BBB' != bext


    """ Done Test """


def test_pather():
    """
    """

    sad = dict(a=dict(z="value", b=dict(x=1, y=2, c="test")))
    path = []
    pather = coring.Pather(path=path)
    assert pather.bext == "-"
    assert pather.qb64 == "6AABAAA-"
    assert pather.raw == b'>'
    assert pather.resolve(sad) == sad
    assert pather.path == path

    path = ["a", "b", "c"]
    pather = coring.Pather(path=path)
    assert pather.bext == "-a-b-c"
    assert pather.qb64 == "5AACAA-a-b-c"
    assert pather.raw == b'\x0f\x9a\xf9\xbf\x9c'
    assert pather.resolve(sad) == "test"
    assert pather.path == path

    path = ["0", "1", "2"]
    pather = coring.Pather(path=path)
    assert pather.bext == "-0-1-2"
    assert pather.qb64 == "5AACAA-0-1-2"
    assert pather.raw == b'\x0f\xb4\xfb_\xb6'
    assert pather.resolve(sad) == "test"
    assert pather.path == path

    sad = dict(field0=dict(z="value", field1=dict(field2=1, field3=2, c="test")))
    path = ["field0"]
    pather = coring.Pather(path=path)
    assert pather.bext == "-field0"
    assert pather.qb64 == "4AACA-field0"
    assert pather.raw == b'\x03\xe7\xe2zWt'
    assert pather.resolve(sad) == {'field1': {'c': 'test', 'field2': 1, 'field3': 2}, 'z': 'value'}
    assert pather.path == path

    path = ["field0", "field1", "field3"]
    pather = coring.Pather(path=path)
    assert pather.bext == "-field0-field1-field3"
    assert pather.qb64 == "6AAGAAA-field0-field1-field3"
    assert pather.raw == b">~'\xa5wO\x9f\x89\xe9]\xd7\xe7\xe2zWw"
    assert pather.resolve(sad) == 2
    assert pather.path == path

    path = ["field0", "1", "0"]
    pather = coring.Pather(path=path)
    assert pather.bext == "-field0-1-0"
    assert pather.qb64 == "4AADA-field0-1-0"
    assert pather.raw == b'\x03\xe7\xe2zWt\xfb_\xb4'
    assert pather.resolve(sad) == 1
    assert pather.path == path

    sad = dict(field0=dict(z=dict(field2=1, field3=2, c="test"), field1="value"))
    text = "-0-z-2"
    pather = coring.Pather(bext=text)
    assert pather.bext == text
    assert pather.qb64 == "5AACAA-0-z-2"
    assert pather.raw == b'\x0f\xb4\xfb?\xb6'
    assert pather.resolve(sad) == "test"
    assert pather.path == ["0", "z", "2"]

    text = "-0-a"
    pather = coring.Pather(bext=text)
    assert pather.bext == text
    assert pather.qb64 == "4AAB-0-a"
    assert pather.raw == b'\xfbO\x9a'
    with pytest.raises(KeyError):
        pather.resolve(sad)
    assert pather.path == ["0", "a"]

    text = "-0-field1-0"
    pather = coring.Pather(bext=text)
    assert pather.bext == text
    assert pather.qb64 == "4AADA-0-field1-0"
    assert pather.raw == b"\x03\xed>~'\xa5w_\xb4"
    with pytest.raises(ValueError):
        pather.resolve(sad)
    assert pather.path == ["0", "field1", "0"]

    path = ["Not$Base64", "@moreso", "*again"]
    with pytest.raises(ValueError):
        pather = coring.Pather(path=path)

    text = "-a"
    a = coring.Pather(bext=text)
    b = coring.Pather(bext="-a-b")

    pather = coring.Pather(bext=text)
    assert pather.startswith(a)
    assert not pather.startswith(b)

    pnew = pather.strip(a)
    assert pnew.path == []

    pnew = pather.strip(b)
    assert pnew.path == pather.path

    pather = coring.Pather(bext="-a-b-c-d-e-f")
    assert pather.startswith(a)
    assert pather.startswith(b)

    pnew = pather.strip(a)
    assert pnew.path == ["b", "c", "d", "e", "f"]

    pnew = pather.strip(b)
    assert pnew.path == ["c", "d", "e", "f"]

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

    # create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    sig = pysodium.crypto_sign_detached(ser, seed + verkey)  # sigkey = seed + verkey

    result = verfer.verify(sig, ser)
    assert result == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    assert verfer.raw == verkey
    assert verfer.code == MtrDex.Ed25519

    # create something to sign and verify
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

    qsig64 = '0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'

    cigar = Cigar(qb64=qsig64)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert cigar.qb64 == qsig64
    assert cigar.verfer == None

    verkey, sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    cigar.verfer = verfer
    assert cigar.verfer == verfer

    cigar = Cigar(qb64=qsig64, verfer=verfer)
    assert cigar.verfer == verfer
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

    # create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    index = 0
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.Ed25519_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False

    assert cigar.raw == siger.raw

    with pytest.raises(ValueError):  # use invalid code not SEED type code
        signer = Signer(code=MtrDex.Ed25519N)

    # Non transferable defaults
    signer = Signer(transferable=False)  # Ed25519N verifier
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519N
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    siger = signer.sign(ser, index=0)
    assert siger.code == IdrDex.Ed25519_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True
    result = signer.verfer.verify(siger.raw, ser + b'ABCDEFG')
    assert result == False


    # non default seed
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    signer = Signer(raw=seed, code=MtrDex.Ed25519_Seed)
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.raw == seed
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)

    cigar = signer.sign(ser)
    assert cigar.code == MtrDex.Ed25519_Sig
    assert len(cigar.raw) == Matter._rawSize(cigar.code)
    result = signer.verfer.verify(cigar.raw, ser)
    assert result == True

    index = 1
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.Ed25519_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    assert cigar.raw == siger.raw

    # different both so Big
    ondex = 3
    siger = signer.sign(ser, index=index, ondex=ondex)
    assert siger.code == IdrDex.Ed25519_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == ondex
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # same but Big
    index = 67
    siger = signer.sign(ser, index=index)
    assert siger.code == IdrDex.Ed25519_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == index
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # different both so Big
    ondex = 67
    siger = signer.sign(ser, index=index, ondex=ondex)
    assert siger.code == IdrDex.Ed25519_Big_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == ondex
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # current only
    index = 4
    siger = signer.sign(ser, index=index, only=True)
    assert siger.code == IdrDex.Ed25519_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # ignores ondex if only
    siger = signer.sign(ser, index=index, only=True, ondex=index+2)
    assert siger.code == IdrDex.Ed25519_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # big current only
    index = 65
    siger = signer.sign(ser, index=index, only=True)
    assert siger.code == IdrDex.Ed25519_Big_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    # ignores ondex if only
    siger = signer.sign(ser, index=index, only=True, ondex=index+2)
    assert siger.code == IdrDex.Ed25519_Big_Crt_Sig
    assert len(siger.raw) == Indexer._rawSize(siger.code)
    assert siger.index == index
    assert siger.ondex == None
    result = signer.verfer.verify(siger.raw, ser)
    assert result == True

    with pytest.raises(ValueError):  # use invalid code not SEED type code
        signer = Signer(raw=seed, code=MtrDex.Ed25519N)



    # test with only and ondex parameters


    """ Done Test """


def test_cipher():
    """
    Test Cipher subclass of Matter
    """
    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
            b'\xde\x06\xc0+')
    seedqb64b = Matter(raw=seed, code=MtrDex.Ed25519_Seed).qb64b
    assert seedqb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'
    #b'AGDswxA8qdkb646JFZWUflm_OKUeF41iG2gTw3N4GwCs'

    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'6\x08d\r\xa1\xbb9\x8dp\x8d\xa0\xc0\x13J\x87r'
    saltqb64b = Matter(raw=salt, code=MtrDex.Salt_128).qb64b
    assert saltqb64b == b'0AA2CGQNobs5jXCNoMATSody'

    # seed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    cryptseed = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(cryptseed)
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    with pytest.raises(EmptyMaterialError):
        cipher = Cipher()

    raw = pysodium.crypto_box_seal(seedqb64b, pubkey)  # uses nonce so different everytime
    cipher = Cipher(raw=raw)
    assert cipher.code == MtrDex.X25519_Cipher_Seed
    uncb = pysodium.crypto_box_seal_open(cipher.raw, pubkey, prikey)
    assert uncb == seedqb64b

    # test .decrypt method needs qb64
    prikeyqb64 = Matter(raw=prikey, code=MtrDex.X25519_Private).qb64b
    assert cipher.decrypt(prikey=prikeyqb64).qb64b == seedqb64b

    cryptseedqb64 = Matter(raw=cryptseed, code=MtrDex.Ed25519_Seed).qb64b
    assert cipher.decrypt(seed=cryptseedqb64).qb64b == seedqb64b

    raw = pysodium.crypto_box_seal(saltqb64b, pubkey)  # uses nonce so different everytime
    cipher = Cipher(raw=raw)
    assert cipher.code == MtrDex.X25519_Cipher_Salt
    uncb = pysodium.crypto_box_seal_open(cipher.raw, pubkey, prikey)
    assert uncb == saltqb64b

    # test .decrypt method needs qb64
    prikeyqb64 = Matter(raw=prikey, code=MtrDex.X25519_Private).qb64b
    assert cipher.decrypt(prikey=prikeyqb64).qb64b == saltqb64b

    cryptseedqb64 = Matter(raw=cryptseed, code=MtrDex.Ed25519_Seed).qb64b
    assert cipher.decrypt(seed=cryptseedqb64).qb64b == saltqb64b

    with pytest.raises(ValueError):  # bad code
        cipher = Cipher(raw=raw, code=MtrDex.Ed25519N)
    """ Done Test """


def test_encrypter():
    """
    Test Encrypter subclass of Matter
    """
    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
            b'\xde\x06\xc0+')
    seedqb64b = Matter(raw=seed, code=MtrDex.Ed25519_Seed).qb64b
    assert seedqb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'

    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'6\x08d\r\xa1\xbb9\x8dp\x8d\xa0\xc0\x13J\x87r'
    saltqb64b = Matter(raw=salt, code=MtrDex.Salt_128).qb64b
    assert saltqb64b == b'0AA2CGQNobs5jXCNoMATSody'

    # seed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    cryptseed = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner = Signer(raw=cryptseed, code=MtrDex.Ed25519_Seed, transferable=True)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(cryptseed)  # raw
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    with pytest.raises(EmptyMaterialError):
        encrypter = Encrypter()

    encrypter = Encrypter(raw=pubkey)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey
    assert encrypter.verifySeed(seed=cryptsigner.qb64)

    cipher = encrypter.encrypt(ser=seedqb64b)
    assert cipher.code == MtrDex.X25519_Cipher_Seed
    uncb = pysodium.crypto_box_seal_open(cipher.raw, encrypter.raw, prikey)
    assert uncb == seedqb64b

    cipher = encrypter.encrypt(ser=saltqb64b)
    assert cipher.code == MtrDex.X25519_Cipher_Salt
    uncb = pysodium.crypto_box_seal_open(cipher.raw, encrypter.raw, prikey)
    assert uncb == saltqb64b

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)

    encrypter = Encrypter(verkey=verfer.qb64)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey

    encrypter = Encrypter(verkey=verfer.qb64b)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey

    # user Prefixer to generate original verkey
    prefixer = Prefixer(qb64=verfer.qb64)
    encrypter = Encrypter(verkey=prefixer.qb64b)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey
    """ Done Test """


def test_decrypter():
    """
    Test Decrypter subclass of Matter
    """
    # conclusion never use box_seed_keypair always use sign_seed_keypair and
    # then use crypto_sign_xk_to_box_xk to generate x25519 keys so the prikey
    # is always the same.

    assert pysodium.crypto_box_SEEDBYTES == pysodium.crypto_sign_SEEDBYTES == 32

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
            b'\xde\x06\xc0+')
    signer = Signer(raw=seed, code=MtrDex.Ed25519_Seed)
    assert signer.verfer.code == MtrDex.Ed25519
    assert signer.verfer.transferable  # default
    seedqb64b = signer.qb64b
    assert seedqb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'
    # also works for Matter
    assert seedqb64b == Matter(raw=seed, code=MtrDex.Ed25519_Seed).qb64b

    # raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    raw = b'6\x08d\r\xa1\xbb9\x8dp\x8d\xa0\xc0\x13J\x87r'
    salter = Salter(raw=raw, code=MtrDex.Salt_128)
    assert salter.code == MtrDex.Salt_128
    saltqb64b = salter.qb64b
    assert saltqb64b == b'0AA2CGQNobs5jXCNoMATSody'
    # also works for Matter
    assert saltqb64b == Matter(raw=raw, code=MtrDex.Salt_128).qb64b  #

    # cryptseed = pysodium.randombytes(pysodium.crypto_box_SEEDBYTES)
    cryptseed = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner = Signer(raw=cryptseed, code=MtrDex.Ed25519_Seed, transferable=True)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(cryptseed)  # raw
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
    prikey = pysodium.crypto_sign_sk_to_box_sk(sigkey)

    with pytest.raises(EmptyMaterialError):
        decrypter = Decrypter()

    # create encrypter
    encrypter = Encrypter(raw=pubkey)
    assert encrypter.code == MtrDex.X25519
    assert encrypter.qb64 == 'CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR'
    assert encrypter.raw == pubkey

    # create cipher of seed
    seedcipher = encrypter.encrypt(ser=seedqb64b)
    assert seedcipher.code == MtrDex.X25519_Cipher_Seed
    # each encryption uses a nonce so not a stable representation for testing

    # create decrypter from prikey
    decrypter = Decrypter(raw=prikey)
    assert decrypter.code == MtrDex.X25519_Private
    assert decrypter.qb64 == 'OLCFxqMz1z1UUS0TEJnvZP_zXHcuYdQsSGBWdOZeY5VQ'
    assert decrypter.raw == prikey

    # decrypt seed cipher using ser
    designer = decrypter.decrypt(ser=seedcipher.qb64b, transferable=signer.verfer.transferable)
    assert designer.qb64b == seedqb64b
    assert designer.code == MtrDex.Ed25519_Seed
    assert designer.verfer.code == MtrDex.Ed25519
    assert signer.verfer.transferable

    # decrypt seed cipher using cipher
    designer = decrypter.decrypt(cipher=seedcipher, transferable=signer.verfer.transferable)
    assert designer.qb64b == seedqb64b
    assert designer.code == MtrDex.Ed25519_Seed
    assert designer.verfer.code == MtrDex.Ed25519
    assert signer.verfer.transferable

    # create cipher of salt
    saltcipher = encrypter.encrypt(ser=saltqb64b)
    assert saltcipher.code == MtrDex.X25519_Cipher_Salt
    # each encryption uses a nonce so not a stable representation for testing

    # decrypt salt cipher using ser
    desalter = decrypter.decrypt(ser=saltcipher.qb64b)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    # decrypt salt cipher using cipher
    desalter = decrypter.decrypt(cipher=saltcipher)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    # use previously stored fully qualified seed cipher with different nonce
    # get from seedcipher above
    cipherseed = ('PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_'
                  'NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw')
    designer = decrypter.decrypt(ser=cipherseed, transferable=signer.verfer.transferable)
    assert designer.qb64b == seedqb64b
    assert designer.code == MtrDex.Ed25519_Seed
    assert designer.verfer.code == MtrDex.Ed25519

    # use previously stored fully qualified salt cipher with different nonce
    # get from saltcipher above
    ciphersalt = ('1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWy'
                  'IwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu')
    desalter = decrypter.decrypt(ser=ciphersalt)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

    # Create new decrypter but use seed parameter to init prikey
    decrypter = Decrypter(seed=cryptsigner.qb64b)
    assert decrypter.code == MtrDex.X25519_Private
    assert decrypter.qb64 == 'OLCFxqMz1z1UUS0TEJnvZP_zXHcuYdQsSGBWdOZeY5VQ'
    assert decrypter.raw == prikey

    # decrypt ciphersalt
    desalter = decrypter.decrypt(ser=saltcipher.qb64b)
    assert desalter.qb64b == saltqb64b
    assert desalter.code == MtrDex.Salt_128

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
    assert salter.qb64 == '0AAwMTIzNDU2Nzg5YWJjZGVm'  #'0ACDEyMzQ1Njc4OWFiY2RlZg'

    signer = salter.signer(path="01", temp=True)  # defaults to Ed25519
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'AMPsqBZxWdtYpBhrWnKYitwFa77s902Q-nX3sPTzqs0R'
    #'Aw-yoFnFZ21ikGGtacpiK3AVrvuz3TZD6dfew9POqzRE'
    assert signer.verfer.qb64 == 'DFYFwZJOMNy3FknECL8tUaQZRBUyQ9xCv6F8ckG-UCrC'  #
    # 'DVgXBkk4w3LcWScQIvy1RpBlEFTJD3EK_oXxyQb5QKsI'

    signer = salter.signer(path="01")  # defaults to Ed25519 temp = False level="low"
    assert signer.code == MtrDex.Ed25519_Seed
    assert len(signer.raw) == Matter._rawSize(signer.code)
    assert signer.verfer.code == MtrDex.Ed25519
    assert len(signer.verfer.raw) == Matter._rawSize(signer.verfer.code)
    assert signer.qb64 == 'AEkqQiNTexWB9fTLpgJp_lXW63tFlT-Y0_mgQww4o-dC'
    # 'ASSpCI1N7FYH19MumAmn-Vdbre0WVP5jT-aBDDDij50I'
    assert signer.verfer.qb64 == 'DPJGyH9H1M_SUSf18RzX8OqdyhxEyZJpKm5Em0PnpsWd'
    #'D8kbIf0fUz9JRJ_XxHNfw6p3KHETJkmkqbkSbQ-emxZ0'

    salter = Salter(qb64='0AAwMTIzNDU2Nzg5YWJjZGVm')
    assert salter.raw == raw
    assert salter.qb64 == '0AAwMTIzNDU2Nzg5YWJjZGVm'

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

    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    assert len(salt) == 16
    signers = generateSigners(salt=salt, count=4)  # default is transferable
    assert len(signers) == 4
    for signer in signers:
        assert signer.code == MtrDex.Ed25519_Seed
        assert signer.verfer.code == MtrDex.Ed25519

    sigkeys = [signer.qb64 for signer in signers]
    assert sigkeys == ['AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH',
                       'AOs8-zNPPh0EhavdrCfCiTk9nGeO8e6VxUCzwdKXJAd0',
                       'AHMBU5PsIJN2U9m7j0SGyvs8YD8fkym2noELzxIrzfdG',
                       'AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP']

    secrets = generatePrivates(salt=salt, count=4)
    assert secrets == sigkeys

    """ End Test """


def test_diger():
    """
    Test the support functionality for Diger subclass of CryMat
    """
    with pytest.raises(EmptyMaterialError):
        diger = Diger()

    # create something to digest and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    dig = blake3.blake3(ser).digest()
    with pytest.raises(coring.InvalidValueError):
        diger = Diger(raw=dig, code=MtrDex.Ed25519)

    with pytest.raises(coring.InvalidValueError):
        diger = Diger(ser=ser, code=MtrDex.Ed25519)

    diger = Diger(raw=dig)  # defaults provide Blake3_256 digester
    assert diger.code == MtrDex.Blake3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)
    assert not diger.verify(ser=ser + b'ABCDEF')

    diger = Diger(raw=dig, code=MtrDex.Blake3_256)
    assert diger.code == MtrDex.Blake3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)

    diger = Diger(ser=ser)  # default code is  Blake3_256
    assert diger.code == MtrDex.Blake3_256
    assert len(diger.raw) == Matter._rawSize(diger.code)
    assert diger.verify(ser=ser)
    assert diger.qb64b == b'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    #b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'

    digb = b'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    #b'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
    dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    #'EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E'
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

    diger0 = Diger(ser=ser)  # default code
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


def test_prefixer():
    """
    Test the support functionality for prefixer subclass of crymat
    """
    preN = 'BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    # 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
    pre = 'DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #'DrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    # verkey,  sigkey = pysodium.crypto_sign_keypair()
    verkey = (b'\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0='
              b'`\xf7\xbf\x8a\x18\x8a`q')
    verfer = Verfer(raw=verkey)
    assert verfer.qb64 == 'BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx'
    #'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'

    nxtkey = (b"\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2"
              b'\xc4_\xf6\x00')
    nxtfer = Verfer(raw=nxtkey, code=MtrDex.Ed25519)
    assert nxtfer.qb64 == 'DKZfiTRK8jVUwYMjBphMpu8as2jqQTp4J9oEiLLEX_YA'
    #'Dpl-JNEryNVTBgyMGmEym7xqzaOpBOngn2gSIssRf9gA'

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
    assert len(prefixer.qb64) == Matter.Sizes[prefixer.code].fs

    ked = dict(k=[prefixer.qb64], n="", t="icp")
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(k=[prefixer.qb64], n="ABC", t="icp")
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    prefixer = Prefixer(raw=verkey, code=MtrDex.Ed25519)  # defaults provide Ed25519N prefixer
    assert prefixer.code == MtrDex.Ed25519
    assert len(prefixer.raw) == Matter._rawSize(prefixer.code)
    assert len(prefixer.qb64) == Matter.Sizes[prefixer.code].fs

    ked = dict(k=[prefixer.qb64], t="icp")
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    prefixer = Prefixer(raw=verfer.raw, code=MtrDex.Ed25519N)
    assert prefixer.code == MtrDex.Ed25519N
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # Test basic derivation from ked
    ked = dict(k=[verfer.qb64], n="", t="icp")
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519)
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(k=[verfer.qb64], n="", t="icp")  # ked without prefix
    with pytest.raises(EmptyMaterialError):  # no code and no pre in ked
        prefixer = Prefixer(ked=ked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)  # verfer code not match pre code
    ked = dict(k=[verfer.qb64], n="", t="icp", i=preN)
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    ked = dict(k=[verfer.qb64], n="", t="icp", i=pre)
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519N)  # verfer code not match code

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="", t="icp", i=pre)
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519N)  # verfer code match code but not pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="", t="icp", i=preN)
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519N)  # verfer code match code and pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="", t="icp", i=preN)
    prefixer = Prefixer(ked=ked)  # verfer code match pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    ked = dict(k=[verfer.qb64], n="", t="icp")
    with pytest.raises(EmptyMaterialError):
        prefixer = Prefixer(ked=ked)

    ked = dict(k=[verfer.qb64], n="ABCD", t="icp")
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519)

    # Test digest derivation from inception ked
    vs = versify(version=Version, kind=Serials.json, size=0)
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
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'ELEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo'
    #'EREh4RHCZHUy5nPrY131A4h4RuDAOynRQdQY0PLJybEQ'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with next digs
    ndigs = [Diger(ser=nxtfer.qb64b).qb64]
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=ndigs,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EHZUmVPq9cXFvGwWP4ohwA27XlsWHBxxu4xFiXp8UOol'
    #'EDve7ZqtIsIMrx6UVZRTcnLgEnYGGV2is_JI_Ps3hEnE'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False


    salt = b'g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW'
    #secrets = generateSecrets(salt=salt,  count=8)

    # test with fractionally weighted sith
    secrets =  ['AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH',
                'AOs8-zNPPh0EhavdrCfCiTk9nGeO8e6VxUCzwdKXJAd0',
                'AHMBU5PsIJN2U9m7j0SGyvs8YD8fkym2noELzxIrzfdG',
                'AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP',
                'ANfkMQ5LKPfjEdQPK2c_zWsOn4GgLWsnWvIa25EVVbtR',
                'ACrmDHtPQjnM8H9pyKA-QBNdfZ-xixTlRZTS8WXCrrMH',
                'AMRXyU3ErhBNdRSDX1zKlrbZGRp1GfCmkRIa58gF07I8',
                'AC6vsNVCpHa6acGcxk7c-D1mBHlptPrAx8zr-bKvesSW']

    # create signers from secrets
    signers = [Signer(qb64=secret) for secret in secrets]  # faster
    assert [siger.qb64 for siger in signers] == secrets
    # each signer has verfer for keys

    # Test with sith with one clause
    keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
    sith = [["1/2", "1/2", "1"]]
    ndigs = [Diger(ser=signers[3].verfer.qb64b).qb64]  # default limen/sith
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=ndigs,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer1 = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer1.qb64 == 'EBfPkd-A2CQfJmfpmtc1V-yuleSeCcyWBIrTAygUgQ_T'
    assert prefixer1.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # now test with different sith but same weights in two clauses
    sith = [["1/2", "1/2"], ["1"]]
    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=ndigs,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    prefixer2 = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer2.qb64 == 'EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb'
    assert prefixer2.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False
    assert prefixer2.qb64 != prefixer1.qb64  # semantic diff -> syntactic diff

    sith = "1"
    seal = dict(i='EBfPkd-A2CQfJmfpmtc1V-yuleSeCcyWBIrTAygUgQ_T',
                s='2',
                t=Ilks.ixn,
                d='EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb')

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=Ilks.dip,
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=ndigs,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               da=seal
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with allows
    with pytest.raises(ValueError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256,
                            allows=[MtrDex.Ed25519N, MtrDex.Ed25519])

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256,
                        allows=[MtrDex.Blake3_256, MtrDex.Ed25519])
    assert prefixer.qb64 == 'EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    """ Done Test """


def test_siger():
    """
    Test Siger subclass of Indexer
    """
    with pytest.raises(EmptyMaterialError):
        siger = Siger()

    qsig64 = ('AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd'
              '7K_H9-1298F4Id1DxvIoEmCQ')
    #'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
    qsig64b = qsig64.encode("utf-8")
    assert qsig64b == (b'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGR'
                       b'cKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ')

    siger = Siger(qb64b=qsig64b)
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.ondex == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    siger = Siger(qb64=qsig64)
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.ondex == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    siger = Siger(qb64=qsig64b)  # also bytes
    assert siger.code == IdrDex.Ed25519_Sig
    assert siger.index == 0
    assert siger.ondex == 0
    assert siger.qb64 == qsig64
    assert siger.verfer == None


    verkey, sigkey = pysodium.crypto_sign_keypair()
    verfer = Verfer(raw=verkey)

    siger.verfer = verfer
    assert siger.verfer == verfer

    siger = Siger(qb64=qsig64, verfer=verfer)
    assert siger.verfer == verfer

    siger = Siger(
        raw=b'abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456'
            b'789abcdef', code=IdrDex.Ed448_Sig, index=4)
    assert siger.qb64 == ('0AEEYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTI'
                          'zNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVm')


    """ Done Test """


def test_saider():
    """
    Test Saider object
    """
    # Test class attribute Digest matches DigDex (i.e.DigestCodex)
    assert set(Saider.Digests.keys()) == set(code for code in DigDex)

    code = MtrDex.Blake3_256
    kind = Serials.json
    label = Ids.dollar

    # Test with valid said qb64
    said0 = 'EBG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA'
    saider = Saider(qb64=said0)  # raw and code from qb64
    assert saider.code == code == MtrDex.Blake3_256  # code from said
    assert saider.qb64 == said0

    ser0 = (b'{"$id": "", "$schema": '
            b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
            b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')

    sad0 = json.loads(ser0)

    saider, sad = Saider.saidify(sad=sad0, label=label)
    assert saider.qb64 == 'EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw'
    said0 = 'EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw'

    # Test with JSON Schema for SAD
    # serialized with valid said in $id field as JSON Schema
    ser0 = (b'{"$id": "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw", "$schema": '
            b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
            b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')

    sad0 = json.loads(ser0)
    assert saider.verify(sad0, prefixed=True, label=label)  # kind default

    # dict with empty said in $id field
    sad1 = {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
    }
    sad1.update(dict(
        type="object",
        properties=dict(
            a=dict(type="string"),
            b=dict(type="number"),
            c=dict(
                type="string",
                format="date-time"
            )
        )
    )
    )
    assert saider.verify(sad1, prefixed=False, label=label)  # kind default
    assert not saider.verify(sad1, prefixed=True, label=label)  # kind default

    # Initialize from dict needs code
    saider = Saider(sad=sad1, code=code, label=label)  # kind default
    assert saider.code == code == MtrDex.Blake3_256
    assert saider.qb64 == said0
    assert saider.verify(sad1, prefixed=False, label=label)  # kind default
    assert not saider.verify(sad1, prefixed=True, label=label)  # kind default
    assert saider.verify(sad0, prefixed=True, label=label)  # kind default

    # make copy of sad1 and saidify the copy
    saider, sad = Saider.saidify(sad=dict(sad1), label=label)  # default code
    assert saider.code == code == MtrDex.Blake3_256
    assert saider.qb64 == said0
    assert sad != sad1
    assert not sad1[label]
    assert sad[label] == said0
    assert saider.verify(sad, prefixed=True, label=label)

    # Use different code not the default
    code = MtrDex.Blake2b_256

    said2 = 'FG1_1lgNJ69QPnJK-pD5s8cinFFYhnGN8nuyz8Mdrezg'
    saider = Saider(qb64=said2, label=label)
    assert saider.code == code == MtrDex.Blake2b_256
    assert saider.qb64 == said2

    ser2 = (b'{"$id":"FW1_1lgNJ69QPnJK-pD5s8cinFFYhnGN8nuyz8Mdrezg","$schema":"http://json'
            b'-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"str'
            b'ing"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}')
    sad2 = json.loads(ser2)
    saider, sad = Saider.saidify(sad=sad2, code = MtrDex.Blake2b_256, label='$id')
    assert saider.qb64 == 'FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4'
    said2 = 'FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4'

    ser2 = (b'{"$id":"FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4","$schema":"http://json'
            b'-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"str'
            b'ing"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}')
    sad2 = json.loads(ser2)

    assert saider.verify(sad2, prefixed=True, label=label)  # kind default

    # Initialize from dict needs code
    saider = Saider(sad=sad1, code=code, label=label)
    assert saider.code == code == MtrDex.Blake2b_256
    assert saider.qb64 == said2
    assert saider.verify(sad1, prefixed=False, label=label)  # kind default
    assert not saider.verify(sad1, prefixed=True, label=label)  # kind default
    assert saider.verify(sad2, prefixed=True, label=label)  # kind default

    # Initialize from dict get code from label
    saider = Saider(sad=sad2, label=label)  # no code and label code not default
    assert saider.code == code == MtrDex.Blake2b_256  # not default
    assert saider.qb64 == said2
    assert saider.verify(sad1, prefixed=False, label=label)  # kind default
    assert not saider.verify(sad1, prefixed=True, label=label)  # kind default
    assert saider.verify(sad2, prefixed=True, label=label)  # kind default

    # saidify copy of sad1
    saider, sad = Saider.saidify(sad=dict(sad1), code=code, label=label)
    assert saider.code == code == MtrDex.Blake2b_256
    assert saider.qb64 == said2
    assert sad != sad1
    assert not sad1[label]
    assert sad[label] == said2
    assert saider.verify(sad, prefixed=True, label=label)
    assert saider.verify(sad1, prefixed=False, label=label)  # kind default
    assert not saider.verify(sad1, prefixed=True, label=label)  # kind default
    assert saider.verify(sad2, prefixed=True, label=label)  # kind default

    # test with default id field label Ids.d == 'd' and contains 'v' field
    label = Ids.d
    code = MtrDex.Blake3_256  # back to default code

    # Load from vaccuous dict
    label = Ids.d
    vs = versify(version=Version, kind=kind, size=0)  # vaccuous size == 0
    assert vs == 'KERI10JSON000000_'
    sad4 = dict(
        v=vs,
        t="rep",
        d="",  # vacuous said
        dt="2020-08-22T17:50:12.988921+00:00",
        r="logs/processor",
        a=dict(
            d="EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg",
            i="EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb",
            name="John Jones",
            role="Founder",
        ),
    )
    saider = Saider(sad=sad4)  # default version string code, kind, and label
    assert saider.code == code == MtrDex.Blake3_256
    assert saider.qb64 == 'ELzewBpZHSENRP-sL_G_2Ji4YDdNkns9AzFzufleJqdw'
    assert saider.verify(sad4, prefixed=False, versioned=False)  # kind and label default
    assert not saider.verify(sad4, prefixed=False)  # kind and label default
    assert not saider.verify(sad4, prefixed=True, versioned=False)  # kind and label default

    sad5 = dict(sad4)
    sad5[label] = saider.qb64  # assign said to label field
    assert saider.verify(sad5, prefixed=True, versioned=False)  # default kind label

    sad6 = dict(sad5)
    _, dsad = saider.derive(sad=sad4)
    sad6['v'] = dsad['v']
    assert saider.verify(sad6, prefixed=True)

    said3 = saider.qb64
    saider = Saider(qb64=said3)
    assert saider.code == code == MtrDex.Blake3_256
    assert saider.qb64 == said3

    ser5 = coring.dumps(ked=sad5, kind=kind)

    assert ser5 == (b'{"v":"KERI10JSON000000_","t":"rep","d":"ELzewBpZHSENRP-sL_G_2Ji4YDdNkns9AzFz'
                    b'ufleJqdw","dt":"2020-08-22T17:50:12.988921+00:00","r":"logs/processor","a":{'
                    b'"d":"EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg","i":"EB0_D51cTh_q6uOQ-byF'
                    b'iv5oNXZ-cxdqCqBAa4JmBLtb","name":"John Jones","role":"Founder"}}')

    sad3 = coring.loads(ser5)
    assert not saider.verify(sad3, prefixed=True)
    assert saider.verify(sad3, prefixed=True, versioned=False)  # default kind label

    # saidify copy of sad4
    assert not sad4[label]
    assert sad4['v'] == 'KERI10JSON000000_'
    saider, sad = Saider.saidify(sad=sad4)  # vaccuous size default code kind label
    assert saider.code == code == MtrDex.Blake3_256
    assert saider.qb64 == said3
    assert sad != sad4
    assert not sad4[label]
    assert sad[label] == said3

    assert saider.verify(sad, prefixed=True)  # default kind label
    assert not saider.verify(sad4, prefixed=True)  # kind and label default
    assert not saider.verify(sad4, prefixed=False)  # kind and label default
    assert saider.verify(sad4, prefixed=False, versioned=False)  # kind and label default
    assert saider.verify(sad3, prefixed=True, versioned=False)  # default kind label

    # verify code  not default
    saider = Saider(sad=sad3, code=MtrDex.Blake2b_256)  # default label
    assert saider.code == MtrDex.Blake2b_256 != code
    assert saider.qb64 != said3
    assert saider.verify(sad3, prefixed=False, versioned=False)
    assert not saider.verify(sad3, prefixed=True)
    saider, sad7 = Saider.saidify(sad=sad3, code=MtrDex.Blake2b_256)
    assert saider.qb64 != said3
    assert saider.verify(sad7, prefixed=True)

    assert saider.verify(sad4, prefixed=False, versioned=False)  # kind and label default
    assert not saider.verify(sad4, prefixed=True)  # kind and label default
    saider, sad8 = Saider.saidify(sad=sad4, code=MtrDex.Blake2b_256)
    assert saider.qb64 != said3
    assert saider.verify(sad8, prefixed=True)

    # verify gets kind from version string if provided when loading from dict
    vs = versify(version=Version, kind=Serials.mgpk, size=0)  # vaccuous size == 0
    assert vs == 'KERI10MGPK000000_'
    sad9 = dict(sad4)
    sad9['v'] = vs
    saider = Saider(sad=sad9)  # default code and label not default kind
    assert saider.code == code == MtrDex.Blake3_256
    said9 = saider.qb64
    assert said9 == 'EJyT3AEkPq3clvvZ2IZN_cU0kcbcDiAnNRULl_tTWzJo' != said3
    assert saider.verify(sad9, prefixed=False, versioned=False)
    assert not saider.verify(sad9, prefixed=True)
    assert not saider.verify(sad3, prefixed=False)
    assert not saider.verify(sad3, prefixed=True)
    saider, sad10 = Saider.saidify(sad=sad9)
    assert saider.qb64 == said9
    assert saider.verify(sad10, prefixed=True)

    # ignore some fields from SAID calculation
    sad = dict(
        d="",
        first="John",
        last="Doe",
        read=False
    )

    saider1 = Saider(sad=sad, ignore=["read"])
    assert saider1.qb64 == 'EBam6rzvfq0yF6eI7Czrg3dUVhqg2cwNkSoJvyHWPj3p'

    saider2, sad2 = Saider.saidify(sad=sad, ignore=["read"])
    assert saider2.qb64 == saider1.qb64
    assert sad2["d"] == saider2.qb64 == saider1.qb64
    assert sad2["read"] is False

    assert saider1.verify(sad=sad2, prefixed=True, ignore=["read"]) is True

    # Change the 'read' field that is ignored and make sure it still verifies
    sad2["read"] = True
    assert saider1.verify(sad=sad2, prefixed=True, ignore=["read"]) is True

    saider3 = Saider(sad=sad2, ignore=["read"])
    assert saider3.qb64 == saider2.qb64
    assert sad2["read"] is True

    """Done Test"""


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

    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'

    icp = dict(vs=Vstrings.json,
               pre='AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
               sn='0001',
               ilk='icp',
               dig='DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
               sith=1,
               keys=['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
               nxt='DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
               toad=0,
               wits=[],
               cnfg=[],
               )

    rot = dict(vs=Vstrings.json,
               pre='AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
               sn='0001',
               ilk='rot',
               dig='DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
               sith=1,
               keys=['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
               nxt='DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
               toad=0,
               cuts=[],
               adds=[],
               data=[],
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
    vs = versify(kind=Serials.json, size=0)
    assert vs == "KERI10JSON000000_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.keri
    assert kind == Serials.json
    assert version == Version
    assert size == 0

    vs = versify(kind=Serials.json, size=65)
    assert vs == "KERI10JSON000041_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.keri
    assert kind == Serials.json
    assert version == Version
    assert size == 65

    vs = versify(ident=Idents.acdc, kind=Serials.json, size=86)
    assert vs == "ACDC10JSON000056_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.acdc
    assert kind == Serials.json
    assert version == Version
    assert size == 86

    vs = versify(kind=Serials.mgpk, size=0)
    assert vs == "KERI10MGPK000000_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.keri
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 0

    vs = versify(kind=Serials.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.keri
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 65

    vs = versify(kind=Serials.cbor, size=0)
    assert vs == "KERI10CBOR000000_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.keri
    assert kind == Serials.cbor
    assert version == Version
    assert size == 0

    vs = versify(kind=Serials.cbor, size=65)
    assert vs == "KERI10CBOR000041_"
    assert len(vs) == VERFULLSIZE
    ident, kind, version, size = deversify(vs)
    assert ident == Idents.keri
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
              d="",
              i="ABCDEFG",
              s="0001",
              t="rot")
    _, e1 = coring.Saider.saidify(sad=e1)

    serder = Serder(ked=e1)
    assert serder.ked == e1
    assert serder.kind == Serials.json
    assert serder.version == Versionage(major=1, minor=0)
    assert serder.said == 'EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F'
    #'EgzrpOMEx_A-dvAruhmptnIbP2c55WZAd4fc1nGuyTwU'
    assert serder.saidb == b'EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F'
    assert serder.size == 111
    assert serder.verfers == []
    assert serder.raw == (b'{"v":"KERI10JSON00006f_","d":"EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F",'
                          b'"i":"ABCDEFG","s":"0001","t":"rot"}')
    assert serder.sn == 1
    assert serder.pre == "ABCDEFG"
    assert serder.preb == b"ABCDEFG"

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert e1s == ((b'{"v":"KERI10JSON00006f_","d":"EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F",'
                    b'"i":"ABCDEFG","s":"0001","t":"rot"}'))
    vs = versify(kind=Serials.json, size=len(e1s))  # use real length
    assert vs == 'KERI10JSON00006f_'
    e1["v"] = vs  # has real length
    pretty = serder.pretty()
    assert pretty == ('{\n'
                      ' "v": "KERI10JSON00006f_",\n'
                      ' "d": "EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F",\n'
                      ' "i": "ABCDEFG",\n'
                      ' "s": "0001",\n'
                      ' "t": "rot"\n'
                      '}')

    e1s = json.dumps(e1, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(ShortageError):  # test too short
        ident1, kind1, vers1, size1 = sniff(e1s[:VERFULLSIZE])

    ident1, kind1, vers1, size1 = sniff(e1s[:MINSNIFFSIZE])
    assert ident1 == Idents.keri
    assert kind1 == Serials.json
    assert size1 == 111

    ident1, kind1, vers1, size1 = sniff(e1s)
    assert ident1 == Idents.keri
    assert kind1 == Serials.json
    assert size1 == 111
    e1ss = e1s + b'extra attached at the end.'
    ked1, idnt1, knd1, vrs1, siz1 = serder._inhale(e1ss)
    assert ked1 == e1
    assert idnt1 == Idents.keri
    assert knd1 == kind1
    assert vrs1 == vers1
    assert siz1 == size1

    with pytest.raises(ShortageError):  # test too short
        ked1, knd1, vrs1, siz1 = serder._inhale(e1ss[:size1 - 1])

    raw1, idnt1, knd1, ked1, ver1 = serder._exhale(ked=e1)
    assert raw1 == e1s
    assert idnt1 == Idents.keri
    assert knd1 == kind1
    assert ked1 == e1
    assert vrs1 == vers1

    e2 = dict(e1)
    e2["v"] = Vstrings.mgpk
    e2s = msgpack.dumps(e2)
    assert e2s == (b'\x85\xa1v\xb1KERI10MGPK000000_\xa1d\xd9,EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH'
                   b'3NZxrsk8F\xa1i\xa7ABCDEFG\xa1s\xa40001\xa1t\xa3rot')
    vs = versify(kind=Serials.mgpk, size=len(e2s))  # use real length
    assert vs == 'KERI10MGPK00005c_'
    e2["v"] = vs  # has real length
    _, e2 = coring.Saider.saidify(sad=e2)
    e2s = msgpack.dumps(e2)

    with pytest.raises(ShortageError):  # test too short
        ident2, kind2, vers2, size2 = sniff(e2s[:VERFULLSIZE])

    ident2, kind2, vers2, size2 = sniff(e2s[:MINSNIFFSIZE])
    assert ident2 == Idents.keri
    assert kind2 == Serials.mgpk
    assert size2 == 92

    ident2, kind2, vers2, size2 = sniff(e2s)
    assert ident1 == Idents.keri
    assert kind2 == Serials.mgpk
    assert size2 == 92
    e2ss = e2s + b'extra attached  at the end.'
    ked2, idnt2, knd2, vrs2, siz2 = serder._inhale(e2ss)
    assert ked2 == e2
    assert idnt2 == Idents.keri
    assert knd2 == kind2
    assert vrs2 == vers2
    assert siz2 == size2

    with pytest.raises(ShortageError):  # test too short
        ked2, knd2, vrs2, siz2 = serder._inhale(e2ss[:size2 - 1])

    raw2, idnt2, knd2, ked2, ver2 = serder._exhale(ked=e2)
    assert raw2 == e2s
    assert idnt2 == Idents.keri
    assert knd2 == kind2
    assert ked2 == e2
    assert vrs2 == vers2

    e3 = dict(e1)
    e3["v"] = Vstrings.cbor
    e3s = cbor.dumps(e3)
    assert e3s == (b'\xa5avqKERI10CBOR000000_adx,EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8Faig'
                   b'ABCDEFGasd0001atcrot')
    vs = versify(kind=Serials.cbor, size=len(e3s))  # use real length
    assert vs == 'KERI10CBOR00005c_'
    e3["v"] = vs  # has real length
    _, e3 = coring.Saider.saidify(sad=e3)
    e3s = cbor.dumps(e3)

    with pytest.raises(ShortageError):  # test too short
        ident3, kind3, vers3, size3 = sniff(e3s[:VERFULLSIZE])

    ident3, kind3, vers3, size3 = sniff(e3s[:MINSNIFFSIZE])
    assert ident1 == Idents.keri
    assert kind3 == Serials.cbor
    assert size3 == 92

    ident3, kind3, vers3, size3 = sniff(e3s)
    assert ident3 == Idents.keri
    assert kind3 == Serials.cbor
    assert size3 == 92
    e3ss = e3s + b'extra attached  at the end.'
    ked3, idnt3, knd3, vrs3, siz3 = serder._inhale(e3ss)
    assert ked3 == e3
    assert idnt3 == Idents.keri
    assert knd3 == kind3
    assert vrs3 == vers3
    assert siz3 == size3

    with pytest.raises(ShortageError):  # test too short
        ked3, knd3, vrs3, siz3 = serder._inhale(e3ss[:size3 - 1])

    raw3, idnt3, knd3, ked3, ver3 = serder._exhale(ked=e3)
    assert raw3 == e3s
    assert idnt3 == Idents.keri
    assert knd3 == kind3
    assert ked3 == e3
    assert vrs3 == vers3

    e4 = dict(v=versify(ident=Idents.acdc, kind=Serials.json, size=0),
              d="",
              i="ABCDEFG",
              s="0001",
              t="rot")
    _, e4 = coring.Saider.saidify(sad=e4)
    print()
    print(e4)
    e4s = json.dumps(e4, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert e4s == (b'{"v":"ACDC10JSON00006f_","d":"EMFw6MEBmwWU28-7wK4SJ2kasSzVgLKkAM7iwoqJJ07Z",'
                   b'"i":"ABCDEFG","s":"0001","t":"rot"}')
    vs = versify(ident=Idents.acdc, kind=Serials.json, size=len(e4s))  # use real length
    assert vs == 'ACDC10JSON00006f_'
    e4["v"] = vs  # has real length
    serder = Sadder(ked=e4)
    pretty = serder.pretty()
    assert pretty == ('{\n'
                      ' "v": "ACDC10JSON00006f_",\n'
                      ' "d": "EMFw6MEBmwWU28-7wK4SJ2kasSzVgLKkAM7iwoqJJ07Z",\n'
                      ' "i": "ABCDEFG",\n'
                      ' "s": "0001",\n'
                      ' "t": "rot"\n'
                      '}')

    e4s = json.dumps(e4, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(ShortageError):  # test too short
        ident4, kind4, vers4, size4 = sniff(e4s[:VERFULLSIZE])

    ident4, kind4, vers4, size4 = sniff(e4s[:MINSNIFFSIZE])
    assert ident4 == Idents.acdc
    assert kind4 == Serials.json
    assert size4 == 111

    ident4, kind4, vers4, size4 = sniff(e4s)
    assert ident4 == Idents.acdc
    assert kind4 == Serials.json
    assert size4 == 111

    evt1 = Serder(raw=e1ss)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1
    assert evt1.sn == 1

    # test digest properties .diger and .dig
    assert evt1.saider.qb64 == evt1.said
    assert evt1.saider.code == MtrDex.Blake3_256
    assert len(evt1.saider.raw) == 32
    assert len(evt1.said) == 44
    assert len(evt1.said) == Matter.Sizes[MtrDex.Blake3_256].fs
    assert evt1.said == 'EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F'
    assert evt1.saider.verify(evt1.ked)

    evt1 = Serder(ked=ked1)
    assert evt1.kind == kind1
    assert evt1.raw == e1s
    assert evt1.ked == ked1
    assert evt1.size == size1
    assert evt1.raw == e1ss[:size1]
    assert evt1.version == vers1
    assert evt1.saider.code == MtrDex.Blake3_256

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
    ked1["v"] = Vstrings.mgpk
    _, ked1 = coring.Saider.saidify(sad=ked1)
    evt1 = Serder(ked=ked1, kind=Serials.mgpk)  # ked is json but kind mgpk
    assert evt1.kind == kind2
    assert evt1.raw == e2s
    assert evt1.ked == ked2
    assert evt1.size == size2
    assert evt1.raw == e2ss[:size2]
    assert evt1.version == vers1
    assert evt1.said == 'EMvr339cs3EH-WcXfLDGOi-rRjNQxK46PqvBcgdAgg8p'
    assert evt1.saider.verify(evt1.ked)

    #  round trip
    evt2 = Serder(raw=evt1.raw)
    assert evt2.kind == evt1.kind
    assert evt2.raw == evt1.raw
    assert evt2.ked == evt1.ked
    assert evt2.size == evt1.size
    assert evt2.version == vers2

    ked1["v"] = Vstrings.cbor
    _, ked1 = coring.Saider.saidify(sad=ked1)
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
    ident, knd, version, size = deversify(evt2.ked["v"])
    assert ident == Idents.keri
    assert knd == Serials.json

    #  Test diger code
    ked = {'v': "KERI10JSON00006a_",
           'd': 'HAg9_-rPd8oga-oyPghCEIlJZHKbYXcP86LQl0Yg2AvA',
           'i': 'ABCDEFG', 's': 1,
           't': 'rot'}
    raw = (
        b'{"v":"KERI10JSON00006a_","d":"HAg9_-rPd8oga-oyPghCEIlJZHKbYXcP86LQl0Yg2AvA","i":"ABCDEFG","s":1,"t":"rot"}')
    srdr = Serder(raw=raw, code=MtrDex.SHA3_256)
    assert srdr.kind == 'JSON'
    assert srdr.raw == raw
    assert srdr.ked == ked
    assert srdr.saider.code == MtrDex.SHA3_256

    #  Test compare
    ked = {'v': "KERI10JSON00006a_",
           'd': 'EADZ055vgh5utgSY3OOL1lW0m1pJ1W0Ia6-SVuGa0OqE',
           'i': 'ABCDEFG', 's': 1,
           't': 'rot'}
    raw = (
        b'{"v":"KERI10JSON00006a_","d":"EADZ055vgh5utgSY3OOL1lW0m1pJ1W0Ia6-SVuGa0OqE","i":"ABCDEFG","s":1,"t":"rot"}')
    srdr = Serder(raw=raw)
    assert srdr.kind == 'JSON'
    assert srdr.raw == raw
    assert srdr.ked == ked
    assert srdr.saider.code == MtrDex.Blake3_256

    # need tests will fully populated serder for icp rot dip drt
    #aids = generatePublics(salt=None, count=3, transferable=False)
    aids = ['BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI',
            'BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4',
            'BEejlxZytU7gjUwtgkmNKmBWiFPKSsXjk_uxzoun8dtK']


    pre0 = aids[0]
    wit0 = aids[1]
    wit1 = aids[2]
    srdr = eventing.incept(keys=[pre0], wits=[wit0, wit1])
    assert srdr.raw == (b'{"v":"KERI10JSON00015a_","t":"icp","d":"EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQK'
                        b'VXvg7oqd","i":"BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI","s":"0","kt":"1'
                        b'","k":["BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI"],"nt":"0","n":[],"bt":'
                        b'"2","b":["BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4","BEejlxZytU7gjUwtgkm'
                        b'NKmBWiFPKSsXjk_uxzoun8dtK"],"c":[],"a":[]}')
    # test for serder.verfers and serder.werfers
    assert srdr.pre == pre0
    assert srdr.sn == 0
    assert [verfer.qb64 for verfer in srdr.verfers] == [pre0]
    assert [werfer.qb64 for werfer in srdr.werfers] == [wit0, wit1]

    # test .said and .saidb properties
    ked = {
        "v": "KERI10JSON00011c_",
        "t": "rep",
        "d": "EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd",
        "dt": "2020-08-22T17:50:12.988921+00:00",
        "r": "logs/processor",
        "a":
            {
                "d": "EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd",
                "i": "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
                "name": "John Jones",
                "role": "Founder",
            }
    }
    srdr = Serder(ked=ked)
    assert srdr.said == 'EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd'
    assert srdr.saidb == b'EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd'

    # test tholder
    ked = dict(v="KERI10JSON000000_",  # version string
               t="icp",
               d="",
               i="BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt="1",  # hex string no leading zeros lowercase
               k=["BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4"],  # list of qb64
               n="",  # hash qual Base64
               bt="0",  # hex string no leading zeros lowercase
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    _, ked = coring.Saider.saidify(sad=ked)

    srdr = Serder(ked=ked)
    assert srdr.tholder.sith == "1"
    assert srdr.tholder.thold == 1
    assert srdr.sn == 0
    assert srdr.sner.num == srdr.sn

    # test validation in Serder.sn property
    ked["s"] = "-1"
    srdr = Serder(ked=ked)
    with pytest.raises(InvalidValueError):
        sn = srdr.sn

    #ked["s"] = "0" * 33
    #srdr = Serder(ked=ked)
    #with pytest.raises(InvalidValueError):
        #sn = srdr.sn

    ked["s"] = "15.34"
    srdr = Serder(ked=ked)
    with pytest.raises(InvalidValueError):
        sn = srdr.sn

    """Done Test """


def test_tholder():
    """
    Test Tholder signing threshold satisfier class
    """

    with pytest.raises(EmptyMaterialError):
        tholder = Tholder()

    limen = b'MAAL'

    tholder = Tholder(sith="b")
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 11
    assert tholder.limen == limen
    assert tholder.sith == "b"
    assert tholder.json == '"b"'
    assert tholder.num == 11
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))

    tholder = Tholder(sith=11)
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 11
    assert tholder.limen == limen
    assert tholder.sith == "b"
    assert tholder.json == '"b"'
    assert tholder.num == 11
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))

    tholder = Tholder(limen=limen)
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 11
    assert tholder.limen == limen
    assert tholder.sith == "b"
    assert tholder.json == '"b"'
    assert tholder.num == 11
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))

    tholder = Tholder(thold=11)
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 11
    assert tholder.limen == limen
    assert tholder.sith == "b"
    assert tholder.json == '"b"'
    assert tholder.num == 11
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))

    tholder = Tholder(sith=f'{15:x}')
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 15
    assert tholder.limen == b'MAAP'
    assert tholder.sith == "f"
    assert tholder.json == '"f"'
    assert tholder.num == 15
    assert not tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))

    tholder = Tholder(sith=2)
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 2
    assert tholder.limen == b'MAAC'  # b'MAAI'
    assert tholder.sith == "2"
    assert tholder.json == '"2"'
    assert tholder.num == 2
    assert tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=list(range(tholder.thold)))


    tholder = Tholder(sith=1)
    assert not tholder.weighted
    assert tholder.size == tholder.thold
    assert tholder.thold == 1
    assert tholder.limen == b'MAAB'  # b'MAAE'
    assert tholder.sith == "1"
    assert tholder.json == '"1"'
    assert tholder.num == 1
    assert tholder.satisfy(indices=[0])
    assert tholder.satisfy(indices=list(range(tholder.thold)))


    with pytest.raises(ValueError):  # not 0 <= w <= 1
        tholder = Tholder(sith=-1)

    tholder = Tholder(sith=2)  # single weight not weighted
    assert not tholder.weighted
    assert  tholder.thold == 2

    with pytest.raises(ValueError):  # json with int not str for given weight
        tholder = Tholder(sith='[1]')

    with pytest.raises(ValueError):  # json with int not str for given weight
        tholder = Tholder(sith='[2]')

    with pytest.raises(ValueError):  # json but not 0 <= w <= 1 for a given weight
        tholder = Tholder(sith='["2"]')

    with pytest.raises(ValueError):  # json but given weight evals to float
        tholder = Tholder(sith='["0.5", "0.5"]')

    with pytest.raises(ValueError):  # non int for unweighted
        tholder = Tholder(sith="1.0")

    with pytest.raises(ValueError):  # non int for unweighted
        tholder = Tholder(sith="0.5")

    with pytest.raises(ValueError):  # ratio of floats
        tholder = Tholder(sith="1.0/2.0")

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

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2"], [[], "1"]])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2", "3/2"]])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=["1/2", "1/2", "3/2"])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2", "2/1"]])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=["1/2", "1/2", "2/1"])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=["1/2", "1/2", "2"])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2", "2"]])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2"], "1"])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2"], 1])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=[["1/2", "1/2"], "1.0"])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=["1/2", "1/2", []])

    with pytest.raises(ValueError) as ex:
        tholder = Tholder(sith=["1/2", 0.5])

    tholder = Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4"])
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)]]
    assert tholder.limen == b'4AAFA1s2c1s2c1s4c1s4c1s4'
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4"]
    assert tholder.json == '["1/2", "1/2", "1/4", "1/4", "1/4"]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[0, 2, 4])
    assert tholder.satisfy(indices=[0, 1])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])

    tholder = Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4", "0"])
    assert tholder.weighted
    assert tholder.size == 6
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(0, 1)]]
    assert tholder.limen == b'6AAGAAA1s2c1s2c1s4c1s4c1s4c0'
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4", "0"]
    assert tholder.json == '["1/2", "1/2", "1/4", "1/4", "1/4", "0"]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[0, 2, 4])
    assert tholder.satisfy(indices=[0, 1])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1])
    assert not tholder.satisfy(indices=[0, 2, 5])
    assert not tholder.satisfy(indices=[2, 3, 4, 5])

    tholder = Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"]])
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)]]
    assert tholder.limen == b'4AAFA1s2c1s2c1s4c1s4c1s4'
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4"]
    assert tholder.json == '["1/2", "1/2", "1/4", "1/4", "1/4"]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[1, 2, 3])
    assert tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1, 4, 4])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])

    tholder = Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]])
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)],
                             [Fraction(1, 1), Fraction(1, 1)]]
    assert tholder.limen == b'4AAGA1s2c1s2c1s4c1s4c1s4a1c1'
    assert tholder.sith == [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
    assert tholder.json == '[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[1, 2, 3, 5])
    assert tholder.satisfy(indices=[0, 1, 6])
    assert not tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[5, 6])
    assert not tholder.satisfy(indices=[2, 3, 4])
    assert not tholder.satisfy(indices=[])

    # test json sith is string json expression
    tholder = Tholder(sith='[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]]')
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)],
                             [Fraction(1, 1), Fraction(1, 1)]]
    assert tholder.limen == b'4AAGA1s2c1s2c1s4c1s4c1s4a1c1'
    assert tholder.sith == [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
    assert tholder.json == '[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[1, 2, 3, 5])
    assert tholder.satisfy(indices=[0, 1, 6])
    assert not tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[5, 6])
    assert not tholder.satisfy(indices=[2, 3, 4])
    assert not tholder.satisfy(indices=[])

    # test json sith is string json expression
    tholder = Tholder(sith='[["1/2", "1/2", "1/4", "1/4", "1/4"]]')
    assert tholder.weighted
    assert tholder.size == 5
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)]]
    assert tholder.limen == b'4AAFA1s2c1s2c1s4c1s4c1s4'
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4"]
    assert tholder.json == '["1/2", "1/2", "1/4", "1/4", "1/4"]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[1, 2, 3])
    assert tholder.satisfy(indices=[0, 1, 2])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1, 4, 4])
    assert not tholder.satisfy(indices=[0, 2])
    assert not tholder.satisfy(indices=[2, 3, 4])

    # test json sith is string json expression
    tholder = Tholder(sith='["1/2", "1/2", "1/4", "1/4", "1/4", "0"]')
    assert tholder.weighted
    assert tholder.size == 6
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(0, 1)]]
    assert tholder.limen == b'6AAGAAA1s2c1s2c1s4c1s4c1s4c0'
    assert tholder.sith == ["1/2", "1/2", "1/4", "1/4", "1/4", "0"]
    assert tholder.json == '["1/2", "1/2", "1/4", "1/4", "1/4", "0"]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[0, 2, 4])
    assert tholder.satisfy(indices=[0, 1])
    assert tholder.satisfy(indices=[1, 3, 4])
    assert tholder.satisfy(indices=[0, 1, 2, 3, 4])
    assert tholder.satisfy(indices=[3, 2, 0])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1])
    assert not tholder.satisfy(indices=[0, 2, 5])
    assert not tholder.satisfy(indices=[2, 3, 4, 5])

    # bexter
    tholder = Tholder(limen=b'4AAGA1s2c1s2c1s4c1s4c1s4a1c1')
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)],
                             [Fraction(1, 1), Fraction(1, 1)]]
    assert tholder.limen == b'4AAGA1s2c1s2c1s4c1s4c1s4a1c1'
    assert tholder.sith == [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
    assert tholder.json == '[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[1, 2, 3, 5])
    assert tholder.satisfy(indices=[0, 1, 6])
    assert not tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[5, 6])
    assert not tholder.satisfy(indices=[2, 3, 4])
    assert not tholder.satisfy(indices=[])

    tholder = Tholder(thold=[[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)],
                             [Fraction(1, 1), Fraction(1, 1)]])
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[Fraction(1, 2),
                              Fraction(1, 2),
                              Fraction(1, 4),
                              Fraction(1, 4),
                              Fraction(1, 4)],
                             [Fraction(1, 1), Fraction(1, 1)]]
    assert tholder.limen == b'4AAGA1s2c1s2c1s4c1s4c1s4a1c1'
    assert tholder.sith == [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
    assert tholder.json == '[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[1, 2, 3, 5])
    assert tholder.satisfy(indices=[0, 1, 6])
    assert not tholder.satisfy(indices=[0, 1])
    assert not tholder.satisfy(indices=[5, 6])
    assert not tholder.satisfy(indices=[2, 3, 4])
    assert not tholder.satisfy(indices=[])



    raw = b"raw salt to test"

    #  create signers with verfers for keys
    signers = coring.Salter(raw=raw).signers(count=3, path="next", temp=True)

    keys = [signer.verfer.qb64 for signer in signers]
    assert keys == ['DKX2UxU85IcgiGdhfAQUfd2kYyVVf6CLUp7ejNBlCYyC',
                    'DDo75eoTr0yuYsgEwf5PGAZ7z9dsDb7jjt0ymdNGMKIy',
                    'DBnsqw0gaUXMBqFs_4A3wUjnOyiVEMCrY5tWwvRj-wwl']

    digers = [Diger(ser=signer.verfer.qb64b) for signer in signers]
    digs = [diger.qb64 for diger in digers]
    assert digs == ['EAfMsW8tCq-tdsBufV9kqgqvfuKVWNdf9mSpIXQ1Vjdf',
                    'EA76Pjxa03Bm62TjwO07C3_EVViO4Bgn5SLSr7FedoEG',
                    'EBnncARb7X0yWLOTBW9X387vakzaiAwF6DCFYdiIDob2']

    assert tholder.includes(keys, digs)

    bdigs = list(digs)
    del bdigs[0]
    assert not tholder.includes(keys, bdigs)

    bkeys = list(keys)
    del bkeys[1]
    assert tholder.includes(bkeys, digs)

    bkeys.append(keys[1])
    assert not tholder.includes(bkeys, digs)

    signer = Signer()
    # create something to sign and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
    index = 0
    siger = signer.sign(ser, index=index)
    digs = [Diger(ser=siger.verfer.qb64b).qb64]
    sigers = [siger]

    assert tholder.matches(sigers, digs) == [0]


    """ Done Test """


if __name__ == "__main__":
    #test_matter()
    #test_counter()
    #test_prodex()
    #test_indexer()
    #test_number()
    #test_siger()
    #test_signer()
    #test_nexter()
    test_tholder()
