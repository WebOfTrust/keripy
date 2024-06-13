# -*- encoding: utf-8 -*-
"""
tests.core.test_coring module

"""
from dataclasses import dataclass, asdict, astuple
import hashlib
import json
from base64 import urlsafe_b64decode as decodeB64
from base64 import urlsafe_b64encode as encodeB64
from fractions import Fraction
from builtins import OverflowError
from math import ceil
from collections import namedtuple

import blake3
import cbor2 as cbor
import msgpack
import pysodium
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions

from keri import kering
from keri.kering import (EmptyMaterialError, RawMaterialError, DerivationError,
                         ShortageError, InvalidCodeSizeError, InvalidVarIndexError,
                         InvalidValueError, DeserializeError, ValidationError,
                         InvalidVarRawSizeError, ConversionError,
                         SoftMaterialError, InvalidSoftError, InvalidCodeError)
from keri.kering import Version, Versionage, VersionError, Vrsn_1_0, Vrsn_2_0
from keri.kering import Protocols, Protocolage, Ilkage, Ilks, TraitDex

from keri.help import helping
from keri.help.helping import (sceil, intToB64, intToB64b, b64ToInt, codeB64ToB2, codeB2ToB64,
                              B64_CHARS, Reb64, nabSextets)

from keri import core
from keri.core import coring
from keri.core.coring import (Saids, Sadder, Tholder, Seqner, NumDex, Number,
                              Dater, Bexter, Texter,
                              TagDex, PadTagDex, Tagger, Ilker, Traitor,
                              Verser, Versage, )
from keri.core.coring import Serialage, Serials
from keri.core.coring import (Sizage, MtrDex, Matter, CtrDex, Counter)
from keri.core.coring import (Verfer, Cigar, Saider, DigDex,
                              Diger, Prefixer,)
from keri.core.coring import versify, deversify, Rever, MAXVERFULLSPAN

from keri.core.indexing import (Siger, Xizage, IdrDex, IdxSigDex,
                                IdxCrtSigDex, IdxBthSigDex, Indexer)


from keri.core.coring import MapHood, MapDom



def test_mapdom():
    """Test MapDom base dataclass"""

    @dataclass
    class TestMapDom(MapHood):
        """

        """
        xray: str = 'X'
        yankee: str = 'Y'
        zulu: str = 'Z'

        def __iter__(self):  # so value in dataclass not key in dataclass
            return iter(astuple(self))

    tmd = TestMapDom()

    assert 'X' in tmd
    assert 'Y' in tmd
    assert 'Z' in tmd

    assert tmd["xray"] == tmd.xray == 'X'
    assert tmd["yankee"] == tmd.yankee == 'Y'
    assert tmd["zulu"] == tmd.zulu == 'Z'


    tmd["xray"] = "x"
    assert tmd.xray == tmd["xray"] == "x"

    tmd["yankee"] = "y"
    assert tmd.yankee == tmd["yankee"] == "y"

    tmd["zulu"] = "z"
    assert tmd.zulu == tmd["zulu"] == "z"

    delattr(tmd, "zulu")  # deletes instance attribute
    assert tmd.zulu == "Z"  # so returns so class attribute default  value

    tmd["zulu"] = "z"
    assert tmd["zulu"] == "z"

    del tmd["zulu"]  # deletes instance attribute
    assert tmd.zulu == "Z"  # so returns so class attribute default  value

    # create dynamic attribute
    with pytest.raises(AttributeError):
        assert tmd.alpha == None

    with pytest.raises(IndexError):
        assert tmd["alpha"] == None

    tmd["alpha"] = "A"  # add new attribute but without default
    assert tmd.alpha == tmd["alpha"] == "A"

    del tmd["alpha"]  # deletes instance attribute and no class default

    with pytest.raises(AttributeError):
        assert tmd.alpha == "A"

    with pytest.raises(IndexError):
        assert tmd["alpha"] == "A"

    # another dynamic attribut but delattr instead of del
    with pytest.raises(AttributeError):
        assert tmd.beta == None

    with pytest.raises(IndexError):
        assert tmd["beta"] == None

    tmd["beta"] = "B"  # add new attribute but without default
    assert tmd.beta == tmd["beta"] == "B"

    delattr(tmd, "beta")  # deletes instance attribute and no class default

    with pytest.raises(AttributeError):
        assert tmd.beta == "B"

    with pytest.raises(IndexError):
        assert tmd["beta"] == "B"

    # attempt to delete non-existing
    with pytest.raises(IndexError):
        del tmd["gamma"]

    with pytest.raises(AttributeError):
        delattr(tmd, "gamma")

    """End Test"""


def test_mapcodex():
    """Test MapCodex base dataclass frozen"""


    @dataclass(frozen=True)
    class TestMapCodex(MapDom):
        """

        """
        xray: str = 'X'
        yankee: str = 'Y'
        zulu: str = 'Z'

        def __iter__(self):  # so value in dataclass not key in dataclass
            return iter(astuple(self))

    tmc = TestMapCodex()

    assert 'X' in tmc
    assert 'Y' in tmc
    assert 'Z' in tmc

    assert tmc.xray == tmc["xray"] == 'X'
    assert tmc.yankee == tmc["yankee"] == 'Y'
    assert tmc.zulu == tmc["zulu"] == 'Z'

    with pytest.raises(IndexError):
        tmc["xray"] = "x"

    with pytest.raises(AttributeError):
        tmc.xray = "x"

    with pytest.raises(IndexError):
        del tmc["xray"]

    with pytest.raises(AttributeError):
        delattr(tmc, "xray")

    with pytest.raises(IndexError):
        tmc["alpha"] = "A"

    with pytest.raises(AttributeError):
        tmc.alpha = "A"

    # attempt to delete non-existing
    with pytest.raises(IndexError):
        del tmc["gamma"]

    with pytest.raises(AttributeError):
        delattr(tmc, "gamma")

    """End Test"""


def test_matter_class():
    """
    Test Matter class attributes
    """

    assert Matter.Codes == \
    {
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
        'ECDSA_256r1_Seed': 'Q',
        'Tall': 'R',
        'Large': 'S',
        'Great': 'T',
        'Vast': 'U',
        'Label1': 'V',
        'Label2': 'W',
        'Tag3': 'X',
        'Tag7': 'Y',
        'Blind': 'Z',
        'Salt_128': '0A',
        'Ed25519_Sig': '0B',
        'ECDSA_256k1_Sig': '0C',
        'Blake3_512': '0D',
        'Blake2b_512': '0E',
        'SHA3_512': '0F',
        'SHA2_512': '0G',
        'Long': '0H',
        'ECDSA_256r1_Sig': '0I',
        'Tag1': '0J',
        'Tag2': '0K',
        'Tag5': '0L',
        'Tag6': '0M',
        'Tag9': '0N',
        'Tag10': '0O',
        'ECDSA_256k1N': '1AAA',
        'ECDSA_256k1': '1AAB',
        'Ed448N': '1AAC',
        'Ed448': '1AAD',
        'Ed448_Sig': '1AAE',
        'Tag4': '1AAF',
        'DateTime': '1AAG',
        'X25519_Cipher_Salt': '1AAH',
        'ECDSA_256r1N': '1AAI',
        'ECDSA_256r1': '1AAJ',
        'Null': '1AAK',
        'No': '1AAL',
        'Yes': '1AAM',
        'Tag8': '1AAN',
        'TBD0S': '1__-',
        'TBD0': '1___',
        'TBD1S': '2__-',
        'TBD1': '2___',
        'TBD2S': '3__-',
        'TBD2': '3___',
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
        'X25519_Cipher_L0': '4C',
        'X25519_Cipher_L1': '5C',
        'X25519_Cipher_L2': '6C',
        'X25519_Cipher_Big_L0': '7AAC',
        'X25519_Cipher_Big_L1': '8AAC',
        'X25519_Cipher_Big_L2': '9AAC',
        'X25519_Cipher_QB64_L0': '4D',
        'X25519_Cipher_QB64_L1': '5D',
        'X25519_Cipher_QB64_L2': '6D',
        'X25519_Cipher_QB64_Big_L0': '7AAD',
        'X25519_Cipher_QB64_Big_L1': '8AAD',
        'X25519_Cipher_QB64_Big_L2': '9AAD',
        'X25519_Cipher_QB2_L0': '4E',
        'X25519_Cipher_QB2_L1': '5E',
        'X25519_Cipher_QB2_L2': '6E',
        'X25519_Cipher_QB2_Big_L0': '7AAE',
        'X25519_Cipher_QB2_Big_L1': '8AAE',
        'X25519_Cipher_QB2_Big_L2': '9AAE'
    }

    assert Matter.Names == \
    {
        'A': 'Ed25519_Seed',
        'B': 'Ed25519N',
        'C': 'X25519',
        'D': 'Ed25519',
        'E': 'Blake3_256',
        'F': 'Blake2b_256',
        'G': 'Blake2s_256',
        'H': 'SHA3_256',
        'I': 'SHA2_256',
        'J': 'ECDSA_256k1_Seed',
        'K': 'Ed448_Seed',
        'L': 'X448',
        'M': 'Short',
        'N': 'Big',
        'O': 'X25519_Private',
        'P': 'X25519_Cipher_Seed',
        'Q': 'ECDSA_256r1_Seed',
        'R': 'Tall',
        'S': 'Large',
        'T': 'Great',
        'U': 'Vast',
        'V': 'Label1',
        'W': 'Label2',
        'X': 'Tag3',
        'Y': 'Tag7',
        'Z': 'Blind',
        '0A': 'Salt_128',
        '0B': 'Ed25519_Sig',
        '0C': 'ECDSA_256k1_Sig',
        '0D': 'Blake3_512',
        '0E': 'Blake2b_512',
        '0F': 'SHA3_512',
        '0G': 'SHA2_512',
        '0H': 'Long',
        '0I': 'ECDSA_256r1_Sig',
        '0J': 'Tag1',
        '0K': 'Tag2',
        '0L': 'Tag5',
        '0M': 'Tag6',
        '0N': 'Tag9',
        '0O': 'Tag10',
        '1AAA': 'ECDSA_256k1N',
        '1AAB': 'ECDSA_256k1',
        '1AAC': 'Ed448N',
        '1AAD': 'Ed448',
        '1AAE': 'Ed448_Sig',
        '1AAF': 'Tag4',
        '1AAG': 'DateTime',
        '1AAH': 'X25519_Cipher_Salt',
        '1AAI': 'ECDSA_256r1N',
        '1AAJ': 'ECDSA_256r1',
        '1AAK': 'Null',
        '1AAL': 'No',
        '1AAM': 'Yes',
        '1AAN': 'Tag8',
        '1__-': 'TBD0S',
        '1___': 'TBD0',
        '2__-': 'TBD1S',
        '2___': 'TBD1',
        '3__-': 'TBD2S',
        '3___': 'TBD2',
        '4A': 'StrB64_L0',
        '5A': 'StrB64_L1',
        '6A': 'StrB64_L2',
        '7AAA': 'StrB64_Big_L0',
        '8AAA': 'StrB64_Big_L1',
        '9AAA': 'StrB64_Big_L2',
        '4B': 'Bytes_L0',
        '5B': 'Bytes_L1',
        '6B': 'Bytes_L2',
        '7AAB': 'Bytes_Big_L0',
        '8AAB': 'Bytes_Big_L1',
        '9AAB': 'Bytes_Big_L2',
        '4C': 'X25519_Cipher_L0',
        '5C': 'X25519_Cipher_L1',
        '6C': 'X25519_Cipher_L2',
        '7AAC': 'X25519_Cipher_Big_L0',
        '8AAC': 'X25519_Cipher_Big_L1',
        '9AAC': 'X25519_Cipher_Big_L2',
        '4D': 'X25519_Cipher_QB64_L0',
        '5D': 'X25519_Cipher_QB64_L1',
        '6D': 'X25519_Cipher_QB64_L2',
        '7AAD': 'X25519_Cipher_QB64_Big_L0',
        '8AAD': 'X25519_Cipher_QB64_Big_L1',
        '9AAD': 'X25519_Cipher_QB64_Big_L2',
        '4E': 'X25519_Cipher_QB2_L0',
        '5E': 'X25519_Cipher_QB2_L1',
        '6E': 'X25519_Cipher_QB2_L2',
        '7AAE': 'X25519_Cipher_QB2_Big_L0',
        '8AAE': 'X25519_Cipher_QB2_Big_L1',
        '9AAE': 'X25519_Cipher_QB2_Big_L2'
    }


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
    assert Matter.Sizes == \
    {
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
        'Q': Sizage(hs=1, ss=0, fs=44, ls=0),
        'R': Sizage(hs=1, ss=0, fs=8, ls=0),
        'S': Sizage(hs=1, ss=0, fs=16, ls=0),
        'T': Sizage(hs=1, ss=0, fs=20, ls=0),
        'U': Sizage(hs=1, ss=0, fs=24, ls=0),
        'V': Sizage(hs=1, ss=0, fs=4, ls=1),
        'W': Sizage(hs=1, ss=0, fs=4, ls=0),
        'X': Sizage(hs=1, ss=3, fs=4, ls=0),
        'Y': Sizage(hs=1, ss=7, fs=8, ls=0),
        'Z': Sizage(hs=1, ss=0, fs=44, ls=0),
        '0A': Sizage(hs=2, ss=0, fs=24, ls=0),
        '0B': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0C': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0D': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0E': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0F': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0G': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0H': Sizage(hs=2, ss=0, fs=8, ls=0),
        '0I': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0J': Sizage(hs=2, ss=2, fs=4, ls=0),
        '0K': Sizage(hs=2, ss=2, fs=4, ls=0),
        '0L': Sizage(hs=2, ss=6, fs=8, ls=0),
        '0M': Sizage(hs=2, ss=6, fs=8, ls=0),
        '0N': Sizage(hs=2, ss=10, fs=12, ls=0),
        '0O': Sizage(hs=2, ss=10, fs=12, ls=0),
        '1AAA': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAB': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAC': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAD': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAE': Sizage(hs=4, ss=0, fs=56, ls=0),
        '1AAF': Sizage(hs=4, ss=4, fs=8, ls=0),
        '1AAG': Sizage(hs=4, ss=0, fs=36, ls=0),
        '1AAH': Sizage(hs=4, ss=0, fs=100, ls=0),
        '1AAI': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAJ': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAK': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAL': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAM': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAN': Sizage(hs=4, ss=8, fs=12, ls=0),
        '1__-': Sizage(hs=4, ss=2, fs=12, ls=0),
        '1___': Sizage(hs=4, ss=0, fs=8, ls=0),
        '2__-': Sizage(hs=4, ss=2, fs=12, ls=1),
        '2___': Sizage(hs=4, ss=0, fs=8, ls=1),
        '3__-': Sizage(hs=4, ss=2, fs=12, ls=2),
        '3___': Sizage(hs=4, ss=0, fs=8, ls=2),
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
        '4C': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5C': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6C': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAC': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAC': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAC': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4D': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5D': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6D': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAD': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAD': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAD': Sizage(hs=4, ss=4, fs=None, ls=2),
        '4E': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5E': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6E': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAE': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAE': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAE': Sizage(hs=4, ss=4, fs=None, ls=2)
    }


    assert Matter.Sizes['A'].hs == 1  # hard size
    assert Matter.Sizes['A'].ss == 0  # soft size
    assert Matter.Sizes['A'].fs == 44  # full size
    assert Matter.Sizes['A'].ls == 0  # lead size


    #  verify all Codes
    for code, val in Matter.Sizes.items():  # hard code
        hs = val.hs
        ss = val.ss
        fs = val.fs
        ls = val.ls
        cs = hs + ss

        assert (isinstance(hs, int) and isinstance(ss, int) and
                isinstance(ls, int))
        assert hs > 0 and ss >= 0 and ls in (0, 1, 2)
        assert len(code) == hs

        if fs is None:  # variable sized
            assert ss > 0 and not (cs % 4)  # full code is 24 bit aligned
            # assumes that Matter methods also ensure (ls + rs) % 3 == 0 i.e.
            # variable raw with lead is 24 bit aligned, where rs is raw size.
            assert code[0] in coring.SmallVrzDex or code[0] in coring.LargeVrzDex

            if code[0] in coring.SmallVrzDex:  # small variable sized code
                assert hs == 2 and ss == 2 and fs is None
                assert code[0] == astuple(coring.SmallVrzDex)[ls]
                if code[0] in '4':
                    assert ls == 0
                elif code[0] in '5':
                    assert ls == 1
                elif code[0] in '6':
                    assert ls == 2
                else:
                    assert False

            elif code[0] in coring.LargeVrzDex: # large veriable sized code
                assert val.hs == 4 and val.ss == 4 and val.fs is None
                assert code[0] == astuple(coring.LargeVrzDex)[ls]
                if code[0] in '7':
                    assert ls == 0
                elif code[0] in '8':
                    assert ls == 1
                elif code[0] in '9':
                    assert ls == 2
                else:
                    assert False

            else:
                assert False

        else:  # fixed size
            assert not (code[0] in coring.SmallVrzDex or code[0] in coring.LargeVrzDex)
            assert isinstance(fs, int) and fs > 0 and not fs % 4
            assert fs >= cs
            assert cs % 4 != 3  # prevent ambiguous conversion
            if ss > 0 and fs == cs:  # special soft value with raw empty
                assert ls == 0  # no lead
                assert Matter._rawSize(code) == 0

            # verify correct sizes given raw size. Assumes properties above
            rs = ((fs - cs) * 3 // 4) - ls  # raw size bytes sans lead
            assert sceil((rs + ls) * 4 / 3) + cs == fs  # sextets add up
            ps = (3 - ((rs + ls) % 3)) % 3  # net pad size given raw with lead
            assert ps == (cs % 4)  # ensure correct midpad zero bits for cs

            if code[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
                assert len(code) == 1
            elif code[0] in '0':
                assert len(code) == 2
            elif code[0] in '1':
                assert len(code) == 4 and ls == 0
            elif code[0] in '2':
                assert len(code) == 4 and ls == 1
            elif code[0] in '3':
                assert len(code) == 4 and ls == 2
            else:
                assert code[0] not in '456789-_'  # count or op code


    # Test .Hards
    # verify first hs Sizes matches hs in Codes for same first char
    for ckey in Matter.Sizes.keys():
        assert Matter.Hards[ckey[0]] == Matter.Sizes[ckey].hs

    # Test .Bards
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Matter.Hards.items():
        ckey = codeB64ToB2(skey)
        assert Matter.Bards[ckey] == sval

    assert Matter._rawSize(MtrDex.Ed25519) == 32
    assert Matter._leadSize(MtrDex.Ed25519) == 0
    assert not Matter._special(MtrDex.Ed25519)
    assert Matter._special(MtrDex.Tag3)



def test_matter():
    """
    Test Matter instances
    """


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
    assert matter.code == MtrDex.Ed25519N == matter.hard
    assert matter.name == 'Ed25519N'
    assert matter.soft == ""
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
    assert matter.prefixive == True
    assert not matter.special
    assert matter.composable


    # test round trip
    assert matter.qb64 == encodeB64(matter.qb2).decode("utf-8")
    assert matter.qb2 == decodeB64(matter.qb64.encode("utf-8"))
    assert matter.composable

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
    with pytest.raises(ConversionError) as ex:
        matter = Matter(qb64=badprefix1)
    #assert str(ex.value) == "Non zeroed prepad bits = 110000 in b'_'."
    assert str(ex.value) == 'Nonzero midpad bytes=0x03.'

    # test non-zero pad bits in qb64 init ps == 2
    badprefix2 = '0A_wMTIzNDU2Nzg5YWJjZGVm'
    with pytest.raises(ConversionError) as ex:
        matter = Matter(qb64=badprefix2)
    #assert str(ex.value) == "Non zeroed prepad bits = 111100 in b'_'."
    assert str(ex.value) == 'Nonzero midpad bytes=0x000f.'

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
    with pytest.raises(ConversionError) as ex:
        matter = Matter(qb2=badprebin1)
    #assert str(ex.value) == 'Non zeroed pad bits = 00000011 in 0x07.'
    assert str(ex.value) == 'Nonzero code mid pad bits=0b11.'

    # test non-zero pad bits in qb2 init ps ==2
    badprebin2 = decodeB64(badprefix2)  # b'\xd0\x0f\xf0123456789abcdef'
    with pytest.raises(ConversionError) as ex:
        matter = Matter(qb2=badprebin2)
    #assert str(ex.value) == 'Non zeroed pad bits = 00001111 in 0x0f.'
    assert str(ex.value) == 'Nonzero code mid pad bits=0b1111.'


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
    assert matter.prefixive == True

    # test nongreedy prefixb on full identifier
    both = prefixb + b":mystuff/mypath/toresource?query=what#fragment"
    matter = Matter(qb64b=both)
    assert matter.code == MtrDex.Ed25519N
    assert matter.raw == verkey
    assert matter.qb64 == prefix
    assert matter.qb2 == prebin
    assert matter.transferable == False
    assert matter.digestive == False
    assert matter.prefixive == True

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
    assert matter.prefixive == True

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
    assert matter.prefixive == True
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
    assert matter.prefixive == True
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
    assert matter.prefixive == True
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
    assert matter.prefixive == True
    assert ims == extra  # stripped not include extra

    # test fixed size with leader 0
    # TBD0 = '1___'  # Testing purposes only fixed with lead size 0

    code = MtrDex.TBD0  # '1___'
    assert Matter._rawSize(code) == 3
    assert Matter._leadSize(code) == 0
    raw = b'abc'
    qb64 = '1___YWJj'  #
    qb2 = decodeB64(qb64)
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
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

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
    assert matter.prefixive == False

    # Can't have bad pad because cs % 4 == 0
    # Can't habe bad lead because ls ==0

    # test fix sized with leader 1
    # TBD1 = '2___'  # Testing purposes only fixed with lead size 1

    code = MtrDex.TBD1  # '2___'
    assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 1
    raw = b'ab'
    qb64 = '2___AGFi'  # '2___' + encodeB64(b'\x00ab').decode("utf-8")
    qb2 = decodeB64(qb64)
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.name == 'TBD1'
    assert matter.both == code
    assert matter.size == None
    assert matter.fullSize == 8
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

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
    assert matter.prefixive == False

    # test with bad pad or lead
    badqb64 = '2____2Fi'  # '2___' + encodeB64(b'\xffab').decode("utf-8")
    badqb2 = decodeB64(badqb64)  # b'\xd8\x00\x00\xffab'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb64=badqb64)
    #assert str(ex.value) ==  'Non zeroed lead byte = 0xff.'
    assert str(ex.value) == 'Nonzero midpad bytes=0xff.'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb2=badqb2)
    #assert str(ex.value) == 'Non zeroed lead byte = 0xff.'
    assert str(ex.value) == 'Nonzero lead midpad bytes=0xff.'


    # test fix sized with leader 2
    # TBD2 = '3___'  # Testing purposes only of fixed with lead size 2
    code = MtrDex.TBD2  # '3AAA'
    assert Matter._rawSize(code) == 1
    assert Matter._leadSize(code) == 2
    raw = b'z'
    qb64 = '3___AAB6'
    qb2 = decodeB64(qb64)
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
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

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
    assert matter.prefixive == False

    # test with bad pad or lead
    badqb64 = '3_____96'  # '3AAA' + encodeB64(b'\xff\xffz').decode("utf-8")
    badqb2 = decodeB64(badqb64)  #b'\xdc\x00\x00\xff\xffz'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb64=badqb64)
    #assert str(ex.value) ==  'Non zeroed lead bytes = 0xffff.'
    assert str(ex.value) == 'Nonzero midpad bytes=0xffff.'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb2=badqb2)
    #assert str(ex.value) == 'Non zeroed lead bytes = 0xffff.'
    assert str(ex.value) == 'Nonzero lead midpad bytes=0xffff.'

    # test variable sized with leader 1
    code = MtrDex.Bytes_L1
    with pytest.raises(InvalidCodeSizeError):
        assert Matter._rawSize(code) == 2
    assert Matter._leadSize(code) == 1
    raw = b'abcde'  # 5 bytes two triplets with lead 1
    both = '5BAC'  # full code both hard and soft parts two quadlets/triplets
    soft = 'AC'
    qb64 = '5BACAGFiY2Rl'
    qb2 = b'\xe4\x10\x02\x00abcde'
    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code == matter.hard
    assert matter.size == 2  # quadlets
    assert matter.soft == soft
    assert matter.both == both
    assert matter.fullSize == 12  # chars
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.transferable is True
    assert matter.digestive is False
    assert matter.prefixive == False

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
    assert matter.prefixive == False

    # test strip
    matter = Matter(qb2=bytearray(qb2), strip=True)
    assert matter.code == code
    assert matter.raw == raw

    # test with bad lead 1
    # 5 bytes with lead 1 = two triplets = b'\xffabcde'
    badqb64 = '5BAC_2FiY2Rl'  # '5BAC' + encodeB64(b'\xffabcde').decode("utf-8")
    badqb2 = decodeB64(badqb64)  # b'\xe4\x10\x02\xffabcde'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb64=badqb64)
    #assert str(ex.value) ==  'Non zeroed lead byte = 0xff.'
    assert str(ex.value) == 'Nonzero midpad bytes=0xff.'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb2=badqb2)
    #assert str(ex.value) == 'Non zeroed lead byte = 0xff.'
    assert str(ex.value) == 'Nonzero lead midpad bytes=0xff.'

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

    # test with bad lead 2
    # 4 bytes with lead 2 = two triplets = b'\xff\xffabcd'
    badqb64 = '6BAC__9hYmNk'  # '5BAC' + encodeB64(b'\xff\xffabcd').decode("utf-8")
    badqb2 = decodeB64(badqb64)  # b'\xe8\x10\x02\xff\xffabcd'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb64=badqb64)
    #assert str(ex.value) ==  'Non zeroed lead bytes = 0xffff.'
    assert str(ex.value) == 'Nonzero midpad bytes=0xffff.'

    with pytest.raises(ConversionError) as  ex:
        matter = Matter(qb2=badqb2)
    #assert str(ex.value) == 'Non zeroed lead bytes = 0xffff.'
    assert str(ex.value) == 'Nonzero lead midpad bytes=0xffff.'

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

    matter = Matter(qb64b=qsig64b)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False

    matter = Matter(qb64=qsig64)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False

    matter = Matter(qb2=qsigB2)
    assert matter.raw == sig
    assert matter.code == MtrDex.Ed25519_Sig
    assert matter.qb64 == qsig64
    assert matter.qb64b == qsig64b
    assert matter.qb2 == qsigB2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

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
    assert matter.prefixive == False

    # test Label1
    code = MtrDex.Label1
    raw = b'*'
    qb64 = 'VAAq'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)

    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    # test Label2
    code = MtrDex.Label2
    raw = b'@&'
    qb64 = 'WEAm'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)

    matter = Matter(raw=raw, code=code)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    matter = Matter(qb64b=qb64b)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    matter = Matter(qb64=qb64)
    assert matter.raw == raw
    assert matter.code == code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable

    matter = Matter(qb2=qb2)
    assert matter.raw == raw
    assert matter.code ==code
    assert matter.qb64 == qb64
    assert matter.qb64b == qb64b
    assert matter.qb2 == qb2
    assert matter.transferable == True
    assert matter.digestive == False
    assert matter.prefixive == False
    assert not matter.special
    assert matter.composable


    """ Done Test """

def test_matter_special():
    """
    Test Matter instances using code with special soft values
    """
    # test Tag3
    code = MtrDex.Tag3
    soft = 'icp'
    qb64 = 'Xicp'
    qb2 = b"^')"
    raw = b''

    matter = Matter(code=code, soft=soft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    code = matter.code
    soft = matter.soft
    qb2 = matter.qb2
    qb64 = matter.qb64

    matter = Matter(qb2=qb2)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb64=qb64)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # Test corner conditions
    # Empty raw
    matter = Matter(raw=b'', code=code, soft=soft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    #non empty raw ignored since code special, forces empty raw
    badraw = b'abcdefg'
    matter = Matter(raw=badraw, code=code, soft=soft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    #raw None
    matter = Matter(code=code, soft=soft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # soft extra chars ignored
    bigsoft = 'icprot'
    matter = Matter(code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # soft bytes not str
    bigsoft = b'icprot'
    matter = Matter(code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # soft too small
    weesoft = 'ic'
    with pytest.raises(SoftMaterialError):
        matter = Matter(code=code, soft=weesoft)

    # soft not B64 chars
    badsoft = b'#@$%^&*!'
    with pytest.raises(InvalidSoftError):
        matter = Matter(code=code, soft=badsoft)

    #non empty raw and badsoft
    badraw = b'abcdefg'
    badsoft = b'#@$%^&*!'
    with pytest.raises(InvalidSoftError):
        matter = Matter(raw=badraw, code=code, soft=badsoft)

    # soft but not special code
    numraw = b'\xf7\x7f'
    matter = Matter(raw=numraw, code=MtrDex.Short, soft=soft)
    assert matter.code == matter.hard == MtrDex.Short
    assert matter.soft == ''
    assert matter.raw == numraw
    assert not matter.special
    assert matter.composable

    # Test TBD0S  '1__-'
    # soft special but valid non-empty raw as part of primitive
    code = MtrDex.TBD0S  # sizes '1__-': Sizage(hs=4, ss=2, fs=12, ls=0),
    rs = Matter._rawSize(code)  # raw size
    soft = 'TG'
    qb64 = '1__-TGB1dnd4'
    qb2 = b'\xd7\xff\xfeL`uvwx'
    raw = b'uvwx'

    assert rs == 4

    bigsoft = 'TGIF'
    extraw = b'uvwxyz'

    matter = Matter(raw=extraw, code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb2=qb2)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb64=qb64)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # Same as above but raw all zeros

    qb64 = '1__-TGAAAAAA'
    qb2 = b'\xd7\xff\xfeL`\x00\x00\x00\x00'
    raw = b'\x00\x00\x00\x00'

    assert rs == 4

    bigsoft = 'TGIF'
    extraw = bytearray([0] * 7)

    matter = Matter(raw=extraw, code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # Test TBD1S  '2__-'
    # soft special but valid non-empty raw as part of primitive
    code = MtrDex.TBD1S  # sizes '2__-': Sizage(hs=4, ss=2, fs=12, ls=1),
    rs = Matter._rawSize(code)  # raw size
    soft = 'TG'
    qb64 = '2__-TGAAdXZ3'  # see lead byte
    qb2 = b'\xdb\xff\xfeL`\x00uvw'
    raw = b'uvw'

    assert rs == 3

    bigsoft = 'TGIF'
    extraw = b'uvwxyz'

    matter = Matter(raw=extraw, code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb2=qb2)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb64=qb64)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # Same as above but raw all zeros

    qb64 = '2__-TGAAAAAA'
    qb2 = b'\xdb\xff\xfeL`\x00\x00\x00\x00'
    raw = b'\x00\x00\x00'

    assert rs == 3

    bigsoft = 'TGIF'
    extraw = bytearray([0] * 7)

    matter = Matter(raw=extraw, code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # Test TBD2S  '3__-'
    # soft special but valid non-empty raw as part of primitive
    code = MtrDex.TBD2S  # sizes '2__-': Sizage(hs=4, ss=2, fs=12, ls=1),
    rs = Matter._rawSize(code)  # raw size
    soft = 'TG'
    qb64 = '3__-TGAAAHV2'  # see lead byte
    qb2 = b'\xdf\xff\xfeL`\x00\x00uv'
    raw = b'uv'

    assert rs == 2

    bigsoft = 'TGIF'
    extraw = b'uvwxyz'

    matter = Matter(raw=extraw, code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb2=qb2)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    matter = Matter(qb64=qb64)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable

    # Same as above but raw all zeros

    qb64 = '3__-TGAAAAAA'
    qb2 = b'\xdf\xff\xfeL`\x00\x00\x00\x00'
    raw = b'\x00\x00'

    assert rs == 2

    bigsoft = 'TGIF'
    extraw = bytearray([0] * 7)

    matter = Matter(raw=extraw, code=code, soft=bigsoft)
    assert matter.code == matter.hard == code
    assert matter.soft == soft
    assert matter.raw == raw
    assert matter.qb64 == qb64
    assert matter.qb2 == qb2
    assert matter.special
    assert matter.composable


    """ Done Test """


def test_counter():
    """
    Test Counter class
    """
    assert asdict(CtrDex) == {
        'ControllerIdxSigs': '-A',
        'WitnessIdxSigs': '-B',
        'NonTransReceiptCouples': '-C',
        'TransReceiptQuadruples': '-D',
        'FirstSeenReplayCouples': '-E',
        'TransIdxSigGroups': '-F',
        'SealSourceCouples': '-G',
        'TransLastIdxSigGroups': '-H',
        'SealSourceTriples': '-I',
        'SadPathSigGroups': '-J',
        'RootSadPathSigGroups': '-K',
        'PathedMaterialGroup': '-L',
        'BigPathedMaterialGroup': '-0L',
        'AttachmentGroup': '-V',
        'ESSRPayloadGroup': '-Z',
        'BigAttachmentGroup': '-0V',
        'KERIACDCGenusVersion': '--AAA',
    }


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
        '-0L': Sizage(hs=3, ss=5, fs=8, ls=0),
        '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-Z': Sizage(hs=2, ss=2, fs=4, ls=0),
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

    # test with big codes index=1024000
    count = 1024000
    qsc = CtrDex.BigAttachmentGroup + intToB64(count, l=5)
    assert qsc == '-0VAD6AA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigAttachmentGroup, count=count)
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.BigAttachmentGroup
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

    # Test limits of PathedMaterialGroup
    count = 255
    qsc = CtrDex.PathedMaterialGroup + intToB64(count, l=2)
    assert qsc == '-LD_'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.PathedMaterialGroup, count=count)
    assert counter.code == CtrDex.PathedMaterialGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64='-L__')
    assert counter.count == 4095

    with pytest.raises(kering.InvalidVarIndexError):
        Counter(code=CtrDex.PathedMaterialGroup, count=4096)  # Too big

    # Test BigPathedMaterialGroup
    # test with big codes index=1024000
    count = 1024000
    qsc = CtrDex.BigPathedMaterialGroup + intToB64(count, l=5)
    assert qsc == '-0LAD6AA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigPathedMaterialGroup, count=count)
    assert counter.code == CtrDex.BigPathedMaterialGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2


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
    qsc = CtrDex.BigAttachmentGroup + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True)  # test with qb2
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    # test protocol genus with CESR version
    # test with big codes index=1024
    verint = 0
    version = intToB64(verint, l=3)
    assert version == 'AAA'
    assert verint == b64ToInt(version)
    qsc = CtrDex.KERIACDCGenusVersion + version
    assert qsc == '--AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIACDCGenusVersion, count=verint)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.count == verint
    assert counter.countToB64(l=3) == version
    assert counter.countToB64() == version  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(code=CtrDex.KERIACDCGenusVersion, countB64=version)
    assert counter.code == CtrDex.KERIACDCGenusVersion
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




def test_seqner():
    """
    Test Seqner sequence number subclass Matter
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

    with pytest.raises(InvalidValueError):  # negative
        number = Seqner(sn=-1)

    with pytest.raises(ValidationError): # too big
        number = Seqner(sn=(256 ** 16))

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

    assert asdict(NumDex) == {
        'Short': 'M',
        'Long': '0H',
        'Tall': 'R',
        'Big': 'N',
        'Large': 'S',
        'Great': 'T',
        'Huge': '0A',
        'Vast': 'U'
    }

    assert Number.Codes == \
    {
        'Short': 'M',
        'Long': '0H',
        'Tall': 'R',
        'Big': 'N',
        'Large': 'S',
        'Great': 'T',
        'Huge': '0A',
        'Vast': 'U'
    }


    assert Number.Names == \
    {
        'M': 'Short',
        '0H': 'Long',
        'R': 'Tall',
        'N': 'Big',
        'S': 'Large',
        'T': 'Great',
        '0A': 'Huge',
        'U': 'Vast'
    }


    with pytest.raises(EmptyMaterialError):
        number = Number(raw=b'')  # missing code

    with pytest.raises(RawMaterialError):
        number = Number(raw=b'', code=MtrDex.Short)  # empty raw

    with pytest.raises(InvalidValueError):
        number = Number(num=-1)  # negative

    # when code provided does not dynamically size code
    with pytest.raises(InvalidValueError):
        number = Number(num=256 ** 2, code=MtrDex.Short)  # wrong code for num


    number = Number()  # test defaults, num is None forces to zero, code dynamic
    assert number.code == NumDex.Short
    assert number.raw == b'\x00\x00'
    assert number.qb64 == 'MAAA'
    assert number.qb64b == b'MAAA'
    assert number.qb2 == b'0\x00\x00'
    assert number.num == 0
    assert number.numh == '0'
    assert number.sn == 0
    assert number.snh == '0'
    assert number.huge == '0AAAAAAAAAAAAAAAAAAAAAAA'
    assert len(number.huge) == 24
    assert not number.positive
    assert number.inceptive
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

    # force bigger code for smaller number like for lexicographic namespace
    # which must be fixed length no matter the numeric value such as sequence
    # numbers in namespaces for lmdb
    number = Number(num=1, code=NumDex.Huge)
    assert number.qb64 == '0AAAAAAAAAAAAAAAAAAAAAAB'
    assert len(number.raw) == 16
    assert NumDex.Huge == MtrDex.Salt_128


    num = (256 ** 18 - 1)  # too big to represent
    assert num == 22300745198530623141535718272648361505980415
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffffffffffffffffff'
    assert len(numh) == 18 * 2

    with pytest.raises(InvalidValueError):
        number = Number(num=num)

    with pytest.raises(InvalidValueError):
        number = Number(numh=numh)


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

    num = (256 ** 5 - 1)
    assert num == 1099511627775
    numh = f"{num:x}"
    assert numh == 'ffffffffff'
    raw = b'\xff\xff\xff\xff\xff'
    code = NumDex.Tall
    nqb64 = 'RP______'  # '0HD_____'  # '0H_____w'
    nqb2 = b'D\xff\xff\xff\xff\xff' # b'\xd0p\xff\xff\xff\xff'

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
    nqb2 = b'4\xff\xff\xff\xff\xff\xff\xff\xff'

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

    num = (256 ** 11 - 1)
    assert num == 309485009821345068724781055
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Large
    nqb64 = 'SP______________' # 'NP__________'  # 'N__________8'
    nqb2 = b'H\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' # b'4\xff\xff\xff\xff\xff\xff\xff\xff'

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

    num = (256 ** 14 - 1)
    assert num == 5192296858534827628530496329220095
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Great
    nqb64 = 'TP__________________' # '0AD_____________________'
    nqb2 = b'L\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    # b'\xd0\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'

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

    num = (256 ** 17 - 1)
    assert num == 87112285931760246646623899502532662132735
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Vast
    nqb64 = 'UP______________________' #'TP__________________'
    nqb2 =  b'P\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    # b'L\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'

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
    with pytest.raises(InvalidValueError):
        number.huge  # too big for huge

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
    with pytest.raises(InvalidValueError):
        number.huge  # too big for huge

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
    with pytest.raises(InvalidValueError):
        number.huge  # too big for huge

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
    with pytest.raises(InvalidValueError):
        number.huge  # too big for huge



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
    with pytest.raises(InvalidValueError):
        number.huge  # too big for huge

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

    # raw too small for code raises error
    raw2bad = b'\xff'
    assert raw != raw2bad
    assert len(raw2bad) < len(raw)

    with pytest.raises(RawMaterialError):
        number = Number(raw=raw2bad, code=code)


    # tests with wrong size raw for code large
    num = (256 ** 5 - 1)
    assert num == 1099511627775
    numh = f"{num:x}"
    assert numh == 'ffffffffff'
    raw = b'\xff\xff\xff\xff\xff'
    code = NumDex.Tall
    nqb64 = 'RP______'  # '0HD_____'  # '0H_____w'
    nqb2 = b'D\xff\xff\xff\xff\xff' # b'\xd0p\xff\xff\xff\xff'


    # raw to large for code, then truncates
    raw2bad = b'\xff\xff\xff\xff\xff\xff'
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

    # raw too small for code raises error
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


    # tests with wrong size raw for code Vast
    num = (256 ** 17 - 1)
    assert num == 87112285931760246646623899502532662132735
    numh = f"{num:x}"
    assert numh == 'ffffffffffffffffffffffffffffffffff'
    raw = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    code = NumDex.Vast
    nqb64 = 'UP______________________' #'TP__________________'
    nqb2 =  b'P\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'


    # raw to large for code, then truncates
    raw2bad = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffxff'
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


    # test with negative num
    num = -1
    numh = f"{num:x}"
    assert numh == '-1'
    code = NumDex.Short

    with pytest.raises(InvalidValueError):
        number = Number(num=num)

    with pytest.raises(InvalidValueError):
        number = Number(numh=numh)



    # test using num to initialize Number
    num = 0
    numh = f"{num:x}"
    assert numh == '0'
    code = NumDex.Short
    raw = b'\x00\x00'
    nqb64 = 'MAAA'
    nqb2 = b'0\x00\x00'
    assert hex(int.from_bytes(nqb2, 'big')) == '0x300000'

    number = Number(num=num)
    assert number.code == code
    assert number.raw == raw
    assert number.qb64 == nqb64
    assert number.qb64b == nqb64.encode("utf-8")
    assert number.qb2 == nqb2
    assert number.num == num
    assert number.numh == numh
    assert not number.positive
    bs = ceil((len(number.code) * 3) / 4)
    assert number.qb2[bs:] == number.raw
    # test validate()
    assert number.validate() == number  # default inceptive = None
    assert number.validate(inceptive=True) == number  # inceptive = True
    with pytest.raises(ValidationError):
        number.validate(inceptive=False) # inceptive = False

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
    # test validate
    assert number.validate() == number  # default inceptive = None
    with pytest.raises(ValidationError):
        number.validate(inceptive=True)  # inceptive = True
    assert number.validate(inceptive=False) == number  # inceptive = False


    num = 65536
    numh = f"{num:x}"
    assert numh == '10000'  # hex
    code = NumDex.Tall
    raw = b'\x00\x00\x01\x00\x00'
    nqb64 = 'RAAAAQAA'
    nqb2 = b'D\x00\x00\x01\x00\x00'
    assert hex(int.from_bytes(nqb2, 'big')) == '0x440000010000'

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
    # test validate
    assert number.validate() == number  # default inceptive = None
    with pytest.raises(ValidationError):
        number.validate(inceptive=True)  # inceptive = True
    assert number.validate(inceptive=False) == number  # inceptive = False

    # too big for ordinal
    num = num = (256 ** 16)
    numh = f"{num:x}"
    assert numh == '100000000000000000000000000000000'  # hex
    code = NumDex.Vast
    raw =b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    nqb64 = 'UAEAAAAAAAAAAAAAAAAAAAAA'
    nqb2 = b'P\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    assert hex(int.from_bytes(nqb2, 'big')) == '0x500100000000000000000000000000000000'

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
    # test validate
    with pytest.raises(ValidationError): # too big
        number.validate() # default inceptive = None
    with pytest.raises(ValidationError): # too big
        number.validate(inceptive=True)  # inceptive = True
    with pytest.raises(ValidationError): # too big
        number.validate(inceptive=False)  # inceptive = False

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

def test_tagger():
    """
    Test Tagger version primitive subclass of Matter
    """
    # Test TagCodex PadTagCodex and associated Sizes to be valid specials

    with pytest.raises(EmptyMaterialError):
        tagger = Tagger()  # defaults

    # Tag1
    tag = 'v'
    code = MtrDex.Tag1
    soft = '_v'
    qb64 = '0J_v'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)
    raw = b''

    tagger = Tagger(tag=tag)  # defaults
    assert tagger.code == tagger.hard == code
    assert tagger.soft == soft
    assert tagger.raw == raw
    assert tagger.qb64 == qb64
    assert tagger.qb2 == qb2
    assert tagger.special
    assert tagger.composable
    assert tagger.tag == tag

    tagger = Tagger(qb2=qb2)
    assert tagger.code == tagger.hard == code
    assert tagger.soft == soft
    assert tagger.raw == raw
    assert tagger.qb64 == qb64
    assert tagger.qb2 == qb2
    assert tagger.special
    assert tagger.composable
    assert tagger.tag == tag

    tagger = Tagger(qb64=qb64)
    assert tagger.code == tagger.hard == code
    assert tagger.soft == soft
    assert tagger.raw == raw
    assert tagger.qb64 == qb64
    assert tagger.qb2 == qb2
    assert tagger.special
    assert tagger.composable
    assert tagger.tag == tag

    tagger = Tagger(qb64b=qb64b)
    assert tagger.code == tagger.hard == code
    assert tagger.soft == soft
    assert tagger.raw == raw
    assert tagger.qb64 == qb64
    assert tagger.qb2 == qb2
    assert tagger.special
    assert tagger.composable
    assert tagger.tag == tag


    tags = 'abcdefghij'
    alltags = dict()
    for l in range(1, len(astuple(TagDex)) + 1):
        tag = tags[:l]
        tagger = Tagger(tag=tag)
        assert tagger.tag == tag
        assert len(tagger.tag) == l
        assert tagger.code == astuple(TagDex)[l - 1]
        alltags[l] = (tagger.tag, tagger.code)

    assert alltags == \
        {
            1: ('a', '0J'),
            2: ('ab', '0K'),
            3: ('abc', 'X'),
            4: ('abcd', '1AAF'),
            5: ('abcde', '0L'),
            6: ('abcdef', '0M'),
            7: ('abcdefg', 'Y'),
            8: ('abcdefgh', '1AAN'),
            9: ('abcdefghi', '0N'),
            10: ('abcdefghij', '0O')
         }
    """ Done Test """


def test_ilker():
    """
    Test Ilker message type subclass of Tagger
    """
    with pytest.raises(EmptyMaterialError):
        ilker = Ilker()  # defaults

    ilk = Ilks.rot
    tag = ilk
    code = MtrDex.Tag3
    soft = 'rot'
    qb64 = 'Xrot'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)
    raw = b''

    ilker = Ilker(ilk=ilk)  # defaults
    assert ilker.code == ilker.hard == code
    assert ilker.soft == soft
    assert ilker.raw == raw
    assert ilker.qb64 == qb64
    assert ilker.qb2 == qb2
    assert ilker.special
    assert ilker.composable
    assert ilker.tag == tag
    assert ilker.ilk == ilk

    ilker = Ilker(qb2=qb2)
    assert ilker.code == ilker.hard == code
    assert ilker.soft == soft
    assert ilker.raw == raw
    assert ilker.qb64 == qb64
    assert ilker.qb2 == qb2
    assert ilker.special
    assert ilker.composable
    assert ilker.tag == tag
    assert ilker.ilk == ilk

    ilker = Ilker(qb64=qb64)
    assert ilker.code == ilker.hard == code
    assert ilker.soft == soft
    assert ilker.raw == raw
    assert ilker.qb64 == qb64
    assert ilker.qb2 == qb2
    assert ilker.special
    assert ilker.composable
    assert ilker.tag == tag
    assert ilker.ilk == ilk

    ilker = Ilker(qb64b=qb64b)
    assert ilker.code == ilker.hard == code
    assert ilker.soft == soft
    assert ilker.raw == raw
    assert ilker.qb64 == qb64
    assert ilker.qb2 == qb2
    assert ilker.special
    assert ilker.composable
    assert ilker.tag == tag
    assert ilker.ilk == ilk

    ilker = Ilker(tag=tag)
    assert ilker.code == ilker.hard == code
    assert ilker.soft == soft
    assert ilker.raw == raw
    assert ilker.qb64 == qb64
    assert ilker.qb2 == qb2
    assert ilker.special
    assert ilker.composable
    assert ilker.tag == tag
    assert ilker.ilk == ilk

    # test error condition
    with pytest.raises(InvalidSoftError):
        ilker = Ilker(ilk='bad')

    # ignores code
    ilker = Ilker(ilk=ilk, code=MtrDex.Tag4)
    assert ilker.code == ilker.hard == code
    assert ilker.soft == soft
    assert ilker.raw == raw
    assert ilker.qb64 == qb64
    assert ilker.qb2 == qb2
    assert ilker.special
    assert ilker.composable
    assert ilker.tag == tag
    assert ilker.ilk == ilk

    # test error using soft and code
    with pytest.raises(InvalidCodeError):
        ilker = Ilker(soft='bady', code=MtrDex.Tag4)

    """End Test"""


def test_traitor():
    """
    Test Traitor configuration trait subclass of Tagger
    """
    with pytest.raises(EmptyMaterialError):
        traitor = Traitor()  # defaults

    trait = TraitDex.EstOnly
    tag = trait
    code = MtrDex.Tag2
    soft = 'EO'
    qb64 = '0KEO'
    qb64b = qb64.encode("utf-8")
    qb2 = decodeB64(qb64b)
    raw = b''

    traitor = Traitor(trait=trait)  # defaults
    assert traitor.code == traitor.hard == code
    assert traitor.soft == soft
    assert traitor.raw == raw
    assert traitor.qb64 == qb64
    assert traitor.qb2 == qb2
    assert traitor.special
    assert traitor.composable
    assert traitor.tag == tag
    assert traitor.trait == trait

    traitor = Traitor(qb2=qb2)
    assert traitor.code == traitor.hard == code
    assert traitor.soft == soft
    assert traitor.raw == raw
    assert traitor.qb64 == qb64
    assert traitor.qb2 == qb2
    assert traitor.special
    assert traitor.composable
    assert traitor.tag == tag
    assert traitor.trait == trait

    traitor = Traitor(qb64=qb64)
    assert traitor.code == traitor.hard == code
    assert traitor.soft == soft
    assert traitor.raw == raw
    assert traitor.qb64 == qb64
    assert traitor.qb2 == qb2
    assert traitor.special
    assert traitor.composable
    assert traitor.tag == tag
    assert traitor.trait == trait

    traitor = Traitor(qb64b=qb64b)
    assert traitor.code == traitor.hard == code
    assert traitor.soft == soft
    assert traitor.raw == raw
    assert traitor.qb64 == qb64
    assert traitor.qb2 == qb2
    assert traitor.special
    assert traitor.composable
    assert traitor.tag == tag
    assert traitor.trait == trait

    traitor = Traitor(tag=tag)
    assert traitor.code == traitor.hard == code
    assert traitor.soft == soft
    assert traitor.raw == raw
    assert traitor.qb64 == qb64
    assert traitor.qb2 == qb2
    assert traitor.special
    assert traitor.composable
    assert traitor.tag == tag
    assert traitor.trait == trait

    # test error condition
    with pytest.raises(InvalidSoftError):
        traitor = Traitor(trait='bad')

    # ignores code
    traitor = Traitor(trait=trait, code=MtrDex.Tag4)
    assert traitor.code == traitor.hard == code
    assert traitor.soft == soft
    assert traitor.raw == raw
    assert traitor.qb64 == qb64
    assert traitor.qb2 == qb2
    assert traitor.special
    assert traitor.composable
    assert traitor.tag == tag
    assert traitor.trait == trait

    # test error using soft and code
    with pytest.raises(InvalidSoftError):
        traitor = Traitor(soft='bady', code=MtrDex.Tag4)

    """End Test"""


def test_verser():
    """
    Test Verser version primitive subclass of Matter
    """
    # Test defaults
    code = MtrDex.Tag7
    soft = 'KERICAA'
    tag = 'KERICAA'
    qb64 = 'YKERICAA'
    qb64b = qb64.encode()
    qb2 = decodeB64(qb64b)
    raw = b''
    versage = Versage(proto=Protocols.keri, vrsn=Vrsn_2_0, gvrsn=None)

    verser = Verser()  # defaults
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.composable
    assert verser.versage == versage

    # test with default equivalent values
    verser = Verser(versage=versage)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.composable
    assert verser.versage == versage

    verser = Verser(proto=Protocols.keri, vrsn=Vrsn_2_0)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    verser = Verser(qb2=qb2)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    verser = Verser(qb64=qb64)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    verser = Verser(qb64b=qb64b)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    # Test with gvrsn
    code = MtrDex.Tag10
    soft = 'ACDCCAACAA'
    tag = 'ACDCCAACAA'
    qb64 = '0OACDCCAACAA'
    qb64b = qb64.encode()
    qb2 = decodeB64(qb64b)
    raw = b''
    versage = Versage(proto=Protocols.acdc, vrsn=Vrsn_2_0, gvrsn=Vrsn_2_0)

    verser = Verser(versage=versage)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.composable
    assert verser.versage == versage

    verser = Verser(proto=Protocols.acdc, vrsn=Vrsn_2_0, gvrsn=Vrsn_2_0)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    verser = Verser(qb2=qb2)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    verser = Verser(qb64=qb64)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    verser = Verser(qb64b=qb64b)
    assert verser.code == verser.hard == code
    assert verser.soft == soft
    assert verser.tag == tag
    assert verser.raw == raw
    assert verser.qb64 == qb64
    assert verser.qb2 == qb2
    assert verser.special
    assert verser.versage == versage

    """ Done Test """


def test_texter():
    """
    Test Texter variable sized text (bytes) subclass of Matter
    """
    with pytest.raises(EmptyMaterialError):
        texter = Texter()

    with pytest.raises(ValidationError):
        texter = Texter(raw=b'Wrong code for Texter', code=MtrDex.StrB64_L0)


    text = ""
    textb = b""

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L0
    assert texter.both == '4BAA'
    assert texter.raw == textb
    assert texter.qb64 == '4BAA'
    assert texter.text == text

    texter = Texter(text=textb)
    assert texter.both == '4BAA'
    assert texter.raw == b'' == textb

    texter = Texter(raw=textb)
    assert texter.both == '4BAA'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '4BAA'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '4BAA'
    assert texter.raw == textb


    text = "$"
    textb = b"$"

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L2
    assert texter.both == '6BAB'
    assert texter.raw == textb
    assert texter.qb64 == '6BABAAAk'
    assert texter.qb2 ==b'\xe8\x10\x01\x00\x00$'
    assert texter.text == text

    texter = Texter(text=textb)
    assert texter.both == '6BAB'
    assert texter.raw == textb

    texter = Texter(raw=textb)
    assert texter.both == '6BAB'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '6BAB'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '6BAB'
    assert texter.raw == textb



    text = "@!"
    textb = b"@!"

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L1
    assert texter.both == '5BAB'
    assert texter.raw == textb
    assert texter.qb64 == '5BABAEAh'
    assert texter.qb2 ==b'\xe4\x10\x01\x00@!'
    assert texter.text == text

    texter = Texter(text=textb)
    assert texter.both == '5BAB'
    assert texter.raw == textb

    texter = Texter(raw=textb)
    assert texter.both == '5BAB'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '5BAB'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '5BAB'
    assert texter.raw == textb

    text = "^*#"
    textb = b"^*#"

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L0
    assert texter.both == '4BAB'
    assert texter.raw == textb
    assert texter.qb64 == '4BABXioj'
    assert texter.qb2 == b'\xe0\x10\x01^*#'
    assert texter.text == text

    texter = Texter(text=textb)
    assert texter.both == '4BAB'
    assert texter.raw == textb

    texter = Texter(raw=textb)
    assert texter.both == '4BAB'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '4BAB'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '4BAB'
    assert texter.raw == textb

    text = "&~?%"
    textb = b"&~?%"

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L2
    assert texter.both == '6BAC'
    assert texter.raw == textb
    assert texter.qb64 == '6BACAAAmfj8l'
    assert texter.qb2 == b'\xe8\x10\x02\x00\x00&~?%'
    assert texter.text == text

    texter = Texter(text=textb)
    assert texter.both == '6BAC'
    assert texter.raw == textb

    texter = Texter(raw=textb)
    assert texter.both == '6BAC'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '6BAC'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '6BAC'
    assert texter.raw == textb


    text = "\n"  # control character
    textb = b"\n"

    assert len(text) == len(textb) == 1

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L2
    assert texter.both == '6BAB'
    assert texter.raw == textb
    assert texter.qb64 == '6BABAAAK'
    assert texter.qb2 ==b'\xe8\x10\x01\x00\x00\n'
    assert texter.text == text

    texter = Texter(text=textb)
    assert texter.both == '6BAB'
    assert texter.raw == textb

    texter = Texter(raw=textb)
    assert texter.both == '6BAB'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '6BAB'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '6BAB'
    assert texter.raw == textb


    text = "Did the lazy fox jumped over the big dog? But it's not its dog!\n"
    textb = b"Did the lazy fox jumped over the big dog? But it's not its dog!\n"

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_L2
    assert texter.both == '6BAW'
    assert texter.raw == textb
    assert texter.qb64 == '6BAWAABEaWQgdGhlIGxhenkgZm94IGp1bXBlZCBvdmVyIHRoZSBiaWcgZG9nPyBCdXQgaXQncyBub3QgaXRzIGRvZyEK'
    assert texter.qb2 ==(b"\xe8\x10\x16\x00\x00Did the lazy fox jumped over the big dog? But it's not "
                         b'its dog!\n')
    assert texter.text == text

    assert len(texter.qb64) * 3 / 4 == len(texter.qb2)

    texter = Texter(text=textb)
    assert texter.both == '6BAW'
    assert texter.raw == textb

    texter = Texter(raw=textb)
    assert texter.both == '6BAW'
    assert texter.raw == textb

    texter = Texter(qb64=texter.qb64)
    assert texter.both == '6BAW'
    assert texter.raw == textb

    texter = Texter(qb2=texter.qb2)
    assert texter.both == '6BAW'
    assert texter.raw == textb



    text =  "a" * ((64 ** 2) * 3)  # big variable size
    textb = text.encode("utf-8")

    assert len(text) // 3 > (64 ** 2 - 1)

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_Big_L0
    assert texter.both == '7AABABAA'
    assert texter.raw == textb
    assert len(texter.qb64) == 16392
    assert len(texter.qb2) == 12294
    assert len(texter.qb64) * 3 / 4 == len(texter.qb2)
    assert texter.text == text

    text =  "b" * ((64 ** 2 ) * 3 + 1)  # big variable size
    textb = text.encode("utf-8")

    assert len(text) // 3 > (64 ** 2 - 1)

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_Big_L2
    assert texter.both == '9AABABAB'
    assert texter.raw == textb
    assert len(texter.qb64) == 16396
    assert len(texter.qb2) == 12297
    assert len(texter.qb64) * 3 / 4 == len(texter.qb2)
    assert texter.text == text

    text =  "c" * ((64 ** 2 ) * 3 + 2)  # big variable size
    textb = text.encode("utf-8")

    assert len(text) // 3 > (64 ** 2 - 1)

    texter = Texter(text=text)
    assert texter.code == MtrDex.Bytes_Big_L1
    assert texter.both == '8AABABAB'
    assert texter.raw == textb
    assert len(texter.qb64) == 16396
    assert len(texter.qb2) == 12297
    assert len(texter.qb64) * 3 / 4 == len(texter.qb2)
    assert texter.text == text

    text =  "c" * ((64 ** 4) * 3)  # excessive variable size
    with pytest.raises(InvalidVarRawSizeError):
        texter = Texter(text=text)

    """ Done Test """



def test_bexter():
    """
    Test Bexter variable sized Base64 text subclass of Matter
    """
    with pytest.raises(EmptyMaterialError):
        bexter = Bexter()

    with pytest.raises(ValidationError):
        bexter = Bexter(raw=b'Wrong_code_for_Bexter', code=MtrDex.Bytes_L0)

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
    with pytest.raises(KeyError):
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

    # secp256r1
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    d = int.from_bytes(seed, byteorder="big")
    sigkey = ec.derive_private_key(d, ec.SECP256R1())
    verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1)
    assert verfer.raw == verkey
    assert verfer.code == MtrDex.ECDSA_256r1

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
    (r, s) = utils.decode_dss_signature(der)
    sig = bytearray(r.to_bytes(32, "big"))
    sig.extend(s.to_bytes(32, "big"))

    result = verfer.verify(sig, ser)
    assert result == True

    result = verfer.verify(der, b'ABC')
    assert result == False

    # secp256r1N
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    d = int.from_bytes(seed, byteorder="big")
    sigkey = ec.derive_private_key(d, ec.SECP256R1())
    verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)

    verferN = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1N)
    assert verferN.raw == verkey
    assert verferN.code == MtrDex.ECDSA_256r1N

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
    (r, s) = utils.decode_dss_signature(der)
    sig = bytearray(r.to_bytes(32, "big"))
    sig.extend(s.to_bytes(32, "big"))

    result = verferN.verify(sig, ser)
    assert result == True

    result = verferN.verify(der, b'ABC')
    assert result == False

    # secp256k1
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    d = int.from_bytes(seed, byteorder="big")
    sigkey = ec.derive_private_key(d, ec.SECP256K1())
    verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256k1)
    assert verfer.raw == verkey
    assert verfer.code == MtrDex.ECDSA_256k1

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
    (r, s) = utils.decode_dss_signature(der)
    sig = bytearray(r.to_bytes(32, "big"))
    sig.extend(s.to_bytes(32, "big"))

    result = verfer.verify(sig, ser)
    assert result == True

    result = verfer.verify(der, b'ABC')
    assert result == False

    # secp256k1N
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    d = int.from_bytes(seed, byteorder="big")
    sigkey = ec.derive_private_key(d, ec.SECP256K1())
    verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256k1N)
    assert verfer.raw == verkey
    assert verfer.code == MtrDex.ECDSA_256k1N

    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'

    der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
    (r, s) = utils.decode_dss_signature(der)
    sig = bytearray(r.to_bytes(32, "big"))
    sig.extend(s.to_bytes(32, "big"))

    result = verfer.verify(sig, ser)
    assert result == True

    result = verfer.verify(der, b'ABC')
    assert result == False

    """ Done Test """


def test_cigar():
    """
    Test Cigar subclass of Matter
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

    ked = dict(v="",  # version string
               t="icp",
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt=1,
               k=[prefixer.qb64],  # list of qb64
               nt="",
               n=[],  # hash qual Base64
               bt=0,
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    ked = dict(v="",  # version string
               t="icp",
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt=1,
               k=[prefixer.qb64],  # list of qb64
               nt="1",
               n=["ABCD"],  # hash qual Base64
               bt=0,
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    prefixer = Prefixer(raw=verkey, code=MtrDex.Ed25519)  # defaults provide Ed25519N prefixer
    assert prefixer.code == MtrDex.Ed25519
    assert len(prefixer.raw) == Matter._rawSize(prefixer.code)
    assert len(prefixer.qb64) == Matter.Sizes[prefixer.code].fs

    ked = dict(v="",  # version string
               t="icp",
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt=1,
               k=[prefixer.qb64],  # list of qb64
               nt="1",
               n=["ABCD"],  # hash qual Base64
               bt=0,
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    prefixer = Prefixer(raw=verfer.raw, code=MtrDex.Ed25519N)
    assert prefixer.code == MtrDex.Ed25519N
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # Test basic derivation from ked
    ked = dict(v="",  # version string
               t="icp",
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt=1,
               k=[verfer.qb64],  # list of qb64
               nt="",
               n=0,  # hash qual Base64
               bt=0,
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.Ed25519)
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    badked = dict(ked)
    del badked["i"]
    with pytest.raises(EmptyMaterialError):  # no pre
        prefixer = Prefixer(ked=badked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=preN
    with pytest.raises(DerivationError):  # verfer code not match pre code
        prefixer = Prefixer(ked=badked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=pre
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=badked, code=MtrDex.Ed25519N)  # verfer code not match code

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=pre
    prefixer = Prefixer(ked=badked, code=MtrDex.Ed25519N)  # verfer code match code but not pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=badked) == True
    assert prefixer.verify(ked=badked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=preN
    prefixer = Prefixer(ked=badked, code=MtrDex.Ed25519N)  # verfer code match code and pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=badked) == True
    assert prefixer.verify(ked=badked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=preN
    prefixer = Prefixer(ked=badked)  # verfer code match pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=badked) == True
    assert prefixer.verify(ked=badked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    del badked["i"]
    with pytest.raises(EmptyMaterialError):  # missing pre
        prefixer = Prefixer(ked=badked)

    verfer = Verfer(raw=verkey, code=MtrDex.Ed25519N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    with pytest.raises(ShortageError):  # empty pre
        prefixer = Prefixer(ked=badked)

    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["n"] = "ABCD"
    with pytest.raises(DerivationError):  # wrong code for transferable
        prefixer = Prefixer(ked=badked, code=MtrDex.Ed25519)

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
               t=ilk,
               d="",  # SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=0,
               n=[],
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EEZn82xRQYFjfkPJ5ECrDNHJ6xSt_hjxybbt_WMpinEF'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with next digs
    ndigs = [Diger(ser=nxtfer.qb64b).qb64]
    ked = dict(v=vs,  # version string
               t=ilk,
               d="",  # SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=1,
               n=ndigs,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EHB9-i6jOH6DbK_40vlGF0X78Mg__c3MSzu9AE9ZRrsC'
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
    signers = [core.Signer(qb64=secret) for secret in secrets]  # faster
    assert [siger.qb64 for siger in signers] == secrets
    # each signer has verfer for keys

    # Test with sith with one clause
    keys = [signers[0].verfer.qb64, signers[1].verfer.qb64, signers[2].verfer.qb64]
    sith = [["1/2", "1/2", "1"]]
    ndigs = [Diger(ser=signers[3].verfer.qb64b).qb64]  # default limen/sith

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",  # SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=1,
               n=ndigs,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )

    prefixer1 = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer1.qb64 == 'EOnpRzJpF1LNdCXl7aQ76BxF7qT94PChM7WGKARhZeKj'
    assert prefixer1.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # now test with different sith but same weights in two clauses
    sith = [["1/2", "1/2"], ["1"]]

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",  # SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=1,
               n=ndigs,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )

    prefixer2 = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer2.qb64 == 'ECBv9o83MnNYRTdXhwTeR5zgwt8jTr5NIuJ8P00BKySW'
    assert prefixer2.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False
    assert prefixer2.qb64 != prefixer1.qb64  # semantic diff -> syntactic diff

    sith = "1"
    seal = dict(i='EBfPkd-A2CQfJmfpmtc1V-yuleSeCcyWBIrTAygUgQ_T',
                s='2',
                t=Ilks.ixn,
                d='EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb')

    ked = dict(v=vs,  # version string
               t=Ilks.dip,
               d="",  # SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=1,
               n=ndigs,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=[seal],  # list of seal dicts
               di='EBfPkd-A2CQfJmfpmtc1V-yuleSeCcyWBIrTAygUgQ_T',
               )

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256)
    assert prefixer.qb64 == 'EEGithHj9A85F9hz1fxlF80U7wvpFoAPj6U4q4YWMehp'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # test with allows
    with pytest.raises(ValueError):
        prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256,
                            allows=[MtrDex.Ed25519N, MtrDex.Ed25519])

    prefixer = Prefixer(ked=ked, code=MtrDex.Blake3_256,
                        allows=[MtrDex.Blake3_256, MtrDex.Ed25519])
    assert prefixer.qb64 == 'EEGithHj9A85F9hz1fxlF80U7wvpFoAPj6U4q4YWMehp'
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    #  Secp256r1

    preN = '1AAIA-KzxCX8SZSl-fpU3vc3z_MBuH06YShJFuiMdAmo37TM'
    # 'BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE'
    pre = '1AAJA-KzxCX8SZSl-fpU3vc3z_MBuH06YShJFuiMdAmo37TM'

    # sigkey = ec.generate_private_key(ec.SECP256R1())
    # verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
    verkey = b'\x03\xe2\xb3\xc4%\xfcI\x94\xa5\xf9\xfaT\xde\xf77\xcf\xf3\x01\xb8}:a(I\x16\xe8\x8ct\t\xa8\xdf\xb4\xcc'

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1)
    assert verfer.qb64 == '1AAJA-KzxCX8SZSl-fpU3vc3z_MBuH06YShJFuiMdAmo37TM'

    nxtkeyqb64 = [coring.Diger(ser=verfer.qb64b).qb64]  # dfault sith is 1
    assert nxtkeyqb64 == ['EPrVv1ppjxrtV48cS9Tm49n5xojMlZfhEzExg6Ye_ORN']

    prefixer = Prefixer(raw=verkey, code=MtrDex.ECDSA_256r1)  # default code is None
    assert prefixer.code == MtrDex.ECDSA_256r1
    assert len(prefixer.raw) == Matter._rawSize(prefixer.code)
    assert len(prefixer.qb64) == Matter.Sizes[prefixer.code].fs

    ked = dict(v="",  # version string
               t="icp",
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt=1,
               k=[prefixer.qb64],  # list of qb64
               nt="1",
               n=["ABCD"],  # hash qual Base64
               bt=0,
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1)
    prefixer = Prefixer(raw=verfer.raw, code=MtrDex.ECDSA_256r1N)
    assert prefixer.code == MtrDex.ECDSA_256r1N
    assert prefixer.verify(ked=ked) == False
    assert prefixer.verify(ked=ked, prefixed=True) == False

    # Test basic derivation from ked
    ked = dict(v="",  # version string
               t="icp",
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="0",  # hex string no leading zeros lowercase
               kt=1,
               k=[verfer.qb64],  # list of qb64
               nt="",
               n=0,  # hash qual Base64
               bt=0,
               b=[],  # list of qb64 may be empty
               c=[],  # list of config ordered mappings may be empty
               a=[],  # list of seal dicts
               )
    prefixer = Prefixer(ked=ked, code=MtrDex.ECDSA_256r1)
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=ked) == True
    assert prefixer.verify(ked=ked, prefixed=True) == False

    badked = dict(ked)
    del badked["i"]
    with pytest.raises(EmptyMaterialError):  # no pre
        prefixer = Prefixer(ked=badked)

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=preN
    with pytest.raises(DerivationError):  # verfer code not match pre code
        prefixer = Prefixer(ked=badked)

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=pre
    with pytest.raises(DerivationError):
        prefixer = Prefixer(ked=badked, code=MtrDex.ECDSA_256r1N)  # verfer code not match code

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=pre
    prefixer = Prefixer(ked=badked, code=MtrDex.ECDSA_256r1N)  # verfer code match code but not pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=badked) == True
    assert prefixer.verify(ked=badked, prefixed=True) == False

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=preN
    prefixer = Prefixer(ked=badked, code=MtrDex.ECDSA_256r1N)  # verfer code match code and pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=badked) == True
    assert prefixer.verify(ked=badked, prefixed=True) == True

    verfer = Verfer(raw=verkey, code=MtrDex.ECDSA_256r1N)
    badked = dict(ked)
    badked["k"]=[verfer.qb64]
    badked["i"]=preN
    prefixer = Prefixer(ked=badked)  # verfer code match pre code
    assert prefixer.qb64 == verfer.qb64
    assert prefixer.verify(ked=badked) == True
    assert prefixer.verify(ked=badked, prefixed=True) == True

    """ Done Test """



def test_saider():
    """
    Test Saider object
    """
    # Test class attribute Digest matches DigDex (i.e.DigestCodex)
    assert set(Saider.Digests.keys()) == set(code for code in DigDex)

    code = MtrDex.Blake3_256
    kind = Serials.json
    label = Saids.dollar

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
    label = Saids.d
    code = MtrDex.Blake3_256  # back to default code

    # Load from vaccuous dict
    label = Saids.d
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

    # test new nested weighted with Mapping dict with one clause
    # 1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1
    tholder = Tholder(sith='[{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]')
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[(Fraction(1, 3),
                                  [Fraction(1, 2),
                                   Fraction(1, 2),
                                   Fraction(1, 2)]),
                              Fraction(1, 3),
                              Fraction(1, 2),
                              (Fraction(1, 2),
                                   [1, 1])]]
    assert tholder.limen ==b'4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1'
    assert tholder.sith ==[{'1/3': ['1/2', '1/2', '1/2']}, '1/3', '1/2', {'1/2': ['1', '1']}]
    assert tholder.json == '[{"1/3": ["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]'
    assert tholder.num == None
    assert tholder.satisfy(indices=[0, 2, 3, 6])
    assert tholder.satisfy(indices=[3, 4, 5])
    assert tholder.satisfy(indices=[1, 2, 3, 4])
    assert tholder.satisfy(indices=[4, 6])
    assert tholder.satisfy(indices=[4, 2, 0, 3])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1, 5, 6, 3])
    assert not tholder.satisfy(indices=[0, 2, 5])
    assert not tholder.satisfy(indices=[2, 3, 4])

    tholder = Tholder(limen=b'4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1')
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[(Fraction(1, 3),
                                  [Fraction(1, 2),
                                   Fraction(1, 2),
                                   Fraction(1, 2)]),
                              Fraction(1, 3),
                              Fraction(1, 2),
                              (Fraction(1, 2),
                                   [1, 1])]]
    assert tholder.limen ==b'4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1'
    assert tholder.sith ==[{'1/3': ['1/2', '1/2', '1/2']}, '1/3', '1/2', {'1/2': ['1', '1']}]
    assert tholder.json == '[{"1/3": ["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]'
    assert tholder.num == None

    tholder = Tholder(thold=[[(Fraction(1, 3),
                                  [Fraction(1, 2),
                                   Fraction(1, 2),
                                   Fraction(1, 2)]),
                              Fraction(1, 3),
                              Fraction(1, 2),
                              (Fraction(1, 2),
                                   [1, 1])]])
    assert tholder.weighted
    assert tholder.size == 7
    assert tholder.thold == [[(Fraction(1, 3),
                                  [Fraction(1, 2),
                                   Fraction(1, 2),
                                   Fraction(1, 2)]),
                              Fraction(1, 3),
                              Fraction(1, 2),
                              (Fraction(1, 2),
                                   [1, 1])]]
    assert tholder.limen ==b'4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1'
    assert tholder.sith ==[{'1/3': ['1/2', '1/2', '1/2']}, '1/3', '1/2', {'1/2': ['1', '1']}]
    assert tholder.json == '[{"1/3": ["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]'
    assert tholder.num == None

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[{"1/3":["1/3", "1/3", "1/4"]}, "1/3", "1/2", {"1/2": ["1", "1"]}])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["2/3", "1/4"]}])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[{"1/5":["1/2", "1/2", "1/2"]}, "1/4", "1/5", {"1/5": ["1", "1"]}])

    # test new nested weighted with Mapping dict with two clauses

    tholder = Tholder(sith='[[{"1/3":["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/2": ["1", "1"]}]]')
    assert tholder.weighted
    assert tholder.size == 9
    assert tholder.thold == [[(Fraction(1, 3),
                               [Fraction(1, 2), Fraction(1, 2), Fraction(1, 2)]),
                              Fraction(1, 2),
                              (Fraction(1, 2), [1, 1])],
                             [Fraction(1, 2), (Fraction(1, 2), [1, 1])]]
    assert tholder.limen == b'4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1'
    assert tholder.sith == [[{'1/3': ['1/2', '1/2', '1/2']}, '1/2', {'1/2': ['1', '1']}],
                            ['1/2', {'1/2': ['1', '1']}]]

    assert tholder.json == ('[[{"1/3": ["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], '
                            '["1/2", ''{"1/2": ["1", "1"]}]]')
    assert tholder.num == None
    assert tholder.satisfy(indices=[0, 2, 3, 5, 6, 7])
    assert tholder.satisfy(indices=[3, 4, 5, 6, 8])
    assert tholder.satisfy(indices=[1, 2, 3, 4, 6, 7])
    assert tholder.satisfy(indices=[4, 2, 0, 3, 8, 6])
    assert tholder.satisfy(indices=[0, 0, 1, 2, 1, 8, 3, 5, 6, 3])
    assert not tholder.satisfy(indices=[0, 2, 5])
    assert not tholder.satisfy(indices=[6, 7, 8])

    tholder = Tholder(limen=b'4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1')
    assert tholder.weighted
    assert tholder.size == 9
    assert tholder.thold == [[(Fraction(1, 3),
                               [Fraction(1, 2), Fraction(1, 2), Fraction(1, 2)]),
                              Fraction(1, 2),
                              (Fraction(1, 2), [1, 1])],
                             [Fraction(1, 2), (Fraction(1, 2), [1, 1])]]
    assert tholder.limen == b'4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1'
    assert tholder.sith == [[{'1/3': ['1/2', '1/2', '1/2']}, '1/2', {'1/2': ['1', '1']}],
                            ['1/2', {'1/2': ['1', '1']}]]

    assert tholder.json == ('[[{"1/3": ["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], '
                            '["1/2", ''{"1/2": ["1", "1"]}]]')
    assert tholder.num == None

    tholder = Tholder(thold=[[(Fraction(1, 3),
                               [Fraction(1, 2), Fraction(1, 2), Fraction(1, 2)]),
                              Fraction(1, 2),
                              (Fraction(1, 2), [1, 1])],
                             [Fraction(1, 2), (Fraction(1, 2), [1, 1])]])
    assert tholder.weighted
    assert tholder.size == 9
    assert tholder.thold == [[(Fraction(1, 3),
                               [Fraction(1, 2), Fraction(1, 2), Fraction(1, 2)]),
                              Fraction(1, 2),
                              (Fraction(1, 2), [1, 1])],
                             [Fraction(1, 2), (Fraction(1, 2), [1, 1])]]
    assert tholder.limen == b'4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1'
    assert tholder.sith == [[{'1/3': ['1/2', '1/2', '1/2']}, '1/2', {'1/2': ['1', '1']}],
                            ['1/2', {'1/2': ['1', '1']}]]

    assert tholder.json == ('[[{"1/3": ["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], '
                            '["1/2", ''{"1/2": ["1", "1"]}]]')
    assert tholder.num == None

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[[{"1/3":["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/3": ["1", "1"]}]])

    with pytest.raises(ValueError):
        tholder = Tholder(sith=[[{"1/3":["1/3", "1/4", "1/3"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/2": ["1/2", "1/2"]}]])


    """ Done Test """


if __name__ == "__main__":
    test_mapdom()
    test_mapcodex()
    test_matter_class()
    test_matter()
    test_matter_special()
    test_tagger()
    test_ilker()
    test_traitor()
    test_verser()
    #test_texter()
    #test_counter()
    #test_prodex()
    #test_indexer()
    test_number()
    #test_seqner()
    #test_siger()
    #test_nexter()
    #test_tholder()
    #test_labels()
    #test_prefixer()

