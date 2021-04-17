# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import re
import json
import copy

from dataclasses import dataclass, astuple
from collections import namedtuple, deque
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from math import ceil
from fractions import Fraction
from orderedset import OrderedSet

import cbor2 as cbor
import msgpack
import pysodium
import blake3
import hashlib


from ..kering import (EmptyMaterialError, RawMaterialError, UnknownCodeError,
                      InvalidCodeIndexError, InvalidCodeSizeError,
                      ConversionError,
                      ValidationError, VersionError, DerivationError,
                      ShortageError, UnexpectedCodeError, DeserializationError,
                      UnexpectedCountCodeError, UnexpectedOpCodeError)
from ..kering import Versionage, Version
from ..help.helping import sceil, nowIso8601

Serialage = namedtuple("Serialage", 'json mgpk cbor')

Serials = Serialage(json='JSON', mgpk='MGPK', cbor='CBOR')

Mimes = Serialage(json='application/keri+json',
                  mgpk='application/keri+msgpack',
                  cbor='application/keri+cbor',)

VERRAWSIZE = 6  # hex characters in raw serialization size in version string
# "{:0{}x}".format(300, 6)  # make num char in hex a variable
# '00012c'
VERFMT = "KERI{:x}{:x}{}{:0{}x}_"  #  version format string
VERFULLSIZE = 17  # number of characters in full versions string

def Versify(version=None, kind=Serials.json, size=0):
    """
    Return version string
    """
    if kind not in Serials:
        raise  ValueError("Invalid serialization kind = {}".format(kind))
    version = version if version else Version
    return VERFMT.format(version[0], version[1], kind, size, VERRAWSIZE)

Vstrings = Serialage(json=Versify(kind=Serials.json, size=0),
                     mgpk=Versify(kind=Serials.mgpk, size=0),
                     cbor=Versify(kind=Serials.cbor, size=0))


VEREX = b'KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'
Rever = re.compile(VEREX) #compile is faster
MINSNIFFSIZE = 12 + VERFULLSIZE  # min bytes in buffer to sniff else need more

def Deversify(vs):
    """
    Returns tuple(kind, version, size)
      Where:
        kind is serialization kind, one of Serials
                   json='JSON', mgpk='MGPK', cbor='CBOR'
        version is version tuple of type Version
        size is int of raw size

    Parameters:
      vs is version string str

    Uses regex match to extract:
        serialization kind
        keri version
        serialization size
    """
    match = Rever.match(vs.encode("utf-8"))  #  match takes bytes
    if match:
        major, minor, kind, size = match.group("major", "minor", "kind", "size")
        version = Versionage(major=int(major, 16), minor=int(minor, 16))
        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return(kind, version, size)

    raise ValueError("Invalid version string = {}".format(vs))

Ilkage = namedtuple("Ilkage", 'icp rot ixn dip drt rct vrc ksn')  # Event ilk (type of event)

Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt', rct='rct',
              vrc='vrc', ksn='ksn')


# Base64 utilities
BASE64_PAD = b'='

# Mappings between Base64 Encode Index and Decode Characters
#  B64ChrByIdx is dict where each key is a B64 index and each value is the B64 char
#  B64IdxByChr is dict where each key is a B64 char and each value is the B64 index
# Map Base64 index to char
B64ChrByIdx = dict((index, char) for index, char in enumerate([chr(x) for x in range(65, 91)]))
B64ChrByIdx.update([(index + 26, char) for index, char in enumerate([chr(x) for x in range(97, 123)])])
B64ChrByIdx.update([(index + 52, char) for index, char in enumerate([chr(x) for x in range(48, 58)])])
B64ChrByIdx[62] = '-'
B64ChrByIdx[63] = '_'
# Map char to Base64 index
B64IdxByChr = {char: index for index, char in B64ChrByIdx.items()}


def intToB64(i, l=1):
    """
    Returns conversion of int i to Base64 str
    l is min number of b64 digits left padded with Base64 0 == "A" char
    """
    d = deque()  # deque of characters base64
    d.appendleft(B64ChrByIdx[i % 64])
    i = i // 64
    while i:
        d.appendleft(B64ChrByIdx[i % 64])
        i = i // 64
    for j in range(l - len(d)):  # range(x)  x <= 0 means do not iterate
        d.appendleft("A")
    return ( "".join(d))


def intToB64b(i, l=1):
    """
    Returns conversion of int i to Base64 bytes
    l is min number of b64 digits left padded with Base64 0 == "A" char
    """
    return (intToB64(i=i, l=l).encode("utf-8"))


def b64ToInt(s):
    """
    Returns conversion of Base64 str s or bytes to int
    """
    if hasattr(s, 'decode'):
        s = s.decode("utf-8")
    i = 0
    for e, c in enumerate(reversed(s)):
        i |= B64IdxByChr[c] << (e * 6)  # same as i += B64IdxByChr[c] * (64 ** e)
    return i


def b64ToB2(s):
    """
    Returns conversion (decode) of Base64 chars to Base2 bytes.
    Where the number of total bytes returned is equal to the minimun number of
    octets sufficient to hold the total converted concatenated sextets from s,
    with one sextet per each Base64 decoded char of s. Assumes no pad chars in s.
    Sextets are left aligned with pad bits in last (rightmost) byte.
    This is useful for decoding as bytes, code characters from the front of
    a Base64 encoded string of characters.
    """
    i = b64ToInt(s)
    i <<= 2 * (len(s) % 4)  # add 2 bits right padding for each sextet
    n = sceil(len(s) * 3 / 4)  # compute min number of ocetets to hold all sextets
    return (i.to_bytes(n, 'big'))


def b2ToB64(b, l):
    """
    Returns conversion (encode) of l Base2 sextets from front of b to Base64 chars.
    One char for each of l sextets from front (left) of b.
    This is useful for encoding as code characters, sextets from the front of
    a Base2 bytes (byte string). Must provide l because of ambiguity between l=3
    and l=4. Both require 3 bytes in b.
    """
    if hasattr(b, 'encode'):
        b = b.encode("utf-8")  # convert to bytes
    n = sceil(l * 3 / 4)  # number of bytes needed for l sextets
    if n > len(b):
        raise ValueError("Not enough bytes in {} to nab {} sextets.".format(b, l))
    i = int.from_bytes(b[:n], 'big')
    i >>= 2 * (l % 4)  #  shift out padding bits make right aligned
    return (intToB64(i, l))


def nabSextets(b, l):
    """
    Return first l sextets from front (left) of b as bytes (byte string).
    Length of bytes returned is minimum sufficient to hold all l sextets.
    Last byte returned is right bit padded with zeros
    b is bytes or str
    """
    if hasattr(b, 'encode'):
        b = b.encode("utf-8")  # convert to bytes
    n = sceil(l * 3 / 4)  # number of bytes needed for l sextets
    if n > len(b):
        raise ValueError("Not enough bytes in {} to nab {} sextets.".format(b, l))
    i = int.from_bytes(b[:n], 'big')
    p = 2 * (l % 4)
    i >>= p  #  strip of last bits
    i <<= p  #  pad with empty bits
    return (i.to_bytes(n, 'big'))


def generateSigners(salt=None, count=8, transferable=True):
    """
    Returns list of Signers for Ed25519

    Parameters:
        salt is bytes 16 byte long root cryptomatter from which seeds for Signers
            in list are derived
            random salt created if not provided
        count is number of signers in list
        transferable is boolean true means signer.verfer code is transferable
                                non-transferable otherwise
    """
    if not salt:
        salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)

    signers = []
    for i in range(count):
        path = "{:x}".format(i)
        # algorithm default is argon2id
        seed = pysodium.crypto_pwhash(outlen=32,
                                      passwd=path,
                                      salt=salt,
                                      opslimit=pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                      memlimit=pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                      alg=pysodium.crypto_pwhash_ALG_DEFAULT)

        signers.append(Signer(raw=seed, transferable=transferable))

    return signers


def generateSecrets(salt=None, count=8):
    """
    Returns list of fully qualified Base64 secret seeds for Ed25519 private keys

    Parameters:
        salt is bytes 16 byte long root cryptomatter from which seeds for Signers
            in list are derived
            random salt created if not provided
        count is number of signers in list
    """
    signers = generateSigners(salt=salt, count=count)

    return [signer.qb64 for signer in signers]  #  fetch the qb64 as secret


@dataclass(frozen=True)
class CryNonTransCodex:
    """
    CryNonTransCodex is codex all non-transferable derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N:      str = 'B'  #  Ed25519 verification key non-transferable, basic derivation.
    ECDSA_256k1N:  str = "1AAA"  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    Ed448N:        str = "1AAC"  # Ed448 non-transferable prefix public signing verification key. Basic derivation.

    def __iter__(self):
        return iter(astuple(self))

CryNonTransDex = CryNonTransCodex()  #  Make instance


@dataclass(frozen=True)
class CryDigCodex:
    """
    CryDigCodex is codex all digest derivation codes. This is needed to ensure
    delegated inception using a self-addressing derivation i.e. digest derivation
    code.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Blake3_256:           str = 'E'  #  Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:          str = 'F'  #  Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:          str = 'G'  #  Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:             str = 'H'  #  SHA3 256 bit digest self-addressing derivation.
    SHA2_256:             str = 'I'  #  SHA2 256 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))

CryDigDex = CryDigCodex()  #  Make instance

# secret derivation security tier
Tierage = namedtuple("Tierage", 'low med high')

Tiers = Tierage(low='low', med='med', high='high')



@dataclass(frozen=True)
class MatterCodex:
    """
    MatterCodex is codex code (stable) part of all matter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Seed:         str = 'A'  # Ed25519 256 bit random seed for private key
    Ed25519N:             str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    X25519:               str = 'C'  # X25519 public encryption key, converted from Ed25519.
    Ed25519:              str = 'D'  # Ed25519 verification key basic derivation
    Blake3_256:           str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:          str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:          str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:             str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256:             str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    ECDSA_256k1_Seed:     str = 'J'  # ECDSA secp256k1 256 bit random Seed for private key
    Ed448_Seed:           str = 'K'  # Ed448 448 bit random Seed for private key
    X448:                 str = 'L'  # X448 public encryption key, converted from Ed448
    Short:                str = 'M'  # Short 2 byte number
    Salt_128:             str = '0A'  # 128 bit random seed or 128 bit number
    Ed25519_Sig:          str = '0B'  # Ed25519 signature.
    ECDSA_256k1_Sig:      str = '0C'  # ECDSA secp256k1 signature.
    Blake3_512:           str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:          str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:             str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:             str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    Long:                 str = '0H'  # Long 4 byte number
    ECDSA_256k1N:         str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:          str = '1AAB'  # Ed25519 public verification or encryption key, basic derivation
    Ed448N:               str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.
    Ed448:                str = '1AAD'  # Ed448 public signing verification key. Basic derivation.
    Ed448_Sig:            str = '1AAE'  # Ed448 signature. Self-signing derivation.
    Tag:                  str = '1AAF'  # Base64 4 char tag or 3 byte number.
    DateTime:             str = '1AAG'  # Base64 custom encoded 32 char ISO-8601 DateTime


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"

MtrDex = MatterCodex()

@dataclass(frozen=True)
class NonTransCodex:
    """
    NonTransCodex is codex all non-transferable derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N:      str = 'B'  #  Ed25519 verification key non-transferable, basic derivation.
    ECDSA_256k1N:  str = "1AAA"  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    Ed448N:        str = "1AAC"  # Ed448 non-transferable prefix public signing verification key. Basic derivation.

    def __iter__(self):
        return iter(astuple(self))

NonTransDex = NonTransCodex()  #  Make instance


@dataclass(frozen=True)
class DigCodex:
    """
    DigCodex is codex all digest derivation codes. This is needed to ensure
    delegated inception using a self-addressing derivation i.e. digest derivation
    code.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Blake3_256:           str = 'E'  #  Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:          str = 'F'  #  Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:          str = 'G'  #  Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:             str = 'H'  #  SHA3 256 bit digest self-addressing derivation.
    SHA2_256:             str = 'I'  #  SHA2 256 bit digest self-addressing derivation.
    Blake3_512:           str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:          str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:             str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:             str = '0G'  # SHA2 512 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))

DigDex =DigCodex()  #  Make instance


# namedtuple for size entries in matter derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# fs is the full size int number of chars in code plus appended material if any
Sizage = namedtuple("Sizage", "hs ss fs")

class Matter:
    """
    Matter is fully qualified cryptographic material primitive base class for
    non-indexed primitives.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise
        .digestive is Boolean, True when digest derivation code False otherwise

    Hidden:
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Codex = MtrDex
    # Sizes table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always 0 for Matter.
    Sizes = ({chr(c): 1 for c in range(65, 65+26)})  # size of hard part of code
    Sizes.update({chr(c): 1 for c in range(97, 97+26)})
    Sizes.update([('0', 2), ('1', 4), ('2', 5), ('3', 6), ('4', 8), ('5', 9), ('6', 10)])
    # Codes table maps to Sizage namedtuple of (hs, ss, fs) from hs chars of code
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be 0 for Matter
    Codes = {
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
            }
    # Bizes table maps to hard size, hs, of code from bytes holding sextets
    # converted from first code char. Used for ._bexfil.
    Bizes = ({b64ToB2(c): hs for c, hs in Sizes.items()})


    def __init__(self, raw=None, code=MtrDex.Ed25519N, qb64b=None, qb64=None,
                 qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            code is str of stable (hard) part of derivation code
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            strip is Boolean True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip



        Needs either (raw and code) or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign .raw and .code

        """
        if raw is not None:  #  raw provided
            if not code:
                raise EmptyMaterialError("Improper initialization need either "
                                         "(raw and code) or qb64b or qb64 or qb2.")
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))

            if code not in self.Codes:
                raise UnknownCodeError("Unsupported code={}.".format(code))

            #hs, ss, fs = self.Codes[code]  # get sizes
            #rawsize = (fs - (hs + ss)) * 3 // 4
            rawsize = Matter._rawSize(code)
            raw = raw[:rawsize]  # copy only exact size from raw stream
            if len(raw) != rawsize:  # forbids shorter
                raise RawMaterialError("Not enougth raw bytes for code={}"
                                             "expected {} got {}.".format(code,
                                                             rawsize,
                                                             len(raw)))

            self._code = code
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self.Codes[self.code].fs]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self.Codes[self.code].fs*3//4]

        else:
            raise EmptyMaterialError("Improper initialization need either "
                                     "(raw and code) or qb64b or qb64 or qb2.")


    @classmethod
    def _rawSize(cls, code):
        """
        Returns raw size in bytes for a given code
        """
        hs, ss, fs = cls.Codes[code]  # get sizes
        return ( (fs - (hs + ss)) * 3 // 4 )


    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code


    @property
    def raw(self):
        """
        Returns ._raw
        Makes .raw read only
        """
        return self._raw


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64b.decode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version Bytes
        """
        return self._binfil()


    @property
    def transferable(self):
        """
        Property transferable:
        Returns True if identifier does not have non-transferable derivation code,
                False otherwise
        """
        return(self.code not in NonTransDex)


    @property
    def digestive(self):
        """
        Property digestable:
        Returns True if identifier has digest derivation code,
                False otherwise
        """
        return(self.code in DigDex)


    def _infil(self):
        """
        Returns bytes of fully qualified base64 characters
        self.code + converted self.raw to Base64 with pad chars stripped
        """
        code = self.code  # codex value
        raw = self.raw  #  bytes or bytearray
        ps = (3 - (len(raw) % 3)) % 3  # pad size
        # check valid pad size for code size
        if len(code) % 4 != ps:  # pad size is not remainder of len(code) % 4
            raise InvalidCodeSizeError("Invalid code = {} for converted raw "
                                       "pad size= {}.".format(code, ps))
        # prepend derivation code and strip off trailing pad characters
        return (code.encode("utf-8") + encodeB64(raw)[:-ps if ps else None])


    def _exfil(self, qb64b):
        """
        Extracts self.code and self.raw from qualified base64 bytes qb64b
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material, Need more characters.")

        first = qb64b[:1]  # extract first char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Sizes:
            if first[0] == '-':
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                               "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start char={}.".format(first))

        cs = self.Sizes[first]  # get hard code size
        if len(qb64b) < cs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(cs-len(qb64b)))

        code = qb64b[:cs]  # extract hard code
        if hasattr(code, "decode"):
            code = code.decode("utf-8")
        if code not in self.Codes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(code))

        hs, ss, fs = self.Codes[code]
        bs = hs + ss  # both hs and ss
        # assumes that unit tests on Matter and MatterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs == cs and ss == 0 and not fs % 4 and hs > 0 and fs > hs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError("Need {} more chars.".format(fs-len(qb64b)))
        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # strip off prepended code and append pad characters
        ps = bs % 4  # pad size ps = bs mod 4
        base = qb64b[bs:] + ps * BASE64_PAD
        raw = decodeB64(base)
        if len(raw) != (len(qb64b) - bs) * 3 // 4:  # exact lengths
            raise ConversionError("Improperly qualified material = {}".format(qb64b))

        self._code = code
        self._raw = raw


    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 + self.raw left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex value
        raw = self.raw  #  bytes or bytearray

        hs, ss, fs = self.Codes[code]
        bs = hs + ss
        if len(code) != bs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                          .format(bs, len(code)))
        n = sceil(bs * 3 / 4)  # number of b2 bytes to hold b64 code
        bcode = b64ToInt(code).to_bytes(n,'big')  # right aligned b2 code

        full = bcode + raw
        bfs = len(full)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError("Invalid code = {} for raw size= {}."
                                          .format(code, len(raw)))

        i = int.from_bytes(full, 'big') << (2 * (bs % 4))  # left shift in pad bits
        return (i.to_bytes(bfs, 'big'))


    def _bexfil(self, qb2):
        """
        Extracts self.code and self.raw from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 1)  # extract first sextet as code selector
        if first not in self.Bizes:
            if first[0] == b'\xf8':  # b64ToB2('-')
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == b'\xfc':  #  b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                               "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        cs = self.Bizes[first]  # get code hard size equvalent sextets
        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs-len(qb2)))

        # bode = nabSextets(qb2, cs)  # b2 version of hard part of code
        code = b2ToB64(qb2, cs)  # extract and convert hard part of code
        if code not in self.Codes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(code))

        hs, ss, fs = self.Codes[code]
        bs = hs + ss  # both hs and ss
        # assumes that unit tests on Matter and MatterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs == cs and ss == 0 and not fs % 4 and hs > 0 and fs > hs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs-len(qb2)))
        qb2 = qb2[:bfs]  # fully qualified primitive code plus material

        # right shift to right align raw material
        i = int.from_bytes(qb2, 'big')
        i >>= 2 * (bs % 4)
        bbs = ceil(bs * 3 / 4)  # bbs is min bytes to hold bs sextets
        raw = i.to_bytes(bfs, 'big')[bbs:]  # extract raw

        if len(raw) != (len(qb2) - bbs):  # exact lengths
            raise ConversionError("Improperly qualified material = {}".format(qb2))

        self._code = code
        self._raw = raw


class Seqner(Matter):
    """
    Seqner is subclass of Matter, cryptographic material, for ordinal numbers
    such as sequence numbers or first seen ordering numbers.
    Seqner provides fully qualified format for ordinals (sequence numbers etc)
    when provided as attached cryptographic material elements.

    Useful when parsing attached receipt groupings with sn from stream or database

    Uses default initialization code = CryTwoDex.Salt_128
    Raises error on init if code not CryTwoDex.Salt_128

    Attributes:

    Inherited Properties:  (See Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:
        .sn is int sequence number
        .snh is hex string representation of sequence number no leading zeros

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64


    Methods:


    """
    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None,
                 code=MtrDex.Salt_128, sn=None, snh=None, **kwa):
        """
        Inhereited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes


        Parameters:
            sn is int sequence number
            snh is hex string of sequence number

        """
        if sn is None:
            if snh is None:
                sn = 0
            else:
                sn = int(snh, 16)

        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            raw = sn.to_bytes(Matter._rawSize(MtrDex.Salt_128), 'big')

        super(Seqner, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                         code=code, **kwa)

        if self.code != MtrDex.Salt_128:
            raise ValidationError("Invalid code = {} for SeqNumber."
                                  "".format(self.code))

    @property
    def sn(self):
        """
        Property sn:
        Returns .raw converted to int
        """
        return int.from_bytes(self.raw, 'big')

    @property
    def snh(self):
        """
        Property snh:
        Returns .raw converted to hex str
        """
        return "{:x}".format(self.sn)


class Dater(Matter):
    """
    Dater is subclass of Matter, cryptographic material, for ISO-8601 datetimes.
    Dater provides a custom Base64 coding of an ASCII ISO-8601 datetime by replacing
    the three non-Base64 characters ':.+' with the Base64 equivalents 'cdp'.
    Dater provides a more compact representation than would be obtained by converting
    the raw ASCII ISO-8601 datetime to Base64.
    Dater supports datetimes as attached crypto material in replay of events for
    the datetime of when the event was first seen.
    Restricted to specific 32 byte variant of ISO-8601 date time with microseconds
    and UTC offset in HH:MM. For example:

    '2020-08-22T17:50:09.988921+00:00'
    '2020-08-22T17:50:09.988921-01:00'

    The fully encoded versions are respectively

    '1AAG2020-08-22T17c50c09d988921p00c00'
    '1AAG2020-08-22T17c50c09d988921-01c00'

    Useful when parsing attached first seen couples with fn  + dt

    Uses default initialization code = MtrDex.DateTime
    Raises error on init if code not  MtrDex.DateTime

    Attributes:

    Inherited Properties:  (See Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:
        .dts is the ISO-8601 datetime string

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    Methods:

    """
    ToB64 = str.maketrans(":.+", "cdp")
    FromB64 = str.maketrans("cdp", ":.+")

    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None,
                 code=MtrDex.Salt_128, dts=None, **kwa):
        """
        Inhereited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            dt the ISO-8601 datetime as str or bytes
        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            if dts is None:  # defaults to now
                dts = nowIso8601()
            if len(dts) != 32:
                raise ValueError("Invalid length of date time string")
            if hasattr(dts, "decode"):
                dts = dts.decode("utf-8")
            qb64 = MtrDex.DateTime + dts.translate(self.ToB64)

        super(Dater, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                         code=code, **kwa)
        if self.code != MtrDex.DateTime:
            raise ValidationError("Invalid code = {} for Dater date time."
                                  "".format(self.code))

    @property
    def dts(self):
        """
        Property sn:
        Returns .qb64 translated to ISO 8601 DateTime str
        """
        return self.qb64[self.Codes[self.code].hs:].translate(self.FromB64)

    @property
    def dtsb(self):
        """
        Property sn:
        Returns .qb64 translated to ISO 8601 DateTime bytes
        """
        return self.qb64[self.Codes[self.code].hs:].translate(self.FromB64).encode("utf-8")


class Verfer(Matter):
    """
    Verfer is Matter subclass with method to verify signature of serialization
    using the .raw as verifier key and .code for signature cipher suite.

    See Matter for inherited attributes and properties:

    Attributes:

    Properties:

    Methods:
        verify: verifies signature

    """
    def __init__(self, **kwa):
        """
        Assign verification cipher suite function to ._verify

        """
        super(Verfer, self).__init__(**kwa)

        if self.code in [MtrDex.Ed25519N, MtrDex.Ed25519]:
            self._verify = self._ed25519
        else:
            raise ValueError("Unsupported code = {} for verifier.".format(self.code))


    def verify(self, sig, ser):
        """
        Returns True if bytes signature sig verifies on bytes serialization ser
        using .raw as verifier public key for ._verify cipher suite determined
        by .code

        Parameters:
            sig is bytes signature
            ser is bytes serialization
        """
        return (self._verify(sig=sig, ser=ser, key=self.raw))

    @staticmethod
    def _ed25519(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verifiy ed25519 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        try:  # verify returns None if valid else raises ValueError
            pysodium.crypto_sign_verify_detached(sig, ser, key)
        except Exception as ex:
            return False

        return True


class Cigar(Matter):
    """
    Cigar is Matter subclass holding a nonindexed signature with verfer property.
        From Matter .raw is signature and .code is signature cipher suite
    Adds .verfer property to hold Verfer instance of associated verifier public key
        Verfer's .raw as verifier key and .code is verifier cipher suite.

    See Matter for inherited attributes and properties:

    Attributes:

    Inherited Properties:
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:
        .verfer is verfer of public key used to verify signature


    Methods:

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    def __init__(self, verfer=None, **kwa):
        """
        Assign verfer to ._verfer attribute

        """
        super(Cigar, self).__init__(**kwa)

        self._verfer = verfer


    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    @verfer.setter
    def verfer(self, verfer):
        """ verfer property setter """
        self._verfer = verfer


class Signer(Matter):
    """
    Signer is Matter subclass with method to create signature of serialization
    using the .raw as signing (private) key seed, .code as cipher suite for
    signing and new property .verfer whose property .raw is public key for signing.
    If not provided .verfer is generated from private key seed using .code
    as cipher suite for creating key-pair.


    See Matter for inherited attributes and properties:

    Attributes:

    Properties:
        .verfer is Verfer object instance

    Methods:
        sign: create signature

    """
    def __init__(self,raw=None, code=MtrDex.Ed25519_Seed, transferable=True, **kwa):
        """
        Assign signing cipher suite function to ._sign

        Parameters:  See Matter for inherted parameters
            raw is bytes crypto material seed or private key
            code is derivation code
            transferable is Boolean True means verifier code is transferable
                                    False othersize non-transerable

        """
        try:
            super(Signer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == MtrDex.Ed25519_Seed:
                raw = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
                super(Signer, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise ValueError("Unsupported signer code = {}.".format(code))

        if self.code == MtrDex.Ed25519_Seed:
            self._sign = self._ed25519
            verkey, sigkey = pysodium.crypto_sign_seed_keypair(self.raw)
            verfer = Verfer(raw=verkey,
                                code=MtrDex.Ed25519 if transferable
                                                    else MtrDex.Ed25519N )
        else:
            raise ValueError("Unsupported signer code = {}.".format(self.code))

        self._verfer = verfer

    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    def sign(self, ser, index=None):
        """
        Returns either Cigar or Siger (indexed) instance of cryptographic
        signature material on bytes serialization ser

        If index is None
            return Cigar instance
        Else
            return Siger instance

        Parameters:
            ser is bytes serialization
            index is int index of associated verifier key in event keys
        """
        return (self._sign(ser=ser,
                           seed=self.raw,
                           verfer=self.verfer,
                           index=index))

    @staticmethod
    def _ed25519(ser, seed, verfer, index):
        """
        Returns signature


        Parameters:
            ser is bytes serialization
            seed is bytes seed (private key)
            verfer is Verfer instance. verfer.raw is public key
            index is index of offset into signers list or None

        """
        sig = pysodium.crypto_sign_detached(ser, seed + verfer.raw)
        if index is None:
            return Cigar(raw=sig, code=MtrDex.Ed25519_Sig, verfer=verfer)
        else:
            return Siger(raw=sig,
                          code=IdrDex.Ed25519_Sig,
                          index=index,
                          verfer=verfer)


class Salter(Matter):
    """
    Salter is Matter subclass to maintain random salt for secrets (private keys)
    Its .raw is random salt, .code as cipher suite for salt

    Attributes:
        .level is str security level code. Provides default level

    Inherited Properties
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:

    Methods:

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Tier = Tiers.low

    def __init__(self, raw=None, code=MtrDex.Salt_128, tier=None, **kwa):
        """
        Initialize salter's raw and code

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:

        """
        try:
            super(Salter, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == MtrDex.Salt_128:
                raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
                super(Salter, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise ValueError("Unsupported salter code = {}.".format(code))

        if self.code not in (MtrDex.Salt_128, ):
            raise ValueError("Unsupported salter code = {}.".format(self.code))

        self.tier = tier if tier is not None else self.Tier


    def signer(self, path="", tier=None, code=MtrDex.Ed25519_Seed,
               transferable=True, temp=False):
        """
        Returns Signer instance whose .raw secret is derived from path and
        salter's .raw and stretched to size given by code. The signers public key
        for its .verfer is derived from code and transferable.

        Parameters:
            path is str of unique chars used in derivation of secret seed for signer
            code is str code of secret crypto suite
            transferable is Boolean, True means use transferace code for public key
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use more time to stretch
        """
        tier = tier if tier is not None else self.tier

        if temp:
            opslimit = pysodium.crypto_pwhash_OPSLIMIT_MIN
            memlimit = pysodium.crypto_pwhash_MEMLIMIT_MIN
        else:
            if tier == Tiers.low:
                opslimit = pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
                memlimit = pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
            elif tier == Tiers.med:
                opslimit = pysodium.crypto_pwhash_OPSLIMIT_MODERATE
                memlimit = pysodium.crypto_pwhash_MEMLIMIT_MODERATE
            elif tier == Tiers.high:
                opslimit = pysodium.crypto_pwhash_OPSLIMIT_SENSITIVE
                memlimit = pysodium.crypto_pwhash_MEMLIMIT_SENSITIVE
            else:
                raise ValueError("Unsupported security tier = {}.".format(tier))

         # stretch algorithm is argon2id
        seed = pysodium.crypto_pwhash(outlen=Matter._rawSize(code),
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_DEFAULT)

        return (Signer(raw=seed, code=code, transferable=transferable))


class Diger(Matter):
    """
    Diger is Matter subclass with method to verify digest of serialization
    using  .raw as digest and .code for digest algorithm.

    See Matter for inherited attributes and properties:

    Inherited Properties:
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Methods:
        verify: verifies digest given ser
        compare: compares provide digest given ser to this digest of ser.
                enables digest agility of different digest algos to compare.

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    def __init__(self, raw=None, ser=None, code=MtrDex.Blake3_256, **kwa):
        """
        Assign digest verification function to ._verify

        See Matter for inherited parameters

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
           ser is bytes serialization from which raw is computed if not raw

        """
        try:
            super(Diger, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not ser:
                raise ex
            if code == MtrDex.Blake3_256:
                dig = blake3.blake3(ser).digest()
            elif code == MtrDex.Blake2b_256:
                dig = hashlib.blake2b(ser, digest_size=32).digest()
            elif code == MtrDex.Blake2s_256:
                dig = hashlib.blake2s(ser, digest_size=32).digest()
            elif code == MtrDex.SHA3_256:
                dig = hashlib.sha3_256(ser).digest()
            elif code == MtrDex.SHA2_256:
                dig = hashlib.sha256(ser).digest()
            else:
                raise ValueError("Unsupported code = {} for digester.".format(code))

            super(Diger, self).__init__(raw=dig, code=code, **kwa)

        if self.code == MtrDex.Blake3_256:
            self._verify = self._blake3_256
        elif self.code == MtrDex.Blake2b_256:
            self._verify = self._blake2b_256
        elif self.code == MtrDex.Blake2s_256:
            self._verify = self._blake2s_256
        elif self.code == MtrDex.SHA3_256:
            self._verify = self._sha3_256
        elif self.code == MtrDex.SHA2_256:
            self._verify = self._sha2_256
        else:
            raise ValueError("Unsupported code = {} for digester.".format(self.code))


    def verify(self, ser):
        """
        Returns True if digest of bytes serialization ser matches .raw
        using .raw as reference digest for ._verify digest algorithm determined
        by .code

        Parameters:
            ser is bytes serialization
        """
        return (self._verify(ser=ser, raw=self.raw))


    def compare(self, ser, dig=None, diger=None):
        """
        Returns True  if dig and .qb64 or .qb64b match or
            if both .raw and dig are valid digests of ser
            Otherwise returns False

        Parameters:
            ser is bytes serialization
            dig is qb64b or qb64 digest of ser to compare with self
            diger is Diger instance of digest of ser to compare with self

            if both supplied dig takes precedence


        If both match then as optimization returns True and does not verify either
          as digest of ser
        Else If both have same code but do not match then as optimization returns False
           and does not verify if either is digest of ser
        Else recalcs both digests using each one's code to verify they
            they are both digests of ser regardless of matching codes.
        """
        if dig is not None:
            if hasattr(dig, "encode"):
                dig = dig.encode('utf-8')  #  makes bytes

            if dig == self.qb64b:  #  matching
                return True

            diger = Diger(qb64b=dig)  # extract code

        elif diger is not None:
            if diger.qb64b == self.qb64b:
                return True

        else:
            raise ValueError("Both dig and diger may not be None.")

        if diger.code == self.code: # digest not match but same code
            return False

        if diger.verify(ser=ser) and self.verify(ser=ser):  # both verify on ser
            return True

        return (False)


    @staticmethod
    def _blake3_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake3_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return(blake3.blake3(ser).digest() == raw)

    @staticmethod
    def _blake2b_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2b_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return(hashlib.blake2b(ser, digest_size=32).digest() == raw)

    @staticmethod
    def _blake2s_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2s_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return(hashlib.blake2s(ser, digest_size=32).digest() == raw)

    @staticmethod
    def _sha3_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2s_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return(hashlib.sha3_256(ser).digest() == raw)

    @staticmethod
    def _sha2_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2s_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return(hashlib.sha256(ser).digest() == raw)



class Nexter(Matter):
    """
    Nexter is Matter subclass with support to derive itself from
    next sith and next keys given code.

    See Diger for inherited attributes and properties:

    Attributes:

    Inherited Properties:
        .code  str derivation code to indicate cypher suite
        .raw   bytes crypto material only without code
        .pad  int number of pad chars given raw
        .qb64 str in Base64 fully qualified with derivation code + crypto mat
        .qb64b bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  bytes in binary with derivation code + crypto material
        .nontrans True when non-transferable derivation code False otherwise

    Properties:

    Methods:

    Hidden:
        ._digest is digest method
        ._derive is derivation method


    """
    def __init__(self, limen=None, sith=None, digs=None, keys=None, ked=None,
                 code=MtrDex.Blake3_256, **kwa):
        """
        Assign digest verification function to ._verify

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
           limen is string extracted from sith expression in event
           sith is int threshold or lowercase hex str no leading zeros
           digs is list of qb64 digests of public keys
           keys is list of keys each is qb64 public key str
           ked is key event dict

           Raises error if not any of raw, digs,keys, ked

           if not raw
               use digs
               If digs not provided
                  use keys
                  if keys not provided
                     get keys from ked
                  compute digs from keys

           If sith not provided
               get sith from ked
               but if not ked then compute sith as simple majority of keys

        """
        try:
            super(Nexter, self).__init__(code=code, **kwa)
        except EmptyMaterialError as ex:
            if not digs and not keys and not ked:
                raise ex
            if code == MtrDex.Blake3_256:
                self._digest = self._blake3_256
            else:
                raise ValueError("Unsupported code = {} for nexter.".format(code))

            raw = self._derive(code=code, limen=limen, sith=sith, digs=digs,
                               keys=keys, ked=ked)  #  derive nxt raw
            super(Nexter, self).__init__(raw=raw, code=code, **kwa)  # attaches code etc

        else:
            if self.code == MtrDex.Blake3_256:
                self._digest = self._blake3_256
            else:
                raise ValueError("Unsupported code = {} for nexter.".format(code))


    def verify(self, raw=b'', limen=None, sith=None, digs=None, keys=None, ked=None):
        """
        Returns True if digest of bytes nxt raw matches .raw
        Uses .raw as reference nxt raw for ._verify algorithm determined by .code

        If raw not provided then extract raw from either (sith, keys) or ked

        Parameters:
            raw is bytes serialization
            sith is str lowercase hex
            keys is list of keys qb64
            ked is key event dict
        """
        if not raw:
            raw = self._derive(code=self.code, limen=limen, sith=sith, digs=digs,
                               keys=keys, ked=ked)

        return (raw == self.raw)


    def _derive(self, code, limen=None, sith=None, digs=None, keys=None, ked=None):
        """
        Returns ser where ser is serialization derived from code, sith, keys, or ked
        """
        if not digs:
            if not keys:
                try:
                    keys = ked["k"]
                except KeyError as ex:
                    raise DerivationError("Error extracting keys from"
                                          " ked = {}".format(ex))

            if not keys:  # empty keys
                raise DerivationError("Empty keys.")

            keydigs = [self._digest(key.encode("utf-8")) for key in keys]

        else:
            digers = [Diger(qb64=dig) for dig in digs]
            for diger in digers:
                if diger.code != code:
                    raise DerivationError("Mismatch of public key digest "
                                          "code = {} for next digest code = {}."
                                          "".format(diger.code, code))
            keydigs = [diger.raw for diger in digers]

        if limen is None:  # compute default limen
            if sith is None:  # need len keydigs to compute default sith
                try:
                    sith = ked["kt"]
                except Exception as ex:
                    # default simple majority
                    sith = "{:x}".format(max(1, ceil(len(keydigs) / 2)))

            limen = Tholder(sith=sith).limen

        kints = [int.from_bytes(keydig, 'big') for keydig in keydigs]
        sint = int.from_bytes(self._digest(limen.encode("utf-8")), 'big')
        for kint in kints:
            sint ^= kint  # xor together

        return (sint.to_bytes(Matter._rawSize(code), 'big'))


    @staticmethod
    def _blake3_256(raw):
        """
        Returns digest of raw using Blake3_256

        Parameters:
            raw is bytes serialization of nxt raw
        """
        return(blake3.blake3(raw).digest())



class Prefixer(Matter):
    """
    Prefixer is Matter subclass for autonomic identifier prefix using
    derivation as determined by code from ked

    Attributes:

    Inherited Properties:  (see Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:

    Methods:
        verify():  Verifies derivation of aid prefix from a ked

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64
    """
    Dummy = "#"  # dummy spaceholder char for pre. Must not be a valid Base64 char
    # element labels to exclude in digest or signature derivation from inception icp
    IcpExcludes = ["i"]
    # element labels to exclude in digest or signature derivation from delegated inception dip
    DipExcludes = ["i"]

    def __init__(self, raw=None, code=None, ked=None,
                 seed=None, secret=None, **kwa):
        """
        assign ._derive to derive derivatin of aid prefix from ked
        assign ._verify to verify derivation of aid prefix  from ked

        Default code is None to force EmptyMaterialError when only raw provided but
        not code.

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            seed is bytes seed when signature derivation
            secret is qb64 when signature derivation when applicable
               one of seed or secret must be provided when signature derivation

        """
        try:
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not  ked or (not code and "i" not in ked):
                raise  ex

            if not code:  # get code from pre in ked
                super(Prefixer, self).__init__(qb64=ked["i"], code=code, **kwa)
                code = self.code

            if code == MtrDex.Ed25519N:
                self._derive = self._derive_ed25519N
            elif code == MtrDex.Ed25519:
                self._derive = self._derive_ed25519
            elif code == MtrDex.Blake3_256:
                self._derive = self._derive_blake3_256
            elif code == MtrDex.Ed25519_Sig:
                self._derive = self._derive_sig_ed25519
            else:
                raise ValueError("Unsupported code = {} for prefixer.".format(code))

            # use ked and ._derive from code to derive aid prefix and code
            raw, code = self._derive(ked=ked, seed=seed, secret=secret)
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)

        if self.code == MtrDex.Ed25519N:
            self._verify = self._verify_ed25519N
        elif self.code == MtrDex.Ed25519:
            self._verify = self._verify_ed25519
        elif self.code == MtrDex.Blake3_256:
            self._verify = self._verify_blake3_256
        elif code == MtrDex.Ed25519_Sig:
            self._verify = self._verify_sig_ed25519
        else:
            raise ValueError("Unsupported code = {} for prefixer.".format(self.code))


    def derive(self, ked, seed=None, secret=None):
        """
        Returns tuple (raw, code) of aid prefix as derived from key event dict ked.
                uses a derivation code specific _derive method

        Parameters:
            ked is inception key event dict
            seed is only used for sig derivation it is the secret key/secret

        """
        if ked["t"] not in (Ilks.icp, Ilks.dip):
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ked["t"]))
        return (self._derive(ked=ked, seed=seed, secret=secret))


    def verify(self, ked, prefixed=False):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        Parameters:
            ked is inception key event dict
        """
        if ked["t"] not in (Ilks.icp, Ilks.dip):
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ked["t"]))
        return (self._verify(ked=ked, pre=self.qb64, prefixed=prefixed))


    def _derive_ed25519N(self, ked, seed=None, secret=None):
        """
        Returns tuple (raw, code) of basic nontransferable Ed25519 prefix (qb64)
            as derived from inception key event dict ked keys[0]
        """
        ked = dict(ked)  # make copy so don't clobber original ked
        try:
            keys = ked["k"]
            if len(keys) != 1:
                raise DerivationError("Basic derivation needs at most 1 key "
                                      " got {} keys instead".format(len(keys)))
            verfer = Verfer(qb64=keys[0])
        except Exception as ex:
            raise DerivationError("Error extracting public key ="
                                  " = {}".format(ex))

        if verfer.code not in [MtrDex.Ed25519N]:
            raise DerivationError("Mismatch derivation code = {}."
                                  "".format(verfer.code))

        try:
            if verfer.code == MtrDex.Ed25519N and ked["n"]:
                raise DerivationError("Non-empty nxt = {} for non-transferable"
                                      " code = {}".format(ked["n"],
                                                          verfer.code))
        except Exception as ex:
            raise DerivationError("Error checking nxt = {}".format(ex))

        return (verfer.raw, verfer.code)


    def _verify_ed25519N(self, ked, pre, prefixed=False):
        """
        Returns True if verified  False otherwise
        Verify derivation of fully qualified Base64 pre from inception iked dict

        Parameters:
            ked is inception key event dict
            pre is Base64 fully qualified prefix default to .qb64
        """
        try:
            keys = ked["k"]
            if len(keys) != 1:
                return False

            if keys[0] != pre:
                return False

            if prefixed and ked["i"] != pre:
                return False

            if ked["n"]:  # must be empty
                return False

        except Exception as ex:
            return False

        return True


    def _derive_ed25519(self, ked, seed=None, secret=None):
        """
        Returns tuple (raw, code) of basic Ed25519 prefix (qb64)
            as derived from inception key event dict ked keys[0]
        """
        ked = dict(ked)  # make copy so don't clobber original ked
        try:
            keys = ked["k"]
            if len(keys) != 1:
                raise DerivationError("Basic derivation needs at most 1 key "
                                      " got {} keys instead".format(len(keys)))
            verfer = Verfer(qb64=keys[0])
        except Exception as ex:
            raise DerivationError("Error extracting public key ="
                                  " = {}".format(ex))

        if verfer.code not in [MtrDex.Ed25519]:
            raise DerivationError("Mismatch derivation code = {}"
                                  "".format(verfer.code))

        return (verfer.raw, verfer.code)


    def _verify_ed25519(self, ked, pre, prefixed=False):
        """
        Returns True if verified False otherwise
        Verify derivation of fully qualified Base64 prefix from
        inception key event dict (ked)

        Parameters:
            ked is inception key event dict
            pre is Base64 fully qualified prefix default to .qb64
        """
        try:
            keys = ked["k"]
            if len(keys) != 1:
                return False

            if keys[0] != pre:
                return False

            if prefixed and ked["i"] != pre:
                return False

        except Exception as ex:
            return False

        return True


    def _derive_blake3_256(self, ked, seed=None, secret=None):
        """
        Returns tuple (raw, code) of basic Ed25519 pre (qb64)
            as derived from inception key event dict ked
        """
        ked = dict(ked)  # make copy so don't clobber original ked
        ilk = ked["t"]
        if ilk == Ilks.icp:
            labels = [key for key in ked if key not in self.IcpExcludes]
        elif ilk == Ilks.dip:
            labels = [key for key in ked if key not in self.DipExcludes]
        else:
            raise DerivationError("Invalid ilk = {} to derive pre.".format(ilk))

        # put in dummy pre to get size correct
        ked["i"] = "{}".format(self.Dummy*Matter.Codes[MtrDex.Blake3_256].fs)
        serder = Serder(ked=ked)
        ked = serder.ked  # use updated ked with valid vs element

        for l in labels:
            if l not in ked:
                raise DerivationError("Missing element = {} from ked.".format(l))

        dig =  blake3.blake3(serder.raw).digest()
        return (dig, MtrDex.Blake3_256)


    def _verify_blake3_256(self, ked, pre, prefixed=False):
        """
        Returns True if verified False otherwise
        Verify derivation of fully qualified Base64 prefix from
        inception key event dict (ked)

        Parameters:
            ked is inception key event dict
            pre is Base64 fully qualified default to .qb64
        """
        try:
            raw, code =  self._derive_blake3_256(ked=ked)
            crymat = Matter(raw=raw, code=MtrDex.Blake3_256)
            if crymat.qb64 != pre:
                return False

            if prefixed and ked["i"] != pre:
                return False

        except Exception as ex:
            return False

        return True


    def _derive_sig_ed25519(self, ked, seed=None, secret=None):
        """
        Returns tuple (raw, code) of basic Ed25519 pre (qb64)
            as derived from inception key event dict ked
        """
        ked = dict(ked)  # make copy so don't clobber original ked
        ilk = ked["t"]
        if ilk == Ilks.icp:
            labels = [key for key in ked if key not in self.IcpExcludes]
        elif ilk == Ilks.dip:
            labels = [key for key in ked if key not in self.DipExcludes]
        else:
            raise DerivationError("Invalid ilk = {} to derive pre.".format(ilk))

        # put in dummy pre to get size correct
        ked["i"] = "{}".format(self.Dummy*Matter.Codes[MtrDex.Ed25519_Sig].fs)
        serder = Serder(ked=ked)
        ked = serder.ked  # use updated ked with valid vs element

        for l in labels:
            if l not in ked:
                raise DerivationError("Missing element = {} from ked.".format(l))

        try:
            keys = ked["k"]
            if len(keys) != 1:
                raise DerivationError("Basic derivation needs at most 1 key "
                                      " got {} keys instead".format(len(keys)))
            verfer = Verfer(qb64=keys[0])
        except Exception as ex:
            raise DerivationError("Error extracting public key ="
                                  " = {}".format(ex))

        if verfer.code not in [MtrDex.Ed25519]:
            raise DerivationError("Invalid derivation code = {}"
                                  "".format(verfer.code))

        if not (seed or secret):
            raise DerivationError("Missing seed or secret.")

        signer = Signer(raw=seed, qb64=secret)

        if verfer.raw != signer.verfer.raw:
            raise DerivationError("Key in ked not match seed.")

        cigar = signer.sign(ser=serder.raw)

        # sig = pysodium.crypto_sign_detached(ser, signer.raw + verfer.raw)

        return (cigar.raw, MtrDex.Ed25519_Sig)


    def _verify_sig_ed25519(self, ked, pre, prefixed=False):
        """
        Returns True if verified False otherwise
        Verify derivation of fully qualified Base64 prefix from
        inception key event dict (ked)

        Parameters:
            ked is inception key event dict
            pre is Base64 fully qualified prefix default to .qb64
        """
        try:
            dked = dict(ked)  # make copy so don't clobber original ked
            ilk = dked["t"]
            if ilk == Ilks.icp:
                labels = [key for key in dked if key not in self.IcpExcludes]
            elif ilk == Ilks.dip:
                labels = [key for key in dked if key not in self.DipExcludes]
            else:
                raise DerivationError("Invalid ilk = {} to derive prefix.".format(ilk))

            # put in dummy pre to get size correct
            dked["i"] = "{}".format(self.Dummy*Matter.Codes[MtrDex.Ed25519_Sig].fs)
            serder = Serder(ked=dked)
            dked = serder.ked  # use updated ked with valid vs element

            for l in labels:
                if l not in dked:
                    raise DerivationError("Missing element = {} from ked.".format(l))

            try:
                keys = dked["k"]
                if len(keys) != 1:
                    raise DerivationError("Basic derivation needs at most 1 key "
                                          " got {} keys instead".format(len(keys)))
                verfer = Verfer(qb64=keys[0])
            except Exception as ex:
                raise DerivationError("Error extracting public key ="
                                      " = {}".format(ex))

            if verfer.code not in [MtrDex.Ed25519]:
                raise DerivationError("Mismatched derivation code = {}"
                                      "".format(verfer.code))

            if prefixed and ked["i"] != pre:
                return False

            cigar = Cigar(qb64=pre, verfer=verfer)

            result = cigar.verfer.verify(sig=cigar.raw, ser=serder.raw)
            return result

            #try:  # verify returns None if valid else raises ValueError
                #result = pysodium.crypto_sign_verify_detached(sig, ser, verfer.raw)
            #except Exception as ex:
                #return False

        except Exception as ex:
            return False

        return True


@dataclass(frozen=True)
class IndexerCodex:
    """
    IndexerCodex is codex hard (stable) part of all indexer derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Sig:        str = 'A'  # Ed25519 signature.
    ECDSA_256k1_Sig:    str = 'B'  # ECDSA secp256k1 signature.
    Ed448_Sig:          str = '0A'  # Ed448 signature.
    Label:              str = '0B'  # Variable len bytes label L=N*4 <= 4095 char quadlets

    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"

IdrDex = IndexerCodex()


@dataclass(frozen=True)
class IndexedSigCodex:
    """
    IndexedSigCodex is codex all indexed signature derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Sig:        str = 'A'  # Ed25519 signature.
    ECDSA_256k1_Sig:    str = 'B'  # ECDSA secp256k1 signature.
    Ed448_Sig:          str = '0A'  # Ed448 signature.

    def __iter__(self):
        return iter(astuple(self))

IdxSigDex = IndexedSigCodex()  #  Make instance


class Indexer:
    """
    Indexer is fully qualified cryptographic material primitive base class for
    indexed primitives.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .pad  is int number of pad chars given raw
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material

    Hidden:
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._pad is method to compute  .pad property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Codex = IdrDex
    # Sizes table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always > 0 for Indexer.
    Sizes = ({chr(c): 1 for c in range(65, 65+26)})
    Sizes.update({chr(c): 1 for c in range(97, 97+26)})
    Sizes.update([('0', 2), ('1', 2), ('2', 2), ('3', 2), ('4', 3), ('5', 4)])
    # Codes table maps hs chars of code to Sizage namedtuple of (hs, ss, fs)
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be  > 0 for Indexer
    Codes = {
                'A': Sizage(hs=1, ss=1, fs=88),
                'B': Sizage(hs=1, ss=1, fs=88),
                '0A': Sizage(hs=2, ss=2, fs=156),
                '0B': Sizage(hs=2, ss=2, fs=None),
            }
    # Bizes table maps to hard size, hs, of code from bytes holding sextets
    # converted from first code char. Used for ._bexfil.
    Bizes = ({b64ToB2(c): hs for c, hs in Sizes.items()})

    def __init__(self, raw=None, code=IdrDex.Ed25519_Sig, index=0,
                 qb64b=None, qb64=None, qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            code is str of stable (hard) part of derivation code
            index is int of offset index into key or id list or length of material
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            strip is Boolean True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip

        Needs either (raw and code and index) or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code and index provided then validate that code is correct
        for length of raw  and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign
        .raw and .code and .index

        """
        if raw is not None:  #  raw provided
            if not code:
                raise EmptyMaterialError("Improper initialization need either "
                                         "(raw and code) or qb64b or qb64 or qb2.")
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))

            if code not in self.Codes:
                raise UnexpectedCodeError("Unsupported code={}.".format(code))

            hs, ss, fs = self.Codes[code] # get sizes for code
            bs = hs + ss  # both hard + soft code size
            if index < 0 or index > (64 ** ss - 1):
                raise InvalidCodeIndexError("Invalid index={} for code={}.".format(index, code))

            if not fs:  # compute fs from index
                if bs % 4:
                    raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                          "variable length material. bs={}.".format(bs))
                fs = (index * 4) + bs

            rawsize = (fs - bs) * 3 // 4

            raw = raw[:rawsize]  # copy only exact size from raw stream
            if len(raw) != rawsize:  # forbids shorter
                raise RawMaterialError("Not enougth raw bytes for code={}"
                                             "and index={} ,expected {} got {}."
                                      "".format(code, index, rawsize, len(raw)))

            self._code = code
            self._index = index
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:len(self.qb64b)]  # may be variable length fs

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:len(self.qb2)]  # may be variable length fs

        else:
            raise EmptyMaterialError("Improper initialization need either "
                                     "(raw and code and index) or qb64b or "
                                     "qb64 or qb2.")

    @classmethod
    def _rawSize(cls, code):
        """
        Returns raw size in bytes for a given code
        """
        hs, ss, fs = cls.Codes[code]  # get sizes
        return ( (fs - (hs + ss)) * 3 // 4 )


    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code


    @property
    def raw(self):
        """
        Returns ._raw
        Makes .raw read only
        """
        return self._raw


    @property
    def index(self):
        """
        Returns ._index
        Makes .index read only
        """
        return self._index


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64b.decode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version Bytes
        """
        return self._binfil()


    def _infil(self):
        """
        Returns fully qualified attached sig base64 bytes computed from
        self.raw, self.code and self.index.
        """
        code = self.code  # codex value chars hard code
        index = self.index  # index value int used for soft
        raw = self.raw  # bytes or bytearray

        hs, ss, fs = self.Codes[code]
        bs = hs + ss  # both hard + soft size
        if not fs:  # compute fs from index
            if bs % 4:
                raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                      "variable length material. bs={}.".format(bs))
            fs = (index * 4) + bs

        if index < 0 or index > (64 ** ss - 1):
            raise InvalidCodeIndexError("Invalid index={} for code={}."
                                        "".format(index, code))

        # both is hard code + converted index
        both =  "{}{}".format(code, intToB64(index, l=ss))

        ps = (3 - (len(raw) % 3)) % 3  # pad size
        # check valid pad size for whole code size
        if len(both) % 4 != ps:  # pad size is not remainder of len(both) % 4
            raise InvalidCodeSizeError("Invalid code = {} for converted raw pad size = {}."
                                  .format(both, ps))
        # prepending full derivation code with index and strip off trailing pad characters
        return (both.encode("utf-8") + encodeB64(raw)[:-ps if ps else None])


    def _exfil(self, qb64b):
        """
        Extracts self.code, self.index, and self.raw from qualified base64 bytes qb64b
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material, Need more characters.")

        first = qb64b[:1]  # extract first char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Sizes:
            if first[0] == '-':
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Indexer.")
            elif first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                               "while extracing Indexer.")
            else:
                raise UnexpectedCodeError("Unsupported code start char={}.".format(first))

        cs = self.Sizes[first]  # get hard code size
        if len(qb64b) < cs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(cs-len(qb64b)))

        hard = qb64b[:cs] # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")
        if hard not in self.Codes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs = self.Codes[hard]
        bs = hs + ss  # both hard + soft code size
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs == cs and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

        if len(qb64b) < bs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(bs-len(qb64b)))

        index = qb64b[hs:hs+ss]  # extract index chars
        if hasattr(index, "decode"):
            index = index.decode("utf-8")
        index = b64ToInt(index)  # compute int index

        if not fs:  # compute fs from index
            if bs % 4:
                raise ValidationError("Whole code size not multiple of 4 for "
                                      "variable length material. bs={}.".format(bs))
            fs = (index * 4) + bs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError("Need {} more chars.".format(fs-len(qb64b)))

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # strip off prepended code and append pad characters
        ps = bs % 4  # pad size ps = cs mod 4
        base = qb64b[bs:] + ps * BASE64_PAD
        raw = decodeB64(base)
        if len(raw) != (len(qb64b) - bs) * 3 // 4:  # exact lengths
            raise ConversionError("Improperly qualified material = {}".format(qb64b))

        self._code = hard
        self._index = index
        self._raw = raw


    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code and self.index  converted to Base2 + self.raw left shifted
        with pad bits equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex chars hard code
        index = self.index  # index value int used for soft
        raw = self.raw  #  bytes or bytearray

        hs, ss, fs = self.Codes[code]
        bs = hs + ss
        if not fs:  # compute fs from index
            if bs % 4:
                raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                      "variable length material. bs={}.".format(bs))
            fs = (index * 4) + bs

        if index < 0 or index > (64 ** ss - 1):
            raise InvalidCodeIndexError("Invalid index={} for code={}.".format(index, code))

        # both is hard code + converted index
        both =  "{}{}".format(code, intToB64(index, l=ss))

        if len(both) != bs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                          .format(bs, len(both)))

        n = sceil(bs * 3 / 4)  # number of b2 bytes to hold b64 code + index
        bcode = b64ToInt(both).to_bytes(n,'big')  # right aligned b2 code

        full = bcode + raw
        bfs = len(full)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError("Invalid code = {} for raw size= {}."
                                          .format(both, len(raw)))

        i = int.from_bytes(full, 'big') << (2 * (bs % 4))  # left shift in pad bits
        return (i.to_bytes(bfs, 'big'))


    def _bexfil(self, qb2):
        """
        Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 1)  # extract first sextet as code selector
        if first not in self.Bizes:
            if first[0] == b'\xf8':  # b64ToB2('-')
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == b'\xfc':  #  b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                               "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        cs = self.Bizes[first]  # get code hard size equvalent sextets
        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs-len(qb2)))

        # bode = nabSextets(qb2, cs)  # b2 version of hard part of code
        hard = b2ToB64(qb2, cs)  # extract and convert hard part of code
        if hard not in self.Codes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs = self.Codes[hard]
        bs = hs + ss  # both hs and ss
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs == cs and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

        bbs = ceil(bs * 3 / 4)  # bbs is min bytes to hold bs sextets
        if len(qb2) < bbs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bbs-len(qb2)))

        both = b2ToB64(qb2, bs)  # extract and convert both hard and soft part of code
        index = b64ToInt(both[hs:hs+ss])  # get index

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs-len(qb2)))

        qb2 = qb2[:bfs]  # fully qualified primitive code plus material

        # right shift to right align raw material
        i = int.from_bytes(qb2, 'big')
        i >>= 2 * (bs % 4)

        raw = i.to_bytes(bfs, 'big')[bbs:]  # extract raw

        if len(raw) != (len(qb2) - bbs):  # exact lengths
            raise ConversionError("Improperly qualified material = {}".format(qb2))

        self._code = hard
        self._index = index
        self._raw = raw


class Siger(Indexer):
    """
    Siger is subclass of Indexer, indexed signature material,
    Adds .verfer property which is instance of Verfer that provides
          associated signature verifier.

    See Indexer for inherited attributes and properties:

    Attributes:

    Properties:
        .verfer is Verfer object instance

    Methods:


    """
    def __init__(self, verfer=None, **kwa):
        """
        Assign verfer to ._verfer

        Parameters:  See Matter for inherted parameters
            verfer if Verfer instance if any

        """
        super(Siger, self).__init__(**kwa)
        if self.code not in IdxSigDex:
            raise ValidationError("Invalid code = {} for Siger."
                                  "".format(self.code))
        self._verfer = verfer

    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    @verfer.setter
    def verfer(self, verfer):
        """ verfer property setter """
        self._verfer = verfer


@dataclass(frozen=True)
class CounterCodex:
    """
    CounterCodex is codex hard (stable) part of all counter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """

    ControllerIdxSigs:              str =  '-A'  # Qualified Base64 Indexed Signature.
    WitnessIdxSigs:                 str =  '-B'  # Qualified Base64 Indexed Signature.
    NonTransReceiptCouples:         str =  '-C'  # Composed Base64 Couple, pre + cig.
    TransReceiptQuadruples:         str =  '-D'  # Composed Base64 Quadruple, pre + snu + dig + sig.
    FirstSeenReplayCouples:         str =  '-E'  # Composed Base64 Couple, fnu + dts.
    TransIndexedSigGroups:          str =  '-F'  # Composed Base64 Triple, pre+snu+dig+ControllerIdxSigs group.
    MessageDataGroups:              str =  '-U'  # Composed Message Data Group or Primitive
    AttachedMaterialQuadlets:       str =  '-V'  # Composed Grouped Attached Material Quadlet (4 char each)
    MessageDataMaterialQuadlets:    str =  '-W'  # Composed Grouped Message Data Quadlet (4 char each)
    CombinedMaterialQuadlets:       str =  '-X'  # Combined Message Data + Attachments Quadlet (4 char each)
    MaterialGroups:                 str =  '-Y'  # Composed Generic Material Group or Primitive
    MaterialQuadlets:               str =  '-Z'  # Composed Generic Material Quadlet (4 char each)
    AnchorSealGroups:               str =  '-a'  # Composed Anchor Seal Material Group
    ConfigTraits:                   str =  '-c'  # Composed Config Trait Material Group
    DigestSealQuadlets:             str =  '-d'  # Composed Digest Seal Quadlet (4 char each)
    EventSealQuadlets:              str =  '-e'  # Composed Event Seal Quadlet (4 char each)
    Keys:                           str =  '-k'  # Composed Key Material Primitive
    LocationSealQuadlets:           str =  '-l'  # Composed Location Seal Quadlet (4 char each)
    RootDigestSealQuadlets:         str =  '-r'  # Composed Root Digest Seal Quadlet (4 char each)
    Witnesses:                      str =  '-w'  # Composed Witness Prefix Material Primitive
    BigMessageDataGroups:           str =  '-0U'  # Composed Message Data Group or Primitive
    BigAttachedMaterialQuadlets:    str =  '-0V'  # Composed Grouped Attached Material Quadlet (4 char each)
    BigMessageDataMaterialQuadlets: str =  '-0W'  # Composed Grouped Message Data Quadlet (4 char each)
    BigCombinedMaterialQuadlets:    str =  '-0X'  # Combined Message Data + Attachments Quadlet (4 char each)
    BigMaterialGroups:              str =  '-0Y'  # Composed Generic Material Group or Primitive
    BigMaterialQuadlets:            str =  '-0Z'  # Composed Generic Material Quadlet (4 char each)


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"

CtrDex = CounterCodex()


class Counter:
    """
    Counter is fully qualified cryptographic material primitive base class for
    counter primitives (framing composition grouping count codes).

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .pad  is int number of pad chars given raw
        .count is int count of grouped following material (not part of counter)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material

    Hidden:
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._pad is method to compute  .pad property
        ._count is int value for .count property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Codex = CtrDex
    # Sizes table maps from bytes Base64 first two code chars to int of
    # hard size, hs,(stable) of code. The soft size, ss, (unstable) for Counter
    # is always > 0 and hs + ss = fs always
    Sizes = ({('-' +  chr(c)): 2 for c in range(65, 65+26)})
    Sizes.update({('-' + chr(c)): 2 for c in range(97, 97+26)})
    Sizes.update([('-0', 3)])
    # Codes table maps hs chars of code to Sizage namedtuple of (hs, ss, fs)
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be  > 0 and hs+ss=fs for Counter
    Codes = {
                '-A': Sizage(hs=2, ss=2, fs=4),
                '-B': Sizage(hs=2, ss=2, fs=4),
                '-C': Sizage(hs=2, ss=2, fs=4),
                '-D': Sizage(hs=2, ss=2, fs=4),
                '-E': Sizage(hs=2, ss=2, fs=4),
                '-F': Sizage(hs=2, ss=2, fs=4),
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
    # Bizes table maps to hard size, hs, of code from bytes holding sextets
    # converted from first two code char. Used for ._bexfil.
    Bizes = ({b64ToB2(c): hs for c, hs in Sizes.items()})


    def __init__(self, code=None, count=1, qb64b=None, qb64=None,
                 qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            code is str of stable (hard) part of derivation code
            count is int count for following group of items (primitives or groups)
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            strip is Boolean True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip


        Needs either (code and count) or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When code and count provided then validate that code and count are correct
        Else when qb64b or qb64 or qb2 provided extract and assign
        .code and .count

        """
        if code is not None:  #  code provided
            if code not in self.Codes:
                raise UnknownCodeError("Unsupported code={}.".format(code))

            hs, ss, fs = self.Codes[code] # get sizes for code
            bs = hs + ss  # both hard + soft code size
            if fs != bs or bs % 4:  # fs must be bs and multiple of 4 for count codes
                raise InvalidCodeSizeError("Whole code size not full size or not "
                                      "multiple of 4. bs={} fs={}.".format(bs, fs))

            if count < 0 or count > (64 ** ss - 1):
                raise InvalidCodeIndexError("Invalid count={} for code={}.".format(count, code))

            self._code = code
            self._count = count

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self.Codes[self.code].fs]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:  # rewrite to use direct binary exfiltration
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self.Codes[self.code].fs*3//4]

        else:
            raise EmptyMaterialError("Improper initialization need either "
                                     "(code and count) or qb64b or "
                                     "qb64 or qb2.")


    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code


    @property
    def count(self):
        """
        Returns ._count
        Makes ._count read only
        """
        return self._count


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64b.decode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version Bytes
        """
        return self._binfil()

    def _infil(self):
        """
        Returns fully qualified attached sig base64 bytes computed from
        self.code and self.count.
        """
        code = self.code  # codex value chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs = self.Codes[code]
        bs = hs + ss  # both hard + soft size
        if fs != bs or bs % 4:  # fs must be bs and multiple of 4 for count codes
            raise InvalidCodeSizeError("Whole code size not full size or not "
                                  "multiple of 4. bs={} fs={}.".format(bs, fs))
        if count < 0 or count > (64 ** ss - 1):
            raise InvalidCodeIndexError("Invalid count={} for code={}.".format(count, code))

        # both is hard code + converted count
        both = "{}{}".format(code, intToB64(count, l=ss))

        # check valid pad size for whole code size
        if len(both) % 4:  # no pad
            raise InvalidCodeSizeError("Invalid size = {} of {} not a multiple of 4."
                                  .format(len(both), both))
        # prepending full derivation code with index and strip off trailing pad characters
        return (both.encode("utf-8"))


    def _exfil(self, qb64b):
        """
        Extracts self.code and self.count from qualified base64 bytes qb64b
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material, Need more characters.")

        first = qb64b[:2]  # extract first two char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Sizes:
            if first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected op code start"
                                               "while extracing Counter.")
            else:
                raise UnexpectedCodeError("Unsupported code start ={}.".format(first))

        cs = self.Sizes[first]  # get hard code size
        if len(qb64b) < cs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(cs-len(qb64b)))

        hard = qb64b[:cs]  # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")
        if hard not in self.Codes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs = self.Codes[hard]
        bs = hs + ss  # both hard + soft code size

        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs == cs and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        if len(qb64b) < bs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(bs-len(qb64b)))

        count = qb64b[hs:hs+ss]  # extract count chars
        if hasattr(count, "decode"):
            count = count.decode("utf-8")
        count = b64ToInt(count)  # compute int count

        self._code = hard
        self._count = count


    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs = self.Codes[code]
        bs = hs + ss
        if fs != bs or bs % 4:  # fs must be bs and multiple of 4 for count codes
            raise InvalidCodeSizeError("Whole code size not full size or not "
                                  "multiple of 4. bs={} fs={}.".format(bs, fs))

        if count < 0 or count > (64 ** ss - 1):
            raise InvalidCodeIndexError("Invalid count={} for code={}.".format(count, code))

        # both is hard code + converted count
        both =  "{}{}".format(code, intToB64(count, l=ss))
        if len(both) != bs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                          .format(bs, len(both)))

        return (b64ToB2(both))  # convert to b2 left shift if any


    def _bexfil(self, qb2):
        """
        Extracts self.code and self.count from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 2)  # extract first two sextets as code selector
        if first not in self.Bizes:
            if first[0] == b'\xfc':  #  b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                               "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        cs = self.Bizes[first]  # get code hard size equvalent sextets
        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs-len(qb2)))

        hard = b2ToB64(qb2, cs)  # extract and convert hard part of code
        if hard not in self.Codes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs = self.Codes[hard]
        bs = hs + ss  # both hs and ss
        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs == cs and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        bbs = ceil(bs * 3 / 4)  # bbs is min bytes to hold bs sextets
        if len(qb2) < bbs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bbs-len(qb2)))

        both = b2ToB64(qb2, bs)  # extract and convert both hard and soft part of code
        count = b64ToInt(both[hs:hs+ss])  # get count

        self._code = hard
        self._count = count


class Serder:
    """
    Serder is KERI key event serializer-deserializer class
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw is bytes of serialized event only
        .ked is key event dict
        .kind is serialization kind string value (see namedtuple coring.Serials)
        .version is Versionage instance of event version
        .size is int of number of bytes in serialed event only
        .diger is Diger instance of digest of .raw
        .dig  is qb64 digest from .diger
        .digb is qb64b digest from .diger
        .verfers is list of Verfers converted from .ked["k"]
        .sn is int sequence number converted from .ked["s"]
        .pre is qb64 str of identifier prefix from .ked["i"]
        .preb is qb64b bytes of identifier prefix from .ked["i"]

    Hidden Attributes:
          ._raw is bytes of serialized event only
          ._ked is key event dict
          ._kind is serialization kind string value (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
          ._version is Versionage instance of event version
          ._size is int of number of bytes in serialed event only
          ._code is default code for .diger
          ._diger is Diger instance of digest of .raw

    Note:
        loads and jumps of json use str whereas cbor and msgpack use bytes

    """
    def __init__(self, raw=b'', ked=None, kind=None, code=MtrDex.Blake3_256):
        """
        Deserialize if raw provided
        Serialize if ked provided but not raw
        When serilaizing if kind provided then use kind instead of field in ked

        Parameters:
          raw is bytes of serialized event plus any attached signatures
          ked is key event dict or None
            if None its deserialized from raw
          kind is serialization kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind is None then its extracted from ked or raw
          code is .diger default digest code

        """
        self._code = code  # need default code for .diger
        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif ked: # serialize ked using property setter
            self._kind = kind
            self.ked = ked  # ked property setter does the serialization
        else:
            raise ValueError("Improper initialization need raw or ked.")


    @staticmethod
    def _sniff(raw):
        """
        Returns serialization kind, version and size from serialized event raw
        by investigating leading bytes that contain version string

        Parameters:
          raw is bytes of serialized event

        """
        if len(raw) < MINSNIFFSIZE:
            raise ShortageError("Need more bytes.")

        match = Rever.search(raw)  #  Rever's regex takes bytes
        if not match or match.start() > 12:
            raise VersionError("Invalid version string in raw = {}".format(raw))

        major, minor, kind, size = match.group("major", "minor", "kind", "size")
        version = Versionage(major=int(major, 16), minor=int(minor, 16))
        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise DeserializationError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return(kind, version, size)


    def _inhale(self, raw):
        """
        Parses serilized event ser of serialization kind and assigns to
        instance attributes.

        Parameters:
          raw is bytes of serialized event
          kind is str of raw serialization kind (see namedtuple Serials)
          size is int size of raw to be deserialized

        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes

        """
        kind, version, size = self._sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}, expected {}."
                               "".format(version.major, version.minor, Version))
        if len(raw) < size:
            raise ShortageError("Need more bytes.")

        if kind == Serials.json:
            try:
                ked = json.loads(raw[:size].decode("utf-8"))
            except Exception as ex:
                raise DeserializationError("Error deserializing JSON: {}"
                        "".format(raw[:size].decode("utf-8")))

        elif kind == Serials.mgpk:
            try:
                ked = msgpack.loads(raw[:size])
            except Exception as ex:
                raise DeserializationError("Error deserializing MGPK: {}"
                        "".format(raw[:size]))

        elif kind ==  Serials.cbor:
            try:
                ked = cbor.loads(raw[:size])
            except Exception as ex:
                raise DeserializationError("Error deserializing CBOR: {}"
                        "".format(raw[:size]))

        else:
            ked = None

        return (ked, kind, version, size)


    def _exhale(self, ked,  kind=None):
        """
        ked is key event dict
        kind is serialization if given else use one given in ked
        Returns tuple of (raw, kind, ked, version) where:
            raw is serialized event as bytes of kind
            kind is serialzation kind
            ked is key event dict
            version is Versionage instance

        Assumes only supports Version
        """
        if "v" not in ked:
            raise ValueError("Missing or empty version string in key event dict = {}".format(ked))

        knd, version, size = Deversify(ked["v"])  # extract kind and version
        if version != Version:
            raise ValueError("Unsupported version = {}.{}".format(version.major,
                                                                    version.minor))

        if not kind:
            kind = knd

        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        if kind == Serials.json:
            raw = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        elif kind == Serials.mgpk:
            raw = msgpack.dumps(ked)

        elif kind == Serials.cbor:
            raw = cbor.dumps(ked)

        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        size = len(raw)

        match = Rever.search(raw)  #  Rever's regex takes bytes
        if not match or match.start() > 12:
            raise ValueError("Invalid version string in raw = {}".format(raw))

        fore, back = match.span()  #  full version string
        # update vs with latest kind version size
        vs = Versify(version=version, kind=kind, size=size)
        # replace old version string in raw with new one
        raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
        if size != len(raw):  # substitution messed up
            raise ValueError("Malformed version string size = {}".format(vs))
        ked["v"] = vs  #  update ked

        return (raw, kind, ked, version)


    def compare(self, dig=None, diger=None):
        """
        Returns True  if dig and either .diger.qb64 or .diger.qb64b match or
            if both .diger.raw and dig are valid digests of self.raw
            Otherwise returns False

        Convenience method to allow comparison of own .diger digest self.raw
        with some other purported digest of self.raw

        Parameters:
            dig is qb64b or qb64 digest of ser to compare with .diger.raw
            diger is Diger instance of digest of ser to compare with .diger.raw

            if both supplied dig takes precedence


        If both match then as optimization returns True and does not verify either
          as digest of ser
        Else If both have same code but do not match then as optimization returns False
           and does not verify if either is digest of ser
        Else recalcs both digests using each one's code to verify they
            they are both digests of ser regardless of matching codes.
        """
        return (self.diger.compare(ser=self.raw, dig=dig, diger=diger))


    @property
    def raw(self):
        """ raw property getter """
        return self._raw


    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        ked, kind, version, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._ked = ked
        self._kind = kind
        self._version = version
        self._size = size
        self._diger = Diger(ser=self._raw, code=self._code)


    @property
    def ked(self):
        """ ked property getter"""
        return self._ked


    @ked.setter
    def ked(self, ked):
        """ ked property setter  assumes ._kind """
        raw, kind, ked, version = self._exhale(ked=ked, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size
        self._version = version
        self._diger = Diger(ser=self._raw, code=self._code)


    @property
    def kind(self):
        """ kind property getter"""
        return self._kind


    @kind.setter
    def kind(self, kind):
        """ kind property setter Assumes ._ked """
        raw, kind, ked, version = self._exhale(ked=self._ked, kind=kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size
        self._version = version
        self._diger = Diger(ser=self._raw, code=self._code)


    @property
    def version(self):
        """ version property getter"""
        return self._version


    @property
    def size(self):
        """ size property getter"""
        return self._size


    @property
    def diger(self):
        """
        Returns Diger of digest of self.raw
        diger (digest material) property getter
        """
        return self._diger


    @property
    def dig(self):
        """
        Returns qualified Base64 digest of self.raw
        dig (digest) property getter
        """
        return self.diger.qb64


    @property
    def digb(self):
        """
        Returns qualified Base64 digest of self.raw
        dig (digest) property getter
        """
        return self.diger.qb64b


    @property
    def verfers(self):
        """
        Returns list of Verifier instances as converted from .ked.keys
        verfers property getter
        """
        if "k" in self.ked:  # establishment event
            keys = self.ked["k"]
        else:  # non-establishment event
            keys =  []

        return [Verfer(qb64=key) for key in keys]

    @property
    def sn(self):
        """
        Returns int of .ked["s"] (sequence number)
        sn (sequence number) property getter
        """
        return int(self.ked["s"], 16)


    @property
    def pre(self):
        """
        Returns str qb64  of .ked["i"] (identifier prefix)
        pre (identifier prefix) property getter
        """
        return self.ked["i"]


    @property
    def preb(self):
        """
        Returns bytes qb64b  of .ked["i"] (identifier prefix)
        preb (identifier prefix) property getter
        """
        return self.pre.encode("utf-8")

    def pretty(self):
        """
        Returns str JSON of .ked with pretty formatting
        """
        return json.dumps(self.ked, indent=1)


class Tholder:
    """
    Tholder is KERI Signing Threshold Satisfactionclass
    .satisfy method evaluates satisfaction based on ordered list of indices of
    verified signatures where indices correspond to offsets in key list of
    associated signatures.

    Has the following public properties:

    Properties:
        .sith is original signing threshold
        .thold is parsed signing threshold
        .limen is the extracted string for the next commitment to the threshold
        .weighted is Boolean True if fractional weighted threshold False if numeric
        .size is int of minimun size of keys list

    Hidden:
        ._sith is original signing threshold
        ._thold is parsed signing threshold maybe int or list of clauses
        ._limen is extracted string for the next commitment to threshold
        ._weighted is Boolean, True if fractional weighted threshold False if numeric
        ._size is int minimum size of of keys list
        ._satisfy is method reference of threshold specified verification method
        ._satisfy_numeric is numeric threshold verification method
        ._satisfy_weighted is fractional weighted threshold verification method


    """
    def __init__(self, sith=''):
        """
        Parse threshold

        Parameters:
            sith is either hex string of threshold number or iterable of fractional
                weights. Fractional weights may be either an iterable of
                fraction strings or an iterable of iterables of fractions strings.

                The verify method appropriately evaluates each of the threshold
                forms.

        """
        self._sith = sith
        if isinstance(sith, str):
            self._weighted = False
            thold = int(sith, 16)
            if thold < 1:
                raise ValueError("Invalid sith = {} < 1.".format(thold))
            self._thold = thold
            self._size = self._thold  # used to verify that keys list size is at least size
            self._satisfy = self._satisfy_numeric
            self._limen = self._sith  # just use hex string

        else:  # assumes iterable of weights or iterable of iterables of weights
            self._weighted = True
            if not sith:  # empty iterable
                raise ValueError("Invalid sith = {}, empty weight list.".format(sith))

            mask = [isinstance(w, str) for w in sith]
            if mask and all(mask):  # not empty and all strings
                sith = [sith]  # make list of list so uniform
            elif any(mask):  # some strings but not all
                raise ValueError("Invalid sith = {} some weights non non string."
                                 "".format(sith))

            # replace fractional strings with fractions
            thold = []
            for clause in sith:  # convert string fractions to Fractions
                thold.append([Fraction(w) for w in clause])  # append list of Fractions

            for clause in thold:  #  sum of fractions in clause must be >= 1
                if not (sum(clause) >= 1):
                    raise ValueError("Invalid sith cLause = {}, all clause weight "
                                     "sums must be >= 1.".format(thold))

            self._thold = thold
            self._size = sum(len(clause) for clause in thold)
            self._satisfy = self._satisfy_weighted

            # extract limen from sith
            self._limen = "&".join([",".join(clause) for clause in sith])



    @property
    def sith(self):
        """ sith property getter """
        return self._sith

    @property
    def thold(self):
        """ thold property getter """
        return self._thold

    @property
    def weighted(self):
        """ weighted property getter """
        return self._weighted

    @property
    def size(self):
        """ size property getter """
        return self._size

    @property
    def limen(self):
        """ limen property getter """
        return self._limen


    def satisfy(self, indices):
        """
        Returns True if indices list of verified signature key indices satisfies
        threshold, False otherwise.

        Parameters:
            indices is list of indices (offsets into key list) of verified signatures
        """
        return (self._satisfy(indices=indices))


    def _satisfy_numeric(self, indices):
        """
        Returns True if satisfies numeric threshold False otherwise

        Parameters:
            indices is list of indices (offsets into key list) of verified signatures
        """
        try:
            if len(indices) >= self.thold:
                return True

        except Exception as ex:
            return False

        return False


    def _satisfy_weighted(self, indices):
        """
        Returns True if satifies fractional weighted threshold False otherwise


        Parameters:
            indices is list of indices (offsets into key list) of verified signatures

        """
        try:
            if not indices:  #  empty indices
                return False

            # remove duplicates with set, sort low to high
            indices = sorted(set(indices))
            sats = [False] * self.size  # default all satifactions to False
            for idx in indices:
                sats[idx] = True  # set aat atverified signature index to True

            wio = 0  # weight index offset
            for clause in self.thold:
                cw = 0  # init clause weight
                for w in clause:
                    if sats[wio]:  # verified signature so weight applies
                        cw += w
                    wio += 1
                if cw < 1:
                    return False

            return True  # all clauses including final one cw >= 1

        except Exception as ex:
            return False

        return False
