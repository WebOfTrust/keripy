# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import re
import json
from typing import Union

from dataclasses import dataclass, astuple
from collections import namedtuple, deque
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from math import ceil
from fractions import Fraction

import cbor2 as cbor
import msgpack
import pysodium
import blake3
import hashlib

from ..kering import (EmptyMaterialError, RawMaterialError, UnknownCodeError,
                      InvalidCodeSizeError, InvalidVarIndexError,
                      InvalidVarSizeError, InvalidVarRawSizeError,
                      ConversionError,
                      ValidationError, VersionError, DerivationError,
                      ShortageError, UnexpectedCodeError, DeserializationError,
                      UnexpectedCountCodeError, UnexpectedOpCodeError)
from ..kering import Versionage, Version
from ..help import helping
from ..help.helping import sceil

"""
ilk is short for message type
icp = incept, inception
rot = rotate, rotation
ixn = interact, interaction
dip = delcept, delegated inception
drt = deltate, delegated rotation
rct = receipt
ksn = state, key state notice
qry = query
rpy = reply
exn = exchange
exp = expose, sealed data exposition
vcp = vdr incept, verifiable data registry inception
vrt = vdr rotate, verifiable data registry rotation
iss = vc issue, verifiable credential issuance
rev = vc revoke, verifiable credential revocation
bis = backed vc issue, registry-backed transaction event log credential issuance
brv = backed vc revoke, registry-backed transaction event log credential revocation
"""

Ilkage = namedtuple("Ilkage", ('icp rot ixn dip drt rct ksn qry rpy exn exp '
                               'vcp vrt iss rev bis brv '))

Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt', rct='rct',
              ksn='ksn', qry='qry', rpy='rpy', exn='exn', exp='exp',
              vcp='vcp', vrt='vrt', iss='iss', rev='rev', bis='bis', brv='brv')

Serialage = namedtuple("Serialage", 'json mgpk cbor')

Serials = Serialage(json='JSON', mgpk='MGPK', cbor='CBOR')

Identage = namedtuple("Identage", "keri acdc")

Idents = Identage(keri="KERI", acdc="ACDC")

VERRAWSIZE = 6  # hex characters in raw serialization size in version string
# "{:0{}x}".format(300, 6)  # make num char in hex a variable
# '00012c'
VERFMT = "{}{:x}{:x}{}{:0{}x}_"  # version format string
VERFULLSIZE = 17  # number of characters in full versions string


def Versify(ident=Idents.keri, version=None, kind=Serials.json, size=0):
    """
    Return version string
    """
    if ident not in Idents:
        raise ValueError("Invalid message identifier = {}".format(ident))
    if kind not in Serials:
        raise ValueError("Invalid serialization kind = {}".format(kind))
    version = version if version else Version
    return VERFMT.format(ident, version[0], version[1], kind, size, VERRAWSIZE)


Vstrings = Serialage(json=Versify(kind=Serials.json, size=0),
                     mgpk=Versify(kind=Serials.mgpk, size=0),
                     cbor=Versify(kind=Serials.cbor, size=0))

VEREX = b'(?P<ident>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'
Rever = re.compile(VEREX)  # compile is faster
MINSNIFFSIZE = 12 + VERFULLSIZE  # min bytes in buffer to sniff else need more


def Deversify(vs):
    """
    Returns tuple(ident, kind, version, size)
      Where:
        ident is event type identifier one of Idents
                   acdc='ACDC', keri='KERI'
        kind is serialization kind, one of Serials
                   json='JSON', mgpk='MGPK', cbor='CBOR'
        version is version tuple of type Version
        size is int of raw size

    Parameters:
      vs is version string str

    Uses regex match to extract:
        event type identifier
        serialization kind
        keri version
        serialization size
    """
    match = Rever.match(vs.encode("utf-8"))  # match takes bytes
    if match:
        ident, major, minor, kind, size = match.group("ident", "major", "minor", "kind", "size")
        version = Versionage(major=int(major, 16), minor=int(minor, 16))
        ident = ident.decode("utf-8")
        kind = kind.decode("utf-8")

        if ident not in Idents:
            raise ValueError("Invalid message identifier = {}".format(ident))
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return ident, kind, version, size

    raise ValueError("Invalid version string = {}".format(vs))


def Sizeify(ked, kind=None):
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
        raise ValueError("Missing or empty version string in key event "
                         "dict = {}".format(ked))

    ident, knd, version, size = Deversify(ked["v"])  # extract kind and version
    if version != Version:
        raise ValueError("Unsupported version = {}.{}".format(version.major,
                                                              version.minor))

    if not kind:
        kind = knd

    if kind not in Serials:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    raw = dumps(ked, kind)
    size = len(raw)

    match = Rever.search(raw)  # Rever's regex takes bytes
    if not match or match.start() > 12:
        raise ValueError("Invalid version string in raw = {}".format(raw))

    fore, back = match.span()  # full version string
    # update vs with latest kind version size
    vs = Versify(ident=ident, version=version, kind=kind, size=size)
    # replace old version string in raw with new one
    raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
    if size != len(raw):  # substitution messed up
        raise ValueError("Malformed version string size = {}".format(vs))
    ked["v"] = vs  # update ked

    return raw, ident, kind, ked, version


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
B64_CHARS = tuple(B64ChrByIdx.values())  # tuple of characters in Base64

B64REX = b'^[A-Za-z0-9\-\_]*\Z'
Reb64 = re.compile(B64REX)  # compile is faster


def intToB64(i, l=1):
    """
    Returns conversion of int i to Base64 str
    l is min number of b64 digits left padded with Base64 0 == "A" char
    """
    d = deque()  # deque of characters base64

    while l:
        d.appendleft(B64ChrByIdx[i % 64])
        i = i // 64
        if not i:
            break
        # d.appendleft(B64ChrByIdx[i % 64])
        # i = i // 64
    for j in range(l - len(d)):  # range(x)  x <= 0 means do not iterate
        d.appendleft("A")
    return ("".join(d))


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
    if not s:
        raise ValueError("Empty string, conversion undefined.")
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
    i >>= 2 * (l % 4)  # shift out padding bits make right aligned
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
    i >>= p  # strip of last bits
    i <<= p  # pad with empty bits
    return (i.to_bytes(n, 'big'))


def sniff(raw):
    """
    Returns serialization kind, version and size from serialized event raw
    by investigating leading bytes that contain version string

    Parameters:
      raw is bytes of serialized event

    """
    if len(raw) < MINSNIFFSIZE:
        raise ShortageError("Need more bytes.")

    match = Rever.search(raw)  # Rever's regex takes bytes
    if not match or match.start() > 12:
        raise VersionError("Invalid version string in raw = {}".format(raw))

    ident, major, minor, kind, size = match.group("ident", "major", "minor", "kind", "size")
    version = Versionage(major=int(major, 16), minor=int(minor, 16))
    kind = kind.decode("utf-8")
    ident = ident.decode("utf-8")
    if kind not in Serials:
        raise DeserializationError("Invalid serialization kind = {}".format(kind))
    size = int(size, 16)

    return ident, kind, version, size


def dumps(ked, kind=Serials.json):
    """
    utility function to handle serialization by kind

    Returns:
       raw (bytes): serialized version of ked dict

    Parameters:
       ked (Optional(dict, list)): key event dict or message dict to serialize
       kind (str): serialization kind (JSON, MGPK, CBOR)
    """
    if kind == Serials.json:
        raw = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    elif kind == Serials.mgpk:
        raw = msgpack.dumps(ked)

    elif kind == Serials.cbor:
        raw = cbor.dumps(ked)
    else:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    return raw


def loads(raw, size=None, kind=Serials.json):
    """
    utility function to handle deserialization by kind

    Returns:
       ked (dict): deserialized

    Parameters:
       raw (Union[bytes,bytearray]): raw serialization to deserialze as dict
       size (int): number of bytes to consume for the deserialization. If None
                   then consume all bytes
       kind (str): serialization kind (JSON, MGPK, CBOR)
    """
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

    elif kind == Serials.cbor:
        try:
            ked = cbor.loads(raw[:size])
        except Exception as ex:
            raise DeserializationError("Error deserializing CBOR: {}"
                                       "".format(raw[:size]))

    else:
        raise DeserializationError("Invalid deserialization kind: {}"
                                   "".format(kind))

    return ked


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

    return [signer.qb64 for signer in signers]  # fetch the qb64 as secret


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
    Short:                str = 'M'  # Short 2 byte b2 number or 3 char b64 str
    Big:                  str = 'N'  # Big 8 byte b2 number or 11 char b64 str
    X25519_Private:       str = 'O'  # X25519 private decryption key converted from Ed25519
    X25519_Cipher_Seed:   str = 'P'  # X25519 124 char b64 Cipher of 44 char qb64 Seed
    Salt_128:             str = '0A'  # 128 bit random salt or 128 bit number
    Ed25519_Sig:          str = '0B'  # Ed25519 signature.
    ECDSA_256k1_Sig:      str = '0C'  # ECDSA secp256k1 signature.
    Blake3_512:           str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:          str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:             str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:             str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    Long:                 str = '0H'  # Long 4 byte b2 number or 6 char b54 str
    ECDSA_256k1N:         str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:          str = '1AAB'  # Ed25519 public verification or encryption key, basic derivation
    Ed448N:               str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.
    Ed448:                str = '1AAD'  # Ed448 public signing verification key. Basic derivation.
    Ed448_Sig:            str = '1AAE'  # Ed448 signature. Self-signing derivation.
    Tag:                  str = '1AAF'  # Base64 4 char tag or 3 byte number.
    DateTime:             str = '1AAG'  # Base64 custom encoded 32 char ISO-8601 DateTime
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 100 char b64 Cipher of 24 char qb64 Salt
    TBD1:                 str = '2AAA'  # Testing purposes only of 1 lead size
    TBD2:                 str = '3AAA'  # Testing purposes only of 2 lead size
    StrB64_L0:            str = '4A'    # String Base64 Only Leader Size 0
    StrB64_L1:            str = '5A'    # String Base64 Only Leader Size 1
    StrB64_L2:            str = '6A'    # String Base64 Only Leader Size 2
    Str_L0:               str = '4B'    # String Leader Size 0
    Str_L1:               str = '5B'    # String Leader Size 1
    Str_L2:               str = '6B'    # String Leader Size 2
    StrB64_Big_L0:        str = '7AAA'    # String Base64 Only Big Leader Size 0
    StrB64_Big_L1:        str = '8AAA'    # String Base64 Only Big Leader Size 1
    StrB64_Big_L2:        str = '9AAA'    # String Base64 Only Big Leader Size 2
    Str_Big_L0:           str = '7AAB'    # String Big Leader Size 0
    Str_Big_L1:           str = '8AAB'    # String Big Leader Size 1
    Str_Big_L2:           str = '9AAB'    # String Big Leader Size 2


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"


MtrDex = MatterCodex()  # Make instance


@dataclass(frozen=True)
class SmallVarRawSizeCodex:
    """
    SmallVarRawSizeCodex is codex all selector characters for the three small
    variable raw size tables that act as one table but with different leader
    byte sizes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Lead0: str = '4'  # First Selector Character for all ls == 0 codes
    Lead1: str = '5'  # First Selector Character for all ls == 1 codes
    Lead2: str = '6'  # First Selector Character for all ls == 2 codes

    def __iter__(self):
        return iter(astuple(self))


SmallVrzDex = SmallVarRawSizeCodex()  # Make instance


@dataclass(frozen=True)
class LargeVarRawSizeCodex:
    """
    LargeVarRawSizeCodex is codex all selector characters for the three large
    variable raw size tables that act as one table but with different leader
    byte sizes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Lead0_Big: str = '7'  # First Selector Character for all ls == 0 codes
    Lead1_Big: str = '8'  # First Selector Character for all ls == 1 codes
    Lead2_Big: str = '9'  # First Selector Character for all ls == 2 codes

    def __iter__(self):
        return iter(astuple(self))


LargeVrzDex = LargeVarRawSizeCodex()  # Make instance


@dataclass(frozen=True)
class NonTransCodex:
    """
    NonTransCodex is codex all non-transferable derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N: str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    ECDSA_256k1N: str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    Ed448N: str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.

    def __iter__(self):
        return iter(astuple(self))


NonTransDex = NonTransCodex()  # Make instance


@dataclass(frozen=True)
class DigCodex:
    """
    DigCodex is codex all digest derivation codes. This is needed to ensure
    delegated inception using a self-addressing derivation i.e. digest derivation
    code.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Blake3_256: str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256: str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256: str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256: str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256: str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    Blake3_512: str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512: str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512: str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512: str = '0G'  # SHA2 512 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))


DigDex = DigCodex()  # Make instance


@dataclass(frozen=True)
class TextCodex:
    """
    TextCodex is codex all variable sized Base64 Text derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    StrB64_L0: str = '4A'  # String Base64 Only Leader Size 0
    StrB64_L1: str = '5A'  # String Base64 Only Leader Size 1
    StrB64_L2: str = '6A'  # String Base64 Only Leader Size 2
    StrB64_Big_L0: str = '7AAA'  # String Base64 Only Big Leader Size 0
    StrB64_Big_L1: str = '8AAA'  # String Base64 Only Big Leader Size 1
    StrB64_Big_L2: str = '9AAA'  # String Base64 Only Big Leader Size 2

    def __iter__(self):
        return iter(astuple(self))


TexDex = TextCodex()  # Make instance

# namedtuple for size entries in matter derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# fs is the full size int number of chars in code plus appended material if any
# ls is the lead size int number of bytes to pre-pad pre-converted raw binary
Sizage = namedtuple("Sizage", "hs ss fs ls")


class Matter:
    """
    Matter is fully qualified cryptographic material primitive base class for
    non-indexed primitives.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        code (str): derivation code to indicate cypher suite
        size (int): number of quadlets of variable sized material including
                    lead bytes otherwise None
        rize (int): number of bytes of raw material not including
                    lead bytes
        raw (bytes): crypto material only without code
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise

    Hidden:
        _code (str): value for .code property
        _raw (bytes): value for .raw property
        _rsize (bytes): value for .rsize property. Raw size in bytes when
            variable sized material else None.
        _size (int): value for .size property. Number of quadlets of variable
            sized material else None.
        _infil (types.MethodType): creates qb64b from .raw and .code
                                   (fully qualified Base64)
        _exfil (types.MethodType): extracts .code and .raw from qb64b
                                   (fully qualified Base64)

    """
    Codex = MtrDex
    # Hards table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always 0 for Matter
    # unless fs is None which allows for variable size multiple of 4, i.e.
    # not (hs + ss) % 4.
    Hards = ({chr(c): 1 for c in range(65, 65 + 26)})  # size of hard part of code
    Hards.update({chr(c): 1 for c in range(97, 97 + 26)})
    Hards.update([('0', 2), ('1', 4), ('2', 4), ('3', 4), ('4', 2), ('5', 2),
                  ('6', 2), ('7', 4), ('8', 4), ('9', 4)])
    # Sizes table maps from value of hs chars of code to Sizage namedtuple of
    # (hs, ss, fs, ls) where hs is hard size, ss is soft size, and fs is full size
    # and ls is lead size
    # soft size, ss, should always be 0 for Matter unless fs is None which allows
    # for variable size multiple of 4, i.e. not (hs + ss) % 4.
    Sizes = {
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
        '4B': Sizage(hs=2, ss=2, fs=None, ls=0),
        '5B': Sizage(hs=2, ss=2, fs=None, ls=1),
        '6B': Sizage(hs=2, ss=2, fs=None, ls=2),
        '7AAA': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAA': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAA': Sizage(hs=4, ss=4, fs=None, ls=2),
        '7AAB': Sizage(hs=4, ss=4, fs=None, ls=0),
        '8AAB': Sizage(hs=4, ss=4, fs=None, ls=1),
        '9AAB': Sizage(hs=4, ss=4, fs=None, ls=2),
    }
    # Bards table maps first code char. converted to binary sextext  to hard size,
    # hs. Used for ._bexfil.
    Bards = ({b64ToB2(c): hs for c, hs in Hards.items()})

    def __init__(self, raw=None, code=MtrDex.Ed25519N, rize=None,
                 qb64b=None, qb64=None, qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            raw (bytes): unqualified crypto material usable for crypto operations
            code (str): stable (hard) part of derivation code
            rize (int): raw size in bytes when variable sized material else None
            qb64b (bytes): fully qualified crypto material Base64
            qb64 (str, bytes):  fully qualified crypto material Base64
            qb2 (bytes): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip


        Needs either (raw and code and optionally size and rsize)
               or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code and option size and rsize provided
            then validate that code is correct for length of raw, size, rsize
            and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign
            .raw and .code and .size and .rsize

        """
        size = None  # variable raw binary size including leader in quadlets
        if raw is not None:  # raw provided
            if not code:
                raise EmptyMaterialError(f"Improper initialization need either "
                                         f"(raw and code) or qb64b or qb64 or qb2.")
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError(f"Not a bytes or bytearray, raw={raw}.")

            if code not in self.Sizes:
                raise UnknownCodeError("Unsupported code={}.".format(code))

            if code[0] in SmallVrzDex or code[0] in LargeVrzDex:  # dynamic size
                if rize:  # use rsize to determin length of raw to extract
                    if rize < 0:
                        raise InvalidVarRawSizeError(f"Missing var raw size for "
                                                     f"code={code}.")
                else:  # use length of provided raw as rize
                    rize = len(raw)

                ls = (3 - (rize % 3)) % 3  # calc actual lead (pad) size
                # raw binary size including leader in bytes
                size = (rize + ls) // 3  # calculate value of size in triplets
                if code[0] in SmallVrzDex:  # compute code with sizes
                    if size <= (64 ** 2 - 1):
                        hs = 2
                        s = astuple(SmallVrzDex)[ls]
                        code = f"{s}{code[1:hs]}"
                    elif size <= (64 ** 4 - 1):  # make big version of code
                        hs = 4
                        s = astuple(LargeVrzDex)[ls]
                        code = f"{s}{'A' * (hs - 2)}{code[1]}"
                    else:
                        raise InvalidVarRawSizeError(r"Unsupported raw size for "
                                                     f"code={code}.")
                elif code[0] in LargeVrzDex:  # compute code with sizes
                    if size <= (64 ** 4 - 1):
                        hs = 4
                        s = astuple(LargeVrzDex)[ls]
                        code = f"{s}{code[1:hs]}"
                    else:
                        raise InvalidVarRawSizeError(r"Unsupported raw size for "
                                                     f"code={code}.")
                else:
                    raise InvalidVarRawSizeError(r"Unsupported variable raw size "
                                                 f"code={code}.")

            else:
                hs, ss, fs, ls = self.Sizes[code]  # get sizes assumes ls consistent
                if fs is None:  # invalid
                    raise InvalidVarSizeError(r"Unsupported variable size "
                                              f"code={code}.")
                rize = Matter._rawSize(code)

            raw = raw[:rize]  # copy only exact size from raw stream
            if len(raw) != rize:  # forbids shorter
                raise RawMaterialError(f"Not enougth raw bytes for code={code}"
                                       f"expected {rize} got {len(raw)}.")

            self._code = code  # hard value part of code
            self._size = size  # soft value part of code in int
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self.fullSize]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self.fullSize * 3 // 4]

        else:
            raise EmptyMaterialError(f"Improper initialization need either "
                                     f"(raw and code) or qb64b or qb64 or qb2.")

    @classmethod
    def _rawSize(cls, code):
        """
        Returns raw size in bytes not including leader for a given code
        Parameters:
            code (str): derivation code Base64
        """
        hs, ss, fs, ls = cls.Sizes[code]  # get sizes
        cs = hs + ss  # both hard + soft code size
        if fs is None:
            raise InvalidCodeSizeError(f"Non-fixed raw size code {code}.")
        return (((fs - cs) * 3 // 4) - ls)

    @classmethod
    def _leadSize(cls, code):
        """
        Returns lead size in bytes for a given code
        Parameters:
            code (str): derivation code Base64
        """
        _, _, _, ls = cls.Sizes[code]  # get lead size from .Sizes table
        return ls

    @property
    def code(self):
        """
        Returns ._code which is the hard part of full text code
        Makes .code read only
        """
        return self._code

    @property
    def size(self):
        """
        Returns ._size int or None if not variable sized matter
        Makes .size read only
        ._size (int): number of quadlets of variable sized material else None
        """
        return self._size

    @property
    def both(self):
        """
        Returns both hard and soft parts that are the complete text code
        """
        _, ss, _, _ = self.Sizes[self.code]
        return (f"{self.code}{intToB64(self.size, l=ss)}")

    @property
    def fullSize(self):
        """
        Returns full size of matter in bytes
        Fixed size codes returns fs from .Sizes
        Variable size codes where fs==None computes fs from .size and sizes
        """
        hs, ss, fs, _ = self.Sizes[self.code]  # get sizes

        if fs is None:  # compute fs from ss characters in code
            fs = hs + ss + (self.size * 4)
        return fs

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
        return (self.code not in NonTransDex)

    @property
    def digestive(self):
        """
        Property digestable:
        Returns True if identifier has digest derivation code,
                False otherwise
        """
        return (self.code in DigDex)

    def _infil(self):
        """
        Returns bytes of fully qualified base64 characters
        self.code + converted self.raw to Base64 with pad chars stripped
        """
        code = self.code  # hard size codex value
        size = self.size  # size if variable length, None otherwise
        raw = self.raw  # bytes or bytearray

        hs, ss, fs, ls = self.Sizes[code]
        if fs is None:  # compute code ss value from .size
            cs = hs + ss  # both hard + soft size
            if cs % 4:
                raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                           "variable length material. cs={}.".format(cs))

            if size < 0 or size > (64 ** ss - 1):
                raise InvalidVarSizeError("Invalid size={} for code={}."
                                          "".format(size, code))
            # both is hard code + converted size
            both = f"{code}{intToB64(size, l=ss)}"
        else:
            both = code

        ps = ((3 - (len(raw) % 3)) % 3) - ls  # adjusted pad size, 0 if ls
        # check valid pad size for code size
        if len(both) % 4 != ps:  # pad size is not remainder of len(both) % 4
            raise InvalidCodeSizeError("Invalid code = {} for converted raw "
                                       "pad size= {}.".format(both, ps))
        # prepend derivation code and strip off trailing pad characters
        return (both.encode("utf-8") + encodeB64(bytes([0] * ls) + raw)[:-ps if ps else None])

    def _exfil(self, qb64b):
        """
        Extracts self.code and self.raw from qualified base64 bytes qb64b
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material, Need more characters.")

        first = qb64b[:1]  # extract first char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Hards:
            if first[0] == '-':
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start char={}.".format(first))

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(hs - len(qb64b)))

        code = qb64b[:hs]  # extract hard code
        if hasattr(code, "decode"):
            code = code.decode("utf-8")
        if code not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(code))

        hs, ss, fs, ls = self.Sizes[code]  # assumes hs in both tables match
        cs = hs + ss  # both hs and ss
        size = None
        if not fs:  # compute fs from size chars in ss part of code
            if cs % 4:
                raise ValidationError("Whole code size not multiple of 4 for "
                                      "variable length material. cs={}.".format(cs))
            size = qb64b[hs:hs + ss]  # extract size chars
            if hasattr(size, "decode"):
                size = size.decode("utf-8")
            size = b64ToInt(size)  # compute int size
            fs = (size * 4) + cs

        # assumes that unit tests on Matter and MatterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and ss == 0 and not fs % 4 and hs > 0 and fs > hs unless
        # fs is None

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError("Need {} more chars.".format(fs - len(qb64b)))
        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # strip off prepended code and append pad characters
        ps = cs % 4  # pad size ps = cs mod 4
        base = qb64b[cs:] + ps * BASE64_PAD
        raw = decodeB64(base)[ls:]  # decode and strip off leader bytes
        if len(raw) != ((len(qb64b) - cs) * 3 // 4) - ls:  # exact lengths
            raise ConversionError("Improperly qualified material = {}".format(qb64b))

        self._code = code
        self._size = size
        self._raw = raw

    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 + self.raw left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex value
        size = self.size  # optional size if variable length
        raw = self.raw  # bytes or bytearray

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss

        if fs is None:  # compute both and fs from size
            cs = hs + ss  # both hard + soft size
            if cs % 4:
                raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                           "variable length material. cs={}.".format(cs))

            if size < 0 or size > (64 ** ss - 1):
                raise InvalidVarSizeError("Invalid size={} for code={}."
                                          "".format(size, code))
            # both is hard code + converted index
            both = f"{code}{intToB64(size, l=ss)}"
            fs = hs + ss + (size * 4)
        else:
            both = code

        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(code)))
        n = sceil(cs * 3 / 4)  # number of b2 bytes to hold b64 code
        bcode = b64ToInt(both).to_bytes(n, 'big')  # right aligned b2 code

        full = bcode + bytes([0] * ls) + raw
        bfs = len(full)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError("Invalid code = {} for raw size= {}."
                                       .format(both, len(raw)))

        i = int.from_bytes(full, 'big') << (2 * (cs % 4))  # left shift in pad bits
        return (i.to_bytes(bfs, 'big'))

    def _bexfil(self, qb2):
        """
        Extracts self.code and self.raw from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 1)  # extract first sextet as code selector
        if first not in self.Bards:
            if first[0] == b'\xf8':  # b64ToB2('-')
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == b'\xfc':  # b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bhs - len(qb2)))

        code = b2ToB64(qb2, hs)  # extract and convert hard part of code
        if code not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(code))

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss  # both hs and ss
        size = None
        if not fs:  # compute fs from size chars in ss part of code
            if cs % 4:
                raise ValidationError("Whole code size not multiple of 4 for "
                                      "variable length material. cs={}.".format(cs))
            bcs = ceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
            if len(qb2) < bcs:  # need more bytes
                raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

            both = b2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
            size = b64ToInt(both[hs:hs + ss])  # get size
            fs = (size * 4) + cs

        # assumes that unit tests on Matter and MatterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and ss == 0 and not fs % 4 and hs > 0 and fs > hs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))
        qb2 = qb2[:bfs]  # fully qualified primitive code plus material

        # right shift to right align raw material
        i = int.from_bytes(qb2, 'big') >> (2 * (cs % 4))
        # i >>= 2 * (cs % 4)
        bcs = ceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        raw = i.to_bytes(bfs, 'big')[(bcs + ls):]  # extract raw strip leader bytes

        if len(raw) != (len(qb2) - bcs - ls):  # exact lengths
            raise ConversionError("Improperly qualified material = {}".format(qb2))

        self._code = code
        self._size = size
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
        .transferable is Boolean, True when transferable derivation code False otherwise

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
        Inherited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes


        Parameters:
            sn is int sequence number or some form of ordinal number
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
        Property sn: sequence number as int
        Returns .raw converted to int
        """
        return int.from_bytes(self.raw, 'big')

    @property
    def snh(self):
        """
        Property snh:  sequence number as hex
        Returns .sn int converted to hex str
        """
        return f"{self.sn:x}"  # "{:x}".format(self.sn)


class Dater(Matter):
    """
    Dater is subclass of Matter, cryptographic material, for RFC-3339 profile of
    ISO-8601 formatted datetimes.

    Dater provides a custom Base64 coding of an ASCII RFC-3339 profile of an
    ISO-8601 datetime by replacing the three non-Base64 characters, ':.+' with
    the Base64 equivalents, 'cdp' respectively.
    Dater provides a more compact representation than would be obtained by converting
    the raw ASCII RFC-3339 profile ISO-8601 datetime to Base64.
    Dater supports datetimes as attached crypto material in replay of events for
    the datetime of when the event was first seen.
    Restricted to specific 32 byte variant of ISO-8601 date time with microseconds
    and UTC offset in HH:MM (See RFC-3339).
    Uses default initialization derivation code = MtrDex.DateTime.
    Raises error on init if code not  MtrDex.DateTime

    Examples: given RFC-3339 profiles of ISO-8601 datetime strings:

    '2020-08-22T17:50:09.988921+00:00'
    '2020-08-22T17:50:09.988921-01:00'

    The fully encoded versions are respectively

    '1AAG2020-08-22T17c50c09d988921p00c00'
    '1AAG2020-08-22T17c50c09d988921-01c00'

    Example uses: attached first seen couples with fn+dt

    Attributes:

    Inherited Properties:  (See Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise

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
        Inherited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            dts is the ISO-8601 datetime as str or bytes
        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            if dts is None:  # defaults to now
                dts = helping.nowIso8601()
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
        Property dts:  date-time-stamp str
        Returns .qb64 translated to RFC-3339 profile of ISO 8601 datetime str
        """
        return self.qb64[self.Sizes[self.code].hs:].translate(self.FromB64)

    @property
    def dtsb(self):
        """
        Property dtsb:  date-time-stamp bytes
        Returns .qb64 translated to RFC-3339 profile of ISO 8601 datetime bytes
        """
        return self.qb64[self.Sizes[self.code].hs:].translate(self.FromB64).encode("utf-8")

    @property
    def datetime(self):
        """
        Property datetime:
        Returns datetime.datetime instance converted from .dts
        """
        return helping.fromIso8601(self.dts)


class Texter(Matter):
    """
    Texter is subclass of Matter, cryptographic material, for variable length
    strings that only contain Base64 URL safe characters. When created using
    the 'text' paramaeter, the encoded matter in qb64 format in the text domain
    is more compact than would be the case if the string were passed in as raw
    bytes. The text is used as is to form the value part of the qb64 version not
    including the leader.

    Due to ambiguity that arises for  text that starts with 'A' and whose length
    is a multiple of 3 or 4 the leading 'A' may be stripped.

    Examples: strings:
    text = ""
    qb64 = '4AAA'

    text = "-"
    qb64 = '6AABAAA-'

    text = "-A"
    qb64 = '5AABAA-A'

    text = "-A-"
    qb64 = '4AABA-A-'

    text = "-A-B"
    qb64 = '4AAB-A-B'

    Example uses: pathing for nested SADs and SAIDs


    Attributes:

    Inherited Properties:  (See Matter)
        .pad  is int number of pad chars given raw

        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise

    Properties:
        .text is the Base64 text value, .qb64 with text code and leader removed.

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
                 code=MtrDex.StrB64_L0, text=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            text is the variable sized Base64 text string
        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            if text is None:
                raise EmptyMaterialError("Missing text string.")
            if hasattr(text, "encode"):
                text = text.encode("utf-8")
            if not Reb64.match(text):
                raise ValueError("Invalid Base64.")
            raw = self._rawify(text)

        super(Texter, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)
        if self.code not in TexDex:
            raise ValidationError("Invalid code = {} for Texter."
                                  "".format(self.code))

    def _rawify(self, text):
        """Returns raw value equivalent of Base64 text.
        Suitable for variable sized matter

        Parameters:
            text (bytes): Base64 bytes
        """
        ts = len(text) % 4  # text size mod 4
        ws = (4 - ts) % 4  # pre conv wad size in chars
        ls = (3 - ts) % 3  # post conv lead size in bytes
        base = b'A' * ws + text  # pre pad with wad of zeros in Base64 == 'A'
        raw = decodeB64(base)[ls:]  # convert and remove leader
        return raw  # raw binary equivalent of text

    @property
    def text(self):
        """
        Property test:  value portion Base64 str
        Returns the value portion of .qb64 with text code and leader removed
        """
        _, _, _, ls = self.Sizes[self.code]
        text = encodeB64(bytes([0] * ls) + self.raw)
        ws = 0
        if ls == 0 and text:
            if text[0] == ord(b'A'):  # strip leading 'A' zero pad
                ws = 1
        else:
            ws = (ls + 1) % 4
        return text.decode('utf-8')[ws:]


class Pather(Texter):
    """
    Pather is a subclass of Texter that provides SAD Path language specific functionality
    for variable length strings that only contain Base64 URL safe characters.  Pather allows
    the specification of SAD Paths as a list of field components which will be converted to the
    Base64 URL safe character representation.

    Additionally, Pather provides .rawify for extracting and serializing the content targeted by
    .path for a SAD, represented as an instance of Serder.  Pather enforces Base64 URL character
    safety by leveraging the fact that SADs must have static field ordering.  Any field label can
    be replaced by its field ordinal to allow for path specification and traversal for any field
    labels that contain non-Base64 URL safe characters.


    Examples: strings:
        path = []
        text = "-"
        qb64 = '6AABAAA-'

        path = ["A"]
        text = "-A"
        qb64 = '5AABAA-A'

        path = ["A", "B"]
        text = "-A-B"
        qb64 = '4AAB-A-B'

        path = ["A", 1, "B", 3]
        text = "-A-1-B-3"
        qb64 = '4AAC-A-1-B-3'

    """

    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None, text=None,
                 code=MtrDex.StrB64_L0, path=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            path (list): array of path field components
        """

        if raw is None and text is None and qb64b is None and qb64 is None and qb2 is None:
            if path is None:
                raise EmptyMaterialError("Missing path list.")

            text = self._textify(path)

        super(Pather, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2, text=text,
                                     code=code, **kwa)

    @property
    def path(self):
        """ Path property is an array of path elements

        Path property is an array of path elements.  Empty path represents the top level.

        Returns:
            list: array of field specs of the path

        """
        if not self.text.startswith("-"):
            raise Exception("invalid SAD ptr")

        path = self.text.strip("-").split("-")
        return path if path[0] != '' else []

    def root(self, root):
        """ Returns a new Pather anchored at new root

        Returns a new Pather anchoring this path at the new root specified by root.

        Args:
            root(Pather): the new root to apply to this path

        Returns:
            Pather: new path anchored at root
        """
        return Pather(path=root.path + self.path)

    def strip(self, root):
        """ Returns a new Pather with root stipped off the front if it exists

        Returns a new Pather with root stripped off the front

        Args:
            root(Pather): the new root to apply to this path

        Returns:
            Pather: new path anchored at root
        """
        if len(root.path) > len(self.path):
            return Pather(path=self.path)

        path = list(self.path)
        try:
            for i in root.path:
                path.remove(i)
        except ValueError:
            return Pather(path=self.path)

        return Pather(path=path)

    def startswith(self, path):
        """ Returns True is path is the root of self

        Parameters:
            path (Pather): the path to check against self

        Returns:
            bool: True if path is the root of self

        """

        return self.text.startswith(path.text)

    def resolve(self, sad):
        """ Recurses thru value following ptr

        Parameters:
            sad(dict or list): the next component

        Returns:
            Value at the end of the path
        """
        return self._resolve(sad, self.path)

    def rawify(self, serder):
        """ Recurses thru value following .path and returns terminal value

        Finds the value at this path and applies the version string rules of the serder
        to serialize the value at ptr.

        Parameters:
            serder(Serder): the versioned dict to in which to resolve .path

        Returns:
            bytes: Value at the end of the path
        """
        val = self.resolve(sad=serder.ked)
        if isinstance(val, str):
            saider = Saider(qb64=val)
            return saider.qb64b
        elif isinstance(val, dict):
            return dumps(val, serder.kind)
        elif isinstance(val, list):
            return dumps(val, serder.kind)
        else:
            raise ValueError("Non-rawifiable value at {} of {}"
                             .format(self.path, serder.ked))

    @staticmethod
    def _textify(path):
        """ Returns raw value equivalent of array of path field components.

        Suitable for variable sized matter

        Parameters:
            path (list): array of path field components

        Returns:
            str:  textual representation of SAD path

        """
        text = "-"
        if not path:
            return text

        for p in path:
            if isinstance(p, str):
                text += p
            elif hasattr(p, "decode"):
                text += p.decode("utf-8")
            elif isinstance(p, int):
                text += str(p)
            else:
                raise ValueError("Invalid Path.")

            text += "-"

        return text[:-1]

    def _resolve(self, val, ptr):
        """ Recurses thru value following ptr

        Parameters:
            val(Optional(dict,list)): the next component
            ptr(list): list of path components

        Returns:
            Value at the end of the chain
        """

        if len(ptr) == 0:
            return val

        idx = ptr.pop(0)

        if isinstance(val, dict):
            if idx.isdigit():
                i = int(idx)

                keys = list(val)
                if i >= len(keys):
                    raise Exception(f"invalid dict pointer index {i} for keys {keys}")

                cur = val[list(val)[i]]
            elif idx == "":
                return val
            else:
                cur = val[idx]

        elif isinstance(val, list):
            i = int(idx)
            if i >= len(val):
                raise Exception(f"invalid array pointer index {i} for array {val}")

            cur = val[i]

        else:
            raise ValueError("invalid traversal type")

        return self._resolve(cur, ptr)


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

    Properties:  (Inherited)
        .code is str derivation code to indicate cypher suite
        .size is size (int): number of quadlets when variable sized material besides
                        full derivation code else None
        .raw is bytes crypto material only without code
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise
        .digestive is Boolean, True when digest derivation code False otherwise

    Properties:
        .verfer is verfer of public key used to verify signature

    Hidden:
        ._code is str value for .code property
        ._size is int value for .size property
        ._raw is bytes value for .raw property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

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
        .verfer is Verfer object instance of public key derived from private key
            seed which is .raw

    Methods:
        sign: create signature

    """

    def __init__(self, raw=None, code=MtrDex.Ed25519_Seed, transferable=True, **kwa):
        """
        Assign signing cipher suite function to ._sign

        Parameters:  See Matter for inherted parameters
            raw is bytes crypto material seed or private key
            code is derivation code
            transferable is Boolean True means make verifier code transferable
                                    False make non-transferable

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
                            else MtrDex.Ed25519N)
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
        .transferable is Boolean, True when transferable derivation code False otherwise

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

        if self.code not in (MtrDex.Salt_128,):
            raise ValueError("Unsupported salter code = {}.".format(self.code))

        self.tier = tier if tier is not None else self.Tier

    def stretch(self, *, size=32, path="", tier=None, temp=False):
        """
        Returns (bytes): raw binary seed (secret) derived from path and .raw
        and stretched to size given by code using argon2d stretching algorithm.

        Parameters:
            size (int): number of bytes in stretched seed
            path (str): unique chars used in derivation of seed (secret)
            tier (str): value from Tierage for security level of stretch
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use time set by tier to stretch
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
        seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_DEFAULT)
        return (seed)

    def signer(self, *, code=MtrDex.Ed25519_Seed, transferable=True, path="",
               tier=None, temp=False):
        """
        Returns Signer instance whose .raw secret is derived from path and
        salter's .raw and stretched to size given by code. The signers public key
        for its .verfer is derived from code and transferable.

        Parameters:
            code is str code of secret crypto suite
            transferable is Boolean, True means use transferace code for public key
            path is str of unique chars used in derivation of secret seed for signer
            tier is str Tierage security level
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use more time to stretch
        """
        seed = self.stretch(size=Matter._rawSize(code), path=path, tier=tier,
                            temp=temp)

        return (Signer(raw=seed, code=code, transferable=transferable))


class Cipher(Matter):
    """
    Cipher is Matter subclass holding a cipher text of a secret that may be
    either a secret seed (private key) or secret salt. The cipher text is created
    with assymetric encryption using an unrelated (public, private)
    encryption/decryption key pair. The public key is used for encryption the
    private key for decryption. The default is to use X25519 sealed box encryption.

    The Cipher instances .raw is the raw binary encrypted cipher text and its
    .code indicates what type of secret has been encrypted. The cipher suite used
    for the encryption/decryption is implied by the context where the cipher is
    used.

    See Matter for inherited attributes and properties

    """

    def __init__(self, raw=None, code=None, **kwa):
        """
        Parmeters:
            raw (Union[bytes, str]): cipher text
            code (str): cipher suite
        """
        if raw is not None and code is None:
            if len(raw) == Matter._rawSize(MtrDex.X25519_Cipher_Salt):
                code = MtrDex.X25519_Cipher_Salt
            elif len(raw) == Matter._rawSize(MtrDex.X25519_Cipher_Seed):
                code = MtrDex.X25519_Cipher_Seed

        if hasattr(raw, "encode"):
            raw = raw.encode("utf-8")  # ensure bytes not str

        super(Cipher, self).__init__(raw=raw, code=code, **kwa)

        if self.code not in (MtrDex.X25519_Cipher_Salt, MtrDex.X25519_Cipher_Seed):
            raise ValueError("Unsupported cipher code = {}.".format(self.code))

    def decrypt(self, prikey=None, seed=None):
        """
        Returns plain text as Matter instance (Signer or Salter) of cryptographic
        cipher text material given by .raw. Encrypted plain text is fully
        qualified (qb64) so derivaton code of plain text preserved through
        encryption/decryption round trip.

        Uses either decryption key given by prikey or derives prikey from
        signing key derived from private seed.

        Parameters:
            prikey (Union[bytes, str]): qb64b or qb64 serialization of private
                decryption key
            seed (Union[bytes, str]): qb64b or qb64 serialization of private
                signing key seed used to derive private decryption key
        """
        decrypter = Decrypter(qb64b=prikey, seed=seed)
        return decrypter.decrypt(ser=self.qb64b)


class Encrypter(Matter):
    """
    Encrypter is Matter subclass with method to create a cipher text of a
    fully qualified (qb64) private key/seed where private key/seed is the plain
    text. Encrypter uses assymetric (public, private) key encryption of a
    serialization (plain text). Using its .raw as the encrypting (public) key and
    its .code to indicate the cipher suite for the encryption operation.

    For example .code == MtrDex.X25519 indicates that X25519 sealed box
    encyrption is used. The encryption key may be derived from an Ed25519
    signing public key that associated with a nontransferable or basic derivation
    self certifying identifier. This allows use of the self certifying identifier
    to track or manage the encryption/decryption key pair. And could be used to
    provide additional authentication operations for using the
    encryption/decryption key pair. Support for this is provided at init time
    with the verkey parameter which allows deriving the encryption public key from
    the fully qualified verkey (signature verification key).

    See Matter for inherited attributes and properties:

    Methods:
        encrypt: returns cipher text

    """

    def __init__(self, raw=None, code=MtrDex.X25519, verkey=None, **kwa):
        """
        Assign encrypting cipher suite function to ._encrypt

        Parameters:  See Matter for inherted parameters such as qb64, qb64b
            raw (bytes): public encryption key
            qb64b (bytes): fully qualified public encryption key
            qb64 (str): fully qualified public encryption key
            code (str): derivation code for public encryption key
            verkey (Union[bytes, str]): qb64b or qb64 of verkey used to derive raw
        """
        if not raw and verkey:
            verfer = Verfer(qb64b=verkey)
            if verfer.code not in (MtrDex.Ed25519N, MtrDex.Ed25519):
                raise ValueError("Unsupported verkey derivation code = {}."
                                 "".format(verfer.code))
            # convert signing public key to encryption public key
            raw = pysodium.crypto_sign_pk_to_box_pk(verfer.raw)

        super(Encrypter, self).__init__(raw=raw, code=code, **kwa)

        if self.code == MtrDex.X25519:
            self._encrypt = self._x25519
        else:
            raise ValueError("Unsupported encrypter code = {}.".format(self.code))

    def verifySeed(self, seed):
        """
        Returns:
            Boolean: True means private signing key seed corresponds to public
                signing key verkey used to derive encrypter's .raw public
                encryption key.

        Parameters:
            seed (Union(bytes,str)): qb64b or qb64 serialization of private
                signing key seed
        """
        signer = Signer(qb64b=seed)
        verkey, sigkey = pysodium.crypto_sign_seed_keypair(signer.raw)
        pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
        return (pubkey == self.raw)

    def encrypt(self, ser=None, matter=None):
        """
        Returns:
            Cipher instance of cipher text encryption of plain text serialization
            provided by either ser or Matter instance when provided.

        Parameters:
            ser (Union[bytes,str]): qb64b or qb64 serialization of plain text
            matter (Matter): plain text as Matter instance of seed or salt to
                be encrypted
        """
        if not (ser or matter):
            raise EmptyMaterialError("Neither ser or plain are provided.")

        if ser:
            matter = Matter(qb64b=ser)

        if matter.code == MtrDex.Salt_128:  # future other salt codes
            code = MtrDex.X25519_Cipher_Salt
        elif matter.code == MtrDex.Ed25519_Seed:  # future other seed codes
            code = MtrDex.X25519_Cipher_Seed
        else:
            raise ValueError("Unsupported plain text code = {}.".format(matter.code))

        # encrypting fully qualified qb64 version of plain text ensures its
        # derivation code round trips through eventual decryption
        return (self._encrypt(ser=matter.qb64b, pubkey=self.raw, code=code))

    @staticmethod
    def _x25519(ser, pubkey, code):
        """
        Returns cipher text as Cipher instance
        Parameters:
            ser (Union[bytes, str]): qb64b or qb64 serialization of seed or salt
                to be encrypted.
            pubkey (bytes): raw binary serialization of encryption public key
            code (str): derivation code of serialized plain text seed or salt
        """
        raw = pysodium.crypto_box_seal(ser, pubkey)
        return Cipher(raw=raw, code=code)


class Decrypter(Matter):
    """
    Decrypter is Matter subclass with method to decrypt the plain text from a
    ciper text of a fully qualified (qb64) private key/seed where private
    key/seed is the plain text. Decrypter uses assymetric (public, private) key
    decryption of the cipher text using its .raw as the decrypting (private) key
    and its .code to indicate the cipher suite for the decryption operation.

    For example .code == MtrDex.X25519 indicates that X25519 sealed box
    decyrption is used. The decryption key may be derived from an Ed25519
    signing private key that is associated with a nontransferable or basic derivation
    self certifying identifier. This allows use of the self certifying identifier
    to track or manage the encryption/decryption key pair. And could be used to
    provide additional authentication operations for using the
    encryption/decryption key pair. Support for this is provided at init time
    with the sigkey parameter which allows deriving the decryption private key
    from the fully qualified sigkey (signing key).

    See Matter for inherited attributes and properties:

    Attributes:

    Properties:


    Methods:
        decrypt: create cipher text

    """

    def __init__(self, code=MtrDex.X25519_Private, seed=None, **kwa):
        """
        Assign decrypting cipher suite function to ._decrypt

        Parameters:  See Matter for inheirted parameters
            raw (bytes): private decryption key derived from seed (private signing key)
            qb64b (bytes): fully qualified private decryption key
            qb64 (str): fully qualified private decryption key
            code (str): derivation code for private decryption key
            seed (Union[bytes, str]): qb64b or qb64 of signing key seed used to
                derive raw which is private decryption key
        """
        try:
            super(Decrypter, self).__init__(code=code, **kwa)
        except EmptyMaterialError as ex:
            if seed:
                signer = Signer(qb64b=seed)
                if signer.code not in (MtrDex.Ed25519_Seed,):
                    raise ValueError("Unsupported signing seed derivation code = {}."
                                     "".format(signer.code))
                # verkey, sigkey = pysodium.crypto_sign_seed_keypair(signer.raw)
                sigkey = signer.raw + signer.verfer.raw  # sigkey is raw seed + raw verkey
                raw = pysodium.crypto_sign_sk_to_box_sk(sigkey)  # raw private encrypt key
                super(Decrypter, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise

        if self.code == MtrDex.X25519_Private:
            self._decrypt = self._x25519
        else:
            raise ValueError("Unsupported decrypter code = {}.".format(self.code))

    def decrypt(self, ser=None, cipher=None, transferable=False):
        """
        Returns:
            Salter or Signer instance derived from plain text decrypted from
            encrypted cipher text material given by ser or cipher. Plain text
            that is orignally encrypt should always be fully qualified (qb64b)
            so that derivaton code of plain text is preserved through
            encryption/decryption round trip.

        Parameters:
            ser (Union[bytes,str]): qb64b or qb64 serialization of cipher text
            cipher (Cipher): optional Cipher instance when ser is None
            transferable (bool): True means associated verfer of returned
                signer is transferable. False means non-transferable
        """
        if not (ser or cipher):
            raise EmptyMaterialError("Neither ser or cipher are provided.")

        if ser:  # create cipher to ensure valid derivation code of material in ser
            cipher = Cipher(qb64b=ser)

        return (self._decrypt(cipher=cipher,
                              prikey=self.raw,
                              transferable=transferable))

    @staticmethod
    def _x25519(cipher, prikey, transferable=False):
        """
        Returns plain text as Salter or Signer instance depending on the cipher
            code and the embedded encrypted plain text derivation code.

        Parameters:
            cipher (Cipher): instance of encrypted seed or salt
            prikey (bytes): raw binary decryption private key derived from
                signing seed or sigkey
            transferable (bool): True means associated verfer of returned
                signer is transferable. False means non-transferable
        """
        pubkey = pysodium.crypto_scalarmult_curve25519_base(prikey)
        plain = pysodium.crypto_box_seal_open(cipher.raw, pubkey, prikey)  # qb64b
        # ensure raw plain text is qb64b or qb64 so its derivation code is round tripped
        if cipher.code == MtrDex.X25519_Cipher_Salt:
            return Salter(qb64b=plain)
        elif cipher.code == MtrDex.X25519_Cipher_Seed:
            return Signer(qb64b=plain, transferable=transferable)
        else:
            raise ValueError("Unsupported cipher text code = {}.".format(cipher.code))


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
        .transferable is Boolean, True when transferable derivation code False otherwise

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
                dig = dig.encode('utf-8')  # makes bytes

            if dig == self.qb64b:  # matching
                return True

            diger = Diger(qb64b=dig)  # extract code

        elif diger is not None:
            if diger.qb64b == self.qb64b:
                return True

        else:
            raise ValueError("Both dig and diger may not be None.")

        if diger.code == self.code:  # digest not match but same code
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
        return (blake3.blake3(ser).digest() == raw)

    @staticmethod
    def _blake2b_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2b_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return (hashlib.blake2b(ser, digest_size=32).digest() == raw)

    @staticmethod
    def _blake2s_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2s_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return (hashlib.blake2s(ser, digest_size=32).digest() == raw)

    @staticmethod
    def _sha3_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2s_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return (hashlib.sha3_256(ser).digest() == raw)

    @staticmethod
    def _sha2_256(ser, raw):
        """
        Returns True if verified False otherwise
        Verifiy blake2s_256 digest of ser matches raw

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return (hashlib.sha256(ser).digest() == raw)


class Nexter:
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
        .transferable True when transferable derivation code False otherwise

    Properties:

    Methods:

    Hidden:
        ._digest is digest method
        ._derive is derivation method


    """

    def __init__(self, digs=None, keys=None, ked=None):
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
        self.digs = self._derive(digs=digs, keys=keys, ked=ked)  # derive nxt raw

    def verify(self, digs=None, keys=None, ked=None):
        """
        Returns True if digest of bytes nxt raw matches .raw
        Uses .raw as reference nxt raw for ._verify algorithm determined by .code

        If raw not provided then extract raw from either (sith, keys) or ked

        Parameters:
            raw is bytes serialization
            imen is string extracted from sith expression using Tholder
            sith is signing threshold as
                str lowercase hex or
                int or
                list of strs or list of list of strs
            digs is list of digests qb64
            keys is list of keys qb64
            ked is key event dict
        """
        if not digs:
            digs = self._derive(digs=digs, keys=keys, ked=ked)

        if len(digs) == len(self.digs):
            return self.digs == digs

        elif len(digs) < len(self.digs):
            existing = list(self.digs)
            found = []
            for kdig in digs:
                while existing:
                    ndig = existing.pop(0)
                    if kdig == ndig:
                        found.append(kdig)
                        break

                if not existing:
                    break

            return digs == found

        else:
            return False

    def indices(self, sigers):
        ion = []
        for sig in sigers:
            idig = Diger(ser=sig.verfer.qb64b).qb64
            try:
                ion.append(self.digs.index(idig))
            except ValueError:
                raise ValueError(f'indices into verfer unable to locate {idig} in {self.digs}')

        return ion

    @staticmethod
    def _derive(digs=None, keys=None, ked=None):
        """
        Returns ser where ser is serialization derived from code, sith, keys, or ked
        """
        if digs is None:
            if not keys:
                try:
                    keys = ked["k"]
                except KeyError as ex:
                    raise DerivationError("Error extracting keys from"
                                          " ked = {}".format(ex))

            if not keys:  # empty keys
                raise DerivationError("Empty keys.")

            digs = [Diger(ser=key.encode("utf-8")).qb64 for key in keys]

        return digs

    @property
    def digers(self):
        return [Diger(qb64=dig) for dig in self.digs]

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
        .transferable is Boolean, True when transferable derivation code False otherwise

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

    def __init__(self, raw=None, code=None, ked=None, allows=None, **kwa):
        """
        assign ._derive to derive aid prefix from ked
        assign ._verify to verify derivation of aid prefix from ked

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
            allows (list): allowed codes for prefix. When None then all supported
                codes are allowed. This enables a particular use case to restrict
                the codes allowed to a subset of all supported.

        """
        try:
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not ked or (not code and "i" not in ked):
                raise ex

            if not code:  # get code from pre in ked
                super(Prefixer, self).__init__(qb64=ked["i"], code=code, **kwa)
                code = self.code

            if allows is not None and code not in allows:
                raise ValueError("Unallowed code={} for prefixer.".format(code))

            if code == MtrDex.Ed25519N:
                self._derive = self._derive_ed25519N
            elif code == MtrDex.Ed25519:
                self._derive = self._derive_ed25519
            elif code == MtrDex.Blake3_256:
                self._derive = self._derive_blake3_256
            else:
                raise ValueError("Unsupported code = {} for prefixer.".format(code))

            # use ked and ._derive from code to derive aid prefix and code
            raw, code = self._derive(ked=ked)
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)

        if self.code == MtrDex.Ed25519N:
            self._verify = self._verify_ed25519N
        elif self.code == MtrDex.Ed25519:
            self._verify = self._verify_ed25519
        elif self.code == MtrDex.Blake3_256:
            self._verify = self._verify_blake3_256
        else:
            raise ValueError("Unsupported code = {} for prefixer.".format(self.code))

    def derive(self, ked):
        """
        Returns tuple (raw, code) of aid prefix as derived from key event dict ked.
                uses a derivation code specific _derive method

        Parameters:
            ked is inception key event dict
            seed is only used for sig derivation it is the secret key/secret

        """
        if ked["t"] not in (Ilks.icp, Ilks.dip, Ilks.vcp):
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ked["t"]))
        return (self._derive(ked=ked))

    def verify(self, ked, prefixed=False):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        Parameters:
            ked is inception key event dict
        """
        if ked["t"] not in (Ilks.icp, Ilks.dip, Ilks.vcp):
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ked["t"]))
        return (self._verify(ked=ked, pre=self.qb64, prefixed=prefixed))

    def _derive_ed25519N(self, ked):
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

            if verfer.code == MtrDex.Ed25519N and "b" in ked and ked["b"]:
                raise DerivationError("Non-empty b = {} for non-transferable"
                                      " code = {}".format(ked["b"],
                                                          verfer.code))

            if verfer.code == MtrDex.Ed25519N and "a" in ked and ked["a"]:
                raise DerivationError("Non-empty a = {} for non-transferable"
                                      " code = {}".format(ked["a"],
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

    def _derive_ed25519(self, ked):
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

    def _derive_blake3_256(self, ked):
        """
        Returns tuple (raw, code) of pre (qb64) as blake3 digest
            as derived from inception key event dict ked
        """
        ked = dict(ked)  # make copy so don't clobber original ked
        ilk = ked["t"]
        if ilk not in (Ilks.icp, Ilks.dip, Ilks.vcp):
            raise DerivationError("Invalid ilk = {} to derive pre.".format(ilk))

        # put in dummy pre to get size correct
        ked["i"] = self.Dummy * Matter.Sizes[MtrDex.Blake3_256].fs
        ked["d"] = ked["i"]
        raw, ident, kind, ked, version = Sizeify(ked=ked)
        dig = blake3.blake3(raw).digest()  # digest with dummy 'i'
        return (dig, MtrDex.Blake3_256)  # dig is derived correct new 'i'

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
            raw, code = self._derive_blake3_256(ked=ked)  # replace with dummy 'i'
            crymat = Matter(raw=raw, code=MtrDex.Blake3_256)
            if crymat.qb64 != pre:  # derived raw with dummy 'i' must match pre
                return False

            if prefixed and ked["i"] != pre:  # incoming 'i' must match pre
                return False

        except Exception as ex:
            return False

        return True


Idage = namedtuple("Idage", "dollar at id_ i d")

Ids = Idage(dollar="$id", at="@id", id_="id", i="i", d="d")

# digest klas, digest size (not default), digest length
# size and length are needed for some digest types as function parameters
Digestage = namedtuple("Digestage", "klas size length")


class Saider(Matter):
    """
    Saider is Matter subclass for self-addressing identifier prefix using
    derivation as determined by code from ked

    Properties: (inherited)
        code (str): derivation code to indicate cypher suite
        size (int): number of quadlets when variable sized material besides
                        full derivation code else None
        raw (bytes): crypto material only without code
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise

    Hidden:
        _code (str): value for .code property
        _size (int): value for .size property
        _raw (bytes): value for .raw property
        _infil (types.MethodType): creates qb64b from .raw and .code
                                   (fully qualified Base64)
        _exfil (types.MethodType): extracts .code and .raw from qb64b
                                   (fully qualified Base64)
        _derive (types.MethodType): derives said (.qb64 )
        _verify (types.MethodType): verifies said ((.qb64 ) against a given sad

    """
    Dummy = "#"  # dummy spaceholder char for said. Must not be a valid Base64 char
    # should be same set of codes as in coring.DigestCodex coring.DigDex so
    # .digestive property works. Unit test ensures code sets match
    Digests = {
        MtrDex.Blake3_256: Digestage(klas=blake3.blake3, size=None, length=None),
        MtrDex.Blake2b_256: Digestage(klas=hashlib.blake2b, size=32, length=None),
        MtrDex.Blake2s_256: Digestage(klas=hashlib.blake2s, size=None, length=None),
        MtrDex.SHA3_256: Digestage(klas=hashlib.sha3_256, size=None, length=None),
        MtrDex.SHA2_256: Digestage(klas=hashlib.sha256, size=None, length=None),
        MtrDex.Blake3_512: Digestage(klas=blake3.blake3, size=None, length=64),
        MtrDex.Blake2b_512: Digestage(klas=hashlib.blake2b, size=None, length=None),
        MtrDex.SHA3_512: Digestage(klas=hashlib.sha3_512, size=None, length=None),
        MtrDex.SHA2_512: Digestage(klas=hashlib.sha512, size=None, length=None),
    }

    def __init__(self, raw=None, *, code=None, sad=None,
                 kind=None, label=Ids.d, **kwa):
        """
        See Matter.__init__ for inherited parameters

        Parameters:
            sad (dict): self addressed data to serialize and inject said
            kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json
            label (str): id field label, one of Ids
        """
        try:
            # when raw and code are both provided
            super(Saider, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:  # raw or code missing
            if not sad or label not in sad:
                raise ex  # need sad with label field to calculate raw or qb64

            if not code:
                if sad[label]:  # no code but sad[label] not empty
                    # attempt to get code from said in sad
                    super(Saider, self).__init__(qb64=sad[label], code=code, **kwa)
                    code = self._code
                else:  # use default code
                    code = MtrDex.Blake3_256

            if code not in DigDex:  # need valid code
                raise ValueError("Unsupported digest code = {}.".format(code))

            # re-derive said raw bytes from sad and code, so code overrides label
            raw, sad = self.derive(sad=dict(sad), code=code, kind=kind, label=label)
            super(Saider, self).__init__(raw=raw, code=code, **kwa)

        if not self.digestive:
            raise ValueError("Unsupported digest code = {}."
                             "".format(self.code))

    @classmethod
    def _serialize(clas, sad: dict, kind: str = None):
        """
        Serialize sad with serialization kind if provided else use
            use embedded 'v', version string if provided else use default
            Serials.json

        Returns:
           ser (bytes): raw serialization of sad

        Parameters:
           sad (dict): serializable dict
           kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json

        """
        knd = Serials.json
        if 'v' in sad:  # versioned sad
            _, knd, _, _ = Deversify(sad['v'])

        if not kind:  # match logic of Serder for kind
            kind = knd

        return dumps(sad, kind=kind)

    @classmethod
    def saidify(clas, sad: dict, *,
                code: str = MtrDex.Blake3_256,
                kind: str = None,
                label: str = Ids.d, **kwa):
        """
        Derives said from sad and injects it into copy of sad and said and
        injected sad

        Returns:
            result (tuple): of the form (saider, sad) where saider is Saider
                    instance generated from sad using code and sad is copy of
                    parameter sad but with its label id field filled
                    in with generated said from saider

        Parameters:
            sad (dict): serializable dict
            code (str): digest type code from DigDex
            kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json
            label (str): id field label from Ids in which to inject said

        """
        if label not in sad:
            raise KeyError("Missing id field labeled={} in sad.".format(label))
        raw, sad = clas._derive(sad=sad, code=code, kind=kind, label=label)
        saider = clas(raw=raw, code=code, kind=kind, label=label, **kwa)
        sad[label] = saider.qb64
        return (saider, sad)

    @classmethod
    def _derive(clas, sad: dict, *,
                code: str = MtrDex.Blake3_256,
                kind: str = None,
                label: str = Ids.d, ):
        """
        Derives raw said from sad with .Dummy filled sad[label]

        Returns:
            raw (bytes): raw said from sad with dummy filled label id field

        Parameters:
            sad (dict): self addressed data to be injected with dummy and serialized
            code (str): digest type code from DigDex
            kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json
            label (str): id field label from Ids in which to inject dummy
        """
        if code not in DigDex or code not in clas.Digests:
            raise ValueError("Unsupported digest code = {}.".format(code))

        sad = dict(sad)  # make shallow copy so don't clobber original sad
        # fill id field denoted by label with dummy chars to get size correct
        sad[label] = clas.Dummy * Matter.Sizes[code].fs
        if 'v' in sad:  # if versioned then need to set size in version string
            raw, ident, kind, sad, version = Sizeify(ked=sad, kind=kind)

        # string now has
        # correct size
        klas, size, length = clas.Digests[code]
        # sad as 'v' verision string then use its kind otherwise passed in kind
        cpa = [clas._serialize(sad, kind=kind)]  # raw pos arg class
        ckwa = dict()  # class keyword args
        if size:
            ckwa.update(digest_size=size)  # optional digest_size
        dkwa = dict()  # digest keyword args
        if length:
            dkwa.update(length=length)
        return klas(*cpa, **ckwa).digest(**dkwa), sad  # raw digest and sad

    def derive(self, sad, code=None, **kwa):
        """
        Returns:
            result (tuple): (raw, sad) raw said as derived from serialized dict
                            and modified sad during derivation.

        Parameters:
            sad (dict): self addressed data to be serialized
            code (str): digest type code from DigDex.
            kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json
            label (str): id field label from Ids in which to inject dummy
        """
        code = code if code is not None else self.code
        return self._derive(sad=sad, code=code, **kwa)

    def verify(self, sad, *, prefixed=False, versioned=True, code=None,
               kind=None, label=Ids.d, **kwa):
        """
        Returns:
            result (bool): True means derivation from sad with dummy label
                field value replacement for ._code matches .qb64. False otherwise
                If prefixed is True then also validates that label field of
                provided sad also matches .qb64. False otherwise
                If versioned is True and provided sad includes version field 'v'
                then also validates that version field 'v' of provided
                sad matches the version field of modified sad that results from
                the derivation process. The size chars in the version field
                are set to the size of the sad during derivation. False otherwise.

        Parameters:
            sad (dict): self addressed data to be serialized
            prefixed (bool): True means also verify if labeled field in
                sad matches own .qb64
            versioned (bool):
            code (str): digest type code from DigDex.
            kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json
            label (str): id field label from Ids in which to inject dummy
        """
        try:
            # override ensure code is self.code
            raw, dsad = self._derive(sad=sad, code=self.code, kind=kind, label=label)
            saider = Saider(raw=raw, code=self.code, **kwa)
            if self.qb64b != saider.qb64b:
                return False  # not match .qb64b

            if 'v' in sad and versioned:
                if sad['v'] != dsad['v']:
                    return False  # version fields not match

            if prefixed and sad[label] != self.qb64:  # check label field
                return False  # label id field not match .qb64

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
    Ed25519_Sig: str = 'A'  # Ed25519 signature.
    ECDSA_256k1_Sig: str = 'B'  # ECDSA secp256k1 signature.
    Ed448_Sig: str = '0A'  # Ed448 signature.
    Label: str = '0B'  # Variable len label L=N*4 <= 4095 char quadlets

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
    Ed25519_Sig: str = 'A'  # Ed25519 signature.
    ECDSA_256k1_Sig: str = 'B'  # ECDSA secp256k1 signature.
    Ed448_Sig: str = '0A'  # Ed448 signature.

    def __iter__(self):
        return iter(astuple(self))


IdxSigDex = IndexedSigCodex()  # Make instance


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
    # Hards table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always > 0 for Indexer.
    Hards = ({chr(c): 1 for c in range(65, 65 + 26)})
    Hards.update({chr(c): 1 for c in range(97, 97 + 26)})
    Hards.update([('0', 2), ('1', 2), ('2', 2), ('3', 2), ('4', 3), ('5', 4)])
    # Sizes table maps hs chars of code to Sizage namedtuple of (hs, ss, fs)
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be  > 0 for Indexer
    Sizes = {
        'A': Sizage(hs=1, ss=1, fs=88, ls=0),
        'B': Sizage(hs=1, ss=1, fs=88, ls=0),
        '0A': Sizage(hs=2, ss=2, fs=156, ls=0),
        '0B': Sizage(hs=2, ss=2, fs=None, ls=0),
    }
    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first code char. Used for ._bexfil.
    Bards = ({b64ToB2(c): hs for c, hs in Hards.items()})

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
        if raw is not None:  # raw provided
            if not code:
                raise EmptyMaterialError("Improper initialization need either "
                                         "(raw and code) or qb64b or qb64 or qb2.")
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))

            if code not in self.Sizes:
                raise UnexpectedCodeError("Unsupported code={}.".format(code))

            hs, ss, fs, ls = self.Sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            if index < 0 or index > (64 ** ss - 1):
                raise InvalidVarIndexError("Invalid index={} for code={}.".format(index, code))

            if not fs:  # compute fs from index
                if cs % 4:
                    raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                               "variable length material. cs={}.".format(cs))
                fs = (index * 4) + cs

            rawsize = (fs - cs) * 3 // 4

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
        hs, ss, fs, ls = cls.Sizes[code]  # get sizes
        return ((fs - (hs + ss)) * 3 // 4)

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

        hs, ss, fs, ls = self.Sizes[code]

        if index < 0 or index > (64 ** ss - 1):
            raise InvalidVarIndexError("Invalid index={} for code={}."
                                       "".format(index, code))

        # both is hard code + converted index
        both = "{}{}".format(code, intToB64(index, l=ss))

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
        if first not in self.Hards:
            if first[0] == '-':
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Indexer.")
            elif first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Indexer.")
            else:
                raise UnexpectedCodeError("Unsupported code start char={}.".format(first))

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(hs - len(qb64b)))

        hard = qb64b[:hs]  # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")
        if hard not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]  # assumes hs in both tables consistent
        cs = hs + ss  # both hard + soft code size
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

        if len(qb64b) < cs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(cs - len(qb64b)))

        index = qb64b[hs:hs + ss]  # extract index chars
        if hasattr(index, "decode"):
            index = index.decode("utf-8")
        index = b64ToInt(index)  # compute int index

        if not fs:  # compute fs from index
            if cs % 4:
                raise ValidationError("Whole code size not multiple of 4 for "
                                      "variable length material. cs={}.".format(cs))
            fs = (index * 4) + cs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError("Need {} more chars.".format(fs - len(qb64b)))

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # strip off prepended code and append pad characters
        ps = cs % 4  # pad size ps = cs mod 4
        base = qb64b[cs:] + ps * BASE64_PAD
        raw = decodeB64(base)
        if len(raw) != (len(qb64b) - cs) * 3 // 4:  # exact lengths
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
        raw = self.raw  # bytes or bytearray

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss
        if not fs:  # compute fs from index
            if cs % 4:
                raise InvalidCodeSizeError("Whole code size not multiple of 4 for "
                                           "variable length material. cs={}.".format(cs))
            fs = (index * 4) + cs

        if index < 0 or index > (64 ** ss - 1):
            raise InvalidVarIndexError("Invalid index={} for code={}.".format(index, code))

        # both is hard code + converted index
        both = "{}{}".format(code, intToB64(index, l=ss))

        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        n = sceil(cs * 3 / 4)  # number of b2 bytes to hold b64 code + index
        bcode = b64ToInt(both).to_bytes(n, 'big')  # right aligned b2 code

        full = bcode + raw
        bfs = len(full)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError("Invalid code = {} for raw size= {}."
                                       .format(both, len(raw)))

        i = int.from_bytes(full, 'big') << (2 * (cs % 4))  # left shift in pad bits
        return (i.to_bytes(bfs, 'big'))

    def _bexfil(self, qb2):
        """
        Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 1)  # extract first sextet as code selector
        if first not in self.Bards:
            if first[0] == b'\xf8':  # b64ToB2('-')
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == b'\xfc':  # b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bcs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bhs - len(qb2)))

        hard = b2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

        bcs = ceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = b2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        index = b64ToInt(both[hs:hs + ss])  # get index
        if not fs:
            fs = (index * 4) + cs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))

        qb2 = qb2[:bfs]  # fully qualified primitive code plus material

        # right shift to right align raw material
        i = int.from_bytes(qb2, 'big')
        i >>= 2 * (cs % 4)

        raw = i.to_bytes(bfs, 'big')[bcs:]  # extract raw

        if len(raw) != (len(qb2) - bcs):  # exact lengths
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

    ControllerIdxSigs: str = '-A'  # Qualified Base64 Indexed Signature.
    WitnessIdxSigs: str = '-B'  # Qualified Base64 Indexed Signature.
    NonTransReceiptCouples: str = '-C'  # Composed Base64 Couple, pre+cig.
    TransReceiptQuadruples: str = '-D'  # Composed Base64 Quadruple, pre+snu+dig+sig.
    FirstSeenReplayCouples: str = '-E'  # Composed Base64 Couple, fnu+dts.
    TransIdxSigGroups: str = '-F'  # Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.
    SealSourceCouples: str = '-G'  # Composed Base64 couple, snu+dig of given delegators or issuers event
    TransLastIdxSigGroups: str = '-H'  # Composed Base64 Group, pre+ControllerIdxSigs group.
    SealSourceTriples: str = '-I'  # Composed Base64 triple, pre+snu+dig of anchoring source event
    SadPathSig: str = '-J'  # Composed Base64 Group path+TransIdxSigGroup of SAID of content
    SadPathSigGroup: str = '-K'  # Composed Base64 Group, root(path)+SaidPathCouples
    PathedMaterialQuadlets: str = '-L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    MessageDataGroups: str = '-U'  # Composed Message Data Group or Primitive
    AttachedMaterialQuadlets: str = '-V'  # Composed Grouped Attached Material Quadlet (4 char each)
    MessageDataMaterialQuadlets: str = '-W'  # Composed Grouped Message Data Quadlet (4 char each)
    CombinedMaterialQuadlets: str = '-X'  # Combined Message Data + Attachments Quadlet (4 char each)
    MaterialGroups: str = '-Y'  # Composed Generic Material Group or Primitive
    MaterialQuadlets: str = '-Z'  # Composed Generic Material Quadlet (4 char each)
    AnchorSealGroups: str = '-a'  # Composed Anchor Seal Material Group
    ConfigTraits: str = '-c'  # Composed Config Trait Material Group
    DigestSealQuadlets: str = '-d'  # Composed Digest Seal Quadlet (4 char each)
    EventSealQuadlets: str = '-e'  # Composed Event Seal Quadlet (4 char each)
    Keys: str = '-k'  # Composed Key Material Primitive
    LocationSealQuadlets: str = '-l'  # Composed Location Seal Quadlet (4 char each)
    RootDigestSealQuadlets: str = '-r'  # Composed Root Digest Seal Quadlet (4 char each)
    Witnesses: str = '-w'  # Composed Witness Prefix Material Primitive
    BigMessageDataGroups: str = '-0U'  # Composed Message Data Group or Primitive
    BigAttachedMaterialQuadlets: str = '-0V'  # Composed Grouped Attached Material Quadlet (4 char each)
    BigMessageDataMaterialQuadlets: str = '-0W'  # Composed Grouped Message Data Quadlet (4 char each)
    BigCombinedMaterialQuadlets: str = '-0X'  # Combined Message Data + Attachments Quadlet (4 char each)
    BigMaterialGroups: str = '-0Y'  # Composed Generic Material Group or Primitive
    BigMaterialQuadlets: str = '-0Z'  # Composed Generic Material Quadlet (4 char each)

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
    # Hards table maps from bytes Base64 first two code chars to int of
    # hard size, hs,(stable) of code. The soft size, ss, (unstable) for Counter
    # is always > 0 and hs + ss = fs always
    Hards = ({('-' + chr(c)): 2 for c in range(65, 65 + 26)})
    Hards.update({('-' + chr(c)): 2 for c in range(97, 97 + 26)})
    Hards.update([('-0', 3)])
    # Sizes table maps hs chars of code to Sizage namedtuple of (hs, ss, fs)
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be  > 0 and hs+ss=fs for Counter
    Sizes = {
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
        '-U': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-W': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-X': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-Y': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-Z': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-a': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-c': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-d': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-e': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-k': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-l': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-r': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-w': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-0U': Sizage(hs=3, ss=5, fs=8, ls=0),
        '-0V': Sizage(hs=3, ss=5, fs=8, ls=0),
        '-0W': Sizage(hs=3, ss=5, fs=8, ls=0),
        '-0X': Sizage(hs=3, ss=5, fs=8, ls=0),
        '-0Y': Sizage(hs=3, ss=5, fs=8, ls=0),
        '-0Z': Sizage(hs=3, ss=5, fs=8, ls=0)
    }
    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first two code char. Used for ._bexfil.
    Bards = ({b64ToB2(c): hs for c, hs in Hards.items()})

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
        if code is not None:  # code provided
            if code not in self.Sizes:
                raise UnknownCodeError("Unsupported code={}.".format(code))

            hs, ss, fs, ls = self.Sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            if fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
                raise InvalidCodeSizeError("Whole code size not full size or not "
                                           "multiple of 4. cs={} fs={}.".format(cs, fs))

            if count < 0 or count > (64 ** ss - 1):
                raise InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

            self._code = code
            self._count = count

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self.Sizes[self.code].fs]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:  # rewrite to use direct binary exfiltration
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self.Sizes[self.code].fs * 3 // 4]

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

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss  # both hard + soft size
        if fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
            raise InvalidCodeSizeError("Whole code size not full size or not "
                                       "multiple of 4. cs={} fs={}.".format(cs, fs))
        if count < 0 or count > (64 ** ss - 1):
            raise InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

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
        if first not in self.Hards:
            if first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected op code start"
                                            "while extracing Counter.")
            else:
                raise UnexpectedCodeError("Unsupported code start ={}.".format(first))

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(hs - len(qb64b)))

        hard = qb64b[:hs]  # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")
        if hard not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]  # assumes hs consistent in both tables
        cs = hs + ss  # both hard + soft code size

        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        if len(qb64b) < cs:  # need more bytes
            raise ShortageError("Need {} more characters.".format(cs - len(qb64b)))

        count = qb64b[hs:hs + ss]  # extract count chars
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

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss
        if fs != cs or cs % 4:  # fs must be cs and multiple of 4 for count codes
            raise InvalidCodeSizeError("Whole code size not full size or not "
                                       "multiple of 4. cs={} fs={}.".format(cs, fs))

        if count < 0 or count > (64 ** ss - 1):
            raise InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

        # both is hard code + converted count
        both = "{}{}".format(code, intToB64(count, l=ss))
        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        return (b64ToB2(both))  # convert to b2 left shift if any

    def _bexfil(self, qb2):
        """
        Extracts self.code and self.count from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 2)  # extract first two sextets as code selector
        if first not in self.Bards:
            if first[0] == b'\xfc':  # b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bhs - len(qb2)))

        hard = b2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        bcs = ceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = b2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        count = b64ToInt(both[hs:hs + ss])  # get count

        self._code = hard
        self._count = count


class Sadder:
    """
    Sadder is KERI key event serializer-deserializer class
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
        .werfers is list of Verfers converted from .ked["b"]
        .tholder is Tholder instance from .ked["kt'] else None
        .ntholder is Tholder instance from .ked["nt'] else None
        .sn is int sequence number converted from .ked["s"]
        .pre is qb64 str of identifier prefix from .ked["i"]
        .preb is qb64b bytes of identifier prefix from .ked["i"]
        .said is qb64 of .ked['d'] if present
        .saidb is qb64b of .ked['d'] of present

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

    def __init__(self, raw=b'', ked=None, kind=None, sad=None, code=MtrDex.Blake3_256):
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
        self._code = code  # need default code for .saider
        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif ked:  # serialize ked using property setter
            self._kind = kind
            self.ked = ked  # ked property setter does the serialization
        elif sad:
            self._clone(sad=sad)
        else:
            raise ValueError("Improper initialization need sad, raw or ked.")

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
        ident, kind, version, size = sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}, expected {}."
                               "".format(version.major, version.minor, Version))
        if len(raw) < size:
            raise ShortageError("Need more bytes.")

        ked = loads(raw=raw, size=size, kind=kind)

        return ked, ident, kind, version, size


    def _exhale(self, ked, kind=None):
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
        return Sizeify(ked=ked, kind=kind)

    def compare(self, said=None):
        """
        Returns True  if said and either .saider.qb64 or .saider.qb64b match

        Convenience method to allow comparison of own .saider digest self.raw
        with some other purported said of self.raw

        Parameters:
            said is qb64b or qb64 SAID of ser to compare with .said

        """

        if said is not None:
            if hasattr(said, "encode"):
                said = said.encode('utf-8')  # makes bytes

            return said == self.saidb  # matching

        else:
            raise ValueError("Both said and saider may not be None.")


    def _clone(self, sad):
        self._raw = sad.raw
        self._ked = sad.ked
        self._ident = sad.ident
        self._kind = sad.kind
        self._size = sad.size
        self._version = sad.version
        self._saider = sad.saider


    @property
    def raw(self):
        """ raw property getter """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        ked, ident, kind, version, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._ked = ked
        self._ident = ident
        self._kind = kind
        self._version = version
        self._size = size
        self._saider = Saider(qb64=ked["d"], code=self._code)

    @property
    def ked(self):
        """ ked property getter"""
        return self._ked

    @ked.setter
    def ked(self, ked):
        """ ked property setter  assumes ._kind """
        raw, ident, kind, ked, version = self._exhale(ked=ked, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._ident = ident
        self._kind = kind
        self._size = size
        self._version = version
        self._saider = Saider(qb64=ked["d"], code=self._code)

    @property
    def kind(self):
        """ kind property getter"""
        return self._kind

    @kind.setter
    def kind(self, kind):
        """ kind property setter Assumes ._ked """
        raw, ident, kind, ked, version = self._exhale(ked=self._ked, kind=kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ident = ident
        self._ked = ked
        self._kind = kind
        self._size = size
        self._version = version
        self._saider = Saider(qb64=ked["d"], code=self._code)


    @property
    def ident(self):
        """ ident property getter

        Returns:
            (Identage)
        """
        return self._ident

    @property
    def version(self):
        """
        version property getter

        Returns:
            (Versionage)
        """
        return self._version

    @property
    def size(self):
        """ size property getter"""
        return self._size

    @property
    def saider(self):
        """
        Returns Diger of digest of self.raw
        diger (digest material) property getter
        """
        return self._saider

    @property
    def said(self):
        """
        Returns str qb64  of .ked["d"] (said when ked is SAD)
        said (self-addressing identifier) property getter
        """
        return self.saider.qb64

    @property
    def saidb(self):
        """
        Returns bytes qb64b of .ked["d"] (said when ked is SAD)
        said (self-addressing identifier) property getter
        """
        return self.saider.qb64b

    def pretty(self, *, size=1024):
        """
        Returns str JSON of .ked with pretty formatting

        ToDo: add default size limit on pretty when used for syslog UDP MCU
        like 1024 for ogler.logger
        """
        return json.dumps(self.ked, indent=1)[:size if size is not None else None]


class Serder(Sadder):
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
        .werfers is list of Verfers converted from .ked["b"]
        .tholder is Tholder instance from .ked["kt'] else None
        .ntholder is Tholder instance from .ked["nt'] else None
        .sn is int sequence number converted from .ked["s"]
        .pre is qb64 str of identifier prefix from .ked["i"]
        .preb is qb64b bytes of identifier prefix from .ked["i"]
        .said is qb64 of .ked['d'] if present
        .saidb is qb64b of .ked['d'] of present

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

    def __init__(self, raw=b'', ked=None, kind=None, sad=None, code=MtrDex.Blake3_256):
        """
        Deserialize if raw provided
        Serialize if ked provided but not raw
        When serilaizing if kind provided then use kind instead of field in ked

        Parameters:
          raw is bytes of serialized event plus any attached signatures
          ked is key event dict or None
            if None its deserialized from raw
          sad (Sadder) is clonable base class
          kind is serialization kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind is None then its extracted from ked or raw
          code is .diger default digest code

        """
        super(Serder, self).__init__(raw=raw, ked=ked, kind=kind, sad=sad, code=code)

        if self._ident != Idents.keri:
            raise ValueError("Invalid ident {}, must be KERI".format(self._ident))


    @property
    def verfers(self):
        """
        Returns list of Verfer instances as converted from .ked['k'].
        One for each key.
        verfers property getter
        """
        if "k" in self.ked:  # establishment event
            keys = self.ked["k"]
        else:  # non-establishment event
            keys = []

        return [Verfer(qb64=key) for key in keys]

    @property
    def nexter(self):
        """
        Returns list of Diger instances as converted from .ked['n'].
        One for each key.
        nkeys property getter
        """
        if "n" in self.ked:  # establishment event
            keys = self.ked["n"]
        else:  # non-establishment event
            keys = []

        return Nexter(digs=keys)

    @property
    def werfers(self):
        """
        Returns list of Verfer instances as converted from .ked['b'].
        One for each backer (witness).
        werfers property getter
        """
        if "b" in self.ked:  # inception establishment event
            wits = self.ked["b"]
        else:  # non-establishment event
            wits = []

        return [Verfer(qb64=wit) for wit in wits]

    @property
    def tholder(self):
        """
        Returns Tholder instance as converted from .ked['kt'] or None if missing.

        """
        return Tholder(sith=self.ked["kt"]) if "kt" in self.ked else None

    @property
    def ntholder(self):
        """
        Returns Tholder instance as converted from .ked['nt'] or None if missing.

        """
        return Tholder(sith=self.ked["nt"]) if "nt" in self.ked else None

    @property
    def sn(self):
        """
        sn (sequence number) property getter
        Returns:
            sn (int): converts hex str .ked["s"] to non neg int
        """
        sn = self.ked["s"]

        if len(sn) > 32:
            raise ValueError("Invalid sn = {} too large.".format(sn))

        sn = int(sn, 16)
        if sn < 0:
            raise ValueError("Negative sn={}.".format(sn))

        return (sn)

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

    @property
    def est(self):  # establishative
        """ Returns True if Serder represents an establishment event """
        return self.ked["t"] in (Ilks.icp, Ilks.rot, Ilks.dip, Ilks.drt)

    def pretty(self, *, size=1024):
        """
        Returns str JSON of .ked with pretty formatting

        ToDo: add default size limit on pretty when used for syslog UDP MCU
        like 1024 for ogler.logger
        """
        return json.dumps(self.ked, indent=1)[:size if size is not None else None]


class Tholder:
    """
    Tholder is KERI Signing Threshold Satisfactionclass
    .satisfy method evaluates satisfaction based on ordered list of indices of
    verified signatures where indices correspond to offsets in key list of
    associated signatures.

    ClassMethods
        .fromLimen returns corresponding sith as str or list from a limen str

    Has the following public properties:

    Properties:
        .sith is original signing threshold as str or list of str ratios
        .thold is parsed signing threshold as int or list of Fractions
        .limen is the extracted string for the next commitment to the threshold
            [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]] is extracted as
            '1/2,1/2,1/4,1/4,1/4&1,1'
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

    @classmethod
    def fromLimen(cls, limen):
        """
        Returns signing threshold from limen str
        """
        sith = limen
        if '/' in limen:  # weighted threshold
            sith = []
            clauses = limen.split('&')
            for clause in clauses:
                sith.append(clause.split(','))
        return sith

    def __init__(self, sith=''):
        """
        Parse threshold

        Parameters:
            sith is signing threshold expressed as:
                either hex string of threshold number
                or int of threshold number
                or iterable of strs of fractional weight clauses.

                Fractional weight clauses may be either an iterable of
                fraction strings or an iterable of iterables of fraction strings.

                The verify method appropriately evaluates each of the threshold
                forms.

        """
        if isinstance(sith, str):
            sith = int(sith, 16)

        if isinstance(sith, int):
            thold = sith
            if thold < 0:
                raise ValueError("Invalid sith = {} < 0.".format(thold))
            self._thold = thold
            self._size = self._thold  # used to verify that keys list size is at least size
            self._weighted = False
            self._satisfy = self._satisfy_numeric
            self._sith = "{:x}".format(sith)  # store in event form as str
            self._limen = self._sith  # just use hex string

        else:  # assumes iterable of weights or iterable of iterables of weights
            self._sith = sith
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

            for clause in thold:  # sum of fractions in clause must be >= 1
                if not (sum(clause) >= 1):
                    raise ValueError("Invalid sith clause = {}, all clause weight "
                                     "sums must be >= 1.".format(thold))

            self._thold = thold
            self._size = sum(len(clause) for clause in thold)
            self._satisfy = self._satisfy_weighted

            # extract limen from sith by joining ratio str elements of each
            # clause with "," and joining clauses with "&"
            # [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]] becomes
            # '1/2,1/2,1/4,1/4,1/4&1,1'
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
            if self.thold > 0 and len(indices) >= self.thold:  # at least one
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
            if not indices:  # empty indices
                return False

            # remove duplicates with set, sort low to high
            indices = sorted(set(indices))
            sats = [False] * self.size  # default all satifactions to False
            for idx in indices:
                sats[idx] = True  # set verified signature index to True

            wio = 0  # weight index offset
            for clause in self.thold:
                cw = 0  # init clause weight
                for w in clause:
                    if sats[wio]:  # verified signature so weight applies
                        cw += w
                    wio += 1
                if cw < 1:  # each clause must sum to at least 1
                    return False

            return True  # all clauses including final one cw >= 1

        except Exception as ex:
            return False

        return False


def randomNonce():
    """ Generate a random ed25519 seed and encode as qb64

    Returns:
        str: qb64 encoded ed25519 random seed
    """
    preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedqb64 = Matter(raw=preseed, code=MtrDex.Ed25519_Seed).qb64
    return seedqb64
