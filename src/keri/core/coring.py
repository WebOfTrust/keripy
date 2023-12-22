# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import re
import json
from typing import Union
from collections.abc import Iterable

from dataclasses import dataclass, astuple
from collections import namedtuple, deque
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from fractions import Fraction

import cbor2 as cbor
import msgpack
import pysodium
import blake3
import hashlib

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ..kering import (EmptyMaterialError, RawMaterialError, InvalidCodeError,
                      InvalidCodeSizeError, InvalidVarIndexError,
                      InvalidVarSizeError, InvalidVarRawSizeError,
                      ConversionError, InvalidValueError, InvalidTypeError,
                      ValidationError, VersionError, DerivationError,
                      EmptyListError,
                      ShortageError, UnexpectedCodeError, DeserializeError,
                      UnexpectedCountCodeError, UnexpectedOpCodeError)
from ..kering import (Versionage, Version, VERRAWSIZE, VERFMT, VERFULLSIZE,
                      versify, deversify, Rever)
from ..kering import Serials, Serialage, Protos, Protocolage, Ilkage, Ilks
from ..kering import (ICP_LABELS, DIP_LABELS, ROT_LABELS, DRT_LABELS, IXN_LABELS,
                      RPY_LABELS)
from ..kering import (VCP_LABELS, VRT_LABELS, ISS_LABELS, BIS_LABELS, REV_LABELS,
                      BRV_LABELS, TSN_LABELS, CRED_TSN_LABELS)

from ..help import helping
from ..help.helping import sceil, nonStringIterable


Labels = Ilkage(icp=ICP_LABELS, rot=ROT_LABELS, ixn=IXN_LABELS, dip=DIP_LABELS,
                drt=DRT_LABELS, rct=[], qry=[], rpy=RPY_LABELS,
                exn=[], pro=[], bar=[],
                vcp=VCP_LABELS, vrt=VRT_LABELS, iss=ISS_LABELS, rev=REV_LABELS,
                bis=BIS_LABELS, brv=BRV_LABELS)


DSS_SIG_MODE = "fips-186-3"
ECDSA_256r1_SEEDBYTES = 32
ECDSA_256k1_SEEDBYTES = 32


Vstrings = Serialage(json=versify(kind=Serials.json, size=0),
                     mgpk=versify(kind=Serials.mgpk, size=0),
                     cbor=versify(kind=Serials.cbor, size=0))

# SAID field labels
Saidage = namedtuple("Saidage", "dollar at id_ i d")

Saids = Saidage(dollar="$id", at="@id", id_="id", i="i", d="d")

def sizeify(ked, kind=None, version=Version):
    """
    Compute serialized size of ked and update version field
    Returns tuple of associated values extracted and or changed by sizeify

    Returns tuple of (raw, proto, kind, ked, version) where:
        raw (str): serialized event as bytes of kind
        proto (str): protocol type as value of Protocolage
        kind (str): serialzation kind as value of Serialage
        ked (dict): key event dict
        version (Versionage): instance

    Parameters:
        ked (dict): key event dict
        kind (str): value of Serials is serialization type
            if not provided use that given in ked["v"]
        version (Versionage): instance supported protocol version for message


    Assumes only supports Version
    """
    if "v" not in ked:
        raise ValueError("Missing or empty version string in key event "
                         "dict = {}".format(ked))

    proto, vrsn, knd, size = deversify(ked["v"])  # extract kind and version
    if vrsn != version:
        raise ValueError("Unsupported version = {}.{}".format(vrsn.major,
                                                              vrsn.minor))

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
    vs = versify(proto=proto, version=vrsn, kind=kind, size=size)
    # replace old version string in raw with new one
    raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
    if size != len(raw):  # substitution messed up
        raise ValueError("Malformed version string size = {}".format(vs))
    ked["v"] = vs  # update ked

    return raw, proto, kind, ked, vrsn


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


def codeB64ToB2(s):
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
    i <<= 2 * (len(s) % 4)  # add 2 bits right zero padding for each sextet
    n = sceil(len(s) * 3 / 4)  # compute min number of ocetets to hold all sextets
    return (i.to_bytes(n, 'big'))


def codeB2ToB64(b, l):
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
    i = int.from_bytes(b[:n], 'big')  # convert only first n bytes to int
    # check if prepad bits are zero
    tbs = 2 * (l % 4)  # trailing bit size in bits
    i >>= tbs  # right shift out trailing bits to make right aligned
    return (intToB64(i, l))  # return as B64


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

MINSNIFFSIZE = 12 + VERFULLSIZE  # min bytes in buffer to sniff else need more

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

    proto, major, minor, kind, size = match.group("proto", "major", "minor", "kind", "size")
    version = Versionage(major=int(major, 16), minor=int(minor, 16))
    kind = kind.decode("utf-8")
    proto = proto.decode("utf-8")
    if kind not in Serials:
        raise DeserializeError("Invalid serialization kind = {}".format(kind))
    size = int(size, 16)

    return proto, kind, version, size


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
            raise DeserializeError("Error deserializing JSON: {}"
                                       "".format(raw[:size].decode("utf-8")))

    elif kind == Serials.mgpk:
        try:
            ked = msgpack.loads(raw[:size])
        except Exception as ex:
            raise DeserializeError("Error deserializing MGPK: {}"
                                       "".format(raw[:size]))

    elif kind == Serials.cbor:
        try:
            ked = cbor.loads(raw[:size])
        except Exception as ex:
            raise DeserializeError("Error deserializing CBOR: {}"
                                       "".format(raw[:size]))

    else:
        raise DeserializeError("Invalid deserialization kind: {}"
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
        path = f"{i:x}"
        # algorithm default is argon2id
        seed = pysodium.crypto_pwhash(outlen=32,
                                      passwd=path,
                                      salt=salt,
                                      opslimit=2,  # pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                      memlimit=67108864,  # pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)

        signers.append(Signer(raw=seed, transferable=transferable))

    return signers


def generatePrivates(salt=None, count=8):
    """
    Returns list of fully qualified Base64 secret Ed25519 seeds  i.e private keys

    Parameters:
        salt is bytes 16 byte long root cryptomatter from which seeds for Signers
            in list are derived
            random salt created if not provided
        count is number of signers in list
    """
    signers = generateSigners(salt=salt, count=count)

    return [signer.qb64 for signer in signers]  # fetch sigkey as private key


def generatePublics(salt=None, count=8, transferable=True):
    """
    Returns list of fully qualified Base64 secret seeds for Ed25519 private keys

    Parameters:
        salt is bytes 16 byte long root cryptomatter from which seeds for Signers
            in list are derived
            random salt created if not provided
        count is number of signers in list
    """
    signers = generateSigners(salt=salt, count=count, transferable=transferable)

    return [signer.verfer.qb64 for signer in signers]  # fetch verkey as public key


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
    X25519:               str = 'C'  # X25519 public encryption key, converted from Ed25519 or Ed25519N.
    Ed25519:              str = 'D'  # Ed25519 verification key basic derivation
    Blake3_256:           str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:          str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:          str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:             str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256:             str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    ECDSA_256k1_Seed:     str = 'J'  # ECDSA secp256k1 256 bit random Seed for private key
    Ed448_Seed:           str = 'K'  # Ed448 448 bit random Seed for private key
    X448:                 str = 'L'  # X448 public encryption key, converted from Ed448
    Short:                str = 'M'  # Short 2 byte b2 number
    Big:                  str = 'N'  # Big 8 byte b2 number
    X25519_Private:       str = 'O'  # X25519 private decryption key converted from Ed25519
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    ECDSA_256r1_Seed:     str = "Q"  # ECDSA secp256r1 256 bit random Seed for private key
    Tall:                 str = 'R'  # Tall 5 byte b2 number
    Large:                str = 'S'  # Large 11 byte b2 number
    Great:                str = 'T'  # Great 14 byte b2 number
    Vast:                 str = 'U'  # Vast 17 byte b2 number
    Label1:               str = 'V'  # Label1 as one char (bytes) field map label lead size 1
    Label2:               str = 'W'  # Label2 as two char (bytes) field map label lead size 0
    Tag3:                 str = 'X'  # Tag3 3 B64 encoded chars for field tag or packet type, semver, trait like 'DND'
    Tag7:                 str = 'Y'  # Tag7 7 B64 encoded chars for field tag or packet kind and version KERIVVV
    Salt_128:             str = '0A'  # 128 bit random salt or 128 bit number (see Huge)
    Ed25519_Sig:          str = '0B'  # Ed25519 signature.
    ECDSA_256k1_Sig:      str = '0C'  # ECDSA secp256k1 signature.
    Blake3_512:           str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:          str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:             str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:             str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    Long:                 str = '0H'  # Long 4 byte b2 number
    ECDSA_256r1_Sig:      str = '0I'  # ECDSA secp256r1 signature.
    Tag1:                 str = '0J'  # Tag1 1 B64 encoded char with pre pad for field tag
    Tag2:                 str = '0K'  # Tag2 2 B64 encoded chars for field tag or version VV or trait like 'EO'
    Tag5:                 str = '0L'  # Tag5 5 B64 encoded chars with pre pad for field tag
    Tag6:                 str = '0M'  # Tag6 6 B64 encoded chars for field tag or protocol kind version like KERIVV (KERI 1.1) or KKKVVV
    ECDSA_256k1N:         str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:          str = '1AAB'  # ECDSA public verification or encryption key, basic derivation
    Ed448N:               str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.
    Ed448:                str = '1AAD'  # Ed448 public signing verification key. Basic derivation.
    Ed448_Sig:            str = '1AAE'  # Ed448 signature. Self-signing derivation.
    Tag4:                 str = '1AAF'  # Tag4 4 B64 encoded chars for field tag or message kind
    DateTime:             str = '1AAG'  # Base64 custom encoded 32 char ISO-8601 DateTime
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    ECDSA_256r1N:         str = '1AAI'  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:          str = '1AAJ'  # ECDSA secp256r1 verification or encryption key, basic derivation
    Null:                 str = '1AAK'  # Null None or empty value
    Yes:                  str = '1AAL'  # Yes Truthy Boolean value
    No:                   str = '1AAM'  # No Falsey Boolean value
    TBD1:                 str = '2AAA'  # Testing purposes only fixed with lead size 1
    TBD2:                 str = '3AAA'  # Testing purposes only of fixed with lead size 2
    StrB64_L0:            str = '4A'  # String Base64 only lead size 0
    StrB64_L1:            str = '5A'  # String Base64 only lead size 1
    StrB64_L2:            str = '6A'  # String Base64 only lead size 2
    StrB64_Big_L0:        str = '7AAA'  # String Base64 only big lead size 0
    StrB64_Big_L1:        str = '8AAA'  # String Base64 only big lead size 1
    StrB64_Big_L2:        str = '9AAA'  # String Base64 only big lead size 2
    Bytes_L0:             str = '4B'  # Byte String lead size 0
    Bytes_L1:             str = '5B'  # Byte String lead size 1
    Bytes_L2:             str = '6B'  # Byte String lead size 2
    Bytes_Big_L0:         str = '7AAB'  # Byte String big lead size 0
    Bytes_Big_L1:         str = '8AAB'  # Byte String big lead size 1
    Bytes_Big_L2:         str = '9AAB'  # Byte String big lead size 2
    X25519_Cipher_L0:     str = '4C'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 0
    X25519_Cipher_L1:     str = '5C'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 1
    X25519_Cipher_L2:     str = '6C'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAC'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAC'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAC'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 2
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    X25519_Cipher_QB2_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    X25519_Cipher_QB2_L1:     str = '5D'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    X25519_Cipher_QB2_L2:     str = '6D'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    X25519_Cipher_QB2_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    X25519_Cipher_QB2_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    X25519_Cipher_QB2_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 2


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
    ECDSA_256r1N: str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.

    def __iter__(self):
        return iter(astuple(self))


NonTransDex = NonTransCodex()  # Make instance

# When add new to DigCodes update Saider.Digests and Serder.Digests class attr
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
class NumCodex:
    """
    NumCodex is codex of Base64 derivation codes for compactly representing
    numbers across a wide rage of sizes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Short:   str = 'M'  # Short 2 byte b2 number
    Long:    str = '0H'  # Long 4 byte b2 number
    Big:     str = 'N'  # Big 8 byte b2 number
    Huge:    str = '0A'  # Huge 16 byte b2 number (same as Salt_128)

    def __iter__(self):
        return iter(astuple(self))


NumDex = NumCodex()  # Make instance




@dataclass(frozen=True)
class BextCodex:
    """
    BextCodex is codex of all variable sized Base64 Text (Bext) derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    StrB64_L0:     str = '4A'  # String Base64 Only Leader Size 0
    StrB64_L1:     str = '5A'  # String Base64 Only Leader Size 1
    StrB64_L2:     str = '6A'  # String Base64 Only Leader Size 2
    StrB64_Big_L0: str = '7AAA'  # String Base64 Only Big Leader Size 0
    StrB64_Big_L1: str = '8AAA'  # String Base64 Only Big Leader Size 1
    StrB64_Big_L2: str = '9AAA'  # String Base64 Only Big Leader Size 2

    def __iter__(self):
        return iter(astuple(self))


BexDex = BextCodex()  # Make instance



@dataclass(frozen=True)
class TextCodex:
    """
    TextCodex is codex of all variable sized byte string (Text) derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Bytes_L0:     str = '4B'  # Byte String lead size 0
    Bytes_L1:     str = '5B'  # Byte String lead size 1
    Bytes_L2:     str = '6B'  # Byte String lead size 2
    Bytes_Big_L0: str = '7AAB'  # Byte String big lead size 0
    Bytes_Big_L1: str = '8AAB'  # Byte String big lead size 1
    Bytes_Big_L2: str = '9AAB'  # Byte String big lead size 2

    def __iter__(self):
        return iter(astuple(self))


TexDex = TextCodex()  # Make instance

@dataclass(frozen=True)
class CipherX25519VarCodex:
    """
    CipherX25519VarCodex is codex all variable sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is B2.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_L0:     str = '4D'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 0
    X25519_Cipher_L1:     str = '5D'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 1
    X25519_Cipher_L2:     str = '6D'  # X25519 sealed box cipher bytes of sniffable plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of sniffable plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXVarDex = CipherX25519VarCodex()  # Make instance


@dataclass(frozen=True)
class CipherX25519FixQB64Codex:
    """
    CipherX25519FixQB64Codex is codex all fixed sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is B64.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt

    def __iter__(self):
        return iter(astuple(self))


CiXFixQB64Dex = CipherX25519FixQB64Codex()  # Make instance


@dataclass(frozen=True)
class CipherX25519VarQB64Codex:
    """
    CipherX25519VarQB64Codex is codex all variable sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is QB64.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXVarQB64Dex = CipherX25519VarQB64Codex()  # Make instance


@dataclass(frozen=True)
class CipherX25519AllQB64Codex:
    """
    CipherX25519AllQB64Codex is codex all both fixed and variable sized cipher bytes
    derivation codes for sealed box encryped ciphertext. Plaintext is B64.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXAllQB64Dex = CipherX25519AllQB64Codex()  # Make instance


@dataclass(frozen=True)
class CipherX25519QB2VarCodex:
    """
    CipherX25519QB2VarCodex is codex all variable sized cipher bytes derivation codes
    for sealed box encryped ciphertext. Plaintext is B2.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    X25519_Cipher_L0:     str = '4E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    X25519_Cipher_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    X25519_Cipher_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 2

    def __iter__(self):
        return iter(astuple(self))


CiXVarQB2Dex = CipherX25519QB2VarCodex()  # Make instance




# namedtuple for size entries in Matter  and Counter derivation code tables
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
        code (str): hard part of derivation code to indicate cypher suite
        both (int): hard and soft parts of full text code
        size (int): Number of triplets of bytes including lead bytes
            (quadlets of chars) of variable sized material. Value of soft size,
            ss, part of full text code.
            Otherwise None.
        rize (int): number of bytes of raw material not including
                    lead bytes
        raw (bytes): crypto material only without code
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise

    Hidden:
        _code (str): value for .code property
        _raw (bytes): value for .raw property
        _rsize (bytes): value for .rsize property. Raw size in bytes when
            variable sized material else None.
        _size (int): value for .size property. Number of triplets of bytes
            including lead bytes (quadlets of chars) of variable sized material
            else None.
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
        'Q': Sizage(hs=1, ss=0, fs=44, ls=0),
        'R': Sizage(hs=1, ss=0, fs=8, ls=0),
        'S': Sizage(hs=1, ss=0, fs=16, ls=0),
        'T': Sizage(hs=1, ss=0, fs=20, ls=0),
        'U': Sizage(hs=1, ss=0, fs=24, ls=0),
        'V': Sizage(hs=1, ss=0, fs=4, ls=1),
        'W': Sizage(hs=1, ss=0, fs=4, ls=0),
        'X': Sizage(hs=1, ss=0, fs=4, ls=0),
        'Y': Sizage(hs=1, ss=0, fs=8, ls=0),
        '0A': Sizage(hs=2, ss=0, fs=24, ls=0),
        '0B': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0C': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0D': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0E': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0F': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0G': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0H': Sizage(hs=2, ss=0, fs=8, ls=0),
        '0I': Sizage(hs=2, ss=0, fs=88, ls=0),
        '0J': Sizage(hs=2, ss=0, fs=4, ls=0),
        '0K': Sizage(hs=2, ss=0, fs=4, ls=0),
        '0L': Sizage(hs=2, ss=0, fs=8, ls=0),
        '0M': Sizage(hs=2, ss=0, fs=8, ls=0),
        '1AAA': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAB': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAC': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAD': Sizage(hs=4, ss=0, fs=80, ls=0),
        '1AAE': Sizage(hs=4, ss=0, fs=56, ls=0),
        '1AAF': Sizage(hs=4, ss=0, fs=8, ls=0),
        '1AAG': Sizage(hs=4, ss=0, fs=36, ls=0),
        '1AAH': Sizage(hs=4, ss=0, fs=100, ls=0),
        '1AAI': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAJ': Sizage(hs=4, ss=0, fs=48, ls=0),
        '1AAK': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAL': Sizage(hs=4, ss=0, fs=4, ls=0),
        '1AAM': Sizage(hs=4, ss=0, fs=4, ls=0),
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
        '9AAE': Sizage(hs=4, ss=4, fs=None, ls=2),
    }


    # Bards table maps first code char. converted to binary sextext of hard size,
    # hs. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

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
        When raw and code and optional size and rsize provided
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
                raise InvalidCodeError("Unsupported code={}.".format(code))

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
                if not fs:  # invalid
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
        Returns ._code which is the hard part only of full text code.
        Some codes only have a hard part. Soft part is for variable sized matter.
        Makes .code read only
        """
        return self._code

    @property
    def both(self):
        """
        Returns both hard and soft parts of full text code
        """
        _, ss, _, _ = self.Sizes[self.code]
        return (f"{self.code}{intToB64(self.size, l=ss)}")


    @property
    def size(self):
        """
        Returns ._size int or None if not variable sized matter
        Makes .size read only

        Number of triplets of bytes including lead bytes (quadlets of chars)
        of variable sized material. Value of soft size, ss, part of full text code.
        """
        return self._size


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


    @property
    def prefixive(self):
        """
        Property prefixive:
        Returns True if identifier has prefix derivation code,
                False otherwise
        """
        return (self.code in PreDex)


    def _infil(self):
        """
        Returns bytes of fully qualified base64 characters
        self.code + converted self.raw to Base64 with pad chars stripped

        cs = hs + ss
        fs = (size * 4) + cs

        """
        code = self.code  # hard size codex value
        size = self.size  # size if variable length, None otherwise
        raw = self.raw  # bytes or bytearray

        ps = ((3 - (len(raw) % 3)) % 3)  # pad size chars or lead size bytes
        hs, ss, fs, ls = self.Sizes[code]
        if not fs:  # variable sized, compute code ss value from .size
            cs = hs + ss  # both hard + soft size
            if cs % 4:
                raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                           f"variable length material. cs={cs}.")

            if size < 0 or size > (64 ** ss - 1):
                raise InvalidVarSizeError("Invalid size={} for code={}."
                                          "".format(size, code))
            # both is hard code + size converted to ss B64 chars
            both = f"{code}{intToB64(size, l=ss)}"

            if len(both) % 4 != ps - ls:  # adjusted pad given lead bytes
                raise InvalidCodeSizeError(f"Invalid code={both} for converted"
                                           f" raw pad size={ps}.")
            # prepad, convert, and prepend
            return (both.encode("utf-8") + encodeB64(bytes([0] * ls) + raw))

        else:  # fixed size so prepad but lead ls may not be zero
            both = code
            cs = len(both)
            if (cs % 4) != ps - ls:  # adjusted pad given lead bytes
                raise InvalidCodeSizeError(f"Invalid code={both} for converted"
                                           f" raw pad size={ps}.")
            # prepad, convert, and replace upfront
            # when fixed and ls != 0 then cs % 4 is zero and ps==ls
            # otherwise  fixed and ls == 0 then cs % 4 == ps
            return (both.encode("utf-8") + encodeB64(bytes([0] * ps) + raw)[cs % 4:])


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

        if not fs:  # compute both and fs from size
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
        # convert code both to right align b2 int then left shift in pad bits
        # then convert to bytes
        bcode = (b64ToInt(both) << (2 * (cs % 4))).to_bytes(n, 'big')
        full = bcode + bytes([0] * ls) + raw
        bfs = len(full)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid code={both} for raw size={len(raw)}.")

        return full


    def _exfil(self, qb64b):
        """
        Extracts self.code and self.raw from qualified base64 bytes qb64b

        cs = hs + ss
        fs = (size * 4) + cs
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material.")

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
                raise UnexpectedCodeError(f"Unsupported code start char={first}.")

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError(f"Need {hs - len(qb64b)} more characters.")

        hard = qb64b[:hs]  # extract hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")  # converts bytes/bytearray to str
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, fs, ls = self.Sizes[hard]  # assumes hs in both tables match
        cs = hs + ss  # both hs and ss
        size = None
        if not fs:  # compute fs from size chars in ss part of code
            if cs % 4:
                raise ValidationError(f"Whole code size not multiple of 4 for "
                                      f"variable length material. cs={cs}.")
            size = qb64b[hs:hs + ss]  # extract size chars
            if hasattr(size, "decode"):
                size = size.decode("utf-8")
            size = b64ToInt(size)  # compute int size
            fs = (size * 4) + cs

        # assumes that unit tests on Matter and MatterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and ss == 0 and not fs % 4 and hs > 0 and fs >= hs + ss
        # unless fs is None

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError(f"Need {fs - len(qb64b)} more chars.")

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # check for non-zeroed pad bits or lead bytes
        ps = cs % 4  # code pad size ps = cs mod 4
        pbs = 2 * (ps if ps else ls)  # pad bit size in bits
        if ps:  # ps. IF ps THEN not ls (lead) and vice versa OR not ps and not ls
            base = ps * b'A' + qb64b[cs:]  # replace pre code with prepad chars of zero
            paw = decodeB64(base)  # decode base to leave prepadded raw
            pi = (int.from_bytes(paw[:ps], "big"))  # prepad as int
            if pi & (2 ** pbs - 1 ):  # masked pad bits non-zero
                raise ValueError(f"Non zeroed prepad bits = "
                                 f"{pi & (2 ** pbs - 1 ):<06b} in {qb64b[cs:cs+1]}.")
            raw = paw[ps:]  # strip off ps prepad paw bytes

        else:  # not ps. IF not ps THEN may or may not be ls (lead)
            base = qb64b[cs:]  # strip off code leaving lead chars if any and value
            # decode lead chars + val leaving lead bytes + raw bytes
            # then strip off ls lead bytes leaving raw
            paw = decodeB64(base) # decode base to leave prepadded paw bytes
            li = int.from_bytes(paw[:ls], "big")  # lead as int
            if li:  # pre pad lead bytes must be zero
                if ls == 1:
                    raise ValueError(f"Non zeroed lead byte = 0x{li:02x}.")
                else:
                    raise ValueError(f"Non zeroed lead bytes = 0x{li:04x}.")
            raw = paw[ls:]  # paw is bytes so raw is bytes

        if len(raw) != ((len(qb64b) - cs) * 3 // 4) - ls:  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb64b}")

        self._code = hard  # hard only
        self._size = size
        self._raw = raw  # ensure bytes so immutable and for crypto ops


    def _bexfil(self, qb2):
        """
        Extracts self.code and self.raw from qualified base2 qb2

        Parameters:
            qb2 (bytes | bytearray): fully qualified base2 from stream
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
                raise UnexpectedCodeError(f"Unsupported code start sextet={first}.")

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError(f"Need {bhs - len(qb2)} more bytes.")

        hard = codeB2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        size = None
        if not fs:  # compute fs from size chars in ss part of code
            if cs % 4:
                raise ValidationError("Whole code size not multiple of 4 for "
                                      "variable length material. cs={}.".format(cs))

            if len(qb2) < bcs:  # need more bytes
                raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

            both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
            size = b64ToInt(both[hs:hs + ss])  # get size
            fs = (size * 4) + cs

        # assumes that unit tests on Matter and MatterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and ss == 0 and not fs % 4 and hs > 0 and
        # (fs >= hs + ss if fs is not None else True)

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))

        qb2 = qb2[:bfs]  # extract qb2 fully qualified primitive code plus material
        # check for non-zeroed prepad bits or lead bytes
        ps = cs % 4  # code pad size ps = cs mod 4
        pbs = 2 * (ps if ps else ls)  # pad bit size in bits
        if ps:  # ps. IF ps THEN not ls (lead) and vice versa OR not ps and not ls
            # convert last byte of code bytes in which are pad bits to int
            pi = (int.from_bytes(qb2[bcs-1:bcs], "big"))
            if pi & (2 ** pbs - 1 ):  # masked pad bits non-zero
                raise ValueError(f"Non zeroed pad bits = "
                                 f"{pi & (2 ** pbs - 1 ):>08b} in 0x{pi:02x}.")
        else:  # not ps. IF not ps THEN may or may not be ls (lead)
            li = int.from_bytes(qb2[bcs:bcs+ls], "big")  # lead as int
            if li:  # pre pad lead bytes must be zero
                if ls == 1:
                    raise ValueError(f"Non zeroed lead byte = 0x{li:02x}.")
                else:
                    raise ValueError(f"Non zeroed lead bytes = 0x{li:02x}.")

        raw = qb2[(bcs + ls):]  # strip code and leader bytes from qb2 to get raw

        if len(raw) != (len(qb2) - bcs - ls):  # exact lengths
            raise ConversionError(r"Improperly qualified material = {qb2}")

        self._code = hard
        self._size = size
        self._raw = bytes(raw)  # ensure bytes so immutable and crypto operations


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
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            if sn is None:
                if snh is None:
                    sn = 0
                else:
                    sn = int(snh, 16)

            raw = sn.to_bytes(Matter._rawSize(MtrDex.Salt_128), 'big')

        super(Seqner, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)

        if self.code != MtrDex.Salt_128:
            raise ValidationError("Invalid code = {} for Seqner."
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


class Number(Matter):
    """
    Number is subclass of Matter, cryptographic material, for ordinal counting
    whole numbers  (non-negative integers) up to a maximum size of 16 bytes,
    256 ** 16 - 1.
    Examples uses are sequence numbers or first seen ordering numbers or thresholds.
    Seqner provides fully qualified format for ordinals (sequence numbers etc)
    when provided as attached cryptographic material elements.

    Useful when parsing attached receipt groupings with sn from stream or database

    Uses default initialization code = CryTwoDex.Salt_128
    Raises error on init if code not CryTwoDex.Salt_128

    Attributes:

    Inherited Properties:  (See Matter)
        code (str): hard part of derivation code to indicate cypher suite
        both (int): hard and soft parts of full text code
        size (int): Number of triplets of bytes including lead bytes
            (quadlets of chars) of variable sized material. Value of soft size,
            ss, part of full text code.
            Otherwise None.
        rize (int): number of bytes of raw material not including lead bytes
        raw (bytes): crypto material only without code
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise

    Properties:
        num  (int): int representation of number
        humh (str): hex string representation of number with no leading zeros
        positive (bool): True if .num  > 0, False otherwise. Because .num must be
            non-negative, .positive == False means .num == 0

    Hidden:
        _code (str): value for .code property
        _raw (bytes): value for .raw property
        _rsize (bytes): value for .rsize property. Raw size in bytes when
            variable sized material else None.
        _size (int): value for .size property. Number of triplets of bytes
            including lead bytes (quadlets of chars) of variable sized material
            else None.
        _infil (types.MethodType): creates qb64b from .raw and .code
                                   (fully qualified Base64)
        _exfil (types.MethodType): extracts .code and .raw from qb64b
                                   (fully qualified Base64)

    Methods:
    """

    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None,
                 code=NumDex.Short, num=None, numh=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw (bytes): unqualified crypto material usable for crypto operations
            code (str): stable (hard) part of derivation code
            rize (int): raw size in bytes when variable sized material else None
            qb64b (bytes): fully qualified crypto material Base64
            qb64 (str, bytes):  fully qualified crypto material Base64
            qb2 (bytes): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
            bytearray after parsing qb64b or qb2. False means do not strip

        Parameters:
            num (int | str | None): non-negative int number or hex str of int
                number or 0 if None
            numh (str):  string equivalent of non-negative int number

        Note: int("0xab", 16) is also valid since int recognizes 0x hex prefix

        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            try:
                if num is None:
                    if numh is None or numh == '':
                        num = 0
                    else:
                        #if len(numh) > 32:
                            #raise InvalidValueError(f"Hex numh={numh} str too long.")
                        num = int(numh, 16)

                else:  # handle case where num is hex str'
                    if isinstance(num, str):
                        if num == '':
                            num = 0
                        else:
                            #if len(num) > 32:
                                #raise InvalidValueError(f"Hex num={num} str too long.")
                            num = int(num, 16)
            except ValueError as ex:
                raise InvalidValueError(f"Invalid whole number={num} .") from ex

            if not isinstance(num, int) or num < 0:
                raise InvalidValueError(f"Invalid whole number={num}.")

            if num <= (256 ** 2 - 1):  # make short version of code
                code = NumDex.Short

            elif num <= (256 ** 4 - 1):  # make long version of code
                code = code = NumDex.Long

            elif num <= (256 ** 8 - 1):  # make big version of code
                code = code = NumDex.Big

            elif num <= (256 ** 16 - 1):  # make huge version of code
                code = code = NumDex.Huge

            else:
                raise InvalidValueError(f"Invalid num = {num}, too large to encode.")

            # default to_bytes parameter signed is False. If negative raises
            # OverflowError: can't convert negative int to unsigned
            raw = num.to_bytes(Matter._rawSize(code), 'big')  # big endian unsigned

        super(Number, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)

        if self.code not in NumDex:
            raise ValidationError(f"Invalid code = {self.code} for Number.")


    @property
    def num(self):
        """
        Property num: number as int
        Returns .raw converted to int
        """
        return int.from_bytes(self.raw, 'big')

    @property
    def numh(self):
        """
        Property numh:  number as hex string no leading zeros
        Returns .num int converted to hex str
        """
        return f"{self.num:x}"


    @property
    def sn(self):
        """Sequence number, sn property getter to mimic Seqner interface
        Returns:
            sn (int): alias for num
        """
        return self.num


    @property
    def snh(self):
        """Sequence number hex str, snh property getter to mimic Seqner interface
        Returns:
            snh (hex str): alias for numh
        """
        return self.numh



    @property
    def positive(self):
        """
        Returns True if .num is strictly positive non-zero False otherwise.
        Because valid number .num must be non-negative, positive False also means
        that .num is zero.
        """
        return True if self.num > 0 else False

    @property
    def inceptive(self):
        """
        Returns True if .num == 0 False otherwise.
        Because valid number .num must be non-negative, positive False means
        that .num is zero.
        """
        return True if self.num == 0 else False


class Dater(Matter):
    """
    Dater is subclass of Matter, cryptographic material, for RFC-3339 profile of
    ISO-8601 formatted datetimes.

    Dater provides a custom Base64 coding of an ASCII RFC-3339 profile of an
    ISO-8601 datetime by replacing (using translate) the three non-Base64 characters,
    ':.+' with the Base64 equivalents, 'cdp' respectively.

    Dater provides a more compact representation than would be obtained by converting
    the raw ASCII RFC-3339 profile ISO-8601 datetime to Base64.
    Dater supports datetimes as attached crypto material in replay of events for
    the datetime of when the event was first seen.
    The datetime textual representation is restricted to a specific 32 byte
    variant (profile) of ISO-8601 datetime with microseconds and UTC offset in
    HH:MM (See RFC-3339).
    Uses default initialization derivation code = MtrDex.DateTime.
    Raises error on init if code not  MtrDex.DateTime

    Examples: given RFC-3339 profiles of ISO-8601 datetime strings:

    '2020-08-22T17:50:09.988921+00:00'
    '2020-08-22T17:50:09.988921-01:00'

    The fully encoded qualified Base64, .qb64 versions are respectively

    '1AAG2020-08-22T17c50c09d988921p00c00'
    '1AAG2020-08-22T17c50c09d988921-01c00'


    The qualified binary version, .qb2 is the Base64 decoding the qualified Base64,
    qb64, '1AAG2020-08-22T17c50c09d988921p00c00'

    The raw binary of the fully encoded version is the Base64 decoding of the
    the datetime only portion, '2020-08-22T17c50c09d988921p00c00'

    Use the properties to get the different representations
    .dts is ASCII RFC-3339 of ISO-8601
    .qb64 is qualified Base64 encoding with derivation code proem and ':.+'
        replaced with 'cdp'
    .qb2 is qualified binary decoding of the .qb64
    .code is text CESR derivation code
    .raw is binary version of the converted datetime only portion of .qb64

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
    ToB64 = str.maketrans(":.+", "cdp")  #  translate characters
    FromB64 = str.maketrans("cdp", ":.+")  #  translate characters

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
            # if len(dts) != 32:
            #     raise ValueError("Invalid length of date time string")
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


class Bexter(Matter):
    """
    Bexter is subclass of Matter, cryptographic material, for variable length
    strings that only contain Base64 URL safe characters, i.e. Base64 text (bext).
    When created using the 'bext' paramaeter, the encoded matter in qb64 format
    in the text domain is more compact than would be the case if the string were
    passed in as raw bytes. The text is used as is to form the value part of the
    qb64 version not including the leader.

    Due to ambiguity that arises from pre-padding bext whose length is a multiple of
    three with one or more 'A' chars. Any bext that starts with an 'A' and whose length
    is either a multiple of 3 or 4 may not round trip. Bext with a leading 'A'
    whose length is a multiple of four may have the leading 'A' stripped when
    round tripping.

        Bexter(bext='ABBB').bext == 'BBB'
        Bexter(bext='BBB').bext == 'BBB'
        Bexter(bext='ABBB').qb64 == '4AABABBB' == Bexter(bext='BBB').qb64

    To avoid this problem, only use for applications of base 64 strings that
    never start with 'A'

    Examples: base64 text strings:

    bext = ""
    qb64 = '4AAA'

    bext = "-"
    qb64 = '6AABAAA-'

    bext = "-A"
    qb64 = '5AABAA-A'

    bext = "-A-"
    qb64 = '4AABA-A-'

    bext = "-A-B"
    qb64 = '4AAB-A-B'


    Example uses:
        CESR encoded paths for nested SADs and SAIDs
        CESR encoded fractionally weighted threshold expressions


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
                 code=MtrDex.StrB64_L0, bext=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            bext is the variable sized Base64 text string
        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            if bext is None:
                raise EmptyMaterialError("Missing bext string.")
            if hasattr(bext, "encode"):
                bext = bext.encode("utf-8")
            if not Reb64.match(bext):
                raise ValueError("Invalid Base64.")
            raw = self._rawify(bext)

        super(Bexter, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)
        if self.code not in BexDex:
            raise ValidationError("Invalid code = {} for Bexter."
                                  "".format(self.code))

    def _rawify(self, bext):
        """Returns raw value equivalent of Base64 text.
        Suitable for variable sized matter

        Parameters:
            text (bytes): Base64 bytes
        """
        ts = len(bext) % 4  # bext size mod 4
        ws = (4 - ts) % 4  # pre conv wad size in chars
        ls = (3 - ts) % 3  # post conv lead size in bytes
        base = b'A' * ws + bext  # pre pad with wad of zeros in Base64 == 'A'
        raw = decodeB64(base)[ls:]  # convert and remove leader
        return raw  # raw binary equivalent of text

    @property
    def bext(self):
        """
        Property bext: Base64 text value portion of qualified b64 str
        Returns the value portion of .qb64 with text code and leader removed
        """
        _, _, _, ls = self.Sizes[self.code]
        bext = encodeB64(bytes([0] * ls) + self.raw)
        ws = 0
        if ls == 0 and bext:
            if bext[0] == ord(b'A'):  # strip leading 'A' zero pad
                ws = 1
        else:
            ws = (ls + 1) % 4
        return bext.decode('utf-8')[ws:]


class Pather(Bexter):
    """
    Pather is a subclass of Bexter that provides SAD Path language specific functionality
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

    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None, bext=None,
                 code=MtrDex.StrB64_L0, path=None, **kwa):
        """
        Inherited Parameters:  (see Bexter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes
            bext is the variable sized Base64 text string

        Parameters:
            path (list): array of path field components
        """

        if raw is None and bext is None and qb64b is None and qb64 is None and qb2 is None:
            if path is None:
                raise EmptyMaterialError("Missing path list.")

            bext = self._bextify(path)

        super(Pather, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2, bext=bext,
                                     code=code, **kwa)

    @property
    def path(self):
        """ Path property is an array of path elements

        Path property is an array of path elements.  Empty path represents the top level.

        Returns:
            list: array of field specs of the path

        """
        if not self.bext.startswith("-"):
            raise Exception("invalid SAD ptr")

        path = self.bext.strip("-").split("-")
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
        """ Returns True if path is the root of self

        Parameters:
            path (Pather): the path to check against self

        Returns:
            bool: True if path is the root of self

        """

        return self.bext.startswith(path.bext)

    def resolve(self, sad):
        """ Recurses thru value following ptr

        Parameters:
            sad(dict or list): the next component

        Returns:
            Value at the end of the path
        """
        return self._resolve(sad, self.path)


    def tail(self, serder):
        """ Recurses thru value following .path and returns terminal value

        Finds the value at this path and applies the version string rules of the serder
        to serialize the value at ptr.

        Parameters:
            serder(Serder): the versioned dict to in which to resolve .path

        Returns:
            bytes: Value at the end of the path
        """
        val = self.resolve(sad=serder.sad)
        if isinstance(val, str):
            saider = Saider(qb64=val)
            return saider.qb64b
        elif isinstance(val, dict):
            return dumps(val, serder.kind)
        elif isinstance(val, list):
            return dumps(val, serder.kind)
        else:
            raise ValueError("Bad tail value at {} of {}"
                             .format(self.path, serder.ked))


    @staticmethod
    def _bextify(path):
        """ Returns Base64 text delimited equivalent of path components

        Suitable for variable sized matter


        Parameters:
            path (list): array of path field components

        Returns:
            str:  textual representation of SAD path

        """
        vath = []  # valid path components
        for p in path:
            if hasattr(p, "decode"):
                p = p.decode("utf-8")

            elif isinstance(p, int):
                p = str(p)

            if not Reb64.match(p.encode("utf-8")):
                raise ValueError(f"Non Base64 path component = {p}.")

            vath.append(p)

        return ("-" + "-".join(vath))

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
                    raise KeyError(f"invalid dict pointer index {i} for keys {keys}")

                cur = val[list(val)[i]]
            elif idx == "":
                return val
            else:
                cur = val[idx]

        elif isinstance(val, list):
            i = int(idx)
            if i >= len(val):
                raise KeyError(f"invalid array pointer index {i} for array {val}")

            cur = val[i]

        else:
            raise KeyError("invalid traversal type")

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
        elif self.code in [MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256r1]:
            self._verify = self._secp256r1
        elif self.code in [MtrDex.ECDSA_256k1N, MtrDex.ECDSA_256k1]:
            self._verify = self._secp256k1
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
        Verify Ed25519 sig on ser using key

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

    @staticmethod
    def _secp256r1(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verify secp256r1 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        verkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = utils.encode_dss_signature(r, s)
        try:
            verkey.verify(der, ser, ec.ECDSA(hashes.SHA256()))
            return True
        except exceptions.InvalidSignature:
            return False

    @staticmethod
    def _secp256k1(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verify secp256k1 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        verkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = utils.encode_dss_signature(r, s)
        try:
            verkey.verify(der, ser, ec.ECDSA(hashes.SHA256()))
            return True
        except exceptions.InvalidSignature:
            return False


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
    using:
        .raw as signing (private) key seed,
        .code as cipher suite for signing
        .verfer whose property .raw is public key for signing.

    If not provided .verfer is generated from private key seed using .code
    as cipher suite for creating key-pair.


    See Matter for inherited attributes and properties:

    Attributes:

    Properties:  (inherited)
        code (str): hard part of derivation code to indicate cypher suite
        both (int): hard and soft parts of full text code
        size (int): Number of triplets of bytes including lead bytes
            (quadlets of chars) of variable sized material. Value of soft size,
            ss, part of full text code.
            Otherwise None.
        rize (int): number of bytes of raw material not including
                    lead bytes
        raw (bytes): private signing key crypto material only without code
        qb64 (str): private signing key Base64 fully qualified with
                    derivation code + crypto mat
        qb64b (bytes): private signing keyBase64 fully qualified with
            derivation code + crypto mat
        qb2  (bytes): private signing key binary with
            derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise

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
            elif code == MtrDex.ECDSA_256r1_Seed:
                raw = pysodium.randombytes(ECDSA_256r1_SEEDBYTES)
                super(Signer, self).__init__(raw=bytes(raw), code=code, **kwa)
            elif code == MtrDex.ECDSA_256k1_Seed:
                raw = pysodium.randombytes(ECDSA_256k1_SEEDBYTES)
                super(Signer, self).__init__(raw=bytes(raw), code=code, **kwa)

            else:
                raise ValueError("Unsupported signer code = {}.".format(code))

        if self.code == MtrDex.Ed25519_Seed:
            self._sign = self._ed25519
            verkey, sigkey = pysodium.crypto_sign_seed_keypair(self.raw)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.Ed25519 if transferable
                            else MtrDex.Ed25519N)
        elif self.code == MtrDex.ECDSA_256r1_Seed:
            self._sign = self._secp256r1
            d = int.from_bytes(self.raw, byteorder="big")
            sigkey = ec.derive_private_key(d, ec.SECP256R1())
            verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.ECDSA_256r1 if transferable
                            else MtrDex.ECDSA_256r1N)
        elif self.code == MtrDex.ECDSA_256k1_Seed:
            self._sign = self._secp256k1
            d = int.from_bytes(self.raw, byteorder="big")
            sigkey = ec.derive_private_key(d, ec.SECP256K1())
            verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.ECDSA_256k1 if transferable
                            else MtrDex.ECDSA_256k1N)
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

    def sign(self, ser, index=None, only=False, ondex=None, **kwa):
        """
        Returns either Cigar or Siger (indexed) instance of cryptographic
        signature material on bytes serialization ser

        If index is None
            return Cigar instance
        Else
            return Siger instance

        Parameters:
            ser (bytes): serialization to be signed
            index (int):  main index of associated verifier key in event keys
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next

        """
        return (self._sign(ser=ser,
                           seed=self.raw,
                           verfer=self.verfer,
                           index=index,
                           only=only,
                           ondex=ondex,
                           **kwa))

    @staticmethod
    def _ed25519(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        Ed25519 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        sig = pysodium.crypto_sign_detached(ser, seed + verfer.raw)

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.Ed25519_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = IdrDex.Ed25519_Crt_Sig  # use small current only
                else:
                    code = IdrDex.Ed25519_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = IdrDex.Ed25519_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = IdrDex.Ed25519_Big_Sig  # use use big both

            return Siger(raw=sig,
                         code=code,
                         index=index,
                         ondex=ondex,
                         verfer=verfer,)

    @staticmethod
    def _secp256r1(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        Ed25519 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        d = int.from_bytes(seed, byteorder="big")
        sigkey = ec.derive_private_key(d, ec.SECP256R1())
        der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(der)
        sig = bytearray(r.to_bytes(32, "big"))
        sig.extend(s.to_bytes(32, "big"))

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.ECDSA_256r1_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = IdrDex.ECDSA_256r1_Crt_Sig  # use small current only
                else:
                    code = IdrDex.ECDSA_256r1_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = IdrDex.ECDSA_256r1_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = IdrDex.ECDSA_256r1_Big_Sig  # use use big both

            return Siger(raw=sig,
                         code=code,
                         index=index,
                         ondex=ondex,
                         verfer=verfer,)

    @staticmethod
    def _secp256k1(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        secp256k1 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        d = int.from_bytes(seed, byteorder="big")
        sigkey = ec.derive_private_key(d, ec.SECP256K1())
        der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(der)
        sig = bytearray(r.to_bytes(32, "big"))
        sig.extend(s.to_bytes(32, "big"))

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.ECDSA_256k1_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = IdrDex.ECDSA_256k1_Crt_Sig  # use small current only
                else:
                    code = IdrDex.ECDSA_256k1_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = IdrDex.ECDSA_256k1_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = IdrDex.ECDSA_256k1_Big_Sig  # use use big both

            return Siger(raw=sig,
                         code=code,
                         index=index,
                         ondex=ondex,
                         verfer=verfer,)

    # def derive_index_code(code, index, only=False, ondex=None, **kwa):
    #     # should add Indexer class method to get ms main index size for given code
    #     if only:  # only main index ondex not used
    #         ondex = None
    #         if index <= 63: # (64 ** ms - 1) where ms is main index size,  use small current only
    #             if code == MtrDex.Ed25519_Seed:
    #                 indxSigCode = IdrDex.Ed25519_Crt_Sig
    #             elif code == MtrDex.ECDSA_256r1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256r1_Crt_Sig
    #             elif code == MtrDex.ECDSA_256k1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256k1_Crt_Sig
    #             else:
    #                 raise ValueError("Unsupported signer code = {}.".format(code))
    #         else:    # use big current only
    #             if code == MtrDex.Ed25519_Seed:
    #                 indxSigCode = IdrDex.Ed25519_Big_Crt_Sig
    #             elif code == MtrDex.ECDSA_256r1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256r1_Big_Crt_Sig
    #             elif code == MtrDex.ECDSA_256k1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256k1_Big_Crt_Sig
    #             else:
    #                 raise ValueError("Unsupported signer code = {}.".format(code))
    #     else:  # both
    #         if ondex == None:
    #             ondex = index  # enable default to be same
    #         if ondex == index and index <= 63:  # both same and small so use small both same
    #             if code == MtrDex.Ed25519_Seed:
    #                 indxSigCode = IdrDex.Ed25519_Sig
    #             elif code == MtrDex.ECDSA_256r1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256r1_Sig
    #             elif code == MtrDex.ECDSA_256k1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256k1_Sig
    #             else:
    #                 raise ValueError("Unsupported signer code = {}.".format(code))
    #         else:  # otherwise big or both not same so use big both
    #             if code == MtrDex.Ed25519_Seed:
    #                 indxSigCode = IdrDex.Ed25519_Big_Sig
    #             elif code == MtrDex.ECDSA_256r1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256r1_Big_Sig
    #             elif code == MtrDex.ECDSA_256k1_Seed:
    #                 indxSigCode = IdrDex.ECDSA_256k1_Big_Sig
    #             else:
    #                 raise ValueError("Unsupported signer code = {}.".format(code))

    #     return (indxSigCode, ondex)

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
            opslimit = 1  # pysodium.crypto_pwhash_OPSLIMIT_MIN
            memlimit = 8192  # pysodium.crypto_pwhash_MEMLIMIT_MIN
        else:
            if tier == Tiers.low:
                opslimit = 2  # pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
                memlimit = 67108864  # pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
            elif tier == Tiers.med:
                opslimit = 3  # pysodium.crypto_pwhash_OPSLIMIT_MODERATE
                memlimit = 268435456  # pysodium.crypto_pwhash_MEMLIMIT_MODERATE
            elif tier == Tiers.high:
                opslimit = 4  # pysodium.crypto_pwhash_OPSLIMIT_SENSITIVE
                memlimit = 1073741824  # pysodium.crypto_pwhash_MEMLIMIT_SENSITIVE
            else:
                raise ValueError("Unsupported security tier = {}.".format(tier))

        # stretch algorithm is argon2id
        seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
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


    def signers(self, count=1, start=0, path="",  **kwa):
        """
        Returns list of count number of Signer instances with unique derivation
        path made from path prefix and suffix of start plus offset for each count
        value from 0 to count - 1.

        See .signer for parameters used to create each signer.

        """
        return [self.signer(path=f"{path}{i + start:x}", **kwa) for i in range(count)]


class Cipher(Matter):
    """
    Cipher is Matter subclass holding a cipher text of a secret that may be
    either a secret seed (private key) or secret salt with appropriate CESR code
    to indicate which kind (which indicates size). The cipher text is created
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


    See Matter for inherited attributes and properties:


    Methods:
        verify: verifies digest given ser
        compare: compares provide digest given ser to this digest of ser.
                enables digest agility of different digest algos to compare.


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
        # Should implement all digests in DigCodex instance DigDex
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
                raise InvalidValueError("Unsupported code={code} for diger.")

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
            raise InvalidValueError("Unsupported code={self.code} for diger.")

    def verify(self, ser):
        """
        Returns True if raw digest of ser bytes (serialization) matches .raw
        using .raw as reference digest for ._verify digest algorithm determined
        by .code

        Parameters:
            ser (bytes): serialization to be digested and compared to .ser
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



@dataclass(frozen=True)
class PreCodex:
    """
    PreCodex is codex all identifier prefix derivation codes.
    This is needed to verify valid inception events.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N:      str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    Ed25519:       str = 'D'  # Ed25519 verification key basic derivation
    Blake3_256:    str = 'E'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:   str = 'F'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:   str = 'G'  # Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:      str = 'H'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256:      str = 'I'  # SHA2 256 bit digest self-addressing derivation.
    Blake3_512:    str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:   str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:      str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:      str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    ECDSA_256k1N:  str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:   str = '1AAB'  # ECDSA public verification or encryption key, basic derivation
    ECDSA_256r1N:  str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:   str = "1AAJ"  # ECDSA secp256r1 verification or encryption key, basic derivation

    def __iter__(self):
        return iter(astuple(self))


PreDex = PreCodex()  # Make instance


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

            if code in [MtrDex.Ed25519N, MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256k1N]:
                self._derive = self._derive_non_transferable
            elif code in [MtrDex.Ed25519, MtrDex.ECDSA_256r1, MtrDex.ECDSA_256k1]:
                self._derive = self._derive_transferable
            elif code == MtrDex.Blake3_256:
                self._derive = self._derive_blake3_256
            else:
                raise ValueError("Unsupported code = {} for prefixer.".format(code))

            # use ked and ._derive from code to derive aid prefix and code
            raw, code = self.derive(ked=ked)
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)

        if self.code in [MtrDex.Ed25519N, MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256k1N]:
            self._verify = self._verify_non_transferable
        elif self.code in [MtrDex.Ed25519, MtrDex.ECDSA_256r1, MtrDex.ECDSA_256k1]:
            self._verify = self._verify_transferable
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
        ilk = ked["t"]
        if ilk not in (Ilks.icp, Ilks.dip, Ilks.vcp, Ilks.iss):
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ilk))

        labels = getattr(Labels, ilk)
        for k in labels:
            if k not in ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, ked))

        return (self._derive(ked=ked))

    def verify(self, ked, prefixed=False):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        Parameters:
            ked is inception key event dict
        """
        ilk = ked["t"]
        if ilk not in (Ilks.icp, Ilks.dip, Ilks.vcp, Ilks.iss):
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ilk))

        labels = getattr(Labels, ilk)
        for k in labels:
            if k not in ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, ked))

        return (self._verify(ked=ked, pre=self.qb64, prefixed=prefixed))

    def _derive_non_transferable(self, ked):
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

        if verfer.code not in [MtrDex.Ed25519N, MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256k1N]:
            raise DerivationError("Mismatch derivation code = {}."
                                  "".format(verfer.code))

        try:
            if verfer.code in [MtrDex.Ed25519N, MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256k1N] and ked["n"]:
                raise DerivationError("Non-empty nxt = {} for non-transferable"
                                      " code = {}".format(ked["n"],
                                                          verfer.code))

            if verfer.code in [MtrDex.Ed25519N, MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256k1N] and "b" in ked and ked["b"]:
                raise DerivationError("Non-empty b = {} for non-transferable"
                                      " code = {}".format(ked["b"],
                                                          verfer.code))

            if verfer.code in [MtrDex.Ed25519N, MtrDex.ECDSA_256r1N, MtrDex.ECDSA_256k1N] and "a" in ked and ked["a"]:
                raise DerivationError("Non-empty a = {} for non-transferable"
                                      " code = {}".format(ked["a"],
                                                          verfer.code))

        except Exception as ex:
            raise DerivationError("Error checking nxt = {}".format(ex))

        return (verfer.raw, verfer.code)

    def _verify_non_transferable(self, ked, pre, prefixed=False):
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

    def _derive_transferable(self, ked):
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

        if verfer.code not in [MtrDex.Ed25519, MtrDex.ECDSA_256r1, MtrDex.ECDSA_256k1]:
            raise DerivationError("Mismatch derivation code = {}"
                                  "".format(verfer.code))

        return (verfer.raw, verfer.code)

    def _verify_transferable(self, ked, pre, prefixed=False):
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
        if ilk not in (Ilks.icp, Ilks.dip, Ilks.vcp, Ilks.iss):
            raise DerivationError("Invalid ilk = {} to derive pre.".format(ilk))

        # put in dummy pre to get size correct
        ked["i"] = self.Dummy * Matter.Sizes[MtrDex.Blake3_256].fs
        ked["d"] = ked["i"]  # must be same dummy
        #raw, proto, kind, ked, version = sizeify(ked=ked)
        raw, _, _, _, _ = sizeify(ked=ked)
        dig = blake3.blake3(raw).digest()  # digest with dummy 'i' and 'd'
        return (dig, MtrDex.Blake3_256)  # dig is derived correct new 'i' and 'd'


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

            if ked["i"] != ked["d"]:  # when digestive then SAID must match pre
                return False

        except Exception as ex:
            return False

        return True



# digest algorithm  klas, digest size (not default), digest length
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
                 kind=None, label=Saids.d, ignore=None, **kwa):
        """
        See Matter.__init__ for inherited parameters

        Parameters:
            sad (dict): self addressed data to serialize and inject said
            kind (str): serialization algorithm of sad, one of Serials
                        used to override that given by 'v' field if any in sad
                        otherwise default is Serials.json
            label (str): Saidage value as said field label
            ignore (list): fields to ignore when generating SAID

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

            # make copy of sad to derive said raw bytes and new sad
            # need new sad because sets sad[label] and sad['v'] fields
            raw, sad = self.derive(sad=dict(sad),
                                   code=code,
                                   kind=kind,
                                   label=label,
                                   ignore=ignore)
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
            _, _, knd, _ = deversify(sad['v'])

        if not kind:  # match logic of Serder for kind
            kind = knd

        return dumps(sad, kind=kind)

    @classmethod
    def saidify(clas,
                sad: dict,
                *,
                code: str = MtrDex.Blake3_256,
                kind: str = None,
                label: str = Saids.d,
                ignore: list = None, **kwa):
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
            label (str): Saidage value as said field label in which to inject said
            ignore (list): fields to ignore when generating SAID

        """
        if label not in sad:
            raise KeyError("Missing id field labeled={} in sad.".format(label))
        raw, sad = clas._derive(sad=sad, code=code, kind=kind, label=label, ignore=ignore)
        saider = clas(raw=raw, code=code, kind=kind, label=label, ignore=ignore, **kwa)
        sad[label] = saider.qb64
        return saider, sad


    @classmethod
    def _derive(clas, sad: dict, *,
                code: str = MtrDex.Blake3_256,
                kind: str = None,
                label: str = Saids.d,
                ignore: list = None):
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
            label (str): Saidage value as said field label in which to inject dummy
            ignore (list): fields to ignore when generating SAID

        """
        if code not in DigDex or code not in clas.Digests:
            raise ValueError("Unsupported digest code = {}.".format(code))

        sad = dict(sad)  # make shallow copy so don't clobber original sad
        # fill id field denoted by label with dummy chars to get size correct
        sad[label] = clas.Dummy * Matter.Sizes[code].fs
        if 'v' in sad:  # if versioned then need to set size in version string
            raw, proto, kind, sad, version = sizeify(ked=sad, kind=kind)

        ser = dict(sad)
        if ignore:
            for f in ignore:
                del ser[f]

        # string now has
        # correct size
        klas, size, length = clas.Digests[code]
        # sad as 'v' verision string then use its kind otherwise passed in kind
        cpa = [clas._serialize(ser, kind=kind)]  # raw pos arg class
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
            label (str): Saidage value of said field labelin which to inject dummy
        """
        code = code if code is not None else self.code
        return self._derive(sad=sad, code=code, **kwa)


    def verify(self, sad, *, prefixed=False, versioned=True, code=None,
               kind=None, label=Saids.d, ignore=None, **kwa):
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
            label (str): Saidage value of said field label in which to inject dummy
            ignore (list): fields to ignore when generating SAID
        """
        try:
            # override ensure code is self.code
            raw, dsad = self._derive(sad=sad, code=self.code, kind=kind, label=label, ignore=ignore)
            saider = Saider(raw=raw, code=self.code, ignore=ignore, **kwa)
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
    """ IndexerCodex is codex hard (stable) part of all indexer derivation codes.

    Codes indicate which list of keys, current and/or prior next, index is for:

        _Sig:           Indices in code may appear in both current signing and
                        prior next key lists when event has both current and prior
                        next key lists. Two character code table has only one index
                        so must be the same for both lists. Other index if for
                        prior next.
                        The indices may be different in those code tables which
                        have two sets of indices.

        _Crt_Sig:       Index in code for current signing key list only.

        _Big_:          Big index values


    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """

    Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
    Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Sig: str = 'C'  # ECDSA secp256k1 sig appears same in both lists if any.
    ECDSA_256k1_Crt_Sig: str = 'D'  # ECDSA secp256k1 sig appears in current list.
    ECDSA_256r1_Sig: str = "E"  # ECDSA secp256r1 sig appears same in both lists if any.
    ECDSA_256r1_Crt_Sig: str = "F"  # ECDSA secp256r1 sig appears in current list.
    Ed448_Sig: str = '0A'  # Ed448 signature appears in both lists.
    Ed448_Crt_Sig: str = '0B'  # Ed448 signature appears in current list only.
    Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both lists.
    Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Big_Sig: str = '2C'  # ECDSA secp256k1 sig appears in both lists.
    ECDSA_256k1_Big_Crt_Sig: str = '2D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Big_Sig: str = "2E"  # ECDSA secp256r1 sig appears in both lists.
    ECDSA_256r1_Big_Crt_Sig: str = "2F"  # ECDSA secp256r1 sig appears in current list only.
    Ed448_Big_Sig: str = '3A'  # Ed448 signature appears in both lists.
    Ed448_Big_Crt_Sig: str = '3B'  # Ed448 signature appears in current list only.
    TBD0: str = '0z'  # Test of Var len label L=N*4 <= 4095 char quadlets includes code
    TBD1: str = '1z'  # Test of index sig lead 1
    TBD4: str = '4z'  # Test of index sig lead 1 big

    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"

IdrDex = IndexerCodex()


@dataclass(frozen=True)
class IndexedSigCodex:
    """IndexedSigCodex is codex all indexed signature derivation codes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
    Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Sig: str = 'C'  # ECDSA secp256k1 sig appears same in both lists if any.
    ECDSA_256k1_Crt_Sig: str = 'D'  # ECDSA secp256k1 sig appears in current list.
    ECDSA_256r1_Sig: str = "E"  # ECDSA secp256r1 sig appears same in both lists if any.
    ECDSA_256r1_Crt_Sig: str = "F"  # ECDSA secp256r1 sig appears in current list.
    Ed448_Sig: str = '0A'  # Ed448 signature appears in both lists.
    Ed448_Crt_Sig: str = '0B'  # Ed448 signature appears in current list only.
    Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both lists.
    Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Big_Sig: str = '2C'  # ECDSA secp256k1 sig appears in both lists.
    ECDSA_256k1_Big_Crt_Sig: str = '2D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Big_Sig: str = "2E"  # ECDSA secp256r1 sig appears in both lists.
    ECDSA_256r1_Big_Crt_Sig: str = "2F"  # ECDSA secp256r1 sig appears in current list only.
    Ed448_Big_Sig: str = '3A'  # Ed448 signature appears in both lists.
    Ed448_Big_Crt_Sig: str = '3B'  # Ed448 signature appears in current list only.

    def __iter__(self):
        return iter(astuple(self))

IdxSigDex = IndexedSigCodex()  # Make instance


@dataclass(frozen=True)
class IndexedCurrentSigCodex:
    """IndexedCurrentSigCodex is codex indexed signature codes for current list.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Crt_Sig: str = 'D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Crt_Sig: str = "F"  # ECDSA secp256r1 sig appears in current list.
    Ed448_Crt_Sig: str = '0B'  # Ed448 signature appears in current list only.
    Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Big_Crt_Sig: str = '2D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Big_Crt_Sig: str = "2F"  # ECDSA secp256r1 sig appears in current list only.
    Ed448_Big_Crt_Sig: str = '3B'  # Ed448 signature appears in current list only.

    def __iter__(self):
        return iter(astuple(self))

IdxCrtSigDex = IndexedCurrentSigCodex()  # Make instance



@dataclass(frozen=True)
class IndexedBothSigCodex:
    """IndexedBothSigCodex is codex indexed signature codes for both lists.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
    ECDSA_256k1_Sig: str = 'C'  # ECDSA secp256k1 sig appears same in both lists if any.
    ECDSA_256r1_Sig: str = "E"  # ECDSA secp256r1 sig appears same in both lists if any.
    Ed448_Sig: str = '0A'  # Ed448 signature appears in both lists.
    Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both listsy.
    ECDSA_256k1_Big_Sig: str = '2C'  # ECDSA secp256k1 sig appears in both lists.
    ECDSA_256r1_Big_Sig: str = "2E"  # ECDSA secp256r1 sig appears in both lists.
    Ed448_Big_Sig: str = '3A'  # Ed448 signature appears in both lists.

    def __iter__(self):
        return iter(astuple(self))

IdxBthSigDex = IndexedBothSigCodex()  # Make instance

# namedtuple for size entries in Incexer derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# os is the other size int number of chars in other index part of soft
#     ms = ss - os main index size computed
# fs is the full size int number of chars in code plus appended material if any
# ls is the lead size int number of bytes to pre-pad pre-converted raw binary
Xizage = namedtuple("Xizage", "hs ss os fs ls")

class Indexer:
    """ Indexer is fully qualified cryptographic material primitive base class for
    indexed primitives. In special cases some codes in the Index code table
    may be of variable length (i.e. not indexed) when the full size table entry
    is None. In that case the index is used instread as the length.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        code is str of stable (hard) part of derivation code
        raw (bytes): unqualified crypto material usable for crypto operations
        index (int): main index offset into list or length of material
        ondex (int | None): other index offset into list or length of material
        qb64b (bytes): fully qualified Base64 crypto material
        qb64 (str | bytes):  fully qualified Base64 crypto material
        qb2 (bytes): fully qualified binary crypto material

    Hidden:
        ._code (str): value for .code property
        ._raw (bytes): value for .raw property
        ._index (int): value for .index property
        ._ondex (int): value for .ondex property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._binfil is method to compute fully qualified Base2 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64
        ._bexfil is method to extract .code and .raw from fully qualified Base2

    """
    Codex = IdrDex
    # Hards table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always > 0 for Indexer.
    Hards = ({chr(c): 1 for c in range(65, 65 + 26)})
    Hards.update({chr(c): 1 for c in range(97, 97 + 26)})
    Hards.update([('0', 2), ('1', 2), ('2', 2), ('3', 2), ('4', 2)])
    # Sizes table maps hs chars of code to Xizage namedtuple of (hs, ss, os, fs, ls)
    # where hs is hard size, ss is soft size, os is other index size,
    # and fs is full size, ls is lead size.
    # where ss includes os, so main index size ms = ss - os
    # soft size, ss, should always be  > 0 for Indexer
    Sizes = {
        'A': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'B': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'C': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'D': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'E': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'F': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        '0A': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '0B': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '2A': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2B': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2C': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2D': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2E': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2F': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '3A': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '3B': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '0z': Xizage(hs=2, ss=2, os=0, fs=None, ls=0),
        '1z': Xizage(hs=2, ss=2, os=1, fs=76, ls=1),
        '4z': Xizage(hs=2, ss=6, os=3, fs=80, ls=1),
    }
    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first code char. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    def __init__(self, raw=None, code=IdrDex.Ed25519_Sig, index=0, ondex=None,
                 qb64b=None, qb64=None, qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            raw (bytes): unqualified crypto material usable for crypto operations
            code is str of stable (hard) part of derivation code
            index (int): main index offset into list or length of material
            ondex (int | None): other index offset into list or length of material
            qb64b (bytes): fully qualified Base64 crypto material
            qb64 (str | bytes):  fully qualified Base64 crypto material
            qb2 (bytes): fully qualified binary crypto material
            strip (bool): True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip

        Needs either (raw and code and index) or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code provided then validate that code is correct
        for length of raw  and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign
        .raw, .code, .index, .ondex.

        """
        if raw is not None:  # raw provided
            if not code:
                raise EmptyMaterialError("Improper initialization need either "
                                         "(raw and code) or qb64b or qb64 or qb2.")
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError(f"Not a bytes or bytearray, raw={raw}.")

            if code not in self.Sizes:
                raise UnexpectedCodeError(f"Unsupported code={code}.")

            hs, ss, os, fs, ls = self.Sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            ms = ss - os

            if not isinstance(index, int) or index < 0 or index > (64 ** ms - 1):
                raise InvalidVarIndexError(f"Invalid index={index} for code={code}.")

            if isinstance(ondex, int) and os and not (ondex >= 0 and ondex <= (64 ** os - 1)):
                raise InvalidVarIndexError(f"Invalid ondex={ondex} for code={code}.")

            if code in IdxCrtSigDex and ondex is not None:
                raise InvalidVarIndexError(f"Non None ondex={ondex} for code={code}.")

            if code in IdxBthSigDex:
                if ondex is None:  # set default
                    ondex = index  # when not provided make ondex match index
                else:
                    if ondex != index and os == 0:  # must match if os == 0
                        raise InvalidVarIndexError(f"Non matching ondex={ondex}"
                                                   f" and index={index} for "
                                                   f"code={code}.")


            if not fs:  # compute fs from index
                if cs % 4:
                    raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                               f"variable length material. cs={cs}.")
                if os != 0:
                    raise InvalidCodeSizeError(f"Non-zero other index size for "
                                               f"variable length material. os={os}.")
                fs = (index * 4) + cs

            rawsize = (fs - cs) * 3 // 4

            raw = raw[:rawsize]  # copy rawsize from stream, may be less
            if len(raw) != rawsize:  # forbids shorter
                raise RawMaterialError(f"Not enougth raw bytes for code={code}"
                                       f"and index={index} ,expected {rawsize} "
                                       f"got {len(raw)}.")

            self._code = code
            self._index = index
            self._ondex = ondex
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
        Returns expected raw size in bytes for a given code. Not applicable to
        codes with fs = None
        """
        hs, ss, os, fs, ls = cls.Sizes[code]  # get sizes
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
    def ondex(self):
        """
        Returns ._ondex
        Makes .ondex read only
        """
        return self._ondex

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

        cs = hs + ss
        os = ss - ms (main index size)
        when fs None then size computed & fs = size * 4 + cs

        """
        code = self.code  # codex value chars hard code
        index = self.index  # main index value
        ondex = self.ondex  # other index value
        raw = self.raw  # bytes or bytearray

        ps = (3 - (len(raw) % 3)) % 3  # if lead then same pad size chars & lead size bytes
        hs, ss, os, fs, ls = self.Sizes[code]
        cs = hs + ss
        ms = ss - os

        if not fs:  # compute fs from index
            if cs % 4:
                raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                           f"variable length material. cs={cs}.")
            if os != 0:
                raise InvalidCodeSizeError(f"Non-zero other index size for "
                                           f"variable length material. os={os}.")
            fs = (index * 4) + cs

        if index < 0 or index > (64 ** ms - 1):
            raise InvalidVarIndexError(f"Invalid index={index} for code={code}.")

        if (isinstance(ondex, int) and os and
                not (ondex >= 0 and ondex <= (64 ** os - 1))):
            raise InvalidVarIndexError(f"Invalid ondex={ondex} for os={os} and "
                                       f"code={code}.")

        # both is hard code + converted index + converted ondex
        both = (f"{code}{intToB64(index, l=ms)}"
                f"{intToB64(ondex if ondex is not None else 0, l=os)}")

        # check valid pad size for whole code size, assumes ls is zero
        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        if (cs % 4) != ps - ls:  # adjusted pad given lead bytes
            raise InvalidCodeSizeError(f"Invalid code={both} for converted"
                                       f" raw pad size={ps}.")

        # prepend pad bytes, convert, then replace pad chars with full derivation
        # code including index,
        full = both.encode("utf-8") + encodeB64(bytes([0] * ps) + raw)[ps - ls:]

        if len(full) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid code={both} for raw size={len(raw)}.")

        return full


    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code and self.index  converted to Base2 + self.raw left shifted
        with pad bits equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex chars hard code
        index = self.index  # main index value
        ondex = self.ondex  # other index value
        raw = self.raw  # bytes or bytearray

        ps = (3 - (len(raw) % 3)) % 3  # same pad size chars & lead size bytes
        hs, ss, os, fs, ls = self.Sizes[code]
        cs = hs + ss
        ms = ss - os

        if index < 0 or index > (64 ** ss - 1):
            raise InvalidVarIndexError(f"Invalid index={index} for code={code}.")

        if (isinstance(ondex, int) and os and
                not (ondex >= 0 and ondex <= (64 ** os - 1))):
            raise InvalidVarIndexError(f"Invalid ondex={ondex} for os={os} and "
                                       f"code={code}.")

        if not fs:  # compute fs from index
            if cs % 4:
                raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                           f"variable length material. cs={cs}.")
            if os != 0:
                raise InvalidCodeSizeError(f"Non-zero other index size for "
                                           f"variable length material. os={os}.")
            fs = (index * 4) + cs

        # both is hard code + converted index
        both = (f"{code}{intToB64(index, l=ms)}"
                f"{intToB64(ondex if ondex is not None else 0, l=os)}")

        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        if (cs % 4) != ps - ls:  # adjusted pad given lead bytes
                    raise InvalidCodeSizeError(f"Invalid code={both} for converted"
                                               f" raw pad size={ps}.")

        n = sceil(cs * 3 / 4)  # number of b2 bytes to hold b64 code + index
        # convert code both to right align b2 int then left shift in pad bits
        # then convert to bytes
        bcode = (b64ToInt(both) << (2 * (ps - ls))).to_bytes(n, 'big')
        full = bcode + bytes([0] * ls) + raw

        bfs = len(full)  # binary full size
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid code={both} for raw size={len(raw)}.")

        return full


    def _exfil(self, qb64b):
        """
        Extracts self.code, self.index, and self.raw from qualified base64 bytes qb64b

        cs = hs + ss
        ms = ss - os (main index size)
        when fs None then size computed & fs = size * 4 + cs
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material.")

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
                raise UnexpectedCodeError(f"Unsupported code start char={first}.")

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError(f"Need {hs - len(qb64b)} more characters.")

        hard = qb64b[:hs]  # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, os, fs, ls = self.Sizes[hard]  # assumes hs in both tables consistent
        cs = hs + ss  # both hard + soft code size
        ms = ss - os
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)
        # assumes no variable length indexed codes so fs is not None

        if len(qb64b) < cs:  # need more bytes
            raise ShortageError(f"Need {cs - len(qb64b)} more characters.")

        index = qb64b[hs:hs+ms]  # extract index/size chars
        if hasattr(index, "decode"):
            index = index.decode("utf-8")
        index = b64ToInt(index)  # compute int index

        ondex = qb64b[hs+ms:hs+ms+os]  # extract ondex chars
        if hasattr(ondex, "decode"):
            ondex = ondex.decode("utf-8")

        if hard in IdxCrtSigDex:  # if current sig then ondex from code must be 0
            ondex = b64ToInt(ondex) if os else None  # compute ondex from code
            if ondex:  # not zero or None so error
                raise ValueError(f"Invalid ondex={ondex} for code={hard}.")
            else:
                ondex = None  # zero so set to None when current only
        else:
            ondex = b64ToInt(ondex) if os else index

        # index is index for some codes and variable length for others
        if not fs:  # compute fs from index which means variable length
            if cs % 4:
                raise ValidationError(f"Whole code size not multiple of 4 for "
                                      f"variable length material. cs={cs}.")
            if os != 0:
                raise ValidationError(f"Non-zero other index size for "
                                      f"variable length material. os={os}.")
            fs = (index * 4) + cs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError(f"Need {fs - len(qb64b)} more chars.")

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # strip off prepended code and append pad characters
        #ps = cs % 4  # pad size ps = cs mod 4, same pad chars and lead bytes
        #base = ps * b'A' + qb64b[cs:]  # replace prepend code with prepad zeros
        #raw = decodeB64(base)[ps+ls:]  # decode and strip off ps+ls prepad bytes

        # check for non-zeroed pad bits or lead bytes
        ps = cs % 4  # code pad size ps = cs mod 4
        pbs = 2 * (ps if ps else ls)  # pad bit size in bits
        if ps:  # ps. IF ps THEN not ls (lead) and vice versa OR not ps and not ls
            base = ps * b'A' + qb64b[cs:]  # replace pre code with prepad chars of zero
            paw = decodeB64(base)  # decode base to leave prepadded raw
            pi = (int.from_bytes(paw[:ps], "big"))  # prepad as int
            if pi & (2 ** pbs - 1 ):  # masked pad bits non-zero
                raise ValueError(f"Non zeroed prepad bits = "
                                 f"{pi & (2 ** pbs - 1 ):<06b} in {qb64b[cs:cs+1]}.")
            raw = paw[ps:]  # strip off ps prepad paw bytes
        else:  # not ps. IF not ps THEN may or may not be ls (lead)
            base = qb64b[cs:]  # strip off code leaving lead chars if any and value
            # decode lead chars + val leaving lead bytes + raw bytes
            # then strip off ls lead bytes leaving raw
            paw = decodeB64(base) # decode base to leave prepadded paw bytes
            li = int.from_bytes(paw[:ls], "big")  # lead as int
            if li:  # pre pad lead bytes must be zero
                if ls == 1:
                    raise ValueError(f"Non zeroed lead byte = 0x{li:02x}.")
                else:
                    raise ValueError(f"Non zeroed lead bytes = 0x{li:04x}.")

            raw = paw[ls:]

        if len(raw) != (len(qb64b) - cs) * 3 // 4:  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb64b}")

        self._code = hard
        self._index = index
        self._ondex = ondex
        self._raw = raw  # must be bytes for crpto opts and immutable not bytearray



    def _bexfil(self, qb2):
        """
        Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2

        cs = hs + ss
        ms = ss - os (main index size)
        when fs None then size computed & fs = size * 4 + cs
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
                raise UnexpectedCodeError(f"Unsupported code start sextet={first}.")

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError(f"Need {bhs - len(qb2)} more bytes.")

        hard = codeB2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, os, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        ms = ss - os
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        index = b64ToInt(both[hs:hs+ms])  # compute index

        if hard in IdxCrtSigDex:  # if current sig then ondex from code must be 0
            ondex = b64ToInt(both[hs+ms:hs+ms+os]) if os else None  # compute ondex from code
            if ondex:  # not zero or None so error
                raise ValueError(f"Invalid ondex={ondex} for code={hard}.")
            else:
                ondex = None  # zero so set to None when current only
        else:
            ondex = b64ToInt(both[hs+ms:hs+ms+os]) if os else index

        if hard in IdxCrtSigDex:  # if current sig then ondex from code must be 0
            if ondex:  # not zero so error
                raise ValueError(f"Invalid ondex={ondex} for code={hard}.")
            else:  # zero so set to None
                ondex = None

        if not fs:  # compute fs from size chars in ss part of code
            if cs % 4:
                raise ValidationError(f"Whole code size not multiple of 4 for "
                                      f"variable length material. cs={cs}.")
            if os != 0:
                raise ValidationError(f"Non-zero other index size for "
                                      f"variable length material. os={os}.")
            fs = (index * 4) + cs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))

        qb2 = qb2[:bfs]  # extract qb2 fully qualified primitive code plus material

        # check for non-zeroed prepad bits or lead bytes
        ps = cs % 4  # code pad size ps = cs mod 4
        pbs = 2 * (ps if ps else ls)  # pad bit size in bits
        if ps:  # ps. IF ps THEN not ls (lead) and vice versa OR not ps and not ls
            # convert last byte of code bytes in which are pad bits to int
            pi = (int.from_bytes(qb2[bcs-1:bcs], "big"))
            if pi & (2 ** pbs - 1 ):  # masked pad bits non-zero
                raise ValueError(f"Non zeroed pad bits = "
                                 f"{pi & (2 ** pbs - 1 ):>08b} in 0x{pi:02x}.")
        else:  # not ps. IF not ps THEN may or may not be ls (lead)
            li = int.from_bytes(qb2[bcs:bcs+ls], "big")  # lead as int
            if li:  # pre pad lead bytes must be zero
                if ls == 1:
                    raise ValueError(f"Non zeroed lead byte = 0x{li:02x}.")
                else:
                    raise ValueError(f"Non zeroed lead bytes = 0x{li:02x}.")


        raw = qb2[(bcs + ls):]  # strip code and leader bytes from qb2 to get raw

        if len(raw) != (len(qb2) - bcs - ls):  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb2}")

        self._code = hard
        self._index = index
        self._ondex = ondex
        self._raw = bytes(raw)  # must be bytes for crypto ops and not bytearray mutable


class Siger(Indexer):
    """
    Siger is subclass of Indexer, indexed signature material,

    Adds .verfer property which is instance of Verfer that provides
          associated signature verifier.

    See Indexer for inherited attributes and properties:

    Attributes:

    Properties:
        verfer (Verfer): instance if any provides public verification key

    Methods:

    Hidden:
        _verfer (Verfer): value for .verfer property


    """

    def __init__(self, verfer=None, **kwa):
        """Initialze instance

        Parameters:  See Matter for inherted parameters
            verfer (Verfer): instance if any provides public verification key

        """
        super(Siger, self).__init__(**kwa)
        if self.code not in IdxSigDex:
            raise ValidationError("Invalid code = {} for Siger."
                                  "".format(self.code))
        self.verfer = verfer

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
    AttachedMaterialQuadlets: str = '-V'  # Composed Grouped Attached Material Quadlet (4 char each)
    BigAttachedMaterialQuadlets: str = '-0V'  # Composed Grouped Attached Material Quadlet (4 char each)
    KERIProtocolStack: str = '--AAA'  # KERI ACDC Protocol Stack CESR Version

    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"

CtrDex = CounterCodex()


@dataclass(frozen=True)
class ProtocolGenusCodex:
    """ProtocolGenusCodex is codex of protocol genera for code table.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    KERI: str = '--AAA'  # KERI and ACDC Protocol Stacks share the same tables
    ACDC: str = '--AAA'  # KERI and ACDC Protocol Stacks share the same tables


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"
        # duplicate values above just result in multiple entries in tuple so
        # in inclusion still works

ProDex = ProtocolGenusCodex()  # Make instance


@dataclass(frozen=True)
class AltCounterCodex:
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
    BigMessageDataGroups: str = '-0U'  # Composed Message Data Group or Primitive
    BigAttachedMaterialQuadlets: str = '-0V'  # Composed Grouped Attached Material Quadlet (4 char each)
    BigMessageDataMaterialQuadlets: str = '-0W'  # Composed Grouped Message Data Quadlet (4 char each)
    BigCombinedMaterialQuadlets: str = '-0X'  # Combined Message Data + Attachments Quadlet (4 char each)
    BigMaterialGroups: str = '-0Y'  # Composed Generic Material Group or Primitive
    BigMaterialQuadlets: str = '-0Z'  # Composed Generic Material Quadlet (4 char each)


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"


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
    Hards.update([('--', 5)])
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
        '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
        '-0V': Sizage(hs=3, ss=5, fs=8, ls=0),
        '--AAA': Sizage(hs=5, ss=3, fs=8, ls=0),
    }
    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first two code char. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    def __init__(self, code=None, count=None, countB64=None,
                 qb64b=None, qb64=None, qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            code (str | None):  stable (hard) part of derivation code
            count (int | None): count for composition.
                Count may represent quadlets/triplet, groups, primitives or
                other numericy
                When both count and countB64 are None then count defaults to 1
            countB64 (str | None): count for composition as Base64
                countB64 may represent quadlets/triplet, groups, primitives or
                other numericy
            qb64b (bytes | bytearray | None): fully qualified crypto material text domain
            qb64 (str | None) fully qualified crypto material text domain
            qb2 (bytes | bytearray | None)  fully qualified crypto material binary domain
            strip (bool):  True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip.
                default False


        Needs either code or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When code and count provided then validate that code and count are correct
        Else when qb64b or qb64 or qb2 provided extract and assign
        .code and .count

        """
        if code is not None:  # code provided
            if code not in self.Sizes:
                raise InvalidCodeError("Unsupported code={}.".format(code))

            hs, ss, fs, ls = self.Sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            if fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
                raise InvalidCodeSizeError("Whole code size not full size or not "
                                           "multiple of 4. cs={} fs={}.".format(cs, fs))

            if count is None:
                count = 1 if countB64 is None else b64ToInt(countB64)

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


    def countToB64(self, l=None):
        """ Returns count as Base64 left padded with "A"s
            Parameters:
                l (int | None): minimum number characters including left padding
                    When not provided use the softsize of .code

        """
        if l is None:
            _, ss, _, _ = self.Sizes[self.code]
            l = ss
        return (intToB64(self.count, l=l))


    @staticmethod
    def semVerToB64(version="", major=0, minor=0, patch=0):
        """ Converts semantic version to Base64 representation of countB64
        suitable for CESR protocol genus and version

        Returns:
            countB64 (str): suitable for input to Counter
            example: Counter(countB64=semVerToB64(version = "1.0.0"))

        Parameters:
            version (str | None): dot separated semantic version string of format
                "major.minor.patch"
            major (int): When version is None or empty then use major,minor, patch
            minor (int): When version is None or empty then use major,minor, patch
            patch (int): When version is None or empty then use major,minor, patch

        each of major, minor, patch must be in range [0,63] for represenation as
        three Base64 characters

        """
        parts = [major, minor, patch]
        if version:
            splits = version.split(".", maxsplit=3)
            splits = [(int(s) if s else 0) for s in splits]
            for i in range(3-len(splits),0, -1):
                splits.append(parts[-i])
            parts = splits

        for p in parts:
            if p < 0 or p > 63:
                raise ValueError(f"Out of bounds semantic version. "
                                 f"Part={p} is < 0 or > 63.")
        return ("".join(intToB64(p, l=1) for p in parts))


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

        return (codeB64ToB2(both))  # convert to b2 left shift if any


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
            hard = hard.decode("utf-8")  # decode converts bytearray/bytes to str
        if hard not in self.Sizes:  # Sizes needs str not bytes
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

        hard = codeB2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        count = b64ToInt(both[hs:hs + ss])  # get count

        self._code = hard
        self._count = count


class Sadder:
    """
    Sadder is self addressed data (SAD) serializer-deserializer class

    Instance creation of a Sadder does not verifiy it .said property it merely
    extracts it. In order to ensure Sadder instance has a verified .said then
    must call .saider.verify(sad=self.ked)

    Has the following public properties:

    Properties:
        raw (bytes): of serialized event only
        ked (dict): self addressed data dict
        kind (str): serialization kind coring.Serials such as JSON, CBOR, MGPK, CESR
        size (int): number of bytes in serialization
        version (Versionage): protocol version (Major, Minor)
        proto (str): Protocolage value as protocol identifier such as KERI, ACDC
        label (str): Saidage value as said field label
        saider (Saider): of SAID of this SAD .ked['d'] if present
        said (str): SAID of .saider qb64
        saidb (bytes): SAID of .saider  qb64b
        pretty (str): Pretty JSON of this SAD

    Hidden Attributes:
        ._raw is bytes of serialized event only
        ._ked is key event dict
        ._kind is serialization kind string value (see namedtuple coring.Serials)
          supported kinds are 'json', 'cbor', 'msgpack', 'binary'
        ._size is int of number of bytes in serialed event only
        ._version is Versionage instance of event version
        ._proto (str):  Protocolage value as protocol type identifier
        ._saider (Saider): instance for this Sadder's SAID

    Note:
        loads and jumps of json use str whereas cbor and msgpack use bytes

    """

    def __init__(self, raw=b'', ked=None, sad=None, kind=None, saidify=False,
                 code=MtrDex.Blake3_256):
        """
        Deserialize if raw provided does not verify assumes embedded said is valid
        Serialize if ked provided but not raw verifies if verify is True?
        When serializing if kind provided then use kind instead of field in ked

        Parameters:
          raw (bytes): serialized event
          ked is key event dict or None
            if None its deserialized from raw
          kind is serialization kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind is None then its extracted from ked or raw
          saidify (bool): True means compute said for ked
          code is .diger default digest code for computing said .saider

        """
        self._code = code  # need default code for .saider
        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif ked:  # serialize ked using property setter
            #ToDo  when pass in ked and saidify True then compute said
            self._kind = kind
            self.ked = ked  # ked property setter does the serialization
        elif sad:
            # ToDo do we need this or should we be using ked above with saidify flag
            self._clone(sad=sad)  # copy fields from sad
        else:
            raise ValueError("Improper initialization need sad, raw or ked.")


    def _clone(self, sad):
        """ copy hidden attributes from sad """
        self._raw = sad.raw
        self._ked = sad.ked
        self._kind = sad.kind
        self._size = sad.size
        self._version = sad.version
        self._proto = sad.proto
        self._saider = sad.saider


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
        proto, kind, version, size = sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}, expected {}."
                               "".format(version.major, version.minor, Version))
        if len(raw) < size:
            raise ShortageError("Need more bytes.")

        ked = loads(raw=raw, size=size, kind=kind)

        return ked, proto, kind, version, size


    def _exhale(self, ked, kind=None):
        """
        Returns sizeify(ked, kind)

        From sizeify
        Returns tuple of (raw, proto, kind, ked, version) where:
            raw (str): serialized event as bytes of kind
            proto (str): protocol type as value of Protocolage
            kind (str): serialzation kind as value of Serialage
            ked (dict): key event dict or sad dict
            version (Versionage): instance

        Parameters:
            ked (dict): key event dict or sad dict
            kind (str): value of Serials serialization kind.
                When not provided use

        Assumes only supports Version
        """
        return sizeify(ked=ked, kind=kind)


    def compare(self, said=None):
        """
        Returns True  if said and either .saider.qb64 or .saider.qb64b match
        via string equality ==

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


    @property
    def raw(self):
        """ raw property getter """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        ked, proto, kind, version, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._ked = ked
        self._proto = proto
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
        raw, proto, kind, ked, version = self._exhale(ked=ked, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._proto = proto
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
        """ kind property setter Assumes ._ked. Serialization kind. """
        raw, proto, kind, ked, version = self._exhale(ked=self._ked, kind=kind)
        size = len(raw)
        self._raw = raw[:size]
        self._proto = proto
        self._ked = ked
        self._kind = kind
        self._size = size
        self._version = version
        self._saider = Saider(qb64=ked["d"], code=self._code)


    @property
    def size(self):
        """ size property getter"""
        return self._size


    @property
    def version(self):
        """
        version property getter

        Returns:
            (Versionage):
        """
        return self._version


    @property
    def proto(self):
        """ proto property getter
        protocol identifier type value of Protocolage such as 'KERI' or 'ACDC'

        Returns:
            (str): Protocolage value as protocol type
        """
        return self._proto


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



class Tholder:
    """
    Tholder is KERI Signing Threshold Satisfaction class
    .satisfy method evaluates satisfaction based on ordered list of indices of
    verified signatures where indices correspond to offsets in key list of
    associated signatures.

    Has the following public properties:

    Properties:
        .weighted is Boolean True if fractional weighted threshold False if numeric
        .size is int of minimum size of keys list
                    when weighted is size of keys list
                    when unweighted is size of int thold since don't have anyway
                        to know size of keys list in this case

        .limen is qualified b64 signing threshold suitable for CESR serialization.
            either Number.qb64b or Bexter.qb64b.
            The b64 portion of limen  with code stripped (Bexter.bext) of
              [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
              is '1s2c1s2c1s4c1s4c1s4a1c1' basically slash is 's', comma is 'c',
              and ANDed clauses are delimited by 'a'.

        .sith is original signing threshold suitable for value to be serialized
            as json, cbor, mgpk in key event message as either:
                non-negative hex number str or
                list of str rational number fractions >= 0 and <= 1 or
                list of list of str rational number fractions >= 0 and <= 1

        .thold is parsed signing threshold suitable for calculating satisfaction.
            either as int or list of Fractions

        .num is int signing threshold when not ._weighted

    Methods:
        .satisfy returns bool, True means ilist of verified signature key indices satisfies
             threshold, False otherwise.

    Static Methods:
        weight (str): converts weight str expression into either int or Fraction
                    else raises ValueError must satisfy 0 <= w <= 1
                    Ensures strict proper rational number fraction of ints or
                    0 or 1

    Hidden:
        ._weighted is Boolean, True if fractional weighted threshold False if numeric
        ._size is int minimum size of of keys list
        ._sith is signing threshold for .sith property
        ._thold is signing threshold for .thold propery
        ._bexter is Bexter instance of weighted signing threshold or None
        ._number is Number instance of integer threshold or None
        ._satisfy is method reference of threshold specified verification method
        ._satisfy_numeric is numeric threshold verification method
        ._satisfy_weighted is fractional weighted threshold verification method


    """

    def __init__(self, *, thold=None , limen=None, sith=None, **kwa):
        """
        Accepts signing threshold in various forms so that may output correct
        forms for serialization and/or calculation of satisfaction.

        Parameters:
            sith is signing threshold (current or next) expressed as either:
                non-negative int of threshold number (M-of-N threshold)
                    next threshold may be zero
                non-negative hex string of threshold number (M-of-N threshold)
                    next threshold may be zero
                fractional weight clauses which may be expressed as either:
                    an iterable of rational number fraction strings  >= 0 and <= 1
                    an iterable of iterables of rational number fraction strings >= 0 and <= 1
                JSON serialized str of either:
                   list of rational number fraction strings >= 0 and <= 1  or
                   list of list of rational number fraction strings >= 0 and <= 1


            limen is qualified signing threshold (current or next) expressed as either:
                Number.qb64 or .qb64b of integer threshold or
                Bexter.qb64 or .qb64b of fractional weight clauses which may be either:
                    Base64 delimited clauses of fractions
                    Base64 delimited clauses of fractions

            thold is signing threshold (current or next) is suitable for computing
                the satisfaction of a threshold and is expressed as either:
                    int of threshold number (M of N)
                    fractional weight clauses which may be expressed as either:
                        an iterable of Fractions or
                        an iterable of iterables of Fractions.

        The sith representation is meant to parse threhold expressions from
           deserializations of JSON, CBOR, or MGPK key event message fields  or
           the command line or configuration files.

        The limen representation is meant to parse threshold expressions from
           CESR serializations of key event message fields or attachments.

        The thold representation is meant to accept thresholds from computable
            expressions for satisfaction of a threshold


        """
        if thold is not None:
            self._processThold(thold=thold)

        elif limen is not None:
            self._processLimen(limen=limen, **kwa)  # kwa for strip

        elif sith is not None:
            if isinstance(sith, str) and not sith:  # empty str
                raise EmptyMaterialError("Empty threshold expression.")

            self._processSith(sith=sith)

        else:
            raise EmptyMaterialError("Missing threshold expression.")


    @property
    def weighted(self):
        """ weighted property getter """
        return self._weighted

    @property
    def thold(self):
        """ thold property getter """
        return self._thold

    @property
    def size(self):
        """ size property getter """
        return self._size

    @property
    def limen(self):
        """ limen property getter """
        return self._bexter.qb64b if self._weighted else self._number.qb64b

    @property
    def sith(self):
        """ sith property getter """
        # make sith expression of thold
        if self.weighted:
            sith = [[f"{f.numerator}/{f.denominator}" if (0 < f < 1) else f"{int(f)}"
                                           for f in clause]
                                                   for clause in self.thold]
            if len(sith) == 1:
                sith = sith[0]  # simplify list of one clause to clause
        else:
            sith = f"{self.thold:x}"

        return sith

    @property
    def json(self):
        """Returns json serialization of sith expression

        Essentially JSON list of lists of strings
        """
        return json.dumps(self.sith)


    @property
    def num(self):
        """ sith property getter """
        return self.thold if not self._weighted else None



    def _processThold(self, thold: int | Iterable):
        """Process thold input

        Parameters:
            thold (int | Iterable): computable thold expression
        """
        if isinstance(thold, int):
            self._processUnweighted(thold=thold)

        else:
            self._processWeighted(thold=thold)


    def _processLimen(self, limen: str | bytes, **kwa):
        """Process limen input

        Parameters:
            limen (str): CESR encoded qb64 threshold (weighted or unweighted)
        """
        matter = Matter(qb64b=limen, **kwa)  # kwa for strip of stream
        if matter.code in NumDex:
            number = Number(raw=matter.raw, code=matter.code, **kwa)
            self._processUnweighted(thold=number.num)

        elif matter.code in BexDex:
            # Convert to fractional thold expression
            bexter = Bexter(raw=matter.raw, code=matter.code, **kwa)
            t = bexter.bext.replace('s', '/')
            # get clauses
            thold = [clause.split('c') for clause in t.split('a')]
            thold = [[self.weight(w) for w in clause] for clause in thold]
            self._processWeighted(thold=thold)

        else:
            raise InvalidCodeError(f"Invalid code for limen = {matter.code}.")


    def _processSith(self, sith: int | str | Iterable):
        """
        Process attributes for fractionall weighted threshold sith

        Parameters:
            sith is signing threshold (current or next) expressed as either:
                non-negative int of threshold number (M-of-N threshold)
                    next threshold may be zero
                non-negative hex string of threshold number (M-of-N threshold)
                    next threshold may be zero
                fractional weight clauses which may be expressed as either:
                    an iterable of rational number fraction weight str or int str
                        each denoted w where 0 <= w <= 1
                    an iterable of iterables of rational number fraction weight
                       or int str
                       each denoted w where 0 <= w <= 1>= 0
                JSON serialized str of either:
                    list of rational number fraction weight strings
                        each denoted w where 0 <= w <= 1
                    list of lists of rational number fraction weight strings
                        each denoted w where 0 <= w <= 1

                when any w is 0 or 1 then representation is 0 or 1 not 0/1 or 1/1
        """
        if isinstance(sith, int):
            self._processUnweighted(thold=sith)

        elif isinstance(sith, str) and '[' not in sith:
            self._processUnweighted(thold=int(sith, 16))

        else:  # assumes iterable of weights or iterable of iterables of weights
            if isinstance(sith, str):  # json of weighted sith from cli
                sith = json.loads(sith)  # deserialize

            if not sith:  # empty iterable
                raise ValueError(f"Empty weight list = {sith}.")

            # because all([]) == True  have to also test for emply mask
            # is it non str iterable of non str iterable of strs
            mask = [nonStringIterable(c) for c in sith]
            if mask and not all(mask):  # not empty and not iterable of iterables
                sith = [sith]  # attempt to make Iterable of Iterables

            for c in sith:  # get each clause
                mask = [isinstance(w, str) for w in c]  # must be all strs
                if mask and not all(mask):  # not empty and not iterable of strs?
                    raise ValueError(f"Invalid sith = {sith} some weights in"
                                     f"clause {c} are non string.")


            # replace weight str expression, int str or fractional strings with
            # int or fraction as appropriate.
            thold = []
            for clause in sith:  # convert string fractions to Fractions
                # append list of weights converted fromnn str expression
                thold.append([self.weight(w) for w in clause])

            self._processWeighted(thold=thold)


    def _processUnweighted(self, thold=0):
        """
        Process attributes for unweighted (numeric) threshold thold

        Parameters:
            thold (int): non-negative threshold number M-of-N threshold

        """
        if thold < 0:
            raise ValueError(f"Non-positive int threshold = {thold}.")
        self._thold = thold
        self._weighted = False
        self._size = self._thold  # used to verify that keys list size is at least size
        self._satisfy = self._satisfy_numeric
        self._number = Number(num=thold)
        self._bexter = None


    def _processWeighted(self, thold=[]):
        """
        Process attributes for fractionall weighted threshold thold

        Parameters:
            thold (iterable):  iterable or iterable or iterables of
                rational number fraction strings  >= 0 and <= 1

        """
        for clause in thold:  # sum of fractions in clause must be >= 1
            if not (sum(clause) >= 1):
                raise ValueError(f"Invalid sith clause = {thold}, all "
                                 f"clause weight sums must be >= 1.")

        self._thold = thold
        self._weighted = True
        self._size = sum(len(clause) for clause in thold)
        self._satisfy = self._satisfy_weighted
        # make bext str of thold for .bexter for limen
        bext = [[f"{f.numerator}s{f.denominator}" if (0 < f < 1) else f"{int(f)}"
                                           for f in clause]
                                                           for clause in thold]
        bext = "a".join(["c".join(clause) for clause in bext])
        self._number = None
        self._bexter = Bexter(bext=bext)


    @staticmethod
    def _oldcheckWeight(w: Fraction) -> Fraction:
        """Returns w if 0 <= w <= 1 Else raises ValueError

        Parameters:
            w (Fraction): Threshold weight Fraction
        """
        if not 0 <= w <= 1:
            raise ValueError(f"Invalid weight not 0 <= {w} <= 1.")
        return w


    @staticmethod
    def weight(w: str) -> Fraction:
        """Returns valid weight from w else raises error (ValueError or TypeError).
        w expression must evaluate to 0, 1, or strict proper rational fraction.
        w expression must be 0 <= w <= 1 Else raises ValueError
        w must not be float else raises TypeError
        When not int w must be ratio of integers n/d else raise ValueError.

        Parameters:
            w (str): threshold weight expression
        """
        try:  # float str or ratio str raises ValueError
            if int(float(w)) != float(w):  # float str
                raise TypeError("Invalid weight str got float w={w}.")
            w = int(w)  # expression is int str
        except TypeError as ex:
            raise  ValueError(str(ex)) from  ex

        except ValueError as ex:  # not float str or int str so try ration str
            w = Fraction(w)

        if not 0 <= w <= 1:
            raise ValueError(f"Invalid weight not 0 <= {w} <= 1.")
        return w


    def satisfy(self, indices):
        """
        Returns True if indices list of verified signature key indices satisfies
        threshold, False otherwise.

        Parameters:
            indices is list of non-negative indices (offsets into key list)
                of verified signatures. the indices may be in any order, they
                are normalized herein
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
            indices is list of non-negative indices (offsets into key list)
                of verified signatures. the indices may be in any order, they
                are normalized herein

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



class Dicter:
    """ Dicter class is base class for objects that can be stored in a Suber

    Dicter classes can be initialized by a dict and then expose bytes of JSON
    in the .raw property  Subclasses can add semantically appropriate properties
    that extract / add specific keys to the underlying dict .pad

    """

    def __init__(self, raw=b'', pad=None, sad=None, label=Saids.i):
        """ Create Dicter from either pad dict or raw bytes

        Parameters:
            raw(bytes): raw JSON of dicter class
            pad(dict) data dict for class:
            label (str): field name of the SAID field.

        """
        self._label = label
        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
        elif pad:  # serialize ked using property setter
            self.pad = pad  # pad property setter does the serialization
        elif sad:
            self._clone(sad=sad)
        else:
            raise ValueError("Improper initialization need sad, raw or ked.")

    def _clone(self, sad):
        self._raw = sad.raw
        self._pad = sad.pad
        self._rid = sad.rid

    @property
    def raw(self):
        """ raw property getter """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        self._raw = raw
        self._pad = json.loads(self._raw.decode("utf-8"))
        if self._label not in self._pad or self._pad[self._label] == "":
            self._pad[self._label] = randomNonce()

        self._rid = self._pad[self._label]

    @property
    def pad(self):
        """ pad property getter"""
        return self._pad

    @pad.setter
    def pad(self, pad):
        """ pad property setter """
        self._pad = pad
        if self._label not in self._pad or self._pad[self._label] == "":
            self._pad[self._label] = randomNonce()

        self._raw = json.dumps(self._pad).encode("utf-8")
        self._rid = self._pad[self._label]

    @property
    def rid(self):
        """ ID of dict data as str """
        return self._rid

    def pretty(self, *, size=1024):
        """
        Returns str JSON of .ked with pretty formatting

        ToDo: add default size limit on pretty when used for syslog UDP MCU
        like 1024 for ogler.logger
        """
        return json.dumps(self.pad, indent=1)[:size if size is not None else None]


def randomNonce():
    """ Generate a random ed25519 seed and encode as qb64

    Returns:
        str: qb64 encoded ed25519 random seed
    """
    preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seedqb64 = Matter(raw=preseed, code=MtrDex.Ed25519_Seed).qb64
    return seedqb64
