# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import re
import json
from typing import Union
from collections import namedtuple, deque
from collections.abc import Sequence, Mapping
from dataclasses import dataclass, astuple, asdict
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

from ..kering import MaxON

from ..kering import (EmptyMaterialError, RawMaterialError, SoftMaterialError,
                      InvalidCodeError, InvalidSoftError,
                      InvalidSizeError,
                      InvalidCodeSizeError, InvalidVarIndexError,
                      InvalidVarSizeError, InvalidVarRawSizeError,
                      ConversionError, InvalidValueError, InvalidTypeError,
                      ValidationError, VersionError, DerivationError,
                      EmptyListError,
                      ShortageError, UnexpectedCodeError, DeserializeError,
                      UnexpectedCountCodeError, UnexpectedOpCodeError)
from ..kering import (Versionage, Version, Vrsn_1_0, Vrsn_2_0,
                      VERRAWSIZE, VERFMT, MAXVERFULLSPAN,
                      versify, deversify, Rever, smell)
from ..kering import (Kinds, Kindage, Protocols, Protocolage, Ilkage, Ilks,
                      TraitDex, )

from ..help import helping
from ..help.helping import sceil, nonStringIterable, nonStringSequence
from ..help.helping import (intToB64, intToB64b, b64ToInt, B64_CHARS,
                            codeB64ToB2, codeB2ToB64, Reb64, nabSextets)





DSS_SIG_MODE = "fips-186-3"
ECDSA_256r1_SEEDBYTES = 32
ECDSA_256k1_SEEDBYTES = 32

# digest algorithm  klas, digest size (not default), digest length
# size and length are needed for some digest types as function parameters
Digestage = namedtuple("Digestage", "klas size length")

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

    proto, vrsn, knd, size, _ = deversify(ked["v"])  # extract kind and version
    if vrsn != version:
        raise ValueError("Unsupported version = {}.{}".format(vrsn.major,
                                                              vrsn.minor))

    if not kind:
        kind = knd

    if kind not in Kinds:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    raw = dumps(ked, kind)
    size = len(raw)

    match = Rever.search(raw)  # Rever's regex takes bytes
    if not match or match.start() > 12:
        raise ValueError("Invalid version string in raw = {}".format(raw))

    fore, back = match.span()  # full version string
    # update vs with latest kind version size
    vs = versify(protocol=proto, version=vrsn, kind=kind, size=size)
    # replace old version string in raw with new one
    raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
    if size != len(raw):  # substitution messed up
        raise ValueError("Malformed version string size = {}".format(vs))
    ked["v"] = vs  # update ked

    return raw, proto, kind, ked, vrsn




def dumps(ked, kind=Kinds.json):
    """
    utility function to handle serialization by kind

    Returns:
       raw (bytes): serialized version of ked dict

    Parameters:
       ked (Optional(dict, list)): key event dict or message dict to serialize
       kind (str): serialization kind (JSON, MGPK, CBOR)
    """
    if kind == Kinds.json:
        raw = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    elif kind == Kinds.mgpk:
        raw = msgpack.dumps(ked)

    elif kind == Kinds.cbor:
        raw = cbor.dumps(ked)
    else:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    return raw


def loads(raw, size=None, kind=Kinds.json):
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
    if kind == Kinds.json:
        try:
            ked = json.loads(raw[:size].decode("utf-8"))
        except Exception as ex:
            raise DeserializeError("Error deserializing JSON: {}"
                                       "".format(raw[:size].decode("utf-8")))

    elif kind == Kinds.mgpk:
        try:
            ked = msgpack.loads(raw[:size])
        except Exception as ex:
            raise DeserializeError("Error deserializing MGPK: {}"
                                       "".format(raw[:size]))

    elif kind == Kinds.cbor:
        try:
            ked = cbor.loads(raw[:size])
        except Exception as ex:
            raise DeserializeError("Error deserializing CBOR: {}"
                                       "".format(raw[:size]))

    else:
        raise DeserializeError("Invalid deserialization kind: {}"
                                   "".format(kind))

    return ked


# Deprecated
# randomNonce() refactored to match Salter().qb64 and only used in coring to avoid circular dependencies
# use Salter().qb64 in other places

def randomNonce():
    """ Generate a random 128 bits salt and encode as qb64

    Returns:
        str: qb64 encoded 128 bits random salt
    """
    preseed = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    seedqb64 = Matter(raw=preseed, code=MtrDex.Salt_128).qb64
    return seedqb64


# secret derivation security tier
Tierage = namedtuple("Tierage", 'low med high')

Tiers = Tierage(low='low', med='med', high='high')



@dataclass
class MapHood:
    """Base class for mutable dataclasses that support map syntax
    Adds support for dunder methods for map syntax dc[name].
    Converts exceptions from attribute syntax to raise map syntax when using
    map syntax.

    Enables dataclass instances to use Mapping item syntax
    """

    def __getitem__(self, name):
        try:
            return getattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __setitem__(self, name, value):
        try:
            return setattr(self, name, value)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __delitem__(self, name):
        try:
            return delattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


@dataclass(frozen=True)
class MapDom:
    """Base class for frozen dataclasses (codexes) that support map syntax
    Adds support for dunder methods for map syntax dc[name].
    Converts exceptions from attribute syntax to raise map syntax when using
    map syntax.

    Enables dataclass instances to use Mapping item syntax
    """

    def __getitem__(self, name):
        try:
            return getattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __setitem__(self, name, value):
        try:
            return setattr(self, name, value)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __delitem__(self, name):
        try:
            return delattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex





@dataclass(frozen=True)
class MatterCodex:
    """
    MatterCodex is codex code (stable) part of all matter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """

    Ed25519_Seed:         str = 'A'  # Ed25519 256 bit random seed for private key
    Ed25519N:             str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    X25519:               str = 'C'  # X25519 public encryption key, may be converted from Ed25519 or Ed25519N.
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
    X25519_Private:       str = 'O'  # X25519 private decryption key/seed, may be converted from Ed25519
    X25519_Cipher_Seed:   str = 'P'  # X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    ECDSA_256r1_Seed:     str = "Q"  # ECDSA secp256r1 256 bit random Seed for private key
    Tall:                 str = 'R'  # Tall 5 byte b2 number
    Large:                str = 'S'  # Large 11 byte b2 number
    Great:                str = 'T'  # Great 14 byte b2 number
    Vast:                 str = 'U'  # Vast 17 byte b2 number
    Label1:               str = 'V'  # Label1 1 bytes for label lead size 1
    Label2:               str = 'W'  # Label2 2 bytes for label lead size 0
    Tag3:                 str = 'X'  # Tag3  3 B64 encoded chars for special values
    Tag7:                 str = 'Y'  # Tag7  7 B64 encoded chars for special values
    Blind:                str = 'Z'  # Blinding factor 256 bits, Cryptographic strength deterministically generated from random salt
    Salt_128:             str = '0A'  # random salt/seed/nonce/private key or number of length 128 bits (Huge)
    Ed25519_Sig:          str = '0B'  # Ed25519 signature.
    ECDSA_256k1_Sig:      str = '0C'  # ECDSA secp256k1 signature.
    Blake3_512:           str = '0D'  # Blake3 512 bit digest self-addressing derivation.
    Blake2b_512:          str = '0E'  # Blake2b 512 bit digest self-addressing derivation.
    SHA3_512:             str = '0F'  # SHA3 512 bit digest self-addressing derivation.
    SHA2_512:             str = '0G'  # SHA2 512 bit digest self-addressing derivation.
    Long:                 str = '0H'  # Long 4 byte b2 number
    ECDSA_256r1_Sig:      str = '0I'  # ECDSA secp256r1 signature.
    Tag1:                 str = '0J'  # Tag1 1 B64 encoded char + 1 prepad for special values
    Tag2:                 str = '0K'  # Tag2 2 B64 encoded chars for for special values
    Tag5:                 str = '0L'  # Tag5 5 B64 encoded chars + 1 prepad for special values
    Tag6:                 str = '0M'  # Tag6 6 B64 encoded chars for special values
    Tag9:                 str = '0N'  # Tag9 9 B64 encoded chars + 1 prepad for special values
    Tag10:                str = '0O'  # Tag10 10 B64 encoded chars for special values
    ECDSA_256k1N:         str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:          str = '1AAB'  # ECDSA public verification or encryption key, basic derivation
    Ed448N:               str = '1AAC'  # Ed448 non-transferable prefix public signing verification key. Basic derivation.
    Ed448:                str = '1AAD'  # Ed448 public signing verification key. Basic derivation.
    Ed448_Sig:            str = '1AAE'  # Ed448 signature. Self-signing derivation.
    Tag4:                 str = '1AAF'  # Tag4 4 B64 encoded chars for special values
    DateTime:             str = '1AAG'  # Base64 custom encoded 32 char ISO-8601 DateTime
    X25519_Cipher_Salt:   str = '1AAH'  # X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    ECDSA_256r1N:         str = '1AAI'  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:          str = '1AAJ'  # ECDSA secp256r1 verification or encryption key, basic derivation
    Null:                 str = '1AAK'  # Null None or empty value
    No:                   str = '1AAL'  # No Falsey Boolean value
    Yes:                  str = '1AAM'  # Yes Truthy Boolean value
    Tag8:                 str = '1AAN'  # Tag8 8 B64 encoded chars for special values
    TBD0S:                str = '1__-'  # Testing purposes only, fixed special values with non-empty raw lead size 0
    TBD0:                 str = '1___'  # Testing purposes only, fixed with lead size 0
    TBD1S:                str = '2__-'  # Testing purposes only, fixed special values with non-empty raw lead size 1
    TBD1:                 str = '2___'  # Testing purposes only, fixed with lead size 1
    TBD2S:                str = '3__-'  # Testing purposes only, fixed special values with non-empty raw lead size 2
    TBD2:                 str = '3___'  # Testing purposes only, fixed with lead size 2
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
    X25519_Cipher_L0:     str = '4C'  # X25519 sealed box cipher bytes of sniffable stream plaintext lead size 0
    X25519_Cipher_L1:     str = '5C'  # X25519 sealed box cipher bytes of sniffable stream plaintext lead size 1
    X25519_Cipher_L2:     str = '6C'  # X25519 sealed box cipher bytes of sniffable stream plaintext lead size 2
    X25519_Cipher_Big_L0: str = '7AAC'  # X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 0
    X25519_Cipher_Big_L1: str = '8AAC'  # X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 1
    X25519_Cipher_Big_L2: str = '9AAC'  # X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 2
    X25519_Cipher_QB64_L0:     str = '4D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    X25519_Cipher_QB64_L1:     str = '5D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    X25519_Cipher_QB64_L2:     str = '6D'  # X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    X25519_Cipher_QB64_Big_L0: str = '7AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    X25519_Cipher_QB64_Big_L1: str = '8AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    X25519_Cipher_QB64_Big_L2: str = '9AAD'  # X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    X25519_Cipher_QB2_L0:     str = '4E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    X25519_Cipher_QB2_L1:     str = '5E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    X25519_Cipher_QB2_L2:     str = '6E'  # X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    X25519_Cipher_QB2_Big_L0: str = '7AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    X25519_Cipher_QB2_Big_L1: str = '8AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    X25519_Cipher_QB2_Big_L2: str = '9AAE'  # X25519 sealed box cipher bytes of QB2 plaintext big lead size 2


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
    Tall:    str = 'R'  # Tall 5 byte b2 number
    Big:     str = 'N'  # Big 8 byte b2 number
    Large:   str = 'S'  # Large 11 byte b2 number
    Great:   str = 'T'  # Great 14 byte b2 number
    Huge:    str = '0A'  # Huge 16 byte b2 number (same as Salt_128)
    Vast:    str = 'U'  # Vast 17 byte b2 number

    def __iter__(self):
        return iter(astuple(self))


NumDex = NumCodex()  # Make instance


@dataclass(frozen=True)
class TagCodex:
    """
    TagCodex is codex of Base64 derivation codes for compactly representing
    various small Base64 tag values as special code soft part values.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Tag1:  str = '0J'  # 1 B64 char tag with 1 pre pad
    Tag2:  str = '0K'  # 2 B64 char tag
    Tag3:  str = 'X'  # 3 B64 char tag
    Tag4:  str = '1AAF'  # 4 B64 char tag
    Tag5:  str = '0L'  # 5 B64 char tag with 1 pre pad
    Tag6:  str = '0M'  # 6 B64 char tag
    Tag7:  str = 'Y'  # 7 B64 char tag
    Tag8:  str = '1AAN'  # 8 B64 char tag
    Tag9:  str = '0N'  # 9 B64 char tag with 1 pre pad
    Tag10: str = '0O'  # 10 B64 char tag

    def __iter__(self):
        return iter(astuple(self))


TagDex = TagCodex()  # Make instance


@dataclass(frozen=True)
class LabelCodex:
    """
    LabelCodex is codex of.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Tag1:  str = '0J'  # 1 B64 char tag with 1 pre pad
    Tag2:  str = '0K'  # 2 B64 char tag
    Tag3:  str = 'X'  # 3 B64 char tag
    Tag4:  str = '1AAF'  # 4 B64 char tag
    Tag5:  str = '0L'  # 5 B64 char tag with 1 pre pad
    Tag6:  str = '0M'  # 6 B64 char tag
    Tag7:  str = 'Y'  # 7 B64 char tag
    Tag8:  str = '1AAN'  # 8 B64 char tag
    Tag9:  str = '0N'  # 9 B64 char tag with 1 pre pad
    Tag10: str = '0O'  # 10 B64 char tag
    StrB64_L0:     str = '4A'  # String Base64 Only Leader Size 0
    StrB64_L1:     str = '5A'  # String Base64 Only Leader Size 1
    StrB64_L2:     str = '6A'  # String Base64 Only Leader Size 2
    StrB64_Big_L0: str = '7AAA'  # String Base64 Only Big Leader Size 0
    StrB64_Big_L1: str = '8AAA'  # String Base64 Only Big Leader Size 1
    StrB64_Big_L2: str = '9AAA'  # String Base64 Only Big Leader Size 2
    Label1:        str = 'V'  # Label1 1 bytes for label lead size 1
    Label2:        str = 'W'  # Label2 2 bytes for label lead size 0
    Bytes_L0:     str = '4B'  # Byte String lead size 0
    Bytes_L1:     str = '5B'  # Byte String lead size 1
    Bytes_L2:     str = '6B'  # Byte String lead size 2
    Bytes_Big_L0: str = '7AAB'  # Byte String big lead size 0
    Bytes_Big_L1: str = '8AAB'  # Byte String big lead size 1
    Bytes_Big_L2: str = '9AAB'  # Byte String big lead size 2

    def __iter__(self):
        return iter(astuple(self))


LabelDex = LabelCodex()  # Make instance



@dataclass(frozen=True)
class PreCodex:
    """
    PreCodex is codex all identifier prefix derivation codes.
    This is needed to verify valid inception events.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N:      str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    Ed25519:       str = 'D'  # Ed25519 verification key, basic derivation.
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
    Ed448N:        str = '1AAC'  # Ed448 verification key non-transferable, basic derivation.
    Ed448:         str = '1AAD'  # Ed448 verification key, basic derivation.
    Ed448_Sig:     str = '1AAE'  # Ed448 signature. Self-signing derivation.
    ECDSA_256r1N:  str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:   str = "1AAJ"  # ECDSA secp256r1 verification or encryption key, basic derivation

    def __iter__(self):
        return iter(astuple(self))


PreDex = PreCodex()  # Make instance


@dataclass(frozen=True)
class NonTransCodex:
    """
    NonTransCodex is codex all non-transferable derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N: str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    ECDSA_256k1N: str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    Ed448N: str = '1AAC'  # Ed448 verification key non-transferable, basic derivation.
    ECDSA_256r1N: str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.

    def __iter__(self):
        return iter(astuple(self))


NonTransDex = NonTransCodex()  # Make instance


@dataclass(frozen=True)
class PreNonDigCodex:
    """
    PreNonDigCodex is codex all prefixive but non-digestive derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519N:      str = 'B'  # Ed25519 verification key non-transferable, basic derivation.
    Ed25519:       str = 'D'  # Ed25519 verification key, basic derivation.
    ECDSA_256k1N:  str = '1AAA'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:   str = '1AAB'  # ECDSA public verification or encryption key, basic derivation
    Ed448N:        str = '1AAC'  # Ed448 verification key non-transferable, basic derivation.
    Ed448:         str = '1AAD'  # Ed448 verification key, basic derivation.
    ECDSA_256r1N:  str = "1AAI"  # ECDSA secp256r1 verification key non-transferable, basic derivation.
    ECDSA_256r1:   str = "1AAJ"  # ECDSA secp256r1 verification or encryption key, basic derivation

    def __iter__(self):
        return iter(astuple(self))


PreNonDigDex = PreNonDigCodex()  # Make instance




# namedtuple for size entries in Matter  and Counter derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# xs is the xtra size into number of xtra (pre-pad) chars as part of soft
# fs is the full size int number of chars in code plus appended material if any
# ls is the lead size int number of bytes to pre-pad pre-converted raw binary
Sizage = namedtuple("Sizage", "hs ss xs fs ls")


class Matter:
    """
    Matter is fully qualified cryptographic material primitive base class for
    non-indexed primitives.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Class Attributes:
        Codex (MatterCodex):  MtrDex
        Hards (dict): hard sizes keyed by qb64 selector
        Bards (dict): hard size keyed by qb2 selector
        Sizes (dict): sizes tables for codes
        Codes (dict): maps code name to code
        Names (dict): maps code to code name
        Pad (str): B64 pad char for xtra size pre-padded soft values

    Class Methods:


    Attributes:

    Properties:
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str | bytes): soft part of full code exclusive of xs xtra prepad.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip

    Hidden:
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)


    Special soft values are indicated when fn in table is None and ss > 0.

    """
    Codex = MtrDex  # class variable holding MatterDex reference

    # Hards table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always 0 for Matter
    # unless fs is None which allows for variable size multiple of 4, i.e.
    # not (hs + ss) % 4.
    Hards = ({chr(c): 1 for c in range(65, 65 + 26)})  # size of hard part of code
    Hards.update({chr(c): 1 for c in range(97, 97 + 26)})
    Hards.update([('0', 2), ('1', 4), ('2', 4), ('3', 4), ('4', 2), ('5', 2),
                  ('6', 2), ('7', 4), ('8', 4), ('9', 4)])


    # Bards table maps first code char. converted to binary sextext of hard size,
    # hs. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    # Sizes table maps from value of hs chars of code to Sizage namedtuple of
    # (hs, ss, xs, fs, ls) where hs is hard size, ss is soft size,
    # xs is extra size of soft, fs is full size, and ls is lead size of raw.
    Sizes = {
        'A': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'B': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'C': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'D': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'E': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'F': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'G': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'H': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'I': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'J': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'K': Sizage(hs=1, ss=0, xs=0, fs=76, ls=0),
        'L': Sizage(hs=1, ss=0, xs=0, fs=76, ls=0),
        'M': Sizage(hs=1, ss=0, xs=0, fs=4, ls=0),
        'N': Sizage(hs=1, ss=0, xs=0, fs=12, ls=0),
        'O': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'P': Sizage(hs=1, ss=0, xs=0, fs=124, ls=0),
        'Q': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        'R': Sizage(hs=1, ss=0, xs=0, fs=8, ls=0),
        'S': Sizage(hs=1, ss=0, xs=0, fs=16, ls=0),
        'T': Sizage(hs=1, ss=0, xs=0, fs=20, ls=0),
        'U': Sizage(hs=1, ss=0, xs=0, fs=24, ls=0),
        'V': Sizage(hs=1, ss=0, xs=0, fs=4, ls=1),
        'W': Sizage(hs=1, ss=0, xs=0, fs=4, ls=0),
        'X': Sizage(hs=1, ss=3, xs=0, fs=4, ls=0),
        'Y': Sizage(hs=1, ss=7, xs=0, fs=8, ls=0),
        'Z': Sizage(hs=1, ss=0, xs=0, fs=44, ls=0),
        '0A': Sizage(hs=2, ss=0, xs=0, fs=24, ls=0),
        '0B': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0C': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0D': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0E': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0F': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0G': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0H': Sizage(hs=2, ss=0, xs=0, fs=8, ls=0),
        '0I': Sizage(hs=2, ss=0, xs=0, fs=88, ls=0),
        '0J': Sizage(hs=2, ss=2, xs=1, fs=4, ls=0),
        '0K': Sizage(hs=2, ss=2, xs=0, fs=4, ls=0),
        '0L': Sizage(hs=2, ss=6, xs=1, fs=8, ls=0),
        '0M': Sizage(hs=2, ss=6, xs=0, fs=8, ls=0),
        '0N': Sizage(hs=2, ss=10, xs=1, fs=12, ls=0),
        '0O': Sizage(hs=2, ss=10, xs=0, fs=12, ls=0),
        '1AAA': Sizage(hs=4, ss=0, xs=0, fs=48, ls=0),
        '1AAB': Sizage(hs=4, ss=0, xs=0, fs=48, ls=0),
        '1AAC': Sizage(hs=4, ss=0, xs=0, fs=80, ls=0),
        '1AAD': Sizage(hs=4, ss=0, xs=0, fs=80, ls=0),
        '1AAE': Sizage(hs=4, ss=0, xs=0, fs=56, ls=0),
        '1AAF': Sizage(hs=4, ss=4, xs=0, fs=8, ls=0),
        '1AAG': Sizage(hs=4, ss=0, xs=0, fs=36, ls=0),
        '1AAH': Sizage(hs=4, ss=0, xs=0, fs=100, ls=0),
        '1AAI': Sizage(hs=4, ss=0, xs=0, fs=48, ls=0),
        '1AAJ': Sizage(hs=4, ss=0, xs=0, fs=48, ls=0),
        '1AAK': Sizage(hs=4, ss=0, xs=0, fs=4, ls=0),
        '1AAL': Sizage(hs=4, ss=0, xs=0, fs=4, ls=0),
        '1AAM': Sizage(hs=4, ss=0, xs=0, fs=4, ls=0),
        '1AAN': Sizage(hs=4, ss=8, xs=0, fs=12, ls=0),
        '1__-': Sizage(hs=4, ss=2, xs=0, fs=12, ls=0),
        '1___': Sizage(hs=4, ss=0, xs=0, fs=8, ls=0),
        '2__-': Sizage(hs=4, ss=2, xs=1, fs=12, ls=1),
        '2___': Sizage(hs=4, ss=0, xs=0, fs=8, ls=1),
        '3__-': Sizage(hs=4, ss=2, xs=0, fs=12, ls=2),
        '3___': Sizage(hs=4, ss=0, xs=0, fs=8, ls=2),
        '4A': Sizage(hs=2, ss=2, xs=0, fs=None, ls=0),
        '5A': Sizage(hs=2, ss=2, xs=0, fs=None, ls=1),
        '6A': Sizage(hs=2, ss=2, xs=0, fs=None, ls=2),
        '7AAA': Sizage(hs=4, ss=4, xs=0, fs=None, ls=0),
        '8AAA': Sizage(hs=4, ss=4, xs=0, fs=None, ls=1),
        '9AAA': Sizage(hs=4, ss=4, xs=0, fs=None, ls=2),
        '4B': Sizage(hs=2, ss=2, xs=0, fs=None, ls=0),
        '5B': Sizage(hs=2, ss=2, xs=0, fs=None, ls=1),
        '6B': Sizage(hs=2, ss=2, xs=0, fs=None, ls=2),
        '7AAB': Sizage(hs=4, ss=4, xs=0, fs=None, ls=0),
        '8AAB': Sizage(hs=4, ss=4, xs=0, fs=None, ls=1),
        '9AAB': Sizage(hs=4, ss=4, xs=0, fs=None, ls=2),
        '4C': Sizage(hs=2, ss=2, xs=0, fs=None, ls=0),
        '5C': Sizage(hs=2, ss=2, xs=0, fs=None, ls=1),
        '6C': Sizage(hs=2, ss=2, xs=0, fs=None, ls=2),
        '7AAC': Sizage(hs=4, ss=4, xs=0, fs=None, ls=0),
        '8AAC': Sizage(hs=4, ss=4, xs=0, fs=None, ls=1),
        '9AAC': Sizage(hs=4, ss=4, xs=0, fs=None, ls=2),
        '4D': Sizage(hs=2, ss=2, xs=0, fs=None, ls=0),
        '5D': Sizage(hs=2, ss=2, xs=0, fs=None, ls=1),
        '6D': Sizage(hs=2, ss=2, xs=0, fs=None, ls=2),
        '7AAD': Sizage(hs=4, ss=4, xs=0, fs=None, ls=0),
        '8AAD': Sizage(hs=4, ss=4, xs=0, fs=None, ls=1),
        '9AAD': Sizage(hs=4, ss=4, xs=0, fs=None, ls=2),
        '4E': Sizage(hs=2, ss=2, xs=0, fs=None, ls=0),
        '5E': Sizage(hs=2, ss=2, xs=0, fs=None, ls=1),
        '6E': Sizage(hs=2, ss=2, xs=0, fs=None, ls=2),
        '7AAE': Sizage(hs=4, ss=4, xs=0, fs=None, ls=0),
        '8AAE': Sizage(hs=4, ss=4, xs=0, fs=None, ls=1),
        '9AAE': Sizage(hs=4, ss=4, xs=0, fs=None, ls=2),
    }

    Codes = asdict(MtrDex)  # map code name to code
    Names = {val : key for key, val in Codes.items()} # invert map code to code name
    Pad = '_'  # B64 pad char for special codes with xtra size pre-padded soft values


    def __init__(self, raw=None, code=MtrDex.Ed25519N, soft='', rize=None,
                 qb64b=None, qb64=None, qb2=None, strip=False, **kwa):
        """
        Validate as fully qualified
        Parameters:
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part exclusive of prepad for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (str | bytes | bytearray | memoryview | None): fully qualified
                crypto material Base64. When str, encodes as utf-8. Strips when
                bytearray and strip is True.
            qb64 (str | bytes | bytearray | memoryview | None):  fully qualified
                crypto material Base64. When str, encodes as utf-8. Ignores strip
            qb2 (bytes | bytearray | memoryview | None): fully qualified crypto
                material Base2. Strips when bytearray and strip is True.
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip


        Needs either (raw and code and optionally rsize)
               or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code and optional rsize provided
            then validate that code is correct for length of raw, rsize,
            computed size from Sizes and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign
            .raw and .code and .size and .rsize

        """
        if hasattr(soft, "decode"):  # make soft str
            soft = soft.decode("utf-8")

        if raw is not None:  # raw provided but may be empty
            if not code:
                raise EmptyMaterialError(f"Improper initialization need either "
                                         f"(raw not None and code) or "
                                         f"(code and soft) or "
                                         f"qb64b or qb64 or qb2.")

            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError(f"Not a bytes or bytearray {raw=}.")

            if code not in self.Sizes:
                raise InvalidCodeError(f"Unsupported {code=}.")

            hs, ss, xs, fs, ls = self.Sizes[code]  # assumes unit tests force valid sizes

            if fs is None:  # variable sized assumes code[0] in SmallVrzDex or LargeVrzDex
                # assumes xs must be 0 when variable sized
                if rize:  # use rsize to determine length of raw to extract
                    if rize < 0:
                        raise InvalidVarRawSizeError(f"Missing var raw size for "
                                                     f"code={code}.")
                else:  # use length of provided raw as rize
                    rize = len(raw)

                ls = (3 - (rize % 3)) % 3  # calc actual lead (pad) size
                # raw binary size including leader in bytes
                size = (rize + ls) // 3  # calculate value of size in triplets

                if code[0] in SmallVrzDex:  # compute code with sizes
                    if size <= (64 ** 2 - 1):  # ss = 2
                        hs = 2
                        s = astuple(SmallVrzDex)[ls]
                        code = f"{s}{code[1:hs]}"
                        ss = 2
                    elif size <= (64 ** 4 - 1):  # ss = 4 make big version of code
                        hs = 4
                        s = astuple(LargeVrzDex)[ls]
                        code = f"{s}{'A' * (hs - 2)}{code[1]}"
                        soft = intToB64(size, 4)
                        ss = 4
                    else:
                        raise InvalidVarRawSizeError(f"Unsupported raw size for "
                                                     f"{code=}.")
                elif code[0] in LargeVrzDex:  # compute code with sizes
                    if size <= (64 ** 4 - 1):  # ss = 4
                        hs = 4
                        s = astuple(LargeVrzDex)[ls]
                        code = f"{s}{code[1:hs]}"
                        ss = 4
                    else:
                        raise InvalidVarRawSizeError(f"Unsupported raw size for large "
                                                     f"{code=}. {size} <= {64 ** 4 - 1}")
                else:
                    raise InvalidVarRawSizeError(f"Unsupported variable raw size "
                                                 f"{code=}.")
                soft = intToB64(size, ss)

            else:  # fixed size but raw may be empty and/or special soft
                rize = Matter._rawSize(code)  # get raw size from Sizes for code
                # if raw then ls may be nonzero

                if ss > 0: # special soft size, so soft must be provided
                    soft = soft[:ss-xs]  #
                    if len(soft) != ss - xs:
                        raise SoftMaterialError(f"Not enough chars in {soft=} "
                                                 f"with {ss=} {xs=} for {code=}.")

                    if not Reb64.match(soft.encode("utf-8")):
                        raise InvalidSoftError(f"Non Base64 chars in {soft=}.")
                else:
                    soft = ''  # must be empty when ss == 0


            raw = raw[:rize]  # copy only exact size from raw stream
            if len(raw) != rize:  # forbids shorter
                raise RawMaterialError(f"Not enougth raw bytes for code={code}"
                                       f"expected {rize=} got {len(raw)}.")

            self._code = code  # str hard part of full code
            self._soft = soft  # str soft part of full code exclusive of xs prepad, empty when ss=0
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif soft and code:  # raw None so ls == 0 with fixed size and special
            hs, ss, xs, fs, ls = self.Sizes[code]  # assumes unit tests force valid sizes
            if not fs:  # variable sized code so can't be special soft
                raise InvalidSoftError(f"Unsupported variable sized {code=} "
                                       f" with {fs=} for special {soft=}.")

            if not ss > 0 or (fs == hs + ss and not ls == 0):  # not special soft
                raise InvalidSoftError("Invalid soft size={ss} or lead={ls} "
                                       f" or {code=} {fs=} when special soft.")

            soft = soft[:ss-xs]
            if len(soft) != ss - xs:
                raise SoftMaterialError(f"Not enough chars in {soft=} "
                                         f"with {ss=} {xs=} for {code=}.")

            if not Reb64.match(soft.encode("utf-8")):
                raise InvalidSoftError(f"Non Base64 chars in {soft=}.")

            self._code = code  # str hard part of code
            self._soft = soft  # str soft part of code, empty when ss=0
            self._raw = b''  # force raw empty when None given and special soft

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
                                         f"(raw not None and code) or "
                                         f"(code and soft) or "
                                         f"qb64b or qb64 or qb2.")


    @classmethod
    def _rawSize(cls, code):
        """
        Returns raw size in bytes not including leader for a given code
        Parameters:
            code (str): derivation code Base64
        """
        hs, ss, xs, fs, ls = cls.Sizes[code]  # get sizes
        cs = hs + ss  # both hard + soft code size
        if fs is None:
            raise InvalidCodeSizeError(f"Non-fixed raw size code {code}.")
        # assumes .Sizes only has valid entries, cs % 4 != 3, and fs % 4 == 0
        return (((fs - cs) * 3 // 4) - ls)


    @classmethod
    def _leadSize(cls, code):
        """
        Returns lead size in bytes for a given code
        Parameters:
            code (str): derivation code Base64
        """
        _, _, _, _, ls = cls.Sizes[code]  # get lead size from .Sizes table
        return ls

    @classmethod
    def _xtraSize(cls, code):
        """
        Returns xtra size in bytes for a given code
        Parameters:
            code (str): derivation code Base64
        """
        _, _, xs, _, _ = cls.Sizes[code]  # get lead size from .Sizes table
        return xs


    @classmethod
    def _special(cls, code):
        """
        Returns:
            special (bool): True when code has special soft i.e. when
                    fs is not None and ss > 0
                False otherwise

        """
        hs, ss, xs, fs, ls = cls.Sizes[code]

        return (fs is not None and ss > 0)


    @property
    def code(self):
        """
        Returns:
            code (str): hard part only of full text code.

        Getter for ._code. Makes ._code read only

        Some codes only have a hard part. Soft part may be for variable sized
        matter or for special codes that are code only (raw is empty)
        """
        return self._code


    @property
    def name(self):
        """
        Returns:
            name (str): code name for self.code. Used for annotation for
            primitives like Matter

        """
        return self.Names[self.code]


    @property
    def hard(self):
        """
        Returns:
            hard (str): hard part only of full text code. Alias for .code.

        """
        return self.code


    @property
    def soft(self):
        """
        Returns:
            soft (str): soft part only of full text code.

        Getter for ._soft. Make ._soft read only
        """
        return self._soft


    @property
    def size(self):
        """
        Returns:
            size(int | None): Number of variably sized b64 quadlets/b2 triplets
                                in primitive when varibly sized
                              None when not variably sized when (fs!=None)

        Number of quadlets/triplets of chars/bytes of variable sized material or
        None when not variably sized.

        Converted qb64 value to int of soft ss portion of full text code
        when variably sized primitive material (fs == None).
        """
        return (b64ToInt(self.soft) if self.soft else None)


    @property
    def both(self):
        """
        Returns:
            both (str):  hard + soft parts of full text code
        """
        #_, ss, _, _ = self.Sizes[self.code]

        #if self.size is not None:
            #return (f"{self.code}{intToB64(self.size, l=ss)}")
        #else:
            #return (f"{self.code}{self.soft}")

        _, _, xs, _, _ = self.Sizes[self.code]

        return (f"{self.code}{self.Pad * xs}{self.soft}")


    @property
    def fullSize(self):
        """
        Returns full size of matter in bytes
        Fixed size codes returns fs from .Sizes
        Variable size codes where fs==None computes fs from .size and sizes
        """
        hs, ss, _, fs, _ = self.Sizes[self.code]  # get sizes

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


    @property
    def special(self):
        """
        special (bool): True when self.code has special self.soft i.e. when
                    fs is not None and ss > 0  and fs = hs + ss and ls = 0
                    i.e. (fs fixed and soft not empty and raw is empty and no lead)
                False otherwise
        """
        return self._special(self.code)

    @property
    def composable(self):
        """
        composable (bool): True when both .qb64b and .qb2 are 24 bit aligned and
                           round trip using encodeB64 and decodeB64.
                           False otherwise
        """
        qb64b = self.qb64b
        qb2 = self.qb2
        return (len(qb64b) % 4 == 0 and len(qb2) % 3 == 0 and
                encodeB64(qb2) == qb64b and decodeB64(qb64b) == qb2)


    def _infil(self):
        """
        Create text domain representation

        Returns:
            primitive (bytes): fully qualified base64 characters.
        """
        code = self.code  # hard part of full code == codex value
        both = self.both  # code + soft, soft may be empty
        raw = self.raw  # bytes or bytearray, raw may be empty
        rs = len(raw)  # raw size
        hs, ss, xs, fs, ls = self.Sizes[code]
        cs = hs + ss
        # assumes unit tests on Matter.Sizes ensure valid size entries

        if cs != len(both):
            InvalidCodeSizeError(f"Invalid full code={both} for sizes {hs=} and"
                                f" {ss=}.")

        if not fs:  # variable sized
            # Tests on .Sizes table must ensure ls in (0,1,2) and cs % 4 == 0 but
            # can't know the variable size. So instance methods must ensure that
            # (ls + rs) % 3 == 0 i.e. both full code (B64) and lead+raw (B2)
            # are both 24 bit aligned.
            # If so then should not need following check.
            if (ls + rs) % 3 or cs % 4:
                raise InvalidCodeSizeError(f"Invalid full code{both=} with "
                                           f"variable raw size={rs} given "
                                           f" {cs=}, {hs=}, {ss=}, {fs=}, and "
                                           f"{ls=}.")

            # When ls+rs is 24 bit aligned then encodeB64 has no trailing
            # pad chars that need to be stripped. So simply prepad raw with
            # ls zero bytes and convert (encodeB64).
            full = (both.encode("utf-8") + encodeB64(bytes([0] * ls) + raw))

        else:  # fixed size
            ps = (3 - ((rs + ls) % 3)) % 3  # net pad size given raw with lead
            # net pad size must equal both code size remainder so that primitive
            # both + converted padded raw is fs long. Assumes ls in (0,1,2) and
            # cs % 4 != 3, fs % 4 == 0. Sizes table test must ensure these properties.
            # If so then should not need following check.
            if ps != (cs % 4):  # given cs % 4 != 3 then cs % 4 is pad size
                raise InvalidCodeSizeError(f"Invalid full code{both=} with "
                                           f"fixed raw size={rs} given "
                                           f" {cs=}, {hs=}, {ss=}, {fs=}, and "
                                           f"{ls=}.")

            # Predpad raw so we midpad the full primitive. Prepad with ps+ls
            # zero bytes ensures encodeB64 of prepad+lead+raw has no trailing
            # pad characters. Finally skip first ps == cs % 4 of the converted
            # characters to ensure that when full code is prepended, the full
            # primitive size is fs but midpad bits are zeros.
            full = (both.encode("utf-8") + encodeB64(bytes([0] * (ps + ls)) + raw)[ps:])

        if (len(full) % 4) or (fs and len(full) != fs):
            raise InvalidCodeSizeError(f"Invalid full size given code{both=} "
                                       f" with raw size={rs}, {cs=}, {hs=}, "
                                       f"{ss=}, {xs=} {fs=}, and {ls=}.")

        return full


    def _binfil(self):
        """
        Create binary domain representation

        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 + self.raw left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # hard part of full code == codex value
        both = self.both  # code + soft, soft may be empty
        raw = self.raw  # bytes or bytearray may be empty

        hs, ss, xs, fs, ls = self.Sizes[code]
        cs = hs + ss
        # assumes unit tests on Matter.Sizes ensure valid size entries
        n = sceil(cs * 3 / 4)  # number of b2 bytes to hold b64 code
        # convert code both to right align b2 int then left shift in pad bits
        # then convert to bytes
        bcode = (b64ToInt(both) << (2 * (cs % 4))).to_bytes(n, 'big')
        full = bcode + bytes([0] * ls) + raw  # includes lead bytes

        bfs = len(full)
        if not fs:  # compute fs
            fs = hs + ss + (len(raw) + ls) * 4 // 3 # hs + ss + (size * 4)
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid full code={both} for raw size"
                                       f"={len(raw)}.")
        return full


    def _exfil(self, qb64b):
        """
        Extracts self.code and self.raw from qualified base64 qb64b of type
        str or bytes or bytearray or memoryview

        Detects if str and converts to bytes

        Parameters:
            qb64b (str | bytes | bytearray | memoryview): fully qualified base64 from stream

        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material.")

        first = qb64b[:1]  # extract first char code selector
        if isinstance(first, memoryview):
            first = bytes(first)
        if hasattr(first, "decode"):
            first = first.decode()  # converts bytes/bytearray to str
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
        if isinstance(hard, memoryview):
            hard = bytes(hard)
        if hasattr(hard, "decode"):
            hard = hard.decode()  # converts bytes/bytearray to str
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, xs, fs, ls = self.Sizes[hard]  # assumes hs in both tables match
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Matter .Sizes .Hards and .Bards ensure that
        # these are well formed.
        # when fs is None then ss > 0 otherwise fs > hs + ss when ss > 0


        # extract soft chars including xtra, empty when ss==0 and xs == 0
        # assumes that when ss == 0 then xs must be 0
        soft = qb64b[hs:hs+ss]
        if isinstance(soft, memoryview):
            soft = bytes(soft)
        if hasattr(soft, "decode"):
            soft = soft.decode()  # converts bytes/bytearray to str
        xtra = soft[:xs]  # extract xtra if any from front of soft
        soft = soft[xs:]  # strip xtra from soft
        if xtra != f"{self.Pad * xs}":
            raise UnexpectedCodeError(f"Invalid prepad xtra ={xtra}.")

        if not fs:  # compute fs from soft from ss part which provides size B64
            # compute variable size as int may have value 0
            fs = (b64ToInt(soft) * 4) + cs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError(f"Need {fs - len(qb64b)} more chars.")

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if isinstance(qb64b, memoryview):
            qb64b = bytes(qb64b)
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode()  # converts str to bytes

        # check for non-zeroed pad bits and/or lead bytes
        # net prepad ps == cs % 4 (remainer).  Assumes ps != 3 i.e ps in (0,1,2)
        # To ensure number of prepad bytes and prepad chars are same.
        # need net prepad chars ps to invert using decodeB64 of lead + raw

        ps = cs % 4  # net prepad bytes to ensure 24 bit align when encodeB64
        base =  ps * b'A' + qb64b[cs:]  # prepad ps 'A's to  B64 of (lead + raw)
        paw = decodeB64(base)  # now should have ps + ls leading sextexts of zeros
        raw = paw[ps+ls:]  # remove prepad midpat bytes to invert back to raw
        # ensure midpad bytes are zero
        pi = int.from_bytes(paw[:ps+ls], "big")
        if pi != 0:
            raise ConversionError(f"Nonzero midpad bytes=0x{pi:0{(ps + ls) * 2}x}.")

        if len(raw) != ((len(qb64b) - cs) * 3 // 4) - ls:  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb64b}")

        self._code = hard  # hard only str
        self._soft = soft  # soft only str
        self._raw = raw  # ensure bytes for crypto ops, may be empty


    def _bexfil(self, qb2):
        """
        Extracts self.code and self.raw from qualified base2 qb2

        Parameters:
            qb2 (bytes | bytearray | memoryview): fully qualified base2 from stream
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

        hs, ss, xs, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Matter .Sizes .Hards and .Bards ensure that
        # these are well formed.
        # when fs is None then ss > 0 otherwise fs > hs + ss when ss > 0

        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code

        # extract soft chars including xtra, empty when ss==0 and xs == 0
        # assumes that when ss == 0 then xs must be 0
        soft = both[hs:hs+ss]  # get soft may be empty
        xtra = soft[:xs]  # extract xtra if any from front of soft
        soft = soft[xs:]  # strip xtra from soft
        if xtra != f"{self.Pad * xs}":
            raise UnexpectedCodeError(f"Invalid prepad xtra ={xtra}.")

        if not fs:  # compute fs from size chars in ss part of code
            if len(qb2) < bcs:  # need more bytes
                raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

            # compute size as int from soft part given by ss B64 chars
            fs = (b64ToInt(soft) * 4) + cs  # compute fs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))

        qb2 = qb2[:bfs]  # extract qb2 fully qualified primitive code plus material

        # check for nonzero trailing full code mid pad bits
        ps = cs % 4  # full code (both) net pad size for 24 bit alignment
        pbs = 2 * ps  # mid pad bits = 2 per net pad
        # get pad bits in last byte of full code
        pi = (int.from_bytes(qb2[bcs-1:bcs], "big")) # convert byte to int
        pi = pi & (2 ** pbs - 1 ) # mask with 1's in pad bit locations
        if pi:  # not zero so raise error
            raise ConversionError(f"Nonzero code mid pad bits=0b{pi:0{pbs}b}.")

        # check nonzero leading mid pad lead bytes in lead + raw
        li = int.from_bytes(qb2[bcs:bcs+ls], "big")  # lead as int
        if li:  # midpad lead bytes must be zero
            raise ConversionError(f"Nonzero lead midpad bytes=0x{li:0{ls*2}x}.")

        # strip code and leader bytes from qb2 to get raw
        raw = qb2[(bcs + ls):]  # may be empty

        if len(raw) != (len(qb2) - bcs - ls):  # exact lengths
            raise ConversionError(r"Improperly qualified material = {qb2}")

        self._code = hard  # hard only
        self._soft = soft  # soft only may be empty
        self._raw = bytes(raw)  # ensure bytes for crypto ops may be empty


class Seqner(Matter):
    """
    Seqner is subclass of Matter, cryptographic material, for fully qualified
    fixed serialization sized ordinal numbers such as sequence numbers or
    first seen numbers.

    The serialization is forced to a fixed size (single code) so that it may be
    used  for lexocographically ordered namespaces such as database indices.
    That code is MtrDex.Salt_128

    Default initialization code = MtrDex.Salt_128
    Raises error on init if code is not MtrDex.Salt_128

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
            sn (int | str | None): some form of ordinal number int or hex str
            snh (str | None): hex string of ordinal number

        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            try:
                if sn is None:
                    if snh is None or snh == '':
                        sn = 0
                    else:
                        sn = int(snh, 16)

                else:  # sn is not None but so may be hex str
                    if isinstance(sn, str):  # is it a hex str
                        if sn == '':
                            sn = 0
                        else:
                            sn = int(sn, 16)
            except ValueError as ex:
                raise InvalidValueError(f"Not whole number={sn} .") from ex

            if not isinstance(sn, int) or sn < 0:
                raise InvalidValueError(f"Not whole number={sn}.")

            if sn > MaxON:  # too big for ordinal 256 ** 16 - 1
                raise ValidationError(f"Non-ordinal {sn} exceeds {MaxON}.")

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
        sn (int): alias for num
        snh (str): alias for numh
        huge (str): qb64 of num but with code NumDex.Huge so 24 char compatible
                    with fixed size seq num for lexicographic lmdb key space
        positive (bool): True if .num  > 0, False otherwise. Because .num must be
                         non-negative, .positive == False means .num == 0
        inceptive (bool): True means .num == 0 False otherwise.


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
    Codes = asdict(NumDex)  # map code name to code
    Names = {val : key for key, val in Codes.items()} # invert map code to code name



    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None,
                 code=None, num=None, numh=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw (bytes): unqualified crypto material usable for crypto operations
            code (str | None): stable (hard) part of derivation code.
                               None means pick code based on value of num or numh
                               otherwise raise error
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
                        num = int(numh, 16)

                else:  # handle case where num is hex str'
                    if isinstance(num, str):
                        if num == '':
                            num = 0
                        else:
                            num = int(num, 16)
            except ValueError as ex:
                raise InvalidValueError(f"Not whole number={num} .") from ex

            if code is None:  # dynamically size code
                if not isinstance(num, int) or num < 0:
                    raise InvalidValueError(f"Not whole number={num}.")

                if num <= (256 ** 2 - 1):  # make short version of code
                    code = NumDex.Short

                elif num <= (256 ** 5 - 1):  # make tall version of code
                    code = code = NumDex.Tall

                elif num <= (256 ** 8 - 1):  # make big version of code
                    code = code = NumDex.Big

                elif num <= (256 ** 11 - 1):  # make large version of code
                    code = code = NumDex.Large

                elif num <= (256 ** 14 - 1):  # make great version of code
                    code = code = NumDex.Great

                elif num <= (256 ** 17 - 1):  # make vast version of code
                    code = code = NumDex.Vast

                else:
                    raise InvalidValueError(f"Invalid num = {num}, too large to encode.")

            # default to_bytes parameter signed is False. If negative raises
            # OverflowError: can't convert negative int to unsigned
            try:
                raw = num.to_bytes(Matter._rawSize(code), 'big')  # big endian unsigned
            except Exception as ex:
                raise InvalidValueError(f"Not convertable to bytes {num=}.") from ex

            if len(raw) > Matter._rawSize(code):
                raise InvalidValueError(f"To big {num=} for {code=}.")

        super(Number, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)

        if self.code not in NumDex:
            raise ValidationError(f"Invalid code = {self.code} for Number.")


    def validate(self, inceptive=None):
        """
        Returns:
            self (Number):

        Raises:
            ValidationError: when .num is invalid ordinal such as
               sequence number or first seen number etc.

        Parameters:
           inceptive(bool): raise ValidationError whan .num invalid
                            None means exception when .num < 0
                            True means exception when .num != 0
                            False means exception when .num < 1

        """
        num = self.num

        if num > MaxON:  # too big for ordinal 256 ** 16 - 1
            raise ValidationError(f"Non-ordinal {num} exceeds {MaxON}.")

        if inceptive is not None:
            if inceptive:
                if num != 0:
                    raise ValidationError(f"Nonzero num = {num} non-inceptive"
                                          f" ordinal.")
            else:
                if num < 1:
                    raise ValidationError(f"Non-positive num = {num} not "
                                          f"non-inceptive ordinal.")
        else:
            if num < 0:
                raise ValidationError(f"Negative num = {num} non-ordinal.")

        return self



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
    def huge(self):
        """Provides number value as qb64 but with code NumDex.huge. This is the
        same as Seqner.qb64. Raises error if too big.

        Returns:
            huge (str): qb64 of num coded as NumDex.Huge
        """
        num = self.num
        if num > MaxON:  # too big for ordinal 256 ** 16 - 1
            raise InvalidValueError(f"Non-ordinal {num} exceeds {MaxON}.")

        return Number(num=num, code=NumDex.Huge).qb64


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


class Tagger(Matter):
    """
    Tagger is subclass of Matter, cryptographic material, for compact special
    fixed size primitive with non-empty soft part and empty raw part.

    Tagger provides a more compact representation of small Base64 values in
    as soft part of code rather than would be obtained by by using a small raw
    part whose ASCII representation is converted to Base64.

    Attributes:

    Inherited Properties:  (See Matter)
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str): soft part of derivation code fs any.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip

    Properties:
        tag (str): B64 .soft portion of code but without prepad


    Inherited Hidden:  (See Matter)
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)


    Hidden:


    Methods:


    """


    def __init__(self, tag='', soft='', code=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (bytes | None): fully qualified crypto material Base64
            qb64 (str | bytes | None):  fully qualified crypto material Base64
            qb2 (bytes | None): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip

        Parameters:
            tag (str | bytes):  Base64 automatic sets code given size of tag

        """
        if tag:
            if hasattr(tag, "encode"):  # make tag bytes for regex
                tag = tag.encode("utf-8")

            if not Reb64.match(tag):
                raise InvalidSoftError(f"Non Base64 chars in {tag=}.")

            code = self._codify(tag=tag)
            soft = tag


        super(Tagger, self).__init__(soft=soft, code=code, **kwa)

        if (not self._special(self.code)) or self.code not in TagDex:
            raise InvalidCodeError(f"Invalid code={self.code} for Tagger.")


    @staticmethod
    def _codify(tag):
        """Returns code for tag when tag is appropriately sized Base64

        Parameters:
           tag (str | bytes):  Base64 value

        Returns:
           code (str): derivation code for tag

        """
        # TagDex tags appear in order of size 1 to 10, at indices 0 to 9
        codes = astuple(TagDex)
        l = len(tag)
        if l < 1 or l > len(codes):
            raise InvalidSoftError(f"Invalid {tag=} size {l=}, empty or oversized.")
        return codes[l-1]  # return code at index = len - 1



    @property
    def tag(self):
        """Returns:
            tag (str): B64 primitive without prepad (alias of self.soft)

        """
        return self.soft


class Ilker(Tagger):
    """
    Ilker is subclass of Tagger, cryptographic material, for formatted
    message types (ilks) in Base64. Leverages Tagger support compact special
    fixed size primitives with non-empty soft part and empty raw part.

    Ilker provides a more compact representation than would be obtained by
    converting the raw ASCII representation to Base64.

    Attributes:

    Inherited Properties:  (See Tagger)
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str): soft part of derivation code fs any.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip
        tag (str): B64 primitive without prepad (strips prepad from soft)


    Properties:
        ilk (str):  message type from Ilks of Ilkage

    Inherited Hidden:  (See Tagger)
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)

    Hidden:


    Methods:

    """


    def __init__(self, qb64b=None, qb64=None, qb2=None, tag='', ilk='', **kwa):
        """
        Inherited Parameters:  (see Tagger)
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (bytes | None): fully qualified crypto material Base64
            qb64 (str | bytes | None):  fully qualified crypto material Base64
            qb2 (bytes | None): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip
            tag (str | bytes):  Base64 plain. Prepad is added as needed.

        Parameters:
            ilk (str):  message type from Ilks of Ilkage

        """
        if not (qb64b or qb64 or qb2):
            if ilk:
                tag = ilk


        super(Ilker, self).__init__(qb64b=qb64b, qb64=qb64, qb2=qb2, tag=tag, **kwa)

        if self.code not in (MtrDex.Tag3, ):
            raise InvalidCodeError(f"Invalid code={self.code} for Ilker "
                                   f"{self.ilk=}.")
        if self.ilk not in Ilks:
            raise InvalidSoftError(f"Ivalid ilk={self.ilk} for Ilker.")



    @property
    def ilk(self):
        """Returns:
                tag (str): B64 primitive without prepad (strips prepad from soft)

        Alias for self.tag

        """
        return self.tag


class Traitor(Tagger):
    """
    Traitor is subclass of Tagger, cryptographic material, for formatted
    configuration traits for key events in Base64. Leverages Tagger support of
    compact special fixed size primitives with non-empty soft part and empty raw part.

    Traitor provides a more compact representation than would be obtained by
    converting the raw ASCII representation to Base64.

    Attributes:

    Inherited Properties:  (See Tagger)
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str): soft part of derivation code fs any.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip
        tag (str): B64 primitive without prepad (strips prepad from soft)


    Properties:
        trait (str):  configuration trait B64 from TraitDex

    Inherited Hidden:  (See Tagger)
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)

    Hidden:


    Methods:

    """


    def __init__(self, qb64b=None, qb64=None, qb2=None, tag='', trait='', **kwa):
        """
        Inherited Parameters:  (see Tagger)
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (bytes | None): fully qualified crypto material Base64
            qb64 (str | bytes | None):  fully qualified crypto material Base64
            qb2 (bytes | None): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip
            tag (str | bytes):  Base64 plain. Prepad is added as needed.

        Parameters:
            trait (str):  configuration trait B64 from TraitDex

        """
        if not (qb64b or qb64 or qb2):
            if trait:
                tag = trait


        super(Traitor, self).__init__(qb64b=qb64b, qb64=qb64, qb2=qb2, tag=tag, **kwa)


        if self.trait not in TraitDex:
            raise InvalidSoftError(f"Invalid trait={self.trait} for Traitor.")



    @property
    def trait(self):
        """Returns:
                trait (str): B64 primitive without prepad (strips prepad from soft)

        Alias for self.tag

        """
        return self.tag




# Versage namedtuple
# proto (str): protocol element of Protocols
# vrsn (Versionage): instance protocol version namedtuple (major, minor) ints
# vrsn (Versionage | None): instance genus version namedtuple (major, minor) ints
Versage = namedtuple("Versage", "proto vrsn gvrsn", defaults=(None, ))


class Verser(Tagger):
    """
    Verser is subclass of Tagger, cryptographic material, for formatted
    version primitives in Base64. Leverages Tagger support compact special
    fixed size primitives with non-empty soft part and empty raw part.

    Verser provides a more compact representation than would be obtained by
    converting the raw ASCII representation to Base64.

    Attributes:

    Inherited Properties:  (See Tagger)
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str): soft part of derivation code fs any.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip
        tag (str): B64 primitive without prepad (strips prepad from soft)


    Properties:
        versage (Versage):  named tuple of (proto, vrsn, gvrsn)

    Inherited Hidden:  (See Tagger)
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)

    Hidden:


    Methods:

    """


    def __init__(self, qb64b=None, qb64=None, qb2=None, versage=None,
                 proto=Protocols.keri, vrsn=Vrsn_2_0, gvrsn=None, tag='', **kwa):
        """
        Inherited Parameters:  (see Tagger)
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (bytes | None): fully qualified crypto material Base64
            qb64 (str | bytes | None):  fully qualified crypto material Base64
            qb2 (bytes | None): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip
            tag (str | bytes):  Base64 plain. Prepad is added as needed.

        Parameters:
            versage (Versage | None): namedtuple of (proto, vrsn, gvrsn)
            proto (str | None): protocol from Protocols
            vrsn  (Versionage | None): instance protocol version.
               namedtuple (major, minor) of ints
            gvrsn (Versionage | None): instance genus version.
               namedtuple (major, minor) of ints

        """
        if not (qb64b or qb64 or qb2):
            if versage:
                proto, vrsn, gvrsn = versage

            tag = proto + self.verToB64(vrsn)

            if gvrsn:
                tag += self.verToB64(gvrsn)

        super(Verser, self).__init__(qb64b=qb64b, qb64=qb64, qb2=qb2, tag=tag, **kwa)

        if self.code not in (MtrDex.Tag7, MtrDex.Tag10, ):
            raise InvalidCodeError(f"Invalid code={self.code} for "
                                   f"Verser={self.tag}.")


    @property
    def versage(self):
        """Returns:
            versage (Versage):  named tuple of (proto, vrsn, gvrsn)

        """
        gvrsn = None
        proto = self.tag[:4]
        vrsn = self.b64ToVer(self.tag[4:7])
        gvrsn = self.b64ToVer(self.tag[7:10]) if len(self.tag) == 10 else None

        return Versage(proto=proto, vrsn=vrsn, gvrsn=gvrsn)


    @staticmethod
    def verToB64(version=None, *, text="", major=0, minor=0):
        """ Converts version to Base64 representation

        Returns:
            verB64 (str):

        Example:
            Verser.verToB64(verstr = "1.0"))

        Parameters:
            version (Versionage): instange of namedtuple
                         Versionage(major=major,minor=minor)
            text (str): text format of version as dotted decimal "major.minor"
            major (int): When version is None and verstr is empty then use major minor
                        range [0, 63] for one Base64 character
            minor (int): When version is None and verstr is  empty then use major minor
                        range [0, 4095] for two Base64 characters

        """
        if version:
            major = version.major
            minor = version.minor

        elif text:
            splits = text.split(".", maxsplit=2)
            splits = [(int(s) if s else 0) for s in splits]
            parts = [major, minor]
            for i in range(2-len(splits),0, -1):  # append missing minor and/or major
                splits.append(parts[-i])
            major = splits[0]
            minor = splits[1]

        if major < 0 or major > 63 or minor < 0 or minor > 4095:
                raise ValueError(f"Out of bounds version = {major}.{minor}.")

        return (f"{intToB64(major)}{intToB64(minor, l=2)}")


    @staticmethod
    def b64ToVer(b64, *, texted=False):
        """ Converts Base64 representation of version to Versionage or
        text dotted decimal format

        default is Versionage

        Returns:
            version (Versionage | str):

        Example:
            .b64ToVer("BAA"))

        Parameters:
            b64 (str): base64 string of three characters Mmm for Major minor
            texted (bool): return text format dotted decimal string


        """
        if not Reb64.match(b64.encode("utf-8")):
            raise ValueError("Invalid Base64.")

        if texted:
            return ".".join([f"{b64ToInt(b64[0])}", f"{b64ToInt(b64[1:3])}"])

        return Versionage(major=b64ToInt(b64[0]), minor=b64ToInt(b64[1:3]))


class Texter(Matter):
    """
    Texter is subclass of Matter, cryptographic material, for variable length
    text strings as bytes not unicode. Unicode strings converted to bytes.


    Attributes:

    Inherited Properties:  (See Matter)

    Properties:
        .text is bytes value with CESR code and leader removed.
        .uext is str value with CESR code and leader removed unicode of .text

    Inherited Hidden Properties:  (See Matter)

    Methods:

    Codes:
        Bytes_L0:     str = '4B'  # Byte String lead size 0
        Bytes_L1:     str = '5B'  # Byte String lead size 1
        Bytes_L2:     str = '6B'  # Byte String lead size 2
        Bytes_Big_L0: str = '7AAB'  # Byte String big lead size 0
        Bytes_Big_L1: str = '8AAB'  # Byte String big lead size 1
        Bytes_Big_L2: str = '9AAB'  # Byte String big lead size 2

    """

    def __init__(self, raw=None, qb64b=None, qb64=None, qb2=None,
                 code=MtrDex.Bytes_L0, text=None, **kwa):
        """
        Inherited Parameters:  (see Matter)
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            text is the variable sized text string as either bytes or str

        """
        if raw is None and qb64b is None and qb64 is None and qb2 is None:
            if text is None:
                raise EmptyMaterialError("Missing text string.")
            if hasattr(text, "encode"):
                text = text.encode("utf-8")
            raw = text

        super(Texter, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)
        if self.code not in TexDex:
            raise ValidationError("Invalid code = {} for Texter."
                                  "".format(self.code))


    @property
    def text(self):
        """
        Property text: raw as str
        """
        return self.raw.decode('utf-8')


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

    Properties:
        .bext is the Base64 text value, .qb64 with text code and leader removed.

    Inherited Hidden Properties:  (See Matter)

    Methods:
        ._rawify(self, bext)

    Codes:
        StrB64_L0:     str = '4A'  # String Base64 Only Leader Size 0
        StrB64_L1:     str = '5A'  # String Base64 Only Leader Size 1
        StrB64_L2:     str = '6A'  # String Base64 Only Leader Size 2
        StrB64_Big_L0: str = '7AAA'  # String Base64 Only Big Leader Size 0
        StrB64_Big_L1: str = '8AAA'  # String Base64 Only Big Leader Size 1
        StrB64_Big_L2: str = '9AAA'  # String Base64 Only Big Leader Size 2

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
                bext = bext.encode("utf-8")  # convert to bytes
            if not Reb64.match(bext):
                raise ValueError("Invalid Base64.")
            raw = self._rawify(bext)  # convert bytes to raw with padding

        super(Bexter, self).__init__(raw=raw, qb64b=qb64b, qb64=qb64, qb2=qb2,
                                     code=code, **kwa)
        if self.code not in BexDex:
            raise ValidationError("Invalid code = {} for Bexter."
                                  "".format(self.code))

    @staticmethod
    def _rawify(bext):
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

    @classmethod
    def _derawify(cls, raw, code):
        """Returns decoded raw as B64 str aka bext value

        Returns:
           bext (str): decoded raw as B64 str aka bext value
        """
        _, _, _, _, ls = cls.Sizes[code]
        bext = encodeB64(bytes([0] * ls) + raw)
        ws = 0
        if ls == 0 and bext:
            if bext[0] == ord(b'A'):  # strip leading 'A' zero pad
                ws = 1
        else:
            ws = (ls + 1) % 4
        return bext.decode('utf-8')[ws:]


    @property
    def bext(self):
        """
        Property bext: Base64 text value portion of qualified b64 str
        Returns the value portion of .qb64 with text code and leader removed
        """
        return self._derawify(raw=self.raw, code=self.code)


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


class Labeler(Matter):
    """
    Labeler is subclass of Matter for CESR native field map labels and/or generic
    textual field values. Labeler auto sizes the instance code to minimize
    the total encoded size of associated field label or textual field value.



    Attributes:

    Inherited Properties:
        (See Matter)


    Properties:
        label (str):  base value without encoding

    Inherited Hidden:
        (See Matter)

    Hidden:

    Methods:

    """


    def __init__(self, label='', raw=None, code=None, soft=None, **kwa):
        """
        Inherited Parameters:
            (see Matter)

        Parameters:
            label (str | bytes):  base value before encoding

        """
        if label:
            if hasattr(label, "encode"):  # make label bytes
                label = label.encode("utf-8")

            if Reb64.match(label):  # candidate for Base64 compact encoding
                try:
                    code = Tagger._codify(tag=label)
                    soft = label

                except InvalidSoftError as ex:  # too big
                    if label[0] != ord(b'A'):  # use Bexter code
                        code = LabelDex.StrB64_L0
                        raw = Bexter._rawify(label)

                    else:  # use Texter code since ambiguity if starts with 'A'
                        code = LabelDex.Bytes_L0
                        raw = label

            else:
                if len(label) == 1:
                    code = LabelDex.Label1

                elif len(label) == 2:
                    code = LabelDex.Label2

                else:
                    code = LabelDex.Bytes_L0

                raw = label

        super(Labeler, self).__init__(raw=raw, code=code, soft=soft, **kwa)

        if self.code not in LabelDex:
            raise InvalidCodeError(f"Invalid code={self.code} for Labeler.")



    @property
    def label(self):
        """Extracts and returns label from .code and .soft or .code and .raw

        Returns:
            label (str): base value without encoding
        """
        if self.code in TagDex:  # tag
            return self.soft  # soft part of code

        if self.code in BexDex:  # bext
            return Bexter._derawify(raw=self.raw, code=self.code)  # derawify

        return self.raw.decode()  # everything else is just raw as str



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



class Diger(Matter):
    """
    Diger is Matter subclass with method to verify digest of serialization


    See Matter for inherited attributes and properties:


    Methods:
        verify: verifies digest given ser
        compare: compares provide digest given ser to this digest of ser.
                enables digest agility of different digest algos to compare.


    """

    # Maps digest codes to Digestages of algorithms for computing digest.
    # Should be based on the same set of codes as in DigestCodex
    # so Matter.digestive property works.
    # Use unit tests to ensure codex elements sets match

    Digests = {
        DigDex.Blake3_256: Digestage(klas=blake3.blake3, size=None, length=None),
        DigDex.Blake2b_256: Digestage(klas=hashlib.blake2b, size=32, length=None),
        DigDex.Blake2s_256: Digestage(klas=hashlib.blake2s, size=None, length=None),
        DigDex.SHA3_256: Digestage(klas=hashlib.sha3_256, size=None, length=None),
        DigDex.SHA2_256: Digestage(klas=hashlib.sha256, size=None, length=None),
        DigDex.Blake3_512: Digestage(klas=blake3.blake3, size=None, length=64),
        DigDex.Blake2b_512: Digestage(klas=hashlib.blake2b, size=None, length=None),
        DigDex.SHA3_512: Digestage(klas=hashlib.sha3_512, size=None, length=None),
        DigDex.SHA2_512: Digestage(klas=hashlib.sha512, size=None, length=None),
    }

    def __init__(self, raw=None, ser=None, code=DigDex.Blake3_256, **kwa):
        """Initialize attributes

        Inherited Parameters:
            See Matter

        Parameters:
           ser (bytes): serialization from which raw is computed if not raw

        """

        try:
            super(Diger, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not ser:
                raise ex

            raw = self._digest(ser, code=code)

            super(Diger, self).__init__(raw=raw, code=code, **kwa)

        if self.code not in DigDex:
            raise InvalidCodeError(f"Unsupported Digest {code=}.")

    @classmethod
    def _digest(cls, ser, code=DigDex.Blake3_256):
        """Returns raw digest of ser using digest algorithm given by code

        Parameters:
            ser (bytes): serialization from which raw digest is computed
            code (str): derivation code used to lookup digest algorithm
        """
        if code not in cls.Digests:
            raise InvalidCodeError(f"Unsupported Digest {code=}.")

        klas, size, length = cls.Digests[code]  # digest algo size & length
        ikwa = dict(digest_size=size) if size else dict()  # opt digest size
        dkwa = dict(length=length) if length else dict() # opt digest length
        raw = klas(ser, **ikwa).digest(**dkwa)
        return (raw)


    def verify(self, ser):
        """
        Returns True if raw digest of ser bytes (serialization) matches .raw
        using .raw as reference digest for digest algorithm determined
        by .code

        Parameters:
            ser (bytes): serialization to be digested and compared to .raw

        """
        return (self._digest(ser=ser, code=self.code) == self.raw)


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



class Prefixer(Matter):
    """
    Prefixer is Matter subclass for autonomic identifier AID prefix

    Attributes:

    Inherited Properties:  (see Matter)

    Properties:

    Methods:

    Hidden:

    """

    def __init__(self, **kwa):
        """Checks for .code in PreDex so valid prefixive code
        Inherited Parameters:
            See Matter

        """
        super(Prefixer, self).__init__(**kwa)
        if self.code not in PreDex:
            raise InvalidCodeError(f"Invalid prefixer code = {self.code}.")





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
        knd = Kinds.json
        if 'v' in sad:  # versioned sad
            _, _, knd, _, _ = deversify(sad['v'])

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
        if code not in DigDex:
            raise ValueError(f"Unsupported digest {code=}.")

        sad = dict(sad)  # make shallow copy so don't clobber original sad
        # fill id field denoted by label with dummy chars to get size correct
        sad[label] = clas.Dummy * Matter.Sizes[code].fs
        if 'v' in sad:  # if versioned then need to set size in version string
            raw, proto, kind, sad, version = sizeify(ked=sad, kind=kind)

        ser = dict(sad)
        if ignore:  # delete ignore fields in said calculation from ser dict
            for f in ignore:
                del ser[f]

        cpa = clas._serialize(ser, kind=kind) # serialize ser
        return (Diger._digest(ser=cpa, code=code), sad)   # raw digest and sad


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

        .limen is qualified b64b signing threshold suitable for CESR serialization.
            either Number.qb64b or Bexter.qb64b.
            The b64 portion of limen  with code stripped (Bexter.bext) of
              [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]
              is '1s2c1s2c1s4c1s4c1s4a1c1' basically slash is 's', comma is 'c',
            ANDed clauses are delimited by 'a'.
            Each clause top level weight may be optionally a weighted set of weights
            delimited by 'k' for the weight on the set and 'v' for the weights in
            the set.
            [[{'1/3': ['1/2', '1/2', '1/2']}, '1/2', {'1/2': ['1', '1']}],
                            ['1/2', {'1/2': ['1', '1']}]]
            b'4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1'


        .sith is original signing threshold suitable for value to be serialized
            as json, cbor, mgpk in key event message as either:
                non-negative hex number str or
                list of str rational number fractions >= 0 and <= 1 or
                list of list of str rational number fractions >= 0 and <= 1
                list of list of weighted map of weights

        .thold is parsed signing threshold suitable for calculating satisfaction.
            either as int or list of Fractions

        .num is int signing threshold when not ._weighted

    Methods:
        .satisfy returns bool, True means list of verified signature key indices
        satisfies the threshold, False otherwise.

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

        The thold representation is meant to accept thresholds from computable
        expressions for satisfaction of a threshold

        The limen representation is meant to parse threshold expressions from
        CESR serializations of key event message fields or attachments.

        The sith representation is meant to parse threhold expressions from
        deserializations of JSON, CBOR, or MGPK key event message fields  or
        the command line or configuration files.


        Parameters:

            thold is signing threshold (current or next) is suitable for computing
                the satisfaction of a threshold and is expressed as either:
                    int of threshold number (M of N)
                    fractional weight clauses which may be expressed as either:
                        sequence of either Fractions or tuples of Fraction and
                            sequence of Fractions
                        sequence of sequence of either Fractions or tuples of
                            Fraction and sequence of Fractions

            limen is qualified signing threshold (current or next) expressed as either:
                Number.qb64 or .qb64b of integer threshold or
                Bexter.qb64 or .qb64b of fractional weight clauses which may be either:
                    Base64 delimited clauses of fractions
                    Base64 delimited clauses of fractions

            sith is signing threshold (current or next) expressed as either:
                non-negative int of threshold number (M-of-N threshold)
                    next threshold may be zero
                non-negative hex string of threshold number (M-of-N threshold)
                    next threshold may be zero
                fractional weight clauses which may be expressed as either:
                    sequence of rational number fraction strings  >= 0 and <= 1
                    sequence of either rational number fraction strings  >= 0 and <= 1 or
                    map with key rational number string and value as sequence
                    of rational number fraction strings
                    rational number fraction string
                    sequence of sequences of rational number fraction strings >= 0 and <= 1
                    sequence of sequnces of either rational number fraction strings or
                    map with key rational number fraction string with value sequence of
                    rationaly number fraction strings
                JSON serialized str of the above:


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
            sith = []
            for c in self.thold:
                clause = []
                for e in c:
                    if isinstance(e, tuple):
                        f = e[0]
                        k = f"{f.numerator}/{f.denominator}" if (0 < f < 1) else f"{int(f)}"
                        v = [f"{f.numerator}/{f.denominator}" if (0 < f < 1) else f"{int(f)}"
                                for f in e[1]]
                        clause.append({k: v})
                    else:
                        f = e
                        clause.append(f"{f.numerator}/{f.denominator}" if (0 < f < 1) else f"{int(f)}")
                sith.append(clause)

            #sith = [[f"{f.numerator}/{f.denominator}" if (0 < f < 1) else f"{int(f)}"
                                           #for f in clause]
                                                   #for clause in self.thold]
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



    def _processThold(self, thold: int | Sequence):
        """Process thold input

        Parameters:
            thold (int | Sequence): computable thold expression
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
            clauses = [clause.split('c') for clause in t.split('a')]

            thold = []
            for c in clauses:
                clause = []
                for e in c:
                    k, s, v = e.partition("k")
                    if s:  #not empty
                        clause.append((self.weight(k), [self.weight(w) for w in v.split("v")]))
                    else:
                        clause.append(self.weight(k))

                thold.append(clause)

            self._processWeighted(thold=thold)

        else:
            raise InvalidCodeError(f"Invalid code for limen = {matter.code}.")


    def _processSith(self, sith: int | str | Sequence):
        """
        Process attributes for fractionall weighted threshold sith

        Parameters:
            sith is signing threshold (current or next) expressed as either:
                non-negative int of threshold number (M-of-N threshold)
                    next threshold may be zero
                non-negative hex string of threshold number (M-of-N threshold)
                    next threshold may be zero
                fractional weight clauses which may be expressed as either:
                    an sequence of rational number fraction weight str or int str
                        each denoted w where 0 <= w <= 1
                    an sequence of sequences of rational number fraction weight
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

        else:  # assumes sequence of weights or sequence of sequence of weights
            if isinstance(sith, str):  # json of weighted sith from cli
                sith = json.loads(sith)  # deserialize

            if not sith:  # empty or None
                raise ValueError(f"Empty weight list = {sith}.")

            # is it non str sequence of sequences? or non str sequnce of strs?
            # must test for emply mask because all([]) == True
            mask = [nonStringSequence(c) for c in sith]  # check each element
            if mask and not all(mask):  # not empty and not sequence of sequenes
                sith = [sith]  # attempt to make sequnce of sequqnces of strs

            for c in sith:  # get each clause
                # each element of a clause must be a str or dict
                mask = [(isinstance(w, str) or isinstance(w, Mapping)) for w in c]
                if mask and not all(mask):  # not empty and not sequence of str or dicts
                    raise ValueError(f"Invalid sith = {sith} some weights in"
                                     f"clause {c} are non string.")

            # replace weight str expression, int str or fractional strings with
            # int or fraction as appropriate.
            thold = []
            for c in sith:  # convert string fractions to Fractions
                # append list of where each element is either bare weight or
                # single key map with value as list of weights
                # each weight is converted from its  str expression
                clause = []
                for e in c:  # each element of clause c
                    if isinstance(e, Mapping):
                        if len(e) != 1:
                            raise ValueError(f"Invalid sith = {sith} nested "
                                             f"weight map {e} in clause {c} "
                                             f" not single key value.")
                        k = list(e)[0]  # zeroth key is used
                        # convert to tuple of (weight, [list of weights])
                        clause.append((self.weight(k), [self.weight(w) for w in e[k]]))
                    else:
                        clause.append(self.weight(e))

                thold.append(clause)

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
        for clause in thold:  # sum of top level weights in clause must be >= 1
            # When element is dict then sum of value's weights must be >= 1
            top = []  # top level weights
            for e in clause:
                if isinstance(e, tuple):
                    top.append(e[0])
                    if not (sum(e[1]) >= 1):
                        raise ValueError(f"Invalid sith clause = {clause}, "
                                         f"element = {e}. All nested clause "
                                         f"weight sums must be >= 1.")
                else:
                    top.append(e)
            if not (sum(top) >= 1):
                raise ValueError(f"Invalid sith clause = {clause}, all top level"
                                 f"clause weight sums must be >= 1.")

        self._thold = thold
        self._weighted = True
        #self._size = sum(len(clause) for clause in thold)
        s = 0
        for clause in thold:
            for e in clause:
                if isinstance(e, tuple):
                    s += len(e[1])
                else:
                    s += 1
        self._size = s

        self._satisfy = self._satisfy_weighted
        # make bext str of thold for .bexter for limen
        ta = []  # list of list of fractions and/or single element map of fractions
        for c in thold:
            bc = []  # list of fractions and/or single element map of fractions
            for e in c:
                if isinstance(e, tuple):
                    f = e[0]
                    k = f"{f.numerator}s{f.denominator}" if (0 < f < 1) else f"{int(f)}"
                    v = "v".join([f"{f.numerator}s{f.denominator}" if (0 < f < 1) else f"{int(f)}" for f in e[1]])
                    kv = "k".join([k, v])
                    bc.append(kv)
                else:
                    bc.append(f"{e.numerator}s{e.denominator}" if (0 < e < 1) else f"{int(e)}")

            ta.append(bc)

        bext = "a".join(["c".join(bc) for bc in ta])
        self._number = None
        self._bexter = Bexter(bext=bext)


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
                for e in clause:
                    if isinstance(e, tuple):
                        vw = 0  # init element value weight
                        for w in e[1]:   # sum weights of value
                            if sats[wio]:
                                vw += w
                            wio += 1
                        if vw >= 1:  # element true
                            cw += e[0]  # add element key weight to clause weight
                    else:
                        w = e
                        if sats[wio]:  # verified signature so weight applies
                            cw += w
                        wio += 1
                if cw < 1:  # each clause must sum to at least 1
                    return False

            return True  # all clauses have cw >= 1 including final one, AND true

        except Exception as ex:
            return False

        return False



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
    MaxVSOffset = 12
    SmellSize = MaxVSOffset + MAXVERFULLSPAN  # min buffer size to inhale

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
        proto, vrsn, kind, size, _ = smell(raw)
        if vrsn != Version:
            raise VersionError("Unsupported version = {}.{}, expected {}."
                               "".format(vrsn.major, vrsn.minor, Version))

        ked = loads(raw=raw, size=size, kind=kind)

        return ked, proto, kind, vrsn, size


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


