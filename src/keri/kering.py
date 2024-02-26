# -*- coding: utf-8 -*-
"""
Generic Constants and Classes
"""
import sys
import re
from collections import namedtuple, deque
from dataclasses import dataclass, astuple

from .help.helping import sceil

FALSEY = (False, 0, None, "?0", "no", "false", "False", "off")
TRUTHY = (True, 1, "?1", "yes" "true", "True", 'on')

MaxON = int("f"*32, 16)  # 256 ** 16 - 1 maximum ordinal number, sequence or first seen etc


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
# tuple
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



# Serialization Kinds
Serialage = namedtuple("Serialage", 'json mgpk cbor')
Serials = Serialage(json='JSON', mgpk='MGPK', cbor='CBOR')

# Protocol Types
Protocolage = namedtuple("Protocolage", "keri crel acdc")
Protos = Protocolage(keri="KERI", crel="CREL", acdc="ACDC", )

Versionage = namedtuple("Versionage", "major minor")
Version = Versionage(major=1, minor=0)  # KERI Protocol Version
Vrsn_1_0 = Versionage(major=1, minor=0)  # KERI Protocol Version Specific
Vrsn_1_1 = Versionage(major=1, minor=1)  # KERI Protocol Version Specific

VERRAWSIZE = 6  # hex characters in raw serialization size in version string
# "{:0{}x}".format(300, 6)  # make num char in hex a variable
# '00012c'
VERFMT = "{}{:x}{:x}{}{:0{}x}_"  # version format string
VERFULLSIZE = 17  # number of characters in full version string

VEREX0 = b'(?P<proto>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'

#Rever = re.compile(VEREX0)  # compile is faster


VER1FULLSPAN = 17  # number of characters in full version string
VER1TERM = b'_'
VEREX1 = b'(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_'

VER2FULLSPAN = 16  # number of characters in full version string
VER2TERM = b'.'
VEREX2 = b'(?P<proto2>[A-Z]{4})(?P<major2>[0-9A-Za-z_-])(?P<minor2>[0-9A-Za-z_-]{2})(?P<kind2>[A-Z]{4})(?P<size2>[0-9A-Za-z_-]{4}).'

VEREX = VEREX2 + b'|' + VEREX1

Rever = re.compile(VEREX)  # compile is faster

"""
Smellage  (results of smelling a version string such as in a Serder)
    protocol (str): protocol type value of Protos examples 'KERI', 'ACDC'
    version (Versionage): named tuple (major, minor) ints of major minor version
    kind (str): serialization value of Serials examples 'JSON', 'CBOR', 'MGPK'
    size (str): int size of raw serialization

"""
Smellage = namedtuple("Smellage", "protocol version kind size")


def versify(proto=Protos.keri, version=Version, kind=Serials.json, size=0):
    """
    Returns version string
    """
    if proto not in Protos:
        raise ValueError("Invalid message identifier = {}".format(proto))
    #version = version if version else Version
    if kind not in Serials:
        raise ValueError("Invalid serialization kind = {}".format(kind))

    return VERFMT.format(proto, version[0], version[1], kind, size, VERRAWSIZE)


def deversify(vs, version=None):
    """
    Returns:  tuple(proto, kind, version, size) Where:
        proto (str): value is protocol type identifier one of Protos (Protocolage)
                   acdc='ACDC', keri='KERI'

        vrsn (tuple):  version tuple of type Versionage
        kind (str): value is serialization kind, one of Serials
                   json='JSON', mgpk='MGPK', cbor='CBOR'
        size  (int): raw size in bytes

    Parameters:
      vs (str | bytes): version string to extract from
      version (Versionage | None): supported version. None means do not check
            for supported version.

    Uses regex match to extract:
        protocol type
        protocol version tuple
        serialization kind
        serialization size
    """
    if hasattr(vs, "encode"):   # match takes bytes
        vs = vs.encode("utf-8")

    match = Rever.match(vs)
    if match:
        full = match.group()  # full matched version string
        if len(full) == VER2FULLSPAN and full[-1] == ord(VER2TERM):
            proto, major, minor, kind, size  = match.group("proto2",
                                                           "major2",
                                                           "minor2",
                                                           "kind2",
                                                           "size2")
            protocol = proto.decode("utf-8")
            if protocol not in Protos:
                raise ProtocolError(f"Invalid protocol type = {protocol}.")
            vrsn = Versionage(major=b64ToInt(major), minor=b64ToInt(minor))
            if vrsn.major < 2:  # version2 vs but major < 2
                VersionError(f"Incompatible {vrsn=} with version string.")
            if version is not None:  # compatible version with vrsn
                if (vrsn.major > version.major or
                    (vrsn.major == version.major and vrsn.minor > version.minor)):
                        raise VersionError(f"Incompatible {version=}, with "
                                               f"{vrsn=}.")

            kind = kind.decode("utf-8")
            if kind not in Serials:
                raise KindError(f"Invalid serialization kind = {kind}.")
            size = b64ToInt(size)
            return Smellage(protocol=protocol, version=vrsn, kind=kind, size=size)



        elif len(full) == VER1FULLSPAN and full[-1] == ord(VER1TERM):
            proto, major, minor, kind, size = match.group("proto1",
                                                         "major1",
                                                         "minor1",
                                                         "kind1",
                                                         "size1")
            protocol = proto.decode("utf-8")
            if protocol not in Protos:
                raise ProtocolError(f"Invalid protocol type = {protocol}.")
            vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
            if vrsn.major > 1:  # version1 vs but major > 1
                VersionError(f"Incompatible {vrsn=} with version string.")
            if version is not None and vrsn != version:
                            raise VersionError(f"Expected {version=}, got "
                                               f"{vrsn=}.")
            kind = kind.decode("utf-8")
            if kind not in Serials:
                raise KindError(f"Invalid serialization kind = {kind}.")
            size = int(size, 16)
            return Smellage(protocol=protocol, version=vrsn, kind=kind, size=size)



    raise ValueError(f"Invalid version string '{vs}'.")


#proto, major, minor, kind, size = match.group("proto",
                                              #"major",
                                              #"minor",
                                              #"kind",
                                              #"size")

#proto = proto.decode("utf-8")
#vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
#kind = kind.decode("utf-8")

#if proto not in Protos:
    #raise ValueError("Invalid message identifier = {}".format(proto))
#if version is not None and vrsn != version:
    #raise ValueError(f"Expected version = {version}, got "
                       #f"{vrsn.major}.{vrsn.minor}.")
#if kind not in Serials:
    #raise ValueError("Invalid serialization kind = {}".format(kind))
#size = int(size, 16)
#return proto, vrsn, kind, size



MAXVSOFFSET = 12
SMELLSIZE = MAXVSOFFSET + VERFULLSIZE  # min buffer size to inhale



def smell(raw, *, version=None):
    """Extract and return instance of Smellage from version string inside
    raw serialization.

    Returns:
        smellage (Smellage): named Tuple of (protocol, version, kind, size)

    Parameters:
        raw (bytearray) of serialized incoming message stream. Assumes start
            of stream is JSON, CBOR, or MGPK field map with first field
            is labeled 'v' and value is version string.
        version (Versionage | None): instance supported protocol version
            None means do not enforce a supported version
    """
    if len(raw) < SMELLSIZE:
        raise ShortageError(f"Need more raw bytes to smell full version string.")

    match = Rever.search(raw)  # Rever regex takes bytes/bytearray not str
    if not match or match.start() > MAXVSOFFSET:
        raise VersionError(f"Invalid version string from smelled raw = "
                           f"{raw[: SMELLSIZE]}.")



    full = match.group()  # full matched version string
    if len(full) == VER2FULLSPAN and full[-1] == ord(VER2TERM):
        proto, major, minor, kind, size  = match.group("proto2",
                                                       "major2",
                                                       "minor2",
                                                       "kind2",
                                                       "size2")
        protocol = proto.decode("utf-8")
        if protocol not in Protos:
            raise ProtocolError(f"Invalid protocol type = {protocol}.")
        vrsn = Versionage(major=b64ToInt(major), minor=b64ToInt(minor))
        if vrsn.major < 2:  # version2 vs but major < 2
            VersionError(f"Incompatible {vrsn=} with version string.")
        if version is not None:  # compatible version with vrsn
            if (vrsn.major > version.major or
                (vrsn.major == version.major and vrsn.minor > version.minor)):
                    raise VersionError(f"Incompatible {version=}, with "
                                           f"{vrsn=}.")

        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise KindError(f"Invalid serialization kind = {kind}.")
        size = b64ToInt(size)
        return Smellage(protocol=protocol, version=vrsn, kind=kind, size=size)



    elif len(full) == VER1FULLSPAN and full[-1] == ord(VER1TERM):
        proto, major, minor, kind, size = match.group("proto1",
                                                     "major1",
                                                     "minor1",
                                                     "kind1",
                                                     "size1")
        protocol = proto.decode("utf-8")
        if protocol not in Protos:
            raise ProtocolError(f"Invalid protocol type = {protocol}.")
        vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
        if vrsn.major > 1:  # version1 vs but major > 1
            VersionError(f"Incompatible {vrsn=} with version string.")
        if version is not None and vrsn != version:
                        raise VersionError(f"Expected {version=}, got "
                                           f"{vrsn=}.")
        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise KindError(f"Invalid serialization kind = {kind}.")
        size = int(size, 16)
        return Smellage(protocol=protocol, version=vrsn, kind=kind, size=size)





    #proto, major, minor, kind, size = match.group("proto", "major", "minor", "kind", "size")

    ## use length of version string matched to determine if version 1.x or 2.x
    ## so can convert major, minor, and size correctly hex vs B64 numbers

    ## Global version compatibility check. Serder instances also peform version check
    #major = int(major, 16)
    #minor = int(minor, 16)
    #vrsn = Versionage(major=major, minor=minor)
    #if version is not None:  # test here for compatible code version with message vrsn
        #if (vrsn.major > version.major or
            #(vrsn.major == version.major and vrsn.minor > version.minor)):
                #pass  # raise error here?


    #protocol = proto.decode("utf-8")
    #if protocol not in Protos:
        #raise ProtocolError(f"Invalid protocol type = {protocol}.")

    #kind = kind.decode("utf-8")
    #if kind not in Serials:
        #raise KindError(f"Invalid serialization kind = {kind}.")

    #size = int(size, 16)
    #if len(raw) < size:
        #raise ShortageError(f"Need more bytes.")

    #return Smellage(protocol=protocol, version=vrsn, kind=kind, size=size)


@dataclass(frozen=True)
class ColdCodex:
    """
    ColdCodex is codex of cold stream start tritets of first byte
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    First three bits:
        0o0 = 000 free
        0o1 = 001 cntcode B64
        0o2 = 010 opcode B64
        0o3 = 011 json
        0o4 = 100 mgpk
        0o5 = 101 cbor
        0o6 = 110 mgpk
        007 = 111 cntcode or opcode B2

    status is one of ('evt', 'txt', 'bny' )
    'evt' if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2)
    'txt' if tritet in (ColdDex.CtB64, ColdDex.OpB64)
    'bny' if tritet in (ColdDex.CtOpB2,)

    otherwise raise ColdStartError

    x = bytearray([0x2d, 0x5f])
    x == bytearray(b'-_')
    x[0] >> 5 == 0o1
    True
    """
    Free: int = 0o0  # not taken
    CtB64: int = 0o1  # CountCode Base64
    OpB64: int = 0o2  # OpCode Base64
    JSON: int = 0o3  # JSON Map Event Start
    MGPK1: int = 0o4  # MGPK Fixed Map Event Start
    CBOR: int = 0o5  # CBOR Map Event Start
    MGPK2: int = 0o6  # MGPK Big 16 or 32 Map Event Start
    CtOpB2: int = 0o7  # CountCode or OpCode Base2

    def __iter__(self):
        return iter(astuple(self))


ColdDex = ColdCodex()  # Make instance

Coldage = namedtuple("Coldage", 'msg txt bny')  # stream cold start status
Colds = Coldage(msg='msg', txt='txt', bny='bny')


def sniff(ims):
    """
    Returns status string of cold start of stream ims bytearray by looking
    at first triplet of first byte to determin if message or counter code
    and if counter code whether Base64 or Base2 representation

    First three bits:
    0o0 = 000 free
    0o1 = 001 cntcode B64
    0o2 = 010 opcode B64
    0o3 = 011 json
    0o4 = 100 mgpk
    0o5 = 101 cbor
    0o6 = 110 mgpk
    007 = 111 cntcode or opcode B2

    counter B64 in (0o1, 0o2) return 'txt'
    counter B2 in (0o7)  return 'bny'
    event in (0o3, 0o4, 0o5, 0o6)  return 'evt'
    unexpected in (0o0)  raise ColdStartError
    Colds = Coldage(msg='msg', txt='txt', bny='bny')

    'msg' if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2)
    'txt' if tritet in (ColdDex.CtB64, ColdDex.OpB64)
    'bny' if tritet in (ColdDex.CtOpB2,)
    """
    if not ims:
        raise ShortageError("Need more bytes.")

    tritet = ims[0] >> 5
    if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2):
        return Colds.msg
    if tritet in (ColdDex.CtB64, ColdDex.OpB64):
        return Colds.txt
    if tritet in (ColdDex.CtOpB2,):
        return Colds.bny

    raise ColdStartError("Unexpected tritet={} at stream start.".format(tritet))


"""
ilk is short for packet or message type for a given protocol
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

# KERI protocol packet (message) types
Ilkage = namedtuple("Ilkage", ('icp rot ixn dip drt rct qry rpy exn '
                               'pro bar vcp vrt iss rev bis brv '))

Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
              rct='rct',
              qry='qry', rpy='rpy', exn='exn', pro='pro', bar='bar',
              vcp='vcp', vrt='vrt', iss='iss', rev='rev', bis='bis', brv='brv')

# note ksn is not actual standalone message but is embedded in exn msg when sent
# over the wire. But keep ilk for legacy reasons.


SEPARATOR = "\r\n\r\n"
SEPARATOR_BYTES = SEPARATOR.encode("utf-8")


Schemage = namedtuple("Schemage", 'tcp http https')
Schemes = Schemage(tcp='tcp', http='http', https='https')

Rolage = namedtuple("Rolage", 'controller witness registrar watcher judge juror peer mailbox agent')
Roles = Rolage(controller='controller', witness='witness', registrar='registrar',
               watcher='watcher', judge='judge', juror='juror', peer='peer', mailbox="mailbox", agent="agent")



# Exception Subclasses
class KeriError(Exception):
    """
    Base Class for keri exceptions

    To use   raise KeriError("Error: message")
    """


class ClosedError(KeriError):
    """
    Error attempting to use closed (unopened) resource such as file, database etc that is

    Usage:
        raise ClosedError("error message")
    """


class ConfigurationError(KeriError):
    """
    Error configuring or initing KERI component (Controller etc)

    Usage:
        raise ConfigurationError("error message")
    """


class AuthError(KeriError):
    """
    Error authenticating AuthN or authorizing AuthZ

    Usage:
        raise AuthError("error message")
    """


class AuthNError(AuthError):
    """
    Error authenticating

    Usage:
        raise AuthNError("error message")
    """


class AuthZError(AuthError):
    """
    Error authorizing

    Usage:
        raise AuthZError("error message")
    """


class DecryptError(AuthZError):
    """
    Error when attempting decryption

    Usage:
        raise DecryptError("error message")
    """


# errors associated with databases
class DatabaseError(KeriError):
    """
    Error accessing database

    Usage:
        raise DatabaseError("error message")
    """


class MissingEntryError(DatabaseError):
    """
    Error Missing entry or entry not found in database

    Usage:
        raise MissingEntryError("error message")
    """


# Errors when initing cryptographic material
class MaterialError(KeriError):
    """
    Base class for errors related to initing cryptographic material object instances
    """


class RawMaterialError(MaterialError):
    """
    Not Enough bytes in buffer bytearray for raw material
    Usage:
        raise ShortageError("error message")
    """


class EmptyMaterialError(MaterialError):
    """
    Empty or Missing Crypto Material
    Usage:
        raise EmptyMaterialError("error message")
    """


class InvalidCodeError(MaterialError):
    """
    Invalid, Unknown, or unrecognized code encountered during crypto material init
    Usage:
        raise InvalidCodeError("error message")
    """

class InvalidTypeError(MaterialError):
    """
    Invalid material value type encountered during crypto material init
    Usage:
        raise InvalidTypeError("error message")
    """

class InvalidValueError(MaterialError):
    """
    Invalid material value encountered during crypto material init
    Usage:
        raise InvalidValueError("error message")
    """

class InvalidSizeError(MaterialError):
    """
    Invalid size encountered during crypto material init
    Usage:
        raise InvalidSizeError("error message")
    """


class InvalidCodeSizeError(InvalidSizeError):
    """
    Invalid code size encountered during crypto material init
    Usage:
        raise InvalidCodeSizeError("error message")
    """


class InvalidVarIndexError(InvalidSizeError):
    """
    Invalid code index encountered during crypto material init
    Usage:
        raise UnknownCodeError("error message")
    """


class InvalidVarSizeError(InvalidSizeError):
    """
    Invalid variable size encountered during crypto material init
    Usage:
        raise InvalidVarSizeError("error message")
    """


class InvalidVarRawSizeError(InvalidSizeError):
    """
    Invalid raw size encountered during crypto material init
    Usage:
        raise InvalidRawSizeError("error message")
    """

# Errors serializing messages

class SerializeError(KeriError):
    """
    Message creation and serialization errors

    Usage:
        raise MessageError("error message")
    """



# Errors validating  event messages and attachements
class ValidationError(KeriError):
    """
    Validation related errors
    Usage:
        raise ValidationError("error message")
    """

class MissingFieldError(ValidationError):
    """
    Missing a required element or field of message
    Usage:
        raise MissingElementError("error message")
    """


class MissingSignatureError(ValidationError):
    """
    Error At least One but Missing Enough Signatures for Threshold
    Usage:
        raise MissingSignatureError("error message")
    """


class MissingDestinationError(ValidationError):
    """
    Destination field ("i") mising from exn message
    Usage:
        raise MissingDestinationError("error message")
    """


class MissingWitnessSignatureError(ValidationError):
    """
    Error Missing Enough Witness Signatures for Threshold
    Usage:
        raise MissingWitnessSignatureError("error message")
    """


class MissingDelegationError(ValidationError):
    """
    Error Missing Event with Delegation source attachments
    Usage:
        raise MissingDelegationError("error message")
    """


class OutOfOrderError(ValidationError):
    """
    Error prior event missing from log so can't verify sigs on this event
    Usage:
        raise OutOfOrderError("error message")
    """


class LikelyDuplicitousError(ValidationError):
    """
    Error event is likely duplicitous
    Usage:
        raise LikelyDuplicitousError("error message")
    """


class UnverifiedWitnessReceiptError(ValidationError):
    """
    Error witness receipt is unverfied  event not yet in database
    Usage:
        raise UnverifiedWitnessReceiptError("error message")
    """


class UnverifiedReceiptError(ValidationError):
    """
    Error receipt is unverfied because event not yet in database
    Usage:
        raise UnverifiedReceiptError("error message")
    """


class UnverifiedTransferableReceiptError(ValidationError):
    """
    Error reciept from transferable identifier (validator) is unverfied
    Usage:
        raise UnverifiedTransferableReceiptError("error message")
    """


class DerivationError(ValidationError):
    """
    Derivation related errors
    Usage:
        raise DerivationError("error message")
    """

class UnverifiedReplyError(ValidationError):
    """
    Error Reply message not verified usually missing sigs
    Usage:
        raise UnverifiedReplyError("error message")
    """

class EmptyListError(ValidationError):
    """
    Error Required non empty list is empty
    Usage:
        raise EmptyListError("error message")
    """

class MissingAnchorError(ValidationError):
    """
    Error TEL event missing anchor to validating KEL event
    Usage:
        raise MissingAnchorError("error message")
    """


class MissingRegistryError(ValidationError):
    """
    Error registry is missing from the Tevers
    Usage:
        raise MissingRegistryError("error message")
    """


class MissingIssuerError(ValidationError):
    """
    Error issuer is missing from the Tevers
    Usage:
        raise MissingIssuerError("error message")
    """


class InvalidCredentialStateError(ValidationError):
    """
    Error in state of credential, either has not been issued or has been revoked
    Usage:
        raise InvalidCredentialStateError("error message")
    """


class UnverifiedProofError(ValidationError):
    """
    Error signature from credential CESR proof is unverfied
    Usage:
        raise UnverifiedProofError("error message")
    """


class OutOfOrderKeyStateError(ValidationError):
    """
    Error referenced event missing from log so can't verify this key state event
    Usage:
        raise OutOfOrderKeyStateError("error message")
    """


class OutOfOrderTxnStateError(ValidationError):
    """
    Error referenced event missing from log so can't verify this txn state event
    Usage:
        raise OutOfOrderTxnStateError("error message")
    """

class MisfitEventSourceError(ValidationError):
    """
    Error referenced event missing from log so can't verify this txn state event
    Usage:
        raise MisfitEventSourceError("error message")
    """

class MissingDelegableApprovalError(ValidationError):
    """
    Error referenced event missing from log so can't verify this txn state event
    Usage:
        raise MissingDelegableApprovalError("error message")
    """

MissingDelegableApprovalError


# Stream Parsing and Extraction Errors
class ExtractionError(KeriError):
    """
    Base class for errors related to extracting messages and attachments
    from message streams. Rasised in stream processing when extracted data
    does not meet expectations.
    """


class ShortageError(ExtractionError):
    """
    Not Enough bytes in buffer for complete message or material
    Usage:
        raise ShortageError("error message")
    """


class ColdStartError(ExtractionError):
    """
    Bad tritet in first byte of cold start of incoming message stream

    Usage:
        raise ColdStartError("error message")
    """


class SizedGroupError(ExtractionError):
    """
    Error while extracted within sized group. Assumes sized group already
    deleted from stream before raise

    Usage:
        raise SizedGroupError("error message")
    """


class VersionError(ExtractionError):
    """
    Bad or Unsupported Version

    Usage:
        raise VersionError("error message")
    """

class ProtocolError(ExtractionError):
    """
    Bad or Unsupported Protocol type

    Usage:
        raise ProtocolError("error message")
    """

class KindError(ExtractionError):
    """
    Bad or Unsupported Serialization Kind

    Usage:
        raise KindError("error message")
    """


class ConversionError(ExtractionError):
    """
    Problem with Base64 to Binary conversion

    Usage:
        raise ConversionError("error message")

    """

class DeserializeError(ExtractionError):
    """
    Error deserializing message
    Usage:
        raise DeserializeError("error message")
    """


class FieldError(DeserializeError):
    """
    Deserialized field error
    Usage:
        raise FieldError("error message")

    """

class ElementError(DeserializeError):
    """
    Deserialized element error
    Usage:
        raise ElementError("error message")
    """


class DerivationCodeError(ExtractionError):
    """
    Derivation Code crypto material conversion errors
    Usage:
        raise DerivationCodeError("error message")
    """


class UnexpectedCodeError(DerivationCodeError):
    """
    Unexpected or unknown or unsupported derivation code during extraction
    Usage:
        raise UnexpectedCodeError("error message")
    """


class UnexpectedCountCodeError(DerivationCodeError):
    """
    Encountered count code start char "-" unexpectantly
    Usage:
        raise DerivationCodeError("error message")
    """


class UnexpectedOpCodeError(DerivationCodeError):
    """
    Encountered opcode code start char "_" unexpectantly
    Usage:
        raise DerivationCodeError("error message")
    """




# Other errors

class ExchangeError(KeriError):
    """
    Error handling an `exn` message
    Usage:
        raise ExchangeError("error message")
    """


class InvalidEventTypeError(KeriError):
    """
    Error trying to process an unexpected event type
    Usage:
        raise InvalidEventTypeError("error message")
    """


class MissingAidError(KeriError):
    """
    Error trying to process a group identifier without having all the other group members
    Usage:
        raise MissingAidError("error message")
    """


class InvalidGroupError(KeriError):
    """
    Error trying to process a group identifier for an identifier that is not a participant in the group
    Usage:
        raise InvalidGroupError("error message")
    """

class GroupFormationError(KeriError):
    """
    Error trying to form a group rotation event
    Usage:
        raise GroupFormationError("error message")
    """


class MissingChainError(KeriError):
    """
    Error chain from AC/DC credential is not verified.

    Usage:
        raise MissingChainError("error message")
    """


class RevokedChainError(KeriError):
    """
    Error chain from AC/DC credential is not verified.

    Usage:
        raise RevokedChainError("error message")
    """


class MissingSchemaError(KeriError):
    """
    Error loading AC/DC credential schema from cache.

    Usage:
        raise MissingSchemaError("error message")
    """


class FailedSchemaValidationError(KeriError):
    """
    Error from AC/DC credential is not valid against its schema.

    Usage:
        raise FailedSchemaValidationError("error message")
    """


class UntrustedKeyStateSource(KeriError):
    """
    Error untrusted source of key state, not aid, aid's witness or our watcher
    Usage:
        raise UntrustedKeyStateSource("error message")
    """


class QueryNotFoundError(KeriError):
    """
    Error results for a qry message are not yet available
    Usage:
        raise QueryNotFoundError("error message")
    """

