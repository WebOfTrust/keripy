# -*- coding: utf-8 -*-
"""
Generic Constants and Classes
"""
import sys
import re
from collections import namedtuple, deque
from dataclasses import dataclass, astuple

from .help.helping import sceil
from .help.helping import intToB64, intToB64b, b64ToInt


MaxON = int("f"*32, 16)  # 256 ** 16 - 1 maximum ordinal number, sequence or first seen etc


# Serialization Kinds
Kindage = namedtuple("Kindage", 'json mgpk cbor cesr')
Kinds = Kindage(json='JSON', mgpk='MGPK', cbor='CBOR', cesr='CESR')

# Protocol Types
Protocolage = namedtuple("Protocolage", "keri acdc")
Protocols = Protocolage(keri="KERI", acdc="ACDC")

Versionage = namedtuple("Versionage", "major minor")
Version = Versionage(major=1, minor=0)  # KERI Protocol Version
Vrsn_1_0 = Versionage(major=1, minor=0)  # KERI Protocol Version Specific
Vrsn_2_0 = Versionage(major=2, minor=0)  # KERI Protocol Version Specific


# "{:0{}x}".format(300, 6)  # make num char in hex a variable
# '00012c'
VERFMT = "{}{:x}{:x}{}{:0{}x}_"  # version format string
VERRAWSIZE = 6  # hex characters in raw serialization size in version string

#VEREX0 = b'(?P<proto>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'
#Rever = re.compile(VEREX0)  # compile is faster

# version string in JSON, CBOR, or MGPK field map serialization version 1
VER1FULLSPAN = 17  # number of characters in full version string
VER1TERM = b'_'
VEREX1 = b'(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_'

# version string in JSON, CBOR, or MGPK field map serialization version 2
VER2FULLSPAN = 16  # number of characters in full version string
VER2TERM = b'.'
VEREX2 = b'(?P<proto2>[A-Z]{4})(?P<major2>[0-9A-Za-z_-])(?P<minor2>[0-9A-Za-z_-]{2})(?P<kind2>[A-Z]{4})(?P<size2>[0-9A-Za-z_-]{4})\.'

VEREX = VEREX2 + b'|' + VEREX1

# max number of characters in full version string
MAXVERFULLSPAN = max(VER2FULLSPAN, VER1FULLSPAN)

Rever = re.compile(VEREX)  # compile is faster

MAXVSOFFSET = 12
SMELLSIZE = MAXVSOFFSET + MAXVERFULLSPAN  # min buffer size to inhale



"""
Smellage  (results of smelling a version string such as in a Serder)
    proto (str): protocol type value of Protocols examples 'KERI', 'ACDC'
    vrsn (Versionage): protocol version namedtuple (major, minor) of ints
    kind (str): serialization value of Serials examples 'JSON', 'CBOR', 'MGPK'
    size (int): int size of raw serialization or
    gvrsn (None | Versionage): optional default is None
                For CESR native genus version namedtuple (major, minor) of ints

"""
Smellage = namedtuple("Smellage", "proto vrsn kind size gvrsn", defaults=(None, ))

def rematch(match):
    """
    Returns:
        smellage (Smellage): named tuple extracted from version string regex match
                            (protocol, version, kind, size)

    Parameters:
        match (re.Match):  instance of Match class

    Notes:
        regular expressions work with memoryview objects not just bytes or
        bytearrays
    """
    full = match.group()  # full matched version string
    if len(full) == VER2FULLSPAN and full[-1] == ord(VER2TERM):
        proto, major, minor, kind, size  = match.group("proto2",
                                                       "major2",
                                                       "minor2",
                                                       "kind2",
                                                       "size2")
        proto = proto.decode("utf-8")
        if proto not in Protocols:
            raise ProtocolError(f"Invalid protocol={proto}.")
        vrsn = Versionage(major=b64ToInt(major), minor=b64ToInt(minor))
        if vrsn.major < 2:  # version2 vs but major < 2
            raise VersionError(f"Incompatible {vrsn=} with version string.")

        kind = kind.decode("utf-8")
        if kind not in Kinds:
            raise KindError(f"Invalid serialization kind = {kind}.")
        size = b64ToInt(size)

    elif len(full) == VER1FULLSPAN and full[-1] == ord(VER1TERM):
        proto, major, minor, kind, size = match.group("proto1",
                                                     "major1",
                                                     "minor1",
                                                     "kind1",
                                                     "size1")
        proto = proto.decode("utf-8")
        if proto not in Protocols:
            raise ProtocolError(f"Invalid protocol={proto}.")
        vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
        if vrsn.major > 1:  # version1 vs but major > 1
            raise VersionError(f"Incompatible {vrsn=} with version string.")

        kind = kind.decode("utf-8")
        if kind not in Kinds:
            raise KindError(f"Invalid serialization kind = {kind}.")
        size = int(size, 16)

    else:
        raise VersionError(f"Bad rematch.")

    return Smellage(proto=proto, vrsn=vrsn, kind=kind, size=size)


def versify(protocol=Protocols.keri, version=Version, kind=Kinds.json, size=0):
    """
    Returns:
       vs (str): version string

    Parameters:
        protocol (str): protocol one of Protocols
        version (Versionage): namedtuple (major, minor) of ints
        kind (str): one of Serials
        size (int): length of serialized map that embeds version string field.
    """
    if protocol not in Protocols:
        raise ProtocolError("Invalid message identifier = {}".format(protocol))
    if kind not in Kinds:
        raise KindError("Invalid serialization kind = {}".format(kind))

    if version.major < 2:  # version1 version string
        return VERFMT.format(protocol, version.major, version.minor, kind, size, VERRAWSIZE)
    else:  # version 2+ version string
        return (f"{protocol}{intToB64(version.major)}"
                f"{intToB64(version.minor, l=2)}{kind}{intToB64(size, l=4)}.")


def deversify(vs):
    """
    Returns:  tuple(proto, kind, version, size) Where:
        proto (str): value is protocol type identifier one of Protocols (Protocolage)
                   acdc='ACDC', keri='KERI'

        vrsn (tuple):  version tuple of type Versionage
        kind (str): value is serialization kind, one of Serials
                   json='JSON', mgpk='MGPK', cbor='CBOR'
        size  (int): raw size in bytes

    Parameters:
      vs (str | bytes): version string to extract from

    Uses regex match to extract:
        protocol type
        protocol version tuple
        serialization kind
        serialization size
    """
    if hasattr(vs, "encode"):   # match takes bytes
        vs = vs.encode("utf-8")

    match = Rever.match(vs)
    if not match:
        raise VersionError(f"Invalid version string = '{vs}'.")

    return rematch(match)


def smell(raw):
    """Extract and return instance of Smellage from version string inside
    raw serialization.

    Returns:
        smellage (Smellage): named Tuple of (protocol, version, kind, size)

    Parameters:
        raw (bytearray) of serialized incoming message stream. Assumes start
            of stream is JSON, CBOR, or MGPK field map with first field
            is labeled 'v' and value is version string.


    """
    if len(raw) < SMELLSIZE:
        raise ShortageError(f"Need more raw bytes to smell full version string.")

    match = Rever.search(raw)  # Rever regex takes bytes/bytearray not str
    if not match or match.start() > MAXVSOFFSET:
        raise VersionError(f"Invalid version string from smelled raw = "
                           f"{raw[: SMELLSIZE]}.")

    return rematch(match)


@dataclass(frozen=True)
class ColdCodex:
    """
    ColdCodex is codex of cold stream start tritets of first byte
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    First three bits:
        0o0 = 000 annotated B64 (exhaustive)
        0o1 = 001 cntcode B64
        0o2 = 010 opcode B64
        0o3 = 011 json
        0o4 = 100 mgpk1
        0o5 = 101 cbor
        0o6 = 110 mgpk2
        007 = 111 cntcode or opcode B2

    status is one of ('evt', 'txt', 'bny' )
    'evt' if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2)
    'txt' if tritet in (ColdDex.CtB64, ColdDex.OpB64)
    'bny' if tritet in (ColdDex.CtOpB2,)
    'ann' if trited in (ColdDex.AnB64)

    otherwise raise ColdStartError

    x = bytearray([0x2d, 0x5f])
    x == bytearray(b'-_')
    x[0] >> 5 == 0o1
    True
    """
    AnB64: int = 0o0  # Annotated CESR
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
Colds = Coldage(msg='msg', txt='txt', bny='bny') # add 'ant' for annotated


def sniff(ims):
    """
    Returns status string of cold start of stream ims bytearray by looking
    at first triplet of first byte to determin if message or counter code
    and if counter code whether Base64 or Base2 representation

    First three bits:
    0o0 = 000 annotated cesr
    0o1 = 001 cntcode B64
    0o2 = 010 opcode B64
    0o3 = 011 json
    0o4 = 100 mgpk
    0o5 = 101 cbor
    0o6 = 110 mgpk
    007 = 111 cntcode B2 or opcode B2

    counter B64 in (0o1, 0o2) return 'txt'
    counter B2 in (0o7)  return 'bny'
    event in (0o3, 0o4, 0o5, 0o6)  return 'evt'
    unexpected in (0o0)  raise ColdStartError
    Colds = Coldage(msg='msg', txt='txt', bny='bny')

    'msg' if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2)
    'txt' if tritet in (ColdDex.CtB64, ColdDex.OpB64)
    'bny' if tritet in (ColdDex.CtOpB2,)
    'ano' if tritet in (ColdDex.Anno,)
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
    #if tritet in (ColdDex.AnB64, ):


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

# KERI/ACDC protocol packet (message) types
Ilkage = namedtuple("Ilkage", ('icp rot ixn dip drt rct qry rpy xip exn '
                               'pro bar vcp vrt iss rev bis brv rip upd '
                               'acd ace sch att agg edg rul '))

Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
              rct='rct',
              qry='qry', rpy='rpy', xip='xip', exn='exn', pro='pro', bar='bar',
              vcp='vcp', vrt='vrt', iss='iss', rev='rev', bis='bis', brv='brv',
              rip='rip', upd='upd', acd='acd', ace='ace',
              sch='sch', att='att', agg='agg', edg='edg', rul='rul')

# Ilks needs to be versioned for Protocol versions or else use Serder.Fields

# note ksn is not actual standalone message but is embedded in exn msg when sent
# over the wire. But keep ilk for legacy reasons.


SEPARATOR = "\r\n\r\n"
SEPARATOR_BYTES = SEPARATOR.encode("utf-8")


Schemage = namedtuple("Schemage", 'tcp http https')
Schemes = Schemage(tcp='tcp', http='http', https='https')

Rolage = namedtuple("Rolage", 'controller witness registrar watcher judge juror peer mailbox agent')
Roles = Rolage(controller='controller', witness='witness', registrar='registrar',
               watcher='watcher', judge='judge', juror='juror', peer='peer', mailbox="mailbox", agent="agent")


@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    EstOnly: str = 'EO'  # Only allow establishment events. Inception only.
    DoNotDelegate: str = 'DND'  # Dot not allow delegated identifiers. Inception only.
    RegistrarBackers: str = 'RB' # Registrar backer provided in Registrar seal in this event
    NoBackers: str = 'NB'  #  Do not allow any (registrar backers).
                             # Inception and Rotation in v2.  This should be NRB in next version.
    NoRegistrarBackers: str = 'NRB'  #  Do not allow any registrar backers. Inception and Rotation.
    DelegateIsDelegator: str = 'DID'  # Treat delegate AIDs same as their delegator. Inception only

    def __iter__(self):
        return iter(astuple(self))


TraitDex = TraitCodex()  # Make instance


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
    Invalid raw material
    Usage:
        raise RawMaterialError("error message")
    """


class SoftMaterialError(MaterialError):
    """
    Invalid soft material
    Usage:
        raise SoftMaterialError("error message")
    """


class EmptyMaterialError(MaterialError):
    """
    Empty or Missing Crypto Material
    Usage:
        raise EmptyMaterialError("error message")
    """


class InvalidVersionError(MaterialError):
    """
    Invalid, Unknown, or unrecognized CESR code table version encountered during
    crypto material init
    Usage:
        raise InvalidVersionError("error message")
    """


class InvalidCodeError(MaterialError):
    """
    Invalid, Unknown, or unrecognized code encountered during crypto material init
    Usage:
        raise InvalidCodeError("error message")
    """


class InvalidSoftError(MaterialError):
    """
    Invalid, Unknown, or unrecognized soft part encountered during crypto material init
    Usage:
        raise InvalidSoftError("error message")
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


class ExtraFieldError(ValidationError):
    """
    Extra unallowed field in message
    Usage:
        raise ExtraFieldError("error message")
    """


class AlternateFieldError(ValidationError):
    """
    Unallowed alternate field in message

    Usage:
        raise AlternateFieldError("error message")
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

class IlkError(ExtractionError):
    """
    Bad or Unsupported Message Type (Ilk)

    Usage:
        raise IlkError("error message")
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

