# -*- coding: utf-8 -*-
"""
Generic Constants and Classes
"""
import sys
import re
from collections import namedtuple


FALSEY = (False, 0, None, "?0", "no", "false", "False", "off")
TRUTHY = (True, 1, "?1", "yes" "true", "True", 'on')

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

VEREX = b'(?P<proto>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'
Rever = re.compile(VEREX)  # compile is faster


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
        kind (str): value is serialization kind, one of Serials
                   json='JSON', mgpk='MGPK', cbor='CBOR'
        vrsn (tuple):  version tuple of type Versionage
        size  (int): raw size in bytes

    Parameters:
      vs (str): version string to extract from
      version (Versionage | None): supported version. None means do not check
            for supported version.

    Uses regex match to extract:
        protocol type
        protocol version tuple
        serialization kind
        serialization size
    """
    match = Rever.match(vs.encode("utf-8"))  # match takes bytes
    if match:
        proto, major, minor, kind, size = match.group("proto",
                                                      "major",
                                                      "minor",
                                                      "kind",
                                                      "size")
        proto = proto.decode("utf-8")
        vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
        kind = kind.decode("utf-8")

        if proto not in Protos:
            raise ValueError("Invalid message identifier = {}".format(proto))
        if version is not None and vrsn != version:
            raise ValueError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return proto, vrsn, kind, size

    raise ValueError("Invalid version string = {}".format(vs))

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


ICP_LABELS = ["v", "t", "d", "i", "s", "kt", "k", "nt", "n",
              "bt", "b", "c", "a"]
DIP_LABELS = ["v", "d", "i", "s", "t", "kt", "k", "nt", "n",
              "bt", "b", "c", "a", "di"]
ROT_LABELS = ["v", "d", "i", "s", "t", "p", "kt", "k", "nt", "n",
              "bt", "br", "ba", "a"]
DRT_LABELS = ["v", "d", "i", "s", "t", "p", "kt", "k", "nt", "n",
              "bt", "br", "ba", "a"]
IXN_LABELS = ["v", "d", "i", "s", "t", "p", "a"]

#KSN_LABELS = ["v", "d", "i", "s", "p", "d", "f", "dt", "et", "kt", "k", "nt", "n",
              #"bt", "b", "c", "ee", "di"]

RPY_LABELS = ["v", "d", "t", "d", "dt", "r", "a"]

VCP_LABELS = ["v", "d", "i", "s", "t", "bt", "b", "c"]
VRT_LABELS = ["v", "d", "i", "s", "t", "p", "bt", "b", "ba", "br"]

ISS_LABELS = ["v", "i", "s", "t", "ri", "dt"]
BIS_LABELS = ["v", "i", "s", "t", "ra", "dt"]

REV_LABELS = ["v", "i", "s", "t", "p", "dt"]
BRV_LABELS = ["v", "i", "s", "t", "ra", "p", "dt"]

TSN_LABELS = ["v", "i", "s", "d", "ii", "a", "et", "bt", "b", "c", "br", "ba"]
CRED_TSN_LABELS = ["v", "i", "s", "d", "ri", "a", "ra"]


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

