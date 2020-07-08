# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import re
import json
import cbor2 as cbor
import msgpack

from dataclasses import dataclass, astuple
from collections import namedtuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

from ..kering import ValidationError, VersionError, Versionage, Version

Serialage = namedtuple("Serialage", 'json mgpk cbor')

Serials = Serialage(json='JSON', mgpk='MGPK', cbor='CBOR')

Mimes = Serialage(json='application/keri+json',
                  mgpk='application/keri+msgpack',
                  cbor='application/keri+cbor',)

VERRAWSIZE = 6  # hex characters in raw serialization size in version string
# "{:0{}x}".format(300, 6)  # make num char in hex a variable
# '00012c'
VERFMT = "KERI{:x}{:x}{}{:0{}x}_"  #  version format string

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

Ilkage = namedtuple("Ilkage", 'icp rot ixn dip drt')  # Event ilk (type of event)

Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt')

@dataclass(frozen=True)
class CrySelectCodex:
    """
    Select codex of selector characters for cyptographic material
    Only provide defined characters.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    two:  str = '0'  # use two character table.
    four: str = '1'  # use four character table.

    def __iter__(self):
        return iter(astuple(self))

CrySelect = CrySelectCodex()  # Make instance

@dataclass(frozen=True)
class CryOneCodex:
    """
    CryOneCodex is codex of one character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in CryOneCodex results in 1 Base64 pad byte.
    """
    Ed25519N:     str = 'A'  #  Ed25519 verification key non-transferable, basic derivation.
    X25519:       str = 'B'  #  X25519 public encryption key, converted from Ed25519.
    Ed25519:      str = 'C'  #  Ed25519 verification key basic derivation
    Blake3_256:   str = 'D'  #  Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:  str = 'E'  #  Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:  str = 'F'  #  Blake2s 256 bit digest self-addressing derivation.
    ECDSA_256k1N: str = 'G'  #  ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:  str = 'H'  #  Ed25519 verification key basic derivation
    SHA3_256:     str = 'I'  #  SHA3 256 bit digest self-addressing derivation.
    SHA2_256:     str = 'J'  #  SHA2 256 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))

CryOne = CryOneCodex()  # Make instance


# Mapping of Code to Size
CryOneSizes = {
               "A": 44, "B": 44, "C": 44, "D": 44, "E": 44, "F": 44,
               "G": 44, "H": 44, "I": 44, "J": 44,
              }


@dataclass(frozen=True)
class CryTwoCodex:
    """
    CryTwoCodex is codex of two character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in CryTwoCodex results in 2 Base64 pad bytes.
    """
    Ed25519:     str =  '0A'  # Ed25519 signature.
    ECDSA_256k1: str = '0B'  # ECDSA secp256k1 signature.


    def __iter__(self):
        return iter(astuple(self))

CryTwo = CryTwoCodex()  #  Make instance

# Mapping of Code to Size
CryTwoSizes = {
               "0A": 88,
               "0B": 88,
              }

@dataclass(frozen=True)
class CryFourCodex:
    """
    CryFourCodex codex of four character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in CryFourCodex results in 0 Base64 pad bytes.
    """

    def __iter__(self):
        return iter(astuple(self))

CryFour = CryFourCodex()  #  Make instance

# Mapping of Code to Size
CryFourSizes = {}


class CryMat:
    """
    CryMat is fully qualified cryptographic material base class
    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:
        .code  str derivation code to indicate cypher suite
        .raw   bytes crypto material only without code

    Properties:
        .pad  int number of pad chars
        .qb64 str in Base64 with derivation code and crypto material
        .qb2  bytes in binary with derivation code and crypto material

    """

    def __init__(self, raw=b'', qb64='', qb2='', code=CryOne.Ed25519N):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code

        When raw provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64 or qb2 provided extract and assign .raw and .code

        """
        if raw:  #  raw provided so infil with code
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))
            pad = self._pad(raw)
            if (not ( (pad == 1 and (code in CryOne)) or  # One or Five or Nine
                      (pad == 2 and (code in CryTwo)) or  # Two or Six or Ten
                      (pad == 0 and (code in CryFour)) )):  #  Four or Eight

                raise ValidationError("Wrong code={} for raw={}.".format(code, raw))

            self.code = code
            self.raw = raw
        elif qb64:
            self._exfil(qb64)
        elif qb2:  # rewrite to use direct binary exfiltration
            self._exfil(encodeB64(qb2).decode("utf-8"))
        else:
            raise ValueError("Improper initialization need raw or b64 or b2.")


    @staticmethod
    def _pad(raw):
        """
        Returns number of pad characters that would result from converting raw
        to Base64 encoding
        raw is bytes or bytearray
        """
        m = len(raw) % 3
        return (3 - m if m else 0)


    @property
    def pad(self):
        """
        Returns number of pad characters that would result from converting
        self.raw to Base64 encoding
        self.raw is raw is bytes or bytearray
        """
        return self._pad(self.raw)


    def _infil(self):
        """
        Returns fully qualified base64 given self.pad, self.code and self.raw
        code is Codex value
        raw is bytes or bytearray
        """
        pad = self.pad
        # valid pad for code length
        if len(self.code) % 4 != pad:  # pad is not remainder of len(code) % 4
            raise ValidationError("Invalid code = {} for converted raw pad = {}."
                                  .format(self.code, self.pad))
        # prepending derivation code and strip off trailing pad characters
        return (self.code + encodeB64(self.raw).decode("utf-8")[:-pad])


    def _exfil(self, qb64):
        """
        Extracts self.code and self.raw from qualified base64 qb64
        """
        pre = 1
        code = qb64[:pre]

        # need to map code to length so can only consume proper number of chars
        #  from front of qb64 so can use with full identifiers not just id prefixes

        if code in CryOne:  # One Char code
            qb64 = qb64[:CryOneSizes[code]]  # strip of identifier after prefix

        elif code == CrySelect.two: # first char of two char code
            pre += 1
            code = qb64[pre-2:pre]  #  get full code
            if code not in CryTwo:
                raise ValidationError("Invalid derivation code = {} in {}.".format(code, qb64))
            qb64 = qb64[:CryTwoSizes[code]]  # strip of identifier after prefix

        else:
            raise ValueError("Improperly coded material = {}".format(qb64))

        pad = pre % 4  # pad is remainder pre mod 4
        # strip off prepended code and append pad characters
        base = qb64[pre:] + pad * BASE64_PAD
        raw = decodeB64(base.encode("utf-8"))

        if len(raw) != (len(qb64) - pre) * 3 // 4:  # exact lengths
            raise ValueError("Improperly qualified material = {}".format(qb64))

        self.code = code
        self.raw = raw

    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version Bytes
        redo to use b64 to binary decode table since faster
        """
        # rewrite to do direct binary infiltration by
        # decode self.code as bits and prepend to self.raw
        return decodeB64(self._infil().encode("utf-8"))


BASE64_PAD = '='

# Mappings between Base64 Encode Index and Decode Characters
#  B64ChrByIdx is dict where each key is a B64 index and each value is the B64 char
#  B64IdxByChr is dict where each key is a B64 chars and each values is the B64 indexe
# Map Base64 index to char
B64ChrByIdx = dict((index, char) for index,  char in enumerate([chr(x) for x in range(65, 91)]))
B64ChrByIdx.update([(index + 26, char) for index,  char in enumerate([chr(x) for x in range(97, 123)])])
B64ChrByIdx.update([(index + 52, char) for index,  char in enumerate([chr(x) for x in range(48, 58)])])
B64ChrByIdx[62] = '-'
B64ChrByIdx[63] = '_'

B64IdxByChr = {char: index for index, char in B64ChrByIdx.items()}  # map char to Base64 index

def IntToB64(i):
    """
    Returns conversion of int i to 2 digit Base64 str
    0 <= 1 <= 4095
    """
    if i < 0 or i >  4095:
        raise ValueError("Invalid int = {}".format(i))

    return "{}{}".format(B64ChrByIdx[i // 64], B64ChrByIdx[i % 64])

def B64ToInt(cs):
    """
    Returns conversion of 2 digit Base64 str cs to int
    """
    if len(cs) > 2:
        raise ValueError("Invalid cs = {}".format(cs))

    return (B64IdxByChr[cs[0]] * 64 + B64IdxByChr[cs[1]])


@dataclass(frozen=True)
class SigSelectCodex:
    """
    SigSelectCodex codex of selector characters for attached signature cyptographic material
    Only provide defined characters.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    four: str = '0'  # use four character table.
    five: str = '1'  # use five character table.
    six:  str = '2'  # use siz character table.

    def __iter__(self):
        return iter(astuple(self))

SigSelect = SigSelectCodex()  # Make instance


@dataclass(frozen=True)
class SigTwoCodex:
    """
    SigTwoCodex codex of two character length derivation codes for attached signatures
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in SigTwoCodex results in 2 Base64 pad bytes.

    First code character selects signature cipher suite
    Second code charater selects index into current signing key list
    Only provide first character here
    """
    Ed25519: str =  'A'  # Ed25519 signature.
    ECDSA_256k1: str = 'B'  # ECDSA secp256k1 signature.


    def __iter__(self):
        return iter(astuple(self))

SigTwo = SigTwoCodex()  #  Make instance

# Mapping of Code to Size
SigTwoSizes = {
                "A": 88,
                "B": 88,
              }

SIGTWOMAX = 63  # maximum index value given one base64 digit

@dataclass(frozen=True)
class SigFourCodex:
    """
    SigFourCodex codex of four character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in SigFourCodex results in 0 Base64 pad bytes.

    First two code characters select signature cipher suite
    Next two code charaters select index into current signing key list
    Only provide first two characters here
    """
    Ed448: str =  '0A'  # Ed448 signature.


    def __iter__(self):
        return iter(astuple(self))

SigFour = SigFourCodex()  #  Make instance

# Mapping of Code to Size
SigFourSizes = {
                "0A": 156,
               }

SIGFOURMAX = 4095  # maximum index value given two base 64 digits

@dataclass(frozen=True)
class SigFiveCodex:
    """
    Five codex of five character length derivation codes
    Only provide defined codes. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in Four results in 0 Base64 pad bytes.

    First three code characters select signature cipher suite
    Next two code charaters select index into current signing key list
    Only provide first three characters here
    """

    def __iter__(self):
        return iter(astuple(self))

SigFive = SigFiveCodex()  #  Make instance

# Mapping of Code to Size
SigFiveSizes = {}

SIGFIVEMAX = 4095  # maximum index value given two base 64 digits

class SigMat:
    """
    SigMat is fully qualified attached signature crypto material base class
    Sub classes are derivation code specific.

    Includes the following attributes and properites.

    Attributes:
        .code  str derivation code of cipher suite for signature
        .index int zero based offset into signing key list
        .raw   bytes crypto material only without code

    Properties:
        .pad  int number of pad chars
        .qb64 str in Base64 with derivation code and signature crypto material
        .qb2  bytes in binary with derivation code and signature crypto material
    """

    def __init__(self, raw=b'', qb64='', qb2='', code=SigTwo.Ed25519, index=0):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code cipher suite
            index is int of offset index into current signing key list

        When raw provided then validate that code is correct for length of raw
            and assign .raw .code and .index
        Else when qb64 pr qb2 provided extract and assign .raw and .code

        """
        if raw:  #  raw provided
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))
            pad = self._pad(raw)
            if (not ( (pad == 2 and (code in SigTwo)) or  # Two or Six or Ten
                      (pad == 0 and (code in SigFour)) or  #  Four or Eight
                      (pad == 1 and (code in SigFive)) )):   # Five or Nine

                raise ValidationError("Wrong code={} for raw={}.".format(code, raw))

            if ( (code in SigTwo and ((index < 0) or (index > SIGTWOMAX)) ) or
                 (code in SigFour and ((index < 0) or (index > SIGFOURMAX)) ) or
                 (code in SigFive and ((index < 0) or (index > SIGFIVEMAX)) ) ):

                raise ValidationError("Invalid index={} for code={}.".format(index, code))

            self.code = code  # front part without index
            self.index = index
            self.raw = raw

        elif qb64:
            self._exfil(qb64)

        elif qb2:  # rewrite to use direct binary exfiltration
            self._exfil(encodeB64(qb2).decode("utf-8"))

        else:
            raise ValueError("Improper initialization need raw or b64 or b2.")


    @staticmethod
    def _pad(raw):
        """
        Returns number of pad characters that would result from converting raw
        to Base64 encoding
        raw is bytes or bytearray
        """
        m = len(raw) % 3
        return (3 - m if m else 0)


    @property
    def pad(self):
        """
        Returns number of pad characters that would result from converting
        self.raw to Base64 encoding
        self.raw is raw is bytes or bytearray
        """
        return self._pad(self.raw)


    def _infil(self):
        """
        Returns fully qualified attached sig base64 computed from
        self.raw, self.code and self.index.
        """
        pad = self.pad
        # valid pad for code length
        if self.code in SigTwo:  # 2 char = code + index
            full = "{}{}".format(self.code, B64ChrByIdx[self.index])

        elif self.code == SigSelect.four: # 4 char = code + index
            pass

        else:
            raise ValueError("Unrecognized code = {}".format(self.code))

        if len(full) % 4 != pad:  # pad is not remainder of len(code) % 4
            raise ValidationError("Invalid code + index = {} for converted raw pad = {}."
                                  .format(full, self.pad))
        # prepending full derivation code with index and strip off trailing pad characters
        return (full + encodeB64(self.raw).decode("utf-8")[:-pad])


    def _exfil(self, qb64):
        """
        Extracts self.code,self.index, and self.raw from qualified base64 qb64
        """
        pre = 1
        code = qb64[:pre]
        index = 0

        # need to map code to length so can only consume proper number of chars
        #  from front of qb64 so can use with full identifiers not just id prefixes

        if code in SigTwo:  # 2 char = 1 code + 1 index
            qb64 = qb64[:SigTwoSizes[code]]  # strip of identifier after prefix
            pre += 1
            index = B64IdxByChr[qb64[pre-1:pre]]

        elif code == SigSelect.four:  #  '0'
            pre += 1
            code = qb64[pre-2:pre]
            if code not in SigFour:  # 4 char = 2 code + 2 index
                raise ValidationError("Invalid derivation code = {} in {}.".format(code, qb64))
            qb64 = qb64[:SigFourSizes[code]]  # strip of identifier after prefix
            pre += 2
            index = B64ToInt(qb64[pre-2:pre])

        else:
            raise ValueError("Improperly coded material = {}".format(qb64))

        pad = pre % 4  # pad is remainder pre mod 4
        # strip off prepended code and append pad characters
        base = qb64[pre:] + pad * BASE64_PAD
        raw = decodeB64(base.encode("utf-8"))

        if len(raw) != (len(qb64) - pre) * 3 // 4:  # exact lengths
            raise ValueError("Improperly qualified material = {}".format(qb64))

        self.code = code
        self.index = index
        self.raw = raw


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version
        redo to use b64 to binary decode table since faster
        """
        # rewrite to do direct binary infiltration by
        # decode self.code as bits and prepend to self.raw
        return decodeB64(self._infil().encode("utf-8"))


"""
Need to add Serdery  as Serder factory that figures out what type of
serialization and creates appropriate subclass

"""

class Serder:
    """
    Serder is KERI key event serializer-deserializer class
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw is bytes of serialized event only
        .ked is key event dict
        .kind is serialization kind string value (see namedtuple coring.Serials)
        .size is int of number of bytes in serialed event only

    """
    def __init__(self, raw=b'', ked=None, kind=None):
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
          size is int number of bytes in raw if any


        Attributes:
          ._raw is bytes of serialized event only
          ._ked is key event dict
          ._kind is serialization kind string value (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
          ._size is int of number of bytes in serialed event only

        Properties:
          .raw is bytes of serialized event only
          .ked is key event dict
          .kind is serialization kind string value (see namedtuple coring.Serials)
          .size is int of number of bytes in serialed event only


        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes
        """
        if raw:  # deserialize raw using property
            self.raw = raw  # raw property setter does the deserialization
        elif ked: # serialize ked
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
        match = Rever.search(raw)  #  Rever's regex takes bytes
        if not match or match.start() > 12:
            raise ValueError("Invalid version string in raw = {}".format(raw))

        major, minor, kind, size = match.group("major", "minor", "kind", "size")
        version = Versionage(major=int(major, 16), minor=int(minor, 16))
        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return(kind, version, size)


    def _inhale(self, raw):
        """
        Parses serilized event ser of serialization kind and assigns to
        instance attributes.

        Parameters:
          raw is bytes of serialized event
          kind id str of raw serialization kind (see namedtuple Serials)
          size is int size of raw to be deserialized

        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes

        """
        kind, version, size = self._sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}".format(version.major,
                                                                    version.minor))

        if kind == Serials.json:
            try:
                ked = json.loads(raw[:size].decode("utf-8"))
            except Exception as ex:
                raise ex

        elif kind == Serials.mgpk:
            try:
                ked = msgpack.loads(raw[:size])
            except Exception as ex:
                raise ex

        elif kind ==  Serials.cbor:
            try:
                ked = cbor.loads(raw[:size])
            except Exception as ex:
                raise ex

        else:
            ked = None

        return (ked, kind, size)


    def _exhale(self, ked,  kind=None):
        """
        ked is key event dict
        kind is serialization if given else use one given in ked
        Returns tuple of (raw, kind) where raw is serialized event as bytes of kind
        and kind is serialzation kind

        Assumes only supports Version
        """
        if "vs" not in ked:
            raise ValueError("Missing or empty version string in key event dict = {}".format(ked))

        knd, version, size = Deversify(ked['vs'])  # extract kind and version
        if version != Version:
            raise VersionError("Unsupported version = {}.{}".format(version.major,
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
        ked['vs'] = vs  #  update ked

        return (raw, kind, ked)

    @property
    def raw(self):
        """ raw property getter """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        ked, kind, size = self._inhale(raw=raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size

    @property
    def ked(self):
        """ ked property getter"""
        return self._ked

    @ked.setter
    def ked(self, ked):
        """ ked property setter  assumes ._kind """
        raw, kind, ked = self._exhale(ked=ked, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size

    @property
    def kind(self):
        """ kind property getter"""
        return self._kind

    @kind.setter
    def kind(self, kind):
        """ kind property setter Assumes ._ked """
        raw, kind, ked = self._exhale(ked=self._ked, kind=kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size

    @property
    def size(self):
        """ size property getter"""
        return self._size


class Corver:
    """
    Corver is KERI key event verifier class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .serder is Serder instance created from serialized event

    """
    def __init__(self, raws=bytearray()):
        """
        Extract event and attached signatures from event stream raws

        Parameters:
          raws is bytes of serialized event stream.
            Stream raws may have zero or more sets of a serialized event plus any
            attached signatures


        Attributes:


        Properties:
          .raw is bytes of serialized event plus attached signatures
          .size is int of number of bytes in serialed event plus attached signatures



        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes
        """
        if not raws:
            raise ValueError("Empty serialized event stream.")

        if not isinstance(raws, bytearray):
            raws = bytearray(raws)
