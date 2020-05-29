# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import json
import cbor2 as cbor
import msgpack

from dataclasses import dataclass, astuple
from collections import namedtuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64


from ..kering import ValidationError, VERSION


BASE64_PAD = '='

Serializations = namedtuple("Serializations", 'json mgpk cbor')

Serials = Serializations(json='JSON', mgpk='MGPK', cbor='CBOR')

Mimes = Serializations(json='application/keri+json',
                       mgpk='application/keri+msgpack',
                       cbor='application/keri+cbor',)

VERFMT = "KERI{}{:x}{:x}{:06x}_"  #  version format string
Versions = Serializations(json=VERFMT.format(Serials.json, VERSION[0], VERSION[1], 0),
                          mgpk=VERFMT.format(Serials.mgpk, VERSION[0], VERSION[1], 0),
                          cbor=VERFMT.format(Serials.cbor, VERSION[0], VERSION[1], 0))


Sniffs = Serializations(json=b'KERIJSON',
                        mgpk=b'KERIMGPK',
                        cbor=b'KERICBOR')

RAWSIZE = 6  # hex characters in raw serialization size in version string

VERNUMSIZE = 2  # hex characters in version number in version string

SniffSizeOffs = Serializations(json=len(Sniffs.json) + VERNUMSIZE,
                          mgpk=len(Sniffs.mgpk) + VERNUMSIZE,
                         cbor=len(Sniffs.cbor) + VERNUMSIZE)




@dataclass(frozen=True)
class SelectCodex:
    """
    Select codex of selector characters
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.
    """
    two: str = '0'  # use two character table.

    def __iter__(self):
        return iter(astuple(self))

Select = SelectCodex()  # Make instance

@dataclass(frozen=True)
class OneCodex:
    """
    One codex of one character length derivation codes
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in One results in 1 Base64 pad byte.
    """
    Ed25519N: str =  'A'  # Ed25519 verification key non-transferable, basic derivation.
    X25519: str = 'B'  # X25519 public encryption key, converted from Ed25519.
    Ed25519: str = 'C'  #  Ed25519 verification key basic derivation
    Blake3_256: str = 'D'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256: str = 'E'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256: str = 'F'  # Blake2s 256 bit digest self-addressing derivation.
    ECDSA_256k1N: str = 'G'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1: str = 'H'  #  Ed25519 verification key basic derivation
    SHA3_256: str = 'I'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256: str = 'J'  # SHA2 256 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))

One = OneCodex()  # Make instance

@dataclass(frozen=True)
class TwoCodex:
    """
    Two codex of two character length derivation codes
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in Two results in 2 Base64 pad bytes.
    """
    Ed25519: str =  '0A'  # Ed25519 signature.
    ECDSA_256k1: str = '0B'  # ECDSA secp256k1 signature.


    def __iter__(self):
        return iter(astuple(self))

Two = TwoCodex()  #  Make instance

@dataclass(frozen=True)
class FourCodex:
    """
    Four codex of four character length derivation codes
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in Four results in 0 Base64 pad bytes.
    """

    def __iter__(self):
        return iter(astuple(self))

Four = FourCodex()  #  Make instance


class CryMat:
    """
    Fully Qualified Cryptographic Material Base Class
    Material has derivation code that indicates cipher suite
    Sub classes provide key event element context.
    """

    def __init__(self, raw=b'', qb64='', qb2='', code=One.Ed25519N):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code

        When raw provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64 pr qb2 provided extract and assign .raw and .code

        """
        if raw:  #  raw provided so infil with code
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))
            pad = self._pad(raw)
            if (not ( (pad == 1 and (code in One)) or  # One or Five or Nine
                      (pad == 2 and (code in Two)) or  # Two or Six or Ten
                      (pad == 0 and (code in Four)) )):  #  Four or Eight

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

        if code in One:  # One Char code
            pad = pre % 4  # pad is remainder pre mod 4
            # strip off prepended code and append pad characters
            base = qb64[pre:] + pad * BASE64_PAD

        elif code == Select.two: # two char code
            code = qb64[pre-1:pre+1]
            if code not in Two:
                raise ValidationError("Invalid derivation code = {} in {}.".format(code, qb64))
            pre += 1
            pad = pre % 4
            base = qb64[pre:] + pad * BASE64_PAD
        else:
            raise ValueError("Improperly coded material = {}".format(qb64))

        raw = decodeB64(base.encode("utf-8"))

        if len(raw) != (len(qb64) - pre) * 3 // 4:  # exact lengths
            raise ValueError("Improperly qualified material = {}".format(qb64))

        self.code = code
        self.raw = raw

    @property
    def pad(self):
        """
        Returns number of pad characters that would result from converting
        self.raw to Base64 encoding
        self.raw is raw is bytes or bytearray
        """
        return self._pad(self.raw)


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
Need to add factory that figures out what type of event and creates appropriate
subclass

"""

class Serder:
    """
    KERI Key Event Serializer Deserializer

    """


    def __init__(self, raw=b'', kind=None, size=0, ked=None):
        """
        Parameters:
          raw is bytes of serialized event
          kind is serialization kind string value (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
          ked is key event dict

        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes
        """
        if raw:
            if not kind or not size:
                kind, size = self._sniff(raw)
            ked = self._inhale(raw, kind, size)

        self.raw = raw
        self.kind = kind
        self.size = size
        self.ked = ked



    @staticmethod
    def _sniff(raw):
        """
        Returns serialization kind and size of serialized event raw
        by investigating leading bytes that contain version string

        Parameters:
          raw is bytes of serialized event

        """
        offset = raw.find(Sniffs.json)
        if offset == 7:  #  json serialization
            kind = Serials.json
            size = int(raw[offset+SniffSizeOffs.json:offset+SniffSizeOffs.json+RAWSIZE], 16)
            return (kind, size)

        offset = raw.find(Sniffs.mgpk)
        if 5 <= offset <=  12:  #  msgpack serialization
            kind = Serials.mgpk
            size = int(raw[offset+SniffSizeOffs.mgpk:offset+SniffSizeOffs.mgpk+RAWSIZE], 16)
            return (kind, size)

        offset = raw.find(Sniffs.cbor)
        if 5 <= offset <=  12:  #  msgpack serialization
            kind = Serials.cbor
            size = int(raw[offset+SniffSizeOffs.cbor:offset+SniffSizeOffs.cbor+RAWSIZE], 16)
            return (kind, size)

       # unknown serializaiton kind
        raise ValueError("Unrecognized serialization ser='{}'".format(raw))


    def _inhale(self, raw, kind, size):
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
        if kind == Serials.json:
            try:
                ked = json.loads(raw.decode("utf-8"))
            except Exception as ex:
                raise ex

        elif kind == Serials.mgpk:
            try:
                ked = msgpack.loads(raw)
            except Exception as ex:
                raise ex

        elif kind ==  Serials.cbor:
            try:
                ked = cbor.loads(raw)
            except Exception as ex:
                raise ex

        else:
            ked = None

        return ked


    def _exhale(self, kind=None, ked=None):
        """
        ked is key event dict
        Returns serialized event as bytes of kind
        """
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        if not ked:
            raise ValueError("Missing or empty key event dict = {}".format(ked))

        if kind == Serials.json:
            raw = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        elif kind == Serials.mgpk:
            raw = msgpack.dumps(ked)
        elif kind == Serials.cbor:
            raw = cbor.dumps(ked)
        else:
            raw = b""

        return raw

