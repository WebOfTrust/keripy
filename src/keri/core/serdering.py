# -*- encoding: utf-8 -*-
"""
keri.core.serdering module

"""
import json
from collections import namedtuple

from ..kering import (EmptyMaterialError, RawMaterialError, DerivationError,
                         ShortageError, InvalidCodeSizeError, InvalidVarIndexError,
                         InvalidValueError, )
from ..kering import ValidationError, DeserializationError, VersionError

from ..core import coring
from .coring import Rever, Vstrings, versify, deversify, Version, Versionage
from .coring import Protos, Serials, MtrDex, DigDex
from .coring import Saider


Labelage = namedtuple("Labelage", "saids fields")  #values are lists of str
# saids is list of saided field labels
# fields is list of all field labels including saided ones
# Label = Labelage(saids=['d'], fields=['v','d'])  # minimum required

class Serdery:
    """Serder factory class for generating serder instances from streams.
    """


class Serder:
    """Serder is serializer-deserializer class for saidified  over-the-wire
    messages that deserializes to a field map (label value pairs) from
    either a serialized field map or an unlabeled fixed field structure with
    affiliated label list. The messages must include a version string field
    with proto (protocol), version, kind, and size elements or equivalent
    header with same elements. The messages may have an optional ilk field
    that is protocol specific. Protocols that have fixed  top-level fields
    also perform label inclusion validation.

    Message saidification and verification may be dependent on protocol and
    optionally ilk specific field label(s) and digest code type for its SAID(s).

    The base Serder class provides the common properties for all messages for
    all protocols. Each subclass is protocol based and adds properties that are
    required for all message ilks in a given protocol. Each protocol subclass
    may have dynamically injected ilk specific properties (as descriptors)
    if any.

    To support a new protocol, add a protocol specific subclass and update
    the superclass supervised injection of ilk specific property descriptors.
    Define the  class variables that configure field label(s) for said
    generation and verification.

    To support a new ilk for a given protocol, update the class variables for
    label validation and define ilk specific property descriptors for injection.
    Update the class variables that configure field label(s) for said
    generation and verification.

    Class Attributes:
        MaxVSOffset (int): Maximum Version String Offset in bytes/chars
        InhaleSize (int): Minimum raw buffer size needed to inhale
        Labels (dict): Protocol specific dict of field labels keyed by ilk
            (packet type string value). None is default key when no ilk needed.
            Each entry is a

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
    InhaleSize = MaxVSOffset + coring.VERFULLSIZE  # min buffer size to inhale

    # Protocol specific field labels dict, keyed by ilk (packet type string).
    # value of each entry is Labelage instance that provides saided field labels
    # and all field labels
    # A key of None is default when no ilk required
    # Override in sub class that is protocol specific
    Labels = {None: Labelage(saids=['d'], fields=['v','d'])}


    def __init__(self, *, raw=b'', sad=None, kind=None, strip=False,
                 verify=False, saidify=False,
                 dcode=MtrDex.Blake3_256, pcode=MtrDex.Blake3_256):
        """Deserialize raw if provided. Update properties from deserialized raw.
            Verifies said(s) embedded in sad as given by labels.
            When verify is True then verify said(s) in deserialized raw as
            given by label(s) according to proto and ilk and code
        If raw not provided then serialize .raw from sad with kind and code.
            When kind not provided use kind embedded in sad['v'] version string.
            When saidify is True then compute and update said(s) in sad as
            given by label(s) according to proto and ilk and code.

        Parameters:
            raw (bytes): serialized event
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            kind is serialization kind string value or None (see namedtuple coring.Serials)
                supported kinds are 'json', 'cbor', 'msgpack', 'binary'
                if kind is None then its extracted from ked or raw
            strip (bool): True means strip (delete) raw from input stream
                bytearray after parsing. False means do not strip.
                Assumes that raw is bytearray when strip is True.
            verify (bool): True means verify said(s) of given raw or sad.
                Raises ValidationError if verification fails
            saidify (bool): True means compute and replace said(s) for sad
            dcode (str): default said digest code (DigDex value)
                for computing said(s) and .saider
            pcode (str): default prefix code when message is inceptive
                if prefix is a said then pcode must be in DigDex.


        """
        self._dcode = dcode  # need default code saidifying and for .saider
        self._pcode = dcode  # need default code for verifying saided prefix
        if raw:  # deserialize raw using property setter
            self.raw = raw  # raw property setter does the deserialization
            # sets sad, kind, and code from raw
            # verifies said
            if strip:  # assumes raw is bytearray
                del raw[:self.size]
        elif sad:  # serialize sad using property setter
            self._kind = kind
            self.sad = sad  # sad property setter does the serialization
        else:
            raise ValueError("Improper initialization need raw or sad.")


    @classmethod
    def _inhale(cls, raw, version=Version):
        """Deserializes raw.
        Parses serilized event ser of serialization kind and assigns to
        instance attributes and returns tuple of associated elements.

        Returns: tuple (sad, proto, vrsn, kind, size) where:
           sad (dict): serializable attribute dict of saidified data
           proto (str): value of Protos (Protocolage) protocol type
           vrsn (Versionage): tuple of (major, minor) version ints
           kind (str): value of Serials (Serialage) serialization kind

        Parameters:
           raw (bytes): serialized sad message
           version (Versionage): instance supported protocol version

        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes
          Assumes only supports Version

        """
        if len(raw) < cls.InhaleSize:
            raise ShortageError(f"Need more raw bytes for Serder to inhale.")

        match = Rever.search(raw)  # Rever's regex takes bytes
        if not match or match.start() > cls.MaxVSOffset:
            raise VersionError(f"Invalid version string in raw = {raw}.")

        proto, major, minor, kind, size = match.group("proto",
                                                      "major",
                                                      "minor",
                                                      "kind",
                                                      "size")

        proto = proto.decode("utf-8")
        if proto not in Protos:
            raise DeserializationError(f"Invalid protocol type = {proto}.")

        vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
        if vrsn != version:
            raise VersionError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")

        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise DeserializationError(f"Invalid serialization kind = {kind}.")

        size = int(size, 16)
        if len(raw) < size:
            raise ShortageError(f"Need more bytes.")

        sad = cls.loads(raw=raw, size=size, kind=kind)

        return sad, proto, version, kind, size


    @staticmethod
    def loads(raw, size=None, kind=Serials.json):
        """Utility static method to handle deserialization by kind

        Returns:
           sad (dict | list): deserialized dict or list. Assumes attribute
                dict of saidified data.

        Parameters:
           raw (bytes |bytearray): raw serialization to deserialze as dict
           size (int): number of bytes to consume for the deserialization.
                       If None then consume all bytes in raw
           kind (str): value of Serials (Serialage) serialization kind
                       "JSON", "MGPK", "CBOR"
        """
        if kind == Serials.json:
            try:
                sad = json.loads(raw[:size].decode("utf-8"))
            except Exception as ex:
                raise DeserializationError("Error deserializing JSON: {}"
                                           "".format(raw[:size].decode("utf-8")))

        elif kind == Serials.mgpk:
            try:
                sad = msgpack.loads(raw[:size])
            except Exception as ex:
                raise DeserializationError("Error deserializing MGPK: {}"
                                           "".format(raw[:size]))

        elif kind == Serials.cbor:
            try:
                sad = cbor.loads(raw[:size])
            except Exception as ex:
                raise DeserializationError("Error deserializing CBOR: {}"
                                           "".format(raw[:size]))

        else:
            raise DeserializationError("Invalid deserialization kind: {}"
                                       "".format(kind))

        return sad


    @classmethod
    def _exhale(cls, sad, kind=None, version=Version):
        """Serializes sad given kind and version

        Returns tuple of (raw, proto, kind, sad, vrsn) where:
            raw (str): serialized event as bytes of kind
            proto (str): protocol type as value of Protocolage
            kind (str): serialzation kind as value of Serialage
            sad (dict): modified serializable attribute dict of saidified data
            vrsn (Versionage): tuple value (major, minor)

        Parameters:
            sad (dict): serializable attribute dict of saidified data
            kind (str): value of Serials serialization kind. If provided
                override that given in sad["v"]
            version (Versionage): instance supported protocol version for message


        """
        if "v" not in sad:
            raise ValueError(f"Missing or empty version string in sad "
                             "dict = {sad}")

        proto, knd, vrsn, size = deversify(sad["v"])  # extract elements

        if proto not in Protos:
            raise ValueError(f"Invalid protocol type = {proto}.")

        if vrsn != version:
            raise VersionError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")

        if not kind:
            kind = knd

        if kind not in Serials:
            raise ValueError(f"Invalid serialization kind = {kind}")

        raw = cls.dumps(sad, kind)
        size = len(raw)

        # generate new version string with correct size and desired kind
        vs = versify(proto=proto, version=vrsn, kind=kind, size=size)

        # find location of old version string inside raw
        match = Rever.search(raw)  # Rever's regex takes bytes
        if not match or match.start() > 12:
            raise ValueError(f"Invalid version string in raw = {raw}.")
        fore, back = match.span()  # start and end positions of version string

        # replace old version string in raw with new one
        raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
        if size != len(raw):  # substitution messed up
            raise ValueError(f"Malformed size of raw in version string == {vs}")
        sad["v"] = vs  # update sad

        return raw, sad, proto, vrsn, kind, size


    @staticmethod
    def dumps(sad, kind=Serials.json):
        """Utility static method to handle serialization by kind

        Returns:
           raw (bytes): serialization of sad dict using serialization kind

        Parameters:
           sad (dict | list)): serializable dict or list to serialize
           kind (str): value of Serials (Serialage) serialization kind
                "JSON", "MGPK", "CBOR"
        """
        if kind == Serials.json:
            raw = json.dumps(sad, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")

        elif kind == Serials.mgpk:
            raw = msgpack.dumps(sad)

        elif kind == Serials.cbor:
            raw = cbor.dumps(sad)
        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        return raw


    def pretty(self, *, size=1024):
        """Utility method to pretty print .sad as JSON str.
        Returns:
            pretty (str):  JSON of .sad with pretty formatting

        Pararmeters:
            size (int): size limit. Default protects against error when
                exceeding UDP MTU (max trans unit) for syslog applications.
                Guaranteed IPv4 MTU is 576, and IPv6 MTU is 1280.
                Most broadband routers have an UDP MTU set to 1454.
                Must include not just payload but UDP/IP header in
                MTU calculation. So must leave room for either UDP/IpV4 or
                the bigger UDP/IPv6 header.
                Except for old IoT hardware, modern implementations all
                support IPv6 so 1024 is usually a safe value for payload.
        """
        return json.dumps(self.sad, indent=1)[:size if size is not None else None]


    def compare(self, said=None):
        """Utility method to allow comparison of own .said digest of .raw
        with some other purported said of .raw

        Returns:
            success (bool): True if said matches self.saidb  via string
               equality. Converts said to bytes if unicode


        Parameters:
            said (bytes | str): qb64b or qb64 digest to compare with .said
        """
        if said is not None:
            if hasattr(said, "encode"):
                said = said.encode('utf-8')  # makes bytes

            return said == self.saidb  # str match bool

        else:
            raise ValueError(f"Uncomparable saids.")


    @property
    def raw(self):
        """raw property getter
        Returns:
            raw (bytes):  serialized version
        """
        return self._raw


    @raw.setter
    def raw(self, raw):
        """raw property setter
        Forces update of other derived properties
        """
        sad, proto, vrsn, kind, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._sad = sad
        self._proto = proto
        self._version = vrsn
        self._kind = kind
        self._size = size
        self._saider = Saider(qb64=sad["d"], code=self._dcode)
        # ToDo  check what happens with code above


    @property
    def sad(self):
        """sad property getter
        Returns:
            sad (dict): serializable attribute dict (saidified data)
        """
        return self._sad


    @sad.setter
    def sad(self, sad):
        """sad property setter  assumes ._kind
        Forces update of other derived properties
        """
        raw, sad, proto, vrsn, kind, size = self._exhale(sad=sad, kind=self.kind)
        self._raw = raw[:size]
        self._sad = sad
        self._proto = proto
        self._version = vrsn
        self._kind = kind
        self._size = size
        self._saider = Saider(qb64=sad["d"], code=self._dcode)
        # ToDo  check what happens with code above


    @property
    def kind(self):
        """kind property getter
        Returns:
            kind (str): value of Serials (Serialage)"""
        return self._kind


    @kind.setter
    def kind(self, kind):
        """kind property setter Assumes ._ked. Serialization kind.
        Forces update of other derived properties
        """
        raw, sad, proto, vrsn, kind, size = self._exhale(sad=self.sad, kind=kind)
        self._raw = raw[:size]
        self._sad = sad
        self._proto = proto
        self._version = vrsn
        self._kind = kind
        self._size = size
        self._saider = Saider(qb64=sad["d"], code=self._dcode)
        # ToDo  check what happens with code above


    @property
    def proto(self):
        """proto property getter
        protocol identifer type value of Protocolage such as 'KERI' or 'ACDC'

        Returns:
            proto (str): Protocolage value as protocol type
        """
        return self._proto


    @property
    def version(self):
        """version property getter

        Returns:
            version (Versionage): instance
        """
        return self._version


    @property
    def size(self):
        """size property getter
        Returns:
            size (int): number of bytes in .raw
        """
        return self._size


    @property
    def saider(self):
        """saider property getter
        Returns:
            saider (Diger): instance of saidified digest self.raw
        """
        return self._saider


    @property
    def said(self):
        """said property getter
        Returns:
           said (str): qb64 said of .saider
        """
        return self.saider.qb64


    @property
    def saidb(self):
        """saidb property getter
        Returns:
            saidb (bytes): qb64b of said  of .saider
        """
        return self.saider.qb64b
