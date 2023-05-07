# -*- encoding: utf-8 -*-
"""
keri.core.serdering module

"""
import json
from collections import namedtuple

import cbor2 as cbor
import msgpack

from .. import kering
from ..kering import (ValidationError, SerDesError, MissingElementError,
                      VersionError, UnexpectedCodeError, ShortageError, )

from ..core import coring
from .coring import Rever, versify, deversify, Version, Versionage
from .coring import Protos, Serials, MtrDex, DigDex, PreDex
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

    To support a new protocol with its ilks, add a protocol specific subclass,
    override the Labels class attribute, and if necessary the .verify and
    .saidify methods and define any protocol specific properties. If necessary
    define ilk specific subclasses of a given protocol (ilk is packet type).
    The .Labels class attributes configures the field label(s) for said
    generation and verification in addition to the required fields.

    Class Attributes:
        MaxVSOffset (int): Maximum Version String Offset in bytes/chars
        InhaleSize (int): Minimum raw buffer size needed to inhale
        Labels (dict): Protocol specific dict of field labels keyed by ilk
            (packet type string value). None is default key when no ilk needed.
            Each entry is a

    Properties:
        raw (bytes): of serialized event only
        sad (dict): self addressed data dict
        proto (str): Protocolage value as protocol identifier such as KERI, ACDC
        version (Versionage): protocol version (Major, Minor)
        kind (str): serialization kind coring.Serials such as JSON, CBOR, MGPK, CESR
        size (int): number of bytes in serialization
        saider (Saider): of SAID of this SAD as given by .Labels for this ilk
        said (str): SAID of .saider qb64
        saidb (bytes): SAID of .saider  qb64b
        ilk (str | None): packet type for this Serder if any (may be None)


    Hidden Attributes:
        ._raw is bytes of serialized event only
        ._sad is key event dict
        ._proto (str):  Protocolage value as protocol type identifier
        ._version is Versionage instance of event version
        ._kind is serialization kind string value (see namedtuple coring.Serials)
          supported kinds are 'json', 'cbor', 'msgpack', 'binary'
        ._size is int of number of bytes in serialed event only
        ._saider (Saider): instance for this Sadder's SAID
        ._dcode (str): digest derivation code value of DigDex
        ._pcode (str): prefix derivation code value of MtrDex

    Methods:
        pretty(size: int | None ) -> str: Prettified JSON of this SAD

    Note:
        loads and jumps of json use str whereas cbor and msgpack use bytes

    ToDo:
        verify
            add fields check for required fields
        saidify

        Errors for extraction versus verification

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
                 dcode=DigDex.Blake3_256, pcode=PreDex.Blake3_256):
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
                Ignore when raw not provided and saidify is True
            saidify (bool): True means compute and replace said(s) for sad
                when raw not provided
            dcode (str): default said digest code (DigDex value)
                for computing said(s) and .saider
            pcode (str): default prefix code when message is inceptive
                if prefix is a said then pcode must be in DigDex.


        """
        if dcode not in DigDex:
            raise UnexpectedCodeError(f"Invalid digest code = {dcode}.")
        self._dcode = dcode  # need default code for saidify
        if pcode not in PreDex:
            raise UnexpectedCodeError(f"Invalid prefix code = {pcode}.")
        self._pcode = pcode  # need default code for saidify when saided prefix

        if raw:  # deserialize raw using property setter
            # raw setter also sets sad, proto, version, kind, and size from raw
            self.raw = raw  # raw property setter does the deserialization

            if strip:  # assumes raw is bytearray
                del raw[:self.size]

            if verify:  # verify the said(s) provided in raw
                if not self.verify():
                    raise ValidationError(f"Invalid said(s) for sad = "
                                          f"{self.pretty()}")

        elif sad:  # serialize sad into raw using sad property setter
            self._kind = kind  # does not trigger .kind property setter.
            self.sad = sad  # sad property setter does the serialization
            # sad setter also sets raw, proto, version, kind, and size from sad

            if saidify:  # recompute said(s) and reset sad
                # saidify resets sad, raw, proto, version, kind, and size
                self.saidify()

            elif verify:  # verify the said(s) provided in sad
                if not self.verify():
                    raise ValidationError(f"Invalid said(s) for sad = "
                                          f"{self.pretty()}")

        else:
            raise ValueError("Improper initialization need raw or sad.")


    def verify(self):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Returns:
            verify (bool): True if said(s) verify. False otherwise
        """
        for label in self.Labels[self.ilk].fields:
            if label not in self.sad:
                return False
        return True


    def saidify(self, dcode=None, pcode=None):
        """Saidify given .sad and resets raw, sad, proto, version, kind, and size
        Override for protocol and ilk specific saidification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Parameters:
            dcode (str): value of DigDex DigCodex for computed saids
            pcode (str): value of MatDex MatterCodes for computed saidified prefix


        """
        if dcode is not None and dcode in DigDex:
            self._dcode = dcode
        if pcode is not None and pcode in PreDex:
            self._pcode = pcode

        for label in self.Labels[self.ilk].saids:
            if label not in self.sad:
                return False

        pass


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
            raise SerDesError(f"Invalid protocol type = {proto}.")

        vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
        if vrsn != version:
            raise VersionError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")

        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise SerDesError(f"Invalid serialization kind = {kind}.")

        size = int(size, 16)
        if len(raw) < size:
            raise ShortageError(f"Need more bytes.")

        sad = cls.loads(raw=raw, size=size, kind=kind)

        if "v" not in sad:
            raise SerDesError(f"Missing version string field in {sad}.")

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
                raise SerDesError(f"Error deserializing JSON: "
                    f"{raw[:size].decode('utf-8')}") from ex

        elif kind == Serials.mgpk:
            try:
                sad = msgpack.loads(raw[:size])
            except Exception as ex:
                raise SerDesError(f"Error deserializing MGPK: "
                    f"{raw[:size].decode('utf-8')}") from ex

        elif kind == Serials.cbor:
            try:
                sad = cbor.loads(raw[:size])
            except Exception as ex:
                raise SerDesError(f"Error deserializing CBOR: "
                    f"{raw[:size].decode('utf-8')}") from ex

        else:
            raise SerDesError(f"Invalid deserialization kind: {kind}")

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
            raise SerDesError(f"Missing version string field in {sad}.")

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
            raise ValueError(f"Invalid serialization kind = {kind}")

        return raw


    def pretty(self, *, size=None):
        """Utility method to pretty print .sad as JSON str.
        Returns:
            pretty (str):  JSON of .sad with pretty formatting

        Pararmeters:
            size (int | None): size limit. None means not limit.
                Enables protection against syslog error when
                exceeding UDP MTU (max trans unit) for syslog applications.
                Guaranteed IPv4 MTU is 576, and IPv6 MTU is 1280.
                Most broadband routers have an UDP MTU set to 1454.
                Must include not just payload but UDP/IP header in
                MTU calculation. So must leave room for either UDP/IpV4 or
                the bigger UDP/IPv6 header.
                Except for old IoT hardware, modern implementations all
                support IPv6 so 1024 is usually a safe value for payload.
        """
        return json.dumps(self.sad, indent=1)[:size]


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
        self._sad = sad  # does not trigger .sad property setter
        self._proto = proto
        self._version = vrsn
        self._kind = kind  # does not trigger kind setter
        self._size = size
        label = self.Labels[self.ilk].saids[0]  # primary said field label
        if label not in self._sad:
            raise SerDesError(f"Missing primary said field in {self._sad}.")
        self._saider = Saider(qb64=self._sad[label])
        # ._saider is not yet verified


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
        self._raw = raw  # does not trigger raw setter
        self._sad = sad  # does not trigger sad setter
        self._proto = proto
        self._version = vrsn
        self._kind = kind  # does not trigger kind setter
        self._size = size
        label = self.Labels[self.ilk].saids[0]  # primary said field label
        if label not in self._sad:
            raise SerDesError(f"Missing primary said field in {self._sad}.")
        self._saider = Saider(qb64=self._sad[label])
        # ._saider is not yet verified


    @property
    def kind(self):
        """kind property getter
        Returns:
            kind (str): value of Serials (Serialage)"""
        return self._kind


    @kind.setter
    def kind(self, kind):
        """kind property setter Assumes ._sad. Serialization kind.
        Forces update of other derived properties
        """
        raw, sad, proto, vrsn, kind, size = self._exhale(sad=self.sad, kind=kind)
        self._raw = raw  # does not trigger raw setter
        self._sad = sad  # does not trigger sad setter
        self._proto = proto
        self._version = vrsn
        self._kind = kind  # does not trigger kind setter
        self._size = size
        label = self.Labels[self.ilk].saids[0]  # primary said field label
        if label not in self._sad:
            raise SerDesError(f"Missing primary said field in {self._sad}.")
        self._saider = Saider(qb64=self._sad[label])
        # ._saider is not yet verified


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


    @property
    def ilk(self):
        """ilk property getter
        Returns:
            ilk (str): pracket type given by sad['t'] if any
        """
        return self.sad.get('t')  # returns None if 't' not in sad

