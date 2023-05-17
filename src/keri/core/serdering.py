# -*- encoding: utf-8 -*-
"""
keri.core.serdering module

"""
import json
from collections import namedtuple

import cbor2 as cbor
import msgpack
import pysodium
import blake3
import hashlib

from .. import kering
from ..kering import (ValidationError,  MissingFieldError,
                      ShortageError, VersionError, ProtocolError, KindError,
                      DeserializeError, FieldError, SerializeError)

from ..core import coring
from .coring import Rever, versify, deversify, Version, Versionage, Ilks
from .coring import Protos, Serials, MtrDex, DigDex, PreDex
from .coring import Matter, Diger, Saider, Digestage

from .. import help


logger = help.ogler.getLogger()

"""
Labelage
    saids (list[str]): saidive field labels
    codes (list[str]): saidive field codes
    fields (list[str]): all field labels including saidive ones

Example:
    Label = Labelage(saids=['d'], codes=[DigDex.Blake3_256], fields=['v','d'])
"""
Labelage = namedtuple("Labelage", "saids codes fields")  #values are lists of str



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

    Methods:
        verify()
        _verify()
        makify()
        compare()
        pretty(size: int | None ) -> str: Prettified JSON of this SAD

    ClassMethods:
        _inhale()
        _exhale()

    StaticMethods:
        loads()
        dumps()

    Note:
        loads and jumps of json use str whereas cbor and msgpack use bytes

    """

    MaxVSOffset = 12
    InhaleSize = MaxVSOffset + coring.VERFULLSIZE  # min buffer size to inhale

    Dummy = "#"  # dummy spaceholder char for said. Must not be a valid Base64 char

    # should be same set of codes as in coring.DigestCodex coring.DigDex so
    # .digestive property works. Use unit tests to ensure codex sets match
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

    Proto = Protos.keri  # default protocol type
    Vrsn = Version  # default protocol version for protocol type
    Kind = Serials.json  # default serialization kind
    Code = DigDex.Blake3_256  # default said field code

    # Protocol specific field labels dict, keyed by ilk (packet type string).
    # value of each entry is Labelage instance that provides saidive field labels,
    # codes, and all field labels
    # A key of None is default when no ilk required
    # Override in sub class that is protocol specific
    Labels = {None: Labelage(saids=['d'],
                             codes=[DigDex.Blake3_256],
                             fields=['v','d'])}




    def __init__(self, *, raw=b'', sad=None, strip=False, version=Version,
                 verify=True, makify=False,
                 proto=None, vrsn=None, kind=None, codes=None):
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
            strip (bool): True means strip (delete) raw from input stream
                bytearray after parsing. False means do not strip.
                Assumes that raw is bytearray when strip is True.
            version (Versionage | None): instance supported protocol version
                None means do not enforce a supported version
            verify (bool): True means verify said(s) of given raw or sad.
                Raises ValidationError if verification fails
                Ignore when raw not provided or when raw and saidify is True
            makify (bool): True means compute fields for sad including size and
                saids.
            proto (str | None): desired protocol type str value of Protos
                If None then its extracted from raw or sad or uses default .Proto
            vrsn (Versionage | None): instance desired protocol version
                If None then its extracted from raw or sad or uses default .Vrsn
            kind (str None): serialization kind string value of Serials
                supported kinds are 'json', 'cbor', 'msgpack', 'binary'
                If None then its extracted from raw or sad or uses default .Kind
            codes (list[str]): of codes for saidive fields in .Labels[ilk].saids
                one for each said in same order of .Labels[ilk].saids


        """

        if raw:  # deserialize raw using property setter
            # self._inhale works because it only references class attributes
            sad, proto, vrsn, kind, size = self._inhale(raw=raw, version=version)
            self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
            self._sad = sad
            self._proto = proto
            self._version = vrsn
            self._kind = kind
            self._size = size
            label = self.Labels[self.ilk].saids[0]  # primary said field label
            if label not in self._sad:
                raise FieldError(f"Missing primary said field in {self._sad}.")
            self._saider = Saider(qb64=self._sad[label]) # saider not verified

            if strip:  # assumes raw is bytearray
                del raw[:self._size]

            if verify:  # verify the said(s) provided in raw
                try:
                    self._verify()  # raises exception when not verify
                except Exception as ex:
                    logger.error("Invalid raw for Serder %s\n%s",
                                 self.pretty(), ex.args[0])
                    raise ValidationError(f"Invalid raw for Serder"
                                          f"\n{self.pretty()}\n.") from ex

        elif sad:  # serialize sad into raw using sad property setter
            if makify:  # recompute properties and said(s) and reset sad
                # makify resets sad, raw, proto, version, kind, and size
                self.makify(sad=sad, version=version,
                            proto=proto, vrsn=vrsn, kind=kind, codes=codes)

            else:
                # self._exhale works because it only access class attributes
                raw, sad, proto, vrsn, kind, size = self._exhale(sad=sad,
                                                                 version=version)
                self._raw = raw
                self._sad = sad
                self._proto = proto
                self._version = vrsn
                self._kind = kind
                self._size = size
                label = self.Labels[self.ilk].saids[0]  # primary said field label
                if label not in self._sad:
                    raise DeserializeError(f"Missing primary said field in {self._sad}.")
                self._saider = Saider(qb64=self._sad[label]) # saider not verified

                if verify:  # verify the said(s) provided in sad
                    try:
                        self._verify()  # raises exception when not verify
                    except Exception as ex:
                        logger.error("Invalid sad for Serder %s\n%s",
                                     self.pretty(), ex.args[0])
                        raise ValidationError(f"Invalid raw for Serder"
                                              f"\n{self.pretty()}\n.") from ex

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
        try:
            self._verify()
        except Exception as ex:              # log validation error here
            logger.error("Invalid Serder: %s\n for %s\n",
                         ex.args[0], self.pretty())

            return False

        return True


    def _verify(self):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Raises a ValidationError (or subclass) if any verification fails

        """
        if self.ilk not in self.Labels:
            raise ValidationError(f"Invalid packet type (ilk) = {self.ilk} for"
                                  f"protocol = {self.proto}.")

        # ensure required fields are in sad
        fields = self.Labels[self.ilk].fields  # all field labels
        keys = list(self.sad)  # get list of keys of self.sad
        for key in list(keys):  # make copy to mutate
            if key not in fields:
                del keys[key]  # remove non required fields

        if fields != keys:  # forces ordered appearance of labels in .sad
            raise MissingFieldError(f"Missing required fields = {fields}"
                                      f" in sad = \n{self.pretty()}")

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        saids = self.Labels[self.ilk].saids  # saidive field labels
        if not (set(saids) <= set(fields)):
            raise MissingFieldError(f"Missing required said fields = {saids}"
                                      f" in sad = \n{self.pretty()}")

        sad = dict(self.sad)  # make shallow copy so don't clobber original .sad
        labCodes = {}  # dict of codes keyed by label
        for label in saids:
            value = sad[label]
            try:
                code = Matter(qb64=value).code
            except Exception as ex:
                raise ValidationError(f"Invalid said field '{label}' in sad\n"
                                  f" =  {self.pretty()}") from ex

            if code in DigDex:  # if digestive then fill with dummy
                sad[label] = self.Dummy * len(value)

            labCodes[label] = code

        raw = self.dumps(sad, kind=self.kind)  # serialize dummied sad copy

        for label, code in labCodes.items():
            if code in DigDex:  # subclass override if non digestive allowed
                klas, size, length = self.Digests[code]  # digest algo size & length
                ikwa = dict()  # digest algo class initi keyword args
                if size:
                    ikwa.update(digest_size=size)  # optional digest_size
                dkwa = dict()  # digest method keyword args
                if length:
                    dkwa.update(length=length)
                dig = Matter(raw=klas(raw, **ikwa).digest(**dkwa), code=code).qb64
                if dig != self.sad[label]:  # compare to original
                    raise ValidationError(f"Invalid said field '{label}' in sad"
                                          f" = \n{self.pretty()}")
                sad[label] = dig

        raw = self.dumps(sad, kind=self.kind)
        if raw != self.raw:
            raise ValidationError(f"Invalid round trip of = sad = \n"
                                  f"{self.pretty()}")
        # verified successfully since no exception


    def makify(self, sad, *, version=None,
               proto=None, vrsn=None, kind=None, codes=None):
        """Makify given sad dict makes the versions string and computes the said
        field values and sets associated properties:
        raw, sad, proto, version, kind, size

        Override for protocol and ilk specific saidification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Default prioritization.
           Use method parameter if not None
           Else use provided version string if valid
           Otherwise use class attribute


        Parameters:
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            version (Versionage): instance supported protocol version
                None means do not enforce version
            proto (str | None): desired protocol type str value of Protos
                If None then its extracted from raw or sad or uses default .Proto
            vrsn (Versionage | None): instance desired protocol version
                If None then its extracted from raw or sad or uses default .Vrsn
            kind (str None): serialization kind string value of Serials
                supported kinds are 'json', 'cbor', 'msgpack', 'binary'
                If None then its extracted from raw or sad or uses default .Kind
            codes (list[str]): of codes for saidive fields in .Labels[ilk].saids
                one for each said in same order of .Labels[ilk].saids
                If empty list then use defaults
                If entry is None then use default
                Code assignment for each said field in desending priority:
                   the code provided in codes when not None
                   the code extracted from sad[said label] when valid CESR
                   self.Code



        """
        if 'v' not in sad:
            raise SerializeError(f"missing version string field 'v'. in sad = "
                                  f"\n{self.pretty()}.")

        try:  # extract version string elements as defaults if provided
            sproto, svrsn, skind, _ = deversify(sad["v"], version=version)
        except ValueError as ex:
            sproto = self.Proto
            svrsn = self.Vrsn
            skind = self.Kind

        proto = proto if proto is not None else sproto
        vrsn = vrsn if vrsn is not None else svrsn
        kind = kind if kind is not None else skind

        if proto not in Protos:
            raise SerializeError(f"Invalid protocol type = {proto}.")

        if version is not None and vrsn != version:
            raise SerializeError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")

        if kind not in Serials:
            raise SerializeError(f"Invalid serialization kind = {kind}")

        sad['v'] = self.Dummy * coring.VERFULLSIZE  # ensure size of vs

        ilk = sad.get('t')
        if ilk not in self.Labels:
            raise SerializeError(f"No field labels for packet type (ilk) = "
                                  f"{ilk} .")
        # ensure required fields are in sad
        fields = self.Labels[ilk].fields  # all field labels
        keys = list(sad)  # get list of keys of self.sad
        for key in list(keys):  # make copy to mutate
            if key not in fields:
                del keys[key]  # remove non required fields

        if fields != keys:  # forces ordered appearance of labels in .sad
            raise SerializeError(f"Missing one or more required fields = {fields}"
                                          f" in sad = \n{self.pretty()}")

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        saids = self.Labels[ilk].saids
        if not (set(saids) <= set(fields)):
            raise SerializeError(f"Missing one or more required said fields = {saids}"
                                          f" in sad = \n{self.pretty()}")

        labCodes = {}  # compute mapping of said labeled fields to codes
        for i, label in enumerate(saids):
            try:
                code = codes[i]
            except (IndexError, TypeError):
                code = None

            if code is None:
                value = sad[label]
                try:
                    code = Matter(qb64=value).code
                except Exception:
                    code = self.Code
                    # This code assumes that any non-digestive saidive fields
                    # in sad must have valid CESR. Otherwise override in subclass

            if code in DigDex:  # if digestive then fill with dummy
                sad[label] = self.Dummy * Matter.Sizes[code].fs

            labCodes[label] = code


        raw = self.dumps(sad, kind)  # get size of fully dummied sad
        size = len(raw)

        # generate new version string with correct size
        vs = versify(proto=proto, version=vrsn, kind=kind, size=size)
        sad["v"] = vs  # update sad

        # now have correctly sized version string in sad
        # now compute saidive digestive field values using sized dummied sad
        raw = self.dumps(sad, kind=kind)  # serialize sized dummied sad

        for label, code in labCodes.items():
            if code in DigDex:  # subclass override if non digestive allowed
                klas, dsize, dlen = self.Digests[code]  # digest algo size & length
                ikwa = dict()  # digest algo class initi keyword args
                if dsize:
                    ikwa.update(digest_size=dsize)  # optional digest_size
                dkwa = dict()  # digest method keyword args
                if dlen:
                    dkwa.update(length=dlen)
                dig = Matter(raw=klas(raw, **ikwa).digest(**dkwa), code=code).qb64
                sad[label] = dig

        raw = self.dumps(sad, kind=kind)  # compute final raw

        self._raw = raw
        self._sad = sad
        self._proto = proto
        self._version = vrsn
        self._kind = kind
        self._size = size
        label = self.Labels[self.ilk].saids[0]  # primary said field label
        self._saider = Saider(qb64=self._sad[label]) # implicitly verified


    @classmethod
    def _inhale(clas, raw, version=Version):
        """Deserializes raw.
        Parses serilized event ser of serialization kind and assigns to
        instance attributes and returns tuple of associated elements.

        As classmethod enables testing parsing raw serder values. This can be
        called on self as well because it only ever accesses clas attributes
        not instance attributes.

        Returns: tuple (sad, proto, vrsn, kind, size) where:
            sad (dict): serializable attribute dict of saidified data
            proto (str): value of Protos (Protocolage) protocol type
            vrsn (Versionage | None): tuple of (major, minor) version ints
                None means do not enforce version
            kind (str): value of Serials (Serialage) serialization kind

        Parameters:
            raw (bytes): serialized sad message
            version (Versionage): instance supported protocol version

        Note:
            loads and jumps of json use str whereas cbor and msgpack use bytes
            Assumes only supports Version

        """
        if len(raw) < clas.InhaleSize:
            raise ShortageError(f"Need more raw bytes for Serder to inhale.")

        match = Rever.search(raw)  # Rever's regex takes bytes
        if not match or match.start() > clas.MaxVSOffset:
            raise VersionError(f"Invalid version string in raw = {raw}.")

        proto, major, minor, kind, size = match.group("proto",
                                                      "major",
                                                      "minor",
                                                      "kind",
                                                      "size")

        proto = proto.decode("utf-8")
        if proto not in Protos:
            raise ProtocolError(f"Invalid protocol type = {proto}.")

        vrsn = Versionage(major=int(major, 16), minor=int(minor, 16))
        if version is not None and vrsn != version:
            raise VersionError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")

        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise KindError(f"Invalid serialization kind = {kind}.")

        size = int(size, 16)
        if len(raw) < size:
            raise ShortageError(f"Need more bytes.")

        sad = clas.loads(raw=raw, size=size, kind=kind)

        if "v" not in sad:
            raise FieldError(f"Missing version string field in {sad}.")

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
                raise DeserializeError(f"Error deserializing JSON: "
                    f"{raw[:size].decode('utf-8')}") from ex

        elif kind == Serials.mgpk:
            try:
                sad = msgpack.loads(raw[:size])
            except Exception as ex:
                raise DeserializeError(f"Error deserializing MGPK: "
                    f"{raw[:size].decode('utf-8')}") from ex

        elif kind == Serials.cbor:
            try:
                sad = cbor.loads(raw[:size])
            except Exception as ex:
                raise DeserializeError(f"Error deserializing CBOR: "
                    f"{raw[:size].decode('utf-8')}") from ex

        else:
            raise DeserializeError(f"Invalid deserialization kind: {kind}")

        return sad


    @classmethod
    def _exhale(clas, sad, version=None):
        """Serializes sad given kind and version and sets the serialized size
        in the version string.

        As classmethod enables bootstrap of valid sad dict that has correct size
        in version string. This obviates sizeify. This can be called on self as
        well because it only ever accesses clas attributes not instance attributes.

        Returns tuple of (raw, proto, kind, sad, vrsn) where:
            raw (str): serialized event as bytes of kind
            proto (str): protocol type as value of Protocolage
            kind (str): serialzation kind as value of Serialage
            sad (dict): modified serializable attribute dict of saidified data
            vrsn (Versionage): tuple value (major, minor)

        Parameters:
            sad (dict): serializable attribute dict of saidified data
            version (Versionage | None): supported protocol version for message
                None means do not enforce a supported version


        """
        if "v" not in sad:
            raise SerializeError(f"Missing version string field in {sad}.")

        # extract elements so can replace size element but keep others
        proto, vrsn, kind, size = deversify(sad["v"], version=version)

        raw = clas.dumps(sad, kind)
        size = len(raw)

        # generate new version string with correct size
        vs = versify(proto=proto, version=vrsn, kind=kind, size=size)

        # find location of old version string inside raw
        match = Rever.search(raw)  # Rever's regex takes bytes
        if not match or match.start() > 12:
            raise SerializeError(f"Invalid version string in raw = {raw}.")
        fore, back = match.span()  # start and end positions of version string

        # replace old version string in raw with new one
        raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
        if size != len(raw):  # substitution messed up
            raise SerializeError(f"Malformed size of raw in version string == {vs}")
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
            raise SerializeError(f"Invalid serialization kind = {kind}")

        return raw


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
            raise ValidationError(f"Uncomparable saids.")



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


    @property
    def raw(self):
        """raw property getter
        Returns:
            raw (bytes):  serialized version
        """
        return self._raw


    @property
    def sad(self):
        """sad property getter
        Returns:
            sad (dict): serializable attribute dict (saidified data)
        """
        return self._sad



    @property
    def kind(self):
        """kind property getter
        Returns:
            kind (str): value of Serials (Serialage)"""
        return self._kind


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



class SerderKERI(Serder):
    """SerderKERI is Serder subclass with Labels for KERI packet types (ilks) and
       properties for exposing field values of KERI messages

       See docs for Serder
    """

    # Protocol specific field labels dict, keyed by ilk (packet type string).
    # value of each entry is Labelage instance that provides saidive field labels,
    # codes, and all field labels
    # A key of None is default when no ilk required
    Labels = {Ilks.icp: Labelage(saids=['d'], codes=[DigDex.Blake3_256], fields=['v','d']),
             }
