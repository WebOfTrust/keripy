# -*- encoding: utf-8 -*-
"""
keri.core.serdering module

"""
import copy
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
from ..kering import (Versionage, Version, Vrsn_1_0, Vrsn_1_1,
                      VERRAWSIZE, VERFMT, VERFULLSIZE)
from ..kering import Protos, Serials, Rever, versify, deversify, Ilks
from ..core import coring
from .coring import MtrDex, DigDex, PreDex, Saids,  Digestage
from .coring import Matter, Saider, Verfer, Diger, Number, Tholder

from .. import help
from ..help import helping

logger = help.ogler.getLogger()

"""
Fieldage
    saids (dict): keyed by saidive field labels with values as default codes
    alls (dict): keyed by all field labels including saidive ones
                   with values as default codes

Example:
    Fields = Labelage(saids={'d': DigDex.Blake3_256},
                      alls={'v': '','d':''})
"""
Fieldage = namedtuple("Fieldage", "saids alls")  #values are dicts


"""
Reapage
    proto (str): protocol type value of Protos examples 'KERI', 'ACDC'
    major (str): single char hex string of major version number
    minor (str): single char hex string of minor version number
    kind (str): serialization value of Serials examples 'JSON', 'CBOR', 'MGPK'

"""
Reapage = namedtuple("Reapage", "proto major minor kind size")


class Serdery:
    """Serder factory class for generating serder instances by protocol type
    from an incoming message stream.


    """

    def __init__(self, *, version=None):
        """Init instance

        Parameters:
            version (Versionage | None): instance supported protocol version
                     None means do not enforce a supported version
        """
        self.version = version  # default version


    def reap(self, ims, *, version=None):
        """Extract and return Serder subclass based on protocol type reaped from
        version string inside serialized raw of Serder.

        Returns:
            serder (Serder): instance of Serder subclass where subclass is
                determined by the protocol type of its version string.

        Parameters:
            ims (bytearray) of serialized incoming message stream. Assumes start
                of stream is raw Serder.
            version (Versionage | None): instance supported protocol version
                None means do not enforce a supported version
        """
        version = version if version is not None else self.version

        if len(ims) < Serder.InhaleSize:
            raise ShortageError(f"Need more raw bytes for Serdery to reap.")

        match = Rever.search(ims)  # Rever regex takes bytes/bytearray not str
        if not match or match.start() > Serder.MaxVSOffset:
            raise VersionError(f"Invalid version string for Serder raw = "
                               f"{ims[: Serder.InhaleSize]}.")

        reaped = Reapage(*match.group("proto", "major", "minor", "kind", "size"))

        if reaped.proto == Protos.keri.encode("utf-8"):
            return SerderKERI(raw=ims, strip=True, version=version, reaped=reaped)
        elif reaped.proto == Protos.acdc.encode("utf-8"):
            return SerderACDC(raw=ims, strip=True, version=version, reaped=reaped)
        else:
            raise ProtocolError(f"Unsupported protocol type = {reaped.proto}.")



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
        said (str): qb64 said of .raw given by appropriate field
        saidb (bytes): qb64b of .said
        ilk (str | None): packet type for this Serder if any (may be None)


    Hidden Attributes:
        ._raw is bytes of serialized event only
        ._sad is key event dict
        ._proto (str):  Protocolage value as protocol type identifier
        ._version is Versionage instance of event version
        ._kind is serialization kind string value (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
        ._size is int of number of bytes in serialed event only
        ._said (str): qb64 given by appropriate saidive field

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
    InhaleSize = MaxVSOffset + VERFULLSIZE  # min buffer size to inhale

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

    #override in subclass to enforce specific protocol
    Protocol = None  # required protocol, None means any in Protos is ok

    Proto = Protos.keri  # default protocol type
    Vrsn = Vrsn_1_0  # default protocol version for protocol type
    Kind = Serials.json  # default serialization kind


    # Nested dict keyed by protocol.
    # Each protocol value is a dict keyed by ilk.
    # Each ilk value is a Labelage named tuple with saids, codes and fields
    # ilk value of None is default for protocols that support ilkless packets
    Fields = {
            Protos.keri:
            {
                Vrsn_1_0:
                {
                    Ilks.icp: Fieldage(saids={Saids.d: DigDex.Blake3_256,
                                              Saids.i: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', kt='0',
                            k=[], nt='0', n=[], bt='0', b=[], c=[], a=[])),
                    Ilks.rot: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', s='0', p='',
                            kt='0',k=[], nt='0', n=[], bt='0', br=[],
                            ba=[], a=[])),
                    Ilks.ixn: Fieldage({Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', s='0', p='', a=[])),
                    Ilks.dip: Fieldage(saids={Saids.d: DigDex.Blake3_256,
                                              Saids.i: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', kt='0',
                            k=[], nt='0', n=[], bt='0', b=[], c=[], a=[],
                            di='')),
                    Ilks.drt: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', s='0', p='',
                            kt='0',k=[], nt='0', n=[], bt='0', br=[],
                            ba=[], a=[])),
                    Ilks.rct: Fieldage(saids={},
                        alls=dict(v='', t='',d='', i='', s='0')),
                    Ilks.qry: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', dt='', r='', rr='',
                                    q={})),
                    Ilks.rpy: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', dt='', r='',a=[])),
                    Ilks.pro: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', dt='', r='', rr='',
                                    q={})),
                    Ilks.bar: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', dt='', r='',a=[])),
                    Ilks.exn: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='', d='', i="", p="", dt='', r='',q={},
                                    a=[], e={})),
                    Ilks.vcp: Fieldage(saids={Saids.d: DigDex.Blake3_256,
                                              Saids.i: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', ii='', s='0', c=[],
                                    bt='0', b=[], n='')),
                    Ilks.vrt: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', p='', s='0',
                                    bt='0', br=[], ba=[])),
                    Ilks.iss: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', ri='',
                                  dt='')),
                    Ilks.rev: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', ri='',
                                  p='', dt='')),
                    Ilks.bis: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', ii='', s='0', ra={},
                                  dt='')),
                    Ilks.brv: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', p='', ra={},
                                  dt='')),
                },
                Vrsn_1_1:
                {
                    Ilks.icp: Fieldage(saids={Saids.d: DigDex.Blake3_256,
                                              Saids.i: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', kt='0',
                            k=[], nt='0', n=[], bt='0', b=[], c=[], a=[])),
                    Ilks.rot: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', s='0', p='',
                            kt='0',k=[], nt='0', n=[], bt='0', br=[],
                            ba=[], c=[], a=[])),
                    Ilks.ixn: Fieldage({Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', s='0', p='', a=[])),
                    Ilks.dip: Fieldage(saids={Saids.d: DigDex.Blake3_256,
                                              Saids.i: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', kt='0',
                            k=[], nt='0', n=[], bt='0', b=[], c=[], a=[],
                            di='')),
                    Ilks.drt: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', s='0', p='',
                            kt='0',k=[], nt='0', n=[], bt='0', br=[],
                            ba=[], c=[], a=[])),
                    Ilks.rct: Fieldage(saids={},
                        alls=dict(v='', t='',d='', i='', s='0')),
                    Ilks.qry: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', dt='', r='', rr='',
                                    q={})),
                    Ilks.rpy: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', dt='', r='',a=[])),
                    Ilks.pro: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', dt='', r='', rr='',
                                    q={})),
                    Ilks.bar: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='',d='', i='', dt='', r='',a=[])),
                    Ilks.exn: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                        alls=dict(v='', t='', d='', i="", p="", dt='', r='', q={},
                                    a=[], e={})),
                },
            },
            Protos.crel:
            {
                Vrsn_1_1:
                {
                    Ilks.vcp: Fieldage(saids={Saids.d: DigDex.Blake3_256,
                                              Saids.i: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', ii='', s='0', c=[],
                                    bt='0', b=[], u='')),
                    Ilks.vrt: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', p='', s='0',
                                    bt='0', br=[], ba=[])),
                    Ilks.iss: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', ri='',
                                  dt='')),
                    Ilks.rev: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', ri='',
                                  p='', dt='')),
                    Ilks.bis: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', ii='', s='0', ra={},
                                  dt='')),
                    Ilks.brv: Fieldage(saids={Saids.d: DigDex.Blake3_256,},
                        alls=dict(v='', t='',d='', i='', s='0', p='', ra={},
                                  dt='')),
                },
            },
            Protos.acdc:
            {
                Vrsn_1_0:
                {
                    None: Fieldage(saids={Saids.d: DigDex.Blake3_256},
                                   alls=dict(v='', d='', i='', s='')),
                }
            },
        }


    # default ilk for each protocol at default version is zeroth ilk in dict
    Ilks = dict()
    for key, val in Fields.items():
        Ilks[key] = list(list(val.values())[0].keys())[0]


    def __init__(self, *, raw=b'', sad=None, strip=False, version=Version,
                 reaped=None, verify=True, makify=False,
                 proto=None, vrsn=None, kind=None, ilk=None, saids=None):
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
            reaped (Reapage | None): instance of deconstructed version string
                elements. If none or empty ignore otherwise assume that raw
                already had its version string extracted (reaped) into the
                elements of reaped.
            verify (bool): True means verify said(s) of given raw or sad.
                Raises ValidationError if verification fails
                Ignore when raw not provided or when raw and saidify is True
            makify (bool): True means compute fields for sad including size and
                saids.
            proto (str | None): desired protocol type str value of Protos
                If None then its extracted from sad or uses default .Proto
            vrsn (Versionage | None): instance desired protocol version
                If None then its extracted from sad or uses default .Vrsn
            kind (str None): serialization kind string value of Serials
                supported kinds are 'json', 'cbor', 'msgpack', 'binary'
                If None then its extracted from sad or uses default .Kind
            ilk (str | None): desired ilk packet type str value of Ilks
                If None then its extracted from sad or uses default .Ilk
            saids (dict): of keyed by label of codes for saidive fields to
                override defaults given in .Fields for a given ilk.
                If None then use defaults
                Code assignment for each saidive field in desending priority:
                   - the code provided in saids when not None
                   - the code extracted from sad[said label] when valid CESR
                   - the code provided in .Fields...saids


        """

        if raw:  # deserialize raw using property setter
            # self._inhale works because it only references class attributes
            sad, proto, vrsn, kind, size = self._inhale(raw=raw,
                                                        version=version,
                                                        reaped=reaped)
            self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
            self._sad = sad
            self._proto = proto
            self._vrsn = vrsn
            self._kind = kind
            self._size = size
            # primary said field label
            try:
                label = list(self.Fields[self.proto][self.vrsn][self.ilk].saids.keys())[0]
                if label not in self._sad:
                    raise FieldError(f"Missing primary said field in {self._sad}.")
                self._said = self._sad[label]  # not verified
            except Exception as ex:
                self._said = None  # no saidive field

            if strip:  #only when raw is bytearray
                try:
                    del raw[:self._size]
                except TypeError:
                    pass  # ignore if bytes

            if verify:  # verify the said(s) provided in raw
                try:
                    self._verify()  # raises exception when not verify
                except Exception as ex:
                    logger.error("Invalid raw for Serder %s\n%s",
                                 self.pretty(), ex.args[0])
                    raise ValidationError(f"Invalid raw for Serder = "
                                          f"{self._sad}. {ex.args[0]}") from ex

        elif sad or makify:  # serialize sad into raw or make sad
            if makify:  # recompute properties and said(s) and reset sad
                # makify resets sad, raw, proto, version, kind, and size
                self.makify(sad=sad, version=version,
                        proto=proto, vrsn=vrsn, kind=kind, ilk=ilk, saids=saids)

            else:
                # self._exhale works because it only access class attributes
                raw, sad, proto, vrsn, kind, size = self._exhale(sad=sad,
                                                                 version=version)
                self._raw = raw
                self._sad = sad
                self._proto = proto
                self._vrsn = vrsn
                self._kind = kind
                self._size = size
                # primary said field label
                try:
                    label = list(self.Fields[self.proto][self.vrsn][self.ilk].saids.keys())[0]
                    if label not in self._sad:
                        raise DeserializeError(f"Missing primary said field in {self._sad}.")
                    self._said = self._sad[label]  # not verified
                except Exception:
                    self._said = None  # no saidive field

                if verify:  # verify the said(s) provided in sad
                    try:
                        self._verify()  # raises exception when not verify
                    except Exception as ex:
                        logger.error("Invalid sad for Serder %s\n%s",
                                     self.pretty(), ex.args[0])
                        raise ValidationError(f"Invalid sad for Serder ="
                                              f"{self._sad}.") from ex

        else:
            raise ValueError("Improper initialization need raw or sad or makify.")



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
        if self.Protocol and self.proto != self.Protocol:
            raise ValidationError(f"Expected protocol = {self.Protocol}, got "
                                 f"{self.proto} instead.")

        if self.proto not in self.Fields:
            raise ValidationError(f"Invalid protocol type = {self.proto}.")

        if self.ilk not in self.Fields[self.proto][self.vrsn]:
            raise ValidationError(f"Invalid packet type (ilk) = {self.ilk} for"
                                  f"protocol = {self.proto}.")

        fields = self.Fields[self.proto][self.vrsn][self.ilk]  # get labelage
        # ensure all required fields in alls are in sad
        alls = fields.alls  # dict of all field labels with default values
        keys = list(self._sad)  # get list of keys of self.sad
        for key in list(keys):  # make copy to mutate
            if key not in alls:
                del keys[keys.index(key)]  # remove non required fields

        if list(alls.keys()) != keys:  # forces ordering of labels in .sad
            raise MissingFieldError(f"Missing one or more required fields from"
                                    f"= {list(alls.keys())} in sad = "
                                    f"{self._sad}.")

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        saids = copy.copy(fields.saids)  # get copy of saidive field labels and defaults values
        if not (set(saids.keys()) <= set(alls.keys())):
            raise MissingFieldError(f"Missing one or more required said fields"
                                    f" from {list(saids.keys())} in sad = "
                                    f"{self._sad}.")

        sad = self.sad  # make shallow copy so don't clobber original .sad
        for label in saids.keys():
            try:  # replace default code with code of value from sad
                saids[label] = Matter(qb64=sad[label]).code
            except Exception as ex:
                if saids[label] in DigDex:  # digestive but invalid
                    raise ValidationError(f"Invalid said field '{label}' in sad\n"
                                      f" = {self._sad}.") from ex

            if saids[label] in DigDex:  # if digestive then replace with dummy
                sad[label] = self.Dummy * len(sad[label])


        raw = self.dumps(sad, kind=self.kind)  # serialize dummied sad copy

        for label, code in saids.items():
            if code in DigDex:  # subclass override if non digestive allowed
                klas, size, length = self.Digests[code]  # digest algo size & length
                ikwa = dict()  # digest algo class initi keyword args
                if size:
                    ikwa.update(digest_size=size)  # optional digest_size
                dkwa = dict()  # digest method keyword args
                if length:
                    dkwa.update(length=length)
                dig = Matter(raw=klas(raw, **ikwa).digest(**dkwa), code=code).qb64
                if dig != self._sad[label]:  # compare to original
                    raise ValidationError(f"Invalid said field '{label}' in sad"
                                          f" = {self._sad}, should be {dig}.")
                sad[label] = dig

        raw = self.dumps(sad, kind=self.kind)
        if raw != self.raw:
            raise ValidationError(f"Invalid round trip of {sad} != \n"
                                  f"{self.sad}.")
        # verified successfully since no exception


    def makify(self, sad, *, version=None,
               proto=None, vrsn=None, kind=None, ilk=None, saids=None):
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
                If None then its extracted from sad or uses default .Proto
            vrsn (Versionage | None): instance desired protocol version
                If None then its extracted from sad or uses default .Vrsn
            kind (str None): serialization kind string value of Serials
                supported kinds are 'json', 'cbor', 'msgpack', 'binary'
                If None then its extracted from sad or uses default .Kind
            ilk (str | None): desired ilk packet type str value of Ilks
                If None then its extracted from sad or uses default .Ilk
            saids (dict): of keyed by label of codes for saidive fields to
                override defaults given in .Fields for a given ilk.
                If None then use defaults
                Code assignment for each saidive field in desending priority:
                   - the code provided in saids when not None
                   - the code extracted from sad[said label] when valid CESR
                   - the code provided in .Fields...saids
        """
        sproto = svrsn = skind = silk = None
        if sad and 'v' in sad:  # attempt to get from vs in sad
            try:  # extract version string elements as defaults if provided
                sproto, svrsn, skind, _ = deversify(sad["v"], version=version)
            except ValueError as ex:
                pass
            else:
                silk = sad.get('t')  # if not in get returns None which may be valid

        if proto is None:
            proto = sproto if sproto is not None else self.Proto

        if vrsn is None:
            vrsn = svrsn if svrsn is not None else self.Vrsn

        if kind is None:
            kind = skind if skind is not None else self.Kind

        if ilk is None:
            ilk = silk if silk is not None else self.Ilks[proto]


        if proto not in self.Fields:
            raise SerializeError(f"Invalid protocol type = {proto}.")


        if self.Protocol and proto != self.Protocol:
            raise SerializeError(f"Expected protocol = {self.Protocol}, got "
                                 f"{proto} instead.")

        if version is not None and vrsn != version:
            raise SerializeError(f"Expected version = {version}, got "
                               f"{vrsn.major}.{vrsn.minor}.")

        if kind not in Serials:
            raise SerializeError(f"Invalid serialization kind = {kind}")


        if ilk not in self.Fields[proto][vrsn]:
            raise SerializeError(f"Invalid packet type (ilk) = {ilk} for"
                                  f"protocol = {proto}.")

        fields = self.Fields[proto][vrsn][ilk]  # get Fieldage of fields

        if not sad:  # empty or None so create from defaults
            sad = {}
            for label, value in fields.alls.items():
                if helping.nonStringIterable(value):  # copy iterable defaults
                    value = copy.copy(value)
                sad[label] = value

            if 't' in sad:  # packet type (ilk) requried so set value to ilk
                sad['t'] = ilk

        # ensure all required fields in alls are in sad
        alls = fields.alls  # all field labels
        for label, value in alls.items():  # ensure provided sad as all required fields
            if label not in sad:  # supply default
                if helping.nonStringIterable(value):  # copy iterable defaults
                    value = copy.copy(value)
                sad[label] = value

        keys = list(sad)  # get list of keys of self.sad
        for key in list(keys):  # make copy to mutate
            if key not in alls:
                del keys[keys.index(key)]  # remove non required fields

        if list(alls.keys()) != keys:  # ensure ordering of fields matches alls
            raise SerializeError(f"Mismatch one or more of all required fields "
                                 f" = {list(alls.keys())} in sad = {sad}.")

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        _saids = copy.copy(fields.saids)  # get copy of defaults
        if not (set(_saids.keys()) <= set(alls.keys())):
            raise SerializeError(f"Missing one or more required said fields "
                                 f"from {list(_saids.keys())} in sad = {sad}.")

        # override saidive defaults
        for label in _saids:
            if saids and label in saids:  # use parameter override
                _saids[label] = saids[label]
            else:
                try:  # use sad field override
                    _saids[label] = Matter(qb64=sad[label]).code
                except Exception:
                    pass  # no override

            if _saids[label] in DigDex:  # if digestive then fill with dummy
                sad[label] = self.Dummy * Matter.Sizes[_saids[label]].fs


        if 'v' not in sad:  # ensures that 'v' is always required by .Labels
            raise SerializeError(f"Missing requires version string field 'v'"
                                          f" in sad = {sad}.")

        sad['v'] = self.Dummy * VERFULLSIZE  # ensure size of vs

        raw = self.dumps(sad, kind)  # get size of fully dummied sad
        size = len(raw)

        # generate new version string with correct size
        vs = versify(proto=proto, version=vrsn, kind=kind, size=size)
        sad["v"] = vs  # update version string in sad

        # now have correctly sized version string in sad
        # now compute saidive digestive field values using sized dummied sad
        raw = self.dumps(sad, kind=kind)  # serialize sized dummied sad

        for label, code in _saids.items():
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
        self._vrsn = vrsn
        self._kind = kind
        self._size = size
        # primary said field label
        try:
            label = list(self.Fields[self.proto][self.vrsn][self.ilk].saids.keys())[0]
            if label not in self._sad:
                raise SerializeError(f"Missing primary said field in {self._sad}.")
            self._said = self._sad[label]  # implicitly verified
        except Exception:
            self._said = None  # no saidive field



    @classmethod
    def _inhale(clas, raw, version=Version, reaped=None):
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
            reaped (Reapage | None): instance of deconstructed version string
                elements. If none or empty ignore otherwise assume that raw
                already had its version string extracted (reaped) into the
                elements of reaped.

        Note:
            loads and jumps of json use str whereas cbor and msgpack use bytes
            Assumes only supports Version

        """
        if reaped:
            proto, major, minor, kind, size = reaped  # tuple unpack
        else:
            if len(raw) < clas.InhaleSize:
                raise ShortageError(f"Need more raw bytes for Serder to inhale.")

            match = Rever.search(raw)  # Rever regex takes bytes/bytearray not str
            if not match or match.start() > clas.MaxVSOffset:
                raise VersionError(f"Invalid version string in raw = "
                                   f"{raw[:clas.InhaleSize]}.")

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

        return sad, proto, vrsn, kind, size


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
        return json.dumps(self._sad, indent=1)[:size]


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
        return dict(self._sad)  # return copy


    @property
    def kind(self):
        """kind property getter
        Returns:
            kind (str): value of Serials (Serialage)"""
        return self._kind


    @property
    def proto(self):
        """proto property getter
        protocol identifier type value of Protocolage such as 'KERI' or 'ACDC'

        Returns:
            proto (str): Protocolage value as protocol type
        """
        return self._proto


    @property
    def vrsn(self):
        """vrsn (version) property getter

        Returns:
            vrsn (Versionage): instance of protocol version for this Serder
        """
        return self._vrsn

    @property
    def version(self):
        """version property getter alias of .vrsn

        Returns:
            version (Versionage): instance of protocol version for this Serder
        """
        return self.vrsn


    @property
    def size(self):
        """size property getter
        Returns:
            size (int): number of bytes in .raw
        """
        return self._size


    @property
    def said(self):
        """said property getter
        Returns:
           said (str): qb64
        """
        if not self.Fields[self.proto][self.vrsn][self.ilk].saids.keys() and 'd' in self._sad:
            return self._sad['d']  # special case for non-saidive messages like rct
        return self._said


    @property
    def saidb(self):
        """saidb property getter
        Returns:
            saidb (bytes): qb64b of said  of .saider
        """
        return self.said.encode("utf-8") if self.said is not None else None


    @property
    def ilk(self):
        """ilk property getter
        Returns:
            ilk (str): pracket type given by sad['t'] if any
        """
        return self._sad.get('t')  # returns None if 't' not in sad



class SerderKERI(Serder):
    """SerderKERI is Serder subclass with Labels for KERI packet types (ilks) and
       properties for exposing field values of KERI messages

       See docs for Serder
    """
    #override in subclass to enforce specific protocol
    Protocol = Protos.keri  # required protocol, None means any in Protos is ok
    Proto = Protos.keri  # default protocol type



    def _verify(self, **kwa):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Raises a ValidationError (or subclass) if any verification fails

        """
        super(SerderKERI, self)._verify(**kwa)

        allkeys = list(self.Fields[self.proto][self.vrsn][self.ilk].alls.keys())
        keys = list(self.sad.keys())
        if allkeys != keys:
            raise ValidationError(f"Invalid top level field list. Expected "
                                  f"{allkeys} got {keys}.")

        if (self.vrsn.major < 2 and self.vrsn.minor < 1 and
            self.ilk in (Ilks.qry, Ilks.rpy, Ilks.pro, Ilks.bar, Ilks.exn)):
                pass
        else:  # verify pre
            try:
                code = Matter(qb64=self.pre).code
            except Exception as ex:
                raise ValidationError(f"Invalid identifier prefix = "
                                      f"{self.pre}.") from ex

            if self.ilk in (Ilks.dip, Ilks.drt):
                idex = DigDex  # delegatee must be digestive prefix
            else:
                idex = PreDex  # non delegatee may be non digest

            if code not in idex:
                raise ValidationError(f"Invalid identifier prefix code = {code}.")

            # non-transferable pre validations
            if code in [PreDex.Ed25519N, PreDex.ECDSA_256r1N, PreDex.ECDSA_256k1N]:
                if self.ndigs:
                    raise ValidationError(f"Non-transferable code = {code} with"
                                          f" non-empty nxt = {self.ndigs}.")

                if self.backs:
                    raise ValidationError("Non-transferable code = {code} with"
                                          f" non-empty backers = {self.backs}.")

                if self.seals:
                    raise ValidationError("Non-transferable code = {code} with"
                                          f" non-empty seals = {self.seals}.")

        if self.ilk in (Ilks.dip):  # validate delpre
            try:
                code = Matter(qb64=self.delpre).code
            except Exception as ex:
                raise ValidationError(f"Invalid delegator prefix = "
                                      f"{self.delpre}.") from ex

            if code not in PreDex:  # delegator must be valid prefix code
                raise ValidationError(f"Invalid delegator prefix code = {code}.")


    @property
    def estive(self):  # establishative
        """ Returns True if Serder represents an establishment event """
        return (self._sad["t"] in (Ilks.icp, Ilks.rot, Ilks.dip, Ilks.drt)
                     if "t" in self._sad else False)


    @property
    def ked(self):
        """
        Returns:
            ked (dict): key event dict property getter. Alias for .sad
        """
        return self.sad


    @property
    def pre(self):
        """
        Returns:
           pre (str): qb64  of .sad["i"] identifier prefix property getter
        """
        return self._sad.get("i")


    @property
    def preb(self):
        """
        Returns:
        preb (bytes): qb64b  of .pre identifier prefix property getter as bytes
        """
        return self.pre.encode("utf-8") if self.pre is not None else None


    @property
    def sner(self):
        """Number instance of sequence number, sner property getter

        Returns:
            (Number): of ._sad["s"] hex number str converted
        """
        # auto converts hex num str to int
        return Number(num=self._sad["s"]) if 's' in self._sad else None


    @property
    def sn(self):
        """Sequence number, sn property getter
        Returns:
            sn (int): of .sner.num from .sad["s"]
        """
        return self.sner.num if self.sner is not None else None


    @property
    def snh(self):
        """Sequence number hex str, snh property getter
        Returns:
            snh (hex str): of .sner.numh from .sad["s"]
        """
        return self.sner.numh if self.sner is not None else None


    @property
    def seals(self):
        """Seals property getter

        Returns:
            seals (list): from ._sad["a"]
        """
        return self._sad.get("a")

    #Properties of inceptive Serders ilks in (icp, dip) and version2 estive serders

    @property
    def traits(self):
        """Traits list property getter  (config traits)

        Returns:
            traits (list): from ._sad["c"]
        """
        return self._sad.get("c")


    #Properties of estive Serders ilks in  (icp, rot, dip, drt)
    @property
    def tholder(self):
        """Tholder property getter

        Returns:
            tholder (Tholder): instance as converted from ._sad['kt']
                or None if missing.

        """
        return Tholder(sith=self._sad["kt"]) if "kt" in self._sad else None


    @property
    def keys(self):
        """Returns list of qb64 keys from ._sad['k'].
        One for each key.
        keys property getter
        """
        return self._sad.get("k")


    @property
    def verfers(self):
        """Returns list of Verfer instances as converted from ._sad['k'].
        One for each key.
        verfers property getter
        """
        keys = self._sad.get("k")
        return [Verfer(qb64=key) for key in keys] if keys is not None else None


    @property
    def ntholder(self):
        """Returns Tholder instance as converted from ._sad['nt'] or None if missing.

        """
        return Tholder(sith=self._sad["nt"]) if "nt" in self._sad else None


    @property
    def ndigs(self):
        """
        Returns:
            (list): digs
        """
        if self.vrsn.major < 2 and self.vrsn.minor < 1 and self.ilk == Ilks.vcp:
            return None

        return self._sad.get("n")

    @property
    def ndigers(self):
        """NDigers property getter

        Returns:
            ndigers (list[Diger]): instance as converted from ._sad['n'].
            One for each next key digests.
        """
        if self.vrsn.major < 2 and self.vrsn.minor < 1 and self.ilk == Ilks.vcp:
            return None

        digs = self._sad.get("n")
        return [Diger(qb64=dig) for dig in digs] if digs is not None else None


    @property
    def bner(self):  # toader
        """
        bner (Number of backer TOAD threshold of accountable duplicity property getter
        Returns:
            (Number): of ._sad["bt"] hex number str converted. Auto converts
            hex num str to int
        """
        return Number(num=self._sad["bt"]) if 'bt' in self._sad else None


    @property
    def bn(self):
        """
        bn (backer TOAD number) property getter
        Returns:
            bn (int): of .bner.num from .ked["bt"]
        """
        return self.bner.num if self.bner is not None else None


    # properties for incentive Serders like icp, dip
    @property
    def backs(self):
        """Backers property getter

        Returns:
            backs (list[str]): aids qb64 from ._sad['b'].
                           One for each backer (witness).

        """
        return self._sad.get("b")


    @property
    def berfers(self):
        """Berfers property getter
        Returns list of Verfer instances as converted from ._sad['b'].
                One for each backer (witness).

        """
        baks = self._sad.get("b")
        return [Verfer(qb64=bak) for bak in baks] if baks is not None else None


    # properties for priorative Serders like ixn rot drt

    @property
    def prior(self):
        """Prior property getter
        Returns:
            prior (str): said qb64 of prior event from ._sad['p'].

        """
        return self._sad.get("p")


    @property
    def priorb(self):
        """Priorb bytes property getter
        Returns:
            priorb (str): said qb64b of prior event from ._sad['p'].

        """
        return self.prior.encode("utf-8") if self.prior is not None else None


    # properties for rotative Serders like rot drt

    @property
    def cuts(self):
        """Cuts property getter
        Returns list of aids of instances as converted from ._sad['br'].
                 One for each backer (witness) to be cut (removed).

        """
        return self._sad.get("br")


    @property
    def adds(self):
        """Adds property getter
        Returns list of aids of instances as converted from ._sad['ba'].
                 One for each backer (witness) to be added.

        """
        return self._sad.get("ba")


    #Properties for delegated Serders ilks in (dip, drt)

    @property
    def delpre(self):
        """
        Returns:
           delpre (str): qb64  of .sad["di"] delegator ID prefix property getter
        """
        return self._sad.get("di")


    @property
    def delpreb(self):
        """
        Returns:
        delpreb (bytes): qb64b  of .delpre property getter as bytes
        """
        return self.delpre.encode("utf-8") if self.delpre is not None else None

    #Propertives for dated Serders, qry, rpy, pro, bar, exn

    @property
    def stamp(self):
        """
        Returns:
           stamp (str): date-time-stamp sad["dt"]. RFC-3339 profile of ISO-8601
                datetime of creation of message or data
        """
        return self._sad.get("dt")


    #Properties for exn  exchange


    #Properties for vcp  (registry  inception event)
    @property
    def uuid(self):
        """uuid property getter

        Returns:
           uuid (str): qb64  of .sad["u"] salty nonce
        """
        return self._sad.get("u")

    @property
    def nonce(self):
        """
        should be deprecated

        Returns:
           nonce (str): alias for .uuid property
        """
        if self.vrsn.major < 2 and self.vrsn.minor < 1 and self.ilk == Ilks.vcp:
            return self._sad.get("n")
        else:
            return self.uuid


class SerderCREL(Serder):
    """SerderCREL is Serder subclass with Labels for CREL packet types (ilks) and
       properties for exposing field values of CREL messages
       Container Registry Event Log for issuance, revocation, etc registries of
       ACDC

       See docs for Serder
    """
    #override in subclass to enforce specific protocol
    Protocol = Protos.crel  # required protocol, None means any in Protos is ok
    Proto = Protos.crel  # default protocol type
    Vrsn = Vrsn_1_1  # default protocol version for protocol type


    def _verify(self, **kwa):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Raises a ValidationError (or subclass) if any verification fails

        """
        super(SerderCREL, self)._verify(**kwa)

        try:
            code = Matter(qb64=self.issuer).code
        except Exception as ex:
            raise ValidationError(f"Invalid issuer AID = "
                                  f"{self.issuer}.") from ex

        if code not in PreDex:
            raise ValidationError(f"Invalid issuer AID code = {code}.")


    @property
    def issuer(self):
        """
        Returns:
           issuer (str): qb64  of .sad["i"] issuer AID property getter
        """
        return self._sad.get('i')


    @property
    def issuerb(self):
        """
        Returns:
        issuerb (bytes): qb64b  of .issuer property getter as bytes
        """
        return self.issuer.encode("utf-8") if self.issuer is not None else None


class SerderACDC(Serder):
    """SerderACDC is Serder subclass with Labels for ACDC packet types (ilks) and
       properties for exposing field values of ACDC messages

       See docs for Serder
    """
    #override in subclass to enforce specific protocol
    Protocol = Protos.acdc  # required protocol, None means any in Protos is ok
    Proto = Protos.acdc  # default protocol type



    def _verify(self, **kwa):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Raises a ValidationError (or subclass) if any verification fails

        """
        super(SerderACDC, self)._verify(**kwa)

        try:
            code = Matter(qb64=self.issuer).code
        except Exception as ex:
            raise ValidationError(f"Invalid issuer AID = "
                                  f"{self.issuer}.") from ex

        if code not in PreDex:
            raise ValidationError(f"Invalid issuer AID code = {code}.")

    @property
    def uuid(self):
        """uuid property getter
        Optional fields return None when not present
        Returns:
           uuid (str | None): qb64  of .sad["u"] salty nonce
        """
        return self._sad.get("u")


    @property
    def uuidb(self):
        """uuid property getter (uuid bytes)
        Optional fields return None when not present
        Returns:
           uuidb (bytes | None): qb64b  of .sad["u"] salty nonce as bytes
        """
        return self.uuid.encode("utf-8") if self.uuid is not None else None


    @property
    def issuer(self):
        """issuer property getter (issuer AID)
        Optional fields return None when not present
        Returns:
           issuer (str | None): qb64  of .sad["i"] issuer AID
        """
        return self._sad.get('i')


    @property
    def issuerb(self):
        """issuerb property getter (issuer AID bytes)
        Optional fields return None when not present
        Returns:
        issuerb (bytes | None): qb64b  of .issuer AID as bytes
        """
        return self.issuer.encode("utf-8") if self.issuer is not None else None


    @property
    def regi(self):
        """regi property getter (registry identifier SAID)
        Optional fields return None when not present
        Returns:
           regi (str | None): qb64  of .sad["ri"] registry SAID
        """
        return self._sad.get('ri')


    @property
    def regib(self):
        """regib property getter (registry identifier SAID bytes)
        Optional fields return None when not present
        Returns:
        regib (bytes | None): qb64b  of .issuer AID as bytes
        """
        return self.issuer.encode("utf-8") if self.issuer is not None else None


    @property
    def schema(self):
        """schema block or SAID property getter
        Optional fields return None when not present
        Returns:
            schema (dict | str | None): from ._sad["s"]
        """
        return self._sad.get('s')


    @property
    def attrib(self):
        """attrib block or SAID property getter (attribute)
        Optional fields return None when not present
        Returns:
            attrib (dict | str | None): from ._sad["a"]
        """
        return self._sad.get("a")


    @property
    def issuee(self):
        """ise property getter (issuee AID)
        Optional fields return None when not present
        Returns:
           issuee (str | None): qb64  of .sad["a"]["i"] issuee AID
        """
        try:
            return self.attrib.get['i']
        except:
            return None


    @property
    def issueeb(self):
        """isrb property getter (issuee AID bytes)
        Optional fields return None when not present
        Returns:
        issueeb (bytes | None): qb64b  of .issuee AID as bytes
        """
        return self.issuee.encode("utf-8") if self.issuee is not None else None


    @property
    def attagg(self):
        """Attagg block property getter (attribute aggregate)
        Optional fields return None when not present
        Returns:
            attagg (dict | str): from ._sad["A"]
        """
        return self._sad.get("A")


    @property
    def edge(self):
        """Edge block property getter
        Optional fields return None when not present
        Returns:
            edge (dict | str): from ._sad["e"]
        """
        return self._sad.get("e")


    @property
    def rule(self):
        """Rule block property getter
        Optional fields return None when not present

        Returns:
            rule (dict | str): from ._sad["r"]
        """
        return self._sad.get("r") # or {}  # need to fix logic so can remove or since optional

    # ToDo Schemer property getter. Schemer object should change name to Schemar
