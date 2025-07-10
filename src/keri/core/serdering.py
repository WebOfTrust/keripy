# -*- coding: utf-8 -*-
"""
keri.core.serdering module

"""
import copy
import json
from collections import namedtuple
from collections.abc import Mapping, Iterable
from dataclasses import dataclass, asdict, field
from base64 import urlsafe_b64decode as decodeB64
from base64 import urlsafe_b64encode as encodeB64

import cbor2 as cbor
import msgpack
import pysodium
import blake3
import hashlib
from  ordered_set import OrderedSet as oset


from .. import kering
from ..kering import (ValidationError,  MissingFieldError, ExtraFieldError,
                      AlternateFieldError, InvalidValueError,
                      ShortageError, VersionError, ProtocolError, KindError,
                      DeserializeError, FieldError, SerializeError)
from ..kering import (Versionage, Version, Vrsn_1_0, Vrsn_2_0,
                      VERRAWSIZE1, VERFMT1,
                      MAXVERFULLSPAN, VER1FULLSPAN,  VER2FULLSPAN)
from ..kering import SMELLSIZE, Smellage, smell, sniff, Colds

from ..kering import Protocols, Kinds, versify, deversify, Ilks

from .. import help
from ..help import helping


from . import coring
from .coring import (MtrDex, DigDex, PreDex, NonTransDex, PreNonDigDex,
                     Saids,  Digestage, NonceDex)
from .coring import (Matter, Saider, Verfer, Prefixer, Diger, Number, Tholder,
                     Tagger, Ilker, Traitor, Verser, Dater, Texter, Pather,
                     Noncer, Labeler)
from .mapping import Mapper, Compactor

from .counting import GenDex, ProGen, Counter, Codens, SealDex_2_0, MUDex_2_0

from .structing import Sealer, SClanDom


logger = help.ogler.getLogger()


@dataclass
class FieldDom:
    """
    Field configuration dataclass for Serder messages. Provides field labels
    and default field values for a given ilk (message type).

    Attributes:
        alls (dict): Allowed fields (not extra)
                    alls must not be empty since at least version string
                    or protocol version filed is always required.
                    Fields in alls that appear must appear in order.

        opts (dict): Optional fields within alls.
                    opts defaults to empty.
                    When opts is empty than all alls are required.
                    Any fields in alls but not in opts are required.
                    opts is a subset of alls

        alts (dict): Alternate fields within alls.
                    alts defaults to empty.
                    An alt field means that one or the other of two fields is
                    allowed but not both. Two entries in alts are required, one
                    for each field in an alt pair. the alt pair key value are
                    the two labels. One entry for each order.
                    all alts must be in opts since both can't be required.
                    Suppose 'a' and 'A' are an alternate pair then alts =
                    { 'a': 'A', 'A': 'a'}. This allows the presence of one to
                    block the presence of the other by looking up the one present
                    as key to see the value of the one to block.

        saids (dict): are saidive fields whose value may be computed as a said of the message.
                    saids defaults to empty
                    when provided a field in saids indicates the field value is saidive.
                    A simple SAID field value is always computed.
                    An AID SAID field value is only computed when its code indicates.
                    saids is a subset of alls

        strict (bool): determines if alls is strict, no extra fields are allowed
                       strict defaults to True.
                       True means no extra fields are allowed, only those in alls.
                       False means extra fields are allowed besides thos in alls.
                       Extra fields are fields not in alls.
                       Extra fields may appear in any order after the last field
                       in alls.


        When strict:  no extras allowed
           Any fields not in alls raise error
           If opts is empty then all alls are required in order
           If opts is not empty then fields in opts are optional but the rest of
                the fields in alls are required

        When not strict: extras allowed
           Any fields not in alls must appear after all fields in alls
           If opts is empty then all alls are required in order
           If opts is not empty then fields in opts are optional but the rest of
                the fields in alls are required

    ACDC messages have an additional set of special rules. When an ACDC message
    is fixed field using the universal group count code -F## or --F##### then all
    fields are required. And one or both of fields 'a' or 'A' must be empty.

    Emptiness for field values that allow a field map count code as a value
    is indicated by a generic map count code with zero-length contents.
    Emptiness for field values that allow a list field count code as a value
    is indicated by a generic list count code with zero-length contents.
    Emptiness for field values that require a CESR primitive is indicated
    by the `Null` CESR primitive code, `1AAK`.

    The `ace`  message type in the ACDC protocol is for ACDC messages that allows
    extra field i.e. ace means ac dc with e xtra fields. This is an experimental
    type may not be normative.


    """
    alls: dict  # all allowed fields when strict
    opts: dict = field(default_factory=dict)  # optional fields
    alts:  dict = field(default_factory=dict)  # alternate optional fields
    saids: dict = field(default_factory=dict)  # saidive fields
    strict: bool = True  # only alls allowed no extras

    def __iter__(self):
        return iter(asdict(self))



class Serdery:
    """Serder factory class for generating serder instances by protocol type
    from an incoming message stream.

    Attributes:
        version (Versionage):  KERI ACDC supported protocol version
    """

    def __init__(self, version=Vrsn_2_0, **kwa):
        """Init instance

        Parameters:
            version (Versionage): keri acdc supported protocol version

        """
        self.version = version


    def reap(self, ims, genus, svrsn, cold=None, ctr=None, size=None, fixed=True):
        """Extract and return Serder subclass based on protocol type reaped from
        version string inside serialized raw of Serder.

        Returns:
            serder (Serder): instance of Serder subclass where subclass is
                determined by the protocol type of its version string.

        Parameters:
            ims (bytearray) of serialized incoming message stream. Assumes start
                of stream is raw Serder.
            genus (str): stream genus CESR code from stream parser.
                    Provides genus of enclosing stream top-level or nested group
            svrsn (Versionage): stream genus version instance CESR genus code
                    table version (Major, Minor)
                    Provides CESR version of enclosing stream top-level or nested group
            cold (None|Colds): Not None means sniff determined CESR native message
                                Using ctr. Must then be colds.txt or colds.bny.
                                Otherwise JSON, CBOR, MGPK field map.
                                so use smell. Default None
            ctr (None|Counter): Not None means sniff determined CESR native message
                                Using ctr. Otherwise JSON, CBOR, MGPK field map.
                                so use smell. Default None
            size (None|int): Not None means CESR native message using ctr and
                             size already calculated. All bytes in stream.
            fixed (bool): when CESR native message.
                               True means top-level fixed field
                               False means top-level field map
        """
        if ctr:  # parser sniffed and peekd so native and assigned ctr, size, fixed
            # parser already peeked to see .FixBodyGroup or .MapBodyGroup so
            # know it's native and assigned ctr, size, and fixed
            # So here peek further into ims to see version field if fixed
            # or label then version field if not fixed
            # (just index past ctr or ctr + label
            # with version field can get proto, pvrsn, and gvrsn
            # since native set kind to Kinds.CESR,
            # then can populate smellage  "proto pvrsn kind size gvrsn"
            # Serder._inhale then does its .loads given the smellage kind is CESR

            lsize = 0  # label size in bytes
            if not fixed:  # extract label for version field
                labeler = Labeler(qb64b=ims[ctr.fullSize:])  # offset past ctr
                lsize = labeler.fullsize

            verser = Verser(qb64b=ims[ctr.fullSize+lsize:])  # in text domain
            proto, pvrsn, gvrsn = verser.versage
            smellage = Smellage(proto=proto, pvrsn=pvrsn, kind=Kinds.cesr,
                                size=size, gvrsn=gvrsn)
        else:
            smellage = smell(ims)  # non native so smell to get version smellage

        if smellage.pvrsn.major > svrsn.major:  # likely not supported
            raise DeserializeError(f"Incompatible message protocol major version="
                                 f"{smellage.pvrsn} with stream  genus major "
                                 f"version={svrsn}.")

        if getattr(GenDex, ProGen.get(smellage.proto), None) != genus:
            raise DeserializeError(f"Incompatible message protocol={smellage.proto}"
                                 f" with genus={genus}.")

        if smellage.gvrsn:
            if smellage.gvrsn.major > svrsn.major:  # Message major later than stream
                raise DeserializeError(f"Incompatible message genus major version="
                                 f"{smellage.gvrsn} with stream major genus "
                                 f"version={svrsn}.")

            if smellage.gvrsn.minor > svrsn.minor:  # message minor later than stream
                raise DeserializeError(f"Incompatible message minor genus version="
                                     f"{smellage.gvrsn} with stream genus minor "
                                     f"version={svrsn}.")

            latest = list(Counter.Sizes[smellage.gvrsn.major])[-1]  # get latest supported minor version
            if smellage.gvrsn.minor > latest:
                raise DeserializeError(f"Incompatible message genus minor version"
                                     f"={smellage.gvrsn.minor} exceeds latest supported "
                                     f"genus minor version={latest}.")


        if smellage.proto == Protocols.keri:
            return SerderKERI(raw=ims, strip=True, smellage=smellage)
        elif smellage.proto == Protocols.acdc:
            return SerderACDC(raw=ims, strip=True, smellage=smellage)
        else:
            raise ProtocolError(f"Unsupported protocol type = {smellage.proto}.")



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
        Dummy (str): dummy character for computing SAIDs
        Spans (dict): version string spans keyed by version
        Digests (dict): map of digestive codes. Should be same set of codes as
            in coring.DigestCodex coring.DigDex so that .digestive property works.
            Use unit tests to ensure codex sets match
        Protocol (str): class specific message protocol
        Proto (str): default message protocol
        Vrsn (Versionage): default version
        Kind (str): default serialization kind one of Serials
        Fields (dict): nested dict of field labels keyed by protocol, version,
            and message type (ilk). Felds labels are provided with a Fieldage
            named tuple (saids, reqs, alls) that governs field type and presence.
            None is default message type (ilk) when no ilk needed in a message.
            See below for detailed logic associated with Fields class attribute

    Properties:
        raw (bytes): of serialized event only
        sad (dict): self addressed data dict

        proto (str): Protocolage value as protocol identifier such as KERI, ACDC
                     alias of .protocol
        protocol (str): Protocolage value as protocol identifier such as KERI, ACDC
                        alias of .proto
        pvrsn (Versionage): protocol version (Major, Minor)
        genus (str): CESR genus code for supported cesr genus
        gvrsn (Versionage): instance CESR genus code table version (Major, Minor)
                            when version field includes it (future)
        kind (str): serialization kind coring.Serials such as JSON, CBOR, MGPK, CESR
        size (int): number of bytes in serialization

        said (str): qb64 said of .raw given by appropriate field
        saidb (bytes): qb64b of .said
        ilk (str | None): packet type for this Serder if any (may be None)


    Hidden Attributes:
        ._raw (bytes): serialized message
        ._sad (dict): sad dict (key event dict)
        ._proto (str):  Protocolage value as protocol type identifier
        ._pvrsn (Versionage): instance of protocol version
        ._genus (str): GenDex genus code for CESR
        ._gvrsn (Versionage): instance of genus version for CESR
        ._pvrsn (Versionage): CESR code table version
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


    Fields:
        Each element of Fields is a FieldDom dataclass instance with four attributes:
            alls (dict):
            opts (dict):
            saids (dict):
            strict (bool):

    """
    Dummy = "#"  # dummy spaceholder char for SAID. Must not be a valid Base64 char

    # Spans dict keyed by version (Versionage instance) of version string span (size)
    Spans = {Vrsn_1_0: VER1FULLSPAN, Vrsn_2_0: VER2FULLSPAN}

    # map seal clan names to seal counter code for grouping seals in anchor list
    # change to Coden (Code Name)
    ClanCodes = dict()
    ClanCodes[SClanDom.SealDigest.__name__] = SealDex_2_0.DigestSealSingles
    ClanCodes[SClanDom.SealRoot.__name__] = SealDex_2_0.MerkleRootSealSingles
    ClanCodes[SClanDom.SealEvent.__name__] = SealDex_2_0.SealSourceTriples
    ClanCodes[SClanDom.SealTrans.__name__] = SealDex_2_0.SealSourceCouples
    ClanCodes[SClanDom.SealLast.__name__] = SealDex_2_0.SealSourceLastSingles
    ClanCodes[SClanDom.SealBack.__name__] = SealDex_2_0.BackerRegistrarSealCouples
    ClanCodes[SClanDom.SealKind.__name__] = SealDex_2_0.TypedDigestSealCouples

    # map seal counter code to seal clan name for parsing seal groups in anchor list
    CodeClans = { val: key for key, val in ClanCodes.items()}  # invert dict

    #override in subclass to enforce specific protocol
    Protocol = None  # class based message protocol, None means any in Protocols is ok
    Proto = Protocols.keri  # default message protocol type for makify on base Serder
    PVrsn = Vrsn_1_0  # default protocol version
    GVrsn = Vrsn_2_0  # default CESR genus version
    Kind = Kinds.json  # default serialization kind
    Genus = GenDex.KERI  # default CESR genus code
    MUCodes = Counter.MUCodes # message universal code tables from Counter


    # Nested dict keyed by protocol.
    # Each protocol value is a dict keyed by ilk.
    # Each ilk value is a Labelage named tuple with saids, codes and fields
    # ilk value of None is default for protocols that support ilkless packets
    Fields = \
    {
        Protocols.keri:
        {
            Vrsn_1_0:
            {
                Ilks.icp: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        kt='0',k=[], nt='0', n=[], bt='0', b=[], c=[],
                        a=[]),
                    saids={Saids.d: DigDex.Blake3_256,
                           Saids.i: DigDex.Blake3_256,}),
                Ilks.rot: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                            p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                            ba=[], a=[]),
                        saids={Saids.d: DigDex.Blake3_256}),
                Ilks.ixn: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        p='', a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.dip: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        kt='0', k=[], nt='0', n=[], bt='0', b=[], c=[],
                        a=[], di=''),
                    saids={Saids.d: DigDex.Blake3_256,
                           Saids.i: DigDex.Blake3_256,}),
                Ilks.drt: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                        ba=[], a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rct: FieldDom(alls=dict(v='', t='',d='', i='', s='0')),
                Ilks.qry: FieldDom(alls=dict(v='', t='',d='', dt='', r='',
                        rr='',q={}),
                    saids={Saids.d: DigDex.Blake3_256},),
                Ilks.rpy: FieldDom(alls=dict(v='', t='',d='', dt='', r='',
                        a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.pro: FieldDom(alls=dict(v='', t='',d='', dt='', r='',
                        rr='',q={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.bar: FieldDom(alls=dict(v='', t='',d='', dt='', r='',
                        a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.exn: FieldDom(alls=dict(v='', t='', d='', i="", rp="",
                        p="", dt='', r='',q={}, a=[], e={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.vcp: FieldDom(alls=dict(v='', t='',d='', i='', ii='',
                        s='0', c=[], bt='0', b=[], n=''),
                    saids={Saids.d: DigDex.Blake3_256,
                           Saids.i: DigDex.Blake3_256,}),
                Ilks.vrt: FieldDom(alls=dict(v='', t='',d='', i='', p='',
                        s='0', bt='0', br=[], ba=[]),
                    saids={Saids.d: DigDex.Blake3_256,}),
                Ilks.iss: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        ri='', dt=''),
                    saids={Saids.d: DigDex.Blake3_256,}),
                Ilks.rev: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        ri='', p='', dt=''),
                    saids={Saids.d: DigDex.Blake3_256,}),
                Ilks.bis: FieldDom(alls=dict(v='', t='',d='', i='', ii='',
                        s='0', ra={}, dt=''),
                    saids={Saids.d: DigDex.Blake3_256,}),
                Ilks.brv: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                         p='', ra={}, dt=''),
                    saids={Saids.d: DigDex.Blake3_256,}),
            },
            Vrsn_2_0:
            {
                Ilks.icp: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                         kt='0', k=[], nt='0', n=[], bt='0', b=[], c=[],
                         a=[]),
                    saids={Saids.d: DigDex.Blake3_256,
                           Saids.i: DigDex.Blake3_256,}),
                Ilks.rot: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                        ba=[], c=[], a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.ixn: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        p='', a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.dip: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                        kt='0', k=[], nt='0', n=[], bt='0', b=[], c=[],
                        a=[], di=''),
                    saids={Saids.d: DigDex.Blake3_256,
                           Saids.i: DigDex.Blake3_256,}),
                Ilks.drt: FieldDom(alls=dict(v='', t='',d='', i='', s='0',
                         p='', kt='0',k=[], nt='0', n=[], bt='0', br=[],
                        ba=[], c=[], a=[]),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rct: FieldDom(alls=dict(v='', t='',d='', i='', s='0')),
                Ilks.qry: FieldDom(alls=dict(v='', t='',d='', i='', dt='',
                        r='', rr='', q={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rpy: FieldDom(alls=dict(v='', t='',d='', i='', dt='',
                        r='',a={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.pro: FieldDom(alls=dict(v='', t='',d='', i='', dt='',
                        r='', rr='', q={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.bar: FieldDom(alls=dict(v='', t='',d='', i='', dt='',
                        r='',a={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.xip: FieldDom(alls=dict(v='', t='', d='', u='', i="", ri="",
                                             dt='', r='', q={}, a={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.exn: FieldDom(alls=dict(v='', t='', d='', i="", ri="",
                        x="", p="", dt='', r='', q={}, a={}),
                    saids={Saids.d: DigDex.Blake3_256}),
            },
        },
        Protocols.acdc:
        {
            Vrsn_1_0:
            {
                None: FieldDom(alls=dict(v='', d='', u='', i='',
                        ri='', s='', a='', A='', e='', r=''),
                    opts=dict(u='', ri='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256},
                    strict=True),
                Ilks.ace: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        ri='', s='', a='', A='', e='', r=''),
                    opts=dict(u='', ri='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256},
                    strict=False),
            },
            Vrsn_2_0:
            {
                None: FieldDom(alls=dict(v='', d='', u='', i='',
                        rd='', s='', a='', A='', e='', r=''),
                    opts=dict(u='', rd='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.acm: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        rd='', s='', a='', A='', e='', r=''),
                    opts=dict(t='', u='', rd='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.ace: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        ri='', s='', a='', A='', e='', r=''),
                    opts=dict(u='', ri='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256},
                    strict=False),
                Ilks.act: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        rd='', s='', a='', e='', r=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.acg: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        rd='', s='', A='', e='', r=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.sch: FieldDom(alls=dict(v='', t='', d='', s=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.att: FieldDom(alls=dict(v='', t='', d='', a=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.agg: FieldDom(alls=dict(v='', t='', d='', A=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.edg: FieldDom(alls=dict(v='', t='', d='', e=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rul: FieldDom(alls=dict(v='', t='', d='', r=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rip: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                                              n='', dt=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.bup: FieldDom(alls=dict(v='', t='', d='', rd='', n='',
                                              p='', dt='', b=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.upd: FieldDom(alls=dict(v='', t='', d='', rd='', n='',
                                              p='', dt='', td='', ts=''),
                    saids={Saids.d: DigDex.Blake3_256}),
            },
        },
    }


    def __init__(self, *, raw=b'', sad=None, strip=False, verify=True,
                 makify=False, smellage=None, proto=None, pvrsn=None,
                 genus=GenDex.KERI, gvrsn=None, kind=None, ilk=None, saids=None):
        """Deserialize raw if provided. Update properties from deserialized raw.
            Verifies said(s) embedded in sad as given by labels.
            When verify is True then verify said(s) in deserialized raw as
            given by label(s) according to proto and ilk and code
        If raw not provided then serialize .raw from sad with kind and code.
            When kind not provided use kind embedded in sad['v'] version string.
            When saidify is True then compute and update said(s) in sad as
            given by label(s) according to proto and ilk and code.

        Parameters:
            raw (bytes|bytearray): serialized event
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            strip (bool): True means strip (delete) raw from input stream
                bytearray after parsing. False means do not strip.
                Assumes that raw is bytearray when strip is True.
            verify (bool): True means verify said(s) of given raw or sad.
                           False means don't verify. Useful to avoid unnecessary
                           reverification when deserializing from database
                           as opposed to over the wire reception.
                           Raises ValidationError if verification fails
                           Ignore when raw empty or when raw and saidify is True
            makify (bool): True means compute fields for sad including size and
                saids.
            smellage (Smellage | None): instance of deconstructed and converted
                protocol version string elements. If none or empty ignore otherwise assume
                that raw already had its version string extracted (reaped) into the
                elements of smellage.
            proto (str | None): desired protocol type str value of Protocols
                If None then its extracted from sad or uses default .Proto
            pvrsn (Versionage | None): instance desired protocol version
                If None then its extracted from sad or uses default .Vrsn
            genus (str): CESR genus code when version field includes it (future native)
                      Otherwise use one compatible with proto
            gvrsn (Versionage): instance CESR genus code table version (Major, Minor)
                when version field includes it (future)
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
        # initialize to something to be overriden later
        self._raw = raw
        self._sad = sad
        self._proto = proto
        self._pvrsn = pvrsn
        self._genus = genus
        self._gvrsn = gvrsn
        self._kind = kind
        self._size = None


        if raw:  # deserialize raw using property setter
            self._inhale(raw=raw, smellage=smellage, strip=strip)
            # ._inhale updates ._raw, ._sad, ._proto, ._pvrsn, .gvrsn, ._kind, ._size

            # primary said field label
            try:
                label = list(self.Fields[self.proto][self.pvrsn][self.ilk].saids)[0]
                if label not in self._sad:
                    raise FieldError(f"Missing primary said field in {self._sad}.")
                self._said = self._sad[label]  # not verified
            except Exception as ex:
                self._said = None  # no saidive field

            if verify:  # verify fields including the said(s) provided in raw
                try:
                    self._verify()  # raises exception when not verify
                except Exception as ex:
                    logger.error("Invalid raw for Serder %s\n%s",
                                 self.pretty(), ex.args[0])
                    raise ValidationError(f"Invalid raw for Serder = "
                                          f"{self._sad}. {ex.args[0]}") from ex

        elif sad or makify:  # serialize sad into raw or make sad
            if makify:  # recompute properties and said(s) and reset sad
                # makify resets properties:
                # sad, raw, size, proto, pvrsn, genus, gvrsn, kind, and ilk
                self.makify(sad, proto=proto, pvrsn=pvrsn,
                            genus=genus, gvrsn=gvrsn,
                            kind=kind, ilk=ilk, saids=saids)

            else:
                # .exhale potentially updates properties:
                # sad, raw, size, proto, pvrsn, genus, gvrsn, kind, ilk
                self._exhale(sad=sad)


            try:  # ensure primary said field label is present
                label = list(self.Fields[self.proto][self.pvrsn][self.ilk].saids)[0]
                if label not in self._sad:
                    raise DeserializeError(f"Missing primary said field in {self._sad}.")
                self._said = self._sad[label]  # not verified
            except Exception:
                self._said = None  # no saidive field

            if verify:  # verify fields including the said(s) provided in sad
                try:
                    self._verify()  # raises exception if failure
                except Exception as ex:
                    logger.error("Invalid sad for Serder %s\n%s",
                                 self.pretty(), ex.args[0])
                    raise ValidationError(f"Invalid sad for Serder ="
                                              f"{self._sad}.") from ex

        else:
            raise InvalidValueError("Improper initialization need raw or sad "
                                    f"or makify.")



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
        sad, saids = self._validate()

        sad, raw, size = self._compute(sad=sad, saids=saids)

        if raw != self.raw:
            raise ValidationError(f"Invalid round trip of {sad} != \n"
                                  f"{self.sad}.")

        # extract version string elements to verify consistency with attributes
        proto, pvrsn, kind, size, gvrsn = deversify(sad["v"])
        if self.proto != proto:
            raise ValidationError(f"Inconsistent protocol={self.proto} from"
                                  f" deversify of sad.")

        if self.pvrsn != pvrsn:
            raise ValidationError(f"Inconsistent version={self.pvrsn} from"
                                  f" deversify of sad.")

        if self.kind != kind:
            raise ValidationError(f"Inconsistent kind={self.kind} ifrom"
                                  f" deversify of sad.")

        if self.kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
            if size != self.size != len(raw):
                raise ValidationError(f"Inconsistent size={self.size} from"
                                  f" deversify of sad.")
        else:  # size is not set in version string when kind is CESR
            if self.size != len(raw):
                raise ValidationError(f"Inconsistent size={self.size} from"
                                  f" deversify of sad.")

        if self.gvrsn != gvrsn:
            raise ValidationError(f"Inconsistent genus version={self.gvrsn} from"
                                  f" deversify of sad.")
        # verified successfully since no exception


    def _validate(self):
        """Validate field presence and values but not including SAID or size
        computation. Raises exception if anything is invalid

        Returns:
           tuple (sad, saids):  where
                sad (dict): self addressed data dict with dummied fields
                saids (dict)
        """

        if self.Protocol and self.proto != self.Protocol:  # class required
            raise ValidationError(f"Required protocol = {self.Protocol}, got "
                                 f"{self.proto} instead.")

        if self.proto not in self.Fields:
            raise ValidationError(f"Invalid protocol type = {self.proto}.")

        if self.genus not in GenDex:  # ensures self.genus != None
            raise ValidationError(f"Invalid genus={self.genus}.")

        if getattr(GenDex, ProGen.get(self.proto), None) != self.genus:
            raise ValidationError(f"Incompatible protocol={self.proto} with "
                                  f"genus={self.genus}.")

        if self.gvrsn is not None and self.gvrsn.major < 2:
            raise ValidationError(f"Incompatible major protocol version={self.pvrsn}"
                                 f" with major genus version={self.gvrsn}.")

        if (self.kind == Kinds.cesr and (self.pvrsn.major < Vrsn_2_0.major or
                (self.gvrsn is not None and self.gvrsn.major < Vrsn_2_0.major))):
            raise ValidationError(f"Invalid major protocol version={pvrsn} and/or"
                                  f" invalid major genus version={gvrsn} "
                                  f"for native CESR serialization.")

        if self.pvrsn not in self.Fields[self.proto]:
            raise ValidationError(f"Invalid version={self.pvrsn} for "
                                 f"protocol={self.proto}.")

        if self.ilk not in self.Fields[self.proto][self.pvrsn]:
            raise ValidationError(f"Invalid packet type (ilk) = {self.ilk} for"
                                  f"protocol = {self.proto}.")

        fields = self.Fields[self.proto][self.pvrsn][self.ilk]  # get labelage

        alls = fields.alls  # faster local reference
        oalls = oset(alls)  # ordereset of field labels
        oopts = oset(fields.opts)  # ordereset of field labels
        oreqs = oalls - oopts  # required fields

        oskeys = oset(self._sad)  # ordered set of keys in sad (skeys)
        osexts = oskeys - oalls  # get ordered set of extras in sad (sexts)
        if osexts and fields.strict:
            raise ExtraFieldError(f"Unallowed extra field(s) = {list(osexts)} "
                                     f"in sad.")

        osopts = oskeys - oreqs - osexts  # subset of opts in sad

        osalls = oalls - (oopts - osopts)  # subset of alls without missing opts in sad

        for k, v in fields.alts.items():
            if k in osopts and v in osopts:
                raise AlternateFieldError(f"Unallowed, alternate fields '{k}' "
                                          f"and '{v}' both present in sad.")

        # can't do set math osalls == oskeys - osexts becasue of osexts might be
        # out-of-order so have to iterate to ensure osexts if any appear in oskeys
        # after all fields in osalls
        for i, label in enumerate(osalls):
            if oskeys[i] != label:
                raise MissingFieldError(f"Missing or out-of-order field = {label} "
                                         f"from = {list(osalls)} in sad.")

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        saids = copy.copy(fields.saids)  # get copy of saidive field labels and defaults values
        if not (set(saids) <= set(alls)):
            raise MissingFieldError(f"Missing one or more required said fields"
                                    f" from {list(saids)} in sad = "
                                    f"{self._sad}.")

        if "v" not in self._sad:
            raise ValidationError(f"Missing version string field in {self._sad}.")

        sad = copy.copy(self._sad)  # make shallow copy so don't clobber original .sad

        for label in saids:
            try:  # replace default code with code of value from sad
                saids[label] = Matter(qb64=sad[label]).code
            except Exception as ex:
                if saids[label] in DigDex:  # digestive but invalid
                    raise ValidationError(f"Invalid said field '{label}' in sad\n"
                                      f" = {self._sad}.") from ex

            if saids[label] in DigDex:  # if digestive then replace with dummy
                sad[label] = self.Dummy * len(sad[label])

        return (sad, saids)


    def makify(self, sad, *, proto=None, pvrsn=None, genus=None, gvrsn=None,
                   kind=None, ilk=None, saids=None):
        """makify builds serder with valid properties and attributes. Computes
        saids and sizes. and assigns hidden attributes for properties:
        sad, raw, size, proto, pvrsn, genus, gvrsn, kind

        Prioritization of assigned and default values.
           Use method parameter if not None
           Else use version string from provided sad if valid
           Otherwise use class attribute

        Parameters:
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            proto (str | None): desired protocol type str value of Protocols
                If None then its extracted from sad or uses default .Proto
            pvrsn (Versionage | None): instance desired protocol version
                If None then its extracted from sad or uses default .Vrsn
            genus (str): desired CESR genus code
                If None then its uses one compatible with proto
            gvrsn (Versionage): instance desired CESR genus code table version
                If None then stays None
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
        # sets ._proto, ._pvrsn, ._genus, ._gvrsn, ._kind
        sad, saids = self._makify(sad, proto=proto, pvrsn=pvrsn, genus=genus,
                                gvrsn=gvrsn, kind=kind, ilk=ilk, saids=saids)

        sad, raw, size = self._compute(sad=sad, saids=saids)

        self._raw = raw
        self._size = size
        self._sad = sad


    def _makify(self, sad, *, proto=None, pvrsn=None, genus=None, gvrsn=None,
                   kind=None, ilk=None, saids=None):
        """_makify ensures sad has appropriate fields and field values from
        provided sad as template and parameter proto, pvrsn, genus, gvrsn,
        kind, ilk and saids, include filling in any dummy values for computing
        size and saids. Assigns hidden attributes for properties:
        proto, pvrsn, genus, gvrsn, kind


        Default prioritization.
           Use method parameter if not None
           Else use version string from provided sad if valid
           Otherwise use class attribute

        Returns:
           tuple (sad, saids):  where
                sad (dict): self addressed data dict with dummied fields
                saids (dict)


        Parameters:
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            proto (str | None): desired protocol type str value of Protocols
                If None then its extracted from sad or uses default .Proto
            pvrsn (Versionage | None): instance desired protocol version
                If None then its extracted from sad or uses default .Vrsn
            genus (str): desired CESR genus code
                If None then its uses one compatible with proto
            gvrsn (Versionage): instance desired CESR genus code table version
                If None then stays None
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
        sproto = spvrsn = skind = silk = sgvrsn = None  # from sad
        if sad:
            if 'v' in sad:  # attempt to get from vs in sad
                try:  # extract version string elements as defaults if provided
                    sproto, spvrsn, skind, _, sgvrsn = deversify(sad["v"])
                except VersionError as ex:
                    pass
                else:
                    silk = sad.get('t')  # if 't' not in sad .get returns None which may be valid

        else:  # empty or None so create sad dict
            sad = {}


        if proto is None:
            proto = sproto if sproto is not None else self.Proto

        if proto not in self.Fields:
            raise SerializeError(f"Invalid protocol={proto}.")

        if self.Protocol and proto != self.Protocol:  # required by class
            raise SerializeError(f"Required protocol={self.Protocol}, got "
                                 f"protocol={proto} instead.")

        if genus is None:  # and proto is not None
            genus = self.Genus # getattr(GenDex, proto, None)

        if genus not in GenDex:  # ensures valid genus != None
            raise SerializeError(f"Invalid genus={self.genus}.")

        if getattr(GenDex, ProGen.get(proto), None) != genus:   # ensure compatible proto
            raise SerializeError(f"Incompatible protocol={proto} with "
                                  f"genus={genus}.")

        if pvrsn is None:
            pvrsn = spvrsn if spvrsn is not None else self.PVrsn

        if pvrsn not in self.Fields[proto]:
            raise SerializeError(f"Invalid version={pvrsn} for protocol={proto}.")

        if gvrsn is None:  # use default GVrsn only if pvrsn >= 2 othwise leave gvrsn None
            gvrsn = sgvrsn if sgvrsn is not None else (self.GVrsn if pvrsn.major >= 2 else None)


        if gvrsn is not None and gvrsn.major < 2:
            raise SerializeError(f"Incompatible major protocol version={pvrsn} "
                                 f"with major genus version={gvrsn}")

        if kind is None:
            kind = skind if skind is not None else self.Kind

        if ilk is None:  # default is first ilk in Fields for given proto pvrsn
            ilk = (silk if silk is not None else
                   list(self.Fields[proto][pvrsn])[0])  # list(dict) gives list of keys

        if kind not in Kinds:
            raise SerializeError(f"Invalid serialization kind = {kind}")

        if ilk not in self.Fields[proto][pvrsn]:
            raise SerializeError(f"Invalid packet type (ilk) = {ilk} for"
                                  f"protocol = {proto}.")

        fields = self.Fields[proto][pvrsn][ilk]  # get FieldDom of fields

        alls = fields.alls  # faster local reference
        oalls = oset(alls)  # ordereset of field labels
        oopts = oset(fields.opts)  # ordereset of field labels
        oreqs = oalls - oopts  # required fields

        # ensure all required fields are in sad. If not provide default
        for label in oreqs:
            if label not in sad:
                value = alls[label]
                if helping.isNonStringIterable(value):
                    value = copy.copy(value)  # copy iterable defaults
                sad[label] = value

        sadold = sad
        sad = {}
        for label in oalls:  # make sure all fields are in correct order
            if label in sadold:
                sad[label] = sadold[label]

        for label in sadold:  # copy extras if any
            if label not in sad:
                sad[label] = sadold[label]

        if 't' in sad:  # when packet type field then force ilk
            sad['t'] = ilk  # assign ilk

        # ensure required fields are present and all fields are ordered wrt alls
        oskeys = oset(sad)  # ordered set of keys in sad (skeys)
        osexts = oskeys - oalls  # get ordered set of extras in sad (sexts)
        if osexts and fields.strict:
            raise SerializeError(f"Unallowed extra field(s) = {list(osexts)} "
                                 f"in sad.")

        osopts = oskeys - oreqs - osexts  # subset of opts in sad

        osalls = oalls - (oopts - osopts)  # subset of alls without missing opts in sad

        for k, v in fields.alts.items():
            if k in osopts and v in osopts:
                raise SerializeError(f"Unallowed, alternate fields '{k}' "
                                          f"and '{v}' both present in sad.")

        # can't do set math osalls == oskeys - osexts becasue of osexts might be
        # out-of-order so have to iterate to ensure osexts if any appear in oskeys
        # after all fields in osalls
        for i, label in enumerate(osalls):
            if oskeys[i] != label:
                raise SerializeError(f"Missing or out-of-order field = {label} "
                                            f"from = {list(osalls)} in sad.")

        if 'v' not in sad:  # ensures that 'v' is always required by .Labels
            raise SerializeError(f"Missing required version string field 'v'"
                                          f" in sad = {sad}.")

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        _saids = copy.copy(fields.saids)  # get copy of defaults
        if not (set(_saids) <= set(alls)):  # sets from labels (dict keys)
            raise SerializeError(f"Missing one or more required said fields "
                                 f"from {list(_saids)} in sad = {sad}.")

        # override saidive defaults
        for label in _saids:
            if saids and label in saids:  # use makify parameter override
                _saids[label] = saids[label]  # value is cesr code
            else:  # use provided sad field override if any
                try:  # use code of sad field value if present
                    _saids[label] = Matter(qb64=sad[label]).code
                except Exception:
                    pass  # no provided sad field override
            # when code is digestive then we know we have to compute said dummy
            # this accounts for aid fields that may or may not be saids
            if _saids[label] in DigDex:  # if digestive then fill with dummy
                sad[label] = self.Dummy * Matter.Sizes[_saids[label]].fs

        if kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):  # dummy version string
            # Non native the size the version string depends on version so we
            # need to dummy the version string in order to get the size right.
            # It needs to be computed based on actual version string span
            # since not same for all versions
            sad['v'] = self.Dummy * self.Spans[pvrsn]  # ensure span of vs is dummied MAXVERFULLSPAN

        # do this now so ._dumps of cesr native can use properties without having
        # re-deversify sad['v'] each time
        self._proto = proto
        self._pvrsn = pvrsn
        self._genus = genus
        self._gvrsn = gvrsn
        self._kind = kind

        return (sad, _saids)


    def _compute(self, sad, saids):
        """Computes computed fields. These include size and said fields that have
        dummy characters. Replaces dummied fields with computed values.
        In the case of version strings replaces dummy size characters with
        actual size. In the case of SAID fields replaces dummy said characters
        with actual computed saids

        Returns:
            stuff (tuple): of form (sad, raw, size) where:
                sad is de-dummied sad, raw is raw serialization of dedummied sad,
                and size is size of raw or None when sized is True and hence the
                size is not calculated.

        Parameters:
            sad (dict): dummied serder sad (self addressed data dict)
            saids (dict): said field labels and cesr code that identifies how


        """
        # assumes sad['v'] sad said fields are fully dummied at this point

        if self.kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):  # sizify version string
            raw = self.dumps(sad, self.kind)  # get size of sad with fully dummied vs and saids
            size = len(raw)

            # generate version string with correct size
            vs = versify(proto=self.proto, pvrsn=self.pvrsn, kind=self.kind, size=size, gvrsn=self.gvrsn)
            sad["v"] = vs  # update version string in sad
            # now have correctly sized version string in sad

        # compute saidive digestive field values using raw from sized dummied sad
        raw = self.dumps(sad, kind=self.kind)  # serialize sized dummied sad

        # replace dummied fields with computed digests
        for label, code in saids.items():
            if code in DigDex:  # subclass override if non digestive allowed
                sad[label] = Diger(ser=raw, code=code).qb64

        # Now reserialize raw with undummied field values
        raw = self.dumps(sad, kind=self.kind)  # assign final raw

        if self.kind == Kinds.cesr:# cesr kind version string does not set size
            size = len(raw) # size of whole message
            sad['v'] = versify(proto=self.proto, pvrsn=self.pvrsn,
                               kind=self.kind, size=size, gvrsn=self.gvrsn)

        return (sad, raw, size)


    def _inhale(self, raw, *, smellage=None, strip=False):
        """Deserializes raw.
        Parses serilized event ser of serialization kind and assigns to
        instance attributes and returns tuple of associated elements.

        As classmethod enables testing parsing raw serder values. This can be
        called on self as well because it only ever accesses clas attributes
        not instance attributes.

        Returns: tuple (sad, proto, vrsn, kind, size) where:
            sad (dict): serializable attribute dict of saidified data
            proto (str): value of Protocols (Protocolage) protocol type
            pvrsn (Versionage | None): protocol tuple of (major, minor) version ints
                None means do not enforce version
            kind (str): value of Serials (Serialage) serialization kind

        Parameters:
            clas (Serder): class reference
            raw (bytes|bytearray): serialized sad message
            smellage (Smellage | None): instance of deconstructed version string
                elements. If none or empty ignore otherwise assume that raw
                already had its version string extracted (reaped) into the
                elements of smellage.
            strip (bool): True means strip (delete) raw from input stream
                bytearray after parsing. False means do not strip.
                Assumes that raw is bytearray when strip is True.

        """
        # CESR native must always pass in smellage since can't smell native
        if smellage:  # passed in so don't need to smell raw again
            proto, pvrsn, kind, size, gvrsn = smellage  # tuple unpack
            if len(raw) < size:
                raise ShortageError(f"Need more bytes to de-serialize Serder")

            sraw = raw[:size]
            if strip and isinstance(raw, bytearray):
                del raw[:size]

        else:  # not passed in so smell raw raises VersionError if native
            cold = sniff(raw)
            if cold == Colds.msg:
                proto, pvrsn, kind, size, gvrsn = smell(raw)
                if len(raw) < size:
                    raise ShortageError(f"Need more bytes to de-serialize Serder")

                sraw = raw[:size]
                if strip and isinstance(raw, bytearray):
                    del raw[:size]

            else:
                if cold == Colds.bny:
                    counter = Counter(qb2=raw)
                    ss = counter.byteCount(cold=cold) + counter.byteSize(cold=cold)
                    if len(raw) < ss:
                        raise ShortageError(f"Not enough raw bytes for serder")
                    sraw = raw[:ss]  # only copy enough bytes for serder
                    if strip and isinstance(raw, bytearray):
                        del raw[:ss]
                    sraw = encodeB64(raw)  # loads expects Base64 text domain
                elif cold == Colds.txt:
                    counter = Counter(qb64b=raw)
                    ss = counter.byteCount(cold=cold) + counter.byteSize(cold=cold)
                    if len(raw) < ss:
                        raise ShortageError(f"Not enough raw bytes for serder")
                    sraw = raw[:ss]  # only copy enough bytes for serder
                    if strip and isinstance(raw, bytearray):
                        del raw[:ss]
                else:
                    raise ValueError(f"Invalid {cold=} for Serder raw")

                size = len(sraw)
                kind = Kinds.cesr
                proto, pvrsn, gvrsn = Verser(qb64b=sraw[counter.fullSize:]).versage

        self._proto = proto
        self._pvrsn = pvrsn
        self._kind = kind
        self._size = size
        self._gvrsn = gvrsn

        sad = self.loads(raw=sraw, size=size, kind=kind)

        if "v" not in sad:  # Regex does not check for version string label itself
            raise FieldError(f"Missing version string field in {sad}.")

        # cypto opts want bytes not bytearray
        self._raw = bytes(sraw)  # make bytes if bytearray
        self._sad = sad



    def loads(self, raw, size=None, kind=Kinds.json):
        """method to handle deserialization by kind
        assumes already sniffed and smelled to determine
        serialization size and kind

        Returns:
            sad (dict|list): de-serialized dict or list.
                            Supposed to be dict of saidified data.

        Parameters:
            raw (bytes | bytearray): raw serialization to deserialze as dict
            size (int): number of bytes to consume for the deserialization.
                       If None then consume all bytes in raw
            kind (str): value of Serials (Serialage) serialization kind
                       "JSON", "MGPK", "CBOR", "CESR"

        Notes:
            loads of json uses str whereas loads of cbor and msgpack use bytes
        """
        if size is None:
            size = len(raw)

        if kind == Kinds.cesr:
            try:
                sad = self._loads(raw=raw, size=size)
            except Exception as ex:
                raise DeserializeError(f"Error deserializing CESR: "
                                      f"{raw[:size].decode()}") from ex

        elif kind == Kinds.json:
            try:
                sad = json.loads(raw[:size].decode("utf-8"))
            except Exception as ex:
                raise DeserializeError(f"Error deserializing JSON: "
                    f"{raw[:size].decode()}") from ex

        elif kind == Kinds.mgpk:
            try:
                sad = msgpack.loads(raw[:size])
            except Exception as ex:
                raise DeserializeError(f"Error deserializing MGPK: "
                    f"{raw[:size].decode()}") from ex

        elif kind == Kinds.cbor:
            try:
                sad = cbor.loads(raw[:size])
            except Exception as ex:
                raise DeserializeError(f"Error deserializing CBOR: "
                    f"{raw[:size].decode()}") from ex

        else:
            raise DeserializeError(f"Invalid deserialization kind: {kind}")

        return sad


    def _loads(self, raw, size=None):
        """CESR native de-serialization from raw in qb64b text domain bytes

        Returns:
            sad (dict): deserialized dict of CESR native serialization.

        Parameters:
            raw (bytes |bytearray): qb64b raw serialization in text domain byte
                                   to deserialze as dict
            size (int): number of bytes to consume for the deserialization.
                       If None then consume all bytes in raw

        """
        # assumes that .proto, .kind, .size, .pvrsn, .gvrsn set above in
        # .inhale with passed in smellage
        sad = {}
        # make copy so strip here does not collide with .__init__ strip
        if size is None:
            size = len(raw)
        raw = bytearray(raw[:size])  # extract full message from raw as bytearray

        # consume body ctr
        bctr = Counter(qb64b=raw, strip=True, version=self.gvrsn) # gvrsn from smellage
        # assign fixed
        if (bctr.code in (self.mucodes.FixBodyGroup,
                          self.mucodes.BigFixBodyGroup)):
            fixed = True
        elif  (bctr.code in (self.mucodes.MapBodyGroup,
                             self.mucodes.BigMapBodyGroup)):
            fixed = False
        else:
            raise DeserializeError(f"Unexpected CESR message body group "
                                   f"code={bctr.code}")


        # consume label for version field if field map (not fixed)
        if not fixed:
            labeler = Labeler(qb64b=raw, strip=True)  # offset past ctr

        # consume version field assumes compatible versage with prior smellage
        versage = Verser(qb64b=raw, strip=True).versage


        if self.proto == Protocols.keri:
            # read off ilk so can get rest of fields in order to parse
            ilk = Ilker(qb64b=raw, strip=True).ilk
            if ilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt,
                                 Ilks.rct, Ilks.qry, Ilks.rpy, Ilks.pro, Ilks.bar,
                                 Ilks.xip, Ilks.exn):
                raise DeserializeError(f"Unexpected {ilk=}")

            # FieldDom for given protocol and ilk,must be fixed field see check below
            fields = self.Fields[self.proto][self.pvrsn][ilk]  # get fields keyed by ilk

            if not fixed:
                raise DeserializeError(f"Expected fixed field got {ilk=}")

            if fields.opts or not fields.strict:  # optional or extra fields allowed
                raise DeserializeError(f"Expected fixed field for {ilk=} got {fields=}")

            # assumes that sad's field ordering and field inclusion is correct
            # so can deserialize in order
            for l in fields.alls:  # l for label assumes valid field order & presence
                match l:  # label
                    case "v":  # proto+pvrsn+gvrsn when gvrsn not None, not vs
                        sad[l] = versify(proto=self.proto, pvrsn=self.pvrsn, kind=self.kind,
                           size=size, gvrsn=self.gvrsn)

                    case "t":  # message type (ilk), already got ilk
                        sad[l] = ilk

                    case "d" | "p" | "x":  # SAID
                        sad[l] = Diger(qb64b=raw, strip=True).qb64

                    case "u":  # UUID salty Nonce
                        sad[l] = Noncer(qb64b=raw, strip=True).qb64

                    case "i" | "di" | "ri":  # AID
                        sad[l] = Prefixer(qb64b=raw, strip=True).qb64

                    case "s" | "bt":  # sequence number or numeric threshold
                        sad[l] = Number(qb64b=raw, strip=True).numh  # as hex str

                    case "kt" | "nt":  # current or next signing threshold
                        sad[l] = Tholder(limen=raw, strip=True).sith  # as sith str

                    case "k" | "n" | "b" | "ba" | "br":  # list of primitives
                        ctr = Counter(qb64b=raw, strip=True, version=self.gvrsn)
                        if ctr.name not in ('GenericListGroup', 'BigGenericListGroup'):
                            raise DeserializeError(f"Expected List group got {ctr.name}")
                        fs = ctr.count * 4  # frame size since qb64 text mode
                        frame = raw[:fs]  # extract list frame
                        raw = raw[fs:]
                        elements = []
                        while frame:  # not yet empty
                            elements.append(Matter(qb64b=frame, strip=True).qb64)
                        sad[l] = elements

                    case "dt":  # datetime string
                        sad[l] = Dater(qb64b=raw, strip=True).dts

                    case "r" | "rr":  # route or return route
                        sad[l] = Pather(qb64b=raw, strip=True).path

                    case "c":  # list of config traits strings
                        ctr = Counter(qb64b=raw, strip=True, version=self.gvrsn)
                        if ctr.name not in ('GenericListGroup', 'BigGenericListGroup'):
                            raise DeserializeError(f"Expected List group got {ctr.name}")
                        fs = ctr.count * 4  # frame size since qb64 text mode
                        frame = raw[:fs]  # extract list frame
                        raw = raw[fs:]
                        elements = []
                        while frame:  # not yet empty
                            elements.append(Traitor(qb64b=frame, strip=True).trait) # as trait str
                        sad[l] = elements

                    case "a":  # list of seals or field map of attributes
                        ctr = Counter(qb64b=raw, version=self.gvrsn)  # peek at counter
                        if ctr.name in ('GenericMapGroup', 'BigGenericMapGroup'):
                            sad[l] = Mapper(raw=raw, strip=True).mad

                        elif ctr.name in ('GenericListGroup', 'BigGenericListGroup'):
                            if ilk not in (Ilks.icp, Ilks.ixn, Ilks.rot, Ilks.dip, Ilks.drt):
                                raise SerializeError(f"Unexpected list value for"
                                            f"field='{l}' for {ilk=}")
                            del raw[:ctr.fullSize]  # consume counter
                            seals = []
                            fs = ctr.count * 4  # frame size since qb64 text mode
                            frame = raw[:fs]  # extract list frame
                            raw = raw[fs:]  # strip frame from raw
                            while frame:  # while list frame not empty
                                sctr = Counter(qb64b=frame, strip=True, version=self.gvrsn)  # seal counter
                                if sctr.code not in Serder.CodeClans:
                                    raise DeserializeError(f"Expected Sealer group got {sctr.name}")
                                cast = Sealer.Casts[Serder.CodeClans[sctr.code]]
                                sfs = sctr.count * 4
                                sframe = frame[:sfs]  # extra seal frame
                                frame = frame[sfs:]  # strip sfram from frame
                                while sframe:  # while seal frame not empty
                                    # append sad dict version of seal to seals
                                    seals.append(Sealer(cast=cast,
                                                        qb64b=sframe,
                                                        strip=True).asdict)
                            sad[l] = seals

                        else:
                            raise DeserializeError(f"Expected Map or List group"
                                                   f"got {ctr.name}")

                    case "q":  # Query parameters field map
                        sad[l] = Mapper(raw=raw, strip=True).mad

                    case _:  # if extra fields this is where logic would be
                        raise DeserializeError(f"Unsupported protocol field label"
                                             f"='{l}' for protocol={proto}"
                                             f" version={pvrsn}.")



        elif self.proto == Protocols.acdc:
            if fixed:
                ilk = Ilker(qb64b=raw, strip=True).ilk  # consume message typle field
                if ilk not in (Ilks.rip, Ilks.bup, Ilks.upd, Ilks.act, Ilks.acg,
                              Ilks.sch, Ilks.att, Ilks.agg, Ilks.edg, Ilks.rul):
                    raise DeserializeError(f"Unexpected {ilk=} for fixed field body")
                # FieldDom for given protocol and ilk
                fields = self.Fields[self.proto][self.pvrsn][ilk]  # get fields keyed by ilk

                if fields.opts or not fields.strict and fixed:  # optional or extra fields allowed
                    raise DeserializeError(f"Expected fixed field for {ilk=} got {fields=}")

                # assumes that sad's field ordering and field inclusion is correct
                # so can deserialize in order
                for l in fields.alls:  # assumes valid field order & presence
                    match l:  # label
                        case "v":  # proto+pvrsn+gvrsn not vs
                            sad[l] = versify(proto=self.proto, pvrsn=self.pvrsn, kind=self.kind,
                               size=size, gvrsn=self.gvrsn)

                        case "t":  # message type (ilk), already got ilk
                            sad[l] = ilk

                        case "d"|"p"|"b":  # SAID must not be empty
                            sad[l] = Diger(qb64b=raw, strip=True).qb64

                        case "u":  # UUID salty Nonce or empty
                            sad[l] = Noncer(qb64b=raw, strip=True).nonce

                        case "i":  # AID must not be empty
                            sad[l] = Prefixer(qb64b=raw, strip=True).qb64

                        case "n":  # sequence number
                            sad[l] = Number(qb64b=raw, strip=True).numh  # as hex str

                        case "rd":  # said or empty
                            sad[l] = Noncer(qb64b=raw, strip=True).nonce

                        case "dt":  # datetime string
                            sad[l] = Dater(qb64b=raw, strip=True).dts

                        case "td":  # transaction event acdc said or empty
                            sad[l] = Noncer(qb64b=raw, strip=True).nonce

                        case "ts":  # transaction event state string or empty
                            sad[l] = Labeler(qb64b=raw, strip=True).text

                        case "s":  # schema said, or schema block
                            if raw[0] == ord(b'-'):  # counter so should be field map
                                ctr = Counter(qb64b=raw)  # peek at counter
                                if ctr.name in ('GenericMapGroup', 'BigGenericMapGroup'):
                                    # schema field labels not strict
                                    sad[l] = Mapper(qb64=raw,
                                                    strip=True,
                                                    strict=False).mad
                                else:
                                    raise DeserializeError(f"Expected Map group"
                                                       f"got {ctr.name}")
                            else:
                                sad[l] = Diger(qb64b=raw, strip=True).qb64

                        case "a"|"e"|"r" :  # attribute SAID or attribute block
                            if raw[0] == ord(b'-'):  # counter so should be field map
                                ctr = Counter(qb64b=raw)  # peek at counter
                                if ctr.name in ('GenericMapGroup', 'BigGenericMapGroup'):
                                    sad[l] = Mapper(qb64=raw, strip=True).mad
                                else:
                                    raise DeserializeError(f"Expected Map group"
                                                       f"got {ctr.name}")
                            else:  # may not be empty str
                                sad[l] = Diger(qb64b=raw, strip=True).qb64

                        case "A":  # Aggregate said or Aggregate list of blocks
                            if raw[0] == ord(b'-'):  # counter so should be field map
                                ctr = Counter(qb64b=raw)  # peek at counter
                                if ctr.name in ('GenericListGroup', 'BigGenericListGroup'):
                                    fs = ctr.fullSize
                                    del raw[:fs]  # consume counter
                                    gcs = ctr.byteSize()  # content size
                                    buf = raw[:gcs]
                                    del raw[:gcs]  # consume counter content
                                    blocks = []
                                    while buf:
                                        blocks.append(Mapper(raw=buf, strip=True).mad)
                                    sad[l] = blocks
                                else:
                                    raise DeserializeError(f"Expected List group"
                                                       f"got {ctr.name}")
                            else:
                                sad[l] = Diger(qb64b=raw, strip=True).qb64


                        case _:  # if extra fields this is where logic would be
                            raise DeserializeError(f"Unsupported protocol field label"
                                                 f"='{l}' for protocol={proto}"
                                                 f" version={pvrsn}.")



            else:  # not fixed
                labeler = Labeler(qb64b=raw, strip=True)  # consume message type label
                ilk = Ilker(qb64b=raw, strip=True).ilk  # consume message typle field
                if ilk not in (Ilks.acm,Ilks.ace):
                    raise DeserializeError(f"Unexpected {ilk=} for field map body")

                # FieldDom for given protocol and ilk
                fields = self.Fields[self.proto][self.pvrsn][ilk]  # get fields keyed by ilk

                # see mapper for how to deserialized field map here


        else:
            raise DeserializeError(f"Unsupported protocol={self.proto}.")

        return sad


    def _exhale(self, sad):
        """Serializes sad and assigns attributes.
        Asssumes all field values in sad are valid
        Otherwise must first call .verify

        Parameters:
            sad (dict): serializable attribute dict of saidified data
        """
        if "v" not in sad:
            raise SerializeError(f"Missing version string field in {sad}.")

        # extract elements so can get kind, replace size element but keep others
        proto, pvrsn, kind, size, gvrsn = deversify(sad["v"])
        # cesr native  uses self.proto, self,prvsn, and self.gvsn  in dumps
        # need kind to indicate dump without relooking at version.

        self._proto = proto
        self._pvrsn = pvrsn
        self._gvrsn = gvrsn
        self._kind = kind

        raw = self.dumps(sad, kind)

        if kind == Kinds.cesr:  # cesr kind version string does not set size
            size = len(raw) # size of whole message
            sad['v'] = versify(proto=proto, pvrsn=pvrsn, kind=kind, size=size, gvrsn=gvrsn)

        # must call .verify to ensure these are compatible
        self._raw = raw  # crypto opts want bytes not bytearray
        self._size = size
        self._sad = sad



    def dumps(self, sad=None, kind=Kinds.json):
        """Method to handle serialization by kind
        Assumes sad fields are properly filled out for serialization kind.

        Returns:
            raw (bytes): serialization of sad dict using serialization kind

        Parameters:
            sad (dict|None)): serializable dict or list to serialize
                              If None use self.sad
            kind (str): value of Serials (Serialage) serialization kind
                "JSON", "MGPK", "CBOR", "CESR"

        Notes:
            dumps of json uses str whereas dumps of cbor and msgpack use bytes
            crypto opts want bytes not bytearray
        """
        sad = sad if sad is not None else self.sad

        if not isinstance(sad, Mapping):
            raise ValueError(f"Serder sad must be Mapping not {type(sad)}")

        if kind == Kinds.json: # json.dumps returns str
            raw = json.dumps(sad, separators=(",", ":"),
                             ensure_ascii=False).encode()

        elif kind == Kinds.mgpk:  # mgpk.dumps returns bytes
            raw = msgpack.dumps(sad)

        elif kind == Kinds.cbor:  # cbor.dumps returns bytes
            raw = cbor.dumps(sad)

        elif kind == Kinds.cesr:  # _dumps returns bytes qb64b
            raw = self._dumps(sad)

        else:
            raise SerializeError(f"Invalid serialization kind = {kind}")

        return raw


    def _dumps(self, sad=None):
        """CESR native serialization of sad in qb64b text domain bytes

        Returns:
            raw (bytes): CESR native serialization of sad dict in qb64b text domain

        Parameters:
            sad (dict|None)): serializable dict to serialize
                              If None use self.sad

        Versioning:
            CESR native serialization includes in its fixed version field
            a version primitive that includes message protocol+protocol version
            +genus version: 0NPPPPMmmMmm (12 B64 characters)

            This assumes that genus is compatible with message
            protocol so genus is not needed. This protects from malleability attack
            and ensure compatible cesr codes especially count (group) codes.
            Primitive codes are less problematic since so far all primitive codes
            tables are backwards compatible across major versions.

        """
        sad = sad if sad is not None else self.sad
        proto = self.proto
        pvrsn = self.pvrsn
        gvrsn = self.gvrsn

        raw = bytearray()  # message as qb64
        bdy = bytearray()  # message body as qb64

        ilks = self.Fields[proto][pvrsn]  # get fields keyed by ilk

        if proto == Protocols.keri:
            ilk = sad.get('t')  # returns None if missing message type (ilk)
            if ilk not in ilks:  #
                raise SerializeError(f"Missing or unsupported message type field "
                                     f"'t', {ilk=} for protocol={proto} "
                                     f"version={pvrsn} with {sad=}.")

            if ilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt,
                            Ilks.rct, Ilks.qry, Ilks.rpy, Ilks.pro, Ilks.bar,
                            Ilks.xip, Ilks.exn):
                raise SerializeError(f"Unexpected {ilk=} for protocol={proto}")

            fields = ilks[ilk]  # FieldDom for given protocol and ilk

            if fields.opts or not fields.strict:  # not fixed
                raise SerializeError(f"Not fixed field {ilk=}")

            # assumes that sad's field ordering and field inclusion is correct
            # so can serialize in order to compute saidive fields
            for l, v in sad.items():  # assumes valid field order & presence
                match l:  # label
                    case "v":  # proto+pvrsn+gvrsn when gvrsn not None, not vs
                        # ignores sad['vs'] field
                        val = Verser(proto=proto, pvrsn=pvrsn, gvrsn=gvrsn).qb64b

                    case "t":  # message type (ilk), already got ilk
                        val = Ilker(ilk=v).qb64b  # assumes same

                    case "d" | "i" | "p" | "u" | "di" | "ri" | "x":  # said or aid
                        val = v.encode("utf-8")  # already primitive qb64 make qb6b

                    case "s" | "bt":  # sequence number or numeric threshold
                        val = Number(numh=v).qb64b  # convert hex str

                    case "kt" | "nt": # current or next signing threshold
                        val = Tholder(sith=v).limen  # convert sith str

                    case "k" | "n" | "b" | "ba" | "br":  # list of primitives
                        frame = bytearray()
                        for e in v:  # list
                            frame.extend(e.encode("utf-8"))

                        val = bytearray(Counter(Codens.GenericListGroup,
                                                count=len(frame) // 4,
                                                version=gvrsn).qb64b)
                        val.extend(frame)

                    case "dt":  # iso datetime
                        val = Dater(dts=v).qb64b  # dts to qb64b

                    case "r" | "rr":  # route or return route
                        val = Pather(path=v, relative=True, pathive=False).qb64b  # path to qb64b

                    case "c":  # list of config traits strings
                        frame = bytearray()
                        for e in v:  # list
                            frame.extend(Traitor(trait=e).qb64b)

                        val = bytearray(Counter(Codens.GenericListGroup,
                                                count=len(frame) // 4,
                                                version=gvrsn).qb64b)
                        val.extend(frame)

                    case "a":  # list of seals or field map of attributes
                        if isinstance(v, Mapping): # field map of attributes
                            val = Mapper(mad=v).qb64b

                        else:  # assumes list of seals
                            if ilk not in (Ilks.icp, Ilks.ixn, Ilks.rot, Ilks.dip, Ilks.drt):
                                raise SerializeError(f"Unexpected list value for"
                                                     f" field='{l}' for {ilk=}")
                            frame = bytearray()  # whole list
                            gcode = None  # code for counter for consecutive same type seals
                            gframe = bytearray()  # consecutive same type seals
                            for e in v:  # list of seal dicts
                                # need support for grouping consecutive seals of same type with same counter

                                try:
                                    sealer = Sealer(crew=e)
                                    code = self.ClanCodes[sealer.name]
                                    if gcode and gcode == code:
                                        gframe.extend(sealer.qb64b)
                                    else:
                                        if gframe:  # not same so close off and rotate group
                                            counter = Counter(code=gcode,
                                                              count=len(gframe) // 4,
                                                              version=gvrsn)
                                            frame.extend(counter.qb64b + gframe)
                                            gframe = bytearray()  # new group
                                        gcode = code  # new group or keep same group
                                        gframe.extend(sealer.qb64b)  # extend in new group

                                except kering.InvalidValueError:
                                    if gframe:
                                        counter = Counter(code=gcode,
                                                          count=len(gframe) // 4,
                                                          version=gvrsn)
                                        frame.extend(counter.qb64b + gframe)
                                        gframe = bytearray()
                                        gcode = None

                                    #unknown seal type so serialize as field map
                                    #generic seal no count type (v, Mapping):
                                    #for l, e in v.items():
                                        #pass
                                    #val = bytearray(Counter(tag=""GenericMapGroup"",
                                                   # count=len(frame) // 4).qb64b)
                                    #val.extend(mapframe)

                            if gframe:  # close off last group if any
                                counter = Counter(code=gcode,
                                                  count=len(gframe) // 4,
                                                  version=gvrsn)
                                frame.extend(counter.qb64b + gframe)
                                gframe = bytearray()
                                gcode = None

                            val = bytearray(Counter(Codens.GenericListGroup,
                                                    count=len(frame) // 4).qb64b)
                            val.extend(frame)

                    case "q":  # map of query parameters
                        val = Mapper(mad=v).qb64b

                    case _:  # if extra fields this is where logic would be
                        raise SerializeError(f"Unsupported protocol field label"
                                             f"='{l}' for protocol={proto}"
                                             f" version={pvrsn}.")

                bdy.extend(val)

            raw = Counter.enclose(qb64=bdy, code=Codens.FixBodyGroup, version=gvrsn)

        elif proto == Protocols.acdc:
            ilk = sad.get('t')  # returns None if missing message type (ilk)
            if ilk not in ilks:  # allows None for implicit 'acm'
                raise SerializeError(f"Missing or unsupported message type field "
                                     f"'t', {ilk=} for protocol={proto} "
                                     f"version={pvrsn} with {sad=}.")

            if ilk not in (Ilks.acm, Ilks.ace, Ilks.act, Ilks.acg,
                           Ilks.sch, Ilks.att, Ilks.agg, Ilks.edg, Ilks.rul,
                           Ilks.rip, Ilks.bup, Ilks.upd):
                raise SerializeError(f"Unexpected {ilk=} for protocol={proto}")

            fields = ilks[ilk]  # FieldDom for given protocol and ilk

            if (fields.opts or not fields.strict) and ilk not in (Ilks.acm, Ilks.ace):
                raise SerializeError(f"Mismatch field spec to {ilk=}")

            # assumes that sad's field ordering and field inclusion is correct
            # so can serialize in order to compute saidive fields

            if ilk in (Ilks.acm, Ilks.ace):  # top-level field map
                for l, v in sad.items():  # assumes valid field order & presence
                    pass

                raw = Counter.enclose(qb64=bdy, code=Codens.MapBodyGroup, version=gvrsn)

            else: # top-level fixed field
                for l, v in sad.items():  # assumes valid field order & presence
                    match l:  # label
                        case "v":  # proto+pvrsn+gvrsn when gvrsn not None, not vs
                            val = Verser(proto=proto, pvrsn=pvrsn, gvrsn=gvrsn).qb64b

                        case "t":  # message type (ilk), already got ilk
                            val = Ilker(ilk=v).qb64b  # assumes same

                        case "d"|"i"|"p"|"b":  # said or aid non-empty
                            val = v.encode()  # already primitive qb64 make qb6b

                        case "u":  # uuid or nonce or empty
                            val = Noncer(nonce=v).qb64b  # convert nonce/uuid

                        case "rd":  # registry said or empty
                            val = Noncer(nonce=v).qb64b  # convert nonce/uuid

                        case "n":  # sequence number
                            val = Number(numh=v).qb64b  # convert hex str

                        case "dt":  # iso datetime
                            val = Dater(dts=v).qb64b  # dts to qb64b

                        case "td":  # transaction event acdc said or empty
                            val = Noncer(nonce=v).qb64b  # convert nonce/uuid

                        case "ts":  # transaction event state string
                            val = Labeler(text=v).qb64b  # convert text to qb64b

                        case "s":  # schema said or block
                            if isinstance(v, Mapping):  # assumes valid said
                                val = Mapper(mad=v, strict=False).qb64b
                            else:  # said but may not be empty
                                if not v:  # schema as said must not be empty
                                    raise SerializeError(f"Invalid section={l} "
                                                         f"empty said")
                                val = Diger(qb64=v).qb64b

                        case "a"|"e"|"r" :  # said or block, block may be empty
                            if isinstance(v, Mapping):
                                val = Mapper(mad=v).qb64b
                            else:  # said but may not be empty
                                if not v:  # section as said must not be empty
                                    raise SerializeError(f"Invalid section={l} "
                                                         f"empty said")
                                val = Diger(qb64=v).qb64b

                        case "A":  # aggregate or list of blocks list may be empty
                            if isinstance(v, list):
                                frame = bytearray()
                                for e in v:  # list of blocks
                                    frame.extend(Mapper(mad=e).qb64b)

                                val = Counter.enclose(qb64=frame,
                                                      code=Codens.GenericListGroup)
                            else:  # said but may not be empty
                                if not v:  # aggregate as said must not be empty
                                    raise SerializeError(f"Invalid section={l} "
                                                         f"empty said")
                                val = val = Diger(qb64=v).qb64b

                        case _:  # if extra fields this is where logic would be
                            raise SerializeError(f"Unsupported protocol field label"
                                                 f"='{l}' for protocol={proto}"
                                                 f" version={pvrsn}.")

                    bdy.extend(val)

                raw = Counter.enclose(qb64=bdy, code=Codens.FixBodyGroup, version=gvrsn)

        else:
            raise SerializeError(f"Unsupported protocol={self.proto}.")




        return bytes(raw)  # must return bytes so can sign, do crypto operations



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
    def genus(self):
        """genus (CESR genu code) property getter

        Returns:
            genus (stre): CESR genus code for this Serder
        """
        return self._genus


    @property
    def gvrsn(self):
        """gvrsn (CESR genus version) property getter

        Returns:
            gvrsn (Versionage): instance, CESR genus code table version for this Serder
        """
        return self._gvrsn


    @property
    def kind(self):
        """kind property getter
        Returns:
            kind (str): value of Serials (Serialage)"""
        return self._kind


    @property
    def proto(self):
        """proto property getter,
        protocol identifier type value of Protocolage such as 'KERI' or 'ACDC'

        Returns:
            proto (str): Protocolage value as protocol type
        """
        return self._proto

    @property
    def protocol(self):
        """protocp; property getter, alias of .proto
        protocol identifier type value of Protocolage such as 'KERI' or 'ACDC'

        Returns:
            protocol (str): Protocolage value as protocol type
        """
        return self.proto


    @property
    def pvrsn(self):
        """vrsn (version) property getter

        Returns:
            vrsn (Versionage): instance of protocol version for this Serder
        """
        return self._pvrsn


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
        if not self.Fields[self.proto][self.pvrsn][self.ilk].saids and 'd' in self._sad:
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

    @property
    def stamp(self):
        """stamp property getter (datetime stamp in iso8601 format)
        Optional fields return None when not present
        Returns:
           stamp (str | None): sad["dt"] when present
        """
        return self._sad.get('dt')

    @property
    def mucodes(self):
        """Selects mucodes from .MUCodes based on .gvrsn
        Returns:
            mucodes (MUDex): selected by .gvrsn latest from (MUDex_1_0, MUDex_2_0)
        """
        # get latest supported minor version
        latest = list(self.MUCodes[self.gvrsn.major])[-1]
        return self.MUCodes[self.gvrsn.major][latest]


class SerderKERI(Serder):
    """SerderKERI is Serder subclass with Labels for KERI packet types (ilks) and
       properties for exposing field values of KERI messages

       See docs for Serder
    """
    #override in subclass to enforce specific protocol
    Protocol = Protocols.keri  # required protocol, None means any in Protocols is ok
    Proto = Protocols.keri  # default protocol type


    def _verify(self, **kwa):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Raises a ValidationError (or subclass) if any verification fails

        """
        super(SerderKERI, self)._verify(**kwa)

        allkeys = list(self.Fields[self.proto][self.pvrsn][self.ilk].alls)
        keys = list(self.sad)
        if allkeys != keys:
            raise ValidationError(f"Invalid top level field list. Expected "
                                  f"{allkeys} got {keys}.")

        if (self.pvrsn.major < 2 and self.pvrsn.minor < 1 and
            self.ilk in (Ilks.qry, Ilks.rpy, Ilks.pro, Ilks.bar, Ilks.exn)):
                pass  # non prefixive ilks do not have 'i' field
        else:  # verify pre 'i' field
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


            if self.ilk in (Ilks.icp, Ilks.dip, Ilks.rot, Ilks.drt):  # est event
                if self.ilk in (Ilks.icp, Ilks.dip):  # inceptive event
                    if code in PreNonDigDex:
                        if len(self.keys) != 1:
                            raise ValidationError(f"Invalid keys = {self.keys} "
                                                  "for non-digestive prefix "
                                                  f"{code=}.")

                        if self.tholder.sith != '1':
                            raise ValidationError(f"Invalid signing threshold ="
                                                  f" {self.tholder.sith} for "
                                                  f"non-digestive prefix {code=}.")

                        if self.pre != self.keys[0]:
                            raise ValidationError(f"Mismatch prefix = {self.pre} and"
                                                  f" zeroth key = {self.keys[0]} for "
                                                  f" non-digestive prefix {code=}.")

                # non-transferable pre validations
                if code in NonTransDex:
                    if self.ndigs:  # when field missing returns None
                        raise ValidationError(f"Non-transferable code = {code} with"
                                              f" non-empty nxt = {self.ndigs}.")

                    if self.backs:  # when field missing returns None
                        raise ValidationError("Non-transferable code = {code} with"
                                              f" non-empty backers = {self.backs}.")

                    if self.seals:  # when field missing returns None
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
        if self.pvrsn.major < 2 and self.pvrsn.minor < 1 and self.ilk == Ilks.vcp:
            return None

        return self._sad.get("n")

    @property
    def ndigers(self):
        """NDigers property getter

        Returns:
            ndigers (list[Diger]): instance as converted from ._sad['n'].
            One for each next key digests.
        """
        if self.pvrsn.major < 2 and self.pvrsn.minor < 1 and self.ilk == Ilks.vcp:
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
        if self.pvrsn.major < 2 and self.pvrsn.minor < 1 and self.ilk == Ilks.vcp:
            return self._sad.get("n")
        else:
            return self.uuid



class SerderACDC(Serder):
    """SerderACDC is Serder subclass with Labels for ACDC packet types (ilks) and
       properties for exposing field values of ACDC messages

       See docs for Serder

    ToDo:
        Schemer property getter. Schemer object should change name to Schemar
    """
    #override in subclass to enforce specific protocol
    Protocol = Protocols.acdc  # required protocol, None means any in Protocols is ok
    Proto = Protocols.acdc  # default protocol type



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
    def regid(self):
        """regi property getter (registry SAID)
        Optional fields return None when not present
        Returns:
           regi (str | None): qb64  registry SAID
                              v1 .sad["ri"]
                              v2 .said["rd"]
        """
        if self.pvrsn.major == 1:
            return self._sad.get('ri')
        else:
            return self._sad.get('rd')


    @property
    def regib(self):
        """regib property getter (registry identifier SAID bytes)
        Optional fields return None when not present
        Returns:
        regib (bytes | None): qb64b  of .issuer AID as bytes
        """
        return self.regid.encode() if self.regid is not None else None


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
            return self.attrib.get('i')
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



    def _verify(self, **kwa):
        """Verifies said(s) in sad against raw
        Override for protocol and ilk specific verification behavior. Especially
        for inceptive ilks that have more than one said field like a said derived
        identifier prefix.

        Raises a ValidationError (or subclass) if any verification fails

        """
        #super(SerderACDC, self)._verify(**kwa)
        sad, saids = self._validate()

        sad, raw, size = self._compute(sad=sad, saids=saids)

        if raw != self.raw:
            raise ValidationError(f"Invalid round trip of {sad} != \n"
                                  f"{self.sad}.")

        # extract version string elements to verify consistency with attributes
        proto, pvrsn, kind, size, gvrsn = deversify(sad["v"])
        if self.proto != proto:
            raise ValidationError(f"Inconsistent protocol={self.proto} from"
                                  f" deversify of sad.")

        if self.pvrsn != pvrsn:
            raise ValidationError(f"Inconsistent version={self.pvrsn} from"
                                  f" deversify of sad.")

        if self.kind != kind:
            raise ValidationError(f"Inconsistent kind={self.kind} ifrom"
                                  f" deversify of sad.")

        if self.kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
            if size != self.size != len(raw):
                raise ValidationError(f"Inconsistent size={self.size} from"
                                  f" deversify of sad.")
        else:  # size is not set in version string when kind is CESR
            if self.size != len(raw):
                raise ValidationError(f"Inconsistent size={self.size} from"
                                  f" deversify of sad.")

        if self.gvrsn != gvrsn:
            raise ValidationError(f"Inconsistent genus version={self.gvrsn} from"
                                  f" deversify of sad.")
        # verified successfully since no exception

        if (not self.ilk or self.ilk in
                (Ilks.acm, Ilks.ace, Ilks.act, Ilks.acg, Ilks.rip)):
            # required issuer field as valid AID, not empty
            try:
                code = Matter(qb64=self.issuer).code
            except Exception as ex:
                raise ValidationError(f"Invalid issuer AID = "
                                      f"{self.issuer}.") from ex

            if code not in PreDex:
                raise ValidationError(f"Invalid issuer AID code = {code}.")



    def makify(self, sad, *, proto=None, pvrsn=None, genus=None, gvrsn=None,
                   kind=None, ilk=None, saids=None):
        """makify builds serder with valid properties and attributes. Computes
        saids and sizes. and assigns hidden attributes for properties:
        sad, raw, size, proto, pvrsn, genus, gvrsn, kind

        Prioritization of assigned and default values.
           Use method parameter if not None
           Else use version string from provided sad if valid
           Otherwise use class attribute

        Parameters:
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            proto (str | None): desired protocol type str value of Protocols
                If None then its extracted from sad or uses default .Proto
            pvrsn (Versionage | None): instance desired protocol version
                If None then its extracted from sad or uses default .Vrsn
            genus (str): desired CESR genus code
                If None then its uses one compatible with proto
            gvrsn (Versionage): instance desired CESR genus code table version
                If None then stays None
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
        # sets ._proto, ._pvrsn, ._genus, ._gvrsn, ._kind
        sad, saids = self._makify(sad, proto=proto, pvrsn=pvrsn, genus=genus,
                                gvrsn=gvrsn, kind=kind, ilk=ilk, saids=saids)

        sad, raw, size = self._compute(sad=sad, saids=saids)

        self._raw = raw
        self._size = size
        self._sad = sad


    def _compute(self, sad, saids):
        """Computes computed fields. These include size and said fields that have
        dummy characters. Replaces dummied fields with computed values.
        In the case of version strings replaces dummy size characters with
        actual size. In the case of SAID fields replaces dummy said characters
        with actual computed saids

        Returns:
            stuff (tuple): of form (sad, raw, size) where:
                sad is de-dummied sad, raw is raw serialization of dedummied sad,
                and size is size of raw or None when sized is True and hence the
                size is not calculated.

        Parameters:
            sad (dict): dummied serder sad (self addressed data dict)
            saids (dict): said field labels and cesr code that identifies how


        """
        # assumes sad['v'] vesion string vield and top-level sad said fields
        # not including section fields are fully dummied at this point
        if self.kind != Kinds.cesr:  # non-native so sizify version string
            raw = self.dumps(sad, self.kind)  # get size of sad with fully dummied vs and saids
            size = len(raw)

            # generate version string with correct size
            vs = versify(proto=self.proto, pvrsn=self.pvrsn, kind=self.kind,
                                 size=size, gvrsn=self.gvrsn)
            sad["v"] = vs  # update version string in sad
            # now have correctly sized version string in sad for non-native
        # else: vs ignored for native cesr for now

        if (self.pvrsn.major >= 2 and self.ilk in
                (Ilks.acm, Ilks.act, Ilks.acg, Ilks.ace, None)):  # compactable
            # compactable so fixup saids and size
            csad = copy.deepcopy(sad)  # make copy to compute most compact sad

            for l in ("s", "a", "e", "r", "A"):
                if v := csad.get(l, None):  # field exists and is not empty
                    sector = None
                    if isinstance(v, Mapping):  # v is non-empty mapping
                        # compact to its most compact said
                        match l:
                            case 's':  # schema is only top-level said
                                sector = Compactor(mad=v,
                                                    makify=True,
                                                    strict=False,
                                                    saids={"$id": 'E',},
                                                    kind=self.kind)


                            case 'a' | 'e' | 'r':
                                sector = Compactor(mad=v,
                                                   makify=True,
                                                  kind=self.kind)
                                sector.compact()

                    elif isinstance(v, Iterable):  # v is non-empty iterable
                        match l:
                            case 'A':  # aggregator
                                pass  # ToDo create Aggregator instance from list

                    if sector is not None:
                        said = sector.said
                        if said:
                            csad[l] = said


            # Most compact size fixup in vs
            if self.kind != Kinds.cesr:  # not native so fixup vs
                # use size from most compact raw so stable said as most compact
                raw = self.dumps(csad, kind=self.kind)
                csize = len(raw)
                vs = versify(proto=self.proto, pvrsn=self.pvrsn, kind=self.kind,
                                     size=csize, gvrsn=self.gvrsn)
                csad["v"] = vs  # update version string in sad

            # reserialize using sized, dummied, and fixed up
            raw = self.dumps(csad, kind=self.kind)

        elif (self.pvrsn.major >= 2 and self.ilk in
                (Ilks.sch, Ilks.att, Ilks.agg, Ilks.edg, Ilks.rul)):  # partial sections
            # verify embedded section saids are most compact
            csad = copy.deepcopy(sad)  # make copy to compute most compact sad

            for l in ("s", "a", "e", "r", "A"):
                if v := csad.get(l, None):  # field exists and is not empty
                    sector = None
                    if isinstance(v, Mapping):  # v is non-empty mapping
                        # verify embedded most compact saids
                        match l:
                            case 's':  # schema is only top-level said $id
                                sector = Compactor(mad=v,
                                                      makify=True,
                                                      strict=False,
                                                      saids={"$id": 'E',},
                                                      kind=self.kind)
                                slabel ='$id'


                            case 'a' | 'e' | 'r':
                                sector = Compactor(mad=v,
                                                      makify=True,
                                                      kind=self.kind)
                                sector.compact()
                                slabel ='d'

                        said = sector.said
                        if v.get(slabel) != said:
                            raise InvalidValueError(f"Invalid section {said=} "
                                                    f"in section message")
                    elif isinstance(v, Iterable):  # v is non-empty iterable
                        match l:
                            case 'A':  # aggregator
                                pass  # ToDo create Aggregator instance from list

                        # verify exposed elements in v versus Aggregator

        else:  # non-compactable, no need to fixup
            # compute saidive digestive field values using raw from sized dummied sad
            raw = self.dumps(sad, kind=self.kind)  # serialize sized dummied sad

        # replace dummied said fields at top level of sad with computed digests
        for label, code in saids.items():
            if code in DigDex:  # subclass override if non digestive allowed
                sad[label] = Diger(ser=raw, code=code).qb64

        # Now reserialize raw with undummied said and unfixed up uncompact sections
        raw = self.dumps(sad, kind=self.kind)  # assign final raw

        if self.kind == Kinds.cesr:# cesr native serialization does not use vs
            # but want vs to have real size so fixup here
            size = len(raw) # size of whole message
            sad['v'] = versify(proto=self.proto, pvrsn=self.pvrsn,
                               kind=self.kind, size=size, gvrsn=self.gvrsn)

        return (sad, raw, size)
