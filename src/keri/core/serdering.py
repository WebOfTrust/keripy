# -*- coding: utf-8 -*-
"""
keri.core.serdering module

"""
import copy
import json
from collections import namedtuple
from collections.abc import Mapping
from dataclasses import dataclass, asdict, field

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
                      VERRAWSIZE, VERFMT,
                      MAXVERFULLSPAN, VER1FULLSPAN,  VER2FULLSPAN)
from ..kering import SMELLSIZE, Smellage, smell

from ..kering import Protocols, Kinds, versify, deversify, Ilks

from .. import help
from ..help import helping


from . import coring
from .coring import (MtrDex, DigDex, PreDex, NonTransDex, PreNonDigDex,
                     Saids,  Digestage)
from .coring import (Matter, Saider, Verfer, Diger, Number, Tholder, Tagger,
                     Ilker, Traitor, Verser, )

from .counting import GenDex, Counter, Codens, SealDex_2_0

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

    """
    alls: dict  # all allowed fields when strict
    opts: dict = field(default_factory=dict)  # optional fields
    alts:  dict = field(default_factory=dict)  # alternate optional fields
    saids: dict = field(default_factory=dict)  # saidive fields
    strict: bool = True  # only alls allowed no extras

    def __iter__(self):
        return iter(asdict(self))

"""Design Notes:

Problems is that sniff only determines if counter not which type of
counter. Then smell does regex lookahead to find out which serialization
when not count code but extractor does not look ahead but strips from
stream. So when possibility that CESR message is next either need to
not strip from stream when extracting or if counter is message
then grab rest of frame and reattach so raw in Serder includes the
message counter. Latter is better since always keep counter around
until later. So need to check counter type and if message then
extract rest of counter frame (message) and reattach counter raw.
Then can call Serder with raw and smellage that indicates CESR kind

But this does not solve the problem of using the Serder subclass
for the given protocol. Merely knowing is a CESR message is not
enough also have to know the protocol which comes in the version
field (not version string).

One solution is to modify smell so that it also can lookahead and
see the version field. Or lookahead and see the version field with
count codes in front. Problem is that the Regexes don't separate
cleanly.

Another solution is to use distinct function for cesr native called
snuff like smell but regex only for CESR native. Reap can be told which
because sniff tells which it is.
So question for snuff is should it be searching over the counter or should it
start at version field. This changes regex so forced start at front of raw.
so if reattach counter but use skip then can snuff at start of string.
Begine regex with b'^' or b'\A' to match at start of string.

So change Smellage to return extra field that has gvrsn when used by snuff
so can use Smellage for both smell and snuff in both reap and inhale
where smellage is used. Change egacy uses of smell to ignore extra value.



Lets try that as it works the best.

while True:  # extract, deserialize, and strip message from ims
    try:
        serder = serdery.reap(ims=ims)  # can set version here
    except kering.ShortageError as ex:  # need more bytes
        yield
    else: # extracted and stripped successfully
        break  # break out of while loop

ctr = yield from self._extractor(ims=ims, klas=Counter, cold=cold)
if ctr.code == CtrDex.AttachmentGroup:  # pipeline ctr?
    pipelined = True

@staticmethod
def _extractor(ims, klas, cold=Colds.txt, abort=False):
    while True:
        try:
            if cold == Colds.txt:
                return klas(qb64b=ims, strip=True)
            elif cold == Colds.bny:
                return klas(qb2=ims, strip=True)
            else:
                raise kering.ColdStartError("Invalid stream state cold={}.".format(cold))
        except kering.ShortageError as ex:
            if abort:  # pipelined pre-collects full frame before extracting
                raise  # bad pipelined frame so abort by raising error
            yield



"""


class Serdery:
    """Serder factory class for generating serder instances by protocol type
    from an incoming message stream.
    """

    def __init__(self, *pa, **kwa):
        """Init instance

        Parameters:

        """
        pass


    def reap(self, ims, genus=GenDex.KERI, gvrsn=Vrsn_2_0, native=False, skip=0):
        """Extract and return Serder subclass based on protocol type reaped from
        version string inside serialized raw of Serder.

        Returns:
            serder (Serder): instance of Serder subclass where subclass is
                determined by the protocol type of its version string.

        Parameters:
            ims (bytearray) of serialized incoming message stream. Assumes start
                of stream is raw Serder.
            genus (str): CESR genus code from stream parser.
                    Provides genus of enclosing stream top-level or nested group
            gvrsn (Versionage): instance CESR genus code table version (Major, Minor)
                    Provides genus of enclosing stream top-level or nested group
            native (bool): True means sniff determined may be CESR native message
                           so snuff instead of smell.
                           False means sniff determined not CESR native i.e
                           JSON, CBOR, MGPK field map. so use smell. Default False
             skip (int): bytes to skip at front of ims. Useful when CESR native
                serialization where skip is size of the message counter so smell
                does need to see counter

        """
        if native:
            pass
            #smellage = smell(memoryview(ims)[skip:])  # does not copy to skip

        else:
            smellage = smell(ims)

        if smellage.proto == Protocols.keri:
            return SerderKERI(raw=ims, strip=True, smellage=smellage,
                              genus=genus, gvrsn=gvrsn)
        elif smellage.proto == Protocols.acdc:
            return SerderACDC(raw=ims, strip=True, smellage=smellage,
                              genus=genus, gvrsn=gvrsn)
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
        genus (str): CESR genus code
        gvrsn (Versionage): instance CESR genus code table version (Major, Minor)
        proto (str): Protocolage value as protocol identifier such as KERI, ACDC
                     alias of .protocol
        protocol (str): Protocolage value as protocol identifier such as KERI, ACDC
                        alias of .proto
        vrsn (Versionage): protocol version (Major, Minor) alias of .version
        version (Versionage): protocol version (Major, Minor) alias of .vrsn
        kind (str): serialization kind coring.Serials such as JSON, CBOR, MGPK, CESR
        size (int): number of bytes in serialization
        said (str): qb64 said of .raw given by appropriate field
        saidb (bytes): qb64b of .said
        ilk (str | None): packet type for this Serder if any (may be None)


    Hidden Attributes:
        ._raw (bytes): serialized message
        ._sad (dict): sad dict (key event dict)
        ._cvrsn (Versionage): CESR code table version
        ._proto (str):  Protocolage value as protocol type identifier
        ._vrsn is Versionage instance of event version
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
    ClanCodes = dict()
    ClanCodes[SClanDom.SealDigest.__name__] = SealDex_2_0.DigestSealSingles
    ClanCodes[SClanDom.SealRoot.__name__] = SealDex_2_0.MerkleRootSealSingles
    ClanCodes[SClanDom.SealBacker.__name__] = SealDex_2_0.BackerRegistrarSealCouples
    ClanCodes[SClanDom.SealLast.__name__] = SealDex_2_0.SealSourceLastSingles
    ClanCodes[SClanDom.SealTrans.__name__] = SealDex_2_0.SealSourceCouples
    ClanCodes[SClanDom.SealEvent.__name__] = SealDex_2_0.SealSourceTriples

    # map seal counter code to seal clan name for parsing seal groups in anchor list
    CodeClans = { val: key for key, val in ClanCodes.items()}  # invert dict

    #override in subclass to enforce specific protocol
    Protocol = None  # class based message protocol, None means any in Protocols is ok
    Proto = Protocols.keri  # default message protocol type for makify on base Serder
    Vrsn = Vrsn_1_0  # default protocol version for protocol type
    Kind = Kinds.json  # default serialization kind
    CVrsn = Vrsn_2_0  # default CESR code table version


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
                Ilks.xip: FieldDom(alls=dict(v='', t='', d='', i="", dt='',
                                             r='', q={}, a={}),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.exn: FieldDom(alls=dict(v='', t='', d='', i="", x="",
                        p="", dt='', r='', q={}, a={}),
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
                    saids={Saids.d: DigDex.Blake3_256}),
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
                Ilks.acd: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        rd='', s='', a='', A='', e='', r=''),
                    opts=dict(u='', rd='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.ace: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                        rd='', s='', a='', A='', e='', r=''),
                    opts=dict(u='', rd='', a='', A='', e='', r=''),
                    alts=dict(a="A", A="a"),
                    saids={Saids.d: DigDex.Blake3_256},
                    strict=False),
                Ilks.sch: FieldDom(alls=dict(v='', t='', d='', s=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.att: FieldDom(alls=dict(v='', t='', d='', a=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.agg: FieldDom(alls=dict(v='', t='', d='', A=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rul: FieldDom(alls=dict(v='', t='', d='', e=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.rip: FieldDom(alls=dict(v='', t='', d='', u='', i='',
                                              s='', dt=''),
                    saids={Saids.d: DigDex.Blake3_256}),
                Ilks.upd: FieldDom(alls=dict(v='', t='', d='', r='', s='',
                                              p='', dt='', a=''),
                    saids={Saids.d: DigDex.Blake3_256}),
            },
        },
    }


    def __init__(self, *, raw=b'', sad=None, strip=False, smellage=None,
                 genus=GenDex.KERI, gvrsn=Vrsn_2_0, verify=True, makify=False,
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
            raw (bytes | bytearray): serialized event
            sad (dict): serializable saidified field map of message.
                Ignored if raw provided
            strip (bool): True means strip (delete) raw from input stream
                bytearray after parsing. False means do not strip.
                Assumes that raw is bytearray when strip is True.
            smellage (Smellage | None): instance of deconstructed and converted
                version string elements. If none or empty ignore otherwise assume
                that raw already had its version string extracted (reaped) into the
                elements of smellage.
            genus (str):  CESR genus str. Either provided by parser from stream
                or generated by Serder to stream
            gvrsn (Versionage): instance CESR genus code table version
                Either provided by parser from stream genus version or desired when
                generating Serder instance to stream
            verify (bool): True means verify said(s) of given raw or sad.
                           False means don't verify. Useful to avoid unnecessary
                           reverification when deserializing from database
                           as opposed to over the wire reception.
                           Raises ValidationError if verification fails
                           Ignore when raw empty or when raw and saidify is True
            makify (bool): True means compute fields for sad including size and
                saids.
            proto (str | None): desired protocol type str value of Protocols
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
        self._gvrsn = gvrsn
        self._genus = genus

        if raw:  # deserialize raw using property setter
            self._inhale(raw=raw, smellage=smellage)
            # ._inhale updates ._raw, ._sad, ._proto, ._vrsn, ._kind, ._size

            # primary said field label
            try:
                label = list(self.Fields[self.proto][self.vrsn][self.ilk].saids)[0]
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
                # makify resets sad, raw, proto, vrsn, kind, ilk, and size
                self.makify(sad=sad, proto=proto, vrsn=vrsn, kind=kind,
                            ilk=ilk, saids=saids)
                # .makify updates ._raw, ._sad, ._proto, ._vrsn, ._kind, ._size

            else:
                self._exhale(sad=sad)
                # .exhale updates ._raw, ._sad, ._proto, ._vrsn, ._kind, ._size

            # primary said field label
            try:
                label = list(self.Fields[self.proto][self.vrsn][self.ilk].saids)[0]
                if label not in self._sad:
                    raise DeserializeError(f"Missing primary said field in {self._sad}.")
                self._said = self._sad[label]  # not verified
            except Exception:
                self._said = None  # no saidive field

            if verify:  # verify fields including the said(s) provided in sad
                try:
                    self._verify()  # raises exception when not verify
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
        if self.Protocol and self.proto != self.Protocol:  # class required
            raise ValidationError(f"Required protocol = {self.Protocol}, got "
                                 f"{self.proto} instead.")

        if self.proto not in self.Fields:
            raise ValidationError(f"Invalid protocol type = {self.proto}.")

        if self.genus not in GenDex:  # ensures self.genus != None
            raise SerializeError(f"Invalid genus={self.genus}.")

        if getattr(GenDex, self.proto, None) != self.genus:
            raise SerializeError(f"Incompatible protocol={self.proto} with "
                                 f"genus={self.genus}.")

        if self.vrsn.major > self.gvrsn.major:
            raise SerializeError(f"Incompatible major protocol version={self.vrsn}"
                                 f" with major genus version={self.gvrsn}.")

        if self.vrsn not in self.Fields[self.proto]:
            raise SerializeError(f"Invalid version={self.vrsn} for "
                                 f"protocol={self.proto}.")

        if self.ilk not in self.Fields[self.proto][self.vrsn]:
            raise ValidationError(f"Invalid packet type (ilk) = {self.ilk} for"
                                  f"protocol = {self.proto}.")



        fields = self.Fields[self.proto][self.vrsn][self.ilk]  # get labelage

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

        sad = self.sad  # make shallow copy so don't clobber original .sad
        for label in saids:
            try:  # replace default code with code of value from sad
                saids[label] = Matter(qb64=sad[label]).code
            except Exception as ex:
                if saids[label] in DigDex:  # digestive but invalid
                    raise ValidationError(f"Invalid said field '{label}' in sad\n"
                                      f" = {self._sad}.") from ex

            if saids[label] in DigDex:  # if digestive then replace with dummy
                sad[label] = self.Dummy * len(sad[label])

        # compute saidive digestive field values using raw from sized dummied sad
        raw = self.dumps(sad, kind=self.kind)  # serialize dummied sad copy
        for label, code in saids.items():
            if code in DigDex:  # subclass override if non digestive allowed
                dig = Diger(ser=raw, code=code).qb64
                if dig != self._sad[label]:  # compare to original
                    raise ValidationError(f"Invalid said field '{label}' in sad"
                                          f" = {self._sad}, should be {dig}.")
                sad[label] = dig

        raw = self.dumps(sad, kind=self.kind)  # compute final raw

        if raw != self.raw:
            raise ValidationError(f"Invalid round trip of {sad} != \n"
                                  f"{self.sad}.")

        if "v" not in sad:
            raise ValidationError(f"Missing version string field in {sad}.")

        # extract version string elements to verify consistency with attributes
        proto, vrsn, kind, size, opt = deversify(sad["v"])
        if self.proto != proto:
            raise ValidationError(f"Inconsistent protocol={self.proto} in {sad}.")

        if self.vrsn != vrsn:
            raise ValidationError(f"Inconsistent version={self.vrsn} in {sad}.")

        if self.kind != kind:
            raise ValidationError(f"Inconsistent kind={self.kind} in {sad}.")

        if self.kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
            if size != self.size != len(raw):
                raise ValidationError(f"Inconsistent size={self.size} in {sad}.")
        else:  # size is not set in version string when kind is CESR
            if self.size != len(raw):
                raise ValidationError(f"Inconsistent size={self.size} in {sad}.")

        # verified successfully since no exception


    def makify(self, sad, *, proto=None, vrsn=None, kind=None,
               ilk=None, saids=None):
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
            proto (str | None): desired protocol type str value of Protocols
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
                sproto, svrsn, skind, _, _ = deversify(sad["v"])
            except VersionError as ex:
                pass
            else:
                silk = sad.get('t')  # if 't' not in sad .get returns None which may be valid

        if proto is None:
            proto = sproto if sproto is not None else self.Proto

        if proto not in self.Fields:
            raise SerializeError(f"Invalid protocol={proto}.")

        if self.Protocol and proto != self.Protocol:  # required by class
            raise SerializeError(f"Required protocol={self.Protocol}, got "
                                 f"protocol={proto} instead.")

        if self.genus not in GenDex:  # ensures self.genus != None
            raise SerializeError(f"Invalid genus={self.genus}.")

        if getattr(GenDex, proto, None) != self.genus:
            raise SerializeError(f"Incompatible protocol={proto} with "
                                 f"genus={self.genus}.")

        if vrsn is None:
            vrsn = svrsn if svrsn is not None else self.Vrsn

        if vrsn not in self.Fields[proto]:
            raise SerializeError(f"Invalid version={vrsn} for protocol={proto}.")

        if vrsn.major > self.gvrsn.major:
            raise SerializeError(f"Incompatible major protocol version={vrsn} "
                                 f"with major genus version={self.gvrsn}.")

        if kind is None:
            kind = skind if skind is not None else self.Kind

        if ilk is None:  # default is first ilk in Fields for given proto vrsn
            ilk = (silk if silk is not None else
                   list(self.Fields[proto][vrsn])[0])  # list(dict) gives list of keys

        if kind not in Kinds:
            raise SerializeError(f"Invalid serialization kind = {kind}")

        if ilk not in self.Fields[proto][vrsn]:
            raise SerializeError(f"Invalid packet type (ilk) = {ilk} for"
                                  f"protocol = {proto}.")

        fields = self.Fields[proto][vrsn][ilk]  # get FieldDom of fields

        alls = fields.alls  # faster local reference
        oalls = oset(alls)  # ordereset of field labels
        oopts = oset(fields.opts)  # ordereset of field labels
        oreqs = oalls - oopts  # required fields


        if not sad:  # empty or None so create sad dict
            sad = {}

        # ensure all required fields are in sad. If not provide default
        for label in oreqs:
            if label not in sad:
                value = alls[label]
                if helping.nonStringIterable(value):
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

        # said field labels are not order dependent with respect to all fields
        # in sad so use set() to test inclusion
        _saids = copy.copy(fields.saids)  # get copy of defaults
        if not (set(_saids) <= set(alls)):
            raise SerializeError(f"Missing one or more required said fields "
                                 f"from {list(_saids)} in sad = {sad}.")

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

        if kind in (Kinds.json, Kinds.cbor, Kinds.mgpk):
            # this size of sad needs to be computed based on actual version string span
            # since not same for all versions
            sad['v'] = self.Dummy * self.Spans[vrsn]  # ensure span of vs is dummied MAXVERFULLSPAN

            raw = self.dumps(sad, kind)  # get size of sad with fully dummied vs and saids
            size = len(raw)

            # generate new version string with correct size
            vs = versify(protocol=proto, version=vrsn, kind=kind, size=size)
            sad["v"] = vs  # update version string in sad
            # now have correctly sized version string in sad


        # compute saidive digestive field values using raw from sized dummied sad
        raw = self.dumps(sad, kind=kind, proto=proto, vrsn=vrsn)  # serialize sized dummied sad
        for label, code in _saids.items():
            if code in DigDex:  # subclass override if non digestive allowed
                sad[label] = Diger(ser=raw, code=code).qb64

        raw = self.dumps(sad, kind=kind, proto=proto, vrsn=vrsn)  # compute final raw
        if kind == Kinds.cesr:# cesr kind version string does not set size
            size = len(raw) # size of whole message

        self._raw = raw
        self._sad = sad
        self._proto = proto
        self._vrsn = vrsn
        self._kind = kind
        self._size = size


    def _inhale(self, raw, *, smellage=None):
        """Deserializes raw.
        Parses serilized event ser of serialization kind and assigns to
        instance attributes and returns tuple of associated elements.

        As classmethod enables testing parsing raw serder values. This can be
        called on self as well because it only ever accesses clas attributes
        not instance attributes.

        Returns: tuple (sad, proto, vrsn, kind, size) where:
            sad (dict): serializable attribute dict of saidified data
            proto (str): value of Protocols (Protocolage) protocol type
            vrsn (Versionage | None): tuple of (major, minor) version ints
                None means do not enforce version
            kind (str): value of Serials (Serialage) serialization kind

        Parameters:
            clas (Serder): class reference
            raw (bytes): serialized sad message
            smellage (Smellage | None): instance of deconstructed version string
                elements. If none or empty ignore otherwise assume that raw
                already had its version string extracted (reaped) into the
                elements of smellage.



        """
        if smellage:  # passed in so don't need to smell raw again
            proto, vrsn, kind, size, gvrsn = smellage  # tuple unpack
        else:  # not passed in so smell raw
            proto, vrsn, kind, size, gvrsn = smell(raw)

        sad = self.loads(raw=raw, size=size, kind=kind)
        # ._gvrsn may be set in loads when CESR native deserialization provides _gvrsn

        if "v" not in sad:  # Regex does not check for version string label itself
            raise FieldError(f"Missing version string field in {sad}.")

        # cypto opts want bytes not bytearray
        self._raw = bytes(raw[:size])  # make copy so strip not affect
        self._sad = sad
        self._proto = proto
        self._vrsn = vrsn
        self._kind = kind
        self._size = size



    def loads(self, raw, size=None, kind=Kinds.json):
        """method to handle deserialization by kind
        assumes already sniffed and smelled to determine
        serialization size and kind

        Returns:
           sad (dict | list): deserialized dict or list. Assumes attribute
                dict of saidified data.

        Parameters:
           raw (bytes | bytearray): raw serialization to deserialze as dict
           size (int): number of bytes to consume for the deserialization.
                       If None then consume all bytes in raw
           kind (str): value of Serials (Serialage) serialization kind
                       "JSON", "MGPK", "CBOR"

        Notes:
            loads of json uses str whereas loads of cbor and msgpack use bytes
        """
        if kind == Kinds.json:
            try:
                sad = json.loads(raw[:size].decode("utf-8"))
            except Exception as ex:
                raise DeserializeError(f"Error deserializing JSON: "
                    f"{raw[:size].decode('utf-8')}") from ex

        elif kind == Kinds.mgpk:
            try:
                sad = msgpack.loads(raw[:size])
            except Exception as ex:
                raise DeserializeError(f"Error deserializing MGPK: "
                    f"{raw[:size].decode('utf-8')}") from ex

        elif kind == Kinds.cbor:
            try:
                sad = cbor.loads(raw[:size])
            except Exception as ex:
                raise DeserializeError(f"Error deserializing CBOR: "
                    f"{raw[:size].decode('utf-8')}") from ex

        else:
            raise DeserializeError(f"Invalid deserialization kind: {kind}")

        return sad


    def _loads(self, raw, size=None):
        """CESR native desserialization of raw

        Returns:
           sad (dict): deserialized dict of CESR native serialization.

        Parameters:
           clas (Serder): class reference
           raw (bytes |bytearray): raw serialization to deserialze as dict
           size (int): number of bytes to consume for the deserialization.
                       If None then consume all bytes in raw
        """
        # ._gvrsn may be set in loads when CESR native deserialization provides _gvrsn
        pass


    def _exhale(self, sad):
        """Serializes sad and assigns attributes.
        Asssumes all field values in sad are valid.
        Call .verify to otherwise

        Parameters:
            sad (dict): serializable attribute dict of saidified data
        """
        if "v" not in sad:
            raise SerializeError(f"Missing version string field in {sad}.")

        # extract elements so can replace size element but keep others
        proto, vrsn, kind, size, opt = deversify(sad["v"])

        raw = self.dumps(sad, kind)

        if kind in (Kinds.cesr):  # cesr kind version string does not set size
            size = len(raw) # size of whole message

        # must call .verify to ensure these are compatible
        self._raw = raw  # crypto opts want bytes not bytearray
        self._sad = sad
        self._proto = proto
        self._vrsn = vrsn
        self._kind = kind
        self._size = size


    def dumps(self, sad=None, kind=Kinds.json, proto=None, vrsn=None):
        """Method to handle serialization by kind
        Assumes sad fields are properly filled out for serialization kind.

        Returns:
            raw (bytes): serialization of sad dict using serialization kind

        Parameters:
            sad (dict | list | None)): serializable dict or list to serialize
            kind (str): value of Serials (Serialage) serialization kind
                "JSON", "MGPK", "CBOR", "CSER"
            proto (str | None): desired protocol type str value of Protocols
                If None then eventually use self.proto
            vrsn (Versionage | None): instance desired protocol version
                If None then eventually self.vrsn


        Notes:
            dumps of json uses str whereas dumps of cbor and msgpack use bytes
            crypto opts want bytes not bytearray
        """
        sad = sad if sad is not None else self.sad

        if kind == Kinds.json:
            raw = json.dumps(sad, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")

        elif kind == Kinds.mgpk:
            raw = msgpack.dumps(sad)

        elif kind == Kinds.cbor:
            raw = cbor.dumps(sad)

        elif kind == Kinds.cesr:  # does not support list only dict
            raw = self._dumps(sad, proto=proto, vrsn=vrsn)

        else:
            raise SerializeError(f"Invalid serialization kind = {kind}")

        return raw


    def _dumps(self, sad=None, proto=None, vrsn=None):
        """CESR native serialization of sad

        Returns:
            raw (bytes): CESR native serialization of sad dict

        Parameters:
            sad (dict | None)): serializable dict to serialize
            proto (str | None): desired protocol type str value of Protocols
                If None then self.proto
            vrsn (Versionage | None): instance desired protocol version
                If None then self.vrsn

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
        proto = proto if proto is not None else self.proto
        vrsn = vrsn if vrsn is not None else self.vrsn

        if (self.gvrsn.major < Vrsn_2_0.major or vrsn.major < Vrsn_2_0.major):
            raise SerializeError(f"Invalid major genus version={self.gvrsn}"
                                f"or Invalid major protocol version={vrsn}"
                                f" for native CESR serialization.")

        if self.genus not in GenDex:  # ensures self.genus != None
            raise SerializeError(f"Invalid genus={self.genus}.")

        if getattr(GenDex, proto, None) != self.genus:
            raise SerializeError(f"Incompatible protocol={proto} with "
                                 f"genus={self.genus}.")




        raw = bytearray()  # message as qb64
        bdy = bytearray()  # message body as qb64
        ilks = self.Fields[proto][vrsn]  # get fields keyed by ilk

        ilk = sad.get('t')  # returns None if missing message type (ilk)
        if ilk not in ilks:  #
            raise SerializeError(f"Missing message type field "
                                 f"'t' for protocol={proto} "
                                 f"version={vrsn} with {sad=}.")

        fields = ilks[ilk]  # FieldDom for given protocol and ilk

        if fields.opts or not fields.strict:  # optional or extra fields allowed
            fixed = False  # so must use field map
        else:
            fixed = True  #fixed field


        # assumes that sad's field ordering and field inclusion is correct
        # so can serialize in order to compute saidive fields
        # need to fix ._verify and .makify to account for CESR native serialization

        if proto == Protocols.keri:
            if not fixed:  # prepend label
                pass  # raise error

            for l, v in sad.items():  # assumes valid field order & presence
                match l:  # label
                    case "v":  # protocol+version  do not use version string itself
                        val = Verser(proto=proto, vrsn=vrsn).qb64b

                    case "t":  # message type (ilk), already got ilk
                        val = Ilker(ilk=v).qb64b  # assumes same

                    case "d" | "i" | "p" | "di":  # said or aid
                        val = v.encode("utf-8")  # already primitive qb64 make qb6b

                    case "s" | "bt":  # sequence number or numeric threshold
                        val = coring.Number(numh=v).qb64b  # convert hex str

                    case "kt" | "nt": # current or next signing threshold
                        val = coring.Tholder(sith=v).limen  # convert sith str

                    case "k" | "n" | "b" | "ba" | "br":  # list of primitives
                        frame = bytearray()
                        for e in v:  # list
                            frame.extend(e.encode("utf-8"))

                        val = bytearray(Counter(Codens.GenericListGroup,
                                                count=len(frame) // 4).qb64b)
                        val.extend(frame)

                    case "c":  # list of config traits strings
                        frame = bytearray()
                        for e in v:  # list
                            frame.extend(Traitor(trait=e).qb64b)

                        val = bytearray(Counter(Codens.GenericListGroup,
                                                count=len(frame) // 4).qb64b)
                        val.extend(frame)

                    case "a":  # list of seals or field map of attributes
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
                                        counter = Counter(code=gcode, count=len(gframe) // 4)
                                        frame.extend(counter.qb64b + gframe)
                                        gframe = bytearray()  # new group
                                    gcode = code  # new group or keep same group
                                    gframe.extend(sealer.qb64b)  # extend in new group

                            except kering.InvalidValueError:
                                if gframe:
                                    counter = Counter(code=gcode, count=len(gframe) // 4)
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
                            counter = Counter(code=gcode, count=len(gframe) // 4)
                            frame.extend(counter.qb64b + gframe)
                            gframe = bytearray()
                            gcode = None

                        val = bytearray(Counter(Codens.GenericListGroup,
                                                count=len(frame) // 4).qb64b)
                        val.extend(frame)

                    case _:  # if extra fields this is where logic would be
                        raise SerializeError(f"Unsupported protocol field label"
                                             f"='{l}' for protocol={proto}"
                                             f" version={vrsn}.")

                bdy.extend(val)


        elif proto == Protocols.acdc:
            for l, val in sad.items():  # assumes valid field order & presence
                if not fixed:
                    pass  # prepend label



        else:
            raise SerializeError(f"Unsupported protocol={self.proto}.")


        # prepend count code for message
        if fixed:

            raw = bytearray(Counter(Codens.FixedMessageBodyGroup,
                                    count=len(bdy) // 4).qb64b)
            raw.extend(bdy)
        else:
            pass


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
    def vrsn(self):
        """vrsn (version) property getter

        Returns:
            vrsn (Versionage): instance of protocol version for this Serder
        """
        return self._vrsn

    @property
    def version(self):
        """version property getter, alias of .vrsn

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
        if not self.Fields[self.proto][self.vrsn][self.ilk].saids and 'd' in self._sad:
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

        allkeys = list(self.Fields[self.proto][self.vrsn][self.ilk].alls)
        keys = list(self.sad)
        if allkeys != keys:
            raise ValidationError(f"Invalid top level field list. Expected "
                                  f"{allkeys} got {keys}.")

        if (self.vrsn.major < 2 and self.vrsn.minor < 1 and
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



class SerderACDC(Serder):
    """SerderACDC is Serder subclass with Labels for ACDC packet types (ilks) and
       properties for exposing field values of ACDC messages

       See docs for Serder
    """
    #override in subclass to enforce specific protocol
    Protocol = Protocols.acdc  # required protocol, None means any in Protocols is ok
    Proto = Protocols.acdc  # default protocol type



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
