# -*- coding: utf-8 -*-
"""
keri.core.structing module

Creates fixed field data structures
"""


from typing import NamedTuple
from collections import namedtuple
from collections.abc import Mapping
from dataclasses import dataclass, astuple, asdict

from ..kering import (Colds, ValidationError, InvalidValueError,
                      EmptyMaterialError, DeserializeError, SerializeError)

from .. import help
from ..help import isNonStringSequence


from .coring import (IceMapDom, Matter, Diger, DigDex, Prefixer, Number, Verser,
                     Labeler, Noncer, NonceDex, Texter)
from .counting import CtrDex_2_0, Codens, Counter
from .signing import Tiers, Salter

#  for the following Seal namedtuples use the ._asdict() method to convert to dict
#  when using in events
# to convert seal namedtuple to dict use namedtuple._asdict()
# seal == SealEvent(i="abc",s="1",d="efg")
# sealdict =seal._asdict()
# to convet dict to namedtuple use ** unpacking as in seal = SealDigest(**sealdict)
# to check if dict of seal matches fields of associted namedtuple
# if tuple(sealdict) == SealEvent._fields:

# Digest Seal: uniple (d,)
# d = digest qb64 of data  (usually SAID)
# use DigestSealSingles as count code for CESR native
SealDigest = namedtuple("SealDigest", 'd')

# Root Seal: uniple (rd,)
# rd = Merkle tree root digest qb64 digest of anchored (sealed) data in Merkle tree
# use MerkleRootSealSingles as count code for CESR native
SealRoot = namedtuple("SealRoot", 'rd')

# Source Seal: duple (s, d)  for Issuance, Delegation, or Transaction Event
# where the AID pre of the issuer is implied by the context wherein the seal appears.
# s = sn of event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of event (issuance, delegation, or transaction)
# the pre is provided in the 'i' field  qb64 of identifier prefix of KEL
# use SealSourceCouples as count code for CESR native
SealSource = namedtuple("SealSource", 's d')

# Event Seal: triple (i, s, d)
# i = pre is qb64 of identifier prefix of KEL for event,
# s = sn of event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of key event
# use SealSourceTriples as count code for CESR native
SealEvent = namedtuple("SealEvent", 'i s d')

# Last Establishment Event Seal: uniple (i,)
# i = pre is qb64 of identifier prefix of KEL from which to get last est, event
# used to indicate to get the latest keys available from KEL for 'i'
# use SealSourceLastSingles as count code for CESR native
SealLast = namedtuple("SealLast", 'i')

# Backer Seal: couple (bi, d)
# bi = pre qb64 backer nontrans identifier prefix
# d = digest qb64 of backer metadata anchored to event usually SAID of data (Diger)
# use BackerRegistrarSealCouples as count code for CESR native
SealBack = namedtuple("SealBack", 'bi d')

# Kind Digest Seal for typed versioned digests : duple (t, d)
# t = type of digest as (Verser)
# d = SAID digest qb64 of transaction event (Diger)
# use TypedDigestSealCouples count code for CESR Native
SealKind = namedtuple("SealKind", 't d')

# Blinded State quadruple for Blindable State Update Event 'bup' for Transaction
# Event Registry
# d = SAID digest qb64 of blindable state (Noncer)
# u = UUID blind as deterministically derived from update sn and salty nonce (Noncer)
# td = SAID of ACDC top-level 'd' field value (Noncer)
# ts = state as string text (Labeler)
# use BlindedStateQuadruples count code for CESR native
BlindState = namedtuple("BlindState", 'd u td ts')

# Bound Blinded State sextuple for Blindable State Update Event 'bup' for Transaction
# Event Registry. Binds the key state of the issue to the state update. This
# effectively cross anchors the issuees key state to the issuers key state at
# the time of the state update so that downstream issuances by issuee can be
# verified against the delegated entitlements (authorizations) from issuer
# d = SAID digest qb64 of blindable state (Noncer)
# u = UUID blind as deterministically derived from update sn and salty nonce (Noncer)
# td = SAID of ACDC top-level 'd' field value (Noncer)
# ts = state as string text (Labeler)
# bn = bound issuee key event hex sequence number at time of state update
# bd = bound issuee key event SAID at time of state update
# use BoundStateSextuples count code for CESR native
BoundState = namedtuple("BoundState", 'd u td ts bn bd')

# Typed and Blinded Media quadruple for IANA media-type media in attachment
# d = SAID digest qb64 of blindable media  (Noncer)
# u = UUID blind as salty nonce (Noncer)
# mt = IANA media type text string (Labeler)
# mv = media value as Text (Texter)
# use TypedMediaQuadruples count code for CESR native
TypeMedia = namedtuple("TypeMedia", 'd u mt mv')

# Following are not seals only used in database

# State Establishment Event (latest current) : quadruple (s, d, br, ba)
# s = sn of latest est event as lowercase hex string  no leading zeros,
# d = SAID digest qb64  of latest establishment event
# br = backer (witness) remove list (cuts) from latest est event
# ba = backer (witness) add list (adds) from latest est event
StateEstEvent = namedtuple("StateEstEvent", 's d br ba')

# not used should this be depricated?
# State Event (latest current) : triple (s, t, d)
# s = sn of latest event as lowercase hex string  no leading zeros,
# t = message type of latest event (ilk)
# d = SAID digest qb64 of latest event
StateEvent = namedtuple("StateEvent", 's t d')


# Cast conversion: duple (kls, ipn)
# kls = primitive class reference in order to cast as appropriate
#       namedtuple with values as primitive classes
# ipn = primitive __init__ keyword parameter name to use when casting
#        default None. When default then use qb64 or qb64b as appropriate.
Castage = namedtuple('Castage', "kls ipn", defaults=(None, ))


@dataclass(frozen=True)
class EmptyClanDom(IceMapDom):
    """EmptyClanDom is dataclass of namedtuple empty class references (clans) each
    indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: EmptyClanDex[name]
    """

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

EClanDom = EmptyClanDom()  # create instance


@dataclass(frozen=True)
class EmptyCastDom(IceMapDom):
    """EmptyCastCodex is dataclass of namedtuple instances (empty casts) whose
    field values are Castage instances of named primitive class class references
    for those fields.

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: EmptyCastDex[name]
    """

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

ECastDom = EmptyCastDom()  # create instance


@dataclass(frozen=True)
class SealClanDom(IceMapDom):
    """SealClanDom is dataclass of namedtuple seal class references (clans) each
    indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: SealClanDom[name]
    """
    SealDigest: type[NamedTuple] = SealDigest  # SealDigest class reference (d,)
    SealRoot: type[NamedTuple] = SealRoot  # SealRoot class reference (rd,)
    SealSource: type[NamedTuple] = SealSource  # SealSource class reference couple (s,d)
    SealEvent: type[NamedTuple] = SealEvent  # SealEvent class reference triple (i,s,d)
    SealLast: type[NamedTuple] = SealLast  # SealLast class reference single (i,)
    SealBack: type[NamedTuple] = SealBack  # SealBack class reference (bi, d)
    SealKind: type[NamedTuple] = SealKind  # SealKind class reference (t, d)


    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SClanDom = SealClanDom()  # create instance




@dataclass(frozen=True)
class SealCastDom(IceMapDom):
    """SealCastDom is dataclass of namedtuple instances (seal casts) whose
    field values are Castage instances of named primitive class class references for those fields.

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: SealCastDom[name]
    """
    SealDigest: NamedTuple = SealDigest(d=Castage(Diger))  # SealDigest class reference
    SealRoot: NamedTuple = SealRoot(rd=Castage(Diger))  # SealRoot class reference
    SealSource: NamedTuple = SealSource(s=Castage(Number, 'numh'),
                                      d=Castage(Diger))  # SealSource class reference couple
    SealEvent: NamedTuple = SealEvent(i=Castage(Prefixer),
                                      s=Castage(Number, 'numh'),
                                      d=Castage(Diger))  # SealEvent class reference triple
    SealLast: NamedTuple = SealLast(i=Castage(Prefixer))  # SealLast class reference single
    SealBack: NamedTuple = SealBack(bi=Castage(Prefixer),
                                        d=Castage(Diger))  # SealBack class reference
    SealKind: NamedTuple = SealKind(t=Castage(Verser),
                                        d=Castage(Diger))  # SealKind class reference

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SCastDom = SealCastDom()  # create instance


@dataclass(frozen=True)
class BlindStateClanDom(IceMapDom):
    """BlindStateClanDom is dataclass of namedtuple blinded state class references
    (clans) each indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: BlindStateClanDom[name]
    """
    BlindState: type[NamedTuple] = BlindState  # BlindState class reference (d,u,td,ts)
    BoundState: type[NamedTuple] = BoundState  # BoundState class reference (d,u,td,ts,bn,bd)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

BSClanDom = BlindStateClanDom()  # create instance

@dataclass(frozen=True)
class BlindStateCastDom(IceMapDom):
    """BlindStateCastDom is dataclass of namedtuple instances (blind casts) whose
    field values are Castage instances of named primitive class class references
    for those fields.

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: BlindStateCastDom[name]

    Note: the d, and td field values may be empty so instead of Diger users
    Noncer which allows all the Diger codes plus empty
    """
    BlindState: NamedTuple = BlindState(d=Castage(Noncer, 'nonce'),
                                        u=Castage(Noncer, 'nonce'),
                                        td=Castage(Noncer, 'nonce'),
                                        ts=Castage(Labeler, 'text'))  # BlindState instance
    BoundState: NamedTuple = BoundState(d=Castage(Noncer, 'nonce'),
                                        u=Castage(Noncer, 'nonce'),
                                        td=Castage(Noncer, 'nonce'),
                                        ts=Castage(Labeler, 'text'),
                                        bn=Castage(Number, 'numh'),
                                        bd=Castage(Noncer, 'nonce'))  # BoundState instance

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

BSCastDom = BlindStateCastDom()  # create instance


@dataclass(frozen=True)
class TypeMediaClanDom(IceMapDom):
    """TypeMediaClanDom is dataclass of namedtuple blinded media class references
    (clans) each indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: TypeMediaClanDom[name]
    """
    TypeMedia: type[NamedTuple] = TypeMedia  # TypeMedia class reference (d,u,mt,mv)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

TMClanDom = TypeMediaClanDom()  # create instance


@dataclass(frozen=True)
class TypeMediaCastDom(IceMapDom):
    """TypeMediaCastDom is dataclass of namedtuple instances (blind casts) whose
    field values are Castage instances of named primitive class class references
    for those fields.

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Example: TypeMediaCastDom[name]

    Note: the d field value is a SAID but so instead of Diger users Noncer which
    allows all the Diger codes plus empty
    """
    TypeMedia: NamedTuple = TypeMedia(d=Castage(Noncer, 'nonce'),
                                        u=Castage(Noncer, 'nonce'),
                                        mt=Castage(Labeler, 'text'),
                                        mv=Castage(Texter, 'text'))  # TypeMedia instance

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

TMCastDom = TypeMediaCastDom()  # create instance


@dataclass(frozen=True)
class AllClanDom(IceMapDom):
    """AllClanDom is dataclass of all namedtuple class references (clans) each
    indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get class reference with item syntax using
    name variables.

    Example: AllClanDom[name]
    """
    SealDigest: type[NamedTuple] = SealDigest  # SealDigest class reference (d,)
    SealRoot: type[NamedTuple] = SealRoot  # SealRoot class reference (rd,)
    SealSource: type[NamedTuple] = SealSource  # SealSource class reference couple (s,d)
    SealEvent: type[NamedTuple] = SealEvent  # SealEvent class reference triple (i,s,d)
    SealLast: type[NamedTuple] = SealLast  # SealLast class reference single (i,)
    SealBack: type[NamedTuple] = SealBack  # SealBack class reference (bi, d)
    SealKind: type[NamedTuple] = SealKind  # SealKind class reference (t, d)
    BlindState: type[NamedTuple] = BlindState  # BlindState class reference (d,u,td,ts)
    BoundState: type[NamedTuple] = BoundState  # BoundState class reference (d,u,td,ts,bn,bd)
    TypeMedia: type[NamedTuple] = TypeMedia  # TypeMedia class reference (d,u,mt,mv)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

AClanDom = AllClanDom()  # create instance


@dataclass(frozen=True)
class AllCastDom(IceMapDom):
    """AllCastDom is dataclass of namedtuple instances (casts) whose
    field values are Castage instances of named primitive class class references
    for those fields.

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get namedtuple instance with item syntax using
    name variables.

    Example: AllCastDom[name]
    """
    SealDigest: NamedTuple = SealDigest(d=Castage(Diger))  # SealDigest class reference
    SealRoot: NamedTuple = SealRoot(rd=Castage(Diger))  # SealRoot class reference
    SealSource: NamedTuple = SealSource(s=Castage(Number, 'numh'),
                                      d=Castage(Diger))  # SealSource class reference couple
    SealEvent: NamedTuple = SealEvent(i=Castage(Prefixer),
                                      s=Castage(Number, 'numh'),
                                      d=Castage(Diger))  # SealEvent class reference triple
    SealLast: NamedTuple = SealLast(i=Castage(Prefixer))  # SealLast class reference single
    SealBack: NamedTuple = SealBack(bi=Castage(Prefixer),
                                        d=Castage(Diger))  # SealBack class reference
    SealKind: NamedTuple = SealKind(t=Castage(Verser),
                                        d=Castage(Diger))  # SealKind class reference
    BlindState: NamedTuple = BlindState(d=Castage(Noncer, 'nonce'),
                                        u=Castage(Noncer, 'nonce'),
                                        td=Castage(Noncer, 'nonce'),
                                        ts=Castage(Labeler, 'text'))  # BlindState instance
    BoundState: NamedTuple = BoundState(d=Castage(Noncer, 'nonce'),
                                        u=Castage(Noncer, 'nonce'),
                                        td=Castage(Noncer, 'nonce'),
                                        ts=Castage(Labeler, 'text'),
                                        bn=Castage(Number, 'numh'),
                                        bd=Castage(Noncer, 'nonce'))  # BoundState instance
    TypeMedia: NamedTuple = TypeMedia(d=Castage(Noncer, 'nonce'),
                                        u=Castage(Noncer, 'nonce'),
                                        mt=Castage(Labeler, 'text'),
                                        mv=Castage(Texter, 'text'))  # TypeMedia instance

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

ACastDom = AllCastDom()  # create instance


# map Structor clan names to counter code names for ser/des as counted group
ClanToCodens = dict()
ClanToCodens[AClanDom.SealDigest.__name__] = Codens.DigestSealSingles
ClanToCodens[AClanDom.SealRoot.__name__] = Codens.MerkleRootSealSingles
ClanToCodens[AClanDom.SealSource.__name__] = Codens.SealSourceCouples
ClanToCodens[AClanDom.SealEvent.__name__] = Codens.SealSourceTriples
ClanToCodens[AClanDom.SealLast.__name__] = Codens.SealSourceLastSingles
ClanToCodens[AClanDom.SealBack.__name__] = Codens.BackerRegistrarSealCouples
ClanToCodens[AClanDom.SealKind.__name__] = Codens.TypedDigestSealCouples
ClanToCodens[AClanDom.BlindState.__name__] = Codens.BlindedStateQuadruples
ClanToCodens[AClanDom.BoundState.__name__] = Codens.BoundStateSextuples
ClanToCodens[AClanDom.TypeMedia.__name__] = Codens.TypedMediaQuadruples


# map counter codename to Structor clan name for ser/des as counted group
CodenToClans = { val: key for key, val in ClanToCodens.items()}  # invert dict


class Structor:
    """Structor class each instance holds a namedtuple .data of named values.
    Each value is a primitive instance of CESR primitive subclass that supports
    text (qb64) and binary (qb2) domains.
    Structor instances can be serialized to or deserialized from concatenation
    of the qb64 or qb2 representations of the data values. Creation requires
    input of an instance of an ordered collection of named classes for creating
    the named instances from the input data.
    Smart data format inputs are supported to accomodate the many ways
    the named data may appear in messages and or databases.

    Instance Creation Patterns:

        Structor(data):

        Structor(clan, cast, crew):
        Structor(clan, cast, qb64):
        Structor(clan, cast, qb2):

        Structor(cast, crew):
        Structor(cast, qb64):
        Structor(cast, qb2):

        Structor(clan, crew):  when known cast in .Casts for clan
        Structor(clan, qb64): when known cast in .Casts for clan
        Structor(clan, qb2):  when known cast in .Casts for clan

        Structor(crew): when known cast in .Casts for crew


    Class Attributes:
        Clans (type[Namedtuple]): each value is known NamedTuple class keyed
            by its own field names (tuple). Enables easy query of its values() to
            find known data types given field names tuple.
        Casts (NamedTuple): each value is primitive class of cast keyed by fields
            names of the associated NamedTuple class in .Clans. Enables finding
            known primitive classes given NamedTuple class of clan or instance
            of cast or crew.
        Names (dict):  maps tuple of clan/cast fields names to its namedtuple
                       class type name so can look up a know clan or cast
                       given a matching tuple
        ClanCodens (dict): map of clan namedtuple to counter code name for
                           ser/des as group
        CodenClans (dict): map of counter code name to clan named tuple for
                           ser/des as group
        Saids (dict):  default saidive fields at top-level. Assumes .mad already
            in most compact form.
            Each key is label of saidive field.
            Each value is default primitive code of said digest value to be
                computed from serialized dummied .mad
        Dummy (str): dummy character for computing SAIDs


    When known casts or provided in .Clans/.Casts then more flexible creation
    is supported for different types of provided cast and crew.
    When no clan is provided and an unknown cast and/or crew are provided as
    Mappings then Structor may create custom clan from the names given by the
    cast and/or crew keys(). Subclasses may override this behavior by raising
    an exception for unknown or custom clans.


    Properties:
        data (NamedTuple): instance whose fields are named instances of CESR primitives
        clan (type[NamedTuple]): .data's class, class object reference
        cast (NamedTuple | None): values are Castage instances that each provide
                    CESR primitive class references and primitive init parameters
                    used to initialize .data's primitive instances.
        crew (NamedTuple): named qb64 values of .data's primitive instances
        qb64 (str): concatenated data values as qb64 str of data's primitives
        qb64b (bytes): concatenated data values as qb64b  of data's primitives
        qb2 (bytes): concatenated data values as qb2 bytes of data's primitives
        saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs
        said (str): qb64 said given .saids given .saids as saidive .data.d.qb64
                      primary said field value if any. None otherwise
                      primary has same label as zeroth item in .saids
        saidb (bytes): qb64b said given .saids as saidive fields .data.d.qb64b

    Methods:


    Hidden:
        _data (namedtuple): named CESR primitive instances
        _cast (namedtuple): named Castage instances
        _saids (dict): default top-level said fields and codes
        _saidive (bool): compute saids or not


    Requires that any Castage where castage.ipn is not None must have a
    matching property or attribute name (same as value of ipn) on its Matter
    subclass so it can round trip as a data field in a structor.crew

    For example:
    Given the cast for a structor of
    SealEvent(i=Castage(kls=<class 'keri.core.coring.Prefixer'>, ipn=None),
              s=Castage(kls=<class 'keri.core.coring.Number'>, ipn='numh'),
              d=Castage(kls=<class 'keri.core.coring.Diger'>, ipn=None))

    Then the castage.ipn = 'numh' for its field as a  Number instance,
    then number.numh must be property or attribute whose value is a
    serialization that would be the value of the same named __init__
    parameter 'numh', as in, getattr(number, ipn) == serialization value

    as in:
    number = Number(numh=value)
    getattr(number,'numh')== value

    Note that default of ipn='qb64' is already property of Matter base class
    as in:
    matter = Matter(qb64=value)
    matter.qb64 == value


    """
    Clans = AClanDom  # EClanDom known namedtuple clans. Override in subclass with non-empty
    Casts = ACastDom  # ECastDom known namedtuple casts. Override in subclass with non-empty
    # Create .Names dict that maps tuple of clan/cast fields names to its namedtuple
    # class type name so can look up a know clan or cast given a matching tuple
    # of either field names from a namedtuple or keys from a dict. The tuple of
    # field names is a mark of the structor type. This maps a mark to a class name
    Names = {tuple(clan._fields): clan.__name__ for clan in Clans}

    ClanCodens = ClanToCodens  # map of clan namedtuple to counter code name
    CodenClans = CodenToClans  # map of counter code name to clan namedtuple
    Saids = dict(d=DigDex.Blake3_256)  # default said field label with digestive code
    Dummy = '#'  # default dummy for computing SAIDS

    @classmethod
    def enclose(cls, structors, cold=Colds.txt):
        """Serializes structors with prepended counter code in either text or binary
        domain as bytes determined by cold where text='txt' or binary='bny'
        Uses .clan to determine counter.code from .ClanCodes

        Returns:
            enclosure (bytearray): enclosure serialized structors with
                leading Counter using .clan of zeroth structor that maps to
                Counter code given by .ClanCodes.
                When cold==Colds.txt then enclosure is in qb64 text domain
                When cold==Colds.bny then enclosure is in qb2 binary domain

        Parameters:
            structors (list[Structor]): instances of Structure.
                                        Must all share the same clan
            cold (str): Colds value, 'txt' means qb64b text domain
                        Colds value, 'bny' means qb2 binary domain
        """
        buf = bytearray()
        clan = None
        for structor in structors:
            if clan is None:
                clan = structor.clan
            else:
                if structor.clan != clan:
                    raise InvalidValueError(f"Invalid  as clan={structor.clan.__name__}"
                                            f" not sames as clan={clan.__name__}")
            if cold == Colds.txt:
                buf.extend(structor.qb64b)
            elif cold == Colds.bny:
                buf.extend(structor.qb2)
            else:
                raise InvalidValueError(f"Invalid {cold=}, not {Cold.txt} or {Colds.bny}")

        if clan is None:  # empty structors
            clan = list(cls.ClanCodens.keys())[0]  # use default as zeroth clan

        try:
            coden = cls.ClanCodens[clan.__name__]
        except KeyError as ex:
            raise InvalidValueError(f"Invalid on-the-fly "
                                    f"clan={clan.__name__}") from ex

        if cold == Colds.txt:
            return Counter.enclose(qb64=buf, code=coden)
        elif cold == Colds.bny:
            return Counter.enclose(qb2=buf, code=coden)
        else:
            raise InvalidValueError(f"Invalid {cold=}, not {Cold.txt} or {Colds.bny}")


    @classmethod
    def extract(cls, qb64b=None, qb64=None, qb2=None, strip=False):
        """List of Structor instances from  serialization of counted group

        Returns:
            structors (list[Structor]): extracts structor instances of type cls
                from qb64 or qb2 of encoded Counter and framed group that is
                structor uses counter.code that maps to clan given by .CodeClans

        Parameters:
            qb64b (str|bytes|bytearray|memoryview|None): text domain CESR
                serializaton of framed counter group (count code inclusive)
            qb64 (str|bytes|bytearray|memoryview|None): alias of qb64 for
                matter interface compatability
            qb2 (bytes|bytearray|memoryview|None): binary domain CESR
                serializaton of framed counter group (count code inclusive)
            strip (bool): when True and qb64 or qb2 is bytearray then strip
                                extracted group from qb64/qb2
                          Otherwise  do not strip

        """
        qb64b = qb64b if qb64b is not None else qb64
        structors = []

        if qb64b is not None:
            if hasattr(qb64b, 'encode'):
                qb64b = qb64b.encode()

            ims = qb64b   # reference start of stream
            ctr = Counter(qb64b=qb64b)  # peek at counter
            clan = cls.Clans[cls.CodenClans[ctr.name]]  # get clan from code name
            cs = ctr.byteSize(cold=Colds.txt)  # counter byte size
            es = ctr.byteCount(cold=Colds.txt)  # enclosed content byte size
            gs = cs + es  # total group size including counter
            qb64b = bytearray(qb64b[cs:gs])  # copy contents as bytearray so can strip
            while qb64b:
                structors.append(cls(clan=clan, qb64b=qb64b, strip=True))
            if strip and isinstance(ims, bytearray):
                del ims[:gs]  # strip original

        elif qb2 is not None:
            ims = qb2   # reference start of stream
            ctr = Counter(qb2=qb2)  # peek at counter
            clan = cls.Clans[cls.CodenClans[ctr.name]]  # get clan from code name
            cs = ctr.byteSize(cold=Colds.bny)  # counter byte size
            es = ctr.byteCount(cold=Colds.bny)  # enclosed content byte size
            gs = cs + es  # total group size including counter
            qb2 = bytearray(qb2[cs:gs])  # copy contents as bytearray so can strip
            while qb2:
                structors.append(cls(clan=clan, qb2=qb2, strip=True))
            if strip and isinstance(ims, bytearray):
                del ims[:gs]  # strip original

        else:
            raise EmptyMaterialError(f"Missing qb64b or qb64 or qb2")

        return structors


    def __init__(self, data=None, *, clan=None, cast=None, crew=None, naive=False,
                                     qb64b=None, qb64=None, qb2=None,
                                     strip=False, makify=False, verify=True,
                                     saids=None, saidive=False):
        """Initialize instance

        Parameters:
            data (NamedTuple | None): fields are named primitive instances for .data
                Given data can derive clan, cast, crew, qb64, and qb2
            clan (type[NamedTuple]): data's class, provides class reference for
                generating .data when data missing.
            cast (NamedTuple | dict | Iterable | None):  values are Castage
                instances that each provide CESR primitive class references
                and primitive init parameter used to .data's primitive
                instances. None means .data provided directly not generated
                from cast. Each value provides CESR  primitive subclass reference
                used to create primitive instances for generating .data.
                Can be used to infer namedtuple type of .data when data and
                clan missing. Takes precendence over crew.
            crew (NamedTuple | dict | Iterable | None): each value provides qb64 value
                of primitive for generating .data with .cast when data missing.
                Can be used to infer namedtuple type of .data when data and clan
                missing.
            naive (bool): False means when none of cast, clan, crew provided
                            then infer cast from namedtupe type of data in .Costs
                            otherwise create naive cast from fields in data
                          True means when when none of cast, clan, crew provided
                            then create naive cast from fields in data
            qb64b (str|bytes|bytearray|None): concatenation of qb64b data values to
                generate .data with data and crew missing.
            qb64 (str|bytes|bytearray|None): alias for qb64b
            qb2 (bytes|bytearray|None): concatenation of qb2 data values to generate
                .data when data and crew and qb64 missing.
            strip (bool): False means do not strip each value from qb64 or qb2.
                Default is False. True means if qb64 or qb2 are bytearray then
                strip contained concatenated data values. Else convert qb64 or
                qb2 to bytearray so can strip inplace. Enables parser to extract
                data fields from front of CESR stream when stream is bytearray.
            makify (bool): True means compute saids when .saidive
                           False means do not comput saids even when .saidive
            verify (bool): True means verify serialization against mad.
                           False means do not verify
            saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
            saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs


        """
        makify = True if makify else False
        verify = True if verify else False

        self._saids = dict(saids if saids is not None else self.Saids)  # make copy
        self._saidive = True if saidive else False

        if data:
            if not (isinstance(data, tuple) and hasattr(data, "_fields")):
                raise InvalidValueError(f"Not namedtuple subclass {data=}.")

            for pi in data:  # check for primitive interface
                if not (hasattr(pi, "qb64") and hasattr(pi, "qb2")):
                    raise InvalidValueError(f"Non-primitive data member={pi}.")

            # when cast is not None then will be used instead of generating
            # custom cast below

        else:  # no data and not counter so see if can infer clan and cast
            if not clan:  # attempt to get from cast and/or crew
                if cast and isinstance(cast, tuple) and hasattr(cast, "_fields"):
                    clan = cast.__class__

                if not clan and crew:
                    if isinstance(crew, tuple) and hasattr(crew, "_fields"):
                        clan = crew.__class__

                if not clan and isinstance(cast, Mapping):  # get clan from cast
                    mark = tuple(cast)  # create custom clan based on cast mark
                    if (cname := self.Names.get(mark)):  # get known else None
                        clan = self.Clans[cname]
                        cast = self.Casts[cname]

                    else:  # create custom clan from cast
                        clan = namedtuple("_".join(mark), mark)  # custom clan

                if not clan and isinstance(crew, Mapping):  # get clan from crew
                    mark = tuple(crew)  # create custom clan based on crew mark
                    if (cname := self.Names.get(mark)):  # get known else None
                        clan = self.Clans[cname]
                        cast = self.Casts[cname]

                    else:  # create custom clan from crew
                        clan = namedtuple("_".join(mark), mark)  # custom clan from cast keys

            if clan:
                if not (issubclass(clan, tuple) and hasattr(clan, "_fields")):
                    raise InvalidValueError(f"Not namedtuple subclass {clan=}.")
            else:
                raise InvalidValueError(f"Missing or unobtainable clan.")

            # have clan but may not have cast
            if cast:
                if not isinstance(cast, clan):
                    if isinstance(cast, tuple) and hasattr(cast, "_fields"):
                        if cast._fields != clan._fields:  # fields is mark
                            raise InvalidValueError(f"Mismatching fields clan="
                                                    f"{clan._fields} and cast="
                                                    f"{cast._fields}.")

                        cast = clan(**cast._asdict())  # convert to clan

                    elif isinstance(cast, Mapping):
                        if tuple(cast) != clan._fields:  # fields is mark
                            raise InvalidValueError(f"Mismatching fields clan="
                                                    f"{clan._fields} and keys cast="
                                                    f"{tuple(cast)}.")

                        cast = clan(**cast)  # convert to clan

                    elif isinstance(cast, isNonStringSequence):
                        cast = clan(*cast)  # convert to clan assumes elements in correct order

                    else:
                        raise InvalidValueError(f"Invalid {cast=}.")

            else:  # get cast from known .Casts if possible
                if (cname := self.Names.get(clan._fields)):  # fields is mark
                    cast = self.Casts[cname]  # get known cast
                else:  # cast missing or unobtainable
                    raise InvalidValueError(f"Missing or unobtainable cast.")

            # have cast now
            for cstg in cast:
                if not (hasattr(cstg.kls, "qb64b") and hasattr(cstg.kls, "qb2")):
                    raise InvalidValueError(f"Cast member {cstg.kls=} not CESR"
                                            " Primitive.")

            qb64b = qb64b if qb64b is not None else qb64  # copy qb64 to qb64b
            if crew:  # have clan and cast and crew
                if not isinstance(crew, clan):
                    if isinstance(crew, tuple) and hasattr(crew, "_fields"):
                        if crew._fields != clan._fields:  # fields is mark
                            raise InvalidValueError(f"Mismatching fields clan="
                                                    f"{clan._fields} and crew="
                                                    f"{crew._fields}.")

                        crew = clan(**crew._asdict())  # convert to clan

                    elif isinstance(crew, Mapping):
                        if tuple(crew) != clan._fields:  # fields is mark
                            raise InvalidValueError(f"Mismatching fields clan="
                                                    f"{clan._fields} and keys crew="
                                                    f"{tuple(crew)}.")

                        crew = clan(**crew)  # convert to clan

                    elif isinstance(crew, isNonStringSequence):
                        crew = clan(*crew)  # convert to clan assumes elements in correct order

                    else:
                        raise InvalidValueError(f"Invalid {crew=}.")

                data = clan(*(cstg.kls(**{cstg.ipn if cstg.ipn is not None else 'qb64': val})
                              for cstg, val in zip(cast, crew)))

            elif qb64b:  # have clan and cast but not crew
                if hasattr(qb64b, "encode"):
                    qb64b = qb64b.encode()

                o = 0  # offset into memoryview of qb64
                pis = []  # primitive instances
                mv = memoryview(qb64b)
                for cstg in cast:  # Castage
                    pi = cstg.kls(qb64b=mv[o:])
                    pis.append(pi)
                    o += len(pi.qb64b)
                data = clan(*pis)

                if strip and isinstance(qb64b, bytearray):
                    del mv  # release memoryview ref count so can resize buffer
                    del qb64b[:o]  # strip original  to final offset

            elif qb2:  # have clan and cast but not crew
                o = 0  # offset into memoryview of qb2
                pis = []  # primitive instances
                mv = memoryview(qb2)
                for cstg in cast:  # Castage
                    pi = cstg.kls(qb2=mv[o:])
                    pis.append(pi)
                    o += len(pi.qb2)
                data = clan(*pis)

                if strip and isinstance(qb2, bytearray):
                    del mv  # release memoryview ref count so can resize buffer
                    del qb2[:o]  # strip original  to final offset

            else:
                raise EmptyMaterialError(f"Need crew or qb64(b) or qb2 or "
                                         f"eqb64(b) or eqb2.")

        if makify and self.saidive:  # compute saids at top level
                # dummy serialization of data
            said = None
            dqb64 = {l: v.qb64 for l, v in data._asdict().items()}
            for l in self.saids:
                if l in data._fields:
                    v = getattr(data, l)
                    if isinstance(v, Noncer) and v.code in DigDex:
                        code = v.code
                    else:
                        code = self.saids[l]

                    if code != self.saids[l]:  # different than default
                        # remember actual code for field when not default so
                        # eventually computed said uses this code not default
                        self.saids[l] = code  # replace default with provided

                    size = Noncer._fullSize(code)
                    dqb64[l] = self.Dummy * size

            ser = ''.join(dqb64.values())  # dummied ser
            said = Diger(ser=ser.encode(), code=code).qb64

            if said:
                replace = {}
                for l, code in self.saids.items():
                    if l in data._fields:  # has saidive field
                        noncer = Noncer(qb64=said)
                        replace[l] = noncer
                if replace:  # replace saidive field values with saided noncers
                    data = data._replace(**replace)  # data with saided noncers


        self._data = data  # now have self.clan which is self._data.__class__
        if cast is None:
            if naive:  # force naive
                cast = self.clan(*(Castage(val.__class__) for val in self.data))
            elif cname := self.Names.get(self.clan._fields):  # fields is mark
                cast = self.Casts[cname]  # get known cast if possilbe
            else:  # naive cast as only recourse
                cast = self.clan(*(Castage(val.__class__) for val in self.data))
        self._cast = cast

        if self.saidive and not makify and verify:  # verify saids
            # dummy serialization of .data
            said = None
            dqb64 = {l: v.qb64 for l, v in self.data._asdict().items()}
            for l in self.saids:
                if l in data._fields:
                    v = getattr(data, l)
                    if isinstance(v, Noncer) and v.code in DigDex:
                        code = v.code
                    else:
                        code = self.saids[l]

                    if code != self.saids[l]:  # different than default
                        # remember actual code for field when not default so
                        # eventually computed said uses this code not default
                        self.saids[l] = code  # replace default with provided

                    size = Noncer._fullSize(code)
                    dqb64[l] = self.Dummy * size

                    ser = ''.join(dqb64.values())  # dummied ser
                    said = Diger(ser=ser.encode(), code=code).qb64

            if said:
                for l, code in self.saids.items():
                    if l in self.data._fields:  # has saidive field
                        if getattr(self.data, l).qb64 != said:
                            raise ValidationError(f"Invalid SAID for structor"
                                                  f"={self.crew}")



    @property
    def data(self):
        """Property data
        Returns:
            data (NamedTuple): ._data namedtuple of primitive instances

        Getter for ._data makes it read only
        """
        return self._data


    @property
    def clan(self):
        """Property clan
        Returns:
            clan (type[NamedTuple]): class of .data

        """
        return self.data.__class__


    @property
    def name(self):
        """Property name
        Returns:
            name (str): name of class of .data

        """
        return self.data.__class__.__name__


    @property
    def cast(self):
        """Property cast
        Returns:
            cast (NamedTuple): named primitive classes in .data

        Getter for ._cast makes it read only when not None
        """
        return self._cast


    @property
    def crew(self):
        """Property crew
        Returns:
            crew (NamedTuple): named qb64 field values from .data

        Requires that any Castage where castage.ipn is not None must have a
        matching property or attribute name (same as value of ipn) on its Matter
        subclass so it can round trip as a data field in a structor.crew

        For example:
        Given the cast for a structor of
        SealEvent(i=Castage(kls=<class 'keri.core.coring.Prefixer'>, ipn=None),
                  s=Castage(kls=<class 'keri.core.coring.Number'>, ipn='numh'),
                  d=Castage(kls=<class 'keri.core.coring.Diger'>, ipn=None))

        Then the castage.ipn = 'numh' for its field as a  Number instance,
        then number.numh must be property or attribute whose value is a
        serialization that would be the value of the same named __init__
        parameter 'numh', as in, getattr(number, ipn) == serialization value

        given:
        number = Number(numh=value)
        getattr(number,'numh')== value

        Note that default of ipn='qb64' is already property of Matter base class
        as in:
        matter = Matter(qb64=value)
        matter.qb64 == value

        """
        return (self.clan(*(getattr(val, cstg.ipn if cstg.ipn is not None else "qb64")
                    for cstg, val in zip(self.cast, self.data))))


    @property
    def asdict(self):
        """Property asdict shorthand for .crew._asdict() for round trip
        conversion for sad dict representation in Serder instances.

        .crew is namedtuple whose fields values are serializations of the data
        values that respect .cast Castage.ipn formats.

        Returns:
            dcrew (dict): .crew._asdict() as a field value map (dict) with
                serialized values of the data value Matter instances whose
                serializations respect the .cast Castage.ipn serialization formats.
        """
        return self.crew._asdict()


    @property
    def qb64(self):
        """Property qb64
        Returns:
            qb64 (str): concatenated qb64 of each primitive in .data
        """
        return (''.join(val.qb64 for val in self.data))


    @property
    def qb64b(self):
        """Property qb64b
        Returns:
            qb64b (bytes): concatenated qb64b of each primitive in .data
        """
        return (b''.join(val.qb64b for val in self.data))


    @property
    def qb2(self):
        """Property qb2
        Returns:
            qb2 (bytes): concatenated qb2 of each primitive in .data
        """
        return (b''.join(val.qb2 for val in self.data))

    @property
    def said(self):
        """primary said field value if any. None otherwise

        Returns:
              said (str|None): primary said field value if any. None otherwise
                               primary has same label as zeroth item in .saids
        """
        if self.saidive and self.saids:
            l = list(self.saids.keys())[0]  # primary said is zeroth entry in said
            v = getattr(self.data, l, None)
            return v.qb64 if v is not None else None

        return None


    @property
    def saidb(self):
        """primary said field value if any. None otherwise

        Returns:
              said (bytes|None): primary said field value if any. None otherwise
                               primary has same label as zeroth item in .saids
        """
        return self.said.encode() if self.said is not None else None



    @property
    def saids(self):
        """Getter for ._saids

        Returns:
            saids (dict): default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        """
        return self._saids


    @property
    def saidive(self):
        """Getter for ._saidive

        Returns:
              saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                            False means do not compute SAIDs
        """
        return self._saidive


class Sealer(Structor):
    """Sealer is Structor subclass each instance holds a namedtuple .data of
    named values belonging to KERI Seals for anchoring in messages or adding
    to message attachments.

    See Structor class for more details.


    Inherited Class Attributes:
        Clans (type[Namedtuple]): each value is known NamedTuple class keyed
            by its own field names (tuple). Enables easy query of its values() to
            find known data types given field names tuple.
        Casts (NamedTuple): each value is primitive class of cast keyed by fields
            names of the associated NamedTuple class in .Clans. Enables finding
            known primitive classes given NamedTuple class of clan or instance
            of cast or crew.
        Names (dict):  maps tuple of clan/cast fields names to its namedtuple
                       class type name so can look up a know clan or cast
                       given a matching tuple
        ClanCodens (dict): map of clan namedtuple to counter code name for
                           ser/des as group
        CodenClans (dict): map of counter code name to clan named tuple for
                           ser/des as group
        Saids (dict):  default saidive fields at top-level. Assumes .mad already
            in most compact form.
            Each key is label of saidive field.
            Each value is default primitive code of said digest value to be
                computed from serialized dummied .mad
        Dummy (str): dummy character for computing SAIDs



    When known casts are provided in .Clans/.Casts then more flexible creation
    is supported for different types of provided cast and crew.
    When no clan is provided and an unknown cast and/or crew are provided as
    Mappings then Structor may create custom clan from the names given by the
    cast and/or crew keys(). Subclasses may override this behavior by raising
    an exception for unknown or custom clans.


    Inherited Properties:
        data (NamedTuple): fields are named instances of CESR primitives
        clan (type[NamedTuple]): class reference of .data's class
        cast (NamedTuple): CESR primitive class references of .data's primitive
                           instances
        crew (NamedTuple): named qb64 values of .data's primitive instances
        qb64 (str): concatenated data values as qb64 str of data's primitives
        qb64b (bytes): concatenated data values as qb64b  of data's primitives
        qb2 (bytes): concatenated data values as qb2 bytes of data's primitives
        saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs
        said (str): qb64 said given .saids given .saids as saidive .data.d.qb64
                      primary said field value if any. None otherwise
                      primary has same label as zeroth item in .saids
        saidb (bytes): qb64b said given .saids as saidive fields .data.d.qb64b


    Methods:


    Hidden:
        _data (NamedTuple): named CESR primitive instances

    Example:
        dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
        diger = Diger(qb64=dig)
        data = SealDigest(d=diger)
        name = SealDigest.__name__

        sealer = Sealer(data=data)
        assert sealer.data == data
        assert sealer.clan == SealDigest
        assert sealer.name == SealDigest.__name__
        assert sealer.cast == SealDigest(d=Castage(Diger))
        assert sealer.crew == SealDigest(d=dig)
        assert sealer.asdict == data._asdict() ==sealer.crew._asdict()



    """
    Clans = SClanDom  # known namedtuple clans. Override in subclass with non-empty
    Casts = SCastDom  # known namedtuple casts. Override in subclass with non-empty
    # Create .Names dict that maps clan/cast fields names to its namedtuple
    # class type name so can look up a know clan or cast given a matching set
    # of either field names from a namedtuple or keys from a dict.
    Names = {tuple(clan._fields): clan.__name__ for clan in Clans}

    # map clan names to counter code for ser/des as counted group
    ClanCodens = dict()
    ClanCodens[SClanDom.SealDigest.__name__] = Codens.DigestSealSingles
    ClanCodens[SClanDom.SealRoot.__name__] = Codens.MerkleRootSealSingles
    ClanCodens[SClanDom.SealEvent.__name__] = Codens.SealSourceTriples
    ClanCodens[SClanDom.SealSource.__name__] = Codens.SealSourceCouples
    ClanCodens[SClanDom.SealLast.__name__] = Codens.SealSourceLastSingles
    ClanCodens[SClanDom.SealBack.__name__] = Codens.BackerRegistrarSealCouples
    ClanCodens[SClanDom.SealKind.__name__] = Codens.TypedDigestSealCouples

    # map counter code to clan name for ser/des as counted group
    CodenClans = { val: key for key, val in ClanCodens.items()}  # invert dict


    def __init__(self, *pa, **kwa):
        """Initialize instance


        Inherited Parameters:
            data (NamedTuple): fields are named primitive instances for .data
                Given data can derive clan, cast, crew, qb64, and qb2
            clan (type[NamedTuple]): provides class reference for generated .data
                when data missing.
            cast (NamedTuple | dict | Iterable): each value provides CESR
                primitive subclass reference used to create primitive instances
                for generating .data. Can be used to infer namedtuple type of
                .data when data and clan missing. Takes precendence over crew.
            crew (NamedTuple | dict | Iterable): each value provides qb64 value
                of primitive for generating .data with .cast when data missing.
                Can be used to infer namedtuple type of .data when data and clan
                missing.
            qb64 (str | bytes | bytearray): concatenation of qb64 data values to
                generate .data with data and crew missing.
            qb2 (bytes | bytearray): concatenation of qb2 data values to generate
                .data when data and crew and qb64 missing.
            strip (bool): False means do not strip each value from qb64 or qb2.
                            Default is False.
                          True means if qb64 or qb2 are bytearray then strip
                            contained concatenated data values. Enables parser
                            to extract data fields from front of CESR stream.

        """
        super(Sealer, self).__init__(*pa, **kwa)

        if self.clan not in self.Clans:
            raise InvalidValueError("Unrecognized clan={self.clan}")


class Blinder(Structor):
    """Blinder is Structor subclass each instance holds a namedtuple .data of
    named values belonging to ACDC blinded state attribute for blindable state
    registry for TEL for ACDC to unblind the state attribute via a message
    attachment.

    See Structor class for more details.


    Inherited Class Attributes:
        Clans (type[Namedtuple]): each value is known NamedTuple class keyed
            by its own field names (tuple). Enables easy query of its values() to
            find known data types given field names tuple.
        Casts (NamedTuple): each value is primitive class of cast keyed by fields
            names of the associated NamedTuple class in .Clans. Enables finding
            known primitive classes given NamedTuple class of clan or instance
            of cast or crew.
        Names (dict):  maps tuple of clan/cast fields names to its namedtuple
                       class type name so can look up a know clan or cast
                       given a matching tuple
        ClanCodens (dict): map of clan namedtuple to counter code name for
                           ser/des as group
        CodenClans (dict): map of counter code name to clan named tuple for
                           ser/des as group
        Saids (dict):  default saidive fields at top-level. Assumes .mad already
            in most compact form.
            Each key is label of saidive field.
            Each value is default primitive code of said digest value to be
                computed from serialized dummied .mad
        Dummy (str): dummy character for computing SAIDs

    Class Attributes:

    When known casts are provided in .Clans/.Casts then more flexible creation
    is supported for different types of provided cast and crew.
    When no clan is provided and an unknown cast and/or crew are provided as
    Mappings then Structor may create custom clan from the names given by the
    cast and/or crew keys(). Subclasses may override this behavior by raising
    an exception for unknown or custom clans.


    Inherited Properties:
        data (NamedTuple): fields are named instances of CESR primitives
        clan (type[NamedTuple]): class reference of .data's class
        cast (NamedTuple): CESR primitive class references of .data's primitive
                           instances
        crew (NamedTuple): named qb64 values of .data's primitive instances
        qb64 (str): concatenated data values as qb64 str of data's primitives
        qb64b (bytes): concatenated data values as qb64b  of data's primitives
        qb2 (bytes): concatenated data values as qb2 bytes of data's primitives
        saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs
        said (str): qb64 said given .saids given .saids as saidive .data.d.qb64
                      primary said field value if any. None otherwise
                      primary has same label as zeroth item in .saids
        saidb (bytes): qb64b said given .saids as saidive fields .data.d.qb64b

    Properties:
        blid (str): alias of .said property
        blidb (bytes): alias .saidb property
        uuid (str): qb64 uuid of BlindState CESR .data.u 'u' field
        uuidb (bytes): qb64b uuid of BlindState CESR .data.u 'u' field
        acdc (str): qb64 transaction acdc said or empty of
                       BlindState CESR .data.td 'td' field
        acdcb (bytes): qb64b transaction acdc said of
                           BlindState CESR .data.td 'td' field
        state (str):  transaction state string of
                        BlindState CESR .data.ts 'ts' field
        stateb (bytes): transaction state string of
                            BlindState CESR .data.ts 'ts' field
        bsn (int): bound key state sequence number of issuees key state at
                      time of update
                      BoundState CESR .data.bn 'bn' field
        bnh (str): bound key state  hex sequence number of issuees key state
                       at time of update
                       BoundState CESR .data.bn 'bn' field
        bnhb (bytes): bound key state hex sequence number of issuees key
                           state at time of update
                           BoundState CESR .data.bn 'bn' field
        bd (str): qb64 bound key state said  of issuee at time of update
                      BoundState CESR .data.bd 'bd' field
        bdb (bytes): qb64b bound key state said of issuee at time of update
                          BoundState CESR .data.bd 'bd' field

    Methods:


    Hidden:
        _data (namedtuple): named CESR primitive instances
        _cast (namedtuple): named Castage instances
        _saids (dict): default top-level said fields and codes
        _saidive (bool): compute saids or not

    Example:
        sdig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
        sdiger = Diger(qb64=dig)
        noncer = Noncer(code=NonceDex.Salt_256)
        adig = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
        adiger = Diger(qb64=adig)
        labeler = Labeler(text="issued")
        data = BlindState(d=sdiger, u=noncer, td=adiger, ts=labeler)
        name = BlindState.__name__

        blinder = Blinder(data=data)
        assert blinder.data == data
        assert blinder.clan == BlindState
        assert blinder.name == BlindState.__name__
        assert blinder.cast == BlindState(d=Castage(Diger),
                                          u=Castage(Noncer, 'nonce'),
                                          td=Castage(Noncer, 'nonce'),
                                          ts=Castage(Labeler, 'text'))
        assert blinder.crew == BlindState(d=sdig,
                                         u=noncer.nonce,
                                         td=adig,
                                         ts=labeler.text)
        assert blinder.asdict == data._asdict() == sealer.crew._asdict()

    """
    Clans = BSClanDom  # known namedtuple clans. Override in subclass with non-empty
    Casts = BSCastDom  # known namedtuple casts. Override in subclass with non-empty
    # Create .Names dict that maps clan/cast fields names to its namedtuple
    # class type name so can look up a know clan or cast given a matching set
    # of either field names from a namedtuple or keys from a dict.
    Names = {tuple(clan._fields): clan.__name__ for clan in Clans}

    # map clan names to counter code for ser/des as counted group
    ClanCodens = dict()
    ClanCodens[BSClanDom.BlindState.__name__] = Codens.BlindedStateQuadruples
    ClanCodens[BSClanDom.BoundState.__name__] = Codens.BoundStateSextuples

    # mapcounter code to clan name for ser/des as counted group
    CodenClans = { val: key for key, val in ClanCodens.items()}  # invert dict

    Tier = Tiers.low  # since used as blinding factor not authenticator

    @classmethod
    def makeUUID(cls, raw=None, salt=None, sn=1, tier=None):
        """Creates UUID salty nonce from provided parameters

        Returns:
            uuid (str): blinding factor qb64

        Parameters:
            raw (bytes|None): random crypto material as salt
            salt (str|None): qb64 of 128 bit random salt
            sn (int): sequence number of blindable update message. Converted to
                      Number.snh which is hex str no leading zeros
            tier (str|None): used to generate salt when not provided
        """
        tier = tier if tier is not None else cls.Tier
        salter = Salter(raw=raw, qb64=salt, tier=tier)
        path = Number(num=sn).snh
        return Noncer(raw=salter.stretch(path=path), code=NonceDex.Salt_256).qb64


    @classmethod
    def blind(cls, *, raw=None, salt=None, sn=1, tier=None, acdc='', state='',
                      bound=False, bsn=0, bd=''):
        """Creates blinded blinder by generating blinding factor uuid given:
           either raw or salt as shared secret if both None then generate salt
           sn of blindable update event,
           acdc said (may be empty for placeholder
           state string (may be empty for placeholder)
           tier for generator salt when not provided

        Returns:
            blinder (Blinder): blinded blinder

        Parameters:

            raw (bytes|None): random crypto material as salt used to generate uuid
            salt (str|None): qb64 of 128 bit random salt used to generate uuid
            sn (int): sequence number of blindable update message. Converted to
                      Number.huge which is qb64 (24 char) used to generate uuid
            tier (str|None): used to generate uuid
            acdc (str): qb64 said of associated acdc (trans event acdc).
                        Allows empty str for placeholder
            state (str): state string value.
                        Allows empty str for placeholder
            bound (bool): True means use BoundState
                          False means use BlindState default
            bsn (int): bound sequence number of latest key event of issuee at
                       time of state update as (cross anchor)
                       when bound==True and bsaid is not empty
                       when bsaid is empty then bsn must be 0 as placeholder
            bd (str): bound key event said of latest issuee key event at
                        time of state update as (cross anchor)
                         when bound==True and bsaid is not empty
                        Empty string means placeholder and bsn must be 0

        """
        uuid = cls.makeUUID(raw=raw, salt=salt, sn=sn, tier=tier)

        if bound:
            crew = BoundState(d="", u=uuid, td=acdc, ts=state, bn=bsn, bd=bd)
        else:
            crew = BlindState(d="", u=uuid, td=acdc, ts=state)
        return cls(crew=crew, makify=True, saidive=True)


    @classmethod
    def unblind(cls, said, *, uuid=None, acdc="", states=None,
                raw=None, salt=None, sn=1, tier=None, bound=False, bounds=None):
        """Creates unblinded blinder given said, uuid, acdc said, and states
        list of possible state values

        Returns:
            blinder (Blinder): unblinded blinder when possbile
                               otherwise returns None

        Parameters:
            said (str): qb64 said of blinded blinder
            uuid (str|None): qb64 blinding uuid hierarchically derived from blindable
                        update sn and salty nonce
            acdc (str): qb64 said of associated acdc (trans event acdc)
            states (list[str]|None): list of possible state value string
            raw (bytes|None): random crypto material as salt
                            used to create uuid when provided uuid is None
            salt (str|None): qb64 of 128 bit random salt
                             used to create uuid when provided uuid is None
                             and raw is none
            sn (int): sequence number of blindable update message. Converted to
                      Number.huge which is qb64 (24 char)
                      used to create uuid when provided uuid is None
            tier (str|None): used to create uuid when provided uuid is None
            bound (bool): True means use BoundState
                          False means use BlindState default
            bounds (list[tuple[bsn, bd]]): possible (bsn, bd) pairs to try in
                    computing possible bound blinded state where:
                    bsn (int): possible bound issuee key event sequence number
                    bd (str): bound issuee key event SAID qb64

        Tests possible combinations of empty acdc, provided acdc,  with
        empty state string plus all states strings provided by states to find
        and unblinded blinder that verifies against the provided said and uuid.
        Empty combinations for placeholder blinder
        """
        if uuid is None:  # create uuid from salt and sn
            if salt is None:
                raise InvalidValueError(f"Invalid {salt=}")
            uuid = cls.makeUUID(raw=raw, salt=salt, sn=sn, tier=tier)

        acdcs = [acdc]
        if "" not in acdcs:
            acdcs.append('')
        states = states if states is not None else []
        if "" not in states:
            states.append("")

        if bound:
            bounds = bounds if bounds is not None else [(0, '')]
            if (0, '') not in bounds:
                bounds.append((0, ''))

            for bsn, bd in bounds:
                # bn = f"{bsn:x}"  # numh respects ints now
                for td in acdcs:
                    for ts in states:
                        crew = BoundState(d="", u=uuid, td=td, ts=ts, bn=bsn, bd=bd)
                        blinder = cls(crew=crew, makify=True, saidive=True)
                        if blinder.crew.d == said:
                            return blinder

        else:
            for td in acdcs:
                for ts in states:
                    crew = BlindState(d="", u=uuid, td=td, ts=ts)
                    blinder = cls(crew=crew, makify=True, saidive=True)
                    if blinder.crew.d == said:
                        return blinder
        return None


    def __init__(self, saidive=True, **kwa):
        """Initialize instance

        Inherited Parameters:  (see Structor)
            data (NamedTuple): fields are named primitive instances for .data
                Given data can derive clan, cast, crew, qb64, and qb2
            clan (type[NamedTuple]): provides class reference for generated .data
                when data missing.
            cast (NamedTuple | dict | Iterable): each value provides CESR
                primitive subclass reference used to create primitive instances
                for generating .data. Can be used to infer namedtuple type of
                .data when data and clan missing. Takes precendence over crew.
            crew (NamedTuple | dict | Iterable): each value provides qb64 value
                of primitive for generating .data with .cast when data missing.
                Can be used to infer namedtuple type of .data when data and clan
                missing.
            qb64b (str|bytes|bytearray|None): concatenation of qb64b data values to
                generate .data with data and crew missing.
            qb64 (str|bytes|bytearray|None): alias for qb64b
            qb2 (bytes|bytearray|None): concatenation of qb2 data values to generate
                .data when data and crew and qb64 missing.
            strip (bool): False means do not strip each value from qb64 or qb2.
                Default is False. True means if qb64 or qb2 are bytearray then
                strip contained concatenated data values. Else convert qb64 or
                qb2 to bytearray so can strip inplace. Enables parser to extract
                data fields from front of CESR stream when stream is bytearray.
            makify (bool): True means compute saids when .saidive
                           False means do not comput saids even when .saidive
            verify (bool): True means verify serialization against mad.
                           False means do not verify
            saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
            saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs

        Parameters:


        """
        super(Blinder, self).__init__(saidive=saidive, **kwa)

        if self.clan not in self.Clans:
            raise InvalidValueError("Unrecognized clan={self.clan}")


    @property
    def blid(self):
        """blid property getter (alias of .said)
        Returns:
           blid (str): blid of BlindState CESR .data.d 'd' field
        """
        return self.said


    @property
    def blidb(self):
        """blidb property getter (alias of .saidb)
        Returns:
            blidb (bytes): qb64b blid of BlindState CESR .data.d 'd' field
        """
        return self.saidb


    @property
    def uuid(self):
        """uuid property getter
        Returns:
           uuid (str): uuid of BlindState CESR .data.u 'u' field
        """
        return self.data.u.nonce


    @property
    def uuidb(self):
        """uuidb property getter
        Returns:
            uuidb (bytes): qb64b uuid of BlindState CESR .data.u 'u' field
        """
        return self.data.u.nonceb


    @property
    def acdc(self):
        """acdc property getter
        Returns:
           acdc (str): qb64 transaction acdc said or empty of
                       BlindState CESR .data.td 'td' field
        """
        return self.data.td.nonce


    @property
    def acdcb(self):
        """acdcb property getter
        Returns:
            acdcb (bytes): qb64b transaction acdc said of
                           BlindState CESR .data.td 'td' field
        """
        return self.data.td.nonceb


    @property
    def state(self):
        """state property getter
        Returns:
           state (str):  transaction state string of
                        BlindState CESR .data.ts 'ts' field
        """
        return self.data.ts.text


    @property
    def stateb(self):
        """stateb property getter
        Returns:
            stateb (bytes): transaction state string of
                            BlindState CESR .data.ts 'ts' field
        """
        return self.data.ts.text.encode()


    @property
    def bsn(self):
        """bsn property getter
        Returns:
           bsn (int): bound key state sequence number of issuees key state at
                      time of update
                      BoundState CESR .data.bn 'bn' field
        """
        return self.data.bn.sn if self.clan is BoundState else None


    @property
    def bnh(self):
        """bnh property getter
        Returns:
            bnh (str): bound key state  hex sequence number of issuees key state
                       at time of update
                       BoundState CESR .data.bn 'bn' field
        """
        return self.data.bn.snh if self.clan is BoundState else None

    @property
    def bnhb(self):
        """bnhb property getter
        Returns:
            bnhb (bytes): bound key state hex sequence number of issuees key
                           state at time of update
                           BoundState CESR .data.bn 'bn' field
        """
        return self.data.bn.snh.encode() if self.clan is BoundState else None


    @property
    def bd(self):
        """bd property getter
        Returns:
           bd (str): qb64 bound key state said  of issuee at time of update
                      BoundState CESR .data.bd 'bd' field
        """
        return self.data.bd.nonce if self.clan is BoundState else None


    @property
    def bdb(self):
        """bdb property getter
        Returns:
            bdb (bytes): qb64b bound key state said of issuee at time of update
                          BoundState CESR .data.bd 'bd' field
        """
        return self.data.bd.nonceb if self.clan is BoundState else None


class Mediar(Structor):
    """Mediar is Structor subclass each instance holds a namedtuple .data of
    named values belonging to IANA media type media quadrule with blindable SAID
    (BLID)

    See Structor class for more details.

    Inherited Class Attributes:
        Clans (type[Namedtuple]): each value is known NamedTuple class keyed
            by its own field names (tuple). Enables easy query of its values() to
            find known data types given field names tuple.
        Casts (NamedTuple): each value is primitive class of cast keyed by fields
            names of the associated NamedTuple class in .Clans. Enables finding
            known primitive classes given NamedTuple class of clan or instance
            of cast or crew.
        Names (dict):  maps tuple of clan/cast fields names to its namedtuple
                       class type name so can look up a know clan or cast
                       given a matching tuple
        ClanCodens (dict): map of clan namedtuple to counter code name for
                           ser/des as group
        CodenClans (dict): map of counter code name to clan named tuple for
                           ser/des as group
        Saids (dict):  default saidive fields at top-level. Assumes .mad already
            in most compact form.
            Each key is label of saidive field.
            Each value is default primitive code of said digest value to be
                computed from serialized dummied .mad
        Dummy (str): dummy character for computing SAIDs

    Class Attributes:

    When known casts are provided in .Clans/.Casts then more flexible creation
    is supported for different types of provided cast and crew.
    When no clan is provided and an unknown cast and/or crew are provided as
    Mappings then Structor may create custom clan from the names given by the
    cast and/or crew keys(). Subclasses may override this behavior by raising
    an exception for unknown or custom clans.


    Inherited Properties:
        data (NamedTuple): fields are named instances of CESR primitives
        clan (type[NamedTuple]): class reference of .data's class
        cast (NamedTuple): CESR primitive class references of .data's primitive
                           instances
        crew (NamedTuple): named qb64 values of .data's primitive instances
        qb64 (str): concatenated data values as qb64 str of data's primitives
        qb64b (bytes): concatenated data values as qb64b  of data's primitives
        qb2 (bytes): concatenated data values as qb2 bytes of data's primitives
        saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs
        said (str): qb64 said given .saids given .saids as saidive .data.d.qb64
                      primary said field value if any. None otherwise
                      primary has same label as zeroth item in .saids
        saidb (bytes): qb64b said given .saids as saidive fields .data.d.qb64b

    Properties:
        uuid (str): qb64 uuid of TypeMedia CESR .data.u.qb64 'u' field
        uuidb (bytes): qb64b uuid of TypeMedia CESR .data.u.qb64b 'u' field
        mt (str): media type string TypeMedia  .data.mt.text 'mt' field
        mtb (bytes): media tytpe as bytes TypeMedia .data.mt.text 'mt' field
        mv (str):  media value string TypeMedia .data.mv.text 'mv' field
        mvb (bytes): media value as bytes TypeMedia .data.mv.text  'mv' field

    Methods:


    Hidden:
        _data (namedtuple): named CESR primitive instances
        _cast (namedtuple): named Castage instances
        _saids (dict): default top-level said fields and codes
        _saidive (bool): compute saids or not

    Example:


    """
    Clans = TMClanDom  # known namedtuple clans. Override in subclass with non-empty
    Casts = TMCastDom  # known namedtuple casts. Override in subclass with non-empty
    # Create .Names dict that maps clan/cast fields names to its namedtuple
    # class type name so can look up a know clan or cast given a matching set
    # of either field names from a namedtuple or keys from a dict.
    Names = {tuple(clan._fields): clan.__name__ for clan in Clans}

    # map clan names to counter code for ser/des as counted group
    ClanCodens = dict()
    ClanCodens[TMClanDom.TypeMedia.__name__] = Codens.TypedMediaQuadruples

    # mapcounter code to clan name for ser/des as counted group
    CodenClans = { val: key for key, val in ClanCodens.items()}  # invert dict


    def __init__(self, saidive=True, **kwa):
        """Initialize instance

        Inherited Parameters:  (see Structor)
            data (NamedTuple): fields are named primitive instances for .data
                Given data can derive clan, cast, crew, qb64, and qb2
            clan (type[NamedTuple]): provides class reference for generated .data
                when data missing.
            cast (NamedTuple | dict | Iterable): each value provides CESR
                primitive subclass reference used to create primitive instances
                for generating .data. Can be used to infer namedtuple type of
                .data when data and clan missing. Takes precendence over crew.
            crew (NamedTuple | dict | Iterable): each value provides qb64 value
                of primitive for generating .data with .cast when data missing.
                Can be used to infer namedtuple type of .data when data and clan
                missing.
            qb64b (str|bytes|bytearray|None): concatenation of qb64b data values to
                generate .data with data and crew missing.
            qb64 (str|bytes|bytearray|None): alias for qb64b
            qb2 (bytes|bytearray|None): concatenation of qb2 data values to generate
                .data when data and crew and qb64 missing.
            strip (bool): False means do not strip each value from qb64 or qb2.
                Default is False. True means if qb64 or qb2 are bytearray then
                strip contained concatenated data values. Else convert qb64 or
                qb2 to bytearray so can strip inplace. Enables parser to extract
                data fields from front of CESR stream when stream is bytearray.
            makify (bool): True means compute saids when .saidive
                           False means do not comput saids even when .saidive
            verify (bool): True means verify serialization against mad.
                           False means do not verify
            saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
            saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs

        Parameters:


        """
        super(Mediar, self).__init__(saidive=saidive, **kwa)

        if self.clan not in self.Clans:
            raise InvalidValueError("Unrecognized clan={self.clan}")


    @property
    def uuid(self):
        """uuid property getter
        Returns:
           uuid (str): uuid of TypeMedia CESR .data.u 'u' field
        """
        return self.data.u.nonce


    @property
    def uuidb(self):
        """uuidb property getter
        Returns:
            uuidb (bytes): qb64b uuid of TypeMedia CESR .data.u 'u' field
        """
        return self.data.u.nonceb


    @property
    def mt(self):
        """mt property getter
        Returns:
           mt (str): media type string TypeMedia  .data.mt.text 'mt' field
        """
        return self.data.mt.text


    @property
    def mtb(self):
        """mtb property getter
        Returns:
            mtb (bytes): media type as  bytes TypeMedia .data.mt.text 'mt' field
        """
        return self.data.mt.text.encode()


    @property
    def mv(self):
        """mv property getter
        Returns:
           mv (str): media value string TypeMedia .data.mv.text 'mv' field
        """
        return self.data.mv.text


    @property
    def mvb(self):
        """mvb property getter
        Returns:
            mvb (bytes): media value as bytes TypeMedia .data.mv.text 'mv' field
        """
        return self.data.mv.text.encode()
