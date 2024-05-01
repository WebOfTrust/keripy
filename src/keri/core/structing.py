# -*- coding: utf-8 -*-
"""
keri.core.indexing module

Provides versioning support for Indexer classes and codes
"""


from typing import NamedTuple
from collections import namedtuple
from collections.abc import Mapping
from dataclasses import dataclass, astuple, asdict

from ..kering import (EmptyMaterialError, InvalidValueError,)

from .. import help
from ..help import nonStringSequence

from . import coring
from .coring import (MapDom, Matter, Diger, Prefixer, Number)



# ToDo Change seal namedtuple definitions to NamedTuple subclasses so can
# use typehints on field values which type hints are the primitive types. Use
# union | on type hints to allow qb64, qb2, primitive instance, primitive class
# as acceptable values  This provides more clarity in documentation. Actually
# enforcing types is harder with union | but can still be accomplished.

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
SealDigest = namedtuple("SealDigest", 'd')

# Root Seal: uniple (rd,)
# rd = Merkle tree root digest qb64 digest of anchored (sealed) data in Merkle tree
SealRoot = namedtuple("SealRoot", 'rd')

# Backer Seal: couple (bi, d)
# bi = pre qb64 backer nontrans identifier prefix
# d = digest qb64 of backer metadata anchored to event usually SAID of data
SealBacker = namedtuple("SealBacker", 'bi d')

# Last Establishment Event Seal: uniple (i,)
# i = pre is qb64 of identifier prefix of KEL from which to get last est, event
# used to indicate to get the latest keys available from KEL for 'i'
SealLast = namedtuple("SealLast", 'i')

# Transaction Event Seal for Transaction Event: duple (s, d)
# s = sn of transaction event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of transaction event
# the pre is provided in the 'i' field  qb64 of identifier prefix of KEL
# key event that this seal appears.
# use SealSourceCouples count code for attachment
SealTrans = namedtuple("SealTrans", 's d')

# Event Seal: triple (i, s, d)
# i = pre is qb64 of identifier prefix of KEL for event,
# s = sn of event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of event
SealEvent = namedtuple("SealEvent", 'i s d')


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


# Cast conversion: duple (c, k)
# kls = primitive class reference in order to cast as appropriate
#       namedtuple with values as primitive classes
# prm = primitive __init__ keyword parameter name to use when casting
#        default None. When default then use qb64 or qb64b as appropriate.
Castage = namedtuple('Castage', "kls prm", defaults=(None, ))


@dataclass(frozen=True)
class EmptyClanDom(MapDom):
    """
    SealClanDom is dataclass of namedtuple seal class references (clans) each
    indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get class reference with item syntax using
    name variables.

    Example: EmptyClanDex[name]
    """

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

EClanDom = EmptyClanDom()  # create instance


@dataclass(frozen=True)
class EmptyCastDom(MapDom):
    """
    SealCastCodex is dataclass of namedtuple instances (seal casts) whose values
    are named primitive class references

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get namedtuple instance with item syntax using
    name variables.

    Example: EmptyCastDex[name]
    """

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

ECastDom = EmptyCastDom()  # create instance


@dataclass(frozen=True)
class SealClanDom(MapDom):
    """
    SealClanDom is dataclass of namedtuple seal class references (clans) each
    indexed by its class name.

    Only provide defined classes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get class reference with item syntax using
    name variables.

    Example: ClanDom[name]
    """
    SealDigest: type[NamedTuple] = SealDigest  # SealDigest class reference
    SealRoot: type[NamedTuple] = SealRoot  # SealRoot class reference
    SealBacker: type[NamedTuple] = SealBacker  # SealBacker class reference
    SealLast: type[NamedTuple] = SealLast  # SealLast class reference single
    SealTrans: type[NamedTuple] = SealTrans  # SealTrans class reference couple
    SealEvent: type[NamedTuple] = SealEvent  # SealEvent class reference triple

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SClanDom = SealClanDom()  # create instance




@dataclass(frozen=True)
class SealCastDom(MapDom):
    """
    SealCastDom is dataclass of namedtuple instances (seal casts) whose values
    are named primitive class references

    indexed by its namedtuple class name.

    Only provide defined namedtuples casts.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get namedtuple instance with item syntax using
    name variables.

    Example: CastDom[name]
    """
    SealDigest: NamedTuple = SealDigest(d=Castage(Diger))  # SealDigest class reference
    SealRoot: NamedTuple = SealRoot(rd=Castage(Diger))  # SealRoot class reference
    SealBacker: NamedTuple = SealBacker(bi=Castage(Prefixer),
                                        d=Castage(Diger))  # SealBacker class reference
    SealLast: NamedTuple = SealLast(i=Castage(Prefixer))  # SealLast class reference single
    SealTrans: NamedTuple = SealTrans(s=Castage(Number, 'numh'),
                                      d=Castage(Diger))  # SealTrans class reference couple
    SealEvent: NamedTuple = SealEvent(i=Castage(Prefixer),
                                      s=Castage(Number, 'numh'),
                                      d=Castage(Diger))  # SealEvent class reference triple

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SCastDom = SealCastDom()  # create instance



class Structor:
    """Structor class each instance holds a namedtuple .data of named values.
    Each value is a primitive instance of CESR primitive subclass that supports
    text (ab64) and binary (qb2) domains.
    Structor instances can be serialized to or deserialized from concatenation
    of the qb64 or qb2 representations of the data values. Creation requires
    input of a ordered named classes for creating the named instances from the
    input data. Smart data format input are supported to accomodate the many ways
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

    When known casts or provided in .Clans/.Casts then more flexible creation
    is supported for different types of provided cast and crew.
    When no clan is provided and an unknown cast and/or crew are provided as
    Mappings then Structor may create custom clan from the names given by the
    cast and/or crew keys(). Subclasses may override this behavior by raising
    an exception for unknown or custom clans.


    Properties:
        data (NamedTuple): fields are named instances of CESR primitives
        clan (type[NamedTuple]): class reference of .data's class
        cast (NamedTuple | None): values are Castage instances that each provide
                    CESR primitive class references and primitive init parameter
                    used to .data's primitive instances.
        crew (NamedTuple): named qb64 values of .data's primitive instances
        qb64 (str): concatenated data values as qb64 str of data's primitives
        qb64b (bytes): concatenated data values as qb64b  of data's primitives
        qb2 (bytes): concatenated data values as qb2 bytes of data's primitives


    Methods:


    Hidden:
        _data (NamedTuple): named CESR primitive instances


    """
    Clans = EClanDom  # known namedtuple clans. Override in subclass with non-empty
    Casts = ECastDom  # known namedtuple casts. Override in subclass with non-empty
    # Create .Names dict that maps tuple of clan/cast fields names to its namedtuple
    # class type name so can look up a know clan or cast given a matching tuple
    # of either field names from a namedtuple or keys from a dict. The tuple of
    # field names is a mark of the structor type. Maps mark to class name.
    Names = {tuple(clan._fields): clan.__name__ for clan in Clans}


    def __init__(self, data=None, *, clan=None, cast=None, crew=None,
                 qb64=None, qb2=None, strip=False):
        """Initialize instance

        Parameters:
            data (NamedTuple | None): fields are named primitive instances for .data
                Given data can derive clan, cast, crew, qb64, and qb2
            clan (type[NamedTuple]): provides class reference for generated .data
                when data missing.
            cast (NamedTuple | dict | Iterable | None):  values are Castage
                    instances that each provide CESR primitive class references
                    and primitive init parameter used to .data's primitive
                    instances. None means .data provided directly not generated
                    from cast
            each value provides CESR
                primitive subclass reference used to create primitive instances
                for generating .data. Can be used to infer namedtuple type of
                .data when data and clan missing. Takes precendence over crew.
            crew (NamedTuple | dict | Iterable | None): each value provides qb64 value
                of primitive for generating .data with .cast when data missing.
                Can be used to infer namedtuple type of .data when data and clan
                missing.
            qb64 (str | bytes | bytearray | None): concatenation of qb64 data values to
                generate .data with data and crew missing.
            qb2 (bytes | bytearray | None): concatenation of qb2 data values to generate
                .data when data and crew and qb64 missing.
            strip (bool): False means do not strip each value from qb64 or qb2.
                            Default is False.
                          True means if qb64 or qb2 are bytearray then strip
                            contained concatenated data values. Enables parser
                            to extract data fields from front of CESR stream.


        """
        if data:
            if not (isinstance(data, tuple) and hasattr(data, "_fields")):
                raise InvalidValueError(f"Not namedtuple subclass {data=}.")

            for pi in data:  # check for primitive interface
                if not (hasattr(pi, "qb64") and hasattr(pi, "qb2")):
                    raise InvalidValueError(f"Non-primitive data member={pi}.")

            cast = None  # ensure cast is None since not used to generate data


        else:
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

                    elif isinstance(cast, nonStringSequence):
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
                if not (hasattr(cstg.kls, "qb64") and hasattr(cstg.kls, "qb2")):
                    raise InvalidValueError(f"Cast member {cstg.kls=} not CESR"
                                            " Primitive.")

            # have clan and cast but may not have crew
            if crew:
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

                    elif isinstance(crew, nonStringSequence):
                        crew = clan(*crew)  # convert to clan assumes elements in correct order

                    else:
                        raise InvalidValueError(f"Invalid {crew=}.")

                data = clan(*(cstg.kls(**{cstg.prm if cstg.prm is not None else 'qb64': val})
                              for cstg, val in zip(cast, crew)))
                # data = clan(*(klas(qb64=val) for klas, val in zip(cast, crew)))

            elif qb64:
                if hasattr(qb64, "encode"):
                    qb64 = qb64.encode()

                if strip:
                    if not isinstance(qb64, bytearray):
                        qb64 = bytearray(qb64)

                    data = clan(*(cstg.kls(qb64b=qb64, strip=strip) for cstg in cast))

                else:
                    o = 0  # offset into memoryview of qb64
                    pis = []  # primitive instances
                    mv = memoryview(qb64)
                    for cstg in cast:  # Castage
                        pi = cstg.kls(qb64b=mv[o:])
                        pis.append(pi)
                        o += len(pi.qb64b)
                    data = clan(*pis)

            elif qb2:
                if strip:
                    if not isinstance(qb2, bytearray):
                        qb2 = bytearray(qb2)

                    data = clan(*(cstg.kls(qb2=qb2, strip=strip) for cstg in cast))

                else:
                    o = 0  # offset into memoryview of qb2
                    pis = []  # primitive instances
                    mv = memoryview(qb2)
                    for cstg in cast:  # Castage
                        pi = cstg.kls(qb2=mv[o:])
                        pis.append(pi)
                        o += len(pi.qb2)
                    data = clan(*pis)

            else:
                raise EmptyMaterialError("Need crew or qb64 or qb2.")


        self._data = data
        self._cast = (cast if cast is not None else
                      self.clan(*(Castage(val.__class__) for val in self.data)))




    @property
    def data(self):
        """Returns:
            data (NamedTuple): ._data namedtuple of primitive instances

        Getter for ._data makes it read only
        """
        return self._data


    @property
    def clan(self):
        """Returns:
              clan (type[NamedTuple]): class of .data

        """
        return self.data.__class__

    @property
    def name(self):
        """Returns:
              name (str): name of class of .data

        """
        return self.data.__class__.__name__

    @property
    def cast(self):
        """Return:
            cast (NamedTuple): named primitive classes in .data

        Getter for ._cast makes it read only when not None
        """
        return self._cast

    @property
    def crew(self):
        """Return:
            crew (NamedTuple): named qb64 field values from .data

        """
        return (self.clan(*(getattr(val, cstg.prm if cstg.prm is not None else "qb64")
                    for cstg, val in zip(self.cast, self.data))))
        # return self.clan(*(val.qb64 for val in self.data))


    @property
    def asdict(self):
        """Returns:
            map (dict): .data as a dictionary

        """
        return self.data._asdict()


    @property
    def qb64(self):
        """Returns:
              qb64 (str): concatenated qb64 of each primitive in .data
        """
        return (''.join(val.qb64 for val in self.data))


    @property
    def qb64b(self):
        """Returns:
              qb64b (bytes): concatenated qb64b of each primitive in .data
        """
        return (b''.join(val.qb64b for val in self.data))


    @property
    def qb2(self):
        """Returns:
              qb2 (bytes): concatenated qb2 of each primitive in .data

        """
        return (b''.join(val.qb2 for val in self.data))




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

    When known casts or provided in .Clans/.Casts then more flexible creation
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


    Methods:


    Hidden:
        _data (NamedTuple): named CESR primitive instances


    """
    Clans = SClanDom  # known namedtuple clans. Override in subclass with non-empty
    Casts = SCastDom  # known namedtuple casts. Override in subclass with non-empty
    # Create .Names dict that maps clan/cast fields names to its namedtuple
    # class type name so can look up a know clan or cast given a matching set
    # of either field names from a namedtuple or keys from a dict.
    Names = {tuple(clan._fields): clan.__name__ for clan in Clans}


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
