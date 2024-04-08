# -*- coding: utf-8 -*-
"""
keri.core.indexing module

Provides versioning support for Indexer classes and codes
"""


from typing import NamedTuple
from collections import namedtuple
from collections.abc import Mapping

from ..kering import (EmptyMaterialError, InvalidValueError,)

from .. import help
from ..help import nonStringSequence

from . import coring
from .coring import (Matter, )


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

# Event Seal: triple (i, s, d)
# i = pre is qb64 of identifier prefix of KEL for event,
# s = sn of event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of event
SealEvent = namedtuple("SealEvent", 'i s d')

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

# State Establishment Event (latest current) : quadruple (s, d, br, ba)
# s = sn of latest est event as lowercase hex string  no leading zeros,
# d = SAID digest qb64  of latest establishment event
# br = backer (witness) remove list (cuts) from latest est event
# ba = backer (witness) add list (adds) from latest est event
StateEstEvent = namedtuple("StateEstEvent", 's d br ba')



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
        cast (NamedTuple): CESR primitive class references of .data's primitive
                           instances
        qb64 (str): concatenated data values as qb64 str of data's primitives
        qb64b (bytes): concatenated data values as qb64b  of data's primitives
        qb2 (bytes): concatenated data values as qb2 bytes of data's primitives


    Methods:


    Hidden:
        _data (NamedTuple): named CESR primitive instances


    if not nonStringIterable(val):  # not iterable
        val = (val, )  # make iterable
    return (b''.join(obj.qb64b for obj in val))


    if not isinstance(val, bytearray):  # is memoryview or bytes
        val = bytearray(val)  # convert so may strip
    return tuple(klas(qb64b=val, strip=True) for klas in self.klas)

    >>> T = namedtuple("a_b_c", ["a", "b", "c"])
    >>> T
        <class '__main__.a_b_c'>



    """
    Clans = {}  # each value is known namedtuple class keyed by own fields (tuple)
    Casts = {}  # each value is cast primitive class for its .Clans keyed by fields


    def __init__(self, data=None, clan=None, cast=None, crew=None,
                 qb64=None, qb2=None, strip=False):
        """Initialize instance

        Parameters:
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


        from collections import namedtuple
        T = namedtuple("Test", "a b c")
        issubclass(T, tuple)
        True
        hasattr(T, "_fields")
        True
        T._fields
        ('a', 'b', 'c')
        T.__name__
        'Test'
        t = T(a=1, b=2, c=3)
        t
        Test(a=1, b=2, c=3)
        t.__class__
        <class '__main__.Test'>
        issubclass(t.__class__, T)
        True


        Test for namedtuple subclass

        issubclass(T, tuple) and hasattr(T, "_fields")
        T._feilds

        def FuncA(arg: type[CustomClass]):

        """
        if data:
            if not (isinstance(data, tuple) and hasattr(data, "_fields")):
                raise InvalidValueError(f"Not namedtuple subclass {data=}.")

            for val in data:  # check for primitive interface
                if not (hasattr(val, "qb64") and hasattr(val, "qb2")):
                    raise InvalidValueError(f"Non-primitive data member={val}.")


        else:
            if not clan:  # attempt to get from cast and/or crew
                if cast and isinstance(cast, tuple) and hasattr(cast, "_fields"):
                    clan = cast.__class__

                if not clan and crew:
                    if isinstance(crew, tuple) and hasattr(crew, "_fields"):
                        clan = crew.__class__

                if not clan and isinstance(cast, Mapping):  # get clan from cast
                    names = tuple(cast)  # create custom clan based on cast
                    if names in self.Clans:  # get known clan and cast
                        clan = self.Clans[names]
                        cast = self.Casts[names]  # same keys as self.Clans

                    else:  # create custom clan from cast
                        clan = namedtuple("_".join(names), names)  # custom clan from cast keys
                        cast = clan(**cast)  # convert to clan

                if not clan and isinstance(crew, Mapping):  # get clan from crew
                    names = tuple(crew)  # create custom clan based on cast
                    if names in self.Clans:  # get known clan and cast
                        clan = self.Clans[names]
                        crew = clan(**crew)  # convert to clan

                    else:  # create custom clan from crew
                        clan = namedtuple("_".join(names), names)  # custom clan from cast keys
                        crew = clan(**crew)  # convert to clan

            if clan:
                if not (issubclass(clan, tuple) and hasattr(clan, "_fields")):
                    raise InvalidValueError(f"Not namedtuple subclass {clan=}.")
            else:
                raise InvalidValueError(f"Missing or unobtainable clan.")

            # have clan but may not have cast
            if cast:
                if isinstance(cast, tuple) and hasattr(cast, "_fields"):
                    if cast._fields != clan._fields:
                        raise InvalidValueError(f"Mismatching fields clan="
                                                f"{clan._fields} and cast="
                                                f"{cast._fields}.")

                    if not isinstance(cast, clan):
                        cast = clan(**cast._asdict())  # convert to clan

                elif isinstance(cast, Mapping):
                    if tuple(cast) != clan._fields:
                        raise InvalidValueError(f"Mismatching fields clan="
                                                f"{clan._fields} and keys cast="
                                                f"{tuple(cast)}.")

                    cast = clan(**cast)  # convert to clan

                elif isinstance(cast, nonStringSequence):
                    cast = clan(*cast)  # convert to clan assumes elements in correct order

                else:
                    raise InvalidValueError(f"Invalid {cast=}.")

            else:  # get cast from .Casts if possible
                if clan._fields in self.Casts:  # same keys for self.Clans
                    cast = self.Casts[clan._fields]  # get known cast
                else:  # cast missing or unobtainable
                    raise InvalidValueError(f"Missing or unobtainable "
                                            f"{cast=}.")
            # have cast now
            for klas in cast:
                if not (hasattr(klas, "qb64") and hasattr(klas, "qb2")):
                    raise InvalidValueError(f"Cast member {klas=} not CESR"
                                            " Primitive.")

            # have clan and cast but may not have crew
            if crew:
                if isinstance(crew, tuple) and hasattr(crew, "_fields"):
                    if crew._fields != clan._fields:
                        raise InvalidValueError(f"Mismatching fields clan="
                                                f"{clan._fields} and crew="
                                                f"{crew._fields}.")

                    if not isinstance(crew, clan):
                        crew = clan(**crew._asdict())  # convert to clan

                elif isinstance(crew, Mapping):
                    if tuple(crew) != clan._fields:
                        raise InvalidValueError(f"Mismatching fields clan="
                                                f"{clan._fields} and keys crew="
                                                f"{tuple(crew)}.")

                    crew = clan(**crew)  # convert to clan

                elif isinstance(crew, nonStringSequence):
                    crew = clan(*crew)  # convert to clan assumes elements in correct order

                else:
                    raise InvalidValueError(f"Invalid {crew=}.")

                data = clan(*(klas(qb64=val) for klas, val in zip(cast, crew)))

            elif qb64:
                if hasattr(qb64, "encode"):
                    qb64 = qb64.encode()




                # if strip then make bytearray if not and strip

                if not isinstance(qb64, bytearray):
                    qb64 = bytearray(qb64)

                data = clan(*(klas(qb64=qb64, strip=strip) for klas in cast))

                # if not strip then must count and offset qb64
                #data = clan(*(klas(qb64=qb64, strip=strip) for klas in cast))

            elif qb2:
                if not isinstance(qb2, bytearray):
                    qb64 = bytearray(qb2)

                data = clan(*(klas(qb2=qb2, strip=strip) for klas in cast))

            else:
                raise EmptyMaterialError("Need crew or qb64 or qb2.")

        self._data = data


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
    def cast(self):
        """Return:
            cast (NamedTuple): named primitive classes in .data

        """
        return self.clan(*(val.__class__ for val in self.data))


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
    """Sealer is Structor subclass that holds a KERI namedtuple representation
    of a KERI seal where its values are CESR primitive instances.

    Its primitives can be serialized and deserialized as a concatenation of
    their qb64 or qb2 representations.
    A Structor can also construct a dict version of its .fields suitable for
    serialization by using each field name as item key and each named value's
    qb64 as item value. Structor may have only one field.

    Has the following public properties:

    Properties:


    Methods:


    Hidden:



    """

    def __init__(self, fields):
        """Initialize instance


        Parameters:
            stream (bytes | bytearray): sniffable CESR stream


        """
        self._stream = bytes(stream)


    @property
    def qb64(self):
        """
        """
        return

    @property
    def qb2(self):
        """

        """
        return

    @property
    def asdict(self):
        """

        """
        return
