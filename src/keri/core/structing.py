# -*- coding: utf-8 -*-
"""
keri.core.indexing module

Provides versioning support for Indexer classes and codes
"""
from collections import namedtuple


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

# Last Estalishment Event Seal: uniple (i,)
# i = pre is qb64 of identifier prefix of KEL from which to get last est, event
# used to indicate to get the latest keys available from KEL for 'i'
SealLast = namedtuple("SealLast", 'i')

# State Establishment Event (latest current) : quadruple (s, d, br, ba)
# s = sn of latest est event as lowercase hex string  no leading zeros,
# d = SAID digest qb64  of latest establishment event
# br = backer (witness) remove list (cuts) from latest est event
# ba = backer (witness) add list (adds) from latest est event
StateEstEvent = namedtuple("StateEstEvent", 's d br ba')

# Transaction Event Seal for Transaction Event: duple (s, d)
# s = sn of transaction event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of transaction event
# the pre is provided in the 'i' field  qb64 of identifier prefix of KEL
# key event that this seal appears.
# use SealSourceCouples count code for attachment
SealTrans = namedtuple("SealTrans", 's d')


class Structor:
    """Structor class holds a namedtuple .fields whose values are  primitive
    (Matter subclass) instances.
    These instances can be serialized and deserialized as a concatenation of
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


class Sealer(Structor):
    """Sealer is Structor subclass that holds a KERI namedtuple representation
    of a KERI seal where its values are primitive (Matter subclass) instances.

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
