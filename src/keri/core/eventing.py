# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""
import datetime
import json
import logging
from collections import namedtuple, deque
from dataclasses import dataclass, astuple
from math import ceil

from orderedset import OrderedSet as oset

from hio.help import decking

from .. import help
from ..help import helping
from .coring import (Versify, Serials, Ilks, MtrDex, NonTransDex, CtrDex, Counter,
                     Seqner, Siger, Cigar, Dater,
                     Verfer, Diger, Nexter, Prefixer, Serder, Tholder)
from ..db import basing
from ..db.dbing import dgKey, snKey, fnKey, splitKeySN

from ..kering import (MissingEntryError,
                      ExtractionError, ShortageError, ColdStartError,
                      SizedGroupError, UnexpectedCountCodeError,
                      ValidationError, MissingSignatureError,
                      MissingWitnessSignatureError,
                      MissingDelegationError, OutOfOrderError,
                      LikelyDuplicitousError, UnverifiedWitnessReceiptError,
                      UnverifiedReceiptError, UnverifiedTransferableReceiptError)
from ..kering import Version

logger = help.ogler.getLogger()

EscrowTimeoutPS = 3600  # seconds for partial signed escrow timeout

ICP_LABELS = ["v", "i", "s", "t", "kt", "k", "n",
              "bt", "b", "c",  "a"]
DIP_LABELS = ["v", "i", "s", "t", "kt", "k", "n",
              "bt", "b", "c", "a", "di"]
ROT_LABELS = ["v", "i", "s", "t", "p", "kt", "k", "n",
              "bt", "br", "ba", "a"]
DRT_LABELS = ["v", "i", "s", "t", "p", "kt", "k", "n",
              "bt", "br", "ba", "a"]
IXN_LABELS = ["v", "i", "s", "t", "p", "a"]

KSN_LABELS = ["v", "i", "s", "t", "p", "d", "f", "dt", "et", "kt", "k", "n",
              "bt", "b", "c", "ee", "di", "r"]


@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    EstOnly:         str = 'EO'  #  Only allow establishment events
    DoNotDelegate:   str = 'DND'  #  Dot not allow delegated identifiers
    NoBackers:       str = 'NB'  # Do not allow any backers for registry

    def __iter__(self):
        return iter(astuple(self))

TraitDex = TraitCodex()  # Make instance

# Location of last establishment key event: sn is int, dig is qb64 digest
LastEstLoc = namedtuple("LastEstLoc", 's d')

#  for the following Seal namedtuples use the ._asdict() method to convert to dict
#  when using in events

# Digest Seal: dig is qb64 digest of data
SealDigest = namedtuple("SealDigest", 'd')

# Root Seal: root is qb64 digest that is merkle tree root of data tree
SealRoot = namedtuple("SealRoot", 'rd')

# Event Seal: triple (i,s , d)
# i = pre is qb64 of identifier prefix of KEL for event,
# s = sn of event as lowercase hex string  no leading zeros,
# d = dig is qb64 digest of event
SealEvent = namedtuple("SealEvent", 'i s d')

# Event Location Seal:
# i = pre is qb64 of identifier prefix of KEL,
# s = sn of event as lowercase hex string  no leading zeros,
# t = message type ilk is str,
# p = prior digest dig is qb64 of prior event digest
SealLocation = namedtuple("SealLocation", 'i s t p')

# Source Seal: couple (s,d)
# s = sn of event as lowercase hex string  no leading zeros,
# d = dig is qb64 digest of source event (delegator or issuer)
SealSource = namedtuple("SealSource", 's d')

# State Latest (current) Event:
# s = sn of latest event as lowercase hex string  no leading zeros,
# t = message type of latest event (ilk)
# d = digest of latest event
StateEvent = namedtuple("StateEvent", 's t d')

# State Latest Establishment Event:
# s = sn of latest est event as lowercase hex string  no leading zeros,
# d = digest of latest establishment event
# wr = witness remove list (cuts) from latest est event
# wa = witness add list (adds) from latest est event
StateEstEvent = namedtuple("StateEstEvent", 's d br ba')


@dataclass(frozen=True)
class ColdCodex:
    """
    ColdCodex is codex of cold stream start tritets of first byte
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    First three bits:
        0o0 = 000 free
        0o1 = 001 cntcode B64
        0o2 = 010 opcode B64
        0o3 = 011 json
        0o4 = 100 mgpk
        0o5 = 101 cbor
        0o6 = 110 mgpk
        007 = 111 cntcode or opcode B2

    status is one of ('evt', 'txt', 'bny' )
    'evt' if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2)
    'txt' if tritet in (ColdDex.CtB64, ColdDex.OpB64)
    'bny' if tritet in (ColdDex.CtOpB2,)

    otherwise raise ColdStartError

    x = bytearray([0x2d, 0x5f])
    x == bytearray(b'-_')
    x[0] >> 5 == 0o1
    True
    """
    Free:      int = 0o0  # not taken
    CtB64:     int = 0o1  # CountCode Base64
    OpB64:     int = 0o2  # OpCode Base64
    JSON:      int = 0o3  # JSON Map Event Start
    MGPK1:     int = 0o4  # MGPK Fixed Map Event Start
    CBOR:      int = 0o5  # CBOR Map Event Start
    MGPK2:     int = 0o6  # MGPK Big 16 or 32 Map Event Start
    CtOpB2:    int = 0o7  # CountCode or OpCode Base2

    def __iter__(self):
        return iter(astuple(self))

ColdDex = ColdCodex()  # Make instance

Coldage = namedtuple("Coldage", 'msg txt bny')  # stream cold start status
Colds = Coldage(msg='msg', txt='txt', bny='bny')

# Future make Cues dataclasses  instead of dicts. Dataclasses so may be converted
# to/from dicts easily  example: dict(kin="receipt", serder=serder)


def validateSN(sn, inceptive=False):
    """
    Returns int of sn, raises ValueError if invalid sn

    Parameters:
       sn is hex char sequence number of event or seal in an event
    """
    if len(sn) > 32:
        raise ValueError("Invalid sn = {} too large."
                              "".format(sn))
    try:
        sn = int(sn, 16)
    except Exception as ex:
        raise ValueError("Invalid sn = {}.".format(sn))

    if inceptive is not None:
        if inceptive:
            if sn != 0:
                raise ValidationError("Nonzero sn = {} for inception evt."
                                      "".format(sn))
        else:
            if sn < 1:
                raise ValidationError("Zero or less sn = {} for non-inception evt."
                                      "".format(sn))
    else:
        if sn < 0:
            raise ValidationError("Negative sn = {} for event.".format(sn))

    return sn


def simple(n):
    """
    Returns int as simple majority of n when n >=1
        otherwise returns 0
    Parameters:
        n is int total number of elements
    """
    return min(max(0, n), (max(0, n)//2)+1)


def ample(n, f=None, weak=True):
    """
    Returns int as sufficient immune (ample) majority of n when n >=1
        otherwise returns 0
    Parameters:
        n is int total number of elements
        f is int optional fault number
        weak is Boolean
            If f is not None and
                weak is True then minimize m for f
                weak is False then maximize m for f that satisfies n >= 3*f+1
            Else
                weak is True then find maximum f and minimize m
                weak is False then find maximum f and maximize m

        n,m,f are subject to
        f >= 1 if n > 0
        n >= 3*f+1
        (n+f+1)/2 <= m <= n-f
    """
    n = max(0, n)  # no negatives
    if f is None:
        f1 = max(1, max(0, n-1)//3)  # least floor f subject to n >= 3*f+1
        f2 = max(1, ceil(max(0, n-1)/3))  # most ceil f subject to n >= 3*f+1
        if weak:  # try both fs to see which one has lowest m
            return min(n, ceil((n+f1+1)/2), ceil((n+f2+1)/2))
        else:
            return min(n, max(0, n-f1, ceil((n+f1+1)/2)))
    else:
        f = max(0, f)
        m1 = ceil((n+f+1)/2)
        m2 = max(0, n - f)
        if m2 < m1 and n > 0:
            raise ValueError("Invalid f={} is too big for n={}.".format(f, n))
        if weak:
            return min(n, m1, m2)
        else:
            return min(n, max(m1, m2))


# Utility functions for extracting groups of primitives
# bytearray of memoryview makes a copy so does not delete underlying data
# behind memory view but del on bytearray itself does delete bytearray

def deWitnessCouple(data, strip=False):
    """
    Returns tuple of (diger, wiger) extracted from bytes or bytearray
    that hold concatenated data couple where:
        diger is Diger instance
        wiger is Siger instance
    Couple is dig+wig  where:
        dig is receipted event digest
        wig is indexed signature made with key pair derived from witness nontrans
            identifier prefix from witness list. Index is offset into witness
            list of latest establishment event for receipted event.

    Parameters:
        data is couple of bytes concatenation of dig+wig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream

    Witness couple is used for escrows of unverified witness recipts signed by
    nontransferable witness prefix keys with indexed signatures where index
    is offset into associated witness list. At time of escrow receipted event
    may not be in KEL so need the dig to look up event and then look up witness
    list from key state.


    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes

    diger = Diger(qb64b=data, strip=strip)
    if not strip:
        data = data[len(diger.qb64b):]
    wiger = Siger(qb64b=data, strip=strip)
    return (diger, wiger)


def deReceiptCouple(data, strip=False):
    """
    Returns tuple of (prefixer, cigar) from concatenated bytes or bytearray
    of data couple made up of qb64 or qb64b versions of pre+cig where:
       pre is nontransferable identifier prefix of receiptor
       cig is nonindexed signature made with key pair derived from pre
    Couple is used for receipts signed by nontransferable prefix keys

    Parameters:
        data is couple of bytes concatenation of pre+sig from receipt
        strip is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
            Raises error if not bytearray
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes

    prefixer = Prefixer(qb64b=data, strip=strip)
    if not strip:
        data = data[len(prefixer.qb64b):]
    cigar = Cigar(qb64b=data, strip=strip)
    return (prefixer, cigar)


def deSourceCouple(data, strip=False):
    """
    Returns tuple of (seqner, diger) from concatenated bytes or bytearray
    of data couple made up of qb64 or qb64b versions of snu+dig where:
       snu is sn of delegator/issuer source event
       dig is digest of delegator/issuer source event
    Couple is used for delegated/issued event attachment of delegator/issuer evt

    Parameters:
        data is couple of bytes concatenation of pre+sig from receipt
        strip is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
            Raises error if not bytearray
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes

    seqner = Seqner(qb64b=data, strip=strip)
    if not strip:
        data = data[len(seqner.qb64b):]
    diger = Diger(qb64b=data, strip=strip)
    return (seqner, diger)



def deReceiptTriple(data, strip=False):
    """
    Returns tuple of (diger, prefixer, cigar) from concatenated bytes or bytearray
    of data triple made up of qb64 or qb64b versions of dig+pre+cig where:
        dig is receipted event digest
        pre is nontransferable identifier prefix of receiptor
        cig is nonindexed signature made with key pair derived from pre

    Triple is used for escrows of unverified receipts signed by nontransferable
    prefix keys

    Parameters:
        data is triple of bytes concatenation of dig+pre+cig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes

    diger = Diger(qb64b=data, strip=strip)
    if not strip:
        data = data[len(diger.qb64b):]
    prefixer = Prefixer(qb64b=data, strip=strip)
    if not strip:
        data = data[len(prefixer.qb64b):]
    cigar = Cigar(qb64b=data, strip=strip)
    return (diger, prefixer, cigar)


def deTransReceiptQuadruple(data, strip=False):
    """
    Returns tuple (quadruple) of (prefixer, seqner, diger, siger) from
    concatenated bytes or bytearray of quadruple made up of qb64 or qb64b
    versions of spre+ssnu+sdig+sig.
    Quadruple is used for receipts signed by transferable prefix keys

    Parameters:
        quadruple is bytes concatenation of pre+snu+dig+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes

    prefixer = Prefixer(qb64b=data, strip=strip)
    if not strip:
        data = data[len(prefixer.qb64b):]
    seqner = Seqner(qb64b=data, strip=strip)
    if not strip:
        data = data[len(seqner.qb64b):]
    diger = Diger(qb64b=data, strip=strip)
    if not strip:
        data = data[len(diger.qb64b):]
    siger = Siger(qb64b=data, strip=strip)
    return (prefixer, seqner, diger, siger)


def deTransReceiptQuintuple(data, strip=False):
    """
    Returns tuple of (ediger, seal prefixer, seal seqner, seal diger, siger)
    from concatenated bytes or bytearray of quintuple made up of qb64 or qb64b
    versions of quntipuple given by  concatenation of  edig+spre+ssnu+sdig+sig.
    Quintuple is used for unverified escrows of validator receipts signed
    by transferable prefix keys

    Parameters:
        quintuple is bytes concatenation of edig+spre+ssnu+sdig+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes


    ediger = Diger(qb64b=data, strip=strip)  #  diger of receipted event
    if not strip:
        data = data[len(ediger.qb64b):]
    sprefixer = Prefixer(qb64b=data, strip=strip)  # prefixer of recipter
    if not strip:
        data = data[len(sprefixer.qb64b):]
    sseqner = Seqner(qb64b=data, strip=strip)  # seqnumber of receipting event
    if not strip:
        data = data[len(sseqner.qb64b):]
    sdiger = Diger(qb64b=data, strip=strip)  # diger of receipting event
    if not strip:
        data = data[len(sdiger.qb64b):]
    siger = Siger(qb64b=data, strip=strip)  #  indexed siger of event
    return (ediger, sprefixer, sseqner, sdiger, siger)


def verifySigs(serder, sigers, verfers):
    """
    Returns tuple of (vsigers, vindices) where:
        vsigers is list  of unique verified sigers with assigned verfer
        vindices is list of indices from those verified sigers

    The returned vsigers  and vindices may be used for threshold validation

    Assigns appropriate verfer from verfers to each siger based on siger index
    If no signatures verify then sigers and indices are empty

    Parameters:
        serder is Serder of signed event
        sigers is list of indexed Siger instances (signatures)
        verfers is list of Verfer instance (public keys)

    """
    if sigers is None:
        sigers = []
    # Ensure no duplicate sigers by using set math on sigers' sigs otherwise
    # indices count for threshold will be erroneous. Does not modify in place
    # passed in sigers list, but instead depends on caller to use indices to
    # modify its copy to filter out unverifiable or duplicate sigers
    usigs = oset([siger.qb64 for siger in sigers])
    usigers = [Siger(qb64=sig) for sig in usigs]

    # verify indexes of attached signatures against verifiers and assign
    # verfer to each siger
    for siger in usigers:
        if siger.index >= len(verfers):
            raise ValidationError("Index = {} to large for keys for evt = "
                                  "{}.".format(siger.index, serder.ked))
        siger.verfer = verfers[siger.index]  # assign verfer

    # create lists of unique verified signatures and indices
    vindices = []
    vsigers = []
    for siger in usigers:
        if siger.verfer.verify(siger.raw, serder.raw):
            vindices.append(siger.index)
            vsigers.append(siger)

    return (vsigers, vindices)



def incept(keys,
           sith=None,
           nxt="",
           toad=None,
           wits=None,
           cnfg=None,
           data=None,
           version=Version,
           kind=Serials.json,
           code=None,
          ):

    """
    Returns serder of inception event message.
    Utility function to automate creation of inception events.

     Parameters:
        keys is list of qb64 signing keys
        sith is int, string, or list format for signing threshold
        nxt  is qb64 next digest xor
        toad is int, or str hex of witness threshold
        wits is list of qb64 witness prefixes
        cnfg is list of strings TraitDex of configuration trait strings
        data is list of seal dicts
        version is Version instance
        kind is serialization kind
        code is derivation code for prefix
    """
    vs = Versify(version=version, kind=kind, size=0)
    sn = 0
    ilk = Ilks.icp

    if sith is None:
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.size > len(keys):
        raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))

    wits = wits if wits is not None else []
    if len(oset(wits)) != len(wits):
        raise ValueError("Invalid wits = {}, has duplicates.".format(wits))

    if isinstance(toad, str):
        toad = "{:x}".format(toad)
    elif toad is None:
        if not wits:
            toad = 0
        else:  #  compute default f and m for len(wits)
            toad = ample(len(wits))

    if wits:
        if toad < 1 or toad > len(wits):  # out of bounds toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))

    cnfg = cnfg if cnfg is not None else []

    data = data if data is not None else []

    # see compact labels in KID0003.md

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=data,  # list of seal dicts
               )

    if code is None and len(keys) == 1:
        prefixer = Prefixer(qb64=keys[0])
    else:
        # raises derivation error if non-empty nxt but ephemeral code
        prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64

    return Serder(ked=ked)  # return serialized ked



def delcept(keys,
            delpre,
            code=None,
            sith=None,
            nxt="",
            toad=None,
            wits=None,
            cnfg=None,
            data=None,
            version=Version,
            kind=Serials.json,
          ):

    """
    Returns serder of delegated inception event message.
    Utility function to automate creation of delegated inception events.

     Parameters:
        keys is list of qb64 keys
        delpre is qb64 of delegators's prefix
        code is derivation code for prefix
        sith is int  of signing threshold
        nxt  is qb64 next digest xor
        toad is int of str hex of witness threshold
        wits is list of qb64 witness prefixes
        cnfg is list of configuration trait dicts including permissions dicts
        data is list of seal dicts
        version is Version instance
        kind is serialization kind
    """
    vs = Versify(version=version, kind=kind, size=0)
    sn = 0
    ilk = Ilks.dip

    if sith is None:
        sith = max(1, ceil(len(keys) / 2))

    if isinstance(sith, int):
        if sith < 1 or sith > len(keys):  # out of bounds sith
            raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))
    else:  # list sith not yet supported
        raise ValueError("invalid sith = {}.".format(sith))

    wits = wits if wits is not None else []
    if len(oset(wits)) != len(wits):
        raise ValueError("Invalid wits = {}, has duplicates.".format(wits))

    if isinstance(toad, str):
        toad = "{:x}".format(toad)
    elif toad is None:
        if not wits:
            toad = 0
        else:  # compute default f and m for len(wits)
            toad = ample(len(wits))

    if wits:
        if toad < 1 or toad > len(wits):  # out of bounds toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))

    cnfg = cnfg if cnfg is not None else []

    data = data if data is not None else []

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt="{:x}".format(sith), # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config and permission ordered mappings may be empty
               a=data,  # list of seal dicts
               di=delpre  # qb64 delegator prefix
               )

    if code is None:
        code = MtrDex.Blake3_256  # Default digest

    # raises derivation error if non-empty nxt but ephemeral code
    prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

    if not prefixer.digestive:
        raise ValueError("Invalid derivation code ={} for delegation. Must be"
                         " digestive".format(prefixer.code))

    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64

    return Serder(ked=ked)  # return serialized ked



def rotate(pre,
           keys,
           dig,
           sn=1,
           sith=None,
           nxt="",
           toad=None,
           wits=None, # prior existing wits
           cuts=None,
           adds=None,
           data=None,
           version=Version,
           kind=Serials.json,
          ):

    """
    Returns serder of rotation event message.
    Utility function to automate creation of rotation events.

     Parameters:
        pre is identifier prefix qb64
        keys is list of qb64 signing keys
        dig is digest of previous event qb64
        sn is int sequence number
        sith is string or list format for signing threshold
        nxt  is qb64 next digest xor
        toad is int or str hex of witness threshold
        wits is list of prior witness prefixes qb64
        cuts is list of witness prefixes to cut qb64
        adds is list of witness prefixes to add qb64
        data is list of seal dicts
        version is Version instance
        kind is serialization kind
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.rot

    if sn < 1:
        raise ValueError("Invalid sn = {} for rot.".format(sn))

    if sith is None:
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.size > len(keys):
        raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))

    wits = wits if wits is not None else []
    witset = oset(wits)
    if len(witset) != len(wits):
        raise ValueError("Invalid wits = {}, has duplicates.".format(wits))

    cuts = cuts if cuts is not None else []
    cutset = oset(cuts)
    if len(cutset) != len(cuts):
        raise ValueError("Invalid cuts = {}, has duplicates.".format(cuts))

    if (witset & cutset) != cutset:  #  some cuts not in wits
        raise ValueError("Invalid cuts = {}, not all members in wits.".format(cuts))

    adds = adds if adds is not None else []
    addset = oset(adds)
    if len(addset) != len(adds):
        raise ValueError("Invalid adds = {}, has duplicates.".format(adds))

    if cutset & addset:  # non empty intersection
        raise ValueError("Intersecting cuts = {} and  adds = {}.".format(cuts, adds))

    if witset & addset:  # non empty intersection
        raise ValueError("Intersecting wits = {} and  adds = {}.".format(wits, adds))

    newitset = (witset - cutset) | addset

    if len(newitset) != (len(wits) - len(cuts) + len(adds)):  # redundant?
        raise ValueError("Invalid member combination among wits = {}, cuts ={}, "
                         "and adds = {}.".format(wits, cuts, adds))

    if isinstance(toad, str):
        toad = "{:x}".format(toad)
    elif toad is None:
        if not newitset:
            toad = 0
        else:  # compute default f and m for len(newitset)
            toad = ample(len(newitset))

    if newitset:
        if toad < 1 or toad > len(newitset):  # out of bounds toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(newitset)))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(newitset)))


    data = data if data is not None else []

    ked = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               p=dig,  #  qb64 digest of prior event
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               a=data,  # list of seals
               )

    return Serder(ked=ked)  # return serialized ked


def deltate(pre,
           keys,
           dig,
           sn=1,
           sith=None,
           nxt="",
           toad=None,
           wits=None, # prior existing wits
           cuts=None,
           adds=None,
           data=None,
           version=Version,
           kind=Serials.json,
          ):

    """
    Returns serder of delegated rotation event message.
    Utility function to automate creation of delegated rotation events.

     Parameters:
        pre is identifier prefix qb64
        keys is list of qb64 signing keys
        dig is digest of previous event qb64
        sn is int sequence number
        sith is int signing threshold
        nxt  is qb64 next digest xor
        toad is int or str hex of witness threshold
        wits is list of prior witness prefixes qb64
        cuts is list of witness prefixes to cut qb64
        adds is list of witness prefixes to add qb64
        data is list of seals
        version is Version instance
        kind is serialization kind
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.drt

    if sn < 1:
        raise ValueError("Invalid sn = {} for rot.".format(sn))

    if sith is None:
        sith = max(1, ceil(len(keys) / 2))

    if isinstance(sith, int):
        if sith < 1 or sith > len(keys):  # out of bounds sith
            raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))
    else:  # list sith not yet supported
        raise ValueError("invalid sith = {}.".format(sith))

    wits = wits if wits is not None else []
    witset = oset(wits)
    if len(witset) != len(wits):
        raise ValueError("Invalid wits = {}, has duplicates.".format(wits))

    cuts = cuts if cuts is not None else []
    cutset = oset(cuts)
    if len(cutset) != len(cuts):
        raise ValueError("Invalid cuts = {}, has duplicates.".format(cuts))

    if (witset & cutset) != cutset:  # some cuts not in wits
        raise ValueError("Invalid cuts = {}, not all members in wits.".format(cuts))

    adds = adds if adds is not None else []
    addset = oset(adds)
    if len(addset) != len(adds):
        raise ValueError("Invalid adds = {}, has duplicates.".format(adds))

    if cutset & addset:  # non empty intersection
        raise ValueError("Intersecting cuts = {} and  adds = {}.".format(cuts, adds))

    if witset & addset:  # non empty intersection
        raise ValueError("Intersecting wits = {} and  adds = {}.".format(wits, adds))

    newitset = (witset - cutset) | addset

    if len(newitset) != (len(wits) - len(cuts) + len(adds)):  # redundant?
        raise ValueError("Invalid member combination among wits = {}, cuts ={}, "
                         "and adds = {}.".format(wits, cuts, adds))

    if isinstance(toad, str):
        toad = "{:x}".format(toad)
    elif toad is None:
        if not newitset:
            toad = 0
        else:  #  compute default f and m for len(newitset)
            toad = ample(len(newitset))

    if newitset:
        if toad < 1 or toad > len(newitset):  # out of bounds toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(newitset)))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(newitset)))


    data = data if data is not None else []

    ked = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               p=dig,  # qb64 digest of prior event
               kt="{:x}".format(sith), # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               a=data,  # list of seals ordered mappings may be empty
               )

    return Serder(ked=ked)  # return serialized ked



def interact(pre,
             dig,
             sn=1,
             data=None,
             version=Version,
             kind=Serials.json,
            ):

    """
    Returns serder of interaction event message.
    Utility function to automate creation of interaction events.

     Parameters:
        pre is identifier prefix qb64
        dig is digest of previous event qb64
        sn is int sequence number
        data is list of dicts of comitted data such as seals
        version is Version instance
        kind is serialization kind
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.ixn

    if sn < 1:
        raise ValueError("Invalid sn = {} for ixn.".format(sn))

    data = data if data is not None else []

    ked = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               p=dig,  #  qb64 digest of prior event
               a=data,  # list of seals
               )

    return Serder(ked=ked)  # return serialized ked


def receipt(pre,
            sn,
            dig,
            version=Version,
            kind=Serials.json
           ):

    """
    Returns serder of event receipt message for non-transferable receipter prefix.
    Utility function to automate creation of interaction events.

     Parameters:
        pre is qb64 str of prefix of event being receipted
        sn  is int sequence number of event being receipted
        dig is qb64 of digest of event being receipted
        version is Version instance of receipt
        kind  is serialization kind of receipt
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.rct

    if sn < 0:
        raise ValueError("Invalid sn = {} for rct.".format(sn))

    ked = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,  #  Ilks.rct
               d=dig,  # qb64 digest of receipted event
               )

    return Serder(ked=ked)  # return serialized ked


def state(pre,
          sn,
          pig,
          dig,
          fn,
          eilk,
          keys,
          eevt,
          dts=None,  # default current datetime
          sith=None, # default based on keys
          nxt="",
          toad=None, # default based on wits
          wits=None, # default to []
          cnfg=None, # default to []
          dpre=None,
          route="",
          version=Version,
          kind=Serials.json,
          ):

    """
    Returns serder of key state notification message.
    Utility function to automate creation of rotation events.

    Parameters:
        pre is identifier prefix qb64
        sn is int sequence number of latest event
        dig is digest of latest event
        eilk is message type (ilk) oflatest event
        keys is list of qb64 signing keys
        eevt is namedtuple of fields from latest establishment event s,d,wr,wa
            s = sn
            d = digest
            wr = witness remove list (cuts)
            wa = witness add list (adds)
        sith is string or list format for signing threshold
        nxt  is qb64 next digest xor if any
        toad is int of witness threshold
        wits is list of witness prefixes qb64
        cnfg is list of strings TraitDex of configuration traits
        dpre is qb64 of delegator's identifier prefix if any
        route (str): endpoint route of this ksn
        version is Version instance
        kind is serialization kind

    Key State Dict
    {
        "v": "KERI10JSON00011c_",
        "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
        "s": "2":,
        "t": "ksn",
        "p": "EYAfSVPzhzZ-i0d8JZS6b5CMAoTNZH3ULvaU6JR2nmwy",
        "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
        "f": "3",
        "dt": "2020-08-22T20:35:06.687702+00:00",
        "et": "rot",
        "kt": "1",
        "k": ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],
        "n": "EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
        "bt": "1",
        "b": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"],
        "c": ["eo"],
        "ee":
          {
            "s": "1",
            "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
            "br": ["Dd8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CMZ-i0"],
            "ba": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"]
          },
        "di": "EYAfSVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULv",
        "r": "route/to/endpoint/buffer"
    }

    "di": "" when not delegated
    "r": ""  when no route
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.ksn

    if sn < 0:
        raise ValueError("Negative sn = {} in key state.".format(sn))

    if eilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
        raise ValueError("Invalid evernt type et=  in key state.".format(eilk))

    if dts is None:
        dts = helping.nowIso8601()

    if sith is None:
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.size > len(keys):
        raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))

    wits = wits if wits is not None else []
    witset = oset(wits)
    if len(witset) != len(wits):
        raise ValueError("Invalid wits = {}, has duplicates.".format(wits))

    if toad is None:
        if not witset:
            toad = 0
        else:
            toad = max(1, ceil(len(witset) / 2))

    if witset:
        if toad < 1 or toad > len(witset):  # out of bounds toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(witset)))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(witset)))

    cnfg = cnfg if cnfg is not None else []

    if not eevt or not isinstance(eevt, StateEstEvent):
        raise ValueError("Missing or invalid latest est event = {} for key "
                         "state.".format(eevt))

    validateSN(eevt.s, inceptive=None)  # both incept and rotate

    if len(oset(eevt.br)) != len(eevt.br):  # duplicates in cuts
        raise ValueError("Invalid cuts = {} in latest est event, has duplicates"
                         ".".format(eevt.br))

    if len(oset(eevt.ba)) != len(eevt.ba):  # duplicates in adds
        raise ValueError("Invalid adds = {} in latest est event, has duplicates"
                         ".".format(eevt.ba))


    ksd = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn), # lowercase hex string no leading zeros
               t=ilk,
               p=pig,
               d=dig,
               f="{:x}".format(fn), # lowercase hex string no leading zeros
               dt=dts,
               et=eilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               ee=eevt._asdict(),  # latest est event dict
               di=dpre if dpre is not None else "",
               r=route,
               )

    return Serder(ked=ksd)  # return serialized ksd


def query(pre,
          res,
          dt=None,
          dta=None,
          dtb=None,
          sn=None,
          version=Version,
          kind=Serials.json):

    """
    Returns serder of query event message.
    Utility function to automate creation of interaction events.

     Parameters:
        pre is identifier prefix qb64
        dig is digest of previous event qb64
        sn is int sequence number
        data is list of dicts of comitted data such as seals
        version is Version instance
        kind is serialization kind
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.req

    qry = dict(
        i=pre
    )

    if dt is not None:
        qry["dt"] = dt

    if dta is not None:
        qry["dta"] = dt

    if dtb is not None:
        qry["dtb"] = dt

    if sn is not None:
        qry["s"] = sn


    ked = dict(v=vs,  # version string
               t=ilk,
               r=res,  # resource type for single item request
               q=qry
               )

    return Serder(ked=ked)  # return serialized ked


def messagize(serder, sigers=None, seal=None, wigers=None, cigars=None, pipelined=False):
    """
    Attaches indexed signatures from sigers and/or cigars and/or wigers to
    KERI message data from serder
    Parameters:
        serder is Serder instance containing the event
        sigers is optional list of Siger instance to create indexed signatures
        seal is optional seal when present use complex attachment group of triple
            pre+snu+dig made from (i,s,d) of seal plus attached indexed sigs in sigers
        wigers is optional list of Siger instances of witness index signatures
        cigars is optional list of Cigars instances of non-transferable non indexed
            signatures from  which to form receipt couples.
            Each cigar.vefer.qb64 is pre of receiptor and cigar.qb64 is signature
        pipelined is Boolean, True means prepend pipelining count code to attachemnts
            False means to not prepend pipelining count code

    Returns: bytearray KERI event message
    """
    msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
    atc = bytearray()

    if not (sigers or cigars or wigers):
        raise ValueError("Missing attached signatures on message = {}."
                         "".format(serder.ked))

    if sigers:
        if seal is not None:
            atc.extend(Counter(CtrDex.TransIndexedSigGroups, count=1).qb64b)
            atc.extend(seal.i.encode("utf-8"))
            atc.extend(Seqner(snh=seal.s).qb64b)
            atc.extend(seal.d.encode("utf-8"))

        atc.extend(Counter(code=CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)
        for siger in sigers:
            atc.extend(siger.qb64b)

    if wigers:
        atc.extend(Counter(code=CtrDex.WitnessIdxSigs, count=len(wigers)).qb64b)
        for wiger in wigers:
            if wiger.verfer and wiger.verfer.code not in NonTransDex:
                raise ValueError("Attempt to use tranferable prefix={} for "
                                 "receipt.".format(wiger.verfer.qb64))
            atc.extend(wiger.qb64b)

    if cigars:
        atc.extend(Counter(code=CtrDex.NonTransReceiptCouples, count=len(cigars)).qb64b)
        for cigar in cigars:
            if cigar.verfer.code not in NonTransDex:
                raise ValueError("Attempt to use tranferable prefix={} for "
                                 "receipt.".format(cigar.verfer.qb64))
            atc.extend(cigar.verfer.qb64b)
            atc.extend(cigar.qb64b)


    if pipelined:
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        msg.extend(Counter(code=CtrDex.AttachedMaterialQuadlets,
                                  count=(len(atc) // 4)).qb64b)

    msg.extend(atc)
    return msg


class Kever:
    """
    Kever is KERI key event verifier class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Class Attributes:
        .EstOnly is Boolean
                True means allow only establishment events
                False means allow all events
        .DoNotDelegate is Boolean
                True means do not allow delegation other identifiers
                False means allow delegation of delegated identifiers

    Attributes:
        .db is reference to Baser instance that manages the LMDB database
        .cues is reference to Kevery.cues deque when provided
        .prefixes is list of fully qualified base64 identifier prefixes of own
            habitat identifiers if any from Kevery when provided. If empty then
            operate in promiscuous mode
        .local is Boolean (from kevery when provided)
            True means only process msgs for own events if .prefixes is not empty
            False means only process msgs for not own events if .prefixes is not empty
        .version is version of current event state
        .prefixer is prefixer instance for current event state
        .sn is sequence number int
        .fn is first seen ordinal number int
        .dater is first seen Dater instance (datetime)
        .serder is Serder instance of current event with .serder.diger for digest
        .ilk is str of current event type
        .tholder is Tholder instance for event sith
        .verfers is list of Verfer instances for current event state set of signing keys
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .cuts is list of qualified qb64 aids for witnesses cut from prev wits list
        .adds is list of qualified qb64 aids for witnesses added to prev wits list
        .estOnly is boolean trait True means only allow establishment events
        .doNotDelegate is boolean trait True means do not allow delegation
        .lastEst is LastEstLoc namedtuple of int sn .s and qb64 digest .d of last est event
        .delegated is Boolean, True means delegated identifier, False not delegated
        .delgator is str qb64 of delegator's prefix


    Properties:
        .kevers (dict): reference to self.db.kevers
        .transferable (bool): True if nexter is not none and pre is transferable

    """
    EstOnly = False
    DoNotDelegate = False

    def __init__(self, *, state=None, serder=None, sigers=None, wigers=None,
                 db=None, estOnly=None,
                 seqner=None, diger=None, firner=None, dater=None,
                 cues=None, prefixes=None, local=False,
                 check=False):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigers raises ValidationError if not

        Parameters:
            state (Serder): instance of key state
            serder is Serder instance of inception event
            sigers is list of Siger instances of indexed controller signatures
                of event. Index is offset into keys list of latest est event
            wigers is list of Siger instances of indexed witness signatures of
                event. Index is offset into wits list of latest est event
            db is Baser instance of lmdb database
            estOnly is boolean trait to indicate establish only event
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            diger is Diger instance of of delegating event digest.
                If this event is not delegated then diger is ignored
            firner is optional Seqner instance of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater is optional Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
            kevers is reference Kevery.kevers dict when provided needed for
                validation of delegation seal .doNotDelegate of delegator
            cues is reference to Kevery.cues deque when provided i.e. notices of
                events or requests to respond to
            prefixes is list of own prefixes for own local habitats. May not be the
                prefix of this Kever's event. Some restrictions if present
                If empty then promiscuous mode
            local (bool): True means only process msgs for own controller's
                events if .prefixes is not empty. False means only process msgs
                for not own events if .prefixes is not empty
            check (bool): True means do not update the database in any
                non-idempotent way. Useful for reinitializing the Kevers from
                a persisted KEL without updating non-idempotent first seen .fels
                and timestamps.
        """
        if not (state or (serder and sigers)):
            raise ValueError("Missing required arguments. Need state or serder"
                             " and sigers")

        if db is None:
            db = basing.Baser(reopen=True)  # default name = "main"
        self.db = db
        self.cues = cues
        self.prefixes = prefixes if prefixes is not None else oset()
        self.local = True if local else False

        if state:  # preload from state
            self.reload(state)
            return

        # may update state as we go because if invalid we fail to finish init
        self.version = serder.version  # version dispatch ?

        ilk = serder.ked["t"]
        if ilk not in (Ilks.icp, Ilks.dip):
            raise ValidationError("Expected ilk = {} or {} got {} for evt = {}."
                                  "".format(Ilks.icp, Ilks.dip,
                                  ilk, serder.ked))
        self.ilk = ilk

        labels = DIP_LABELS if ilk == Ilks.dip else ICP_LABELS
        for k in labels:
            if k not in serder.ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, serder.ked))

        self.incept(serder=serder)  # do major event validation and state setting

        self.config(serder=serder, estOnly=estOnly)  # assign config traits perms


        # Validates signers, delegation if any, and witnessing when applicable
        # If does not validate then escrows as needed and raises ValidationError
        sigers, delegator, wigers = self.valSigsDelWigs(serder=serder,
                                                            sigers=sigers,
                                                            verfers=serder.verfers,
                                                            tholder=self.tholder,
                                                            wigers=wigers,
                                                            toad=self.toad,
                                                            wits=self.wits,
                                                            seqner=seqner,
                                                            diger=diger)

        self.delegator = delegator
        if self.delegator is None:
            self.delegated = False
        else:
            self.delegated = True

        # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
        # all validated above so may add to KEL and FEL logs as first seen
        fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers,
                                first=True if not check else False, seqner=seqner, diger=diger,
                                firner=firner, dater=dater)
        if fn is not None:  # first is non-idempotent for fn check mode fn is None
            self.fn = fn
            self.dater = Dater(dts=dts)
            self.db.states.pin(keys=self.prefixer.qb64, val=self.state())


    @property
    def kevers(self):
        """
        Returns .baser.kevers
        """
        return self.db.kevers


    @property
    def transferable(self):
        """
        Property transferable:
        Returns True if identifier does not have non-transferable derivation code
                and .nextor is not None
                False otherwise
        """
        return(self.nexter is not None and self.prefixer.transferable)


    def reload(self, state):
        """
        Reload Kever attributes (aka its state) from state serder

        Parameters:
            state (Serder): instance of key stat notice 'ksn' message body

        """
        for k in KSN_LABELS:
            if k not in state.ked:
                raise ValidationError("Missing element = {} from {} event."
                                      " evt = {}.".format(k, Ilks.ksn,
                                                          state.pretty()))

        self.version = state.version
        self.prefixer = Prefixer(qb64=state.pre)
        self.sn = state.sn
        self.fn = int(state.ked["f"], 16)
        self.dater = Dater(dts=state.ked["dt"])
        self.ilk = state.ked["et"]
        self.tholder = Tholder(sith=state.ked["kt"])
        self.verfers = [Verfer(qb64=key) for key in state.ked["k"]]
        self.nexter = Nexter(qb64=state.ked["n"]) if state.ked["n"] else None
        self.toad = int(state.ked["bt"], 16)
        self.wits = state.ked["b"]
        self.cuts = state.ked["ee"]["br"]
        self.adds = state.ked["ee"]["ba"]
        self.estOnly = False
        self.doNotDelegate = True if "DND" in state.ked["c"] else False
        self.estOnly = True if "EO" in state.ked["c"] else False
        self.lastEst = LastEstLoc(s=int(state.ked['ee']['s'], 16),
                                 d=state.ked['ee']['d'])
        self.delegator = state.ked['di'] if state.ked['di'] else None
        self.delegated = True if self.delegator else False

        if (raw := self.db.getEvt(key=dgKey(pre=self.prefixer.qb64,
                                                  dig=state.ked['d']))) is None:
            raise MissingEntryError("Corresponding event for state={} not found."
                             "".format(state.pretty()))
        self.serder = Serder(raw=bytes(raw))
        # May want to do additional checks here


    def incept(self, serder, estOnly=None):
        """
        Verify incept key event message from serder


        Parameters:
            serder is Serder instance of inception event
            estOnly is boolean  to indicate establish only events allowed
        """
        ked = serder.ked

        self.verfers = serder.verfers  # converts keys to verifiers
        self.tholder = Tholder(sith=ked["kt"])  #  parse sith into Tholder instance
        if len(self.verfers) < self.tholder.size:
            raise ValidationError("Invalid sith = {} for keys = {} for evt = {}."
                             "".format(ked["kt"],
                                       [verfer.qb64 for verfer in self.verfers],
                                       ked))

        self.prefixer = Prefixer(qb64=serder.pre)
        if not self.prefixer.verify(ked=ked, prefixed=True):  # invalid prefix
            raise ValidationError("Invalid prefix = {} for inception evt = {}."
                                  "".format(self.prefixer.qb64, ked))


        self.sn = self.validateSN(ked=ked, inceptive=True)
        self.serder = serder  # need whole serder for digest agility comparisons

        nxt = ked["n"]
        if not self.prefixer.transferable and nxt:  # nxt must be empty for nontrans prefix
            raise ValidationError("Invalid inception nxt not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))
        self.nexter = Nexter(qb64=nxt) if nxt else None

        self.cuts = []  # always empty at inception since no prev event
        self.adds = []  # always empty at inception since no prev event
        wits = ked["b"]
        if len(oset(wits)) != len(wits):
            raise ValidationError("Invalid backers = {}, has duplicates for evt = {}."
                             "".format(wits, ked))
        self.wits = wits

        toad = int(ked["bt"], 16)
        if wits:
            if toad < 1 or toad > len(wits):  # out of bounds toad
                raise ValidationError("Invalid toad = {} for backers = {} for evt = {}."
                                 "".format(toad, wits, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValidationError("Invalid toad = {} for backers = {} for evt = {}."
                                 "".format(toad, wits, ked))
        self.toad = toad

        # need this to recognize recovery events and transferable receipts
        self.lastEst = LastEstLoc(s=self.sn, d=self.serder.diger.qb64)  # last establishment event location


    def config(self, serder, estOnly=None, doNotDelegate=None):
        """
        Process cnfg field for configuration traits
        """
        # assign traits
        self.estOnly = (True if (estOnly if estOnly is not None else self.EstOnly)
                            else False)  # ensure default estOnly is boolean

        self.doNotDelegate = (True if (doNotDelegate if doNotDelegate is not None
                                       else self.DoNotDelegate)
                              else False)  # ensure default doNotDelegate is boolean

        cnfg = serder.ked["c"]  # process cnfg for traits
        if TraitDex.EstOnly in cnfg:
            self.estOnly = True
        if TraitDex.DoNotDelegate in cnfg:
            self.doNotDelegate = True


    def update(self, serder,  sigers, wigers=None, seqner=None, diger=None,
               firner=None, dater=None, check=False):
        """
        Not an inception event. Verify event serder and indexed signatures
        in sigers and update state

        Parameters:
            serder is Serder instance of  event
            sigers is list of SigMat instances of signatures of event
            wigers is list of Siger instances of indexed witness signatures of
                event. Index is offset into wits list of latest est event
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            diger is Diger instance of of delegating event digest.
                If this event is not delegated then diger is ignored
            firner is optional Seqner instance of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater is optional Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
            check (bool): True means do not update the database in any
                non-idempotent way. Useful for reinitializing the Kevers from
                a persisted KEL without updating non-idempotent first seen .fels
                and timestamps.

        """
        if not self.transferable:  # not transferable so no events after inception allowed
            raise ValidationError("Unexpected event = {} is nontransferable "
                                  " state.".format(serder.ked))
        ked = serder.ked
        if serder.pre != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {} for evt = {}.".format(ked["i"],
                                                               self.prefixer.qb64,
                                                               ked))

        sn = self.validateSN(ked=ked, inceptive=False)
        ilk = ked["t"]

        if ilk in (Ilks.rot, Ilks.drt):  # rotation (or delegated rotation) event
            if self.delegated and ilk != Ilks.drt:
                raise ValidationError("Attempted non delegated rotation on "
                                      "delegated pre = {} with evt = {}."
                                      "".format(ked["i"], ked))

            labels = DRT_LABELS if ilk == Ilks.dip else ROT_LABELS
            for k in labels:
                if k not in ked:
                    raise ValidationError("Missing element = {} from {} event for "
                                          "evt = {}.".format(k, ilk, ked))

            tholder, toad, wits, cuts, adds = self.rotate(serder, sn)

            # Validates signers, delegation if any, and witnessing when applicable
            # If does not validate then escrows as needed and raises ValidationError
            sigers, delegator, wigers = self.valSigsDelWigs(serder=serder,
                                                                sigers=sigers,
                                                                verfers=serder.verfers,
                                                                tholder=tholder,
                                                                wigers=wigers,
                                                                toad=toad,
                                                                wits=wits,
                                                                seqner=seqner,
                                                                diger=diger)

            if delegator != self.delegator:  #
                raise ValidationError("Erroneous attempted  delegated rotation"
                                      " on either undelegated event or with"
                                      " wrong delegator = {} for pre  = {}"
                                      " with evt = {}."
                                  "".format(delegator, ked["i"], ked))

            # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
            # all validated above so may add to KEL and FEL logs as first seen
            fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers,
                                    first=True if not check else False, seqner=seqner, diger=diger,
                                    firner=firner, dater=dater)

            # nxt and signatures verify so update state
            self.sn = sn
            self.serder = serder  #  need whole serder for digest agility compare
            self.ilk = ilk
            self.tholder = tholder
            self.verfers = serder.verfers
            # update .nexter
            nxt = ked["n"]
            self.nexter = Nexter(qb64=nxt) if nxt else None  # check for empty

            self.toad = toad
            self.wits = wits
            self.cuts = cuts
            self.adds = adds

            # last establishment event location need this to recognize recovery events
            self.lastEst = LastEstLoc(s=self.sn, d=self.serder.diger.qb64)
            if fn is not None:  # first is non-idempotent for fn check mode fn is None
                self.fn = fn
                self.dater = Dater(dts=dts)
                self.db.states.pin(keys=self.prefixer.qb64, val=self.state())


        elif ilk == Ilks.ixn:  # subsequent interaction event
            if self.estOnly:
                raise ValidationError("Unexpected non-establishment event = {}."
                                  "".format(serder.ked))

            for k in IXN_LABELS:
                if k not in ked:
                    raise ValidationError("Missing element = {} from {} event."
                                          " evt = {}.".format(k, Ilks.ixn, ked))

            if not sn == (self.sn + 1):  # sn not in order
                raise ValidationError("Invalid sn = {} expecting = {} for evt "
                                      "= {}.".format(sn, self.sn+1, ked))

            if not self.serder.compare(dig=ked["p"]):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with state dig"
                                      " = {} for evt = {}.".format(ked["p"],
                                                                   self.serder.diger.qb64,
                                                                   ked))

            # interaction event use keys, sith, toad, and wits from pre-existing Kever state

            # Validates signers, delegation if any, and witnessing when applicable
            # If does not validate then escrows as needed and raises ValidationError
            sigers, delegator, wigers = self.valSigsDelWigs(serder=serder,
                                                                sigers=sigers,
                                                                verfers=self.verfers,
                                                                tholder=self.tholder,
                                                                wigers=wigers,
                                                                toad=self.toad,
                                                                wits=self.wits)

            # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
            # all validated above so may add to KEL and FEL logs as first seen
            fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers,
                                    first=True if not check else False)  # First seen accepted

            # update state
            self.sn = sn
            self.serder = serder  # need for digest agility includes .serder.diger
            self.ilk = ilk
            if fn is not None: # first is non-idempotent for fn check mode fn is None
                self.fn = fn
                self.dater = Dater(dts=dts)
                self.db.states.pin(keys=self.prefixer.qb64, val=self.state())

        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))


    def rotate(self, serder, sn):
        """
        Generic Rotate Operation Processing
        Same logic for both rot and drt (plain and delegated rotation)
        Returns triple (tholder, toad, wits, cuts, adds)

        Parameters:
            serder is event Serder instance
            sn is int sequence number

        """
        ked = serder.ked
        pre = ked["i"]
        dig = ked["p"]

        if sn > self.sn + 1:  #  out of order event
            raise ValidationError("Out of order event sn = {} expecting"
                                  " = {} for evt = {}.".format(sn,
                                                               self.sn+1,
                                                               ked))

        elif sn <= self.sn:  #  stale or recovery
            #  stale events could be duplicitous
            #  duplicity detection should have happend before .update called
            #  so raise exception if stale
            if sn <= self.lastEst.s :  # stale  event
                raise ValidationError("Stale event sn = {} expecting"
                                      " = {} for evt = {}.".format(sn,
                                                                   self.sn+1,
                                                                   ked))

            else:  # sn > self.lastEst.sn  #  recovery event
                if self.ilk != Ilks.ixn:  #  recovery  may only override ixn state
                    raise ValidationError("Invalid recovery attempt: Recovery"
                                          "at ilk = {} not ilk = {} for evt"
                                          " = {}.".format(self.ilk,
                                                          Ilks.ixn,
                                                          ked))

                psn = sn - 1 # sn of prior event
                # fetch raw serialization of last inserted  event at psn
                pdig = self.db.getKeLast(key=snKey(pre=pre, sn=psn))
                if pdig is None:
                    raise ValidationError("Invalid recovery attempt: "
                                          "Bad sn = {} for event = {}."
                                          "".format(psn, ked))
                praw = self.db.getEvt(key=dgKey(pre=pre, dig=pdig))
                if praw is None:
                    raise ValidationError("Invalid recovery attempt: "
                                          " Bad dig = {}.".format(pdig))
                pserder = Serder(raw=bytes(praw))  # deserialize prior event raw
                if not pserder.compare(dig=dig): #  bad recovery event
                    raise ValidationError("Invalid recovery attempt:"
                                          "Mismatch recovery event prior dig"
                                          "= {} with dig = {} of event sn = {}"
                                          " evt = {}.".format(dig,
                                                              pserder.dig,
                                                              psn,
                                                              ked))

        else:  # sn == self.sn + 1   new non-recovery event
            if not self.serder.compare(dig=dig):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with"
                                      " state dig = {} for evt = {}."
                                      "".format(dig, self.serder.diger.qb64, ked))


        # also check derivation code of pre for non-transferable
        if self.nexter is None:   # empty so rotations not allowed
            raise ValidationError("Attempted rotation for nontransferable"
                                  " prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))

        tholder = Tholder(sith=ked["kt"])  #  parse sith into Tholder instance
        if len(serder.verfers) < tholder.size:
            raise ValidationError("Invalid sith = {} for keys = {} for evt = {}."
                             "".format(ked["kt"],
                                       [verfer.qb64 for verfer in serder.verfers],
                                       ked))

        # verify nxt from prior
        keys = ked["k"]
        if not self.nexter.verify(limen=tholder.limen, keys=keys):
            raise ValidationError("Mismatch nxt digest = {} with rotation"
                                  " sith = {}, keys = {} for evt = {}."
                                  "".format(self.nexter.qb64, tholder.thold, keys, ked))

        # compute wits from existing .wits with new cuts and adds from event
        # use ordered set math ops to verify and ensure strict ordering of wits
        # cuts and add to ensure that indexed signatures on indexed witness
        # receipts work
        witset = oset(self.wits)
        cuts = ked["br"]
        cutset = oset(cuts)
        if len(cutset) != len(cuts):
            raise ValidationError("Invalid cuts = {}, has duplicates for evt = "
                             "{}.".format(cuts, ked))

        if (witset & cutset) != cutset:  #  some cuts not in wits
            raise ValidationError("Invalid cuts = {}, not all members in wits"
                             " for evt = {}.".format(cuts, ked))

        adds = ked["ba"]
        addset = oset(adds)
        if len(addset) != len(adds):
            raise ValidationError("Invalid adds = {}, has duplicates for evt = "
                             "{}.".format(adds, ked))

        if cutset & addset:  # non empty intersection
            raise ValidationError("Intersecting cuts = {} and  adds = {} for "
                             "evt = {}.".format(cuts, adds, ked))

        if witset & addset:  # non empty intersection
            raise ValidationError("Intersecting wits = {} and  adds = {} for "
                             "evt = {}.".format(self.wits, adds, ked))

        wits = list((witset - cutset) | addset)

        if len(wits) != (len(self.wits) - len(cuts) + len(adds)):  # redundant?
            raise ValidationError("Invalid member combination among wits = {}, cuts ={}, "
                             "and adds = {} for evt = {}.".format(self.wits,
                                                                  cuts,
                                                                  adds,
                                                                  ked))

        toad = int(ked["bt"], 16)
        if wits:
            if toad < 1 or toad > len(wits):  # out of bounds toad
                raise ValidationError("Invalid toad = {} for wits = {} for evt "
                                 "= {}.".format(toad, wits, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValidationError("Invalid toad = {} for wits = {} for evt "
                                 "= {}.".format(toad, wits, ked))

        return (tholder, toad, wits, cuts, adds)

    def validateSN(self, sn=None, ked=None, inceptive=False):
        """
        Returns int validated from hex str sn in ked

        Parameters:
           sn (str): is str hex of sequence number
           ked (dict): is key event dict of associated event or message such as seal
        """
        if sn is None:
            sn = ked["s"]

        return validateSN(sn, inceptive=inceptive)


    def valSigsDelWigs(self, serder, sigers, verfers, tholder,
                       wigers, toad, wits, seqner=None, diger=None):
        """
        Returns triple (sigers, delegator, wigers) where:
        sigers is unique validated signature verified members of inputed sigers
        delegator is qb64 delegator prefix if delegated else None
        wigers is unique validated signature verified members of inputed wigers

        Validates sigers signatures by validating indexes, verifying signatures, and
            validating threshold sith.
        Validate witness receipts by validating indexes, verifying
            witness signatures and validating toad.
        Witness validation is a function of wits .prefixes and .local

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controllers signatures.
                Index is offset into verfers list from which public key may be derived.
            verfers is list of Verfer instances of keys from latest est event
            tholder is Tholder instance of sith threshold
            wigers is list of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.
            toad is int or  str hex of witness threshold
            wits is list of qb64 non-transferable prefixes of witnesses used to
                derive werfers for wigers
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            diger is Diger instance of of delegating event digest.
                If this event is not delegated then diger is ignored

        """
        if len(verfers) < self.tholder.size:
            raise ValidationError("Invalid sith = {} for keys = {} for evt = {}."
                             "".format(tholder.sith,
                                       [verfer.qb64 for verfer in verfers],
                                       serder.ked))

        # get unique verified sigers and indices lists from sigers list
        sigers, indices = verifySigs(serder=serder, sigers=sigers, verfers=verfers)
        # sigers  now have .verfer assigned

        werfers = [Verfer(qb64=wit) for wit in wits]

        # get unique verified wigers and windices lists from wigers list
        wigers, windices = verifySigs(serder=serder, sigers=wigers, verfers=werfers)
        # each wiger now has werfer of corresponding wit

        # check if fully signed
        if not indices:  # must have a least one verified sig
            raise ValidationError("No verified signatures for evt = {}."
                                  "".format(serder.ked))

        if not tholder.satisfy(indices):  #  at least one but not enough
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            if seqner and diger:
                self.escrowPACouple(serder=serder, seqner=seqner, diger=diger)
            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                  " for evt = {}.".format(tholder.sith,
                                                [siger.qb64 for siger in sigers],
                                                serder.ked))

        delegator = self.validateDelegation(serder, sigers=sigers, wigers=wigers,
                                            seqner=seqner, diger=diger)

        # Kevery .process event logic prevents this from seeing event when
        # not local and event pre is own pre
        if ((wits and not self.prefixes) or  # in promiscuous mode so assume must verify toad
            (wits and self.prefixes and not self.local and  # not promiscuous nonlocal
                not (oset(self.prefixes) & oset(wits)))):  # own prefix is not a witness
            # validate that event is fully witnessed
            if isinstance(toad, str):
                toad = int(toad, 16)
            if toad < 0 or len(wits) < toad:
                raise ValidationError("Invalid toad = {} for wits = {} for evt"
                                       " = {}.".format(toad, wits, serder.ked))

            if len(windices) < toad:  # not fully witnessed yet
                self.escrowPWEvent(serder=serder, wigers=wigers, sigers=sigers)

                raise MissingWitnessSignatureError("Failure satisfying toad = {} "
                            "on witness sigs for {} for evt = {}.".format(toad,
                                                    [siger.qb64 for siger in wigers],
                                                    serder.ked))
        return (sigers, delegator, wigers)


    def validateDelegation(self, serder, sigers, wigers=None, seqner=None, diger=None):
        """
        Returns delegator's qb64 identifier prefix if seal instance of SealLocation if seal validates with respect
        to Delegator's KEL
        Location Seal is from Delegate's establishment event
        Assumes state setup

        Parameters:
            serder is Serder instance of delegated event serder
            sigers is list of Siger instances of indexed controller sigs of
                delegated event. Assumes sigers is list of unique verified sigs
            wigers is optional list of Siger instance of indexed witness sigs of
                delegated event. Assumes wigers is list of unique verified sigs
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            diger is Diger instance of of delegating event digest.
                If this event is not delegated then diger is ignored

        """
        if serder.ked['t'] not in (Ilks.dip, Ilks.drt):  # not delegated
            return None  # delegator is None

        # verify delegator and attachment pointing to delegating event
        if serder.ked['t'] == Ilks.dip:
            delegator = serder.ked["di"]
        else:
            delegator = self.delegator

        ssn = self.validateSN(sn=seqner.snh, inceptive=False)

        # get the dig of the delegating event
        key = snKey(pre=delegator, sn=ssn)
        raw = self.db.getKeLast(key)  # get dig of delegating event
        if raw is None:  # no delegating event at key pre, sn
            #  escrow event here
            inceptive = True if serder.ked["t"] in (Ilks.icp, Ilks.dip) else False
            sn = self.validateSN(sn=serder.ked["s"], inceptive=inceptive)
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            self.escrowPACouple(serder=serder, seqner=seqner, diger=diger)
            raise MissingDelegationError("No delegating event from {} at {} for "
                                             "evt = {}.".format(delegator,
                                                                diger.qb64,
                                                                serder.ked))

        # get the delegating event from dig
        ddig = bytes(raw)
        key = dgKey(pre=delegator, dig=ddig)
        raw = self.db.getEvt(key)
        if raw is None:
            raise ValidationError("Missing delegation from {} at event dig = {} for evt = {}."
                                  "".format(delegator, ddig, serder.ked))

        dserder = Serder(raw=bytes(raw))  # delegating event
        # compare digests to make sure they match here
        if not dserder.compare(diger=diger):
            raise ValidationError("Invalide delegation from {} at event dig = {} for evt = {}."
                                  "".format(delegator, ddig, serder.ked))

        if self.kevers is None or delegator not in self.kevers:
            raise ValidationError("Missing Kever for delegator = {} for evt = {}."
                                  "".format(delegator, serder.ked))

        dkever = self.kevers[delegator]
        if dkever.doNotDelegate:
            raise ValidationError("Delegator = {} for evt = {},"
                           " does not allow delegation.".format(delegator,
                                                                serder.ked))

        pre = serder.ked["i"]
        sn = serder.ked["s"]
        dig = serder.dig
        found = False  # find event seal of delegated event in delegating data
        for dseal in dserder.ked["a"]:  # find delegating seal anchor
            if ("i" in dseal and dseal["i"] == pre and
                "s" in dseal and dseal["s"] == sn and
                "d" in dseal and serder.compare(dig=dseal["d"])):  # dseal["d"] == dig
                found = True
                break

        if not found:
            raise ValidationError("Missing delegation from {} in {} for evt = {}."
                                  "".format(delegator, dserder.ked["a"], serder.ked))

        # should we reverify signatures or trust the database?
        # if database is loaded into memory fresh and reverified each bootup
        # then we can trust it otherwise we can't

        return delegator  # return delegator prefix


    def logEvent(self, serder, sigers=None, wigers=None, first=False,
                 seqner=None, diger=None, firner=None, dater=None):
        """
        Update associated logs for verified event.
        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            serder is Serder instance of current event
            sigers is optional list of Siger instance for current event
            wigers is optional list of Siger instance of indexed witness sigs
            first is Boolean True means first seen accepted log of event.
                    Otherwise means idempotent log of event to accept additional
                    signatures beyond the threshold provided for first seen
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            diger is Diger instance of of delegating event digest.
                If this event is not delegated then diger is ignored
            firner is optional Seqner instance of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater is optional Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
        """
        fn = None
        dgkey = dgKey(serder.preb, serder.digb)
        dtsb = helping.nowIso8601().encode("utf-8")
        self.db.putDts(dgkey, dtsb)  #  idempotent do not change dts if already
        if sigers:
            self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])  # idempotent
        if wigers:
            self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        self.db.putEvt(dgkey, serder.raw)  # idempotent (maybe already excrowed)
        if first:  # append event dig to first seen database in order
            if seqner and diger: # authorized delegated or issued event
                couple = seqner.qb64b + diger.qb64b
                self.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
            fn = self.db.appendFe(serder.preb, serder.digb)
            if firner and fn != firner.sn:  # cloned replay but replay fn not match
                if self.cues is not None:
                    self.cues.append(dict(kin="noticeBadCloneFN", serder=serder,
                                fn=fn, firner=firner, dater=dater))
                logger.info("Kever Mismatch Cloned Replay FN: %s First seen "
                            "ordinal fn %s and clone fn %s \nEvent=\n%s\n",
                             serder.preb, fn, firner.sn, serder.pretty())
            if dater:  # cloned replay use original's dts from dater
                dtsb = dater.dtsb
            self.db.setDts(dgkey, dtsb)  # first seen so set dts to now
            self.db.firsts.pin(keys=dgkey, val=Seqner(sn=fn))
            logger.info("Kever state: %s First seen ordinal %s at %s\nEvent=\n%s\n",
                         serder.preb, fn, dtsb.decode("utf-8"), serder.pretty())
        self.db.addKe(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Kever state: %s Added to KEL valid event=\n%s\n",
                                               serder.preb, serder.pretty())
        return (fn, dtsb.decode("utf-8"))  #  (fn int, dts str) if first else (None, dts str)


    def escrowPSEvent(self, serder, sigers, wigers=None):
        """
        Update associated logs for escrow of partially signed event
        or fully signed delegated event but not yet verified delegation

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controller sigs
            wigers is optional list of Siger instance of indexed witness sigs
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))   # idempotent
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        if wigers:
            self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addPse(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Kever state: Escrowed partially signed "
                     "event = %s\n", serder.ked)

    def escrowPACouple(self, serder, seqner, diger):
        """
        Update associated logs for escrow of partially signed event
        or fully signed delegated event but not yet verified delegation

        Parameters:
            serder is Serder instance of delegated or issued event
            seqner is Seqner instance of sn of seal source event of delegator/issuer
            diger is Diger instance of digest of delegator/issuer
        """
        dgkey = dgKey(serder.preb, serder.digb)
        couple = seqner.qb64b + diger.qb64b
        self.db.putPde(dgkey, couple)   # idempotent
        logger.info("Kever state: Escrowed partially delegated "
                     "event = %s\n", serder.ked)


    def escrowPWEvent(self, serder, wigers, sigers=None):
        """
        Update associated logs for escrow of partially witnessed event

        Parameters:
            serder is Serder instance of  event
            wigers is list of Siger instance of indexed witness sigs
            sigers is optional list of Siger instances of indexed controller sigs
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))  # idempotent
        self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        if sigers:
            self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addPwe(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Kever state: Escrowed partially witnessed "
                     "event = %s\n", serder.ked)


    def state(self, kind=Serials.json):
        """
        Returns Serder instance of current key state notification message

        Parameters:
            kind is serialization kind for message json, cbor, mgpk
        """
        eevt = StateEstEvent(s="{:x}".format(self.lastEst.s),
                             d=self.lastEst.d,
                             br=self.cuts,
                             ba=self.adds)

        cnfg = []
        if self.estOnly:
            cnfg.append(TraitDex.EstOnly)
        if self.doNotDelegate:
            cnfg.append(TraitDex.DoNotDelegate)

        return (state(pre=self.prefixer.qb64,
                      sn=self.sn,
                      pig=(self.serder.ked["p"] if "p" in self.serder.ked else ""),
                      dig=self.serder.dig,
                      fn=self.fn,
                      dts=self.dater.dts,   # need to add dater object for first seen dts
                      eilk=self.ilk,
                      keys=[verfer.qb64 for verfer in self.verfers],
                      eevt=eevt,
                      sith=self.tholder.sith,
                      nxt=self.nexter.qb64 if self.nexter else "",
                      toad=self.toad,
                      wits=self.wits,
                      cnfg = cnfg,
                      dpre=self.delegator,
                      kind=kind
                     )
               )


class Kevery:
    """
    Kevery (Key Event Message Processing Facility) processes an incoming
    message stream composed of KERI key event related messages and attachments.
    Kevery acts a Kever (key event verifier) factory for managing key state of
    KERI identifier prefixes.

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        evts (Deck): of Events i.e. events to process
        cues (Deck):  of Cues i.e. notices of events needing receipt or
                      requests needing response

        .db is instance of LMDB Baser object
        .framed is Boolean stream is packet framed If True Else not framed
        .pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
        lax (bool): True means operate in promiscuous (unrestricted) mode,
                           False means operate in nonpromiscuous (restricted) mode
                              as determined by local and prefixes

        local (bool): True means only process msgs for own events if not lax
                         False means only process msgs for not own events if not lax
        cloned (bool): True means cloned message stream so use attached
                         datetimes from clone source not own.
                         False means use current datetime
        direct (bool): True means direct mode so cue notices for receipts etc
                          False means indirect mode so don't cue notices
        check (bool): True means do not update the database in any
                non-idempotent way. Useful for reinitializing the Kevers from
                a persisted KEL without updating non-idempotent first seen .fels
                and timestamps.


    Properties:
        .kevers is dict of db kevers indexed by pre (qb64) of each Kever
        .prefixes is OrderedSet of fully qualified base64 identifier prefixes of db
            local habitats if any.


    """
    TimeoutOOE = 1200  # seconds to timeout out of order escrows
    TimeoutPSE = 3600  # seconds to timeout partially signed or delegated escrows
    TimeoutPWE = 3600  # seconds to timeout partially witnessed escrows
    TimeoutLDE = 3600  # seconds to timeout likely duplicitous escrows
    TimeoutUWE = 3600  # seconds to timeout unverified receipt escrows
    TimeoutURE = 3600  # seconds to timeout unverified receipt escrows
    TimeoutVRE = 3600  # seconds to timeout unverified transferable receipt escrows


    def __init__(self, *, evts=None, cues=None, db=None,
                 lax=True, local=False, cloned=False, direct=True, check=False):
        """
        Initialize instance:

        Parameters:
            evts (Deck): derived from various messages to be processes
            cues (Deck)  notices to create responses to evts
            kevers is dict of Kever instances of key state in db
            db (Baser): instance of database
            lax (bool): True means operate in promiscuous (unrestricted) mode,
                           False means operate in nonpromiscuous (restricted) mode
                              as determined by local and prefixes
            local (bool): True means only process msgs for own events if not lax
                         False means only process msgs for not own events if not lax
            cloned (bool): True means cloned message stream so use attached
                         datetimes from clone source not own.
                         False means use current datetime
            direct (bool): True means direct mode so cue notices for receipts etc
                          False means indirect mode so don't cue notices
            check (bool): True means do not update the database in any
                non-idempotent way. Useful for reinitializing the Kevers from
                a persisted KEL without updating non-idempotent first seen .fels
                and timestamps.
        """
        self.evts = evts if evts is not None else decking.Deck()  # subclass of deque
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque
        if db is None:
            db = basing.Baser(reopen=True)  # default name = "main"
        self.db = db
        self.lax = True if lax else False  # promiscuous mode
        self.local = True if local else False  # local vs nonlocal restrictions
        self.cloned = True if cloned else False  # process as cloned
        self.direct = True if direct else False  # process as direct mode
        self.check = True if check else False  # process as check mode


    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self.db.kevers


    @property
    def prefixes(self):
        """
        Returns .db.prefixes
        """
        return self.db.prefixes


    def processEvents(self, evts=None):
        """
        Process event dicts in evts or if evts is None in .evts
        Parameters:
            evts (Deck): each entry is dict that matches call signature of
                .processEvent
        """
        if evts is None:
            evts = self.evts

        while evts:
            self.processEvent(**evts.pull())


    def processEvent(self, serder, sigers, *, wigers=None,
                     seqner=None, diger=None,
                     firner=None, dater=None):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:
            serder is Serder instance of event to process
            sigers is list of Siger instances of attached controller indexed sigs
            wigers is optional list of Siger instances of attached witness indexed sigs
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            diger is Diger instance of of delegating event digest.
                If this event is not delegated then diger is ignored
            firner is optional Seqner instance of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater is optional Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
        """
        # fetch ked ilk  pre, sn, dig to see how to process
        ked = serder.ked
        try:  # see if code of pre is supported and matches size of pre
            Prefixer(qb64b=serder.preb)
        except Exception as ex:  # if unsupported code or bad size raises error
            raise ValidationError("Invalid pre = {} for evt = {}."
                                  "".format(serder.pre, ked))
        pre = serder.pre
        ked = serder.ked
        sn = self.validateSN(ked)
        ilk = ked["t"]
        dig = serder.dig

        if not self.lax:  # otherwise in promiscuous mode
            if self.local:
                if pre not in self.prefixes:  # nonlocal event when in local mode
                    raise ValueError("Nonlocal event pre={} not in prefixes={}."
                                "when local mode.".format(pre, self.prefixes))
            else:
                if pre in self.prefixes:  # local event when in nonlocal mode
                    raise ValueError("Local event pre={} in prefixes when "
                                     "nonlocal mode.".format(pre, self.prefixes))


        if pre not in self.kevers:  #  first seen event for pre
            if ilk in (Ilks.icp, Ilks.dip):  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem
                # otherwise adds to KEL
                # create kever from serder
                kever = Kever(serder=serder,
                              sigers=sigers,
                              wigers=wigers,
                              db=self.db,
                              seqner=seqner,
                              diger=diger,
                              firner=firner if self.cloned else None,
                              dater=dater if self.cloned else None,
                              cues=self.cues,
                              prefixes=self.prefixes,
                              local=self.local,
                              check=self.check)
                self.kevers[pre] = kever  # not exception so add to kevers

                if self.direct or self.lax or pre not in self.prefixes:  # not own event when owned
                    # create cue for receipt   direct mode for now
                    #  receipt of actual type is dependent on own type of identifier
                    self.cues.push(dict(kin="receipt", serder=serder))

            else:  # not inception so can't verify sigs etc, add to out-of-order escrow
                self.escrowOOEvent(serder=serder, sigers=sigers,
                                   seqner=seqner, diger=diger)
                raise OutOfOrderError("Out-of-order event={}.".format(ked))

        else:  # already accepted inception event for pre so already first seen
            if ilk in (Ilks.icp, Ilks.dip):  # another inception event so maybe duplicitous
                if sn != 0:
                    raise ValueError("Invalid sn={} for inception event={}."
                                     "".format(sn, serder.ked))
                # check if duplicate of existing inception event since est is icp
                eserder = self.fetchEstEvent(pre, sn)  # latest est evt wrt sn
                if eserder.dig == dig:  # event is a duplicate but not duplicitous
                    # may have attached valid signature not yet logged
                    # raises ValidationError if no valid sig
                    kever = self.kevers[pre]  # get key state
                    # get unique verified lists of sigers and indices from sigers
                    sigers, indices = verifySigs(serder=serder,
                                                 sigers=sigers,
                                                 verfers=eserder.verfers)

                    wigers, windices = verifySigs(serder=serder,
                                                  sigers=wigers,
                                                  verfers=eserder.werfers)

                    if sigers or wigers:  # at least one verified sig or wig so log evt
                        # not first seen inception so ignore return
                        kever.logEvent(serder, sigers=sigers, wigers=wigers)  # idempotent update db logs

                else:   # escrow likely duplicitous event
                    self.escrowLDEvent(serder=serder, sigers=sigers)
                    raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))

            else:  # rot, drt, or ixn, so sn matters
                kever = self.kevers[pre]  # get existing kever for pre
                sno = kever.sn + 1  # proper sn of new inorder event

                if sn > sno:  # sn later than sno so out of order escrow
                    # escrow out-of-order event
                    self.escrowOOEvent(serder=serder, sigers=sigers,
                                       seqner=seqner, diger=diger)
                    raise OutOfOrderError("Out-of-order event={}.".format(ked))

                elif ((sn == sno) or  # new inorder event or recovery
                      (ilk in (Ilks.rot, Ilks.drt) and kever.lastEst.s < sn <= sno )):
                    # verify signatures etc and update state if valid
                    # raise exception if problem.
                    # Otherwise adds to KELs
                    kever.update(serder=serder, sigers=sigers, wigers=wigers,
                                 seqner=seqner, diger=diger,
                                 firner=firner if self.cloned else None,
                                 dater=dater if self.cloned else None,
                                 check=self.check)

                    if self.direct or self.lax or pre not in self.prefixes:  # not own event when owned
                        # create cue for receipt   direct mode for now
                        #  receipt of actual type is dependent on own type of identifier
                        self.cues.push(dict(kin="receipt", serder=serder))

                else:  # maybe duplicitous
                    # check if duplicate of existing valid accepted event
                    ddig = bytes(self.db.getKeLast(key=snKey(pre, sn))).decode("utf-8")
                    if ddig == dig:  # event is a duplicate but not duplicitous
                        eserder = self.fetchEstEvent(pre, sn)  # latest est event wrt sn
                        # may have attached valid signature not yet logged
                        # raises ValidationError if no valid sig
                        kever = self.kevers[pre]
                        # get unique verified lists of sigers and indices from sigers
                        sigers, indices = verifySigs(serder=serder,
                                                     sigers=sigers,
                                                     verfers=eserder.verfers)

                        # only verify wigers if lastest est event of current key state
                        # matches est event of processed event
                        if (eserder.sn == kever.lastEst.s and
                                eserder.dig == kever.lastEst.d):
                            werfers = [Verfer(qb64=wit) for wit in kever.wits]
                            wigers, windices = verifySigs(serder=serder,
                                                          sigers=wigers,
                                                          verfers=werfers)
                        else:
                            wigers = []

                        if sigers or wigers:  # at least one verified sig or wig so log evt
                            # not first seen update so ignore return
                            kever.logEvent(serder, sigers=sigers, wigers=wigers)  # idempotent update db logs

                    else:   # escrow likely duplicitous event
                        self.escrowLDEvent(serder=serder, sigers=sigers)
                        raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))


    def processReceiptWitness(self, serder, wigers):
        """
        Process one witness receipt serder with attached witness sigers

        Parameters:
            serder is Serder instance of serialized receipt message not receipted event
            sigers is list of Siger instances that with witness indexed signatures
                signature in .raw. Index is offset into witness list of latest
                establishment event for receipted event. Signature uses key pair
                derived from nontrans witness prefix in associated witness list.

        Receipt dict labels
            vs  # version string
            pre  # qb64 prefix
            sn  # hex string sequence number
            ilk  # rct
            dig  # qb64 digest of receipted event
        """
        # fetch  pre dig to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        # Only accept receipt if for last seen version of event at sn
        snkey = snKey(pre=pre, sn=sn)
        ldig = self.db.getKeLast(key=snkey)   # retrieve dig of last event at sn.

        if ldig is not None:  #  verify digs match
            ldig = bytes(ldig).decode("utf-8")
            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            raw = bytes(self.db.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none
            lserder = Serder(raw=raw)  # deserialize event raw

            if not lserder.compare(dig=ked["d"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["s"], ked))

            # process each couple verify sig and write to db
            for wiger in wigers:
                # assign verfers from witness list
                kever = self.kevers[pre]  # get key state
                if wiger.index >= len(kever.wits):
                    continue  # skip invalid witness index
                wiger.verfer = Verfer(qb64=kever.wits[wiger.index])  # assign verfer
                if wiger.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid witness prefix

                if not self.lax and wiger.verfer.qb64 in self.prefixes:  # own is receiptor
                    if pre in self.prefixes:  # skip own receiptor of own event
                        # sign own events not receipt them
                        logger.info("Kevery process: skipped own receipt attachment"
                                    " on own event receipt=\n%s\n",serder.pretty())
                        continue  # skip own receipt attachment on own event
                    if not self.local:  # own receipt on other event when not local
                        logger.info("Kevery process: skipped own receipt attachment"
                                " on nonlocal event receipt=\n%s\n", serder.pretty())
                        continue  # skip own receipt attachment on non-local event

                if wiger.verfer.verify(wiger.raw, lserder.raw):
                    # write receipt indexed sig to database
                    self.db.addWig(key=dgkey, val=wiger.qb64b)

        else:  # no events to be receipted yet at that sn so escrow
            # get digest from receipt message not receipted event
            self.escrowUWReceipt(serder=serder, wigers=wigers, dig=ked["d"])
            raise UnverifiedWitnessReceiptError("Unverified witness receipt={}."
                                                "".format(ked))


    def processReceipt(self, serder, cigars):
        """
        Process one receipt serder with attached cigars

        Parameters:
            serder is Serder instance of serialized receipt message not receipted message
            cigars is list of Cigar instances that contain receipt couple
                signature in .raw and public key in .verfer

        Receipt dict labels
            vs  # version string
            pre  # qb64 prefix
            sn  # hex string sequence number
            ilk  # rct
            dig  # qb64 digest of receipted event
        """
        # fetch  pre dig to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        # Only accept receipt if for last seen version of event at sn
        snkey = snKey(pre=pre, sn=sn)
        ldig = self.db.getKeLast(key=snkey)   # retrieve dig of last event at sn.

        if ldig is not None:  #  verify digs match
            ldig = bytes(ldig).decode("utf-8")
            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            raw = bytes(self.db.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none
            lserder = Serder(raw=raw)  # deserialize event raw

            if not lserder.compare(dig=ked["d"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["s"], ked))

            # process each couple verify sig and write to db
            for cigar in cigars:
                if cigar.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid couplets

                if not self.lax and cigar.verfer.qb64 in self.prefixes: # own is receiptor
                    if pre in self.prefixes:  # skip own receipter of own event
                        # sign own events not receipt them
                        logger.info("Kevery process: skipped own receipt attachment"
                                    " on own event receipt=\n%s\n", serder.pretty())
                        continue  # skip own receipt attachment on own event
                    if not self.local:  # own receipt on other event when not local
                        logger.info("Kevery process: skipped own receipt attachment"
                                " on nonlocal event receipt=\n%s\n", serder.pretty())
                        continue  # skip own receipt attachment on non-local event

                if cigar.verfer.verify(cigar.raw, lserder.raw):
                    kever = self.kevers[pre]  # get key state to check if witness
                    rpre = cigar.verfer.qb64  # prefix of receiptor
                    if rpre in kever.wits:  # its a witness receipt
                        index = kever.wits.index(rpre)
                        # create witness indexed signature
                        wiger = Siger(raw=cigar.raw, index=index, verfer=cigar.verfer)
                        self.db.addWig(key=dgkey, val=wiger.qb64b)  # write to db
                    else:  # write receipt couple to database
                        couple = cigar.verfer.qb64b + cigar.qb64b
                        self.db.addRct(key=dgkey, val=couple)

        else:  # no events to be receipted yet at that sn so escrow
            self.escrowUReceipt(serder, cigars, dig=ked["d"])  # digest in receipt
            raise UnverifiedReceiptError("Unverified receipt={}.".format(ked))


    def processReceiptCouples(self, serder, cigars, firner=None):
        """
        Process replay event serder with attached cigars for attached receipt couples.

        Parameters:
            serder is Serder instance of receipted serialized event message
                to which receipts are attached from replay
            cigars is list of Cigar instances that contain receipt couple
                signature in .raw and public key in .verfer
            firner is Seqner instance of first seen ordinal,
                if provided lookup event by fn = firner.sn

        """
        # fetch  pre dig to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        # Only accept receipt if event is latest event at sn. Means its been
        # first seen and is the most recent first seen with that sn
        if firner:
            ldig = self.db.getFe(key=fnKey(pre=pre, sn=firner.sn))
        else:
            ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.

        if ldig is None:  # escrow because event does not yet exist in database
            # # take advantage of fact that receipt and event have same pre, sn fields
            self.escrowUReceipt(serder, cigars, dig=serder.dig)  # digest in receipt
            raise UnverifiedReceiptError("Unverified receipt={}.".format(ked))

        ldig = bytes(ldig).decode("utf-8")  # verify digs match
        # retrieve event by dig assumes if ldig is not None that event exists at ldig

        if not serder.compare(dig=ldig):  # mismatch events problem with replay
            raise ValidationError("Mismatch replay event at sn = {} with db."
                                  "".format(ked["s"]))

        # process each couple to verify sig and write to db
        for cigar in cigars:
            if cigar.verfer.transferable:  # skip transferable verfers
                continue  # skip invalid couplets
            if not self.lax and cigar.verfer.qb64 in self.prefixes:  # own is receiptor
                if pre in self.prefixes:  # skip own receipter on own event
                    # sign own events not receipt them
                    logger.info("Kevery process: skipped own receipt attachment"
                                " on own event receipt=\n%s\n", serder.pretty())
                    continue  # skip own receipt attachment on own event
                if not self.local:  # own receipt on other event when not local
                    logger.info("Kevery process: skipped own receipt attachment"
                            " on nonlocal event receipt=\n%s\n", serder.pretty())
                    continue  # skip own receipt attachment on non-local event

            if cigar.verfer.verify(cigar.raw, serder.raw):
                kever = self.kevers[pre]  # get key state to check if witness
                rpre = cigar.verfer.qb64  # prefix of receiptor
                if rpre in kever.wits:  # its a witness receipt
                    index = kever.wits.index(rpre)
                    # create witness indexed signature and write to db
                    wiger = Siger(raw=cigar.raw, index=index, verfer=cigar.verfer)
                    self.db.addWig(key=dgKey(pre, ldig), val=wiger.qb64b)
                else:  # write receipt couple to database
                    couple = cigar.verfer.qb64b + cigar.qb64b
                    self.db.addRct(key=dgKey(pre, ldig), val=couple)


    def processReceiptTrans(self, serder, tsgs):
        """
        Process one transferable validator receipt (chit) serder with attached sigers

        Parameters:
            serder is chit serder (transferable validator receipt message)
            tsgs is tist of tuples from extracted transferable indexed sig groups
                each converted group is tuple of (i,s,d) triple plus list of sigs

        Receipt dict labels
            vs  # version string
            pre  # qb64 prefix
            sn  # hex string sequence number
            ilk  # rct
            dig  # qb64 digest of receipted event

        """
        # fetch  pre, dig,seal to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        # Only accept receipt if for last seen version of event at sn
        ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.

        if ldig is None:  # escrow because event does not yet exist in database
            # take advantage of fact that receipt and event have same pre, sn fields
            self.escrowTRGroups(serder, tsgs)
            raise UnverifiedTransferableReceiptError("Unverified receipt={}.".format(ked))

        # retrieve event by dig assumes if ldig is not None that event exists at ldig
        ldig = bytes(ldig).decode("utf-8")
        lraw = self.db.getEvt(key=dgKey(pre=pre, dig=ldig))
        lserder = Serder(raw=bytes(lraw))
         # verify digs match
        if not lserder.compare(dig=ldig):  # mismatch events problem with replay
            raise ValidationError("Mismatch receipt of event at sn = {} with db."
                                  "".format(sn))

        for sprefixer, sseqner, sdiger, sigers in tsgs:  # iterate over each tsg
            if not self.lax and sprefixer.qb64 in self.prefixes:  # own is receipter
                if pre in self.prefixes:  # skip own receipter of own event
                    # sign own events not receipt them
                    raise ValidationError("Own pre={} receipter of own event"
                                          " {}.".format(self.prefixes, serder.pretty()))
                if not self.local:  # skip own receipts of nonlocal events
                    raise ValidationError("Own pre={} receipter of nonlocal event "
                                          "{}.".format(self.prefixes, serder.pretty()))

            if sprefixer.qb64 in self.kevers:
                # receipted event and receipter in database so get receipter est evt
                # retrieve dig of last event at sn of est evt of receipter.
                sdig = self.db.getKeLast(key=snKey(pre=sprefixer.qb64b,
                                                      sn=sseqner.sn))
                if sdig is None:
                    # receipter's est event not yet in receipters's KEL
                    self.escrowTReceipts(serder, sprefixer, sseqner, sdiger, sigers)
                    raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                        "missing establishment event of transferable "
                                        "receipter for event={}."
                                        "".format(ked))


                # retrieve last event itself of receipter est evt from sdig
                sraw = self.db.getEvt(key=dgKey(pre=sprefixer.qb64b, dig=bytes(sdig)))
                # assumes db ensures that sraw must not be none because sdig was in KE
                sserder = Serder(raw=bytes(sraw))
                if not sserder.compare(diger=sdiger):  # endorser's dig not match event
                    raise ValidationError("Bad trans indexed sig group at sn = {}"
                                          " for ksn = {}."
                                          "".format(sseqner.sn, sserder.ked))

                #verify sigs and if so write receipt to database
                sverfers = sserder.verfers
                if not sverfers:
                    raise ValidationError("Invalid key state endorser's est. event"
                                          " dig = {} for ksn from pre ={}, "
                                          "no keys."
                                          "".format(sdiger.qb64, sprefixer.qb64))

                for siger in sigers:
                    if siger.index >= len(sverfers):
                        raise ValidationError("Index = {} to large for keys."
                                                  "".format(siger.index))
                    siger.verfer = sverfers[siger.index]  # assign verfer
                    if siger.verfer.verify(siger.raw, lserder.raw):  # verify sig
                        # good sig so write receipt quadruple to database
                        quadruple = sprefixer.qb64b + sseqner.qb64b + sdiger.qb64b + siger.qb64b
                        self.db.addVrc(key=dgKey(pre=pre, dig=ldig),
                                       val=quadruple)  # dups kept


    def processReceiptQuadruples(self, serder, trqs, firner=None):
        """
        Process one transferable validator receipt (chit) serder with attached sigers

        Parameters:
            serder is chit serder (transferable validator receipt message)
            trqs is list of tuples (quadruples) of form
                (prefixer, seqner, diger, siger)
            firner is Seqner instance of first seen ordinal,
               if provided lookup event by fn = firner.sn

        Seal labels
            i pre  # qb64 prefix of receipter
            s sn   # hex of sequence number of est event for receipter keys
            d dig  # qb64 digest of est event for receipter keys

        """
        # fetch  pre, dig,seal to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        if firner:  # retrieve last event by fn ordinal
            ldig = self.db.getFe(key=fnKey(pre=pre, sn=firner.sn))
        else:
            # Only accept receipt if for last seen version of receipted event at sn
            ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.

        for sprefixer, sseqner, sdiger, siger in trqs:  # iterate over each trq
            if not self.lax and sprefixer.qb64 in self.prefixes:  # own trans receipt quadruple (chit)
                if pre in self.prefixes:  # skip own trans receipts of own events
                    raise ValidationError("Own pre={} replay attached transferable "
                                          "receipt quadruple of own event {}."
                                      "".format(self.prefixes, serder.pretty()))
                if not self.local:  # skip own trans receipt quadruples of nonlocal events
                    raise ValidationError("Own pre={} seal in replay attached "
                                          "transferable receipt quadruples of nonlocal"
                                          " event {}.".format(self.prefixes, serder.pretty()))

            if ldig is not None and sprefixer.qb64 in self.kevers:
                # both receipted event and receipter in database so retreive
                if isinstance(ldig, memoryview):
                    ldig = bytes(ldig).decode("utf-8")

                if not serder.compare(dig=ldig):  # mismatch events problem with replay
                    raise ValidationError("Mismatch replay event at sn = {} with db."
                                          "".format(ked["s"]))

                # retrieve dig of last event at sn of receipter.
                sdig = self.db.getKeLast(key=snKey(pre=sprefixer.qb64b,
                                                      sn=sseqner.sn))
                if sdig is None:
                    # receipter's est event not yet in receipter's KEL
                    # receipter's seal event not in receipter's KEL
                    self.escrowTRQuadruple(serder, sprefixer, sseqner, sdiger, siger)
                    raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                        "missing establishment event of transferable "
                                        "validator receipt quadruple for event={}."
                                        "".format(ked))

                # retrieve last event itself of receipter
                sraw = self.db.getEvt(key=dgKey(pre=sprefixer.qb64b, dig=bytes(sdig)))
                # assumes db ensures that sraw must not be none because sdig was in KE
                sserder = Serder(raw=bytes(sraw))
                if not sserder.compare(diger=sdiger):  # seal dig not match event
                    raise ValidationError("Bad trans receipt quadruple at sn = {}"
                                          " for rct = {}."
                                          "".format(sseqner.sn, sserder.ked))

                #verify sigs and if so write quadruple to database
                sverfers = sserder.verfers
                if not sverfers:
                    raise ValidationError("Invalid trans receipt quad est. event"
                                          " dig = {} for receipt from pre ={}, "
                                          "no keys."
                                          "".format(sdiger.qb64, sprefixer.qb64))

                if siger.index >= len(sverfers):
                    raise ValidationError("Index = {} to large for keys."
                                              "".format(siger.index))

                siger.verfer = sverfers[siger.index]  # assign verfer
                if not siger.verfer.verify(siger.raw, serder.raw):  # verify sig
                    logger.info("Kevery unescrow error: Bad trans receipt sig."
                             "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                    raise ValidationError("Bad escrowed trans receipt sig at "
                                          "pre={} sn={:x} receipter={}."
                                          "".format(pre, sn, sprefixer.qb64))

                # good sig so write receipt quadruple to database

                # Set up quadruple
                quadruple = sprefixer.qb64b + sseqner.qb64b + sdiger.qb64b + siger.qb64b
                self.db.addVrc(key=dgKey(pre, serder.dig), val=quadruple)


            else:  # escrow  either receiptor or receipted event not yet in database
                self.escrowTRQuadruple(serder, sprefixer, sseqner, sdiger, siger)
                raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                      "missing associated event for transferable "
                                      "validator receipt quadruple for event={}."
                                      "".format(ked))


    def processKeyStateNotice(self, serder, cigars=None, tsgs=None):
        """
        Process one key state notification with attached nontrans receipt couples
        in cigars and/or attached trans indexed sig groups in tsgs

        Parameters:
            serder is receipt serder
            cigars is list of Cigar instances that contain receipt couple
                signature in .raw and public key in .verfer
            tsgs is list of tuples (quadruples) of form
                (prefixer, seqner, diger, [sigers]) where
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                [sigers] is list of indexed sigs from trans endorser's keys from est evt

        """
        for k in KSN_LABELS:
            if k not in serder.ked:
                raise ValidationError("Missing element = {} from {} event."
                                      " evt = {}.".format(k, Ilks.ksn,
                                                          serder.pretty()))
        # fetch from serder to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        """
        Discussion

        key state acceptance mode needs to be defined.
        unconfirmed but trusted key state:
           from trusted endorsers we accept if endorsed. Need list of trusted
           trusted endorsers
        confirmed key state:
           from any endorser, endorser sig provides duplicity
        detection of malicious endorsers. We drope key state message if its
        digest does not match agains its KEL stored locally and escrow key state
        message if its local KEL is incomplete.
        need to change logic below

         may want to separate into two different functions one for unconfirmed
         keystate notices from trusted endorsers (always authenticate endorser)

         two classes of escrow. May be staged.
         1) Endorser is transferable and we do not have
         KEL of endorser so can't verify its signature yet
         2) Endorser is untrusted and we do not have KEL of keystate notice so
         can't confirm that keystate is matches local copy of KEL

        Start with authorized watchers (endorsers) in .wats database. This is
        for Judge application also for standard controller need to lookup
        So each Habitat has a .watchers .wats set The set is persisted in an
        applicaton database of application configuration data. So for ordered list
        use ordinal

        Also authorized by default are witnesses if habitat is one that has
        witnesses so watcher set could default to witness set.

        Need to define the workflow
        request keystate from watcher in order to verifiy siganture of some XX
        truster watcher keystate so download KEL
        once KEL downloaded then verify


        """

        # Only accept key state if for last seen version of event at sn
        ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.


        if ldig is None:  # escrow because event does not yet exist in database
            # # take advantage of fact that receipt and event have same pre, sn fields
            pass

            #self.escrowUREvent(serder, cigars, dig=serder.dig)  # digest in receipt
            #raise UnverifiedReceiptError("Unverified receipt={}.".format(ked))

        ldig = bytes(ldig).decode("utf-8")  # verify digs match
        # retrieve event by dig assumes if ldig is not None that event exists at ldig

        if not serder.compare(dig=ldig):  # mismatch events problem with replay
            raise ValidationError("Mismatch keystate at sn = {} with db."
                                  "".format(ked["s"]))

        # process each couple to verify sig and write to db
        for cigar in cigars:
            if cigar.verfer.transferable:  # skip transferable verfers
                continue  # skip invalid couplets
            if not self.lax and cigar.verfer.qb64 in self.prefixes:  # own receipt when own nontrans
                if pre in self.prefixes:  # own receipt attachment on own event
                    logger.info("Kevery process: skipped own receipt attachment"
                                " on own event receipt=\n%s\n", serder.pretty())
                    continue  # skip own receipt attachment on own event
                if not self.local:  # own receipt on other event when not local
                    logger.info("Kevery process: skipped own receipt attachment"
                            " on nonlocal event receipt=\n%s\n", serder.pretty())
                    continue  # skip own receipt attachment on non-local event

            if cigar.verfer.verify(cigar.raw, serder.raw):
                # write receipt couple to database
                couple = cigar.verfer.qb64b + cigar.qb64b
                self.db.addRct(key=dgKey(pre=pre, dig=ldig), val=couple)

        for sprefixer, sseqner, sdiger, sigers in tsgs:  # iterate over each tsg
            if not self.lax and sprefixer.qb64 in self.prefixes:  # own endorsed ksn
                if pre in self.prefixes:  # skip own endorsed ksn
                    raise ValidationError("Own endorsement pre={} of own key"
                        " state notifiction {}.".format(self.prefixes, serder.pretty()))
                if not self.local:  # skip own nonlocal ksn
                    raise ValidationError("Own endorsement pre={}  "
                                          "of nonlocal key state notification "
                                    "{}.".format(self.prefixes, serder.pretty()))

            if ldig is not None and sprefixer.qb64 in self.kevers:
                # both key state event and endorser in database so retreive
                if isinstance(ldig, memoryview):
                    ldig = bytes(ldig).decode("utf-8")

                if not serder.compare(dig=ldig):  # mismatch events problem with replay
                    raise ValidationError("Mismatch replay event at sn = {} with db."
                                          "".format(ked["s"]))

                # retrieve dig of last event at sn of endorser.
                sdig = self.db.getKeLast(key=snKey(pre=sprefixer.qb64b,
                                                      sn=sseqner.sn))
                if sdig is None:
                    # endorser's est event not yet in endorser's KEL
                    #  do we escrow key state notifications ?
                    pass
                    #self.escrowVRQuadruple(serder, sprefixer, sseqner, sdiger, siger)
                    #raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                        #"missing establishment event of transferable "
                                        #"validator receipt quadruple for event={}."
                                        #"".format(ked))

                # retrieve last event itself of endorser
                sraw = self.db.getEvt(key=dgKey(pre=sprefixer.qb64b, dig=bytes(sdig)))
                # assumes db ensures that sraw must not be none because sdig was in KE
                sserder = Serder(raw=bytes(sraw))
                if not sserder.compare(diger=sdiger):  # endorser's dig not match event
                    raise ValidationError("Bad trans indexed sig group at sn = {}"
                                          " for ksn = {}."
                                          "".format(sseqner.sn, sserder.ked))

                #verify sigs and if so write keystate to database
                sverfers = sserder.verfers
                if not sverfers:
                    raise ValidationError("Invalid key state endorser's est. event"
                                          " dig = {} for ksn from pre ={}, "
                                          "no keys."
                                          "".format(sdiger.qb64, sprefixer.qb64))



                for siger in sigers:
                    if siger.index >= len(sverfers):
                        raise ValidationError("Index = {} to large for keys."
                                                  "".format(siger.index))
                    siger.verfer = sverfers[siger.index]  # assign verfer
                    if not siger.verfer.verify(siger.raw, serder.raw):  # verify sig
                        logger.info("Kevery unescrow error: Bad trans receipt sig."
                                 "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                        raise ValidationError("Bad escrowed trans receipt sig at "
                                              "pre={} sn={:x} receipter={}."
                                              "".format(pre, sn, sprefixer.qb64))

                    # good sig so write ksn to database

                    # Set up quadruple
                    #quadruple = sprefixer.qb64b + sseqner.qb64b + sdiger.qb64b + siger.qb64b
                    #self.db.addVrc(key=dgKey(pre, serder.dig), val=quadruple)


            else:  # escrow  either endorser or key stated event not yet in database
                pass
                #self.escrowVRQuadruple(serder, sprefixer, sseqner, sdiger, siger)
                #raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                      #"missing associated event for transferable "
                                      #"validator receipt quadruple for event={}."
                                      #"".format(ked))

    def processQuery(self, serder, src=None, sigers=None):
        """
        Process query mode replay message for collective or single element query.
        Assume promiscuous mode for now.

        Parameters:
            serder (Serder) is query message serder
            src (qb64) identifier prefix of event sender
            sigers (list) of Siger instances of attached controller indexed sigs

        """
        ked = serder.ked

        ilk = ked["t"]
        res = ked["r"]
        qry = ked["q"]

        if res == "logs":
            pre = qry["i"]
            cloner = self.db.clonePreIter(pre=pre, fn=0)  # create iterator at 0
            msgs = bytearray()  # outgoing messages
            for msg in cloner:
                msgs.extend(msg)

            self.cues.push(dict(kin="replay", msgs=msgs, dest=src))
        else:
            raise ValidationError("invalid query message {} for evt = {}".format(ilk, ked))



    def validateSN(self, ked):
        """
        Returns int validated from hex str sn in ked

        Parameters:
           sn is hex char sequence number of event or seal in an event
           ked is key event dict of associated event
        """
        sn = ked["s"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large for evt = {}."
                                  "".format(sn, ked))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {} for evt = {}.".format(sn, ked))

        return sn


    def fetchEstEvent(self, pre, sn):
        """
        Returns Serder instance of establishment event that is authoritative for
        event in KEL for pre at sn.
        Returns None if no event at sn accepted in KEL for pre

        Parameters:
            pre is qb64 of identifier prefix for KEL
            sn is int sequence number of event in KEL of pre
        """

        found = False
        while not found:
            dig = bytes(self.db.getKeLast(key=snKey(pre, sn)))
            if not dig:
                return None

            # retrieve event by dig
            raw = bytes(self.db.getEvt(key=dgKey(pre=pre, dig=dig)))
            if not raw:
                return None

            serder = Serder(raw=raw)  # deserialize event raw
            if serder.ked["t"] in (Ilks.icp, Ilks.dip, Ilks.rot, Ilks.drt):
                return serder  # establishment event so return

            sn = int(serder.ked["s"], 16) - 1  # set sn to previous event
            if sn < 0: # no more events
                return None


    def escrowOOEvent(self, serder, sigers, seqner=None, diger=None):
        """
        Update associated logs for escrow of Out-of-Order event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
            seqner is Seqner instance of sn of event delegatint/issuing event if any
            diger is Diger instance of dig of event delegatint/issuing event if any
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addOoe(snKey(serder.preb, serder.sn), serder.digb)
        if seqner and diger:
            couple = seqner.qb64b + diger.qb64b
            self.db.putPde(dgkey, couple)   # idempotent
        # log escrowed
        logger.info("Kevery process: escrowed out of order event=\n%s\n",
                                      json.dumps(serder.ked, indent=1))


    def escrowLDEvent(self, serder, sigers):
        """
        Update associated logs for escrow of Likely Duplicitous event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addLde(snKey(serder.preb, serder.sn), serder.digb)
        # log duplicitous
        logger.info("Kevery process: escrowed likely duplicitous event=\n%s\n",
                                            json.dumps(serder.ked, indent=1))


    def escrowUWReceipt(self, serder, wigers, dig):
        """
        Update associated logs for escrow of Unverified Event Witness Receipt
        (non-transferable)
        Escrowed value is couple edig+wig where:
           edig is receipted event dig not serder.dig
           wig is witness indexed signature on receipted event with key pair
                derived from witness nontrans identifier prefix in witness list.
                Index is offset into witness list of latest establishment event
                for receipted event.

        Parameters:
            serder instance of receipt msg not receipted event
            wigers is list of Siger instances for witness indexed signature
                of receipted event
            dig is digest of receipted event not serder.dig because
                serder is a receipt not the receipted event
        """
        # note receipt dig algo may not match database dig also so must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to include dig
        # so can compare digs from receipt and in database for receipted event
        # with different algos.  Can't lookup event by dig for same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, dig), helping.nowIso8601().encode("utf-8"))
        for wiger in wigers:  # escrow each couple
            # don't know witness pre yet without witness list so no verfer in wiger
            #if wiger.verfer.transferable:  # skip transferable verfers
                #continue  # skip invalid triplets
            couple = dig.encode("utf-8") + wiger.qb64b
            self.db.addUwe(key=snKey(serder.preb, serder.sn), val=couple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified witness indexed receipt"
                    " of pre= %s sn=%x dig=%s\n", serder.pre, serder.sn, dig)



    def escrowUReceipt(self, serder, cigars, dig):
        """
        Update associated logs for escrow of Unverified Event Receipt (non-transferable)
        Escrowed value is triple edig+rpre+cig where:
           edig is event dig
           rpre is nontrans receiptor prefix
           cig is non-indexed signature on event with key pair derived from rpre

        Parameters:
            serder instance of receipt msg not receipted event
            cigars is list of Cigar instances for event receipt
            dig is digest in receipt of receipted event not serder.dig because
                serder is of receipt not receipted event
        """
        # note receipt dig algo may not match database dig also so must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to include dig
        # so can compare digs from receipt and in database for receipted event
        # with different algos.  Can't lookup event by dig for same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, dig), helping.nowIso8601().encode("utf-8"))
        for cigar in cigars:  # escrow each triple
            if cigar.verfer.transferable:  # skip transferable verfers
                continue  # skip invalid triplets
            triple = dig.encode("utf-8") + cigar.verfer.qb64b + cigar.qb64b
            self.db.addUre(key=snKey(serder.preb, serder.sn), val=triple)  # should be snKey
        # log escrowed
        logger.info("Kevery process: escrowed unverified receipt of pre= %s "
                     " sn=%x dig=%s\n", serder.pre, serder.sn, dig)


    def escrowTRGroups(self, serder, tsgs):
        """
        Update associated logs for escrow of Transferable Receipt Groups for
        event (transferable)

        Parameters:
            serder instance of receipt message not receipted event
            tsgs is list of tuples of form: (prefixer,seqner,diger, sigers)
                prefixer is Prefixer instance of prefix of receipter
                seqner is Seqner instance of  sn of est event of receiptor
                diger is Diger instance of digest of est event of receiptor
                sigers is list of Siger instances of multi-sig of receiptor

        escrow quintuple for each siger
            quintuple = edig+pre+snu+dig+sig
            where:
                edig is receipted event dig (serder.dig)
                pre is receipter prefix
                snu is receipter est event sn
                dig is receipt est evant dig
                sig is indexed sig of receiptor of receipted event
        """
        # Receipt dig algo may not match database dig. So must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to be quintuple with
        # edig, validator prefix, validtor est event sn, validator est evvent dig
        # and sig stored at kel pre, sn so can compare digs
        # with different algos.  Can't lookup by dig for the same reason. Must
        # lookup last event by sn not by dig.
        for tsg in tsgs:
            prefixer, seqner, diger, sigers = tsg
            self.db.putDts(dgKey(serder.preb, serder.digb), helping.nowIso8601().encode("utf-8"))
            # since serder of of receipt not receipted event must use dig in
            # serder.ked["d"] not serder.dig
            prelet = (serder.ked["d"].encode("utf-8") + prefixer.qb64b +
                      seqner.qb64b + diger.qb64b)
            for siger in sigers:  # escrow each quintlet
                quintuple = prelet + siger.qb64b  # quintuple
                self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
            # log escrowed
            logger.info("Kevery process: escrowed unverified transferable receipt "
                         "of pre=%s sn=%x dig=%s by pre=%s\n", serder.pre,
                             serder.sn, serder.ked["d"], prefixer.qb64)


    def escrowTReceipts(self, serder, prefixer, seqner, diger, sigers):
        """
        Update associated logs for escrow of Transferable Event Receipt Group
        (transferable)

        Parameters:
            serder instance of receipt message not receipted event
            prefixer is Prefixer instance of prefix of receipter
            seqner is Seqner instance of  sn of est event of receiptor
            diger is Diger instance of digest of est event of receiptor
            igers is list of Siger instances of multi-sig of receiptor

        escrow quintuple for each siger
            quintuple = edig+pre+snu+dig+sig
            where:
                edig is receipted event dig (serder.dig)
                pre is receipter prefix
                snu is receipter est event sn
                dig is receipt est evant dig
                sig is indexed sig of receiptor of receipted event
        """
        # Receipt dig algo may not match database dig. So must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to be quintuple with
        # edig, validator prefix, validtor est event sn, validator est evvent dig
        # and sig stored at kel pre, sn so can compare digs
        # with different algos.  Can't lookup by dig for the same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, serder.digb), helping.nowIso8601().encode("utf-8"))
        # since serder of of receipt not receipted event must use dig in
        # serder.ked["d"] not serder.dig
        prelet = (serder.ked["d"].encode("utf-8") + prefixer.qb64b +
                  seqner.qb64b + diger.qb64b)
        for siger in sigers:  # escrow each quintlet
            quintuple = prelet + siger.qb64b  # quintuple
            self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified transferable receipt "
                     "of pre=%s sn=%x dig=%s by pre=%s\n", serder.pre,
                         serder.sn, serder.ked["d"], prefixer.qb64)


    def escrowTRQuadruple(self, serder, sprefixer, sseqner, sdiger, siger):
        """
        Update associated logs for escrow of Unverified Transferable Receipt
        (transferable)

        escrow quintuple made from quadruple where:
            quadruple = spre+ssnu+sdig+sig  (s is trans receipt signer)
            quintuple = edig+spre+ssnu+sdig+sig  (edig is signed event digest)

        Parameters:
            serder instance of receipt message not receipted event
            sigers is list of Siger instances attached to receipt message
            seal is SealEvent instance (namedTuple)
            dig is digest of receipted event provided in receipt

        """
        # Receipt dig algo may not match database dig. So must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to be quintuple with
        # edig, validator prefix, validtor est event sn, validator est evvent dig
        # and sig stored at kel pre, sn so can compare digs
        # with different algos.  Can't lookup by dig for the same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, serder.dig), helping.nowIso8601().encode("utf-8"))
        quintuple = (serder.digb + sprefixer.qb64b + sseqner.qb64b +
                     sdiger.qb64b + siger.qb64b)
        self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified transferabe validator "
                     "receipt of pre= %s sn=%x dig=%s\n", serder.pre, serder.sn,
                     serder.dig)


    def processEscrows(self):
        """
        Iterate throush escrows and process any that may now be finalized

        Parameters:
        """

        try:
            self.processEscrowOutOfOrders()
            self.processEscrowUnverWitness()
            self.processEscrowUnverNonTrans()
            self.processEscrowUnverTrans()
            self.processEscrowPartialWigs()
            self.processEscrowPartialSigs()
            self.processEscrowDuplicitous()


        except Exception as ex:  # log diagnostics errors etc
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Kevery escrow process error: %s\n", ex.args[0])
            else:
                logger.error("Kevery escrow process error: %s\n", ex.args[0])


    def processEscrowOutOfOrders(self):
        """
        Process events escrowed by Kever that are recieved out-of-order.
        An event is out of order if its prior event has not been accepted into its KEL.
        Without the prior event there is no way to know the key state and therefore no way
        to verify signatures on the out-of-order event.

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different dig inserted in insertion order.
        This allows FIFO processing of events with same prefix and sn but different
        digest.

        Uses  .db.addOoe(self, key, val) which is IOVal with dups.

        Value is dgkey for event stored in .Evt where .Evt has serder.raw of event.

        Original Escrow steps:
            dgkey = dgKey(pre, serder.dig)
            self.db.putDts(dgkey, nowIso8601().encode("utf-8"))
            self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
            self.db.putEvt(dgkey, serder.raw)
            self.db.addOoe(snKey(pre, sn), serder.dig)
            where:
                serder is Serder instance of  event
                sigers is list of Siger instance for  event
                pre is str qb64 of identifier prefix of event
                sn is int sequence number of event

        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        Get and Attach Signatures
                        Process event as if it came in over the wire
                        If successful then remove from escrow table
        """

        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getOoeItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow item
                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(edig)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(bytes(edig)))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutOOE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(bytes(edig)))

                    # get the escrowed event using edig
                    eraw = self.db.getEvt(dgKey(pre, bytes(edig)))
                    if eraw is None:
                        # no event so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt at dig = {}."
                                              "".format(bytes(edig)))

                    eserder = Serder(raw=bytes(eraw))  # escrowed event

                    #  get sigs and attach
                    sigs = self.db.getSigs(dgKey(pre, bytes(edig)))
                    if not sigs:  #  otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in  sigs]
                    self.processEvent(serder=eserder, sigers=sigers)

                    # If process does NOT validate event with sigs, becasue it is
                    # still out of order then process will attempt to re-escrow
                    # and then raise OutOfOrderError (subclass of ValidationError)
                    # so we can distinquish between ValidationErrors that are
                    # re-escrow vs non re-escrow. We want process to be idempotent
                    # with respect to processing events that result in escrow items.
                    # On re-escrow attempt by process, Ooe escrow is called by
                    # Kevery.self.escrowOOEvent Which calls
                    # self.db.addOoe(snKey(pre, sn), serder.digb)
                    # which in turn will not enter dig as dup if one already exists.
                    # So re-escrow attempt will not change the escrowed ooe db.
                    # Non re-escrow ValidationError means some other issue so unescrow.
                    # No error at all means processed successfully so also unescrow.

                except OutOfOrderError as ex:
                    # still waiting on missing prior event to validate
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than out of order so remove from OO escrow
                    self.db.delOoe(snKey(pre, sn), edig)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delOoe(snKey(pre, sn), edig)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded in valid event: "
                             "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey



    def processEscrowPartialSigs(self):
        """
        Process events escrowed by Kever that were only partially fulfilled,
        either due to missing signatures or missing dependent events like a
        delegating event.  But event has at least one verified signature.

        Escrowed items are indexed in database table keyed by prefix and
        sequence number with duplicates inserted in insertion order. This allows
        FIFO processing of events with same prefix and sn.
        Uses  .db.addPse(self, key, val) which is IOVal with dups.

        Value is dgkey for event stored in .Evt where .Evt has serder.raw of event.

        Original Escrow steps:
            dgkey = dgKey(pre, serder.digb)
            .db.putDts(dgkey, nowIso8601().encode("utf-8"))
            .db.putSigs(dgkey, [siger.qb64b for siger in sigers])
            .db.putEvt(dgkey, serder.raw)
            .db.addPse(snKey(pre, sn), serder.digb)
            where:
                serder is Serder instance of  event
                sigers is list of Siger instance for  event
                pre is str qb64 of identifier prefix of event
                sn is int sequence number of event

        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        Get and Attach Signatures
                        Process event as if it came in over the wire
                        If successful then remove from escrow table
        """

        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getPseItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow item
                    dgkey = dgKey(pre, bytes(edig))
                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgkey)
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(bytes(edig)))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutPSE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(bytes(edig)))

                    # get the escrowed event using edig
                    eraw = self.db.getEvt(dgkey)
                    if eraw is None:
                        # no event so so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt at dig = {}."
                                              "".format(bytes(edig)))

                    eserder = Serder(raw=bytes(eraw))  # escrowed event
                    #  get sigs and attach
                    sigs = self.db.getSigs(dgkey)
                    if not sigs:  #  otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    # seal source (delegator issuer if any)
                    seqner = diger = None
                    couple = self.db.getPde(dgkey)
                    if couple is not None:
                        seqner, diger = deSourceCouple(couple)

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in  sigs]
                    self.processEvent(serder=eserder, sigers=sigers,
                                      seqner=seqner, diger=diger)

                    # If process does NOT validate sigs or delegation seal (when delegated),
                    # but there is still one valid signature then process will
                    # attempt to re-escrow and then raise MissingSignatureError
                    # or MissingDelegationSealError (subclass of ValidationError)
                    # so we can distinquish between ValidationErrors that are
                    # re-escrow vs non re-escrow. We want process to be idempotent
                    # with respect to processing events that result in escrow items.
                    # On re-escrow attempt by process, Pse escrow is called by
                    # Kever.self.escrowPSEvent Which calls
                    # self.db.addPse(snKey(pre, sn), serder.digb)
                    # which in turn will not enter dig as dup if one already exists.
                    # So re-escrow attempt will not change the escrowed pse db.
                    # Non re-escrow ValidationError means some other issue so unescrow.
                    # No error at all means processed successfully so also unescrow.

                except (MissingSignatureError, MissingDelegationError) as ex:
                    # still waiting on missing sigs or missing seal to validate
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than waiting on sigs or seal so remove from escrow
                    self.db.delPse(snKey(pre, sn), edig)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delPse(snKey(pre, sn), edig)  # removes one escrow at key val
                    self.db.delPde(dgkey)  # remove escrow if any
                    logger.info("Kevery unescrow succeeded in valid event: "
                             "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey


    def processEscrowPartialWigs(self):
        """
        Process events escrowed by Kever that were only partially fulfilled
        due to missing signatures from witnesses. Events only make into this
        escrow after fully signed and if delegated, delegation has been verified.

        Escrowed items in .pwes are indexed in database table keyed by prefix and
        sequence number with duplicates inserted in insertion order. This allows
        FIFO processing of events with same prefix and sn.
        Reads db.pwes .db.getPwe put there by  .db.addPwe(self, key, val)
            which is IOVal with dups.

        Value is dgkey for event stored in .Evt where .Evt has serder.raw of event.

        Original Escrow steps:
            dgkey = dgKey(pre, serder.digb)
            .db.putDts(dgkey, nowIso8601().encode("utf-8"))
            .db.putWigs(dgkey, [siger.qb64b for siger in sigers])
            .db.putEvt(dgkey, serder.raw)
            .db.addPwe(snKey(pre, sn), serder.digb)
            where:
                serder is Serder instance of  event
                wigers is list of Siger instance for of witnesses of event
                pre is str qb64 of identifier prefix of event
                sn is int sequence number of event

        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        Get and Attach Signatures
                        Get and Attach Witness Signatures
                        Process event as if it came in over the wire
                        If successful then remove from escrow table
        """

        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getPweItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow item
                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(edig)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(bytes(edig)))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutPWE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(bytes(edig)))

                    # get the escrowed event using edig
                    eraw = self.db.getEvt(dgKey(pre, bytes(edig)))
                    if eraw is None:
                        # no event so so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt at dig = {}."
                                              "".format(bytes(edig)))

                    eserder = Serder(raw=bytes(eraw))  # escrowed event

                    #  get sigs
                    sigs = self.db.getSigs(dgKey(pre, bytes(edig)))  # list of sigs
                    if not sigs:  # empty list
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    #  get wigs
                    wigs = self.db.getWigs(dgKey(pre, bytes(edig)))  # list of wigs

                    if not wigs:  # empty list
                        # wigs maybe empty while waiting for first witness signature
                        # which may not arrive until some time after event is fully signed
                        # so just log for debugging but do not unescrow by raising
                        # ValidationError
                        logger.info("Kevery unescrow wigs: No event wigs yet at."
                                 "dig = %s\n", bytes(edig))

                        #raise ValidationError("Missing escrowed evt wigs at "
                                              #"dig = {}.".format(bytes(edig)))

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]
                    wigers = [Siger(qb64b=bytes(wig)) for wig in wigs]
                    self.processEvent(serder=eserder, sigers=sigers, wigers=wigers)

                    # If process does NOT validate wigs then process will attempt
                    # to re-escrow and then raise MissingWitnessSignatureError
                    # (subclass of ValidationError)
                    # so we can distinquish between ValidationErrors that are
                    # re-escrow vs non re-escrow. We want process to be idempotent
                    # with respect to processing events that result in escrow items.
                    # On re-escrow attempt by process, Pwe escrow is called by
                    # Kever.self.escrowPWEvent Which calls
                    # self.db.addPwe(snKey(pre, sn), serder.digb)
                    # which in turn will NOT enter dig as dup if one already exists.
                    # So re-escrow attempt will not change the escrowed pwe db.
                    # Non re-escrow ValidationError means some other issue so unescrow.
                    # No error at all means processed successfully so also unescrow.
                    # Assumes that controller signature validation and delegation
                    # validation will be successful as event would not be in
                    # partially witnessed escrow unless they had already validated

                except MissingWitnessSignatureError as ex:
                    # still waiting on missing witness sigs
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than waiting on sigs or seal so remove from escrow
                    self.db.delPwe(snKey(pre, sn), edig)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delPwe(snKey(pre, sn), edig)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded in valid event: "
                             "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey


    def processEscrowUnverWitness(self):
        """
        Process escrowed unverified event receipts from witness receiptors
        A receipt is unverified if the associated event has not been accepted
        into its KEL.
        Without the event, there is no way to know where to store the receipt
        signatures neither to look up the witness list to verify the indexed
        signatures.

        The escrow is a couple with edig+wig where:
            edig is receipted event digest
            wig is witness indexed signature by key-pair derived from witness
                prefix in associated witness list. Index is offset into witness
                list of of latest establishment event for receipted event.

        The (unescrowed) verified receipt is stored as wig at event digest edig

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different receipt couple inserted in insertion order.
        This allows FIFO processing of escrows for events with same prefix and
        sn but different digest.

        Uses .uwes reads .db.getUwe
        was put there by.db.addUwe(self, key, val) which is IOVal with dups.

        Value is couple

        Original Escrow steps:
            self.db.putDts(dgKey(pre, dig), nowIso8601().encode("utf-8"))
            for wiger in wigers:  # escrow each couple
                couple = dig.encode("utf-8") + wiger.qb64b
                self.db.addUwe(key=snKey(pre, sn), val=triple)
            where:
                dig is dig in receipt of receipted event
                wigers is list of Siger instances witness indexed signature of
                     receipted event
                pre is str qb64 of identifier prefix of receipted event
                sn is int sequence number of receipted event

        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        compare dig so same event
                        verify wigs via wigers
                        If successful then remove from escrow table
        """

        ims = bytearray()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, ecouple in self.db.getUweItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow db key
                    #  get escrowed receipt's rdiger of receipted event and
                    # wiger indexed signature of receipted event
                    rdiger, wiger = deWitnessCouple(ecouple)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(rdiger.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", rdiger.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(rdiger.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutUWE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", rdiger.qb64b)

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(rdiger.qb64b))

                    # lookup database dig of the receipted event in pwes escrow
                    # using pre and sn lastEvt
                    found = self._processEscrowFindUnver(pre=pre,
                                                         sn=sn,
                                                         rdiger=rdiger,
                                                         wiger=wiger)

                    if not found:  # no partial witness escrow of event found
                        # so keep in escrow by raising UnverifiedWitnessReceiptError
                        logger.info("Kevery unescrow error: Missing witness "
                                 "receipted evt at pre=%s sn=%x\n", (pre, sn))

                        raise UnverifiedWitnessReceiptError("Missing witness "
                            "receipted evt at pre={}  sn={:x}".format(pre, sn))

                except UnverifiedWitnessReceiptError as ex:
                    # still waiting on missing prior event to validate
                    # only happens if we process above
                    if logger.isEnabledFor(logging.DEBUG):  # adds exception data
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than out of order so remove from OO escrow
                    self.db.delUwe(snKey(pre, sn), ecouple)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):  # adds exception data
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delUwe(snKey(pre, sn), ecouple)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded for event pre=%s "
                                "sn=%s\n", pre, sn)

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey


    def processEscrowUnverNonTrans(self):
        """
        Process escrowed unverified event receipts from nontrans receiptors
        A receipt is unverified if the associated event has not been accepted
        into its KEL.
        Without the event, there is no way to know where to store the receipts.

        The escrow is a triple with edig+rpre+cig where:
           edig is event digest
           rpre is receiptor (signer) of event
           cig is non-indexed signature by key-pair derived from rpre of event

        The verified receipt is just the couple rpre+cig that is stored by event
        digest edig

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different receipt triple inserted in insertion order.
        This allows FIFO processing of escrows for events with same prefix and
        sn but different digest.

        Uses  .db.addUre(self, key, val) which is IOVal with dups.

        Value is triple

        Original Escrow steps:
            self.db.putDts(dgKey(pre, dig), nowIso8601().encode("utf-8"))
            for cigar in cigars:  # escrow each triple
                if cigar.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid couplets
                triple = dig.encode("utf-8") + cigar.verfer.qb64b + cigar.qb64b
                self.db.addUre(key=snKey(pre, sn), val=triple)  # should be snKey
            where:
                dig is dig in receipt of receipted event
                cigars is list of cigars instances for receipted event
                pre is str qb64 of identifier prefix of receipted event
                sn is int sequence number of receipted event

        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        compare dig so same event
                        verify sigs via cigars
                        If successful then remove from escrow table
        """

        ims = bytearray()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, etriplet in self.db.getUreItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow item
                    rdiger, sprefixer, cigar = deReceiptTriple(etriplet)
                    cigar.verfer = Verfer(qb64b=sprefixer.qb64b)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(rdiger.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", rdiger.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(rdiger.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutURE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", rdiger.qb64b)

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(rdiger.qb64b))

                    # Is receipt for unverified witnessed event in .Pwes escrow
                    # if found then try else clause will remove from escrow
                    found = self._processEscrowFindUnver(pre=pre,
                                                         sn=sn,
                                                         rdiger=rdiger,
                                                         cigar=cigar)

                    if not found:  # no partial witness escrow of event found
                        # so process as escrow of receipt for accept event
                        # not two stage witnessed event escrow
                        # get dig of receipted accepted event in kel using lastEvt
                        # at pre and sn

                        dig = self.db.getKeLast(snKey(pre, sn))
                        if dig is None:  # no receipted event so keep in escrow
                            logger.info("Kevery unescrow error: Missing receipted "
                                     "event at pre=%s sn=%x\n", (pre, sn))

                            raise UnverifiedReceiptError("Missing receipted evt "
                                    "at pre={} sn={:x}".format(pre, sn))

                        # get receipted event using pre and edig
                        raw = self.db.getEvt(dgKey(pre, dig))
                        if raw is None:  # receipted event superseded so remove from escrow
                            logger.info("Kevery unescrow error: Invalid receipted "
                                     "event refereance at pre=%s sn=%x\n", pre, sn)

                            raise ValidationError("Invalid receipted evt reference"
                                              " at pre={} sn={:x}".format(pre, sn))

                        serder = Serder(raw=bytes(raw))  # receipted event

                        #  compare digs
                        if not rdiger.compare(ser=serder.raw, diger=rdiger):
                            logger.info("Kevery unescrow error: Bad receipt dig."
                                 "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                            raise ValidationError("Bad escrowed receipt dig at "
                                              "pre={} sn={:x} receipter={}."
                                              "".format( pre, sn, sprefixer.qb64))

                        #  verify sig verfer key is prefixer from triple
                        if not cigar.verfer.verify(cigar.raw, serder.raw):
                            # no sigs so raise ValidationError which unescrows below
                            logger.info("Kevery unescrow error: Bad receipt sig."
                                     "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                            raise ValidationError("Bad escrowed receipt sig at "
                                                  "pre={} sn={:x} receipter={}."
                                                  "".format( pre, sn, sprefixer.qb64))

                        # get current wits from kever state assuming not stale
                        # receipt. Need function here to compute wits for actual
                        # state at pre, sn. XXXX
                        wits = self.kevers[serder.pre].wits
                        rpre = cigar.verfer.qb64  # prefix of receiptor
                        if rpre in wits:  # its a witness receipt
                            # this only works for extra receipts that come in later
                            # after event is out of .Pwes escrow
                            index = wits.index(rpre)
                            # create witness indexed signature and write to db
                            wiger = Siger(raw=cigar.raw, index=index, verfer=cigar.verfer)
                            self.db.addWig(key=dgKey(pre, serder.dig), val=wiger.qb64b)
                        else:  # write receipt couple to database
                            couple = cigar.verfer.qb64b + cigar.qb64b
                            self.db.addRct(key=dgKey(pre, serder.dig), val=couple)


                except UnverifiedReceiptError as ex:
                    # still waiting on missing prior event to validate
                    # only happens if we process above
                    if logger.isEnabledFor(logging.DEBUG):  # adds exception data
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than out of order so remove from OO escrow
                    self.db.delUre(snKey(pre, sn), etriplet)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):  # adds exception data
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delUre(snKey(pre, sn), etriplet)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded for event pre=%s "
                                                         "sn=%s\n", pre, sn)

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey



    def _processEscrowFindUnver(self, pre, sn, rdiger, wiger=None, cigar=None):
        """
        ToDo XXXX Incomplete Placeholder

        Support method called by other processEscowUnverXXX Receipt methods to
        find escrowed serder in .Pwes for unverifiable receipt due to signed but
        partially witnessed event

        Returns:
           found (bool): True means found matching event in .Pwes and added wig
                        to .Wigs. False means dig not find matching event in .Pwes


        Raises:
            Validation error if found matching event but signature does not verify

        Parameters:
           pre (Union[str,bytes]): pre of receipted event controller kel
           sn (int): sequence number of receipted event
           rdiger (Diger): derived from receipt's dig of receipted event to find
           wiger (Siger): instance of witness indexed signature from receipt
           cigar (Cigar): instance of witness nonindexed signature from receipt

        """
        # lookup the database dig of the receipted event in pwes escrow using
        # snKey(pre,sn) where pre is controller and sn is event sequence number
        # compare dig to rdiger derived from receipt's dig of receipted event
        found = False
        for dig in self.db.getPwesIter(key=snKey(pre,sn)):  # search entries
            dig = bytes(dig)  # database dig of receipted event
            # get the escrowed event using database dig in .Pwes
            serder = Serder(raw=bytes(self.db.getEvt(dgKey(pre, dig))))  # receipted event
            #  compare digs to ensure database dig and rdiger (receipt's dig) match
            if not rdiger.compare(ser=serder.raw, dig=dig):
                continue  # not match keep looking

            # Extract or compute witness list
            if serder.ked['t'] in (Ilks.icp, Ilks.dip):  # inception get from event
                wits = serder.ked['b']  # get wits from event itself
                if len(oset(wits)) != len(wits):
                    raise ValidationError("Invalid wits = {}, has duplicates for evt = {}."
                                                          "".format(wits, serder.ked))

            elif serder.ked['t'] in (Ilks.rot, Ilks.drt):  # rotation compute from state
                # calculate wits from rotation and kever key state.
                wits = self.kevers[serder.pre].wits  # get wits from key state
                cuts = serder.ked['br']
                adds = serder.ked['ba']
                witset = oset(wits)
                cutset = oset(cuts)
                addset = oset(adds)
                if len(cutset) != len(cuts):
                    raise ValidationError("Invalid cuts={}, has duplicates "
                                        "for evt={}.".format(cuts, serder.ked))
                if (witset & cutset) != cutset:  #  some cuts not in wits
                    raise ValidationError("Invalid cuts={}, not all members "
                                "in wits for evt={}.".format(cuts, serder.ked))
                if len(addset) != len(adds):
                    raise ValidationError("Invalid adds={}, has duplicates "
                                        "for evt={}.".format(adds, serder.ked))
                if cutset & addset:  # non empty intersection
                    raise ValidationError("Intersecting cuts={} and  adds={} "
                                "for evt={}.".format(cuts, adds, serder.ked))
                if witset & addset:  # non empty intersection
                    raise ValidationError("Intersecting wits={} and  adds={} "
                            "for evt={}.".format(self.wits, adds, serder.ked))
                wits = list((witset - cutset) | addset)

            else:  # interaction so get wits from kever key state
                # would not be in this escrow if out of order event
                wits = self.kevers[serder.pre].wits  # get wits fromkey state

            if cigar:  # if recipter is a witness make wiger
                rpre = cigar.verfer.qb64  # prefix of receiptor
                if rpre in wits:  # its a witness receipt
                    index = wits.index(rpre)
                    # create witness indexed signature wiger from cigar and wit index
                    wiger = Siger(raw=cigar.raw, index=index, verfer=cigar.verfer)
                    found = True
                    break # done with search have caller add wig.

            elif wiger:  # check index and assign verfier to wiger
                if wiger.index >= len(wits):  # bad index
                    # raise ValidationError which removes from escrow by caller
                    logger.info("Kevery unescrow error: Bad witness receipt"
                        " index=%i for pre=%s sn=%x\n", wiger.index, pre, sn)
                    raise ValidationError("Bad escrowed witness receipt index={}"
                            " at pre={} sn={:x}.".format(wiger.index, pre, sn))

                wiger.verfer = Verfer(qb64=wits[wiger.index])
                found = True
                break  # done with search have caller add wig.

        if found:  # verify signature and if verified write to .Wigs
            if not wiger.verfer.verify(wiger.raw, serder.raw): # not verify
                # raise ValidationError which unescrows .Uwes or .Ures in caller
                logger.info("Kevery unescrow error: Bad witness receipt"
                                            " wig. pre=%s sn=%x\n", pre, sn)

                raise ValidationError("Bad escrowed witness receipt wig"
                                                      " at pre={} sn={:x}."
                                                      "".format( pre, sn))
            self.db.addWig(key=dgKey(pre, serder.dig), val=wiger.qb64b)
            # processEscrowPartialWigs removes from this .Pwes escrow
            # when fully witnessed using self.db.delPwe(snkey, dig)

        return found


    def processEscrowUnverTrans(self):
        """
        Process event receipts from transferable identifiers (validators)
        escrowed by Kever that are unverified.
        A transferable receipt is unverified if either the receipted event has not
        been accepted into the receipted's KEL or the establishment event of the
        receiptor has not been accepted into the receipter's KEL.
        Without either event there is no way to know where to store the receipt
        quadruples.

        The escrow is a quintuple with dig+spre+ssnu+sdig+sig
        the verified receipt is just the quadruple spre+ssnu+sdig+sig that is
        stored by event dig

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different receipt quintuple inserted in insertion order.
        This allows FIFO processing of escrows of events with same prefix and sn
        but different digest.

        Uses  .db.addVre(self, key, val) which is IOVal with dups.

        Value is quintuple

        Original Escrow steps:
            self.db.putDts(dgKey(serder.preb, dig), nowIso8601().encode("utf-8"))
            prelet = (dig.encode("utf-8") + seal.i.encode("utf-8") +
                  Seqner(sn=int(seal.s, 16)).qb64b + seal.d.encode("utf-8"))
            for siger in sigers:  # escrow each quintlet
                quintuple = prelet +  siger.qb64b  # quintuple
                self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
            where:
                dig is dig in receipt of receipted event
                sigers is list of Siger instances for receipted event


        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        compare dig so same event
                        verify sigs via sigers
                        If successful then remove from escrow table
        """

        ims = bytearray()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, equinlet in self.db.getVreItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow item
                    ediger, sprefixer, sseqner, sdiger, siger = deTransReceiptQuintuple(equinlet)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(ediger.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", ediger.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(ediger.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutVRE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", ediger.qb64b)

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(ediger.qb64b))

                    # get dig of the receipted event using pre and sn lastEvt
                    raw = self.db.getKeLast(snKey(pre, sn))
                    if raw is None:
                        # no event so keep in escrow
                        logger.info("Kevery unescrow error: Missing receipted "
                                 "event at pre=%s sn=%x\n", (pre, sn))

                        raise UnverifiedTransferableReceiptError("Missing receipted evt at pre={} "
                                              " sn={:x}".format(pre, sn))

                    dig = bytes(raw)
                    # get receipted event using pre and edig
                    raw = self.db.getEvt(dgKey(pre, dig))
                    if raw is None:  #  receipted event superseded so remove from escrow
                        logger.info("Kevery unescrow error: Invalid receipted "
                                 "event referenace at pre=%s sn=%x\n", pre, sn)

                        raise ValidationError("Invalid receipted evt reference "
                                              "at pre={} sn={:x}".format(pre, sn))

                    serder = Serder(raw=bytes(raw))  # receipted event

                    #  compare digs
                    if not ediger.compare(ser=serder.raw, diger=ediger):
                        logger.info("Kevery unescrow error: Bad receipt dig."
                             "pre=%s sn=%x receipter=%s\n", (pre, sn, sprefixer.qb64))

                        raise ValidationError("Bad escrowed receipt dig at "
                                          "pre={} sn={:x} receipter={}."
                                          "".format( pre, sn, sprefixer.qb64))

                    # get receipter's last est event
                    # retrieve dig of last event at sn of receipter.
                    sdig = self.db.getKeLast(key=snKey(pre=sprefixer.qb64b,
                                                          sn=sseqner.sn))
                    if sdig is None:
                        # no event so keep in escrow
                        logger.info("Kevery unescrow error: Missing receipted "
                                 "event at pre=%s sn=%x\n", pre, sn)

                        raise UnverifiedTransferableReceiptError("Missing receipted evt at pre={} "
                                              " sn={:x}".format(pre, sn))

                    # retrieve last event itself of receipter
                    sraw = self.db.getEvt(key=dgKey(pre=sprefixer.qb64b, dig=bytes(sdig)))
                    # assumes db ensures that sraw must not be none because sdig was in KE
                    sserder = Serder(raw=bytes(sraw))
                    if not sserder.compare(diger=sdiger):  # seal dig not match event
                        # this unescrows
                        raise ValidationError("Bad chit seal at sn = {} for rct = {}."
                                              "".format(sseqner.sn, sserder.ked))

                    #verify sigs and if so write quadruple to database
                    verfers = sserder.verfers
                    if not verfers:
                        raise ValidationError("Invalid seal est. event dig = {} for "
                                              "receipt from pre ={} no keys."
                                              "".format(sdiger.qb64, sprefixer.qb64))

                    # Set up quadruple
                    sealet = sprefixer.qb64b + sseqner.qb64b + sdiger.qb64b

                    if siger.index >= len(verfers):
                        raise ValidationError("Index = {} to large for keys."
                                                  "".format(siger.index))

                    siger.verfer = verfers[siger.index]  # assign verfer
                    if not siger.verfer.verify(siger.raw, serder.raw):  # verify sig
                        logger.info("Kevery unescrow error: Bad trans receipt sig."
                                 "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                        raise ValidationError("Bad escrowed trans receipt sig at "
                                              "pre={} sn={:x} receipter={}."
                                              "".format( pre, sn, sprefixer.qb64))

                    # good sig so write receipt quadruple to database
                    quadruple = sealet + siger.qb64b
                    self.db.addVrc(key=dgKey(pre, serder.dig), val=quadruple)


                except UnverifiedTransferableReceiptError as ex:
                    # still waiting on missing prior event to validate
                    # only happens if we process above
                    if logger.isEnabledFor(logging.DEBUG):  # adds exception data
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than out of order so remove from OO escrow
                    self.db.delVre(snKey(pre, sn), equinlet)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):  # adds exception data
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delVre(snKey(pre, sn), equinlet)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded for event = %s\n", serder.ked)

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey


    def processEscrowDuplicitous(self):
        """
        Process events escrowed by Kever that are likely duplicitous.
        An event is likely duplicitous if a different version of event already
        has been accepted into the KEL.

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different dig inserted in insertion order.
        This allows FIFO processing of events with same prefix and sn but different
        digest.

        Uses  .db.addLde(self, key, val) which is IOVal with dups.

        Value is dgkey for event stored in .Evt where .Evt has serder.raw of event.

        Original Escrow steps:
            dgkey = dgKey(pre, serder.dig)
            self.db.putDts(dgkey, nowIso8601().encode("utf-8"))
            self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
            self.db.putEvt(dgkey, serder.raw)
            self.db.addLde(snKey(pre, sn), serder.digb)
            where:
                serder is Serder instance of  event
                sigers is list of Siger instance for  event
                pre is str qb64 of identifier prefix of event
                sn is int sequence number of event

        Steps:
            Each pass  (walk index table)
                For each prefix,sn
                    For each escrow item dup at prefix,sn:
                        Get Event
                        Get and Attach Signatures
                        Process event as if it came in over the wire
                        If successful then remove from escrow table
        """
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getLdeItemsNextIter(key=key):
                try:
                    pre, sn = splitKeySN(ekey)  # get pre and sn from escrow item
                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(edig)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(bytes(edig)))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutLDE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                 " at dig = %s\n", bytes(edig))

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(bytes(edig)))

                    # get the escrowed event using edig
                    eraw = self.db.getEvt(dgKey(pre, bytes(edig)))
                    if eraw is None:
                        # no event so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt at dig = {}."
                                              "".format(bytes(edig)))

                    eserder = Serder(raw=bytes(eraw))  # escrowed event

                    #  get sigs and attach
                    sigs = self.db.getSigs(dgKey(pre, bytes(edig)))
                    if not sigs:  #  otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]
                    self.processEvent(serder=eserder, sigers=sigers)

                    # If process does NOT validate event with sigs, becasue it is
                    # still out of order then process will attempt to re-escrow
                    # and then raise OutOfOrderError (subclass of ValidationError)
                    # so we can distinquish between ValidationErrors that are
                    # re-escrow vs non re-escrow. We want process to be idempotent
                    # with respect to processing events that result in escrow items.
                    # On re-escrow attempt by process, Ooe escrow is called by
                    # Kevery.self.escrowOOEvent Which calls
                    # self.db.addOoe(snKey(pre, sn), serder.digb)
                    # which in turn will not enter dig as dup if one already exists.
                    # So re-escrow attempt will not change the escrowed ooe db.
                    # Non re-escrow ValidationError means some other issue so unescrow.
                    # No error at all means processed successfully so also unescrow.

                except LikelyDuplicitousError as ex:
                    # still can't determine if duplicitous
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than likely duplicitous so remove from escrow
                    self.db.delLde(snKey(pre, sn), edig)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])

                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delLde(snKey(pre, sn), edig)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded in valid event: "
                             "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey



    def duplicity(self, serder, sigers):
        """
        PlaceHolder Reminder
        Processes potential duplicitous events in PDELs

        Handles duplicity detection and logging if duplicitous

        Placeholder here for logic need to move

        """
        pass

