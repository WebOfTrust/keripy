# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""
import datetime
import re
import json
import logging

from dataclasses import dataclass, astuple
from collections import namedtuple, deque
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from math import ceil

import cbor2 as cbor
import msgpack
import pysodium
import blake3

from orderedset import OrderedSet as oset

from ..kering import (ExtractionError, ShortageError, ColdStartError,
                      UnexpectedCountCodeError, SizedGroupError,
                      UnexpectedCodeError,
                      ValidationError,  MissingSignatureError,
                      MissingDelegatingSealError, OutOfOrderError,
                      LikelyDuplicitousError,  UnverifiedReceiptError,
                      UnverifiedTransferableReceiptError)
from ..kering import Versionage, Version
from ..help.helping import nowIso8601, fromIso8601, toIso8601
from ..db.dbing import dgKey, snKey, splitKey, splitKeySN, Baser

from .coring import Versify, Serials, Ilks
from .coring import MtrDex, NonTransDex, IdrDex, CtrDex, Counter
from .coring import Signer, Verfer, Diger, Nexter, Prefixer, Serder, Tholder
from .coring import Seqner, Siger, Cigar

from .. import help

logger = help.ogler.getLogger()

EscrowTimeoutPS = 3600  # seconds for partial signed escrow timeout

ICP_LABELS = ["v", "i", "s", "t", "kt", "k", "n",
              "wt", "w", "c"]
ROT_LABELS = ["v", "i", "s", "t", "p", "kt", "k", "n",
              "wt", "wr", "wa", "a"]
IXN_LABELS = ["v", "i", "s", "t", "p", "a"]
DIP_LABELS = ["v", "i", "s", "t", "kt", "k", "n",
              "wt", "w", "c", "da"]
DRT_LABELS = ["v", "i", "s", "t", "p", "kt", "k", "n",
              "wt", "wr", "wa", "a", "da"]


@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    EstOnly:         str = 'EO'  #  Only allow establishment events
    DoNotDelegate:   str = 'DND'  #  Dot not allow delegated identifiers


    def __iter__(self):
        return iter(astuple(self))

TraitDex = TraitCodex()  # Make instance

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


TraitDex = TraitCodex()  # Make instance

# Location of last establishment key event: sn is int, dig is qb64 digest
LastEstLoc = namedtuple("LastEstLoc", 's d')

#  for the following Seal namedtuples use the ._asdict() method to convert to dict
#  when using in events

# Digest Seal: dig is qb64 digest of data
SealDigest = namedtuple("SealDigest", 'd')

# Root Seal: root is qb64 digest that is merkle tree root of data tree
SealRoot = namedtuple("SealRoot", 'rd')

# Event Seal: pre is qb64 of identifier prefix of KEL, sn is hex string,
# dig is qb64 digest of event
SealEvent = namedtuple("SealEvent", 'i s d')

# Event Location Seal: pre is qb64 of identifier prefix of KEL,
# sn is hex string, ilk is str, dig is qb64 of prior event digest
SealLocation = namedtuple("SealLocation", 'i s t p')

# Cues are dataclasses may be converted tofrom dicts easily


# bytearray of memoryview makes a copy so does not delete underlying data
# behind memory view but del on bytearray itself does delete bytearray

def decouple(data, deletive=False):
    """
    Returns tuple of (prefixer, cigar) from concatenated bytes or
    bytearray of data couple made up of qb64 or qb64b versions of pre+sig
    couple is used for receipts signed by nontransferable prefix keys

    Parameters:
        data is couple of bytes concatenation of pre+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, bytearray):
        if not deletive:
            data = bytearray(data)  # make copy so does not delete underlying data
    elif isinstance(data, memoryview):
        data = bytearray(data)
    elif hasattr(data, "encode"):
        data = bytearray(data.encode("utf-8"))  # convert to bytearray
    elif isinstance(data, bytes):
        data = bytearray(data)
    else:
        raise ValueError("Unrecognized data type, not str, bytes, memoryview, "
                         "or bytearray.")

    prefixer = Prefixer(qb64b=data)
    del data[:len(prefixer.qb64b)]  # strip off part
    cigar = Cigar(qb64b=data)
    del data[:len(cigar.qb64b)]  # strip off part
    return (prefixer, cigar)


def detriple(data, deletive=False):
    """
    Returns tuple of (diger, prefixer, cigar) from concatenated bytes
    of data triple made up of qb64 or qb64b versions of dig+pre+sig
    triple is used for escrows of unverified receipts signed by nontransferable prefix keys

    Parameters:
        data is triple of bytes concatenation of dig+pre+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, bytearray):
        if not deletive:
            data = bytearray(data)  # make copy so does not delete underlying data
    elif isinstance(data, memoryview):
        data = bytearray(data)
    elif hasattr(data, "encode"):
        data = bytearray(data.encode("utf-8"))  # convert to bytearray
    elif isinstance(data, bytes):
        data = bytearray(data)
    else:
        raise ValueError("Unrecognized data type, not str, bytes, memoryview, "
                         "or bytearray.")

    diger = Diger(qb64b=data)
    del data[:len(diger.qb64b)]  # strip off part
    prefixer = Prefixer(qb64b=data)
    del data[:len(prefixer.qb64b)]  # strip off part
    cigar = Cigar(qb64b=data)
    del data[:len(cigar.qb64b)]  # strip off part
    return (diger, prefixer, cigar)


def dequadruple(data, deletive=False):
    """
    Returns tuple (quadruple) of (prefixer, seqner, diger, siger) from concatenated bytes
    of quadruple made up of qb64 or qb64b versions of spre+ssnu+sdig+sig
    quadruple is used for receipts signed by transferable prefix keys

    Parameters:
        quadruple is bytes concatenation of pre+snu+dig+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, bytearray):
        if not deletive:
            data = bytearray(data)  # make copy so does not delete underlying data
    elif isinstance(data, memoryview):
        data = bytearray(data)
    elif hasattr(data, "encode"):
        data = bytearray(data.encode("utf-8"))  # convert to bytearray
    elif isinstance(data, bytes):
        data = bytearray(data)
    else:
        raise ValueError("Unrecognized data type, not str, bytes, memoryview, "
                         "or bytearray.")

    prefixer = Prefixer(qb64b=data)
    del data[:len(prefixer.qb64b)]  # strip off part
    seqner = Seqner(qb64b=data)
    del data[:len(seqner.qb64b)]  # strip off part
    diger = Diger(qb64b=data)
    del data[:len(diger.qb64b)]  # strip off part
    siger = Siger(qb64b=data)
    del data[:len(siger.qb64b)]  # strip off part
    return (prefixer, seqner, diger, siger)


def dequintuple(data, deletive=False):
    """
    Returns tuple of (ediger, seal prefixer, seal seqner, seal diger, siger)
    from concatenated bytes of quintuple made up of qb64 or qb64b versions of
    quntipuple given by  concatenation of  edig+spre+ssnu+sdig+sig
    Quintuple is used for unverified escrows of validator receipts signed
    by transferable prefix keys

    Parameters:
        quintuple is bytes concatenation of edig+spre+ssnu+sdig+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, bytearray):
        if not deletive:
            data = bytearray(data)  # make copy so does not delete underlying data
    elif isinstance(data, memoryview):
        data = bytearray(data)
    elif hasattr(data, "encode"):
        data = bytearray(data.encode("utf-8"))  # convert to bytearray
    elif isinstance(data, bytes):
        data = bytearray(data)
    else:
        raise ValueError("Unrecognized data type, not str, bytes, memoryview, "
                         "or bytearray.")

    ediger = Diger(qb64b=data)  #  diger of receipted event
    del data[:len(ediger.qb64b)]  # strip off part
    sprefixer = Prefixer(qb64b=data)  # prefixer of recipter
    del data[:len(sprefixer.qb64b)]  # strip off part
    sseqner = Seqner(qb64b=data)  # seqnumber of receipting event
    del data[:len(sseqner.qb64b)]  # strip off part
    sdiger = Diger(qb64b=data)  # diger of receipting event
    del data[:len(sdiger.qb64b)]  # strip off part
    siger = Siger(qb64b=data)  #  indexed siger of event
    del data[:len(siger.qb64b)]  # strip off part
    return (ediger, sprefixer, sseqner, sdiger, siger)


def incept(keys,
           sith=None,
           nxt="",
           toad=None,
           wits=None,
           cnfg=None,
           version=Version,
           kind=Serials.json,
           code=None,
          ):

    """
    Returns serder of inception event message.
    Utility function to automate creation of inception events.

     Parameters:
        keys is list of qb64 signing keys
        sith is string, or list format for signing threshold
        nxt  is qb64 next digest xor
        toad is int of witness threshold
        wits is list of qb64 witness prefixes
        cnfg is list of dicts of configuration traits
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

    if toad is None:
        if not wits:
            toad = 0
        else:
            toad = max(1, ceil(len(wits) / 2))

    if wits:
        if toad < 1 or toad > len(wits):  # out of bounds toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))

    cnfg = cnfg if cnfg is not None else []

    # see compact labels in KID0003.md

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt=sith, # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               )

    if code is None and len(keys) == 1:
        prefixer = Prefixer(qb64=keys[0])
    else:
        # raises derivation error if non-empty nxt but ephemeral code
        prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

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
        toad is int of witness threshold
        wits is list of prior witness prefixes qb64
        cuts is list of witness prefixes to cut qb64
        adds is list of witness prefixes to add qb64
        data is list of dicts of comitted data such as seals
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

    if toad is None:
        if not newitset:
            toad = 0
        else:
            toad = max(1, ceil(len(newitset) / 2))

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
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               wr=cuts,  # list of qb64 may be empty
               wa=adds,  # list of qb64 may be empty
               a=data,  # list of seals
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

def chit(pre,
         sn,
         dig,
         seal,
         version=Version,
         kind=Serials.json
        ):

    """
    Returns serder of validator event receipt message for transferable receipter
    prefix.
    Utility function to automate creation of interaction events.

     Parameters:
        pre is qb64 str of prefix of event being receipted
        sn  is int sequence number of event being receipted
        dig is qb64 of digest of event being receipted
        seal is namedTuple of SealEvent of receipter's last Est event
            pre is qb64 of receipter's prefix
            dig is qb64 digest of receipter's last Est event
        version is Version instance of receipt
        kind  is serialization kind of receipt

    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.vrc
    if sn < 0:
        raise ValueError("Invalid sn = {} for rct.".format(sn))

    ked = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,  #  Ilks.rct
               d=dig,  # qb64 digest of receipted event
               a=seal._asdict()  # event seal: pre, dig
               )

    return Serder(ked=ked)  # return serialized ked


def delcept(keys,
            seal,
            code=None,
            sith=None,
            nxt="",
            toad=None,
            wits=None,
            cnfg=None,
            version=Version,
            kind=Serials.json,
          ):

    """
    Returns serder of delegated inception event message.
    Utility function to automate creation of delegated inception events.

     Parameters:
        keys is list of qb64 keys
        seal is namedTuple of type SealLocation of delegating event
            pre is qb64 of receipter's prefix
            sn is sequence number of delegating event
            ilk is ilk of delegating event
            dig is qb64 digest of prior event to delegating event
        code is derivation code for prefix
        sith is int  of signing threshold
        nxt  is qb64 next digest xor
        toad is int  of witness threshold
        wits is list of qb64 witness prefixes
        cnfg is list of configuration trait dicts including permissions dicts
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

    if toad is None:
        if not wits:
            toad = 0
        else:
            toad = max(1, ceil(len(wits) / 2))

    if wits:
        if toad < 1 or toad > len(wits):  # out of bounds toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))

    cnfg = cnfg if cnfg is not None else []

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               kt="{:x}".format(sith), # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               n=nxt,  # hash qual Base64
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               w=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config and permission ordered mappings may be empty
               da=seal._asdict()  # event seal: pre, dig
               )

    if code is None:
        code = MtrDex.Blake3_256  # Default digest

    # raises derivation error if non-empty nxt but ephemeral code
    prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

    if not prefixer.digestive:
        raise ValueError("Invalid derivation code ={} for delegation. Must be"
                         " digestive".formate(prefixer.code))

    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64

    return Serder(ked=ked)  # return serialized ked



def deltate(pre,
           keys,
           dig,
           seal,
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
        seal is namedTuple of type SealLocation of delegating event
            pre is qb64 of receipter's prefix
            sn is sequence number of delegating event
            ilk is ilk of delegating event
            dig is qb64 digest of prior event to delegating event
        sn is int sequence number
        sith is int signing threshold
        nxt  is qb64 next digest xor
        toad is int of witness threshold
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

    if toad is None:
        if not newitset:
            toad = 0
        else:
            toad = max(1, ceil(len(newitset) / 2))

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
               wt="{:x}".format(toad),  # hex string no leading zeros lowercase
               wr=cuts,  # list of qb64 may be empty
               wa=adds,  # list of qb64 may be empty
               a=data,  # list of seals ordered mappings may be empty
               da=seal._asdict()  # event seal: pre, dig
               )

    return Serder(ked=ked)  # return serialized ked


def messagize(serder, sigers):
    """
    Attaches indexed signatures from sigers to KERI message data from serder
    Parameters:
        serder: Serder instance containing the event
        sigers: Sigers[] array of indexed signatures

    Returns: bytearray KERI event message
    """
    msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
    count = len(sigers)
    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count)
    msg.extend(counter.qb64b)
    for siger in sigers:
        msg.extend(siger.qb64b)

    return msg


def receiptize(serder, cigars):
    """
    Attaches receipt couplets from cigars to KERI message data from serder
    Parameters:
        serder: Serder instance containing the event
        cigars: Cigars[] array of non-transferable non indexed signatures

    Returns: bytearray KERI event message
    """
    msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
    count = len(cigars)
    counter = Counter(code=CtrDex.NonTransReceiptCouples, count=count)
    msg.extend(counter.qb64b)
    for cigar in cigars:
        if cigar.verfer.code not in NonTransDex:
            raise ValueError("Attempt to use tranferable prefix={} for "
                             "receipt.".format(cigar.verfer.qb64))
        msg.extend(cigar.verfer.qb64b)
        msg.extend(cigar.qb64b)

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

    Attributes:
        .baser is reference for Baser instance that managers the LMDB database
        .version is version of current event state
        .prefixer is prefixer instance for current event state
        .sn is sequence number int
        .serder is Serder instance of current event with .serder.diger for digest
        .ilk is str of current event type
        .tholder is Tholder instance for event sith
        .verfers is list of Verfer instances for current event state set of signing keys
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .estOnly is boolean trait True means only allow establishment events
        .lastEst is LastEstLoc namedtuple of int .sn and qb64 .dig of last est event
        .delegated is Boolean, True means delegated identifier, False not delegated
        .delgator is str qb64 of delegator's prefix


    Properties:
        .transferable Boolean True if nexter is not none and pre is transferable

    """
    EstOnly = False

    def __init__(self, serder, sigers, baser=None, estOnly=None):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigers raises ValidationError if not

        Parameters:
            serder is Serder instance of inception event
            sigers is list of SigMat instances of signatures of event
            baser is Baser instance of lmdb database
            estOnly is boolean trait to indicate establish only event
        """

        if baser is None:
            baser = Baser()  # default name = "main"
        self.baser = baser

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

        # validates if not escrows as needed and raises validation error
        self.validateSigs(serder=serder,
                          sigers=sigers,
                          verfers=serder.verfers,
                          tholder=self.tholder)

        if ilk == Ilks.dip:
            seal = self.validateSeal(serder=serder, sigers=sigers)
            self.delegated = True
            self.delegator = seal.i
        else:
            self.delegated = False
            self.delegator = None

        #  .validateSigs above ensures threshold met otherwise raises exception
        self.logEvent(serder, sigers, first=True)  # First seen accepted


    @property
    def transferable(self):
        """
        Property transferable:
        Returns True if identifier does not have non-transferable derivation code
                and .nextor is not None
                False otherwise
        """
        return(self.nexter is not None and self.prefixer.transferable)


    def incept(self, serder, baser=None, estOnly=None):
        """
        Verify incept key event message from serder


        Parameters:
            serder is Serder instance of inception event
            estOnly is boolean  to indicate establish only events allowed
            baser is LMDB Baser instance

        """
        ked = serder.ked

        self.verfers = serder.verfers  # converts keys to verifiers
        self.tholder = Tholder(sith=ked["kt"])  #  parse sith into Tholder instance
        if len(self.verfers) < self.tholder.size:
            raise ValueError("Invalid sith = {} for keys = {} for evt = {}."
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

        wits = ked["w"]
        if len(oset(wits)) != len(wits):
            raise ValueError("Invalid wits = {}, has duplicates for evt = {}."
                             "".format(wits, ked))
        self.wits = wits

        toad = int(ked["wt"], 16)
        if wits:
            if toad < 1 or toad > len(wits):  # out of bounds toad
                raise ValueError("Invalid toad = {} for wits = {} for evt = {}."
                                 "".format(toad, wits, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValueError("Invalid toad = {} for wits = {} for evt = {}."
                                 "".format(toad, wits, ked))
        self.toad = toad

        # need this to recognize recovery events and transferable receipts
        self.lastEst = LastEstLoc(s=self.sn, d=self.serder.diger.qb64)  # last establishment event location


    def config(self, serder, estOnly=None):
        """
        Process cnfg field for configuration traits
        """
        # assign traits
        self.estOnly = (True if (estOnly if estOnly is not None else self.EstOnly)
                            else False)  # ensure default estOnly is boolean

        cnfg = serder.ked["c"]  # process cnfg for traits
        if TraitDex.EstOnly in cnfg:
            self.estOnly = True


    def update(self, serder,  sigers):
        """
        Not original inception event. So verify event serder and
        indexed signatures in sigers and update state

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

        if ilk in (Ilks.rot, Ilks.drt) :  # rotation (or delegated rotation) event
            if self.delegated and ilk != Ilks.drt:
                raise ValidationError("Attempted non delegated rotation on "
                                      "delegated pre = {} with evt = {}."
                                      "".format(ked["i"], ked))

            labels = DRT_LABELS if ilk == Ilks.dip else ROT_LABELS
            for k in labels:
                if k not in ked:
                    raise ValidationError("Missing element = {} from {} event for "
                                          "evt = {}.".format(k, ilk, ked))

            tholder, toad, wits = self.rotate(serder, sn)

            # validates and escrows as needed raises ValidationError if not successful
            self.validateSigs(serder=serder,
                              sigers=sigers,
                              verfers=serder.verfers,
                              tholder=tholder)

            if ilk == Ilks.drt:
                seal = self.validateSeal(serder=serder, sigers=sigers)
                if seal.i != self.delegator:
                    raise ValidationError("Attempted delegated rotation with "
                                      "wrong delegator = {} for delegated pre "
                                      " = {} with evt = {}."
                                      "".format(seal.i, ked["i"], ked))

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

            # last establishment event location need this to recognize recovery events
            self.lastEst = LastEstLoc(s=self.sn, d=self.serder.diger.qb64)

            #  .validateSigs above ensures threshold met otherwise raises exception
            self.logEvent(serder, sigers, first=True)  # First seen accepted


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

            # interaction event use sith and keys from pre-existing Kever state
            # validates and escrows as needed
            self.validateSigs(serder=serder,
                              sigers=sigers,
                              verfers=self.verfers,
                              tholder=self.tholder)

            # update state
            self.sn = sn
            self.serder = serder  # need for digest agility includes .serder.diger
            self.ilk = ilk

            #  .validateSigs above ensure threshold met otherwise raises exception
            self.logEvent(serder, sigers, first=True)  # First seen accepted

        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))


    def rotate(self, serder, sn):
        """
        Generic Rotate Operation Processing
        Same logic for both rot and drt (plain and delegated rotation)
        Returns triple (tholder, toad, wits)

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
                pdig = self.baser.getKeLast(key=snKey(pre=pre, sn=psn))
                if pdig is None:
                    raise ValidationError("Invalid recovery attempt: "
                                          "Bad sn = {} for event = {}."
                                          "".format(psn, ked))
                praw = self.baser.getEvt(key=dgKey(pre=pre, dig=pdig))
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
            raise ValueError("Invalid sith = {} for keys = {} for evt = {}."
                             "".format(ked["kt"],
                                       [verfer.qb64 for verfer in serder.verfers],
                                       ked))

        # verify nxt from prior
        keys = ked["k"]
        if not self.nexter.verify(limen=tholder.limen, keys=keys):
            raise ValidationError("Mismatch nxt digest = {} with rotation"
                                  " sith = {}, keys = {} for evt = {}."
                                  "".format(self.nexter.qb64, tholder.thold, keys, ked))

        # compute wits from cuts and adds use set
        # verify set math uses ordered set to ensure that witness list is strictly
        #  ordered so that indexed signatures work
        witset = oset(self.wits)
        cuts = ked["wr"]
        cutset = oset(cuts)
        if len(cutset) != len(cuts):
            raise ValueError("Invalid cuts = {}, has duplicates for evt = "
                             "{}.".format(cuts, ked))

        if (witset & cutset) != cutset:  #  some cuts not in wits
            raise ValueError("Invalid cuts = {}, not all members in wits"
                             " for evt = {}.".format(cuts, ked))


        adds = ked["wa"]
        addset = oset(adds)
        if len(addset) != len(adds):
            raise ValueError("Invalid adds = {}, has duplicates for evt = "
                             "{}.".format(adds, ked))

        if cutset & addset:  # non empty intersection
            raise ValueError("Intersecting cuts = {} and  adds = {} for "
                             "evt = {}.".format(cuts, adds, ked))

        if witset & addset:  # non empty intersection
            raise ValueError("Intersecting wits = {} and  adds = {} for "
                             "evt = {}.".format(self.wits, adds, ked))

        wits = list((witset - cutset) | addset)

        if len(wits) != (len(self.wits) - len(cuts) + len(adds)):  # redundant?
            raise ValueError("Invalid member combination among wits = {}, cuts ={}, "
                             "and adds = {} for evt = {}.".format(self.wits,
                                                                  cuts,
                                                                  adds,
                                                                  ked))

        toad = int(ked["wt"], 16)
        if wits:
            if toad < 1 or toad > len(wits):  # out of bounds toad
                raise ValueError("Invalid toad = {} for wits = {} for evt "
                                 "= {}.".format(toad, wits, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValueError("Invalid toad = {} for wits = {} for evt "
                                 "= {}.".format(toad, wits, ked))

        return (tholder, toad, wits)

    def validateSN(self, ked, inceptive=False):
        """
        Returns int validated from hex str sn in ked

        Parameters:
           ked is key event dict of associated event or message such as seal
        """
        sn = ked["s"]
        if len(sn) > 32:
            raise ValidationError("Oversize sn = {} for evt={}."
                                  "".format(sn, ked))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Noninteger sn = {} for evt={}.".format(sn, ked))

        if inceptive:
            if sn != 0:
                raise ValidationError("Nonzero sn = {} for inception evt={}."
                                      "".format(sn, ked))
        else:
            if sn == 0:
                raise ValidationError("Zero sn = {} for non-inception evt={}."
                                      "".format(sn, ked))
        return sn


    def verifySigs(self, serder, sigers, verfers):
        """
        Returns list of indices of verified signatures for serder, sigers, and verfers.
        Assigns verfer to appropriate siger based on index
        If no signatures verify then indices is empty

        Parameters:
            serder is Serder of signed event
            sigers is list of indexed Siger instances (signatures)
            verfers is list of Verfer instance (public keys)

        """
        # verify indexes of attached signatures against verifiers
        for siger in sigers:
            if siger.index >= len(verfers):
                raise ValidationError("Index = {} to large for keys for evt = "
                                      "{}.".format(siger.index, serder.ked))
            siger.verfer = verfers[siger.index]  # assign verfer

        # verify signatures
        indices = []
        for siger in sigers:
            if siger.verfer.verify(siger.raw, serder.raw):
                indices.append(siger.index)

        return indices



    def validateSigs(self, serder, sigers, verfers, tholder):
        """
        Validate signatures by validating sith indexs and verifying signatures

        Parameters:
            serder
            sigers
            verfers
            tholder
            sn
            escrow

        """
        if len(verfers) < self.tholder.size:
            raise ValueError("Invalid sith = {} for keys = {} for evt = {}."
                             "".format(tholder.sith,
                                       [verfer.qb64 for verfer in verfers],
                                       serder.ked))

        indices = self.verifySigs(serder, sigers, verfers)

        if not indices:  # must have a least one verified
            raise ValidationError("No verified signatures among {} for evt = {}."
                                  "".format([siger.qb64 for siger in sigers],
                                            serder.ked))

        if not tholder.satisfy(indices):  #  at least one but not enough
            self.escrowPSEvent(serder=serder, sigers=sigers)

            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                  " for evt = {}.".format(tholder.sith,
                                                [siger.qb64 for siger in sigers],
                                                serder.ked))


    def validateSeal(self, serder, sigers):
        """
        Returns seal instance of SealLocation if seal validates with respect
        to Delegator's KEL
        Location Seal is from Delegate's establishment event
        Assumes state setup

        Parameters:
            serder is delegated event serder
            sigers is delegated event list of event sigers
            sn is int delegated event sequence number

        """
        # verify seal pointing delegator event
        seal = SealLocation(**serder.ked["da"])
        # seal has pre sn ilk dig (prior dig)

        ssn = self.validateSN(ked=seal._asdict(), inceptive=False)

        # get the dig of the delegating event
        key = snKey(pre=seal.i, sn=ssn)
        raw = self.baser.getKeLast(key)  # get dig of delegating event
        if raw is None:  # no delegating event at key pre, sn
            #  escrow event here
            inceptive = True if serder.ked["t"] in (Ilks.icp, Ilks.dip) else False
            sn = self.validateSN(ked=serder.ked, inceptive=inceptive)
            self.escrowPSEvent(serder=serder, sigers=sigers)
            raise MissingDelegatingSealError("No delegating event at seal = {} for "
                                             "evt = {}.".format(serder.ked["da"],
                                                     serder.ked))

        # get the delegating event from dig
        key = dgKey(pre=seal.i, dig=bytes(raw))
        raw = self.baser.getEvt(key)
        if raw is None:
            raise ValidationError("Missing event at seal = {} for evt = {}."
                                  "".format(serder.ked["da"], serder.ked))

        dserder = Serder(raw=bytes(raw))  # delegating event

        # get prior event
        pdig = self.baser.getKeLast(key=snKey(pre=seal.i, sn=int(dserder.ked["s"], 16) - 1 ))

        if pdig is  None:
            raise ValidationError("Missing prior event for seal = {}."
                                  "".format(serder.ked["da"]))

        praw = self.baser.getEvt(key=dgKey(pre=seal.i, dig=pdig))
        if praw is None:
            raise ValidationError("Missing prior event for seal = {}."
                                  "".format(serder.ked["da"]))

        pserder = Serder(raw=bytes(praw))  # prior event of delegating event

        # need to retrieve prior event from database in order to verify digest agility
        if not pserder.compare(dig=seal.p):  # delegating event prior dig match seal
            raise ValidationError("Mismatch prior dig of delegating event at "
                                  "seal = {} for evt = {}.".format(serder.ked["da"],
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
            raise ValidationError("Missing delegating seal = {} for evt = {}."
                                  "".format(serder.ked["a"], serder.ked))

        # should we reverify signatures or trust the database?
        # if database is loaded into memory fresh and reverified each bootup
        # then we can trust it otherwise we can't

        return seal


    def logEvent(self, serder, sigers, first=False):
        """
        Update associated logs for verified event.
        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            serder is Serder instance of current event
            sigers is list of Siger instance for current event
            first is Boolean True means first seen accepted log of event.
                    Otherwise means idempotent log of event to accept additional
                    signatures beyond the threshold provided for first seen
        """
        dgkey = dgKey(self.prefixer.qb64b, self.serder.diger.qb64b)
        dtsb = nowIso8601().encode("utf-8")
        self.baser.putDts(dgkey, dtsb)  #  do not change dts if already
        self.baser.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.baser.putEvt(dgkey, serder.raw)
        if first:  # append event dig to first seen database in order
            fn = self.baser.appendFe(self.prefixer.qb64b, self.serder.diger.qb64b)
            self.baser.setDts(dgkey, dtsb)  # first seen so set dts to now
            logger.info("Kever state: %s First seen ordinal %s at %s\nEvent=\n%s\n",
                         self.prefixer.qb64, fn, dtsb.decode("utf-8"),
                         json.dumps(serder.ked, indent=1))
        self.baser.addKe(snKey(self.prefixer.qb64b, self.sn), self.serder.diger.qb64b)
        logger.info("Kever state: %s Added to KEL valid event=\n%s\n",
                        self.prefixer.qb64, json.dumps(serder.ked, indent=1))


    def escrowPSEvent(self, serder, sigers):
        """
        Update associated logs for escrow of partially signed event
        or fully signed delegated event but without delegating event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.baser.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.baser.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.baser.putEvt(dgkey, serder.raw)
        self.baser.addPse(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Kever state: Escrowed partial signature or delegated "
                     "event = %s\n", serder.ked)


class Kevery:
    """
    Kevery (Key Event Message Processing Facility) processes an incoming
    message stream composed of KERI key event related messages and attachments.
    Kevery acts a Kever (key event verifier) factory for managing key state of
    KERI identifier prefixes.

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .ims is bytearray incoming message stream
        .cues is deque of Cues i.e. notices of events or requests to respond to
        .kevers is dict of existing kevers indexed by pre (qb64) of each Kever
        .db is instance of LMDB Baser object
        .framed is Boolean stream is packet framed If True Else not framed
        .pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
        .pre is fully qualified base64 identifier prefix of own identifier if any
        .local is Boolean, True means only process msgs for own events if .pre
                           False means only process msgs for not own events if .pre

    Properties:
        .kever own Kever if self.pre else None

    Properties:

    """
    TimeoutPSE = 3600  # seconds to timeout partial signed escrows
    TimeoutOOE = 1200  # seconds to timeout out of order escrows
    TimeoutURE = 3600  # seconds to timeout unverified receipt escrows
    TimeoutVRE = 3600  # seconds to timeout nverified transferable receipt escrows
    TimeoutLDE = 3600  # seconds to timeout likely duplicitous escrows

    def __init__(self, ims=None, cues=None, kevers=None, db=None, framed=True,
                 pipeline=False, cloned=False, pre=None, local=False):
        """
        Initialize instance:

        Parameters:
            ims is incoming message stream bytearray
            cues is deque if cues to create responses to messages
            kevers is dict of Kever instances of key state in db
            db is Baser instance
            framed is Boolean, True means ims contains only one frame of msg plus
                attachments instead of stream with multiple messages
            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.
            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own
            pre is local or own identifier prefix. Some restriction if present
            local is Boolean, True means only process msgs for own events if .pre
                        False means only process msgs for not own events if .pre



        """
        self.ims = ims if ims is not None else bytearray()
        self.cues = cues if cues is not None else deque()
        self.kevers = kevers if kevers is not None else dict()

        if db is None:
            db = Baser()  # default name = "main"
        self.db = db
        self.framed = True if framed else False  # extract until end-of-stream
        self.pipeline = True if pipeline else False  # process as pipelined
        self.cloned = True if cloned else False  # process as cloned
        self.pre = pre  # local prefix for restrictions on local events
        self.local = True if local else False  # local vs nonlocal restrictions


    @property
    def kever(self):
        """
        Returns kever for its .pre
        """
        return self.kevers[self.pre] if self.pre else None

    @staticmethod
    def _sniff(ims):
        """
        Returns status string of cold start of stream ims bytearray by looking
        at first triplet of first byte to determin if message or counter code
        and if counter code whether Base64 or Base2 representation

        First three bits:
        0o0 = 000 free
        0o1 = 001 cntcode B64
        0o2 = 010 opcode B64
        0o3 = 011 json
        0o4 = 100 mgpk
        0o5 = 101 cbor
        0o6 = 110 mgpk
        007 = 111 cntcode or opcode B2

        counter B64 in (0o1, 0o2) return 'txt'
        counter B2 in (0o7)  return 'bny'
        event in (0o3, 0o4, 0o5, 0o6)  return 'evt'
        unexpected in (0o0)  raise ColdStartError
        Colds = Coldage(msg='msg', txt='txt', bny='bny')

        'msg' if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2)
        'txt' if tritet in (ColdDex.CtB64, ColdDex.OpB64)
        'bny' if tritet in (ColdDex.CtOpB2,)
        """
        if not ims:
            raise ShortageError("Need more bytes.")

        tritet = ims[0] >> 5
        if tritet in (ColdDex.JSON, ColdDex.MGPK1, ColdDex.CBOR, ColdDex.MGPK2):
            return Colds.msg
        if tritet in (ColdDex.CtB64, ColdDex.OpB64):
            return Colds.txt
        if tritet in (ColdDex.CtOpB2,):
            return Colds.bny

        raise ColdStartError("Unexpected tritet={} at stream start.".format(tritet))


    @staticmethod
    def _extract(ims, klas, cold=Colds.txt):
        """
        Extract and return instance of klas from input message stream, ims, given
        stream state, cold, is txt or bny. Inits klas from ims using qb64b or
        qb2 parameter based on cold.
        """
        if cold == Colds.txt:
            return klas(qb64b=ims, strip=True)
        elif cold == Colds.bny:
            return klas(qb2=ims, strip=True)
        else:
            raise ColdStartError("Invalid stream state cold={}.".format(cold))


    @staticmethod
    def _extractor(ims, klas, cold=Colds.txt):
        """
        Returns generator to extract and return instance of klas from input
        message stream, ims, given stream state, cold, is txt or bny.
        Inits klas from ims using qb64b or qb2 parameter based on cold.
        Yields if not enough bytes in ims to fill out klas instance.

        Usage:

        instance = self._extractGen
        """
        while True:
            try:
                if cold == Colds.txt:
                    return klas(qb64b=ims, strip=True)
                elif cold == Colds.bny:
                    return klas(qb2=ims, strip=True)
                else:
                    raise ColdStartError("Invalid stream state cold={}.".format(cold))
            except ShortageError as ex:
                yield


    def process(self, ims=None, framed=None, pipeline=None, cloned=None):
        """
        Processes all messages from incoming message stream, ims,
        when provided. Otherwise process messages from .ims
        Returns when ims is empty.
        Convenience executor for .processAllGen when ims is not live, i.e. fixed

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own. False means ignore attached
                datetimes.

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        processor = self.allProcessor(ims=ims,
                                       framed=framed,
                                       pipeline=pipeline,
                                       cloned=cloned)

        while True:
            try:
                next(processor)
            except StopIteration:
                break


    def allProcessor(self, ims=None, framed=None, pipeline=None, cloned=None):
        """
        Returns generator to process all messages from incoming message stream,
        ims until ims is exhausted (empty) then returns.
        If ims not provided then process messages from .ims
        Must be framed.

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own. False means ignore attached
                datetimes.

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims  # use instance attribute by default

        framed = framed if framed is not None else self.framed
        pipeline = pipeline if pipeline is not None else self.pipeline
        cloned = cloned if cloned is not None else self.cloned

        while ims:
            try:
                done = yield from self.msgProcessor(ims=ims,
                                               framed=framed,
                                               pipeline=pipeline,
                                               cloned=cloned)

            except SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s\n", ex.args[0])

            except (ColdStartError, ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s\n", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg non-extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg non-extraction error: %s\n", ex.args[0])
            yield

        return True


    def processor(self, ims=None, framed=None, pipeline=None, cloned=None):
        """
        Returns generator to continually process messages from incoming message
        stream, ims. Yields waits whenever ims empty.
        If ims not provided then process messages from .ims

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own. False means ignore attached
                datetimes.

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims  # use instance attribute by default

        framed = framed if framed is not None else self.framed
        pipeline = pipeline if pipeline is not None else self.pipeline
        cloned = cloned if cloned is not None else self.cloned

        while True:  # continuous stream processing
            try:
                done = yield from self.msgProcessor(ims=ims,
                                               framed=framed,
                                               pipeline=pipeline,
                                               cloned=cloned)

            except SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s\n", ex.args[0])

            except (ColdStartError, ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s\n", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg non-extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg non-extraction error: %s\n", ex.args[0])
            yield

        return True


    def onceProcessor(self, ims=None, framed=None, pipeline=None, cloned=None):
        """
        Returns generator to process one message from incoming message stream, ims.
        If ims not provided process messages from .ims

        Parameters:
            ims is bytearray of incoming message stream. May contain one or more
                sets each of a serialized message with attached cryptographic
                material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own. False means ignore attached
                datetimes.

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims  # use instance attribute by default

        framed = framed if framed is not None else self.framed
        pipeline = pipeline if pipeline is not None else self.pipeline
        cloned = cloned if cloned is not None else self.cloned

        done = False
        while not done:
            try:
                done = yield from self.msgProcessor(ims=ims,
                                               framed=framed,
                                               pipeline=pipeline,
                                               cloned=cloned)

            except SizedGroupError as ex:  # error inside sized group
                # processOneIter already flushed group so do not flush stream
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s\n", ex.args[0])

            except (ColdStartError, ExtractionError) as ex:  # some extraction error
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg extraction error: %s\n", ex.args[0])
                del ims[:]  # delete rest of stream to force cold restart

            except (ValidationError, Exception) as ex:  # non Extraction Error
                # Non extraction errors happen after successfully extracted from stream
                # so we don't flush rest of stream just resume
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery msg non-extraction error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery msg non-extraction error: %s\n", ex.args[0])
            finally:
                done = True

        return done


    def processOne(self, ims=None, framed=True, pipeline=False, cloned=False):
        """
        Processes one messages from incoming message stream, ims,
        when provided. Otherwise process message from .ims
        Returns once one message is processed.
        Convenience executor for .processOneGen when ims is not live, i.e. fixed

        Parameters:
            ims is bytearray of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own. False means ignore attached
                datetimes.

        New Logic:
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counters.
        """
        processor = self.msgProcessor(ims=ims,
                                        framed=framed,
                                        pipeline=pipeline,
                                        cloned=cloned)
        while True:
            try:
                next(processor)
            except StopIteration:
                break


    def msgProcessor(self, ims=None, framed=True, pipeline=False, cloned=False):
        """
        Returns generator that extracts one msg with attached crypto material
        (signature etc) from incoming message stream, ims, and dispatches
        processing of message with attachments.

        Uses .ims when ims is not provided.

        Iterator yields when not enough bytes in ims to finish one msg plus
        attachments. Returns (which raises StopIteration) when finished.

        Parameters:
            ims is bytearray of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            framed is Boolean, True means ims contains only one frame of msg plus
                counted attachments instead of stream with multiple messages

            pipeline is Boolean, True means use pipeline processor to process
                ims msgs when stream includes pipelined count codes.

            cloned is Boolen, True means cloned message stream so use attached
                datetimes from clone source not own. False means ignore attached
                datetimes.

        Logic:
            Currently only support couters on attachments not on combined or
            on message
            Attachments must all have counters so know if txt or bny format for
            attachments. So even when framed==True must still have counter.
            Do While loop
               sniff to set up first extraction
                  raise exception and flush full tream if stream start is counter
                  must be message
               extract message
               sniff for counter
               if group counter extract and discard but keep track of count
               so if error while processing attachments then only need to flush
               attachment count not full stream.


        """
        if ims is None:
            ims = self.ims

        while not ims:
            yield
        cold = self._sniff(ims)  # check for spurious counters at front of stream
        if cold in (Colds.txt, Colds.bny):  # not message error out to flush stream
            # replace with pipelining here once CESR message format supported.
            raise ColdStartError("Expecting message counter tritet={}"
                                 "".format(cold))
        # Otherwise its a message cold start
        while True:# extract and deserialize message from ims
            try:
                serder = Serder(raw=ims)
            except ShortageError as ex:  # need more bytes
                yield
            else:  # extracted successfully
                del ims[:serder.size]  # strip off event from front of ims
                break

        sigers = []  # list of Siger instances for attached indexed signatures
        cigars = []  # List of cigars to hold nontrans rct couplets
        pipelined = False  # all attachments in one big pipeline counted group
        # extract and deserialize attachments
        try:  # catch errors here to flush only counted part of stream
            # extract attachments must start with counter so know if txt or bny.
            while not ims:
                yield
            cold = self._sniff(ims)  # expect counter at front of attachments
            if cold != Colds.msg:  # not new message so process attachments
                ctr = yield from self._extractor(ims=ims, klas=Counter, cold=cold)
                if ctr.code == CtrDex.AttachedMaterialQuadlets:  # pipeline ctr?
                    pipelined = True
                    # compute pipelined attached group size based on txt or bny
                    pags = ctr.count * 4 if cold == Colds.txt else ctr.count * 3
                    while len(ims) < pags:  # wait until rx full pipelned group
                        yield

                    pims = ims[:pags]  # copy out substream pipeline group
                    del ims[:pags]  # strip off from ims
                    ims = pims  # now just process substream as one counted frame

                    if pipeline:
                        pass  #  pass extracted ims to pipeline processor
                        return

                    ctr = yield from self._extractor(ims=ims, klas=Counter, cold=cold)

                # iteratively process attachment counters (all non pipelined)
                while True:  # do while already extracted first counter is ctr
                    if ctr.code == CtrDex.ControllerIdxSigs:
                        for i in range(ctr.count): # extract each attached signature
                            siger = yield from self._extractor(ims=ims, klas=Siger, cold=cold)
                            sigers.append(siger)


                    elif ctr.code == CtrDex.WitnessIdxSigs:
                        pass

                    elif ctr.code == CtrDex.NonTransReceiptCouples:
                        # extract attached rct couplets into list of sigvers
                        # verfer property of cigar is the identifier prefix
                        # cigar itself has the attached signature

                        for i in range(ctr.count): # extract each attached couple
                            verfer = yield from self._extractor(ims=ims, klas=Verfer, cold=cold)
                            cigar = yield from self._extractor(ims=ims, klas=Cigar, cold=cold)
                            cigar.verfer = verfer
                            cigars.append(cigar)

                    elif ctr.code == CtrDex.TransReceiptQuadruples:
                        pass

                    elif ctr.code == CtrDex.FirstSeenReplayCouples:
                        pass

                    else:
                        raise UnexpectedCodeError("Unsupported count code={}."
                                                  "".format(ctr.code))

                    if pipelined:  # process to end of stream (group)
                        if not ims:  # end of pipelined group frame
                            break
                    elif framed:
                        # because not all in one pipeline group, each attachment
                        # group may switch stream state txt or bny
                        if not ims:  # end of frame
                            break
                        cold = self._sniff(ims)
                        if cold == Colds.msg:  # new message so attachments done
                            break  # finished attachments since new message
                    else:  # process until next message
                        # because not all in one pipeline group, each attachment
                        # group may switch stream state txt or bny
                        while not ims:
                            yield  # no frame so must wait for next message
                        cold = self._sniff(ims)  # ctr or msg
                        if cold == Colds.msg:  # new message
                            break  # finished attachments since new message

                    while True:  # not msg so extract next counter
                        ctr = yield from self._extractor(ims=ims, klas=Counter, cold=cold)

        except ExtractionError as ex:
            if pipelined:  # extracted pipelined group is preflushed
                raise SizedGroupError("Error processing pipelined size"
                                "attachment group of size={}.".format(pags))
            raise  # no pipeline group so can't preflush, must flush stream


        ilk = serder.ked["t"]  # dispatch abased on ilk

        if ilk in [Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt]:  # event msg


            if not sigers:
                raise ValidationError("Missing attached signature(s) for evt "
                                      "= {}.".format(serder.ked))

            self.processEvent(serder, sigers)

        elif ilk in [Ilks.rct]:  # event receipt msg (nontransferable)

            if not cigars:
                raise ValidationError("Missing attached receipt couple(s)"
                                      " for evt = {}.".formate(serder.ked))

            self.processReceipt(serder, cigars)

        elif ilk in [Ilks.vrc]:  # validator event receipt msg (transferable)

            if not sigers:
                raise ValidationError("Missing attached signature(s) to receipt"
                                      " for evt = {}.".format(serder.ked))

            self.processChit(serder, sigers)

        else:
            raise ValidationError("Unexpected message ilk = {} for evt ="
                                  " {}.".format(ilk, serder.ked))

        return True  # done state



    def processEvent(self, serder, sigers):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:
            serder is Serder instance of event to process
            sigers is list of Siger instances of signatures attached to event
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

        if self.pre:
            if self.local:
                if self.pre != pre:  # nonlocal event when in local mode
                    raise ValueError("Nonlocal event pre={} when local mode for pre={}."
                                                      "".format(pre, self.pre))
            else:
                if self.pre == pre:  # local event when not in local mode
                    raise ValueError("Local event pre={} when nonlocal mode."
                                                      "".format(pre))


        if pre not in self.kevers:  #  first seen event for pre
            if ilk in (Ilks.icp, Ilks.dip):  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem
                # otherwise adds to KEL
                # create kever from serder
                kever = Kever(serder=serder,
                              sigers=sigers,
                              baser=self.db)
                self.kevers[pre] = kever  # not exception so add to kevers

                if not self.pre or self.pre != pre:  # not own event when owned
                    # create cue for receipt   direct mode for now
                    #  receipt of actual type is dependent on own type of identifier
                    self.cues.append(dict(kin="receipt", serder=serder))

            else:  # not inception so can't verify sigs etc, add to out-of-order escrow
                self.escrowOOEvent(serder=serder, sigers=sigers)
                raise OutOfOrderError("Out-of-order event={}.".format(ked))

        else:  # already accepted inception event for pre
            if ilk in (Ilks.icp, Ilks.dip):  # another inception event so maybe duplicitous
                if sn != 0:
                    raise ValueError("Invalid sn={} for inception event={}."
                                     "".format(sn, serder.ked))
                # check if duplicate of existing inception
                eserder = self.fetchEstEvent(pre, sn)
                if eserder.dig == dig:  # event is a duplicate but not duplicitous
                    # may have attached valid signature not yet logged
                    # raises ValidationError if no valid sig
                    kever = self.kevers[pre]
                    indices = kever.verifySigs(serder=serder,
                                               sigers=sigers,
                                               verfers=eserder.verfers)
                    if indices:  # at least one verified signature so log sigs
                        # not first seen update
                        kever.logEvent(serder, sigers)  # idempotent update db logs

                else:   # escrow likely duplicitous event
                    self.escrowLDEvent(serder=serder, sigers=sigers)
                    raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))

            else:  # rot, drt, or ixn, so sn matters
                kever = self.kevers[pre]  # get existing kever for pre
                sno = kever.sn + 1  # proper sn of new inorder event

                if sn > sno:  # sn later than sno so out of order escrow
                    # escrow out-of-order event
                    self.escrowOOEvent(serder=serder, sigers=sigers)
                    raise OutOfOrderError("Out-of-order event={}.".format(ked))

                elif ((sn == sno) or  # new inorder event or recovery
                      (ilk in (Ilks.rot, Ilks.drt) and kever.lastEst.s < sn <= sno )):
                    # verify signatures etc and update state if valid
                    # raise exception if problem.
                    # Otherwise adds to KELs
                    kever.update(serder=serder, sigers=sigers)

                    if not self.pre or self.pre != pre:  # not own event when owned
                        # create cue for receipt   direct mode for now
                        #  receipt of actual type is dependent on own type of identifier
                        self.cues.append(dict(kin="receipt", serder=serder))

                else:  # maybe duplicitous
                    # check if duplicate of existing valid accepted event
                    ddig = bytes(self.db.getKeLast(key=snKey(pre, sn))).decode("utf-8")
                    if ddig == dig:  # event is a duplicate but not duplicitous
                        eserder = self.fetchEstEvent(pre, sn)
                        # may have attached valid signature not yet logged
                        # raises ValidationError if no valid sig
                        kever = self.kevers[pre]
                        indices = kever.verifySigs(serder=serder,
                                                   sigers=sigers,
                                                   verfers=eserder.verfers)
                        if indices:  # at least one verified signature so log sigs
                            # not first seen update
                            kever.logEvent(serder, sigers)  # idempotent update db logs

                    else:   # escrow likely duplicitous event
                        self.escrowLDEvent(serder=serder, sigers=sigers)
                        raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))


    def processReceipt(self, serder, cigars):
        """
        Process one receipt serder with attached cigars

        Parameters:
            serder is Serder instance of serialized receipt message
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
                if self.pre and self.pre == cigar.verfer.qb64:  # own receipt when own nontrans
                    if self.pre == pre:  # own receipt attachment on own event
                        logger.info("Kevery process: skipped own receipt attachment"
                                    " on own event receipt=\n%s\n",
                                               json.dumps(serder.ked, indent=1))
                        continue  # skip own receipt attachment on own event
                    if not self.local:  # own receipt on other event when not local
                        logger.info("Kevery process: skipped own receipt attachment"
                                    " on nonlocal event receipt=\n%s\n",
                                               json.dumps(serder.ked, indent=1))
                        continue  # skip own receipt attachment on non-local event

                if cigar.verfer.verify(cigar.raw, lserder.raw):
                    # write receipt couple to database
                    couple = cigar.verfer.qb64b + cigar.qb64b
                    self.db.addRct(key=dgkey, val=couple)

        else:  # no events to be receipted yet at that sn so escrow
            self.escrowUREvent(serder, cigars, dig=ked["d"])  # digest in receipt
            raise UnverifiedReceiptError("Unverified receipt={}.".format(ked))


    def processChit(self, serder, sigers):
        """
        Process one transferable validator receipt (chit) serder with attached sigers

        Parameters:
            serder is chit serder (transferable validator receipt message)
            sigers is list of Siger instances that contain signature

        Chit dict labels
            v vs  # version string
            i pre  # qb64 prefix
            s sn   # hex of sequence number
            t ilk  # vrc
            d dig  # qb64 digest of receipted event
            a seal # event seal of receipters last est event at time of receipt

        Seal labels
            i pre  # qb64 prefix of receipter
            s sn   # hex of sequence number of est event for receipter keys
            d dig  # qb64 digest of est event for receipter keys

        """
        # fetch  pre, dig,seal to process
        ked = serder.ked
        pre = serder.pre
        sn = self.validateSN(ked)

        # Only accept receipt if for last seen version of receipted event at sn
        ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.
        seal = SealEvent(**ked["a"])
        if self.pre and self.pre == seal.i:  # own chit
            if self.pre == pre:  # skip own chits of own events
                raise ValidationError("Own pre={} chit of own event {}."
                                  "".format(self.pre, ked))
            if not self.local:  # skip own chits of nonlocal events
                raise ValidationError("Own pre={} seal in chit of nonlocal event "
                                  "{}.".format(self.pre, ked))

        if ldig is not None and seal.i in self.kevers:  #  verify digs match last seen and receipt dig
            # both receipted event and receipter in database
            # so retreive
            ldig = bytes(ldig).decode("utf-8")

            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            lraw = bytes(self.db.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none because ldig was in KE
            lserder = Serder(raw=lraw)  # deserialize event raw

            if not lserder.compare(dig=ked["d"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["s"], ked))

            # retrieve dig of last event at sn of receipter.
            sdig = self.db.getKeLast(key=snKey(pre=seal.i, sn=int(seal.s, 16)))
            if sdig is None:
                # receipter's est event not yet in receipter's KEL
                # receipter's seal event not in receipter's KEL
                self.escrowVREvent(serder, sigers, seal, dig=ked["d"])
                raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                    "missing establishment event of transferable "
                                    "validator, receipt={}.".format(ked))

            # retrieve last event itself of receipter
            sraw = self.db.getEvt(key=dgKey(pre=seal.i, dig=bytes(sdig)))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = Serder(raw=bytes(sraw))
            if not sserder.compare(dig=seal.d):  # seal dig not match event
                raise ValidationError("Bad chit seal at sn = {} for rct = {}."
                                      "".format(seal.s, ked))

            verfers = sserder.verfers
            if not verfers:
                raise ValidationError("Invalid seal est. event dig = {} for "
                                      "receipt from pre ={} no keys."
                                      "".format(seal.d, seal.i))

            # convert sn in seal to fully qualified SeqNumber 24 bytes, raw 16 bytes
            sealet = seal.i.encode("utf-8") + Seqner(sn=int(seal.s, 16)).qb64b + seal.d.encode("utf-8")

            for siger in sigers:  # verify sigs
                if siger.index >= len(verfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(siger.index))

                siger.verfer = verfers[siger.index]  # assign verfer
                if siger.verfer.verify(siger.raw, lserder.raw):  # verify sig
                    # good sig so write receipt quadruple to database
                    quadruple = sealet + siger.qb64b
                    self.db.addVrc(key=dgkey, val=quadruple)  # dups kept

        else:  # escrow  either receiptor or receipted event not yet in database
            self.escrowVREvent(serder, sigers, seal, dig=ked["d"])
            raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                  "missing associated event for transferable "
                                  "validator receipt={}.".format(ked))

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


    def escrowOOEvent(self, serder, sigers):
        """
        Update associated logs for escrow of Out-of-Order event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.db.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addOoe(snKey(serder.preb, serder.sn), serder.digb)
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
        self.db.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addLde(snKey(serder.preb, serder.sn), serder.digb)
        # log duplicitous
        logger.info("Kevery process: escrowed likely duplicitous event=\n%s\n",
                                            json.dumps(serder.ked, indent=1))


    def escrowUREvent(self, serder, cigars, dig):
        """
        Update associated logs for escrow of Unverified Event Receipt (non-transferable)

        Parameters:
            serder instance of receipt msg not receipted event
            cigars is list of Cigar instances for event receipt
            dig is digest in receipt of receipted event not serder.dig because
                serder is of receipt not receipted event
        """
        # note receipt dig algo may not match database dig also so must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to be triple with
        # dig, witness prefix, sig stored at kel pre, sn so can compare digs
        # with different algos.  Can't lookup by dig for same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, dig), nowIso8601().encode("utf-8"))
        for cigar in cigars:  # escrow each triple
            if cigar.verfer.transferable:  # skip transferable verfers
                continue  # skip invalid triplets
            triple = dig.encode("utf-8") + cigar.verfer.qb64b + cigar.qb64b
            self.db.addUre(key=snKey(serder.preb, serder.sn), val=triple)  # should be snKey
        # log escrowed
        logger.info("Kevery process: escrowed unverified receipt of pre= %s "
                     " sn=%x dig=%s\n", serder.pre, serder.sn, dig)


    def escrowVREvent(self, serder, sigers, seal, dig):
        """
        Update associated logs for escrow of Unverified Validator Event Receipt
        (transferable)

        Parameters:
            serder instance of receipt message not receipted event
            sigers is list of Siger instances attached to receipt message
            seal is SealEvent instance (namedTuple)
            dig is digest of receipted event provided in receipt

        """
        # Receipt dig algo may not match database dig. So must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to be quintlet with
        # edig, validator prefix, validtor est event sn, validator est evvent dig
        # and sig stored at kel pre, sn so can compare digs
        # with different algos.  Can't lookup by dig for the same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, dig), nowIso8601().encode("utf-8"))
        prelet = (dig.encode("utf-8") + seal.i.encode("utf-8") +
                  Seqner(snh=seal.s).qb64b + seal.d.encode("utf-8"))
        for siger in sigers:  # escrow each quintlet
            quintuple = prelet +  siger.qb64b  # quintuple
            self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified transferabe validator "
                     "receipt of pre= %s sn=%x dig=%s\n", serder.pre, serder.sn, dig)


    def processEscrows(self):
        """
        Iterate throush escrows and process any that may now be finalized

        Parameters:
        """

        try:
            self.processOutOfOrders()
            self.processPartials()
            self.processDuplicitous()
            self.processUnverifieds()
            self.processTransUnverifieds()

        except Exception as ex:  # log diagnostics errors etc
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Kevery escrow process error: %s\n", ex.args[0])
            else:
                logger.error("Kevery escrow process error: %s\n", ex.args[0])


    def processPartials(self):
        """
        Process events escrowed by Kever that were only partially fulfilled.
        Either due to missing signatures or missing dependent events like a
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

        ims = bytearray()
        key = ekey = b''  # both start same. when not same means escrows found
        while True:  # break when done
            for ekey, edig in self.db.getPseItemsNextIter(key=key):
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
                    dtnow =  datetime.datetime.now(datetime.timezone.utc)
                    dte = fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutPSE):
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
                    ims.extend(eserder.raw)

                    #  get sigs and attach
                    sigs = self.db.getSigs(dgKey(pre, bytes(edig)))
                    if not sigs:  #  otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    counter = Counter(code=CtrDex.ControllerIdxSigs, count=len(sigs))
                    ims.extend(counter.qb64b)
                    for sig in sigs:  # stored in db as qb64b
                        ims.extend(sig)

                    # process event
                    self.processOne(ims=ims)  # default framed True

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

                except (MissingSignatureError, MissingDelegatingSealError) as ex:
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
                    logger.info("Kevery unescrow succeeded in valid event: "
                             "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey


    def processOutOfOrders(self):
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

        ims = bytearray()
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
                    dtnow =  datetime.datetime.now(datetime.timezone.utc)
                    dte = fromIso8601(bytes(dtb))
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
                    ims.extend(eserder.raw)

                    #  get sigs and attach
                    sigs = self.db.getSigs(dgKey(pre, bytes(edig)))
                    if not sigs:  #  otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    counter = Counter(code=CtrDex.ControllerIdxSigs,
                                      count=len(sigs))
                    ims.extend(counter.qb64b)
                    for sig in sigs:  # stored in db as qb64b
                        ims.extend(sig)

                    # process event
                    self.processOne(ims=ims)  # default framed True

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


    def processUnverifieds(self):
        """
        Process event receipts escrowed by Kever that are unverified.
        A receipt is unverified if the associated event has not been accepted into its KEL.
        Without the event there is no way to know where to store the receipt couplets.

        The escrow is a triple with dig+spre+sig the verified receipt is just the
        couple spre+sig that is stored by event dig

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different recipt triple inserted in insertion order.
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
                    ediger, sprefixer, cigar = detriple(etriplet)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(ediger.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", ediger.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(ediger.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow =  datetime.datetime.now(datetime.timezone.utc)
                    dte = fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutURE):
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

                        raise UnverifiedReceiptError("Missing receipted evt at pre={} "
                                              " sn={:x}".format(pre, sn))

                    dig = bytes(raw)
                    # get receipted event using pre and edig
                    raw = self.db.getEvt(dgKey(pre, dig))
                    if raw is None:  # receipted event superseded so remove from escrow
                        logger.info("Kevery unescrow error: Invalid receipted "
                                 "event refereance at pre=%s sn=%x\n", pre, sn)

                        raise ValidationError("Invalid receipted evt reference"
                                          " at pre={} sn={:x}".format(pre, sn))

                    serder = Serder(raw=bytes(raw))  # receipted event

                    #  compare digs
                    if not ediger.compare(ser=serder.raw, diger=ediger):
                        logger.info("Kevery unescrow error: Bad receipt dig."
                             "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                        raise ValidationError("Bad escrowed receipt dig at "
                                          "pre={} sn={:x} receipter={}."
                                          "".format( pre, sn, sprefixer.qb64))

                    #  verify sig verfer key is prefixer from triple
                    cigar.verfer = Verfer(qb64b=sprefixer.qb64b)
                    if not cigar.verfer.verify(cigar.raw, serder.raw):
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Bad receipt sig."
                                 "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                        raise ValidationError("Bad escrowed receipt sig at "
                                              "pre={} sn={:x} receipter={}."
                                              "".format( pre, sn, sprefixer.qb64))

                    # write receipt couple to database
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
                    logger.info("Kevery unescrow succeeded for event=\n%s\n",
                                json.dumps(serder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey #  setup next while iteration, with key after ekey


    def processTransUnverifieds(self):
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
                    ediger, sprefixer, sseqner, sdiger, siger = dequintuple(equinlet)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(ediger.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                 " at dig = %s\n", ediger.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(ediger.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow =  datetime.datetime.now(datetime.timezone.utc)
                    dte = fromIso8601(bytes(dtb))
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


    def processDuplicitous(self):
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

        ims = bytearray()
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
                    dtnow =  datetime.datetime.now(datetime.timezone.utc)
                    dte = fromIso8601(bytes(dtb))
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
                    ims.extend(eserder.raw)

                    #  get sigs and attach
                    sigs = self.db.getSigs(dgKey(pre, bytes(edig)))
                    if not sigs:  #  otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                 "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    counter = Counter(code=CtrDex.ControllerIdxSigs,
                                      count=len(sigs))
                    ims.extend(counter.qb64b)
                    for sig in sigs:  # stored in db as qb64b
                        ims.extend(sig)

                    # process event
                    self.processOne(ims=ims)  # default framed True

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
