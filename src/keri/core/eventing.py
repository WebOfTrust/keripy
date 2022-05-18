# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""
import datetime
import json
import logging
from collections import namedtuple
from dataclasses import dataclass, astuple
from urllib.parse import urlsplit
from math import ceil
from  ordered_set import OrderedSet as oset
from hio.help import decking

from . import coring
from .coring import (Versify, Serials, Ilks, MtrDex, NonTransDex, CtrDex, Counter,
                     Seqner, Siger, Cigar, Dater,
                     Verfer, Diger, Nexter, Prefixer, Serder, Tholder, Saider)
from .. import help
from .. import kering
from ..db import basing
from ..db.dbing import dgKey, snKey, fnKey, splitKeySN, splitKey
from ..help import helping
from ..kering import (MissingEntryError,
                      ValidationError, MissingSignatureError,
                      MissingWitnessSignatureError, UnverifiedReplyError,
                      MissingDelegationError, OutOfOrderError,
                      LikelyDuplicitousError, UnverifiedWitnessReceiptError,
                      UnverifiedReceiptError, UnverifiedTransferableReceiptError, QueryNotFoundError)
from ..kering import Version

logger = help.ogler.getLogger()

EscrowTimeoutPS = 3600  # seconds for partial signed escrow timeout

ICP_LABELS = ["v", "i", "s", "t", "kt", "k", "n",
              "bt", "b", "c", "a"]
DIP_LABELS = ["v", "i", "s", "t", "kt", "k", "n",
              "bt", "b", "c", "a", "di"]
ROT_LABELS = ["v", "i", "s", "t", "p", "kt", "k", "n",
              "bt", "br", "ba", "a"]
DRT_LABELS = ["v", "i", "s", "t", "p", "kt", "k", "n",
              "bt", "br", "ba", "a"]
IXN_LABELS = ["v", "i", "s", "t", "p", "a"]

KSN_LABELS = ["v", "i", "s", "p", "d", "f", "dt", "et", "kt", "k", "n",
              "bt", "b", "c", "ee", "di"]

RPY_LABELS = ["v", "t", "d", "dt", "r", "a"]


@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    EstOnly: str = 'EO'  # Only allow establishment events
    DoNotDelegate: str = 'DND'  # Dot not allow delegated identifiers
    NoBackers: str = 'NB'  # Do not allow any backers for registry

    def __iter__(self):
        return iter(astuple(self))


TraitDex = TraitCodex()  # Make instance

# Location of last establishment key event: sn is int, dig is qb64 digest
LastEstLoc = namedtuple("LastEstLoc", 's d')

#  for the following Seal namedtuples use the ._asdict() method to convert to dict
#  when using in events

# Digest Seal: uniple (d,)
# d = dig is qb64 digest of data
SealDigest = namedtuple("SealDigest", 'd')

# Root Seal: uniple (rd,)
# rd = root dig id qb64 digest that is root of data digest Merkle tree
SealRoot = namedtuple("SealRoot", 'rd')

# Backer Seal: couple (bi, d)
# bi = pre qb64 backer nontrans identifier prefix
# d = dig is qb64 digest of backer metadata attached to event with anchored seal
SealBacker = namedtuple("SealBacker", 'bi d')

# Event Seal: triple (i, s, d)
# i = pre is qb64 of identifier prefix of KEL for event,
# s = sn of event as lowercase hex string  no leading zeros,
# d = dig is qb64 digest of event
SealEvent = namedtuple("SealEvent", 'i s d')

# Last Estalishment Event Seal: uniple (i,)
# i = pre is qb64 of identifier prefix of KEL from which to get last est, event
# used to indicate to get the latest keys available from KEL for 'i'
SealLast = namedtuple("SealLast", 'i')

# State (latest current) Event: triple (s, t, d)
# s = sn of latest event as lowercase hex string  no leading zeros,
# t = message type of latest event (ilk)
# d = digest of latest event
StateEvent = namedtuple("StateEvent", 's t d')

# State (latest current) Establishment Event: quadruple (s, d, br, ba)
# s = sn of latest est event as lowercase hex string  no leading zeros,
# d = digest of latest establishment event
# br = backer (witness) remove list (cuts) from latest est event
# ba = backer (witness) add list (adds) from latest est event
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
    Free: int = 0o0  # not taken
    CtB64: int = 0o1  # CountCode Base64
    OpB64: int = 0o2  # OpCode Base64
    JSON: int = 0o3  # JSON Map Event Start
    MGPK1: int = 0o4  # MGPK Fixed Map Event Start
    CBOR: int = 0o5  # CBOR Map Event Start
    MGPK2: int = 0o6  # MGPK Big 16 or 32 Map Event Start
    CtOpB2: int = 0o7  # CountCode or OpCode Base2

    def __iter__(self):
        return iter(astuple(self))


ColdDex = ColdCodex()  # Make instance

Coldage = namedtuple("Coldage", 'msg txt bny')  # stream cold start status
Colds = Coldage(msg='msg', txt='txt', bny='bny')


# Future make Cues dataclasses  instead of dicts. Dataclasses so may be converted
# to/from dicts easily  example: dict(kin="receipt", serder=serder)


def simple(n):
    """
    Returns int as simple majority of n when n >=1
        otherwise returns 0
    Parameters:
        n is int total number of elements
    """
    return min(max(0, n), (max(0, n) // 2) + 1)


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
        f1 = max(1, max(0, n - 1) // 3)  # least floor f subject to n >= 3*f+1
        f2 = max(1, ceil(max(0, n - 1) / 3))  # most ceil f subject to n >= 3*f+1
        if weak:  # try both fs to see which one has lowest m
            return min(n, ceil((n + f1 + 1) / 2), ceil((n + f2 + 1) / 2))
        else:
            return min(n, max(0, n - f1, ceil((n + f1 + 1) / 2)))
    else:
        f = max(0, f)
        m1 = ceil((n + f + 1) / 2)
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
    Returns tuple of (seqner, saider) from concatenated bytes or bytearray
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
    saider = Saider(qb64b=data, strip=strip)
    return (seqner, saider)


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

    saider = Saider(qb64b=data, strip=strip)
    if not strip:
        data = data[len(saider.qb64b):]
    prefixer = Prefixer(qb64b=data, strip=strip)
    if not strip:
        data = data[len(prefixer.qb64b):]
    cigar = Cigar(qb64b=data, strip=strip)
    return (saider, prefixer, cigar)


def deTransReceiptQuadruple(data, strip=False):
    """
    Returns tuple (quadruple) of (prefixer, seqner, diger, siger) from
    concatenated bytes or bytearray of quadruple made up of qb64 or qb64b
    versions of spre+ssnu+sdig+sig.
    Quadruple is used for receipts signed by transferable prefix keys. Recept
    for event that is in kel where event is given by context or key

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
    saider = Saider(qb64b=data, strip=strip)
    if not strip:
        data = data[len(saider.qb64b):]
    siger = Siger(qb64b=data, strip=strip)
    return (prefixer, seqner, saider, siger)


def deTransReceiptQuintuple(data, strip=False):
    """
    Returns tuple of (ediger, seal prefixer, seal seqner, seal diger, siger)
    from concatenated bytes or bytearray of quintuple made up of qb64 or qb64b
    versions of quntipuple given by  concatenation of  edig+spre+ssnu+sdig+sig.
    Quintuple is used for unverified escrows of validator receipts signed
    by transferable prefix keys. Receipt for event that is not yet in KEL where
    event is given by event digest (ediger)

    Parameters:
        quintuple is bytes concatenation of edig+spre+ssnu+sdig+sig from receipt
        deletive is Boolean True means delete from data each part as parsed
            Only useful if data is bytearray from front of stream
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    if hasattr(data, "encode"):
        data = data.encode("utf-8")  # convert to bytes

    esaider = Saider(qb64b=data, strip=strip)  # diger of receipted event
    if not strip:
        data = data[len(esaider.qb64b):]
    sprefixer = Prefixer(qb64b=data, strip=strip)  # prefixer of recipter
    if not strip:
        data = data[len(sprefixer.qb64b):]
    sseqner = Seqner(qb64b=data, strip=strip)  # seqnumber of receipting event
    if not strip:
        data = data[len(sseqner.qb64b):]
    ssaider = Saider(qb64b=data, strip=strip)  # diger of receipting event
    if not strip:
        data = data[len(ssaider.qb64b):]
    siger = Siger(qb64b=data, strip=strip)  # indexed siger of event
    return esaider, sprefixer, sseqner, ssaider, siger


def validateSN(sn, inceptive=None):
    """
    Returns:
        sn (int): converted from sn hex str

    Raises ValueError if invalid sn

    Parameters:
       sn (str): hex char sequence number of event or seal in an event
       inceptive(bool): Check sn value and raise ValueError if invalid
                        None means check for sn < 0
                        True means check for sn != 0
                        False means check for sn < 1

    """
    if len(sn) > 32:
        raise ValueError("Invalid sn = {} too large.".format(sn))

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


def verifySigs(raw, sigers, verfers):
    """
    Returns tuple of (vsigers, vindices) where:
        vsigers is list  of unique verified sigers with assigned verfer
        vindices is list of indices from those verified sigers

    The returned vsigers  and vindices may be used for threshold validation

    Assigns appropriate verfer from verfers to each siger based on siger index
    If no signatures verify then sigers and indices are empty

    Parameters:
        raw (bytes) signed data
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
            logger.info("Skipped sig: Index=%s to large.\n", siger.index)
        siger.verfer = verfers[siger.index]  # assign verfer

    # create lists of unique verified signatures and indices
    vindices = []
    vsigers = []
    for siger in usigers:
        if siger.verfer.verify(siger.raw, raw):
            vindices.append(siger.index)
            vsigers.append(siger)

    return (vsigers, vindices)


def validateSigs(serder, sigers, verfers, tholder):
    """
    Validates signatures given by sigers using keys given by verfers on msg
    given by serder subject to threshold given by tholder. Returns subset of
    valid signatures for storage.

    Returns:
        result (tuple): (sigers, valid) where:
            sigers (list): subset of of provided sigers of verified signatures
                on serder using verfers
            valid (bool): True means threshold from tholder satisfied by sigers,
                          False otherwise.

    Parameters:
        serder (coring.Serder): instance of message
        sigers (Iterable): Siger instances of indexed signatures.
            Index is offset into verfers list each providing verification key
        verfers (Iterable): Verfer instances of keys
        tholder (Tholder): instance of signing threshold (sith)

        seqner is Seqner instance of delegating event sequence number.
            If this event is not delegated then seqner is ignored
        diger is Diger instance of of delegating event digest.
            If this event is not delegated then diger is ignored

    """
    valid = False
    if len(verfers) < tholder.size:
        raise ValidationError("Invalid sith = {} for keys = {}."
                              "".format(tholder.sith,
                                        [verfer.qb64 for verfer in verfers]))

    # get unique verified sigers and indices lists from sigers list
    sigers, indices = verifySigs(raw=serder.raw, sigers=sigers, verfers=verfers)
    # sigers  now have .verfer assigned

    # check if satisfies threshold for fully signed
    if not indices:  # must have a least one verified sig
        raise ValidationError("No verified signatures for message={}."
                              "".format(serder.ked))

    valid = tholder.satisfy(indices)

    return (sigers, valid)


def fetchTsgs(db, saider, snh=None):
    """
    Fetch tsgs for saider from .db.ssgs. When sn then only fetch if sn <= snh
    Returns:
        tsgs (list): of tsg quadruple of form (prefixer, seqner, diger, sigers)
            where:
                prefixer (Prefixer): instance trans signer aid,
                seqner (Seqner): of sn of trans signer key state est event
                diger (Diger): of digest of trans signer key state est event
                signers (list): of Siger instances of indexed signatures

    Parameters:
        db: (Cesr
        saider (Saider): instance of said for reply SAD to which signatures
            are attached
        snh (str): 32 char zero pad lowercase hex of sequence number f"{sn:032x}"
    """
    klases = (coring.Prefixer, coring.Seqner, coring.Diger)
    args = ("qb64", "snh", "qb64")
    tsgs = []  # transferable signature groups
    sigers = []
    old = None  # empty keys
    for keys, siger in db.getItemIter(keys=(saider.qb64, "")):
        triple = keys[1:]
        if triple != old:  # new tsg
            if snh is not None and triple[1] > snh:  # only lower sn
                break
            if sigers:  # append tsg made for old and sigers
                tsgs.append((*helping.klasify(sers=old, klases=klases, args=args), sigers))
                sigers = []
            old = triple
        sigers.append(siger)
    if sigers and old:
        tsgs.append((*helping.klasify(sers=old, klases=klases, args=args), sigers))

    return tsgs


def incept(keys,
           sith=None,
           nkeys=None,
           nsith=None,
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
        nkeys is list of qb64 next key digests
        nsith  is is int, string, or list format for next signing threshold
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

    if nsith is None:
        nsith = 0 if not nkeys else "{:x}".format(max(1, ceil(len(nkeys) / 2)))

    if nkeys is None:
        nkeys = []

    ntholder = Tholder(sith=nsith)
    if ntholder.size > len(nkeys):
        raise ValueError("Invalid nsith = {} for keys = {}".format(nsith, nkeys))

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

    # see compact labels in KID0003.md

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=ntholder.sith,
               n=nkeys,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=data,  # list of seal dicts
               )

    if code is None and len(keys) == 1:
        prefixer = Prefixer(qb64=keys[0])  # not self-addressing code
        if prefixer.digestive:
            raise ValueError("Invalid code, digestive={}, must be derived from"
                             " ked.".format(prefixer.code))
    else:
        # raises derivation error if non-empty nxt but ephemeral code
        prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64
    if prefixer.digestive:
        ked["d"] = prefixer.qb64
    else:
        _, ked = coring.Saider.saidify(sad=ked)

    return Serder(ked=ked)  # return serialized ked


def delcept(keys,
            delpre,
            code=None,
            sith=None,
            nkeys=None,
            nsith=None,
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
        sith is int of signing threshold
        nkeys is list of qb64 next key digests
        nsith  is is int, string, or list format for next signing threshold
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
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.size > len(keys):
        raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))

    if nsith is None:
        nsith = 0 if not nkeys else "{:x}".format(max(1, ceil(len(nkeys) / 2)))


    if nkeys is None:
        nkeys = []

    ntholder = Tholder(sith=nsith)
    if ntholder.size > len(nkeys):
        raise ValueError("Invalid nsith = {} for keys = {}".format(nsith, nkeys))

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
               t=ilk,
               d="",
               i="",  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               kt=tholder.sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=ntholder.sith,
               n=nkeys,  # hash qual Base64
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
        raise ValueError("Invalid derivation code = {} for delegation. Must be"
                         " digestive".format(prefixer.code))

    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64
    if prefixer.digestive:
        ked["d"] = prefixer.qb64
    else:
        _, ked = coring.Saider.saidify(sad=ked)

    return Serder(ked=ked)  # return serialized ked


def rotate(pre,
           keys,
           dig,
           sn=1,
           sith=None,
           nkeys=None,
           nsith=None,
           toad=None,
           wits=None,  # prior existing wits
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
        nkeys is list of qb64 next key digests
        nsith  is is int, string, or list format for next signing threshold
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

    if nsith is None:
        nsith = 0 if not nkeys else "{:x}".format(max(1, ceil(len(nkeys) / 2)))


    if nkeys is None:
        nkeys = []

    ntholder = Tholder(sith=nsith)
    if ntholder.size > len(nkeys):
        raise ValueError("Invalid sith = {} for keys = {}".format(nsith, nkeys))

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
               t=ilk,
               d="",
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               p=dig,  # qb64 digest of prior event
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=ntholder.sith,
               n=nkeys,  # hash qual Base64
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               a=data,  # list of seals
               )
    _, ked = coring.Saider.saidify(sad=ked)

    return Serder(ked=ked)  # return serialized ked


def deltate(pre,
            keys,
            dig,
            sn=1,
            sith=None,
            nkeys=None,
            nsith=None,
            toad=None,
            wits=None,  # prior existing wits
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
        nkeys is list of qb64 next key digests
        nsith  is is int, string, or list format for next signing threshold
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
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.size > len(keys):
        raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))

    if nsith is None:
        nsith = 0 if not nkeys else "{:x}".format(max(1, ceil(len(nkeys) / 2)))

    if nkeys is None:
        nkeys = []

    ntholder = Tholder(sith=nsith)
    if ntholder.size > len(nkeys):
        raise ValueError("Invalid nsith = {} for keys = {}".format(nsith, nkeys))

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
        toad = int(toad, 16)
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
               t=ilk,
               d="",
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               p=dig,  # qb64 digest of prior event
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=ntholder.sith,
               n=nkeys,
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               a=data,  # list of seals ordered mappings may be empty
               )
    _, ked = coring.Saider.saidify(sad=ked)

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
               t=ilk,
               d="",
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               p=dig,  # qb64 digest of prior event
               a=data,  # list of seals
               )
    _, ked = coring.Saider.saidify(sad=ked)

    return Serder(ked=ked)  # return serialized ked


def receipt(pre,
            sn,
            said,
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
               t=ilk,  # Ilks.rct
               d=said,  # qb64 digest of receipted event
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
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
          stamp=None,  # default current datetime
          sith=None,  # default based on keys
          nkeys=None,
          nsith=None,
          toad=None,  # default based on wits
          wits=None,  # default to []
          cnfg=None,  # default to []
          dpre=None,
          version=Version,
          kind=Serials.json,
          ):
    """
    Returns serder of key state notification message.
    Utility function to automate creation of rotation events.

    Parameters:
        pre (str): identifier prefix qb64
        sn (int); sequence number of latest event
        pig (str): qb64 digest of prior event
        dig (str): qb64 digest of latest (current) event
        eilk (str): event (message) type (ilk) of latest (current) event
        keys is list of qb64 signing keys
        eevt is namedtuple of fields from latest establishment event s,d,wr,wa
            s = sn
            d = digest
            wr = witness remove list (cuts)
            wa = witness add list (adds)
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message or data
        sith is string or list format for signing threshold
        nkeys is list of qb64 next key digests
        nsith  is is int, string, or list format for next signing threshold
        toad is int of witness threshold
        wits is list of witness prefixes qb64
        cnfg is list of strings TraitDex of configuration traits
        dpre is qb64 of delegator's identifier prefix if any
        version is Version instance
        kind is serialization kind

    Key State Dict
    {
        "v": "KERI10JSON00011c_",
        "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
        "s": "2":,
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
    }

    "di": "" when not delegated
    "r": ""  when no route
    """
    vs = Versify(version=version, kind=kind, size=0)

    if sn < 0:
        raise ValueError("Negative sn = {} in key state.".format(sn))

    if eilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
        raise ValueError("Invalid evernt type et=  in key state.".format(eilk))

    if stamp is None:
        stamp = helping.nowIso8601()

    if sith is None:
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.size > len(keys):
        raise ValueError("Invalid sith = {} for keys = {}".format(sith, keys))

    if nsith is None:
        nsith = 0 if not nkeys else "{:x}".format(max(1, ceil(len(nkeys) / 2)))

    if nkeys is None:
        nkeys = []

    ntholder = Tholder(sith=nsith)
    if ntholder.size > len(nkeys):
        raise ValueError("Invalid nsith = {} for keys = {}".format(nsith, nkeys))


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

    validateSN(eevt.s)  # both incept and rotate

    if len(oset(eevt.br)) != len(eevt.br):  # duplicates in cuts
        raise ValueError("Invalid cuts = {} in latest est event, has duplicates"
                         ".".format(eevt.br))

    if len(oset(eevt.ba)) != len(eevt.ba):  # duplicates in adds
        raise ValueError("Invalid adds = {} in latest est event, has duplicates"
                         ".".format(eevt.ba))

    ksd = dict(v=vs,  # version string
               i=pre,  # qb64 prefix
               s="{:x}".format(sn),  # lowercase hex string no leading zeros
               p=pig,
               d=dig,
               f="{:x}".format(fn),  # lowercase hex string no leading zeros
               dt=stamp,
               et=eilk,
               kt=sith,  # hex string no leading zeros lowercase
               k=keys,  # list of qb64
               nt=ntholder.sith,
               n=nkeys,
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               ee=eevt._asdict(),  # latest est event dict
               di=dpre if dpre is not None else "",
               )

    return Serder(ked=ksd)  # return serialized ksd


def query(route="",
          replyRoute="",
          query=None,
          stamp=None,
          version=Version,
          kind=Serials.json):
    """
    Returns serder of query 'qry' message.
    Utility function to automate creation of query messages.


    Parameters:
        route (str): namesapaced path, '/' delimited, that indicates data flow
                     handler (behavior) to processs the query
        replyRoute (str): namesapaced path, '/' delimited, that indicates data flow
                     handler (behavior) to processs reply message to query if any.
        query (dict): query data paramaters modifiers
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message
        version (Version): KERI message Version namedtuple instance
        kind (str): serialization kind value of Serials


    {
      "v" : "KERI10JSON00011c_",
      "t" : "qry",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "logs",
      "rr": "log/processor",
      "q" :
      {
        "i":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
        "sn": "5",
        "dt": "2020-08-01T12:20:05.123456+00:00",
      }
    }
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.qry

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route,  # resource type for single item request
               rr=replyRoute,
               q=query,
               )
    _, ked = coring.Saider.saidify(sad=ked)

    return Serder(ked=ked)  # return serialized ked


def reply(route="",
          data=None,
          stamp=None,
          version=Version,
          kind=Serials.json):
    """
    Returns serder of reply 'rpy' message.
    Utility function to automate creation of reply messages.
    Reply 'rpy' message is a SAD item with an associated derived SAID in its
    'd' field.

     Parameters:
        route (str):  '/' delimited path identifier of data flow handler
            (behavior) to processs the reply if any
        data (dict): attribute section of reply
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message or data
        version (Version):  KERI message Version namedtuple instance
        kind (str): serialization kind value of Serials

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rpy",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "logs/processor",
      "a" :
      {
         "d":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
         "name": "John Jones",
         "role": "Founder",
      }
    }
    """
    label = coring.Ids.d
    vs = Versify(version=version, kind=kind, size=0)
    if data is None:
        data = {}

    sad = dict(v=vs,  # version string
               t=Ilks.rpy,
               d="",
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route if route is not None else "",  # route
               a=data if data else {},  # attributes
               )

    _, sad = coring.Saider.saidify(sad=sad, kind=kind, label=label)

    saider = coring.Saider(qb64=sad[label])
    if not saider.verify(sad=sad, kind=kind, label=label, prefixed=True):
        raise ValidationError("Invalid said = {} for reply msg={}."
                              "".format(saider.qb64, sad))

    return Serder(ked=sad)  # return serialized Self-Addressed Data (SAD)


def bare(route="",
           data=None,
           version=Version,
           kind=Serials.json):
    """
    Returns serder of bare 'bre' message.
    Utility function to automate creation of unhiding (bareing) messages for
    disclosure of sealed data associated with anchored seals in a KEL.
    Reference to anchoring seal is provided as an attachment to bare message.
    Bare 'bre' message is a SAD item with an associated derived SAID in its
    'd' field.

     Parameters:
        route is route path string that indicates data flow handler (behavior)
            to processs the exposure
        data is list of dicts of comitted data such as seals
        version is Version instance
        kind is serialization kind

    {
      "v" : "KERI10JSON00011c_",
      "t" : "bre",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "r" : "sealed/processor",
      "a" :
      {
         "d":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
         "dt": "2020-08-22T17:50:12.988921+00:00",
         "name": "John Jones",
         "role": "Founder",
      }
    }
    """
    vs = Versify(version=version, kind=kind, size=0)
    if data is None:
        data = {}

    sad = dict(v=vs,  # version string
               t=Ilks.bre,
               d="",
               r=route if route is not None else "",  # route
               a=data if data else {},  # attributes
               )

    _, sad = coring.Saider.saidify(sad=sad)

    return Serder(ked=sad)  # return serialized Self-Addressed Data (SAD)


def messagize(serder, *, sigers=None, seal=None, wigers=None, cigars=None,
              pipelined=False):
    """
    Attaches indexed signatures from sigers and/or cigars and/or wigers to
    KERI message data from serder
    Parameters:
        serder (Serder): instance containing the event
        sigers (list): of Siger instances (optional) to create indexed signatures
        seal (Union[SealEvent, SealLast]): optional if sigers and
            If SealEvent use attachment group code TransIdxSigGroups plus attach
                triple pre+snu+dig made from (i,s,d) of seal plus ControllerIdxSigs
                plus attached indexed sigs in sigers
            Else If SealLast use attachment group code TransLastIdxSigGroups plus
                attach uniple pre made from (i,) of seal plus ControllerIdxSigs
                plus attached indexed sigs in sigers
            Else use ControllerIdxSigs plus attached indexed sigs in sigers
        wigers (list): optional list of Siger instances of witness index signatures
        cigars (list): optional list of Cigars instances of non-transferable non indexed
            signatures from  which to form receipt couples.
            Each cigar.vefer.qb64 is pre of receiptor and cigar.qb64 is signature
        pipelined (bool), True means prepend pipelining count code to attachemnts
            False means to not prepend pipelining count code

    Returns: bytearray KERI event message
    """
    msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
    atc = bytearray()

    if not (sigers or cigars or wigers):
        raise ValueError("Missing attached signatures on message = {}."
                         "".format(serder.ked))

    if sigers:
        if isinstance(seal, SealEvent):
            atc.extend(Counter(CtrDex.TransIdxSigGroups, count=1).qb64b)
            atc.extend(seal.i.encode("utf-8"))
            atc.extend(Seqner(snh=seal.s).qb64b)
            atc.extend(seal.d.encode("utf-8"))

        elif isinstance(seal, SealLast):
            atc.extend(Counter(CtrDex.TransLastIdxSigGroups, count=1).qb64b)
            atc.extend(seal.i.encode("utf-8"))

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


def proofize(sadtsgs=None, *, sadsigers=None, sadcigars=None, pipelined=False):
    """

    Args:
        sadsigers (list) sad path signatures from transferable identifier of just sigs
        sadtsgs (list) sad path signatures from transferable identifier
        sadcigars (list) sad path signatures from non-transferable identifier
        pipelined (bool), True means prepend pipelining count code to attachemnts
            False means to not prepend pipelining count code

    Returns:
        bytes of CESR Proof Signature attachments
    """
    atc = bytearray()

    if sadtsgs is None and sadcigars is None:
        return atc

    sadtsgs = [] if sadtsgs is None else sadtsgs
    sadsigers = [] if sadsigers is None else sadsigers
    sadcigars = [] if sadcigars is None else sadcigars

    count = 0
    for (pather, sigers) in sadsigers:
        count += 1
        atc.extend(coring.Counter(coring.CtrDex.SadPathSig, count=1).qb64b)
        atc.extend(pather.qb64b)

        atc.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)
        for siger in sigers:
            atc.extend(siger.qb64b)

    for (pather, prefixer, seqner, saider, sigers) in sadtsgs:
        count += 1
        atc.extend(coring.Counter(coring.CtrDex.SadPathSig, count=1).qb64b)
        atc.extend(pather.qb64b)

        atc.extend(coring.Counter(coring.CtrDex.TransIdxSigGroups, count=1).qb64b)
        atc.extend(prefixer.qb64b)
        atc.extend(seqner.qb64b)
        atc.extend(saider.qb64b)

        atc.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)
        for siger in sigers:
            atc.extend(siger.qb64b)

    for (pather, cigars) in sadcigars:
        count += 1
        atc.extend(coring.Counter(coring.CtrDex.SadPathSig, count=1).qb64b)
        atc.extend(pather.qb64b)

        atc.extend(coring.Counter(code=coring.CtrDex.NonTransReceiptCouples, count=len(sadcigars)).qb64b)
        for cigar in cigars:
            if cigar.verfer.code not in coring.NonTransDex:
                raise ValueError("Attempt to use tranferable prefix={} for "
                                 "receipt.".format(cigar.verfer.qb64))
            atc.extend(cigar.verfer.qb64b)
            atc.extend(cigar.qb64b)

    msg = bytearray()

    if pipelined:
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        msg.extend(coring.Counter(code=coring.CtrDex.AttachedMaterialQuadlets,
                                  count=(len(atc) // 4)).qb64b)

    if count > 1:
        root = coring.Pather(text="-")
        msg.extend(coring.Counter(code=coring.CtrDex.SadPathSigGroup, count=count).qb64b)
        msg.extend(root.qb64b)

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
                 db=None, estOnly=None, seqner=None, saider=None, firner=None, dater=None,
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
            Saider is Saider instance of of delegating event said.
                If this event is not delegated then saider is ignored
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
        self.prefixes = prefixes if prefixes is not None else db.prefixes
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
                                                        saider=saider)

        self.delegator = delegator
        if self.delegator is None:
            self.delegated = False
        else:
            self.delegated = True

        wits = serder.ked["b"]
        # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
        # all validated above so may add to KEL and FEL logs as first seen
        fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers, wits=wits,
                                first=True if not check else False, seqner=seqner, saider=saider,
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
        return self.nexter is not None and self.nexter.digs and self.prefixer.transferable

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
        self.ntholder = Tholder(sith=state.ked["nt"])
        self.verfers = [Verfer(qb64=key) for key in state.ked["k"]]
        self.nexter = coring.Nexter(digs=state.ked["n"])
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
        self.tholder = serder.tholder  # Tholder(sith=ked["kt"])  #  parse sith into Tholder instance
        if len(self.verfers) < self.tholder.size:
            raise ValidationError("Invalid sith = {} for keys = {} for evt = {}."
                                  "".format(ked["kt"],
                                            [verfer.qb64 for verfer in self.verfers],
                                            ked))

        self.prefixer = Prefixer(qb64=serder.pre)
        if not self.prefixer.verify(ked=ked, prefixed=True):  # invalid prefix
            raise ValidationError("Invalid prefix = {} for inception evt = {}."
                                  "".format(self.prefixer.qb64, ked))

        self.sn = validateSN(sn=ked["s"], inceptive=True)
        self.serder = serder  # need whole serder for digest agility comparisons

        nxt = ked["n"]
        if not self.prefixer.transferable and nxt:  # nxt must be empty for nontrans prefix
            raise ValidationError("Invalid inception nxt not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))
        self.nexter = serder.nexter
        self.ntholder = serder.ntholder

        self.cuts = []  # always empty at inception since no prev event
        self.adds = []  # always empty at inception since no prev event
        wits = ked["b"]
        if not self.prefixer.transferable and wits:  # wits must be empty for nontrans prefix
            raise ValidationError("Invalid inception wits not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))
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

        data = ked["a"]
        if not self.prefixer.transferable and data:  # data must be empty for nontrans prefix
            raise ValidationError("Invalid inception data not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))


        # need this to recognize recovery events and transferable receipts
        self.lastEst = LastEstLoc(s=self.sn, d=self.serder.saider.qb64)  # last establishment event location

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

    def update(self, serder, sigers, wigers=None, seqner=None, saider=None,
               firner=None, dater=None, check=False):
        """
        Not an inception event. Verify event serder and indexed signatures
        in sigers and update state

        Parameters:
            serder (Serder): instance of  event
            sigers (list): of SigMat instances of signatures of event
            wigers (list): of Siger instances of indexed witness signatures of
                event. Index is offset into wits list of latest est event
            seqner (Seqner): instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            saider (Saider): instance of of delegating event said.
                If this event is not delegated then diger is ignored
            firner (optional): Seqner instance of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater (optional): Dater instance of cloned replay datetime
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

        sn = validateSN(sn=ked["s"], inceptive=False)
        ilk = ked["t"]

        if ilk in (Ilks.rot, Ilks.drt):  # rotation (or delegated rotation) event
            if self.delegated and ilk != Ilks.drt:
                raise ValidationError("Attempted non delegated rotation on "
                                      "delegated pre = {} with evt = {}."
                                      "".format(ked["i"], ked))

            # labels = DRT_LABELS if ilk == Ilks.dip else ROT_LABELS
            labels = DRT_LABELS if ilk == Ilks.drt else ROT_LABELS
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
                                                            saider=saider)

            if not self.ntholder.satisfy(indices=self.nexter.indices(sigers=sigers)):
                self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
                if seqner and saider:
                    self.escrowPACouple(serder=serder, seqner=seqner, saider=saider)
                raise MissingSignatureError("Failure satisfying nsith = {} on sigs for {}"
                                            " for evt = {}.".format(self.ntholder.sith,
                                                                    [siger.qb64 for siger in sigers],
                                                                    serder.ked))




            if delegator != self.delegator:  #
                raise ValidationError("Erroneous attempted  delegated rotation"
                                      " on either undelegated event or with"
                                      " wrong delegator = {} for pre  = {}"
                                      " with evt = {}."
                                      "".format(delegator, ked["i"], ked))

            # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
            # all validated above so may add to KEL and FEL logs as first seen
            fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers, wits=wits,
                                    first=True if not check else False, seqner=seqner, saider=saider,
                                    firner=firner, dater=dater)

            # nxt and signatures verify so update state
            self.sn = sn
            self.serder = serder  # need whole serder for digest agility compare
            self.ilk = ilk
            self.tholder = tholder
            self.verfers = serder.verfers
            # update .nexter
            self.nexter = serder.nexter
            self.ntholder = serder.ntholder

            self.toad = toad
            self.wits = wits
            self.cuts = cuts
            self.adds = adds

            # last establishment event location need this to recognize recovery events
            self.lastEst = LastEstLoc(s=self.sn, d=self.serder.saider.qb64)
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
                                      "= {}.".format(sn, self.sn + 1, ked))

            if not self.serder.compare(said=ked["p"]):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with state dig"
                                      " = {} for evt = {}.".format(ked["p"],
                                                                   self.serder.saider.qb64,
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
            if fn is not None:  # first is non-idempotent for fn check mode fn is None
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

        if sn > self.sn + 1:  # out of order event
            raise ValidationError("Out of order event sn = {} expecting"
                                  " = {} for evt = {}.".format(sn,
                                                               self.sn + 1,
                                                               ked))

        elif sn <= self.sn:  # stale or recovery
            #  stale events could be duplicitous
            #  duplicity detection should have happend before .update called
            #  so raise exception if stale
            if sn <= self.lastEst.s:  # stale  event
                raise ValidationError("Stale event sn = {} expecting"
                                      " = {} for evt = {}.".format(sn,
                                                                   self.sn + 1,
                                                                   ked))

            else:  # sn > self.lastEst.sn  #  recovery event
                if self.ilk != Ilks.ixn:  # recovery  may only override ixn state
                    raise ValidationError("Invalid recovery attempt: Recovery"
                                          "at ilk = {} not ilk = {} for evt"
                                          " = {}.".format(self.ilk,
                                                          Ilks.ixn,
                                                          ked))

                psn = sn - 1  # sn of prior event
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
                if not pserder.compare(said=dig):  # bad recovery event
                    raise ValidationError("Invalid recovery attempt:"
                                          "Mismatch recovery event prior dig"
                                          "= {} with dig = {} of event sn = {}"
                                          " evt = {}.".format(dig,
                                                              pserder.said,
                                                              psn,
                                                              ked))

        else:  # sn == self.sn + 1   new non-recovery event
            if not self.serder.compare(said=dig):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with"
                                      " state dig = {} for evt = {}."
                                      "".format(dig, self.serder.saider.qb64, ked))

        # also check derivation code of pre for non-transferable
        if not self.nexter:  # empty so rotations not allowed
            raise ValidationError("Attempted rotation for nontransferable"
                                  " prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))

        tholder = serder.tholder  # Tholder(sith=ked["kt"])  #  parse sith into Tholder instance
        if len(serder.verfers) < tholder.size:
            raise ValidationError("Invalid sith = {} for keys = {} for evt = {}."
                                  "".format(ked["kt"],
                                            [verfer.qb64 for verfer in serder.verfers],
                                            ked))

        # verify next keys from prior
        ntholder = serder.ntholder
        keys = ked["k"]
        if not self.nexter.verify(keys=keys):
            raise ValidationError("Mismatch nxt digest = {} with rotation"
                                  " sith = {}, keys = {} for evt = {}."
                                  "".format(self.nexter.digs, tholder.thold, keys, ked))

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

        if (witset & cutset) != cutset:  # some cuts not in wits
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

        return tholder, toad, wits, cuts, adds

    def valSigsDelWigs(self, serder, sigers, verfers, tholder,
                       wigers, toad, wits, seqner=None, saider=None):
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
            saider is Saider instance of of delegating event said.
                If this event is not delegated then saider is ignored

        """
        if len(verfers) < tholder.size:
            raise ValidationError("Invalid sith = {} for keys = {} for evt = {}."
                                  "".format(tholder.sith,
                                            [verfer.qb64 for verfer in verfers],
                                            serder.ked))

        # get unique verified sigers and indices lists from sigers list
        sigers, indices = verifySigs(raw=serder.raw, sigers=sigers, verfers=verfers)
        # sigers  now have .verfer assigned

        werfers = [Verfer(qb64=wit) for wit in wits]

        # get unique verified wigers and windices lists from wigers list
        wigers, windices = verifySigs(raw=serder.raw, sigers=wigers, verfers=werfers)
        # each wiger now has werfer of corresponding wit

        # check if fully signed
        if not indices:  # must have a least one verified sig
            raise ValidationError("No verified signatures for evt = {}."
                                  "".format(serder.ked))

        if not tholder.satisfy(indices):  # at least one but not enough
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            if seqner and saider:
                self.escrowPACouple(serder=serder, seqner=seqner, saider=saider)
            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                        " for evt = {}.".format(tholder.sith,
                                                                [siger.qb64 for siger in sigers],
                                                                serder.ked))

        delegator = self.validateDelegation(serder, sigers=sigers, wigers=wigers,
                                            seqner=seqner, saider=saider)

        # Kevery .process event logic prevents this from seeing event when
        # not local and event pre is own pre
        if serder.pre not in self.prefixes:
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
                    if self.escrowPWEvent(serder=serder, wigers=wigers, sigers=sigers, seqner=seqner, saider=saider):
                        self.cues.append(dict(kin="query", q=dict(pre=serder.pre, sn=serder.sn)))
                    raise MissingWitnessSignatureError("Failure satisfying toad = {} "
                                                       "on witness sigs for {} for evt = {}.".format(toad,
                                                                                                     [siger.qb64 for siger
                                                                                                      in wigers],
                                                                                                     serder.ked))
        return sigers, delegator, wigers

    def validateDelegation(self, serder, sigers, wigers=None, seqner=None, saider=None):
        """
        Returns delegator's qb64 identifier prefix if seal validates with respect to Delegator's KEL
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
            saider is Saider instance of of delegating event digest.
                If this event is not delegated then diger is ignored
        Returns:
            str: qb64 delegator prefix

        """
        if serder.ked['t'] not in (Ilks.dip, Ilks.drt):  # not delegated
            return None  # delegator is None

        # verify delegator and attachment pointing to delegating event
        if serder.ked['t'] == Ilks.dip:
            delegator = serder.ked["di"]
        else:
            delegator = self.delegator

        # if we are the delegatee, accept the event without requiring the delegator validation
        if delegator is not None and serder.pre in self.prefixes:
            return delegator

        # during initial delegation we just escrow the delcept event
        if seqner is None and saider is None and delegator is not None:
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            raise MissingDelegationError("No delegation seal for delegator {} "
                                         "with evt = {}.".format(delegator, serder.ked))

        ssn = validateSN(sn=seqner.snh, inceptive=False)

        # get the dig of the delegating event
        key = snKey(pre=delegator, sn=ssn)
        raw = self.db.getKeLast(key)  # get dig of delegating event

        if raw is None:  # no delegating event at key pre, sn
            #  create cue to fetch delegating event this may include MFA business logic
            #  for the delegator

            #  escrow event here
            inceptive = True if serder.ked["t"] in (Ilks.icp, Ilks.dip) else False
            sn = validateSN(sn=serder.ked["s"], inceptive=inceptive)
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            self.escrowPACouple(serder=serder, seqner=seqner, saider=saider)
            raise MissingDelegationError("No delegating event from {} at {} for "
                                         "evt = {}.".format(delegator,
                                                            saider.qb64,
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
        if not dserder.compare(said=saider.qb64):
            raise ValidationError("Invalid delegation from {} at event dig = {} for evt = {}."
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
        found = False  # find event seal of delegated event in delegating data
        for dseal in dserder.ked["a"]:  # find delegating seal anchor
            if ("i" in dseal and dseal["i"] == pre and
                    "s" in dseal and dseal["s"] == sn and
                    "d" in dseal and serder.compare(said=dseal["d"])):  # dseal["d"] == dig
                found = True
                break

        if not found:
            raise ValidationError("Missing delegation from {} in {} for evt = {}."
                                  "".format(delegator, dserder.ked["a"], serder.ked))

        # re-verify signatures or trust the database?
        # if database is loaded into memory fresh and reverified each bootup
        # when custody of disc is in question then trustable otherwise not

        return delegator  # return delegator prefix

    def logEvent(self, serder, sigers=None, wigers=None, wits=None, first=False,
                 seqner=None, saider=None, firner=None, dater=None):
        """
        Update associated logs for verified event.
        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            serder is Serder instance of current event
            sigers is optional list of Siger instance for current event
            wigers is optional list of Siger instance of indexed witness sigs
            wits is optional list of current witnesses provide during any establishment event
            first is Boolean True means first seen accepted log of event.
                    Otherwise means idempotent log of event to accept additional
                    signatures beyond the threshold provided for first seen
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            saider is Saider instance of of delegating event said.
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
        dgkey = dgKey(serder.preb, serder.saidb)
        dtsb = helping.nowIso8601().encode("utf-8")
        self.db.putDts(dgkey, dtsb)  # idempotent do not change dts if already
        if sigers:
            self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])  # idempotent
        if wigers:
            self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        if wits:
            self.db.wits.put(keys=dgkey, vals=[coring.Prefixer(qb64=w) for w in wits])
        self.db.putEvt(dgkey, serder.raw)  # idempotent (maybe already excrowed)
        if first:  # append event dig to first seen database in order
            if seqner and saider:  # authorized delegated or issued event
                couple = seqner.qb64b + saider.qb64b
                self.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
            fn = self.db.appendFe(serder.preb, serder.saidb)
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
            self.db.fons.pin(keys=dgkey, val=Seqner(sn=fn))
            logger.info("Kever state: %s First seen ordinal %s at %s\nEvent=\n%s\n",
                        serder.preb, fn, dtsb.decode("utf-8"), serder.pretty())
        self.db.addKe(snKey(serder.preb, serder.sn), serder.saidb)
        logger.info("Kever state: %s Added to KEL valid event=\n%s\n",
                    serder.preb, serder.pretty())
        return (fn, dtsb.decode("utf-8"))  # (fn int, dts str) if first else (None, dts str)

    def escrowPSEvent(self, serder, sigers, wigers=None):
        """
        Update associated logs for escrow of partially signed event
        or fully signed delegated event but not yet verified delegation.

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controller sigs
            wigers is optional list of Siger instance of indexed witness sigs
        """
        dgkey = dgKey(serder.preb, serder.saidb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))  # idempotent
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        if wigers:
            self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        self.db.putEvt(dgkey, serder.raw)
        snkey = snKey(serder.preb, serder.sn)
        self.db.addPse(snkey, serder.saidb)  # b'EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk.00000000000000000000000000000001'
        logger.info("Kever state: Escrowed partially signed or delegated "
                    "event = %s\n", serder.ked)

    def escrowPACouple(self, serder, seqner, saider):
        """
        Update associated logs for escrow of partially authenticated issued event.
        Assuming signatures are provided elsewhere. Partial authentication results
        from either a partially signed event or a fully signed delegated event
        but whose delegation is not yet verified.

        Escrow allows escrow processor to retrieve serder from key and source
        couple from val in order to to re-verify authentication status. Sigs
        are escrowed elsewhere.

        Parameters:
            serder is Serder instance of delegated or issued event
            seqner is Seqner instance of sn of seal source event of delegator/issuer
            saider is Saider instance of said of delegator/issuer
        """
        dgkey = dgKey(serder.preb, serder.saidb)
        couple = seqner.qb64b + saider.qb64b
        self.db.putPde(dgkey, couple)  # idempotent
        logger.info("Kever state: Escrowed source couple for partially signed "
                    "or delegated event = %s\n", serder.ked)

    def escrowPWEvent(self, serder, wigers, sigers=None, seqner=None, saider=None):
        """
        Update associated logs for escrow of partially witnessed event

        Parameters:
            serder is Serder instance of  event
            wigers is list of Siger instance of indexed witness sigs
            sigers is optional list of Siger instances of indexed controller sigs
            seqner is Seqner instance of sn of seal source event of delegator/issuer
            saider is Diger instance of digest of delegator/issuer
        """
        dgkey = dgKey(serder.preb, serder.saidb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))  # idempotent
        if wigers:
            self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        if sigers:
            self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        if seqner and saider:
            couple = seqner.qb64b + saider.qb64b
            self.db.putPde(dgkey, couple)

        self.db.putEvt(dgkey, serder.raw)
        logger.info("Kever state: Escrowed partially witnessed "
                    "event = %s\n", serder.ked)
        return self.db.addPwe(snKey(serder.preb, serder.sn), serder.saidb)

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
                      dig=self.serder.said,
                      fn=self.fn,
                      stamp=self.dater.dts,  # need to add dater object for first seen dts
                      eilk=self.ilk,
                      keys=[verfer.qb64 for verfer in self.verfers],
                      eevt=eevt,
                      sith=self.tholder.sith,
                      nsith=self.ntholder.sith if self.ntholder else 0,
                      nkeys=self.nexter.digs if self.nexter else [],
                      toad=self.toad,
                      wits=self.wits,
                      cnfg=cnfg,
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
    TimeoutKSN = 3600  # seconds to timeout key state notice message escrows
    TimeoutQNF = 300   # seconds to timeout query not found escrows

    def __init__(self, *, evts=None, cues=None, db=None, rvy=None,
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
        self.rvy = rvy
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

    def fetchWitnessState(self, pre, sn):
        """ Returns the list of witness for the identifier prefix at the sequence number

        Returns the witness state (list of witnesses) at the given sequence number (sn) of the
        identifier prefix (pre).  It uses the .wits database that stores witness state at the
        sequence number of each establishment event.  If sn represents an interaction event (ixn) it
        searches backwards for the last establishment event prior to sn and returns that witness state.

        Args:
            pre (str): identifier prefix qb64
            sn (int): sequence number of the event for which witness state is desired

        Returns:
            list:  list of coring.Prefixer objects representing the witness state for the identifier prefix at
                 the sequence number

        """
        preb = pre.encode("utf-8")
        for digb in self.db.getKelBackIter(preb, sn):
            dgkey = dgKey(preb, digb)
            raw = self.db.getEvt(dgkey)
            serder = coring.Serder(raw=bytes(raw))
            if serder.est:
                wits = self.db.wits.get(dgkey)
                return wits

        return []

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
                     seqner=None, saider=None,
                     firner=None, dater=None):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:
            serder is Serder instance of event to process
            sigers is list of Siger instances of attached controller indexed sigs
            wigers is optional list of Siger instances of attached witness indexed sigs
            seqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            sadier is Saider instance of of delegating event SAID.
                If this event is not delegated then saider is ignored
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
        sn = serder.sn
        ilk = ked["t"]
        said = serder.said

        if not self.lax:  # otherwise in promiscuous mode
            if self.local:
                if pre not in self.prefixes:  # nonlocal event when in local mode
                    raise ValueError("Nonlocal event pre={} not in prefixes={}."
                                     "when local mode.".format(pre, self.prefixes))
            else:
                if pre in self.prefixes:  # local event when in nonlocal mode
                    raise ValueError("Local event pre={} in prefixes when "
                                     "nonlocal mode.".format(pre, self.prefixes))

        if pre not in self.kevers:  # first seen event for pre
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
                              saider=saider,
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
                                   seqner=seqner, saider=saider, wigers=wigers)
                raise OutOfOrderError("Out-of-order event={}.".format(ked))

        else:  # already accepted inception event for pre so already first seen
            if ilk in (Ilks.icp, Ilks.dip):  # another inception event so maybe duplicitous
                if sn != 0:
                    raise ValueError("Invalid sn={} for inception event={}."
                                     "".format(sn, serder.ked))
                # check if duplicate of existing inception event since est is icp
                eserder = self.fetchEstEvent(pre, sn)  # latest est evt wrt sn
                if eserder.said == said:  # event is a duplicate but not duplicitous
                    # may have attached valid signature not yet logged
                    # raises ValidationError if no valid sig
                    kever = self.kevers[pre]  # get key state
                    # get unique verified lists of sigers and indices from sigers
                    sigers, indices = verifySigs(raw=serder.raw,
                                                 sigers=sigers,
                                                 verfers=eserder.verfers)

                    wigers, windices = verifySigs(raw=serder.raw,
                                                  sigers=wigers,
                                                  verfers=eserder.werfers)

                    if sigers or wigers:  # at least one verified sig or wig so log evt
                        # not first seen inception so ignore return
                        kever.logEvent(serder, sigers=sigers, wigers=wigers)  # idempotent update db logs

                else:  # escrow likely duplicitous event
                    self.escrowLDEvent(serder=serder, sigers=sigers)
                    raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))

            else:  # rot, drt, or ixn, so sn matters
                kever = self.kevers[pre]  # get existing kever for pre
                kever.cues = self.cues
                sno = kever.sn + 1  # proper sn of new inorder event

                if not serder.saider.verify(sad=serder.ked):
                    raise ValidationError("Invalid SAID {} for event {}".format(said, serder.ked))

                if sn > sno:  # sn later than sno so out of order escrow
                    # escrow out-of-order event
                    self.escrowOOEvent(serder=serder, sigers=sigers,
                                       seqner=seqner, saider=saider, wigers=wigers)
                    raise OutOfOrderError("Out-of-order event={}.".format(ked))

                elif ((sn == sno) or  # new inorder event or recovery
                      (ilk in (Ilks.rot, Ilks.drt) and kever.lastEst.s < sn <= sno)):
                    # verify signatures etc and update state if valid
                    # raise exception if problem.
                    # Otherwise adds to KELs
                    kever.update(serder=serder, sigers=sigers, wigers=wigers,
                                 seqner=seqner, saider=saider,
                                 firner=firner if self.cloned else None,
                                 dater=dater if self.cloned else None,
                                 check=self.check)

                    if self.direct or self.lax or pre not in self.prefixes:  # not own event when owned
                        # create cue for receipt   direct mode for now
                        #  receipt of actual type is dependent on own type of identifier
                        self.cues.push(dict(kin="receipt", serder=serder))
                    elif not self.direct:
                        self.cues.push(dict(kin="notice", serder=serder))

                else:  # maybe duplicitous
                    # check if duplicate of existing valid accepted event
                    ddig = bytes(self.db.getKeLast(key=snKey(pre, sn))).decode("utf-8")
                    if ddig == said:  # event is a duplicate but not duplicitous
                        eserder = self.fetchEstEvent(pre, sn)  # latest est event wrt sn
                        # may have attached valid signature not yet logged
                        # raises ValidationError if no valid sig
                        kever = self.kevers[pre]
                        # get unique verified lists of sigers and indices from sigers
                        sigers, indices = verifySigs(raw=serder.raw,
                                                     sigers=sigers,
                                                     verfers=eserder.verfers)

                        wits = [wit.qb64 for wit in self.fetchWitnessState(pre, sn)]
                        werfers = [Verfer(qb64=wit) for wit in wits]
                        wigers, windices = verifySigs(raw=serder.raw,
                                                      sigers=wigers,
                                                      verfers=werfers)

                        if sigers or wigers:  # at least one verified sig or wig so log evt
                            # not first seen update so ignore return
                            kever.logEvent(serder, sigers=sigers, wigers=wigers)  # idempotent update db logs

                    else:  # escrow likely duplicitous event
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

        sn = serder.sn

        # Only accept receipt if for last seen version of event at sn
        snkey = snKey(pre=pre, sn=sn)
        ldig = self.db.getKeLast(key=snkey)  # retrieve dig of last event at sn.

        if ldig is not None:  # verify digs match
            ldig = bytes(ldig).decode("utf-8")
            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            raw = bytes(self.db.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none
            lserder = Serder(raw=raw)  # deserialize event raw

            if not lserder.compare(said=ked["d"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["s"], ked))

            # process each couple verify sig and write to db
            wits = [wit.qb64 for wit in self.fetchWitnessState(pre, sn)]
            for wiger in wigers:
                # assign verfers from witness list
                if wiger.index >= len(wits):
                    continue  # skip invalid witness index
                wiger.verfer = Verfer(qb64=wits[wiger.index])  # assign verfer
                if wiger.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid witness prefix

                if not self.lax and wiger.verfer.qb64 in self.prefixes:  # own is receiptor
                    if pre in self.prefixes:  # skip own receiptor of own event
                        # sign own events not receipt them
                        logger.info("Kevery process: skipped own receipt attachment"
                                    " on own event receipt=\n%s\n", serder.pretty())
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
            self.escrowUWReceipt(serder=serder, wigers=wigers, said=ked["d"])
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
        sn = serder.sn

        # Only accept receipt if for last seen version of event at sn
        snkey = snKey(pre=pre, sn=sn)
        ldig = self.db.getKeLast(key=snkey)  # retrieve dig of last event at sn.

        if ldig is not None:  # verify digs match
            ldig = bytes(ldig).decode("utf-8")
            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            raw = bytes(self.db.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none
            lserder = Serder(raw=raw)  # deserialize event raw

            if not lserder.compare(said=ked["d"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["s"], ked))

            # process each couple verify sig and write to db
            for cigar in cigars:
                if cigar.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid couplets

                if not self.lax and cigar.verfer.qb64 in self.prefixes:  # own is receiptor
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
                    wits = [wit.qb64 for wit in self.fetchWitnessState(pre, sn)]
                    rpre = cigar.verfer.qb64  # prefix of receiptor
                    if rpre in wits:  # its a witness receipt
                        index = wits.index(rpre)
                        # create witness indexed signature
                        wiger = Siger(raw=cigar.raw, index=index, verfer=cigar.verfer)
                        self.db.addWig(key=dgkey, val=wiger.qb64b)  # write to db
                    else:  # write receipt couple to database
                        couple = cigar.verfer.qb64b + cigar.qb64b
                        self.db.addRct(key=dgkey, val=couple)

        else:  # no events to be receipted yet at that sn so escrow
            self.escrowUReceipt(serder, cigars, said=ked["d"])  # digest in receipt
            raise UnverifiedReceiptError("Unverified receipt={}.".format(ked))

    def processReceiptCouples(self, serder, cigars, firner=None):
        """
        Process attachment with receipt couple

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
        sn = serder.sn

        # Only accept receipt if event is latest event at sn. Means its been
        # first seen and is the most recent first seen with that sn
        if firner:
            ldig = self.db.getFe(key=fnKey(pre=pre, sn=firner.sn))
        else:
            ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.

        if ldig is None:  # escrow because event does not yet exist in database
            # # take advantage of fact that receipt and event have same pre, sn fields
            self.escrowUReceipt(serder, cigars, said=serder.said)  # digest in receipt
            raise UnverifiedReceiptError("Unverified receipt={}.".format(ked))

        ldig = bytes(ldig).decode("utf-8")  # verify digs match
        # retrieve event by dig assumes if ldig is not None that event exists at ldig

        if not serder.compare(said=ldig):  # mismatch events problem with replay
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
                wits = self.fetchWitnessState(pre, sn)
                rpre = cigar.verfer.qb64  # prefix of receiptor
                if rpre in wits:  # its a witness receipt
                    index = wits.index(rpre)
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
        sn = serder.sn

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
        if not lserder.compare(said=ldig):  # mismatch events problem with replay
            raise ValidationError("Mismatch receipt of event at sn = {} with db."
                                  "".format(sn))

        for sprefixer, sseqner, saider, sigers in tsgs:  # iterate over each tsg
            if not self.lax and sprefixer.qb64 in self.prefixes:  # own is receipter
                if pre in self.prefixes:  # skip own receipter of own event
                    # sign own events not receipt them
                    raise ValidationError("Own pre={} receipter of own event"
                                          " {}.".format(self.prefixes, serder.pretty()))
                if not self.local:  # skip own receipts of nonlocal events
                    raise ValidationError("Own pre={} receipter of nonlocal event "
                                          "{}.".format(self.prefixes, serder.pretty()))

            # receipted event in db so attempt to get receipter est evt
            # retrieve dig of last event at sn of est evt of receipter.
            sdig = self.db.getKeLast(key=snKey(pre=sprefixer.qb64b, sn=sseqner.sn))
            if sdig is None:
                # receipter's est event not yet in receipters's KEL
                # so need cue to discover est evt KEL for receipter from watcher etc
                self.escrowTReceipts(serder, sprefixer, sseqner, saider, sigers)
                raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                                         "missing establishment event of transferable "
                                                         "receipter for event={}."
                                                         "".format(ked))

            # retrieve last event itself of receipter est evt from sdig.
            sraw = self.db.getEvt(key=dgKey(pre=sprefixer.qb64b, dig=bytes(sdig)))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = Serder(raw=bytes(sraw))
            if not sserder.compare(said=saider.qb64):  # endorser's dig not match event
                raise ValidationError("Bad trans indexed sig group at sn = {}"
                                      " for ksn = {}."
                                      "".format(sseqner.sn, sserder.ked))

            # verify sigs and if so write receipt to database
            sverfers = sserder.verfers
            if not sverfers:
                raise ValidationError("Invalid receipter's est. event"
                                      " dig = {}  from pre ={}, no keys."
                                      "".format(saider.qb64, sprefixer.qb64))

            for siger in sigers:
                if siger.index >= len(sverfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(siger.index))
                siger.verfer = sverfers[siger.index]  # assign verfer
                if siger.verfer.verify(siger.raw, lserder.raw):  # verify sig
                    # good sig so write receipt quadruple to database
                    quadruple = sprefixer.qb64b + sseqner.qb64b + saider.qb64b + siger.qb64b
                    self.db.addVrc(key=dgKey(pre=pre, dig=ldig),
                                   val=quadruple)  # dups kept

    def processReceiptQuadruples(self, serder, trqs, firner=None):
        """
        Process one attachment quadruple that comprises a transferable receipt

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
        sn = serder.sn

        if firner:  # retrieve last event by fn ordinal
            ldig = self.db.getFe(key=fnKey(pre=pre, sn=firner.sn))
        else:
            # Only accept receipt if for last seen version of receipted event at sn
            ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.

        for sprefixer, sseqner, saider, siger in trqs:  # iterate over each trq
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

                if not serder.compare(said=ldig):  # mismatch events problem with replay
                    raise ValidationError("Mismatch replay event at sn = {} with db."
                                          "".format(ked["s"]))

                # retrieve dig of last event at sn of receipter.
                sdig = self.db.getKeLast(key=snKey(pre=sprefixer.qb64b,
                                                   sn=sseqner.sn))
                if sdig is None:
                    # receipter's est event not yet in receipter's KEL
                    # receipter's seal event not in receipter's KEL
                    self.escrowTRQuadruple(serder, sprefixer, sseqner, saider, siger)
                    raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                                             "missing establishment event of transferable "
                                                             "validator receipt quadruple for event={}."
                                                             "".format(ked))

                # retrieve last event itself of receipter
                sraw = self.db.getEvt(key=dgKey(pre=sprefixer.qb64b, dig=bytes(sdig)))
                # assumes db ensures that sraw must not be none because sdig was in KE
                sserder = Serder(raw=bytes(sraw))
                if not sserder.compare(said=saider.qb64):  # seal dig not match event
                    raise ValidationError("Bad trans receipt quadruple at sn = {}"
                                          " for rct = {}."
                                          "".format(sseqner.sn, sserder.ked))

                # verify sigs and if so write quadruple to database
                sverfers = sserder.verfers
                if not sverfers:
                    raise ValidationError("Invalid trans receipt quad est. event"
                                          " dig = {} for receipt from pre ={}, "
                                          "no keys."
                                          "".format(saider.qb64, sprefixer.qb64))

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
                quadruple = sprefixer.qb64b + sseqner.qb64b + saider.qb64b + siger.qb64b
                self.db.addVrc(key=dgKey(pre, serder.said), val=quadruple)


            else:  # escrow  either receiptor or receipted event not yet in database
                self.escrowTRQuadruple(serder, sprefixer, sseqner, saider, siger)
                raise UnverifiedTransferableReceiptError("Unverified receipt: "
                                                         "missing associated event for transferable "
                                                         "validator receipt quadruple for event={}."
                                                         "".format(ked))

    def removeStaleReplyEndRole(self, saider):
        """
        Process reply escrow at saider for route "/end/role"
        """
        pass

    def removeStaleReplyLocScheme(self, saider):
        """
        Process reply escrow at saider for route "/loc/scheme"
        """
        pass


    def registerReplyRoutes(self, router):
        """ Register the routes for processing messages embedded in `rpy` event messages

        Parameters:
            router(Router): reply message router

        """
        router.addRoute("/end/role/{action}", self, suffix="EndRole")
        router.addRoute("/loc/scheme", self, suffix="LocScheme")
        router.addRoute("/ksn/{aid}", self, suffix="KeyStateNotice")

    def processReplyEndRole(self, *, serder, saider, route,
                            cigars=None, tsgs=None, **kwargs):
        """
        Process one reply message for route = /end/role/add or /end/role/cut
        with either attached nontrans receipt couples in cigars or attached trans
        indexed sig groups in tsgs.
        Assumes already validated saider, dater, and route from serder.ked

        Parameters:
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            route (str): reply route
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer
            tsgs (list): tuples (quadruples) of form
                (prefixer, seqner, diger, [sigers]) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                [sigers] is list of indexed sigs from trans endorser's keys from est evt

        EndpointRecord:
            allowed: bool = False  # True eid allowed (add), False eid disallowed (cut)
            name: str = ""  # optional user friendly name of endpoint

        Reply Message:
        {
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/end/role/add",
          "a" :
          {
             "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
             "role": "watcher",  # one of kering.Roles
             "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
          }
        }

        {
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/end/role/cut",
          "a" :
          {
             "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
             "role": "watcher",  # one of kering.Roles
             "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
          }
        }

        """
        # reply specific logic
        if route.startswith("/end/role/add"):
            allowed = True
        elif route.startswith("/end/role/cut"):
            allowed = False
        else:  # unsupported route
            raise ValidationError(f"Usupported route={route} in {Ilks.rpy} "
                                  f"msg={serder.ked}.")
        route = "/end/role"  # escrow based on route base

        data = serder.ked["a"]
        for k in ("cid", "role", "eid"):
            if k not in data:
                raise ValidationError(f"Missing element={k} from attributes in"
                                      f" {Ilks.rpy} msg={serder.ked}.")

        cider = coring.Prefixer(qb64=data["cid"])  # raises error if unsupported code
        cid = cider.qb64  # controller authorizing eid at role
        role = data["role"]
        if role not in kering.Roles:
            raise ValidationError(f"Invalid role={role} from attributes in "
                                  f"{Ilks.rpy} msg={serder.ked}.")
        eider = coring.Prefixer(qb64=data["eid"])  # raises error if unsupported code
        eid = eider.qb64  # controller of endpoint at role
        aid = cid  # authorizing attribution id
        keys = (aid, role, eid)
        osaider = self.db.eans.get(keys=keys)  # get old said if any
        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=osaider, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified reply.")

        self.updateEnd(keys=keys, saider=saider, allowed=allowed)  # update .eans and .ends

    def processReplyLocScheme(self, *, serder, saider, route,
                              cigars=None, tsgs=None):
        """
        Process one reply message for route = /loc/scheme with either
        attached nontrans receipt couples in cigars or attached trans indexed
        sig groups in tsgs.
        Assumes already validated saider, dater, and route from serder.ked

        Parameters:
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            route (str): reply route
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer
            tsgs (list): tuples (quadruples) of form
                (prefixer, seqner, diger, [sigers]) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                [sigers] is list of indexed sigs from trans endorser's keys from est evt

        EndAuthRecord
             cid: str = ""  # identifier prefix of controller that authorizes endpoint
             roles: list[str] = field(default_factory=list)  # str endpoint roles such as watcher, witness etc

        LocationRecord:
            url: str  # full url including host:port/path?query scheme is optional
            cids: list[EndAuthRecord] = field(default_factory=list)  # optional authorization record references

        Reply Message:

        {
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/loc/scheme",
          "a" :
          {
             "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
             "scheme": "http",  # one of kering.Schemes
             "url":  "http://localhost:8080/watcher/wilma",
          }
        }

        {
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/loc/scheme",
          "a" :
          {
             "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
             "scheme": "http",  # one of kering.Schemes
             "url":  "",  # Nullifies
          }
        }


        """
        # reply specific logic
        if not route.startswith("/loc/scheme"):
            raise ValidationError("Usupported route={} in {} msg={}."
                                  "".format(route, Ilks.rpy, serder.ked))
        route = "/loc/scheme"  # escrow based on route base

        data = serder.ked["a"]
        for k in ("eid", "scheme", "url"):
            if k not in data:
                raise ValidationError("Missing element={} from attributes in {} "
                                      "msg={}.".format(k, Ilks.rpy, serder.ked))
        eider = coring.Prefixer(qb64=data["eid"])  # raises error if unsupported code
        eid = eider.qb64  # controller of endpoint at role
        scheme = data["scheme"]
        if scheme not in kering.Schemes:
            raise ValidationError("Invalid scheme={} from attributes in {} "
                                  "msg={}.".format(scheme, Ilks.rpy, serder.ked))
        url = data["url"]
        splits = urlsplit(url)
        # empty scheme allowed in, will use scheme field
        if splits.scheme and splits.scheme != scheme:  # non empty but not match
            raise ValidationError("Invalid url={} for scheme={} from attributes in {} "
                                  "msg={}.".format(url, scheme, Ilks.rpy, serder.ked))
        # empty host port allowed will use default localhost:8080
        aid = eid  # authorizing attribution id
        keys = (aid, scheme)
        osaider = self.db.lans.get(keys=keys)  # get old said if any
        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                      aid=aid, osaider=osaider, cigars=cigars,
                                      tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified reply.")

        self.updateLoc(keys=keys, saider=saider, url=url)  # update .lans and .locs

    def processReplyKeyStateNotice(self, *, serder, saider, route,
                                   cigars=None, tsgs=None, **kwargs):
        """ Process one reply message for key state = /ksn

        Process one reply message for key state = /ksn
        with either attached nontrans receipt couples in cigars or attached trans
        indexed sig groups in tsgs.
        Assumes already validated saider, dater, and route from serder.ked

        Parameters:
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            route (str): reply route
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer
            tsgs (list): tuples (quadruples) of form
                (prefixer, seqner, diger, [sigers]) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                [sigers] is list of indexed sigs from trans endorser's keys from est evt

        Reply Message:
        {
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/ksn/EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg",
          "a" :
          {
            "v": "KERI10JSON000274_",
            "i": "EeS834LMlGVEOGR8WU3rzZ9M6HUv_vtF32pSXQXKP7jg",
            "s": "1",
            "t": "ksn",
            "p": "ESORkffLV3qHZljOcnijzhCyRT0aXM2XHGVoyd5ST-Iw",
            "d": "EtgNGVxYd6W0LViISr7RSn6ul8Yn92uyj2kiWzt51mHc",
            "f": "1",
            "dt": "2021-11-04T12:55:14.480038+00:00",
            "et": "ixn",
            "kt": "1",
            "k": [
              "DTH0PwWwsrcO_4zGe7bUR-LJX_ZGBTRsmP-ZeJ7fVg_4"
            ],
            "n": "E6qpfz7HeczuU3dAd1O9gPPS6-h_dCxZGYhU8UaDY2pc",
            "bt": "3",
            "b": [
              "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
              "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
              "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
            ],
            "c": [],
            "ee": {
              "s": "0",
              "d": "ESORkffLV3qHZljOcnijzhCyRT0aXM2XHGVoyd5ST-Iw",
              "br": [],
              "ba": []
            },
            "di": ""
          }
        }

        """
        cigars = cigars if cigars is not None else []
        tsgs = tsgs if tsgs is not None else []

        # reply specific logic
        if not route.startswith("/ksn"):
            raise ValidationError(f"Usupported route={route} in {Ilks.rpy} "
                                  f"msg={serder.ked}.")
        aid = kwargs["aid"]
        data = serder.ked["a"]
        kserder = coring.Serder(ked=data)

        for k in KSN_LABELS:
            if k not in kserder.ked:
                raise ValidationError("Missing element = {} from {} msg."
                                      " ksn = {}.".format(k, Ilks.ksn,
                                                          serder.pretty()))
        # fetch from serder to process
        ked = kserder.ked
        pre = kserder.pre
        sn = kserder.sn

        # check source and ensure we should accept it
        baks = ked["b"]
        wats = set()
        for _, habr in self.db.habs.getItemIter():
            wats |= set(habr.watchers)

        # not in promiscuous mode
        if not self.lax:
            if aid != kserder.pre and \
                    aid not in baks and \
                    aid not in wats:
                raise kering.UntrustedKeyStateSource("key state notice for {} from untrusted source {} "
                                                     .format(kserder.pre, aid))

        if kserder.pre in self.kevers:
            kever = self.kevers[kserder.pre]
            if kserder.sn < kever.sn:
                raise ValidationError("Skipped stale key state at sn {} for {}."
                                      "".format(kserder.sn, kserder.pre))

        keys = (pre, aid,)
        osaider = self.db.knas.get(keys=keys)  # get old said if any
        dater = coring.Dater(dts=serder.ked["dt"])

        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=osaider, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified reply.")

        ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.

        # Only accept key state if for last seen version of event at sn
        if ldig is None:  # escrow because event does not yet exist in database
            if self.escrowKeyStateNotice(pre=pre, aid=aid, serder=serder, saider=saider, dater=dater,
                                         cigars=cigars, tsgs=tsgs):
                self.cues.append(dict(kin="query", q=dict(pre=pre)))

            raise kering.OutOfOrderKeyStateError("Out of order key state={}.".format(ked))

        diger = coring.Diger(qb64=ked["d"])
        ldig = bytes(ldig)
        # retrieve last event itself of signer given sdig
        sraw = self.db.getEvt(key=dgKey(pre=pre, dig=ldig))
        # assumes db ensures that sraw must not be none because sdig was in KE
        sserder = Serder(raw=bytes(sraw))

        if not sserder.compare(said=diger.qb64b):  # mismatch events problem with replay
            raise ValidationError("Mismatch keystate at sn = {} with db."
                                  "".format(ked["s"]))

        ksaider = coring.Saider(qb64=diger.qb64)
        self.updateKeyState(aid=aid, serder=kserder, saider=ksaider, dater=dater)
        self.cues.append(dict(kin="keyStateSaved", serder=kserder))

    def updateEnd(self, keys, saider, allowed=None):
        """
        Update end auth database .eans and end database .ends.

        Parameters:
            keys (tuple): of key strs for databases (cid, role, eid)
            saider (Saider): instance from said in reply serder (SAD)
            allowed (bool): True allow eid to be endpoint provided
                          False otherwise
        """
        # update .eans and .ends
        self.db.eans.pin(keys=keys, val=saider)  # overwrite
        if ender := self.db.ends.get(keys=keys):  # preexisting record
            ender.allowed = allowed  # update allowed status
        else:  # no preexisting record
            ender = basing.EndpointRecord(allowed=allowed)  # create new record
        self.db.ends.pin(keys=keys, val=ender)  # overwrite

    def updateLoc(self, keys, saider, url):
        """
        Update loc auth database .lans and loc database .locs.

        Parameters:
            keys (tuple): of key strs for databases (eid, scheme)
            saider (Saider): instance from said in reply serder (SAD)
            url (str): endpoint url
        """
        self.db.lans.pin(keys=keys, val=saider)  # overwrite
        if locer := self.db.locs.get(keys=keys):  # preexisting record
            locer.url = url  # update preexisting record
        else:  # no preexisting record
            locer = basing.LocationRecord(url=url)  # create new record

        self.db.locs.pin(keys=keys, val=locer)  # overwrite

    def escrowKeyStateNotice(self, *, pre, aid, serder, saider, dater, cigars=None, tsgs=None):
        """
        Escrow reply by route

        Parameters:
            pre (str): identifier of key state
            aid (str): identifier of authorizer of key state
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer

            tsgs (Iterable): of quadruples of form (prefixer, seqner, diger, siger) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                siger is indexed sig from trans endorser's key from est evt
        """
        keys = (saider.qb64,)
        self.db.kdts.put(keys=keys, val=dater)  # first one idempotent
        self.db.ksns.put(keys=keys, val=serder)  # first one idempotent

        for prefixer, seqner, diger, sigers in tsgs:  # iterate over each tsg
            quadkeys = (saider.qb64, prefixer.qb64, f"{seqner.sn:032x}", diger.qb64)
            self.db.ksgs.put(keys=quadkeys, vals=sigers)
        for cigar in cigars:  # process each couple to verify sig and write to db
            self.db.kcgs.put(keys=keys, vals=[(cigar.verfer, cigar)])

        return self.db.knes.put(keys=(pre, aid), vals=[saider])  # overwrite

    def updateKeyState(self, aid, serder, saider, dater):
        """
        Update Reply SAD in database given by by serder and associated databases
        for attached cig couple or sig quadruple.
        Overwrites val at key if already exists.

        Parameters:
            aid (str): identifier of key state
            serder (Serder): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
        """
        keys = (saider.qb64,)

        # Add source of ksn to the key for DATEs too...  (source AID, ksn AID)
        self.db.kdts.put(keys=keys, val=dater)  # first one idempotent
        self.db.ksns.pin(keys=keys, val=serder)  # first one idempotent
        # Add source of ksn to the key...  (source AID, ksn AID)
        self.db.knas.pin(keys=(serder.pre, aid), val=saider)  # overwrite

    def removeKeyState(self, saider):
        if saider:
            keys = (saider.qb64,)

            self.db.ksgs.trim(keys=(saider.qb64, ""))  # remove whole branch
            self.db.kcgs.rem(keys=keys)
            self.db.ksns.rem(keys=keys)
            self.db.kdts.rem(keys=keys)

    def processEscrowKeyState(self):
        """
        Process escrows for reply messages. Escrows are keyed by reply pre
        and val is reply said

        triple (prefixer, seqner, diger)
        quadruple (prefixer, seqner, diger, siger)

        """
        for (pre, aid, ion), saider in self.db.knes.getIoItemIter():
            try:
                tsgs = fetchTsgs(db=self.db.ksgs, saider=saider)

                keys = (saider.qb64,)
                dater = self.db.kdts.get(keys=keys)
                serder = self.db.ksns.get(keys=keys)
                vcigars = self.db.kcgs.get(keys=keys)

                try:
                    if not (dater and serder and (tsgs or vcigars)):
                        raise ValueError(f"Missing escrow artifacts at said={saider.qb64}"
                                         f"for pre={pre}.")

                    cigars = []
                    if vcigars:
                        for (verfer, cigar) in vcigars:
                            cigar.verfer = verfer
                            cigars.append(cigar)

                    # do date math for stale escrow
                    if ((helping.nowUTC() - dater.datetime) >
                            datetime.timedelta(seconds=self.TimeoutKSN)):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale key state escrow "
                                    " at pre = %s\n", pre)

                        raise ValidationError(f"Stale key state escrow at pre = {pre}.")

                    self.processReplyKeyStateNotice(serder=serder, saider=saider, route=serder.ked["r"], cigars=cigars,
                                                    tsgs=tsgs, aid=aid)

                except kering.OutOfOrderKeyStateError as ex:
                    # still waiting on missing prior event to validate
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow attempt failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow attempt failed: %s\n", ex.args[0])

                except Exception as ex:  # other error so remove from reply escrow
                    self.db.knes.remIokey(iokeys=(pre, aid, ion))  # remove escrow
                    self.removeKeyState(saider)
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed due to error: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed due to error: %s\n", ex.args[0])

                else:  # unescrow succeded
                    self.db.knes.remIokey(iokeys=(pre, aid, ion))  # remove escrow only
                    logger.info("Kevery unescrow succeeded for key state=\n%s\n",
                                serder.pretty())

            except Exception as ex:  # log diagnostics errors etc
                self.db.knes.remIokey(iokeys=(pre, aid, ion))  # remove escrow
                self.removeKeyState(saider)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Kevery unescrowed due to error: %s\n", ex.args[0])
                else:
                    logger.error("Kevery unescrowed due to error: %s\n", ex.args[0])

    def processQuery(self, serder, source=None, sigers=None, cigars=None):
        """
        Process query mode replay message for collective or single element query.
        Assume promiscuous mode for now.

        Parameters:
            serder (Serder) is query message serder
            source (Prefixer) identifier prefix of querier
            sigers (list) of Siger instances of attached controller indexed sigs
            cigars (list) of Cigar instance of attached non-trans sigs

        """
        ked = serder.ked

        ilk = ked["t"]
        route = ked["r"]
        qry = ked["q"]

        # do signature validation and replay attack prevention logic here
        # src, dt, route

        if route == "logs":
            pre = qry["i"]
            src = qry["src"]
            anchor = qry["a"] if "a" in qry else None
            sn = qry["s"] if "s" in qry else None

            if pre not in self.kevers:
                self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                raise QueryNotFoundError("Query not found error={}.".format(ked))

            kever = self.kevers[pre]
            if anchor:
                if not self.db.findAnchoringEvent(pre=pre, anchor=anchor):
                    self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                    raise QueryNotFoundError("Query not found error={}.".format(ked))

            elif sn is not None:
                if kever.sn < sn or not self.db.fullyWitnessed(kever.serder):
                    self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                    raise QueryNotFoundError("Query not found error={}.".format(ked))

            msgs = list()  # outgoing messages
            for msg in self.db.clonePreIter(pre=pre, fn=0):
                msgs.append(msg)

            if kever.delegator:
                cloner = self.db.clonePreIter(pre=kever.delegator, fn=0)  # create iterator at 0
                for msg in cloner:
                    msgs.append(msg)

            if msgs:
                self.cues.push(dict(kin="replay", src=src, msgs=msgs, dest=source.qb64))

        elif route == "ksn":
            pre = qry["i"]
            src = qry["src"]

            if pre not in self.kevers:
                self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                raise QueryNotFoundError("Query not found error={}.".format(ked))

            kever = self.kevers[pre]
            ksn = kever.state()
            self.cues.push(dict(kin="reply", src=src, route="/ksn", serder=ksn, dest=source.qb64))

        elif route == "mbx":
            pre = qry["i"]
            src = qry["src"]
            topics = qry["topics"]

            if pre not in self.kevers:
                self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                raise QueryNotFoundError("Query not found error={}.".format(ked))

            self.cues.push(dict(kin="stream", serder=serder, pre=pre, src=src, topics=topics))
            # if pre in self.kevers:
            #     kever = self.kevers[pre]
            #     if src in kever.wits and src in self.db.prefixes:  # We are a witness for identifier
            #         self.cues.push(dict(kin="stream", serder=serder, pre=pre, src=src, topics=topics))
        else:
            self.cues.push(dict(kin="invalid", serder=serder))
            raise ValidationError("invalid query message {} for evt = {}".format(ilk, ked))

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
            if sn < 0:  # no more events
                return None

    def escrowOOEvent(self, serder, sigers, seqner=None, saider=None, wigers=None):
        """
        Update associated logs for escrow of Out-of-Order event

        Parameters:
            serder (Serder): instance of  event
            sigers (list): of Siger instance for  event
            seqner (Seqner): instance of sn of event delegatint/issuing event if any
            saider (Saider): instance of dig of event delegatint/issuing event if any
            wigers (list): of witness signatures
        """
        dgkey = dgKey(serder.preb, serder.saidb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addOoe(snKey(serder.preb, serder.sn), serder.saidb)
        if wigers:
            self.db.putWigs(dgkey, [siger.qb64b for siger in wigers])
        if seqner and saider:
            couple = seqner.qb64b + saider.qb64b
            self.db.putPde(dgkey, couple)  # idempotent
        # log escrowed
        logger.info("Kevery process: escrowed out of order event=\n%s\n",
                    json.dumps(serder.ked, indent=1))

    def escrowQueryNotFoundEvent(self, prefixer, serder, sigers, cigars=None):
        """
        Update associated logs for escrow of Out-of-Order event

        Parameters:
            prefixer (Prefixer): source of query message
            serder (Serder): instance of  event
            sigers (list): of Siger instance for  event
            cigars (list): of non-transferable receipts
        """
        cigars = cigars if cigars is not None else []
        dgkey = dgKey(prefixer.qb64b, serder.saidb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addQnf(dgkey, serder.saidb)

        for cigar in cigars:
            self.db.addRct(key=dgkey, val=cigar.verfer.qb64b + cigar.qb64b)

        # log escrowed
        logger.info("Kevery process: escrowed query not found event=\n%s\n",
                    json.dumps(serder.ked, indent=1))

    def escrowLDEvent(self, serder, sigers):
        """
        Update associated logs for escrow of Likely Duplicitous event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
        """
        dgkey = dgKey(serder.preb, serder.saidb)
        self.db.putDts(dgkey, helping.nowIso8601().encode("utf-8"))
        self.db.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.db.putEvt(dgkey, serder.raw)
        self.db.addLde(snKey(serder.preb, serder.sn), serder.saidb)
        # log duplicitous
        logger.info("Kevery process: escrowed likely duplicitous event=\n%s\n",
                    json.dumps(serder.ked, indent=1))

    def escrowUWReceipt(self, serder, wigers, said):
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
            serder (Serder): instance of receipt msg not receipted event
            wigers (list): of Siger instances for witness indexed signature
                of receipted event
            said (str) qb64 said of receipted event not serder.dig because
                serder is a receipt not the receipted event
        """
        # note receipt dig algo may not match database dig also so must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to include dig
        # so can compare digs from receipt and in database for receipted event
        # with different algos.  Can't lookup event by dig for same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, said), helping.nowIso8601().encode("utf-8"))
        for wiger in wigers:  # escrow each couple
            # don't know witness pre yet without witness list so no verfer in wiger
            # if wiger.verfer.transferable:  # skip transferable verfers
            # continue  # skip invalid triplets
            couple = said.encode("utf-8") + wiger.qb64b
            self.db.addUwe(key=snKey(serder.preb, serder.sn), val=couple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified witness indexed receipt"
                    " of pre= %s sn=%x dig=%s\n", serder.pre, serder.sn, said)

    def escrowUReceipt(self, serder, cigars, said):
        """
        Update associated logs for escrow of Unverified Event Receipt (non-transferable)
        Escrowed value is triple edig+rpre+cig where:
           edig is event dig
           rpre is nontrans receiptor prefix
           cig is non-indexed signature on event with key pair derived from rpre

        Parameters:
            serder (Serder): instance of receipt msg not receipted event
            cigars (list): of Cigar instances for event receipt
            said (str): qb64 said in receipt of receipted event not serder.dig because
                serder is of receipt not receipted event
        """
        # note receipt dig algo may not match database dig also so must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to include dig
        # so can compare digs from receipt and in database for receipted event
        # with different algos.  Can't lookup event by dig for same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, said), helping.nowIso8601().encode("utf-8"))
        for cigar in cigars:  # escrow each triple
            if cigar.verfer.transferable:  # skip transferable verfers
                continue  # skip invalid triplets
            triple = said.encode("utf-8") + cigar.verfer.qb64b + cigar.qb64b
            self.db.addUre(key=snKey(serder.preb, serder.sn), val=triple)  # should be snKey
        # log escrowed
        logger.info("Kevery process: escrowed unverified receipt of pre= %s "
                    " sn=%x dig=%s\n", serder.pre, serder.sn, said)

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
            prefixer, seqner, saider, sigers = tsg
            self.db.putDts(dgKey(serder.preb, serder.saidb), helping.nowIso8601().encode("utf-8"))
            # since serder of of receipt not receipted event must use dig in
            # serder.ked["d"] not serder.dig
            prelet = (serder.ked["d"].encode("utf-8") + prefixer.qb64b +
                      seqner.qb64b + saider.qb64b)
            for siger in sigers:  # escrow each quintlet
                quintuple = prelet + siger.qb64b  # quintuple
                self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
            # log escrowed
            logger.info("Kevery process: escrowed unverified transferable receipt "
                        "of pre=%s sn=%x dig=%s by pre=%s\n", serder.pre,
                        serder.sn, serder.ked["d"], prefixer.qb64)

    def escrowTReceipts(self, serder, prefixer, seqner, saider, sigers):
        """
        Update associated logs for escrow of Transferable Event Receipt Group
        (transferable)

        Parameters:
            serder instance of receipt message not receipted event
            prefixer is Prefixer instance of prefix of receipter
            seqner is Seqner instance of  sn of est event of receiptor
            saider is Saider instance of said of est event of receiptor
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
        self.db.putDts(dgKey(serder.preb, serder.saidb), helping.nowIso8601().encode("utf-8"))
        # since serder of of receipt not receipted event must use dig in
        # serder.ked["d"] not serder.dig
        prelet = (serder.ked["d"].encode("utf-8") + prefixer.qb64b +
                  seqner.qb64b + saider.qb64b)
        for siger in sigers:  # escrow each quintlet
            quintuple = prelet + siger.qb64b  # quintuple
            self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified transferable receipt "
                    "of pre=%s sn=%x dig=%s by pre=%s\n", serder.pre,
                    serder.sn, serder.ked["d"], prefixer.qb64)

    def escrowTRQuadruple(self, serder, sprefixer, sseqner, saider, siger):
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
            saider is digest of receipted event provided in receipt

        """
        # Receipt dig algo may not match database dig. So must always
        # serder.compare to match. So receipts for same event may have different
        # digs of that event due to different algos. So the escrow may have
        # different dup at same key, sn.  Escrow needs to be quintuple with
        # edig, validator prefix, validtor est event sn, validator est evvent dig
        # and sig stored at kel pre, sn so can compare digs
        # with different algos.  Can't lookup by dig for the same reason. Must
        # lookup last event by sn not by dig.
        self.db.putDts(dgKey(serder.preb, serder.said), helping.nowIso8601().encode("utf-8"))
        quintuple = (serder.saidb + sprefixer.qb64b + sseqner.qb64b +
                     saider.qb64b + siger.qb64b)
        self.db.addVre(key=snKey(serder.preb, serder.sn), val=quintuple)
        # log escrowed
        logger.info("Kevery process: escrowed unverified transferabe validator "
                    "receipt of pre= %s sn=%x dig=%s\n", serder.pre, serder.sn,
                    serder.said)

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
            self.processEscrowKeyState()
            self.processQueryNotFound()

        except Exception as ex:  # log diagnostics errors etc
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Kevery escrow process error: %s\n", ex.args[0])
            else:
                logger.error("Kevery escrow process error: %s\n", ex.args[0])
            raise ex

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
                    if not sigs:  # otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                    "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]

                    #  get wigs
                    wigs = self.db.getWigs(dgKey(pre, bytes(edig)))  # list of wigs
                    wigers = [Siger(qb64b=bytes(wig)) for wig in wigs]

                    self.processEvent(serder=eserder, sigers=sigers, wigers=wigers)

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
            key = ekey  # setup next while iteration, with key after ekey

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
                eserder = None
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
                    if not sigs:  # otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                    "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    # seal source (delegator issuer if any)
                    seqner = saider = None
                    couple = self.db.getPde(dgkey)
                    if couple is not None:
                        seqner, saider = deSourceCouple(couple)
                    elif eserder.ked["t"] in (Ilks.dip, Ilks.drt,):
                        if eserder.pre in self.kevers:
                            delpre = self.kevers[eserder.pre].delegator
                        else:
                            delpre = eserder.ked["di"]

                        anchor = dict(i=eserder.ked["i"], s=eserder.sn, d=eserder.said)
                        srdr = self.db.findAnchoringEvent(pre=delpre, anchor=anchor)
                        if srdr is not None:
                            seqner = coring.Seqner(sn=srdr.sn)
                            saider = srdr.saider
                            couple = seqner.qb64b + saider.qb64b
                            self.db.putPde(dgkey, couple)

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]
                    self.processEvent(serder=eserder, sigers=sigers,
                                      seqner=seqner, saider=saider)

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

                    if eserder is not None and eserder.ked["t"] in (Ilks.dip, Ilks.drt,):
                        self.cues.append(dict(kin="psUnescrow", serder=eserder))

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

                    if eserder is not None and eserder.ked["t"] in (Ilks.dip, Ilks.drt,):
                        self.cues.append(dict(kin="psUnescrow", serder=eserder))

                    logger.info("Kevery unescrow succeeded in valid event: "
                                "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

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

                        # raise ValidationError("Missing escrowed evt wigs at "
                        # "dig = {}.".format(bytes(edig)))

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]
                    wigers = [Siger(qb64b=bytes(wig)) for wig in wigs]

                    # seal source (delegator issuer if any)
                    seqner = saider = None
                    couple = self.db.getPde(dgKey(pre, bytes(edig)))
                    if couple is not None:
                        seqner, saider = deSourceCouple(couple)

                    self.processEvent(serder=eserder, sigers=sigers, wigers=wigers, seqner=seqner, saider=saider)

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
            key = ekey  # setup next while iteration, with key after ekey

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
                                                         rsaider=rdiger,
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
            key = ekey  # setup next while iteration, with key after ekey

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
                    rsaider, sprefixer, cigar = deReceiptTriple(etriplet)
                    cigar.verfer = Verfer(qb64b=sprefixer.qb64b)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(rsaider.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                    " at dig = %s\n", rsaider.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(rsaider.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutURE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                    " at dig = %s\n", rsaider.qb64b)

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(rsaider.qb64b))

                    # Is receipt for unverified witnessed event in .Pwes escrow
                    # if found then try else clause will remove from escrow
                    found = self._processEscrowFindUnver(pre=pre,
                                                         sn=sn,
                                                         rsaider=rsaider,
                                                         cigar=cigar)

                    if not found:  # no partial witness escrow of event found
                        # so process as escrow of receipt for accept event
                        # not two stage witnessed event escrow
                        # get dig of receipted accepted event in kel using lastEvt
                        # at pre and sn

                        dig = self.db.getKeLast(snKey(pre, sn))
                        if dig is None:  # no receipted event so keep in escrow
                            logger.info("Kevery unescrow error: Missing receipted "
                                        "event at pre=%s sn=%x\n", pre, sn)

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
                        if rsaider.qb64b != serder.saidb:
                            logger.info("Kevery unescrow error: Bad receipt dig."
                                        "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                            raise ValidationError("Bad escrowed receipt dig at "
                                                  "pre={} sn={:x} receipter={}."
                                                  "".format(pre, sn, sprefixer.qb64))

                        #  verify sig verfer key is prefixer from triple
                        if not cigar.verfer.verify(cigar.raw, serder.raw):
                            # no sigs so raise ValidationError which unescrows below
                            logger.info("Kevery unescrow error: Bad receipt sig."
                                        "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                            raise ValidationError("Bad escrowed receipt sig at "
                                                  "pre={} sn={:x} receipter={}."
                                                  "".format(pre, sn, sprefixer.qb64))

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
                            self.db.addWig(key=dgKey(pre, serder.said), val=wiger.qb64b)
                        else:  # write receipt couple to database
                            couple = cigar.verfer.qb64b + cigar.qb64b
                            self.db.addRct(key=dgKey(pre, serder.said), val=couple)


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
            key = ekey  # setup next while iteration, with key after ekey

    def processQueryNotFound(self):
        """
        Process qry events escrowed by Kevery for KELs that have not yet met the criteria of the query.
        A missing KEL or criteria for an event in a KEL at a particular sequence number or an event containing a
        specific anchor can result in query not found escrowed events.

        Escrowed items are indexed in database table keyed by prefix and
        sn with duplicates given by different dig inserted in insertion order.
        This allows FIFO processing of events with same prefix and sn but different
        digest.

        Uses  .db.addQnf(self, key, val) which is IOVal with dups.

        Value is dgkey for event stored in .Evt where .Evt has serder.raw of event.

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
        pre = b''
        sn = 0
        while True:  # break when done
            for ekey, edig in self.db.getQnfItemsNextIter(key=key):
                try:
                    pre, _ = splitKey(ekey)  # get pre and sn from escrow item
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
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutQNF):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale qry event escrow "
                                    " at dig = %s\n", bytes(edig))

                        raise ValidationError("Stale qry event escrow "
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
                    if not sigs:  # otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                    "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]

                    #  get wigs
                    cigars = []
                    cigs = self.db.getRcts(dgKey(pre, bytes(edig)))  # list of wigs
                    for cig in cigs:
                        (_, cigar) = deReceiptCouple(cig)
                        cigars.append(cigar)

                    source = coring.Prefixer(qb64b=pre)
                    self.processQuery(serder=eserder, source=source, sigers=sigers, cigars=cigars)

                except QueryNotFoundError as ex:
                    # still waiting on missing prior event to validate
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrow failed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrow failed: %s\n", ex.args[0])

                except Exception as ex:  # log diagnostics errors etc
                    # error other than out of order so remove from OO escrow
                    self.db.delQnf(dgKey(pre, edig), edig)  # removes one escrow at key val
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Kevery unescrowed: %s\n", ex.args[0])
                    else:
                        logger.error("Kevery unescrowed: %s\n", ex.args[0])
                else:  # unescrow succeeded, remove from escrow
                    # We don't remove all escrows at pre,sn because some might be
                    # duplicitous so we process remaining escrows in spite of found
                    # valid event escrow.
                    self.db.delQnf(dgKey(pre, edig), edig)  # removes one escrow at key val
                    logger.info("Kevery unescrow succeeded in valid event: "
                                "event=\n%s\n", json.dumps(eserder.ked, indent=1))

            if ekey == key:  # still same so no escrows found on last while iteration
                break
            key = ekey  # setup next while iteration, with key after ekey

    def _processEscrowFindUnver(self, pre, sn, rsaider, wiger=None, cigar=None):
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
           rsaider (Saider): derived from receipt's dig of receipted event to find
           wiger (Siger): instance of witness indexed signature from receipt
           cigar (Cigar): instance of witness nonindexed signature from receipt

        """
        # lookup the database dig of the receipted event in pwes escrow using
        # snKey(pre,sn) where pre is controller and sn is event sequence number
        # compare dig to rdiger derived from receipt's dig of receipted event
        found = False
        for dig in self.db.getPwesIter(key=snKey(pre, sn)):  # search entries
            dig = bytes(dig)  # database dig of receipted event
            # get the escrowed event using database dig in .Pwes
            serder = Serder(raw=bytes(self.db.getEvt(dgKey(pre, dig))))  # receipted event
            #  compare digs to ensure database dig and rdiger (receipt's dig) match
            if rsaider.qb64b != dig:
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
                if (witset & cutset) != cutset:  # some cuts not in wits
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
                    break  # done with search have caller add wig.

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
            if not wiger.verfer.verify(wiger.raw, serder.raw):  # not verify
                # raise ValidationError which unescrows .Uwes or .Ures in caller
                logger.info("Kevery unescrow error: Bad witness receipt"
                            " wig. pre=%s sn=%x\n", pre, sn)

                raise ValidationError("Bad escrowed witness receipt wig"
                                      " at pre={} sn={:x}."
                                      "".format(pre, sn))
            self.db.addWig(key=dgKey(pre, serder.said), val=wiger.qb64b)
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
                    esaider, sprefixer, sseqner, ssaider, siger = deTransReceiptQuintuple(equinlet)

                    # check date if expired then remove escrow.
                    dtb = self.db.getDts(dgKey(pre, bytes(esaider.qb64b)))
                    if dtb is None:  # othewise is a datetime as bytes
                        # no date time so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event datetime"
                                    " at dig = %s\n", esaider.qb64b)

                        raise ValidationError("Missing escrowed event datetime "
                                              "at dig = {}.".format(esaider.qb64b))

                    # do date math here and discard if stale nowIso8601() bytes
                    dtnow = helping.nowUTC()
                    dte = helping.fromIso8601(bytes(dtb))
                    if (dtnow - dte) > datetime.timedelta(seconds=self.TimeoutVRE):
                        # escrow stale so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Stale event escrow "
                                    " at dig = %s\n", esaider.qb64b)

                        raise ValidationError("Stale event escrow "
                                              "at dig = {}.".format(esaider.qb64b))

                    # get dig of the receipted event using pre and sn lastEvt
                    raw = self.db.getKeLast(snKey(pre, sn))
                    if raw is None:
                        # no event so keep in escrow
                        logger.info("Kevery unescrow error: Missing receipted "
                                    "event at pre=%s sn=%x\n", pre, sn)

                        raise UnverifiedTransferableReceiptError("Missing receipted evt at pre={} "
                                                                 " sn={:x}".format(pre, sn))

                    dig = bytes(raw)
                    # get receipted event using pre and edig
                    raw = self.db.getEvt(dgKey(pre, dig))
                    if raw is None:  # receipted event superseded so remove from escrow
                        logger.info("Kevery unescrow error: Invalid receipted "
                                    "event referenace at pre=%s sn=%x\n", pre, sn)

                        raise ValidationError("Invalid receipted evt reference "
                                              "at pre={} sn={:x}".format(pre, sn))

                    serder = Serder(raw=bytes(raw))  # receipted event

                    #  compare digs
                    if esaider.qb64b != serder.saidb:
                        logger.info("Kevery unescrow error: Bad receipt dig."
                                    "pre=%s sn=%x receipter=%s\n", (pre, sn, sprefixer.qb64))

                        raise ValidationError("Bad escrowed receipt dig at "
                                              "pre={} sn={:x} receipter={}."
                                              "".format(pre, sn, sprefixer.qb64))

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
                    if not sserder.compare(said=ssaider.qb64):  # seal dig not match event
                        # this unescrows
                        raise ValidationError("Bad chit seal at sn = {} for rct = {}."
                                              "".format(sseqner.sn, sserder.ked))

                    # verify sigs and if so write quadruple to database
                    verfers = sserder.verfers
                    if not verfers:
                        raise ValidationError("Invalid seal est. event dig = {} for "
                                              "receipt from pre ={} no keys."
                                              "".format(ssaider.qb64, sprefixer.qb64))

                    # Set up quadruple
                    sealet = sprefixer.qb64b + sseqner.qb64b + ssaider.qb64b

                    if siger.index >= len(verfers):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(siger.index))

                    siger.verfer = verfers[siger.index]  # assign verfer
                    if not siger.verfer.verify(siger.raw, serder.raw):  # verify sig
                        logger.info("Kevery unescrow error: Bad trans receipt sig."
                                    "pre=%s sn=%x receipter=%s\n", pre, sn, sprefixer.qb64)

                        raise ValidationError("Bad escrowed trans receipt sig at "
                                              "pre={} sn={:x} receipter={}."
                                              "".format(pre, sn, sprefixer.qb64))

                    # good sig so write receipt quadruple to database
                    quadruple = sealet + siger.qb64b
                    self.db.addVrc(key=dgKey(pre, serder.said), val=quadruple)


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
            key = ekey  # setup next while iteration, with key after ekey

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
                    if not sigs:  # otherwise its a list of sigs
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
            key = ekey  # setup next while iteration, with key after ekey

    def duplicity(self, serder, sigers):
        """
        PlaceHolder Reminder
        Processes potential duplicitous events in PDELs

        Handles duplicity detection and logging if duplicitous

        Placeholder here for logic need to move

        """
        pass
