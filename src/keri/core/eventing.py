# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""
import datetime
import json
import logging
from collections import namedtuple
from dataclasses import dataclass, astuple, asdict, field
from urllib.parse import urlsplit
from math import ceil
from ordered_set import OrderedSet as oset
from hio.help import decking

from . import coring, serdering
from .coring import (versify, Serials, Ilks, MtrDex, PreDex, DigDex,
                     NonTransDex, CtrDex, Counter,
                     Number, Seqner, Siger, Cigar, Dater, Indexer, IdrDex,
                     Verfer, Diger, Prefixer, Tholder, Saider)
from . import serdering
from .. import help
from .. import kering
from ..db import basing, dbing
from ..db.basing import KeyStateRecord, StateEERecord
from ..db.dbing import dgKey, snKey, fnKey, splitKeySN, splitKey

from ..kering import (MissingEntryError,
                      ValidationError, DerivationError, MissingSignatureError,
                      MissingWitnessSignatureError, UnverifiedReplyError,
                      MissingDelegationError, OutOfOrderError,
                      LikelyDuplicitousError, UnverifiedWitnessReceiptError,
                      UnverifiedReceiptError, UnverifiedTransferableReceiptError, QueryNotFoundError)
from ..kering import Version, Versionage
from ..kering import (ICP_LABELS, DIP_LABELS, ROT_LABELS, DRT_LABELS, IXN_LABELS,
                       RPY_LABELS)

from ..help import helping

logger = help.ogler.getLogger()

EscrowTimeoutPS = 3600  # seconds for partial signed escrow timeout

MaxIntThold = 2 ** 32 - 1

@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    EstOnly: str = 'EO'  # Only allow establishment events
    DoNotDelegate: str = 'DND'  # Dot not allow delegated identifiers
    NoBackers: str = 'NB'  # Do not allow any registrar backers
    Backers: str = 'RB' # Registrar backer provided in Registrar seal

    def __iter__(self):
        return iter(astuple(self))


TraitDex = TraitCodex()  # Make instance

# Location of last establishment key event: sn is int, dig is qb64 digest
LastEstLoc = namedtuple("LastEstLoc", 's d')

#  for the following Seal namedtuples use the ._asdict() method to convert to dict
#  when using in events
# to convert seal namedtuple to dict use namedtuple._asdict()
# seal == SealEvent(i="abc",s="1",d="efg")
# sealdict =seal._asdict()
# to convet dict to namedtuple use ** unpacking as in seal = SealDigest(**sealdict)
# to check if dict of seal matches fields of associted namedtuple
# if tuple(sealdict.keys()) == SealEvent._fields:

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

# Establishment Event for Source of Message: duple (s, d)
# s = sn of event as lowercase hex string  no leading zeros,
# d = SAID digest qb64 of event
# the pre is provided in the 'i' field of the message itself which is the qb64
# of identifier prefix of KEL from which to get  est, event given by 's d'
# use SealSourceCouples count code for attachment
SealEst = namedtuple("SealEst", 's d')

# State (latest current) Event: triple (s, t, d)
# s = sn of latest event as lowercase hex string  no leading zeros,
# t = message type of latest event (ilk)
# d = SAID digest qb64 of latest event
StateEvent = namedtuple("StateEvent", 's t d')

# State (latest current) Establishment Event: quadruple (s, d, br, ba)
# s = sn of latest est event as lowercase hex string  no leading zeros,
# d = SAID digest qb64  of latest establishment event
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
        serder (SerderKERI): instance of message
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
                sigers (list): of Siger instances of indexed signatures

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
          ndigs=None,
          nsith=None,
          toad=None,  # default based on wits
          wits=None,  # default to []
          cnfg=None,  # default to []
          dpre=None,
          version=Version,
          kind=Serials.json,
          intive = False,
          ):
    """
    Returns instance of KeyStateRecord in support of key state notification messages.
    Utility function to automate creation embedded key static notices

    Parameters:
        pre (str): identifier prefix qb64
        sn (int): sequence number of latest event
        pig (str): SAID qb64 of prior event
        dig (str): SAID qb64 of latest (current) event
        fn (int):  first seen ordinal number of latest event
        eilk (str): event (message) type (ilk) of latest (current) event
        keys (list): qb64 signing keys
        eevt (StateEstEvent): namedtuple (s,d,wr,wa) for latest est event
            s = sn of est event
            d = SAID of est event
            wr = witness remove list (cuts)
            wa = witness add list (adds)
        stamp (str | None):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message or data
        sith sith (int | str | list | None): current signing threshold input to Tholder
        ndigs (list | None): current signing key digests qb64
        nsith int | str | list | None): next signing threshold input to Tholder
        toad (int | str | None): witness threshold number if str then hex str
        wits (list | None): prior witness identifier prefixes qb64
        cnfg (list | None):  strings from TraitDex configuration trait strings
        dpre (str | None): identifier prefix qb64 delegator if any
                           If None then dpre in state is empty ""
        version (Version): KERI protocol version string
        kind (str): serialization kind from Serials
        intive (bool): True means sith, nsith, and toad are serialized as ints
                       instead of hex str when numeric threshold

    """
    sner = Number(num=sn)  # raises InvalidValueError if sn < 0
    fner = Number(num=fn)  # raises InvalidValueError if fn < 0

    if eilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
        raise ValueError(f"Invalid event type et={eilk} in key state.")

    if stamp is None:
        stamp = helping.nowIso8601()

    if sith is None:
        sith = "{:x}".format(max(1, ceil(len(keys) / 2)))

    tholder = Tholder(sith=sith)
    if tholder.num is not None and tholder.num < 1:
        raise ValueError(f"Invalid sith = {tholder.num} less than 1.")
    if tholder.size > len(keys):
        raise ValueError(f"Invalid sith = {tholder.num} for keys = {keys}")

    if ndigs is None:
        ndigs = []

    if nsith is None:
        nsith = max(0, ceil(len(ndigs) / 2))

    ntholder = Tholder(sith=nsith)
    if ntholder.num is not None and ntholder.num < 0:
        raise ValueError(f"Invalid nsith = {ntholder.num} less than 0.")
    if ntholder.size > len(ndigs):
        raise ValueError(f"Invalid nsith = {ntholder.num} for keys = {ndigs}")

    wits = wits if wits is not None else []
    witset = oset(wits)
    if len(witset) != len(wits):
        raise ValueError(f"Invalid wits = {wits}, has duplicates.")

    if toad is None:
        if not witset:
            toad = 0
        else:
            toad = max(1, ceil(len(witset) / 2))

    if toad is None:
        if not witset:
            toad = 0
        else:  # compute default f and m for len(wits)
            toad = ample(len(witset))
    toader = Number(num=toad)

    if witset:
        if toader.num < 1 or toader.num > len(witset):  # out of bounds toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {witset}")
    else:
        if toader.num != 0:  # invalid toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {witset}")

    if not eevt or not isinstance(eevt, StateEstEvent):
        raise ValueError(f"Missing or invalid latest est event = {eevt} for key "
                         f"state.")
    eesner = Number(numh=eevt.s)  # if not whole number raises InvalidValueError

    # cuts is relative to prior wits not current wits provided here
    cuts = eevt.br if eevt.br is not None else []
    cutset = oset(cuts)
    if len(cutset) != len(cuts):  # duplicates in cuts
        raise ValueError(f"Invalid cuts = {cuts}, has "
                         f"duplicates, in latest est event, .")

    # adds is relative to prior wits not current wits provided here
    adds = eevt.ba if eevt.ba is not None else []
    addset = oset(adds)

    if len(addset) != len(adds):  # duplicates in adds
        raise ValueError(f"Invalid adds = {adds}, has duplicates,"
                         f" in latest est event,.")

    if cutset & addset:  # non empty intersection
        raise ValueError(f"Intersecting cuts = {cuts} and adds = {adds} in "
                         f"latest est event.")

    ksr = basing.KeyStateRecord(
               vn=list(version), # version number as list [major, minor]
               i=pre,  # qb64 prefix
               s=sner.numh,  # lowercase hex string no leading zeros
               p=pig,
               d=dig,
               f=fner.numh,  # lowercase hex string no leading zeros
               dt=stamp,
               et=eilk,
               kt=(tholder.num if intive and tholder.num is not None and
                    tholder.num <= MaxIntThold else tholder.sith),
               k=keys,  # list of qb64
               nt=(ntholder.num if intive and ntholder.num is not None and
                    ntholder.num <= MaxIntThold else ntholder.sith),
               n=ndigs,
               bt=toader.num if intive and toader.num <= MaxIntThold else toader.numh,
               b=wits,  # list of qb64 may be empty
               c=cnfg if cnfg is not None else [],
               ee=StateEERecord._fromdict(eevt._asdict()),  # latest est event dict
               di=dpre if dpre is not None else "",
               )
    return ksr  # return KeyStateRecord  use asdict(ksr) to get dict version



def incept(keys,
           *,
           isith=None,
           ndigs=None,
           nsith=None,
           toad=None,
           wits=None,
           cnfg=None,
           data=None,
           version=Version,
           kind=Serials.json,
           code=None,
           intive=False,
           delpre=None,
           ):
    """
    Returns serder of inception event message.
    Utility function to automate creation of inception events.

    Parameters:
        keys  (list): current signing keys qb64
        sith (int | str | list | None): current signing threshold input to Tholder
        ndigs (list | None): current signing key digests qb64
        nsith int | str | list | None): next signing threshold input to Tholder
        toad (int | str | None): witness threshold number if str then hex str
        wits (list | None): witness identifier prefixes qb64
        cnfg (list | None): configuration traits from TraitDex
        data (list | None): seal dicts
        version (Version): KERI protocol version string
        kind (str): serialization kind from Serials
        code (str | None): derivation code for computed prefix
        intive (bool): True means sith, nsith, and toad are serialized as ints
            not hex str when numeric threshold. Most compact JSON representation
            when Numbers are small because no quotes. Number accepts both.
        delpre (str | None): delegator identifier prefix qb64. When not None
            makes this a msg type "dip", delegated inception event.
    """
    vs = versify(version=version, kind=kind, size=0)
    ilk = Ilks.icp if delpre is None else Ilks.dip  # inception or delegated inception
    sner = Number(num=0)  # sn for incept must be 0

    if isith is None:
        isith = max(1, ceil(len(keys) / 2))

    tholder = Tholder(sith=isith)
    if tholder.num is not None and tholder.num < 1:
        raise ValueError(f"Invalid sith = {tholder.num} less than 1.")
    if tholder.size > len(keys):
        raise ValueError(f"Invalid sith = {tholder.num} for keys = {keys}")

    if ndigs is None:
        ndigs = []

    if nsith is None:
        nsith = max(0, ceil(len(ndigs) / 2))

    ntholder = Tholder(sith=nsith)
    if ntholder.num is not None and ntholder.num < 0:
        raise ValueError(f"Invalid nsith = {ntholder.num} less than 0.")
    if ntholder.size > len(ndigs):
            raise ValueError(f"Invalid nsith = {ntholder.num} for keys = {ndigs}")


    wits = wits if wits is not None else []
    if len(oset(wits)) != len(wits):
        raise ValueError(f"Invalid wits = {wits}, has duplicates.")

    if toad is None:
        if not wits:
            toad = 0
        else:  # compute default f and m for len(wits)
            toad = ample(len(wits))
    toader = Number(num=toad)

    if wits:
        if toader.num < 1 or toader.num > len(wits):  # out of bounds toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {wits}")
    else:
        if toader.num != 0:  # invalid toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {wits}")

    cnfg = cnfg if cnfg is not None else []

    data = data if data is not None else []

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",   # qb64 SAID
               i="",  # qb64 prefix
               s=sner.numh,  # hex string no leading zeros lowercase
               kt=(tholder.num if intive and tholder.num is not None and
                    tholder.num <= MaxIntThold else tholder.sith),
               k=keys,  # list of qb64
               nt=(ntholder.num if intive and ntholder.num is not None and
                    ntholder.num <= MaxIntThold else ntholder.sith),
               n=ndigs,  # list of hashes qb64
               bt=toader.num if intive and toader.num <= MaxIntThold else toader.numh,
               b=wits,  # list of qb64 may be empty
               c=cnfg,  # list of config ordered mappings may be empty
               a=data,  # list of seal dicts
               )

    pre = ""
    saids = None
    if delpre is not None:  # delegated inception with ilk = dip
        ked['di'] = delpre  # SerderKERI .verify will ensure valid prefix
    else:  # non delegated
        if (code is None or code not in DigDex) and len(keys) == 1:  # use key[0] as default
            ked["i"] = keys[0]  # SerderKERI .verify will ensure valid prefix

    if code is not None and code in PreDex:  # use code to override all else
        saids = {'i': code}

    serder = serdering.SerderKERI(sad=ked, makify=True, saids=saids)
    serder._verify()  # raises error if fails verifications
    return serder

    #if delpre is not None:  # delegated inception with ilk = dip
        #ked['di'] = delpre
        #if code is None:
            #code = MtrDex.Blake3_256  # force digestive

    #if delpre is None and code is None and len(keys) == 1:
        #prefixer = Prefixer(qb64=keys[0])  # defaults to not digestive code
        #if prefixer.digestive:
            #raise ValueError("Invalid code, digestive={}, must be derived from"
                             #" ked.".format(prefixer.code))
    #else:  # digestive
        ## raises derivation error if non-empty nxt but ephemeral code
        #prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

        #if delpre is not None:
            #if not prefixer.digestive:
                #raise ValueError(f"Invalid derivation code = {prefixer.code} "
                                 #f"for delegation. Must be digestive")

    #ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64
    #if prefixer.digestive:
        #ked["d"] = prefixer.qb64
    #else:
        #_, ked = coring.Saider.saidify(sad=ked)

    #return Serder(ked=ked)  # return serialized ked

def delcept(keys, delpre, **kwa):
    """
    Returns serder of delegated inception event message.
    Utility function to automate creation of delegated inception events.
    Syntactic suger that calls incept but with delpre so ilk is dip.

    Parameters:
        keys  (list): current signing keys qb64
        sith (int | str | list | None): current signing threshold input to Tholder
        ndigs (list | None): current signing key digests qb64
        nsith int | str | list | None): next signing threshold input to Tholder
        toad (int | str | None): witness threshold number if str then hex str
        wits (list | None): witness identifier prefixes qb64
        cnfg (list | None): configuration traits from TraitDex
        data (list | None): seal dicts
        version (Version): KERI protocol version string
        kind (str): serialization kind from Serials
        code (str | None): derivation code for computed prefix
        intive (bool): True means sith, nsith, and toad are serialized as ints
            not hex str when numeric threshold
        delpre (str | None): delegator identifier prefix qb64. When not None
            makes this a msg type "dip", delegated inception event.
    """
    return incept(keys=keys, delpre=delpre, **kwa)


def rotate(pre,
           keys,
           dig,
           *,
           ilk=Ilks.rot,
           sn=1,
           isith=None,
           ndigs=None,
           nsith=None,
           toad=None,
           wits=None,  # prior existing wits
           cuts=None,
           adds=None,
           data=None,
           version=Version,
           kind=Serials.json,
           intive = False,
           ):
    """
    Returns serder of rotation event message.
    Utility function to automate creation of rotation events.

    Parameters:
        pre (str): identifier prefix qb64
        keys  (list): current signing keys qb64
        dig (str): SAID of previous event qb64
        ilk (str): ilk of event. Must be in (Ilks.rot, Ilks.drt)
        sn (int | str): sequence number int or hex str
        sith (int | str | list | None): current signing threshold input to Tholder
        ndigs (list | None): current signing key digests qb64
        nsith int | str | list | None): next signing threshold input to Tholder
        toad (int | str | None): witness threshold number if str then hex str
        wits (list | None): prior witness identifier prefixes qb64
        cuts (list | None): witness prefixes to cut qb64
        adds (list | None): witness prefixes to add qb64
        data (list | None): seal dicts
        version (Version): KERI protocol version string
        kind (str): serialization kind from Serials
        intive (bool): True means sith, nsith, and toad are serialized as ints
                       instead of hex str when numeric threshold
    """
    vs = versify(version=version, kind=kind, size=0)

    ilk = ilk
    if ilk not in (Ilks.rot, Ilks.drt):
        raise  ValueError(f"Invalid ilk ={ilk} for rot or drt.")

    sner = Number(num=sn)
    if sner.num < 1:  # sn for rotate must be >= 1
        raise ValueError(f"Invalid sn = 0x{sner.numh} for rot or drt.")

    if isith is None:
        isith = max(1, ceil(len(keys) / 2))

    tholder = Tholder(sith=isith)
    if tholder.num is not None and tholder.num < 1:
        raise ValueError(f"Invalid sith = {tholder.num} less than 1.")
    if tholder.size > len(keys):
        raise ValueError(f"Invalid sith = {tholder.num} for keys = {keys}")

    if ndigs is None:
        ndigs = []

    if nsith is None:
        nsith = max(0, ceil(len(ndigs) / 2))

    ntholder = Tholder(sith=nsith)
    if ntholder.num is not None and ntholder.num < 0:
        raise ValueError(f"Invalid nsith = {ntholder.num} less than 0.")
    if ntholder.size > len(ndigs):
        raise ValueError(f"Invalid nsith = {ntholder.num} for keys = {ndigs}")

    wits = wits if wits is not None else []
    witset = oset(wits)
    if len(witset) != len(wits):
        raise ValueError(f"Invalid wits = {wits}, has duplicates.")

    cuts = cuts if cuts is not None else []
    cutset = oset(cuts)
    if len(cutset) != len(cuts):
        raise ValueError(f"Invalid cuts = {cuts}, has duplicates.")

    if (witset & cutset) != cutset:  # some cuts not in wits
        raise ValueError(f"Invalid cuts = {cuts}, not all members in wits.")

    adds = adds if adds is not None else []
    addset = oset(adds)
    if len(addset) != len(adds):
        raise ValueError(f"Invalid adds = {adds}, has duplicates.")

    if witset & addset:  # non empty intersection
        raise ValueError(f"Intersecting wits = {wits} and  adds = {adds}.")

    if cutset & addset:  # non empty intersection
        raise ValueError(f"Intersecting cuts = {cuts} and  adds = {adds}.")

    newitset = (witset - cutset) | addset

    if len(newitset) != (len(wits) - len(cuts) + len(adds)):  # redundant?
        raise ValueError(f"Invalid member combination among wits = {wits}, "
                         f"cuts ={cuts}, and adds = {adds}.")

    if toad is None:
        if not newitset:
            toad = 0
        else:  # compute default f and m for len(wits)
            toad = ample(len(newitset))
    toader = Number(num=toad)

    if newitset:
        if toader.num < 1 or toader.num > len(newitset):  # out of bounds toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {newitset}")
    else:
        if toader.num != 0:  # invalid toad
            raise ValueError(f"Invalid toad = {toader.num} for wits = {newitset}")

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",  # qb64 SAID
               i=pre,  # qb64 prefix
               s=sner.numh,  # hex string no leading zeros lowercase
               p=dig,  # SAID qb64 digest of prior event
               kt=(tholder.num if intive and tholder.num is not None and
                    tholder.num <= MaxIntThold else tholder.sith),
               k=keys,  # list of qb64
               nt=(ntholder.num if intive and ntholder.num is not None and
                    ntholder.num <= MaxIntThold else ntholder.sith),
               n=ndigs,  # hash qual Base64
               bt=toader.num if intive and toader.num <= MaxIntThold else toader.numh,
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               a= data if data is not None else [],  # list of seals
               )

    serder = serdering.SerderKERI(sad=ked, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder

    #_, ked = coring.Saider.saidify(sad=ked)

    #return Serder(ked=ked)  # return serialized ked

def deltate(pre,
           keys,
           dig,
           ilk=Ilks.drt,
           **kwa
           ):
    """
    Returns serder of delegated rotation event message.
    Utility function to automate creation of delegated rotation events.
    Syntactic suger that calls rotate but with ilk set to drt.


    Parameters:
        pre (str): identifier prefix qb64
        keys  (list): current signing keys qb64
        dig (str): said of previous event qb64
        ilk (str): ilk of event. Must be in (Ilks.rot, Ilks.drt)
        sn (int | str): sequence number int or hex str
        sith (int | str | list): current signing threshold input to Tholder
        ndigs (list): current signing key digests qb64
        nsith int | str | list): next signing threshold input to Tholder
        toad (int | str ): witness threshold number if str then hex str
        wits (list): prior witness identifier prefixes qb64
        cuts (list): witness prefixes to cut qb64
        adds (list): witness prefixes to add qb64
        data (list): seal dicts
        version (Version): KERI protocol version string
        kind (str): serialization kind from Serials
        intive (bool): True means sith, nsith, and toad are serialized as ints
            not hex str when numeric threshold

    """
    return rotate(pre=pre, keys=keys, dig=dig, ilk=ilk, **kwa)



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
        dig is said digest of previous event qb64
        sn is int sequence number
        data is list of dicts of comitted data such as seals
        version is Version instance
        kind is serialization kind
    """
    vs = versify(version=version, kind=kind, size=0)
    ilk = Ilks.ixn
    sner = Number(num=sn)
    if sner.num < 1:  # sn for interact must be >= 1
        raise ValueError(f"Invalid sn = 0x{sner.numh} for ixn.")


    data = data if data is not None else []

    sad = dict(v=vs,  # version string
               t=ilk,
               d="",
               i=pre,  # qb64 prefix
               s=sner.numh,  # hex string no leading zeros lowercase
               p=dig,  # qb64 digest of prior event
               a=data,  # list of seals
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder

    #_, ked = coring.Saider.saidify(sad=ked)

    #return Serder(ked=ked)  # return serialized ked


def receipt(pre,
            sn,
            said,
            *,
            version=Version,
            kind=Serials.json
            ):
    """
    Returns serder of event receipt message. Used for both non-trans and trans
    signers as determined by signature attachment type (cigar or siger)

    Utility function to automate creation of receipts.

     Parameters:
        pre is qb64 str of prefix of event being receipted
        sn  is int sequence number of event being receipted
        said is qb64 of said of event being receipted
        version is Version instance of receipt
        kind  is serialization kind of receipt
    """
    vs = versify(version=version, kind=kind, size=0)
    ilk = Ilks.rct

    sner = Number(num=sn)
    if sner.num < 0:  # sn for receipt must be >= 1
        raise ValueError(f"Invalid sn = 0x{sner.numh} for rect.")

    sad = dict(v=vs,  # version string
               t=ilk,  # Ilks.rct
               d=said,  # qb64 digest of receipted event
               i=pre,  # qb64 prefix
               s=sner.numh,  # hex string no leading zeros lowercase
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder


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
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
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
    vs = versify(version=version, kind=kind, size=0)
    ilk = Ilks.qry

    sad = dict(v=vs,  # version string
               t=ilk,
               d="",
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route,  # resource type for single item request
               rr=replyRoute,
               q=query,
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder

    #_, ked = coring.Saider.saidify(sad=ked)

    #return Serder(ked=ked)  # return serialized ked


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
         "d": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
         "name": "John Jones",
         "role": "Founder",
      }
    }
    """
    label = coring.Saids.d
    vs = versify(version=version, kind=kind, size=0)
    if data is None:
        data = {}

    sad = dict(v=vs,  # version string
               t=Ilks.rpy,
               d="",
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route if route is not None else "",  # route
               a=data if data else {},  # attributes
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder

    #_, sad = coring.Saider.saidify(sad=sad, kind=kind, label=label)

    #saider = coring.Saider(qb64=sad[label])
    #if not saider.verify(sad=sad, kind=kind, label=label, prefixed=True):
        #raise ValidationError("Invalid said = {} for reply msg={}."
                              #"".format(saider.qb64, sad))

    #return Serder(ked=sad)  # return serialized Self-Addressed Data (SAD)


def prod(route="",
          replyRoute="",
          query=None,
          stamp=None,
          version=Version,
          kind=Serials.json):
    """
    Returns serder of prod, 'pro', msg to request disclosure via bare, 'bar' msg
    of data anchored via seal(s) on KEL for identifier prefix, pre, when given
    by all SAIDs given in digs list.

    {
      "v" : "KERI10JSON00011c_",
      "t" : "pro",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "data",
      "rr": "data/processor",
      "q":
      {
        "d":"EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
      }
    }

    """
    vs = versify(version=version, kind=kind, size=0)
    ilk = Ilks.pro

    sad = dict(v=vs,  # version string
               t=ilk,
               d="",
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route,  # resource type for single item request
               rr=replyRoute,
               q=query,
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder

    #_, ked = coring.Saider.saidify(sad=ked)

    #return Serder(ked=ked)  # return serialized ked

def bare(route="",
           data=None,
           stamp=None,
           version=Version,
           kind=Serials.json):
    """
    Returns serder of bare 'bar' message.
    Utility function to automate creation of unhiding (bareing) messages for
    disclosure of sealed data associated with anchored seals in a KEL.
    Reference to anchoring seal is provided as an attachment to bare message.
    Bare 'bar' message is a SAD item with an associated derived SAID in a 'd'
    field in side its 'a' block.

     Parameters:
        route is route path string that indicates data flow handler (behavior)
            to processs the exposure
        data is dict of dicts of comitted SADS for SAIDs in seals keyed by SAID
        stamp (str):  date-time-stamp RFC-3339 profile of ISO-8601 datetime of
                      creation of message or data
        version is Version instance
        kind is serialization kind


    {
      "v" : "KERI10JSON00011c_",
      "t" : "bar",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "sealed/processor",
      "a" :
        {
          "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM":
            {
               "d":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
               "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
               "dt": "2020-08-22T17:50:12.988921+00:00",
               "name": "John Jones",
               "role": "Founder",
            }
        }
    }
    """
    vs = versify(version=version, kind=kind, size=0)

    sad = dict(v=vs,  # version string
               t=Ilks.bar,
               d="",
               dt=stamp if stamp is not None else helping.nowIso8601(),
               r=route if route is not None else "",  # route
               a=data if data else {},  # dict of SADs
               )

    serder = serdering.SerderKERI(sad=sad, makify=True)
    serder._verify()  # raises error if fails verifications
    return serder

    #_, sad = coring.Saider.saidify(sad=sad)

    #return Serder(ked=sad)  # return serialized Self-Addressed Data (SAD)


def messagize(serder, *, sigers=None, seal=None, wigers=None, cigars=None,
              pipelined=False):
    """
    Attaches indexed signatures from sigers and/or cigars and/or wigers to
    KERI message data from serder
    Parameters:
        serder (SerderKERI): instance containing the event
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
    atc = bytearray()  # attachment

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
        root = coring.Pather(bext="-")
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
        EstOnly (bool):
                True means allow only establishment events
                False means allow all events
        DoNotDelegate (bool):
                True means do not allow delegation other identifiers
                False means allow delegation of delegated identifiers

    Attributes:
        db (Baser | None): instance that manages the LMDB database when provided.
            When None provided then create and assign vacuous instance of Baser.
        cues (deque | None): Injected Kevery.cues when provided. Default None.
        prefixes (list | None): Injected from Kevery when provided.
            qb64 identifier prefixes of own habitat identifiers.
            Assign db.prefixes when None
            When empty operate in promiscuous mode
        local (bool): Injected from kevery when provided.
            True means only process msgs for own events when .prefixes is not empty
            False means only process msgs for not own events when .prefixes is not empty
                Default is False.
        version (Versionage): serder.version instance of current event state version
        prefixer (Prefixer):  instance for current event state
        sner (Number): instance of sequence number
        fner (Number): instance of first seen ordinal number
        dater (Dater): instance of first seen datetime
        serder (SerderKERI): instance of current event with .serder.diger for digest
        ilk (str): from Ilks for current event type
        tholder (Tholder): instance for event signing threshold
        verfers (list): of Verfer instances for current event state set of signing keys
        ndigers (list): of Diger instances for current event state set  of
            next (rotation) key digests
        ntholder (Tholder): instance for next (rotation) threshold
            from serder.ntholder
        toader (Number): instance of TOAD (threshold of accountable duplicity)
        wits (list): of qualified qb64 aids for witnesses
        cuts (list): of qualified qb64 aids for witnesses cut from prev wits list
        adds (list) of qualified qb64 aids for witnesses added to prev wits list

        estOnly (bool): config trait True means only allow establishment events
            Default False. Corresponds to config trait string "EO"
        doNotDelegate (bool): config trait True means do not allow delegation
            Default False. Corresponds to config trait string "DND"

        lastEst (LastEstLoc): namedtuple of int sn .s and qb64 digest .d of last est event
        delegated (bool): True means delegated identifier, False not delegated
        delgator (str): qb64 of delegator's prefix


    Properties:
        sn (int): sequence number property that returns .sner.num
        fn (int): first seen ordinal number property the returns .fner.num
        ndigs (list): of digests qb64 of .digers
        kevers (dict): reference to self.db.kevers
        transferable (bool): True if .digers is not empty and pre is transferable



    ToDo:
       Add Registrar Backer support:
        Class variable, instance variable and parse support config trait.
        raise error for now


    """
    EstOnly = False
    DoNotDelegate = False

    def __init__(self, *, state=None, serder=None, sigers=None, wigers=None,
                 db=None, estOnly=None, delseqner=None, delsaider=None, firner=None,
                 dater=None, cues=None, prefixes=None, local=False, check=False):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigers raises ValidationError if not

        Parameters:
            state (KeyStateRecord | None): instance for key state notice
            serder (SerderKERI | None): instance of inception event
            sigers (list | None): of Siger instances of indexed controller signatures
                of event. Index is offset into keys list from latest est event
            wigers (list | None): of Siger instances of indexed witness signatures of
                event. Index is offset into wits list from latest est event
            db (Baser | None): instance of lmdb database
            estOnly (bool | None): True means establishment only events allowed 'EO'.
                            False all events allowed.
            delseqner (Seqner | None): instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            delsaider (Saider | None): instance of of delegating event SAID.
                If this event is not delegated then saider is ignored
            firner (Seqner | None): instance optional of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater (Dater | None): optional instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
            cues (Deck | None): reference to Kevery.cues Deck when provided
                i.e. notices of events or requests to respond to
            prefixes (list | None): own prefixes for own local habitats.
                May not include the prefix of this Kever's event when inception
                has not yet been accepted into KEL
                Some restrictions if present
                If empty then effectively in promiscuous mode
            local (bool): True means only process msgs for own controller's
                              events if .prefixes is not empty.
                          False means only process msgs for not own events
                              if .prefixes is not empty
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

        ilk = serder.ilk # serder.ked["t"]
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
                                                        toader=self.toader,
                                                        wits=self.wits,
                                                        delseqner=delseqner,
                                                        delsaider=delsaider)

        self.delegator = delegator
        self.delegated = True if self.delegator else False

        wits = serder.backs  # serder.ked["b"]
        # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
        # all validated above so may add to KEL and FEL logs as first seen
        # returns fn == None if already logged fn log is non idempotent
        fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers, wits=wits,
                                first=True if not check else False,
                                seqner=delseqner, saider=delsaider,
                                firner=firner, dater=dater)
        if fn is not None:  # first is non-idempotent for fn check mode fn is None
            self.fner = Number(num=fn)
            self.dater = Dater(dts=dts)
            self.db.states.pin(keys=self.prefixer.qb64,
                               val=self.state())


    @property
    def sn(self):
        """
        Returns:
            (int): .sner.num
        """
        return self.sner.num


    @property
    def fn(self):
        """
        Returns:
            (int): .fner.num
        """
        return self.fner.num


    @property
    def ndigs(self):
        """
        Returns:
            (list): digs of digers
        """
        return [diger.qb64 for diger in self.ndigers]


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
        return True if self.ndigers and self.prefixer.transferable else False


    def locallyOwned(self, pre=''):
        """Returns True if pre is in .prefixes False otherwise. Indicates that
        provided identifier prefix is controlled by a local controller from
        .prefixes
        i.e pre is a locally owned (controlled) AID (identifier prefix)

        Parameters:
           pre (str): qb64 identifier prefix

        """
        return pre in self.prefixes


    def locallyWitnessed(self, serder=None):
        """Returns True if a local controller is a witness of this Kever's KEL
           of wits in serder of if None then current wits for this Kever.
           i.e.  self is witnessd by locally owned (controlled) AID (identifier prefix)

        Parameters:
           serder ( SerderKERI | None): SerderKERI instace if any

        """
        if serder and serder.pre != self.prefixer.qb64:  # same KEL as self
            return False
        wits = serder.backs if serder is not None else self.wits
        return (oset(self.prefixes) & oset(wits))


    def reload(self, state):
        """
        Reload Kever attributes (aka its state) from state (KeyStateRecord)

        Parameters:
            state (KeyStateRecord | None): instance for key state notice

        """
        self.version = Versionage._make(state.vn)
        self.prefixer = Prefixer(qb64=state.i)
        self.sner = Number(numh=state.s)  # sequence number Number instance hex str
        self.fner = Number(numh=state.f) # first seen ordinal Number hex str
        self.dater = Dater(dts=state.dt)
        self.ilk = state.et
        self.tholder = Tholder(sith=state.kt)
        self.ntholder = Tholder(sith=state.nt)
        self.verfers = [Verfer(qb64=key) for key in state.k]
        self.ndigers = [Diger(qb64=dig) for dig in state.n]
        self.toader = Number(numh=state.bt)  # auto converts from hex num
        self.wits = state.b
        self.cuts = state.ee.br
        self.adds = state.ee.ba
        self.estOnly = False
        self.doNotDelegate = True if TraitCodex.DoNotDelegate in state.c else False
        self.estOnly = True if TraitCodex.EstOnly in state.c else False
        self.lastEst = LastEstLoc(s=int(state.ee.s, 16),
                                  d=state.ee.d)
        self.delegator = state.di if state.di else None
        self.delegated = True if self.delegator else False

        if (raw := self.db.getEvt(key=dgKey(pre=self.prefixer.qb64,
                                            dig=state.d))) is None:
            raise MissingEntryError(f"Corresponding event not found for state="
                                    f"{state}.")
        self.serder = serdering.SerderKERI(raw=bytes(raw))
        # May want to do additional checks here


    def incept(self, serder, estOnly=None):
        """
        Verify incept key event message from serder


        Parameters:
            serder is SerderKERI instance of inception event
            estOnly is boolean  to indicate establish only events allowed
        """
        ked = serder.ked

        self.sner = serder.sner
        if self.sner.positive:
            raise ValidationError(f"Nonzero sn={self.sner.num} in inception event.")

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

        self.serder = serder  # need whole serder for digest agility comparisons

        ndigs = serder.ndigs # ked["n"]
        if not self.prefixer.transferable and ndigs:  # nxt must be empty for nontrans prefix
            raise ValidationError("Invalid inception next digest list not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))
        self.ndigers = serder.ndigers
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

        toader = Number(num=ked["bt"])  # auto converts hex num to int
        if wits:
            if toader.num < 1 or toader.num > len(wits):  # out of bounds toad
                raise ValueError(f"Invalid toad = {toader.num} for backers "
                                 f"(wits)={wits} for event={ked}.")
        else:
            if toader.num != 0:  # invalid toad
                raise ValueError(f"Invalid toad = {toader.num} for backers "
                                 "(wits)={wits} for event={ked}.")
        self.toader = toader

        data = ked["a"]
        if not self.prefixer.transferable and data:  # data must be empty for nontrans prefix
            raise ValidationError("Invalid inception data not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))


        # need this to recognize recovery events and transferable receipts
        # last establishment event location
        self.lastEst = LastEstLoc(s=self.sner.num, d=self.serder.said)


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

        cnfg = serder.traits # serder.ked["c"]  # process cnfg for traits
        if TraitDex.EstOnly in cnfg:
            self.estOnly = True
        if TraitDex.DoNotDelegate in cnfg:
            self.doNotDelegate = True


    def update(self, serder, sigers, wigers=None, delseqner=None, delsaider=None,
               firner=None, dater=None, check=False):
        """
        Not an inception event. Verify event serder and indexed signatures
        in sigers and update state

        Parameters:
            serder (SerderKERI): instance of  event
            sigers (list): of SigMat instances of indexed signatures of controller
                signatures of event. Index is offset into keys list from latest
                est event and when provided ondex is offset into key digest list
                from prior next est event to latest est event.
            wigers (list | None): of Siger instances of indexed witness signatures of
                event. Index is offset into wits list from latest est event
            delseqner (Seqner | None): instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            delsaider (Saider | None): instance of of delegating event said.
                If this event is not delegated then diger is ignored
            firner (Seqner | None): Seqner instance of cloned first seen ordinal
                If cloned mode then firner maybe provided (not None)
                When firner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater (Dater | None): Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
            check (bool): True means do not update the database in any
                non-idempotent way. Useful for reinitializing the Kevers from
                a persisted KEL without updating non-idempotent first seen .fels
                and timestamps.

        """
        ked = serder.ked
        if not self.transferable:  # not transferable so no further events allowed
            raise ValidationError("Unexpected event = {} is nontransferable "
                                  " or abandoned state.".format(ked))

        if serder.pre != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {} for evt = {}.".format(serder.pre,
                                                               self.prefixer.qb64,
                                                               ked))


        sner = serder.sner  # Number instance ensures whole number for sequence number
        ilk = serder.ilk # ked["t"]

        if ilk in (Ilks.rot, Ilks.drt):  # rotation (or delegated rotation) event
            if self.delegated and ilk != Ilks.drt:
                raise ValidationError("Attempted non delegated rotation on "
                                      "delegated pre = {} with evt = {}."
                                      "".format(serder.pre, ked))

            tholder, toader, wits, cuts, adds = self.rotate(serder)

            # Validates signers, delegation if any, and witnessing when applicable
            # returned sigers and wigers are verified signatures
            # If does not validate then escrows as needed and raises ValidationError
            sigers, delegator, wigers = self.valSigsDelWigs(serder=serder,
                                                            sigers=sigers,
                                                            verfers=serder.verfers,
                                                            tholder=tholder,
                                                            wigers=wigers,
                                                            toader=toader,
                                                            wits=wits,
                                                            delseqner=delseqner,
                                                            delsaider=delsaider)


            # rotation so check rotation threshold against exposed sigers versus
            # prior next digers in .ndigers
            #ondices = self.exposeds(sigers)
            #if not self.ntholder.satisfy(indices=ondices):
                #self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
                #if delseqner and delsaider:  # save in case not attached later
                    #self.escrowPACouple(serder=serder, seqner=delseqner, saider=delsaider)
                #raise MissingSignatureError(f"Failure satisfying nsith="
                                            #f"{self.ntholder.sith} on sigs="
                                            #f"{[siger.qb64 for siger in sigers]}"
                                            #f" for evt={serder.ked}.")


            # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
            # all validated above so may add to KEL and FEL logs as first seen
            fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers, wits=wits,
                                    first=True if not check else False, seqner=delseqner, saider=delsaider,
                                    firner=firner, dater=dater)

            # nxt and signatures verify so update state
            self.sner = sner  # sequence number Number instance
            self.serder = serder  # need whole serder for digest agility compare
            self.ilk = ilk
            self.tholder = tholder
            self.verfers = serder.verfers
            self.ndigers = serder.ndigers
            self.ntholder = serder.ntholder

            self.toader = toader
            self.wits = wits
            self.cuts = cuts
            self.adds = adds

            # last establishment event location need this to recognize recovery events
            self.lastEst = LastEstLoc(s=self.sner.num, d=self.serder.said)
            if fn is not None:  # first is non-idempotent for fn check mode fn is None
                self.fner = Number(num=fn)
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

            if not sner.num == (self.sner.num + 1):  # sn not in order
                raise ValidationError("Invalid sn = {} expecting = {} for evt "
                                      "= {}.".format(sner.num, self.sner.num + 1, ked))

            if not self.serder.compare(said=ked["p"]):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with state dig"
                                      " = {} for evt = {}.".format(ked["p"],
                                                                   self.serder.said,
                                                                   ked))

            # interaction event use keys, sith, toad, and wits from pre-existing Kever state

            # Validates signers, delegation if any, and witnessing when applicable
            # If does not validate then escrows as needed and raises ValidationError
            sigers, delegator, wigers = self.valSigsDelWigs(serder=serder,
                                                            sigers=sigers,
                                                            verfers=self.verfers,
                                                            tholder=self.tholder,
                                                            wigers=wigers,
                                                            toader=self.toader,
                                                            wits=self.wits)

            # .validateSigsDelWigs above ensures thresholds met otherwise raises exception
            # all validated above so may add to KEL and FEL logs as first seen
            fn, dts = self.logEvent(serder=serder, sigers=sigers, wigers=wigers,
                                    first=True if not check else False)  # First seen accepted

            # validates so update state
            self.sner = sner  # sequence number Number instance
            self.serder = serder  # need for digest agility includes .serder.diger
            self.ilk = ilk
            if fn is not None:  # first is non-idempotent for fn check mode fn is None
                self.fner = Number(num=fn)
                self.dater = Dater(dts=dts)
                self.db.states.pin(keys=self.prefixer.qb64, val=self.state())

        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))


    def rotate(self, serder):
        """
        Generic Rotate Operation Validation Processing
        Validates provisional rotation
        Same logic for both 'rot' and 'drt' (plain and delegated rotation)

        Returns: tuple (tholder, toader, wits, cuts, adds) of provisional  results
        of rotation subject to additional validation

        Parameters:
            serder (SerderKERI): instance of rotation ('rot' or 'drt') event.


        """
        ked = serder.ked
        sner = serder.sner
        pre = serder.pre  # ked["i"]  # controller AID prefix
        prior = serder.prior # ked["p"]  # prior event said
        ilk = serder.ilk

        if sner.num > self.sner.num + 1:  # out of order event
            raise ValidationError(f"Out of order event sn = {sner.num} expecting"
                                  f" = {self.sner.num + 1} for evt = {ked}.")

        elif sner.num <= self.sner.num:  # stale or recovery
            #  stale events could be duplicitous
            #  duplicity detection should have happend in Kevery before .update
            # and .rotate called so raise exception if stale
            # seems redundant but protects bare .update if not called by Kevery

            if ((ilk == Ilks.rot and sner.num <= self.lastEst.s) or
                (ilk == Ilks.drt and sner.num < self.lastEst.s)):  # stale  event
                    raise ValidationError("Stale event sn = {} expecting"
                                      " = {} for evt = {}.".format(sner.num,
                                                                   self.sner.num + 1,
                                                                   ked))

            else:  # recovery event rot sn > self.lastEst.s or drt sn = self.lastEst.s
                if ilk == Ilks.rot and self.ilk != Ilks.ixn:  # rot recovery  may only override ixn state
                    raise ValidationError("Invalid recovery attempt: Recovery"
                                          "at ilk = {} not ilk = {} for evt"
                                          " = {}.".format(self.ilk,
                                                          Ilks.ixn,
                                                          ked))

                psn = sner.num - 1  # use sn of prior event to fetch prior event
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
                pserder = serdering.SerderKERI(raw=bytes(praw))  # deserialize prior event raw
                if not pserder.compare(said=prior):  # bad recovery event
                    raise ValidationError("Invalid recovery attempt:"
                                          "Mismatch recovery event prior dig"
                                          "= {} with dig = {} of event sn = {}"
                                          " evt = {}.".format(prior,
                                                              pserder.said,
                                                              psn,
                                                              ked))

        else:  # sn == self.sn + 1   new non-recovery event
            if not self.serder.compare(said=prior):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with"
                                      " state dig = {} for evt = {}."
                                      "".format(prior, self.serder.said, ked))

        # check derivation code of pre for non-transferable
        if not self.ndigers:  # prior next list is empty so rotations not allowed
            raise ValidationError("Attempted rotation for nontransferable"
                                  " prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))

        tholder = serder.tholder  # Tholder(sith=ked["kt"])  #  parse sith into Tholder instance
        keys = serder.keys # event's keys ked["k"]
        if len(keys) < tholder.size:
            raise ValidationError(f"Invalid sith = {serder.tholder} for keys = "
                                  f"{keys} for evt = {ked}.")



        # compute wits from existing .wits with new cuts and adds from event
        # use ordered set math ops to verify and ensure strict ordering of wits
        # cuts and add to ensure that indexed signatures on indexed witness
        # receipts work
        witset = oset(self.wits)
        cuts = serder.cuts # ked["br"]
        cutset = oset(cuts)
        if len(cutset) != len(cuts):
            raise ValidationError("Invalid cuts = {}, has duplicates for evt = "
                                  "{}.".format(cuts, ked))

        if (witset & cutset) != cutset:  # some cuts not in wits
            raise ValidationError("Invalid cuts = {}, not all members in wits"
                                  " for evt = {}.".format(cuts, ked))

        adds = serder.adds # ked["ba"]
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

        toader = serder.bner # Number(num=ked["bt"])  # auto converts hex num to int
        if wits:
            if toader.num < 1 or toader.num > len(wits):  # out of bounds toad
                raise ValueError(f"Invalid toad = {toader.num} for backers "
                                 f"(wits)={wits} for event={ked}.")
        else:
            if toader.num != 0:  # invalid toad
                raise ValueError(f"Invalid toad = {toader.num} for backers "
                                 "(wits)={wits} for event={ked}.")

        return tholder, toader, wits, cuts, adds


    def valSigsDelWigs(self, serder, sigers, verfers, tholder,
                       wigers, toader, wits,
                       delseqner=None, delsaider=None):
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
            serder (SerderKERI): instance of event
            sigers (list): of Siger instances of indexed controllers signatures.
                Index is offset into verfers list from which public key may be derived.
            verfers (list): of Verfer instances of keys from latest est event
            tholder (Tholder): instance of sith threshold
            wigers (list): of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.
            toader (Number): instance of backer witness threshold
            wits (list): of qb64 non-transferable prefixes of witnesses used to
                derive werfers for wigers
            delseqner (Seqner | None): instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            delsaider (Saider | None): instance of of delegating event said.
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

        # check if minimally signed in order to continue processing
        if not indices:  # must have a least one verified sig
            raise ValidationError("No verified signatures for evt = {}."
                                  "".format(serder.ked))

        werfers = [Verfer(qb64=wit) for wit in wits]  # get witnes signatures

        # get unique verified wigers and windices lists from wigers list
        wigers, windices = verifySigs(raw=serder.raw, sigers=wigers, verfers=werfers)
        # each wiger now has added to it a werfer of its wit in its .verfer property

        # escrow if not fully signed vs threshold
        if not tholder.satisfy(indices):  # at least one but not enough
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            if delseqner and delsaider:
                self.escrowPACouple(serder=serder, seqner=delseqner, saider=delsaider)
            raise MissingSignatureError(f"Failure satisfying sith = {tholder.sith}"
                                        f" on sigs for {[siger.qb64 for siger in sigers]}"
                                        f" for evt = {serder.ked}.")

        if serder.ilk in (Ilks.rot, Ilks.drt):  # rotation so check prior next threshold
            # prior next threshold in .ntholder and digers in .ndigers
            ondices = self.exposeds(sigers)
            if not self.ntholder.satisfy(indices=ondices):
                self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
                if delseqner and delsaider:  # save in case not attached later
                    self.escrowPACouple(serder=serder, seqner=delseqner, saider=delsaider)
                raise MissingSignatureError(f"Failure satisfying prior nsith="
                                            f"{self.ntholder.sith} with exposed "
                                            f"sigs= {[siger.qb64 for siger in sigers]}"
                                            f" for new est evt={serder.ked}.")


        delegator = self.validateDelegation(serder, sigers=sigers, wigers=wigers,
                                            delseqner=delseqner, delsaider=delsaider)

        # Kevery .process event logic does not prevent this from seeing event when
        # not local and event pre is own pre
        if not self.locallyOwned(serder.pre):  # not in self.prefixes
            if ((wits and not self.prefixes) or  # in promiscuous mode so assume must verify toad
                    (wits and self.prefixes and not self.local and  # not promiscuous nonlocal
                     not (oset(self.prefixes) & oset(wits)))):  # own prefix is not a witness
                # validate that event is fully witnessed

                if wits:
                    if toader.num < 1 or toader.num > len(wits):  # out of bounds toad
                        raise ValidationError(f"Invalid toad = {toader.num} for wits = {wits}")
                else:
                    if toader.num != 0:  # invalid toad
                        raise ValidationError(f"Invalid toad = {toader.num} for wits = {wits}")

                if len(windices) < toader.num:  # not fully witnessed yet
                    if self.escrowPWEvent(serder=serder, wigers=wigers, sigers=sigers,
                                          seqner=delseqner, saider=delsaider):
                        # cue to query for witness receipts
                        self.cues.push(dict(kin="query", q=dict(pre=serder.pre, sn=serder.snh)))
                    raise MissingWitnessSignatureError(f"Failure satisfying toad={toader.num} "
                                                       f"on witness sigs="
                                                       f"{[siger.qb64 for siger in wigers]} "
                                                       f"for event={serder.ked}.")


        return sigers, delegator, wigers


    def exposeds(self, sigers):
        """Returns list of ondices (indices) suitable for Tholder.satisfy
        from self.ndigers (prior next key digests ) as exposed by event sigers.
        Uses dual index feature of siger. Assumes that each siger.verfer is
        from the correct key given by siger.index and the signature has been verified.

        A key given by siger.verfer (at siger.index in the current key list)
        may expose a prior next key hidden by the diger at siger.ondex in .digers.

        Each returned ondex must be properly exposed by a siger in sigers
        such that the siger's indexed key given by siger.verfer matches the
        siger's ondexed digest from digers.

        The ondexed digest's code is used to compute the digest of the corresponding
        indexed key verfer to verify that they match. This supports crypto agility
        for different digest codes, i.e. all digests in .digers may use a different
        algorithm.

        Only ondices from properly matching key and digest are returned.

        Used to extract the indices from the list of prior next digests .digers
        exposed by the signatures (sigers) on a rotation event of the newly
        current keys given by each .verfer at .index from sigers. Only checks
        keys and digests that correspond to provided signatures not all keys and
        digests defined by the rotation event.

        Parameters:
            sigers (list): of Siger instances  of indexed signature with .verfer
        """
        odxs = []
        for siger in sigers:
            try:
                diger = self.ndigers[siger.ondex]
            except TypeError as ex:  # ondex may be None
                continue
            except IndexError as ex:
                continue
                #raise ValidationError(f'Invalid ondex={siger.ondex} '
                                      #f'to expose digest.') from ex

            kdig = Diger(ser=siger.verfer.qb64b, code=diger.code).qb64
            if kdig == diger.qb64:
                odxs.append(siger.ondex)

        return odxs


    def validateDelegation(self, serder, sigers, wigers=None, delseqner=None, delsaider=None):
        """
        Returns delegator's qb64 identifier prefix if validation successful.
        Rules:
            If event is not a delegated event then not valid delegation
            If delegatee's own event (.mine) then valid delegation
            If delegation seal found in delgator's KEL then valid delegation given
                valid superseding rules below
            Otherwise escrow or reject if error condition

        seal validates with respect to Delegator's KEL
        Location Seal is from Delegate's establishment event
        Assumes state setup

        Parameters:
            serder (SerderKERI): instance of delegated event serder
            sigers (list): of Siger instances of indexed controller sigs of
                delegated event. Assumes sigers is list of unique verified sigs
            wigers (list | None): of optional Siger instance of indexed witness sigs of
                delegated event. Assumes wigers is list of unique verified sigs
            delseqner (Seqner | None): instance of delegating event sequence number.
                If this event is not delegated then ignored
            delsaider (Saider | None): instance of of delegating event digest.
                If this event is not delegated ignored

        Returns:
            (str | None): qb64 delegator prefix or None if not delegated

        Superseding Recovery

        Supersede means that after an event has already been accepted as first seen
        into a KEL that a different event with the same sequence number is accepted
        that supersedes the pre-existing event at that sn. This enables the recovery of
        events signed by compromised keys. The result of superseded recovery is that
        the KEL is forked at the sn of the superseding event. All events in the
        superseded branch of the fork still exist but, by virtue of being superseded,
        are disputed. The set of superseding events in the superseding fork forms the authoritative
        branch of the KEL. All the already seen superseded events in the superseded fork
        still remain in the KEL and may be viewed in order of their original acceptance
        because the database stores all accepted events in order of acceptance and
        denotes this order using the first seen ordinal number, fn.
        The fn is not the same as the sn (sequence number).
        Each event accepted into a KEL has a unique fn but multiple events due to
        recovery forks may share the same sn.


        Superseding Rules for Recovery at given SN (sequence number)

        A0. Any rotation event may supersede an interaction event at the same sn. (existing rule)
        A1. A non-delegated rotation may not supersede another rotation at the same sn.  (modified rule)
        A2. An interaction event may not supersede any event. ( existing rule).

        (B. and C. below provide the new rules)

        B.  A delegated rotation may supersede another delegated rotation at the same sn
        under either of the following conditions:
            B1.  The superseding rotation's delegating event is later than
            the superseded rotation's delegating event in the delegator's KEL, i.e. the
            sn of the superseding event's delegation is higher than the superseded event's
            delegation.
            B2. The sn of the superseding rotation's delegating event is the same as
            the sn of the superseded rotation's delegating event in the delegator's KEL
            and the superseding rotation's delegating event is a rotation and the
            superseded rotation's delegating event is an interaction,
            i.e. the superseding rotation's delegating event is itself a superseding
            rotation of the superseded rotations delegating interaction event in the
            delgator's KEL

        C. IF Neither A nor B is satisfied, then recursively apply rules A. and B. to
        the delegating events of those delegating events and so on until either  A. or B.
        is satisfied, or the root KEL of the delegation has been reached.
          C1. If neither A. nor B. is satisfied by recursive application on the
          delegator's KEL (i.e. the root KEL of the delegation has been reached without
          satisfaction) then the superseding rotation is discarded. The terminal case of
          the recursive application will occur at the root KEL which by defintion is
          non-delegated wherefore either A. or B. must be satisfied, or else the
          superseding rotation must be discarded.

        """
        if serder.ilk not in (Ilks.dip, Ilks.drt):  # not delegated
            return None  # delegator is None

        # verify delegator and attachment pointing to delegating event
        if serder.ilk == Ilks.dip:
            delegator = serder.delpre  # delegator from dip event
            if not delegator:
                raise ValidationError(f"Empty or missing delegator for delegated"
                                      f" inception event = {serder.ked}.")
        else:  # serder.ilk == Ilks.drt so rotation
            delegator = self.delegator


        # if we are the delegatee, accept the event without requiring the
        # delegator validation via an anchored delegation seal or by requiring
        # it to be witnessed
        # ToDo XXXX add local lax check after figure out dist multisig group
        # ToDo XXXX add check for witness to accept so that witness will
        # add to its KEL without waiting for delegation seal to be anchored in
        # delegator's KEL  witness cue in Kevery will then generate reciept
        if self.locallyOwned(serder.pre) or self.locallyWitnessed(serder=serder):
            return delegator

        # during initial delegation we just escrow the delcept event
        if delseqner is None and delsaider is None and delegator is not None:
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            raise MissingDelegationError("No delegation seal for delegator {} "
                                         "with evt = {}.".format(delegator, serder.ked))

        ssn = validateSN(sn=delseqner.snh, inceptive=False)  # delseqner Number should already do this
        #ssn = sner.num sner is Number seqner is Seqner need to replace Seqners with Numbers

        # get the dig of the delegating event. Using getKeLast ensures delegating
        #  event has not already been superceded
        key = snKey(pre=delegator, sn=ssn)  # database key
        raw = self.db.getKeLast(key)  # get dig of delegating event

        if raw is None:  # no delegating event at key pre, sn
            # ToDo XXXX create cue to send query to fetch delegating event from
            # delegator
            self.cues.push(dict(kin="query", q=dict(pre=delegator,
                                                              sn=delseqner.snh,
                                                              dig=delsaider.qb64)))

            #  escrow event here
            inceptive = True if serder.ilk in (Ilks.icp, Ilks.dip) else False
            sn = validateSN(sn=serder.snh, inceptive=inceptive)
            self.escrowPSEvent(serder=serder, sigers=sigers, wigers=wigers)
            self.escrowPACouple(serder=serder, seqner=delseqner, saider=delsaider)
            raise MissingDelegationError("No delegating event from {} at {} for "
                                         "evt = {}.".format(delegator,
                                                            delsaider.qb64,
                                                            serder.ked))

        # get the delegating event from dig
        ddig = bytes(raw)
        key = dgKey(pre=delegator, dig=ddig)  # database key
        raw = self.db.getEvt(key)
        if raw is None:   # drop event
            raise ValidationError("Missing delegation from {} at event dig = {} for evt = {}."
                                  "".format(delegator, ddig, serder.ked))

        dserder = serdering.SerderKERI(raw=bytes(raw))  # delegating event
        # compare digests to make sure they match here
        if not dserder.compare(said=delsaider.qb64):  # drop event
            raise ValidationError("Invalid delegation from {} at event dig = {} for evt = {}."
                                  "".format(delegator, ddig, serder.ked))

        if self.kevers is None or delegator not in self.kevers:   # drop event
            raise ValidationError("Missing Kever for delegator = {} for evt = {}."
                                  "".format(delegator, serder.ked))

        dkever = self.kevers[delegator]
        if dkever.doNotDelegate:  # drop event
            raise ValidationError("Delegator = {} for evt = {},"
                                  " does not allow delegation.".format(delegator,
                                                                       serder.ked))


        found = False  # find event seal of delegated event in delegating data
        # XXXX ToDo need to change logic here to support native CESR seals not just dicts
        # for JSON, CBOR, MGPK
        for dseal in dserder.seals:  # find delegating seal anchor
            if tuple(dseal.keys()) == SealEvent._fields:
                seal = SealEvent(**dseal)
                if (seal.i == serder.pre and
                    seal.s == serder.sner.numh and
                    serder.compare(said=seal.d)):
                        found = True
                        break

        if not found:  # drop event
            raise ValidationError("Missing delegation from {} in {} for evt = {}."
                                  "".format(delegator, dserder.seals, serder.ked))

        # Assumes database is reverified each bootup chain-of-custody of dic broken.
        # Rule for non-supeding delegated rotation of rotation.
        # Returning delegator indicates success and eventually results acceptance
        # via Kever.logEvent which also writes the delgating event source couple to
        # db.aess so we can find it later
        if ((serder.ilk == Ilks.dip) or  # delegated inception
            (serder.sner.num == self.sner.num + 1) or  # inorder event
            (serder.sner.num == self.sner.num and
                self.ilk == Ilks.ixn and
                serder.ilk == Ilks.drt)):  # recovery rotation superseding ixn
                    return delegator  # indicates delegation valid with return of delegator

        # Kever.logEvent saves authorizer (delegator) seal source couple in
        # db.aess data base so can use it here to recusively look up delegating
        # events

        # set up recursive search for superseding delegations
        serfn = serder  # new potentially superseding delegated event i.e. serf new
        bossn = dserder # new delegating event of superseding delegated event i.e. boss new
        serfo = self.serder  # original delegated event i.e. serf original
        bosso = self.fetchDelegatingEvent(delegator, serfo)

        while (True):  # superseding delegated rotation of rotation recovery rules
            # Only get to here if same sn for drt existing and drt superseding

            if (bossn.sn > bosso.sn or  # later supersedes
                (bossn.Ilk == Ilks.drt and
                 bosso.Ilk == Ilks.ixn) ): # drt supersedes ixn
                    return delegator  # valid superseding delegation

            if bossn.said == bosso.said: # same delegating event
                nseals = [SealEvent(**seal) for seal in bossn.seals
                                  if tuple(seal.keys()) == SealEvent._fields]
                nindex = nseals.index(SealEvent(i=serfn.pre, s=serfn.snh, d=serfn.said))
                oseals = [SealEvent(**seal) for seal in bosso.seals
                                      if tuple(seal.keys()) == SealEvent._fields]
                oindex = oseals.index(SealEvent(i=serfo.pre, s=serfo.snh, d=serfo.said))

                if nindex > oindex:  # later seal supersedes
                    # assumes index can't be None
                    return delegator  # valid superseding delegation

                else:
                    # ToDo: XXXX may want to cue up business logic for delegator
                    # if self.mine(delegator):  # failed attempt at recovery
                    raise ValidationError(f"Invalid delegation recovery rotation"
                                          f"of {serfo.ked} by {serfn.ked}")

            # tie condition same sn and drt so need to climb delegation chain
            serfn = bossn
            bossn = self.fetchDelegatingEvent(delegator, serfn)
            serfo = bosso
            bosso = self.fetchDelegatingEvent(delegator, serfo)
            # repeat


    def fetchDelegatingEvent(self, delegator, serder):
        """Returns delegating event by delegator of delegated event given by
        serder otherwise raises ValidationError.
        Assumes serder is already delegated event

        Parameters:
            delegator (str): qb64 of identifier prefix of delegator
            serder (SerderKERI): delegated serder

        """
        dgkey = dgKey(pre=serder.preb, dig=serder.saidb)  # database key
        if (couple := self.db.getAes(dgkey)):  # delegation source couple
            seqner, saider = deSourceCouple(couple)
            dgkey = dgKey(pre=delegator, dig=saider)  # event at its said
            # get event by dig not by sn at last event because may have been superceded
            if not (raw := self.db.getEvt(dgkey)):
                # database broken this should never happen so do not supersede
                raise ValidationError(f"Missing delegation event for {serder.ked}")

            dserder = serdering.SerderKERI(raw=bytes(raw))  # original delegating event i.e. boss original

        else:  #try to find seal the hard way
            seal = SealEvent(i=serder.pre, s=serder.snh, d=serder.said)._asdict
            if not (dserder := self.db.findAnchoringSealEvent(pre=serder.delpre, seal=seal)):
                # database broken this should never happen so do not supersede
                raise ValidationError(f"Missing delegation source seal for {serder.ked}")

        return dserder


    def logEvent(self, serder, sigers=None, wigers=None, wits=None, first=False,
                 seqner=None, saider=None, firner=None, dater=None):
        """
        Update associated logs for verified event.
        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            serder is SerderKERI instance of current event
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
        fn = None  # None means not a first seen log event so does not return an fn
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
        val = (coring.Prefixer(qb64b=serder.preb), coring.Seqner(sn=serder.sn))
        for verfer in (serder.verfers if serder.verfers is not None else []):
            self.db.pubs.add(keys=(verfer.qb64,), val=val)
        for diger in (serder.ndigers if serder.ndigers is not None else []):
            self.db.digs.add(keys=(diger.qb64,), val=val)
        if first:  # append event dig to first seen database in order
            if seqner and saider:  # delegation for authorized delegated or issued event
                couple = seqner.qb64b + saider.qb64b
                self.db.setAes(dgkey, couple)  # authorizer (delegator/issuer) event seal
            fn = self.db.appendFe(serder.preb, serder.saidb)
            if firner and fn != firner.sn:  # cloned replay but replay fn not match
                if self.cues is not None:  # cue to notice BadCloneFN
                    self.cues.push(dict(kin="noticeBadCloneFN", serder=serder,
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
            serder is SerderKERI instance of event
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
            serder is SerderKERI instance of delegated or issued event
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
            serder is SerderKERI instance of  event
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


    def state(self):
        """
        Returns KeyStateRecord instance of current key state

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
                      sn=self.sn, # property self.sner.num
                      pig=(self.serder.prior if self.serder.prior is not None else ""),
                      dig=self.serder.said,
                      fn=self.fn, # property self.fner.num
                      stamp=self.dater.dts,  # need to add dater object for first seen dts
                      eilk=self.ilk,
                      keys=[verfer.qb64 for verfer in self.verfers],
                      eevt=eevt,
                      sith=self.tholder.sith,
                      nsith=self.ntholder.sith if self.ntholder else '0',
                      ndigs=[diger.qb64 for diger in self.ndigers],
                      toad=self.toader.num,
                      wits=self.wits,
                      cnfg=cnfg,
                      dpre=self.delegator,
                      )
                )


    def fetchPriorDigers(self, sn: int | None = None) -> list | None:
        """ Returns either the most recent prior list of digers before .lastEst or None

        Starts searching at sn or if sn is None at sn = .lastEst.s - 1

        Returns list of Digers instances at the most recent prior est event relative
        to the given sequence number (sn) otherwise returns None.
        Walks backwards to the more recent prior establishment event before the
        .sn if any.
        If sn represents an interaction event (ixn) then the result will be the
        current valid list of digers. If sn represents an establishment event then
        the result will be the list of digers immediately prior to the current list.

        Parameters:
          sn (int | None): sn to start searching. If None then start at .lastEst.s - 1

        Returns:
            digers (list | None): of Diger instances or None if no prior est evt
                to current .lastEst

        """
        pre = self.prefixer.qb64
        if sn is None:
            sn = self.lastEst.s - 1

        for digb in self.db.getKelBackIter(pre, sn):
            dgkey = dgKey(pre, digb)
            raw = self.db.getEvt(dgkey)
            serder = serdering.SerderKERI(raw=bytes(raw))
            if serder.estive:  # establishment event
                return serder.ndigers

        return None


    def fetchLatestContribTo(self, verfers, sn: int | None = None):
        """ Returns tuple of (sn, index, verfer) from latest est event whose
        verfer is found in verfers at index offset else None if not found.
        Fetches latest event sn and associated index and verfer that contributed
        to the provided verfers at index.

        Starts searching at sn or if sn is None at sn = .lastEst.s

        Returns tuple (sn, index, verfer) from the latest est event that matches by
        starting at the given sequence number (sn) and walking backwards
        otherwise returns None.

        If given sn represents an interaction event (ixn) then a latest possible
        matching result may be from an event that is no later than the last est
        event prior to that interaction event.
        If the sn represents an establishment event then the latest possible
        matching result may be from that event.

        Parameters:
          verfers (list[Verfer]): of verfer instances
          sn (int | None): sn to start searching. If None then start at .lastEst.s

        Returns:
            tuple(int, int,Verfer) | None: where tuple is of form (sn, idx, verfer).
                sn is sequence number.
                idx is index of verfer in verfers
                verfer is instance of Verfer

        """
        pre = self.prefixer.qb64
        if sn is None:
            sn = self.lastEst.s

        keys = [verfer.qb64 for verfer in verfers]

        for digb in self.db.getKelBackIter(pre, sn):
            dgkey = dgKey(pre, digb)
            raw = self.db.getEvt(dgkey)
            serder = serdering.SerderKERI(raw=bytes(raw))
            if serder.estive:  # establishment event
                key = serder.verfers[0].qb64
                try:
                    i = keys.index(key)  # find index of key in keys
                except ValueError:  # not found
                    continue

                return (serder.sn, i, serder.verfers[0])

        return None


    def fetchLatestContribFrom(self, verfer, sn: int | None = None):
        """ Returns tuple of  form (sn, index, verfers) where verfers is a list of
        verfers from latest est event where verfer is found in that event's
        verfers at index offset else None if not found.
        Fetches latest event sn and associated verfers list that recieved a
        contribution from the provided verfer at index.

        Starts searching at sn or if sn is None at sn = .lastEst.s

        Returns tuple (sn, index, list[verfers]) from the latest est event that
        matches by starting at the given sequence number (sn) and walking backwards
        otherwise returns None.

        If given sn represents an interaction event (ixn) then a latest possible
        matching result may be from an event that is no later than the last est
        event prior to that interaction event.
        If the sn represents an establishment event then the latest possible
        matching result may be from that event.

        Parameters:
          verfer (Verfer): instance of verfer
          sn (int | None): sn to start searching. If None then start at .lastEst.s

        Returns:
            tuple(int, int, list[Verfer]) | None: where tuple is of form
            (sn, index, verfers)
                sn is sequence number
                index is index into verfers of verfers
                verfers is list of Verfer instances.

        """
        pre = self.prefixer.qb64
        if sn is None:
            sn = self.lastEst.s

        key = verfer.qb64

        for digb in self.db.getKelBackIter(pre, sn):
            dgkey = dgKey(pre, digb)
            raw = self.db.getEvt(dgkey)
            serder = serdering.SerderKERI(raw=bytes(raw))
            if serder.estive:  # establishment event
                keys = [verfer.qb64 for verfer in serder.verfers]
                try:
                    i = keys.index(key) # find index of key in keys
                except ValueError:  # not found
                    continue

                return (serder.sn, i, serder.verfers)

        return None



class Kevery:
    """
    Kevery (Key Event Message Processing Facility) processes an incoming
    message stream composed of KERI key event related messages and attachments.
    Kevery acts a Kever (key event verifier) factory for managing key state of
    KERI identifier prefixes.

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
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

    def __init__(self, *, cues=None, db=None, rvy=None,
                 lax=True, local=False, cloned=False, direct=True, check=False):
        """
        Initialize instance:

        Parameters:
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
            serder = serdering.SerderKERI(raw=bytes(raw))
            if serder.estive:
                wits = self.db.wits.get(dgkey)
                return wits

        return []


    def processEvent(self, serder, sigers, *, wigers=None,
                     delseqner=None, delsaider=None,
                     firner=None, dater=None):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:
            serder is SerderKERI instance of event to process
            sigers is list of Siger instances of attached controller indexed sigs
            wigers is optional list of Siger instances of attached witness indexed sigs
            delseqner is Seqner instance of delegating event sequence number.
                If this event is not delegated then seqner is ignored
            delsaider is Saider instance of of delegating event SAID.
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
        pre = serder.pre
        ked = serder.ked

        # See todo for Prefixer fix redundancy XXX
        try:  # see if code of pre is supported and matches size of pre
            Prefixer(qb64=pre)
        except Exception as ex:  # if unsupported code or bad size raises error
            raise ValidationError("Invalid pre = {} for evt = {}."
                                  "".format(pre, ked)) from ex

        sn = serder.sn
        ilk = serder.ilk # ked["t"]
        said = serder.said


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
                              delseqner=delseqner,
                              delsaider=delsaider,
                              firner=firner if self.cloned else None,
                              dater=dater if self.cloned else None,
                              cues=self.cues,
                              prefixes=self.prefixes,
                              local=self.local,
                              check=self.check)
                self.kevers[pre] = kever  # not exception so add to kevers

                if self.direct or self.lax or pre not in self.prefixes:  # not own event when owned
                    # create cue for receipt  controller or watcher
                    #  receipt of actual type is dependent on own type of identifier
                    self.cues.push(dict(kin="receipt", serder=serder))
                elif not self.direct:  # notice of new  event
                    self.cues.push(dict(kin="notice", serder=serder))

                if kever.locallyWitnessed():
                    # ToDo XXXX  need to cue task here kin = "witness"
                    self.cues.push(dict(kin="witness", serder=serder))

                if kever.locallyOwned(kever.delegator):  # delegator may be None
                    # ToDo XXXX  need to cue task here  to approve delegation by generating
                    # and anchoring SealEvent of serder in delegators KEL
                    # may include MFA business logic for the delegator i.e. is local
                    self.cues.push(dict(kin="approveDelegation",
                                            delegator=kever.delegator,
                                            serder=serder))


            else:  # not inception so can't verify sigs etc, add to out-of-order escrow
                self.escrowOOEvent(serder=serder, sigers=sigers,
                                   seqner=delseqner, saider=delsaider, wigers=wigers)
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
                                                  verfers=eserder.berfers)

                    if sigers or wigers:  # at least one verified sig or wig so log evt
                        # this allows late arriving witness receipts or controller
                        # signatures to be added to the databse
                        # not first seen inception so ignore return
                        kever.logEvent(serder, sigers=sigers, wigers=wigers)  # idempotent update db logs

                else:  # escrow likely duplicitous event
                    self.escrowLDEvent(serder=serder, sigers=sigers)
                    raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))

            else:  # rot, drt, or ixn, so sn matters
                kever = self.kevers[pre]  # get existing kever for pre
                sno = kever.sner.num + 1  # proper sn of new inorder event

                if sn > sno:  # sn later than sno so out of order escrow
                    # escrow out-of-order event
                    self.escrowOOEvent(serder=serder, sigers=sigers,
                                       seqner=delseqner, saider=delsaider, wigers=wigers)
                    raise OutOfOrderError("Out-of-order event={}.".format(ked))

                elif ((sn == sno) or  # inorder event (ixn, rot, drt) or
                      (ilk == Ilks.rot and  # superseding recovery rot or
                        kever.lastEst.s < sn <= sno) or
                      (ilk == Ilks.drt and # delegated superseding recovery drt
                        kever.lastEst.s <= sn <= sno)):

                    # verify signatures etc and update state if valid
                    # raise exception if problem.
                    # Otherwise adds to KELs
                    kever.update(serder=serder, sigers=sigers, wigers=wigers,
                                 delseqner=delseqner, delsaider=delsaider,
                                 firner=firner if self.cloned else None,
                                 dater=dater if self.cloned else None,
                                 check=self.check)

                    if self.direct or self.lax or pre not in self.prefixes:  # not own event when owned
                        # create cue for receipt  controller or watcher
                        #  receipt of actual type is dependent on own type of identifier
                        self.cues.push(dict(kin="receipt", serder=serder))
                    elif not self.direct:  # notice of new  event
                        self.cues.push(dict(kin="notice", serder=serder))

                    if kever.locallyWitnessed():
                        # ToDo XXXX  need to cue task here kin = "witness"
                        self.cues.push(dict(kin="witness", serder=serder))

                    if kever.locallyOwned(kever.delegator):  # delegator may be None
                        # ToDo XXXX  need to cue task here  to approve delegation by generating
                        # and anchoring SealEvent of serder in delegators KEL
                        # may include MFA business logic   for the delegator i.e. is local
                        self.cues.push(dict(kin="approveDelegation",
                                            delegator=kever.delegator,
                                            serder=serder))


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
            serder is SerderKERI instance of serialized receipt message not receipted event
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
            lserder = serdering.SerderKERI(raw=raw)  # deserialize event raw

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
            serder is SerderKERI instance of serialized receipt message not receipted message
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
            lserder = serdering.SerderKERI(raw=raw)  # deserialize event raw

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
            serder is SerderKERI instance of receipted serialized event message
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
        lserder = serdering.SerderKERI(raw=bytes(lraw))
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
            sserder = serdering.SerderKERI(raw=bytes(sraw))
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
                sserder = serdering.SerderKERI(raw=bytes(sraw))
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
            serder (SerderKERI): instance of reply msg (SAD)
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
        data = serder.ked['a']

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
        if osaider is not None and osaider.qb64b == saider.qb64b: # check idempotent
            osaider = None
        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=osaider, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified end role reply. {serder.ked}")

        self.updateEnd(keys=keys, saider=saider, allowed=allowed)  # update .eans and .ends

    def processReplyLocScheme(self, *, serder, saider, route,
                              cigars=None, tsgs=None):
        """
        Process one reply message for route = /loc/scheme with either
        attached nontrans receipt couples in cigars or attached trans indexed
        sig groups in tsgs.
        Assumes already validated saider, dater, and route from serder.ked

        Parameters:
            serder (SerderKERI): instance of reply msg (SAD)
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
            raise UnverifiedReplyError(f"Unverified loc scheme reply. {serder.ked}")

        self.updateLoc(keys=keys, saider=saider, url=url)  # update .lans and .locs

    def processReplyKeyStateNotice(self, *, serder, saider, route,
                                   cigars=None, tsgs=None, **kwargs):
        """ Process one reply message for key state = /ksn

        Process one reply message for key state = /ksn
        with either attached nontrans receipt couples in cigars or attached trans
        indexed sig groups in tsgs.
        Assumes already validated saider, dater, and route from serder.ked

        Parameters:
            serder (SerderKERI): instance of reply msg (SAD)
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
        try:
            ksr = KeyStateRecord._fromdict(d=data)
        except Exception as ex:
            raise ValidationError(f"Malformed key state notice = {data}.") from ex

        # fetch from serder to process
        pre = ksr.i
        sn = int(ksr.s, 16)

        # check source and ensure we should accept it
        baks = ksr.b
        wats = set()
        for _, habr in self.db.habs.getItemIter():
            wats |= set(habr.watchers)

        # not in promiscuous mode
        if not self.lax:
            if aid != ksr.i and \
                    aid not in baks and \
                    aid not in wats:
                raise kering.UntrustedKeyStateSource("key state notice for {} from untrusted source {} "
                                                     .format(ksr.pre, aid))

        if ksr.i in self.kevers:
            kever = self.kevers[ksr.i]
            if int(ksr.s, 16) < kever.sner.num:
                raise ValidationError("Skipped stale key state at sn {} for {}."
                                      "".format(int(ksr.s, 16), ksr.i))

        keys = (pre, aid,)
        osaider = self.db.knas.get(keys=keys)  # get old said if any
        dater = coring.Dater(dts=ksr.dt)

        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=osaider, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified key state notice reply. {serder.ked}")

        ldig = self.db.getKeLast(key=snKey(pre=pre, sn=sn))  # retrieve dig of last event at sn.
        diger = coring.Diger(qb64=ksr.d)

        # Only accept key state if for last seen version of event at sn
        if ldig is not None:  # escrow because event does not yet exist in database
            ldig = bytes(ldig)
            # retrieve last event itself of signer given sdig
            sraw = self.db.getEvt(key=dgKey(pre=pre, dig=ldig))
            # assumes db ensures that sraw must not be none because sdig was in KE
            sserder = serdering.SerderKERI(raw=bytes(sraw))

            if not sserder.compare(said=diger.qb64b):  # mismatch events problem with replay
                raise ValidationError(f"Mismatch keystate at sn = {int(ksr.s,16)}"
                                      f" with db.")

        ksaider = coring.Saider(qb64=diger.qb64)
        self.updateKeyState(aid=aid, ksr=ksr, saider=ksaider, dater=dater)
        self.cues.push(dict(kin="keyStateSaved", ksn=ksr._asdict()))

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

    def updateKeyState(self, aid, ksr, saider, dater):
        """
        Update Reply SAD in database given by by serder and associated databases
        for attached cig couple or sig quadruple.
        Overwrites val at key if already exists.

        Parameters:
            aid (str): identifier of key state
            ksr (KeyStateRecord): converted from key state notice dict in reply msg
            saider (Saider): instance  from said in serder (SAD)
            dater (Dater): instance from date-time in serder (SAD)
        """
        keys = (saider.qb64,)

        # Add source of ksn to the key for DATEs too...  (source AID, ksn AID)
        self.db.kdts.put(keys=keys, val=dater)  # first one idempotent
        self.db.ksns.pin(keys=keys, val=ksr)  # first one idempotent
        # Add source of ksr to the key...  (ksr AID, source aid)
        self.db.knas.pin(keys=(ksr.i, aid), val=saider)  # overwrite

    def removeKeyState(self, saider):
        if saider:
            keys = (saider.qb64,)

            self.db.ksns.rem(keys=keys)
            self.db.kdts.rem(keys=keys)

    def processQuery(self, serder, source=None, sigers=None, cigars=None):
        """
        Process query mode replay message for collective or single element query.
        Assume promiscuous mode for now.

        Parameters:
            serder (SerderKERI) is query message serder
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
            sn = int(qry["s"], 16) if "s" in qry else None

            if pre not in self.kevers:
                self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                raise QueryNotFoundError("Query not found error={}.".format(ked))

            kever = self.kevers[pre]
            if anchor:
                if not self.db.findAnchoringSealEvent(pre=pre, seal=anchor):
                    self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                    raise QueryNotFoundError("Query not found error={}.".format(ked))

            elif sn is not None:
                if kever.sner.num < sn or not self.db.fullyWitnessed(kever.serder):
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

            # get list of witness signatures to ensure we are presenting a fully witnessed event
            wigs = self.db.getWigs(dgKey(pre, kever.serder.saidb))  # list of wigs
            wigers = [Siger(qb64b=bytes(wig)) for wig in wigs]

            if len(wigers) < kever.toader.num:
                self.escrowQueryNotFoundEvent(serder=serder, prefixer=source, sigers=sigers, cigars=cigars)
                raise QueryNotFoundError("Query not found error={}.".format(ked))

            rserder = reply(route=f"/ksn/{src}", data=kever.state()._asdict())
            self.cues.push(dict(kin="reply", src=src, route="/ksn", serder=rserder,
                                dest=source.qb64))

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
        Returns SerderKERI instance of establishment event that is authoritative for
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

            serder = serdering.SerderKERI(raw=raw)  # deserialize event raw
            if serder.ked["t"] in (Ilks.icp, Ilks.dip, Ilks.rot, Ilks.drt):
                return serder  # establishment event so return

            sn = int(serder.ked["s"], 16) - 1  # set sn to previous event
            if sn < 0:  # no more events
                return None

    def escrowOOEvent(self, serder, sigers, seqner=None, saider=None, wigers=None):
        """
        Update associated logs for escrow of Out-of-Order event

        Parameters:
            serder (SerderKERI): instance of  event
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
            serder (SerderKERI): instance of  event
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
            serder is SerderKERI instance of  event
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
            serder (SerderKERI): instance of receipt msg not receipted event
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
            serder (SerderKERI): instance of receipt msg not receipted event
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
                serder is SerderKERI instance of  event
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

                    eserder = serdering.SerderKERI(raw=bytes(eraw))  # escrowed event

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
                serder is SerderKERI instance of  event
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

                    eserder = serdering.SerderKERI(raw=bytes(eraw))  # escrowed event
                    #  get sigs and attach
                    sigs = self.db.getSigs(dgkey)
                    if not sigs:  # otherwise its a list of sigs
                        # no sigs so raise ValidationError which unescrows below
                        logger.info("Kevery unescrow error: Missing event sigs at."
                                    "dig = %s\n", bytes(edig))

                        raise ValidationError("Missing escrowed evt sigs at "
                                              "dig = {}.".format(bytes(edig)))

                    # seal source (delegator issuer if any)
                    delseqner = delsaider = None
                    couple = self.db.getPde(dgkey)
                    if couple is not None:
                        delseqner, delsaider = deSourceCouple(couple)
                    elif eserder.ked["t"] in (Ilks.dip, Ilks.drt,):
                        if eserder.pre in self.kevers:
                            delpre = self.kevers[eserder.pre].delegator
                        else:
                            delpre = eserder.ked["di"]

                        seal = dict(i=eserder.ked["i"], s=eserder.snh, d=eserder.said)
                        srdr = self.db.findAnchoringSealEvent(pre=delpre, seal=seal)
                        if srdr is not None:
                            delseqner = coring.Seqner(sn=srdr.sn)
                            delsaider = coring.Saider(qb64=srdr.said)
                            couple = delseqner.qb64b + delsaider.qb64b
                            self.db.putPde(dgkey, couple)

                    # process event
                    sigers = [Siger(qb64b=bytes(sig)) for sig in sigs]
                    self.processEvent(serder=eserder, sigers=sigers,
                                      delseqner=delseqner, delsaider=delsaider)

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
                        self.cues.push(dict(kin="psUnescrow", serder=eserder))

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
                        self.cues.push(dict(kin="psUnescrow", serder=eserder))

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
                serder is SerderKERI instance of  event
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

                    eserder = serdering.SerderKERI(raw=bytes(eraw))  # escrowed event

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
                    delseqner = delsaider = None
                    couple = self.db.getPde(dgKey(pre, bytes(edig)))
                    if couple is not None:
                        delseqner, delsaider = deSourceCouple(couple)

                    self.processEvent(serder=eserder, sigers=sigers, wigers=wigers,
                                      delseqner=delseqner, delsaider=delsaider)

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

                        serder = serdering.SerderKERI(raw=bytes(raw))  # receipted event

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

                    eserder = serdering.SerderKERI(raw=bytes(eraw))  # escrowed event

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
            serder = serdering.SerderKERI(raw=bytes(self.db.getEvt(dgKey(pre, dig))))  # receipted event
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

                    serder = serdering.SerderKERI(raw=bytes(raw))  # receipted event

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
                    sserder = serdering.SerderKERI(raw=bytes(sraw))
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
                serder is SerderKERI instance of  event
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

                    eserder = serdering.SerderKERI(raw=bytes(eraw))  # escrowed event

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


def loadEvent(db, preb, dig):
    """ Load event details from database

    Args:
        db (Baser): database to load event fro,
        preb (bytes): qb64b identifier prefix
        dig (bytes): digest of event to load

    Returns:
        dict: data from event

    """
    event = dict()
    dgkey = dbing.dgKey(preb, dig)  # get message
    if not (raw := db.getEvt(key=dgkey)):
        raise ValueError("Missing event for dig={}.".format(dig))

    serder = serdering.SerderKERI(raw=bytes(raw))
    event["ked"] = serder.ked

    sn = serder.sn
    sdig = db.getKeLast(key=dbing.snKey(pre=preb,
                                        sn=sn))
    if sdig is not None:
        event["stored"] = True

    # add indexed signatures to attachments
    sigs = db.getSigs(key=dgkey)
    dsigs = []
    for s in sigs:
        sig = coring.Siger(qb64b=bytes(s))
        dsigs.append(dict(index=sig.index, signature=sig.qb64))
    event["signatures"] = dsigs

    # add witness state at this event
    wits = db.wits.get(dgkey) if serder.estive else []
    event["witnesses"] = [wit.qb64 for wit in wits]

    # add indexed witness signatures to attachments
    dwigs = []
    if wigs := db.getWigs(key=dgkey):
        for w in wigs:
            sig = coring.Siger(qb64b=bytes(w))
            dwigs.append(dict(index=sig.index, signature=sig.qb64))
    event["witness_signatures"] = dwigs

    # add authorizer (delegator/issuer) source seal event couple to attachments
    couple = db.getAes(dgkey)
    if couple is not None:
        raw = bytearray(couple)
        seqner = coring.Seqner(qb64b=raw, strip=True)
        saider = coring.Saider(qb64b=raw)
        event["source_seal"] = dict(sequence=seqner.sn, said=saider.qb64)

    receipts = dict()
    # add trans receipts quadruples
    if quads := db.getVrcs(key=dgkey):
        trans = []
        for quad in quads:
            raw = bytearray(quad)
            trans.append(dict(
                prefix=coring.Prefixer(qb64b=raw, strip=True).qb64,
                sequence=coring.Seqner(qb64b=raw, strip=True).qb64,
                said=coring.Saider(qb64b=raw, strip=True).qb64,
                signature=coring.Siger(qb64b=raw, strip=True).qb64,
            ))

        receipts["transferable"] = trans

    # add nontrans receipts couples
    if coups := db.getRcts(key=dgkey):
        nontrans = []
        for coup in coups:
            raw = bytearray(coup)
            (prefixer, cigar) = deReceiptCouple(raw, strip=True)
            nontrans.append(dict(prefix=prefixer.qb64, signature=cigar.qb64))
        receipts["nontransferable"] = nontrans

    event["receipts"] = receipts
    # add first seen replay couple to attachments
    if not (dts := db.getDts(key=dgkey)):
        raise ValueError("Missing datetime for dig={}.".format(dig))

    event["timestamp"] = coring.Dater(dts=bytes(dts)).dts
    return event
