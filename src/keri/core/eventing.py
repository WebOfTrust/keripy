# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""

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

from ..kering import (ValidationError, VersionError, EmptyMaterialError,
                      DerivationError, ShortageError)
from ..kering import Versionage, Version
from ..help.helping import nowIso8601
from ..db.dbing import dgKey, snKey, Baser

from .coring import Versify, Serials, Ilks, CryOneDex
from .coring import Signer, Verfer, Diger, Nexter, Prefixer, Serder
from .coring import CryCounter, Cigar
from .coring import SigCounter, Siger

from ..help import ogling

blogger, flogger = ogling.ogler.getLoggers()

ICP_LABELS = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt",
              "toad", "wits", "cnfg"]
ROT_LABELS = ["vs", "pre", "sn", "ilk", "dig", "sith", "keys", "nxt",
              "toad", "cuts", "adds", "data"]
IXN_LABELS = ["vs", "pre", "sn", "ilk", "dig", "data"]
DIP_LABELS = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt",
              "toad", "wits", "cnfg", "seal"]
DRT_LABELS = ["vs", "pre", "sn", "ilk", "dig", "sith", "keys", "nxt",
              "toad", "cuts", "adds", "perm", "seal"]


@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    EstOnly:         str = 'EstOnly'  #  Only allow establishment events


    def __iter__(self):
        return iter(astuple(self))

TraitDex = TraitCodex()  # Make instance



# Location of last establishment key event: sn is int, dig is qb64 digest
LastEstLoc = namedtuple("LastEstLoc", 'sn dig')

#  for the following Seal namedtuples use the ._asdict() method to convert to dict
#  when using in events

# Digest Seal: dig is qb64 digest of data
SealDigest = namedtuple("SealDigest", 'dig')

# Root Seal: root is qb64 digest that is merkle tree root of data tree
SealRoot = namedtuple("SealRoot", 'root')

# Event Seal: pre is qb64 of identifier prefix of KEL, sn is hex string,
# dig is qb64 digest of event
SealEvent = namedtuple("SealEvent", 'pre sn dig')

# Event Location Seal: pre is qb64 of identifier prefix of KEL,
# sn is hex string, ilk is str, dig is qb64 of prior event digest
SealLocation = namedtuple("SealLocation", 'pre sn ilk dig')

# Cues are dataclasses may be converted tofrom dicts easily



def incept(keys,
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
    Returns serder of inception event message.
    Utility function to automate creation of inception events.

     Parameters:
        keys is list of qb64 signing keys
        code is derivation code for prefix
        sith is int  of signing threshold
        nxt  is qb64 next digest xor
        toad is int of witness threshold
        wits is list of qb64 witness prefixes
        cnfg is list of dicts of configuration traits
        version is Version instance
        kind is serialization kind
    """
    vs = Versify(version=version, kind=kind, size=0)
    sn = 0
    ilk = Ilks.icp

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

    ked = dict(vs=vs,  # version string
               pre="",  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               sith="{:x}".format(sith), # hex string no leading zeros lowercase
               keys=keys,  # list of qb64
               nxt=nxt,  # hash qual Base64
               toad="{:x}".format(toad),  # hex string no leading zeros lowercase
               wits=wits,  # list of qb64 may be empty
               cnfg=cnfg,  # list of config ordered mappings may be empty
               )

    if code is None and len(keys) == 1:
        prefixer = Prefixer(qb64=keys[0])
    else:
        # raises derivation error if non-empty nxt but ephemeral code
        prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

    ked["pre"] = prefixer.qb64  # update pre element in ked with pre qb64

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
        sith is int signing threshold
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

    ked = dict(vs=vs,  # version string
               pre=pre,  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               dig=dig,  #  qb64 digest of prior event
               sith="{:x}".format(sith), # hex string no leading zeros lowercase
               keys=keys,  # list of qb64
               nxt=nxt,  # hash qual Base64
               toad="{:x}".format(toad),  # hex string no leading zeros lowercase
               cuts=cuts,  # list of qb64 may be empty
               adds=adds,  # list of qb64 may be empty
               data=data,  # list of seals
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

    ked = dict(vs=vs,  # version string
               pre=pre,  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               dig=dig,  #  qb64 digest of prior event
               data=data,  # list of seals
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

    ked = dict(vs=vs,  # version string
               pre=pre,  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,  #  Ilks.rct
               dig=dig,  # qb64 digest of receipted event
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

    ked = dict(vs=vs,  # version string
               pre=pre,  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,  #  Ilks.rct
               dig=dig,  # qb64 digest of receipted event
               seal=seal._asdict()  # event seal: pre, dig
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

    ked = dict(vs=vs,  # version string
               pre="",  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               sith="{:x}".format(sith), # hex string no leading zeros lowercase
               keys=keys,  # list of qb64
               nxt=nxt,  # hash qual Base64
               toad="{:x}".format(toad),  # hex string no leading zeros lowercase
               wits=wits,  # list of qb64 may be empty
               cnfg=cnfg,  # list of config and permission ordered mappings may be empty
               seal=seal._asdict()  # event seal: pre, dig
               )

    if code is None:
        code = CryOneDex.Blake3_256  # Default digest

    # raises derivation error if non-empty nxt but ephemeral code
    prefixer = Prefixer(ked=ked, code=code)  # Derive AID from ked and code

    if not prefixer.digestive:
        raise ValueError("Invalid derivation code ={} for delegation. Must be"
                         " digestive".formate(prefixer.code))

    ked["pre"] = prefixer.qb64  # update pre element in ked with pre qb64

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

    ked = dict(vs=vs,  # version string
               pre=pre,  # qb64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               dig=dig,  #  qb64 digest of prior event
               sith="{:x}".format(sith), # hex string no leading zeros lowercase
               keys=keys,  # list of qb64
               nxt=nxt,  # hash qual Base64
               toad="{:x}".format(toad),  # hex string no leading zeros lowercase
               cuts=cuts,  # list of qb64 may be empty
               adds=adds,  # list of qb64 may be empty
               data=data,  # list of seals ordered mappings may be empty
               seal=seal._asdict()  # event seal: pre, dig
               )

    return Serder(ked=ked)  # return serialized ked


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
        .baser is reference for Baser instance that managers the
        .version is version of current event state
        .prefixer is prefixer instance for current event state
        .sn is sequence number int
        .serder is Serder instance of current event with .serder.diger for digest
        .ilk is str of current event type
        .sith is int or list of current signing threshold
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
            establishOnly is boolean trait to indicate establish only event

        """
        if baser is None:
            baser = Baser()  # default name = "main"
        self.baser = baser

        # may update state as we go because if invalid we fail to finish init
        self.version = serder.version  # version dispatch ?

        ilk = serder.ked["ilk"]
        if ilk not in (Ilks.icp, Ilks.dip):
            raise ValidationError("Expected ilk = {} or {} got {} for evt = {}."
                                              "".format(Ilks.icp, Ilks.dip,
                                                        ilk, serder.ked))
        self.ilk = ilk

        labels = DIP_LABELS if ilk ==  Ilks.dip else ICP_LABELS
        for k in labels:
            if k not in serder.ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, serder.ked))

        self.incept(serder=serder)  # do major event validation and state setting

        self.config(serder=serder, estOnly=estOnly)  # assign config traits perms

        # validates and escrows as needed
        self.validateSigs(serder=serder, sigers=sigers, verfers=serder.verfers,
                          sith=self.sith, sn=self.sn)

        if ilk == Ilks.dip:
            seal = self.validateSeal(serder=serder, sigers=sigers)
            self.delegated = True
            self.delegator = seal.pre
        else:
            self.delegated = False
            self.delegator = None

        self.logEvent(serder, sigers)  # update logs


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
        sith = ked["sith"]
        if isinstance(sith, str):
            self.sith = int(sith, 16)
            if self.sith < 1 or self.sith > len(self.verfers):  # out of bounds sith
                raise ValueError("Invalid sith = {} for keys = {} for evt = {}."
                                 "".format(sith,
                                           [verfer.qb64 for verfer in self.verfers],
                                           ked))
        else:
            # fix this to support list sith
            raise ValueError("Unsupported type for sith = {} for evt = {}."
                             "".format(sith, ked))

        self.prefixer = Prefixer(qb64=ked["pre"])
        if not self.prefixer.verify(ked=ked):  # invalid prefix
            raise ValidationError("Invalid prefix = {} for inception evt = {}."
                                  "".format(self.prefixer.qb64, ked))

        sn = self.validateSN(sn=ked["sn"], ked=ked, inceptive=True)
        self.sn = sn
        self.serder = serder  # need whole serder for digest agility comparisons

        nxt = ked["nxt"]
        if not self.prefixer.transferable and nxt:  # nxt must be empty for nontrans prefix
            raise ValidationError("Invalid inception nxt not empty for "
                                  "non-transferable prefix = {} for evt = {}."
                                  "".format(self.prefixer.qb64, ked))
        self.nexter = Nexter(qb64=nxt) if nxt else None

        wits = ked["wits"]
        if len(oset(wits)) != len(wits):
            raise ValueError("Invalid wits = {}, has duplicates for evt = {}."
                             "".format(wits, ked))
        self.wits = wits

        toad = int(ked["toad"], 16)
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
        self.lastEst = LastEstLoc(sn=self.sn, dig=self.serder.diger.qb64)  # last establishment event location


    def config(self, serder, estOnly=None):
        """
        Process cnfg field for configuration traits
        """
        # assign traits
        self.estOnly = (True if (estOnly if estOnly is not None else self.EstOnly)
                            else False)  # ensure default estOnly is boolean

        cnfg = serder.ked["cnfg"]  # process cnfg for traits
        for d in cnfg:
            if "trait" in d and d["trait"] == TraitDex.EstOnly:
                self.estOnly = True


    def update(self, serder,  sigers):
        """
        Not original inception event. So verify event serder and
        indexed signatures in sigers and update state

        """
        if not self.transferable:  # not transferable so no events after inception allowed
            raise ValidationError("Unexpected event = {} in nontransferable "
                                  " state.".format(serder.ked))
        ked = serder.ked
        if ked["pre"] != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {} for evt = {}.".format(ked["pre"],
                                                               self.prefixer.qb64,
                                                               ked))

        sn = self.validateSN(sn=ked["sn"], ked=ked, inceptive=False)
        ilk = ked["ilk"]

        if ilk in (Ilks.rot, Ilks.drt) :  # rotation (or delegated rotation) event
            if self.delegated and ilk != Ilks.drt:
                raise ValidationError("Attempted non delegated rotation on "
                                      "delegated pre = {} with evt = {}."
                                      "".format(ked["pre"], ked))

            labels = DRT_LABELS if ilk == Ilks.dip else ROT_LABELS
            for k in labels:
                if k not in ked:
                    raise ValidationError("Missing element = {} from {} event for "
                                          "evt = {}.".format(k, ilk, ked))

            sith, toad, wits = self.rotate(serder, sn)

            # validates and escrows as needed
            self.validateSigs(serder=serder, sigers=sigers, verfers=serder.verfers,
                              sith=sith, sn=sn)

            if ilk == Ilks.drt:
                seal = self.validateSeal(serder=serder, sigers=sigers)
                if seal.pre != self.delegator:
                    raise ValidationError("Attempted delegated rotation with "
                                      "wrong delegator = {} for delegated pre "
                                      " = {} with evt = {}."
                                      "".format(seal.pre, ked["pre"], ked))

            # nxt and signatures verify so update state
            self.sn = sn
            self.serder = serder  #  need whole serder for digest agility compare
            self.ilk = ilk
            self.sith = sith
            self.verfers = serder.verfers
            # update .nexter
            nxt = ked["nxt"]
            self.nexter = Nexter(qb64=nxt) if nxt else None  # check for empty

            self.toad = toad
            self.wits = wits

            # last establishment event location need this to recognize recovery events
            self.lastEst = LastEstLoc(sn=self.sn, dig=self.serder.diger.qb64)



            self.logEvent(serder, sigers)  # update logs


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

            if not self.serder.compare(dig=ked["dig"]):  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with state dig"
                                      " = {} for evt = {}.".format(ked["dig"],
                                                                   self.serder.diger.qb64,
                                                                   ked))

            # interaction event use sith and keys from pre-existing Kever state
            # validates and escrows as needed
            self.validateSigs(serder=serder, sigers=sigers, verfers=self.verfers,
                              sith=self.sith, sn=sn)

            # update state
            self.sn = sn
            self.serder = serder  # need for digest agility includes .serder.diger
            self.ilk = ilk

            self.logEvent(serder, sigers)  # update logs

        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))


    def rotate(self, serder, sn):
        """
        Generic Rotate Operation Processing
        Same logic for both rot and drt (plain and delegated rotation)

        Parameters:
            serder is event Serder instance
            sn is int sequence number

        """
        ked = serder.ked
        pre = ked["pre"]
        dig = ked["dig"]

        if sn > self.sn + 1:  #  out of order event
            raise ValidationError("Out of order event sn = {} expecting"
                                  " = {} for evt = {}.".format(sn,
                                                               self.sn+1,
                                                               ked))

        elif sn <= self.sn:  #  stale or recovery
            #  stale events could be duplicitous
            #  duplicity detection should have happend before .update called
            #  so raise exception if stale
            if sn <= self.lastEst.sn :  # stale  event
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


        sith = ked["sith"]
        if isinstance(sith, str):
            sith = int(sith, 16)
            if sith < 1 or sith > len(serder.verfers):  # out of bounds sith
                raise ValueError("Invalid sith = {} for keys = {} for evt "
                                 "= {}.".format(sith,
                                      [verfer.qb64 for verfer in serder.verfers],
                                      ked))
        else:
            # fix this to support list sith
            raise ValueError("Unsupported type for sith = {} for evt = {}."
                             "".format(sith, ked))

        # verify nxt from prior
        keys = ked["keys"]
        if not self.nexter.verify(sith=sith, keys=keys):
            raise ValidationError("Mismatch nxt digest = {} with rotation"
                                  " sith = {}, keys = {} for evt = {}."
                                  "".format(self.nexter.qb64, sith, keys, ked))

        # compute wits from cuts and adds use set
        # verify set math
        witset = oset(self.wits)
        cuts = ked["cuts"]
        cutset = oset(cuts)
        if len(cutset) != len(cuts):
            raise ValueError("Invalid cuts = {}, has duplicates for evt = "
                             "{}.".format(cuts, ked))

        if (witset & cutset) != cutset:  #  some cuts not in wits
            raise ValueError("Invalid cuts = {}, not all members in wits"
                             " for evt = {}.".format(cuts, ked))


        adds = ked["adds"]
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

        toad = int(ked["toad"], 16)
        if wits:
            if toad < 1 or toad > len(wits):  # out of bounds toad
                raise ValueError("Invalid toad = {} for wits = {} for evt "
                                 "= {}.".format(toad, wits, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValueError("Invalid toad = {} for wits = {} for evt "
                                 "= {}.".format(toad, wits, ked))

        return (sith, toad, wits)

    def validateSN(self, sn, ked, inceptive=False):
        """
        Returns int validated from hex str sn in ked

        Parameters:
           sn is hex char sequence number of event or seal in an event
           ked is key event dict of associated event
        """
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large for evt = {}."
                                  "".format(sn, ked))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {} for evt = {}.".format(sn, ked))

        if inceptive:
            if sn != 0:
                raise ValidationError("Nonzero sn = {} for inception evt = {}."
                                      "".format(sn, ked))
        else:
            if sn == 0:
                raise ValidationError("Zero sn = {} for non=inception evt = {}."
                                      "".format(sn, ked))
        return sn


    def validateSigs(self, serder, sigers, verfers, sith, sn):
        """
        Validate signatures by validating sith indexs and verifying signatures
        """
        # verify indexes of attached signatures against verifiers
        for siger in sigers:
            if siger.index >= len(verfers):
                raise ValidationError("Index = {} to large for keys for evt = "
                                      "{}.".format(siger.index, serder.ked))
            siger.verfer = verfers[siger.index]  # assign verfer

        # verify signatures
        if not self.verifySigs(sigers=sigers, serder=serder):
            raise ValidationError("Failure verifying signatures = {} for {} for"
                                  " evt = {}.".format(sigers, serder, serder.ked))

        # verify sith given signatures verify
        if not self.verifySith(sigers=sigers, sith=sith):
            self.escrowPSEvent(self, serder, sigers, self.prefixer.qb64b, sn)

            raise ValidationError("Failure verifying sith = {} on sigs for {}"
                                  " for evt = {}.".format(self.sith, sigers, serder.ked))


    def verifySigs(self, sigers, serder):
        """
        Use verfer in each siger to verify signature against serder
        Assumes that sigers with verfer already extracted correctly wrt indexes

        Parameters:
            sigers is list of Siger instances
            serder is Serder instance

        """
        for siger in sigers:
            if not siger.verfer.verify(siger.raw, serder.raw):
                return False

        if len(sigers) < 1:  # at least one signature
            return False

        return True


    def verifySith(self, sigers, sith=None):
        """
        Assumes that all sigers signatures were already verified
        If sith not provided then use .sith instead

        Parameters:
            sigers is list of Siger instances
            sith is int threshold

        """
        sith = sith if sith is not None else self.sith

        if not isinstance(sith, int):
            raise ValueError("Unsupported type for sith = {}".format(sith))

        if len(sigers) < sith:  # not meet threshold fix for list sith
            return False

        return True


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
        seal = SealLocation(**serder.ked["seal"])
        # seal has pre sn ilk dig (prior dig)

        ssn = self.validateSN(sn=seal.sn, ked=serder.ked, inceptive=False)

        # get the dig of the delegating event
        key = snKey(pre=seal.pre, sn=ssn)
        raw = self.baser.getKeLast(key)
        if raw is None:  # no delegating event at key
            #  escrow event here
            inceptive = True if serder.ked["ilk"] in (Ilks.icp, Ilks.dip) else False
            sn = self.validateSN(serder.ked["sn"], serder.ked, inceptive=inceptive)
            self.escrowPSEvent(serder=serder, sigers=sigers,
                             pre=self.prefixer.qb64b, sn=sn)
            raise ValidationError("No delegating event at seal = {} for "
                                  "evt = {}.".format(serder.ked["seal"],
                                                     serder.ked))

        # get the delegating event from dig
        key = dgKey(pre=seal.pre, dig=bytes(raw))
        raw = self.baser.getEvt(key)
        if raw is None:
            raise ValidationError("Missing event at seal = {} for evt = {}."
                                  "".format(serder.ked["seal"], serder.ked))

        dserder = Serder(raw=bytes(raw))  # delegating event

        # get prior event
        pdig = self.baser.getKeLast(key=snKey(pre=seal.pre, sn=int(dserder.ked["sn"], 16) - 1 ))

        if pdig is  None:
            raise ValidationError("Missing prior event for seal = {}."
                                  "".format(serder.ked["seal"]))

        praw = self.baser.getEvt(key=dgKey(pre=seal.pre, dig=pdig))
        if praw is None:
            raise ValidationError("Missing prior event for seal = {}."
                                  "".format(serder.ked["seal"]))

        pserder = Serder(raw=bytes(praw))  # prior event of delegating event

        # need to retrieve prior event from database in order to verify digest agility
        if not pserder.compare(dig=seal.dig):  # delegating event prior dig match seal
            raise ValidationError("Mismatch prior dig of delegating event at "
                                  "seal = {} for evt = {}.".format(serder.ked["seal"],
                                                                   serder.ked))

        pre = serder.ked["pre"]
        dig = serder.dig
        found = False  # find event seal of delegated event in delegating data
        for dseal in dserder.ked["data"]:  #  find delegating seal
            if ("pre" in dseal and dseal["pre"] == pre and
                "dig" in dseal and serder.compare(dig=dseal["dig"])):  # dseal["dig"] == dig
                found = True
                break

        if not found:
            raise ValidationError("Missing delegating seal = {} for evt = {}."
                                  "".format(serder.ked["seal"], serder.ked))

        # should we reverify signatures or trust the database?
        # if database is loaded into memory fresh and reverified each bootup
        # then we can trust it otherwise we can't

        return seal


    def logEvent(self, serder, sigers):
        """
        Update associated logs for verified event

        Parameters:
            serder is Serder instance of current event
            sigers is list of Siger instance for current event
        """
        dgkey = dgKey(self.prefixer.qb64b, self.serder.diger.qb64b)
        self.baser.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.baser.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.baser.putEvt(dgkey, serder.raw)
        self.baser.addKe(snKey(self.prefixer.qb64b, self.sn), self.serder.diger.qb64b)
        blogger.info("Kever process: added valid event to KEL event = %s\n", serder.ked)


    def escrowPSEvent(self, serder, sigers, pre, sn):
        """
        Update associated logs for escrow of partially signed event
        or fully signed delegated event but without delegating event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
            pre is str qb64 of identifier prefix of event
            sn is int sequence number of event
        """
        dgkey = dgKey(pre, serder.digb)
        self.baser.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.baser.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.baser.putEvt(dgkey, serder.raw)
        self.baser.addPse(snKey(pre, sn), serder.digb)
        blogger.info("Kever process: escrowed partial siganture or delegated "
                     "event = %s\n", serder.ked)


class Kevery:
    """
    Kevery processes an incoming message stream and when appropriate generates
    an outgoing steam. When the incoming streams includes key event messages
    then Kevery acts a Kever (KERI key event verifier) factory.

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .ims is bytearray incoming message stream
        .cues is deque of Cues i.e. notices of events or requests to respond to
        .kevers is dict of existing kevers indexed by pre (qb64) of each Kever
        .logs is named tuple of logs
        .framed is Boolean stream is packet framed If True Else not framed


    Properties:

    """
    def __init__(self, ims=None, cues=None, kevers=None, baser=None, framed=True):
        """
        Set up event stream and logs

        """
        self.ims = ims if ims is not None else bytearray()
        self.cues = cues if cues is not None else deque()
        self.framed = True if framed else False  # extract until end-of-stream
        self.kevers = kevers if kevers is not None else dict()

        if baser is None:
            baser = Baser()  # default name = "main"
        self.baser = baser


    def processAll(self, ims=None):
        """
        Process all messages from incoming message stream, ims, when provided
        Otherwise process all messages from .ims
        """
        if ims is not None:  # needs bytearray not bytes since deletes as processes
            if not isinstance(ims, bytearray):
                ims = bytearray(ims)  # so make bytearray copy
        else:
            ims = self.ims

        while ims:
            try:
                self.processOne(ims=ims, framed=self.framed)

            except ShortageError as ex:  # need more bytes
                break  # break out of while loop

            except Exception as ex:  # log diagnostics errors etc
                if blogger.isEnabledFor(logging.DEBUG):
                    blogger.exception("Kevery msg process error: %s\n", ex.args[0])
                else:
                    blogger.error("Kevery msg process error: %s\n", ex.args[0])
                del ims[:]  #  delete rest of stream
                break


    def processOne(self, ims, framed=True):
        """
        Extract one msg with attached signatures from incoming message stream, ims
        And dispatch processing of message

        Parameters:
            ims is bytearray of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.

            framed is Boolean, If True and no sig counter then extract signatures
                until end-of-stream. This is useful for framed packets with
                one event and one set of attached signatures per invocation.

        """
        # deserialize packet from ims
        try:
            serder = Serder(raw=ims)

        except ShortageError as ex:  # need more bytes
            raise ex  # reraise

        except Exception as ex:
            raise ValidationError("Error while processing message stream"
                                  " = {}".format(ex))

        version = serder.version
        if version != Version:  # This is where to dispatch version switch
            raise VersionError("Unsupported version = {}, expected {} for evt "
                                  "= {}.".format(version, Version, serder.ked))

        del ims[:serder.size]  # strip off event from front of ims

        ilk = serder.ked['ilk']  # dispatch abased on ilk

        if ilk in [Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt]:  # event msg
            # extract sig counter if any for attached sigs
            try:
                counter = SigCounter(qb64b=ims)  # qb64b
                nsigs = counter.count
                del ims[:len(counter.qb64)]  # strip off counter
            except ValidationError as ex:
                nsigs = 0  # no signature count

            # extract attached sigs as Sigers
            sigers = []  # list of Siger instances for attached indexed signatures
            if nsigs:
                for i in range(nsigs): # extract each attached signature
                    # check here for type of attached signatures qb64 or qb2
                    siger = Siger(qb64b=ims)  # qb64
                    sigers.append(siger)
                    del ims[:len(siger.qb64)]  # strip off signature

            else:  # no info on attached sigs
                if framed:  # parse for signatures until end-of-stream
                    while ims:
                        # check here for type of attached signatures qb64 or qb2
                        siger = Siger(qb64b=ims)  # qb64
                        sigers.append(siger)
                        del ims[:len(siger.qb64)]  # strip off signature

            if not sigers:
                raise ValidationError("Missing attached signature(s) for evt "
                                      "= {}.".format(serder.ked))

            self.processEvent(serder, sigers)

        elif ilk in [Ilks.rct]:  # event receipt msg (nontransferable)
            # extract cry counter if any for attached receipt couplets
            try:
                counter = CryCounter(qb64b=ims)  # qb64
                ncpts = counter.count
                del ims[:len(counter.qb64)]  # strip off counter
            except ValidationError as ex:
                ncpts = 0  # no couplets count

            # extract attached rct couplets into list of sigvers
            # verfer property of cigar is the identifier prefix
            # cigar itself has the attached signature
            cigars = []  # List of cigars to hold couplets
            if ncpts:
                for i in range(ncpts): # extract each attached couplet
                    # check here for type of attached couplets qb64 or qb2
                    verfer = Verfer(qb64b=ims)  # qb64
                    del ims[:len(verfer.qb64)]  # strip off identifier prefix
                    cigar = Cigar(qb64b=ims, verfer=verfer)  # qb64
                    cigars.append(cigar)
                    del ims[:len(cigar.qb64)]  # strip off signature

            else:  # no info on attached receipt couplets
                if framed:  # parse for receipts until end-of-stream
                    while ims:
                        # check here for type of attached receipts qb64 or qb2
                        verfer = Verfer(qb64b=ims)  # qb64
                    del ims[:len(verfer.qb64)]  # strip off identifier prefix
                    cigar = Cigar(qb64b=ims, verfer=verfer)  # qb64
                    cigars.append(cigar)
                    del ims[:len(cigar.qb64)]  # strip off signature

            if not cigars:
                raise ValidationError("Missing attached receipt couplet(s)"
                                      " for evt = {}.".formate(serder.ked))

            self.processReceipt(serder, cigars)

        elif ilk in [Ilks.vrc]:  # validator event receipt msg (transferable)
            # extract sig counter if any for attached sigs
            try:
                counter = SigCounter(qb64b=ims)  # qb64
                nsigs = counter.count
                del ims[:len(counter.qb64)]  # strip off counter
            except ValidationError as ex:
                nsigs = 0  # no signature count

            # extract attached sigs as Sigers
            sigers = []  # list of Siger instances for attached indexed signatures
            if nsigs:
                for i in range(nsigs): # extract each attached signature
                    # check here for type of attached signatures qb64 or qb2
                    siger = Siger(qb64b=ims)  # qb64
                    sigers.append(siger)
                    del ims[:len(siger.qb64)]  # strip off signature

            else:  # no info on attached sigs
                if framed:  # parse for signatures until end-of-stream
                    while ims:
                        # check here for type of attached signatures qb64 or qb2
                        siger = Siger(qb64b=ims)  # qb64
                        sigers.append(siger)
                        del ims[:len(siger.qb64)]  # strip off signature

            if not sigers:
                raise ValidationError("Missing attached signature(s) to receipt"
                                      " for evt = {}.".format(serder.ked))

            self.processChit(serder, sigers)

        else:
            raise ValidationError("Unexpected message ilk = {} for evt ="
                                  " {}.".format(ilk, serder.ked))


    def validateSN(self, ked):
        """
        Returns int validated from hex str sn in ked

        Parameters:
           sn is hex char sequence number of event or seal in an event
           ked is key event dict of associated event
        """
        sn = ked["sn"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large for evt = {}."
                                  "".format(sn, ked))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {} for evt = {}.".format(sn, ked))

        return sn

    def escrowOOEvent(self, serder, sigers, pre, sn):
        """
        Update associated logs for escrow of Out-of-Order event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
            pre is str qb64 of identifier prefix of event
            sn is int sequence number of event
        """
        dgkey = dgKey(pre, serder.dig)
        self.baser.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.baser.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.baser.putEvt(dgkey, serder.raw)
        self.baser.addOoes(snKey(pre, sn), serder.dig)
        # log escrowed
        blogger.info("Kevery process: escrowed out of order event = %s\n", serder.ked)


    def escrowLDEvent(self, serder, sigers, pre, sn):
        """
        Update associated logs for escrow of Likely Duplicitous event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
            pre is str qb64 of identifier prefix of event
            sn is int sequence number of event
        """
        dgkey = dgKey(pre, serder.dig)
        self.baser.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.baser.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.baser.putEvt(dgkey, serder.raw)
        self.baser.addLde(snKey(pre, sn), serder.dig)
        # log duplicitous
        blogger.info("Kevery process: escrowed likely duplicitous event = %s\n", serder.ked)


    def processEvent(self, serder, sigers):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:


        """
        # fetch ked ilk  pre, sn, dig to see how to process
        ked = serder.ked
        try:  # see if pre in event validates
            prefixer = Prefixer(qb64=ked["pre"])
        except Exception as ex:
            raise ValidationError("Invalid pre = {} for evt = {}."
                                  "".format(ked["pre"], ked))
        pre = prefixer.qb64
        ked = serder.ked
        sn = self.validateSN(ked)
        ilk = ked["ilk"]
        dig = serder.dig

        if self.baser.getEvt(dgKey(pre, dig)) is not None:
            # performance log duplicate event
            blogger.info("Kevery process: discarded duplicate event = %s\n", ked)
            return  # discard duplicate

        if pre not in self.kevers:  #  first seen event for pre
            if ilk in (Ilks.icp, Ilks.dip):  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem
                # otherwise adds to KEL
                # create kever from serder
                kever = Kever(serder=serder,
                              sigers=sigers,
                              baser=self.baser)
                self.kevers[pre] = kever  # not exception so add to kevers

                # create cue for receipt   direct mode for now
                self.cues.append(dict(pre=pre, serder=serder))

            else:  # not inception so can't verify, add to out-of-order escrow
                self.escrowOOEvent(serder=serder, sigers=sigers, pre=pre, sn=sn)

        else:  # already accepted inception event for pre
            if ilk in (Ilks.icp, Ilks.dip):  # inception event so maybe duplicitous
                # escrow likely duplicitous event
                self.escrowLDEvent(serder=serder, sigers=sigers, pre=pre, sn=sn)

            else:  # rot, drt, or ixn, so sn matters
                kever = self.kevers[pre]  # get existing kever for pre
                sno = kever.sn + 1  # proper sn of new inorder event

                if sn > sno:  # sn later than sno so out of order escrow
                    # escrow out-of-order event
                    self.escrowOOEvent(serder=serder, sigers=sigers, pre=pre, sn=sn)

                elif ((sn == sno) or  # new inorder event or recovery
                      (ilk in (Ilks.rot, Ilks.drt) and kever.lastEst.sn < sn <= sno )):
                    # verify signatures etc and update state if valid
                    # raise exception if problem.
                    # Otherwise adds to KELs
                    kever.update(serder=serder, sigers=sigers)

                    # create cue for receipt direct mode for now
                    self.cues.append(dict(pre=pre, serder=serder))

                else:  # maybe duplicitous
                    #  escrow likely duplicitous event
                    self.escrowLDEvent(serder=serder, sigers=sigers, pre=pre, sn=sn)


    def processReceipt(self, serder, cigars):
        """
        Process one receipt serder with attached cigars

        Parameters:
            serder is
            cigars is list of Cigar instances that contain receipt couplet
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
        pre = ked["pre"]
        sn = ked["sn"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large for evt = {}."
                                  "".format(sn, ked))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {} for evt = {}.".format(sn, ked))

        # Only accept receipt if for last seen version of event at sn
        snkey = snKey(pre=pre, sn=sn)
        ldig = self.baser.getKeLast(key=snkey)   # retrieve dig of last event at sn.

        if ldig is not None:  #  verify digs match
            ldig = bytes(ldig).decode("utf-8")
            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            raw = bytes(self.baser.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none
            lserder = Serder(raw=raw)  # deserialize event raw

            if not lserder.compare(dig=ked["dig"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["sn"], ked))

            # process each couplet verify sig and write to db
            for cigar in cigars:
                if cigar.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid couplets
                if cigar.verfer.verify(cigar.raw, lserder.raw):
                    # write receipt couplet to database
                    couplet = cigar.verfer.qb64b + cigar.qb64b
                    self.baser.addRct(key=dgkey, val=couplet)

        else:  # no events to be receipted yet at that sn so escrow
            for cigar in cigars:  # escrow each couplet
                if cigar.verfer.transferable:  # skip transferable verfers
                    continue  # skip invalid couplets
                couplet = cigar.verfer.qb64b + cigar.qb64b
                dgkey = dgKey(pre=pre, dig=ked["dig"])
                self.baser.addUre(key=dgkey, val=couplet)


    def processChit(self, serder, sigers):
        """
        Process one transferable validator receipt (chit) serder with attached sigers

        Parameters:
            serder is chit serder (transferable validator receipt message)
            sigers is list of Siger instances that contain signature

        Chit dict labels
            vs  # version string
            pre  # qb64 prefix
            ilk  # vrc
            dig  # qb64 digest of receipted event
            seal # event seal of last est event pre dig
        """
        # fetch  pre, dig,seal to process
        ked = serder.ked
        pre = ked["pre"]
        sn = ked["sn"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large for evt = {}."
                                  "".format(sn, ked))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {} for evt = {}.".format(sn, ked))

        seal = SealEvent(**ked["seal"])
        sealet = seal.pre.encode("utf-8") + seal.dig.encode("utf-8")

        # Only accept receipt if for last seen version of event at sn
        snkey = snKey(pre=pre, sn=sn)
        ldig = self.baser.getKeLast(key=snkey)  # retrieve dig of last event at sn.

        if ldig is not None and seal.pre in self.kevers:  #  verify digs match last seen and receipt dig
            # both receipted event and receipter in database
            # so retreive
            ldig = bytes(ldig).decode("utf-8")

            # retrieve event by dig assumes if ldig is not None that event exists at ldig
            dgkey = dgKey(pre=pre, dig=ldig)
            raw = bytes(self.baser.getEvt(key=dgkey))  # retrieve receipted event at dig
            # assumes db ensures that raw must not be none
            lserder = Serder(raw=raw)  # deserialize event raw

            if not lserder.compare(dig=ked["dig"]):  # stale receipt at sn discard
                raise ValidationError("Stale receipt at sn = {} for rct = {}."
                                      "".format(ked["sn"], ked))

            # retrieve dig of last event at sn.
            sigdig = self.baser.getKeLast(key=snKey(pre=seal.pre, sn=int(seal.sn, 16)))

            sigraw = self.baser.getEvt(key=dgKey(pre=seal.pre, dig=bytes(sigdig)))
            if sigraw is None:
                raise ValidationError("Missing seal est. event dig = {} for "
                                      "receipt from pre ={}."
                                      "".format(seal.dig, seal.pre))

            sigSerder = Serder(raw=bytes(sigraw))
            if not sigSerder.compare(dig=seal.dig):  # seal dig not match event
                raise ValidationError("Bad chit seal at sn = {} for rct = {}."
                                      "".format(seal.sn, ked))

            verfers = sigSerder.verfers
            if not verfers:
                raise ValidationError("Invalid seal est. event dig = {} for "
                                      "receipt from pre ={} no keys."
                                      "".format(seal.dig, seal.pre))

            raw = bytes(raw)
            for siger in sigers:  # verify sigs
                if siger.index >= len(verfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(siger.index))

                siger.verfer = verfers[siger.index]  # assign verfer
                if siger.verfer.verify(siger.raw, raw):  # verify sig
                    # good sig so write receipt truplet to database
                    triplet = sealet + siger.qb64b
                    self.baser.addVrc(key=dgkey, val=triplet)  # dups kept

        else:  # escrow  either receiptor or event not yet in database
            for siger in sigers:  # escrow triplets one for each sig
                triplet = sealet + siger.qb64b
                dgkey = dgKey(pre=pre, dig=ked["dig"])
                self.baser.addVre(key=dgkey, val=triplet)


    def duplicity(self, serder, sigers):
        """
        Processes potential duplicitous events in PDELs

        Handles duplicity detection and logging if duplicitous

        Placeholder here for logic need to move

        """
        pass
        ## fetch ked ilk  pre, sn, dig to see how to process
        #ked = serder.ked
        #try:  # see if pre in event validates
            #prefixer = Prefixer(qb64=ked["pre"])
        #except Exception as ex:
            #raise ValidationError("Invalid pre = {}.".format(ked["pre"]))
        #pre = prefixer.qb64
        #ked = serder.ked
        #ilk = ked["ilk"]
        #try:
            #sn = int(ked["sn"], 16)
        #except Exception as ex:
            #raise ValidationError("Invalid sn = {}".format(ked["sn"]))
        #dig = serder.dig

        ##if dig in DELPs["pre"]:
            ##return

        #if ilk == Ilks.icp:  # inception event so maybe duplicitous
            ## Using Kever for cheap duplicity detection of inception events
            ## kever init verifies basic inception stuff and signatures
            ## raises exception if problem.
            #kever = Kever(serder=serder, sigers=siger, baser=self.baser)  # create kever from serder
            ## No exception above so verified duplicitous event
            ## log it and add to DELS if first time
            ##if pre not in DELs:  #  add to DELS
                ##DELs[pre] = dict()
            ##if dig not in DELS[pre]:
                ##DELS[pre][dig] = LogEntry(serder=serder, sigers=sigers)

        #else:
            #pass
