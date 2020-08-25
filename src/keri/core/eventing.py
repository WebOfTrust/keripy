# -*- encoding: utf-8 -*-
"""
keri.core.eventing module

"""

import re
import json

from dataclasses import dataclass, astuple
from collections import namedtuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from math import ceil

import cbor2 as cbor
import msgpack
import pysodium
import blake3

from orderedset import OrderedSet as oset

from ..kering import ValidationError, VersionError, EmptyMaterialError, DerivationError
from ..kering import Versionage, Version
from ..help.helping import nowIso8601
from ..db.dbing import dgKey, snKey, Logger

from .coring import Versify, Serials, Ilks, CryOneDex
from .coring import Signer, Verfer, Diger, Nexter, Prefixer, Serder
from .coring import SigCounter, Siger

ICP_LABELS = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt",
              "toad", "wits", "cnfg"]
ROT_LABELS = ["vs", "pre", "sn", "ilk", "dig", "sith", "keys", "nxt",
              "toad", "cuts", "adds", "data"]
IXN_LABELS = ["vs", "pre", "sn", "ilk", "dig", "data"]
DIP_LABELS = ["vs", "pre", "sn", "ilk", "sith", "keys", "nxt",
              "toad", "wits", "perm", "seal"]
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

Location = namedtuple("Location", 'sn dig')  # Location of key event


def incept(
            keys,
            code=None,
            version=Version,
            kind=Serials.json,
            sith=None,
            nxt="",
            toad=None,
            wits=None,
            cnfg=None,
          ):

    """
    Returns serder of inception event.
    Utility function to automate creation of inception events.

     Parameters:
        keys,
        version
        kind
        sith
        nxt
        toad
        wits
        cnfg
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


def rotate( pre,
            keys,
            dig,
            version=Version,
            kind=Serials.json,
            sn=1,
            sith=None,
            nxt="",
            toad=None,
            wits=None, # prior existing wits
            cuts=None,
            adds=None,
            data=None,
          ):

    """
    Returns serder of rotation event.
    Utility function to automate creation of rotation events.

     Parameters:
        pre
        keys
        dig
        version
        kind
        sn
        sith
        nxt
        toad
        cuts
        adds
        data
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
               pre=pre,  # ab64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               dig=dig,
               sith="{:x}".format(sith), # hex string no leading zeros lowercase
               keys=keys,  # list of qb64
               nxt=nxt,  # hash qual Base64
               toad="{:x}".format(toad),  # hex string no leading zeros lowercase
               cuts=cuts,  # list of qb64 may be empty
               adds=adds,  # list of qb64 may be empty
               data=data,  # list of seals
               )

    return Serder(ked=ked)  # return serialized ked


def interact( pre,
              dig,
              version=Version,
              kind=Serials.json,
              sn=1,
              data=None,
          ):

    """
    Returns serder of interaction event.
    Utility function to automate creation of interaction events.

     Parameters:
        pre
        dig
        version
        kind
        sn
        data
    """
    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.ixn

    if sn < 1:
        raise ValueError("Invalid sn = {} for ixn.".format(sn))

    data = data if data is not None else []

    ked = dict(vs=vs,  # version string
               pre=pre,  # ab64 prefix
               sn="{:x}".format(sn),  # hex string no leading zeros lowercase
               ilk=ilk,
               dig=dig,
               data=data,  # list of seals
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
        .version is version of current event state
        .prefixer is prefixer instance for current event state
        .sn is sequence number int
        .diger is Diger instance with digest of current event not prior event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .verfers is list of Verfer instances for current event state set of signing keys
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .cnfg is list of inception configuration data mappings
        .data is list of current seals
        .estOnly is boolean
        .nonTrans is boolean

    Properties:

        .nonTransferable  .nonTrans

    """
    EstOnly = False

    def __init__(self, serder, sigers, estOnly=None, logger=None):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigers raises ValidationError if not

        Parameters:
            serder is Serder instance of inception event
            sigers is list of SigMat instances of signatures of event
            establishOnly is boolean trait to indicate establish only event

        """
        # update state as we go because if invalid we fail to finish init

        if logger is None:
            logger = Logger()  # default name = "main"
        self.logger = logger

        self.version = serder.version  # version dispatch ?
        self.verfers = serder.verfers  # converts keys to verifiers
        # verify indexes of attached signatures against verifiers
        for siger in sigers:
            if siger.index >= len(self.verfers):
                raise ValidationError("Index = {} to large for keys."
                                      "".format(siger.index))
            siger.verfer = self.verfers[siger.index]  # assign verfer

        ked = serder.ked

        for k in ICP_LABELS:
            if k not in ked:
                raise ValidationError("Missing element = {} from {}  event."
                                      "".format(k, Ilks.icp))

        ilk = ked["ilk"]
        if ilk != Ilks.icp:
            raise ValidationError("Expected ilk = {} got {}."
                                              "".format(Ilks.icp, ilk))
        self.ilk = ilk

        sith = ked["sith"]
        if isinstance(sith, str):
            self.sith = int(sith, 16)
            if self.sith < 1 or self.sith > len(self.verfers):  # out of bounds sith
                raise ValueError("Invalid sith = {} for keys = {}".format(sith,
                                      [verfer.qb64 for verfer in self.verfers]))
        else:
            # fix this to support list sith
            raise ValueError("Unsupported type for sith = {}".format(sith))

        self.prefixer = Prefixer(qb64=ked["pre"])
        if not self.prefixer.verify(ked=ked):  # invalid prefix
            raise ValidationError("Invalid prefix = {} for inception ked = {}."
                                  "".format(self.prefixer.qb64, ked))

        sn = ked["sn"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large.".format(sn))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {}".format(sn))
        if sn != 0:
            raise ValidationError("Nonzero sn = {} for inception ked = {}."
                                              "".format(sn, ked))
        self.sn = sn
        self.diger = serder.diger

        nxt = ked["nxt"]
        self.nexter = Nexter(qb64=nxt) if nxt else None
        self.nonTrans = True if self.nexter is None else False


        wits = ked["wits"]
        if len(oset(wits)) != len(wits):
            raise ValueError("Invalid wits = {}, has duplicates.".format(wits))
        self.wits = wits

        toad = int(ked["toad"], 16)
        if wits:
            if toad < 1 or toad > len(wits):  # out of bounds toad
                raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
        else:
            if toad != 0:  # invalid toad
                raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
        self.toad = toad

        self.cnfg = ked["cnfg"]
        self.data = None

        # ensure boolean
        self.estOnly = (True if (estOnly if estOnly is not None else self.EstOnly)
                             else False)
        for d in self.cnfg:
            if "trait" in d and d["trait"] == TraitDex.EstOnly:
                self.estOnly = True

        # need this to recognize recovery events
        self.lastEst = Location(sn=self.sn, dig=self.diger.qb64)  # last establishment event location

        # verify signatures
        if not self.verifySigs(sigers=sigers, serder=serder):
            raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigers, serder))

        # verify sith given signatures verify
        if not self.verifySith(sigers=sigers):  # uses self.sith
            self.escrowEvent(self, serder, sigers, self.prefixer.qb64b, self.sn)

            raise ValidationError("Failure verifying sith = {} on sigs for {}"
                                  "".format(self.sith, sigers))

        self.logEvent(serder, sigers)  # update logs


    def update(self, serder,  sigers):
        """
        Not original inception event. So verify event serder and
        indexed signatures in sigers and update state

        """
        if self.nonTrans:  # nonTransferable so no events after inception allowed
            raise ValidationError("Unexpected event = {} in nontransferable "
                                  " state.".format(serder))

        ked = serder.ked
        pre = ked["pre"]
        sn = ked["sn"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large.".format(sn))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {}".format(sn))
        if sn == 0:
            raise ValidationError("Zero sn = {} for non=inception ked = {}."
                                              "".format(sn, ked))
        dig = ked["dig"]  # prior dig
        ilk = ked["ilk"]

        if pre != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {}.".format(pre, self.prefixer.qb64))

        if ilk == Ilks.rot:  # subsequent rotation event
            for k in ROT_LABELS:
                if k not in ked:
                    raise ValidationError("Missing element = {} from {}  event."
                                          "".format(k, Ilks.rot))


            if sn > self.sn + 1:  #  out of order event
                raise ValidationError("Out of order event sn = {} expecting"
                                      " = {}.".format(sn, self.sn+1))

            elif sn <= self.sn:  #  stale or recovery
                #  stale events could be duplicitous
                #  duplicity detection should happend before .update called
                if sn <= self.lastEst.sn :  # stale
                    raise ValidationError("Stale event sn = {} expecting"
                                          " = {}.".format(sn, self.sn+1))

                else:  # sn > self.lastEst.sn  recovery event
                    # fetch last entry of prior events at prior sn = sn -1
                    # need KEL for generator use and KERL for validator
                    pass

                    #entry = self.logs.kels[pre].nabone("{:x}".format(sn - 1))
                    #if dig == entry.serder.dig:
                        #raise ValidationError("Mismatch event dig = {} with dig "
                                              #"= {} at event sn = {}."
                                              #"".format(dig,
                                                        #entry.serder.dig,
                                                        #psn))

            else:  # sn == self.sn +1   new event
                if dig != self.diger.qb64:  # prior event dig not match
                    raise ValidationError("Mismatch event dig = {} with"
                                          " state dig = {}.".format(dig, self.dig.qb64))

            # verify nxt from prior
            # also check derivation code of pre for non-transferable
            #  check and

            if self.nexter is None:   # empty so rotations not allowed
                raise ValidationError("Attempted rotation for nontransferable"
                                      " prefix = {}".format(self.prefixer.qb64))

            verfers = serder.verfers  # only for establishment events

            sith = ked["sith"]
            if isinstance(sith, str):
                sith = int(sith, 16)
                if sith < 1 or sith > len(self.verfers):  # out of bounds sith
                    raise ValueError("Invalid sith = {} for keys = {}".format(sith,
                                          [verfer.qb64 for verfer in verfers]))
            else:
                # fix this to support list sith
                raise ValueError("Unsupported type for sith = {}".format(sith))

            keys = ked["keys"]
            if not self.nexter.verify(sith=sith, keys=keys):
                raise ValidationError("Mismatch nxt digest = {} with rotation"
                                      " sith = {}, keys = {}.".format(nexter.qb64))

            # compute wits from cuts and adds use set
            # verify set math
            witset = oset(self.wits)
            cuts = ked["cuts"]
            cutset = oset(cuts)
            if len(cutset) != len(cuts):
                raise ValueError("Invalid cuts = {}, has duplicates.".format(cuts))

            if (witset & cutset) != cutset:  #  some cuts not in wits
                raise ValueError("Invalid cuts = {}, not all members in wits.".format(cuts))


            adds = ked["adds"]
            addset = oset(adds)
            if len(addset) != len(adds):
                raise ValueError("Invalid adds = {}, has duplicates.".format(adds))

            if cutset & addset:  # non empty intersection
                raise ValueError("Intersecting cuts = {} and  adds = {}.".format(cuts, adds))

            if witset & addset:  # non empty intersection
                raise ValueError("Intersecting wits = {} and  adds = {}.".format(self.wits, adds))

            wits = list((witset - cutset) | addset)

            if len(wits) != (len(self.wits) - len(cuts) + len(adds)):  # redundant?
                raise ValueError("Invalid member combination among wits = {}, cuts ={}, "
                                 "and adds = {}.".format(self.wits, cuts, adds))

            toad = int(ked["toad"], 16)
            if wits:
                if toad < 1 or toad > len(wits):  # out of bounds toad
                    raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))
            else:
                if toad != 0:  # invalid toad
                    raise ValueError("Invalid toad = {} for wits = {}".format(toad, wits))

            # prior nxt valid so verify sigers using new verifier keys from event
            # rotation event use keys from event
            # verify indexes of attached signatures against verifiers
            for siger in sigers:
                if siger.index >= len(verfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(siger.index))
                siger.verfer = verfers[siger.index]  # assign verfer

            if not self.verifySigs(sigers=sigers, serder=serder):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigers, serder))

            # verify sith given signatures verify
            if not self.verifySith(sigers=sigers, sith=sith):  # uses new sith
                self.escrowEvent(self, serder, sigers, self.prefixer.qb64b, sn)
                raise ValidationError("Failure verifying sith = {} on sigs for {}"
                                      "".format(self.sith, sigers))

            # nxt and signatures verify so update state
            self.sn = sn
            self.diger = serder.diger
            self.ilk = ilk
            self.sith = sith
            self.verfers = verfers
            # update .nexter
            nxt = ked["nxt"]
            self.nexter = Nexter(qb64=nxt) if nxt else None  # check for empty
            if self.nexter is None:
                self.nonTrans = True

            self.toad = toad
            self.wits = wits
            self.data = ked["data"]

            # last establishment event location need this to recognize recovery events
            self.lastEst = Location(sn=self.sn, dig=self.diger.qb64)

            self.logEvent(serder, sigers)  # update logs


        elif ilk == Ilks.ixn:  # subsequent interaction event
            if self.estOnly:
                raise ValidationError("Unexpected non-establishment event = {}."
                                  "".format(serder))

            for k in IXN_LABELS:
                if k not in ked:
                    raise ValidationError("Missing element = {} from {} event."
                                          "".format(k, Ilks.ixn))

            if not sn == (self.sn + 1):  # sn not in order
                raise ValidationError("Invalid sn = {} expecting = {}.".format(sn, self.sn+1))

            if dig != self.diger.qb64:  # prior event dig not match
                raise ValidationError("Mismatch event dig = {} with"
                                      " state dig = {}.".format(dig, self.dig.qb64))


            # interaction event use keys from existing Kever
            # use prior .verfers
            # verify indexes of attached signatures against verifiers
            for siger in sigers:
                if siger.index >= len(self.verfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(siger.index))
                siger.verfer = self.verfers[siger.index]  # assign verfer

            if not self.verifySigs(sigers=sigers, serder=serder):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigers, serder))

            # verify sith given signatures verify
            if not self.verifySith(sigers=sigers):  # uses self.sith
                self.escrowEvent(self, serder, sigers, self.prefixer.qb64b, sn)
                raise ValidationError("Failure verifying sith = {} on sigs for {}"
                                      "".format(self.sith, sigers))

            # update state
            self.sn = sn
            self.diger = serder.diger
            self.ilk = ilk

            self.logEvent(serder, sigers)  # update logs

        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {}.".format(ilk))


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
            raise ValueError("Unsupported type for sith ={}".format(sith))

        if len(sigers) < sith:  # not meet threshold fix for list sith
            return False

        return True

    def logEvent(self, serder, sigers):
        """
        Update associated logs for verified event

        Parameters:
            serder is Serder instance of current event
            sigers is list of Siger instance for current event
        """
        dgkey = dgKey(self.prefixer.qb64b, self.diger.qb64b)
        self.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.logger.putEvt(dgkey, serder.raw)
        self.logger.addKe(snKey(self.prefixer.qb64b, self.sn), self.diger.qb64b)

    def escrowEvent(self, serder, sigers, pre, sn):
        """
        Update associated logs for escrow of partially signed event

        Parameters:
            serder is Serder instance of  event
            sigers is list of Siger instance for  event
            pre is str qb64 ofidentifier prefix of event
            sn is int sequence number of event
        """
        dgkey = dgKey(pre, serder.digb)
        self.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
        self.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
        self.logger.putEvt(dgkey, serder.raw)
        self.logger.addPses(snKey(pre, sn), serder.digb)


class Kevery:
    """
    Kevery is Kever (KERI key event verifier) instance factory which are
    extracted from a key event stream of event and attached signatures

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .kevers is dict of existing kevers indexed by pre (qb64) of each Kever
        .logs is named tuple of logs
        .framed is Boolean stream is packet framed If True Else not framed

    Properties:

    """
    def __init__(self, kevers=None, logger=None, framed=True):
        """
        Set up event stream and logs

        """
        self.framed = True if framed else False  # extract until end-of-stream
        self.kevers = kevers if kevers is not None else dict()

        if logger is None:
            logger = Logger()  # default name = "main"
        self.logger = logger


    def extractOne(self, kes, framed=True):
        """
        Extract one event with attached signatures from key event stream kes
        Returns: (serder, sigers)

        Parameters:
            kes is bytearray of serialized key event stream.
                May contain one or more sets each of a serialized event with
                attached signatures.

            framed is Boolean, If True and no sig counter then extract signatures
                until end-of-stream. This is useful for framed packets with
                one event and one set of attached signatures per invocation.

        """
        # deserialize packet from kes
        try:
            serder = Serder(raw=kes)
        except Exception as ex:
            raise ValidationError("Error while processing key event stream"
                                  " = {}".format(ex))

        version = serder.version
        if version != Version:  # This is where to dispatch version switch
            raise VersionError("Unsupported version = {}, expected {}."
                                  "".format(version, Version))

        del kes[:serder.size]  # strip off event from front of kes

        # extact sig counter if any
        try:
            counter = SigCounter(qb64=kes)  # qb64
            nsigs = counter.count
            del kes[:len(counter.qb64)]  # strip off counter
        except ValidationError as ex:
            nsigs = 0  # no signature count

        # extract attached sigs as Sigers
        sigers = []  # list of Siger instances for attached indexed signatures
        if nsigs:
            for i in range(nsigs): # extract each attached signature
                # check here for type of attached signatures qb64 or qb2
                siger = Siger(qb64=kes)  # qb64
                sigers.append(siger)
                del kes[:len(siger.qb64)]  # strip off signature

        else:  # no info on attached sigs
            if framed:  # parse for signatures until end-of-stream
                while kes:
                    # check here for type of attached signatures qb64 or qb2
                    siger = Siger(qb64=kes)  # qb64
                    sigers.append(siger)
                    del kes[:len(siger.qb64)]  # strip off signature

        if not sigers:
            raise ValidationError("Missing attached signature(s).")

        return (serder, sigers)


    def processOne(self, serder, sigers):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:
            kes is bytearray of serialized key event stream.
                May contain one or more sets each of a serialized event with
                attached signatures.

        """
        # fetch ked ilk  pre, sn, dig to see how to process
        ked = serder.ked
        try:  # see if pre in event validates
            prefixer = Prefixer(qb64=ked["pre"])
        except Exception as ex:
            raise ValidationError("Invalid pre = {}.".format(ked["pre"]))
        pre = prefixer.qb64
        ked = serder.ked
        ilk = ked["ilk"]

        sn = ked["sn"]
        if len(sn) > 32:
            raise ValidationError("Invalid sn = {} too large.".format(sn))
        try:
            sn = int(sn, 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {}".format(sn))
        dig = serder.dig

        if self.logger.getEvt(dgKey(pre, dig)) is not None:
            # performance log duplicate event
            return  # discard duplicate

        if pre not in self.kevers:  #  first seen event for pre
            if ilk == Ilks.icp:  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem adds to KEL Kevers
                # create kever from serder
                kever = Kever(serder=serder,
                              sigers=sigers,
                              logger=self.logger)
                self.kevers[pre] = kever

            else:  # not inception so can't verify, add to escrow
                # log escrowed
                dgkey = dgKey(pre, dig)
                self.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                self.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                self.logger.putEvt(dgkey, serder.raw)
                self.logger.addOoes(snKey(pre, sn), dig)


        else:  # already accepted inception event for pre
            if ilk == Ilks.icp:  # inception event so maybe duplicitous
                # log duplicitous
                dgkey = dgKey(pre, dig)
                self.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                self.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                self.logger.putEvt(dgkey, serder.raw)
                self.logger.addLdes(snKey(pre, sn), dig)

            else:  # rot or ixn, so sn matters
                kever = self.kevers[pre]  # get existing kever for pre
                sno = kever.sn + 1  # proper sn of new inorder event

                if sn > sno:  # sn later than sno so out of order escrow
                    #  log escrowed
                    dgkey = dgKey(pre, dig)
                    self.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                    self.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                    self.logger.putEvt(dgkey, serder.raw)
                    self.logger.addOoes(snKey(pre, sn), dig)

                elif ((sn == sno) or  # new inorder event
                      (ilk == Ilks.rot and kever.lastEst.sn < sn <= sno )):  # recovery
                    # verify signatures etc and update state if valid
                    # raise exception if problem. adds to KELs
                    kever.update(serder=serder, sigers=sigers)

                else:  # maybe duplicitous
                    # log duplicitous
                    dgkey = dgKey(pre, dig)
                    self.logger.putDts(dgkey, nowIso8601().encode("utf-8"))
                    self.logger.putSigs(dgkey, [siger.qb64b for siger in sigers])
                    self.logger.putEvt(dgkey, serder.raw)
                    self.logger.addLdes(snKey(pre, sn), dig)


    def processAll(self, kes):
        """

        """
        if not isinstance(kes, bytearray):  # destructive processing
            kes = bytearray(kes)

        while kes:
            try:
                serder, sigers = self.extractOne(kes=kes, framed=self.framed)
            except Exception as ex:
                # log diagnostics errors etc
                # error extracting means bad key event stream
                del kes[:]  #  delete rest of stream
                continue

            try:
                self.processOne(serder=serder, sigers=sigers)
            except Exception as  ex:
                # log diagnostics errors etc
                continue


    def duplicity(self, serder, sigers):
        """
        Processes potential duplicitous events in PDELs

        Handles duplicity detection and logging if duplicitous

        Placeholder here for logic need to move

        """

        # fetch ked ilk  pre, sn, dig to see how to process
        ked = serder.ked
        try:  # see if pre in event validates
            prefixer = Prefixer(qb64=ked["pre"])
        except Exception as ex:
            raise ValidationError("Invalid pre = {}.".format(ked["pre"]))
        pre = prefixer.qb64
        ked = serder.ked
        ilk = ked["ilk"]
        try:
            sn = int(ked["sn"], 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {}".format(ked["sn"]))
        dig = serder.dig

        #if dig in DELPs["pre"]:
            #return

        if ilk == Ilks.icp:  # inception event so maybe duplicitous
            # Using Kever for cheap duplicity detection of inception events
            # kever init verifies basic inception stuff and signatures
            # raises exception if problem.
            kever = Kever(serder=serder, sigers=siger, logger=self.logger)  # create kever from serder
            # No exception above so verified duplicitous event
            # log it and add to DELS if first time
            #if pre not in DELs:  #  add to DELS
                #DELs[pre] = dict()
            #if dig not in DELS[pre]:
                #DELS[pre][dig] = LogEntry(serder=serder, sigers=sigers)

        else:
            pass
