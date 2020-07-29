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

import cbor2 as cbor
import msgpack
import pysodium
import blake3

from ..kering import ValidationError, VersionError, EmptyMaterialError, DerivationError
from ..kering import Versionage, Version
from .coring import Ilks

from .coring import Signer, Verifier, Digester, Nexter, Aider


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

Traitdex = TraitCodex()  # Make instance

Kevage = namedtuple("Kevage", 'serder sigs')  # Key Event tuple for KELS and DELs

Kevers = dict()  # dict of existing Kevers indexed by aid.qb64 of each Kever

KELs = dict() # dict of dicts of ordered events keyed by aid.qb64 then by event dig

DELs = dict()  # dict of dicts of dup events keyed by aid.qb64 then by event dig

Escrows = dict()

class Kevery:
    """
    Kevery is Kever (KERI key event verifier) instance factory which are
    extracted from a key event stream of event and attached signatures

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:

    Properties:

    """
    def __init__(self):
        """
        Set up event stream

        """


    def processAll(self, kes):
        """

        """
        if not isinstance(kes, bytearray):  # destructive processing
            kes = bytearray(kes)

        while kes:
            try:
                serder, sigs = self.extractOne(kes)
            except Exception as  ex:
                # log diagnostics errors etc
                del kes[:]  # error extracting means bad key event stream
                continue

            try:
                self.processOne(serder, sigs)
            except Exception as  ex:
                # log diagnostics errors etc
                pass

    def extractOne(self, kes):
        """
        Extract one event with attached signatures from key event stream kes
        Returns: (serder, sigs)

        Parameters:
            kes is bytearray of serialized key event stream.
                May contain one or more sets each of a serialized event with
                attached signatures.

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

        del kes[:srdr.size]  # strip off event from front of kes

        # extract attached sigs if any
        # protocol dependent if http may use http header instead of stream

        ked = serder.ked
        keys = ked["keys"]
        sigs = []  # list of SigMat instances for attached signatures
        if "idxs" in ked and ked["idxs"]: # extract signatures given indexes
            indexes = ked["idxs"]
            if isinstance(indexes, str):
                nsigs = int(indexes, 16)
                if nsigs < 1:
                    raise ValidationError("Invalid number of attached sigs = {}."
                                              " Must be > 1 if not empty.".format(nsigs))

                for i in range(nsigs): # extract each attached signature
                    # check here for type of attached signatures qb64 or qb2
                    sig = SigMat(qb64=kes)  #  qb64
                    sigs.append(sig)
                    del kes[:len(sig.qb64)]  # strip off signature

                    if sig.index >= len(keys):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(sig.index))

            elif isinstance(indexes, list):
                if len(set(indexes)) != len(indexes):  # duplicate index(es)
                    raise ValidationError("Duplicate indexes in sigs = {}."
                                              "".format(indexes))

                for index in indexes:
                    # check here for type of attached signatures qb64 or qb2
                    sig = SigMat(qb64=kes)  #  qb64
                    sigs.append(sig)
                    del kes[:len(sig.qb64)]  # strip off signature

                    if sig.index >= len(keys):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(sig.index))

                    if index != sig.index:
                        raise ValidationError("Mismatching signature index = {}"
                                              " with index = {}".format(sig.index,
                                                                        index))

            else:
                raise ValidationError("Invalid format of indexes = {}."
                                          "".format(indexes))

        else:  # no info on attached sigs
            pass
            #  check flag if should parse rest of stream for attached sigs
            #  or should parse for index block

        if not sigs:
            raise ValidationError("Missing attached signature(s).")

        return (serder, sigs)

    def processOne(self, serder, sigs):
        """
        Process one event with attached signatures

        Parameters:
            serder is Serder instance of event
            sigs is list of SigMat instances of attached signatures

        """
        # Verify serder.ked fields based on ked ilk and version.
        # If missing fields then raise error.

        # extract aid, sn, ilk to see how to process

        dig = serder.dig
        try:
            aider = Aider(qb64=ked["id"])
        except Exception as ex:
            raise ValidationError("Invalid aid = {}.".format(ked["id"]))

        aid = aider.qb64
        ked = serder.ked
        ilk = ked["ilk"]

        try:
            sn = int(ked["sn"], 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {}".format(ked["sn"]))


        if aid not in KELs:  #  first seen event for aid
            if ilk == Ilks.icp:  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem adds to KEL Kevers
                kever = Kever(serder=serder, sigs=sigs)  # create kever from serder

            else:  # not inception so can't verify add to escrow
                # log escrowed
                if aid not in Escrows:  #  add to Escrows
                    Escrows[aid] = dict()
                if dig not in Escrows[aid]:
                    Escrows[aid][dig] = Kevage(serder=serder, sigs=sigs)


        else:  # already accepted inception event for aid
            if dig in KELs["aid"]:  #  duplicate event so dicard
                # log duplicate
                return  # discard

            if ilk == Ilks.icp:  # inception event so maybe duplicitous
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem
                kever = Kever(serder=serder, sigs=sigs)  # create kever from serder

                #  verified duplicitous event log it and add to DELS if first time
                if aid not in DELs:  #  add to DELS
                    DELs[aid] = dict()
                if dig not in DELS[aid]:
                    DELS[aid][dig] = Kevage(serder=serder, sigs=sigs)

            else:
                kever = Kevers[aid]  # get existing kever for aid
                # if sn not subsequent to prior event  else escrow
                if sn <= kever.sn:  # stale event
                    # log stale event
                    return  # discard

                if sn > kever.sn + 1:  # sn not in order
                    #  log escrowed
                    if aid not in Escrows:  #  add to Escrows
                        Escrows[aid] = dict()
                    if dig not in Escrows[aid]:
                        Escrows[aid][dig] = Kevage(serder=serder, sigs=sigs)

                else:  # sn == kever.sn + 1
                    if dig != kever.dig:  # prior event dig not match
                        raise ValidationError("Mismatch prior dig = {} with"
                                              " current = {}.".format(dig,
                                                                      kever.dig))

                    # verify signatures etc and update state if valid
                    # raise exception if problem. adds to KELs
                    kever.update(serder=serder, sigs=sigs)








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
        .serder is Serder instance of current packet
        .sigs is list of SigMat instances of signatures
        .verifiers is list of Verifier instances of current signing keys
        .version is version of current event
        .aider is aider instance
        .sn is sequence number int
        .dig is qualified qb64 digest of event not prior event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .conf is list of inception configuration data mappings
        .estOnly is boolean

    Properties:

    """
    EstOnly = False

    def __init__(self, serder, sigs, estOnly=None):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigs raises ValidationError if not

        Parameters:
            serder is Serder instance of inception event
            sigs is list of SigMat instances of signatures of event
            establishOnly is boolean trait to indicate establish only event

        """
        self.serder = serder
        self.verifiers = serder.verifiers  # converts keys to verifiers
        self.sigs = sigs
        ked = self.serder.ked
        sith = ked["sith"]
        if isinstance(sith, str):
            self.sith =  int(sith, 16)
        else:
            # fix this to support list sith
            raise ValueError("Unsupported type for sith = {}".format(sith))

        if not self.verify():
            raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigs, serder))

        self.version = self.serder.version  # version switch?

        self.aider = Aider(qb64=ked["id"])
        if not self.aider.verify(ked=ked):  # invalid aid
            raise ValidationError("Invalid aid = {} for inception ked = {}."
                                  "".format(self.aider.qb64, ked))

        self.sn = int(ked["sn"], 16)
        if self.sn != 0:
            raise ValidationError("Invalid sn = {} for inception ked = {}."
                                              "".format(self.sn, ked))
        self.dig = self.serder.dig

        self.ilk = ked["ilk"]
        if self.ilk != Ilks.icp:
            raise ValidationError("Expected ilk = {} got {}."
                                              "".format(Ilks.icp, self.ilk))
        self.nexter = Nexter(qb64=ked["next"]) if ked["next"] else None  # check for empty
        self.toad = int(ked["toad"], 16)
        self.wits = ked["wits"]
        self.conf = ked["conf"]

        # ensure boolean
        self.estOnly = (True if (estOnly if estOnly is not None else self.EstOnly)
                             else False)
        for d in self.conf:
            if "trait" in d and d["trait"] == Traitdex.EstOnly:
                self.estOnly = True

        aid = self.aider.qb64
        if aid not in KELs:
            KELs[aid] = dict()
        KELs[aid][self.dig] = Kevage(serder=serder, sigs=sigs)
        if aid not in Kevers:
            Kevers[aid] = dict()
        Kevers[aid][self.dig] = self



    def verify(self, sigs=None, serder=None, sith=None, verifiers=None):
        """
        Verify sigs against serder using sith and verifiers
        Assumes that sigs already extracted correctly wrt indexes
        If any of serder, sith, verifiers not provided then replace missing
           value with respective attribute .serder, .sith .verifiers instead

        Parameters:
            sigs is list of SigMat instances
            serder is Serder instance
            sith is int threshold
            verifiers is list of Verifier instances

        """
        sigs = sigs if sigs is not None else self.sigs
        serder = serder if serder is not None else self.serder
        sith = sith if sith is not None else self.sith
        verifiers = verifiers if verifiers is not None else self.verifiers

        for sig in sigs:
            verifier = verifiers[sig.index]
            if not verifier.verify(sig.raw, serder.raw):
                return False

        if not isinstance(sith, int):
            raise ValueError("Unsupported type for sith ={}".format(sith))
        if len(sigs) < sith:  # not meet threshold fix for list sith
            return False

        return True



    def update(self, serder,  sigs):
        """

        """
        # if rotation event use keys from event
        # if interaction event use keys from existing Kever
        ked = serder.ked
        ilk = ked["ilk"]

        if ilk == Ilks.rot:  # subsequent rotation event
            # verify next from prior
            # also check derivation code of aid for non-transferable
            #  check and

            if self.nexter is None:   # empty so rotations not allowed
                raise ValidationError("Attempted rotation for nontransferable"
                                      " aid = {}".format(self.aider.qb64))

            sith = ked["sith"]
            if isinstance(sith, str):
                sith =  int(ked.sith, 16)
            else:
                # fix this to support list sith
                raise ValueError("Unsupported type for sith = {}".format(sith))

            keys = ked["keys"]
            if not self.nexter.verify(sith=sith, keys=keys):
                raise ValidationError("Mismatch next digest = {} with rotation"
                                      " sith = {}, keys = {}.".format(nexter.qb64))


            # prior next valid so verify sigs using new verifier keys from event
            if not self.verify(serder.serder,
                               sigs=sigs,
                               sith=sith,
                               verifiers=serder.verifiers):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigs, serder))

            # next and signatures verify so update state
            self.sn = sn
            self.dig = dig
            self.sith = sith
            self.verifiers = serder.verifiers
            # verify nxt prior
            nexter = Nexter(qb64=ked["next"]) if nxt else None  # check for empty
            # update non transferable if None
            self.nexter = nexter
            self.toad = int(ked["toad"], 16)
            self.wits = ked["wits"]
            self.conf = ked["conf"]


            KELS[aid][dig] = Kevage(serder=serder, sigs=sigs)


        elif ilk == Ilks.ixn:  # subsequent interaction event
            if self.estOnly:
                raise ValidationError("Unexpected non-establishment event = {}."
                                  "".format(serder))
            if not self.verify(serder=serder, sigs=sigs):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigs, serder))

            # update state
            self.sn = sn
            self.dig = dig
            KELS[aid][dig] = Kevage(serder=serder, sigs=sigs)


        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {}.".format(ilk))





class Keger:
    """
    Keger is KERI key event generator class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .version is version of current event
        .aid is fully qualified qb64 autonomic id
        .sn is sequence number
        .predig is qualified qb64 digest of previous event
        .dig is qualified qb64 dige of current event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .keys is list of qb64 current verification keys
        .nxt is qualified qb64 of next sith plus next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .conf is list of inception configuration data mappings
        .indexes is int or list of signature indexes of current event if any

    Properties:



    """
    def __init__(self):
        """
        Extract and verify event and attached signatures from key event stream kes

        Parameters:


        """
        # initial state is vacuous
        self.version = None
        self.aid = None
        self.sn =  None
        self.predig = None
        self.dig = None
        self.ilk = None
        self.sith = None
        self.keys = []
        self.nxt = None
        self.toad = None
        self.wits = None
        self.conf = None
        self.indexes = None

