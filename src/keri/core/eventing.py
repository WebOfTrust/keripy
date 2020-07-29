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

from .coring import Signer, Verfer, Diger, Nexter, Aider


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

Kevage = namedtuple("Kevage", 'serder sigxers')  # Key Event tuple for KELS and DELs

Kevers = dict()  # dict of existing Kevers indexed by aid.qb64 of each Kever

KELs = dict()  # dict of dicts of events keyed by aid.qb64 then in order by event sn
KELDs = dict()  # dict of dicts of events keyed by aid.qb64 then by event dig
DELs = dict()  # dict of dicts of dup events keyed by aid.qb64 then by event dig

Escrows = dict()






class Keger:
    """
    Keger is KERI key event generator class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .version is version of current event
        .aid is fully qualified qb64 autonomic id
        .sn is sequence number
        .diger is qualified qb64 dige of current event
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
        self.aider = None
        self.sn =  None
        self.diger = None
        self.ilk = None
        self.sith = None
        self.keys = []
        self.nxt = None
        self.toad = None
        self.wits = None
        self.conf = None
        self.indexes = None


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
        .aider is aider instance of current event state
        .sn is sequence number int
        .diger is Diger instance with digest of current event not prior event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .verfers is list of Verfer instances for current event state set of signing keys
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .conf is list of inception configuration data mappings
        .estOnly is boolean

    Properties:

        .nonTransferable  .nonTrans

    """
    EstOnly = False

    def __init__(self, serder, sigxers, estOnly=None):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigxers raises ValidationError if not

        Parameters:
            serder is Serder instance of inception event
            sigxers is list of SigMat instances of signatures of event
            establishOnly is boolean trait to indicate establish only event

        """
        # update state as we go because if invalid we fail to finish init
        self.version =  serder.version  # version dispatch ?
        self.verfers = serder.verfers  # converts keys to verifiers
        # verify indexes of attached signatures against verifiers
        for sigxer in sigxers:
            if sigxer.index >= len(self.verfers):
                raise ValidationError("Index = {} to large for keys."
                                      "".format(sigxer.index))
            sigxer.verfer = self.verfers[sigxer.index]  # assign verfer

        ked = serder.ked
        sith = ked["sith"]
        if isinstance(sith, str):
            self.sith =  int(sith, 16)
        else:
            # fix this to support list sith
            raise ValueError("Unsupported type for sith = {}".format(sith))

        if not self.verify(sigxers=sigxers, serder=serder):
            raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigxers, serder))

        self.aider = Aider(qb64=ked["id"])
        if not self.aider.verify(ked=ked):  # invalid aid
            raise ValidationError("Invalid aid = {} for inception ked = {}."
                                  "".format(self.aider.qb64, ked))

        self.sn = int(ked["sn"], 16)
        if self.sn != 0:
            raise ValidationError("Invalid sn = {} for inception ked = {}."
                                              "".format(self.sn, ked))
        self.diger =  serder.diger

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
            if "trait" in d and d["trait"] == TraitDex.EstOnly:
                self.estOnly = True

        aid = self.aider.qb64
        if aid not in KELDs:
            KELDs[aid] = dict()
        KELDs[aid][self.diger.qb64] = Kevage(serder=serder, sigxers=sigxers)
        if aid not in Kevers:
            Kevers[aid] = dict()
        Kevers[aid][self.diger] = self


    def update(self, serder,  sigxers):
        """
        Not original inception event. So verify event serder and
        signatures sigxers and update state

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


            # prior next valid so verify sigxers using new verifier keys from event
            verfers = serder.verfers  # only for establishment events

            # verify indexes of attached signatures against verifiers
            for sigxer in sigxers:
                if sigxer.index >= len(verfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(sigxer.index))
                sigxer.verfer = verfers[sigxer.index]  # assign verfer

            if not self.verify(sigxers=sigxers, serder=serder, sith=sith):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigxers, serder))

            # next and signatures verify so update state
            self.verfers = verfers
            self.sith = sith
            self.sn = sn
            self.diger = serder.diger

            # update .nexter
            nexter = Nexter(qb64=ked["next"]) if nxt else None  # check for empty
            # update nontransferable  if None
            self.nexter = nexter
            self.toad = int(ked["toad"], 16)
            self.wits = ked["wits"]
            self.conf = ked["conf"]


            KELS[aid][self.diger.qb64] = Kevage(serder=serder, sigxers=sigxers)


        elif ilk == Ilks.ixn:  # subsequent interaction event
            if self.estOnly:
                raise ValidationError("Unexpected non-establishment event = {}."
                                  "".format(serder))

            # use prior .verfers
            # verify indexes of attached signatures against verifiers
            for sigxer in sigxers:
                if sigxer.index >= len(self.verfers):
                    raise ValidationError("Index = {} to large for keys."
                                          "".format(sigxer.index))
                sigxer.verfer = self.verfers[sigxer.index]  # assign verfer

            if not self.verify(sigxers=sigxers, serder=serder):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigxers, serder))

            # update state
            self.sn = sn
            self.diger = serder.diger
            KELS[aid][self.diger.qb64] = Kevage(serder=serder, sigxers=sigxers)


        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {}.".format(ilk))


    def verify(self, sigxers, serder, sith=None):
        """
        Use verfer in each sigxer to verify signature against serder with sith
        Assumes that sigxers with verfer already extracted correctly wrt indexes
        If sith not provided then use .sith instead

        Parameters:
            sigxers is list of Sigxer instances
            serder is Serder instance
            sith is int threshold

        """
        sith = sith if sith is not None else self.sith

        for sigxer in sigxers:
            if not sigxer.verfer.verify(sigxer.raw, serder.raw):
                return False

        if not isinstance(sith, int):
            raise ValueError("Unsupported type for sith ={}".format(sith))
        if len(sigxers) < sith:  # not meet threshold fix for list sith
            return False

        return True





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
                self.processOne(kes)
            except Exception as  ex:
                # log diagnostics errors etc
                del kes[:]  # error extracting means bad key event stream
                continue


    def processOne(self, kes):
        """
        Process one event with attached signatures from key event stream kes

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


        # fetch ked ilk  aid, sn, dig to see how to finish extraction
        ked = serder.ked
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
        dig = serder.dig



        # extract attached sigs as Sigxers
        sigxers = []  # list of Sigxer instances for attached indexed signatures
        if "idxs" in ked and ked["idxs"]: # extract signatures given indexes
            indexes = ked["idxs"]
            if isinstance(indexes, str):
                nsigs = int(indexes, 16)
                if nsigs < 1:
                    raise ValidationError("Invalid number of attached sigs = {}."
                                              " Must be > 1 if not empty.".format(nsigs))

                for i in range(nsigs): # extract each attached signature
                    # check here for type of attached signatures qb64 or qb2
                    sigxer = Sigxer(qb64=kes)  #  qb64
                    sigxers.append(sigxer)
                    del kes[:len(sigxer.qb64)]  # strip off signature

            elif isinstance(indexes, list):
                if len(set(indexes)) != len(indexes):  # duplicate index(es)
                    raise ValidationError("Duplicate indexes in sigs = {}."
                                              "".format(indexes))

                for index in indexes:
                    # check here for type of attached signatures qb64 or qb2
                    sigxer = SigMat(qb64=kes)  #  qb64
                    sigxers.append(sigxer)
                    del kes[:len(sigxer.qb64)]  # strip off signature

                    if index != sigxer.index:
                        raise ValidationError("Mismatching signature index = {}"
                                              " with index = {}".format(sigxer.index,
                                                                        index))
            else:
                raise ValidationError("Invalid format of indexes = {}."
                                          "".format(indexes))

        else:  # no info on attached sigs
            pass
            #  check flag if should parse rest of stream for attached sigs
            #  or should parse for index block

        if not sigxers:
            raise ValidationError("Missing attached signature(s).")





        if aid not in KELDs:  #  first seen event for aid
            if ilk == Ilks.icp:  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem adds to KEL Kevers
                kever = Kever(serder=serder, sigxers=sigxers)  # create kever from serder

            else:  # not inception so can't verify add to escrow
                # log escrowed
                if aid not in Escrows:  #  add to Escrows
                    Escrows[aid] = dict()
                if dig not in Escrows[aid]:
                    Escrows[aid][dig] = Kevage(serder=serder, sigxers=sigxers)


        else:  # already accepted inception event for aid
            if dig in KELDs["aid"]:  #  duplicate event so dicard
                # log duplicate
                return  # discard

            if ilk == Ilks.icp:  # inception event so maybe duplicitous
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem
                kever = Kever(serder=serder, sigxers=sigxers)  # create kever from serder

                #  verified duplicitous event log it and add to DELS if first time
                if aid not in DELs:  #  add to DELS
                    DELs[aid] = dict()
                if dig not in DELS[aid]:
                    DELS[aid][dig] = Kevage(serder=serder, sigxers=sigxers)

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
                        Escrows[aid][dig] = Kevage(serder=serder, sigxers=sigxers)

                else:  # sn == kever.sn + 1
                    if dig != kever.diger:  # prior event dig not match
                        raise ValidationError("Mismatch prior dig = {} with"
                                              " current = {}.".format(dig,
                                                                      kever.diger))

                    # verify signatures etc and update state if valid
                    # raise exception if problem. adds to KELs
                    kever.update(serder=serder, sigxers=sigxers)


    def extractOne(self, kes):
        """
        Extract one event with attached signatures from key event stream kes
        Returns: (serder, sigxers)

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

        # extract attached sigs as Sigers if any
        # protocol dependent if http may use http header instead of stream
        # matching sigxers to keys only works if establishment event
        # interaction events do not have keys but use prior keys of most recent
        # establishment event

        ked = serder.ked

        # extract aid, sn, ilk to see how to finish extraction

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


        verfers = serder.verfers  # only for establishment events

        sigxers = []  # list of Sigxer instances for attached indexed signatures
        if "idxs" in ked and ked["idxs"]: # extract signatures given indexes
            indexes = ked["idxs"]
            if isinstance(indexes, str):
                nsigs = int(indexes, 16)
                if nsigs < 1:
                    raise ValidationError("Invalid number of attached sigs = {}."
                                              " Must be > 1 if not empty.".format(nsigs))

                for i in range(nsigs): # extract each attached signature
                    # check here for type of attached signatures qb64 or qb2
                    sigxer = Sigxer(qb64=kes)  #  qb64
                    sigxers.append(sigxer)
                    del kes[:len(sigxer.qb64)]  # strip off signature

                    if sigxer.index >= len(verfers):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(sigxer.index))
                    sigxer.verfer = verfers[sigxer.index]  # assign verfer

            elif isinstance(indexes, list):
                if len(set(indexes)) != len(indexes):  # duplicate index(es)
                    raise ValidationError("Duplicate indexes in sigs = {}."
                                              "".format(indexes))

                for index in indexes:
                    # check here for type of attached signatures qb64 or qb2
                    sigxer = SigMat(qb64=kes)  #  qb64
                    sigxers.append(sigxer)
                    del kes[:len(sigxer.qb64)]  # strip off signature

                    if sigxer.index >= len(verfers):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(sigxer.index))

                    if index != sigxer.index:
                        raise ValidationError("Mismatching signature index = {}"
                                              " with index = {}".format(sigxer.index,
                                                                        index))
                    sigxer.verfer = verfers[sigxer.index]  # assign verfer

            else:
                raise ValidationError("Invalid format of indexes = {}."
                                          "".format(indexes))

        else:  # no info on attached sigs
            pass
            #  check flag if should parse rest of stream for attached sigs
            #  or should parse for index block

        if not sigxers:
            raise ValidationError("Missing attached signature(s).")

        return (serder, sigxers)
