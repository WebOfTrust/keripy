from collections import namedtuple
from dataclasses import dataclass, astuple

import blake3
import json

from keri.db.dbing import Baser, fnKey, dgKey, snKey
from keri.core.coring import (Matter, MtrDex, Serder, Serials, Versify, Prefixer,
                              Ilks, Seqner, Verfer)
from keri.core.eventing import SealEvent, ample, TraitDex, verifySigs, validateSN
from keri.kering import EmptyMaterialError, DerivationError, MissingWitnessSignatureError, Version, MissingAnchorError
from keri.vdr.viring import Registry, nsKey

from orderedset import OrderedSet as oset
from .. import help

logger = help.ogler.getLogger()

VCP_LABELS = ["v", "i", "s", "t", "bt", "b", "c"]


def incept(
        pre,
        toad=None,
        baks=None,
        cnfg=None,
        version=Version,
        kind=Serials.json,
        code=None,
):
    """

    Returns serder of vcp message event
    Utility function to create a Registry inception event

    Parameters:
         pre is issuer identifier prefix qb64
         cnfg is list of strings TraitDex of configuration traits
         toad is int, or str hex of backer threshold
         baks is the initial list of backers prefixes for VCs in the Registry

         version is the API version
         kind is the event type
         code is default code for Prefixer

    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 0
    ilk = Ilks.vcp

    cnfg = cnfg if cnfg is not None else []

    baks = baks if baks is not None else []
    if TraitDex.NoBackers in cnfg and len(baks) > 0:
        raise ValueError("{} backers specified for NB vcp, 0 allowed".format(len(baks)))

    if len(oset(baks)) != len(baks):
        raise ValueError("Invalid baks = {}, has duplicates.".format(baks))

    if isinstance(toad, str):
        toad = "{:x}".format(toad)
    elif toad is None:
        if not baks:
            toad = 0
        else:  # compute default f and m for len(baks)
            toad = ample(len(baks))

    if baks:
        if toad < 1 or toad > len(baks):  # out of bounds toad
            raise ValueError("Invalid toad = {} for baks = {}".format(toad, baks))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for baks = {}".format(toad, baks))

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               ii=pre,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
               c=cnfg,
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=baks  # list of qb64 may be empty
               )

    prefixer = Prefixer(ked=ked, code=code, allows=[MtrDex.Blake3_256])  # Derive AID from ked and code
    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64

    return Serder(ked=ked)  # return serialized ked


def rotate(
        regk,
        dig,
        sn=1,
        toad=None,
        baks=None,
        cuts=None,
        adds=None,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of vrt message event
    Utility function to create a Registry rotation event

    Parameters:
        pre is identifier prefix qb64
        regk is regsitry identifier prefix qb64
        sn is int sequence number
        toad is int or str hex of witness threshold
        baks is list of prior backers prefixes qb64
        cuts is list of witness prefixes to cut qb64
        adds is list of witness prefixes to add qb64

    """

    if sn < 1:
        raise ValueError("Invalid sn = {} for vrt.".format(sn))

    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.vrt

    baks = baks if baks is not None else []
    bakset = oset(baks)
    if len(bakset) != len(baks):
        raise ValueError("Invalid baks = {}, has duplicates.".format(baks))

    cuts = cuts if cuts is not None else []
    cutset = oset(cuts)
    if len(cutset) != len(cuts):
        raise ValueError("Invalid cuts = {}, has duplicates.".format(cuts))

    if (bakset & cutset) != cutset:  # some cuts not in wits
        raise ValueError("Invalid cuts = {}, not all members in baks.".format(cuts))

    adds = adds if adds is not None else []
    addset = oset(adds)
    if len(addset) != len(adds):
        raise ValueError("Invalid adds = {}, has duplicates.".format(adds))

    if cutset & addset:  # non empty intersection
        raise ValueError("Intersecting cuts = {} and  adds = {}.".format(cuts, adds))

    if bakset & addset:  # non empty intersection
        raise ValueError("Intersecting baks = {} and  adds = {}.".format(baks, adds))

    newbakset = (bakset - cutset) | addset

    if len(newbakset) != (len(baks) - len(cuts) + len(adds)):  # redundant?
        raise ValueError("Invalid member combination among baks = {}, cuts ={}, "
                         "and adds = {}.".format(baks, cuts, adds))

    if isinstance(toad, str):
        toad = "{:x}".format(toad)
    elif toad is None:
        if not newbakset:
            toad = 0
        else:  # compute default f and m for len(newbakset)
            toad = ample(len(newbakset))

    if newbakset:
        if toad < 1 or toad > len(newbakset):  # out of bounds toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(newbakset)))
    else:
        if toad != 0:  # invalid toad
            raise ValueError("Invalid toad = {} for resultant wits = {}"
                             "".format(toad, list(newbakset)))

    ked = dict(v=vs,  # version string
               i=regk,  # qb64 prefix
               p=dig,
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               )

    return Serder(ked=ked)  # return serialized ked


def issue(
        vcdig,
        regk,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of iss message event
    Utility function to create a VC issuance event

    Parameters:
        vcdig is hash digest of vc content qb64
        regk is regsitry identifier prefix qb64

    """

    vs = Versify(version=version, kind=kind, size=0)
    ked = dict(v=vs,  # version string
               i=vcdig,  # qb64 prefix
               s="{:x}".format(0),  # hex string no leading zeros lowercase
               t=Ilks.iss,
               ri=regk
               )

    return Serder(ked=ked)  # return serialized ked


def revoke(
        vcdig,
        dig,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of rev message event
    Utility function to create a VC revocation vent

    Parameters:
        vcdig is hash digest of vc content qb64
        regk is regsitry identifier prefix qb64
        dig is digest of previous event qb64

    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 1
    ilk = Ilks.rev

    ked = dict(v=vs,
               i=vcdig,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
               p=dig
               )

    return Serder(ked=ked)  # return serialized ked


def backerIssue(
        vcdig,
        regk,
        regsn,
        regd,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of bis message event
    Utility function to create a VC issuance event

    Parameters:
        vcdig is hash digest of vc content qb64
        regk is regsitry identifier prefix qb64
        regsn is int sequence number of anchoring registry TEL event
        regd is digest qb64 of anchoring registry TEL event

    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 0
    ilk = Ilks.bis

    seal = SealEvent(regk, regsn, regd)

    ked = dict(v=vs,  # version string
               i=vcdig,  # qb64 prefix
               ii=regk,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
               ra=seal._asdict()
               )

    return Serder(ked=ked)  # return serialized ked


def backerRevoke(
        vcdig,
        regk,
        regsn,
        regd,
        dig,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of brv message event
    Utility function to create a VC revocation event

    Parameters:
        vcdig is hash digest of vc content qb64
        regk is regsitry identifier prefix qb64
        regsn is int sequence number of anchoring registry TEL event
        regd is digest qb64 of anchoring registry TEL event
        dig is digest of previous event qb64

    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 1
    ilk = Ilks.brv

    seal = SealEvent(regk, regsn, regd)

    ked = dict(v=vs,
               i=vcdig,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
               p=dig,
               ra=seal._asdict()
               )

    return Serder(ked=ked)  # return serialized ked


class Tever:
    """
    Tever is KERI transaction event verifier class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Class Attributes:
        .NoBackers is Boolean
                True means do not allow backers (default to witnesses of controlling KEL)
                False means allow backers (ignore witnesses of controlling KEL)

    Attributes:
        .db is reference to Baser instance that managers the LMDB database
        .reg is regerence to Registry instance that manages VC LMDB database
        .regk is fully qualified base64 identifier prefix of own Registry if any
        .local is Boolean
            True means only process msgs for own events if .regk
            False means only process msgs for not own events if .regk
        .version is version of current event state
        .prefixer is prefixer instance for current event state
        .sn is sequence number int
        .serder is Serder instance of current event with .serder.diger for digest
        .toad is int threshold of accountable duplicity
        .baks is list of qualified qb64 aids for backers
        .cuts is list of qualified qb64 aids for backers cut from prev wits list
        .adds is list of qualified qb64 aids for backers added to prev wits list
        .noBackers is boolean trait True means do not allow backers



    """
    NoBackers=False

    def __init__(self, serder, anchor=None, bigers=None, db=None, reger=None, noBackers=None,
                 regk=None, local=False):
        """
        Create incepting tever and state from registry inception serder

        Parameters:
            serder is Serder instance of registry inception event
            anchor is EventSeal of anchor to controlling KEL
            bigers is list of Siger instances of indexed backer signatures of
                event. Index is offset into baks list of latest est event
            db is Baser instance of lmdb database
            reger is Registry instance of VC lmdb database
            noBackers is boolean True means do not allow backer configuration
            regk is identifier prefix of own or local registry. May not be the
                prefix of this Tever's event. Some restrictions if present
            local is Boolean, True means only process msgs for own controller's
                events if .regk. False means only process msgs for not own events
                if .regk
        """
        self.reger = reger if reger is not None else Registry()
        self.db = db if db is not None else Baser()
        self.version = serder.version
        self.regk = regk
        self.local = True if local else False

        ilk = serder.ked["t"]
        if ilk is not Ilks.vcp:
            raise ValidationError("Expected ilk {} got {} for evt: {}".format(Ilks.vcp, ilk, serder))

        self.ilk = ilk
        labels = VCP_LABELS
        for k in labels:
            if k not in serder.ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, serder.ked))

        self.incept(serder=serder)

        self.config(serder=serder, noBackers=noBackers)

        anchors, bigers = self.valAnchorBigs(serder=serder,
                                             anchor=anchor,
                                             bigers=bigers,
                                             toad=self.toad,
                                             baks=self.baks)

        # do we need seqner and dater?
        sealet = anchor.i.encode("utf-8") + Seqner(sn=int(anchor.s, 16)).qb64b + anchor.d.encode("utf-8")
        self.fn = self.logEvent(serder=serder, anchor=sealet, bigers=bigers)


    def incept(self, serder):

        ked = serder.ked
        self.prefixer = Prefixer(qb64=serder.pre)
        if not self.prefixer.verify(ked=ked, prefixed=True):  # invalid prefix
            raise ValidationError("Invalid prefix = {} for registry inception evt = {}."
                                  .format(self.prefixer.qb64, ked))

        sn = ked["s"]
        self.sn = validateSN(sn, inceptive=True)

        self.cuts = []  # always empty at inception since no prev event
        self.adds = []  # always empty at inception since no prev event
        baks = ked["b"]
        if len(oset(baks)) != len(baks):
            raise ValidationError("Invalid baks = {}, has duplicates for evt = {}."
                                  "".format(baks, ked))
        self.baks = baks

        toad = int(ked["bt"], 16)
        if baks:
            if toad < 1 or toad > len(baks):  # out of bounds toad
                raise ValidationError("Invalid toad = {} for baks = {} for evt = {}."
                                      "".format(toad, baks, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValidationError("Invalid toad = {} for baks = {} for evt = {}."
                                      "".format(toad, baks, ked))
        self.toad = toad

    def config(self, serder, noBackers=None):
        """
        Process cnfg field for configuration traits
        """
        # assign traits
        self.noBackers = (True if (noBackers if noBackers is not None
                                   else self.NoBackers)
                          else False)  # ensure default noBackers is boolean

        cnfg = serder.ked["c"]  # process cnfg for traits
        if TraitDex.NoBackers in cnfg:
            self.noBackers = True

    def update(self, serder, anchor, bigers=None):
        """
        Process registry non-inception events.
        Currently placeholder.
        """

        ked = serder.ked

        sn = ked["s"]
        sn = validateSN(sn, inceptive=False)

        ilk = ked["t"]

        if ilk in (Ilks.vcp, Ilk.vrt):
            self.management(serder, anchor, bigers)
        elif ilk in (Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
            self.issueRevoke(serder, anchor, bigers)
        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))


    def management(self, serder, anchor, bigers=None):
        """
        Process registry management TEL, non-inception events (vrt)
        """

        ked = serder.ked
        pre = ked["i"]
        dig = ked["p"]

        if serder.pre != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {} for evt = {}.".format(ked["i"],
                                                               self.prefixer.qb64,
                                                               ked))


    def issueRevoke(self, serder, anchor, bigers=None):
        """
        Process VC TEL events (iss, rev, bis, brv)
        Currently placeholder
        """

        ked = serder.ked
        vcpre = ked["i"]
        pre = ked["ii"]
        dig = ked["p"]

        if serder.pre != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {} for evt = {}.".format(ked["i"],
                                                               self.prefixer.qb64,
                                                               ked))


    def logEvent(self, serder, anchor, bigers=None):
        """
        Update associated logs for verified event.
        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            serder is Serder instance of current event
            anchor is seal anchor to KEL event
            bigers is optional list of Siger instance of indexed backer sigs
            seqner is optional Seqner instance of cloned first seen ordinal
                If cloned mode then seqner maybe provided (not None)
                When seqner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            dater is optional Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
        """
        fn = None
        dig = serder.diger.qb64b
        key = dgKey(self.prefixer.qb64b, dig)
        self.reger.putAnc(key, anchor)
        if bigers:
            self.reger.putTibs(key, [biger.qb64b for biger in bigers])
        self.reger.putTvt(key, serder.raw)
        self.reger.putTel(snKey(self.prefixer.qb64b, self.sn), dig)
        logger.info("Tever state: %s Added to KEL valid event=\n%s\n",
                    self.prefixer.qb64, json.dumps(serder.ked, indent=1))
        return fn


    def valAnchorBigs(self, serder, anchor, bigers, toad, baks):
        """
        Returns double (anchors, bigers) where:
        anchor is seal anchor to KEL event
        bigers is unique validated signature verified members of inputed bigers

        Validates sigers signatures by validating indexes, verifying signatures, and
            validating threshold sith.
        Validate backer receipts by validating indexes, verifying
            backer signatures and validating toad.
        Backer validation is a function of .regk and .local
        TODO:  Fall back to KEL Witnesses for validation if backers not supported

        Parameters:
            serder is Serder instance of event
            anchor is seal anchor to KEL event
            bigers is list of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.
            toad is int or  str hex of witness threshold
            baks is list of qb64 non-transferable prefixes of backers used to
                derive werfers for bigers

        """

        # get anchroed event, extract seal and verify digest
        anchor = self.verifyAnchor(serder=serder, anchor=anchor)

        berfers = [Verfer(qb64=bak) for bak in baks]
        #for wit in wits:  # create list of werfers one for each witness
            #werfers.append(Verfer(qb64=wit))

        # get unique verified bigers and bindices lists from bigers list
        bigers, bindices = verifySigs(serder=serder, sigers=bigers, verfers=berfers)
        # each biger now has werfer of corresponding wit

        # check if fully anchored
        if anchor == None:
            self.escrowALEvent(serder=serder, anchor=anchor, bigers=bigers)

            raise MissingAnchorError("Failure verify event = {} "
                        "with anchor = {}".format(serder.ked,
                                                anchor))


        # Kevery .process event logic prevents this from seeing event when
        # not local and event pre is own pre
        if ((baks and not self.regk) or  # in promiscuous mode so assume must verify toad
            (baks and not self.local and self.regk and self.regk not in baks)):
            # validate that event is fully witnessed
            if isinstance(toad, str):
                toad = int(toad, 16)
            if toad < 0 or len(baks) < toad:
                raise ValidationError("Invalid toad = {} for wits = {} for evt"
                                       " = {}.".format(toad, baks, serder.ked))

            if len(bindices) < toad:  # not fully witnessed yet
                sealet = anchor.i.encode("utf-8") + Seqner(sn=int(anchor.s, 16)).qb64b + anchor.d.encode("utf-8")
                self.escrowPWEvent(serder=serder, anchor=sealet, bigers=bigers)

                raise MissingWitnessSignatureError("Failure satisfying toad = {} "
                            "on witness sigs for {} for evt = {}.".format(toad,
                                                    [siger.qb64 for siger in bigers],
                                                    serder.ked))
        return (anchor, bigers)


    def verifyAnchor(self, serder, anchor):
        """
        retrieve event from db using anchor
        get seal from event eserder
        verify pre, sn and dig against serder
        """

        apre = anchor.i
        asn = validateSN(anchor.s)
        adig = anchor.d

        dig = self.db.getFe(key=fnKey(pre=apre, sn=asn))
        if not dig:
            return None
        else:
            dig = bytes(dig)

        # retrieve event by dig
        raw = self.db.getEvt(key=dgKey(pre=apre, dig=dig))
        if not raw:
            return None
        else:
            raw = bytes(raw)

        eserder = Serder(raw=raw)  # deserialize event raw

        if eserder.dig != adig:
            return None

        seal = eserder.ked["a"]
        if seal is None or len(seal) != 1:
            return None

        seal = seal[0]
        spre = seal["i"]
        ssn = seal["s"]
        sdig = seal["d"]

        if spre == serder.ked["i"] and ssn == serder.ked["s"] \
            and serder.dig == sdig:
            return anchor

        return None


    def escrowPWEvent(self, serder, anchor, bigers):
        """
        Update associated logs for escrow of partially witnessed event

        Parameters:
            serder is Serder instance of  event
            bigers is list of Siger instance of indexed witness sigs
        """
        dgkey = dgKey(serder.preb, serder.digb)
        self.reger.putAnc(dgkey, anchor)
        self.reger.putTibs(dgkey, [biger.qb64b for biger in bigers])
        self.reger.putTvt(dgkey, serder.raw)
        self.reger.putTwe(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Tever state: Escrowed partially witnessed "
                     "event = %s\n", serder.ked)


    def escrowALEvent(self, serder, anchor, bigers=None):
        """
        Update associated logs for escrow of anchorless event

        Parameters:
            serder is Serder instance of  event
        """
        key = dgKey(serder.preb, serder.digb)
        if bigers:
            self.reger.putTibs(key, [biger.qb64b for biger in bigers])
        self.reger.putTvt(key, serder.raw)
        self.reger.putTae(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Tever state: Escrowed anchorless event "
                     "event = %s\n", serder.ked)


class Tevery:
    """
    Tevery (Transaction Event Message Processing Facility)

    Currently placeholder
    """

