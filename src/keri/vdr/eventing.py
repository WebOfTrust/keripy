# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.eventing module

VC TEL  support
"""


import json
from collections import deque, namedtuple

from orderedset import OrderedSet as oset

from ..core.coring import (MtrDex, Serder, Serials, Versify, Prefixer,
                              Ilks, Seqner, Verfer)
from ..core.eventing import SealEvent, ample, TraitDex, verifySigs, validateSN
from ..db import basing
from ..db.dbing import dgKey, snKey
from ..help import helping
from ..kering import (MissingWitnessSignatureError, Version,
                         MissingAnchorError, ValidationError, OutOfOrderError, LikelyDuplicitousError)
from ..vdr.viring import Registry, nsKey
from .. import help

logger = help.ogler.getLogger()

VCP_LABELS = ["v", "i", "s", "t", "bt", "b", "c"]
VRT_LABELS = ["v", "i", "s", "t", "p", "bt", "b", "ba", "br"]

ISS_LABELS = ["v", "i", "s", "t", "ri", "dt"]
BIS_LABELS = ["v", "i", "s", "t", "ra", "dt"]

REV_LABELS = ["v", "i", "s", "t", "p", "dt"]
BRV_LABELS = ["v", "i", "s", "t", "ra", "p", "dt"]

VcState = namedtuple("VcState", 'issued revoked')

VcStates = VcState(issued='issued', revoked="revoked")


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
               ri=regk,
               dt=helping.nowIso8601()
               )

    return Serder(ked=ked)  # return serialized ked


def revoke(
        vcdig,
        regk,
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
               ri=regk,
               p=dig,
               dt=helping.nowIso8601()
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
        regk is registry identifier prefix qb64
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
               ra=seal._asdict(),
               dt=helping.nowIso8601(),
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
               ra=seal._asdict(),
               dt=helping.nowIso8601(),
               )

    return Serder(ked=ked)  # return serialized ked


def query(regk,
          vcid,
          res,
          dt=None,
          dta=None,
          dtb=None,
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
        i=vcid,
        ri=regk
    )

    if dt is not None:
        qry["dt"] = dt

    if dta is not None:
        qry["dta"] = dt

    if dtb is not None:
        qry["dtb"] = dt


    ked = dict(v=vs,  # version string
               t=ilk,
               r=res,  # resource type for single item request
               q=qry
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
    NoBackers = False

    def __init__(self, serder, seqner=None, diger=None, bigers=None, db=None,
                 reger=None, noBackers=None, regk=None, local=False):
        """
        Create incepting tever and state from registry inception serder

        Parameters:
            serder is Serder instance of registry inception event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            diger (Diger): issuing event digest from controlling KEL.
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
        self.db = db if db is not None else basing.Baser(reopen=True)
        self.version = serder.version
        self.regk = regk
        self.local = True if local else False

        ilk = serder.ked["t"]
        if ilk not in [Ilks.vcp]:
            raise ValidationError("Expected ilk {} got {} for evt: {}".format(Ilks.vcp, ilk, serder))

        self.ilk = ilk
        labels = VCP_LABELS
        for k in labels:
            if k not in serder.ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, serder.ked))

        self.incept(serder=serder)

        self.config(serder=serder, noBackers=noBackers)

        bigers = self.valAnchorBigs(serder=serder,
                                    seqner=seqner,
                                    diger=diger,
                                    bigers=bigers,
                                    toad=self.toad,
                                    baks=self.baks)

        self.logEvent(pre=self.prefixer.qb64b,
                      sn=0,
                      serder=serder,
                      seqner=seqner,
                      diger=diger,
                      bigers=bigers,
                      baks=self.baks)

    def incept(self, serder):

        ked = serder.ked
        self.pre = ked["ii"]
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
        self.serder = serder

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

    def update(self, serder, seqner=None, diger=None, bigers=None):
        """
        Process registry non-inception events.
        """

        ked = serder.ked
        ilk = ked["t"]
        sn = ked["s"]

        icp = ilk in (Ilks.iss, Ilks.bis)

        # validate SN for
        sn = validateSN(sn, inceptive=icp)

        if ilk in (Ilks.vrt,):
            if self.noBackers is True:
                raise ValidationError("invalid rotation evt {} against backerless registry {}".
                                      format(ked, self.regk))
            toad, baks, cuts, adds = self.rotate(serder, sn=sn)

            bigers = self.valAnchorBigs(serder=serder,
                                        seqner=seqner,
                                        diger=diger,
                                        bigers=bigers,
                                        toad=toad,
                                        baks=baks)

            self.sn = sn
            self.serder = serder
            self.ilk = ilk
            self.toad = toad
            self.baks = baks
            self.cuts = cuts
            self.adds = adds

            self.logEvent(pre=self.prefixer.qb64b,
                          sn=sn,
                          serder=serder,
                          seqner=seqner,
                          diger=diger,
                          bigers=bigers,
                          baks=self.baks)
            return

        elif ilk in (Ilks.iss, Ilks.bis):
            self.issue(serder, seqner=seqner, diger=diger, sn=sn, bigers=bigers)
        elif ilk in (Ilks.rev, Ilks.brv):
            self.revoke(serder, seqner=seqner, diger=diger, sn=sn, bigers=bigers)
        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))

    def rotate(self, serder, sn):
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
        if not sn == (self.sn + 1):  # sn not in order
            raise ValidationError("Invalid sn = {} expecting = {} for evt "
                                  "= {}.".format(sn, self.sn + 1, ked))

        if not self.serder.compare(dig=dig):  # prior event dig not match
            raise ValidationError("Mismatch event dig = {} with state dig"
                                  " = {} for evt = {}.".format(ked["p"],
                                                               self.serder.diger.qb64,
                                                               ked))

        witset = oset(self.baks)
        cuts = ked["br"]
        cutset = oset(cuts)
        if len(cutset) != len(cuts):
            raise ValidationError("Invalid cuts = {}, has duplicates for evt = "
                                  "{}.".format(cuts, ked))

        if (witset & cutset) != cutset:  # some cuts not in baks
            raise ValidationError("Invalid cuts = {}, not all members in baks"
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
            raise ValidationError("Intersecting baks = {} and  adds = {} for "
                                  "evt = {}.".format(self.baks, adds, ked))

        baks = list((witset - cutset) | addset)

        if len(baks) != (len(self.baks) - len(cuts) + len(adds)):  # redundant?
            raise ValidationError("Invalid member combination among baks = {}, cuts ={}, "
                                  "and adds = {} for evt = {}.".format(self.baks,
                                                                       cuts,
                                                                       adds,
                                                                       ked))

        toad = int(ked["bt"], 16)
        if baks:
            if toad < 1 or toad > len(baks):  # out of bounds toad
                raise ValidationError("Invalid toad = {} for baks = {} for evt "
                                      "= {}.".format(toad, baks, ked))
        else:
            if toad != 0:  # invalid toad
                raise ValidationError("Invalid toad = {} for baks = {} for evt "
                                      "= {}.".format(toad, baks, ked))

        return toad, baks, cuts, adds

    def issue(self, serder, seqner, diger, sn, bigers=None):
        """
        Process VC TEL issuance events (iss, bis)
        Currently placeholder
        """

        ked = serder.ked
        vcpre = ked["i"]
        ilk = ked["t"]
        vci = nsKey([self.prefixer.qb64, vcpre])

        labels = ISS_LABELS if ilk == Ilks.iss else BIS_LABELS

        for k in labels:
            if k not in ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, ked))

        if ilk == Ilks.iss:  # simple issue
            if self.noBackers is False:
                raise ValidationError("invalid simple issue evt {} against backer based registry {}".
                                      format(ked, self.regk))

            regi = ked["ri"]
            if regi != self.prefixer.qb64:
                raise ValidationError("Mismatch event regi prefix = {} expecting"
                                      " = {} for evt = {}.".format(regi,
                                                                   self.prefixer.qb64,
                                                                   ked))

            # check if fully anchored
            if not self.verifyAnchor(serder=serder, seqner=seqner, diger=diger):
                self.escrowALEvent(serder=serder)

                raise MissingAnchorError("Failure verify event = {} "
                                         "".format(serder.ked,
                                                   ))

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, diger=diger)

        elif ilk == Ilks.bis:  # backer issue
            if self.noBackers is True:
                raise ValidationError("invalid backer issue evt {} against backerless registry {}".
                                      format(ked, self.regk))

            rtoad, baks = self.getBackerState(ked)
            bigers = self.valAnchorBigs(serder=serder,
                                        seqner=seqner,
                                        diger=diger,
                                        bigers=bigers,
                                        toad=rtoad,
                                        baks=baks)

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, diger=diger, bigers=bigers)

        else:
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))

    def revoke(self, serder, seqner, diger, sn, bigers=None):
        """
        Process VC TEL revocation events (rev, brv)
        Currently placeholder
        """

        ked = serder.ked
        vcpre = ked["i"]
        ilk = ked["t"]

        labels = REV_LABELS if ilk == Ilks.rev else BRV_LABELS

        for k in labels:
            if k not in ked:
                raise ValidationError("Missing element = {} from {} event for "
                                      "evt = {}.".format(k, ilk, ked))

        # have to compare with VC issuance serder
        vci = nsKey([self.prefixer.qb64, vcpre])

        dig = self.reger.getTel(snKey(pre=vci, sn=sn - 1))
        ievt = self.reger.getTvt(dgKey(pre=vci, dig=dig))
        if ievt is None:
            raise ValidationError("revoke without issue... probably have to escrow")

        ievt = bytes(ievt)
        iserder = Serder(raw=ievt)
        if not iserder.compare(dig=ked["p"]):  # prior event dig not match
            raise ValidationError("Mismatch event dig = {} with state dig"
                                  " = {} for evt = {}.".format(ked["p"],
                                                               self.serder.diger.qb64,
                                                               ked))

        if ilk in (Ilks.rev,):  # simple revoke
            if self.noBackers is False:
                raise ValidationError("invalid simple issue evt {} against backer based registry {}".
                                      format(ked, self.regk))

            # check if fully anchored
            if not self.verifyAnchor(serder=serder, seqner=seqner, diger=diger):
                self.escrowALEvent(serder=serder)

                raise MissingAnchorError("Failure verify event = {} "
                                         "".format(serder.ked))

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, diger=diger)

        elif ilk in (Ilks.brv,):  # backer revoke
            if self.noBackers is True:
                raise ValidationError("invalid backer issue evt {} against backerless registry {}".
                                      format(ked, self.regk))

            rtoad, baks = self.getBackerState(ked)
            bigers = self.valAnchorBigs(serder=serder,
                                        seqner=seqner,
                                        diger=diger,
                                        bigers=bigers,
                                        toad=rtoad,
                                        baks=baks)

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, diger=diger, bigers=bigers)

        else:
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))

    def vcState(self, vcpre):
        """
        Calculate state (issued/revoked) of VC from db.
         Returns None if never issued from this Registry

        Parameters:
          vcpre:  the VC identifier
        """
        vci = nsKey([self.prefixer.qb64, vcpre])
        cnt = self.reger.cntTels(vci)
        if cnt == 1:
            return VcStates.issued
        elif cnt == 2:
            return VcStates.revoked

        return None

    def vcSn(self, vcpre):
        """
        Calculates the current seq no of VC from db.
         Returns None if never issued from this Registry

        Parameters:
          vcpre:  the VC identifier

        """
        vci = nsKey([self.prefixer.qb64, vcpre])
        cnt = self.reger.cntTels(vci)

        return None if cnt == 0 else cnt - 1

    def logEvent(self, pre, sn, serder, seqner, diger, bigers=None, baks=None):
        """
        Update associated logs for verified event.
        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            pre (qb64): is event prefix
            sn (int): is event sequence number
            serder (Serder): is Serder instance of current event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            diger (Diger): issuing event digest from controlling KEL.
            bigers (Siger): is optional list of Siger instance of indexed backer sigs
            seqner (Seqner): is optional Seqner instance of cloned first seen ordinal
                If cloned mode then seqner maybe provided (not None)
                When seqner provided then compare fn of dater and database and
                first seen if not match then log and add cue notify problem
            baks (qb64): is optional Dater instance of cloned replay datetime
                If cloned mode then dater maybe provided (not None)
                When dater provided then use dater for first seen datetime
        """

        dig = serder.diger.qb64b
        key = dgKey(pre, dig)
        sealet = seqner.qb64b + diger.qb64b
        self.reger.putAnc(key, sealet)
        if bigers:
            self.reger.putTibs(key, [biger.qb64b for biger in bigers])
        if baks:
            self.reger.delBaks(key)
            self.reger.putBaks(key, [bak.encode("utf-8") for bak in baks])
        self.reger.putTvt(key, serder.raw)
        self.reger.putTel(snKey(pre, sn), dig)
        logger.info("Tever state: %s Added to TEL valid event=\n%s\n",
                    pre, json.dumps(serder.ked, indent=1))

    def valAnchorBigs(self, serder, seqner, diger, bigers, toad, baks):
        """
        Returns double (bigers) where:
        bigers is unique validated signature verified members of inputed bigers

        Validates sigers signatures by validating indexes, verifying signatures, and
            validating threshold sith.
        Validate backer receipts by validating indexes, verifying
            backer signatures and validating toad.
        Backer validation is a function of .regk and .local

        Parameters:
            serder is Serder instance of event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            diger (Diger): issuing event digest from controlling KEL.
            bigers is list of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.
            toad is int or  str hex of witness threshold
            baks is list of qb64 non-transferable prefixes of backers used to
                derive werfers for bigers

        """

        berfers = [Verfer(qb64=bak) for bak in baks]

        # get unique verified bigers and bindices lists from bigers list
        bigers, bindices = verifySigs(serder=serder, sigers=bigers, verfers=berfers)
        # each biger now has werfer of corresponding wit

        # check if fully anchored
        if not self.verifyAnchor(serder=serder, seqner=seqner, diger=diger):
            self.escrowALEvent(serder=serder, bigers=bigers)

            raise MissingAnchorError("Failure verify event = {} "
                                     "".format(serder.ked))

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
                self.escrowPWEvent(serder=serder, seqner=seqner, diger=diger, bigers=bigers)

                raise MissingWitnessSignatureError("Failure satisfying toad = {} "
                                                   "on witness sigs for {} for evt = {}.".format(toad,
                                                                                                 [siger.qb64 for siger
                                                                                                  in bigers],
                                                                                                 serder.ked))
        return bigers

    def verifyAnchor(self, serder, seqner, diger):
        """
        retrieve event from db using anchor
        get seal from event eserder
        verify pre, sn and dig against serder
        """

        dig = self.db.getKeLast(key=snKey(pre=self.pre, sn=seqner.sn))
        if not dig:
            return False
        else:
            dig = bytes(dig)

        # retrieve event by dig
        raw = self.db.getEvt(key=dgKey(pre=self.pre, dig=dig))
        if not raw:
            return False
        else:
            raw = bytes(raw)

        eserder = Serder(raw=raw)  # deserialize event raw

        if eserder.dig != diger.qb64:
            return False

        seal = eserder.ked["a"]
        if seal is None or len(seal) != 1:
            return False

        seal = seal[0]
        spre = seal["i"]
        ssn = seal["s"]
        sdig = seal["d"]

        if spre == serder.ked["i"] and ssn == serder.ked["s"] \
                and serder.dig == sdig:
            return True

        return False

    def escrowPWEvent(self, serder, seqner, diger, bigers=None):
        """
        Update associated logs for escrow of partially witnessed event

        Parameters:
            serder is Serder instance of  event
            bigers is list of Siger instance of indexed witness sigs
        """
        dgkey = dgKey(serder.preb, serder.digb)
        sealet = seqner.qb64b + diger.qb64b
        self.reger.putAnc(dgkey, sealet)
        self.reger.putTibs(dgkey, [biger.qb64b for biger in bigers])
        self.reger.putTvt(dgkey, serder.raw)
        self.reger.putTwe(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Tever state: Escrowed partially witnessed "
                    "event = %s\n", serder.ked)

    def escrowALEvent(self, serder, bigers=None):
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

    def getBackerState(self, ked):
        rega = ked["ra"]
        regi = rega["i"]
        regd = rega["d"]

        if regi != self.prefixer.qb64:
            raise ValidationError("Mismatch event regk prefix = {} expecting"
                                  " = {} for evt = {}.".format(self.regk,
                                                               self.prefixer.qb64,
                                                               ked))

        # load backer list and toad (via event) for specific event in registry from seal in event
        dgkey = dgKey(regi, regd)
        revt = self.reger.getTvt(dgkey)
        if revt is None:
            raise ValidationError("have to escrow this somewhere")

        rserder = Serder(raw=bytes(revt))
        # the backer threshold at this event in mgmt TEL
        rtoad = rserder.ked["bt"]

        baks = [bytes(bak) for bak in self.reger.getBaks(dgkey)]

        return rtoad, baks


class Tevery:
    """
    Tevery (Transaction Event Message Processing Facility)

    Currently placeholder

    Attributes:

    """

    def __init__(self, tevers=None, reger=None, db=None, regk=None, local=False):
        """
        Initialize instance:

        Parameters:
            tevers is dict of Kever instances of key state in db
            reger is Registry instance
            db is Baser instance
            regk is local or own identifier prefix. Some restriction if present
            local is Boolean, True means only process msgs for own events if .pre
                        False means only process msgs for not own events if .pre
        """
        self.tevers = tevers if tevers is not None else dict()
        self.db = db if db is not None else basing.Baser(reopen=True)  # default name = "main"
        self.reger = reger if reger is not None else Registry()
        self.regk = regk  # local prefix for restrictions on local events
        self.local = True if local else False  # local vs nonlocal restrictions
        self.cues = deque()

    def processEvent(self, serder, seqner, diger, wigers=None):
        """
        Process one event serder with attached indexd signatures sigers

        Parameters:
            serder (Serder): event to process
            seqner (Seqner): issuing event sequence number from controlling KEL.
            diger (Diger): issuing event digest from controlling KEL.
            wigers (Siger): is optional list of Siger instances of attached witness indexed sigs

        """
        ked = serder.ked
        try:  # see if code of pre is supported and matches size of pre
            Prefixer(qb64b=serder.preb)
        except Exception as ex:  # if unsupported code or bad size raises error
            raise ValidationError("Invalid pre = {} for evt = {}."
                                  "".format(serder.pre, ked))

        regk = self.registryKey(serder)
        pre = serder.pre
        ked = serder.ked
        sn = ked["s"]
        ilk = ked["t"]

        inceptive = ilk in (Ilks.vcp, Ilks.iss, Ilks.bis)

        # validate SN for
        sn = validateSN(sn, inceptive=inceptive)

        if self.regk:
            if self.local:
                if self.regk != regk:  # nonlocal event when in local mode
                    raise ValueError("Nonlocal event regk={} when local mode for regk={}."
                                     "".format(regk, self.regk))
            else:
                if self.regk == regk:  # local event when not in local mode
                    raise ValueError("Local event regk={} when nonlocal mode."
                                     "".format(regk))

        if regk not in self.tevers:  # first seen for this registry
            if ilk in [Ilks.vcp]:
                # incepting a new registry, Tever create will validate anchor, etc.
                tever = Tever(serder=serder,
                              seqner=seqner,
                              diger=diger,
                              bigers=wigers,
                              reger=self.reger,
                              db=self.db,
                              regk=self.regk,
                              local=self.local)
                self.tevers[regk] = tever
                if not self.regk or self.regk != regk:
                    # witness style backers will need to send receipts so lets queue them up for now
                    self.cues.append(dict(kin="receipt", serder=serder))
            else:
                # out of order, need to escrow
                self.escrowOOEvent(serder=serder, seqner=seqner, diger=diger)
                raise OutOfOrderError("escrowed out of order event {}".format(ked))

        else:
            if ilk in (Ilks.vcp,):
                # we don't have multiple signatures to verify so this
                # is already first seen and then lifely duplicitious
                raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))

            tever = self.tevers[regk]

            if ilk in [Ilks.vrt]:
                sno = tever.sn + 1  # proper sn of new inorder event
            else:
                esn = tever.vcSn(pre)
                sno = 0 if esn is None else esn + 1

            if sn > sno:  # sn later than sno so out of order escrow
                # escrow out-of-order event
                self.escrowOOEvent(serder=serder, seqner=seqner, diger=diger)
                raise OutOfOrderError("Out-of-order event={}.".format(ked))
            elif sn == sno:  # new inorder event
                tever.update(serder=serder, seqner=seqner, diger=diger, bigers=wigers)

                if not self.regk or self.regk != regk:
                    # witness style backers will need to send receipts so lets queue them up for now
                    self.cues.append(dict(kin="receipt", serder=serder))
            else:  # duplicitious
                raise LikelyDuplicitousError("Likely Duplicitous event={} with sn {}.".format(ked, sn))

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

        if res == "tels":
            mgmt = qry["ri"]
            vcpre = qry["i"]
            vck = nsKey([mgmt, vcpre])

            cloner = self.reger.clonePreIter(pre=mgmt, fn=0)  # create iterator at 0
            msgs = bytearray()  # outgoing messages
            for msg in cloner:
                msgs.extend(msg)

            cloner = self.reger.clonePreIter(pre=vck, fn=0)  # create iterator at 0
            for msg in cloner:
                msgs.extend(msg)

            self.cues.append(dict(kin="replay", msgs=msgs))
        else:
            raise ValidationError("invalid query message {} for evt = {}".format(ilk, ked))

    @staticmethod
    def registryKey(serder):
        ilk = serder.ked["t"]

        if ilk in (Ilks.vcp, Ilks.vrt):
            return serder.pre
        elif ilk in (Ilks.iss, Ilks.rev):
            return serder.ked["ri"]
        elif ilk in (Ilks.bis, Ilks.brv):
            rega = serder.ked["ra"]
            return rega["i"]
        else:
            raise ValidationError("invalid ilk {} for tevery event = {}".format(ilk, serder.ked))

    def escrowOOEvent(self, serder, seqner, diger):
        key = dgKey(serder.preb, serder.digb)
        self.reger.putTvt(key, serder.raw)
        sealet = seqner.qb64b + diger.qb64b
        self.reger.putAnc(key, sealet)
        self.reger.putOot(snKey(serder.preb, serder.sn), serder.digb)
        logger.info("Tever state: Escrowed anchorless event "
                    "event = %s\n", serder.ked)
