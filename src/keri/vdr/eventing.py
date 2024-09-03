# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.eventing module

VC TEL  support
"""

import json
import logging
from dataclasses import asdict
from math import ceil
from  ordered_set import OrderedSet as oset

from hio.help import decking

from keri import kering
from .. import core
from .. import help
from ..core import serdering, coring, indexing
from ..core.coring import (MtrDex, Kinds, versify, Prefixer,
                           Ilks, Seqner, Verfer, Number)
from ..core.signing import (Salter,)
from ..core.eventing import SealEvent, ample, TraitDex, verifySigs
from ..db import basing, dbing
from ..db.dbing import dgKey, snKey, splitSnKey
from ..help import helping
from ..kering import (MissingWitnessSignatureError, Version,
                      MissingAnchorError, ValidationError, OutOfOrderError, LikelyDuplicitousError)
from ..vdr import viring

logger = help.ogler.getLogger()


def incept(
        pre,
        toad=None,
        baks=None,
        nonce=None,
        cnfg=None,
        version=Version,
        kind=Kinds.json,
        code=MtrDex.Blake3_256,
):
    """ Returns serder of credential registry inception (vcp) message event

    Returns serder of vcp message event
    Utility function to create a Registry inception event

    Parameters:
         pre (str): issuer identifier prefix qb64
         toad (Union(int,str)): int or str hex of backer threshold
         baks (list): the initial list of backers prefixes for VCs in the Registry
         nonce (str): qb64 encoded ed25519 random seed of credential registry
         cnfg (list): is list of strings TraitDex of configuration traits

         version (Versionage): the API version
         kind (str): the event type
         code (str): default code for Prefixer

    Returns:
        Serder: Event message Serder

    """

    vs = versify(version=version, kind=kind, size=0)
    isn = 0
    ilk = Ilks.vcp

    cnfg = cnfg if cnfg is not None else []

    baks = baks if baks is not None else []
    if TraitDex.NoBackers in cnfg and len(baks) > 0:
        raise ValueError("{} backers specified for NB vcp, 0 allowed".format(len(baks)))

    if len(oset(baks)) != len(baks):
        raise ValueError("Invalid baks = {}, has duplicates.".format(baks))

    if isinstance(toad, str):
        toad = int(toad, 16)
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

    nonce = nonce if nonce is not None else Salter().qb64
    ked = dict(v=vs,  # version string
               t=ilk,
               d="",
               i="",  # qb64 prefix
               ii=pre,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               c=cnfg,
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=baks,  # list of qb64 may be empty
               n=nonce  # nonce of random bytes to make each registry unique
               )

    serder = serdering.SerderKERI(sad=ked, makify=True)
    return serder


def rotate(
        regk,
        dig,
        sn=1,
        toad=None,
        baks=None,
        cuts=None,
        adds=None,
        version=Version,
        kind=Kinds.json,
):
    """ Returns serder of registry rotation (brt) message event

    Returns serder of vrt message event
    Utility function to create a Registry rotation event

    Parameters:
        regk (str): identifier prefix qb64
        dig (str): qb64 digest or prior event
        sn (int): sequence number
        toad (int): int or str hex of witness threshold
        baks (list): prior backers prefixes qb64
        cuts (list): witness prefixes to cut qb64
        adds (list): witness prefixes to add qb64
        version (Versionage): the API version
        kind (str): the event type

    Returns:
        Serder: event message Serder

    """

    if sn < 1:
        raise ValueError("Invalid sn = {} for vrt.".format(sn))

    vs = versify(version=version, kind=kind, size=0)
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
        toad = int(toad, 16)
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
               t=ilk,
               d="",
               i=regk,  # qb64 prefix
               p=dig,
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               br=cuts,  # list of qb64 may be empty
               ba=adds,  # list of qb64 may be empty
               )

    serder = serdering.SerderKERI(sad=ked, makify=True)
    return serder


def issue(
        vcdig,
        regk,
        version=Version,
        kind=Kinds.json,
        dt=None
):
    """ Returns serder of issuance (iss) message event

    Returns serder of iss message event
    Utility function to create a VC issuance event

    Parameters:
        vcdig (str): qb64 SAID of credential
        regk (str): qb64 AID of credential registry
        version (Versionage): the API version
        kind (str): the event type
        dt (str): ISO 8601 formatted date string of issuance date

    Returns:
        Serder: event message Serder

    """

    vs = versify(version=version, kind=kind, size=0)
    ked = dict(v=vs,  # version string
               t=Ilks.iss,
               d="",
               i=vcdig,  # qb64 prefix
               s="{:x}".format(0),  # hex string no leading zeros lowercase
               ri=regk,
               dt=helping.nowIso8601()
               )
    if dt is not None:
        ked["dt"] = dt

    serder = serdering.SerderKERI(sad=ked, makify=True)
    return serder


def revoke(
        vcdig,
        regk,
        dig,
        version=Version,
        kind=Kinds.json,
        dt=None
):
    """ Returns serder of backerless credential revocation (rev) message event

    Returns serder of rev message event
    Utility function to create a VC revocation vent

    Parameters:
        vcdig (str): qb64 SAID of credential
        regk (str): qb64 AID of credential registry
        dig (str): digest of previous event qb64
        version (Versionage): the API version
        kind (str): the event type
        dt (str): ISO 8601 formatted date string of revocation date

    Returns:
        Serder: event message Serder

    """

    vs = versify(version=version, kind=kind, size=0)
    isn = 1
    ilk = Ilks.rev

    ked = dict(v=vs,
               t=ilk,
               d="",
               i=vcdig,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               ri=regk,
               p=dig,
               dt=helping.nowIso8601()
               )

    if dt is not None:
        ked["dt"] = dt

    _, ked = coring.Saider.saidify(sad=ked)

    serder = serdering.SerderKERI(sad=ked, makify=True)
    return serder


def backerIssue(
        vcdig,
        regk,
        regsn,
        regd,
        version=Version,
        kind=Kinds.json,
        dt=None,
):
    """ Returns serder of backer issuance (bis) message event

    Returns serder of bis message event
    Utility function to create a VC issuance event

    Parameters:
        vcdig (str): qb64 SAID of credential
        regk (str): qb64 AID of credential registry
        regsn (int): sequence number of anchoring registry TEL event
        regd (str): digest qb64 of anchoring registry TEL event
        version (Versionage): the API version
        kind (str): the event type
        dt (str): ISO 8601 formatted date string of issuance date

    Returns:
        Serder: event message Serder

    """

    vs = versify(version=version, kind=kind, size=0)
    isn = 0
    ilk = Ilks.bis

    seal = SealEvent(regk, "{:x}".format(regsn), regd)

    ked = dict(v=vs,  # version string
               t=ilk,
               d="",
               i=vcdig,  # qb64 prefix
               ii=regk,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               ra=seal._asdict(),
               dt=helping.nowIso8601(),
               )
    _, ked = coring.Saider.saidify(sad=ked)

    if dt is not None:
        ked["dt"] = dt

    serder = serdering.SerderKERI(sad=ked, makify=True)
    return serder


def backerRevoke(
        vcdig,
        regk,
        regsn,
        regd,
        dig,
        version=Version,
        kind=Kinds.json,
        dt=None
):
    """ Returns serder of backer credential revocation (brv) message event

    Returns serder of brv message event
    Utility function to create a VC revocation event

    Parameters:
        vcdig (str): qb64 SAID of credential
        regk (str): qb64 AID of credential registry
        regsn (int): sequence number of anchoring registry TEL event
        regd (str): digest qb64 of anchoring registry TEL event
        dig (str) digest of previous event qb64
        version (Versionage): the API version
        kind (str): the event type
        dt (str): ISO 8601 formatted date string of issuance date

    Returns:
        Serder: event message Serder

    """

    vs = versify(version=version, kind=kind, size=0)
    isn = 1
    ilk = Ilks.brv

    seal = SealEvent(regk, "{:x}".format(regsn), regd)

    ked = dict(v=vs,
               t=ilk,
               d="",
               i=vcdig,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               p=dig,
               ra=seal._asdict(),
               dt=helping.nowIso8601(),
               )
    _, ked = coring.Saider.saidify(sad=ked)

    if dt is not None:
        ked["dt"] = dt

    serder = serdering.SerderKERI(sad=ked, makify=True)
    return serder


def state(pre,
          said,
          sn,
          ri,
          eilk,
          dts=None,  # default current datetime
          toad=None,  # default based on wits
          wits=None,  # default to []
          cnfg=None,  # default to []
          version=Version,
          ):
    """
    Utility function to create a RegStateRecord of state notice of a given
        Registry Event Log (REL)

        Returns:
            rsr: (RegStateRecord): instance

    Parameters:
        pre (str): identifier prefix qb64
        sn (int): int sequence number of latest event
        said (str): digest of latest event
        ri (str): qb64 AID of credential registry
        eilk (str): message type (ilk) oflatest event
        a (dict): key event anchored seal data
        dts (str) ISO 8601 formated current datetime
        toad (int): int of witness threshold
        wits (list): list of witness prefixes qb64
        cnfg (list): list of strings TraitDex of configuration traits
        version (str): Version instance
        kind (str): serialization kind

    Returns:
        Serder: Event message Serder

    Key State Dict
    {
        "v": "KERI10JSON00011c_",
        "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
        "s": "2":,
        "p": "EYAfSVPzhzZ-i0d8JZS6b5CMAoTNZH3ULvaU6JR2nmwy",
        "d": "EAoTNZH3ULvaU6JR2nmwyYAfSVPzhzZ-i0d8JZS6b5CM",
        "ri": "EYAfSVPzhzZ-i0d8JZS6b5CMAoTNZH3ULvaU6JR2nmwy",
        "dt": "2020-08-22T20:35:06.687702+00:00",
        "et": "vrt",
        "a": {i=12, d="EYAfSVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULv"},
        "k": ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],
        "n": "EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
        "bt": "1",
        "b": ["DnmwyYAfSVPzhzS6b5CMZ-i0d8JZAoTNZH3ULvaU6JR2"],
        "di": "EYAfSVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULv",
        "c": ["EO"],
    }

    """
    #vs = versify(version=version, kind=kind, size=0)

    if sn < 0:
        raise ValueError("Negative sn = {} in key state.".format(sn))

    if eilk not in (Ilks.vcp, Ilks.vrt):
        raise ValueError("Invalid evernt type et=  in key state.".format(eilk))

    if dts is None:
        dts = helping.nowIso8601()

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

    rsr = viring.RegStateRecord(
               vn=list(version),  # version number as list [major, minor]
               i=ri,  # qb64 registry SAID
               s="{:x}".format(sn),  # lowercase hex string no leading zeros
               d=said,
               ii=pre,
               dt=dts,
               et=eilk,
               bt="{:x}".format(toad),  # hex string no leading zeros lowercase
               b=wits,  # list of qb64 may be empty
               c=cnfg if cnfg is not None else [],
               )
    return rsr  # return RegStateRecord  use asdict(rsr) to get dict version


def vcstate(vcpre,
            said,
            sn,
            ri,
            eilk,
            a,
            ra=None,
            dts=None,  # default current datetime
            version=Version,
            kind=Kinds.json,
            ):
    """ Returns the credential transaction state notification

    Returns serder of credential transaction state notification message.
    Utility function to automate creation of tsn events.

    Parameters:
        vcpre (str): is qb64 SAID of the credential
        said (str): is qb64 digest of latest event
        sn (int): sequence number of latest event
        ri (str): registry identifier
        ra (dict): optional registry seal for registries with backers
        eilk (str): is message type (ilk) of latest event
        a (dict): is seal for anchor in KEL
        dts (str): iso8601 formatted date string of state
        version (Version): is KERI version instance
        kind (str): is serialization kind

    Credential Transaction State Dict
    {
       "v": "KERI10JSON00012d_",
       "i": "EDGhJ8V1tuwH55Bk0fBFe9L0za2BUNOt2FX4GUeOLNHQ",
       "s": "0",
       "d": "ENNTabgWbaNqOKLqEZdQCjxbafwwSoXNzAsE1Enq-kdk",
       "ri": "EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",
       "a": {
        "s": 3,
        "d": "Ex7i6wv4YzDRTO9_iHkTQSXrvLYldSd_UEjNfqia3Pqc"
       },
       "dt": "2021-01-01T00:00:00.000000+00:00",
       "et": "bis"
    }
    """

    if sn < 0:
        raise ValueError("Negative sn = {} in key state.".format(sn))

    if eilk not in (Ilks.iss, Ilks.bis, Ilks.rev, Ilks.brv):
        raise ValueError("Invalid event type et=  in key state.".format(eilk))

    if dts is None:
        dts = helping.nowIso8601()

    if ra is None:
        ra = dict()

    vsr = viring.VcStateRecord(vn=list(version),  # version string
                               i=vcpre,  # qb64 prefix
                               s="{:x}".format(sn),  # lowercase hex string no leading zeros
                               d=said,
                               ri=ri,
                               ra=ra,
                               a=a,
                               dt=dts,
                               et=eilk,
                               )

    return vsr  # return vc state record data class


def query(regk,
          vcid,
          route="",
          replyRoute="",
          dt=None,
          dta=None,
          dtb=None,
          stamp=None,
          version=Version,
          kind=Kinds.json
          ):
    """ Returns serder of credentialquery (qry) event message.

    Returns serder of query event message.
    Utility function to automate creation of interaction events.

    Parameters:
        regk (str): qb64 AID of credential registry
        vcid (str): qb64 SAID of credential
        route (str): namesapaced path, '/' delimited, that indicates data flow
                     handler (behavior) to processs the query
        replyRoute (str): namesapaced path, '/' delimited, that indicates data flow
                     handler (behavior) to processs reply message to query if any.
        dt (str): ISO 8601 formatted datetime query
        dta (str): ISO 8601 formatted datetime after query
        dtb (str): ISO 8601 formatted datetime before query
        stamp (str): ISO 8601 formatted current datetime of query message
        version (Versionage): the API version
        kind (str): the event type

    Returns:
        Serder: query event message Serder

    """
    qry = dict(i=vcid, ri=regk)

    if dt is not None:
        qry["dt"] = dt

    if dta is not None:
        qry["dta"] = dt

    if dtb is not None:
        qry["dtb"] = dt

    return core.eventing.query(route=route,
                               replyRoute=replyRoute,
                               query=qry,
                               stamp=stamp,
                               version=version,
                               kind=kind)


class Tever:
    """
    Tever is KERI/ACDC transaction event log verifier class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Class Attributes:
        .NoRegistrarBackers is Boolean
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
        .prefixer is prefixer instance fParemtersor current event state
        .sn is sequence number int
        .serder is Serder instance of current event with .serder.diger for digest
        .toad is int threshold of accountable duplicity
        .baks is list of qualified qb64 aids for backers
        .cuts is list of qualified qb64 aids for backers cut from prev wits list
        .adds is list of qualified qb64 aids for backers added to prev wits list
        .noBackers is boolean trait True means do not allow backers

    """
    NoRegistrarBackers = False

    def __init__(self, cues=None, rsr=None, serder=None, seqner=None, saider=None,
                 bigers=None, db=None, reger=None, noBackers=None, estOnly=None,
                 regk=None, local=False):
        """ Create incepting tever and state from registry inception serder

        Create incepting tever and state from registry inception serder

        Parameters:
            serder (Serder): instance of registry inception event
            rsr (RegStateRecord): transaction state notice state message Serder
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event said from controlling KEL.
            bigers (list): list of Siger instances of indexed backer signatures of
                event. Index is offset into baks list of latest est event
            db (Baser): instance of baser lmdb database
            reger (Reger): instance of VC lmdb database
            noBackers (bool): True means do not allow backer configuration
            estOnly (bool): True means do not allow interaction events
            regk (str): identifier prefix of own or local registry. May not be the
                prefix of this Tever's event. Some restrictions if present
            local (bool): True means only process msgs for own controller's
                events if .regk. False means only process msgs for not own events
                if .regk

        Returns:
            Tever:  instance representing credential Registry

        """

        if not (rsr or serder):
            raise ValueError("Missing required arguments. Need state or serder")

        self.reger = reger if reger is not None else viring.Reger()
        self.cues = cues if cues is not None else decking.Deck()

        self.db = db if db is not None else basing.Baser(reopen=True)
        self.local = True if local else False

        if rsr:  # preload from state
            self.reload(rsr)
            return

        self.version = serder.version
        self.regk = regk

        ilk = serder.ked["t"]
        if ilk not in [Ilks.vcp]:
            raise ValidationError("Expected ilk {} got {} for evt: {}".format(Ilks.vcp, ilk, serder))

        self.ilk = ilk
        self.incept(serder=serder)
        self.config(serder=serder, noBackers=noBackers, estOnly=estOnly)

        bigers = self.valAnchorBigs(serder=serder,
                                    seqner=seqner,
                                    saider=saider,
                                    bigers=bigers,
                                    toad=self.toad,
                                    baks=self.baks)

        self.logEvent(pre=self.prefixer.qb64b,
                      sn=0,
                      serder=serder,
                      seqner=seqner,
                      saider=saider,
                      bigers=bigers,
                      baks=self.baks)

        self.regk = self.prefixer.qb64

    def reload(self, rsr):
        """ Reload Tever attributes (aka its state) from state serder

        Reload Tever attributes (aka its state) from state serder

        Parameters:
            rsr (RegStateRecord): instance of key stat notice 'ksn' message body

        """

        ked = asdict(rsr)

        self.version = rsr.vn
        self.pre = ked["ii"]
        self.regk = ked["i"]
        self.prefixer = Prefixer(qb64=self.regk)
        self.sn = int(ked['s'], 16)
        self.ilk = ked["et"]
        self.toad = int(ked["bt"], 16)
        self.baks = ked["b"]

        self.noBackers = True if TraitDex.NoBackers in ked["c"] else False
        self.estOnly = True if TraitDex.EstOnly in ked["c"] else False

        if (raw := self.reger.getTvt(key=dgKey(pre=self.prefixer.qb64,
                                               dig=ked['d']))) is None:
            raise kering.MissingEntryError("Corresponding event for state={} not found."
                                           "".format(ked))
        self.serder = serdering.SerderKERI(raw=bytes(raw))

    def state(self):  #state(self, kind=Serials.json)
        """ Returns RegStateRecord of state notice of given Registry Event Log
        (REL)

        Returns:
            rsr: (RegStateRecord): instance for this Tever


        """

        cnfg = []
        if self.noBackers:
            cnfg.append(TraitDex.NoBackers)

        dgkey = dbing.dgKey(self.regk, self.serder.said)
        couple = self.reger.getAnc(dgkey)
        ancb = bytearray(couple)
        seqner = coring.Seqner(qb64b=ancb, strip=True)
        diger = coring.Diger(qb64b=ancb, strip=True)

        return (state(pre=self.pre,
                      said=self.serder.said,
                      sn=self.sn,
                      ri=self.regk,
                      dts=None,
                      eilk=self.ilk,
                      #a=dict(s=seqner.sn, d=diger.qb64),
                      toad=self.toad,
                      wits=self.baks,
                      cnfg=cnfg,
                      #kind=kind
                      )
                )

    def incept(self, serder):
        """  Validate registry inception event and initialize local attributes

        Parse and validate registry inception event for this Tever.  Update all
        local attributes with initial values.

        Parameters:
            serder (Serder): registry inception event (vcp)

        """

        ked = serder.ked
        self.pre = ked["ii"]  # which is not the AID of the serder in ked["i"]
        self.prefixer = Prefixer(qb64=serder.pre)  # this not related to self.pre
        #if not self.prefixer.verify(ked=ked, prefixed=True):  # invalid prefix
            #raise ValidationError("Invalid prefix = {} for registry inception evt = {}."
                                  #.format(self.prefixer.qb64, ked))


        self.sn = Number(numh=ked["s"]).validate(inceptive=True).sn

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

    def config(self, serder, noBackers=None, estOnly=None):
        """ Process cnfg field for configuration traits

        Parse and validate the configuration options for registry inception from
        the `c` field of the provided inception event.

        Parameters:
            serder (Serder): credential registry inception event `vcp`
            noBackers (bool): override flag for specifying a registry with no additional backers
                              beyond the controlling KEL's witnesses


        """
        # assign traits
        self.noBackers = (True if (noBackers if noBackers is not None
                                   else self.NoRegistrarBackers)
                          else False)  # ensure default noBackers is boolean

        self.estOnly = (True if (estOnly if estOnly is not None
                                   else False)
                          else False)  # ensure default estOnly is boolean

        cnfg = serder.ked["c"]  # process cnfg for traits
        if TraitDex.NoBackers in cnfg:
            self.noBackers = True
        if TraitDex.EstOnly in cnfg:
            self.estOnly = True

    def update(self, serder, seqner=None, saider=None, bigers=None):
        """ Process registry non-inception events.

        Process non-inception registry and credential events and update local
        Tever state for registry or credential

        Parameters:
            serder (Serder): instance of issuance or backer issuance event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event SAID from controlling KEL.
            bigers (list): of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.

        """

        ked = serder.ked
        ilk = ked["t"]
        #sn = ked["s"]

        icp = ilk in (Ilks.iss, Ilks.bis)

        # validate SN for
        #sn = validateSN(sn, inceptive=icp)
        sn = Number(numh=ked["s"]).validate(inceptive=icp).sn

        if ilk in (Ilks.vrt,):
            if self.noBackers is True:
                raise ValidationError("invalid rotation evt {} against backerless registry {}".
                                      format(ked, self.regk))

            toad, baks, cuts, adds = self.rotate(serder, sn=sn)

            bigers = self.valAnchorBigs(serder=serder,
                                        seqner=seqner,
                                        saider=saider,
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
                          saider=saider,
                          bigers=bigers,
                          baks=self.baks)

            return

        elif ilk in (Ilks.iss, Ilks.bis):
            self.issue(serder, seqner=seqner, saider=saider, sn=sn, bigers=bigers)
        elif ilk in (Ilks.rev, Ilks.brv):
            self.revoke(serder, seqner=seqner, saider=saider, sn=sn, bigers=bigers)
        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))


    def rotate(self, serder, sn):
        """ Process registry management TEL, non-inception events (vrt)

        Parameters:
            serder (Serder): registry rotation event
            sn (int): sequence number of event

        Returns:
            int: calculated backer threshold
            list: new list of backers after applying cuts and adds to previous list
            list: list of backer adds processed from event
            list: list of backer cuts processed from event

        """

        ked = serder.ked
        ilk = ked["t"]
        dig = ked["p"]


        #labels = VRT_LABELS  # assumes ilk == Ilks.vrt
        #for k in labels:
            #if k not in ked:
                #raise ValidationError("Missing element = {} from {} event for "
                                      #"evt = {}.".format(k, ilk, ked))

        if serder.pre != self.prefixer.qb64:
            raise ValidationError("Mismatch event aid prefix = {} expecting"
                                  " = {} for evt = {}.".format(ked["i"],
                                                               self.prefixer.qb64,
                                                               ked))
        if not sn == (self.sn + 1):  # sn not in order
            raise ValidationError("Invalid sn = {} expecting = {} for evt "
                                  "= {}.".format(sn, self.sn + 1, ked))

        if not self.serder.compare(said=dig):  # prior event dig not match
            raise ValidationError("Mismatch event dig = {} with state dig"
                                  " = {} for evt = {}.".format(ked["p"],
                                                               self.serder.said,
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

    def issue(self, serder, seqner, saider, sn, bigers=None):
        """ Process VC TEL issuance events (iss, bis)

        Validate and process credential issuance events.  If valid, event is persisted
        in local datastore for TEL.  Will escrow event if missing anchor or backer signatures

        Parameters
            serder (Serder): instance of issuance or backer issuance event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event SAID from controlling KEL.
            sn (int): event sequence event
            bigers (list): of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.

        """

        ked = serder.ked
        vcpre = ked["i"]
        ilk = ked["t"]
        vci = vcpre

        #labels = ISS_LABELS if ilk == Ilks.iss else BIS_LABELS
        #for k in labels:
            #if k not in ked:
                #raise ValidationError("Missing element = {} from {} event for "
                                      #"evt = {}.".format(k, ilk, ked))

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
            if not self.verifyAnchor(serder=serder, seqner=seqner, saider=saider):
                self.escrowALEvent(serder=serder, seqner=seqner, saider=saider)
                raise MissingAnchorError("Failure verify event = {} "
                                         "".format(serder.ked,
                                                   ))

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, saider=saider)

        elif ilk == Ilks.bis:  # backer issue
            if self.noBackers is True:
                raise ValidationError("invalid backer issue evt {} against backerless registry {}".
                                      format(ked, self.regk))

            rtoad, baks = self.getBackerState(ked)
            bigers = self.valAnchorBigs(serder=serder,
                                        seqner=seqner,
                                        saider=saider,
                                        bigers=bigers,
                                        toad=rtoad,
                                        baks=baks)

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, saider=saider, bigers=bigers)

        else:
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))

    def revoke(self, serder, seqner, saider, sn, bigers=None):
        """ Process VC TEL revocation events (rev, brv)

        Validate and process credential revocation events.  If valid, event is persisted
        in local datastore for TEL.  Will escrow event if missing anchor or backer signatures

        Parameters
            serder (Serder): instance of issuance or backer issuance event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event digest from controlling KEL.
            sn (int): event sequence event
            bigers (list): of Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.

        """

        ked = serder.ked
        vcpre = ked["i"]
        ilk = ked["t"]

        #labels = REV_LABELS if ilk == Ilks.rev else BRV_LABELS
        #for k in labels:
            #if k not in ked:
                #raise ValidationError("Missing element = {} from {} event for "
                                      #"evt = {}.".format(k, ilk, ked))

        # have to compare with VC issuance serder
        vci = vcpre

        dig = self.reger.getTel(snKey(pre=vci, sn=sn - 1))
        ievt = self.reger.getTvt(dgKey(pre=vci, dig=dig))
        if ievt is None:
            raise ValidationError("revoke without issue... probably have to escrow")

        ievt = bytes(ievt)
        iserder = serdering.SerderKERI(raw=ievt)
        if not iserder.compare(said=ked["p"]):  # prior event dig not match
            raise ValidationError("Mismatch event dig = {} with state dig"
                                  " = {} for evt = {}.".format(ked["p"],
                                                               self.serder.said,
                                                               ked))

        if ilk in (Ilks.rev,):  # simple revoke
            if self.noBackers is False:
                raise ValidationError("invalid simple issue evt {} against backer based registry {}".
                                      format(ked, self.regk))

            # check if fully anchored
            if not self.verifyAnchor(serder=serder, seqner=seqner, saider=saider):
                self.escrowALEvent(serder=serder, seqner=seqner, saider=saider)
                raise MissingAnchorError("Failure verify event = {} "
                                         "".format(serder.ked))

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, saider=saider)
            self.cues.push(dict(kin="revoked", serder=serder))

        elif ilk in (Ilks.brv,):  # backer revoke
            if self.noBackers is True:
                raise ValidationError("invalid backer issue evt {} against backerless registry {}".
                                      format(ked, self.regk))

            rtoad, baks = self.getBackerState(ked)
            bigers = self.valAnchorBigs(serder=serder,
                                        seqner=seqner,
                                        saider=saider,
                                        bigers=bigers,
                                        toad=rtoad,
                                        baks=baks)

            self.logEvent(pre=vci, sn=sn, serder=serder, seqner=seqner, saider=saider, bigers=bigers)
            self.cues.push(dict(kin="revoked", serder=serder))

        else:
            raise ValidationError("Unsupported ilk = {} for evt = {}.".format(ilk, ked))

    def vcState(self, vci):
        """ Calculate state (issued/revoked) of VC from db.

        Returns None if never issued from this Registry

        Parameters:
          vci (str):  qb64 VC identifier

        Returns:
            status (Serder): transaction event state notification message
        """
        digs = []
        for _, _, dig in self.reger.getTelItemPreIter(pre=vci.encode("utf-8")):
            digs.append(dig)

        if len(digs) == 0:
            return None

        vcsn = len(digs) - 1
        vcdig = bytes(digs[-1])

        dgkey = dbing.dgKey(vci, vcdig)  # get message
        raw = self.reger.getTvt(key=dgkey)
        serder = serdering.SerderKERI(raw=bytes(raw))

        if self.noBackers:
            vcilk = Ilks.iss if len(digs) == 1 else Ilks.rev
            ra = dict()
        else:
            vcilk = Ilks.bis if len(digs) == 1 else Ilks.brv
            ra = serder.ked["ra"]

        dgkey = dbing.dgKey(vci, vcdig)
        couple = self.reger.getAnc(dgkey)
        ancb = bytearray(couple)
        seqner = coring.Seqner(qb64b=ancb, strip=True)
        saider = coring.Saider(qb64b=ancb, strip=True)

        return vcstate(vcpre=vci,
                       said=vcdig.decode("utf-8"),
                       sn=vcsn,
                       ri=self.prefixer.qb64,
                       dts=serder.ked['dt'],
                       eilk=vcilk,
                       ra=ra,
                       a=dict(s=seqner.sn, d=saider.qb64),
                       )

    def vcSn(self, vci):
        """ Calculates the current seq no of VC from db.

        Returns None if never issued from this Registry

        Parameters:
          vci (str):  qb64 VC identifier

        Returns:
            int: current TEL sequence number of credential or None if not found

        """
        cnt = self.reger.cntTels(vci)

        return None if cnt == 0 else cnt - 1

    def logEvent(self, pre, sn, serder, seqner, saider, bigers=None, baks=None):
        """ Update associated logs for verified event.

        Update is idempotent. Logs will not write dup at key if already exists.

        Parameters:
            pre (str): is event prefix
            sn (int): is event sequence number
            serder (Serder): is Serder instance of current event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event SAID from controlling KEL.
            bigers (list): is optional list of Siger instance of indexed backer sigs
            baks (list): is optional list of qb64 non-trans identifiers of backers
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes

        dig = serder.saidb
        key = dgKey(pre, dig)
        sealet = seqner.qb64b + saider.qb64b
        self.reger.putAnc(key, sealet)
        if bigers:
            self.reger.putTibs(key, [biger.qb64b for biger in bigers])
        if baks:
            self.reger.delBaks(key)
            self.reger.putBaks(key, [bak.encode("utf-8") for bak in baks])
        self.reger.tets.pin(keys=(pre.decode("utf-8"), dig.decode("utf-8")), val=coring.Dater())
        self.reger.putTvt(key, serder.raw)
        self.reger.putTel(snKey(pre, sn), dig)
        logger.info("Tever state: %s Added to TEL valid said=%s",
                    pre, serder.said)
        logger.debug(f"event=\n{serder.pretty()}\n")

    def valAnchorBigs(self, serder, seqner, saider, bigers, toad, baks):
        """ Validate anchor and backer signatures (bigers) when provided.

        Validates sigers signatures by validating indexes, verifying signatures, and
            validating threshold sith.
        Validate backer receipts by validating indexes, verifying
            backer signatures and validating toad.
        Backer validation is a function of .regk and .local

        Parameters:
            serder (Serder): instance of event
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event said from controlling KEL.
            bigers (list)  Siger instances of indexed witness signatures.
                Index is offset into wits list of associated witness nontrans pre
                from which public key may be derived.
            toad (int):  str hex of witness threshold
            baks (list): qb64 non-transferable prefixes of backers used to
                derive werfers for bigers

        Returns:
            list: unique validated signature verified members of inputed bigers

        """

        berfers = [Verfer(qb64=bak) for bak in baks]

        # get unique verified bigers and bindices lists from bigers list
        bigers, bindices = verifySigs(raw=serder.raw, sigers=bigers, verfers=berfers)
        # each biger now has werfer of corresponding wit

        # check if fully anchored
        if not self.verifyAnchor(serder=serder, seqner=seqner, saider=saider):
            self.escrowALEvent(serder=serder, seqner=seqner, saider=saider, bigers=bigers, baks=baks)
            raise MissingAnchorError("Failure verify event = {}".format(serder.ked))

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
                self.escrowPWEvent(serder=serder, seqner=seqner, saider=saider, bigers=bigers)

                raise MissingWitnessSignatureError("Failure satisfying toad = {} "
                                                   "on witness sigs for {} for evt = {}.".format(toad,
                                                                                                 [siger.qb64 for siger
                                                                                                  in bigers],
                                                                                                 serder.ked))
        return bigers

    def verifyAnchor(self, serder, seqner=None, saider=None):
        """ Retrieve specified anchoring event and verify seal

        Retrieve event from db using anchor, get seal from event eserder and
        verify pre, sn and dig against serder

        Parameters:
            serder (Serder): anchored TEL event
            seqner (Seqner): sequence number of anchoring event
            saider (Saider): digest of anchoring event

        Returns:
             bool: True is anchoring event exists in database and seal is valid against
                   TEL event.

        """

        if seqner is None or saider is None:
            return False

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

        eserder = serdering.SerderKERI(raw=raw)  # deserialize event raw

        if eserder.said != saider.qb64:
            return False

        seal = eserder.ked["a"]
        if seal is None or len(seal) != 1:
            return False

        seal = seal[0]
        spre = seal["i"]
        ssn = seal["s"]
        sdig = seal["d"]

        if spre == serder.ked["i"] and ssn == serder.ked["s"] \
                and serder.said == sdig:
            return True

        return False

    def escrowPWEvent(self, serder, seqner, saider, bigers=None):
        """ Update associated logs for escrow of partially witnessed event

        Parameters:
            serder (Serder): instance of  event
            seqner (Seqner): sequence number for anchor seal
            saider (Saider): digest of anchor
            bigers (list): Siger instance of indexed witness sigs

        """
        dgkey = dgKey(serder.preb, serder.saidb)
        sealet = seqner.qb64b + saider.qb64b
        self.reger.putAnc(dgkey, sealet)
        self.reger.putTibs(dgkey, [biger.qb64b for biger in bigers])
        self.reger.putTvt(dgkey, serder.raw)
        self.reger.putTwe(snKey(serder.preb, serder.sn), serder.saidb)
        logger.debug("Tever state: Escrowed partially witnessed "
                     "event = %s", serder.ked)

    def escrowALEvent(self, serder, seqner, saider, bigers=None, baks=None):
        """ Update associated logs for escrow of anchorless event

        Parameters:
            serder (Serder): instance of  event
            seqner (Seqner): sequence number for anchor seal
            saider (Saider): SAID of anchor
            bigers (list): Siger instance of indexed witness sigs
            baks (list): qb64 of new backers

        Returns:
            bool: True if escrow is successful, False otherwith (eg. already escrowed)

        """
        key = dgKey(serder.preb, serder.saidb)
        if seqner and saider:
            sealet = seqner.qb64b + saider.qb64b
            self.reger.putAnc(key, sealet)
        if bigers:
            self.reger.putTibs(key, [biger.qb64b for biger in bigers])
        if baks:
            self.reger.delBaks(key)
            self.reger.putBaks(key, [bak.encode("utf-8") for bak in baks])
        self.reger.putTvt(key, serder.raw)
        logger.debug("Tever state: Escrowed anchorless event "
                     "event = %s", serder.ked)
        return self.reger.putTae(snKey(serder.preb, serder.sn), serder.saidb)

    def getBackerState(self, ked):
        """ Calculate and return the current list of backers for event dict

        Parameters:
            ked (dict):  event dict

        Returns:
            list:  qb64 of current list of backers for state at ked

        """
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

        rserder = serdering.SerderKERI(raw=bytes(revt))
        # the backer threshold at this event in mgmt TEL
        rtoad = rserder.ked["bt"]

        baks = [bytes(bak).decode("utf-8") for bak in self.reger.getBaks(dgkey)]

        return rtoad, baks


class Tevery:
    """ Tevery (Transaction Event Message Processing Facility)

    Tevery processes an incoming message stream composed of KERI key event related
    messages and attachments.  Tevery acts as a Tever (transaction event verifier)
    factory for managing transaction state of KERI credential registries and associated
    credentials.

    Attributes:
        db (Baser):  local LMDB identifier database
        reger (Reger): local LMDB credential database
        local (bool): True means only process msgs for own events if .regk
                        False means only process msgs for not own events if .regk
        cues (Deck): notices generated from processing events


    """

    TimeoutTSN = 3600

    def __init__(self, reger=None, db=None, local=False, lax=False, cues=None, rvy=None):
        """ Initialize instance:

        Parameters:
            reger (Reger): local LMDB credential database
            db (Baser):  local LMDB identifier database
            local (bool): True means only process msgs for own events if .regk
                        False means only process msgs for not own events if .regk
            cues (Deck): notices generated from processing events


        """
        self.db = db if db is not None else basing.Baser(reopen=True)  # default name = "main"
        self.rvy = rvy
        self.reger = reger if reger is not None else viring.Reger()
        self.local = True if local else False  # local vs nonlocal restrictions
        self.lax = True if lax else False
        self.cues = cues if cues is not None else decking.Deck()

    @property
    def tevers(self):
        """ Returns .reger.tevers read through cache of credential registries """

        return self.reger.tevers

    @property
    def kevers(self):
        """ Returns .db.kevers read through cache of key event logs """

        return self.db.kevers

    @property
    def registries(self):
        """ Returns .reger.registries """

        return self.reger.registries

    def processEvent(self, serder, seqner=None, saider=None, wigers=None):
        """ Process one event serder with attached indexed signatures sigers

        Validates event against current state of registry or credential, creating registry
        on inception events and processing change in state to credential or registry for
        other events

        Parameters:
            serder (Serder): event to process
            seqner (Seqner): issuing event sequence number from controlling KEL.
            saider (Saider): issuing event digest from controlling KEL.
            wigers (list): optional list of Siger instances of attached witness indexed sigs

        """
        ked = serder.ked
        try:  # see if code of pre is supported and matches size of pre
            Prefixer(qb64b=serder.preb)
        except Exception:  # if unsupported code or bad size raises error
            raise ValidationError("Invalid pre = {} for evt = {}."
                                  "".format(serder.pre, ked))

        regk = self.registryKey(serder)
        pre = serder.pre
        ked = serder.ked
        #sn = ked["s"]
        ilk = ked["t"]

        inceptive = ilk in (Ilks.vcp, Ilks.iss, Ilks.bis)

        # validate SN for
        #sn = validateSN(sn, inceptive=inceptive)
        sn = Number(numh=ked["s"]).validate(inceptive=inceptive).sn

        if not self.lax:
            if self.local:
                if regk not in self.registries:  # nonlocal event when in local mode
                    raise ValueError("Nonlocal event regk={} when local mode for registries={}."
                                     "".format(regk, self.registries))
            else:
                if regk in self.registries:  # local event when not in local mode
                    raise ValueError("Local event regk={} when nonlocal mode."
                                     "".format(regk))

        if regk not in self.tevers:  # first seen for this registry
            if ilk in [Ilks.vcp]:
                # incepting a new registry, Tever create will validate anchor, etc.
                tever = Tever(serder=serder,
                              seqner=seqner,
                              saider=saider,
                              bigers=wigers,
                              reger=self.reger,
                              db=self.db,
                              regk=regk,
                              local=self.local,
                              cues=self.cues)
                self.tevers[regk] = tever
                if regk not in self.registries:
                    # witness style backers will need to send receipts so lets queue them up for now
                    # actually, lets not because the Kevery has no idea what to do with them!
                    # self.cues.append(dict(kin="receipt", serder=serder))
                    pass
            else:
                # out of order, need to escrow
                self.escrowOOEvent(serder=serder, seqner=seqner, saider=saider)
                raise OutOfOrderError("escrowed out of order event {}".format(ked))

        else:
            if ilk in (Ilks.vcp,):
                # we don't have multiple signatures to verify so this
                # is already first seen and then lifely duplicitious
                raise LikelyDuplicitousError("Likely Duplicitous event={}.".format(ked))

            tever = self.tevers[regk]
            tever.cues = self.cues
            if ilk in [Ilks.vrt]:
                sno = tever.sn + 1  # proper sn of new inorder event
            else:
                esn = tever.vcSn(pre)
                sno = 0 if esn is None else esn + 1

            #if not serder.saider.verify(sad=serder.sad):
                #raise ValidationError("Invalid SAID {} for event {}".format(said, serder.ked))

            if sn > sno:  # sn later than sno so out of order escrow
                # escrow out-of-order event
                self.escrowOOEvent(serder=serder, seqner=seqner, saider=saider)
                raise OutOfOrderError("Out-of-order event={}.".format(ked))
            elif sn == sno:  # new inorder event
                tever.update(serder=serder, seqner=seqner, saider=saider, bigers=wigers)

                if regk not in self.registries:
                    # witness style backers will need to send receipts so lets queue them up for now
                    # actually, lets not because the Kevery has no idea what to do with them!
                    # self.cues.append(dict(kin="receipt", serder=serder))
                    pass
            else:  # duplicitious
                raise LikelyDuplicitousError("Likely Duplicitous event={} with sn {}.".format(ked, sn))

    def processQuery(self, serder, source=None, sigers=None, cigars=None):
        """ Process TEL query event message (qry)

        Process query mode replay message for collective or single element query.
        Will cue response message with kin of "replay".  Assume promiscuous mode for now.

        Parameters:
            serder (Serder): is query message serder
            source (qb64): identifier prefix of querier
            sigers (list): Siger instances of attached controller indexed sigs
            cigars (list): Siger instances of non-transferable signatures

        """
        ked = serder.ked

        ilk = ked["t"]
        route = ked["r"]
        qry = ked["q"]

        # do signature validation and replay attack prevention logic here
        # src, dt, route

        if route == "tels":
            mgmt = qry["ri"]
            src = qry["src"]

            cloner = self.reger.clonePreIter(pre=mgmt, fn=0)  # create iterator at 0
            msgs = list()  # outgoing messages
            for msg in cloner:
                msgs.append(msg)

            if vci := qry["i"]:
                cloner = self.reger.clonePreIter(pre=vci, fn=0)  # create iterator at 0
                for msg in cloner:
                    msgs.append(msg)

            if msgs:
                self.cues.append(dict(kin="replay", src=src, dest=source.qb64, msgs=msgs))
        elif route == "tsn":
            ri = qry["ri"]
            if ri in self.tevers:
                tever = self.tevers[ri]
                tsn = tever.state()
                self.cues.push(dict(kin="reply", route="/tsn/registry", data=asdict(tsn), dest=source))

                if vcpre := qry["i"]:
                    tsn = tever.vcState(vcpre=vcpre)
                    self.cues.push(dict(kin="reply", route="/tsn/credential", data=asdict(tsn), dest=source))

        else:
            raise ValidationError("invalid query message {} for evt = {}".format(ilk, ked))

    def registerReplyRoutes(self, router):
        """ Register the routes for processing messages embedded in `rpy` event messages

        Parameters:
            router(Router): reply message router

        """
        router.addRoute("/tsn/registry/{aid}", self, suffix="RegistryTxnState")
        router.addRoute("/tsn/credential/{aid}", self, suffix="CredentialTxnState")

    def processReplyRegistryTxnState(self, *, serder, saider, route, cigars=None, tsgs=None, **kwargs):
        """ Process one reply message for key state = /tsn/registry

         Process one reply message for key state = /tsn/registry
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
           "r" : "/tsn/EgHOJJ9mgNosU2hgt7bsM8AViwgz--ey3ZXWgfIcxdpI",
           "a" :
             {
               "v": "KERI10JSON0001b0_",
               "i": "EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",
               "s": "1",
               "d": "EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0",
               "ii": "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",
               "dt": "2021-01-01T00:00:00.000000+00:00",
               "et": "vrt",
               "a": {
                "s": 2,
                "d": "Ef12IRHtb_gVo5ClaHHNV90b43adA0f8vRs3jeU-AstY"
               },
               "bt": "1",
               "br": [],
               "ba": [
                "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
               ],
               "b": [
                "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
               ],
               "c": []
             }
         }

         """
        cigars = cigars if cigars is not None else []
        tsgs = tsgs if tsgs is not None else []

        # reply specific logic
        if not route.startswith("/tsn"):
            raise ValidationError(f"Usupported route={route} in {Ilks.rpy} "
                                  f"msg={serder.ked}.")
        aid = kwargs["aid"]
        data = serder.ked["a"]
        dater = coring.Dater(dts=serder.ked["dt"])

        rsr = viring.RegStateRecord(**data)

        # fetch from serder to process
        regk = rsr.i
        pre = rsr.ii
        sn = int(rsr.s, 16)

        if pre not in self.kevers:
            if self.reger.txnsb.escrowStateNotice(typ="registry-mae", pre=regk, aid=aid, serder=serder, saider=saider,
                                                  dater=dater, cigars=cigars, tsgs=tsgs):
                self.cues.append(dict(kin="query", q=dict(pre=pre)))

            raise kering.MissingAnchorError("Failure verify event = {} ".format(serder.ked))

        # Load backers from either tsn or Kever of issuer
        cnfg = rsr.c
        if TraitDex.NoBackers in cnfg:
            kevers = self.kevers[pre]
            baks = kevers.wits
        else:
            baks = rsr.b

        wats = set()
        for _, habr in self.db.habs.getItemIter():
            wats |= set(habr.watchers)

        # not in promiscuous mode
        if not self.lax:
            # check source and ensure we should accept it
            if aid != pre and \
                    aid not in baks and \
                    aid not in wats:
                raise kering.UntrustedKeyStateSource("transaction state notice for {} from untrusted source {} "
                                                     .format(rsr.i, aid))

        if regk in self.tevers:
            tever = self.tevers[regk]
            if int(rsr.s, 16) < tever.sn:
                raise ValidationError("Skipped stale transaction state at sn {} for {}."
                                      "".format(rsr.s, rsr.i))

        keys = (regk, aid,)
        osaider = self.reger.txnsb.current(keys=keys)  # get old said if any

        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=osaider, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise kering.UnverifiedReplyError(f"Unverified registry txn state reply.")

        ldig = self.reger.getTel(key=snKey(pre=regk, sn=sn))  # retrieve dig of last event at sn.

        # Only accept key state if for last seen version of event at sn
        if ldig is None:  # escrow because event does not yet exist in database
            if self.reger.txnsb.escrowStateNotice(typ="registry-ooo", pre=regk, aid=aid, serder=serder, saider=saider,
                                                  dater=dater, cigars=cigars, tsgs=tsgs):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk)))

            raise kering.OutOfOrderTxnStateError("Out of order txn state={}.".format(rsr))

        tsaider = coring.Saider(qb64=rsr.d)
        ldig = bytes(ldig)
        # retrieve last event itself of signer given sdig
        sraw = self.reger.getTvt(key=dgKey(pre=regk, dig=ldig))
        # assumes db ensures that sraw must not be none because sdig was in KE
        sserder = serdering.SerderKERI(raw=bytes(sraw))

        if sserder.said != tsaider.qb64:  # mismatch events problem with replay
            raise ValidationError("Mismatch keystate at sn = {} with db."
                                  "".format(rsr.s))

        self.reger.txnsb.updateReply(aid=aid, serder=serder, saider=tsaider, dater=dater)
        self.cues.append(dict(kin="txnStateSaved", record=rsr))

    def processReplyCredentialTxnState(self, *, serder, saider, route, cigars=None, tsgs=None, **kwargs):
        """ Process one reply message for key state = /tsn/registry

         Process one reply message for key state = /tsn/registry
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
           "r" : "/tsn/EgHOJJ9mgNosU2hgt7bsM8AViwgz--ey3ZXWgfIcxdpI",
           "a" :
             {
              "v": "KERI10JSON00012d_",
              "i": "EDGhJ8V1tuwH55Bk0fBFe9L0za2BUNOt2FX4GUeOLNHQ",
              "s": "0",
              "d": "ENNTabgWbaNqOKLqEZdQCjxbafwwSoXNzAsE1Enq-kdk",
              "ri": "EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",
              "a": {
               "s": 3,
               "d": "Ex7i6wv4YzDRTO9_iHkTQSXrvLYldSd_UEjNfqia3Pqc"
              },
              "dt": "2021-01-01T00:00:00.000000+00:00",
              "et": "bis"
             }
         }

         """
        cigars = cigars if cigars is not None else []
        tsgs = tsgs if tsgs is not None else []

        # reply specific logic
        if not route.startswith("/tsn"):
            raise ValidationError(f"Usupported route={route} in {Ilks.rpy} "
                                  f"msg={serder.ked}.")
        aid = kwargs["aid"]
        data = serder.ked["a"]
        dater = coring.Dater(dts=serder.ked["dt"])

        vsr = viring.VcStateRecord(**data)

        # fetch from serder to process
        regk = vsr.ri
        vci = vsr.i
        sn = int(vsr.s, 16)
        ra = vsr.ra

        if 's' in ra:
            regsn = int(ra["s"], 16)
        else:
            regsn = 0

        if regk not in self.tevers or self.tevers[regk].sn < regsn:
            if self.reger.txnsb.escrowStateNotice(typ="credential-mre", pre=vci, aid=aid, serder=serder,
                                                  saider=saider, dater=dater, cigars=cigars, tsgs=tsgs):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk)))

            raise kering.MissingRegistryError("Failure verify event = {} ".format(serder.ked))

        tever = self.tevers[regk]
        pre = tever.pre

        if pre not in self.kevers:
            if self.reger.txnsb.escrowStateNotice(typ="credential-mae", pre=vci, aid=aid, serder=serder,
                                                  saider=saider, dater=dater, cigars=cigars, tsgs=tsgs):
                self.cues.append(dict(kin="query", q=dict(pre=aid)))

            raise kering.MissingAnchorError("Failure verify event = {} ".format(serder.ked))

        # Load backers from either tsn or Kever of issuer
        if tever.noBackers:
            kevers = self.kevers[pre]
            baks = kevers.wits
        else:
            baks = tever.baks

        wats = set()
        for _, habr in self.db.habs.getItemIter():
            wats |= set(habr.watchers)

        # not in promiscuous mode
        if not self.lax:
            # check source and ensure we should accept it
            if aid != pre and \
                    aid not in baks and \
                    aid not in wats:
                raise kering.UntrustedKeyStateSource("transaction state notice for {} from untrusted source {} "
                                                     .format(vsr.i, aid))

        keys = (vci, aid,)
        osaider = self.reger.txnsb.current(keys=keys)  # get old said if any

        # BADA Logic
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=osaider, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise kering.UnverifiedReplyError(f"Unverified credential state reply.")

        ldig = self.reger.getTel(key=snKey(pre=vci, sn=sn))  # retrieve dig of last event at sn.

        # Only accept key state if for last seen version of event at sn
        if ldig is None:  # escrow because event does not yet exist in database
            if self.reger.txnsb.escrowStateNotice(typ="credential-ooo", pre=vci, aid=aid, serder=serder,
                                                  saider=saider, dater=dater, cigars=cigars, tsgs=tsgs):
                self.cues.append(dict(kin="telquery", q=dict(ri=regk, i=vci)))

            raise kering.OutOfOrderTxnStateError("Out of order txn state={}.".format(vsr))

        tsaider = coring.Saider(qb64=vsr.d)
        ldig = bytes(ldig)
        # retrieve last event itself of signer given sdig
        sraw = self.reger.getTvt(key=dgKey(pre=vci, dig=ldig))
        # assumes db ensures that sraw must not be none because sdig was in KE
        sserder = serdering.SerderKERI(raw=bytes(sraw))

        if sn < sserder.sn:
            raise ValidationError("Stale txn state at sn = {} with db."
                                  "".format(vsr.s))

        if sserder.said != tsaider.qb64:  # mismatch events problem with replay
            raise ValidationError("Mismatch txn state at sn = {} with db."
                                  "".format(vsr.s))

        self.reger.txnsb.updateReply(aid=aid, serder=serder, saider=tsaider, dater=dater)
        self.cues.append(dict(kin="txnStateSaved", record=vsr))

    @staticmethod
    def registryKey(serder):
        """  Utility method to extract registry key from any type of TEL serder

        Parameters:
            serder (Serder): event messate

        Returns:
            str: qb64 registry identifier
        """
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

    def escrowOOEvent(self, serder, seqner, saider):
        """ Escrow out-of-order TEL events.

        Saves the serialized event, anchor and event digest in escrow for any
        event that is received out of order.

        Examples include registry rotation events, credential issuance event
         received before the registry inception event or a credential revocation
         event received before the issuance event.

        Parameters:
            serder (Serder): serder of event message
            seqner (Seqner): sequence number of anchoring TEL event
            saider (Diger) digest of anchoring TEL event


        """
        key = dgKey(serder.preb, serder.saidb)
        self.reger.putTvt(key, serder.raw)
        sealet = seqner.qb64b + saider.qb64b
        self.reger.putAnc(key, sealet)
        self.reger.putOot(snKey(serder.preb, serder.sn), serder.saidb)
        logger.debug("Tever state: Escrowed our of order TEL event "
                     "event = %s", serder.ked)

    def processEscrows(self):
        """ Loop through escrows and process and events that may now be finalized """

        try:
            self.processEscrowAnchorless()
            self.processEscrowOutOfOrders()
            self.reger.txnsb.processEscrowState(typ="credential-mre", processReply=self.processReplyCredentialTxnState,
                                                extype=kering.MissingRegistryError)
            self.reger.txnsb.processEscrowState(typ="credential-mae", processReply=self.processReplyCredentialTxnState,
                                                extype=kering.MissingAnchorError)
            self.reger.txnsb.processEscrowState(typ="credential-ooo", processReply=self.processReplyCredentialTxnState,
                                                extype=kering.OutOfOrderTxnStateError)
            self.reger.txnsb.processEscrowState(typ="registry-mae", processReply=self.processReplyRegistryTxnState,
                                                extype=kering.MissingAnchorError)
            self.reger.txnsb.processEscrowState(typ="registry-ooo", processReply=self.processReplyRegistryTxnState,
                                                extype=kering.OutOfOrderTxnStateError)

        except Exception as ex:  # log diagnostics errors etc
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Tevery escrow process error: %s", ex.args[0])
            else:
                logger.error("Tevery escrow process error: %s", ex.args[0])

    def processEscrowOutOfOrders(self):
        """ Loop through out of order escrow:

         Process out of order events in the following way:
           1. loop over event digests saved in oots
           2. deserialize event out of tvts
           3. read anchor information out of .ancs
           4. perform process event
           5. Remove event digest from oots if processed successfully or a non-out-of-order event occurs.

        """
        for key, digb in self.reger.getOotItemIter(): # (pre, snb, digb) in self.reger.getOotItemIter()
            try:
                #sn = int(snb, 16)
                pre, sn = splitSnKey(key)
                dgkey = dgKey(pre, digb)
                traw = self.reger.getTvt(dgkey)
                if traw is None:
                    # no event so raise ValidationError which unescrows below
                    logger.info("Tevery unescrow error: Missing event at."
                                "dig = %s", bytes(digb))

                    raise ValidationError("Missing escrowed evt at dig = {}."
                                          "".format(bytes(digb)))

                tserder = serdering.SerderKERI(raw=bytes(traw))  # escrowed event

                bigers = None
                if tibs := self.reger.getTibs(key=dgkey):
                    bigers = [indexing.Siger(qb64b=tib) for tib in tibs]

                couple = self.reger.getAnc(dgkey)
                if couple is None:
                    logger.info("Tevery unescrow error: Missing anchor at."
                                "dig = %s", bytes(digb))

                    raise ValidationError("Missing escrowed anchor at dig = {}."
                                          "".format(bytes(digb)))
                ancb = bytearray(couple)
                seqner = coring.Seqner(qb64b=ancb, strip=True)
                saider = coring.Saider(qb64b=ancb, strip=True)

                self.processEvent(serder=tserder, seqner=seqner, saider=saider, wigers=bigers)

            except OutOfOrderError as ex:
                # still waiting on missing prior event to validate
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Tevery unescrow failed: %s", ex.args[0])
                else:
                    logger.error("Tevery unescrow failed: %s", ex.args[0])

            except Exception as ex:  # log diagnostics errors etc
                # error other than out of order so remove from OO escrow
                self.reger.delOot(snKey(pre, sn))  # removes one escrow at key val
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Tevery unescrowed: %s", ex.args[0])
                else:
                    logger.error("Tevery unescrowed: %s", ex.args[0])

            else:  # unescrow succeeded, remove from escrow
                # We don't remove all escrows at pre,sn because some might be
                # duplicitous so we process remaining escrows in spite of found
                # valid event escrow.
                self.reger.delOot(snKey(pre, sn))  # removes from escrow
                logger.info("Tevery unescrow succeeded in valid event: "
                            "said=%s", tserder.said)
                logger.debug(f"event=\n{tserder.pretty()}\n")

    def processEscrowAnchorless(self):
        """ Process escrow of TEL events received before the anchoring KEL event.

        Process anchorless events in the following way:
           1. loop over event digests saved in taes
           2. deserialize event out of tvts
           3. load backer signatures out of tibs
           4. read anchor information out of ancs
           5. perform process event
           6. Remove event digest from oots if processed successfully or a non-anchorless event occurs.

        """
        for key, digb in self.reger.getTaeItemIter():  #(pre, snb, digb) in self.reger.getTaeItemIter()
            pre, sn = splitSnKey(key)
            #sn = int(snb, 16)
            try:
                dgkey = dgKey(pre, digb)
                traw = self.reger.getTvt(dgkey)
                if traw is None:
                    # no event so raise ValidationError which unescrows below
                    logger.info("Tevery unescrow error: Missing event at."
                                "dig = %s", bytes(digb))

                    raise ValidationError("Missing escrowed evt at dig = {}."
                                          "".format(bytes(digb)))

                tserder = serdering.SerderKERI(raw=bytes(traw))  # escrowed event

                bigers = None
                if tibs := self.reger.getTibs(key=dgkey):
                    bigers = [indexing.Siger(qb64b=tib) for tib in tibs]

                couple = self.reger.getAnc(dgkey)
                if couple is None:
                    logger.info("Tevery unescrow error: Missing anchor at."
                                "dig = %s", bytes(digb))

                    raise MissingAnchorError("Missing escrowed anchor at dig = {}."
                                             "".format(bytes(digb)))
                ancb = bytearray(couple)
                seqner = coring.Seqner(qb64b=ancb, strip=True)
                saider = coring.Saider(qb64b=ancb, strip=True)

                self.processEvent(serder=tserder, seqner=seqner, saider=saider, wigers=bigers)

            except MissingAnchorError as ex:
                # still waiting on missing prior event to validate
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Tevery unescrow failed: %s", ex.args[0])
                else:
                    logger.error("Tevery unescrow failed: %s", ex.args[0])

            except Exception as ex:  # log diagnostics errors etc
                # error other than out of order so remove from OO escrow
                self.reger.delTae(snKey(pre, sn))  # removes one escrow at key val
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Tevery unescrowed: %s", ex.args[0])
                else:
                    logger.error("Tevery unescrowed: %s", ex.args[0])

            else:  # unescrow succeeded, remove from escrow
                # We don't remove all escrows at pre,sn because some might be
                # duplicitous so we process remaining escrows in spite of found
                # valid event escrow.
                self.reger.delTae(snKey(pre, sn))  # removes from escrow
                logger.info("Tevery unescrow succeeded in valid event: "
                            "said=%s", tserder.said)
                logger.debug(f"event=\n{tserder.pretty()}\n")
