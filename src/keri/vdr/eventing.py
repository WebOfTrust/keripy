from collections import namedtuple
from dataclasses import dataclass, astuple

import blake3

from keri.core.coring import (Matter, MtrDex, Serder, Serials, Versify, Prefixer,
                              Ilks)
from keri.core.eventing import SealEvent, ample
from keri.kering import EmptyMaterialError, DerivationError
from keri.kering import Version

from orderedset import OrderedSet as oset


@dataclass(frozen=True)
class TraitCodex:
    """
    TraitCodex is codex of TEL inception configuration trait code strings
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    """
    NoBackers:         str = 'NB'  # Do not allow any backers for registry

    def __iter__(self):
        return iter(astuple(self))


TraitDex = TraitCodex()  # Make instance


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
        else:  #  compute default f and m for len(baks)
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

    if (bakset & cutset) != cutset:  #  some cuts not in wits
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


def backer_issue(
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


def backer_revoke(
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

    Currently placeholder
    """


class Tevery:
    """
    Tevery (Transaction Event Message Processing Facility)

    Currently placeholder
    """

