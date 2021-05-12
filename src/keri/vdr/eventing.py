from collections import namedtuple
from dataclasses import dataclass, astuple

import blake3

from keri.core.coring import Matter, MtrDex, Serder, Serials, Versify
from keri.core.eventing import SealEvent
from keri.kering import EmptyMaterialError, DerivationError
from keri.kering import Version

Ilkage = namedtuple("Ilkage", 'vcp vrt iss rev, bis, brv')  # Event ilk (type of event)

Ilks = Ilkage(vcp='vcp', vrt='vrt', iss='iss', rev='rev', bis="bis", brv="brv")


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
        baks=None,
        cnfg=None,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of vcp message event
    Utility function to create a Registry inception event

    Parameters:
         pre is issuer identifier prefix qb64
         cnfg is list of strings TraitDex of configuration traits
         baks is the initial list of backers prefixes for VCs in the Registry

         version is the API version
         kind is the event type

    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 0
    ilk = Ilks.vcp

    cnfg = cnfg if cnfg is not None else []

    if TraitDex.NoBackers in cnfg and len(baks) > 0:
        raise ValueError("{} backers specified for NB vcp, 0 allowed".format(len(baks)))

    ked = dict(v=vs,  # version string
               i="",  # qb64 prefix
               ii=pre,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
               c=cnfg,
               b=baks  # list of qb64 may be empty
               )

    prefixer = Prefixer(ked=ked)  # Derive AID from ked and code
    ked["i"] = prefixer.qb64  # update pre element in ked with pre qb64

    return Serder(ked=ked)  # return serialized ked


def rotate(
        pre,
        regk,
        sn=1,
        baks=None,
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
        baks is new list of backers prefixes for VCs in the Registry


    """

    if sn < 1:
        raise ValueError("Invalid sn = {} for vrt.".format(sn))

    vs = Versify(version=version, kind=kind, size=0)
    ilk = Ilks.vrt

    ked = dict(v=vs,  # version string
               i=regk,  # qb64 prefix
               ii=pre,
               s="{:x}".format(sn),  # hex string no leading zeros lowercase
               t=ilk,
               b=baks,  # list of qb64 may be empty
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
        regk,
        version=Version,
        kind=Serials.json,
):
    """

    Returns serder of rev message event
    Utility function to create a VC revocation vent

    Parameters:
        vcdig is hash digest of vc content qb64
        regk is regsitry identifier prefix qb64

    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 1
    ilk = Ilks.rev

    ked = dict(v=vs,
               i=vcdig,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
               ri=regk
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
    """

    vs = Versify(version=version, kind=kind, size=0)
    isn = 1
    ilk = Ilks.rev

    seal = SealEvent(regk, regsn, regd)

    ked = dict(v=vs,
               i=vcdig,
               s="{:x}".format(isn),  # hex string no leading zeros lowercase
               t=ilk,
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


class Prefixer(Matter):
    """
    Prefixer is Matter subclass for autonomic identifier prefix using
    derivation as determined by code from ked

    Attributes:

    Inherited Properties:  (see Matter)
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .nontrans is Boolean, True when non-transferable derivation code False otherwise

    Properties:

    Methods:
        verify():  Verifies derivation of aid prefix from a ked

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64
    """
    Dummy = "#"  # dummy spaceholder char for pre. Must not be a valid Base64 char
    # element labels to exclude in digest or signature derivation from inception vcp
    VcpExcludes = ["i"]

    def __init__(self, raw=None, code=MtrDex.Blake3_256, ked=None, **kwa):
        """
        assign ._derive to derive derivatin of aid prefix from ked
        assign ._verify to verify derivation of aid prefix  from ked

        Default code is None to force EmptyMaterialError when only raw provided but
        not code.

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:
            ked is dict of transaction event fields

        """
        try:
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not ked or (not code and "i" not in ked):
                raise ex

            if not code:  # get code from pre in ked
                super(Prefixer, self).__init__(qb64=ked["i"], code=code, **kwa)
                code = self.code

            if code == MtrDex.Blake3_256:
                self._derive = self._derive_blake3_256
            else:
                raise ValueError("Unsupported code = {} for prefixer.".format(code))

            # use ked and ._derive from code to derive aid prefix and code
            raw, code = self._derive(ked=ked)
            super(Prefixer, self).__init__(raw=raw, code=code, **kwa)

        if self.code == MtrDex.Blake3_256:
            self._verify = self._verify_blake3_256
        else:
            raise ValueError("Unsupported code = {} for prefixer.".format(self.code))

    def derive(self, ked, seed=None, secret=None):
        """
        Returns tuple (raw, code) of aid prefix as derived from key event dict ked.
                uses a derivation code specific _derive method

        Parameters:
            ked is inception key event dict
            seed is only used for sig derivation it is the secret key/secret

        """
        if ked["t"] is not Ilks.vcp:
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ked["t"]))
        return self._derive(ked=ked)

    def verify(self, ked, prefixed=False):
        """
        Returns True if derivation from ked for .code matches .qb64 and
                If prefixed also verifies ked["i"] matches .qb64
                False otherwise

        Parameters:
            ked is inception key event dict
        """
        if ked["t"] is not Ilks.vcp:
            raise ValueError("Nonincepting ilk={} for prefix derivation.".format(ked["t"]))
        return self._verify(ked=ked, pre=self.qb64, prefixed=prefixed)

    def _derive_blake3_256(self, ked):
        """
        Returns tuple (raw, code) of basic Ed25519 pre (qb64)
            as derived from inception key event dict ked
        """
        ked = dict(ked)  # make copy so don't clobber original ked
        ilk = ked["t"]
        if ilk == Ilks.vcp:
            labels = [key for key in ked if key not in self.VcpExcludes]
        else:
            raise DerivationError("Invalid ilk = {} to derive pre.".format(ilk))

        # put in dummy pre to get size correct
        ked["i"] = "{}".format(self.Dummy * Matter.Codes[MtrDex.Blake3_256].fs)
        serder = Serder(ked=ked)
        ked = serder.ked  # use updated ked with valid vs element

        for l in labels:
            if l not in ked:
                raise DerivationError("Missing element = {} from ked.".format(l))

        dig = blake3.blake3(serder.raw).digest()
        return dig, MtrDex.Blake3_256

    def _verify_blake3_256(self, ked, pre, prefixed=False):
        """
        Returns True if verified False otherwise
        Verify derivation of fully qualified Base64 prefix from
        inception key event dict (ked)

        Parameters:
            ked is inception key event dict
            pre is Base64 fully qualified default to .qb64
        """
        try:
            raw, code = self._derive_blake3_256(ked=ked)
            crymat = Matter(raw=raw, code=MtrDex.Blake3_256)
            if crymat.qb64 != pre:
                return False

            if prefixed and ked["i"] != pre:
                return False

        except Exception as ex:
            return False

        return True
