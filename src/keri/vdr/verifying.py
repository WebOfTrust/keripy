# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.verifying module

VC verifier support
"""

from ..core import parsing
from ..core import eventing as ceventing
from ..core.coring import Verfer, Cigar
from ..vdr import eventing
from ..vdr.eventing import VcStates
from ..vdr.viring import Registry

from .. import help

logger = help.ogler.getLogger()


class Verifier:
    """
    Verifier class accepts and validates TEL events.

    """
    def __init__(self, hab, name="test", reger=None, tevers=None):
        """
        Initialize Verifier instance

        Parameters:
            hab is Habitat for this verifier's context
            name is user synonym for this verifier
            reger is Registry database instance
            tevers is dict of Tever instances keys by registry identifier
        """
        self.hab = hab
        self.reger = reger if reger is not None else Registry(name=name)
        self.tevers = tevers if tevers is not None else dict()


        self.tvy = eventing.Tevery(tevers=self.tevers, reger=self.reger, db=self.hab.db,
                                   regk=None, local=False)
        self.psr = parsing.Parser(framed=True, kvy=self.hab.kvy, tvy=self.tvy)


    def verify(self, pre, sidx, regk, vcid, vcdata, vcsig):
        """
        Verifiy the signature and issuance status of a verifiable credential.
        Returns True if the signature is valid

        Parameters:
            pre is qb64 prefix identifier of issuer
            sidx is Int signing key index into issuers keys
            regk is qb64 identifier of the registry
            vcpre is qb64 identifier of VC
            vcdata is the serialized content of the VC
            vcsig is the signature of VC
        """

        state = self.tevers[regk].vcState(vcid)
        if state is None or state is VcStates.revoked:
            return False

        # we don't know about this issuer
        if pre not in self.hab.kevers:
            return False

        kever = self.hab.kevers[pre]
        ksn = kever.state()

        # invalid signature index
        if sidx >= len(ksn.ked["k"]):
            return False

        # assume single signature for now
        verfer = kever.verfers[sidx]

        cigar = Cigar(qb64=vcsig)

        if verfer.verify(sig=cigar.raw, ser=vcdata) is True:
            return True

        return False


    def query(self, regk, vcid, res, dt=None, dta=None, dtb=None):
        """
        Returns query message for querying for a single element of type res
        """
        kever = self.hab.kever
        serder = eventing.query(regk=regk, vcid=vcid, res=res, dt=dt, dta=dta, dtb=dtb)

        sigers = self.hab.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        msg = ceventing.messagize(serder, sigers=sigers)

        return msg


    @staticmethod
    def processCuesIter(cues):
        """
        Iterate through cues and yields one or more msgs for each cue.

        Parameters:
            cues is deque of cues

        """
        while cues:  # iteratively process each cue in cues
            cue = cues.popleft()
            cueKin = cue["kin"]  # type or kind of cue

            if cueKin in ("replay", ):
                msgs = cue["msgs"]
                yield msgs

