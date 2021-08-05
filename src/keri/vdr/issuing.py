# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.issuing module

VC issuer support
"""
from hio.base import doing

from .. import kering
from ..core import parsing
from ..core.coring import Counter, Seqner, CtrDex, MtrDex, Serder
from ..core.eventing import SealEvent, SealSource, TraitDex
from ..db.dbing import snKey, dgKey
from ..vdr import eventing
from ..vdr.viring import Registry, nsKey


class Issuer:
    """
    Issuer provides encapsulation of creating a Verifiable Credential Registry with issuance
    and revocation of VCs against that registry.

    The Registry consists of 1 management TEL for maintaining the state of the registry wrt special
    Backers that can act as witnesses of VC events, and 1 VC TEL for each VC issued that tracks the
    issuance and revocation status of those VCs.

    """

    def __init__(self, hab, name="test", reger=None, tevers=None, regk=None, estOnly=False, **kwa):
        """
        Initialize Instance

        Parameters:
            name is the alias for this issuer
            hab is Habitat instance of local controller's context
            reger is Registry database instance for controller's credentials
            tevers is a dict of Tever instances keys by qb64 prefix of registry
            noBackers is boolean True to allow specification of TEL specific backers
            backers is the initial list of backer prefixes qb64 for VCs in the Registry
            toad is int or str hex of witness threshold
            estOnly is boolean True for forcing rotation events for every TEL event.
        """

        self.hab = hab
        self.name = name
        self.estOnly = estOnly
        self.regk = regk
        self.incept = None
        self.ianchor = None

        self.reger = reger if reger is not None else Registry(name=name)
        self.tevers = tevers if tevers is not None else dict()
        self.inited = False


        # save init kwy word arg parameters as ._inits in order to later finish
        # init setup elseqhere after databases are opened if not below
        self._inits = kwa

        if self.hab.inited:
            self.setup(**self._inits)

    def setup(self, *, noBackers=False, baks=None, toad=None, ):

        if self.regk is None:
            self.regi = 0

            self.noBackers = noBackers

            # save backers locally for now.  will be managed by tever when implemented
            self.backers = baks if baks is not None else []

            self.cnfg = [TraitDex.NoBackers] if self.noBackers else []

            self.regser = eventing.incept(self.hab.pre,
                                          baks=self.backers,
                                          toad=toad,
                                          cnfg=self.cnfg,
                                          code=MtrDex.Blake3_256)
            self.regk = self.regser.pre
            self.tvy = eventing.Tevery(tevers=self.tevers, reger=self.reger, db=self.hab.db,
                                       regk=self.regk, local=True)
            self.psr = parsing.Parser(framed=True, kvy=self.hab.kvy, tvy=self.tvy)

            rseal = SealEvent(self.regk, self.regser.ked["s"], self.regser.diger.qb64)

            if self.estOnly:
                self.ianchor = self.hab.rotate(data=[rseal._asdict()])
            else:
                self.ianchor = self.hab.interact(data=[rseal._asdict()])

            seal = SealSource(s=self.hab.kever.sn, d=self.hab.kever.serder.dig)

            msg = self.messagize(serder=self.regser, seal=seal)

            # Process message in local Tevery when ready for now assign to self for testing
            self.incept = bytearray(msg)
            self.psr.parseOne(ims=msg)
            if self.regk not in self.tevers:
                raise kering.ConfigurationError("Improper Issuer inception for "
                                                "pre={}.".format(self.regk))
        else:
            self.tvy = eventing.Tevery(tevers=self.tevers, reger=self.reger, db=self.hab.db,
                                       regk=self.regk, local=True)
            self.psr = parsing.Parser(framed=True, kvy=self.hab.kvy, tvy=self.tvy)

            clone = self.reger.clonePreIter(self.regk)
            for msg in clone:
                self.psr.parseOne(ims=msg)

            if self.regk not in self.tevers:
                raise kering.ConfigurationError("Improper Issuer inception for "
                                                "pre={}.".format(self.regk))

        tever = self.tevers[self.regk]
        self.noBackers = tever.noBackers
        self.backers = tever.baks
        self.regi = int(tever.serder.ked["s"], 16)

        self.inited = True

    def rotate(self, toad=None, cuts=None, adds=None):
        """
        Rotate backer list for registry

        Parameters:
            toad is int or str hex of backer threshold after cuts and adds
            cuts is list of qb64 pre of backers to be removed from witness list
            adds is list of qb64 pre of backers to be added to witness list
        """

        if self.noBackers:
            raise ValueError("Attempt to rotate registry {} that does not support backers".format(self.regk))

        tever = self.tevers[self.regk]
        serder = eventing.rotate(dig=self.regser.dig, regk=self.regk, sn=self.regi + 1, toad=toad, baks=self.backers,
                                 adds=adds, cuts=cuts)

        self.regser = serder
        rseal = SealEvent(self.regk, serder.ked["s"], self.regser.diger.qb64)

        tevt, kevt = self.anchorMsg(serder, rseal._asdict())

        self.psr.parseOne(ims=bytearray(tevt))
        if tever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Issuer registry rotation for "
                                         "pre={}.".format(self.regk))

        tever = self.tevers[self.regk]
        self.backers = tever.baks
        self.regi = int(tever.serder.ked["s"], 16)

        return tevt, kevt

    def issue(self, vcdig):
        """

        Create and process an iss or bis message event

        Parameters:
            vcdig is hash digest of vc content qb64

        """

        if self.noBackers:
            serder = eventing.issue(vcdig=vcdig, regk=self.regk)
        else:
            serder = eventing.backerIssue(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.diger.qb64)

        rseal = SealEvent(vcdig, serder.ked["s"], serder.diger.qb64)

        msg, kevt = self.anchorMsg(serder, rseal._asdict())

        # Process message in local Tevery when ready
        self.psr.parseOne(ims=bytearray(msg))  # make copy as kvr deletes

        return msg, kevt

    def revoke(self, vcdig):
        """

        Create and process iss message event

        Parameters:
            vcdig is hash digest of vc content qb64

        """

        vckey = nsKey([self.regk, vcdig])
        vcser = self.reger.getTel(snKey(pre=vckey, sn=0))
        if vcser is None:
            raise kering.ValidationError("Invalid revoke of {} that has not been issued "
                                         "pre={}.".format(vcdig, self.regk))
        ievt = self.reger.getTvt(dgKey(pre=vckey, dig=vcser))
        iserder = Serder(raw=bytes(ievt))

        if self.noBackers:
            serder = eventing.revoke(vcdig=vcdig, regk=self.regk, dig=iserder.dig)
        else:
            serder = eventing.backerRevoke(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.diger.qb64,
                                           dig=iserder.dig)

        rseal = SealEvent(vcdig, serder.ked["s"], serder.diger.qb64)

        msg, kevt = self.anchorMsg(serder, rseal._asdict())

        # Process message in local Tevery when ready
        self.psr.parseOne(ims=bytearray(msg))  # make copy as kvr deletes

        return msg, kevt

    @staticmethod
    def messagize(serder, seal):
        msg = bytearray(serder.raw)
        msg.extend(Counter(CtrDex.SealSourceCouples, count=1).qb64b)
        msg.extend(Seqner(sn=seal.s).qb64b)
        msg.extend(seal.d.encode("utf-8"))

        return msg

    def anchorMsg(self, serder, rseal):
        if self.estOnly:
            kevt = self.hab.rotate(data=[rseal])
        else:
            kevt = self.hab.interact(data=[rseal])

        seal = SealSource(s=self.hab.kever.sn, d=self.hab.kever.serder.dig)
        tevt = self.messagize(serder=serder, seal=seal)

        return tevt, kevt


class IssuerDoer(doing.Doer):
    """
    Basic Issuer Doer  to initialize inception events of the registry

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.

    Attributes:
        .issuer is Issuer subclass

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Hidden:
        ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
        ._tock is hidden attribute for .tock property
    """

    def __init__(self, issuer, **kwa):
        """
        Parameters:
           issuer (Issuer): instance
        """
        super(IssuerDoer, self).__init__(**kwa)
        self.issuer = issuer

    def enter(self):
        """"""
        if not self.issuer.inited:
            self.issuer.setup(**self.issuer._inits)

    def exit(self):
        """"""
        pass
