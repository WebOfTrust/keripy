# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.credentialing module

VC issuer support
"""
from typing import Optional

from hio.base import doing
from hio.help import decking

from keri.vdr import viring
from ..kering import Vrsn_1_0, Vrsn_2_0
from .. import help
from .. import kering, core
from ..app import agenting
from ..app.habbing import GroupHab
from ..core import parsing, coring, scheming, serdering
from ..core.coring import Seqner, MtrDex
from ..core.eventing import TraitDex
from ..db import dbing
from ..db.dbing import snKey, dgKey
from ..vc import proving
from ..vdr import eventing
from ..vdr.viring import Reger

logger = help.ogler.getLogger()


class Regery:
    """
    ACDC Registry and Tevery manager handling registry construction and loading and TEL event
    escrow processing.
    """

    def __init__(self, hby, name="test", base="", reger=None, temp=False, cues=None):
        """
        Initialize Regery instance and construct a list of registries found in the Reger database.

        Parameters:
            hby (Habery): instance of local controller's context
            name (str): name for the local Habery, used in Reger database name
            base (str): optional base path for Reger database
            reger (Reger): optional Reger database instance, if None then a new Reger is created
            temp (bool): True means regery is temporary and not persistent
            cues (Decking): optional Decking instance for event processing cues
        """

        self.hby = hby
        self.name = name
        self.base = base
        self.temp = temp
        self.cues = cues if cues is not None else decking.Deck()

        self.reger = reger if reger is not None else Reger(name=self.name, base=base, db=self.hby.db, temp=temp,
                                                           reopen=True)
        self.tvy = eventing.Tevery(reger=self.reger, db=self.hby.db, local=True, lax=True)
        self.psr = parsing.Parser(framed=True, kvy=self.hby.kvy, tvy=self.tvy, version=Vrsn_1_0)

        self.regs = {}  # List of local registries
        self.inited = False

        if self.reger.opened:
            self.setup()

    def setup(self):
        if not self.reger.opened:
            raise kering.ClosedError("Attempt to setup Regery with closed "
                                     "reger.")
        self.loadRegistries()
        self.inited = True

    def loadRegistries(self):
        """ Load Registry objects for each entry in the .regs database

        """

        for name, regord in self.reger.regs.getItemIter():
            name, = name
            regk = regord.registryKey
            pre = regord.prefix

            hab = self.hby.habs[pre]
            if hab is None:
                raise kering.ConfigurationError(f"Unknown prefix {pre} for creating Registry {name}")

            reg = Registry(hab=hab, reger=self.reger, tvy=self.tvy, psr=self.psr,
                           name=name, regk=regk, cues=self.cues)

            reg.inited = True
            self.regs[regk] = reg
            self.reger.registries.add(regk)

    def makeRegistry(self, name, prefix, **kwa):
        hab = self.hby.habs[prefix]
        if hab is None:
            raise kering.ConfigurationError(f"Unknown prefix {prefix} for creating Registry {name}")

        reg = Registry(hab=hab, name=name, reger=self.reger, tvy=self.tvy, psr=self.psr, cues=self.cues)

        reg.make(**kwa)
        self.regs[reg.regk] = reg

        return reg

    def makeSignifyRegistry(self, name, prefix, regser):
        hab = self.hby.habs[prefix]
        if hab is None:
            raise kering.ConfigurationError(f"Unknown prefix {prefix} for creating Registry {name}")

        reg = SignifyRegistry(hab=hab, name=name, reger=self.reger, tvy=self.tvy, psr=self.psr, cues=self.cues)

        reg.make(regser=regser)

        self.regs[reg.regk] = reg

        return reg

    def registryByName(self, name):
        if regrec := self.reger.regs.get(name):
            return self.regs[regrec.registryKey] if regrec.registryKey in self.regs else None
        return None

    @property
    def tevers(self):
        """ tevers property

        Returns .reger.tevers

        """
        return self.reger.tevers

    def processEscrows(self):
        """ Process escrows for each registry """
        self.tvy.processEscrows()

    def close(self):
        if self.reger.opened:
            self.reger.close()


class RegeryDoer(doing.Doer):
    """ """

    def __init__(self, rgy):
        self.rgy = rgy
        super(RegeryDoer, self).__init__()

    def do(self, tymth, tock=0.0, **opts):
        """

        Parameters:
            tymth: is injected function wrapper closure returned by .tymen() of
                  Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock: is injected initial tock value
            **opts (dict): additional keyword arguments

        Returns:

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.rgy.processEscrows()
            yield self.tock


class BaseRegistry:
    """
    Issuer provides encapsulation of creating a Verifiable Credential Registry with issuance
    and revocation of VCs against that registry.

    The Registry consists of 1 management TEL for maintaining the state of the registry wrt special
    Backers that can act as witnesses of VC events, and 1 VC TEL for each VC issued that tracks the
    issuance and revocation status of those VCs.

    """

    def __init__(self, hab, reger, tvy, psr, name="test", regk=None, cues=None):
        """Initialize BaseRegistry Instance

        Parameters:
            hab (Habitat): instance of local controller's context
            name (str): alias for this issuer
            reger (Reger): database instance for controller's credentials
            tvy (Tevery): injected Tevery instance for processing TEL events
            psr (Parser): injected Parser instance for parsing TEL events
            regk (str): registry key qb64 prefix for this registry read from Registry record
            cues (Decking): optional Decking instance for outbound event processing cues
        """

        self.hab = hab
        self.name = name
        self.reger = reger
        self.tvy = tvy  # injected
        self.psr = psr  # injected

        self.cues = cues if cues is not None else decking.Deck()
        self.regk = regk
        self.regd = None
        self.vcp = None
        self.cnfg = []

        self.inited = False

    @property
    def tevers(self):
        """ tevers property

        Returns .reger.tevers

        """
        return self.reger.tevers

    @property
    def tever(self):
        return self.reger.tevers[self.regk]

    @property
    def estOnly(self):
        return self.tever.estOnly

    @property
    def noBackers(self):
        return self.tever.noBackers

    @property
    def baks(self):
        return self.tever.baks

    @property
    def regi(self):
        return int(self.tever.serder.ked["s"], 16)

    @property
    def regser(self):
        return self.tever.serder

    @property
    def registries(self):
        return self.reger.registries

    def processEvent(self, serder):
        """ Process registry events

        Parameters:
            serder (Serder): Registry TEL event to process

        """

        try:
            self.tvy.processEvent(serder=serder)
        except kering.MissingAnchorError:
            logger.info("Credential registry missing anchor for inception = %s", serder.said)
            logger.debug("Event=\n%s\n", serder.pretty())

    def anchorMsg(self, pre, regd, seqner, saider):
        """Adds to the anchor database a seal of a TEL event to a KEL event.

        Parameters:
            pre (str): TEL event SAID whether registry or credential event; "i" prop
            regd (str): TEL event SAID whether registry or credential event; "d" prop
            seqner (Seqner): sequence number from KEL of anchoring key event
            saider (Saider): SAID of the anchoring KEL event
        """
        key = dgKey(pre, regd)
        sealet = seqner.qb64b + saider.qb64b
        self.reger.putAnc(key, sealet)


class Registry(BaseRegistry):
    """
    TEL Registry subclass supporting registry delayed instantiation and rotation and credential
    issuance and revocation.
    """

    def make(self, *, nonce=None, noBackers=True, baks=None, toad=None, estOnly=False, vcp=None):
        """ Delayed initialization of Issuer.

        Actual initialization of Issuer from properties or loaded from .reger.  Should
        only be called after .hab is inited.

        Parameters:
            nonce (str) qb64 random seed for credential registries
            noBackers (boolean): True to allow specification of TEL specific backers
            baks (list[str]): initial list of backer prefixes qb64 for VCs in the Registry
            toad (str): hex of witness threshold
            estOnly (boolean): True for forcing rotation events for every TEL event.
            vcp (SerderKERI): optional vcp event serder if configured outside the Registry
        """
        pre = self.hab.pre

        if vcp is None:
            baks = baks if baks is not None else []

            self.cnfg = [TraitDex.NoBackers] if noBackers else []
            if estOnly:
                self.cnfg.append(TraitDex.EstOnly)

            self.vcp = eventing.incept(pre,
                                       baks=baks,
                                       toad=toad,
                                       nonce=nonce,
                                       cnfg=self.cnfg,
                                       code=MtrDex.Blake3_256)
        else:
            self.vcp = vcp

        self.regk = self.vcp.pre
        self.regd = self.vcp.said
        self.registries.add(self.regk)
        self.reger.regs.put(keys=self.name,
                            val=viring.RegistryRecord(registryKey=self.regk, prefix=pre))

        self.processEvent(serder=self.vcp)
        self.inited = True

    def rotate(self, toad=None, cuts=None, adds=None):
        """ Rotate backer list for registry

        Parameters:
            toad (int): or str hex of backer threshold after cuts and adds
            cuts (list[str]): of qb64 pre of backers to be removed from witness list
            adds (list[str]): of qb64 pre of backers to be added to witness list

        Returns:
            SerderKERI: The SerderKERI of the registry rotation event
        """
        if self.noBackers:
            raise ValueError("Attempt to rotate registry {} that does not support backers".format(self.regk))

        serder = eventing.rotate(dig=self.regser.said,
                                 regk=self.regk,
                                 sn=self.regi + 1,
                                 toad=toad,
                                 baks=self.baks,
                                 adds=adds,
                                 cuts=cuts)

        self.processEvent(serder=serder)
        return serder

    def issue(self, said, dt=None):
        """ Create and process an iss or bis message event

        Parameters:
            said (str): qb64 SAID of credential to issue
            dt (str): iso8601 formatted date time string of issuance

        Returns:
            SerderKERI: The SerderKERI of the credential issuance event
        """
        if self.noBackers:
            serder = eventing.issue(vcdig=said, regk=self.regk, dt=dt)
        else:
            serder = eventing.backerIssue(vcdig=said,
                                          regk=self.regk,
                                          regsn=self.regi,
                                          regd=self.regser.said,
                                          dt=dt)

        self.processEvent(serder=serder)
        return serder

    def revoke(self, said, dt=None):
        """ Perform revocation of credential

        Create and process rev or brv message event

        Parameters:
            said (str): qb64 SAID of the credential to revoke
            dt (str): iso8601 formatted date time string of revocation

        Returns:
            SerderKERI: The SerderKERI of the credential revocation event
        """
        vci = said
        vcser = self.reger.getTel(snKey(pre=vci, sn=0))
        if vcser is None:
            raise kering.ValidationError("Invalid revoke of {} that has not been issued "
                                         "pre={}.".format(vci, self.regk))
        ievt = self.reger.getTvt(dgKey(pre=vci, dig=vcser))
        iserder = serdering.SerderKERI(raw=bytes(ievt)) #Serder(raw=bytes(ievt))

        if self.noBackers:
            serder = eventing.revoke(vcdig=vci, regk=self.regk, dig=iserder.said, dt=dt)
        else:
            serder = eventing.backerRevoke(vcdig=vci,
                                           regk=self.regk,
                                           regsn=self.regi,
                                           regd=self.regser.said,
                                           dig=iserder.said, dt=dt)

        self.processEvent(serder=serder)
        return serder


class SignifyRegistry(BaseRegistry):
    """
    Subclass supporting registry construction and rotation and credential issuance and revocation
    for Signify controllers.
    """

    def make(self, *, regser):
        """ Delayed initialization of Issuer.

        Actual initialization of Issuer from properties or loaded from .reger.  Should
        only be called after .hab is initied.

        Parameters:
            regser (SerderKERI): Regsitry inception event
        """
        pre = self.hab.pre
        self.regk = regser.pre
        self.regd = regser.said
        self.registries.add(self.regk)
        self.reger.regs.put(keys=self.name,
                            val=viring.RegistryRecord(registryKey=self.regk, prefix=pre))

        try:
            self.processEvent(serder=regser)
        except kering.LikelyDuplicitousError:
            pass

        self.inited = True

    def rotate(self, serder):
        """ Rotate backer list for registry

        Parameters:
            serder (SerderKERI): Regsitry inception event

        Returns:
            SerderKERI: The SerderKERI of the registry rotation event
        """
        if self.noBackers:
            raise ValueError("Attempt to rotate registry {} that does not support backers".format(self.regk))

        if serder.ked['s'] != self.regi + 1:
            raise ValueError(f"Invalid sequence number {serder.ked['s']}")

        self.processEvent(serder=serder)
        return serder

    def issue(self, said, dt=None):
        """ Create and process an iss or bis message event

        Parameters:
            said (str): qb64 SAID of credential to issue
            dt (str): iso8601 formatted date time string of issuance

        Returns:
            SerderKERI: The SerderKERI of the credential issuance event
        """
        if self.noBackers:
            serder = eventing.issue(vcdig=said, regk=self.regk, dt=dt)
        else:
            serder = eventing.backerIssue(vcdig=said, regk=self.regk, regsn=self.regi, regd=self.regser.said,
                                          dt=dt)

        self.processEvent(serder=serder)
        return serder

    def revoke(self, said, dt=None):
        """Create and process credential revocation event

        Create and process rev or brv message event

        Parameters:
            said (str): qb64 SAID of the credential to revoke
            dt (str): iso8601 formatted date time string of revocation

        Returns:
            SerderKERI: The SerderKERI of the credential revocation event
        """
        vci = said
        vcser = self.reger.getTel(snKey(pre=vci, sn=0))
        if vcser is None:
            raise kering.ValidationError("Invalid revoke of {} that has not been issued "
                                         "pre={}.".format(vci, self.regk))
        ievt = self.reger.getTvt(dgKey(pre=vci, dig=vcser))
        iserder = serdering.SerderACDC(raw=bytes(ievt))  # Serder(raw=bytes(ievt))

        if self.noBackers:
            serder = eventing.revoke(vcdig=vci, regk=self.regk, dig=iserder.said, dt=dt)
        else:
            serder = eventing.backerRevoke(vcdig=vci, regk=self.regk, regsn=self.regi, regd=self.regser.said,
                                           dig=iserder.said, dt=dt)

        self.processEvent(serder=serder)
        return serder


class Registrar(doing.DoDoer):
    """
    Registrar is a DoDoer that manages registry inception, issuance and revocation of credentials,
    escrow handling for witnessing TEL events, multisig TEL event processing, and TEL event
    dissemination to witnesses as a fire and forget mechanism. Also supports determining
    if a registry event is complete.

    Doers:
        witDoer (WitnessReceiptor): Doer for receiving witness receipts
        witPub (WitnessPublisher): Doer for publishing witness events
        escrowDo (doified function): Doer for processing TEL event escrows
    """

    def __init__(self, hby, rgy, counselor):
        """
        Initialize Registrar instance.

        Parameters:
            hby (Habery): instance of local controller's context
            rgy (Regery): instance of Regery for managing registries and TEL Tevery escrows
            counselor (Counselor): instance of Counselor for multisig group processing of TEL events
        """
        self.hby = hby
        self.rgy = rgy
        self.counselor = counselor
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.witPub = agenting.WitnessPublisher(hby=self.hby)

        doers = [self.witDoer, self.witPub, doing.doify(self.escrowDo)]

        super(Registrar, self).__init__(doers=doers)

    def incept(self, iserder, anc):
        """
        Create a registry with a registry inception event. Supports both single sig and multisig groups.

        Parameters:
            iserder (SerderKERI): Serder object of TEL iss event
            anc (SerderKERI): Serder object of anchoring event
        """
        registry = self.rgy.regs[iserder.pre]
        hab = registry.hab
        rseq = coring.Seqner(sn=0)

        if not isinstance(hab, GroupHab):  # not a multisig group
            seqner = coring.Seqner(sn=hab.kever.sner.num)
            saider = coring.Saider(qb64=hab.kever.serder.said)
            registry.anchorMsg(pre=iserder.pre,
                               regd=iserder.said,
                               seqner=seqner,
                               saider=saider)

            print("Waiting for TEL event witness receipts")
            self.witDoer.msgs.append(dict(pre=anc.pre, sn=seqner.sn))

            self.rgy.reger.tpwe.add(keys=(registry.regk, rseq.qb64), val=(hab.kever.prefixer, seqner, saider))

        else:
            sn = anc.sn
            said = anc.said

            prefixer = coring.Prefixer(qb64=hab.pre)
            seqner = coring.Seqner(sn=sn)
            saider = coring.Saider(qb64=said)

            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=hab)

            print("Waiting for TEL registry vcp event multisig anchoring event")
            self.rgy.reger.tmse.add(keys=(registry.regk, rseq.qb64, registry.regd), val=(prefixer, seqner, saider))

    def issue(self, creder, iserder, anc):
        """
        Create and process the credential issuance TEL events on the given registry

        Parameters:
            creder (SerderACDC): credential to issue
            iserder (SerderKERI): Serder object of TEL iss event
            anc (SerderKERI): Serder object of anchoring event

        """
        regk = creder.regid
        registry = self.rgy.regs[regk]
        hab = registry.hab

        vcid = iserder.ked["i"]
        rseq = coring.Seqner(snh=iserder.ked["s"])

        if not isinstance(hab, GroupHab):  # not a multisig group
            seqner = coring.Seqner(sn=hab.kever.sner.num)
            saider = coring.Saider(qb64=hab.kever.serder.said)
            registry.anchorMsg(pre=vcid, regd=iserder.said, seqner=seqner, saider=saider)

            print("Waiting for TEL event witness receipts")
            self.witDoer.msgs.append(dict(pre=hab.pre, sn=seqner.sn))

            self.rgy.reger.tpwe.add(keys=(vcid, rseq.qb64), val=(hab.kever.prefixer, seqner, saider))

        else:  # multisig group hab
            sn = anc.sn
            said = anc.said

            prefixer = coring.Prefixer(qb64=hab.pre)
            seqner = coring.Seqner(sn=sn)
            saider = coring.Saider(qb64=said)

            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=hab)

            print(f"Waiting for TEL iss event multisig anchoring event {seqner.sn}")
            self.rgy.reger.tmse.add(keys=(vcid, rseq.qb64, iserder.said), val=(prefixer, seqner, saider))

    def revoke(self, creder, rserder, anc):
        """
        Create and process the credential revocation TEL events on the given registry

        Parameters:
            creder (Creder): credential to issue
            rserder (Serder): Serder object of TEL rev event
            anc (Serder): Serder object of anchoring event

        Returns:
            (str, str): (vcid, rseq.sn) of the registry identifier and TEL event sequence number
        """

        regk = creder.regid
        registry = self.rgy.regs[regk]
        hab = registry.hab

        vcid = rserder.ked["i"]
        rseq = coring.Seqner(snh=rserder.ked["s"])

        if not isinstance(hab, GroupHab):  # not a multisig group
            seqner = coring.Seqner(sn=hab.kever.sner.num)
            saider = coring.Saider(qb64=hab.kever.serder.said)
            registry.anchorMsg(pre=vcid, regd=rserder.said, seqner=seqner, saider=saider)

            print("Waiting for TEL event witness receipts")
            self.witDoer.msgs.append(dict(pre=hab.pre, sn=seqner.sn))

            self.rgy.reger.tpwe.add(keys=(vcid, rseq.qb64), val=(hab.kever.prefixer, seqner, saider))
            return vcid, rseq.sn
        else:
            sn = anc.sn
            said = anc.said

            prefixer = coring.Prefixer(qb64=hab.pre)
            seqner = coring.Seqner(sn=sn)
            saider = coring.Saider(qb64=said)

            self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=hab)

            print(f"Waiting for TEL rev event multisig anchoring event {seqner.sn}")
            self.rgy.reger.tmse.add(keys=(vcid, rseq.qb64, rserder.said), val=(prefixer, seqner, saider))
            return vcid, rseq.sn

    @staticmethod
    def multisigIxn(hab, rseal):
        """
        Create and process an interaction event containing the given registry seal as its data.

        Parameters:
            hab (Habitat): instance of local controller's context
            rseal (dict): TEL event seal to include in the interaction event.

        Returns:
            (bytearray, Prefixer, Seqner, Saider): tuple of ixn event, Hab pre, and seq. no. and SAID of the ixn event.
        """
        ixn = hab.interact(data=[rseal])
        serder = serdering.SerderKERI(raw=bytes(ixn))

        sn = serder.sn
        said = serder.said

        prefixer = coring.Prefixer(qb64=hab.pre)
        seqner = coring.Seqner(sn=sn)
        saider = coring.Saider(qb64=said)

        return ixn, prefixer, seqner, saider

    def complete(self, pre, sn=0):
        """
        Determine if registry event (inception, issuance, revocation, etc.) is finished validation.
        A TEL event is complete when its underlying KEL event has been signed by all participants.

        Parameters:
            pre (str): qb64 identifier of registry event
            sn (int): integer sequence number of regsitry event

        Returns:
            bool: True means event has completed and is commited to database
        """

        seqner = coring.Seqner(sn=sn)
        said = self.rgy.reger.ctel.get(keys=(pre, seqner.qb64))
        return said is not None and self.witPub.sent(said=pre)

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """Process escrows of TEL events and their underlying KEL events waiting to be fully signed
         and witnessed.

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchor
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        """
        Process TEL event escrows for multisig TEL events and their underlying KEL events.
        """
        self.processWitnessEscrow()
        self.processMultisigEscrow()
        self.processDisseminationEscrow()

    def processWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full complement of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.
        """
        for (regk, snq), (prefixer, seqner, saider) in self.rgy.reger.tpwe.getItemIter():  # partial witness escrow
            kever = self.hby.kevers[prefixer.qb64]
            dgkey = dbing.dgKey(prefixer.qb64b, saider.qb64)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            if kever.wits:
                if len(wigs) == len(kever.wits):  # We have all of them, this event is finished
                    hab = self.hby.habs[prefixer.qb64]
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == hab.pre and cue["sn"] == seqner.sn:
                            witnessed = True

                    if not witnessed:
                        continue
                else:
                    continue

            rseq = coring.Seqner(qb64=snq)
            self.rgy.reger.tpwe.rem(keys=(regk, snq))

            self.rgy.reger.tede.add(keys=(regk, rseq.qb64), val=(prefixer, seqner, saider))

    def processMultisigEscrow(self):
        """
        Process escrow of group multisig events that do not have a full complement of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.
        """
        for (regk, snq, regd), (prefixer, seqner, saider) in self.rgy.reger.tmse.getItemIter():  # multisig escrow
            try:
                if not self.counselor.complete(prefixer, seqner, saider):
                    continue
            except kering.ValidationError:
                self.rgy.reger.tmse.rem(keys=(regk, snq, regd))
                continue

            rseq = coring.Seqner(qb64=snq)

            # Anchor the message, registry or otherwise
            key = dgKey(regk, regd)
            sealet = seqner.qb64b + saider.qb64b
            self.rgy.reger.putAnc(key, sealet)

            self.rgy.reger.tmse.rem(keys=(regk, snq, regd))
            self.rgy.reger.tede.add(keys=(regk, rseq.qb64), val=(prefixer, seqner, saider))

    def processDisseminationEscrow(self):
        """
        Process escrow of group multisig events that have been completed and are ready to be
        disseminated to witnesses.  This is a fire and forget mechanism where the WitnessPublisher
        handles sending events to the witnesses and collecting receipts.
        """
        for (regk, snq), (prefixer, seqner, saider) in self.rgy.reger.tede.getItemIter():  # group multisig escrow
            rseq = coring.Seqner(qb64=snq)
            dig = self.rgy.reger.getTel(key=snKey(pre=regk, sn=rseq.sn))
            if dig is None:
                continue

            self.rgy.reger.tede.rem(keys=(regk, snq))

            tevt = bytearray()
            for msg in self.rgy.reger.clonePreIter(pre=regk, fn=rseq.sn):
                tevt.extend(msg)

            print(f"Sending TEL events to witnesses")
            # Fire and forget the TEL event to the witnesses.  Consumers will have to query
            # to determine when the Witnesses have received the TEL events.
            self.witPub.msgs.append(dict(pre=prefixer.qb64, said=regk, msg=tevt))
            self.rgy.reger.ctel.put(keys=(regk, rseq.qb64), val=saider)  # idempotent


class Credentialer(doing.DoDoer):
    """
    Credentialer is a DoDoer that manages credential creation, validation, issuance, and escrow
    for credential events. This includes ensuring KEL events underlying TEL events have all needed
    signatures and then disseminating the credential events to witnesses for receipting.

    Doers:
        escrowDo (doified function): Doer for processing credential escrows waiting for signatures
    """

    def __init__(self, hby, rgy, registrar, verifier):
        """
        Initialize Credentialer instance.

        Parameters:
            hby (Habery): instance of local controller's context
            rgy (Regery): instance of Regery for managing registries and TEL Tevery escrows
            registrar (Registrar): Registrar used for checking TEL event completion (has all signatures)
            verifier (Verifier): instance of Verifier for validating credentials against schemas
        """
        self.hby = hby
        self.rgy = rgy
        self.registrar = registrar
        self.verifier = verifier
        doers = [doing.doify(self.escrowDo)]

        super(Credentialer, self).__init__(doers=doers)

    def create(self, regname, recp: str, schema, source, rules, data, private: bool = False,
               private_credential_nonce: Optional[str] = None, private_subject_nonce: Optional[str] = None):
        """  Create and validate a credential returning the fully populated Creder

        Parameters:
            regname:
            recp (str):
            schema:
            source:
            rules:
            data:
            private (bool): apply nonce used for privacy preserving ACDC
            private_credential_nonce (Optional[str]): nonce used for privacy vc
            private_subject_nonce (Optional[str]): nonce used for subject

        Returns:
            Creder: Creder class for the issued credential

        """
        if recp is not None and recp not in self.hby.kevers:
            raise kering.ConfigurationError("Unable to issue credential to {}.  A connection to that identifier must "
                                            "already be established".format(recp))

        registry = self.rgy.registryByName(regname)
        if registry is None:
            raise kering.ConfigurationError("Credential registry {} does not exist.  It must be created before issuing "
                                            "credentials".format(regname))

        creder = proving.credential(issuer=registry.hab.pre,
                                    schema=schema,
                                    recipient=recp,
                                    data=data,
                                    source=source,
                                    private=private,
                                    private_credential_nonce=private_credential_nonce,
                                    private_subject_nonce=private_subject_nonce,
                                    rules=rules,
                                    status=registry.regk)
        self.validate(creder)
        return creder

    def validate(self, creder):
        """
        Validates a credential against its locally resolved schema.

        Args:
            creder (Creder): creder object representing the credential to validate

        Returns:
            bool: true if credential is valid against a known schema

        """
        schema = creder.sad['s']
        scraw = self.verifier.resolver.resolve(schema)
        if not scraw:
            raise kering.ConfigurationError("Credential schema {} not found.  It must be loaded with data oobi before "
                                            "issuing credentials".format(schema))

        schemer = scheming.Schemer(raw=scraw)
        try:
            schemer.verify(creder.raw)
        except kering.ValidationError as ex:
            raise kering.ConfigurationError(f"Credential schema validation failed for {schema}: {ex}")

        return True

    def issue(self, creder, serder):
        """ Issue the credential creder and handle witness propagation and communication

        Args:
            creder (Creder): Credential object to issue
            serder (Serder): KEL or TEL anchoring event
                need to contribute digest of next rotating key
        """
        # escrow waiting for other signatures
        prefixer = coring.Prefixer(qb64=serder.pre)
        seqner = coring.Seqner(sn=serder.sn)

        self.rgy.reger.cmse.put(keys=(creder.said, seqner.qb64), val=creder)

        try:
            self.verifier.processCredential(creder=creder, prefixer=prefixer, seqner=seqner,
                                            saider=coring.Saider(qb64=serder.said))
        except kering.MissingRegistryError:
            pass

    def processCredentialMissingSigEscrow(self):
        """
        Process credential events that are missing signatures. If the TEL event's underlying KEL
        event signing is complete then disseminate the event to the witnesses for receipting.
        """
        for (said, snq), creder in self.rgy.reger.cmse.getItemIter():
            rseq = coring.Seqner(qb64=snq)
            if not self.registrar.complete(pre=said, sn=rseq.sn):
                continue

            saider = self.rgy.reger.saved.get(keys=said)
            if saider is None:
                continue

            # Remove from this escrow
            self.rgy.reger.cmse.rem(keys=(said, snq))

            # place in escrow to disseminate to other if witnesser and if there is an issuee
            self.rgy.reger.ccrd.put(keys=(said,), val=creder)

    def complete(self, said):
        """
        A credential event is complete when issued and sent to witnesses for receipting.
        """
        return self.rgy.reger.ccrd.get(keys=(said,)) is not None

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """ Process escrows of credentials waiting to be completed.

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchor
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        """
        Process credential missing signature escrow.
        """
        self.processCredentialMissingSigEscrow()


def sendCredential(hby, hab, reger, postman, creder, recp):
    """ Stream credential artifacts to recipient using postman

    Parameters:
        hby (Habery): instance of local controller's context
        hab (Habitat): the local controller sending the credential artifacts
        reger (Reger): the credential database to pull the artifacts from
        postman (StreamPoster): poster to stream credential artifacts with
        creder (Creder): the credential to pull artifacts for and send
        recp (str): qb64 prefix of the recipient to send the artifacts to
    """
    if isinstance(hab, GroupHab):
        sender = hab.mhab.pre
    else:
        sender = hab.pre

    sendArtifacts(hby, reger, postman, creder, recp)

    sources = reger.sources(hby.db, creder)
    for source, atc in sources:
        sendArtifacts(hby, reger, postman, source, recp)
        postman.send(serder=source, attachment=atc)

    serder, prefixer, seqner, saider = reger.cloneCred(creder.said)
    atc = bytearray(core.Counter(core.Codens.SealSourceTriples,
                                 count=1, version=kering.Vrsn_1_0).qb64b)
    atc.extend(prefixer.qb64b)
    atc.extend(seqner.qb64b)
    atc.extend(saider.qb64b)
    postman.send(serder=creder, attachment=atc)


def sendArtifacts(hby, reger, postman, creder, recp):
    """ Stream credential artifacts to recipient using postman

    Parameters:
        hby (Habery): instance of local controller's context
        reger (Reger): the credential database to pull the artifacts from
        postman (StreamPoster): poster to stream credential artifacts with
        creder (Creder): the credential to pull artifacts for and send
        recp (str): qb64 prefix of the recipient to send the artifacts to
    """
    issr = creder.issuer
    isse = creder.attrib["i"] if "i" in creder.attrib else None
    regk = creder.regid

    ikever = hby.db.kevers[issr]
    for msg in hby.db.cloneDelegation(ikever):
        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        postman.send(serder=serder, attachment=atc)

    for msg in hby.db.clonePreIter(pre=issr):
        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        postman.send(serder=serder, attachment=atc)

    if isse is not None and isse != recp:
        ikever = hby.db.kevers[isse]
        for msg in hby.db.cloneDelegation(ikever):
            serder = serdering.SerderKERI(raw=msg)
            atc = msg[serder.size:]
            postman.send(serder=serder, attachment=atc)

        for msg in hby.db.clonePreIter(pre=isse):
            serder = serdering.SerderKERI(raw=msg)
            atc = msg[serder.size:]
            postman.send(serder=serder, attachment=atc)

    if regk is not None:
        for msg in reger.clonePreIter(pre=regk):
            serder = serdering.SerderKERI(raw=msg)
            atc = msg[serder.size:]
            postman.send(serder=serder, attachment=atc)

    for msg in reger.clonePreIter(pre=creder.said):
        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        postman.send(serder=serder, attachment=atc)


def sendRegistry(hby, reger, postman, creder, sender, recp):
    """Stream registry artifacts to recipient using postman

    Parameters:
        hby (Habery): instance of local controller's context
        reger (Reger): the registry database to pull the artifacts from
        postman (StreamPoster): poster to stream registry artifacts with
        creder (Creder): the registry to pull artifacts for and send
        sender (str): qb64 prefix of the sender of the registry artifacts
        recp (str): qb64 prefix of the recipient to send the artifacts to
    """
    issr = creder.issuer
    regk = creder.regid

    if regk is None:
        return

    ikever = hby.db.kevers[issr]
    for msg in hby.db.cloneDelegation(ikever):
        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        postman.send(serder=serder, attachment=atc)

    for msg in hby.db.clonePreIter(pre=issr):
        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        postman.send(serder=serder, attachment=atc)

    for msg in reger.clonePreIter(pre=regk):
        serder = serdering.SerderKERI(raw=msg)
        atc = msg[serder.size:]
        postman.send(serder=serder, attachment=atc)
