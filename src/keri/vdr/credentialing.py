# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.credentialing module

VC issuer support
"""
import json

from hio.base import doing
from hio.help import decking

from keri.vdr import viring
from .. import kering, help
from ..app import agenting
from ..core import parsing, coring
from ..core.coring import Counter, Seqner, CtrDex, MtrDex, Serder
from ..core.eventing import SealEvent, SealSource, TraitDex
from ..db.dbing import snKey, dgKey
from ..help import helping
from ..vc import proving
from ..vdr import eventing
from ..vdr.viring import Reger, nsKey

logger = help.ogler.getLogger()


class Regery:

    def __init__(self, hby, name="test", base="", reger=None, temp=False, cues=None):

        self.hby = hby
        self.name = name
        self.base = base
        self.temp = temp
        self.cues = cues if cues is not None else decking.Deck()

        self.reger = reger if reger is not None else Reger(name=self.name, base=base, db=self.hby.db, temp=temp)
        self.tvy = eventing.Tevery(reger=self.reger, db=self.hby.db, local=True)
        self.psr = parsing.Parser(framed=True, kvy=self.hby.kvy, tvy=self.tvy)

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

            reg = Registry(hab=hab, reger=self.reger, tvy=self.tvy, psr=self.psr, name=name, regk=regk, cues=self.cues)

            reg.inited = True
            self.regs[regk] = reg

    def makeRegistry(self, name, prefix, **kwa):
        hab = self.hby.habs[prefix]
        if hab is None:
            raise kering.ConfigurationError(f"Unknown prefix {prefix} for creating Registry {name}")

        reg = Registry(hab=hab, name=name, reger=self.reger, tvy=self.tvy, psr=self.psr, cues=self.cues)

        reg.make(**kwa)
        self.regs[reg.regk] = reg

        return reg

    def registryByName(self, name):
        if regrec := self.reger.regs.get(name):
            return self.regs[regrec.registryKey] if regrec.registryKey in self.regs else None
        return None

    def processEscrows(self):
        """ Process escrows for each registry """
        self.tvy.processEscrows()
        for registry in self.regs.values():
            registry.processEscrows()

    def close(self):
        if self.reger.inited:
            self.reger.close()


class Registry:
    """
    Issuer provides encapsulation of creating a Verifiable Credential Registry with issuance
    and revocation of VCs against that registry.

    The Registry consists of 1 management TEL for maintaining the state of the registry wrt special
    Backers that can act as witnesses of VC events, and 1 VC TEL for each VC issued that tracks the
    issuance and revocation status of those VCs.

    """

    def __init__(self, hab, reger, tvy, psr, name="test", regk=None, cues=None):
        """ Initialize Instance

        Parameters:
            hab (Habitat): instance of local controller's context
            name (str): alias for this issuer
            reger (Reger): database instance for controller's credentials

        """

        self.hab = hab
        self.name = name
        self.reger = reger
        self.tvy = tvy  # injected
        self.psr = psr  # injected

        self.cues = cues if cues is not None else decking.Deck()
        self.regk = regk

        self.inited = False

    def make(self, *, noBackers=True, baks=None, toad=None, estOnly=False):
        """ Delayed initialization of Issuer.

        Actual initialization of Issuer from properties or loaded from .reger.  Should
        only be called after .hab is initied.

        Parameters:
            noBackers (boolean): True to allow specification of TEL specific backers
            baks (list): initial list of backer prefixes qb64 for VCs in the Registry
            toad (str): hex of witness threshold
            estOnly (boolean): True for forcing rotation events for every TEL event.

        """
        baks = baks if baks is not None else []

        self.cnfg = [TraitDex.NoBackers] if noBackers else []
        if estOnly:
            self.cnfg.append(TraitDex.EstOnly)

        pre = self.hab.pre

        regser = eventing.incept(pre,
                                 baks=baks,
                                 toad=toad,
                                 cnfg=self.cnfg,
                                 code=MtrDex.Blake3_256)
        self.regk = regser.pre
        self.registries.add(self.regk)
        self.reger.regs.put(keys=self.name,
                            val=viring.RegistryRecord(registryKey=self.regk, prefix=pre))

        try:
            self.anchorMsg(regser, estOnly=estOnly)
        except kering.MissingAnchorError:
            logger.info("Credential registry missing anchor for inception = {}".format(regser.ked))

        self.inited = True

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

    def rotate(self, toad=None, cuts=None, adds=None):
        """ Rotate backer list for registry

        Parameters:
            toad (int): or str hex of backer threshold after cuts and adds
            cuts (list): of qb64 pre of backers to be removed from witness list
            adds (list): of qb64 pre of backers to be added to witness list

        Returns:
            boolean: True if rotation is successful

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

        self.anchorMsg(serder, estOnly=self.estOnly)

        return True

    def issue(self, creder, dt=None):
        """ Create and process an iss or bis message event

        Parameters:
            creder (Credentialer): instance of the credential to issue
            dt (str): iso8601 formatted date time string of issuance

        Returns:
            boolean: True if issuance is successful

        """
        vcdig = creder.said
        craw = self.hab.endorse(creder)

        if self.noBackers:
            serder = eventing.issue(vcdig=vcdig, regk=self.regk, dt=dt)
        else:
            serder = eventing.backerIssue(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.saider.qb64,
                                          dt=dt)

        self.anchorMsg(serder=serder, estOnly=self.estOnly)

        return True

    def revoke(self, creder, dt=None):
        """ Perform revocation of credential

        Create and process rev or brv message event

        Parameters:
            creder (Credentialer): instance of the credential to revoke
            dt (str): iso8601 formatted date time string of revocation

        Returns:
            boolean: True if revocation is successful.

        """
        vcdig = creder.said
        vckey = nsKey([self.regk, vcdig])
        vcser = self.reger.getTel(snKey(pre=vckey, sn=0))
        if vcser is None:
            raise kering.ValidationError("Invalid revoke of {} that has not been issued "
                                         "pre={}.".format(vcdig, self.regk))
        ievt = self.reger.getTvt(dgKey(pre=vckey, dig=vcser))
        iserder = Serder(raw=bytes(ievt))

        if self.noBackers:
            serder = eventing.revoke(vcdig=vcdig, regk=self.regk, dig=iserder.said, dt=dt)
        else:
            serder = eventing.backerRevoke(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.saider.qb64,
                                           dig=iserder.said, dt=dt)

        self.anchorMsg(serder, estOnly=self.estOnly)

        return True

    @staticmethod
    def attachSeal(serder, seal):
        """ Create serialization of event message with attached source seal.

        Parameters:
            serder (Serder): event message
            seal (SealSource): {s, d} source seal couple of sequence number and digest of sealed event

        Returns:
            bytearray:  serialization of event message with attached source seal

        """
        msg = bytearray(serder.raw)
        msg.extend(Counter(CtrDex.SealSourceCouples, count=1).qb64b)
        msg.extend(Seqner(sn=seal.s).qb64b)
        msg.extend(seal.d.encode("utf-8"))

        return msg

    def anchorMsg(self, serder, seal=None, estOnly=None):
        """  Create key event with seal to serder anchored as data.

        Performs a rotation or interaction event for single sig or multiple sig identifier
        to anchor the provide regsitry event.  Inserts outbound cues for external processing
        of resulting events or multisig handling.

        Parameters:
            serder (Serder): registry event message
            seal (Optional(SealSource)): option seal provided to n > 1 participants of multsig registry
            estOnly (bool): True means do not allow interaction events

        """

        rseal = SealEvent(serder.pre, serder.ked["s"], serder.said)
        rseal = rseal._asdict()
        estOnly = estOnly if estOnly is not None else False

        if self.hab.phab is None:
            if estOnly:
                kevt = self.hab.rotate(data=[rseal])
            else:
                kevt = self.hab.interact(data=[rseal])

            seal = SealSource(s=self.hab.kever.sn, d=self.hab.kever.serder.said)
            tevt = self.attachSeal(serder=serder, seal=seal)

            self.psr.parseOne(ims=bytearray(tevt))  # make copy as kvr deletes
            self.cues.extend([
                dict(
                    kin="kevt",
                    msg=kevt,
                    pre=self.hab.pre,
                    regk=self.regk
                ),
                dict(
                    kin="send",
                    msg=tevt,
                    pre=self.hab.pre,
                    regk=self.regk
                ),
            ])

        else:
            if seal is None:
                ixn = self.hab.interact(data=[rseal])
                gserder = coring.Serder(raw=ixn)
                self.cues.append(dict(kin="counselor", pre=self.hab.pre, regk=self.regk, sn=gserder.sn,
                                      said=gserder.said))

                self.escrow(serder)
                raise kering.MissingAnchorError("anchor not provided for multisig")
            else:
                tevt = self.attachSeal(serder=serder, seal=seal)
                self.psr.parseOne(ims=bytearray(tevt))  # make copy as kvr deletes

                self.cues.append(dict(
                    kin="send",
                    msg=tevt,
                    pre=self.hab.pre,
                    regk=self.regk
                ))

    def escrow(self, serder):
        """ Save Issuer event for future process when anchor becomes available

        Parameters:
           serder: (Serder) is event to escrow

        """
        self.reger.mase.add(self.regk, serder.raw)

    def processEscrows(self):
        """
        Process credential registry missing anchor escrow:

        """
        for (regk,), raw in self.reger.mase.getItemIter():
            serder = coring.Serder(raw=raw.encode("utf-8"))

            if "ri" in serder.ked:
                tev = self.tevers[serder.ked["ri"]]
                pre = tev.pre
            else:
                pre = serder.ked["ii"]

            sn = serder.sn
            dig = serder.said

            seal = None
            for evts in self.hab.db.clonePreIter(pre=pre):
                eserder = coring.Serder(raw=evts)
                if "a" in eserder.ked:
                    ancs = eserder.ked["a"]
                    if len(ancs) != 1:
                        continue

                    anc = ancs[0]
                    spre = anc["i"]
                    ssn = int(anc["s"])
                    sdig = anc["d"]

                    if spre == serder.ked["i"] and ssn == sn \
                            and dig == sdig:
                        seal = SealSource(s=eserder.sn, d=eserder.said)
                        break

            if not seal:
                continue

            try:
                self.anchorMsg(serder, seal=seal)
            except kering.MissingAnchorError as ex:
                logger.exception("Issuer unescrow failed event from escrow = {}", ex.args[0])
            except Exception as ex:
                logger.exception("Issuer unescrow failed event from escrow = {}", ex.args[0])
                self.reger.mase.rem(regk, raw)
            else:  # unescrow succeeded, remove from escrow
                # We don't remove all escrows at pre,sn because some might be
                # duplicitous so we process remaining escrows in spite of found
                # valid event escrow.
                self.reger.mase.rem(regk, raw)
                logger.info("Issuer unescrow succeeded in valid event: "
                            "event=\n%s\n", json.dumps(serder.ked, indent=1))


class RegistryInceptDoer(doing.DoDoer):
    """ DoDoer for creating a VDR registry.

    Accepts command messages on .msgs for creating credential registries.
    Creates Issuers for each new registry and handles requests from multi-sig identifiers.

    Notifies status on .cues

    Properties:
       .msgs (decking.Deck): inbound cue messages for handler
       .cues (decking.Deck): outbound cue messages from handler

    """

    def __init__(self, hby, rgy, counselor, msgs=None, cues=None):
        """ Initialize registry incept DoDoer.

        Parameters:
            hby (Habery): identifier environment
            rgy (Regery): Credential registry environment
            msgs (decking.Deck): inbound cue messages for handler
            cues (decking.Deck): outbound cue messages from handler
        """

        self.hby = hby
        self.rgy = rgy
        self.counselor = counselor
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)

        doers = [self.witDoer, doing.doify(self.inceptDo)]
        super(RegistryInceptDoer, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0):
        """ Doist capable of creating a credential registry.

        Processes inbound cues to create credential registries using Issuer objects.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list

        Returns:
            Doist: compatible generator method for creating a registry and sending its inception and anchoring
            events to witnesses or backers

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                name = msg["name"]
                pre = msg["pre"]
                conf = msg['c'] if 'c' in msg else {}  # default config if none specified

                registry = self.rgy.makeRegistry(name=name, prefix=pre, **conf)

                self.extend([doing.doify(self.escrowDo), doing.doify(self.issuerDo)])
                yield self.tock

                while registry.regk not in registry.tevers:
                    yield self.tock

                print(f"Registry {registry.regk} in tevers")
                yield self.tock

            yield self.tock

    def issuerDo(self, tymth, tock=0.0):
        """ Process cues from credential issue coroutine

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:
            Doist: doifiable compatible generator method
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.rgy.cues:
                cue = self.rgy.cues.popleft()
                cueKin = cue['kin']
                pre = cue["pre"]
                regk = cue["regk"]
                hab = self.hby.habs[pre]

                if cueKin == "send":
                    tevt = cue["msg"]
                    witSender = agenting.WitnessPublisher(hab=hab, msg=tevt)
                    self.extend([witSender])
                    while not witSender.done:
                        _ = yield self.tock
                    self.remove([witSender])
                    self.cues.append(dict(kin="finished", regk=regk, pre=pre))

                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    serder = eventing.Serder(raw=bytearray(kevt))
                    self.witDoer.msgs.append(dict(pre=serder.pre, sn=serder.sn))

                    while not self.witDoer.cues:
                        yield self.tock

                elif cueKin == "counselor":
                    if not hab.phab:  # not a group hab, this is an invalid cue
                        continue

                    sn = cue["sn"]
                    said = cue["said"]

                    prefixer = coring.Prefixer(qb64=pre)
                    seqner = coring.Seqner(sn=sn)
                    saider = coring.Saider(qb64=said)

                    self.counselor.start(aids=hab.aids, pid=hab.phab.pre, prefixer=prefixer, seqner=seqner,
                                         saider=saider)
                    while True:
                        if self.counselor.cues:
                            cue = self.counselor.cues.popleft()
                            if cue["pre"] == hab.pre:
                                break

                        yield self.tock

                    self.cues.append(dict(kin="finished", regk=regk, pre=pre))

                yield self.tock
            yield self.tock

    def escrowDo(self, tymth, tock=0.0):
        """ Escrow processing Doist generator

        Processes escrows for all newly created issuers.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value


        Returns:
            Doist: doifiable compatible generator method

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            self.rgy.processEscrows()
            yield


class RegistryDoer(doing.DoDoer):
    """
    Basic Registry Doer to perform credential issuance of the registry

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

    def __init__(self, hby, registry, verifier, msgs=None, cues=None, **kwa):
        """ Initialize DoDoer for issuing credentials.

        Parameters:
            hab (Habitat): identifier environment
            registry (Registry): instance to use to perform credential issuance
            verifier (Verifier): credential verifier tied to local credential store for persistence.
            msgs (decking.Deck): inbound cue messages for handler
            cues (decking.Deck): outbound cue messages from handler
            **kwa (dict): keyword args passed through to DoDoer
        """
        self.hby = hby
        self.registry = registry
        self.verifier = verifier
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [
            doing.doify(self.registryDo),
            doing.doify(self.cueDo),
            doing.doify(self.escrowDo),
            doing.doify(self.verifierDo),
        ]

        super(RegistryDoer, self).__init__(doers=doers, **kwa)

    def registryDo(self, tymth, tock=0.0):
        """ Generator method for issuing a credential from a registry


        Creating issuance events and anchoring them to key state.
        Propagates all events to witnesses or backers

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value


        Returns:
            Doist: doifiable Doist compatible generator

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                schema = msg["schema"]
                source = msg["source"]
                recipient = msg["recipient"]
                data = msg["data"]

                dt = data["dt"] if "dt" in data else helping.nowIso8601()

                d = dict(
                    d="",
                    i=recipient,
                    dt=dt,
                )

                d |= data

                creder = proving.credential(issuer=self.hby.pre,
                                            schema=schema,
                                            subject=d,
                                            source=source,
                                            status=self.registry.regk)

                try:
                    self.registry.issue(creder=creder, dt=dt)
                except kering.MissingAnchorError:
                    logger.info("Missing anchor from credential issuance due to multisig identifier")

                craw = self.hby.endorse(creder)
                parsing.Parser().parse(ims=craw, vry=self.verifier)

                yield self.tock

            yield self.tock

    def cueDo(self, tymth, tock=0.0):
        """ Process cues from credential issue coroutine

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): initial tock value
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.registry.cues:
                cue = self.registry.cues.popleft()

                cueKin = cue['kin']
                if cueKin == "send":
                    tevt = cue["msg"]
                    witSender = agenting.WitnessPublisher(hab=self.hby, msg=tevt)
                    self.extend([witSender])

                    while not witSender.done:
                        _ = yield self.tock

                    self.remove([witSender])
                    self.cues.append(dict(kin="finished", regk=self.registry.regk))
                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    serder = eventing.Serder(raw=bytearray(kevt))
                    witDoer = agenting.WitnessReceiptor(hby=self.hby)
                    witDoer.msgs.append(dict(pre=serder.pre, sn=serder.sn))
                    self.extend([witDoer])

                    while not witDoer.done:
                        yield self.tock

                    self.remove([witDoer])
                    self.cues.append(dict(kin="witnessed", regk=self.registry.regk))

                yield self.tock

            yield self.tock

    def escrowDo(self, tymth, tock=0.0):
        """ Processes .issuer and .verifier escrows.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list

        Returns:
            Doist: doifiable Doist compatible generator method

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            self.registry.processEscrows()
            self.verifier.processEscrows()
            yield

    def verifierDo(self, tymth, tock=0.0):
        """ Processes the Verifier cues.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list

        Returns:
            Doist: doifiable Doist compatible generator method

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.verifier.cues:
                cue = self.verifier.cues.popleft()
                if cue["kin"] == "saved":
                    self.cues.append(cue)
                yield self.tock
            yield
