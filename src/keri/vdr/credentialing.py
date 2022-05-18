# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.credentialing module

VC issuer support
"""
from hio.base import doing
from hio.help import decking

from keri.vdr import viring
from .. import kering, help
from ..app import agenting, signing, forwarding
from ..core import parsing, coring, scheming
from ..core.coring import Seqner, MtrDex, Serder
from ..core.eventing import SealEvent, TraitDex
from ..db import dbing
from ..db.dbing import snKey, dgKey
from ..help import helping
from ..vc import proving, protocoling
from ..vdr import eventing
from ..vdr.viring import Reger

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
            self.reger.registries.add(regk)

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
        if self.reger.inited:
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
        self.regd = None
        self.cnfg = []

        self.inited = False

    def make(self, *, nonce=None, noBackers=True, baks=None, toad=None, estOnly=False):
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
                                 nonce=nonce,
                                 cnfg=self.cnfg,
                                 code=MtrDex.Blake3_256)
        self.regk = regser.pre
        self.regd = regser.said
        self.registries.add(self.regk)
        self.reger.regs.put(keys=self.name,
                            val=viring.RegistryRecord(registryKey=self.regk, prefix=pre))

        try:
            self.tvy.processEvent(serder=regser)
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

        try:
            self.tvy.processEvent(serder=serder)
        except kering.MissingAnchorError:
            logger.info("Credential registry missing anchor for inception = {}".format(serder.ked))

        return serder

    def issue(self, said, dt=None):
        """ Create and process an iss or bis message event

        Parameters:
            said (str): qb64 SAID of credential to issue
            dt (str): iso8601 formatted date time string of issuance

        Returns:
            boolean: True if issuance is successful

        """

        if self.noBackers:
            serder = eventing.issue(vcdig=said, regk=self.regk, dt=dt)
        else:
            serder = eventing.backerIssue(vcdig=said, regk=self.regk, regsn=self.regi, regd=self.regser.saider.qb64,
                                          dt=dt)

        try:
            self.tvy.processEvent(serder=serder)
        except kering.MissingAnchorError:
            logger.info("Credential registry missing anchor for inception = {}".format(serder.ked))

        return serder

    def revoke(self, said, dt=None):
        """ Perform revocation of credential

        Create and process rev or brv message event

        Parameters:
            said (str): qb64 SAID of the credential to revoke
            dt (str): iso8601 formatted date time string of revocation

        Returns:
            boolean: True if revocation is successful.

        """
        vci = said
        vcser = self.reger.getTel(snKey(pre=vci, sn=0))
        if vcser is None:
            raise kering.ValidationError("Invalid revoke of {} that has not been issued "
                                         "pre={}.".format(vci, self.regk))
        ievt = self.reger.getTvt(dgKey(pre=vci, dig=vcser))
        iserder = Serder(raw=bytes(ievt))

        if self.noBackers:
            serder = eventing.revoke(vcdig=vci, regk=self.regk, dig=iserder.said, dt=dt)
        else:
            serder = eventing.backerRevoke(vcdig=vci, regk=self.regk, regsn=self.regi, regd=self.regser.saider.qb64,
                                           dig=iserder.said, dt=dt)

        try:
            self.tvy.processEvent(serder=serder)
        except kering.MissingAnchorError:
            logger.info("Credential registry missing anchor for inception = {}".format(serder.ked))

        return serder

    def anchorMsg(self, pre, regd, seqner, saider):
        """  Create key event with seal to serder anchored as data.

        Performs a rotation or interaction event for single sig or multiple sig identifier
        to anchor the provide regsitry event.  Inserts outbound cues for external processing
        of resulting events or multisig handling.

        Parameters:
            pre (str): registry event identifier
            regd (str): registry event SAID
            seqner (Seqner): sequence number of anchoring event
            saider (Saider): SAID of the anchoring event

        """

        key = dgKey(pre, regd)
        sealet = seqner.qb64b + saider.qb64b
        self.reger.putAnc(key, sealet)


class Registrar(doing.DoDoer):

    def __init__(self, hby, rgy, counselor):
        self.hby = hby
        self.rgy = rgy
        self.counselor = counselor
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.witPub = agenting.WitnessPublisher(hby=self.hby)

        doers = [self.witDoer, self.witPub, doing.doify(self.escrowDo)]

        super(Registrar, self).__init__(doers=doers)

    def incept(self, name, pre, conf=None, aids=None):
        """

        Parameters:
            name (str): human readable name for the registry
            pre (str): qb64 identifier prefix of issuing identifier in control of this registry
            conf (dict): configuration information for the registry (noBackers, estOnly)
            aids (list): participants of a multisig group in the anchoring event

        Returns:
            Registry:  created registry

        """
        conf = conf if conf is not None else {}  # default config if none specified
        estOnly = "estOnly" in conf and conf["estOnly"]
        hab = self.hby.habs[pre]

        registry = self.rgy.makeRegistry(name=name, prefix=pre, **conf)

        rseq = coring.Seqner(sn=0)
        rseal = SealEvent(registry.regk, "0", registry.regd)._asdict()
        if hab.phab is None:
            if estOnly:
                hab.rotate(data=[rseal])
            else:
                hab.interact(data=[rseal])

            seqner = coring.Seqner(sn=hab.kever.sn)
            saider = hab.kever.serder.saider
            registry.anchorMsg(pre=registry.regk, regd=registry.regd, seqner=seqner, saider=saider)

            print("Waiting for TEL event witness receipts")
            self.witDoer.msgs.append(dict(pre=pre, sn=seqner.sn))

            self.rgy.reger.tpwe.add(keys=(registry.regk, rseq.qb64), val=(hab.kever.prefixer, seqner, saider))

        else:
            aids = aids if aids is not None else hab.aids
            prefixer, seqner, saider = self.multisigIxn(hab, rseal)
            self.counselor.start(aids=aids, pid=hab.phab.pre, prefixer=prefixer, seqner=seqner,
                                 saider=saider)

            print("Waiting for TEL event mulisig anchoring event")
            self.rgy.reger.tmse.add(keys=(registry.regk, rseq.qb64, registry.regd), val=(prefixer, seqner, saider))

        return registry

    def issue(self, regk, said, dt=None, aids=None):
        """
        Create and process the credential issuance TEL events on the given registry

        Parameters:
            regk (str): qb64 identifier prefix of the credential registry
            said (str): qb64 SAID of the credential to issue
            dt (str): iso8601 formatted date string of issuance date
            aids (list): participants of a multisig group in the anchoring event

        """
        registry = self.rgy.regs[regk]
        hab = registry.hab

        iserder = registry.issue(said=said, dt=dt)

        vcid = iserder.ked["i"]
        rseq = coring.Seqner(snh=iserder.ked["s"])
        rseal = SealEvent(vcid, rseq.snh, iserder.said)._asdict()

        if hab.phab is None:
            if registry.estOnly:
                hab.rotate(data=[rseal])
            else:
                hab.interact(data=[rseal])

            seqner = coring.Seqner(sn=hab.kever.sn)
            saider = hab.kever.serder.saider
            registry.anchorMsg(pre=vcid, regd=iserder.said, seqner=seqner, saider=saider)

            print("Waiting for TEL event witness receipts")
            self.witDoer.msgs.append(dict(pre=hab.pre, sn=seqner.sn))

            self.rgy.reger.tpwe.add(keys=(vcid, rseq.qb64), val=(hab.kever.prefixer, seqner, saider))
            return vcid, rseq.sn
        else:
            aids = aids if aids is not None else hab.aids
            prefixer, seqner, saider = self.multisigIxn(hab, rseal)
            self.counselor.start(aids=aids, pid=hab.phab.pre, prefixer=prefixer, seqner=seqner,
                                 saider=saider)

            print(f"Waiting for TEL event mulisig anchoring event {seqner.sn}")
            self.rgy.reger.tmse.add(keys=(vcid, rseq.qb64, iserder.said), val=(prefixer, seqner, saider))
            return vcid, rseq.sn

    def revoke(self, regk, said, dt=None, aids=None):
        """
        Create and process the credential revocation TEL events on the given registry

        Parameters:
            regk (str): qb64 identifier prefix of the credential registry
            said (str): qb64 SAID of the credential to issue
            dt (str): iso8601 formatted date string of issuance date
            aids (list): participants of a multisig group in the anchoring event

        """
        registry = self.rgy.regs[regk]
        hab = registry.hab

        state = registry.tever.vcState(vci=said)
        if state is None or state.ked["et"] not in (coring.Ilks.iss, coring.Ilks.rev):
            raise kering.ValidationError(f"credential {said} not is correct state for revocation")

        rserder = registry.revoke(said=said, dt=dt)

        vcid = rserder.ked["i"]
        rseq = coring.Seqner(snh=rserder.ked["s"])
        rseal = SealEvent(vcid, rseq.snh, rserder.said)._asdict()

        if hab.phab is None:
            if registry.estOnly:
                hab.rotate(data=[rseal])
            else:
                hab.interact(data=[rseal])

            seqner = coring.Seqner(sn=hab.kever.sn)
            saider = hab.kever.serder.saider
            registry.anchorMsg(pre=vcid, regd=rserder.said, seqner=seqner, saider=saider)

            print("Waiting for TEL event witness receipts")
            self.witDoer.msgs.append(dict(pre=hab.pre, sn=seqner.sn))

            self.rgy.reger.tpwe.add(keys=(vcid, rseq.qb64), val=(hab.kever.prefixer, seqner, saider))
            return vcid, rseq.sn
        else:
            aids = aids if aids is not None else hab.aids
            prefixer, seqner, saider = self.multisigIxn(hab, rseal)
            self.counselor.start(aids=aids, pid=hab.phab.pre, prefixer=prefixer, seqner=seqner,
                                 saider=saider)

            print(f"Waiting for TEL event mulisig anchoring event {seqner.sn}")
            self.rgy.reger.tmse.add(keys=(vcid, rseq.qb64, rserder.said), val=(prefixer, seqner, saider))
            return vcid, rseq.sn

    @staticmethod
    def multisigIxn(hab, rseal):
        ixn = hab.interact(data=[rseal])
        gserder = coring.Serder(raw=ixn)

        sn = gserder.sn
        said = gserder.said

        prefixer = coring.Prefixer(qb64=hab.pre)
        seqner = coring.Seqner(sn=sn)
        saider = coring.Saider(qb64=said)

        return prefixer, seqner, saider

    def complete(self, pre, sn=0):
        seqner = coring.Seqner(sn=sn)
        said = self.rgy.reger.ctel.get(keys=(pre, seqner.qb64))
        return said is not None

    def escrowDo(self, tymth, tock=1.0):
        """ Process escrows of group multisig identifiers waiting to be compeleted.

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
        Process credential registry anchors:

        """
        self.processWitnessEscrow()
        self.processMultisigEscrow()
        self.processDiseminationEscrow()

    def processWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full compliment of receipts
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
        Process escrow of group multisig events that do not have a full compliment of receipts
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

    def processDiseminationEscrow(self):
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
            self.witPub.msgs.append(dict(pre=prefixer.qb64, msg=tevt))
            self.rgy.reger.ctel.put(keys=(regk, rseq.qb64), val=saider)  # idempotent


class Credentialer(doing.DoDoer):

    def __init__(self, hby, rgy, registrar, verifier):
        self.hby = hby
        self.rgy = rgy
        self.registrar = registrar
        self.verifier = verifier
        self.postman = forwarding.Postman(hby=hby)
        doers = [self.postman, doing.doify(self.escrowDo)]

        super(Credentialer, self).__init__(doers=doers)

    def create(self, regname, recp, schema, source, rules, data):
        """  Create and validate a credential returning the fully populated Creder

        Parameters:
            regname:
            recp:
            schema:
            source:
            rules:
            data:

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
        hab = registry.hab

        dt = data["dt"] if "dt" in data else helping.nowIso8601()

        d = dict(
            d="",
            dt=dt,
        )

        if recp is not None:
            d['i'] = recp

        d |= data

        creder = proving.credential(issuer=hab.pre,
                                    schema=schema,
                                    subject=d,
                                    source=source,
                                    rules=rules,
                                    status=registry.regk)
        self.validate(creder)
        return creder

    def validate(self, creder):
        """

        Args:
            creder:

        Returns:
            bool: true if credential is valid against a known schema

        """
        schema = creder.crd['s']
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

    def issue(self, creder, aids=None):
        """ Issue the credential creder and handle witness propagation and communication

        Args:
            creder (Creder): Credential object to issue
            aids (list): optional participant list for multisig issuance

        """
        regk = creder.crd["ri"]
        registry = self.rgy.regs[regk]
        hab = registry.hab
        aids = aids if aids is not None else hab.aids
        dt = creder.subject["dt"] if "dt" in creder.subject else None

        vcid, seq = self.registrar.issue(regk=registry.regk, said=creder.said, dt=dt, aids=aids)

        rseq = coring.Seqner(sn=seq)
        if hab.phab:
            craw = signing.ratify(hab=hab.phab, serder=creder)
            atc = bytearray(craw[creder.size:])
            others = list(aids)
            others.remove(hab.phab.pre)

            print(f"Sending signed credential to {len(aids) - 1} other participants")
            for recpt in others:
                self.postman.send(src=hab.phab.pre, dest=recpt, topic="multisig", serder=creder, attachment=atc)

            # escrow waiting for other signatures
            self.rgy.reger.cmse.put(keys=(creder.said, rseq.qb64), val=creder)
        else:
            craw = signing.ratify(hab=hab, serder=creder)

            # escrow waiting for registry anchors to be complete
            self.rgy.reger.crie.put(keys=(creder.said, rseq.qb64), val=creder)

        parsing.Parser().parse(ims=craw, vry=self.verifier)

    def processCredentialMissingSigEscrow(self):
        for (said, snq), creder in self.rgy.reger.cmse.getItemIter():
            rseq = coring.Seqner(qb64=snq)

            # Look for the saved saider
            saider = self.rgy.reger.saved.get(keys=said)
            if saider is None:
                continue

            # Remove from this escrow
            self.rgy.reger.cmse.rem(keys=(said, snq))

            hab = self.hby.habs[creder.issuer]
            kever = hab.kever
            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = hab.phab.kever.verfers[0].qb64 == keys[0]  # Elected to perform delegation and witnessing

            # place in escrow to diseminate to other if witnesser and if there is an issuee
            if witer:
                self.rgy.reger.crie.put(keys=(creder.said, rseq.qb64), val=creder)
            else:  # not witnesser or no one to send it to so just save as issued.
                self.rgy.reger.ccrd.put(keys=(said,), val=creder)

    def processCredentialIssuedEscrow(self):
        for (said, snq), creder in self.rgy.reger.crie.getItemIter():
            rseq = coring.Seqner(qb64=snq)

            if not self.registrar.complete(pre=said, sn=rseq.sn):
                continue

            issr = creder.issuer
            regk = creder.status

            if "i" in creder.subject:
                recp = creder.subject["i"]

                hab = self.hby.habs[issr]

                for msg in self.hby.db.clonePreIter(pre=issr):
                    serder = coring.Serder(raw=msg)
                    atc = msg[serder.size:]
                    self.postman.send(src=issr, dest=recp, topic="credential", serder=serder, attachment=atc)

                if regk is not None:
                    for msg in self.verifier.reger.clonePreIter(pre=regk):
                        serder = coring.Serder(raw=msg)
                        atc = msg[serder.size:]
                        self.postman.send(src=issr, dest=recp, topic="credential", serder=serder, attachment=atc)

                for msg in self.verifier.reger.clonePreIter(pre=creder.said):
                    serder = coring.Serder(raw=msg)
                    atc = msg[serder.size:]
                    self.postman.send(src=issr, dest=recp, topic="credential", serder=serder, attachment=atc)

                sources = self.verifier.reger.sources(self.hby.db, creder)
                sender = issr
                for source, atc in sources:
                    regk = source.status
                    vci = source.said

                    issr = source.crd["i"]
                    for msg in self.verifier.reger.clonePreIter(pre=vci):
                        serder = coring.Serder(raw=msg)
                        atc = msg[serder.size:]
                        self.postman.send(src=sender, dest=recp, topic="credential", serder=serder,
                                          attachment=atc)

                    for msg in self.verifier.reger.clonePreIter(pre=regk):
                        serder = coring.Serder(raw=msg)
                        atc = msg[serder.size:]
                        self.postman.send(src=sender, dest=recp, topic="credential", serder=serder, attachment=atc)

                    for msg in self.hby.db.clonePreIter(pre=issr):
                        serder = coring.Serder(raw=msg)
                        atc = msg[serder.size:]
                        self.postman.send(src=sender, dest=recp, topic="credential", serder=serder,
                                          attachment=atc)

                    serder, sadsigs, sadcigs = self.rgy.reger.cloneCred(source.said)
                    atc = signing.provision(serder=source, sadcigars=sadcigs, sadsigers=sadsigs)
                    del atc[:serder.size]
                    self.postman.send(src=sender, dest=recp, topic="credential", serder=source, attachment=atc)

                serder, sadsigs, sadcigs = self.rgy.reger.cloneCred(creder.said)
                atc = signing.provision(serder=creder, sadcigars=sadcigs, sadsigers=sadsigs)
                del atc[:serder.size]
                self.postman.send(src=sender, dest=recp, topic="credential", serder=creder, attachment=atc)

                exn, atc = protocoling.credentialIssueExn(hab=hab, schema=creder.schema, said=creder.said)
                self.postman.send(src=sender, dest=recp, topic="credential", serder=exn, attachment=atc)

            self.rgy.reger.crie.rem(keys=(said, snq))
            self.rgy.reger.ccrd.put(keys=(said,), val=creder)

    def complete(self, said):
        return self.rgy.reger.ccrd.get(keys=(said,)) is not None and len(self.postman.evts) == 0

    def escrowDo(self, tymth, tock=1.0):
        """ Process escrows of group multisig identifiers waiting to be compeleted.

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
        Process credential registry anchors:

        """
        self.processCredentialIssuedEscrow()
        self.processCredentialMissingSigEscrow()
