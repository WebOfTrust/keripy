# -*- encoding: utf-8 -*-
"""
KERI
keri.vdr.issuing module

VC issuer support
"""
import json

from hio.base import doing
from hio.help import decking

from keri.vdr import viring
from .. import kering, help
from ..app import grouping, agenting
from ..core import parsing, coring
from ..core.coring import Counter, Seqner, CtrDex, MtrDex, Serder
from ..core.eventing import SealEvent, SealSource, TraitDex
from ..db.dbing import snKey, dgKey
from ..help import helping
from ..vc import proving
from ..vdr import eventing
from ..vdr.viring import Registry, nsKey

logger = help.ogler.getLogger()


class Issuer:
    """
    Issuer provides encapsulation of creating a Verifiable Credential Registry with issuance
    and revocation of VCs against that registry.

    The Registry consists of 1 management TEL for maintaining the state of the registry wrt special
    Backers that can act as witnesses of VC events, and 1 VC TEL for each VC issued that tracks the
    issuance and revocation status of those VCs.

    """

    def __init__(self, hab, name="test", cues=None, reger=None, estOnly=False,
                 temp=False, **kwa):
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
        self.cues = cues if cues is not None else decking.Deck()
        self.regk = None

        self.reger = reger if reger is not None else Registry(name=self.hab.name, temp=temp)
        self.inited = False

        # save init kwy word arg parameters as ._inits in order to later finish
        # init setup elseqhere after databases are opened if not below
        self._inits = kwa

        if self.hab.inited:
            self.setup(**self._inits)

    def setup(self, *, noBackers=False, baks=None, toad=None, ):

        ex = self.reger.regs.get(keys=self.name)
        if ex is not None:
            self.regk = ex.registryKey

        if self.regk is None:
            self.regi = 0

            self.noBackers = noBackers

            # save backers locally for now.  will be managed by tever when implemented
            self.backers = baks if baks is not None else []

            self.cnfg = [TraitDex.NoBackers] if self.noBackers else []

            group = self.hab.group()
            if group is None:
                pre = self.hab.pre
            else:
                pre = group.gid

            self.regser = eventing.incept(pre,
                                          baks=self.backers,
                                          toad=toad,
                                          cnfg=self.cnfg,
                                          code=MtrDex.Blake3_256)
            self.regk = self.regser.pre
            self.reger.regs.put(keys=self.name,
                                val=viring.RegistryRecord(registryKey=self.regk))

            self.tvy = eventing.Tevery(reger=self.reger, db=self.hab.db, regk=self.regk, local=True)
            self.psr = parsing.Parser(framed=True, kvy=self.hab.kvy, tvy=self.tvy)

            try:
                self.anchorMsg(self.regser)
            except kering.MissingAnchorError:
                logger.info("Credential registry missing anchor for inception = {}".format(self.regser.ked))
        else:
            self.tvy = eventing.Tevery(reger=self.reger, db=self.hab.db, regk=self.regk, local=True)
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

    @property
    def tevers(self):
        """
        Returns .db.tevers
        """
        return self.reger.tevers

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

        serder = eventing.rotate(dig=self.regser.dig, regk=self.regk, sn=self.regi + 1, toad=toad, baks=self.backers,
                                 adds=adds, cuts=cuts)

        self.regser = serder

        self.anchorMsg(serder)

        tever = self.tevers[self.regk]
        self.backers = tever.baks
        self.regi = int(tever.serder.ked["s"], 16)

        return True

    def issue(self, creder, dt=None):
        """
        Create and process an iss or bis message event

        Parameters:
            creder is hash digest of vc content qb64

        """
        vcdig = creder.said
        craw = self.hab.endorse(creder)

        if self.noBackers:
            serder = eventing.issue(vcdig=vcdig, regk=self.regk, dt=dt)
        else:
            serder = eventing.backerIssue(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.diger.qb64,
                                          dt=dt)

        self.anchorMsg(serder, reason=craw.decode("utf-8"))

        return True

    def revoke(self, vcdig, dt=None):
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
            serder = eventing.revoke(vcdig=vcdig, regk=self.regk, dig=iserder.dig, dt=dt)
        else:
            serder = eventing.backerRevoke(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.diger.qb64,
                                           dig=iserder.dig, dt=dt)

        self.anchorMsg(serder)

        return True

    @staticmethod
    def messagize(serder, seal):
        msg = bytearray(serder.raw)
        msg.extend(Counter(CtrDex.SealSourceCouples, count=1).qb64b)
        msg.extend(Seqner(sn=seal.s).qb64b)
        msg.extend(seal.d.encode("utf-8"))

        return msg

    def anchorMsg(self, serder, reason=None, seal=None):

        group = self.hab.group()

        rseal = SealEvent(serder.pre, serder.ked["s"], serder.dig)
        rseal = rseal._asdict()

        if group is None:
            if self.estOnly:
                kevt = self.hab.rotate(data=[rseal])
            else:
                kevt = self.hab.interact(data=[rseal])

            seal = SealSource(s=self.hab.kever.sn, d=self.hab.kever.serder.dig)
            tevt = self.messagize(serder=serder, seal=seal)

            self.psr.parseOne(ims=bytearray(tevt))  # make copy as kvr deletes
            self.cues.extend([
                dict(
                    kin="kevt",
                    msg=kevt
                ),
                dict(
                    kin="send",
                    msg=tevt
                ),
            ])

        else:
            if seal is None:
                op = grouping.Ops.rot if self.estOnly else grouping.Ops.ixn
                mmsg = dict(kin="multisig", op=op, data=[rseal], reason=reason)
                self.cues.append(mmsg)

                self.escrow(serder)
                raise kering.MissingAnchorError("anchor not provided for multisig")
            else:
                tevt = self.messagize(serder=serder, seal=seal)
                self.psr.parseOne(ims=bytearray(tevt))  # make copy as kvr deletes

                self.cues.append(dict(kin="logEvent", msg=tevt))

    def escrow(self, serder):
        """
        Save Issuer event for future process when anchor become available
        Parameters:
           serder: (Serder) is event to escrow

        """
        self.reger.mase.add(self.regk, serder.raw)

    def processEscrows(self):
        """
        Process

        """
        for (regk,), raw in self.reger.mase.getItemIter():
            serder = coring.Serder(raw=raw.encode("utf-8"))

            if "ri" in serder.ked:
                tev = self.tevers[serder.ked["ri"]]
                pre = tev.pre
            else:
                pre = serder.ked["ii"]

            sn = serder.sn
            dig = serder.dig

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
                        seal = SealSource(s=eserder.sn, d=eserder.dig)
                        break

            if not seal:
                continue

            try:
                self.anchorMsg(serder, seal=seal, reason=None)
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


class IssuerDoer(doing.DoDoer):
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

    def __init__(self, hab, issuer, verifier, msgs=None, cues=None, **kwa):
        """
        Parameters:
           issuer (Issuer): instance
        """
        self.hab = hab
        self.issuer = issuer
        self.verifier = verifier
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.gdoer = grouping.MultiSigGroupDoer(hab=hab)

        doers = [self.gdoer, doing.doify(self.issueDo), doing.doify(self.issuerDo), doing.doify(self.escrowDo)]

        super(IssuerDoer, self).__init__(doers=doers, **kwa)


    def enter(self, **kwargs):
        if not self.issuer.inited:
            self.issuer.setup(**self.issuer._inits)
        super(IssuerDoer, self).enter(**kwargs)


    def issueDo(self, tymth, tock=0.0, **kwa):
        """
        Returns:  doifiable Doist compatible generator method for creating a registry
        and sending its inception and anchoring events to witnesses or backers

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                schema = msg["schema"]
                typ = msg["typ"]
                source = msg["source"]
                recipient = msg["recipient"]
                data = msg["data"]

                dt = data["dt"] if "dt" in data else None

                types = ["VerifiableCredential", typ]

                d = dict(
                    i="",
                    type=types,
                    si=recipient,
                    dt=helping.nowIso8601()
                )

                d |= data

                group = self.hab.group()
                if group is None:
                    pre = self.hab.pre
                else:
                    name, group = group
                    pre = group.gid

                creder = proving.credential(issuer=pre,
                                            schema=schema,
                                            subject=d,
                                            source=source,
                                            status=self.issuer.regk)



                try:
                    self.issuer.issue(creder=creder, dt=dt)
                except kering.MissingAnchorError:
                    logger.info("Missing anchor from credential issuance due to multisig identifier")

                craw = self.hab.endorse(creder)
                proving.parseCredential(ims=craw, verifier=self.verifier)

                yield self.tock

            yield self.tock

    def issuerDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from credential issue coroutine

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.issuer.cues:
                cue = self.issuer.cues.popleft()

                cueKin = cue['kin']
                if cueKin == "send":
                    tevt = cue["msg"]
                    witSender = agenting.WitnessPublisher(hab=self.hab, msg=tevt)
                    self.extend([witSender])

                    while not witSender.done:
                        _ = yield self.tock

                    self.remove([witSender])
                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=kevt)
                    self.extend([witDoer])

                    while not witDoer.done:
                        yield self.tock

                    self.remove([witDoer])

                    self.cues.append(dict(kin="finished"))
                elif cueKin == "multisig":
                    msg = dict(
                        op=cue["op"],
                        group=cue["group"],
                        data=cue["data"],
                        reason=cue["reason"]
                    )
                    self.gdoer.msgs.append(msg)
                elif cueKin == "logEvent":
                    print("TEL event saved")


                yield self.tock

            yield self.tock

    def escrowDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list

        Processes the Groupy escrow for group icp, rot and ixn request messages.

        """
        # start enter context
        yield  # enter context
        while True:
            self.issuer.processEscrows()
            self.verifier.processEscrows()
            yield

