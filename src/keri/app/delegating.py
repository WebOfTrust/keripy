# -*- encoding: utf-8 -*-
"""
KERI
keri.app.delegating module

module for enveloping and forwarding KERI message
"""

from hio.base import doing
from hio.help import ogler

from .agenting import WitnessInquisitor, Receiptor, WitnessPublisher
from .forwarding import Poster
from .habbing import GroupHab

from ..kering import ValidationError
from ..core import Number, Diger, Seqner, SerderKERI, NumDex
from ..peer import exchange

logger = ogler.getLogger()


class Anchorer(doing.DoDoer):
    """Manages the delegation anchoring lifecycle for a delegated identifier.

    Sends the delegated inception or rotation event to the delegator and waits
    for the anchoring seal to appear in the delegator's KEL, confirming that the
    delegation has been approved.  Once the event is fully witnessed and the
    anchor is confirmed, all internal Doers are removed and this DoDoer exits as
    done.

    Attributes:
        hby (Habery): Local controller database and keystore.
        postman (Poster): Sends KERI messages to remote AIDs.
        witq (WitnessInquisitor): Queries witnesses for receipts and KEL state.
        witDoer (Receiptor): Collects witness receipts for local events.
        publishers (dict[str, WitnessPublisher]): Maps delegated AID prefix to
            its WitnessPublisher, used to broadcast the anchored event.
        proxy (Hab | None): Optional proxy Habitat used to sign and send
            outbound messages on behalf of the delegated identifier.
        auths (list[str] | None): TOTP codes forwarded to witnesses to
            authorize event receipting.
    """

    def __init__(self, hby, proxy=None, auths=None, **kwa):
        """Initializes Anchorer with required doers and optional proxy/auth.

        Args:
            hby (Habery): Local controller database and keystore for this
                Anchorer instance.
            proxy (Hab, optional): Proxy Habitat used to send outbound
                messages when the delegated identifier cannot send directly.
                Defaults to None.
            auths (list[str], optional): TOTP authentication codes sent to
                witnesses to authorize event receipting. Defaults to None.
            **kwa: Additional keyword arguments forwarded to DoDoer.__init__.
        """
        self.hby = hby
        self.postman = Poster(hby=hby)
        self.witq = WitnessInquisitor(hby=hby)
        self.witDoer = Receiptor(hby=self.hby)
        self.publishers = dict()
        self.proxy = proxy
        self.auths = auths

        super(Anchorer, self).__init__(doers=[self.witq, self.witDoer, self.postman, doing.doify(self.escrowDo)], **kwa)

    def delegation(self, pre, sn=None, proxy=None, auths=None):
        """Initiates the delegation protocol for a locally-controlled identifier.

        Creates a WitnessPublisher for the delegated AID, queues the target
        event for witness receipting via the Receiptor doer, and places the
        event on the partial-witness delegation escrow (``dpwe``) so that
        ``escrowDo`` can drive it through the remaining protocol steps.

        Args:
            pre (str): qb64 identifier prefix of the locally-controlled
                delegated AID whose inception or rotation requires anchoring.
            sn (int, optional): Sequence number of the event to anchor.
                Defaults to the current sequence number of the AID's KEL.
            proxy (Hab, optional): Proxy Habitat to use for sending outbound
                messages.  Overrides ``self.proxy`` when provided.
                Defaults to None.
            auths (list[str], optional): TOTP authentication codes sent to
                witnesses to authorize event receipting.  Overrides
                ``self.auths`` when provided. Defaults to None.

        Raises:
            ValidationError: If ``pre`` does not correspond to a locally
                controlled AID in ``hby.habs``.
            ValidationError: If the delegator prefix recorded in the AID's
                KEL is not present in the known kevers.
        """
        if pre not in self.hby.habs:
            raise ValidationError(f"{pre} is not a valid local AID for delegation")

        if proxy is not None:
            self.proxy = proxy

        self.publishers[pre] = WitnessPublisher(hby=self.hby)
        # load the hab of the delegated identifier to anchor
        hab = self.hby.habs[pre]
        delpre = hab.kever.delpre  # get the delegator identifier
        if delpre not in hab.kevers:
            raise ValidationError(f"delegator {delpre} not found, unable to process delegation")

        sn = sn if sn is not None else hab.kever.sner.num
        self.auths = auths if auths is not None else self.auths

        # load the event and signatures
        evt = hab.makeOwnEvent(sn=sn)

        # Send exn message for notification purposes
        srdr = SerderKERI(raw=evt)
        self.witDoer.msgs.append(dict(pre=pre, sn=srdr.sn, auths=self.auths))
        self.hby.db.dpwe.pin(keys=(srdr.pre, srdr.said), val=srdr)

    def complete(self, prefixer, number, diger=None):
        """Checks whether the delegation protocol has completed for a specific event.

        Looks up the completed-delegation database (``cdel``) for a confirmed
        anchor at the given sequence number.  Optionally verifies that the
        anchored event digest matches the expected value.

        Args:
            prefixer (Prefixer): Prefixer for the delegated AID whose
                delegation status is being queried.
            number (Number): Sequence number (``Number.huge``) of the event
                to check.
            diger (Diger, optional): Expected digest of the anchored event.
                When provided, the stored digest is compared and a
                ``ValidationError`` is raised on mismatch. Defaults to None.

        Returns:
            bool: ``True`` if the delegation anchor has been recorded for the
            event; ``False`` if the anchor has not yet been confirmed.

        Raises:
            ValidationError: If ``diger`` is provided and does not match the
                digest stored in the completed-delegation database.
        """
        cdiger = self.hby.db.cdel.get(keys=prefixer.qb64b, on=number.sn)
        if not cdiger:
            return False
        else:
            if diger and (cdiger.qb64 != diger.qb64):
                raise ValidationError(f"invalid delegation protocol escrowed event {cdiger.qb64}-{diger.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """Async generator doer that continuously drives delegation escrow processing.

        Enters the tymist context and then loops forever, calling
        ``processEscrows`` on each cycle and yielding to allow other doers
        to run.  The full delegation lifecycle managed across escrow buckets is:

        1. Collect witness receipts for the local delegated event.
        2. Once receipts reach threshold, forward the event to the delegator
           via an ``exn`` delegation-request and a direct KEL message.
        3. Query the delegator's witnesses for the anchoring seal.
        4. On anchor confirmation, publish the event to the delegated AID's
           own witnesses.
        5. Record completion in the ``cdel`` database.

        Args:
            tymth (function): Injected wrapper closure returned by
                ``Tymist.tymen()``. Calling ``tymth()`` returns the associated
                Tymist ``.tyme`` value.
            tock (float, optional): Initial tock value controlling the doer's
                scheduling interval in seconds. Defaults to 1.0.
            **kwa: Additional keyword arguments (unused; accepted for
                DoDoer compatibility).

        Yields:
            float: Tock value that signals the scheduler how long to wait
            before resuming this generator.
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        """Runs all delegation escrow processing steps in order.

        Delegates to the three escrow processors that collectively drive an
        event through the full delegation lifecycle:

        1. ``processPartialWitnessEscrow`` — waits for witness receipts and,
           once complete, forwards the event to the delegator.
        2. ``processUnanchoredEscrow`` — waits for the delegator's anchor seal
           and, once found, moves the event to witness publication.
        3. ``processWitnessPublication`` — waits for publication to the
           delegated AID's witnesses to finish, then records completion.
        """
        self.processPartialWitnessEscrow()
        self.processUnanchoredEscrow()
        self.processWitnessPublication()

    def processUnanchoredEscrow(self):
        """Processes events waiting for the delegator's anchoring seal.

        Iterates over the delegated-unanchored escrow (``dune``).  For each
        event, queries the delegator's KEL for a sealing event whose seal
        matches the delegated event's prefix, sequence number, and digest.
        When a matching sealing event is found:

        - Stores the authorizer event seal (delegator sequence number and
          digest) in ``aess``.
        - Moves the event to the witness-publication escrow (``dpub``).
        - Removes the event from the unanchored escrow (``dune``).
        - Triggers ``publishDelegator`` to broadcast the delegation event to
          the delegated AID's witnesses.
        """
        for (pre, said), serder in self.hby.db.dune.getTopItemIter():  # delegated unanchored escrow
            kever = self.hby.kevers[pre]
            dkever = self.hby.kevers[kever.delpre]

            seal = dict(i=serder.pre, s=serder.snh, d=serder.said)
            if dserder := self.hby.db.fetchLastSealingEventByEventSeal(dkever.prefixer.qb64, seal=seal):
                sner = Number(num=dserder.sn, code=NumDex.Huge)
                diger = Diger(qb64b=dserder.saidb)
                self.hby.db.aess.pin(keys=(kever.prefixer.qb64b, kever.serder.saidb),
                                     val=(sner, diger))  # authorizer event seal (delegator/issuer)

                # Move to escrow waiting for witness receipts
                logger.info(f"Delegation approval received, {serder.pre} confirmed, publishing to my witnesses")
                self.publishDelegator(pre)
                self.hby.db.dpub.put(keys=(pre, said), val=serder)
                self.hby.db.dune.rem(keys=(pre, said))

    def processPartialWitnessEscrow(self):
        """Processes delegated events waiting for a full complement of witness receipts.

        Iterates over the delegation partial-witness escrow (``dpwe``).  For
        each event, checks whether the number of receipts in ``wigs`` equals
        the number of witnesses for the delegated AID's KEL.  When the receipt
        threshold is met and the Receiptor has confirmed witnessing:

        - Sends a signed ``exn`` delegation-request message to the delegator
          via the Postman.
        - Sends the raw delegated event to the delegator via the Postman.
        - Queues a witness query on the delegator's KEL for the expected
          anchoring seal.
        - Moves the event from the partial-witness escrow (``dpwe``) to the
          unanchored escrow (``dune``).

        For group (multisig) Habs the member Hab (``mhab``) is used as the
        signing proxy; for single-sig Habs ``self.proxy`` must be set.

        Raises:
            ValidationError: If the delegated Hab is not a GroupHab and
                ``self.proxy`` is ``None``, because there is no available
                proxy to sign and send the delegation messages.
        """
        for (pre, said), serder in self.hby.db.dpwe.getTopItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]
            seqner = Seqner(sn=serder.sn)

            # Load all the witness receipts we have so far
            wigers = self.hby.db.wigs.get(keys=(pre, serder.said))
            if len(wigers) == len(kever.wits):  # We have all of them, this event is finished
                if len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == serder.pre and cue["sn"] == seqner.sn:
                            witnessed = True
                    if not witnessed:
                        continue
                logger.info(f"Witness receipts complete, waiting for delegation approval.")
                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]
                delpre = hab.kever.delpre  # get the delegator identifier
                dkever = hab.kevers[delpre]  # and the delegator's kever
                smids = []

                if isinstance(hab, GroupHab):
                    phab = hab.mhab
                    smids = hab.smids
                elif self.proxy is not None:
                    phab = self.proxy
                else:
                    raise ValidationError("no proxy to send messages for delegation")

                evt = hab.db.cloneEvtMsg(pre=serder.pre, fn=0, dig=serder.said)
                srdr = SerderKERI(raw=evt)
                exn, atc = delegateRequestExn(phab, delpre=delpre, evt=bytes(evt), aids=smids)

                logger.info(
                    "Sending delegation request exn for %s from %s to delegator %s", srdr.ilk, phab.pre, delpre)
                logger.debug("Delegation request=\n%s\n", exn.pretty())
                self.postman.send(hab=phab, dest=hab.kever.delpre, topic="delegate", serder=exn, attachment=atc)

                del evt[:srdr.size]
                logger.info("Sending delegation event %s from %s to delegator %s", srdr.ilk, phab.pre, delpre)
                logger.debug("Delegated inception=\n%s\n", srdr.pretty())
                self.postman.send(hab=phab, dest=delpre, topic="delegate", serder=srdr, attachment=evt)

                seal = dict(i=srdr.pre, s=srdr.snh, d=srdr.said)
                self.witq.query(hab=phab, pre=dkever.prefixer.qb64, anchor=seal)

                self.hby.db.dpwe.rem(keys=(pre, said))
                self.hby.db.dune.pin(keys=(srdr.pre, srdr.said), val=srdr)

    def processWitnessPublication(self):
        """Processes events whose delegation is anchored and awaiting witness publication.

        Iterates over the delegation publication escrow (``dpub``).  For each
        event, checks whether the associated WitnessPublisher has finished
        broadcasting.  When publication is complete:

        - Removes the publisher from the active doer set and from
          ``self.publishers``.
        - Removes the event from the publication escrow (``dpub``).
        - Records completion of the delegation in ``cdel`` keyed by the
          delegated AID prefix and indexed by sequence number.
        """
        for (pre, said), serder in self.hby.db.dpub.getTopItemIter():  # group partial witness escrow
            if pre not in self.publishers:
                continue

            publisher = self.publishers[pre]

            if not publisher.idle:
                continue

            self.remove([publisher])
            del self.publishers[pre]

            self.hby.db.dpub.rem(keys=(pre, said))
            self.hby.db.cdel.put(keys=pre, on=serder.sn, val=Diger(qb64=serder.said))

    def publishDelegator(self, pre):
        """Queues the delegation event for broadcast to the delegated AID's witnesses.

        Retrieves the WitnessPublisher for ``pre``, adds it to the active doer
        set, and enqueues each message from the cloned delegation KEL so the
        publisher can forward them to the witnesses.  Does nothing if no
        publisher has been registered for ``pre``.

        Args:
            pre (str): qb64 identifier prefix of the delegated AID whose
                delegation event should be published to witnesses.
        """
        if pre not in self.publishers:
            return

        publisher = self.publishers[pre]
        hab = self.hby.habs[pre]
        self.extend([publisher])
        for msg in hab.db.cloneDelegation(hab.kever):
            publisher.msgs.append(dict(pre=hab.pre, msg=bytes(msg)))


def loadHandlers(hby, exc, notifier):
    """Registers peer-to-peer delegation protocol handlers with the Exchanger.

    Currently registers ``DelegateRequestHandler`` so that inbound
    ``/delegate/request`` ``exn`` messages are routed to the correct handler
    and converted into controller notifications.

    Args:
        hby (Habery): Database and keystore for the local environment.
        exc (Exchanger): Peer-to-peer message router that dispatches ``exn``
            messages to registered handlers by route.
        notifier (Notifier): Outbound notification bus used by
            ``DelegateRequestHandler`` to surface delegation requests to the
            controller UI.
    """
    delreq = DelegateRequestHandler(hby=hby, notifier=notifier)
    exc.addHandler(delreq)


class DelegateRequestHandler:
    """Handles inbound ``/delegate/request`` peer-to-peer ``exn`` messages.

    Validates that the target delegator AID (``delpre``) is controlled
    locally, then converts the message payload into a controller notification
    so the operator can approve or reject the delegation request.

    Attributes:
        resource (str): Route string that identifies this handler to the
            Exchanger; set to ``"/delegate/request"``.
        hby (Habery): Database and keystore for the local environment.
        notifier (Notifier): Outbound notification bus for surfacing
            delegation requests to the controller UI.
    """
    resource = "/delegate/request"

    def __init__(self, hby, notifier):
        """Initializes DelegateRequestHandler.

        Args:
            hby (Habery): Database and keystore for the local environment.
            notifier (Notifier): Outbound notification bus used to surface
                inbound delegation requests to the controller UI.
        """
        self.hby = hby
        self.notifier = notifier

    def handle(self, serder, attachments=None):
        """Processes an inbound ``/delegate/request`` ``exn`` message.

        Extracts the delegator AID (``delpre``) and embedded event from the
        message payload, verifies that ``delpre`` is a locally controlled AID,
        and adds a notification so the controller can act on the request.
        Logs an error and returns without raising if ``delpre`` is not local.

        Args:
            serder (Serder): Serder of the inbound ``exn`` delegation-request
                message.
            attachments (list[tuple], optional): List of ``(pather, SAD)``
                path-attachment tuples from the ``exn`` envelope.
                Defaults to None.
        """

        src = serder.pre
        pay = serder.ked['a']
        embeds = serder.ked['e']

        delpre = pay["delpre"]
        if delpre not in self.hby.habs:
            logger.error(f"invalid delegate request message, no local delpre for evt=: {pay}")
            return

        data = dict(
            src=src,
            r='/delegate/request',
            delpre=delpre,
            ked=embeds["evt"]
        )
        if "aids" in pay:
            data["aids"] = pay["aids"]

        self.notifier.add(attrs=data)


def delegateRequestExn(hab, delpre, evt, aids=None):
    """Constructs a signed ``/delegate/request`` ``exn`` peer-to-peer message.

    Builds the payload and embeds dict for a delegation-request ``exn``,
    creates the ``exn`` envelope via ``exchange()``, and endorses it with
    the sender's current signing keys.  Returns the serder and detached
    attachment bytes so the caller can forward both to the delegator.

    Args:
        hab (Hab): Sending Habitat used to sign the ``exn`` message.
        delpre (str): qb64 AID of the delegator that must approve the event.
        evt (bytes): Fully serialized and signed delegated event (e.g. ``icp``
            or ``rot``) that requires the delegator's anchoring seal.
        aids (list[str], optional): qb64 AIDs of the multisig group members
            participating in this delegation, included in the payload when the
            delegated identifier is a group Hab. Defaults to None.

    Returns:
        tuple[SerderKERI, bytes]: A two-tuple of:
            - **exn** (SerderKERI): The signed ``/delegate/request`` ``exn``
              serder.
            - **atc** (bytes): Detached CESR attachment bytes (signatures)
              to be sent alongside the ``exn`` serder.
    """
    data = dict(
        delpre=delpre,
    )

    embeds = dict(
        evt=evt
    )

    if aids is not None:
        data["aids"] = aids

    # Create `exn` peer to peer message to notify other participants UI
    exn, _ = exchange(route=DelegateRequestHandler.resource, modifiers=dict(),
                                 payload=data, sender=hab.pre, embeds=embeds)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]

    return exn, ims
