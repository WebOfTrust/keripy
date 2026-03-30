# -*- encoding: utf-8 -*-
"""
KERI
keri.app.forwarding module

module for enveloping and forwarding KERI message
"""
import random
import pysodium
from ordered_set import OrderedSet as oset

from hio.base import doing
from hio.help import decking, ogler

from ..kering import (Roles, Vrsn_1_0, Kinds,
                      ConfigurationError, ValidationError)
from .agenting import messengerFrom, streamMessengerFrom
from ..core import (Bexter, Prefixer, Verfer, Texter, Diger,
                    Sadder, Counter, SerderKERI,
                    MtrDex, Codens, NonTransDex)
from ..db import dgKey
from ..peer import exchange
from ..spac import PayloadTyper, PayloadTypes

logger = ogler.getLogger()


class Poster(doing.DoDoer):
    """DoDoer that wraps any KERI event (KEL, TEL, Peer to Peer) in a /fwd ``exn``
    envelope and delivers it to one of the target recipient's witnesses for
    store and forward to the intended recipient.

    Routing priority for a given recipient:
        1. Controller, agent, or mailbox endpoints — contacted directly
           (mailbox role is wrapped in a ``/fwd`` envelope; controller/agent
           roles are sent unwrapped).
        2. Witness endpoints — message is wrapped in a ``/fwd`` envelope and
           forwarded to a randomly chosen witness.

    Attributes:
        hby (Habery): Database environment used to look up habs and kevers.
        mbx (Mailboxer): Optional local mailbox for store-and-forward when this
            hab is itself one of the destination endpoints.
        evts (Deck): Queue of outbound event dicts awaiting delivery.
        cues (Deck): Queue of delivery-confirmation dicts populated after each
            successful send.
    """

    def __init__(self, hby, mbx=None, evts=None, cues=None, **kwa):
        self.hby = hby
        self.mbx = mbx
        self.evts = evts if evts is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.deliverDo)]
        super(Poster, self).__init__(doers=doers, **kwa)

    def deliverDo(self, tymth=None, tock=0.0, **kwa):
        """Doist-compatible generator that drains ``self.evts`` and delivers each
        event to the appropriate endpoint.

        For each event the method resolves the recipient's end-role endpoints via
        ``hab.endsFor`` and dispatches using :meth:`sendDirect` (controller/agent)
        or :meth:`forward` / :meth:`forwardToWitness` (mailbox/witness).
        Successful deliveries are acknowledged by appending a cue dict to
        ``self.cues``.

        Args:
            tymth: Tymth generator reference injected by the Doist framework;
                used to bind the local ``tock`` clock.
            tock (float): Scheduling interval in seconds (default ``0.0``).
            **kwa: Additional keyword arguments passed through to the parent
                DoDoer.

        Yields:
            float: ``self.tock`` on each scheduling pause so the Doist
                event-loop can interleave other doers.
        """

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.evts:
                evt = self.evts.popleft()
                src = evt["src"]
                recp = evt["dest"]
                tpc = evt["topic"]
                srdr = evt["serder"]
                atc = evt["attachment"] if "attachment" in evt else None

                # Get the hab of the sender
                if "hab" in evt:
                    hab = evt["hab"]
                else:
                    hab = self.hby.habs[src]

                ends = hab.endsFor(recp)
                try:
                    # If there is a controller, agent or mailbox in ends, send to all
                    if {Roles.controller, Roles.agent, Roles.mailbox} & set(ends):
                        for role in (Roles.controller, Roles.agent, Roles.mailbox):
                            if role in ends:
                                if role == Roles.mailbox:
                                    yield from self.forward(hab, ends[role], recp=recp, serder=srdr, atc=atc, topic=tpc)
                                else:
                                    yield from self.sendDirect(hab, ends[role], serder=srdr, atc=atc)

                    # otherwise send to one witness
                    elif Roles.witness in ends:
                        yield from self.forwardToWitness(hab, ends[Roles.witness], recp=recp, serder=srdr, atc=atc, topic=tpc)
                    else:
                        logger.info(f"No end roles for {recp} to send evt={srdr.said}")
                        continue
                except ConfigurationError as e:
                    logger.error(f"Error sending to {recp} with ends={ends}.  Err={e}")
                    continue
                # Get the kever of the recipient and choose a witness

                self.cues.append(dict(dest=recp, topic=tpc, said=srdr.said))

                yield self.tock

            yield self.tock

    def send(self, dest, topic, serder, src=None, hab=None, attachment=None):
        """Enqueue a KERI event for enveloping and forwarding.

        Builds an event dict from the supplied arguments and appends it to
        ``self.evts`` for asynchronous processing by :meth:`deliverDo`.

        Args:
            dest (str): qb64 identifier prefix of the intended recipient.
            topic (str): Routing topic string used by the recipient's mailbox
                (e.g. ``"delegate"``, ``"credential"``).
            serder (Serder): KERI event to envelope and forward.
            src (str, optional): qb64 identifier prefix of the sender.
                Derived from ``hab.pre`` when omitted.
            hab (Hab, optional): Sender's habitat. Used directly when provided;
                otherwise the hab is looked up from ``self.hby.habs[src]``
                during delivery.
            attachment (bytes, optional): Raw CESR attachment bytes to append
                to the serialised event.
        """
        src = src if src is not None else hab.pre

        evt = dict(src=src, dest=dest, topic=topic, serder=serder)
        if attachment is not None:
            evt["attachment"] = attachment
        if hab is not None:
            evt["hab"] = hab

        self.evts.append(evt)

    def sent(self, said):
        """Return whether a message with the given SAID has been sent.

        Scans ``self.cues`` for a confirmation entry whose ``said`` field
        matches the supplied value.

        Args:
            said (str): qb64 SAID of the message to check.

        Returns:
            bool: ``True`` if a matching delivery confirmation exists in
                ``self.cues``, ``False`` otherwise.
        """

        for cue in self.cues:
            if cue["said"] == said:
                return True

        return False

    def sendEventToDelegator(self, sender, hab, fn=0):
        """Send a KEL event to the delegator and block until send is complete.

        Clones the event at sequence position ``fn`` from the database, queues it
        for delivery to the delegator prefix stored in ``hab.kever.delpre``, and
        yields until a matching cue appears in ``self.cues``.

        Args:
            sender (Hab): Habitat of the sending identifier whose prefix is used
                as the ``src`` for the outbound event.
            hab (Hab): Delegatee habitat whose KEL event is being forwarded to
                the delegator.
            fn (int, optional): First-seen sequence number of the event to
                clone from the database (default ``0``).

        Yields:
            float: ``self.tock`` on each scheduling pause while waiting for the
                delivery confirmation.
        """
        # Send KEL event for processing
        icp = self.hby.db.cloneEvtMsg(pre=hab.pre, fn=fn, dig=hab.kever.serder.saidb)
        ser = SerderKERI(raw=icp)
        del icp[:ser.size]

        self.send(src=sender.pre, dest=hab.kever.delpre, topic="delegate", serder=ser, attachment=icp)
        while True:
            if self.cues:
                cue = self.cues.popleft()
                if cue["said"] == ser.said:
                    break
                else:
                    self.cues.append(cue)
            yield self.tock

    def sendDirect(self, hab, ends, serder, atc):
        """Send a KERI event directly to one or more endpoints for a single role.

        For each prefix in ``ends``, constructs a messenger, enqueues the
        serialised event and any attachment, then yields until the messenger
        becomes idle before removing it.

        Args:
            hab (Hab): Sender's habitat used to authenticate the outbound
                connection.
            ends (dict): Mapping of ``{prefix: {scheme: url}}`` for a single
                role (controller or agent), as returned by a single-role slice
                of ``hab.endsFor``.
            serder (Serder): KERI event to send.
            atc (bytes-like or None): Raw CESR attachment bytes to append to
                the event, or ``None`` if there is no attachment.

        Yields:
            float: ``self.tock`` on each scheduling pause while waiting for the
                messenger to finish sending.
        """
        for ctrl, locs in ends.items():
            witer = messengerFrom(hab=hab, pre=ctrl, urls=locs)

            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)

            witer.msgs.append(bytearray(msg))  # make a copy
            self.extend([witer])

            while not witer.idle:
                _ = (yield self.tock)

            self.remove([witer])

    def forward(self, hab, ends, recp, serder, atc, topic):
        """Wrap a KERI event in a ``/fwd`` ``exn`` envelope and deliver it to a mailbox.

        If this hab is itself one of the mailbox endpoints the message is stored
        locally via ``self.mbx``; ``atc`` may be ``None`` in this path. Otherwise
        a mailbox is chosen at random from ``ends``, ``atc`` is extended onto the
        raw event (must not be ``None`` in this path), a ``/fwd`` exchange message
        is constructed and endorsed, the sender's KEL is prepended via
        :func:`introduce`, and the bundle is dispatched through a messenger.

        Note:
            Unlike :meth:`sendDirect`, the messenger is not removed from the doer
            list after the send completes.

        Args:
            hab (Hab): Sender's habitat used to sign and endorse the forwarded
                envelope.
            ends (dict): Mapping of ``{mailbox_prefix: {scheme: url}}`` for all
                known mailbox endpoints of the recipient.
            recp (str): qb64 identifier prefix of the intended final recipient.
            serder (Serder): KERI event to embed inside the ``/fwd`` envelope.
            atc (bytes-like or None): Raw CESR attachment bytes for the embedded
                event. May be ``None`` only when this hab is itself a mailbox
                endpoint; required to be non-``None`` for the remote send path.
            topic (str): Routing topic placed in the ``/fwd`` envelope modifiers
                (e.g. ``"credential"``, ``"delegate"``).

        Yields:
            float: ``self.tock`` on each scheduling pause while waiting for the
                messenger to finish sending.
        """
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)
            self.mbx.storeMsg(topic=f"{recp}/{topic}".encode("utf-8"), msg=msg)
            return

        # Its not us, randomly select a mailbox and forward it on
        mbx, mailbox = random.choice(list(ends.items()))
        msg = bytearray()
        msg.extend(introduce(hab, mbx))
        # create the forward message with payload embedded at `a` field

        evt = bytearray(serder.raw)
        evt.extend(atc)
        fwd, atc = exchange(route='/fwd', modifiers=dict(pre=recp, topic=topic),
                            payload={}, embeds=dict(evt=evt), sender=hab.pre)
        ims = hab.endorse(serder=fwd, last=False, pipelined=False)

        # Transpose the signatures to point to the new location
        witer = messengerFrom(hab=hab, pre=mbx, urls=mailbox)
        msg.extend(ims)
        msg.extend(atc)

        witer.msgs.append(bytearray(msg))  # make a copy
        self.extend([witer])

        while not witer.idle:
            _ = (yield self.tock)

    def forwardToWitness(self, hab, ends, recp, serder, atc, topic):
        """Wrap a KERI event in a ``/fwd`` ``exn`` envelope and deliver it to a witness.

        Identical in behaviour to :meth:`forward` but operates against witness
        endpoints rather than mailbox endpoints. If this hab is itself one of the
        witness endpoints the message is stored locally via ``self.mbx``; ``atc``
        may be ``None`` in this path. Otherwise a witness is chosen at random from
        ``ends``, ``atc`` is extended onto the raw event (must not be ``None`` in
        this path), a ``/fwd`` exchange message is constructed and endorsed, the
        sender's KEL is prepended via :func:`introduce`, and the bundle is
        dispatched through a messenger.

        Note:
            Unlike :meth:`sendDirect`, the messenger is not removed from the doer
            list after the send completes.

        Args:
            hab (Hab): Sender's habitat used to sign and endorse the forwarded
                envelope.
            ends (dict): Mapping of ``{witness_prefix: {scheme: url}}`` for all
                known witness endpoints of the recipient.
            recp (str): qb64 identifier prefix of the intended final recipient.
            serder (Serder): KERI event to embed inside the ``/fwd`` envelope.
            atc (bytes-like or None): Raw CESR attachment bytes for the embedded
                event. May be ``None`` only when this hab is itself a witness
                endpoint; required to be non-``None`` for the remote send path.
            topic (str): Routing topic placed in the ``/fwd`` envelope modifiers
                (e.g. ``"credential"``, ``"delegate"``).

        Yields:
            float: ``self.tock`` on each scheduling pause while waiting for the
                messenger to finish sending.
        """
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)
            self.mbx.storeMsg(topic=f"{recp}/{topic}".encode("utf-8"), msg=msg)
            return

        # Its not us, randomly select a mailbox and forward it on
        mbx, mailbox = random.choice(list(ends.items()))
        msg = bytearray()
        msg.extend(introduce(hab, mbx))
        # create the forward message with payload embedded at `a` field

        evt = bytearray(serder.raw)
        evt.extend(atc)
        fwd, atc = exchange(route='/fwd', modifiers=dict(pre=recp, topic=topic),
                            payload={}, embeds=dict(evt=evt), sender=hab.pre)
        ims = hab.endorse(serder=fwd, last=False, pipelined=False)

        # Transpose the signatures to point to the new location
        witer = messengerFrom(hab=hab, pre=mbx, urls=mailbox)
        msg.extend(ims)
        msg.extend(atc)

        witer.msgs.append(bytearray(msg))  # make a copy
        self.extend([witer])

        while not witer.idle:
            _ = (yield self.tock)


class StreamPoster:
    """Synchronous poster that batches KERI events into a single stream message
    and delivers them to a fixed recipient.

    Unlike :class:`Poster`, ``StreamPoster`` targets a single recipient
    (``recp``) established at construction time and exposes a synchronous
    :meth:`deliver` method that returns a list of ready-to-run messenger doers
    rather than driving an internal async loop.

    Optionally supports ESSR (Encrypted Streaming Sealed Replies) mode, in
    which outbound message chunks are sealed with the recipient's public key
    before transmission.

    Attributes:
        hab (Hab): Sender's habitat.
        hby (Habery): Database environment.
        recp (str): qb64 identifier prefix of the fixed recipient.
        src (str): qb64 identifier prefix of the sender.
        messagers (list): Accumulated messenger doers produced during delivery.
        mbx (Mailboxer): Optional local mailbox for self-addressed storage.
        topic (str): Default routing topic for forwarded messages.
        headers (dict): Optional HTTP headers forwarded to the stream messenger.
        essr (bool): When ``True``, outbound chunks are ESSR-encrypted.
        evts (Deck): Queue of outbound event dicts.
    """

    def __init__(self, hby, recp, src=None, hab=None, mbx=None, topic=None, headers=None, essr=False, **kwa):
        if hab is not None:
            self.hab = hab
        else:
            self.hab = hby.habs[src]

        self.hby = hby
        self.hab = hab
        self.recp = recp
        self.src = src
        self.messagers = []
        self.mbx = mbx
        self.topic = topic
        self.headers = headers
        self.essr = essr
        self.evts = decking.Deck()

    def deliver(self):
        """Drain ``self.evts`` and return a list of messenger doers ready for scheduling.

        Repeatedly calls :meth:`_chunk` until all queued events have been
        consumed, collecting the messenger doers produced by each chunk.

        Returns:
            list: Messenger doer instances that can be added to a Doist for
                execution.
        """
        doers = []
        while self.evts:
            doers += self._chunk()

        return doers

    def _chunk(self):
        """Consume queued events up to the stream size limit and build a single delivery.

        In ESSR mode, a ``SCS`` payload-type header is prepended and chunk size
        is capped at 16 384 bytes; any event that would exceed the cap is pushed
        back to the front of ``self.evts`` for the next call.  In non-ESSR mode,
        all queued events are concatenated without size restriction.

        The assembled message is then dispatched according to the recipient's
        available end roles (controller/agent → direct; mailbox/witness → forwarded).

        Returns:
            list: Messenger doer instances for this chunk, or an empty list if
                the assembled message is empty or no suitable endpoints exist.
        """
        msg = bytearray()

        if self.essr:
            msg.extend(PayloadTyper(type=PayloadTypes.SCS).qb64b)
            msg.extend(self.hab.kever.prefixer.qb64b)

            # bext field can be randomized to reduce correlation based on packet size, empty for now
            msg.extend(Bexter(bext="").qb64b)

        while self.evts:
            evt = self.evts.popleft()

            serder = evt["serder"]
            atc = evt["attachment"] if "attachment" in evt else b''

            if self.essr and len(msg) + len(serder.raw) + len(atc) > 16384:
                self.evts.appendleft(evt)
                break

            msg.extend(serder.raw)
            msg.extend(atc)

        if len(msg) == 0:
            return []

        ends = self.hab.endsFor(self.recp)
        try:
            # If there is a controller or agent in ends, send to all
            if {Roles.controller, Roles.agent, Roles.mailbox} & set(ends):
                for role in (Roles.controller, Roles.agent, Roles.mailbox):
                    if role in ends:
                        if role == Roles.mailbox:
                            return self.forward(self.hab, ends[role], msg=msg, topic=self.topic)
                        else:
                            return self.sendDirect(self.hab, ends[role], msg=msg)
            # otherwise send to one witness
            elif Roles.witness in ends:
                return self.forward(self.hab, ends[Roles.witness], msg=msg, topic=self.topic)

            else:
                logger.info(f"No end roles for {self.recp} to send evt={self.recp}")
                return []

        except ConfigurationError as e:
            logger.error(f"Error sending to {self.recp} with ends={ends}.  Err={e}")
            return []

    def send(self, serder, attachment=None):
        """Resolve the recipient's endpoints, optionally wrap the event in a
        ``/fwd`` envelope, and enqueue it for delivery.

        Determines whether the event needs to be wrapped (mailbox or witness
        role) by inspecting the recipient's end roles.  If wrapping is required
        :meth:`createForward` is called to produce the signed envelope before
        the event dict is appended to ``self.evts``.

        Args:
            serder (Serder): KERI event to forward.
            attachment (bytes, optional): Raw CESR attachment bytes to include
                with the event, or ``None`` if there is no attachment.

        Raises:
            ValidationError: If no suitable end roles exist for the recipient,
                or if a ``ConfigurationError`` is raised during endpoint
                resolution.
        """
        ends = self.hab.endsFor(self.recp)
        try:
            # If there is a controller, agent or mailbox in ends, send to all
            if {Roles.controller, Roles.agent, Roles.mailbox} & set(ends):
                for role in (Roles.controller, Roles.agent, Roles.mailbox):
                    if role in ends:
                        if role == Roles.mailbox:
                            serder, attachment = self.createForward(self.hab, serder=serder, ends=ends,
                                                                    atc=attachment, topic=self.topic)

            # otherwise send to one witness
            elif Roles.witness in ends:
                serder, attachment = self.createForward(self.hab, ends=ends, serder=serder,
                                                        atc=attachment, topic=self.topic)
            else:
                logger.info(f"No end roles for {self.recp} to send evt={self.recp}")
                raise ValidationError(f"No end roles for {self.recp} to send evt={self.recp}")
        except ConfigurationError as e:
            logger.error(f"Error sending to {self.recp} with ends={ends}.  Err={e}")
            raise ValidationError(f"Error sending to {self.recp} with ends={ends}.  Err={e}")

        evt = dict(serder=serder)
        if attachment is not None:
            evt["attachment"] = attachment

        self.evts.append(evt)

    def sendDirect(self, hab, ends, msg):
        """Create stream messengers for each direct (controller/agent) endpoint.

        In ESSR mode the message is encrypted with the recipient's public key
        via :meth:`_essrWrapper` before being handed to the messenger.  All
        created messengers are also appended to ``self.messagers``.

        Args:
            hab (Hab): Sender's habitat.
            ends (dict): Mapping of ``{prefix: {scheme: url}}`` for each
                controller or agent endpoint.
            msg (bytearray): Serialised event stream to deliver.

        Returns:
            list: Stream messenger instances created for this delivery.
        """
        for ctrl, locs in ends.items():
            ims = self._essrWrapper(hab, msg, ctrl) if self.essr else msg
            self.messagers.append(streamMessengerFrom(hab=hab, pre=ctrl, urls=locs, msg=ims,
                                                               headers=self.headers))

        return self.messagers

    def _essrWrapper(self, hab, msg, ctrl):
        """Encrypt a message stream for the target identifier using ESSR box-seal.

        Resolves the recipient's current verification key (from their kever for
        transferable prefixes, or directly from the prefix for non-transferable
        ones), converts it to a Curve25519 box key, seals the message with
        ``crypto_box_seal``, and returns a signed ``/essr/req`` exchange message
        with the ciphertext appended as an ``ESSRPayloadGroup`` counter group.

        Args:
            hab (Hab): Sender's habitat used to sign the ``/essr/req`` envelope.
            msg (bytearray): Plaintext message stream to encrypt.
            ctrl (str): qb64 identifier prefix of the intended recipient.

        Returns:
            bytearray: Signed ``/essr/req`` exchange message with the
                ESSR payload group and ciphertext appended.
        """
        prefixer = Prefixer(qb64=ctrl)
        if prefixer.code in NonTransDex:  # e.g. witness mbx
            verfer = Verfer(qb64=ctrl)
        else:
            rkever = self.hby.kevers[ctrl]
            verfer = rkever.verfers[0]

        pubkey = pysodium.crypto_sign_pk_to_box_pk(verfer.raw)
        raw = pysodium.crypto_box_seal(bytes(msg), pubkey)

        texter = Texter(raw=raw)
        diger = Diger(ser=raw, code=MtrDex.Blake3_256)
        essr, _ = exchange(route='/essr/req', sender=hab.pre, diger=diger,
                           modifiers=dict(src=hab.pre, dest=ctrl))
        ims = hab.endorse(serder=essr, pipelined=False)
        ims.extend(Counter(Codens.ESSRPayloadGroup, count=1,
                           gvrsn=Vrsn_1_0).qb64b)
        ims.extend(texter.qb64b)
        return ims

    def createForward(self, hab, ends, serder, atc, topic):
        """Build and sign a ``/fwd`` exchange envelope for the given event.

        If this hab is itself one of the destination endpoints (determined by
        intersecting ``ends.keys()`` with ``hab.prefixes``), the raw event is
        stored locally in ``self.mbx`` and ``(None, None)`` is returned.
        Otherwise a ``/fwd`` exchange message is created with ``self.recp`` and
        ``topic`` in the modifiers, the event embedded under the ``evt`` key in
        the ``e`` field, and the bundle endorsed by ``hab``.

        Args:
            hab (Hab): Sender's habitat used to endorse the forward envelope.
            ends (dict): Mapping of endpoint prefixes to URL location dicts;
                only the keys are used to determine whether this hab is a local
                endpoint.
            serder (Serder): KERI event to embed inside the ``/fwd`` envelope.
            atc (bytes-like or None): Raw CESR attachment bytes for the embedded
                event. May be ``None`` only when storing locally; must be
                non-``None`` for the remote build path.
            topic (str): Routing topic placed in the ``/fwd`` envelope modifiers.

        Returns:
            tuple: ``(fwd_serder, ims)`` where ``fwd_serder`` is the ``/fwd``
                Serder and ``ims`` is the endorsed message concatenated with the
                exchange's own attachment bytes, or ``(None, None)`` when the
                message was stored locally.
        """
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)
            self.mbx.storeMsg(topic=f"{self.recp}/{topic}".encode("utf-8"), msg=msg)
            return None, None

        # Its not us, randomly select a mailbox and forward it on
        evt = bytearray(serder.raw)
        evt.extend(atc)
        fwd, atc = exchange(route='/fwd', modifiers=dict(pre=self.recp, topic=topic),
                            payload={}, embeds=dict(evt=evt), sender=hab.pre)
        ims = hab.endorse(serder=fwd, last=False, pipelined=False)
        return fwd, ims + atc

    def forward(self, hab, ends, msg, topic):
        """Deliver a pre-assembled stream message to a mailbox or witness endpoint.

        If this hab is itself one of the destination endpoints the message is
        stored locally (stripping any ESSR header fields first in ESSR mode).
        Otherwise a random endpoint is chosen from ``ends``, the sender's KEL
        is prepended via :func:`introduce`, the message is optionally ESSR-
        encrypted via :meth:`_essrWrapper`, and a stream messenger is created
        and appended to ``self.messagers``.

        Args:
            hab (Hab): Sender's habitat.
            ends (dict): Mapping of ``{endpoint_prefix: {scheme: url}}`` for
                all known mailbox or witness endpoints.
            msg (bytearray): Pre-assembled serialised event stream to deliver.
            topic (str): Routing topic used when storing locally in ``self.mbx``.

        Returns:
            list: Stream messenger instances created for this delivery, or an
                empty list if the message was stored locally.
        """
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            # Remove again if ESSR mode
            if self.essr:
                _tag = self.hby.psr.extract(msg, PayloadTyper)
                _pre = self.hby.psr.extract(msg, Prefixer)
                _pad = self.hby.psr.extract(msg, Bexter)
            self.mbx.storeMsg(topic=f"{self.recp}/{topic}".encode("utf-8"), msg=msg)
            return []

        # Its not us, randomly select a mailbox and forward it on
        mbx, mailbox = random.choice(list(ends.items()))

        if self.essr:
            msg = self._essrWrapper(hab, msg, mbx)

        ims = bytearray()
        ims.extend(introduce(hab, mbx))
        ims.extend(msg)

        self.messagers.append(streamMessengerFrom(hab=hab, pre=mbx, urls=mailbox, msg=bytes(ims)))
        return self.messagers


class ForwardHandler:
    """Handler for ``/fwd`` ``exn`` messages that act as a store-and-forward mailbox.

    Receives a ``/fwd`` exchange message whose ``q`` modifiers carry the
    intended recipient prefix and topic, extracts each embedded SAD from the
    ``e`` field together with its CESR attachments, and writes the reconstituted
    event stream to the local mailbox under the key ``"{recipient}/{topic}"``.

    Example ``/fwd`` message structure::

        {
           "v": "KERI10JSON00011c_",
           "t": "exn",
           "dt": "2020-08-22T17:50:12.988921+00:00",
           "r": "/fwd",
           "q": {
              "pre": "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",
              "topic": "delegate"
            },
           "e": {
              "v": "KERI10JSON000154_",
              "t": "dip",
              ...
           }
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    Attributes:
        hby (Habery): Database environment.
        mbx (Mailboxer): Mailbox used to persist forwarded messages.
    """

    resource = "/fwd"

    def __init__(self, hby, mbx):
        """Initialise the ForwardHandler.

        Args:
            hby (Habery): Database environment used for identifier resolution.
            mbx (Mailboxer): Mailbox storage backend for persisting forwarded
                messages.
        """
        self.hby = hby
        self.mbx = mbx

    def handle(self, serder, attachments=None):
        """Process an incoming ``/fwd`` exchange message and store its payload.

        Reads the ``q`` modifiers to determine the recipient and topic, then
        iterates over the path/attachment pairs in ``attachments`` to reconstruct
        each embedded SAD.  The reconstituted events are concatenated and stored
        in ``self.mbx`` under the key ``"{recipient}/{topic}"``.

        Args:
            serder (Serder): Serder of the incoming ``/fwd`` ``exn`` message.
            attachments (list, optional): List of ``(Pather, atc_bytes)`` tuples
                where each ``Pather`` resolves a path into the ``e`` embed field
                and ``atc_bytes`` are the corresponding CESR SAD path attachments.
        """

        embeds = serder.ked['e']
        modifiers = serder.ked['q'] if 'q' in serder.ked else {}

        recipient = modifiers["pre"]
        topic = modifiers["topic"]
        resource = f"{recipient}/{topic}"

        pevt = bytearray()
        for pather, atc in attachments:
            ked = pather.resolve(embeds)
            sadder = Sadder(ked=ked, kind=Kinds.json)
            pevt.extend(sadder.raw)
            pevt.extend(atc)

        if not pevt:
            print("error with message, nothing to forward", serder.ked)
            return

        self.mbx.storeMsg(topic=resource, msg=pevt)


def introduce(hab, wit):
    """Return the cloned KEL of ``hab`` if ``wit`` has not yet receipted its
    latest event.

    Checks whether ``wit`` has issued a receipt (transferable: vrc; non-transferable:
    rct) for the current establishment event of ``hab``.  If no such receipt is
    found the full KEL is cloned and returned so it can be transmitted to ``wit``
    as part of a forwarding bundle.  If ``wit`` is already one of ``hab``'s
    witnesses an empty bytearray is returned immediately, since that witness
    is assumed to have the KEL already.

    Args:
        hab (Hab): Local environment for the identifier whose KEL may be
            propagated.
        wit (str): qb64 identifier prefix of the potential receipt target.

    Returns:
        bytearray: Cloned KEL of ``hab`` (including any delegation event and
            end-role reply) when ``wit`` has not yet receipted the latest event,
            or an empty bytearray if no KEL transmission is needed.
    """
    msgs = bytearray()
    if wit in hab.kever.wits:
        return msgs

    iserder = hab.kever.serder
    witPrefixer = Prefixer(qb64=wit)
    dgkey = dgKey(wit, iserder.said)
    found = False
    if witPrefixer.transferable:  # find if have rct from other pre for own icp
        for sprefixer, snum, sdiger, siger in hab.db.vrcs.getIter(dgkey):
            # Receipt is from this hab if the prefix matches
            if sprefixer.qb64 == hab.pre:
                found = True
    else:  # find if already rcts of own icp
        for prefixer, cigar in hab.db.rcts.getIter(dgkey):
            if prefixer.qb64.startswith(hab.pre):
                found = True  # yes so don't send own inception

    if not found:  # no receipt from remote so send own inception
        # no vrcs or rct of own icp from remote so send own inception
        for msg in hab.db.clonePreIter(pre=hab.pre):
            msgs.extend(msg)
        for msg in hab.db.cloneDelegation(hab.kever):
            msgs.extend(msg)
        msgs.extend(hab.replyEndRole(cid=hab.pre))
    return msgs
