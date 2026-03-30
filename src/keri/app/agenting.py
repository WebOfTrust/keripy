# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import random
from urllib.parse import urlparse, urljoin

from hio.base import doing
from hio.core import http
from hio.core.tcp import clienting
from hio.help import decking, Hict, ogler

from socket import gaierror

from .httping import Clienter, streamCESRRequests, CESR_DESTINATION_HEADER

from ..kering import (Schemes, Roles, Vrsn_1_0,
                      MissingEntryError, ConfigurationError,
                      MissingEntryError)
from ..core import Counter, eventing, parsing, coring, serdering, Codens


logger = ogler.getLogger()


class Receiptor(doing.DoDoer):
    """Orchestrates witness receipt retrieval for KEL events.

    Manages both initial receipt submission to witnesses and subsequent
    querying of receipts for specific events. Spawns internal doers for
    processing outbound event messages and querying existing receipts.
    """

    def __init__(self, hby, msgs=None, gets=None, cues=None):
        """Initializes the Receiptor and creates doers for processing and retrieving witness receipts.

        Args:
            hby (Habery): Provides access to local identifiers and their associated
                witness configurations.
            msgs (Deck, optional): Inbound queue of KEL events to submit to witnesses
                for receipting. Each entry must contain ``{"pre": str, "sn": int, "auths": dict}``.
            gets (Deck, optional): Inbound queue of receipt queries to dispatch to
                witnesses. Each entry must contain ``{"pre": str, "sn": int}``.
            cues (Deck, optional): Outbound queue onto which completed events are pushed.
                Not currently consumed by any downstream component.
        """
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.gets = gets if gets is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.clienter = Clienter()

        doers = [self.clienter, doing.doify(self.witDo), doing.doify(self.gitDo)]
        self.hby = hby

        super(Receiptor, self).__init__(doers=doers)

    def receipt(self, pre, sn=None, auths=None):
        """Submits a KEL event to all witnesses and propagates collected receipts.

        Submits the designated event to each witness via the synchronous witness
        API, collects their receipts, and propagates each witness's receipt to all
        other witnesses. Also catches up any newly-added witnesses via
        :meth:`catchup` when processing rotation events.

        Args:
            pre (str): Qualified base64 identifier prefix to gather receipts for.
            sn (int, optional): Sequence number of the event to receipt. Defaults to
                the latest sequence number for the identifier.
            auths (dict, optional): Map of witness AIDs to ``(time, auth)`` tuples
                for TOTP-based witness authentication.

        Yields:
            float: ``self.tock`` to cede control while waiting for HTTP responses.

        Returns:
            dict_keys: Identifiers of witnesses that returned receipts.

        Raises:
            MissingEntryError: If ``pre`` is not a locally managed identifier.
        """
        auths = auths if auths is not None else dict()
        if pre not in self.hby.prefixes:
            raise MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        sn = sn if sn is not None else hab.kever.sner.num
        wits = hab.kever.wits

        if len(wits) == 0:
            return

        msg = hab.makeOwnEvent(sn=sn)
        ser = serdering.SerderKERI(raw=msg)

        # If we are a rotation event, may need to catch new witnesses up to current key state
        if ser.ked['t'] in (coring.Ilks.rot,):
            adds = ser.ked["ba"]
            for wit in adds:
                yield from self.catchup(ser.pre, wit)

        clients = dict()
        doers = []
        for wit in wits:
            try:
                client, clientDoer = httpClient(hab, wit)
                clients[wit] = client
                doers.append(clientDoer)
                self.extend([clientDoer])
            except (MissingEntryError, gaierror) as e:
                logger.error(f"unable to create http client for witness {wit}: {e}")

        # send to each witness and gather receipts
        rcts = dict()
        for wit, client in clients.items():
            headers = dict()
            if wit in auths:
                headers["Authorization"] = auths[wit]

            streamCESRRequests(client=client, dest=wit, ims=bytearray(msg), path="/receipts", headers=headers)
            while not client.responses:
                yield self.tock

            rep = client.respond()
            if rep.status == 200:
                rct = bytearray(rep.body)
                hab.psr.parseOne(bytearray(rct))
                rserder = serdering.SerderKERI(raw=rct)
                del rct[:rserder.size]

                # pull off the count code
                Counter(qb64b=rct, strip=True, version=Vrsn_1_0)
                rcts[wit] = rct
            else:
                print(f"invalid response {rep.status} from witnesses {wit}")

        # send retrieved receipts to all other witnesses
        for wit in rcts:
            ewits = [w for w in rcts if w != wit] # get complement of all other witnesses
            wigers = [rcts[w] for w in ewits] # all other witness signatures

            msg = bytearray()
            if ser.ked['t'] in (coring.Ilks.icp, coring.Ilks.dip):  # introduce new witnesses
                msg.extend(schemes(self.hby.db, eids=ewits))
            elif ser.ked['t'] in (coring.Ilks.rot, coring.Ilks.drt) and \
                    ("ba" in ser.ked and wit in ser.ked["ba"]):  # Newly added witness, introduce to all
                msg.extend(schemes(self.hby.db, eids=ewits))

            rserder = eventing.receipt(pre=hab.pre,
                                       sn=sn,
                                       said=ser.said)
            msg.extend(rserder.raw)
            msg.extend(Counter(Codens.NonTransReceiptCouples,
                                    count=len(wigers), version=Vrsn_1_0).qb64b)
            for wiger in wigers:
                msg.extend(wiger)

            client = clients[wit]

            sent = streamCESRRequests(client=client, dest=wit, ims=bytearray(msg))
            while len(client.responses) < sent:
                yield self.tock

        self.remove(doers)

        return rcts.keys()

    def get(self, pre, sn=None):
        """Queries a randomly selected witness for a specific event receipt.

        Args:
            pre (str): Qualified base64 identifier prefix to retrieve a receipt for.
            sn (int, optional): Sequence number of the event. Defaults to the latest
                sequence number for the identifier.

        Yields:
            float: ``self.tock`` to cede control while waiting for HTTP responses.

        Returns:
            bool: ``True`` if the witness responded with HTTP 200, ``False`` otherwise.

        Raises:
            MissingEntryError: If ``pre`` is not a locally managed identifier, or if
                the selected witness has no resolvable HTTP endpoint.
        """
        if pre not in self.hby.prefixes:
            raise MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        sn = sn if sn is not None else hab.kever.sner.num
        wits = hab.kever.wits

        if len(wits) == 0:
            return

        wit = random.choice(hab.kever.wits)
        urls = hab.fetchUrls(eid=wit, scheme=Schemes.https) or hab.fetchUrls(eid=wit, scheme=Schemes.http)
        if not urls:
            raise MissingEntryError(f"unable to query witness {wit}, no http endpoint")

        base = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
        url = urljoin(base, f"/receipts?pre={pre}&sn={sn}")

        client = self.clienter.request("GET", url)
        while not client.responses:
            yield self.tock

        rep = client.respond()
        if rep.status == 200:
            rct = bytearray(rep.body)
            hab.psr.parseOne(bytearray(rct))

        self.clienter.remove(client)
        return rep.status == 200

    def catchup(self, pre, wit):
        """Sends the full KEL for a prefix to a single witness to bring it up to date.

        Intended for use when a new witness is added via rotation. Iterates through
        all events in the local KEL and streams each to the target witness over HTTP.

        Args:
            pre (str): Qualified base64 AID of the KEL to send.
            wit (str): Qualified base64 AID of the witness to receive the KEL.

        Yields:
            float: ``self.tock`` to cede control while waiting for HTTP responses.

        Raises:
            MissingEntryError: If ``pre`` is not a locally managed identifier.
        """
        if pre not in self.hby.prefixes:
            raise MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]

        client, clientDoer = httpClient(hab, wit)
        self.extend([clientDoer])

        for fmsg in hab.db.clonePreIter(pre=pre):
            streamCESRRequests(client=client, dest=wit, ims=bytearray(fmsg))
            while not client.responses:
                yield self.tock

        self.remove([clientDoer])

    def witDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that drains the ``msgs`` queue and submits each event for receipting.

        Processes one message at a time from ``self.msgs``, delegates to
        :meth:`receipt`, and pushes completed messages onto ``self.cues``.
        Intended to be wrapped with :func:`doing.doify`.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control each cycle.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pre = msg["pre"]
                sn = msg["sn"] if "sn" in msg else None
                auths = msg["auths"] if "auths" in msg else None

                yield from self.receipt(pre, sn, auths)
                self.cues.push(msg)

            yield self.tock

    def gitDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that drains the ``gets`` queue and queries witnesses for receipts.

        Processes one query message at a time from ``self.gets`` and delegates
        to :meth:`get`. Intended to be wrapped with :func:`doing.doify`.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control each cycle.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.gets:
                msg = self.gets.popleft()
                pre = msg["pre"]
                sn = msg["sn"] if "sn" in msg else None

                yield from self.get(pre, sn)

            yield self.tock


class WitnessReceiptor(doing.DoDoer):
    """Receipts queued key events across all current witnesses and propagates the results.

    For each event in ``msgs``, sends the event to every current witness, waits until
    all witnesses have returned receipts, then distributes each witness's receipt to
    all other witnesses. Newly added witnesses (inception/rotation) are caught up with
    the full KEL before receipting. Runs continuously, processing new events as they
    arrive.

    Can be extended to support a ``once``/``all`` interface for single-shot operation.
    """

    def __init__(self, hby, msgs=None, cues=None, force=False, auths=None, **kwa):
        """Initializes the WitnessReceiptor with event queue and propagation options.

        Args:
            hby (Habery): Habery containing the identifier whose witnesses will be
                receipted.
            msgs (Deck, optional): Incoming events to receipt and propagate. Each
                message dict must contain ``{"pre": str, "sn": int, "auths": dict}``.
            cues (Deck, optional): Outgoing cues for events confirmed as fully
                receipted. Messages have the same shape as ``msgs`` entries.
            force (bool, optional): When ``True``, re-sends all receipts to witnesses
                even if a full complement already exists. Defaults to ``False``.
            auths (dict, optional): Map of witness AIDs to ``(time, auth)`` tuples
                for TOTP-based witness authentication.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.
        """
        self.hby = hby
        self.force = force
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.auths = auths if auths is not None else dict()

        super(WitnessReceiptor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)

    def receiptDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that sends events and receipts to each witness and waits for completion.

        For each event in ``self.msgs``: sends the event to every current witness,
        waits until all witnesses have returned receipts, then distributes each
        witness's receipt to all other witnesses along with location introduction
        messages where required (inception/rotation).

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` or ``1.0`` to cede control while waiting for
                witnesses to become idle or receipts to arrive.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                evt = self.msgs.popleft()
                pre = evt["pre"]

                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]

                sn = evt["sn"] if "sn" in evt else hab.kever.sner.num
                wits = hab.kever.wits

                if len(wits) == 0:
                    continue

                msg = hab.makeOwnEvent(sn=sn)
                ser = serdering.SerderKERI(raw=msg)

                witers = []
                for wit in wits:
                    auth = self.auths[wit] if wit in self.auths else None
                    witer = messenger(hab, wit, auth=auth)
                    witers.append(witer)
                    self.extend([witer])

                # Check to see if we already have all the receipts we need for this event
                wigers = hab.db.wigs.get(keys=(ser.preb, ser.saidb))
                completed = len(wigers) == len(wits)
                if len(wigers) != len(wits):  # We have all the receipts, skip
                    for idx, witer in enumerate(witers):
                        wit = wits[idx]

                        for dmsg in hab.db.cloneDelegation(hab.kever):
                            witer.msgs.append(bytearray(dmsg))

                        if ser.ked['t'] in (coring.Ilks.icp, coring.Ilks.dip) or \
                                "ba" in ser.ked and wit in ser.ked["ba"]:  # Newly added witness, must send full KEL to catch up
                            for fmsg in hab.db.clonePreIter(pre=pre):
                                witer.msgs.append(bytearray(fmsg))

                        witer.msgs.append(bytearray(msg))  # make a copy
                        _ = (yield self.tock)

                    while True:
                        wigers = hab.db.wigs.get(keys=(ser.preb, ser.saidb))
                        if len(wigers) == len(wits):
                            break
                        _ = yield self.tock

                # If we started with all our receipts, exit unless told to force resubmit of all receipts
                if completed and not self.force:
                    self.cues.push(evt)
                    continue

                # generate all rct msgs to send to all witnesses
                awigers = wigers

                # make sure all witnesses have fully receipted KERL and know about each other
                for witer in witers:
                    ewits = []
                    wigers = []
                    for i, wit in enumerate(wits):
                        if wit == witer.wit:
                            continue
                        ewits.append(wit)
                        wigers.append(awigers[i])

                    if len(wigers) == 0:
                        continue

                    rctMsg = bytearray()

                    # Now that the witnesses have not met each other, send them each other's receipts
                    if ser.ked['t'] in (coring.Ilks.icp, coring.Ilks.dip):  # introduce new witnesses
                        rctMsg.extend(schemes(self.hby.db, eids=ewits))
                    elif ser.ked['t'] in (coring.Ilks.rot, coring.Ilks.drt) and \
                            ("ba" in ser.ked and witer.wit in ser.ked["ba"]):  # Newly added witness, introduce to all
                        rctMsg.extend(schemes(self.hby.db, eids=ewits))

                    rserder = eventing.receipt(pre=ser.pre,
                                               sn=sn,
                                               said=ser.said)
                    rctMsg.extend(eventing.messagize(serder=rserder, wigers=wigers))

                    witer.msgs.append(rctMsg)
                    _ = (yield self.tock)

                while True:
                    done = True
                    for witer in witers:
                        if not witer.idle:
                            yield 1.0
                            done = False
                            break
                    if done:
                        break

                self.remove(witers)

                self.cues.push(evt)
                yield self.tock

            yield self.tock


class WitnessInquisitor(doing.DoDoer):
    """Sends KEL and TEL query messages to witnesses, controllers, or agents.

    Selects query targets from locally available endpoint role records. Sends
    to a random witness when no KEL is known for the target prefix, or to a
    controller/agent endpoint when one is available. Exits once each queued
    message has been dispatched.

    Note:
        May be renamed in a future release to reflect that multiple endpoint
        role types (controller, agent, witness) are supported as query targets.
    """

    def __init__(self, hby, msgs=None, klas=None, **kwa):
        """Initializes the WitnessInquisitor with context, message queue, and messenger class.

        Args:
            hby (Habery): Habery context used to retrieve the source Hab for reading
                endpoint role records.
            msgs (Deck, optional): Query message buffer. Each message is dispatched to
                the appropriate target or a randomly selected witness.
            klas (type, optional): Messenger class used to send outbound messages.
                Defaults to :class:`HTTPMessenger`. Currently unused.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.
        """
        self.hby = hby
        self.klas = klas if klas is not None else HTTPMessenger
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = decking.Deck()

        super(WitnessInquisitor, self).__init__(doers=[doing.doify(self.msgDo)], **kwa)

    def msgDo(self, tymth=None, tock=1.0, **opts):
        """Doer generator that signs and dispatches query messages from the ``msgs`` queue.

        Selects a target endpoint from local role records (controller > agent > witness
        priority) or from the explicitly provided witness list. Introduces the source
        hab to the target witness before sending the query message.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``1.0``.
            **opts: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control while waiting for the messenger to
                confirm the message was sent.
        """
        from .forwarding import introduce
        
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.msgs:
                yield self.tock

            evt = self.msgs.popleft()
            pre = evt["pre"]
            target = evt["target"]
            src = evt["src"]
            r = evt["r"]
            q = evt["q"]
            wits = evt["wits"] if "wits" in evt else None

            if "hab" in evt:
                hab = evt["hab"]
            elif (hab := self.hby.habByPre(src)) is None:
                continue

            if not wits and pre not in self.hby.kevers:
                logger.error(f"must have KEL for identifier to query {pre}")
                continue

            if not wits:
                ends = hab.endsFor(pre=pre)
                if Roles.controller in ends:
                    end = ends[Roles.controller]
                elif Roles.agent in ends:
                    end = ends[Roles.agent]
                elif Roles.witness in ends:
                    end = ends[Roles.witness]
                else:
                    logger.error(f"unable query: can not find a valid role for {pre}")
                    continue

                if len(end.items()) == 0:
                    logger.error(f"must have endpoint to query for pre={pre}")
                    continue

                ctrl, locs = random.choice(list(end.items()))
                if len(locs.items()) == 0:
                    logger.error(f"must have location in endpoint to query for pre={pre}")
                    continue

                witer = messengerFrom(hab=hab, pre=ctrl, urls=locs)
            else:
                wit = random.choice(wits)
                witer = messenger(hab, wit)

            self.extend([witer])

            msg = hab.query(target, src=witer.wit, route=r, query=q)  # Query for remote pre Event

            kel = introduce(hab, witer.wit)
            if kel:
                witer.msgs.append(bytearray(kel))

            witer.msgs.append(bytearray(msg))

            while not witer.sent:
                yield self.tock

            self.sent.append(witer.sent.popleft())

            yield self.tock

    def query(self, pre, r="logs", sn='0', fn='0', src=None, hab=None, anchor=None, wits=None, **kwa):
        """Enqueues a KEL query message for the given prefix onto ``self.msgs``.

        Constructs a ``qry`` message targeting ``pre`` and appends it to the internal
        message queue for processing by :meth:`msgDo`.

        Args:
            pre (str): Qualified base64 identifier prefix being queried for.
            r (str, optional): Query route. Defaults to ``"logs"``.
            sn (str, optional): Hex string of the sequence number to query for.
                Defaults to ``"0"``.
            fn (str, optional): Hex string of the first sequence number to start from.
                Defaults to ``"0"``.
            src (str, optional): Qualified base64 identifier prefix of the query source.
            hab (Hab, optional): Hab to use for signing and endpoint role lookups,
                in place of resolving ``src``.
            anchor (Seal, optional): Anchored seal to include in the query.
            wits (list, optional): Explicit list of witness AIDs to query.
            **kwa: Absorbed for forward compatibility.
        """
        qry = dict(s=sn, fn=fn)
        if anchor is not None:
            qry["a"] = anchor

        msg = dict(src=src, pre=pre, target=pre, r=r, q=qry, wits=wits)
        if hab is not None:
            msg["hab"] = hab

        self.msgs.append(msg)

    def telquery(self, ri, src=None, i=None, r="tels", hab=None, pre=None, wits=None, **kwa):
        """Enqueues a TEL query message for the given registry onto ``self.msgs``.

        Constructs a TEL query targeting registry ``ri`` and appends it to the internal
        message queue for processing by :meth:`msgDo`.

        Args:
            ri (str): Qualified base64 identifier prefix of the registry being queried.
            src (str, optional): Qualified base64 identifier prefix of the query source.
            i (str, optional): Qualified base64 identifier prefix of the registry issuer.
            r (str, optional): Query route. Defaults to ``"tels"``.
            hab (Hab, optional): Hab to use for signing and endpoint role lookups,
                in place of resolving ``src``.
            pre (str, optional): Qualified base64 identifier prefix of the query target.
            wits (list, optional): Explicit list of witness AIDs to query.
            **kwa: Absorbed for forward compatibility.
        """
        qry = dict(ri=ri)
        msg = dict(src=src, pre=pre, target=i, r=r, wits=wits, q=qry)
        if hab is not None:
            msg["hab"] = hab

        self.msgs.append(msg)


class WitnessPublisher(doing.DoDoer):
    """Sends an arbitrary message to all current witnesses of an identifier and exits.

    Exits cleanly once every current witness has received the message. Can be
    enhanced to support continuous operation via a dedicated ``once``/``all``
    interface.
    """

    def __init__(self, hby, msgs=None, cues=None, **kwa):
        """Initializes the WitnessPublisher with publish queue and completion cues.

        Args:
            hby (Habery): Habery containing the identifier whose witnesses will be
                published to.
            msgs (Deck, optional): Incoming messages to broadcast to all witnesses.
                Each message dict must contain ``{"pre": str, "msg": bytes}``.
            cues (Deck, optional): Outgoing cues signalling successful delivery.
                Each entry mirrors the corresponding ``msgs`` entry.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.
        """
        self.hby = hby
        self.posted = 0
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        super(WitnessPublisher, self).__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **opts):
        """Doer generator that drains the ``msgs`` queue and broadcasts each message to all witnesses.

        For each queued message, creates a messenger per witness, sends a copy of
        the message to each, waits for all messengers to become idle, then pushes
        the original event to ``self.cues``.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **opts: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control while waiting for messengers to finish.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                evt = self.msgs.popleft()
                self.posted += 1
                pre = evt["pre"]
                msg = evt["msg"]

                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]
                wits = hab.kever.wits

                witers = []
                for wit in wits:
                    witer = messenger(hab, wit)
                    witers.append(witer)
                    witer.msgs.append(bytearray(msg))  # make a copy so everyone munges their own
                    self.extend([witer])

                    _ = (yield self.tock)

                while witers:
                    witer = witers.pop()
                    while not witer.idle:
                        _ = (yield self.tock)

                self.remove(witers)
                self.cues.push(evt)

                yield self.tock

            yield self.tock

    def sent(self, said):
        """Returns whether the message with the given SAID has been delivered.

        Args:
            said (str): Qualified base64 SAID of the message to check.

        Returns:
            bool: ``True`` if a cue with the matching SAID is present, ``False``
                otherwise.
        """
        for cue in self.cues:
            if cue["said"] == said:
                return True

        return False

    @property
    def idle(self):
        """bool: ``True`` if all posted messages have completed delivery."""
        return len(self.msgs) == 0 and self.posted == len(self.cues)


class TCPMessenger(doing.DoDoer):
    """Sends outbound CESR messages to a witness via TCP and parses inbound receipts."""

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, **kwa):
        """Initializes the TCPMessenger with queues, a Kevery, and the receipt doer.

        Args:
            hab (Hab): Habitat for KEL parsing and database access.
            wit (str): Qualified base64 witness identifier.
            url (str): TCP endpoint URL for the witness (must use the ``tcp`` scheme).
            msgs (Deck, optional): Outbound message queue.
            sent (Deck, optional): Queue of successfully sent messages.
            doers (list, optional): Additional doers to compose into this DoDoer.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.
        """
        self.hab = hab
        self.wit = wit
        self.url = url
        self.posted = 0
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.receiptDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      **kwa)

        super(TCPMessenger, self).__init__(doers=doers)

    def receiptDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that connects to the witness over TCP and sends queued messages.

        Establishes a TCP connection, wires up a :class:`parsing.Parser` for inbound
        data, and drains ``self.msgs``, transmitting each message and waiting for the
        send buffer to flush before appending to ``self.sent``.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control while waiting for the send buffer
                to flush or for new messages to arrive.

        Raises:
            ValueError: If the URL scheme is not ``tcp``.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        up = urlparse(self.url)
        if up.scheme != Schemes.tcp:
            raise ValueError(f"invalid scheme {up.scheme} for TcpWitnesser")

        client = clienting.Client(host=up.hostname, port=up.port)
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     version=Vrsn_1_0)

        clientDoer = clienting.ClientDoer(client=client)
        self.extend([clientDoer, doing.doify(self.msgDo)])

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()
            self.posted += 1

            client.tx(msg)  # send to connected remote

            while client.txbs:
                yield self.tock

            self.sent.append(msg)
            yield self.tock

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Doer generator that continuously parses inbound TCP messages into the Kevery.

        Args:
            tymth (callable, optional): Unused; present for doer framework compatibility.
            tock (float, optional): Unused; present for doer framework compatibility.
            **opts: Absorbed keyword arguments.

        Yields:
            Delegates entirely to :meth:`parsing.Parser.parsator`.
        """
        yield from self.parser.parsator(local=True)  # process messages continuously

    @property
    def idle(self):
        """bool: ``True`` if all posted messages have been sent."""
        return len(self.sent) == self.posted


class TCPStreamMessenger(doing.DoDoer):
    """Streams a single CESR message to a witness via TCP and parses inbound receipts."""

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, **kwa):
        """Initializes the TCPStreamMessenger with queues, a Kevery, and the receipt doer.

        Args:
            hab (Hab): Habitat for KEL parsing and database access.
            wit (str): Qualified base64 witness identifier.
            url (str): TCP endpoint URL for the witness (must use the ``tcp`` scheme).
            msgs (Deck, optional): Outbound message queue.
            sent (Deck, optional): Queue of successfully sent messages.
            doers (list, optional): Additional doers to compose into this DoDoer.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.
        """
        self.hab = hab
        self.wit = wit
        self.url = url
        self.posted = 0
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.receiptDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      **kwa)

        super(TCPStreamMessenger, self).__init__(doers=doers)

    def receiptDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that connects to the witness over TCP and sends queued messages.

        Establishes a TCP connection, wires up a :class:`parsing.Parser` for inbound
        data, and drains ``self.msgs``, transmitting each and waiting for the send
        buffer to flush before appending to ``self.sent``.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control while waiting for the send buffer
                to flush or for new messages to arrive.

        Raises:
            ValueError: If the URL scheme is not ``tcp``.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        up = urlparse(self.url)
        if up.scheme != Schemes.tcp:
            raise ValueError(f"invalid scheme {up.scheme} for TcpWitnesser")

        client = clienting.Client(host=up.hostname, port=up.port)
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     version=Vrsn_1_0)

        clientDoer = clienting.ClientDoer(client=client)
        self.extend([clientDoer, doing.doify(self.msgDo)])

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()
            self.posted += 1

            client.tx(msg)  # send to connected remote

            while client.txbs:
                yield self.tock

            self.sent.append(msg)
            yield self.tock

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Doer generator that continuously parses inbound TCP messages into the Kevery.

        Args:
            tymth (callable, optional): Unused; present for doer framework compatibility.
            tock (float, optional): Unused; present for doer framework compatibility.
            **opts: Absorbed keyword arguments.

        Yields:
            Delegates entirely to :meth:`parsing.Parser.parsator`.
        """
        yield from self.parser.parsator(local=True)  # process messages continuously

    @property
    def idle(self):
        """bool: ``True`` if all posted messages have been sent."""
        return len(self.sent) == self.posted


class HTTPMessenger(doing.DoDoer):
    """Sends CESR messages to a witness over HTTP and captures responses."""

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, auth=None, **kwa):
        """Initializes the HTTPMessenger with queues, an HTTP client, and optional auth.

        Args:
            hab (Hab): Habitat for KEL parsing and database access.
            wit (str): Qualified base64 witness identifier.
            url (str): HTTP or HTTPS endpoint URL for the witness.
            msgs (Deck, optional): Outbound message queue.
            sent (Deck, optional): Queue of HTTP response objects.
            doers (list, optional): Additional doers to compose into this DoDoer.
            auth (str, optional): Authorization header value for TOTP-based witness
                authentication.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.

        Raises:
            ValueError: If the URL scheme is neither ``http`` nor ``https``.
        """
        self.hab = hab
        self.wit = wit
        self.posted = 0
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        self.auth = auth
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo), doing.doify(self.responseDo)])

        up = urlparse(url)
        if up.scheme != Schemes.http and up.scheme != Schemes.https:
            raise ValueError(f"invalid scheme {up.scheme} for HTTPMessenger")

        self.client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        doers.extend([clientDoer])

        super(HTTPMessenger, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that drains the ``msgs`` queue and streams each message over HTTP.

        Attaches an ``Authorization`` header when ``self.auth`` is set.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            float: ``self.tock`` to cede control while the HTTP client flushes pending
                requests or while the queue is empty.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()
            headers = dict()
            if self.auth is not None:
                headers["Authorization"] = self.auth

            self.posted += streamCESRRequests(client=self.client, dest=self.wit, ims=msg, headers=headers)
            while self.client.requests:
                yield self.tock

            yield self.tock

    def responseDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that drains the HTTP client response queue into ``self.sent``.

        Args:
            tymth (callable, optional): Function returning the current cycle time used
                to configure this doer's tock.
            tock (float, optional): Cycle time in seconds. Defaults to ``0.0``.
            **kwa: Absorbed keyword arguments passed through by the doer framework.

        Yields:
            None: Yields after each response or each empty-queue check to remain
                cooperative.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.client.responses:
                rep = self.client.respond()
                self.sent.append(rep)
                yield
            yield

    @property
    def idle(self):
        """bool: ``True`` if the message queue is empty and all responses have been received."""
        return len(self.msgs) == 0 and self.posted == len(self.sent)


class HTTPStreamMessenger(doing.DoDoer):
    """Streams a single CESR message via an HTTP PUT request and captures the response."""

    def __init__(self, hab, wit, url, msg=b'', headers=None, **kwa):
        """Initializes the HTTPStreamMessenger, issues the PUT request immediately, and starts the client doer.

        The HTTP request is issued during ``__init__``; no separate send step is needed.

        Args:
            hab (Hab): Habitat for KEL parsing and database access.
            wit (str): Qualified base64 witness identifier.
            url (str): HTTP or HTTPS endpoint URL for the witness.
            msg (bytes, optional): CESR message body to transmit. Defaults to ``b''``.
            headers (dict, optional): Additional HTTP headers to merge into the
                request. Merged after the required CESR headers.
            **kwa: Additional keyword arguments forwarded to :class:`doing.DoDoer`.

        Raises:
            ValueError: If the URL scheme is neither ``http`` nor ``https``.
        """
        self.hab = hab
        self.wit = wit
        self.rep = None
        headers = headers if headers is not None else {}

        up = urlparse(url)
        if up.scheme != Schemes.http and up.scheme != Schemes.https:
            raise ValueError(f"invalid scheme {up.scheme} for HTTPMessenger")

        self.client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        headers = Hict([
            ("Content-Type", "application/cesr"),
            ("Content-Length", len(msg)),
            (CESR_DESTINATION_HEADER, self.wit),
        ] + list(headers.items()))

        self.client.request(
            method="PUT",
            path="/",
            headers=headers,
            body=bytes(msg)
        )

        doers = [clientDoer]

        super(HTTPStreamMessenger, self).__init__(doers=doers, **kwa)

    def recur(self, tyme, deeds=None):
        """Polls for a response on each cycle and stops the doer once one is received.

        Args:
            tyme (float): Current cycle time provided by the Hio framework.
            deeds (list, optional): Deed list forwarded to the parent ``recur``.

        Returns:
            bool: ``True`` when a response has been received and this doer is done,
                otherwise delegates to the parent and returns its result.
        """
        if self.client.responses:
            self.rep = self.client.respond()
            self.remove([self.client])
            return True

        return super(HTTPStreamMessenger, self).recur(tyme, deeds)


def mailbox(hab, cid):
    """Resolves the mailbox AID for a given controller identifier.

    Checks ``hab.db.ends`` for an allowed mailbox role record first. Falls back
    to selecting a random witness from the controller's KEL if no explicit mailbox
    role is found.

    Args:
        hab (Hab): Hab used to look up endpoint role records and witness URLs.
        cid (str): Qualified base64 identifier prefix of the controller to find a
            mailbox for.

    Returns:
        str or None: Qualified base64 identifier prefix of the resolved mailbox, or
            ``None`` if neither a mailbox role record nor any witnesses exist.
    """
    for (_, erole, eid), end in hab.db.ends.getTopItemIter(keys=(cid, Roles.mailbox)):
        if end.allowed:
            return eid

    if cid not in hab.kevers:
        return None

    kever = hab.kevers[cid]
    if not kever.wits:
        return None

    mbx = random.choice(kever.wits)
    return mbx


def messenger(hab, pre, auth=None):
    """Creates a TCP or HTTP messenger for the given recipient based on available endpoints.

    Fetches URL records from ``hab`` for ``pre`` and delegates to
    :func:`messengerFrom`.

    Args:
        hab (Hab): Habitat used to look up endpoint URLs for the recipient.
        pre (str): Qualified base64 identifier prefix of the recipient.
        auth (str, optional): Authorization header value to include in HTTP requests.

    Returns:
        TCPMessenger or HTTPMessenger: Messenger appropriate for the available endpoint.
    """
    urls = hab.fetchUrls(eid=pre)
    return messengerFrom(hab, pre, urls, auth)


def messengerFrom(hab, pre, urls, auth=None):
    """Creates a TCP or HTTP messenger for the given recipient from an explicit URL map.

    Prefers HTTPS over HTTP and HTTP/HTTPS over TCP when multiple schemes are
    available.

    Args:
        hab (Hab): Habitat used for KEL access and event parsing.
        pre (str): Qualified base64 identifier prefix of the recipient.
        urls (dict): Map of URL scheme strings to endpoint URL strings.
        auth (str, optional): Authorization header value to include in HTTP requests.

    Returns:
        TCPMessenger or HTTPMessenger: Messenger appropriate for the available endpoint.

    Raises:
        ConfigurationError: If ``urls`` contains no supported scheme
            (``http``, ``https``, or ``tcp``).
    """
    if Schemes.http in urls or Schemes.https in urls:
        url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
        witer = HTTPMessenger(hab=hab, wit=pre, url=url, auth=auth)
    elif Schemes.tcp in urls:
        url = urls[Schemes.tcp]
        witer = TCPMessenger(hab=hab, wit=pre, url=url)
    else:
        raise ConfigurationError(f"unable to find a valid endpoint for witness {pre}")

    return witer


def streamMessengerFrom(hab, pre, urls, msg, headers=None):
    """Creates a single-shot TCP or HTTP stream messenger for one outbound message.

    Prefers HTTPS over HTTP and HTTP/HTTPS over TCP when multiple schemes are
    available.

    Args:
        hab (Hab): Habitat used for KEL access and event parsing.
        pre (str): Qualified base64 identifier prefix of the recipient.
        urls (dict): Map of URL scheme strings to endpoint URL strings.
        msg (bytes): CESR message bytes to transmit.
        headers (dict, optional): Additional HTTP headers for the request.

    Returns:
        TCPStreamMessenger or HTTPStreamMessenger: Stream messenger appropriate for
            the available endpoint.

    Raises:
        ConfigurationError: If ``urls`` contains no supported scheme
            (``http``, ``https``, or ``tcp``).
    """
    if Schemes.http in urls or Schemes.https in urls:
        url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
        witer = HTTPStreamMessenger(hab=hab, wit=pre, url=url, msg=msg, headers=headers)
    elif Schemes.tcp in urls:
        url = urls[Schemes.tcp]
        witer = TCPStreamMessenger(hab=hab, wit=pre, url=url)
    else:
        raise ConfigurationError(f"unable to find a valid endpoint for witness {pre}")

    return witer


def httpClient(hab, wit):
    """Creates and returns an HTTP client and its associated ClientDoer for a witness.

    Prefers HTTPS over HTTP when both are available.

    Args:
        hab (Hab): Habitat used to look up witness endpoint URLs.
        wit (str): Qualified base64 identifier prefix of the witness.

    Returns:
        tuple[http.clienting.Client, http.clienting.ClientDoer]: A 2-tuple of the
            HTTP client and its doer.

    Raises:
        MissingEntryError: If no HTTP or HTTPS endpoint is found for ``wit``.
    """
    urls = hab.fetchUrls(eid=wit, scheme=Schemes.https) or hab.fetchUrls(eid=wit, scheme=Schemes.http)
    if not urls:
        raise MissingEntryError(f"unable to query witness {wit}, no http endpoint")

    url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
    up = urlparse(url)
    client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port, path=up.path)
    clientDoer = http.clienting.ClientDoer(client=client)

    return client, clientDoer


def schemes(db, eids):
    """Builds a bytearray of signed location record reply messages for a list of endpoint AIDs.

    For each AID in ``eids``, retrieves all available scheme-specific location
    records from ``db`` and serializes them as signed reply messages. Used to
    introduce witnesses to each other during inception and rotation events.

    Args:
        db (Baser): Habitat database used to retrieve location records and witness
            signatures.
        eids (list[str]): Qualified base64 endpoint role AIDs whose location records
            are to be included.

    Returns:
        bytearray: Concatenated, pipelined reply messages and their signatures for
            all resolvable location records.
    """
    msgs = bytearray()
    for eid in eids:
        for scheme in Schemes:
            keys = (eid, scheme)
            said = db.lans.get(keys=keys)
            if said is not None:
                serder = db.rpys.get(keys=(said.qb64,))
                cigars = db.scgs.get(keys=(said.qb64,))

                if len(cigars) == 1:
                    (verfer, cigar) = cigars[0]
                    cigar.verfer = verfer
                else:
                    cigar = None
                msgs.extend(eventing.messagize(serder=serder,
                                               cigars=[cigar],
                                               pipelined=True))
    return msgs
