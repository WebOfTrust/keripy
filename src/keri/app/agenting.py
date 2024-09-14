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
from hio.help import decking, Hict

from socket import gaierror

from . import httping, forwarding
from .. import help
from .. import kering
from .. import core
from ..core import eventing, parsing, coring, serdering, indexing
from ..db import dbing
from ..kering import Roles

logger = help.ogler.getLogger()


class Receiptor(doing.DoDoer):

    def __init__(self, hby, msgs=None, gets=None, cues=None):

        self.msgs = msgs if msgs is not None else decking.Deck()
        self.gets = gets if gets is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.clienter = httping.Clienter()

        doers = [self.clienter, doing.doify(self.witDo), doing.doify(self.gitDo)]
        self.hby = hby

        super(Receiptor, self).__init__(doers=doers)

    def receipt(self, pre, sn=None, auths=None):
        """ Returns a generator for witness receipting

        The returns a generator that will submit the designated event to witnesses for receipts using
        the synchronous witness API, then propogate the receipts to each of the other witnesses.


        Parameters:
            pre (str): qualified base64 identifier to gather receipts for
            sn: (Optiona[int]): sequence number of event to gather receipts for, latest is used if not provided
            auths: (Options[dict]): map of witness AIDs to (time,auth) tuples for providing TOTP auth for witnessing

        Returns:
            list: identifiers of witnesses that returned receipts.

        """
        auths = auths if auths is not None else dict()
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

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
            except (kering.MissingEntryError, gaierror) as e:
                logger.error(f"unable to create http client for witness {wit}: {e}")

        rcts = dict()
        for wit, client in clients.items():
            headers = dict()
            if wit in auths:
                headers["Authorization"] = auths[wit]

            httping.streamCESRRequests(client=client, dest=wit, ims=bytearray(msg), path="receipts", headers=headers)
            while not client.responses:
                yield self.tock

            rep = client.respond()
            if rep.status == 200:
                rct = bytearray(rep.body)
                hab.psr.parseOne(bytearray(rct))
                rserder = serdering.SerderKERI(raw=rct)
                del rct[:rserder.size]

                # pull off the count code
                core.Counter(qb64b=rct, strip=True, gvrsn=kering.Vrsn_1_0)
                rcts[wit] = rct
            else:
                print(f"invalid response {rep.status} from witnesses {wit}")

        for wit in rcts:
            ewits = [w for w in rcts if w != wit]
            wigs = [sig for w, sig in rcts.items() if w != wit]

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
            msg.extend(core.Counter(core.Codens.NonTransReceiptCouples,
                                    count=len(wigs), gvrsn=kering.Vrsn_1_0).qb64b)
            for wig in wigs:
                msg.extend(wig)

            client = clients[wit]

            sent = httping.streamCESRRequests(client=client, dest=wit, ims=bytearray(msg))
            while len(client.responses) < sent:
                yield self.tock

        self.remove(doers)

        return rcts.keys()

    def get(self, pre, sn=None):
        """ Returns a generator for witness querying

        The returns a generator that will request receipts for event identified by pre and sn


        Parameters:
            pre (str): qualified base64 identifier to gather receipts for
            sn: (Optiona[int]): sequence number of event to gather receipts for, latest is used if not provided

        Returns:
            list: identifiers of witnesses that returned receipts.

        """
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        sn = sn if sn is not None else hab.kever.sner.num
        wits = hab.kever.wits

        if len(wits) == 0:
            return

        wit = random.choice(hab.kever.wits)
        urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
        if not urls:
            raise kering.MissingEntryError(f"unable to query witness {wit}, no http endpoint")

        base = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
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
        """ When adding a new Witness, use this method to catch the witness up to the current state of the KEL

        Parameters:
            pre (str): qualified base64 AID of the KEL to send
            wit (str): qualified base64 AID of the witness to send the KEL to

        """
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]

        client, clientDoer = httpClient(hab, wit)
        self.extend([clientDoer])

        for fmsg in hab.db.clonePreIter(pre=pre):
            httping.streamCESRRequests(client=client, dest=wit, ims=bytearray(fmsg))
            while not client.responses:
                yield self.tock

        self.remove([clientDoer])

    def witDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery and .tevery escrows.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
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

    def gitDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery and .tevery escrows.

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
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
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propagates those receipts to each
    of the other witnesses after receiving the complete set.

    Removes all Doers and exits as Done once all witnesses have been sent the entire
    receipt set.  Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hby, msgs=None, cues=None, force=False, auths=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hby (Habery): Habitat of the identifier to receipt witnesses
            msgs (Deck): incoming messages to publish to witnesses
            cues (Deck): outgoing cues of successful messages
            force (bool): True means to send witnesses all receipts even if we have a full compliment.

        """
        self.hby = hby
        self.force = force
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.auths = auths if auths is not None else dict()

        super(WitnessReceiptor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)

    def receiptDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

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

                dgkey = dbing.dgKey(ser.preb, ser.saidb)

                witers = []
                for wit in wits:
                    auth = self.auths[wit] if wit in self.auths else None
                    witer = messenger(hab, wit, auth=auth)
                    witers.append(witer)
                    self.extend([witer])

                # Check to see if we already have all the receipts we need for this event
                wigs = hab.db.getWigs(dgkey)
                completed = len(wigs) == len(wits)
                if len(wigs) != len(wits):  # We have all the receipts, skip
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
                        wigs = hab.db.getWigs(dgkey)
                        if len(wigs) == len(wits):
                            break
                        _ = yield self.tock

                # If we started with all our recipts, exit unless told to force resubmit of all receipts
                if completed and not self.force:
                    self.cues.push(evt)
                    continue

                # generate all rct msgs to send to all witnesses
                awigers = [indexing.Siger(qb64b=bytes(wig)) for wig in wigs]

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
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propagates those receipts to each
    of the other witnesses after receiving the complete set.

    Removes all Doers and exits as Done once all witnesses have been sent the entire
    receipt set.  Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hby, reger=None, msgs=None, klas=None, **kwa):
        """
        For all msgs, select a random witness from Habitat's current set of witnesses
        send the msg and process all responses (KEL replays, RCTs, etc)

        Parameters:
            hby (Habitat): Habitat of the identifier to use to identify witnesses
            msgs: is the message buffer to process and send to one random witness.

        """
        self.hby = hby
        self.reger = reger
        self.klas = klas if klas is not None else HTTPMessenger
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = decking.Deck()

        super(WitnessInquisitor, self).__init__(doers=[doing.doify(self.msgDo)], **kwa)

    def msgDo(self, tymth=None, tock=1.0, **opts):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
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

            kel = forwarding.introduce(hab, witer.wit)
            if kel:
                witer.msgs.append(bytearray(kel))

            witer.msgs.append(bytearray(msg))

            while not witer.sent:
                yield self.tock

            self.sent.append(witer.sent.popleft())

            yield self.tock

    def query(self, pre, r="logs", sn='0', fn='0', src=None, hab=None, anchor=None, wits=None, **kwa):
        """ Create, sign and return a `qry` message against the attester for the prefix

        Parameters:
            src (str): qb64 identifier prefix of source of query
            hab (Hab): Hab to use instead of src if provided
            pre (str): qb64 identifier prefix being queried for
            r (str): query route
            sn (str): optional specific hex str of sequence number to query for
            fn (str): optional specific hex str of sequence number to start with
            anchor (Seal): anchored Seal to search for
            wits (list) witnesses to query

        Returns:
            bytearray: signed query event

        """
        qry = dict(s=sn, fn=fn)
        if anchor is not None:
            qry["a"] = anchor

        msg = dict(src=src, pre=pre, target=pre, r=r, q=qry, wits=wits)
        if hab is not None:
            msg["hab"] = hab

        self.msgs.append(msg)

    def telquery(self, ri, src=None, i=None, r="tels", hab=None, pre=None, wits=None, **kwa):
        qry = dict(ri=ri)
        msg = dict(src=src, pre=pre, target=i, r=r, wits=wits, q=qry)
        if hab is not None:
            msg["hab"] = hab

        self.msgs.append(msg)


class WitnessPublisher(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and exits.

    Removes all Doers and exits as Done once all witnesses have been sent the message.
    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hby, msgs=None, cues=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hby (Habery): Habitat of the identifier to populate witnesses
            msgs (Deck): incoming messages to publish to witnesses
            cues (Deck): outgoing cues of successful messages

        """
        self.hby = hby
        self.posted = 0
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        super(WitnessPublisher, self).__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
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
        """ Check if message with given SAID was sent

        Parameters:
            said (str): qb64 SAID of message to check for
        """

        for cue in self.cues:
            if cue["said"] == said:
                return True

        return False

    @property
    def idle(self):
        return len(self.msgs) == 0 and self.posted == len(self.cues)


class TCPMessenger(doing.DoDoer):
    """ Send events to witnesses for receipting using TCP direct connection

    """

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

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

    def receiptDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        up = urlparse(self.url)
        if up.scheme != kering.Schemes.tcp:
            raise ValueError(f"invalid scheme {up.scheme} for TcpWitnesser")

        client = clienting.Client(host=up.hostname, port=up.port)
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

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
        """
        Returns doifiable Doist compatible generator method (doer dog) to process
            incoming message stream of .kevery

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters


        Usage:
            add result of doify on this method to doers list
        """
        yield from self.parser.parsator(local=True)  # process messages continuously

    @property
    def idle(self):
        return len(self.sent) == self.posted


class TCPStreamMessenger(doing.DoDoer):
    """ Send events to witnesses for receipting using TCP direct connection

    """

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

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

    def receiptDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        up = urlparse(self.url)
        if up.scheme != kering.Schemes.tcp:
            raise ValueError(f"invalid scheme {up.scheme} for TcpWitnesser")

        client = clienting.Client(host=up.hostname, port=up.port)
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

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
        """
        Returns doifiable Doist compatible generator method (doer dog) to process
            incoming message stream of .kevery

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters


        Usage:
            add result of doify on this method to doers list
        """
        yield from self.parser.parsator(local=True)  # process messages continuously

    @property
    def idle(self):
        return len(self.sent) == self.posted


class HTTPMessenger(doing.DoDoer):
    """
    Interacts with Recipients on HTTP and SSE for sending events and receiving receipts

    """

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, auth=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

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
        if up.scheme != kering.Schemes.http and up.scheme != kering.Schemes.https:
            raise ValueError(f"invalid scheme {up.scheme} for HTTPMessenger")

        self.client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        doers.extend([clientDoer])

        super(HTTPMessenger, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
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

            self.posted += httping.streamCESRRequests(client=self.client, dest=self.wit, ims=msg, headers=headers)
            while self.client.requests:
                yield self.tock

            yield self.tock

    def responseDo(self, tymth=None, tock=0.0):
        """
        Processes responses from client and adds them to sent cue

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
        return len(self.msgs) == 0 and self.posted == len(self.sent)


class HTTPStreamMessenger(doing.DoDoer):
    """
    Interacts with Recipients on HTTP and SSE for sending events and receiving receipts

    """

    def __init__(self, hab, wit, url, msg=b'', headers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        self.wit = wit
        self.rep = None
        headers = headers if headers is not None else {}

        up = urlparse(url)
        if up.scheme != kering.Schemes.http and up.scheme != kering.Schemes.https:
            raise ValueError(f"invalid scheme {up.scheme} for HTTPMessenger")

        self.client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        headers = Hict([
            ("Content-Type", "application/cesr"),
            ("Content-Length", len(msg)),
            (httping.CESR_DESTINATION_HEADER, self.wit),
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
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        if self.client.responses:
            self.rep = self.client.respond()
            self.remove([self.client])
            return True

        return super(HTTPStreamMessenger, self).recur(tyme, deeds)


def mailbox(hab, cid):
    for (_, erole, eid), end in hab.db.ends.getItemIter(keys=(cid, kering.Roles.mailbox)):
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
    """ Create a Messenger (tcp or http) based on available endpoints

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        pre (str): qb64 identifier prefix of recipient to create a messanger for
        auth (str): optional auth code to send with any request for messenger

    Returns:
        Optional(TcpWitnesser, HTTPMessenger): witnesser for ensuring full reciepts
    """
    urls = hab.fetchUrls(eid=pre)
    return messengerFrom(hab, pre, urls, auth)


def messengerFrom(hab, pre, urls, auth=None):
    """ Create a Witnesser (tcp or http) based on provided endpoints

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        pre (str): qb64 identifier prefix of recipient to create a messanger for
        urls (dict): map of schemes to urls of available endpoints
        auth (str): optional auth code to send with any request for messenger

    Returns:
        Optional(TcpWitnesser, HTTPMessenger): witnesser for ensuring full reciepts
    """
    if kering.Schemes.http in urls or kering.Schemes.https in urls:
        url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        witer = HTTPMessenger(hab=hab, wit=pre, url=url, auth=auth)
    elif kering.Schemes.tcp in urls:
        url = urls[kering.Schemes.tcp]
        witer = TCPMessenger(hab=hab, wit=pre, url=url)
    else:
        raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {pre}")

    return witer


def streamMessengerFrom(hab, pre, urls, msg, headers=None):
    """ Create a Witnesser (tcp or http) based on provided endpoints

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        pre (str): qb64 identifier prefix of recipient to create a messanger for
        urls (dict): map of schemes to urls of available endpoints
        msg (bytes): bytes of message to send
        headers (dict): optional headers to send with HTTP requests

    Returns:
        Optional(TcpWitnesser, HTTPMessenger): witnesser for ensuring full reciepts
    """
    if kering.Schemes.http in urls or kering.Schemes.https in urls:
        url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        witer = HTTPStreamMessenger(hab=hab, wit=pre, url=url, msg=msg, headers=headers)
    elif kering.Schemes.tcp in urls:
        url = urls[kering.Schemes.tcp]
        witer = TCPStreamMessenger(hab=hab, wit=pre, url=url)
    else:
        raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {pre}")

    return witer


def httpClient(hab, wit):
    """ Create and return a http.client and http.ClientDoer for the witness

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        wit (str): qb64 identifier prefix of witness for which to create a client

    Returns:
        Client: Http client for connecting to remote identifier
        ClientDoer: Doer for client

    """
    urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
    if not urls:
        raise kering.MissingEntryError(f"unable to query witness {wit}, no http endpoint")

    url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
    up = urlparse(url)
    client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port, path=up.path)
    clientDoer = http.clienting.ClientDoer(client=client)

    return client, clientDoer


def schemes(db, eids):
    msgs = bytearray()
    for eid in eids:
        for scheme in kering.Schemes:
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
