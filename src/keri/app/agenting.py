# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import random
from urllib.parse import urlparse

from hio.base import doing
from hio.core import http
from hio.core.tcp import clienting
from hio.help import decking

from . import httping
from .. import help
from .. import kering
from ..core import eventing, parsing, coring
from ..db import dbing

logger = help.ogler.getLogger()


class WitnessReceiptor(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propagates those receipts to each
    of the other witnesses after receiving the complete set.

    Removes all Doers and exits as Done once all witnesses have been sent the entire
    receipt set.  Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hby, msgs=None, cues=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab (Hab): Habitat of the identifier to populate witnesses
            msg (bytes): is the message to send to all witnesses.
                 Defaults to sending the latest KEL event if msg is None
            scheme (str): Scheme to favor if available

        """
        self.hby = hby
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        super(WitnessReceiptor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)

    def receiptDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pre = msg["pre"]

                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]

                sn = msg["sn"] if "sn" in msg else hab.kever.sn
                wits = hab.kever.wits

                if len(wits) == 0:
                    continue

                msg = hab.makeOwnEvent(sn=sn)
                ser = coring.Serder(raw=msg)

                witers = []
                for wit in wits:
                    urls = hab.fetchUrls(eid=wit)
                    if kering.Schemes.http in urls:
                        url = urls[kering.Schemes.http]
                        witer = HttpWitnesser(hab=hab, wit=wit, url=url)
                    elif kering.Schemes.tcp in urls:
                        url = urls[kering.Schemes.tcp]
                        witer = TCPWitnesser(hab=hab, wit=wit, url=url)
                    else:
                        raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {wit}")

                    witers.append(witer)
                    witer.msgs.append(bytearray(msg))  # make a copy
                    self.extend([witer])

                    _ = (yield self.tock)

                dgkey = dbing.dgKey(ser.preb, ser.saidb)
                while True:
                    wigs = hab.db.getWigs(dgkey)
                    if len(wigs) == len(wits):
                        break
                    _ = yield self.tock

                # generate all rct msgs to send to all witnesses
                wigers = [coring.Siger(qb64b=bytes(wig)) for wig in wigs]
                rserder = eventing.receipt(pre=ser.pre,
                                           sn=sn,
                                           said=ser.said)
                rctMsg = eventing.messagize(serder=rserder, wigers=wigers)

                # this is a little brute forcey and can be improved by gathering receipts
                # along the way and passing them out as we go and only sending the
                # required ones here
                for witer in witers:
                    witer.msgs.append(bytearray(rctMsg))
                    _ = (yield self.tock)

                total = len(witers) * 2
                count = 0
                while count < total:
                    for witer in witers:
                        count += len(witer.sent)
                    _ = (yield self.tock)

                self.remove(witers)

                self.cues.append(msg)
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

    def __init__(self, hab, reger=None, msgs=None, wits=None, klas=None, **kwa):
        """
        For all msgs, select a random witness from Habitat's current set of witnesses
        send the msg and process all responses (KEL replays, RCTs, etc)

        Parameters:
            hby (Habitat): Habitat of the identifier to use to identify witnesses
            msgs: is the message buffer to process and send to one random witness.

        """
        self.hab = hab
        self.reger = reger
        self.wits = wits
        self.klas = klas if klas is not None else HttpWitnesser
        self.msgs = msgs if msgs is not None else decking.Deck()

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

        wits = self.wits if self.wits is not None else self.hab.kever.wits
        if len(wits) == 0:
            raise kering.ConfigurationError("Must be used with an identifier that has witnesses")

        witers = []
        for wit in wits:
            urls = self.hab.fetchUrls(eid=wit)
            if kering.Schemes.http in urls:
                url = urls[kering.Schemes.http]
                witer = HttpWitnesser(hab=self.hab, wit=wit, url=url)
            elif kering.Schemes.tcp in urls:
                url = urls[kering.Schemes.tcp]
                witer = TCPWitnesser(hab=self.hab, wit=wit, url=url)
            else:
                raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {wit}")
            witers.append(witer)

        self.extend(witers)

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()
            witer = random.choice(witers)
            witer.msgs.append(bytearray(msg))

            yield self.tock

    def query(self, pre, r="logs", sn=0, **kwa):
        msg = self.hab.query(pre, route=r, query=dict(), **kwa)  # Query for remote pre Event
        self.msgs.append(bytes(msg))  # bytes not bytearray so set membership compare works

    def telquery(self, ri, i=None, r="tels", **kwa):
        msg = self.hab.query(i, route=r, query=dict(ri=ri), **kwa)  # Query for remote pre Event
        self.msgs.append(bytes(msg))  # bytes not bytearray so set membership compare works

    def backoffQuery(self, pre, sn=None, anc=None):
        backoff = BackoffWitnessQuery(hab=self.hab, pre=pre, sn=sn, anc=anc)
        self.extend([backoff])

    def backoffTelQuery(self, ri=None, i=None):
        backoff = BackoffWitnessTelQuery(hab=self.hab, reger=self.reger, ri=ri, i=i, wits=self.hab.kever.wits)
        self.extend([backoff])


class WitnessPublisher(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and exits.

    Removes all Doers and exits as Done once all witnesses have been sent the message.
    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hab, msg, wits=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses
            msg: is the message to send to all witnesses.
                 Defaults to sending the latest KEL event if msg is None

        """
        self.hab = hab
        self.msg = msg
        self.wits = wits if wits is not None else self.hab.kever.wits
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

        if len(self.wits) == 0:
            return True

        witers = []
        for wit in self.wits:
            urls = self.hab.fetchUrls(eid=wit)
            if kering.Schemes.http in urls:
                url = urls[kering.Schemes.http]
                witer = HttpWitnesser(hab=self.hab, wit=wit, url=url)
            elif kering.Schemes.tcp in urls:
                url = urls[kering.Schemes.tcp]
                witer = TCPWitnesser(hab=self.hab, wit=wit, url=url)
            else:
                raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {wit}")

            witers.append(witer)
            witer.msgs.append(bytearray(self.msg))  # make a copy so everyone munges their own
            self.extend([witer])

            _ = (yield self.tock)

        total = len(witers)
        count = 0
        while count < total:
            for witer in witers:
                count += len(witer.sent)
            _ = (yield self.tock)

        self.remove(witers)
        return True


class TCPWitnesser(doing.DoDoer):
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
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.receiptDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      **kwa)

        super(TCPWitnesser, self).__init__(doers=doers)

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
        yield from self.parser.parsator()  # process messages continuously


class HttpWitnesser(doing.DoDoer):
    """
    Interacts with Witnesses on HTTP and SSE for sending events and receiving receipts

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
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo), doing.doify(self.responseDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        up = urlparse(url)
        if up.scheme != kering.Schemes.http:
            raise ValueError(f"invalid scheme {up.scheme} for HttpWitnesser")

        self.client = http.clienting.Client(hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        doers.extend([clientDoer])

        super(HttpWitnesser, self).__init__(doers=doers, **kwa)

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
            httping.createCESRRequest(msg, self.client)
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
            while not self.client.responses:
                rep = self.client.respond()
                self.sent.append(rep)
                yield
            yield


class BackoffWitnessQuery(doing.DoDoer):
    """
    Queries selection of target witnesses randomly performing truncated exponential backoff
    retries

    """

    def __init__(self, hab, pre, wits=None, sn=None, anchor=None, startTyme=0.25, maxTyme=60, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses
            maxTime is seconds int of maximum amount of time before giving up

        """
        self.hab = hab
        self.wits = wits if wits is not None else self.hab.kever.wits
        self.startTyme = startTyme
        self.maxTyme = maxTyme

        self.pre = pre
        self.sn = sn
        self.anchor = anchor

        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.queryDo)])

        super(BackoffWitnessQuery, self).__init__(doers=doers, **kwa)

    def queryDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        tyme = self.startTyme
        while tyme <= self.maxTyme:

            if self.pre in self.hab.kevers:
                kever = self.hab.kevers[self.pre]
                if self.sn is not None and kever.sn >= self.sn:
                    break
                if self.anchor is not None:
                    srdr = self.hab.db.findAnchoringEvent(pre=self.pre, anchor=self.anchor)
                    if srdr is not None:
                        break

            wit = random.choice(self.wits)
            urls = self.hab.fetchUrls(eid=wit, scheme=kering.Schemes.http)
            if not urls:
                raise kering.ConfigurationError(f"unable to query witness {wit}, no http endpoint")

            up = urlparse(urls[kering.Schemes.http])
            client = http.clienting.Client(hostname=up.hostname, port=up.port)
            clientDoer = http.clienting.ClientDoer(client=client)

            self.extend([clientDoer])

            msg = self.hab.query(self.pre, route="logs", query=dict())  # Query for remote pre Event
            httping.createCESRRequest(msg, client)
            while client.requests:
                yield self.tock

            while not client.responses:
                yield self.tock

            self.remove([clientDoer])

            delay = tyme + random.randint(0, 1000) / 1000.0
            tyme *= 2

            yield delay


class BackoffWitnessTelQuery(doing.DoDoer):
    """
    Queries selection of target witnesses randomly performing truncated exponential backoff
    retries

    """

    def __init__(self, hab, reger, ri, i, wits, startTyme=0.25, maxTyme=60, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses
            maxTime is seconds int of maximum amount of time before giving up

        """
        self.hab = hab
        self.reger = reger
        self.wits = wits
        self.maxTyme = maxTyme
        self.startTyme = startTyme

        self.ri = ri
        self.i = i

        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.queryDo)])

        super(BackoffWitnessTelQuery, self).__init__(doers=doers, **kwa)

    def queryDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        tyme = self.startTyme
        while tyme <= self.maxTyme:

            if self.ri in self.reger.tevers:
                tever = self.reger.tevers[self.ri]
                if self.i is None or tever.vcState(self.i) is not None:
                    break

            wit = random.choice(self.wits)
            urls = self.hab.fetchUrls(eid=wit, scheme=kering.Schemes.http)
            if not urls:
                raise kering.ConfigurationError(f"unable to query witness {wit}, no http endpoint")

            up = urlparse(urls[kering.Schemes.http])
            client = http.clienting.Client(hostname=up.hostname, port=up.port)
            clientDoer = http.clienting.ClientDoer(client=client)

            self.extend([clientDoer])

            msg = self.hab.query(self.i, route="tels", query=dict(ri=self.ri))  # Query for remote pre Event

            httping.createCESRRequest(msg, client)
            while client.requests:
                yield self.tock

            while not client.responses:
                yield self.tock

            self.remove([clientDoer])

            delay = tyme + random.randint(0, 1000) / 1000.0
            tyme *= 2

            yield delay
