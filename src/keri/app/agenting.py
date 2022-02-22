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

from . import httping, forwarding
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
                    witer = witnesser(hab, wit)

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
        self.wits = wits if wits is not None else self.hab.kever.wits
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

        if len(self.wits) == 0:
            raise kering.ConfigurationError("Must be used with an identifier that has witnesses")

        witers = dict()
        for wit in self.wits:
            witer = witnesser(self.hab, wit)
            witers[wit] = witer

        self.extend(witers.values())

        while True:
            while not self.msgs:
                yield self.tock

            (wit, msg) = self.msgs.popleft()
            witer = witers[wit]
            kel = forwarding.introduce(self.hab, wit)
            if kel:
                witer.msgs.append(bytearray(kel))

            witer.msgs.append(bytearray(msg))

            yield self.tock

    def query(self, pre, r="logs", sn=0, anchor=None, **kwa):
        """ Create, sign and return a `qry` message against the attester for the prefix

        Parameters:
            pre (str): qb64 identifier prefix being queried for
            r (str): query route
            sn (int): optional specific sequence number to query for
            anchor (Seal) anchor to search for
            **kwa (dict): keyword arguments passed to eventing.query

        Returns:
            bytearray: signed query event

        """
        wit = random.choice(self.wits)
        qry = dict(s=sn)
        if anchor is not None:
            qry["a"] = anchor

        msg = self.hab.query(pre, src=wit, route=r, query=qry, **kwa)  # Query for remote pre Event
        self.msgs.append((wit, bytes(msg)))  # bytes not bytearray so set membership compare works

    def telquery(self, ri, i=None, r="tels", **kwa):
        wit = random.choice(self.wits)
        msg = self.hab.query(i, src=wit, route=r, query=dict(ri=ri), **kwa)  # Query for remote pre Event
        self.msgs.append((wit, bytes(msg)))  # bytes not bytearray so set membership compare works


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
            witer = witnesser(self.hab, wit)
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
            httping.streamCESRRequests(client=self.client, ims=msg)
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


def witnesser(hab, wit):
    """ Create a Witnesser (tcp or http) based on available endpoints

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        wit (str): qb64 identifier prefix of witness to create a witnesser for

    Returns:
        Optional(TcpWitnesser, HttpWitnesser): witnesser for ensuring full reciepts
    """
    urls = hab.fetchUrls(eid=wit)
    if kering.Schemes.http in urls:
        url = urls[kering.Schemes.http]
        witer = HttpWitnesser(hab=hab, wit=wit, url=url)
    elif kering.Schemes.tcp in urls:
        url = urls[kering.Schemes.tcp]
        witer = TCPWitnesser(hab=hab, wit=wit, url=url)
    else:
        raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {wit}")

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
    urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http)
    if not urls:
        raise kering.ConfigurationError(f"unable to query witness {wit}, no http endpoint")

    up = urlparse(urls[kering.Schemes.http])
    client = http.clienting.Client(hostname=up.hostname, port=up.port)
    clientDoer = http.clienting.ClientDoer(client=client)

    return client, clientDoer

