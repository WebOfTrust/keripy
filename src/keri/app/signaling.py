# -*- encoding: utf-8 -*-
"""
keri.app.signaling module

"""
import datetime
import time

import falcon
from hio.base import doing
from hio.help import decking

from keri.core import coring
from keri.help import helping


def signal(attrs, topic, ckey=None, dt=None):
    """

    Parameters:
        attrs (dict): payload of the notice
        topic (str): routing for recipient of message
        dt(Optional(str, datetime)): iso8601 formatted datetime of notice
        ckey (str): collapse key

    Returns:
        Notice:  Notice instance

    """
    dt = dt if dt is not None else datetime.datetime.now().isoformat()

    if hasattr(dt, "isoformat"):
        dt = dt.isoformat()

    pad = dict(i="",
               dt=dt,
               r=topic,
               a=attrs
               )

    return Signal(pad=pad, ckey=ckey)


class Signal(coring.Dicter):
    def __init__(self, pad, ckey=None):
        """ New Signal

        Signals with a collapse key will replace any existing signal not yet read with a matching value
        as collapse key

        Parameters:
            pad (dict):  Attribute values that make up the payload of the signal
            ckey (str): The collapse key to use for
        """
        super(Signal, self).__init__(pad=pad)
        self._ckey = ckey

        if 'dt' not in self.pad:
            self.pad['dt'] = helping.nowIso8601()

    @property
    def topic(self):
        if 'r' in self.pad:
            return self.pad['r']
        else:
            return None

    @property
    def ckey(self):
        return self._ckey

    @property
    def dt(self):
        return self.pad['dt']

    @dt.setter
    def dt(self, dt):
        if hasattr(dt, "isoformat"):
            dt = dt.isoformat()

        self.pad['dt'] = dt

    @property
    def attrs(self):
        if 'a' in self.pad:
            return self.pad['a']
        return None


class Signaler(doing.DoDoer):
    """ Class for sending signals to the controller of an agent.

    The signals are just pings to reload data and not persistent messages that can be reread

    """

    SignalTimeout = datetime.timedelta(minutes=10)

    def __init__(self, signals=None):
        """

        Parameters:
        """
        self.signals = signals if signals is not None else decking.Deck()
        doers = [doing.doify(self.expireDo)]
        super(Signaler, self).__init__(doers=doers)

    def push(self, attrs, topic, ckey=None, dt=None):
        """

        Parameters:
            attrs (dict): signal attributes to push to the cue
            topic (str): routing for recipient of message
            ckey (str): collapse key
            dt(Optional(str, datetime)): iso8601 formatted datetime of notice

        Returns:

        """
        dt = dt if dt is not None else datetime.datetime.now()
        sig = signal(attrs=attrs, topic=topic, ckey=ckey, dt=dt)

        if sig.ckey is not None:
            for i, s in enumerate(self.signals):
                if s.ckey == sig.ckey:
                    self.signals[i] = sig
                    return

        self.signals.append(sig)

    def expireDo(self, tymth=None, tock=0.0):
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

        while True:  # loop checking for expired messages
            now = datetime.datetime.now()
            toRemove = []
            for sig in self.signals:
                if now - helping.fromIso8601(sig.dt) > self.SignalTimeout:  # Expire messages that are too old
                    toRemove.append(sig)
                yield self.tock

            for sig in toRemove:
                self.signals.remove(sig)

            yield self.tock


def loadEnds(app, *, signals=None):
    """ Load endpoints for agent to controller messages

    Args:
        app (falcon.App): falcon.App to register handlers with:
        signals (Deck): messages for the mailbox stream

    Returns:

    """
    sigEnd = SignalsEnd(signals=signals)
    app.add_route("/mbx", sigEnd)
    return sigEnd


class SignalsEnd:
    """
    HTTP handler that accepts and KERI events POSTed as the body of a request with all attachments to
    the message as a CESR attachment HTTP header.  KEL Messages are processed and added to the database
    of the provided Habitat.

    This also handles `req`, `exn` and `tel` messages that respond with a KEL replay.
    """

    def __init__(self, signals=None):
        """
        Create the MBX HTTP server from the Habitat with an optional Falcon App to
        register the routes with.

        Parameters
             rxbs (bytearray): output queue of bytes for message processing
             mbx (Mailboxer): Mailbox storage
             qrycues (Deck): inbound qry response queues

        """
        self.signals = signals if signals is not None else decking.Deck()

    def on_post(self, req, rep):
        """
        Handles POST for KERI mailbox service.

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        ---
        summary:  Stream Server-Sent Events for KERI mailbox for identifier
        description:  Stream Server-Sent Events for KERI mailbox for identifier
        tags:
           - Mailbox

        responses:
           200:
              content:
                 text/event-stream:
                    schema:
                       type: object
              description: Signal query response for server sent events
           204:
              description: KEL or EXN event accepted.
        """
        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        rep.set_header('Content-Type', "text/event-stream")
        rep.status = falcon.HTTP_200
        rep.stream = SignalIterable(signals=self.signals)

    def on_get(self, req, rep):
        """
        Handles GET requests as a stream of SSE events
        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response
        ---
        summary:  Stream Server-Sent Events for KERI mailbox for identifier
        description:  Stream Server-Sent Events for KERI mailbox for identifier
        tags:
           - Mailbox
        responses:
           200:
              content:
                 text/event-stream:
                    schema:
                       type: object
              description: Mailbox query response for server sent events
           204:
              description: KEL or EXN event accepted.
        """
        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")
        rep.set_header('Content-Type', "text/event-stream")

        rep.stream = SignalIterable(signals=self.signals)


class SignalIterable:
    TimeoutMBX = 300

    def __init__(self, signals, retry=5000):
        self.signals = signals
        self.retry = retry

    def __iter__(self):
        self.start = self.end = time.perf_counter()
        return self

    def __next__(self):
        if self.end - self.start < self.TimeoutMBX:
            if self.start == self.end:
                self.end = time.perf_counter()
                return bytes(f"retry: {self.retry}\n\n".encode("utf-8"))

            data = bytearray()
            while self.signals:
                sig = self.signals.popleft()
                topic = sig.topic
                if topic is not None:
                    data.extend(bytearray("id: {}\nretry: {}\nevent: {}\ndata: ".format(sig.rid, self.retry,
                                                                                        topic).encode("utf-8")))
                else:
                    data.extend(bytearray("id: {}\nretry: {}\ndata: ".format(sig.id, self.retry).encode(
                        "utf-8")))

                data.extend(sig.raw)
                data.extend(b'\n\n')
            self.end = time.perf_counter()
            return bytes(data)

        raise StopIteration
