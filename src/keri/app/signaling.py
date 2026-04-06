# -*- encoding: utf-8 -*-
"""
KERI
keri.app.signaling module

"""
import datetime
import time

import falcon
from hio.base import doing
from hio.help import decking

from ..core import Dicter
from ..help import fromIso8601, nowIso8601, nowUTC


def signal(attrs, topic, ckey=None, dt=None):
    """Create a Signal instance with the given payload and routing information.

    Parameters:
        attrs (dict): Payload attributes of the signal.
        topic (str): Routing topic for the recipient of the signal.
        ckey (str): Collapse key. Signals sharing a collapse key
            replace any unread signal with the same key. Defaults to None.
        dt (str | datetime): ISO 8601 formatted datetime for the
            signal. If a ``datetime`` object is provided it will be converted
            via ``isoformat()``. Defaults to the current UTC time.

    Returns:
        Signal: A new Signal instance constructed from the given arguments.
    """
    dt = dt if dt is not None else nowIso8601()

    if hasattr(dt, "isoformat"):
        dt = dt.isoformat()

    pad = dict(i="",
               dt=dt,
               r=topic,
               a=attrs
               )

    return Signal(pad=pad, ckey=ckey)


class Signal(Dicter):
    """A single signal message passed from an agent to its controller.

    Signals are ephemeral pings that carry a structured payload (``pad``) and
    an optional collapse key (``ckey``).  A Signal with a collapse key replaces
    any existing unread Signal that shares the same key in the queue.

    Attributes:
        _ckey (str): The collapse key for this signal.
    """

    def __init__(self, pad, ckey=None):
        """Initialize a Signal.

        Parameters:
            pad (dict): Attribute values that make up the payload of the
                signal. Expected keys are ``i`` (identifier), ``dt``
                (ISO 8601 datetime), ``r`` (topic/route), and ``a``
                (application-level attributes dict).
            ckey (str): Collapse key. A signal with a collapse key
                replaces any existing unread signal with the same key.
                Defaults to None.
        """
        super(Signal, self).__init__(pad=pad)
        self._ckey = ckey

        if 'dt' not in self.pad:
            self.pad['dt'] = nowIso8601()

    @property
    def topic(self):
        """str: The routing topic of the signal (``pad['r']``), or
        ``None`` if not present."""
        if 'r' in self.pad:
            return self.pad['r']
        else:
            return None

    @property
    def ckey(self):
        """str: The collapse key for this signal."""
        return self._ckey

    @property
    def dt(self):
        """str: ISO 8601 datetime string for this signal (``pad['dt']``)."""
        return self.pad['dt']

    @dt.setter
    def dt(self, dt):
        """Set the datetime for this signal.

        Parameters:
            dt (str | datetime): ISO 8601 formatted string or a
                ``datetime`` object. If a ``datetime`` object is provided
                it will be converted via ``isoformat()``.
        """
        if hasattr(dt, "isoformat"):
            dt = dt.isoformat()

        self.pad['dt'] = dt

    @property
    def attrs(self):
        """dict: Application-level attributes from the signal payload
        (``pad['a']``), or ``None`` if not present."""
        if 'a' in self.pad:
            return self.pad['a']
        return None


class Signaler(doing.DoDoer):
    """Manages a queue of Signal messages from an agent to its controller.

    Signals are ephemeral pings intended to notify the controller to reload
    data; they are not persistent and cannot be re-read once consumed.  A
    background doer (``expireDo``) automatically removes signals that have
    been in the queue longer than ``SignalTimeout``.

    Attributes:
        signals (Deck): Queue holding pending Signal instances.
        SignalTimeout (datetime.timedelta): Maximum age of a signal before it
            is expired. Defaults to 10 minutes.
    """

    SignalTimeout = datetime.timedelta(minutes=10)

    def __init__(self, signals=None):
        """Initialize a Signaler.

        Parameters:
            signals (Deck): Existing deck to use as the signal
                queue. A new ``decking.Deck`` is created when not provided.
                Defaults to None.
        """
        self.signals = signals if signals is not None else decking.Deck()
        doers = [doing.doify(self.expireDo)]
        super(Signaler, self).__init__(doers=doers)

    def push(self, attrs, topic, ckey=None, dt=None):
        """Build a Signal and append it to the signal queue.

        If the signal carries a collapse key and an unread signal with the
        same key already exists in the queue, that existing signal is replaced
        in-place rather than a new entry being appended.

        Parameters:
            attrs (dict): Signal attributes to push to the queue.
            topic (str): Routing topic for the recipient of the signal.
            ckey (str): Collapse key. Defaults to None.
            dt (str | datetime): ISO 8601 formatted datetime for
                the signal. Defaults to the current UTC time.
        """
        dt = dt if dt is not None else nowIso8601()
        sig = signal(attrs=attrs, topic=topic, ckey=ckey, dt=dt)

        if sig.ckey is not None:
            for i, s in enumerate(self.signals):
                if s.ckey == sig.ckey:
                    self.signals[i] = sig
                    return

        self.signals.append(sig)

    def expireDo(self, tymth=None, tock=0.0, **kwa):
        """Doer generator that periodically removes expired signals from the queue.

        Iterates over the signal queue on every tock and removes any signal
        whose age exceeds ``SignalTimeout``.  Intended to be registered via
        ``doing.doify`` and driven by a ``Doist``.

        Parameters:
            tymth (callable): Injected function wrapper closure
                returned by ``Tymist.tymen()``. Calling ``tymth()`` returns
                the associated ``Tymist.tyme``. Defaults to None.
            tock (float): Injected initial tock value representing
                the scheduler time increment in seconds. Defaults to 0.0.
            **kwa: Additional keyword arguments passed by the doer framework.

        Yields:
            float: The current tock value, yielding control back to the
                ``Doist`` scheduler on each iteration.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:  # loop checking for expired messages
            now = nowUTC()
            toRemove = []
            for sig in self.signals:
                if now - fromIso8601(sig.dt) > self.SignalTimeout:  # Expire messages that are too old
                    toRemove.append(sig)
                yield self.tock

            for sig in toRemove:
                self.signals.remove(sig)

            yield self.tock


def loadEnds(app, *, signals=None):
    """Register the signaling mailbox endpoint with a Falcon application.

    Creates a ``SignalsEnd`` instance and mounts it at ``/mbx``.

    Parameters:
        app (falcon.App): Falcon application instance to register the route on.
        signals (Deck): Deck of pending Signal instances to pass to
            the endpoint handler. Defaults to None.

    Returns:
        SignalsEnd: The endpoint handler instance that was registered.
    """
    sigEnd = SignalsEnd(signals=signals)
    app.add_route("/mbx", sigEnd)
    return sigEnd


class SignalsEnd:
    """Falcon HTTP resource that streams pending signals as Server-Sent Events.

    Exposes a mailbox endpoint (``/mbx``) that both GET and POST requests can
    use to receive a stream of SSE-formatted Signal messages destined for the
    agent's controller.
    """

    def __init__(self, signals=None):
        """Initialize a SignalsEnd resource.

        Parameters:
            signals (Deck): Deck of pending Signal instances to
                stream to clients. A new ``decking.Deck`` is created when not
                provided. Defaults to None.
        """
        self.signals = signals if signals is not None else decking.Deck()

    def on_post(self, req, rep):
        """Handle POST requests by streaming pending signals as SSE.

        Streams all pending signals from the mailbox queue as a
        ``text/event-stream`` response. Each signal is encoded as an SSE
        event frame and sent to the client.

        Parameters:
            req (falcon.Request): Incoming Falcon HTTP request.
            rep (falcon.Response): Outgoing Falcon HTTP response. On return,
                ``rep.status`` is set to ``200 OK``, ``Content-Type`` is set
                to ``text/event-stream``, and ``rep.stream`` is set to a
                :class:`SignalIterable` that drains the pending signal queue.
        """
        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        rep.set_header('Content-Type', "text/event-stream")
        rep.status = falcon.HTTP_200
        rep.stream = SignalIterable(signals=self.signals)

    def on_get(self, req, rep):
        """Handle GET requests by streaming pending signals as SSE.

        Streams all pending signals from the mailbox queue as a
        ``text/event-stream`` response. Each signal is encoded as an SSE
        event frame and sent to the client.

        Parameters:
            req (falcon.Request): Incoming Falcon HTTP request.
            rep (falcon.Response): Outgoing Falcon HTTP response. On return,
                ``Content-Type`` is set to ``text/event-stream`` and
                ``rep.stream`` is set to a :class:`SignalIterable` that
                drains the pending signal queue.
        """
        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")
        rep.set_header('Content-Type', "text/event-stream")

        rep.stream = SignalIterable(signals=self.signals)


class SignalIterable:
    """Iterator that yields SSE-formatted bytes from the signal queue.

    On the first call to ``__next__`` a ``retry`` directive is sent to the
    client.  Subsequent calls drain all available signals from the queue,
    encode each one as an SSE event frame, and return the combined bytes.
    Iteration stops once ``TimeoutMBX`` seconds have elapsed since the
    iterator was first entered.

    Attributes:
        TimeoutMBX (int): Maximum number of seconds the iterator will produce
            data before raising ``StopIteration``. Defaults to 300.
        signals (Deck): Shared signal queue consumed by this iterator.
        retry (int): SSE ``retry`` interval in milliseconds sent to the
            client. Defaults to 5000.
    """

    TimeoutMBX = 300

    def __init__(self, signals, retry=5000):
        """Initialize a SignalIterable.

        Parameters:
            signals (Deck): Shared queue of pending Signal instances to drain
                and encode as SSE event frames.
            retry (int): SSE ``retry`` interval in milliseconds
                included in each event frame. Defaults to 5000.
        """
        self.signals = signals
        self.retry = retry

    def __iter__(self):
        """Prepare the iterator and record the start time.

        Returns:
            SignalIterable: This iterator instance.
        """
        self.start = self.end = time.perf_counter()
        return self

    def __next__(self):
        """Yield the next chunk of SSE-encoded signal bytes.

        On the very first call, returns a ``retry`` directive frame.  On
        subsequent calls, drains all currently available signals from the
        queue and returns them as concatenated SSE event frames.  Raises
        ``StopIteration`` once ``TimeoutMBX`` seconds have elapsed.

        Returns:
            bytes: SSE-formatted bytes containing one or more event frames,
                or an empty payload when no signals are pending.

        Raises:
            StopIteration: When the elapsed time exceeds ``TimeoutMBX``.
        """
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
