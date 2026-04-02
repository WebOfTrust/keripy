# -*- encoding: utf-8 -*-
"""
keri.app.httping module

Provides utilities for sending and receiving KERI events over HTTP
"""
import datetime
import json
from dataclasses import dataclass
from urllib import parse

import falcon
from hio.base import doing
from hio.core import http
from hio.help import Hict, ogler

from ..kering import (ShortageError, ExtractionError,
                      ColdStartError, sniff, Colds)
from ..core import Sadder, SerderKERI
from ..end import designature
from ..help import nowUTC


logger = ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"
CESR_DESTINATION_HEADER = "CESR-DESTINATION"


class SignatureValidationComponent(object):
    """Validates SKWA signatures on incoming requests.

    Verifies that each request carries a ``Signature`` header whose value is a
    valid signature over the JSON-encoded request body, produced by the
    controller identified by ``pre``.

    Attributes:
        hby: Habery instance providing access to the local key state.
        pre (str): qb64 identifier prefix of the expected signer.
    """

    def __init__(self, hby, pre):
        """Initializes SignatureValidationComponent.

        Args:
            hby: Habery instance used to look up key state for ``pre``.
            pre (str): qb64 identifier prefix of the controller whose
                signature must be present on every request.
        """
        self.hby = hby
        self.pre = pre

    def process_request(self, req, resp):
        """Validates the ``Signature`` header against the request body.

        Reads the ``Signature`` header and the JSON-encoded media body,
        then delegates to :meth:`validate`. Sets the response status to
        ``401 Unauthorized`` and marks the response complete if validation
        fails, preventing further processing.

        Args:
            req (falcon.Request): Incoming HTTP request object.
            resp (falcon.Response): Outgoing HTTP response object.
        """
        sig = req.headers.get("SIGNATURE")
        ked = req.media
        ser = json.dumps(ked).encode("utf-8")
        if not self.validate(sig=sig, ser=ser):
            resp.complete = True
            resp.status = falcon.HTTP_401
            return

    def validate(self, sig, ser):
        """Verifies a raw signature string against serialized data.

        Parses the ``sig`` string into signage markers and checks each
        indexed verfer in the current key state of ``self.pre`` against
        the corresponding siger.

        Args:
            sig (str): Raw signature header value, parseable by
                :func:`~keri.end.designature`.
            ser (bytes): Serialized data that was signed.

        Returns:
            bool: ``True`` if all verfers successfully verify their
            corresponding sigers; ``False`` if ``self.pre`` is absent
            from the key state, a required index is missing, or any
            signature fails verification.
        """
        signages = designature(sig)
        markers = signages[0].markers

        if self.pre not in self.hby.kevers:
            return False

        verfers = self.hby.kevers[self.pre].verfers
        for idx, verfer in enumerate(verfers):
            key = str(idx)
            if key not in markers:
                return False
            siger = markers[key]
            siger.verfer = verfer

            if not verfer.verify(siger.raw, ser):
                return False

        return True


@dataclass
class CesrRequest:
    """Container for a parsed CESR HTTP request.

    Attributes:
        payload (dict): Decoded JSON body of the request.
        attachments (str): Value of the ``CESR-ATTACHMENT`` header.
    """
    payload: dict
    attachments: str


def parseCesrHttpRequest(req):
    """Parses a Falcon HTTP request in CESR format into a :class:`CesrRequest`.

    Validates the ``Content-Type`` header, decodes the JSON body, and
    extracts the required ``CESR-ATTACHMENT`` header.

    Args:
        req (falcon.Request): Incoming HTTP request object.  Must have
            ``Content-Type: application/cesr`` and a valid JSON body.

    Returns:
        CesrRequest: Dataclass holding the decoded payload and the raw
        attachment header value.

    Raises:
        falcon.HTTPError: With status ``406 Not Acceptable`` if the
            content type is not ``application/cesr``.
        falcon.HTTPError: With status ``400 Bad Request`` if the body
            cannot be decoded as JSON.
        falcon.HTTPError: With status ``412 Precondition Failed`` if the
            ``CESR-ATTACHMENT`` header is absent.
    """
    if req.content_type != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(falcon.HTTP_NOT_ACCEPTABLE,
                               title="Content type error",
                               description="Unacceptable content type.")

    try:
        data = json.load(req.bounded_stream)
    except ValueError:
        raise falcon.HTTPError(falcon.HTTP_400,
                               title="Malformed JSON",
                               description="Could not decode the request body. The "
                                           "JSON was incorrect.")

    if CESR_ATTACHMENT_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_PRECONDITION_FAILED,
                               title="Attachment error",
                               description="Missing required attachment header.")
    attachment = req.headers[CESR_ATTACHMENT_HEADER]

    cr = CesrRequest(
        payload=data,
        attachments=attachment)

    return cr


def createCESRRequest(msg, client, dest, path=None):
    """Converts a single KERI message into a CESR HTTP POST request.

    Deserializes the leading event from ``msg`` using
    :class:`~keri.core.SerderKERI`, strips it from the bytearray, treats
    the remainder as the attachment, and issues a ``POST`` via ``client``.

    Args:
        msg (bytearray): Raw KERI message stream.  The leading event is
            consumed; remaining bytes become the attachment.
        client: hio HTTP ``Client`` instance used to send the request.
        dest (str): qb64 identifier prefix of the destination controller,
            written to the ``CESR-DESTINATION`` header.
        path (str, optional): URL path to post to.  Defaults to ``"/"``.

    Raises:
        ExtractionError: If fewer bytes are available than the declared
            event size (:class:`~keri.kering.ShortageError` is caught
            internally and re-raised as :class:`~keri.kering.ExtractionError`).
    """
    path = path if path is not None else "/"

    try:
        serder = SerderKERI(raw=msg)
    except ShortageError as ex:  # need more bytes
        raise ExtractionError("unable to extract a valid message to send as HTTP")
    else:  # extracted successfully
        del msg[:serder.size]  # strip off event from front of ims

    attachments = bytearray(msg)
    body = serder.raw

    headers = Hict([
        ("Content-Type", CESR_CONTENT_TYPE),
        ("Content-Length", len(body)),
        ("connection", "close"),
        (CESR_ATTACHMENT_HEADER, attachments),
        (CESR_DESTINATION_HEADER, dest)
    ])

    client.request(
        method="POST",
        path=path,
        headers=headers,
        body=body
    )


def streamCESRRequests(client, ims, dest, path=None, headers=None):
    """Decomposes a KERI message stream into individual CESR HTTP POST requests.

    Iterates over ``ims``, extracting one :class:`~keri.core.Sadder` event
    at a time followed by its attachment bytes (everything up to the next
    ``0x7b`` / ``{`` byte).  Each event-plus-attachment pair is dispatched
    as a separate ``POST`` via ``client``.

    Args:
        client: hio HTTP ``Client`` instance that will send each request.
        ims (bytearray): Stream of concatenated KERI messages.  Consumed
            in place as events and attachments are extracted.
        dest (str): qb64 identifier prefix of the destination controller,
            written to the ``CESR-DESTINATION`` header of every request.
        path (str, optional): URL path to post to.  Defaults to ``"/"``.
            Joined with ``client.requester.path`` using
            :func:`urllib.parse.urljoin`.
        headers (Hict, optional): Additional headers merged into each
            request after the standard CESR headers.  Defaults to an
            empty :class:`~hio.help.Hict`.

    Returns:
        int: Number of individual HTTP requests posted.

    Raises:
        ColdStartError: If the stream begins with a counter triplet
            (``txt`` or ``bny`` cold-start indicator) rather than a
            message.
        ExtractionError: If a message cannot be fully extracted due to
            insufficient bytes.
    """
    path = path if path is not None else "/"
    path = parse.urljoin(client.requester.path, path)

    cold = sniff(ims)  # check for spurious counters at front of stream
    if cold in (Colds.txt, Colds.bny):  # not message error out to flush stream
        # replace with pipelining here once CESR message format supported.
        raise ColdStartError("Expecting message counter tritet={}"
                                    "".format(cold))

    # Otherwise its a message cold start
    cnt = 0
    while ims:  # extract and deserialize message from ims
        try:
            serder = Sadder(raw=ims)
        except ShortageError as ex:  # need more bytes
            raise ExtractionError("unable to extract a valid message to send as HTTP")
        else:  # extracted successfully
            del ims[:serder.size]  # strip off event from front of ims

        attachment = bytearray()
        while ims and ims[0] != 0x7b:  # not new message so process attachments, must support CBOR and MsgPack
            attachment.append(ims[0])
            del ims[:1]

        body = serder.raw

        headers = headers if headers is not None else Hict()
        heads = (Hict([
            ("Content-Type", CESR_CONTENT_TYPE),
            ("Content-Length", len(body)),
            (CESR_ATTACHMENT_HEADER, attachment),
            (CESR_DESTINATION_HEADER, dest)
        ]))
        heads.update(headers)

        client.request(
            method="POST",
            path=path,
            headers=heads,
            body=body
        )
        cnt += 1

    return cnt


class Clienter(doing.DoDoer):
    """DoDoer that manages a pool of hio HTTP clients, one per outbound request.

    Each call to :meth:`request` creates a new :class:`~hio.core.http.clienting.Client`
    and a corresponding :class:`~hio.core.http.clienting.ClientDoer`, both
    tracked internally.  A background coroutine (:meth:`clientDo`) periodically
    removes clients whose responses have been pending longer than
    :attr:`TimeoutClient` seconds.

    Attributes:
        TimeoutClient (int): Class-level timeout in seconds before a client
            with no response is pruned.  Default is ``300`` (5 minutes).
        clients (list[tuple]): Active client records as
            ``(client, clientDoer, datetime)`` triples.

    Doers:
        clientDo: Background generator that periodically scans for and
            removes timed-out clients.
    """

    TimeoutClient = 300  # seconds to wait for response before removing client, default is 5 minutes

    def __init__(self):
        """Initialize clienter with an empty list of client tuples.

        Attributes:
            clients (list[tuple]): Active client tuples, each containing a
                ``ClientDoer`` instance, an hio HTTP ``Client`` instance,
                and a ``datetime`` timestamp.
            doers (list): Doers managed by this Clienter, initialized with clientDo.
        """
        self.clients = []
        doers = [doing.doify(self.clientDo)]
        super(Clienter, self).__init__(doers=doers)

    def request(self, method, url, body=None, headers=None):
        """Issues an HTTP request and registers the client in the managed pool.

        Parses ``url``, constructs a :class:`~hio.core.http.clienting.Client`,
        sends the request, wraps the client in a
        :class:`~hio.core.http.clienting.ClientDoer`, and appends both to the
        internal ``clients`` list alongside the current UTC timestamp.

        Args:
            method (str): HTTP method (e.g., ``"GET"``, ``"POST"``).
            url (str): Fully qualified URL including scheme, host, port, path,
                and optional query string.
            body (str or bytes, optional): Request body.  ``str`` values are
                encoded to UTF-8 before sending.  Defaults to ``None``.
            headers (dict, optional): Request headers.  Defaults to ``None``.

        Returns:
            hio.core.http.clienting.Client: The client used to send the request,
            or ``None`` if the connection could not be established.
        """
        purl = parse.urlparse(url)

        try:
            client = http.clienting.Client(scheme=purl.scheme,
                                           hostname=purl.hostname,
                                           port=purl.port,
                                           portOptional=True)
        except Exception as e:
            print(f"error establishing client connection={e}")
            return None

        if hasattr(body, "encode"):
            body = body.encode("utf-8")

        client.request(
            method=method,
            path=f"{purl.path}?{purl.query}",
            qargs=None,
            headers=headers,
            body=body
        )

        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])
        self.clients.append((client, clientDoer, nowUTC()))

        return client

    def remove(self, client):
        """Removes a client and its associated doer from the managed pool.

        Looks up the first entry in ``self.clients`` whose client object
        matches ``client``, removes it from the list, and delegates doer
        removal to the parent :class:`~hio.base.doing.DoDoer`.  No-ops if
        ``client`` is not found.

        Args:
            client (hio.core.http.clienting.Client): The client instance to
                remove.
        """
        doers = [(c, d, dt) for (c, d, dt) in self.clients if c == client]
        if len(doers) == 0:
            return

        tup = doers[0]
        self.clients.remove(doers[0])
        (_, doer, _) = tup
        super(Clienter, self).remove([doer])

    def clientDo(self, tymth, tock=0.0, **kwa):
        """Background coroutine that prunes timed-out clients.

        Runs continuously, yielding between iterations.  On each pass,
        collects clients that have received a response and whose elapsed
        time since creation exceeds :attr:`TimeoutClient`, then removes
        them via :meth:`remove`.

        Args:
            tymth (callable): Injected closure returned by ``.tymen()`` on
                the governing :class:`~hio.base.tyming.Tymist`.  Calling
                ``tymth()`` returns the current tyme.
            tock (float): Initial tock value injected by the DoDoer
                framework.  Controls the yield cadence.
            **kwa: Additional keyword arguments (unused).

        Yields:
            float: ``self.tock`` on each iteration to cede control back to
            the hio scheduler.
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            toRemove = []
            for (client, doer, dt) in self.clients:
                if client.responses:
                    now = nowUTC()
                    if (now - dt) > datetime.timedelta(seconds=self.TimeoutClient):
                        toRemove.append(client)

                yield self.tock

            for client in toRemove:
                self.remove(client)

            yield self.tock
