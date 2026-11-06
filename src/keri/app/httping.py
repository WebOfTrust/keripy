# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import datetime
import hashlib
import hmac
import json
import re
import ssl
from dataclasses import dataclass
from urllib import parse

import falcon
from hio.base import doing
from hio.core import http, tcp
from hio.help import Hict, ogler

from ..kering import (ShortageError, ExtractionError,
                      ColdStartError, sniff, Colds, Decls, Schemes)
from ..core import SerderKERI
from ..end import designature
from ..help import nowUTC


logger = ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"
CESR_DESTINATION_HEADER = "CESR-DESTINATION"


class SignatureValidationComponent(object):
    """ Validate SKWA signatures """

    def __init__(self, hby, pre):
        self.hby = hby
        self.pre = pre

    def process_request(self, req, resp):
        """ Process request to ensure has a valid signature from controller

        Parameters:
            req: Http request object
            resp: Http response object

        """
        sig = req.headers.get("SIGNATURE")
        ked = req.media
        ser = json.dumps(ked).encode("utf-8")
        if not self.validate(sig=sig, ser=ser):
            resp.complete = True
            resp.status = falcon.HTTP_401
            return

    def validate(self, sig, ser):
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
    payload: dict
    attachments: str


def parseCesrHttpRequest(req):
    """
    Parse Falcon HTTP request and create a CESR message from the body of the request and the two
    CESR HTTP headers (Date, Attachment).

    Parameters
        req (falcon.Request) http request object in CESR format:

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
    """
    Turns a KERI message into a CESR http request against the provided hio http Client

    Parameters
       msg:  KERI message parsable as Serder.raw
       dest (str): qb64 identifier prefix of destination controller
       client: hio http Client that will send the message as a CESR request
       path (str): path to post to

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
    """
    Turns a stream of KERI messages into CESR http requests against the provided hio http Client

    Parameters
       client (Client): hio http Client that will send the message as a CESR request
       ims (bytearray):  stream of KERI messages parsable as Serder.raw
       dest (str): qb64 identifier prefix of destination controller
       path (str): path to post to

    Returns
       int: Number of individual requests posted

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
            serder = SerderKERI(raw=ims)
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


# The attrib a peer declares, in a /decl/attribs reply, to say which TLS certificate it serves.
TlsCertPinAttrib = "tls-cert-sha256"

# 64 hex digits, either run together or as colon-separated pairs (the openssl -fingerprint form).
_PinHex = re.compile(r"[0-9A-Fa-f]{64}|(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}")


def declaredCertPin(db, eid):
    """Return the SHA-256 of the TLS certificate ``eid`` declared, as 32 bytes, or None.

    The value is read from the /decl/attribs map that BADA accepted for ``eid`` itself (see
    DeclRecord), so the pin is authenticated by the peer's own key state, not by a certificate
    authority. A value this code does not recognize as a SHA-256 fingerprint is treated as absent,
    as DeclRecord requires, which leaves the connection to the CA check.

    Parameters:
        db (Baser): database holding accepted declarations
        eid (str): qb64 prefix of the peer being connected to

    Returns:
        bytes | None: the 32-byte digest, or None when nothing usable is declared."""
    record = db.decls.get(keys=(eid, Decls.attribs))
    if record is None:
        return None
    value = record.attribs.get(TlsCertPinAttrib)
    if not isinstance(value, str) or not _PinHex.fullmatch(value):
        return None
    return bytes.fromhex(value.replace(":", ""))


def _unverifiedContext():
    """A client context that completes a handshake without judging the certificate.

    The handshake still proves the server holds the private key of the certificate it shows; what
    is skipped is the CA chain and the hostname, which the caller replaces with its own check."""
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class PinnedClientTls(tcp.ClientTls):
    """A hio TLS connector that accepts exactly one certificate: the one whose SHA-256 is ``pin``.

    The pin replaces the CA and hostname checks rather than adding to them, because the peer it is
    for has no CA. The comparison runs as soon as the handshake completes and before the connector
    reports itself connected, so a mismatch closes the connection with nothing sent over it.

    Why a pin and not simply skipping verification for witnesses: KERI messages are signed, so an
    interloper on an unverified connection cannot forge events or receipts, but it can read the
    traffic, including the Authorization header HTTPMessenger sends with witness 2FA codes. A pin
    authenticates the peer by its own key state and closes that.

    A mismatch is refused, not raised. It is routine -- a witness renews its certificate before
    this consumer has re-resolved its OOBI -- and an exception from the handshake leaves hio's
    ClientDoer and ends the whole Doist, which on restart reads the same pin and ends again. So the
    connector logs an error naming the remedy, marks itself ``refused``, and stays closed for its
    lifetime, failing closed without hammering the peer with reconnects.

    Attributes:
        pin (bytes): the SHA-256 digest a presented certificate must have
        refused (bool): True once a presented certificate failed the pin
    """

    def __init__(self, pin, **kwa):
        """
        Parameters:
            pin (bytes): SHA-256 digest of the DER certificate the peer must present
            **kwa: passed to tcp.ClientTls, typically host and port"""
        if not isinstance(pin, bytes) or len(pin) != hashlib.sha256().digest_size:
            raise ValueError("A TLS pin is the 32-byte SHA-256 of a certificate.")
        super(PinnedClientTls, self).__init__(context=_unverifiedContext(), **kwa)
        self.pin = pin
        self.refused = False

    def connect(self):
        """Attempt a connection, unless a certificate has already failed the pin."""
        if self.refused:
            return False
        return super(PinnedClientTls, self).connect()

    def handshake(self):
        """Complete the handshake, then refuse the connection unless the certificate is pinned."""
        if not super(PinnedClientTls, self).handshake():
            return False
        der = self.cs.getpeercert(binary_form=True)
        if der is None or not hmac.compare_digest(hashlib.sha256(der).digest(), self.pin):
            presented = hashlib.sha256(der).hexdigest() if der is not None else None
            self.close()
            self.refused = True
            logger.error("Refused TLS connection to %s: its certificate (SHA-256 %s) is not the "
                         "one it declared (%s). If it renewed its certificate, re-resolve its "
                         "OOBI to learn the new declaration.", self.ha, presented, self.pin.hex())
            return False
        return True


class BootstrapClientTls(tcp.ClientTls):
    """A hio TLS connector for fetching an OOBI before any pin for its peer is held.

    It makes the ordinary CA and hostname check first. Only if that check fails does it reconnect
    once without verifying the certificate. That is safe only for an OOBI whose answer is checked
    against its own URL -- the signed KEL of the AID the path names, or data whose SAID the path
    names -- and Oobiery uses it for nothing else. The request carries no secret, so an interloper
    can read public data or withhold it but cannot change what is believed. A caller must not take
    anything from such a response that is not checked that way, such as the KERI-AID header.

    Attributes:
        verified (bool | None): True when the CA check passed, False when the connection was made
            without it, None before a handshake has completed."""

    def __init__(self, **kwa):
        super(BootstrapClientTls, self).__init__(**kwa)
        self.verified = None

    def handshake(self):
        try:
            done = super(BootstrapClientTls, self).handshake()
        except ssl.SSLCertVerificationError as ex:
            if self.verified is False:  # already unverified, so this is not a CA failure
                raise
            logger.info("CA check failed for %s (%s); fetching the OOBI without it, since what it "
                        "returns is verified on arrival.", self.ha, ex)
            self.verified = False
            self.context = _unverifiedContext()
            self.reopen()  # connect() accepts and wraps again under the new context
            return False
        if done and self.verified is None:
            self.verified = True
        return done


def _hostPort(url):
    up = parse.urlparse(url)
    return up, dict(host=up.hostname, port=up.port or 443)


def tlsConnector(db, eid, url, **kwa):
    """Return the connector for an https connection to ``eid``: pinned when it declared a
    certificate, else None, which leaves hio to make its ordinary CA-checked connection.

    Parameters:
        db (Baser): database holding accepted declarations
        eid (str): qb64 prefix of the peer that ``url`` belongs to
        url (str): the endpoint being connected to
        **kwa: passed to the connector

    Returns:
        PinnedClientTls | None"""
    up, ha = _hostPort(url)
    if up.scheme != Schemes.https:
        return None
    pin = declaredCertPin(db, eid)
    if pin is None:
        return None
    return PinnedClientTls(pin=pin, **ha, **kwa)


def bootstrapConnector(url, **kwa):
    """Return the connector for fetching an OOBI at ``url``, or None for plain http.

    It never consults a pin. Re-resolving a peer's OOBI is how a consumer learns that the peer
    rotated its certificate, so this fetch must not be held to the pin it is fetching a
    replacement for.

    Parameters:
        url (str): the OOBI being fetched
        **kwa: passed to the connector, such as cafilepath

    Returns:
        BootstrapClientTls | None"""
    up, ha = _hostPort(url)
    if up.scheme != Schemes.https:
        return None
    return BootstrapClientTls(**ha, **kwa)


# Status of the response a PinnedClient gives a request it refused, after nginx's 495 "SSL
# Certificate Error". It never came from the peer, which is why it is not a standard code.
TlsPinRefusedStatus = 495


class PinnedClient(http.clienting.Client):
    """A hio http Client over a PinnedClientTls that answers every request a refusal leaves
    stranded.

    A refused connector never connects, so without this its requests would never get a response,
    and every caller that waits for one -- Receiptor, the witness inquisitor, a messenger counting
    replies -- would wait forever on the witness. Each stranded request instead gets a response
    with status TlsPinRefusedStatus and ``errored`` set, which a caller treats like any failed
    request."""

    def service(self):
        super(PinnedClient, self).service()
        if not getattr(self.connector, "refused", False):
            return
        stranded = []
        if self.waited and self.latest is not None:
            stranded.append(self.latest)
        stranded.extend(self.requests)
        self.requests.clear()
        self.latest = None
        self.waited = False
        self.connector.txbs.clear()
        for request in stranded:
            self.responses.append(dict(version=None, status=TlsPinRefusedStatus,
                                       reason="TLS certificate does not match the declared pin",
                                       headers={}, body=bytearray(), data=None,
                                       request=request, errored=True,
                                       error="TLS pin refused"))


def makeClient(url, connector=None, **kwa):
    """Return a hio http Client for ``url`` over ``connector``.

    A PinnedClientTls gets a PinnedClient, so a refusal answers its requests. Either a pinned or a
    bootstrap connector turns off redirects, because hio rebuilds the connector for a redirect to
    another host with the same unverified context, and the new one keeps neither the pin nor the
    record that the connection was unverified.

    Parameters:
        url (str): the endpoint
        connector (tcp.ClientTls | None): from tlsConnector or bootstrapConnector, or None for
            hio's default
        **kwa: passed to http.clienting.Client, such as path

    Returns:
        http.clienting.Client"""
    up = parse.urlparse(url)
    if isinstance(connector, (PinnedClientTls, BootstrapClientTls)):
        kwa["redirectable"] = False
    klas = PinnedClient if isinstance(connector, PinnedClientTls) else http.clienting.Client
    return klas(scheme=up.scheme, hostname=up.hostname, port=up.port, connector=connector, **kwa)


def clientFor(db, eid, url, **kwa):
    """Return a hio http Client for ``url``, an endpoint of ``eid``, pinned if ``eid`` declared a
    certificate.

    Parameters:
        db (Baser): database holding accepted declarations
        eid (str): qb64 prefix of the peer that ``url`` belongs to
        url (str): the endpoint being connected to
        **kwa: passed to http.clienting.Client, such as path

    Returns:
        http.clienting.Client: a PinnedClient when pinned; see makeClient"""
    return makeClient(url, connector=tlsConnector(db, eid, url), **kwa)


class Clienter(doing.DoDoer):
    """
    Clienter is a DoDoer that manages hio HTTP clients using a ClientDoer for each HTTP request.
    It executes HTTP requests using a HIO HTTP Client run by a ClientDoer. Once a request has
    received a response then the corresponding Doer is removed from this Clienter.

    Doers:
        - clientDo: Periodically checks for stale clients and removes them if they have not received a response
          within the specified timeout period.
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

    def request(self, method, url, body=None, headers=None, connector=None):
        """
        Perform an HTTP request using a hio http Client and ClientDoer and returns the Client.

        Parameters:
            method (str): HTTP method to use (e.g., "GET", "POST")
            url (str): URL to send the request to
            body (str or bytes, optional): Body of the request, defaults to None
            headers (dict, optional): Headers to include in the request, defaults to None
            connector (tcp.ClientTls | None): TLS connector to use, such as one from
                tlsConnector or bootstrapConnector. None means hio's default for the scheme.
                Either kind also turns off redirects; see makeClient.

        Returns:
            http.clienting.Client: The hio HTTP Client used for the request, or None if an error occurs.
        """
        purl = parse.urlparse(url)

        try:
            client = makeClient(url, connector=connector, portOptional=True)
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
        """
        Find a client tuple by hio HTTP Client and remove it and its Doer from the Clienter.

        Parameters:
            client (http.clienting.Client): The hio HTTP Client to remove from the Clienter.
        """
        doers = [(c, d, dt) for (c, d, dt) in self.clients if c == client]
        if len(doers) == 0:
            return

        tup = doers[0]
        self.clients.remove(doers[0])
        (_, doer, _) = tup
        super(Clienter, self).remove([doer])

    def clientDo(self, tymth, tock=0.0, **kwa):
        """ Periodically prune stale clients

        Process existing clients and prune any that have receieved a response longer than timeout

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

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
