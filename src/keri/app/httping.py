# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import datetime
import json
from dataclasses import dataclass
from urllib import parse
from urllib.parse import urlparse

import falcon
from hio.base import doing
from hio.core import http
from hio.help import Hict

from keri import help
from keri import kering
from keri.core import coring, parsing, serdering
from keri.end import ending
from keri.help import helping

logger = help.ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr+json"
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
        signages = ending.designature(sig)
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
        serder = serdering.SerderKERI(raw=msg)
    except kering.ShortageError as ex:  # need more bytes
        raise kering.ExtractionError("unable to extract a valid message to send as HTTP")
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


def streamCESRRequests(client, ims, dest, path=None):
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

    cold = parsing.Parser.sniff(ims)  # check for spurious counters at front of stream
    if cold in (parsing.Colds.txt, parsing.Colds.bny):  # not message error out to flush stream
        # replace with pipelining here once CESR message format supported.
        raise kering.ColdStartError("Expecting message counter tritet={}"
                                    "".format(cold))

    # Otherwise its a message cold start
    cnt = 0
    while ims:  # extract and deserialize message from ims
        try:
            serder = coring.Sadder(raw=ims)
        except kering.ShortageError as ex:  # need more bytes
            raise kering.ExtractionError("unable to extract a valid message to send as HTTP")
        else:  # extracted successfully
            del ims[:serder.size]  # strip off event from front of ims

        attachment = bytearray()
        while ims and ims[0] != 0x7b:  # not new message so process attachments, must support CBOR and MsgPack
            attachment.append(ims[0])
            del ims[:1]

        body = serder.raw

        headers = Hict([
            ("Content-Type", CESR_CONTENT_TYPE),
            ("Content-Length", len(body)),
            (CESR_ATTACHMENT_HEADER, attachment),
            (CESR_DESTINATION_HEADER, dest)
        ])

        client.request(
            method="POST",
            path=path,
            headers=headers,
            body=body
        )
        cnt += 1

    return cnt


class Clienter(doing.DoDoer):

    TimeoutClient = 300

    def __init__(self):
        self.clients = []
        doers = [doing.doify(self.clientDo)]
        super(Clienter, self).__init__(doers=doers)

    def request(self, method, url, body=None, headers=None):
        purl = parse.urlparse(url)

        try:
            client = http.clienting.Client(scheme=purl.scheme,
                                           hostname=purl.hostname,
                                           port=purl.port,
                                           portOptional=True)
        except Exception as e:
            print(f"error establishing client connection={e}")
            return None

        client.request(
            method=method,
            path=f"{purl.path}?{purl.query}",
            qargs=None,
            headers=headers,
            body=body
        )

        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])
        self.clients.append((client, clientDoer, helping.nowUTC()))

        return client

    def remove(self, client):
        doers = [(c, d, dt) for (c, d, dt) in self.clients if c == client]
        if len(doers) == 0:
            return

        tup = doers[0]
        self.clients.remove(doers[0])
        (_, doer, _) = tup
        super(Clienter, self).remove([doer])

    def clientDo(self, tymth, tock=0.0):
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
                    now = helping.nowUTC()
                    if (now - dt) > datetime.timedelta(seconds=self.TimeoutClient):
                        toRemove.append(client)

                yield self.tock

            for client in toRemove:
                self.remove(client)

            yield self.tock

