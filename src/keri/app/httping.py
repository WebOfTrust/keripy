# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import json
from dataclasses import dataclass

import falcon
from hio.help import Hict

from keri import help
from keri import kering
from keri.core import coring, parsing
from keri.end import ending

logger = help.ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"


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


def createCESRRequest(msg, client, path=None):
    """
    Turns a KERI message into a CESR http request against the provided hio http Client

    Parameters
       msg:  KERI message parsable as Serder.raw
       client: hio http Client that will send the message as a CESR request

    """
    path = path if path is not None else "/"

    try:
        serder = coring.Serder(raw=msg)
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
        (CESR_ATTACHMENT_HEADER, attachments)
    ])

    client.request(
        method="POST",
        path=path,
        headers=headers,
        body=body
    )


def streamCESRRequests(client, ims, path=None):
    """
    Turns a stream of KERI messages into CESR http requests against the provided hio http Client

    Parameters
       ims (bytearray):  stream of KERI messages parsable as Serder.raw
       client (Client): hio http Client that will send the message as a CESR request
       path (str): path to post to

    """
    path = path if path is not None else "/"

    cold = parsing.Parser.sniff(ims)  # check for spurious counters at front of stream
    if cold in (parsing.Colds.txt, parsing.Colds.bny):  # not message error out to flush stream
        # replace with pipelining here once CESR message format supported.
        raise kering.ColdStartError("Expecting message counter tritet={}"
                                    "".format(cold))

    # Otherwise its a message cold start
    while ims:  # extract and deserialize message from ims
        try:
            serder = coring.Serder(raw=ims)
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
            (CESR_ATTACHMENT_HEADER, attachment)
        ])

        client.request(
            method="POST",
            path=path,
            headers=headers,
            body=body
        )


