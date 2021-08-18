# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import json
import random
from dataclasses import dataclass

import falcon
from hio.base import doing
from hio.core import http
from hio.help import helping, Hict, decking

from .. import help
from .. import kering
from ..app import obtaining
from ..core import parsing, coring
from ..core.coring import Ilks
from ..help.helping import nowIso8601
from ..peer import exchanging

logger = help.ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"
CESR_DATE_HEADER = "CESR-DATE"
CESR_RECIPIENT_HEADER = "CESR-RECIPIENT"


@dataclass
class CesrRequest:
    resource: str
    recipient: str
    date: str
    payload: dict
    modifiers: dict
    attachments: str


def parseCesrHttpRequest(req, prefix=None):
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

    resource = req.path
    if prefix is not None:
        resource = resource.removeprefix(prefix)

    if CESR_DATE_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_UNAUTHORIZED,
                               title="Date error",
                               description="Missing required date header.")

    dt = req.headers[CESR_DATE_HEADER]

    if CESR_ATTACHMENT_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_PRECONDITION_FAILED,
                               title="Attachment error",
                               description="Missing required attachment header.")
    attachment = req.headers[CESR_ATTACHMENT_HEADER]
    recipient = req.headers[CESR_RECIPIENT_HEADER] if CESR_RECIPIENT_HEADER in req.headers else None

    cr = CesrRequest(
        resource=resource,
        recipient=recipient,
        date=dt,
        payload=data,
        modifiers=req.params,
        attachments=attachment)

    return cr


def createCESRRequest(msg, client, date=None):
    """
    Turns a KERI message into a CESR http request against the provided hio http Client

    Parameters
       msg:  KERI message parsable as Serder.raw
       client: hio http Client that will send the message as a CESR request

    """

    dt = date if date is not None else nowIso8601()
    try:
        serder = coring.Serder(raw=msg)
    except kering.ShortageError as ex:  # need more bytes
        raise kering.ExtractionError("unable to extract a valid message to send as HTTP")
    else:  # extracted successfully
        del msg[:serder.size]  # strip off event from front of ims

    ilk = serder.ked["t"]
    attachments = bytearray(msg)
    query = serder.ked["q"] if "q" in serder.ked else None

    if ilk in (Ilks.exn,):
        resource = "/" + ilk + serder.ked['r']
        body = json.dumps(serder.ked["d"]).encode("utf-8")
        dt = serder.ked["dt"]
    elif ilk in (Ilks.req,):
        resource = "/" + ilk + "/" + serder.ked['r']
        body = serder.raw
    elif ilk in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt, Ilks.ksn, Ilks.rct):
        resource = "/kel"
        body = serder.raw
    elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
        resource = "/tel"
        body = serder.raw
    else:
        raise kering.InvalidEventTypeError("Event type {} is not handled by http clients".format(ilk))

    headers = Hict([
        ("Content-Type", CESR_CONTENT_TYPE),
        ("Content-Length", len(body)),
        (CESR_DATE_HEADER, dt),
        (CESR_ATTACHMENT_HEADER, attachments)
    ])

    if "i" in serder.ked:
        headers[CESR_RECIPIENT_HEADER] = serder.pre

    client.request(
        method="POST",
        path=resource,
        qargs=query,
        headers=headers,
        body=body
    )


class MailboxServer(doing.DoDoer):
    """
    Message storage for Witnesses.  Provides an inbox service for storing messages for an identifier.

    """

    def __init__(self, mbx: exchanging.Mailboxer, app=None, **kwa):
        """
        Create Mailbox server for storing messages on a Witness for a witnessed
        identifier.

        Parameters:
             app(falcon.App): REST app to register routes with

        """

        self.mbx = mbx
        self.rxbs = bytearray()

        self.app = app if app is not None else falcon.App(cors_enable=True)

        self.app.add_route("/req/mbx", self)

        doers = []

        super(MailboxServer, self).__init__(doers=doers, **kwa)

    def on_get(self, req, rep):
        """
        Handles GET requests as a stream of SSE events

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        rep.stream = self.mailboxGenerator(query=req.params, resp=rep)

    def on_post(self, req, rep):
        """
        Handles GET requests as a stream of SSE events

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        cr = parseCesrHttpRequest(req=req)

        q = cr.payload['q']

        rep.stream = self.mailboxGenerator(query=q, resp=rep)


    @helping.attributize
    def mailboxGenerator(self, me, query=None, resp=None):
        """

        Parameters:
            me:
            query:
            resp:

        """
        pre = coring.Prefixer(qb64=query["i"])
        idx = int(query["s"]) if "s" in query else 0

        me._status = http.httping.OK

        headers = Hict()
        headers['Content-Type'] = "text/event-stream"
        headers['Cache-Control'] = "no-cache"
        headers['Connection'] = "keep-alive"
        me._headers = headers

        yield b'retry: 1000\n'

        while True:
            for fn, msg in self.mbx.clonePreIter(pre.qb64b, idx):
                data = bytearray("id: {}\nevent: data\ndata: ".format(fn).encode("utf-8"))
                data.extend(msg.encode("utf-8"))
                data.extend(b'\n\n')
                idx += 1
                yield data

            yield b''


class Respondant(doing.DoDoer):
    """
    Respondant processes buffer of response messages from inbound 'exn' messages and
    routes them to the appropriate mailbox.  If destination has witnesses, send response to
    one of the (randomly selected) witnesses.  Otherwise store the response in the recipients
    mailbox locally.

    """

    def __init__(self, hab, reps=None, cues=None, mbx=None, **kwa):
        """
        Creates Respondant that uses local environment to find the destination KEL and stores
        peer to peer messages in mbx, the mailboxer

        Parameters:
            hab (Habitat):  local environment
            mbx (Mailboxer): storage for local messages

        """
        self.reps = reps if reps is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.hab = hab
        self.mbx = mbx if mbx is not None else exchanging.Mailboxer(name=hab.name)

        doers = [doing.doify(self.responseDo), doing.doify(self.cueDo)]
        super(Respondant, self).__init__(doers=doers, **kwa)


    def responseDo(self, tymth=None, tock=0.0, **opts):
        """
        Doifiable Doist compatibile generator method to process response messages from `exn` handlers.
        If dest is not in local environment, ignore the response (for now).  If dest has witnesses,
        pick one at random and send the response to that witness for storage in the recipients mailbox
        on that witness.  Otherwise this is a peer to peer HTTP message and should be stored in a mailbox
        locally for the recipient.

        Usage:
            add result of doify on this method to doers list
        """
        while True:
            while self.reps:
                rep = self.reps.popleft()
                dest = rep["dest"]
                msg = rep["msg"]

                kever = self.hab.kevers[dest]
                if kever is None:
                    logger.Error("unable to reply, dest {} not found".format(dest))
                    continue

                if len(kever.wits) == 0:
                    self.mbx.storeMsg(dest=dest, msg=msg)
                else:
                    wit = random.choice(kever.wits)
                    loc = obtaining.getwitnessbyprefix(wit)

                    client = http.clienting.Client(hostname=loc.ip4, port=loc.http)
                    clientDoer = http.clienting.ClientDoer(client=client)

                    self.extend([clientDoer])

                    createCESRRequest(msg, client)

                    while not client.responses:
                        yield self.tock

                    self.remove([clientDoer])

                yield  # throttle just do one cue at a time
            yield



    def cueDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            Kevery and Tevery cues deque

        Usage:
            add result of doify on this method to doers list
        """
        yield  # enter context
        while True:
            while self.cues:  # iteratively process each cue in cues
                msg = bytearray()
                cue = self.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue

                if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                    serder = cue["serder"]  # Serder of received event for other pre
                    msg.extend(self.hab.receipt(serder))
                    print("storing receipt in", serder.pre)

                    self.mbx.storeMsg(dest=serder.preb, msg=msg)
                elif cueKin in ("replay",):
                    dest = cue["dest"]
                    msgs = cue["msgs"]
                    self.mbx.storeMsg(dest=dest.encode("utf-8"), msg=msgs)

                yield self.tock

            yield self.tock
