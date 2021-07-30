# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import json
from dataclasses import dataclass

import falcon
from hio.base import doing
from hio.core import http
from hio.help import helping, Hict

from .. import help
from .. import kering
from ..core import parsing, coring
from ..core.coring import Ilks
from ..help.helping import nowIso8601
from ..peer import exchanging

logger = help.ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"
CESR_DATE_HEADER = "CESR-DATE"
CESR_RECIPIENT_HEADER = "CESR-RECIPIENT"


class AgentExnServer(doing.DoDoer):
    """
    Peer 2 Peer HTTP Server that allows for handler registration of `exn` messages by providing an Exchanger
    that is configured with Handlers for all message types to handle.


    """

    RoutePrefix = "/exn"

    def __init__(self, exc, app, **kwa):
        """
        Registers all behaviors in provided Exchanged as routes to be handled in the provided Falcon app.
        POST requests are extracted and mapped to `exn` messages that are passed to the provided Exchanger.

        Parameters:
            exc (Exchanger): an the instance of Exchanger configured to handle behaviors
            app (falcon.App):  app to use for route registration

        """
        self.exc = exc
        self.rxbs = bytearray()

        self.app = app if app is not None else falcon.App()

        for route in exc.routes:
            self.app.add_route(self.RoutePrefix + route, self)

        self.parser = parsing.Parser(ims=self.rxbs,
                                     framed=True,
                                     kvy=None,
                                     tvy=None,
                                     exc=self.exc)

        doers = [self.exchangerDo, self.msgDo]

        super(AgentExnServer, self).__init__(doers=doers, **kwa)

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns Doist compatibile generator method (doer dog) to process
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
            add to doers list
        """
        if self.parser.ims:
            logger.info("Client exn-http received:\n%s\n...\n", self.parser.ims[:1024])
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close

    @doing.doize()
    def exchangerDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .tevery.cues deque

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
            add to doers list
        """
        while True:
            for msg in self.exc.processResponseIter():
                # TODO: figure out how to handle responses.
                print(msg)
                yield  # throttle just do one cue at a time
            yield

    def on_post(self, req, rep):
        """
        Handles POST requests by generating an `exn` message from the request and passing it to the Exchanger

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """

        cr = parseCesrHttpRequest(req=req, prefix=self.RoutePrefix)

        serder = exchanging.exchange(route=cr.resource, date=cr.date, payload=cr.payload)
        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.status = falcon.HTTP_202  # This is the default status


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

    if ilk in (Ilks.req, Ilks.exn):
        resource = "/" + ilk + serder.ked['r']
    elif ilk in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt, Ilks.ksn, Ilks.rct):
        resource = "/kel"
    elif ilk in (Ilks.vcp, Ilks.vrt, Ilks.iss, Ilks.rev, Ilks.bis, Ilks.brv):
        resource = "/tel"
    else:
        raise kering.InvalidEventTypeError("Event type {} is not handled by http clients".format(ilk))

    headers = Hict([
        ("Content-Type", CESR_CONTENT_TYPE),
        ("Content-Length", serder.size),
        (CESR_DATE_HEADER, dt),
        (CESR_ATTACHMENT_HEADER, attachments)
    ])

    if "i" in serder.ked:
        headers[CESR_RECIPIENT_HEADER] = serder.pre

    client.request(
        method="POST",
        path=resource,
        quargs=query,
        headers=headers,
        body=serder.raw
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

        self.app = app if app is not None else falcon.App()

        self.app.add_route("/req/mbx", self)

        doers = []

        super(MailboxServer, self).__init__(doers=doers, **kwa)

    def on_post(self, req, rep):
        """
        Handles POST requests as a stream of SSE events

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        rep.stream = self.mailboxGenerator(req=req, resp=rep)

    @helping.attributize
    def mailboxGenerator(self, me, req=None, resp=None):
        """

        Parameters:
            me:
            req:
            resp:

        """
        cr = parseCesrHttpRequest(req=req)

        q = cr.payload['q']

        pre = coring.Prefixer(qb64=q["i"])
        idx = int(q["s"]) if "s" in q else 0
        cur = -1

        me._status = http.httping.CREATED

        headers = Hict()
        headers['Content-Type'] = "text/event-stream"
        headers['Cache-Control'] = "no-cache"
        headers['Connection'] = "keep-alive"
        me._headers = headers

        while True:
            if cur < idx:
                for msg in self.mbx.clonePreIter(pre.qb64b, idx):
                    cur += 1
                    data = bytearray("event: msg\ndata:".format(cur).encode("utf-8"))
                    data.extend(msg.encode("utf-8"))
                    data.extend(b'\n\n')
                    yield data

            yield b''
