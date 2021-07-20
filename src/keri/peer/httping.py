# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import json

import falcon
from hio.base import doing
from hio.core import http
from hio.help import helping, Hict

from .. import help
from ..app import habbing
from ..core import parsing, eventing, coring
from ..peer import exchanging

logger = help.ogler.getLogger()


CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "X-CESR-ATTACHMENT"
CESR_DATE_HEADER = "X-CESR-DATE"


class AgentExnServer(doing.DoDoer):
    """
    Peer 2 Peer HTTP Server that allows for handler registration of `exn` messages by providing an Exchanger
    that is configured with Handlers for all message types to handle.


    """

    RoutePrefix = "/exn"

    def __init__(self, exc: exchanging.Exchanger, app, **kwa):
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
        Handles POST requests
        """

        resource, dt, q, signerSeal = parseCesrHttpRequest(req)

        resource = resource.removeprefix(self.RoutePrefix)

        serder = exchanging.exchange(route=resource, date=dt, payload=q)
        msg = bytearray(serder.raw)
        msg.extend(signerSeal.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.status = falcon.HTTP_202  # This is the default status


class AgentKelServer(doing.DoDoer):

    def __init__(self, hab: habbing.Habitat, app=None, **kwa):
        self.hab = hab
        self.rxbs = bytearray()

        self.app = app if app is not None else falcon.App()

        self.app.add_route("/", self)
        self.app.add_route("/req/logs", self, suffix="req")
        self.app.add_route("/req/tels", self, suffix="req")

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=False)

        self.parser = parsing.Parser(ims=self.rxbs,
                                     framed=True,
                                     kvy=self.kevery,
                                     tvy=None,
                                     exc=None)


        doers = [self.msgDo]

        super(AgentKelServer, self).__init__(doers=doers, **kwa)


    def on_post(self, req, rep):
        """
        Handles POST requests
        """

        resource, dt, q, attachments = parseCesrHttpRequest(req)

        # TODO:  do we want to time window KEL messages here?

        serder = eventing.Serder(ked=q, kind=eventing.Serials.json)
        msg = bytearray(serder.raw)
        msg.extend(attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.status = falcon.HTTP_202  # This is the default status


    def on_post_req(self, req, rep):
        """
        Handles POST requests for `req` messages
        """

        resource, dt, q, attachments = parseCesrHttpRequest(req)

        serder = eventing.Serder(ked=q, kind=eventing.Serials.json)
        msg = bytearray(serder.raw)
        msg.extend(attachments.encode("utf-8"))

        self.rxbs.extend(msg)

        rep.stream = self.cueReplayGenerator(req=req, resp=rep)


    @helping.attributize
    def cueReplayGenerator(self, me, req=None, resp=None):
        """

        Parameters:
            me:
            req:
            resp:

        """
        yield b''
        return '{v="TEST", i="asfsadf", t="icp}'.encode("utf-8")


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
            logger.info("Client %s received:\n%s\n...\n", self.kevery, self.parser.ims[:1024])
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close



def parseCesrHttpRequest(req):
    if req.content_type != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(falcon.HTTP_NOT_ACCEPTABLE,
                               "Content type error",
                               "Unacceptable content type.")


    try:
        raw_json = req.bounded_stream.read()
    except Exception:
        raise falcon.HTTPError(falcon.HTTP_748,
                               "Read Error",
                               "Could not read the request body.")

    try:
        q = json.loads(raw_json)
    except ValueError:
        raise falcon.HTTPError(falcon.HTTP_753,
                               "Malformed JSON",
                               "Could not decode the request body. The "
                               "JSON was incorrect.")

    resource = req.path

    if CESR_DATE_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_UNAUTHORIZED,
                               "Date error",
                               "Missing required date header.")

    dt = req.headers[CESR_DATE_HEADER]

    if CESR_ATTACHMENT_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_PRECONDITION_FAILED,
                               "Attachment error",
                               "Missing required attachment header.")


    attachment = req.headers[CESR_ATTACHMENT_HEADER]

    return resource, dt, q, attachment


class MailboxServer(doing.DoDoer):
    """

    """

    def __init__(self, port, hab: habbing.Habitat, mbx: exchanging.Mailboxer, **kwa):
        """

        :param port:
        :param hab:
        :param kwa:
        """
        self.hab = hab
        self.mbx = mbx
        self.port = port
        self.rxbs = bytearray()

        self.app = falcon.App()

        self.app.add_route("/mbx", self)

        self.server = http.Server(port=self.port, app=self.app)
        serdoer = http.ServerDoer(server=self.server)


        doers = [serdoer]

        super(MailboxServer, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.server.wind(self.tymth)


    def on_post(self, req, rep):
        """
        Handles POST requests as a stream of SSE events
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

        resource, dt, msg, attachments = parseCesrHttpRequest(req)

        q = msg["q"]

        pre = coring.Prefixer(qb64=q["i"])
        idx = q["s"] if "s" in q else 0
        cur = -1

        yield b''


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
                    data = bytearray(b'data:')
                    data.extend(msg)
                    data.extend(b'\n\n')
                    yield data

            yield b''


