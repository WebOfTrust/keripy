# -*- encoding: utf-8 -*-
"""
KERI
keri.witness module

"""

import falcon
import keri.app.oobiing
from hio.core import http, tcp
from hio.core.tcp import serving
from hio.help import decking
from .http_end import HttpEnd
from .query_end import QueryEnd
from .receipt_end import ReceiptEnd
from .witness import Witness
from .. import help
from ..app import directing, storing, httping, oobiing
from ..core import (eventing, parsing, routing)
from ..db import basing
from ..end import ending
from ..vdr import verifying, viring
from ..vdr.eventing import Tevery

logger = help.ogler.getLogger()

def setup(hby, alias="witness", aids=None, tcpPort=5631, httpPort=5632,
          keypath=None, certpath=None, cafilepath=None):
        """
        Setup witness controller and doers

        """
        host = "0.0.0.0"
        cues = decking.Deck()
        doers = []

        # make hab
        hab = hby.habByName(name=alias)
        if hab is None:
            hab = hby.makeHab(name=alias, transferable=False)

        reger = viring.Reger(name=hab.name, db=hab.db, temp=False)
        verfer = verifying.Verifier(hby=hby, reger=reger)

        clienter = httping.Clienter()
        oobiery = keri.app.oobiing.Oobiery(hby=hby, clienter=clienter)

        app = falcon.App(cors_enable=True)
        ending.loadEnds(app=app, hby=hby, default=hab.pre)
        oobiing.loadEnds(app=app, hby=hby, prefix="/ext")
        rep = storing.Respondant(hby=hby, aids=aids)

        rvy = routing.Revery(db=hby.db, cues=cues)
        kvy = eventing.Kevery(db=hby.db,
                              lax=True,
                              local=False,
                              rvy=rvy,
                              cues=cues)
        kvy.registerReplyRoutes(router=rvy.rtr)

        tvy = Tevery(reger=verfer.reger,
                     db=hby.db,
                     local=False,
                     cues=cues)

        tvy.registerReplyRoutes(router=rvy.rtr)
        parser = parsing.Parser(framed=True,
                                kvy=kvy,
                                tvy=tvy,
                                rvy=rvy)

        httpEnd = HttpEnd(rxbs=parser.ims)
        app.add_route("/", httpEnd)
        receiptEnd = ReceiptEnd(hab=hab, inbound=cues, aids=aids)
        app.add_route("/receipts", receiptEnd)
        queryEnd = QueryEnd(hab=hab)
        app.add_route("/query", queryEnd)

        server = create(host, httpPort, app, keypath, certpath, cafilepath)
        if not server.reopen():
            raise RuntimeError(f"cannot create http server on port {httpPort}")
        httpServerDoer = http.ServerDoer(server=server)

        # setup doers
        regDoer = basing.BaserDoer(baser=verfer.reger)

        if tcpPort is not None:
            server = serving.Server(host="", port=tcpPort)
            if not server.reopen():
                raise RuntimeError(f"cannot create tcp server on port {tcpPort}")
            serverDoer = serving.ServerDoer(server=server)

            directant = directing.Directant(hab=hab, server=server, verifier=verfer)
            doers.extend([directant, serverDoer])

        witStart = Witness(hab=hab, parser=parser, cues=receiptEnd.outbound,
                           kvy=kvy, tvy=tvy, rvy=rvy, replies=rep.reps,
                           responses=rep.cues, queries=httpEnd.qrycues)

        doers.extend([regDoer, httpServerDoer, rep, witStart, receiptEnd, *oobiery.doers])
        return doers


def create(host, port, app, keypath=None, certpath=None, cafilepath=None):
    """
    Create an HTTP or HTTPS server depending on whether TLS key material is present
    Parameters:
        host(str)          : host to bind to for this server, or None for default of '0.0.0.0', all ifaces
        port (int)         : port to listen on for all HTTP(s) server instances
        app (Any)          : WSGI application instance to pass to the http.Server instance
        keypath (string)   : the file path to the TLS private key
        certpath (string)  : the file path to the TLS signed certificate (public key)
        cafilepath (string): the file path to the TLS CA certificate chain file
    Returns:
        hio.core.http.Server
    """
    if keypath is not None and certpath is not None and cafilepath is not None:
        servant = tcp.ServerTls(certify=False,
                                keypath=keypath,
                                certpath=certpath,
                                cafilepath=cafilepath,
                                port=port)
        server = http.Server(host=host, port=port, app=app, servant=servant)
    else:
        server = http.Server(host=host, port=port, app=app)
    return server