# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging

import falcon
from hio.base import doing
from hio.core import http
from hio.core.tcp import serving as tcpServing
from hio.help import decking

from keri import __version__, kering
from keri import help
from keri.app import directing, habbing, keeping, agenting, indirecting
from keri.core import scheming
from keri.db import basing
from keri.peer import httping, exchanging
from keri.vc import walleting, handling

d = "Runs KERI Agent controller.\n"
d += "Example:\nagent -t 5621\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-H', '--http',
                    action='store',
                    default=5620,
                    help="Local port number the HTTP server listens on. Default is 5620.")
parser.add_argument('-T', '--tcp',
                    action='store',
                    default=5621,
                    help="Local port number the HTTP server listens on. Default is 5621.")
parser.add_argument('-a', '--admin-http-port',
                    action='store',
                    default=5623,
                    help="Admin port number the HTTP server listens on. Default is 5623.")
parser.add_argument('-t', '--admin-tcp-port',
                    action='store',
                    default=5624,
                    help="Admin port number the HTTP server listens on. Default is 5624.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="agent",
                    help="Name of controller. Default is agent.")
parser.add_argument('-p', '--pre',
                    action='store',
                    default="",
                    help="Identifier prefix to accept control messages from.")



def launch(args):
    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Agent for %s listening: http/%s, tcp/%s "
                ".******\n\n", args.name, args.http, args.tcp)



    runAgent(controller=args.pre, name=args.name,
             httpPort=int(args.http),
             tcp=int(args.tcp),
             adminHttpPort=int(args.admin_http_port),
             adminTcpPort=int(args.admin_tcp_port))

    logger.info("\n******* Ended Agent for %s listening: http/%s, tcp/%s"
                ".******\n\n", args.name, args.http, args.tcp)


def runAgent(controller, name="agent", httpPort=5620, tcp=5621, adminHttpPort=5623, adminTcpPort=5624):
    """
    Setup and run one agent
    """

    ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

    # setup doers
    server = tcpServing.Server(host="", port=tcp)
    tcpServerDoer = tcpServing.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)

    wallet = walleting.Wallet(hab=hab, name=name)

    jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)
    issueHandler = handling.IssueHandler(wallet=wallet, typ=jsonSchema)
    requestHandler = handling.RequestHandler(wallet=wallet, typ=jsonSchema)
    proofHandler = handling.ProofHandler()
    exchanger = exchanging.Exchanger(hab=hab, handlers=[issueHandler, requestHandler, proofHandler])

    mbx = indirecting.MailboxDirector(hab=hab, exc=exchanger)

    doers = [ksDoer, dbDoer, habDoer, exchanger, directant, tcpServerDoer, mbx]
    doers.extend(adminInterface(controller, hab, proofHandler.proofs, adminHttpPort, adminTcpPort))

    try:
        tock = 0.03125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )


def adminInterface(controller, hab, proofs, adminHttpPort=5623, adminTcpPort=5624):
    echoHandler = agenting.EchoHandler()
    rotateHandler = agenting.RotateHandler(hab=hab)
    issueHandler = agenting.IssueCredentialHandler(hab=hab)
    requestHandler = agenting.PresentationRequestHandler(hab=hab)
    handlers = [rotateHandler, issueHandler, requestHandler, echoHandler]

    exchanger = exchanging.Exchanger(hab=hab, controller=controller, handlers=handlers)

    server = tcpServing.Server(host="", port=adminTcpPort)
    tcpServerDoer = tcpServing.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)

    # app = falcon.App(cors_enable=True)
    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))

    mbx = exchanging.Mailboxer(name=hab.name)
    rep = httping.Respondant(hab=hab, mbx=mbx)
    exnServer = httping.AgentExnServer(exc=exchanger, app=app, rep=rep)
    mbxer = httping.MailboxServer(app=app, hab=hab, mbx=mbx)
    proofHandler = AdminProofHandler(hab=hab, controller=controller, mbx=mbx, proofs=proofs)
    server = http.Server(port=adminHttpPort, app=exnServer.app)
    httpServerDoer = http.ServerDoer(server=server)

    doers = [exchanger, exnServer, tcpServerDoer, directant, httpServerDoer, rep, mbxer, proofHandler]

    return doers


class AdminProofHandler(doing.Doer):
    def __init__(self, hab, controller, mbx, proofs=None, **kwa):
        self.hab = hab
        self.controller = controller
        self.mbx = mbx
        self.proofs = proofs if proofs is not None else decking.Deck()

        super(AdminProofHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle proofs presented externally

        Parameters:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """

        while True:
            while self.proofs:
                (pre, vc) = self.proofs.popleft()

                pl = dict(
                    pre=pre.qb64,
                    vc=vc
                )

                ser = exchanging.exchange(route="/cmd/presentation/proof", payload=pl, recipient=self.controller)
                msg = self.hab.sanction(ser)

                print("STORING VC PROOF FOR MY CONTROLLER", self.controller)

                self.mbx.storeMsg(self.controller, msg)

                yield

            yield
