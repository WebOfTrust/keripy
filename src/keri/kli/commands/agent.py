# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging

from hio.base import doing
from hio.core.tcp import serving as tcpServing

from keri import __version__
from keri import help
from keri.app import directing, habbing, keeping
from keri.core import eventing
from keri.db import basing
from keri.demo import demoing
from keri.peer import httping, exchanging
from keri.vc import handling, walleting

d = "Runs KERI Agent controller.\n"
d += "Example:\nagent -p 5621 --e 10.0\n"
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
parser.add_argument('-t', '--tcp',
                    action='store',
                    default=5621,
                    help="Local port number the HTTP server listens on. Default is 5621.")
parser.add_argument('-e', '--expire',
                    action='store',
                    default=0.0,
                    help="Expire time for demo. 0.0 means not expire. Default is 0.0.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="agent",
                    help="Name of controller. Default is eve. Choices are bob, sam, or eve.")



def launch(args):
    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Agent for %s listening on %s "
                ".******\n\n", args.name, args.http)

    runAgent(name=args.name,
             http=int(args.http),
             tcp=int(args.tcp),
             expire=args.expire)

    logger.info("\n******* Ended Agent for %s listening on %s"
                ".******\n\n", args.name, args.http)



def runAgent(name="agent", http=5620, tcp=5621, expire=0.0):
    """
    Setup and run one agent
    """
    logger = help.ogler.getLogger()

    wsith = 1

    hab = habbing.Habitat(name=name, temp=False, transferable=True,
                          isith=wsith, icount=1,)
    kvy = eventing.Kevery(db=hab.db, local=False)
    logger.info("\nAgent- %s:\nNamed %s on HTTP port %s.\n\n",
                hab.pre, hab.name, http)

    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)  # doer do reopens if not opened and closes
    dbDoer = basing.BaserDoer(baser=hab.db)  # doer do reopens if not opened and closes

    server = tcpServing.Server(host="", port=tcp)
    serverDoer = tcpServing.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)

    excDoer = exchanging.Exchanger(hab=hab)

    wallet = walleting.Wallet(hab=hab, name=name)

    jsonSchema = demoing.jsonSchemaCache()
    issueHandler = handling.IssueHandler(wallet=wallet, typ=jsonSchema)
    excDoer.registerBehavior(route=issueHandler.resource, behave=issueHandler.behavior)
    requestHandler = handling.RequestHandler(wallet=wallet, typ=jsonSchema)
    excDoer.registerBehavior(route=requestHandler.resource, behave=requestHandler.behavior)

    httpServer = httping.AgentExnServer(port=http, exc=excDoer)
    httpKelServer = httping.AgentKelServer(port=5629, kvy=kvy)

    doers = [ksDoer, dbDoer, excDoer, directant, serverDoer, httpServer, httpKelServer]

    tock = 0.03125
    doist = doing.Doist(limit=expire, tock=tock, real=True)
    doist.do(doers=doers)

