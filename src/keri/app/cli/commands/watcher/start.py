# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse

import falcon
from hio.core import http
from hio.core.tcp import serving
from keri.app import directing, indirecting
from keri.app.cli.common import existing
from keri.db import basing
from keri.peer import exchanging, httping
from keri import help

logger = help.ogler.getLogger()


parser = argparse.ArgumentParser(description='Start watcher')
parser.set_defaults(handler=lambda args: startWatcher(args))
parser.add_argument('-H', '--http',
                    action='store',
                    default=5651,
                    help="Local port number the HTTP server listens on. Default is 5651.")
parser.add_argument('-T', '--tcp',
                    action='store',
                    default=5652,
                    help="Local port number the HTTP server listens on. Default is 5652.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="watcher",
                    help="Name of controller. Default is watcher.")



def startWatcher(args):
    name = args.name
    tcpPort = int(args.tcp)
    httpPort = int(args.http)

    logger.info("\n******* Starting Watcher for %s listening: http/%s, tcp/%s "
                ".******\n\n", args.name, args.http, args.tcp)

    doers = setupWatcher(name, tcpPort=tcpPort, httpPort=httpPort)
    directing.runController(doers=doers, expire=0.0)

    logger.info("\n******* Ended Watcher for %s listening: http/%s, tcp/%s"
                ".******\n\n", args.name, args.http, args.tcp)


def setupWatcher(name="watcher", tcpPort=5651, httpPort=5652):
    """
    """

    hab, doers = existing.openHabitat(name=name)
    app = falcon.App(cors_enable=True)

    exchanger = exchanging.Exchanger(hab=hab, handlers=[])

    mbx = exchanging.Mailboxer(name=name)
    storeExchanger = exchanging.StoreExchanger(hab=hab, mbx=mbx, exc=exchanger)

    rep = httping.Respondant(hab=hab, mbx=mbx)
    httpHandler = indirecting.HttpMessageHandler(hab=hab, app=app, rep=rep, exchanger=storeExchanger)
    mbxer = httping.MailboxServer(app=app, hab=hab, mbx=mbx)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server, exc=storeExchanger)

    doers.extend([directant, serverDoer, mbxer, httpServerDoer, httpHandler, rep])

    return doers
