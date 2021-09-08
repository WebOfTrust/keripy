# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse
import logging
import sys

import falcon
from hio.core import http
from hio.core.tcp import serving
from keri import help, kering
from keri.app import directing, indirecting, watching, habbing, storing
from keri.app.cli.common import existing

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
parser.add_argument('-p', '--pre',
                    action='store',
                    default="",
                    help="Identifier prefix of controller of this watcher")



def startWatcher(args):
    name = args.name
    tcpPort = int(args.tcp)
    httpPort = int(args.http)

    help.ogler.level = logging.INFO
    help.ogler.reopen(name="keri", temp=True, clear=True)
    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Watcher for %s listening: http/%s, tcp/%s "
                ".******\n\n", args.name, args.http, args.tcp)

    doers = setupWatcher(name, controller=args.pre, tcpPort=tcpPort, httpPort=httpPort)
    directing.runController(doers=doers, expire=0.0)

    logger.info("\n******* Ended Watcher for %s listening: http/%s, tcp/%s"
                ".******\n\n", args.name, args.http, args.tcp)


def setupWatcher(name="watcher", controller=None, tcpPort=5651, httpPort=5652):
    """
    """

    try:
        with habbing.existingHab(name=name, transferable=False) as hab:
            print("Watcher Identifier: {}".format(hab.pre))
            if hab.kever.prefixer.transferable:
                raise kering.ConfigurationError("watchers can only have a non-transferable identifier")
    except kering.ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        sys.exit(-1)

    hab, doers = existing.openHabitat(name=name, transferable=False)
    app = falcon.App(cors_enable=True)

    mbx = storing.Mailboxer(name=name)
    rep = storing.Respondant(hab=hab, mbx=mbx)

    kiwiServer = watching.KiwiServer(hab=hab, app=app, rep=rep, controller=controller)

    httpHandler = indirecting.HttpMessageHandler(hab=hab, app=app, rep=rep)
    mbxer = storing.MailboxServer(app=app, hab=hab, mbx=mbx)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server)

    doers.extend([directant, serverDoer, mbxer, httpServerDoer, httpHandler, rep, kiwiServer])

    return doers
