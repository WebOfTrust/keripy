# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse
import logging

import falcon
from hio.core import http
from hio.core.tcp import serving

from keri import help
from keri.app import directing, indirecting, habbing, storing

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
parser.add_argument('--controller',
                    action='store',
                    default="",
                    help="Identifier prefix of controller of this watcher")
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def startWatcher(args):
    name = args.name
    tcpPort = int(args.tcp)
    httpPort = int(args.http)

    help.ogler.level = logging.INFO
    help.ogler.reopen(name="keri", temp=True, clear=True)
    doers = setupWatcher(name, controller=args.controller, alias=args.alias, base=args.base, bran=args.bran,
                         tcpPort=tcpPort, httpPort=httpPort)
    return doers


def setupWatcher(name="watcher", controller=None, alias="watcher", base="", bran=None, tcpPort=5651, httpPort=5652):
    """
    """

    hby = habbing.Habery(name=name, base=base, bran=bran)
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
    doers = [hbyDoer]
    hab = hby.makeHab(name=alias, transferable=False)

    app = falcon.App(cors_enable=True)

    mbx = storing.Mailboxer(name=name)
    rep = storing.Respondant(hby=hby, mbx=mbx)

    httpEnd = indirecting.HttpEnd(hab=hab, app=app, rep=rep, mbx=mbx)
    app.add_route("/", httpEnd)

    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    server = serving.Server(host="", port=tcpPort)
    serverDoer = serving.ServerDoer(server=server)

    directant = directing.Directant(hab=hab, server=server)

    doers.extend([directant, serverDoer, httpServerDoer, httpEnd, rep])

    return doers
