# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.mailbox module

Mailbox host command line interface.

This command starts the standalone mailbox host composition from
``keri.app.mailboxing`` around an existing non-transferable local habitat.
"""
import argparse
import logging
from urllib.parse import urlparse

from hio.help import ogler

from keri import __version__

from ...common import Parsery, setupHby

from ....app import runController, setupMailbox
from ....kering import Schemes


d = "Runs KERI mailbox host.\n"
d += "Example:\nmailbox start --alias relay --http 5632\n"
parser = argparse.ArgumentParser(description=d, parents=[Parsery.keystore()], conflict_handler='resolve')
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-H', '--http',
                    action='store',
                    default=5632,
                    help="Local port number the HTTP server listens on. Default is 5632.")
parser.add_argument('--alias', '-a', help='human readable alias for the local mailbox identifier', required=True)
parser.add_argument("--keypath", action="store", required=False, default=None)
parser.add_argument("--certpath", action="store", required=False, default=None)
parser.add_argument("--cafilepath", action="store", required=False, default=None)
parser.add_argument("--loglevel", action="store", required=False, default="CRITICAL",
                    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is CRITICAL")
parser.add_argument("--logfile", action="store", required=False, default=None,
                    help="path of the log file. If not defined, logs will not be written to the file.")


def launch(args):
    """CLI entrypoint that configures logging and runs one mailbox host."""
    ogler.level = logging.getLevelName(args.loglevel)
    if args.logfile is not None:
        ogler.headDirPath = args.logfile
        ogler.reopen(name=args.name, temp=False, clear=True)
    logger = ogler.getLogger()

    logger.info("\n******* Starting Mailbox for %s listening: http/%s .******\n\n", args.name, args.http)

    runMailbox(name=args.name,
               base=args.base,
               alias=args.alias,
               bran=args.bran,
               http=int(args.http),
               keypath=args.keypath,
               certpath=args.certpath,
               cafilepath=args.cafilepath)

    logger.info("\n******* Ended Mailbox for %s listening: http/%s .******\n\n", args.name, args.http)


def runMailbox(name="mailbox", base="", alias="mailbox", bran="", http=5632, expire=0.0,
               keypath=None, certpath=None, cafilepath=None):
    """Set up and run one mailbox host over an existing local mailbox habitat.

    The selected alias must resolve to a non-transferable local habitat because
    that identifier is the hosted mailbox AID used for:
        - mailbox authorization target checks
        - forwarded-message storage authorization
        - canonical root-shaped mailbox OOBI and ingress endpoints
    """
    hby = setupHby(name=name, base=base, bran=bran)
    hab = hby.habByName(alias)
    if hab is None:
        raise ValueError(f"invalid alias {alias}")

    doers = setupMailbox(alias=alias,
                         hby=hby,
                         httpPort=http,
                         keypath=keypath,
                         certpath=certpath,
                         cafilepath=cafilepath)

    runController(doers=doers, expire=expire)
