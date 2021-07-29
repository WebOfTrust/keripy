# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging

from keri import __version__
from keri import help
from keri.app import directing, indirecting

d = "Runs KERI witness controller.\n"
d += "Example:\nwitness -H 5631 -t 5632\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-H', '--http',
                    action='store',
                    default=5631,
                    help="Local port number the HTTP server listens on. Default is 5631.")
parser.add_argument('-T', '--tcp',
                    action='store',
                    default=5632,
                    help="Local port number the HTTP server listens on. Default is 5632.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="witness",
                    help="Name of controller. Default is witness.")


def launch(args):
    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Witness for %s listening: http/%s, tcp/%s "
                ".******\n\n", args.name, args.http, args.tcp)

    runWitness(name=args.name,
               tcp=int(args.tcp),
               http=int(args.http))

    logger.info("\n******* Ended Witness for %s listening: http/%s, tcp/%s"
                ".******\n\n", args.name, args.http, args.tcp)


def runWitness(name="witness", tcp=5631, http=5632, expire=0.0):
    """
    Setup and run one witness
    """

    doers = indirecting.setupWitness(name=name,
                                     tcpPort=tcp,
                                     httpPort=http)

    directing.runController(doers=doers, expire=expire)
