# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging

from keri import __version__
from keri import help  # logger support
from keri.app import directing, indirecting

d = "Runs KERI witness controller.\n"
d += "Example:\nwitness -l 5621 --e 10.0\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-l', '--local',
                    action='store',
                    default=5621,
                    help="Local port number the server listens on. Default is 5620.")
parser.add_argument('-e', '--expire',
                    action='store',
                    default=0.0,
                    help="Expire time for demo. 0.0 means not expire. Default is 0.0.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="witness",
                    help="Name of controller. Default is eve. Choices are bob, sam, or eve.")


def launch(args):
    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Witness for %s listening on %s "
                ".******\n\n", args.name, args.local)

    runWitness(name=args.name,
               local=args.local,
               expire=args.expire)

    logger.info("\n******* Ended Witness for %s listening on %s"
                ".******\n\n", args.name, args.local)



def runWitness(name="witness", local=5621, expire=0.0):
    """
    Setup and run one witness
    """

    doers = indirecting.setupWitness(name=name,
                                     localPort=local)

    directing.runController(doers=doers, expire=expire)

