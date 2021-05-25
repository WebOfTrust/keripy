# -*- encoding: utf-8 -*-
"""
KERI
keri.cli.witness module

Witness command line interface
"""
import argparse
import logging

from keri import __version__
from keri import help  # logger support
from keri.base import directing
from keri.witness import witnessing


def runWitness(name="witness", local=5621, expire=0.0):
    """
    Setup and run one witness
    """

    doers = witnessing.setupWitness(name=name,
                                    localPort=local)

    directing.runController(doers=doers, expire=expire)



def parseArgs(version=__version__):
    d = "Runs KERI witness controller.\n"
    d += "Example:\nwitness -l 5621 --e 10.0\n"
    p = argparse.ArgumentParser(description=d)
    p.add_argument('-V', '--version',
                   action='version',
                   version=version,
                   help="Prints out version of script runner.")
    p.add_argument('-l', '--local',
                   action='store',
                   default=5621,
                   help="Local port number the server listens on. Default is 5620.")
    p.add_argument('-e', '--expire',
                   action='store',
                   default=0.0,
                   help="Expire time for demo. 0.0 means not expire. Default is 0.0.")
    p.add_argument('-n', '--name',
                   action='store',
                   default="witness",
                   help="Name of controller. Default is eve. Choices are bob, sam, or eve.")


    args = p.parse_args()

    return args


def main():
    args = parseArgs(version=__version__)

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


if __name__ == "__main__":
    main()

