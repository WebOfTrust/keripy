# -*- encoding: utf-8 -*-
"""
keri.end.priming module

Prime (preload) setup witnesses, watchers, etc

"""
import sys
import os
import argparse
import logging

import keri
from keri import kering
from keri.core import coring, eventing

from keri import help

logger = help.ogler.getLogger()


def prime(name="main"):
    """
    Prime (preload) db with service endpoints
    """




def parseArgs(version=keri.__version__):
    d = "Runs KERI direct mode demo controller.\n"
    d += "Example:\npriming -n best'\n"
    p = argparse.ArgumentParser(description=d)
    p.add_argument('-V', '--version',
                   action='version',
                   version=version,
                   help="Prints out version of script runner.")
    p.add_argument('-n', '--name',
                   action='store',
                   default="main",
                   help="Name of habitat")


    args = p.parse_args()

    return args


def main():
    args = parseArgs(version=keri.__version__)

    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Priming %s.******\n\n", args.name)

    prime(name=args.name)

    logger.info("\n******* Ending Priming %s \n\n", args.name,)


if __name__ == "__main__":
    main()

