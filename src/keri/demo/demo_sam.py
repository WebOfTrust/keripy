# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import os
import argparse
import logging


from keri import __version__
from keri import help  # logger support

from keri import core

from keri.app import directing
from keri.demo import demoing



def runDemo(name="sam", remote=5621, local=5620, expire=0.0):
    """
    Setup and run one demo controller for sam, like bob only better
    """

    raw = b"raw salt to test"

    #  create secrecies
    secrecies = [[signer.qb64] for signer in
                 core.Salter(raw=raw).signers(count=8,
                                                path=name,
                                                temp=True)]


    doers = demoing.setupDemoController(secrecies=secrecies,
                                        name=name,
                                        remotePort=remote,
                                        localPort=local)

    directing.runController(doers=doers, expire=expire)



def parseArgs(version=__version__):
    d = "Runs KERI direct mode demo controller.\n"
    d += "Example:\nkeri_bob -r 5621 -l 5620 --e 10.0'\n"
    p = argparse.ArgumentParser(description=d)
    p.add_argument('-V', '--version',
                   action='version',
                   version=version,
                   help="Prints out version of script runner.")
    p.add_argument('-r', '--remote',
                   action='store',
                   default=5621,
                   help="Remote port number the client connects to. Default is 5621.")
    p.add_argument('-l', '--local',
                   action='store',
                   default=5620,
                   help="Local port number the server listens on. Default is 5620.")
    p.add_argument('-e', '--expire',
                   action='store',
                   default=0.0,
                   help="Expire time for demo. 0.0 means not expire. Default is 0.0.")
    p.add_argument('-n', '--name',
                   action='store',
                   default="sam",
                   help="Name of controller. Default is sam. Choices are bob, sam, or eve.")


    args = p.parse_args()

    return args


def main():
    args = parseArgs(version=__version__)

    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Demo for %s listening on %s connecting to "
                 "%s.******\n\n", args.name, args.local, args.remote)

    runDemo(name=args.name,
            remote=args.remote,
            local=args.local,
            expire=args.expire)

    logger.info("\n******* Ended Demo for %s listening on %s connecting to "
                 "%s.******\n\n", args.name, args.local, args.remote)


if __name__ == "__main__":
    main()

