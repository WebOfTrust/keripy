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
from keri.base import directing
from keri.demo import demoing
from keri import help


def runDemo(name="bob", remote=5621, local=5620, expire=0.0):
    """
    Setup and run one demo controller for Bob
    """
    secrets = [
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                ]

    doers = demoing.setupDemoController(secrets=secrets,
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
                   default="bob",
                   help="Name of controller. Default is bob. Choices are bob, sam, or eve.")


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

