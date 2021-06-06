# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import argparse
import logging
import os

from hio.base import doing
from hio.core import wiring
from hio.core.tcp import clienting

from keri import __version__
from keri import help
from keri.app import habbing, keeping, directing
from keri.db import dbing, basing
from keri.demo.demoing import VicDirector
from keri.vdr import verifying

logger = help.ogler.getLogger()


def runDemo(vcfile, remote=5621, expire=0.0):
    """
    Setup and run one demo controller for Vic
    """
    secrets = [
                'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
                'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
                'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
                'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
                'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
                'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
                'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
                'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
                ]

    doers = setupController(secrets=secrets,
                            remotePort=remote,
                            indirect=True,
                            vcfile=vcfile)

    directing.runController(doers=doers, expire=expire)


def setupController(secrets, remotePort=5621, indirect=False, vcfile=""):
    """
    Setup and return doers list to run controller
    """
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])

    # setup habitat
    hab = habbing.Habitat(name="vic", secrecies=secrecies, temp=True)
    logger.info("\nDirect Mode demo of %s:\nNamed %s to TCP port %s.\n\n",
                hab.pre, hab.name, remotePort)

    verifier = verifying.Verifier(name="vic", hab=hab)
    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)  # doer do reopens if not opened and closes
    dbDoer = basing.BaserDoer(baser=hab.db)  # doer do reopens if not opened and closes
    regDoer = basing.BaserDoer(baser=verifier.reger)

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')

    wl = wiring.WireLog(samed=True, filed=True, name="vic", prefix='demo', reopen=True,
                        headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)

    client = clienting.Client(host='127.0.0.1', port=remotePort, wl=wl)
    clientDoer = doing.ClientDoer(client=client)

    director = VicDirector(vcfile=vcfile, hab=hab, verifier=verifier, client=client, tock=0.125)

    reactor = directing.Reactor(hab=hab, client=client, verifier=verifier, indirect=indirect)

    return [ksDoer, dbDoer, regDoer, wireDoer, clientDoer, director, reactor]


def parseArgs(version=__version__):
    d = "Runs KERI direct mode demo controller.\n"
    d += "Example:\nkeri_vic -r 5621 -l 5620 --e 10.0'\n"
    p = argparse.ArgumentParser(description=d)
    p.add_argument('-V', '--version',
                   action='version',
                   version=version,
                   help="Prints out version of script runner.")
    p.add_argument('-r', '--remote',
                   action='store',
                   default=5621,
                   help="Remote port number the client connects to. Default is 5621.")
    p.add_argument('-e', '--expire',
                   action='store',
                   default=0.0,
                   help="Expire time for demo. 0.0 means not expire. Default is 0.0.")
    p.add_argument('-v', '--vc',
                   action='store',
                   help="File name of verifiable credential to validate (Required)")


    args = p.parse_args()

    return args


def main():
    args = parseArgs(version=__version__)

    help.ogler.level = logging.INFO
    help.ogler.reopen(name="vic", temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Demo for Vic connecting to "
                "%s.******\n\n", args.remote)

    runDemo(vcfile=args.vc,
            remote=args.remote,
            expire=args.expire)

    logger.info("\n******* Ended Demo for Vic connecting to "
                "%s.******\n\n", args.remote)


if __name__ == "__main__":
    main()

