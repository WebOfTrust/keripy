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
from keri import help  # logger support
from keri.app import habbing, keeping, directing
from keri.db import dbing, basing
from keri.demo.demoing import IanDirector
from keri.vdr import issuing

logger = help.ogler.getLogger()


def runDemo(vcfile, did, lei, remote=5621, expire=0.0):
    """
    Setup and run one demo controller for sam, like bob only better
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

    doers = setupController(secrets=secrets,
                            vcfile=vcfile,
                            did=did,
                            lei=lei,
                            remotePort=remote)

    directing.runController(doers=doers, expire=expire)


def setupController(secrets, vcfile, did, lei, remotePort=5621, indirect=False):
    """
    Setup and return doers list to run controller
    """
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])

    # setup habitat
    hab = habbing.Habitat(name="ian", secrecies=secrecies, temp=True)
    logger.info("\nDirect Mode demo of %s:\nNamed %s to TCP port %s.\n\n",
                hab.pre, hab.name, remotePort)

    iss = issuing.Issuer(hab=hab, name="ian", noBackers=True)
    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)  # doer do reopens if not opened and closes
    dbDoer = basing.BaserDoer(baser=hab.db)  # doer do reopens if not opened and closes
    regDoer = basing.BaserDoer(baser=iss.reger)

    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')

    wl = wiring.WireLog(samed=True, filed=True, name="ian", prefix='demo', reopen=True,
                        headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)

    client = clienting.Client(host='127.0.0.1', port=remotePort, wl=wl)
    clientDoer = doing.ClientDoer(client=client)

    director = IanDirector(hab=hab,
                           issuer=iss,
                           client=client,
                           tock=0.125,
                           vcfile=vcfile,
                           recipientIdentifier=did,
                           lei=lei)

    reactor = directing.Reactor(hab=hab, client=client, indirect=indirect)

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
                   help="File name of verifiable credential to create on issuance (Required)")
    p.add_argument('-d', '--did',
                   action='store',
                   help="Recipient DID method specific identifier (Required)")
    p.add_argument('-l', '--lei',
                   action='store',
                   help="Legal Entity Identifier (Required)")

    args = p.parse_args()

    return args


def main():
    args = parseArgs(version=__version__)

    help.ogler.level = logging.INFO
    help.ogler.reopen(name="ian", temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Demo for Ian connecting to "
                "%s.******\n\n", args.remote)

    runDemo(vcfile=args.vc,
            did=args.did,
            lei=args.lei,
            remote=args.remote,
            expire=args.expire)

    logger.info("\n******* Ended Demo for Ian connecting to "
                "%s.******\n\n", args.remote)


if __name__ == "__main__":
    main()
