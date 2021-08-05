# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import argparse
import logging
import os

from hio.core import wiring
from hio.core.tcp import clienting, serving

from keri import __version__
from keri import help
from keri.app import habbing, keeping, directing
from keri.core import scheming
from keri.db import basing
from keri.demo.demoing import HanDirector
from keri.peer import exchanging
from keri.vc import walleting, handling

logger = help.ogler.getLogger()


def runDemo(witness=5631, local=5629, expire=0.0):
    """
    Setup and run one demo controller for Han, like bob only better
    """


    secrets = [
        'A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E',
        'A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q',
        'ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'
        'AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw',
        'AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc',
        'ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc',
        'AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y',
        'Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8',
    ]
    doers = setupController(secrets=secrets,
                            witnessPort=witness,
                            localPort=local)

    directing.runController(doers=doers, expire=expire)


def setupController(secrets, witnessPort=5631, localPort=5629, indirect=False):
    """
    Setup and return doers list to run controller
    """
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])

    # setup habitat
    hab = habbing.Habitat(name="han", secrecies=secrecies, temp=True)
    logger.info("\nDirect Mode demo of %s:\nNamed %s listening on TCP port %s, witness on TCP Port %s.\n\n",
                hab.pre, hab.name, localPort, witnessPort)
    wallet = walleting.Wallet(hab=hab, name="han")

    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)  # doer do reopens if not opened and closes
    dbDoer = basing.BaserDoer(baser=hab.db)  # doer do reopens if not opened and closes
    pdbDoer = basing.BaserDoer(baser=wallet.db)  # doer do reopens if not opened and closes

    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')

    wl = wiring.WireLog(samed=True, filed=True, name="han", prefix='demo', reopen=True,
                        headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)

    jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)

    issueHandler = handling.IssueHandler(wallet=wallet, typ=jsonSchema)
    requestHandler = handling.RequestHandler(wallet=wallet, typ=jsonSchema)

    witnessClient = clienting.Client(host='127.0.0.1', port=witnessPort, wl=wl)
    witnessClientDoer = clienting.ClientDoer(client=witnessClient)

    excDoer = exchanging.Exchanger(hab=hab, handlers=[issueHandler, requestHandler])
    director = HanDirector(hab=hab,
                           client=witnessClient,
                           exchanger=excDoer,
                           tock=0.125,
                           wallet=wallet)

    reactor = directing.Reactor(hab=hab, client=witnessClient, indirect=indirect)
    server = serving.Server(host="", port=localPort)
    serverDoer = serving.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server, exchanger=excDoer)

    return [ksDoer, dbDoer, pdbDoer, excDoer, wireDoer, witnessClientDoer, director, reactor, serverDoer, directant]


def parseArgs(version=__version__):
    d = "Runs KERI direct mode demo controller.\n"
    d += "Example:\nkeri_vic -r 5621 -l 5620 --e 10.0'\n"
    p = argparse.ArgumentParser(description=d)
    p.add_argument('-V', '--version',
                   action='version',
                   version=version,
                   help="Prints out version of script runner.")
    p.add_argument('-w', '--witness',
                   action='store',
                   default=5631,
                   help="Remote port number of the witness. Default is 5631.")
    p.add_argument('-l', '--local',
                   action='store',
                   default=5629,
                   help="Local port number the server listens on. Default is 5629.")
    p.add_argument('-e', '--expire',
                   action='store',
                   default=0.0,
                   help="Expire time for demo. 0.0 means not expire. Default is 0.0.")

    args = p.parse_args()

    return args


def main():
    args = parseArgs(version=__version__)

    help.ogler.level = logging.CRITICAL
    help.ogler.reopen(name="han", temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Demo for Han listening: tcp/%s "
                ".******\n\n", args.local)

    runDemo(witness=args.witness,
            local=int(args.local),
            expire=args.expire)

    logger.info("\n******* Ended Demo for Han listening: tcp/%s "
                ".******\n\n", args.local)


if __name__ == "__main__":
    main()
