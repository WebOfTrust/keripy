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
from hio.help import decking
from hio.core.tcp import clienting

from keri import __version__
from keri import help
from keri.app import habbing, keeping, directing
from keri.core import scheming
from keri.db import basing
from keri.demo.demoing import VicDirector
from keri.peer import exchanging
from keri.vc import handling
from keri.vdr import verifying


logger = help.ogler.getLogger()


def runDemo(witness=5621, peer=5629, expire=0.0):
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
                            witnessPort=witness,
                            peerPort=peer,
                            indirect=True)

    directing.runController(doers=doers, expire=expire)


def setupController(secrets, witnessPort=5621, peerPort=5629, indirect=False):
    """
    Setup and return doers list to run controller
    """
    name = "vic"

    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])

    # setup databases for dependency injection
    ks = keeping.Keeper(name=name, temp=True)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=True)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=True, secrecies=secrecies)
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

    verifier = verifying.Verifier(name=name, hab=hab)
    regDoer = basing.BaserDoer(baser=verifier.reger)

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')

    wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='demo', reopen=True,
                        headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)

    witnessClient = clienting.Client(host='127.0.0.1', port=witnessPort, wl=wl)
    witnessClientDoer = clienting.ClientDoer(client=witnessClient)

    peerClient = clienting.Client(host='127.0.0.1', port=peerPort, wl=wl)
    peerClientDoer = clienting.ClientDoer(client=peerClient)

    jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)

    proofs = decking.Deck()
    proofHandler = handling.ProofHandler(typ=jsonSchema, proofs=proofs)

    excDoer = exchanging.Exchanger(hab=hab, handlers=[proofHandler])
    director = VicDirector(hab=hab,
                           verifier=verifier,
                           witnessClient=witnessClient,
                           peerClient=peerClient,
                           exchanger=excDoer,
                           jsonSchema=jsonSchema,
                           proofs=proofs,
                           tock=0.125)


    witnessReactor = directing.Reactor(hab=hab, client=witnessClient, verifier=verifier, indirect=indirect)
    peerReactor = directing.Reactor(hab=hab, client=peerClient, verifier=verifier, indirect=indirect, exchanger=excDoer)

    logger.info("\nDirect Mode demo of %s:\nNamed %s to TCP port %s.\n\n",
                hab.pre, hab.name, witnessPort)


    return [ksDoer, dbDoer, habDoer, regDoer, excDoer, wireDoer,
            witnessClientDoer, director, witnessReactor,
            peerClientDoer, peerReactor]



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
                   default=5621,
                   help="Remote witness port number the witness client connects to. Default is 5621.")
    p.add_argument('-p', '--peer',
                   action='store',
                   default=5629,
                   help="Remote peer port number the peer client connects to. Default is 5629.")
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
                "%s.******\n\n", args.witness)

    runDemo(witness=args.witness,
            peer=int(args.peer),
            expire=args.expire)

    logger.info("\n******* Ended Demo for Vic connecting to "
                "%s.******\n\n", args.witness)


if __name__ == "__main__":
    main()

