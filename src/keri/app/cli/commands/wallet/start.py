# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging

from hio.base import doing
from keri import __version__, kering
from keri import help
from keri.app import indirecting, storing
from keri.app.cli.common import existing
from keri.core import scheming
from keri.peer import exchanging
from keri.vc import walleting, handling
from keri.vdr import verifying

d = "Runs KERI Agent controller.\n"
d += "Example:\nagent -t 5621\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-V', '--version',
                    action='version',
                    version=__version__,
                    help="Prints out version of script runner.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="wallet",
                    help="Name of controller. Default is wallet.")



def launch(args):
    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Wallet for %s."
                ".******\n\n", args.name)

    runWallet(name=args.name)

    logger.info("\n******* Ended Wallet for %s."
                ".******\n\n", args.name)


def runWallet(name="wallet"):
    """
    Setup and run one wallet
    """

    hab, doers = existing.openHabitat(name=name)
    verifier = verifying.Verifier(hab=hab, name=name)
    wallet = walleting.Wallet(db=verifier.reger, name=name)
    walletDoer = walleting.WalletDoer(hab=hab, verifier=verifier)

    jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)
    issueHandler = handling.IssueHandler(hab=hab, verifier=verifier, typ=jsonSchema)
    requestHandler = handling.RequestHandler(wallet=wallet, typ=jsonSchema)
    exchanger = exchanging.Exchanger(hab=hab, handlers=[issueHandler, requestHandler])

    mbx = storing.Mailboxer(name=name)
    rep = storing.Respondant(hab=hab, mbx=mbx)
    mdir = indirecting.MailboxDirector(hab=hab, exc=exchanger, rep=rep, topics=["/receipt", "/replay", "/credential"])

    doers.extend([exchanger, mdir, rep, walletDoer])

    try:
        tock = 0.03125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
