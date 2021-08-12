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
from keri.app import indirecting
from keri.app.cli.common import existing
from keri.core import scheming
from keri.peer import httping, exchanging
from keri.vc import walleting, handling

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
    wallet = walleting.Wallet(hab=hab, name=name)

    jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)
    issueHandler = handling.IssueHandler(wallet=wallet, typ=jsonSchema)
    requestHandler = handling.RequestHandler(wallet=wallet, typ=jsonSchema)
    exchanger = exchanging.Exchanger(hab=hab, handlers=[issueHandler, requestHandler])

    mbx = exchanging.Mailboxer(name=name)
    rep = httping.Respondant(hab=hab, mbx=mbx)
    mdir = indirecting.MailboxDirector(hab=hab, exc=exchanger, rep=rep)

    doers.extend([exchanger, mdir, rep])

    try:
        tock = 0.03125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except kering.ConfigurationError:
        print(f"prefix for {name} does not exist, incept must be run first", )
