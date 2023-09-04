# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging

from keri import __version__
from keri import help
from keri.app import indirecting, storing, habbing
from keri.app.cli.common import existing
from keri.core import scheming
from keri.peer import exchanging
from keri.vc import walleting, protocoling
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

    return runWallet(name=args.name)


def runWallet(name="wallet", base="", bran=None):
    """
    Setup and run one wallet
    """

    hby = existing.setupHby(name=name, base=base, bran=bran)
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
    doers = [hbyDoer]

    verifier = verifying.Verifier(hby=hby)
    wallet = walleting.Wallet(reger=verifier.reger, name=name)
    walletDoer = walleting.WalletDoer(hby=hby, verifier=verifier)

    jsonSchema = scheming.JSONSchema(resolver=scheming.CacheResolver(db=hby.db))
    issueHandler = protocoling.IssueHandler(hby=hby, verifier=verifier)
    requestHandler = protocoling.PresentationRequestHandler(hby=hby, wallet=wallet, typ=jsonSchema)
    exchanger = exchanging.Exchanger(hby=hby, handlers=[issueHandler, requestHandler])

    mbx = storing.Mailboxer(name=name)
    rep = storing.Respondant(hby=hby, mbx=mbx)
    mdir = indirecting.MailboxDirector(hby=hby, exc=exchanger, rep=rep, topics=["/receipt", "/replay", "/credential"])

    doers.extend([exchanger, mdir, rep, walletDoer])

    return doers