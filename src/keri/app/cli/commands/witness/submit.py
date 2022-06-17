# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json
from dataclasses import dataclass
from json import JSONDecodeError

import sys
from hio import help
from hio.base import doing

from keri.app import habbing, agenting, indirecting, configing, delegating, forwarding
from keri.app.cli.common import existing
from keri.core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config", "-c", help="directory override for configuration data")

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)

def handler(args):
    """
    Submit KERI identifier prefix to its witnesses for receipts.

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias

    icpDoer = InceptDoer(name=name, base=base, alias=alias, bran=bran)

    doers = [icpDoer]
    return doers


class InceptDoer(doing.DoDoer):
    """ DoDoer for creating a new identifier prefix and Hab with an alias.
    """

    def __init__(self, name, base, alias, bran, ):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.mbx = indirecting.MailboxDirector(hby=hby, topics=['/receipt', "/replay", "/reply"])
        self.alias = alias
        self.hby = hby

        self.witDoer = None
        doers = [self.hbyDoer,  self.mbx, doing.doify(self.inceptDo)]

        super(InceptDoer, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0):
        """
        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.extend([self.witDoer])

        if hab.kever.wits:
            print("Waiting for witness receipts...")
            self.witDoer.msgs.append(dict(pre=hab.pre))
            while not self.witDoer.cues:
                _ = yield self.tock

        print(f'Prefix  {hab.pre}')
        for idx, verfer in enumerate(hab.kever.verfers):
            print(f'\tPublic key {idx + 1}:  {verfer.qb64}')
        print()

        toRemove = [self.hbyDoer, self.witDoer, self.mbx]
        self.remove(toRemove)

        return

