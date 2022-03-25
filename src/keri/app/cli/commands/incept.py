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

parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)


@dataclass
class InceptOptions:
    """ Options loaded from file parameter.

    """
    transferable: bool
    wits: list
    icount: int
    isith: int
    ncount: int
    nsith: int
    toad: int = 0
    delpre: str = None
    estOnly: bool = False


def handler(args):
    """
    Create KERI identifier prefix in specified key store with alias

    Args:
        args(Namespace): arguments object from command line
    """

    try:
        f = open(args.file)
        config = json.load(f)

        opts = InceptOptions(**config)
    except FileNotFoundError:
        print("config file", args.file, "not found")
        sys.exit(-1)
    except JSONDecodeError:
        print("config file", args.file, "not valid JSON")
        sys.exit(-1)

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    config = args.config

    kwa = opts.__dict__
    icpDoer = InceptDoer(name=name, base=base, alias=alias, bran=bran, config=config, **kwa)

    doers = [icpDoer]
    return doers


class InceptDoer(doing.DoDoer):
    """ DoDoer for creating a new identifier prefix and Hab with an alias.
    """

    def __init__(self, name, base, alias, bran, config=None, **kwa):

        cf = None
        if config is not None:
            cf = configing.Configer(name=name,
                                    base=base,
                                    headDirPath=config,
                                    temp=False,
                                    reopen=True,
                                    clear=False)

        hby = existing.setupHby(name=name, base=base, bran=bran, cf=cf)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.swain = delegating.Boatswain(hby=hby)
        self.postman = forwarding.Postman(hby=hby)
        self.mbx = indirecting.MailboxDirector(hby=hby, topics=['/receipt', "/replay", "/reply"])
        self.witDoer = None
        doers = [self.hbyDoer, self.postman, self.mbx, self.swain, doing.doify(self.inceptDo)]

        self.inits = kwa
        self.alias = alias
        self.hby = hby
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

        hab = self.hby.makeHab(name=self.alias, **self.inits)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.extend([self.witDoer])

        if hab.kever.delegator:
            self.swain.msgs.append(dict(alias=self.alias, pre=hab.pre, sn=0))
            print("Waiting for delegation approval...")
            while not self.swain.cues:
                yield self.tock

        if hab.kever.wits:
            print("Waiting for witness receipts...")
            self.witDoer.msgs.append(dict(pre=hab.pre))
            while not self.witDoer.cues:
                _ = yield self.tock

        if hab.kever.delegator:
            yield from self.postman.sendEvent(hab=hab, fn=hab.kever.sn)

        print(f'Prefix  {hab.pre}')
        for idx, verfer in enumerate(hab.kever.verfers):
            print(f'\tPublic key {idx + 1}:  {verfer.qb64}')
        print()

        toRemove = [self.hbyDoer, self.witDoer, self.mbx, self.swain, self.postman]
        self.remove(toRemove)

        return

