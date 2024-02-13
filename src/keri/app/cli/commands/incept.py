# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
from dataclasses import dataclass

from hio import help
from hio.base import doing

from keri.app import habbing, agenting, indirecting, configing, delegating, forwarding
from keri.app.cli.common import existing, incepting, config
from keri.core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config", "-c", help="directory override for configuration data")
parser.add_argument("--receipt-endpoint", help="Attempt to connect to witness receipt endpoint for witness receipts.",
                    dest="endpoint", action='store_true')
parser.add_argument("--proxy", help="alias for delegation communication proxy", default="")

parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=False)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)
incepting.addInceptingArgs(parser)


@dataclass
class InceptOptions:
    """ Options loaded from file parameter.

    """
    transferable: bool | None
    wits: list | None
    icount: int | None
    isith: int | str | list | None
    ncount: int | None
    nsith: int | str | list | None = '0'
    toad: int = 0
    delpre: str = None
    estOnly: bool = False
    data: list = None


def handler(args):
    """
    Create KERI identifier prefix in specified key store with alias

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    config_dir = args.config
    endpoint = args.endpoint
    proxy = args.proxy

    kwa = mergeArgsWithFile(args).__dict__

    icpDoer = InceptDoer(name=name, base=base, alias=alias, bran=bran, endpoint=endpoint, proxy=proxy,
                         cnfg=config_dir, **kwa)

    doers = [icpDoer]
    return doers


def emptyOptions():
    """
    Initializes an empty inception options to be used only when required values are passed in at the command line
    """
    return InceptOptions(
        transferable=None, wits=None, icount=None, isith=None, ncount=None, nsith=None
    )


def mergeArgsWithFile(args):
    """
    Merge options specified with command line arguments with any specified config file
    with command line arguments taking precedence.
    """
    required_args = ['transferable', 'wits', 'icount', 'isith', 'ncount', 'nsith', 'toad']
    if args.file is None or args.file == '':
        config.checkRequiredArgs(args, required_args)

    incept_opts = config.loadFileOptions(args.file, InceptOptions) if args.file != '' else emptyOptions()

    incept_opts.transferable = True if args.transferable else incept_opts.transferable
    if len(args.wits) > 0:
        incept_opts.wits = args.wits
    if args.icount is not None:
        incept_opts.icount = int(args.icount)
    if args.toad is not None:
        incept_opts.toad = int(args.toad)
    if args.icount is not None:
        incept_opts.icount = int(args.icount)
    if args.isith is not None:
        incept_opts.isith = args.isith
    if args.ncount is not None:
        incept_opts.ncount = int(args.ncount)
    if args.nsith is not None:
        incept_opts.nsith = args.nsith
    if args.est_only is not None:
        incept_opts.estOnly = args.est_only
    if args.data is not None:
        incept_opts.data = config.parseData(args.data)

    return incept_opts


class InceptDoer(doing.DoDoer):
    """ DoDoer for creating a new identifier prefix and Hab with an alias.
    """

    def __init__(self, name, base, alias, bran, endpoint, proxy=None, cnfg=None, **kwa):

        cf = None
        if config is not None:
            cf = configing.Configer(name=name,
                                    base="",
                                    headDirPath=cnfg,
                                    temp=False,
                                    reopen=True,
                                    clear=False)
        self.endpoint = endpoint
        self.proxy = proxy
        hby = existing.setupHby(name=name, base=base, bran=bran, cf=cf)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.swain = delegating.Sealer(hby=hby)
        self.postman = forwarding.Poster(hby=hby)
        self.mbx = indirecting.MailboxDirector(hby=hby, topics=['/receipt', "/replay", "/reply"])
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
        witDoer = agenting.WitnessReceiptor(hby=self.hby)
        receiptor = agenting.Receiptor(hby=self.hby)
        self.extend([witDoer, receiptor])

        if hab.kever.delegator:
            self.swain.delegation(pre=hab.pre, sn=0, proxy=self.hby.habByName(self.proxy))
            print("Waiting for delegation approval...")
            while not self.swain.complete(hab.kever.prefixer, coring.Seqner(sn=hab.kever.sn)):
                yield self.tock

        elif hab.kever.wits:
            print("Waiting for witness receipts...")
            if self.endpoint:
                yield from receiptor.receipt(hab.pre, sn=0)
            else:
                witDoer.msgs.append(dict(pre=hab.pre))
                while not witDoer.cues:
                    _ = yield self.tock

        if hab.kever.delegator:
            yield from self.postman.sendEvent(hab=hab, fn=hab.kever.sn)

        print(f'Prefix  {hab.pre}')
        for idx, verfer in enumerate(hab.kever.verfers):
            print(f'\tPublic key {idx + 1}:  {verfer.qb64}')
        print()

        toRemove = [self.hbyDoer, witDoer, self.mbx, self.swain, self.postman, receiptor]
        self.remove(toRemove)

        return
