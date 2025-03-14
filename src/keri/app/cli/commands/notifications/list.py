# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json

from hio.base import doing
from keri import help
from keri.app import habbing, notifying
from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Display notifications for an identifier')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def handler(args):
    """
    List notifications for an identifier.

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    verbose = args.verbose

    notesDoer = NotesDoer(name=name, base=base, alias=alias, bran=bran, verbose=verbose)

    doers = [notesDoer]
    return doers


class NotesDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran, verbose):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby
        self.verbose = verbose
        self.notifier = notifying.Notifier(hby=self.hby)

        doers = [self.hbyDoer, doing.doify(self.readDo)]

        super(NotesDoer, self).__init__(doers=doers)

    def readDo(self, tymth, tock=0.0, **kwa):
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

        print("Waiting for notifications...")

        while self.notifier.noter.notes.cntAll() == 0:
            yield self.tock

        for keys, notice in self.notifier.noter.notes.getItemIter():
            if self.verbose:
                print(keys)
                print(json.dumps(notice.pad, indent=4))
            else:
                print(keys, notice.attrs.get('r', 'no route'))

        self.remove([self.hbyDoer,])
        return