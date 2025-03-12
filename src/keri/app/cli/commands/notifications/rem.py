# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

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
parser.add_argument("--rid", '-r', help='notification SAID to mark as read', default=None)
parser.add_argument("--all", help="mark all notifications as read", action="store_true")


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
    rid = args.rid
    all = args.all

    removeDoer = RemoveDoer(name=name, base=base, alias=alias, bran=bran, rid=rid, all=all)

    doers = [removeDoer]
    return doers


class RemoveDoer(doing.DoDoer):
    def __init__(self, name, base, alias, bran, rid, all):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby
        self.notifier = notifying.Notifier(hby=self.hby)
        self.rid = rid
        self.all = all

        doers = [self.hbyDoer, doing.doify(self.remDoer)]

        super(RemoveDoer, self).__init__(doers=doers)

    def remDoer(self, tymth, tock=0.0, **kwa):
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

        if self.all:
            print()
            print("This command will remove all notifications")
            print()
            yn = input("Are you sure you want to continue? [y|N]: ")

            if yn not in ("y", "Y"):
                print("...exiting")
            else:
                for n in self.notifier.getNotes():
                    print(f"removing {n.rid}")
                    self.notifier.rem(rid=n.rid)
        elif self.rid is not None:
            print(f"removing {self.rid}")
            self.notifier.rem(rid=self.rid)
        else:
            print("Must specify one of --rid or --all")

        self.remove([self.hbyDoer,])
        return