# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri import help
from hio.base import doing

from keri.app import habbing, agenting
from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Send full KEL to a specific witness to catch it up')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the identifier prefix', required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--witness', '-w', help='witness AID to send KEL to', required=True)
parser.add_argument('--force', '-f', help='send KEL even if witness is not in current witness pool',
                    action='store_true', default=False)


def handler(args):
    """
    Send full KEL to a specific witness to catch it up.

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    witness = args.witness
    force = args.force

    doer = CatchupDoer(name=name, base=base, alias=alias, bran=bran, witness=witness, force=force)

    return [doer]


class CatchupDoer(doing.DoDoer):
    """ DoDoer for sending full KEL to a witness to catch it up.
    """

    def __init__(self, name, base, alias, bran, witness, force=False):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby
        self.witness = witness
        self.force = force

        doers = [self.hbyDoer, doing.doify(self.catchupDo)]

        super(CatchupDoer, self).__init__(doers=doers)

    def catchupDo(self, tymth, tock=0.0):
        """
        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            print(f"Error: unknown alias {self.alias}")
            self.remove([self.hbyDoer])
            return

        # Validate witness is in the current witness list
        if self.witness not in hab.kever.wits:
            if not self.force:
                print(f"Error: {self.witness} is not a witness for {self.alias}")
                print(f"Current witnesses: {hab.kever.wits}")
                print("Use --force to send KEL anyway")
                self.remove([self.hbyDoer])
                return
            else:
                print(f"Warning: {self.witness} is not a witness for {self.alias}, forcing anyway")

        receiptor = agenting.Receiptor(hby=self.hby)
        self.extend([receiptor])

        print(f"Sending full KEL to witness {self.witness}...")
        yield from receiptor.catchup(hab.pre, self.witness)

        print(f"KEL sent successfully. Witness should now be at sn={hab.kever.sn}")

        self.remove([receiptor, self.hbyDoer])

        return
