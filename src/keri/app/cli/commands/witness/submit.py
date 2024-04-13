# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app import habbing, agenting, indirecting
from keri.app.cli.common import existing, displaying
from keri.help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Submit current event to witnesses for receipting')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config", "-c", help="directory override for configuration data")

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)
parser.add_argument('--force', action="store_true", required=False,
                    help='True means to send witnesses all receipts even if we have a full compliment of receipts for '
                         'the current event')
parser.add_argument("--receipt-endpoint", help="Attempt to connect to witness receipt endpoint for witness receipts.",
                    dest="endpoint", action='store_true')
parser.add_argument("--authenticate", '-z', help="Prompt the controller for authentication codes for each witness",
                    action='store_true')


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
    force = args.force

    subDoer = SubmitDoer(name=name, base=base, alias=alias, bran=bran, force=force, authenticate=args.authenticate,
                         endpoint=args.endpoint)

    doers = [subDoer]
    return doers


class SubmitDoer(doing.DoDoer):
    """ DoDoer for creating a new identifier prefix and Hab with an alias.
    """

    def __init__(self, name, base, alias, bran, force, endpoint=False, authenticate=False):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.mbx = indirecting.MailboxDirector(hby=hby, topics=['/receipt', "/replay", "/reply"])
        self.alias = alias
        self.hby = hby
        self.force = force
        self.endpoint = endpoint
        self.authenticate = authenticate

        doers = [self.hbyDoer, self.mbx, doing.doify(self.submitDo)]

        super(SubmitDoer, self).__init__(doers=doers)

    def submitDo(self, tymth, tock=0.0):
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
        auths = {}
        if self.authenticate:
            for wit in hab.kever.wits:
                code = input(f"Entire code for {wit}: ")
                auths[wit] = f"{code}#{helping.nowIso8601()}"

        if self.endpoint:
            receiptor = agenting.Receiptor(hby=self.hby)
            self.extend([receiptor])

            yield from receiptor.receipt(hab.pre, sn=hab.kever.sn, auths=auths)
            self.remove([receiptor])

        else:
            witDoer = agenting.WitnessReceiptor(hby=self.hby, force=self.force, auths=auths)
            self.extend([witDoer])

            if hab.kever.wits:
                print("Waiting for witness receipts...")
                witDoer.msgs.append(dict(pre=hab.pre))
                while not witDoer.cues:
                    _ = yield self.tock

            self.remove([witDoer])

        displaying.printIdentifier(self.hby, hab.pre)

        toRemove = [self.hbyDoer, self.mbx]
        self.remove(toRemove)

        return
