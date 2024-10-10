# -*- encoding: utf-8 -*-
"""
keri.kli.commands.oobi module

"""
import argparse

from hio import help
from hio.base import doing

import keri.app.oobiing
from keri.app import habbing, oobiing
from keri.app.cli.common import existing
from keri.db import basing
from keri.end import ending
from keri.help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description="Resolve the provided OOBI")
parser.set_defaults(handler=lambda args: resolve(args),
                    transferable=True)

# Parameters for basic structure of database
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument("--oobi", "-o", help="out-of-band introduciton to load", required=True)
parser.add_argument("--oobi-alias", dest="oobiAlias", help="alias for AID resolved from out-of-band introduciton",
                    required=False, default=None)
parser.add_argument('--force', action="store_true", required=False,
                    help='True means to resolve OOBI even if it has already been previously resolved')


# Parameters for Manager access
# passcode => bran
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)


def resolve(args):
    """ command line method for resolving oobies

    Parameters:
        args(Namespace): parse args namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    oobi = args.oobi
    oobiAlias = args.oobiAlias
    force = args.force

    icpDoer = OobiDoer(name=name, oobi=oobi, bran=bran, base=base, oobiAlias=oobiAlias, force=force)

    doers = [icpDoer]
    return doers


class OobiDoer(doing.DoDoer):
    """ DoDoer for loading oobis and waiting for the results """

    def __init__(self, name, oobi, oobiAlias, force=False, bran=None, base=None):

        self.processed = 0
        self.oobi = oobi
        self.force = force
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)

        obr = basing.OobiRecord(date=helping.nowIso8601())
        if oobiAlias is not None:
            obr.oobialias = oobiAlias

        self.hby.db.oobis.put(keys=(oobi,), val=obr)

        self.obi = keri.app.oobiing.Oobiery(hby=self.hby)
        self.authn = oobiing.Authenticator(hby=self.hby)
        doers = [self.hbyDoer, doing.doify(self.waitDo)]

        super(OobiDoer, self).__init__(doers=doers)

    def waitDo(self, tymth, tock=0.0):
        """ Waits for oobis to load

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method for loading oobis using
        the Oobiery
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.force:  # if --force specified, remove previous record of OOBI resolution
            self.hby.db.roobi.rem(keys=(self.oobi,))

        self.extend(self.obi.doers)
        self.extend(self.authn.doers)

        while not self.obi.hby.db.roobi.get(keys=(self.oobi,)):
            yield 0.25

        obr = self.obi.hby.db.roobi.get(keys=(self.oobi,))
        if self.force:
            while obr.cid not in self.hby.kevers:
                self.hby.kvy.processEscrows()
                yield 0.25

        print(self.oobi, obr.state)

        self.remove([self.hbyDoer, *self.obi.doers, *self.authn.doers])
