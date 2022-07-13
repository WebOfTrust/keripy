# -*- encoding: utf-8 -*-
"""
keri.kli.commands.oobi module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app import habbing, oobiing
from keri.app.cli.common import existing

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

# Parameters for Manager access
# passcode => bran
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
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

    icpDoer = OobiDoer(name=name, oobi=oobi, bran=bran, base=base, oobiAlias=oobiAlias)

    doers = [icpDoer]
    return doers


class OobiDoer(doing.DoDoer):
    """ DoDoer for loading oobis and waiting for the results """

    def __init__(self, name, oobi, oobiAlias, bran=None, base=None):

        self.processed = 0

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)

        self.obl = oobiing.OobiLoader(hby=self.hby)
        if oobiAlias is None:
            msg = dict(url=oobi)
        else:
            msg = dict(oobialias=oobiAlias, url=oobi)

        self.obl.queue([msg])

        doers = [self.hbyDoer, self.obl, doing.doify(self.waitDo)]

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

        while not self.obl.done:
            yield 0.25

        self.remove([self.hbyDoer, self.obl])
