# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json

from hio import help
from hio.base import doing

from keri import kering
from keri.app import indirecting, habbing, forwarding, grouping
from keri.app.cli.common import existing
from keri.core import eventing, parsing, coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Add new endpoint role authorization.')
parser.set_defaults(handler=lambda args: add_end(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--aid", help="qualified base64 of AID to export rpy messages for all endpoints.",
                    required=True)


def add_end(args):
    """ Command line tool for adding endpoint role authorizations

    """
    ld = RoleDoer(name=args.name,
                  base=args.base,
                  alias=args.alias,
                  bran=args.bran,
                  aid=args.aid)
    return [ld]


class RoleDoer(doing.DoDoer):

    def __init__(self, name, base, alias, bran, aid):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        if self.hab is None:
            raise kering.ConfigurationError(f"unknown alias={alias}")

        self.aid = aid
        doers = [doing.doify(self.roleDo)]

        super(RoleDoer, self).__init__(doers=doers)

    def roleDo(self, tymth, tock=0.0):
        """ Export any end reply messages previous saved for the provided AID

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

        ends = self.hab.endsFor(self.aid)
        print(json.dumps(ends, indent=1))
        return
