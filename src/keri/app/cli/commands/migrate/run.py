# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

import keri
from hio import help
from hio.base import doing
from keri import kering

from keri.app.cli.common import existing
from keri.db import basing

logger = help.ogler.getLogger()


def handler(args):
    """
    Launch KERI database initialization

    Args:
        args(Namespace): arguments object from command line
    """
    clean = MigrateDoer(args)
    return [clean]


parser = argparse.ArgumentParser(description='Cleans and migrates a database and keystore')
parser.set_defaults(handler=handler,
                    transferable=True)

# Parameters for basic structure of database
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--temp', '-t', help='create a temporary keystore, used for testing', default=False)

# Parameters for Manager creation
# passcode => bran
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)


class MigrateDoer(doing.Doer):

    def __init__(self, args):
        self.args = args
        super(MigrateDoer, self).__init__()

    def recur(self, tyme):
        db = basing.Baser(name=self.args.name,
                          base=self.args.base,
                          temp=self.args.temp,
                          reopen=False)

        try:
            db.reopen()
        except kering.DatabaseError:
            pass

        print("Migrating...")
        db.migrate()
        print("Finished")

        return True
