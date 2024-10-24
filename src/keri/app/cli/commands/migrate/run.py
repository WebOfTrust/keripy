# -*- encoding: utf-8 -*-
"""
keri.kli.commands.migrate.run module

"""
import argparse

from hio import help
from hio.base import doing
from keri import kering

from keri.db import basing

logger = help.ogler.getLogger()


def handler(args):
    """
    Launch KERI database migrator

    Args:
        args(Namespace): arguments object from command line
    """
    migrator = MigrateDoer(args)
    return [migrator]


parser = argparse.ArgumentParser(description='Migrates a database and keystore')
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

        print(f"Migrating {self.args.name}...")
        db.migrate()
        print(f"Finished migrating {self.args.name}")

        return True
