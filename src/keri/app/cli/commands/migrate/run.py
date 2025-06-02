# -*- encoding: utf-8 -*-
"""
keri.kli.commands.migrate.run module

"""
import argparse

from hio.base import doing
from keri import kering

from keri import help
from keri.app.cli.common.parsing import Parsery
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


parser = argparse.ArgumentParser(description='Migrates a database and keystore', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=handler)
parser.add_argument('--temp', '-t', help='create a temporary keystore, used for testing', default=False)


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
