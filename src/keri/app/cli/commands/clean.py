# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import help
from keri.app.cli.common import existing
from keri.app.cli.common.parsing import Parsery

logger = help.ogler.getLogger()


def handler(args):
    """
    Launch KERI database initialization

    Args:
        args(Namespace): arguments object from command line
    """
    clean = CleanDoer(args)
    return [clean]


parser = argparse.ArgumentParser(description='Cleans and migrates a database and keystore', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=handler)
parser.add_argument('--temp', '-t', help='create a temporary keystore, used for testing', default=False)

class CleanDoer(doing.Doer):

    def __init__(self, args):
        self.args = args
        super(CleanDoer, self).__init__()

    def recur(self, tyme):
        hby = existing.setupHby(name=self.args.name, base=self.args.base,
                                bran=self.args.bran, temp=self.args.temp)

        print("Clearing escrows...")
        hby.db.clearEscrows()
        print("Finished")

        print("Migrating...")
        hby.db.migrate()
        print("Finished")

        hby = existing.setupHby(name=self.args.name, base=self.args.base,
                                bran=self.args.bran, temp=self.args.temp)

        print("Database open, performing clean...")
        hby.db.clean()
        print("Finished")

        return True
