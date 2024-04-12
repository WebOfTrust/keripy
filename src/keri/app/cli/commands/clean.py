# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import existing

logger = help.ogler.getLogger()


def handler(args):
    """
    Launch KERI database initialization

    Args:
        args(Namespace): arguments object from command line
    """
    clean = CleanDoer(args)
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


class CleanDoer(doing.Doer):

    def __init__(self, args):
        self.args = args
        super(CleanDoer, self).__init__()

    def recur(self, tyme):

        hby = existing.setupHby(name=self.args.name, base=self.args.base,
                                bran=self.args.bran, temp=self.args.temp)
        print("Migrating...")
        hby.db.migrate()
        print("Finished")

        hby = existing.setupHby(name=self.args.name, base=self.args.base,
                                bran=self.args.bran, temp=self.args.temp)

        print("Database open, performing clean...")
        hby.db.clean()
        print("Finished.")

        return True
