# -*- encoding: utf-8 -*-
"""
keri.kli.commands.migrate.list module

"""
import argparse

from hio.base import doing
from prettytable import PrettyTable

from keri import help
from keri.app.cli.common import existing
from keri.app.cli.common.parsing import Parsery

logger = help.ogler.getLogger()


def handler(args):
    """
    List local LMDB database migrations and their completion status

    Args:
        args(Namespace): arguments object from command line
    """
    lister = ListDoer(args)
    return [lister]


parser = argparse.ArgumentParser(description='Lists the local LMDB migrations and their completion status', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=handler)
parser.add_argument('--temp', '-t', help='create a temporary keystore, used for testing', default=False)


class ListDoer(doing.Doer):

    def __init__(self, args):
        self.args = args
        super(ListDoer, self).__init__()

    def recur(self, tyme):
        tab = PrettyTable()
        tab.field_names = ["Num", "Name", "Date Completed"]
        tab.align["Name"] = "l"

        hby = existing.setupHby(name=self.args.name, base=self.args.base,
                                bran=self.args.bran, temp=self.args.temp)

        for idx, (name, dater) in enumerate(hby.db.complete()):
            print(name, dater)
            date = dater.datetime.strftime("%Y-%m-%d %H:%M") if dater is not None else "Not Run"
            tab.add_row((f"{idx + 1}", f"{name}", date))

        print(tab)
        return True
