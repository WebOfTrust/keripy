import argparse
import logging

from hio import help
from hio.base import doing

from keri.app.cli.consoling import Consoling

logger = help.ogler.getLogger()


class KLI(doing.Doist):

    def __init__(self, name: str, **kwa):
        super().__init__(**kwa)
        self.name = name

        self.doers.extend(Consoling(self.name))


def parseArgs():
    p = argparse.ArgumentParser(description="Interactive command line for KERI")

    p.add_argument('-n', '--name',
                   required=True,
                   action='store',
                   default='',
                   help="A human friendly name for the 'environment'")

    args = p.parse_args()

    return args


def main():
    args = parseArgs()

    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    kli = KLI(name=args.name)
    kli.do(limit=0.0, tyme=0.03125)


if __name__ == "__main__":
    main()
