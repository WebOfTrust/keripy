import argparse

import multicommand
from hio import help

from keri.app.cli import commands

logger = help.ogler.getLogger()


def parseArgs():
    p = argparse.ArgumentParser(description="Interactive command line for KERI")

    p.add_argument('-p', '--port',
                   action='store',
                   default='5678',
                   help="port")

    args = p.parse_args()

    return args


def main():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()
    if hasattr(args, "handler"):
        args.handler(args)


if __name__ == "__main__":
    main()
