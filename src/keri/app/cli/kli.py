# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import multicommand
from hio import help

from keri.app.cli import commands

logger = help.ogler.getLogger()


def main():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()
    if hasattr(args, "handler"):
        args.handler(args)


if __name__ == "__main__":
    main()
