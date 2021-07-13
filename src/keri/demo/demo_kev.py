# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.demoing module

Utilities for demos
"""
import argparse
import logging

from hio import help
from hio.base import doing

from ..app import habbing, keeping, apping
from ..db import basing

logger = help.ogler.getLogger()


def parseArgs():
    p = argparse.ArgumentParser(description="Demo")

    p.add_argument('-n', '--name',
                   action='store',
                   default='',
                   help="A name")

    args = p.parse_args()

    return args


def main():
    args = parseArgs()

    help.ogler.level = logging.INFO
    help.ogler.reopen(name=args.name, temp=True, clear=True)

    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Demo ******")

    conDoer = apping.Consoler()

    tock = 1.03125
    doist = doing.Doist(limit=0.0, tock=tock, real=True)
    doist.do(doers=[conDoer])

    return


if __name__ == "__main__":
    main()
