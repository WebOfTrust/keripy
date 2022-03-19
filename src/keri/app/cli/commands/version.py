# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

import keri

parser = argparse.ArgumentParser(description='Print version of KLI')
parser.set_defaults(handler=lambda args: handler(args))


def handler(args):
    return [doing.doify(version)]


def version(tymth, tock=0.0):
    """ Command line version handler
    """
    _ = (yield tock)

    print(keri.__version__)
