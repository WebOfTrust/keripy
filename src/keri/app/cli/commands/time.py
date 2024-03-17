# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

from keri.help import helping

parser = argparse.ArgumentParser(description='Print a new time')
parser.set_defaults(handler=lambda args: handler(args))


def handler(_):
    return [doing.doify(time)]


def time(tymth, tock=0.0):
    """ time
    """
    _ = (yield tock)

    print(helping.nowIso8601())
