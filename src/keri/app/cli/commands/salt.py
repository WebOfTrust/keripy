# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

import pysodium
from hio.base import doing

from keri.core import coring

parser = argparse.ArgumentParser(description='Print a new random passcode')
parser.set_defaults(handler=lambda args: handler(args))


def handler(_):
    return [doing.doify(passcode)]


def passcode(tymth, tock=0.0):
    """ Command line version handler
    """
    _ = (yield tock)

    print(coring.Salter(raw=pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)).qb64)
