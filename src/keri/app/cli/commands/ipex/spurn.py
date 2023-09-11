# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

from keri.core import coring

parser = argparse.ArgumentParser(description='Reject an IPEX apply, offer, agree or grant message')
parser.set_defaults(handler=lambda args: handler(args))


def handler(_):
    return [doing.doify(nonce)]


def nonce(tymth, tock=0.0):
    """ nonce
    """
    _ = (yield tock)

    print(coring.randomNonce())
