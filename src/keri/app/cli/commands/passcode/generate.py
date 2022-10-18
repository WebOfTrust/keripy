# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse
import secrets

import string
from hio.base import doing

parser = argparse.ArgumentParser(description='Print a new random salt')
parser.set_defaults(handler=lambda args: handler(args))

PASSCODE_SIZE = 21
PASSCODE_CHARS = string.ascii_lowercase + string.ascii_uppercase + '123456789'


def handler(_):
    return [doing.doify(salt)]


def salt(tymth, tock=0.0):
    """ Command line version handler
    """
    _ = (yield tock)

    code = []
    for x in range(PASSCODE_SIZE):
        code.append(PASSCODE_CHARS[secrets.randbelow(len(PASSCODE_CHARS))])

    print("".join(code))

