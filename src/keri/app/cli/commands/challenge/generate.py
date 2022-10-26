# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from hio import help
from hio.base import doing
from mnemonic import mnemonic

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Generate a cryptographically random challenge phrase')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--strength', '-s', help='Cryptographic strength in bits.  Defaults to 128', default=128,
                    required=False)
parser.add_argument("--out", "-o", help="Output type [words|string|json] of phrase.  Default is json",
                    choices=["words", "string", "json"], default="json", required=False)


def handler(args):
    """
    Generate a cryptographically random challenge phrase

    Args:
        args(Namespace): arguments object from command line
    """
    kwa = dict(args=args)
    return [doing.doify(generate, **kwa)]


def generate(tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    generateWords(args.strength, args.out)
    return True


def generateWords(strength, out):
    mnem = mnemonic.Mnemonic(language='english')
    s = strength
    strength = int(s) if s is not None else 128

    words = mnem.generate(strength=strength)
    if out == "json":
        msg = words.split(" ")
        print(json.dumps(msg))
    elif out == "string":
        print(words)
    else:
        for w in words.split(" "):
            print(w)

    return words.split(" ")
