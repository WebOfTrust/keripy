# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from hio import help
from hio.base import doing

from keri.core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Saidify a JSON file.')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--label', '-l', help='Field label to SAID-ify', default="d", required=False)


def handler(args):
    """
    Saidify the provided SAD

    Args:
        args(Namespace): arguments object from command line
    """
    kwa = dict(args=args)
    return [doing.doify(saidify, **kwa)]


def saidify(tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]

    with open(args.file, 'r') as f:
        sad = json.load(f)
        _, out = coring.Saider.saidify(sad=sad, label=args.label)

    with open(args.file, 'w') as f:
        json.dump(out, f)
