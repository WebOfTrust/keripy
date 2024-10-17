# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts module

"""
import argparse
import sys

from hio import help
from hio.base import doing

from keri.app import connecting
from keri.app.cli.common import existing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

# Could be expanded to provide arbitrary data if desired
parser = argparse.ArgumentParser(description='Replace contact information for identifier prefix with alias information')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--prefix', '-o', help='identifier prefix to replace contact information for', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the contact', required=True)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(replace, **kwa)]


def replace(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    prefix = args.prefix
    alias = args.alias

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            org = connecting.Organizer(hby=hby)

            if prefix not in hby.kevers:
                print(f"{prefix} is not a known identifier, oobi must be resolved first")
                sys.exit(-1)

            org.replace(pre=prefix, data=dict(alias=alias))

    except ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first")
        sys.exit(-1)
