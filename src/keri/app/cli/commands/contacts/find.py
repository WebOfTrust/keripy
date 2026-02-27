# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts.find module

"""
import argparse
import json

from ..... import help
from hio.base import doing

from .... import organizing as connecting
from ...common import existing
from .....kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Find contacts by field value')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--field', '-f', help='field name to search (default: alias)', default='alias')
parser.add_argument('--value', '-v', help='value or regex pattern to match', required=True)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(find, **kwa)]


def find(tymth, tock=0.0, **opts):
    """ Command line handler for finding contacts by field value

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    field = args.field
    value = args.value

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            org = connecting.Organizer(hby=hby)

            contacts = org.find(field, value)

            if len(contacts) == 0:
                print(f"No contacts found matching {field}='{value}'")
                return

            print(json.dumps(contacts, indent=2))

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first")
        return -1
