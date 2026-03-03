# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts module

"""
import argparse
import sys

from hio.base import doing

from ..... import help
from .... import organizing
from ...common import existing
from ...common.parsing import Parsery
from .....kering import ConfigurationError

logger = help.ogler.getLogger()

# Could be expanded to provide arbitrary data if desired
parser = argparse.ArgumentParser(description='Replace contact information for identifier prefix with alias information', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
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
            org = organizing.Organizer(hby=hby)

            if prefix not in hby.kevers:
                print(f"{prefix} is not a known identifier, oobi must be resolved first")
                sys.exit(-1)

            org.replace(pre=prefix, data=dict(alias=alias))

    except ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first")
        sys.exit(-1)
