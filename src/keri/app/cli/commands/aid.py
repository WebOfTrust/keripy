# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import help
from keri.app.cli.common import existing 

from keri.app.cli.common.parsing import Parsery
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Print the AID for a given alias', parents=[Parsery.keystore()]) 
parser.set_defaults(handler=lambda args: handler(args))

parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None,
                    required=True)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(status, **kwa)]


def status(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            if alias is None:
                alias = existing.aliasInput(hby)

            hab = hby.habByName(alias)
            if hab is None:
                print(f"{alias} is not a valid alias for an identifier")

            print(hab.pre)

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
