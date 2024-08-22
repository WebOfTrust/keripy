# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import json

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Print an event from an AID, or specific values from an event (defaults to latest event).')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None,
                    required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--said', '-S', help='Print the SAID of the event in question', action="store_true")
parser.add_argument('--sn', '-s', help='Print the decimal value of the sequence number of the event in question',
                    action="store_true")
parser.add_argument('--snh', help='Print the decimal value of the sequence number of the event in question',
                    action="store_true")
parser.add_argument('--raw', '-r', help='Print the raw, signed value of the event', action="store_true")
parser.add_argument('--json', '-j', help='Pretty print the JSON of the event.', action="store_true")
parser.add_argument('--seal', help='Print an anchorable seal of the event in question.', action="store_true")


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(event, **kwa)]


def event(tymth, tock=0.0, **opts):
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
                print(f"{alias} is not a valid identifier")

            if args.said:
                print(hab.kever.serder.said)

            if args.sn:
                print(hab.kever.sn)

            if args.snh:
                print(hab.kever.serder.snh)

            if args.raw:
                print(hab.kever.serder.raw.decode("utf-8"))

            if args.json:
                print(hab.kever.serder.pretty())

            if args.seal:
                seal = dict(i=hab.pre, s=hab.kever.serder.snh, d=hab.kever.serder.said)
                print(json.dumps(seal))

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
