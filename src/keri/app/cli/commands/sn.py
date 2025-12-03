# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

parser = argparse.ArgumentParser(description='Convert sequence number between hex and decimal')
parser.set_defaults(handler=lambda args: handler(args))

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--hex', '-x', help='hex sequence number to convert to decimal', dest='hex_value')
group.add_argument('--decimal', '-d', help='decimal sequence number to convert to hex', type=int, dest='dec_value')


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(convert, **kwa)]


def convert(tock=0.0, **opts):
    """ Convert sequence number between hex and decimal
    """
    _ = (yield tock)

    args = opts["args"]

    if args.hex_value is not None:
        # Convert hex to decimal
        dec = int(args.hex_value, 16)
        print(dec)
    else:
        # Convert decimal to hex
        print(f"{args.dec_value:x}")
