# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.db import koming
from keri.kering import ConfigurationError, Version
from keri.vdr import viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='View status of a local AID')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(migrate, **kwa)]


def migrate(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            rgy = viring.Reger(name=name, base=base, db=hby.db, temp=hby.temp,
                               reopen=True)

            states = koming.Komer(db=rgy,
                                  schema=dict,
                                  subkey='stts.')

            for _, sad in states.getItemIter():
                rsr = viring.RegStateRecord(
                    vn=list(Version),  # version number as list [major, minor]
                    i=sad['i'],  # qb64 registry SAID
                    s=sad['s'],  # lowercase hex string no leading zeros
                    d=sad['d'],
                    ii=sad['ii'],
                    dt=sad['dt'],
                    et=sad['et'],
                    bt=sad['bt'],  # hex string no leading zeros lowercase
                    b=sad['b'],  # list of qb64 may be empty
                    c=sad['c'],
                )
                # ksr = stateFromKever(kever)
                rgy.states.pin(sad['i'], val=rsr)

    except ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
