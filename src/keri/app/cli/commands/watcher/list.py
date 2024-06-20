# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app import connecting
from keri.app.cli.common import existing
from keri.kering import ConfigurationError, Roles

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='List current watchers')
parser.set_defaults(handler=lambda args: handle(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def handle(args):
    """ Command line handler for adding an aid to a watcher's list of AIds to watch

    Parameters:
        args(Namespace): parsed command line arguments

    """

    kwa = dict(args=args)
    return [doing.doify(listWatchers, **kwa)]


def listWatchers(tymth, tock=0.0, **opts):
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
            org = connecting.Organizer(hby=hby)
            if alias is None:
                alias = existing.aliasInput(hby)

            hab = hby.habByName(alias)

            for (aid, role, eid), ender in hab.db.ends.getItemIter(keys=(hab.pre, Roles.watcher, )):
                if ender.allowed:
                    contact = org.get(eid)
                    print(f"{contact['alias']}: {eid}")

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
