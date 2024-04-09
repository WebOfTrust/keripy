# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Display OOBIs waiting for resolution and allow for clean up')
parser.set_defaults(handler=lambda args: list_oobis(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

def list_oobis(args):
    """ Command line list handler

    """
    kwa = dict(args=args)
    return [doing.doify(oobis, **kwa)]


def oobis(tymth, tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran


    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        oobis = []
        for (oobi,), _ in hby.db.oobis.getItemIter():
            oobis.append(oobi)

        if not oobis:
            print("No OOBIs waiting resolution")
            return

        print("The following OOBIs are pending resolution (enter number to delete):")
        for idx, oobi in enumerate(oobis):
            print(f"\t{idx+1}: {oobi}")

        try:
            idx = input("Number: ")
            idx = int(idx) - 1
            if 0 <= idx < len(oobis):
                if hby.db.oobis.rem(oobis[idx]):
                    print("OOBI deleted")
                else:
                    print("Unable to delete OOBI")
            else:
                print("Invalid number\n")
        except ValueError:
            print("Invalid number\n")


