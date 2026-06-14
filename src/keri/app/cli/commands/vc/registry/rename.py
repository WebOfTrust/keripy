# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.vc.registry.rename module

"""
import argparse

from hio.base import doing

from keri.app.cli.common import existing
from keri.kering import ConfigurationError
from keri.vdr import credentialing, viring

parser = argparse.ArgumentParser(description='Rename a local credential registry')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)
parser.add_argument('--registry-name', '-r', help='current local registry name', required=True)
parser.add_argument('--new-name', help='new local registry name')


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(rename, **kwa)]


def rename(tymth, tock=0.0, **opts):
    """Command line registry rename handler."""
    _ = (yield tock)
    args = opts["args"]

    try:
        with existing.existingHby(name=args.name, base=args.base, bran=args.bran) as hby:
            rgy = credentialing.Regery(hby=hby, name=args.name, base=args.base)
            oldName = args.registry_name
            newName = args.new_name

            if oldName == newName:
                print(f"Registry {oldName} already has requested name")
                return

            regrec = rgy.reger.regs.get(keys=oldName)
            if regrec is None:
                print(f"Registry {oldName} not found")
                return -1

            existingReg = rgy.reger.regs.get(keys=newName)
            if existingReg is not None:
                if existingReg.registryKey != regrec.registryKey or existingReg.prefix != regrec.prefix:
                    print(f"Registry name {newName} already exists")
                    return -1
                rgy.reger.regs.rem(keys=oldName)
                print(f"Registry {oldName} renamed to {newName}")
                return

            ok = rgy.reger.regs.put(keys=newName,
                                    val=viring.RegistryRecord(registryKey=regrec.registryKey,
                                                              prefix=regrec.prefix))
            if not ok:
                print(f"Unable to create registry name {newName}")
                return -1

            rgy.reger.regs.rem(keys=oldName)
            print(f"Registry {oldName} renamed to {newName}")

    except ConfigurationError:
        print(f"identifier prefix for {args.name} does not exist, incept must be run first")
        return -1
