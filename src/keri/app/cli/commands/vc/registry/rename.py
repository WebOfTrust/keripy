# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.vc.registry.rename module

"""
import argparse

from hio.base import doing

from keri.app.cli.common import existing
from keri.vdr import credentialing, viring

parser = argparse.ArgumentParser(description='Rename a local credential registry')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)
parser.add_argument('--registry-name', '-r', help='current local registry name', required=False, default=None)
parser.add_argument('--registry-said', help='current registry SAID', required=False, default=None)
parser.add_argument('--new-name', help='new local registry name')


def handler(args):
    if args.registry_said is None and args.registry_name is None:
        parser.error("--registry-name or --registry-said is required")

    return [RenameDoer(name=args.name,
                       base=args.base,
                       bran=args.bran,
                       registryName=args.registry_name,
                       registrySaid=args.registry_said,
                       newName=args.new_name)]


class RenameDoer(doing.Doer):
    """Doer that renames a local credential registry."""

    def __init__(self, name, base, bran, registryName, registrySaid, newName):
        self.name = name
        self.base = base
        self.bran = bran
        self.registryName = registryName
        self.registrySaid = registrySaid
        self.newName = newName

        self.hby = existing.setupHby(name=self.name, base=self.base, bran=self.bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=self.name, base=self.base)

        super(RenameDoer, self).__init__()

    def recur(self, tyme):
        """Command line registry rename handler."""
        self.renameRegistry()
        return True

    def exit(self):
        super(RenameDoer, self).exit()
        self.close()

    def renameRegistry(self):
        """Rename the registry record in the local registry store."""
        newName = self.newName
        regs = self.rgy.reger.regs

        oldName, regrec = self._registryRecord()
        if regrec is None:
            name = self.registrySaid if self.registrySaid is not None else self.registryName
            print(f"Registry {name} not found")
            return -1

        if oldName == newName:
            print(f"Registry {oldName} already has requested name")
            return

        existingReg = regs.get(keys=newName)
        if existingReg is not None:
            if existingReg.registryKey != regrec.registryKey or existingReg.prefix != regrec.prefix:
                print(f"Registry name {newName} already exists")
                return -1
            regs.rem(keys=oldName)
            print(f"Registry {oldName} renamed to {newName}")
            return

        ok = regs.put(keys=newName,
                      val=viring.RegistryRecord(registryKey=regrec.registryKey,
                                                prefix=regrec.prefix))
        if not ok:
            print(f"Unable to create registry name {newName}")
            return -1

        regs.rem(keys=oldName)
        print(f"Registry {oldName} renamed to {newName}")

    def _registryRecord(self):
        """Return the local registry-name key and record to rename."""
        regs = self.rgy.reger.regs

        if self.registrySaid is not None:
            regrec = regs.get(keys=self.registrySaid)
            if regrec is not None and regrec.registryKey == self.registrySaid:
                return self.registrySaid, regrec

            for (name,), regrec in regs.getItemIter():
                if regrec.registryKey == self.registrySaid:
                    return name, regrec

            return None, None

        if self.registryName is None:
            return None, None

        return self.registryName, regs.get(keys=self.registryName)

    def close(self):
        if self.rgy is not None:
            self.rgy.close()
            self.rgy = None
        if self.hby is not None:
            self.hby.close(clear=self.hby.temp)
            self.hby = None
