# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.vc.registry.test_rename module
"""
import pytest

from keri import core, kering
from keri.app import directing, habbing
from keri.app.cli.commands.vc.registry import rename as rename_cmd
from keri.vdr import credentialing, viring


SALT = core.Salter(raw=b'0123456789abcdef').qb64
CLI_BASE = "test-vc-registry-rename"


def isolatedBase(tmp_path):
    """Return a command-addressable base namespace unique to this pytest test."""
    return f"{CLI_BASE}-{tmp_path.parent.name}-{tmp_path.name}"


def closeRegery(rgy, clear=True):
    reger = getattr(rgy, "reger", None)
    if reger is not None and (reger.opened or clear):
        reger.close(clear=clear)


def closeHby(hby, clear=True):
    if hby is not None:
        cf = getattr(hby, "cf", None)
        hby.close(clear=clear)
        if clear and cf is not None:
            cf.close(clear=True)


def renameArgs(registry_name="old", new_name="new", name="test", base=CLI_BASE, registry_said=None):
    args = ["--name", name,
            "--base", base,
            "--new-name", new_name]
    if registry_name is not None:
        args.extend(["--registry-name", registry_name])
    if registry_said is not None:
        args.extend(["--registry-said", registry_said])
    return rename_cmd.parser.parse_args(args)


def test_registry_rename_branches(tmp_path, capsys):
    # Purpose: cover registry rename outcomes against a persistent keystore.
    # Import materializes registries by SAID, and rename preserves the operator-facing registry naming workflow.
    with habbing.openHby(name="rename", base=isolatedBase(tmp_path),
                         temp=False, clear=True, salt=SALT) as hby:
        rgy = None

        def reopenRegistry():
            rhby = rename_cmd.existing.setupHby(name=hby.name, base=hby.base)
            rrgy = credentialing.Regery(hby=rhby, name=rhby.name, base=rhby.base)
            return rhby, rrgy

        try:
            # initial setup
            hab = hby.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
            reg = rgy.makeRegistry(prefix=hab.pre, name="old", noBackers=True)
            record = viring.RegistryRecord(registryKey=reg.regk, prefix=hab.pre)
            closeRegery(rgy, clear=False)
            closeHby(hby, clear=False)

            # already exists with name
            directing.runController(doers=rename_cmd.handler(renameArgs("old", "old", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old already has requested name\n"

            # missing registry
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") == record
                rrgy.reger.regs.rem(keys="old")
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
            directing.runController(doers=rename_cmd.handler(renameArgs("missing", "new", name=hby.name,
                                                                        base=hby.base)))
            assert capsys.readouterr().out == "Registry missing not found\n"

            # registry already exists under new name
            rhby, rrgy = reopenRegistry()
            try:
                rrgy.reger.regs.pin(keys="old", val=record)
                rrgy.makeRegistry(prefix=hab.pre, name="new", noBackers=True)
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
            directing.runController(doers=rename_cmd.handler(renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry name new already exists\n"

            # success when target name already maps to the same registry
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") == record
                rrgy.reger.regs.pin(keys="new", val=record)
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)

            directing.runController(doers=rename_cmd.handler(renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"

            # success when target name does not exist yet
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") is None
                assert rrgy.reger.regs.get(keys="new") == record
                rrgy.reger.regs.rem(keys="new")
                rrgy.reger.regs.pin(keys="old", val=record)
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)

            directing.runController(doers=rename_cmd.handler(renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") is None
                assert rrgy.reger.regs.get(keys="new") == record
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
        finally:
            closeRegery(rgy)
            closeHby(hby)


def test_registry_rename_accepts_registry_said(tmp_path, capsys):
    # Purpose: verify registry rename can target the stable registry SAID, not only the current local name.
    # Imported registries are initially keyed by SAID, so this is the production recovery path for friendly names.
    with habbing.openHby(name="rename-said", base=isolatedBase(tmp_path),
                         temp=False, clear=True, salt=SALT) as hby:
        rgy = None
        try:
            hab = hby.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
            reg = rgy.makeRegistry(prefix=hab.pre, name="old", noBackers=True)
            record = viring.RegistryRecord(registryKey=reg.regk, prefix=hab.pre)
            closeRegery(rgy, clear=False)
            closeHby(hby, clear=False)

            directing.runController(doers=rename_cmd.handler(renameArgs(registry_name="missing",
                                                                        registry_said=reg.regk,
                                                                        new_name="new",
                                                                        name=hby.name,
                                                                        base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"

            rhby = rename_cmd.existing.setupHby(name=hby.name, base=hby.base)
            rrgy = credentialing.Regery(hby=rhby, name=rhby.name, base=rhby.base)
            try:
                assert rrgy.reger.regs.get(keys="old") is None
                assert rrgy.reger.regs.get(keys="new") == record

                rrgy.reger.regs.rem(keys="new")
                rrgy.reger.regs.pin(keys=reg.regk, val=record)
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)

            directing.runController(doers=rename_cmd.handler(renameArgs(registry_name=None,
                                                                        registry_said=reg.regk,
                                                                        new_name="renamed",
                                                                        name=hby.name,
                                                                        base=hby.base)))
            assert capsys.readouterr().out == f"Registry {reg.regk} renamed to renamed\n"

            rhby = rename_cmd.existing.setupHby(name=hby.name, base=hby.base)
            rrgy = credentialing.Regery(hby=rhby, name=rhby.name, base=rhby.base)
            try:
                assert rrgy.reger.regs.get(keys=reg.regk) is None
                assert rrgy.reger.regs.get(keys="renamed") == record
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
        finally:
            closeRegery(rgy)
            closeHby(hby)


def test_registry_rename_missing_keystore(monkeypatch):
    def missingHby(name, base="", bran=None):
        raise kering.ConfigurationError("missing")

    # Monkeypatching just used to simulate a missing keystore.
    monkeypatch.setattr(rename_cmd.existing, "setupHby", missingHby)
    with pytest.raises(kering.ConfigurationError):
        rename_cmd.handler(renameArgs(name="missing"))
