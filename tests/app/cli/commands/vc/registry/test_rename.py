# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.vc.registry.test_rename module
"""
from keri.app.cli.common import existing
from keri import core
import pytest

from keri.app import directing, habbing
from keri.app.cli.commands.vc.registry import rename as rename_cmd
from keri.vdr import credentialing, viring

# Temp Base Path for this test file's temporary LMDB and Configer paths.
TMP_BASE_PATH = "base-reg-rename"


def renameArgs(registry_name="old", new_name="new", name="test", base=TMP_BASE_PATH, registry_said=None):
    """Constructs array of correct registry rename options for multicommand parser"""
    args = ["--name", name,
            "--base", base,
            "--new-name", new_name]
    if registry_name is not None:
        args.extend(["--registry-name", registry_name])
    if registry_said is not None:
        args.extend(["--registry-said", registry_said])
    return rename_cmd.parser.parse_args(args)


def test_registry_rename_requires_new_name(capsys):
    with pytest.raises(SystemExit) as ex:
        rename_cmd.parser.parse_args(["--name", "test", "--registry-name", "old"])

    assert ex.value.code == 2
    assert "--new-name" in capsys.readouterr().err


def test_registry_rename(tmp_path, capsys, helpers):
    # Purpose: cover registry rename outcomes against a persistent keystore.
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name="rename", base=helpers.isolatedBase(TMP_BASE_PATH, tmp_path),
                         temp=False, clear=True, salt=salt) as hby:
        rgy = None

        def reopenRegistry():
            rhby = existing.setupHby(name=hby.name, base=hby.base)
            rrgy = credentialing.Regery(hby=rhby, name=rhby.name, base=rhby.base)
            return rhby, rrgy

        try:
            # initial setup
            hab = hby.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
            reg = rgy.makeRegistry(prefix=hab.pre, name="old", noBackers=True)
            record = viring.RegistryRecord(registryKey=reg.regk, prefix=hab.pre)
            helpers.closeRegery(rgy, clear=False)
            helpers.closeHby(hby, clear=False)

            # missing registry
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") == record
                rrgy.reger.regs.rem(keys="old")
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)
            directing.runController(doers=rename_cmd.handler(
                renameArgs("missing", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry missing not found\n"

            # registry already exists under new name
            rhby, rrgy = reopenRegistry()
            try:
                rrgy.reger.regs.pin(keys="old", val=record)
                rrgy.makeRegistry(prefix=hab.pre, name="new", noBackers=True)
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)
            directing.runController(doers=rename_cmd.handler(
                renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry name new already exists\n"

            # already exists with name
            directing.runController(doers=rename_cmd.handler(
                renameArgs("old", "old", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old already has requested name\n"


            # success when target name already maps to the same registry
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") == record
                rrgy.reger.regs.pin(keys="new", val=record)
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)

            directing.runController(doers=rename_cmd.handler(
                renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"

            # success when target name does not exist yet
            rhby, rrgy = reopenRegistry()
            try:
                # clean up from prior tests
                assert rrgy.reger.regs.get(keys="old") is None
                assert rrgy.reger.regs.get(keys="new") == record
                rrgy.reger.regs.rem(keys="new")
                rrgy.reger.regs.pin(keys="old", val=record)
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)

            directing.runController(doers=rename_cmd.handler(
                renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"

            # Final assertions, that registry record exists in expected state and old one does not
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") is None
                assert rrgy.reger.regs.get(keys="new") == record
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)
        finally:
            helpers.closeRegery(rgy)
            helpers.closeHby(hby)


def test_registry_rename_accepts_registry_said(tmp_path, capsys, helpers):
    # Purpose: verify registry rename can target the stable registry SAID, not only the current local name.
    # Imported registries are initially keyed by SAID, so this is the production recovery path for friendly names.
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name="rename-said", base=helpers.isolatedBase(TMP_BASE_PATH, tmp_path),
                         temp=False, clear=True, salt=salt) as hby:
        rgy = None
        try:
            # Initial setup
            hab = hby.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
            reg = rgy.makeRegistry(prefix=hab.pre, name="old", noBackers=True)
            record = viring.RegistryRecord(registryKey=reg.regk, prefix=hab.pre)
            helpers.closeRegery(rgy, clear=False)
            helpers.closeHby(hby, clear=False)

            # Rename by SAID lookup
            directing.runController(doers=rename_cmd.handler(
                renameArgs(registry_name="missing",
                           registry_said=reg.regk,
                           new_name="new",
                           name=hby.name,
                           base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"

            # setup for next test, reset registry record, store by SAID
            rhby = existing.setupHby(name=hby.name, base=hby.base)
            rrgy = credentialing.Regery(hby=rhby, name=rhby.name, base=rhby.base)
            try:
                assert rrgy.reger.regs.get(keys="old") is None
                assert rrgy.reger.regs.get(keys="new") == record

                rrgy.reger.regs.rem(keys="new")
                rrgy.reger.regs.pin(keys=reg.regk, val=record)
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)

            # Rename should work when registry_name is set to None (exists by SAID, not name)
            directing.runController(doers=rename_cmd.handler(
                renameArgs(registry_name=None,
                           registry_said=reg.regk,
                           new_name="renamed",
                           name=hby.name,
                           base=hby.base)))
            assert capsys.readouterr().out == f"Registry {reg.regk} renamed to renamed\n"

            # Assertions that registry record exists in expected state and old one does not
            rhby = existing.setupHby(name=hby.name, base=hby.base)
            rrgy = credentialing.Regery(hby=rhby, name=rhby.name, base=rhby.base)
            try:
                assert rrgy.reger.regs.get(keys=reg.regk) is None
                assert rrgy.reger.regs.get(keys="renamed") == record
            finally:
                helpers.closeRegery(rrgy, clear=False)
                helpers.closeHby(rhby, clear=False)
        finally:
            helpers.closeRegery(rgy)
            helpers.closeHby(hby)
