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


def isolatedBase(tmp_path):
    """
    Return a relative KERI base namespace string unique to this pytest test.
    Supports parallelization.

    pytest's tmp_path is a per-test filesystem path, for example:
    /.../pytest-42/test_registry_rename_branches0

    KERI's base must be relative, so this helper uses only the final directory names:
        tmp_path.parent.name  # "pytest-42"
        tmp_path.name         # "test_registry_rename_branches0"

    Result:
        base-reg-rename-pytest-42-test_registry_rename_branches0

    When openHby(..., name="rename", base=<base>, temp=False) opens KERI resources,
    KERI/HIO combines this relative base with each resource tail:
      - /usr/local/var/keri/ks/<base>/rename/data.mdb
      - /usr/local/var/keri/db/<base>/rename/data.mdb
      - /usr/local/var/keri/cf/<base>/rename/rename.json
      - /usr/local/var/keri/reg/<base>/rename/data.mdb
      - and so forth
    For temp=True paths get created under /tmp/...
    """
    return f"{TMP_BASE_PATH}-{tmp_path.parent.name}-{tmp_path.name}"


def closeRegery(rgy, clear=True):
    """
    Closes Regery
    Needed to avoid LMDB's recently added strict double open errors (used to be just warnings).
    """
    reger = getattr(rgy, "reger", None)
    if reger is not None and (reger.opened or clear):
        reger.close(clear=clear)


def closeHby(hby, clear=True):
    """
    Closes Habery and its Configer.
    Needed to avoid LMDB's new strict double open errors.
    """
    if hby is not None:
        cf = getattr(hby, "cf", None)
        hby.close(clear=clear)
        if clear and cf is not None:
            cf.close(clear=True)


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


def test_registry_rename(tmp_path, capsys):
    # Purpose: cover registry rename outcomes against a persistent keystore.
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name="rename", base=isolatedBase(tmp_path),
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
            closeRegery(rgy, clear=False)
            closeHby(hby, clear=False)

            # missing registry
            rhby, rrgy = reopenRegistry()
            try:
                assert rrgy.reger.regs.get(keys="old") == record
                rrgy.reger.regs.rem(keys="old")
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
            directing.runController(doers=rename_cmd.handler(
                renameArgs("missing", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry missing not found\n"

            # registry already exists under new name
            rhby, rrgy = reopenRegistry()
            try:
                rrgy.reger.regs.pin(keys="old", val=record)
                rrgy.makeRegistry(prefix=hab.pre, name="new", noBackers=True)
            finally:
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
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
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)

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
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)

            directing.runController(doers=rename_cmd.handler(
                renameArgs("old", "new", name=hby.name, base=hby.base)))
            assert capsys.readouterr().out == "Registry old renamed to new\n"

            # Final assertions, that registry record exists in expected state and old one does not
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
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name="rename-said", base=isolatedBase(tmp_path),
                         temp=False, clear=True, salt=salt) as hby:
        rgy = None
        try:
            # Initial setup
            hab = hby.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
            reg = rgy.makeRegistry(prefix=hab.pre, name="old", noBackers=True)
            record = viring.RegistryRecord(registryKey=reg.regk, prefix=hab.pre)
            closeRegery(rgy, clear=False)
            closeHby(hby, clear=False)

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
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)

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
                closeRegery(rrgy, clear=False)
                closeHby(rhby, clear=False)
        finally:
            closeRegery(rgy)
            closeHby(hby)