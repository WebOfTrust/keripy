# -*- encoding: utf-8 -*-
"""
tests.app.cli.test_kli_vc_schema_import module
"""
import multicommand
import pytest

from keri import core, kering
from keri.app import directing, habbing
from keri.app.cli import commands
from keri.app.cli.common import existing
from keri.app.cli.commands.vc.schema import import_ as import_cmd
from keri.core import scheming
from keri.db import dbing, subing


GLEIF_SCHEMA_SAID = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"
TMP_BASE_PATH = "base-schema-import"


def importArgs(name="test", base=TMP_BASE_PATH, schema=None):
    """Construct schema import args with the command parser."""
    return import_cmd.importParser.parse_args(["--name", name,
                                               "--base", base,
                                               "--schema", schema])


def seedSchemaFile(tmp_path, seeder):
    """Write seed schema file to disk so we can test importing it with `kli vc schema import`"""
    with habbing.openHby(name="schema-import-source", temp=True) as hby:
        seeder.seedSchema(hby.db)
        schemer = hby.db.schema.get(GLEIF_SCHEMA_SAID)
        schema_path = tmp_path / "gleif-vlei-credential-schema.json"
        schema_path.write_bytes(schemer.raw)
        return schema_path, schemer


def test_schema_import_cmd_name_correct(tmp_path):
    parser = multicommand.create_parser(commands)
    schema_path = tmp_path / "schema.json"

    # "kli vc schema import" should work
    args = parser.parse_args(["vc", "schema", "import",
                              "--name", "test",
                              "--schema", str(schema_path)])
    assert args.handler is not None
    assert args.name == "test"
    assert args.schema == str(schema_path)
    assert args.base == ""
    assert args.bran is None
    assert args.transferable is True

    # "kli vc schema import_" should fail (trailing underscore invalid)
    with pytest.raises(SystemExit):
        parser.parse_args(["vc", "schema", "import_", "--name", "test"])


def test_schema_import_requires_schema_argument():
    parser = multicommand.create_parser(commands)

    with pytest.raises(SystemExit) as ex:
        parser.parse_args(["vc", "schema", "import", "--name", "test"])

    assert ex.value.code == 2


def test_import_pins_to_schema_db(tmp_path, seeder):
    schema_path, schemer = seedSchemaFile(tmp_path, seeder)
    assert schemer.said == GLEIF_SCHEMA_SAID

    with dbing.openLMDB(name="schema-import") as db:
        schema = subing.SchemerSuber(db=db, subkey="schema.")
        said = import_cmd.importSchema(schema, str(schema_path))

        actual = schema.get(keys=(schemer.said,))
        assert said == schemer.said
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == schemer.said


def test_schema_import_doer_pins_to_target_habery_db(tmp_path, seeder, helpers):
    schema_path, schemer = seedSchemaFile(tmp_path, seeder)
    salt = core.Salter(raw=b'0123456789abcdef').qb64

    with habbing.openHby(name="schema-import-target", base=helpers.isolatedBase(TMP_BASE_PATH, tmp_path),
                         temp=False, clear=True, salt=salt) as hby:
        try:
            # assert schema is not in db prior to running import
            assert hby.db.schema.get(keys=(schemer.said,)) is None
            name = hby.name
            base = hby.base
            helpers.closeHby(hby, clear=False)

            doers = import_cmd.import_schema(importArgs(name=name,
                                                        base=base,
                                                        schema=str(schema_path)))
            # Run `kli vc schema import`
            try:
                directing.runController(doers=doers)
            finally:
                for doer in doers:
                    helpers.closeHby(getattr(doer, "hby", None), clear=False)

            rhby = existing.setupHby(name=name, base=base)
            # assert schema is in DB after import command
            try:
                actual = rhby.db.schema.get(keys=(schemer.said,))
                assert isinstance(actual, scheming.Schemer)
                assert actual.said == schemer.said
            finally:
                helpers.closeHby(rhby, clear=False)
        finally:
            helpers.closeHby(hby)


def test_import_missing_file_raises(tmp_path):
    with dbing.openLMDB(name="schema-import-missing") as db:
        schema = subing.SchemerSuber(db=db, subkey="schema.")
        with pytest.raises(kering.ConfigurationError):
            import_cmd.importSchema(schema, str(tmp_path / "missing.json"))


def test_schema_import_invalid_json_raises_configuration_error(tmp_path):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text("{bad json")

    with dbing.openLMDB(name="schema-import-invalid") as db:
        schema = subing.SchemerSuber(db=db, subkey="schema.")
        with pytest.raises(kering.ConfigurationError):
            import_cmd.importSchema(schema, str(schema_path))
