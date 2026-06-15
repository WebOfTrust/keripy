# -*- encoding: utf-8 -*-
"""
tests.app.cli.test_kli_vc_schema_import module
"""
import multicommand
import pytest

from keri import kering
from keri.app import habbing
from keri.app.cli import commands
from keri.app.cli.commands.vc.schema import import_ as schema_import_cmd
from keri.core import scheming
from keri.db import dbing, subing


GLEIF_SCHEMA_SAID = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"


def seededGleifSchemaFile(tmp_path, seeder):
    with habbing.openHby(name="schema-import-source", temp=True) as hby:
        seeder.seedSchema(hby.db)
        schemer = hby.db.schema.get(GLEIF_SCHEMA_SAID)
        schema_path = tmp_path / "gleif-vlei-credential-schema.json"
        schema_path.write_bytes(schemer.raw)
        return schema_path, schemer


def test_public_vc_schema_import_command_is_discoverable_and_import__is_hidden(tmp_path):
    parser = multicommand.create_parser(commands)
    schema_path = tmp_path / "schema.json"

    args = parser.parse_args(["vc", "schema", "import",
                              "--name", "test",
                              "--schema", str(schema_path)])
    assert args.handler is not None
    assert args.name == "test"
    assert args.schema == str(schema_path)
    assert args.base == ""
    assert args.bran is None
    assert args.transferable is True

    with pytest.raises(SystemExit):
        parser.parse_args(["vc", "schema", "import_", "--name", "test"])


def test_schema_import_pins_schema_to_schema_db(tmp_path, seeder):
    schema_path, schemer = seededGleifSchemaFile(tmp_path, seeder)
    assert schemer.said == GLEIF_SCHEMA_SAID

    with dbing.openLMDB(name="schema-import") as db:
        schema = subing.SchemerSuber(db=db, subkey="schema.")
        said = schema_import_cmd.importSchema(schema, str(schema_path))

        actual = schema.get(keys=(schemer.said,))
        assert said == schemer.said
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == schemer.said


def test_schema_import_missing_file_raises_configuration_error(tmp_path):
    with dbing.openLMDB(name="schema-import-missing") as db:
        schema = subing.SchemerSuber(db=db, subkey="schema.")
        with pytest.raises(kering.ConfigurationError):
            schema_import_cmd.importSchema(schema, str(tmp_path / "missing.json"))


def test_schema_import_invalid_json_raises_configuration_error(tmp_path):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text("{bad json")

    with dbing.openLMDB(name="schema-import-invalid") as db:
        schema = subing.SchemerSuber(db=db, subkey="schema.")
        with pytest.raises(kering.ConfigurationError):
            schema_import_cmd.importSchema(schema, str(schema_path))
