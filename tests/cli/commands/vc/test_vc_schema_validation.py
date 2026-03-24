# -*- encoding: utf-8 -*-
"""
Tests for kli vc list and kli vc create empty schema validation (issue #1058).
"""

import pytest

from keri.kering import ConfigurationError
from keri.cli.commands.vc import list as list_cmd
from keri.cli.commands.vc import create as create_cmd


class TestEmptySchemaValidation:
    """Empty or blank --schema argument should raise ConfigurationError early,
    not a KeyError from LMDB."""

    def test_list_parser_accepts_schema(self):
        """Verify the parser has --schema and default is None."""
        args = list_cmd.parser.parse_args([
            "--name", "test",
        ])
        assert args.schema is None

    def test_list_empty_schema_raises(self):
        """Passing --schema '' to kli vc list should raise ConfigurationError."""
        args = list_cmd.parser.parse_args([
            "--name", "test",
            "--schema", "",
        ])
        with pytest.raises(ConfigurationError, match="schema.*must not be empty"):
            list_cmd.ListDoer(
                name=args.name,
                alias="test",
                base=args.base,
                bran=args.bran,
                schema=args.schema,
            )

    def test_create_empty_schema_raises(self):
        """Passing --schema '' to kli vc create should raise ConfigurationError."""
        with pytest.raises(ConfigurationError, match="schema.*must not be empty"):
            create_cmd.CredentialIssuer(
                name="test",
                alias="test",
                base="",
                bran=None,
                schema="",
                data={"d": "test"},
            )
