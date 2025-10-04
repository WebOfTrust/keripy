import os

import pytest

from keri.app.cli.common import parsing


class TestKeystoreParser:
    def test_default_keystore_base(self):
        parser = parsing.Parsery.keystore()

        result = parser.parse_args(["--name", "test"])
        assert result.base is ""

    def test_optional_keystore_name(self):
        parser = parsing.Parsery.keystore(required=False)

        result = parser.parse_args([])
        assert result.name is None

    def test_set_keystore_name(self):
        parser = parsing.Parsery.keystore()

        result = parser.parse_args(["--name", "foobar"])
        assert result.name is "foobar"

    def test_passcode_to_bran(self):
        parser = parsing.Parsery.keystore(required=False)

        result = parser.parse_args(["--passcode", "foobar"])
        assert result.bran is "foobar"
        assert result.base is ""
