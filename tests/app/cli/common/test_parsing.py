import json
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


class TestDataParser:
    def test_parse_json_string(self):
        data_str = '{"key": "value"}'
        result = parsing.parseDataItems([data_str])
        assert result == {"key": "value"}

    def test_parse_json_file(self, tmp_path):
        data = {"file_key": "file_value"}
        file_path = tmp_path / "data.json"
        with open(file_path, "w") as f:
            f.write(json.dumps(data))

        result = parsing.parseDataItems([f"@{file_path}"])
        assert result == data

    def test_parse_key_value_pairs(self):
        kv_pairs = ["key1=value1", "key2=value2"]
        result = parsing.parseDataItems(kv_pairs)
        assert result == {"key1": "value1", "key2": "value2"}

    def test_parse_mixed_inputs(self, tmp_path):
        data = {"file_key": "file_value"}
        file_path = tmp_path / "data.json"
        with open(file_path, "w") as f:
            f.write(json.dumps(data))

        inputs = ['{"json_key": "json_value"}', f"@{file_path}", "key=value"]
        result = parsing.parseDataItems(inputs)
        assert result == {
            "json_key": "json_value",
            "file_key": "file_value",
            "key": "value",
        }

    def test_parse_empty_string(self):
        result = parsing.parseDataItems([""])
        assert result == {}

    def test_parse_invalid_json(self):
        invalid_json = '{"key": "value"'
        with pytest.raises(json.JSONDecodeError):
            parsing.parseDataItems([invalid_json])

    def test_parse_boolean_value(self):
        kv_pairs = ["key1=true", "key2=false"]
        result = parsing.parseDataItems(kv_pairs)
        assert result == {"key1": True, "key2": False}

    def test_parse_numeric_value(self):
        kv_pairs = ["key1=123", "key2=-45.67"]
        result = parsing.parseDataItems(kv_pairs)
        print(result)
        assert result == {"key1": 123, "key2": -45.67}
