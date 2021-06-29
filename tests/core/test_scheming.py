# -*- encoding: utf-8 -*-
"""
tests keri.core.scheming

"""
import json

import pytest

from keri.core.coring import MtrDex
from keri.core.scheming import Schemer, Saider, JSONSchema, CacheResolver
from keri.kering import ValidationError


def test_saider():
    # Initialize from JSON Schema JSON
    scer = (
        b'{"$id": "EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
        b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')

    sad = Saider(qb64="EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY")
    assert sad.code == MtrDex.Blake3_256

    sed = json.loads(scer)
    assert sad.verify(sed, prefixed=True) is True

    sed = dict()
    sed["$id"] = ""
    sed["$schema"] = "http://json-schema.org/draft-07/schema#"
    sed.update(dict(
        type="object",
        properties=dict(
            a=dict(
                type="string"
            ),
            b=dict(
                type="number"
            ),
            c=dict(
                type="string",
                format="date-time"
            )
        )
    ))

    assert sad.verify(sed, prefixed=False) is True
    assert sad.verify(sed, prefixed=True) is False

    # Initialize from dict
    sad = Saider(sed=sed, code=MtrDex.Blake3_256)
    assert sad.qb64 == "EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY"
    assert sad.verify(sed, prefixed=False) is True

    sed = json.loads(scer)
    assert sad.verify(sed, prefixed=True) is True


def test_json_schema():
    scer = (
        b'{"$id": "EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
        b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')
    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00"}'
    mismatch = b'{"a": "test", "b": "123", "c": "2018-11-13T20:20:39+00:00"}'
    badjson = b'{"a": "test" "b": 123 "c": "2018-11-13T20:20:39+00:00"}'

    sce = Schemer(raw=scer)
    assert sce.said == "EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY"
    assert sce.verify(raw=payload) is True
    assert sce.verify(raw=mismatch) is False
    assert sce.verify(raw=badjson) is False

    payload = b'{"a": "test", "c": "2018-11-13T20:20:39+00:00"}'
    assert sce.verify(raw=payload) is True

    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00", d:"not valid"}'
    assert sce.verify(raw=payload) is False

    # Invalid SAID for given schema
    badsaid = (b'{"$id": "ExG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPz", "$schema": '
               b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
               b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')

    with pytest.raises(ValidationError):
        Schemer(raw=badsaid)

    # Invalid schema
    invalid = (b'{"$id": "EOo3qzfwxPxY5VvhM816apl1zEV88F1CICr_BSKy45lk", "$schema": '
               b'"http://json-schema.org/draft-07/schema#", "type": "foo", "properties": {"a": {"type": "string"}, '
               b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')

    with pytest.raises(ValidationError):
        Schemer(raw=invalid)


def test_json_schema_dict():
    sed = dict()
    sed["$id"] = ""
    sed["$schema"] = "http://json-schema.org/draft-07/schema#"
    sed.update(dict(
        type="object",
        properties=dict(
            a=dict(
                type="string"
            ),
            b=dict(
                type="number"
            ),
            c=dict(
                type="string",
                format="date-time"
            )
        )
    ))

    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00"}'
    mismatch = b'{"a": "test", "b": "123", "c": "2018-11-13T20:20:39+00:00"}'
    badjson = b'{"a": "test" "b": 123 "c": "2018-11-13T20:20:39+00:00"}'

    sce = Schemer(sed=sed, typ=JSONSchema(), code=MtrDex.Blake3_256)
    assert sce.said == "EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY"
    assert sce.verify(raw=payload) is True
    assert sce.verify(raw=mismatch) is False
    assert sce.verify(raw=badjson) is False

    sed["$id"] = sce.said
    raw = json.dumps(sed).encode("utf-8")

    sce = Schemer(raw=raw)
    assert sce.said == "EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndY"

    # Invalid JSON Schema
    sed = dict()
    sed["$id"] = ""
    sed["$schema"] = "http://json-schema.org/draft-07/schema#"
    sed.update(dict(
        type="foo",
        properties=dict(
            a=dict(
                type="string"
            ),
            b=dict(
                type="number"
            ),
            c=dict(
                type="string",
                format="date-time"
            )
        )
    ))

    with pytest.raises(ValidationError):
        Schemer(sed=sed, code=MtrDex.Blake3_256)

    # Nested JSON Schema
    sed = dict()
    sed["$id"] = ""
    sed["$schema"] = "http://json-schema.org/draft-07/schema#"
    sed.update(dict(
        type="object",
        properties=dict(
            a=dict(
                type="object",
                properties=dict(
                    b=dict(
                        type="number"
                    ),
                    c=dict(
                        type="string",
                        format="date-time"
                    )
                )
            ),
        )
    ))

    sce = Schemer(sed=sed, code=MtrDex.Blake3_256)
    assert sce.said == "E85XpgsvzBLPVHiy0EzFmNCTN13DUK4eITMoY2kmVD8o"
    payload = b'{"a": {"b": 123, "c": "2018-11-13T20:20:39+00:00"}}'
    assert sce.verify(payload)

    # Additional hash types
    sce = Schemer(sed=sed, code=MtrDex.Blake2b_256)
    assert sce.said == "FtDGHM1-15UdUiIki8mtKgfpC9CLxuq16wr55nw3htZs"
    sce = Schemer(sed=sed, code=MtrDex.Blake2s_256)
    assert sce.said == "Ga063NUEvWf4ZNm7qgbAUVhcBMEL8vddQhEauTk2HuKo"
    sce = Schemer(sed=sed, code=MtrDex.SHA3_256)
    assert sce.said == "HUhsiL9Hl9c6DVZ9YioCKiyLIuJmnEd0ALKNge3bMMn0"
    sce = Schemer(sed=sed, code=MtrDex.SHA3_512)
    assert sce.said == "0FaBVrb4jLlfgSqNaAGf3gFpRJJvZUiyPg-2W240y3IO1SCv2kD3rkowQ9i9yOVYT_K3BZ54eBN1zpqvkoEMk7YQ"
    sce = Schemer(sed=sed, code=MtrDex.SHA2_256)
    assert sce.said == "IRgVJumn8RaXh0WJV1QT3zS3rUwhuCJDDhzgFRE-Fdn4"
    sce = Schemer(sed=sed, code=MtrDex.SHA2_512)
    assert sce.said == "0GiFhrQdu9N7xDkB7IDLVdj13zGydat-oJyYK0pFXaW695YeZZh-KPJJ-8ku47W-XmRqI8TpwV0NVyr0LC6ogGMg"


def test_resolution():
    ref = (b'{'
           b'   "$id": "EMZXD1QYBN3PtDq4M2Y_BWiswd3bdraXGoFj_ALcOPjI", '
           b'   "$schema": "http://json-schema.org/draft-07/schema#", '
           b'   "type": "object", '
           b'   "properties": {'
           b'      "z": {"type": "number"}'
           b'    }'
           b'}')

    scer = (
        b'{'
        b'   "$id": "ETZr8wWfVcUm7HdXwNjJaQJpcdlMeY6kR3eA9i9ZItxo", '
        b'   "$schema": "http://json-schema.org/draft-07/schema#", '
        b'   "type": "object", '
        b'   "properties": {'
        b'      "a": {'
        b'         "type": "string"'
        b'      }, '
        b'      "b": {'
        b'         "type": "number"'
        b'      }, '
        b'      "c": {'
        b'         "type": "string", '
        b'         "format": "date-time"'
        b'      },'
        b'      "xy": {'
        b'         "$ref": "did:keri:EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndZ"'
        b'      }'
        b'   }'
        b'}')

    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00", "xy": {"z": 456}}'
    badload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00", "xy": {"z": "456"}}'

    cache = CacheResolver()
    cache.add("did:keri:EQtF_DhWj-uCPTsq4BONO0yR0PWLpUITkSqHoW0JjndZ", ref)

    schemer = Schemer(raw=scer, typ=JSONSchema(resolver=cache.resolver(scer)))
    assert schemer.verify(payload) is True
    assert schemer.verify(badload) is False


if __name__ == '__main__':
    test_saider()
    test_json_schema()
    test_json_schema_dict()
    test_resolution()
