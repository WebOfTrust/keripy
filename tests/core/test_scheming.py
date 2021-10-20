# -*- encoding: utf-8 -*-
"""
tests keri.core.scheming

"""
import json

import pytest

from keri.core.coring import MtrDex, Saider
from keri.core.scheming import Ids, Schemer, JSONSchema, CacheResolver
from keri.kering import ValidationError



def test_json_schema():
    scer = (
        b'{"$id": "ExG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA", "$schema": '
        b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
        b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')
    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00"}'
    mismatch = b'{"a": "test", "b": "123", "c": "2018-11-13T20:20:39+00:00"}'
    badjson = b'{"a": "test" "b": 123 "c": "2018-11-13T20:20:39+00:00"}'

    sce = Schemer(raw=scer)
    assert sce.said == "ExG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA"
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
    assert sce.said == "ExG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA"
    assert sce.sed["$id"] == "ExG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA"
    assert sce.verify(raw=payload) is True
    assert sce.verify(raw=mismatch) is False
    assert sce.verify(raw=badjson) is False

    raw = json.dumps(sce.sed).encode("utf-8")

    sce = Schemer(raw=raw)
    assert sce.said == "ExG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA"

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
    assert sce.said == "E1AqXevVnoeItc4P7TnRpW8rOIJYm1daDe9jYVZQZLEY"
    payload = b'{"a": {"b": 123, "c": "2018-11-13T20:20:39+00:00"}}'
    assert sce.verify(payload)

    # Additional hash types
    sce = Schemer(sed=sed, code=MtrDex.Blake2b_256)
    assert sce.said == 'Ff3FXnx2ncqwIwwpSbY4fozdL01OQK3d9TG1Ejp9DZN8'
    sce = Schemer(sed=sed, code=MtrDex.Blake2s_256)
    assert sce.said == "GRidELCmdk-47s0OI6EAVk1PBolvS1HetzVbxbwBNIbI"
    sce = Schemer(sed=sed, code=MtrDex.SHA3_256)
    assert sce.said == "HmDms9gN0b0Zjmu7HyT2HEDkdnaOYm-1KgxIIhNTQPaI"
    sce = Schemer(sed=sed, code=MtrDex.SHA2_256)
    assert sce.said == "IvT1u5jtwcVQl6GlOGyfNeoyJoSmKXnOwJyIZuB2Vsh4"
    sce = Schemer(sed=sed, code=MtrDex.Blake3_512)
    assert sce.said == '0DdBaf5mQNkJku1SMrA0fOx1B2Pw4a8ZreOt8fUp2qAjDSqTfjmyUcX2Nwt28wWbD1E804ACGky8-qnmtrKSU05g'
    sce = Schemer(sed=sed, code=MtrDex.Blake2b_512)
    assert sce.said == '0E1h6aA1i48yX1nNPEVbxUwo82e6DwYIu5pf6ty6xybuKpzLYw-HQrBxfl02rhpfBci319PXt4BL_1gBqsc6Q6gw'
    sce = Schemer(sed=sed, code=MtrDex.SHA3_512)
    assert sce.said == "0FAYWj9GFRxh-YrppcR5lpVM1rm-sez1K6DDTKGfTljfbYPcdpeatBl46G8IXsQUG8ww0AbqDZRzeFuWWar2wAyA"
    sce = Schemer(sed=sed, code=MtrDex.SHA2_512)
    assert sce.said == "0GkKvqMZLvSfsGhYfl8wTZAq7Gv4khAs8v7JmUNBzZ-WOuL21RkJpxaiTXMk4_S8w_y73AnfjQZK06Vr0KMYdxww"


def test_resolution():
    ref = (b'{'
           b'   "$id": "Evcu66xr3s_x1k4IjwoQ3ZKEbfkdVLxLr7PW-67nYX4I", '
           b'   "$schema": "http://json-schema.org/draft-07/schema#", '
           b'   "type": "object", '
           b'   "properties": {'
           b'      "z": {"type": "number"}'
           b'    }'
           b'}')

    scer = (
        b'{'
        b'   "$id": "Er21QX8KuraJO-3KYXpcyBN7TFSgrasvJiTbgNLIMbbI", '
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

    schemer = Schemer(raw=scer)
    schemer.typ = JSONSchema(resolver=cache)
    v = schemer.verify(payload)
    assert v is True
    v = schemer.verify(badload)
    assert v is False


if __name__ == '__main__':
    test_json_schema()
    test_json_schema_dict()
    test_resolution()
