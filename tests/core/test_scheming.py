# -*- encoding: utf-8 -*-
"""
tests keri.core.scheming

"""
import json

import pytest

from keri.core.coring import MtrDex, dumps, Saider, Saids
from keri.core.scheming import Schemer, JSONSchema, CacheResolver
from keri.db import basing
from keri.kering import ValidationError


def test_json_schema():
    """ Tests to validate JSON schema with SAIDS"""
    # unsaidified sad of schema
    ssad = \
    {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties":
        {
            "a":
            {
                "type": "string"
            },
            "b":
            {
                "type": "number"
            },
            "c":
            {
                "type": "string",
                "format": "date-time"
            }
        }
    }

    # generate serialized saidified schema ssad
    saider, ssad = Saider.saidify(ssad, label=Saids.dollar)
    assert saider.qb64 == 'EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw'
    sser = dumps(ssad)
    assert sser == (b'{"$id":"EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw","$schema":"http://json'
        b'-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"str'
        b'ing"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}')


    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00"}'
    mismatch = b'{"a": "test", "b": "123", "c": "2018-11-13T20:20:39+00:00"}'
    badjson = b'{"a": "test" "b": 123 "c": "2018-11-13T20:20:39+00:00"}'

    sce = Schemer(raw=sser)
    assert sce.said == saider.qb64
    assert sce.verify(raw=payload) is True
    with pytest.raises(ValidationError):
        sce.verify(raw=mismatch)

    with pytest.raises(ValidationError):
        sce.verify(raw=badjson)

    payload = b'{"a": "test", "c": "2018-11-13T20:20:39+00:00"}'
    assert sce.verify(raw=payload) is True

    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00", d:"not valid"}'
    with pytest.raises(ValidationError):
        sce.verify(raw=payload)

    # Invalid SAID for given schema
    badsaid = (b'{"$id": "EAG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPz", "$schema": '
               b'"http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, '
               b'"b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}')

    with pytest.raises(ValidationError):
        Schemer(raw=badsaid)

    # Invalid schema  with invalid type "foo" not object
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
    said = 'EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw'
    assert sce.said == sce.sed["$id"] == said
    assert sce.verify(raw=payload) is True
    with pytest.raises(ValidationError):
        sce.verify(raw=mismatch)

    with pytest.raises(ValidationError):
        sce.verify(raw=badjson)

    raw = json.dumps(sce.sed).encode("utf-8")

    sce = Schemer(raw=raw)
    assert sce.said ==said

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
    said = 'ENQKl3r1Z6HiLXOD-050aVvKziCWJtXWg3vY2FWUGSxG'
    assert sce.said == said

    payload = b'{"a": {"b": 123, "c": "2018-11-13T20:20:39+00:00"}}'
    assert sce.verify(payload)

    # Additional hash types
    sce = Schemer(sed=sed, code=MtrDex.Blake2b_256)
    assert sce.said == 'FH9xV58dp3KsCMMKUm2OH6M3S9NTkCt3fUxtRI6fQ2Tf'
    sce = Schemer(sed=sed, code=MtrDex.Blake2s_256)
    assert sce.said == 'GEYnRCwpnZPuO7NDiOhAFZNTwaJb0tR3rc1W8W8ATSGy'
    sce = Schemer(sed=sed, code=MtrDex.SHA3_256)
    assert sce.said == 'HJg5rPYDdG9GY5rux8k9hxA5HZ2jmJvtSoMSCITU0D2i'
    sce = Schemer(sed=sed, code=MtrDex.SHA2_256)
    assert sce.said == 'IL09buY7cHFUJehpThsnzXqMiaEpil5zsCciGbgdlbIe'
    sce = Schemer(sed=sed, code=MtrDex.Blake3_512)
    assert sce.said == '0DB0Fp_mZA2QmS7VIysDR87HUHY_Dhrxmt463x9SnaoCMNKpN-ObJRxfY3C3bzBZsPUTzTgAIaTLz6qea2spJTTm'
    sce = Schemer(sed=sed, code=MtrDex.Blake2b_512)
    assert sce.said == '0EDWHpoDWLjzJfWc08RVvFTCjzZ7oPBgi7ml_q3LrHJu4qnMtjD4dCsHF-XTauGl8FyLfX09e3gEv_WAGqxzpDqD'
    sce = Schemer(sed=sed, code=MtrDex.SHA3_512)
    assert sce.said == '0FABhaP0YVHGH5iumlxHmWlUzWub6x7PUroMNMoZ9OWN9tg9x2l5q0GXjobwhexBQbzDDQBuoNlHN4W5ZZqvbADI'
    sce = Schemer(sed=sed, code=MtrDex.SHA2_512)
    assert sce.said == '0GCQq-oxku9J-waFh-XzBNkCrsa_iSECzy_smZQ0HNn5Y64vbVGQmnFqJNcyTj9LzD_LvcCd-NBkrTpWvQoxh3HD'


def test_resolution():
    """ Test resolve in db schema SAID references in another schema """
    refsad = \
    {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties":
        {
            "z":
            {
                "type": "number"
            }
        }
    }

    # generate serialized saidified schema refsad
    saider, refsad = Saider.saidify(refsad, label=Saids.dollar)
    refsaid = saider.qb64
    assert refsaid == 'EL3Luusa97P8dZOCI8KEN2ShG35HVS8S6-z1vuu52F-C'
    ref = dumps(refsad)

    ssad = \
    {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties":
        {
            "a":
            {
                "type": "string"
            },
            "b":
            {
                "type": "number"
            },
            "c":
            {
                "type": "string",
                "format": "date-time"
            },
            "xy":
            {
                "$ref": ""
            }
        }
    }

    ssad["properties"]["xy"]["$ref"] = f"did:keri:{refsaid}"

    # generate serialized saidified schema ssad
    saider, ssad = Saider.saidify(ssad, label=Saids.dollar)
    said = saider.qb64
    assert said == 'EKcRFuOiLUMEgTljL8FWPOpDosH2Cz38HhgdmRKpUHTe'
    sser = dumps(ssad)
    assert sser ==  (b'{"$id":"EKcRFuOiLUMEgTljL8FWPOpDosH2Cz38HhgdmRKpUHTe","$schema":"http://json'
                    b'-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"str'
                    b'ing"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"},"xy":'
                    b'{"$ref":"did:keri:EL3Luusa97P8dZOCI8KEN2ShG35HVS8S6-z1vuu52F-C"}}}')


    scer = (
        b'{'
        b'   "$id": "EDfHSaA1XvjltvoO1flnZVuNr8y-wWvGTBKiP1naFxUs", '
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
        b'         "$ref": "did:keri:Evcu66xr3s_x1k4IjwoQ3ZKEbfkdVLxLr7PW-67nYX4I"'
        b'      }'
        b'   }'
        b'}')

    payload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00", "xy": {"z": 456}}'
    badload = b'{"a": "test", "b": 123, "c": "2018-11-13T20:20:39+00:00", "xy": {"z": "456"}}'

    with basing.openDB(name="edy") as db:
        cache = CacheResolver(db=db)
        cache.add(refsaid, ref)  # add referenced schema to db indexed by its said

        schemer = Schemer(raw=sser)
        schemer.typ = JSONSchema(resolver=cache)
        v = schemer.verify(payload)
        assert v is True

        with pytest.raises(ValidationError):
            schemer.verify(badload)


if __name__ == '__main__':
    test_json_schema()
    test_json_schema_dict()
    test_resolution()
