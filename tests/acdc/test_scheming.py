# -*- encoding: utf-8 -*-
"""Security and profile tests for ACDC schema validation."""

import urllib.request
from copy import deepcopy

import pytest

from keri import Vrsn_2_0
from keri.acdc import acdcmap, scheming
from keri.app import openHby
from keri.core import Diger, Schemer, dumps
from keri.kering import FailedSchemaValidationError, MissingSchemaError
from tests.sedi import test_sedi as sedi


def _schema(attribute=None, *, dialect=scheming.SchemaDialect,
            version="1.0.0", extra=None):
    sad = {
        "$id": "",
        "type": "object",
        "required": ["v", "d", "i", "s", "a"],
        "properties": {
            "v": {"type": "string"},
            "d": {"type": "string"},
            "i": {"type": "string"},
            "s": {},
            "a": attribute or {"type": "object"},
        },
    }
    if dialect is not None:
        sad["$schema"] = dialect
    if version is not None:
        sad["version"] = version
    if extra:
        sad.update(extra)
    return Schemer(sed=sad)


@pytest.mark.parametrize(
    "said,schema",
    (
        (sedi.ReplaceSchemaSaid, sedi.ReplaceSchema),
        (sedi.UnitSchemaSaid, sedi.UnitSchema),
        (sedi.AgentSchemaSaid, sedi.AgentSchema),
        (sedi.IarSchemaSaid, sedi.IarSchema),
        (sedi.CoreSchemaSaid, sedi.CoreSchema),
        (sedi.GuardianSchemaSaid, sedi.GuardianSchema),
        (sedi.ResidenceSchemaSaid, sedi.ResidenceSchema),
        (sedi.AgeSchemaSaid, sedi.AgeSchema),
        (sedi.ImageSchemaSaid, sedi.ImageSchema),
        (sedi.SocialSchemaSaid, sedi.SocialSchema),
        (sedi.BespokeSchemaSaid, sedi.BespokeSchema),
    ),
)
def test_sedi_schema_profile(said, schema):
    """Accept every production-like SEDI model with its content-bound SAID."""
    # Verify the schema SAID
    schemer = scheming._verifySchemer(schema, expected=said)

    # Check the ACDC schema profile
    assert scheming._checkProfile(schemer) == []


def test_acdc_schema_profile():
    """Accept omitted dialect metadata and reject invalid schema profiles."""
    with openHby(name="acdc-schema-profile", base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")

        # Validate a complete schema
        valid = _schema()
        credential = acdcmap(israid=hab.pre,
                             schema=valid.sed,
                             attribute={"d": ""})
        assert scheming.validateSchema(credential, hby.db)

        # Validate without a declared dialect
        withoutDialect = _schema(dialect=None)
        credential = acdcmap(israid=hab.pre,
                             schema=withoutDialect.sed,
                             attribute={"d": ""})
        assert scheming.validateSchema(credential, hby.db)

        # Reject invalid dialect and version values
        for invalid in (_schema(dialect="http://json-schema.org/draft-07/schema#"),
                        _schema(version=None),
                        _schema(version="one"),
                        _schema(version="1.0.0-alpha"),
                        _schema(version="1.0.0+build")):
            credential = acdcmap(israid=hab.pre,
                                 schema=invalid.sed,
                                 attribute={"d": ""})
            with pytest.raises(FailedSchemaValidationError):
                scheming.validateSchema(credential, hby.db)

        # Reject a dynamic reference
        dynamic = _schema(attribute={"$dynamicRef": "#attribute"})
        credential = acdcmap(israid=hab.pre,
                             schema=dynamic.sed,
                             attribute={"d": ""})
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)

        # Reject a recursive reference
        recursive = _schema(extra={"$ref": "#"})
        credential = acdcmap(israid=hab.pre,
                             schema=recursive.sed,
                             attribute={"d": ""})
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)


def test_acdc_schema_never_dereferences_urls(monkeypatch):
    """Reject arbitrary remote references without making network requests."""
    with openHby(name="acdc-schema-no-network", base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")
        calls = []

        # Record any network request
        def urlopen(*args, **kwa):
            calls.append((args, kwa))
            raise AssertionError("schema validation attempted network access")

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        schema = _schema()

        # Validate a local embedded schema
        credential = acdcmap(israid=hab.pre,
                             schema=schema.sed,
                             attribute={"d": ""})
        assert scheming.validateSchema(credential, hby.db)

        # Create an unsafe remote reference
        remote = _schema(attribute={
            "$ref": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        })
        credential = acdcmap(israid=hab.pre,
                             schema=remote.sed,
                             attribute={"d": ""})

        # Reject it without using the network
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)
        assert calls == []


def test_acdc_schema_draft_202012_vocabulary():
    """Apply standard composition, conditional, and pattern constraints."""
    with openHby(name="acdc-schema-vocabulary", base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")

        # Build a schema with standard Draft 2020-12 keywords
        schema = _schema(attribute={
            "allOf": [
                {
                    "type": "object",
                    "required": ["d", "code"],
                    "properties": {
                        "d": {"type": "string"},

                        # Require two letters and two digits
                        "code": {"type": "string", "pattern": "^[A-Z]{2}[0-9]{2}$"},
                    },
                    "patternProperties": {"^x-": {"type": "integer"}},
                },
                {
                    # Require approved only for AB12
                    "if": {"properties": {"code": {"const": "AB12"}}},
                    "then": {"required": ["approved"]},
                    "else": {"not": {"required": ["approved"]}},
                },
            ],
        })

        # Validate a matching credential
        credential = acdcmap(israid=hab.pre,
                             schema=schema.sed,
                             attribute={"d": "", "code": "AB12",
                                        "approved": True, "x-rank": 1})
        assert scheming.validateSchema(credential, hby.db)

        # Reject credentials that break each constraint
        for attribute in ({"d": "", "code": "bad"},
                          {"d": "", "code": "AB12"},
                          {"d": "", "code": "CD34", "x-rank": "first"}):
            credential = acdcmap(israid=hab.pre,
                                 schema=schema.sed,
                                 attribute=attribute)
            with pytest.raises(FailedSchemaValidationError):
                scheming.validateSchema(credential, hby.db)


def test_acdc_schema_internal_and_said_bound_references():
    """Resolve internal, cached external, and bundled static schema resources."""
    with openHby(name="acdc-schema-references", base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")

        # Resolve an internal reference
        internal = _schema(
            attribute={"$ref": "#/$defs/attribute"},
            extra={
                "$defs": {
                    "attribute": {
                        "type": "object",
                        "required": ["d", "name"],
                        "properties": {
                            "d": {"type": "string"},
                            "name": {"type": "string"},
                        },
                    },
                },
            },
        )
        credential = acdcmap(israid=hab.pre,
                             schema=internal.sed,
                             attribute={"d": "", "name": "Ada"})
        assert scheming.validateSchema(credential, hby.db)

        # Cache a separate schema resource
        external = Schemer(sed={
            "$id": "",
            "$schema": scheming.SchemaDialect,
            "version": "1.0.0",
            "$ref": "#/$defs/attribute",
            "$defs": {
                "attribute": {
                    "type": "object",
                    "required": ["d", "name"],
                    "properties": {
                        "d": {"type": "string"},
                        "name": {"type": "string"},
                    },
                },
            },
        })
        hby.db.schema.pin(external.said, external)

        # Resolve each supported form from the local cache
        for reference in (
            external.said,
            f"sad:{external.said}",
            f"sad:{external.said}#/$defs/attribute",
            f"did:keri:{external.said}",
            f"https://schemas.example/oobi/{external.said}",
        ):
            root = _schema(attribute={"$ref": reference})
            credential = acdcmap(israid=hab.pre,
                                 schema=root.sed,
                                 attribute={"d": "", "name": "Ada"})
            assert scheming.validateSchema(credential, hby.db)

            # Apply the referenced schema constraints
            credential = acdcmap(israid=hab.pre,
                                 schema=root.sed,
                                 attribute={"d": "", "name": 7})
            with pytest.raises(FailedSchemaValidationError):
                scheming.validateSchema(credential, hby.db)

        # Verify a bundled schema with its own $id
        bundled = {
            "$id": "did:keri:" + "#" * 44,
            "version": "1.0.0",
            "type": "object",
            "required": ["d", "score"],
            "properties": {
                "d": {"type": "string"},
                "score": {"type": "integer"},
            },
        }
        bundled["$id"] = "did:keri:" + Diger(ser=dumps(bundled)).qb64
        root = _schema(
            attribute={"$ref": bundled["$id"]},
            extra={"$defs": {"attribute": bundled}},
        )
        credential = acdcmap(israid=hab.pre,
                             schema=root.sed,
                             attribute={"d": "", "score": 10})
        assert scheming.validateSchema(credential, hby.db)


def test_acdc_schema_reference_failures(monkeypatch):
    """Fail closed on mutable references, bad fragments, and unverified SADs."""
    with openHby(name="acdc-schema-reference-failures", base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")
        calls = []

        # Record any network request
        def urlopen(*args, **kwa):
            calls.append((args, kwa))
            raise AssertionError("schema validation attempted network access")

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)

        # Reject references without a valid schema SAID
        for reference in (
            "https://schemas.example/current.json",
            "file:///tmp/schema.json",
            "relative/schema.json",
            "sad:not-a-said",
            "did:keri:not-a-said",
            "https://schemas.example/oobi/not-a-said",
        ):
            root = _schema(attribute={"$ref": reference})
            credential = acdcmap(israid=hab.pre,
                                 schema=root.sed,
                                 attribute={"d": ""})
            with pytest.raises(FailedSchemaValidationError):
                scheming.validateSchema(credential, hby.db)
        assert calls == []

        # Reject a missing internal target
        root = _schema(attribute={"$ref": "#/$defs/missing"})
        credential = acdcmap(israid=hab.pre,
                             schema=root.sed,
                             attribute={"d": ""})
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)

        # Reject internal references that resolve to data instead of a schema
        for target in (5, "not a schema", []):
            root = _schema(attribute={"$ref": "#/notASchema"},
                           extra={"notASchema": target})
            credential = acdcmap(israid=hab.pre,
                                 schema=root.sed,
                                 attribute={"d": ""})
            with pytest.raises(FailedSchemaValidationError):
                scheming.validateSchema(credential, hby.db)

        # Accept Boolean schema targets
        root = _schema(attribute={"$ref": "#/allowed"},
                       extra={"allowed": True})
        credential = acdcmap(israid=hab.pre,
                             schema=root.sed,
                             attribute={"d": ""})
        assert scheming.validateSchema(credential, hby.db)

        # Report an unavailable external schema as missing
        external = Schemer(sed={
            "$id": "",
            "$schema": scheming.SchemaDialect,
            "version": "1.0.0",
            "type": "object",
        })
        root = _schema(attribute={"$ref": f"sad:{external.said}"})
        credential = acdcmap(israid=hab.pre,
                             schema=root.sed,
                             attribute={"d": ""})
        with pytest.raises(MissingSchemaError) as ex:
            scheming.validateSchema(credential, hby.db)
        assert ex.value.args == (external.said,)

        # Reject content stored under the wrong SAID
        wrong = Schemer(sed={
            "$id": "",
            "$schema": scheming.SchemaDialect,
            "version": "1.0.0",
            "type": "string",
        })
        hby.db.schema.pin(external.said, wrong)
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)

        # Reject an external fragment that resolves to data
        invalidTarget = Schemer(sed={
            "$id": "",
            "$schema": scheming.SchemaDialect,
            "version": "1.0.0",
            "type": "object",
            "notASchema": 5,
        })
        hby.db.schema.pin(invalidTarget.said, invalidTarget)
        root = _schema(attribute={
            "$ref": f"sad:{invalidTarget.said}#/notASchema",
        })
        credential = acdcmap(israid=hab.pre,
                             schema=root.sed,
                             attribute={"d": ""})
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)

        # Reject a changed bundled schema
        bundled = Schemer(sed={
            "$id": "",
            "version": "1.0.0",
            "type": "object",
        }).sed
        bundled = deepcopy(bundled)
        bundled["type"] = "string"
        root = _schema(attribute={"$ref": bundled["$id"]},
                       extra={"$defs": {"attribute": bundled}})
        credential = acdcmap(israid=hab.pre,
                             schema=root.sed,
                             attribute={"d": ""})
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)


def test_acdc_schema_root_lookup_failures():
    """Escrow a missing root schema and reject content stored under its SAID."""
    with openHby(name="acdc-schema-root-failures", base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")
        root = _schema()
        credential = acdcmap(israid=hab.pre,
                             schema=root.said,
                             attribute={"d": ""})

        # Report an uncached root schema as missing
        with pytest.raises(MissingSchemaError) as ex:
            scheming.validateSchema(credential, hby.db)
        assert ex.value.args == (root.said,)

        # Reject the wrong schema under the requested SAID
        wrong = _schema(attribute={"type": "string"})
        hby.db.schema.pin(root.said, wrong)
        with pytest.raises(FailedSchemaValidationError):
            scheming.validateSchema(credential, hby.db)

        # Accept the credential after caching the correct schema
        hby.db.schema.pin(root.said, root)
        assert scheming.validateSchema(credential, hby.db)
