# -*- encoding: utf-8 -*-
"""
keri.acdc.scheming module

ACDC Schema support

"""

from collections.abc import Mapping
from copy import deepcopy
from urllib.parse import urlsplit

import jsonschema
import referencing
import semver
from referencing.jsonschema import DRAFT202012

from ..core import Diger, Saider, Schemer, dumps
from ..kering import (FailedSchemaValidationError, MissingSchemaError,
                      ValidationError)

SchemaDialect = "https://json-schema.org/draft/2020-12/schema"
_DynamicKeywords = frozenset(("$dynamicAnchor", "$dynamicRef",
                              "$recursiveAnchor", "$recursiveRef"))


def _referenceSaid(reference):
    """Get the schema SAID named by a JSON Schema reference.

    Internal references such as ``#/$defs/name`` return ``None`` because they
    stay inside the current schema. External references are accepted only when
    they contain one valid SAID in a supported bare, ``sad:``, DID, or OOBI
    form.

    Parameters:
        reference (str): Value from ``$ref`` or a nested ``$id``.

    Returns:
        str | None: The referenced schema SAID, or ``None`` for an internal
            reference.

    Raises:
        FailedSchemaValidationError: If the reference is invalid or does not
            contain exactly one usable schema SAID.
    """
    # Require a non-empty string
    if not isinstance(reference, str) or not reference:
        raise FailedSchemaValidationError("schema reference is not a non-empty string")

    # Separate the resource from its fragment
    base, _, _ = reference.partition("#")
    if not base:
        return None

    # Accept a bare SAID
    try:
        saider = Saider(qb64=base)
    except Exception:
        saider = None
    if saider is not None and saider.qb64 == base:
        return base

    # Look for a SAID in another supported form
    candidate = None

    # Read the SAID from a sad URI
    if base.startswith("sad:"):
        candidate = base[4:]

    # Read the SAID from a DID URI
    elif base.startswith("did:"):

        # A DID reference must contain one SAID
        separators = str.maketrans({char: " " for char in ":/;?&="})
        tokens = base.translate(separators).split()
        candidates = []
        for token in tokens:
            try:
                saider = Saider(qb64=token)
            except Exception:
                continue
            if saider.qb64 == token:
                candidates.append(token)
        if len(candidates) == 1:
            candidate = candidates[0]
    else:
        # Read the SAID from a schema OOBI URL
        parsed = urlsplit(base)
        parts = [part for part in parsed.path.split("/") if part]
        if (parsed.scheme in ("http", "https") and parsed.netloc
                and len(parts) == 2 and parts[0].lower() == "oobi"):
            candidate = parts[1]

    # Confirm the result is one complete SAID
    try:
        saider = Saider(qb64=candidate) if candidate is not None else None
    except Exception:
        saider = None
    if saider is None or saider.qb64 != candidate:
        raise FailedSchemaValidationError(
            f"schema reference {reference} is not statically SAID-bound")
    return candidate


def _checkVersion(schema, identifier):
    """Check that a schema has a ``major.minor.patch`` version.

    Parameters:
        schema (Mapping): Schema containing the ``version`` field.
        identifier (str): Schema name used in error messages.

    Raises:
        FailedSchemaValidationError: If ``version`` is missing or is not a
            plain three-part semantic version such as ``1.2.3``.
    """
    # Require a version
    version = schema.get("version")
    if version is None:
        raise FailedSchemaValidationError(f"schema {identifier} is missing version")
    if not isinstance(version, str):
        raise FailedSchemaValidationError(
            f"schema {identifier} version is not semantic version text")

    try:
        # Parse the semantic version
        parsed = semver.Version.parse(version)
    except ValueError as ex:
        raise FailedSchemaValidationError(
            f"schema {identifier} has invalid semantic version {version}") from ex

    # Reject prerelease and build values
    if parsed.prerelease is not None or parsed.build is not None:
        raise FailedSchemaValidationError(
            f"schema {identifier} version must use major.minor.patch")


def _verifyResource(schema, kind=None):
    """Verify a bundled subschema that has its own ``$id``.

    The ``$id`` must contain the SAID produced by the bundled subschema's
    content. The bundled subschema must also have a valid version.

    Parameters:
        schema (Mapping): Bundled subschema to verify.
        kind (str | None): Serialization format used to calculate its SAID.

    Raises:
        FailedSchemaValidationError: If the ``$id``, SAID, content, or version
            is invalid.
    """
    # Require a valid nested $id
    declared = schema.get("$id")
    if not isinstance(declared, str) or "#" in declared:
        raise FailedSchemaValidationError("bundled schema has an invalid $id")

    # Get the one SAID from the $id
    said = _referenceSaid(declared)
    if said is None or declared.count(said) != 1:
        raise FailedSchemaValidationError(
            f"bundled schema $id {declared} does not contain one SAID")

    # Replace the SAID with its digest placeholder
    saider = Saider(qb64=said)
    sad = dict(schema)
    sad["$id"] = declared.replace(said, "#" * len(said))
    raw = dumps(sad) if kind is None else dumps(sad, kind=kind)

    # Confirm the content produces the declared SAID
    if Diger(ser=raw, code=saider.code).qb64 != said:
        raise FailedSchemaValidationError(
            f"bundled schema {declared} content does not match its SAID")

    # Check the bundled schema version
    _checkVersion(schema, declared)


def _inspectSchema(schema, *, root=True, kind=None, base=None):
    """Check a schema and collect the references it uses.

    This walks only fields that Draft 2020-12 treats as subschemas. It rejects
    dynamic references, checks nested schema resources, and collects valid
    ``$ref`` values for later local resolution.

    Parameters:
        schema (Mapping | bool): Schema or subschema to inspect.
        root (bool): ``True`` when inspecting the top-level schema.
        kind (str | None): Serialization format used to verify bundled schemas.
        base (str | None): ``$id`` of the schema resource containing this
            subschema.

    Returns:
        list: Pairs containing each reference's base URI and ``$ref`` value.

    Raises:
        FailedSchemaValidationError: If the schema uses an unsupported feature,
            unsafe reference, wrong dialect, or invalid bundled schema.
    """
    # Boolean schemas have nothing else to inspect
    if isinstance(schema, bool):
        return []
    if not isinstance(schema, Mapping):
        raise FailedSchemaValidationError("schema contains an invalid subschema")

    # Reject dynamic and recursive references
    dynamic = set(schema).intersection(_DynamicKeywords)
    if dynamic:
        raise FailedSchemaValidationError(
            f"schema uses prohibited dynamic keyword {sorted(dynamic)[0]}")

    # Check a declared schema dialect
    dialect = schema.get("$schema")
    if dialect is not None and dialect != SchemaDialect:
        raise FailedSchemaValidationError(
            f"schema resource must use $schema {SchemaDialect}")

    # Use the root schema ID as its reference base
    if root:
        base = schema.get("$id")

    # Verify a bundled schema and use its $id as the new base
    if not root and "$id" in schema:
        _verifyResource(schema, kind=kind)
        base = schema["$id"]

    # Check and collect a $ref
    references = []
    if "$ref" in schema:
        _referenceSaid(schema["$ref"])
        references.append((base, schema["$ref"]))

    # Inspect each Draft 2020-12 subschema
    for child in DRAFT202012.subresources_of(schema):
        references.extend(_inspectSchema(child, root=False, kind=kind,
                                         base=base))
    return references


def _verifySchemer(schema, *, expected=None):
    """Verify that a schema's content matches its claimed SAID.

    The schema is rebuilt so its SAID is calculated again. When ``expected``
    is supplied, the calculated SAID must also match that cache key or external
    reference.

    Parameters:
        schema (Schemer | Mapping): Embedded or cached schema to verify.
        expected (str | None): SAID the schema is expected to have.

    Returns:
        Schemer: A rebuilt schema whose content and SAID agree.

    Raises:
        FailedSchemaValidationError: If the schema has an invalid ``$id`` or
            its content does not match the declared or expected SAID.
    """
    # Rebuild an existing Schemer from its bytes
    if isinstance(schema, Schemer):
        schemer = Schemer(raw=schema.raw, verify=False)
        declared = schemer.said

    # Require a bare SAID for a schema mapping
    elif isinstance(schema, Mapping):
        declared = schema.get("$id")
        try:
            saider = Saider(qb64=declared) if isinstance(declared, str) else None
        except Exception:
            saider = None
        if saider is None or saider.qb64 != declared:
            raise FailedSchemaValidationError(
                "schema has an invalid or non-SAID $id")
        # Rebuild a copy to calculate its SAID
        try:
            schemer = Schemer(sed=deepcopy(schema), verify=False)
        except (TypeError, ValidationError, ValueError) as ex:
            raise FailedSchemaValidationError("schema has an invalid SAID") from ex

        # Compare the calculated and declared SAIDs
        if schemer.said != declared:
            raise FailedSchemaValidationError(
                f"schema {declared} content does not match its SAID")
    else:
        raise FailedSchemaValidationError("schema content is not an object")

    # Match the requested cache SAID when provided
    if expected is not None and schemer.said != expected:
        raise FailedSchemaValidationError(
            f"schema {schemer.said} does not match expected SAID {expected}")
    return schemer


def _checkProfile(schemer):
    """Check that a verified schema follows the supported ACDC rules.

    This checks the top-level ``$id``, optional ``$schema``, version, Draft
    2020-12 structure, nested schemas, and references.

    Parameters:
        schemer (Schemer): Schema whose SAID has already been verified.

    Returns:
        list: Valid ``$ref`` values found in the schema.

    Raises:
        FailedSchemaValidationError: If the schema does not follow the
            supported ACDC or Draft 2020-12 rules.
    """
    # Require the calculated bare SAID as the root $id
    schema = schemer.sed
    declared = schema.get("$id")
    try:
        saider = Saider(qb64=declared) if isinstance(declared, str) else None
    except Exception:
        saider = None
    if saider is None or saider.qb64 != declared or declared != schemer.said:
        raise FailedSchemaValidationError(
            f"schema {schemer.said} must use its bare SAID as $id")

    # Check the optional schema dialect
    dialect = schema.get("$schema")
    if dialect is not None and dialect != SchemaDialect:
        raise FailedSchemaValidationError(
            f"schema {schemer.said} must use $schema {SchemaDialect}")

    # Check the schema version
    _checkVersion(schema, schemer.said)

    # Check the Draft 2020-12 schema structure
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as ex:
        raise FailedSchemaValidationError(
            f"schema {schemer.said} is not valid JSON Schema 2020-12") from ex

    # Check subschemas and collect references
    return _inspectSchema(schema, kind=schemer.kind)


def _registry(schemer, db):
    """Build the local schema collection used during validation.

    The collection contains the root schema, bundled schemas, and referenced
    schemas already stored in ``db.schema``. Every schema is verified before it
    is added. This function never downloads a schema.

    Parameters:
        schemer (Schemer): Verified root schema.
        db (Baser): Local database containing cached schemas.

    Returns:
        referencing.Registry: Registry containing verified local schemas.

    Raises:
        MissingSchemaError: If a referenced schema is not in the local cache.
        FailedSchemaValidationError: If a referenced schema is invalid.
    """
    # Start an empty local registry
    registry = referencing.Registry()
    resources = {}
    references = []

    def add(current, aliases=()):
        nonlocal registry
        said = current.said

        # Reuse a schema already added to this registry
        if said in resources:
            resource = resources[said]
            for alias in aliases:
                registry = registry.with_resource(alias, resource)
            return

        # Check and register this schema
        currentReferences = _checkProfile(current)
        references.extend(currentReferences)
        resource = DRAFT202012.create_resource(current.sed)
        resources[said] = resource
        registry = registry.with_resource(said, resource)
        for alias in aliases:
            registry = registry.with_resource(alias, resource)
        # Add bundled schemas to the registry
        registry = registry.crawl()

        # Load each external schema reference
        for _, reference in currentReferences:
            dependency = _referenceSaid(reference)
            if dependency is None:
                continue

            # Use the reference without its fragment as an alias
            uri = reference.partition("#")[0]
            if dependency in resources:
                registry = registry.with_resource(uri, resources[dependency])
                continue

            # Reuse a bundled schema when available
            bundled = registry.get(uri)
            if bundled is not None:
                resources[dependency] = bundled
                registry = registry.with_resource(dependency, bundled)
                continue

            # Load the schema from the local cache
            cached = db.schema.get(dependency)
            if cached is None:
                raise MissingSchemaError(dependency)
            # Verify and add the cached schema
            add(_verifySchemer(cached, expected=dependency), aliases=(uri,))

    # Add the root schema and its dependencies
    add(schemer)

    # Confirm every reference resolves to a schema
    for base, reference in references:
        try:
            resolved = registry.resolver(base_uri=base).lookup(reference)
        except (referencing.exceptions.Unresolvable, LookupError) as ex:
            raise FailedSchemaValidationError(
                f"schema reference {reference} cannot be resolved") from ex
        if not isinstance(resolved.contents, (Mapping, bool)):
            raise FailedSchemaValidationError(
                f"schema reference {reference} does not point to a schema")

    return registry


def validateSchema(acdc, db, schema=None):
    """Validate an ACDC against a verified local schema.

    The function normally uses the schema in the ACDC's ``s`` field. A caller
    may provide ``schema`` to apply another schema, such as an edge schema. All
    schema content and references are checked against their SAIDs, and Draft
    2020-12 validation uses only locally available schemas.

    Parameters:
        acdc (SerderACDC): ACDC to validate.
        db (Baser): Local database containing cached schemas.
        schema (Mapping | str | None): Optional schema content or schema SAID
            to use instead of the ACDC's own schema.

    Returns:
        bool: ``True`` when the ACDC satisfies the selected schema.

    Raises:
        MissingSchemaError: If a required schema is not in the local cache.
        FailedSchemaValidationError: If the schema is invalid or the ACDC does
            not satisfy it.
    """
    # Select the schema to use
    source = acdc.schema if schema is None else schema
    try:
        # Verify an embedded schema
        if isinstance(source, Mapping):
            schemer = _verifySchemer(source)

        # Load a schema by its SAID
        elif isinstance(source, str):
            try:
                saider = Saider(qb64=source)
            except Exception:
                saider = None
            if saider is None or saider.qb64 != source:
                raise FailedSchemaValidationError(
                    f"credential {acdc.said} has invalid schema SAID {source}")

            # Get the schema from the local cache
            cached = db.schema.get(source)
            if cached is None:
                raise MissingSchemaError(source)

            # Verify the cached schema
            schemer = _verifySchemer(cached, expected=source)
        else:
            raise FailedSchemaValidationError(
                f"credential {acdc.said} has an invalid schema field")

        # Build the local schema registry
        registry = _registry(schemer, db)

        # Create the Draft 2020-12 validator
        validator = jsonschema.Draft202012Validator(schema=schemer.sed,
                                                    registry=registry)

        # Validate the ACDC
        error = next(validator.iter_errors(acdc.sad), None)
        if error is not None:
            raise FailedSchemaValidationError(
                f"credential {acdc.said} is not valid against schema {schemer.said}: {error.message}")
    except MissingSchemaError:
        raise
    except FailedSchemaValidationError:
        raise
    except (jsonschema.SchemaError, jsonschema.ValidationError,
            referencing.exceptions.Unresolvable, RecursionError,
            AttributeError, TypeError, ValidationError, ValueError) as ex:
        raise FailedSchemaValidationError(
            f"credential {acdc.said} failed schema validation: {ex}") from ex

    return True
