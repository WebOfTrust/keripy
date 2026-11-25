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


def _resolveSchema(acdc, db, schema=None):
    """Resolve and verify an embedded or locally cached ACDC schema.

    Parameters:
        acdc (SerderACDC): ACDC whose declared schema is used when ``schema``
            is not supplied.
        db (Baser): Database containing schemas indexed by SAID.
        schema (Mapping | str | None): Optional schema body or schema SAID that
            overrides the schema declared by the ACDC.

    Returns:
        tuple: The verified ``Schemer`` and a local registry containing its
            verified static dependencies.

    Raises:
        MissingSchemaError: If a schema or referenced dependency is not cached.
        FailedSchemaValidationError: If a schema field, SAID, schema body, or
            dependency is invalid.
    """
    source = acdc.schema if schema is None else schema
    if isinstance(source, Mapping):
        schemer = _verifySchemer(source)
    elif isinstance(source, str):
        try:
            saider = Saider(qb64=source)
        except Exception:
            saider = None
        if saider is None or saider.qb64 != source:
            raise FailedSchemaValidationError(
                f"credential {acdc.said} has invalid schema SAID {source}")

        cached = db.schema.get(source)
        if cached is None:
            raise MissingSchemaError(source)
        schemer = _verifySchemer(cached, expected=source)
    else:
        raise FailedSchemaValidationError(
            f"credential {acdc.said} has an invalid schema field")

    return schemer, _registry(schemer, db)


def _propertySchemas(schema, label, resolver, instance, seen):
    """Collect alternative sets of schemas that constrain a property.

    Follow locally resolved ``$ref`` values and preserve JSON Schema composition
    semantics. Direct properties, references, and ``allOf`` branches contribute
    simultaneous constraints. Each viable ``anyOf`` or ``oneOf`` branch produces
    a separate alternative so an unconstrained branch cannot be silently ignored.
    Dynamic references are excluded by schema profile validation.

    Parameters:
        schema (Mapping | bool): Schema or boolean subschema to inspect.
        label (str): Property name whose subschemas are requested.
        resolver (referencing.Resolver): Resolver for the current schema scope.
        instance: Value of the object containing ``label``. It selects viable
            ``anyOf`` and ``oneOf`` branches.
        seen (set): Recursion markers accumulated during this lookup.

    Returns:
        list[list[tuple]]: Alternative constraint sets. Every inner list holds
            ``(subschema, resolver)`` pairs that apply together. An empty inner
            list means that viable alternative does not constrain ``label``.

    Raises:
        FailedSchemaValidationError: If a static reference cannot be resolved.
    """
    # True is unconstrained; false has no valid match.
    if isinstance(schema, bool):
        return [[]] if schema else []

    # Reject values that are not schemas.
    if not isinstance(schema, Mapping):
        return []

    # Stop cyclic references without inferring a meaning.
    marker = (id(schema), label, resolver._base_uri)
    if marker in seen:
        return [[]]
    seen = seen | {marker}

    # Use a nested schema's reference scope.
    if "$id" in schema:
        resolver = resolver.in_subresource(DRAFT202012.create_resource(schema))

    # Outer entries are alternatives; constraints inside each entry all apply.
    alternatives = [[]]

    # A $ref and its sibling constraints both apply.
    reference = schema.get("$ref")
    if reference is not None:
        try:
            resolved = resolver.lookup(reference)
        except (referencing.exceptions.Unresolvable, LookupError) as ex:
            raise FailedSchemaValidationError(
                f"schema reference {reference} cannot be resolved") from ex
        referenced = _propertySchemas(resolved.contents, label,
                                      resolved.resolver, instance, seen)

        # Combine referenced constraints with the current ones.
        combined = []
        for existing in alternatives:
            for constraints in referenced:
                combined.append(existing + constraints)
        alternatives = combined

    # A direct property applies to every alternative.
    properties = schema.get("properties")
    if isinstance(properties, Mapping) and label in properties:
        for constraints in alternatives:
            constraints.append((properties[label], resolver))

    # Every allOf branch applies.
    branches = schema.get("allOf", ())
    if isinstance(branches, list):
        for branch in branches:
            branchAlternatives = _propertySchemas(
                branch, label, resolver, instance, seen)

            # Combine this branch with the constraints already collected.
            combined = []
            for existing in alternatives:
                for constraints in branchAlternatives:
                    combined.append(existing + constraints)
            alternatives = combined

    # Keep anyOf and oneOf branches as separate alternatives.
    for keyword in ("anyOf", "oneOf"):
        branches = schema.get(keyword)
        if not isinstance(branches, list):
            continue

        viable = []
        for branch in branches:
            # Keep only branches matching the actual value.
            validator = jsonschema.Draft202012Validator(
                branch, _resolver=resolver)
            if not validator.is_valid(instance):
                continue

            # An empty result records an unconstrained branch.
            viable.extend(_propertySchemas(
                branch, label, resolver, instance, seen))

        # No branch accepts this value.
        if not viable:
            return []

        # Add shared constraints to each alternative.
        combined = []
        for existing in alternatives:
            for constraints in viable:
                combined.append(existing + constraints)
        alternatives = combined

    return alternatives


def _edgeForms(schema, resolver, seen):
    """Find the compact and expanded forms declared by an Edge schema.

    Parameters:
        schema (Mapping | bool): Edge-member schema to inspect.
        resolver (referencing.Resolver): Resolver for the current schema scope.
        seen (set): Recursion markers accumulated during this lookup.

    Returns:
        set[str]: Forms found in the schema. ``string`` denotes a SAID value,
            ``block`` an expanded Edge block, ``simple`` an expanded simple
            reference, and ``unknown`` an object form that is not distinctive.

    Raises:
        FailedSchemaValidationError: If a static reference cannot be resolved.
    """
    # These schemas do not identify an Edge form.
    if isinstance(schema, bool) or not isinstance(schema, Mapping):
        return {"unknown"}

    # Stop cyclic references.
    marker = (id(schema), resolver._base_uri)
    if marker in seen:
        return set()
    seen.add(marker)

    # Use a nested schema's reference scope.
    if "$id" in schema:
        resolver = resolver.in_subresource(DRAFT202012.create_resource(schema))

    # Collect the forms declared by this schema.
    forms = set()

    # Include forms from a referenced schema.
    reference = schema.get("$ref")
    if reference is not None:
        try:
            resolved = resolver.lookup(reference)
        except (referencing.exceptions.Unresolvable, LookupError) as ex:
            raise FailedSchemaValidationError(
                f"schema reference {reference} cannot be resolved") from ex
        forms.update(_edgeForms(resolved.contents, resolved.resolver, seen))

    # Include forms from composed schemas.
    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword, ())
        if isinstance(branches, list):
            for branch in branches:
                forms.update(_edgeForms(branch, resolver, seen))

    # Normalize one type or a list of types.
    types = schema.get("type")
    types = set(types) if isinstance(types, list) else {types}

    # A compact representation is a string.
    if "string" in types:
        forms.add("string")

    # Object keywords may imply an object without an explicit type.
    objectish = ("object" in types or "properties" in schema
                 or "required" in schema)
    if objectish:
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Field order does not affect the shape.
        propertyLabels = (set(properties)
                          if isinstance(properties, Mapping) else set())
        requiredLabels = set(required) if isinstance(required, list) else set()

        # Required `d` identifies a SAIDed Edge block.
        if "d" in requiredLabels:
            forms.add("block")

        # A strict `{n}` object identifies a simple Edge.
        elif (requiredLabels == {"n"} and propertyLabels == {"n"}
              and schema.get("additionalProperties") is False):
            forms.add("simple")

        # Other object shapes are ambiguous.
        else:
            forms.add("unknown")

    # Do not guess when no form was recognized.
    if not forms:
        forms.add("unknown")
    return forms


def classifyEdge(acdc, db, path):
    """Classify a string-valued Edge from its verified near-node schema.

    ``simple`` means the string is the far-node ACDC SAID. ``compact`` means
    it is the SAID of a hidden Edge block. ``None`` means the schema does not
    make that distinction machine-readable.

    Parameters:
        acdc (SerderACDC): Near-node ACDC whose schema defines the Edge Section.
        db (Baser): Database used to resolve schema SAIDs and dependencies.
        path (tuple | list): Non-reserved Edge labels from the Edge Section to
            the string-valued member being classified.

    Returns:
        str | None: ``simple``, ``compact``, or ``None`` when the schema is
            missing a usable declaration or permits ambiguous forms.

    Raises:
        ValueError: If ``path`` is empty or contains a non-string label.
        MissingSchemaError: If the ACDC schema or a dependency is not cached.
        FailedSchemaValidationError: If the schema or a dependency is invalid.
    """
    # The path must name a member below `e`.
    if (not isinstance(path, (list, tuple)) or not path
            or not all(isinstance(label, str) for label in path)):
        raise ValueError("edge schema path must contain field labels")

    # Load the verified schema and its local dependencies.
    schemer, registry = _resolveSchema(acdc, db)

    # Outer entries are alternatives; pairs inside each entry all apply.
    candidates = [[(schemer.sed, registry.resolver(base_uri=schemer.said))]]

    # Follow the schema and disclosed value together.
    instance = acdc.sad
    for label in ("e", *path):
        # The path must exist in the ACDC.
        if not isinstance(instance, Mapping) or label not in instance:
            return None

        # Find constraints for this property.
        found = []
        for alternative in candidates:
            # Combine constraints that apply together.
            combinations = [[]]
            for candidate, resolver in alternative:
                propertyAlternatives = _propertySchemas(candidate, label, resolver, instance, set())

                # Keep alternative property constraints separate.
                combined = []
                for existing in combinations:
                    for constraints in propertyAlternatives:
                        combined.append(existing + constraints)
                combinations = combined
            found.extend(combinations)

        # No schema path reaches this property.
        if not found:
            return None

        # Move to the next path level.
        candidates = found
        instance = instance[label]

    # Classify each alternative independently.
    kinds = set()
    for alternative in candidates:
        # An unconstrained alternative is ambiguous.
        if not alternative:
            return None

        # Gather forms from constraints that apply together.
        forms = set()
        for candidate, resolver in alternative:
            forms.update(_edgeForms(candidate, resolver, set()))

        # The schema must clearly allow a string form.
        if "string" not in forms or "unknown" in forms:
            return None

        # Check the expanded form paired with the string.
        expanded = forms.intersection(("simple", "block"))

        # A SAIDed block means the string identifies that block.
        if expanded == {"block"}:
            kinds.add("compact")

        # A bare string or strict `{n}` means a far-node SAID.
        elif expanded in (set(), {"simple"}):
            kinds.add("simple")

        # Conflicting forms are ambiguous.
        else:
            return None

    # All alternatives must agree.
    if len(kinds) == 1:
        return kinds.pop()
    return None


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
    try:
        schemer, registry = _resolveSchema(acdc, db, schema=schema)

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
