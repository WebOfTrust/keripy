# -*- encoding: utf-8 -*-
"""Tests for protocol-independent ACDC Edge Section evaluation."""

from copy import deepcopy

from keri import Kinds, Vrsn_2_0
from keri.acdc import (EdgeEvaluator, SchemaEvaluator, Verdicts, acdcmap,
                       valid)
from keri.app.habbing import openHby
from keri.core import Compactor, Schemer, SealEvent


def test_leaf_edge_accepts_inline_schema_pin():
    """A leaf edge may pin its far node's schema with an inline schema document."""
    with openHby(name="inline-schema-pin", base="test",
                 version=Vrsn_2_0) as hby:
        # Create near and far nodes
        issuer = hby.makeHab(name="issuer")
        child = acdcmap(israid=issuer.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=issuer.pre)
        origin = acdcmap(israid=issuer.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83BG36"),
                         iseaid=issuer.pre)

        # Use the far node's embedded schema as the Edge pin
        schema = dict(child.sad["s"])
        assert isinstance(schema.get("$id"), str)

        # Keep node authentication outside this schema-pin test
        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for edge test")

        evaluator = EdgeEvaluator(
            schemaEvaluator=SchemaEvaluator(hby.db),
            verifyNode=verifyNode,
            isDelegated=hby.kvy.isDelegated,
        )

        # Building a wire ACDC with this pin fails in the compactor, so the
        # leaf is evaluated directly
        leaf = dict(d="", n=child.said, s=schema)
        verdict = evaluator._evaluateLeafEdge(
            leaf,
            nodes={child.said: {"serder": child}},
            nserder=origin,
            memo={child.said: valid("far node vetted elsewhere")},
            inheritedPins=())
        assert verdict is not None
        assert verdict.verdict == Verdicts.valid


def test_issuer_identity_operators():
    """I1I and DI1I compose, suppress defaults, and preserve retryability."""
    with openHby(name="issuer-identity-edges", base="test",
                 version=Vrsn_2_0) as hby:
        root = hby.makeHab(name="root", kind=Kinds.cesr)
        unrelated = hby.makeHab(name="unrelated", kind=Kinds.cesr)
        issuee = hby.makeHab(name="issuee", kind=Kinds.cesr)
        otherIssuee = hby.makeHab(name="other-issuee", kind=Kinds.cesr)

        delegate = hby.makeHab(name="delegate", delpre=root.pre,
                               kind=Kinds.cesr)

        # Keep node authentication outside these Edge tests
        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for edge test")

        schemaEvaluator = SchemaEvaluator(hby.db)
        evaluator = EdgeEvaluator(schemaEvaluator=schemaEvaluator,
                                  verifyNode=verifyNode,
                                  isDelegated=hby.kvy.isDelegated)

        # Build one labeled leaf Edge.
        def makeEdge(label, far, operator, schema=None):
            node = dict(d="", n=far.said, o=operator)
            if schema is not None:
                node["s"] = schema
            return dict(d="", **{label: node})

        # Build and evaluate a two-node graph.
        def evaluate(nearIssuer, far, operator, *, nearIssuee=None,
                     schema=None):
            near = acdcmap(
                israid=nearIssuer,
                attribute=dict(d="", role="near"),
                edge=makeEdge("source", far, operator, schema=schema),
                iseaid=nearIssuee,
            )
            nodes = {
                near.said: {"serder": near},
                far.said: {"serder": far},
            }
            return evaluator.evaluate(near.said, nodes=nodes)

        # Build a schema for a chosen Edge Section shape.
        def edgeSchema(properties, required):
            return Schemer(sed={
                "$id": "",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "version": "1.0.0",
                "type": "object",
                "required": ["v", "t", "d", "i", "s", "a", "e"],
                "properties": {
                    "v": {"type": "string"},
                    "t": {"type": "string"},
                    "d": {"type": "string"},
                    "i": {"type": "string"},
                    "s": {},
                    "a": {"type": "object"},
                    "e": {
                        "type": "object",
                        "required": ["d", *required],
                        "properties": {
                            "d": {"type": "string"},
                            **properties,
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            })

        compactBlock = {
            "oneOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "required": ["d", "n"],
                    "properties": {
                        "d": {"type": "string"},
                        "n": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            ],
        }

        rootFar = acdcmap(israid=root.pre,
                          attribute=dict(d="", role="far"))
        unrelatedFar = acdcmap(israid=unrelated.pre,
                               attribute=dict(d="", role="far"))

        # An empty Edge Section carries no requirements
        emptySection = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="empty-edge-section"),
            edge={},
        )
        verdict = evaluator.evaluate(
            emptySection.said,
            nodes={emptySection.said: {"serder": emptySection}},
        )
        assert verdict.verdict == Verdicts.valid

        # A compact section is valid but its hidden logic cannot be evaluated
        hiddenSection = Compactor(
            mad=dict(d="", source=dict(d="", n=rootFar.said, o="I1I")),
            makify=True,
        )
        hiddenSection.compact()

        compactSection = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="compact-edge-section"),
            edge=hiddenSection.said,
        )
        compactSectionNodes = {
            compactSection.said: {"serder": compactSection},
        }

        assert evaluator.walk(
            compactSection.said, nodes=compactSectionNodes, closed=True,
        ) == [compactSection.said]
        
        verdict = evaluator.evaluate(
            compactSection.said, nodes=compactSectionNodes,
        )
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is False

        # Reject malformed top-level Edge Section representations.
        for malformedEdgeSection in ("", "garbage", []):
            malformed = acdcmap(
                israid=root.pre,
                attribute=dict(d="", role="malformed-edge-section"),
                edge=malformedEdgeSection,
            )
            assert evaluator.evaluate(
                malformed.said,
                nodes={malformed.said: {"serder": malformed}},
            ) is None

        # A schema cannot redefine the Edge Section as an array.
        arraySchema = deepcopy(edgeSchema({}, []).sed)
        arraySchema["$id"] = ""
        arraySchema["properties"]["e"] = {
            "type": "array",
            "minItems": 1,
            "items": {"type": "object"},
        }
        arraySchema = Schemer(sed=arraySchema)
        arrayEdgeSection = acdcmap(
            israid=root.pre,
            schema=arraySchema.sed,
            attribute=dict(d="", role="array-edge-section"),
            edge=[makeEdge("source", rootFar, "I1I")],
        )
        assert schemaEvaluator.evaluate(arrayEdgeSection).verdict == Verdicts.valid
        assert evaluator.evaluate(
            arrayEdgeSection.said,
            nodes={
                arrayEdgeSection.said: {"serder": arrayEdgeSection},
                rootFar.said: {"serder": rootFar},
            },
        ) is None

        # The top-level Edge Section must be a group, not a leaf Edge.
        topLevelEdge = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="top-level-edge"),
            edge=dict(d="", n=rootFar.said, o="I1I"),
        )
        assert evaluator.evaluate(
            topLevelEdge.said,
            nodes={
                topLevelEdge.said: {"serder": topLevelEdge},
                rootFar.said: {"serder": rootFar},
            },
        ) is None

        # Reject false SAIDs on either the section or a nested Edge.
        falseCommitments = (
            dict(d=unrelatedFar.said,
                 source=dict(d="", n=rootFar.said, o="I1I")),
            dict(d="",
                 source=dict(d=unrelatedFar.said, n=rootFar.said, o="I1I")),
        )
        for edge in falseCommitments:
            falseCommitment = acdcmap(
                israid=root.pre,
                attribute=dict(d="", role="false-edge-commitment"),
                edge=edge,
            )
            assert evaluator.evaluate(
                falseCommitment.said,
                nodes={
                    falseCommitment.said: {"serder": falseCommitment},
                    rootFar.said: {"serder": rootFar},
                },
            ) is None

        # A top-level group cannot carry a weight because it has no parent.
        weightedSection = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="weighted-edge-section"),
            edge=dict(
                d="",
                w=1,
                source=dict(d="", n=rootFar.said, o="I1I"),
            ),
        )
        assert evaluator.evaluate(
            weightedSection.said,
            nodes={
                weightedSection.said: {"serder": weightedSection},
                rootFar.said: {"serder": rootFar},
            },
        ) is None

        # A schema-declared simple Edge points directly to a far node.
        simpleCompactEdge = acdcmap(
            israid=root.pre,
            schema=edgeSchema({"source": {"type": "string"}},
                              ["source"]).sed,
            attribute=dict(d="", role="simple-compact-edge"),
            edge=dict(d="", source=rootFar.said),
        )
        simpleCompactNodes = {
            simpleCompactEdge.said: {"serder": simpleCompactEdge},
            rootFar.said: {"serder": rootFar},
        }
        assert evaluator.walk(
            simpleCompactEdge.said, nodes=simpleCompactNodes, closed=True,
        ) == [simpleCompactEdge.said, rootFar.said]
        assert schemaEvaluator.edgeKind(
            simpleCompactEdge, ("source",)) == "simple"
        verdict = evaluator.evaluate(
            simpleCompactEdge.said, nodes=simpleCompactNodes,
        )
        assert verdict.verdict == Verdicts.valid
        assert evaluator.walk(
            simpleCompactEdge.said,
            nodes={simpleCompactEdge.said: {"serder": simpleCompactEdge}},
            closed=True,
        ) is None
        verdict = evaluator.evaluate(
            simpleCompactEdge.said,
            nodes={simpleCompactEdge.said: {"serder": simpleCompactEdge}},
        )
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True

        # Refuse a string Edge when its schema does not define its meaning.
        ambiguousSchema = deepcopy(
            edgeSchema({"source": {"type": "string"}}, ["source"]).sed)
        ambiguousSchema["$id"] = ""
        edgeDefinition = ambiguousSchema["properties"]["e"]
        edgeDefinition["properties"].pop("source")
        edgeDefinition["additionalProperties"] = True
        edgeDefinition["anyOf"] = [
            {"properties": {"source": {"type": "string"}}},
            {"type": "object"},
        ]
        ambiguousSchema = Schemer(sed=ambiguousSchema).sed
        ambiguousCompactEdge = acdcmap(
            israid=root.pre,
            schema=ambiguousSchema,
            attribute=dict(d="", role="ambiguous-compact-edge"),
            edge=dict(d="", source=rootFar.said),
        )
        assert schemaEvaluator.edgeKind(
            ambiguousCompactEdge, ("source",)) is None
        verdict = evaluator.evaluate(
            ambiguousCompactEdge.said,
            nodes={ambiguousCompactEdge.said: {"serder": ambiguousCompactEdge}},
        )
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is False

        # A compact Edge remains unknown when AND requires it.
        opaqueCompactEdge = acdcmap(
            israid=root.pre,
            schema=edgeSchema({
                "source": {
                    "type": "object",
                    "required": ["d", "n", "o"],
                    "properties": {
                        "d": {"type": "string"},
                        "n": {"type": "string"},
                        "o": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "compact": compactBlock,
            }, ["source", "compact"]).sed,
            attribute=dict(d="", role="opaque-compact-edge"),
            edge=dict(
                d="",
                source=dict(d="", n=rootFar.said, o="I1I"),
                compact=rootFar.said,
            ),
        )
        assert schemaEvaluator.edgeKind(
            opaqueCompactEdge, ("compact",)) == "compact"
        verdict = evaluator.evaluate(
            opaqueCompactEdge.said,
            nodes={
                opaqueCompactEdge.said: {"serder": opaqueCompactEdge},
                rootFar.said: {"serder": rootFar},
            },
        )
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is False

        # OR succeeds when one disclosed Edge is valid.
        validCompactEdge = acdcmap(
            israid=root.pre,
            schema=edgeSchema({
                "o": {"type": "string"},
                "source": {
                    "type": "object",
                    "required": ["d", "n", "o"],
                    "properties": {
                        "d": {"type": "string"},
                        "n": {"type": "string"},
                        "o": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "compact": compactBlock,
            }, ["o", "source", "compact"]).sed,
            attribute=dict(d="", role="valid-compact-edge"),
            edge=dict(
                d="",
                o="OR",
                source=dict(d="", n=rootFar.said, o="I1I"),
                compact=rootFar.said,
            ),
        )
        verdict = evaluator.evaluate(
            validCompactEdge.said,
            nodes={
                validCompactEdge.said: {"serder": validCompactEdge},
                rootFar.said: {"serder": rootFar},
            },
        )
        assert verdict.verdict == Verdicts.valid
        assert schemaEvaluator.edgeKind(
            validCompactEdge, ("compact",)) == "compact"

        # A valid sibling satisfies OR when a simple far-node Edge is undisclosed.
        simpleOrEdge = acdcmap(
            israid=root.pre,
            schema=edgeSchema({
                "o": {"type": "string"},
                "source": deepcopy(compactBlock["oneOf"][1]),
                "missing": {"type": "string"},
            }, ["o", "source", "missing"]).sed,
            attribute=dict(d="", role="simple-or-edge"),
            edge=dict(
                d="",
                o="OR",
                source=dict(d="", n=rootFar.said),
                missing=unrelatedFar.said,
            ),
        )
        verdict = evaluator.evaluate(
            simpleOrEdge.said,
            nodes={
                simpleOrEdge.said: {"serder": simpleOrEdge},
                rootFar.said: {"serder": rootFar},
            },
        )
        assert verdict.verdict == Verdicts.valid

        # A compact Edge value must be a valid SAID.
        invalidCompactEdge = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="invalid-compact-edge"),
            edge=dict(
                d="",
                o="OR",
                source=dict(d="", n=rootFar.said, o="I1I"),
                compact="garbage",
            ),
        )
        assert evaluator.evaluate(
            invalidCompactEdge.said,
            nodes={
                invalidCompactEdge.said: {"serder": invalidCompactEdge},
                rootFar.said: {"serder": rootFar},
            },
        ) is None

        # I1I requires equal near and far issuers.
        verdict = evaluate(root.pre, rootFar, "I1I")
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(unrelated.pre, rootFar, "I1I")
        assert verdict.verdict == Verdicts.invalid

        # DI1I accepts equality but waits for missing delegation evidence.
        verdict = evaluate(root.pre, rootFar, "DI1I")
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(delegate.pre, rootFar, "DI1I")
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True

        # Anchor the delegate, then accept only its actual ancestry.
        root.interact(data=[SealEvent(i=delegate.pre,
                                      s=delegate.kever.serder.snh,
                                      d=delegate.kever.serder.said)._asdict()],
                      kind=Kinds.cesr)
        verdict = evaluate(delegate.pre, rootFar, "DI1I")
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(delegate.pre, unrelatedFar, "DI1I")
        assert verdict.verdict == Verdicts.invalid

        # The latest issuer-identity operator wins.
        verdict = evaluate(delegate.pre, rootFar, ["DI1I", "I1I"])
        assert verdict.verdict == Verdicts.invalid
        verdict = evaluate(delegate.pre, rootFar, ["I1I", "DI1I"])
        assert verdict.verdict == Verdicts.valid

        # Explicit I1I suppresses the targeted far node's I2I default.
        targetedFar = acdcmap(israid=root.pre,
                              attribute=dict(d="", role="targeted-far"),
                              iseaid=issuee.pre)
        verdict = evaluate(root.pre, targetedFar, "I1I")
        assert verdict.verdict == Verdicts.valid

        # Independent operator groups compose with I1I.
        verdict = evaluate(root.pre, targetedFar, ["NI2I", "I1I"])
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(root.pre, targetedFar, ["E1E", "I1I"],
                           nearIssuee=issuee.pre)
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(root.pre, targetedFar, ["E1E", "I1I"],
                           nearIssuee=otherIssuee.pre)
        assert verdict.verdict == Verdicts.invalid

        # Unrecognized operators never weaken a proven failure.
        verdict = evaluate(unrelated.pre, rootFar, ["BOGUS", "I1I"])
        assert verdict.verdict == Verdicts.invalid
        verdict = evaluate(root.pre, targetedFar, "BOGUS")
        assert verdict.verdict == Verdicts.invalid

        # A matching far-node schema pin is valid.
        verdict = evaluate(root.pre, rootFar, "I1I",
                           schema=rootFar.schema["$id"])
        assert verdict.verdict == Verdicts.valid

        # A proven E1E failure overrides retryable DI1I evidence.
        missingAnchor = hby.makeHab(name="missing-anchor", delpre=root.pre,
                                    kind=Kinds.cesr)
        verdict = evaluate(missingAnchor.pre, targetedFar,
                           ["E1E", "DI1I"], nearIssuee=otherIssuee.pre)
        assert verdict.verdict == Verdicts.invalid

        # Every operator in a list must be a string.
        malformed = evaluate(root.pre, rootFar, ["I1I", 1])
        assert malformed is None

        # Reject malformed, missing, and unreachable graph nodes.
        assert evaluator.evaluate(rootFar.said, nodes={}) is None
        assert evaluator.evaluate(
            [], nodes={rootFar.said: {"serder": rootFar}}) is None
        assert evaluator.evaluate(rootFar.said,
                                  nodes={rootFar.said: {}}) is None
        assert evaluator.evaluate(
            rootFar.said,
            nodes={
                rootFar.said: {"serder": rootFar},
                unrelatedFar.said: {"serder": unrelatedFar},
            }) is None

        # A required missing far node is retryable evidence, not malformed input.
        dangling = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="near"),
            edge=makeEdge("source", rootFar, "I1I"),
        )
        verdict = evaluator.evaluate(
            dangling.said, nodes={dangling.said: {"serder": dangling}})
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True

        # An Edge node reference must be a SAID string.
        malformedReference = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="near"),
            edge=makeEdge("source", rootFar, "I1I"),
        )
        malformedReference.sad["e"]["source"]["n"] = []
        assert evaluator.evaluate(
            malformedReference.said,
            nodes={
                malformedReference.said: {"serder": malformedReference},
                rootFar.said: {"serder": rootFar},
            }) is None

        # Reject a malformed inline schema pin.
        malformedSchema = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="near"),
            edge=makeEdge("source", rootFar, "I1I"),
        )
        malformedSchema.sad["e"]["source"]["s"] = {
            "$id": rootFar.schema["$id"],
            "type": object(),
        }
        assert evaluator.evaluate(
            malformedSchema.said,
            nodes={
                malformedSchema.said: {"serder": malformedSchema},
                rootFar.said: {"serder": rootFar},
            }) is None

        # Schema collection validation rejects malformed caller input.
        verdict = schemaEvaluator.validateSchemas(nodes=None, order=[])
        assert verdict.verdict == Verdicts.invalid


def test_node_schema_verdicts_follow_edge_group_reduction():
    """Treat a far node's own schema as part of its Edge-group member verdict."""
    with openHby(name="edge-node-schema-reduction", base="test",
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer", kind=Kinds.cesr)

        # Keep node authentication outside this schema-reduction test.
        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for schema reduction")

        schemaEvaluator = SchemaEvaluator(hby.db)
        evaluator = EdgeEvaluator(schemaEvaluator=schemaEvaluator,
                                  verifyNode=verifyNode,
                                  isDelegated=hby.kvy.isDelegated)

        # This far node satisfies its own schema.
        validFar = acdcmap(
            israid=issuer.pre,
            attribute=dict(d="", role="valid"),
        )

        # This far node is missing a field required by its schema.
        invalidSchema = deepcopy(validFar.schema)
        invalidSchema["$id"] = ""
        invalidSchema["title"] = "Schema requiring an absent top-level field"
        invalidSchema["required"] = [*invalidSchema["required"], "missing"]
        invalidSchemer = Schemer(sed=invalidSchema)
        invalidFar = acdcmap(
            israid=issuer.pre,
            schema=invalidSchemer.sed,
            attribute=dict(d="", role="schema-invalid"),
        )

        # This far node references a schema that is not cached.
        missingSchema = deepcopy(validFar.schema)
        missingSchema["$id"] = ""
        missingSchema["title"] = "Uncached far-node schema"
        missingSchemer = Schemer(sed=missingSchema)
        missingFar = acdcmap(
            israid=issuer.pre,
            schema=missingSchemer.said,
            attribute=dict(d="", role="schema-missing"),
        )
        undisclosedFar = acdcmap(
            israid=issuer.pre,
            attribute=dict(d="", role="undisclosed"),
        )

        # Place both far-node verdicts inside the same logical group.
        def evaluateGroup(operator, optionalFar, discloseOptional=True):
            origin = acdcmap(
                israid=issuer.pre,
                attribute=dict(d="", role="origin"),
                edge=dict(
                    d="",
                    alternatives=dict(
                        d="",
                        o=operator,
                        valid=dict(d="", n=validFar.said, o="I1I"),
                        optional=dict(d="", n=optionalFar.said, o="I1I"),
                    ),
                ),
            )
            nodes = {
                origin.said: {"serder": origin},
                validFar.said: {"serder": validFar},
            }
            if discloseOptional:
                nodes[optionalFar.said] = {"serder": optionalFar}
            return evaluator.evaluate(origin.said, nodes=nodes)

        # One valid branch satisfies OR despite an invalid branch.
        verdict = evaluateGroup("OR", invalidFar)
        assert verdict.verdict == Verdicts.valid

        # AND propagates the invalid branch.
        verdict = evaluateGroup("AND", invalidFar)
        assert verdict.verdict == Verdicts.invalid

        # One valid branch satisfies OR without waiting for missing evidence.
        verdict = evaluateGroup("OR", missingFar)
        assert verdict.verdict == Verdicts.valid

        # AND remains retryable while a required schema is missing.
        verdict = evaluateGroup("AND", missingFar)
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True

        # Missing far nodes participate in the same OR/AND reduction.
        verdict = evaluateGroup("OR", undisclosedFar, discloseOptional=False)
        assert verdict.verdict == Verdicts.valid
        verdict = evaluateGroup("AND", undisclosedFar, discloseOptional=False)
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True
