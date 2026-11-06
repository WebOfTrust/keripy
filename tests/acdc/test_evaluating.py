# -*- encoding: utf-8 -*-
"""Tests for protocol-independent ACDC Edge Section evaluation."""

from copy import deepcopy

from keri import Kinds, Vrsn_2_0
from keri.acdc import (EdgeEvaluator, SchemaEvaluator, Verdicts, acdcmap,
                       valid)
from keri.app.habbing import openHby
from keri.core import Compactor, Schemer, SealEvent


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

        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for edge test")

        schemaEvaluator = SchemaEvaluator(hby.db)
        evaluator = EdgeEvaluator(schemaEvaluator=schemaEvaluator,
                                  verifyNode=verifyNode,
                                  isDelegated=hby.kvy.isDelegated)

        def makeEdge(label, far, operator, schema=None):
            node = dict(d="", n=far.said, o=operator)
            if schema is not None:
                node["s"] = schema
            return dict(d="", **{label: node})

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

        verdict = evaluate(root.pre, rootFar, "I1I")
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(unrelated.pre, rootFar, "I1I")
        assert verdict.verdict == Verdicts.invalid

        verdict = evaluate(root.pre, rootFar, "DI1I")
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(delegate.pre, rootFar, "DI1I")
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True

        root.interact(data=[SealEvent(i=delegate.pre,
                                      s=delegate.kever.serder.snh,
                                      d=delegate.kever.serder.said)._asdict()],
                      kind=Kinds.cesr)
        verdict = evaluate(delegate.pre, rootFar, "DI1I")
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(delegate.pre, unrelatedFar, "DI1I")
        assert verdict.verdict == Verdicts.invalid

        verdict = evaluate(delegate.pre, rootFar, ["DI1I", "I1I"])
        assert verdict.verdict == Verdicts.invalid
        verdict = evaluate(delegate.pre, rootFar, ["I1I", "DI1I"])
        assert verdict.verdict == Verdicts.valid

        targetedFar = acdcmap(israid=root.pre,
                              attribute=dict(d="", role="targeted-far"),
                              iseaid=issuee.pre)
        verdict = evaluate(root.pre, targetedFar, "I1I")
        assert verdict.verdict == Verdicts.valid

        verdict = evaluate(root.pre, targetedFar, ["NI2I", "I1I"])
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(root.pre, targetedFar, ["E1E", "I1I"],
                           nearIssuee=issuee.pre)
        assert verdict.verdict == Verdicts.valid
        verdict = evaluate(root.pre, targetedFar, ["E1E", "I1I"],
                           nearIssuee=otherIssuee.pre)
        assert verdict.verdict == Verdicts.invalid

        verdict = evaluate(unrelated.pre, rootFar, ["BOGUS", "I1I"])
        assert verdict.verdict == Verdicts.invalid
        verdict = evaluate(root.pre, targetedFar, "BOGUS")
        assert verdict.verdict == Verdicts.invalid

        verdict = evaluate(root.pre, rootFar, "I1I",
                           schema=rootFar.schema["$id"])
        assert verdict.verdict == Verdicts.valid

        missingAnchor = hby.makeHab(name="missing-anchor", delpre=root.pre,
                                    kind=Kinds.cesr)
        verdict = evaluate(missingAnchor.pre, targetedFar,
                           ["E1E", "DI1I"], nearIssuee=otherIssuee.pre)
        assert verdict.verdict == Verdicts.invalid

        malformed = evaluate(root.pre, rootFar, ["I1I", 1])
        assert malformed is None

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

        dangling = acdcmap(
            israid=root.pre,
            attribute=dict(d="", role="near"),
            edge=makeEdge("source", rootFar, "I1I"),
        )
        assert evaluator.evaluate(
            dangling.said, nodes={dangling.said: {"serder": dangling}}) is None

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

        verdict = schemaEvaluator.validateSchemas(nodes=None, order=[])
        assert verdict.verdict == Verdicts.invalid


def test_node_schema_verdicts_follow_edge_group_reduction():
    """Treat a far node's own schema as part of its Edge-group member verdict."""
    with openHby(name="edge-node-schema-reduction", base="test",
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer", kind=Kinds.cesr)

        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for schema reduction")

        schemaEvaluator = SchemaEvaluator(hby.db)
        evaluator = EdgeEvaluator(schemaEvaluator=schemaEvaluator,
                                  verifyNode=verifyNode,
                                  isDelegated=hby.kvy.isDelegated)

        validFar = acdcmap(
            israid=issuer.pre,
            attribute=dict(d="", role="valid"),
        )

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

        missingSchema = deepcopy(validFar.schema)
        missingSchema["$id"] = ""
        missingSchema["title"] = "Uncached far-node schema"
        missingSchemer = Schemer(sed=missingSchema)
        missingFar = acdcmap(
            israid=issuer.pre,
            schema=missingSchemer.said,
            attribute=dict(d="", role="schema-missing"),
        )

        def evaluateGroup(operator, optionalFar):
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
                optionalFar.said: {"serder": optionalFar},
            }
            return evaluator.evaluate(origin.said, nodes=nodes)

        verdict = evaluateGroup("OR", invalidFar)
        assert verdict.verdict == Verdicts.valid

        verdict = evaluateGroup("AND", invalidFar)
        assert verdict.verdict == Verdicts.invalid

        verdict = evaluateGroup("OR", missingFar)
        assert verdict.verdict == Verdicts.valid

        verdict = evaluateGroup("AND", missingFar)
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True
