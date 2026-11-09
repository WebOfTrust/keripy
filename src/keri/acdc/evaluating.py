# -*- encoding: utf-8 -*-
"""ACDC Edge Section evaluation independent of a disclosure protocol."""

from collections import deque
from collections.abc import Mapping
from copy import deepcopy

from ..core import Compactor, Saider, Schemer
from ..kering import (FailedSchemaValidationError, MissingChainError,
                      MissingSchemaError, ValidationError)
from . import chaining, scheming


EdgeSectionLabels = ("d", "u", "s", "o", "w")
EdgeGroupLabels = ("d", "u", "s", "o", "w")
EdgeNodeLabels = ("d", "u", "n", "s", "o", "w")
UnaryEdgeOps = ("I2I", "NI2I", "DI2I", "E1E", "I1I", "DI1I", "NOT")
DelegativeEdgeOps = ("I2I", "NI2I", "DI2I")
IssuerIdentityEdgeOps = ("I1I", "DI1I")
DefaultSuppressingEdgeOps = DelegativeEdgeOps + ("E1E",) + IssuerIdentityEdgeOps


def verifyExpandedSection(section, *, kind):
    """Verify every carried SAID in one expanded ACDC section.

    Recompute the section and nested-block commitments with ``Compactor`` and
    compare each ``d`` value with the canonical result. A non-mapping value
    has no expanded commitments to inspect.

    Parameters:
        section (Mapping | Any): Expanded section mapping, or another section form.
        kind (str): Serialization kind used when recomputing the commitments.

    Returns:
        bool: True when every carried commitment matches, False when recomputation
            fails or a claimed commitment is false.
    """
    if not isinstance(section, Mapping):
        return True

    try:
        compactor = Compactor(mad=deepcopy(section), makify=True, kind=kind)
        compactor.compact()
        for path, leaf in compactor.leaves.items():
            carried = compactor.getTail(path, mad=section)
            if (not isinstance(carried, Mapping) or (carried.get("d") and carried["d"] != leaf.said)):
                return False
    except Exception:
        return False

    return True


class SchemaEvaluator:
    """Map ACDC schema validation results into edge-evaluation verdicts."""

    def __init__(self, db):
        """Initialize schema evaluation with the schema cache database.

        Parameters:
            db: Database used to resolve referenced schema SAIDs.
        """
        self.db = db

    def evaluate(self, acdc, *, schema=None, context="ACDC"):
        """Evaluate one ACDC against its declared or supplied schema.

        Parameters:
            acdc: ACDC serder to validate.
            schema (str | Mapping | None): Optional edge-pinned schema. ``None``
                validates the ACDC against its own declared schema.
            context (str): Description used in the returned verdict reason.

        Returns:
            EdgeVerdict: Valid on success, retryable unknown when a referenced
                schema is missing, or invalid for a proven schema mismatch.
        """
        try:
            scheming.validateSchema(acdc=acdc, db=self.db, schema=schema)
        except MissingSchemaError as ex:
            return chaining.unknown(
                f"{context} schema is not in cache", retryable=True, cause=ex)
        except (FailedSchemaValidationError, ValidationError, ValueError) as ex:
            return chaining.invalid(f"{context} does not satisfy its schema: {ex}")

        return chaining.valid(f"{context} satisfies its schema")

    def edgeKind(self, acdc, path):
        """Return the schema-declared meaning of a string-valued Edge.

        Parameters:
            acdc: Near-node ACDC whose schema defines the Edge Section.
            path (tuple | list): Edge labels from the Edge Section to the member.

        Returns:
            str | None: ``simple`` for a far-node SAID, ``compact`` for an
                Edge-block SAID, or ``None`` when the schema is ambiguous.

        Raises:
            MissingSchemaError: When classification needs an unavailable schema.
        """
        try:
            return scheming.classifyEdge(acdc=acdc, db=self.db, path=path)
        except MissingSchemaError:
            raise
        except (FailedSchemaValidationError, RecursionError, TypeError,
                ValidationError, ValueError):
            return None

    def validateSchemas(self, *, nodes, order):
        """Validate every walked ACDC against its own declared schema.

        Parameters:
            nodes (Mapping): ACDC SAID to parsed nest or nest-like object mapping.
            order (list | tuple): Walk order containing every node to validate.

        Returns:
            EdgeVerdict: Valid when all schemas pass, retryable unknown when a
                declared schema is unavailable, or invalid for malformed input or
                a schema mismatch.
        """
        if not isinstance(nodes, Mapping) or not isinstance(order, (list, tuple)):
            return chaining.invalid("disclosed nodes or graph order are malformed")

        for said in order:
            if not isinstance(said, str) or said not in nodes:
                return chaining.invalid(f"graph order contains unknown node {said}")
            nest = nodes.get(said)
            try:
                nserder = nest["serder"] if isinstance(nest, Mapping) else nest.serder
            except (AttributeError, KeyError, TypeError):
                return chaining.invalid(f"node {said} has no ACDC body")

            verdict = self.evaluate(nserder, context=f"node {said}")
            if verdict.verdict != chaining.Verdicts.valid:
                return verdict

        return chaining.valid("all disclosed nodes satisfy their own schemas")


class EdgeEvaluator:
    """Evaluate a closed ACDC graph using caller-provided evidence."""

    def __init__(self, schemaEvaluator, verifyNode, isDelegated, reducers=None):
        """Initialize an evaluator with storage and evidence.

        Parameters:
            schemaEvaluator (SchemaEvaluator): Independent schema-policy layer.
            verifyNode (Callable): Adapter called as ``verifyNode(serder, nest,
                records=records)`` and returning the node-authentication verdict.
            isDelegated (Callable): Adapter called with a possible delegate and
                ancestor AID. It returns True for proven delegation, False for a
                proven mismatch, and None when required evidence is missing.
            reducers (Mapping | None): Optional m-ary Operator reducer mapping.
                Defaults to the reducers supplied by ``acdc.chaining``.
        """
        self.schemaEvaluator = schemaEvaluator
        self.verifyNode = verifyNode
        self.isDelegated = isDelegated
        self.reducers = chaining.MAryReducers if reducers is None else reducers

    def walk(self, origin, *, nodes, closed):
        """Validate and walk a disclosed ACDC graph in breadth-first order.

        The walk verifies Edge Section commitments and shapes and follows
        expanded or schema-declared simple Edge references. A compact Edge
        Section is a valid opaque terminal, so it contributes no references to
        the walk. Every disclosed node must be reachable from ``origin``.

        Parameters:
            origin (str): SAID of the disclosed graph's root ACDC.
            nodes (Mapping): ACDC SAID to parsed nest or nest-like object mapping.
            closed (bool): True requires every expanded far-node reference to be
                disclosed; False permits undisclosed far nodes.

        Returns:
            list[str] | None: Breadth-first node SAIDs, or None when the graph,
                an Edge Section, or a reference is malformed or violates closure.
        """
        if not isinstance(origin, str) or not isinstance(nodes, Mapping):
            return None
        try:
            if Saider(qb64=origin).qb64 != origin:
                return None
        except Exception:
            return None
        if origin not in nodes:
            return None

        seen = set()
        order = []
        queue = deque([origin])
        while queue:
            said = queue.popleft()
            if said in seen:
                continue

            nest = nodes.get(said)
            try:
                nserder = nest["serder"] if isinstance(nest, Mapping) else nest.serder
                if nserder.said != said:
                    return None
                sad = nserder.sad
            except (AttributeError, KeyError, TypeError):
                return None

            seen.add(said)
            order.append(said)
            hasEdgeSection = "e" in sad
            edges = sad.get("e")
            emptyEdgeSection = isinstance(edges, Mapping) and not edges
            if not hasEdgeSection or emptyEdgeSection:
                continue

            # String means it is a compact Edge Section, so validate the SAID and continue
            if isinstance(edges, str):
                try:
                    if Saider(qb64=edges).qb64 != edges:
                        return None
                except Exception:
                    return None
                continue

            # An expanded Edge Section is one top-level Edge-group block.
            if not isinstance(edges, Mapping):
                return None

            if not verifyExpandedSection(edges, kind=nserder.kind):
                return None
            groups = deque([(edges, (), False)])
            while groups:
                group, path, nested = groups.popleft()
                labels = EdgeGroupLabels if nested else EdgeSectionLabels
                if not nested and "w" in group:
                    return None
                if "n" in group:
                    if not nested:  # the Edge Section itself is an Edge-group
                        return None
                    if any(label not in EdgeNodeLabels for label in group):
                        return None
                    edgeSaid = group.get("n")
                    if not isinstance(edgeSaid, str):
                        return None
                    try:
                        if Saider(qb64=edgeSaid).qb64 != edgeSaid:
                            return None
                    except Exception:
                        return None
                    if edgeSaid not in nodes:
                        if closed:
                            return None
                        continue
                    if edgeSaid not in seen:
                        queue.append(edgeSaid)
                    continue

                for label, node in group.items():
                    if label in labels:
                        continue
                    childPath = path + (label,)
                    if isinstance(node, str):
                        try:
                            if Saider(qb64=node).qb64 != node:
                                return None
                        except Exception:
                            return None
                        edgeKind = self.schemaEvaluator.edgeKind(
                            nserder, childPath)
                        if edgeKind == "simple":
                            if node not in nodes:
                                if closed:
                                    return None
                                continue
                            if node not in seen:
                                queue.append(node)
                        continue
                    if not isinstance(node, Mapping):
                        return None
                    groups.append((node, childPath, True))

        if len(seen) != len(nodes):
            return None
        return order

    def evaluate(self, origin, *, nodes, records=None):
        """Evaluate a closed graph rooted at ``origin`` to one verdict.

        Validate graph closure and shape, then recursively evaluate each node's
        authentication, own schema, and Edge Section as one verdict.

        Parameters:
            origin (str): SAID of the graph's root ACDC.
            nodes (Mapping): ACDC SAID to parsed nest or nest-like object mapping.
            records (dict | None): Optional caller-owned collection populated by
                the node-authentication adapter.

        Returns:
            EdgeVerdict | None: Root verdict, or None when the disclosed graph or
                any Edge shape is malformed.
        """
        if self.walk(origin, nodes=nodes, closed=True) is None:
            return None

        return self._evaluateNode(origin, nodes=nodes, memo={}, records=records)

    def _evaluateNode(self, said, *, nodes, memo, records=None):
        """Evaluate one disclosed node and its Edge Section recursively.

        A node's authentication and own-schema verdicts are conjoined with the
        reduction of its Edge Section. An opaque compact Edge Section contributes
        a non-retryable unknown because its hidden operators cannot be evaluated.
        The memo stores completed verdicts and a temporary unknown verdict that
        prevents unexpected re-entry from recursing indefinitely.

        Parameters:
            said (str): SAID of the node to evaluate.
            nodes (Mapping): Disclosed graph indexed by ACDC SAID.
            memo (dict): Shared node-SAID to verdict memo for this evaluation.
            records (dict | None): Optional authentication records passed through
                to the caller-provided node verifier.

        Returns:
            EdgeVerdict | None: Combined node verdict, or None for malformed Edge
                structure.
        """
        if said in memo:
            return memo[said]

        memo[said] = chaining.unknown(
            f"node {said} is already being evaluated", retryable=False)

        nest = nodes[said]
        nserder = nest["serder"] if isinstance(nest, Mapping) else nest.serder

        auth = self.verifyNode(serder=nserder, nest=nest, records=records)
        schema = self.schemaEvaluator.evaluate(nserder, context=f"node {said}")

        sad = nserder.sad
        hasEdgeSection = "e" in sad
        edges = sad.get("e")

        emptyEdgeSection = isinstance(edges, Mapping) and not edges
        if not hasEdgeSection or emptyEdgeSection:
            section = chaining.valid(f"node {said} carries no edges")

        # String means it is a compact Edge
        elif isinstance(edges, str):
            section = chaining.unknown(
                f"node {said} carries compact Edge Section SAID {edges}, "
                f"whose hidden section this verifier cannot evaluate",
                retryable=False)
        else:
            if not isinstance(edges, Mapping):
                return None

            section = self._evaluateGroupEdge(
                edges, nodes=nodes, nserder=nserder, nested=False,
                memo=memo, records=records, inheritedPins=(), path=())
            if section is None:
                return None

        memo[said] = chaining.reduceAnd([auth, schema, section])
        return memo[said]

    def _evaluateLeafEdge(self, group, *, nodes, nserder, memo, records=None,
                          inheritedPins=()):
        """Evaluate one unary Edge and the far node it references.

        Resolve unary Operator defaults and conflict groups, evaluate their
        issuer/issuee relationships, enforce all inherited and local schema pins,
        and conjoin that result with the recursively evaluated far-node verdict.

        Parameters:
            group (Mapping): Expanded Edge block containing its required ``n``.
            nodes (Mapping): Disclosed graph indexed by ACDC SAID.
            nserder: Serder for the near-node ACDC that carries this Edge.
            memo (dict): Shared node-verdict memo for recursive evaluation.
            records (dict | None): Optional authentication-record collection.
            inheritedPins (tuple): Schema constraints inherited from enclosing
                Edge-groups.

        Returns:
            EdgeVerdict | None: Edge relation, schema, and far-node verdict, or
                None when the Edge block or a schema pin is malformed.
        """
        for label in group:
            if label not in EdgeNodeLabels:
                return None

        edgeSaid = group.get("n")
        if not isinstance(edgeSaid, str) or edgeSaid not in nodes:
            return None
        far = nodes[edgeSaid]
        fserder = far["serder"] if isinstance(far, Mapping) else far.serder

        operator = group.get("o")
        if operator is None:
            operators = []
        elif isinstance(operator, str):
            operators = [operator]
        elif (isinstance(operator, (list, tuple))
              and all(isinstance(item, str) for item in operator)):
            operators = list(operator)
        else:
            return None

        unrecognized = [item for item in operators if item not in UnaryEdgeOps]
        pins = tuple(inheritedPins)
        if "s" in group:
            pins = pins + (group["s"],)

        farSchema = fserder.schema if pins else None
        if isinstance(farSchema, Mapping):
            farSchemaId = farSchema.get("$id")
        elif isinstance(farSchema, str):
            farSchemaId = farSchema
        else:
            farSchemaId = None
        if pins and not isinstance(farSchemaId, str):
            return None

        resolvedPins = []
        for edgeSchema in pins:
            if isinstance(edgeSchema, str):
                try:
                    if Saider(qb64=edgeSchema).qb64 != edgeSchema:
                        return None
                except Exception:
                    return None
                resolvedPins.append((edgeSchema, edgeSchema))
            elif isinstance(edgeSchema, Mapping):
                declared = edgeSchema.get("$id")
                if not isinstance(declared, str):
                    return None
                try:
                    edgeSchemer = Schemer(sed=deepcopy(edgeSchema))
                except (RecursionError, TypeError, ValidationError, ValueError):
                    return None
                if edgeSchemer.said != declared:
                    return None
                resolvedPins.append((edgeSchemer.said, edgeSchema))
            else:
                return None

        relations = []
        if unrecognized:
            relations.append(chaining.unknown(
                f"unrecognized unary Operator(s) {unrecognized} on edge to node "
                f"{edgeSaid}; recognized are {list(UnaryEdgeOps)}",
                retryable=False))

        if not any(item in DefaultSuppressingEdgeOps for item in operators):
            default = "I2I" if fserder.iseaid is not None else "NI2I"
            operators.append(default)

        delegativeOperator = None
        issuerIdentityOperator = None
        for item in operators:
            if item in DelegativeEdgeOps:
                delegativeOperator = item
            if item in IssuerIdentityEdgeOps:
                issuerIdentityOperator = item

        unevaluable = [item for item in operators if item == "NOT"]
        if unevaluable:
            relations.append(chaining.unknown(
                f"unimplemented unary Operator(s) {unevaluable} on edge to node "
                f"{edgeSaid}", retryable=False))

        if "E1E" in operators:
            if (nserder.iseaid and fserder.iseaid
                    and nserder.iseaid == fserder.iseaid):
                relations.append(chaining.valid(
                    f"E1E edge to node {edgeSaid} has equal issuees"))
            else:
                relations.append(chaining.invalid(
                    f"E1E edge to node {edgeSaid} requires equal issuees; near "
                    f"issuee {nserder.iseaid} != far issuee {fserder.iseaid}"))

        if delegativeOperator == "I2I":
            if not fserder.iseaid:
                relations.append(chaining.invalid(
                    f"I2I edge to node {edgeSaid} requires a targeted far node, "
                    f"which has no issuee"))
            elif nserder.israid != fserder.iseaid:
                relations.append(chaining.invalid(
                    f"I2I edge to node {edgeSaid} requires the near issuer to be "
                    f"the far issuee; issuer {nserder.israid} != far issuee "
                    f"{fserder.iseaid}"))
            else:
                relations.append(chaining.valid(
                    f"I2I edge to node {edgeSaid} links issuer to far issuee"))

        if delegativeOperator == "DI2I":
            nearIssuer = nserder.israid
            farIssuee = fserder.iseaid
            if not nearIssuer or not farIssuee:
                relations.append(chaining.invalid(
                    f"DI2I edge to node {edgeSaid} requires a near issuer and "
                    f"a targeted far node; near issuer {nearIssuer}, far issuee "
                    f"{farIssuee}"))
            elif nearIssuer == farIssuee:
                relations.append(chaining.valid(
                    f"DI2I edge to node {edgeSaid} links issuer to far issuee"))
            else:
                delegated = self.isDelegated(nearIssuer, farIssuee)
                if delegated is True:
                    relations.append(chaining.valid(
                        f"DI2I edge to node {edgeSaid} has near issuer "
                        f"{nearIssuer} delegated from far issuee {farIssuee}"))
                elif delegated is False:
                    relations.append(chaining.invalid(
                        f"DI2I edge to node {edgeSaid} fails because near issuer "
                        f"{nearIssuer} is not delegated from far issuee "
                        f"{farIssuee}"))
                else:
                    reason = (f"DI2I edge to node {edgeSaid} is missing KEL or "
                              f"delegation-anchor evidence between near issuer "
                              f"{nearIssuer} and far issuee {farIssuee}")
                    relations.append(chaining.unknown(
                        reason, retryable=True, cause=MissingChainError(reason)))

        if issuerIdentityOperator is not None:
            nearIssuer = nserder.israid
            farIssuer = fserder.israid
            if not nearIssuer or not farIssuer:
                relations.append(chaining.invalid(
                    f"{issuerIdentityOperator} edge to node {edgeSaid} requires "
                    f"both nodes to have issuers"))
            elif nearIssuer == farIssuer:
                relations.append(chaining.valid(
                    f"{issuerIdentityOperator} edge to node {edgeSaid} has equal "
                    f"issuers"))
            elif issuerIdentityOperator == "I1I":
                relations.append(chaining.invalid(
                    f"I1I edge to node {edgeSaid} requires equal issuers; near "
                    f"issuer {nearIssuer} != far issuer {farIssuer}"))
            else:
                delegated = self.isDelegated(nearIssuer, farIssuer)
                if delegated is True:
                    relations.append(chaining.valid(
                        f"DI1I edge to node {edgeSaid} has near issuer "
                        f"{nearIssuer} delegated from far issuer {farIssuer}"))
                elif delegated is False:
                    relations.append(chaining.invalid(
                        f"DI1I edge to node {edgeSaid} fails because near issuer "
                        f"{nearIssuer} is not delegated from far issuer "
                        f"{farIssuer}"))
                else:
                    reason = (f"DI1I edge to node {edgeSaid} is missing KEL or "
                              f"delegation-anchor evidence between near issuer "
                              f"{nearIssuer} and far issuer {farIssuer}")
                    relations.append(chaining.unknown(
                        reason, retryable=True, cause=MissingChainError(reason)))

        relation = chaining.reduceAnd(relations) if relations else chaining.valid(
            f"edge to node {edgeSaid} satisfies its Operator")

        pinVerdicts = []
        if relation.verdict != chaining.Verdicts.invalid:
            for edgeSchemaId, edgeSchema in resolvedPins:
                if (isinstance(edgeSchema, str) and edgeSchema == farSchemaId
                        and isinstance(farSchema, Mapping)):
                    edgeSchema = farSchema
                context = (f"far node {edgeSaid} against edge schema "
                           f"{edgeSchemaId}")
                pinVerdicts.append(self.schemaEvaluator.evaluate(
                    fserder, schema=edgeSchema, context=context))

        own = chaining.reduceAnd([relation] + pinVerdicts)
        farVerdict = self._evaluateNode(
            edgeSaid, nodes=nodes, memo=memo, records=records)
        if farVerdict is None:
            return None
        return chaining.reduceAnd([own, farVerdict])

    def _evaluateGroupEdge(self, group, *, nodes, nserder, nested, memo,
                           records=None, inheritedPins=(), path=()):
        """Evaluate an Edge-group and reduce its child verdicts.

        Recurse through expanded child groups and Edges. The near-node schema
        determines whether a string child is a simple far-node reference or an
        opaque compact Edge-block commitment. Schema pins accumulate through
        nested groups and apply to every descendant Edge.

        Parameters:
            group (Mapping): Top-level Edge Section or nested Edge-group.
            nodes (Mapping): Disclosed graph indexed by ACDC SAID.
            nserder: Serder for the near-node ACDC that owns this group.
            nested (bool): False for the top-level Edge Section, True otherwise.
            memo (dict): Shared node-verdict memo for recursive evaluation.
            records (dict | None): Optional authentication-record collection.
            inheritedPins (tuple): Schema constraints inherited from parent groups.
            path (tuple): Edge labels from the Edge Section to this group.

        Returns:
            EdgeVerdict | None: Group verdict reduced by its m-ary Operator, or
                None when the group or one of its children is malformed.
        """
        labels = EdgeGroupLabels if nested else EdgeSectionLabels
        groupOperator = group.get("o", "AND")
        if not isinstance(groupOperator, str):
            return None

        nextPins = tuple(inheritedPins)
        if "s" in group:
            nextPins = nextPins + (group["s"],)

        results = []
        for label, node in group.items():
            if label in labels:
                continue
            childPath = path + (label,)
            if isinstance(node, str):
                try:
                    if Saider(qb64=node).qb64 != node:
                        return None
                except Exception:
                    return None
                edgeKind = self.schemaEvaluator.edgeKind(nserder, childPath)
                if edgeKind == "simple":
                    if node in nodes:
                        verdict = self._evaluateLeafEdge(
                            {"n": node}, nodes=nodes, nserder=nserder,
                            memo=memo, records=records,
                            inheritedPins=nextPins)
                        if verdict is None:
                            return None
                        results.append(verdict)
                    else:
                        reason = (f"simple edge {label} is missing far node "
                                  f"{node}")
                        results.append(chaining.unknown(
                            reason, retryable=True,
                            cause=MissingChainError(reason)))
                elif edgeKind == "compact":
                    results.append(chaining.unknown(
                        f"compact edge {label} carries Edge-block SAID {node}, "
                        f"whose hidden block this verifier cannot evaluate",
                        retryable=False))
                else:
                    results.append(chaining.unknown(
                        f"schema does not distinguish whether edge {label} "
                        f"carries a far-node or Edge-block SAID",
                        retryable=False))
                continue
            if not isinstance(node, Mapping):
                return None

            if "n" in node:
                verdict = self._evaluateLeafEdge(
                    node, nodes=nodes, nserder=nserder, memo=memo,
                    records=records, inheritedPins=nextPins)
            else:
                verdict = self._evaluateGroupEdge(
                    node, nodes=nodes, nserder=nserder, nested=True, memo=memo,
                    records=records, inheritedPins=nextPins, path=childPath)
            if verdict is None:
                return None
            results.append(verdict)

        if not results:
            return None
        if groupOperator not in self.reducers:
            return chaining.unknown(
                f"Edge-group Operator {groupOperator!r} is not reduced by this "
                f"verifier; reducible are {sorted(self.reducers)}", retryable=False)

        return chaining.reduce(groupOperator, results, reducers=self.reducers)
