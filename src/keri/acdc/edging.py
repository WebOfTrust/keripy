# -*- encoding: utf-8 -*-
"""
keri.acdc.edging module

v2 Edge Section verification over far nodes presented alongside the ACDC that
points at them.

keripy's other edge evaluators are welded to where their evidence comes from: the v1
Verifier reads far nodes and their state from a Reger and its Tevers, and the v2
IpexHandler reads them from a grant's nests and a Regery store. A party that is
handed an ACDC and the ACDCs it chains to -- as bytes, over any transport -- has
neither, so it had no v2 edge verifier to call. This module is that verifier, with
no storage and no transport of its own. The caller hands over the far nodes, a
judgment of each far node's own standing, and a schema resolver, and gets back one
verdict for the Edge Section.

The algebra is keri.acdc.chaining's three-valued lattice, and the leaf, group and
default-Operator rules follow the v2 IPEX evaluator on feat/edge-operators rule for
rule, so the two v2 evaluators agree. Three differences are deliberate:

- A far node that was not presented is an unknown, retryable verdict naming it
  (FarNodeAbsent), not a malformed shape. A grant's closure rule makes a dangling
  reference malformed there; here the presenter simply withheld it, and under OR a
  sibling may carry the group without it.
- NOT is evaluated, as the Kleene negation of the far node's own verdict. That is
  the specification's text (spec-body.md, "The NOT unary Operator ... inverts the
  validation truthiness of the node pointed to by this Edge"). Withholding cannot
  satisfy it, because the negation of unknown is unknown.
- DI2I is evaluated when the caller supplies a delegator resolver, and is an unknown
  no arrival settles when it does not.

Malformed shapes raise EdgeShapeError rather than entering the lattice, because a
shape is not a truth value and a satisfied sibling under OR must not outvote it.
"""

from collections import namedtuple
from collections.abc import Mapping
from copy import deepcopy

from ..kering import KeriError, ValidationError, MissingAnchorError
from . import chaining


EdgeSectionLabels = ("d", "u", "s", "o", "w")
EdgeGroupLabels = ("d", "u", "s", "o", "w")
EdgeNodeLabels = ("d", "u", "n", "s", "o", "w")
UnaryOps = ("I2I", "NI2I", "DI2I", "E1E", "NOT")
DelegativeOps = ("I2I", "NI2I", "DI2I")
DefaultSuppressingOps = ("I2I", "NI2I", "DI2I", "E1E")
"""Unary Operators whose presence suppresses the default rule. "When the Operator,
`o`, field is missing or empty or is present but does not include any of the `I2I`,
`NI2I`, `DI2I`, or `E1E` Operators" the default is appended (ACDC v1.1 line)."""

AcceptedStates = ("issued",)
"""Registry states registryStanding reads as good standing. Policy, not protocol:
ACDC defines a registry's transaction states per registry."""

TerminalStates = ("revoked",)
"""Registry states registryStanding reads as refusing the far node."""

DelegationDepth = 32
"""How many delegators DI2I will climb from the near issuer before giving up. A
bound rather than a belief: the resolver is the caller's, and nothing here can
promise it terminates."""

FarNodeAbsent = namedtuple("FarNodeAbsent", "said")
"""The cause attached to an edge whose far node was not presented.

Fields:
    said (str): the far node's SAID, as the Edge names it
"""


class EdgeShapeError(ValidationError):
    """An Edge Section, Edge-group or Edge whose shape this verifier cannot read.

    Raised rather than returned as a verdict: a malformed shape says the ACDC is not
    well-formed, which is not something a satisfied sibling may outvote.
    """


def verifyEdges(acdc, *, nodes, standing, schemas=None, delegators=None,
                reducers=None):
    """Returns the verdict of acdc's Edge Section over the far nodes presented.

    Every far node reached is judged on two axes and both must hold: the edge's own
    Operator relation and schema pins, and the far node's own verdict -- its standing
    as judged by the caller, conjoined with its own Edge Section, recursively. So a
    Residence whose Core rests on a Utah agent credential needs all three.

    The ACDC's own standing is not consulted. The caller has presumably judged it
    already, and an Edge Section is a claim about far nodes.

    Parameters:
        acdc (SerderACDC): the near ACDC whose Edge Section is verified
        nodes (Mapping): far-node SAID -> SerderACDC for every far node presented.
            Keys must equal their serder's SAID.
        standing (callable): standing(serder) -> EdgeVerdict for a far node's own
            authenticity and registry state. Called at most once per far node, and
            only for far nodes an edge reaches. See registryStanding.
        schemas (callable|None): schemas(said) -> Schemer|None resolving an edge
            schema pin named by SAID. None resolves nothing, which leaves every pin
            named by SAID an unknown, retryable verdict.
        delegators (callable|None): delegators(aid) -> str|None naming the AID that
            delegated aid, or None when it is not delegated or not known. Needed only
            by DI2I; without it DI2I is an unknown no arrival settles.
        reducers (dict|None): m-ary Operator table, default chaining.MAryReducers

    Returns:
        EdgeVerdict: valid, invalid, or unknown with its retryable bit and causes

    Raises:
        EdgeShapeError: when any Edge Section reached is malformed
    """
    for said, serder in nodes.items():
        if said != serder.said:
            raise EdgeShapeError(f"far node keyed {said} is {serder.said}")

    walker = _Walker(nodes=nodes, standing=standing, schemas=schemas,
                     delegators=delegators,
                     reducers=chaining.MAryReducers if reducers is None else reducers)
    return walker.section(acdc)


def reach(acdc, nodes):
    """Returns the SAIDs of presented far nodes acdc rests on, in walk order.

    Breadth-first over edges, through presented far nodes only: a far node reached
    only through one that was withheld is not reached. A caller uses this to know
    which far nodes to judge before calling verifyEdges, and which presented ones
    no edge needs.

    Parameters:
        acdc (SerderACDC): the near ACDC
        nodes (Mapping): far-node SAID -> SerderACDC

    Raises:
        EdgeShapeError: when any Edge Section reached is malformed
    """
    order, queue, seen = [], [acdc], {acdc.said}
    while queue:
        serder = queue.pop(0)
        for said in _named(serder.sad.get("e")):
            if said in nodes and said not in seen:
                seen.add(said)
                order.append(said)
                queue.append(nodes[said])
    return tuple(order)


def registryStanding(acdc, rip, updates=(), *, db, blinder=None,
                     accepted=AcceptedStates, terminal=TerminalStates):
    """Returns a far node's standing in its v2 registry as an EdgeVerdict.

    Wraps keri.acdc.regeventing.vet, which verifies the registry chain (rip plus
    upd/bup updates) against the issuer's KEL in db and binds the ACDC to the head,
    and reads the head's transaction state the way the v2 IPEX evaluator does.

    Parameters:
        acdc (SerderACDC): the far node
        rip (SerderACDC|bytes): registry inception event
        updates (Iterable): the registry's upd/bup events
        db (Baser): KEL database already holding the issuer's KEL
        blinder (Blinder|None): disclosed blinded state for a bup head
        accepted (Iterable): states read as good standing
        terminal (Iterable): states read as refusing the far node

    Returns:
        EdgeVerdict: valid for an accepted state, invalid for a terminal state or
            evidence vet refuses, unknown and retryable for an anchor not yet in
            db, unknown for good when the head states nothing or a state outside
            both vocabularies. Causes carry the RegStateRecord, or the exception
            vet raised, so a caller can say which.
    """
    from . import regeventing

    try:
        record = regeventing.vet(rip, updates, db=db, acdc=acdc, blinder=blinder)
    except MissingAnchorError as ex:
        return chaining.unknown(f"registry evidence for {acdc.said} is not all "
                                f"anchored yet: {ex}", retryable=True, cause=ex)
    except (KeriError, ValueError) as ex:  # every named refusal, and bytes that do not parse
        return chaining.invalid(f"registry evidence for {acdc.said} does not vet: "
                                f"{type(ex).__name__}: {ex}", cause=ex)

    if record.state is None:
        return chaining.unknown(f"registry {record.regid} head at n={record.sn} "
                                f"states nothing for {acdc.said}", retryable=False,
                                cause=record)
    if record.state in terminal:
        return chaining.invalid(f"registry {record.regid} says {acdc.said} is "
                                f"{record.state!r}", cause=record)
    if record.state not in accepted:
        return chaining.unknown(f"registry {record.regid} says {acdc.said} is "
                                f"{record.state!r}, which is neither "
                                f"{list(accepted)} nor {list(terminal)}",
                                retryable=False, cause=record)
    return chaining.valid(f"registry {record.regid} says {acdc.said} is "
                          f"{record.state!r}", cause=record)


def negate(verdict):
    """Returns the Kleene negation of an EdgeVerdict, keeping reason and causes."""
    if verdict.verdict == chaining.Verdicts.valid:
        return chaining.EdgeVerdict(chaining.Verdicts.invalid, False,
                                    f"NOT of: {verdict.reason}", verdict.causes)
    if verdict.verdict == chaining.Verdicts.invalid:
        return chaining.EdgeVerdict(chaining.Verdicts.valid, True,
                                    f"NOT of: {verdict.reason}", verdict.causes)
    return verdict


def _blocks(section):
    """The Edge Section as a list of top-level blocks, or None for a compact one."""
    if isinstance(section, str):
        return None
    if isinstance(section, Mapping):
        return [section]
    if isinstance(section, list) and all(isinstance(block, Mapping)
                                         for block in section):
        return section
    raise EdgeShapeError(f"Edge Section is a {type(section).__name__}, neither a "
                         f"block, a list of blocks nor a SAID")


def _reserved(group, labels):
    """Refuses a reserved `d` or `u` that is not a string.

    keripy's walkers skip reserved labels by name, so a `u` holding an edge-shaped
    map is an edge one reader waves through while another reads an Operator out of
    the same bytes.
    """
    for label in ("d", "u"):
        if label in group and label in labels and not isinstance(group[label], str):
            raise EdgeShapeError(f"reserved Edge-group label {label!r} holds a "
                                 f"{type(group[label]).__name__}, not a string")


def _named(section):
    """Yields every far-node SAID an Edge Section names, checking only its shape."""
    blocks = _blocks(section) if section else []
    for block in blocks or []:
        groups = [(block, False)]
        while groups:
            group, nested = groups.pop()
            if "n" in group:
                if not isinstance(group["n"], str):
                    raise EdgeShapeError(f"Edge node field is a "
                                         f"{type(group['n']).__name__}, not a SAID")
                yield group["n"]
                continue
            labels = EdgeGroupLabels if nested else EdgeSectionLabels
            _reserved(group, labels)
            for label, member in group.items():
                if label in labels or isinstance(member, str):
                    continue
                if not isinstance(member, Mapping):
                    raise EdgeShapeError(f"Edge-group member {label!r} is a "
                                         f"{type(member).__name__}")
                groups.append((member, True))


class _Walker:
    """One evaluation of one near ACDC's Edge Section, memoised by far node."""

    def __init__(self, *, nodes, standing, schemas, delegators, reducers):
        self.nodes = nodes
        self.standing = standing
        self.schemas = schemas
        self.delegators = delegators
        self.reducers = reducers
        self.memo = {}

    def section(self, serder):
        """Returns the verdict of serder's Edge Section alone."""
        edges = serder.sad.get("e")
        if not edges:
            return chaining.valid(f"node {serder.said} carries no edges")
        blocks = _blocks(edges)
        if blocks is None:
            return chaining.unknown(f"Edge Section of {serder.said} is compact "
                                    f"({edges}) and cannot be dereferenced",
                                    retryable=False)
        verdicts = []
        for block in blocks:
            if "n" in block:
                verdicts.append(self.leaf(block, near=serder, pins=()))
            else:
                verdicts.append(self.group(block, near=serder, nested=False, pins=()))
        return chaining.reduceAnd(verdicts)

    def node(self, said):
        """Returns a presented far node's own verdict: standing AND its edges.

        Memoised, so a far node several edges name is judged once. No re-entry
        guard: the node table's keys are checked against their SAIDs, and an edge's
        `n` sits inside the content its near node's SAID commits to, so a cycle
        would need a digest fixed point.
        """
        if said not in self.memo:
            serder = self.nodes[said]
            own = self.standing(serder)
            self.memo[said] = chaining.reduceAnd([own, self.section(serder)])
        return self.memo[said]

    def group(self, group, *, near, nested, pins):
        """Returns the verdict of one Edge-group, reduced under its Operator."""
        labels = EdgeGroupLabels if nested else EdgeSectionLabels
        _reserved(group, labels)
        op = group.get("o", "AND")
        if not isinstance(op, str):
            raise EdgeShapeError(f"Edge-group Operator is a {type(op).__name__}; "
                                 f"only an Edge's unary `o` may be a list")
        if "s" in group:
            pins = pins + (group["s"],)

        results = []
        for label, member in group.items():
            if label in labels:
                continue
            if isinstance(member, str):
                results.append(chaining.unknown(
                    f"compact edge {label} names Edge block {member}, which this "
                    f"verifier cannot dereference", retryable=False))
                continue
            if not isinstance(member, Mapping):
                raise EdgeShapeError(f"Edge-group member {label!r} is a "
                                     f"{type(member).__name__}")
            if "n" in member:
                results.append(self.leaf(member, near=near, pins=pins))
            else:
                results.append(self.group(member, near=near, nested=True, pins=pins))

        if not results:
            raise EdgeShapeError("Edge-group with no members cannot reduce")
        if op not in self.reducers:
            return chaining.unknown(f"Edge-group Operator {op!r} is not reduced by "
                                    f"this verifier; reducible are "
                                    f"{sorted(self.reducers)}", retryable=False)
        return chaining.reduce(op, results, reducers=self.reducers)

    def leaf(self, edge, *, near, pins):
        """Returns one Edge's verdict: its Operator relation, its pins, and the far
        node's own verdict, conjoined (or the far node negated, under NOT)."""
        for label in edge:
            if label not in EdgeNodeLabels:
                raise EdgeShapeError(f"Edge carries unknown label {label!r}")
        said = edge["n"]
        if not isinstance(said, str):
            raise EdgeShapeError(f"Edge node field is a {type(said).__name__}, "
                                 f"not a SAID")

        op = edge.get("o")
        if op is None:
            ops = []
        elif isinstance(op, str):
            ops = [op]
        elif isinstance(op, list):
            ops = list(op)
        else:
            raise EdgeShapeError(f"Edge Operator is a {type(op).__name__}")

        if "s" in edge:
            pins = pins + (edge["s"],)
        resolved = [_pin(pin) for pin in pins]

        unrecognized = [cand for cand in ops if cand not in UnaryOps]
        if unrecognized:
            own = chaining.unknown(f"unrecognized unary Operator(s) {unrecognized} "
                                   f"on edge to node {said}; recognized are "
                                   f"{list(UnaryOps)}", retryable=False)
            if said not in self.nodes:
                return own
            return chaining.reduceAnd([own, self.node(said)])

        if said not in self.nodes:
            return chaining.unknown(f"far node {said} was not presented",
                                    retryable=True, cause=FarNodeAbsent(said))
        far = self.nodes[said]

        if not any(cand in DefaultSuppressingOps for cand in ops):
            ops = ops + ["I2I" if far.iseaid is not None else "NI2I"]
        dop = next((cand for cand in reversed(ops) if cand in DelegativeOps), None)

        own = self.relation(ops, dop, near=near, far=far)
        if own.verdict == chaining.Verdicts.valid:
            own = self.pinned(resolved, far=far) or own

        farVerdict = self.node(said)
        if "NOT" in ops:
            farVerdict = negate(farVerdict)
        return chaining.reduceAnd([own, farVerdict])

    def relation(self, ops, dop, *, near, far):
        """Returns the verdict of the unary Operators' relation between the nodes."""
        said = far.said
        if "E1E" in ops:
            if not near.iseaid or not far.iseaid or near.iseaid != far.iseaid:
                return chaining.invalid(f"E1E edge to node {said} requires equal "
                                        f"issuees; near issuee {near.iseaid} != far "
                                        f"issuee {far.iseaid}")
        if dop in ("I2I", "DI2I") and not far.iseaid:
            return chaining.invalid(f"{dop} edge to node {said} requires a targeted "
                                    f"far node, which has no issuee")
        if dop == "I2I" and near.israid != far.iseaid:
            return chaining.invalid(f"I2I edge to node {said} requires the near "
                                    f"issuer to be the far issuee; issuer "
                                    f"{near.israid} != far issuee {far.iseaid}")
        if dop == "DI2I":
            if self.delegators is None:
                return chaining.unknown(f"DI2I edge to node {said} needs a delegator "
                                        f"resolver, and none was given",
                                        retryable=False)
            if not self.delegated(near.israid, far.iseaid):
                return chaining.invalid(f"DI2I edge to node {said} requires the near "
                                        f"issuer {near.israid} to be the far issuee "
                                        f"{far.iseaid} or delegated from it")
        return chaining.valid(f"edge to node {said} satisfies its Operators")

    def delegated(self, issuer, issuee):
        """True when issuer is issuee or sits below it in a delegation chain."""
        aid, seen = issuer, set()
        while aid is not None and aid not in seen and len(seen) <= DelegationDepth:
            if aid == issuee:
                return True
            seen.add(aid)
            aid = self.delegators(aid)
        return False

    def pinned(self, resolved, *, far):
        """Returns a non-valid verdict when a schema pin fails, else None."""
        farSchema = far.schema
        farSchemaId = farSchema.get("$id") if isinstance(farSchema, Mapping) else farSchema
        for said, schemer in resolved:
            if schemer is None:
                if said == farSchemaId and isinstance(farSchema, Mapping):
                    schemer = _pin(dict(farSchema))[1]
                elif self.schemas is not None:
                    schemer = self.schemas(said)
            if schemer is None:
                return chaining.unknown(f"edge schema {said} pinned on the edge to "
                                        f"node {far.said} is not in cache",
                                        retryable=True)
            try:
                schemer.verify(far.raw)
            except ValidationError as ex:
                return chaining.invalid(f"far node {far.said} does not satisfy edge "
                                        f"schema {said}: {ex}")
        return None


def _pin(pin):
    """Returns (SAID, Schemer-or-None) for one schema pin, or raises on its shape."""
    from ..core.scheming import Schemer

    if isinstance(pin, str):
        return pin, None
    if not isinstance(pin, Mapping):
        raise EdgeShapeError(f"edge schema pin is a {type(pin).__name__}")
    declared = pin.get("$id")
    if not isinstance(declared, str):
        raise EdgeShapeError("inline edge schema pin carries no string $id")
    try:
        schemer = Schemer(sed=deepcopy(dict(pin)))
    except (ValidationError, ValueError, TypeError) as ex:
        raise EdgeShapeError(f"inline edge schema pin does not load: {ex}") from ex
    if schemer.said != declared:
        raise EdgeShapeError(f"inline edge schema pin declares {declared} and "
                             f"derives {schemer.said}")
    return schemer.said, schemer
