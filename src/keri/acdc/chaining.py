# -*- encoding: utf-8 -*-
"""
keri.acdc.chaining module

Edge Section verdicts and the m-ary Operator reductions over them.

An ACDC edge is decided on two axes: the unary Operator's relation between the near
and far nodes, and the far node itself -- whether it is in hand, whether it satisfies
the schemas pinned on the edge and its enclosing groups, and what its registry says
about it. An m-ary Operator aggregates members, so both axes have to reach it as one
value or the Operator does not mean what the ACDC specification says it means. An
`OR` whose second member is merely absent must not escrow the near ACDC, because the
group is already satisfied; that is only expressible if "absent" is a verdict rather
than a control-flow jump out of the loop.

So this module holds no storage and no evidence. It defines the verdict a member
evaluates to, the reductions the Edge-group Operators perform over them, and nothing
else. Each caller maps its own evidence into verdicts and disposes of the reduced one
its own way -- v1 escrows and cues, the v2 IPEX path escrows through the Exchanger --
which is why the mapping and the disposition stay with the callers while the algebra
lives here.

It does hold one policy, and says so rather than pretending otherwise: which
Operators reduce, and how they read a member whose validity is not determined. ACDC
assigns edge-validity logic to the Ecosystem Governance Framework, so the Kleene
reading below is keripy's default rather than protocol. Both callers reach the table
through a `MAryReducers` attribute they own, so a profile overrides it instead of
forking the evaluator. See .MAryReducers.

Three values, not four. An unknown verdict carries a retryability bit instead:
"the evidence has not arrived" and "this implementation cannot evaluate the Operator"
sit in the same place in the lattice and differ only in what the caller should do, so
a flag keeps every reduction's table three rows wide rather than four.
"""

from collections import namedtuple

from ..kering import ValidationError


Verdictage = namedtuple("Verdictage", "valid invalid unknown")

Verdicts = Verdictage(valid='valid', invalid='invalid', unknown='unknown')
"""The three truth values an edge or Edge-group evaluates to.

Fields:
    valid (str): the edge holds on the evidence in hand
    invalid (str): the edge does not hold, decided on the evidence in hand
    unknown (str): the edge's validity is not determined -- see EdgeVerdict.retryable
"""

EdgeVerdict = namedtuple("EdgeVerdict", "verdict retryable reason causes",
                         defaults=((),))
"""One edge's or Edge-group's verdict, with why.

Fields:
    verdict (str): one of Verdicts
    retryable (bool): whether evidence that may still arrive could change an unknown
        verdict to valid. Meaningful only when verdict is Verdicts.unknown; fixed
        True for valid and False for invalid, since neither is waiting on anything.
    reason (str): diagnostic naming what decided this verdict, carried through the
        reductions so a refusal names the member that caused it rather than only the
        group that contained it
    causes (tuple): whatever the caller attached to the members that decided this
        verdict, in section order. Opaque here -- this module holds no policy -- and
        a tuple rather than one value because a group's unknown genuinely has
        several contributing members, and a caller that escrows must act on every
        one of them or the ACDC waits forever on a query nobody sent.
"""


def valid(reason, cause=None):
    """Returns an EdgeVerdict for an edge that holds.

    Parameters:
        reason (str): what was checked
        cause (object|None): caller payload for this member, see EdgeVerdict.causes

    """
    return EdgeVerdict(Verdicts.valid, True, reason, _causes(cause))


def invalid(reason, cause=None):
    """Returns an EdgeVerdict for an edge decided not to hold.

    Nothing that arrives later changes an invalid verdict, so .retryable is False.
    Reserve this for a conclusion drawn from evidence already in hand -- an Operator
    relation that fails, or a far node that fails a resolvable schema pin -- and use
    .unknown for anything merely absent.

    Parameters:
        reason (str): what failed
        cause (object|None): caller payload for this member, see EdgeVerdict.causes

    """
    return EdgeVerdict(Verdicts.invalid, False, reason, _causes(cause))


def unknown(reason, *, retryable, cause=None):
    """Returns an EdgeVerdict for an edge whose validity is not determined.

    Parameters:
        reason (str): why the edge could not be decided
        retryable (bool): True when evidence that may still arrive could decide it,
            which is the caller's cue to escrow. False when nothing can -- an
            Operator this implementation does not evaluate, for instance -- in which
            case escrowing would promise a retry that cannot succeed. Keyword-only
            and required, because defaulting it either way silently converts one of
            those cases into the other.
        cause (object|None): caller payload for this member, see EdgeVerdict.causes

    """
    return EdgeVerdict(Verdicts.unknown, retryable, reason, _causes(cause))


def _causes(cause):
    """Returns the one-or-none cause of a single member as a tuple."""
    return () if cause is None else (cause,)


def _join(verdicts):
    """Returns the joined reasons and concatenated causes of several members."""
    causes = ()
    for verdict in verdicts:
        causes = causes + tuple(verdict.causes)
    return "; ".join(verdict.reason for verdict in verdicts), causes


def reduceAnd(verdicts):
    """Returns the AND reduction of member verdicts.

    "Logical AND of the validity of the Edge-group members. Edge-group is valid only
    if all members are valid" (ACDC spec-body.md, m-ary Operator table), read over
    three values as Kleene strong conjunction: one invalid member decides the group
    however many are unknown, and an unknown member only matters when nothing else
    has decided it.

    A group's unknown is retryable only when every unknown member is. One member
    that can never become valid makes the conjunction unreachable no matter what
    arrives for the others.

    Parameters:
        verdicts (list): EdgeVerdict of each member, in section order

    """
    for verdict in verdicts:
        if verdict.verdict == Verdicts.invalid:
            return verdict  # the deciding member, with its own reason and causes

    unknowns = [v for v in verdicts if v.verdict == Verdicts.unknown]
    if unknowns:
        reason, causes = _join(unknowns)
        return EdgeVerdict(Verdicts.unknown,
                           all(v.retryable for v in unknowns), reason, causes)

    return valid(_join(verdicts)[0])


def reduceOr(verdicts):
    """Returns the OR reduction of member verdicts.

    "Logical OR of the validity of the Edge-group members. Edge-group is valid if one
    of the members is valid" (ACDC spec-body.md, m-ary Operator table), read over
    three values as Kleene strong disjunction. One valid member decides the group,
    which is what keeps a satisfied group from waiting on -- or querying for -- a
    member it does not need.

    A group's unknown is retryable when any unknown member is, since one arrival can
    carry the whole group on its own.

    Parameters:
        verdicts (list): EdgeVerdict of each member, in section order

    """
    for verdict in verdicts:
        if verdict.verdict == Verdicts.valid:
            return verdict  # the deciding member, with its own reason and causes

    unknowns = [v for v in verdicts if v.verdict == Verdicts.unknown]
    if unknowns:
        reason, causes = _join(unknowns)
        return EdgeVerdict(Verdicts.unknown,
                           any(v.retryable for v in unknowns), reason, causes)

    reason, causes = _join(verdicts)
    return EdgeVerdict(Verdicts.invalid, False, reason, causes)


MAryReducers = dict(AND=reduceAnd, OR=reduceOr)
"""keripy's default reduction for the ACDC Edge-group Operators, by token.

A default, not a protocol constant. ACDC assigns "the actual logic for interpreting
the validity of a set of chained or treed ACDCs" to the Ecosystem Governance
Framework (spec-body.md), and its m-ary Operator table is written over two values:
it says an `AND` group is valid only if all members are valid and an `OR` group is
valid if one member is, and says nothing about a member whose validity is not
determined. Reading those rows as Kleene strong logic is this implementation's
answer to that deferral. Both callers reach it through a `MAryReducers` attribute of
their own, so a profile registers its Operators -- the dossier's weighted thresholds,
for instance -- rather than growing a second evaluator.

`NAND` and `NOR` are **unimplemented rather than unreducible**. Kleene negation is
total (not-valid is invalid, not-invalid is valid, not-unknown is unknown), so both
reduce over this lattice with no step that reads an undetermined member as false.
What is unsettled is the specification, whose negation prose is two-valued -- the
unary `NOT` row says "If valid, then not valid. If invalid, then valid" -- so a
verifier following it literally satisfies a negative constraint on evidence the
Discloser simply withheld, and reduces `NAND`/`NOR` to a different answer than this
lattice would. Registering them here before that clause is amended would make keripy
and a literal reader disagree on a security-relevant shape; failing closed until then
is the conservative side of a disagreement this module cannot settle on its own.

`AVG` and `WAVG` are a different case: they return a number over a schema-defined
member property rather than a validity, so they do not reduce to a verdict at all.

A caller meeting any unregistered token must fail closed; .reduce raises.
"""


def reduce(op, verdicts):
    """Returns the reduction of member verdicts under the m-ary Operator op.

    Parameters:
        op (str): m-ary Operator token, which MUST be a key of .MAryReducers
        verdicts (list): EdgeVerdict of each member, in section order

    Raises:
        ValidationError: if op is not reduced by this module, or if there are no
            members. Neither has an answer here, but they are different kinds of
            thing and the callers treat them differently.

            An Edge-group with no members is malformed: read as valid it would
            satisfy an enclosing AND, and read as invalid it would refuse a section
            its Issuer wrote deliberately. A malformed shape says the ACDC is not
            well-formed rather than that some member's validity is unknown, so it
            aborts the Edge Section before any reduction runs -- otherwise a
            satisfied sibling under OR could outvote a well-formedness failure.

            An Operator this table does not reduce is not malformed; the Issuer
            named a rule and this implementation cannot apply it. Inventing a
            verdict for it would be the silent substitution that makes the rule mean
            less than it says, so the raise is how a caller learns to record the
            group as an unknown no arrival can settle. Under Kleene reduction such
            an unknown cannot change a verdict its siblings already decide, which is
            what the specification's OR row asks for, and where it *is* outcome
            relevant the section reduces to an unknown and is refused.

    """
    if op not in MAryReducers:
        raise ValidationError(f"Edge-group Operator {op} is not reduced to a "
                              f"verdict; reducible are {sorted(MAryReducers)}")

    if not verdicts:
        raise ValidationError(f"Edge-group with no members cannot reduce under {op}")

    return MAryReducers[op](verdicts)
