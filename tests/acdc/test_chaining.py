# -*- encoding: utf-8 -*-
"""
tests.acdc.test_chaining module

Tests for keri.acdc.chaining: the three-valued verdict an ACDC edge evaluates to,
and the m-ary reducers that aggregate an Edge-group's members into one.

Storage-free by construction. A verdict is a value, not control flow, so these
tests need no KEL, no registry, no LMDB and no fixtures -- which is the point of
putting the reduction here rather than in either verifier's disposition loop.
"""

import pytest

from keri.kering import ValidationError
from keri.acdc.chaining import (Verdicts, EdgeVerdict, valid, invalid, unknown,
                                reduce, MAryReducers)


def test_verdict_values():
    """Three values, and an unknown that remembers whether waiting can help.

    The third value carries a retryability bit rather than splitting into a fourth
    value. "This edge cannot be evaluated because the evidence has not arrived" and
    "because this implementation does not implement the operator" have the same
    place in the lattice -- an unknown truth value -- and differ only in what the
    caller should do about it. Making that a flag keeps every reducer's table three
    rows wide instead of four.
    """
    assert Verdicts.valid == 'valid'
    assert Verdicts.invalid == 'invalid'
    assert Verdicts.unknown == 'unknown'

    # The constructors name the three cases so a caller never spells a verdict by
    # hand, and each carries a reason for diagnostics (keri-sow tick 22pi).
    assert valid("far node issued") == EdgeVerdict(Verdicts.valid, True,
                                                  "far node issued")
    assert invalid("I2I mismatch") == EdgeVerdict(Verdicts.invalid, False,
                                                 "I2I mismatch")
    assert unknown("far node absent", retryable=True).retryable is True
    assert unknown("DI2I unimplemented", retryable=False).retryable is False

    # Retryability is meaningful only for an unknown. A valid verdict needs no
    # retry and an invalid one cannot be helped by any, so the flag is fixed for
    # both rather than left to the caller to interpret.
    assert valid("ok").retryable is True
    assert invalid("no").retryable is False

    with pytest.raises(TypeError):  # a bare unknown is ambiguous; say which kind
        unknown("no flag")


def test_reduce_and_or_over_the_lattice():
    """Kleene three-valued AND and OR, as the ACDC m-ary table's first two rows.

    spec-body.md:1103-1104: AND means the "Edge-group is valid only if all members
    are valid"; OR means it "is valid if one of the members is valid". Over three
    values those read as Kleene strong logic, which is the only reading that leaves
    an unknown member unable to change a verdict its siblings already decide.

    The two rows that carry the design are OR(unknown, valid) = valid, so a group
    already satisfied on evidence in hand does not wait on a member it does not
    need, and AND(unknown, invalid) = invalid, so a group already doomed does not
    wait either.
    """
    V = valid("v")
    I = invalid("i")
    U = unknown("u", retryable=True)

    table = {
        ('AND', 'valid', 'valid'): Verdicts.valid,
        ('AND', 'valid', 'invalid'): Verdicts.invalid,
        ('AND', 'valid', 'unknown'): Verdicts.unknown,
        ('AND', 'invalid', 'invalid'): Verdicts.invalid,
        ('AND', 'invalid', 'unknown'): Verdicts.invalid,
        ('AND', 'unknown', 'unknown'): Verdicts.unknown,
        ('OR', 'valid', 'valid'): Verdicts.valid,
        ('OR', 'valid', 'invalid'): Verdicts.valid,
        ('OR', 'valid', 'unknown'): Verdicts.valid,
        ('OR', 'invalid', 'invalid'): Verdicts.invalid,
        ('OR', 'invalid', 'unknown'): Verdicts.unknown,
        ('OR', 'unknown', 'unknown'): Verdicts.unknown,
    }
    byName = dict(valid=V, invalid=I, unknown=U)

    for (op, left, right), expected in table.items():
        members = [byName[left], byName[right]]
        assert reduce(op, members).verdict == expected, (op, left, right)
        # Commutative, so a producer cannot change a verdict by reordering members.
        assert reduce(op, list(reversed(members))).verdict == expected, (op, right, left)

    # A single member reduces to itself under both operators.
    for op in ('AND', 'OR'):
        for member in (V, I, U):
            assert reduce(op, [member]).verdict == member.verdict

    # Only the operators this module reduces are registered. AND and OR are the
    # ACDC table's monotone rows; NAND, NOR, AVG and WAVG are not here, and a
    # caller meeting one must fail closed rather than reach for a reducer.
    assert sorted(MAryReducers) == ['AND', 'OR']


def test_reduce_propagates_retryability():
    """Retryability propagates with the verdict, so a disposition reads one bit.

    Without a propagation rule "escrow if every unknown that contributed is
    retryable" admits two readings -- every unknown member, or every member whose
    arrival could change the reduced verdict -- and two conforming verifiers reach
    opposite, externally visible outcomes on the same bytes.

    The rule follows from what an arrival can do. Under AND, one non-retryable
    unknown makes valid unreachable however much else arrives, so the group is
    retryable only if every unknown member is. Under OR, one retryable unknown can
    still carry the whole group, so any is enough.
    """
    V = valid("v")
    I = invalid("i")
    R = unknown("evidence not in hand", retryable=True)
    N = unknown("operator unimplemented", retryable=False)

    assert reduce('AND', [R, R]).retryable is True
    assert reduce('AND', [R, N]).retryable is False
    assert reduce('AND', [N, V]).retryable is False
    assert reduce('AND', [R, V]).retryable is True

    assert reduce('OR', [R, N]).retryable is True
    assert reduce('OR', [N, N]).retryable is False
    assert reduce('OR', [N, I]).retryable is False
    assert reduce('OR', [R, I]).retryable is True

    # A decided verdict fixes the bit regardless of the members' flags: nothing is
    # waiting on evidence once the group is valid or invalid.
    assert reduce('OR', [V, N]).retryable is True     # valid
    assert reduce('AND', [I, N]).retryable is False   # invalid


def test_reduce_carries_a_reason_from_the_member_that_decided():
    """The reduced verdict names why, so a refusal is triageable.

    The reason a group failed is the reason one of its members did; a group-level
    message alone leaves an operator to re-derive which edge broke. Under AND the
    decider is the first invalid member, under OR the first valid one, and for an
    unknown group the reasons of the unknown members are gathered.
    """
    first = invalid("I2I mismatch on endorsed.work")
    second = invalid("far node fails edge schema")

    assert reduce('AND', [valid("v"), first, second]).reason == first.reason
    assert reduce('OR', [invalid("i"), valid("carried by this one")]).reason == \
        "carried by this one"

    both = reduce('AND', [unknown("far node absent", retryable=True),
                          unknown("DI2I unimplemented", retryable=False)])
    assert "far node absent" in both.reason
    assert "DI2I unimplemented" in both.reason


def test_reduce_carries_the_deciding_members_causes():
    """A reduced verdict carries the caller's payload for the members that decided it.

    A reason is prose, and a disposition needs more than prose. When an Edge Section
    reduces to something other than valid, v1 has to raise the exception class the
    evidence produced -- ``EdgeRefusalError`` for a relation decided against,
    ``MissingChainError`` for a far node not yet in hand, ``MissingSchemaError`` for a
    pin not yet cached -- and, for the retryable ones, escrow the near ACDC and cue
    the query that would resolve it. Those are values the caller built while mapping
    its evidence, and the reduction is the only thing that knows which members
    survived to decide the group. So it carries them through.

    Opaque on purpose: this module holds no policy, and .causes is whatever the
    caller put there. It is a tuple rather than one value because a group's unknown
    genuinely has several contributing members, and a caller that escrows must cue
    every one of them or the ACDC waits forever on a query nobody sent.
    """
    proof = object()      # stands in for a caller's (exception, cue, escrow) record
    schema = object()
    revoked = object()

    assert valid("v").causes == ()
    assert invalid("i", cause=revoked).causes == (revoked,)
    assert unknown("u", retryable=True, cause=proof).causes == (proof,)

    # A decided group carries the deciding member's causes and no others: under AND
    # the first invalid member, under OR the first valid one. Anything else would
    # have the caller raise on account of a member the reduction did not use.
    V = valid("v")
    first = invalid("first failure", cause=revoked)
    second = invalid("second failure", cause=schema)
    assert reduce('AND', [V, first, second]).causes == (revoked,)
    assert reduce('OR', [first, V, second]).causes == ()

    # An unknown group gathers every unknown member's causes, in section order.
    # Cueing only the first would leave the other far node unqueried, so the escrow
    # would age out having asked for half of what it was waiting on.
    absent = unknown("far node absent", retryable=True, cause=proof)
    uncached = unknown("pin not cached", retryable=True, cause=schema)
    assert reduce('AND', [V, absent, uncached]).causes == (proof, schema)
    assert reduce('OR', [first, absent, uncached]).causes == (proof, schema)

    # An OR that is invalid was decided by all of its members together, so all of
    # their causes come through; there is no single one to name.
    assert reduce('OR', [first, second]).causes == (revoked, schema)

    # A member that carried no cause contributes none, and does not displace the
    # ones that did.
    assert reduce('AND', [unknown("bare", retryable=True), absent]).causes == (proof,)

    # Causes are additive to the existing shape, not a replacement for it: a verdict
    # spelled without one is unchanged.
    assert valid("far node issued") == EdgeVerdict(Verdicts.valid, True,
                                                  "far node issued", ())


def test_reduce_rejects_what_is_not_a_reduction():
    """An empty group and an unregistered operator are the caller's to refuse.

    An Edge-group with no members reduces to nothing: read as valid it would let an
    empty group satisfy an AND, and read as invalid it would make one refuse a
    section its Issuer wrote deliberately. Both stacks already treat an empty group
    as malformed, and malformed input aborts before any reduction runs rather than
    entering the lattice -- otherwise OR(satisfied, malformed) would accept, which
    is a well-formedness failure outvoted by a sibling.

    Likewise an operator this module does not reduce. Returning a verdict for one
    would be the silent substitution the branch's earlier commits exist to stop.
    """
    with pytest.raises(ValidationError):
        reduce('AND', [])

    with pytest.raises(ValidationError):
        reduce('NAND', [valid("v")])

    with pytest.raises(ValidationError):
        reduce('WAVG', [valid("v")])

    """End Test"""
