# -*- encoding: utf-8 -*-
"""
tests.acdc.test_edging module

Tests for keri.acdc.edging: the v2 Edge Section verifier over far nodes presented
alongside the ACDC that points at them.

Most rows build ACDCs with keripy's own acdcmap and judge them with a stub far-node
standing, because what they pin is the Operator algebra rather than registry
evidence. The registryStanding rows at the bottom use real Habs and real anchored
registry events, built the way tests/acdc/test_regeventing.py builds them.

The SEDI rows reproduce the edge shapes of Sam Smith's tests/sedi/test_sedi.py:
Core carries a `utahAgent` edge with operator I2I, and Residence a `coreIdentity`
edge with `o: ["E1E", "NI2I"]`. Sam's Core far node is a stand-in digest, so these
rows issue a real Utah agent credential to stand behind it.
"""

import pytest

from keri import kering
from keri import Vrsn_2_0
from keri.acdc import acdcmap, regcept, update, blindate
from keri.acdc import chaining, edging
from keri.acdc.chaining import Verdicts
from keri.app import habbing
from keri.core import Blinder, Salter
from keri.core.scheming import Schemer


# ---------------------------------------------------------------------------
# Material
# ---------------------------------------------------------------------------

_SIGNERS = Salter(raw=b'edgingtestsalt00').signers(count=6, transferable=False)
UTAH, SUE, GUY, GAL, PAT, EVE = (signer.verfer.qb64 for signer in _SIGNERS)
"""Six distinct AIDs. Non-transferable prefixes are enough here: the Operator rows
never read a KEL, and the rows that do use real Habs."""

STAMP0 = '2025-07-04T17:50:00.000000+00:00'
STAMP1 = '2025-08-01T18:06:10.988921+00:00'
STAMP2 = '2025-09-01T18:06:10.988921+00:00'
SALT = Salter(raw=b'0123456789abcdef').qb64


def _schemer(title, required=()):
    """A real, SAID-bearing JSON schema for an ACDC whose attribute section is an
    object, optionally requiring some attribute labels."""
    sed = {
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": title,
        "type": "object",
        "properties": {
            "a": {"type": "object",
                  "required": list(required)},
        },
    }
    return Schemer(sed=sed)


UTAH_AGENT_SCHEMA = _schemer("Utah agent", required=("agency",))
CORE_SCHEMA = _schemer("SEDI Core", required=("legalName",))
RESIDENCE_SCHEMA = _schemer("SEDI Residence", required=("residence",))
SCHEMAS = {schemer.said: schemer
           for schemer in (UTAH_AGENT_SCHEMA, CORE_SCHEMA, RESIDENCE_SCHEMA)}


def schemas(said):
    """The schema resolver every Operator row uses: a cache holding the three."""
    return SCHEMAS.get(said)


def acdc(issuer, *, issuee=None, schema=CORE_SCHEMA, edge=None, uuid=None,
         attrs=None):
    """An acm issued by issuer, targeted at issuee when given."""
    attribute = dict(d='', **(attrs if attrs is not None else {"legalName": "x"}))
    if issuee is not None:
        attribute["i"] = issuee
    return acdcmap(israid=issuer, schema=schema.said, attribute=attribute,
                   edge=edge, uuid=uuid)


def edge(far, *, op="__absent__", schema="__absent__", label="link", **extra):
    """An Edge Section with one Edge named label pointing at far."""
    block = dict(n=far if isinstance(far, str) else far.said)
    if schema != "__absent__":
        block["s"] = schema
    if op != "__absent__":
        block["o"] = op
    block.update(extra)
    return {label: block}


def nodes(*serders):
    """The far nodes presented alongside, keyed by SAID."""
    return {serder.said: serder for serder in serders}


class Standing:
    """A far-node standing stub that records who was asked.

    Returns valid unless the far node's SAID was named in `verdicts`.
    """

    def __init__(self, **verdicts):
        self.verdicts = verdicts
        self.asked = []

    def __call__(self, serder):
        self.asked.append(serder.said)
        return self.verdicts.get(serder.said,
                                 chaining.valid(f"stub says {serder.said} stands"))


def verify(near, *far, standing=None, **kwa):
    """verifyEdges with the defaults every Operator row shares."""
    return edging.verifyEdges(near, nodes=nodes(*far),
                              standing=standing if standing is not None else Standing(),
                              schemas=kwa.pop("schemas", schemas), **kwa)


# ---------------------------------------------------------------------------
# Sam's SEDI shapes
# ---------------------------------------------------------------------------

def sedi():
    """Utah agent -> Core -> Residence, shaped as test_sedi.py shapes them.

    The Utah agent credential is issued by the Utah root to Sue, so Core's I2I edge
    (near issuer Sue == far issuee Sue) holds. Residence's list-valued operator
    reads E1E (both issued to Guy) and NI2I (no issuer constraint).
    """
    utah = acdc(UTAH, issuee=SUE, schema=UTAH_AGENT_SCHEMA,
                attrs={"agency": "Department of Government Operations"})
    core = acdc(SUE, issuee=GUY, schema=CORE_SCHEMA,
                edge=dict(d='', u='', utahAgent=dict(d='', u='', n=utah.said,
                                                     s=UTAH_AGENT_SCHEMA.said,
                                                     o="I2I")))
    residence = acdc(SUE, issuee=GUY, schema=RESIDENCE_SCHEMA,
                     attrs={"residence": "Cedar City"},
                     edge=dict(d='', u='', coreIdentity=dict(d='', u='', n=core.said,
                                                             s=CORE_SCHEMA.said,
                                                             o=["E1E", "NI2I"])))
    return utah, core, residence


def test_sams_core_verifies_with_its_utah_agent_far_node():
    utah, core, _ = sedi()
    standing = Standing()
    verdict = verify(core, utah, standing=standing)
    assert verdict.verdict == Verdicts.valid
    assert standing.asked == [utah.said]  # the far node's own standing was consulted


def test_sams_residence_walks_core_and_its_utah_agent():
    utah, core, residence = sedi()
    standing = Standing()
    verdict = verify(residence, core, utah, standing=standing)
    assert verdict.verdict == Verdicts.valid
    assert sorted(standing.asked) == sorted([core.said, utah.said])


def test_sams_residence_without_the_core_far_node_is_undecided_and_retryable():
    utah, core, residence = sedi()
    verdict = verify(residence, utah)
    assert verdict.verdict == Verdicts.unknown
    assert verdict.retryable
    assert edging.FarNodeAbsent(core.said) in verdict.causes


def test_sams_residence_with_core_but_not_utah_is_undecided_one_level_down():
    """The chain is walked, not just the first hop: Core's own edge needs Utah."""
    utah, core, residence = sedi()
    verdict = verify(residence, core)
    assert verdict.verdict == Verdicts.unknown
    assert verdict.retryable
    assert verdict.causes == (edging.FarNodeAbsent(utah.said),)


def test_a_revoked_far_node_refuses_the_edge_and_carries_its_cause():
    utah, core, _ = sedi()
    cause = object()
    standing = Standing(**{utah.said: chaining.invalid("revoked", cause=cause)})
    verdict = verify(core, utah, standing=standing)
    assert verdict.verdict == Verdicts.invalid
    assert verdict.causes == (cause,)


def test_a_revoked_core_refuses_residence_through_the_chain():
    utah, core, residence = sedi()
    standing = Standing(**{core.said: chaining.invalid("revoked")})
    assert verify(residence, core, utah, standing=standing).verdict == Verdicts.invalid


def test_i2i_refuses_a_far_node_issued_to_somebody_other_than_the_near_issuer():
    """Core's I2I: the Utah agent credential must be issued TO Sue."""
    utah = acdc(UTAH, issuee=PAT, schema=UTAH_AGENT_SCHEMA, attrs={"agency": "x"})
    core = acdc(SUE, issuee=GUY, edge=edge(utah, op="I2I"))
    verdict = verify(core, utah)
    assert verdict.verdict == Verdicts.invalid
    assert "I2I" in verdict.reason


def test_i2i_refuses_an_untargeted_far_node():
    utah = acdc(UTAH, schema=UTAH_AGENT_SCHEMA, attrs={"agency": "x"})
    core = acdc(SUE, issuee=GUY, edge=edge(utah, op="I2I"))
    verdict = verify(core, utah)
    assert verdict.verdict == Verdicts.invalid
    assert "no issuee" in verdict.reason


def test_e1e_refuses_a_core_issued_to_a_different_aid():
    """Residence's E1E: Gal's Residence cannot rest on Guy's Core."""
    utah, core, _ = sedi()
    galResidence = acdc(SUE, issuee=GAL, schema=RESIDENCE_SCHEMA,
                        attrs={"residence": "x"},
                        edge=edge(core, op=["E1E", "NI2I"], schema=CORE_SCHEMA.said))
    verdict = verify(galResidence, core, utah)
    assert verdict.verdict == Verdicts.invalid
    assert "E1E" in verdict.reason


def test_e1e_refuses_an_untargeted_near_node():
    far = acdc(SUE, issuee=GUY)
    near = acdc(PAT, edge=edge(far, op="E1E"))
    assert verify(near, far).verdict == Verdicts.invalid


# ---------------------------------------------------------------------------
# The unary Operator list and the default rule
# ---------------------------------------------------------------------------

def test_ni2i_places_no_constraint_on_the_issuer():
    far = acdc(SUE, issuee=GUY)
    near = acdc(PAT, issuee=EVE, edge=edge(far, op="NI2I"))
    assert verify(near, far).verdict == Verdicts.valid


def test_a_bare_edge_to_a_targeted_far_node_defaults_to_i2i():
    far = acdc(SUE, issuee=GUY)
    assert verify(acdc(PAT, edge=edge(far)), far).verdict == Verdicts.invalid
    assert verify(acdc(GUY, edge=edge(far)), far).verdict == Verdicts.valid


def test_a_bare_edge_to_an_untargeted_far_node_defaults_to_ni2i():
    far = acdc(SUE)
    assert verify(acdc(PAT, edge=edge(far)), far).verdict == Verdicts.valid


def test_an_empty_operator_list_takes_the_default():
    far = acdc(SUE, issuee=GUY)
    assert verify(acdc(PAT, edge=edge(far, op=[])), far).verdict == Verdicts.invalid


def test_e1e_alone_suppresses_the_default():
    """E1E is in the spec's default-suppressing list, so E1E alone adds no I2I."""
    far = acdc(SUE, issuee=GUY)
    near = acdc(PAT, issuee=GUY, edge=edge(far, op="E1E"))
    assert verify(near, far).verdict == Verdicts.valid


def test_the_latest_delegative_operator_wins_and_e1e_composes_with_it():
    far = acdc(SUE, issuee=GUY)
    near = acdc(PAT, issuee=GUY, edge=edge(far, op=["NI2I", "I2I"]))
    assert verify(near, far).verdict == Verdicts.invalid  # I2I wins, PAT != GUY
    near = acdc(PAT, issuee=GUY, edge=edge(far, op=["I2I", "E1E", "NI2I"]))
    assert verify(near, far).verdict == Verdicts.valid    # NI2I wins, E1E holds
    near = acdc(PAT, issuee=EVE, edge=edge(far, op=["I2I", "E1E", "NI2I"]))
    assert verify(near, far).verdict == Verdicts.invalid  # E1E still binds


def test_an_unrecognized_operator_is_undecided_for_good():
    far = acdc(SUE, issuee=GUY)
    verdict = verify(acdc(GUY, edge=edge(far, op=["I2I", "XYZ"])), far)
    assert verdict.verdict == Verdicts.unknown
    assert not verdict.retryable
    assert "XYZ" in verdict.reason


def test_an_unrecognized_operator_stays_unretryable_when_its_far_node_is_absent():
    """Presenting the far node could never make an unreadable Operator hold, so the
    absence does not get to advertise a retry."""
    far = acdc(SUE, issuee=GUY)
    verdict = verify(acdc(GUY, edge=edge(far, op="XYZ")))
    assert verdict.verdict == Verdicts.unknown
    assert not verdict.retryable


def test_an_operator_that_is_neither_string_nor_list_is_malformed():
    far = acdc(SUE, issuee=GUY)
    with pytest.raises(edging.EdgeShapeError):
        verify(acdc(GUY, edge=edge(far, op=7)), far)


# ---------------------------------------------------------------------------
# NOT and DI2I
# ---------------------------------------------------------------------------

def test_not_inverts_the_far_nodes_validity():
    far = acdc(SUE)
    near = acdc(PAT, edge=edge(far, op="NOT"))
    assert verify(near, far).verdict == Verdicts.invalid
    revoked = Standing(**{far.said: chaining.invalid("revoked")})
    assert verify(near, far, standing=revoked).verdict == Verdicts.valid


def test_not_cannot_be_satisfied_by_withholding_the_far_node():
    """Kleene negation of unknown is unknown, so a withheld far node leaves the edge
    undecided rather than satisfied."""
    far = acdc(SUE)
    verdict = verify(acdc(PAT, edge=edge(far, op="NOT")))
    assert verdict.verdict == Verdicts.unknown
    undecided = Standing(**{far.said: chaining.unknown("x", retryable=True)})
    assert verify(acdc(PAT, edge=edge(far, op="NOT")), far,
                  standing=undecided).verdict == Verdicts.unknown


def test_not_leaves_the_relation_and_the_pins_in_force():
    """NOT inverts the far node, not the Operator relation: the default I2I still
    applies to a targeted far node, and a failed relation is not rescued."""
    far = acdc(SUE, issuee=GUY)
    revoked = Standing(**{far.said: chaining.invalid("revoked")})
    assert verify(acdc(PAT, edge=edge(far, op="NOT")), far,
                  standing=revoked).verdict == Verdicts.invalid
    assert verify(acdc(GUY, edge=edge(far, op="NOT")), far,
                  standing=revoked).verdict == Verdicts.valid


def test_di2i_accepts_the_issuee_itself_or_any_delegate_of_it():
    far = acdc(UTAH, issuee=SUE)
    chain = {PAT: SUE, EVE: PAT}  # PAT is SUE's delegate, EVE is PAT's
    delegators = chain.get
    for issuer in (SUE, PAT, EVE):
        near = acdc(issuer, edge=edge(far, op="DI2I"))
        assert verify(near, far, delegators=delegators).verdict == Verdicts.valid
    near = acdc(GUY, edge=edge(far, op="DI2I"))
    assert verify(near, far, delegators=delegators).verdict == Verdicts.invalid


def test_di2i_refuses_an_untargeted_far_node():
    far = acdc(UTAH)
    near = acdc(SUE, edge=edge(far, op="DI2I"))
    assert verify(near, far, delegators={}.get).verdict == Verdicts.invalid


def test_di2i_survives_a_delegation_cycle_in_the_resolver():
    far = acdc(UTAH, issuee=SUE)
    near = acdc(PAT, edge=edge(far, op="DI2I"))
    looped = {PAT: EVE, EVE: PAT}.get
    assert verify(near, far, delegators=looped).verdict == Verdicts.invalid


def test_di2i_without_a_resolver_is_undecided_for_good():
    far = acdc(UTAH, issuee=SUE)
    verdict = verify(acdc(PAT, edge=edge(far, op="DI2I")), far)
    assert verdict.verdict == Verdicts.unknown
    assert not verdict.retryable


# ---------------------------------------------------------------------------
# Schema pins
# ---------------------------------------------------------------------------

def test_a_pin_the_far_node_does_not_satisfy_refuses_the_edge():
    far = acdc(SUE, issuee=GUY, schema=CORE_SCHEMA)
    near = acdc(GUY, edge=edge(far, schema=UTAH_AGENT_SCHEMA.said))
    verdict = verify(near, far)
    assert verdict.verdict == Verdicts.invalid
    assert "does not satisfy" in verdict.reason


def test_a_pin_is_checked_even_when_it_names_the_far_nodes_own_schema():
    """The far node declaring its own type is exactly what a pin must not take on
    trust: a Core whose attributes do not fit the Core schema fails its pin."""
    far = acdc(SUE, issuee=GUY, schema=CORE_SCHEMA, attrs={"notLegalName": "x"})
    near = acdc(GUY, edge=edge(far, schema=CORE_SCHEMA.said))
    assert verify(near, far).verdict == Verdicts.invalid


def test_a_pin_not_in_cache_is_undecided_and_retryable():
    far = acdc(SUE, issuee=GUY)
    near = acdc(GUY, edge=edge(far, schema=CORE_SCHEMA.said))
    verdict = verify(near, far, schemas=lambda said: None)
    assert verdict.verdict == Verdicts.unknown
    assert verdict.retryable


def test_a_pin_with_no_schema_resolver_is_undecided_and_retryable():
    far = acdc(SUE, issuee=GUY)
    near = acdc(GUY, edge=edge(far, schema=CORE_SCHEMA.said))
    verdict = edging.verifyEdges(near, nodes=nodes(far), standing=Standing())
    assert verdict.verdict == Verdicts.unknown
    assert verdict.retryable


def test_an_inline_pin_is_rederived_before_it_is_believed():
    far = acdc(SUE, issuee=GUY)
    good = dict(CORE_SCHEMA.sed)
    assert verify(acdc(GUY, edge=edge(far, schema=good)), far).verdict == Verdicts.valid
    lying = dict(good, title="something else")
    with pytest.raises(edging.EdgeShapeError):
        verify(acdc(GUY, edge=edge(far, schema=lying)), far)
    with pytest.raises(edging.EdgeShapeError):
        verify(acdc(GUY, edge=edge(far, schema={"title": "no id"})), far)
    with pytest.raises(edging.EdgeShapeError):
        verify(acdc(GUY, edge=edge(far, schema={"$id": "Enot", "type": 5})), far)
    with pytest.raises(edging.EdgeShapeError):
        verify(acdc(GUY, edge=edge(far, schema=12)), far)


def test_a_far_node_carrying_its_schema_inline_is_checked_against_it():
    inline = acdcmap(israid=SUE, schema=dict(CORE_SCHEMA.sed),
                     attribute=dict(d='', i=GUY, legalName="x"))
    near = acdc(GUY, edge=edge(inline, schema=CORE_SCHEMA.said))
    assert verify(near, inline, schemas=lambda said: None).verdict == Verdicts.valid


def test_a_group_pin_is_a_floor_its_members_cannot_lower():
    far = acdc(SUE, issuee=GUY, schema=CORE_SCHEMA)
    section = dict(d='', grp=dict(d='', s=UTAH_AGENT_SCHEMA.said,
                                  link=dict(n=far.said, s=CORE_SCHEMA.said)))
    assert verify(acdc(GUY, edge=section), far).verdict == Verdicts.invalid
    section = dict(d='', s=CORE_SCHEMA.said, link=dict(n=far.said))
    assert verify(acdc(GUY, edge=section), far).verdict == Verdicts.valid


# ---------------------------------------------------------------------------
# Edge-groups
# ---------------------------------------------------------------------------

def test_or_is_carried_by_one_valid_member_even_when_another_is_withheld():
    good = acdc(SUE, issuee=GUY, uuid='aGoodGoodGoodGoodGoodGoodGoodGoodGoodGoodGood')
    gone = acdc(SUE, issuee=GUY, uuid='aGoneGoneGoneGoneGoneGoneGoneGoneGoneGoneGone')
    section = dict(d='', o="OR", a=dict(n=good.said), b=dict(n=gone.said))
    assert verify(acdc(GUY, edge=section), good).verdict == Verdicts.valid
    section = dict(d='', a=dict(n=good.said), b=dict(n=gone.said))  # AND by default
    verdict = verify(acdc(GUY, edge=section), good)
    assert verdict.verdict == Verdicts.unknown and verdict.retryable


def test_an_operator_the_verifier_does_not_reduce_is_undecided_for_good():
    far = acdc(SUE, issuee=GUY)
    section = dict(d='', grp=dict(d='', o="NAND", link=dict(n=far.said)))
    verdict = verify(acdc(GUY, edge=section), far)
    assert verdict.verdict == Verdicts.unknown and not verdict.retryable


def test_a_compact_edge_member_is_undecided_for_good():
    far = acdc(SUE, issuee=GUY)
    section = dict(d='', o="OR", link=dict(n=far.said), hidden=far.said)
    assert verify(acdc(GUY, edge=section), far).verdict == Verdicts.valid
    section = dict(d='', hidden=far.said)
    verdict = verify(acdc(GUY, edge=section), far)
    assert verdict.verdict == Verdicts.unknown and not verdict.retryable


def test_a_compact_edge_section_is_undecided_for_good():
    far = acdc(SUE, issuee=GUY)
    near = acdcmap(israid=GUY, schema=CORE_SCHEMA.said,
                   attribute=dict(d='', legalName="x"), edge=dict(d='', **edge(far)),
                   compactify=True)
    assert isinstance(near.sad["e"], str)
    verdict = verify(near, far)
    assert verdict.verdict == Verdicts.unknown and not verdict.retryable


def test_a_list_of_edge_blocks_is_one_conjunction():
    a = acdc(SUE, issuee=GUY, uuid='aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    b = acdc(SUE, issuee=PAT, uuid='aBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB')
    near = acdc(GUY)
    sad = dict(near.sad)
    sad["e"] = [dict(n=a.said), dict(d='', link=dict(n=b.said))]
    from keri.core import SerderACDC
    listed = SerderACDC(sad=dict(sad, d=''), makify=True)
    assert verify(listed, a, b).verdict == Verdicts.invalid  # b is PAT's, GUY issued
    sad["e"] = [dict(n=a.said)]
    assert verify(SerderACDC(sad=dict(sad, d=''), makify=True), a).verdict == Verdicts.valid


def test_no_edges_is_valid_and_asks_nothing():
    standing = Standing()
    assert verify(acdc(GUY), standing=standing).verdict == Verdicts.valid
    assert standing.asked == []


def test_a_far_node_named_twice_is_judged_once():
    far = acdc(SUE, issuee=GUY)
    section = dict(d='', a=dict(n=far.said), b=dict(n=far.said, o="NI2I"))
    standing = Standing()
    assert verify(acdc(GUY, edge=section), far, standing=standing).verdict == Verdicts.valid
    assert standing.asked == [far.said]


def test_di2i_gives_up_past_the_delegation_depth():
    far = acdc(UTAH, issuee=SUE)
    depth = edging.DelegationDepth
    chain = {f"aid{k}": f"aid{k + 1}" for k in range(depth + 2)}
    chain[f"aid{depth + 2}"] = SUE
    near = acdc(PAT, edge=edge(far, op="DI2I"))
    chain[PAT] = "aid0"
    assert verify(near, far, delegators=chain.get).verdict == Verdicts.invalid
    shallow = {PAT: "aid0", "aid0": SUE}
    assert verify(near, far, delegators=shallow.get).verdict == Verdicts.valid


# ---------------------------------------------------------------------------
# Malformed shapes raise, whatever the Operators would have said
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", [
    dict(d='', link=dict(n="E" + "A" * 43, zz=1)),         # unknown Edge label
    dict(d='', link=dict(n=7)),                            # n not a string
    dict(d='', u=dict(d='', n="E" + "A" * 43, o="I2I")),   # an edge hiding in u
    dict(d=dict(n="E" + "A" * 43)),                        # or in d
    dict(d='', grp=dict(d='', o=["AND"], link=dict(n="E" + "A" * 43))),  # group o list
    dict(d='', grp=dict(d='')),                            # empty group
    dict(d='', link=7),                                    # member neither map nor SAID
])
def test_a_malformed_section_raises(section):
    near = acdc(GUY, edge=section)
    with pytest.raises(edging.EdgeShapeError):
        verify(near)


def test_an_edge_section_of_the_wrong_type_raises():
    near = acdc(GUY)
    sad = dict(near.sad)
    sad["e"] = [1, 2]
    from keri.core import SerderACDC
    with pytest.raises(edging.EdgeShapeError):
        verify(SerderACDC(sad=dict(sad, d=''), makify=True))


def test_a_node_table_keyed_by_the_wrong_said_raises():
    far = acdc(SUE, issuee=GUY)
    with pytest.raises(edging.EdgeShapeError):
        edging.verifyEdges(acdc(GUY, edge=edge(far)), nodes={"Ewrong": far},
                           standing=Standing(), schemas=schemas)


# ---------------------------------------------------------------------------
# reach: which presented far nodes the near ACDC actually rests on
# ---------------------------------------------------------------------------

def test_reach_follows_the_chain_through_presented_nodes_only():
    utah, core, residence = sedi()
    stray = acdc(PAT, issuee=EVE)
    assert edging.reach(residence, nodes(core, utah, stray)) == (core.said, utah.said)
    assert edging.reach(residence, nodes(utah)) == ()  # Core withheld: Utah unreachable
    assert edging.reach(acdc(GUY), nodes(utah)) == ()


def test_reach_refuses_a_malformed_section():
    with pytest.raises(edging.EdgeShapeError):
        edging.reach(acdc(GUY, edge=dict(d='', link=7)), {})
    with pytest.raises(edging.EdgeShapeError):
        edging.reach(acdc(GUY, edge=dict(d='', link=dict(n=7))), {})


# ---------------------------------------------------------------------------
# registryStanding: a far node's v2 registry state as a verdict
# ---------------------------------------------------------------------------

def seal(serder):
    return dict(s=serder.sad['n'], d=serder.said)


def openIssuer(name):
    return habbing.openHab(name=name, temp=True, version=Vrsn_2_0)


def test_an_issued_far_node_stands():
    with openIssuer("rs-issued") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        upd = update(regid=rip.said, prior=rip.said, acdc=far.said, state="issued",
                     sn=1, stamp=STAMP1)
        hab.interact(data=[seal(upd)])
        verdict = edging.registryStanding(far, rip, [upd], db=hby.db)
        assert verdict.verdict == Verdicts.valid
        record, = verdict.causes
        assert record.state == "issued" and record.regid == rip.said


def test_a_revoked_far_node_does_not_stand():
    with openIssuer("rs-revoked") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        upd1 = update(regid=rip.said, prior=rip.said, acdc=far.said, state="issued",
                      sn=1, stamp=STAMP1)
        upd2 = update(regid=rip.said, prior=upd1.said, acdc=far.said, state="revoked",
                      sn=2, stamp=STAMP2)
        hab.interact(data=[seal(upd1), seal(upd2)])
        verdict = edging.registryStanding(far, rip, [upd1, upd2], db=hby.db)
        assert verdict.verdict == Verdicts.invalid
        assert verdict.causes[0].state == "revoked"


def test_a_state_outside_the_vocabulary_is_undecided_for_good():
    with openIssuer("rs-other") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        upd = update(regid=rip.said, prior=rip.said, acdc=far.said, state="suspended",
                     sn=1, stamp=STAMP1)
        hab.interact(data=[seal(upd)])
        verdict = edging.registryStanding(far, rip, [upd], db=hby.db)
        assert verdict.verdict == Verdicts.unknown and not verdict.retryable
        custom = edging.registryStanding(far, rip, [upd], db=hby.db,
                                         accepted=("issued", "suspended"))
        assert custom.verdict == Verdicts.valid


def test_a_blinded_head_stands_on_its_disclosure():
    with openIssuer("rs-blind") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        blinder = Blinder.blind(acdc=far.said, state="issued", salt=SALT, sn=1)
        bup = blindate(regid=rip.said, prior=rip.said, blid=blinder.said, sn=1,
                       stamp=STAMP1)
        hab.interact(data=[seal(bup)])
        verdict = edging.registryStanding(far, rip, [bup], db=hby.db, blinder=blinder)
        assert verdict.verdict == Verdicts.valid
        blind = edging.registryStanding(far, rip, [bup], db=hby.db)
        assert blind.verdict == Verdicts.invalid
        assert isinstance(blind.causes[0], kering.UnverifiedBlindError)


def test_a_registry_that_states_nothing_is_undecided_for_good():
    with openIssuer("rs-empty") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        upd = update(regid=rip.said, prior=rip.said, acdc=far.said, state="",
                     sn=1, stamp=STAMP1)
        hab.interact(data=[seal(upd)])
        verdict = edging.registryStanding(far, rip, [upd], db=hby.db)
        assert verdict.verdict == Verdicts.unknown and not verdict.retryable


def test_an_unanchored_update_is_undecided_and_retryable():
    with openIssuer("rs-unanchored") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        upd = update(regid=rip.said, prior=rip.said, acdc=far.said, state="issued",
                     sn=1, stamp=STAMP1)  # never anchored
        verdict = edging.registryStanding(far, rip, [upd], db=hby.db)
        assert verdict.verdict == Verdicts.unknown and verdict.retryable
        assert isinstance(verdict.causes[0], kering.MissingAnchorError)


def test_evidence_that_binds_a_different_acdc_does_not_stand():
    with openIssuer("rs-misbound") as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[seal(rip)])
        far = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="x"))
        other = acdcmap(israid=hab.pre, regid=rip.said, attribute=dict(d='', name="y"))
        upd = update(regid=rip.said, prior=rip.said, acdc=other.said, state="issued",
                     sn=1, stamp=STAMP1)
        hab.interact(data=[seal(upd)])
        verdict = edging.registryStanding(far, rip, [upd], db=hby.db)
        assert verdict.verdict == Verdicts.invalid
        assert isinstance(verdict.causes[0], kering.MisbindingError)


def test_registry_evidence_that_does_not_parse_does_not_stand():
    with openIssuer("rs-garbage") as (hby, hab):
        far = acdcmap(israid=hab.pre, attribute=dict(d='', name="x"))
        verdict = edging.registryStanding(far, b"not a registry event", [], db=hby.db)
        assert verdict.verdict == Verdicts.invalid
