# -*- coding: utf-8 -*-
"""
tests.acdc.test_bulk_issuance module

Worked, working example of *bulk-issued private ACDCs* (ACDC spec section 15.4,
"Bulk-Issued Private ACDCs") used to defeat cross-verifier correlation for SEDI
(Utah's State-Endorsed Digital Identity, Utah Code 63A-20). It is a sibling to
tests/acdc/test_clc_disclosure.py (contractually-protected disclosure) and
tests/acdc/test_guardianship_presentation.py (represented presentation), and it
adds the one axis neither shows: IDENTIFIER-level cross-verifier unlinkability.

The problem, from keripy discussion #1515. The sibling examples achieve ATTRIBUTE
minimization (reveal "over 21", hide the birthdate) but still hand every verifier a
STANDING identifier -- the source credential's SAID, its registry SAID, and any
standing edge whose 'n' points at a stable core sedi-id. Two verifiers who each
receive a presentation can compare notes and JOIN on that shared SAID, and that
holds whether the edge is labeled E1E, I2I, or nothing at all. That join key
undercuts SEDI's partition claim ("multiple breaches across multiple agencies would
be required to leak everything"). Selective disclosure does not touch it.

The answer, from the ACDC spec (section 15.4) and Sam Smith's reply in #1515:
BULK ISSUANCE. The Issuer mints a SET of M semantically-identical copies of a
credential, each with a unique SAID, generated on demand from one shared salt plus a
template -- no per-copy storage. The public commitment is a BLINDED AGGREGATE 'B'
(below), so the real SAIDs stay hidden. The holder spends a DIFFERENT copy per
verifier, so each presentation context (discloser + disclosee) gets its own set of
SEDI credentials and standing edges. The contexts form a partition of the set of
correlatable identifiers, including edges: no standing SAID is a join key across
contexts. The State of Utah has indicated it intends to use bulk-issued ACDCs for
SEDI.

Scenario. Alice, a Utah resident over 21, proves "over 21" at a wide fan-out of
mutually-unrelated verifiers -- a bar, a cannabis dispensary, an online sportsbook.
The State/DGO bulk-issues her BOTH source credentials: a set of sedi-id copies (the
core identity) and a set of sedi-age copies (the aggregate age flags), index-aligned
so copy k of sedi-age carries an E1E identity edge to copy k of sedi-id. Alice spends
copy k at verifier k. Two verifiers therefore hold DISJOINT sets of SAIDs and edges
and cannot join, yet each still cryptographically verifies "over 21: true" as the
State's endorsement. This is the E1E standing edge (added in PR #1523/#1527, the very
edge #1515 worried creates a join key) made SAFE by pointing it at a fresh,
per-context far node -- Daniel's own proposed mitigation in #1515, realized.

The privacy claim, scoped honestly (Sam's #1515 coda). Bulk issuance defeats
cryptographically PROVABLE third-party correlation via public SAIDs. It does not
claim perfect unlinkability against statistical/contextual correlation by colluding
verifiers (an AI "super correlator" defeats pure unlinkability eventually). Its value
is DECORRELATION-BY-ENFORCEMENT: a partitioned identifier set makes any downstream
reappearance of one context's identifiers prima facie evidence of a Utah 63A-20-701
data-loyalty violation -- granular provenance makes enforcement precise. The
independent-AID and independent-registry variants (spec 15.4) raise the technical bar
further and are a deliberate follow-on, not this example.

A note on altitude. Like the sibling examples, this one models the credential graph,
the bulk derivation, the blinded aggregate, and the registry state at the
data-structure level, built from the real v2 primitives in keri.core and
keri.acdc.messaging (Salter.stretch, Noncer, Diger, acdcmap/acdcagg, Aggor, Blinder,
blindate, exchange). It does not stand up a Habery/keystore. Every ACDC validates
against a real, purpose-authored JSON Schema (Draft 2020-12) from its first commit.
Actor AIDs and all bulk nonces are DERIVED from fixed salts so the example is
reproducible.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks
from keri.core import Salter, Noncer, Aggor, Mapper, Diger, Verfer, exchange
from keri.core.coring import MtrDex, NonceDex
from keri.core.eventing import incept
from keri.acdc import regcept, blindate, acdcmap, acdcagg
from keri.core.structing import Blinder


# --- Reproducible example actors (see module docstring). ---
# Five actors, each a self-addressing ('E') transferable AID: its prefix is the SAID
# of an inception event committing to the actor's current signing key and a digest of
# its pre-rotated next key. Ten signers from one fixed salt: _SIGNERS[0..4] are the
# five actors' current signing keys (State/DGO, Alice, and the three verifiers) and
# _SIGNERS[5..9] are their matching pre-rotated next keys.
_SIGNERS = Salter(raw=b'bulkworkexamsig0').signers(count=10, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


# STATE = Utah's digital-government office (the issuer of both bulk sets); ALICE is the
# adult holder (over 21); ALCOVE (a bar), DISPENSARY (cannabis), and SPORTSBOOK (an
# online sportsbook) are the mutually-unrelated verifiers she proves over-21 to.
STATE, ALICE, ALCOVE, DISPENSARY, SPORTSBOOK = (
    _actor_aid(_SIGNERS[i], _SIGNERS[i + 5]) for i in range(5))

# The three verifiers in spend order; Alice's wallet maps verifier -> copy index.
VERIFIERS = (ALCOVE, DISPENSARY, SPORTSBOOK)


# ===========================================================================
# Phase 1: the bulk-issuance derivation primitive (ACDC spec 15.4).
# ===========================================================================
# The shared secret salt for Alice's bulk sets -- known to the Issuer (State) and the
# Issuee (Alice), never handed to a verifier. In a real flow it is transported to Alice
# encrypted to her AID-derived X25519 key (keri.core Encrypter/Decrypter); here it is a
# fixed value so the example is reproducible.
BULK_SALT = b'bulkworkexamsalt'
# M: copies per bulk-issued set. Small for a readable example; a real deployment sizes M
# to the expected number of distinct verifier contexts (one copy spent per verifier).
BULK_SIZE = 5


class _BulkNonces:
    """Deterministic per-copy nonce derivation for a bulk-issued set (ACDC spec 15.4).

    Every nonce for every copy is derived from ONE shared secret salt by argon2id
    (Salter.stretch) at a hierarchical path keyed on the copy index k, then wrapped as a
    256-bit salty nonce (Noncer):

        path "k"    -> copy k's top-level ACDC uuid  u_k
        path "k/j"  -> copy k's nested block j uuid   (attribute section j=0, blocks j>=1)
        path "k."   -> copy k's BLINDING factor       v_k  (distinct from every u)

    The Issuer ships only (salt, template with empty u/d); the Issuee regenerates any
    copy on demand and stores neither the copies nor the nonces. temp=True selects the
    fast (test-only) argon2 parameters, matching how the sibling examples derive nonces.
    """

    def __init__(self, salt_raw):
        self._salter = Salter(raw=salt_raw)

    def _nonce(self, path):
        return Noncer(raw=self._salter.stretch(size=32, path=path, temp=True),
                      code=NonceDex.Salt_256).qb64

    def u(self, k, j=None):
        """Copy k's uuid: the top-level ACDC uuid (j is None) or nested block j's uuid."""
        return self._nonce(f"{k}" if j is None else f"{k}/{j}")

    def v(self, k):
        """Copy k's blinding factor v_k, derived at the distinct path "k." (spec 15.4)."""
        return self._nonce(f"{k}.")


def _blind_said(v, d):
    """b_k = H(v_k + d_k): the blinded commitment to copy k's SAID (spec 15.4).

    Concatenation (not XOR) because CESR crypto-agility means SAIDs and nonces are
    variable length. A commitment to b_k discloses nothing about d_k until v_k is
    revealed, so the list of b_k can be published while the SAIDs stay hidden.
    """
    return Diger(ser=(v + d).encode()).qb64


def _bulk_aggregate(vs, ds):
    """Return (blist, B): the ordered blinded-SAID list and the aggregate B = H(C(b_k)).

    B is the blinded issuance-proof digest: a single value committing to every member of
    the set. The Issuer anchors ONE commitment to B (a KEL seal, or the td of a shared
    blindable TEL -- Phase 2) to cover the whole set.
    """
    blist = [_blind_said(v, d) for v, d in zip(vs, ds)]
    B = Diger(ser="".join(blist).encode()).qb64
    return blist, B


def _verify_membership(d, v, blist, B):
    """The verifier's per-copy membership check (spec 15.4).

    Given the disclosed copy SAID d_k, its blinding factor v_k, the published blinded
    list [b_k], and the committed aggregate B, confirm (1) the list commits to B
    (recompute B over the list) and (2) copy k is a member (b_k = H(v_k + d_k) is in the
    list). Learns nothing about any other member. Returns True only if both hold.
    """
    if Diger(ser="".join(blist).encode()).qb64 != B:   # the list must commit to B
        return False
    return _blind_said(v, d) in blist                  # this copy is a member


def test_bulk_derivation_primitive_JSON():
    """Phase 1: derive a bulk set's per-copy nonces and its blinded aggregate 'B'.

    The whole set is generated on demand from ONE shared salt (no per-copy storage):
    for copy k, path "k" derives the top-level ACDC uuid u_k, path "k/j" derives nested
    block j's uuid, and the DISTINCT path "k." derives the blinding factor v_k (spec
    15.4: the blinding factor is deliberately NOT the ACDC's own 'u'). The public
    commitment blinds each copy's SAID -- b_k = H(v_k + d_k) -- and aggregates the
    blinded digests -- B = H(C(b_k for k)) -- so publishing the list [b_k] and B leaks
    no SAID until a v_k is unblinded. A verifier proves copy k belongs to the committed
    set from (d_k, v_k, [b_k], B) without learning any other member.

    Asserted here: the derivation is deterministic and its u/v spaces are disjoint; the
    aggregate is a stable, order-dependent commitment that leaks no SAID; each real copy
    verifies as a member; and a wrong blinding factor, a non-member SAID, a tampered
    list, or a wrong B all fail.
    """
    nonces = _BulkNonces(BULK_SALT)
    M = BULK_SIZE

    # Per-copy top-level uuids and blinding factors, all from one salt.
    us = [nonces.u(k) for k in range(M)]
    vs = [nonces.v(k) for k in range(M)]

    # Determinism: same salt + index regenerates the identical nonce (Issuer and Issuee
    # each regenerate the set independently -- neither stores it).
    assert [_BulkNonces(BULK_SALT).u(k) for k in range(M)] == us
    assert [_BulkNonces(BULK_SALT).v(k) for k in range(M)] == vs
    # Uniqueness: every u_k distinct, every v_k distinct, and the blinding path "k."
    # never collides with the uuid path "k" -- the u and v spaces are disjoint.
    assert len(set(us)) == M and len(set(vs)) == M
    assert not (set(us) & set(vs))

    # Stand-in copy SAIDs d_k (Phase 2 wires REAL sedi-id SAIDs here); the aggregate math
    # is identical whatever produced d_k.
    ds = [Diger(ser=(us[k] + f"copy{k}").encode()).qb64 for k in range(M)]

    blist, B = _bulk_aggregate(vs, ds)
    # B is a stable, order-dependent commitment to every member.
    assert _bulk_aggregate(vs, ds) == (blist, B)
    # Publishing the blinded list leaks NO SAID: no d_k appears anywhere in it.
    joined = "".join(blist)
    assert all(d not in joined for d in ds)

    # Membership: each real copy verifies against the committed set...
    for k in range(M):
        assert _verify_membership(ds[k], vs[k], blist, B)
    # ...a wrong blinding factor (v of another copy) fails...
    assert not _verify_membership(ds[0], vs[1], blist, B)
    # ...a non-member SAID fails...
    assert not _verify_membership(Diger(ser=b'not-a-member').qb64, vs[0], blist, B)
    # ...a tampered published list fails (recomputed B no longer matches)...
    assert not _verify_membership(ds[0], vs[0], [Diger(ser=b'x').qb64] + blist[1:], B)
    # ...and a wrong committed B fails.
    assert not _verify_membership(ds[0], vs[0], blist, Diger(ser=b'wrong-B').qb64)


# ===========================================================================
# Phase 2: the bulk sedi-id set + its shared blindable registry (keyed on B).
# ===========================================================================
# Schema helpers, ported verbatim in intent from the sibling SEDI examples
# (test_clc_disclosure.py / test_guardianship_presentation.py).
def _saidify_schema(mad, kind=Kinds.json):
    """Compute a JSON Schema's SAID and return (said, schema-with-$id). Mirrors the
    sibling examples: a Mapper self-addresses the '$id' field (which must be first)."""
    mapper = Mapper(mad=mad, makify=True, strict=False, saids={"$id": 'E'},
                    saidive=True, kind=kind)
    return mapper.said, mapper.mad


def assert_acdc_schema_valid(acdc, schema=None):
    """Validate a worked-example ACDC against its JSON Schema (Draft 2020-12)."""
    if schema is None:
        schema = acdc.sad['s']
        if not isinstance(schema, dict):
            raise ValueError("schema section is compacted to a SAID; pass schema=")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(acdc.sad)
    return schema


def _disclosable_block(attr, attr_schema, desc):
    """One partially-disclosable block schema: oneOf(block SAID, block detail)."""
    return {
        "description": f"{desc} block",
        "oneOf": [
            {"description": f"{desc} block SAID", "type": "string"},
            {"description": f"{desc} block detail", "type": "object",
             "required": ["d", "u", attr],
             "properties": {"d": {"description": "Block SAID", "type": "string"},
                            "u": {"description": "Block UUID", "type": "string"},
                            attr: attr_schema},
             "additionalProperties": False},
        ],
    }


# acm/acg always carry (possibly empty) e and r sections, so the schema must admit them.
_EMPTY_OR_SECTION = {"oneOf": [{"type": "string"}, {"type": "object"}]}

# sedi-id: the holder's ATTRIBUTIVE ('acm') core identity credential. Every bulk copy
# shares this schema (a public, non-correlating identifier -- see the module docstring's
# partition classification). The issuee 'i' is the per-copy holder AID ALICE_k.
SEDI_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Identity Credential",
    "description": "State-endorsed SEDI digital-identity credential; attributes carried "
                   "as individually partially-disclosable nested blocks.",
    "credentialType": "SEDI_Identity",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (State/DGO) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {
            "description": "Attribute section with individually-disclosable blocks",
            "oneOf": [
                {"description": "Attribute Section SAID", "type": "string"},
                {"description": "Attribute detail",
                 "type": "object",
                 "required": ["d", "u", "i", "photo", "dob", "residence", "name"],
                 "properties": {
                     "d": {"description": "Section SAID", "type": "string"},
                     "u": {"description": "Section UUID", "type": "string"},
                     "i": {"description": "Issuee (the holder) AID", "type": "string"},
                     "photo": _disclosable_block("photo",
                         {"description": "State-endorsed photo", "type": "string"},
                         "Photo"),
                     "dob": _disclosable_block("dob",
                         {"description": "Date of birth", "type": "string",
                          "format": "date"}, "DOB"),
                     "residence": _disclosable_block("residence",
                         {"description": "Residence", "type": "string"}, "Residence"),
                     "name": _disclosable_block("name",
                         {"description": "Full name", "type": "string"}, "Name"),
                 },
                 "additionalProperties": False},
            ],
        },
        "e": _EMPTY_OR_SECTION,
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}


# --- Per-copy holder AIDs (the independent-AID variant). ---
# The DOMINANT correlator a basic (shared-AID) bulk issuance would leave is the holder
# AID itself (Sam, issue #1532: "we need bulk issuance because then one has a unique AID
# per context"). So each copy k is issued to its OWN holder AID ALICE_k, derived from a
# HOLDER-ONLY secret salt the issuer never sees -- the holder supplies the public AIDs
# and the issuer commits to AIDs it cannot forge. 2*M signers: ALICE_k's current key is
# _HOLDER_SIGNERS[k], its pre-rotated next key _HOLDER_SIGNERS[M+k].
_HOLDER_SIGNERS = Salter(raw=b'bulkaliceseckey0').signers(count=2 * BULK_SIZE,
                                                          transferable=True, temp=True)
ALICES = [_actor_aid(_HOLDER_SIGNERS[k], _HOLDER_SIGNERS[BULK_SIZE + k])
          for k in range(BULK_SIZE)]

# The sedi-id set's ONE shared blindable registry, its blinding salt (shared issuer <->
# holder, never handed to a verifier), and the states its update events can carry.
REG_ID_UUID = Noncer(raw=b'bulkidreguuid000').qb64
REG_ID_STAMP = "2026-01-05T12:00:00.000000+00:00"
ISSUE_ID_STAMP = "2026-01-05T12:05:00.000000+00:00"
BULK_ID_REG_SALT = Noncer(raw=b'bulkidregblindsl').qb64
SET_STATES = ['issued', 'revoked']

# Alice's identity attribute values -- the SAME across every copy (it is one Alice); only
# the per-copy blinding nonces differ, so the copies are semantically identical but have
# unique SAIDs. DOB puts her well over 21 at the 2026 presentation.
ALICE_DOB = "2000-03-15"


def _sedi_id_attr(nonces, k):
    """Copy k's sedi-id attribute section (issuee inserted by acdcmap via iseaid).

    Per-copy blinding nonces come from the shared bulk salt at hierarchical paths keyed
    on k: the section uuid at "k/0" and one nested-block uuid per attribute at "k/1".."k/4".
    """
    return dict(d='', u=nonces.u(k, 0),
                photo=dict(d='', u=nonces.u(k, 1),
                           photo="<state-endorsed-photo-bytes>"),
                dob=dict(d='', u=nonces.u(k, 2), dob=ALICE_DOB),
                residence=dict(d='', u=nonces.u(k, 3),
                               residence="Salt Lake City UT"),
                name=dict(d='', u=nonces.u(k, 4), name="Alice Anders"))


def _sedi_id_set(kind, nonces=None):
    """Build the bulk sedi-id set and its shared blindable registry.

    Returns (reg, copies, blist, B, issued): the shared registry inception, the M sedi-id
    copies (each issued by STATE to its own per-context holder AID ALICE_k, all bound to
    the one registry), the published blinded list [b_k] and the aggregate B_id, and the
    blindable 'issued' update (bup) that commits the whole set (identified by B_id) as
    issued. The registry inception SAID (rd) is independent of B, so there is no circular
    dependency: copies bind rd, B is computed over the copy SAIDs, then the bup commits B.
    """
    if nonces is None:
        nonces = _BulkNonces(BULK_SALT)
    reg = regcept(israid=STATE, uuid=REG_ID_UUID, stamp=REG_ID_STAMP, kind=kind)
    _, schema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    copies = [acdcmap(israid=STATE, uuid=nonces.u(k), regid=reg.said, schema=schema,
                      attribute=_sedi_id_attr(nonces, k), iseaid=ALICES[k], kind=kind)
              for k in range(BULK_SIZE)]
    vs = [nonces.v(k) for k in range(BULK_SIZE)]
    ds = [c.said for c in copies]
    blist, B = _bulk_aggregate(vs, ds)
    # The single issuance-proof commitment to B (spec 15.4): a blindable update whose
    # blinded state binds "this set (identified by B) is issued". Reuses the existing
    # sn-keyed Blinder -- there is ONE shared registry per set, so no copy-index blinder
    # is needed. (A real Issuer also anchors the rip seal in its KEL; omitted at this
    # data-structure altitude, as the sibling examples omit KEL/Habery.)
    blinder = Blinder.blind(acdc=B, state='issued', salt=BULK_ID_REG_SALT, sn=1)
    issued = blindate(regid=reg.said, prior=reg.said, blid=blinder.said, sn=1,
                      stamp=ISSUE_ID_STAMP, kind=kind)
    return reg, copies, blist, B, issued


def test_bulk_sedi_id_set_JSON():
    """Phase 2: the State bulk-issues Alice's sedi-id as M private copies.

    Each copy is the SAME sedi-id (same attributes) with a UNIQUE SAID, issued to its OWN
    per-context holder AID ALICE_k -- the independent-AID variant (issue #1532), so the
    dominant correlator (the holder AID) is partitioned per context, not just the source
    SAIDs. All M copies bind ONE shared blindable registry, and a single blindable update
    commits the whole set (identified by the aggregate B_id) as issued -- one issuance
    event covering many credentials.

    Asserted: every copy is a schema-valid attributive sedi-id issued by STATE to a
    DISTINCT ALICE_k; copy SAIDs and top-level uuids are all distinct; each copy verifies
    as a member of the committed B_id and an outsider does not; and the registry update
    blinds the set state (neither the word 'issued' nor B_id crosses the wire) while the
    salt-holder can unblind it to 'issued'.
    """
    kind = Kinds.json
    nonces = _BulkNonces(BULK_SALT)
    reg, copies, blist, B, issued = _sedi_id_set(kind, nonces)

    assert len(copies) == BULK_SIZE
    for k, copy in enumerate(copies):
        assert copy.ilk == Ilks.acm
        assert copy.sad['i'] == STATE                 # issued by the State/DGO
        assert copy.sad['rd'] == reg.said             # all copies share ONE registry
        assert copy.sad['a']['i'] == ALICES[k]        # per-copy holder AID (independent-AID)
        assert copy.iseaid == ALICES[k]
        assert copy.sad['a']['dob']['dob'] == ALICE_DOB   # same Alice in every copy...
        assert_acdc_schema_valid(copy)

    # ...but every copy is cryptographically distinct: unique holder AID, SAID, and uuid.
    assert len(set(ALICES)) == BULK_SIZE                          # AID partitioned per context
    assert len({c.said for c in copies}) == BULK_SIZE            # unique copy SAIDs
    assert len({c.sad['u'] for c in copies}) == BULK_SIZE        # unique top-level uuids

    # Pinned reproducible values (derived, not pasted -- regenerate by printing on change).
    assert reg.said == "EJ1pXgiZJcpglJ_HYCXd9w1ETN4Wh5Op0y1bkdTJQIgB"   # shared id registry
    assert ALICES[0] == "EK4lOjo9f0WgCSnfI6hLjG9rsw_C5762GZf0TKJI612P"  # holder AID, context 0
    assert copies[0].said == "EPelN-PbE6nz-DnwGHaEtGSyp0C9o_PSuY0Nqn88aRsE"
    assert B == "EEeJA8dF4eoi9TRG0i9yfiLR9XGFQ3_9--Bee4vouJHk"          # blinded aggregate B_id

    # Membership: each copy verifies against the committed B_id; an outsider fails.
    for k, copy in enumerate(copies):
        assert _verify_membership(copy.said, nonces.v(k), blist, B)
    assert not _verify_membership(Diger(ser=b'outsider').qb64, nonces.v(0), blist, B)

    # The shared registry commits the whole set as 'issued' via a blindable update; the
    # state word and the aggregate B never appear on the wire, yet the salt-holder unblinds.
    assert issued.ilk == Ilks.bup
    assert issued.sad['b']                                       # blinded id present
    assert b"issued" not in issued.raw
    assert B.encode() not in issued.raw
    unblinded = Blinder.unblind(said=issued.sad['b'], acdc=B, states=SET_STATES,
                                salt=BULK_ID_REG_SALT, sn=1)
    assert unblinded.state == 'issued'


# ===========================================================================
# Phase 3: the bulk sedi-age set, index-aligned to sedi-id via an E1E edge.
# ===========================================================================
def _edge_schema(op_const, desc):
    """One edge schema whose operator is PINNED to a single value (const op_const)."""
    return {
        "oneOf": [
            {"type": "string"},
            {"type": "object", "required": ["d", "n", "o"],
             "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                            "n": {"description": f"{desc}: far node SAID",
                                  "type": "string"},
                            "s": {"description": "Far node schema SAID",
                                  "type": "string"},
                            "o": {"description": f"Edge operator ({desc})",
                                  "const": op_const}}}]}


# sedi-age: the holder's AGGREGATIVE ('acg') derived age credential -- a homogeneous
# boolean vector where hiding WHICH thresholds are asserted is the point (Sam's PR #1505
# aggregate criterion). It REQUIRES an E1E identity edge back to the SAME-index sedi-id
# copy (same subject, issuer != issuee), so the identity relation is schema-enforced.
AGE_THRESHOLDS = (13, 16, 18, 21, 55, 65)
AGE_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Age Threshold Credential",
    "description": "Derived age credential: a selectively disclosable aggregate of "
                   "boolean flags, one per age threshold, chained to the core identity "
                   "credential by an E1E identity edge.",
    "credentialType": "AgeThresholds",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "A", "e"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acg"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (State/DGO) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "A": {
            "description": "Selectively disclosable age-threshold aggregate section",
            "oneOf": [
                {"description": "Aggregate Section AGID", "type": "string"},
                {"description": "Selectively disclosable flag details",
                 "type": "array", "uniqueItems": True,
                 "items": {"anyOf": [
                     _disclosable_block("i", {"description": "Issuee (holder) AID",
                                              "type": "string"}, "Issuee"),
                     *[_disclosable_block(f"over{n}",
                         {"description": f"Over-{n} flag", "type": "boolean"},
                         f"Over{n}") for n in AGE_THRESHOLDS],
                 ]}},
            ],
        },
        "e": {
            "description": "Edge section: one E1E identity edge to the sedi-id core cred",
            "oneOf": [
                {"type": "string"},
                {"type": "object", "required": ["d", "identity"],
                 "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                "identity": _edge_schema(
                                    "E1E", "identity relation, issuer unconstrained")},
                 "additionalProperties": False}],
        },
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}

# The sedi-age bulk set derives its per-copy nonces from a DISTINCT salt so its uuids
# never collide with the sedi-id set's. Its own shared blindable registry + blinding salt.
BULK_AGE_SALT = b'bulkageexamsalt0'
REG_AGE_UUID = Noncer(raw=b'bulkagereguuid00').qb64
REG_AGE_STAMP = "2026-01-06T12:00:00.000000+00:00"
ISSUE_AGE_STAMP = "2026-01-06T12:05:00.000000+00:00"
BULK_AGE_REG_SALT = Noncer(raw=b'bulkageregblinds').qb64

# Aggregate ARRAY positions (A[0]=AGID; A[1]=issuee; A[2..]=flags) and Alice's age.
AGE_ISSUEE = 1
AGE_FLAG0 = 2
AGE_OVER21 = AGE_FLAG0 + AGE_THRESHOLDS.index(21)
ALICE_AGE = 26                                   # DOB 2000-03-15 at the 2026 presentation

# Per-copy nonce slots for a sedi-age copy: aggregate elements at "k/1".."k/(1+len)",
# the edge section at "k/20" and the E1E edge at "k/21" (high slots avoid collision).
_AGE_EDGE_SEC, _AGE_EDGE_ID = 20, 21


def _age_ael(nonces, k):
    """Copy k's age-threshold aggregate element list, issued to holder ALICE_k.

    Element 0 is the AGID placeholder; element 1 is the issuee block (i = ALICE_k), where
    SerderACDC.iseaid resolves the aggregate issuee; elements 2.. are one blinded boolean
    block per threshold (over<n> = ALICE_AGE >= n). All thresholds present, so disclosing
    one flag reveals nothing about the others. Per-copy blinding nonces at paths "k/j".
    """
    els = ['', dict(d='', u=nonces.u(k, 1), i=ALICES[k])]
    for offset, n in enumerate(AGE_THRESHOLDS):
        els.append(dict(d='', u=nonces.u(k, 2 + offset),
                        **{f"over{n}": ALICE_AGE >= n}))
    return els


def _verify_identity_edge(near, far):
    """The example's verifier branch for an E1E identity edge (near -> far).

    E1E binds two credentials to the SAME subject: near's issuee AID MUST equal far's
    issuee AID (both via SerderACDC.iseaid), with NO constraint on the issuer -- so it
    holds for two credentials whose issuee is ALICE_k though the issuer is the State
    (issuer != issuee), the case a coerce-to-I2I verifier would reject. Returns True or
    raises.
    """
    edge = near.sad['e']['identity']
    assert edge['o'] == 'E1E'                          # identity operator
    assert edge['n'] == far.said                       # points at this far node
    assert near.iseaid is not None                     # near is targeted (has an issuee)
    assert near.iseaid == far.iseaid                   # same subject: the identity relation
    return True


def _sedi_age_set(kind, idCopies, nonces=None):
    """Build the bulk sedi-age set, index-aligned to the sedi-id set via E1E.

    Returns (reg, copies, aggors, blist, B, issued). Copy k is issued by STATE to holder
    ALICE_k and carries an E1E edge to sedi-id copy k (idCopies[k]) -- the SAME subject
    (ALICE_k) but a different section (the aggregate far node, A[1].i). The Aggor per copy
    is returned so callers can selectively disclose over the aggregate. Its own shared
    blindable registry commits the set (B_age) as issued.
    """
    if nonces is None:
        nonces = _BulkNonces(BULK_AGE_SALT)
    reg = regcept(israid=STATE, uuid=REG_AGE_UUID, stamp=REG_AGE_STAMP, kind=kind)
    _, schema = _saidify_schema(dict(AGE_SCHEMA_MAD), kind=kind)
    copies, aggors = [], []
    for k in range(BULK_SIZE):
        edge = dict(d='', u=nonces.u(k, _AGE_EDGE_SEC),
                    identity=dict(d='', u=nonces.u(k, _AGE_EDGE_ID),
                                  n=idCopies[k].said,
                                  s=idCopies[k].sad['s']['$id'], o='E1E'))
        aggor = Aggor(ael=_age_ael(nonces, k), makify=True, kind=kind)
        age = acdcagg(israid=STATE, uuid=nonces.u(k), regid=reg.said, schema=schema,
                      aggregate=aggor.ael, edge=edge, kind=kind)
        copies.append(age)
        aggors.append(aggor)
    vs = [nonces.v(k) for k in range(BULK_SIZE)]
    ds = [c.said for c in copies]
    blist, B = _bulk_aggregate(vs, ds)
    blinder = Blinder.blind(acdc=B, state='issued', salt=BULK_AGE_REG_SALT, sn=1)
    issued = blindate(regid=reg.said, prior=reg.said, blid=blinder.said, sn=1,
                      stamp=ISSUE_AGE_STAMP, kind=kind)
    return reg, copies, aggors, blist, B, issued


def test_bulk_sedi_age_set_JSON():
    """Phase 3: the bulk sedi-age set, index-aligned to sedi-id by an E1E edge.

    The State bulk-issues Alice's sedi-age as M private copies, each to the SAME
    per-context holder AID ALICE_k as the matching sedi-id copy, and each carrying an E1E
    identity edge to sedi-id copy k. This is the #1515 standing-edge tension resolved: the
    E1E edge (the one #1515 worried would be a cross-verifier join key) is SAFE because it
    points at a fresh, per-context far node -- copy k's edge references sedi-id[k], not one
    stable core. Two verifiers holding copies k1 != k2 see different far-node SAIDs AND
    different holder AIDs.

    Asserted: every copy is a schema-valid aggregative sedi-age issued to ALICE_k, over-21
    true / over-65 false; the E1E edge is index-aligned (n == sedi-id[k].said) and verifies
    as the same subject; copies have distinct SAIDs; each verifies as a member of B_age;
    selective disclosure reveals over-21 while withholding the other thresholds; and the
    two sets share the holder AID per index but nothing else (different SAIDs, registries).
    """
    kind = Kinds.json
    idNonces = _BulkNonces(BULK_SALT)
    idReg, idCopies, _, _, _ = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageReg, ageCopies, ageAggors, blistAge, Bage, issuedAge = _sedi_age_set(
        kind, idCopies, ageNonces)

    over65Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(65)
    assert len(ageCopies) == BULK_SIZE
    for k, age in enumerate(ageCopies):
        assert age.ilk == Ilks.acg
        assert age.sad['i'] == STATE                          # issued by the State/DGO
        assert age.sad['rd'] == ageReg.said                   # shared age registry
        assert age.sad['A'][AGE_ISSUEE]['i'] == ALICES[k]     # per-copy holder AID
        assert age.iseaid == ALICES[k]
        assert age.sad['A'][AGE_OVER21]['over21'] is True     # over 21...
        assert age.sad['A'][over65Pos]['over65'] is False     # ...not over 65
        ageSchema = assert_acdc_schema_valid(age)
        # Index-aligned E1E edge -> the SAME-index sedi-id copy (the #1515 fix).
        assert age.sad['e']['identity']['o'] == 'E1E'
        assert age.sad['e']['identity']['n'] == idCopies[k].said
        assert _verify_identity_edge(age, idCopies[k])
        assert age.iseaid == idCopies[k].iseaid == ALICES[k]  # same subject per context

    # Schema teeth: the identity operator is const-pinned to E1E -- a swapped operator (the
    # I2I coercion #1515 warns about) and a non-boolean flag are both rejected at validation.
    badOp = json.loads(json.dumps(ageCopies[0].sad))
    badOp['e']['identity']['o'] = 'I2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(badOp)
    badFlag = json.loads(json.dumps(ageCopies[0].sad))
    badFlag['A'][AGE_OVER21] = dict(badFlag['A'][AGE_OVER21], over21="yes")
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(badFlag)

    # Distinct across copies; each verifies as a member of the committed B_age.
    assert len({a.said for a in ageCopies}) == BULK_SIZE
    for k, age in enumerate(ageCopies):
        assert _verify_membership(age.said, ageNonces.v(k), blistAge, Bage)

    # Pinned reproducible values (derived, not pasted).
    assert ageReg.said == "EEoc-CPP2nh8RoNYLL1fLKDYogKM9N2aKhuOwvk_qTiv"   # shared age registry
    assert Bage == "EAVHvdSmGMTUudmJpnktavMhJosgr9p8HgfzIogDumtd"          # blinded aggregate B_age
    assert ageCopies[0].said == "EHApv7RymJmbsCOvhzUuXgNFg_2IP0-MstWfNWj4oom0"
    assert ageAggors[0].agid == "EIhjnMKnP0I7Tzngtv4DPnvTc8szhi0NIdIQhXm0GZLU"

    # Selective disclosure over copy 0's aggregate: reveal over-21 + issuee, hide the rest.
    disclosed, _ = ageAggors[0].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    assert disclosed[AGE_ISSUEE]['i'] == ALICES[0]
    assert disclosed[AGE_OVER21]['over21'] is True
    assert Aggor.verifyDisclosure(disclosed, kind=kind)
    assert "over55" not in json.dumps(disclosed) and "over65" not in json.dumps(disclosed)

    # The two bulk sets meet only at the per-index holder AID (same subject); their
    # credential SAIDs and registries are disjoint.
    assert ageCopies[0].iseaid == idCopies[0].iseaid          # same subject ALICE_0
    assert ageReg.said != idReg.said                          # different registries
    assert {a.said for a in ageCopies}.isdisjoint({c.said for c in idCopies})

    # The age set's issuance is committed (blindably) to B_age.
    unblinded = Blinder.unblind(said=issuedAge.sad['b'], acdc=Bage, states=SET_STATES,
                                salt=BULK_AGE_REG_SALT, sn=1)
    assert unblinded.state == 'issued'


# ===========================================================================
# Phase 4: per-verifier presentations + the partition property (the headline).
# ===========================================================================
# The presentation envelope: a self-presentation (holder == subject) ALICE_k issues to
# verifier k, with I2I edges to copy k's sedi-id and sedi-age. It is minted fresh per
# presentation and is deliberately NOT registry-bound. Its own nonces come from a
# presentation salt at index k.
PRESENT_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Age-Portrait Presentation",
    "description": "Holder-issued self-presentation: ALICE_k (issuer) presents to a "
                   "verifier (issuee) via I2I edges to copy k's sedi-id and sedi-age. "
                   "Not registry-bound (a one-time presentation is not logged).",
    "credentialType": "SEDI_AgePortraitPresentation",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "s", "a", "e"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer = the holder ALICE_k", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "u", "i", "venue", "occurredAt"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "i": {"description": "Issuee = the verifier",
                                        "type": "string"},
                                  "venue": {"type": "string"},
                                  "occurredAt": {"type": "string"}},
                   "additionalProperties": False}]},
        "e": {"description": "Edge Section: I2I to copy k's sedi-id + sedi-age",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "identity", "age"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "identity": _edge_schema("I2I", "self-presentation id"),
                                  "age": _edge_schema("I2I", "self-presentation age")},
                   "additionalProperties": False}]},
    },
    "additionalProperties": False,
}

PRESENT_SALT = b'bulkpresexamsalt'
PRESENT_STAMP = "2026-07-22T21:30:00.000000+00:00"
# Per-verifier venue text (the disclosee's own context).
VENUES = {ALCOVE: "The Alcove Club, 200 S West Temple, Salt Lake City UT",
          DISPENSARY: "Wasatch Dispensary, Salt Lake City UT",
          SPORTSBOOK: "online sportsbook age-gate"}
# Presentation nonce slots (per context k): acdc uuid at "k", attr section at "k/0",
# edge section at "k/1", the two edges at "k/2"/"k/3".
_P_ATTR, _P_EDGE_SEC, _P_EDGE_ID, _P_EDGE_AGE = 0, 1, 2, 3


def _copy_index_for(verifier):
    """Alice's wallet policy: context = disclosee AID, so each verifier maps to ONE fixed
    copy index (per-verifier spend). Injective -- a copy is never shared across verifiers.
    A broader context (per activity domain) is the documented alternative (issue #1532)."""
    return VERIFIERS.index(verifier)


def _presentation(kind, verifier, idCopies, ageCopies, nonces=None, compactify=False):
    """The self-presentation ALICE_k issues to `verifier`, k = the wallet's index for it.

    Issuer = ALICE_k (holder == subject), issuee = the verifier. Two I2I edges reference
    copy k's sedi-id and sedi-age; I2I holds because ALICE_k issues the presentation and
    is the issuee of both sources. Fresh per presentation, not registry-bound.
    """
    if nonces is None:
        nonces = _BulkNonces(PRESENT_SALT)
    k = _copy_index_for(verifier)
    _, schema = _saidify_schema(dict(PRESENT_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=nonces.u(k, _P_ATTR), i=verifier,
                     venue=VENUES[verifier], occurredAt=PRESENT_STAMP)
    edge = dict(d='', u=nonces.u(k, _P_EDGE_SEC),
                identity=dict(d='', u=nonces.u(k, _P_EDGE_ID), n=idCopies[k].said,
                              s=idCopies[k].sad['s']['$id'], o='I2I'),
                age=dict(d='', u=nonces.u(k, _P_EDGE_AGE), n=ageCopies[k].said,
                         s=ageCopies[k].sad['s']['$id'], o='I2I'))
    return acdcmap(israid=ALICES[k], uuid=nonces.u(k), schema=schema,
                   attribute=attribute, edge=edge, kind=kind, compactify=compactify)


def _verify_presentation(pres, idCopy, ageCopy):
    """The verifier's binding for a self-presentation: I2I to both sources.

    I2I ("issuer-to-issuee") is the same-holder constraint: it holds only when the issuer
    of the presentation is the issuee of each source credential it references. Since
    ALICE_k issues the presentation and is the issuee of both copy-k sources, I2I is
    exactly right. Returns True or raises.
    """
    e = pres.sad['e']
    assert e['identity']['o'] == 'I2I' and e['identity']['n'] == idCopy.said
    assert e['age']['o'] == 'I2I' and e['age']['n'] == ageCopy.said
    assert pres.sad['i'] == idCopy.iseaid == ageCopy.iseaid   # I2I same-holder binding
    return True


def _context_correlators(k, idCopies, ageCopies, ageAggors, pres):
    """The per-copy identifiers a verifier of context k receives that bulk issuance
    PARTITIONS (Sam's #1532 list, the '✅ partitioned' rows): the holder AID, both source
    SAIDs, the aggregate AGID, and the fresh presentation SAID. Disjoint across contexts
    is the structural un-joinability proof."""
    return {ALICES[k], idCopies[k].said, ageCopies[k].said, ageAggors[k].agid,
            pres.said}


def test_partition_across_verifiers_JSON():
    """Phase 4: two disparate verifiers get disjoint identifier sets -- the headline.

    Alice proves over-21 at two mutually-unrelated venues. Her wallet maps each verifier
    to its own copy index (context = disclosee AID), so the Alcove gets copy 0 and the
    dispensary gets copy 1: different holder AIDs (ALICE_0 vs ALICE_1), different sedi-id
    and sedi-age SAIDs, different AGIDs, different presentation SAIDs. The two verifiers
    cannot join on any of these -- the partition of the correlatable identifier space that
    #1515 asked for and that bulk issuance provides.

    Scoped honestly per Sam's issue #1532: this classifies EVERY ACDC identifier, not just
    a hand-picked few. The holder AID IS partitioned here (the independent-AID variant),
    which is the dominant correlator basic bulk issuance would have left. The one residual
    is the SHARED registry (and the aggregate B) keyed per set -- a contract-gated
    2nd-party correlator that full 3rd-party decorrelation (independent/herd registries via
    a Sparse-Merkle-Tree root, tick 6sjz) would remove; it is asserted PRESENT in both, not
    hidden. Public issuer/schema identifiers are shared by the whole population and single
    out no one.
    """
    kind = Kinds.json
    idNonces = _BulkNonces(BULK_SALT)
    idReg, idCopies, _, Bid, _ = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageReg, ageCopies, ageAggors, _, Bage, _ = _sedi_age_set(kind, idCopies, ageNonces)
    presNonces = _BulkNonces(PRESENT_SALT)

    # Two disparate verifiers; the wallet maps them to distinct copy indices.
    v1, v2 = ALCOVE, DISPENSARY
    k1, k2 = _copy_index_for(v1), _copy_index_for(v2)
    assert k1 != k2                                       # per-verifier spend is injective
    pres1 = _presentation(kind, v1, idCopies, ageCopies, presNonces)
    pres2 = _presentation(kind, v2, idCopies, ageCopies, presNonces)
    assert pres1.said == "EAkAGbSXZo8nT1HOvI8gF-zMeFLw_ymmMafsRZao2lTi"   # Alcove context
    assert pres2.said == "EFBArucmWAjDKX-oE25MUvaVEWgqiCj49UTbH9XJL56_"   # dispensary context

    # Each presentation verifies (I2I same-holder to copy-k sources) and rides the over-21
    # selective disclosure.
    assert _verify_presentation(pres1, idCopies[k1], ageCopies[k1])
    assert _verify_presentation(pres2, idCopies[k2], ageCopies[k2])
    for k in (k1, k2):
        disclosed, _ = ageAggors[k].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
        assert disclosed[AGE_OVER21]['over21'] is True
        assert Aggor.verifyDisclosure(disclosed, kind=kind)
    # Self-presentation: holder == subject (unlike the guardianship represented case).
    assert pres1.sad['i'] == idCopies[k1].iseaid == ALICES[k1]

    # The presentation validates against its purpose-authored schema, and the schema
    # ENFORCES the I2I self-presentation operators: a swapped operator is rejected.
    presSchema = assert_acdc_schema_valid(pres1)
    assert_acdc_schema_valid(pres2, schema=presSchema)
    badOp = json.loads(json.dumps(pres1.sad))
    badOp['e']['identity']['o'] = 'NI2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(presSchema).validate(badOp)

    # --- PARTITIONED: the two contexts share NONE of the per-copy identifiers, INCLUDING
    # the holder AID (the independent-AID variant's payoff). ---
    corr1 = _context_correlators(k1, idCopies, ageCopies, ageAggors, pres1)
    corr2 = _context_correlators(k2, idCopies, ageCopies, ageAggors, pres2)
    assert corr1.isdisjoint(corr2)                        # THE headline: no join key
    assert ALICES[k1] != ALICES[k2]                       # holder AID partitioned
    assert idCopies[k1].said != idCopies[k2].said         # sedi-id SAID partitioned
    assert ageCopies[k1].said != ageCopies[k2].said       # sedi-age SAID partitioned
    assert ageAggors[k1].agid != ageAggors[k2].agid       # AGID partitioned
    assert pres1.said != pres2.said                       # presentation SAID partitioned

    # --- RESIDUAL: the shared registry (and B) recur in BOTH contexts -- the honest gap
    # that independent/herd registries (tick 6sjz) would close. Asserted present, not hidden.
    assert idCopies[k1].sad['rd'] == idCopies[k2].sad['rd'] == idReg.said   # shared id registry
    assert ageCopies[k1].sad['rd'] == ageCopies[k2].sad['rd'] == ageReg.said  # shared age registry
    assert Bid and Bage                                   # the aggregates are per-set, shared

    # --- PUBLIC, non-correlating: issuer + schema are shared by the whole population and
    # single out no holder. ---
    assert idCopies[k1].sad['i'] == idCopies[k2].sad['i'] == STATE
    assert idCopies[k1].sad['s']['$id'] == idCopies[k2].sad['s']['$id']     # same sedi-id schema
    assert ageCopies[k1].sad['s']['$id'] == ageCopies[k2].sad['s']['$id']   # same sedi-age schema

    # --- Guardrail: the wallet mapping is 1-verifier -> 1-copy; a third distinct verifier
    # gets a third distinct index (never a reused copy across contexts). ---
    assert len({_copy_index_for(v) for v in VERIFIERS}) == len(VERIFIERS)


# ===========================================================================
# Phase 5: disclosure gating (v_k only post-agree) + set revocation.
# ===========================================================================
# A published SEDI over-21 governance framework, referenced by SAID (public, shared by
# the whole population -> non-correlating). PLACEHOLDER digest of a description string.
GOVERNANCE_SAID = Diger(ser=b'SEDI over-21 governance framework v1').qb64
APPLY_STAMP = "2026-07-22T21:15:00.000000+00:00"
OFFER_STAMP = "2026-07-22T21:16:00.000000+00:00"
AGREE_STAMP = "2026-07-22T21:17:00.000000+00:00"
GRANT_STAMP = "2026-07-22T21:18:00.000000+00:00"
REVOKE_STAMP = "2026-08-01T09:00:00.000000+00:00"


def _offer(kind, *, sender, receiver, prior, presentationSaid, governance):
    """Leak-proof pre-agree offer constructor (Sam, issue #1532: make the leak
    UNREPRESENTABLE at the API rather than merely asserted-absent).

    Its signature has NO parameter for source-credential SAIDs, the registry, or the
    blinding factor v_k, so the pre-agree offer STRUCTURALLY cannot carry a stable holder
    correlator. It commits only the fresh, per-context presentation SAID (safe because it
    is built with a per-presentation salt, so it is an ephemeral, not a stable correlator)
    and a public governance ref. This is the 'correlation-budget doctrine' as
    policy-by-construction -- an EGF/implementation-guide requirement, not a schema change.
    """
    return exchange(sender=sender, receiver=receiver, route="/ipex/offer", prior=prior,
                    attributes=dict(acdc=presentationSaid, governance=governance),
                    stamp=OFFER_STAMP, kind=kind)


def test_disclosure_gating_and_revocation_JSON():
    """Phase 5: the blinding factor v_k rides only in the grant; a revoked set fails.

    Two properties. First, disclosure gating: the pre-agree /ipex/offer commits only the
    fresh presentation SAID + public governance -- built with a constructor that cannot
    carry the source SAIDs, the registry, or the blinding factor v_k (Sam #1532's
    make-it-unrepresentable guidance). v_k appears ONLY in the grant, after a valid signed
    agree, so a verifier who spurns walks away with no stable correlator and no membership
    proof. Second, revocation: the State flips the shared set's blindable state to
    'revoked'; a verifier that checks current status MUST then refuse, even though the
    credential graph still binds.
    """
    kind = Kinds.json
    idNonces = _BulkNonces(BULK_SALT)
    idReg, idCopies, idBlist, Bid, idIssued = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageReg, ageCopies, ageAggors, ageBlist, Bage, ageIssued = _sedi_age_set(
        kind, idCopies, ageNonces)
    presNonces = _BulkNonces(PRESENT_SALT)

    verifier = ALCOVE
    k = _copy_index_for(verifier)
    pres = _presentation(kind, verifier, idCopies, ageCopies, presNonces)

    # 1. apply (verifier -> holder): the challenge (schema/fields + governance).
    apply = exchange(sender=verifier, receiver=ALICES[k], route="/ipex/apply",
                     attributes=dict(m="Prove over-21.",
                                     disclose={ageCopies[k].sad['s']['$id']:
                                               ["/A/i", "/A/over21"]},
                                     g=GOVERNANCE_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['r'] == "/ipex/apply"

    # 2. offer (holder -> verifier): via the leak-proof constructor. NO source SAIDs, NO v_k.
    offer = _offer(kind, sender=ALICES[k], receiver=verifier, prior=apply.said,
                   presentationSaid=pres.said, governance=GOVERNANCE_SAID)
    assert offer.sad['p'] == apply.said
    assert pres.said.encode() in offer.raw                      # fresh per-context SAID: safe
    assert idCopies[k].said.encode() not in offer.raw           # source SAID withheld
    assert ageCopies[k].said.encode() not in offer.raw          # source SAID withheld
    assert idReg.said.encode() not in offer.raw                 # registry withheld
    assert ageReg.said.encode() not in offer.raw
    assert ageNonces.v(k).encode() not in offer.raw             # blinding factor withheld
    assert idNonces.v(k).encode() not in offer.raw

    # 3. agree (verifier -> holder): signed acceptance binding the offer.
    agree = exchange(sender=verifier, receiver=ALICES[k], route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    vSigner = _SIGNERS[2 + k]                                   # the verifier's establishing key
    vSig = vSigner.sign(ser=agree.raw, index=0)
    keyState = Verfer(qb64=vSigner.verfer.qb64)
    assert keyState.verify(sig=vSig.raw, ser=agree.raw)

    # 4. The gate: the holder discloses (grant carrying v_k + the membership proof) ONLY on
    # a valid, offer-binding, signed agree.
    def disclose(agreeMsg, sig):
        if not (agreeMsg.sad['r'] == "/ipex/agree" and agreeMsg.sad['p'] == offer.said
                and keyState.verify(sig=sig.raw, ser=agreeMsg.raw)):
            return None
        # The grant carries the EXPANDED presentation (edges visible, so the verifier can
        # walk the I2I chain to the source SAIDs), the age selective disclosure, and the
        # membership proof (v_k + list + B). The issuer-committed source SAIDs and v_k
        # cross the wire ONLY here -- after the contract -- never in the pre-agree offer.
        ageDisc, _ = ageAggors[k].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
        return exchange(sender=ALICES[k], receiver=verifier, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(acdc=pres.sad, ageDisclosure=ageDisc,
                                        membership=dict(v=ageNonces.v(k), blist=ageBlist,
                                                        B=Bage)),
                        stamp=GRANT_STAMP, kind=kind)

    # A forged signature unlocks nothing.
    assert disclose(agree, _SIGNERS[0].sign(ser=agree.raw, index=0)) is None
    # A valid agree unlocks the grant; v_k and the source SAIDs appear ONLY now.
    grant = disclose(agree, vSig)
    assert grant is not None and grant.sad['p'] == agree.said
    assert ageNonces.v(k).encode() in grant.raw                 # v_k revealed only in the grant
    assert idCopies[k].said.encode() in grant.raw               # source SAIDs revealed...
    assert ageCopies[k].said.encode() in grant.raw              # ...only post-agree
    # The verifier walks the chain from the grant: the presentation's age edge names the
    # source, the source is a proven member of the committed set, and it discloses over-21.
    granted = grant.sad['a']['acdc']
    assert granted['e']['age']['n'] == ageCopies[k].said        # edge -> the disclosed source
    assert granted['e']['identity']['n'] == idCopies[k].said
    assert _verify_membership(ageCopies[k].said, ageNonces.v(k), ageBlist, Bage)
    assert grant.sad['a']['ageDisclosure'][AGE_OVER21]['over21'] is True

    # --- Revocation: the State records a 'revoked' update on the shared set registry. ---
    revokedBlinder = Blinder.blind(acdc=Bage, state='revoked', salt=BULK_AGE_REG_SALT, sn=2)
    revoked = blindate(regid=ageReg.said, prior=ageIssued.said, blid=revokedBlinder.said,
                       sn=2, stamp=REVOKE_STAMP, kind=kind)
    assert revoked.sad['p'] == ageIssued.said                   # chains onto the issuance
    assert b"revoked" not in revoked.raw                        # state word stays blinded

    def status_issued(event, sn):
        return Blinder.unblind(said=event.sad['b'], acdc=Bage, states=SET_STATES,
                               salt=BULK_AGE_REG_SALT, sn=sn).state == 'issued'
    assert status_issued(ageIssued, 1) is True                  # honored while issued
    assert status_issued(revoked, 2) is False                   # refused once revoked

    # The graph still binds (edges are immutable), but a status-checking verifier refuses.
    assert _verify_presentation(pres, idCopies[k], ageCopies[k])   # graph still binds...
    assert status_issued(revoked, 2) is False                      # ...yet status forbids it


# ===========================================================================
# Phase 6: the invariants hold across every serialization kind.
# ===========================================================================
@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_bulk_serialization_kinds(kind):
    """Phases 1-5 invariants hold across every serialization kind, not just JSON.

    Exercises the same flows -- the bulk sedi-id and sedi-age sets issued to per-context
    holder AIDs ALICE_k, the index-aligned E1E edge, the blinded-aggregate membership
    proof, the per-verifier partition, and the blindable set-state gate -- over CESR (the
    native KERI wire format) and CBOR/MGPK, asserting the behavioral invariants without
    pinning per-kind SAIDs. (The no-correlator-on-the-wire substring checks are
    JSON-specific: the CESR wire form base64-encodes the payload.)
    """
    idNonces = _BulkNonces(BULK_SALT)
    idReg, idCopies, idBlist, Bid, idIssued = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageReg, ageCopies, ageAggors, ageBlist, Bage, ageIssued = _sedi_age_set(
        kind, idCopies, ageNonces)

    # Per copy: schema-valid; issued to its own per-context holder AID; index-aligned E1E;
    # a valid member of the committed aggregate.
    for k in range(BULK_SIZE):
        assert idCopies[k].ilk == Ilks.acm and idCopies[k].kind == kind
        assert ageCopies[k].ilk == Ilks.acg
        assert idCopies[k].iseaid == ageCopies[k].iseaid == ALICES[k]
        assert_acdc_schema_valid(idCopies[k])
        assert_acdc_schema_valid(ageCopies[k])
        assert _verify_identity_edge(ageCopies[k], idCopies[k])       # E1E on every kind
        assert _verify_membership(idCopies[k].said, idNonces.v(k), idBlist, Bid)
        assert _verify_membership(ageCopies[k].said, ageNonces.v(k), ageBlist, Bage)

    # Partition across two contexts holds on every kind (holder AID included).
    presNonces = _BulkNonces(PRESENT_SALT)
    k1, k2 = _copy_index_for(ALCOVE), _copy_index_for(DISPENSARY)
    pres1 = _presentation(kind, ALCOVE, idCopies, ageCopies, presNonces)
    pres2 = _presentation(kind, DISPENSARY, idCopies, ageCopies, presNonces)
    assert _verify_presentation(pres1, idCopies[k1], ageCopies[k1])
    assert _verify_presentation(pres2, idCopies[k2], ageCopies[k2])
    assert_acdc_schema_valid(pres1)                  # presentation schema-valid on every kind
    assert _context_correlators(k1, idCopies, ageCopies, ageAggors, pres1).isdisjoint(
        _context_correlators(k2, idCopies, ageCopies, ageAggors, pres2))

    # Private presentation: compact and expanded forms share one SAID.
    presCompact = _presentation(kind, ALCOVE, idCopies, ageCopies, presNonces,
                                compactify=True)
    assert presCompact.said == pres1.said
    assert isinstance(pres1.sad['e'], dict)          # sections inline...
    assert isinstance(presCompact.sad['e'], str)     # ...vs. collapsed to a SAID

    # Selective over-21 disclosure verifies via the AGID; blindable set state resolves.
    disclosed, _ = ageAggors[k1].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    assert disclosed[AGE_OVER21]['over21'] is True
    assert Aggor.verifyDisclosure(disclosed, kind=kind)
    assert Blinder.unblind(said=ageIssued.sad['b'], acdc=Bage, states=SET_STATES,
                           salt=BULK_AGE_REG_SALT, sn=1).state == 'issued'


if __name__ == "__main__":
    test_bulk_derivation_primitive_JSON()
    test_bulk_sedi_id_set_JSON()
    test_bulk_sedi_age_set_JSON()
    test_partition_across_verifiers_JSON()
    test_disclosure_gating_and_revocation_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_bulk_serialization_kinds(_kind)
