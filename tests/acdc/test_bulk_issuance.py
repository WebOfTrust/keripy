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
from keri.core import (Salter, Noncer, Aggor, Compactor, Mapper, Diger, Verfer,
                       exchange, messagize)
from keri.core.coring import MtrDex, NonceDex
from keri.core.eventing import incept
from keri.core.serdering import SerderACDC
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
