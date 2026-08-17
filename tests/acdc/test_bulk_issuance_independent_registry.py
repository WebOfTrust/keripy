# -*- coding: utf-8 -*-
"""
tests.acdc.test_bulk_issuance_independent_registry module

Worked, working example of INDEPENDENT-REGISTRY bulk-issued private ACDCs (ACDC spec
section 15.4, "Independent Registry Bulk-Issued ACDCs" and "Independent Registry
Transaction Event Seals Using Merkle Tree Roots") -- the variant the State of Utah
intends to deploy for SEDI (State-Endorsed Digital Identity, Utah Code 63A-20).

WHY A SECOND BULK-ISSUANCE EXAMPLE. The sibling module
tests/acdc/test_bulk_issuance_shared_registry.py works the BASIC form: M copies of a
credential share ONE registry, and a blinded aggregate 'B' = H(C(b_k)) commits the
whole set in a single issuance event. That module closes the correlators #1515 raised
-- per-copy SAIDs, per-copy holder AIDs, per-copy edges -- but it ends with an honest
residual it asserts rather than hides: the shared registry SAID recurs in every
presentation context, and so does 'B'. Sam Smith, on ACDC spec PR
trustoverip/kswg-acdc-specification#200 (2026-07-23): "From a SEDI perspective they
want to do Independent registry bulk issuance which does not use B." This module is
that variant. Read the sibling first for the derivation mechanics; read this one for
the deployment target.

WHAT CHANGES, AND WHY 'B' DISAPPEARS RATHER THAN SHRINKS. Give every copy its own
registry and the aggregate has nothing left to aggregate. 'B' existed for one reason:
to let M copies share a single TEL without that TEL naming any of them. A registry
holding exactly one ACDC can blind that ACDC's own SAID directly, so the blinded
aggregate, the per-copy blinding factor v_k, and the disclosed [b_k] membership list
all go away together. Sam's "does not use B" is not a preference; it is what the
structure forces. In exchange, proof of issuance moves from "this SAID is a member of
the committed set" to "this registry's update event is a leaf under the issuer's
committed batch root".

THE PART THAT IS EASY TO GET WRONG. M independent registries do not by themselves
decorrelate anything. If the issuer anchors M registry-inception seals side by side in
one KEL event, any third party reading that KEL sees the M registries co-anchored and
reassembles the set -- the correlator has moved from the ACDC to the KEL, not
vanished. That is why spec 15.4 prescribes a SINGLE Merkle-root seal per batch, over a
tree whose leaves deliberately MIX transaction events across registries AND across
Issuees (spec L2918-2922). The batch is the anonymity set; the tree is what lets one
member prove inclusion without disclosing the others. Herd privacy is load-bearing
here, so this example builds the tree and the inclusion proofs rather than gesturing
at them.

Scenario, unchanged from the sibling so the two read side by side. Alice, a Utah
resident over 21, proves "over 21" at mutually-unrelated verifiers -- a bar, a
cannabis dispensary, an online sportsbook. The State/DGO bulk-issues her both source
credentials, a set of sedi-id copies and a set of sedi-age copies, index-aligned so
copy k of sedi-age carries an E1E identity edge to copy k of sedi-id. Alice spends
copy k at verifier k. What is new is underneath: copy k of each set has its OWN
registry, its OWN blinding salt, and its own transaction event, and all of those
events -- Alice's and every other Utah resident's -- are committed by ONE Merkle root
seal in the State's KEL.

Plain Merkle tree, not a sparse Merkle tree. Spec L2918 calls for an SMT. An SMT buys
two things this example does not exercise: efficient NON-inclusion proofs, and
fixed-depth addressing keyed by the leaf's own SAID. The property that carries the
privacy argument here -- prove one leaf under a herd-wide root without disclosing any
sibling leaf -- is delivered by an ordinary domain-separated Merkle tree, which is
what _BatchTree below implements. A production Registrar SHOULD use an SMT for the
incremental-update and non-inclusion properties described at spec L2918-2926; nothing
in this example's proofs would change shape.

SPEC GAPS THIS EXAMPLE HAD TO PIN (candidates for a follow-on spec PR, the way the
sibling produced #200). Spec 15.4 pins the derivation paths "k" (top-level uuid),
"k/j" (nested block uuid) and "k." (the blinding factor v_k, pinned by #200). It pins
nothing for the two values independent-registry bulk issuance needs per copy. This
module extends the same dot-suffix convention: "k.r" derives copy k's REGISTRY
inception uuid, and "k.b" derives copy k's registry BLINDING salt. Nor does the spec
pin the tree's leaf definition or its hashing: this module takes the leaf to be the
transaction event's SAID (spec L2922 describes the tree as holding "all the event SAIDs
from all transaction events across the Issuer's Registries") and uses RFC-6962 domain
separation (0x00 leaf, 0x01 interior) over qb64 TEXT concatenation with Blake3-256 --
the same concatenation domain #200 pinned for b_k. Two implementations that chose
differently would compute different roots and fail to cross-verify, so these are
interop-blocking and belong in the spec, not here.

WHERE THE L-NUMBERS POINT. Every "spec L####" in this module is a line number in
spec/spec-body.md of trustoverip/kswg-acdc-specification at commit f96ef54 (2026-07-27),
which is `main` with PR #200 merged. The pin is stated because these numbers drift: an
earlier revision of this module was written against a checkout that predated #200 and
every citation in this region ran two lines low, which is invisible until someone follows
one. If you are checking these against a different commit and they miss by a small
constant, that is why -- re-derive them rather than assuming the text moved.

A note on altitude. Like the sibling examples, this one models the credential graph,
the bulk derivation, the registries, and the batch anchor at the data-structure level,
built from the real v2 primitives in keri.core and keri.acdc.messaging (Salter.stretch,
Noncer, Diger, Sealer/SealRoot, acdcmap/acdcagg, Aggor, Blinder, regcept, blindate,
exchange). It does not stand up a Habery/keystore, so the KEL that would carry the
root seal is represented by the real Sealer object rather than by a real KEL. Every
ACDC validates against a real, purpose-authored JSON Schema (Draft 2020-12). Actor
AIDs and all nonces are DERIVED from fixed salts so the example is reproducible.
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
from keri.core.structing import Blinder, Sealer, SealRoot


# --- Reproducible example actors (see module docstring). ---
# Five actors, each a self-addressing ('E') transferable AID: its prefix is the SAID of
# an inception event committing to the actor's current signing key and a digest of its
# pre-rotated next key. Ten signers from one fixed salt: _SIGNERS[0..4] are the five
# actors' current signing keys (State/DGO, Alice, and the three verifiers) and
# _SIGNERS[5..9] are their matching pre-rotated next keys.
_SIGNERS = Salter(raw=b'indregworkexsig0').signers(count=10, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


# STATE = Utah's digital-government office (the issuer of both bulk sets); ALICE is the
# adult holder (over 21) -- her per-copy AIDs are derived further below; ALCOVE (a bar),
# DISPENSARY (cannabis), and SPORTSBOOK (an online sportsbook) are the mutually
# unrelated verifiers she proves over-21 to.
STATE, ALICE, ALCOVE, DISPENSARY, SPORTSBOOK = (
    _actor_aid(_SIGNERS[i], _SIGNERS[i + 5]) for i in range(5))

# The three verifiers in spend order; Alice's wallet maps verifier -> copy index.
VERIFIERS = (ALCOVE, DISPENSARY, SPORTSBOOK)


# ===========================================================================
# Phase 1a: the per-copy derivation primitive (ACDC spec 15.4 + this example's
# proposed extension for the registry uuid and registry blinding salt).
# ===========================================================================
# The shared secret salt for Alice's bulk sets -- known to the Issuer (State) and the
# Issuee (Alice), never handed to a verifier. In a real flow it is transported to Alice
# encrypted to her AID-derived X25519 key (keri.core Encrypter/Decrypter); here it is a
# fixed value so the example is reproducible.
BULK_SALT = b'indregexamsalt00'
# M: copies per bulk-issued set, and therefore ALSO the number of registries. Small for
# a readable example. A real deployment sizes M to the expected number of distinct
# verifier contexts -- and pays for it in TELs, one per copy per set per resident (spec
# L2911: "the size of the Registry database increases as a multiple of the number of
# copies"). That cost is the price of removing the registry as a correlator.
BULK_SIZE = 5
# The states a registry's blindable update can carry, for both bulk sets.
SET_STATES = ['issued', 'revoked']


def _hx(index):
    """Render a derivation-path index as LOWERCASE HEX with no leading zeros.

    Every index that becomes part of an HD derivation path goes through here. ACDC spec
    15.4 currently says a bulk-issuance path index is "the decimal or hexadecimal textual
    representation" of the index, which is an either/or that no implementation can honor:
    the two renderings agree only for indices 0-9 and diverge from 10 onward ("10" vs
    "a"), so two conformant implementations derive different nonces, different SAIDs and
    different REGISTRIES for every copy from the tenth. Hex is what KERI's HD paths
    actually use everywhere -- Salter.signers (src/keri/core/signing.py:484), SaltyCreator
    (src/keri/app/keeping.py:542,544) and Blinder.makeUUID via Number.snh
    (src/keri/core/structing.py:1479) all render "{:x}", as does signify-ts
    (src/keri/core/manager.ts:296) -- and it is what both specs already say for this same
    object in prose (KERI spec L1914 / ACDC spec L3328: "the hex representation of the
    count offset"). Sam's keripy discussion #929, the rationale for the separator-free
    salty path, states the premise as "hex strings with no zero pre-padding" and builds
    its whole proof on it.

    Non-integer path segments (the herd's composite tags below) pass through unchanged;
    they are labels, not indices. Pinning the rendering in the spec is proposed in
    trustoverip/kswg-acdc-specification#204.
    """
    return f"{index:x}" if isinstance(index, int) else index


class _BulkNonces:
    """Deterministic per-copy nonce derivation for a bulk-issued set (ACDC spec 15.4).

    Every nonce for every copy is derived from ONE shared secret salt by argon2id
    (Salter.stretch) at a hierarchical path keyed on the copy index k, then wrapped as a
    salty nonce (Noncer). Every index in a path is lowercase hex, no leading zeros
    (see _hx):

        path "k"    -> copy k's top-level ACDC uuid  u_k       (spec)
        path "k/j"  -> copy k's nested block j uuid            (spec)
        path "k.r"  -> copy k's REGISTRY inception uuid        (proposed, see below)
        path "k.b"  -> copy k's REGISTRY blinding salt         (proposed, see below)

    SPEC GAP / PROPOSED EXTENSION. Spec 15.4 pins "k" and "k/j", and PR #200 pinned "k."
    for the blinding factor v_k that the SHARED-registry variant needs. Independent
    registry bulk issuance does not use v_k at all -- there is no aggregate to blind
    into -- but it needs two values the spec never names: where each copy's registry
    inception uuid comes from, and where each copy's registry blinding salt comes from.
    Both must derive from the shared salt for the same reason the ACDC uuids do: so the
    Issuee stores only (salt, template) and regenerates the rest on demand. This module
    extends the dot-suffix convention #200 established, reserving "k." (v_k, unused
    here) and adding "k.r" and "k.b". An implementation that chose other paths would
    compute different registry SAIDs and could not unblind this one's TEL state, so the
    paths are interop-blocking and belong in the spec.

    PRIVACY NOTE on the per-copy blinding salt. Deriving it per copy is not bookkeeping
    tidiness -- it is what keeps a verifier's disclosure scoped. A verifier handed copy
    k's blinding salt can unblind copy k's registry state and NOTHING else; the sibling
    module's single set-wide registry salt would let that same verifier follow every
    state update the whole set ever makes. test_indreg_derivation_and_batch_JSON asserts
    the negative case directly.

    temp=True selects the fast (test-only) argon2 parameters, matching how the sibling
    examples derive nonces.
    """

    def __init__(self, salt_raw):
        self._salter = Salter(raw=salt_raw)

    def _nonce(self, path):
        return Noncer(raw=self._salter.stretch(size=32, path=path, temp=True),
                      code=NonceDex.Salt_256).qb64

    def u(self, k, j=None):
        """Copy k's uuid: the top-level ACDC uuid (j is None) or nested block j's uuid."""
        return self._nonce(_hx(k) if j is None else f"{_hx(k)}/{_hx(j)}")

    def r(self, k):
        """Copy k's own registry inception uuid, derived at the path "k.r"."""
        return self._nonce(f"{_hx(k)}.r")

    def b(self, k):
        """Copy k's own registry blinding salt, derived at the path "k.b".

        A 128-bit qb64 salt, which is what Blinder.makeUUID consumes; the other nonces
        here are 256-bit uuids. Only this copy's salt is ever disclosed to a verifier.
        """
        return Noncer(raw=self._salter.stretch(size=16, path=f"{_hx(k)}.b",
                                              temp=True)).qb64


# ===========================================================================
# Phase 1b: the batch anchoring primitive (ACDC spec 15.4, "Independent Registry
# Transaction Event Seals Using Merkle Tree Roots").
# ===========================================================================
class _BatchTree:
    """Merkle tree over TEL transaction-event SAIDs, anchored by ONE root seal.

    The Issuer periodically anchors a single seal in its KEL whose value is this tree's
    root, committing every transaction event from every registry updated since the last
    anchor -- across all bulk-issued sets and ALL Issuees (spec L2920-2922). A Validator
    that receives one event plus its inclusion proof learns that the Issuer committed to
    that event and learns nothing about any other leaf. The batch is the anonymity set:
    the more registries and Issuees it mixes, the less a co-anchored pair of events says
    about a common holder. Spec L2926 goes further and suggests the Issuer inject
    state-preserving no-op updates to pad thin batches.

    SPEC GAP / PINNED HERE. Spec L2922 describes the leaves as "all the event
    SAIDs from all transaction events" and L2932 requires second-pre-image protection
    of interior nodes, but pins
    neither the domain separation nor the digest. This implementation uses RFC 6962
    domain separation -- a leaf is H(0x00 + leafSAID), an interior node is
    H(0x01 + left + right) -- over qb64 TEXT concatenation with Blake3-256, matching the
    concatenation domain PR #200 pinned for the sibling variant's b_k. Domain separation
    is what stops an interior node's preimage from being replayed as a leaf. An odd node
    at any level is PROMOTED unchanged to the next level rather than duplicated, which
    avoids the duplicate-last-leaf ambiguity (CVE-2012-2459). Two implementations that
    chose differently would compute different roots.

    This is a plain Merkle tree; see the module docstring on why not an SMT.
    """

    Leaf = b'\x00'      # RFC 6962 leaf domain prefix
    Node = b'\x01'      # RFC 6962 interior-node domain prefix

    def __init__(self, leaves):
        if not leaves:
            raise ValueError("a batch must commit at least one transaction event")
        self.leaves = list(leaves)
        self.levels = [[self._leaf(leaf) for leaf in self.leaves]]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = [self._node(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
            if len(cur) % 2:            # promote the odd node, never duplicate it
                nxt.append(cur[-1])
            self.levels.append(nxt)

    @classmethod
    def _leaf(cls, said):
        return Diger(ser=cls.Leaf + said.encode()).qb64

    @classmethod
    def _node(cls, left, right):
        return Diger(ser=cls.Node + (left + right).encode()).qb64

    @property
    def root(self):
        """The batch root: the single value the Issuer seals in its KEL."""
        return self.levels[-1][0]

    def prove(self, said):
        """Return the inclusion proof for event `said`: an ordered list of
        (siblingDigest, side) pairs, leaf level first. `side` is which side the sibling
        sits on. A promoted odd node contributes no sibling at that level."""
        index = self.leaves.index(said)
        proof = []
        for level in self.levels[:-1]:
            if index % 2:
                proof.append((level[index - 1], 'L'))
            elif index + 1 < len(level):
                proof.append((level[index + 1], 'R'))
            index //= 2
        return proof

    @classmethod
    def verify(cls, said, proof, root):
        """Recompute the root from the event SAID and its proof; True iff it matches."""
        digest = cls._leaf(said)
        for sibling, side in proof:
            digest = (cls._node(sibling, digest) if side == 'L'
                      else cls._node(digest, sibling))
        return digest == root


def _batch(*eventSaidGroups):
    """Order one anchoring batch's leaves: every group's event SAIDs, sorted.

    Sorting by SAID is a deterministic stand-in for the shuffle a real Registrar would
    apply. It matters because an inclusion proof discloses the leaf's PATH (the L/R
    bits), so a verifier learns roughly where in the tree its event sits. Leaving one
    holder's events in contiguous submission order would let two colluding verifiers
    notice their proofs are adjacent. SAIDs are digests, so sorting by them interleaves
    holders pseudo-randomly while staying reproducible.
    """
    return sorted(said for group in eventSaidGroups for said in group)


def test_indreg_derivation_and_batch_JSON():
    """Phase 1: the per-copy derivation paths and the batch Merkle tree.

    Two primitives, neither of which the shared-registry variant needs. First, the
    derivation: one shared salt yields, per copy k, the ACDC uuid ("k"), the nested block
    uuids ("k/j"), the copy's own registry inception uuid ("k.r") and the copy's own
    registry blinding salt ("k.b") -- four disjoint spaces, all regenerable by Issuer and
    Issuee from the salt alone, with nothing stored per copy. Second, the batch tree: a
    domain-separated Merkle tree over transaction-event SAIDs whose single root is what
    the Issuer seals, and which proves one leaf without disclosing any other.

    Asserted here: the derivation is deterministic and its four path spaces never
    collide; a per-copy blinding salt unblinds its own registry state and REFUSES every
    other copy's (the scoping the sibling's set-wide salt cannot give); the tree root is
    stable and order-dependent; every leaf proves; a proof discloses no other member's
    event SAID; and a wrong leaf, a tampered proof, a flipped side, or a wrong root all
    fail.
    """
    nonces = _BulkNonces(BULK_SALT)
    M = BULK_SIZE

    us = [nonces.u(k) for k in range(M)]
    nested = [nonces.u(k, 0) for k in range(M)]
    rs = [nonces.r(k) for k in range(M)]
    bs = [nonces.b(k) for k in range(M)]

    # Determinism: same salt + index regenerates every nonce (Issuer and Issuee each
    # regenerate independently -- neither stores per-copy material).
    fresh = _BulkNonces(BULK_SALT)
    assert [fresh.u(k) for k in range(M)] == us
    assert [fresh.r(k) for k in range(M)] == rs
    assert [fresh.b(k) for k in range(M)] == bs

    # The path index rendering is LOWERCASE HEX, no leading zeros -- pinned by assertion
    # rather than left to the coincidence that indices 0-9 render identically in both
    # bases. Copy 10's uuid MUST derive at path "a", never at path "10". Every SAID in
    # this module depends on this; get it wrong and nothing cross-verifies from the tenth
    # copy onward (and, via the nested slots 20/21 below, from the first).
    salter = Salter(raw=BULK_SALT)

    def _at(path):
        return Noncer(raw=salter.stretch(size=32, path=path, temp=True),
                      code=NonceDex.Salt_256).qb64

    assert nonces.u(10) == _at("a")
    assert nonces.u(10) != _at("10")
    assert nonces.u(1, 20) == _at("1/14")            # the age edge slots, already >9
    assert nonces.r(255) == _at("ff.r")
    assert _hx(0) == "0" and _hx(15) == "f" and _hx(16) == "10"   # no padding, lowercase

    # Four disjoint derivation spaces, each internally unique.
    spaces = [set(us), set(nested), set(rs), set(bs)]
    for space in spaces:
        assert len(space) == M
    for i, left in enumerate(spaces):
        for right in spaces[i + 1:]:
            assert not (left & right)

    # The per-copy blinding salt SCOPES disclosure: copy k's salt unblinds copy k's
    # registry state and no other copy's. This is the property a single set-wide
    # registry salt (the sibling variant) cannot provide.
    saids = [Diger(ser=f"copy{k}".encode()).qb64 for k in range(M)]
    blinders = [Blinder.blind(acdc=saids[k], state='issued', salt=bs[k], sn=1)
                for k in range(M)]
    assert Blinder.unblind(said=blinders[0].said, acdc=saids[0],
                           states=SET_STATES, salt=bs[0], sn=1).state == 'issued'
    assert Blinder.unblind(said=blinders[0].said, acdc=saids[0],
                           states=SET_STATES, salt=bs[1], sn=1) is None

    # The batch tree over those (stand-in) transaction-event SAIDs.
    events = [Diger(ser=f"bup{k}".encode()).qb64 for k in range(7)]   # odd count on purpose
    tree = _BatchTree(_batch(events))
    assert _BatchTree(_batch(events)).root == tree.root          # stable
    assert _BatchTree(list(reversed(tree.leaves))).root != tree.root   # order-dependent

    # Every event proves against the one root the Issuer seals.
    for said in events:
        proof = _BatchTree.verify(said, tree.prove(said), tree.root)
        assert proof is True
    # A proof is log-sized and discloses no other member's event SAID -- only interior
    # digests. This is the non-disclosure property herd privacy rests on.
    proof = tree.prove(events[0])
    assert len(proof) <= 3                                       # ceil(log2(7))
    material = "".join(sibling for sibling, _ in proof)
    assert all(said not in material for said in events)

    # Negative cases: a non-member, a tampered sibling, a flipped side, a wrong root.
    outsider = Diger(ser=b'not-in-this-batch').qb64
    assert not _BatchTree.verify(outsider, proof, tree.root)
    tampered = [(Diger(ser=b'x').qb64, side) for _, side in proof]
    assert not _BatchTree.verify(events[0], tampered, tree.root)
    flipped = [(sibling, 'L' if side == 'R' else 'R') for sibling, side in proof]
    assert not _BatchTree.verify(events[0], flipped, tree.root)
    assert not _BatchTree.verify(events[0], proof, Diger(ser=b'wrong-root').qb64)

    # A one-event batch is legal (its root is its leaf digest) and an empty one is not.
    assert _BatchTree([events[0]]).root == _BatchTree._leaf(events[0])
    with pytest.raises(ValueError):
        _BatchTree([])


# ===========================================================================
# Phase 2: the bulk sedi-id set, one INDEPENDENT registry per copy.
# ===========================================================================
# Schema helpers, ported verbatim in intent from the sibling SEDI examples
# (test_cp_disclosure.py / test_bulk_issuance_shared_registry.py).
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
# shares this schema (a public, non-correlating identifier). The issuee 'i' is the
# per-copy holder AID ALICE_k and the registry 'rd' is copy k's OWN registry.
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
        "rd": {"description": "This copy's own registry SAID", "type": "string"},
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


# --- Per-copy holder AIDs. ---
# Independent registries ASSUME independent AIDs (spec L2905): a per-copy registry that
# every copy's shared holder AID points back at would decorrelate nothing. So each copy
# k is issued to its OWN holder AID ALICE_k, derived from a HOLDER-ONLY secret salt the
# issuer never sees -- the holder supplies the public AIDs and the issuer commits to
# AIDs it cannot forge. 2*M signers: ALICE_k's current key is _HOLDER_SIGNERS[k], its
# pre-rotated next key _HOLDER_SIGNERS[M+k].
_HOLDER_SIGNERS = Salter(raw=b'indregaliceseckey').signers(count=2 * BULK_SIZE,
                                                           transferable=True, temp=True)
ALICES = [_actor_aid(_HOLDER_SIGNERS[k], _HOLDER_SIGNERS[BULK_SIZE + k])
          for k in range(BULK_SIZE)]

REG_ID_STAMP = "2026-01-05T12:00:00.000000+00:00"
ISSUE_ID_STAMP = "2026-01-05T12:05:00.000000+00:00"

# Alice's identity attribute values -- the SAME across every copy (it is one Alice);
# only the per-copy nonces differ, so the copies are semantically identical but have
# unique SAIDs. DOB puts her well over 21 at the 2026 presentation.
ALICE_DOB = "2000-03-15"


def _sedi_id_attr(nonces, k):
    """Copy k's sedi-id attribute section (issuee inserted by acdcmap via iseaid).

    Per-copy blinding nonces come from the shared bulk salt at hierarchical paths keyed
    on k: the section uuid at "k/0" and one nested-block uuid per attribute at
    "k/1".."k/4".
    """
    return dict(d='', u=nonces.u(k, 0),
                photo=dict(d='', u=nonces.u(k, 1),
                           photo="<state-endorsed-photo-bytes>"),
                dob=dict(d='', u=nonces.u(k, 2), dob=ALICE_DOB),
                residence=dict(d='', u=nonces.u(k, 3),
                               residence="Salt Lake City UT"),
                name=dict(d='', u=nonces.u(k, 4), name="Alice Anders"))


def _issue(copy, nonces, k, *, regid, prior, stamp, kind):
    """Copy k's 'issued' blindable update, on copy k's OWN registry.

    The blinded state binds THIS ONE ACDC's SAID -- not an aggregate. That is the whole
    of "does not use B": a registry holding exactly one credential has nothing to
    aggregate, so the blinding factor v_k, the blinded list [b_k] and the aggregate all
    disappear together. The blinding salt is copy k's own, so unblinding this event
    conveys no ability to unblind any other copy's registry.
    """
    blinder = Blinder.blind(acdc=copy.said, state='issued', salt=nonces.b(k), sn=1)
    return blindate(regid=regid, prior=prior, blid=blinder.said, sn=1,
                    stamp=stamp, kind=kind)


def _sedi_id_set(kind, nonces=None):
    """Build the bulk sedi-id set: M copies, each with its OWN registry.

    Returns (regs, copies, issues): the M registry inceptions, the M sedi-id copies
    (copy k issued by STATE to holder ALICE_k and bound to registry k), and the M
    'issued' blindable updates, one per registry. Ordering has no circularity: each
    registry inception is independent of its copy, the copy binds its registry's SAID as
    'rd', and the update then blinds the copy's SAID.
    """
    if nonces is None:
        nonces = _BulkNonces(BULK_SALT)
    _, schema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    regs = [regcept(israid=STATE, uuid=nonces.r(k), stamp=REG_ID_STAMP, kind=kind)
            for k in range(BULK_SIZE)]
    copies = [acdcmap(israid=STATE, uuid=nonces.u(k), regid=regs[k].said, schema=schema,
                      attribute=_sedi_id_attr(nonces, k), iseaid=ALICES[k], kind=kind)
              for k in range(BULK_SIZE)]
    issues = [_issue(copies[k], nonces, k, regid=regs[k].said, prior=regs[k].said,
                     stamp=ISSUE_ID_STAMP, kind=kind)
              for k in range(BULK_SIZE)]
    return regs, copies, issues


def test_indreg_sedi_id_set_JSON():
    """Phase 2: the State bulk-issues Alice's sedi-id as M copies in M registries.

    Each copy is the SAME sedi-id (same attributes) with a UNIQUE SAID, issued to its
    OWN per-context holder AID ALICE_k, and -- the change from the sibling variant --
    bound to its OWN registry. The registry SAID, which recurs in every context of the
    shared-registry variant and is asserted there as the honest residual, is now
    partitioned like everything else.

    Asserted: every copy is a schema-valid attributive sedi-id issued by STATE to a
    DISTINCT ALICE_k with a DISTINCT rd; there are exactly M registries and no two
    copies share one; each registry's blindable update commits exactly ONE ACDC SAID --
    the operative form of "does not use B" -- and refuses to unblind against any other
    copy's SAID or with any other copy's salt; and neither the state word nor the
    credential SAID crosses the wire in the update.
    """
    kind = Kinds.json
    nonces = _BulkNonces(BULK_SALT)
    regs, copies, issues = _sedi_id_set(kind, nonces)

    assert len(regs) == len(copies) == len(issues) == BULK_SIZE
    for k, copy in enumerate(copies):
        assert copy.ilk == Ilks.acm
        assert copy.sad['i'] == STATE                 # issued by the State/DGO
        assert copy.sad['rd'] == regs[k].said         # ...into ITS OWN registry
        assert copy.sad['a']['i'] == ALICES[k]        # per-copy holder AID
        assert copy.iseaid == ALICES[k]
        assert copy.sad['a']['dob']['dob'] == ALICE_DOB   # same Alice in every copy...
        assert_acdc_schema_valid(copy)

    # ...but every copy is cryptographically distinct in all four axes, the registry now
    # among them.
    assert len(set(ALICES)) == BULK_SIZE                          # AID partitioned
    assert len({c.said for c in copies}) == BULK_SIZE             # copy SAID partitioned
    assert len({c.sad['u'] for c in copies}) == BULK_SIZE         # top-level uuid
    assert len({r.said for r in regs}) == BULK_SIZE               # REGISTRY partitioned
    assert len({c.sad['rd'] for c in copies}) == BULK_SIZE

    # Pinned reproducible values (derived, not pasted -- regenerate by printing on change).
    assert regs[0].said == "EEuVMxLzT6avdqtT2hH4lvXd3U0L0104CmdjLl3t2Q36"   # registry 0
    assert ALICES[0] == "ENwop9UXMNwdx_6SEpLJKouS1MVVzn_a6g6ya7eBfmwV"     # holder AID 0
    assert copies[0].said == "EPeaP6YboVYRkfaps_Rfpz_Po96CTaCjJ1gm-_7Ppyxr"

    # Each registry commits exactly ONE credential. There is no aggregate to be a member
    # of: the blindable update's state binds this copy's SAID directly, so the sibling
    # variant's v_k, [b_k] list and B have nothing to do here.
    for k, issued in enumerate(issues):
        assert issued.ilk == Ilks.bup
        assert issued.sad['rd'] == regs[k].said
        assert issued.sad['p'] == regs[k].said        # chains onto its own inception
        assert issued.sad['b']                        # blinded id present
        assert b"issued" not in issued.raw            # state word stays blinded...
        assert copies[k].said.encode() not in issued.raw   # ...and so does the SAID
        unblinded = Blinder.unblind(said=issued.sad['b'], acdc=copies[k].said,
                                    states=SET_STATES, salt=nonces.b(k), sn=1)
        assert unblinded.state == 'issued'

    # The binding is exact in both directions: another copy's SAID does not unblind this
    # registry's state, and another copy's salt does not either.
    other = (0 + 1) % BULK_SIZE
    assert Blinder.unblind(said=issues[0].sad['b'], acdc=copies[other].said,
                           states=SET_STATES, salt=nonces.b(0), sn=1) is None
    assert Blinder.unblind(said=issues[0].sad['b'], acdc=copies[0].said,
                           states=SET_STATES, salt=nonces.b(other), sn=1) is None


# ===========================================================================
# Phase 3: ONE batch root seal over M registries -- and over the herd.
# ===========================================================================
# Other Utah residents whose registry updates land in the same anchoring batch. They
# are what makes the batch an anonymity set rather than a list of Alice's registries.
# Their credentials are out of scope -- only their TRANSACTION EVENTS reach the tree --
# so each is modeled as a real registry carrying a real blindable update over a stand-in
# credential SAID.
HERD_SALT = b'indregherdsalt00'
HERD_RESIDENTS = 4
HERD_STAMP = "2026-01-05T12:05:00.000000+00:00"
# Spec L2926: an Issuer SHOULD pad thin batches with state-PRESERVING updates so that
# every anchor captures enough events to meet a stated herd-privacy level. Two such
# no-ops are included below; they change nothing and exist only to be leaves.
DECOY_UPDATES = 2
DECOY_STAMP = "2026-01-05T12:06:00.000000+00:00"


def _herd_events(kind, nonces=None):
    """The other residents' transaction events that share Alice's anchoring batch.

    HERD_RESIDENTS residents x BULK_SIZE copies, each an independent registry with its
    own 'issued' blindable update, plus DECOY_UPDATES state-preserving no-ops. Returns
    the list of event SAIDs; nothing else about these residents is modeled.
    """
    if nonces is None:
        nonces = _BulkNonces(HERD_SALT)
    saids = []
    for r in range(HERD_RESIDENTS):
        for k in range(BULK_SIZE):
            tag = f"{_hx(r)}/{_hx(k)}"
            reg = regcept(israid=STATE, uuid=nonces.r(tag), stamp=HERD_STAMP, kind=kind)
            acdc = Diger(ser=f"resident{r}-copy{k}".encode()).qb64
            blinder = Blinder.blind(acdc=acdc, state='issued', salt=nonces.b(tag), sn=1)
            saids.append(blindate(regid=reg.said, prior=reg.said, blid=blinder.said,
                                  sn=1, stamp=HERD_STAMP, kind=kind).said)
    for d in range(DECOY_UPDATES):
        tag = f"decoy{d}"
        reg = regcept(israid=STATE, uuid=nonces.r(tag), stamp=HERD_STAMP, kind=kind)
        blinder = Blinder.blind(acdc='', state='', salt=nonces.b(tag), sn=1)
        saids.append(blindate(regid=reg.said, prior=reg.said, blid=blinder.said, sn=1,
                              stamp=DECOY_STAMP, kind=kind).said)
    return saids


def _anchor(*eventSaidGroups):
    """Anchor one batch: build the tree and return (tree, sealer).

    The Sealer is the real KERI seal the Issuer would place in its KEL -- a SealRoot,
    whose CESR count code is MerkleRootSealSingles ('-R'). ONE of these covers every
    registry in the batch, which is the whole point: M registry inceptions anchored
    side by side in a KEL event would let any third party reading that KEL reassemble
    the bulk-issued set, moving the correlator from the ACDC to the KEL rather than
    removing it.
    """
    tree = _BatchTree(_batch(*eventSaidGroups))
    return tree, Sealer(crew=SealRoot(rd=tree.root))


def _verify_anchored(said, tree, sealer):
    """A Validator's check that the Issuer committed to transaction event `said`:
    the proof reconstructs the sealed root. Returns True or False."""
    return _BatchTree.verify(said, tree.prove(said), sealer.crew.rd)


def test_indreg_batch_anchor_JSON():
    """Phase 3: M registries, ONE seal, and a herd that makes the batch mean nothing.

    The State anchors a single Merkle-root seal covering every transaction event it
    updated in this batch: Alice's M sedi-id registries alongside four other residents'
    twenty registries and two state-preserving decoys. A Validator given one event and
    its inclusion proof verifies the State's commitment to that event and learns nothing
    about any other leaf -- not which other events exist, not whose they are, not that
    any two belong to one holder.

    Asserted: the seal is a real SealRoot carrying the tree root; every one of Alice's
    events and every herd event proves under it; an event from a different batch does
    not; a proof discloses no other event SAID and the seal itself discloses no registry
    SAID; Alice's M registries are covered by exactly ONE anchor; and her leaves are
    interleaved with the herd rather than sitting in a contiguous run, so a proof's
    disclosed path does not hand two colluding verifiers an adjacency.
    """
    kind = Kinds.json
    nonces = _BulkNonces(BULK_SALT)
    regs, copies, issues = _sedi_id_set(kind, nonces)
    aliceEvents = [issued.said for issued in issues]
    herdEvents = _herd_events(kind)

    tree, sealer = _anchor(aliceEvents, herdEvents)

    # The anchor is one real KERI Merkle-root seal over the whole batch.
    assert sealer.clan is SealRoot
    assert sealer.crew.rd == tree.root
    assert len(tree.leaves) == BULK_SIZE + HERD_RESIDENTS * BULK_SIZE + DECOY_UPDATES

    # M independent registries; ONE anchoring seal covering all of them.
    assert len({issued.sad['rd'] for issued in issues}) == BULK_SIZE
    assert len({r.said for r in regs}) == BULK_SIZE

    # Every event in the batch proves; an event from another batch does not.
    for said in aliceEvents + herdEvents:
        assert _verify_anchored(said, tree, sealer)
    otherBatch = _BatchTree(_batch([Diger(ser=b'some other batch').qb64]))
    assert not _BatchTree.verify(otherBatch.leaves[0],
                                 otherBatch.prove(otherBatch.leaves[0]), sealer.crew.rd)

    # The proof for Alice's copy-0 event discloses interior digests only: no other
    # event's SAID, and nothing that names a registry.
    proof = tree.prove(aliceEvents[0])
    material = "".join(sibling for sibling, _ in proof)
    assert all(said not in material for said in tree.leaves if said != aliceEvents[0])
    assert all(reg.said not in material for reg in regs)
    # Nor does the seal itself: it is one digest, and it names nothing.
    assert all(reg.said not in sealer.qb64 for reg in regs)
    assert all(said not in sealer.qb64 for said in tree.leaves)

    # The herd dominates the batch, and Alice's events are interleaved with it rather
    # than occupying a contiguous run -- an inclusion proof discloses the leaf's path,
    # so contiguity would let two colluding verifiers notice their events are adjacent.
    positions = sorted(tree.leaves.index(said) for said in aliceEvents)
    assert len(aliceEvents) * 4 <= len(tree.leaves)          # she is a small minority
    assert positions != list(range(positions[0], positions[0] + len(positions)))
    assert any(right - left > 1 for left, right in zip(positions, positions[1:]))

    # Pinned reproducible value: the batch root the State would seal.
    assert tree.root == "EOdrbhMmEtYQXYMy9TZso2k6FtHL7K4Q8Ic9S3FcJggz"


# ===========================================================================
# Phase 4: the bulk sedi-age set, index-aligned to sedi-id via an E1E edge.
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
# boolean vector where hiding WHICH thresholds are asserted is the point. It REQUIRES an
# E1E identity edge back to the SAME-index sedi-id copy (same subject, issuer != issuee),
# so the identity relation is schema-enforced.
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
        "rd": {"description": "This copy's own registry SAID", "type": "string"},
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

# The sedi-age bulk set derives its per-copy nonces from a DISTINCT salt so its uuids,
# registry uuids and blinding salts never collide with the sedi-id set's.
BULK_AGE_SALT = b'indregageexsalt0'
REG_AGE_STAMP = "2026-01-06T12:00:00.000000+00:00"
ISSUE_AGE_STAMP = "2026-01-06T12:05:00.000000+00:00"

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
    """Build the bulk sedi-age set: M copies, M more independent registries, E1E-aligned.

    Returns (regs, copies, aggors, issues). Copy k is issued by STATE to holder ALICE_k,
    bound to ITS OWN registry, and carries an E1E edge to sedi-id copy k -- the SAME
    subject (ALICE_k) reached through a different section (the aggregate far node,
    A[1].i). The Aggor per copy is returned so callers can selectively disclose over the
    aggregate.
    """
    if nonces is None:
        nonces = _BulkNonces(BULK_AGE_SALT)
    _, schema = _saidify_schema(dict(AGE_SCHEMA_MAD), kind=kind)
    regs = [regcept(israid=STATE, uuid=nonces.r(k), stamp=REG_AGE_STAMP, kind=kind)
            for k in range(BULK_SIZE)]
    copies, aggors = [], []
    for k in range(BULK_SIZE):
        edge = dict(d='', u=nonces.u(k, _AGE_EDGE_SEC),
                    identity=dict(d='', u=nonces.u(k, _AGE_EDGE_ID),
                                  n=idCopies[k].said,
                                  s=idCopies[k].sad['s']['$id'], o='E1E'))
        aggor = Aggor(ael=_age_ael(nonces, k), makify=True, kind=kind)
        age = acdcagg(israid=STATE, uuid=nonces.u(k), regid=regs[k].said, schema=schema,
                      aggregate=aggor.ael, edge=edge, kind=kind)
        copies.append(age)
        aggors.append(aggor)
    issues = [_issue(copies[k], nonces, k, regid=regs[k].said, prior=regs[k].said,
                     stamp=ISSUE_AGE_STAMP, kind=kind)
              for k in range(BULK_SIZE)]
    return regs, copies, aggors, issues


def test_indreg_sedi_age_set_JSON():
    """Phase 4: the bulk sedi-age set, index-aligned to sedi-id by an E1E edge.

    The State bulk-issues Alice's sedi-age as M copies, each to the SAME per-context
    holder AID ALICE_k as the matching sedi-id copy, each in its OWN registry, and each
    carrying an E1E identity edge to sedi-id copy k. The standing edge is safe for the
    same reason it is safe in the sibling variant -- it points at a fresh, per-context
    far node -- and now the registry behind that far node is per-context too, so a
    verifier who walks the edge and then looks up the far node's registry state still
    learns nothing that another verifier could join on.

    Asserted: every copy is a schema-valid aggregative sedi-age issued to ALICE_k in its
    own registry, over-21 true / over-65 false; the E1E edge is index-aligned and
    verifies as the same subject; the schema rejects a swapped operator and a non-boolean
    flag; selective disclosure reveals over-21 while withholding the other thresholds;
    and the two bulk sets meet ONLY at the per-index holder AID -- disjoint SAIDs,
    disjoint registries, 2*M registries in total.
    """
    kind = Kinds.json
    idNonces = _BulkNonces(BULK_SALT)
    idRegs, idCopies, _ = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageRegs, ageCopies, ageAggors, ageIssues = _sedi_age_set(kind, idCopies, ageNonces)

    over65Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(65)
    assert len(ageCopies) == BULK_SIZE
    for k, age in enumerate(ageCopies):
        assert age.ilk == Ilks.acg
        assert age.sad['i'] == STATE                          # issued by the State/DGO
        assert age.sad['rd'] == ageRegs[k].said               # ...into ITS OWN registry
        assert age.sad['A'][AGE_ISSUEE]['i'] == ALICES[k]     # per-copy holder AID
        assert age.iseaid == ALICES[k]
        assert age.sad['A'][AGE_OVER21]['over21'] is True     # over 21...
        assert age.sad['A'][over65Pos]['over65'] is False     # ...not over 65
        ageSchema = assert_acdc_schema_valid(age)
        # Index-aligned E1E edge -> the SAME-index sedi-id copy.
        assert age.sad['e']['identity']['o'] == 'E1E'
        assert age.sad['e']['identity']['n'] == idCopies[k].said
        assert _verify_identity_edge(age, idCopies[k])
        assert age.iseaid == idCopies[k].iseaid == ALICES[k]  # same subject per context

    # Schema teeth: the identity operator is const-pinned to E1E -- a swapped operator
    # and a non-boolean flag are both rejected at validation.
    badOp = json.loads(json.dumps(ageCopies[0].sad))
    badOp['e']['identity']['o'] = 'I2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(badOp)
    badFlag = json.loads(json.dumps(ageCopies[0].sad))
    badFlag['A'][AGE_OVER21] = dict(badFlag['A'][AGE_OVER21], over21="yes")
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(badFlag)

    # Distinct across copies, registries included; each registry commits its own copy.
    assert len({a.said for a in ageCopies}) == BULK_SIZE
    assert len({r.said for r in ageRegs}) == BULK_SIZE
    for k, issued in enumerate(ageIssues):
        assert Blinder.unblind(said=issued.sad['b'], acdc=ageCopies[k].said,
                               states=SET_STATES, salt=ageNonces.b(k),
                               sn=1).state == 'issued'

    # Pinned reproducible values (derived, not pasted).
    assert ageRegs[0].said == "EGUtUfYkaKyF3jq45ew8FOB4f0izb7rLPXgLiaZkcDzn"
    assert ageCopies[0].said == "EAExbHDFN80m_9OPguIOpyzAsExodDs-pNJY-f4Nzr6v"
    assert ageAggors[0].agid == "EBimirc3NBSuQQZLBPyuF6LP8W6ywStAQZm34DFNQdUj"

    # Selective disclosure over copy 0's aggregate: reveal over-21 + issuee, hide the rest.
    disclosed, _ = ageAggors[0].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    assert disclosed[AGE_ISSUEE]['i'] == ALICES[0]
    assert disclosed[AGE_OVER21]['over21'] is True
    assert Aggor.verifyDisclosure(disclosed, kind=kind)
    assert "over55" not in json.dumps(disclosed) and "over65" not in json.dumps(disclosed)

    # The two bulk sets meet only at the per-index holder AID (same subject). Everything
    # else is disjoint -- and there are now 2*M registries for one resident's two
    # credentials, which is the storage cost spec L2911 warns about, stated plainly.
    assert ageCopies[0].iseaid == idCopies[0].iseaid          # same subject ALICE_0
    assert {a.said for a in ageCopies}.isdisjoint({c.said for c in idCopies})
    assert {r.said for r in ageRegs}.isdisjoint({r.said for r in idRegs})
    assert len({r.said for r in ageRegs} | {r.said for r in idRegs}) == 2 * BULK_SIZE


# ===========================================================================
# Phase 5: per-verifier presentations + the partition property (the headline).
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

PRESENT_SALT = b'indregpresalt000'
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


def _context_correlators(k, idCopies, idIssues, ageCopies, ageAggors, ageIssues, pres):
    """Every identifier a verifier of context k can receive that is holder-specific.

    Nine values now, against the sibling variant's five: the holder AID, both source
    SAIDs, the aggregate AGID, the fresh presentation SAID -- and the four this variant
    adds to the partitioned column, both source REGISTRY SAIDs and both TRANSACTION
    EVENT SAIDs. Disjoint across contexts is the structural un-joinability proof.
    """
    return {ALICES[k], idCopies[k].said, ageCopies[k].said, ageAggors[k].agid,
            pres.said, idCopies[k].sad['rd'], ageCopies[k].sad['rd'],
            idIssues[k].said, ageIssues[k].said}


def test_indreg_partition_across_verifiers_JSON():
    """Phase 5: two disparate verifiers get disjoint identifier sets -- and this time
    the residual column is empty of anything holder-specific.

    Alice proves over-21 at two mutually-unrelated venues. Her wallet maps each verifier
    to its own copy index, so the Alcove gets copy 0 and the dispensary copy 1: different
    holder AIDs, different source SAIDs, different AGIDs, different presentation SAIDs
    -- all of which the shared-registry sibling already delivers -- and now also
    different REGISTRIES and different transaction events, which it does not.

    What is left over is the point of the whole exercise. In the sibling variant the
    honest residual is the shared registry SAID and the aggregate B, recurring in every
    context: a contract-gated 2nd-party correlator. Here there is no aggregate at all,
    and the only values both contexts share are ones the entire population shares --
    the issuer AID, the two schema SAIDs, and the batch root, which covers other
    residents' events too and therefore singles out no one.
    """
    kind = Kinds.json
    idNonces = _BulkNonces(BULK_SALT)
    idRegs, idCopies, idIssues = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageRegs, ageCopies, ageAggors, ageIssues = _sedi_age_set(kind, idCopies, ageNonces)
    presNonces = _BulkNonces(PRESENT_SALT)

    # Two disparate verifiers; the wallet maps them to distinct copy indices.
    v1, v2 = ALCOVE, DISPENSARY
    k1, k2 = _copy_index_for(v1), _copy_index_for(v2)
    assert k1 != k2                                       # per-verifier spend is injective
    pres1 = _presentation(kind, v1, idCopies, ageCopies, presNonces)
    pres2 = _presentation(kind, v2, idCopies, ageCopies, presNonces)
    assert pres1.said == "EN4G8PuyrKW-eIfkZXGLrtzoKZx-B8jQEn5Y1vDaDYql"   # Alcove context
    assert pres2.said == "EDC1XX7NqH4YOBnNG-txVw5z3XNsFZGH61FDvlHZPo82"   # dispensary

    # Each presentation verifies (I2I same-holder to copy-k sources) and rides the
    # over-21 selective disclosure.
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

    # --- PARTITIONED: the two contexts share NONE of the holder-specific identifiers. ---
    corr1 = _context_correlators(k1, idCopies, idIssues, ageCopies, ageAggors,
                                 ageIssues, pres1)
    corr2 = _context_correlators(k2, idCopies, idIssues, ageCopies, ageAggors,
                                 ageIssues, pres2)
    assert corr1.isdisjoint(corr2)                        # THE headline: no join key
    assert len(corr1) == 9                                # nine distinct correlators...
    assert ALICES[k1] != ALICES[k2]                       # holder AID
    assert idCopies[k1].said != idCopies[k2].said         # sedi-id SAID
    assert ageCopies[k1].said != ageCopies[k2].said       # sedi-age SAID
    assert ageAggors[k1].agid != ageAggors[k2].agid       # AGID
    assert pres1.said != pres2.said                       # presentation SAID

    # ...the last four of which the shared-registry variant leaves shared. This is the
    # residual that variant asserts and this one closes.
    assert idCopies[k1].sad['rd'] != idCopies[k2].sad['rd']    # sedi-id REGISTRY
    assert ageCopies[k1].sad['rd'] != ageCopies[k2].sad['rd']  # sedi-age REGISTRY
    assert idIssues[k1].said != idIssues[k2].said              # TEL event
    assert ageIssues[k1].said != ageIssues[k2].said

    # --- PUBLIC, non-correlating: what both contexts DO share is shared by everyone. ---
    assert idCopies[k1].sad['i'] == idCopies[k2].sad['i'] == STATE          # issuer
    assert idCopies[k1].sad['s']['$id'] == idCopies[k2].sad['s']['$id']     # sedi-id schema
    assert ageCopies[k1].sad['s']['$id'] == ageCopies[k2].sad['s']['$id']   # sedi-age schema
    # The batch root is shared by both contexts -- and by four other residents, which is
    # what stops it being a correlator. A root over Alice's events ALONE would be one.
    tree, sealer = _anchor([i.said for i in idIssues], [i.said for i in ageIssues],
                           _herd_events(kind))
    assert _verify_anchored(idIssues[k1].said, tree, sealer)
    assert _verify_anchored(idIssues[k2].said, tree, sealer)
    assert len(tree.leaves) > 2 * BULK_SIZE               # the herd is in there too

    # --- Guardrail: the wallet mapping is 1-verifier -> 1-copy; a third distinct verifier
    # gets a third distinct index (never a reused copy across contexts). ---
    assert len({_copy_index_for(v) for v in VERIFIERS}) == len(VERIFIERS)


# ===========================================================================
# Phase 6: disclosure gating (registry material post-agree) + per-copy revocation.
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

    Its signature has NO parameter for source-credential SAIDs, for a registry SAID, for
    a transaction event, or for a blinding salt, so the pre-agree offer STRUCTURALLY
    cannot carry a stable holder correlator. It commits only the fresh, per-context
    presentation SAID (safe because it is built with a per-presentation salt, so it is an
    ephemeral, not a stable correlator) and a public governance ref.

    Independent registries do NOT retire this discipline, and it is worth being clear why,
    because the naive reading is that they do. What they retire is the registry SAID as a
    SET-WIDE correlator: it no longer ties copy k to copies 0..M-1. It remains a perfectly
    good PER-CONTEXT correlator -- disclose rd_k pre-agree to a verifier who then spurns
    the exchange, and that verifier keeps a durable handle on this context forever. Spec
    L2844-2850's three graduated-disclosure methods for `rd` therefore still apply.

    Its query block carries an EMPTY disclosure-paths list, `dp: []`. Because this offer
    is SOLICITED -- `prior` binds the apply it answers -- an empty `dp` means "the same
    paths the apply asked for" (#1549).
    """
    return exchange(sender=sender, receiver=receiver, route="/ipex/offer", prior=prior,
                    modifiers=dict(dp=[]),
                    attributes=dict(acdc=presentationSaid, governance=governance),
                    stamp=OFFER_STAMP, kind=kind)


def _verify_issuance(copy, *, reg, event, blind, proof, sealer):
    """The Disclosee's proof-of-issuance check for an independent-registry ACDC.

    Spec L2871 lists five steps for the shared-registry variant: recompute the SAID,
    recompute b_k, find it in the disclosed [b_k] list, recompute B from the list, and
    confirm the Issuer sealed B. With one ACDC per registry there is no list and no
    aggregate, and the middle three collapse into two different ones -- unblind this
    registry's state, and prove this registry's event under the Issuer's batch root:

      1. the credential's `rd` names this registry, this registry was incepted by the
         credential's OWN issuer, and the event belongs to it. The middle clause is the
         one it would be easy to skip: `rd` is a secure DISCOVERY mechanism (spec L2842),
         so following it must end at a registry the credential's issuer controls. Skip
         it and a holder can point the verifier at a registry SHE incepted and keeps
         'issued' forever;
      2. the event's blinded state unblinds, with the blind disclosed FOR THIS ONE EVENT,
         to a state bound to THIS COPY's SAID (a wrong blind or a wrong SAID yields None);
      3. the event is a leaf under the root the Issuer sealed in its KEL.

    TAKES THE BLIND, NOT THE SALT, AND THE DIFFERENCE IS THE WHOLE PROPERTY. An earlier
    revision of this example passed `salt=` here and disclosed the per-copy blinding salt
    in the grant. That is more authority than the disclosure needs and more than the spec
    contemplates: `Blinder.makeUUID` derives the blind as Salter(salt).stretch(path=hex(sn))
    (src/keri/core/structing.py:1421-1436), so the sequence number is the ENTIRE derivation
    path and there is no per-event secret. A Disclosee holding the salt can therefore
    unblind every event in the registry, past and future, without ever interacting again.

    That defeats the remedy spec L2131 describes -- "the Discloser may then request that
    the Issuer update the state with a new blinding factor… The Disclosee cannot then
    observe the current state of the TEL without yet another disclosure interaction" --
    and it contradicts spec L2133, which reserves the salt to the Issuer and Discloser
    alone: "Only the Issuer and Discloser have a copy of the secret salt, so only they can
    independently derive the current blind from the sequence number."

    So the Discloser computes Blinder.makeUUID(salt=..., sn=n) for the one event being
    disclosed and sends THAT. `Blinder.unblind` accepts it directly and skips derivation
    (structing.py:1483, :1518-1521). Each later state change then requires a fresh
    disclosure, which is what makes the re-blinding remedy real. Note this is the minimum
    correction, not a finished disclosure protocol: event binding, replay, freshness and
    substitution resistance are out of scope here.

    Returns the state string ('issued' / 'revoked') or None if any step fails.
    """
    if copy.sad['rd'] != reg.said or event.sad['rd'] != reg.said:
        return None
    if reg.sad['i'] != copy.sad['i']:      # the issuer controls the registry it names
        return None
    blinder = Blinder.unblind(said=event.sad['b'], acdc=copy.said, states=SET_STATES,
                              uuid=blind)
    if blinder is None:
        return None
    if not _BatchTree.verify(event.said, proof, sealer.crew.rd):
        return None
    return blinder.state


def test_indreg_disclosure_gating_and_revocation_JSON():
    """Phase 6: the registry material rides only in the grant; one copy revokes alone.

    Two properties. First, disclosure gating: the pre-agree /ipex/offer commits only the
    fresh presentation SAID and public governance, built with a constructor that cannot
    carry the source SAIDs, the registry SAIDs, the transaction events or any blinding
    material (#1532's make-it-unrepresentable guidance). All of that appears ONLY in the
    grant, after a valid signed agree, so a verifier who spurns walks away with no stable
    correlator and no proof of issuance. Note what the grant does and does not carry: the
    blind for the ONE event being proved, never the per-copy blinding salt that would
    derive every other event's blind too (see _verify_issuance). Second, revocation, which
    this variant changes
    qualitatively: the State revokes the copy spent at the Alcove and the copy spent at
    the dispensary is untouched, because they live in different registries. The
    shared-registry variant cannot express that -- one registry, one state, all M copies.
    """
    kind = Kinds.json
    idNonces = _BulkNonces(BULK_SALT)
    idRegs, idCopies, idIssues = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageRegs, ageCopies, ageAggors, ageIssues = _sedi_age_set(kind, idCopies, ageNonces)
    presNonces = _BulkNonces(PRESENT_SALT)
    tree, sealer = _anchor([i.said for i in idIssues], [i.said for i in ageIssues],
                           _herd_events(kind))

    verifier = ALCOVE
    k = _copy_index_for(verifier)
    pres = _presentation(kind, verifier, idCopies, ageCopies, presNonces)
    presSchemaSaid = pres.sad['s']['$id']

    # 1. apply (verifier -> holder): the challenge, as disclosure paths in the query
    # block. Each entry is a TRIPLE, (schemaSAID, prefix, [paths]) (@SmithSamuelM,
    # #1549). The middle element is the DAG-absolute route to the ACDC the entry names,
    # either empty or a route that both begins and ends with '/'; the effective path is
    # prefix + entry with nothing inserted between them, so an entry never leads with
    # '/'. Every prefix is empty here, which leaves the paths ACDC-relative and lets the
    # breadth-first POSITION of each entry say which ACDC it is about -- an ordering
    # required even where a prefix would make it unnecessary.
    #
    # All three nodes get an entry, in the order the presentation's edge block names
    # them: the presentation itself, then sedi-id, then sedi-age. With empty prefixes a
    # skipped node would leave an entry sitting at an index that belongs to another ACDC.
    # The zeroth asks the origin for its issuer and issuee; sedi-id for its issuee alone,
    # which both edge operators are checked against -- I2I wants the presentation's
    # issuer to be the issuee of each source, E1E wants sedi-age and sedi-id to share
    # one -- and sedi-age for the aggregate's issuee and the over-21 flag.
    apply = exchange(sender=verifier, receiver=ALICES[k], route="/ipex/apply",
                     modifiers=dict(dp=[[presSchemaSaid, "", ["i", "a/i"]],
                                        [idCopies[k].sad['s']['$id'], "", ["a/i"]],
                                        [ageCopies[k].sad['s']['$id'], "",
                                         ["A/i", "A/over21"]]]),
                     attributes=dict(m="Prove over-21.", g=GOVERNANCE_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['r'] == "/ipex/apply"
    assert apply.sad['q']['dp'] == [[presSchemaSaid, "", ["i", "a/i"]],
                                    [idCopies[k].sad['s']['$id'], "", ["a/i"]],
                                    [ageCopies[k].sad['s']['$id'], "",
                                     ["A/i", "A/over21"]]]
    dp = apply.sad['q']['dp']
    assert all(len(entry) == 3 for entry in dp)                 # (ssaid, prefix, paths)
    assert [entry[1] for entry in dp] == ["", "", ""]           # relative: position names
    assert all(not p.startswith("/") for _, _, paths in dp for p in paths)
    # The schema SAID is shared across the whole bulk set by design; the request names
    # it, never a copy SAID and never a registry, so the apply introduces no correlator.
    assert all(c.said.encode() not in apply.raw for c in idCopies + ageCopies)
    assert all(r.said.encode() not in apply.raw for r in idRegs + ageRegs)

    # 2. offer (holder -> verifier): via the leak-proof constructor. Nothing stable.
    offer = _offer(kind, sender=ALICES[k], receiver=verifier, prior=apply.said,
                   presentationSaid=pres.said, governance=GOVERNANCE_SAID)
    assert offer.sad['p'] == apply.said
    assert offer.sad['q']['dp'] == []                           # solicited: same paths
    assert pres.said.encode() in offer.raw                      # fresh per-context: safe
    assert idCopies[k].said.encode() not in offer.raw           # source SAID withheld
    assert ageCopies[k].said.encode() not in offer.raw
    assert idRegs[k].said.encode() not in offer.raw             # REGISTRY withheld
    assert ageRegs[k].said.encode() not in offer.raw
    assert idIssues[k].said.encode() not in offer.raw           # TEL event withheld
    assert ageIssues[k].said.encode() not in offer.raw
    assert ageNonces.b(k).encode() not in offer.raw             # blinding salt withheld
    assert sealer.crew.rd.encode() not in offer.raw             # batch root withheld

    # 3. agree (verifier -> holder): signed acceptance binding the offer.
    agree = exchange(sender=verifier, receiver=ALICES[k], route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    vSigner = _SIGNERS[2 + k]                                   # the verifier's key
    vSig = vSigner.sign(ser=agree.raw, index=0)
    keyState = Verfer(qb64=vSigner.verfer.qb64)
    assert keyState.verify(sig=vSig.raw, ser=agree.raw)

    # 4. The gate: the holder discloses the whole issuance-proof bundle ONLY on a valid,
    # offer-binding, signed agree.
    def disclose(agreeMsg, sig):
        if not (agreeMsg.sad['r'] == "/ipex/agree" and agreeMsg.sad['p'] == offer.said
                and keyState.verify(sig=sig.raw, ser=agreeMsg.raw)):
            return None
        ageDisc, _ = ageAggors[k].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
        return exchange(sender=ALICES[k], receiver=verifier, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(
                            acdc=pres.sad, ageDisclosure=ageDisc,
                            issuance=dict(rip=ageRegs[k].sad, event=ageIssues[k].sad,
                                          blind=Blinder.makeUUID(
                                              salt=ageNonces.b(k), sn=1),
                                          proof=tree.prove(ageIssues[k].said),
                                          root=sealer.crew.rd)),
                        stamp=GRANT_STAMP, kind=kind)

    # A forged signature unlocks nothing.
    assert disclose(agree, _SIGNERS[0].sign(ser=agree.raw, index=0)) is None
    # A valid agree unlocks the grant; the registry material appears ONLY now.
    grant = disclose(agree, vSig)
    assert grant is not None and grant.sad['p'] == agree.said
    assert ageRegs[k].said.encode() in grant.raw                # registry revealed...
    assert ageIssues[k].said.encode() in grant.raw              # ...event revealed...
    assert ageNonces.b(k).encode() not in grant.raw             # ...salt STILL withheld...
    assert Blinder.makeUUID(salt=ageNonces.b(k),
                            sn=1).encode() in grant.raw         # ...one event's blind only
    assert idCopies[k].said.encode() in grant.raw               # ...source SAIDs revealed
    assert ageCopies[k].said.encode() in grant.raw

    # The verifier walks the chain from the grant: the presentation's edges name the
    # sources, the source's registry proves 'issued' under the State's sealed batch root,
    # and the aggregate discloses over-21.
    granted = grant.sad['a']['acdc']
    assert granted['e']['age']['n'] == ageCopies[k].said
    assert granted['e']['identity']['n'] == idCopies[k].said
    bundle = grant.sad['a']['issuance']
    # The bundle discloses the registry INCEPTION, not merely its SAID, so the verifier
    # can confirm the State incepted it rather than taking the holder's word for `rd`.
    assert bundle['rip']['d'] == ageRegs[k].said and bundle['rip']['i'] == STATE
    assert _verify_issuance(ageCopies[k], reg=ageRegs[k], event=ageIssues[k],
                            blind=bundle['blind'],
                            proof=[tuple(p) for p in bundle['proof']],
                            sealer=sealer) == 'issued'
    assert grant.sad['a']['ageDisclosure'][AGE_OVER21]['over21'] is True

    # The disclosed bundle proves THIS copy and no other: another copy's registry, event
    # or salt fails the same check.
    other = (k + 1) % BULK_SIZE
    assert _verify_issuance(ageCopies[k], reg=ageRegs[other], event=ageIssues[k],
                            blind=bundle['blind'],
                            proof=[tuple(p) for p in bundle['proof']],
                            sealer=sealer) is None
    assert _verify_issuance(ageCopies[k], reg=ageRegs[k], event=ageIssues[k],
                            blind=Blinder.makeUUID(salt=ageNonces.b(other), sn=1),
                            proof=[tuple(p) for p in bundle['proof']],
                            sealer=sealer) is None

    # And the discovery check has teeth. A credential claiming State issuance whose `rd`
    # points at a registry the HOLDER incepted -- where she can keep the state 'issued'
    # forever -- fails, even though every SAID in the bundle is internally consistent and
    # the event proves under a real batch root. Following `rd` must end at a registry the
    # credential's own issuer controls.
    rogueNonces = _BulkNonces(b'indregrogueslt00')
    rogueReg = regcept(israid=ALICES[k], uuid=rogueNonces.r(k), stamp=REG_AGE_STAMP,
                       kind=kind)
    rogueCopy = acdcagg(israid=STATE, uuid=rogueNonces.u(k), regid=rogueReg.said,
                        schema=ageCopies[k].sad['s'],
                        aggregate=Aggor(ael=_age_ael(rogueNonces, k), makify=True,
                                        kind=kind).ael,
                        edge=ageCopies[k].sad['e'], kind=kind)
    rogueIssue = _issue(rogueCopy, rogueNonces, k, regid=rogueReg.said,
                        prior=rogueReg.said, stamp=ISSUE_AGE_STAMP, kind=kind)
    rogueTree, rogueSealer = _anchor([rogueIssue.said], _herd_events(kind))
    assert _verify_anchored(rogueIssue.said, rogueTree, rogueSealer)   # the event is real
    assert rogueCopy.sad['rd'] == rogueReg.said                        # and self-consistent
    assert _verify_issuance(rogueCopy, reg=rogueReg, event=rogueIssue,
                            blind=Blinder.makeUUID(salt=rogueNonces.b(k), sn=1),
                            proof=rogueTree.prove(rogueIssue.said),
                            sealer=rogueSealer) is None                # yet refused

    # --- Revocation, per copy. The State revokes the copy spent at the Alcove. ---
    revokedBlinder = Blinder.blind(acdc=ageCopies[k].said, state='revoked',
                                   salt=ageNonces.b(k), sn=2)
    revoked = blindate(regid=ageRegs[k].said, prior=ageIssues[k].said,
                       blid=revokedBlinder.said, sn=2, stamp=REVOKE_STAMP, kind=kind)
    assert revoked.sad['p'] == ageIssues[k].said                # chains onto issuance
    assert b"revoked" not in revoked.raw                        # state word stays blinded

    # The revocation is a transaction event like any other and lands in a LATER batch,
    # mixed with the herd again.
    laterTree, laterSealer = _anchor([revoked.said], _herd_events(kind))
    assert _verify_anchored(revoked.said, laterTree, laterSealer)
    # The verifier cannot follow the registry on its own: the blind it was given covers
    # sn=1 only, so reading sn=2 needs a FRESH disclosure from the holder. That is spec
    # L2131's remedy, and it works only because the grant sent a blind and not the salt.
    assert _verify_issuance(ageCopies[k], reg=ageRegs[k], event=revoked,
                            blind=Blinder.makeUUID(salt=ageNonces.b(k), sn=1),
                            proof=laterTree.prove(revoked.said),
                            sealer=laterSealer) is None            # sn=1 blind is useless
    assert _verify_issuance(ageCopies[k], reg=ageRegs[k], event=revoked,
                            blind=Blinder.makeUUID(salt=ageNonces.b(k), sn=2),
                            proof=laterTree.prove(revoked.said),
                            sealer=laterSealer) == 'revoked'       # re-disclosed

    # THE new capability: the dispensary's copy is untouched. Different registry,
    # different state. The shared-registry variant revokes all M or none.
    assert ageRegs[other].said != ageRegs[k].said
    assert _verify_issuance(ageCopies[other], reg=ageRegs[other],
                            event=ageIssues[other],
                            blind=Blinder.makeUUID(salt=ageNonces.b(other), sn=1),
                            proof=tree.prove(ageIssues[other].said),
                            sealer=sealer) == 'issued'

    # The graph still binds (edges are immutable), yet the Alcove's own status check now
    # returns 'revoked' where it returned 'issued', so a status-checking verifier refuses.
    assert _verify_presentation(pres, idCopies[k], ageCopies[k])   # graph still binds...
    assert _verify_issuance(ageCopies[k], reg=ageRegs[k], event=revoked,
                            blind=Blinder.makeUUID(salt=ageNonces.b(k), sn=2),
                            proof=laterTree.prove(revoked.said),
                            sealer=laterSealer) != 'issued'        # ...yet status forbids


# ===========================================================================
# Phase 7: the invariants hold across every serialization kind.
# ===========================================================================
@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_indreg_serialization_kinds(kind):
    """Phases 2-6 invariants hold across every serialization kind, not just JSON.

    Exercises the same flows -- both bulk sets issued to per-context holder AIDs in
    per-copy registries, the index-aligned E1E edge, the batch root seal and its
    inclusion proofs, the per-verifier partition, and the per-copy blindable state --
    over CESR (the native KERI wire format) and CBOR/MGPK, asserting the behavioral
    invariants without pinning per-kind SAIDs. (The no-correlator-on-the-wire substring
    checks are JSON-specific: the CESR wire form base64-encodes the payload.)
    """
    idNonces = _BulkNonces(BULK_SALT)
    idRegs, idCopies, idIssues = _sedi_id_set(kind, idNonces)
    ageNonces = _BulkNonces(BULK_AGE_SALT)
    ageRegs, ageCopies, ageAggors, ageIssues = _sedi_age_set(kind, idCopies, ageNonces)
    tree, sealer = _anchor([i.said for i in idIssues], [i.said for i in ageIssues],
                           _herd_events(kind))

    # Per copy: schema-valid; issued to its own holder AID in its own registry;
    # index-aligned E1E; its registry state provable under the one sealed batch root.
    for k in range(BULK_SIZE):
        assert idCopies[k].ilk == Ilks.acm and idCopies[k].kind == kind
        assert ageCopies[k].ilk == Ilks.acg
        assert idCopies[k].iseaid == ageCopies[k].iseaid == ALICES[k]
        assert idCopies[k].sad['rd'] == idRegs[k].said
        assert ageCopies[k].sad['rd'] == ageRegs[k].said
        assert_acdc_schema_valid(idCopies[k])
        assert_acdc_schema_valid(ageCopies[k])
        assert _verify_identity_edge(ageCopies[k], idCopies[k])       # E1E on every kind
        for copy, regs, issues, nonces in ((idCopies[k], idRegs, idIssues, idNonces),
                                           (ageCopies[k], ageRegs, ageIssues, ageNonces)):
            assert _verify_issuance(copy, reg=regs[k], event=issues[k],
                                    blind=Blinder.makeUUID(salt=nonces.b(k), sn=1),
                                    proof=tree.prove(issues[k].said),
                                    sealer=sealer) == 'issued'

    # 2*M independent registries under exactly ONE anchoring seal, on every kind.
    assert len({r.said for r in idRegs} | {r.said for r in ageRegs}) == 2 * BULK_SIZE
    assert sealer.crew.rd == tree.root

    # Partition across two contexts holds on every kind, registries and events included.
    presNonces = _BulkNonces(PRESENT_SALT)
    k1, k2 = _copy_index_for(ALCOVE), _copy_index_for(DISPENSARY)
    pres1 = _presentation(kind, ALCOVE, idCopies, ageCopies, presNonces)
    pres2 = _presentation(kind, DISPENSARY, idCopies, ageCopies, presNonces)
    assert _verify_presentation(pres1, idCopies[k1], ageCopies[k1])
    assert _verify_presentation(pres2, idCopies[k2], ageCopies[k2])
    assert_acdc_schema_valid(pres1)                  # presentation schema-valid every kind
    assert _context_correlators(k1, idCopies, idIssues, ageCopies, ageAggors, ageIssues,
                                pres1).isdisjoint(
           _context_correlators(k2, idCopies, idIssues, ageCopies, ageAggors, ageIssues,
                                pres2))

    # Private presentation: compact and expanded forms share one SAID.
    presCompact = _presentation(kind, ALCOVE, idCopies, ageCopies, presNonces,
                                compactify=True)
    assert presCompact.said == pres1.said
    assert isinstance(pres1.sad['e'], dict)          # sections inline...
    assert isinstance(presCompact.sad['e'], str)     # ...vs. collapsed to a SAID

    # Selective over-21 disclosure verifies via the AGID on every kind.
    disclosed, _ = ageAggors[k1].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    assert disclosed[AGE_OVER21]['over21'] is True
    assert Aggor.verifyDisclosure(disclosed, kind=kind)


if __name__ == "__main__":
    test_indreg_derivation_and_batch_JSON()
    test_indreg_sedi_id_set_JSON()
    test_indreg_batch_anchor_JSON()
    test_indreg_sedi_age_set_JSON()
    test_indreg_partition_across_verifiers_JSON()
    test_indreg_disclosure_gating_and_revocation_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_indreg_serialization_kinds(_kind)
