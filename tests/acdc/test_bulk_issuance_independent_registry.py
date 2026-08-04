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
Issuees (spec L2914-2924). The batch is the anonymity set; the tree is what lets one
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

Plain Merkle tree, not a sparse Merkle tree. Spec L2916 calls for an SMT. An SMT buys
two things this example does not exercise: efficient NON-inclusion proofs, and
fixed-depth addressing keyed by the leaf's own SAID. The property that carries the
privacy argument here -- prove one leaf under a herd-wide root without disclosing any
sibling leaf -- is delivered by an ordinary domain-separated Merkle tree, which is
what _BatchTree below implements. A production Registrar SHOULD use an SMT for the
incremental-update and non-inclusion properties described at spec L2916-2924; nothing
in this example's proofs would change shape.

SPEC GAPS THIS EXAMPLE HAD TO PIN (candidates for a follow-on spec PR, the way the
sibling produced #200). Spec 15.4 pins the derivation paths "k" (top-level uuid),
"k/j" (nested block uuid) and "k." (the blinding factor v_k, pinned by #200). It pins
nothing for the two values independent-registry bulk issuance needs per copy. This
module extends the same dot-suffix convention: "k.r" derives copy k's REGISTRY
inception uuid, and "k.b" derives copy k's registry BLINDING salt. Nor does the spec
pin the tree's leaf definition or its hashing: this module takes the leaf to be the
transaction event's SAID (spec L2920: "the SAIDs of each transaction event") and uses
RFC-6962 domain separation (0x00 leaf, 0x01 interior) over qb64 TEXT concatenation
with Blake3-256 -- the same concatenation domain #200 pinned for b_k. Two
implementations that chose differently would compute different roots and fail to
cross-verify, so these are interop-blocking and belong in the spec, not here.

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
# L2908: "the size of the Registry database increases as a multiple of the number of
# copies"). That cost is the price of removing the registry as a correlator.
BULK_SIZE = 5
# The states a registry's blindable update can carry, for both bulk sets.
SET_STATES = ['issued', 'revoked']


class _BulkNonces:
    """Deterministic per-copy nonce derivation for a bulk-issued set (ACDC spec 15.4).

    Every nonce for every copy is derived from ONE shared secret salt by argon2id
    (Salter.stretch) at a hierarchical path keyed on the copy index k, then wrapped as a
    salty nonce (Noncer):

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
        return self._nonce(f"{k}" if j is None else f"{k}/{j}")

    def r(self, k):
        """Copy k's own registry inception uuid, derived at the path "k.r"."""
        return self._nonce(f"{k}.r")

    def b(self, k):
        """Copy k's own registry blinding salt, derived at the path "k.b".

        A 128-bit qb64 salt, which is what Blinder.makeUUID consumes; the other nonces
        here are 256-bit uuids. Only this copy's salt is ever disclosed to a verifier.
        """
        return Noncer(raw=self._salter.stretch(size=16, path=f"{k}.b", temp=True)).qb64


# ===========================================================================
# Phase 1b: the batch anchoring primitive (ACDC spec 15.4, "Independent Registry
# Transaction Event Seals Using Merkle Tree Roots").
# ===========================================================================
class _BatchTree:
    """Merkle tree over TEL transaction-event SAIDs, anchored by ONE root seal.

    The Issuer periodically anchors a single seal in its KEL whose value is this tree's
    root, committing every transaction event from every registry updated since the last
    anchor -- across all bulk-issued sets and ALL Issuees (spec L2918-2922). A Validator
    that receives one event plus its inclusion proof learns that the Issuer committed to
    that event and learns nothing about any other leaf. The batch is the anonymity set:
    the more registries and Issuees it mixes, the less a co-anchored pair of events says
    about a common holder. Spec L2924 goes further and suggests the Issuer inject
    state-preserving no-op updates to pad thin batches.

    SPEC GAP / PINNED HERE. Spec L2920 says the leaves are "the SAIDs of each transaction
    event" and L2930 requires second-pre-image protection of interior nodes, but pins
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


if __name__ == "__main__":
    test_indreg_derivation_and_batch_JSON()
