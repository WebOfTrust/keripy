# -*- coding: utf-8 -*-
"""
tests.acdc.test_bulk_issuance_precreated_registry module

Worked, working example of PRE-CREATED INDEPENDENT-REGISTRY bulk-issued private ACDCs
(ACDC spec section 15.4, "Independent Registry Bulk-Issued ACDCs" and "Independent
Registry Transaction Event Seals Using Merkle Tree Roots") -- the arrangement the State
of Utah intends to deploy for SEDI (State-Endorsed Digital Identity, Utah Code 63A-20),
with every anticorrelation measure the spec describes switched ON.

THE THREE MODULES, AND WHY THIS IS THE THIRD. tests/acdc/test_bulk_issuance_
shared_registry.py works the BASIC form: M copies share one registry and one blinded
aggregate 'B'. tests/acdc/test_bulk_issuance_cocreated_registry.py gives each copy its
own registry but incepts those registries WITH the set, deriving each `rip` uuid from
the shared bulk salt at "k.r" -- which keeps the Issuee's storage down to (salt,
template) and gives up decorrelation against a 3rd party, because a registry incepted
in the same moment as the set it serves, from one set-wide datetime, is recognizable as
part of that set to anyone who can see the Issuer's KEL. This module is the other
arrangement, and the one Utah confirmed. Sam Smith, keripy#1576 (2026-08-05):

    "for SEDI the use case the State has confirmed they want is the decorrelatable
    registries which means that their identifiers cannot be HDKey derived but must be
    provided in an indexed list to the citizen at bulk issuance time and the citizen
    wallet must hang onto that list."

and, on what pre-creation buys:

    "The state just creates say 12M registries that are unassigned and anchors them all
    at once (with a merkle tree anchor). Since the full set is not assigned to an ACDC
    there is no correlation signal. ... The State could always update say 100,000
    minimum per bulk update. If only 10,000 were updates to issue or assign ACDCs the
    other 90,000 would be randomly updated with vacuous (no change) updates. This
    ensures a herd privacy of 100,000."

WHAT "PRE-CREATED" ACTUALLY CHANGES, IN ONE SENTENCE EACH.

  1. A registry is incepted before any ACDC exists for it, from entropy the Issuer alone
     holds, at a moment chosen by nothing. Nothing observable about the `rip` event, or
     about when it was published, is a function of an ACDC that did not exist yet, so
     the decorrelation holds against 3rd parties and not merely against colluding
     Verifiers. This is Phase 1.
  2. Because there is no bulk index at inception, `rd` is not derivable. It is the SAID
     of a `rip` event whose fields include the Issuer's own datetime, so no path off the
     shared secret salt reproduces it. The Issuer MUST convey an indexed list of registry
     SAIDs and the wallet MUST retain it (#204). This is Phase 2, which asserts the
     non-derivability directly rather than asserting it in prose.
  3. Assignment is buried in a bulk update round that is mostly vacuous, and that mixes
     across Issuees. A round touches a fixed quota of registries; the ones being assigned
     to ACDCs are a minority and belong to many different residents, and an observer
     cannot tell which is which, because a state-preserving update and an assignment are
     the same event shape carrying a digest. This is Phase 3, and it is the measure the
     co-created module cannot express at all.
  4. Only ONE secret is exchanged. The blinding salt of copy k's registry derives from
     the same shared bulk salt at the path "k.s" (#204), from assignment onward. Blinds
     of the placeholder events published BEFORE assignment stay the Issuer's own affair,
     carrying empty `td` and `ts`, and need not be recoverable by the Issuee -- which is
     what lets the salt arrive later than the registry does.
  5. The registries of one set do not advance in lock step. Each pool registry has its
     own placeholder history, so copy k's assignment lands at its own sequence number
     and each registry's blind derives at its own path. Two registries whose event
     counts move together are correlatable by that fact alone, whatever their states
     (#204, from @SmithSamuelM's keripy discussion #1574); here divergence is a
     consequence of the pool rather than something an Issuer has to remember to do.
  6. Revocation does not stop the stream. The revoking update is followed by further
     state-preserving updates, so the moment a credential died is not legible from the
     shape of the TEL. This is the measure the guardianship example (#1530) names as
     missing and defers.

Scenario, deliberately unchanged from the two siblings so all three read side by side.
Alice, a Utah resident over 21, proves "over 21" at mutually-unrelated verifiers -- a
bar, a cannabis dispensary, an online sportsbook. The State/DGO bulk-issues her both
source credentials, a set of sedi-id copies and a set of sedi-age copies, index-aligned
so copy k of sedi-age carries an E1E identity edge to copy k of sedi-id. Alice spends
copy k at verifier k. What is new is underneath: her 2*M registries were incepted months
earlier among hundreds of others, assigned inside a padded bulk round, and identified to
her wallet by a list she has to keep.

Population scale, honestly scaled. Sam's numbers are 12M registries and 100,000 updates
per round; this module runs POOL_SIZE registries and a WHITEN_QUOTA-event round, which
preserves every RATIO the argument depends on (Alice is a vanishing fraction of the
pool; the real assignments are a small minority of the round) while keeping the module
runnable in seconds. The assertions are written against the ratios, not the absolute
numbers, so raising POOL_SIZE does not invalidate them.

WHERE THE L-NUMBERS AND #204 POINT. Every "spec L####" is a line number in
spec/spec-body.md of trustoverip/kswg-acdc-specification at commit f96ef54 (2026-07-27),
"Sync Working ACDC Examples with the keripy reference implementation (#198)"; the
co-created sibling explains the drift hazard at length. Everything this module does that
the published text does not pin -- the "k.s" blinding-salt path, the conveyed registry
list, the dense batch tree's leaf and interior digests, the typed batch seal, the
mixing and lock-step obligations -- is specified in
trustoverip/kswg-acdc-specification#204, which should land at the same time as this
example.

A note on altitude. Like the sibling examples, this one models the credential graph, the
bulk derivation, the registries and the batch anchors at the data-structure level, built
from the real v2 primitives in keri.core and keri.acdc.messaging (Salter.stretch, Noncer,
Diger, Sealer/SealKind, acdcmap/acdcagg, Aggor, Blinder, regcept, blindate, exchange). It
does not stand up a Habery/keystore, so the KEL that would carry the batch seals is
represented by real Sealer objects rather than by a real KEL, and TEL chain verification
against a database (rd/n/p rules, anchor discovery, escrow) is out of scope here -- that
is what a Rever/vet layer is for. Every ACDC validates against a real, purpose-authored
JSON Schema (Draft 2020-12). Actor AIDs and all nonces are DERIVED from fixed salts so
the example is reproducible.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks, Protocols
from keri.core import Salter, Noncer, Aggor, Mapper, Diger, Verfer, exchange
from keri.core.coring import MtrDex, NonceDex, Verser
from keri.core.eventing import incept
from keri.kering import Vrsn_2_0
from keri.acdc import regcept, blindate, acdcmap, acdcagg
from keri.core.structing import Blinder, BlindState, Sealer, SealKind, SealRoot


# --- Reproducible example actors (see module docstring). ---
# Five actors, each a self-addressing ('E') transferable AID: its prefix is the SAID of
# an inception event committing to the actor's current signing key and a digest of its
# pre-rotated next key. Ten signers from one fixed salt: _SIGNERS[0..4] are the five
# actors' current signing keys (State/DGO, Alice, and the three verifiers) and
# _SIGNERS[5..9] are their matching pre-rotated next keys.
_SIGNERS = Salter(raw=b'precregworkexsig').signers(count=10, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


# STATE = Utah's digital-government office (the issuer of both bulk sets and the owner of
# the registry pool); ALICE is the adult holder (over 21) -- her per-copy AIDs are derived
# further below; ALCOVE (a bar), DISPENSARY (cannabis) and SPORTSBOOK (an online
# sportsbook) are the mutually unrelated verifiers she proves over-21 to.
STATE, ALICE, ALCOVE, DISPENSARY, SPORTSBOOK = (
    _actor_aid(_SIGNERS[i], _SIGNERS[i + 5]) for i in range(5))

# The three verifiers in spend order; Alice's wallet maps verifier -> copy index.
VERIFIERS = (ALCOVE, DISPENSARY, SPORTSBOOK)


# ===========================================================================
# Phase 1a: the per-copy derivation primitive -- SHORTER here than in the
# co-created sibling, and the missing method is the point.
# ===========================================================================
# The shared secret salt for Alice's bulk sets -- known to the Issuer (State) and the
# Issuee (Alice), never handed to a verifier. In a real flow it is transported to Alice
# encrypted to her AID-derived X25519 key (keri.core Encrypter/Decrypter); here it is a
# fixed value so the example is reproducible. It is the ONLY secret exchanged: the
# registry blinding salts derive from it, and the registry SAIDs are conveyed in the
# clear-but-private list of Phase 2 rather than being secrets at all.
BULK_SALT = b'precregexamsalt0'
# The sedi-age bulk set derives its per-copy nonces from a DISTINCT salt so its uuids and
# blinding salts never collide with the sedi-id set's.
BULK_AGE_SALT = b'precregageexsalt'
# M: copies per bulk-issued set, and therefore also the number of registries DRAWN per
# set. Small for a readable example; a real deployment sizes M to the expected number of
# distinct verifier contexts and pays for it in TELs (spec L2911).
BULK_SIZE = 5
# The states a registry's blindable update can carry, for both bulk sets. Every call site
# below passes list(SET_STATES) rather than SET_STATES: Blinder.unblind APPENDS the empty
# placeholder state to the list it is handed (src/keri/core/structing.py), so passing this
# constant directly would leave '' permanently in it and quietly weaken every later
# assertion that iterates over the states an Issuer actually uses.
SET_STATES = ['issued', 'revoked']


def _hx(index):
    """Render a derivation-path index as LOWERCASE HEX with no leading zeros.

    Every index that becomes part of an HD derivation path goes through here. The
    rationale is worked at length in the co-created sibling and in
    trustoverip/kswg-acdc-specification#200/#204: the two renderings agree only for
    indices 0-9 and diverge from 10 onward ("10" vs "a"), so an implementation that chose
    decimal would derive different nonces, different SAIDs and different blinds for every
    copy from the tenth. Hex is what every HD path in KERI already uses -- Salter.signers
    (src/keri/core/signing.py:484), SaltyCreator (src/keri/app/keeping.py:542,544) and
    Blinder.makeUUID via Number.snh (src/keri/core/structing.py:1479).

    Non-integer path segments (the pool's composite tags below) pass through unchanged;
    they are labels, not indices.
    """
    return f"{index:x}" if isinstance(index, int) else index


class _BulkNonces:
    """Deterministic per-copy nonce derivation for a bulk-issued set (ACDC spec 15.4).

    Every nonce for every copy is derived from ONE shared secret salt by argon2id
    (Salter.stretch) at a hierarchical path keyed on the copy index k, then wrapped as a
    salty nonce (Noncer). Every index in a path is lowercase hex, no leading zeros:

        path "k"    -> copy k's top-level ACDC uuid  u_k       (spec)
        path "k/j"  -> copy k's nested block j uuid            (spec)
        path "k.s"  -> copy k's REGISTRY blinding salt         (#204, both arrangements)

    WHAT IS ABSENT, AND WHY THAT IS THE HEADLINE. The co-created sibling's version of
    this class has a fourth method, .r(k), deriving copy k's registry inception uuid at
    the path "k.r". There is no such method here and there cannot be one. A pre-created
    registry was incepted before this set existed, from entropy that belongs to the
    Issuer alone (see _RegistryPool), so there is no derivation to perform -- which is
    exactly why Phase 2 has to convey the registry SAIDs instead.

    The blinding salt at "k.s" survives the change, and #204 requires it in BOTH
    arrangements: the Issuer conveys one shared secret salt rather than M registry
    salts, and copy k's salt still unblinds copy k's registry and nothing else. Note the
    two-stage shape #204 pins: "k.s" yields a SALT, and each event's blind is then
    derived from that salt with the event's sequence number as the path (Blinder.makeUUID)
    -- never straight from the bulk salt, where the bare sequence number would collide
    with the top-level path "k".

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

    def s(self, k):
        """Copy k's registry blinding salt, derived at the path "k.s".

        A 128-bit qb64 salt, which is what Blinder.makeUUID consumes; the other nonces
        here are 256-bit uuids. The salt itself is NEVER disclosed to a verifier -- only
        the blind of the one event being proved (see _verify_issuance).
        """
        return Noncer(raw=self._salter.stretch(size=16, path=f"{_hx(k)}.s",
                                               temp=True)).qb64


# ===========================================================================
# Phase 1b: the batch anchoring primitive, now under a TYPED seal.
# ===========================================================================
# #204: an Issuer anchoring a batch of independent-registry transaction events SHOULD use
# a TYPED seal rather than a bare Merkle-root-digest seal, so that the tree type and
# version a Validator must assume are committed in band. KERI's typed seal carries a
# Verser -- a protocol-and-version tag -- alongside the digest, so what a Validator reads
# off the seal is "the tree construction defined by ACDC protocol v2.0", which is the
# construction pinned in #204 and implemented by _BatchTree. That is a coarser type than
# "dense versus sparse" would be, and it is what KERI offers today; the co-created
# sibling still uses the bare SealRoot, so the two spellings sit side by side.
BATCH_TREE_TYPE = Verser(proto=Protocols.acdc, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0).qb64


class _BatchTree:
    """Merkle tree over TEL transaction-event SAIDs, anchored by ONE typed seal.

    The Issuer periodically anchors a single seal in its KEL whose digest is this tree's
    root, committing every transaction event from every registry touched since the last
    anchor -- across all bulk-issued sets, all Issuees, and (here) all the unassigned
    registries the round padded itself with (spec L2920-2926, #204). A Validator that
    receives one event plus its inclusion proof learns that the Issuer committed to that
    event and learns nothing about any other leaf.

    Construction pinned by #204: a leaf is H(0x00 + leafSAID), an interior node is
    H(0x01 + left + right), over qb64 TEXT concatenation with Blake3-256; RFC 6962 domain
    separation is what stops an interior node's preimage from being replayed as a leaf.
    An odd node at any level is PROMOTED unchanged rather than duplicated, which avoids
    the duplicate-last-leaf ambiguity (CVE-2012-2459).

    This is a plain (dense) Merkle tree. Spec L2918 also describes an amalgamated sparse
    tree over every event of every registry; #204 records that the two are different
    structures and that a bare root digest cannot distinguish them, which is the reason
    for the typed seal above.
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
    apply. It matters because an inclusion proof discloses the leaf's PATH (the L/R bits),
    so a verifier learns roughly where in the tree its event sits. Leaving one holder's
    events in contiguous submission order would let two colluding verifiers notice their
    proofs are adjacent. SAIDs are digests, so sorting by them interleaves holders
    pseudo-randomly while staying reproducible.
    """
    return sorted(said for group in eventSaidGroups for said in group)


def _anchor(*eventSaidGroups):
    """Anchor one batch: build the tree and return (tree, sealer), sealer TYPED.

    ONE seal covers the whole batch. #204 states the negative directly: an Issuer SHOULD
    NOT anchor a set's registry inceptions as a list of individual seals in a single key
    event, because that relocates the correlation into the KEL rather than removing it.
    """
    tree = _BatchTree(_batch(*eventSaidGroups))
    return tree, Sealer(crew=SealKind(t=BATCH_TREE_TYPE, d=tree.root))


def _verify_anchored(said, tree, sealer):
    """A Validator's check that the Issuer committed to transaction event `said`: the
    seal is of the expected tree type and the proof reconstructs its digest."""
    if sealer.clan is not SealKind or sealer.crew.t != BATCH_TREE_TYPE:
        return False
    return _BatchTree.verify(said, tree.prove(said), sealer.crew.d)


# ===========================================================================
# Phase 1c: the Issuer's PRE-CREATED registry pool.
# ===========================================================================
# The pool secret: the State's own entropy for registry inception uuids and for the
# blinds of placeholder events. It is not the bulk salt, it is not derived from the bulk
# salt, and no Issuee ever sees it. That separation is the whole mechanism of Phase 2's
# non-derivability, so it is stated as a constant rather than buried in a helper.
POOL_SECRET = b'utahregpoolsecr0'
# The pool, scaled down from Sam's 12M. Every assertion below is written against ratios.
POOL_SIZE = 240
# Registries are incepted in creation batches on unrelated days, MONTHS before the
# issuance round in 2026-07. A creation batch shares one datetime, which discloses
# nothing: no registry in it is associated with any ACDC, so there is nothing for the
# shared datetime to correlate. Contrast the co-created sibling, where the one shared
# `rip` datetime that makes `rd` regenerable is also what marks M registries as one set.
POOL_STAMPS = ("2025-09-02T09:00:00.000000+00:00",
               "2025-11-14T09:00:00.000000+00:00",
               "2026-02-03T09:00:00.000000+00:00",
               "2026-04-21T09:00:00.000000+00:00")
# How many placeholder updates a pool registry carries before anyone assigns it. Varying
# this per registry is what keeps the registries of one set off lock step (#204).
POOL_PLACEHOLDERS = (1, 2, 3, 4)
# The bulk update rounds that ran before Alice's issuance. An unassigned registry is not
# incepted and then left alone: it is swept into whitening rounds like any other, which is
# what makes a later round containing a real assignment unremarkable.
WHITEN_STAMPS = ("2026-05-05T02:00:00.000000+00:00",
                 "2026-05-19T02:00:00.000000+00:00",
                 "2026-06-02T02:00:00.000000+00:00",
                 "2026-06-16T02:00:00.000000+00:00")


def _blind_with(uuid, *, acdc='', state=''):
    """A blinded state whose blinding factor is SUPPLIED rather than derived from a salt.

    Blinder.blind(salt=...) runs argon2id per call, which is right for the handful of
    blinds whose derivation the example is actually about -- Alice's, from her "k.s"
    salt -- and wrong for the hundreds of pool blinds whose derivation nothing here
    depends on. Those belong to the Issuer alone and are never recovered by anyone else
    (spec, via #204: a placeholder event's blind "is the Issuer's own affair"), so this
    helper builds the same BlindState the derived path builds, with the factor handed in.
    Blinder.unblind(uuid=...) consumes exactly this form.
    """
    return Blinder(crew=BlindState(d='', u=uuid, td=acdc, ts=state),
                   makify=True, saidive=True)


class _RegistryPool:
    """The State's pool of pre-created, unassigned blindable-state registries.

    Every registry here is incepted with no ACDC in view: its `rip` uuid comes from
    POOL_SECRET at a path keyed on the POOL index (not on any bulk-issued set index),
    its datetime is that of a creation batch months before any issuance, and it then
    accrues a private number of placeholder updates carrying empty `td` and `ts`. When
    an ACDC is later assigned to one of these registries, that assignment is a single
    further update -- indistinguishable on the wire from the state-preserving updates
    that surround it.

    The cost is stated rather than glossed. Spec L2911 already warns that independent
    registries multiply the registry database by the number of copies; pre-creation adds
    to that, because the Issuer pays for every registry it may ever need, plus the
    updates that keep the unassigned ones indistinguishable from the assigned ones. That
    is the price of a registry that exists before anyone can say what it is for.
    """

    def __init__(self, kind, size=POOL_SIZE):
        self.kind = kind
        self.size = size
        self._salter = Salter(raw=POOL_SECRET)
        self.regs = [regcept(israid=STATE, uuid=self.uuid(i),
                             stamp=POOL_STAMPS[i % len(POOL_STAMPS)], kind=kind)
                     for i in range(size)]
        self.byRd = {reg.said: i for i, reg in enumerate(self.regs)}
        # chain[i][0] is the rip; every later entry is a bup at sn == its position.
        self.chain = [[reg] for reg in self.regs]
        self.assigned = {}          # pool index -> (acdc said, blinding salt)
        for i in range(size):       # the private pre-assignment history
            for n in range(POOL_PLACEHOLDERS[Diger(ser=f"ph{i}".encode()).raw[0]
                                             % len(POOL_PLACEHOLDERS)]):
                self.placeholder(i, WHITEN_STAMPS[n % len(WHITEN_STAMPS)])

    def uuid(self, i):
        """Pool registry i's `rip` unique entropy, from the ISSUER's secret."""
        return Noncer(raw=self._salter.stretch(size=32, path=f"p{_hx(i)}", temp=True),
                      code=NonceDex.Salt_256).qb64

    def issuerBlind(self, i, sn):
        """The Issuer-only blinding factor for a placeholder event of registry i."""
        return Noncer(raw=self._salter.stretch(size=32, path=f"b{_hx(i)}/{_hx(sn)}",
                                               temp=True),
                      code=NonceDex.Salt_256).qb64

    def rd(self, i):
        return self.regs[i].said

    def head(self, i):
        return self.chain[i][-1]

    def sn(self, i):
        """The sequence number of registry i's latest event (the rip is 0)."""
        return len(self.chain[i]) - 1

    def _append(self, i, blid, stamp):
        event = blindate(regid=self.rd(i), prior=self.head(i).said, blid=blid,
                         sn=self.sn(i) + 1, stamp=stamp, kind=self.kind)
        self.chain[i].append(event)
        return event

    def placeholder(self, i, stamp):
        """A state-preserving update on an UNASSIGNED registry: empty td/ts, fresh blind."""
        return self._append(i, _blind_with(self.issuerBlind(i, self.sn(i) + 1)).said,
                            stamp)

    def assign(self, i, acdcSaid, salt, stamp):
        """Assign an ACDC to registry i: the first update whose blinded state says anything.

        From here on this registry's blinds derive from the copy's "k.s" salt at the
        event's sequence number, which is what lets the Issuee (and, one event at a time,
        a Disclosee) read the state. Everything before this event stays the Issuer's.
        """
        sn = self.sn(i) + 1
        blinder = Blinder.blind(acdc=acdcSaid, state='issued', salt=salt, sn=sn)
        self.assigned[i] = (acdcSaid, salt)
        return self._append(i, blinder.said, stamp)

    def assignOther(self, i, acdcSaid, stamp):
        """Assign a registry to ANOTHER Issuee's credential, modeled only as an event.

        #204 obliges an Issuer to mix a batch "across Registries and across Issuees": a
        round holding one Issuee's events provides no herd privacy, since co-anchoring
        correlates precisely what independent registries were adopted to decorrelate. The
        other residents of the state are therefore present in every round below, and are
        real assignments rather than padding.

        Their credentials are out of scope, so each is a stand-in SAID, and their blinding
        salts belong to them -- this module does not model another resident's wallet, so
        the blinding factor comes from the Issuer's side (see _blind_with). Nothing in the
        example depends on how these blinds were derived; what matters is that the events
        exist, are indistinguishable from Alice's, and belong to other people.
        """
        sn = self.sn(i) + 1
        self.assigned[i] = (acdcSaid, None)
        return self._append(i, _blind_with(self.issuerBlind(i, sn), acdc=acdcSaid,
                                           state='issued').said, stamp)

    def restate(self, i, state, stamp):
        """A further update on an ASSIGNED registry, carrying `state` under a fresh blind.

        Used both for revocation (state='revoked') and for the state-PRESERVING updates
        that follow it, which are what keep the moment of revocation from being legible
        in the shape of the TEL.
        """
        acdcSaid, salt = self.assigned[i]
        sn = self.sn(i) + 1
        blinder = Blinder.blind(acdc=acdcSaid, state=state, salt=salt, sn=sn)
        return self._append(i, blinder.said, stamp)

    def unassignedNear(self, count, exclude=(), *, label="pad"):
        """Deterministically pick `count` unassigned pool indices for padding a round."""
        picked, taken = [], set(exclude) | set(self.assigned)
        if count > self.size - len(taken):
            raise ValueError("a round cannot pad beyond the unassigned population")
        j = 0
        while len(picked) < count:
            i = int.from_bytes(Diger(ser=f"{label}-{j}".encode()).raw[:4], 'big') % self.size
            j += 1
            if i not in taken:
                taken.add(i)
                picked.append(i)
        return picked


def _draw(label, count, size, exclude=()):
    """The Issuer's draw of pool indices to assign to one bulk-issued set.

    Deterministic here so the example reproduces; a real Registrar draws at random from
    the unassigned population. What matters is that the draw is spread across the pool:
    handing a set a contiguous run of pool indices would reintroduce, in the registry
    database's own ordering, the set membership the whole arrangement removes.
    """
    picked, taken = [], set(exclude)
    j = 0
    while len(picked) < count:
        i = int.from_bytes(Diger(ser=f"{label}#{j}".encode()).raw[:4], 'big') % size
        j += 1
        if i not in taken:
            taken.add(i)
            picked.append(i)
    return picked


# ===========================================================================
# Phase 2: conveyance -- the indexed registry list the wallet must keep.
# ===========================================================================
class _Manifest:
    """The indexed list of registry SAIDs an Issuer conveys with a bulk-issued set.

    #204, following Sam's keripy#1576 correction: "The Issuer MUST provide the Issuee
    with a list, indexed by the bulk-issued set member index `k`, whose entry at index
    `k` gives the Registry SAID, `rd`, of the Registry assigned to copy `k`. The Issuee
    MUST retain this list."

    Entries are SAIDs and nothing else. An earlier draft of #204 had each entry carrying
    a per-registry blinding salt as well; Sam's answer replaced that with derivation at
    "k.s", so one secret is exchanged rather than M+1. Nor does the list carry the
    assignment event's sequence number, which the wallet does not need conveyed: the
    registry's events are public, so the wallet reads the head of the TEL and derives the
    blind at that sequence number (see _Wallet.blind).

    In a real flow this list travels with the shared secret salt, encrypted to the
    Issuee's AID-derived X25519 key. It is not secret in the way the salt is -- knowing
    a registry SAID lets you watch a TEL you cannot read -- but it is a stable
    per-context identifier, so it is not published either.
    """

    def __init__(self, rds):
        self.rds = list(rds)

    def rd(self, k):
        return self.rds[k]

    def __len__(self):
        return len(self.rds)


class _Wallet:
    """What the Issuee stores for one bulk-issued set: a salt, a template, and a list.

    The salt regenerates every uuid in every copy and every registry blinding salt. The
    template is the schema plus the fixed attribute values. The list is the one thing
    that cannot be regenerated from anything, which is why losing it loses the set:
    without rd_k the wallet cannot even construct copy k, since `rd` is a committed
    field of the ACDC and therefore part of its SAID.
    """

    def __init__(self, salt_raw, manifest):
        self.nonces = _BulkNonces(salt_raw)
        self.manifest = manifest

    def blind(self, k, sn):
        """The blind for copy k's registry event at sequence number `sn`.

        Two stages, as #204 pins them: "k.s" yields the salt, and the event's sequence
        number is the path from that salt to the blind. Only this value is ever handed to
        a Disclosee -- never the salt, which would unblind every event past and future.
        """
        return Blinder.makeUUID(salt=self.nonces.s(k), sn=sn)


# ===========================================================================
# Phase 3: the bulk update round -- assignment hidden in vacuous traffic.
# ===========================================================================
# One bulk update round touches this many registries. Sam's number is 100,000 minimum per
# round with maybe 10,000 real; the ratio is what the herd-privacy claim rests on.
WHITEN_QUOTA = 60
# Other residents whose credentials are issued in the SAME round. #204 requires a batch to
# mix across Issuees as well as across registries, so these are real assignments, not
# padding: HERD_RESIDENTS people getting HERD_COPIES copies each.
HERD_RESIDENTS = 6
HERD_COPIES = 2
ROUND_STAMP = "2026-07-01T03:00:00.000000+00:00"
ISSUE_ID_STAMP = "2026-07-01T03:00:00.000000+00:00"
ISSUE_AGE_STAMP = "2026-07-01T03:00:00.000000+00:00"
REVOKE_STAMP = "2026-08-01T09:00:00.000000+00:00"
LATER_ROUND_STAMP = "2026-08-01T09:00:00.000000+00:00"


# ===========================================================================
# Phase 4 support: schemas, ported in intent from the sibling SEDI examples.
# ===========================================================================
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


# acm/acg always carry (possibly empty) e and r sections, so the schema must admit them.
_EMPTY_OR_SECTION = {"oneOf": [{"type": "string"}, {"type": "object"}]}

# sedi-id: the holder's ATTRIBUTIVE ('acm') core identity credential. Every bulk copy
# shares this schema (a public, non-correlating identifier). The issuee 'i' is the
# per-copy holder AID ALICE_k and the registry 'rd' is the pool registry assigned to copy
# k -- a value that arrived in the manifest rather than out of the salt.
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
        "rd": {"description": "The pre-created registry assigned to this copy",
               "type": "string"},
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
        "rd": {"description": "The pre-created registry assigned to this copy",
               "type": "string"},
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

# --- Per-copy holder AIDs. ---
# Independent registries assume independent AIDs (spec L2905). Each copy k is issued to
# its OWN holder AID ALICE_k, derived from a HOLDER-ONLY secret salt the issuer never
# sees -- the holder supplies the public AIDs and the issuer commits to AIDs it cannot
# forge. 2*M signers: ALICE_k's current key is _HOLDER_SIGNERS[k], its pre-rotated next
# key _HOLDER_SIGNERS[M+k].
_HOLDER_SIGNERS = Salter(raw=b'precregaliceskey').signers(count=2 * BULK_SIZE,
                                                          transferable=True, temp=True)
ALICES = [_actor_aid(_HOLDER_SIGNERS[k], _HOLDER_SIGNERS[BULK_SIZE + k])
          for k in range(BULK_SIZE)]

# Alice's identity attribute values -- the SAME across every copy (it is one Alice); only
# the per-copy nonces differ, so the copies are semantically identical but have unique
# SAIDs. DOB puts her well over 21 at the 2026 presentation.
ALICE_DOB = "2000-03-15"

# Aggregate ARRAY positions (A[0]=AGID; A[1]=issuee; A[2..]=flags) and Alice's age.
AGE_ISSUEE = 1
AGE_FLAG0 = 2
AGE_OVER21 = AGE_FLAG0 + AGE_THRESHOLDS.index(21)
ALICE_AGE = 26                                   # DOB 2000-03-15 at the 2026 presentation

# Per-copy nonce slots for a sedi-age copy: aggregate elements at "k/1".."k/(1+len)", the
# edge section at "k/20" and the E1E edge at "k/21" (high slots avoid collision).
_AGE_EDGE_SEC, _AGE_EDGE_ID = 20, 21


def _sedi_id_attr(nonces, k):
    """Copy k's sedi-id attribute section (issuee inserted by acdcmap via iseaid).

    Per-copy blinding nonces come from the shared bulk salt at hierarchical paths keyed on
    k: the section uuid at "k/0" and one nested-block uuid per attribute at "k/1".."k/4".
    """
    return dict(d='', u=nonces.u(k, 0),
                photo=dict(d='', u=nonces.u(k, 1),
                           photo="<state-endorsed-photo-bytes>"),
                dob=dict(d='', u=nonces.u(k, 2), dob=ALICE_DOB),
                residence=dict(d='', u=nonces.u(k, 3),
                               residence="Salt Lake City UT"),
                name=dict(d='', u=nonces.u(k, 4), name="Alice Anders"))


def _age_ael(nonces, k):
    """Copy k's age-threshold aggregate element list, issued to holder ALICE_k.

    Element 0 is the AGID placeholder; element 1 is the issuee block (i = ALICE_k), where
    SerderACDC.iseaid resolves the aggregate issuee; elements 2.. are one blinded boolean
    block per threshold (over<n> = ALICE_AGE >= n). Per-copy blinding nonces at "k/j".

    WHAT SELECTIVE DISCLOSURE HIDES HERE, STATED CORRECTLY. The aggregate hides the field
    LABELS and the block SAIDs of the undisclosed elements -- so a verifier shown over-21
    learns nothing about over-65, and cannot even tell which other thresholds exist. What
    it does not hide is a logical consequence, and this vector has plenty: the thresholds
    are ordered, so the flags are a MONOTONE predicate over one underlying age.
    Disclosing the highest TRUE threshold entails every lower one. Alice showing over-21
    leaks nothing upward, but a 66-year-old showing over-65 for a senior discount has
    disclosed the whole vector. An application that needs the upward direction hidden
    wants disjoint bands rather than cumulative thresholds.
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
    (issuer != issuee), the case a coerce-to-I2I verifier would reject.
    """
    edge = near.sad['e']['identity']
    assert edge['o'] == 'E1E'                          # identity operator
    assert edge['n'] == far.said                       # points at this far node
    assert near.iseaid is not None                     # near is targeted (has an issuee)
    assert near.iseaid == far.iseaid                   # same subject: the identity relation
    return True


class _Issuance:
    """Everything one bulk issuance round produces, bundled for the phases below.

    Built by _issue_round: the pool (now carrying Alice's assignments), the two wallets,
    the two manifests, the copies and aggors, the assignment events, the padding events
    that hid them, and the batch tree and typed seal that anchored the round.
    """

    def __init__(self, **kwa):
        self.__dict__.update(kwa)


def _issue_round(kind, pool=None):
    """One bulk issuance: draw registries, build both sets, assign inside a padded round.

    The ORDER here is the arrangement's substance, and it is the reverse of the co-created
    sibling's. There, the registry was incepted as part of building the set. Here the
    registries already exist and have histories; issuance draws them, names them in a
    manifest, builds the ACDCs around the drawn SAIDs, and then emits ONE assignment
    update per registry inside a round whose other events change nothing.
    """
    pool = pool if pool is not None else _RegistryPool(kind)
    idNonces, ageNonces = _BulkNonces(BULK_SALT), _BulkNonces(BULK_AGE_SALT)

    # 1. Draw 2*M registries from the unassigned population, spread across the pool.
    idIdx = _draw("sedi-id", BULK_SIZE, pool.size)
    ageIdx = _draw("sedi-age", BULK_SIZE, pool.size, exclude=idIdx)
    idManifest = _Manifest([pool.rd(i) for i in idIdx])
    ageManifest = _Manifest([pool.rd(i) for i in ageIdx])

    # 2. Build both sets AROUND the drawn registry SAIDs. `rd` is a committed field, so
    # the manifest has to exist before the copies can have SAIDs at all.
    _, idSchema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    _, ageSchema = _saidify_schema(dict(AGE_SCHEMA_MAD), kind=kind)
    idCopies = [acdcmap(israid=STATE, uuid=idNonces.u(k), regid=idManifest.rd(k),
                        schema=idSchema, attribute=_sedi_id_attr(idNonces, k),
                        iseaid=ALICES[k], kind=kind)
                for k in range(BULK_SIZE)]
    ageCopies, ageAggors = [], []
    for k in range(BULK_SIZE):
        edge = dict(d='', u=ageNonces.u(k, _AGE_EDGE_SEC),
                    identity=dict(d='', u=ageNonces.u(k, _AGE_EDGE_ID),
                                  n=idCopies[k].said,
                                  s=idCopies[k].sad['s']['$id'], o='E1E'))
        aggor = Aggor(ael=_age_ael(ageNonces, k), makify=True, kind=kind)
        ageCopies.append(acdcagg(israid=STATE, uuid=ageNonces.u(k),
                                 regid=ageManifest.rd(k), schema=ageSchema,
                                 aggregate=aggor.ael, edge=edge, kind=kind))
        ageAggors.append(aggor)

    # 3. Assign Alice's 2*M registries.
    idIssues = [pool.assign(idIdx[k], idCopies[k].said, idNonces.s(k), ISSUE_ID_STAMP)
                for k in range(BULK_SIZE)]
    ageIssues = [pool.assign(ageIdx[k], ageCopies[k].said, ageNonces.s(k),
                             ISSUE_AGE_STAMP)
                 for k in range(BULK_SIZE)]
    alice = idIssues + ageIssues

    # 4. Other residents are issued in the SAME round -- a batch must mix across Issuees
    # and not merely across registries (#204) -- and the remainder of the quota is
    # vacuous updates on registries that belong to nobody at all.
    others, otherIdx = [], []
    for r in range(HERD_RESIDENTS):
        for c in range(HERD_COPIES):
            i = pool.unassignedNear(1, exclude=idIdx + ageIdx + otherIdx,
                                    label=f"resident{r}/{c}")[0]
            otherIdx.append(i)
            others.append(pool.assignOther(
                i, Diger(ser=f"resident{r}-copy{c}".encode()).qb64, ROUND_STAMP))
    real = alice + others
    padding = [pool.placeholder(i, ROUND_STAMP)
               for i in pool.unassignedNear(WHITEN_QUOTA - len(real),
                                            exclude=idIdx + ageIdx + otherIdx)]

    # 5. ONE typed seal over the whole round.
    tree, sealer = _anchor([e.said for e in real], [e.said for e in padding])

    return _Issuance(pool=pool, kind=kind,
                     idNonces=idNonces, ageNonces=ageNonces,
                     idIdx=idIdx, ageIdx=ageIdx, otherIdx=otherIdx,
                     idManifest=idManifest, ageManifest=ageManifest,
                     idWallet=_Wallet(BULK_SALT, idManifest),
                     ageWallet=_Wallet(BULK_AGE_SALT, ageManifest),
                     idCopies=idCopies, ageCopies=ageCopies, ageAggors=ageAggors,
                     idIssues=idIssues, ageIssues=ageIssues,
                     alice=alice, others=others, real=real, padding=padding,
                     tree=tree, sealer=sealer)


# ===========================================================================
# Phase 1: the pool exists before anything it will ever hold.
# ===========================================================================
def test_precreg_pool_JSON():
    """Phase 1: hundreds of registries, incepted for nobody, anchored in bulk.

    The State incepts POOL_SIZE blindable-state registries months before any of them is
    assigned to a credential. Each has its own entropy from the State's own secret, each
    accrues a private number of placeholder updates carrying empty td/ts, and the
    creation batches are anchored one seal apiece. No ACDC exists for any of them, so
    there is nothing in the registry database, or in the State's KEL, that a 3rd party
    can correlate to anything -- which is the property the co-created arrangement cannot
    have, since there the registry is born knowing what it is for.

    Asserted: the pool is large relative to a set; registry entropy comes from the
    Issuer's secret and NOT from either bulk salt; creation datetimes are unrelated to
    (and long precede) the issuance round; each registry has its own placeholder history,
    so no two are guaranteed to be at the same sequence number; a placeholder event
    carries neither a credential SAID nor a state word on the wire; one typed seal covers
    a whole creation batch and names no registry; and an inclusion proof for one
    registry's event discloses no other.
    """
    kind = Kinds.json
    pool = _RegistryPool(kind)

    assert len(pool.regs) == POOL_SIZE
    assert POOL_SIZE >= 20 * BULK_SIZE              # a set is a vanishing fraction
    assert len({reg.said for reg in pool.regs}) == POOL_SIZE
    for reg in pool.regs:
        assert reg.ilk == Ilks.rip
        assert reg.sad['i'] == STATE                # the State incepted every one
        assert reg.sad['n'] == "0"                  # rip is always sequence number 0
        assert reg.sad['dt'] in POOL_STAMPS

    # The creation datetimes long precede the issuance round, and there is more than one
    # of them: a pool is built in batches on unrelated days.
    assert len({reg.sad['dt'] for reg in pool.regs}) == len(POOL_STAMPS)
    assert all(reg.sad['dt'] < ROUND_STAMP for reg in pool.regs)

    # Registry entropy comes from the Issuer's own secret. Neither bulk salt reaches it,
    # at any of the paths bulk issuance uses -- there is no "k.r" here to try.
    poolUuids = {reg.sad['u'] for reg in pool.regs}
    for salt in (BULK_SALT, BULK_AGE_SALT):
        nonces = _BulkNonces(salt)
        derived = {nonces.u(k) for k in range(BULK_SIZE)}
        derived |= {nonces.u(k, j) for k in range(BULK_SIZE) for j in range(6)}
        derived |= {nonces.s(k) for k in range(BULK_SIZE)}
        assert not (derived & poolUuids)

    # Every registry has its own placeholder history, so the pool does not move in lock
    # step even before anyone is assigned anything.
    sns = [pool.sn(i) for i in range(POOL_SIZE)]
    assert min(sns) >= 1 and len(set(sns)) > 1
    assert set(sns) <= set(POOL_PLACEHOLDERS)

    # Those placeholder updates are themselves bulk rounds: they postdate the inception
    # they follow and predate the issuance round, so an unassigned registry is never a
    # registry that was incepted and then left conspicuously alone.
    for i in (0, 1, 2):
        stamps = [event.sad['dt'] for event in pool.chain[i][1:]]
        assert all(pool.regs[i].sad['dt'] < stamp < ROUND_STAMP for stamp in stamps)
        assert stamps == sorted(stamps)

    # A placeholder update is a real bup carrying a blinded state that says nothing.
    head = pool.head(0)
    assert head.ilk == Ilks.bup
    assert head.sad['rd'] == pool.rd(0)
    assert head.sad['p'] == pool.chain[0][-2].said       # chains onto the prior event
    assert head.sad['b']                                 # a blinded id is present...
    for word in SET_STATES:                              # ...and it commits to nothing
        assert word.encode() not in head.raw
    # Only the Issuer can even confirm it is a placeholder: the combination trial needs
    # the blinding factor, which for a pre-assignment event never leaves the Issuer.
    blind = pool.issuerBlind(0, pool.sn(0))
    unblinded = Blinder.unblind(said=head.sad['b'], acdc='', states=list(SET_STATES),
                                uuid=blind)
    assert unblinded is not None
    assert unblinded.crew.td == '' and unblinded.crew.ts == ''
    assert Blinder.unblind(said=head.sad['b'], acdc='', states=list(SET_STATES),
                           uuid=pool.issuerBlind(1, pool.sn(1))) is None

    # The creation batch: one typed seal over many registries' inception events. Anchoring
    # them individually is what #204 forbids, since a list of seals in one key event
    # relocates the correlation into the KEL rather than removing it.
    batchRegs = [reg for reg in pool.regs if reg.sad['dt'] == POOL_STAMPS[0]]
    assert len(batchRegs) > BULK_SIZE
    tree, sealer = _anchor([reg.said for reg in batchRegs])
    assert sealer.clan is SealKind                       # typed, not a bare root seal
    assert sealer.crew.t == BATCH_TREE_TYPE
    assert sealer.crew.d == tree.root
    assert Verser(qb64=sealer.crew.t).versage.proto == Protocols.acdc
    for reg in batchRegs:
        assert _verify_anchored(reg.said, tree, sealer)
    # The seal names nothing, and one registry's proof discloses no other registry.
    assert all(reg.said not in sealer.qb64 for reg in batchRegs)
    proof = tree.prove(batchRegs[0].said)
    material = "".join(sibling for sibling, _ in proof)
    assert all(reg.said not in material for reg in batchRegs)

    # Pinned reproducible values (derived, not pasted -- regenerate by printing on change).
    assert pool.rd(0) == "EBv0JJ_GLWPFsJ2b5cgLS0iKa3Ts9CMdtojZV7WTBkgv"
    assert pool.head(0).said == "EOvVna_jbi-4nZu0KUuHJksIazL8WAF-i-1U76lKMUiD"


# ===========================================================================
# Phase 2: what the Issuer must convey, and what the wallet must keep.
# ===========================================================================
def test_precreg_conveyance_JSON():
    """Phase 2: `rd` is not derivable, so it is conveyed -- and the wallet keeps the list.

    This is the phase that has no counterpart in the co-created sibling, where the wallet
    stores (salt, template) and regenerates the registry SAIDs along with everything else.
    A pre-created registry's SAID digests a `rip` event the Issuee never saw being made,
    including a datetime the Issuer alone chose, so no path off the shared salt reaches
    it. #204: "The Issuer MUST provide the Issuee with a list, indexed by the bulk-issued
    set member index `k` ... The Issuee MUST retain this list."

    Asserted: the manifest holds M registry SAIDs, one per copy, each naming a registry
    the State incepted; no derivation off either bulk salt reproduces any of them, and
    even a LEAKED registry uuid is insufficient because the SAID also digests the Issuer's
    datetime; a wallet holding (salt, template, list) regenerates copy k exactly; the same
    wallet without the list cannot -- any guessed `rd` yields a different ACDC SAID; and
    the one secret exchanged is the salt, from which every blinding salt derives.
    """
    kind = Kinds.json
    bulk = _issue_round(kind)
    pool, manifest = bulk.pool, bulk.idManifest

    # The list: one registry SAID per copy, each an actual pool registry of the State's.
    assert len(manifest) == BULK_SIZE
    assert len(set(manifest.rds)) == BULK_SIZE
    for k in range(BULK_SIZE):
        i = pool.byRd[manifest.rd(k)]
        assert pool.regs[i].sad['i'] == STATE
        assert bulk.idCopies[k].sad['rd'] == manifest.rd(k)

    # The draw is spread across the pool rather than taking a contiguous run, so the
    # registry database's own ordering does not re-link the set.
    assert sorted(bulk.idIdx) != list(range(min(bulk.idIdx),
                                             min(bulk.idIdx) + BULK_SIZE))
    assert max(bulk.idIdx) - min(bulk.idIdx) > BULK_SIZE
    assert not (set(bulk.idIdx) & set(bulk.ageIdx))       # 2*M distinct registries

    # NOT DERIVABLE, asserted rather than argued. Sweep the paths bulk issuance uses --
    # including "k.r", the co-created sibling's registry-uuid path, and "k.", the
    # aggregate blinding factor's -- against both bulk salts. None of them produces the
    # uuid of any assigned registry, let alone its SAID.
    assigned = {pool.regs[i].sad['u'] for i in bulk.idIdx + bulk.ageIdx}
    for salt in (BULK_SALT, BULK_AGE_SALT):
        salter = Salter(raw=salt)
        for k in range(BULK_SIZE):
            for path in (_hx(k), f"{_hx(k)}.", f"{_hx(k)}.r", f"{_hx(k)}.s",
                         f"{_hx(k)}/0", f"p{_hx(k)}"):
                guess = Noncer(raw=salter.stretch(size=32, path=path, temp=True),
                               code=NonceDex.Salt_256).qb64
                assert guess not in assigned
        # Knowing the Issuer's own path convention does not help either, because what is
        # missing is the Issuer's SECRET, not the shape of its paths: derive at the pool's
        # exact path, for the exact pool index, off the bulk salt, and it still misses.
        for i in bulk.idIdx + bulk.ageIdx:
            assert Noncer(raw=salter.stretch(size=32, path=f"p{_hx(i)}", temp=True),
                          code=NonceDex.Salt_256).qb64 != pool.regs[i].sad['u']

    # And the uuid would not be enough anyway: `rd` is the SAID of a whole `rip` event, so
    # it also digests the Issuer's datetime. Recompute one registry with its TRUE uuid but
    # a datetime the Issuee might have assumed -- the issuance round's -- and the SAID
    # misses. This is why co-created regenerability requires a set-wide `rip` template
    # with one shared `dt`, the very fact that marks those registries as one set.
    i0 = bulk.idIdx[0]
    assert regcept(israid=STATE, uuid=pool.uuid(i0), stamp=ROUND_STAMP,
                   kind=kind).said != pool.rd(i0)
    assert regcept(israid=STATE, uuid=pool.uuid(i0),
                   stamp=pool.regs[i0].sad['dt'], kind=kind).said == pool.rd(i0)

    # WITH the list, the wallet regenerates copy k byte for byte from (salt, template).
    wallet = bulk.idWallet
    _, schema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    for k in range(BULK_SIZE):
        regenerated = acdcmap(israid=STATE, uuid=wallet.nonces.u(k),
                              regid=wallet.manifest.rd(k), schema=schema,
                              attribute=_sedi_id_attr(wallet.nonces, k),
                              iseaid=ALICES[k], kind=kind)
        assert regenerated.said == bulk.idCopies[k].said
        assert regenerated.raw == bulk.idCopies[k].raw

    # WITHOUT it, the same wallet cannot: `rd` is a committed field, so any other registry
    # SAID -- including a real one belonging to a different copy -- yields a different
    # credential. Losing the list loses the set.
    lost = acdcmap(israid=STATE, uuid=wallet.nonces.u(0), regid=manifest.rd(1),
                   schema=schema, attribute=_sedi_id_attr(wallet.nonces, 0),
                   iseaid=ALICES[0], kind=kind)
    assert lost.said != bulk.idCopies[0].said

    # ONE secret, not M+1: every blinding salt in the set comes from the bulk salt at
    # "k.s", and copy k's unblinds copy k's registry and nothing else.
    for k in range(BULK_SIZE):
        i = bulk.idIdx[k]
        sn = pool.sn(i)
        assert Blinder.unblind(said=pool.head(i).sad['b'], acdc=bulk.idCopies[k].said,
                               states=list(SET_STATES),
                               uuid=wallet.blind(k, sn)).state == 'issued'
        other = (k + 1) % BULK_SIZE
        assert Blinder.unblind(said=pool.head(i).sad['b'], acdc=bulk.idCopies[k].said,
                               states=list(SET_STATES),
                               uuid=wallet.blind(other, sn)) is None

    # The wallet cannot read its own registry's PRE-assignment history, and does not need
    # to: those events carry empty td/ts and the assignment is marked by a fresh update.
    # This is what lets the salt arrive later than the registry does.
    firstPlaceholder = pool.chain[bulk.idIdx[0]][1]
    assert all(Blinder.unblind(said=firstPlaceholder.sad['b'],
                               acdc=bulk.idCopies[0].said, states=list(SET_STATES),
                               uuid=wallet.blind(0, sn)) is None
               for sn in range(1, pool.sn(bulk.idIdx[0]) + 1))


# ===========================================================================
# Phase 3: assignment hidden inside a mostly-vacuous bulk update round.
# ===========================================================================
def test_precreg_whitening_round_JSON():
    """Phase 3: the round that issues Alice's credentials mostly does nothing.

    Sam's mechanism, keripy#1576: "The State could always update say 100,000 minimum per
    bulk update. If only 10,000 were updates to issue or assign ACDCs the other 90,000
    would be randomly updated with vacuous (no change) updates. This ensures a herd
    privacy of 100,000." Scaled down here to WHITEN_QUOTA events per round, of which
    Alice's 2*M assignments are a minority.

    The property that makes the padding work is that an assignment and a no-op are the
    same event. Both are `bup` messages with the same field map, both carry one digest in
    `b`, and neither carries a credential SAID or a state word. An observer with no
    blinding factor cannot tell them apart, cannot count how many real issuances a round
    contained, and cannot tell whether a given registry was assigned at all.

    The round also mixes across ISSUEES and not merely across registries, which #204
    requires for the same reason: a batch containing one Issuee's events correlates
    exactly what independent registries were adopted to decorrelate, however much vacuous
    padding surrounds it. Other residents are issued in the same round.

    Asserted: the round meets its quota, with Alice's events a small minority and other
    residents' real assignments present; assignment and padding events are structurally
    identical and disclose nothing; nobody without a blind can distinguish them, while the
    Issuer/Issuee can; ONE typed seal covers the round; every event in it proves and an
    event from another round does not; and Alice's events are interleaved with the rest
    rather than sitting in a contiguous run.
    """
    kind = Kinds.json
    bulk = _issue_round(kind)

    # Quota met, with Alice a small minority of it -- and the round's real assignments
    # belonging mostly to OTHER people.
    assert len(bulk.real) + len(bulk.padding) == WHITEN_QUOTA
    assert len(bulk.alice) == 2 * BULK_SIZE
    assert len(bulk.others) == HERD_RESIDENTS * HERD_COPIES
    assert len(bulk.alice) * 5 <= WHITEN_QUOTA         # herd ratio, scaled from Sam's
    assert len(bulk.others) > len(bulk.alice) / 2      # mixed across Issuees, not just
    assert len(bulk.padding) > len(bulk.real)          # registries; and mostly vacuous

    # Structurally identical: same ilk, same field labels, same shapes.
    assignment, noop = bulk.idIssues[0], bulk.padding[0]
    assert assignment.ilk == noop.ilk == Ilks.bup
    assert list(assignment.sad) == list(noop.sad)
    assert len(assignment.sad['b']) == len(noop.sad['b'])
    for event in (assignment, noop):
        assert event.sad['b']
        for word in SET_STATES:
            assert word.encode() not in event.raw
    assert all(c.said.encode() not in assignment.raw
               for c in bulk.idCopies + bulk.ageCopies)
    # Another resident's assignment is the same shape too, so the round does not fall into
    # "Alice's events and everything else" for anyone reading it.
    stranger = bulk.others[0]
    assert stranger.ilk == Ilks.bup and list(stranger.sad) == list(assignment.sad)
    assert stranger.sad['rd'] not in {c.sad['rd'] for c in
                                      bulk.idCopies + bulk.ageCopies}

    # Indistinguishable to an observer: without a blinding factor, an unblind attempt
    # against every credential SAID and every state the State uses returns nothing on
    # either event. With the right blind, the assignment reads 'issued' and the no-op
    # reads as the placeholder it is.
    guess = Noncer(raw=Diger(ser=b'an observer guessing').raw,
                   code=NonceDex.Salt_256).qb64
    for event in (assignment, noop):
        for copy in bulk.idCopies + bulk.ageCopies:
            assert Blinder.unblind(said=event.sad['b'], acdc=copy.said,
                                   states=list(SET_STATES), uuid=guess) is None
    i0 = bulk.idIdx[0]
    assert Blinder.unblind(said=assignment.sad['b'], acdc=bulk.idCopies[0].said,
                           states=list(SET_STATES),
                           uuid=bulk.idWallet.blind(0, bulk.pool.sn(i0))).state == 'issued'
    padIdx = bulk.pool.byRd[noop.sad['rd']]
    padBlind = bulk.pool.issuerBlind(padIdx, bulk.pool.sn(padIdx))
    padded = Blinder.unblind(said=noop.sad['b'], acdc='', states=list(SET_STATES),
                             uuid=padBlind)
    assert padded is not None and padded.crew.ts == ''

    # ONE typed seal over the whole round; every event proves under it, and an event from
    # another round does not.
    tree, sealer = bulk.tree, bulk.sealer
    assert sealer.clan is SealKind and sealer.crew.d == tree.root
    assert len(tree.leaves) == WHITEN_QUOTA
    for event in bulk.real + bulk.padding:
        assert _verify_anchored(event.said, tree, sealer)
    otherRound = _BatchTree(_batch([Diger(ser=b'some other round').qb64]))
    assert not _BatchTree.verify(otherRound.leaves[0],
                                 otherRound.prove(otherRound.leaves[0]), sealer.crew.d)

    # A proof discloses interior digests only -- no other event's SAID, nothing naming a
    # registry -- and Alice's events are interleaved with the rest of the round rather
    # than sitting in a contiguous run, which two colluding verifiers could notice from
    # the L/R path bits their proofs disclose.
    proof = tree.prove(bulk.idIssues[0].said)
    material = "".join(sibling for sibling, _ in proof)
    assert all(said not in material for said in tree.leaves
               if said != bulk.idIssues[0].said)
    assert all(bulk.pool.rd(i) not in material for i in bulk.idIdx)
    positions = sorted(tree.leaves.index(e.said) for e in bulk.alice)
    assert positions != list(range(positions[0], positions[0] + len(positions)))
    assert any(right - left > 1 for left, right in zip(positions, positions[1:]))

    # Pinned reproducible value: the round root the State would seal.
    assert tree.root == "EApfDnZxVVWf0A87b3WEeXv3-juOndOtXg2Pj-M7nWM1"


# ===========================================================================
# Phase 4: the two bulk sets, built around conveyed registry SAIDs.
# ===========================================================================
def test_precreg_sedi_sets_JSON():
    """Phase 4: sedi-id and sedi-age, index-aligned by an E1E edge, in drawn registries.

    Both sets are exactly what the siblings issue -- M semantically identical copies with
    unique SAIDs, per-copy holder AIDs, and an E1E identity edge from copy k of sedi-age
    to copy k of sedi-id -- with the one difference that a copy's `rd` came out of the
    manifest rather than out of the salt. What that buys shows up here as the registries'
    HISTORIES: copy k's registry was incepted months earlier, has its own placeholder
    prefix, and reaches its assignment at its own sequence number.

    Asserted: every copy is schema-valid, issued by the State to a distinct ALICE_k, in a
    distinct pre-created registry; over-21 is true and over-65 false; the E1E edge is
    index-aligned and verifies as the same subject; the schema rejects a swapped operator
    and a non-boolean flag; selective disclosure yields over-21 while withholding the rest;
    the two sets meet only at the per-index holder AID; and -- the lock-step property --
    the assignment events do NOT all sit at the same sequence number.
    """
    kind = Kinds.json
    bulk = _issue_round(kind)
    pool = bulk.pool
    over65Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(65)

    for k in range(BULK_SIZE):
        idCopy, ageCopy = bulk.idCopies[k], bulk.ageCopies[k]
        assert idCopy.ilk == Ilks.acm and ageCopy.ilk == Ilks.acg
        assert idCopy.sad['i'] == ageCopy.sad['i'] == STATE
        assert idCopy.sad['rd'] == bulk.idManifest.rd(k)
        assert ageCopy.sad['rd'] == bulk.ageManifest.rd(k)
        assert idCopy.sad['a']['i'] == ALICES[k]
        assert idCopy.iseaid == ageCopy.iseaid == ALICES[k]
        assert idCopy.sad['a']['dob']['dob'] == ALICE_DOB     # same Alice in every copy
        assert ageCopy.sad['A'][AGE_OVER21]['over21'] is True
        assert ageCopy.sad['A'][over65Pos]['over65'] is False
        assert_acdc_schema_valid(idCopy)
        ageSchema = assert_acdc_schema_valid(ageCopy)
        assert _verify_identity_edge(ageCopy, idCopy)         # index-aligned E1E

    # Partitioned in every axis, the registry among them.
    assert len(set(ALICES)) == BULK_SIZE
    assert len({c.said for c in bulk.idCopies}) == BULK_SIZE
    assert len({c.sad['rd'] for c in bulk.idCopies}) == BULK_SIZE
    assert len({c.sad['rd'] for c in bulk.ageCopies}) == BULK_SIZE
    assert ({c.sad['rd'] for c in bulk.idCopies}
            .isdisjoint({c.sad['rd'] for c in bulk.ageCopies}))

    # Schema teeth: the identity operator is const-pinned to E1E, and a flag is boolean.
    badOp = json.loads(json.dumps(bulk.ageCopies[0].sad))
    badOp['e']['identity']['o'] = 'I2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(badOp)
    badFlag = json.loads(json.dumps(bulk.ageCopies[0].sad))
    badFlag['A'][AGE_OVER21] = dict(badFlag['A'][AGE_OVER21], over21="yes")
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(badFlag)

    # Selective disclosure over copy 0's aggregate: reveal over-21 + issuee, hide the rest.
    disclosed, _ = bulk.ageAggors[0].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    assert disclosed[AGE_ISSUEE]['i'] == ALICES[0]
    assert disclosed[AGE_OVER21]['over21'] is True
    assert Aggor.verifyDisclosure(disclosed, kind=kind)
    assert "over55" not in json.dumps(disclosed) and "over65" not in json.dumps(disclosed)

    # NOT IN LOCK STEP (#204). Each drawn registry brought its own placeholder prefix, so
    # the assignment events land at different sequence numbers and each copy's blind
    # derives at a different path. An Issuer that advanced all M together would hand a 3rd
    # party a correlator by event count alone, whatever the states were.
    idSns = [pool.sn(i) for i in bulk.idIdx]
    allSns = idSns + [pool.sn(i) for i in bulk.ageIdx]
    assert len(set(allSns)) > 1
    assert [e.sad['n'] for e in bulk.idIssues] == [f"{sn:x}" for sn in idSns]

    # The registries' inception datetimes have nothing to do with the credentials: they
    # precede issuance by months and are spread over several creation batches.
    dts = {pool.regs[i].sad['dt'] for i in bulk.idIdx + bulk.ageIdx}
    assert len(dts) > 1
    assert all(dt < ISSUE_ID_STAMP for dt in dts)

    # Pinned reproducible values (derived, not pasted).
    assert ALICES[0] == "ECOfEi9Fx64Xzln7VtMK7cRr-1-IzJQvw9B_VXsCpaw0"
    assert bulk.idCopies[0].said == "EHT9c_Ju1yWSCVTPdWq_RZ0TG7kj7wnh99xMwCs6afbb"
    assert bulk.ageCopies[0].said == "EORMv256BNOHqCzZqohxdFot8I0E9MQ5ORPgNdygs-8A"
    assert bulk.ageAggors[0].agid == "EEKBIAWc9G5cysYMzpDVPOaMRVXEK0rNFZHLM_1Pkbir"


# ===========================================================================
# Phase 5: per-verifier presentations + the partition property.
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

PRESENT_SALT = b'precregpresalt00'
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
    exactly right.
    """
    e = pres.sad['e']
    assert e['identity']['o'] == 'I2I' and e['identity']['n'] == idCopy.said
    assert e['age']['o'] == 'I2I' and e['age']['n'] == ageCopy.said
    assert pres.sad['i'] == idCopy.iseaid == ageCopy.iseaid   # I2I same-holder binding
    return True


def _context_correlators(k, bulk, pres):
    """Every identifier a verifier of context k can receive that is holder-specific.

    Nine values: the holder AID, both source SAIDs, the aggregate AGID, the fresh
    presentation SAID, both source REGISTRY SAIDs and both ASSIGNMENT EVENT SAIDs.
    Disjoint across contexts is the structural un-joinability proof.
    """
    return {ALICES[k], bulk.idCopies[k].said, bulk.ageCopies[k].said,
            bulk.ageAggors[k].agid, pres.said,
            bulk.idCopies[k].sad['rd'], bulk.ageCopies[k].sad['rd'],
            bulk.idIssues[k].said, bulk.ageIssues[k].said}


def test_precreg_partition_across_verifiers_JSON():
    """Phase 5: two disparate verifiers get disjoint identifier sets, registries included.

    Alice proves over-21 at two mutually-unrelated venues. Her wallet maps each verifier
    to its own copy index, so the Alcove gets copy 0 and the dispensary copy 1: different
    holder AIDs, different source SAIDs, different AGIDs, different presentation SAIDs,
    different registries and different transaction events.

    What is left over is what the whole population shares -- the issuer AID, the two
    schema SAIDs, and the batch root, which covers the round's padding too and therefore
    singles out no one. The arrangement adds one further residual that the co-created
    variant does not have and that is worth stating plainly: the registries were drawn
    from a pool the State also controls, so the State itself can always join Alice's
    contexts. Independent registries decorrelate Alice from VERIFIERS and from 3rd
    parties, not from her Issuer, which is a different problem with a different answer.
    """
    kind = Kinds.json
    bulk = _issue_round(kind)
    presNonces = _BulkNonces(PRESENT_SALT)

    v1, v2 = ALCOVE, DISPENSARY
    k1, k2 = _copy_index_for(v1), _copy_index_for(v2)
    assert k1 != k2                                       # per-verifier spend is injective
    pres1 = _presentation(kind, v1, bulk.idCopies, bulk.ageCopies, presNonces)
    pres2 = _presentation(kind, v2, bulk.idCopies, bulk.ageCopies, presNonces)

    assert _verify_presentation(pres1, bulk.idCopies[k1], bulk.ageCopies[k1])
    assert _verify_presentation(pres2, bulk.idCopies[k2], bulk.ageCopies[k2])
    for k in (k1, k2):
        disclosed, _ = bulk.ageAggors[k].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
        assert disclosed[AGE_OVER21]['over21'] is True
        assert Aggor.verifyDisclosure(disclosed, kind=kind)
    # Self-presentation: holder == subject (unlike the guardianship represented case).
    assert pres1.sad['i'] == bulk.idCopies[k1].iseaid == ALICES[k1]

    # The presentation validates against its purpose-authored schema, and the schema
    # ENFORCES the I2I self-presentation operators: a swapped operator is rejected.
    presSchema = assert_acdc_schema_valid(pres1)
    assert_acdc_schema_valid(pres2, schema=presSchema)
    badOp = json.loads(json.dumps(pres1.sad))
    badOp['e']['identity']['o'] = 'NI2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(presSchema).validate(badOp)

    # --- PARTITIONED: the two contexts share NONE of the holder-specific identifiers. ---
    corr1 = _context_correlators(k1, bulk, pres1)
    corr2 = _context_correlators(k2, bulk, pres2)
    assert corr1.isdisjoint(corr2)                        # THE headline: no join key
    assert len(corr1) == 9
    assert bulk.idCopies[k1].sad['rd'] != bulk.idCopies[k2].sad['rd']
    assert bulk.idIssues[k1].said != bulk.idIssues[k2].said

    # --- PUBLIC, non-correlating: what both contexts DO share is shared by everyone. ---
    assert bulk.idCopies[k1].sad['i'] == bulk.idCopies[k2].sad['i'] == STATE
    assert (bulk.idCopies[k1].sad['s']['$id']
            == bulk.idCopies[k2].sad['s']['$id'])
    assert _verify_anchored(bulk.idIssues[k1].said, bulk.tree, bulk.sealer)
    assert _verify_anchored(bulk.idIssues[k2].said, bulk.tree, bulk.sealer)
    assert len(bulk.tree.leaves) == WHITEN_QUOTA         # the padding is in there too

    # The registries behind the two contexts were incepted at unrelated times among
    # hundreds of others, so even a 3rd party watching the pool cannot pair them.
    i1, i2 = bulk.idIdx[k1], bulk.idIdx[k2]
    assert abs(i1 - i2) > 1
    assert bulk.pool.regs[i1].sad['u'] != bulk.pool.regs[i2].sad['u']

    # --- Guardrail: the wallet mapping is 1-verifier -> 1-copy. ---
    assert len({_copy_index_for(v) for v in VERIFIERS}) == len(VERIFIERS)


# ===========================================================================
# Phase 6: disclosure gating, the four-item proof bundle, and revocation that
# does not announce itself.
# ===========================================================================
# A published SEDI over-21 governance framework, referenced by SAID (public, shared by the
# whole population -> non-correlating). PLACEHOLDER digest of a description string.
GOVERNANCE_SAID = Diger(ser=b'SEDI over-21 governance framework v1').qb64
APPLY_STAMP = "2026-07-22T21:15:00.000000+00:00"
OFFER_STAMP = "2026-07-22T21:16:00.000000+00:00"
AGREE_STAMP = "2026-07-22T21:17:00.000000+00:00"
GRANT_STAMP = "2026-07-22T21:18:00.000000+00:00"


def _offer(kind, *, sender, receiver, prior, presentationSaid, governance):
    """Leak-proof pre-agree offer constructor (Sam, issue #1532: make the leak
    UNREPRESENTABLE at the API rather than merely asserted-absent).

    Its signature has NO parameter for source-credential SAIDs, for a registry SAID, for a
    transaction event, or for a blind, so the pre-agree offer STRUCTURALLY cannot carry a
    stable holder correlator. It commits only the fresh, per-context presentation SAID and
    a public governance ref.

    Pre-created registries do not retire this discipline. What they retire is the registry
    SAID as a SET-WIDE correlator; it remains a perfectly good PER-CONTEXT one -- disclose
    rd_k pre-agree to a verifier who then spurns the exchange, and that verifier keeps a
    durable handle on this context forever. #204 adds the sentence for exactly this case:
    "A Discloser SHOULD NOT disclose the Registry SAID prior to contractual protection
    regardless of which bulk issuance variant is in use."

    Its query block carries an EMPTY disclosure-paths list, `dp: []`. Because this offer
    is SOLICITED -- `prior` binds the apply it answers -- an empty `dp` means "the same
    paths the apply asked for" (#1549).
    """
    return exchange(sender=sender, receiver=receiver, route="/ipex/offer", prior=prior,
                    modifiers=dict(dp=[]),
                    attributes=dict(acdc=presentationSaid, governance=governance),
                    stamp=OFFER_STAMP, kind=kind)


def _verify_issuance(copy, *, reg, event, blind, proof, sealer):
    """The Disclosee's proof-of-issuance check, as #204's verification list states it.

    The Discloser provides four items -- the compact ACDC, the registry inception `rip`,
    the applicable state update together with the blind for that event, and the anchoring
    seal with its inclusion proof -- and the Disclosee performs four checks:

      1. the credential's `rd` names the disclosed `rip`, and the event belongs to it;
      2. the `rip`'s issuer is the ACDC's OWN issuer. This is the step it would be easy to
         skip, and independent registries make skipping it easier, because a distinct
         registry is discovered on every presentation rather than once per set. `rd` is a
         secure DISCOVERY mechanism (spec L2842); follow it without this check and a
         holder can point the verifier at a registry SHE incepted and keeps 'issued'
         forever. The negative case below builds exactly that attack;
      3. the blinded state unblinds, with the blind disclosed FOR THIS ONE EVENT, to a
         state bound to THIS COPY's SAID;
      4. the Issuer's anchoring seal commits to the event, which here means a typed seal
         of the expected tree type whose digest the inclusion proof reconstructs.

    TAKES THE BLIND, NOT THE SALT. Blinder.makeUUID derives the blind from the salt with
    the sequence number as the ENTIRE path (src/keri/core/structing.py), so a Disclosee
    handed the salt could unblind every event in the registry, past and future, without
    ever interacting again. That would defeat the re-blinding remedy at spec L2131 and
    contradict spec L2133, which reserves the salt to Issuer and Discloser. So the
    Discloser sends one event's blind, and each later state change requires a fresh
    disclosure -- which is what Phase 6's revocation exercises.

    Returns the state string ('issued' / 'revoked') or None if any step fails.
    """
    if copy.sad['rd'] != reg.said or event.sad['rd'] != reg.said:
        return None
    if reg.sad['i'] != copy.sad['i']:      # the issuer controls the registry it names
        return None
    blinder = Blinder.unblind(said=event.sad['b'], acdc=copy.said, states=list(SET_STATES),
                              uuid=blind)
    if blinder is None:
        return None
    if sealer.clan is not SealKind or sealer.crew.t != BATCH_TREE_TYPE:
        return None                        # the seal must say which tree it commits to
    if not _BatchTree.verify(event.said, proof, sealer.crew.d):
        return None
    return blinder.state


def test_precreg_disclosure_gating_and_revocation_JSON():
    """Phase 6: registry material rides only in the grant, and revocation is not visible.

    Three properties. First, disclosure gating: the pre-agree /ipex/offer commits only the
    fresh presentation SAID and public governance, built with a constructor that cannot
    carry the source SAIDs, the registry SAIDs, the transaction events or any blinding
    material. All of that appears ONLY in the grant, after a valid signed agree.

    Second, the proof bundle and its verification, per #204: the grant carries the compact
    ACDC, the registry INCEPTION event (not merely its SAID, so the verifier can confirm
    the State incepted it), the assignment event with the blind for THAT event alone, and
    the typed anchoring seal with an inclusion proof.

    Third -- the measure #1530 names as missing -- revocation does not announce itself.
    The State revokes the copy spent at the Alcove and then keeps updating that registry
    in later rounds with state-preserving events, so the TEL does not go quiet at the
    moment the credential died. A verifier that wants current status must come back for a
    fresh blind every time, and gets nothing from the shape of the log.
    """
    kind = Kinds.json
    bulk = _issue_round(kind)
    pool = bulk.pool
    presNonces = _BulkNonces(PRESENT_SALT)

    verifier = ALCOVE
    k = _copy_index_for(verifier)
    i = bulk.ageIdx[k]                                   # copy k's sedi-age registry
    pres = _presentation(kind, verifier, bulk.idCopies, bulk.ageCopies, presNonces)
    presSchemaSaid = pres.sad['s']['$id']

    # 1. apply (verifier -> holder): the challenge, as disclosure paths in the query
    # block. Each entry is a TRIPLE, (schemaSAID, prefix, [paths]) (@SmithSamuelM, #1549).
    apply = exchange(sender=verifier, receiver=ALICES[k], route="/ipex/apply",
                     modifiers=dict(dp=[[presSchemaSaid, "", ["i", "a/i"]],
                                        [bulk.idCopies[k].sad['s']['$id'], "", ["a/i"]],
                                        [bulk.ageCopies[k].sad['s']['$id'], "",
                                         ["A/i", "A/over21"]]]),
                     attributes=dict(m="Prove over-21.", g=GOVERNANCE_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    dp = apply.sad['q']['dp']
    assert all(len(entry) == 3 for entry in dp)                 # (ssaid, prefix, paths)
    assert [entry[1] for entry in dp] == ["", "", ""]           # relative: position names
    # The schema SAID is shared across the whole bulk set by design; the request names it,
    # never a copy SAID and never a registry, so the apply introduces no correlator.
    assert all(c.said.encode() not in apply.raw
               for c in bulk.idCopies + bulk.ageCopies)
    assert all(pool.rd(j).encode() not in apply.raw
               for j in bulk.idIdx + bulk.ageIdx)

    # 2. offer (holder -> verifier): via the leak-proof constructor. Nothing stable.
    offer = _offer(kind, sender=ALICES[k], receiver=verifier, prior=apply.said,
                   presentationSaid=pres.said, governance=GOVERNANCE_SAID)
    assert offer.sad['p'] == apply.said
    assert offer.sad['q']['dp'] == []                           # solicited: same paths
    assert pres.said.encode() in offer.raw                      # fresh per-context: safe
    assert bulk.idCopies[k].said.encode() not in offer.raw     # source SAID withheld
    assert bulk.ageCopies[k].said.encode() not in offer.raw
    assert pool.rd(i).encode() not in offer.raw                 # REGISTRY withheld
    assert bulk.ageIssues[k].said.encode() not in offer.raw    # TEL event withheld
    assert bulk.ageNonces.s(k).encode() not in offer.raw       # blinding salt withheld
    assert bulk.sealer.crew.d.encode() not in offer.raw        # batch root withheld

    # 3. agree (verifier -> holder): signed acceptance binding the offer.
    agree = exchange(sender=verifier, receiver=ALICES[k], route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    vSigner = _SIGNERS[2 + k]                                   # the verifier's key
    vSig = vSigner.sign(ser=agree.raw, index=0)
    keyState = Verfer(qb64=vSigner.verfer.qb64)
    assert keyState.verify(sig=vSig.raw, ser=agree.raw)

    # 4. The gate: the holder discloses the whole issuance-proof bundle ONLY on a valid,
    # offer-binding, signed agree. The wallet reads the registry's head to learn the
    # sequence number, then derives the blind for that ONE event.
    assignSn = pool.sn(i)
    assert pool.head(i).said == bulk.ageIssues[k].said

    def disclose(agreeMsg, sig):
        if not (agreeMsg.sad['r'] == "/ipex/agree" and agreeMsg.sad['p'] == offer.said
                and keyState.verify(sig=sig.raw, ser=agreeMsg.raw)):
            return None
        ageDisc, _ = bulk.ageAggors[k].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
        return exchange(sender=ALICES[k], receiver=verifier, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(
                            acdc=pres.sad, ageDisclosure=ageDisc,
                            issuance=dict(rip=pool.regs[i].sad,
                                          event=bulk.ageIssues[k].sad,
                                          blind=bulk.ageWallet.blind(k, assignSn),
                                          proof=bulk.tree.prove(
                                              bulk.ageIssues[k].said),
                                          seal=bulk.sealer.crew._asdict())),
                        stamp=GRANT_STAMP, kind=kind)

    # A forged signature unlocks nothing.
    assert disclose(agree, _SIGNERS[0].sign(ser=agree.raw, index=0)) is None
    # A valid agree unlocks the grant; the registry material appears ONLY now.
    grant = disclose(agree, vSig)
    assert grant is not None and grant.sad['p'] == agree.said
    assert pool.rd(i).encode() in grant.raw                     # registry revealed...
    assert bulk.ageIssues[k].said.encode() in grant.raw        # ...event revealed...
    assert bulk.ageNonces.s(k).encode() not in grant.raw       # ...salt STILL withheld...
    assert bulk.ageWallet.blind(k, assignSn).encode() in grant.raw   # ...one blind only

    # The verifier walks the chain from the grant and runs #204's four checks.
    granted = grant.sad['a']['acdc']
    assert granted['e']['age']['n'] == bulk.ageCopies[k].said
    bundle = grant.sad['a']['issuance']
    assert bundle['rip']['d'] == pool.rd(i) and bundle['rip']['i'] == STATE
    assert bundle['seal']['t'] == BATCH_TREE_TYPE               # typed seal, in band
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i],
                            event=bulk.ageIssues[k], blind=bundle['blind'],
                            proof=bulk.tree.prove(bulk.ageIssues[k].said),
                            sealer=bulk.sealer) == 'issued'
    assert grant.sad['a']['ageDisclosure'][AGE_OVER21]['over21'] is True

    # The bundle proves THIS copy and no other: another copy's registry or blind fails.
    other = (k + 1) % BULK_SIZE
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[bulk.ageIdx[other]],
                            event=bulk.ageIssues[k], blind=bundle['blind'],
                            proof=bulk.tree.prove(bulk.ageIssues[k].said),
                            sealer=bulk.sealer) is None
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i],
                            event=bulk.ageIssues[k],
                            blind=bulk.ageWallet.blind(other, assignSn),
                            proof=bulk.tree.prove(bulk.ageIssues[k].said),
                            sealer=bulk.sealer) is None

    # And the discovery check has teeth. A credential claiming State issuance whose `rd`
    # points at a registry the HOLDER incepted -- where she can keep the state 'issued'
    # forever -- fails, even though every SAID in the bundle is internally consistent and
    # the event proves under a real batch root.
    rogueNonces = _BulkNonces(b'precregrogueslt0')
    rogueReg = regcept(israid=ALICES[k], uuid=rogueNonces.u(k), stamp=ROUND_STAMP,
                       kind=kind)
    rogueCopy = acdcagg(israid=STATE, uuid=rogueNonces.u(k + 1),
                        regid=rogueReg.said, schema=bulk.ageCopies[k].sad['s'],
                        aggregate=Aggor(ael=_age_ael(rogueNonces, k), makify=True,
                                        kind=kind).ael,
                        edge=bulk.ageCopies[k].sad['e'], kind=kind)
    rogueBlinder = Blinder.blind(acdc=rogueCopy.said, state='issued',
                                 salt=rogueNonces.s(k), sn=1)
    rogueIssue = blindate(regid=rogueReg.said, prior=rogueReg.said,
                          blid=rogueBlinder.said, sn=1, stamp=ROUND_STAMP, kind=kind)
    rogueTree, rogueSealer = _anchor([rogueIssue.said],
                                     [e.said for e in bulk.padding])
    assert _verify_anchored(rogueIssue.said, rogueTree, rogueSealer)  # the event is real
    assert rogueCopy.sad['rd'] == rogueReg.said                       # self-consistent
    assert _verify_issuance(rogueCopy, reg=rogueReg, event=rogueIssue,
                            blind=Blinder.makeUUID(salt=rogueNonces.s(k), sn=1),
                            proof=rogueTree.prove(rogueIssue.said),
                            sealer=rogueSealer) is None               # yet refused

    # The anchoring evidence has to be the right anchoring evidence, in both directions.
    # A proof drawn against some other batch fails against this round's seal...
    strayTree, _ = _anchor([e.said for e in bulk.padding])
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i],
                            event=bulk.ageIssues[k], blind=bundle['blind'],
                            proof=strayTree.prove(bulk.padding[0].said),
                            sealer=bulk.sealer) is None
    # ...and a BARE Merkle-root seal is refused rather than assumed, which is what makes
    # the typed seal load-bearing instead of decorative: a Validator holding a root digest
    # alone cannot tell a dense batch tree from the amalgamated sparse tree spec L2918
    # describes, and #204 therefore has the Issuer commit the construction in band.
    bareSealer = Sealer(crew=SealRoot(rd=bulk.tree.root))
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i],
                            event=bulk.ageIssues[k], blind=bundle['blind'],
                            proof=bulk.tree.prove(bulk.ageIssues[k].said),
                            sealer=bareSealer) is None

    # --- Revocation, per copy, followed by traffic that hides when it happened. ---
    revoked = pool.restate(i, 'revoked', REVOKE_STAMP)
    revokeSn = pool.sn(i)
    assert revoked.sad['p'] == bulk.ageIssues[k].said           # chains onto issuance
    assert b"revoked" not in revoked.raw                         # state word stays blinded

    # Two later state-PRESERVING updates on the same registry. This is what #1530's
    # guardianship example says it does not do: without them, a registry that stops
    # emitting events at the moment of revocation dates the revocation for any observer,
    # even one who can read no state at all.
    quiet = [pool.restate(i, 'revoked', LATER_ROUND_STAMP) for _ in range(2)]
    assert pool.sn(i) == revokeSn + 2
    assert len({e.sad['b'] for e in [revoked] + quiet}) == 3      # each re-blinded afresh
    laterTree, laterSealer = _anchor([revoked.said], [e.said for e in quiet],
                                     [e.said for e in bulk.padding])
    for event in [revoked] + quiet:
        assert _verify_anchored(event.said, laterTree, laterSealer)

    # The verifier cannot follow the registry on its own: the blind it was given covers
    # the assignment event only, so reading any later event needs a FRESH disclosure. That
    # is spec L2131's remedy, and it works only because the grant sent a blind, not a salt.
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i], event=revoked,
                            blind=bulk.ageWallet.blind(k, assignSn),
                            proof=laterTree.prove(revoked.said),
                            sealer=laterSealer) is None
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i], event=revoked,
                            blind=bulk.ageWallet.blind(k, revokeSn),
                            proof=laterTree.prove(revoked.said),
                            sealer=laterSealer) == 'revoked'
    # ...and the state-preserving events after it read 'revoked' too, so following the
    # registry to its head tells the truth without the log ever having gone quiet.
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i], event=quiet[-1],
                            blind=bulk.ageWallet.blind(k, pool.sn(i)),
                            proof=laterTree.prove(quiet[-1].said),
                            sealer=laterSealer) == 'revoked'

    # THE per-copy capability: the dispensary's copy is untouched. Different registry,
    # different state. The shared-registry variant revokes all M or none.
    j = bulk.ageIdx[other]
    assert _verify_issuance(bulk.ageCopies[other], reg=pool.regs[j],
                            event=bulk.ageIssues[other],
                            blind=bulk.ageWallet.blind(other, pool.sn(j)),
                            proof=bulk.tree.prove(bulk.ageIssues[other].said),
                            sealer=bulk.sealer) == 'issued'

    # The graph still binds (edges are immutable), yet the Alcove's own status check now
    # returns 'revoked' where it returned 'issued', so a status-checking verifier refuses.
    assert _verify_presentation(pres, bulk.idCopies[k], bulk.ageCopies[k])
    assert _verify_issuance(bulk.ageCopies[k], reg=pool.regs[i], event=revoked,
                            blind=bulk.ageWallet.blind(k, revokeSn),
                            proof=laterTree.prove(revoked.said),
                            sealer=laterSealer) != 'issued'


# ===========================================================================
# Phase 7: the invariants hold across every serialization kind.
# ===========================================================================
@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_precreg_serialization_kinds(kind):
    """Phases 1-6 invariants hold across every serialization kind, not just JSON.

    Exercises the same flows -- a pre-created pool, a conveyed manifest, both bulk sets
    built around drawn registry SAIDs, the padded round under one typed seal, the
    per-verifier partition and the per-copy blindable state -- over CESR (the native KERI
    wire format) and CBOR/MGPK, asserting the behavioral invariants without pinning
    per-kind SAIDs. (The no-correlator-on-the-wire substring checks are JSON-specific:
    the CESR wire form base64-encodes the payload.)
    """
    bulk = _issue_round(kind, pool=_RegistryPool(kind, size=120))
    pool = bulk.pool

    # Per copy: schema-valid; issued to its own holder AID in its own drawn registry;
    # index-aligned E1E; its registry state provable under the one typed round seal.
    for k in range(BULK_SIZE):
        idCopy, ageCopy = bulk.idCopies[k], bulk.ageCopies[k]
        assert idCopy.ilk == Ilks.acm and idCopy.kind == kind
        assert ageCopy.ilk == Ilks.acg
        assert idCopy.iseaid == ageCopy.iseaid == ALICES[k]
        assert idCopy.sad['rd'] == bulk.idManifest.rd(k)
        assert ageCopy.sad['rd'] == bulk.ageManifest.rd(k)
        assert_acdc_schema_valid(idCopy)
        assert_acdc_schema_valid(ageCopy)
        assert _verify_identity_edge(ageCopy, idCopy)         # E1E on every kind
        for copy, idx, issues, wallet in (
                (idCopy, bulk.idIdx, bulk.idIssues, bulk.idWallet),
                (ageCopy, bulk.ageIdx, bulk.ageIssues, bulk.ageWallet)):
            i = idx[k]
            assert _verify_issuance(copy, reg=pool.regs[i], event=issues[k],
                                    blind=wallet.blind(k, pool.sn(i)),
                                    proof=bulk.tree.prove(issues[k].said),
                                    sealer=bulk.sealer) == 'issued'

    # 2*M drawn registries out of a pool that dwarfs them, under exactly ONE typed seal.
    assert len({c.sad['rd'] for c in bulk.idCopies + bulk.ageCopies}) == 2 * BULK_SIZE
    assert pool.size >= 4 * BULK_SIZE
    assert bulk.sealer.clan is SealKind
    assert bulk.sealer.crew.d == bulk.tree.root
    assert len(bulk.alice) * 5 <= len(bulk.tree.leaves)      # the herd ratio holds

    # `rd` still is not derivable, on every kind: it is the SAID of a whole rip event.
    i0 = bulk.idIdx[0]
    assert regcept(israid=STATE, uuid=pool.uuid(i0), stamp=ROUND_STAMP,
                   kind=kind).said != pool.rd(i0)

    # Partition across two contexts holds on every kind, registries and events included.
    presNonces = _BulkNonces(PRESENT_SALT)
    k1, k2 = _copy_index_for(ALCOVE), _copy_index_for(DISPENSARY)
    pres1 = _presentation(kind, ALCOVE, bulk.idCopies, bulk.ageCopies, presNonces)
    pres2 = _presentation(kind, DISPENSARY, bulk.idCopies, bulk.ageCopies, presNonces)
    assert _verify_presentation(pres1, bulk.idCopies[k1], bulk.ageCopies[k1])
    assert _verify_presentation(pres2, bulk.idCopies[k2], bulk.ageCopies[k2])
    assert_acdc_schema_valid(pres1)                  # presentation schema-valid every kind
    assert _context_correlators(k1, bulk, pres1).isdisjoint(
           _context_correlators(k2, bulk, pres2))

    # Private presentation: compact and expanded forms share one SAID.
    presCompact = _presentation(kind, ALCOVE, bulk.idCopies, bulk.ageCopies,
                                presNonces, compactify=True)
    assert presCompact.said == pres1.said
    assert isinstance(pres1.sad['e'], dict)          # sections inline...
    assert isinstance(presCompact.sad['e'], str)     # ...vs. collapsed to a SAID

    # Selective over-21 disclosure verifies via the AGID on every kind.
    disclosed, _ = bulk.ageAggors[k1].disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    assert disclosed[AGE_OVER21]['over21'] is True
    assert Aggor.verifyDisclosure(disclosed, kind=kind)


if __name__ == "__main__":
    test_precreg_pool_JSON()
    test_precreg_conveyance_JSON()
    test_precreg_whitening_round_JSON()
    test_precreg_sedi_sets_JSON()
    test_precreg_partition_across_verifiers_JSON()
    test_precreg_disclosure_gating_and_revocation_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_precreg_serialization_kinds(_kind)
