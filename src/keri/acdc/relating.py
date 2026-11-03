# -*- encoding: utf-8 -*-
"""
keri.acdc.relating module

Unary edge-Operator relations that need evidence beyond the two ACDCs an edge joins.

I2I, NI2I and E1E compare AIDs already fixed in the near and far SADs. DI2I asks
whether the near ACDC's issuer is a delegated AID of the far node's issuee, which
only the KELs between them can answer. The v1 Verifier and the v2 IPEX path both
evaluate DI2I, so the question is answered once, here, rather than once per path:
two encodings of one relation are how the two evaluators came to disagree before
acdc.chaining existed. Each caller maps the answer into its own verdict and
disposition, as with chaining.
"""


def delegationRefusal(kevers, db, pre, delpre):
    """Returns why pre is not a delegated AID of delpre at any depth, if it is decided.

    Climbs pre's delegation chain toward delpre and requires of every hop that the
    delegator anchored the delegate's `dip` and was itself permitted to delegate.
    Both are per-hop questions, so neither can be asked once at the top.

    Deliberately NOT implemented as ``kevers[pre].delpre == delpre``.
    ``Kever.validateDelegation`` returns early -- with no seal lookup whatsoever --
    when the delegated event is locally owned, locally membered, or locally
    witnessed, and the comment above that return is explicit that a witness "accepts
    without waiting for delegation seal to be anchored in delegator's KEL". Since
    setupWitness co-locates a credential Verifier in the same Habery, a delpre-based
    check would accept a DI2I edge for any AID this Habery happens to witness whose
    claimed delegator never anchored anything: issuance under authority never
    granted. ``delpre`` records what the delegate asserted in its own `di` field;
    only the delegator's anchored approval seal records what the delegator agreed
    to.

    So each hop is confirmed the way the KEL layer confirms it, by delegating to
    Kever.fetchDelegatingEvent: consult the approval source-seal couple in .db.aess
    -- which logEvent writes only when validateDelegation actually found and
    verified the seal, since the exemption returns (None, None) and that write is
    gated on those being present -- and failing that, walk the delegator's KEL for
    the anchoring seal directly. That KEL walk is what keeps a Habery with no .aess
    entry (a witness, or the delegate's own controller) from being permanently
    unable to validate an edge that is in fact approved. .aess is also pinned by
    flows in which this Habery took part in the delegation itself
    (app/delegating.py:153, app/grouping.py:220,
    cli/commands/delegate/confirm.py:109), each only after observing the anchor.

    DND is re-checked here for the same reason delpre is not trusted: the exemption
    above returns before validateDelegation reaches its doNotDelegate refusal, so an
    exempted Habery holds dips a disinterested validator would never have accepted.
    Without this, a witness-hosted Verifier would honor a chain that a watcher-fed
    one refuses -- identical bytes, opposite verdicts, which is precisely what
    reading the anchor instead of `delpre` exists to prevent. The trait is read from
    the delegator's inception event and Kever.config runs once, so a delegator's
    answer here never moves.

    The climb needs no depth bound and gets none: a delegated AID's prefix is a digest
    of the `dip` that carries its `di`, so a cycle in the chain would require a hash
    cycle. A bound would also be a conformance seam, letting two conforming validators
    disagree on identical bytes with no wire-visible cause. Depth is the delegator's to
    choose, via DND. The visited set below is a termination guarantee over a possibly
    corrupt local database, not a policy.

    Called with original=False so that a missing seal returns None rather than raising,
    and so an inconsistent .aess entry is left alone: a verifier reads key state, it
    does not repair the delegate's escrow. The one write this can cause is
    fetchDelegatingEvent pinning the couple it has just verified against the
    delegator's trunk -- the same cache repair keripy performs during escrow
    processing, gated on the delegated event already having been accepted. A
    ValidationError from a genuinely inconsistent database is left to propagate rather
    than being flattened into a silent False.

    Superseding is handled as the KEL layer handles it, not more strictly. The .aess
    fast path accepts a delegating event that was first seen (it checks .fons) even if
    it has since been superseded -- fetchDelegatingEvent documents that as deliberate --
    while the KEL walk looks only at the last event at each sn and so would not find
    one. Inheriting that asymmetry is the right call rather than something to tighten
    here: a validator that has accepted the delegate's KEL should not then refuse the
    credentials that delegate issued, and DI2I asks the same question the KEL layer
    already answered.

    That asymmetry has a consequence worth stating plainly, because it sits in tension
    with the DND paragraph above. A validator that evaluated an edge before an
    intermediate's anchoring event was superseded keeps a pinned .aess entry and goes
    on accepting; one that first evaluates it afterwards walks the KEL, does not find
    the superseded anchor, and refuses. Same bytes, verdicts that differ by when the
    validator first looked. It is not introduced here -- it is fetchDelegatingEvent's
    documented first-seen behavior, and it is identical at one hop -- but this is the
    first caller to reach it from the credential layer, so it is no longer only the KEL
    layer's to own. Answering it belongs with superseding recovery, not with an edge
    operator second-guessing the KEL its own validator accepted.

    Retirement of a delegate is deliberately not modelled. It is key-state based: a
    retired delegate rotates to keys it cannot sign with, so it issues nothing further
    while everything it issued while authorized stays valid, and the approval seals are
    byte-identical before and after. A check here that tried to detect retirement would
    both fail (nothing changes structurally) and be wrong (it would invalidate
    credentials issued while the delegate was legitimately authorized).

    Parameters:
        kevers (dict): key state by prefix, as .kevers of the validating Habery
        db (Baser): the validating Habery's database, read for the `dip`
        pre (str): qb64 AID whose delegation is in question, i.e. the issuer of the
            near (edge-bearing) ACDC
        delpre (str): qb64 AID that must be somewhere above it in the delegation
            chain, i.e. the far node's issuee

    Returns:
        str|None: "" when every hop from pre up to delpre is a delegation its
            delegator anchored and that DND permitted. A non-empty reason when the
            answer is decided against: the chain tops out without meeting delpre,
            or a delegator on it carries DND. Both are read from inception events,
            so no later arrival changes them. None when it is not yet decidable,
            because a key state, a `dip` or an anchoring seal the climb needs is
            not in hand.

    """
    seen = set()
    while pre not in seen:
        seen.add(pre)

        if pre not in kevers:  # no key state yet, nothing to evaluate
            return None

        kever = kevers[pre]
        if kever.delpre is None:  # top of the chain reached without meeting delpre
            return f"{pre} is not delegated, and the chain ends there"

        if kever.delpre not in kevers:  # delegator's KEL not yet in hand
            return None

        if kevers[kever.delpre].doNotDelegate:
            return f"delegator {kever.delpre} of {pre} carries DND"

        # The delegation is settled at inception and does not move afterwards. `di`
        # appears in a `dip` and in no other event -- a `drt` has no such field -- so
        # the delegator anchoring the `dip` is the whole of what makes this hop a
        # delegation, and no later event can change or renew it. An earlier revision
        # keyed on `kever.lastEst.d`, asking whether the delegate's *current*
        # establishment event was approved; that is the KEL layer's question, and
        # asking it again here made a fixed edge unstable inside the exemption above,
        # where an unanchored rotation is accepted locally and `lastEst` advances.
        #
        # A delegated AID's prefix is a digest of its own `dip`, so `i` equals `d`
        # there and the `dip` is retrievable at (pre, pre).
        serder = db.evts.get(keys=(pre, pre))
        if serder is None:  # delegated inception event not retrievable
            return None

        if kever.fetchDelegatingEvent(delpre=kever.delpre, serder=serder,
                                      original=False, eager=True) is None:
            return None  # anchor not seen: the delegator may yet publish it

        if kever.delpre == delpre:
            return ""

        pre = kever.delpre

    # A cycle, reachable only from a corrupt database. Refused rather than left
    # pending, since retrying against the same database cannot break it.
    return f"delegation chain from {pre} cycles"
