# -*- encoding: utf-8 -*-
"""
tests.acdc.test_regeventing module

Tests for keri.acdc.regeventing: the ACDC v2 registry (TEL) verification core.

The verification core answers, for a party holding evidence: given a registry
event chain (rip + bup events), the issuer's KEL (a Baser the caller has
already populated -- KEL verification is not regeventing's job), and optionally
a disclosed blinded-state block, what is the registry's verified state?

All valid material is built with keripy's own builders (regcept, blindate,
acdcmap) and real Habs (habbing) with anchors written through Hab.interact.
Adversarial cases are reached by mutating valid material, never by hand-rolling
events.

The test names carry the row ids (V1..V23) of the approved test catalogue so
the mapping from obligation to test is auditable.  V17 (parallel-registry
equivocation) and V24 (a chain mixing upd and bup events) are absent from this
module: the first belongs with a multi-registry policy layer, and the second
tests the 'upd' event, which is deprecated.  V16b is an added row covering an
ACDC presented against a blinded head with no disclosure.
"""

import inspect
import json

import pytest

from keri import kering
from keri import Vrsn_2_0, Ilks
from keri.core import Blinder, BlindState, Diger, Number, SerderACDC
from keri.core.signing import Salter
from keri.acdc import Registry, Regery, regcept, blindate, acdcmap
from keri.acdc import regeventing
from keri.acdc.regeventing import RegStateRecord, vet, vetBlind
from keri.app import habbing


# Fixed stamps (all the same length so raw mutations preserve size).
STAMP0 = '2025-07-04T17:50:00.000000+00:00'
STAMP1 = '2025-08-01T18:06:10.988921+00:00'
STAMP2 = '2025-09-01T18:06:10.988921+00:00'
STAMP3 = '2025-10-01T18:06:10.988921+00:00'

# Issuer-side secret used only to construct valid blinded material in tests.
# The verify path itself never sees it (that absence is row V23).
SALT = Salter(raw=b'0123456789abcdef').qb64

# The ACDC specification's BLID conformance vectors (spec-body.md ~:2166-2170
# placeholder, ~:2209-2213 issued).  Lineage caveat: the spec's worked examples
# were synced from keripy, so these defend against drift, not shared error.
SPEC_PLACEHOLDER_UUID = "aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8"
SPEC_PLACEHOLDER_BLID = "ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J"
SPEC_ISSUED_UUID = "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB"
SPEC_ISSUED_TD = "EP-iKGmXD-iZu3RhVA2FTI-dOdX50bRBV3VDCy-peOtv"
SPEC_ISSUED_BLID = "EItpXDP26bvHIRZ0GrJwhOIR5lLEaviFcIxFodP6IJ8N"


def seal(serder):
    """Transaction event seal couple {s, d} where s is the TEL event's own
    sequence number (a lookup hint, never a KEL sn) and d its SAID."""
    return dict(s=serder.sad['n'], d=serder.said)


def anchor(hab, *serders, data=None):
    """Anchor seals for the given TEL events in one interaction event in
    hab's KEL.  Returns the anchoring key event's serder."""
    if data is None:
        data = [seal(serder) for serder in serders]
    hab.interact(data=data)
    return hab.kever.serder


def makeRegistry(hab, stamp=STAMP0, anchored=True):
    """Create a registry inception (rip) for hab and, unless told otherwise,
    anchor it in hab's KEL."""
    ripper = regcept(israid=hab.pre, stamp=stamp)
    if anchored:
        anchor(hab, ripper)
    return ripper


def makeUpdate(regid, prior, acdc, state, *, sn=1, stamp=None, salt=SALT):
    """Build one blindable update: the issuer-side blinded state block and the
    bup event that anchors its BLID.

    Returns:
        (blinder, bup) (tuple[Blinder, SerderACDC])
    """
    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
    bup = blindate(regid=regid, prior=prior, blid=blinder.said, sn=sn,
                   stamp=stamp)
    return blinder, bup


def makeAcdc(hab, regid=None, name="Sunspot College"):
    """Create a real ACDC (acm) issued by hab, optionally bound to a registry
    through its rd field."""
    return acdcmap(israid=hab.pre, regid=regid,
                   attribute=dict(d='', name=name, level="gold"))


def remake(serder, **changes):
    """Mutate a valid event's sad and remake it as a self-consistent serder
    (recomputed SAID).  This is the named mutation-operator route to
    adversarial material that the builders refuse to produce."""
    sad = dict(serder.sad)
    sad.update(changes)
    sad['d'] = ''
    return SerderACDC(sad=sad, makify=True)


def openIssuer(name):
    """Context manager for a fresh v2 issuer hab."""
    return habbing.openHab(name=name, temp=True, version=Vrsn_2_0)


# ---------------------------------------------------------------------------
# Chain and fields
# ---------------------------------------------------------------------------

def test_V1_rip_bup_issued_verifies():
    """V1: rip -> bup(issued), both anchored: verifies, state issued at n 1."""
    with openIssuer("v1") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(ripper.said, ripper.said, acdc.said,
                                  'issued', sn=1, stamp=STAMP1)
        anchor(hab, bup)

        rec = vet(rip=ripper, updates=[bup], db=hby.db, acdc=acdc,
                  blinder=blinder)
        assert isinstance(rec, RegStateRecord)
        assert rec.regid == ripper.said
        assert rec.issuer == hab.pre
        assert rec.said == bup.said
        assert rec.sn == 1
        assert rec.ilk == Ilks.bup
        assert rec.acdc == acdc.said
        assert rec.state == 'issued'
        assert rec.binding == 'mutual'
        assert len(rec.anchors) == 2  # one verified couple per TEL event
        for kelsn, kelsaid in rec.anchors:
            assert hby.db.kels.getLast(keys=hab.pre, on=kelsn) is not None

        # the core accepts raw streams as well as SerderACDC instances
        rec2 = vet(rip=bytes(ripper.raw), updates=[bytes(bup.raw)],
                   db=hby.db, blinder=blinder)
        assert rec2.said == bup.said
        assert rec2.state == 'issued'
        assert rec2.binding is None  # no ACDC presented, no binding claimed


def test_V2_revoking_bup_state_revoked():
    """V2: V1 plus a revoking bup, anchored: state revoked at head n 2."""
    with openIssuer("v2") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder1, bup1 = makeUpdate(ripper.said, ripper.said, acdc.said,
                                    'issued', sn=1, stamp=STAMP1)
        anchor(hab, bup1)
        blinder2, bup2 = makeUpdate(ripper.said, bup1.said, acdc.said,
                                    'revoked', sn=2, stamp=STAMP2)
        anchor(hab, bup2)

        rec = vet(rip=ripper, updates=[bup1, bup2], db=hby.db, acdc=acdc,
                  blinder=blinder2)
        assert rec.sn == 2
        assert rec.said == bup2.said
        assert rec.state == 'revoked'
        assert rec.acdc == acdc.said


def test_V3_rip_n_nonzero_refused():
    """V3: a rip whose n is not "0" is refused as malformed."""
    with openIssuer("v3") as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        bad = remake(ripper, n='1')  # builder refuses; mutation reaches it
        anchor(hab, bad)
        with pytest.raises(kering.MissequenceError):
            vet(rip=bad, db=hby.db)


def test_V4_n_gap_refused():
    """V4: a chain with an n gap (0, 2) is refused as malformed; n = prior + 1
    exactly.  A gap is not an escrow candidate on the party-side core."""
    with openIssuer("v4") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, gapped = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                               sn=2, stamp=STAMP1)
        anchor(hab, gapped)  # anchored, so the gap is the only defect
        with pytest.raises(kering.MissequenceError):
            vet(rip=ripper, updates=[gapped], db=hby.db)


def test_V5_p_mismatch_refused():
    """V5: an update whose p is not the prior event's d is refused."""
    with openIssuer("v5") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, crooked = makeUpdate(ripper.said, acdc.said, acdc.said, 'issued',
                                sn=1, stamp=STAMP1)
        anchor(hab, crooked)
        with pytest.raises(kering.MisdigestError):
            vet(rip=ripper, updates=[crooked], db=hby.db)


def test_V6_rd_mismatch_refused():
    """V6: an update whose rd is not the rip's d is refused."""
    with openIssuer("v6") as (hby, hab):
        ripper = makeRegistry(hab)
        other = makeRegistry(hab, stamp=STAMP2)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, stray = makeUpdate(other.said, ripper.said, acdc.said, 'issued',
                              sn=1, stamp=STAMP1)
        anchor(hab, stray)
        with pytest.raises(kering.MisregistryError):
            vet(rip=ripper, updates=[stray], db=hby.db)


def test_V7_field_order_and_said_mutations_refused():
    """V7: field-order and SAID mutations across both event types are each
    refused by SerderACDC's own validation (one row standing for the mutation
    battery)."""
    with openIssuer("v7") as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, bup = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                            sn=1, stamp=STAMP1)

        for serder in (ripper, bup):
            raw = bytes(serder.raw)

            # SAID mutation: tamper the embedded said
            said = serder.said
            flipped = said[:-1] + ('A' if said[-1] != 'A' else 'B')
            traw = raw.replace(said.encode(), flipped.encode())
            assert traw != raw
            with pytest.raises(kering.ValidationError):
                SerderACDC(raw=traw)

            # value mutation without recomputing the said
            traw = raw.replace(serder.sad['dt'].encode(), STAMP3.encode())
            assert traw != raw
            with pytest.raises(kering.ValidationError):
                SerderACDC(raw=traw)

            # field-order mutation: same fields and values, order broken
            sad = json.loads(raw.decode())
            keys = list(sad)
            keys[-1], keys[-2] = keys[-2], keys[-1]
            resad = {k: sad[k] for k in keys}
            traw = json.dumps(resad, separators=(",", ":")).encode()
            assert len(traw) == len(raw)
            with pytest.raises(kering.ValidationError):
                SerderACDC(raw=traw)


def test_shared_tel_validation_kernel_rejects_overlap_rules():
    """The shared TEL validators reject the malformed field combinations both sides care about."""
    with openIssuer("shared-kernel") as (hby, hab):
        # Set up 2 registry, and one ACDC 
        ripper = makeRegistry(hab, anchored=False)
        acdc = makeAcdc(hab, regid=ripper.said)
        other = makeRegistry(hab, stamp=STAMP2, anchored=False)

        # sn = 0 for rip
        bad_rip = remake(ripper, n='1')
        with pytest.raises(kering.MissequenceError):
            regeventing._validateRip(bad_rip, issuer=hab.pre)

        # issuer is unknown
        foreign_rip = remake(ripper, i="EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        with pytest.raises(kering.ValidationError):
            regeventing._validateRip(foreign_rip, issuer=hab.pre)

        # sn = 0 for bup
        _, zero_bup = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                                 sn=0, stamp=STAMP1)
        with pytest.raises(kering.MissequenceError):
            regeventing._validateUpdate(zero_bup, regid=ripper.said)

        # registry mismatch
        _, stray = makeUpdate(other.said, ripper.said, acdc.said, 'issued',
                              sn=1, stamp=STAMP1)
        with pytest.raises(kering.MisregistryError):
            regeventing._validateUpdate(stray, regid=ripper.said)

        # wrong prior
        _, crooked = makeUpdate(ripper.said, acdc.said, acdc.said, 'issued',
                                sn=1, stamp=STAMP1)
        with pytest.raises(kering.MisdigestError):
            regeventing._validateUpdate(crooked, regid=ripper.said,
                                        prior=ripper.said)


# ---------------------------------------------------------------------------
# Anchors (the seal-anchored verification core)
# ---------------------------------------------------------------------------

def test_V8_unanchored_update_retryable():
    """V8: an update never anchored in the issuer's KEL establishes nothing,
    retryably (the maes posture) -- distinct from any refusal class."""
    with openIssuer("v8") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(ripper.said, ripper.said, acdc.said,
                                  'issued', sn=1, stamp=STAMP1)
        # deliberately not anchored
        with pytest.raises(kering.MissingAnchorError):
            vet(rip=ripper, updates=[bup], db=hby.db)
        # once the anchor arrives, the same evidence verifies (retryable)
        anchor(hab, bup)
        rec = vet(rip=ripper, updates=[bup], db=hby.db, blinder=blinder)
        assert rec.state == 'issued'


def test_shared_anchor_couple_verifier_matches_local_and_verifier_policies():
    """The shared anchor-couple verifier drives local commit while verifier-side still treats missing anchors as retryable."""
    with openIssuer("shared-anchor-couple") as (hby, hab):
        rgy = Regery(hby=hby, name="shared-anchor-couple", temp=True)
        try:
            registry = Registry(hab=hab, store=rgy.store, name="shared-anchor-couple")

            # Setup registry and anchor the rip event 
            ripper = registry.make(stamp=STAMP0)
            seal = dict(i=ripper.said, s=ripper.sad['n'], d=ripper.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            assert registry.anchorMsg(ripper.said) is True

            # Stage a valid update without its KEL anchor so the local path
            # must escrow it in maes rather than accept it immediately.
            acdc = makeAcdc(hab, regid=registry.regk)
            blinder, bup = makeUpdate(registry.regk, ripper.said, acdc.said,
                                      'issued', sn=1, stamp=STAMP1)
            assert registry.processEvent(bup) is False
            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == [(bup.said,)]

            # The verifier-side policy is stricter: the same missing anchor is
            # still a retryable failure, not an escrowed local state.
            with pytest.raises(kering.MissingAnchorError):
                vet(rip=ripper, updates=[bup], db=hby.db, blinder=blinder)

            # Once the issuer does anchor the update, both paths should rely on
            # the same explicit anchor-couple verifier for the KEL event.
            seal = dict(i=registry.regk, s=bup.sad['n'], d=bup.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            number = Number(num=hab.kever.sn)
            diger = Diger(qb64=hab.kever.serder.said)
            
            assert regeventing._verifyAnchorCouple(bup,
                                                   db=hby.db,
                                                   issuer=hab.pre,
                                                   number=number,
                                                   diger=diger)
            assert registry.anchorMsg(bup.said, number=number, diger=diger) is True
        finally:
            rgy.close()


def test_V9_anchor_in_strangers_kel_refused():
    """V9: every event anchored, but in a KEL whose controller is not rip.i:
    refused -- an endorsement is not a commitment -- naming the mismatch."""
    with habbing.openHby(name="v9", temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer", version=Vrsn_2_0)
        stranger = hby.makeHab(name="stranger", version=Vrsn_2_0)
        ripper = regcept(israid=issuer.pre, stamp=STAMP0)
        anchor(stranger, ripper)  # endorsement by the wrong controller
        with pytest.raises(kering.MisanchorError) as ex:
            vet(rip=ripper, db=hby.db)
        assert issuer.pre in str(ex.value)
        assert stranger.pre in str(ex.value)


def test_V10_bare_digest_seal_accepted():
    """V10: a seal carrying only the digest, no s, is accepted -- matched by
    digest; seal.s is a lookup hint, never load-bearing."""
    with openIssuer("v10") as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        anchor(hab, data=[dict(d=ripper.said)])  # digest-only seal
        rec = vet(rip=ripper, db=hby.db)
        assert rec.said == ripper.said
        assert rec.sn == 0

        # a seal as simple as the bare SAID string also anchors (spec :1918)
        second = makeRegistry(hab, stamp=STAMP1, anchored=False)
        anchor(hab, data=[second.said])
        rec2 = vet(rip=second, db=hby.db)
        assert rec2.said == second.said


def test_V11_multiple_seals_tolerated():
    """V11: the anchoring KEL event carries several seals, ours among them:
    accepted.  A wrong s hint on our own seal is also tolerated (digest is
    what matches)."""
    with openIssuer("v11") as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        noise1 = Diger(ser=b'some other commitment').qb64
        noise2 = Diger(ser=b'yet another commitment').qb64
        anchor(hab, data=[dict(s='99', d=noise1),
                          dict(s='7', d=ripper.said),  # wrong s hint, right d
                          dict(d=noise2)])
        rec = vet(rip=ripper, db=hby.db)
        assert rec.said == ripper.said


def test_V12_smt_root_anchor_refused_by_name():
    """V12: a registry whose claimed anchor is an SMT root -- a seal digest
    matching no TEL event SAID -- is refused by its own name, not as a
    generic "unanchored"."""
    with openIssuer("v12") as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        root = Diger(ser=ripper.saidb + b'sibling tel event saids').qb64
        anchor(hab, data=[dict(d=root)])  # Merkle-root style bulk seal
        claim = hab.kever.sn  # the caller claims this KEL event anchors it

        with pytest.raises(kering.RootSealError):
            vet(rip=ripper, db=hby.db, sources={ripper.said: claim})

        # without the claim there is nothing to refuse: the seal is simply
        # not found, which establishes nothing, retryably
        with pytest.raises(kering.MissingAnchorError):
            vet(rip=ripper, db=hby.db)


def test_V13_seal_reference_without_seal_retryable():
    """V13: a seal reference naming a KEL event that does not contain the
    seal establishes nothing, retryably -- indistinguishable from an anchor
    not yet gathered."""
    with openIssuer("v13") as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        anchor(hab, data=[dict(note="no seal here")])  # sealless event
        claim = hab.kever.sn
        with pytest.raises(kering.MissingAnchorError):
            vet(rip=ripper, db=hby.db, sources={ripper.said: claim})
        # the claim may also name the KEL event by SAID; same outcome
        with pytest.raises(kering.MissingAnchorError):
            vet(rip=ripper, db=hby.db,
                sources={ripper.said: hab.kever.serder.said})


# ---------------------------------------------------------------------------
# Bindings -- the substitution family
# ---------------------------------------------------------------------------

def test_V14_substitution_sibling_registry_refused():
    """V14: revoked ACDC-A presented with sibling registry RB's genuine
    issued chain, same issuer: refused because td != acdc.d.  Every other
    check passes by construction."""
    with openIssuer("v14") as (hby, hab):
        # registry RA: acdcA issued then revoked
        ripA = makeRegistry(hab, stamp=STAMP0)
        acdcA = makeAcdc(hab, regid=ripA.said, name="Sunspot College")
        _, bupA1 = makeUpdate(ripA.said, ripA.said, acdcA.said, 'issued',
                              sn=1, stamp=STAMP1)
        anchor(hab, bupA1)
        blindA2, bupA2 = makeUpdate(ripA.said, bupA1.said, acdcA.said,
                                    'revoked', sn=2, stamp=STAMP2)
        anchor(hab, bupA2)

        # sibling registry RB: acdcB genuinely issued
        ripB = makeRegistry(hab, stamp=STAMP1)
        acdcB = makeAcdc(hab, regid=ripB.said, name="Moonspot College")
        blindB1, bupB1 = makeUpdate(ripB.said, ripB.said, acdcB.said,
                                    'issued', sn=1, stamp=STAMP1)
        anchor(hab, bupB1)

        # both registries verify on their own evidence
        assert vet(rip=ripA, updates=[bupA1, bupA2], db=hby.db, acdc=acdcA,
                   blinder=blindA2).state == 'revoked'
        assert vet(rip=ripB, updates=[bupB1], db=hby.db, acdc=acdcB,
                   blinder=blindB1).state == 'issued'

        # the substitution: revoked acdcA riding RB's issued chain
        with pytest.raises(kering.MisbindingError) as ex:
            vet(rip=ripB, updates=[bupB1], db=hby.db, acdc=acdcA,
                blinder=blindB1)
        assert 'td' in str(ex.value)


def test_V15_acdc_rd_mismatch_refused():
    """V15: an ACDC carrying rd that is not the presented rip's d is refused:
    the mutual binding fails even though td matches."""
    with openIssuer("v15") as (hby, hab):
        ripA = makeRegistry(hab, stamp=STAMP0)
        acdcA = makeAcdc(hab, regid=ripA.said)

        ripB = makeRegistry(hab, stamp=STAMP1)
        # RB's update genuinely commits td = acdcA -- but acdcA names RA
        blindB1, bupB1 = makeUpdate(ripB.said, ripB.said, acdcA.said,
                                    'issued', sn=1, stamp=STAMP1)
        anchor(hab, bupB1)

        with pytest.raises(kering.MisbindingError) as ex:
            vet(rip=ripB, updates=[bupB1], db=hby.db, acdc=acdcA,
                blinder=blindB1)
        assert 'rd' in str(ex.value)


def test_V16_rdless_acdc_oneway_binding():
    """V16: an rd-less ACDC whose chain td matches verifies, and the verdict
    names the one-directional binding (registry->ACDC only)."""
    with openIssuer("v16") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=None)  # correlation-minimized: no rd
        assert 'rd' not in acdc.sad
        blinder, bup = makeUpdate(ripper.said, ripper.said, acdc.said,
                                  'issued', sn=1, stamp=STAMP1)
        anchor(hab, bup)

        rec = vet(rip=ripper, updates=[bup], db=hby.db, acdc=acdc,
                  blinder=blinder)
        assert rec.state == 'issued'
        assert rec.binding == 'oneway'  # nothing commits ACDC->registry


def test_V16b_blinded_head_undisclosed_binds_nothing():
    """V16b: an ACDC presented against a blinded head with no disclosure is
    refused: the chain verifies, but nothing binds the ACDC to it."""
    with openIssuer("v16b") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, bup = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                            sn=1, stamp=STAMP1)
        anchor(hab, bup)

        with pytest.raises(kering.UnverifiedBlindError):
            vet(rip=ripper, updates=[bup], db=hby.db, acdc=acdc)


# ---------------------------------------------------------------------------
# Latest-state and duplicity
# ---------------------------------------------------------------------------

def test_V18_equal_n_duplicity_both_orders():
    """V18: two verifying events at equal n, both anchored, are refused as
    registry duplicity in both evidence orders."""
    with openIssuer("v18") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, forkA = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                              sn=1, stamp=STAMP1)
        _, forkB = makeUpdate(ripper.said, ripper.said, acdc.said, 'revoked',
                              sn=1, stamp=STAMP2)
        anchor(hab, forkA)
        anchor(hab, forkB)

        for updates in ([forkA, forkB], [forkB, forkA]):
            with pytest.raises(kering.DuplicitousRegistryError):
                vet(rip=ripper, updates=updates, db=hby.db)


def test_V19_later_event_wins():
    """V19: when the evidence holds a later verifying event than the one the
    presenter relies on, the later state wins -- evidence is evidence."""
    with openIssuer("v19") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, bup1 = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                             sn=1, stamp=STAMP1)
        anchor(hab, bup1)
        blinder2, bup2 = makeUpdate(ripper.said, bup1.said, acdc.said,
                                    'revoked', sn=2, stamp=STAMP2)
        anchor(hab, bup2)

        # the presenter would rely on bup1 (issued); the evidence knows better,
        # in whatever order the events arrive
        for updates in ([bup1, bup2], [bup2, bup1]):
            rec = vet(rip=ripper, updates=updates, db=hby.db, acdc=acdc,
                      blinder=blinder2)
            assert rec.sn == 2
            assert rec.said == bup2.said
            assert rec.state == 'revoked'


# ---------------------------------------------------------------------------
# Blinded registries, verify-side
# ---------------------------------------------------------------------------

def test_V20_bup_disclosed_blind_verifies():
    """V20: a bup chain with a disclosed blinded block that reproduces the
    BLID: state established from the disclosed ts."""
    with openIssuer("v20") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(ripper.said, ripper.said, acdc.said,
                                  'issued', sn=1, stamp=STAMP1)
        anchor(hab, bup)

        rec = vet(rip=ripper, updates=[bup], db=hby.db, acdc=acdc,
                  blinder=blinder)
        assert rec.sn == 1
        assert rec.ilk == Ilks.bup
        assert rec.acdc == acdc.said
        assert rec.state == 'issued'
        assert rec.binding == 'mutual'

        # the disclosure may arrive as the raw qb64 concatenation (what a
        # discloser attaches on the wire), not only as a Blinder instance
        rec2 = vet(rip=ripper, updates=[bup], db=hby.db, blinder=blinder.qb64)
        assert rec2.state == 'issued'
        assert rec2.acdc == acdc.said

        # without a disclosure the chain still verifies but the state stays
        # blinded: the record reports no state rather than guessing
        rec3 = vet(rip=ripper, updates=[bup], db=hby.db)
        assert rec3.sn == 1
        assert rec3.state is None
        assert rec3.acdc is None


def test_V21_blind_not_reproducing_refused():
    """V21: a disclosed block that does not reproduce the anchored b is
    refused -- the disclosure proves nothing."""
    with openIssuer("v21") as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(ripper.said, ripper.said, acdc.said,
                                  'issued', sn=1, stamp=STAMP1)
        anchor(hab, bup)

        # same salt and sn, wrong state: the recomputed BLID differs
        wrong = Blinder.blind(acdc=acdc.said, state='revoked', salt=SALT, sn=1)
        with pytest.raises(kering.UnverifiedBlindError):
            vet(rip=ripper, updates=[bup], db=hby.db, blinder=wrong)

        # right state, wrong sn: the blind derives per event, so it also fails
        stale = Blinder.blind(acdc=acdc.said, state='issued', salt=SALT, sn=2)
        with pytest.raises(kering.UnverifiedBlindError):
            vet(rip=ripper, updates=[bup], db=hby.db, blinder=stale)


def test_V22_spec_blid_vectors():
    """V22: the spec text's BLID conformance vectors (placeholder and issued)
    are reproduced exactly.  Lineage caveat: the spec's examples were synced
    from keripy, so this defends against drift, not against shared error."""
    placeholder = Blinder(crew=BlindState(d='', u=SPEC_PLACEHOLDER_UUID,
                                          td='', ts=''), makify=True)
    assert placeholder.said == SPEC_PLACEHOLDER_BLID
    issued = Blinder(crew=BlindState(d='', u=SPEC_ISSUED_UUID,
                                     td=SPEC_ISSUED_TD, ts='issued'),
                     makify=True)
    assert issued.said == SPEC_ISSUED_BLID

    # the verify-side operation accepts each disclosure against its BLID
    acdc, state = vetBlind(blinder=placeholder, blid=SPEC_PLACEHOLDER_BLID)
    assert (acdc, state) == ('', '')
    acdc, state = vetBlind(blinder=issued.qb64, blid=SPEC_ISSUED_BLID)
    assert (acdc, state) == (SPEC_ISSUED_TD, 'issued')

    # and refuses a disclosure presented against the wrong BLID
    with pytest.raises(kering.UnverifiedBlindError):
        vetBlind(blinder=issued, blid=SPEC_PLACEHOLDER_BLID)


def test_V23_no_salt_parameter_anywhere():
    """V23: the verify path's API surface -- no parameter anywhere accepts a
    salt.  The salt's absence from every signature is itself the row."""
    checked = 0
    for name, obj in inspect.getmembers(regeventing):
        if getattr(obj, "__module__", None) != regeventing.__name__:
            continue
        if inspect.isfunction(obj):
            assert 'salt' not in inspect.signature(obj).parameters, name
            checked += 1
        elif inspect.isclass(obj):
            for mname, meth in inspect.getmembers(obj, inspect.isfunction):
                assert 'salt' not in inspect.signature(meth).parameters, (
                    f"{name}.{mname}")
                checked += 1
    assert checked > 0  # the sweep saw a real API surface


if __name__ == "__main__":
    test_V1_rip_bup_issued_verifies()
    test_V2_revoking_bup_state_revoked()
    test_V3_rip_n_nonzero_refused()
    test_V4_n_gap_refused()
    test_V5_p_mismatch_refused()
    test_V6_rd_mismatch_refused()
    test_V7_field_order_and_said_mutations_refused()
    test_V8_unanchored_update_retryable()
    test_V9_anchor_in_strangers_kel_refused()
    test_V10_bare_digest_seal_accepted()
    test_V11_multiple_seals_tolerated()
    test_V12_smt_root_anchor_refused_by_name()
    test_V13_seal_reference_without_seal_retryable()
    test_V14_substitution_sibling_registry_refused()
    test_V15_acdc_rd_mismatch_refused()
    test_V16_rdless_acdc_oneway_binding()
    test_V16b_blinded_head_undisclosed_binds_nothing()
    test_V18_equal_n_duplicity_both_orders()
    test_V19_later_event_wins()
    test_V20_bup_disclosed_blind_verifies()
    test_V21_blind_not_reproducing_refused()
    test_V22_spec_blid_vectors()
    test_V23_no_salt_parameter_anywhere()
