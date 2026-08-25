# -*- encoding: utf-8 -*-
"""tests.acdc.test_registraring module"""

from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import Registry, Regery, Registrar, acdcmap, blindate as regbup, regcept
from keri.app import openHby
from keri.core import Blinder, Diger, Number, SerderACDC
from keri.kering import ConfigurationError, ValidationError


def _anchor(hab, registry, serder):
    """Seal one registry event in the habitat KEL and commit it to the registry store."""

    # Build the KEL seal that points at this registry event
    seal = dict(i=registry.regk, s=serder.sad["n"], d=serder.said)

    # Commit that seal into the habitat's KEL as a real anchoring event
    hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)

    # Feed the new KEL event back through the registry service
    assert registry.anchorMsg(serder.said) is True
    
    # Return the original registry event for test setup
    return serder


def test_registrar_blindable_registry_state_updates():
    """Commit a rip and two blind updates through the public registrar facade."""
    with openHby(name="acdc-registry-service",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-service", temp=True)
        try:
            # Create one registry through the public facade and load its staged rip
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blindable", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)

            # Anchor the rip so the registry can accept later updates
            _anchor(hab, registry, rip)

            # Build an ACDC whose declared registry is this new registry
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Issue one blindable update via the default public path and anchor it
            first_blinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, issued)

            # Then issue a second blindable update and anchor that too
            blinder, bup = registrar.issue(registry, acdc=acdc,
                                           state="revoked")
            _anchor(hab, registry, bup)

            # The accepted TEL should now show a clean rip -> bup -> bup chain
            assert rgy.store.headEvent(registry.regk).said == bup.said
            assert rgy.store.seqEvent(registry.regk, 0).ilk == "rip"
            assert rgy.store.seqEvent(registry.regk, 1).said == issued.said
            assert rgy.store.seqEvent(registry.regk, 2).said == bup.said

            # The second blindable update should point back to the first and
            # carry the generated blinded-state SAID
            assert issued.sad["b"] == first_blinder.said
            assert bup.sad["p"] == issued.said
            assert bup.sad["b"] == blinder.said
        finally:
            rgy.close()


def test_registry_create_and_issue_staged_without_real_seal():
    """Stage a rip and blind update first, then prove they wait for later KEL anchoring."""
    with openHby(name="acdc-registry-staged",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-staged", temp=True)
        try:
            # Create the registry but do not provide a real anchoring KEL event yet
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="staged", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)

            # The rip body should be stored, but the registry should still be uncommitted
            assert rip is not None
            assert registry.head is None
            assert rgy.store.baser.maes.get(keys=registry.regk, on=0) == [(rip.said,)]

            # Once the rip is anchored, the registry can accept later blind state updates
            _anchor(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # A new blind update should be stored immediately but remain in missing-anchor
            # escrow until its own KEL seal arrives
            _, bup = registrar.issue(registry, acdc=acdc, state="issued")
            assert rgy.store.event(bup.said).said == bup.said
            assert rgy.store.headEvent(registry.regk).said == rip.said
            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == [(bup.said,)]

            # Once the update is anchored, it should leave escrow and become the new head.
            _anchor(hab, registry, bup)
            assert rgy.store.headEvent(registry.regk).said == bup.said
            assert rgy.store.seqEvent(registry.regk, 1).said == bup.said
            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == []
        finally:
            rgy.close()


def test_registry_rejects_malformed_inception_before_mutation():
    """Reject a rip with an impossible sequence number before mutating store state."""
    with openHby(name="acdc-registry-bad-rip",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-bad-rip", temp=True)
        try:
            # Create one valid rip only to borrow its field layout for a malformed copy.
            registry = Registry(hab=hab, store=rgy.store, name="bad-rip")
            rip = registry.make()

            # Force an impossible inception sequence number.
            bad = dict(rip.sad)
            bad["n"] = "1"
            badrip = SerderACDC(sad=bad, makify=True)
            badreg = Registry(hab=hab, store=rgy.store, name="bad-rip-check")

            # The malformed rip should fail before it binds state or touches storage.
            with pytest.raises(ValidationError):
                badreg.processEvent(badrip)

            assert badreg.regk is None
            assert rgy.store.event(badrip.said) is None
            assert rgy.store.baser.maes.get(keys=badrip.said, on=1) == []
        finally:
            rgy.close()


def test_registry_rejects_foreign_issuer_inception_before_mutation():
    """Reject a rip whose issuer does not match the controlling habitat."""
    with openHby(name="acdc-registry-bad-issuer",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-bad-issuer", temp=True)
        try:
            # Build a rip that claims a different issuer AID
            registry = Registry(hab=hab, store=rgy.store, name="bad-issuer")
            badrip = regcept(israid="EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

            # The registry service should reject it before storing or escrowing it
            with pytest.raises(ValidationError):
                registry.processEvent(badrip)

            assert registry.regk is None
            assert rgy.store.event(badrip.said) is None
            assert rgy.store.baser.maes.get(keys=badrip.said, on=0) == []
        finally:
            rgy.close()


def test_registry_anchor_msg_discovers_prior_sealing_event():
    """Find an older sealing KEL event even after the habitat head has advanced."""
    with openHby(name="acdc-registry-anchor-discovery",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-anchor-discovery", temp=True)
        try:
            # Stage a rip and create the correct sealing interaction
            registry = Registry(hab=hab, store=rgy.store, name="anchor-discovery")
            rip = registry.make()

            seal = dict(i=rip.said, s=rip.sad["n"], d=rip.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            sealing = hab.kever.serder.said

            # Advance the KEL again so the sealing event is no longer the current head
            hab.interact(framed=True, gvrsn=Vrsn_2_0)
            assert hab.kever.serder.said != sealing

            # anchorMsg should still discover and use the older sealing event by seal lookup
            assert registry.anchorMsg(rip.said) is True
            assert rgy.store.anchor(rip.said)[1].qb64 == sealing
        finally:
            rgy.close()


def test_registry_rejects_bad_prior_before_mutation():
    """Reject a blind update whose declared prior does not match the accepted head."""
    with openHby(name="acdc-registry-bad-prior",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-bad-prior", temp=True)
        try:
            # Commit a real rip first so sn=1 prior validation has an accepted predecessor
            registry = Registry(hab=hab, store=rgy.store, name="bad-prior")
            rip = registry.make()
            _anchor(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Point the update at the wrong prior SAID on purpose
            badupd = regbup(regid=registry.regk,
                            prior=acdc.said,
                            blid=Blinder.blind(acdc=acdc.said,
                                               state="issued",
                                               sn=1).said,
                            sn=1)

            # The bad prior should fail before the event body or escrow state is written
            with pytest.raises(ValidationError):
                registry.processEvent(badupd)

            assert rgy.store.event(badupd.said) is None
            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == []
        finally:
            rgy.close()


def test_registry_anchor_msg_rejects_bad_prior_without_storing_anchor():
    """Reject an anchored bad-prior event without leaving a stored anchor behind."""
    with openHby(name="acdc-registry-anchor-bad-prior",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-anchor-bad-prior", temp=True)
        try:
            # Commit one real rip so sn=1 validation has an accepted predecessor to compare.
            registry = Registry(hab=hab, store=rgy.store, name="anchor-bad-prior")
            rip = registry.make()
            _anchor(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Seed a malformed blind update body directly into storage with the wrong prior SAID.
            badupd = regbup(regid=registry.regk,
                            prior=acdc.said,
                            blid=Blinder.blind(acdc=acdc.said,
                                               state="issued",
                                               sn=1).said,
                            sn=1)
            rgy.store.putEvent(badupd)

            # Even if the KEL seal is real, anchorMsg should reject it before storing the anchor.
            seal = dict(i=registry.regk, s=badupd.sad["n"], d=badupd.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            with pytest.raises(ValidationError):
                registry.anchorMsg(badupd.said)

            assert rgy.store.anchor(badupd.said) is None
            assert rgy.store.headEvent(registry.regk).said == rip.said
        finally:
            rgy.close()


def test_registry_issue_requires_full_acdc_object():
    """Reject bare SAIDs and duck-typed stand-ins on the blind issuance path."""
    with openHby(name="acdc-registry-full-acdc",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-full-acdc", temp=True)
        try:
            registry = Registry(hab=hab, store=rgy.store, name="full-acdc")
            rip = registry.make()
            _anchor(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Bare SAID strings are no longer accepted on the blind path
            with pytest.raises(ConfigurationError):
                registry.blind(acdc.said, state="issued")

            # Duck-typed objects with the right attributes should also be rejected
            fake = SimpleNamespace(said=acdc.said,
                                   sad=dict(rd=registry.regk, i=hab.pre))

            with pytest.raises(ConfigurationError):
                registry.blind(fake, state="issued")
        finally:
            rgy.close()


def test_registry_issue_requires_valid_acdc_object():
    """Reject tampered ACDCs that fail internal verification before issuance."""
    with openHby(name="acdc-registry-valid-acdc",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-valid-acdc", temp=True)
        try:
            registry = Registry(hab=hab, store=rgy.store, name="valid-acdc")
            rip = registry.make()
            _anchor(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            acdc._sad["a"]["LEI"] = "tampered"

            # Sanity-check the fixture so the later ConfigurationError is meaningful
            assert not acdc.verify()

            # Blind issuance should reject an invalid serialized artifact
            with pytest.raises(ConfigurationError):
                registry.blind(acdc, state="issued")
        finally:
            rgy.close()


def test_registry_blind_rejects_caller_supplied_blinder():
    """Reject external blinder overrides so blind issuance always derives its own blinder."""
    with openHby(name="acdc-registry-no-blinder-override",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-no-blinder-override", temp=True)
        try:
            # Commit the registry and build one valid ACDC/blinder pair
            registry = Registry(hab=hab, store=rgy.store, name="no-blinder-override")
            rip = registry.make()
            _anchor(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1)

            # The blind path now derives the blinder internally and rejects overrides
            with pytest.raises(ConfigurationError):
                registry.blind(acdc, state="issued", blinder=blinder)
        finally:
            rgy.close()


def test_registry_rejects_acdc_from_different_registry():
    """Reject issuance when the supplied ACDC declares a different governing registry."""
    with openHby(name="acdc-registry-cross-regid",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-cross-regid", temp=True)
        try:
            # Create and anchor two separate registries under the same habitat
            registrar = Registrar(rgy=rgy)
            first = registrar.makeRegistry(name="first", prefix=hab.pre)
            second = registrar.makeRegistry(name="second", prefix=hab.pre)
            _anchor(hab, first, rgy.store.event(first.regk))
            _anchor(hab, second, rgy.store.event(second.regk))

            # Build an ACDC that belongs to the second registry
            foreign = acdcmap(israid=hab.pre,
                              regid=second.regk,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              iseaid=hab.pre)

            # The first registry should reject blind issuance for it.
            with pytest.raises(ConfigurationError):
                registrar.issue(first, acdc=foreign, state="issued")
        finally:
            rgy.close()


def test_registry_anchor_msg_rejects_other_registry_without_mutation():
    """Fail cross-registry anchor attempts before they mutate shared anchor state."""
    with openHby(name="acdc-registry-cross-anchor",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-cross-anchor", temp=True)
        try:
            # Create two registries so we can try to anchor one through the other
            registrar = Registrar(rgy=rgy)
            first = registrar.makeRegistry(name="first", prefix=hab.pre)
            second = registrar.makeRegistry(name="second", prefix=hab.pre)
            second_rip = rgy.store.event(second.regk)

            # Create a real KEL seal for the second registry's rip
            seal = dict(i=second.regk, s=second_rip.sad["n"], d=second_rip.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)

            # The wrong Registry object should reject the anchor before mutating shared state
            with pytest.raises(ValidationError):
                first.anchorMsg(second_rip.said)

            assert rgy.store.anchor(second_rip.said) is None
            assert rgy.store.headEvent(second.regk) is None
        finally:
            rgy.close()


def test_registry_rejects_issue_from_foreign_issuer():
    """Reject blind issuance for an ACDC whose issuer differs from the habitat."""
    with openHby(name="acdc-registry-blind-foreign-issuer",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        other = hby.makeHab(name="other")
        rgy = Regery(hby=hby, name="acdc-registry-blind-foreign-issuer", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blind-foreign-issuer", prefix=hab.pre)
            _anchor(hab, registry, rgy.store.event(registry.regk))
            foreign = acdcmap(israid=other.pre,
                              regid=registry.regk,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              iseaid=hab.pre)

            with pytest.raises(ConfigurationError):
                registrar.issue(registry, acdc=foreign, state="issued")
        finally:
            rgy.close()


def test_registry_rejects_non_inception_sn_zero_before_mutation():
    """Reject non-rip registry events that incorrectly try to reuse sequence number zero."""
    with openHby(name="acdc-registry-bad-sn-zero",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-bad-sn-zero", temp=True)
        try:
            # Stage a rip so we have a registry id to target with an impossible update
            registry = Registry(hab=hab, store=rgy.store, name="bad-sn-zero")
            rip = registry.make()
            acdc = acdcmap(israid=hab.pre,
                           regid=rip.said,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Force a non-rip event to reuse sn=0, which should never be valid
            badupd = regbup(regid=rip.said,
                            prior=rip.said,
                            blid=Blinder.blind(acdc=acdc.said,
                                               state="issued",
                                               sn=0).said,
                            sn=0)

            # The bad event should fail before overwriting the staged rip slot.
            with pytest.raises(ValidationError):
                registry.processEvent(badupd)

            assert rgy.store.event(badupd.said) is None
            assert rgy.store.baser.maes.get(keys=rip.said, on=0) == [(rip.said,)]
        finally:
            rgy.close()


def test_registry_anchor_msg_requires_complete_explicit_couple():
    """Require both explicit anchor components together or fall back to pure discovery."""
    with openHby(name="acdc-registry-anchor-explicit",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-anchor-explicit", temp=True)
        try:
            # Stage and seal a rip so anchorMsg has a real explicit-anchor target
            registry = Registry(hab=hab, store=rgy.store, name="anchor-explicit")
            rip = registry.make()
            seal = dict(i=rip.said, s=rip.sad["n"], d=rip.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)

            # Supplying only half of the explicit couple should be rejected
            with pytest.raises(ValidationError):
                registry.anchorMsg(rip.said, number=Number(num=hab.kever.sn))

            assert rgy.store.anchor(rip.said) is None

            # With no partial explicit input, normal discovery should still work
            assert registry.anchorMsg(rip.said) is True
        finally:
            rgy.close()


def test_registry_anchor_msg_accepts_complete_explicit_couple():
    """Accept a fully supplied explicit anchor couple and commit the staged event."""
    with openHby(name="acdc-registry-anchor-explicit-happy",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-anchor-explicit-happy", temp=True)
        try:
            registry = Registry(hab=hab, store=rgy.store, name="anchor-explicit-happy")
            rip = registry.make()
            seal = dict(i=rip.said, s=rip.sad["n"], d=rip.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            number = Number(num=hab.kever.sn)
            diger = Diger(qb64=hab.kever.serder.said)

            # A complete explicit couple should validate, store the anchor, and commit the rip.
            assert registry.anchorMsg(rip.said, number=number, diger=diger) is True
            stored_number, stored_diger = rgy.store.anchor(rip.said)
            assert stored_number.sn == number.sn
            assert stored_diger.qb64 == diger.qb64
            assert rgy.store.headEvent(rip.said).said == rip.said
        finally:
            rgy.close()


def test_regery_process_escrows_replays_missing_anchors():
    """Auto-discover and commit staged rip and bup events during escrow replay."""
    with openHby(name="acdc-registry-escrows",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-escrows", temp=True)
        try:
            # Stage a registry rip, then create its KEL seal without calling anchorMsg directly
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="replayable", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            seal = dict(i=registry.regk, s=rip.sad["n"], d=rip.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)

            # Manager-level escrow processing should discover and commit that staged rip
            rgy.processEscrows()
            assert rgy.store.headEvent(registry.regk).said == rip.said

            # Stage one blind update the same way: body stored now, seal arrives separately
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            _, bup = registrar.issue(registry, acdc=acdc, state="issued")
            assert rgy.store.headEvent(registry.regk).said == rip.said

            seal = dict(i=registry.regk, s=bup.sad["n"], d=bup.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)

            # The second escrow replay pass should discover and commit the update too
            rgy.processEscrows()
            assert rgy.store.headEvent(registry.regk).said == bup.said
        finally:
            rgy.close()


def test_registry_purges_bad_queued_prior_when_prior_arrives():
    """Drop a queued successor whose prior pointer is still wrong once replay can inspect it."""
    with openHby(name="acdc-registry-bad-queued-prior",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-bad-queued-prior", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="bad-queued-prior", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip)

            # Build an ACDC for this registry, then craft a queued event with a bad prior
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            badqueued = regbup(regid=registry.regk,
                               prior=acdc.said,
                               blid=Blinder.blind(acdc=acdc.said,
                                                  state="accepted",
                                                  sn=2).said,
                               sn=2)

            # With sn=1 still missing, the event should stage as out-of-order for now
            assert registry.processEvent(badqueued) is False

            # Once its own seal exists, the event should move from maes into ooes
            seal = dict(i=registry.regk, s=badqueued.sad["n"], d=badqueued.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            assert registry.anchorMsg(badqueued.said) is False
            assert rgy.store.baser.ooes.get(keys=registry.regk, on=2) == [(badqueued.said,)]

            # Commit the real sn=1 update so queued replay can examine the bad sn=2 entry
            _, bup = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, bup)

            # The malformed queued entry should be purged instead of blocking progress
            assert rgy.store.headEvent(registry.regk).said == bup.said
            assert rgy.store.baser.ooes.get(keys=registry.regk, on=2) == []
        finally:
            rgy.close()


def test_regery_process_escrows_clears_malformed_missing_anchor_entry():
    """Purge malformed missing-anchor junk during manager-level escrow replay."""
    with openHby(name="acdc-registry-bad-escrow",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-bad-escrow", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="bad-escrow", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip)

            # Build a bad blind update whose prior points at the ACDC instead of the accepted rip
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            badupd = regbup(regid=registry.regk,
                            prior=acdc.said,
                            blid=Blinder.blind(acdc=acdc.said,
                                               state="issued",
                                               sn=1).said,
                            sn=1)

            # Seed the malformed body directly into missing-anchor escrow like legacy junk data
            rgy.store.putEvent(badupd)
            rgy.store.escrowMissingAnchor(registry.regk, 1, badupd.said)

            # Escrow replay should drop the malformed entry
            rgy.processEscrows()

            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == []
            assert rgy.store.headEvent(registry.regk).said == rip.said
        finally:
            rgy.close()


def test_registry_clears_conflicting_missing_anchor_siblings():
    """Commit one missing-anchor sibling and clear competing staged entries for that slot."""
    with openHby(name="acdc-registry-sibling-maes",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-sibling-maes", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="siblings", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip)

            # Create one normal staged blind update and one competing sibling for the same slot
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            _, winner = registrar.issue(registry, acdc=acdc, state="issued")
            loser = regbup(regid=registry.regk,
                           prior=rip.said,
                           blid=Blinder.blind(acdc=acdc.said,
                                              state="revoked",
                                              sn=1).said,
                           sn=1)
            assert registry.processEvent(loser) is False
            # Both siblings should sit in missing-anchor escrow until one is committed.
            assert sorted(said for (said,) in rgy.store.baser.maes.get(keys=registry.regk, on=1)) == \
                   sorted([winner.said, loser.said])

            # Note that currently the policy is to deterministically choose the first anchored sibling 
            # and purge the rest.
            # Anchoring the winner should commit that slot and clear the losing sibling too
            _anchor(hab, registry, winner)
            assert rgy.store.seqEvent(registry.regk, 1).said == winner.said
            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == []

            # Reintroducing the stale loser should let replay purge it defensively as junk
            rgy.store.escrowMissingAnchor(registry.regk, 1, loser.said)
            rgy.processEscrows()
            assert rgy.store.baser.maes.get(keys=registry.regk, on=1) == []
        finally:
            rgy.close()


def test_registry_clears_conflicting_out_of_order_siblings():
    """Commit one queued successor and clear competing out-of-order siblings for that slot."""
    with openHby(name="acdc-registry-sibling-ooes",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-sibling-ooes", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="queued-siblings", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip)

            # Create one real sn=1 blind update plus two competing sn=2 successors
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            _, bup = registrar.issue(registry, acdc=acdc, state="issued")
            queued = regbup(regid=registry.regk,
                            prior=bup.said,
                            blid=Blinder.blind(acdc=acdc.said,
                                               state="accepted",
                                               sn=2).said,
                            sn=2)
            sibling = regbup(regid=registry.regk,
                             prior=bup.said,
                             blid=Blinder.blind(acdc=acdc.said,
                                                state="revoked",
                                                sn=2).said,
                             sn=2)

            # Both successors should stage as out-of-order because sn=1 is not committed
            assert registry.processEvent(queued) is False
            assert registry.processEvent(sibling) is False

            # After each successor gets its own seal, both should still remain queued at sn=2
            seal = dict(i=registry.regk, s=queued.sad["n"], d=queued.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            assert registry.anchorMsg(queued.said) is False

            seal = dict(i=registry.regk, s=sibling.sad["n"], d=sibling.said)
            hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
            assert registry.anchorMsg(sibling.said) is False
            assert sorted(said for (said,) in rgy.store.baser.ooes.get(keys=registry.regk, on=2)) == \
                   sorted([queued.said, sibling.said])

            # Committing the real sn=1 update should now choose the first anchored
            # sn=2 sibling deterministically and clear the later one.
            _anchor(hab, registry, bup)
            assert rgy.store.seqEvent(registry.regk, 2).said == queued.said
            assert rgy.store.baser.ooes.get(keys=registry.regk, on=2) == []
        finally:
            rgy.close()


def test_regery_reloads_persisted_registry_records():
    """Reload persisted registry alias records and accepted TEL state after reopen."""
    with openHby(name="acdc-registry-reload",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby,
                     name="acdc-registry-reload-store",
                     base="test",
                     temp=False)
        try:
            # Persist one registry record and anchor its rip so reopen has durable state to reload
            registry = Registrar(rgy=rgy).makeRegistry(name="reloadable",
                                                       prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip)
            regk = registry.regk
        finally:
            rgy.close()

        # Reopen the same non-temp store and reload the manager view from persisted records
        reopened = Regery(hby=hby,
                          name="acdc-registry-reload-store",
                          base="test",
                          temp=False)
        try:
            # The alias lookup, regk lookup, and accepted TEL head should all survive reopen
            reloaded = reopened.registryByName("reloadable")
            assert reloaded is not None
            assert reloaded.regk == regk
            assert reopened.regs[regk] is reloaded
            assert reopened.store.headEvent(regk).said == rip.said
        finally:
            reopened.baser.close(clear=True)


def test_regery_reload_uses_stored_rip_issuer_for_reopened_issuance():
    """Derive reopened registry ownership from the stored rip issuer."""
    with openHby(name="acdc-registry-reload-rip-authority",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        other = hby.makeHab(name="other")
        rgy = Regery(hby=hby,
                     name="acdc-registry-reload-rip-authority-store",
                     base="test",
                     temp=False)
        try:
            # Create and anchor one registry under the first habitat
            registry = Registrar(rgy=rgy).makeRegistry(name="reloadable",
                                                       prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip)
            regk = registry.regk
        finally:
            rgy.close()

        # Reopen the store and ensure ownership still comes from the stored rip issuer
        reopened = Regery(hby=hby,
                          name="acdc-registry-reload-rip-authority-store",
                          base="test",
                          temp=False)
        try:
            reloaded = reopened.registryByName("reloadable")
            assert reloaded is not None
            assert reloaded.hab.pre == hab.pre

            # The reopened registry should still issue from the original controller
            acdc = acdcmap(israid=hab.pre,
                           regid=regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            _, bup = Registrar(rgy=reopened).issue(reloaded, acdc=acdc, state="issued")
            assert reopened.store.headEvent(regk).said == rip.said
            _anchor(hab, reloaded, bup)
            assert reopened.store.headEvent(regk).said == bup.said

            # A different loaded habitat should still be rejected as a foreign issuer
            foreign = acdcmap(israid=other.pre,
                              regid=regk,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              iseaid=hab.pre)
            with pytest.raises(ConfigurationError):
                Registrar(rgy=reopened).issue(reloaded, acdc=foreign, state="issued")

            assert reopened.store.records.get(keys="reloadable").registryKey == regk
        finally:
            reopened.baser.close(clear=True)


def test_regery_reload_normalizes_duplicate_registry_alias_records():
    """Collapse legacy duplicate alias records onto one in-memory Registry object on reopen."""
    with openHby(name="acdc-registry-duplicate-reload",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby,
                     name="acdc-registry-duplicate-reload-store",
                     base="test",
                     temp=False)
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name="one",
                                                       prefix=hab.pre)
            rgy.store.records.pin(keys="two",
                                  val=rgy.store.records.klas(registryKey=registry.regk))
            regk = registry.regk
        finally:
            rgy.close()

        # Reopen the store and ensure both aliases collapse onto one in-memory Registry object
        reopened = Regery(hby=hby,
                          name="acdc-registry-duplicate-reload-store",
                          base="test",
                          temp=False)
        try:
            one = reopened.registryByName("one")
            two = reopened.registryByName("two")
            assert one is not None
            assert one is two
            assert reopened.regs[regk] is one
        finally:
            reopened.baser.close(clear=True)


def test_regery_rejects_duplicate_registry_key_creation():
    """Reject a second alias create that would deterministically reproduce the same regk."""
    with openHby(name="acdc-registry-duplicate-regk",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="acdc-registry-duplicate-regk", temp=True)
        try:
            # Reuse deterministic rip inputs so a second create would reproduce the same regk
            kwa = dict(uuid="0AAAAAAAAAAAAAAAAAAAAAAA",
                       stamp="2026-08-10T00:00:00+00:00")
            first = Registrar(rgy=rgy).makeRegistry(name="one",
                                                    prefix=hab.pre,
                                                    **kwa)

            # The manager should now reject a second alias that would map to the same registry key
            with pytest.raises(ConfigurationError):
                Registrar(rgy=rgy).makeRegistry(name="two",
                                                prefix=hab.pre,
                                                **kwa)

            # The original alias should remain the only live registry record
            assert rgy.registryByName("one") is first
            assert rgy.registryByName("two") is None
            assert list(rgy.regs.keys()) == [first.regk]
        finally:
            rgy.close()
