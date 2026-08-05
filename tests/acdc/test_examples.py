# -*- coding: utf-8 -*-
"""
tests.acdc.test_examples module

Worked, working examples for the ACDC v2 specification that fill the gaps left
by the spec-linked examples in tests/spec/acdc/test_acdc_examples.py, namely:

  * the full registry-dependent issuance lifecycle (create the registry, then
    bind the about-to-be-issued ACDC into it) instead of assuming a
    pre-existing registry with hard-coded state, and
  * graduated (partial and selective) disclosure, both how an issuer plans for
    it via schema choices and how an issuee performs it at presentation.

The example actors (amy the issuer, bob the issuee) and the raw seeds are the
ones derived in tests/spec/acdc/test_acdc_examples.py::test_acdc_examples_setup,
kept here as module constants so these examples line up with the specification's
worked examples and stay in one place.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from keri import Vrsn_2_0, Kinds, Protocols, Ilks
from keri.core import (Noncer, Blinder, GenDex, Aggor, Compactor, Diger,
                       DigDex, Parser)
from keri.acdc import (regcept, blindate, acdcmap, acdcagg, loadHandlers,
                       grant as ipexGrant, admit as ipexAdmit)
from keri.app import openHby
from keri.peer import Exchanger


# Spec-aligned example fixtures (see test_acdc_examples_setup in the spec tests).
AMY = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"    # issuer AID
BOB = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"    # issuee AID
RAWS = [b'acdcspecworkraw' + b'%0x' % (i, ) for i in range(16)]
NONCES = [Noncer(raw=raw).qb64 for raw in RAWS]
REG_AMY = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"  # Amy's registry (derived in example 1)


def assert_acdc_schema_valid(acdc, schema=None):
    """Validate a worked-example ACDC against its JSON Schema.

    Uses the pypi jsonschema (Draft 2020-12) library -- the same check an
    independent verifier would run -- to make two guarantees:

      1. the schema is itself well-formed (Draft202012Validator.check_schema);
         this is exactly what catches a typo like the missing comma in a
         'required' array from issue #1482; and
      2. the ACDC instance conforms to that schema (.validate raises on failure).

    The schema validated against is the one the ACDC commits to and carries in
    its own 's' section. When that section is carried expanded (a JSON object) it
    is taken from the ACDC directly; when it has been compacted to a bare SAID
    string, pass the schema explicitly (e.g. the expanded sibling's sad['s']).

    Returns the schema used, so callers can make further assertions.
    """
    if schema is None:
        schema = acdc.sad['s']
        if not isinstance(schema, dict):
            raise ValueError("schema section is compacted to a SAID; pass "
                             "schema= (e.g. the expanded ACDC's sad['s'])")
    Draft202012Validator.check_schema(schema)          # guarantee 1
    Draft202012Validator(schema).validate(acdc.sad)    # guarantee 2 (raises on failure)
    return schema


def test_schema_validation_harness_has_teeth():
    """The schema-validation harness must actually reject bad input.

    A validator that silently passes everything is worse than none: it would let
    a broken example -- or a typo in a schema like the missing comma in issue
    #1482 -- sail through unnoticed. So before the other examples lean on
    assert_acdc_schema_valid, prove it (a) accepts a good ACDC, (b) rejects a
    malformed schema, and (c) rejects a nonconforming instance.
    """
    acdc = acdcmap(israid=AMY, uuid=NONCES[10], regid=REG_AMY,
                   attribute=dict(d='', u=NONCES[7], name="Sunspot College",
                                  level="gold"),
                   iseaid=BOB)

    # (a) a good ACDC validates against the schema it carries in its 's' section.
    schema = assert_acdc_schema_valid(acdc)
    assert schema is acdc.sad['s']
    assert schema['title'] == "ACM Default Schema"

    # (b) a malformed schema is caught: 'required' must be an array, not a string
    # (this is the shape of the missing-comma / bad-required-array bug class).
    broken = dict(schema, required="v d i s")
    with pytest.raises(SchemaError):
        Draft202012Validator.check_schema(broken)

    # (c) nonconforming instances are rejected: an extra field (the schema sets
    # additionalProperties: False) and a missing required field.
    validator = Draft202012Validator(schema)
    with pytest.raises(ValidationError):
        validator.validate(dict(acdc.sad, bogus="x"))
    with pytest.raises(ValidationError):
        validator.validate({k: v for k, v in acdc.sad.items() if k != 'i'})


def test_registry_issuance_lifecycle_JSON():
    """Example: the full registry-dependent issuance lifecycle.

    Shows what the spec-linked examples hand-wave over: an issuer stands up a
    fresh credential registry, constructs a real ACDC whose SAID is *derived*
    here (not pasted in), binds that ACDC into the registry as 'issued' via a
    blindable update, and a verifier unblinds the registry state to confirm the
    issued state. The credential is then revoked and the new state re-confirmed.

    The blindable registry keeps the registry state (issued/revoked and which
    ACDC) hidden on the wire; only a party holding the shared salt can unblind
    it, which is the basis for the correlation-minimizing state disclosure
    demonstrated elsewhere in this file.
    """
    # --- Step 1: Amy creates a fresh credential registry (rip event). ---
    # The registry inception is a vacuous placeholder: it commits to no ACDC
    # state, so it leaks nothing about what will later be issued. The registry
    # identifier (regid) is simply the SAID of this inception event.
    regStamp = '2025-07-04T17:50:00.000000+00:00'
    ripper = regcept(israid=AMY, uuid=NONCES[0], stamp=regStamp)
    assert ripper.proto == Protocols.acdc
    assert ripper.pvrsn == Vrsn_2_0
    assert ripper.genus == GenDex.KERI
    assert ripper.kind == Kinds.json
    assert ripper.ilk == Ilks.rip
    assert ripper.sad['i'] == AMY          # registry belongs to its issuer
    assert ripper.sad['n'] == "0"          # inception is sequence number 0
    regid = ripper.said                    # registry id == SAID of the rip event
    # This is the same registry (regAmy) used in the spec's worked examples,
    # here derived from its inception event rather than assumed to pre-exist.
    assert regid == REG_AMY

    # --- Step 2: Amy constructs a real ACDC bound to that registry. ---
    # Constructing the credential is not yet issuance: it becomes 'issued' only
    # when its state is recorded in the registry (Step 3). The ACDC's 'rd' field
    # references the registry created in Step 1. Because the SAID is derived from
    # the ACDC content, we do not know it in advance; the point is that it is
    # produced here rather than assumed to pre-exist.
    attribute = dict(d='', u=NONCES[7], name="Sunspot College", level="gold")
    acdc = acdcmap(israid=AMY, uuid=NONCES[10], regid=regid,
                   attribute=attribute, iseaid=BOB)
    assert acdc.ilk == Ilks.acm
    assert acdc.sad['i'] == AMY            # issued by Amy
    assert acdc.sad['rd'] == regid         # bound to Amy's registry
    assert acdc.sad['a']['i'] == BOB       # issued to Bob
    acdcSaid = acdc.said
    assert acdcSaid == "EKqjwYRfEGl5rLu9TAN277K0fUUO87c0iIfMMRWdoTcp"
    # The credential conforms to its ACDC-message JSON Schema (Draft 2020-12) and
    # commits to that schema via its 's' section.
    assert_acdc_schema_valid(acdc)

    # --- Step 3: Amy binds the issued ACDC into the registry (bup event). ---
    # The blindable state block commits to (this ACDC, 'issued') but is hidden by
    # a per-event "blind" -- a nonce the issuer derives from a secret salt via a
    # hierarchically-deterministic path whose only ingredient is the event's
    # sequence number. So EACH event gets its own distinct blind, yet every one
    # of them is reproducible from that single salt plus the event's sn. The salt
    # is shared ONLY between the issuer and the holder (the party the issuer
    # designates to disclose state, usually the issuee); it is deliberately never
    # handed to verifiers -- Step 4 explains why. Only the blinded state's SAID
    # (the "blid") travels in the 'bup' message; the ACDC SAID and the word
    # 'issued' never appear on the wire.
    salt = NONCES[15]                       # secret shared issuer<->holder only
    issuedBlinder = Blinder.blind(acdc=acdcSaid, state='issued', salt=salt, sn=1)
    assert issuedBlinder.acdc == acdcSaid
    assert issuedBlinder.state == 'issued'
    # The blinding nonce derives from (salt, sn) only, so it matches the spec's
    # blindable example at sn=1; the blinded state SAID differs because here it
    # commits to a really-issued ACDC rather than an empty placeholder.
    assert issuedBlinder.uuid == "aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8"
    assert issuedBlinder.said == "EElISYQ4JG1SyKkHrWL8URdR80tzJNnytCDjAkYbJiNY"

    issueStamp = '2025-08-01T18:06:10.988921+00:00'
    issued = blindate(regid=regid, prior=regid, blid=issuedBlinder.said,
                      sn=1, stamp=issueStamp)
    assert issued.ilk == Ilks.bup
    assert issued.sad['rd'] == regid       # names the registry
    assert issued.sad['p'] == regid        # prior is the rip event
    assert issued.sad['n'] == "1"          # first update after inception
    assert issued.sad['b'] == issuedBlinder.said
    assert issued.said == "EHtnkxegbSnTqAaSoo8jxtXi0yD-xbQji82NMJsiC8fl"

    # Privacy invariant: the issued/revoked state and the ACDC SAID are blinded,
    # so a verifier that merely observes the 'bup' message on the wire learns
    # neither of them.
    assert 'ts' not in issued.sad and 'td' not in issued.sad
    assert b'issued' not in issued.raw
    assert acdcSaid.encode() not in issued.raw

    # --- Step 4: confirm the state by unblinding. ---
    # Unblinding = recompute the blinded state's SAID (the 'b'/blid value) over
    # each candidate state and the shown ACDC, and see which candidate reproduces
    # it. To do that you need the event's blind. Here we hand Blinder the SALT
    # (plus sn) and let it derive the blind for us. That is a TEST SHORTCUT, and
    # it models the issuer's/holder's own view -- NOT a real presentation to a
    # verifier. A verifier must NEVER be given the salt: from the salt it could
    # derive the blind for every sequence number and so read the credential's
    # entire state history, past AND future, forever -- which would defeat the
    # entire purpose of a blindable registry. In a real presentation a verifier
    # instead receives just one event's blind (its per-sn nonce), which unblinds
    # that single event and no other. test_blindable_registry_correlation_minimizing_JSON
    # below shows that faithful per-event disclosure and why it stays private.
    unblinder = Blinder.unblind(said=issued.sad['b'], acdc=acdcSaid,
                                states=['issued', 'revoked'], salt=salt, sn=1)
    assert unblinder is not None           # a candidate matched -> verified
    assert unblinder.state == 'issued'
    assert unblinder.acdc == acdcSaid
    assert unblinder.crew == issuedBlinder.crew

    # --- Step 5: Amy revokes the ACDC with a second blindable update. ---
    revokedBlinder = Blinder.blind(acdc=acdcSaid, state='revoked', salt=salt, sn=2)
    assert revokedBlinder.state == 'revoked'
    assert revokedBlinder.uuid == "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB"
    assert revokedBlinder.said == "ECIgacw-6qPWs7Xwpok-D87IkQI6yyDLNiYSH9IyC7tx"

    revokeStamp = '2025-09-01T18:06:10.988921+00:00'
    revoked = blindate(regid=regid, prior=issued.said, blid=revokedBlinder.said,
                       sn=2, stamp=revokeStamp)
    assert revoked.ilk == Ilks.bup
    assert revoked.sad['p'] == issued.said  # chains onto the issuance update
    assert revoked.sad['n'] == "2"
    assert revoked.said == "ENACMzpaiMMcdpQRBA4IbbqjUMcoJ_wBBsbhwpg_MYJM"

    reunblinder = Blinder.unblind(said=revoked.sad['b'], acdc=acdcSaid,
                                  states=['issued', 'revoked'], salt=salt, sn=2)
    assert reunblinder is not None
    assert reunblinder.state == 'revoked'
    assert reunblinder.acdc == acdcSaid           # bound to this credential, not another
    assert reunblinder.crew == revokedBlinder.crew


def test_registry_issuance_lifecycle_IPEX_JSON():
    """Same lifecycle as the worked example, but transported through IPEX.

    This stays distinct from test_clc_disclosure.py's gated exchange. The point
    here is not pre-disclosure negotiation; it is to carry the foundational
    registry artifacts inside the IPEX builders and route them through the real
    IPEX handlers we have today.

    The current ``ipexing.grant`` builder gives us three carried artifacts:
    ``acdc`` (the credential), ``iss`` (the current registry update), and
    ``anc`` (one ancillary artifact). For this registry lifecycle example we use
    that ancillary slot for the registry inception (`rip`) itself, so one bare
    grant snapshots the whole state package the holder needs:

      credential + current `bup` state + originating registry `rip`

    A second bare grant later carries the revoked-state snapshot. Each bare
    grant is acknowledged by an IPEX admit.
    """

    class Recorder:
        def __init__(self):
            self.items = []

        def add(self, attrs):
            self.items.append(attrs)

    with openHby(name="ipex-registry-lifecycle",
                 base="test",
                 version=Vrsn_2_0) as hby:
        amy = hby.makeHab(name="amy", version=Vrsn_2_0, kind=Kinds.json)
        bob = hby.makeHab(name="bob", version=Vrsn_2_0, kind=Kinds.json)

        # Rebuild the same artifact pattern as the JSON worked example, but with
        # live Hab AIDs because the current IPEX builders sign through Hab.
        regStamp = '2025-07-04T17:50:00.000000+00:00'
        ripper = regcept(israid=amy.pre, uuid=NONCES[0], stamp=regStamp)
        assert ripper.ilk == Ilks.rip
        regid = ripper.said

        attribute = dict(d='', u=NONCES[7], name="Sunspot College", level="gold")
        acdc = acdcmap(israid=amy.pre, uuid=NONCES[10], regid=regid,
                       attribute=attribute, iseaid=bob.pre)
        assert acdc.ilk == Ilks.acm
        assert acdc.sad['rd'] == regid
        assert acdc.sad['a']['i'] == bob.pre
        assert_acdc_schema_valid(acdc)

        salt = NONCES[15]
        issuedBlinder = Blinder.blind(acdc=acdc.said, state='issued', salt=salt, sn=1)
        issued = blindate(regid=regid, prior=regid, blid=issuedBlinder.said,
                          sn=1, stamp='2025-08-01T18:06:10.988921+00:00')
        revokedBlinder = Blinder.blind(acdc=acdc.said, state='revoked', salt=salt, sn=2)
        revoked = blindate(regid=regid, prior=issued.said, blid=revokedBlinder.said,
                           sn=2, stamp='2025-09-01T18:06:10.988921+00:00')

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Bare grant 1: the issued-state snapshot. In today's builder shape the
        # lifecycle package is encoded as:
        #   acdc = credential, iss = current `bup`, anc = registry inception `rip`
        issuedGrant, issuedGrantAtc = ipexGrant(
            hab=amy,
            recp=bob.pre,
            message="Issued registry snapshot",
            acdc=acdc,
            iss=issued,
            anc=ripper,
        )
        issuedGrantIms = bytearray(issuedGrant.raw)
        issuedGrantIms.extend(issuedGrantAtc)
        issuedGrantResults = Parser(version=Vrsn_2_0).parse(ims=issuedGrantIms,
                                                            framed=False,
                                                            processive=False)
        assert issuedGrantIms == bytearray()
        assert len(issuedGrantResults) == 1
        issuedGrantResult = issuedGrantResults[0]
        assert issuedGrantResult.serder.said == issuedGrant.said
        assert issuedGrantResult.serder.ked['r'] == "/ipex/grant"
        assert issuedGrantResult.serder.ked['p'] == ""          # bare grant opens the flow
        assert issuedGrantResult.serder.ked['a']['i'] == bob.pre
        assert issuedGrantResult.serder.ked['a']['acdc'] == acdc.said
        assert issuedGrantResult.serder.ked['a']['iss'] == issued.said
        assert issuedGrantResult.serder.ked['a']['anc'] == ripper.said
        assert [nest.serder.said for nest in issuedGrantResult.nests] == [
            acdc.said, issued.said, ripper.said
        ]
        issuedGrantWire = bytes(issuedGrant.raw) + bytes(issuedGrantAtc)
        # The disclosed credential is present on the wire, but the registry state
        # word itself remains hidden because the nested `bup` is blindable
        assert b'issued' not in issuedGrantWire
        assert b'revoked' not in issuedGrantWire

        # Route the same message through the real IPEX handlers and persist it
        issuedGrantDispatch = bytearray(issuedGrant.raw)
        issuedGrantDispatch.extend(issuedGrantAtc)
        Parser(version=Vrsn_2_0).parse(ims=issuedGrantDispatch, framed=False, exc=exc)
        assert issuedGrantDispatch == bytearray()

        # Assert that it was stored
        storedIssuedGrant = hby.db.exns.get(keys=(issuedGrant.said,))
        assert storedIssuedGrant is not None
        assert storedIssuedGrant.ked['a']['iss'] == issued.said
        assert storedIssuedGrant.ked['a']['anc'] == ripper.said

        issuedAdmit, issuedAdmitAtc = ipexAdmit(
            hab=bob,
            message="Received issued snapshot",
            grant=issuedGrant,
        )
        issuedAdmitIms = bytearray(issuedAdmit.raw)
        issuedAdmitIms.extend(issuedAdmitAtc)
        Parser(version=Vrsn_2_0).parse(ims=issuedAdmitIms, framed=False, exc=exc)
        assert issuedAdmitIms == bytearray()
        storedIssuedAdmit = hby.db.exns.get(keys=(issuedAdmit.said,))
        assert storedIssuedAdmit is not None
        assert storedIssuedAdmit.ked['p'] == issuedGrant.said

        # The holder/verifier can now pull the carried `bup` out of the IPEX
        # grant and perform the same unblinding confirmation as in the base test
        issuedNest = issuedGrantResult.nests[1].serder
        unblinder = Blinder.unblind(said=issuedNest.sad['b'], acdc=acdc.said,
                                    states=['issued', 'revoked'], salt=salt, sn=1)
        assert unblinder is not None
        assert unblinder.state == 'issued'
        assert unblinder.acdc == acdc.said
        assert unblinder.crew == issuedBlinder.crew

        # Bare grant 2: later the issuer ships the revoked-state snapshot the
        # same way, again through the handler chain.
        revokedGrant, revokedGrantAtc = ipexGrant(
            hab=amy,
            recp=bob.pre,
            message="Revoked registry snapshot",
            acdc=acdc,
            iss=revoked,
            anc=ripper,
        )
        revokedGrantIms = bytearray(revokedGrant.raw)
        revokedGrantIms.extend(revokedGrantAtc)
        revokedGrantResults = Parser(version=Vrsn_2_0).parse(ims=revokedGrantIms,
                                                             framed=False,
                                                             processive=False)
        assert revokedGrantIms == bytearray()
        assert len(revokedGrantResults) == 1
        revokedGrantResult = revokedGrantResults[0]
        assert revokedGrantResult.serder.ked['r'] == "/ipex/grant"
        assert revokedGrantResult.serder.ked['p'] == ""
        assert revokedGrantResult.serder.ked['a']['iss'] == revoked.said
        assert revokedGrantResult.serder.ked['a']['anc'] == ripper.said
        assert [nest.serder.said for nest in revokedGrantResult.nests] == [
            acdc.said, revoked.said, ripper.said
        ]
        revokedGrantWire = bytes(revokedGrant.raw) + bytes(revokedGrantAtc)
        assert b'issued' not in revokedGrantWire
        assert b'revoked' not in revokedGrantWire

        revokedGrantDispatch = bytearray(revokedGrant.raw)
        revokedGrantDispatch.extend(revokedGrantAtc)
        Parser(version=Vrsn_2_0).parse(ims=revokedGrantDispatch, framed=False, exc=exc)
        assert revokedGrantDispatch == bytearray()
        storedRevokedGrant = hby.db.exns.get(keys=(revokedGrant.said,))
        assert storedRevokedGrant is not None
        assert storedRevokedGrant.ked['a']['iss'] == revoked.said

        revokedAdmit, revokedAdmitAtc = ipexAdmit(
            hab=bob,
            message="Received revoked snapshot",
            grant=revokedGrant,
        )
        revokedAdmitIms = bytearray(revokedAdmit.raw)
        revokedAdmitIms.extend(revokedAdmitAtc)
        Parser(version=Vrsn_2_0).parse(ims=revokedAdmitIms, framed=False, exc=exc)
        assert revokedAdmitIms == bytearray()
        storedRevokedAdmit = hby.db.exns.get(keys=(revokedAdmit.said,))
        assert storedRevokedAdmit is not None
        assert storedRevokedAdmit.ked['p'] == revokedGrant.said

        revokedNest = revokedGrantResult.nests[1].serder
        reunblinder = Blinder.unblind(said=revokedNest.sad['b'], acdc=acdc.said,
                                      states=['issued', 'revoked'], salt=salt, sn=2)
        assert reunblinder is not None
        assert reunblinder.state == 'revoked'
        assert reunblinder.acdc == acdc.said
        assert reunblinder.crew == revokedBlinder.crew

        assert [(item["r"], item["m"]) for item in recorder.items] == [
            ("/exn/ipex/grant", "Issued registry snapshot"),
            ("/exn/ipex/admit", "Received issued snapshot"),
            ("/exn/ipex/grant", "Revoked registry snapshot"),
            ("/exn/ipex/admit", "Received revoked snapshot"),
        ]


def test_selective_disclosure_aggregate_JSON():
    """Example: issuer plans for selective disclosure via an aggregate section.

    Instead of a single attribute block, the issuer places each attribute in
    its own element of an aggregate ('A') section. Each element is individually
    blinded (carries its own nonce) and self-addressing (carries its own SAID),
    and the section as a whole is committed to by a single aggregate digest
    (AGID). This schema choice is made at issuance time and is what makes
    selective disclosure possible later.

    At presentation the holder discloses only the chosen elements (as full
    blocks) and leaves the rest as bare SAIDs. The verifier recomputes the AGID
    over the mix of disclosed blocks and undisclosed SAIDs and confirms it still
    equals the committed AGID -- so the disclosure is authentic and tamper
    evident, yet the undisclosed attribute values never appear on the wire.

    (The verifier still learns how many elements the section has and which were
    withheld -- the count and positions are structural, not blinded. Only the
    withheld values themselves are protected.)
    """
    kind = Kinds.json

    # --- Issuer: design the credential as an aggregate of blindable elements. ---
    # ael[0] is a placeholder for the aggregate digest (AGID); each remaining
    # element is a block with an empty SAID ('d') to be computed, its own
    # blinding nonce ('u'), and one disclosable attribute.
    iael = ["",
            dict(d='', u=NONCES[0], i=BOB),
            dict(d='', u=NONCES[1], score=96),
            dict(d='', u=NONCES[2], name="Zoe Doe")]
    aggor = Aggor(ael=iael, makify=True, kind=kind)

    agid = aggor.agid
    assert agid == "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx"
    assert aggor.ael[0] == agid                 # element 0 is the aggregate digest
    # every element block now carries a computed Blake3-256 SAID in its 'd' field.
    # Diger(qb64=...) parses and validates the CESR digest -- raising on a
    # malformed string, unlike a bare startswith -- and .code pins it to Blake3-256.
    assert all(Diger(qb64=elem['d']).code == DigDex.Blake3_256
               for elem in aggor.ael[1:])

    # The issuer references the aggregate from the top-level ACDC via its 'A'
    # field. In compact form that is just the AGID; the ACDC SAID is computed
    # over the most compact form either way.
    acdc = acdcagg(israid=AMY, uuid=NONCES[10], regid=REG_AMY,
                   aggregate=aggor.ael, kind=kind)
    acdcCompact = acdcagg(israid=AMY, uuid=NONCES[10], regid=REG_AMY,
                          aggregate=agid, kind=kind)
    assert acdc.ilk == Ilks.acg
    assert acdc.said == acdcCompact.said        # same SAID, compact or expanded
    # Both the expanded and compact forms conform to the acg (aggregate)
    # ACDC-message JSON Schema.
    assert_acdc_schema_valid(acdc)
    assert_acdc_schema_valid(acdcCompact)

    assert acdc.iseaid == BOB
    assert acdc.issuee.qb64 == BOB

    # --- Holder: fully disclose (all elements collapse to SAIDs). ---
    full, k = aggor.disclose()
    assert k == kind
    assert full == [agid] + [elem['d'] for elem in aggor.ael[1:]]
    assert Aggor.verifyDisclosure(full, kind=kind)   # the compact form verifies too

    # --- Holder: selectively disclose only the issuee element. ---
    # Disclosable elements are indexed from 1; index 0 is the AGID anchor, which
    # is always present in a disclosure and is never itself disclosed.
    disclosed, k = aggor.disclose(indices=[1])
    assert disclosed[0] == agid                 # AGID anchor
    assert isinstance(disclosed[1], dict)       # element 1 fully disclosed
    assert disclosed[1]['i'] == BOB
    assert isinstance(disclosed[2], str)        # element 2 hidden (SAID only)
    assert isinstance(disclosed[3], str)        # element 3 hidden (SAID only)

    # Privacy invariant: the undisclosed elements appear only as SAID strings
    # (asserted just above), so their attribute values are provably absent from
    # the disclosure -- e.g. the withheld name value never appears on the wire.
    assert 'Zoe Doe' not in json.dumps(disclosed)

    # --- Verifier: the selective disclosure verifies against the AGID. ---
    assert Aggor.verifyDisclosure(disclosed, kind=kind)

    # Tamper evidence: altering a disclosed value breaks AGID verification.
    tampered = [disclosed[0], dict(disclosed[1], i=AMY), disclosed[2], disclosed[3]]
    assert not Aggor.verifyDisclosure(tampered, kind=kind)


def test_selective_disclosure_aggregate_IPEX_JSON():
    """Selective aggregate disclosure carried through the real IPEX grant path.

    The sibling JSON worked example proves the disclosure math directly on the
    aggregate section. This companion test packages the selectively disclosed
    *variant of that same ACDC* inside a real IPEX `grant`, routes it through the
    v2 IPEX handlers, and shows that the verifier can still validate the carried
    disclosure against the committed AGID while the withheld values stay off the
    wire.
    """

    class Recorder:
        def __init__(self):
            self.items = []

        def add(self, attrs):
            self.items.append(attrs)

    with openHby(name="ipex-selective-aggregate",
                 base="test",
                 version=Vrsn_2_0) as hby:
        amy = hby.makeHab(name="amy", version=Vrsn_2_0, kind=Kinds.json)
        bob = hby.makeHab(name="bob", version=Vrsn_2_0, kind=Kinds.json)
        vic = hby.makeHab(name="vic", version=Vrsn_2_0, kind=Kinds.json)

        kind = Kinds.json
        ripper = regcept(israid=amy.pre, uuid=NONCES[3],
                         stamp='2025-07-04T17:50:00.000000+00:00')

        # Issuer-side setup mirrors the original example, but with live Habs for
        # the transport actors that will sign the outer IPEX messages.
        iael = ["",
                dict(d='', u=NONCES[0], i=bob.pre),
                dict(d='', u=NONCES[1], score=96),
                dict(d='', u=NONCES[2], name="Zoe Doe")]
        aggor = Aggor(ael=iael, makify=True, kind=kind)
        agid = aggor.agid

        acdc = acdcagg(israid=amy.pre, uuid=NONCES[10], regid=ripper.said,
                       aggregate=aggor.ael, kind=kind)
        compact = acdcagg(israid=amy.pre, uuid=NONCES[10], regid=ripper.said,
                          aggregate=agid, kind=kind)
        schema = assert_acdc_schema_valid(acdc)
        assert_acdc_schema_valid(compact, schema=schema)
        assert acdc.said == compact.said
        assert acdc.iseaid == bob.pre

        # A fully collapsed disclosure variant still commits to the same top-level
        # ACDC SAID: the holder can present only element SAIDs and preserve the
        # commitment.
        full, k = aggor.disclose()
        assert k == kind
        assert Aggor.verifyDisclosure(full, kind=kind)
        collapsed = acdcagg(israid=amy.pre, uuid=NONCES[10], regid=ripper.said,
                            aggregate=full, kind=kind)
        assert collapsed.said == acdc.said

        # Holder-side selective disclosure: reveal only the issuee element and
        # withhold the score/name elements as bare SAIDs.
        disclosed, k = aggor.disclose(indices=[1])
        assert k == kind
        selective = acdcagg(israid=amy.pre, uuid=NONCES[10], regid=ripper.said,
                            aggregate=disclosed, kind=kind)
        assert selective.said == acdc.said
        assert_acdc_schema_valid(selective, schema=schema)
        assert selective.sad['A'][0] == agid
        assert isinstance(selective.sad['A'][1], dict)
        assert selective.sad['A'][1]['i'] == bob.pre
        assert isinstance(selective.sad['A'][2], str)
        assert isinstance(selective.sad['A'][3], str)
        assert 'Zoe Doe' not in json.dumps(selective.sad['A'])

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # The holder (Bob) presents Amy's credential to the verifier (Vic). The
        # outer IPEX sender is Bob, while the nested ACDC issuer remains Amy.
        grant, grantAtc = ipexGrant(
            hab=bob,
            recp=vic.pre,
            message="Selective aggregate disclosure",
            acdc=selective,
        )
        grantIms = bytearray(grant.raw)
        grantIms.extend(grantAtc)
        grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                      framed=False,
                                                      processive=False)
        assert grantIms == bytearray()
        assert len(grantResults) == 1
        grantResult = grantResults[0]
        assert grantResult.serder.said == grant.said
        assert grantResult.serder.ked['r'] == "/ipex/grant"
        assert grantResult.serder.ked['p'] == ""        # bare grant opens the flow
        assert grantResult.serder.ked['i'] == bob.pre   # holder/discloser
        assert grantResult.serder.ked['a']['i'] == vic.pre
        assert grantResult.serder.ked['a']['acdc'] == selective.said
        assert [nest.serder.said for nest in grantResult.nests] == [selective.said]

        carried = grantResult.nests[0].serder
        assert carried.said == acdc.said                # same credential commitment
        assert carried.sad['i'] == amy.pre              # still Amy's credential
        assert carried.iseaid == bob.pre                # held by Bob
        assert carried.sad['A'][0] == agid
        assert isinstance(carried.sad['A'][1], dict)
        assert carried.sad['A'][1]['i'] == bob.pre
        assert isinstance(carried.sad['A'][2], str)
        assert isinstance(carried.sad['A'][3], str)

        grantWire = bytes(grant.raw) + bytes(grantAtc)
        # The carried selective disclosure reveals only the chosen element: the
        # withheld name value never appears on the IPEX wire message.
        assert b'Zoe Doe' not in grantWire

        # Verifier-side check: recomputing the AGID over the mixed disclosure
        # still verifies the selective presentation against the committed
        # aggregate, and any tampering breaks that proof.
        assert Aggor.verifyDisclosure(carried.sad['A'], kind=kind)
        tampered = [carried.sad['A'][0],
                    dict(carried.sad['A'][1], i=amy.pre),
                    carried.sad['A'][2],
                    carried.sad['A'][3]]
        assert not Aggor.verifyDisclosure(tampered, kind=kind)

        grantDispatch = bytearray(grant.raw)
        grantDispatch.extend(grantAtc)
        Parser(version=Vrsn_2_0).parse(ims=grantDispatch, framed=False, exc=exc)
        assert grantDispatch == bytearray()
        storedGrant = hby.db.exns.get(keys=(grant.said,))
        assert storedGrant is not None
        assert storedGrant.ked['a']['acdc'] == selective.said

        admit, admitAtc = ipexAdmit(
            hab=vic,
            message="Received selective aggregate disclosure",
            grant=grant,
        )
        admitIms = bytearray(admit.raw)
        admitIms.extend(admitAtc)
        Parser(version=Vrsn_2_0).parse(ims=admitIms, framed=False, exc=exc)
        assert admitIms == bytearray()
        storedAdmit = hby.db.exns.get(keys=(admit.said,))
        assert storedAdmit is not None
        assert storedAdmit.ked['p'] == grant.said

        assert [(item["r"], item["m"]) for item in recorder.items] == [
            ("/exn/ipex/grant", "Selective aggregate disclosure"),
            ("/exn/ipex/admit", "Received selective aggregate disclosure"),
        ]


def test_partial_disclosure_compaction_JSON():
    """Example: graduated (partial) disclosure via compaction of a private ACDC.

    An ACDC is 'private' when it carries a top-level nonce ('u'), which lets it
    circulate in most-compact form -- every section reduced to its SAID -- while
    still committing to its full content. The top-level ACDC SAID is always
    computed over the most-compact form, so it is identical whether the ACDC is
    held compact or expanded. That stable commitment is what lets a holder
    disclose sections one at a time (graduated disclosure): the verifier checks
    each disclosed section's SAID against the compact ACDC and can be sure it
    belongs, without ever seeing the sections still withheld.

    Part A shows section-level disclosure. Following the spec's Chain-Link
    Confidentiality flow, it reveals the rule section (the terms of use, which a
    verifier needs up front) and keeps the private attribute section withheld as
    a bare SAID. Part B shows disclosure *within* a section, where a nested block
    (grades) can itself be withheld or revealed while the credential commitment
    is unchanged. Part C generalizes that to several independently-disclosable
    nested blocks, and shows a *mixed* disclosure -- one block revealed, another
    withheld -- which the holder assembles by hand.
    """
    kind = Kinds.json

    # --- Part A: section-level graduated disclosure. ---
    # The issuer builds one private ACDC. The uncompacted form carries the
    # section blocks inline; the compacted form carries only their SAIDs. Both
    # have the same top-level SAID because it is taken over the most-compact form.
    ruleText = "AS IS basis. MUST NOT be shared."
    # Define the section blocks once and pass a fresh copy to each call, because
    # acdcmap inserts the issuee into the attribute block in place.
    attrMad = dict(d='', u=NONCES[7], name="Bob Student", gpa=4)
    ruleMad = dict(d='', l=ruleText)
    expanded = acdcmap(israid=AMY, uuid=NONCES[13], regid=REG_AMY,
                       attribute=dict(attrMad), iseaid=BOB, rule=dict(ruleMad),
                       compactify=False, kind=kind)
    compact = acdcmap(israid=AMY, uuid=NONCES[13], regid=REG_AMY,
                      attribute=dict(attrMad), iseaid=BOB, rule=dict(ruleMad),
                      compactify=True, kind=kind)

    assert compact.sad['u'] == NONCES[13]             # private ACDC (has a nonce)
    assert expanded.said == compact.said             # same commitment either way
    assert compact.said == "EDlaFELjgpoRQ7zPh0DISKR1n5ku1UZWr_my6bLF8Bjg"
    assert isinstance(expanded.sad['a'], dict)       # sections inline
    assert isinstance(compact.sad['a'], str)         # sections as SAIDs
    assert compact.sad['a'] == "ED1pc3B7apjLEMgWnI08EZky8TU5SfqpARRQ5mr_z9vh"
    assert compact.sad['r'] == "ECIxF7cojMJIXm-SKGR1w8Bj8N1v0637trHKYT9TWqd9"
    # Both forms conform to the acm ACDC-message JSON Schema: its section fields
    # are oneOf(SAID string, block), so a section validates whether compacted to
    # a SAID or carried inline. The compact form's own schema section is a bare
    # SAID, so it validates against the schema its expanded sibling carries.
    schema = assert_acdc_schema_valid(expanded)
    assert_acdc_schema_valid(compact, schema=schema)

    # Privacy invariant: the compact ACDC leaks neither the attribute values nor
    # the rule text -- only their SAIDs travel.
    assert b"Bob Student" not in compact.raw
    assert b"MUST NOT" not in compact.raw

    # Holder discloses the rule section (the contract / terms of use) and keeps
    # the private attribute section withheld. This is the direction the spec's
    # Chain-Link Confidentiality flow uses: the terms are shown first so the
    # verifier (Disclosee) can agree to them, and the private attributes stay
    # hidden until, and unless, that agreement is made (spec-body.md lines 256,
    # 741). Hiding the terms while exposing the attributes would invert that.
    disclosedRule = expanded.sad['r']                # the full rule block
    # Verifier recomputes the disclosed block's SAID and confirms it is the very
    # section the compact ACDC commits to under 'r'.
    recomputed = Compactor(mad=dict(disclosedRule, d=''), makify=True, kind=kind)
    assert recomputed.said == compact.sad['r']       # disclosure belongs to this ACDC
    assert disclosedRule['l'] == ruleText            # verifier now sees the terms of use
    # The attribute section remains a bare SAID to the verifier -- the private
    # values (name, gpa) stay withheld until the terms are agreed.
    assert compact.sad['a'] == "ED1pc3B7apjLEMgWnI08EZky8TU5SfqpARRQ5mr_z9vh"

    # --- Part B: graduated disclosure *within* a section. ---
    # A nested attribute holds a 'grades' sub-block. Compaction collapses grades
    # to a SAID; expansion offers each disclosure level as a partial. Crucially,
    # every partial verifies to the same section SAID, so withholding or
    # revealing grades does not change what the credential commits to.
    nested = dict(d='', u=NONCES[7], i=BOB, name="Bob Student",
                  grades=dict(d='', u=NONCES[8], math=4, english=3))
    compactor = Compactor(mad=nested, makify=True, kind=kind)
    compactor.compact()
    sectSaid = compactor.said
    assert sectSaid == "EAFKvz7kgHrJDNFmQj0Uz0hVtOM9W2OTMqPZf2d8j0a_"
    assert compactor.mad['grades'] == "EHMIUzFxN36XlRsRLIl8totAM1dLPDnYbjO5FAuWddN5"

    compactor.expand(greedy=True)
    # Two disclosure levels: grades withheld ('' path) and grades revealed.
    withheld = compactor.partials[('', )]
    revealed = compactor.partials[('.grades', )]
    assert withheld.said == sectSaid                 # same commitment...
    assert revealed.said == sectSaid                 # ...at every disclosure level
    assert isinstance(withheld.mad['grades'], str)   # grades hidden as a SAID
    assert isinstance(revealed.mad['grades'], dict)  # grades disclosed in full
    assert revealed.mad['grades']['math'] == 4
    # The withheld form does not leak the grades.
    assert b"math" not in withheld.raw

    # --- Part C: a mixed partial disclosure across multiple nested blocks. ---
    # An attribute may hold several independently-disclosable nested blocks, each
    # with its own SAID ('d') and blinding nonce ('u'). Here the attribute carries
    # both a 'grades' block and an 'address' block, so the holder can reveal one
    # and withhold the other. The disclosable unit is the block, not the field:
    # street/number/zip inside 'address' are disclosed together; to hide just the
    # zip it would have to be its own nested block (spec-body.md line 692).
    multi = dict(d='', u=NONCES[7], i=BOB, name="Bob Student",
                 grades=dict(d='', u=NONCES[8], math=4, english=3),
                 address=dict(d='', u=NONCES[9], street="Main", number=5, zip="90210"))
    mc = Compactor(mad=multi, makify=True, kind=kind)
    mc.compact()
    multiSaid = mc.said
    assert multiSaid == "EL_9Vlsx4xpfkRZJbURLugfDRVjFTRbD19n9Ytvoyn9-"

    # expand() enumerates only the tier-by-tier progression -- everything compact,
    # or the whole nested tier expanded -- NOT arbitrary per-block subsets.
    mc.expand(greedy=True)
    # expand() yields only the two tier extremes (all-compact, and the whole
    # nested tier expanded), never per-block subsets -- hence exactly two partials.
    assert len(mc.partials) == 2 and ('', ) in mc.partials
    allCompact = mc.partials[('', )].mad                     # both blocks as SAIDs
    allExpanded = next(v.mad for k, v in mc.partials.items() if k != ('', ))  # both in full

    # A MIXED disclosure -- reveal grades, withhold address -- is therefore one the
    # holder assembles directly: start from the all-compact form and expand only
    # the chosen branch, leaving the rest as bare SAIDs.
    mixed = dict(allCompact)
    mixed['grades'] = allExpanded['grades']
    assert isinstance(mixed['grades'], dict)                # grades revealed in full
    # address stays a bare SAID, so the WHOLE address block (street, number, zip)
    # is withheld -- proven structurally, not by fragile substring matching.
    assert isinstance(mixed['address'], str)

    # The verifier recomputes the most-compact SAID of the mixed form and confirms
    # it is the same commitment -- a disclosure is authentic at any mix of levels.
    check = Compactor(mad=dict(mixed, d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == multiSaid
    assert mixed['grades']['math'] == 4                     # verifier sees the revealed block


def test_partial_disclosure_compaction_IPEX_JSON():
    """Graduated partial disclosures carried through the real IPEX grant path.

    The sibling JSON worked example proves the compaction math directly on
    private ACDCs and nested section blocks. This companion test packages those
    same disclosure variants into real IPEX `grant` messages, routes them
    through the v2 handlers, and shows that the carried artifacts preserve the
    same top-level commitments while only the intended sections appear on the
    wire.
    """

    class Recorder:
        def __init__(self):
            self.items = []

        def add(self, attrs):
            self.items.append(attrs)

    with openHby(name="ipex-partial-compaction",
                 base="test",
                 version=Vrsn_2_0) as hby:
        amy = hby.makeHab(name="amy", version=Vrsn_2_0, kind=Kinds.json)
        bob = hby.makeHab(name="bob", version=Vrsn_2_0, kind=Kinds.json)
        vic = hby.makeHab(name="vic", version=Vrsn_2_0, kind=Kinds.json)

        kind = Kinds.json
        ripper = regcept(israid=amy.pre, uuid=NONCES[0],
                         stamp='2025-07-04T17:50:00.000000+00:00')

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        def ipexExn(acdc, message, admitMessage):
            grant, grantAtc = ipexGrant(
                hab=bob,
                recp=vic.pre,
                message=message,
                acdc=acdc,
            )
            grantIms = bytearray(grant.raw)
            grantIms.extend(grantAtc)
            grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                          framed=False,
                                                          processive=False)
            assert grantIms == bytearray()
            assert len(grantResults) == 1
            grantResult = grantResults[0]
            assert grantResult.serder.said == grant.said
            assert grantResult.serder.ked['r'] == "/ipex/grant"
            assert grantResult.serder.ked['p'] == ""
            assert grantResult.serder.ked['i'] == bob.pre
            assert grantResult.serder.ked['a']['i'] == vic.pre
            assert grantResult.serder.ked['a']['acdc'] == acdc.said
            assert [nest.serder.said for nest in grantResult.nests] == [acdc.said]
            wire = bytes(grant.raw) + bytes(grantAtc)

            grantDispatch = bytearray(grant.raw)
            grantDispatch.extend(grantAtc)
            Parser(version=Vrsn_2_0).parse(ims=grantDispatch, framed=False, exc=exc)
            assert grantDispatch == bytearray()
            storedGrant = hby.db.exns.get(keys=(grant.said,))
            assert storedGrant is not None
            assert storedGrant.ked['a']['acdc'] == acdc.said

            admit, admitAtc = ipexAdmit(
                hab=vic,
                message=admitMessage,
                grant=grant,
            )
            admitIms = bytearray(admit.raw)
            admitIms.extend(admitAtc)
            Parser(version=Vrsn_2_0).parse(ims=admitIms, framed=False, exc=exc)
            assert admitIms == bytearray()
            storedAdmit = hby.db.exns.get(keys=(admit.said,))
            assert storedAdmit is not None
            assert storedAdmit.ked['p'] == grant.said

            return grantResult, wire

        # Part A: disclose only the rule section while withholding attributes as
        # a bare SAID, then carry that partial ACDC through IPEX.
        ruleText = "AS IS basis. MUST NOT be shared."
        attrMad = dict(d='', u=NONCES[7], name="Bob Student", gpa=4)
        ruleMad = dict(d='', l=ruleText)
        expanded = acdcmap(israid=amy.pre, uuid=NONCES[13], regid=ripper.said,
                           attribute=dict(attrMad), iseaid=bob.pre, rule=dict(ruleMad),
                           compactify=False, kind=kind)
        compact = acdcmap(israid=amy.pre, uuid=NONCES[13], regid=ripper.said,
                          attribute=dict(attrMad), iseaid=bob.pre, rule=dict(ruleMad),
                          compactify=True, kind=kind)
        assert expanded.said == compact.said             # same commitment either way
        schema = assert_acdc_schema_valid(expanded)
        assert_acdc_schema_valid(compact, schema=schema)
        
        assert b"Bob Student" not in compact.raw
        assert b"MUST NOT" not in compact.raw

        # Build the rule section disclosure
        ruleOnly = acdcmap(israid=amy.pre, uuid=NONCES[13], regid=ripper.said,
                           schema=compact.sad['s'], attribute=compact.sad['a'],
                           rule=expanded.sad['r'], kind=kind)
        assert ruleOnly.said == compact.said == expanded.said
        assert_acdc_schema_valid(ruleOnly, schema=schema)
        assert isinstance(ruleOnly.sad['a'], str)
        assert isinstance(ruleOnly.sad['r'], dict)

        ruleGrantResult, ruleWire = ipexExn(
            ruleOnly,
            "Rule section disclosure",
            "Received rule section disclosure",
        )
        carriedRule = ruleGrantResult.nests[0].serder
        assert carriedRule.said == expanded.said
        assert carriedRule.sad['i'] == amy.pre
        assert isinstance(carriedRule.sad['a'], str)
        assert isinstance(carriedRule.sad['r'], dict)
        recomputedRule = Compactor(mad=dict(carriedRule.sad['r'], d=''),
                                   makify=True,
                                   kind=kind)
        assert recomputedRule.said == compact.sad['r']
        assert carriedRule.sad['r']['l'] == ruleText
        assert b"Bob Student" not in carriedRule.raw
        assert b"gpa" not in carriedRule.raw
        assert ruleText.encode() in carriedRule.raw
        assert b"Bob Student" not in ruleWire

        # Part B: the same credential commitment can first withhold a nested
        # grades block, then later reveal it, without changing the ACDC SAID.
        nested = dict(d='', u=NONCES[7], i=bob.pre, name="Bob Student",
                      grades=dict(d='', u=NONCES[8], math=4, english=3))
        compactor = Compactor(mad=nested, makify=True, kind=kind)
        compactor.compact()
        sectSaid = compactor.said
        compactor.expand(greedy=True)
        
        withheld = compactor.partials[('', )]
        revealed = compactor.partials[('.grades', )]

        gradesBase = acdcmap(israid=amy.pre, uuid=NONCES[11], regid=ripper.said,
                             attribute=nested, kind=kind)
        gradesSchema = assert_acdc_schema_valid(gradesBase)
        gradesWithheld = acdcmap(israid=amy.pre, uuid=NONCES[11], regid=ripper.said,
                                 schema=gradesBase.sad['s'], attribute=withheld.mad,
                                 kind=kind)
        gradesRevealed = acdcmap(israid=amy.pre, uuid=NONCES[11], regid=ripper.said,
                                 schema=gradesBase.sad['s'], attribute=revealed.mad,
                                 kind=kind)
        assert withheld.said == sectSaid and revealed.said == sectSaid
        assert gradesWithheld.said == gradesRevealed.said == gradesBase.said
        assert_acdc_schema_valid(gradesWithheld, schema=gradesSchema)
        assert_acdc_schema_valid(gradesRevealed, schema=gradesSchema)

        withheldGrantResult, withheldWire = ipexExn(
            gradesWithheld,
            "Grades withheld partial disclosure",
            "Received grades-withheld partial disclosure",
        )
        carriedWithheld = withheldGrantResult.nests[0].serder
        assert carriedWithheld.said == gradesBase.said
        assert carriedWithheld.sad['i'] == amy.pre
        assert carriedWithheld.iseaid == bob.pre
        assert isinstance(carriedWithheld.sad['a']['grades'], str)
        withheldCheck = Compactor(mad=dict(carriedWithheld.sad['a'], d=''),
                                  makify=True,
                                  kind=kind)
        withheldCheck.compact()
        assert withheldCheck.said == sectSaid
        assert b"math" not in carriedWithheld.raw
        assert b"math" not in withheldWire

        revealedGrantResult, revealedWire = ipexExn(
            gradesRevealed,
            "Grades revealed partial disclosure",
            "Received grades-revealed partial disclosure",
        )
        carriedRevealed = revealedGrantResult.nests[0].serder
        assert carriedRevealed.said == gradesBase.said
        assert carriedRevealed.sad['i'] == amy.pre
        assert carriedRevealed.iseaid == bob.pre
        assert isinstance(carriedRevealed.sad['a']['grades'], dict)
        assert carriedRevealed.sad['a']['grades']['math'] == 4
        revealedCheck = Compactor(mad=dict(carriedRevealed.sad['a'], d=''),
                                  makify=True,
                                  kind=kind)
        revealedCheck.compact()
        assert revealedCheck.said == sectSaid
        assert b"math" in carriedRevealed.raw

        # Part C: carry a mixed nested disclosure where grades are revealed but
        # the address block stays compacted to its SAID.
        multi = dict(d='', u=NONCES[7], i=bob.pre, name="Bob Student",
                     grades=dict(d='', u=NONCES[8], math=4, english=3),
                     address=dict(d='', u=NONCES[9], street="Main", number=5, zip="90210"))
        mc = Compactor(mad=multi, makify=True, kind=kind)
        mc.compact()
        multiSaid = mc.said
        mc.expand(greedy=True)
        allCompact = mc.partials[('', )].mad
        allExpanded = next(v.mad for k, v in mc.partials.items() if k != ('', ))
        mixed = dict(allCompact)
        mixed['grades'] = allExpanded['grades']

        mixedBase = acdcmap(israid=amy.pre, uuid=NONCES[12], regid=ripper.said,
                            attribute=multi, kind=kind)
        mixedSchema = assert_acdc_schema_valid(mixedBase)
        mixedAcdc = acdcmap(israid=amy.pre, uuid=NONCES[12], regid=ripper.said,
                            schema=mixedBase.sad['s'], attribute=mixed, kind=kind)
        assert mixedAcdc.said == mixedBase.said
        assert_acdc_schema_valid(mixedAcdc, schema=mixedSchema)

        mixedGrantResult, mixedWire = ipexExn(
            mixedAcdc,
            "Mixed nested partial disclosure",
            "Received mixed nested partial disclosure",
        )
        carriedMixed = mixedGrantResult.nests[0].serder
        assert carriedMixed.said == mixedBase.said
        assert carriedMixed.sad['i'] == amy.pre
        assert carriedMixed.iseaid == bob.pre
        assert isinstance(carriedMixed.sad['a']['grades'], dict)
        assert carriedMixed.sad['a']['grades']['math'] == 4
        assert isinstance(carriedMixed.sad['a']['address'], str)
        mixedCheck = Compactor(mad=dict(carriedMixed.sad['a'], d=''),
                               makify=True,
                               kind=kind)
        mixedCheck.compact()
        assert mixedCheck.said == multiSaid
        assert b"math" in carriedMixed.raw
        assert b"Main" not in carriedMixed.raw
        assert b"90210" not in carriedMixed.raw
        assert b"Main" not in mixedWire
        assert b"90210" not in mixedWire

        assert [(item["r"], item["m"]) for item in recorder.items] == [
            ("/exn/ipex/grant", "Rule section disclosure"),
            ("/exn/ipex/admit", "Received rule section disclosure"),
            ("/exn/ipex/grant", "Grades withheld partial disclosure"),
            ("/exn/ipex/admit", "Received grades-withheld partial disclosure"),
            ("/exn/ipex/grant", "Grades revealed partial disclosure"),
            ("/exn/ipex/admit", "Received grades-revealed partial disclosure"),
            ("/exn/ipex/grant", "Mixed nested partial disclosure"),
            ("/exn/ipex/admit", "Received mixed nested partial disclosure"),
        ]


def test_blindable_registry_correlation_minimizing_JSON():
    """Example: correlation-minimizing state disclosure from a blindable registry.

    A blindable registry lets an issuer publish a credential's state (issued,
    revoked, ...) while keeping that state hidden on the wire. The update events
    stay public and chained -- an observer sees that the registry advanced, when,
    and that the updates belong to it (the 'rd', sequence number, and prior link
    are all in the clear) -- but what each update commits to (the state, and which
    ACDC it concerns) is blinded. The spec calls the resulting disclosure
    "correlation-minimizing" (spec-body.md line 91).

    Each update's blinded state is protected by its own "blind": a nonce derived
    by a deterministic key-derivation over the secret salt and that event's
    sequence number (see Blinder.makeUUID). Deriving one blind per event gives
    two properties:

      1. The blinds are mutually independent: given the blind for one event you
         cannot compute the blind for any other event without the salt, nor
         invert a blind to recover the salt. This is the load-bearing, always-
         true guarantee, and it is what this test asserts.

      2. So a party enabled to read one update's state (by being handed that
         event's blind) learns nothing about any other update's state -- neither
         a later one (a verifier that saw 'issued' cannot later spot a 'revoked'
         by watching the registry) nor an earlier one. The salt itself is never
         disclosed; only per-event blinds are, and only to a chosen verifier at
         presentation time.

    The spec also mentions an OPTIONAL follow-on called re-blinding: after a
    presentation the holder MAY ask the issuer to publish a fresh event (new
    sequence number => new blind) even without a state change, so a previously
    disclosed blind no longer matches the head and cannot be reused as a standing
    proof of current state. Re-blinding is issuer-provided and issuer-timed
    (spec-body.md lines 2131, 2135): a holder cannot compel it, and it costs one
    registry event per presentation, so it MAY or MAY NOT be used. This test does
    not rely on it -- the guarantees above follow from per-event blind
    independence alone.

    (This is confidentiality of the state content, not anonymity of the
    credential: issuer, registry, and issuance chronology remain linkable, which
    is KERI's intended, auditable trade-off.)
    """
    kind = Kinds.json
    states = ['issued', 'revoked']

    # Amy constructs a credential that references her registry by SAID (REG_AMY,
    # from example 1). Passing regid only sets the ACDC's 'rd' pointer field -- it
    # does NOT create or modify any registry. This test publishes no events at
    # all; it works directly with the two blinded-state snapshots below to show
    # the disclosure math. salt is the secret shared between issuer and holder.
    acdc = acdcmap(israid=AMY, uuid=NONCES[10], regid=REG_AMY,
                   attribute=dict(d='', u=NONCES[7], name="Sunspot College",
                                  level="gold"),
                   iseaid=BOB, kind=kind)
    acdcSaid = acdc.said
    assert_acdc_schema_valid(acdc)                     # conforms to its acm schema
    salt = NONCES[15]                                  # shared issuer<->holder secret

    # Two blinded-state snapshots for the same credential, as it would move
    # issued (sn=1) -> revoked (sn=2). These are in-memory Blinder objects, not
    # published events; in a live registry each would ride inside a 'bup' event,
    # where only the blinded-state SAID (the blid) appears on the wire.
    issuedBlinder = Blinder.blind(acdc=acdcSaid, state='issued', salt=salt, sn=1)
    revokedBlinder = Blinder.blind(acdc=acdcSaid, state='revoked', salt=salt, sn=2)
    assert issuedBlinder.said == "EElISYQ4JG1SyKkHrWL8URdR80tzJNnytCDjAkYbJiNY"
    assert revokedBlinder.said == "ECIgacw-6qPWs7Xwpok-D87IkQI6yyDLNiYSH9IyC7tx"

    # State independence: each update's blinded state and its nonce are derived
    # independently (per sequence number), so the ability to read one update's
    # state confers no ability to read another's. The update events remain
    # linkable to the registry via 'rd' and the prior chain; it is the state
    # *content* that is protected.
    assert issuedBlinder.said != revokedBlinder.said
    assert issuedBlinder.uuid != revokedBlinder.uuid

    # --- Presentation at sn=1: holder proves 'issued' with a per-event nonce. ---
    # This is the faithful presentation model -- contrast Step 4 of the
    # registry-lifecycle example, which passed the whole salt as a test shortcut.
    # The holder hands the verifier ONLY this one event's blind (its per-sn nonce,
    # here issuedBlinder.uuid), never the salt. So unblind is called with uuid=...
    # and no salt=; it can therefore check this event, and only this event.
    verifierAtIssuance = Blinder.unblind(said=issuedBlinder.said,
                                         uuid=issuedBlinder.uuid,
                                         acdc=acdcSaid, states=states)
    assert verifierAtIssuance is not None
    assert verifierAtIssuance.state == 'issued'

    # --- A disclosed nonce reads ONE event -- not a later one, not an earlier one. ---
    # Forward: later, Amy revokes at sn=2. A verifier that was shown sn=1 holds
    # only sn=1's nonce and the public wire SAID of the sn=2 event. Lacking the
    # salt, it cannot regenerate sn=2's independent nonce, so it cannot unblind
    # the revocation -- the state change is invisible to it.
    laterPeek = Blinder.unblind(said=revokedBlinder.said,
                                uuid=issuedBlinder.uuid,      # sn=1 nonce, wrong for sn=2
                                acdc=acdcSaid, states=states)
    assert laterPeek is None                                  # cannot read the later state

    # Backward (symmetric): a verifier handed sn=2's nonce likewise cannot read
    # sn=1's state. The blinds are per-event and independent, so a disclosed nonce
    # is confined to its own event in either direction.
    earlierPeek = Blinder.unblind(said=issuedBlinder.said,
                                  uuid=revokedBlinder.uuid,    # sn=2 nonce, wrong for sn=1
                                  acdc=acdcSaid, states=states)
    assert earlierPeek is None                                # cannot read the earlier state

    # The legitimate holder, who has the salt, can regenerate any update's nonce
    # and disclose the current state per presentation.
    holderAtRevocation = Blinder.unblind(said=revokedBlinder.said, acdc=acdcSaid,
                                         states=states, salt=salt, sn=2)
    assert holderAtRevocation is not None
    assert holderAtRevocation.state == 'revoked'


def test_blindable_registry_correlation_minimizing_IPEX_JSON():
    """Per-event blind disclosure carried through the real IPEX grant path.

    The sibling JSON worked example proves that a disclosed blind reads exactly
    one blindable registry update and no others. This companion test packages
    those blinded registry updates as nested `bup` artifacts inside real IPEX
    `grant` messages, routes them through the v2 handlers, and shows that the
    verifier can unblind only the event whose per-sn nonce the holder chooses to
    disclose out of band. The IPEX wire itself never carries the salt or either
    cleartext state word.
    """

    class Recorder:
        def __init__(self):
            self.items = []

        def add(self, attrs):
            self.items.append(attrs)

    with openHby(name="ipex-correlation-minimizing",
                 base="test",
                 version=Vrsn_2_0) as hby:
        amy = hby.makeHab(name="amy", version=Vrsn_2_0, kind=Kinds.json)
        bob = hby.makeHab(name="bob", version=Vrsn_2_0, kind=Kinds.json)
        vic = hby.makeHab(name="vic", version=Vrsn_2_0, kind=Kinds.json)

        kind = Kinds.json
        states = ['issued', 'revoked']

        ripper = regcept(israid=amy.pre, uuid=NONCES[0],
                         stamp='2025-07-04T17:50:00.000000+00:00')
        acdc = acdcmap(israid=amy.pre, uuid=NONCES[10], regid=ripper.said,
                       attribute=dict(d='', u=NONCES[7], name="Sunspot College",
                                      level="gold"),
                       iseaid=bob.pre, kind=kind)
        assert_acdc_schema_valid(acdc)
        salt = NONCES[15]

        issuedBlinder = Blinder.blind(acdc=acdc.said, state='issued', salt=salt, sn=1)
        revokedBlinder = Blinder.blind(acdc=acdc.said, state='revoked', salt=salt, sn=2)
        assert issuedBlinder.said != revokedBlinder.said
        assert issuedBlinder.uuid != revokedBlinder.uuid

        issued = blindate(regid=ripper.said, prior=ripper.said, blid=issuedBlinder.said,
                          sn=1, stamp='2025-08-01T18:06:10.988921+00:00')
        revoked = blindate(regid=ripper.said, prior=issued.said, blid=revokedBlinder.said,
                           sn=2, stamp='2025-09-01T18:06:10.988921+00:00')

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        def ipexExn(iss, message, admitMessage):
            grant, grantAtc = ipexGrant(
                hab=bob,
                recp=vic.pre,
                message=message,
                acdc=acdc,
                iss=iss,
                anc=ripper,
            )
            grantIms = bytearray(grant.raw)
            grantIms.extend(grantAtc)
            grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                          framed=False,
                                                          processive=False)
            assert grantIms == bytearray()
            assert len(grantResults) == 1
            grantResult = grantResults[0]
            assert grantResult.serder.said == grant.said
            assert grantResult.serder.ked['r'] == "/ipex/grant"
            assert grantResult.serder.ked['p'] == ""
            assert grantResult.serder.ked['i'] == bob.pre
            assert grantResult.serder.ked['a']['i'] == vic.pre
            assert grantResult.serder.ked['a']['acdc'] == acdc.said
            assert grantResult.serder.ked['a']['iss'] == iss.said
            assert grantResult.serder.ked['a']['anc'] == ripper.said
            assert [nest.serder.said for nest in grantResult.nests] == [
                acdc.said, iss.said, ripper.said
            ]
            wire = bytes(grant.raw) + bytes(grantAtc)

            grantDispatch = bytearray(grant.raw)
            grantDispatch.extend(grantAtc)
            Parser(version=Vrsn_2_0).parse(ims=grantDispatch, framed=False, exc=exc)
            assert grantDispatch == bytearray()
            storedGrant = hby.db.exns.get(keys=(grant.said,))
            assert storedGrant is not None
            assert storedGrant.ked['a']['acdc'] == acdc.said
            assert storedGrant.ked['a']['iss'] == iss.said
            assert storedGrant.ked['a']['anc'] == ripper.said

            admit, admitAtc = ipexAdmit(
                hab=vic,
                message=admitMessage,
                grant=grant,
            )
            admitIms = bytearray(admit.raw)
            admitIms.extend(admitAtc)
            Parser(version=Vrsn_2_0).parse(ims=admitIms, framed=False, exc=exc)
            assert admitIms == bytearray()
            storedAdmit = hby.db.exns.get(keys=(admit.said,))
            assert storedAdmit is not None
            assert storedAdmit.ked['p'] == grant.said

            return grantResult, wire

        # Bob presents the issuance-state snapshot to Vic. The IPEX grant carries
        # the blinded registry update, but not the per-event nonce Vic needs to
        # interpret it; that nonce is modeled here as the separately-shared
        # issuedBlinder.uuid, just as in the JSON example.
        issuedGrantResult, issuedWire = ipexExn(
            issued,
            "Current registry snapshot",
            "Received current registry snapshot",
        )
        carriedIssued = issuedGrantResult.nests[1].serder
        assert carriedIssued.said == issued.said
        assert carriedIssued.sad['b'] == issuedBlinder.said
        assert b'issued' not in carriedIssued.raw
        assert b'revoked' not in carriedIssued.raw
        assert issuedBlinder.uuid.encode() not in issuedWire
        assert revokedBlinder.uuid.encode() not in issuedWire

        verifierAtIssuance = Blinder.unblind(said=carriedIssued.sad['b'],
                                             uuid=issuedBlinder.uuid,
                                             acdc=acdc.said, states=states)
        assert verifierAtIssuance is not None
        assert verifierAtIssuance.state == 'issued'
        assert verifierAtIssuance.acdc == acdc.said

        # Later the holder sends a new blinded registry snapshot. A verifier that
        # remembers only the earlier nonce still cannot read this later event.
        revokedGrantResult, revokedWire = ipexExn(
            revoked,
            "Later registry snapshot",
            "Received later registry snapshot",
        )
        carriedRevoked = revokedGrantResult.nests[1].serder
        assert carriedRevoked.said == revoked.said
        assert carriedRevoked.sad['b'] == revokedBlinder.said
        assert b'issued' not in carriedRevoked.raw
        assert b'revoked' not in carriedRevoked.raw
        assert issuedBlinder.uuid.encode() not in revokedWire
        assert revokedBlinder.uuid.encode() not in revokedWire

        laterPeek = Blinder.unblind(said=carriedRevoked.sad['b'],
                                    uuid=issuedBlinder.uuid,
                                    acdc=acdc.said, states=states)
        assert laterPeek is None

        earlierPeek = Blinder.unblind(said=carriedIssued.sad['b'],
                                      uuid=revokedBlinder.uuid,
                                      acdc=acdc.said, states=states)
        assert earlierPeek is None

        holderAtRevocation = Blinder.unblind(said=carriedRevoked.sad['b'],
                                             acdc=acdc.said,
                                             states=states, salt=salt, sn=2)
        assert holderAtRevocation is not None
        assert holderAtRevocation.state == 'revoked'
        assert holderAtRevocation.acdc == acdc.said

        assert [(item["r"], item["m"]) for item in recorder.items] == [
            ("/exn/ipex/grant", "Current registry snapshot"),
            ("/exn/ipex/admit", "Received current registry snapshot"),
            ("/exn/ipex/grant", "Later registry snapshot"),
            ("/exn/ipex/admit", "Received later registry snapshot"),
        ]


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_examples_serialization_kinds(kind):
    """The example flows hold across every serialization kind, not just JSON.

    The detailed examples above pin canonical JSON values for readability. This
    check exercises the same registry-lifecycle, selective-disclosure, and
    compaction flows over CESR (the native KERI wire format) and CBOR/MGPK as
    well, asserting the
    behavioral invariants without pinning per-kind SAIDs -- so a serialization
    regression on a non-JSON wire path cannot pass silently.
    """
    # Registry-lifecycle builders: create the registry, construct an ACDC bound
    # to it (rd), construct a blindable update (bup), then unblind to check state.
    ripper = regcept(israid=AMY, uuid=NONCES[0],
                     stamp='2025-07-04T17:50:00.000000+00:00', kind=kind)
    assert ripper.ilk == Ilks.rip and ripper.kind == kind
    regid = ripper.said

    acdc = acdcmap(israid=AMY, uuid=NONCES[10], regid=regid,
                   attribute=dict(d='', u=NONCES[7], name="Sunspot College",
                                  level="gold"),
                   iseaid=BOB, kind=kind)
    assert acdc.sad['rd'] == regid                # ACDC bound to the derived registry
    assert_acdc_schema_valid(acdc)                # schema validation holds on every kind

    salt = NONCES[15]
    blinder = Blinder.blind(acdc=acdc.said, state='issued', salt=salt, sn=1)
    issued = blindate(regid=regid, prior=regid, blid=blinder.said, sn=1,
                      stamp='2025-08-01T18:06:10.988921+00:00', kind=kind)
    assert issued.ilk == Ilks.bup and issued.sad['b'] == blinder.said
    assert b'issued' not in issued.raw            # state stays blinded on every kind

    unblinder = Blinder.unblind(said=blinder.said, acdc=acdc.said,
                                states=['issued', 'revoked'], salt=salt, sn=1)
    assert unblinder is not None and unblinder.state == 'issued'

    # Selective disclosure over an aggregate section verifies on every kind.
    aggor = Aggor(ael=["",
                       dict(d='', u=NONCES[2], i=BOB),
                       dict(d='', u=NONCES[3], score=96)],
                  makify=True, kind=kind)
    # The issuer references the made aggregate by its AGID from an 'acg' ACDC.
    acg = acdcagg(israid=AMY, uuid=NONCES[10], regid=regid,
                  aggregate=aggor.agid, kind=kind)
    assert acg.ilk == Ilks.acg and acg.sad['A'] == aggor.agid
    assert_acdc_schema_valid(acg)                 # acg schema validation on every kind

    disclosed, k = aggor.disclose(indices=[1])
    assert k == kind
    assert isinstance(disclosed[1], dict) and isinstance(disclosed[2], str)
    assert Aggor.verifyDisclosure(disclosed, kind=kind)

    # Partial disclosure via compaction is serialization-sensitive too -- the
    # top-level ACDC SAID is a digest of the message in its own kind -- so
    # exercise it on every kind: the compact and expanded forms of one ACDC must
    # share the same SAID, with sections carried as SAIDs vs inline respectively.
    attrMad = dict(d='', u=NONCES[7], name="Bob Student", gpa=4)
    ruleMad = dict(d='', l="terms")
    expanded = acdcmap(israid=AMY, uuid=NONCES[13], regid=regid,
                       attribute=dict(attrMad), iseaid=BOB, rule=dict(ruleMad),
                       compactify=False, kind=kind)
    compact = acdcmap(israid=AMY, uuid=NONCES[13], regid=regid,
                      attribute=dict(attrMad), iseaid=BOB, rule=dict(ruleMad),
                      compactify=True, kind=kind)
    assert expanded.said == compact.said         # same commitment, compact or expanded
    assert isinstance(expanded.sad['a'], dict)   # sections carried inline...
    assert isinstance(compact.sad['a'], str)     # ...vs. as SAIDs
    schema = assert_acdc_schema_valid(expanded)  # both forms conform on every kind
    assert_acdc_schema_valid(compact, schema=schema)


if __name__ == "__main__":
    test_registry_issuance_lifecycle_JSON()
    test_selective_disclosure_aggregate_JSON()
    test_partial_disclosure_compaction_JSON()
    test_blindable_registry_correlation_minimizing_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_examples_serialization_kinds(_kind)
