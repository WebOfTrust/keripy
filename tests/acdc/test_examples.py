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

from keri import Vrsn_2_0, Kinds, Protocols, Ilks
from keri.core import Noncer, Blinder, GenDex, Aggor, Compactor, Diger, DigDex
from keri.acdc import regcept, blindate, acdcmap, acdcagg


# Spec-aligned example fixtures (see test_acdc_examples_setup in the spec tests).
AMY = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"    # issuer AID
BOB = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"    # issuee AID
RAWS = [b'acdcspecworkraw' + b'%0x' % (i, ) for i in range(16)]
NONCES = [Noncer(raw=raw).qb64 for raw in RAWS]
REG_AMY = "EOMMCyztOvg970W0dZVJT2JIwlQ22DSeY7wtxNBBtpmX"  # Amy's registry (derived in example 1)


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
    ripper = regcept(issuer=AMY, uuid=NONCES[0], stamp=regStamp)
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
    acdc = acdcmap(issuer=AMY, uuid=NONCES[10], regid=regid,
                   attribute=attribute, issuee=BOB)
    assert acdc.ilk == Ilks.acm
    assert acdc.sad['i'] == AMY            # issued by Amy
    assert acdc.sad['rd'] == regid         # bound to Amy's registry
    assert acdc.sad['a']['i'] == BOB       # issued to Bob
    acdcSaid = acdc.said
    assert acdcSaid == "EKqjwYRfEGl5rLu9TAN277K0fUUO87c0iIfMMRWdoTcp"

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
    acdc = acdcagg(issuer=AMY, uuid=NONCES[10], regid=REG_AMY,
                   aggregate=aggor.ael, kind=kind)
    acdcCompact = acdcagg(issuer=AMY, uuid=NONCES[10], regid=REG_AMY,
                          aggregate=agid, kind=kind)
    assert acdc.ilk == Ilks.acg
    assert acdc.said == acdcCompact.said        # same SAID, compact or expanded

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
    expanded = acdcmap(issuer=AMY, uuid=NONCES[13], regid=REG_AMY,
                       attribute=dict(attrMad), issuee=BOB, rule=dict(ruleMad),
                       compactify=False, kind=kind)
    compact = acdcmap(issuer=AMY, uuid=NONCES[13], regid=REG_AMY,
                      attribute=dict(attrMad), issuee=BOB, rule=dict(ruleMad),
                      compactify=True, kind=kind)

    assert compact.sad['u'] == NONCES[13]             # private ACDC (has a nonce)
    assert expanded.said == compact.said             # same commitment either way
    assert compact.said == "EDlaFELjgpoRQ7zPh0DISKR1n5ku1UZWr_my6bLF8Bjg"
    assert isinstance(expanded.sad['a'], dict)       # sections inline
    assert isinstance(compact.sad['a'], str)         # sections as SAIDs
    assert compact.sad['a'] == "ED1pc3B7apjLEMgWnI08EZky8TU5SfqpARRQ5mr_z9vh"
    assert compact.sad['r'] == "ECIxF7cojMJIXm-SKGR1w8Bj8N1v0637trHKYT9TWqd9"

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
    acdc = acdcmap(issuer=AMY, uuid=NONCES[10], regid=REG_AMY,
                   attribute=dict(d='', u=NONCES[7], name="Sunspot College",
                                  level="gold"),
                   issuee=BOB, kind=kind)
    acdcSaid = acdc.said
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
    ripper = regcept(issuer=AMY, uuid=NONCES[0],
                     stamp='2025-07-04T17:50:00.000000+00:00', kind=kind)
    assert ripper.ilk == Ilks.rip and ripper.kind == kind
    regid = ripper.said

    acdc = acdcmap(issuer=AMY, uuid=NONCES[10], regid=regid,
                   attribute=dict(d='', u=NONCES[7], name="Sunspot College",
                                  level="gold"),
                   issuee=BOB, kind=kind)
    assert acdc.sad['rd'] == regid                # ACDC bound to the derived registry

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
    acg = acdcagg(issuer=AMY, uuid=NONCES[10], regid=regid,
                  aggregate=aggor.agid, kind=kind)
    assert acg.ilk == Ilks.acg and acg.sad['A'] == aggor.agid

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
    expanded = acdcmap(issuer=AMY, uuid=NONCES[13], regid=regid,
                       attribute=dict(attrMad), issuee=BOB, rule=dict(ruleMad),
                       compactify=False, kind=kind)
    compact = acdcmap(issuer=AMY, uuid=NONCES[13], regid=regid,
                      attribute=dict(attrMad), issuee=BOB, rule=dict(ruleMad),
                      compactify=True, kind=kind)
    assert expanded.said == compact.said         # same commitment, compact or expanded
    assert isinstance(expanded.sad['a'], dict)   # sections carried inline...
    assert isinstance(compact.sad['a'], str)     # ...vs. as SAIDs


if __name__ == "__main__":
    test_registry_issuance_lifecycle_JSON()
    test_selective_disclosure_aggregate_JSON()
    test_partial_disclosure_compaction_JSON()
    test_blindable_registry_correlation_minimizing_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_examples_serialization_kinds(_kind)
