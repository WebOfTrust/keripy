# -*- coding: utf-8 -*-
"""
tests.acdc.test_clc_disclosure module

Worked, working example of *contractually-protected disclosure* -- Chain-Link
Confidentiality (CLC) realized as a credential rather than an out-of-band
agreement. It complements tests/acdc/test_examples.py (registry lifecycle,
graduated/selective disclosure, blindable registries) by adding the pieces that
file does not yet show:

  * a selectively disclosable Aggregate ('A') section as an mDL-style identity
    credential (reveal the photo, withhold the birthdate),
  * edges carrying the I2I operator that bind a rich presentation to a single
    holder,
  * combined disclosure across two source credentials into one bespoke
    presentation ACDC (the spec's "rich presentation" pattern), and
  * a Rules section that negotiates CLC terms -- a Purpose clause, an
    anti-assimilation clause, and a statutory safe-harbor clause -- grounded in
    the ACDC spec's "Bespoke Issued ACDC" example (spec-body.md, the GoodFood
    Restaurant admittance example).

Scenario. Alice, a Utah resident, holds two ACDCs under one holder AID: a SEDI
digital-identity credential (name, date of birth, state-endorsed photo,
residence -- as an aggregate of individually-blinded, selectively-disclosable
elements) and a derived "over-21" credential. To enter a dance club that serves
alcohol she runs CLC as a credential: she (Issuer/Discloser) issues a bespoke
presentation ACDC to the club (Issuee/Disclosee) that edges (I2I) to her two
source credentials and carries the CLC terms in its Rules section, binding the
club before it receives her state-endorsed photo and age proof.

Every ACDC validates against a real, purpose-authored JSON Schema (Draft 2020-12)
from its first commit -- not the generic default -- and the source credentials
are bound to real registries created via regcept, matching the worked examples in
tests/acdc/test_examples.py. Actor AIDs are derived once here from a fixed salt so
the example is reproducible; each is a self-addressing ('E') transferable AID, the
SAID of an inception event that commits to the actor's initial key and a pre-rotated
next key.

A note on why later phases model the IPEX exchange and the club key rotation at
the data-structure level: it is a deliberate scope choice, NOT a gap in keripy.
Full IPEX support is implemented in keri.vc.protocoling (apply/offer/agree/grant/
admit/spurn, version-aware), backed by the registry/TEL machinery in keri.vdr --
but that tooling runs through a live Habery/keystore. keripy is midway through a
deliberate v1->v2 reorganization: ACDC v1 stays in keri.vc, and the new keri.acdc
subpackage is the v2 home, with keri.acdc.messaging filled in (the v2 message
builders these examples use) and the other modules -- keri.acdc.ipexing,
registring, registraring, scheming, ... -- still placeholder stubs awaiting
migration. To keep this example Habery-free and v2-native, the exchange is built
directly from the real v2 exn primitive keri.core.exchange. See the phase
docstrings.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks
from keri.core import (Salter, Noncer, Aggor, Mapper, Diger, Verfer,
                       exchange, messagize, incept, rotate)
from keri.core.coring import MtrDex
from keri.acdc import regcept, acdcmap, acdcagg


# --- Reproducible example actors (see module docstring). ---
# Each actor is a self-addressing ('E') transferable AID: its prefix is the SAID of
# an inception event that commits to the actor's current signing key and a digest of
# its pre-rotated next key. This is the identifier form a real transferable
# participant uses. A bare public key ('D' basic prefix) is a spec-legal corner that
# real deployments skip: self-addressing binds the identifier to its inception, and
# thus to the pre-rotation, rather than leaving which-KEL-is-authoritative to the
# controller's witnesses and each validator's watchers to establish and confirm.
#
# Eight signers derived from one fixed salt: _SIGNERS[0..3] are the four actors'
# current signing keys (State, endorser, Alice, club) and _SIGNERS[4..7] are their
# matching pre-rotated next keys. The club rotates to its next key (_SIGNERS[7]) in
# Phase 4.
_SIGNERS = Salter(raw=b'clcworkexamplsal').signers(count=8, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


STATE, ENDORSER, ALICE, CLUB = (
    _actor_aid(_SIGNERS[i], _SIGNERS[i + 4]) for i in range(4))

# Per-example blinding nonces, derived (not pasted) the same way the sibling
# examples derive theirs, but from a distinct raw prefix so the two files do not
# share nonce values.
RAWS = [b'clcworkexamplra' + b'%0x' % (i,) for i in range(16)]
NONCES = [Noncer(raw=raw).qb64 for raw in RAWS]


def _saidify_schema(mad, kind=Kinds.json):
    """Compute a JSON Schema's SAID and return (said, schema-with-$id).

    keri exposes public builders only for the *default* ACDC schemas
    (acm/acg/actSchemaDefault), not a general "self-address an arbitrary schema"
    helper, so this mirrors the pattern those builders use internally: run the
    schema map through a Mapper that self-addresses the '$id' field. The '$id'
    must be the FIRST field (its position is part of the serialization the SAID
    digests), so callers author the schema with "$id": "" up front. The returned
    schema carries its SAID in '$id'; an edge that points at a credential of this
    schema references that same SAID in its 's' field. Mapper deep-copies its
    input, so the caller's schema map is never mutated.
    """
    mapper = Mapper(mad=mad, makify=True, strict=False, saids={"$id": 'E'},
                    saidive=True, kind=kind)
    return mapper.said, mapper.mad


# ---------------------------------------------------------------------------
# Purpose-authored JSON Schemas (Draft 2020-12), one per credential. Authored as
# maps with "$id" first so _saidify_schema can self-address them per wire kind.
# ---------------------------------------------------------------------------

# sedi-id follows the spec's canonical Aggregate-section schema pattern
# (spec-body.md, "Composed Schema for selectively disclosable Aggregate section"):
# 'A' is oneOf(AGID string, uncompacted array); the array uses items+anyOf over
# the block TYPES (not prefixItems), and each block is oneOf(block SAID, block
# detail). That is what lets ANY subset of blocks be disclosed as detail while the
# rest stay bare SAIDs -- selective disclosure -- without fixing count or order.
def _agg_block(attr, attr_schema, desc):
    """One aggregate-element schema: oneOf(block SAID, block detail)."""
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

# acg is a fixed-field format: it always carries (possibly empty) e and r sections
# even for a pure aggregate credential, so the schema must admit them.
_EMPTY_OR_SECTION = {"oneOf": [{"type": "string"}, {"type": "object"}]}

SEDI_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Identity Credential",
    "description": "State-endorsed SEDI digital-identity credential; attributes "
                   "carried as a selectively disclosable Aggregate section of "
                   "individually-blinded attribute blocks.",
    "credentialType": "SEDI_Identity",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "A"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acg"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (State) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "A": {
            "description": "Selectively disclosable attribute aggregate section",
            "oneOf": [
                {"description": "Aggregate Section AGID", "type": "string"},
                {"description": "Selectively disclosable attribute details",
                 "type": "array", "uniqueItems": True,
                 "items": {"anyOf": [
                     _agg_block("i", {"description": "Issuee AID",
                                      "type": "string"}, "Issuee"),
                     _agg_block("photo", {"description": "State-endorsed photo",
                                          "type": "string"}, "Photo"),
                     _agg_block("dob", {"description": "Date of birth",
                                        "type": "string", "format": "date"}, "DOB"),
                     _agg_block("residence", {"description": "Residence",
                                              "type": "string"}, "Residence"),
                     _agg_block("name", {"description": "Full name",
                                         "type": "string"}, "Name"),
                 ]}},
            ],
        },
        "e": _EMPTY_OR_SECTION,
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}

OVER21_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Over-21 Age Credential",
    "description": "Derived boolean age credential asserting the holder is over 21.",
    "credentialType": "Over21",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (endorser) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "u", "i", "over21"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "i": {"description": "Issuee AID", "type": "string"},
                                  "over21": {"description": "Age assertion",
                                             "type": "boolean"}},
                   "additionalProperties": False}]},
    },
    "additionalProperties": False,
}

# One I2I edge and one Rules clause, as schema fragments reused by the bespoke.
_I2I_EDGE_SCHEMA = {
    "oneOf": [
        {"type": "string"},
        {"type": "object", "required": ["d", "n", "o"],
         "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                        "n": {"description": "Far node (source cred) SAID",
                              "type": "string"},
                        "s": {"description": "Far node schema SAID",
                              "type": "string"},
                        "o": {"description": "Edge operator; I2I = same holder",
                              "const": "I2I"}}}]}
_CLAUSE_SCHEMA = {
    "oneOf": [
        {"type": "string"},
        {"type": "object", "required": ["d", "l"],
         "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                        "l": {"description": "Legal language", "type": "string"}}}]}

BESPOKE_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Bespoke Presentation ACDC",
    "description": "Holder-issued disclosure-specific ACDC: I2I edges to two source "
                   "credentials and a Rules section carrying the CLC terms. Not "
                   "registry-bound (no 'rd'): a one-time presentation is "
                   "deliberately not logged.",
    "credentialType": "BespokePresentation",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "s", "a", "e", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer = Discloser (the holder) AID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object",
                   "required": ["d", "u", "i", "date", "place", "over21"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "i": {"description": "Issuee = Disclosee",
                                        "type": "string"},
                                  "date": {"type": "string"},
                                  "place": {"type": "string"},
                                  "over21": {"type": "boolean"}},
                   "additionalProperties": False}]},
        "e": {"description": "Edge Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "identity", "age"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "identity": _I2I_EDGE_SCHEMA,
                                  "age": _I2I_EDGE_SCHEMA},
                   "additionalProperties": False}]},
        "r": {"description": "Rule Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object",
                   "required": ["d", "Purpose", "Assimilation", "SafeHarbor"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "Purpose": _CLAUSE_SCHEMA,
                                  "Assimilation": _CLAUSE_SCHEMA,
                                  "SafeHarbor": _CLAUSE_SCHEMA},
                   "additionalProperties": False}]},
    },
    "additionalProperties": False,
}


# A published SEDI governance-framework provision, referenced BY SAID (not
# authored here) from the SafeHarbor rule -- incorporation by reference, so a
# verifier can pre-authorize the standard clause. This is a PLACEHOLDER SAID (a
# bare digest of a description string), standing in for the SAID a real deployment
# would compute over the governance document's canonical serialization.
GOV_PROVISION_SAID = Diger(
    ser=b'SEDI governance framework safe-harbor provision v1').qb64


# The three CLC Rules clauses, adapted from the ACDC spec's "Bespoke Issued ACDC"
# example (Purpose + Assimilation, verbatim-then-specialised) plus a new SafeHarbor
# clause that makes this SEDI rather than generic CLC. Kept as module constants so
# both the Phase 2 construction and the Phase 3 exchange assert the identical text.
PURPOSE_TEXT = ("One-time verification by the Verifier that the Discloser is over "
                "21 and matches the state-endorsed photo, for the sole purpose of "
                "admittance to place on date as specified in the Attribute section.")
ASSIMILATION_TEXT = (
    "Verifier agrees to NOT assimilate, aggregate, correlate, sell, or otherwise "
    "use in combination with other information available to the Verifier -- "
    "including information collected by independent means before, during, or after "
    "this presentation -- the information referenced by this container or any "
    "containers recursively referenced by the edge section, for any purpose other "
    "than that expressly permitted by the Purpose clause.")
SAFE_HARBOR_TEXT = (
    f"This disclosure is made under SEDI governance-framework provision "
    f"{GOV_PROVISION_SAID}. By accepting these terms (a signed IPEX agree "
    f"referencing this container's SAID), the Verifier elects the safe harbor "
    f"therein against liability under Utah Code 63A-20-701, conditioned on "
    f"compliance with the Purpose and Assimilation clauses. Breach forfeits the "
    f"safe harbor and constitutes evidence under 63A-20-801.")

# Registry inception timestamps (the State and endorser each stand up a registry).
REG_STATE_STAMP = "2026-01-05T12:00:00.000000+00:00"
REG_ENDORSER_STAMP = "2026-01-06T12:00:00.000000+00:00"

# A note on the pinned SAID values asserted throughout this file (credential,
# registry, and exn SAIDs): every one is DERIVED here, not authored -- the tests
# construct the object and pin the SAID it computes. They are stable because the
# inputs are fixed (the salt-derived actor AIDs, the NONCES, these timestamps, and
# the schema maps above). Change any of those and the dependent SAIDs change too;
# regenerate them by running this file's __main__ and reading the failure diffs, or
# print the .said of the object in question. This is the same "derive, don't paste"
# convention as tests/acdc/test_examples.py.

# Fixed timestamps for the IPEX exn messages. exchange() defaults the 'dt' field
# to the current time, which would make the messages (and their SAIDs) vary run to
# run; pinning stamps keeps the worked example reproducible and xdist-safe.
APPLY_STAMP = "2026-07-14T21:15:00.000000+00:00"
OFFER_STAMP = "2026-07-14T21:16:00.000000+00:00"
AGREE_STAMP = "2026-07-14T21:17:00.000000+00:00"
GRANT_STAMP = "2026-07-14T21:18:00.000000+00:00"
ADMIT_STAMP = "2026-07-14T21:19:00.000000+00:00"


def assert_acdc_schema_valid(acdc, schema=None):
    """Validate a worked-example ACDC against its JSON Schema (Draft 2020-12).

    Identical in intent to the helper in tests/acdc/test_examples.py: it proves
    the schema is itself well-formed and that the ACDC instance conforms to the
    schema it commits to in its own 's' section. When the schema section has been
    compacted to a bare SAID string, pass the schema explicitly.
    """
    if schema is None:
        schema = acdc.sad['s']
        if not isinstance(schema, dict):
            raise ValueError("schema section is compacted to a SAID; pass "
                             "schema= (e.g. the expanded ACDC's sad['s'])")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(acdc.sad)
    return schema


# --- Aggregate element indices for the sedi-id credential (a[0] is the AGID). ---
# These serve double duty: as positions in the aggregate list AND as the NONCES
# slot for each element's blinding nonce (so sedi elements own NONCES[1..5]).
# Other credentials/sections use disjoint NONCES slots -- over-21 uses NONCES[14],
# the bespoke edge section NONCES[15] -- so no blinding nonce is ever reused.
SEDI_ISSUEE, SEDI_PHOTO, SEDI_DOB, SEDI_RESIDENCE, SEDI_NAME = 1, 2, 3, 4, 5


def _sedi_ael():
    """Alice's sedi-id aggregate element list (a fresh list each call).

    Element 0 is the AGID placeholder; elements 1..5 are each an individually-
    blinded (own 'u'), self-addressing (own 'd') attribute block. The issuee
    binding (i = ALICE) is itself an aggregate element -- the convention for
    aggregate ACDCs, which carry no top-level a.i -- so it can be disclosed and
    checked alongside the attributes it accompanies.
    """
    return ['',
            dict(d='', u=NONCES[SEDI_ISSUEE], i=ALICE),
            dict(d='', u=NONCES[SEDI_PHOTO], photo="<state-endorsed-photo-bytes>"),
            dict(d='', u=NONCES[SEDI_DOB], dob="2000-03-15"),
            dict(d='', u=NONCES[SEDI_RESIDENCE], residence="Salt Lake City UT"),
            dict(d='', u=NONCES[SEDI_NAME], name="Alice Anders")]


def _source_credentials(kind):
    """Build Alice's two source credentials, registry-bound and schema-validated.

    sedi-id is an aggregate ('acg') credential carrying the mDL-style, selectively
    disclosable identity attributes; over-21 is a simple attribute ('acm') boolean
    age credential. Both are bound to real registries created here via regcept, and
    both validate against their purpose-authored schemas. Returns
    (sedi, over21, aggor) -- the Aggor is returned so callers can perform selective
    disclosure over the same aggregate.
    """
    # Real registries: the State and the endorser each stand up a registry (rip
    # event); the credential's 'rd' binds it to that registry.
    regState = regcept(israid=STATE, uuid=NONCES[12], stamp=REG_STATE_STAMP, kind=kind)
    regEndorser = regcept(israid=ENDORSER, uuid=NONCES[13],
                          stamp=REG_ENDORSER_STAMP, kind=kind)

    _, sediSchema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    _, over21Schema = _saidify_schema(dict(OVER21_SCHEMA_MAD), kind=kind)

    aggor = Aggor(ael=_sedi_ael(), makify=True, kind=kind)
    sedi = acdcagg(israid=STATE, uuid=NONCES[10], regid=regState.said,
                   schema=sediSchema, aggregate=aggor.ael, kind=kind)
    # DESIGN DECISION (pending Sam, plan-of-record §9.1): over-21 is a pre-derived
    # boolean credential issued by an endorser to Alice (the plan's default), NOT a
    # zero-knowledge predicate proof. An over-21 -> sedi-id edge could only be I2I if
    # over-21's issuer equaled sedi-id's issuee (both Alice) -- i.e. if Alice
    # self-issued over-21; under endorser issuance issuer(over-21) = ENDORSER != ALICE,
    # so the edge is omitted rather than mislabeled I2I. The load-bearing I2I edges
    # are the bespoke ACDC's edges to both source creds (Phase 2), where Alice issues.
    over21 = acdcmap(israid=ENDORSER, uuid=NONCES[11], regid=regEndorser.said,
                     schema=over21Schema,
                     attribute=dict(d='', u=NONCES[14], i=ALICE, over21=True), kind=kind)
    return sedi, over21, aggor


def _photo_disclosure(aggor):
    """Alice's selective disclosure of sedi-id: reveal issuee + photo, withhold DOB.

    Returns the disclosure list produced by Aggor: the issuee and photo elements in
    full, the rest (dob, residence, name) as bare SAIDs. The issuee element is
    revealed because the club must check the I2I binding (issuee == Alice); the
    photo is the state-endorsed image; the birthdate never crosses the wire. The
    disclosure still verifies against the committed AGID.
    """
    disclosed, _ = aggor.disclose(indices=[SEDI_ISSUEE, SEDI_PHOTO])
    return disclosed


def _bespoke_rules():
    """The bespoke ACDC's Rules section: Purpose + Assimilation + SafeHarbor.

    Mirrors the spec's bespoke-ACDC rule shape -- a top-level block plus one named
    sub-block per clause, each an object carrying its own SAID ('d') and legal
    prose ('l'). No blinding nonce: the terms are meant to be read, not hidden.
    """
    return dict(
        d='',
        Purpose=dict(d='', l=PURPOSE_TEXT),
        Assimilation=dict(d='', l=ASSIMILATION_TEXT),
        SafeHarbor=dict(d='', l=SAFE_HARBOR_TEXT),
    )


def _bespoke_edges(sedi, over21):
    """The bespoke ACDC's edge section: I2I edges to the two source credentials.

    Each edge names the target credential's SAID ('n') and schema ('s', read from
    the target's own schema section) and sets the operator ('o') to I2I.
    I2I ("issuer-to-issuee") is the same-holder constraint: it holds only when the
    issuer of the ACDC carrying the edge is the issuee of the credential the edge
    points to. Since Alice issues the bespoke ACDC and is the issuee of both source
    credentials, I2I is exactly right -- it is what cryptographically distinguishes
    "Alice presenting her own credentials" from "two credentials that merely happen
    to share an AID," which anyone could arrange.
    """
    return dict(
        d='', u=NONCES[15],
        identity=dict(d='', u=NONCES[6], n=sedi.said, s=sedi.sad['s']['$id'], o='I2I'),
        age=dict(d='', u=NONCES[7], n=over21.said, s=over21.sad['s']['$id'], o='I2I'),
    )


def _bespoke_presentation(sedi, over21, kind, compactify=False, rule=None):
    """Build Alice's bespoke presentation ACDC to the club (helper for Phase 2+).

    Issuer = Alice (Discloser), Issuee = the club (Disclosee). Attributes mirror
    the spec's restaurant example -- date and place of admittance -- plus the
    over-21 assertion the club is checking. Edges are I2I to both source creds; the
    Rules section carries the three CLC clauses (override via rule= to show that
    changing the terms changes the ACDC's identity). It is deliberately NOT
    registry-bound (no 'rd'), matching the spec's bespoke example and the plan's
    "no correlatable log" intent. Returns the SerderACDC, most-compact when
    compactify=True (same SAID either way).

    DESIGN DECISION (pending Sam, plan-of-record §9.2): the state-endorsed photo is
    NOT copied into these attributes; it stays the single source of truth in
    sedi-id, reached via the I2I edge and disclosed by selective disclosure of just
    that element (see _photo_disclosure). So no photo bytes are duplicated here.
    """
    _, schema = _saidify_schema(dict(BESPOKE_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[8], i=CLUB,
                     date="2026-07-14T21:30:00.000000+00:00",
                     place="The Alcove Club, 200 S West Temple, Salt Lake City UT",
                     over21=True)
    return acdcmap(israid=ALICE, uuid=NONCES[9], schema=schema, attribute=attribute,
                   edge=_bespoke_edges(sedi, over21),
                   rule=rule if rule is not None else _bespoke_rules(),
                   kind=kind, compactify=compactify)


def test_source_credentials_and_selective_disclosure_JSON():
    """Phase 1: Alice's two source credentials, with selective disclosure.

    Alice holds two ACDCs under one holder AID (ALICE), each bound to a real
    registry and validated against a purpose-authored JSON Schema:

      * sedi-id -- issued by the STATE to Alice as an aggregate ('acg') credential.
        Each identity attribute (issuee, photo, dob, residence, name) is its own
        individually-blinded, self-addressing element of the Aggregate ('A')
        section. This is the mDL-style selective-disclosure mechanism: at
        presentation the holder discloses an arbitrary SUBSET of elements in full
        and leaves the rest as bare SAIDs, and the verifier recomputes the
        aggregate digest (AGID) to confirm the disclosure is authentic.

      * over-21 -- a derived boolean age credential issued to Alice, following the
        plan's default of a pre-derived boolean (not a zero-knowledge predicate),
        so the club never needs the birthdate to confirm the age claim.

    The load-bearing selective-disclosure claim -- prove-age-without-birthdate --
    is asserted here: a disclosure revealing the issuee binding and the state-
    endorsed photo while withholding the date of birth still verifies against the
    committed AGID, and the birthdate value is provably absent from it.

    The purpose-authored schemas have teeth: this test also confirms the over-21
    schema rejects a non-boolean age assertion.
    """
    kind = Kinds.json
    sedi, over21, aggor = _source_credentials(kind)

    # sedi-id: aggregate identity credential, registry-bound, schema-valid.
    assert sedi.ilk == Ilks.acg
    assert sedi.sad['i'] == STATE               # issued by the state
    assert sedi.sad['rd'] == "EHVOJQtOz0B_YAio90qC7t0_YgdiGTHHgX8Lga-Q3_AM"    # bound to the State's registry
    # The issuee binding is an aggregate element (acg has no top-level a.i).
    assert sedi.sad['A'][SEDI_ISSUEE]['i'] == ALICE
    assert sedi.said == "EGv1HMP4xWZYf7GpHUv1yBwSufdVSmpLxCldIc7h9SGY"
    assert_acdc_schema_valid(sedi)

    # over-21: boolean age credential, registry-bound, schema-valid.
    assert over21.sad['i'] == ENDORSER          # issued by the endorser
    assert over21.sad['rd'] == "EJ008F-JLQ3k2tacTL8Xv5WEOYHaIvW7lfeGAbKPSDTf"
    assert over21.sad['a']['i'] == ALICE        # to the same holder
    assert over21.sad['a']['over21'] is True
    assert over21.said == "EG7L78EoESOI6RKazj9wEgG-MA3-0SlkkndAksXiqXAm"
    over21Schema = assert_acdc_schema_valid(over21)

    # Schema teeth: a non-boolean age assertion is rejected.
    bad = dict(over21.sad, a=dict(over21.sad['a'], over21="yes"))
    with pytest.raises(ValidationError):
        Draft202012Validator(over21Schema).validate(bad)

    # --- Selective disclosure of sedi-id: reveal issuee + photo, withhold DOB. ---
    disclosed = _photo_disclosure(aggor)
    assert disclosed[0] == aggor.agid                       # AGID anchor
    assert isinstance(disclosed[SEDI_ISSUEE], dict)         # issuee revealed
    assert disclosed[SEDI_ISSUEE]['i'] == ALICE
    assert isinstance(disclosed[SEDI_PHOTO], dict)          # photo revealed
    assert disclosed[SEDI_PHOTO]['photo'] == "<state-endorsed-photo-bytes>"
    assert isinstance(disclosed[SEDI_DOB], str)             # birthdate withheld (SAID)
    assert isinstance(disclosed[SEDI_RESIDENCE], str)       # residence withheld
    assert isinstance(disclosed[SEDI_NAME], str)            # name withheld

    # Privacy invariant: the withheld birthdate value never appears on the wire --
    # dob/residence/name travel only as bare block SAIDs. Those SAIDs are
    # computationally unlinkable to their values because each element block carries
    # its own blinding nonce ('u'); without it a verifier cannot brute-force the
    # (low-entropy) value from the SAID.
    assert "2000-03-15" not in json.dumps(disclosed)

    # The verifier recomputes the AGID over the mixed disclosure and confirms it.
    assert Aggor.verifyDisclosure(disclosed, kind=kind)
    # Tamper evidence: altering a revealed value breaks AGID verification.
    tampered = list(disclosed)
    tampered[SEDI_ISSUEE] = dict(disclosed[SEDI_ISSUEE], i=CLUB)
    assert not Aggor.verifyDisclosure(tampered, kind=kind)


def test_bespoke_presentation_acdc_JSON():
    """Phase 2: Alice issues a bespoke presentation ACDC to the club.

    This is Chain-Link Confidentiality realized as a credential (spec-body.md,
    "Disclosure-specific (Bespoke) Issued ACDCs"). Alice -- the Discloser -- issues
    her own purpose-built ACDC *to the club* (the Disclosee): Issuer = Discloser,
    Issuee = Disclosee. It combines two source credentials into one rich
    presentation via edges, and carries the CLC terms in its Rules section, so the
    terms bind the club as a named party before any private data is disclosed.

    Two things earn this example's keep, and both are asserted structurally here.
    The v2 acdc subpackage's message builders (keri.acdc.messaging) construct and
    SAID-commit edge/rule sections but do not themselves interpret edge operators.
    The v1 runtime verifier keri.vdr.verifying.verifyChain enforces I2I, but only
    via the far node's TOP-LEVEL attribute issuee (creder.attrib['i']); for an
    aggregate ('acg') far node like sedi-id -- whose issuee is an aggregate element,
    with no top-level a.i -- verifyChain cannot perform the check at all. So no
    shipped verifier currently enforces the same-holder binding for this edge; the
    test asserts the spec-intended binding a v2-native, aggregate-aware verifier
    would enforce, playing that structural check directly:

      1. The I2I same-holder binding: the bespoke ACDC's issuer equals the issuee
         of each source credential its edges point to. sedi-id's issuee is an
         aggregate element; over-21's is its attribute issuee.
      2. The three Rules clauses are present with their exact agreed text.

    The purpose-authored bespoke schema pins the edge operator to const "I2I", so
    the schema itself ENFORCES the same-holder binding; this test confirms it
    rejects any other operator. Finally, because the ACDC is private (top-level
    nonce), its most-compact and expanded forms share one SAID.
    """
    kind = Kinds.json
    sedi, over21, _ = _source_credentials(kind)

    bespoke = _bespoke_presentation(sedi, over21, kind)

    assert bespoke.ilk == Ilks.acm
    assert bespoke.sad['i'] == ALICE           # Alice is the Issuer (Discloser)
    assert bespoke.sad['a']['i'] == CLUB       # the club is the Issuee (Disclosee)
    assert bespoke.sad['a']['over21'] is True
    assert 'rd' not in bespoke.sad             # deliberately not registry-bound
    assert bespoke.said == "EKR4iCZ48DPaSnR2c-L3PhfcpO37kBMHh7q6xpALVGzW"

    # (1) I2I same-holder binding. The v2 path does not enforce operators, so we
    # assert the constraint the I2I operator stands for: the bespoke ACDC's issuer
    # is the issuee of every source credential its edges reference.
    assert bespoke.sad['e']['identity']['o'] == 'I2I'
    assert bespoke.sad['e']['age']['o'] == 'I2I'
    assert bespoke.sad['e']['identity']['n'] == sedi.said     # edge -> sedi-id
    assert bespoke.sad['e']['age']['n'] == over21.said        # edge -> over-21
    # issuer(bespoke) == issuee(sedi, an aggregate element) == issuee(over21)
    assert bespoke.sad['i'] == sedi.sad['A'][SEDI_ISSUEE]['i']
    assert bespoke.sad['i'] == over21.sad['a']['i']

    # (2) The three Rules clauses are present with their exact agreed text.
    assert bespoke.sad['r']['Purpose']['l'] == PURPOSE_TEXT
    assert bespoke.sad['r']['Assimilation']['l'] == ASSIMILATION_TEXT
    assert bespoke.sad['r']['SafeHarbor']['l'] == SAFE_HARBOR_TEXT
    # The SafeHarbor clause incorporates the governance provision by SAID.
    assert GOV_PROVISION_SAID in bespoke.sad['r']['SafeHarbor']['l']

    # The private ACDC's compact and expanded forms share one SAID.
    compact = _bespoke_presentation(sedi, over21, kind, compactify=True)
    assert compact.said == bespoke.said
    assert isinstance(bespoke.sad['e'], dict)     # sections inline...
    assert isinstance(compact.sad['e'], str)      # ...vs. collapsed to SAIDs

    # Schema-valid in both forms; the schema ENFORCES the I2I operator.
    schema = assert_acdc_schema_valid(bespoke)
    assert_acdc_schema_valid(compact, schema=schema)
    badEdge = json.loads(json.dumps(bespoke.sad))
    badEdge['e']['identity']['o'] = 'NI2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(badEdge)


def test_gated_ipex_exchange_JSON():
    """Phase 3: the gated IPEX exchange -- terms bind before any PII is disclosed.

    The presentation runs as an IPEX exchange, apply -> offer -> agree -> grant ->
    admit, and the whole point is the ORDER: the club commits to Alice's terms
    (via a signed agree) *before* Alice discloses her state-endorsed photo.

    keripy DOES implement IPEX end to end -- keri.vc.protocoling provides
    apply/offer/agree/grant/admit/spurn handlers and exn builders (version-aware),
    backed by the registry/TEL machinery in keri.vdr. That tooling runs through a
    live Habery/keystore, though, and its v2-native home, keri.acdc.ipexing, is
    still a placeholder in keripy's in-progress v1->v2 reorganization. So to keep
    this worked example Habery-free and v2-native, it models the exchange at the
    data-structure level -- but with real machinery, not hand-waving: each message
    is a genuine v2 'exn' peer message built by keri.core.exchange (sender,
    receiver, route, prior, payload), and the club's acceptance carries a real
    Ed25519 signature made with keri.core.Signer and checked with Verfer.verify.
    The reductions are (a) no Habery/keystore stands behind the AIDs, and (b) the
    club's "key state" is modeled as its establishing Verfer rather than resolved
    from a live KEL (Phase 4 shows why capturing it matters).

    Four properties are asserted, each a design point from the plan:

      1. The offer carries only SAIDs and terms -- NO PII (no name, photo, or
         birthdate). Alice commits to the bespoke ACDC (and its two source creds)
         by SAID, so the club learns what it is agreeing to before receiving any
         attribute values. (Alice's AID is still visible -- she is the offer's
         sender -- so "no PII" means no attribute values, not sender anonymity.
         Note too that the offer commits to the real, private bespoke SAID rather
         than the spec's metadata-ACDC variant, a deliberate scope reduction per
         plan-of-record §6; the SAIDs leak no PII because the ACDCs are private, but
         the metadata variant is the spec's canonical pre-agreement artifact and
         additionally decorrelates across presentations.)
      2. The agree binds the OFFER's SAID (its 'p' field), not the credential
         SAIDs. Because the offer commits to {cred SAIDs + governance + terms},
         referencing the offer transitively binds the club to all of it.
      3. The signed agree verifies against the club's captured key state -- a
         non-repudiable acceptance, signed but (deliberately) not KEL-anchored, so
         the club keeps no public, correlatable log of every patron it admits.
      4. Disclosure happens ONLY after a valid agree. A forged signature or an
         agree that fails to bind the offer unlocks nothing; the state-endorsed
         photo appears on the wire only inside the grant that a valid agree gates.

    Mapping onto the shipped tooling. Each step here corresponds to a real handler
    in keri.vc.protocoling that a production (Habery-backed) agent would call
    instead of building the exn by hand:

        apply  -> ipexApplyExn      offer -> ipexOfferExn
        agree  -> ipexAgreeExn      grant -> ipexGrantExn
        admit  -> ipexAdmitExn      (decline -> ipexSpurnExn)

    Those helpers sign via hab.endorse (which wraps keri.core.messagize, the same
    attachment path used for the agree below), and a production grant additionally
    carries the ACDC's TEL issuance event (iss) and its KEL anchoring event (anc).
    This example omits the Habery, registry and KEL anchoring on purpose, to keep
    the focus on the exchange's structure and its ordering guarantee.
    """
    kind = Kinds.json
    sedi, over21, aggor = _source_credentials(kind)
    bespoke = _bespoke_presentation(sedi, over21, kind)
    # The grant carries the bespoke ACDC in most-compact form (schema as a SAID):
    # the club already received the terms in the offer, and compact form keeps the
    # grant small. The revealed photo rides alongside as a selective disclosure.
    bespokeCompact = _bespoke_presentation(sedi, over21, kind, compactify=True)
    clubSigner = _SIGNERS[3]              # the club's establishing signing key

    # The exn peer messages are serialized as JSON here so the privacy invariants
    # below (no PII on the wire) can be checked as plaintext structural facts, the
    # same way the ACDC examples assert them; the CESR wire form base64-encodes the
    # payload, which would make a substring check meaningless.

    # 1. apply (club -> Alice): the challenge -- which schemas to use and the SEDI
    # governance framework under which the club proposes to interact. No creds yet.
    apply = exchange(sender=CLUB, receiver=ALICE, route="/ipex/apply",
                     attributes=dict(m="Prove over-21 and show the state-endorsed photo.",
                                     s=[sedi.sad['s']['$id'], over21.sad['s']['$id']],
                                     g=GOV_PROVISION_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['t'] == Ilks.exn
    assert apply.sad['r'] == "/ipex/apply"
    assert apply.sad['i'] == CLUB and apply.sad['ri'] == ALICE
    assert apply.said == "EHaKgaup1e_R0V9ToYj0VI2pOcnzuSX07cEsSkQnAe_J"

    # 2. offer (Alice -> club): "I'll prove over-21 and show my photo if you accept
    # these terms." Carries only the SAIDs of the bespoke ACDC and its sources plus
    # the terms and the governance ref -- no PII -- and binds the apply it answers.
    offer = exchange(sender=ALICE, receiver=CLUB, route="/ipex/offer",
                     prior=apply.said,
                     attributes=dict(acdc=bespoke.said,
                                     credentials=[sedi.said, over21.said],
                                     governance=GOV_PROVISION_SAID,
                                     terms=_bespoke_rules()),
                     stamp=OFFER_STAMP, kind=kind)
    assert offer.sad['p'] == apply.said                 # answers the apply
    assert bespoke.said.encode() in offer.raw           # commits to the bespoke by SAID
    assert offer.said == "EJWA0EwRhLRCXJgNumeoOsBDlmFqKk6VDD5uGxTQQdOy"
    # (property 1) the offer leaks no PII: not Alice's name, photo, or birthdate.
    assert b"Alice Anders" not in offer.raw
    assert b"<state-endorsed-photo-bytes>" not in offer.raw
    assert b"2000-03-15" not in offer.raw

    # 3. agree (club -> Alice): acceptance. It binds the OFFER's SAID (property 2),
    # and the club signs it (property 3). It is signed but NOT KEL-anchored.
    agree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said                 # binds the offer SAID
    assert agree.said == "EIoW0Un6pRpmawHvnFrjXWP9YUwcyF0nzWtlkUmPENSE"
    # The club signs the agree, and we assemble the signed wire message the blessed
    # way: messagize() frames the signature as a CESR attachment group (genus code
    # and all). New keripy code should never hand-roll attachment framing -- pass
    # authenticators to messagize(); hab.endorse() is just the Habery-backed wrapper
    # over this same call. An indexed controller signature (index 0) is the right
    # authenticator for the club's single-key AID and needs no keystore here.
    clubSig = clubSigner.sign(ser=agree.raw, index=0)   # indexed controller signature
    signedAgree = messagize(agree, sigers=[clubSig])    # agree.raw + attachment group
    assert bytes(agree.raw) in signedAgree              # the body rides in the signed msg
    # Alice's wallet captures the club's current public key (a simplified stand-in
    # for full key state; Phase 4 uses a real establishment event). Capture the
    # serialized qb64 and reconstruct, so the verify is a genuine round-trip against
    # captured bytes -- not a tautology against the live signer's own verfer object.
    capturedKeyState = Verfer(qb64=clubSigner.verfer.qb64)
    assert capturedKeyState.verify(sig=clubSig.raw, ser=agree.raw)

    # 4. The gate: Alice discloses only when handed a message that (a) IS an agree,
    # (b) binds this offer's SAID, and (c) carries a signature that verifies against
    # the captured key state. Dropping the route check would let a signed spurn that
    # binds the offer unlock disclosure -- a decline must never open the gate.
    def disclose(agreeMsg, sig, keyState):
        isAgree = agreeMsg.sad['r'] == "/ipex/agree"
        bound = agreeMsg.sad['p'] == offer.said
        signed = keyState.verify(sig=sig.raw, ser=agreeMsg.raw)
        if not (isAgree and bound and signed):
            return None                                 # terms not accepted -> nothing
        # The grant carries the bespoke ACDC (compact) and the selective disclosure
        # of sedi-id revealing issuee + photo -- the PII appears only here.
        return exchange(sender=ALICE, receiver=CLUB, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(acdc=bespokeCompact.sad,
                                        photo=_photo_disclosure(aggor)),
                        stamp=GRANT_STAMP, kind=kind)

    # A forged signature (someone else's key over the agree) unlocks nothing.
    forged = _SIGNERS[0].sign(ser=agree.raw, index=0)
    assert disclose(agree, forged, capturedKeyState) is None
    # An agree that does not bind this offer unlocks nothing, even correctly signed.
    strayAgree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                          prior="", stamp=AGREE_STAMP, kind=kind)
    assert disclose(strayAgree, clubSigner.sign(ser=strayAgree.raw, index=0),
                    capturedKeyState) is None
    # A spurn (decline) -- even validly signed and binding the offer -- is not an
    # agree, so the gate stays shut: a decline must never unlock disclosure.
    spurn = exchange(sender=CLUB, receiver=ALICE, route="/ipex/spurn",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert disclose(spurn, clubSigner.sign(ser=spurn.raw, index=0),
                    capturedKeyState) is None

    # The valid, signed, offer-binding agree unlocks the disclosure.
    grant = disclose(agree, clubSig, capturedKeyState)
    assert grant is not None
    assert grant.sad['p'] == agree.said                 # grant follows the agree
    assert grant.said == "EB6JGkVLYAay8tSvbnVqeNaQARsGxq9-z1eWx-73mNoE"
    # (property 4) the state-endorsed photo crosses the wire only now, in the grant.
    assert b"<state-endorsed-photo-bytes>" in grant.raw
    # ...and even the grant never carries the withheld birthdate.
    assert b"2000-03-15" not in grant.raw

    # 5. admit (club -> Alice): acknowledges receipt, closing the exchange.
    admit = exchange(sender=CLUB, receiver=ALICE, route="/ipex/admit",
                     prior=grant.said, stamp=ADMIT_STAMP, kind=kind)
    assert admit.sad['p'] == grant.said
    assert admit.said == "EM3rizh8WpsGF9jv7Hp460bU8xknbmsRH0DuhmexE-of"


def test_accountability_and_terms_follow_data_JSON():
    """Phase 4: the saved agree survives a club key rotation; terms follow the data.

    The agree is signed but deliberately NOT KEL-anchored (Phase 3), so the club
    keeps no public, correlatable log of whom it admits. The cost of that privacy
    is that a bare signature rots: once the club rotates its signing key, a verifier
    who resolves the club's CURRENT key state can no longer verify the old agree. So
    Alice's wallet must capture the club's key state -- its establishing event -- at
    acceptance time, alongside the signed agree. This test proves why.

    It also shows terms follow the data: the CLC terms live in the bespoke ACDC's
    Rules section, which is committed by the ACDC's SAID. Any change to a clause
    yields a different SAID, so a verifier cannot strip or weaken the terms while
    still presenting "the same" credential. (The complementary decline path -- a
    signed spurn does not open the disclosure gate -- is exercised in Phase 3, where
    the gate lives.)

    The club's key state is modeled with real KEL events (keri.core.incept /
    rotate). The club's AID is a self-addressing ('E') transferable identifier, the
    SAID of the inception event reconstructed below, which is the identifier form a
    real transferable participant uses. Because the identifier binds to its inception,
    what a verifier still needs after a rotation is the captured establishing event
    rather than the identifier alone, and that is the point this test makes.
    """
    kind = Kinds.json
    sedi, over21, _ = _source_credentials(kind)
    bespoke = _bespoke_presentation(sedi, over21, kind)

    # Offer and the club's signed agree, as in Phase 3.
    offer = exchange(sender=ALICE, receiver=CLUB, route="/ipex/offer",
                     attributes=dict(acdc=bespoke.said, terms=_bespoke_rules()),
                     stamp=OFFER_STAMP, kind=kind)
    agree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)

    # --- The club's key state at acceptance: its inception event. ---
    # This reconstructs the same self-addressing ('E') inception that defines CLUB
    # (its current key _SIGNERS[3], pre-rotated to _SIGNERS[7]), so icp.pre is the
    # club's AID. clubKey1 is the club's dedicated next key, not any actor's key.
    clubKey0, clubKey1 = _SIGNERS[3], _SIGNERS[7]     # current and next signing keys
    icp = incept(keys=[clubKey0.verfer.qb64],
                 ndigs=[Diger(ser=clubKey1.verfer.qb64b).qb64], code=MtrDex.Blake3_256)
    assert icp.pre == CLUB                            # CLUB is this inception's SAID (E)
    clubSig = clubKey0.sign(ser=agree.raw, index=0)
    # Alice's wallet saves the signed agree AND the club's establishing key state.
    capturedEstEvent = icp

    # --- Later, the club rotates its signing key to key1. ---
    rot = rotate(pre=CLUB, keys=[clubKey1.verfer.qb64], dig=icp.said, sn=1,
                 ndigs=[Diger(ser=b'clc-club-next-key-2').qb64])
    assert rot.sad['k'][0] == clubKey1.verfer.qb64    # current key is now key1

    # A verifier resolving the club's CURRENT key state cannot verify the old agree.
    assert not Verfer(qb64=rot.sad['k'][0]).verify(sig=clubSig.raw, ser=agree.raw)
    # But the CAPTURED establishing key state still verifies it -- which is exactly
    # why the wallet must capture key state alongside a non-KEL-anchored signature.
    assert Verfer(qb64=capturedEstEvent.sad['k'][0]).verify(sig=clubSig.raw,
                                                            ser=agree.raw)

    # --- Terms follow the data: the CLC terms are bound into the bespoke SAID. ---
    tamperedRules = _bespoke_rules()
    tamperedRules['Assimilation']['l'] = "Verifier may do anything it likes."
    weakened = _bespoke_presentation(sedi, over21, kind, rule=tamperedRules)
    assert weakened.said != bespoke.said              # cannot weaken terms silently


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_clc_serialization_kinds(kind):
    """Phases 1-3 invariants hold across every serialization kind, not just JSON.

    The detailed phases above pin canonical JSON SAIDs for readability. This check
    exercises the same flows -- aggregate source creds + selective disclosure, the
    bespoke ACDC with I2I edges and rules, and the gated exchange with a real signed
    agree -- over CESR (the native KERI wire format) and CBOR/MGPK, asserting the
    behavioral invariants without pinning per-kind SAIDs. (The no-PII-on-the-wire
    invariant is JSON-specific and asserted in Phase 3: the CESR wire form
    base64-encodes the payload, so a plaintext substring check does not apply.)
    """
    sedi, over21, aggor = _source_credentials(kind)
    assert sedi.ilk == Ilks.acg and sedi.kind == kind
    assert over21.ilk == Ilks.acm
    assert sedi.sad['rd'] and over21.sad['rd']            # registry-bound on every kind
    assert_acdc_schema_valid(sedi)                        # schema validation holds
    assert_acdc_schema_valid(over21)

    # Selective disclosure: reveal issuee + photo, withhold DOB; verifies via AGID.
    disclosed = _photo_disclosure(aggor)
    assert isinstance(disclosed[SEDI_PHOTO], dict)        # photo revealed
    assert isinstance(disclosed[SEDI_DOB], str)           # birthdate withheld
    assert Aggor.verifyDisclosure(disclosed, kind=kind)

    # Bespoke ACDC: I2I edges + rules, schema-valid, compact == expanded SAID.
    bespoke = _bespoke_presentation(sedi, over21, kind)
    compact = _bespoke_presentation(sedi, over21, kind, compactify=True)
    assert bespoke.said == compact.said
    assert bespoke.sad['e']['identity']['o'] == 'I2I'
    assert bespoke.sad['e']['age']['o'] == 'I2I'
    schema = assert_acdc_schema_valid(bespoke)
    assert_acdc_schema_valid(compact, schema=schema)
    # I2I same-holder binding: issuer(bespoke) == issuee(sedi element) == issuee(over21)
    assert bespoke.sad['i'] == sedi.sad['A'][SEDI_ISSUEE]['i']
    assert bespoke.sad['i'] == over21.sad['a']['i']

    # Gated exchange: the offer binds nothing PII, the agree binds the offer SAID,
    # and the club's signed agree (assembled via messagize) verifies.
    offer = exchange(sender=ALICE, receiver=CLUB, route="/ipex/offer",
                     attributes=dict(acdc=bespoke.said, terms=_bespoke_rules()),
                     stamp=OFFER_STAMP, kind=kind)
    agree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    clubSig = _SIGNERS[3].sign(ser=agree.raw, index=0)
    signedAgree = messagize(agree, sigers=[clubSig])
    assert bytes(agree.raw) in signedAgree
    assert _SIGNERS[3].verfer.verify(sig=clubSig.raw, ser=agree.raw)


if __name__ == "__main__":
    test_source_credentials_and_selective_disclosure_JSON()
    test_bespoke_presentation_acdc_JSON()
    test_gated_ipex_exchange_JSON()
    test_accountability_and_terms_follow_data_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_clc_serialization_kinds(_kind)
