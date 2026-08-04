# -*- coding: utf-8 -*-
"""
tests.acdc.test_cp_disclosure module

Worked, working example of *contractually-protected disclosure* -- Chain-Link
Confidentiality (CLC) realized as a credential rather than an out-of-band
agreement. It complements tests/acdc/test_examples.py (registry lifecycle,
graduated/selective disclosure, blindable registries) by adding the pieces that
file does not yet show:

  * BOTH graduated-disclosure mechanisms, each on the credential it fits: an
    ATTRIBUTIVE identity credential with individually partially-disclosable nested
    blocks (reveal the photo, withhold the birthdate), and an AGGREGATIVE age
    credential -- an array of boolean age-threshold flags (reveal over-21, withhold
    whether she is over 55 or 65),
  * an E1E identity edge chaining the age entitlement back to the core SEDI identity
    credential -- an IDENTITY relation (same subject / issuee, issuer != issuee), NOT
    a delegation, so it is the operator I2I would misapply (keripy discussion #1515) --
    alongside the presentation-time I2I edges that bind a rich presentation to a single
    holder, with the issuee resolved uniformly (SerderACDC.iseaid) whether the far node
    is attributive (a.i) or aggregative (A[1].i),
  * combined disclosure across two source credentials into one bespoke
    presentation ACDC (the spec's "rich presentation" pattern), and
  * a Rules section that negotiates CLC terms -- a Purpose clause, an
    anti-assimilation clause, and a statutory safe-harbor clause -- grounded in
    the ACDC spec's "Bespoke Issued ACDC" example (spec-body.md, the GoodFood
    Restaurant admittance example).

The choice of section per credential is deliberate (see the schema comments): a
fixed, well-labeled identity field set is best modeled attributively (clean labels,
clean partial disclosure), while the aggregate (unlabeled-position) form earns its
keep for the age-threshold flags, where hiding which thresholds are asserted is the
whole point -- a poor man's sparse Merkle tree, as mdoc models age proofs.

Scenario. Alice, a Utah resident, holds two ACDCs under one holder AID: an
attributive SEDI digital-identity credential (issuee plus individually-disclosable
name, date of birth, state-endorsed photo, and residence blocks) and an aggregative
age credential (boolean flags for the thresholds 13, 16, 18, 21, 55, 65). To enter a
dance club that serves alcohol she runs CLC as a credential: she (Issuer/Discloser)
issues a bespoke presentation ACDC to the club (Issuee/Disclosee) that edges (I2I) to
her two source credentials and carries the CLC terms in its Rules section, binding
the club before it receives her state-endorsed photo and age proof.

Every ACDC validates against a real, purpose-authored JSON Schema (Draft 2020-12)
from its first commit -- not the generic default -- and the source credentials
are bound to real registries created via regcept, matching the worked examples in
tests/acdc/test_examples.py. Actor AIDs are derived once here from a fixed salt so
the example is reproducible; each is a self-addressing ('E') transferable AID, the
SAID of an inception event that commits to the actor's initial key and a pre-rotated
next key.

A note on why later phases model the IPEX exchange and the club key rotation at
the data-structure level: it is a deliberate scope choice, NOT a gap in keripy,
and it is the right altitude for a first worked example. keripy is midway through
a deliberate v1->v2 reorganization. ACDC v1 -- and its v1 IPEX handlers in
keri.vc.protocoling -- stays in keri.vc; the new keri.acdc subpackage is the v2
home, with keri.acdc.messaging filled in (the v2 message builders these examples
use) and the other modules -- keri.acdc.ipexing, registring, registraring,
scheming, ... -- still placeholder stubs awaiting migration. The v1
keri.vc.protocoling handlers do not speak v2 messaging, so this example does NOT
route through them; doing so would only mislead a reader about how v2 IPEX works.
Instead the exchange is built directly from the real v2 exn primitive
keri.core.exchange, Habery-free and v2-native. This "bare bones at the data-
structure level" altitude is also the most useful one for implementers in other
languages, who need to see the primitives before the automation. When
keri.acdc.ipexing is fleshed out, a companion example will re-run this same
scenario through that tooling -- layered examples, one scenario, escalating
automation. See the phase docstrings.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks
from keri.core import (Salter, Noncer, Aggor, Compactor, Mapper, Diger, Verfer,
                       exchange, messagize, incept, rotate)
from keri.core.coring import MtrDex, Pather
from keri.core.serdering import SerderACDC
from keri.help.helping import Repath
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
RAWS = [b'clcworkexamplra' + b'%0x' % (i,) for i in range(24)]
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

# Both credentials use partially/selectively disclosable BLOCKS of one shape --
# oneOf(block SAID, block detail{d, u, <attr>}) -- whether the block is a nested
# attribute block (attributive ACDC) or an element of an aggregate array. Disclosing a
# block in full lets a verifier recompute its SAID and confirm it belongs; a withheld
# block travels as its bare SAID and leaks nothing (each block carries its own blinding
# nonce 'u', so its low-entropy value cannot be brute-forced from the SAID).
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

# ACDC sections may appear either expanded as an object or compacted to the SAID
# of that section. Schema sections use this directly; edge/rule sections reuse it
# because acm/acg carry those fields even when they are compact.
_SAID_OR_SECTION = {"oneOf": [{"type": "string"}, {"type": "object"}]}
_EMPTY_OR_SECTION = _SAID_OR_SECTION

# One E1E identity edge, pinned by schema (const "E1E"). This is the SEDI core-identity
# <-> entitlement relationship (keripy discussion #1515): the near ACDC's issuee is the
# SAME subject as the far node's issuee. E1E is an IDENTITY relation, NOT a delegation --
# unlike I2I ("issuer = far issuee") it says nothing about the issuer, so it holds even
# though the State issues sedi-id and the endorser issues age (issuer != issuee in both).
# Pinning the operator to const "E1E" makes the identity relation schema-enforced.
_E1E_EDGE_SCHEMA = {
    "oneOf": [
        {"type": "string"},
        {"type": "object", "required": ["d", "n", "o"],
         "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                        "n": {"description": "Far node (sedi-id core cred) SAID",
                              "type": "string"},
                        "s": {"description": "Far node schema SAID",
                              "type": "string"},
                        "o": {"description": "Edge operator; E1E: this ACDC's issuee = "
                                             "far node's issuee (identity relation, "
                                             "issuer unconstrained)",
                              "const": "E1E"}}}]}

# sedi-id is an ATTRIBUTIVE ('acm') credential. Its identity attributes are a fixed set
# of well-known, meaningfully-labeled fields, so an attribute section with individually
# partially-disclosable nested blocks is the right model: labels give clean paths and
# clean partial disclosure, and the aggregate (unlabeled-array) form buys nothing for a
# fixed labeled field set. The 'a' section is oneOf(section SAID, object); the object
# carries the top-level issuee 'i' plus one nested, individually-blinded block per
# attribute (photo/dob/residence/name), each oneOf(block SAID, block detail). Partial
# disclosure reveals a chosen block in full and leaves the rest as bare SAIDs -- every
# mix verifying to the same committed section SAID.
SEDI_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Identity Credential",
    "description": "State-endorsed SEDI digital-identity credential; attributes carried "
                   "as individually partially-disclosable nested blocks of an "
                   "attribute section.",
    "credentialType": "SEDI_Identity",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (State) AID", "type": "string"},
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
                     "i": {"description": "Issuee AID", "type": "string"},
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

# age is an AGGREGATIVE ('acg') credential: an array of boolean age-threshold flags.
# THIS is where the aggregate (unlabeled-position) form earns its keep. Every threshold
# has an element and all are present, so disclosing one flag (e.g. over21) reveals
# nothing about which OTHER thresholds are asserted -- a poor man's sparse Merkle tree,
# matching how mdoc models age proofs. Element 0 is the AGID, the index-1 block carries
# the issuee 'i', and the rest are one boolean block per threshold (over13..over65).
AGE_THRESHOLDS = (13, 16, 18, 21, 55, 65)
AGE_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Age Threshold Credential",
    "description": "Derived age credential: a selectively disclosable aggregate of "
                   "boolean flags, one per age threshold.",
    "credentialType": "AgeThresholds",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "A"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acg"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (endorser) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "A": {
            "description": "Selectively disclosable age-threshold aggregate section",
            "oneOf": [
                {"description": "Aggregate Section AGID", "type": "string"},
                {"description": "Selectively disclosable flag details",
                 "type": "array", "uniqueItems": True,
                 "items": {"anyOf": [
                     _disclosable_block("i", {"description": "Issuee AID",
                                              "type": "string"}, "Issuee"),
                     *[_disclosable_block(f"over{n}",
                         {"description": f"Over-{n} flag", "type": "boolean"},
                         f"Over{n}") for n in AGE_THRESHOLDS],
                 ]}},
            ],
        },
        # The entitlement chains back to the core SEDI identity credential via one
        # E1E identity edge (same subject). Schema-required, so the identity relation
        # is enforced rather than incidental.
        "e": {
            "description": "Edge section: one E1E identity edge to the sedi-id core cred",
            "oneOf": [
                {"type": "string"},
                {"type": "object", "required": ["d", "identity"],
                 "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                "identity": _E1E_EDGE_SCHEMA},
                 "additionalProperties": False}],
        },
        "r": _EMPTY_OR_SECTION,
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
                        "o": {"description": "Edge operator; I2I: this ACDC's "
                                             "issuer = far node's issuee",
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
                   "required": ["d", "u", "i", "date", "place"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "i": {"description": "Issuee = Disclosee",
                                        "type": "string"},
                                  "date": {"type": "string"},
                                  "place": {"type": "string"}},
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


# --- Blinding-nonce / uuid slot allocation: each NONCES[i] is used exactly once. ---
# sedi-id (attributive): attribute-section uuid + one nonce per nested block + acdc uuid.
N_SEDI_A, N_SEDI_PHOTO, N_SEDI_DOB, N_SEDI_RES, N_SEDI_NAME, N_SEDI_ACDC = 1, 2, 3, 4, 5, 6
# age (aggregative): issuee-block nonce + six flag-block nonces (8..13) + acdc uuid.
N_AGE_ISSUEE, N_AGE_FLAG0, N_AGE_ACDC = 7, 8, 14
# registries and bespoke (attribute uuid, acdc uuid, edge-section uuid, two edge uuids).
N_REG_STATE, N_REG_ENDORSER = 15, 16
N_BESP_A, N_BESP_ACDC, N_BESP_E, N_BESP_E_ID, N_BESP_E_AGE = 17, 18, 19, 20, 21
# age -> sedi-id E1E identity edge: edge-section uuid + edge uuid.
N_AGE_E, N_AGE_E_ID = 22, 23

# Age aggregate ARRAY positions (A[0] = AGID; A[1] = issuee; A[2..] = the flags, one per
# AGE_THRESHOLDS entry). SerderACDC.iseaid resolves the aggregate issuee from A[1].i.
AGE_ISSUEE = 1
AGE_FLAG0 = 2
AGE_OVER21 = AGE_FLAG0 + AGE_THRESHOLDS.index(21)   # array index of the over-21 flag

# Alice's age at the admittance date (DOB 2000-03-15, admittance 2026-07-14).
ALICE_AGE = 26


def _sedi_attr():
    """Alice's sedi-id attribute section (a fresh map each call).

    sedi-id is attributive: the issuee ('i') is inserted at the top of the section by
    acdcmap via iseaid, and each identity attribute is its own individually-blinded
    (own 'u'), self-addressing (own 'd') nested block, so it can be partially disclosed
    or withheld independently (see _photo_disclosure).
    """
    return dict(d='', u=NONCES[N_SEDI_A],
                photo=dict(d='', u=NONCES[N_SEDI_PHOTO],
                           photo="<state-endorsed-photo-bytes>"),
                dob=dict(d='', u=NONCES[N_SEDI_DOB], dob="2000-03-15"),
                residence=dict(d='', u=NONCES[N_SEDI_RES],
                               residence="Salt Lake City UT"),
                name=dict(d='', u=NONCES[N_SEDI_NAME], name="Alice Anders"))


def _age_ael():
    """Alice's age-threshold aggregate element list (a fresh list each call).

    Element 0 is the AGID placeholder; element 1 is the issuee block (i = ALICE), which
    is where SerderACDC.iseaid resolves an aggregate issuee from (.sad["A"][1]["i"]);
    elements 2.. are one individually-blinded boolean block per AGE_THRESHOLDS entry
    (over<n> = ALICE_AGE >= n). All thresholds are present as blocks, so disclosing one
    flag reveals nothing about which others are asserted.
    """
    els = ['', dict(d='', u=NONCES[N_AGE_ISSUEE], i=ALICE)]
    for offset, n in enumerate(AGE_THRESHOLDS):
        els.append(dict(d='', u=NONCES[N_AGE_FLAG0 + offset],
                        **{f"over{n}": ALICE_AGE >= n}))
    return els


def _source_credentials(kind):
    """Build Alice's two source credentials, registry-bound and schema-validated.

    sedi-id is an ATTRIBUTIVE ('acm') identity credential whose attributes are
    individually partially-disclosable nested blocks (issuee at a.i); age is an
    AGGREGATIVE ('acg') credential carrying an array of boolean age-threshold flags
    (issuee at A[1].i). The age entitlement chains back to the core sedi-id credential
    with one E1E identity edge -- the SEDI "entitlement chains to the core identity"
    pattern (disc #1515), an identity relation (same issuee, issuer != issuee), verified
    by _verify_identity_edge. Both are bound to real registries created here via regcept
    and validate against their purpose-authored schemas (the age schema now REQUIRES the
    E1E edge). Returns (sedi, age, ageAggor) -- the Aggor is returned so callers can
    selectively disclose over the age aggregate.
    """
    # Real registries: the State and the endorser each stand up a registry (rip
    # event); the credential's 'rd' binds it to that registry.
    regState = regcept(israid=STATE, uuid=NONCES[N_REG_STATE], stamp=REG_STATE_STAMP,
                       kind=kind)
    regEndorser = regcept(israid=ENDORSER, uuid=NONCES[N_REG_ENDORSER],
                          stamp=REG_ENDORSER_STAMP, kind=kind)

    _, sediSchema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    _, ageSchema = _saidify_schema(dict(AGE_SCHEMA_MAD), kind=kind)

    # sedi-id: attributive; acdcmap inserts the issuee (iseaid -> a.i). Built expanded
    # so its attribute section can be partially disclosed block-by-block.
    sedi = acdcmap(israid=STATE, uuid=NONCES[N_SEDI_ACDC], regid=regState.said,
                   schema=sediSchema, attribute=_sedi_attr(), iseaid=ALICE, kind=kind)
    # age: aggregative boolean-flag credential the endorser issues to Alice; its issuee
    # is the index-1 aggregate block. It chains back to the core sedi-id credential with
    # one E1E identity edge: both name the same subject (issuee), so this is an IDENTITY
    # relation, not a delegation. E1E constrains only the issuee (near == far), which is
    # why it holds even though the State issues sedi-id and the endorser issues age
    # (issuer != issuee in both) -- the case the delegative I2I would wrongly reject.
    # This is the SEDI "entitlement chains to the core identity" pattern (disc #1515);
    # the bespoke presentation's own I2I edges (Phase 2) are a separate, presentation-
    # time binding of Alice-as-discloser to her sources.
    ageEdge = dict(d='', u=NONCES[N_AGE_E],
                   identity=dict(d='', u=NONCES[N_AGE_E_ID], n=sedi.said,
                                 s=sedi.sad['s']['$id'], o='E1E'))
    ageAggor = Aggor(ael=_age_ael(), makify=True, kind=kind)
    age = acdcagg(israid=ENDORSER, uuid=NONCES[N_AGE_ACDC], regid=regEndorser.said,
                  schema=ageSchema, aggregate=ageAggor.ael, edge=ageEdge, kind=kind)
    return sedi, age, ageAggor


def _photo_disclosure(sedi, kind):
    """Alice's partial disclosure of sedi-id: reveal the photo block + issuee, withhold
    dob/residence/name as bare SAIDs.

    sedi-id is attributive, so disclosure is by compaction rather than by aggregate
    index: the attribute section's nested blocks each collapse to a SAID, and the holder
    expands only the chosen block. Returns the mixed 'a' section -- photo in full, the
    rest as SAIDs, the issuee ('i') always present as a top-level simple field. Every mix
    recomputes to the same committed section SAID, so a verifier can confirm the
    disclosure belongs to the ACDC (test_examples.test_partial_disclosure_compaction
    shows the same Compactor mechanism).
    """
    compactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
    compactor.compact()
    compactor.expand(greedy=True)
    allCompact = compactor.partials[('',)].mad
    allExpanded = next(v.mad for k, v in compactor.partials.items() if k != ('',))
    mixed = dict(allCompact)                    # every block as a bare SAID...
    mixed['photo'] = allExpanded['photo']       # ...then reveal only the photo block
    return mixed


def _age_disclosure(ageAggor):
    """Alice's selective disclosure of the age credential: reveal the issuee + the
    over-21 flag, withhold every other threshold as a bare SAID.

    The club learns she is over 21 and nothing about the other thresholds -- not whether
    she is over 13/16/18 (which over-21 implies anyway) and, importantly, not whether she
    is over 55 or 65. The disclosure still verifies against the committed AGID.
    """
    disclosed, _ = ageAggor.disclose(indices=[AGE_ISSUEE, AGE_OVER21])
    return disclosed


def _committed_a_said(sedi, kind):
    """The SAID sedi-id commits to for its attribute section -- the value its most-
    compact form carries under 'a'.

    A private ACDC's section SAID is taken over the most-compact form, so it is not
    the (empty) 'd' the expanded section carries; it is recomputed by compacting the
    section. A partial disclosure recompacts to this same SAID, which is what lets a
    verifier confirm the disclosure belongs to the credential.
    """
    compactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
    compactor.compact()
    return compactor.said


def _rules_in_bespoke():
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


def _verify_identity_edge(near, far, coreSchemaSaid):
    """The example's real verifier branch for an E1E identity edge.

    E1E binds the two credentials to the SAME subject: the near ACDC's issuee AID MUST
    equal the far node's issuee AID, both resolved via SerderACDC.iseaid (so an aggregate
    node's A[1].i reads the same as an attributive a.i). Unlike the delegative I2I it puts
    NO constraint on the issuer -- which is why it holds for two credentials issued by
    different third parties to one subject (issuer != issuee), exactly the case a
    coerce-to-I2I verifier (keri.vdr.verifying.verifyChain before PR #1523) rejects.

    E1E constrains only the SUBJECT -- not the far node's issuer or schema -- so on its
    own an identity edge is satisfied by ANY un-revoked credential naming that subject,
    including a self-issued core-shaped credential from a bogus issuer. The "chains to the
    SEDI core identity" guarantee therefore rests on ALSO binding the far node's schema:
    a real SEDI EGF const-pins the edge's far-node schema ('s') to the core-identity
    schema SAID (an edge s-constraint). This verifier enforces that -- the edge names, and
    the far node carries, the expected core schema (coreSchemaSaid) -- rather than trusting
    the subject match alone. (Far-issuer fitness beyond the schema stays a Layer-2
    governance concern; the s-constraint is what makes "core-shaped" mean "the core schema".)

    A real chain verifier would additionally confirm the far node's registry (TEL) state;
    that live check is out of scope for this data-structure-level example (see
    _club_accepts_grant and test_examples.py). Returns True or raises AssertionError.
    """
    edge = near.sad['e']['identity']
    assert edge['o'] == 'E1E'                          # identity operator
    assert edge['n'] == far.said                       # edge points at this far node
    assert edge['s'] == coreSchemaSaid                 # edge s-constraint: the SEDI core schema
    assert far.sad['s']['$id'] == coreSchemaSaid       # far node actually IS that schema
    assert near.iseaid is not None                     # near must be targeted (has issuee)
    assert near.iseaid == far.iseaid                   # same subject: the identity relation
    return True


def _bespoke_edges(sedi, age):
    """The bespoke ACDC's edge section: I2I edges to the two source credentials.

    Each edge names the target credential's SAID ('n') and schema ('s', read from
    the target's own schema section) and sets the operator ('o') to I2I.
    I2I ("issuer-to-issuee") is the same-holder constraint: it holds only when the
    issuer of the ACDC carrying the edge is the issuee of the credential the edge
    points to. Since Alice issues the bespoke ACDC and is the issuee of both source
    credentials, I2I is exactly right -- it is what cryptographically distinguishes
    "Alice presenting her own credentials" from "two credentials that merely happen
    to share an AID," which anyone could arrange. The far-node issuee is resolved
    uniformly via SerderACDC.iseaid whether it is attributive (sedi-id, a.i) or
    aggregative (age, A[1].i).
    """
    return dict(
        d='', u=NONCES[N_BESP_E],
        identity=dict(d='', u=NONCES[N_BESP_E_ID], n=sedi.said,
                      s=sedi.sad['s']['$id'], o='I2I'),
        age=dict(d='', u=NONCES[N_BESP_E_AGE], n=age.said,
                 s=age.sad['s']['$id'], o='I2I'),
    )


def _bespoke_presentation(sedi, age, kind, compactify=False, rule=None):
    """Build Alice's bespoke presentation ACDC to the club (helper for Phase 2+).

    Issuer = Alice (Discloser), Issuee = the club (Disclosee). Attributes mirror the
    spec's restaurant example -- date and place of admittance. Edges are I2I to both
    source creds; the Rules section carries the three CLC clauses (override via rule=
    to show that changing the terms changes the ACDC's identity). It is deliberately
    NOT registry-bound (no 'rd'), matching the spec's bespoke example and the "no
    correlatable log" intent. Returns the SerderACDC, most-compact when compactify=True
    (same SAID either way).

    Neither the photo nor the age assertion is copied into these attributes: the photo
    stays the single source of truth in sedi-id (reached via the identity edge, revealed
    by partial disclosure of just that block), and the over-21 proof comes from the age
    credential (reached via the age edge, revealed by selective disclosure of just that
    flag). The bespoke references; it does not restate.
    """
    _, schema = _saidify_schema(dict(BESPOKE_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[N_BESP_A], i=CLUB,
                     date="2026-07-14T21:30:00.000000+00:00",
                     place="The Alcove Club, 200 S West Temple, Salt Lake City UT")
    return acdcmap(israid=ALICE, uuid=NONCES[N_BESP_ACDC], schema=schema,
                   attribute=attribute, edge=_bespoke_edges(sedi, age),
                   rule=rule if rule is not None else _rules_in_bespoke(),
                   kind=kind, compactify=compactify)


def _club_accepts_grant(grantedSad, agreedSaid, schema):
    """The club's grant-time verification of a delivered credential -- a real
    verification operation, not a SAID-equality trick.

    Three checks: (1) self-verify the artifact -- reconstruct it with SerderACDC,
    which recomputes the SAID over the content and raises if it does not match the
    committed 'd'; (2) confirm the SAID is exactly the one the club agreed to in the
    offer (so the terms accepted are the terms received -- terms follow the data);
    (3) validate against the bespoke schema (which enforces the I2I operator and the
    required CLC clauses). Returns True only if all pass; returns False when the
    credential is well-formed and self-consistent but is NOT the one agreed to.

    A complete verifier performs a 4th check this omits -- revocation: walk the I2I
    edges to each source credential and check its registry ('rd') TEL for a revocation
    event; a revoked source cred must be rejected even when the presentation is
    otherwise perfect. Running that live check (keri.vdr's Tevery/Reger over a Habery)
    is out of scope for this data-structure-level example; test_examples.py exercises
    the registry lifecycle, and a future automation companion will fold it in.
    """
    granted = SerderACDC(sad=grantedSad, verify=True)     # self-verifies or raises
    if granted.said != agreedSaid:                        # well-formed, but not agreed to
        return False
    assert_acdc_schema_valid(granted, schema=schema)
    return True


def test_source_credentials_and_graduated_disclosure_JSON():
    """Phase 1: Alice's two source credentials, each with the disclosure it fits.

    Alice holds two ACDCs under one holder AID (ALICE), each bound to a real registry
    and validated against a purpose-authored JSON Schema, and each using the disclosure
    mechanism that fits its data:

      * sedi-id -- issued by the STATE as an ATTRIBUTIVE ('acm') identity credential.
        The issuee is the top-level a.i; each identity attribute (photo, dob, residence,
        name) is its own individually-blinded, partially-disclosable nested block. At
        presentation the holder reveals a chosen block in full and leaves the rest as
        bare SAIDs (partial disclosure by compaction); every mix recomputes to the same
        committed section SAID. This is the right model for a fixed, labeled field set.

      * age -- issued by the endorser as an AGGREGATIVE ('acg') credential: an array of
        boolean age-threshold flags (over13..over65). All thresholds are present, so
        disclosing one flag (over21) reveals nothing about which others are asserted --
        selective disclosure over the aggregate, verified via the committed AGID. This
        is the use case the aggregate (unlabeled-position) form is actually for.

    The load-bearing claims are asserted here: reveal the photo and over-21 while
    withholding the DOB and the other age thresholds; the withheld values are provably
    absent; and both disclosures are tamper-evident.
    """
    kind = Kinds.json
    sedi, age, ageAggor = _source_credentials(kind)

    # sedi-id: ATTRIBUTIVE identity credential, registry-bound, schema-valid.
    assert sedi.ilk == Ilks.acm
    assert sedi.sad['i'] == STATE                   # issued by the state
    assert sedi.sad['rd'] == "EBi8GblmoTZK6Z5bfhgdJcFD7ed0MGIVk_uSOWupWJUb"        # bound to the State's registry
    assert sedi.sad['a']['i'] == ALICE              # attributive issuee (top-level a.i)
    assert sedi.iseaid == ALICE                     # .iseaid resolves the attributive path
    assert sedi.issuee.qb64 == ALICE
    assert sedi.said == "EECATyTq4KuL-Ixs1EkcN9OjBRqfzR45fWUJ_auPCvEL"
    assert_acdc_schema_valid(sedi)

    # age: AGGREGATIVE boolean-flag credential, registry-bound, schema-valid.
    assert age.ilk == Ilks.acg
    assert age.sad['i'] == ENDORSER                 # issued by the endorser
    assert age.sad['rd'] == "EBoRy72Iko9PF4PyFr1C4FP2HD36jrYNASEk8rK8N9mU"
    assert age.sad['A'][AGE_ISSUEE]['i'] == ALICE   # aggregative issuee (index-1 block)
    assert age.iseaid == ALICE                      # .iseaid resolves the aggregative path
    assert age.issuee.qb64 == ALICE
    assert age.sad['A'][AGE_OVER21]['over21'] is True                          # over 21...
    over65Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(65)
    assert age.sad['A'][over65Pos]['over65'] is False                          # ...not over 65
    assert age.said == "EMYibHkYzqAqJ8frlSDqSfJkODqf3XdCnAvws1Z9Dwqe"
    ageSchema = assert_acdc_schema_valid(age)

    # Schema teeth: a non-boolean threshold flag is rejected.
    badA = list(age.sad['A'])
    badA[AGE_OVER21] = dict(badA[AGE_OVER21], over21="yes")
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(dict(age.sad, A=badA))

    # --- Partial disclosure of sedi-id (attributive): reveal photo + issuee, hide DOB. ---
    photoDisc = _photo_disclosure(sedi, kind)
    assert photoDisc['i'] == ALICE                          # issuee always present (simple field)
    assert isinstance(photoDisc['photo'], dict)             # photo block revealed in full
    assert photoDisc['photo']['photo'] == "<state-endorsed-photo-bytes>"
    assert isinstance(photoDisc['dob'], str)                # birthdate withheld...
    assert isinstance(photoDisc['residence'], str)          # residence withheld...
    assert isinstance(photoDisc['name'], str)               # name withheld...
    # ...as bare block SAIDs: the withheld values never cross the wire.
    assert "2000-03-15" not in json.dumps(photoDisc)        # birthdate
    assert "Salt Lake City" not in json.dumps(photoDisc)    # residence
    assert "Alice Anders" not in json.dumps(photoDisc)      # name
    # The verifier recomputes the section's most-compact SAID over the mixed disclosure
    # and confirms it is the commitment sedi-id carries under 'a'. A withheld block's
    # SAID is covered by this recomputation, so tampering ANY block (revealed OR
    # withheld) is caught -- which is why the withheld blocks need no separate check.
    committedA = _committed_a_said(sedi, kind)
    check = Compactor(mad=dict(photoDisc, d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == committedA
    # Tamper evidence: altering the revealed photo breaks that recomputation.
    tampered = dict(photoDisc, photo=dict(photoDisc['photo'], photo="<forged>"))
    tcheck = Compactor(mad=dict(tampered, d=''), makify=True, kind=kind)
    tcheck.compact()
    assert tcheck.said != committedA

    # --- Selective disclosure of age (aggregative): reveal over21 + issuee, hide rest. ---
    ageDisc = _age_disclosure(ageAggor)
    assert ageDisc[0] == ageAggor.agid                      # AGID anchor
    assert ageDisc[AGE_ISSUEE]['i'] == ALICE                # issuee revealed
    assert ageDisc[AGE_OVER21]['over21'] is True            # over-21 revealed
    assert isinstance(ageDisc[over65Pos], str)              # over-65 flag withheld (SAID)
    # Privacy: no other threshold flag crosses the wire -- the club learns she is over 21
    # and cannot tell whether she is over 55 or 65.
    assert "over55" not in json.dumps(ageDisc)
    assert "over65" not in json.dumps(ageDisc)
    assert Aggor.verifyDisclosure(ageDisc, kind=kind)
    # Tamper evidence: altering a revealed flag breaks AGID verification.
    tamperedAge = list(ageDisc)
    tamperedAge[AGE_OVER21] = dict(ageDisc[AGE_OVER21], over21=False)
    assert not Aggor.verifyDisclosure(tamperedAge, kind=kind)


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
    SAID-commit edge/rule sections but do not themselves interpret edge operators,
    so no shipped v2 runtime yet walks an edge and enforces I2I. (keri.vdr.verifying
    .verifyChain, the v1 runtime check, predates V2 aggregate sections: it resolves
    the far node's issuee only from a top-level attribute 'i', so it is simply out
    of date for an 'acg' far node -- a staleness limitation of that function, not a
    spec one.) The V2-correct way to resolve an issuee from EITHER section is
    SerderACDC.iseaid, which reads a.i for an attributive ACDC and A[1].i for an
    aggregative one; this test uses that property, exactly as a v2-native,
    aggregate-aware verifier would, and plays the edge check directly:

      1. The I2I same-holder binding: the bespoke ACDC's issuer equals the issuee
         (via .iseaid) of each source credential its edges point to -- resolved
         uniformly whether the far node is attributive (sedi-id, a.i) or aggregative
         (age, A[1].i).
      2. The three Rules clauses are present with their exact agreed text.

    The purpose-authored bespoke schema pins the edge operator to const "I2I", so
    the schema itself ENFORCES the same-holder binding; this test confirms it
    rejects any other operator. Finally, because the ACDC is private (top-level
    nonce), its most-compact and expanded forms share one SAID.
    """
    kind = Kinds.json
    sedi, age, _ = _source_credentials(kind)

    bespoke = _bespoke_presentation(sedi, age, kind)

    assert bespoke.ilk == Ilks.acm
    assert bespoke.sad['i'] == ALICE           # Alice is the Issuer (Discloser)
    assert bespoke.sad['a']['i'] == CLUB       # the club is the Issuee (Disclosee)
    assert bespoke.sad['a']['place'].startswith("The Alcove Club")
    assert 'over21' not in bespoke.sad['a']    # age proof referenced via edge, not restated
    assert 'rd' not in bespoke.sad             # deliberately not registry-bound
    assert bespoke.said == "EPYRxEgv7rRZOLOhHIi05zEN_Q3cvcmkzqCZAolba76M"

    # (1) I2I same-holder binding. The v2 path does not enforce operators, so we
    # assert the constraint the I2I operator stands for: the bespoke ACDC's issuer
    # is the issuee of every source credential its edges reference.
    assert bespoke.sad['e']['identity']['o'] == 'I2I'
    assert bespoke.sad['e']['age']['o'] == 'I2I'
    assert bespoke.sad['e']['identity']['n'] == sedi.said     # edge -> sedi-id
    assert bespoke.sad['e']['age']['n'] == age.said           # edge -> age
    # issuer(bespoke) == issuee(each source), resolved via SerderACDC.iseaid so the
    # attributive far node (sedi-id, a.i) and the aggregative one (age, A[1].i) read alike.
    assert bespoke.sad['i'] == sedi.iseaid
    assert bespoke.sad['i'] == age.iseaid

    # (2) The three Rules clauses are present with their exact agreed text.
    assert bespoke.sad['r']['Purpose']['l'] == PURPOSE_TEXT
    assert bespoke.sad['r']['Assimilation']['l'] == ASSIMILATION_TEXT
    assert bespoke.sad['r']['SafeHarbor']['l'] == SAFE_HARBOR_TEXT
    # The SafeHarbor clause incorporates the governance provision by SAID.
    assert GOV_PROVISION_SAID in bespoke.sad['r']['SafeHarbor']['l']

    # The private ACDC's compact and expanded forms share one SAID.
    compact = _bespoke_presentation(sedi, age, kind, compactify=True)
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

    keripy has v1 IPEX handlers in keri.vc.protocoling (apply/offer/agree/grant/
    admit/spurn), but they speak v1 ACDC messaging and run through a live Habery/
    keystore, and their v2-native successor, keri.acdc.ipexing, is still a
    placeholder in keripy's in-progress v1->v2 reorganization. Routing a v2 example
    through the v1 handlers would misrepresent how v2 IPEX works, so this example
    deliberately does NOT use them; instead it models the exchange at the data-
    structure level -- but with real machinery, not hand-waving: each message is a
    genuine v2 'exn' peer message built by keri.core.exchange (sender, receiver,
    route, prior, payload), and the club's acceptance carries a real Ed25519
    signature made with keri.core.Signer and checked with Verfer.verify. The
    reductions are (a) no Habery/keystore stands behind the AIDs, and (b) the
    club's "key state" is modeled as its establishing Verfer rather than resolved
    from a live KEL (Phase 4 shows why capturing it matters). When keri.acdc.ipexing
    lands, a companion example will re-run this exchange through that v2 tooling.

    Four properties are asserted, each a design point from the plan:

      1. The offer carries only SAIDs and terms -- NO PII (no name, photo, or
         birthdate). Alice commits to the bespoke ACDC (and its two source creds)
         by SAID, so the club learns what it is agreeing to before receiving any
         attribute values. (Alice's AID is still visible -- she is the offer's
         sender -- so "no PII" means no attribute values, not sender anonymity.
         Note too that the offer commits to the real, private bespoke SAID rather
         than the spec's metadata-ACDC variant, a deliberate scope reduction; the
         SAIDs leak no PII because the ACDCs are private, but
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

    Mapping onto IPEX message types. Each step here is a standard IPEX message.
    The forthcoming v2 tooling in keri.acdc.ipexing will provide a builder/handler
    per message that a production (Habery-backed) agent would call instead of
    assembling the exn by hand (the v1 analogues, for reference only, live in
    keri.vc.protocoling):

        apply  offer  agree  grant  admit  (decline)

    A production agent signs via hab.endorse -- which wraps keri.core.messagize,
    the same genus-aware attachment path used for the agree below -- and a
    production grant additionally carries the ACDC's TEL issuance event (iss) and
    its KEL anchoring event (anc). This example omits the Habery, registry and KEL
    anchoring on purpose, to keep the focus on the exchange's structure and its
    ordering guarantee.
    """
    kind = Kinds.json
    sedi, age, ageAggor = _source_credentials(kind)
    bespoke = _bespoke_presentation(sedi, age, kind)
    # The grant carries the bespoke ACDC in most-compact form (schema as a SAID): the
    # club already received the terms in the offer, and compact form keeps the grant
    # small. The two disclosures ride alongside -- the sedi-id photo (partial) and the
    # age over-21 flag (selective).
    bespokeCompact = _bespoke_presentation(sedi, age, kind, compactify=True)
    clubSigner = _SIGNERS[3]              # the club's establishing signing key

    # The exn peer messages are serialized as JSON here so the privacy invariants
    # below (no PII on the wire) can be checked as plaintext structural facts, the
    # same way the ACDC examples assert them; the CESR wire form base64-encodes the
    # payload, which would make a substring check meaningless.

    # 1. apply (club -> Alice): the challenge. It narrows what the club will accept up
    # front: not merely which schemas, but which FIELDS must be disclosed from each --
    # the photo and issuee from the attributive sedi-id (a/photo, a/i), and the over-21
    # flag and issuee from the aggregative age credential (A/over21, A/i). The issuee
    # is required from BOTH so the club can confirm the two creds name the same holder
    # (the I2I binding). The request names SCHEMA SAIDs, never ACDC SAIDs -- the
    # applicant is not assumed to know which actual credentials it will be shown. This
    # is a static, one-shot narrowing of the request, NOT full back-and-forth
    # negotiation. No creds yet -- schemas, required paths, governance.
    #
    # The request rides the disclosure-paths `dp` field of the QUERY section, `q`
    # (exchange(modifiers=...)), not the attribute section. An exn's query block is the
    # http-query-string analogue and its attribute block is the body; a disclosure
    # request is a query, so `dp` belongs in `q` (WebOfTrust/keripy discussion #1549).
    #
    # `dp` is an ORDERED LIST OF (schemaSAID, [paths]) PAIRS, not a dict keyed by schema
    # SAID. A dict cannot express a DAG containing two credentials of the SAME schema --
    # they collapse onto one key -- which is legitimate and common (presenting one's own
    # identity alongside a spouse's, both under the same SEDI schema). The ordered list
    # keeps them distinct, and it makes two equivalent requests serialize byte-for-byte
    # identically. Ordering is a breadth-first walk of the DAG from its origin node.
    # JSON has no tuple, so each pair serializes as a 2-element array.
    #
    # Paths are ACDC-RELATIVE and so do NOT lead with '/'. A leading '/' means
    # DAG-ABSOLUTE, rooted at the origin node, and an absolute path that reaches a
    # non-origin ACDC must cross the edge that links it. That hop is written as the
    # virtual path component '_', which stands for the jump from the near-side edge
    # block to the top level of the far-side ACDC (@SmithSamuelM, #1549). The same
    # request in absolute form reads:
    #     origin: /i, /a/i, /r/
    #     sedi:   /e/identity/_/a/i, /e/identity/_/a/photo
    #     age:    /e/age/_/A/i, /e/age/_/A/over21
    # Omitting the '_' does not merely misroot such a path, it makes it meaningless:
    # '/e/identity/a/i' names an 'a' field inside the near-side EDGE block, which has
    # no such field. Relative form is used here because this DAG has no optional edges
    # -- the bespoke schema requires both 'identity' and 'age' -- so the breadth-first
    # ordering of `dp` is gapless and each entry's ACDC is unambiguous without
    # restating the route to it. Absolute form is required only when optional edges
    # could leave holes in that ordering.
    #
    # A TRAILING '/' means the whole node ("the hammer"): the origin's 'r/' asks for the
    # rule section fully expanded, because the club must read the CLC terms it is being
    # asked to agree to. Every other path is a leaf ("the scalpel"), closing over only
    # what is needed to validate the SAIDs along its own branch.
    #
    # The ZEROTH entry is the DAG's origin node (#1549) -- Alice's bespoke presentation
    # ACDC. The club can name its schema even though Alice issues it: the origin is
    # presenter-issued, but its SHAPE is governance, not Alice's invention, and "in all
    # of these applications the Applicant would know the schema of the origin node
    # despite it being a presenter issued ACDC" (@SmithSamuelM, #1542). So the club asks
    # the origin for its issuer, its issuee, and its rules -- who is disclosing, that the
    # presentation is addressed to the club, and the terms the club must agree to before
    # the grant. The rule section is what the offer at step 2 answers with; the issuer
    # and issuee arrive with the presentation itself, in the grant.
    bespokeSchemaSaid, _ = _saidify_schema(dict(BESPOKE_SCHEMA_MAD), kind=kind)
    sediSchemaSaid = sedi.sad['s']['$id']
    ageSchemaSaid = age.sad['s']['$id']
    apply = exchange(sender=CLUB, receiver=ALICE, route="/ipex/apply",
                     modifiers=dict(dp=[[bespokeSchemaSaid, ["i", "a/i", "r/"]],
                                        [sediSchemaSaid, ["a/i", "a/photo"]],
                                        [ageSchemaSaid,  ["A/i", "A/over21"]]]),
                     attributes=dict(m="Prove over-21 and show the state-endorsed photo.",
                                     g=GOV_PROVISION_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['t'] == Ilks.exn
    assert apply.sad['r'] == "/ipex/apply"
    assert apply.sad['i'] == CLUB and apply.sad['ri'] == ALICE
    # The field-level request: issuee + photo from the attributive cred, issuee + over-21
    # flag from the aggregative cred, each under the schema SAID the club is asking for.
    dp = apply.sad['q']['dp']
    # Ordered, not keyed: the schema SAIDs are positions in a list, so a DAG with two
    # same-schema credentials would carry two entries rather than losing one. The order
    # is a breadth-first walk from the origin, which for this DAG is the bespoke
    # presentation and then its two edges in section order, 'identity' and 'age'.
    assert [entry[0] for entry in dp] == [bespokeSchemaSaid, sediSchemaSaid, ageSchemaSaid]
    reqOrigin = dp[0][1]
    reqSedi = dp[1][1]
    reqAge = dp[2][1]
    assert reqOrigin == ["i", "a/i", "r/"]              # origin: discloser, disclosee, terms
    assert reqSedi == ["a/i", "a/photo"]                # attributive: issuee + photo
    assert reqAge == ["A/i", "A/over21"]                # aggregate: issuee + over-21 flag
    assert "a/i" in reqSedi and "A/i" in reqAge         # the joining issuee, from both
    # ACDC-relative form throughout: no path leads with '/', which would root it at the
    # DAG origin and, for a non-origin entry, would have to cross a '_' hop to get back
    # to the credential the entry is already about.
    assert all(not p.startswith("/") for _, paths in dp for p in paths)
    # Node vs. leaf: only the origin's rule section is asked for whole.
    assert [p for _, paths in dp for p in paths if p.endswith("/")] == ["r/"]
    # The request lives in the query block, not the attribute block; the attribute
    # block carries only the human message and the governance reference.
    assert 'dp' not in apply.sad['a'] and 'disclose' not in apply.sad['a']
    assert set(apply.sad['a']) == {'m', 'g'}
    assert apply.said == "EPiL36dPzFMlL5K4ybK5MaxC2a3qIzntPjHvExkn0189"

    # 2. offer (Alice -> club): "I'll prove over-21 and show my photo if you accept
    # these terms." Commits ONLY to Alice's own bespoke-presentation SAID, the CLC
    # terms, and the governance ref -- no PII -- and binds the apply it answers. It
    # deliberately does NOT enumerate the issuer-committed source-credential SAIDs
    # (sedi/age): those are issuer commitments, and attaching them before the club
    # agrees would let the club spurn and walk away with stable holder correlators,
    # defeating the metadata-ACDC decorrelation (panel review, PRV-F2). They arrive
    # only post-agree, in the grant, reachable by expanding the delivered presentation.
    # Its query block carries `dp` too, as an EMPTY list. For a SOLICITED offer -- one
    # that answers an apply -- an empty `dp` means "the same disclosure paths the apply
    # asked for", so Alice restates nothing and the two messages cannot drift (#1549).
    # An unsolicited offer, or one that counter-offers different paths, MUST spell the
    # list out instead; empty is only meaningful because `p` binds the apply it answers.
    offer = exchange(sender=ALICE, receiver=CLUB, route="/ipex/offer",
                     prior=apply.said,
                     modifiers=dict(dp=[]),
                     attributes=dict(acdc=bespoke.said,
                                     governance=GOV_PROVISION_SAID,
                                     terms=_rules_in_bespoke()),
                     stamp=OFFER_STAMP, kind=kind)
    assert offer.sad['p'] == apply.said                 # answers the apply
    assert offer.sad['q']['dp'] == []                   # solicited: "as per the apply"
    assert bespoke.said.encode() in offer.raw           # commits to Alice's own presentation
    assert offer.said == "ENW6Q9TtdEyHtah7Tgg7ClV3XuD9CmAwAs8oEIZAu-KO"
    # (property 1) the offer leaks no PII: not Alice's name, photo, or birthdate.
    assert b"Alice Anders" not in offer.raw
    assert b"<state-endorsed-photo-bytes>" not in offer.raw
    assert b"2000-03-15" not in offer.raw
    # Issuer commitments withheld until after the club agrees (PRV-F2): the source
    # SAIDs are stable cross-presentation correlators, so they must not ride the offer.
    assert sedi.said.encode() not in offer.raw
    assert age.said.encode() not in offer.raw

    # 3. agree (club -> Alice): acceptance. It binds the OFFER's SAID (property 2),
    # and the club signs it (property 3). It is signed but NOT KEL-anchored.
    agree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said                 # binds the offer SAID
    assert agree.said == "ELU6DF53tqV2Dd_2Tpyk1uBcP5JLUnJ0JJQlsw4H1EsC"
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
        # The grant carries the bespoke ACDC (compact) plus the two disclosures -- the
        # sedi-id photo (partial) and the age over-21 flag (selective). PII appears only here.
        return exchange(sender=ALICE, receiver=CLUB, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(acdc=bespokeCompact.sad,
                                        identity=_photo_disclosure(sedi, kind),
                                        age=_age_disclosure(ageAggor)),
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
    assert grant.said == "EKPweFTQmyr2ghr5tBDLxAZY-_AXkiztDWmwcl6h0XTS"
    # (property 4) PII crosses the wire only now, in the grant: the photo and the
    # over-21 flag.
    assert b"<state-endorsed-photo-bytes>" in grant.raw
    assert grant.sad['a']['age'][AGE_OVER21]['over21'] is True
    # ...and the grant still never carries the withheld birthdate or the other age
    # thresholds -- the club cannot tell whether she is over 55 or 65.
    assert b"2000-03-15" not in grant.raw
    assert b"over55" not in grant.raw and b"over65" not in grant.raw
    # The grant honors the apply's field request. sedi-id (attributive): the photo block
    # and issuee are revealed (/a/photo, /a/i), the rest stay bare SAIDs. age
    # (aggregative): the over-21 flag and issuee are revealed.
    identityDisc = grant.sad['a']['identity']
    assert isinstance(identityDisc['photo'], dict) and identityDisc['i'] == ALICE
    assert isinstance(identityDisc['dob'], str)         # dob withheld
    assert grant.sad['a']['age'][AGE_ISSUEE]['i'] == ALICE

    # The club VERIFIES the granted credential before trusting it -- a real operation,
    # not a SAID-equality trick (see _club_accepts_grant: self-verify the artifact,
    # match it to the SAID committed in the offer, schema-validate). It accepts here:
    # the delivered SAID is the one the club agreed to, so the terms it accepted are
    # the terms bound into the data it received -- terms follow the data.
    assert _club_accepts_grant(grant.sad['a']['acdc'], bespoke.said, bespoke.sad['s'])
    # The 4th check, revocation, is documented in _club_accepts_grant; the presentation
    # carries its hooks -- each I2I edge names a registry-bound source credential.
    assert bespoke.sad['e']['identity']['n'] == sedi.said and sedi.sad['rd']
    assert bespoke.sad['e']['age']['n'] == age.said and age.sad['rd']

    # 5. admit (club -> Alice): acknowledges receipt, closing the exchange.
    admit = exchange(sender=CLUB, receiver=ALICE, route="/ipex/admit",
                     prior=grant.said, stamp=ADMIT_STAMP, kind=kind)
    assert admit.sad['p'] == grant.said
    assert admit.said == "EG_v0NItF5AH5QeBBCRaaR1XffK1iivzW9DJgfyNoTZ_"


def _pathable_labels(value):
    """Every field label reachable by a disclosure path, from a SAD value.

    Recurses field maps and arrays. The SCHEMA section is skipped: it is always
    disclosed whole, so no path ever descends into it -- which is just as well, since
    JSON Schema's own keys ('$id', '$schema') are not Base64 at all and could never be
    a Pather part. See test_disclosure_path_label_conformance_JSON.
    """
    if isinstance(value, dict):
        for label, sub in value.items():
            yield label
            if label != 's':
                yield from _pathable_labels(sub)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _pathable_labels(item)


def test_disclosure_path_label_conformance_JSON():
    """Every field label in the worked example can be a disclosure-path component.

    Two restrictions come with the `_` DAG-hop component settled in discussion #1549.
    A label may not contain '-', because '-' is what the '/' delimiter becomes when a
    path is CESR-serialized as compact Base64; and a label may not be exactly '_',
    because a bare '_' is reserved for the hop from an edge to the far-side ACDC.

    The '-' half is already keripy's behavior rather than a new rule: Pather's part
    regex is PATHREX = rb'^[a-zA-Z0-9_]*$' (keri.help.helping), and a part that fails
    it forces the whole path out of compact Base64 into the Bytes code -- or raises
    outright when pathive. So this asserts against Repath itself instead of restating
    the character class, and adds only the bare-'_' rule on top.

    A guard, not a discovery: these labels are clean today. It exists so that adding a
    hyphenated attribute to the example fails here, with the reason, rather than
    silently making a path unrepresentable at the CESR layer.
    """
    kind = Kinds.json
    sedi, age, _ = _source_credentials(kind)
    bespoke = _bespoke_presentation(sedi, age, kind)
    for acdc in (sedi, age, bespoke):
        for label in _pathable_labels(acdc.sad):
            assert Repath.match(label.encode()), \
                f"label {label!r} cannot be a Pather path part"
            assert label != '_', "'_' is reserved for the DAG-hop path component"
    # The hop component round-trips through Pather today, compactly and with no code
    # change, so adopting it costs the wire nothing. What it does NOT yet do is
    # RESOLVE: no Pather method follows '_' across an edge into the far-side ACDC.
    # That extension is the open work item on #1549.
    hop = Pather(path="/e/identity/_/a/photo")
    assert hop.parts == ['', 'e', 'identity', '_', 'a', 'photo']
    # A StrB64 code (4A/5A/6A, by length mod 3), NOT a Bytes code (4B/5B/6B): the '_'
    # part keeps the path in the compact Base64 domain. A '-' in any label is what
    # would force it into Bytes, which is the whole reason for the restriction above.
    assert hop.code in (MtrDex.StrB64_L0, MtrDex.StrB64_L1, MtrDex.StrB64_L2)
    assert hop.qb64 == "6AAGAAA-e-identity-_-a-photo"
    assert Pather(qb64=hop.qb64).path == "/e/identity/_/a/photo"


def test_accountability_and_terms_follow_data_JSON():
    """Phase 4: the saved agree survives a club key rotation; terms follow the data.

    The agree is signed but deliberately NOT KEL-anchored (Phase 3), so the club
    keeps no public, correlatable log of whom it admits. The cost of that privacy
    is that a bare signature rots: once the club rotates its signing key, a verifier
    who resolves the club's CURRENT key state can no longer verify the old agree. So
    Alice's wallet must capture the club's key state -- its establishing event -- at
    acceptance time, alongside the signed agree. This test proves why.

    What this does and does NOT establish. Capturing the establishing event makes the
    signature CHECKABLE against the club's first key; it does not prove that key was
    the club's CURRENT key when it signed. An undated signature by the (now retired)
    first key made AFTER the rotation verifies against the captured inception
    identically -- the scheme cannot distinguish a genuine pre-rotation acceptance
    from a post-rotation forgery by a compromised retired key, nor stop the club from
    repudiating a real acceptance. (Pre-rotation protects the club's ongoing IDENTIFIER
    control -- a thief with the old key cannot continue the KEL -- but not the
    forgeability of an undated message signed by that key.) So this is durable
    VERIFIABILITY under cooperative timing, not non-repudiation robust to key
    compromise. Establishing currency-at-signing requires ordering the signature
    against the KEL -- anchoring the agree as a KEL transaction seal, or a witnessed
    receipt -- which this example forgoes for privacy. A high-stakes CLC flow would
    anchor instead (to a blinded presentation registry, to keep correlation-resistance),
    sitting at the opposite, accountability-maximizing end of the same tradespace.

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
    sedi, age, _ = _source_credentials(kind)
    bespoke = _bespoke_presentation(sedi, age, kind)

    # Offer and the club's signed agree, as in Phase 3.
    offer = exchange(sender=ALICE, receiver=CLUB, route="/ipex/offer",
                     attributes=dict(acdc=bespoke.said, terms=_rules_in_bespoke()),
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
    # If Alice had granted WEAKENED terms, the club's SAME grant-time verification
    # rejects them -- a true verification (_club_accepts_grant), not a SAID inequality.
    # The weakened credential is a perfectly well-formed, self-consistent ACDC, so
    # self-verification accepts the artifact; it is rejected because its SAID is not the
    # one the club agreed to. You cannot weaken a clause and still present the agreed
    # credential -- terms follow the data.
    tamperedRules = _rules_in_bespoke()
    tamperedRules['Assimilation']['l'] = "Verifier may do anything it likes."
    weakened = _bespoke_presentation(sedi, age, kind, rule=tamperedRules)
    assert not _club_accepts_grant(weakened.sad, bespoke.said, bespoke.sad['s'])


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_cpd_serialization_kinds(kind):
    """Phases 1-3 invariants hold across every serialization kind, not just JSON.

    The detailed phases above pin canonical JSON SAIDs for readability. This check
    exercises the same flows -- the attributive sedi-id with partial disclosure, the
    aggregative age credential with selective disclosure, the bespoke ACDC with I2I
    edges and rules, and the gated exchange with a real signed agree -- over CESR (the
    native KERI wire format) and CBOR/MGPK, asserting the behavioral invariants without
    pinning per-kind SAIDs. (The no-PII-on-the-wire invariant is JSON-specific and
    asserted in Phase 3: the CESR wire form base64-encodes the payload, so a plaintext
    substring check does not apply.)
    """
    sedi, age, ageAggor = _source_credentials(kind)
    assert sedi.ilk == Ilks.acm and sedi.kind == kind
    assert age.ilk == Ilks.acg
    assert sedi.sad['rd'] and age.sad['rd']               # registry-bound on every kind
    assert_acdc_schema_valid(sedi)                        # schema validation holds
    assert_acdc_schema_valid(age)

    # Partial disclosure of sedi-id: reveal photo, withhold DOB; recompute the section SAID.
    photoDisc = _photo_disclosure(sedi, kind)
    assert isinstance(photoDisc['photo'], dict)           # photo revealed
    assert isinstance(photoDisc['dob'], str)              # birthdate withheld
    check = Compactor(mad=dict(photoDisc, d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == _committed_a_said(sedi, kind)
    # Selective disclosure of age: reveal over-21, withhold the rest; verifies via AGID.
    ageDisc = _age_disclosure(ageAggor)
    assert ageDisc[AGE_OVER21]['over21'] is True          # over-21 revealed
    assert Aggor.verifyDisclosure(ageDisc, kind=kind)

    # Bespoke ACDC: I2I edges + rules, schema-valid, compact == expanded SAID.
    bespoke = _bespoke_presentation(sedi, age, kind)
    compact = _bespoke_presentation(sedi, age, kind, compactify=True)
    assert bespoke.said == compact.said
    assert bespoke.sad['e']['identity']['o'] == 'I2I'
    assert bespoke.sad['e']['age']['o'] == 'I2I'
    schema = assert_acdc_schema_valid(bespoke)
    assert_acdc_schema_valid(compact, schema=schema)
    # I2I same-holder binding via SerderACDC.iseaid (att + agg far nodes read alike)
    assert bespoke.sad['i'] == sedi.iseaid
    assert bespoke.sad['i'] == age.iseaid

    # Gated exchange: the offer binds nothing PII, the agree binds the offer SAID,
    # and the club's signed agree (assembled via messagize) verifies.
    offer = exchange(sender=ALICE, receiver=CLUB, route="/ipex/offer",
                     attributes=dict(acdc=bespoke.said, terms=_rules_in_bespoke()),
                     stamp=OFFER_STAMP, kind=kind)
    agree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                     prior=offer.said, stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    clubSig = _SIGNERS[3].sign(ser=agree.raw, index=0)
    signedAgree = messagize(agree, sigers=[clubSig])
    assert bytes(agree.raw) in signedAgree
    assert _SIGNERS[3].verfer.verify(sig=clubSig.raw, ser=agree.raw)


def test_age_identity_edge_E1E_JSON():
    """The age entitlement carries an E1E identity edge to the sedi-id core credential.

    Per keripy discussion #1515, the relationship between a SEDI core identity credential
    and an entitlement credential is an IDENTITY relation, not a delegation: both name the
    same subject (issuee), so the edge operator is E1E (near issuee == far issuee), NOT the
    delegative I2I. E1E puts no constraint on the issuer, so the edge holds even though the
    State issues sedi-id and the endorser issues age -- issuer != issuee in both. Routing
    this edge through the V1 keri.vdr.verifying.verifyChain would coerce the unknown
    operator to I2I and wrongly reject it (keripy PR #1523 adds a real E1E branch there);
    this data-structure-level example verifies the edge directly (see _verify_identity_edge).
    """
    kind = Kinds.json
    sedi, age, _ = _source_credentials(kind)

    # The age credential's edge section carries one edge: E1E -> sedi-id.
    edge = age.sad['e']['identity']
    assert edge['o'] == 'E1E'                         # identity operator, not delegation
    assert edge['n'] == sedi.said                     # points at the core identity cred
    assert edge['s'] == sedi.sad['s']['$id']          # names the core cred's schema

    # The identity relation: same subject (issuee), different issuers, issuer != issuee.
    assert age.iseaid == sedi.iseaid == ALICE         # same holder
    assert age.israid == ENDORSER and sedi.israid == STATE   # different issuers ...
    assert age.israid != age.iseaid                   # ... and issuer != issuee (I2I rejects)

    # The example's real E1E verifier branch accepts the edge, the age credential
    # validates against its (E1E-emitting) schema, and a far node naming a DIFFERENT
    # subject is rejected (the bespoke presentation's issuee is the club, not Alice).
    # The expected SEDI-core schema SAID is derived independently (the EGF knows it),
    # not read back from the far node -- that is what gives the s-constraint teeth.
    coreSchemaSaid, _ = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    assert coreSchemaSaid == sedi.sad['s']['$id']
    assert_acdc_schema_valid(age)
    with pytest.raises(AssertionError):                         # wrong subject (far = bespoke)
        _verify_identity_edge(age, _bespoke_presentation(sedi, age, kind), coreSchemaSaid)
    with pytest.raises(AssertionError):                         # right subject, wrong core schema
        _verify_identity_edge(age, sedi, "E" + "A" * 43)
    assert _verify_identity_edge(age, sedi, coreSchemaSaid)


JOB_SEDI_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Job-Application Identity Credential",
    "description": "SEDI identity subset for employment screening, authored for "
                   "graduated disclosure rather than proof-of-age.",
    "credentialType": "SEDI_JobIdentity",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (State) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": _SAID_OR_SECTION,
        "a": {
            "oneOf": [
                {"type": "string"},
                {"type": "object",
                 "required": ["d", "u", "i", "legalName", "address", "phone",
                              "biometric", "dob"],
                 "properties": {
                     "d": {"type": "string"},
                     "u": {"type": "string"},
                     "i": {"type": "string"},
                     "legalName": _disclosable_block(
                         "legalName",
                         {"type": "string"},
                         "LegalName"),
                     "address": _disclosable_block(
                         "address",
                         {"type": "string"},
                         "Address"),
                     "phone": _disclosable_block(
                         "phone",
                         {"type": "string"},
                         "Phone"),
                     "biometric": _disclosable_block(
                         "biometric",
                         {"type": "string"},
                         "Biometric"),
                     "dob": _disclosable_block(
                         "dob",
                         {"type": "string", "format": "date"},
                         "DOB"),
                 },
                 "additionalProperties": False},
            ],
        },
        "e": _EMPTY_OR_SECTION,
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}

FOOD_HANDLER_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Food Handler Permit Credential",
    "description": "Food-handler entitlement credential linked back to a SEDI core "
                   "identity via an E1E identity edge.",
    "credentialType": "FoodHandlerPermit",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a", "e"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"type": "string"},
        "rd": {"type": "string"},
        "s": _SAID_OR_SECTION,
        "a": {
            "oneOf": [
                {"type": "string"},
                {"type": "object",
                 "required": ["d", "u", "i", "permitId", "category", "status",
                              "expires", "jurisdiction"],
                 "properties": {
                     "d": {"type": "string"},
                     "u": {"type": "string"},
                     "i": {"type": "string"},
                     "permitId": {"type": "string"},
                     "category": {"type": "string"},
                     "status": {"type": "string"},
                     "expires": {"type": "string", "format": "date"},
                     "jurisdiction": {"type": "string"},
                 },
                 "additionalProperties": False},
            ],
        },
        "e": {
            "oneOf": [
                {"type": "string"},
                {"type": "object",
                 "required": ["d", "identity"],
                 "properties": {"d": {"type": "string"},
                                "u": {"type": "string"},
                                "identity": _E1E_EDGE_SCHEMA},
                 "additionalProperties": False},
            ],
        },
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}

JOB_PRESENTATION_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Job Application Presentation ACDC",
    "description": "Holder-issued job-application presentation binding the SEDI "
                   "subset and the linked entitlement to one applicant.",
    "credentialType": "JobApplicationPresentation",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "s", "a", "e"],
    "properties": {
        "v": {"type": "string"},
        "t": {"const": "acm"},
        "d": {"type": "string"},
        "u": {"type": "string"},
        "i": {"type": "string"},
        "s": _SAID_OR_SECTION,
        "a": {
            "oneOf": [
                {"type": "string"},
                {"type": "object",
                 "required": ["d", "u", "i", "role", "employer", "submitted"],
                 "properties": {
                     "d": {"type": "string"},
                     "u": {"type": "string"},
                     "i": {"type": "string"},
                     "role": {"type": "string"},
                     "employer": {"type": "string"},
                     "submitted": {"type": "string"},
                 },
                 "additionalProperties": False},
            ],
        },
        "e": {
            "oneOf": [
                {"type": "string"},
                {"type": "object",
                 "required": ["d", "identity", "entitlement"],
                 "properties": {"d": {"type": "string"},
                                "u": {"type": "string"},
                                "identity": _I2I_EDGE_SCHEMA,
                                "entitlement": _I2I_EDGE_SCHEMA},
                 "additionalProperties": False},
            ],
        },
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}


JOB_RAWS = [b'jobappdisclosur' + b'%0x' % (i,) for i in range(18)]
JOB_NONCES = [Noncer(raw=raw).qb64 for raw in JOB_RAWS]
J_SEDI_A, J_SEDI_NAME, J_SEDI_ADDRESS, J_SEDI_PHONE, J_SEDI_BIOMETRIC, J_SEDI_DOB, \
    J_SEDI_ACDC, J_PERMIT_A, J_PERMIT_ACDC, J_PERMIT_E, J_PERMIT_E_ID, J_PRESENT_A, \
    J_PRESENT_ACDC, J_PRESENT_E, J_PRESENT_E_ID, J_PRESENT_E_ENT, J_REG_STATE, \
    J_REG_PERMIT = range(18)


def test_job_application_entitlement_presentation_JSON():
    """Job-application flow: SEDI subset plus linked food-handler entitlement.

    This keeps the Daniel/Sam CLC exchange shape but swaps the second credential from
    proof-of-age to an entitlement. The employer first applies for DAG-scoped
    disclosure, the holder offers a holder-issued presentation that binds the two
    source credentials, a signed agree opens the gate, and the grant carries both
    artifacts: a graduated-disclosure SEDI subset and the linked entitlement.

    Workflow/UX sketch, at the test level:
      1. Employer asks for exactly the fields it needs for hiring.
      2. Holder preview/offers the one-time presentation without leaking PII.
      3. Holder releases the actual data only after the employer signs agree.

    If the employer later needs a separate work-age proof, that should be a second
    apply/offer/agree/grant flow keyed to an age-threshold credential rather than
    broadening this entitlement flow.
    """
    kind = Kinds.json

    # Build registries and self-addressed schemas for the two source credentials
    # and the holder-issued presentation.
    regState = regcept(israid=STATE, uuid=JOB_NONCES[J_REG_STATE],
                       stamp="2026-03-10T12:00:00.000000+00:00", kind=kind)
    regPermit = regcept(israid=ENDORSER, uuid=JOB_NONCES[J_REG_PERMIT],
                        stamp="2026-03-11T12:00:00.000000+00:00", kind=kind)
    _, jobSediSchema = _saidify_schema(dict(JOB_SEDI_SCHEMA_MAD), kind=kind)
    _, permitSchema = _saidify_schema(dict(FOOD_HANDLER_SCHEMA_MAD), kind=kind)
    _, presentationSchema = _saidify_schema(dict(JOB_PRESENTATION_SCHEMA_MAD),
                                            kind=kind)

    # Build the employment-oriented SEDI source credential. The nested blocks let
    # the holder reveal name/address/phone/biometric later while withholding DOB.
    sedi = acdcmap(
        israid=STATE,
        uuid=JOB_NONCES[J_SEDI_ACDC],
        regid=regState.said,
        schema=jobSediSchema,
        attribute=dict(
            d='',
            u=JOB_NONCES[J_SEDI_A],
            legalName=dict(d='', u=JOB_NONCES[J_SEDI_NAME],
                           legalName="Alice Anders"),
            address=dict(d='', u=JOB_NONCES[J_SEDI_ADDRESS],
                         address="220 E 300 S, Salt Lake City UT 84111"),
            phone=dict(d='', u=JOB_NONCES[J_SEDI_PHONE],
                       phone="+1-801-555-0100"),
            biometric=dict(d='', u=JOB_NONCES[J_SEDI_BIOMETRIC],
                           biometric="face-template-sha256:4d0ff9ce-job-app"),
            dob=dict(d='', u=JOB_NONCES[J_SEDI_DOB], dob="2000-03-15"),
        ),
        iseaid=ALICE,
        kind=kind,
    )
    # Build the entitlement credential and chain it back to the SEDI credential
    # with an E1E identity edge.
    permit = acdcmap(
        israid=ENDORSER,
        uuid=JOB_NONCES[J_PERMIT_ACDC],
        regid=regPermit.said,
        schema=permitSchema,
        attribute=dict(d='', u=JOB_NONCES[J_PERMIT_A], i=ALICE,
                       permitId="UT-FH-2026-00917",
                       category="food-handler",
                       status="active",
                       expires="2027-08-31",
                       jurisdiction="Salt Lake County Health Department"),
        edge=dict(d='', u=JOB_NONCES[J_PERMIT_E],
                  identity=dict(d='', u=JOB_NONCES[J_PERMIT_E_ID], n=sedi.said,
                                s=sedi.sad['s']['$id'], o='E1E')),
        kind=kind,
    )
    # Build the expanded holder-issued presentation that binds both source
    # credentials to this one job-application flow.
    presentation = acdcmap(
        israid=ALICE,
        uuid=JOB_NONCES[J_PRESENT_ACDC],
        schema=presentationSchema,
        attribute=dict(d='', u=JOB_NONCES[J_PRESENT_A], i=CLUB,
                       role="crew-member / food-handler",
                       employer="Downtown Burger",
                       submitted="2026-08-04"),
        edge=dict(
            d='',
            u=JOB_NONCES[J_PRESENT_E],
            identity=dict(d='', u=JOB_NONCES[J_PRESENT_E_ID], n=sedi.said,
                          s=sedi.sad['s']['$id'], o='I2I'),
            entitlement=dict(d='', u=JOB_NONCES[J_PRESENT_E_ENT], n=permit.said,
                             s=permit.sad['s']['$id'], o='I2I'),
        ),
        kind=kind,
    )
    # Build the compact form of the same presentation so the grant can carry the
    # smaller wire representation while keeping the same SAID.
    presentationCompact = acdcmap(
        israid=ALICE,
        uuid=JOB_NONCES[J_PRESENT_ACDC],
        schema=presentationSchema,
        attribute=dict(d='', u=JOB_NONCES[J_PRESENT_A], i=CLUB,
                       role="crew-member / food-handler",
                       employer="Downtown Burger",
                       submitted="2026-08-04"),
        edge=dict(
            d='',
            u=JOB_NONCES[J_PRESENT_E],
            identity=dict(d='', u=JOB_NONCES[J_PRESENT_E_ID], n=sedi.said,
                          s=sedi.sad['s']['$id'], o='I2I'),
            entitlement=dict(d='', u=JOB_NONCES[J_PRESENT_E_ENT], n=permit.said,
                             s=permit.sad['s']['$id'], o='I2I'),
        ),
        kind=kind,
        compactify=True,
    )

    # Validate every artifact and assert the presentation binds one holder to one
    # identity credential and one entitlement credential.
    assert_acdc_schema_valid(sedi)
    assert_acdc_schema_valid(permit)
    presentationSchemaExpanded = assert_acdc_schema_valid(presentation)
    assert_acdc_schema_valid(presentationCompact, schema=presentationSchemaExpanded)
    assert presentation.said == presentationCompact.said
    assert presentation.sad['i'] == sedi.iseaid == permit.iseaid == ALICE
    assert presentation.sad['e']['identity']['o'] == 'I2I'
    assert presentation.sad['e']['entitlement']['o'] == 'I2I'
    assert sedi.sad['rd'] and permit.sad['rd']
    assert _verify_identity_edge(permit, sedi, sedi.sad['s']['$id'])

    # Build the dp request in breadth-first order from the presentation DAG's
    # origin node. Each entry is a compact triple:
    #   [schema SAID, DAG-absolute path prefix, list of ACDC-relative paths]
    # The _ component is the virtual DAG hop from an edge block to the far ACDC.
    requestedDp = [
        [presentation.sad['s']['$id'], "/", [
            "i",
            "a/i",
            "a/role",
            "a/employer",
            "a/submitted",
        ]],
        [sedi.sad['s']['$id'], "/e/identity/_/", [
            "i",
            "a/i",
            "a/legalName",
            "a/address",
            "a/phone",
            "a/biometric",
        ]],
        [permit.sad['s']['$id'], "/e/entitlement/_/", [
            "i",
            "a/i",
            "a/permitId",
            "a/category",
            "a/status",
            "a/expires",
            "e/identity/n",
            "e/identity/s",
        ]],
    ]

    # Build apply: the employer asks for the origin presentation plus the linked
    # SEDI subset and entitlement using the normalized dp field.
    apply = exchange(
        sender=CLUB,
        receiver=ALICE,
        route="/ipex/apply",
        attributes=dict(
            m="Show the SEDI identity subset and the linked food-handler permit.",
            dp=requestedDp,
        ),
        stamp="2026-08-04T15:00:00.000000+00:00",
        kind=kind,
    )
    # Assert the apply carries the expected dp triples in BFS order:
    # root presentation first, then SEDI, then the permit.
    assert apply.sad['r'] == "/ipex/apply"
    assert apply.sad['a']['dp'] == requestedDp
    assert apply.sad['a']['dp'][0][0] == presentation.sad['s']['$id']
    assert apply.sad['a']['dp'][0][1] == "/"
    assert apply.sad['a']['dp'][1][1] == "/e/identity/_/"
    assert apply.sad['a']['dp'][2][1] == "/e/entitlement/_/"

    # Build offer: Alice commits to the one-time presentation. Because this
    # offer is solicited and does not narrow or widen the request, an empty dp
    # means "same disclosure plan as the apply".
    offer = exchange(
        sender=ALICE,
        receiver=CLUB,
        route="/ipex/offer",
        prior=apply.said,
        attributes=dict(acdc=presentation.said, dp=[]),
        stamp="2026-08-04T15:01:00.000000+00:00",
        kind=kind,
    )
    # Assert the offer binds the apply and still carries no disclosed identity data.
    assert offer.sad['p'] == apply.said
    assert offer.sad['a']['dp'] == []
    assert b"Alice Anders" not in offer.raw
    assert b"220 E 300 S" not in offer.raw
    assert b"+1-801-555-0100" not in offer.raw
    assert b"2000-03-15" not in offer.raw
    assert sedi.said.encode() not in offer.raw
    assert permit.said.encode() not in offer.raw

    # Build agree and sign it with the employer's key. The holder will only
    # disclose once this signed acceptance verifies against captured key state.
    agree = exchange(sender=CLUB, receiver=ALICE, route="/ipex/agree",
                     prior=offer.said, stamp="2026-08-04T15:02:00.000000+00:00",
                     kind=kind)
    employerSig = _SIGNERS[3].sign(ser=agree.raw, index=0)
    signedAgree = messagize(agree, sigers=[employerSig])
    capturedEmployerKeyState = Verfer(qb64=_SIGNERS[3].verfer.qb64)
    # Assert the agree binds the offer and that the captured key state verifies it.
    assert agree.sad['p'] == offer.said
    assert bytes(agree.raw) in signedAgree
    assert capturedEmployerKeyState.verify(sig=employerSig.raw, ser=agree.raw)

    # Reject a signature over the otherwise-correct agree body made by the wrong
    # signer. The bytes come from a real test key, but not the employer's key, so
    # from the employer's perspective it is a forgery.
    wrongSignerSig = _SIGNERS[0].sign(ser=agree.raw, index=0)
    assert not capturedEmployerKeyState.verify(sig=wrongSignerSig.raw, ser=agree.raw)
    # Build and verify a signed spurn to prove that a valid decline still does
    # not count as agreement for unlocking the disclosure.
    spurn = exchange(sender=CLUB, receiver=ALICE, route="/ipex/spurn",
                     prior=offer.said, stamp="2026-08-04T15:02:00.000000+00:00",
                     kind=kind)
    spurnSig = _SIGNERS[3].sign(ser=spurn.raw, index=0)
    assert spurn.sad['r'] != "/ipex/agree"
    assert spurn.sad['p'] == offer.said
    assert capturedEmployerKeyState.verify(sig=spurnSig.raw, ser=spurn.raw)

    # Re-check the real agreement, then prepare the mixed SEDI disclosure: start
    # from the fully compact form and expand only the employment fields.
    assert agree.sad['r'] == "/ipex/agree"
    assert agree.sad['p'] == offer.said
    assert capturedEmployerKeyState.verify(sig=employerSig.raw, ser=agree.raw)
    identityCompactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
    identityCompactor.compact()
    identityCompactor.expand(greedy=True)
    identityDisclosure = dict(identityCompactor.partials[('',)].mad)
    for field in ("legalName", "address", "phone", "biometric"):
        identityDisclosure[field] = sedi.sad['a'][field]
    # Build grant: carry the compact presentation, the partial SEDI disclosure,
    # and the linked entitlement only after a valid agree has been established.
    grant = exchange(
        sender=ALICE,
        receiver=CLUB,
        route="/ipex/grant",
        prior=agree.said,
        attributes=dict(
            acdc=presentationCompact.sad,
            identity=identityDisclosure,
            entitlement=dict(a=dict(permit.sad['a']), e=dict(permit.sad['e'])),
        ),
        stamp="2026-08-04T15:03:00.000000+00:00",
        kind=kind,
    )
    # Assert the grant follows the agree and that only the intended identity
    # subset appears on the wire.
    assert grant is not None
    assert grant.sad['r'] == "/ipex/grant"
    assert grant.sad['p'] == agree.said
    assert b"Alice Anders" in grant.raw
    assert b"220 E 300 S" in grant.raw
    assert b"+1-801-555-0100" in grant.raw
    assert b"face-template-sha256:4d0ff9ce-job-app" in grant.raw
    assert b"2000-03-15" not in grant.raw
    assert b"over21" not in grant.raw and b"over16" not in grant.raw

    # Assert the identity disclosure reveals the requested fields but leaves DOB
    # compacted as a bare SAID, then recompute the section SAID to prove the
    # mixed disclosure still belongs to the committed SEDI credential.
    identityDisc = grant.sad['a']['identity']
    assert identityDisc['i'] == ALICE
    assert isinstance(identityDisc['legalName'], dict)
    assert isinstance(identityDisc['address'], dict)
    assert isinstance(identityDisc['phone'], dict)
    assert isinstance(identityDisc['biometric'], dict)
    assert isinstance(identityDisc['dob'], str)
    identityCheck = Compactor(mad=dict(identityDisc, d=''), makify=True, kind=kind)
    identityCheck.compact()
    assert identityCheck.said == _committed_a_said(sedi, kind)

    # Assert the entitlement disclosure carries the permit data plus the E1E edge
    # that chains the entitlement back to the original SEDI credential.
    entitlementDisc = grant.sad['a']['entitlement']
    assert entitlementDisc['a']['i'] == ALICE
    assert entitlementDisc['a']['permitId'] == "UT-FH-2026-00917"
    assert entitlementDisc['a']['category'] == "food-handler"
    assert entitlementDisc['a']['status'] == "active"
    assert entitlementDisc['e']['identity']['o'] == 'E1E'
    assert entitlementDisc['e']['identity']['n'] == sedi.said
    assert entitlementDisc['e']['identity']['s'] == sedi.sad['s']['$id']

    # Verify the compact presentation the employer received is the exact artifact
    # it previously accepted in the offer/agree exchange.
    assert _club_accepts_grant(grant.sad['a']['acdc'], presentation.said,
                               presentationSchemaExpanded)

    # Build admit to close the exchange after the employer has received the grant.
    admit = exchange(sender=CLUB, receiver=ALICE, route="/ipex/admit",
                     prior=grant.said, stamp="2026-08-04T15:04:00.000000+00:00",
                     kind=kind)
    assert admit.sad['r'] == "/ipex/admit"
    assert admit.sad['p'] == grant.said


if __name__ == "__main__":
    test_source_credentials_and_graduated_disclosure_JSON()
    test_age_identity_edge_E1E_JSON()
    test_bespoke_presentation_acdc_JSON()
    test_gated_ipex_exchange_JSON()
    test_accountability_and_terms_follow_data_JSON()
    test_job_application_entitlement_presentation_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_cpd_serialization_kinds(_kind)
