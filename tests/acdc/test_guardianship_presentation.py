# -*- coding: utf-8 -*-
"""
tests.acdc.test_guardianship_presentation module

Worked, working example of a REPRESENTED PRESENTATION -- a digital guardian presenting a
fact ABOUT a ward to a verifier, under Utah's State-Endorsed Digital Identity law (SEDI,
Utah Code 63A-20). Sibling to tests/acdc/test_cp_disclosure.py and test_examples.py, it
adds the one thing neither shows: a presentation whose HOLDER IS NOT THE SUBJECT.

TWO REGIMES, TWO MODULES, split where Utah Code 63A-20-302(3)(a) splits them: a ward
"unable to apply ... due to the individual's youth or incapacitation" has a guardian who
acts on her behalf. That ward is THIS module's -- seven-year-old Mia, whose father custodies
her keys -- so the invariant is holder != subject, and collapsing the two is the
impersonation failure the prior art warns against (Sovrin "Guardianship in SSI V2"; Aries
RFC 0103). A ward who CAN act is the sibling's -- 17-year-old Cara, in
tests/acdc/test_ward_authz_presentation.py (PR #1577), bounded by an authorization she
presents herself. Bob Carver is the custodial parent in both, and the four bases the schema
below pins are the four in 63A-20-201(3)(b).

Scenario, under Utah's App Store Accountability Act (13-76). Mia holds two SEDI credentials
under her own AID -- an attributive identity credential, and an aggregative age credential
(boolean flags for 13, 16, 18, 21, 55, 65) chained to it by an E1E identity edge -- and can
present neither. Before an app store may let a minor download an app it must obtain
verifiable parental consent (13-76-201(1)(b)) and verify her AGE CATEGORY, the lowest being
"child", under 13 (13-76-101(2)(a)), which the developer uses to set safety defaults at
their most restrictive (13-76-202(3)(a)). Those two facts are all it gets: not Mia's
birthdate, not a standing correlator. Bob presents them, a relying party being required to
accept a presentation by a digital guardian (63A-20-601(1)(e); also 501(1)(e), 401(1)(h)).

NOT CLAIMED: the statutory consent entire. 13-76-101(21) wants an affirmative choice by
someone the store "has verified is an adult", after a parental consent disclosure. The chain
proves more than adulthood -- a recognized guardian over THIS ward -- and the presentation is
the affirmative grant, but the disclosure is only gestured at, the apply carrying a
governance SAID where 13-76-101(18) wants the app's age rating and data practices.

Three edges, three operators, each PINNED by a schema const so a mislabel fails wire
validation. Each is argued where it is built; in brief:

  presentation -> guardian cred  I2I   issuer(near) == issuee(far): Bob holds the authority.
  presentation -> ward's creds   NI2I  Bob is NOT Mia; I2I here would be impersonation.
  ward age -> ward identity      E1E   same subject, different issuers -- an identity
                                       relation, not a delegation (#1515, operator in #1527).

WHERE THE INVARIANT IS ACTUALLY ENFORCED, the panel review's dominant finding: not by NI2I,
which is relationally inert and which verifyChain never uses to bind presenter against ward.
The pins make only the impersonation SHAPE unrepresentable; the guarantee is the binding
logic at _verify_representation, which an implementer must port rather than copy. E1E
carries the sibling's caveat too: not yet in the spec's closed operator set, so a verifier
coercing an unknown operator either rejects this edge or accepts it unchecked (#1515).

WHAT THE DISCLOSURE HIDES. The store learns "an authorized guardian consents, and this user
is under 13" and nothing else -- not the birthdate, the exact age or the name -- since the
aggregate hides the LABELS and block SAIDs of every withheld threshold. What it cannot hide
is the monotone entailment between cumulative thresholds, at _age_ael. IDENTIFIER-level
unlinkability is NOT achieved and is not claimed: the ward's stable AID and the source SAIDs
cross, and the GUARDIAN's AID correlates the same way. That residual is deployment work,
worked out by the test_bulk_issuance_*.py siblings on branch
feat-indep-registry-bulk-issuance. Phase 4 adds what no date can give: a BLINDABLE registry,
so termination is checked at presentation.

TWO DELIBERATE OMISSIONS. No 'powers' edge to a companion delegated-authority credential --
Utah does not want guardianship to depend on one, so the edge section is CLOSED at subject +
authorization, at the cost that 'scope' cannot say which platforms or hours; a guardianship
needing that carries it inline, which is the sibling's subject. And no contractually-
protected disclosure, which is test_cp_disclosure.py's; accountability rests instead on the
governance framework the Rules section names by SAID, itself a PLACEHOLDER digest.

Altitude, as in the siblings: the credential graph, the edge bindings and the registry state
at the data-structure level on real v2 primitives (acdcmap/acdcagg, Aggor, Compactor,
Blinder, exchange), with no Habery/keystore and no verifyChain, which needs a live
Reger/Tevery. Every ACDC validates against a purpose-authored schema; AIDs derive from a
fixed salt.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks, Vrsn_2_0
from keri.core import (Salter, Noncer, Aggor, Compactor, Mapper, Diger, Verfer,
                       exchange, messagize, Codens, Counter, Parser, Texter)
from keri.core.coring import MtrDex
from keri.core.eventing import incept
from keri.core.serdering import SerderACDC
from keri.acdc import regcept, blindate, acdcmap, acdcagg
from keri.core.structing import Blinder


# --- Reproducible example actors (see module docstring). ---
# Five actors, each a self-addressing ('E') transferable AID: its prefix is the SAID
# of an inception event committing to the actor's current signing key and a digest of
# its pre-rotated next key. Ten signers from one fixed salt: _SIGNERS[0..4] are the
# five actors' current signing keys (DGO, endorser, Bob, Mia, service) and
# _SIGNERS[5..9] are their matching pre-rotated next keys.
_SIGNERS = Salter(raw=b'guardworkexamsal').signers(count=10, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


# DGO = Utah's digital-government office (the State endorser/issuer); ENDORSER issues
# the derived age credential; BOB is the custodial parent (guardian); MIA is his
# seven-year-old ward, whose keys he custodies; STORE is the app store provider (the
# relying party). Bob's other child, the 17-year-old who presents for herself, is the
# sibling module's cast.
DGO, ENDORSER, BOB, MIA, STORE = (
    _actor_aid(_SIGNERS[i], _SIGNERS[i + 5]) for i in range(5))

# Per-example blinding nonces, derived (not pasted) from a distinct raw prefix so this
# file shares no nonce values with the sibling examples.
RAWS = [b'guardworkexamra' + b'%0x' % (i,) for i in range(33)]
NONCES = [Noncer(raw=raw).qb64 for raw in RAWS]


def _saidify_schema(mad, kind=Kinds.json):
    """Compute a JSON Schema's SAID and return (said, schema-with-$id).

    Mirrors the sibling examples: run the schema map through a Mapper that
    self-addresses the '$id' field (which must be first, as its position is part of the
    serialization the SAID digests). Mapper deep-copies its input, so the caller's
    schema map is never mutated.
    """
    mapper = Mapper(mad=mad, makify=True, strict=False, saids={"$id": 'E'},
                    saidive=True, kind=kind)
    return mapper.said, mapper.mad


def assert_acdc_schema_valid(acdc, schema=None):
    """Validate a worked-example ACDC against its JSON Schema (Draft 2020-12).

    Identical in intent to the helper in the sibling examples: it proves the schema is
    itself well-formed and that the ACDC instance conforms to the schema it commits to
    in its own 's' section. When the schema section has been compacted to a bare SAID
    string, pass the schema explicitly.
    """
    if schema is None:
        schema = acdc.sad['s']
        if not isinstance(schema, dict):
            raise ValueError("schema section is compacted to a SAID; pass "
                             "schema= (e.g. the expanded ACDC's sad['s'])")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(acdc.sad)
    return schema


# ---------------------------------------------------------------------------
# Purpose-authored JSON Schemas (Draft 2020-12). Authored as maps with "$id" first so
# _saidify_schema can self-address them per wire kind.
# ---------------------------------------------------------------------------

def _disclosable_block(attr, attr_schema, desc):
    """One partially-disclosable block schema: oneOf(block SAID, block detail).

    Whether the block is a nested attribute block (attributive ACDC) or an element of
    an aggregate array, it has one shape -- oneOf(block SAID, {d, u, <attr>}). A
    withheld block travels as its bare SAID and leaks nothing (its own blinding nonce
    'u' means a low-entropy value cannot be brute-forced from the SAID).
    """
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


# acm/acg are fixed-field formats: they always carry (possibly empty) e and r sections
# even when unused, so the schema must admit them.
_EMPTY_OR_SECTION = {"oneOf": [{"type": "string"}, {"type": "object"}]}


def _edge_schema(op_const, desc):
    """One edge schema whose operator is PINNED to a single value (const op_const).

    Pinning the operator in the schema makes the relationship schema-enforced: an
    I2I authority edge, an NI2I ward-data edge, or an E1E identity edge cannot be
    silently swapped for another operator without failing validation.
    """
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


def _edge_schema_enum(desc):
    """An edge schema whose operator is one of I2I / NI2I (the guardian credential's
    subject/authorization edges: I2I when a principal self-designates, else NI2I)."""
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
                                  "enum": ["I2I", "NI2I"]}}}]}


# --- sedi-id: the ward's ATTRIBUTIVE ('acm') identity credential. ---
# Fixed, well-labeled identity fields, so an attribute section with individually
# partially-disclosable nested blocks is the right model (Sam's first-principles
# criterion, PR #1505 conversation): labels give clean paths and clean partial
# disclosure, and the aggregate (unlabeled-array) form buys nothing for a fixed
# labeled set. The issuee 'i' is the WARD (Mia).
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
        "i": {"description": "Issuer (DGO/State) AID", "type": "string"},
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
                     "i": {"description": "Issuee (ward) AID", "type": "string"},
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

# --- sedi-age: the ward's AGGREGATIVE ('acg') age credential. ---
# THIS is where the aggregate (unlabeled-position) form earns its keep (Sam's
# criterion, PR #1505): a homogeneous boolean vector where hiding WHICH thresholds
# are asserted is the whole point -- a poor man's sparse Merkle tree, as mdoc models
# age proofs. Element 0 is the AGID, index-1 carries the issuee 'i' (the ward), and
# the rest are one boolean block per threshold. It REQUIRES an E1E identity edge back
# to the ward's sedi-id (same subject, issuer != issuee), so the identity relation is
# schema-enforced rather than incidental.
AGE_THRESHOLDS = (13, 16, 18, 21, 55, 65)
AGE_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Age Threshold Credential",
    "description": "Derived age credential: a selectively disclosable aggregate of "
                   "boolean flags, one per age threshold, chained to the core "
                   "identity credential by an E1E identity edge.",
    "credentialType": "AgeThresholds",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "A", "e"],
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
                     _disclosable_block("i", {"description": "Issuee (ward) AID",
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

# --- authorization instrument: a minimal birth-certificate credential. ---
# For a custodial-parent guardianship the authority arises from the inherent parental
# right, EVIDENCED by the birth certificate (authorityType: inherentParental, no
# court). The guardian credential's 'authorization' edge points here, grounding the
# authority in a verifiable instrument -- the accountability chain a document-centric
# mDL/ARF flow has no place for. Disclosed whole (a minimal instrument reference).
BIRTHCERT_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Birth Certificate Credential",
    "description": "Vital-records attestation of a parent-child relationship, the "
                   "authorizing instrument for a custodial-parent guardianship.",
    "credentialType": "BirthCertificate",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (DGO vital records) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "u", "i", "child", "parent"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "i": {"description": "Issuee (the child) AID",
                                        "type": "string"},
                                  "child": {"description": "Child AID", "type": "string"},
                                  "parent": {"description": "Parent AID",
                                             "type": "string"}},
                   "additionalProperties": False}]},
        "e": _EMPTY_OR_SECTION,
        "r": _EMPTY_OR_SECTION,
    },
    "additionalProperties": False,
}

# A published SEDI guardianship governance framework, referenced BY SAID (not authored
# here) from the guardian credential's and the presentation's Rules section. The
# fiduciary/holder!=subject/scope-enforcement/dynamic-revocation clauses live in this
# framework. PLACEHOLDER SAID (a bare digest of a description string), standing in for
# the SAID a real deployment computes over the governance document.
GUARDIAN_RULES_SAID = Diger(
    ser=b'SEDI guardianship governance framework v1').qb64

# The coarse statutory scope enum, the same vocabulary the sibling module carries under
# the same field name. Utah prefers LIMITED guardianship, so a verifier checks the
# specific act against scope rather than taking a guardianship credential at face value.
# ('powers' is deliberately NOT this field: in the sibling it is the finer-grained
# DELEGABLE capability set, and one name meaning two things across two examples of the
# same credential type is a trap for anyone reading both.)
SCOPES = ["plenary", "healthCare", "residence", "education", "personalRecords",
          "socialBenefits", "digitalIdentity", "contracts"]

# --- sedi-guardian: Bob's ATTRIBUTIVE ('acm') authority credential, disclosed WHOLE. ---
# The SEDI legal-recognition layer for a digital guardian: the statutory basis, the
# statutory scope (Utah prefers LIMITED guardianship, so scope is explicit), and the
# appointment/registration. HELD BY THE GUARDIAN (issuee = Bob) and names the WARD by
# edge (subject -> Mia's sedi-id) -- the holder != subject invariant. Authority
# credentials are disclosed whole (a verifier needs basis + scope + validity together),
# so the attribute section is flat, not selectively disclosable. Registry-bound (rd):
# guardianship terminates dynamically, so a verifier MUST check current status.
GUARDIAN_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Digital Guardian",
    "description": "SEDI legal-recognition layer for a digital guardian (Utah Code "
                   "63A-20). Attests the statutory basis, the statutory scope, and the "
                   "appointment/registration. Held by the guardian (issuee); the ward "
                   "is named by the subject edge (holder != subject). Registry-bound: "
                   "guardianship terminates dynamically.",
    "credentialType": "SEDI_Guardian",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a", "e", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer = appointing authority (DGO/court/individual)",
              "type": "string"},
        "rd": {"description": "Registry SAID -- MANDATORY (dynamic termination)",
               "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {
            "description": "The recognized guardianship (disclosed whole)",
            "oneOf": [
                {"description": "Attribute Section SAID", "type": "string"},
                {"type": "object",
                 "required": ["d", "u", "i", "basis", "scope", "fiduciary",
                              "recognition", "effectiveDate"],
                 "properties": {
                     "d": {"description": "Section SAID", "type": "string"},
                     "u": {"description": "Section UUID", "type": "string"},
                     "i": {"description": "Issuee = the GUARDIAN's AID "
                                          "(holder != subject)", "type": "string"},
                     "basis": {"description": "Which of the four SEDI statutory bases",
                               "enum": ["designatedRepresentative", "custodialParent",
                                        "courtGuardianMinor",
                                        "courtGuardianIncapacitated"]},
                     "subtype": {"enum": ["financialPOA", "healthCareAgent"]},
                     "scope": {"description": "Coarse statutory scope (Utah prefers "
                                              "LIMITED guardianship)",
                               "type": "array", "minItems": 1, "uniqueItems": True,
                               "items": {"enum": SCOPES}},
                     "fiduciary": {"enum": ["bestInterest", "substitutedJudgment"]},
                     "capacityConditioned": {"type": "boolean"},
                     "residualParentalRights": {"type": "boolean"},
                     "recognition": {
                         "description": "How this authority is recognized and appointed",
                         "type": "object",
                         "required": ["authorityType", "appointingState",
                                      "registrationStatus"],
                         "properties": {
                             "authorityType": {"enum": ["court", "selfExecuted",
                                                        "inherentParental"]},
                             "court": {"type": "string"},
                             "caseNumber": {"type": "string"},
                             "orderDate": {"type": "string", "format": "date"},
                             "lettersReference": {"type": "string"},
                             "instrumentReference": {"type": "string"},
                             "appointingState": {"description": "ISO 3166-2, e.g. US-UT",
                                                 "type": "string"},
                             "registrationStatus": {"enum": ["native", "registeredForeign",
                                                             "transferred"]},
                             "utahRegistrationReference": {"type": "string"},
                         },
                         "additionalProperties": False},
                     "effectiveDate": {"type": "string", "format": "date"},
                     "reviewDueDate": {"type": "string", "format": "date"},
                     "expiryDate": {"type": "string", "format": "date"},
                 },
                 "additionalProperties": False},
            ],
        },
        "e": {
            "description": "Edge section: subject (-> ward sedi-id) + authorization "
                           "(-> instrument)",
            "oneOf": [
                {"type": "string"},
                {"type": "object", "required": ["d", "subject", "authorization"],
                 "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                "subject": _edge_schema_enum("ward's sedi-id"),
                                "authorization": _edge_schema_enum(
                                    "authorizing instrument")},
                 "additionalProperties": False}],
        },
        "r": {"description": "SAID of the SEDI guardianship governance framework",
              "type": "string"},
    },
    "additionalProperties": False,
}

# --- guardian-presentation: Bob's represented-presentation ACDC to the service. ---
# Issuer = Bob (Discloser/guardian), Issuee = the service (Disclosee). It is the
# NEW pattern: a presentation whose holder is not the subject. Its edges pin their
# operators so the holder != subject security property is schema-enforced:
#   authority (I2I) -> Bob's guardian credential (proves Bob holds the authority),
#   wardId  (NI2I)  -> Mia's sedi-id  (Bob is not the subject),
#   wardAge (NI2I)  -> Mia's sedi-age (Bob is not the subject).
# It is deliberately NOT registry-bound (no 'rd'): a one-time presentation is not
# logged. Its Rules section references the guardianship governance framework by SAID.
PRESENTATION_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Guardian Presentation",
    "description": "Represented presentation: a digital guardian (issuer) presenting a "
                   "ward's fact to a verifier (issuee). Holder != subject, enforced by "
                   "pinned edge operators: I2I to the guardian's own authority "
                   "credential, NI2I to the ward's credentials. Not registry-bound.",
    "credentialType": "SEDI_GuardianPresentation",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "s", "a", "e", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer = Discloser (the guardian) AID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object",
                   "required": ["d", "u", "i", "purpose", "occurredAt"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "i": {"description": "Issuee = Disclosee (service)",
                                        "type": "string"},
                                  "purpose": {"type": "string"},
                                  "occurredAt": {"type": "string"}},
                   "additionalProperties": False}]},
        "e": {"description": "Edge Section",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object",
                   "required": ["d", "authority", "wardId", "wardAge"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "authority": _edge_schema(
                                      "I2I", "presenter holds this authority"),
                                  "wardId": _edge_schema(
                                      "NI2I", "ward data, presenter is not subject"),
                                  "wardAge": _edge_schema(
                                      "NI2I", "ward data, presenter is not subject")},
                   "additionalProperties": False}]},
        "r": {"description": "SAID of the SEDI guardianship governance framework",
              "type": "string"},
    },
    "additionalProperties": False,
}

# Registry inception timestamps (the DGO, the endorser, and the guardianship registry).
REG_DGO_STAMP = "2026-01-05T12:00:00.000000+00:00"
REG_ENDORSER_STAMP = "2026-01-06T12:00:00.000000+00:00"
REG_GUARDIAN_STAMP = "2026-01-07T12:00:00.000000+00:00"

# The ward's date of birth, named once so the tests can assert that a WHOLE-disclosed
# authority credential never restates it. Mia is 6.
WARD_DOB = "2020-03-15"

# Fixed timestamps for the IPEX exn messages (kept stable so SAIDs are reproducible).
APPLY_STAMP = "2027-06-15T15:15:00.000000+00:00"
OFFER_STAMP = "2027-06-15T15:16:00.000000+00:00"
AGREE_STAMP = "2027-06-15T15:17:00.000000+00:00"
GRANT_STAMP = "2027-06-15T15:18:00.000000+00:00"
ADMIT_STAMP = "2027-06-15T15:19:00.000000+00:00"


# --- Blinding-nonce / uuid slot allocation: each NONCES[i] used at most once. ---
# sedi-id (attributive): attribute-section uuid + one nonce per nested block + acdc uuid.
N_SEDI_A, N_SEDI_PHOTO, N_SEDI_DOB, N_SEDI_RES, N_SEDI_NAME, N_SEDI_ACDC = 0, 1, 2, 3, 4, 5
# age (aggregative): issuee-block nonce + six flag-block nonces (7..12) + acdc uuid +
# E1E edge-section uuid + E1E edge uuid.
N_AGE_ISSUEE, N_AGE_FLAG0, N_AGE_ACDC, N_AGE_E, N_AGE_E_ID = 6, 7, 13, 14, 15
# registries (DGO id-cred, endorser age-cred, guardianship) + birth-cert (a uuid + acdc).
N_REG_DGO, N_REG_ENDORSER, N_REG_GUARDIAN = 16, 17, 18
N_BC_A, N_BC_ACDC = 19, 20
# guardian credential (attribute uuid, acdc uuid, edge-section uuid, two edge uuids).
N_G_A, N_G_ACDC, N_G_E, N_G_E_SUBJ, N_G_E_AUTH = 21, 22, 23, 24, 25
# presentation (attribute uuid, acdc uuid, edge-section uuid, three edge uuids).
N_P_A, N_P_ACDC, N_P_E, N_P_E_AUTH, N_P_E_ID, N_P_E_AGE = 26, 27, 28, 29, 30, 31
# The IPEX transaction id -- the one slot here that is not a uuid, and the reason the
# table above runs to 33 rather than 32.
N_XID = 32

# The exchange's TRANSACTION ID, carried in the 'x' field of every message in the flow.
# Merged main requires it: IpexHandler.verify (src/keri/acdc/ipexing.py) rejects an apply
# whose 'x' is empty, and every later message must repeat the same value, which is what
# binds six separately-signed messages into one exchange rather than six that merely
# happen to chain by 'p'. The library mints it as the digest of a fresh random nonce
# (Diger(ser=Noncer().qb64b)); this example pins the nonce so the SAIDs stay reproducible,
# which is the only difference.
XID = Diger(ser=NONCES[N_XID].encode()).qb64

# Age aggregate ARRAY positions (A[0] = AGID; A[1] = issuee; A[2..] = the flags).
AGE_ISSUEE = 1
AGE_FLAG0 = 2
AGE_OVER13 = AGE_FLAG0 + AGE_THRESHOLDS.index(13)   # array index of the over-13 flag

# Mia's age at the presentation date (DOB 2020-03-15, presentation 2027-06-15). She is
# under every threshold, and the one the store asks for is the lowest: over13 is False,
# which places her in 13-76's "child" age category (13-76-101(2)(a)) and so sets the
# developer's safety defaults at their most restrictive (13-76-202(3)(a)).
WARD_AGE = 7

# The guardianship registry's blinding salt -- shared ONLY between the DGO (issuer) and
# Bob (the guardian/holder), never handed to the service. Used to blind the per-event
# registry state (Phase 4). The states a guardianship registry event can carry.
GUARDIAN_SALT = Noncer(raw=b'guardregblindsalt').qb64
GUARDIAN_STATES = ['issued', 'revoked']


def _sedi_attr():
    """Mia's sedi-id attribute section (a fresh map each call).

    Attributive: the issuee ('i') is inserted at the top of the section by acdcmap via
    iseaid, and each identity attribute is its own individually-blinded (own 'u'),
    self-addressing (own 'd') nested block, so it can be partially disclosed or withheld
    independently. Mia is six (DOB 2020-03-15); Bob custodies the keys that control the
    AID this credential is issued to, which is why she never presents it herself.
    """
    return dict(d='', u=NONCES[N_SEDI_A],
                photo=dict(d='', u=NONCES[N_SEDI_PHOTO],
                           photo="<state-endorsed-photo-bytes>"),
                dob=dict(d='', u=NONCES[N_SEDI_DOB], dob=WARD_DOB),
                residence=dict(d='', u=NONCES[N_SEDI_RES],
                               residence="Provo UT"),
                name=dict(d='', u=NONCES[N_SEDI_NAME], name="Mia Carver"))


def _age_ael():
    """Mia's age-threshold aggregate element list (a fresh list each call).

    Element 0 is the AGID placeholder; element 1 is the issuee block (i = MIA), which
    is where SerderACDC.iseaid resolves an aggregate issuee from (.sad['A'][1]['i']);
    elements 2.. are one individually-blinded boolean block per AGE_THRESHOLDS entry
    (over<n> = WARD_AGE >= n). Mia is 6, so every flag is False.

    WHAT THE AGGREGATE HIDES HERE, STATED CORRECTLY. It hides the field LABELS and the
    block SAIDs of the undisclosed elements, so the service cannot tell which other
    thresholds exist. What it cannot hide is a logical consequence, and cumulative
    thresholds have one: the flags are a MONOTONE predicate over a single underlying age,
    so disclosing the lowest FALSE threshold entails that every higher one is False too.
    Mia's over13=False therefore settles over16, over18, over21, over55 and over65 as
    well -- which costs nothing here, since the service is being told she is a child, but
    it is the same property the sibling age-vector examples flag in the other direction
    (a 66-year-old disclosing over65 has disclosed the whole vector). An application that
    needs the entailment hidden wants disjoint bands rather than cumulative thresholds,
    at the cost of more blocks per range query. The birthdate and the exact age are what
    this disclosure actually protects, and they stay in the withheld sedi-id block.
    """
    els = ['', dict(d='', u=NONCES[N_AGE_ISSUEE], i=MIA)]
    for offset, n in enumerate(AGE_THRESHOLDS):
        els.append(dict(d='', u=NONCES[N_AGE_FLAG0 + offset],
                        **{f"over{n}": WARD_AGE >= n}))
    return els


def _ward_credentials(kind):
    """Build Mia's two source credentials, registry-bound and schema-validated.

    sedi-id is ATTRIBUTIVE ('acm') with individually partially-disclosable nested
    blocks (issuee at a.i = MIA); age is AGGREGATIVE ('acg') with an array of boolean
    age-threshold flags (issuee at A[1].i = MIA) and one E1E identity edge chaining it
    back to the core sedi-id credential -- an identity relation (same issuee, issuer !=
    issuee), the SEDI 'entitlement chains to the core identity' pattern (disc #1515),
    verified by _verify_identity_edge. Both bind to real registries created via regcept.
    Returns (sedi, age, ageAggor) -- the Aggor lets callers selectively disclose.
    """
    regDgo = regcept(israid=DGO, uuid=NONCES[N_REG_DGO], stamp=REG_DGO_STAMP, kind=kind)
    regEndorser = regcept(israid=ENDORSER, uuid=NONCES[N_REG_ENDORSER],
                          stamp=REG_ENDORSER_STAMP, kind=kind)

    _, sediSchema = _saidify_schema(dict(SEDI_SCHEMA_MAD), kind=kind)
    _, ageSchema = _saidify_schema(dict(AGE_SCHEMA_MAD), kind=kind)

    # sedi-id: attributive; acdcmap inserts the issuee (iseaid -> a.i = MIA).
    sedi = acdcmap(israid=DGO, uuid=NONCES[N_SEDI_ACDC], regid=regDgo.said,
                   schema=sediSchema, attribute=_sedi_attr(), iseaid=MIA, kind=kind)
    # age: aggregative boolean-flag credential, issued by the endorser to Mia, chained
    # back to the core sedi-id with one E1E identity edge. E1E constrains only the issuee
    # (near == far), so it holds though the DGO issues sedi-id and the endorser issues
    # age (issuer != issuee in both) -- the case delegative I2I would wrongly reject.
    ageEdge = dict(d='', u=NONCES[N_AGE_E],
                   identity=dict(d='', u=NONCES[N_AGE_E_ID], n=sedi.said,
                                 s=sedi.sad['s']['$id'], o='E1E'))
    ageAggor = Aggor(ael=_age_ael(), makify=True, kind=kind)
    age = acdcagg(israid=ENDORSER, uuid=NONCES[N_AGE_ACDC], regid=regEndorser.said,
                  schema=ageSchema, aggregate=ageAggor.ael, edge=ageEdge, kind=kind)
    return sedi, age, ageAggor


def _verify_identity_edge(near, far):
    """The example's verifier branch for an E1E identity edge (near -> far).

    E1E binds two credentials to the SAME subject: the near ACDC's issuee AID MUST
    equal the far node's issuee AID, both resolved via SerderACDC.iseaid (so an
    aggregate node's A[1].i reads the same as an attributive a.i). Unlike delegative
    I2I it puts NO constraint on the issuer -- which is why it holds for two credentials
    issued by different third parties to one subject (issuer != issuee), exactly the
    case a coerce-to-I2I verifier (before PR #1527) rejects. Returns True or raises.
    """
    edge = near.sad['e']['identity']
    assert edge['o'] == 'E1E'                          # identity operator
    assert edge['n'] == far.said                       # edge points at this far node
    assert near.iseaid is not None                     # near must be targeted (has issuee)
    assert near.iseaid == far.iseaid                   # same subject: the identity relation
    return True


def _ward_id_disclosure(sedi, kind):
    """Mia's minimal disclosure of sedi-id: reveal the issuee only, withhold every
    identity attribute (photo/dob/residence/name) as a bare SAID.

    For the guardianship presentation the service needs to BIND the ward, not read her
    identity attributes, so nothing but the issuee is revealed -- the minimal disclosure.
    sedi-id is attributive, so disclosure is by compaction: each nested block collapses
    to a SAID and the mix recomputes to the same committed section SAID. (A richer flow
    could reveal a chosen block in full -- test_cp_disclosure.py reveals the photo that
    way -- but a guardian binding a ward discloses nothing beyond the issuee.)
    """
    compactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
    compactor.compact()
    compactor.expand(greedy=True)          # populates .partials (incl. the compact one)
    return dict(compactor.partials[('',)].mad)


def _disclose(acdc, kind, attribute=None, aggregate=None):
    """Rebuild `acdc` as the partial disclosure carrying `attribute` or `aggregate`.

    THE reason a disclosure can be verified at all. An ACDC's SAID is computed over its
    MOST COMPACT form, so every partial mix of the same sections commits to the same
    'd'. Handing the service a credential whose attribute section is compacted to the
    issuee, or whose aggregate is disclosed at two indices, hands it something that still
    recomputes to the credential SAID the edges point at -- which is what lets the service
    run the binding on what it received instead of on what it was told.

    Both ilks are covered, because this DAG has both: acdcmap for the attributive nodes
    and acdcagg for the aggregative age credential. Passing neither section discloses it
    whole, which is the right call for a FLAT section (see _guardian_attr).
    """
    sad = acdc.sad
    edge = json.loads(json.dumps(sad['e'])) if 'e' in sad else None
    # The schema rides as a BARE SAID, not as the whole block. The disclosee named that
    # SAID in its own dp, so it already has the schema; shipping the block back would be
    # pure bulk -- and worse than bulk on an aggregative credential, because the block
    # enumerates the field names of every withheld element. Sending it would tell the
    # service which age thresholds this credential carries, which is exactly what
    # _age_disclosure says the disclosure does not reveal.
    schema = sad['s']['$id'] if isinstance(sad['s'], dict) else sad['s']
    if 'A' in sad:
        return acdcagg(israid=sad['i'], uuid=sad.get('u'), regid=sad.get('rd'),
                       schema=schema,
                       aggregate=json.loads(json.dumps(aggregate if aggregate is not None
                                                       else sad['A'])),
                       edge=edge, rule=sad.get('r'), kind=kind)
    return acdcmap(israid=sad['i'], uuid=sad.get('u'), regid=sad.get('rd'),
                   schema=schema,
                   attribute=json.loads(json.dumps(attribute if attribute is not None
                                                   else sad['a'])),
                   iseaid=acdc.iseaid, edge=edge, rule=sad.get('r'), kind=kind)


def _nest(serder):
    """Wrap one disclosed artifact as a V2 nested substream the parser will accept.

    Shape borrowed from tests/acdc/test_ipexing.py, which round-trips the same construct:
    a non-CESR body is enclosed in a NonNativeBodyGroup, and an artifact with no
    attachments of its own still needs an empty AttachmentGroup so the parser can tell
    where the substream ends.
    """
    body = bytes(serder.raw)
    if serder.kind != Kinds.cesr:
        body = Counter.enclose(qb64=Texter(raw=body).qb64b,
                               code=Codens.NonNativeBodyGroup, version=Vrsn_2_0)
    empty = Counter.enclose(qb64=b'', code=Codens.ControllerIdxSigs, version=Vrsn_2_0)
    nested = bytearray(body)
    nested.extend(Counter.enclose(qb64=empty, code=Codens.AttachmentGroup,
                                  version=Vrsn_2_0))
    return Counter.enclose(qb64=nested, code=Codens.BodyWithAttachmentGroup,
                           version=Vrsn_2_0)


def _far(byDigest, near, label):
    """The far node of `near`'s `label` edge, looked up by the digest the edge names."""
    said = near.sad['e'][label]['n']
    assert said in byDigest             # the DAG the origin commits to must be complete
    return byDigest[said]


def _service_accepts_grant(grantStream, offeredOrigin):
    """The service's grant-time verification, run on WHAT CAME OFF THE WIRE.

    Returns True or raises. Takes the signed grant STREAM -- body plus attachments -- and
    nothing else, so there is no way for a credential the service already held to stand
    in for one it was sent.

    Four things happen in order:

      1. Parse. Every nested artifact is reaped and self-verified as it is parsed: the
         SAID is recomputed over the disclosed content, using most-compact-form semantics
         so a partial disclosure verifies to the same 'd' as the full credential. A
         tampered payload dies here, and takes the whole stream with it.
      2. Confirm the origin is the presentation the OFFER committed to. Without this the
         service could be handed a different, perfectly valid presentation than the one
         whose terms it agreed to -- terms follow the data. The offer attached that same
         origin compacted to a metadata ACDC, so this is the artifact the service already
         read, arriving expanded; merged main would have allowed the two to be different
         ACDCs entirely, and then there would be nothing here to check.
      3. WALK THE DAG from that origin to find every other node, edge by edge, matching
         each edge's digest against the parsed artifacts. This is what the `o` field buys
         over the bespoke labels it replaced: the service is no longer trusting the
         DISCLOSER'S choice of key names to tell it which artifact is the authority and
         which is the ward's. It reads that from Bob's own edges, which he committed to
         when he minted the presentation. A substituted far node breaks the digest that
         names it.
      4. Run the five-check binding on the artifacts that walk produced.

    Registry status is the sixth check a complete verifier adds, and Phase 4 exercises it
    live: guardianship terminates dynamically, so the blindable registry must show the
    guardian credential currently issued.
    """
    ims = bytearray(grantStream)
    results = Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, processive=False)
    # A nested artifact whose SAID does not recompute over its content voids the WHOLE
    # stream -- the parser returns nothing rather than handing back the good artifacts
    # and dropping the bad one, so a tampered credential cannot be quietly ignored.
    assert results and len(results) == 1
    result = results[0]
    assert result.serder.sad['r'] == "/ipex/grant"
    assert result.serder.sad['a']['o'] == [offeredOrigin]   # terms follow the data
    byDigest = {nest.serder.said: nest.serder for nest in result.nests}

    origin = byDigest[offeredOrigin]
    authority = _far(byDigest, origin, 'authority')     # presentation -I2I-> guardianship
    wardId = _far(byDigest, origin, 'wardId')           # presentation -NI2I-> sedi-id
    wardAge = _far(byDigest, origin, 'wardAge')         # presentation -NI2I-> age
    return _verify_representation(origin, authority, wardId, wardAge)


def _age_disclosure(ageAggor):
    """Mia's selective disclosure of the age credential: reveal the issuee + the
    over-13 flag (False), withhold every other threshold as a bare SAID.

    The store learns she is under 13, which is the fact that fixes her 13-76 age category,
    and learns neither her birthdate nor her exact age. It does
    NOT learn which other thresholds this credential carries, though it can infer their
    values by monotonicity -- see _age_ael. The disclosure verifies against the committed
    AGID.
    """
    disclosed, _ = ageAggor.disclose(indices=[AGE_ISSUEE, AGE_OVER13])
    return disclosed


def _committed_a_said(acdc, kind):
    """The SAID an ACDC commits to for its attribute section (its most-compact form)."""
    compactor = Compactor(mad=dict(acdc.sad['a']), makify=True, kind=kind)
    compactor.compact()
    return compactor.said


def _birth_certificate(kind):
    """The authorizing instrument: a minimal birth-certificate credential (DGO -> Mia)
    naming Bob as parent and Mia as child. The guardian credential's authorization edge
    points here, grounding a custodial-parent guardianship in a verifiable instrument."""
    regDgo = regcept(israid=DGO, uuid=NONCES[N_REG_DGO], stamp=REG_DGO_STAMP, kind=kind)
    _, bcSchema = _saidify_schema(dict(BIRTHCERT_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[N_BC_A], child=MIA, parent=BOB)
    return acdcmap(israid=DGO, uuid=NONCES[N_BC_ACDC], regid=regDgo.said,
                   schema=bcSchema, attribute=attribute, iseaid=MIA, kind=kind)


def _guardian_registry(kind):
    """The guardianship registry inception (rip event). Guardianship terminates
    dynamically, so the guardian credential is bound to a registry a verifier checks;
    Phase 4 blinds its per-event state so status checks leak no correlatable log."""
    return regcept(israid=DGO, uuid=NONCES[N_REG_GUARDIAN], stamp=REG_GUARDIAN_STAMP,
                   kind=kind)


def _guardian_attr():
    """Bob's guardian-credential attribute section (a fresh map each call).

    Disclosed whole (flat, not selectively disclosable): a verifier needs basis + scope
    + validity together. basis = custodialParent (inherent parental right, no court);
    scope limited to digitalIdentity (managing/presenting the ward's digital identity);
    recognition names the inherent-parental authority type and Utah as appointing state.

    DATE HYGIENE, and it is not cosmetic. Because this credential is disclosed WHOLE, every
    date in it reaches the verifier, and a date about the guardianship can silently be a date
    about the WARD. An earlier revision set effectiveDate to the date the parental right
    arose, which for a custodial parent IS the ward's birthdate -- so the example handed the
    service Mia's exact date of birth in the same exchange where it claims the service gets
    only an under-13 predicate. effectiveDate is now the date the State recorded the
    relationship, which is what a verifier actually needs (when this authority became
    checkable) and is not derived from the ward at all.

    The remaining leak is structural and is asserted rather than hidden. A minor
    guardianship expires at majority, so expiryDate is Mia's 18th birthday and the service
    can subtract 18 to recover her birth month and day. Nothing in the represented-
    presentation shape fixes that: the date is load-bearing for the verifier (is this
    authority still valid?) and derived from the ward. Mitigations are deployment-level --
    coarsen to the month or year of majority, or move validity entirely into the registry so
    no date ships at all. test_guardian_authority_credential_JSON asserts the residual is
    present so it cannot regress into being forgotten, and the sibling module carries the
    same residual on its own guardianship credential.
    """
    return dict(d='', u=NONCES[N_G_A],
                basis="custodialParent",
                scope=["digitalIdentity"],
                fiduciary="bestInterest",
                residualParentalRights=True,
                recognition=dict(authorityType="inherentParental",
                                 appointingState="US-UT",
                                 registrationStatus="native"),
                effectiveDate="2020-04-02",    # State recorded it, NOT Mia's birthdate
                expiryDate="2038-03-15")       # majority; leaks her birth month/day, see above


def _guardian_credential(kind, sedi=None, birthCert=None, reg=None):
    """Bob's SEDI digital-guardian credential (DGO -> Bob), registry-bound, schema-valid.

    HELD BY BOB (issuee), naming Mia ONLY by the subject edge (holder != subject). The
    subject edge is NI2I -- Bob is not Mia's issuee, so it is a reference, not a
    same-holder delegation. The authorization edge (NI2I) points at the birth
    certificate that evidences the parental right. Disclosed whole. The Rules section
    ('r') references the SEDI guardianship governance framework by SAID.
    """
    if sedi is None:
        sedi, _, _ = _ward_credentials(kind)
    if birthCert is None:
        birthCert = _birth_certificate(kind)
    if reg is None:
        reg = _guardian_registry(kind)
    _, schema = _saidify_schema(dict(GUARDIAN_SCHEMA_MAD), kind=kind)
    edge = dict(d='', u=NONCES[N_G_E],
                subject=dict(d='', u=NONCES[N_G_E_SUBJ], n=sedi.said,
                             s=sedi.sad['s']['$id'], o='NI2I'),
                authorization=dict(d='', u=NONCES[N_G_E_AUTH], n=birthCert.said,
                                   s=birthCert.sad['s']['$id'], o='NI2I'))
    return acdcmap(israid=DGO, uuid=NONCES[N_G_ACDC], regid=reg.said,
                   schema=schema, attribute=_guardian_attr(), iseaid=BOB,
                   edge=edge, rule=GUARDIAN_RULES_SAID, kind=kind)


# ---------------------------------------------------------------------------
# Phase 1: the ward's two source credentials, each with the disclosure it fits.
# ---------------------------------------------------------------------------
def test_ward_credentials_and_graduated_disclosure_JSON():
    """Phase 1: Mia's two source credentials and the E1E identity edge between them.

    Mia holds two ACDCs under one holder AID (MIA), each registry-bound and validated
    against a purpose-authored JSON Schema, each using the disclosure mechanism that
    fits its data:

      * sedi-id -- issued by the DGO as an ATTRIBUTIVE ('acm') identity credential; the
        issuee is a.i = MIA and each attribute is an individually-blinded nested block.
      * age -- issued by the endorser as an AGGREGATIVE ('acg') credential: an array of
        boolean age-threshold flags (issuee at A[1].i = MIA), chained to sedi-id by an
        E1E identity edge (same subject, issuer != issuee).

    The load-bearing claims: the E1E edge verifies (near issuee == far issuee) where a
    coerce-to-I2I verifier would reject it; a guardian can later disclose the under-13
    predicate while withholding the birthdate and every other threshold label; and both
    disclosures are tamper-evident.
    """
    kind = Kinds.json
    sedi, age, ageAggor = _ward_credentials(kind)

    # sedi-id: ATTRIBUTIVE identity credential, registry-bound, schema-valid.
    assert sedi.ilk == Ilks.acm
    assert sedi.sad['i'] == DGO                     # issued by the DGO (State)
    assert sedi.sad['rd'] == "ECwS8218O0JA_faclrOZSOL8vBzCOHY9dWPNBtrgcXwz"  # DGO registry
    assert sedi.sad['a']['i'] == MIA                # attributive issuee (the ward)
    assert sedi.iseaid == MIA
    assert sedi.said == "ECW-D3niTR0H4A4IjU52PMUtaNxIBvx-Ttpvsf9HXVK3"
    assert_acdc_schema_valid(sedi)

    # age: AGGREGATIVE boolean-flag credential, registry-bound, schema-valid.
    assert age.ilk == Ilks.acg
    assert age.sad['i'] == ENDORSER                 # issued by the endorser
    assert age.sad['rd'] == "EEX6XlR5J5fSs7CfXuxv-jPI28OKpkHYkwGgpBEA_RdW"  # endorser registry
    assert age.sad['A'][AGE_ISSUEE]['i'] == MIA     # aggregative issuee (the ward)
    assert age.iseaid == MIA
    assert age.said == "ECXgaqGNlsllMnqOTSdis9ZE9a9lhRHGzY8cCq07eTeN"
    # Mia is 6, so every flag is False -- the disclosed over-13 flag is the one the
    # store asks for, and by monotonicity it settles all the others.
    assert age.sad['A'][AGE_OVER13]['over13'] is False                   # under 13
    assert not any(el[f"over{n}"] for n, el
                   in zip(AGE_THRESHOLDS, age.sad['A'][AGE_FLAG0:]))
    ageSchema = assert_acdc_schema_valid(age)

    # The E1E identity edge binds age to sedi-id as the SAME subject (Mia), though the
    # DGO issues one and the endorser the other (issuer != issuee) -- the case E1E
    # exists for and the delegative I2I rejects.
    assert age.sad['e']['identity']['o'] == 'E1E'
    assert _verify_identity_edge(age, sedi)

    # Schema teeth: a non-boolean threshold flag is rejected; a missing E1E edge is
    # rejected (the identity relation is schema-required, not incidental).
    badA = list(age.sad['A'])
    badA[AGE_OVER13] = dict(badA[AGE_OVER13], over13="yes")
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(dict(age.sad, A=badA))
    with pytest.raises(ValidationError):
        Draft202012Validator(ageSchema).validate(dict(age.sad, e={"d": age.sad['e']['d']}))

    # --- The guardian's minimal disclosure of the ward's sedi-id: issuee only. ---
    idDisc = _ward_id_disclosure(sedi, kind)
    assert idDisc['i'] == MIA                              # issuee present (binds the ward)
    assert isinstance(idDisc['dob'], str)                  # birthdate withheld (bare SAID)
    assert isinstance(idDisc['name'], str)                 # name withheld
    assert "2020-03-15" not in json.dumps(idDisc)          # birthdate never on the wire
    assert "Mia Carver" not in json.dumps(idDisc)          # name never on the wire
    committedA = _committed_a_said(sedi, kind)
    check = Compactor(mad=dict(idDisc, d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == committedA                        # disclosure belongs to sedi-id

    # --- Selective disclosure of age: reveal over13 + issuee, hide the rest. ---
    ageDisc = _age_disclosure(ageAggor)
    assert ageDisc[0] == ageAggor.agid                     # AGID anchor
    assert ageDisc[AGE_ISSUEE]['i'] == MIA                 # issuee revealed
    assert ageDisc[AGE_OVER13]['over13'] is False          # under-13 revealed
    over18Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(18)
    assert isinstance(ageDisc[over18Pos], str)             # over-18 flag withheld (SAID)
    # Privacy: no other threshold block crosses the wire, so the service cannot tell
    # which other thresholds this credential even carries. It CAN infer their values by
    # monotonicity (see _age_ael); what it cannot recover is the birthdate or the age.
    assert "over18" not in json.dumps(ageDisc)
    assert "over21" not in json.dumps(ageDisc)
    assert "over65" not in json.dumps(ageDisc)
    assert Aggor.verifyDisclosure(ageDisc, kind=kind)
    # Tamper evidence: altering the revealed flag breaks AGID verification.
    tampered = list(ageDisc)
    tampered[AGE_OVER13] = dict(ageDisc[AGE_OVER13], over13=True)
    assert not Aggor.verifyDisclosure(tampered, kind=kind)


# ---------------------------------------------------------------------------
# Phase 2: Bob's SEDI digital-guardian credential -- holder != subject.
# ---------------------------------------------------------------------------
def test_guardian_authority_credential_JSON():
    """Phase 2: Bob's guardian credential names Mia only by edge (holder != subject).

    The SEDI digital-guardian credential is HELD BY THE GUARDIAN (issuee = Bob) and
    names the ward ONLY by the subject edge (-> Mia's sedi-id). This is the invariant
    that keeps guardianship transparent representation, never impersonation: a verifier
    can always tell a guardian -- not the ward -- is acting.

    Asserted here: the issuee is Bob and NOT Mia (holder != subject, structurally); the
    subject edge is NI2I (a reference, not a same-holder delegation -- Bob is not Mia's
    issuee) and points at Mia's sedi-id; the authority is grounded in an authorizing
    instrument (the birth certificate) via the authorization edge; the credential is
    registry-bound (dynamic termination) and disclosed whole; and the schema enforces
    the statutory shape (a bad basis, an empty scope list, a bad recognition block, or
    an edge other than subject/authorization are rejected).
    """
    kind = Kinds.json
    sedi, _, _ = _ward_credentials(kind)
    birthCert = _birth_certificate(kind)
    reg = _guardian_registry(kind)
    guardian = _guardian_credential(kind, sedi=sedi, birthCert=birthCert, reg=reg)

    assert guardian.ilk == Ilks.acm
    assert guardian.sad['i'] == DGO                 # issued by the DGO
    assert guardian.sad['a']['i'] == BOB            # HELD BY THE GUARDIAN (issuee = Bob)
    assert guardian.iseaid == BOB
    # holder != subject: the credential's issuee is Bob, and the ward is Mia, named
    # only by edge. This is the load-bearing invariant, asserted structurally.
    assert guardian.iseaid != sedi.iseaid           # Bob is not the ward
    assert guardian.said == "EK_489biyH5Mvt_VIpCsObT3fe7jSVptG3i5OrlEp5xA"
    assert guardian.sad['e']['subject']['n'] == sedi.said       # ward named by edge
    assert guardian.sad['e']['subject']['o'] == 'NI2I'          # reference, not delegation
    assert guardian.sad['e']['authorization']['n'] == birthCert.said   # authority grounded
    assert birthCert.said == "EOh4FrcZ1XkRkg8HGjhDsoInt35bTb0ZuvfchkWl6uql"  # the instrument
    # Registry-bound (dynamic termination) and disclosed whole (flat attribute section).
    assert reg.said == "EIilAhmBAyNgcoAMe1YLBLtu5eu1_j2jDtZZxV_9IN5B"        # guardianship reg
    assert guardian.sad['rd'] == reg.said
    assert guardian.sad['a']['basis'] == "custodialParent"
    assert guardian.sad['a']['scope'] == ["digitalIdentity"]
    assert guardian.sad['a']['recognition']['authorityType'] == "inherentParental"

    # --- Date hygiene in a WHOLE-disclosed authority credential (see _guardian_attr). ---
    # effectiveDate MUST NOT be the ward's birthdate: for a custodial parent the date the
    # right arose is exactly her DOB, and this credential ships entire, so setting it that
    # way would hand the service the birthdate the whole example exists to withhold.
    assert guardian.sad['a']['effectiveDate'] != WARD_DOB
    # The residual, asserted PRESENT rather than hidden: a minor guardianship expires at
    # majority, so expiryDate is derived from the ward and leaks her birth month and day.
    # Deployment-level mitigations only -- coarsen the date, or carry validity solely in
    # the registry. This assertion exists so the leak cannot be quietly forgotten.
    assert guardian.sad['a']['expiryDate'] == "2038-03-15"
    assert guardian.sad['a']['expiryDate'][5:] == WARD_DOB[5:]      # month/day recoverable

    # The Rules section references the SEDI guardianship governance framework by SAID.
    assert guardian.sad['r'] == GUARDIAN_RULES_SAID
    schema = assert_acdc_schema_valid(guardian)

    # Schema teeth: a bad basis, an empty scope list, and a bad recognition authority
    # type are each rejected -- the statutory shape is machine-checked.
    badBasis = json.loads(json.dumps(guardian.sad))
    badBasis['a']['basis'] = "selfAppointed"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(badBasis)
    emptyScope = json.loads(json.dumps(guardian.sad))
    emptyScope['a']['scope'] = []
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(emptyScope)
    badAuth = json.loads(json.dumps(guardian.sad))
    badAuth['a']['recognition']['authorityType'] = "vibes"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(badAuth)
    # The edge section is closed at subject + authorization: any other edge (here the
    # 'powers' edge an external delegated-authority credential would have hung off, which
    # is exactly the credential the sibling module makes its origin) is rejected, so the
    # guardian credential carries no hook to one.
    extraEdge = json.loads(json.dumps(guardian.sad))
    extraEdge['e']['powers'] = dict(d='', n=sedi.said, s=sedi.sad['s']['$id'], o='NI2I')
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(extraEdge)


PRESENT_STAMP = "2027-06-15T15:18:00.000000+00:00"


def _represented_presentation(kind, guardian, sedi, age, compactify=False):
    """Bob's represented-presentation ACDC to the service (helper for Phase 3+).

    Issuer = Bob (Discloser/guardian), Issuee = the service (Disclosee). It carries no
    ward PII in its own attributes -- just the purpose and time -- and references the
    credential graph by edge:
      authority (I2I)  -> Bob's guardian credential  (proves Bob holds the authority),
      wardId   (NI2I)  -> Mia's sedi-id             (Bob is NOT the subject),
      wardAge  (NI2I)  -> Mia's sedi-age            (Bob is NOT the subject).
    Deliberately NOT registry-bound (no 'rd'): a one-time presentation is not logged.
    The Rules section references the guardianship governance framework by SAID.
    """
    _, schema = _saidify_schema(dict(PRESENTATION_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[N_P_A], i=STORE,
                     purpose="Consent to an app download for a ward in the child age "
                             "category, per Utah Code 13-76-201(1)(b).",
                     occurredAt=PRESENT_STAMP)
    edge = dict(d='', u=NONCES[N_P_E],
                authority=dict(d='', u=NONCES[N_P_E_AUTH], n=guardian.said,
                               s=guardian.sad['s']['$id'], o='I2I'),
                wardId=dict(d='', u=NONCES[N_P_E_ID], n=sedi.said,
                            s=sedi.sad['s']['$id'], o='NI2I'),
                wardAge=dict(d='', u=NONCES[N_P_E_AGE], n=age.said,
                             s=age.sad['s']['$id'], o='NI2I'))
    return acdcmap(israid=BOB, uuid=NONCES[N_P_ACDC], schema=schema,
                   attribute=attribute, edge=edge, rule=GUARDIAN_RULES_SAID,
                   kind=kind, compactify=compactify)


def _verify_representation(presentation, guardian, wardSedi, wardAge,
                           scope="digitalIdentity"):
    """The verifier's binding for a represented presentation -- the security property.

    A represented presentation authorizes disclosure only if ALL of these hold; each is
    a distinct link in the accountability chain. It is THIS app-layer binding -- not the
    NI2I operator, which is relationally inert -- that enforces holder != subject; the
    schema const-pins only reject the mis-labeled impersonation SHAPE at validation.
    Returns True or raises AssertionError. (Two checks a complete verifier adds are out
    of scope at this altitude: the guardian issuer's trust-root/authority-competence and
    each edge's 's' far-node schema constraint -- see the module docstring.)

      1. Authority (I2I): the presentation's issuer holds the authority credential its
         'authority' edge points at -- issuer(presentation) == issuee(guardian), the
         I2I same-holder constraint (resolved via SerderACDC.iseaid).
      2. Subject binding: the guardian credential's own subject edge names THIS ward's
         sedi-id -- so the authority is over the ward actually being presented, not some
         other ward.
      3. Ward data (NI2I), holder != subject: the ward-data edges are NI2I and the
         presenter is NOT the ward's issuee. An I2I ward edge would demand
         presenter == subject (impersonation); the schema pins these to NI2I, and this
         asserts the invariant structurally.
      4. Scope: the requested action falls within the guardian's 'scope' (Utah prefers
         LIMITED guardianship, so a verifier MUST check the specific act against scope).
      5. Identity (E1E): the disclosed age flag is the ward's own -- the age credential
         and the sedi-id name the same subject (via _verify_identity_edge).

    A complete verifier performs a 6th check -- registry status -- exercised in Phase 4:
    guardianship terminates dynamically, so the guardian credential's blindable registry
    must show it currently issued, not revoked.
    """
    e = presentation.sad['e']
    # (1) authority I2I: presenter holds the authority.
    assert e['authority']['o'] == 'I2I'
    assert e['authority']['n'] == guardian.said
    assert presentation.sad['i'] == guardian.iseaid            # issuer == guardian issuee
    # (2) subject binding: the authority is over THIS ward.
    assert guardian.sad['e']['subject']['n'] == wardSedi.said
    # (3) ward data NI2I, holder != subject.
    assert e['wardId']['o'] == 'NI2I' and e['wardId']['n'] == wardSedi.said
    assert e['wardAge']['o'] == 'NI2I' and e['wardAge']['n'] == wardAge.said
    assert presentation.sad['i'] != wardSedi.iseaid            # presenter is not the ward
    assert presentation.sad['i'] != wardAge.iseaid
    # (4) scope: requested action within the statutory scope.
    assert scope in guardian.sad['a']['scope']
    # (5) identity E1E: the disclosed age flag is the ward's own.
    assert _verify_identity_edge(wardAge, wardSedi)
    return True


# ---------------------------------------------------------------------------
# Phase 3: the represented presentation -- guardian mediates, holder != subject.
# ---------------------------------------------------------------------------
def test_represented_presentation_JSON():
    """Phase 3: Bob presents on Mia's behalf; the verifier binds authority to ward.

    Bob issues a represented-presentation ACDC to the service (Issuer = Bob, Issuee =
    the service). This is the NEW pattern: a presentation whose HOLDER IS NOT THE
    SUBJECT, distinct from the self-presentation the sibling examples show -- including
    tests/acdc/test_ward_authz_presentation.py, where a ward old enough to act presents
    an authorization issued to her, and Bob is a node in the DAG rather than a party to
    the exchange. Its three edges carry three operators, and the binding
    (_verify_representation) is the security property: I2I proves Bob holds the
    authority; NI2I marks the ward's data as someone else's (Bob is not the subject);
    E1E proves the disclosed age flag is the ward's. The service can therefore tell --
    and prove later -- that a GUARDIAN, not the child, is acting.

    The load-bearing guardrail is asserted two ways: the schema PINS the ward-data edges
    to NI2I (an I2I ward edge -- the impersonation shape -- is rejected), and the binding
    fails if the authority does not actually cover THIS ward. The presentation runs as a
    gated IPEX exchange so the ward's under-13 disclosure crosses the wire only in the
    grant, after the service accepts -- and the grant delivers the presentation expanded,
    with the guardian credential beside it, so the service can run the scope check its
    own apply asked for rather than being told the answer. The offer attaches the SAME
    presentation compacted to a metadata ACDC, so the store agrees to terms it can read
    without being handed the answer first.
    """
    kind = Kinds.json
    sedi, age, ageAggor = _ward_credentials(kind)
    guardian = _guardian_credential(kind, sedi=sedi)
    presentation = _represented_presentation(kind, guardian, sedi, age)

    assert presentation.ilk == Ilks.acm
    assert presentation.sad['i'] == BOB           # Bob is the Issuer (guardian/Discloser)
    assert presentation.sad['a']['i'] == STORE    # the store is the Issuee (Disclosee)
    assert 'rd' not in presentation.sad           # one-time presentation, not logged
    assert presentation.sad['r'] == GUARDIAN_RULES_SAID   # governance by SAID
    assert presentation.said == "EKb3szYoKJYQjPr4nPWsz__4nWdCgsy3EmZqTjWYjP6S"

    # The full binding holds for the honest presentation.
    assert _verify_representation(presentation, guardian, sedi, age)
    # holder != subject, stated plainly: the presenter is Bob, the subject is Mia.
    assert presentation.sad['i'] == BOB and sedi.iseaid == MIA

    # Private ACDC: compact and expanded forms share one SAID; the schema enforces the
    # pinned edge operators.
    compact = _represented_presentation(kind, guardian, sedi, age, compactify=True)
    assert compact.said == presentation.said
    assert isinstance(presentation.sad['e'], dict)     # sections inline...
    assert isinstance(compact.sad['e'], str)           # ...vs. collapsed to a SAID
    schema = assert_acdc_schema_valid(presentation)
    assert_acdc_schema_valid(compact, schema=schema)

    # --- Guardrail 1 (schema): an I2I ward-data edge -- the impersonation shape -- is
    # rejected. The schema pins wardId/wardAge to const "NI2I". ---
    impersonation = json.loads(json.dumps(presentation.sad))
    impersonation['e']['wardId']['o'] = 'I2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(impersonation)

    # --- Guardrail 2 (binding): the authority must cover THIS ward. A presentation whose
    # guardian credential is over a DIFFERENT ward fails point (2), even though every
    # edge is well-formed. ---
    otherSediMad = dict(SEDI_SCHEMA_MAD)
    _, otherSchema = _saidify_schema(otherSediMad, kind=kind)
    otherWard = acdcmap(israid=DGO, uuid=NONCES[N_SEDI_ACDC], regid=_guardian_registry(kind).said,
                        schema=otherSchema, attribute=_sedi_attr(), iseaid=STORE, kind=kind)
    with pytest.raises(AssertionError):
        _verify_representation(presentation, guardian, otherWard, age)

    # --- The gated IPEX exchange: the ward's age flag crosses only in the grant. ---
    #
    # Every verb below carries a human-readable 'm' in its attribute block, and that is
    # not a courtesy. IpexHandler.verify rejects any IPEX exn whose 'a' section has no
    # 'm' (src/keri/acdc/ipexing.py), and handle() passes it straight to the notifier, so
    # a verb without one is a step in the flow that no human can be shown. The strings
    # below are written to be read in that notification rather than as labels for code.
    #
    # 1. apply (service -> Bob): the challenge -- which schemas and which fields.
    #
    # It carries the ANCHORED-EXCHANGE field 'ax' in the attribute block (#1613), as a
    # LIST of booleans -- one element per DAG, and this presentation is a single DAG
    # (#1627's "Use Required Lists", the same shape as the grant's 'o' for the same
    # reason). The value is False, and the field is present-and-false rather than absent
    # so its shape is visible: #1613 treats a missing 'ax' as no anchoring requirement,
    # so the two are equivalent here.
    #
    # False is the honest value. A truthy 'ax' would oblige Bob to anchor the grant in
    # his own KEL, and this module is data-structure-level throughout -- there is no KEL
    # to anchor in. Note also that #1613's MANDATORY anchoring rule does not fire here:
    # it binds when an ACDC in the DAG signals a presentation-anchor registry via 'rd'
    # and 'i' at the top level of its ATTRIBUTE block, and no credential in this graph
    # carries 'rd' there -- the presentation deliberately has no 'rd' at all, being a
    # one-time artifact that is never logged.
    #
    # It does NOT name a governance framework. An earlier draft carried the guardianship
    # rules SAID here as 'g' and again in the offer as 'governance', which was two labels
    # for a pointer the presentation already publishes in its own rules section (asserted
    # above: presentation.sad['r'] == GUARDIAN_RULES_SAID). Jurisdiction and safe-harbor
    # belong in the ACDC 'r' section, not on the exchange (@ryan-hansen, #1595). If a
    # disclosee ever needs to state a governance REQUIREMENT -- a different claim from
    # the issuer's assertion, and one that could disagree with it -- that is a field to
    # define in #1595 rather than a label to reuse here.
    #
    # The field-level ask rides the disclosure-paths `dp` field of the QUERY section
    # `q` (exchange(modifiers=...)), as an ORDERED LIST of (schemaSAID, prefix, [paths])
    # triples -- the construct settled in WebOfTrust/keripy discussion #1549, shared with
    # tests/acdc/test_cp_disclosure.py and test_bulk_issuance_shared_registry.py.
    # A dict keyed by schema SAID cannot express a DAG holding two credentials of the
    # same schema.
    #
    # The middle element is a path PREFIX: the DAG-absolute route to the ACDC that the
    # entry's schema SAID names. It is either the empty string or a route that both
    # begins and ends with '/', and the effective path is prefix + entry concatenated
    # with no delimiter inserted, so an entry in the path list never begins with '/'
    # (@SmithSamuelM, #1549).
    #
    # Every prefix here is EMPTY, which leaves the entry paths ACDC-RELATIVE: with no
    # prefix naming it, an entry's ACDC is identified by the entry's POSITION, so the
    # list runs breadth-first from the origin node and the zeroth entry is the origin.
    # That breadth-first ordering is required even where a non-empty prefix would make
    # it technically unnecessary (@SmithSamuelM, #1549). Every node this DAG reaches is
    # asked for something here, so the list is gapless -- one entry per node, in
    # breadth-first order -- and each entry's ACDC is unambiguous without restating the
    # route to it. (The sibling's list is a gapless list's opposite number: nothing is
    # asked of the guardian's own citizen credential there, so its entries are an ordered
    # SUBSET, which works only because each entry still names its own schema SAID.)
    #
    # A '/'-rooted prefix would make the effective paths DAG-ABSOLUTE, rooted at the
    # origin node, and an absolute path reaching a non-origin ACDC must cross the edge
    # that links it -- the virtual '_' component, standing for the jump from the
    # near-side edge block to the top level of the far-side ACDC (@SmithSamuelM, #1549).
    # The same request written with non-empty prefixes reads:
    #     origin:   "/"                 ["i", "a/i"]
    #     guardian: "/e/authority/_/"   ["a/i", "a/scope"]
    #     ward id:  "/e/wardId/_/"      ["a/i"]
    #     ward age: "/e/wardAge/_/"     ["A/i", "A/over13"]
    #
    # A represented presentation is the case that makes the joining paths load-bearing.
    # The service asks three nodes for an issuee: the guardian credential (a/i -- who is
    # acting), the ward's sedi-id (a/i -- who is being spoken for) and the ward's age
    # credential (A/i -- whose fact is being asserted). The last two must MATCH and the
    # first must DIFFER, which is the holder != subject split expressed in paths. It is
    # the guardianship edge, not issuee equality, that licenses Bob to speak for Mia --
    # the exact inverse of the sibling, where the ward presents for herself and the
    # origin's issuee and the citizen credential's issuee are required to be equal.
    #
    # The zeroth entry is the DAG's origin node (#1549): Bob's presentation. Its schema
    # is governance even though Bob issues it -- "in all of these applications the
    # Applicant would know the schema of the origin node despite it being a presenter
    # issued ACDC" (@SmithSamuelM, #1542) -- so the service can name it in a
    # first-contact apply. It asks the origin for issuer and issuee -- which in a
    # represented presentation is the first place the holder != subject split shows: the
    # origin's issuer is Bob, and the ward never appears in it at all -- plus the edge
    # section, without which nothing else in the DAG is reachable.
    #
    # EVERY ENTRY IS DERIVED FROM WHAT THE BINDING READS. Walking
    # _verify_representation's five checks and asking what each one consults is what
    # produces this list; anything the binding does not read is not requested, and
    # anything it does read must be requested, or the check cannot run on what arrives.
    # Two consequences worth naming. 'e' is asked of the origin and of the age credential
    # because checks (1), (3) and (5) each read an edge digest. And the guardian
    # credential is asked for its WHOLE attribute section rather than a/i and a/scope
    # individually: _guardian_attr is FLAT by design, and a flat section discloses whole
    # or as one bare SAID with nothing in between, so a field list would name paths that
    # credential cannot produce.
    #
    presentSchemaSaid, _ = _saidify_schema(dict(PRESENTATION_SCHEMA_MAD), kind=kind)
    apply = exchange(sender=STORE, receiver=BOB, route="/ipex/apply", xid=XID,
                     modifiers=dict(dp=[[presentSchemaSaid, "", ["i", "a/i", "e"]],
                                        [guardian.sad['s']['$id'], "", ["i", "a", "e"]],
                                        [sedi.sad['s']['$id'], "", ["a/i"]],
                                        [age.sad['s']['$id'], "",
                                         ["A/i", "A/over13", "e"]]]),
                     attributes=dict(m="Prove a consenting digital guardian and the "
                                       "ward's age category.",
                                     ax=[False]),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['r'] == "/ipex/apply" and apply.sad['i'] == STORE
    # The apply OPENS the flow, so it mints the transaction id and carries no prior.
    assert apply.sad['x'] == XID and apply.sad['p'] == ""
    assert apply.sad['ri'] == BOB               # ...and names its receiver explicitly
    dp = apply.sad['q']['dp']
    assert [entry[0] for entry in dp] == [presentSchemaSaid, guardian.sad['s']['$id'],
                                          sedi.sad['s']['$id'], age.sad['s']['$id']]
    assert all(len(entry) == 3 for entry in dp)             # (schemaSAID, prefix, [paths])
    assert [entry[1] for entry in dp] == ["", "", "", ""]   # no prefixes: paths stay relative
    assert dp[0][2] == ["i", "a/i", "e"]        # origin: who presents, to whom, and edges
    assert dp[1][2] == ["i", "a", "e"]          # guardian cred: flat 'a', so whole; + edges
    assert dp[2][2] == ["a/i"]                  # ward sedi-id: the binding, nothing more
    assert dp[3][2] == ["A/i", "A/over13", "e"] # ward age cred: whose, the flag, + edges
    assert all(not p.startswith("/") and not p.endswith("/")
               for _, _, paths in dp for p in paths)
    assert 'disclose' not in apply.sad['a'] and set(apply.sad['a']) == {'m', 'ax'}
    assert 'g' not in apply.sad['a']            # governance lives in ACDC rules
    assert apply.sad['a']['ax'] == [False]      # unanchored exchange (#1613, #1627)
    assert apply.said == "ELFQ5HP1btm1yGt4QbRWvOCbrUQmbS_C0jrCqZadjbvr"

    # 2. offer (Bob -> service): commits ONLY to the Discloser's own presentation SAID
    # -- attaching that presentation in its compact form, below -- and binds the apply.
    # It deliberately does NOT enumerate the
    # issuer-committed source-credential SAIDs (guardian/sedi/age): those are issuer
    # commitments, and attaching them before the service agrees would let a verifier
    # spurn and walk away with stable ward/guardian correlators, defeating the
    # metadata-ACDC decorrelation (panel review, PRV-F2). They arrive only post-agree, in
    # the grant, which delivers the presentation EXPANDED so its edge section is readable.
    #
    # What the one SAID this offer does commit to costs is nothing, and that is a
    # property of the represented shape rather than of care taken here: the presentation
    # is minted for this exchange, so a service that spurns holds a digest that will
    # never be seen again. The sibling cannot say the same -- there the ward offers the
    # SAID of a durable credential her guardian issued her, which is identical on every
    # presentation she ever makes, so a spurning platform keeps a usable handle on her.
    # Its query block carries `dp` as an EMPTY list: the offer is SOLICITED (its `p`
    # binds the apply), and an empty `dp` means "the same paths the apply asked for"
    # (#1549), so Bob restates nothing and the two messages cannot drift. That is also
    # what the merged helper does -- ipexing.offer() defaults modifiers['dp'] to [] --
    # so the two agree without either restating the paths.
    #
    # The origin rides in the `o` field, NOT the V1 label `acdc`, which #1629 removed
    # from the offer's attribute block (tests/acdc/test_ipexing.py asserts "acdc" is
    # absent). It is written as a ONE-ELEMENT LIST for the same reason the grant's is,
    # and the two are deliberately the same shape: one entry per DAG, and this
    # presentation is a single DAG. Merged main's validator wants a bare string and
    # rejects the list; that divergence is deliberate and is recorded at the grant.
    #
    # THE ORIGIN IS ATTACHED, not merely named. Merged verify requires an offer to carry
    # at least one nested artifact whose SAID matches `a.o`, so naming a digest the
    # disclosee cannot resolve is no longer a well-formed offer. What rides here is the
    # presentation COMPACTIFIED -- the metadata ACDC of Sam's review on #1629: least
    # disclosure, with the rules section visible so the disclosee agrees to terms it can
    # see. An ACDC commits to its MOST COMPACT form, so this recomputes to
    # presentation.said and costs the offer nothing it was not committing to already.
    #
    # WHAT THE COMPACT FORM SHOWS is the issuer (Bob), the schema SAID -- which the
    # service itself named in the apply, so it already holds the schema -- and the rules
    # SAID. The governance half of Sam's requirement is met here for free rather than by
    # care taken: this presentation's `r` is ALREADY a bare SAID (GUARDIAN_RULES_SAID, a
    # placeholder digest for the framework), so it rides identically in both forms and
    # there was never a rules block to withhold.
    #
    # WHAT IT WITHHOLDS is the edge section and the attribute section, and the second is
    # the judgment call. The edge section must go: it names the guardian, sedi-id and age
    # SAIDs, and the PRV-F2 argument above is exactly the case for keeping those off a
    # message a service can spurn. The attribute section is FLAT -- like _guardian_attr it
    # discloses whole or as one bare SAID, with nothing in between -- so there is no
    # partial to choose, and disclosing it whole would put the presentation's `purpose`
    # string on the wire pre-agree. That string says the ward is in the CHILD age
    # category, which is the very answer this gate exists to hold back until the service
    # accepts; a store that spurned would walk away with the under-13 predicate it never
    # agreed to receive. So it is withheld, and what the service agrees to is Bob, this
    # schema, this governance framework: a thinner statement of terms than the purpose
    # text would give, and the one that keeps the gate honest.
    #
    # Merged main PERMITS a wholly different artifact here -- test_ipexing.py's
    # test_ipex_v2_offer_metadata_origin_can_differ_from_grant_origin offers one metadata
    # ACDC and grants another, with unequal `o` fields. This example declines that
    # freedom. _service_accepts_grant checks that the grant's origin is the one the OFFER
    # committed to, and that check is only worth running when the two are the same
    # artifact; a separate metadata ACDC would leave the store agreeing to terms attached
    # to nothing it ever receives.
    offerOrigin = _represented_presentation(kind, guardian, sedi, age, compactify=True)
    assert offerOrigin.said == presentation.said       # same origin, less of it
    offer = exchange(sender=BOB, receiver=STORE, route="/ipex/offer", prior=apply.said,
                     xid=XID, modifiers=dict(dp=[]),
                     attributes=dict(m="Here is the guardian's presentation for the ward.",
                                     o=[presentation.said], ax=[False]),
                     stamp=OFFER_STAMP, kind=kind)
    bobSigner = _SIGNERS[2]                            # the guardian's establishing key
    offerStream = messagize(offer, sigers=[bobSigner.sign(ser=offer.raw, index=0)],
                            nests=[_nest(offerOrigin)], framed=False, gvrsn=Vrsn_2_0)
    assert offer.sad['p'] == apply.said and offer.sad['x'] == XID
    assert offer.sad['q']['dp'] == []                  # solicited: "as per the apply"
    assert 'governance' not in offer.sad['a']          # ...and not on the exchange
    assert 'acdc' not in offer.sad['a']                # the V1 label is gone (#1629)
    assert set(offer.sad['a']) == {'m', 'o', 'ax'}
    assert offer.sad['a']['o'] == [presentation.said]
    assert offer.sad['a']['ax'] == [False]             # Bob agrees: no anchoring
    assert offer.said == "ELVe0HCg5gJO8Fw8xsbyGloJ945zxdL525evDLjrcFNh"

    # What the service can read off the offer, decoded rather than grepped -- the nested
    # body rides Texter-encoded, so a substring check on the raw stream proves nothing.
    # The nested artifact must SAID-match the `o` the body names -- one entry, one nest --
    # or merged verify refuses the offer.
    offerParsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(offerStream), framed=False,
                                                 processive=False)[0]
    assert [nest.serder.said for nest in offerParsed.nests] == offer.sad['a']['o']
    onOffer = offerParsed.nests[0].serder
    assert onOffer.sad['i'] == BOB                     # who will present
    assert onOffer.sad['s'] == presentSchemaSaid       # the schema the apply named
    assert isinstance(onOffer.sad['a'], str)           # purpose withheld...
    assert isinstance(onOffer.sad['e'], str)           # ...and the DAG withheld with it
    offerDecoded = bytes(offer.raw) + b"".join(bytes(nest.serder.raw)
                                               for nest in offerParsed.nests)
    assert presentation.said.encode() in offerDecoded  # the origin, and a one-time one
    assert GUARDIAN_RULES_SAID.encode() in offerDecoded  # the terms, visible pre-agree
    # ...and nothing else. The issuer commitments are behind the origin's compacted edge
    # section, so a service that spurns here holds a digest and no correlator (PRV-F2).
    assert guardian.said.encode() not in offerDecoded
    assert sedi.said.encode() not in offerDecoded
    assert age.said.encode() not in offerDecoded
    assert b"Mia Carver" not in offerDecoded and b"2020-03-15" not in offerDecoded  # no PII
    assert b"child age category" not in offerDecoded   # nor the answer the gate holds back

    # 3. agree (service -> Bob): acceptance, binding the offer SAID and signed by the
    # service (via messagize -- the blessed genus-aware attachment path). The store is
    # agreeing to terms it could actually read: it resolved the offer's `o` against the
    # artifact attached to it, above, before sending this.
    agree = exchange(sender=STORE, receiver=BOB, route="/ipex/agree", prior=offer.said,
                     xid=XID, attributes=dict(m="Agreed; disclose."),
                     stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said and agree.sad['x'] == XID
    assert agree.said == "EI1_PhyDRFJ_A59IaE1yw_9LP5u-waDHD3Iv5e1M8fEi"
    svcSigner = _SIGNERS[4]                             # the service's establishing key
    svcSig = svcSigner.sign(ser=agree.raw, index=0)
    signedAgree = messagize(agree, sigers=[svcSig])
    assert bytes(agree.raw) in signedAgree
    capturedKeyState = Verfer(qb64=svcSigner.verfer.qb64)
    assert capturedKeyState.verify(sig=svcSig.raw, ser=agree.raw)

    # 4. The gate: Bob discloses only when handed a valid, signed, offer-binding agree.
    #
    # THE DISCLOSED ARTIFACTS DO NOT RIDE IN 'a'. The attribute block carries only the
    # origin, and the credentials themselves are nested attachments on the signed grant
    # stream (#1595's V2 table: 'e' embeds dropped, "nested attachments, not embeds").
    # The disclosures are the four the dp list asked for, each cut to the depth its entry
    # named; the ORDER they are attached in carries no meaning, because the service finds
    # each one by following an edge digest rather than by position or label.
    #
    # The presentation itself rides EXPANDED, and that is load-bearing rather than
    # incidental: handing over a COMPACTIFIED presentation would satisfy the offer's
    # promise in form only, since with the edge section collapsed to a bare SAID there is
    # nothing for the service to walk, and the scope check its own apply asked for could
    # never run.
    disclosures = [
        # dp[0] ["i", "a/i", "e"] -- the origin, edges visible so they can be walked;
        # dp[1] ["i", "a", "e"] -- flat section, so disclosed whole.
        _disclose(presentation, kind),
        _disclose(guardian, kind),
        # dp[2] ["a/i"] -- nested section compacted to the issuee; dp[3]
        # ["A/i", "A/over13", "e"] -- aggregate disclosed at exactly two indices. Each
        # still rides as a CREDENTIAL rather than a bare section, so the service can tie
        # it to the edge digest that names it.
        _disclose(sedi, kind, _ward_id_disclosure(sedi, kind)),
        _disclose(age, kind, aggregate=_age_disclosure(ageAggor)),
    ]

    def disclose(agreeMsg, sig, keyState, nests=None):
        if not (agreeMsg.sad['r'] == "/ipex/agree" and agreeMsg.sad['p'] == offer.said
                and agreeMsg.sad['x'] == XID
                and keyState.verify(sig=sig.raw, ser=agreeMsg.raw)):
            return None, None
        nests = nests if nests is not None else disclosures
        serder = exchange(sender=BOB, receiver=STORE, route="/ipex/grant",
                          prior=agreeMsg.said, xid=XID,
                          attributes=dict(m="The disclosure you agreed to.",
                                          o=[presentation.said], ax=[False]),
                          stamp=GRANT_STAMP, kind=kind)
        bobSig = bobSigner.sign(ser=serder.raw, index=0)        # the discloser signs
        return serder, messagize(serder, sigers=[bobSig],
                                 nests=[_nest(d) for d in nests],
                                 framed=False, gvrsn=Vrsn_2_0)

    # A forged signature or a spurn (decline) unlocks nothing.
    assert disclose(agree, _SIGNERS[0].sign(ser=agree.raw, index=0),
                    capturedKeyState) == (None, None)
    spurn = exchange(sender=STORE, receiver=BOB, route="/ipex/spurn", prior=offer.said,
                     xid=XID, attributes=dict(m="Declined."),
                     stamp=AGREE_STAMP, kind=kind)
    assert disclose(spurn, svcSigner.sign(ser=spurn.raw, index=0),
                    capturedKeyState) == (None, None)
    # ...and neither does an agree from a DIFFERENT exchange, however well signed: the
    # transaction id is what says which conversation a message belongs to.
    strayAgree = exchange(sender=STORE, receiver=BOB, route="/ipex/agree",
                          prior=offer.said, xid=Diger(ser=b'another exchange').qb64,
                          attributes=dict(m="Agreed; disclose."),
                          stamp=AGREE_STAMP, kind=kind)
    assert disclose(strayAgree, svcSigner.sign(ser=strayAgree.raw, index=0),
                    capturedKeyState) == (None, None)

    # The valid agree unlocks the grant; the ward's age flag appears only now, and
    # the birthdate and every other threshold stay off the wire.
    grant, grantStream = disclose(agree, svcSig, capturedKeyState)
    assert grant is not None and grant.sad['p'] == agree.said
    assert grant.sad['x'] == XID == apply.sad['x']     # one exchange, six messages
    assert grant.said == "EF3Ea2BEdyLyTH6tE6kxSrJu3sx-IbO2gFBDNe5Rs2g5"
    # The attribute block is the origin and nothing else: a ONE-ELEMENT LIST, which is
    # #1627's "Use Required Lists" form. That option is preferred there over a field map
    # precisely because `dp` is already a list, so writing the single-DAG case as a list
    # now is what keeps this example from needing a second edit when DAG soup lands.
    # RECORDED DIVERGENCE FROM MERGED MAIN: #1629 landed 'o' as a scalar string, and
    # IpexHandler.verify rejects a list. The list is written here because #1627 is where
    # the shape is being decided and this is a worked example of that shape; the
    # reconciliation is being argued in that discussion rather than papered over here.
    granted = grant.sad['a']
    assert granted == dict(m="The disclosure you agreed to.",
                           o=[presentation.said], ax=[False])   # #1595, #1613, #1627
    assert isinstance(granted['o'], list) and len(granted['o']) == 1   # one DAG
    # The offer and the grant name the SAME origin, in the same field and the same shape.
    # That equality is what lets _service_accepts_grant say "terms follow the data": the
    # store is handed the DAG it agreed to, not merely a DAG.
    assert granted['o'] == offer.sad['a']['o']

    # The credentials are on the stream, not in the body -- one artifact per dp entry,
    # each disclosed to the requested depth and each still carrying the SAID of the FULL
    # credential, because an ACDC commits to its most compact form. That is what makes a
    # partial disclosure verifiable, and what ties it to the edge that names it.
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(grantStream), framed=False,
                                            processive=False)[0]
    onWire = {nest.serder.said: nest.serder.sad for nest in parsed.nests}
    assert set(onWire) == {presentation.said, guardian.said, sedi.said, age.said}
    assert onWire[age.said]['A'][AGE_OVER13]['over13'] is False       # under-13 disclosed
    assert onWire[sedi.said]['a']['i'] == MIA                         # ward bound (issuee)
    # The PII checks run against the DECODED bodies rather than the stream: a nested
    # non-CESR body rides Texter-encoded (base64) inside a NonNativeBodyGroup, so a
    # plaintext substring check on grantStream would pass without proving anything. This
    # is everything the service can read after parsing, the grant body included.
    decoded = bytes(grant.raw) + b"".join(bytes(nest.serder.raw) for nest in parsed.nests)
    assert b"2020-03-15" not in decoded                               # birthdate withheld
    assert b"over18" not in decoded and b"over21" not in decoded      # thresholds withheld
    # The service receives exactly what its apply asked of the guardian credential --
    # who is acting, and how far the authority runs -- so it can run the scope check
    # itself rather than taking the presentation's word for it.
    assert onWire[guardian.said]['a']['i'] == BOB
    assert onWire[guardian.said]['a']['scope'] == ["digitalIdentity"]
    # The edge section rides expanded, so the source SAIDs the offer withheld are
    # reachable now and only now -- which is what the offer's comment promises.
    assert isinstance(onWire[presentation.said]['e'], dict)
    assert guardian.said.encode() in decoded
    assert sedi.said.encode() in decoded and age.said.encode() in decoded
    # Honest residual, asserted present rather than quietly avoided: the guardian
    # credential's expiry -- Mia's 18th birthday -- crosses the wire and hands the service
    # her birth month and day. The cause is structural and is named in the dp comment
    # above: _guardian_attr is FLAT, so its section discloses whole or not at all, and the
    # service's request could not have asked for less. Compare sedi-id in this same grant,
    # whose nested section DOES split. See _guardian_attr for why the mitigations are
    # deployment-level, and the sibling module for the same residual.
    assert b"2038-03-15" in decoded

    # The service now runs the same binding a verifier runs anywhere -- on the stream it
    # RECEIVED, reparsed from scratch, not on anything it knew before.
    assert _service_accepts_grant(grantStream, presentation.said)

    # ...and the negatives that prove the acceptance is reading the wire. Each of these
    # would pass unnoticed if the service verified credentials it already held.
    # (a) A guardian credential over a DIFFERENT ward, substituted into the disclosed set.
    # It is a perfectly valid ACDC and it parses; the origin's authority edge names the
    # real guardian credential, which is now missing from the stream, so the walk stops.
    otherGuardian = _guardian_credential(kind, sedi=otherWard)
    _, swapped = disclose(agree, svcSig, capturedKeyState,
                          nests=[disclosures[0], otherGuardian] + disclosures[2:])
    with pytest.raises(AssertionError):
        _service_accepts_grant(swapped, presentation.said)
    # (b) An origin that is not the presentation the offer committed to.
    with pytest.raises(AssertionError):
        _service_accepts_grant(grantStream, guardian.said)
    # (c) A tampered payload. The forged guardian credential keeps the real one's 'd' but
    # widens the scope, so its SAID no longer recomputes over its content. It is refused
    # as it is parsed, and it voids the entire stream -- the service gets no artifacts at
    # all rather than three good ones and a silent gap.
    forged = json.loads(json.dumps(disclosures[1].sad))
    forged['a']['scope'] = ["digitalIdentity", "healthCare"]
    forgedAcdc = SerderACDC(sad=forged, makify=False, verify=False)
    assert forgedAcdc.said == guardian.said            # it still CLAIMS to be Bob's
    _, tampered = disclose(agree, svcSig, capturedKeyState,
                           nests=[disclosures[0], forgedAcdc] + disclosures[2:])
    with pytest.raises(AssertionError):
        _service_accepts_grant(tampered, presentation.said)

    # 5. admit (service -> Bob): closes the exchange.
    admit = exchange(sender=STORE, receiver=BOB, route="/ipex/admit", prior=grant.said,
                     xid=XID,
                     attributes=dict(m="Received; consent and age category accepted."),
                     stamp=ADMIT_STAMP, kind=kind)
    assert admit.sad['p'] == grant.said and admit.sad['x'] == XID
    assert admit.said == "EKkQtb8tJmyTku143Mds3VqS1KPWwh3fltAzoP88ha3N"

    # Every message in the flow carries a human-readable 'm' and the one transaction id.
    # Merged main requires both: IpexHandler.verify rejects any IPEX message whose
    # attribute block has no 'm', and rejects an apply whose 'x' is empty.
    for msg in (apply, offer, agree, grant, admit, spurn):
        assert msg.sad['a']['m'] and msg.sad['x'] == XID


# ---------------------------------------------------------------------------
# Phase 4: dynamic revocation (blindable registry) + provable accountability.
# ---------------------------------------------------------------------------
def _guardian_status(event, guardianSaid, sn):
    """Unblind a guardianship-registry event to its state ('issued' | 'revoked').

    The bup event on the wire carries only the blinded state's SAID (blid); the guardian
    (holder), who shares the registry salt with the DGO (issuer), unblinds the event at
    presentation so the verifier can confirm current status. The salt is never handed to
    the verifier, so the verifier -- watching the public registry -- cannot itself READ
    the state word (issued/revoked). It does NOT follow that the ward is fully
    uncorrelatable: the bup event's existence, count, sequence, and timestamps stay
    public, so a per-guardianship registry (as modeled here) still leaks WHEN a
    guardianship was terminated. Full temporal decorrelation needs placeholder
    pre-issuance, continued blind updates after revocation, and a shared-herd registry
    (panel review, PRV-F3); this example demonstrates the state-blinding, not that.
    """
    unblinder = Blinder.unblind(said=event.sad['b'], acdc=guardianSaid,
                                states=GUARDIAN_STATES, salt=GUARDIAN_SALT, sn=sn)
    return unblinder.state


def test_revocation_and_accountability_JSON():
    """Phase 4: the guardianship is checked live (blindable), and the act is attributable.

    Guardianship terminates dynamically -- majority, restored capacity, death, court
    order -- so a verifier MUST check current registry status, not merely trust the
    dates in the credential. This uses a BLINDABLE registry: each state update (bup)
    carries only a blinded SAID, so a verifier watching the public registry cannot tell
    issued from revoked (no correlatable log of the ward), yet the guardian, holding the
    registry salt, can unblind the current event to prove status at presentation.

    Two things are shown. First, the status gate: while the guardianship is 'issued' the
    presentation is honored; once the DGO records a 'revoked' update, the current event
    unblinds to 'revoked' and the presentation MUST be refused -- even before any stated
    expiry date. Second, provable accountability: because the credential names BOB as
    issuee and the ward only by edge, the verifier attributes the act to BOB (a specific
    guardian AID) through a verifiable chain -- presentation (issuer Bob) -I2I-> guardian
    credential (subject edge) -> the ward -- an accountability trail no document-centric
    mDL/ARF flow carries.
    """
    kind = Kinds.json
    sedi, age, _ = _ward_credentials(kind)
    reg = _guardian_registry(kind)
    guardian = _guardian_credential(kind, sedi=sedi, reg=reg)
    presentation = _represented_presentation(kind, guardian, sedi, age)

    # --- Issued: the DGO binds the guardian credential into its registry (bup). ---
    issuedBlinder = Blinder.blind(acdc=guardian.said, state='issued',
                                  salt=GUARDIAN_SALT, sn=1)
    issued = blindate(regid=reg.said, prior=reg.said, blid=issuedBlinder.said,
                      sn=1, stamp="2026-01-07T12:05:00.000000+00:00", kind=kind)
    assert issued.ilk == Ilks.bup
    assert issuedBlinder.said == "EPzyaHXPUd8NWjK-ig9Eh1nSvOyTAFLfSgQqmExpF7vV"
    assert issued.said == "EDFrYNwV7d-GH5-t0abLRz-AoMPXszt5ILfDl2_Kskzt"
    assert issued.sad['b'] == issuedBlinder.said
    # Privacy: the state word and the guardian SAID never appear on the wire; only the
    # blinded SAID rides in the bup event.
    assert b"issued" not in issued.raw
    assert guardian.said.encode() not in issued.raw
    # The guardian unblinds the current event to prove 'issued'; the presentation binds
    # AND the status is current, so the service honors it.
    assert _guardian_status(issued, guardian.said, sn=1) == 'issued'
    assert _verify_representation(presentation, guardian, sedi, age)

    # --- Revoked: the DGO records a second update; status flips before any expiry. ---
    revokedBlinder = Blinder.blind(acdc=guardian.said, state='revoked',
                                   salt=GUARDIAN_SALT, sn=2)
    revoked = blindate(regid=reg.said, prior=issued.said, blid=revokedBlinder.said,
                       sn=2, stamp="2026-05-01T09:00:00.000000+00:00", kind=kind)
    assert revoked.said == "EDYR2V-oyZsuCwI9b-aaLLY_HMg9P4pA0HGxaKHGau0M"
    assert revoked.sad['p'] == issued.said          # chains onto the issuance update
    assert _guardian_status(revoked, guardian.said, sn=2) == 'revoked'
    # The credential graph still binds (edges are immutable), but a verifier that checks
    # current status MUST refuse: a terminated guardianship confers no authority.
    def status_gated(currentEvent, sn):
        bindsOk = _verify_representation(presentation, guardian, sedi, age)
        return bindsOk and _guardian_status(currentEvent, guardian.said, sn) == 'issued'
    assert status_gated(issued, 1) is True          # honored while issued
    assert status_gated(revoked, 2) is False        # refused once revoked

    # --- Provable accountability: the act is attributable to the GUARDIAN, not the ward.
    # holder != subject is structural, so the verifier reads a verifiable chain from a
    # specific human/guardian AID (Bob) to the ward -- and can prove afterward WHO acted.
    assert presentation.sad['i'] == BOB                         # a guardian acted...
    assert presentation.sad['i'] != sedi.iseaid                 # ...NOT the ward
    assert presentation.sad['e']['authority']['n'] == guardian.said
    assert guardian.sad['a']['i'] == BOB                        # the authority is Bob's
    assert guardian.sad['e']['subject']['n'] == sedi.said       # over this ward


# ---------------------------------------------------------------------------
# Phase 5: the invariants hold across every serialization kind.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_guardianship_serialization_kinds(kind):
    """Phases 1-4 invariants hold across every serialization kind, not just JSON.

    Exercises the same flows -- the attributive ward sedi-id, the aggregative age
    credential with its E1E identity edge, the disclosed-whole guardian credential
    (holder != subject), the represented presentation with its I2I/NI2I edges and the
    full binding, and the blindable-registry status gate -- over CESR (the native KERI
    wire format) and CBOR/MGPK, asserting the behavioral invariants without pinning
    per-kind SAIDs. (The no-PII-on-the-wire checks are JSON-specific: the CESR wire form
    base64-encodes the payload, so a plaintext substring check does not apply.)
    """
    sedi, age, ageAggor = _ward_credentials(kind)
    assert sedi.ilk == Ilks.acm and age.ilk == Ilks.acg and sedi.kind == kind
    assert sedi.sad['rd'] and age.sad['rd']                    # registry-bound on every kind
    assert_acdc_schema_valid(sedi)
    assert_acdc_schema_valid(age)
    assert _verify_identity_edge(age, sedi)                    # E1E holds on every kind

    # Selective disclosure of age: reveal the over-13 flag, withhold the rest; verifies
    # via AGID.
    ageDisc = _age_disclosure(ageAggor)
    assert ageDisc[AGE_OVER13]['over13'] is False
    assert Aggor.verifyDisclosure(ageDisc, kind=kind)

    # Guardian credential: holder != subject, registry-bound, disclosed whole, schema-valid.
    guardian = _guardian_credential(kind, sedi=sedi)
    assert guardian.iseaid == BOB and guardian.iseaid != sedi.iseaid
    assert guardian.sad['e']['subject']['n'] == sedi.said
    assert guardian.sad['e']['subject']['o'] == 'NI2I'
    assert_acdc_schema_valid(guardian)

    # Represented presentation: full binding holds; compact == expanded SAID; schema-valid.
    presentation = _represented_presentation(kind, guardian, sedi, age)
    compact = _represented_presentation(kind, guardian, sedi, age, compactify=True)
    assert presentation.said == compact.said
    assert _verify_representation(presentation, guardian, sedi, age)
    schema = assert_acdc_schema_valid(presentation)
    assert_acdc_schema_valid(compact, schema=schema)

    # Blindable-registry status gate: issued honored, revoked refused.
    reg = _guardian_registry(kind)
    guardian = _guardian_credential(kind, sedi=sedi, reg=reg)
    issuedBlinder = Blinder.blind(acdc=guardian.said, state='issued', salt=GUARDIAN_SALT, sn=1)
    issued = blindate(regid=reg.said, prior=reg.said, blid=issuedBlinder.said, sn=1,
                      stamp="2026-01-07T12:05:00.000000+00:00", kind=kind)
    assert _guardian_status(issued, guardian.said, sn=1) == 'issued'
    revokedBlinder = Blinder.blind(acdc=guardian.said, state='revoked', salt=GUARDIAN_SALT, sn=2)
    revoked = blindate(regid=reg.said, prior=issued.said, blid=revokedBlinder.said, sn=2,
                       stamp="2026-05-01T09:00:00.000000+00:00", kind=kind)
    assert _guardian_status(revoked, guardian.said, sn=2) == 'revoked'


if __name__ == "__main__":
    test_ward_credentials_and_graduated_disclosure_JSON()
    test_guardian_authority_credential_JSON()
    test_represented_presentation_JSON()
    test_revocation_and_accountability_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_guardianship_serialization_kinds(_kind)
