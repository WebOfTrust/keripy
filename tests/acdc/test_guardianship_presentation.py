# -*- coding: utf-8 -*-
"""
tests.acdc.test_guardianship_presentation module

Worked, working example of a *represented presentation* -- a digital guardian
presenting a fact about a ward (a person who cannot fully consent) to a verifier,
under Utah's State-Endorsed Digital Identity law (SEDI, Utah Code 63A-20). It is a
sibling to tests/acdc/test_clc_disclosure.py and tests/acdc/test_examples.py, and it
adds the one thing neither shows: a presentation whose HOLDER IS NOT THE SUBJECT.

The load-bearing invariant, from both the SEDI statute and the guardianship prior
art (Sovrin "Guardianship in SSI V2"; Aries RFC 0103 "Indirect Identity Control"),
is holder != subject: the GUARDIAN holds the authority credential and the WARD is
named only by edge. A verifier can therefore always tell that a guardian -- not the
ward -- is acting; collapsing the two is the classic impersonation failure the whole
field warns against. Be precise about WHERE that invariant is enforced (this was the
panel review's dominant finding): the schema PINS the ward-data edge operators, which
makes the impersonation SHAPE unrepresentable -- a mislabeled I2I ward edge is rejected
at wire validation. But the NI2I operator is relationally inert (it only nullifies
I2I's issuer==issuee requirement; it does NOT assert presenter != subject), and the
reference keri.vdr.verifying.verifyChain performs no presenter-vs-ward binding for an
NI2I edge. So the holder != subject GUARANTEE is enforced by the verifier's binding
LOGIC (_verify_representation, below) together with the issuee field and the presenter's
signature -- NOT by the operator alone. This example is illustrative of that
composition, not a normative cross-language spec for the operators: an implementer must
port the binding logic, not merely the edge labels. What no mDL / EU-ARF style
credential (linkable, document-centric, with no delegation semantics at all) can express
is the composition itself.

Scenario. Cara is a 14-year-old Utah resident. She holds two state-endorsed ACDCs
under HER OWN holder AID: an attributive SEDI identity credential (name, date of
birth, state-endorsed photo, residence) and an aggregative age credential (boolean
flags for the thresholds 13, 16, 18, 21, 55, 65) that chains back to her identity
credential with an E1E identity edge. Bob, her custodial parent, holds a SEDI digital
guardian credential naming Cara as ward. Cara wants to use an age-restricted online
service that must confirm (a) an age floor is met and (b) that an authorized digital
guardian stands behind a minor's use -- but is entitled to neither Cara's birthdate
nor a standing correlator. Because Cara is a minor who cannot fully consent, BOB
presents on her behalf: every SEDI verifier and relying party MUST accept a digital
guardian's presentation on the same terms as the holder's (Utah Code 63A-20 Parts
4-6). Bob issues a represented-presentation ACDC to the service that proves his
authority (an I2I edge to his own guardian credential), references Cara's credentials
(NI2I edges -- he is NOT their subject), and discloses only that Cara is over 13.

Three edge operators, one per relationship, and getting them right is a security
property, not a detail:

  * I2I (authority): the presentation -> Bob's guardian credential. I2I holds when
    the presentation's issuer (Bob) is the issuee of the credential it points to
    (Bob) -- it proves the presenter holds this authority.
  * NI2I (ward data): the presentation -> Cara's identity and age credentials. Bob
    is NOT Cara, so these MUST NOT be I2I: an I2I ward edge would require
    presenter == subject, which is impersonation. The authority to present the
    ward's data comes from the sibling I2I authority edge plus the verifier's
    binding logic, not from these edges' operator.
  * E1E (identity): Cara's age credential -> her identity credential. Same subject
    (issuee), different issuers (issuer != issuee), so it is an IDENTITY relation,
    not a delegation -- the operator I2I would misapply (keripy discussion #1515,
    the E1E operator added in PR #1523). Here it lets the guardian disclose the
    ward's over-13 predicate while proving the disclosed flag is the ward's own.
    CAVEAT (panel review): E1E is NOT yet in the ACDC spec's closed operator set
    {I2I, NI2I, DI2I, NOT}. A spec-default or pre-#1523 verifier does not cleanly
    reject an unknown operator -- it COERCES it: to I2I for a targeted far node
    (which then wrongly REJECTS this same-subject/different-issuer edge), or to NI2I
    for an untargeted far node (which wrongly ACCEPTS it unchecked). So this graph
    validates only against a #1523+ verifier and rides that dependency until E1E is
    ratified into the spec operator table (disc #1515) and adopted by signify-ts.
    E1E is also never INFERRED -- the schema const-pin on 'o' is what makes it
    explicit and non-optional; an unlabeled identity edge would default to I2I.

Privacy AND accountability, stronger than the alternatives -- stated precisely. On
ATTRIBUTES the service learns "an authorized guardian vouches this user is over 13" and
nothing more: not Cara's birthdate, not which other age thresholds exist. That is the
aggregate (unlabeled-position) selective-disclosure pattern -- a poor man's sparse
Merkle tree, as mdoc models age proofs, but additionally hiding WHICH thresholds are
asserted. What this example does NOT achieve, and does not claim to (panel review), is
IDENTIFIER-level unlinkability: the disclosure still hands the service the ward's stable
AID plus the source-credential SAIDs, which two colluding services could join on to
track the same minor. Removing that residual is a deployment-layer concern -- per-facet
ward AIDs or bulk-issued source instances that partition the correlatable identifier
space across verifiers (a separate worked example) -- not something the
represented-presentation shape itself provides. The guardianship is registry-bound with
a BLINDABLE registry, so the service confirms the authority is currently valid and
cannot READ the state word (issued/revoked) off the wire -- dynamic termination
(majority, restored capacity, court order) is checked at presentation, not trusted from
a date. (The bup event's existence, count, and timestamps stay public, so full TEMPORAL
decorrelation of a revocation additionally needs placeholder pre-issuance, continued
blind updates after revocation, and a shared-herd registry rather than the
one-per-guardianship registry modeled here.) And the verifier can PROVE, after the fact,
that a guardian acted: a verifiable chain from the guardian's AID through the DGO-issued
authority credential to the ward's identity -- an accountability chain no
document-centric mDL/ARF flow can carry.

Deliberately NOT contractually-protected disclosure. The sibling CLC example
(test_clc_disclosure.py) negotiates safe-harbor terms in the Rules section; that is
its point, not this one's. Guardianship's accountability rests on the guardian
credential's own governance framework (best-interest fiduciary duty, the holder !=
subject transparency rule, scope enforcement, dynamic revocation), referenced by SAID
from the presentation's Rules section. CLC remains composable (a guardian disclosing
a child's data is a natural home for anti-assimilation terms) but is left out here to
keep the represented-presentation core in focus. NOTE (panel review): that framework is
referenced here by a PLACEHOLDER digest (GUARDIAN_RULES_SAID, a bare Diger over a
description string), not a SAID-committed rules SAD; a real deployment authors the
framework and binds its SAID (as the real SEDI sedi-id/rules.json does), so the
fiduciary/scope/termination semantics have Layer-2 content to enforce.

A note on altitude. Like the sibling examples, this one models the credential graph,
the edge bindings, and the registry state at the data-structure level, built from the
real v2 primitives in keri.acdc.messaging and keri.core (acdcmap/acdcagg, Aggor,
Compactor, Blinder, exchange). It does not stand up a Habery/keystore or route
through keri.vdr.verifying.verifyChain: that v1 runtime needs a live Reger/Tevery,
and PR #1523 already unit-tests its real E1E branch there. This example demonstrates
USAGE of the credential graph a v2-native, aggregate-aware verifier evaluates -- the
same altitude that is most useful to implementers in other languages. Every ACDC
validates against a real, purpose-authored JSON Schema (Draft 2020-12) from its first
commit. Actor AIDs are derived once here from a fixed salt so the example is
reproducible; each is a self-addressing ('E') transferable AID.

Two checks a COMPLETE verifier performs are out of scope at this altitude (panel
review): (a) grounding the guardian credential's ISSUER as an authority competent for
the basis -- the issuerAuthority rule, a Layer-2 governance/registry trust-root check,
not the Layer-1 edge binding _verify_representation covers (so a self-issued guardian
credential passes the edge check here; a real verifier also resolves that the issuer is
the DGO/court); and (b) enforcing each edge's 's' far-node schema constraint (the
illustrative binding reads 'n'/'o' but not 's', as the reference verifyChain also does),
which a cross-trust-domain verifier must add so a far node cannot be substituted with a
different schema of the same shape.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks
from keri.core import (Salter, Noncer, Aggor, Compactor, Mapper, Diger, Verfer,
                       exchange, messagize)
from keri.core.coring import MtrDex
from keri.core.eventing import incept
from keri.acdc import regcept, blindate, acdcmap, acdcagg
from keri.core.structing import Blinder


# --- Reproducible example actors (see module docstring). ---
# Five actors, each a self-addressing ('E') transferable AID: its prefix is the SAID
# of an inception event committing to the actor's current signing key and a digest of
# its pre-rotated next key. Ten signers from one fixed salt: _SIGNERS[0..4] are the
# five actors' current signing keys (DGO, endorser, Bob, Cara, service) and
# _SIGNERS[5..9] are their matching pre-rotated next keys.
_SIGNERS = Salter(raw=b'guardworkexamsal').signers(count=10, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


# DGO = Utah's digital-government office (the State endorser/issuer); ENDORSER issues
# the derived age credential; BOB is the custodial parent (guardian); CARA is the
# minor ward; SERVICE is the age-restricted online verifier/relying party.
DGO, ENDORSER, BOB, CARA, SERVICE = (
    _actor_aid(_SIGNERS[i], _SIGNERS[i + 5]) for i in range(5))

# Per-example blinding nonces, derived (not pasted) from a distinct raw prefix so this
# file shares no nonce values with the sibling examples.
RAWS = [b'guardworkexamra' + b'%0x' % (i,) for i in range(32)]
NONCES = [Noncer(raw=raw).qb64 for raw in RAWS]


def _saidify_schema(mad, kind=Kinds.json):
    """Compute a JSON Schema's SAID and return (said, schema-with-$id).

    Mirrors the sibling examples: run the schema map through a Mapper that
    self-addresses the '$id' field (which must be first, as its position is part
    of the serialization the SAID digests). Mapper deep-copies its input, so the
    caller's schema map is never mutated.
    """
    mapper = Mapper(mad=mad, makify=True, strict=False, saids={"$id": 'E'},
                    saidive=True, kind=kind)
    return mapper.said, mapper.mad


def assert_acdc_schema_valid(acdc, schema=None):
    """Validate a worked-example ACDC against its JSON Schema (Draft 2020-12).

    Identical in intent to the helper in the sibling examples: it proves the schema
    is itself well-formed and that the ACDC instance conforms to the schema it
    commits to in its own 's' section. When the schema section has been compacted to
    a bare SAID string, pass the schema explicitly.
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
# Purpose-authored JSON Schemas (Draft 2020-12). Authored as maps with "$id" first
# so _saidify_schema can self-address them per wire kind.
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
# labeled set. The issuee 'i' is the WARD (Cara).
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

# --- sedi-guardian: Bob's ATTRIBUTIVE ('acm') authority credential, disclosed WHOLE. ---
# The SEDI legal-recognition layer for a digital guardian: the statutory basis, the
# scope of powers (Utah prefers LIMITED guardianship, so scope is explicit), and the
# appointment/registration. HELD BY THE GUARDIAN (issuee = Bob) and names the WARD by
# edge (subject -> Cara's sedi-id) -- the holder != subject invariant. Authority
# credentials are disclosed whole (a verifier needs basis + scope + validity together),
# so the attribute section is flat, not selectively disclosable. Registry-bound (rd):
# guardianship terminates dynamically, so a verifier MUST check current status.
GUARDIAN_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Digital Guardian",
    "description": "SEDI legal-recognition layer for a digital guardian (Utah Code "
                   "63A-20). Attests the statutory basis, the powers scope, and the "
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
                 "required": ["d", "u", "i", "basis", "powers", "fiduciary",
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
                     "powers": {"description": "Scope of authority ('plenary' or an "
                                               "explicit limited set)",
                                "type": "array", "minItems": 1, "uniqueItems": True,
                                "items": {"enum": ["plenary", "healthCare", "residence",
                                                   "education", "personalRecords",
                                                   "socialBenefits", "digitalIdentity",
                                                   "contracts"]}},
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
                           "(-> instrument); optional scope (-> GCD)",
            "oneOf": [
                {"type": "string"},
                {"type": "object", "required": ["d", "subject", "authorization"],
                 "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                "subject": _edge_schema_enum("ward's sedi-id"),
                                "authorization": _edge_schema_enum(
                                    "authorizing instrument"),
                                "scope": _edge_schema_enum("GCD scope")},
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
#   wardId  (NI2I)  -> Cara's sedi-id  (Bob is not the subject),
#   wardAge (NI2I)  -> Cara's sedi-age (Bob is not the subject).
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

# Fixed timestamps for the IPEX exn messages (kept stable so SAIDs are reproducible).
APPLY_STAMP = "2026-07-20T15:15:00.000000+00:00"
OFFER_STAMP = "2026-07-20T15:16:00.000000+00:00"
AGREE_STAMP = "2026-07-20T15:17:00.000000+00:00"
GRANT_STAMP = "2026-07-20T15:18:00.000000+00:00"
ADMIT_STAMP = "2026-07-20T15:19:00.000000+00:00"


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

# Age aggregate ARRAY positions (A[0] = AGID; A[1] = issuee; A[2..] = the flags).
AGE_ISSUEE = 1
AGE_FLAG0 = 2
AGE_OVER13 = AGE_FLAG0 + AGE_THRESHOLDS.index(13)   # array index of the over-13 flag

# Cara's age at the presentation date (DOB 2012-04-10, presentation 2026-07-20).
CARA_AGE = 14

# The guardianship registry's blinding salt -- shared ONLY between the DGO (issuer) and
# Bob (the guardian/holder), never handed to the service. Used to blind the per-event
# registry state (Phase 4). The states a guardianship registry event can carry.
GUARDIAN_SALT = Noncer(raw=b'guardregblindsalt').qb64
GUARDIAN_STATES = ['issued', 'revoked']


def _sedi_attr():
    """Cara's sedi-id attribute section (a fresh map each call).

    Attributive: the issuee ('i') is inserted at the top of the section by acdcmap via
    iseaid, and each identity attribute is its own individually-blinded (own 'u'),
    self-addressing (own 'd') nested block, so it can be partially disclosed or withheld
    independently. Cara is a 14-year-old (DOB 2012-04-10).
    """
    return dict(d='', u=NONCES[N_SEDI_A],
                photo=dict(d='', u=NONCES[N_SEDI_PHOTO],
                           photo="<state-endorsed-photo-bytes>"),
                dob=dict(d='', u=NONCES[N_SEDI_DOB], dob="2012-04-10"),
                residence=dict(d='', u=NONCES[N_SEDI_RES],
                               residence="Provo UT"),
                name=dict(d='', u=NONCES[N_SEDI_NAME], name="Cara Carver"))


def _age_ael():
    """Cara's age-threshold aggregate element list (a fresh list each call).

    Element 0 is the AGID placeholder; element 1 is the issuee block (i = CARA), which
    is where SerderACDC.iseaid resolves an aggregate issuee from (.sad['A'][1]['i']);
    elements 2.. are one individually-blinded boolean block per AGE_THRESHOLDS entry
    (over<n> = CARA_AGE >= n). All thresholds are present as blocks, so disclosing one
    flag reveals nothing about which others are asserted. Cara (14) is over 13 only.
    """
    els = ['', dict(d='', u=NONCES[N_AGE_ISSUEE], i=CARA)]
    for offset, n in enumerate(AGE_THRESHOLDS):
        els.append(dict(d='', u=NONCES[N_AGE_FLAG0 + offset],
                        **{f"over{n}": CARA_AGE >= n}))
    return els


def _ward_credentials(kind):
    """Build Cara's two source credentials, registry-bound and schema-validated.

    sedi-id is ATTRIBUTIVE ('acm') with individually partially-disclosable nested
    blocks (issuee at a.i = CARA); age is AGGREGATIVE ('acg') with an array of boolean
    age-threshold flags (issuee at A[1].i = CARA) and one E1E identity edge chaining it
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

    # sedi-id: attributive; acdcmap inserts the issuee (iseaid -> a.i = CARA).
    sedi = acdcmap(israid=DGO, uuid=NONCES[N_SEDI_ACDC], regid=regDgo.said,
                   schema=sediSchema, attribute=_sedi_attr(), iseaid=CARA, kind=kind)
    # age: aggregative boolean-flag credential, issued by the endorser to Cara, chained
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
    case a coerce-to-I2I verifier (before PR #1523) rejects. Returns True or raises.
    """
    edge = near.sad['e']['identity']
    assert edge['o'] == 'E1E'                          # identity operator
    assert edge['n'] == far.said                       # edge points at this far node
    assert near.iseaid is not None                     # near must be targeted (has issuee)
    assert near.iseaid == far.iseaid                   # same subject: the identity relation
    return True


def _ward_id_disclosure(sedi, kind):
    """Cara's minimal disclosure of sedi-id: reveal the issuee only, withhold every
    identity attribute (photo/dob/residence/name) as a bare SAID.

    For the guardianship presentation the service needs to BIND the ward, not read her
    identity attributes, so nothing but the issuee is revealed -- the minimal disclosure.
    sedi-id is attributive, so disclosure is by compaction: each nested block collapses
    to a SAID and the mix recomputes to the same committed section SAID. (A richer flow
    could reveal a chosen block in full -- the CLC sibling reveals the photo that way --
    but a guardian binding a ward discloses nothing beyond the issuee.)
    """
    compactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
    compactor.compact()
    compactor.expand(greedy=True)               # populates .partials (incl. the compact one)
    allCompact = compactor.partials[('',)].mad
    return dict(allCompact)                     # every attribute block as a bare SAID


def _age_disclosure(ageAggor):
    """Cara's selective disclosure of the age credential: reveal the issuee + the
    over-13 flag, withhold every other threshold as a bare SAID.

    The service learns she is over 13 and nothing about the other thresholds -- not
    that she is UNDER 16/18/21 (those flags withheld), not whether she is over 55/65.
    The disclosure still verifies against the committed AGID.
    """
    disclosed, _ = ageAggor.disclose(indices=[AGE_ISSUEE, AGE_OVER13])
    return disclosed


def _committed_a_said(sedi, kind):
    """The SAID sedi-id commits to for its attribute section (its most-compact form)."""
    compactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
    compactor.compact()
    return compactor.said


def _birth_certificate(kind):
    """The authorizing instrument: a minimal birth-certificate credential (DGO -> Cara)
    naming Bob as parent and Cara as child. The guardian credential's authorization edge
    points here, grounding a custodial-parent guardianship in a verifiable instrument."""
    regDgo = regcept(israid=DGO, uuid=NONCES[N_REG_DGO], stamp=REG_DGO_STAMP, kind=kind)
    _, bcSchema = _saidify_schema(dict(BIRTHCERT_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[N_BC_A], child=CARA, parent=BOB)
    return acdcmap(israid=DGO, uuid=NONCES[N_BC_ACDC], regid=regDgo.said,
                   schema=bcSchema, attribute=attribute, iseaid=CARA, kind=kind)


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
    powers limited to digitalIdentity (managing/presenting the ward's digital identity);
    recognition names the inherent-parental authority type and Utah as appointing state.
    """
    return dict(d='', u=NONCES[N_G_A],
                basis="custodialParent",
                powers=["digitalIdentity"],
                fiduciary="bestInterest",
                residualParentalRights=True,
                recognition=dict(authorityType="inherentParental",
                                 appointingState="US-UT",
                                 registrationStatus="native"),
                effectiveDate="2012-04-10",
                expiryDate="2030-04-10")       # majority (Cara's 18th birthday)


def _guardian_credential(kind, sedi=None, birthCert=None, reg=None):
    """Bob's SEDI digital-guardian credential (DGO -> Bob), registry-bound, schema-valid.

    HELD BY BOB (issuee), naming Cara ONLY by the subject edge (holder != subject). The
    subject edge is NI2I -- Bob is not Cara's issuee, so it is a reference, not a
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
    """Phase 1: Cara's two source credentials and the E1E identity edge between them.

    Cara holds two ACDCs under one holder AID (CARA), each registry-bound and validated
    against a purpose-authored JSON Schema, each using the disclosure mechanism that
    fits its data:

      * sedi-id -- issued by the DGO as an ATTRIBUTIVE ('acm') identity credential; the
        issuee is a.i = CARA and each attribute is an individually-blinded nested block.
      * age -- issued by the endorser as an AGGREGATIVE ('acg') credential: an array of
        boolean age-threshold flags (issuee at A[1].i = CARA), chained to sedi-id by an
        E1E identity edge (same subject, issuer != issuee).

    The load-bearing claims: the E1E edge verifies (near issuee == far issuee) where a
    coerce-to-I2I verifier would reject it; a guardian can later disclose 'over 13'
    while withholding the birthdate and every other threshold; and both disclosures are
    tamper-evident.
    """
    kind = Kinds.json
    sedi, age, ageAggor = _ward_credentials(kind)

    # sedi-id: ATTRIBUTIVE identity credential, registry-bound, schema-valid.
    assert sedi.ilk == Ilks.acm
    assert sedi.sad['i'] == DGO                     # issued by the DGO (State)
    assert sedi.sad['rd'] == "ECwS8218O0JA_faclrOZSOL8vBzCOHY9dWPNBtrgcXwz"  # DGO registry
    assert sedi.sad['a']['i'] == CARA               # attributive issuee (the ward)
    assert sedi.iseaid == CARA
    assert sedi.said == "EEqgm1FjOH3h0Tl3f0H3uSmoqnxUSXRl3NoRjcaYgc_h"
    assert_acdc_schema_valid(sedi)

    # age: AGGREGATIVE boolean-flag credential, registry-bound, schema-valid.
    assert age.ilk == Ilks.acg
    assert age.sad['i'] == ENDORSER                 # issued by the endorser
    assert age.sad['rd'] == "EEX6XlR5J5fSs7CfXuxv-jPI28OKpkHYkwGgpBEA_RdW"  # endorser registry
    assert age.sad['A'][AGE_ISSUEE]['i'] == CARA    # aggregative issuee (the ward)
    assert age.iseaid == CARA
    assert age.said == "EAvQgr6rrm5jggdpvewx-VYSILCzzRAXoa-nJstazk7Y"
    assert age.sad['A'][AGE_OVER13]['over13'] is True                    # over 13...
    over16Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(16)
    assert age.sad['A'][over16Pos]['over16'] is False                    # ...not over 16
    ageSchema = assert_acdc_schema_valid(age)

    # The E1E identity edge binds age to sedi-id as the SAME subject (Cara), though the
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
    assert idDisc['i'] == CARA                              # issuee present (binds the ward)
    assert isinstance(idDisc['dob'], str)                  # birthdate withheld (bare SAID)
    assert isinstance(idDisc['name'], str)                 # name withheld
    assert "2012-04-10" not in json.dumps(idDisc)          # birthdate never on the wire
    assert "Cara Carver" not in json.dumps(idDisc)         # name never on the wire
    committedA = _committed_a_said(sedi, kind)
    check = Compactor(mad=dict(idDisc, d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == committedA                        # disclosure belongs to sedi-id

    # --- Selective disclosure of age: reveal over13 + issuee, hide the rest. ---
    ageDisc = _age_disclosure(ageAggor)
    assert ageDisc[0] == ageAggor.agid                     # AGID anchor
    assert ageDisc[AGE_ISSUEE]['i'] == CARA                # issuee revealed
    assert ageDisc[AGE_OVER13]['over13'] is True           # over-13 revealed
    over18Pos = AGE_FLAG0 + AGE_THRESHOLDS.index(18)
    assert isinstance(ageDisc[over18Pos], str)             # over-18 flag withheld (SAID)
    # Privacy: no other threshold flag crosses the wire -- the service cannot tell she
    # is UNDER 18/21, nor whether she is over 55/65.
    assert "over18" not in json.dumps(ageDisc)
    assert "over21" not in json.dumps(ageDisc)
    assert "over65" not in json.dumps(ageDisc)
    assert Aggor.verifyDisclosure(ageDisc, kind=kind)
    # Tamper evidence: altering the revealed flag breaks AGID verification.
    tampered = list(ageDisc)
    tampered[AGE_OVER13] = dict(ageDisc[AGE_OVER13], over13=False)
    assert not Aggor.verifyDisclosure(tampered, kind=kind)


# ---------------------------------------------------------------------------
# Phase 2: Bob's SEDI digital-guardian credential -- holder != subject.
# ---------------------------------------------------------------------------
def test_guardian_authority_credential_JSON():
    """Phase 2: Bob's guardian credential names Cara only by edge (holder != subject).

    The SEDI digital-guardian credential is HELD BY THE GUARDIAN (issuee = Bob) and
    names the ward ONLY by the subject edge (-> Cara's sedi-id). This is the invariant
    that keeps guardianship transparent representation, never impersonation: a verifier
    can always tell a guardian -- not the ward -- is acting.

    Asserted here: the issuee is Bob and NOT Cara (holder != subject, structurally); the
    subject edge is NI2I (a reference, not a same-holder delegation -- Bob is not Cara's
    issuee) and points at Cara's sedi-id; the authority is grounded in an authorizing
    instrument (the birth certificate) via the authorization edge; the credential is
    registry-bound (dynamic termination) and disclosed whole; and the schema enforces
    the statutory shape (a bad basis, an empty powers list, or a bad recognition block
    are rejected).
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
    # holder != subject: the credential's issuee is Bob, and the ward is Cara, named
    # only by edge. This is the load-bearing invariant, asserted structurally.
    assert guardian.iseaid != sedi.iseaid           # Bob is not the ward
    assert guardian.said == "EKDE_FfO-iXvw-7q-y1-cthaS0qIbLnJDajhF2eDswVd"
    assert guardian.sad['e']['subject']['n'] == sedi.said       # ward named by edge
    assert guardian.sad['e']['subject']['o'] == 'NI2I'          # reference, not delegation
    assert guardian.sad['e']['authorization']['n'] == birthCert.said   # authority grounded
    assert birthCert.said == "EOh4FrcZ1XkRkg8HGjhDsoInt35bTb0ZuvfchkWl6uql"  # the instrument
    # Registry-bound (dynamic termination) and disclosed whole (flat attribute section).
    assert reg.said == "EIilAhmBAyNgcoAMe1YLBLtu5eu1_j2jDtZZxV_9IN5B"        # guardianship reg
    assert guardian.sad['rd'] == reg.said
    assert guardian.sad['a']['basis'] == "custodialParent"
    assert guardian.sad['a']['powers'] == ["digitalIdentity"]
    assert guardian.sad['a']['recognition']['authorityType'] == "inherentParental"
    # The Rules section references the SEDI guardianship governance framework by SAID.
    assert guardian.sad['r'] == GUARDIAN_RULES_SAID
    schema = assert_acdc_schema_valid(guardian)

    # Schema teeth: a bad basis, an empty powers list, and a bad recognition authority
    # type are each rejected -- the statutory shape is machine-checked.
    badBasis = json.loads(json.dumps(guardian.sad))
    badBasis['a']['basis'] = "selfAppointed"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(badBasis)
    emptyPowers = json.loads(json.dumps(guardian.sad))
    emptyPowers['a']['powers'] = []
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(emptyPowers)
    badAuth = json.loads(json.dumps(guardian.sad))
    badAuth['a']['recognition']['authorityType'] = "vibes"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(badAuth)


PRESENT_STAMP = "2026-07-20T15:18:00.000000+00:00"


def _represented_presentation(kind, guardian, sedi, age, compactify=False):
    """Bob's represented-presentation ACDC to the service (helper for Phase 3+).

    Issuer = Bob (Discloser/guardian), Issuee = the service (Disclosee). It carries no
    ward PII in its own attributes -- just the purpose and time -- and references the
    credential graph by edge:
      authority (I2I)  -> Bob's guardian credential  (proves Bob holds the authority),
      wardId   (NI2I)  -> Cara's sedi-id             (Bob is NOT the subject),
      wardAge  (NI2I)  -> Cara's sedi-age            (Bob is NOT the subject).
    Deliberately NOT registry-bound (no 'rd'): a one-time presentation is not logged.
    The Rules section references the guardianship governance framework by SAID.
    """
    _, schema = _saidify_schema(dict(PRESENTATION_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[N_P_A], i=SERVICE,
                     purpose="Authorize a minor ward's access to an age-restricted "
                             "service and prove the ward is over 13.",
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
                           power="digitalIdentity"):
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
      4. Scope: the requested action falls within the guardian's 'powers' (Utah prefers
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
    # (4) scope: requested action within powers.
    assert power in guardian.sad['a']['powers']
    # (5) identity E1E: the disclosed age flag is the ward's own.
    assert _verify_identity_edge(wardAge, wardSedi)
    return True


# ---------------------------------------------------------------------------
# Phase 3: the represented presentation -- guardian mediates, holder != subject.
# ---------------------------------------------------------------------------
def test_represented_presentation_JSON():
    """Phase 3: Bob presents on Cara's behalf; the verifier binds authority to ward.

    Bob issues a represented-presentation ACDC to the service (Issuer = Bob, Issuee =
    the service). This is the NEW pattern: a presentation whose HOLDER IS NOT THE
    SUBJECT, distinct from the self-presentation the sibling examples show. Its three
    edges carry three operators, and the binding (_verify_representation) is the
    security property: I2I proves Bob holds the authority; NI2I marks the ward's data as
    someone else's (Bob is not the subject); E1E proves the disclosed age flag is the
    ward's. The service can therefore tell -- and prove later -- that a GUARDIAN, not
    the child, is acting.

    The load-bearing guardrail is asserted two ways: the schema PINS the ward-data edges
    to NI2I (an I2I ward edge -- the impersonation shape -- is rejected), and the binding
    fails if the authority does not actually cover THIS ward. The presentation runs as a
    gated IPEX exchange so the ward's over-13 disclosure crosses the wire only in the
    grant, after the service accepts.
    """
    kind = Kinds.json
    sedi, age, ageAggor = _ward_credentials(kind)
    guardian = _guardian_credential(kind, sedi=sedi)
    presentation = _represented_presentation(kind, guardian, sedi, age)

    assert presentation.ilk == Ilks.acm
    assert presentation.sad['i'] == BOB           # Bob is the Issuer (guardian/Discloser)
    assert presentation.sad['a']['i'] == SERVICE  # the service is the Issuee (Disclosee)
    assert 'rd' not in presentation.sad           # one-time presentation, not logged
    assert presentation.sad['r'] == GUARDIAN_RULES_SAID   # governance by SAID
    assert presentation.said == "EO-QbZp_ZpRNieLBaBa8UxI_bnUdyVGNFromSSPVeCA2"

    # The full binding holds for the honest presentation.
    assert _verify_representation(presentation, guardian, sedi, age)
    # holder != subject, stated plainly: the presenter is Bob, the subject is Cara.
    assert presentation.sad['i'] == BOB and sedi.iseaid == CARA

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
                        schema=otherSchema, attribute=_sedi_attr(), iseaid=SERVICE, kind=kind)
    with pytest.raises(AssertionError):
        _verify_representation(presentation, guardian, otherWard, age)

    # --- The gated IPEX exchange: the ward's over-13 flag crosses only in the grant. ---
    # 1. apply (service -> Bob): the challenge -- which schemas/fields, and the
    # governance framework the service will honor (guardian acceptance in scope).
    apply = exchange(sender=SERVICE, receiver=BOB, route="/ipex/apply",
                     attributes=dict(m="Prove an authorized guardian and that the ward "
                                       "is over 13.",
                                     disclose={guardian.sad['s']['$id']: ["/a/i", "/a/powers"],
                                               age.sad['s']['$id']: ["/A/i", "/A/over13"]},
                                     g=GUARDIAN_RULES_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['r'] == "/ipex/apply" and apply.sad['i'] == SERVICE
    assert apply.said == "EOnu--t6gKZ2hNG3Lgj4DQUoQ_gmSIAYAgU9zzL0Q8k1"

    # 2. offer (Bob -> service): commits ONLY to the Discloser's own presentation SAID
    # and the governance ref, and binds the apply. It deliberately does NOT enumerate the
    # issuer-committed source-credential SAIDs (guardian/sedi/age): those are issuer
    # commitments, and attaching them before the service agrees would let a verifier
    # spurn and walk away with stable ward/guardian correlators, defeating the
    # metadata-ACDC decorrelation (panel review, PRV-F2). They arrive only post-agree, in
    # the grant, reachable by expanding the delivered presentation.
    offer = exchange(sender=BOB, receiver=SERVICE, route="/ipex/offer", prior=apply.said,
                     attributes=dict(acdc=presentation.said,
                                     governance=GUARDIAN_RULES_SAID),
                     stamp=OFFER_STAMP, kind=kind)
    assert offer.sad['p'] == apply.said
    assert offer.said == "EPh4XM6PCgwUaCL_LCa3m8n6ZFCMUGdglF3PyPq9OAMq"
    assert presentation.said.encode() in offer.raw            # Discloser's own commitment
    assert b"Cara Carver" not in offer.raw and b"2012-04-10" not in offer.raw   # no PII
    # Issuer commitments withheld until after the service agrees (PRV-F2):
    assert guardian.said.encode() not in offer.raw
    assert sedi.said.encode() not in offer.raw
    assert age.said.encode() not in offer.raw

    # 3. agree (service -> Bob): acceptance, binding the offer SAID and signed by the
    # service (via messagize -- the blessed genus-aware attachment path).
    agree = exchange(sender=SERVICE, receiver=BOB, route="/ipex/agree", prior=offer.said,
                     stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    assert agree.said == "EFRC9KA2RHDzdejFlRS0eoXUjcle9wc3qwiSndg-ktd3"
    svcSigner = _SIGNERS[4]                             # the service's establishing key
    svcSig = svcSigner.sign(ser=agree.raw, index=0)
    signedAgree = messagize(agree, sigers=[svcSig])
    assert bytes(agree.raw) in signedAgree
    capturedKeyState = Verfer(qb64=svcSigner.verfer.qb64)
    assert capturedKeyState.verify(sig=svcSig.raw, ser=agree.raw)

    # 4. The gate: Bob discloses only when handed a valid, signed, offer-binding agree.
    def disclose(agreeMsg, sig, keyState):
        if not (agreeMsg.sad['r'] == "/ipex/agree" and agreeMsg.sad['p'] == offer.said
                and keyState.verify(sig=sig.raw, ser=agreeMsg.raw)):
            return None
        presentationCompact = _represented_presentation(kind, guardian, sedi, age,
                                                        compactify=True)
        return exchange(sender=BOB, receiver=SERVICE, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(acdc=presentationCompact.sad,
                                        wardId=_ward_id_disclosure(sedi, kind),
                                        wardAge=_age_disclosure(ageAggor)),
                        stamp=GRANT_STAMP, kind=kind)

    # A forged signature or a spurn (decline) unlocks nothing.
    assert disclose(agree, _SIGNERS[0].sign(ser=agree.raw, index=0), capturedKeyState) is None
    spurn = exchange(sender=SERVICE, receiver=BOB, route="/ipex/spurn", prior=offer.said,
                     stamp=AGREE_STAMP, kind=kind)
    assert disclose(spurn, svcSigner.sign(ser=spurn.raw, index=0), capturedKeyState) is None

    # The valid agree unlocks the grant; the ward's over-13 flag appears only now, and
    # the birthdate and every other threshold stay off the wire.
    grant = disclose(agree, svcSig, capturedKeyState)
    assert grant is not None and grant.sad['p'] == agree.said
    assert grant.said == "EBmpFh91yMV9Iue-zbDJ7FDZl7USQsD05IhU9w5_m5ET"
    assert grant.sad['a']['wardAge'][AGE_OVER13]['over13'] is True     # over-13 disclosed
    assert grant.sad['a']['wardId']['i'] == CARA                       # ward bound (issuee)
    assert b"2012-04-10" not in grant.raw                             # birthdate withheld
    assert b"over18" not in grant.raw and b"over21" not in grant.raw   # thresholds withheld

    # 5. admit (service -> Bob): closes the exchange.
    admit = exchange(sender=SERVICE, receiver=BOB, route="/ipex/admit", prior=grant.said,
                     stamp=ADMIT_STAMP, kind=kind)
    assert admit.sad['p'] == grant.said
    assert admit.said == "ECTIUyg9Q-m-nJXdRb90dcrmvj5fg3ENBaS7-TQ8Fp2g"


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
    assert issuedBlinder.said == "EMXjLjiVaP3FaRUZ2NBvvDUUF545HCFldpw7LeJzesfD"
    assert issued.said == "EHmJLReDPoXzlj5q91yIkI1RmTfMpQurgDbMA24cNVH2"
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
    assert revoked.said == "EOry-I6OUZs0wP8zHFpED-emHcWe_t9pW28VxR5_6BHS"
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

    # Selective disclosure of age: reveal over-13, withhold the rest; verifies via AGID.
    ageDisc = _age_disclosure(ageAggor)
    assert ageDisc[AGE_OVER13]['over13'] is True
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
