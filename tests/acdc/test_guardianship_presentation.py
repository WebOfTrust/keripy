# -*- coding: utf-8 -*-
"""
tests.acdc.test_guardianship_presentation module

Worked, working example of a REPRESENTED PRESENTATION -- a digital guardian presenting a
fact ABOUT a ward to a verifier, under Utah's State-Endorsed Digital Identity law (SEDI,
Utah Code 63A-20). Sibling to tests/acdc/test_cp_disclosure.py and test_examples.py, it
adds the one thing neither shows: a presentation whose HOLDER IS NOT THE SUBJECT.

WHICH GUARDIANSHIP THIS IS, AND WHICH IT IS NOT. Guardianship covers two situations that
look alike on a diagram and are not alike at all. @SmithSamuelM separates them in the
#1550 discussion text by what the ward can physically do:

  * The ward CANNOT ACT -- an infant or young child, or an adult who has lost capacity.
    The guardian custodies the keys controlling the ward's AID, so "any use case where the
    child is required to present something or have something presented on their behalf it
    must be done by the parents" (#1550). THIS module. The invariant is holder != subject:
    a verifier can always tell that a guardian, not the ward, is acting, and collapsing
    the two is the impersonation failure the prior art warns against (Sovrin "Guardianship
    in SSI V2"; Aries RFC 0103).
  * The ward CAN ACT, within a scope -- old enough to operate a device and sign, with a
    parent who modulates her access rather than exercising it. "In that case, the Parent
    would delegate to their child attenuated capabilities" (#1550). That is the sibling,
    tests/acdc/test_ward_authz_presentation.py (PR #1577), where the WARD presents an
    authorization her guardian issued her; its invariant is attenuation.

The 13-to-18 band Utah's social-media law regulates therefore belongs to the SIBLING: a
14-year-old holds her own keys, and having her parent present for her models the wrong
regime. The two modules share a family so the line stays visible -- Bob Carver is the
custodial parent in both, his 14-year-old Cara presents her own authorization there, and
his 6-year-old Mia is the ward here. Her age sits inside a question #1550 leaves open ("at
what age does it make sense for an infant to first have a SEDI").

Scenario. Mia is 6. The State issued her two SEDI credentials under her own holder AID --
an attributive identity credential (name, date of birth, photo, residence) and an
aggregative age credential (boolean flags for the thresholds 13, 16, 18, 21, 55, 65)
chained to it by an E1E identity edge -- but Bob holds the keys, so she can present
neither. Bob holds a SEDI digital-guardian credential naming her as ward. A children's
online service must establish two things before opening an account: that this user is a
child under 13, so the parental-consent regime applies, and that an accountable guardian
stands behind it. It is entitled to neither Mia's birthdate nor a standing correlator. So
BOB presents -- every SEDI verifier MUST accept a guardian's presentation on the same terms
as the holder's (Utah Code 63A-20 Parts 4-6) -- issuing an ACDC that proves his authority
(I2I to his own guardian credential), references Mia's credentials (NI2I -- he is NOT their
subject), and discloses only her under-13 flag.

WHERE THE INVARIANT IS ACTUALLY ENFORCED, since this was the panel review's dominant
finding. The schema PINS the ward-data edge operators, making the impersonation SHAPE
unrepresentable at wire validation. But NI2I is relationally inert, and verifyChain does no
presenter-vs-ward binding for an NI2I edge, so the guarantee comes from the binding LOGIC
(_verify_representation, below): an implementer ports that, not merely the edge labels.

Three edge operators, one per relationship, and getting them right is a security property:

  * I2I (authority): presentation -> Bob's guardian credential. It holds when the
    presentation's issuer (Bob) is the issuee of the far node (Bob), which is what proves
    the presenter holds this authority.
  * NI2I (ward data): presentation -> Mia's identity and age credentials. Bob is NOT Mia,
    so these MUST NOT be I2I, which would require presenter == subject: impersonation.
  * E1E (identity): Mia's age credential -> her identity credential. Same subject (issuee),
    different issuers, so it is an IDENTITY relation and not a delegation; I2I would
    misapply (disc #1515; operator added in PR #1527). It is what lets a guardian disclose
    an age flag while proving the flag is the ward's own.

E1E CAVEAT: it is not yet in the ACDC spec's closed operator set {I2I, NI2I, DI2I, NOT}. A
spec-default or pre-#1527 verifier does not cleanly reject an unknown operator, it COERCES
it -- to I2I for a targeted far node, wrongly REJECTING this same-subject/different-issuer
edge, or to NI2I for an untargeted one, wrongly ACCEPTING it unchecked. So this graph
validates only against a #1527+ verifier until E1E is ratified (disc #1515), and it is
never INFERRED either: the schema const-pin on 'o' is what makes it explicit.

WHAT THE DISCLOSURE HIDES. The service learns "an authorized guardian vouches this user is
under 13" and nothing else -- not Mia's birthdate, not her exact age, not her name. The
aggregate hides the field LABELS and the block SAIDs of every withheld threshold; what it
cannot hide is the monotone entailment between cumulative thresholds, spelled out at
_age_ael. IDENTIFIER-level unlinkability is NOT achieved and is not claimed (panel
review): the disclosure hands over the ward's stable AID and the source-credential SAIDs,
which two colluding services could join on, and the GUARDIAN's AID is a correlator in the
same way. Removing that residual is deployment-layer work -- per-facet AIDs, or bulk-issued
source instances partitioning the identifier space across verifiers -- worked out by the
test_bulk_issuance_*.py siblings on branch feat-indep-registry-bulk-issuance.
Accountability survives the partitioning, because it runs to the issuing authority, which
holds the derivation.

Dynamic status and provable accountability are Phase 4: the guardianship binds to a
BLINDABLE registry, so termination (majority, restored capacity, court order) is checked at
presentation rather than trusted from a date, and the verifier can prove afterward that a
GUARDIAN acted. That chain is what no mDL / EU-ARF style credential expresses.

THREE DELIBERATE OMISSIONS. (a) No 'scope' edge to a companion delegated-authority
credential: Utah does not want guardianship to depend on a separate credential, so the edge
section is CLOSED at subject + authorization. The cost is that 'powers' is the whole scope
vocabulary, coarse enough to say a guardian holds authority over the ward's digital
identity but not which platforms or hours; a guardianship needing that carries it inline,
which is Sam's 'AuthZ' field and the EVAC sketch in #1550, worked out by the sibling. (b) No
contractually-protected disclosure -- that is test_cp_disclosure.py's point. Accountability
rests on the governance framework the Rules section references by SAID, and that reference
is a PLACEHOLDER digest rather than a SAID-committed rules SAD. (c) Two checks a COMPLETE
verifier performs: grounding the guardian credential's ISSUER as competent for the basis
(so a self-issued guardian credential passes the edge check here), and enforcing each
edge's 's' far-node schema constraint, which verifyChain also omits.

A note on altitude. Like the siblings, this models the credential graph, the edge bindings
and the registry state at the data-structure level, built from the real v2 primitives in
keri.acdc.messaging and keri.core (acdcmap/acdcagg, Aggor, Compactor, Blinder, exchange).
It does not stand up a Habery/keystore or route through keri.vdr.verifying.verifyChain:
that v1 runtime needs a live Reger/Tevery, and PR #1527 already unit-tests its real E1E
branch. Every ACDC validates against a purpose-authored JSON Schema (Draft 2020-12). Actor
AIDs derive from a fixed salt, so the example is reproducible; each is self-addressing.
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
# six-year-old ward, whose keys he custodies; SERVICE is the children's online service
# (the verifier/relying party). Bob's other child, the 14-year-old who presents for
# herself, is the sibling module's cast.
DGO, ENDORSER, BOB, MIA, SERVICE = (
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

# --- sedi-guardian: Bob's ATTRIBUTIVE ('acm') authority credential, disclosed WHOLE. ---
# The SEDI legal-recognition layer for a digital guardian: the statutory basis, the
# scope of powers (Utah prefers LIMITED guardianship, so scope is explicit), and the
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

# Mia's age at the presentation date (DOB 2020-03-15, presentation 2026-07-20). She is
# under every threshold, and the one the children's service asks for is the lowest:
# over13 is False, which is what puts the account under the parental-consent regime.
WARD_AGE = 6

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
    compactor.expand(greedy=True)               # populates .partials (incl. the compact one)
    allCompact = compactor.partials[('',)].mad
    return dict(allCompact)                     # every attribute block as a bare SAID


def _age_disclosure(ageAggor):
    """Mia's selective disclosure of the age credential: reveal the issuee + the
    over-13 flag (False), withhold every other threshold as a bare SAID.

    The service learns she is under 13, which is the fact that puts the account under the
    parental-consent regime, and learns neither her birthdate nor her exact age. It does
    NOT learn which other thresholds this credential carries, though it can infer their
    values by monotonicity -- see _age_ael. The disclosure verifies against the committed
    AGID.
    """
    disclosed, _ = ageAggor.disclose(indices=[AGE_ISSUEE, AGE_OVER13])
    return disclosed


def _committed_a_said(sedi, kind):
    """The SAID sedi-id commits to for its attribute section (its most-compact form)."""
    compactor = Compactor(mad=dict(sedi.sad['a']), makify=True, kind=kind)
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
    powers limited to digitalIdentity (managing/presenting the ward's digital identity);
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
                powers=["digitalIdentity"],
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
    # children's service asks for, and by monotonicity it settles all the others.
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
    the statutory shape (a bad basis, an empty powers list, a bad recognition block, or
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
    assert guardian.said == "EK_25_Gj2iHnu-0TpqYtqGgAMq1ZYml4K1G2R1sO8aV0"
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
    # The edge section is closed at subject + authorization: any other edge (here the
    # 'scope' edge an external delegated-authority credential would have hung off) is
    # rejected, so the guardian credential carries no hook to one.
    extraEdge = json.loads(json.dumps(guardian.sad))
    extraEdge['e']['scope'] = dict(d='', n=sedi.said, s=sedi.sad['s']['$id'], o='NI2I')
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(extraEdge)


PRESENT_STAMP = "2026-07-20T15:18:00.000000+00:00"


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
    attribute = dict(d='', u=NONCES[N_P_A], i=SERVICE,
                     purpose="Open a children's-service account for a ward under 13 "
                             "with verifiable guardian consent.",
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
    assert presentation.said == "EH9Rzi__y_-_DWkT5syI8Vkr3--eRmqlXNR5xe7QdsNd"

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
                        schema=otherSchema, attribute=_sedi_attr(), iseaid=SERVICE, kind=kind)
    with pytest.raises(AssertionError):
        _verify_representation(presentation, guardian, otherWard, age)

    # --- The gated IPEX exchange: the ward's age flag crosses only in the grant. ---
    # 1. apply (service -> Bob): the challenge -- which schemas/fields, and the
    # governance framework the service will honor (guardian acceptance in scope).
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
    # it technically unnecessary (@SmithSamuelM, #1549). This DAG has no optional edges,
    # so the ordering is gapless and each entry's ACDC is unambiguous without restating
    # the route to it.
    #
    # A '/'-rooted prefix would make the effective paths DAG-ABSOLUTE, rooted at the
    # origin node, and an absolute path reaching a non-origin ACDC must cross the edge
    # that links it -- the virtual '_' component, standing for the jump from the
    # near-side edge block to the top level of the far-side ACDC (@SmithSamuelM, #1549).
    # The same request written with non-empty prefixes reads:
    #     origin:   "/"                 ["i", "a/i"]
    #     guardian: "/e/authority/_/"   ["a/i", "a/powers"]
    #     ward age: "/e/wardAge/_/"     ["A/i", "A/over13"]
    #
    # A represented presentation is the case that makes the joining paths load-bearing:
    # the service asks for the issuee from BOTH the guardian credential (a/i -- who is
    # acting) and the ward's age credential (A/i -- whose fact is being asserted), and
    # those two issuees are deliberately DIFFERENT AIDs. It is the guardianship edge,
    # not issuee equality, that licenses Bob to speak for Mia.
    #
    # The zeroth entry is the DAG's origin node (#1549): Bob's presentation. Its schema
    # is governance even though Bob issues it -- "in all of these applications the
    # Applicant would know the schema of the origin node despite it being a presenter
    # issued ACDC" (@SmithSamuelM, #1542) -- so the service can name it in a
    # first-contact apply. It asks the origin only for issuer and issuee, which in a
    # represented presentation is the first place the holder != subject split shows:
    # the origin's issuer is Bob, and the ward never appears in it at all.
    presentSchemaSaid, _ = _saidify_schema(dict(PRESENTATION_SCHEMA_MAD), kind=kind)
    apply = exchange(sender=SERVICE, receiver=BOB, route="/ipex/apply",
                     modifiers=dict(dp=[[presentSchemaSaid, "", ["i", "a/i"]],
                                        [guardian.sad['s']['$id'], "", ["a/i", "a/powers"]],
                                        [age.sad['s']['$id'], "", ["A/i", "A/over13"]]]),
                     attributes=dict(m="Prove an authorized guardian and that the ward "
                                       "is under 13.",
                                     g=GUARDIAN_RULES_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['r'] == "/ipex/apply" and apply.sad['i'] == SERVICE
    dp = apply.sad['q']['dp']
    assert [entry[0] for entry in dp] == [presentSchemaSaid,
                                          guardian.sad['s']['$id'], age.sad['s']['$id']]
    assert all(len(entry) == 3 for entry in dp)             # (schemaSAID, prefix, [paths])
    assert [entry[1] for entry in dp] == ["", "", ""]       # no prefixes: paths stay relative
    assert dp[0][2] == ["i", "a/i"]             # origin: who presents, and to whom
    assert dp[1][2] == ["a/i", "a/powers"]      # attributive guardian cred: who acts, and how far
    assert dp[2][2] == ["A/i", "A/over13"]      # aggregative ward age cred: whose, and the flag
    assert all(not p.startswith("/") and not p.endswith("/")
               for _, _, paths in dp for p in paths)
    assert 'disclose' not in apply.sad['a'] and set(apply.sad['a']) == {'m', 'g'}
    assert apply.said == "EGOICgCYMQLiV2BQnLP0XRgb3aa7cqHmBOY2VX60Rj-o"

    # 2. offer (Bob -> service): commits ONLY to the Discloser's own presentation SAID
    # and the governance ref, and binds the apply. It deliberately does NOT enumerate the
    # issuer-committed source-credential SAIDs (guardian/sedi/age): those are issuer
    # commitments, and attaching them before the service agrees would let a verifier
    # spurn and walk away with stable ward/guardian correlators, defeating the
    # metadata-ACDC decorrelation (panel review, PRV-F2). They arrive only post-agree, in
    # the grant, reachable by expanding the delivered presentation.
    # Its query block carries `dp` as an EMPTY list: the offer is SOLICITED (its `p`
    # binds the apply), and an empty `dp` means "the same paths the apply asked for"
    # (#1549), so Bob restates nothing and the two messages cannot drift.
    offer = exchange(sender=BOB, receiver=SERVICE, route="/ipex/offer", prior=apply.said,
                     modifiers=dict(dp=[]),
                     attributes=dict(acdc=presentation.said,
                                     governance=GUARDIAN_RULES_SAID),
                     stamp=OFFER_STAMP, kind=kind)
    assert offer.sad['p'] == apply.said
    assert offer.sad['q']['dp'] == []                         # solicited: "as per the apply"
    assert offer.said == "EIvw3jUdSdpE2cNFHUSCGjDJKYDX5EQevL6G9-LT8iQ2"
    assert presentation.said.encode() in offer.raw            # Discloser's own commitment
    assert b"Mia Carver" not in offer.raw and b"2020-03-15" not in offer.raw   # no PII
    # Issuer commitments withheld until after the service agrees (PRV-F2):
    assert guardian.said.encode() not in offer.raw
    assert sedi.said.encode() not in offer.raw
    assert age.said.encode() not in offer.raw

    # 3. agree (service -> Bob): acceptance, binding the offer SAID and signed by the
    # service (via messagize -- the blessed genus-aware attachment path).
    agree = exchange(sender=SERVICE, receiver=BOB, route="/ipex/agree", prior=offer.said,
                     stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    assert agree.said == "EAeLJZGZE2TFNUinYqQCQI2KqynLupq7BH1ieqja2vXi"
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

    # The valid agree unlocks the grant; the ward's age flag appears only now, and
    # the birthdate and every other threshold stay off the wire.
    grant = disclose(agree, svcSig, capturedKeyState)
    assert grant is not None and grant.sad['p'] == agree.said
    assert grant.said == "EOuqGP8kkcw-vMlOQgybBrfJ4BuQPGZFwfdKEqIp5oaU"
    assert grant.sad['a']['wardAge'][AGE_OVER13]['over13'] is False    # under-13 disclosed
    assert grant.sad['a']['wardId']['i'] == MIA                       # ward bound (issuee)
    assert b"2020-03-15" not in grant.raw                             # birthdate withheld
    assert b"over18" not in grant.raw and b"over21" not in grant.raw   # thresholds withheld

    # 5. admit (service -> Bob): closes the exchange.
    admit = exchange(sender=SERVICE, receiver=BOB, route="/ipex/admit", prior=grant.said,
                     stamp=ADMIT_STAMP, kind=kind)
    assert admit.sad['p'] == grant.said
    assert admit.said == "EK84WCNy-VFpXjKI2fsAJQ0Wo3MiukX6y1z7udnUQCMy"


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
    assert issuedBlinder.said == "EOncwOptXfMMqYCfejdrtkJuu_joNLDK43kckv9HuZ_-"
    assert issued.said == "EFNU7aRxjIXA3N8V0gUM3fwXswlMz0v8UC6WmRNFjh7D"
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
    assert revoked.said == "EBZk65eshMVhrj5n_fK4vEScui9IOK7oBUIt3yxjTIz0"
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
