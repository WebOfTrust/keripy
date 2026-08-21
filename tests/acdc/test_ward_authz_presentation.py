# -*- coding: utf-8 -*-
"""
tests.acdc.test_ward_authz_presentation module

Worked, working example of a DELEGATED AUTHORIZATION that the ward presents herself: a
guardian issues his ward an ACDC carrying an attenuated slice of his own authority, and the
ward -- not the guardian -- shows it to the service that gates the act. It is the shape
@SmithSamuelM drew in WebOfTrust/keripy discussion #1550, in the diagram "Ward with Single
Guardian Issues Authorization: Ward to Access Social".

TWO REGIMES, TWO MODULES, and the split is statutory. Utah Code 63A-20-302(3)(a): "If an
individual is unable to apply for a state-endorsed digital identity due to the individual's
youth or incapacitation, the application may be made on behalf of that individual by the
individual's digital guardian." A ward who cannot act -- an infant, or an adult who has lost
capacity -- has a guardian who custodies her keys and presents ABOUT her, and there the
invariant is holder != subject, so a verifier can always tell that a guardian and not the
ward is acting. That is the sibling, tests/acdc/test_guardianship_presentation.py (PR
#1530), whose ward is a seven-year-old. A ward who CAN act holds her own keys and acts as
herself, bounded by what her guardian has authorized. That is THIS module, and the
invariant here is attenuation rather than holder != subject. Bob Carver is the custodial
parent in both -- his seven-year-old Mia is the sibling's ward, his 17-year-old Cara is
this one's.

Scenario, under Utah's Minor Protection in Social Media Act (Utah Code 13-71). Cara is 17,
so she is a "minor" (13-71-101(8): under 18, unemancipated, unmarried), and a social media
company must run an age assurance system that identifies her as one (13-71-201). Being a
minor does NOT gate her account: it forces maximum-privacy defaults, limiting visibility,
sharing and direct messaging to connected accounts (13-71-202). Two platform duties then
turn on her parent's authority. She may not change those defaults without verifiable
parental consent (13-71-204(1)), and the supervisory tools she may activate are configured
by "an individual selected by the Utah minor account holder", who sets daily time limits
and mandatory breaks (13-71-203). Both are authority Bob holds and Cara exercises, so he
issues her an ACDC naming the routes, capabilities and daily window she may use -- drawn
from, and no larger than, what the State recognized in him -- and SHE presents it.

WHAT THIS EXAMPLE DOES NOT CLAIM. 13-71-101(18) defines "verifiable parental consent" as a
notice ritual running toward the parent: the service gives the parent advance notice of its
information practices, and receives confirmation that the parent received it. An AuthZ
credential runs the other way -- a parent-issued, cryptographically verifiable grant the
ward carries -- so it models the parental AUTHORITY that 13-71-204(1) and 13-71-203 make
load-bearing, not the statutory consent ceremony. A deployment wanting both would pair
them; nothing here substitutes for the notice.

Four credentials, all v2 ACDCs, all registry-bound, each validated against a
purpose-authored JSON Schema (Draft 2020-12):

  1. Guardian as Citizen  -- State -> Bob.  His own SEDI identity credential.
  2. Guardian as Guardian -- State -> Bob.  The recognized guardianship, whose attribute
     block carries the WARD's AID as well as Bob's (see the divergence below). Edge to (1).
  3. Ward as Citizen Ward -- State -> Cara. Her own SEDI identity credential, which by its
     edge to (2) DECLARES ITSELF ENCUMBERED, so a verifier reading only her credential
     learns that her identity is not unencumbered.
  4. Ward AuthZ Social    -- Bob -> Cara, in BOB's OWN registry (not the State's), carrying
     the routes and capabilities she may exercise. Edges to (2) and (3).

Four edges, four different operators, and getting each right is the security content here.
Every one is PINNED by a schema const, so a mislabeled operator fails at wire validation:

  * (4) -> (2) authority, I2I: near issuer Bob == far issuee Bob, which proves Bob HELD
    what he delegates. Without it the AuthZ credential is a stranger's assertion of
    permissions over someone else's child.
  * (4) -> (3) subject, E1E: same subject (Cara), different issuers (Bob vs the State).
    I2I would demand Bob == Cara and would FALSELY REJECT a sound identity relation, where
    E1E (PR #1527) constrains the issuee only. This is the second independent use case for
    the operator, and unlike the first it comes from Sam's diagram rather than from the PR
    that proposed it.
  * (2) -> (1) citizen, E1E again: same subject, and here the same issuer too -- which is
    not what makes it identity. I2I would demand State == Bob.
  * (3) -> (2) guardian, NI2I: different subjects, so neither targeted operator applies.
    The untargeted reference is right for "my credential points at somebody else's" --
    here, the encumbrance marker.

E1E carries the same caveat as in the sibling: it is not yet in the spec's closed operator
set {I2I, NI2I, DI2I, NOT}, and a spec-default or pre-#1527 verifier COERCES an unknown
operator rather than rejecting it -- to I2I for a targeted far node, wrongly rejecting both
E1E edges here. So this graph needs a #1527-or-later verifier until E1E is ratified (#1515).

RECORDED DIVERGENCE: where the ward AID lives. Sam's diagram puts it in the ATTRIBUTE block
of (2); the sibling names the ward only by an EDGE. Both preserve holder != subject, so this
is a DISCLOSURE choice, and the edge form is better on Sam's own argument from #1515 that an
edge "can also be blinded, which means that disclosure of the edge itself can be held back
until the verifier (disclosee) has agreed not to exploit its correlatability" -- where a
whole-disclosed attribute cannot be held back at all. This module models SAM's placement
because it is his diagram, and the question is open on #1550; Phase 4 shows the argument
arriving as an actual leak, since the guardianship's expiry is Cara's 18th birthday.

The AuthZ payload is ILLUSTRATIVE and its syntax UNSETTLED. Sam says only that the field
"contains the specifics of the authorization. The syntax TBD", and points at EVAC (Edge
Verifiable Agent Control), sketched at the end of #1550 as a resource-capabilities map 'rc'
of the form {resourceRoute: [capability, ...]}. That is modeled here, plus the time window
13-71-203 makes relevant, and no assertion reaches into it (the seam is
_authz_capabilities, so a syntax change is one function rather than a rewrite). One
constraint on that syntax is not taste, and this example measured it by serializing rather
than arguing: a route written as a map LABEL falls under CESR's strict field-label grammar,
so "social/feed" cannot be serialized in native CESR at all. The measurement, and the
recommendation it produces for #1550 -- carry the route as a VALUE -- are at
AUTHZ_BLOCK_SCHEMA.

The negative that earns its place: a guardian cannot delegate more than he holds, so (4)'s
capability tokens must be a SUBSET of (2)'s 'powers'. Over-reach is a binding property
rather than a shape property, so the greedy credential is schema-valid and the binding, not
the schema, refuses it (Phase 3). Naming divergence from the sibling while reading 'powers':
there it is the coarse statutory scope enum, carried here as 'scope'.

A note on altitude, the same one the siblings carry. This models the credential graph, the
edge bindings and the registry binding at the data-structure level, built from the real v2
primitives in keri.acdc.messaging and keri.core (acdcmap, Compactor, Mapper, exchange). It
does not stand up a Habery/keystore or route through keri.vdr.verifying.verifyChain, which
needs a live Reger/Tevery; PR #1527 unit-tests its real E1E branch. Actor AIDs and nonces
derive from fixed salts, so the module is reproducible.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from keri import Kinds, Ilks
from keri.core import (Salter, Noncer, Compactor, Mapper, Diger, Verfer,
                       exchange, messagize)
from keri.core.coring import MtrDex
from keri.core.eventing import incept
from keri.acdc import regcept, acdcmap
from keri.help.helping import ATREX


# --- Reproducible example actors (see module docstring). ---
# Four actors, each a self-addressing ('E') transferable AID: its prefix is the SAID of
# an inception event committing to the actor's current signing key and a digest of its
# pre-rotated next key. Eight signers from one fixed salt: _SIGNERS[0..3] are the four
# actors' current signing keys (State, Bob, Cara, the social service) and _SIGNERS[4..7]
# are their matching pre-rotated next keys.
_SIGNERS = Salter(raw=b'wardauthzexamsal').signers(count=8, transferable=True,
                                                   temp=True)


def _actor_aid(cur, nxt):
    """Self-addressing (E) AID: the SAID of an inception committing to cur + next(nxt)."""
    return incept(keys=[cur.verfer.qb64],
                  ndigs=[Diger(ser=nxt.verfer.qb64b).qb64],
                  code=MtrDex.Blake3_256).pre


# STATE = the Utah state agency that endorses citizens and recognizes guardianships;
# BOB = the custodial parent (guardian); CARA = the 17-year-old ward, who holds her own
# keys; SOCIAL = the social media company, which under 13-71 must identify her as a minor
# and hold her account to maximum-privacy defaults she cannot change on her own.
STATE, BOB, CARA, SOCIAL = (_actor_aid(_SIGNERS[i], _SIGNERS[i + 4]) for i in range(4))

# Per-example blinding nonces, derived (not pasted) from a distinct raw prefix so this
# file shares no nonce values with the sibling examples.
RAWS = [b'wardauthzexamra' + b'%0x' % (i,) for i in range(32)]
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

    A nested attribute block has one shape -- oneOf(block SAID, {d, u, <attr>}). A
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


# acm is a fixed-field format: it always carries (possibly empty) e and r sections even
# when unused, so the schema must admit them.
_EMPTY_OR_SECTION = {"oneOf": [{"type": "string"}, {"type": "object"}]}


def _edge_schema(op_const, desc):
    """One edge schema whose operator is PINNED to a single value (const op_const).

    Pinning the operator in the schema is what makes each of this example's four
    relationships schema-enforced rather than conventional: the I2I authority edge, the
    two E1E identity edges and the NI2I encumbrance edge cannot be silently swapped for
    one another without failing wire validation. It also means E1E is never INFERRED --
    an unlabeled identity edge would default to I2I, which is the wrong answer here.
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


# --- The SEDI citizen credential, shared shape for (1) Bob's and (3) Cara's. ---
# Fixed, well-labeled identity fields, so an attribute section with individually
# partially-disclosable nested blocks is the right model: labels give clean paths and
# clean partial disclosure. The issuee 'i' is the citizen. Cara's differs from Bob's in
# exactly one way -- it carries the encumbrance edge -- so the schema is authored twice
# rather than shared, since the edge section is what a verifier reads to tell an
# unencumbered citizen credential from a ward's.
def _citizen_properties():
    """The identity attribute properties both citizen credentials carry."""
    return {
        "d": {"description": "Section SAID", "type": "string"},
        "u": {"description": "Section UUID", "type": "string"},
        "i": {"description": "Issuee (the citizen) AID", "type": "string"},
        "name": _disclosable_block("name",
            {"description": "Full name", "type": "string"}, "Name"),
        "dob": _disclosable_block("dob",
            {"description": "Date of birth", "type": "string", "format": "date"},
            "DOB"),
        "residence": _disclosable_block("residence",
            {"description": "Residence", "type": "string"}, "Residence"),
    }


# --- (1) Guardian as Citizen: the guardian's own SEDI identity credential. ---
# State -> Bob. Registry-bound. No edges: an adult citizen credential stands alone,
# which is precisely the contrast the ward's credential draws.
GUARDIAN_CITIZEN_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Citizen Credential",
    "description": "State-endorsed SEDI identity credential for an adult citizen; "
                   "attributes carried as individually partially-disclosable nested "
                   "blocks. Stands alone: no encumbrance edge.",
    "credentialType": "SEDI_Citizen",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (the State agency) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute section with individually-disclosable blocks",
              "oneOf": [
                  {"description": "Attribute Section SAID", "type": "string"},
                  {"description": "Attribute detail", "type": "object",
                   "required": ["d", "u", "i", "name", "dob", "residence"],
                   "properties": _citizen_properties(),
                   "additionalProperties": False}]},
        "e": _EMPTY_OR_SECTION,
        "r": {"description": "SAID of the SEDI citizen governance framework",
              "type": "string"},
    },
    "additionalProperties": False,
}

# --- (3) Ward as Citizen Ward: the ward's own SEDI identity credential. ---
# State -> Cara. Identical attribute shape to (1), plus ONE required edge back to the
# guardianship credential (2). That edge is the point: the ward's own credential
# DECLARES that it is encumbered, so a verifier who reads only Cara's credential learns
# that a guardianship stands over her identity. Its operator is NI2I, and it must be:
# the near issuee is Cara and the far issuee is Bob, which are different subjects, so
# neither the delegative I2I nor the identity E1E applies.
WARD_CITIZEN_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Ward Citizen Credential",
    "description": "State-endorsed SEDI identity credential for a citizen under "
                   "guardianship. Same attribute shape as the adult citizen credential, "
                   "plus a REQUIRED NI2I edge to the guardianship credential -- the "
                   "ward's own credential declares that it is encumbered.",
    "credentialType": "SEDI_CitizenWard",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a", "e", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer (the State agency) AID", "type": "string"},
        "rd": {"description": "Registry SAID", "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute section with individually-disclosable blocks",
              "oneOf": [
                  {"description": "Attribute Section SAID", "type": "string"},
                  {"description": "Attribute detail", "type": "object",
                   "required": ["d", "u", "i", "name", "dob", "residence"],
                   "properties": _citizen_properties(),
                   "additionalProperties": False}]},
        "e": {"description": "Edge section: the encumbrance edge to the guardianship",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "guardian"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "guardian": _edge_schema(
                                      "NI2I", "encumbrance: a guardianship over this "
                                              "citizen, held by someone else")},
                   "additionalProperties": False}]},
        "r": {"description": "SAID of the SEDI ward governance framework",
              "type": "string"},
    },
    "additionalProperties": False,
}

# The delegable capability vocabulary. 'powers' on the guardianship credential (2) is
# drawn from it, and so is every capability list in the AuthZ credential (4); the subset
# check is what keeps (4) inside (2). Note the naming divergence from the sibling module
# recorded in the docstring: 'powers' there is the coarse statutory scope enum, which
# here is 'scope'.
CAPABILITIES = ["read", "post", "message", "profile", "configure", "purchase",
                "livestream"]

# The coarse statutory scope enum, the same vocabulary the sibling module carries. Utah
# prefers LIMITED guardianship, so a verifier checks the specific act against scope
# before it ever looks at the fine-grained capabilities.
SCOPES = ["plenary", "healthCare", "residence", "education", "personalRecords",
          "socialBenefits", "digitalIdentity", "contracts"]

# --- (2) Guardian as Guardian: the recognized guardianship. ---
# State -> Bob, registry-bound (guardianship terminates dynamically, so a verifier MUST
# check current status rather than trusting a date). Disclosed WHOLE: a verifier needs
# basis + scope + powers + validity together, so the attribute section is flat.
#
# SAM'S PLACEMENT, and the recorded divergence: the ward's AID sits in the ATTRIBUTE
# block, next to the guardian's issuee AID, exactly as drawn in #1550. The sibling #1530
# names the ward by edge instead. See the module docstring for why the edge form is
# better for disclosure and why this is recorded rather than decided.
GUARDIAN_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SEDI Digital Guardian",
    "description": "SEDI legal-recognition layer for a digital guardian (Utah Code "
                   "63A-20). Held by the guardian (issuee); the WARD's AID is carried "
                   "in the attribute block per the #1550 diagram (the sibling #1530 "
                   "names the ward by edge instead). Registry-bound: guardianship "
                   "terminates dynamically. One E1E edge to the guardian's own citizen "
                   "credential.",
    "credentialType": "SEDI_Guardian",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a", "e", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer = the recognizing State agency", "type": "string"},
        "rd": {"description": "Registry SAID -- MANDATORY (dynamic termination)",
               "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "The recognized guardianship (disclosed whole)",
              "oneOf": [
                  {"description": "Attribute Section SAID", "type": "string"},
                  {"type": "object",
                   "required": ["d", "u", "i", "ward", "basis", "scope", "powers",
                                "fiduciary", "effectiveDate"],
                   "properties": {
                       "d": {"description": "Section SAID", "type": "string"},
                       "u": {"description": "Section UUID", "type": "string"},
                       "i": {"description": "Issuee = the GUARDIAN's AID",
                             "type": "string"},
                       "ward": {"description": "The WARD's AID, in the attribute block "
                                               "per the #1550 diagram",
                                "type": "string"},
                       "basis": {"description": "Which statutory basis",
                                 "enum": ["designatedRepresentative", "custodialParent",
                                          "courtGuardianMinor",
                                          "courtGuardianIncapacitated"]},
                       "scope": {"description": "Coarse statutory scope (Utah prefers "
                                                "LIMITED guardianship)",
                                 "type": "array", "minItems": 1, "uniqueItems": True,
                                 "items": {"enum": SCOPES}},
                       "powers": {"description": "The DELEGABLE capability set: the "
                                                 "ceiling on any authorization the "
                                                 "guardian issues to the ward",
                                  "type": "array", "minItems": 1, "uniqueItems": True,
                                  "items": {"enum": CAPABILITIES}},
                       "fiduciary": {"enum": ["bestInterest", "substitutedJudgment"]},
                       "effectiveDate": {"type": "string", "format": "date"},
                       "expiryDate": {"type": "string", "format": "date"},
                   },
                   "additionalProperties": False}]},
        "e": {"description": "Edge section: E1E to the guardian's own citizen credential",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "citizen"],
                   "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                                  "citizen": _edge_schema(
                                      "E1E", "identity: the guardian's own citizen "
                                             "credential, same subject")},
                   "additionalProperties": False}]},
        "r": {"description": "SAID of the SEDI guardianship governance framework",
              "type": "string"},
    },
    "additionalProperties": False,
}

# --- (4) Ward AuthZ Social: the delegated authorization. ---
# Bob -> Cara, in BOB'S OWN registry. This is the credential the ward presents. Its
# attribute block carries the AuthZ payload; its two edges are the security content.
#
# ILLUSTRATIVE PAYLOAD, SYNTAX UNSETTLED. Sam says of the AuthZ field only that it
# "contains the specifics of the authorization. The syntax TBD", and points at EVAC
# (Edge Verifiable Agent Control), sketched at the end of #1550 as a resource-
# capabilities map 'rc' of the form {resourceRoute: [capability, ...]}. That shape is
# adopted here verbatim rather than a third vocabulary being invented, plus a time
# window, and additionalProperties stays OPEN so a later syntax can grow into the slot.
#
# ONE MEASURED CONSTRAINT ON THAT SYNTAX, which this example surfaced by serializing it.
# Making the resource route a map LABEL puts it under CESR's strict field-label grammar,
# ATREX = ^[a-zA-Z_][a-zA-Z0-9_]*$ (src/keri/help/helping.py), enforced by Labeler for
# every native-CESR field map -- and an ACDC attribute section is always compacted
# through a strict Compactor, so this is not optional. A route written the obvious way,
# "social/feed", therefore CANNOT be serialized in native CESR at all: it raises
# SerializeError, not a validation warning. Routes here use '_' as the separator so the
# example serializes on every kind, and the constraint is PINNED below by propertyNames
# rather than merely observed. A syntax that wants real slash-separated routes has to
# carry the route as a VALUE -- 'rc' as a list of {route, caps} objects -- rather than
# as a label. That is a genuine input to the TBD, and it is why this block is worth
# serializing over CESR rather than JSON alone.
_ROUTE_PATTERN = "^[a-zA-Z_][a-zA-Z0-9_]*$"     # CESR's strict field-label grammar
AUTHZ_BLOCK_SCHEMA = {
    "description": "ILLUSTRATIVE authorization payload; SYNTAX UNSETTLED. Modeled on "
                   "the EVAC (Edge Verifiable Agent Control) sketch in WebOfTrust/"
                   "keripy discussion #1550: a resource-capabilities map 'rc' of the "
                   "form {resourceRoute: [capability, ...]}, here with a time window. "
                   "Because the route is a map LABEL it is constrained to CESR's strict "
                   "field-label grammar, so a slash-separated route is not representable "
                   "in native CESR; a syntax needing those must carry the route as a "
                   "value instead. Additional properties are ALLOWED so a later syntax "
                   "can extend this block without invalidating the example.",
    "type": "object",
    "required": ["rc"],
    "properties": {
        "rc": {"description": "Resource-capabilities map: route -> capability list. "
                              "Route labels are pinned to CESR's strict field-label "
                              "grammar, which native-CESR serialization enforces.",
               "type": "object", "minProperties": 1,
               "propertyNames": {"pattern": _ROUTE_PATTERN},
               "additionalProperties": {"type": "array", "minItems": 1,
                                        "uniqueItems": True,
                                        "items": {"enum": CAPABILITIES}}},
        "window": {"description": "Time window over which the authorization is live",
                   "type": "object",
                   "required": ["start", "end"],
                   "properties": {
                       "start": {"type": "string"},
                       "end": {"type": "string"},
                       "dailyHours": {"description": "Local clock window, e.g. "
                                                     "16:00-20:00",
                                      "type": "string"},
                       "tz": {"description": "IANA time zone", "type": "string"}},
                   "additionalProperties": True},
    },
    "additionalProperties": True,
}

AUTHZ_SCHEMA_MAD = {
    "$id": "",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Ward AuthZ Social",
    "description": "A guardian-issued delegated authorization the WARD holds and "
                   "presents herself. Issuer = the guardian, issuee = the ward, bound "
                   "to the GUARDIAN's own registry. Two pinned edges: I2I to the "
                   "guardianship credential (the guardian held what he delegates) and "
                   "E1E to the ward's own citizen credential (same subject, different "
                   "issuers -- the case I2I would falsely reject).",
    "credentialType": "WardAuthZSocial",
    "version": "1.0.0",
    "type": "object",
    "required": ["v", "d", "i", "rd", "s", "a", "e", "r"],
    "properties": {
        "v": {"description": "ACDC version string", "type": "string"},
        "t": {"description": "Message type", "const": "acm"},
        "d": {"description": "Message SAID", "type": "string"},
        "u": {"description": "Message UUID", "type": "string"},
        "i": {"description": "Issuer = the GUARDIAN (not the State)", "type": "string"},
        "rd": {"description": "Registry SAID -- the GUARDIAN's own registry",
               "type": "string"},
        "s": {"description": "Schema Section",
              "oneOf": [{"type": "string"}, {"type": "object"}]},
        "a": {"description": "Attribute Section carrying the authorization payload",
              "oneOf": [
                  {"description": "Attribute Section SAID", "type": "string"},
                  {"type": "object",
                   "required": ["d", "u", "i", "authz", "issuedAt"],
                   "properties": {
                       "d": {"description": "Section SAID", "type": "string"},
                       "u": {"description": "Section UUID", "type": "string"},
                       "i": {"description": "Issuee = the WARD's AID", "type": "string"},
                       "authz": AUTHZ_BLOCK_SCHEMA,
                       "issuedAt": {"type": "string"}},
                   "additionalProperties": False}]},
        "e": {"description": "Edge section: I2I authority + E1E subject",
              "oneOf": [
                  {"type": "string"},
                  {"type": "object", "required": ["d", "authority", "subject"],
                   "properties": {
                       "d": {"type": "string"}, "u": {"type": "string"},
                       "authority": _edge_schema(
                           "I2I", "the guardian holds this authority"),
                       "subject": _edge_schema(
                           "E1E", "identity: the ward's own citizen credential, same "
                                  "subject, different issuer")},
                   "additionalProperties": False}]},
        "r": {"description": "SAID of the delegated-authorization governance framework",
              "type": "string"},
    },
    "additionalProperties": False,
}

# Published governance frameworks, referenced BY SAID rather than authored here. Each is
# a PLACEHOLDER digest of a description string, standing in for the SAID a real
# deployment computes over the governance document.
CITIZEN_RULES_SAID = Diger(ser=b'SEDI citizen governance framework v1').qb64
WARD_RULES_SAID = Diger(ser=b'SEDI ward governance framework v1').qb64
GUARDIAN_RULES_SAID = Diger(ser=b'SEDI guardianship governance framework v1').qb64
AUTHZ_RULES_SAID = Diger(
    ser=b'SEDI delegated-authorization governance framework v1').qb64

# Registry inception timestamps: the State's citizen registry, the State's guardianship
# registry, and the guardian's OWN registry that the AuthZ credential binds to.
REG_CITIZEN_STAMP = "2026-01-05T12:00:00.000000+00:00"
REG_GUARDIAN_STAMP = "2026-01-06T12:00:00.000000+00:00"
REG_AUTHZ_STAMP = "2026-07-01T12:00:00.000000+00:00"

# Fixed timestamps for the credentials and the IPEX exn messages (kept stable so SAIDs
# are reproducible).
AUTHZ_STAMP = "2026-08-01T09:00:00.000000+00:00"
APPLY_STAMP = "2026-08-03T18:00:00.000000+00:00"
OFFER_STAMP = "2026-08-03T18:01:00.000000+00:00"
AGREE_STAMP = "2026-08-03T18:02:00.000000+00:00"
GRANT_STAMP = "2026-08-03T18:03:00.000000+00:00"
ADMIT_STAMP = "2026-08-03T18:04:00.000000+00:00"

# --- Blinding-nonce / uuid slot allocation: each NONCES[i] used at most once. ---
# three registries.
N_REG_CITIZEN, N_REG_GUARDIAN, N_REG_AUTHZ = 0, 1, 2
# (1) guardian-as-citizen: attribute uuid + three block nonces + acdc uuid.
N_GC_A, N_GC_NAME, N_GC_DOB, N_GC_RES, N_GC_ACDC = 3, 4, 5, 6, 7
# (2) guardian-as-guardian: attribute uuid, acdc uuid, edge-section uuid, one edge uuid.
N_GG_A, N_GG_ACDC, N_GG_E, N_GG_E_CIT = 8, 9, 10, 11
# (3) ward-as-citizen: attribute uuid + three block nonces + acdc uuid, edge-section
# uuid, one edge uuid.
N_WC_A, N_WC_NAME, N_WC_DOB, N_WC_RES = 12, 13, 14, 15
N_WC_ACDC, N_WC_E, N_WC_E_GUARD = 16, 17, 18
# (4) ward AuthZ social: attribute uuid, acdc uuid, edge-section uuid, two edge uuids.
N_AZ_A, N_AZ_ACDC, N_AZ_E, N_AZ_E_AUTH, N_AZ_E_SUBJ = 19, 20, 21, 22, 23

# Cara's age at presentation (DOB 2009-04-10, presentation 2026-08-03). 13-71 grades no
# finer than "minor" (under 18), so her exact age is legally immaterial; what matters is
# that she operates her own device and holds her own keys, which is why the ward presents
# here and the guardian presents in the sibling, whose ward is seven
# (tests/acdc/test_guardianship_presentation.py).
CARA_AGE = 17


def _citizen_registry(kind):
    """The State's citizen registry inception (rip event): (1) and (3) bind to it."""
    return regcept(israid=STATE, uuid=NONCES[N_REG_CITIZEN], stamp=REG_CITIZEN_STAMP,
                   kind=kind)


def _guardian_registry(kind):
    """The State's guardianship registry inception. Guardianship terminates dynamically
    (majority, restored capacity, court order), so (2) is registry-bound and a verifier
    checks current status rather than trusting the expiry date."""
    return regcept(israid=STATE, uuid=NONCES[N_REG_GUARDIAN], stamp=REG_GUARDIAN_STAMP,
                   kind=kind)


def _authz_registry(kind):
    """The GUARDIAN's OWN registry. (4) is issued by Bob, not the State, so it binds to
    Bob's registry -- which is also where he revokes the authorization when he changes
    his mind, without the State being involved at all. This registry independence is a
    structural consequence of the ward-presents shape: the delegation is the guardian's
    act, so its lifecycle is the guardian's to manage."""
    return regcept(israid=BOB, uuid=NONCES[N_REG_AUTHZ], stamp=REG_AUTHZ_STAMP,
                   kind=kind)


def _guardian_citizen_attr():
    """Bob's citizen attribute section (a fresh map each call).

    Attributive: the issuee ('i') is inserted at the top of the section by acdcmap via
    iseaid, and each identity attribute is its own individually-blinded (own 'u'),
    self-addressing (own 'd') nested block, so it can be disclosed or withheld
    independently of the others.
    """
    return dict(d='', u=NONCES[N_GC_A],
                name=dict(d='', u=NONCES[N_GC_NAME], name="Bob Carver"),
                dob=dict(d='', u=NONCES[N_GC_DOB], dob="1988-02-17"),
                residence=dict(d='', u=NONCES[N_GC_RES], residence="Provo UT"))


def _ward_citizen_attr():
    """Cara's citizen attribute section (a fresh map each call). Same shape as Bob's --
    what distinguishes a ward's citizen credential is the encumbrance EDGE, not the
    attributes."""
    return dict(d='', u=NONCES[N_WC_A],
                name=dict(d='', u=NONCES[N_WC_NAME], name="Cara Carver"),
                dob=dict(d='', u=NONCES[N_WC_DOB], dob="2009-04-10"),
                residence=dict(d='', u=NONCES[N_WC_RES], residence="Provo UT"))


def _guardian_attr(powers=None):
    """Bob's guardianship attribute section (a fresh map each call).

    Disclosed whole (flat, not selectively disclosable): a verifier needs basis + scope
    + powers + validity together. basis = custodialParent (the inherent parental right);
    scope limited to digitalIdentity; powers is the DELEGABLE capability set, and it is
    the ceiling every AuthZ credential Bob issues must stay under. 'ward' carries Cara's
    AID in the attribute block per Sam's #1550 diagram (see the module docstring's
    recorded divergence).
    """
    if powers is None:
        powers = ["read", "post", "message", "profile", "configure"]
    return dict(d='', u=NONCES[N_GG_A],
                ward=CARA,
                basis="custodialParent",
                scope=["digitalIdentity"],
                powers=list(powers),
                fiduciary="bestInterest",
                # The date the State RECOGNIZED the digital guardianship, deliberately
                # not the date the parental right arose. For a custodial parent the
                # latter is the ward's birth date, and an authority credential that both
                # models agree is disclosed WHOLE cannot withhold an attribute -- so an
                # effectiveDate of 2009-04-10 would hand every verifier Cara's exact
                # birthdate while her own citizen credential was carefully withholding
                # it. That is the docstring's disclosure argument arriving as a concrete
                # leak rather than a principle, and it is dodged here rather than
                # asserted, since a real deployment records the recognition date anyway.
                effectiveDate="2026-01-06",
                # Majority: Cara's 18th birthday. This DOES leak her birth month and day
                # (2027-04-10 minus 18 years), and is left in as an honest residual --
                # a termination date is load-bearing for a verifier in a way an
                # effective date is not, so the fix is a coarser expiry (a quarter, a
                # year) rather than dropping the field, and that is a schema decision
                # for a deployment rather than something this example should invent.
                expiryDate="2027-04-10")


def _authz_block():
    """The ILLUSTRATIVE AuthZ payload (a fresh map each call).

    EVAC-shaped (#1550): 'rc' maps a resource route to the capability list the ward may
    exercise on it, and 'window' bounds when. Bob grants Cara a read-only feed, posting
    on her own posts route, and direct messages -- and does NOT grant 'purchase',
    'livestream' or anything else he holds. The capability tokens here are a strict
    subset of the 'powers' in the guardianship credential, which is the property
    _verify_authz_chain enforces.
    """
    return dict(rc={"social_feed": ["read"],
                    "social_posts": ["read", "post"],
                    "social_dm": ["read", "message"]},
                window=dict(start="2026-08-01T00:00:00+00:00",
                            end="2026-11-30T23:59:59+00:00",
                            dailyHours="16:00-20:00",
                            tz="America/Denver"))


def _authz_capabilities(authz):
    """Every capability token appearing anywhere in an AuthZ payload, as a set.

    THE syntax-insulation seam. The AuthZ block's syntax is explicitly unsettled
    (#1550), so no assertion in this module reaches into it directly: the subset check,
    the over-reach negative and the serialization-kinds test all ask this function. When
    the syntax changes, this function changes and nothing else does.
    """
    caps = set()
    for capabilities in authz.get('rc', {}).values():
        caps.update(capabilities)
    return caps


def _guardian_citizen(kind, reg=None):
    """(1) Guardian as Citizen: the State's SEDI identity credential for Bob.

    Registry-bound, disclosed by compaction, no edges. It is the far node of the
    guardianship credential's E1E edge, which is what ties the recognized guardian to a
    state-endorsed human rather than to a bare AID.
    """
    if reg is None:
        reg = _citizen_registry(kind)
    _, schema = _saidify_schema(dict(GUARDIAN_CITIZEN_SCHEMA_MAD), kind=kind)
    return acdcmap(israid=STATE, uuid=NONCES[N_GC_ACDC], regid=reg.said, schema=schema,
                   attribute=_guardian_citizen_attr(), iseaid=BOB,
                   rule=CITIZEN_RULES_SAID, kind=kind)


def _guardian_credential(kind, guardianCitizen=None, reg=None, powers=None):
    """(2) Guardian as Guardian: the State's recognition of Bob as Cara's guardian.

    Held by Bob (issuee), carrying Cara's AID in the attribute block per the #1550
    diagram. One edge, to Bob's own citizen credential, operator E1E: same subject (Bob
    is the issuee of both), and I2I would demand issuer == issuee, i.e. State == Bob,
    which is false -- so the identity operator from PR #1527 is the only correct label.
    Registry-bound because guardianship terminates dynamically.
    """
    if guardianCitizen is None:
        guardianCitizen = _guardian_citizen(kind)
    if reg is None:
        reg = _guardian_registry(kind)
    _, schema = _saidify_schema(dict(GUARDIAN_SCHEMA_MAD), kind=kind)
    edge = dict(d='', u=NONCES[N_GG_E],
                citizen=dict(d='', u=NONCES[N_GG_E_CIT], n=guardianCitizen.said,
                             s=guardianCitizen.sad['s']['$id'], o='E1E'))
    return acdcmap(israid=STATE, uuid=NONCES[N_GG_ACDC], regid=reg.said, schema=schema,
                   attribute=_guardian_attr(powers=powers), iseaid=BOB, edge=edge,
                   rule=GUARDIAN_RULES_SAID, kind=kind)


def _ward_citizen(kind, guardian=None, reg=None):
    """(3) Ward as Citizen Ward: the State's SEDI identity credential for Cara.

    Same attribute shape as Bob's, plus the encumbrance edge to the guardianship
    credential, operator NI2I: the near issuee is Cara and the far issuee is Bob, so the
    subjects differ and the edge is a plain reference. The edge is what makes the ward's
    OWN credential declare that it is encumbered -- a verifier reading only Cara's
    credential learns a guardianship stands over her identity, which is what tells a
    platform to look for an authorization before it honors a settings change.
    """
    if guardian is None:
        guardian = _guardian_credential(kind)
    if reg is None:
        reg = _citizen_registry(kind)
    _, schema = _saidify_schema(dict(WARD_CITIZEN_SCHEMA_MAD), kind=kind)
    edge = dict(d='', u=NONCES[N_WC_E],
                guardian=dict(d='', u=NONCES[N_WC_E_GUARD], n=guardian.said,
                              s=guardian.sad['s']['$id'], o='NI2I'))
    return acdcmap(israid=STATE, uuid=NONCES[N_WC_ACDC], regid=reg.said, schema=schema,
                   attribute=_ward_citizen_attr(), iseaid=CARA, edge=edge,
                   rule=WARD_RULES_SAID, kind=kind)


def _ward_authz(kind, guardian=None, wardCitizen=None, reg=None, authz=None,
                compactify=False):
    """(4) Ward AuthZ Social: the delegated authorization Cara holds and presents.

    Issuer = BOB (not the State), issuee = CARA, bound to BOB's own registry. Its two
    edges are the security content of the whole example:

      authority (I2I) -> (2). Near issuer is Bob, far issuee is Bob: the same-holder
        constraint, and the proof that Bob held the authority he is attenuating.
      subject (E1E)   -> (3). Near issuee is Cara, far issuee is Cara -- same subject --
        but the issuers differ (Bob vs the State). I2I would demand issuer(near) ==
        issuee(far), i.e. Bob == Cara, and would falsely reject a sound identity
        relation. E1E (PR #1527) constrains only the issuee, which is why it holds. This
        is the second independent use case for the operator, and it comes from Sam's own
        diagram in #1550 rather than from the PR that proposed it.
    """
    if guardian is None:
        guardian = _guardian_credential(kind)
    if wardCitizen is None:
        wardCitizen = _ward_citizen(kind, guardian=guardian)
    if reg is None:
        reg = _authz_registry(kind)
    if authz is None:
        authz = _authz_block()
    _, schema = _saidify_schema(dict(AUTHZ_SCHEMA_MAD), kind=kind)
    attribute = dict(d='', u=NONCES[N_AZ_A], authz=authz, issuedAt=AUTHZ_STAMP)
    edge = dict(d='', u=NONCES[N_AZ_E],
                authority=dict(d='', u=NONCES[N_AZ_E_AUTH], n=guardian.said,
                               s=guardian.sad['s']['$id'], o='I2I'),
                subject=dict(d='', u=NONCES[N_AZ_E_SUBJ], n=wardCitizen.said,
                             s=wardCitizen.sad['s']['$id'], o='E1E'))
    return acdcmap(israid=BOB, uuid=NONCES[N_AZ_ACDC], regid=reg.said, schema=schema,
                   attribute=attribute, iseaid=CARA, edge=edge, rule=AUTHZ_RULES_SAID,
                   kind=kind, compactify=compactify)


def _credential_graph(kind, powers=None, authz=None):
    """Build all four credentials in dependency order and return them.

    Order is forced by the edges: (1) has none, (2) edges to (1), (3) edges to (2), and
    (4) edges to both (2) and (3). The DAG is therefore a chain with one fork at the
    bottom, which is what lets a single presentation of (4) reach every other node.
    """
    citizenReg = _citizen_registry(kind)
    guardianCitizen = _guardian_citizen(kind, reg=citizenReg)
    guardian = _guardian_credential(kind, guardianCitizen=guardianCitizen, powers=powers)
    wardCitizen = _ward_citizen(kind, guardian=guardian, reg=citizenReg)
    wardAuthz = _ward_authz(kind, guardian=guardian, wardCitizen=wardCitizen,
                            authz=authz)
    return guardianCitizen, guardian, wardCitizen, wardAuthz


def _i2i_holds(near, far):
    """Would the DELEGATIVE I2I operator hold on this edge? (issuer(near) == issuee(far))

    Used to show what the two E1E edges cost if an implementer, or a pre-#1527 verifier
    that coerces an unknown operator, treats them as I2I: the answer is False in both
    cases, so I2I does not merely under-specify the relation, it REJECTS it.
    """
    return near.sad['i'] == far.iseaid


# ---------------------------------------------------------------------------
# The verifier's binding for a ward-presented delegated authorization.
# ---------------------------------------------------------------------------
def _verify_authz_chain(wardAuthz, guardian, wardCitizen, guardianCitizen,
                        scope="digitalIdentity"):
    """The security property, checked as a whole. Returns True or raises AssertionError.

    An AuthZ credential the WARD presents authorizes the act only if every one of these
    holds. As in the sibling module, the schema const-pins make a mislabeled operator
    unrepresentable on the wire, but the BINDING -- the correspondence between the AIDs
    those edges connect -- is app-layer logic an implementer must port, not something
    the operator labels achieve on their own.

      1. Authority (I2I): the AuthZ credential's issuer is the issuee of the
         guardianship credential its 'authority' edge points at. Bob issued it and Bob
         holds the guardianship, so the delegation traces to a recognized authority.
      2. Subject (E1E): the AuthZ credential's issuee is the issuee of the ward's own
         citizen credential its 'subject' edge points at -- the same human -- while the
         two ISSUERS differ, which is the shape I2I would falsely reject.
      3. Guardian identity (E1E): the guardianship credential's issuee is the issuee of
         the guardian's own citizen credential, so the recognized guardian is a
         state-endorsed person and not a bare AID.
      4. Encumbrance (NI2I): the ward's citizen credential points at THIS guardianship,
         and the two subjects differ, which is why the operator is the untargeted NI2I.
      5. Ward/guardian correspondence: the ward named in the guardianship credential is
         the same AID as the issuee of the AuthZ credential and of the ward's citizen
         credential. Without this an attacker with any valid guardianship could issue
         an authorization to any child.
      6. Attenuation: every capability delegated by the AuthZ block is one the
         guardianship credential's 'powers' actually confers. A guardian cannot delegate
         more than he holds.
      7. Scope: the coarse statutory scope covers the act (Utah prefers LIMITED
         guardianship, so the specific act is checked against scope before the
         fine-grained capabilities are read at all).

    Two checks a COMPLETE verifier adds are out of scope at this altitude, exactly as in
    the sibling module: grounding the guardianship credential's ISSUER as an authority
    competent to recognize a guardianship (a Layer-2 trust-root check), and enforcing
    each edge's 's' far-node schema constraint, which the reference verifyChain also
    omits. Registry status is a third: (2) and (4) are both registry-bound and a real
    verifier checks that both are currently issued.
    """
    e = wardAuthz.sad['e']
    # (1) authority I2I: the delegator held what he delegated.
    assert e['authority']['o'] == 'I2I'
    assert e['authority']['n'] == guardian.said
    assert wardAuthz.sad['i'] == guardian.iseaid          # issuer(near) == issuee(far)
    # (2) subject E1E: same subject, different issuers -- the case I2I rejects.
    assert e['subject']['o'] == 'E1E'
    assert e['subject']['n'] == wardCitizen.said
    assert wardAuthz.iseaid is not None                   # E1E needs a targeted near node
    assert wardAuthz.iseaid == wardCitizen.iseaid         # the identity relation
    assert wardAuthz.sad['i'] != wardCitizen.sad['i']     # ...across different issuers
    # (3) guardian identity E1E: the guardian is a state-endorsed person.
    gEdge = guardian.sad['e']['citizen']
    assert gEdge['o'] == 'E1E'
    assert gEdge['n'] == guardianCitizen.said
    assert guardian.iseaid == guardianCitizen.iseaid
    # (4) encumbrance NI2I: the ward's own credential points at THIS guardianship, and
    # the subjects differ, which is what disqualifies both targeted operators.
    wEdge = wardCitizen.sad['e']['guardian']
    assert wEdge['o'] == 'NI2I'
    assert wEdge['n'] == guardian.said
    assert wardCitizen.iseaid != guardian.iseaid
    # (5) ward/guardian correspondence: one ward, named consistently everywhere.
    assert guardian.sad['a']['ward'] == wardAuthz.iseaid
    assert guardian.sad['a']['ward'] == wardCitizen.iseaid
    # (6) attenuation: the delegated capabilities are a subset of the delegable powers.
    delegated = _authz_capabilities(wardAuthz.sad['a']['authz'])
    assert delegated                                      # a payload that grants nothing
    assert delegated <= set(guardian.sad['a']['powers'])  # ...cannot be checked
    # (7) scope: the coarse statutory scope covers the act.
    assert scope in guardian.sad['a']['scope']
    return True


# ---------------------------------------------------------------------------
# Phase 1: the four schemas and the helpers that saidify and validate them.
# ---------------------------------------------------------------------------
def test_wardauthz_schemas_JSON():
    """Phase 1: four purpose-authored Draft 2020-12 schemas, each self-addressed.

    Every ACDC in this example commits to a real schema in its own 's' section, so the
    schemas come first and are asserted here on their own terms: each is a well-formed
    Draft 2020-12 document, each saidifies to a stable '$id', and the four SAIDs are
    distinct (the ward's citizen credential and the guardian's share an attribute shape
    but are NOT the same schema -- the ward's requires the encumbrance edge, which is
    what a verifier reads to tell them apart).

    The schema is also where the four edge operators are pinned, so the pins are
    asserted directly rather than only through the credentials that carry them.
    """
    kind = Kinds.json
    gcSaid, gcSchema = _saidify_schema(dict(GUARDIAN_CITIZEN_SCHEMA_MAD), kind=kind)
    ggSaid, ggSchema = _saidify_schema(dict(GUARDIAN_SCHEMA_MAD), kind=kind)
    wcSaid, wcSchema = _saidify_schema(dict(WARD_CITIZEN_SCHEMA_MAD), kind=kind)
    azSaid, azSchema = _saidify_schema(dict(AUTHZ_SCHEMA_MAD), kind=kind)

    for said, schema in ((gcSaid, gcSchema), (ggSaid, ggSchema),
                         (wcSaid, wcSchema), (azSaid, azSchema)):
        Draft202012Validator.check_schema(schema)
        assert schema['$id'] == said                # self-addressed, '$id' first
        assert said.startswith('E')                 # Blake3-256 SAID
    assert len({gcSaid, ggSaid, wcSaid, azSaid}) == 4
    assert gcSaid == "EJVQ1b7CfiAQiq3MB0ffqaM6W3UT_6UW182Hvs9os7dS"
    assert ggSaid == "ENv3zT7Ni1yl8WOE4dIby4thRGXCKrgHMLqG86K1voFd"
    assert wcSaid == "EGg6ihxJmig7CE0cFSuxdQF6Gl4ByVTQqP5qYK8R6bW6"
    assert azSaid == "EP_6kA4inOsIK6DjNEy_qEPUF-vTExbfda1R_NgcPBVo"

    # The four operator pins, read straight off the schemas. Each edge property's 'o'
    # is a const, so the operator is part of the shape rather than a convention.
    def pinned(schema, edgeName):
        return schema['properties']['e']['oneOf'][1]['properties'][edgeName][
            'oneOf'][1]['properties']['o']['const']

    assert pinned(azSchema, 'authority') == 'I2I'   # (4) -> (2), same-holder
    assert pinned(azSchema, 'subject') == 'E1E'     # (4) -> (3), identity
    assert pinned(ggSchema, 'citizen') == 'E1E'     # (2) -> (1), identity
    assert pinned(wcSchema, 'guardian') == 'NI2I'   # (3) -> (2), reference

    # The AuthZ payload is illustrative and its syntax unsettled, so the block is
    # deliberately OPEN: an unknown sibling of 'rc' validates, and a later syntax can
    # grow into the slot without invalidating anything already written.
    authzProps = azSchema['properties']['a']['oneOf'][1]['properties']['authz']
    assert authzProps['additionalProperties'] is True
    assert "SYNTAX UNSETTLED" in authzProps['description']
    assert "#1550" in authzProps['description']
    # ...but the ONE part of it that is not free: because an EVAC resource route is a map
    # LABEL, native-CESR serialization holds it to CESR's strict field-label grammar, so
    # the schema pins routes to exactly that grammar rather than letting a JSON-only
    # author write a route the wire cannot carry.
    assert authzProps['properties']['rc']['propertyNames']['pattern'] == _ROUTE_PATTERN
    assert _ROUTE_PATTERN == ATREX.decode()      # the same rule Labeler enforces


# ---------------------------------------------------------------------------
# Phase 2: the four credentials, their registries and their edges.
# ---------------------------------------------------------------------------
def test_wardauthz_credentials_JSON():
    """Phase 2: the four-credential graph from Sam's #1550 diagram, built and validated.

    The State issues three -- Bob's citizen credential, the guardianship that recognizes
    him, and Cara's citizen credential -- and BOB issues the fourth, the delegated
    authorization, in his OWN registry. That last fact is the structural signature of
    the ward-presents shape: the delegation is the guardian's act, so its lifecycle is
    his to manage and he can revoke it without the State being involved.

    Asserted here: issuer and issuee of each credential; that all four are registry-
    bound and that (4)'s registry is Bob's rather than the State's; that each validates
    against its own schema; that the ward's citizen credential declares its encumbrance;
    and that the schema has teeth -- an unrecognized capability, an empty powers list
    and a missing encumbrance edge are each rejected.
    """
    kind = Kinds.json
    guardianCitizen, guardian, wardCitizen, wardAuthz = _credential_graph(kind)

    # (1) Guardian as Citizen: State -> Bob, registry-bound, no edges.
    assert guardianCitizen.ilk == Ilks.acm
    assert guardianCitizen.sad['i'] == STATE
    assert guardianCitizen.iseaid == BOB
    assert guardianCitizen.sad['rd'] == _citizen_registry(kind).said
    assert guardianCitizen.sad['r'] == CITIZEN_RULES_SAID
    assert guardianCitizen.said == "EPA-I6kmtswtU_Zgvy1Btlp3Hh8e_llzuMjy3pbD_mpZ"
    assert_acdc_schema_valid(guardianCitizen)

    # (2) Guardian as Guardian: State -> Bob, the ward named in the ATTRIBUTE block
    # (Sam's placement), one E1E edge to (1).
    assert guardian.sad['i'] == STATE
    assert guardian.iseaid == BOB
    assert guardian.sad['a']['ward'] == CARA         # the divergence, made concrete
    assert guardian.sad['a']['basis'] == "custodialParent"
    assert guardian.sad['a']['scope'] == ["digitalIdentity"]
    assert guardian.sad['rd'] == _guardian_registry(kind).said
    assert guardian.sad['r'] == GUARDIAN_RULES_SAID
    assert guardian.sad['e']['citizen']['n'] == guardianCitizen.said
    assert guardian.sad['e']['citizen']['o'] == 'E1E'
    assert guardian.said == "EEFqTgzTDdysCOKfIqRtIzTWYhKkHov16QKXmI0R0BbM"
    assert_acdc_schema_valid(guardian)

    # (3) Ward as Citizen Ward: State -> Cara, and its edge is what declares that this
    # citizen credential is ENCUMBERED -- a verifier reading only Cara's credential
    # learns a guardianship stands over her identity.
    assert wardCitizen.sad['i'] == STATE
    assert wardCitizen.iseaid == CARA
    assert wardCitizen.sad['rd'] == _citizen_registry(kind).said    # same State registry
    assert wardCitizen.sad['r'] == WARD_RULES_SAID
    assert wardCitizen.sad['e']['guardian']['n'] == guardian.said
    assert wardCitizen.sad['e']['guardian']['o'] == 'NI2I'
    assert wardCitizen.said == "EI8xD7zuclwId0GunRi2e9q92K1oXuGfSo-HwaXaQOAQ"
    assert_acdc_schema_valid(wardCitizen)

    # (4) Ward AuthZ Social: BOB -> Cara, in BOB's own registry, two edges.
    assert wardAuthz.sad['i'] == BOB                 # NOT the State
    assert wardAuthz.iseaid == CARA
    assert wardAuthz.sad['rd'] == _authz_registry(kind).said
    assert wardAuthz.sad['rd'] != guardian.sad['rd']   # the guardian's own lifecycle
    assert wardAuthz.sad['r'] == AUTHZ_RULES_SAID
    assert wardAuthz.sad['e']['authority']['n'] == guardian.said
    assert wardAuthz.sad['e']['authority']['o'] == 'I2I'
    assert wardAuthz.sad['e']['subject']['n'] == wardCitizen.said
    assert wardAuthz.sad['e']['subject']['o'] == 'E1E'
    assert wardAuthz.said == "EDccew0We_pDxhtHrEOQcP4DIIBeteqZhaokGb7kXtNi"
    authzSchema = assert_acdc_schema_valid(wardAuthz)

    # The payload rides in the attribute block, reached only through the seam so the
    # assertions survive a syntax change (#1550: "The syntax TBD").
    assert _authz_capabilities(wardAuthz.sad['a']['authz']) == {"read", "post",
                                                                "message"}

    # A private ACDC: the compact and expanded forms share one SAID, so a ward can hand
    # over the compact form and expand only what a verifier has agreed to receive.
    compact = _ward_authz(kind, guardian=guardian, wardCitizen=wardCitizen,
                          compactify=True)
    assert compact.said == wardAuthz.said
    assert isinstance(wardAuthz.sad['e'], dict)      # sections inline...
    assert isinstance(compact.sad['e'], str)         # ...vs collapsed to a SAID
    assert_acdc_schema_valid(compact, schema=authzSchema)

    # --- Schema teeth. ---
    # A capability outside the vocabulary is rejected in the AuthZ payload...
    badCap = json.loads(json.dumps(wardAuthz.sad))
    badCap["a"]["authz"]["rc"]["social_feed"] = ["exfiltrate"]
    with pytest.raises(ValidationError):
        Draft202012Validator(authzSchema).validate(badCap)
    # ...and an AuthZ credential with no resource routes at all is rejected, so a
    # payload cannot be vacuously "valid" by granting nothing.
    emptyRc = json.loads(json.dumps(wardAuthz.sad))
    emptyRc['a']['authz']['rc'] = {}
    with pytest.raises(ValidationError):
        Draft202012Validator(authzSchema).validate(emptyRc)
    # A slash-separated resource route -- the obvious way to write one, and the way the
    # EVAC sketch reads -- is rejected, because as a map LABEL it is outside CESR's
    # strict field-label grammar and would raise SerializeError on the native-CESR wire
    # rather than merely validating oddly. The schema catches it at authoring time.
    slashRoute = json.loads(json.dumps(wardAuthz.sad))
    slashRoute['a']['authz']['rc']["social/store"] = ["read"]
    with pytest.raises(ValidationError):
        Draft202012Validator(authzSchema).validate(slashRoute)

    guardianSchema = assert_acdc_schema_valid(guardian)
    emptyPowers = json.loads(json.dumps(guardian.sad))
    emptyPowers['a']['powers'] = []
    with pytest.raises(ValidationError):
        Draft202012Validator(guardianSchema).validate(emptyPowers)
    # The ward's AID is REQUIRED in the attribute block on Sam's placement, so dropping
    # it fails validation -- the divergence is enforced, not merely described.
    noWard = json.loads(json.dumps(guardian.sad))
    del noWard['a']['ward']
    with pytest.raises(ValidationError):
        Draft202012Validator(guardianSchema).validate(noWard)

    # A ward citizen credential without its encumbrance edge is rejected: the schema is
    # what makes "this identity is under guardianship" non-optional.
    wardSchema = assert_acdc_schema_valid(wardCitizen)
    noEncumbrance = json.loads(json.dumps(wardCitizen.sad))
    noEncumbrance['e'] = {"d": wardCitizen.sad['e']['d']}
    with pytest.raises(ValidationError):
        Draft202012Validator(wardSchema).validate(noEncumbrance)


# ---------------------------------------------------------------------------
# Phase 3: the binding, the operator negatives, and the attenuation negative.
# ---------------------------------------------------------------------------
def test_wardauthz_chain_and_negatives_JSON():
    """Phase 3: _verify_authz_chain holds, and each way of breaking it is caught.

    The positive case first: the honest four-credential graph satisfies all seven checks
    in _verify_authz_chain. Then the three families of negative:

      * Operator negatives (schema-level). Each of the four edges has its operator
        pinned by a const, so relabeling any one of them fails wire validation. The two
        E1E edges get an extra assertion apiece showing WHY the pin matters: the
        delegative I2I does not merely under-specify those relations, it would reject
        them, because in both cases issuer(near) != issuee(far).
      * Correspondence negatives (binding-level). A guardianship over a DIFFERENT ward,
        and an authorization whose authority edge points at a guardianship Bob does not
        hold, are both well-formed and both refused.
      * The attenuation negative, which is the one that earns its place here: a guardian
        cannot delegate more than he holds. An AuthZ credential granting 'purchase' --
        a capability in the vocabulary but NOT in the guardianship's powers -- is fully
        schema-valid, and is refused by the binding. That is the point: over-reach is a
        relational property between two credentials, so no amount of schema authoring on
        the AuthZ credential alone can catch it.
    """
    kind = Kinds.json
    guardianCitizen, guardian, wardCitizen, wardAuthz = _credential_graph(kind)

    # The honest graph binds.
    assert _verify_authz_chain(wardAuthz, guardian, wardCitizen, guardianCitizen)

    # --- Operator negatives (schema): a mislabeled operator never reaches a verifier. ---
    authzSchema = assert_acdc_schema_valid(wardAuthz)
    swapped = json.loads(json.dumps(wardAuthz.sad))
    swapped['e']['authority']['o'] = 'NI2I'          # authority downgraded to a reference
    with pytest.raises(ValidationError):
        Draft202012Validator(authzSchema).validate(swapped)
    coerced = json.loads(json.dumps(wardAuthz.sad))
    coerced['e']['subject']['o'] = 'I2I'             # identity edge relabeled delegative
    with pytest.raises(ValidationError):
        Draft202012Validator(authzSchema).validate(coerced)

    guardianSchema = assert_acdc_schema_valid(guardian)
    badCitizenEdge = json.loads(json.dumps(guardian.sad))
    badCitizenEdge['e']['citizen']['o'] = 'I2I'
    with pytest.raises(ValidationError):
        Draft202012Validator(guardianSchema).validate(badCitizenEdge)

    wardSchema = assert_acdc_schema_valid(wardCitizen)
    badEncumbranceEdge = json.loads(json.dumps(wardCitizen.sad))
    badEncumbranceEdge['e']['guardian']['o'] = 'E1E'   # subjects differ: not an identity
    with pytest.raises(ValidationError):
        Draft202012Validator(wardSchema).validate(badEncumbranceEdge)

    # WHY the E1E pins matter: on both identity edges the delegative I2I would REJECT,
    # not merely under-specify. A pre-#1527 verifier that coerces an unknown operator to
    # I2I for a targeted far node therefore refuses this graph outright.
    assert not _i2i_holds(wardAuthz, wardCitizen)      # Bob != Cara
    assert not _i2i_holds(guardian, guardianCitizen)   # the State != Bob
    # ...while the one genuine I2I edge does hold.
    assert _i2i_holds(wardAuthz, guardian)             # Bob == Bob

    # --- Correspondence negatives (binding). ---
    # (a) A guardianship over a different ward. Every edge is well-formed and every
    # operator correct; check (5) fails, because the authority is over somebody else.
    otherGuardianAttr = dict(_guardian_attr(), ward=SOCIAL)
    _, ggSchema = _saidify_schema(dict(GUARDIAN_SCHEMA_MAD), kind=kind)
    otherGuardian = acdcmap(israid=STATE, uuid=NONCES[N_GG_ACDC],
                            regid=_guardian_registry(kind).said, schema=ggSchema,
                            attribute=otherGuardianAttr, iseaid=BOB,
                            edge=dict(guardian.sad['e']), rule=GUARDIAN_RULES_SAID,
                            kind=kind)
    assert_acdc_schema_valid(otherGuardian)            # well-formed...
    with pytest.raises(AssertionError):                # ...and refused
        _verify_authz_chain(wardAuthz, otherGuardian, wardCitizen, guardianCitizen)

    # (b) An authority edge pointing at a guardianship Bob is not the issuee of. Here the
    # far node is the ward's own citizen credential (issuee Cara), so check (1)'s
    # same-holder constraint fails.
    with pytest.raises(AssertionError):
        _verify_authz_chain(wardAuthz, wardCitizen, wardCitizen, guardianCitizen)

    # --- The attenuation negative: a guardian cannot delegate more than he holds. ---
    overreach = dict(_authz_block())
    overreach['rc'] = dict(overreach['rc'], **{"social_store": ["purchase"]})
    greedy = _ward_authz(kind, guardian=guardian, wardCitizen=wardCitizen,
                         authz=overreach)
    # It is entirely schema-valid: 'purchase' is in the capability vocabulary, and the
    # AuthZ credential has no way to know what its issuer holds.
    assert_acdc_schema_valid(greedy)
    assert "purchase" in _authz_capabilities(greedy.sad['a']['authz'])
    assert "purchase" not in guardian.sad['a']['powers']
    # The binding refuses it: check (6) compares the two credentials.
    with pytest.raises(AssertionError):
        _verify_authz_chain(greedy, guardian, wardCitizen, guardianCitizen)
    # And the same over-reaching payload becomes legitimate the moment the State
    # recognizes the broader power -- which is the proof that the check is about the
    # RELATION between the two credentials and not about the payload's contents.
    broaderGuardian = _guardian_credential(
        kind, guardianCitizen=guardianCitizen,
        powers=["read", "post", "message", "profile", "configure", "purchase"])
    broaderAuthz = _ward_authz(kind, guardian=broaderGuardian,
                               wardCitizen=_ward_citizen(kind, guardian=broaderGuardian),
                               authz=overreach)
    assert _verify_authz_chain(broaderAuthz, broaderGuardian,
                               _ward_citizen(kind, guardian=broaderGuardian),
                               guardianCitizen)

    # Scope, check (7): an act outside the coarse statutory scope is refused before the
    # fine-grained capabilities are consulted at all.
    with pytest.raises(AssertionError):
        _verify_authz_chain(wardAuthz, guardian, wardCitizen, guardianCitizen,
                            scope="healthCare")


# ---------------------------------------------------------------------------
# Phase 4: Cara presents the AuthZ credential herself, over IPEX.
# ---------------------------------------------------------------------------
def _ward_id_disclosure(wardCitizen, kind):
    """Cara's minimal disclosure of her citizen credential: issuee only.

    The platform needs to BIND the ward -- to see that the AuthZ credential's issuee and
    the citizen credential's issuee are the same person -- not to read her name, her
    birthdate or where she lives. The citizen credential is attributive, so disclosure
    is by compaction: each nested block collapses to its bare SAID and the mix recomputes
    to the same committed section SAID.
    """
    compactor = Compactor(mad=dict(wardCitizen.sad['a']), makify=True, kind=kind)
    compactor.compact()
    compactor.expand(greedy=True)          # populates .partials (incl. the compact one)
    return dict(compactor.partials[('',)].mad)


def _committed_a_said(acdc, kind):
    """The SAID an ACDC commits to for its attribute section (its most-compact form)."""
    compactor = Compactor(mad=dict(acdc.sad['a']), makify=True, kind=kind)
    compactor.compact()
    return compactor.said


def test_wardauthz_presentation_JSON():
    """Phase 4: the ward presents her own authorization -- a self-presentation.

    Cara walks up to the platform holding a credential issued TO her, and presents it
    herself. Bob is not in the exchange at all: he is a node in the DAG, not a party to
    the conversation. That is the whole difference from
    tests/acdc/test_guardianship_presentation.py, where the ward is too young to hold her
    own keys, so the guardian is the discloser and the ward never speaks.

    The exchange is gated: apply, offer, agree, grant, admit, with the ward's citizen
    attributes crossing the wire only after the platform has signed an agree, and even
    then only as bare SAIDs -- the platform learns that Cara is the subject of a
    state-endorsed citizen credential under guardianship, and learns her authorized
    routes and capabilities, and learns nothing else about her.
    """
    kind = Kinds.json
    guardianCitizen, guardian, wardCitizen, wardAuthz = _credential_graph(kind)
    assert _verify_authz_chain(wardAuthz, guardian, wardCitizen, guardianCitizen)

    # 1. apply (platform -> Cara): the challenge -- which schemas, which fields, and the
    # governance framework the platform will honor.
    #
    # The field-level ask rides the disclosure-paths `dp` field of the QUERY section
    # `q` (exchange(modifiers=...)), as an ORDERED LIST of (schemaSAID, prefix, [paths])
    # triples -- the construct settled in WebOfTrust/keripy discussion #1549, shared with
    # tests/acdc/test_cp_disclosure.py, test_bulk_issuance_shared_registry.py and
    # test_guardianship_presentation.py. A dict keyed by schema SAID cannot express a DAG
    # holding two credentials of the same schema, which is why the construct is a list.
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
    # A '/'-rooted prefix would make the effective paths DAG-ABSOLUTE, and an absolute
    # path reaching a non-origin ACDC must cross the edge that links it -- the virtual
    # '_' component, standing for the jump from the near-side edge block to the top level
    # of the far-side ACDC (#1549). The same request written with non-empty prefixes:
    #     origin:       "/"                ["i", "a/i", "a/authz"]
    #     guardianship: "/e/authority/_/"  ["a/i", "a/ward", "a/powers"]
    #     ward citizen: "/e/subject/_/"    ["a/i"]
    #
    # The zeroth entry is the DAG's origin node (#1549). Here the origin is the AuthZ
    # credential itself -- Cara presents a credential she HOLDS, so unlike the sibling
    # examples the origin is not an envelope she issues. Its schema is still something
    # the platform knows in advance, and for a stronger reason than usual: the platform
    # is the resource the authorization is ABOUT, so the shape of the authorization it
    # will accept is its own published requirement (@SmithSamuelM, #1542, on the
    # applicant knowing the origin schema).
    #
    # What the platform asks for is exactly the shape of the question it has to answer.
    # From the origin: who issued this authorization, to whom, and what does it grant.
    # From the guardianship: who holds it, over which ward, and how far his powers run --
    # the three fields the attenuation check needs. From the ward's citizen credential:
    # the issuee alone, which is all that is needed to bind Cara to the authorization.
    # Guardian-as-Citizen (node 1) is a node in this DAG and carries NO entry, because
    # nothing is requested from it: the platform has no business knowing Bob's name or
    # where he lives. Entries are therefore a breadth-first-ordered SUBSET of the DAG,
    # and each still names its own schema SAID, so a skipped node cannot shift the
    # meaning of the entries below it.
    authzSchemaSaid, _ = _saidify_schema(dict(AUTHZ_SCHEMA_MAD), kind=kind)
    apply = exchange(sender=SOCIAL, receiver=CARA, route="/ipex/apply",
                     modifiers=dict(dp=[[authzSchemaSaid, "",
                                         ["i", "a/i", "a/authz"]],
                                        [guardian.sad['s']['$id'], "",
                                         ["a/i", "a/ward", "a/powers"]],
                                        [wardCitizen.sad['s']['$id'], "", ["a/i"]]]),
                     attributes=dict(m="Prove a guardian authorized this minor account "
                                       "holder's settings, and show the scope.",
                                     g=AUTHZ_RULES_SAID),
                     stamp=APPLY_STAMP, kind=kind)
    assert apply.sad['r'] == "/ipex/apply" and apply.sad['i'] == SOCIAL
    dp = apply.sad['q']['dp']
    assert [entry[0] for entry in dp] == [authzSchemaSaid, guardian.sad['s']['$id'],
                                          wardCitizen.sad['s']['$id']]
    assert all(len(entry) == 3 for entry in dp)       # (schemaSAID, prefix, [paths])
    assert [entry[1] for entry in dp] == ["", "", ""] # no prefixes: paths stay relative
    assert dp[0][2] == ["i", "a/i", "a/authz"]        # origin: who granted, to whom, what
    assert dp[1][2] == ["a/i", "a/ward", "a/powers"]  # guardianship: whose, over whom, how far
    assert dp[2][2] == ["a/i"]                        # ward citizen: the binding, nothing more
    assert all(not p.startswith("/") and not p.endswith("/")
               for _, _, paths in dp for p in paths)
    assert authzSchemaSaid == wardAuthz.sad['s']['$id']   # the origin Cara actually holds
    # The guardian's own citizen credential is a node in the DAG and is asked for
    # nothing: the platform has no business learning the parent's name or residence.
    assert guardianCitizen.sad['s']['$id'] not in [entry[0] for entry in dp]
    assert 'disclose' not in apply.sad['a'] and set(apply.sad['a']) == {'m', 'g'}
    assert apply.said == "EMeUXBWGbmhe5MvD0DTPD1ckI5MyscpSC92qVzcOJFxk"

    # 2. offer (Cara -> platform): commits ONLY to the SAID of the credential she is
    # offering and to the governance ref, and binds the apply. It deliberately does NOT
    # enumerate the issuer-committed source SAIDs (the guardianship, either citizen
    # credential): those are stable correlators, and attaching them before the platform
    # agrees would let a platform spurn and walk away with a persistent handle on both
    # the ward and her parent. They arrive only post-agree, in the grant.
    # Its query block carries `dp` as an EMPTY list: the offer is SOLICITED (its `p`
    # binds the apply), and an empty `dp` means "the same paths the apply asked for"
    # (#1549), so Cara restates nothing and the two messages cannot drift.
    offer = exchange(sender=CARA, receiver=SOCIAL, route="/ipex/offer", prior=apply.said,
                     modifiers=dict(dp=[]),
                     attributes=dict(acdc=wardAuthz.said, governance=AUTHZ_RULES_SAID),
                     stamp=OFFER_STAMP, kind=kind)
    assert offer.sad['p'] == apply.said
    assert offer.sad['q']['dp'] == []                  # solicited: "as per the apply"
    assert offer.said == "EHwBEyvCRbsccjyS_UFNHBYbT7tRq8Z_s4jKD9eSc3LQ"
    assert wardAuthz.said.encode() in offer.raw        # the discloser's own commitment
    assert b"Cara Carver" not in offer.raw and b"2009-04-10" not in offer.raw
    assert guardian.said.encode() not in offer.raw     # issuer commitments withheld...
    assert wardCitizen.said.encode() not in offer.raw
    assert guardianCitizen.said.encode() not in offer.raw

    # 3. agree (platform -> Cara): acceptance, binding the offer SAID and signed by the
    # platform (via messagize -- the blessed genus-aware attachment path).
    agree = exchange(sender=SOCIAL, receiver=CARA, route="/ipex/agree", prior=offer.said,
                     stamp=AGREE_STAMP, kind=kind)
    assert agree.sad['p'] == offer.said
    assert agree.said == "EIcfwLEL6zJ_4TegWOY30qOYAwq8jCYKlxhaLzXfH6Ea"
    svcSigner = _SIGNERS[3]                            # the platform's establishing key
    svcSig = svcSigner.sign(ser=agree.raw, index=0)
    signedAgree = messagize(agree, sigers=[svcSig])
    assert bytes(agree.raw) in signedAgree
    capturedKeyState = Verfer(qb64=svcSigner.verfer.qb64)
    assert capturedKeyState.verify(sig=svcSig.raw, ser=agree.raw)

    # 4. The gate: Cara discloses only when handed a valid, signed, offer-binding agree.
    # The grant carries the EXPANDED AuthZ credential (edges visible, so the platform can
    # walk the chain), the guardianship credential it edges to (disclosed whole, as an
    # authority credential must be), and her own citizen credential compacted to the
    # issuee alone.
    def disclose(agreeMsg, sig, keyState):
        if not (agreeMsg.sad['r'] == "/ipex/agree" and agreeMsg.sad['p'] == offer.said
                and keyState.verify(sig=sig.raw, ser=agreeMsg.raw)):
            return None
        return exchange(sender=CARA, receiver=SOCIAL, route="/ipex/grant",
                        prior=agreeMsg.said,
                        attributes=dict(acdc=wardAuthz.sad,
                                        authority=guardian.sad,
                                        subject=_ward_id_disclosure(wardCitizen, kind)),
                        stamp=GRANT_STAMP, kind=kind)

    # A forged signature or a spurn (decline) unlocks nothing.
    assert disclose(agree, _SIGNERS[0].sign(ser=agree.raw, index=0),
                    capturedKeyState) is None
    spurn = exchange(sender=SOCIAL, receiver=CARA, route="/ipex/spurn", prior=offer.said,
                     stamp=AGREE_STAMP, kind=kind)
    assert disclose(spurn, svcSigner.sign(ser=spurn.raw, index=0),
                    capturedKeyState) is None

    # The valid agree unlocks the grant.
    grant = disclose(agree, svcSig, capturedKeyState)
    assert grant is not None and grant.sad['p'] == agree.said
    assert grant.said == "ECPr0RSNH4H__JNu5Bex2TSaMH_bnlb2P3-4C_Pk41wd"

    # What the platform receives is exactly what it asked for and no more: the
    # authorization payload, the guardianship's scope, and a binding to Cara.
    granted = grant.sad['a']
    assert _authz_capabilities(granted['acdc']['a']['authz']) == {"read", "post",
                                                                  "message"}
    assert granted['authority']['a']['ward'] == CARA
    assert granted['subject']['i'] == CARA             # the ward bound by issuee...
    assert isinstance(granted['subject']['name'], str)  # ...with every attribute withheld
    assert isinstance(granted['subject']['dob'], str)
    assert b"Cara Carver" not in grant.raw             # name never on the wire
    assert b"2009-04-10" not in grant.raw              # birthdate never on the wire
    assert b"Bob Carver" not in grant.raw              # nor the parent's identity
    # Honest residual, asserted present rather than quietly avoided: the guardianship
    # credential is disclosed WHOLE, so its expiry -- Cara's 18th birthday -- crosses the
    # wire and hands the platform her birth month and day. An attribute in a
    # whole-disclosed authority credential cannot be withheld the way an edge can, which
    # is the disclosure argument of the module docstring showing up as an actual leak.
    assert b"2027-04-10" in grant.raw
    # The withheld blocks still recompute to the section SAID the credential commits to,
    # so the platform can prove the disclosure belongs to Cara's citizen credential.
    check = Compactor(mad=dict(granted['subject'], d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == _committed_a_said(wardCitizen, kind)

    # The platform now runs the same binding a verifier runs anywhere, on the credentials
    # it was handed -- which is the point of the whole exchange.
    assert _verify_authz_chain(wardAuthz, guardian, wardCitizen, guardianCitizen)

    # 5. admit (platform -> Cara): closes the exchange.
    admit = exchange(sender=SOCIAL, receiver=CARA, route="/ipex/admit", prior=grant.said,
                     stamp=ADMIT_STAMP, kind=kind)
    assert admit.sad['p'] == grant.said
    assert admit.said == "EIHZtaug8QZLED1659uJMKchvzttEnE7UmarnwiUOo5y"


# ---------------------------------------------------------------------------
# Phase 5: the invariants hold across every serialization kind.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk])
def test_wardauthz_serialization_kinds(kind):
    """Phases 1-4 invariants hold across every serialization kind, not just JSON.

    Exercises the same graph -- four schemas, four credentials, the four pinned edge
    operators, the full binding, the attenuation ceiling and the compact/expanded SAID
    equality -- over CESR (the native KERI wire format) and CBOR/MGPK, asserting the
    behavioral invariants without pinning per-kind SAIDs. (The no-PII-on-the-wire checks
    stay in the JSON phase: the CESR wire form base64-encodes the payload, so a plaintext
    substring check does not apply.)
    """
    guardianCitizen, guardian, wardCitizen, wardAuthz = _credential_graph(kind)
    for acdc in (guardianCitizen, guardian, wardCitizen, wardAuthz):
        assert acdc.ilk == Ilks.acm and acdc.kind == kind
        assert acdc.sad['rd']                          # registry-bound on every kind
        assert_acdc_schema_valid(acdc)

    # The four operators survive every kind, and so does the whole binding.
    assert wardAuthz.sad['e']['authority']['o'] == 'I2I'
    assert wardAuthz.sad['e']['subject']['o'] == 'E1E'
    assert guardian.sad['e']['citizen']['o'] == 'E1E'
    assert wardCitizen.sad['e']['guardian']['o'] == 'NI2I'
    assert _verify_authz_chain(wardAuthz, guardian, wardCitizen, guardianCitizen)

    # The two identity edges are the ones a coerce-to-I2I verifier would reject.
    assert not _i2i_holds(wardAuthz, wardCitizen)
    assert not _i2i_holds(guardian, guardianCitizen)
    assert _i2i_holds(wardAuthz, guardian)

    # Issuer independence: the State issues three, the guardian issues the fourth into
    # his own registry.
    assert guardianCitizen.sad['i'] == guardian.sad['i'] == wardCitizen.sad['i'] == STATE
    assert wardAuthz.sad['i'] == BOB
    assert wardAuthz.sad['rd'] != guardian.sad['rd']

    # Attenuation holds on every kind, and over-reach is refused on every kind.
    overreach = dict(_authz_block())
    overreach['rc'] = dict(overreach['rc'], **{"social_store": ["purchase"]})
    greedy = _ward_authz(kind, guardian=guardian, wardCitizen=wardCitizen,
                         authz=overreach)
    assert_acdc_schema_valid(greedy)                   # schema-valid...
    with pytest.raises(AssertionError):                # ...and refused by the binding
        _verify_authz_chain(greedy, guardian, wardCitizen, guardianCitizen)

    # Compact and expanded forms share one SAID on every kind.
    compact = _ward_authz(kind, guardian=guardian, wardCitizen=wardCitizen,
                          compactify=True)
    assert compact.said == wardAuthz.said
    assert isinstance(compact.sad['e'], str)

    # The ward's minimal disclosure recomputes to the committed section SAID.
    disclosure = _ward_id_disclosure(wardCitizen, kind)
    assert disclosure['i'] == CARA
    check = Compactor(mad=dict(disclosure, d=''), makify=True, kind=kind)
    check.compact()
    assert check.said == _committed_a_said(wardCitizen, kind)


if __name__ == "__main__":
    test_wardauthz_schemas_JSON()
    test_wardauthz_credentials_JSON()
    test_wardauthz_chain_and_negatives_JSON()
    test_wardauthz_presentation_JSON()
    for _kind in (Kinds.json, Kinds.cesr, Kinds.cbor, Kinds.mgpk):
        test_wardauthz_serialization_kinds(_kind)
