# -*- coding: utf-8 -*-
"""
tests.sedi.test_sedi module


Decentralized power separation of powers
entitlements should not require continuing approval by bureaucrats
absence of action or delay in action gives power without accountability
effective revocation via inaction (not refreshing entitlement)
revocation requires positive action by bureaucrats and can therefy be constrained
with accountability to the actor
architecturally ephemeral continuing refresh of credentials due to key managament
is a centralizing force that cedes power via inaction to bureaucrats

Edges allow revocation without continuing reissuance. This better balances power.

Advantages  of E1E edges to core are:
1- leaf can be reissued without reissuing core
so rapid changes in leafs minimize reissuances.
2- all leaves are revoked when core is revoked. So leaves only need one edge
to core not separate delegation chained edge direct to issuer
because revoking core revokes them. And validating leaf requires validating
core which does have delegation chain. This simplifies rapid revocation.
However reissued leaf may use different issuer. So in that case
the new issuer must reissue core and all leaves so all share same delegation
chain. problem when issuer of leaf is not entitled to issue core.
So maybe need to have delegation chain from leaves as well? make delegation
edge optional for leaves so if core issuer differs from leaf issuer AID then
must have separate delegation edge to leaf.
 add optional utahAgent delegation edge to leaf credentials schema
so can add delegation chain when issuer of leaf is not same as issuer of core
(residence, age, guaridanship)

Need new edge operators:
I1I  for Issuer near is Issuer far
DI1I for Issuer of near side is either Issuer of far side or a delegate of far side Issuer

Both so can have delegation edge group that uses either a leaf to core edge
for authority with I2I, DI1I of E1E edges.
Otherwise need a different edge for different chain of authority when near side
Issuer of E1E leaf is not the same as far side issuer.

Disadvantages of E1E edges to core:
All leaves must be reissued if core is reissued. When core is reissued should
clean up by revoking leaves as well but breaking the chain immediately stops
verifiabilty so minimizes latency of stop. Breaking chain is swift.

Despite chain break we need leaf registies to allow revoke and reissuance of
leaf without revoking and reissuing core.

"""

import json
import os
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pytest

from jsonschema import Draft202012Validator as SchemaValidator
from jsonschema.exceptions import SchemaError
from jsonschema.exceptions import ValidationError as SchemaValidationError


from keri import Vrsn_2_0, Kinds, Protocols, Ilks
from keri.core import (MtrDex, NonceDex, Noncer, Salter, Diger, Mapper, Compactor,
                       Structor, Aggor,
                       SealEvent, SealDigest, SealNonce, incept, interact)
from keri.acdc import regcept, blindate, update, acdcmap,  acdcagg

# Questions:
# ? no link to core for credentials that persist even when no longer a citizen
# or should core be reissued when presence status changes?

# ? should guardian ACDC have edge to guardian core with E1E?)
# ? Should guardianship expired Date be optional or mandittory

# ToDo
# high rez image biometric credential with link to guardian core
# fix facial image proof in receipts now blank but set to that in core

# Notable
# added bespoke presentation ACDC example gal and wyn so can present combined
# SEDIs in one dag

# added optional utahAgent delegation edge to leaf credentials schema
# so can add delegation chain when issuer of leaf is not same as issuer of core
# (residence, age, guaridanship)

# Using new edge operators. I1I and DI1I for E1E edges so know to test for same
# Issuer or delegated Issuer of leaf as Core otherwise need different edge
# chain of authority for leaf.

# Added optional guardian edge group in core credential with links to guardian(s)
# so that wards use the same schema as non-wards for core SEDI


ReplaceSchemaSaid = 'EPVlX-S-eWERGiXJmb7FcW75I4J08ptQ-jGglq4VRwou'
ReplaceSchema = \
{
  '$id': 'EPVlX-S-eWERGiXJmb7FcW75I4J08ptQ-jGglq4VRwou',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI AID Replace Schema',
  'description': 'SEDI AID Replace JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Replace_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'issuedDate',
            'obsolete',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee Replacement AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'issuedDate': {'description': 'Issued Date as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
            'obsolete': {'description': 'Obsolete AID', 'type': 'string'},
          },
          'additionalProperties': False
        }
      ]
    },
        'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'utahAgent'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'utahAgent':
            {
              'description': 'Utah Agent Edge Block',
              'type': 'object',
              'required': ['d', 'u', 'n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            }
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}

UnitSchemaSaid = 'ELjJlSaExu9ss766dDpQoLE5aT6-wIRyR72X5YLC3ILc'
UnitSchema = \
{
  '$id': 'ELjJlSaExu9ss766dDpQoLE5aT6-wIRyR72X5YLC3ILc',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Organizational Unit Schema',
  'description': 'SEDI Oganizational Unit JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Org_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'issuedDate',
            'unit',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'issuedDate': {'description': 'Issued Date as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
            'unit': {'description': 'Oganizational Unit', 'type': 'string'},
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}


AgentSchemaSaid = 'EGx4BLclkjhaK1501guyBifxuTTJLwuK61InBTdkKF7v'
AgentSchema = \
{
  '$id': 'EGx4BLclkjhaK1501guyBifxuTTJLwuK61InBTdkKF7v',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Issuing Agent Schema',
  'description': 'SEDI Issuing Agent JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Agent_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'issuedDate',
            'role',
            'name',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'issuedDate': {'description': 'Issued Date as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
            'role': {'description': 'Issuing Agent Role', 'type': 'string'},
            'name':
            {
              'description': 'Name Block',
              'oneOf':
              [
                {'description': 'Name SAID', 'type': 'string'},
                {
                  'description': 'Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Issuing Agent Name', 'type': 'string'},
                  },
                  'additionalProperties': False
                }
              ]
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'orgUnit'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'orgUnit':
            {
              'description': 'Utah Organizational Unit Edge Block',
              'type': 'object',
              'required': ['n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            }
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}

# see test_sedi_schema() for generating and testing
IarSchemaSaid = 'EFAB6k77bXHs6bg9PORW7UYF79GD_OuEcEjmBpwhcfRN'
IarSchema = \
{
  '$id': 'EFAB6k77bXHs6bg9PORW7UYF79GD_OuEcEjmBpwhcfRN',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI IAR Schema',
  'description': 'SEDI IAR Identity Assurance Receipt JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_IAR_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 's', 'a'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail', 'type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID', 'type': 'string'},
        {
        'description': 'Attribute Section Detail',
        'type': 'object',
        'required':
        [
          'd',
          'i',
          'givenName',
          'middleName',
          'familyName',
          'nameSuffix',
          'birthDate',
          'facialImageProof',
          'legalPresenceStatus',
          'residence',
          'proofingDatetime',
          'sediURL'
        ],
        'properties':
        {
          'd': {'description': 'Attribute Section SAID', 'type': 'string'},
          'i': {'description': 'Issuee SMAID SEDI Management AID', 'type': 'string'},
          'givenName': {'description': 'Given Name', 'type': 'string'},
          'middleName': {'description': 'Middle Name(s)', 'type': 'string'},
          'familyName': {'description': 'Family Name', 'type': 'string'},
          'nameSuffix': {'description': 'Name Suffix', 'type': 'string'},
          'birthDate': {'description': 'Date of birth RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
          'facialImageProof': {'description': 'Image typed media block SAID', 'type': 'string'},
          'legalPresenceStatus': {'description': 'Legal presences status i.e. citizen', 'type': 'string'},
          'residence':
          {
            'description': 'Residence detail',
            'type': 'object',
            'required':
            [
              'street',
              'city',
              'county',
              'state',
              'postcode',
              'country'
            ],
            'properties':
            {
              'street': {'description': 'Street address with unit', 'type': 'string'},
              'city': {'description': 'City name', 'type': 'string'},
              'county': {'description': 'County name', 'type': 'string'},
              'state': {'description': 'State name', 'type': 'string'},
              'postcode': {'description': 'Postal (zip) code', 'type': 'string'},
              'country': {'description': 'Country name', 'type': 'string'}
            }
          },
          'proofingDatetime': {'description': 'Proofing session datetime RFC-3339/ISO-8601', 'type': 'string'},
          'sediURL': {'description': 'URL to obtain SEDI', 'type': 'string'}
        },
        'additionalProperties': False}
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
          'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}


CoreSchemaSaid = 'EN0JtdzBmFuTUzyJG9CXZhtdu-bW0V6L95bsVBzi-cY-'
CoreSchema = \
{
  '$id': 'EN0JtdzBmFuTUzyJG9CXZhtdu-bW0V6L95bsVBzi-cY-',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Core Schema',
  'description': 'SEDI Core Identity JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Core_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'primary',
            'givenName',
            'middleName',
            'familyName',
            'nameSuffix',
            'birthDate',
            'facialImageProof',
            'legalPresenceStatus',
            'issuedDate',
            'expirationDate',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            "primary": { "description": "Primary True if not bulk issued else False", "type": "boolean"},
            'givenName':
            {
              'description': 'Given Name Block',
              'oneOf':
              [
                {'description': 'Given Name SAID', 'type': 'string'},
                {
                  'description': 'Given Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Given Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                }
              ]
            },
            'middleName':
            {
              'description': 'Middle Name(s) Block',
              'oneOf':
              [
                {'description': 'Middle Name SAID','type': 'string'},
                {
                  'description': 'Middle Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Middle Name(s) Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'familyName':
            {
              'description': 'Family Name Block',
              'oneOf':
              [
                {'description': 'Family Name SAID', 'type': 'string'},
                {
                  'description': 'Family Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Family Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'nameSuffix':
            {
              'description': 'Name Suffix Block',
              'oneOf':
              [
                {'description': 'Name Suffix SAID', 'type': 'string'},
                {
                  'description': 'Name Suffix Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Name Suffix Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'birthDate':
            {
              'description': 'Birth Date Block',
              'oneOf':
              [
                {'description': 'Birth Date SAID','type': 'string'},
                {
                  'description': 'Birth Date Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Birth Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                  },
                'additionalProperties': False
                },
              ]
            },
            'facialImageProof':
            {
              'description': 'Facial Image Proof Block',
              'oneOf':
              [
                {'description': 'Facial Image Proof SAID', 'type': 'string'},
                {
                  'description': 'Facial Image Proof Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Facial Image Proof Value as SAID of typed media block', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'legalPresenceStatus':
            {
              'description': 'Legal Presence Status Block',
              'oneOf':
              [
                {'description': 'Legal Presence Status SAID', 'type': 'string'},
                {
                  'description': 'Legal Presence Status Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Legal Presence Status Value i.e. citizen', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'issuedDate':
            {
              'description': 'Issued Date Block',
              'oneOf':
              [
                {'description': 'Issued Date SAID', 'type': 'string'},
                {
                  'description': 'Issued Date Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                   'value': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'expirationDate':
            {
              'description': 'Expiration Date Block',
              'oneOf':
              [
                {'description': 'Expiration Date SAID', 'type': 'string'},
                {
                  'description': 'Expiration Date Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Expiration Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                  },
                  'additionalProperties': False
                }
              ]
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'utahAgent'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'utahAgent':
            {
              'description': 'Utah Agent Edge Block',
              'type': 'object',
              'required': ['n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
            'guardians':
            {
              'description': 'Guardian Edge Group Block',
              'type': 'object',
              'required': ['d', 'u', 'o', 'first'],
              'properties':
              {
                'd': {'description': 'Edge Group SAID', 'type': 'string'},
                'u': {'description': 'Edge Group UE', 'type': 'string'},
                'o': {'description': 'Edge Group M-ary Operator', 'type': 'string'},
                'first':
                {
                  'description': 'First Guardian Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'second':
                {
                  'description': 'Second Guardian Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'third':
                {
                  'description': 'Third Guardian Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'fourth':
                {
                  'description': 'Fourth Guardian Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
              },
              'additionalProperties': False
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}

GuardianSchemaSaid = 'EPAYIl4Dy1Zi7Gf8rFiHCRMdxtkjv7tv9uFBtBw5t1zY'
GuardianSchema = \
{
  '$id': 'EPAYIl4Dy1Zi7Gf8rFiHCRMdxtkjv7tv9uFBtBw5t1zY',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Guardianship Schema',
  'description': 'SEDI Guardianship JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Guardian_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'primary',
            'role',
            'ward',
            'issuedDate',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'primary': { 'description': 'Primary True if not bulk issued else False', 'type': 'boolean'},
            'role': {'description': 'Guardian Role', 'type': 'string'},
            'ward': {'description': 'Ward AID', 'type': 'string'},
            'issuedDate':
            {
              'description': 'Issued Date Block',
              'oneOf':
              [
                {'description': 'Issued Date SAID', 'type': 'string'},
                {
                  'description': 'Issued Date Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                   'value': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'expirationDate':
            {
              'description': 'Expiration Date Block',
              'oneOf':
              [
                {'description': 'Expiration Date SAID', 'type': 'string'},
                {
                  'description': 'Expiration Date Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Expiration Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                  },
                  'additionalProperties': False
                }
              ]
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'utahAgent'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'utahAgent':
            {
              'description': 'Utah Agent Edge Block',
              'type': 'object',
              'required': ['n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}


ResidenceSchemaSaid = 'EH5hn7CbtDFxhS3IKioC8P-e4YyZoxqzhRpr4X_e32BD'
ResidenceSchema = \
{
  '$id': 'EH5hn7CbtDFxhS3IKioC8P-e4YyZoxqzhRpr4X_e32BD',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Residence Schema',
  'description': 'SEDI Residence JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Residence_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'street',
            'city',
            'county',
            'state',
            'postcode',
            'country',
            'issuedDate',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'street':
            {
              'description': 'Street Address Block',
              'oneOf':
              [
                {'description': 'Street Address SAID', 'type': 'string'},
                {
                  'description': 'Street Address Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                   'value': {'description': 'Street Address Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'city':
            {
              'description': 'City Name Block',
              'oneOf':
              [
                {'description': 'City Name SAID', 'type': 'string'},
                {
                  'description': 'City Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'City Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'county':
            {
              'description': 'County Name Block',
              'oneOf':
              [
                {'description': 'County Name SAID', 'type': 'string'},
                {
                  'description': 'County Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'County Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'state':
            {
              'description': 'State Name Block',
              'oneOf':
              [
                {'description': 'State Name SAID', 'type': 'string'},
                {
                  'description': 'State Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'State Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'postcode':
            {
              'description': 'Postcode Block',
              'oneOf':
              [
                {'description': 'Postcode SAID', 'type': 'string'},
                {
                  'description': 'Postcode Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Postcode Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'country':
            {
              'description': 'Country Name Block',
              'oneOf':
              [
                {'description': 'Country Name SAID', 'type': 'string'},
                {
                  'description': 'Country Name Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Country Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
              ]
            },
            'issuedDate':
            {
              'description': 'Issued Date Block',
              'oneOf':
              [
                {'description': 'Issued Date SAID', 'type': 'string'},
                {
                  'description': 'Issued Date Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                  },
                'additionalProperties': False
                },
              ]
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'coreIdentity'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'coreIdentity':
            {
              'description': 'Core Identity Edge Block',
              'type': 'object',
              'required': ['d', 'u', 'n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o':
                {
                    'description': 'Edge Unary Operator',
                    'type': 'array',
                    'items': {'type': 'string'},
                    'minItems': 1,
                }
              },
              'additionalProperties': False
            },
            'utahAgent':
            {
              'description': 'Utah Agent Edge Block',
              'type': 'object',
              'required': ['n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}

# Age SEDI ACDC Schema
AgeSchemaSaid = 'EPqXrwPT6b0_KghrrMuIdmuD68Aytv1XK6jU86EumgJV'
AgeSchema = \
{
  '$id': 'EPqXrwPT6b0_KghrrMuIdmuD68Aytv1XK6jU86EumgJV',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Age Schema',
  'description': 'SEDI Age JSON Schema for acg ACDC.',
  'credentialType': 'SEDI_Age_ACDC_acg_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'A', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'A':
    {
      "description": "Aggregate Section",
      "oneOf":
      [
        { "description": "Aggregate Section AGID", "type": "string"},
        {
          "description": "Aggregate Section Detail",
          "type": "array",
          "uniqueItems": True,
          "items":
          {
            "anyOf":
            [
              {"description": "Aggregate Section AGID", "type": "string"},
              {
                "description": "Issuee Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "i"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "i": { "description": "Issuee AID", "type": "string"}
                    },
                    "additionalProperties": False
                  }
                ]
              },
              {
                'description': 'Issued Date Block',
                'oneOf':
                [
                  {'description': 'Block SAID', 'type': 'string'},
                  {
                    'description': 'Block Detail',
                    'type': 'object',
                    'required': ['d', 'u', 'issuedDate'],
                    'properties':
                    {
                      'd': {'description': 'Block SAID', 'type': 'string'},
                      'u': {'description': 'Bock UE', 'type': 'string'},
                     'issuedDate': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                    },
                    'additionalProperties': False
                  },
                ]
              },
              {
                'description': 'Expiration Date Block',
                'oneOf':
                [
                  {'description': 'Block SAID', 'type': 'string'},
                  {
                    'description': 'Block Detail',
                    'type': 'object',
                    'required': ['d', 'u', 'expirationDate'],
                    'properties':
                    {
                      'd': {'description': 'Block SAID', 'type': 'string'},
                      'u': {'description': 'Bock UE', 'type': 'string'},
                      'expirationDate': {'description': 'Expiration Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                    },
                    'additionalProperties': False
                  }
                ]
              },
              {
                "description": "Over13 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over13"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over13": { "description": "Over13 True if age>=13 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over14 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over14"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over14": { "description": "Over14 True if age>=14 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                },
                ]
              },
              {
                "description": "Over15 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over15"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over15": { "description": "Over15 True if age>=15 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over16 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over16"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over16": { "description": "Over16 True if age>=16 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over18 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over18"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over18": { "description": "Over18 True if age>=18 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over21 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over21"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over21": { "description": "Over21 True if age>=21 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over40 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over40"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over40": { "description": "Over40 True if age>=40 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over62 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over62"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over62": { "description": "Over65 True if age>=62 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over65 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over65"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over65": { "description": "Over65 True if age>=65 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over67 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over67"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over67": { "description": "Over67 True if age>=67 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
              {
                "description": "Over70 Block",
                "oneOf":
                [
                  { "description": "Block SAID", "type": "string"},
                  {
                    "description": "Block Detail",
                    "type": "object",
                    "required":
                    [ "d", "u", "over70"],
                    "properties":
                    {
                      "d": {"description": "Block SAID", "type": "string"},
                      "u": { "description": "Block UE", "type": "string"},
                      "over70": { "description": "Over70 True if age>=70 else False", "type": "boolean"}
                    },
                    "additionalProperties": False
                  },
                ]
              },
            ]
          }
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'coreIdentity'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'coreIdentity':
            {
              'description': 'Core Identity Edge Block',
              'type': 'object',
              'required': ['d', 'u', 'n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o':
                {
                    'description': 'Edge Unary Operator',
                    'type': 'array',
                    'items': {'type': 'string'},
                    'minItems': 1,
                }
              },
              'additionalProperties': False
            },
            'utahAgent':
            {
              'description': 'Utah Agent Edge Block',
              'type': 'object',
              'required': ['n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}

# social auth schema
SocialSchemaSaid = 'EB8MUTKRg8284YPduyhDgUVvNM192-247KcRaXhIxoni'
SocialSchema = \
{
  '$id': 'EB8MUTKRg8284YPduyhDgUVvNM192-247KcRaXhIxoni',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Social Authorization Schema',
  'description': 'SEDI Guardian Issued to Ward Social Authorization JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Social_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
            'issued',
            'expires',
            'rc',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'issued': { 'description': 'Issued Datetime Value as RFC-3339/ISO-8601', 'type': 'string'},
            'expires': { 'description': 'Expiration Datetime Value as RFC-3339/ISO-8601', 'type': 'string'},
            'rc':
            {
              'description': 'Authorized Resource Capabilities',
              'type': 'object',
              'properties':
              {
                'myEmptySpace':
                {
                  'description': "Access to My Empty Space",
                  'type': 'array',
                  'items': {'type': 'string'},
                },
              },
              'additionalProperties': True
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u', 'guardian'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'guardian':
            {
              'description': 'Guardian Edge Block',
              'type': 'object',
              'required': ['n', 's', 'o'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}


# SEDI Bespoke Presentation schema
BespokeSchemaSaid = 'ELNJljAHLvAL4ycL2xQhUib1HngH-m_y8azFKXH7dBS8'
BespokeSchema = \
{
  '$id': 'ELNJljAHLvAL4ycL2xQhUib1HngH-m_y8azFKXH7dBS8',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Bespoke Presentation Schema',
  'description': 'SEDI Bespoke Presentation JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Bespoke_ACDC_acm_message',
  'version': '0.1.0',
  'type': 'object',
  'required': ['v', 'd', 'i', 's', 'a', 'e', 'r'],
  'properties':
  {
    'v': {'description': 'ACDC version string', 'type': 'string'},
    't': {'description': 'Message type', 'type': 'string'},
    'd': {'description': 'Message SAID', 'type': 'string'},
    'u': {'description': 'Message UE', 'type': 'string'},
    'i': {'description': 'Issuer AID', 'type': 'string'},
    'rd': {'description': 'Registry SAID', 'type': 'string'},
    's':
    {
      'description': 'Schema Section',
      'oneOf':
      [
        {'description': 'Schema Section SAID', 'type': 'string'},
        {'description': 'Schema Section Detail','type': 'object'}
      ]
    },
    'a':
    {
      'description': 'Attribute Section',
      'oneOf':
      [
        {'description': 'Attribute Section SAID','type': 'string'},
        {
          'description': 'Attribute Section Detail',
          'type': 'object',
          'required':
          [
            'd',
            'u',
            'i',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee AID', 'type': 'string'},
          },
          'additionalProperties': True
        }
      ]
    },
    'e':
    {
      'description': 'Edge Section',
      'oneOf':
      [
        {'description': 'Edge Section SAID', 'type': 'string'},
        {
          'description': 'Edge Section Detail',
          'type': 'object',
          'required': ['d', 'u'],
          'properties':
          {
            'd': {'description': 'Edge Section SAID', 'type': 'string'},
            'u': {'description': 'Edge Section UE', 'type': 'string'},
            'core':
            {
              'description': 'Core Edge Block',
              'type': 'object',
              'required': ['n'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
            'residence':
            {
              'description': 'Residence Edge Block',
              'type': 'object',
              'required': ['n'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
            'age':
            {
              'description': 'Age Edge Block',
              'type': 'object',
              'required': ['n'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
            'guardian':
            {
              'description': 'Guardian Edge Block',
              'type': 'object',
              'required': ['n'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
            'social':
            {
              'description': 'Social Edge Block',
              'type': 'object',
              'required': ['n'],
              'properties':
              {
                'd': {'description': 'Edge SAID', 'type': 'string'},
                'u': {'description': 'Edge UE', 'type': 'string'},
                'n': {'description': 'Far Node SAID', 'type': 'string'},
                's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                'o': {'description': 'Edge Unary Operator', 'type': 'string'}
              },
              'additionalProperties': False
            },
          },
          'additionalProperties': False
        }
      ]
    },
    'r':
    {
      'description': 'Rule Section',
      'oneOf':
      [
        {'description': 'Rule Section SAID', 'type': 'string'},
        {
          'description': 'Rule Section Detail',
          'type': 'object',
          'required': ['d', 'l'],
          'properties':
          {
            'd': {'description': 'Rule Section SAID', 'type': 'string'},
            'l': {'description': 'Legal Language', 'type': 'string'}
          },
        'additionalProperties': False
        }
      ]
    }
  },
  'additionalProperties': False
}



def test_sedi_schema():
    """Test setup of schema for core SEDI acdcs"""

    kind = Kinds.json

    # identity assurance receipt schema
    iarSchemaMad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SEDI IAR Schema",
        "description": "SEDI IAR Identity Assurance Receipt JSON Schema for acm ACDC.",
        "credentialType": "SEDI_IAR_ACDC_acm_message",
        "version": "0.1.0",
        "type": "object",
        "required": ["v", "d", "i", "s", "a"],
        "properties":
        {
            "v": {"description": "ACDC version string", "type": "string"},
            "t": {"description": "Message type", "type": "string"},
            "d": {"description": "Message SAID", "type": "string"},
            "u": {"description": "Message UE", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {"description": "Schema Section SAID", "type": "string"},
                    {"description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":
            {
                "description": "Attribute Section",
                "oneOf":
                [
                    {"description": "Attribute Section SAID", "type": "string"},
                    {
                        "description": "Attribute Section Detail",
                        "type": "object",
                        "required":
                        [
                            'd',
                            'i',
                            'givenName',
                            'middleName',
                            'familyName',
                            'nameSuffix',
                            'birthDate',
                            'facialImageProof',
                            'legalPresenceStatus',
                            'residence',
                            'proofingDatetime',
                            'sediURL'
                        ],
                        "properties":
                        {
                            "d": {"description": "Attribute Section SAID", "type": "string"},
                            "i": {"description": "Issuee SMAID SEDI Management AID", "type": "string"},
                            "givenName": {"description": "Given Name", "type": "string"},
                            "middleName": {"description": "Middle Name(s)", "type": "string"},
                            "familyName": {"description": "Family Name", "type": "string"},
                            'nameSuffix': {'description': 'Name Suffix', 'type': 'string'},
                            "birthDate": {"description": "Date of birth RFC-3339/ISO-8601 time MBZ", "type": "string"},
                            "facialImageProof": {"description": "Image typed media block SAID", "type": "string"},
                            "legalPresenceStatus": {"description": "Legal presences status i.e. citizen", "type": "string"},
                            "residence":
                            {
                                "description": "Residence detail",
                                "type": "object",
                                "required": ["street", "city", "county", "state", "postcode", "country"],
                                "properties":
                                {
                                    "street": {"description": "Street address with unit", "type": "string"},
                                    "city": {"description": "City name", "type": "string"},
                                    "county": {"description": "County name", "type": "string"},
                                    "state": {"description": "State name", "type": "string"},
                                    "postcode": {"description": "Postal (zip) code", "type": "string"},
                                    "country": {"description": "Country name", "type": "string"},
                                }
                            },
                            "proofingDatetime": {"description": "Proofing session datetime RFC-3339/ISO-8601", "type": "string"},
                            "sediURL": {"description": "URL to obtain SEDI", "type": "string"},

                        },
                        "additionalProperties": False
                    }
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {"description": "Rule Section SAID", "type": "string"},
                    {
                        "description": "Rule Section Detail",
                        "type": "object",
                        "required": ["d", "l"],
                        "properties":
                        {
                            "d": {"description": "Rule Section SAID", "type": "string"},
                            "l": {"description": "Legal Language", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            }
        },
        "additionalProperties": False
    }

    mapper = Mapper(mad=iarSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    iarSchemaSaid = mapper.said
    assert  iarSchemaSaid == 'EFAB6k77bXHs6bg9PORW7UYF79GD_OuEcEjmBpwhcfRN'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert iarSchemaSaid == IarSchemaSaid
    assert mapper.mad == IarSchema
    #mapper.raw   # compact json of mapper


    # AID Replacement Schema

    replaceSchemaMad = \
    {
      '$id': '',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI AID Replace Schema',
      'description': 'SEDI AID Replace JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Replace_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
                'issuedDate',
                'obsolete',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee Replacement AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'issuedDate': {'description': 'Issued Date as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                'obsolete': {'description': 'Obsolete AID', 'type': 'string'},
              },
              'additionalProperties': False
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u', 'utahAgent'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'utahAgent':
                {
                  'description': 'Utah Agent Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                }
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=replaceSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    replaceSchemaSaid = mapper.said
    assert replaceSchemaSaid == 'EPVlX-S-eWERGiXJmb7FcW75I4J08ptQ-jGglq4VRwou'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert replaceSchemaSaid == ReplaceSchemaSaid
    assert mapper.mad == ReplaceSchema


    # Organizational Unit Schema
    unitSchemaMad = \
    {
      '$id': '',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Organizational Unit Schema',
      'description': 'SEDI Oganizational Unit JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Org_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'a', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
                'issuedDate',
                'unit',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'issuedDate': {'description': 'Issued Date as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                'unit': {'description': 'Oganizational Unit', 'type': 'string'},
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=unitSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    unitSchemaSaid = mapper.said
    assert  unitSchemaSaid == 'ELjJlSaExu9ss766dDpQoLE5aT6-wIRyR72X5YLC3ILc'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert unitSchemaSaid == UnitSchemaSaid
    assert mapper.mad == UnitSchema

    # Issuing Agent Schema
    agentSchemaMad = \
    {
      '$id': '',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Issuing Agent Schema',
      'description': 'SEDI Issuing Agent JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Agent_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
                'issuedDate',
                'role',
                'name',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'issuedDate': {'description': 'Issued Date as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                'role': {'description': 'Issuing Agent Role', 'type': 'string'},
                'name':
                {
                  'description': 'Name Block',
                  'oneOf':
                  [
                    {'description': 'Name SAID', 'type': 'string'},
                    {
                      'description': 'Name Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Issuing Agent Name', 'type': 'string'},
                      },
                      'additionalProperties': False
                    }
                  ]
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u', 'orgUnit'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'orgUnit':
                {
                  'description': 'Utah Organizational Unit Edge Block',
                  'type': 'object',
                  'required': ['n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                }
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=agentSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    agentSchemaSaid = mapper.said
    assert  agentSchemaSaid == 'EGx4BLclkjhaK1501guyBifxuTTJLwuK61InBTdkKF7v'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert agentSchemaSaid == AgentSchemaSaid
    assert mapper.mad == AgentSchema


    # Core SEDI Schema
    coreSchemaMad = \
    {
        "$id": "",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SEDI Core Schema",
        "description": "SEDI Core Identity JSON Schema for acm ACDC.",
        "credentialType": "SEDI_Core_ACDC_acm_message",
        "version": "0.1.0",
        "type": "object",
        "required": ["v", "d", "i", "rd", "s", "a", "e", "r"],
        "properties":
        {
            "v": {"description": "ACDC version string", "type": "string"},
            "t": {"description": "Message type", "type": "string"},
            "d": {"description": "Message SAID", "type": "string"},
            "u": {"description": "Message UE", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "rd": {"description": "Registry SAID", "type": "string"},
            "s":
            {
                "description": "Schema Section",
                "oneOf":
                [
                    {"description": "Schema Section SAID", "type": "string"},
                    {"description": "Schema Section Detail", "type": "object"}
                ]
            },
            "a":
            {
                "description": "Attribute Section",
                "oneOf":
                [
                    {"description": "Attribute Section SAID", "type": "string"},
                    {
                        "description": "Attribute Section Detail",
                        "type": "object",
                        "required":
                        [
                            'd',
                            'u',
                            'i',
                            'primary',
                            'givenName',
                            'middleName',
                            'familyName',
                            'nameSuffix',
                            'birthDate',
                            'facialImageProof',
                            'legalPresenceStatus',
                            'issuedDate',
                            'expirationDate',
                        ],
                        "properties":
                        {
                            "d": {"description": "Attribute Section SAID", "type": "string"},
                            "u": {"description": "Attribute Section UE", "type": "string"},
                            "i": {"description": "Issuee AID", "type": "string"},
                            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                            "primary": { "description": "Primary True if not bulk issued else False", "type": "boolean"},
                            'givenName':
                            {
                              'description': 'Given Name Block',
                              'oneOf':
                              [
                                {'description': 'Given Name SAID', 'type': 'string'},
                                {
                                  'description': 'Given Name Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Given Name Value', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                }
                              ]
                            },
                            'middleName':
                            {
                              'description': 'Middle Name(s) Block',
                              'oneOf':
                              [
                                {'description': 'Middle Name SAID','type': 'string'},
                                {
                                  'description': 'Middle Name Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Middle Name(s) Value', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                },
                              ]
                            },
                            'familyName':
                            {
                              'description': 'Family Name Block',
                              'oneOf':
                              [
                                {'description': 'Family Name SAID', 'type': 'string'},
                                {
                                  'description': 'Family Name Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Family Name Value', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                },
                              ]
                            },
                            'nameSuffix':
                            {
                              'description': 'Name Suffix Block',
                              'oneOf':
                              [
                                {'description': 'Name Suffix SAID', 'type': 'string'},
                                {
                                  'description': 'Name Suffix Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Name Suffix Value', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                },
                              ]
                            },
                            'birthDate':
                            {
                              'description': 'Birth Date Block',
                              'oneOf':
                              [
                                {'description': 'Birth Date SAID','type': 'string'},
                                {
                                  'description': 'Birth Date Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Birth Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                                  },
                                'additionalProperties': False
                                },
                              ]
                            },
                            'facialImageProof':
                            {
                              'description': 'Facial Image Proof Block',
                              'oneOf':
                              [
                                {'description': 'Facial Image Proof SAID', 'type': 'string'},
                                {
                                  'description': 'Facial Image Proof Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Facial Image Proof Value as SAID of typed media block', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                },
                              ]
                            },
                            'legalPresenceStatus':
                            {
                              'description': 'Legal Presence Status Block',
                              'oneOf':
                              [
                                {'description': 'Legal Presence Status SAID', 'type': 'string'},
                                {
                                  'description': 'Legal Presence Status Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Legal Presence Status Value i.e. citizen', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                },
                              ]
                            },
                            'issuedDate':
                            {
                              'description': 'Issued Date Block',
                              'oneOf':
                              [
                                {'description': 'Issued Date SAID', 'type': 'string'},
                                {
                                  'description': 'Issued Date Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                   'value': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                },
                              ]
                            },
                            'expirationDate':
                            {
                              'description': 'Expiration Date Block',
                              'oneOf':
                              [
                                {'description': 'Expiration Date SAID', 'type': 'string'},
                                {
                                  'description': 'Expiration Date Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Expiration Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                                  },
                                  'additionalProperties': False
                                }
                              ]
                            },
                        },
                        "additionalProperties": False
                    }
                ]
            },
            "e":
            {
                "description": "Edge Section",
                "oneOf":
                [
                    {"description": "Edge Section SAID", "type": "string"},
                    {
                        "description": "Edge Section Detail",
                        "type": "object",
                        "required": ["d", "u", "utahAgent"],
                        "properties":
                        {
                            "d": {"description": "Edge Section SAID", "type": "string"},
                            "u": {"description": "Edge Section UE", "type": "string"},
                            "utahAgent":
                            {
                                "description": "Utah Agent Edge Block",
                                "type": "object",
                                "required": ["n", "s", "o"],
                                "properties":
                                {
                                  "d": {"description": "Edge SAID", "type": "string"},
                                  "u": {"description": "Edge UE", "type": "string"},
                                  "n": {"description": "Far Node SAID", "type": "string"},
                                  "s": {"description": "Far Node Schema SAID", "type": "string"},
                                  "o": {"description": "Edge Unary Operator", "type": "string"},
                                },
                                "additionalProperties": False
                            },
                            'guardians':
                            {
                              'description': 'Guardian Edge Group Block',
                              'type': 'object',
                              'required': ['d', 'u', 'o', 'first'],
                              'properties':
                              {
                                'd': {'description': 'Edge Group SAID', 'type': 'string'},
                                'u': {'description': 'Edge Group UE', 'type': 'string'},
                                'o': {'description': 'Edge Group M-ary Operator', 'type': 'string'},
                                'first':
                                {
                                  'description': 'First Guardian Edge Block',
                                  'type': 'object',
                                  'required': ['d', 'u', 'n', 's', 'o'],
                                  'properties':
                                  {
                                    'd': {'description': 'Edge SAID', 'type': 'string'},
                                    'u': {'description': 'Edge UE', 'type': 'string'},
                                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                                  },
                                  'additionalProperties': False
                                },
                                'second':
                                {
                                  'description': 'Second Guardian Edge Block',
                                  'type': 'object',
                                  'required': ['d', 'u', 'n', 's', 'o'],
                                  'properties':
                                  {
                                    'd': {'description': 'Edge SAID', 'type': 'string'},
                                    'u': {'description': 'Edge UE', 'type': 'string'},
                                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                                  },
                                  'additionalProperties': False
                                },
                                'third':
                                {
                                  'description': 'Third Guardian Edge Block',
                                  'type': 'object',
                                  'required': ['d', 'u', 'n', 's', 'o'],
                                  'properties':
                                  {
                                    'd': {'description': 'Edge SAID', 'type': 'string'},
                                    'u': {'description': 'Edge UE', 'type': 'string'},
                                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                                  },
                                  'additionalProperties': False
                                },
                                'fourth':
                                {
                                  'description': 'Fourth Guardian Edge Block',
                                  'type': 'object',
                                  'required': ['d', 'u', 'n', 's', 'o'],
                                  'properties':
                                  {
                                    'd': {'description': 'Edge SAID', 'type': 'string'},
                                    'u': {'description': 'Edge UE', 'type': 'string'},
                                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                                  },
                                  'additionalProperties': False
                                },
                              },
                              'additionalProperties': False
                            },
                        },
                        "additionalProperties": False
                    }
                ]
            },
            "r":
            {
                "description": "Rule Section",
                "oneOf":
                [
                    {"description": "Rule Section SAID", "type": "string"},
                    {
                        "description": "Rule Section Detail",
                        "type": "object",
                        "required": ["d", "l"],
                        "properties":
                        {
                            "d": {"description": "Rule Section SAID", "type": "string"},
                            "l": {"description": "Legal Language", "type": "string"}
                        },
                        "additionalProperties": False
                    }
                ]
            }
        },
        "additionalProperties": False
    }
    mapper = Mapper(mad=coreSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    coreSchemaSaid = mapper.said
    assert coreSchemaSaid == 'EN0JtdzBmFuTUzyJG9CXZhtdu-bW0V6L95bsVBzi-cY-'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert coreSchemaSaid == CoreSchemaSaid
    assert mapper.mad == CoreSchema


    # SEDI Guardian Schema
    guardianSchemaMad = \
    {
      '$id': 'EGx4BLclkjhaK1501guyBifxuTTJLwuK61InBTdkKF7v',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Guardianship Schema',
      'description': 'SEDI Guardianship JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Guardian_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
                'primary',
                'role',
                'ward',
                'issuedDate',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'primary': { "description": 'Primary True if not bulk issued else False', 'type': 'boolean'},
                'role': {'description': 'Guardian Role', 'type': 'string'},
                'ward': {'description': 'Ward AID', 'type': 'string'},
                'issuedDate':
                {
                  'description': 'Issued Date Block',
                  'oneOf':
                  [
                    {'description': 'Issued Date SAID', 'type': 'string'},
                    {
                      'description': 'Issued Date Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'expirationDate':
                {
                  'description': 'Expiration Date Block',
                  'oneOf':
                  [
                    {'description': 'Expiration Date SAID', 'type': 'string'},
                    {
                      'description': 'Expiration Date Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Expiration Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                      },
                      'additionalProperties': False
                    }
                  ]
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u', 'utahAgent'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'utahAgent':
                {
                  'description': 'Utah Agent Edge Block',
                  'type': 'object',
                  'required': ['n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=guardianSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    guardianSchemaSaid = mapper.said
    assert guardianSchemaSaid == 'EPAYIl4Dy1Zi7Gf8rFiHCRMdxtkjv7tv9uFBtBw5t1zY'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert guardianSchemaSaid == GuardianSchemaSaid
    assert mapper.mad == GuardianSchema


    # Setup Residence Schema
    residenceSchemaMad = \
    {
      '$id': '',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Residence Schema',
      'description': 'SEDI Residence JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Residence_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
                'street',
                'city',
                'county',
                'state',
                'postcode',
                'country',
                'issuedDate',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'street':
                {
                  'description': 'Street Address Block',
                  'oneOf':
                  [
                    {'description': 'Street Address SAID', 'type': 'string'},
                    {
                      'description': 'Street Address Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                       'value': {'description': 'Street Address Value', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'city':
                {
                  'description': 'City Name Block',
                  'oneOf':
                  [
                    {'description': 'City Name SAID', 'type': 'string'},
                    {
                      'description': 'City Name Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'City Name Value', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'county':
                {
                  'description': 'County Name Block',
                  'oneOf':
                  [
                    {'description': 'County Name SAID', 'type': 'string'},
                    {
                      'description': 'County Name Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'County Name Value', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'state':
                {
                  'description': 'State Name Block',
                  'oneOf':
                  [
                    {'description': 'State Name SAID', 'type': 'string'},
                    {
                      'description': 'State Name Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'State Name Value', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'postcode':
                {
                  'description': 'Postcode Block',
                  'oneOf':
                  [
                    {'description': 'Postcode SAID', 'type': 'string'},
                    {
                      'description': 'Postcode Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Postcode Value', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'country':
                {
                  'description': 'Country Name Block',
                  'oneOf':
                  [
                    {'description': 'Country Name SAID', 'type': 'string'},
                    {
                      'description': 'Country Name Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Country Name Value', 'type': 'string'},
                      },
                      'additionalProperties': False
                    },
                  ]
                },
                'issuedDate':
                {
                  'description': 'Issued Date Block',
                  'oneOf':
                  [
                    {'description': 'Issued Date SAID', 'type': 'string'},
                    {
                      'description': 'Issued Date Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                      },
                    'additionalProperties': False
                    },
                  ]
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u', 'coreIdentity'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'coreIdentity':
                {
                  'description': 'Core Identity Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o':
                    {
                        'description': 'Edge Unary Operator',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'minItems': 1,
                    }
                  },
                  'additionalProperties': False
                },
                'utahAgent':
                {
                  'description': 'Utah Agent Edge Block',
                  'type': 'object',
                  'required': ['n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=residenceSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    residenceSchemaSaid = mapper.said
    assert  residenceSchemaSaid == 'EH5hn7CbtDFxhS3IKioC8P-e4YyZoxqzhRpr4X_e32BD'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert residenceSchemaSaid == ResidenceSchemaSaid
    assert mapper.mad == ResidenceSchema

    #assert mapper.mad == {}

    # Age Schema Setup Test
    ageSchemaMad = \
    {
      '$id': '',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Age Schema',
      'description': 'SEDI Age JSON Schema for acg ACDC.',
      'credentialType': 'SEDI_Age_ACDC_acg_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'A', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'A':
        {
          "description": "Aggregate Section",
          "oneOf":
          [
            { "description": "Aggregate Section AGID", "type": "string"},
            {
              "description": "Aggregate Section Detail",
              "type": "array",
              "uniqueItems": True,
              "items":
              {
                "anyOf":
                [
                  {"description": "Aggregate Section AGID", "type": "string"},
                  {
                    "description": "Issuee Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "i"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "i": { "description": "Issuee AID", "type": "string"}
                        },
                        "additionalProperties": False
                      }
                    ]
                  },
                  {
                    'description': 'Issued Date Block',
                    'oneOf':
                    [
                      {'description': 'Block SAID', 'type': 'string'},
                      {
                        'description': 'Block Detail',
                        'type': 'object',
                        'required': ['d', 'u', 'issuedDate'],
                        'properties':
                        {
                          'd': {'description': 'Block SAID', 'type': 'string'},
                          'u': {'description': 'Bock UE', 'type': 'string'},
                         'issuedDate': {'description': 'Issued Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                        },
                        'additionalProperties': False
                      },
                    ]
                  },
                  {
                    'description': 'Expiration Date Block',
                    'oneOf':
                    [
                      {'description': 'Block SAID', 'type': 'string'},
                      {
                        'description': 'Block Detail',
                        'type': 'object',
                        'required': ['d', 'u', 'expirationDate'],
                        'properties':
                        {
                          'd': {'description': 'Block SAID', 'type': 'string'},
                          'u': {'description': 'Bock UE', 'type': 'string'},
                          'expirationDate': {'description': 'Expiration Date Value as RFC-3339/ISO-8601 time MBZ', 'type': 'string'},
                        },
                        'additionalProperties': False
                      }
                    ]
                  },
                  {
                    "description": "Over13 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over13"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over13": { "description": "Over13 True if age>=13 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over14 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over14"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over14": { "description": "Over14 True if age>=14 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                    },
                    ]
                  },
                  {
                    "description": "Over15 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over15"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over15": { "description": "Over15 True if age>=15 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over16 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over16"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over16": { "description": "Over16 True if age>=16 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over18 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over18"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over18": { "description": "Over18 True if age>=18 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over21 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over21"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over21": { "description": "Over21 True if age>=21 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over40 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over40"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over40": { "description": "Over40 True if age>=40 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over62 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over62"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over62": { "description": "Over65 True if age>=62 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over65 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over65"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over65": { "description": "Over65 True if age>=65 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over67 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over67"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over67": { "description": "Over67 True if age>=67 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                  {
                    "description": "Over70 Block",
                    "oneOf":
                    [
                      { "description": "Block SAID", "type": "string"},
                      {
                        "description": "Block Detail",
                        "type": "object",
                        "required":
                        [ "d", "u", "over70"],
                        "properties":
                        {
                          "d": {"description": "Block SAID", "type": "string"},
                          "u": { "description": "Block UE", "type": "string"},
                          "over70": { "description": "Over70 True if age>=70 else False", "type": "boolean"}
                        },
                        "additionalProperties": False
                      },
                    ]
                  },
                ]
              }
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u', 'coreIdentity'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'coreIdentity':
                {
                  'description': 'Core Identity Edge Block',
                  'type': 'object',
                  'required': ['d', 'u', 'n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o':
                    {
                        'description': 'Edge Unary Operator',
                        'type': 'array',
                        'items': {'type': 'string'},
                        'minItems': 1,
                    }
                  },
                  'additionalProperties': False
                },
                'utahAgent':
                {
                  'description': 'Utah Agent Edge Block',
                  'type': 'object',
                  'required': ['n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=ageSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    ageSchemaSaid = mapper.said
    assert  ageSchemaSaid == 'EPqXrwPT6b0_KghrrMuIdmuD68Aytv1XK6jU86EumgJV'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert ageSchemaSaid == AgeSchemaSaid
    assert mapper.mad == AgeSchema

    # Social Media Access Authorization Schema
    socialSchemaMad = \
    {
      '$id': 'EPAYIl4Dy1Zi7Gf8rFiHCRMdxtkjv7tv9uFBtBw5t1zY',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Social Authorization Schema',
      'description': 'SEDI Guardian Issued to Ward Social Authorization JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Social_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 'rd', 's', 'a', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
                'issued',
                'expires',
                'rc',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'issued': { 'description': 'Issued Datetime Value as RFC-3339/ISO-8601', 'type': 'string'},
                'expires': { 'description': 'Expiration Datetime Value as RFC-3339/ISO-8601', 'type': 'string'},
                'rc':
                {
                    'description': 'Authorized Resource Capabilities',
                    'type': 'object',
                    'properties':
                    {
                      'myEmptySpace':
                      {
                        'description':  "Access to My Empty Space",
                        'type': 'array',
                        'items': {'type': 'string'},
                      },
                    },
                    'additionalProperties': True
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u', 'guardian'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'guardian':
                {
                  'description': 'Guardian Edge Block',
                  'type': 'object',
                  'required': ['n', 's', 'o'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=socialSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    socialSchemaSaid = mapper.said
    assert socialSchemaSaid == 'EB8MUTKRg8284YPduyhDgUVvNM192-247KcRaXhIxoni'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert socialSchemaSaid == SocialSchemaSaid
    assert mapper.mad == SocialSchema

    # Bespoke Schema Setup
    bespokeSchemaMad = \
    {
      '$id': 'ELFn0r4Z8kRDuJnkLRD-xPdyb3ZhkTnZ4_Nn3MlBw9R5',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Bespoke Presentation Schema',
      'description': 'SEDI Bespoke Presentation JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Bespoke_ACDC_acm_message',
      'version': '0.1.0',
      'type': 'object',
      'required': ['v', 'd', 'i', 's', 'a', 'e', 'r'],
      'properties':
      {
        'v': {'description': 'ACDC version string', 'type': 'string'},
        't': {'description': 'Message type', 'type': 'string'},
        'd': {'description': 'Message SAID', 'type': 'string'},
        'u': {'description': 'Message UE', 'type': 'string'},
        'i': {'description': 'Issuer AID', 'type': 'string'},
        'rd': {'description': 'Registry SAID', 'type': 'string'},
        's':
        {
          'description': 'Schema Section',
          'oneOf':
          [
            {'description': 'Schema Section SAID', 'type': 'string'},
            {'description': 'Schema Section Detail','type': 'object'}
          ]
        },
        'a':
        {
          'description': 'Attribute Section',
          'oneOf':
          [
            {'description': 'Attribute Section SAID','type': 'string'},
            {
              'description': 'Attribute Section Detail',
              'type': 'object',
              'required':
              [
                'd',
                'u',
                'i',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee AID', 'type': 'string'},
              },
              'additionalProperties': True
            }
          ]
        },
        'e':
        {
          'description': 'Edge Section',
          'oneOf':
          [
            {'description': 'Edge Section SAID', 'type': 'string'},
            {
              'description': 'Edge Section Detail',
              'type': 'object',
              'required': ['d', 'u'],
              'properties':
              {
                'd': {'description': 'Edge Section SAID', 'type': 'string'},
                'u': {'description': 'Edge Section UE', 'type': 'string'},
                'core':
                {
                  'description': 'Core Edge Block',
                  'type': 'object',
                  'required': ['n'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'residence':
                {
                  'description': 'Residence Edge Block',
                  'type': 'object',
                  'required': ['n'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'age':
                {
                  'description': 'Age Edge Block',
                  'type': 'object',
                  'required': ['n'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'guardian':
                {
                  'description': 'Guardian Edge Block',
                  'type': 'object',
                  'required': ['n'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
                'social':
                {
                  'description': 'Social Edge Block',
                  'type': 'object',
                  'required': ['n'],
                  'properties':
                  {
                    'd': {'description': 'Edge SAID', 'type': 'string'},
                    'u': {'description': 'Edge UE', 'type': 'string'},
                    'n': {'description': 'Far Node SAID', 'type': 'string'},
                    's': {'description': 'Far Node Schema SAID', 'type': 'string'},
                    'o': {'description': 'Edge Unary Operator', 'type': 'string'}
                  },
                  'additionalProperties': False
                },
              },
              'additionalProperties': False
            }
          ]
        },
        'r':
        {
          'description': 'Rule Section',
          'oneOf':
          [
            {'description': 'Rule Section SAID', 'type': 'string'},
            {
              'description': 'Rule Section Detail',
              'type': 'object',
              'required': ['d', 'l'],
              'properties':
              {
                'd': {'description': 'Rule Section SAID', 'type': 'string'},
                'l': {'description': 'Legal Language', 'type': 'string'}
              },
            'additionalProperties': False
            }
          ]
        }
      },
      'additionalProperties': False
    }

    mapper = Mapper(mad=bespokeSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    bespokeSchemaSaid = mapper.said
    assert bespokeSchemaSaid == 'ELNJljAHLvAL4ycL2xQhUib1HngH-m_y8azFKXH7dBS8'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert bespokeSchemaSaid == BespokeSchemaSaid
    assert mapper.mad == BespokeSchema

    """done test"""


def test_sedi_acdcs():
    """Test sedi receipt and entitlements

    IAL3 process

    Proof-of-control over SMAID by citizen

    Create incepting key states for participants:
        Roy as State Root of Trust
        Deb as State Organizational Unit (Dept/Division) Level
        Sue as State Issuer Agent  Level
        Stu as State Alterante Issuer Agent  Level
        Pat as Proofer (Identity)
        Guy as Guardian Parent Citizen
        Gal as Guardian Parent Citizen
        Wyn as Ward Child Citizen
        Ryn as Replacement Citizen AID for Wyn

    use same salter for a set of keys where each uses same salt but different path.
          salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)

    Create set of signers each with private signing key and public verification key
        Under the hood, using Argon2, Salter creates a stretched 32 byte seed
        from 16 byte salt thusly;
        size=32
        path='0'
        salt=b'sediacdcworksalt'
        opslimit=1
        memlimit=8192
        seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
        Salter then uses 32 byte seed as private key to create public key Ed25519
        verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
        First 32 bytes of this internal sigkey is seed as private key so we can
        use seed externally as private signing key and verkey as public verification key
        Then Salter.signers generates a set of Signer instances with key pairs
        for signing all based on internal salt but different path for each in
        stretch

    Setup Sue's Issuer ACDC Registries and shared secret salts for blinds
        Create a set of unique entropy Noncer instances for the ue fields (old uuid)
        Creates a set of shared secret salts for later blinded update events
        Create datetime stap for rip events
        Creeate a set of rip events for vacuous registrys
        Create list of rids (registry id as rip event said )

    Notes for delegation chain
    StateEntity Issuer  Roy is RootAID  Issuee is Department/Division Entity Descriptor Field
    OrganizationalUnit  Deb Issuer is Dept/Division  Issuee is SEDI Program Label
    IssuingAgent  Issuer Sue is SEDI Program Issuee is SEDI Program
    """
    kind = Kinds.json

    salt = b'sediacdcworksalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABzZWRpYWNkY3dvcmtzYWx0'  # CESR encoded

    # create signers, each contains siging key pair
    signers = salter.signers(count=32, transferable=True, temp=True)  # two per

    # create witness signers as nontransferable, each contains key pair
    walt = b'sediacdcworkwits'  # different salt for witness keys
    walter = Salter(raw=walt)
    wigners = walter.signers(count=16,transferable=False, temp=True)  # one per

    # Create State's three level delegation chain AIDs
    # Root AID -> Org Unit (division/department/program) -> Issuing Agent

    # Create Roy's AID (Root AID) with single sig single wit inception event JSON
    royKeys = [signers[10].verfer.qb64]  # incepting public verification key(s)
    royNKeys = [signers[11].verfer.qb64]  # next (rotation) public verification key(s)
    royWits = [wigners[5].verfer.qb64]  # witness aids (same as public verkey)
    royISerder = incept(royKeys, code=MtrDex.Blake3_256, ndigs=royNKeys, wits=royWits,
                    version=Vrsn_2_0, kind=Kinds.json)

    assert royISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EAN4gwVu_a9EDxFn-camF6OoQvZAvi-_FyluyyZFKzs5',
        'i': 'EAN4gwVu_a9EDxFn-camF6OoQvZAvi-_FyluyyZFKzs5',
        's': '0',
        'kt': '1',
        'k': ['DJu5WX8jZ8CXRdNPbIjBtkf21bh0vENMWeYciabkDyQT'],
        'nt': '1',
        'n': ['DLILoKGcD8dqxTZKDe1WFqNGoxz-mtBQtuhxuc0KxDK6'],
        'bt': '1',
        'b': ['BDAzSC46GjoKWoOARwd3QfHSPj9BWRaMCAgcIJCMSqSD'],
        'c': [],
        'a': []
    }
    roy = royISerder.aid
    assert roy == 'EAN4gwVu_a9EDxFn-camF6OoQvZAvi-_FyluyyZFKzs5'  # Root AID
    assert royISerder.said == roy
    raid = roy  # root AID

    # Create Deb's AID (Org Unit Dept/Division/Program) with single-sig
    # single-wit inception event JSON
    debKeys = [signers[12].verfer.qb64]  # incepting public verification key(s)
    debNKeys = [signers[13].verfer.qb64]  # next (rotation) public verification key(s)
    debWits = [wigners[6].verfer.qb64]  # witness aids (same as public verkey)
    debISerder = incept(debKeys, code=MtrDex.Blake3_256, ndigs=debNKeys, wits=debWits,
                    version=Vrsn_2_0, kind=Kinds.json)

    assert debISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EMrUfTuv8j3vBVAgPSlDi1D_o35F5uwsIAWjBatLhK9E',
        'i': 'EMrUfTuv8j3vBVAgPSlDi1D_o35F5uwsIAWjBatLhK9E',
        's': '0',
        'kt': '1',
        'k': ['DO1JCVgu-xa3Zvrqfinmm2NirBsYtDAxca03_xFa6yv5'],
        'nt': '1',
        'n': ['DF4yQrug9NA7XEL-nO2zh-rtDjP7UFqimaQuiTR-9oUV'],
        'bt': '1',
        'b': ['BGcevQKxlqpFsVnxsOObpynodkDWG-Y063TKEcHTPafQ'],
        'c': [],
        'a': []
    }
    deb = debISerder.aid
    assert deb == 'EMrUfTuv8j3vBVAgPSlDi1D_o35F5uwsIAWjBatLhK9E'  # Org Unit SEDI Program
    assert debISerder.said == deb

    # Create Sue's AID (State Issuing Agent) with single sig single wit inception event JSON
    sueKeys = [signers[0].verfer.qb64]  # incepting public verification key(s)
    sueNKeys = [signers[1].verfer.qb64]  # next (rotation) public verification key(s)
    sueWits = [wigners[0].verfer.qb64]  # witness aids (same as public verkey)
    sueISerder = incept(sueKeys, code=MtrDex.Blake3_256, ndigs=sueNKeys, wits=sueWits,
                    version=Vrsn_2_0, kind=Kinds.json)

    assert sueISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        'i': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        's': '0',
        'kt': '1',
        'k': ['DOYgdUBxTqXE8f8se-S8JlqAAzRTLa1YV4_E6NkHBv6j'],
        'nt': '1',
        'n': ['DFSfjZGPYPHtEdq8J6qx5EfBXvZxL2K-wGtb5IxFeOGC'],
        'bt': '1',
        'b': ['BHxXu_PNY1C1MKAGiy_CusBjyd9Ys29v4tFNFJQd56GB'],
        'c': [],
        'a': []
    }
    sue = sueISerder.aid
    assert sue == 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-'  # State Issuer Sue's AID
    assert sueISerder.said == sue

    # Create Stu's AID (Alternate State Issuing Agent) with single sig single
    # with inception event JSON
    stuKeys = [signers[16].verfer.qb64]  # incepting public verification key(s)
    stuNKeys = [signers[17].verfer.qb64]  # next (rotation) public verification key(s)
    stuWits = [wigners[8].verfer.qb64]  # witness aids (same as public verkey)
    stuISerder = incept(stuKeys, code=MtrDex.Blake3_256, ndigs=stuNKeys, wits=stuWits,
                    version=Vrsn_2_0, kind=Kinds.json)

    assert stuISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EDOP0lrGzY0VdsRfbcLhOTYw0yrYrtglnGoJsScZtY5o',
        'i': 'EDOP0lrGzY0VdsRfbcLhOTYw0yrYrtglnGoJsScZtY5o',
        's': '0',
        'kt': '1',
        'k': ['DHaQ5aNslyubC9aBJ9nTHLlL5Bed1Ak7kUiWM6TMBdDW'],
        'nt': '1',
        'n': ['DIAcV-NVdH7uy3vu6pskWaeCPzdlr7bcEvbAhGrHBEuv'],
        'bt': '1',
        'b': ['BFUJj6kDo4ocS__nYUfKV_kN9RLEtlFY78MHjgzAOmLF'],
        'c': [],
        'a': []
    }
    stu = stuISerder.aid
    assert stu == 'EDOP0lrGzY0VdsRfbcLhOTYw0yrYrtglnGoJsScZtY5o'  # Alt State Issuer Stu's AID
    assert stuISerder.said == stu

    # Create Pat's AID (Identity Proofer) with single sig single wit inception event JSON
    patKeys = [signers[2].verfer.qb64]  # incepting public verification key(s)
    patNKeys = [signers[3].verfer.qb64]  # next (rotation) public verification key(s)
    patWits = [wigners[1].verfer.qb64]  # witness aids (same as public verkey)
    patISerder = incept(patKeys, code=MtrDex.Blake3_256, ndigs=patNKeys, wits=patWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert patISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh',
        'i': 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh',
        's': '0',
        'kt': '1',
        'k': ['DKq0C5-ptAqPmpDi-hwPzNeIfZUWuBeq_bbb6UCF0_Oz'],
        'nt': '1',
        'n': ['DPJFmK2jfmifFVYvsCPGw-FQbl2xmHJ7fEb_nLlWx4pm'],
        'bt': '1',
        'b': ['BCxpCMenkwNVaaoDKiK0_U3IlCSHPGzQHdm9CYIotUY8'],
        'c': [],
        'a': []
    }
    pat = patISerder.aid
    assert pat== 'EAgq2LY03zk9NUempbqdLzG4PiGnmVMqTD0DfrY9Whwh'  # Proofer Pat's AID
    assert patISerder.said == pat

    # Create Guy's SMAID (Guardian Parent) with single sig single wit inception event JSON
    guyKeys = [signers[4].verfer.qb64]  # incepting public verification key(s)
    guyNKeys = [signers[5].verfer.qb64]  # next (rotation) public verification key(s)
    guyWits = [wigners[2].verfer.qb64]  # witness aids (same as public verkey)
    guyISerder = incept(guyKeys, code=MtrDex.Blake3_256, ndigs=guyNKeys, wits=guyWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert guyISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        'i': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        's': '0',
        'kt': '1',
        'k': ['DLew-r-sGNE2Rr1mKBeNGI78UFgAM4bQ1LprmHHNoFUT'],
        'nt': '1',
        'n': ['DPZOdALUpQMCqhrj2d43BSpwzSW7kn0z15odwVwhU4no'],
        'bt': '1',
        'b': ['BG3WKpXb9Ma91C4TnfbMCuLJ0_mgoCbrpMopUuH7M-cM'],
        'c': [],
        'a': []
    }
    guy = guyISerder.aid
    assert guy == 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR'  # Guardian Guy's AID
    assert guyISerder.said == guy

    # Create Gal's SMAID (Guardian Parent) with single sig single wit inception event JSON
    galKeys = [signers[6].verfer.qb64]  # incepting public verification key(s)
    galNKeys = [signers[7].verfer.qb64]  # next (rotation) public verification key(s)
    galWits = [wigners[3].verfer.qb64]  # witness aids (same as public verkey)
    galISerder = incept(galKeys, code=MtrDex.Blake3_256, ndigs=galNKeys, wits=galWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert galISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
        'i': 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
        's': '0',
        'kt': '1',
        'k': ['DItB34DWsii2vL0nFZbFBRZQljDGmKTY72zZmMAY9_5e'],
        'nt': '1',
        'n': ['DBHznQBZMr94KRQ4lN8e1jS-IWCE_QmrE78d8I0coqyT'],
        'bt': '1',
        'b': ['BDkey6lzDqWVw6ANa6zr81Yl7gy6nzDblbt1_ENNAw0V'],
        'c': [],
        'a': []
    }
    gal = galISerder.aid
    assert gal == 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY'  # Guardian Guy's AID
    assert galISerder.said == gal

    # Create Wyn's SMAID (Ward Child) with single sig single wit inception event JSON
    wynKeys = [signers[8].verfer.qb64]  # incepting public verification key(s)
    wynNKeys = [signers[9].verfer.qb64]  # next (rotation) public verification key(s)
    wynWits = [wigners[4].verfer.qb64]  # witness aids (same as public verkey)
    wynISerder = incept(wynKeys, code=MtrDex.Blake3_256, ndigs=wynNKeys, wits=wynWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert wynISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1',
        'i': 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1',
        's': '0',
        'kt': '1',
        'k': ['DOZasipADYGcDse0RsrrdYKpn2RSLy3U6EDEi4yWrwjm'],
        'nt': '1',
        'n': ['DEep2D7cgt5AmS_QzPvdz0xaGnc9iDX5TO-rwPq9hxUt'],
        'bt': '1',
        'b': ['BA87lX6lbHymHSSunaf4b1X07KvquE-79TthnQ9_ks9A'],
        'c': [],
        'a': []
    }
    wyn = wynISerder.aid
    assert wyn == 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1'  # Ward Wyn's AID
    assert wynISerder.said == wyn

    # Create Wyn's replacement AID ryn to demo replaceACDC
    rynKeys = [signers[14].verfer.qb64]  # incepting public verification key(s)
    rynNKeys = [signers[15].verfer.qb64]  # next (rotation) public verification key(s)
    rynWits = [wigners[7].verfer.qb64]  # witness aids (same as public verkey)
    rynISerder = incept(rynKeys, code=MtrDex.Blake3_256, ndigs=rynNKeys, wits=rynWits,
                        version=Vrsn_2_0, kind=Kinds.json)

    assert rynISerder.sad == \
    {
        'v': 'KERICAACAAJSONAAFb.',
        't': 'icp',
        'd': 'EPvkhZTKfAte3QhfD-O3eKY2dwZqcLQ9OVIVGjT9edmR',
        'i': 'EPvkhZTKfAte3QhfD-O3eKY2dwZqcLQ9OVIVGjT9edmR',
        's': '0',
        'kt': '1',
        'k': ['DITXXIsWZgSLa9kf3pMqPyKtD6_XzZD2EpzPZM2qCq2T'],
        'nt': '1',
        'n': ['DEz8QW3ch4emtSzwLjZX_2tB-RdaU1V4K_mpWY374p4j'],
        'bt': '1',
        'b': ['BDTnSfTkg2X5zqXNCj0ERVUoe4oyr32gxyu4B18r6lMW'],
        'c': [],
        'a': []
    }
    ryn = rynISerder.aid
    assert ryn == 'EPvkhZTKfAte3QhfD-O3eKY2dwZqcLQ9OVIVGjT9edmR'  # Ward  Ryn replacment Wyn's AID
    assert rynISerder.said == ryn


    # Setup Registries for Roy, Deb, Sue, and Stu as State Delegation chain Issuers

    # create datetimek stamp
    stamp = '2026-09-01T08:30:00.000000+00:00'

    # Create Roy's UES for registry events
    salt = b'roysregistrysalt'  # base salt for registry events
    salter = Salter(raw=salt)
    royRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                            for i in range(8)]
    # create registry serders for roy as Issuer
    royRegSerders = [regcept(israid=roy, uuid=ue, stamp=stamp) for ue in royRegUes]
    royRids = [rss.said for rss in royRegSerders]
    assert royRids[0] == royRegSerders[0].said == 'EA3Y6LeoyNFjnLS1xZoRQnzX0fWgUw0XjD4IgIf8ZHxD'
    assert royRegSerders[0].israid == roy
    assert royRegSerders[0].nonce == royRegUes[0]
    assert royRegSerders[0].sner.num == 0
    assert royRegSerders[0].stamp == stamp

    # Create Deb's UES for registry events
    salt = b'debsregistrysalt'  # base salt for registry events
    salter = Salter(raw=salt)
    debRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                            for i in range(8)]
    # create registry serders for Deb as Issuer
    debRegSerders = [regcept(israid=deb, uuid=ue, stamp=stamp) for ue in debRegUes]
    debRids = [rss.said for rss in debRegSerders]
    assert debRids[0] == debRegSerders[0].said == 'EEy3daQxc9NrgzA1V7KjgOqLF_te2gs2-sYElTHsPzYE'
    assert debRegSerders[0].israid == deb
    assert debRegSerders[0].nonce == debRegUes[0]
    assert debRegSerders[0].sner.num == 0
    assert debRegSerders[0].stamp == stamp

    # Create Sues's UES for registry events
    salt = b'suesregistrysalt'  # base salt for registry events
    salter = Salter(raw=salt)
    sueRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                            for i in range(64)]
    # create registry serders for sue as Issuer
    sueRegSerders = [regcept(israid=sue, uuid=ue, stamp=stamp) for ue in sueRegUes]
    sueRids = [rss.said for rss in sueRegSerders]
    assert sueRids[0] == sueRegSerders[0].said == 'EDOfxmEeOsWdi5ZQyuy98W4s15vmV1RWVFuqm4GZflTn'
    assert sueRegSerders[0].israid == sue
    assert sueRegSerders[0].nonce == sueRegUes[0]
    assert sueRegSerders[0].sner.num == 0
    assert sueRegSerders[0].stamp == stamp
    assert sueRegSerders[0].sad == \
    {
        'v': 'ACDCCAACAAJSONAADa.',
        't': 'rip',
        'd': 'EDOfxmEeOsWdi5ZQyuy98W4s15vmV1RWVFuqm4GZflTn',
        'u': '0ADX782wlYptYlK0MqR6ebA-',
        'i': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        'n': '0',
        'dt': '2026-09-01T08:30:00.000000+00:00'
    }

    # Create Stu's UES for registry events
    salt = b'stusregistrysalt'  # base salt for registry events
    salter = Salter(raw=salt)
    stuRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                            for i in range(32)]
    # create registry serders for stu as Issuer
    stuRegSerders = [regcept(israid=stu, uuid=ue, stamp=stamp) for ue in stuRegUes]
    stuRids = [rss.said for rss in stuRegSerders]
    assert stuRids[0] == stuRegSerders[0].said == 'ELm6OhvWprcGl8Ej8rpJXivzAl0NwaVpvwI8V7REHZMm'
    assert stuRegSerders[0].israid == stu
    assert stuRegSerders[0].nonce == stuRegUes[0]
    assert stuRegSerders[0].sner.num == 0
    assert stuRegSerders[0].stamp == stamp

    # Create Guy's UES for registry events
    salt = b'guysregistrysalt'  # base salt for registry events
    salter = Salter(raw=salt)
    guyRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                            for i in range(8)]
    # create registry serders for guy as Issuer
    guyRegSerders = [regcept(israid=guy, uuid=ue, stamp=stamp) for ue in guyRegUes]
    guyRids = [rss.said for rss in guyRegSerders]
    assert guyRids[0] == guyRegSerders[0].said == 'EKuAljh08_m1CXluTeogXxHHlX93iqpmVfjMZ1cufhR-'
    assert guyRegSerders[0].israid == guy
    assert guyRegSerders[0].nonce == guyRegUes[0]
    assert guyRegSerders[0].sner.num == 0
    assert guyRegSerders[0].stamp == stamp

    # Create Gal's UES for registry events
    salt = b'galsregistrysalt'  # base salt for registry events
    salter = Salter(raw=salt)
    galRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                            for i in range(8)]
    # create registry serders for gal as Issuer
    galRegSerders = [regcept(israid=gal, uuid=ue, stamp=stamp) for ue in galRegUes]
    galRids = [rss.said for rss in galRegSerders]
    assert galRids[0] == galRegSerders[0].said == 'EFh-_d-O5-SbkC888zJOOiwHkDSC0hSRJTQkHC7MhF8R'
    assert galRegSerders[0].israid == gal
    assert galRegSerders[0].nonce == galRegUes[0]
    assert galRegSerders[0].sner.num == 0
    assert galRegSerders[0].stamp == stamp


    # Setup SEDI ACDC JsonSchema Validators

    # Replace Validator Setup
    replaceValidator = SchemaValidator(schema=ReplaceSchema)

    # Unit Validator Setup
    unitValidator = SchemaValidator(schema=UnitSchema)

    # Agent Validator Setup
    agentValidator = SchemaValidator(schema=AgentSchema)

    # IAR Validator Setup
    iarValidator = SchemaValidator(schema=IarSchema)

    # Core SEDI Validator setup
    coreValidator = SchemaValidator(schema=CoreSchema)

    # Guardian SEDI Validator setup
    guardianValidator = SchemaValidator(schema=GuardianSchema)

    # Residence SEDI Validator setup
    residenceValidator = SchemaValidator(schema=ResidenceSchema)

    # Age Schema Validator setup
    ageValidator = SchemaValidator(schema=AgeSchema)

    # Social Schema Validator setup
    socialValidator = SchemaValidator(schema=SocialSchema)

    # Bespoke Schema Validator setup
    bespokeValidator = SchemaValidator(schema=BespokeSchema)


    # Setup Utah State Delegation from root roy to unit deb to agent's sue and stu

    # Setup Debs Unit Delegation SEDI ACDC
    salt = b'debsunitsedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0ABkZWJzdW5pdHNlZGlzYWx0'  # CESR encoded
    debUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(16)]
    # Debs unit SEDI attribution section
    debUnitAttBareMad = \
    {
        "d": "",
        "u": debUes[1],
        "i": deb,  # deb is issuee
        "issuedDate": "2020-08-01T00:00:00.000000+00:00",  # Time MBZ
        "unit": "SediProgramOffice"
    }

    compactor = Compactor(mad=debUnitAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    debUnitAttMad = compactor.partials[('',)].mad
    assert debUnitAttMad['i'] == deb
    debUnitAttMadSaid = compactor.said
    assert  debUnitAttMadSaid == 'EHydQsy-4di85pJaiPqVN9_APpLtU15QXcmVFEN2FQE-'

    assert debUnitAttMad == \
    {
        'd': debUnitAttMadSaid,
        'u': debUes[1],
        'i': deb,
        'issuedDate': '2020-08-01T00:00:00.000000+00:00',  # Time MBZ
        'unit': "SediProgramOffice"
    }

    debUnitRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=debUnitRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    debUnitRuleMad = compactor.partials[('',)].mad
    assert debUnitRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # deb's authorizing OrgUnit ACDC
    debSerderUnit = acdcmap(israid=roy,
                            uuid=debUes[0],
                            regid=royRids[0],
                            schema=UnitSchemaSaid,
                            attribute=debUnitAttMad,
                            rule=debUnitRuleMad,
                            kind=kind)

    unitValidator.validate(debSerderUnit.sad)  # raises error if invalid

    debUnitSediSaid = debSerderUnit.said
    assert debUnitSediSaid == 'EP6uB4TN40MCT2ayCVoZ7NekTME3WTCTByH68kvQEnkY'
    assert debSerderUnit.verstr == 'ACDCCAACAAJSONAAIn.'
    assert debSerderUnit.israid == roy
    assert debSerderUnit.regid == royRids[0]
    assert debSerderUnit.iseaid == deb
    assert debSerderUnit.sad['a'] == debUnitAttMad
    assert debSerderUnit.sad == \
    {
        'v': debSerderUnit.verstr,
        't': 'acm',
        'd': debUnitSediSaid,
        'u': debUes[0],
        'i': roy,
        'rd': royRids[0],
        's': UnitSchemaSaid,
        'a': debUnitAttMad,
        'r': debUnitRuleMad,
    }

    # Setup Sue's Issuing Agent Delegation AgentSchema SEDI ACDC
    salt = b'sueagentsedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0ABzdWVhZ2VudHNlZGlzYWx0'  # CESR encoded
    sueUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(16)]
    # Sues agent SEDI attribution section
    sueAgentAttBareMad = \
    {
        "d": "",
        "u": sueUes[1],
        "i": sue,  # sue is issuee
        "issuedDate": "2020-08-01T00:00:00.000000+00:00",  # Time MBZ
        "role": "SediIssuingAgent",
        "name":
        {
            "d": "",
            "u": sueUes[2],
            "value": "Susan Park",
        },
    }

    compactor = Compactor(mad=sueAgentAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    sueAgentAttMad = compactor.partials[('.name',)].mad
    assert sueAgentAttMad['i'] == sue
    sueAgentAttMadSaid = compactor.said
    assert sueAgentAttMadSaid == 'EFPQAD6XLlU9bnNPMWfjl1Q-Rf20Jwoip_1lkp8XGKKt'

    assert sueAgentAttMad == \
    {
        'd': sueAgentAttMadSaid,
        'u': sueUes[1],
        'i': sue,
        'issuedDate': '2020-08-01T00:00:00.000000+00:00',  # Time MBZ
        'role': "SediIssuingAgent",
        'name':
        {
            'd': 'EJj1BPhB8uGFLA8QtNjNJ9MXJ8fvOliIWj5w7YLzReWI',
            'u': sueUes[2],
            'value': "Susan Park",
        },
    }

    sueAgentEdgeBareMad = \
    {
        "d": "",
        "u": sueUes[3],
        "orgUnit":
        {
            "d": "",
            "u": sueUes[4],
            "n": debUnitSediSaid,
            "s": UnitSchemaSaid,
            "o": "DI2I",
        },
    }
    compactor = Compactor(mad=sueAgentEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    sueAgentEdgeMad = compactor.partials[('.orgUnit',)].mad
    assert sueAgentEdgeMad['orgUnit']['n'] == debUnitSediSaid
    assert sueAgentEdgeMad['orgUnit']['o'] == "DI2I"

    sueAgentRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=sueAgentRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    sueAgentRuleMad = compactor.partials[('',)].mad
    assert sueAgentRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # Sue's Agent SEDI ACDC
    sueSerderAgent = acdcmap(israid=deb,
                            uuid=sueUes[0],
                            regid=debRids[0],
                            schema=AgentSchemaSaid,
                            attribute=sueAgentAttMad,
                            edge=sueAgentEdgeMad,
                            rule=sueAgentRuleMad,
                            kind=kind)

    agentValidator.validate(sueSerderAgent.sad)  # raises error if invalid

    sueAgentSediSaid = sueSerderAgent.said
    assert sueAgentSediSaid == 'EH0Mvs2ZE3tttGr0xUPgnzXhYFPVbckqNyW8_CRcp5Dc'
    assert sueSerderAgent.verstr == 'ACDCCAACAAJSONAAO9.'
    assert sueSerderAgent.israid == deb
    assert sueSerderAgent.regid == debRids[0]
    assert sueSerderAgent.iseaid == sue
    assert sueSerderAgent.sad['a'] == sueAgentAttMad
    assert sueSerderAgent.sad == \
    {
        'v': sueSerderAgent.verstr,
        't': 'acm',
        'd': sueAgentSediSaid,
        'u': sueUes[0],
        'i': deb,
        'rd': debRids[0],
        's': AgentSchemaSaid,
        'a': sueAgentAttMad,
        'e': sueAgentEdgeMad,
        'r': sueAgentRuleMad,
    }


    # Setup Stu's Issuing Agent Delegation AgentSchema SEDI ACDC
    salt = b'stuagentsedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABzdHVhZ2VudHNlZGlzYWx0'  # CESR encoded
    stuUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(16)]
    # Stu's agent SEDI attribution section
    stuAgentAttBareMad = \
    {
        "d": "",
        "u": stuUes[1],
        "i": stu,  # stu is issuee
        "issuedDate": "2020-08-01T00:00:00.000000+00:00",  # Time MBZ
        "role": "SediIssuingAgent",
        "name":
        {
            "d": "",
            "u": stuUes[2],
            "value": "Stuart Black",
        },
    }

    compactor = Compactor(mad=stuAgentAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    stuAgentAttMad = compactor.partials[('.name',)].mad
    assert stuAgentAttMad['i'] == stu
    stuAgentAttMadSaid = compactor.said
    assert stuAgentAttMadSaid == 'EK4yVDaY7-RHcZY2A9RTG-eWUwJoz_STt6sxRlyzD7-B'

    assert stuAgentAttMad == \
    {
        'd': stuAgentAttMadSaid,
        'u': stuUes[1],
        'i': stu,
        'issuedDate': '2020-08-01T00:00:00.000000+00:00',  # Time MBZ
        'role': "SediIssuingAgent",
        'name':
        {
            'd': 'EO7zg2QSbE3-T8xGVL_xwLE7GtYgtoV6sIt2N1FVF3JR',
            'u': stuUes[2],
            'value': "Stuart Black",
        },
    }

    stuAgentEdgeBareMad = \
    {
        "d": "",
        "u": stuUes[3],
        "orgUnit":
        {
            "d": "",
            "u": stuUes[4],
            "n": debUnitSediSaid,
            "s": UnitSchemaSaid,
            "o": "DI2I",
        },
    }
    compactor = Compactor(mad=stuAgentEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    stuAgentEdgeMad = compactor.partials[('.orgUnit',)].mad
    assert stuAgentEdgeMad['orgUnit']['n'] == debUnitSediSaid
    assert stuAgentEdgeMad['orgUnit']['o'] == "DI2I"

    stuAgentRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=stuAgentRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    stuAgentRuleMad = compactor.partials[('',)].mad
    assert stuAgentRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # Stu's Agent SEDI ACDC
    stuSerderAgent = acdcmap(israid=deb,
                            uuid=stuUes[0],
                            regid=debRids[0],
                            schema=AgentSchemaSaid,
                            attribute=stuAgentAttMad,
                            edge=stuAgentEdgeMad,
                            rule=stuAgentRuleMad,
                            kind=kind)

    agentValidator.validate(stuSerderAgent.sad)  # raises error if invalid

    stuAgentSediSaid = stuSerderAgent.said
    assert stuAgentSediSaid == 'ELDv-zdEZ8lUXoDkLFd8LGRJs41R2_RwscWsqBw4BmFw'
    assert stuSerderAgent.verstr == 'ACDCCAACAAJSONAAO_.'
    assert stuSerderAgent.israid == deb
    assert stuSerderAgent.regid == debRids[0]
    assert stuSerderAgent.iseaid == stu
    assert stuSerderAgent.sad['a'] == stuAgentAttMad
    assert stuSerderAgent.sad == \
    {
        'v': stuSerderAgent.verstr,
        't': 'acm',
        'd': stuAgentSediSaid,
        'u': stuUes[0],
        'i': deb,
        'rd': debRids[0],
        's': AgentSchemaSaid,
        'a': stuAgentAttMad,
        'e': stuAgentEdgeMad,
        'r': stuAgentRuleMad,
    }

    # Setup Address for Residence ACDCs
    # Guy, Gal, and Wyn have same residence address
    street = "157 E 300 N"
    city = "Beaver"
    county = "Beaver"
    state = "Utah"
    postcode = "84713"
    country = "United States"


    # Setup Guys Registries and Receipt and ACDCs
    #create presentation registries for Guy
    salt = b'guypresntregsalt'  # base salt for presentation registries
    salter = Salter(raw=salt)
    guyPreRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(2)]
    guyRegSerders= [regcept(israid=guy, uuid=ue, stamp=stamp) for ue in guyPreRegUes]
    guyPreRids = [rss.said for rss in guyRegSerders]
    assert guyPreRids == ['ELUW5D0X0pMFM30ZHZKB997lad86PISushrKkKzlhQrl',
                          'EKhN2CBz3b_4fFj9mA3j5URZf2ULQTG7on32rX7V9yFe']

    # Create Guy's unique entropy for ACDCs issued to Guy
    salt = b'guyscoresedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0ABndXlzY29yZXNlZGlzYWx0'  # CESR encoded
    guyUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(64)]


    # setup Guys Receipt
    # Guy's 128 bit Challenge Nonce derived fromSalty Nonce 128 bit entropy
    salt = b'guysedichallenge'  # raw challenge salt
    salter = Salter(raw=salt)
    guyChallenge = salter.qb64
    assert guyChallenge == '0ABndXlzZWRpY2hhbGxlbmdl'  # CESR encoded 128 bit nonce

    # Challenge Nonce Seal to be anchored in guy's SMAID KEL
    guyCns = SealNonce(nd=guyChallenge)
    structor = Structor(crew=guyCns, clan=SealNonce)
    assert structor.qb64 == guyChallenge
    assert structor.crew == guyCns
    assert structor.crew._asdict() == {'nd': guyChallenge}

    #Create sealing interaction event for guy
    data = [guyCns._asdict()]
    guyIxnSerder = interact(guy, dig=guyISerder.said, data=data, version=Vrsn_2_0, kind=Kinds.json)

    assert guyIxnSerder.sad == \
    {
        'v': 'KERICAACAAJSONAADu.',
        't': 'ixn',
        'd': 'EEmZ6nuPKuq8d2rY3DnQaPApFRPNTjXY4xZSlbCq1Iub',
        'i': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        's': '1',
        'p': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        'a': [{'nd': '0ABndXlzZWRpY2hhbGxlbmdl'}]
    }


    # Challenge Seal Reference to sealing (anchoring) event in KEL of SMAID
    # SAID and SN of event in Guy's KEL
    guyCsr = SealEvent(i=guy, s=guyIxnSerder.snh, d=guyIxnSerder.said)
    assert guyCsr == SealEvent(i='EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
                               s='1',
                               d='EEmZ6nuPKuq8d2rY3DnQaPApFRPNTjXY4xZSlbCq1Iub')

    structor = Structor(crew=guyCsr)
    guyAtc = Structor.enclose([Structor(crew=guyCsr)])  # CESR streamable attachment
    assert guyAtc == bytearray(b'-TAXEDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JRMAABEEmZ6nuPKuq8'
                               b'd2rY3DnQaPApFRPNTjXY4xZSlbCq1Iub')

    # Guys biometric facial image proof
    guyImageProof = Diger(ser=b"PretendImageOfGuy").qb64
    assert guyImageProof == 'EIQw_2CqmmC96YYUFXTW8XSkLQU2-v9bDCyItazmKhTW'

    # Guy's Identity Assurance Receipt (iar) ACDC
    guyIarAttBareMad = \
    {
        "d": "",  # SAID
        "i": guy,  # citizens SEDI managment AID (SMAID)
        "givenName": "Guy",  # given name first name(s)
        "middleName":"Marty McFly",  # middle name(s) other names
        "familyName": "Brown",  # last name family name
        "nameSuffix": "",
        "birthDate": "2002-08-22T00:00:00.000000+00:00",  # time MBZ
        "facialImageProof": guyImageProof,  # SAID of typed media block containing image
        "legalPresenceStatus": "citizen",  # Class or type of legal presence
        "residence": \
        {
            "street": street,
            "city": city,
            "county": county,
            "state": state,
            "postcode": postcode,
            "country": country,
        },
        "proofingDatetime": "2026-09-01T09:30:00.000000+00:00",
        "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
    }

    mapper = Mapper(mad=guyIarAttBareMad, makify=True, saidive=True, kind=kind)
    guyIarAttMad = mapper.mad
    assert guyIarAttMad['i'] == guy
    guyIarAttMadSaid = mapper.said
    assert guyIarAttMadSaid == 'EB4wL7gz5HVhxSEdlLfRvT7P0ynCx0IdeRl9huf0wzwt'

    assert guyIarAttMad == \
    {
        'd': guyIarAttMadSaid,
        'i': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        'givenName': 'Guy',
        'middleName': 'Marty McFly',
        'familyName': 'Brown',
        "nameSuffix": "",
        'birthDate': '2002-08-22T00:00:00.000000+00:00',
        'facialImageProof': guyImageProof,
        'legalPresenceStatus': 'citizen',
        'residence':
        {
            "street": street,
            "city": city,
            "county": county,
            "state": state,
            "postcode": postcode,
            "country": country,
        },
        'proofingDatetime': '2026-09-01T09:30:00.000000+00:00',
        'sediURL': 'https://example.com/sedi/here'
    }


    guySerderIar = acdcmap(pat, uuid=guyChallenge, schema=IarSchemaSaid,
                         attribute=guyIarAttMad, kind=kind)
    iarValidator.validate(guySerderIar.sad)  # raises error if invalid

    guySerderIarSaid = guySerderIar.said
    assert guySerderIarSaid == 'EC-p_x5AJQS21gg2KnKfOVwzgFFpCuebBrah5diko1Zl'
    assert guySerderIar.verstr == 'ACDCCAACAAJSONAAMP.'
    assert guySerderIar.sad['a'] == guyIarAttMad
    assert guySerderIar.iseaid == guy
    assert guySerderIar.sad == \
    {
        'v': guySerderIar.verstr,
        't': 'acm',
        'd': guySerderIarSaid,
        'u': guyChallenge,
        'i': pat,
        's': IarSchemaSaid,
        'a':
        {
            'd':  guyIarAttMadSaid,
            'i': guy,
            'givenName': 'Guy',
            'middleName': 'Marty McFly',
            'familyName': 'Brown',
            "nameSuffix": "",
            'birthDate': '2002-08-22T00:00:00.000000+00:00',
            'facialImageProof': guyImageProof,
            'legalPresenceStatus': 'citizen',
            'residence':
            {
                "street": street,
                "city": city,
                "county": county,
                "state": state,
                "postcode": postcode,
                "country": country,
            },
            'proofingDatetime': '2026-09-01T09:30:00.000000+00:00',
            'sediURL': 'https://example.com/sedi/here'
        }
    }


    # Setup Guy's SEDI ACDCs
    # Setup Guy's Core SEDI
    # Guy core SEDI attribution section
    guyCoreAttBareMad = \
    {
        "d": "",
        "u": guyUes[1],
        "i": guy,  #guySMAID
        "rd": guyPreRids[0],
        'primary': True,
        "givenName": \
        {
            "d": "",
            "u": guyUes[2],
            "value": "Guy",
        },
        "middleName": \
        {
            "d": "",
            "u": guyUes[3],
            "value": "Marty McFly",
        },
        "familyName": \
        {
            "d": "",
            "u":guyUes[4],
            "value": "Brown",
        },
        "nameSuffix": \
        {
            "d": "",
            "u":guyUes[5],
            "value": "Jr",
        },
        "birthDate": \
        {
            "d": "",
            "u": guyUes[6],
            "value": "2002-08-22T00:00:00.000000+00:00", # time MBZ
        },
        "facialImageProof": \
        {
            "d": "",
            "u": guyUes[7],
            "value": guyImageProof,  # Digest of image, actual image is attached as blindable typed media block
        },
        "legalPresenceStatus": \
        {
            "d": "",
            "u": guyUes[8],
            "value": "citizen",
        },
        "issuedDate": \
        {
            "d": "",
            "u":  guyUes[9],
            "value": "2020-08-22T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  guyUes[10],
            "value": "2028-09-01T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=guyCoreAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyCoreAttMad = compactor.partials[('.givenName',
                                        '.middleName',
                                        '.familyName',
                                        '.nameSuffix',
                                        '.birthDate',
                                        '.facialImageProof',
                                        '.legalPresenceStatus',
                                        '.issuedDate',
                                        '.expirationDate')].mad
    assert guyCoreAttMad['i'] == guy
    guyCoreAttMadSaid = compactor.said
    assert guyCoreAttMadSaid == 'EPIuMf4tkzdqVMSuq59rBD14LZpmFtFjhnh8Io1BWdbt'

    assert guyCoreAttMad == \
    {
        'd': guyCoreAttMadSaid,
        'u': guyUes[1],
        'i': guy,
        "rd": guyPreRids[0],
        'primary': True,
        'givenName':
        {
            'd': 'EBu_EdUcstZq6woZ7NMe2pyU7jjcQOdC9w1ryHa1P_Sq',
            'u': guyUes[2],
            'value': 'Guy'
        },
        'middleName':
        {
            'd': 'EOhalIHhb5ZbrJZ5SMY_vWBj2ds_z9W8mJ3j-FTjgSUz',
            'u': guyUes[3],
            'value': 'Marty McFly'
        },
        'familyName':
        {
            'd': 'EDBg78wYuNEQkcv-XciKFkxDQmRvIeTsXfjVMJLtUjYW',
            'u': guyUes[4],
            'value': 'Brown'
        },
        "nameSuffix": \
        {
            "d": 'EFDPwXKE-3wg-WTUVu4GWfMeu4bj8rGNkvdFrMo4Ja4N',
            "u":guyUes[5],
            "value": "Jr",
        },
        'birthDate':
        {
            'd': 'EMGKn6dwPJMd79vWaGEv7OlCQQ0oGd0nt0fRqBfz1ZyA',
            'u': guyUes[6],
            'value': '2002-08-22T00:00:00.000000+00:00'
        },
        'facialImageProof':
        {
            'd': 'EInFQsE3pfRWQp3KrpH91f7YMCR2wslrTOTKL5SF6_E7',
            'u': guyUes[7],
            'value': guyImageProof
        },
        'legalPresenceStatus':
        {
            'd': 'EMfOp3-Dd1ZXSDUHNWE4ohAsU0Qp8tfQV_gUYKSJE7-Q',
            'u': guyUes[8],
            'value': 'citizen'
        },
        'issuedDate':
        {
            'd': 'EFkQuDu6twqFQ3GdSpK-jxKRYsxxCx-iSbh9RMbTbIsE',
            'u': guyUes[9],
            'value': '2020-08-22T00:00:00.000000+00:00'
        },
        'expirationDate':
        {
            'd': 'EOjYb0hwGBe1rA0Ui8foLMoCu5lItuhnodomghuyY4r9',
            'u': guyUes[10],
            'value': '2028-09-01T00:00:00.000000+00:00'
        }
    }

    guyCoreEdgeBareMad = \
    {
        "d": "",
        "u": guyUes[11],
        "utahAgent":
        {
            "d": "",
            "u": guyUes[12],
            "n": sueAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "DI2I",
        },
    }
    compactor = Compactor(mad=guyCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyCoreEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert guyCoreEdgeMad['utahAgent']['n'] == sueAgentSediSaid
    assert guyCoreEdgeMad['utahAgent']['o'] == "DI2I"

    guyCoreRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=guyCoreRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    guyCoreRuleMad = compactor.partials[('',)].mad
    assert guyCoreRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # core sedi credential ACDC issued by Sue AID to Guy SMAID
    guySerderCore = acdcmap(israid=sue,
                            uuid=guyUes[0],
                            regid=sueRids[0],
                            schema=CoreSchemaSaid,
                            attribute=guyCoreAttMad,
                            edge=guyCoreEdgeMad,
                            rule=guyCoreRuleMad,
                            kind=kind)

    coreValidator.validate(guySerderCore.sad)  # raises error if invalid

    guyCoreSediSaid = guySerderCore.said
    assert guyCoreSediSaid == 'ENTYxv_drZOsO9aAS1w9VupOX_y1t7HRR9C7rhJeEX1j'
    assert guySerderCore.verstr == 'ACDCCAACAAJSONAAfN.'
    assert guySerderCore.israid == sue
    assert guySerderCore.regid == sueRids[0]
    assert guySerderCore.iseaid == guy
    assert guySerderCore.sad['a'] == guyCoreAttMad


    assert guySerderCore.sad == \
    {
        'v': guySerderCore.verstr,
        't': 'acm',
        'd': guyCoreSediSaid,
        'u': guyUes[0],
        'i': sue,
        'rd': sueRids[0],
        's': CoreSchemaSaid,
        'a':
        {
            'd': guyCoreAttMadSaid,
            'u': guyUes[1],
            'i': guy,
            "rd": guyPreRids[0],
            'primary': True,
            'givenName':
            {
                'd': 'EBu_EdUcstZq6woZ7NMe2pyU7jjcQOdC9w1ryHa1P_Sq',
                'u': guyUes[2],
                'value': 'Guy'
            },
            'middleName':
            {
                'd': 'EOhalIHhb5ZbrJZ5SMY_vWBj2ds_z9W8mJ3j-FTjgSUz',
                'u': guyUes[3],
                'value': 'Marty McFly'
            },
            'familyName':
            {
                'd': 'EDBg78wYuNEQkcv-XciKFkxDQmRvIeTsXfjVMJLtUjYW',
                'u': guyUes[4],
                'value': 'Brown'
            },
            "nameSuffix": \
            {
                "d": "EFDPwXKE-3wg-WTUVu4GWfMeu4bj8rGNkvdFrMo4Ja4N",
                "u":guyUes[5],
                "value": "Jr",
            },
            'birthDate':
            {
                'd': 'EMGKn6dwPJMd79vWaGEv7OlCQQ0oGd0nt0fRqBfz1ZyA',
                'u': guyUes[6],
                'value': '2002-08-22T00:00:00.000000+00:00'
            },
            'facialImageProof':
            {
                'd': 'EInFQsE3pfRWQp3KrpH91f7YMCR2wslrTOTKL5SF6_E7',
                'u':  guyUes[7],
                'value': guyImageProof
            },
            'legalPresenceStatus':
            {
                'd': 'EMfOp3-Dd1ZXSDUHNWE4ohAsU0Qp8tfQV_gUYKSJE7-Q',
                'u': guyUes[8],
                'value': 'citizen'
            },
            'issuedDate':
            {
                'd': 'EFkQuDu6twqFQ3GdSpK-jxKRYsxxCx-iSbh9RMbTbIsE',
                'u': guyUes[9],
                'value': '2020-08-22T00:00:00.000000+00:00'
            },
            'expirationDate':
            {
                'd': 'EOjYb0hwGBe1rA0Ui8foLMoCu5lItuhnodomghuyY4r9',
                'u': guyUes[10],
                'value': '2028-09-01T00:00:00.000000+00:00'
            }
        },
        'e': guyCoreEdgeMad,
        'r': guyCoreRuleMad,
    }

    # Guy residence SEDI attribution section
    guyResidenceAttBareMad = \
    {
        "d": "",
        "u": guyUes[13],
        "i": guy,  #guySMAID
        "street": \
        {
            "d": "",
            "u": guyUes[14],
            "value": street,
        },
        "city": \
        {
            "d": "",
            "u": guyUes[15],
            "value": city,
        },
        "county": \
        {
            "d": "",
            "u":guyUes[16],
            "value": county,
        },
        "state": \
        {
            "d": "",
            "u": guyUes[17],
            "value": state,
        },
        "postcode": \
        {
            "d": "",
            "u": guyUes[18],
            "value": postcode,
        },
        "country": \
        {
            "d": "",
            "u": guyUes[19],
            "value": country,
        },
        "issuedDate": \
        {
            "d": "",
            "u":  guyUes[20],
            "value": "2020-08-22T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=guyResidenceAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyResidenceAttMad = compactor.partials[('.street',
                                             '.city',
                                             '.county',
                                             '.state',
                                             '.postcode',
                                             '.country',
                                             '.issuedDate')].mad
    assert guyResidenceAttMad['i'] == guy
    guyResidenceAttMadSaid = compactor.said
    assert guyResidenceAttMadSaid == 'EMpm7D9f-U9sV_s4xje1kuC3LclwftjFh_g2OvaK15Jd'
    assert guyResidenceAttMad == \
    {
        'd': guyResidenceAttMadSaid,
        'u': guyUes[13],
        'i': guy,
        'street':
        {
            'd': 'EP6pdEcxu4pJbVPZ40NDav1xN-8GjmvaOyHhf-J-20ht',
            'u': guyUes[14],
            'value': street
        },
        'city':
        {
            'd': 'EIWG8UUJR7B59VrrUJiEJpz6cv2b4YEqqdqkHec-VK_d',
            'u': guyUes[15],
            'value': city
        },
        'county':
        {
            'd': 'EESCQE9vhr8Ys6ZE7489Lp7H2k6tKhvKfEmJQ4c0I0zi',
            'u': guyUes[16],
            'value': county
        },
        'state':
        {
            'd': 'EDliUQapanK3jK74GC9FZF3Z5UbwXBs4bFptWlzOK6b6',
            'u': guyUes[17],
            'value': state
        },
        'postcode':
        {
            'd': 'EK26etqB0TxOkjmr71zgFMEC8eGLB9oPjkKlrJ73iqDz',
            'u': guyUes[18],
            'value': postcode
        },
        'country':
        {
            'd': 'EOySpooOzGlATtv1jrqpnkZHzHexVGGSWvUHNdKXnixD',
            'u': guyUes[19],
            'value': country
        },
        'issuedDate':
        {
            'd': 'EPJPv5WXViJqWg4E5szmgJOPM7qskg6qSsiYDeELzaxG',
            'u': guyUes[20],
            'value': '2020-08-22T00:00:00.000000+00:00'
        },
    }

    guyResidenceEdgeBareMad = \
    {
        "d": "",
        "u": guyUes[21],
        "coreIdentity":
        {
            "d": "",
            "u": guyUes[22],
            "n": guyCoreSediSaid,
            "s": CoreSchemaSaid,
            "o": ["E1E", "DI1I", "NI2I"],
        },
    }
    compactor = Compactor(mad=guyResidenceEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyResidenceEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert guyResidenceEdgeMad['coreIdentity']['n'] == guyCoreSediSaid
    assert guyResidenceEdgeMad['coreIdentity']['o'] == ["E1E", "DI1I", "NI2I"]


    guyResidenceRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=guyResidenceRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    guyResidenceRuleMad = compactor.partials[('',)].mad
    assert guyResidenceRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    guySerderResidence = acdcmap(israid=sue,
                            uuid=guyUes[23],
                            regid=sueRids[2],
                            schema=ResidenceSchemaSaid,
                            attribute=guyResidenceAttMad,
                            edge=guyResidenceEdgeMad,
                            rule=guyResidenceRuleMad,
                            kind=kind)

    residenceValidator.validate(guySerderResidence.sad)  # raises error if invalid

    guyResidenceSediSaid = guySerderResidence.said
    assert guyResidenceSediSaid == 'EI9K1dzx1HPGrz9ROoieZo2PuQ5mC6aSEfXuxeBUE8Cs'
    assert guySerderResidence.verstr == 'ACDCCAACAAJSONAAZA.'
    assert guySerderResidence.israid == sue
    assert guySerderResidence.regid == sueRids[2]
    assert guySerderResidence.iseaid == guy
    assert guySerderResidence.sad['a'] == guyResidenceAttMad

    assert guySerderResidence.sad == \
    {
        'v': guySerderResidence.verstr,
        't': 'acm',
        'd': guyResidenceSediSaid,
        'u': guyUes[23],
        'i': sue,
        'rd': sueRids[2],
        's': ResidenceSchemaSaid,
        'a': guyResidenceAttMad,
        'e': guyResidenceEdgeMad,
        'r': guyResidenceRuleMad
    }

    #Setup Guys Age credential
    iael = \
    [
        "",
        dict(d='', u=guyUes[27], i=guy),
        dict(d='', u=guyUes[28], issuedDate='2020-08-22T00:00:00.000000+00:00'),
        dict(d='', u=guyUes[29], expirationDate='2040-08-31T00:00:00.000000+00:00'),
        dict(d='', u=guyUes[31], over13=True),
        dict(d='', u=guyUes[32], over14=True),
        dict(d='', u=guyUes[33], over15=True),
        dict(d='', u=guyUes[34], over16=True),
        dict(d='', u=guyUes[35], over18=True),
        dict(d='', u=guyUes[36], over21=True),
        dict(d='', u=guyUes[37], over40=True),
        dict(d='', u=guyUes[38], over62=False),
        dict(d='', u=guyUes[39], over65=False),
        dict(d='', u=guyUes[40], over67=False),
        dict(d='', u=guyUes[41], over70=False),
    ]
    aggor = Aggor(ael=iael, makify=True, kind=kind)
    guyAgid = aggor.agid
    assert guyAgid == 'EKpXUDp6DObtMdVDmHV4YydNCjUrlfQyxQt88jrxJ88X'
    guyAgeAggAel = aggor.ael

    guyAgeEdgeBareMad = \
    {
        "d": "",
        "u": guyUes[25],
        "coreIdentity":
        {
            "d": "",
            "u": guyUes[26],
            "n": guyCoreSediSaid,
            "s": CoreSchemaSaid,
            "o": ["E1E", "DI1I", "NI2I"],
        },
    }
    compactor = Compactor(mad=guyAgeEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyAgeEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert guyAgeEdgeMad['coreIdentity']['n'] == guyCoreSediSaid
    assert guyAgeEdgeMad['coreIdentity']['o'] == ["E1E", "DI1I", "NI2I"]

    guyAgeRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=guyAgeRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    guyAgeRuleMad = compactor.partials[('',)].mad
    assert guyAgeRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    guySerderAge = acdcagg(israid=sue,
                           uuid=guyUes[24],
                           regid=sueRids[4],
                           schema=AgeSchemaSaid,
                           aggregate=aggor.ael,
                           edge=guyAgeEdgeMad,
                           rule=guyAgeRuleMad,
                           kind=kind)


    ageValidator.validate(guySerderAge.sad)  # raises error if invalid

    guyAgeSediSaid = guySerderAge.said
    assert guyAgeSediSaid == 'EIDR_uFu1OaV9tkRHYNKy3VBF6RcyPvKS-Vm1tH-z4xK'
    assert guySerderAge.verstr == 'ACDCCAACAAJSONAAiO.'
    assert guySerderAge.israid == sue
    assert guySerderAge.regid == sueRids[4]
    assert guySerderAge.iseaid == guy
    assert guySerderAge.sad['A'] == guyAgeAggAel

    assert guySerderAge.sad == \
    {
        'v': guySerderAge.verstr,
        't': 'acg',
        'd': guyAgeSediSaid,
        'u': guyUes[24],
        'i': sue,
        'rd': sueRids[4],
        's': AgeSchemaSaid,
        'A': guyAgeAggAel,
        'e': guyAgeEdgeMad,
        'r': guyAgeRuleMad
    }

    # Guy guardian of ward Wyn
    # Guy guardian SEDI attribution section
    guyGuardianAttBareMad = \
    {
        "d": "",
        "u": guyUes[42],
        "i": guy,
        "rd": guyPreRids[0],
        'primary': True,
        "role": "parent",
        "ward": wyn,
        "issuedDate": \
        {
            "d": "",
            "u":  guyUes[43],
            "value": '2012-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  guyUes[44],
            "value": '2030-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
    }

    compactor = Compactor(mad=guyGuardianAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyGuardianAttMad = compactor.partials[('.issuedDate', '.expirationDate')].mad
    assert guyGuardianAttMad['i'] == guy
    guyGuardianAttMadSaid = compactor.said
    assert guyGuardianAttMadSaid == 'EHPnpFgPhgYQmnLgMUvJYcUqgvagRclCoGKfdNjdz73H'

    assert guyGuardianAttMad == \
    {
        "d": guyGuardianAttMadSaid,
        "u": guyUes[42],
        "i": guy,
        "rd": guyPreRids[0],
        'primary': True,
        "role": "parent",
        "ward": wyn,
        "issuedDate": \
        {
            "d": 'EHDyi3drPTNJ6WDAvPIbcOqtRV03mTPLRuRyTSzQUfpS',
            "u":  guyUes[43],
            "value": '2012-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
        "expirationDate": \
        {
            "d": 'EPtJr5V6lRCBvT4QudVp7ucFspyjWPRhedf9MRG_CaEa',
            "u":  guyUes[44],
            "value": '2030-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
    }

    guyGuardianEdgeBareMad = \
    {
        "d": "",
        "u": guyUes[44],
        "utahAgent":
        {
            "d": "",
            "u": guyUes[45],
            "n": sueAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "DI2I",
        },
    }
    compactor = Compactor(mad=guyGuardianEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyGuardianEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert guyGuardianEdgeMad['utahAgent']['n'] == sueAgentSediSaid
    assert guyGuardianEdgeMad['utahAgent']['o'] == "DI2I"

    guyGuardianRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=guyGuardianRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    guyGuardianRuleMad = compactor.partials[('',)].mad
    assert guyGuardianRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    guySerderGuardian = acdcmap(israid=sue,
                            uuid=guyUes[41],
                            regid=sueRids[0],
                            schema=GuardianSchemaSaid,
                            attribute=guyGuardianAttMad,
                            edge=guyGuardianEdgeMad,
                            rule=guyGuardianRuleMad,
                            kind=kind)

    guardianValidator.validate(guySerderGuardian.sad)  # raises error if invalid

    guyGuardianSediSaid = guySerderGuardian.said
    assert guyGuardianSediSaid == 'EP0aoeuK-4I1ETjR_TltV_nXziaz-chfDGS0IkPRX1IF'
    assert guySerderGuardian.verstr == 'ACDCCAACAAJSONAASq.'
    assert guySerderGuardian.israid == sue
    assert guySerderGuardian.regid == sueRids[0]
    assert guySerderGuardian.iseaid == guy
    assert guySerderGuardian.sad['a'] == guyGuardianAttMad

    assert guySerderGuardian.sad == \
    {
        'v': guySerderGuardian.verstr,
        't': 'acm',
        'd': guyGuardianSediSaid,
        'u': guyUes[41],
        'i': sue,
        'rd': sueRids[0],
        's': GuardianSchemaSaid,
        'a': guyGuardianAttMad,
        'e': guyGuardianEdgeMad,
        'r': guyGuardianRuleMad,
    }


    # Setup Gals Registries and ACDCs
    #create presentation registries for Gal
    salt = b'galpresntregsalt'  # base salt for presentation registries
    salter = Salter(raw=salt)
    galPreRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(2)]
    galRegSerders= [regcept(israid=gal, uuid=ue, stamp=stamp) for ue in galPreRegUes]
    galPreRids = [rss.said for rss in galRegSerders]
    assert galPreRids == ['EETKKNEzII7RVeqrIBWsSUifdAPYRp5qdTOQnsG_zzcm',
                          'EBAeyX2ztgyP5qBek6xWBqkLp7pI080dFyzx8PWxJ-Jg']

    # Setup Gal's unique entropy for ACDCs issued to Gal
    salt = b'galscoresedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0ABnYWxzY29yZXNlZGlzYWx0'  # CESR encoded
    galUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(64)]

    # Setup Gal's reciept
    # Gal's 128 bit Challenge Nonce derived fromSalty Nonce 128 bit entropy
    salt = b'galsedichallenge'  # raw challenge salt
    salter = Salter(raw=salt)
    galChallenge = salter.qb64
    assert galChallenge == '0ABnYWxzZWRpY2hhbGxlbmdl'  # CESR encoded 128 bit nonce

    # Challenge Nonce Seal to be anchored in gal's SMAID KEL
    galCns = SealNonce(nd=galChallenge)
    structor = Structor(crew=galCns, clan=SealNonce)
    assert structor.qb64 == galChallenge
    assert structor.crew == galCns
    assert structor.crew._asdict() == {'nd': galChallenge}

    #Create sealing interaction event for gal
    data = [galCns._asdict()]
    galIxnSerder = interact(gal, dig=galISerder.said, data=data, version=Vrsn_2_0, kind=Kinds.json)

    assert galIxnSerder.sad == \
    {
        'v': 'KERICAACAAJSONAADu.',
        't': 'ixn',
        'd': 'EGpG0MnNDI37DpydkReez_N7uiWzHDSPZN8osxuJ2SCr',
        'i': 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
        's': '1',
        'p': 'EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
        'a': [{'nd': '0ABnYWxzZWRpY2hhbGxlbmdl'}]
    }

    # Challenge Seal Reference to sealing (anchoring) event in KEL of SMAID
    # SAID and SN of event in Gals's KEL
    galCsr = SealEvent(i=gal, s=galIxnSerder.snh, d=galIxnSerder.said)
    assert galCsr == SealEvent(i='EIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegY',
                               s='1',
                               d='EGpG0MnNDI37DpydkReez_N7uiWzHDSPZN8osxuJ2SCr')

    structor = Structor(crew=galCsr)
    galAtc = Structor.enclose([Structor(crew=galCsr)])  # CESR streamable attachment
    assert galAtc == bytearray(b'-TAXEIaSWASllNlAuAFcDG1xbXGEkVw_oL0CX8_o1XkFTegYMAABEGpG0MnNDI37'
                               b'DpydkReez_N7uiWzHDSPZN8osxuJ2SCr')

    # Setup Gal's biometric image proof
    galImageProof = Diger(ser=b"PretendImageOfGal").qb64
    assert galImageProof == 'EGh8sVJumVosTZVgT95YAb0Vor_7JRKGjgCX_2C7I9h4'

    # Gal's Identity Assurance Receipt (iar) ACDC
    # issued signed (not anchored) by proofing agent
    galIarAttBareMad = \
    {
        "d": "",  # SAID
        "i": gal,  # citizens SEDI managment AID (SMAID)
        "givenName": "Gal",  # given name first name(s)
        "middleName":"Parker",  # middle name(s) other names
        "familyName": "Brown",  # last name family name
        "nameSuffix": "",
        "birthDate": "2002-11-01T00:00:00.000000+00:00",  # time MBZ
        "facialImageProof": galImageProof,  # SAID of typed media block containing image
        "legalPresenceStatus": "citizen",  # Status of legal presence, citizen, visitor, etc
        "residence": \
        {
            "street": street,
            "city": city,
            "county": county,
            "state": state,
            "postcode": postcode,
            "country": country,
        },
        "proofingDatetime": "2026-09-02T09:45:00.000000+00:00",
        "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
    }
    mapper = Mapper(mad=galIarAttBareMad, makify=True, saidive=True, kind=kind)
    galIarAttMad = mapper.mad
    galIarAttMadSaid = mapper.said
    assert galIarAttMadSaid == 'EABdFp9rdBlbUydYr1t_NMuNgvjL5jVwfBCNsa1fTqj-'
    assert galIarAttMad['i'] == gal

    galSerderIar = acdcmap(pat, uuid=galChallenge, schema=IarSchemaSaid,
                           attribute=galIarAttMad, kind=kind)
    iarValidator.validate(galSerderIar.sad)  # raises error if invalid

    galSerderIarSaid = galSerderIar.said
    assert galSerderIarSaid == 'EIkWgUAtmGQQf3N4MZxW780LCE_E3GVDR1sp21RX9rs6'
    assert galSerderIar.verstr == 'ACDCCAACAAJSONAAMK.'
    assert galSerderIar.sad['a'] == galIarAttMad

    assert galSerderIar.iseaid == gal

    assert galSerderIar.sad == \
    {
        'v': galSerderIar.verstr,
        't': 'acm',
        'd': galSerderIarSaid,
        'u': galChallenge,
        'i': pat,
        's': IarSchemaSaid,
        'a':
        {
            'd': galIarAttMadSaid,
            'i': gal,
            'givenName': 'Gal',
            'middleName': 'Parker',
            'familyName': 'Brown',
            "nameSuffix": "",
            'birthDate': '2002-11-01T00:00:00.000000+00:00',
            'facialImageProof': galImageProof,
            'legalPresenceStatus': 'citizen',
            'residence':
            {
                "street": street,
                "city": city,
                "county": county,
                "state": state,
                "postcode": postcode,
                "country": country,
            },
            'proofingDatetime': '2026-09-02T09:45:00.000000+00:00',
            'sediURL': 'https://example.com/sedi/here'
        }
    }

    # Setup Gal's SEDI ACDCs
    # Setup Gal's Core SEDI
    # Guy core SEDI attribution section
    galCoreAttBareMad = \
    {
        "d": "",
        "u": galUes[1],
        "i": gal,  #galSMAID
        "rd": galPreRids[0],
        'primary': True,
        "givenName": \
        {
            "d": "",
            "u": galUes[2],
            "value": "Gal",
        },
        "middleName": \
        {
            "d": "",
            "u": galUes[3],
            "value": "Parker",
        },
        "familyName": \
        {
            "d": "",
            "u":galUes[4],
            "value": "Brown",
        },
        "nameSuffix": \
        {
            "d": 'EFDPwXKE-3wg-WTUVu4GWfMeu4bj8rGNkvdFrMo4Ja4N',
            "u":galUes[5],
            "value": "",
        },
        "birthDate": \
        {
            "d": "",
            "u": galUes[6],
            "value": "2002-11-01T00:00:00.000000+00:00", # time MBZ
        },
        "facialImageProof": \
        {
            "d": "",
            "u": galUes[7],
            "value": galImageProof,  # Digest of image, actual image is attached as blindable typed media block
        },
        "legalPresenceStatus": \
        {
            "d": "",
            "u": galUes[8],
            "value": "citizen",
        },
        "issuedDate": \
        {
            "d": "",
            "u":  galUes[9],
            "value": "2020-08-23T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  galUes[10],
            "value": "2028-09-01T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=galCoreAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galCoreAttMad = compactor.partials[('.givenName',
                                        '.middleName',
                                        '.familyName',
                                        '.nameSuffix',
                                        '.birthDate',
                                        '.facialImageProof',
                                        '.legalPresenceStatus',
                                        '.issuedDate',
                                        '.expirationDate')].mad
    assert galCoreAttMad['i'] == gal
    galCoreAttMadSaid = compactor.said
    assert  galCoreAttMadSaid == 'EAOShXJ0qsL90sE1-zoWFXyV7dKYDNhQ9wTzBw8yu2XE'

    assert galCoreAttMad == \
    {
        'd': galCoreAttMadSaid,
        'u': galUes[1],
        'i': gal,
        "rd": galPreRids[0],
        'primary': True,
        'givenName':
        {
            'd': 'ECSb6A4qHXtoh1STpC-aBCvP4NTTh1UAudlbam0rBZ9i',
            'u': galUes[2],
            'value': 'Gal'
        },
        'middleName':
        {
            'd': 'EDK4tSBPZt0oDDZZy4SB8IfH-XELBuVGMickB9y4xlHP',
            'u': galUes[3],
            'value': 'Parker'
        },
        'familyName':
        {
            'd': 'EJoQ6tr804l4JYin_LC8l6qZy_bgQX1y3Re_nLIU6ltS',
            'u': galUes[4],
            'value': 'Brown'
        },
        "nameSuffix": \
        {
            "d": 'EMW0joKDT0vznNDZLiqC6df2acpqoqnc3w9W4-6qu_mK',
            "u":galUes[5],
            "value": "",
        },
        'birthDate':
        {
            'd': 'EL7FCUJJsNgmMpCWsI4jDDngm5dEHBN7cDbtD5rL1dPE',
            'u': galUes[6],
            'value': '2002-11-01T00:00:00.000000+00:00'
        },
        'facialImageProof':
        {
            'd': 'EADiZTmwRLQ7fo3DOvpUCQYlD3dMSGb0L5WffZN68Lo2',
            'u': galUes[7],
            'value': galImageProof
        },
        'legalPresenceStatus':
        {
            'd': 'EGRj9vSBihOIrwHdXUEGq_Q3yBYU7j1d4I6rbb-cwXn9',
            'u': galUes[8],
            'value': 'citizen'
        },
        'issuedDate':
        {
            'd': 'EGA9BBKqOJdpsNl9tRcszQSSiPYfUu9dgh1RT5MTL3sC',
            'u':  galUes[9],
            'value': '2020-08-23T00:00:00.000000+00:00'
        },
        'expirationDate':
        {
            'd': 'EOz91vuot0DyY41pAUQ7UHmAVpYtKH-6JsfDysIj_OLD',
            'u':  galUes[10],
            'value': '2028-09-01T00:00:00.000000+00:00'
        }
    }

    galCoreEdgeBareMad = \
    {
        "d": "",
        "u": galUes[11],
        "utahAgent":
        {
            "d": "",
            "u": galUes[12],
            "n": sueAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "DI2I",
        },
    }
    compactor = Compactor(mad=galCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galCoreEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert galCoreEdgeMad['utahAgent']['n'] == sueAgentSediSaid
    assert galCoreEdgeMad['utahAgent']['o'] == "DI2I"

    galCoreRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=galCoreRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    galCoreRuleMad = compactor.partials[('',)].mad
    assert galCoreRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # core sedi credential ACDC issued by Sue AID to Gal
    galSerderCore = acdcmap(israid=sue,
                            uuid=galUes[0],
                            regid=sueRids[1],
                            schema=CoreSchemaSaid,
                            attribute=galCoreAttMad,
                            edge=galCoreEdgeMad,
                            rule=galCoreRuleMad,
                            kind=kind)

    coreValidator.validate(galSerderCore.sad)  # raises error if invalid

    galCoreSediSaid = galSerderCore.said
    assert galCoreSediSaid == 'EDt8t1jfBlxnAdHN3RD9ssKg-aSzswu10cqSJF7s7CHL'
    assert galSerderCore.verstr == 'ACDCCAACAAJSONAAfG.'
    assert galSerderCore.israid == sue
    assert galSerderCore.regid == sueRids[1]
    assert galSerderCore.iseaid == gal
    assert galSerderCore.sad['a'] == galCoreAttMad

    assert galSerderCore.sad == \
    {
        'v': galSerderCore.verstr,
        't': 'acm',
        'd': galCoreSediSaid,
        'u': galUes[0],
        'i': sue,
        'rd': sueRids[1],
        's': CoreSchemaSaid,
        'a': galCoreAttMad,
        'e': galCoreEdgeMad,
        'r': galCoreRuleMad
    }

    # Gal residence SEDI attribution section
    galResidenceAttBareMad = \
    {
        "d": "",
        "u": galUes[13],
        "i": gal,  #galSMAID
        "street": \
        {
            "d": "",
            "u": galUes[14],
            "value": street,
        },
        "city": \
        {
            "d": "",
            "u": galUes[15],
            "value": city,
        },
        "county": \
        {
            "d": "",
            "u":galUes[16],
            "value": county,
        },
        "state": \
        {
            "d": "",
            "u": galUes[17],
            "value": state,
        },
        "postcode": \
        {
            "d": "",
            "u": galUes[18],
            "value": postcode,
        },
        "country": \
        {
            "d": "",
            "u": galUes[19],
            "value": country,
        },
        "issuedDate": \
        {
            "d": "",
            "u":  galUes[20],
            "value": "2020-08-25T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=galResidenceAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galResidenceAttMad = compactor.partials[('.street',
                                             '.city',
                                             '.county',
                                             '.state',
                                             '.postcode',
                                             '.country',
                                             '.issuedDate')].mad
    assert galResidenceAttMad['i'] == gal
    galResidenceAttMadSaid = compactor.said
    assert galResidenceAttMadSaid == 'EFOYWWemPCfkHO2-rzU_5zqPnz6F-WUj-D7WBrI3KHRv'
    assert galResidenceAttMad == \
    {
        'd': galResidenceAttMadSaid,
        'u': galUes[13],
        'i': gal,
        'street':
        {
            'd': 'EGrKo6qWDkmaBrn3UKLq0P91sDYINCSGL8uFG_XaP9b3',
            'u': galUes[14],
            'value': street
        },
        'city':
        {
            'd': 'EEzJ051463te5YuuQts3VpT7Lds5iePs3B-JgBjsDV03',
            'u': galUes[15],
            'value': city
        },
        'county':
        {
            'd': 'EPjPF9f5IXkSRa7mChNcf710G_qmmndxlSCvyOzYbjPv',
            'u': galUes[16],
            'value': county
        },
        'state':
        {
            'd': 'EAyMLwg_33LLfo2UbcPUmLCYsnah3X02WsCokBVZ6fCh',
            'u': galUes[17],
            'value': state
        },
        'postcode':
        {
            'd': 'EHaqtmH7RoNWGn-HqYH5fPGA9Dj1AKc6UxQZ8YXHA5oh',
            'u': galUes[18],
            'value': postcode
        },
        'country':
        {
            'd': 'EGSPEWGwbYZdLdwoX2WYFtbNeU1yTeJwTD6H0bZE3JWv',
            'u': galUes[19],
            'value': country
        },
        'issuedDate':
        {
            'd': 'EP7eFTF_wkY01YKMUiS1EBjdnU3D0T7lRK8apzV_eIxW',
            'u': galUes[20],
            'value': '2020-08-25T00:00:00.000000+00:00'
        },
    }

    galResidenceEdgeBareMad = \
    {
        "d": "",
        "u": galUes[21],
        "coreIdentity":
        {
            "d": "",
            "u": galUes[22],
            "n": galCoreSediSaid,
            "s": CoreSchemaSaid,
            "o": ["E1E", "DI1I", "NI2I"],
        },
    }
    compactor = Compactor(mad=galResidenceEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galResidenceEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert galResidenceEdgeMad['coreIdentity']['n'] == galCoreSediSaid
    assert galResidenceEdgeMad['coreIdentity']['o'] == ["E1E", "DI1I", "NI2I"]

    galResidenceRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=galResidenceRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    galResidenceRuleMad = compactor.partials[('',)].mad
    assert galResidenceRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    galSerderResidence = acdcmap(israid=sue,
                            uuid=galUes[23],
                            regid=sueRids[3],
                            schema=ResidenceSchemaSaid,
                            attribute=galResidenceAttMad,
                            edge=galResidenceEdgeMad,
                            rule=galResidenceRuleMad,
                            kind=kind)

    residenceValidator.validate(galSerderResidence.sad)  # raises error if invalid

    galResidenceSediSaid = galSerderResidence.said
    assert galResidenceSediSaid == 'EHGdpNxXKqwfPgszWXnGIZkutY51wZoxHx6w6Cn30i_U'
    assert galSerderResidence.verstr == 'ACDCCAACAAJSONAAZA.'
    assert galSerderResidence.israid == sue
    assert galSerderResidence.regid == sueRids[3]
    assert galSerderResidence.iseaid == gal
    assert galSerderResidence.sad['a'] == galResidenceAttMad

    assert galSerderResidence.sad == \
    {
        'v': galSerderResidence.verstr,
        't': 'acm',
        'd': galResidenceSediSaid,
        'u': galUes[23],
        'i': sue,
        'rd': sueRids[3],
        's': ResidenceSchemaSaid,
        'a': galResidenceAttMad,
        'e': galResidenceEdgeMad,
        'r': galResidenceRuleMad
    }

    #Setup Gals Age credential
    iael = \
    [
        "",
        dict(d='', u=galUes[27], i=gal),
        dict(d='', u=galUes[28], issuedDate='2020-08-22T00:00:00.000000+00:00'),
        dict(d='', u=galUes[29], expirationDate='2040-08-31T00:00:00.000000+00:00'),
        dict(d='', u=galUes[31], over13=True),
        dict(d='', u=galUes[32], over14=True),
        dict(d='', u=galUes[33], over15=True),
        dict(d='', u=galUes[34], over16=True),
        dict(d='', u=galUes[35], over18=True),
        dict(d='', u=galUes[36], over21=True),
        dict(d='', u=galUes[37], over40=True),
        dict(d='', u=galUes[38], over62=False),
        dict(d='', u=galUes[39], over65=False),
        dict(d='', u=galUes[40], over67=False),
        dict(d='', u=galUes[41], over70=False),
    ]
    aggor = Aggor(ael=iael, makify=True, kind=kind)
    galAgid = aggor.agid
    assert galAgid == 'EG5RJnPj1XcIw4a2beATxZvbcfUvHuqg99c4HECEawIN'
    galAgeAggAel = aggor.ael

    galAgeEdgeBareMad = \
    {
        "d": "",
        "u": galUes[25],
        "coreIdentity":
        {
            "d": "",
            "u": galUes[26],
            "n": galCoreSediSaid,
            "s": CoreSchemaSaid,
            "o": ["E1E", "DI1I", "NI2I"],
        },
    }
    compactor = Compactor(mad=galAgeEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galAgeEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert galAgeEdgeMad['coreIdentity']['n'] == galCoreSediSaid
    assert galAgeEdgeMad['coreIdentity']['o'] == ["E1E", "DI1I", "NI2I"]

    galAgeRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=galAgeRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    galAgeRuleMad = compactor.partials[('',)].mad
    assert galAgeRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    galSerderAge = acdcagg(israid=sue,
                           uuid=galUes[24],
                           regid=sueRids[5],
                           schema=AgeSchemaSaid,
                           aggregate=aggor.ael,
                           edge=galAgeEdgeMad,
                           rule=galAgeRuleMad,
                           kind=kind)


    ageValidator.validate(galSerderAge.sad)  # raises error if invalid

    galAgeSediSaid = galSerderAge.said
    assert galAgeSediSaid == 'EA7yXspp8zuJqrzwE2huo-4O8rmGMIGzAwfuag8gHibM'
    assert galSerderAge.verstr == 'ACDCCAACAAJSONAAiO.'
    assert galSerderAge.israid == sue
    assert galSerderAge.regid == sueRids[5]
    assert galSerderAge.iseaid == gal
    assert galSerderAge.sad['A'] == galAgeAggAel

    assert galSerderAge.sad == \
    {
        'v': galSerderAge.verstr,
        't': 'acg',
        'd': galAgeSediSaid,
        'u': galUes[24],
        'i': sue,
        'rd': sueRids[5],
        's': AgeSchemaSaid,
        'A': galAgeAggAel,
        'e': galAgeEdgeMad,
        'r': galAgeRuleMad
    }

    # Gal guardian of ward Wyn
    # Gal guardian SEDI attribution section
    galGuardianAttBareMad = \
    {
        "d": "",
        "u": galUes[42],
        "i": gal,
        "rd": galPreRids[0],
        'primary': True,
        "role": "parent",
        "ward": wyn,
        "issuedDate": \
        {
            "d": "",
            "u":  galUes[43],
            "value": '2012-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  galUes[44],
            "value": '2030-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
    }

    compactor = Compactor(mad=galGuardianAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galGuardianAttMad = compactor.partials[('.issuedDate', '.expirationDate')].mad
    assert galGuardianAttMad['i'] == gal
    galGuardianAttMadSaid = compactor.said
    assert galGuardianAttMadSaid == 'EGJXU81iDbXHzU1aLT_FwvB-TNin2W_Ze6j-AnTNO_yh'

    assert galGuardianAttMad == \
    {
        "d": galGuardianAttMadSaid,
        "u": galUes[42],
        "i": gal,
        "rd": galPreRids[0],
        'primary': True,
        "role": "parent",
        "ward": wyn,
        "issuedDate": \
        {
            "d": 'ELspENyn_TjT7HHSpNq_pFT-6tCN5K-hJTNW3sg4vXvS',
            "u":  galUes[43],
            "value": '2012-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
        "expirationDate": \
        {
            "d": 'EDx5Jmnrj0rUufq3eilSLbQ9P3PZ0dU60D4mjLIAeYkV',
            "u":  galUes[44],
            "value": '2030-06-21T00:00:00.000000+00:00',  # Time MBZ
        },
    }

    galGuardianEdgeBareMad = \
    {
        "d": "",
        "u": galUes[44],
        "utahAgent":
        {
            "d": "",
            "u": galUes[45],
            "n": sueAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "DI2I",
        },
    }
    compactor = Compactor(mad=galGuardianEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galGuardianEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert galGuardianEdgeMad['utahAgent']['n'] == sueAgentSediSaid
    assert galGuardianEdgeMad['utahAgent']['o'] == "DI2I"

    galGuardianRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=galGuardianRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    galGuardianRuleMad = compactor.partials[('',)].mad
    assert galGuardianRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # guardian sedi credential ACDC issued by Sue AID to Gal
    galSerderGuardian = acdcmap(israid=sue,
                            uuid=galUes[41],
                            regid=sueRids[0],
                            schema=GuardianSchemaSaid,
                            attribute=galGuardianAttMad,
                            edge=galGuardianEdgeMad,
                            rule=galGuardianRuleMad,
                            kind=kind)

    guardianValidator.validate(galSerderGuardian.sad)  # raises error if invalid

    galGuardianSediSaid = galSerderGuardian.said
    assert galGuardianSediSaid == 'ENnGph1aXP8iryzc2MSvYhMvL0aRXDYHZQqL3bLYlgG7'
    assert galSerderGuardian.verstr == 'ACDCCAACAAJSONAASq.'
    assert galSerderGuardian.israid == sue
    assert galSerderGuardian.regid == sueRids[0]
    assert galSerderGuardian.iseaid == gal
    assert galSerderGuardian.sad['a'] == galGuardianAttMad

    assert galSerderGuardian.sad == \
    {
        'v': galSerderGuardian.verstr,
        't': 'acm',
        'd': galGuardianSediSaid,
        'u': galUes[41],
        'i': sue,
        'rd': sueRids[0],
        's': GuardianSchemaSaid,
        'a': galGuardianAttMad,
        'e': galGuardianEdgeMad,
        'r': galGuardianRuleMad,
    }

    # Gal bespoke presentation Schema to convert multiple SEDI ACDCs into one DAG
    # where bespoke ACDC is origin of the DAG
    # Gal is both Issuer and Issuee with I2I edges so that signing the origin
    # counts as timely proof of control over Gals's keystate everywhere gal AID
    # shows up as an issuee in the resulting DAG
    # This one is  guardian  and residence (which links to core)
    # Gal bespoke attribution section
    galBespokeAttBareMad = \
    {
        "d": "",
        "u": galUes[50],
        "i": gal,
    }

    compactor = Compactor(mad=galBespokeAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galBespokeAttMad = compactor.partials[('',)].mad
    assert galBespokeAttMad['i'] == gal
    galBespokeAttMadSaid = compactor.said
    assert galBespokeAttMadSaid == 'EFfhhIL-0qCzbKkvXBcH1sDAakjfTFgMC9TNcFMYnaN-'

    assert galBespokeAttMad == \
    {
        "d": galBespokeAttMadSaid,
        "u": galUes[50],
        "i": gal,
    }

    galBespokeEdgeBareMad = \
    {
        "d": "",
        "u": galUes[51],
        "residence":
        {
            "d": "",
            "u": galUes[52],
            "n": galResidenceSediSaid,
            "o": "I2I",
        },
        "guardian":
        {
            "d": "",
            "u": galUes[53],
            "n": galGuardianSediSaid,
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=galBespokeEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galBespokeEdgeMad = compactor.partials[('.residence', '.guardian')].mad
    assert galBespokeEdgeMad['residence']['n'] == galResidenceSediSaid
    assert galBespokeEdgeMad['residence']['o'] == "I2I"
    assert galBespokeEdgeMad['guardian']['n'] == galGuardianSediSaid
    assert galBespokeEdgeMad['guardian']['o'] == "I2I"

    galBespokeRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=galBespokeRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    galBespokeRuleMad = compactor.partials[('',)].mad
    assert galBespokeRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    galSerderBespoke = acdcmap(israid=gal,
                                uuid=galUes[49],
                                schema=BespokeSchemaSaid,
                                attribute=galBespokeAttMad,
                                edge=galBespokeEdgeMad,
                                rule=galBespokeRuleMad,
                                kind=kind)

    bespokeValidator.validate(galSerderBespoke.sad)  # raises error if invalid

    galBespokeSediSaid = galSerderBespoke.said
    assert galBespokeSediSaid == 'ELBY34HrWHHmheIzBVJZ6nQ2Jh4GLTl1ZjtC2q-nu6Zj'
    assert galSerderBespoke.verstr == 'ACDCCAACAAJSONAAM5.'
    assert galSerderBespoke.israid == gal
    assert galSerderBespoke.iseaid == gal
    assert galSerderBespoke.sad['a'] == galBespokeAttMad

    assert galSerderBespoke.sad == \
    {
        'v': galSerderBespoke.verstr,
        't': 'acm',
        'd': galBespokeSediSaid,
        'u': galUes[49],
        'i': gal,
        's': BespokeSchemaSaid,
        'a': galBespokeAttMad,
        'e': galBespokeEdgeMad,
        'r': galBespokeRuleMad,
    }

    # Setup Wyn's Registries
    #create presentation registries for Wyn
    salt = b'wynpresntregsalt'  # base salt for presentation registries
    salter = Salter(raw=salt)
    wynPreRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(2)]
    wynRegSerders= [regcept(israid=wyn, uuid=ue, stamp=stamp) for ue in wynPreRegUes]
    wynPreRids = [rss.said for rss in wynRegSerders]
    assert wynPreRids == ['EAbxluMtNsPnHFu9texttH3G6B1s3ZqmJwpLhNbgc6ib',
                          'EGDiYWJ_i59XIjCkVT1pH9cA9aOKz0lO4lrkkf1IL2t-']

    # setup Wyn's Unique Entropy for ACDCs issued to Wyn
    salt = b'wynscoresedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 == '0AB3eW5zY29yZXNlZGlzYWx0'  # CESR encoded
    wynUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(64)]

    # Setup Wyn's reciept
    # Wyn's 128 bit Challenge Nonce derived fromSalty Nonce 128 bit entropy
    salt = b'wynsedichallenge'  # raw challenge salt
    salter = Salter(raw=salt)
    wynChallenge = salter.qb64
    assert wynChallenge == '0AB3eW5zZWRpY2hhbGxlbmdl'  # CESR encoded 128 bit nonce

    # Challenge Nonce Seal to be anchored in wyn's SMAID KEL
    wynCns = SealNonce(nd=wynChallenge)
    structor = Structor(crew=wynCns, clan=SealNonce)
    assert structor.qb64 == wynChallenge
    assert structor.crew == wynCns
    assert structor.crew._asdict() == {'nd': wynChallenge}

    #Create sealing interaction event for wyn
    data = [wynCns._asdict()]
    wynIxnSerder = interact(wyn, dig=wynISerder.said, data=data, version=Vrsn_2_0, kind=Kinds.json)

    assert wynIxnSerder.sad == \
    {
        'v': 'KERICAACAAJSONAADu.',
        't': 'ixn',
        'd': 'EBn5zkdsr1jxUJLIteNnpypbuMujGvY8MPPtSAPH2poq',
        'i': wyn,
        's': '1',
        'p': 'EKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1',
        'a': [{'nd': wynChallenge}]
    }

    # Challenge Seal Reference to sealing (anchoring) event in KEL of SMAID
    # SAID and SN of event in Gals's KEL
    wynCsr = SealEvent(i=wyn, s=wynIxnSerder.snh, d=wynIxnSerder.said)
    assert wynCsr == SealEvent(i=wyn, s='1', d=wynIxnSerder.said)

    structor = Structor(crew=wynCsr)
    wynAtc = Structor.enclose([Structor(crew=wynCsr)])  # CESR streamable attachment
    assert wynAtc == bytearray(b'-TAXEKr8JLtfqWCmHrxO3yu8ocS2n9o0Tlspeaqm9ZOf3FM1MAABEBn5zkdsr1jx'
                               b'UJLIteNnpypbuMujGvY8MPPtSAPH2poq')

    # Setup Wyn's biometric image proof
    wynImageProof = Diger(ser=b"PretendImageOfWyn").qb64
    assert wynImageProof == 'EJFuvB2J1bShwbGmRV4Ignf25r6Pzo8bHg_BeMKmc9wV'


    # Wyn's Identity Assurance Receipt (iar) ACDC
    wynIarAttBareMad = \
    {
        "d": "",  # SAID
        "i": wyn,  # citizens SEDI managment AID (SMAID)
        "givenName": "Wyn",  # given name first name(s)
        "middleName":"Biff",  # middle name(s) other names
        "familyName": "Brown",  # last name family name
        "nameSuffix": "",
        "birthDate": "2012-06-21T00:00:00.000000+00:00",  # time MBZ
        "facialImageProof": wynImageProof,  # SAID of typed media block containing image
        "legalPresenceStatus": "citizen",  # Status of legal presence, citizen, visitor, etc
        "residence": \
        {
            "street": street,
            "city": city,
            "county": county,
            "state": state,
            "postcode": postcode,
            "country": country,
        },
        "proofingDatetime": "2026-09-02T09:45:00.000000+00:00",
        "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
    }
    mapper = Mapper(mad=wynIarAttBareMad, makify=True, saidive=True, kind=kind)
    wynIarAttMad = mapper.mad
    wynIarAttMadSaid = mapper.said
    assert wynIarAttMadSaid == 'EGpd_X4ssqLAFwlSEUnqGWavsAMADZG-RKDmi4DZvDkQ'
    assert wynIarAttMad['i'] == wyn

    wynSerderIar = acdcmap(pat, uuid=wynChallenge, schema=IarSchemaSaid,
                           attribute=wynIarAttMad, kind=kind)
    iarValidator.validate(wynSerderIar.sad)  # raises error if invalid

    wynSerderIarSaid = wynSerderIar.said
    assert wynSerderIarSaid == 'EHLoFbo_a03TolMSALOobS1rpkjGLW_oSu8FdRT-Zslr'
    assert wynSerderIar.verstr == 'ACDCCAACAAJSONAAMI.'
    assert wynSerderIar.sad['a'] == wynIarAttMad

    assert wynSerderIar.iseaid == wyn

    assert wynSerderIar.sad == \
    {
        'v': wynSerderIar.verstr,
        't': 'acm',
        'd': wynSerderIarSaid,
        'u': wynChallenge,
        'i': pat,
        's': IarSchemaSaid,
        'a':
        {
            'd': wynIarAttMadSaid,
            'i': wyn,
            'givenName': 'Wyn',
            'middleName': 'Biff',
            'familyName': 'Brown',
            "nameSuffix": "",
            'birthDate': '2012-06-21T00:00:00.000000+00:00',
            'facialImageProof': wynImageProof,
            'legalPresenceStatus': 'citizen',
            'residence':
            {
                "street": street,
                "city": city,
                "county": county,
                "state": state,
                "postcode": postcode,
                "country": country,
            },
            'proofingDatetime': '2026-09-02T09:45:00.000000+00:00',
            'sediURL': 'https://example.com/sedi/here'
        }
    }

    # Setup Wyn's SEDI ACDCs
    # Setup Wyn's Core SEDI
    # Wyn's core SEDI attribution section
    wynCoreAttBareMad = \
    {
        "d": "",
        "u": wynUes[1],
        "i": wyn,
        "rd": wynPreRids[0],
        'primary': True,
        "givenName": \
        {
            "d": "",
            "u": wynUes[2],
            "value": "Wyn",
        },
        "middleName": \
        {
            "d": "",
            "u": wynUes[3],
            "value": "Biff",
        },
        "familyName": \
        {
            "d": "",
            "u":wynUes[4],
            "value": "Brown",
        },
        "nameSuffix": \
        {
            "d": 'EFDPwXKE-3wg-WTUVu4GWfMeu4bj8rGNkvdFrMo4Ja4N',
            "u":wynUes[5],
            "value": "",
        },
        "birthDate": \
        {
            "d": "",
            "u": wynUes[6],
            "value": '2012-06-21T00:00:00.000000+00:00', # time MBZ
        },
        "facialImageProof": \
        {
            "d": "",
            "u": wynUes[7],
            "value": wynImageProof,  # Digest of image, actual image is attached as blindable typed media block
        },
        "legalPresenceStatus": \
        {
            "d": "",
            "u": wynUes[8],
            "value": "citizen",
        },
        "issuedDate": \
        {
            "d": "",
            "u":  wynUes[9],
            "value": "2026-10-01T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  wynUes[10],
            "value": "2028-06-21T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=wynCoreAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynCoreAttMad = compactor.partials[('.givenName',
                                        '.middleName',
                                        '.familyName',
                                        '.nameSuffix',
                                        '.birthDate',
                                        '.facialImageProof',
                                        '.legalPresenceStatus',
                                        '.issuedDate',
                                        '.expirationDate')].mad
    assert wynCoreAttMad['i'] == wyn
    wynCoreAttMadSaid = compactor.said
    assert  wynCoreAttMadSaid == 'EAO8EoXIY6j3ijYbZx2D9FbV5atkUejkwBLoqPkDHF-m'

    assert wynCoreAttMad == \
    {
        'd': wynCoreAttMadSaid,
        'u': wynUes[1],
        'i': wyn,
        "rd": wynPreRids[0],
        'primary': True,
        'givenName':
        {
            'd': 'EKCbI7LM2X4t8JsVHtMAOOoVb5QQYHq6DeSHD28mywQm',
            'u': wynUes[2],
            'value': 'Wyn'
        },
        'middleName':
        {
            'd': 'EPDk6T5mEGjVX1FTti3iaiIH9kHzgywDclD1rLJyaikS',
            'u': wynUes[3],
            'value': 'Biff'
        },
        'familyName':
        {
            'd': 'EFE_tlePMMqIE-p_kSpAGHS8XXC8wUlEChsKVAimOO4f',
            'u': wynUes[4],
            'value': 'Brown'
        },
        "nameSuffix": \
        {
            "d": 'EHGYewGuju4W-Nj0IRVlXg0mEld9Nvh8hDMIX56GFEyF',
            "u":wynUes[5],
            "value": "",
        },
        'birthDate':
        {
            'd': 'EBaEu3HRO-HIe_XUuX7mZtdi1O3mMD0hpTJt_qr6dBxV',
            'u': wynUes[6],
            'value': '2012-06-21T00:00:00.000000+00:00'
        },
        'facialImageProof':
        {
            'd': 'EIdvmGO9ewW7yEPJPr6ExQ3SY9lEYJgKT8NwPy81d0yv',
            'u': wynUes[7],
            'value': wynImageProof
        },
        'legalPresenceStatus':
        {
            'd': 'EA5TD6VPhiTTg4lCK2SnbUip8dI4VYwhot3qlr9Y3bLA',
            'u': wynUes[8],
            'value': 'citizen'
        },
        'issuedDate':
        {
            'd': 'EG8ZYQnOx7LLTN2WaurlQ3WFi6pHAtDlAEu3U-v0uMZE',
            'u':  wynUes[9],
            'value': "2026-10-01T00:00:00.000000+00:00"
        },
        'expirationDate':
        {
            'd': 'EC-Zrgr4tgbUp4IzrBhWNfMaUThXCpTB1vAmdKR8HCuS',
            'u':  wynUes[10],
            'value': "2028-06-21T00:00:00.000000+00:00"
        }
    }

    wynCoreEdgeBareMad = \
    {
        "d": "",
        "u": wynUes[11],
        "utahAgent":
        {
            "d": "",
            "u": wynUes[12],
            "n": sueAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "DI2I",
        },
        "guardians":
        {
            "d": "",
            "u": wynUes[45],
            "o": "OR",
            "first":
            {
                "d": "",
                "u": wynUes[46],
                "n": guyGuardianSediSaid,
                "s": GuardianSchemaSaid,
                "o": "NI2I",
            },
            "second":
            {
                "d": "",
                "u": wynUes[47],
                "n": galGuardianSediSaid,
                "s": GuardianSchemaSaid,
                "o": "NI2I",
            },
        },
    }
    compactor = Compactor(mad=wynCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynCoreEdgeMad = compactor.partials[('.utahAgent',
                                         '.guardians.first',
                                         '.guardians.second')].mad
    assert wynCoreEdgeMad['utahAgent']['n'] == sueAgentSediSaid
    assert wynCoreEdgeMad['utahAgent']['o'] == "DI2I"
    assert wynCoreEdgeMad['guardians']['o'] == "OR"
    assert wynCoreEdgeMad['guardians']['first']['n'] == guyGuardianSediSaid
    assert wynCoreEdgeMad['guardians']['first']['o'] == 'NI2I'
    assert wynCoreEdgeMad['guardians']['second']['n'] == galGuardianSediSaid
    assert wynCoreEdgeMad['guardians']['second']['o'] == 'NI2I'

    wynCoreRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=wynCoreRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    wynCoreRuleMad = compactor.partials[('',)].mad
    assert wynCoreRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # core sedi credential ACDC issued by Sue AID to Wyn
    wynSerderCore = acdcmap(israid=sue,
                            uuid=wynUes[0],
                            regid=sueRids[1],
                            schema=CoreSchemaSaid,
                            attribute=wynCoreAttMad,
                            edge=wynCoreEdgeMad,
                            rule=wynCoreRuleMad,
                            kind=kind)

    coreValidator.validate(wynSerderCore.sad)  # raises error if invalid

    wynCoreSediSaid = wynSerderCore.said
    assert wynCoreSediSaid == 'EA061ydZXK-r9p7ZlmRNnJJPkgeLujYwmySiSZj_bmp_'
    assert wynSerderCore.verstr == 'ACDCCAACAAJSONAAnI.'
    assert wynSerderCore.israid == sue
    assert wynSerderCore.regid == sueRids[1]
    assert wynSerderCore.iseaid == wyn
    assert wynSerderCore.sad['a'] == wynCoreAttMad

    assert wynSerderCore.sad == \
    {
        'v': wynSerderCore.verstr,
        't': 'acm',
        'd': wynCoreSediSaid,
        'u': wynUes[0],
        'i': sue,
        'rd': sueRids[1],
        's': CoreSchemaSaid,
        'a': wynCoreAttMad,
        'e': wynCoreEdgeMad,
        'r': wynCoreRuleMad
    }

    # Wyn Residence ACDC
    wynResidenceAttBareMad = \
    {
        "d": "",
        "u": wynUes[13],
        "i": wyn,
        "street": \
        {
            "d": "",
            "u": wynUes[14],
            "value": street,
        },
        "city": \
        {
            "d": "",
            "u": wynUes[15],
            "value": city,
        },
        "county": \
        {
            "d": "",
            "u":wynUes[16],
            "value": county,
        },
        "state": \
        {
            "d": "",
            "u": wynUes[17],
            "value": state,
        },
        "postcode": \
        {
            "d": "",
            "u": wynUes[18],
            "value": postcode,
        },
        "country": \
        {
            "d": "",
            "u": wynUes[19],
            "value": country,
        },
        "issuedDate": \
        {
            "d": "",
            "u":  wynUes[20],
            "value": "2020-08-25T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=wynResidenceAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynResidenceAttMad = compactor.partials[('.street',
                                             '.city',
                                             '.county',
                                             '.state',
                                             '.postcode',
                                             '.country',
                                             '.issuedDate')].mad
    assert wynResidenceAttMad['i'] == wyn
    wynResidenceAttMadSaid = compactor.said
    assert wynResidenceAttMadSaid == 'EH_C-WhC3ddA_4SYyrDMh-3qk2KfjgzvFBgwicPKyvzS'
    assert wynResidenceAttMad == \
    {
        'd': wynResidenceAttMadSaid,
        'u': wynUes[13],
        'i': wyn,
        'street':
        {
            'd': 'ECpbebsXRhloMPhtMMl_wNX_xOgFVBs0N9RZd9zD9PrK',
            'u': wynUes[14],
            'value': street
        },
        'city':
        {
            'd': 'EJJQe6VcmuAFp1e8TxwCWWAUcPp3JM2lpKjZLxjciujS',
            'u': wynUes[15],
            'value': city
        },
        'county':
        {
            'd': 'EC1XotsZMg8xfVL1b2ezX70XE-cgxuAK3BOhVSoBOZYO',
            'u': wynUes[16],
            'value': county
        },
        'state':
        {
            'd': 'EO3U513t8sk2FPrbv1ruyUmTZqZTbgBtZLNG6U2F9fAE',
            'u': wynUes[17],
            'value': state
        },
        'postcode':
        {
            'd': 'EG-o4RCn6U0ZK0C7nsWf9-KAEwtzi-LcMDYZqb4BdIVL',
            'u': wynUes[18],
            'value': postcode
        },
        'country':
        {
            'd': 'EHNWVs5YF9d26LCKPLv-ehg9erOV4Dx3oGIGgB2sf3J9',
            'u': wynUes[19],
            'value': country
        },
        'issuedDate':
        {
            'd': 'EHJJsNtl7FHo3Xq0IqRSlt23D6Wd7GQ98YxI_HDSONcw',
            'u': wynUes[20],
            'value': '2020-08-25T00:00:00.000000+00:00'
        },
    }

    wynResidenceEdgeBareMad = \
    {
        "d": "",
        "u": wynUes[21],
        "coreIdentity":
        {
            "d": "",
            "u": wynUes[22],
            "n": wynCoreSediSaid,
            "s": CoreSchemaSaid,
            "o": ["E1E", "DI1I", "NI2I"],
        },
    }
    compactor = Compactor(mad=wynResidenceEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynResidenceEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert wynResidenceEdgeMad['coreIdentity']['n'] == wynCoreSediSaid
    assert wynResidenceEdgeMad['coreIdentity']['o'] == ["E1E", "DI1I", "NI2I"]

    wynResidenceRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=wynResidenceRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    wynResidenceRuleMad = compactor.partials[('',)].mad
    assert wynResidenceRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    wynSerderResidence = acdcmap(israid=sue,
                            uuid=wynUes[23],
                            regid=sueRids[3],
                            schema=ResidenceSchemaSaid,
                            attribute=wynResidenceAttMad,
                            edge=wynResidenceEdgeMad,
                            rule=wynResidenceRuleMad,
                            kind=kind)

    residenceValidator.validate(wynSerderResidence.sad)  # raises error if invalid

    wynResidenceSediSaid = wynSerderResidence.said
    assert wynResidenceSediSaid == 'EMKZOIbeUYeRfFi-hK7k7FES3izvJUuIP55xjAGPuVQf'
    assert wynSerderResidence.verstr == 'ACDCCAACAAJSONAAZA.'
    assert wynSerderResidence.israid == sue
    assert wynSerderResidence.regid == sueRids[3]
    assert wynSerderResidence.iseaid == wyn
    assert wynSerderResidence.sad['a'] == wynResidenceAttMad

    assert wynSerderResidence.sad == \
    {
        'v': wynSerderResidence.verstr,
        't': 'acm',
        'd': wynResidenceSediSaid,
        'u': wynUes[23],
        'i': sue,
        'rd': sueRids[3],
        's': ResidenceSchemaSaid,
        'a': wynResidenceAttMad,
        'e': wynResidenceEdgeMad,
        'r': wynResidenceRuleMad
    }

    # Wyn's Age issued by Stu not Sue
    iael = \
    [
        "",
        dict(d='', u=wynUes[27], i=wyn),
        dict(d='', u=wynUes[28], issuedDate='2020-08-22T00:00:00.000000+00:00'),
        dict(d='', u=wynUes[29], expirationDate='2027-06-21T00:00:00.000000+00:00'),
        dict(d='', u=wynUes[31], over13=True),
        dict(d='', u=wynUes[32], over14=True),
        dict(d='', u=wynUes[33], over15=False),
        dict(d='', u=wynUes[34], over16=False),
        dict(d='', u=wynUes[35], over18=False),
        dict(d='', u=wynUes[36], over21=False),
        dict(d='', u=wynUes[37], over40=False),
        dict(d='', u=wynUes[38], over62=False),
        dict(d='', u=wynUes[39], over65=False),
        dict(d='', u=wynUes[40], over67=False),
        dict(d='', u=wynUes[41], over70=False),
    ]
    aggor = Aggor(ael=iael, makify=True, kind=kind)
    wynAgid = aggor.agid
    assert wynAgid == 'EIPO23PM9_b4wUpdpwnoxSKBtGGHvm5YO7t4EjIeVh_Z'
    wynAgeAggAel = aggor.ael

    wynAgeEdgeBareMad = \
    {
        "d": "",
        "u": wynUes[25],
        "coreIdentity":
        {
            "d": "",
            "u": wynUes[26],
            "n": wynCoreSediSaid,
            "s": CoreSchemaSaid,
            "o": ["E1E", "NI2I"],
        },
        "utahAgent":
        {
            "d": "",
            "u": wynUes[48],
            "n": stuAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "DI2I"
        },
    }
    compactor = Compactor(mad=wynAgeEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynAgeEdgeMad = compactor.partials[('.coreIdentity', '.utahAgent')].mad
    assert wynAgeEdgeMad['coreIdentity']['n'] == wynCoreSediSaid
    assert wynAgeEdgeMad['coreIdentity']['o'] == ["E1E", "NI2I"]
    assert wynAgeEdgeMad['utahAgent']['n'] == stuAgentSediSaid
    assert wynAgeEdgeMad['utahAgent']['o'] == "DI2I"

    wynAgeRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=wynAgeRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    wynAgeRuleMad = compactor.partials[('',)].mad
    assert wynAgeRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    wynSerderAge = acdcagg(israid=stu,
                           uuid=wynUes[24],
                           regid=stuRids[0],
                           schema=AgeSchemaSaid,
                           aggregate=aggor.ael,
                           edge=wynAgeEdgeMad,
                           rule=wynAgeRuleMad,
                           kind=kind)


    ageValidator.validate(wynSerderAge.sad)  # raises error if invalid

    wynAgeSediSaid = wynSerderAge.said
    assert wynAgeSediSaid == 'EJ_IrohXhDC-p3Pw4L5V14NqDh4pz_yjFKs8yUBnDP-X'
    assert wynSerderAge.verstr == 'ACDCCAACAAJSONAAld.'
    assert wynSerderAge.israid == stu
    assert wynSerderAge.regid == stuRids[0]
    assert wynSerderAge.iseaid == wyn
    assert wynSerderAge.sad['A'] == wynAgeAggAel

    assert wynSerderAge.sad == \
    {
        'v': wynSerderAge.verstr,
        't': 'acg',
        'd': wynAgeSediSaid,
        'u': wynUes[24],
        'i': stu,
        'rd': stuRids[0],
        's': AgeSchemaSaid,
        'A': wynAgeAggAel,
        'e': wynAgeEdgeMad,
        'r': wynAgeRuleMad
    }

    # Wyn social authz as Issuee as Issued by Guardian parent Guy
    # Wyn social authz SEDI attribution section
    wynSocialAttBareMad = \
    {
        "d": "",
        "u": wynUes[42],
        "i": wyn,
        "rd": wynPreRids[0],
        "issued": '2026-10-24T09:30:00.000000+00:00',
        "expires": '2026-10-31T22:00:00.000000+00:00',
        "rc":
        {
            "myEmptySpace": ["all"],
        },
    }

    compactor = Compactor(mad=wynSocialAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynSocialAttMad = compactor.partials[('',)].mad
    assert wynSocialAttMad['i'] == wyn
    wynSocialAttMadSaid = compactor.said
    assert wynSocialAttMadSaid == 'ELD17t_hP-FJFTV5Iev7awrNVB8uABFAn0_xVEFrIm-t'

    assert wynSocialAttMad == \
    {
        "d": wynSocialAttMadSaid,
        "u": wynUes[42],
        "i": wyn,
        "rd": wynPreRids[0],
        "issued": '2026-10-24T09:30:00.000000+00:00',
        "expires": '2026-10-31T22:00:00.000000+00:00',
        "rc":
        {
            "myEmptySpace": ["all"],
        },
    }

    wynSocialEdgeBareMad = \
    {
        "d": "",
        "u": wynUes[43],
        "guardian":
        {
            "d": "",
            "u": wynUes[44],
            "n": guyGuardianSediSaid,
            "s": GuardianSchemaSaid,
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=wynSocialEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynSocialEdgeMad = compactor.partials[('.guardian',)].mad
    assert wynSocialEdgeMad['guardian']['n'] == guyGuardianSediSaid
    assert wynSocialEdgeMad['guardian']['o'] == "I2I"

    wynSocialRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=wynSocialRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    wynSocialRuleMad = compactor.partials[('',)].mad
    assert wynSocialRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    wynSerderSocial = acdcmap(israid=guy,
                                uuid=wynUes[41],
                                regid=guyRids[0],
                                schema=SocialSchemaSaid,
                                attribute=wynSocialAttMad,
                                edge=wynSocialEdgeMad,
                                rule=wynSocialRuleMad,
                                kind=kind)

    socialValidator.validate(wynSerderSocial.sad)  # raises error if invalid

    wynSocialSediSaid = wynSerderSocial.said
    assert wynSocialSediSaid == 'EDaJzDdlu8ooTmjkPzEfzCZYjN6wPAgLf7iMOUIvuAqi'
    assert wynSerderSocial.verstr == 'ACDCCAACAAJSONAAOu.'
    assert wynSerderSocial.israid == guy
    assert wynSerderSocial.regid == guyRids[0]
    assert wynSerderSocial.iseaid == wyn
    assert wynSerderSocial.sad['a'] == wynSocialAttMad

    assert wynSerderSocial.sad == \
    {
        'v': wynSerderSocial.verstr,
        't': 'acm',
        'd': wynSocialSediSaid,
        'u': wynUes[41],
        'i': guy,
        'rd': guyRids[0],
        's': SocialSchemaSaid,
        'a': wynSocialAttMad,
        'e': wynSocialEdgeMad,
        'r': wynSocialRuleMad,
    }

    # Wyn bespoke presentation Schema to convert multiple SEDI ACDCs into one DAG
    # where bespoke ACDC is origin of the DAG
    # Wyn is both Issuer and Issuee with I2I edges so that signing the origin
    # counts as timely proof of control over Wyn's keystate everywhere wyn AID
    # shows up as an issuee in the resulting DAG
    # This one is social authz (which links to guardian) and age (which links to core)
    # Wyn bespoke attribution section
    wynBespokeAttBareMad = \
    {
        "d": "",
        "u": wynUes[50],
        "i": wyn,
    }

    compactor = Compactor(mad=wynBespokeAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynBespokeAttMad = compactor.partials[('',)].mad
    assert wynBespokeAttMad['i'] == wyn
    wynBespokeAttMadSaid = compactor.said
    assert wynBespokeAttMadSaid == 'EP9aY5tjVfzqV3CCyB3KnIGRPKuB_NO9ajAFYKOC20cN'

    assert wynBespokeAttMad == \
    {
        "d": wynBespokeAttMadSaid,
        "u": wynUes[50],
        "i": wyn,
    }

    wynBespokeEdgeBareMad = \
    {
        "d": "",
        "u": wynUes[51],
        "age":
        {
            "d": "",
            "u": wynUes[52],
            "n": wynAgeSediSaid,
            "o": "I2I",
        },
        "social":
        {
            "d": "",
            "u": wynUes[53],
            "n": wynSocialSediSaid,
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=wynBespokeEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    wynBespokeEdgeMad = compactor.partials[('.age', '.social')].mad
    assert wynBespokeEdgeMad['age']['n'] == wynAgeSediSaid
    assert wynBespokeEdgeMad['age']['o'] == "I2I"
    assert wynBespokeEdgeMad['social']['n'] == wynSocialSediSaid
    assert wynBespokeEdgeMad['social']['o'] == "I2I"

    wynBespokeRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=wynBespokeRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    wynBespokeRuleMad = compactor.partials[('',)].mad
    assert wynBespokeRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    wynSerderBespoke = acdcmap(israid=wyn,
                                uuid=wynUes[49],
                                schema=BespokeSchemaSaid,
                                attribute=wynBespokeAttMad,
                                edge=wynBespokeEdgeMad,
                                rule=wynBespokeRuleMad,
                                kind=kind)

    bespokeValidator.validate(wynSerderBespoke.sad)  # raises error if invalid

    wynBespokeSediSaid = wynSerderBespoke.said
    assert wynBespokeSediSaid == 'EHgYdFmRPZEIhaL33pYWJVNI-EADUTJW_9Grk9zNOcot'
    assert wynSerderBespoke.verstr == 'ACDCCAACAAJSONAAMx.'
    assert wynSerderBespoke.israid == wyn
    assert wynSerderBespoke.iseaid == wyn
    assert wynSerderBespoke.sad['a'] == wynBespokeAttMad

    assert wynSerderBespoke.sad == \
    {
        'v': wynSerderBespoke.verstr,
        't': 'acm',
        'd': wynBespokeSediSaid,
        'u': wynUes[49],
        'i': wyn,
        's': BespokeSchemaSaid,
        'a': wynBespokeAttMad,
        'e': wynBespokeEdgeMad,
        'r': wynBespokeRuleMad,
    }

    # Setup Ryn's Registries
    #create presentation registries for Ryn
    salt = b'rynpresntregsalt'  # base salt for presentation registries
    salter = Salter(raw=salt)
    rynPreRegUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(2)]
    rynRegSerders= [regcept(israid=ryn, uuid=ue, stamp=stamp) for ue in rynPreRegUes]
    rynPreRids = [rss.said for rss in rynRegSerders]
    assert rynPreRids == ['EIXFfKoXlTCYQF_duHt2Gw62mvhrQfd4b-2tbeWkZnGG',
                          'EEt4vAQKmMYZY8xnPhzr8689VLs4fSLwedWdAexdCOus']

    # setup Ryn's Unique Entropy for ACDCs issued to Ryn
    salt = b'rynscoresedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0AByeW5zY29yZXNlZGlzYWx0'  # CESR encoded
    rynUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(64)]

    # Setup Ryn;s replacement SEDI ACDC to replace wyn AID with Ryn
    # Setup replace SEDI attribution section
    rynReplaceAttBareMad = \
    {
        "d": "",
        "u": rynUes[1],
        "i": ryn,  # ryn is issuee as replacement AID
        "issuedDate": "2020-10-15T00:00:00.000000+00:00",  # Time MBZ
        "obsolete": wyn,  # obsoleted AID for Wyn now Ryn
    }

    compactor = Compactor(mad=rynReplaceAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    rynReplaceAttMad = compactor.partials[('',)].mad
    assert rynReplaceAttMad['i'] == ryn
    rynReplaceAttMadSaid = compactor.said
    assert  rynReplaceAttMadSaid == 'EFAl_GXl1vxkCYb0vhBkDklrYkut-RePW1meTaib1ZdQ'

    assert rynReplaceAttMad == \
    {
        'd': rynReplaceAttMadSaid,
        'u': rynUes[1],
        'i': ryn,
        'issuedDate': "2020-10-15T00:00:00.000000+00:00",  # Time MBZ
        'obsolete': wyn
    }

    # setup edge section
    rynReplaceEdgeBareMad = \
    {
        "d": "",
        "u": rynUes[2],
        "utahAgent":
        {
            "d": "",
            "u": rynUes[3],
            "n": sueAgentSediSaid,
            "s": AgentSchemaSaid,
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=rynReplaceEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    rynReplaceEdgeMad = compactor.partials[('.utahAgent',)].mad
    rynReplaceEdgeMad['utahAgent']['n'] == sueAgentSediSaid
    rynReplaceEdgeMad['utahAgent']['o'] == "I2I"
    #assert rynReplaceEdgeMad == \
    #{
        #'d': 'EHofKRngvvhWVzH_n6c9Ai2qD82cmvFFQjGi970M-DAH',
        #'u': rynUes[2],
        #'utahAgent':
        #{
            #'d': 'EHWniEqtmyqEXlqh8RkcfFOn-SEcxWUMNDQfukkQLXnl',
            #'u': rynUes[3],
            #'n': sueAgentSediSaid,
            #'s': AgentSchemaSaid,
            #'o': 'I2I',
        #}
    #}

    # setup rule section
    rynReplaceRuleBareMad = \
    {
        "d": "",
        "l": "",
    }
    compactor = Compactor(mad=rynReplaceRuleBareMad, makify=True, compactify=True,
                          saidive=True, kind=kind)
    rynReplaceRuleMad = compactor.partials[('',)].mad
    assert rynReplaceRuleMad == \
    {
        'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
        'l': ''
    }

    # core sedi credential ACDC issued by Sue AID to Guy SMAID
    rynSerderReplace = acdcmap(israid=sue,
                              uuid=rynUes[0],
                              regid=sueRids[6],
                              schema=ReplaceSchemaSaid,
                              attribute=rynReplaceAttMad,
                              edge=rynReplaceEdgeMad,
                              rule=rynReplaceRuleMad,
                              kind=kind)

    replaceValidator.validate(rynSerderReplace.sad)  # raises error if invalid

    rynReplaceSediSaid = rynSerderReplace.said
    assert rynReplaceSediSaid == 'EBETSVmFmF3-OdazBEVoi-x2qlLveH7HkxKREIlGyLb2'
    assert rynSerderReplace.verstr == 'ACDCCAACAAJSONAANu.'
    assert rynSerderReplace.israid == sue
    assert rynSerderReplace.regid == sueRids[6]
    assert rynSerderReplace.iseaid == ryn
    assert rynSerderReplace.sad['a'] == rynReplaceAttMad
    assert rynSerderReplace.sad['a']['obsolete'] == wyn
    assert rynSerderReplace.sad == \
    {
        'v': rynSerderReplace.verstr,
        't': 'acm',
        'd': rynReplaceSediSaid,
        'u': rynUes[0],
        'i': sue,
        'rd': sueRids[6],
        's': ReplaceSchemaSaid,
        'a': rynReplaceAttMad,
        'e': rynReplaceEdgeMad,
        'r': rynReplaceRuleMad,
    }

    """Done Test"""



if __name__ == "__main__":
    test_sedi_schema()
    test_sedi_acdcs()
