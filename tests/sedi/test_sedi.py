# -*- coding: utf-8 -*-
"""
tests.sedi.test_sedi module

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




# ward core credential with link to guardian
# Guardian credential with link to core?
# Guardian auth credential ward
# Bespoke ACDC Schema for presenting both age and residence or any set of E1E leaves
# high rez image biometric credential

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


AgentSchemaSaid = 'EMnswUTHQ11HzWlqYVUJGVVtOelwW_bRckn622CkObDQ'
AgentSchema = \
{
  '$id': 'EMnswUTHQ11HzWlqYVUJGVVtOelwW_bRckn622CkObDQ',
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

CoreSchemaSaid = 'EAyyREL1r5OL8Z9HGl47df26rn_JRLsC7PVDBH5RtwLs'
CoreSchema = \
{
  '$id': 'EAyyREL1r5OL8Z9HGl47df26rn_JRLsC7PVDBH5RtwLs',
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
              'description': 'Legal Presense Status Block',
              'oneOf':
              [
                {'description': 'Legal Presense Status SAID', 'type': 'string'},
                {
                  'description': 'Legal Presense Status Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Legal Presense Status Value i.e. citizen', 'type': 'string'},
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


WardCoreSchemaSaid = 'EObxOWfcPJcS_E5mgq2JuthDlt483SJigeRRizcCnT1N'
WardCoreSchema = \
{
  '$id': 'EObxOWfcPJcS_E5mgq2JuthDlt483SJigeRRizcCnT1N',
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  'title': 'SEDI Ward Core Schema',
  'description': 'SEDI Ward Core Identity JSON Schema for acm ACDC.',
  'credentialType': 'SEDI_Ward_Core_ACDC_acm_message',
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
              'description': 'Legal Presense Status Block',
              'oneOf':
              [
                {'description': 'Legal Presense Status SAID', 'type': 'string'},
                {
                  'description': 'Legal Presense Status Detail',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Legal Presense Status Value i.e. citizen', 'type': 'string'},
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
          'required': ['d', 'u', 'utahAgent', 'guardians'],
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


ResidenceSchemaSaid = 'EH7ayivQLHwfBKwFhg7mcpOzHEWcvvJ24EO0OyzvPVKQ'
ResidenceSchema = \
{
  '$id': 'EH7ayivQLHwfBKwFhg7mcpOzHEWcvvJ24EO0OyzvPVKQ',
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

# Age SEDI ACDC Schema
AgeSchemaSaid = 'EH-ZOEzzWm5hw351zL3IBJiEMDnJiKrv17lQp2JFj8Sb'
AgeSchema = \
{
  '$id': 'EH-ZOEzzWm5hw351zL3IBJiEMDnJiKrv17lQp2JFj8Sb',
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

    mapper = Mapper(mad=agentSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    agentSchemaSaid = mapper.said
    assert  agentSchemaSaid == 'EMnswUTHQ11HzWlqYVUJGVVtOelwW_bRckn622CkObDQ'
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
                              'description': 'Legal Presense Status Block',
                              'oneOf':
                              [
                                {'description': 'Legal Presense Status SAID', 'type': 'string'},
                                {
                                  'description': 'Legal Presense Status Detail',
                                  'type': 'object',
                                  'required': ['d', 'u', 'value'],
                                  'properties':
                                  {
                                    'd': {'description': 'Block SAID', 'type': 'string'},
                                    'u': {'description': 'Bock UE', 'type': 'string'},
                                    'value': {'description': 'Legal Presense Status Value i.e. citizen', 'type': 'string'},
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
                                "required": ["d", "u", "n", "s", "o"],
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
    assert  coreSchemaSaid == 'EAyyREL1r5OL8Z9HGl47df26rn_JRLsC7PVDBH5RtwLs'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert coreSchemaSaid == CoreSchemaSaid
    assert mapper.mad == CoreSchema

    wardCoreSchemaMad = \
    {
      '$id': 'EAyyREL1r5OL8Z9HGl47df26rn_JRLsC7PVDBH5RtwLs',
      '$schema': 'https://json-schema.org/draft/2020-12/schema',
      'title': 'SEDI Ward Core Schema',
      'description': 'SEDI Ward Core Identity JSON Schema for acm ACDC.',
      'credentialType': 'SEDI_Ward_Core_ACDC_acm_message',
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
                  'description': 'Legal Presense Status Block',
                  'oneOf':
                  [
                    {'description': 'Legal Presense Status SAID', 'type': 'string'},
                    {
                      'description': 'Legal Presense Status Detail',
                      'type': 'object',
                      'required': ['d', 'u', 'value'],
                      'properties':
                      {
                        'd': {'description': 'Block SAID', 'type': 'string'},
                        'u': {'description': 'Bock UE', 'type': 'string'},
                        'value': {'description': 'Legal Presense Status Value i.e. citizen', 'type': 'string'},
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
              'required': ['d', 'u', 'utahAgent', 'guardians'],
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
    mapper = Mapper(mad=wardCoreSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    wardCoreSchemaSaid = mapper.said
    assert  wardCoreSchemaSaid == 'EObxOWfcPJcS_E5mgq2JuthDlt483SJigeRRizcCnT1N'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert wardCoreSchemaSaid == WardCoreSchemaSaid
    assert mapper.mad == WardCoreSchema

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

    mapper = Mapper(mad=residenceSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    residenceSchemaSaid = mapper.said
    assert  residenceSchemaSaid == 'EH7ayivQLHwfBKwFhg7mcpOzHEWcvvJ24EO0OyzvPVKQ'
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

    mapper = Mapper(mad=ageSchemaMad, makify=True, strict=False, saids={"$id": 'E',},
                    saidive=True, kind=kind)
    ageSchemaSaid = mapper.said
    assert  ageSchemaSaid == 'EH-ZOEzzWm5hw351zL3IBJiEMDnJiKrv17lQp2JFj8Sb'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert ageSchemaSaid == AgeSchemaSaid
    assert mapper.mad == AgeSchema

    """done test"""


def test_sedi_acdcs():
    """Test sedi receipt and entitlements

    IAL3 process

    Proof-of-control over SMAID by citizen

    Create incepting key states for participants:
        Sue as State Issuer Department Level
        Pat as Proofer (Identity)
        Guy as Guardian Parent Citizen
        Gal as Guardian Parent Citizen
        Wyn as Ward Child Citizen

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
    signers = salter.signers(count=16, transferable=True, temp=True)  # two per

    # create witness signers as nontransferable, each contains key pair
    walt = b'sediacdcworkwits'  # different salt for witness keys
    walter = Salter(raw=walt)
    wigners = walter.signers(count=10,transferable=False, temp=True)  # one per

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


    # Setup Registries for Roy, Deb, and Sue as State Issuers

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

    # Residence SEDI Validator setup
    residenceValidator = SchemaValidator(schema=ResidenceSchema)

    # Age Schema Validator setup
    ageValidator = SchemaValidator(schema=AgeSchema)


    # Setup Utah State Delegation from root roy to unit deb to agent sue

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

    # core sedi credential ACDC issued by Sue AID to Guy SMAID
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

    # Setup Sue's Issuing Agent Delegation SEDI ACDC

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
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=sueAgentEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    sueAgentEdgeMad = compactor.partials[('.orgUnit',)].mad
    assert sueAgentEdgeMad == \
    {
        'd': 'EPvTUlgeFWN-da-GVFY6X02koGypjLnEt1ZjpqLf_iOC',
        'u': sueUes[3],
        'orgUnit':
        {
            'd': 'EPa0Jf4VF_uq26Cye07CFGZrw7_sSKQ-aG2xYdWGjo4_',
            'u': sueUes[4],
            'n': debUnitSediSaid,
            's': UnitSchemaSaid,
            'o': 'I2I',
        }
    }


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

    # core sedi credential ACDC issued by Sue AID to Guy SMAID
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
    assert sueAgentSediSaid == 'EM62a9na-h-m81HgCPOJpx3h9iJHVmNeIb3n1EGV24HS'
    assert sueSerderAgent.verstr == 'ACDCCAACAAJSONAAO8.'
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


    # Guy's Identity Assurance Receipt (iar) ACDC
    # issued signed (not anchored) by proofing agent
    guyIarMad = \
    {
        "v": "",  # VersionString
        "t": "acm",
        "d": "",  # SAID
        "u": guyChallenge,  # 128 bit entropy challenge salty nonce
        "i": pat,  # pat as identity assurance proofing agent AID
        "s": "",  # schema of identity assurance receipt
        "a":
        {
            "d": "",  # SAID
            "i": guy,  # citizens SEDI managment AID (SMAID)
            "givenName": "Guy",  # given name first name(s)
            "middleName":"Marty McFly",  # middle name(s) other names
            "familyName": "Brown",  # last name family name
            "nameSuffix": "",  # nameSuffix like Jr Sr etc
            "birthDate": "2002-08-22T00:00:00.000000+00:00",  # time MBZ
            "facialImageProof": "",  # SAID of typed media block containing image
            "legalPresenceStatus": "citizen",  # Class or type of legal presence
            "residence": \
            {
                "street": "157 E 300 N",
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "postcode": "84713",
                "country": "United States",
            },
            "proofingDatetime": "2026-09-01T09:30:00.000000+00:00",
            "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
        }
    }

    iarValidator.validate(guyIarMad)  # raises error if invalid

    mapper = Mapper(mad=guyIarMad, makify=True, saidive=True, kind=kind)
    guyIarMadSaid = mapper.said
    assert  guyIarMadSaid == 'EHJUa3M79igYnjM1oR_kwbx6QZtGUTt6X1gl0W4jhCDg'
    iarValidator.validate(mapper.mad)  # raises error if invalid

    guyIarAttBareMad = \
    {
        "d": "",  # SAID
        "i": guy,  # citizens SEDI managment AID (SMAID)
        "givenName": "Guy",  # given name first name(s)
        "middleName":"Marty McFly",  # middle name(s) other names
        "familyName": "Brown",  # last name family name
        "nameSuffix": "",
        "birthDate": "2002-08-22T00:00:00.000000+00:00",  # time MBZ
        "facialImageProof": "",  # SAID of typed media block containing image
        "legalPresenceStatus": "citizen",  # Class or type of legal presence
        "residence": \
        {
            "street": "157 E 300 N",
            "city": "Beaver",
            "county": "Beaver",
            "state": "Utah",
            "postcode": "84713",
            "country": "United States",
        },
        "proofingDatetime": "2026-09-01T09:30:00.000000+00:00",
        "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
    }

    mapper = Mapper(mad=guyIarAttBareMad, makify=True, saidive=True, kind=kind)
    guyIarAttMad = mapper.mad
    assert guyIarAttMad['i'] == guy
    guyIarAttMadSaid = mapper.said
    assert  guyIarAttMadSaid == 'EBvyK6QLiBkJqsCTCvPzP24Gb9BBEJRHsp6DGHDwQJOm'

    assert guyIarAttMad == \
    {
        'd': guyIarAttMadSaid,
        'i': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        'givenName': 'Guy',
        'middleName': 'Marty McFly',
        'familyName': 'Brown',
        "nameSuffix": "",
        'birthDate': '2002-08-22T00:00:00.000000+00:00',
        'facialImageProof': '',
        'legalPresenceStatus': 'citizen',
        'residence':
        {
            'street': '157 E 300 N',
            'city': 'Beaver',
            'county': 'Beaver',
            'state': 'Utah',
            'postcode': '84713',
            'country': 'United States'
        },
        'proofingDatetime': '2026-09-01T09:30:00.000000+00:00',
        'sediURL': 'https://example.com/sedi/here'
    }


    guySerderIar = acdcmap(pat, uuid=guyChallenge, schema=IarSchemaSaid,
                         attribute=guyIarAttMad, kind=kind)
    iarValidator.validate(guySerderIar.sad)  # raises error if invalid

    guySerderIarSaid = guySerderIar.said
    assert guySerderIarSaid == 'EOci_-BIIESmZ_TbIkc4UZO2ic0e-_RqGzVxAMYNvnO_'
    assert guySerderIar.verstr == 'ACDCCAACAAJSONAALj.'
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
            'facialImageProof': '',
            'legalPresenceStatus': 'citizen',
            'residence':
            {
                'street': '157 E 300 N',
                          'city': 'Beaver',
                          'county': 'Beaver',
                          'state': 'Utah',
                          'postcode': '84713',
                          'country': 'United States'
            },
            'proofingDatetime': '2026-09-01T09:30:00.000000+00:00',
            'sediURL': 'https://example.com/sedi/here'
        }
    }


    # Setup Guy's SEDI ACDCs
    # Setup Guy's Core SEDI
    guyImageProof = Diger(ser=b"PretendImageOfGuy").qb64
    assert guyImageProof == 'EIQw_2CqmmC96YYUFXTW8XSkLQU2-v9bDCyItazmKhTW'

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
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=guyCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyCoreEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert guyCoreEdgeMad == \
    {
        'd': 'EJHkFDojLaEkGHoyKUAb51bX-Hs80KidadO8YRESkGM3',
        'u': guyUes[11],
        'utahAgent':
        {
            'd': 'EIuekCZmpq3772hyQYfDAT_tMH9Zwix7yWmeCkCQqrwh',
            'u': guyUes[12],
            'n': sueAgentSediSaid,
            's': AgentSchemaSaid,
            'o': 'I2I',
        }
    }

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
    assert guyCoreSediSaid == 'ENOVdsuMryEUCyZ1qQ26VSqtIMEzgOdyqZ2WCx2S11Nf'
    assert guySerderCore.verstr == 'ACDCCAACAAJSONAAfM.'
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
            "o": ["E1E", "NI2I"],
        },
    }
    compactor = Compactor(mad=guyResidenceEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyResidenceEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert guyResidenceEdgeMad == \
    {
        'd': 'EEiocTKXFr-yIS5L2EKkYKu-6Q0ZbVXR-ziwqay-VvLo',
        'u': guyUes[21],
        'coreIdentity':
        {
            'd': 'EJXSu5PIbOVXjQjkHJFc_NB25WA4qYcbk6aHDQ2rHg86',
            'u': guyUes[22],
            'n': guyCoreSediSaid,
            's': CoreSchemaSaid,
            'o': ["E1E", "NI2I"],
        }
    }


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

   # delete expiration date on residence credential
   # tBD on street or street1 street2
    # core sedi credential ACDC issued by Sue AID to Guy SMAID
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
    assert guyResidenceSediSaid == 'EPb1xxIaIvPTckSE80yTOsKwECWvTYW_stqpzWvpI2PH'
    assert guySerderResidence.verstr == 'ACDCCAACAAJSONAAY5.'
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



    #Setup Guys Age credentials
    iael = \
    [
        "",
        dict(d='', u=guyUes[27], i=guy),
        dict(d='', u=guyUes[28], issuedDate='2020-08-22T00:00:00.000000+00:00'),
        dict(d='', u=guyUes[29], expirationDate='20400-08-31T00:00:00.000000+00:00'),
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
    assert guyAgid =='EPq_ss81RMpzgVaPLdnB8s1qK7yoSpocwPGVeoJ4Ew1L'
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
            "o": ["E1E", "NI2I"],
        },
    }
    compactor = Compactor(mad=guyAgeEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyAgeEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert guyAgeEdgeMad == \
    {
        'd': 'EH8QZQtYDmFrwCBOyY71G-BF59nQ38juVzL_Ywwr-SkJ',
        'u': guyUes[25],
        'coreIdentity':
        {
            'd': 'EDhh4tQRORfb489i9PNSf53rOIplnQ1T0GBfFX1uT6Xo',
            'u': guyUes[26],
            'n': guyCoreSediSaid,
            's': CoreSchemaSaid,
            'o': ['E1E', 'NI2I']
        }
    }

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
    assert guyAgeSediSaid == 'EL_TknAe1H0HFAO3GiFL3OFLDVCyIbo5e9C978_sKPwI'
    assert guySerderAge.verstr == 'ACDCCAACAAJSONAAiI.'
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



    # Gal's Identity Assurance Receipt (iar) ACDC
    # issued signed (not anchored) by proofing agent
    galIarMad = \
    {
        "v": "",  # VersionString
        "t": "acm",
        "d": "",  # SAID
        "u": galChallenge,  # 128 bit entropy challenge salty nonce
        "i": pat,  # pat as identity assurance proofing agent AID
        "s": "",  # schema of identity assurance receipt
        "a":
        {
            "d": "",  # SAID
            "i": gal,  # citizens SEDI managment AID (SMAID)
            "givenName": "Gal",  # given name first name(s)
            "middleName":"Parker",  # middle name(s) other names
            "familyName": "Brown",  # last name family name
            "nameSuffix": "",
            "birthDate": "2002-11-01T00:00:00.000000+00:00",  # time MBZ
            "facialImageProof": "",  # SAID of typed media block containing image
            "legalPresenceStatus": "citizen",  # Status of legal presence, citizen, visitor, etc
            "residence": \
            {
                "street": "157 E 300 N",
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "postcode": "84713",
                "country": "United States",
            },
            "proofingDatetime": "2026-09-02T09:45:00.000000+00:00",
            "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
        }
    }

    iarValidator.validate(galIarMad)  # raises error if invalid

    galIarAttBareMad = \
    {
        "d": "",  # SAID
        "i": gal,  # citizens SEDI managment AID (SMAID)
        "givenName": "Gal",  # given name first name(s)
        "middleName":"Parker",  # middle name(s) other names
        "familyName": "Brown",  # last name family name
        "nameSuffix": "",
        "birthDate": "2002-11-01T00:00:00.000000+00:00",  # time MBZ
        "facialImageProof": "",  # SAID of typed media block containing image
        "legalPresenceStatus": "citizen",  # Status of legal presence, citizen, visitor, etc
        "residence": \
        {
            "street": "157 E 300 N",
            "city": "Beaver",
            "county": "Beaver",
            "state": "Utah",
            "postcode": "84713",
            "country": "United States",
        },
        "proofingDatetime": "2026-09-02T09:45:00.000000+00:00",
        "sediURL": "https://example.com/sedi/here", # place to go to get core sedi
    }
    mapper = Mapper(mad=galIarAttBareMad, makify=True, saidive=True, kind=kind)
    galIarAttMad = mapper.mad
    galIarAttMadSaid = mapper.said
    assert galIarAttMadSaid == 'ECL3hRdthn1d2m_wklWeX9P6ngpOxtf-x6bWUQgEpLBv'
    assert galIarAttMad['i'] == gal

    galSerderIar = acdcmap(pat, uuid=galChallenge, schema=IarSchemaSaid,
                           attribute=galIarAttMad, kind=kind)
    iarValidator.validate(galSerderIar.sad)  # raises error if invalid

    galSerderIarSaid = galSerderIar.said
    assert galSerderIarSaid == 'EBTgH9X0yI56qOWePTRjbd1DMkhY-3pm0DdPn2tOmO_F'
    assert galSerderIar.verstr == 'ACDCCAACAAJSONAALe.'
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
            'facialImageProof': '',
            'legalPresenceStatus': 'citizen',
            'residence':
            {
                'street': '157 E 300 N',
                'city': 'Beaver',
                'county': 'Beaver',
                'state': 'Utah',
                'postcode': '84713',
                'country': 'United States'
            },
            'proofingDatetime': '2026-09-02T09:45:00.000000+00:00',
            'sediURL': 'https://example.com/sedi/here'
        }
    }

    # Setup Gal's SEDI ACDCs
    # Setup Gal's Core SEDI
    # Setup Gal's biometric image proof
    galImageProof = Diger(ser=b"PretendImageOfGal").qb64
    assert galImageProof == 'EGh8sVJumVosTZVgT95YAb0Vor_7JRKGjgCX_2C7I9h4'

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
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=galCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galCoreEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert galCoreEdgeMad == \
    {
        'd': 'EJ2og1IbznbtGXXCsUVDc6Jyk1Pjwl31ABEhqgjKJ0L5',
        'u': galUes[11],
        'utahAgent':
        {
            'd': 'ECIzJ7Yj_fZNVV2jme6AEgBZPLD_8VS69uNe2111wEba',
            'u': galUes[12],
            'n': sueAgentSediSaid,
            's': AgentSchemaSaid,
            'o': 'I2I',
        }
    }

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

    # core sedi credential ACDC issued by Sue AID to Gal SMAID
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
    assert galCoreSediSaid == 'EA4iEqsUF-Fu6aT1DgBkqPWeT3Rw0W367veAkYSCkRMV'
    assert galSerderCore.verstr == 'ACDCCAACAAJSONAAfF.'
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
            "o": ["E1E", "NI2I"],
        },
    }
    compactor = Compactor(mad=galResidenceEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galResidenceEdgeMad = compactor.partials[('.coreIdentity',)].mad
    assert galResidenceEdgeMad == \
    {
        'd': 'ELrB2N0vAgWJF4qodgtiXZdiULQVACKRr0n_PwpqBdjw',
        'u': galUes[21],
        'coreIdentity':
        {
            'd': 'EKKjzyedaIpXn9ih2ZpumO-Usvz-N346TVZb_Ee4UGZ_',
            'u': galUes[22],
            'n': galCoreSediSaid,
            's': CoreSchemaSaid,
            'o': ["E1E", "NI2I"],
        }
    }

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

    # core sedi credential ACDC issued by Sue AID to Gal SMAID
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
    assert galResidenceSediSaid == 'EAjNpZVjwiFxiEvLmTureyFdRQxOiSROxGxv1ob49LTg'
    assert galSerderResidence.verstr == 'ACDCCAACAAJSONAAY5.'
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
    assert rynReplaceEdgeMad == \
    {
        'd': 'EHofKRngvvhWVzH_n6c9Ai2qD82cmvFFQjGi970M-DAH',
        'u': rynUes[2],
        'utahAgent':
        {
            'd': 'EHWniEqtmyqEXlqh8RkcfFOn-SEcxWUMNDQfukkQLXnl',
            'u': rynUes[3],
            'n': sueAgentSediSaid,
            's': AgentSchemaSaid,
            'o': 'I2I',
        }
    }

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
    assert rynReplaceSediSaid == 'EBRXDVyQRpuT04etQlFgr4sDpKR-zM_ewvupvExc69WQ'
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
