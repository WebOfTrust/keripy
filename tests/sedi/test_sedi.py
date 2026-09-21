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
                       Structor,
                       SealEvent, SealDigest, SealNonce, incept, interact)
from keri.acdc import regcept, blindate, update, acdcmap


# see test_sedi_schema() for generating and testing
IarSchemaSaid = 'EHp3Ik9q-6-sT0IFaLRJDEjd-j3zMRdy1aN6O6awCsZd'
IarSchema = \
{
  '$id': 'EHp3Ik9q-6-sT0IFaLRJDEjd-j3zMRdy1aN6O6awCsZd',
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

CoreSchemaSaid = 'ED7zRxzpuvv89c6jDwgyBNOoW06Ut0wm_8jJQRqKYv_5'
CoreSchema = \
{
  '$id': 'ED7zRxzpuvv89c6jDwgyBNOoW06Ut0wm_8jJQRqKYv_5',
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
            'givenName',
            'middleName',
            'familyName',
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
            'i': {'description': 'Issuee SMAID SEDI Management AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'givenName':
            {
              'description': 'Given Name Block',
              'type': 'object',
              'required': ['d', 'u', 'value'],
              'properties':
              {
                'd': {'description': 'Block SAID', 'type': 'string'},
                'u': {'description': 'Bock UE', 'type': 'string'},
                'value': {'description': 'Given Name Value', 'type': 'string'},
              },
              'additionalProperties': False
            },
            'middleName':
            {
              'description': 'Middle Name(s) Block',
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
            'familyName':
            {
              'description': 'Family Name Block',
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
            'birthDate':
            {
              'description': 'Birth Date Block',
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
            'facialImageProof':
            {
              'description': 'Facial Image Proof Block',
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
            'legalPresenceStatus':
            {
              'description': 'Legal Presense Status Block',
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
            'issuedDate':
            {
              'description': 'Issued Date Block',
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
            'expirationDate':
            {
              'description': 'Expiration Date Block',
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

ResidenceSchemaSaid = 'EEgFNN1XH90koG5J5pbXKlRNU6TnibizaTQmJcRfEcop'
ResidenceSchema = \
{
  '$id': 'EEgFNN1XH90koG5J5pbXKlRNU6TnibizaTQmJcRfEcop',
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
            'expirationDate',
          ],
          'properties':
          {
            'd': {'description': 'Attribute Section SAID', 'type': 'string'},
            'u': {'description': 'Attribute Section UE', 'type': 'string'},
            'i': {'description': 'Issuee SMAID SEDI Management AID', 'type': 'string'},
            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
            'street':
            {
              'description': 'Street Address Block',
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
            'city':
            {
              'description': 'City Name Block',
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
            'county':
            {
              'description': 'County Name Block',
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
            'state':
            {
              'description': 'State Name Block',
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
            'postcode':
            {
              'description': 'Postcode Block',
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
            'country':
            {
              'description': 'Country Name Block',
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
            'issuedDate':
            {
              'description': 'Issued Date Block',
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
            'expirationDate':
            {
              'description': 'Expiration Date Block',
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
    iarSchemaSAID = mapper.said
    assert  iarSchemaSAID == 'EHp3Ik9q-6-sT0IFaLRJDEjd-j3zMRdy1aN6O6awCsZd'

    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format

    assert mapper.mad == IarSchema

    assert mapper.mad == \
    {
      '$id': 'EHp3Ik9q-6-sT0IFaLRJDEjd-j3zMRdy1aN6O6awCsZd',
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
    #mapper.raw   # compact json of mapper


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
                            'givenName',
                            'middleName',
                            'familyName',
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
                            "i": {"description": "Issuee SMAID SEDI Management AID", "type": "string"},
                            'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                            "givenName":
                            {
                              'description': 'Given Name Block',
                              'type': 'object',
                              'required': ['d', 'u', 'value'],
                              'properties':
                              {
                                'd': {'description': 'Block SAID', 'type': 'string'},
                                'u': {'description': 'Bock UE', 'type': 'string'},
                                'value': {'description': 'Given Name Value', 'type': 'string'},
                              },
                              'additionalProperties': False
                            },
                            'middleName':
                            {
                              'description': 'Middle Name(s) Block',
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
                            'familyName':
                            {
                              'description': 'Family Name Block',
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
                            'birthDate':
                            {
                              'description': 'Birth Date Block',
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
                            'facialImageProof':
                            {
                              'description': 'Facial Image Proof Block',
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
                            'legalPresenceStatus':
                            {
                              'description': 'Legal Presense Status Block',
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
                            'issuedDate':
                            {
                              'description': 'Issued Date Block',
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
                            'expirationDate':
                            {
                              'description': 'Expiration Date Block',
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
    assert  coreSchemaSaid == 'ED7zRxzpuvv89c6jDwgyBNOoW06Ut0wm_8jJQRqKYv_5'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert coreSchemaSaid == CoreSchemaSaid
    assert mapper.mad == CoreSchema

    assert mapper.mad == \
    {
      '$id': 'ED7zRxzpuvv89c6jDwgyBNOoW06Ut0wm_8jJQRqKYv_5',
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
        "rd": {"description": "Registry SAID", "type": "string"},
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
                'givenName',
                'middleName',
                'familyName',
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
                'i': {'description': 'Issuee SMAID SEDI Management AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                "givenName":
                {
                  'description': 'Given Name Block',
                  'type': 'object',
                  'required': ['d', 'u', 'value'],
                  'properties':
                  {
                    'd': {'description': 'Block SAID', 'type': 'string'},
                    'u': {'description': 'Bock UE', 'type': 'string'},
                    'value': {'description': 'Given Name Value', 'type': 'string'},
                  },
                  'additionalProperties': False
                },
                'middleName':
                {
                  'description': 'Middle Name(s) Block',
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
                'familyName':
                {
                  'description': 'Family Name Block',
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
                'birthDate':
                {
                  'description': 'Birth Date Block',
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
                'facialImageProof':
                {
                  'description': 'Facial Image Proof Block',
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
                'legalPresenceStatus':
                {
                  'description': 'Legal Presense Status Block',
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
                'issuedDate':
                {
                  'description': 'Issued Date Block',
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
                'expirationDate':
                {
                  'description': 'Expiration Date Block',
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
                'expirationDate',
              ],
              'properties':
              {
                'd': {'description': 'Attribute Section SAID', 'type': 'string'},
                'u': {'description': 'Attribute Section UE', 'type': 'string'},
                'i': {'description': 'Issuee SMAID SEDI Management AID', 'type': 'string'},
                'rd': {'description': 'Issuee Presentation Registry SAID', 'type': 'string'},
                'street':
                {
                  'description': 'Street Address Block',
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
                'city':
                {
                  'description': 'City Name Block',
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
                'county':
                {
                  'description': 'County Name Block',
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
                'state':
                {
                  'description': 'State Name Block',
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
                'postcode':
                {
                  'description': 'Postcode Block',
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
                'country':
                {
                  'description': 'Country Name Block',
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
                'issuedDate':
                {
                  'description': 'Issued Date Block',
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
                'expirationDate':
                {
                  'description': 'Expiration Date Block',
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
    assert  residenceSchemaSaid == 'EEgFNN1XH90koG5J5pbXKlRNU6TnibizaTQmJcRfEcop'
    SchemaValidator.check_schema(schema=mapper.mad)  # raises error if invalid format
    assert residenceSchemaSaid == ResidenceSchemaSaid
    assert mapper.mad == ResidenceSchema

    #assert mapper.mad == {}

    """done test"""


def test_core_identity():
    """Test core identity receipt and entitlement

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
    """
    kind = Kinds.json

    salt = b'sediacdcworksalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABzZWRpYWNkY3dvcmtzYWx0'  # CESR encoded

    # create signers, each contains siging key pair
    signers = salter.signers(count=10, transferable=True, temp=True)  # two per

    # create witness signers as nontransferable, each contains key pair
    walt = b'sediacdcworkwits'  # different salt for witness keys
    walter = Salter(raw=walt)
    wigners = walter.signers(count=5,transferable=False, temp=True)  # one per


    # Create Sue's AID (State Issuer) with single sig single wit inception event JSON
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


    # Setup Registries for Sue as Issuer
    # Create u field values for rip events
    ueraws = [b'sediacdcworkreg' + b'%0x'%(i, ) for i in range(8)]
    uens = [Noncer(raw=raw).qb64 for raw in ueraws]  # unique entropy nonce qb64
    # create shared secret salts for bup events
    ssraws = [b'sediacdcworkreg' + b'%0x'%(i, ) for i in range(8)]
    ssss = [Noncer(raw=raw).qb64 for raw in ssraws]  # shared secret salt qb64
    stamp = '2026-09-00T08:30:00.000000+00:00'

    # create registry serders for sue as Issuer
    regserders = [regcept(israid=sue, uuid=ue, stamp=stamp) for ue in uens]
    sueRids = [rss.said for rss in regserders]

    assert regserders[0].sad == \
    {
        'v': 'ACDCCAACAAJSONAADa.',
        't': 'rip',
        'd': 'ECvi_BgZw_Jp3qaVoNC-kOjW7X33i7fVQ0vIITy8Nfr5',
        'u': '0ABzZWRpYWNkY3dvcmtyZWcw',
        'i': 'EKBCU6u_xObNhFc9uuz1VdntNt99xmB2fA5qz7Li-Sl-',
        'n': '0',
        'dt': '2026-09-00T08:30:00.000000+00:00'
    }
    assert sueRids[0] == regserders[0].said == 'ECvi_BgZw_Jp3qaVoNC-kOjW7X33i7fVQ0vIITy8Nfr5'
    assert regserders[0].israid == sue
    assert regserders[0].nonce == uens[0]
    assert regserders[0].sner.num == 0
    assert regserders[0].stamp == stamp

    #create presentation registries for Guy and Gal
    salt = b'sedipresregisalt'  # base salt
    salter = Salter(raw=salt)
    preregUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(2)]
    regserders= [regcept(israid=guy, uuid=ue, stamp=stamp) for ue in preregUes]
    preRids = [rss.said for rss in regserders]
    assert preRids == ['ELVWDaNYJW8uOv-_D92PvlTO7Syyy2MH04q2wi7cd-zK',
                       'ELb9THYBfn68rUybNhAc-7ZHhJHSlfJ7WxNEN2zLAgtF']


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

    iarValidator = SchemaValidator(schema=IarSchema)  # create validator for proofing reciepts

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
    assert  guyIarMadSaid == 'EPYDIt6majjjR7saXuiBpPL8kWAQbtXN7Vge2fZp9zIf'
    iarValidator.validate(mapper.mad)  # raises error if invalid

    guyIarAttBareMad = \
    {
        "d": "",  # SAID
        "i": guy,  # citizens SEDI managment AID (SMAID)
        "givenName": "Guy",  # given name first name(s)
        "middleName":"Marty McFly",  # middle name(s) other names
        "familyName": "Brown",  # last name family name
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
    assert  guyIarAttMadSaid == 'EIAwt2gUPLL-BydfSx8ftkFrUk39G7seAm4l7DKLFFdl'

    assert guyIarAttMad == \
    {
        'd': guyIarAttMadSaid,
        'i': 'EDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JR',
        'givenName': 'Guy',
        'middleName': 'Marty McFly',
        'familyName': 'Brown',
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

    assert guySerderIar.sad['a'] == guyIarAttMad
    assert guySerderIar.said == 'EOmFbwu1YTdFJ4ltbA_Re3vahl0oaoKnHnQaTprGHJfX'
    assert guySerderIar.iseaid == guy
    assert guySerderIar.sad == \
    {
        'v': 'ACDCCAACAAJSONAALT.',
        't': 'acm',
        'd': guySerderIar.said,
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
    galAtc = Structor.enclose([Structor(crew=guyCsr)])  # CESR streamable attachment
    assert galAtc == bytearray(b'-TAXEDB8gKNwzurf33pV2hsyGR9XFOmitDhc0LUzDamcU2JRMAABEEmZ6nuPKuq8'
                               b'd2rY3DnQaPApFRPNTjXY4xZSlbCq1Iub')


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
    assert galIarAttMadSaid == 'EGrLfrJGwHHPVpHQMU2-bfzntCesFU_Q8rK7nbDBcTPz'
    assert galIarAttMad['i'] == gal

    galSerderIar = acdcmap(pat, uuid=galChallenge, schema=IarSchemaSaid,
                           attribute=galIarAttMad, kind=kind)
    iarValidator.validate(galSerderIar.sad)  # raises error if invalid

    assert galSerderIar.sad['a'] == galIarAttMad
    assert galSerderIar.said == 'EItXy59_XvP0VKOPJy3rQLtwob3fa6smQz9J7MAVUSZ0'
    assert galSerderIar.iseaid == gal

    assert galSerderIar.sad == \
    {
        'v': 'ACDCCAACAAJSONAALO.',
        't': 'acm',
        'd': galSerderIar.said,
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

    # Setup Utah State Sue issuer pretend delegation
    utahAgentAcdcSaid = Diger(ser=b"PretendUtahAgentAcdc").qb64
    assert utahAgentAcdcSaid == 'EE-Lz-snXwc5VCKOZSQGVXeCO0HfrpXLabNqYP9QWgj_'

    utahAgentSchemaSaid = Diger(ser=b"PretendUtahAgentSchema").qb64
    assert utahAgentSchemaSaid == 'EPclO424AuAiGqlvfCfzrgsCirXA2Rj6fg5vo4Wv3I4m'

    # Setup SEDI ACDC JsonSchema Validators
    # CoreSEDI ACDC setup
    coreValidator = SchemaValidator(schema=CoreSchema)  # create validator for core SEDI ACDCs

    # CoreSEDI ACDC setup
    residenceValidator = SchemaValidator(schema=ResidenceSchema)  # create validator for residence SEDI ACDCs

    # Guy and Gal have same residence
    street = "157 E 300 N"
    city = "Beaver"
    county = "Beaver"
    state = "Utah"
    postcode = "84713"
    country = "United States"


    # Setup Guy's SEDI ACDCs
    salt = b'guyscoresedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0ABndXlzY29yZXNlZGlzYWx0'  # CESR encoded
    guyUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(32)]
    assert guyUes == \
    [
        '0ABQNZNkD1y0W4mglDB4ei5Y',
        '0ACd8yXBMGBLNDwr-MMgtris',
        '0ADGYtYEzEdGpaq_sDXwamDm',
        '0ACEZIR6pk97xr2cy-gBdod4',
        '0ACUdqI4OVtXDL5BBO13QdrJ',
        '0ACXabyEAzJ1U-4qOek3adv5',
        '0ABR4UtpgSSmCSVF1eNJ6joz',
        '0ABqxMB1vXX4RL4tFUOLzn8y',
        '0AAvTJo84OMiipKf_90mn7bZ',
        '0ACqPN2zhcII6TVGRKYC1ckJ',
        '0AAfMYErqhjBCf4cgG5huzT2',
        '0AADjz761fupJiCvj4GWFBfg',
        '0AAsHaHfgfNEaRuRwI1Y77ry',
        '0ABZHwn29_HgPlO7tRDEONUK',
        '0AA2UPIBJ6WKRMVk_xgeHpSd',
        '0AC2TvvDIyT60xBlRG9CjFI9',
        '0AARGwC82gXbtRbQXs4cGBpC',
        '0ACkFgtF3ee459teQu6OJBRc',
        '0AC9HltcQYMY0fjn-9zQftZW',
        '0AAkcR_gzffjPL-mrjiJg9rv',
        '0AAuZ1oTBZ6jqFp8Z7UrpKJs',
        '0ABCJgPmvnyuDB_Bj34sb7ec',
        '0ADYpt736nc2ZcVYFJDImwuy',
        '0ACbDaiZmKZcyZLHmfVLpJYQ',
        '0AA-hoK5ewZYxB5hXEMwxq5X',
        '0ACyPy93wKHIWAvzu92ooj2c',
        '0AAYbJl5lc9BwGOLiIaQVWQ8',
        '0ACd7KIJHwn_s5kNHDqmQg8t',
        '0ABQe9skiMkZBj86zvt6gtCY',
        '0ACnZNwFbDOLXr65EDNIE--9',
        '0ADwRPjDS8n94le48SRUTPZn',
        '0ABnfpH75cVvRDh0giU6e1mn'
    ]

    # Setup Guy's Core SEDI

    guyImageProof = Diger(ser=b"PretendImageOfGuy").qb64
    assert guyImageProof == 'EIQw_2CqmmC96YYUFXTW8XSkLQU2-v9bDCyItazmKhTW'

    # Guy core SEDI attribution section

    guyCoreAttBareMad = \
    {
        "d": "",
        "u": guyUes[1],
        "i": guy,  #guySMAID
        "rd": preRids[0],
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
        "birthDate": \
        {
            "d": "",
            "u": guyUes[5],
            "value": "2002-08-22T00:00:00.000000+00:00", # time MBZ
        },
        "facialImageProof": \
        {
            "d": "",
            "u": guyUes[6],
            "value": guyImageProof,  # Digest of image, actual image is attached as blindable typed media block
        },
        "legalPresenceStatus": \
        {
            "d": "",
            "u": guyUes[7],
            "value": "citizen",
        },
        "issuedDate": \
        {
            "d": "",
            "u":  guyUes[8],
            "value": "2020-08-22T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  guyUes[9],
            "value": "2028-09-01T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=guyCoreAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyCoreAttMad = compactor.partials[('.givenName',
                                        '.middleName',
                                        '.familyName',
                                        '.birthDate',
                                        '.facialImageProof',
                                        '.legalPresenceStatus',
                                        '.issuedDate',
                                        '.expirationDate')].mad
    assert guyCoreAttMad['i'] == guy
    guyCoreAttMadSaid = compactor.said
    assert  guyCoreAttMadSaid == 'EDuCEY2WL4SG9D3VHvXjR75Rm0P4Gt-glmnWEMaKWUBn'

    assert guyCoreAttMad == \
    {
        'd': guyCoreAttMadSaid,
        'u': guyUes[1],
        'i': guy,
        "rd": preRids[0],
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
        'birthDate':
        {
            'd': 'EDUdjMw1pCajy659N-qjP_U1Gyop1O78XVUtb6l2ON6A',
            'u': guyUes[5],
            'value': '2002-08-22T00:00:00.000000+00:00'
        },
        'facialImageProof':
        {
            'd': 'EOR1f3q1BbCvhUqrpQjzwY-3sFlklrYyqAZQ-E8L_Lze',
            'u': guyUes[6],
            'value': guyImageProof
        },
        'legalPresenceStatus':
        {
            'd': 'EIi_fYQJ6O__ncYIv3iiq-AHpkcJdxo6R6m142RNEJaq',
            'u': guyUes[7],
            'value': 'citizen'
        },
        'issuedDate':
        {
            'd': 'EHZyg34ZYUOj9GxL0kCJtjrKj7a7IT3LZYl1Oh8fhIVV',
            'u': guyUes[8],
            'value': '2020-08-22T00:00:00.000000+00:00'
        },
        'expirationDate':
        {
            'd': 'ELmeEY75YqosieinUUN0NesC_v_2Zt5eYGMvRgyuHWTw',
            'u': guyUes[9],
            'value': '2028-09-01T00:00:00.000000+00:00'
        }
    }



    guyCoreEdgeBareMad = \
    {
        "d": "",
        "u": guyUes[10],
        "utahAgent":
        {
            "d": "",
            "u": guyUes[11],
            "n": utahAgentAcdcSaid,
            "s": utahAgentSchemaSaid,
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=guyCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    guyCoreEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert guyCoreEdgeMad == \
    {
        'd': 'EDi37yTAxh7v3J6QlLG1ZQDnDASUgrIWo3kg5BOYzwA-',
        'u': guyUes[10],
        'utahAgent':
        {
            'd': 'EB1aIgsOBz7V55G7gfoehU0G9SipPihYS_iSQ12pYZAM',
            'u': guyUes[11],
            'n': utahAgentAcdcSaid,
            's': utahAgentSchemaSaid,
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
    assert guyCoreSediSaid == 'EOU6bsr-dpy37kzCj7OsNu28pxbqXnnriH_UyXKiFVfw'
    assert guySerderCore.verstr == 'ACDCCAACAAJSONAAdP.'
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
            "rd": preRids[0],
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
            'birthDate':
            {
                'd': 'EDUdjMw1pCajy659N-qjP_U1Gyop1O78XVUtb6l2ON6A',
                'u': guyUes[5],
                'value': '2002-08-22T00:00:00.000000+00:00'
            },
            'facialImageProof':
            {
                'd': 'EOR1f3q1BbCvhUqrpQjzwY-3sFlklrYyqAZQ-E8L_Lze',
                'u':  guyUes[6],
                'value': guyImageProof
            },
            'legalPresenceStatus':
            {
                'd': 'EIi_fYQJ6O__ncYIv3iiq-AHpkcJdxo6R6m142RNEJaq',
                'u': guyUes[7],
                'value': 'citizen'
            },
            'issuedDate':
            {
                'd': 'EHZyg34ZYUOj9GxL0kCJtjrKj7a7IT3LZYl1Oh8fhIVV',
                'u': guyUes[8],
                'value': '2020-08-22T00:00:00.000000+00:00'
            },
            'expirationDate':
            {
                'd': 'ELmeEY75YqosieinUUN0NesC_v_2Zt5eYGMvRgyuHWTw',
                'u': guyUes[9],
                'value': '2028-09-01T00:00:00.000000+00:00'
            }
        },
        'e':
        {
            'd': 'EDi37yTAxh7v3J6QlLG1ZQDnDASUgrIWo3kg5BOYzwA-',
            'u': guyUes[10],
            'utahAgent':
            {
                'd': 'EB1aIgsOBz7V55G7gfoehU0G9SipPihYS_iSQ12pYZAM',
                'u': guyUes[11],
                'n': utahAgentAcdcSaid,
                's': utahAgentSchemaSaid,
                'o': 'I2I',
            }
        },
        'r':
        {
            'd': 'EFPxq4WPl29szUqbrQIviOh_Ls_RlrYbp4L-fdQH0XrX',
            'l': ''
        }
    }

    # Guy residence SEDI attribution section
    guyResidenceAttBareMad = \
    {
        "d": "",
        "u": guyUes[12],
        "i": guy,  #guySMAID
        "rd": preRids[0],
        "street": \
        {
            "d": "",
            "u": guyUes[13],
            "value": street,
        },
        "city": \
        {
            "d": "",
            "u": guyUes[14],
            "value": city,
        },
        "county": \
        {
            "d": "",
            "u":guyUes[15],
            "value": county,
        },
        "state": \
        {
            "d": "",
            "u": guyUes[16],
            "value": state,
        },
        "postcode": \
        {
            "d": "",
            "u": guyUes[17],
            "value": postcode,
        },
        "country": \
        {
            "d": "",
            "u": guyUes[18],
            "value": country,
        },
        "issuedDate": \
        {
            "d": "",
            "u":  guyUes[19],
            "value": "2020-08-22T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  guyUes[20],
            "value": "2028-09-01T00:00:00.000000+00:00",  # Time MBZ
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
                                             '.issuedDate',
                                             '.expirationDate')].mad
    assert guyResidenceAttMad['i'] == guy
    guyResidenceAttMadSaid = compactor.said
    assert  guyResidenceAttMadSaid == 'EB26AGZ37bqlhrITXZOdOv1uRXy1ObL0yH7qcTTZTdfH'
    assert guyResidenceAttMad == \
    {
        'd': guyResidenceAttMadSaid,
        'u': guyUes[12],
        'i': guy,
        "rd": preRids[0],
        'street':
        {
            'd': 'EGsUp891O6-4MNUHidQcMd0rEwMvXPl9j8RXZm1fxV26',
            'u': guyUes[13],
            'value': street
        },
        'city':
        {
            'd': 'EPeSuhVXJm-pZzUaheFb91rE9Htr74o0SpL9jXfRsSa6',
            'u': guyUes[14],
            'value': city
        },
        'county':
        {
            'd': 'EIWG8UUJR7B59VrrUJiEJpz6cv2b4YEqqdqkHec-VK_d',
            'u': guyUes[15],
            'value': county
        },
        'state':
        {
            'd': 'EGJVpQ7UmB-LTuyWvov0VPZAbpPq1WQlRbNDqnKt2X64',
            'u': guyUes[16],
            'value': state
        },
        'postcode':
        {
            'd': 'ELaDD30J_a7pTBQtJCjypNQrwr6CYYfFCdpYMSEvGCOS',
            'u': guyUes[17],
            'value': postcode
        },
        'country':
        {
            'd': 'EBQsX5dyXYrHv9Q8bwYWv9fWnfV2nXOu0c_phP5TeKrf',
            'u': guyUes[18],
            'value': country
        },
        'issuedDate':
        {
            'd': 'EPI60lT-lOu-ZQDD8iP05WSjk6APGdwCUh-jR3o_af9r',
            'u': guyUes[19],
            'value': '2020-08-22T00:00:00.000000+00:00'
        },
        'expirationDate':
        {
            'd': 'ED9FMy1sPHpNdZ0-6jjFkzyrnjqTgEnTC5DjUo3heYOv',
            'u': guyUes[20],
            'value': '2028-09-01T00:00:00.000000+00:00'
        }
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
        'd': 'EBasMP58YRfoZ_RE6nzX7iM43hqDO-4ewDOptoUBClXj',
        'u': guyUes[21],
        'coreIdentity':
        {
            'd': 'EO7sXLuQLUDr6eVIyjAj4Psk_JocU0Iuf_ONzeDIKm1D',
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
    assert guyResidenceSediSaid == 'EEWFX2LFhixIf6Jyxypr1xIv7G3Xni27Wa_z6jl1dakf'
    assert guySerderResidence.verstr == 'ACDCCAACAAJSONAAb9.'
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



    # Setup Gal's SEDI ACDCs

    salt = b'galscoresedisalt'  # base salt
    salter = Salter(raw=salt)
    assert salter.qb64 =='0ABnYWxzY29yZXNlZGlzYWx0'  # CESR encoded
    galUes = [ Noncer(raw=salter.stretch(size=16, path=f'{i:x}', temp=True)).qb64
                                                             for i in range(32)]
    assert galUes == \
    [
        '0AAgHaUeg5Pvr7KQMPBeYfIs',
        '0ADkNrf84O_sw7WGXVMSkFWh',
        '0AAe7cgRQjYZAcd0TVbjIxM-',
        '0AAEbE87_XRwLHjbvj16wKqX',
        '0AAa6B2FyXtFiWpXFbJrMg3n',
        '0ABDbo5XZIfCSAsfTVl9jZfF',
        '0ADXx6eI6thDHeHaKi9vWVaj',
        '0AAUr_yhAHP31X1ZHOwUJE1z',
        '0AAsG7_ogfBljU-7OuuYg8eG',
        '0ADyZipGvcuOxw1ChYws3pig',
        '0ACDMVtW0LTB2zvojqA3idZS',
        '0ADPO0qUnzzehhLuLlOE104a',
        '0AChBh2pZwiOkTy675JP3L-f',
        '0AC9zE_ETWdeUUs3yP9kkJ0F',
        '0AA5ZKSBfBOgjiWeqCoCu1V5',
        '0ABbhr2o_M834GMWCYngZC3s',
        '0ABlOWnun7rNDUmzXlIk0OEe',
        '0ADhxScWmTYdq8FrNGvcrYpZ',
        '0AAnwG5mRUe5Et7RQ2TTUUEK',
        '0ADQrYfARrpfPhWdHuz_gHPX',
        '0ADGmcRPXhfi5kG6oQdU4fHW',
        '0AADKjTvIy2bbrS-lXyI9VCS',
        '0ACK5s1TfhDkVlr64Pg1gDl1',
        '0AC2exiiWkYKfrZwUycP4SY9',
        '0AAp2vdhFdWTt9O4E6Wi98VT',
        '0ACjsqsuL-DOKmxTaJ7txUuZ',
        '0ACJEGGAO0WbfqWL0QgHfjfS',
        '0AABy0qynv8r9j8TVlm0E3Eb',
        '0ADdsSxYps95HI5ZD9s6gQH0',
        '0AA2XQraY1bu2gNAuP1TepSL',
        '0AAe0fk7QDnX230fu_jsGYY4',
        '0AArNPcT5h05Wxm0SUKpeL9O'
    ]

    # Setup Gal's Core SEDI

    galImageProof = Diger(ser=b"PretendImageOfGal").qb64
    assert galImageProof == 'EGh8sVJumVosTZVgT95YAb0Vor_7JRKGjgCX_2C7I9h4'

    # Guy core SEDI attribution section

    galCoreAttBareMad = \
    {
        "d": "",
        "u": galUes[1],
        "i": gal,  #galSMAID
        "rd": preRids[1],
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
        "birthDate": \
        {
            "d": "",
            "u": galUes[5],
            "value": "2002-11-01T00:00:00.000000+00:00", # time MBZ
        },
        "facialImageProof": \
        {
            "d": "",
            "u": galUes[6],
            "value": galImageProof,  # Digest of image, actual image is attached as blindable typed media block
        },
        "legalPresenceStatus": \
        {
            "d": "",
            "u": galUes[7],
            "value": "citizen",
        },
        "issuedDate": \
        {
            "d": "",
            "u":  galUes[8],
            "value": "2020-08-23T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  galUes[9],
            "value": "2028-09-01T00:00:00.000000+00:00",  # Time MBZ
        },
    }

    compactor = Compactor(mad=galCoreAttBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galCoreAttMad = compactor.partials[('.givenName',
                                        '.middleName',
                                        '.familyName',
                                        '.birthDate',
                                        '.facialImageProof',
                                        '.legalPresenceStatus',
                                        '.issuedDate',
                                        '.expirationDate')].mad
    assert galCoreAttMad['i'] == gal
    galCoreAttMadSaid = compactor.said
    assert  galCoreAttMadSaid == 'EMGjZ6llanUn4qvbPsKb8uuAnFKRbST6HLJvyJU8lGyL'

    assert galCoreAttMad == \
    {
        'd': galCoreAttMadSaid,
        'u': galUes[1],
        'i': gal,
        "rd": preRids[1],
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
        'birthDate':
        {
            'd': 'ENQsc69ZFy98phXDEUf-1Yla6_A552IncAFq2PfBdfNl',
            'u': galUes[5],
            'value': '2002-11-01T00:00:00.000000+00:00'
        },
        'facialImageProof':
        {
            'd': 'EJ8CEbesqYDG-bOwRl5HAqG95j6iRfToyy4zN0eOu-bd',
            'u': galUes[6],
            'value': galImageProof
        },
        'legalPresenceStatus':
        {
            'd': 'EFEdNqUWOPWxEUs-69ivD5-a9UqiIB4EFwqilxySgdXI',
            'u': galUes[7],
            'value': 'citizen'
        },
        'issuedDate':
        {
            'd': 'ENq03um401R8-ibfRahqDK8RAgQ-nGsRNRx7junPdI3n',
            'u':  galUes[8],
            'value': '2020-08-23T00:00:00.000000+00:00'
        },
        'expirationDate':
        {
            'd': 'EHuL7LKe05akEiBiffEmnmGP-stq3m544EEzOTReczsU',
            'u':  galUes[9],
            'value': '2028-09-01T00:00:00.000000+00:00'
        }
    }


    galCoreEdgeBareMad = \
    {
        "d": "",
        "u": galUes[10],
        "utahAgent":
        {
            "d": "",
            "u": galUes[11],
            "n": utahAgentAcdcSaid,
            "s": utahAgentSchemaSaid,
            "o": "I2I",
        },
    }
    compactor = Compactor(mad=galCoreEdgeBareMad, makify=True, compactify=True,
                       saidive=True, kind=kind)
    galCoreEdgeMad = compactor.partials[('.utahAgent',)].mad
    assert galCoreEdgeMad == \
    {
        'd': 'EFo3AP78OKOKlJW4HPEDRzhguEzHfENcc7x3e2j8THVw',
        'u': galUes[10],
        'utahAgent':
        {
            'd': 'ELP543GOl0bB3LLDJ0sOjySSWsFD2LBXhHfmugU4Juf_',
            'u': galUes[11],
            'n': utahAgentAcdcSaid,
            's': utahAgentSchemaSaid,
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
    assert galCoreSediSaid == 'EOEsu3Gr3PLe6Zy71DK7I3NSWrS1TM21-Odsny0u8fG8'
    assert galSerderCore.verstr == 'ACDCCAACAAJSONAAdK.'
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
        "u": galUes[12],
        "i": gal,  #galSMAID
        "rd": preRids[1],
        "street": \
        {
            "d": "",
            "u": galUes[13],
            "value": street,
        },
        "city": \
        {
            "d": "",
            "u": galUes[14],
            "value": city,
        },
        "county": \
        {
            "d": "",
            "u":galUes[15],
            "value": county,
        },
        "state": \
        {
            "d": "",
            "u": galUes[16],
            "value": state,
        },
        "postcode": \
        {
            "d": "",
            "u": galUes[17],
            "value": postcode,
        },
        "country": \
        {
            "d": "",
            "u": galUes[18],
            "value": country,
        },
        "issuedDate": \
        {
            "d": "",
            "u":  galUes[19],
            "value": "2020-08-25T00:00:00.000000+00:00",  # Time MBZ
        },
        "expirationDate": \
        {
            "d": "",
            "u":  galUes[20],
            "value": "2028-09-01T00:00:00.000000+00:00",  # Time MBZ
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
                                             '.issuedDate',
                                             '.expirationDate')].mad
    assert galResidenceAttMad['i'] == gal
    galResidenceAttMadSaid = compactor.said
    assert  galResidenceAttMadSaid == 'EAt6GhtQyN2IeK1z7yKUtFQKIwkkDzxlyMTMs9qcRUQK'
    assert galResidenceAttMad == \
    {
        'd': galResidenceAttMadSaid,
        'u': galUes[12],
        'i': gal,
        "rd": preRids[1],
        'street':
        {
            'd': 'EGafF9qZ2aSpOT5MFQM0pAXbWMWz9chkOiDd9h1K4BR5',
            'u': galUes[13],
            'value': street
        },
        'city':
        {
            'd': 'EPTnbnIR-JG5bv07K3AoQq76h6nArqgys9tDRH8G1lS7',
            'u': galUes[14],
            'value': city
        },
        'county':
        {
            'd': 'EEzJ051463te5YuuQts3VpT7Lds5iePs3B-JgBjsDV03',
            'u': galUes[15],
            'value': county
        },
        'state':
        {
            'd': 'EI96-7qnveO8SRXBg0WYq-TUfmDnnimuipT1pJvSYxA-',
            'u': galUes[16],
            'value': state
        },
        'postcode':
        {
            'd': 'EDPCBkSS9O9CW46JMpuw1ADzgRmCAvc_KoeaF45-OTCs',
            'u': galUes[17],
            'value': postcode
        },
        'country':
        {
            'd': 'ECJY95wUXqYVVnn_hLdmO6ld3oIRFozvBYXQG5o5jxTd',
            'u': galUes[18],
            'value': country
        },
        'issuedDate':
        {
            'd': 'EMbgVrmOzOpWwc_EuiRdFuHdph55UVlp4N44zz2NpGm3',
            'u': galUes[19],
            'value': '2020-08-25T00:00:00.000000+00:00'
        },
        'expirationDate':
        {
            'd': 'EJ7Eanv7E47CmQG8UoKlrjAw6GU7PHZD68OaSuQfsjDf',
            'u': galUes[20],
            'value': '2028-09-01T00:00:00.000000+00:00'
        }
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
        'd': 'EJeVXBnxv29ORQUqOMUMhrWy6WoFfqCmUv4W-_RB2aBi',
        'u': galUes[21],
        'coreIdentity':
        {
            'd': 'EF8aMQP59vykeJkgq8Y4-l5HDVkY9DXkyOxkI3YVRy0T',
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
    assert galResidenceSediSaid == 'ECxSLBUg2vKUGOuMrMqHXpDdyLzvTkZbHP8b5xF8MXYc'
    assert galSerderResidence.verstr == 'ACDCCAACAAJSONAAb9.'
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



    """Done Test"""



if __name__ == "__main__":
    test_sedi_schema()
    test_core_identity()
