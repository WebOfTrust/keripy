# -*- coding: utf-8 -*-
"""
tests.sedi.test_sedi module

"""
import json
import os
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pytest

from jsonschema import Draft202012Validator

from keri import Vrsn_2_0, Kinds, Protocols, Ilks


def test_core_identity():
    """Test core identity recipt and entitlement """

    ialMad = \
    {
        "v": "",
        "t": "acm",
        "d": "",
        "u": "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux",  # challenge
        "i": "ProofingAgentAID",
        "rd": "",
        "s": "",
        "a":
        {
            "d": "",
            "i": "CitizenSMAID",

            "firstName": "John",
            "middleName":"Henry Davis",
            "lastName": "Smith",
            "premarriedLastName": "",
            "dateOfBirth": "2020-08-22T17:50:09.988921+00:00",
            "placeOfBirth": \
            {
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "country": "United States",
            },
            "legalPresence": "TBD",
            "sexAtBirth": "Male",
            "facialBiometric": "",
            "digitizedSignature": "",
            "dateOfProofing": "2020-08-22T17:50:09.988921+00:00",
            "url": "uniquerequesturlforseditimelimited",
        }
    }

    coreMad = \
    {
        "v": "",
        "t": "acm",
        "d": "",
        "u": "",
        "i": "StateIssuerAID",
        "rd": "",
        "s": "",
        "a":
        {
            "d": "",
            "u": "",
            "i": "CitizenSEDI_AID",
            "given": \
            {
                "d": "",
                "u": "",
                "value": "John",
            },
            "middle": \
            {
                "d": "",
                "u": "",
                "value": "Henry Davis",
            },
            "surname": \
            {
                "d": "",
                "u": "",
                "value": "Smith",
            },
            "premarried": \
            {
                "d": "",
                "u": "",
                "value": "",
            },
            "dateOfBirth": \
            {
                "d": "",
                "u": "",
                "value": "2020-08-22T17:00:00.000000+00:00",
            },
            "placeOfBirth": \
            {
                "d": "",
                "u": "",
                "city": "Beaver",
                "county": "Beaver",
                "state": "Utah",
                "country": "United States",
            },
            "legalPresence": \
            {
                "d": "",
                "u": "",
                "value": "TBD",
            },
            "sexAtBirth": \
            {
                "d": "",
                "u": "",
                "value": "Male",
            },
            "facialBiometric": \
            {
                "d": "",
                "u": "",
                "value": "",
            },
            "digitizedSignature": \
            {
                "d": "",
                "u": "",
                "value": "",
            },
            "dateOfIssuance": \
            {
                "d": "",
                "u": "",
                "value": "2020-08-22T17:00:00.000000+00:00",
            },
            "dateOfExpiration": \
            {
                "d": "",
                "u": "",
                "value": "2020-08-22T17:00:00.000000+00:00",
            },
        },
        "r":
        {
            "d": "",
            "l": ""
        }
    }

    """Done Test"""



if __name__ == "__main__":
    test_core_identity()
