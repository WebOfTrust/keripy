# -*- coding: utf-8 -*-
"""
tests.spec.cesr.test_cesr_example module

"""
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
import json

import pytest

from ordered_set import OrderedSet as oset

from keri import Vrsn_2_0, Kinds, Protocols, Ilks, TraitDex
from keri.core import (MtrDex, Salter, Signer, Diger, Noncer, Number, Structor,
                       SealEvent, SealSource, Counter, Codens, Seqner, Pather)
from keri.core import (incept, interact, rotate, delcept, deltate, receipt,
                       query, reply, prod, bare, exchept, exchange)
from keri.vc import acdcmap

def test_cesr_examples():
    """ Working examples for CESR specification """

    # Trans Indexed Sig Group
    # Ean inception taken from keri examples
    raw = (b'{"v":"KERICAACAAJSONAAKp.","t":"icp","d":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXj'
                        b'BUcMVtvhmB","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","s":"0","kt":'
                        b'"2","k":["DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu","DG-YwInLUxzVDD5z8Sq'
                        b'ZmS2FppXSB-ZX_f2bJC_ZnsM5","DGIAk2jkC3xuLIe-DI9rcA0naevtZiKuU9wz91L_qBAV"],"'
                        b'nt":"2","n":["ELeFYMmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB","ENY9GYShOjeh7qZ'
                        b'UpIipKRHgrWcoR2WkJ7Wgj4wZx1YT","EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG'
                        b'"],"bt":"3","b":["BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","BJfueFAYc7N'
                        b'_V-zmDEn2SPCoVFx3H20alWsNZKgsS1vt","BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V'
                        b'22aH","BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],"c":["DID"],"a":[]}')

    pre = 'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB'
    said = 'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB'
    snh = '0'

    salt = b'kerispecworkexam'  # for example
    salter = Salter(raw=salt)
    assert salter.qb64 == '0ABrZXJpc3BlY3dvcmtleGFt'  # CESR encoded for example

    # create set of signers each with private signing key and trans public
    # verification key
    signers = salter.signers(count=3, transferable=True, temp=True)

    msgs = bytearray()
    buf = bytearray()
    sigs = bytearray()

    buf.extend(pre.encode())
    buf.extend(Seqner(snh=snh).qb64b)
    buf.extend(said.encode())

    for i, signer in enumerate(signers):
        siger = signer.sign(raw, index=i)  # return siger
        sigs.extend(siger.qb64b)

    buf.extend(Counter.enclose(qb64=sigs, code=Codens.ControllerIdxSigs))
    msgs.extend(Counter.enclose(qb64=buf, code=Codens.TransIdxSigGroups))

    assert msgs == bytearray(b'-XBfEPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB0AAAAAAAAAAAAAAA'
          b'AAAAAAAAEPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB-KBCAADQ-rNV'
          b'53XEXW1mI24X6uK3LlSMxqQxzM3HuWv_rbEkGP8kVjEYjzrBg8o5hRCxXPnoO2zp'
          b'Hmh52OdUdog7xb0BABCD_iSjAJvu9JsXHBAnCCTGCA-YSTKiRG-y6gUV42tzkL11'
          b'OSEqRztXZOq4yCBHcf4WTPT8fsMoaJGbW1a5JFkPACBcPS0C_QwGdJUZTKXvC_qC'
          b's6069pqV8rdQymrJTdcmJAEYJDJXuHUc6sjgdb0_VlPYIPtVZ9ypbRhkkuXJOykL')

    # Said computation
    field0 = "field_0_01234567"
    assert len(field0) == 16
    field1 = "field_1_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    assert len(field1) == 44
    field2 = "field_2_98765432"
    assert len(field2) == 16

    dummy = "#" * 44
    assert len(dummy) == 44

    ser = field0 + field1 + field2
    assert len(ser) == 16 + 44 + 16 == 76
    assert ser == 'field_0_01234567field_1_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789field_2_98765432'

    dser = field0 + dummy + field2
    assert len(dser) == len(ser) == 76
    assert dser == 'field_0_01234567############################################field_2_98765432'

    dig = Diger(ser=dser.encode()).qb64
    assert dig == 'ENI2bDYghiu1KYYkFrPofH8tJ5tNiNt8WrTIc4s_5IIH'

    cser = field0 + dig + field2
    assert len(cser) == len(dser) == 76
    assert cser == 'field_0_01234567ENI2bDYghiu1KYYkFrPofH8tJ5tNiNt8WrTIc4s_5IIHfield_2_98765432'


    # SAID computation for dict
    d = \
    {
        "said": "",
        "first": "Sue",
        "last": "Smith",
        "role": "Founder"
    }

    dummy = '#' * 44

    dd = dict(said=dummy, first="Sue", last="Smith", role="Founder")
    assert dd == \
    {
        "said": "############################################",
        "first": "Sue",
        "last": "Smith",
        "role": "Founder"
    }

    raw = json.dumps(dd, separators=(",", ":"), ensure_ascii=False).encode()
    assert raw == b'{"said":"############################################","first":"Sue","last":"Smith","role":"Founder"}'

    said = Diger(ser=raw).qb64
    assert said == 'EJymtAC4piy_HkHWRs4JSRv0sb53MZJr8BQ4SMixXIVJ'

    sd = dict(said=said, first="Sue", last="Smith", role="Founder")
    assert sd == \
    {
        'said': 'EJymtAC4piy_HkHWRs4JSRv0sb53MZJr8BQ4SMixXIVJ',
        'first': 'Sue',
        'last': 'Smith',
        'role': 'Founder'
    }

    # JSON Schema Example SAID
    dschema =  \
    {
        "$id": "############################################",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "full_name": {
                "type": "string"
            }
        }
    }

    assert dschema == \
    {
        '$id': '############################################',
        '$schema': 'http://json-schema.org/draft-07/schema#',
        'type': 'object',
        'properties':
        {
            'full_name': {'type': 'string'}
        }
    }

    raw = json.dumps(dschema, separators=(",", ":"), ensure_ascii=False).encode()
    assert raw == (b'{"$id":"############################################","$schema":"http://json'
                    b'-schema.org/draft-07/schema#","type":"object","properties":{"full_name":{"ty'
                    b'pe":"string"}}}')

    said = Diger(ser=raw).qb64
    assert said == 'EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW'

    dschema["$id"] = said

    assert dschema == \
    {
        "$id": "EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties":
        {
            "full_name": {"type": "string"}
        }
    }

    """Done Test"""

    # Sad path
    ean = 'EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB'
    amy = "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
    bob = "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
    cal = "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"
    deb = "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"
    schema = 'EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW'

    paths = \
    [
      {
        "ref0": {
          "name": "Amy",
          "i": amy
        }
      },
      {
        "ref1": {
          "name": "Bob",
          "i": bob
        }
      }
    ]

    attribute = \
    {
        "d": "",
        "i": cal,
        "dt": "2025-06-09T17:35:54.169967+00:00",
        "personal":
        {
            "name": "John Doe",
            "home": "Atlanta",
        },
        "p": paths,
    }



    serder = acdcmap(issuer=deb, schema=schema, attribute=attribute, issuee=cal, compactify=True)
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAADx.',
        't': 'acm',
        'd': 'EO3117lnAbjDt66qe2PtgHooXKAYQT_C6SIbESMcJ5lN',
        'i': 'EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW',
        's': 'EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW',
        'a': 'ED1wMKzV72L7YI1yJ3NXlClPUgvEerw4jRocOYxaZGtH'
    }

    attribute = \
    {
        "d": 'ED1wMKzV72L7YI1yJ3NXlClPUgvEerw4jRocOYxaZGtH',
        "i": cal,
        "dt": "2025-06-09T17:35:54.169967+00:00",
        "personal":
        {
            "name": "John Doe",
            "home": "Atlanta",
        },
        "p": paths,
    }

    serder = acdcmap(issuer=deb, schema=schema, attribute=attribute, issuee=cal)
    assert serder.sad == \
    {
        "v": "ACDCCAACAAJSONAAIe.",
        "t": "acm",
        "d": "EO3117lnAbjDt66qe2PtgHooXKAYQT_C6SIbESMcJ5lN",
        "i": "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW",
        "s": "EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW",
        "a":
        {
            "d": "ED1wMKzV72L7YI1yJ3NXlClPUgvEerw4jRocOYxaZGtH",
            "i": "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT",
            "dt": "2025-06-09T17:35:54.169967+00:00",
            "personal":
            {
                "name": "John Doe",
                "home": "Atlanta"
            },
            "p":
            [
                {
                    "ref0":
                    {
                        "name": "Amy",
                        "i": "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"
                    }
                },
                {
                    "ref1":
                    {
                        "name": "Bob",
                        "i": "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"
                    }
                }
            ]
        }
    }

    sad = serder.sad

    path = '-'
    pather = Pather(path=path)
    assert pather.qb64 == '6AABAAA-'
    assert pather.resolve(sad=sad) == sad

    path = '-a-personal'
    pather = Pather(path=path)
    assert pather.qb64 == '4AADA-a-personal'
    assert pather.resolve(sad=sad) == {'name': 'John Doe', 'home': 'Atlanta'}

    path = '-5-3'
    pather = Pather(path=path)
    assert pather.qb64 == '4AAB-5-3'
    assert pather.resolve(sad=sad) == {'name': 'John Doe', 'home': 'Atlanta'}

    path = '-5-3-name'
    pather = Pather(path=path)
    assert pather.qb64 == '6AADAAA-5-3-name'
    assert pather.resolve(sad=sad) == 'John Doe'

    path = '-a-personal-1'
    pather = Pather(path=path)
    assert pather.qb64 == '6AAEAAA-a-personal-1'
    assert pather.resolve(sad=sad) == 'Atlanta'

    path = '-a-p-1-0'
    pather = Pather(path=path)
    assert pather.qb64 == '4AAC-a-p-1-0'
    assert pather.resolve(sad=sad) == {'name': 'Bob', 'i': 'ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf'}

    path = '-a-p-0-0-name'
    pather = Pather(path=path)
    assert pather.qb64 == '6AAEAAA-a-p-0-0-name'
    assert pather.resolve(sad=sad) == 'Amy'

    path = '-a-p-0-ref0-i'
    pather = Pather(path=path)
    assert pather.qb64 == '6AAEAAA-a-p-0-ref0-i'
    assert pather.resolve(sad=sad) == 'ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz'


    """Done Test"""




if __name__ == "__main__":
    test_cesr_examples()

