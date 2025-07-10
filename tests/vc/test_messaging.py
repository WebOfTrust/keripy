# -*- encoding: utf-8 -*-
"""
tests.vc.test_messaging module

"""

import pytest

from keri.kering import Protocols, Kinds, Ilks, Vrsn_2_0
from keri.vc.messaging import (regcept, blindate, update, actSchemaDefault,
                               attribute, classic)
from keri.core import GenDex, Noncer, SerderACDC, BlindState, Blinder, Compactor

def test_regcept_message():
    """Test regcept message"""
    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    uuid = '0AAxyHwW6htOZ_rANOaZb2N2'
    stamp = '2020-08-22T17:50:09.988921+00:00'
    said = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'

    # test default kind JSON
    serder = regcept(issuer=issuer, uuid=uuid, stamp=stamp)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json

    assert serder.ilk == Ilks.rip
    assert serder.said == said
    assert serder.uuid == uuid
    assert serder.issuer == issuer
    assert serder.stamp == stamp


    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAADa.',
        't': 'rip',
        'd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        'u': '0AAxyHwW6htOZ_rANOaZb2N2',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'n': '0',
        'dt': '2020-08-22T17:50:09.988921+00:00'
    }

    assert serder.raw == (b'{"v":"ACDCCAACAAJSONAADa.","t":"rip","d":"EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhip'
                        b'wgaoCdK_Wq","u":"0AAxyHwW6htOZ_rANOaZb2N2","i":"EA2X8Lfrl9lZbCGz8cfKIvM_cqLy'
                        b'TYVLSFLhnttezlzQ","n":"0","dt":"2020-08-22T17:50:09.988921+00:00"}')

    # Test CESR
    said = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    serder = regcept(issuer=issuer, uuid=uuid, stamp=stamp, kind=Kinds.cesr)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.rip
    assert serder.said == said
    assert serder.uuid == uuid
    assert serder.issuer == issuer
    assert serder.stamp == stamp

    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAACs.',
        't': 'rip',
        'd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'u': '0AAxyHwW6htOZ_rANOaZb2N2',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'n': '0',
        'dt': '2020-08-22T17:50:09.988921+00:00'
    }

    assert serder.raw == (b'-FAq0OACDCCAACAAXripEM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR80AAxyHwW6htO'
                          b'Z_rANOaZb2N2EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQMAAA1AAG2020-08-22T1'
                          b'7c50c09d988921p00c00')

    # test Serder inhale from raw roundtripped
    sad = serder.sad
    rawcesr = serder.raw

    serder = SerderACDC(raw=rawcesr)
    assert serder.sad == sad
    assert serder.raw == rawcesr

    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.rip
    assert serder.said == said
    assert serder.uuid == uuid
    assert serder.issuer == issuer
    assert serder.stamp == stamp
    """Done Test"""


def test_blindate_message():
    """Test blindate message"""
    uuid = 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
    tsaid = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
    tstate = 'issued'
    crew = BlindState(d='', u=uuid, td=tsaid, ts=tstate)
    blinder = Blinder(crew=crew, makify=True)  # computes said
    blid = blinder.said
    assert blid == 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'

    regid = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    prior = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    stamp = '2020-08-23T18:06:10.988921+00:00'
    said = 'EFCUN22vSYr-O4XfM2TR6DysATSL7vco3JMm_VrWULmH'

    # test default kind JSON and default sn=1
    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json

    assert serder.ilk == Ilks.bup
    assert serder.said == said
    assert serder.stamp == stamp


    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAEi.',
        't': 'bup',
        'd': 'EFCUN22vSYr-O4XfM2TR6DysATSL7vco3JMm_VrWULmH',
        'rd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'n': '1',
        'p': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'dt': '2020-08-23T18:06:10.988921+00:00',
        'b': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
    }

    assert serder.raw == (b'{"v":"ACDCCAACAAJSONAAEi.","t":"bup","d":"EFCUN22vSYr-O4XfM2TR6DysATSL7vco3J'
                        b'Mm_VrWULmH","rd":"EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8","n":"1","p":'
                        b'"EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8","dt":"2020-08-23T18:06:10.988'
                        b'921+00:00","b":"EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5"}')

    # Test CESR
    said = 'EDyoNuGBvrXWj0I6V6jylRsePaz-yODKy8cKvC3zJa6w'
    serder = blindate(regid=regid, prior=prior, blid=blid, stamp=stamp, kind=Kinds.cesr)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.bup
    assert serder.said == said
    assert serder.stamp == stamp

    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAADs.',
        't': 'bup',
        'd': 'EDyoNuGBvrXWj0I6V6jylRsePaz-yODKy8cKvC3zJa6w',
        'rd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'n': '1',
        'p': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'dt': '2020-08-23T18:06:10.988921+00:00',
        'b': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
    }

    assert serder.raw == (b'-FA60OACDCCAACAAXbupEDyoNuGBvrXWj0I6V6jylRsePaz-yODKy8cKvC3zJa6wEM1hJSHgqklx'
                        b'e-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8MAABEM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8'
                        b'paR81AAG2020-08-23T18c06c10d988921p00c00EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdM'
                        b'eR5tHRL5')

    # test Serder inhale from raw roundtripped
    sad = serder.sad
    rawcesr = serder.raw

    serder = SerderACDC(raw=rawcesr)
    assert serder.sad == sad
    assert serder.raw == rawcesr

    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.bup
    assert serder.said == said
    assert serder.stamp == stamp
    """Done Test"""


def test_update_message():
    """Test update message"""
    tsaid = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
    tstate = 'issued'
    regid = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    prior = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    stamp = '2020-08-23T18:06:10.988921+00:00'
    said = 'ELI-gUF8FFE_eTllQSwUZMlY-BeBcnFaIar0V23uxy6A'

    # test default kind JSON and default sn=1
    serder = update(regid=regid, prior=prior, acdc=tsaid, state=tstate,
                    stamp=stamp)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json

    assert serder.ilk == Ilks.upd
    assert serder.said == said
    assert serder.stamp == stamp

    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAEx.',
        't': 'upd',
        'd': 'ELI-gUF8FFE_eTllQSwUZMlY-BeBcnFaIar0V23uxy6A',
        'rd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'n': '1',
        'p': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'dt': '2020-08-23T18:06:10.988921+00:00',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
    }

    assert serder.raw == (b'{"v":"ACDCCAACAAJSONAAEx.","t":"upd","d":"ELI-gUF8FFE_eTllQSwUZMlY-BeBcnFaIa'
                        b'r0V23uxy6A","rd":"EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8","n":"1","p":'
                        b'"EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8","dt":"2020-08-23T18:06:10.988'
                        b'921+00:00","td":"EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ","ts":"issued"'
                        b'}')

    # Test CESR
    prior = 'ELI-gUF8FFE_eTllQSwUZMlY-BeBcnFaIar0V23uxy6A'
    said = 'ECeZ647uldGDcTjWV8wHABE3w4CzrblKGJhzIBiFjS4Q'

    serder = update(regid=regid, prior=prior, acdc=tsaid, state=tstate, sn=2,
                    stamp=stamp, kind=Kinds.cesr)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.upd
    assert serder.said == said
    assert serder.stamp == stamp

    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAD0.',
        't': 'upd',
        'd': 'ECeZ647uldGDcTjWV8wHABE3w4CzrblKGJhzIBiFjS4Q',
        'rd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'n': '2',
        'p': 'ELI-gUF8FFE_eTllQSwUZMlY-BeBcnFaIar0V23uxy6A',
        'dt': '2020-08-23T18:06:10.988921+00:00',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
    }

    assert serder.raw == (b'-FA80OACDCCAACAAXupdECeZ647uldGDcTjWV8wHABE3w4CzrblKGJhzIBiFjS4QEM1hJSHgqklx'
                        b'e-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8MAACELI-gUF8FFE_eTllQSwUZMlY-BeBcnFaIar0V23u'
                        b'xy6A1AAG2020-08-23T18c06c10d988921p00c00EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbY'
                        b'GGCUQgqQ0Missued')

    # test Serder inhale from raw roundtripped
    sad = serder.sad
    rawcesr = serder.raw

    serder = SerderACDC(raw=rawcesr)
    assert serder.sad == sad
    assert serder.raw == rawcesr

    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.upd
    assert serder.said == said
    assert serder.stamp == stamp
    """Done Test"""

def test_schema_defaults():
    """Test utility functions that generate default schema"""
    said, sad = actSchemaDefault()
    assert said == 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK'
    assert sad == \
    {
        '$id': 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACT Default Schema',
        'description': 'Default JSON Schema for act ACDC.',
        'credentialType': 'ACDC_act_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 'd', 'u', 'i', 'rd', 's', 'a', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       'd': {'description': 'Message SAID', 'type': 'string'},
                       'u': {'description': 'Message UUID', 'type': 'string'},
                       'i': {'description': 'Issuer AID', 'type': 'string'},
                       'rd': {'description': 'Registry SAID', 'type': 'string'},
                       's': {'description': 'Schema Section',
                             'oneOf': [{'description': 'Schema Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Schema Section',
                                        'type': 'object'}]},
                       'a': {'description': 'Attribute Section',
                             'oneOf': [{'description': 'Attribute Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Attribute Section',
                                        'type': 'object'}]},
                       'e': {'description': 'Edge Section',
                             'oneOf': [{'description': 'Edge Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Edge Section',
                                        'type': 'object'}]},
                       'r': {'description': 'Rule Section',
                             'oneOf': [{'description': 'Rule Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Rule Section',
                                        'type': 'object'}]}},
        'additionalProperties': False
    }

    """Done Test"""

def test_attribute_message_json():
    """Test act acdc message with json"""

    # Test with JSON serialization
    kind = Kinds.json
    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    issuee = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"
    rawsalt = b'abcdefghijklmmop'
    uuid = Noncer(raw=rawsalt).qb64
    assert uuid == '0ABhYmNkZWZnaGlqa2xtbW9w'
    schemaSaid = 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK'  # default


    # Test Defaults  kind=json
    said = 'EOR-sLOPrmv95_ZfBYrIapqTT-Re85FWTI9nYJZftqT5'
    serder = attribute(issuer=issuer)  # defaults
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.issuee == None
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.sad['v'] == 'ACDCCAACAAJSONAAWh.'
    assert serder.size == 1441

    # Test with uuid and issuee and otherwise defaults
    said = 'ECfABuzokafIpRrE4impKaOJag3SDxLmVffqybwdH_X7'
    serder = attribute(issuer=issuer, uuid=uuid, issuee=issuee)
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.issuee == issuee
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.sad['v'] == 'ACDCCAACAAJSONAAXr.'
    assert serder.size == 1515

    # Test fully populated and expanded

    attrs = dict(d="", i=issuee, name="Zoe")
    attrPactor = Compactor(mad=attrs, makify=True, kind=kind)
    attrPactor.compact()
    attrPactor.expand()
    attrSaid = attrPactor.said
    attrs = list(attrPactor.partials.values())[0].mad    # since already compact
    assert attrs == \
    {
        'd': 'ENSz6GWE-3IW5_82aaT0uks8rZTH2etmj_EgyGL4idgo',
        'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
        'name': 'Zoe'
    }
    assert attrs['d'] == attrSaid

    edges = \
    {
        "d": "",
        "u": "0AwjaDAE0qHcgNghkDaG7OY1",
        "winner": "EBf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9",
        "loser": "EFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lk"
    }
    edgePactor = Compactor(mad=edges, makify=True, kind=kind)
    edgePactor.compact()
    edgePactor.expand()
    edgeSaid = edgePactor.said
    edges = list(edgePactor.partials.values())[0].mad    # since already compact
    assert edges == \
    {
        'd': 'EGaDRO2KMe8Y8JuAiXPuS0kim_MhuOEU17tiCj9Sonf5',
        'u': '0AwjaDAE0qHcgNghkDaG7OY1',
        'winner': 'EBf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9',
        'loser': 'EFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lk'
    }
    assert edges['d'] == edgeSaid

    rules = \
    {
      "d": "",
      "u": "0ADaG7OaDAE0qHcgY1Nghkwj",
      "disclaimers":
      {
        "d": "",
        "u": "0AHcgY1NghkwjDaG7OaDAE0q",
        "l": "Issuer disclaimers:",
        "warrantyDisclaimer":
        {
          "d": "",
          "u": "0AG7OY1wjaDAE0qHcgNghkDa",
          "l": "AS IS"
        },
        "liabilityDisclaimer":
        {
          "d": "",
          "u": "0AHcgNghkDaG7OY1wjaDAE0q",
          "l": "No Liability"
        }
      },
      "permittedUse":
      {
        "d": "",
        "u": "0ADaG7OY1wjaDAE0qHcgNghk",
        "l": "Non-commercial"
      }
    }

    rulePactor = Compactor(mad=rules, makify=True, kind=kind)
    rulePactor.compact()
    rulePactor.expand()
    ruleSaid = rulePactor.said
    rules = list(rulePactor.partials.values())[1].mad
    assert rules == \
    {
        'd': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v',
        'u': '0ADaG7OaDAE0qHcgY1Nghkwj',
        'disclaimers':
        {
            'd': 'EApRECx41f_BjJlk1cvFqDCT-VM1De5GS9KUrItUARnT',
            'u': '0AHcgY1NghkwjDaG7OaDAE0q',
            'l': 'Issuer disclaimers:',
            'warrantyDisclaimer':
            {
                'd': 'ELGxE_uoWQXYi4zm4ooYlSYVVWT_RaYR1oHy_HfrLXkL',
                'u': '0AG7OY1wjaDAE0qHcgNghkDa',
                'l': 'AS IS'
            },
            'liabilityDisclaimer':
            {
                'd': 'EJerMTe6gpOu9nsZDU9ojv1ZMkaDjEPyUI5p-jqCBxyd',
                'u': '0AHcgNghkDaG7OY1wjaDAE0q',
                'l': 'No Liability'
            }
        },
        'permittedUse':
        {
            'd': 'EPH194D7v-QxNt_p9Xkp_bCuYcmWoWy9cZMPHDfx3gxq',
            'u': '0ADaG7OY1wjaDAE0qHcgNghk',
            'l': 'Non-commercial'
        }
    }
    assert rules['d'] == ruleSaid

    said = 'EOilTAfOOWiIzVU9mFmgEeOaLao-H4-1JsYjrbP56_0E'
    vs = 'ACDCCAACAAJSONAARj.'
    size = 1123

    serder = attribute(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attrs=attrs, edges=edges, rules=rules)
    assert serder.said == said
    assert serder.size == size
    assert serder.sad['v'] == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.issuee == issuee
    assert serder.schema == schemaSaid
    assert serder.attrib['d'] == attrSaid
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid

    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAARj.',
        't': 'act',
        'd': 'EOilTAfOOWiIzVU9mFmgEeOaLao-H4-1JsYjrbP56_0E',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK',
        'a': {'d': 'ENSz6GWE-3IW5_82aaT0uks8rZTH2etmj_EgyGL4idgo',
              'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
              'name': 'Zoe'},
        'e': {'d': 'EGaDRO2KMe8Y8JuAiXPuS0kim_MhuOEU17tiCj9Sonf5',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'winner': 'EBf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9',
              'loser': 'EFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lk'},
        'r': {'d': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v',
              'u': '0ADaG7OaDAE0qHcgY1Nghkwj',
              'disclaimers': {'d': 'EApRECx41f_BjJlk1cvFqDCT-VM1De5GS9KUrItUARnT',
                              'u': '0AHcgY1NghkwjDaG7OaDAE0q',
                              'l': 'Issuer disclaimers:',
                              'warrantyDisclaimer': {'d': 'ELGxE_uoWQXYi4zm4ooYlSYVVWT_RaYR1oHy_HfrLXkL',
                                                     'u': '0AG7OY1wjaDAE0qHcgNghkDa',
                                                     'l': 'AS IS'},
                              'liabilityDisclaimer': {'d': 'EJerMTe6gpOu9nsZDU9ojv1ZMkaDjEPyUI5p-jqCBxyd',
                                                      'u': '0AHcgNghkDaG7OY1wjaDAE0q',
                                                      'l': 'No Liability'}},
              'permittedUse': {'d': 'EPH194D7v-QxNt_p9Xkp_bCuYcmWoWy9cZMPHDfx3gxq',
                               'u': '0ADaG7OY1wjaDAE0qHcgNghk',
                               'l': 'Non-commercial'}
              }
    }

    # fully compact version to see if saids are stable
    cvs = 'ACDCCAACAAJSONAAF-.'
    csize = 382

    serder = attribute(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attrs=attrSaid, edges=edgeSaid, rules=ruleSaid)

    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.sad['v'] == cvs != vs  # but vs not stable not same as uncompacted
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAF-.',
        't': 'act',
        'd': 'EOilTAfOOWiIzVU9mFmgEeOaLao-H4-1JsYjrbP56_0E',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK',
        'a': 'ENSz6GWE-3IW5_82aaT0uks8rZTH2etmj_EgyGL4idgo',
        'e': 'EGaDRO2KMe8Y8JuAiXPuS0kim_MhuOEU17tiCj9Sonf5',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }


    """Done Test"""

def test_attribute_message_cesr():
    """Test act acdc message with cser"""

    # Test with CESR serialization
    kind = Kinds.cesr
    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    issuee = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"
    rawsalt = b'abcdefghijklmmop'
    uuid = Noncer(raw=rawsalt).qb64
    assert uuid == '0ABhYmNkZWZnaGlqa2xtbW9w'
    schemaSaid = 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK'  # default



def test_classic_message():
    """Test acdc messages v2"""


    """Done Test"""

if __name__ == '__main__':
    test_regcept_message()
    test_blindate_message()
    test_update_message()
    test_schema_defaults()
    test_attribute_message_json()
    test_attribute_message_cesr()
    test_classic_message()
