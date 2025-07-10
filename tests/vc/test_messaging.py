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
    regid = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'


    # Test Defaults  kind=json
    said = 'EPNnyM5DyYNX3yA9938XM2o6gvy7QLI76oi0GWg9kpe_'
    serder = attribute(issuer=issuer)  # defaults
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.issuee == None
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.sad['v'] == 'ACDCCAACAAJSONAAWh.'
    assert serder.size == 1441

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with uuid and issuee and otherwise defaults
    said = 'EAi889SlRgc0kaGtLj8NCfpCAY3S13m6peIqfJH8BnCe'
    vs = 'ACDCCAACAAJSONAAYX.'
    size = 1559

    serder = attribute(issuer=issuer, uuid=uuid, regid=regid, issuee=issuee)
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == issuee
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

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

    said = 'EIBWIQW5U13qgm1jJN8Yu7OEanXnV0iwappQ5qk4Z9a0'
    vs = 'ACDCCAACAAJSONAARj.'
    size = 1123

    serder = attribute(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attrs=attrs, edges=edges, rules=rules)
    assert serder.said == said
    assert serder.size == size
    assert serder.sad['v'] == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == ""
    assert serder.issuee == issuee
    assert serder.schema == schemaSaid
    assert serder.attrib['d'] == attrSaid
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid

    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAARj.',
        't': 'act',
        'd': 'EIBWIQW5U13qgm1jJN8Yu7OEanXnV0iwappQ5qk4Z9a0',
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

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

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
    assert serder.regid == ""
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAF-.',
        't': 'act',
        'd': 'EIBWIQW5U13qgm1jJN8Yu7OEanXnV0iwappQ5qk4Z9a0',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK',
        'a': 'ENSz6GWE-3IW5_82aaT0uks8rZTH2etmj_EgyGL4idgo',
        'e': 'EGaDRO2KMe8Y8JuAiXPuS0kim_MhuOEU17tiCj9Sonf5',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

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
    schemaSaid = 'EE2yz4qmmFzbJEj8olTa7P1J8R1-QvYB9cD9g26WzSjN'  # default
    regid = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'


    # Test Defaults  but with kind=cesr
    said = 'EFC6LUAuqGp_Mtetf6RXOuTCfD1HCwNdqQfgZ8tWzvIm'
    vs = 'ACDCCAACAACESRAAY4.'
    size = 1592

    serder = attribute(issuer=issuer, kind=kind)
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.issuee == None
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad


    # Test Defaults  but with schema set to schema said and kind=cesr
    said = 'EFC6LUAuqGp_Mtetf6RXOuTCfD1HCwNdqQfgZ8tWzvIm'
    vs = 'ACDCCAACAACESRAACs.'
    size = 172

    serder = attribute(issuer=issuer, schema=schemaSaid, kind=kind)
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test defaults with uuid and issuee and regid and kind=cesr
    said = 'EK60Qa1JYz3NWBf-sV5bS2xPGjThAm0GglKICPeJ0Lns'
    vs = 'ACDCCAACAACESRAAak.'
    size = 1700

    serder = attribute(issuer=issuer, uuid=uuid, regid=regid, issuee=issuee, kind=kind)
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == issuee
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test fully populated and expanded
    attrs = \
    {
        'd': '',
        'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
        'name': 'Zoe'
    }
    attrPactor = Compactor(mad=attrs, makify=True, kind=kind)
    attrPactor.compact()
    attrPactor.expand()
    attrSaid = attrPactor.said
    attrs = list(attrPactor.partials.values())[0].mad    # since already compact
    assert attrs == \
    {
        'd': 'EHqZ3mypGYGMTe0X0ZB7zYavGCJfCkqEmKj5xzyc7xxQ',
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
        'd': 'ECLnO-mApjsPJfY7QWJpKZMRBQcVEXZiyXVa_1QGqFZu',
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
        'd': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-',
        'u': '0ADaG7OaDAE0qHcgY1Nghkwj',
        'disclaimers':
        {
            'd': 'EGMp181uEcUmi5FXs0ebqEhOyVi27-IDiYdoqe453BRD',
            'u': '0AHcgY1NghkwjDaG7OaDAE0q',
            'l': 'Issuer disclaimers:',
            'warrantyDisclaimer':
            {
                'd': 'EO6ekaJYyWfl0Civ2bApVLgCmge43io1KvFCqSPt8Qc5',
                'u': '0AG7OY1wjaDAE0qHcgNghkDa',
                'l': 'AS IS'
            },
            'liabilityDisclaimer':
            {
                'd': 'EDzyrYOaVI3TwLvN-w-pfGyoZfyvV0rslCieRCgXgEF7',
                'u': '0AHcgNghkDaG7OY1wjaDAE0q',
                'l': 'No Liability'
            }
        },
        'permittedUse':
        {
            'd': 'EBdHlf04DK2w4So61ebgUydOr85YGjP_xkLO-CnEXcsj',
            'u': '0ADaG7OY1wjaDAE0qHcgNghk',
            'l': 'Non-commercial'
        }
    }
    assert rules['d'] == ruleSaid

    said = 'EBIdofkjYkm2thryYfwNIrPmNvvhNdnznfo_V68o-QOJ'
    vs = 'ACDCCAACAACESRAARU.'
    size = 1108

    serder = attribute(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       attrs=attrs, edges=edges, rules=rules, kind=kind)
    assert serder.said == said
    assert serder.size == size
    assert serder.sad['v'] == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == issuee
    assert serder.schema == schemaSaid
    assert serder.attrib['d'] == attrSaid
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid

    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAARU.',
        't': 'act',
        'd': 'EBIdofkjYkm2thryYfwNIrPmNvvhNdnznfo_V68o-QOJ',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EE2yz4qmmFzbJEj8olTa7P1J8R1-QvYB9cD9g26WzSjN',
        'a': {'d': 'EHqZ3mypGYGMTe0X0ZB7zYavGCJfCkqEmKj5xzyc7xxQ',
              'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
              'name': 'Zoe'},
        'e': {'d': 'ECLnO-mApjsPJfY7QWJpKZMRBQcVEXZiyXVa_1QGqFZu',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'winner': 'EBf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9',
              'loser': 'EFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lk'},
        'r': {'d': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-',
              'u': '0ADaG7OaDAE0qHcgY1Nghkwj',
              'disclaimers': {'d': 'EGMp181uEcUmi5FXs0ebqEhOyVi27-IDiYdoqe453BRD',
                              'u': '0AHcgY1NghkwjDaG7OaDAE0q',
                              'l': 'Issuer disclaimers:',
                              'warrantyDisclaimer': {'d': 'EO6ekaJYyWfl0Civ2bApVLgCmge43io1KvFCqSPt8Qc5',
                                                     'u': '0AG7OY1wjaDAE0qHcgNghkDa',
                                                     'l': 'AS IS'},
                              'liabilityDisclaimer': {'d': 'EDzyrYOaVI3TwLvN-w-pfGyoZfyvV0rslCieRCgXgEF7',
                                                      'u': '0AHcgNghkDaG7OY1wjaDAE0q',
                                                      'l': 'No Liability'}},
              'permittedUse': {'d': 'EBdHlf04DK2w4So61ebgUydOr85YGjP_xkLO-CnEXcsj',
                               'u': '0ADaG7OY1wjaDAE0qHcgNghk',
                               'l': 'Non-commercial'}
              }
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # fully compact version to see if saids are stable
    cvs = 'ACDCCAACAACESRAAFg.'
    csize = 352

    serder = attribute(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       attrs=attrSaid, edges=edgeSaid, rules=ruleSaid, kind=kind)

    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.sad['v'] == cvs != vs  # but vs not stable not same as uncompacted
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAFg.',
        't': 'act',
        'd': 'EBIdofkjYkm2thryYfwNIrPmNvvhNdnznfo_V68o-QOJ',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EE2yz4qmmFzbJEj8olTa7P1J8R1-QvYB9cD9g26WzSjN',
        'a': 'EHqZ3mypGYGMTe0X0ZB7zYavGCJfCkqEmKj5xzyc7xxQ',
        'e': 'ECLnO-mApjsPJfY7QWJpKZMRBQcVEXZiyXVa_1QGqFZu',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


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
