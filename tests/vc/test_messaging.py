# -*- encoding: utf-8 -*-
"""
tests.vc.test_messaging module

"""

import pytest

from keri.kering import Protocols, Kinds, Ilks, Vrsn_2_0
from keri.vc.messaging import (regcept, blindate, update, actSchemaDefault,
                               acdcatt, schema, attribute, edge, rule, acdcmap)
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

def test_acdcatt_message_json():
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
    serder = acdcatt(issuer=issuer)  # defaults
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, issuee=issuee)
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attribute=attrs, edge=edges, rule=rules)
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid)
    assert serder.kind == kind
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

def test_acdcatt_message_cesr():
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

    serder = acdcatt(issuer=issuer, kind=kind)
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, schema=schemaSaid, kind=kind)
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, issuee=issuee, kind=kind)
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrs, edge=edges, rule=rules, kind=kind)
    assert serder.kind == kind
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

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
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


def test_schema_section():
    """Test sch schema section message"""

    # Test with JSON serialization
    kind = Kinds.json
    schemaSaid, schemaSad = actSchemaDefault(kind=kind)
    assert schemaSaid == 'EJPULhLwM8yQNj3iMSMCi7FdmP9mMCMe1yWO9nATNRzK'
    assert schemaSad == \
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

    # Test using schema said
    said = 'EAeKYjcvKi3N-CaLmtnJoFRt_HlX9Wa6BXr4zwoK9q1e'
    vs = 'ACDCCAACAAJSONAACL.'
    size = 139

    serder = schema(schema=schemaSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
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

    # Test using schema dict
    said = 'EEj1cNd_T2zpynDeGcf8SvB1eLNWr-G1b0TyHrgIT8s_'
    vs = 'ACDCCAACAAJSONAAVK.'
    size = 1354

    serder = schema(schema=schemaSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.schema == schemaSad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with CESR serialization
    kind = Kinds.cesr
    schemaSaid, schemaSad = actSchemaDefault(kind=kind)
    assert schemaSaid == 'EE2yz4qmmFzbJEj8olTa7P1J8R1-QvYB9cD9g26WzSjN'
    assert schemaSad == \
    {
        '$id': 'EE2yz4qmmFzbJEj8olTa7P1J8R1-QvYB9cD9g26WzSjN',
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

    # Test using schema said
    said = 'EGL4V_uyBBkNQCEONb8AM2iXClP7N0iiGDg1ZjJ3Oizi'
    vs = 'ACDCCAACAACESRAABs.'
    size = 108

    serder = schema(schema=schemaSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
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

    # Test using schema dict
    said = 'EDJkXhl6h_ccAik_g4VLFLKEp0K1y5rrG5g9RRXYKWr9'
    vs = 'ACDCCAACAACESRAAX4.'
    size = 1528

    serder = schema(schema=schemaSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.schema == schemaSad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


def test_attribute_section():
    """Test att attribute section message"""
    issuee = 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
    mad = \
    {
        'd': '',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
        'role': 'leader',
        'contact':
        {
            'd': '',
            'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
            'first': 'Cloe',
            'last': 'Cleveridge',
        }
    }

    # Test with JSON serialization
    kind = Kinds.json
    compactor = Compactor(mad=mad, makify=True, saidive=True, kind=kind)
    compactor.compact()
    compactor.expand()
    attrSaid = compactor.said
    attrSad = list(compactor.partials.values())[1].mad
    assert attrSaid == 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL'
    assert attrSad == \
    {
        'd': 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
        'role': 'leader',
        'contact':
        {
            'd': 'EIZo47mJ29cuWW_UjgBEtcN2vAx5bzoBa-uVWOBH-2QP',
            'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
            'first': 'Cloe',
            'last': 'Cleveridge'
        }
    }

    # Test using attr said
    said = 'EJQvYciWzhTAVwq1Yt1UU8VVA-PD6O9E63Lb84ezqOS8'
    vs = 'ACDCCAACAAJSONAACL.'
    size = 139

    serder = attribute(attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None  # since said not sad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using attribute dict
    said = 'ELy9CPlrrOwyHPWYw81Y4N_0Ff4B2VYprpXlT4WVgIiA'
    vs = 'ACDCCAACAAJSONAAF0.'
    size = 372

    serder = attribute(attribute=attrSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee  # since sad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with CESR serialization
    kind = Kinds.cesr
    compactor = Compactor(mad=mad, makify=True, saidive=True, kind=kind)
    compactor.compact()
    compactor.expand()
    attrSaid = compactor.said
    attrSad = list(compactor.partials.values())[1].mad
    assert attrSaid == 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-'
    assert attrSad == \
    {
        'd': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
        'role': 'leader',
        'contact':
        {
            'd': 'EKkFu2dX274cXnfaXh0OWZj1LnaUrjmDKAS_ozGBZ9Pz',
            'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
            'first': 'Cloe',
            'last': 'Cleveridge'
        }
    }

    # Test using attr said
    said = 'ENm6VbJ2sHt2DkjPEiwhhY11cugbsDN2EtwhlI6bAj0x'
    vs = 'ACDCCAACAACESRAABs.'
    size = 108

    serder = attribute(attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None  # since said not sad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using attribute dict
    said = 'EPc8jTHBrPfDm9l8Rj4wbi3R-mYVlBRI8P_D3RO14aoI'
    vs = 'ACDCCAACAACESRAAFM.'
    size = 332

    serder = attribute(attribute=attrSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee  # since sad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


def test_edge_section():
    """Test edg edge section message"""

    mad = \
    {
        'd': '',
        'u': '0AwjaDAE0qHcgNghkDaG7OY1',
        "work":
        {
          "d": "E2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lkFrn9y",
          "u": "0ANghkDaG7OY1wjaDAE0qHcg",
          "n": "ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX",
          "s": "ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw"
        },
        "play":
        {
          "d": "ELxUdYerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOc",
          "u": "0ADAE0qHcgNghkDaG7OY1wja",
          "n": "EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5",
          "s": "EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N",
          "o": "NI2I"
        }
    }

    # Test with JSON serialization
    kind = Kinds.json
    compactor = Compactor(mad=mad, makify=True, saidive=True, kind=kind)
    compactor.compact()
    compactor.expand()
    edgeSaid = compactor.said
    edgeSad = list(compactor.partials.values())[1].mad
    assert edgeSaid == 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF'
    assert edgeSad == \
    {
        'd': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
        'u': '0AwjaDAE0qHcgNghkDaG7OY1',
        'work':
        {
            'd': 'EKJGcxOlhz08bQ9IUukIKl19pPmKpZ81RelPncz29xL2',
            'u': '0ANghkDaG7OY1wjaDAE0qHcg',
            'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
            's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'
        },
        'play':
        {
            'd': 'EO6KOA3fmGtIW65F66oHNMmYOh6x4i8tGJJI0XwRAx9w',
            'u': '0ADAE0qHcgNghkDaG7OY1wja',
            'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
            's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
            'o': 'NI2I'
        }
    }
    assert edgeSad['d'] == edgeSaid

    # Test using edge said
    said = 'EO5mxn9rJue2sXZI7_pC9uYNkDVQ9qA4roeKNGC6maSB'
    vs = 'ACDCCAACAAJSONAACL.'
    size = 139

    serder = edge(edge=edgeSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using edge dict
    said = 'EOeLqwd8pwwtE3EgVmjjq_OlYM3emWw0i-d73eydPffX'
    vs = 'ACDCCAACAAJSONAAI9.'
    size = 573

    serder = edge(edge=edgeSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with CESR serialization
    kind = Kinds.cesr
    compactor = Compactor(mad=mad, makify=True, saidive=True, kind=kind)
    compactor.compact()
    compactor.expand()
    edgeSaid = compactor.said
    edgeSad = list(compactor.partials.values())[1].mad
    assert edgeSaid == 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw'
    assert edgeSad == \
    {
        'd': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
        'u': '0AwjaDAE0qHcgNghkDaG7OY1',
        'work':
        {
            'd': 'EFYkMnj7wgn4Vn02F6iniWoCJFf-kCzvkM2wZ7RFzWPC',
            'u': '0ANghkDaG7OY1wjaDAE0qHcg',
            'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
            's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'
        },
        'play':
        {
            'd': 'ENCGxUkFQndU5bKtD6o3PRXvl2ZbgmSF-aQU1sVkGudj',
            'u': '0ADAE0qHcgNghkDaG7OY1wja',
            'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
            's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
            'o': 'NI2I'
        }
    }
    assert edgeSad['d'] == edgeSaid

    # Test using edge said
    said = 'ED0P_BH7w1kDhZys38miqm0c612pjYYvd_EiV9W4-Gyj'
    vs = 'ACDCCAACAACESRAABs.'
    size = 108

    serder = edge(edge=edgeSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using edge dict
    said = 'ENjBCWeLQk7iYq3J1DFgPkJ-yfDE_7a0gOE1ecNt9bfw'
    vs = 'ACDCCAACAACESRAAIU.'
    size = 532

    serder = edge(edge=edgeSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


def test_rule_section():
    """Test rul rule section message"""

    mad = \
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

    # Test with JSON serialization
    kind = Kinds.json
    compactor = Compactor(mad=mad, makify=True, saidive=True, kind=kind)
    compactor.compact()
    compactor.expand()
    ruleSaid = compactor.said
    ruleSad = list(compactor.partials.values())[1].mad
    assert ruleSaid == 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    assert ruleSad == \
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
    assert ruleSad['d'] == ruleSaid

    # Test using rule said
    said = 'EE0X6gLmNoZK-Gpcq7o8tq114pf_Kv8oGLXLbIyEedjQ'
    vs = 'ACDCCAACAAJSONAACL.'
    size = 139

    serder = rule(rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using rule dict
    said = 'EGqdBnWd5r-S6oiT2xQb1zK5DCxQH587bUJRC31jg4RE'
    vs = 'ACDCCAACAAJSONAAKW.'
    size = 662

    serder = rule(rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with CESR serialization
    kind = Kinds.cesr
    compactor = Compactor(mad=mad, makify=True, saidive=True, kind=kind)
    compactor.compact()
    compactor.expand()
    ruleSaid = compactor.said
    ruleSad = list(compactor.partials.values())[1].mad
    assert ruleSaid == 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    assert ruleSad == \
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
    assert ruleSad['d'] == ruleSaid

    # Test using rule said
    said = 'ELNJn_iLJxRDAFbF8b5C7fZVuurGoOJarXhVdx1itYfq'
    vs = 'ACDCCAACAACESRAABs.'
    size = 108

    serder = rule(rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSaid
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using rule dict
    said = 'EN21tftFSBYQ9VuEUGMzyVIMPjTmktXGWdO9-mHq8ThM'
    vs = 'ACDCCAACAACESRAAKM.'
    size = 652

    serder = rule(rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSad
    assert serder.sad['v'] == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


def test_acdcmap_message():
    """Test acdc messages v2"""


    """Done Test"""

if __name__ == '__main__':
    test_regcept_message()
    test_blindate_message()
    test_update_message()
    test_schema_defaults()
    test_acdcatt_message_json()
    test_acdcatt_message_cesr()
    test_schema_section()
    test_attribute_section()
    test_edge_section()
    test_rule_section()
    test_acdcmap_message()
