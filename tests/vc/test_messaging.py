# -*- encoding: utf-8 -*-
"""
tests.vc.test_messaging module

"""

import pytest

from keri.kering import Protocols, Kinds, Ilks, Vrsn_2_0
from keri.vc import (regcept, blindate, update,
                    acdcatt, acdcagg, acdcmap,
                    sectschema, sectattr, sectedge, sectrule, sectaggr,
                    sectionate,
                    actSchemaDefault, acgSchemaDefault, acmSchemaDefault)
from keri.core import (GenDex, Noncer, SerderACDC, BlindState, Blinder,
                       Compactor, Aggor)

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
    assert blid == 'EBTAKXL5si31rCKCimOwR_gJTRmLaqixvrJEj5OzK769'

    regid = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    prior = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    stamp = '2020-08-23T18:06:10.988921+00:00'
    said = 'EDGouTZMjO0HbHefvBrYtpWTY6y5TykF2LDgaZJNiJjB'

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
        'd': 'EDGouTZMjO0HbHefvBrYtpWTY6y5TykF2LDgaZJNiJjB',
        'rd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'n': '1',
        'p': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'dt': '2020-08-23T18:06:10.988921+00:00',
        'b': 'EBTAKXL5si31rCKCimOwR_gJTRmLaqixvrJEj5OzK769'
    }

    assert serder.raw == (b'{"v":"ACDCCAACAAJSONAAEi.","t":"bup","d":"EDGouTZMjO0HbHefvBrYtpWTY6y5TykF2L'
                        b'DgaZJNiJjB","rd":"EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8","n":"1","p":'
                        b'"EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8","dt":"2020-08-23T18:06:10.988'
                        b'921+00:00","b":"EBTAKXL5si31rCKCimOwR_gJTRmLaqixvrJEj5OzK769"}')

    # Test CESR
    said = 'EIOVlgnJvK96aMVLtB3PoaIcjpvPDoq41xtIKQE92Rx_'
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
        'd': 'EIOVlgnJvK96aMVLtB3PoaIcjpvPDoq41xtIKQE92Rx_',
        'rd': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'n': '1',
        'p': 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8',
        'dt': '2020-08-23T18:06:10.988921+00:00',
        'b': 'EBTAKXL5si31rCKCimOwR_gJTRmLaqixvrJEj5OzK769'
    }

    assert serder.raw == (b'-FA60OACDCCAACAAXbupEIOVlgnJvK96aMVLtB3PoaIcjpvPDoq41xtIKQE92Rx_EM1hJSHgqklx'
                    b'e-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8MAABEM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8'
                    b'paR81AAG2020-08-23T18c06c10d988921p00c00EBTAKXL5si31rCKCimOwR_gJTRmLaqixvrJE'
                    b'j5OzK769')

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
    # Test actSchemaDefault
    said, sad = actSchemaDefault()  # default kind json
    assert said == 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu'
    assert sad == \
    {
        '$id': 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACT Default Schema',
        'description': 'Default JSON Schema for act ACDC.',
        'credentialType': 'ACDC_act_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'a', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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

    # CESR serialization kind
    said, sad = actSchemaDefault(kind=Kinds.cesr)
    assert said == 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi'
    assert sad == \
    {
        '$id': 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACT Default Schema',
        'description': 'Default JSON Schema for act ACDC.',
        'credentialType': 'ACDC_act_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'a', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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

    # Test acgSchemaDefault
    said, sad = acgSchemaDefault()  # default kind json
    assert said == 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO'
    assert sad == \
    {
        '$id': 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACG Default Schema',
        'description': 'Default JSON Schema for acg ACDC.',
        'credentialType': 'ACDC_acg_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'A', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
                       'd': {'description': 'Message SAID', 'type': 'string'},
                       'u': {'description': 'Message UUID', 'type': 'string'},
                       'i': {'description': 'Issuer AID', 'type': 'string'},
                       'rd': {'description': 'Registry SAID', 'type': 'string'},
                       's': {'description': 'Schema Section',
                             'oneOf': [{'description': 'Schema Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Schema Section',
                                        'type': 'object'}]},
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    # CESR serialization kind
    said, sad = acgSchemaDefault(kind=Kinds.cesr)
    assert said == 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl'
    assert sad == \
    {
        '$id': 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACG Default Schema',
        'description': 'Default JSON Schema for acg ACDC.',
        'credentialType': 'ACDC_acg_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'A', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
                       'd': {'description': 'Message SAID', 'type': 'string'},
                       'u': {'description': 'Message UUID', 'type': 'string'},
                       'i': {'description': 'Issuer AID', 'type': 'string'},
                       'rd': {'description': 'Registry SAID', 'type': 'string'},
                       's': {'description': 'Schema Section',
                             'oneOf': [{'description': 'Schema Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Schema Section',
                                        'type': 'object'}]},
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    # Test acmSchemaDefault
    said, sad = acmSchemaDefault()  # default kind json
    assert said == 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ'
    assert sad == \
    {
        '$id': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACM Default Schema',
        'description': 'Default JSON Schema for acm ACDC.',
        'credentialType': 'ACDC_acm_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 'd', 'i', 's'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    # CESR serialization kind
    said, sad = acmSchemaDefault(kind=Kinds.cesr)
    assert said == 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK'
    assert sad == \
    {
        '$id': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACM Default Schema',
        'description': 'Default JSON Schema for acm ACDC.',
        'credentialType': 'ACDC_acm_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 'd', 'i', 's'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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
    schemaSaid, schemaSad = actSchemaDefault(kind=kind)
    assert schemaSaid == 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu'  # default
    regid = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'


    # Test Defaults  kind=json
    said = 'EIARJfTtFysKAwUEhep4AwD_arQGOhU0GeAC0GlinYaM'
    vs = 'ACDCCAACAAJSONAAXY.'
    size = 1496

    serder = acdcatt(issuer=issuer)  # defaults
    assert serder.kind == kind
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.issuee == None
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.attrib == {}
    assert serder.edge == {}
    assert serder.rule == {}
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with uuid and issuee and otherwise defaults
    said = 'ELzCsCE9KjxUy6ONO2ox2VInb4LOVN8Vb-yHkpl1yhhS'
    vs = 'ACDCCAACAAJSONAAZO.'
    size = 1614

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, issuee=issuee)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == issuee
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.verstr == vs
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
    attrPactor = Compactor(mad=attrs, makify=True, compactify=True, kind=kind)
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
    edgePactor = Compactor(mad=edges, makify=True, compactify=True, kind=kind)
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

    rulePactor = Compactor(mad=rules, makify=True, compactify=True, kind=kind)
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

    said = 'EB6VfEwqWzLVq2ZC-VPDwcSWwTWHGDVq101G34N0r4C3'
    vs = 'ACDCCAACAAJSONAARj.'
    size = 1123

    serder = acdcatt(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attribute=attrs, edge=edges, rule=rules)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.size == size
    assert serder.verstr == vs
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
        'd': 'EB6VfEwqWzLVq2ZC-VPDwcSWwTWHGDVq101G34N0r4C3',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu',
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
                               'l': 'Non-commercial'
                               }
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
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
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
        'd': 'EB6VfEwqWzLVq2ZC-VPDwcSWwTWHGDVq101G34N0r4C3',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu',
        'a': 'ENSz6GWE-3IW5_82aaT0uks8rZTH2etmj_EgyGL4idgo',
        'e': 'EGaDRO2KMe8Y8JuAiXPuS0kim_MhuOEU17tiCj9Sonf5',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcatt(issuer=issuer, uuid=uuid, schema=schemaSaid,
                       attribute=attrs, edge=edges, rule=rules, compactify=True)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == ""
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=Ilks.act,
        uuid=uuid, regid="", schema=schemaSad, attribute=attrs, issuee=issuee,
        edge=edges, rule=rules, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == Ilks.act
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == ""
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == attrSaid
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'ECrAWpmZnwdDDzarLtFwfcIVba9xbEB6tNbGqakMWNwV'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att.said == 'EMaznyzQl51_-iDWhKfXVrskl15vj7M89DXPTtwZyX7u'
    assert att.sad['a'] == attrs
    assert att.sad['a']['d'] == attrSaid
    assert att.issuee == issuee

    assert agg == None

    assert edg.said == 'EET_ox52uhD1m64Gv0oQV3cSQ30HgOc-kCCvarOOvOb8'
    assert edg.sad['e'] == edges
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EGqdBnWd5r-S6oiT2xQb1zK5DCxQH587bUJRC31jg4RE'
    assert rul.sad['r'] == rules
    assert rul.sad['r']['d'] == ruleSaid

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
    schemaSaid, schemaSad = actSchemaDefault(kind=kind)
    assert schemaSaid == 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi'
    regid = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'


    # Test Defaults  but with kind=cesr
    said = 'EBIOZiOmpOAj1Hdh08qaSMHIOnryCprbkRbfGFqD1gOg'
    vs = 'ACDCCAACAACESRAAZ0.'
    size = 1652

    serder = acdcatt(issuer=issuer, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.issuee == None
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.attrib == {}
    assert serder.edge == {}
    assert serder.rule == {}
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad


    # Test Defaults  but with schema set to schema said and kind=cesr
    said = 'EBIOZiOmpOAj1Hdh08qaSMHIOnryCprbkRbfGFqD1gOg'
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
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test defaults with uuid and issuee and regid and kind=cesr
    said = 'EN9v6J0BQd5bwer6r5kkYZ93r5zpQduVgPPoVr1E6rDd'
    vs = 'ACDCCAACAACESRAAbg.'
    size = 1760

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, issuee=issuee, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == issuee
    assert serder.sad['s']['$id'] == schemaSaid
    assert serder.verstr == vs
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
    attrPactor = Compactor(mad=attrs, makify=True, compactify=True, kind=kind)
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
    edgePactor = Compactor(mad=edges, makify=True, compactify=True, kind=kind)
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

    rulePactor = Compactor(mad=rules, makify=True, compactify=True, kind=kind)
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

    said = 'EKzjlmBBViXoXmAQtgINF_JNiylA0KaIKJiig1OAataY'
    vs = 'ACDCCAACAACESRAARU.'
    size = 1108

    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrs, edge=edges, rule=rules, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.size == size
    assert serder.verstr == vs
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
        'd': 'EKzjlmBBViXoXmAQtgINF_JNiylA0KaIKJiig1OAataY',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi',
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
                               'l': 'Non-commercial'
                               }
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
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
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
        'd': 'EKzjlmBBViXoXmAQtgINF_JNiylA0KaIKJiig1OAataY',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi',
        'a': 'EHqZ3mypGYGMTe0X0ZB7zYavGCJfCkqEmKj5xzyc7xxQ',
        'e': 'ECLnO-mApjsPJfY7QWJpKZMRBQcVEXZiyXVa_1QGqFZu',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcatt(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrs, edge=edges, rule=rules, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == Ilks.act
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=Ilks.act,
        uuid=uuid, regid=regid, schema=schemaSad, attribute=attrs, issuee=issuee,
        edge=edges, rule=rules, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == Ilks.act
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == regid
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == attrSaid
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'EECUiJ5asY4lThpfvoGZKE2G4JfxjB9uuiVsw-nTfbd3'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att.said == 'EKURq1KGljCjpRb77-Lp2OLMPHmgbrfNZWWxGGBmmDwx'
    assert att.sad['a'] == attrs
    assert att.sad['a']['d'] == attrSaid
    assert att.issuee == issuee

    assert agg == None

    assert edg.said == 'EPuMleT6OdbQpTN5YLTfZ1wZ7ZtCwknWrIQyrU5f0CLV'
    assert edg.sad['e'] == edges
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EN21tftFSBYQ9VuEUGMzyVIMPjTmktXGWdO9-mHq8ThM'
    assert rul.sad['r'] == rules
    assert rul.sad['r']['d'] == ruleSaid


    """Done Test"""


def test_schema_section():
    """Test sch schema section message"""

    # Test with JSON serialization
    kind = Kinds.json
    schemaSaid, schemaSad = actSchemaDefault(kind=kind)
    assert schemaSaid == 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu'
    assert schemaSad == \
    {
        '$id': 'EANZuuCmPzwr81sZiX-2e-bC6nBDt7Gb4xkZo__wzGBu',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACT Default Schema',
        'description': 'Default JSON Schema for act ACDC.',
        'credentialType': 'ACDC_act_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'a', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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
    said = 'EMgkqh3666KIfZaaaoGUYP705D2Z8SZXhQJxnoe91DYS'
    vs = 'ACDCCAACAAJSONAACL.'
    size = 139

    serder = sectschema(schema=schemaSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.schema == schemaSaid
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using schema dict
    said = 'ECrAWpmZnwdDDzarLtFwfcIVba9xbEB6tNbGqakMWNwV'
    vs = 'ACDCCAACAAJSONAAWB.'
    size = 1409

    serder = sectschema(schema=schemaSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.schema == schemaSad
    assert serder.verstr == vs
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
    assert schemaSaid == 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi'
    assert schemaSad == \
    {
        '$id': 'EFd28O1tMjNISThEXiWpZPJL9Ud-ocu2QmOGuMD1RvSi',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACT Default Schema',
        'description': 'Default JSON Schema for act ACDC.',
        'credentialType': 'ACDC_act_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'a', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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
    said = 'EG8LEuZihkqKMQQpKHYYrkjpqbcRkDBFgOXnIO9RXxUR'
    vs = 'ACDCCAACAACESRAABs.'
    size = 108

    serder = sectschema(schema=schemaSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.schema == schemaSaid
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using schema dict
    said = 'EECUiJ5asY4lThpfvoGZKE2G4JfxjB9uuiVsw-nTfbd3'
    vs = 'ACDCCAACAACESRAAY0.'
    size = 1588

    serder = sectschema(schema=schemaSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.schema == schemaSad
    assert serder.verstr == vs
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
    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=kind)

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

    serder = sectattr(attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None  # since said not sad
    assert serder.verstr == vs
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

    serder = sectattr(attribute=attrSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee  # since sad
    assert serder.verstr == vs
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
    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=kind)

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

    serder = sectattr(attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None  # since said not sad
    assert serder.verstr == vs
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

    serder = sectattr(attribute=attrSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee  # since sad
    assert serder.verstr == vs
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
    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=kind)

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

    serder = sectedge(edge=edgeSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSaid
    assert serder.verstr == vs
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

    serder = sectedge(edge=edgeSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSad
    assert serder.verstr == vs
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
    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=kind)

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

    serder = sectedge(edge=edgeSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSaid
    assert serder.verstr == vs
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

    serder = sectedge(edge=edgeSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['e'] == edgeSad
    assert serder.verstr == vs
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
    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=kind)

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

    serder = sectrule(rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSaid
    assert serder.verstr == vs
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

    serder = sectrule(rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSad
    assert serder.verstr == vs
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
    compactor = Compactor(mad=mad, makify=True, compactify=True, kind=kind)

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

    serder = sectrule(rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSaid
    assert serder.verstr == vs
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

    serder = sectrule(rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.sad['r'] == ruleSad
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


def test_aggregate_section():
    """Test aggregate agg section message"""

    # setup AEL
    # Test with all non-nested value types
    rawsalt = b'0saltnonceblinded'
    uuid0 = Noncer(raw=rawsalt).qb64
    assert uuid0 == '0AAwc2FsdG5vbmNlYmxpbmRl'

    rawsalt = b'1saltnonceblinded'
    uuid1 = Noncer(raw=rawsalt).qb64
    assert uuid1 == '0AAxc2FsdG5vbmNlYmxpbmRl'

    rawsalt = b'2saltnonceblinded'
    uuid2 = Noncer(raw=rawsalt).qb64
    assert uuid2 == '0AAyc2FsdG5vbmNlYmxpbmRl'

    rawsalt = b'3saltnonceblinded'
    uuid3 = Noncer(raw=rawsalt).qb64
    assert uuid3 == '0AAzc2FsdG5vbmNlYmxpbmRl'

    issuee = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"

    att0 = \
    {
        'd': '',
        'u': uuid0,
        'issuee': issuee,
    }

    att1 = \
    {
        'd': '',
        'u': uuid1,
        'name': "Betty Boop",
    }

    att2 = \
    {
        'd': '',
        'u': uuid2,
        'role': "entertainment",
    }

    att3 = \
    {
        'd': '',
        'u': uuid3,
        'location': "lake mansion",
    }

    iael = ['', att0, att1, att2, att3]  # agid is empty

    assert iael == \
    [
        '',
        {
            'd': '',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': '',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': '',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': '',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    # Test with JSON serialization
    kind = Kinds.json
    aggor = Aggor(ael=iael, makify=True, kind=kind)

    aggrAgid = aggor.agid
    aggrAel = aggor.ael
    assert aggrAgid == 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH'  # json
    assert aggrAel == \
    [
        'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        {
            'd': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': 'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': 'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    # Test using agid
    said = 'EAA24lJAsvpdvcJdqj5oWVTB0ElRyQFyBxvV8_5ZL8K3'
    vs = 'ACDCCAACAAJSONAACL.'
    size = 139

    serder = sectaggr(aggregate=aggrAgid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.aggreg == aggrAgid

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using Aggor Ael list
    said = 'EIq6Nl0Cn-mgkmfn0p8ZhXlhEssftHMHNptf522XLk8d'
    vs = 'ACDCCAACAAJSONAAJa.'
    size = 602

    serder = sectaggr(aggregate=aggrAel, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.aggreg == aggrAel
    assert serder.aggreg[0] == aggrAgid

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with CESR serialization
    kind = Kinds.cesr
    aggor = Aggor(ael=iael, makify=True, kind=kind)

    aggrAgid = aggor.agid
    aggrAel = aggor.ael
    assert aggrAgid == 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu'  #CESR
    assert aggrAel == \
    [
        'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        {
            'd': 'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': 'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    # Test using agid
    said = 'EFE-J9fxo-L_VDrTGubv5I8B9tX6QgHHxDt_IEfKcMlr'
    vs = 'ACDCCAACAACESRAABs.'
    size = 108

    serder = sectaggr(aggregate=aggrAgid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.aggreg == aggrAgid

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test using Aggor Ael list
    said = 'ED1XsqGtEawsyoVdDL2Y2Yh3qYBL3jdzllTLVmH8PG6l'
    vs = 'ACDCCAACAACESRAAI8.'
    size = 572

    serder = sectaggr(aggregate=aggrAel, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.aggreg == aggrAel

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    """Done Test"""


def test_acdcagg_message():
    """Test acg acdc message"""

    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    regid = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'

    rawsalt = b'abcdefghijklmmop'
    uuid = Noncer(raw=rawsalt).qb64
    assert uuid == '0ABhYmNkZWZnaGlqa2xtbW9w'

    kind = Kinds.json
    # Assign JSON versions of section values
    schemaSaid = 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO'# json
    schemaSad = \
    {
        '$id': 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACG Default Schema',
        'description': 'Default JSON Schema for acg ACDC.',
        'credentialType': 'ACDC_acg_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'A', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
                       'd': {'description': 'Message SAID', 'type': 'string'},
                       'u': {'description': 'Message UUID', 'type': 'string'},
                       'i': {'description': 'Issuer AID', 'type': 'string'},
                       'rd': {'description': 'Registry SAID', 'type': 'string'},
                       's': {'description': 'Schema Section',
                             'oneOf': [{'description': 'Schema Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Schema Section',
                                        'type': 'object'}]},
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    aggrAgid = 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH'  # json
    aggrAel = \
    [
        'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        {
            'd': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': 'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': 'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    edgeSaid = 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF'
    edgeSad = \
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

    ruleSaid = 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    ruleSad = \
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

    # Test with JSON serialization

    # test with empty sections
    said = 'EA14m3AVPhBe1VbLwLW_djyEMb9J_XVJzfQEl1fB71Vu'
    vs = 'ACDCCAACAAJSONAADi.'
    size = 226
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, schema=schemaSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.schema == schemaSaid
    assert serder.aggreg == []
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test some defaults
    said = 'EPpxxXt92XLnOTo31r0g9fyKCfH6Sq79x5SaqKD08JxD'
    vs = 'ACDCCAACAAJSONAALd.'
    size = 733
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, schema=schemaSaid,
                     aggregate=aggrAel, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAel
    assert serder.aggreg[0] == aggrAgid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAALd.',
        't': 'acg',
        'd': 'EPpxxXt92XLnOTo31r0g9fyKCfH6Sq79x5SaqKD08JxD',
        'u': '',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO',
        'A':
        [
            'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
            {
                'd': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
                'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
                'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
            },
            {
                'd': 'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
                'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
                'name': 'Betty Boop'
            },
            {
                'd': 'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
                'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
                'role': 'entertainment'
            },
            {
                'd': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
                'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
                'location': 'lake mansion'
            }
        ],
        'e': {},
        'r': {}
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test stable SAID
    vs = 'ACDCCAACAAJSONAAEO.'
    size = 270
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, schema=schemaSaid,
                     aggregate=aggrAgid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAEO.',
        't': 'acg',
        'd': 'EPpxxXt92XLnOTo31r0g9fyKCfH6Sq79x5SaqKD08JxD',
        'u': '',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO',
        'A': 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        'e': {},
        'r': {}
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad


    # test that compactified said are stable
    said = 'ECtrN424rXGIEwbqcKp61lF7LDZBhpVL5xCUo4mA1JAp'
    vs = 'ACDCCAACAAJSONAAc2.'
    size = 1846
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAel
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAc2.',
        't': 'acg',
        'd': 'ECtrN424rXGIEwbqcKp61lF7LDZBhpVL5xCUo4mA1JAp',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO',
        'A': ['EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
              {'d': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
               'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
               'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'},
              {'d': 'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
               'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
               'name': 'Betty Boop'},
              {'d': 'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
               'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
               'role': 'entertainment'},
              {'d': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
               'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
               'location': 'lake mansion'}
              ],
        'e': {'d': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EKJGcxOlhz08bQ9IUukIKl19pPmKpZ81RelPncz29xL2',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'EO6KOA3fmGtIW65F66oHNMmYOh6x4i8tGJJI0XwRAx9w',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
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
    cvs = 'ACDCCAACAAJSONAAGq.'
    csize = 426
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       aggregate=aggrAgid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAGq.',
        't': 'acg',
        'd': 'ECtrN424rXGIEwbqcKp61lF7LDZBhpVL5xCUo4mA1JAp',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EIgmaDpd1IHrG76EEMkrBbmUJ7xeIl7680PKWVtdebyO',
        'A': 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        'e': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcagg(issuer=issuer, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad
    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=Ilks.acg,
        uuid=uuid, regid=regid, schema=schemaSad, aggregate=aggrAel,
        edge=edgeSad, rule=ruleSad, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == Ilks.acg
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == regid
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == None
    assert acdc.aggreg == aggrAgid
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'EEtnZ6mVdz29lBcP18eT0_UnbzbusjygYhgrF98jhO-t'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att == None

    assert agg.said == 'EIq6Nl0Cn-mgkmfn0p8ZhXlhEssftHMHNptf522XLk8d'
    assert agg.sad['A'] == aggrAel
    assert agg.sad['A'][0] == aggrAgid

    assert edg.said == 'EOeLqwd8pwwtE3EgVmjjq_OlYM3emWw0i-d73eydPffX'
    assert edg.sad['e'] == edgeSad
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EGqdBnWd5r-S6oiT2xQb1zK5DCxQH587bUJRC31jg4RE'
    assert rul.sad['r'] == ruleSad
    assert rul.sad['r']['d'] == ruleSaid

    # Test with CESR
    kind = Kinds.cesr

    # Assign CESR versions of section values
    schemaSaid = 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl' # cesr
    schemaSad = \
    {
        '$id': 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACG Default Schema',
        'description': 'Default JSON Schema for acg ACDC.',
        'credentialType': 'ACDC_acg_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 't', 'd', 'u', 'i', 'rd', 's', 'A', 'e', 'r'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
                       'd': {'description': 'Message SAID', 'type': 'string'},
                       'u': {'description': 'Message UUID', 'type': 'string'},
                       'i': {'description': 'Issuer AID', 'type': 'string'},
                       'rd': {'description': 'Registry SAID', 'type': 'string'},
                       's': {'description': 'Schema Section',
                             'oneOf': [{'description': 'Schema Section SAID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Schema Section',
                                        'type': 'object'}]},
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    aggrAgid = 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu' # cesr
    aggrAel = \
    [
        'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        {
            'd': 'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': 'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    edgeSaid = 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw'
    edgeSad = \
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

    ruleSaid = 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    ruleSad = \
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

    # Test with CESR serialization

    # test with empty sections
    said = 'EMgpI_NgNMgylLAq3AtVKCccjIx0_U0CPl3Oy0LgP_O4'
    vs = 'ACDCCAACAACESRAACs.'
    size = 172
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, schema=schemaSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.schema == schemaSaid
    assert serder.aggreg == []
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test some defaults
    said = 'ECKNXaJDHZt7a0yUm5VWcAijH9gvliyfU29ILvcmWKhQ'
    vs = 'ACDCCAACAACESRAAKk.'
    size = 676
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, schema=schemaSaid,
                     aggregate=aggrAel, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAel
    assert serder.aggreg[0] == aggrAgid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAKk.',
        't': 'acg',
        'd': 'ECKNXaJDHZt7a0yUm5VWcAijH9gvliyfU29ILvcmWKhQ',
        'u': '',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl',
        'A':
        [
            'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
            {
                'd': 'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
                'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
                'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
            },
            {
                'd': 'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
                'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
                'name': 'Betty Boop'
            },
            {
                'd': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
                'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
                'role': 'entertainment'
            },
            {
                'd': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
                'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
                'location': 'lake mansion'
            }
        ],
        'e': {},
        'r': {}
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test stable SAID
    vs = 'ACDCCAACAACESRAADU.'
    size = 212
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, schema=schemaSaid,
                     aggregate=aggrAgid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == ''
    assert serder.regid == ''
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAADU.',
        't': 'acg',
        'd': 'ECKNXaJDHZt7a0yUm5VWcAijH9gvliyfU29ILvcmWKhQ',
        'u': '',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': '',
        's': 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl',
        'A': 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        'e': {},
        'r': {}
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad


    # test that compactified said are stable
    said = 'EB96-m8JpjzlXFS2f-ewWdvi8XSleMtpV65OvM03B4e0'
    vs = 'ACDCCAACAACESRAAb4.'
    size = 1784
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAel
    assert serder.aggreg[0] == aggrAgid
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAb4.',
        't': 'acg',
        'd': 'EB96-m8JpjzlXFS2f-ewWdvi8XSleMtpV65OvM03B4e0',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl',
        'A': ['EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
              {'d': 'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
               'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
               'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'},
              {'d': 'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
               'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
               'name': 'Betty Boop'},
              {'d': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
               'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
               'role': 'entertainment'},
              {'d': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
               'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
               'location': 'lake mansion'}
              ],
        'e': {'d': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EFYkMnj7wgn4Vn02F6iniWoCJFf-kCzvkM2wZ7RFzWPC',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'ENCGxUkFQndU5bKtD6o3PRXvl2ZbgmSF-aQU1sVkGudj',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
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
    ilk = Ilks.acg

    serder = acdcagg(issuer=issuer, uuid=uuid, regid=regid, schema=schemaSaid,
                       aggregate=aggrAgid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAFg.',
        't': 'acg',
        'd': 'EB96-m8JpjzlXFS2f-ewWdvi8XSleMtpV65OvM03B4e0',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EB1_MVIk_DSkPNFejlfTEmxf7txIrc9NpUEwV_cLjWnl',
        'A': 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        'e': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test Compactify
    serder = acdcagg(issuer=issuer, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad
    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=Ilks.acg,
        uuid=uuid, regid=regid, schema=schemaSad, aggregate=aggrAel,
        edge=edgeSad, rule=ruleSad, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == Ilks.acg
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == regid
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == None
    assert acdc.aggreg == aggrAgid
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'EGpMnLmUlQENqHgfbQHy8u9JBsmsjpEj5p2ApofHa6ll'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att == None

    assert agg.said == 'ED1XsqGtEawsyoVdDL2Y2Yh3qYBL3jdzllTLVmH8PG6l'
    assert agg.sad['A'] == aggrAel
    assert agg.sad['A'][0] == aggrAgid

    assert edg.said == 'ENjBCWeLQk7iYq3J1DFgPkJ-yfDE_7a0gOE1ecNt9bfw'
    assert edg.sad['e'] == edgeSad
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EN21tftFSBYQ9VuEUGMzyVIMPjTmktXGWdO9-mHq8ThM'
    assert rul.sad['r'] == ruleSad
    assert rul.sad['r']['d'] == ruleSaid

    """Done Test"""


def test_acdcmap_message():
    """Test acm acdc message"""

    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    regid = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'

    rawsalt = b'abcdefghijklmmop'
    uuid = Noncer(raw=rawsalt).qb64
    assert uuid == '0ABhYmNkZWZnaGlqa2xtbW9w'

    # Test with JSON serialization
    kind = Kinds.json

    # Assign JSON versions of section values
    schemaSaid = 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ' # json
    schemaSad = \
    {
        '$id': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACM Default Schema',
        'description': 'Default JSON Schema for acm ACDC.',
        'credentialType': 'ACDC_acm_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 'd', 'i', 's'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    issuee = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"
    attrSaid = 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL'
    attrSad = \
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

    aggrAgid = 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH'
    aggrAel = \
    [
        'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        {
            'd': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': 'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': 'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    edgeSaid = 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF'
    edgeSad = \
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

    ruleSaid = 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    ruleSad = \
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

    # test some defaults
    said = 'EOs1O6nTpQDcNUVj6BIt9asKQJ7IQorstrUIz9Xd4Xm1'
    vs = 'ACDCCAACAAJSONAADx.'
    size = 241
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, schema=schemaSaid,
                     attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == None
    assert serder.regid == None
    assert serder.schema == schemaSaid
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAADx.',
        't': 'acm',
        'd': 'EOs1O6nTpQDcNUVj6BIt9asKQJ7IQorstrUIz9Xd4Xm1',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        's': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        'a': 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL'
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test some defaults default schema
    said = 'EF8b9kWJvke80o9DQJDgWCeeUl_XBCn8iffXU5LI7Omv'
    vs = 'ACDCCAACAAJSONAAeV.'
    size = 1941
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, regid=regid, attribute=attrSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == None
    assert serder.regid == regid
    assert serder.schema == schemaSad
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test that compactified said are stable
    said = 'ELGpFnh85_q0y-GHsvE_o0othvn42kaUQL7ZfLN4llhK'
    vs = 'ACDCCAACAAJSONAAZQ.'
    size = 1616
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, attribute=attrSad, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
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
        'v': 'ACDCCAACAAJSONAAZQ.',
        't': 'acm',
        'd': 'ELGpFnh85_q0y-GHsvE_o0othvn42kaUQL7ZfLN4llhK',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        'a': {'d': 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL',
              'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
              'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
              'role': 'leader',
              'contact': {'d': 'EIZo47mJ29cuWW_UjgBEtcN2vAx5bzoBa-uVWOBH-2QP',
                          'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
                          'first': 'Cloe',
                          'last': 'Cleveridge'}
              },
        'e': {'d': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EKJGcxOlhz08bQ9IUukIKl19pPmKpZ81RelPncz29xL2',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'EO6KOA3fmGtIW65F66oHNMmYOh6x4i8tGJJI0XwRAx9w',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
              'permittedUse': {'d': 'EPH194D7v-QxNt_p9Xkp_bCuYcmWoWy9cZMPHDfx3gxq',
                               'u': '0ADaG7OY1wjaDAE0qHcgNghk',
                               'l': 'Non-commercial'
                               }
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
    cvs = 'ACDCCAACAAJSONAAGq.'
    csize = 426
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
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
        'v': 'ACDCCAACAAJSONAAGq.',
        't': 'acm',
        'd': 'ELGpFnh85_q0y-GHsvE_o0othvn42kaUQL7ZfLN4llhK',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        'a': 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL',
        'e': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, attribute=attrSad, edge=edgeSad,
                     rule=ruleSad, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=ilk,
        uuid=uuid, regid=regid, schema=schemaSad, attribute=attrSad,
        edge=edgeSad, rule=ruleSad, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == ilk
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == regid
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == attrSaid
    assert acdc.aggreg == None
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'EEnM6V486P-eh3f99WMWjZY3ntHXYrJyhpxQDJSbnRyq'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att.said == 'ELy9CPlrrOwyHPWYw81Y4N_0Ff4B2VYprpXlT4WVgIiA'
    assert att.sad['a'] == attrSad
    assert att.sad['a']['d'] == attrSaid

    assert agg == None

    assert edg.said == 'EOeLqwd8pwwtE3EgVmjjq_OlYM3emWw0i-d73eydPffX'
    assert edg.sad['e'] == edgeSad
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EGqdBnWd5r-S6oiT2xQb1zK5DCxQH587bUJRC31jg4RE'
    assert rul.sad['r'] == ruleSad
    assert rul.sad['r']['d'] == ruleSaid

    # Test with aggregate instead of attribute section
    # test that compactified said are stable
    said = 'EB7pb8VGGWC_2wz5wyFZnGeopbW09yAuj3jmgjAJ27jm'
    vs = 'ACDCCAACAAJSONAAc2.'
    size = 1846
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAel
    assert serder.aggreg[0] == aggrAgid
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAc2.',
        't': 'acm',
        'd': 'EB7pb8VGGWC_2wz5wyFZnGeopbW09yAuj3jmgjAJ27jm',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        'A': ['EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
              {'d': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
               'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
               'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'},
              {'d': 'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
               'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
               'name': 'Betty Boop'},
              {'d': 'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
               'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
               'role': 'entertainment'},
              {'d': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
               'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
               'location': 'lake mansion'}
              ],
        'e': {'d': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EKJGcxOlhz08bQ9IUukIKl19pPmKpZ81RelPncz29xL2',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'EO6KOA3fmGtIW65F66oHNMmYOh6x4i8tGJJI0XwRAx9w',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
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
    cvs = 'ACDCCAACAAJSONAAGq.'
    csize = 426
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid, schema=schemaSaid,
                       aggregate=aggrAgid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAGq.',
        't': 'acm',
        'd': 'EB7pb8VGGWC_2wz5wyFZnGeopbW09yAuj3jmgjAJ27jm',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        'A': 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        'e': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAgid, edge=edgeSad,
                     rule=ruleSad, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == None
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=ilk,
        uuid=uuid, regid=regid, schema=schemaSad, aggregate=aggrAel,
        edge=edgeSad, rule=ruleSad, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == ilk
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == regid
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == None
    assert acdc.aggreg == aggrAgid
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'EEnM6V486P-eh3f99WMWjZY3ntHXYrJyhpxQDJSbnRyq'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att == None

    assert agg.said == 'EIq6Nl0Cn-mgkmfn0p8ZhXlhEssftHMHNptf522XLk8d'
    assert agg.sad['A'] == aggrAel
    assert agg.sad['A'][0] == aggrAgid

    assert edg.said == 'EOeLqwd8pwwtE3EgVmjjq_OlYM3emWw0i-d73eydPffX'
    assert edg.sad['e'] == edgeSad
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EGqdBnWd5r-S6oiT2xQb1zK5DCxQH587bUJRC31jg4RE'
    assert rul.sad['r'] == ruleSad
    assert rul.sad['r']['d'] == ruleSaid

    # private metadata variant empty top-level uuid field
    said = 'EJzD7XSB0EUswRevNRTIypRIsqO_MDrWFvpHeHj6--26'
    vs = 'ACDCCAACAAJSONAAGI.'
    size = 392
    ilk = None

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid="", regid=regid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
    assert serder.issuer == issuer
    assert serder.uuid == ""
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAAJSONAAGI.',
        'd': 'EJzD7XSB0EUswRevNRTIypRIsqO_MDrWFvpHeHj6--26',
        'u': '',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EPrsJF2BXyDUgDCVbGURsGNwCZjyrxD5M2qnBmhvoZYQ',
        'a': 'ENd9eAjJpBQmCmixtzw8V9OI7_1FjrfHiFiYXDzoakRL',
        'e': 'EIA0GPeLyc6RhpPRs0dJpuYxBlb4wo0WkylcYjeygCZF',
        'r': 'EBZrih6_lQczs-QP6HieUGnFrnTftwdnz4DnMVhTOE7v'
    }


    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with CESR serialization
    kind = Kinds.cesr

    # Assign CESR versions of section values
    schemaSaid = 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK'  # cesr
    schemaSad = \
    {
        '$id': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'title': 'ACM Default Schema',
        'description': 'Default JSON Schema for acm ACDC.',
        'credentialType': 'ACDC_acm_message',
        'version': '2.0.0',
        'type': 'object',
        'required': ['v', 'd', 'i', 's'],
        'properties': {'v': {'description': 'ACDC version string', 'type': 'string'},
                       't': {'description': 'Message type', 'type': 'string'},
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
                       'A': {'description': 'Aggregate Section',
                             'oneOf': [{'description': 'Aggregate Section AGID',
                                        'type': 'string'},
                                       {'description': 'Uncompacted Aggregate Section',
                                        'type': 'array'}]},
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

    issuee = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"
    attrSaid = 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-'  # cesr
    attrSad = \
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

    aggrAgid = 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu'
    aggrAel = \
    [
        'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        {
            'd': 'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        {
            'd': 'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
            'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
            'name': 'Betty Boop'
        },
        {
            'd': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        {
            'd': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]

    edgeSaid = 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw'  # cesr
    edgeSad = \
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

    ruleSaid = 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'  # cesr
    ruleSad = \
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


    # test some defaults
    said = 'EFiwa7kea0Pv5QZ2MwM5C_iH7lLTkZFlvDl5nj_WkGOz'
    vs = 'ACDCCAACAACESRAADc.'
    size = 220
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, schema=schemaSaid,
                     attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == None
    assert serder.regid == None
    assert serder.schema == schemaSaid
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAADc.',
        't': 'acm',
        'd': 'EFiwa7kea0Pv5QZ2MwM5C_iH7lLTkZFlvDl5nj_WkGOz',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-'
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test some defaults default schema
    said = 'ECn7BmaXh5srXOx6PfCTsaWBQ4m_K43Ziboe8FjvQORx'
    vs = 'ACDCCAACAACESRAAho.'
    size = 2152
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, regid=regid, attribute=attrSad,
                     kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == None
    assert serder.regid == regid
    assert serder.schema == schemaSad
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test that compactified said are stable
    said = 'EINdarGoQL780jeFl5A71J0ZQgn-zFLSiuPkhIv4piLf'
    vs = 'ACDCCAACAACESRAAYw.'
    size = 1584
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, attribute=attrSad, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
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
        'v': 'ACDCCAACAACESRAAYw.',
        't': 'acm',
        'd': 'EINdarGoQL780jeFl5A71J0ZQgn-zFLSiuPkhIv4piLf',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': {'d': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-',
              'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
              'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
              'role': 'leader',
              'contact': {'d': 'EKkFu2dX274cXnfaXh0OWZj1LnaUrjmDKAS_ozGBZ9Pz',
                          'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
                          'first': 'Cloe',
                          'last': 'Cleveridge'}
              },
        'e': {'d': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EFYkMnj7wgn4Vn02F6iniWoCJFf-kCzvkM2wZ7RFzWPC',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'ENCGxUkFQndU5bKtD6o3PRXvl2ZbgmSF-aQU1sVkGudj',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
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
    cvs = 'ACDCCAACAACESRAAGI.'
    csize = 392
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
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
        'v': 'ACDCCAACAACESRAAGI.',
        't': 'acm',
        'd': 'EINdarGoQL780jeFl5A71J0ZQgn-zFLSiuPkhIv4piLf',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-',
        'e': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }
    csad = serder.sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, attribute=attrSad, edge=edgeSad,
                     rule=ruleSad, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test sectionate
    acdc, sch, att, agg, edg, rul = sectionate(issuer=issuer, ilk=ilk,
        uuid=uuid, regid=regid, schema=schemaSad, attribute=attrSad,
        edge=edgeSad, rule=ruleSad, kind=kind, compactify=True)

    assert acdc.kind == kind
    assert acdc.said == said  # stable said of compact ACDC same as uncompacted
    assert acdc.ilk == ilk
    assert acdc.size == csize
    assert acdc.verstr == cvs
    assert acdc.issuer == issuer
    assert acdc.uuid == uuid
    assert acdc.regid == regid
    assert acdc.issuee == None
    assert acdc.schema == schemaSaid
    assert acdc.attrib == attrSaid
    assert acdc.aggreg == None
    assert acdc.edge == edgeSaid
    assert acdc.rule == ruleSaid
    assert acdc.sad == csad

    assert sch.said == 'EIbdy3ZY6DqTGUhi_ubPo2cgnbQL-ekp5YsgABrK6cx6'
    assert sch.sad['s'] == schemaSad
    assert sch.sad['s']['$id'] == schemaSaid

    assert att.said == 'EPc8jTHBrPfDm9l8Rj4wbi3R-mYVlBRI8P_D3RO14aoI'
    assert att.sad['a'] == attrSad
    assert att.sad['a']['d'] == attrSaid

    assert agg == None

    assert edg.said == 'ENjBCWeLQk7iYq3J1DFgPkJ-yfDE_7a0gOE1ecNt9bfw'
    assert edg.sad['e'] == edgeSad
    assert edg.sad['e']['d'] == edgeSaid

    assert rul.said == 'EN21tftFSBYQ9VuEUGMzyVIMPjTmktXGWdO9-mHq8ThM'
    assert rul.sad['r'] == ruleSad
    assert rul.sad['r']['d'] == ruleSaid


    # Test implicity acm with ilk=None
    # test some defaults
    said = 'EJO5x17vRMfipCQTdniSk---mLLfslObQIvBS1bj_uIC'
    vs = 'ACDCCAACAACESRAADU.'
    size = 212
    ilk = None

    serder = acdcmap(issuer=issuer, ilk=ilk, schema=schemaSaid,
                     attribute=attrSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == None
    assert serder.regid == None
    assert serder.schema == schemaSaid
    assert serder.sad['a'] == attrSaid
    assert serder.issuee == None
    assert serder.verstr == vs
    assert serder.size == size
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAADU.',
        'd': 'EJO5x17vRMfipCQTdniSk---mLLfslObQIvBS1bj_uIC',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-'
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test some defaults default schema
    said = 'EAo7GMv7EoXK5n9WKd8epTYfDBFlrfglaxHKkUl8jZZd'
    vs = 'ACDCCAACAACESRAAhg.'
    size = 2144
    ilk = None

    serder = acdcmap(issuer=issuer, ilk=ilk, regid=regid, attribute=attrSad,
                     kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.issuer == issuer
    assert serder.uuid == None
    assert serder.regid == regid
    assert serder.schema == schemaSad
    assert serder.sad['a'] == attrSad
    assert serder.issuee == issuee
    assert serder.verstr == vs
    assert serder.size == size

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test that compactified said are stable
    said = 'ELuZYAjFP9_XZql1k1YLAxg7u8DSLbSv7MqB-Z7BSg2L'
    vs = 'ACDCCAACAACESRAAYo.'
    size = 1576
    ilk = None

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, attribute=attrSad, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
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
        'v': 'ACDCCAACAACESRAAYo.',
        'd': 'ELuZYAjFP9_XZql1k1YLAxg7u8DSLbSv7MqB-Z7BSg2L',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': {'d': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-',
              'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
              'i': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C',
              'role': 'leader',
              'contact': {'d': 'EKkFu2dX274cXnfaXh0OWZj1LnaUrjmDKAS_ozGBZ9Pz',
                          'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
                          'first': 'Cloe',
                          'last': 'Cleveridge'}
              },
        'e': {'d': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EFYkMnj7wgn4Vn02F6iniWoCJFf-kCzvkM2wZ7RFzWPC',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'ENCGxUkFQndU5bKtD6o3PRXvl2ZbgmSF-aQU1sVkGudj',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
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
    cvs = 'ACDCCAACAACESRAAGA.'
    csize = 384
    ilk = None

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
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
        'v': 'ACDCCAACAACESRAAGA.',
        'd': 'ELuZYAjFP9_XZql1k1YLAxg7u8DSLbSv7MqB-Z7BSg2L',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-',
        'e': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # private metadata variant empty top-level uuid field
    said = 'EP77Cz6zmZ14_uLALBCWbP1dwtwW6S1iQMx9Ceaqwpy_'
    vs = 'ACDCCAACAACESRAAFs.'
    size = 364
    ilk = None

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid="", regid=regid, schema=schemaSaid,
                       attribute=attrSaid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
    assert serder.issuer == issuer
    assert serder.uuid == ""
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.attrib == attrSaid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAFs.',
        'd': 'EP77Cz6zmZ14_uLALBCWbP1dwtwW6S1iQMx9Ceaqwpy_',
        'u': '',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'a': 'EEsqwWsxvtDaiADWKruivw6bKvZz8P6N4fdhtjAeYLO-',
        'e': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }


    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # Test with aggregate instead of attribute section
    # test that compactified said are stable
    said = 'EAZQ6sQ2eusq9fa0MpvfZ6WKr8Tcz1WUA8rRGEPoZMLb'
    vs = 'ACDCCAACAACESRAAcg.'
    size = 1824
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == size
    assert serder.verstr == vs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAel
    assert serder.aggreg[0] == aggrAgid
    assert serder.edge['d'] == edgeSaid
    assert serder.rule['d'] == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAcg.',
        't': 'acm',
        'd': 'EAZQ6sQ2eusq9fa0MpvfZ6WKr8Tcz1WUA8rRGEPoZMLb',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'A': ['EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
              {'d': 'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
               'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
               'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'},
              {'d': 'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
               'u': '0AAxc2FsdG5vbmNlYmxpbmRl',
               'name': 'Betty Boop'},
              {'d': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
               'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
               'role': 'entertainment'},
              {'d': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
               'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
               'location': 'lake mansion'}
              ],
        'e': {'d': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
              'u': '0AwjaDAE0qHcgNghkDaG7OY1',
              'work': {'d': 'EFYkMnj7wgn4Vn02F6iniWoCJFf-kCzvkM2wZ7RFzWPC',
                       'u': '0ANghkDaG7OY1wjaDAE0qHcg',
                       'n': 'ECJnFJL5OuQPyM5K0neuniccMBdXt3gIXOf2BBWNHdSX',
                       's': 'ELIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzw'},
              'play': {'d': 'ENCGxUkFQndU5bKtD6o3PRXvl2ZbgmSF-aQU1sVkGudj',
                       'u': '0ADAE0qHcgNghkDaG7OY1wja',
                       'n': 'EK0neuniccMBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5',
                       's': 'EHwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_N',
                       'o': 'NI2I'}
              },
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
                                                      'l': 'No Liability'}
                              },
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
    cvs = 'ACDCCAACAACESRAAGI.'
    csize = 392
    ilk = Ilks.acm

    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid, schema=schemaSaid,
                       aggregate=aggrAgid, edge=edgeSaid, rule=ruleSaid, kind=kind)
    assert serder.kind == kind
    assert serder.said == said  # stable said of compact ACDC same as uncompacted
    assert serder.ilk == ilk
    assert serder.size == csize != size  # but size not stable not same as uncompacted
    assert serder.verstr == cvs != vs  # but vs not stable not same as uncompacted
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == \
    {
        'v': 'ACDCCAACAACESRAAGI.',
        't': 'acm',
        'd': 'EAZQ6sQ2eusq9fa0MpvfZ6WKr8Tcz1WUA8rRGEPoZMLb',
        'u': '0ABhYmNkZWZnaGlqa2xtbW9w',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        'rd': 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq',
        's': 'EEVFmM1Q_obsLcCCeY0G2wAAGJZUNAzPAwNT5N13bIeK',
        'A': 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        'e': 'EFqscUD0BBVdNbciVYzKIfWu5S7pzJr_O3tUufEQjDTw',
        'r': 'EK0trDLAjntXMNHOxMm62D-3QvKJvhOFLHIN3XbakYl-'
    }
    csad = serder.sad  # compact sad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad

    # test compactify
    serder = acdcmap(issuer=issuer, ilk=ilk, uuid=uuid, regid=regid,
                     schema=schemaSaid, aggregate=aggrAel, edge=edgeSad,
                     rule=ruleSad, kind=kind, compactify=True)
    assert serder.kind == kind
    assert serder.said == said
    assert serder.ilk == ilk
    assert serder.size == csize
    assert serder.verstr == cvs
    assert serder.issuer == issuer
    assert serder.uuid == uuid
    assert serder.regid == regid
    assert serder.issuee == None
    assert serder.schema == schemaSaid
    assert serder.aggreg == aggrAgid
    assert serder.edge == edgeSaid
    assert serder.rule == ruleSaid
    assert serder.sad == csad

    # test round trip
    raw = serder.raw
    sad = serder.sad
    serder = SerderACDC(raw=raw)
    assert serder.said == said
    assert serder.raw == raw
    assert serder.sad == sad


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
    test_aggregate_section()
    test_acdcagg_message()
    test_acdcmap_message()
