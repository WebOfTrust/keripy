# -*- encoding: utf-8 -*-
"""
tests.vc.test_messaging module

"""

import pytest

from keri.kering import Protocols, Kinds, Ilks, Vrsn_2_0
from keri.vc.messaging import regcept, blindate, update, mapACDC
from keri.core import GenDex
from keri.core import SerderACDC, BlindState, Blinder

def test_regcept_message():
    """Test regcept message"""
    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    nonce = '0AAxyHwW6htOZ_rANOaZb2N2'
    stamp = '2020-08-22T17:50:09.988921+00:00'
    said = 'EPC9M2c8LnocZRbaLC-nk2IC06pc-xlhipwgaoCdK_Wq'

    # test default kind JSON
    serder = regcept(issuer=issuer, nonce=nonce, stamp=stamp)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.json

    assert serder.ilk == Ilks.rip
    assert serder.said == said
    assert serder.uuid == nonce
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
    serder = regcept(issuer=issuer, nonce=nonce, stamp=stamp, kind=Kinds.cesr)
    assert serder.proto == Protocols.acdc
    assert serder.pvrsn == Vrsn_2_0
    assert serder.genus == GenDex.KERI
    assert serder.gvrsn == Vrsn_2_0
    assert serder.kind == Kinds.cesr

    assert serder.ilk == Ilks.rip
    assert serder.said == said
    assert serder.uuid == nonce
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
    assert serder.uuid == nonce
    assert serder.issuer == issuer
    assert serder.stamp == stamp
    """Done Test"""


def test_blindate_message():
    """Test blindate message"""
    nonce = 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
    tsaid = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
    tstate = 'issued'
    crew = BlindState(d='', u=nonce, td=tsaid, ts=tstate)
    blinder = Blinder(crew=crew, makify=True)  # computes said
    blind = blinder.said

    regid = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    prior = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'
    stamp = '2020-08-23T18:06:10.988921+00:00'
    said = 'EDGouTZMjO0HbHefvBrYtpWTY6y5TykF2LDgaZJNiJjB'

    # test default kind JSON and default sn=1
    serder = blindate(regid=regid, prior=prior, blind=blind, stamp=stamp)
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
    serder = blindate(regid=regid, prior=prior, blind=blind, stamp=stamp, kind=Kinds.cesr)
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


def test_acdc_messages():
    """Test acdc messages v2"""


    """Done Test"""

if __name__ == '__main__':
    test_regcept_message()
    test_blindate_message()
    test_update_message()
    test_acdc_messages()
