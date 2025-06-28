# -*- encoding: utf-8 -*-
"""
tests.vc.test_messaging module

"""

import pytest

from keri.kering import Protocols, Kinds, Ilks, Vrsn_2_0
from keri.vc.messaging import regcept, mapACDC
from keri.core import GenDex
from keri.core import SerderACDC

def test_regcept_message():
    """Test regcept message"""
    issuer = 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ'
    nonce = '0AAxyHwW6htOZ_rANOaZb2N2'
    stamp = '2020-08-22T17:50:09.988921+00:00'
    said = 'EG__x9JRLSY6IXDwMnnojrrxC2GzXFpdMeLlk0qIORAL'

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
        'd': 'EG__x9JRLSY6IXDwMnnojrrxC2GzXFpdMeLlk0qIORAL',
        'u': '0AAxyHwW6htOZ_rANOaZb2N2',
        'i': 'EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ',
        's': '0',
        'dt': '2020-08-22T17:50:09.988921+00:00'
    }

    assert serder.raw == (b'{"v":"ACDCCAACAAJSONAADa.","t":"rip","d":"EG__x9JRLSY6IXDwMnnojrrxC2GzXFpdMe'
                          b'Llk0qIORAL","u":"0AAxyHwW6htOZ_rANOaZb2N2","i":"EA2X8Lfrl9lZbCGz8cfKIvM_cqLy'
                          b'TYVLSFLhnttezlzQ","s":"0","dt":"2020-08-22T17:50:09.988921+00:00"}')

    # Test CESR
    said = 'EM1hJSHgqklxe-SFOWkGRKRTIzbSh7yd0inf8RZ8paR8'

    # test default kind JSON
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
        's': '0',
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



def test_acdc_messages():
    """Test acdc messages v2"""


    """Done Test"""

if __name__ == '__main__':
    test_regcept_message()
    test_acdc_messages()
