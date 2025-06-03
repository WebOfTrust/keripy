# -*- coding: utf-8 -*-
"""
tests.core.test_mapping module

"""
import json
import cbor2 as cbor

import pytest

from keri.kering import Colds
from keri.core import Mapper, Diger


def test_mapper_basic():
    """Test Mapper class"""
    mapper = Mapper()  # default empty map
    assert mapper.mad == {}
    assert mapper.qb64 == '-IAA'
    assert mapper.qb64b == b'-IAA'
    assert mapper.qb2 == b'\xf8\x80\x00'
    assert mapper.count == 1
    assert mapper.size == 4
    assert mapper.byteCount() == 4
    assert mapper.byteCount(Colds.bny) == 3

    # Test with all non-nested value types
    mad = dict(a=1, b=True, c="hello", d=15.34, e=False, f=None)
    qb64 = '-IAQ0J_a6HABAAA10J_b1AAM0J_c0L_hello0J_d6HACAAA15p340J_e1AAL0J_f1AAK'
    qb64b = b'-IAQ0J_a6HABAAA10J_b1AAM0J_c0L_hello0J_d6HACAAA15p340J_e1AAL0J_f1AAK'
    qb2 = (b'\xf8\x80\x10\xd0\x9f\xda\xe8p\x01\x00\x005\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f'
            b'\xdc\xd0\xbf\xe1zYh\xd0\x9f\xdd\xe8p\x02\x00\x005\xe6\x9d\xf8\xd0'
            b'\x9f\xde\xd4\x00\x0b\xd0\x9f\xdf\xd4\x00\n')
    count = 17
    size = 68
    bc = 51

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    jser = json.dumps(mad)
    assert jser == '{"a": 1, "b": true, "c": "hello", "d": 15.34, "e": false, "f": null}'
    assert len(jser) == 68

    cser = cbor.dumps(mad)
    assert len(cser) == 32

    # test round trips
    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # test strip
    ims = bytearray(qb64b)
    mapper = Mapper(qb64b=ims, strip=True)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert ims == bytearray(b'')  # stripped

    ims = bytearray(qb2)
    mapper = Mapper(qb2=ims, strip=True)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert ims == bytearray(b'')  # stripped


    # test with nested value types
    mad = dict(a="Hi There", nest=dict(a=[True, False, None], b=dict(z=True)),
               icky=[["z", "y"], dict(d=5), "abc"])
    qb64 = ('-IAc0J_a5BADAEhpIFRoZXJl1AAFnest-IAJ0J_a-JAD1AAM1AAL1AAK0J_b-IAC'
            '0J_z1AAM1AAFicky-JAI-JAC0J_z0J_y-IAD0J_d6HABAAA5Xabc')
    qb64b = (b'-IAc0J_a5BADAEhpIFRoZXJl1AAFnest-IAJ0J_a-JAD1AAM1AAL1AAK0J_b-IAC'
            b'0J_z1AAM1AAFicky-JAI-JAC0J_z0J_y-IAD0J_d6HABAAA5Xabc')
    qb2 = (b'\xf8\x80\x1c\xd0\x9f\xda\xe4\x10\x03\x00Hi There\xd4\x00\x05\x9d\xeb-'
            b'\xf8\x80\t\xd0\x9f\xda\xf8\x90\x03\xd4\x00\x0c\xd4\x00\x0b\xd4\x00\n\xd0\x9f'
            b'\xdb\xf8\x80\x02\xd0\x9f\xf3\xd4\x00\x0c\xd4\x00\x05\x89\xc92'
            b'\xf8\x90\x08\xf8\x90\x02\xd0\x9f\xf3\xd0\x9f\xf2\xf8\x80\x03\xd0'
            b'\x9f\xdd\xe8p\x01\x00\x009]\xa6\xdc')

    count = 29
    size = 116
    bc = 87

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    jser = json.dumps(mad)
    assert jser == ('{"a": "Hi There", "nest": {"a": [true, false, null], "b": {"z": true}}, '
                    '"icky": [["z", "y"], {"d": 5}, "abc"]}')
    assert len(jser) == 110

    cser = cbor.dumps(mad)
    assert len(cser) == 49

    # test round trips
    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # bigger labels and values
    mad = dict(lastname='anderson')
    qb64 =  '-IAG1AANlastname1AANanderson'
    qb64b =  b'-IAG1AANlastname1AANanderson'
    qb2 = b"\xf8\x80\x06\xd4\x00\r\x95\xab-\x9d\xa9\x9e\xd4\x00\rjw^\xae\xca'"
    count = 7
    size = 28
    bc = 21

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    jser = json.dumps(mad)
    assert jser == '{"lastname": "anderson"}'
    assert len(jser) == 24

    cser = cbor.dumps(mad)
    assert len(cser) == 19

    # test round trips
    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # Test with valid complete primitives in qb64 format for values
    # create something to digest and verify
    ser = b'abcdefghijklmnopqrstuvwxyz0123456789'
    diger = Diger(ser=ser)  # default code is  Blake3_256
    assert diger.qb64b == b'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'

    mad = dict(a=diger.qb64)
    qb64 =  '-IAM0J_aELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    qb64b =  b'-IAM0J_aELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    qb2 = (b'\xf8\x80\x0c\xd0\x9f\xda\x10\xb0\xb9/x\x81T>\xfbw\xf3\x18m\x81\x86\tD '
                          b'\xa9\x00c\xbbZ8\xc7U\x1d\xfb=\xac/\xeb\xb1')
    count = 13
    size = 52
    bc = 39

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # test round trips
    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc


    """Done Test"""

if __name__ == "__main__":
    test_mapper_basic()
