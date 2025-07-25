# -*- coding: utf-8 -*-
"""
tests.core.test_mapping module

"""
import copy
import json
import cbor2 as cbor
import msgpack

import pytest

from dataclasses import dataclass, astuple, asdict

from keri.kering import (Colds, Kinds,
                         SerializeError, DeserializeError, InvalidValueError)
from keri.core import (EscapeDex, Labeler, Mapper, Compactor, Aggor,
                       DigDex, Diger, DecDex, Decimer, Noncer)


def test_escape_dex():
    """Test EscapeCodex"""
    assert asdict(EscapeDex) == \
    {
        'Escape': '1AAO',
        'Null': '1AAK',
        'No': '1AAL',
        'Yes': '1AAM',
        'Decimal_L0': '4H',
        'Decimal_L1': '5H',
        'Decimal_L2': '6H',
        'Decimal_Big_L0': '7AAH',
        'Decimal_Big_L1': '8AAH',
        'Decimal_Big_L2': '9AAH',
        'Empty': '1AAP',
        'Tag1': '0J',
        'Tag2': '0K',
        'Tag3': 'X',
        'Tag4': '1AAF',
        'Tag5': '0L',
        'Tag6': '0M',
        'Tag7': 'Y',
        'Tag8': '1AAN',
        'Tag9': '0N',
        'Tag10': '0O',
        'Tag11': 'Z',
        'StrB64_L0': '4A',
        'StrB64_L1': '5A',
        'StrB64_L2': '6A',
        'StrB64_Big_L0': '7AAA',
        'StrB64_Big_L1': '8AAA',
        'StrB64_Big_L2': '9AAA',
        'Label1': 'V',
        'Label2': 'W',
        'Bytes_L0': '4B',
        'Bytes_L1': '5B',
        'Bytes_L2': '6B',
        'Bytes_Big_L0': '7AAB',
        'Bytes_Big_L1': '8AAB',
        'Bytes_Big_L2': '9AAB'
    }

    """Done Test"""

def test_mapper_basic():
    """Test Mapper class"""
    mapper = Mapper()  # default empty map
    assert mapper.mad == {}
    assert mapper.said is None
    assert mapper.qb64 == '-IAA'
    assert mapper.raw == mapper.qb64b == b'-IAA'
    assert mapper.qb2 == b'\xf8\x80\x00'
    assert mapper.count == 1
    assert mapper.size == 4
    assert mapper.byteCount() == 4
    assert mapper.byteCount(Colds.bny) == 3
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == False

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
    assert mapper.raw == mapper.qb64b == qb64b
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
    mapper = Mapper(raw=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # test strip
    ims = bytearray(qb64b)
    mapper = Mapper(raw=ims, strip=True)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert ims == bytearray(b'')  # stripped

    ims = bytearray(qb64b)
    mapper = Mapper(qb64b=ims, strip=True)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
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
    assert mapper.raw == mapper.qb64b == qb64b
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
    assert mapper.raw == mapper.qb64b == qb64b
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
    mapper = Mapper(raw=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
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
    assert mapper.raw == mapper.qb64b == qb64b
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
    mapper = Mapper(raw=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
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
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # test round trips
    mapper = Mapper(raw=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64=qb64)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc


    # test bad label
    mad = {"1abc": "Hello",}
    with pytest.raises(SerializeError):
        mapper = Mapper(mad=mad)

    # test bad qb64 due to bad label
    mad = dict(a="bye")
    qb64 =  '-IAC0J_aXbye'
    qb64b =  b'-IAC0J_aXbye'
    qb2 = b'\xf8\x80\x02\xd0\x9f\xda]\xbc\x9e'

    count = 3
    size = 12
    bc = 9

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    bad = '-IAC0J_1Xbye'
    with pytest.raises(DeserializeError):
        mapper = Mapper(qb64=bad)


    # test escape values of field map
    # value is verbatim qb64 of escape code
    mad = dict(a=EscapeDex.Escape)
    assert mad['a'] == '1AAO'
    qb64 =  '-IAD0J_a1AAO1AAO'
    qb64b =  b'-IAD0J_a1AAO1AAO'
    qb2 = b'\xf8\x80\x03\xd0\x9f\xda\xd4\x00\x0e\xd4\x00\x0e'

    count = 4
    size = 16
    bc = 12

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # value is verbatim qb64 of null code
    mad = dict(a=EscapeDex.Null)
    assert mad['a'] == '1AAK'
    qb64 =  '-IAD0J_a1AAO1AAK'
    qb64b =  b'-IAD0J_a1AAO1AAK'
    qb2 = b'\xf8\x80\x03\xd0\x9f\xda\xd4\x00\x0e\xd4\x00\n'

    count = 4
    size = 16
    bc = 12

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # value is verbatim qb64 of No code i.e. boolean False
    mad = dict(a=EscapeDex.No)
    assert mad['a'] == '1AAL'
    qb64 =  '-IAD0J_a1AAO1AAL'
    qb64b =  b'-IAD0J_a1AAO1AAL'
    qb2 = b'\xf8\x80\x03\xd0\x9f\xda\xd4\x00\x0e\xd4\x00\x0b'

    count = 4
    size = 16
    bc = 12

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # value is verbatim qb64 of Yes code i.e. boolean True
    mad = dict(a=EscapeDex.Yes)
    assert mad['a'] == '1AAM'
    qb64 =  '-IAD0J_a1AAO1AAM'
    qb64b =  b'-IAD0J_a1AAO1AAM'
    qb2 = b'\xf8\x80\x03\xd0\x9f\xda\xd4\x00\x0e\xd4\x00\x0c'

    count = 4
    size = 16
    bc = 12

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # value is verbatim qb64 of Decimer qb64
    dqb64 = Decimer(decimal=1).qb64
    mad = dict(a=dqb64)
    assert mad['a'] == '6HABAAA1'
    qb64 =  '-IAE0J_a1AAO6HABAAA1'
    qb64b =  b'-IAE0J_a1AAO6HABAAA1'
    qb2 = b'\xf8\x80\x04\xd0\x9f\xda\xd4\x00\x0e\xe8p\x01\x00\x005'

    count = 5
    size = 20
    bc = 15

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # value is verbatim qb64 of Labeler qb64 as Tag3
    lqb64 = Labeler(text="Pet").qb64
    mad = dict(a=lqb64)
    assert mad['a'] == 'XPet'
    qb64 =  '-IAD0J_a1AAOXPet'
    qb64b =  b'-IAD0J_a1AAOXPet'
    qb2 = b'\xf8\x80\x03\xd0\x9f\xda\xd4\x00\x0e\\\xf7\xad'

    count = 4
    size = 16
    bc = 12

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    # value is verbatim qb64 of Labeler qb64 as Bytes variable length
    lqb64 = Labeler(text="@home").qb64
    mad = dict(a=lqb64)
    assert mad['a'] == '5BACAEBob21l'
    qb64 =  '-IAF0J_a1AAO5BACAEBob21l'
    qb64b =  b'-IAF0J_a1AAO5BACAEBob21l'
    qb2 = b'\xf8\x80\x05\xd0\x9f\xda\xd4\x00\x0e\xe4\x10\x02\x00@home'

    count = 6
    size = 24
    bc = 18

    mapper = Mapper(mad=mad)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size ==size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc



    # Test not strict needed for json schema
    # test with nested value types
    mad = {}
    mad['$1d'] = "Json ID field value"
    mad['nest'] = {'1a': [True, False, None], '1b': {'z': 15,},}

    assert mad == \
    {
        '$1d': 'Json ID field value',
        'nest': \
        {
            '1a': [True, False, None],
            '1b': {'z': 15}
        }
    }

    qb64 = '-IAX4BABJDFk6BAHAABKc29uIElEIGZpZWxkIHZhbHVl1AAFnest-IAK0K1a-JAD1AAM1AAL1AAK0K1b-IAD0J_z5HABAA15'
    qb64b = b'-IAX4BABJDFk6BAHAABKc29uIElEIGZpZWxkIHZhbHVl1AAFnest-IAK0K1a-JAD1AAM1AAL1AAK0K1b-IAD0J_z5HABAA15'
    qb2 = (b'\xf8\x80\x17\xe0\x10\x01$1d\xe8\x10\x07\x00\x00Json ID field valu'
            b'e\xd4\x00\x05\x9d\xeb-\xf8\x80\n\xd0\xadZ\xf8\x90\x03\xd4\x00\x0c\xd4'
            b'\x00\x0b\xd4\x00\n\xd0\xad[\xf8\x80\x03\xd0\x9f\xf3\xe4p\x01\x00\ry')

    count = 24
    size = 96
    bc = 72

    mapper = Mapper(mad=mad, strict=False)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    jser = json.dumps(mad)
    assert jser == ('{"$1d": "Json ID field value", "nest": {"1a": [true, false, null], "1b": '
                    '{"z": 15}}}')
    assert len(jser) == 84

    cser = cbor.dumps(mad)
    assert len(cser) == 45

    # test round trips
    mapper = Mapper(raw=qb64, strict=False)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64=qb64, strict=False)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb64b=qb64b, strict=False)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    mapper = Mapper(qb2=qb2, strict=False)
    assert mapper.mad == mad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == qb64b
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc

    """Done Test"""


def test_mapper_basic_nonnative():
    """Test Mapper class non-native ser/des"""
    mapper = Mapper(kind=Kinds.json)  # default empty map
    assert mapper.mad == {}
    assert mapper.qb64 == '{}'
    assert mapper.raw == mapper.qb64b == b'{}'
    with pytest.raises(ValueError):
        assert mapper.qb2 == b''

    assert mapper.count == None
    assert mapper.size == 2
    with pytest.raises(ValueError):
        assert mapper.byteCount() == 4

    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == False

    # test JSON
    kind = Kinds.json
    # Test with all non-nested value types
    mad = dict(a=1, b=True, c="hello", d=15.34, e=False, f=None)
    raw = b'{"a":1,"b":true,"c":"hello","d":15.34,"e":false,"f":null}'
    size = 57

    mapper = Mapper(mad=mad, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.size == size

    # test round trips
    mapper = Mapper(raw=raw, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == raw
    assert mapper.size == size

    # test with nested
    mad = dict(a="Hi There", nest=dict(a=[True, False, None], b=dict(z=True)),
               icky=[["z", "y"], dict(d=5), "abc"])
    raw = (b'{"a":"Hi There","nest":{"a":[true,false,null],"b":{"z":true}},"icky":[["z","'
           b'y"],{"d":5},"abc"]}')
    size = 95

    mapper = Mapper(mad=mad, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.size == size

    # test round trips
    mapper = Mapper(raw=raw, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == raw
    assert mapper.size == size

    # test CBOR
    kind = Kinds.cbor
    # Test with all non-nested value types
    mad = dict(a=1, b=True, c="hello", d=15.34, e=False, f=None)
    raw = b'\xa6aa\x01ab\xf5acehelload\xfb@.\xae\x14z\xe1G\xaeae\xf4af\xf6'
    size = 32

    mapper = Mapper(mad=mad, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.size == size

    # test round trips
    mapper = Mapper(raw=raw, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == raw
    assert mapper.size == size

    # test with nested
    mad = dict(a="Hi There", nest=dict(a=[True, False, None], b=dict(z=True)),
               icky=[["z", "y"], dict(d=5), "abc"])
    raw = (b'\xa3aahHi Therednest\xa2aa\x83\xf5\xf4\xf6ab\xa1az\xf5dicky\x83\x82aza'
           b'y\xa1ad\x05cabc')
    size = 49

    mapper = Mapper(mad=mad, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.size == size

    # test round trips
    mapper = Mapper(raw=raw, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == raw
    assert mapper.size == size

    # test MGPK
    kind = Kinds.mgpk
    # Test with all non-nested value types
    mad = dict(a=1, b=True, c="hello", d=15.34, e=False, f=None)
    raw = (b'\x86\xa1a\x01\xa1b\xc3\xa1c\xa5hello\xa1d\xcb@.\xae\x14z\xe1G\xae\xa1e'
           b'\xc2\xa1f\xc0')
    size = 32

    mapper = Mapper(mad=mad, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.size == size

    # test round trips
    mapper = Mapper(raw=raw, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == raw
    assert mapper.size == size

    # test with nested
    mad = dict(a="Hi There", nest=dict(a=[True, False, None], b=dict(z=True)),
               icky=[["z", "y"], dict(d=5), "abc"])
    raw = (b'\x83\xa1a\xa8Hi There\xa4nest\x82\xa1a\x93\xc3\xc2\xc0\xa1b\x81\xa1'
           b'z\xc3\xa4icky\x93\x92\xa1z\xa1y\x81\xa1d\x05\xa3abc')
    size = 49

    mapper = Mapper(mad=mad, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.size == size

    # test round trips
    mapper = Mapper(raw=raw, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == mad
    assert mapper.raw == raw
    assert mapper.size == size


def test_mapper_saidive():
    """Test Mapper class with saidive True"""

    # test with default empty mad
    mapper = Mapper(saidive=True)
    assert mapper.mad == {}
    assert mapper.qb64 == '-IAA'
    assert mapper.raw == mapper.qb64b == b'-IAA'
    assert mapper.qb2 == b'\xf8\x80\x00'
    assert mapper.count == 1
    assert mapper.size == 4
    assert mapper.byteCount() == 4
    assert mapper.byteCount(Colds.bny) == 3
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == None

    mapper = Mapper(saidive=True, makify=True)
    assert mapper.mad == {}
    assert mapper.qb64 == '-IAA'
    assert mapper.raw == mapper.qb64b == b'-IAA'
    assert mapper.qb2 == b'\xf8\x80\x00'
    assert mapper.count == 1
    assert mapper.size == 4
    assert mapper.byteCount() == 4
    assert mapper.byteCount(Colds.bny) == 3
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == None

    # test mad with no said fields actually present

    mad = dict(a=1, b=True, c="hello")
    qb64 = '-IAI0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    raw = b'-IAI0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    qb2 = (b'\xf8\x80\x08\xd0\x9f\xda\xe8p\x01\x00\x005\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f'
           b'\xdc\xd0\xbf\xe1zYh')
    count = 9
    size = 36
    bc = 27

    mapper = Mapper(mad=mad, saidive=True, makify=True)
    assert mapper.mad == mad == {'a': 1, 'b': True, 'c': 'hello'}
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True

    # test mad with said field with non-empty but wrong said value and non default code
    dig = Diger(ser=b'A' * 44, code=DigDex.Blake2b_256).qb64
    assert dig == 'FOFYruBtiiRMU24vhPFaDHsgTiKuE6XARrAtGAun1Foo'
    imad = dict(d=dig, a=1, b=True, c="hello")  # input mad

    qb64 = '-IAU0J_dFAT2zGWVcdkf_n6ya8FM_uvDeByq3tD3sNhMAXYXfSPV0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    raw = b'-IAU0J_dFAT2zGWVcdkf_n6ya8FM_uvDeByq3tD3sNhMAXYXfSPV0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    qb2 = (b'\xf8\x80\x14\xd0\x9f\xdd\x14\x04\xf6\xcce\x95q\xd9\x1f\xfe~\xb2k\xc1'
           b'L\xfe\xeb\xc3x\x1c\xaa\xde\xd0\xf7\xb0\xd8L\x01v\x17}#\xd5\xd0\x9f\xda\xe8p'
           b'\x01\x00\x005\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f\xdc\xd0\xbf\xe1zYh')
    count = 21  # quadlets
    size = 84  # characters/bytes in Text domain
    bc = 63  # bytes in Binary domain
    omad = \
    {
        'd': 'FAT2zGWVcdkf_n6ya8FM_uvDeByq3tD3sNhMAXYXfSPV',
        'a': 1,
        'b': True,
        'c': 'hello'
    }
    said = 'FAT2zGWVcdkf_n6ya8FM_uvDeByq3tD3sNhMAXYXfSPV'
    assert said != dig

    mapper = Mapper(mad=imad, saidive=True, makify=True)
    assert mapper.mad == omad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake2b_256)
    assert mapper.saidive == True
    assert mapper.said == said

    # test mad with said field with non-empty but wrong said value
    dig = Diger(ser=b'A' * 44, code=DigDex.Blake3_256).qb64
    assert dig == 'EICiqC6XXEjA4lLFqqSigJGIVBtgLyphDiMiaviQ_jYA'
    imad = dict(d=dig, a=1, b=True, c="hello")  # input mad

    qb64 = '-IAU0J_dELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    raw = b'-IAU0J_dELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    qb2 = (b'\xf8\x80\x14\xd0\x9f\xdd\x10\xba?\xce\x1a\xf0\x9d4\x1a\x8d\xdf\xcb\xd2\xa3'
           b'\xc0\xe9n\xc0,\xa6\r\xb54#Q\x96\xe0\xe8\x81![\xc1\xce\xd0\x9f\xda\xe8p'
           b'\x01\x00\x005\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f\xdc\xd0\xbf\xe1zYh')
    count = 21  # quadlets
    size = 84  # characters/bytes in Text domain
    bc = 63  # bytes in Binary domain
    omad = \
    {
        'd': 'ELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO',
        'a': 1,
        'b': True,
        'c': 'hello'
    }
    said = 'ELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO'
    assert said != dig

    mapper = Mapper(mad=imad, saidive=True, makify=True)
    assert mapper.mad == omad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == said

    # test mad with said field with empty string as value
    imad = dict(d='', a=1, b=True, c="hello")  # input mad
    qb64 = '-IAU0J_dELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    raw = b'-IAU0J_dELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    qb2 = (b'\xf8\x80\x14\xd0\x9f\xdd\x10\xba?\xce\x1a\xf0\x9d4\x1a\x8d\xdf\xcb\xd2\xa3'
           b'\xc0\xe9n\xc0,\xa6\r\xb54#Q\x96\xe0\xe8\x81![\xc1\xce\xd0\x9f\xda\xe8p'
           b'\x01\x00\x005\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f\xdc\xd0\xbf\xe1zYh')
    count = 21  # quadlets
    size = 84  # characters/bytes in Text domain
    bc = 63  # bytes in Binary domain
    omad = \
    {
        'd': 'ELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO',
        'a': 1,
        'b': True,
        'c': 'hello'
    }
    said = 'ELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO'

    mapper = Mapper(mad=imad, saidive=True, makify=True)
    assert mapper.mad == omad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == said

    # test mad with said field with valid said as value so round trips
    said = 'ELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO'
    imad = dict(d=said, a=1, b=True, c="hello")  # input mad
    qb64 = '-IAU0J_dELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    raw = b'-IAU0J_dELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO0J_a6HABAAA10J_b1AAM0J_c0L_hello'
    qb2 = (b'\xf8\x80\x14\xd0\x9f\xdd\x10\xba?\xce\x1a\xf0\x9d4\x1a\x8d\xdf\xcb\xd2\xa3'
           b'\xc0\xe9n\xc0,\xa6\r\xb54#Q\x96\xe0\xe8\x81![\xc1\xce\xd0\x9f\xda\xe8p'
           b'\x01\x00\x005\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f\xdc\xd0\xbf\xe1zYh')
    count = 21  # quadlets
    size = 84  # characters/bytes in Text domain
    bc = 63  # bytes in Binary domain
    omad = \
    {
        'd': 'ELo_zhrwnTQajd_L0qPA6W7ALKYNtTQjUZbg6IEhW8HO',
        'a': 1,
        'b': True,
        'c': 'hello'
    }

    mapper = Mapper(mad=imad, saidive=True, makify=True)
    assert mapper.mad == omad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == said

    # test verify and round trips
    mapper = Mapper(raw=raw, saidive=True, verify=True)
    assert mapper.mad == omad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == said

    # test mad multiple said fields
    saids = dict(d=DigDex.Blake3_256, e=DigDex.Blake2b_256)
    imad = dict(d='', a=1, b=True, c="hello", e="")  # input mad
    qb64 = '-IAg0J_dEHWZOvL0Dn3leHAJ24xdSTH2vhVie0NdH-pd9EmPOAGP0J_a6HABAAA10J_b1AAM0J_c0L_hello0J_eFCeR8nWBFeEdoz74Jxz-QnDEx0CIUdK-ehh_8n0v6DEM'
    raw = b'-IAg0J_dEHWZOvL0Dn3leHAJ24xdSTH2vhVie0NdH-pd9EmPOAGP0J_a6HABAAA10J_b1AAM0J_c0L_hello0J_eFCeR8nWBFeEdoz74Jxz-QnDEx0CIUdK-ehh_8n0v6DEM'
    qb2 = (b'\xf8\x80 \xd0\x9f\xdd\x10u\x99:\xf2\xf4\x0e}\xe5xp\t\xdb\x8c]I1\xf6'
            b'\xbe\x15b{C]\x1f\xea]\xf4I\x8f8\x01\x8f\xd0\x9f\xda\xe8p\x01\x00\x005'
            b"\xd0\x9f\xdb\xd4\x00\x0c\xd0\x9f\xdc\xd0\xbf\xe1zYh\xd0\x9f\xde\x14'"
            b"\x91\xf2u\x81\x15\xe1\x1d\xa3>\xf8'\x1c\xfeBp\xc4\xc7@\x88Q\xd2\xbez\x18"
            b'\x7f\xf2}/\xe81\x0c')

    count = 33  # quadlets
    size = 132  # characters/bytes in Text domain
    bc = 99  # bytes in Binary domain
    omad = \
    {
        'd': 'EHWZOvL0Dn3leHAJ24xdSTH2vhVie0NdH-pd9EmPOAGP',
        'a': 1,
        'b': True,
        'c': 'hello',
        'e': 'FCeR8nWBFeEdoz74Jxz-QnDEx0CIUdK-ehh_8n0v6DEM'
    }
    said = 'EHWZOvL0Dn3leHAJ24xdSTH2vhVie0NdH-pd9EmPOAGP'

    mapper = Mapper(mad=imad, saidive=True, makify=True, saids=saids)
    assert mapper.mad == omad
    assert mapper.qb64 == qb64
    assert mapper.raw == mapper.qb64b == raw
    assert mapper.qb2 == qb2
    assert mapper.count == count
    assert mapper.size == size
    assert mapper.byteCount() == size
    assert mapper.byteCount(Colds.bny) == bc
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256, e=DigDex.Blake2b_256)
    assert mapper.saidive == True
    assert mapper.said == said

    """Done Test"""


def test_mapper_saidive_nonnative():
    """Test Mapper class with saidive True but nonnative kind"""

    # test with default empty mad
    kind = Kinds.json
    raw = b'{}'
    size = 2

    mapper = Mapper(saidive=True, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == {}
    assert mapper.raw == raw
    assert mapper.size == size
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == None

    # test with makify but no said fields
    mapper = Mapper(saidive=True, makify=True, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == {}
    assert mapper.raw == raw
    assert mapper.size == size
    assert mapper.strict == True
    assert mapper.saids == dict(d=DigDex.Blake3_256)
    assert mapper.saidive == True
    assert mapper.said == None

    imad = dict(d='', a=1, b=True, c="hello")  # input mad
    omad = \
    {
        'd': 'ECwfOLNWraidyr1_10BkMPdTNdiPksHHOfSH9OLpzvog',
        'a': 1,
        'b': True,
        'c': 'hello'
    }
    said = 'ECwfOLNWraidyr1_10BkMPdTNdiPksHHOfSH9OLpzvog'
    raw = (b'{"d":"ECwfOLNWraidyr1_10BkMPdTNdiPksHHOfSH9OLpzvog","a":1,"b":true,"c":"hello"}')
    size = 79

    # test with makify but no said fields
    mapper = Mapper(mad=imad, saidive=True, makify=True, kind=kind)
    assert mapper.kind == kind
    assert mapper.mad == omad
    assert mapper.raw == raw
    assert mapper.size == size
    assert mapper.saidive == True
    assert mapper.said == said


def test_compactor_basic():
    """Test Compactor class"""

    compactor = Compactor()  # default empty map
    assert compactor.mad == {}
    assert compactor.qb64 == '-IAA'
    assert compactor.qb64b == b'-IAA'
    assert compactor.qb2 == b'\xf8\x80\x00'
    assert compactor.count == 1
    assert compactor.size == 4
    assert compactor.byteCount() == 4
    assert compactor.byteCount(Colds.bny) == 3
    assert compactor.saids == dict(d=DigDex.Blake3_256)
    assert compactor.saidive == True
    assert compactor.said == None
    assert compactor.leaves == {}
    assert compactor.partials == None
    assert compactor.iscompact is None
    assert compactor.getTail(path='') == compactor.mad
    assert compactor.getTail(path='.x') == None
    assert compactor.getMad(path="") == (None, "")
    assert compactor.getMad(path=".x") == (None, None)

    # Test already fully compacted mad
    imad = \
    {
        'd': '',
        'q': 'top',
        'z':
        {
            'y': 'bottom',
            'x': 'under',
        }
    }

    omad = \
    {
        'd': 'EK3tcDw5SUtzngEbI_rOYL942GRTt9A4aljqjXySagxB',
        'q': 'top',
        'z':
        {
            'y': 'bottom',
            'x': 'under',
        }
    }
    said = 'EK3tcDw5SUtzngEbI_rOYL942GRTt9A4aljqjXySagxB'
    raw = (b'-IAW0J_dEK3tcDw5SUtzngEbI_rOYL942GRTt9A4aljqjXySagxB0J_qXtop0J_z-IAG0J_y0Mbo'
           b'ttom0J_x0L_under')

    compactor = Compactor(mad=imad, makify=True)
    assert compactor.mad == omad
    assert compactor.raw == raw
    assert compactor.saids == dict(d=DigDex.Blake3_256)
    assert compactor.saidive == True
    assert compactor.said == said
    assert compactor.leaves == {}
    assert compactor.partials is None
    assert compactor.iscompact is None
    assert compactor.getTail(path='') == compactor.mad
    assert compactor.getTail(path='.z') == \
    {
        'y': 'bottom',
        'x': 'under',
    }
    assert compactor.getMad(path="") == (None, "")
    assert compactor.getMad(path=".z") == (({'d': 'EK3tcDw5SUtzngEbI_rOYL942GRTt9A4aljqjXySagxB',
                                                'q': 'top',
                                                'z': {'y': 'bottom', 'x': 'under'}},
                                               'z'))

    paths = ['']
    assert compactor._trace(mad=compactor.mad) == paths
    assert compactor.iscompact == True
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert not leafer.saidive
        assert leafer.said is None
    assert compactor.mad == omad  # no change

    assert compactor.trace() == paths
    assert compactor.iscompact == True
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert not leafer.saidive
        assert leafer.said is None
    assert compactor.mad == omad  # no change

    # should not change said since already compacted
    assert compactor._trace(mad=compactor.mad, saidify=True) == paths
    assert compactor.iscompact == True
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    assert len(paths) == 1
    path, leafer = list(compactor.leaves.items())[0]
    assert leafer.saidive
    assert leafer.said == said
    assert compactor.mad == omad  # saidified leaves but no change since already compact

    assert compactor.trace(saidify=True) == paths
    assert compactor.iscompact == True
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    assert len(paths) == 1
    path, leafer = list(compactor.leaves.items())[0]
    assert leafer.saidive
    assert leafer.said == said
    assert compactor.mad == omad  # saidified leaves but no change since already compact

    # complex nested with skips
    imad = dict(d='',
               q='top',
               z=dict(x=dict(d='',
                             w='bottom'),
                      u='under'),
               y=dict(d="",
                      v=dict(d="",
                             t=dict(s='down',
                                    r='deep'))))
    assert imad == \
    {
        'd': '',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': '',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': '',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }

    omad = \
    {
        'd': 'EEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': '',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': '',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }

    oraw = (b'-IAq'
           b'0J_dEEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ'
           b'0J_qXtop'
           b'0J_z-IAK0J_x-IAF0J_d1AAP0J_w0Mbottom'
           b'0J_u0L_under'
           b'0J_y-IAO0J_d1AAP0J_v-IAK'
           b'0J_d1AAP0J_t-IAG0J_s1AAFdown0J_r1AAFdeep')

    osaid = 'EEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ'

    compactor = Compactor(mad=imad, makify=True)
    assert compactor.mad == omad
    assert compactor.raw == oraw
    assert compactor.saids == dict(d=DigDex.Blake3_256)
    assert compactor.saidive == True
    assert compactor.said == osaid
    assert compactor.leaves == {}
    assert compactor.partials is None
    assert compactor.iscompact is None
    assert compactor.getTail(path='') == compactor.mad
    assert compactor.getTail(path='.z.x') == {'d': '', 'w': 'bottom'}
    assert compactor.getTail(path='.y.v') == {'d': '', 't': {'s': 'down', 'r': 'deep'}}
    assert compactor.getMad(path='.z.x') == ({'x': {'d': '', 'w': 'bottom'}, 'u': 'under'}, 'x')
    assert compactor.getMad(path='.y.v') == ({'d': '', 'v': {'d': '', 't': {'s': 'down', 'r': 'deep'}}}, 'v')

    paths = ['.z.x', '.y.v']
    assert compactor._trace(mad=compactor.mad) == paths
    assert compactor.iscompact == False
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert not leafer.saidive
        assert leafer.said is None
    assert compactor.mad == omad  # no change

    assert compactor.trace() == paths
    assert compactor.iscompact == False
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert not leafer.saidive
        assert leafer.said is None
    assert compactor.mad == omad  # no change

    smad = \
    {
        'd': 'EEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }

    assert compactor._trace(mad=compactor.mad, saidify=True) == paths
    assert compactor.iscompact == False
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert leafer.saidive
        assert leafer.said  # not empty or None
    assert compactor.mad == smad  # saidified leaves

    tsmad = \
    {
        'd': 'EDevj28ZwbYZjEcV3wRhnTFNaHOuQZ4u140PJMXH7Ak4',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }
    tsaid = 'EDevj28ZwbYZjEcV3wRhnTFNaHOuQZ4u140PJMXH7Ak4'  # top level said is changed
    assert tsaid != said
    assert compactor.trace(saidify=True) == paths
    assert compactor.iscompact == False
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert leafer.saidive
        assert leafer.said  # not empty or None
    assert compactor.mad == tsmad  # saidified leaves

    # manually compact
    paths = list(compactor.leaves.keys())
    assert paths == ['.z.x', '.y.v']
    mad = dict(compactor.mad)  # make copy
    assert mad == \
    {
        'd': 'EDevj28ZwbYZjEcV3wRhnTFNaHOuQZ4u140PJMXH7Ak4',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }

    # compact the leaves
    for path in paths:
        smad, leaf = compactor.getMad(path=path, mad=mad)
        smad[leaf] = compactor.leaves[path].said

    # smad changes mad
    assert mad == \
    {
        'd': 'EDevj28ZwbYZjEcV3wRhnTFNaHOuQZ4u140PJMXH7Ak4',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX'
        }
    }

    # now create partials manually
    compactor = Compactor(mad=mad, makify=True)

    # compute leaves of partial
    paths = ['.y']
    tsaid = 'EDN5vKpl7ekQZs_A9C__Xk0Elfnkg6OL14JQnTO4gcuW'
    assert compactor.trace(saidify=True) == paths
    assert compactor.iscompact == False
    assert compactor.leaves  # not empty
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert leafer.saidive
        assert leafer.said  # not empty or None

    tmad = \
    {
        'd': 'EDN5vKpl7ekQZs_A9C__Xk0Elfnkg6OL14JQnTO4gcuW',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
        'y':
        {
            'd': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4',
            'v': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX'
        }
    }
    assert compactor.mad == tmad  # saidified leaves
    assert compactor.said == tsaid

    # compact the leaves
    mad = dict(compactor.mad)  # make copy
    for path in paths:
        smad, leaf = compactor.getMad(path=path, mad=mad)
        smad[leaf] = compactor.leaves[path].said

    assert mad == \
    {
        'd': 'EDN5vKpl7ekQZs_A9C__Xk0Elfnkg6OL14JQnTO4gcuW',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
       'y': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4'
    }

    # now create partial
    compactor = Compactor(mad=mad, makify=True)

    # compute leaves of partial
    paths = ['']
    tsaid = 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr'
    tmad = \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
        'y': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4'
    }
    assert compactor.trace(saidify=True) == paths
    assert compactor.iscompact == True
    assert compactor.leaves  # not empty leave is itself
    assert list(compactor.leaves.keys()) == paths
    for path, leafer in compactor.leaves.items():
        assert leafer.saidive
        assert leafer.said  # not empty or None


    assert compactor.said == tsaid  # fully compact said
    assert compactor.mad == tmad  # fully compact mad
    assert compactor.raw == (b'-IAr0J_dEOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr0J_qXtop0J_z-IAP0J_xEKME'
                            b'6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl0J_u0L_under0J_yEAksZZOoIj34ok-04dUU'
                            b'YT_Den2-kkP7fH7wGpsV9Jj4')


    # compactify upon creation
    cmad = \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
        'y': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4'
    }

    craw = (b'-IAq0J_dEEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ0J_qXtop0J_z-IAK0J_x-IAF'
            b'0J_d1AAP0J_w0Mbottom0J_u0L_under0J_y-IAO0J_d1AAP0J_v-IAK0J_d1AAP0J_t-IAG0J_s'
            b'1AAFdown0J_r1AAFdeep')

    csaid = 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr'

    compactor = Compactor(mad=imad, makify=True, compactify=True)
    assert compactor.mad == cmad
    assert compactor.raw == craw
    assert compactor.saids == dict(d=DigDex.Blake3_256)
    assert compactor.saidive == True
    assert compactor.said == csaid
    assert len(compactor.leaves) == 4
    assert len(compactor.partials) == 2
    assert compactor.iscompact

    leafPaths = list(compactor.leaves)
    assert leafPaths == ['.z.x', '.y.v', '.y', '']
    assert compactor.getTail(path='') == compactor.mad
    assert compactor.getTail(path='.z.x') == 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl' # {'d': '', 'w': 'bottom'}
    assert compactor.getTail(path='.y.v') == None
    assert compactor.getMad(path='.z.x') == ({'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl', 'u': 'under'}, 'x')
    assert compactor.getMad(path='.y.v') == (None, None)

    leafPaths = list(compactor.leaves)
    assert leafPaths == ['.z.x', '.y.v', '.y', '']

    partialPaths = list(compactor.partials)
    assert partialPaths == [('',), ('.z.x', '.y.v')]

    cp = compactor.partials[('.z.x', '.y.v')]
    assert cp.mad == \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                'w': 'bottom'
            },
           'u': 'under'
        },
        'y':
        {
            'd': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4',
            'v':
            {
                'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }
    assert not cp.iscompact

    cp = compactor.partials[('',)]
    assert cp.mad == compactor.mad
    assert cp.iscompact


    """Done Test"""


def test_compactor_compact_expand():
    """Test Compactor class compact and expand"""

    imad = \
    {
        'd': '',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': '',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': '',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }
    umad = \
    {
        'd': 'EEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': '',
                'w': 'bottom'
            },
            'u': 'under'
        },
        'y':
        {
            'd': '',
            'v':
            {
                'd': '',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }

    # compacted  top level mad
    cmad = \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
        'y': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4'
    }

    usaid = 'EEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ'  # initial uncompacted said
     # leaf saids
    csaid = 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr'  # compacted top level

    cpath = ''
    xpath = '.z.x'
    vpath = '.y.v'
    ypath = '.y'

    xsaid = 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl'
    vsaid = 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX'
    ysaid = 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4'

    xmad = \
    {
        'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
        'w': 'bottom'
    }

    vmad = \
    {
        'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
         't':
         {
             's': 'down',
             'r': 'deep'
         }
    }

    ymad = \
    {
        'd': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4',
        'v': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX'
    }

    compactor = Compactor(mad=imad, makify=True)
    assert compactor.saidive == True
    assert compactor.said == usaid
    assert compactor.mad == umad
    assert not compactor.leaves
    assert compactor.iscompact is None  # no leaves yet
    assert not compactor.partials

    compactor.compact()
    assert compactor.iscompact == True
    assert compactor.said == csaid
    assert compactor.mad == cmad
    assert list(compactor.leaves.keys()) == ['.z.x', '.y.v', '.y', '']

    cleaf = compactor.leaves[cpath]  # top level compacted
    assert cleaf.said == csaid
    assert cleaf.mad == cmad

    xleaf = compactor.leaves[xpath]
    assert xleaf.said == xsaid
    assert xleaf.mad == xmad

    vleaf = compactor.leaves[vpath]
    assert vleaf.said == vsaid
    assert vleaf.mad == vmad

    yleaf = compactor.leaves[ypath]
    assert yleaf.said == ysaid
    assert yleaf.mad == ymad

    # test expand of compactor
    paths = ['.z.x', '.y.v', '.y', '']
    # fully expanded mad but with most compact computed saids of all leaves
    emad = \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                'w': 'bottom'
            },
           'u': 'under'
        },
        'y':
        {
            'd': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4',
            'v':
            {
                'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }
    assert list(compactor.leaves.keys()) == paths
    assert not compactor.partials
    assert compactor.iscompact
    assert len(compactor.leaves) == 4 == len(paths)

    # test greedy expand
    # first compact
    compactor = Compactor(mad=emad, makify=True)
    compactor.compact()
    assert compactor.iscompact
    assert list(compactor.leaves.keys()) == paths
    assert compactor.mad == cmad
    assert compactor.said == csaid

    # now expand
    indices = [('',), ('.z.x', '.y.v')]
    # index of fully expanded partial is tuple of leaf paths in expansion
    index = ('.z.x', '.y.v')
    compactor.expand()  # default greedy==True
    assert list(compactor.partials.keys()) == indices
    # greedy creates fully compact and fully expanded partials
    assert len(compactor.partials) == 2

    partial = compactor.partials[("", )]  # get fully compact
    assert partial.iscompact
    assert partial.mad == cmad
    assert partial.said == csaid
    assert partial.mad['d'] == csaid

    partial = compactor.partials[index]  # get fully expanded
    assert not partial.iscompact
    assert partial.mad == emad
    assert partial.mad['d'] == csaid
    assert partial.mad['y']['d'] == ysaid
    assert partial.mad['y']['v']['d'] == vsaid
    assert partial.mad['z']['x']['d'] == xsaid

    # test non-greedy expand
    # first compact
    compactor = Compactor(mad=emad, makify=True)
    compactor.compact()
    assert compactor.iscompact
    assert list(compactor.leaves.keys()) == paths
    assert compactor.mad == cmad
    assert compactor.said == csaid

    # now expand
    indices = [('',), ('.z.x', '.y'), ('.z.x', '.y.v')]
    compactor.expand(greedy=False)
    assert list(compactor.partials.keys()) == indices
    assert len(compactor.partials) == 3  # greedy on creates the fully expanded partial

    index0 = ('',)
    partial0 = compactor.partials[index0]
    assert partial0.iscompact
    assert partial0.said == csaid
    assert partial0.mad['d'] == csaid
    assert partial0.mad == \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
            'u': 'under'
        },
        'y': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4'
    }

    index1 = ('.z.x', '.y')
    partial1 = compactor.partials[index1]
    assert not partial1.iscompact
    assert partial1.said == csaid
    assert partial1.mad['d'] == csaid
    assert partial1.mad['y']['d'] == ysaid
    assert partial1.mad['z']['x']['d'] == xsaid
    assert partial1.mad == \
    {'d': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
     'q': 'top',
     'z': {'x': {'d': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                 'w': 'bottom'},
           'u': 'under'},
     'y': {'d': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4',
           'v': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX'}}

    index2 = ('.z.x', '.y.v')
    partial2 = compactor.partials[index2]
    assert not partial2.iscompact
    assert partial2.mad == emad  # fully expanded
    assert partial2.said == csaid
    assert partial2.mad['d'] == csaid
    assert partial2.mad['y']['d'] == ysaid
    assert partial2.mad['y']['v']['d'] == vsaid
    assert partial2.mad['z']['x']['d'] == xsaid
    assert partial2.mad == \
    {
        'd': 'EOJ9rDVPYNNvPd1v7aeDbGX7IbOeKiZYTWjrGeddN8cr',
        'q': 'top',
        'z':
        {
            'x':
            {
                'd': 'EKME6zmr_015kduyBLtNgnFYXzfJu4Z8jhbp2gRUiqGl',
                'w': 'bottom'
            },
           'u': 'under'
        },
        'y':
        {
            'd': 'EAksZZOoIj34ok-04dUUYT_Den2-kkP7fH7wGpsV9Jj4',
            'v':
            {
                'd': 'EJUapYTPqriIaTv2jrQdpBVE6KbgQY35VJyg45-X4jyX',
                't':
                {
                    's': 'down',
                    'r': 'deep'
                }
            }
        }
    }


    # test empty dict for mad for compact and expand
    paths = []
    zmad = {}
    zraw = b'-IAA'

    # first create
    compactor = Compactor(mad=zmad, makify=True)
    assert compactor.mad == zmad
    assert compactor.raw == zraw
    assert compactor.said is None

    # now compact
    compactor.compact()
    assert compactor.iscompact is None
    assert not compactor.leaves
    assert compactor.mad == zmad
    assert compactor.said is None

    # now expand
    compactor.expand()  # default greedy==True
    assert compactor.iscompact is None
    assert not compactor.partials
    assert compactor.mad == zmad
    assert compactor.said is None


    # do compactification at init with empty mad
    compactor = Compactor(mad=zmad, makify=True, compactify=True)
    assert compactor.iscompact is None  # since empty nothing to compact
    assert not compactor.partials
    assert compactor.mad == zmad
    assert compactor.said is None


    # do compactification at init with expanded mad with empty saids
    compactor = Compactor(mad=imad, makify=True, compactify=True)
    assert compactor.iscompact
    assert len(compactor.leaves) == 4
    assert len(compactor.partials) == 2
    assert compactor.mad == cmad
    assert compactor.said == csaid

    """Done Test"""


def test_aggor_basic():
    """Test Aggor (aggregator) class"""

    # test empty default
    kind = Kinds.cesr
    aggor = Aggor()  # default empty ael default kind is cesr
    assert aggor.kind == kind
    assert aggor.agid == None
    assert aggor.ael == []
    assert aggor.raw == b'-JAA'
    assert aggor.qb2 == b'\xf8\x90\x00'
    assert aggor.count == 1
    assert aggor.size == 4
    assert aggor.byteCount() == 4
    assert aggor.code == DigDex.Blake3_256
    assert aggor.strict == True
    assert aggor.saids == dict(d=DigDex.Blake3_256)

    # Test round trip
    ael = aggor.ael
    raw = aggor.raw
    qb2 = aggor.qb2
    aggor = Aggor(raw=raw)
    assert aggor.ael == ael
    assert aggor.raw == raw
    assert aggor.qb2 == qb2

    # test json defaults
    kind = Kinds.json
    aggor = Aggor(kind=kind)  # default empty ael but json
    assert aggor.kind == kind
    assert aggor.agid == None
    assert aggor.ael == []
    assert aggor.raw == b'[]'
    with pytest.raises(ValueError):
        assert aggor.qb2 == b'\xf8\x90\x00'
    assert aggor.count is None
    assert aggor.size == 2
    with pytest.raises(ValueError):
        assert aggor.byteCount() == 4
    assert aggor.code == DigDex.Blake3_256
    assert aggor.strict == True
    assert aggor.saids == dict(d=DigDex.Blake3_256)

    # Test round trip
    ael = aggor.ael
    raw = aggor.raw
    aggor = Aggor(raw=raw, kind=kind)
    assert aggor.ael == ael
    assert aggor.raw == raw

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

    # empty string for agid
    iael = ["", att0, att1, att2, att3]
    assert iael == \
    [
        "",
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

    # Test with cesr
    kind = Kinds.cesr
    oael = \
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

    raw = (b'-JB-EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu-IAg0J_dEMb2KtEJrRYUxOUyw4Tv'
            b'ACeH1767lne0V27ssCQociku0J_u0AAwc2FsdG5vbmNlYmxpbmRl0MissueeEAKCxMOuoRzREVHs'
            b'HCkLilBrUXTvyenBiuM2QtV8BB0C-IAa0J_dEOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm'
            b'4jJu0J_u0AAxc2FsdG5vbmNlYmxpbmRl1AAFname6BAEAABCZXR0eSBCb29w-IAa0J_dEJ0jcxT7'
            b'rGFwj4R39M619BptbmtjqvCsokXu0MLLkek30J_u0AAyc2FsdG5vbmNlYmxpbmRl1AAFrole6AAE'
            b'AAAentertainment-IAb0J_dEPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet0J_u0AAz'
            b'c2FsdG5vbmNlYmxpbmRl1AANlocation4BAEbGFrZSBtYW5zaW9u')


    qb2 = (b'\xf8\x90~\x10Zr_\xef\xf3\xdb\xd4\x0e\x81\xea\x02\x80l~qaK\xe1\xf6C'
        b'\xdcw\xed\x06A\xc3\xb9\x92\x08\x01\xb7.\xf8\x80 \xd0\x9f\xdd\x10\xc6'
        b"\xf6*\xd1\t\xad\x16\x14\xc4\xe52\xc3\x84\xef\x00'\x87\xd7\xbe\xbb\x96w\xb4Wn"
        b'\xec\xb0$(r).\xd0\x9f\xee\xd0\x000saltnonceblinde\xd0\xc8\xac\xb2'
        b'\xe7\x9e\x10\x02\x82\xc4\xc3\xae\xa1\x1c\xd1\x11Q\xec\x1c)\x0b\x8aPk'
        b'Qt\xef\xc9\xe9\xc1\x8a\xe36B\xd5|\x04\x1d\x02\xf8\x80\x1a\xd0\x9f'
        b'\xdd\x10\xe8.\xb2\xe6\xa7v?\xb2\xef\xad\xae\x7f\x9a\xd1Y\x88\x99\xec'
        b'\xb1m\xcc\x0c\xbc\xfce\x11\xb8[f\xe22n\xd0\x9f\xee\xd0\x001saltnoncebli'
        b'nde\xd4\x00\x05\x9d\xa9\x9e\xe8\x10\x04\x00\x00Betty Boop\xf8\x80\x1a\xd0'
        b'\x9f\xdd\x10\x9d#s\x14\xfb\xacap\x8f\x84w\xf4\xce\xb5\xf4\x1amnkc\xaa'
        b'\xf0\xac\xa2E\xee\xd0\xc2\xcb\x91\xe97\xd0\x9f\xee\xd0\x002saltnonceblinde'
        b'\xd4\x00\x05\xae\x89^\xe8\x00\x04\x00\x00\x1e\x9e\xd7\xab\xb5'
        b'\xa8\xa7\x99\xe9\xed\xf8\x80\x1b\xd0\x9f\xdd\x10\xf6\xb6H\xa1<.Vs'
        b'\xf62\xc3\xc8\x17t\xe2\xf2\x99\xd7\xb8\xac\xd2\xd6\x93\x0f\x94W<\x0e'
        b'l\xbd\x87\xad\xd0\x9f\xee\xd0\x003saltnonceblinde\xd4\x00\r\x96\x87\x1a\xb6'
        b"*'\xe0\x10\x04lake mansion")

    count = 127
    size = 508
    agid = 'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu'

    aggor = Aggor(ael=iael, makify=True, kind=kind)
    assert aggor.kind == kind
    assert aggor.agid == agid
    assert aggor.ael == oael
    assert aggor.raw == aggor.qb64b == raw
    assert aggor.qb2 == qb2
    assert aggor.count == count
    assert aggor.size == size
    assert aggor.byteCount() == size
    assert aggor.code == DigDex.Blake3_256
    assert aggor.strict == True
    assert aggor.saids == dict(d=DigDex.Blake3_256)

    # Test round trip
    ael = aggor.ael
    raw = aggor.raw
    qb2 = aggor.qb2
    aggor = Aggor(raw=raw)
    assert aggor.ael == ael
    assert aggor.raw == raw
    assert aggor.qb2 == qb2

    #test disclosure
    dael, kind = aggor.disclose()
    assert dael == \
    [
        'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
        'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
        'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
        'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet'
    ]
    assert Aggor.verifyDisclosure(dael, aggor.kind)

    dael, kind = aggor.disclose([1, 2, 4])
    assert dael == \
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
        'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
        {
            'd': 'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]
    assert Aggor.verifyDisclosure(dael, aggor.kind)

    dael, kind = aggor.disclose([3])
    assert dael == \
    [
        'EFpyX-_z29QOgeoCgGx-cWFL4fZD3HftBkHDuZIIAbcu',
        'EMb2KtEJrRYUxOUyw4TvACeH1767lne0V27ssCQociku',
        'EOgusuandj-y762uf5rRWYiZ7LFtzAy8_GURuFtm4jJu',
        {
            'd': 'EJ0jcxT7rGFwj4R39M619BptbmtjqvCsokXu0MLLkek3',
            'u': '0AAyc2FsdG5vbmNlYmxpbmRl',
            'role': 'entertainment'
        },
        'EPa2SKE8LlZz9jLDyBd04vKZ17is0taTD5RXPA5svYet'
    ]
    assert Aggor.verifyDisclosure(dael, aggor.kind)

    # test strip round trip
    ims = bytearray(raw)
    aggor = Aggor(raw=ims, strip=True)
    assert ims == bytearray(b'')  # stripped
    assert aggor.ael == ael
    assert aggor.raw == raw

    ims = bytearray(qb2)
    aggor = Aggor(qb2=ims, strip=True)
    assert aggor.ael == ael
    assert aggor.raw == raw
    assert aggor.qb2 == qb2

    # test without makify with iael so verify fails
    with pytest.raises(InvalidValueError):
        aggor = Aggor(ael=iael)

    # test without makify with oael so verify succeeds
    aggor = Aggor(ael=oael)
    assert aggor.kind == kind
    assert aggor.agid == agid
    assert aggor.ael == oael
    assert aggor.raw == aggor.qb64b == raw
    assert aggor.qb2 == qb2
    assert aggor.count == count
    assert aggor.size == size
    assert aggor.byteCount() == size
    assert aggor.code == DigDex.Blake3_256
    assert aggor.strict == True
    assert aggor.saids == dict(d=DigDex.Blake3_256)


    # Test with Json
    kind = Kinds.json
    oael = \
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

    raw = (b'["EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH",{"d":"ECg0K_g24tK919rqMBrs2T'
            b'14hPKSbXMwPRwjX8OFh4Fb","u":"0AAwc2FsdG5vbmNlYmxpbmRl","issuee":"EAKCxMOuoRz'
            b'REVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"},{"d":"EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9j'
            b'dP0hu309au","u":"0AAxc2FsdG5vbmNlYmxpbmRl","name":"Betty Boop"},{"d":"EFlxdk'
            b'l8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z","u":"0AAyc2FsdG5vbmNlYmxpbmRl","role'
            b'":"entertainment"},{"d":"EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J","u":"'
            b'0AAzc2FsdG5vbmNlYmxpbmRl","location":"lake mansion"}]')

    count = None
    size = 509
    agid = 'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH'

    aggor = Aggor(ael=iael, makify=True, kind=kind)
    assert aggor.kind == kind
    assert aggor.agid == agid
    assert aggor.ael == oael
    assert aggor.raw == aggor.qb64b == raw
    with pytest.raises(check=ValueError):
        assert aggor.qb2 == b''
    assert aggor.count == count
    assert aggor.size == size
    with pytest.raises(check=ValueError):
        assert aggor.byteCount() == 4
    assert aggor.code == DigDex.Blake3_256
    assert aggor.strict == True
    assert aggor.saids == dict(d=DigDex.Blake3_256)

    # Test round trip
    ael = aggor.ael
    raw = aggor.raw
    aggor = Aggor(raw=raw, kind=kind)
    assert aggor.ael == ael
    assert aggor.raw == raw
    assert aggor.agid == agid

    #test disclosure
    dael, kind = aggor.disclose()
    assert dael == \
    [
        'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
        'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
        'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
        'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J'
    ]
    assert Aggor.verifyDisclosure(dael, aggor.kind)

    dael, kind = aggor.disclose([2, 3])
    assert dael == \
    [
        'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
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
        'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J'
    ]
    assert Aggor.verifyDisclosure(dael, aggor.kind)

    dael, kind = aggor.disclose([1, 4])
    assert dael == \
    [
        'EKfcTG2FZN7sCSeL248w6wqOwl2l_0velioJLjk2a5mH',
        {
            'd': 'ECg0K_g24tK919rqMBrs2T14hPKSbXMwPRwjX8OFh4Fb',
            'u': '0AAwc2FsdG5vbmNlYmxpbmRl',
            'issuee': 'EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C'
        },
        'EGtsAumwa3EcDezzX8UDaoBnUQbHVX_C9jdP0hu309au',
        'EFlxdkl8ki1iwURkviyjKRDfyam7wZZ4HyVq1tv6N_4z',
        {
            'd': 'EILHLTqlZPUIukMCyzHLOQKt0btEdopPXZFSHblsF10J',
            'u': '0AAzc2FsdG5vbmNlYmxpbmRl',
            'location': 'lake mansion'
        }
    ]
    assert Aggor.verifyDisclosure(dael, aggor.kind)


    # test strip round trip
    ims = bytearray(raw)
    aggor = Aggor(raw=ims, strip=True, kind=kind)
    assert ims  # not stripped when json since don't know size
    assert aggor.ael == ael
    assert aggor.raw == raw
    assert aggor.agid == agid

    ims = bytearray(qb2)
    with pytest.raises(InvalidValueError):  # qb2 incompatible with json
        aggor = Aggor(qb2=ims, strip=True, kind=kind)


    # test without makify with iael so verify fails
    with pytest.raises(InvalidValueError):
        aggor = Aggor(ael=iael, kind=kind)

    # test without makify with oael so verify succeeds
    aggor = Aggor(ael=oael, kind=kind)
    assert aggor.kind == kind
    assert aggor.agid == agid
    assert aggor.ael == oael
    assert aggor.raw == aggor.qb64b == raw
    assert aggor.count == count
    assert aggor.size == size
    assert aggor.code == DigDex.Blake3_256
    assert aggor.strict == True
    assert aggor.saids == dict(d=DigDex.Blake3_256)

    """Done Test"""


if __name__ == "__main__":
    test_escape_dex()
    test_mapper_basic()
    test_mapper_basic_nonnative()
    test_mapper_saidive()
    test_mapper_saidive_nonnative()
    test_compactor_basic()
    test_compactor_compact_expand()
    test_aggor_basic()

