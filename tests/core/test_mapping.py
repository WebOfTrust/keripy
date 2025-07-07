# -*- coding: utf-8 -*-
"""
tests.core.test_mapping module

"""
import json
import cbor2 as cbor

import pytest

from dataclasses import dataclass, astuple, asdict

from keri.kering import Colds, SerializeError, DeserializeError
from keri.core import (EscapeDex, Labeler, Mapper, Compactor, DigDex, Diger,
                       DecDex, Decimer)


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
    assert compactor.partials == {}
    assert compactor.iscompact is None
    assert compactor.getSubMad(path='') == compactor.mad
    assert compactor.getSubMad(path='.x') == None
    assert compactor.getSuperMad(path="") == (None, "")
    assert compactor.getSuperMad(path=".x") == (None, None)

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
    assert compactor.partials == {}
    assert compactor.iscompact is None
    assert compactor.getSubMad(path='') == compactor.mad
    assert compactor.getSubMad(path='.z') == \
    {
        'y': 'bottom',
        'x': 'under',
    }
    assert compactor.getSuperMad(path="") == (None, "")
    assert compactor.getSuperMad(path=".z") == (({'d': 'EK3tcDw5SUtzngEbI_rOYL942GRTt9A4aljqjXySagxB',
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
    said = 'EEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ'
    raw = (b'-IAq'
           b'0J_dEEqdCQzFQ0Fu6zzxsxTJ71__z8YuTZaWKeA-NjTDWGWJ'
           b'0J_qXtop'
           b'0J_z-IAK0J_x-IAF0J_d1AAP0J_w0Mbottom'
           b'0J_u0L_under'
           b'0J_y-IAO0J_d1AAP0J_v-IAK'
           b'0J_d1AAP0J_t-IAG0J_s1AAFdown0J_r1AAFdeep')


    compactor = Compactor(mad=imad, makify=True)
    assert compactor.mad == omad
    assert compactor.raw == raw
    assert compactor.saids == dict(d=DigDex.Blake3_256)
    assert compactor.saidive == True
    assert compactor.said == said
    assert compactor.leaves == {}
    assert compactor.partials == {}
    assert compactor.iscompact is None
    assert compactor.getSubMad(path='') == compactor.mad
    assert compactor.getSubMad(path='.z.x') == {'d': '', 'w': 'bottom'}
    assert compactor.getSubMad(path='.y.v') == {'d': '', 't': {'s': 'down', 'r': 'deep'}}
    assert compactor.getSuperMad(path='.z.x') == ({'x': {'d': '', 'w': 'bottom'}, 'u': 'under'}, 'x')
    assert compactor.getSuperMad(path='.y.v') == ({'d': '', 'v': {'d': '', 't': {'s': 'down', 'r': 'deep'}}}, 'v')

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
        smad, leaf = compactor.getSuperMad(path=path, mad=mad)
        smad[leaf] = compactor.leaves[path].said

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

    # now create partial
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
        smad, leaf = compactor.getSuperMad(path=path, mad=mad)
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

    # test expand



    """Done Test"""


if __name__ == "__main__":
    test_escape_dex()
    test_mapper_basic()
    test_mapper_saidive()
    test_compactor_basic()
    test_compactor_compact_expand()
