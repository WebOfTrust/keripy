# -*- coding: utf-8 -*-
"""
tests.core.test_mapping module

"""
import json
import cbor2 as cbor

import pytest

from dataclasses import dataclass, astuple, asdict

from keri.kering import Colds, SerializeError, DeserializeError
from keri.core import (EscapeDex, Labeler, Mapper, Partor, DigDex, Diger,
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


def test_partor_basic():
    """Test Partor class"""

    partor = Partor()  # default empty map
    assert partor.mad == {}
    assert partor.qb64 == '-IAA'
    assert partor.qb64b == b'-IAA'
    assert partor.qb2 == b'\xf8\x80\x00'
    assert partor.count == 1
    assert partor.size == 4
    assert partor.byteCount() == 4
    assert partor.byteCount(Colds.bny) == 3
    assert partor.saids == dict(d=DigDex.Blake3_256)
    assert partor.saidive == True
    assert partor.said == None
    assert partor.partials == {}

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


    partor = Partor(mad=imad, makify=True)
    assert partor.mad == omad
    assert partor.raw == raw
    assert partor.saids == dict(d=DigDex.Blake3_256)
    assert partor.saidive == True
    assert partor.said == said
    assert partor.partials == {}

    leaves = partor._trace(mad=partor.mad)
    assert leaves == ['.z.x', '.y.v']

    # recursively compute saids on leaves so that mads with fully computed
    # saids form the partials

    """Done Test"""

if __name__ == "__main__":
    test_escape_dex()
    test_mapper_basic()
    test_mapper_saidive()
    test_partor_basic()
