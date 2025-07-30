# -*- coding: utf-8 -*-
"""
tests.core.test_structing module

"""
from dataclasses import dataclass, astuple, asdict
from typing import NamedTuple
from collections import namedtuple
from collections.abc import Mapping


import pytest


from keri import kering
from keri.kering import ValidationError, InvalidValueError, EmptyMaterialError, Colds

from keri.help import helping

from keri.core import (Matter, Diger, Prefixer, Number, Verser, Labeler,
                       Noncer, NonceDex, Salter)

from keri.core import (Structor, Sealer, Blinder,
                       SealDigest, SealRoot, SealBack, SealEvent,
                                 SealLast, SealTrans, SealKind, BlindState)
from keri.core.structing import (Castage, CodenToClans, ClanToCodens,
                                 EClanDom, ECastDom, EmptyClanDom, EmptyCastDom,
                                 AClanDom, ACastDom,
                                 SClanDom, SCastDom, SealClanDom, SealCastDom,
                                 BClanDom, BCastDom)


def test_structor_doms():
    """test doms in structure"""

    assert isinstance(EClanDom, EmptyClanDom)
    assert isinstance(ECastDom, EmptyCastDom)
    assert isinstance(SClanDom, SealClanDom)
    assert isinstance(SCastDom, SealCastDom)

    assert asdict(EClanDom) == {}
    assert asdict(ECastDom) == {}

    assert asdict(SClanDom) == \
    {
        'SealDigest': SealDigest,
        'SealRoot': SealRoot,
        'SealEvent': SealEvent,
        'SealTrans': SealTrans,
        'SealLast': SealLast,
        'SealBack': SealBack,
        'SealKind': SealKind,
    }

    assert asdict(SCastDom) == \
    {
        'SealDigest': SealDigest(d=Castage(kls=Diger, ipn=None)),
        'SealRoot': SealRoot(rd=Castage(kls=Diger, ipn=None)),
        'SealEvent': SealEvent(i=Castage(kls=Prefixer, ipn=None),
                               s=Castage(kls=Number, ipn='numh'),
                               d=Castage(kls=Diger, ipn=None)),
        'SealTrans': SealTrans(s=Castage(kls=Number, ipn='numh'),
                               d=Castage(kls=Diger, ipn=None)),
        'SealLast': SealLast(i=Castage(kls=Prefixer, ipn=None)),
        'SealBack': SealBack(bi=Castage(kls=Prefixer, ipn=None),
                                 d=Castage(kls=Diger, ipn=None)),
        'SealKind': SealKind(t=Castage(kls=Verser, ipn=None),
                                 d=Castage(kls=Diger, ipn=None)),
    }

    assert asdict(BClanDom) == \
    {
        'BlindState': BlindState,
    }

    assert asdict(BCastDom) == \
    {
        'BlindState': BlindState(d=Castage(kls=Noncer, ipn='nonce'),
                                 u=Castage(kls=Noncer, ipn='nonce'),
                                 td=Castage(kls=Noncer, ipn='nonce'),
                                 ts=Castage(kls=Labeler, ipn='text'))
    }


    assert ClanToCodens == \
    {
        'SealDigest': 'DigestSealSingles',
        'SealRoot': 'MerkleRootSealSingles',
        'SealEvent': 'SealSourceTriples',
        'SealTrans': 'SealSourceCouples',
        'SealLast': 'SealSourceLastSingles',
        'SealBack': 'BackerRegistrarSealCouples',
        'SealKind': 'TypedDigestSealCouples',
        'BlindState': 'BlindedStateQuadruples'
    }
    assert CodenToClans == \
    {
        'DigestSealSingles': 'SealDigest',
        'MerkleRootSealSingles': 'SealRoot',
        'SealSourceTriples': 'SealEvent',
        'SealSourceCouples': 'SealTrans',
        'SealSourceLastSingles': 'SealLast',
        'BackerRegistrarSealCouples': 'SealBack',
        'TypedDigestSealCouples': 'SealKind',
        'BlindedStateQuadruples': 'BlindState'
    }

    """End Test"""


def test_structor_class():
    """test Structor class variables etc"""

    assert Structor.Clans == AClanDom
    assert Structor.Casts == ACastDom
    assert Structor.Names == \
    {
        ('d',): 'SealDigest',
        ('rd',): 'SealRoot',
        ('i', 's', 'd'): 'SealEvent',
        ('s', 'd'): 'SealTrans',
        ('i',): 'SealLast',
        ('bi', 'd'): 'SealBack',
        ('t', 'd'): 'SealKind',
        ('d', 'u', 'td', 'ts'): 'BlindState'
    }

    assert Structor.ClanCodens == ClanToCodens == \
    {
        'SealDigest': 'DigestSealSingles',
        'SealRoot': 'MerkleRootSealSingles',
        'SealEvent': 'SealSourceTriples',
        'SealTrans': 'SealSourceCouples',
        'SealLast': 'SealSourceLastSingles',
        'SealBack': 'BackerRegistrarSealCouples',
        'SealKind': 'TypedDigestSealCouples',
        'BlindState': 'BlindedStateQuadruples'
    }

    assert Structor.CodenClans == CodenToClans == \
    {
        'DigestSealSingles': 'SealDigest',
        'MerkleRootSealSingles': 'SealRoot',
        'SealSourceTriples': 'SealEvent',
        'SealSourceCouples': 'SealTrans',
        'SealSourceLastSingles': 'SealLast',
        'BackerRegistrarSealCouples': 'SealBack',
        'TypedDigestSealCouples': 'SealKind',
        'BlindedStateQuadruples': 'BlindState'
    }


    """End Test"""

def test_structor():
    """test Structor instance"""

    with pytest.raises(kering.InvalidValueError):
        structor = Structor()  # test default


    aid = 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
    prefixer = Prefixer(qb64=aid)
    num = 14
    number = Number(num=num)
    snq = number.qb64
    snh = number.numh
    assert snh == 'e'
    dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    diger = Diger(qb64=dig)

    # Test with single field namedtuple for data

    data = SealDigest(d=diger)
    clan = SealDigest
    cast = SealDigest(d=Castage(Diger))
    crew = SealDigest(d=dig)
    name = SealDigest.__name__

    dcast = cast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealDigest._fields
    klas = data.__class__
    assert klas == clan

    qb64 = diger.qb64
    qb2 = diger.qb2
    enclqb64 =  bytearray(b'-QALELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux')
    enclqb2 = bytearray(b'\xf9\x00\x0b\x10\xb0\xb9/x\x81T>\xfbw\xf3\x18m\x81\x86\tD \xa9\x00c'
                        b'\xbbZ8\xc7U\x1d\xfb=\xac/\xeb\xb1')

    # Test data
    structor = Structor(data=data)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew == {'d': dig} # data._asdict()
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    # roundtrip with eqb64b parameter
    buf = bytearray(enclqb64)
    structor = Structor(eqb64b=buf, strip=True)
    #assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew == {'d': dig} # data._asdict()
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # roundtrip with eqb64 parameter
    buf = bytearray(enclqb64)
    structor = Structor(eqb64=buf, strip=True)
    #assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew == {'d': dig} # data._asdict()
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb2 parameter
    buf = bytearray(enclqb2)
    structor = Structor(eqb2=buf, strip=True)
    #assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew == {'d': dig} # data._asdict()
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    assert not buf

    # Test data with cast
    structor = Structor(data=data, cast=cast)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew == {'d': dig} # data._asdict()
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    assert not buf


    # Test cast
    structor = Structor(cast=cast, crew=crew)
    #assert structor.data == data different instances so not ==
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    structor = Structor(cast=cast, qb64b=qb64)
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    structor = Structor(cast=cast, qb64b=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    structor = Structor(cast=cast, qb64b=qb64.encode(), strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    ba = bytearray(qb64.encode())
    structor = Structor(cast=cast, qb64b=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=cast, qb2=qb2, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    ba = bytearray(qb2)
    structor = Structor(cast=cast, qb2=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # Test clan and cast
    structor = Structor(clan=clan, cast=cast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(clan=clan, cast=cast, qb64b=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(clan=clan, cast=cast, qb64b=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # Test clan with cast and crew as dicts
    structor = Structor(clan=clan, cast=dcast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    structor = Structor(cast=cast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=dcast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # Although both cast and crew are dicts the mark matches existing clan
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == name
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast  # tuple compare is by field value not type
    assert structor.cast.__class__.__name__ == name
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    # pick cast and crew as dict that does not match mark of any in AllClanDom AllCastDom
    dcast = {'e': Castage(kls=Diger, ipn=None)}
    dcrew = {'e': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'}
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == "e"
    assert structor.clan.__name__ == 'e'
    assert structor.name == "e"
    assert structor.cast.__class__.__name__ == "e"
    assert structor.crew.__class__.__name__ == "e"
    assert structor.asdict == dcrew == {'e': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'}
    assert structor.qb64 == 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    assert structor.qb64b == b'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    assert structor.qb2 ==(b'\x10\xb0\xb9/x\x81T>\xfbw\xf3\x18m\x81\x86\tD \xa9\x00c\xbbZ8\xc7U\x1d\xfb'
                          b'=\xac/\xeb\xb1')
    with pytest.raises(InvalidValueError):  # # on the fly clan not in ClanCodens
        assert structor.enclose() == enclqb64
    with pytest.raises(InvalidValueError):  # # on the fly clan not in ClanCodens
        assert structor.enclose(cold=Colds.bny) == enclqb2

    # Test with multiple field namedtuple for data.  Using ipn parameter name
    # allows a different value than default numh instead of qb64
    data = SealEvent(i=prefixer, s=number, d=diger)
    clan = SealEvent
    cast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number, 'numh'),
                     d=Castage(Diger))

    #naive cast doesn't know about ipn for Number
    ncast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number),
                     d=Castage(Diger))
    crew = SealEvent(i=aid, s=snh, d=dig)

    # naive crew does't know about ipn for Number (ipn init parameter name)
    # so value must be the default of qb64.
    ncrew = SealEvent(i=aid, s=snq, d=dig)
    name = SealEvent.__name__

    dcast = cast._asdict()
    dcrew = crew._asdict()
    dncrew = ncrew._asdict()

    assert data._fields == SealEvent._fields
    klas = data.__class__
    assert klas == clan

    qb64 = prefixer.qb64 + number.qb64 + diger.qb64  # ''.join(crew)
    qb2 = prefixer.qb2 + number.qb2 + diger.qb2
    enclqb64 = bytearray(b'-SAXBN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zRMAAOELC5L3iBVD77'
                         b'd_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux')
    enclqb2 = bytearray(b'\xf9 \x17\x04\xdeK\xbbDj\xa6\xd9\x89\x0b\xe8\x97\x12WL2\xb9'
                        b'D{\x0e\xd0\xd3[^\xd9\xf2\xe0\xaaV\xea[\xdc\xd10\x00\x0e\x10'
                        b'\xb0\xb9/x\x81T>\xfbw\xf3\x18m\x81\x86\tD \xa9\x00c\xbbZ8\xc7'
                        b'U\x1d\xfb=\xac/\xeb\xb1')

    # Test data
    structor = Structor(data=data)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.cast == ncast
    assert structor.crew == ncrew
    assert structor.asdict == dncrew ==  \
    {
        'i': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
        's': 'MAAO',
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
    }
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # does not rountrip with extract since not cast
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew != structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew != structor.crew
    assert not buf  # stripped

    # Test data with cast so not naive
    structor = Structor(data=data, cast=cast)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew ==  \
    {
        'i': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
        's': 'e',
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
    }
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    # roundtrip with eqb64b parameter
    buf = bytearray(enclqb64)
    structor = Structor(eqb64b=buf, strip=True)
    #assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb64 parameter
    buf = bytearray(enclqb64)
    structor = Structor(eqb64=buf, strip=True)
    #assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb2 parameter
    buf = bytearray(enclqb2)
    structor = Structor(eqb2=buf, strip=True)
    #assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    assert not buf

    # Test cast
    structor = Structor(cast=cast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew == \
    {
        'i': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
        's': 'e',
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
    }
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    structor = Structor(cast=cast, qb64b=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=cast, qb64b=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=cast, qb64b=qb64.encode(), strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    ba = bytearray(qb64.encode())
    structor = Structor(cast=cast, qb64b=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=cast, qb2=qb2, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    ba = bytearray(qb2)
    structor = Structor(cast=cast, qb2=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # Test clan and cast
    structor = Structor(clan=clan, cast=cast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(clan=clan, cast=cast, qb64b=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(clan=clan, cast=cast, qb64b=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)


    # Test clan with cast and crew as dicts
    structor = Structor(clan=clan, cast=dcast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)


    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    structor = Structor(cast=cast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    structor = Structor(cast=dcast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)

    # both cast and crew are dicts but finds matching mark for clan
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == 'SealEvent'
    assert structor.clan == clan
    assert structor.name == 'SealEvent'
    assert structor.cast == cast  # tuple compare is by field value not type
    assert structor.cast.__class__.__name__ == 'SealEvent'
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert structor.enclose() == enclqb64
    assert structor.enclose(cold=Colds.bny) == enclqb2
    assert structor.eqb64 == bytes(enclqb64).decode()
    assert structor.eqb64b == bytes(enclqb64)
    assert structor.eqb2 == bytes(enclqb2)
    # rountrip with extract
    buf = bytearray(enclqb64)
    estructor = Structor.extract(qb64b=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped
    buf = bytearray(enclqb2)
    estructor = Structor.extract(qb2=buf, strip=True)
    assert estructor.crew == structor.crew
    assert not buf  # stripped

    # Test no clan and cast or crew as dict
    with pytest.raises(kering.EmptyMaterialError):
        structor = Structor(cast=dcast)  # missing both crew and data need one or the other

    #with pytest.raises(kering.InvalidValueError):
        #structor = Structor(crew=dcrew)  # gets cast from mark from crew

    # creaes custom clan because pick cast and crew as dict that does not match
    # mark of any in AllClanDom AllCastDom
    dcast = {
                'f': Castage(Prefixer),
                'g': Castage(Number, ipn='numh'),
                'h': Castage(Diger)
            }

    dcrew = {
                'f': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
                'g': 'a',
                'h': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
            }

    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == "f_g_h"
    assert structor.clan.__name__ == "f_g_h"
    assert structor.name == "f_g_h"
    assert structor.cast.__class__.__name__ == "f_g_h"
    assert structor.crew.__class__.__name__ == "f_g_h"
    assert structor.asdict == dcrew
    assert structor.qb64 == 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zRMAAKELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    assert structor.qb64b == b'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zRMAAKELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    assert structor.qb2 ==(b'\x04\xdeK\xbbDj\xa6\xd9\x89\x0b\xe8\x97\x12WL2\xb9D{\x0e\xd0\xd3[^'
                           b'\xd9\xf2\xe0\xaaV\xea[\xdc\xd10\x00\n\x10\xb0\xb9/x\x81T>\xfbw\xf3\x18'
                           b'm\x81\x86\tD \xa9\x00c\xbbZ8\xc7U\x1d\xfb=\xac/\xeb\xb1')

    with pytest.raises(InvalidValueError):  # # on the fly clan not in ClanCodens
        assert structor.enclose() == enclqb64
    with pytest.raises(InvalidValueError):  # # on the fly clan not in ClanCodens
        assert structor.enclose(cold=Colds.bny) == enclqb2


    # Test no clan and cast or crew as dict
    with pytest.raises(kering.EmptyMaterialError):
        structor = Structor(cast=dcast)  # missing crew or data need one or the other

    with pytest.raises(kering.InvalidValueError):
        structor = Structor(crew=dcrew)  # missing cast for custom clan from crew


    """End Test"""


def test_sealer_class():
    """test Sealer class variables etc"""
    assert Sealer.Clans == SClanDom
    assert Sealer.Casts == SCastDom
    assert Sealer.Names == \
    {
        ('d',): 'SealDigest',
        ('rd',): 'SealRoot',
        ('i', 's', 'd'): 'SealEvent',
        ('s', 'd'): 'SealTrans',
        ('i',): 'SealLast',
        ('bi', 'd'): 'SealBack',
        ('t', 'd'): 'SealKind',
    }
    assert Sealer.ClanCodens == \
    {
        'SealDigest': 'DigestSealSingles',
        'SealRoot': 'MerkleRootSealSingles',
        'SealEvent': 'SealSourceTriples',
        'SealTrans': 'SealSourceCouples',
        'SealLast': 'SealSourceLastSingles',
        'SealBack': 'BackerRegistrarSealCouples',
        'SealKind': 'TypedDigestSealCouples'
    }

    assert Sealer.CodenClans == \
    {
        'DigestSealSingles': 'SealDigest',
        'MerkleRootSealSingles': 'SealRoot',
        'SealSourceTriples': 'SealEvent',
        'SealSourceCouples': 'SealTrans',
        'SealSourceLastSingles': 'SealLast',
        'BackerRegistrarSealCouples': 'SealBack',
        'TypedDigestSealCouples': 'SealKind'
    }

    """End Test"""


def test_sealer():
    """test sealer instance"""

    with pytest.raises(kering.InvalidValueError):
        sealer = Sealer()  # test default


    aid = 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
    prefixer = Prefixer(qb64=aid)
    num = 14
    number = Number(num=num)
    snq = number.qb64
    assert snq == 'MAAO'
    snh = number.snh
    assert snh == 'e'
    dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    diger = Diger(qb64=dig)

    # Test with single field namedtuple for data

    data = SealDigest(d=diger)
    clan = SealDigest
    cast = SCastDom.SealDigest  # defined dom cast
    ncast = SealDigest(d=Castage(Diger))  # naive cast
    crew = SealDigest(d=dig)
    ncrew = crew  # since Castage.ipn is None
    name = SealDigest.__name__

    dncast = ncast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealDigest._fields
    klas = data.__class__
    assert klas == clan

    qb64 = diger.qb64
    qb2 = diger.qb2

    # Test data
    sealer = Sealer(data=data)
    assert sealer.data == data
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == ncast
    assert sealer.crew == crew == ncrew
    assert sealer.asdict == dcrew == {'d': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'}
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # test round trip using naive cast
    sealer = Sealer(cast=ncast, qb64=diger.qb64)
    assert isinstance(sealer.data, SealDigest)
    assert sealer.data.d.qb64 == diger.qb64 # not same instance but same serialization
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == ncast == cast  # since ipn == None
    assert sealer.crew == crew
    assert sealer.asdict == crew._asdict()

    # test round trip using known cast (not naive)
    sealer = Sealer(cast=cast, qb64=diger.qb64)
    assert isinstance(sealer.data, SealDigest)
    assert sealer.data.d.qb64 == diger.qb64 # not same instance but same serialization
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast == ncast  # since ipn == None
    assert sealer.crew == crew
    assert sealer.asdict == crew._asdict()

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    sealer = Sealer(crew=crew)  # crew uses known cast i.e. not naive cast
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == crew._asdict()
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    sealer = Sealer(crew=dcrew)  # crew uses known cast i.e. not naive cast
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == crew._asdict()
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # naive cast as dict gets converted to known (not-naive) cast
    sealer = Sealer(cast=dncast, crew=dcrew)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast  # tuple compare is by field value not type
    assert sealer.crew == crew
    assert sealer.asdict == crew._asdict()
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # Test with multiple field namedtuple for data

    data = SealEvent(i=prefixer, s=number, d=diger)
    clan = SealEvent
    cast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number, "numh"),
                     d=Castage(Diger))
    # naive cast since data does not provide ipn for number
    ncast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number),
                     d=Castage(Diger))

    crew = SealEvent(i=aid, s=snh, d=dig)
    # naive crew since data does not provide ipn for number
    ncrew = SealEvent(i=aid, s=snq, d=dig)

    name = SealEvent.__name__

    dncast = ncast._asdict()
    dcrew = crew._asdict()
    dncrew = ncrew._asdict()

    assert data._fields == SealEvent._fields
    klas = data.__class__
    assert klas == clan

    qb64 = prefixer.qb64 + number.qb64 + diger.qb64  # ''.join(crew)
    qb64b = qb64.encode()
    qb2 = prefixer.qb2 + number.qb2 + diger.qb2
    enclqb64 = bytearray(b'-SAXBN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zRMAAOELC5L3iBVD77'
                         b'd_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux')
    enclqb2 = bytearray(b'\xf9 \x17\x04\xdeK\xbbDj\xa6\xd9\x89\x0b\xe8\x97\x12WL2\xb9'
                        b'D{\x0e\xd0\xd3[^\xd9\xf2\xe0\xaaV\xea[\xdc\xd10\x00\x0e\x10'
                        b'\xb0\xb9/x\x81T>\xfbw\xf3\x18m\x81\x86\tD \xa9\x00c\xbbZ8\xc7'
                        b'U\x1d\xfb=\xac/\xeb\xb1')

    # Test data
    sealer = Sealer(data=data)  # bare data so uses naive cast
    assert sealer.data == data
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == ncast != cast  # since ipn for s is not None
    assert sealer.crew == ncrew
    assert sealer.asdict == dncrew == \
           {'i': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
            's': 'MAAO',
            'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'}
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # test round trip with enclose  extract
    assert sealer.enclose() == enclqb64
    assert sealer.enclose(cold=Colds.bny) == enclqb2

    ims = bytearray(enclqb64)
    esealer = Sealer.extract(qb64=ims)
    assert isinstance(esealer, Sealer)
    assert esealer.clan == clan
    assert esealer.name == name
    assert esealer.cast == cast  # since look up cast from clan from ctr
    assert esealer.crew == crew  # since look up crew cast from clan from ctr
    assert esealer.asdict == dcrew
    assert esealer.qb64 == qb64
    assert esealer.qb64b == qb64b
    assert esealer.qb2 == qb2
    assert esealer.enclose() == enclqb64
    assert esealer.enclose(cold=Colds.bny) == enclqb2
    assert esealer.eqb64 == bytes(enclqb64).decode()
    assert esealer.eqb64b == bytes(enclqb64)
    assert esealer.eqb2 == bytes(enclqb2)
    assert ims  # not stripped
    esealer = Sealer.extract(qb64=ims, strip=True)
    assert isinstance(esealer, Sealer)
    assert esealer.clan == clan
    assert esealer.name == name
    assert esealer.cast == cast  # since look up cast from clan from ctr
    assert esealer.crew == crew  # since look up crew cast from clan from ctr
    assert esealer.asdict == dcrew
    assert esealer.qb64 == qb64
    assert esealer.qb64b == qb64b
    assert esealer.qb2 == qb2
    assert not ims  # stripped
    # test round trip with extract qb2
    ims = bytearray(enclqb2)
    esealer = Sealer.extract(qb2=ims)
    assert isinstance(esealer, Sealer)
    assert esealer.clan == clan
    assert esealer.name == name
    assert esealer.cast == cast  # since look up cast from clan from ctr
    assert esealer.crew == crew  # since look up crew cast from clan from ctr
    assert esealer.asdict == dcrew
    assert esealer.qb64 == qb64
    assert esealer.qb64b == qb64b
    assert esealer.qb2 == qb2
    assert esealer.enclose() == enclqb64
    assert esealer.enclose(cold=Colds.bny) == enclqb2
    assert esealer.eqb64 == bytes(enclqb64).decode()
    assert esealer.eqb64b == bytes(enclqb64)
    assert esealer.eqb2 == bytes(enclqb2)
    assert ims  # not stripped
    esealer = Sealer.extract(qb2=ims, strip=True)
    assert isinstance(esealer, Sealer)
    assert esealer.clan == clan
    assert esealer.name == name
    assert esealer.cast == cast  # since look up cast from clan from ctr
    assert esealer.crew == crew  # since look up crew cast from clan from ctr
    assert esealer.asdict == dcrew
    assert esealer.qb64 == qb64
    assert esealer.qb64b == qb64b
    assert esealer.qb2 == qb2
    assert not ims  # stripped

    # roundtrip with eqb64b parameter
    buf = bytearray(enclqb64)
    sealer = Sealer(eqb64b=buf, strip=True)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2
    assert sealer.eqb64 == bytes(enclqb64).decode()
    assert sealer.eqb64b == bytes(enclqb64)
    assert sealer.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb64 parameter
    buf = bytearray(enclqb64)
    sealer = Sealer(eqb64=buf, strip=True)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2
    assert sealer.eqb64 == bytes(enclqb64).decode()
    assert sealer.eqb64b == bytes(enclqb64)
    assert sealer.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb2 parameter
    buf = bytearray(enclqb2)
    sealer = Sealer(eqb2=buf, strip=True)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2
    assert sealer.eqb64 == bytes(enclqb64).decode()
    assert sealer.eqb64b == bytes(enclqb64)
    assert sealer.eqb2 == bytes(enclqb2)
    assert not buf

    # test round trip using naive cast
    sealer = Sealer(cast=ncast, qb64=qb64)
    assert isinstance(sealer.data, SealEvent)
    assert sealer.data.s.qb64 == number.qb64 # not same instance but same serialization
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == ncast != cast  # since ipn for s is not None
    assert sealer.crew == ncrew
    assert sealer.asdict == dncrew == \
           {'i': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
            's': 'MAAO',
            'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'}

    # test round trip using known cast (not naive)
    sealer = Sealer(cast=cast, qb64=qb64)
    assert isinstance(sealer.data, SealEvent)
    assert sealer.data.d.qb64 == diger.qb64 # not same instance but same serialization
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast != ncast  # since ipn for s is not None
    assert sealer.crew == crew
    assert sealer.asdict == dcrew == \
           {'i': 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR',
            's': 'e',
            'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'}


    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    sealer = Sealer(crew=crew)  # uses known cast i.e not naive
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2
    assert sealer.eqb64 == bytes(enclqb64).decode()
    assert sealer.eqb64b == bytes(enclqb64)
    assert sealer.eqb2 == bytes(enclqb2)

    sealer = Sealer(crew=dcrew)  # uses known cast i.e. not naive
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2
    assert sealer.eqb64 == bytes(enclqb64).decode()
    assert sealer.eqb64b == bytes(enclqb64)
    assert sealer.eqb2 == bytes(enclqb2)

    # uses naive cast as dict which uses known cast (i.e. not-naive cast)
    sealer = Sealer(cast=dncast, crew=dcrew)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast  # tuple compare is by field value not type
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2
    assert sealer.eqb64 == bytes(enclqb64).decode()
    assert sealer.eqb64b == bytes(enclqb64)
    assert sealer.eqb2 == bytes(enclqb2)

    """Done Test"""

def test_blinder_class():
    """test Blinder class variables etc"""
    assert Blinder.Clans == BClanDom
    assert Blinder.Casts == BCastDom
    assert Blinder.Names == \
    {
        ('d', 'u', 'td', 'ts'): 'BlindState',
    }
    assert Blinder.ClanCodens == \
    {
        'BlindState': 'BlindedStateQuadruples',
    }

    assert Blinder.CodenClans == \
    {
        'BlindedStateQuadruples': 'BlindState',
    }

    # test makeUUID class method
    salt = '0ABdM7EmNFAlGe05ng6s1ljh'
    salter = Salter(qb64=salt)  # default tier is Tiers.low
    assert salter.qb64 == salt
    sn = 1
    path = Number(num=sn).snh
    assert path == '1'
    uuid = Noncer(raw=salter.stretch(path=path), code=NonceDex.Salt_256).qb64
    assert uuid == 'aE3_MHQbvGMppHB9ZiRxhIq6oEoYPm8AGBxMmSrcBCG_'

    muuid = Blinder.makeUUID(salt=salt, sn=sn)
    assert muuid == uuid

    #Test blind classmethod
    #salt = Salter().qb64
    salt = '0ABdM7EmNFAlGe05ng6s1ljh'
    salter = Salter(qb64=salt)  # default tier is Tiers.low
    assert salter.qb64 == salt
    sn = 1
    path = Number(num=sn).snh
    assert path == '1'
    uuid = Noncer(raw=salter.stretch(path=path), code=NonceDex.Salt_256).qb64
    assert uuid == 'aE3_MHQbvGMppHB9ZiRxhIq6oEoYPm8AGBxMmSrcBCG_'
    acdc = ''
    state = ''
    said = 'EA0zRTJbGoqTCnbuUO83kEzsJlq_CBH_Zo9poEGNnuqF'
    blinder = Blinder.blind(salt=salt, sn=sn)  # defaults acdc='' sn=1, tier=Tiers.low
    assert blinder.crew == BlindState(d='EA0zRTJbGoqTCnbuUO83kEzsJlq_CBH_Zo9poEGNnuqF',
                                      u='aE3_MHQbvGMppHB9ZiRxhIq6oEoYPm8AGBxMmSrcBCG_',
                                      td='',
                                      ts='')

    assert blinder.said == said
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state

    # test if unblinded is acdc or placeholder, generate uuid from salt and sn
    unblinder = Blinder.unblind(said=said,
                                acdc='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                states=['issued', 'revoked'],
                                salt=salt,
                                sn=sn)
    assert unblinder
    assert unblinder.crew == blinder.crew

    salt = '0ABdM7EmNFAlGe05ng6s1ljh'
    salter = Salter(qb64=salt)  # default tier is Tiers.low
    assert salter.qb64 == salt
    sn = 2
    path = Number(num=sn).snh
    assert path == '2'
    uuid = Noncer(raw=salter.stretch(path=path), code=NonceDex.Salt_256).qb64
    assert uuid == 'aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev'
    acdc = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
    state = 'revoked'
    said = 'EBNunxe56wpc40cJa-0mOf2WK6TPV9nU1nkZNcvOn7Rr'
    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)  # defaults tier=Tiers.low
    assert blinder.crew == BlindState(d='EBNunxe56wpc40cJa-0mOf2WK6TPV9nU1nkZNcvOn7Rr',
                                      u='aB3RS8CZP2ds_ZgUyJBuJyim8P8qLRG9wMANIkWPGzev',
                                      td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                      ts='revoked')

    assert blinder.said == said
    assert blinder.uuid == uuid
    assert blinder.acdc == acdc
    assert blinder.state == state

    # test if unblinded is acdc or placeholder, generate uuid from salt and sn
    unblinder = Blinder.unblind(said=said,
                                acdc='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                                states=['issued', 'revoked'],
                                salt=salt,
                                sn=sn)
    assert unblinder
    assert unblinder.crew == blinder.crew


    # Test unblind classmethod
    said = 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
    uuid = 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
    acdc = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
    states = ["issued", "revoked"]

    blinder = Blinder.unblind(said=said, uuid=uuid, acdc=acdc, states=states)
    assert blinder is not None
    assert blinder.crew == BlindState(d=said, u=uuid, td=acdc, ts='issued')

    # Test unblind classmethod with placeholder blinder
    said = 'EH5AC1rOvPwID9Iz6bI-0Cr20pNSsD27JsemQBAYZYWi'
    uuid = 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
    # use empty for td and ts to create placeholder
    crew = BlindState(d='', u=uuid, td='', ts='')
    blinder = Blinder(crew=crew, makify=True)
    assert blinder.said == said
    states = ["issued", "revoked"]

    blinder = Blinder.unblind(said=said, uuid=uuid, acdc=acdc, states=states)
    assert blinder is not None
    assert blinder.crew == BlindState(d=said, u=uuid, td='', ts='')

    #test unblind fails when wrong nonce
    uuid = 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPA'
    blinder = Blinder.unblind(said=said, uuid=uuid, acdc=acdc, states=states)
    assert blinder is None
    """End Test"""


def test_blinder():
    """test blinder instance"""

    with pytest.raises(kering.InvalidValueError):
        blinder = Blinder()  # test default

    sdig = 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
    sdiger = Noncer(qb64=sdig)
    nonce = 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
    noncer = Noncer(nonce=nonce)
    adig = 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ'
    adiger = Noncer(nonce=adig)
    labeler = Labeler(text="issued")
    text = labeler.text
    textq = labeler.qb64
    name = BlindState.__name__

    data = BlindState(d=sdiger, u=noncer, td=adiger, ts=labeler)
    clan = BlindState
    cast = BCastDom.BlindState  # defined dom cast with non-None ipns
    ncast = BlindState(d=Castage(Noncer),
                       u=Castage(Noncer),
                       td=Castage(Noncer),
                       ts=Castage(Labeler))  # naive cast
    crew = BlindState(d=sdig, u=nonce, td=adig, ts=text)
    ncrew = BlindState(d=sdig, u=nonce, td=adig, ts=textq)

    dncast = ncast._asdict()
    dcrew = crew._asdict()
    dncrew = ncrew._asdict()

    assert data._fields == BlindState._fields
    klas = data.__class__
    assert klas == clan

    qb64 = sdiger.qb64 + noncer.qb64 + adiger.qb64 + labeler.qb64
    qb64b = qb64.encode()
    qb2 = sdiger.qb2 + noncer.qb2 + adiger.qb2 + labeler.qb2
    enclqb64 = bytearray(b'-aAjEJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5aJte0a_x8dBbGQrB'
                         b'kdYRgkzvFlQss3ovVOkUz1L1YGPdEBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbY'
                         b'GGCUQgqQ0Missued')

    enclqb2 = bytearray(b'\xf9\xa0#\x10\x90\xac\x12?\r\xe7\xa9\xaf\xbdI\xb8\x82\xda*\xe9\x1b'
                        b'\xa2z\x13\xa4\xd2\x19\xf6\ngLy\x1em\x1d\x12\xf9h\x9b^\xd1'
                        b'\xaf\xf1\xf1\xd0[\x19\n\xc1\x91\xd6\x11\x82L\xef\x16T,\xb3z/'
                        b'T\xe9\x14\xcfR\xf5`c\xdd\x10\x18\xee\xd6\x8e1\xd5G~\xcfk'
                        b'\x0b\xfa\xecK\x0b\x92\xf7\x88\x15C\xef\xb7\x7f1\x86\xd8\x18`\x94B'
                        b'\n\x90\xd0\xc8\xac\xb2\xe7\x9d')

    # Test data naive (no cast)
    blinder = Blinder(data=data)  # bare data so uses naive cast
    assert blinder.data == data
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive data
    assert blinder.crew == ncrew != crew  # since naive data
    assert blinder.asdict == dncrew == \
    {
        'd': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': '0Missued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2
    assert blinder.said == sdig
    assert blinder.saidb == sdig.encode()
    assert blinder.uuid == nonce
    assert blinder.uuidb == nonce.encode()
    assert blinder.acdc == adig
    assert blinder.acdcb == adig.encode()
    assert blinder.state == text
    assert blinder.stateb == text.encode()


    # test round trip with enclose and extract qb64
    assert blinder.enclose() == enclqb64  # ctr from clan
    assert blinder.enclose(cold=Colds.bny) == enclqb2  # ctr from clan
    ims = bytearray(enclqb64)
    eblinder = Blinder.extract(qb64=ims)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.enclose() == enclqb64
    assert eblinder.enclose(cold=Colds.bny) == enclqb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert eblinder.said == sdig
    assert eblinder.saidb == sdig.encode()
    assert ims  # not stripped
    eblinder = Blinder.extract(qb64=ims, strip=True)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert not ims  # stripped
    # test round trip with extract qb2
    ims = bytearray(enclqb2)
    eblinder = Blinder.extract(qb2=ims)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.enclose() == enclqb64
    assert eblinder.enclose(cold=Colds.bny) == enclqb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert eblinder.said == sdig
    assert eblinder.saidb == sdig.encode()
    assert ims  # not stripped
    eblinder = Blinder.extract(qb2=ims, strip=True)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert eblinder.said == sdig
    assert eblinder.saidb == sdig.encode()
    assert not ims  # stripped

    # roundtrip with eqb64b parameter
    buf = bytearray(enclqb64)
    blinder = Blinder(eqb64b=buf, strip=True)
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2
    assert blinder.eqb64 == bytes(enclqb64).decode()
    assert blinder.eqb64b == bytes(enclqb64)
    assert blinder.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb64 parameter
    buf = bytearray(enclqb64)
    blinder = Blinder(eqb64=buf, strip=True)
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2
    assert blinder.eqb64 == bytes(enclqb64).decode()
    assert blinder.eqb64b == bytes(enclqb64)
    assert blinder.eqb2 == bytes(enclqb2)
    assert not buf

    # roundtrip with eqb2 parameter
    buf = bytearray(enclqb2)
    blinder = Blinder(eqb2=buf, strip=True)
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2
    assert blinder.eqb64 == bytes(enclqb64).decode()
    assert blinder.eqb64b == bytes(enclqb64)
    assert blinder.eqb2 == bytes(enclqb2)
    assert not buf

    # test round trip using naive cast
    blinder = Blinder(cast=ncast, qb64=qb64)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.ts.qb64 == labeler.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive ipn
    assert blinder.crew == ncrew != crew  # since naive ipn
    assert blinder.asdict == dncrew == \
    {
        'd': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': '0Missued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2
    assert blinder.enclose() == enclqb64
    assert blinder.enclose(cold=Colds.bny) == enclqb2

    # Test data with cast so not naive cast
    blinder = Blinder(data=data, cast=cast)  # not bare data has cast so use it
    assert blinder.data == data
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # test round trip with enclose  extract
    assert blinder.enclose() == enclqb64
    assert blinder.enclose(cold=Colds.bny) == enclqb2

    ims = bytearray(enclqb64)
    eblinder = Blinder.extract(qb64=ims)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.enclose() == enclqb64
    assert eblinder.enclose(cold=Colds.bny) == enclqb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert ims  # not stripped
    eblinder = Blinder.extract(qb64=ims, strip=True)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert not ims  # stripped
    # test round trip with extract qb2
    ims = bytearray(enclqb2)
    eblinder = Blinder.extract(qb2=ims)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.enclose() == enclqb64
    assert eblinder.enclose(cold=Colds.bny) == enclqb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert ims  # not stripped
    eblinder = Blinder.extract(qb2=ims, strip=True)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert not ims  # stripped

    # test round trip using known cast (not naive)
    blinder = Blinder(cast=cast, qb64=qb64)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.d.qb64 == sdiger.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast  # since ipn for s is not None
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # test round trip with enclose  extract
    assert blinder.enclose() == enclqb64
    assert blinder.enclose(cold=Colds.bny) == enclqb2

    ims = bytearray(enclqb64)
    eblinder = Blinder.extract(qb64=ims)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.enclose() == enclqb64
    assert eblinder.enclose(cold=Colds.bny) == enclqb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert ims  # not stripped
    eblinder = Blinder.extract(qb64=ims, strip=True)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert not ims  # stripped
    # test round trip with extract qb2
    ims = bytearray(enclqb2)
    eblinder = Blinder.extract(qb2=ims)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.enclose() == enclqb64
    assert eblinder.enclose(cold=Colds.bny) == enclqb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert ims  # not stripped
    eblinder = Blinder.extract(qb2=ims, strip=True)
    assert isinstance(eblinder, Blinder)
    assert eblinder.clan == clan
    assert eblinder.name == name
    assert eblinder.cast == cast  # since look up cast from clan from ctr
    assert eblinder.crew == crew  # since look up crew cast from clan from ctr
    assert eblinder.asdict == dcrew
    assert eblinder.qb64 == qb64
    assert eblinder.qb64b == qb64b
    assert eblinder.qb2 == qb2
    assert eblinder.eqb64 == bytes(enclqb64).decode()
    assert eblinder.eqb64b == bytes(enclqb64)
    assert eblinder.eqb2 == bytes(enclqb2)
    assert not ims  # stripped

    # test round trip using known cast (not naive)
    blinder = Blinder(cast=cast, qb2=qb2)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.d.qb64 == sdiger.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast  # since ipn for s is not None
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2
    assert blinder.enclose() == enclqb64
    assert blinder.enclose(cold=Colds.bny) == enclqb2

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    blinder = Blinder(crew=crew)  # uses known cast i.e not naive
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2

    blinder = Blinder(crew=dcrew)  # uses known cast i.e. not naive
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2

    # uses naive cast as dict so looks up known cast == not-naive cast
    blinder = Blinder(cast=dncast, crew=dcrew)
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast  # tuple compare is by field value not type
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2

    # Test Verify fails
    badcrew = BlindState(d='EBTRmLaqixvrJEj5OzK769TAKXL5si31rCKCimOwR_gJ', u=nonce, td=adig, ts=text)
    with pytest.raises(ValidationError):
        blinder = Blinder(crew=badcrew)  # uses known cast i.e not naive


    # Test makify using data and cast to init
    # Test data with cast so not naive cast
    said = 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'

    dmcrew = dict(dcrew)
    dmcrew['d'] = said
    mqb64 = ('EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
             'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
             'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ0Missued')
    mqb64b = (b'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
              b'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
              b'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ0Missued')
    mqb2 = (b'\x10\x90\xac\x12?\r\xe7\xa9\xaf\xbdI\xb8\x82\xda*\xe9\x1b\xa2z\x13'
            b'\xa4\xd2\x19\xf6\ngLy\x1em\x1d\x12\xf9h\x9b^\xd1\xaf\xf1\xf1\xd0[\x19\n'
            b'\xc1\x91\xd6\x11\x82L\xef\x16T,\xb3z/T\xe9\x14\xcfR\xf5`c\xdd\x10\x18'
            b'\xee\xd6\x8e1\xd5G~\xcfk\x0b\xfa\xecK\x0b\x92\xf7\x88\x15C\xef\xb7\x7f1\x86'
            b'\xd8\x18`\x94B\n\x90\xd0\xc8\xac\xb2\xe7\x9d')

    blinder = Blinder(data=data, cast=cast, makify=True)
    assert blinder.data.d.qb64 == said
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew._replace(d=said)
    assert blinder.asdict == dmcrew
    assert blinder.qb64 == mqb64
    assert blinder.qb64b == mqb64b
    assert blinder.qb2 == mqb2

    # Test makify with empty said 'd' field using crew to init
    # Test data with cast so not naive cast
    said = 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'

    mcrew = crew._replace(d='')  # crew with empty value for said 'd' field
    assert mcrew == BlindState(d='',
                               u='aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
                               td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                               ts='issued')
    dmcrew = dict(dcrew)
    dmcrew['d'] = said
    mqb64 = ('EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
             'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
             'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ0Missued')
    mqb64b = (b'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
              b'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
              b'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ0Missued')
    mqb2 = (b'\x10\x90\xac\x12?\r\xe7\xa9\xaf\xbdI\xb8\x82\xda*\xe9\x1b\xa2z\x13'
            b'\xa4\xd2\x19\xf6\ngLy\x1em\x1d\x12\xf9h\x9b^\xd1\xaf\xf1\xf1\xd0[\x19\n'
            b'\xc1\x91\xd6\x11\x82L\xef\x16T,\xb3z/T\xe9\x14\xcfR\xf5`c\xdd\x10\x18'
            b'\xee\xd6\x8e1\xd5G~\xcfk\x0b\xfa\xecK\x0b\x92\xf7\x88\x15C\xef\xb7\x7f1\x86'
            b'\xd8\x18`\x94B\n\x90\xd0\xc8\xac\xb2\xe7\x9d')


    blinder = Blinder(crew=mcrew, makify=True)
    assert blinder.data.d.qb64 == said
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew._replace(d=said)
    assert blinder.asdict == dmcrew
    assert blinder.qb64 == mqb64
    assert blinder.qb64b == mqb64b
    assert blinder.qb2 == mqb2

    # Test makify with empty said 'd' field using data and cast to init
    # Test data with cast so not naive cast
    said = 'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
    mdata = data._replace(d=Noncer(nonce=''))
    assert mdata.d.qb64 == '1AAP'
    mcrew = crew._replace(d='')  # crew with empty value for said 'd' field
    assert mcrew == BlindState(d='',
                               u='aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
                               td='EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
                               ts='issued')
    dmcrew = dict(dcrew)
    dmcrew['d'] = said
    mqb64 = ('EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
             'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
             'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ0Missued')
    mqb64b = (b'EJCsEj8N56mvvUm4gtoq6RuiehOk0hn2CmdMeR5tHRL5'
              b'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd'
              b'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ0Missued')
    mqb2 = (b'\x10\x90\xac\x12?\r\xe7\xa9\xaf\xbdI\xb8\x82\xda*\xe9\x1b\xa2z\x13'
            b'\xa4\xd2\x19\xf6\ngLy\x1em\x1d\x12\xf9h\x9b^\xd1\xaf\xf1\xf1\xd0[\x19\n'
            b'\xc1\x91\xd6\x11\x82L\xef\x16T,\xb3z/T\xe9\x14\xcfR\xf5`c\xdd\x10\x18'
            b'\xee\xd6\x8e1\xd5G~\xcfk\x0b\xfa\xecK\x0b\x92\xf7\x88\x15C\xef\xb7\x7f1\x86'
            b'\xd8\x18`\x94B\n\x90\xd0\xc8\xac\xb2\xe7\x9d')

    blinder = Blinder(data=mdata, cast=cast, makify=True)
    assert blinder.data.d.qb64 == said
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew._replace(d=said)
    assert blinder.asdict == dmcrew
    assert blinder.qb64 == mqb64
    assert blinder.qb64b == mqb64b
    assert blinder.qb2 == mqb2

    # repeat tests with empty nonce and empty 'td' trans said and empty state
    sdig = 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc'
    sdiger = Noncer(qb64=sdig)

    nonce = ''
    noncer = Noncer(nonce=nonce)
    nonceq = noncer.qb64

    adig = ''
    adiger = Noncer(nonce=adig)
    adigq = adiger.qb64

    text = ''
    labeler = Labeler(text=text)
    textq = labeler.qb64

    name = BlindState.__name__

    data = BlindState(d=sdiger, u=noncer, td=adiger, ts=labeler)
    clan = BlindState
    cast = BCastDom.BlindState  # defined dom cast with non-None ipns
    ncast = BlindState(d=Castage(Noncer),
                       u=Castage(Noncer),
                       td=Castage(Noncer),
                       ts=Castage(Labeler))  # naive cast
    crew = BlindState(d=sdig, u=nonce, td=adig, ts=text)
    ncrew = BlindState(d=sdig, u=nonceq, td=adigq, ts=textq)

    dncast = ncast._asdict()
    dcrew = crew._asdict()
    dncrew = ncrew._asdict()

    assert data._fields == BlindState._fields
    klas = data.__class__
    assert klas == clan

    qb64 = sdiger.qb64 + noncer.qb64 + adiger.qb64 + labeler.qb64
    qb64b = qb64.encode()
    qb2 = sdiger.qb2 + noncer.qb2 + adiger.qb2 + labeler.qb2

    # Test data naive (no cast)
    blinder = Blinder(data=data)  # bare data so uses naive cast
    assert blinder.data == data
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive data
    assert blinder.crew == ncrew != crew  # since naive data
    assert blinder.asdict == dncrew == \
    {
        'd': 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc',
        'u': '1AAP',
        'td': '1AAP',
        'ts': '1AAP'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2
    assert blinder.said == sdig
    assert blinder.saidb == sdig.encode()
    assert blinder.uuid == nonce
    assert blinder.uuidb == nonce.encode()
    assert blinder.acdc == adig
    assert blinder.acdcb == adig.encode()
    assert blinder.state == text
    assert blinder.stateb == text.encode()

    # test round trip using naive cast
    blinder = Blinder(cast=ncast, qb64=qb64)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.ts.qb64 == labeler.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive ipn
    assert blinder.crew == ncrew != crew  # since naive ipn
    assert blinder.asdict == dncrew == \
    {
        'd': 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc',
        'u': '1AAP',
        'td': '1AAP',
        'ts': '1AAP'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # Test data with cast so non-naive
    blinder = Blinder(data=data, cast=cast)  # data with cast
    assert blinder.data == data
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc',
        'u': '',
        'td': '',
        'ts': ''
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # test round trip using known cast (not naive)
    blinder = Blinder(cast=cast, qb64=qb64)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.d.qb64 == sdiger.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast  # since ipn for s is not None
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc',
        'u': '',
        'td': '',
        'ts': ''
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # test round trip using known cast (not naive)
    blinder = Blinder(cast=cast, qb2=qb2)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.d.qb64 == sdiger.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast  # since ipn for s is not None
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc',
        'u': '',
        'td': '',
        'ts': ''
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    blinder = Blinder(crew=crew)  # uses known cast i.e not naive
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2

    blinder = Blinder(crew=dcrew)  # uses known cast i.e. not naive
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2

    # uses naive cast as dict so looks up known cast == not-naive cast
    blinder = Blinder(cast=dncast, crew=dcrew)
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast  # tuple compare is by field value not type
    assert blinder.crew == crew
    assert blinder.asdict == dcrew
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64.encode()
    assert blinder.qb2 == qb2

    # Test Verify fails
    badcrew = BlindState(d='EBTRmLaqixvrJEj5OzK769TAKXL5si31rCKCimOwR_gJ', u=nonce, td=adig, ts=text)
    with pytest.raises(ValidationError):
        blinder = Blinder(crew=badcrew)  # uses known cast i.e not naive

    # Test makify
    # Test data with cast so not naive cast
    said = 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc'

    dmcrew = dict(dcrew)
    dmcrew['d'] = said
    mqb64 = 'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc1AAP1AAP1AAP'
    mqb64b = b'ENVNCgfL7yPno3U7eJ99EzABtuycUGfLYDFjx6x30VJc1AAP1AAP1AAP'
    mqb2 = (b'\x10\xd5M\n\x07\xcb\xef#\xe7\xa3u;x\x9f}\x130\x01\xb6\xec\x9cPg\xcb`1c\xc7'
            b'\xacw\xd1R\\\xd4\x00\x0f\xd4\x00\x0f\xd4\x00\x0f')

    blinder = Blinder(data=data, cast=cast, makify=True)
    assert blinder.data.d.qb64 == said
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast
    assert blinder.crew == crew._replace(d=said)
    assert blinder.asdict == dmcrew
    assert blinder.qb64 == mqb64
    assert blinder.qb64b == mqb64b
    assert blinder.qb2 == mqb2
    assert blinder.said == sdig
    assert blinder.saidb == sdig.encode()
    assert blinder.uuid == nonce
    assert blinder.uuidb == nonce.encode()
    assert blinder.acdc == adig
    assert blinder.acdcb == adig.encode()
    assert blinder.state == text
    assert blinder.stateb == text.encode()

    """Done Test"""


if __name__ == "__main__":
    test_structor_doms()
    test_structor_class()
    test_structor()
    test_sealer_class()
    test_sealer()
    test_blinder_class()
    test_blinder()



