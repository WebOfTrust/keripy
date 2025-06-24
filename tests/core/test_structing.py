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
from keri.kering import InvalidValueError, EmptyMaterialError

from keri.help import helping

from keri.core import (Matter, Diger, Prefixer, Number, Verser, Labeler,
                       Noncer, NonceDex)


from keri.core import structing
from keri.core.structing import (SealDigest, SealRoot, SealBack, SealEvent,
                                 SealLast, SealTrans, SealKind, BlindState)
from keri.core.structing import (Castage, CodeToClans, ClanToCodes,
                                 Structor, EClanDom, ECastDom,
                                 Sealer, SClanDom, SCastDom,
                                 Blinder, BClanDom, BCastDom)


def test_structor_doms():
    """test doms in structure"""

    assert EClanDom == structing.EmptyClanDom()
    assert ECastDom == structing.EmptyCastDom()
    assert SClanDom == structing.SealClanDom()
    assert SCastDom == structing.SealCastDom()

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
        'BlindState': BlindState(d=Castage(kls=Diger, ipn=None),
                                 u=Castage(kls=Noncer, ipn='nonce'),
                                 td=Castage(kls=Noncer, ipn='nonce'),
                                 ts=Castage(kls=Labeler, ipn='text'))
    }


    assert ClanToCodes == \
    {
        'SealDigest': '-Q',
        'SealRoot': '-R',
        'SealEvent': '-S',
        'SealTrans': '-T',
        'SealLast': '-U',
        'SealBack': '-V',
        'SealKind': '-W',
        'BlindState': '-a'
    }
    assert CodeToClans == \
    {
        '-Q': 'SealDigest',
        '-R': 'SealRoot',
        '-S': 'SealEvent',
        '-T': 'SealTrans',
        '-U': 'SealLast',
        '-V': 'SealBack',
        '-W': 'SealKind',
        '-a': 'BlindState'
    }

    """End Test"""


def test_structor_class():
    """test Structor class variables etc"""

    assert Structor.Clans == EClanDom
    assert Structor.Casts == ECastDom
    assert Structor.Names == {}
    assert Structor.ClanCodes == ClanToCodes == \
    {
        'SealDigest': '-Q',
        'SealRoot': '-R',
        'SealEvent': '-S',
        'SealTrans': '-T',
        'SealLast': '-U',
        'SealBack': '-V',
        'SealKind': '-W',
        'BlindState': '-a'
    }
    assert Structor.CodeClans == CodeToClans == \
    {
        '-Q': 'SealDigest',
        '-R': 'SealRoot',
        '-S': 'SealEvent',
        '-T': 'SealTrans',
        '-U': 'SealLast',
        '-V': 'SealBack',
        '-W': 'SealKind',
        '-a': 'BlindState'
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

    structor = Structor(cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode(), strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    ba = bytearray(qb64.encode())
    structor = Structor(cast=cast, qb64=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty

    structor = Structor(cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb2=qb2, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

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

    structor = Structor(clan=clan, cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

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

    structor = Structor(cast=dcast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # creates custom clan since both cast and crew are dicts
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == "d"
    assert structor.clan != clan
    assert structor.name == "d"
    assert structor.cast == cast  # tuple compare is by field value not type
    assert structor.cast.__class__.__name__ == "d"
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2


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

    structor = Structor(cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode(), strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    ba = bytearray(qb64.encode())
    structor = Structor(cast=cast, qb64=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty

    structor = Structor(cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb2=qb2, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

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

    structor = Structor(clan=clan, cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2


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

    structor = Structor(cast=dcast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # creates custom clan since both cast and crew are dicts
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == "i_s_d"
    assert structor.clan != clan
    assert structor.name == "i_s_d"
    assert structor.cast == cast  # tuple compare is by field value not type
    assert structor.cast.__class__.__name__ == "i_s_d"
    assert structor.crew == crew
    assert structor.asdict == dcrew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test no clan and cast or crew as dict
    with pytest.raises(kering.EmptyMaterialError):
        structor = Structor(cast=dcast)  # missing crew

    with pytest.raises(kering.InvalidValueError):
        structor = Structor(crew=crew)  # missing cast

    """End Test"""



def test_sealer_class():
    """
    test sealer class variables etc
    """
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
    qb2 = prefixer.qb2 + number.qb2 + diger.qb2

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

    sealer = Sealer(crew=dcrew)  # uses known cast i.e. not naive
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == dcrew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

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

    """Done Test"""

def test_blinder():
    """test blinder instance"""


    with pytest.raises(kering.InvalidValueError):
        blinder = Blinder()  # test default


    sdig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    sdiger = Diger(qb64=sdig)
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
    ncast = BlindState(d=Castage(Diger),
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

    # Test data naive (no cast)
    blinder = Blinder(data=data)  # bare data so uses naive cast
    assert blinder.data == data
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive data
    assert blinder.crew == ncrew != crew  # since naive data
    assert blinder.asdict == dncrew == \
    {
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': '0Missued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # test round trip using naive cast
    blinder = Sealer(cast=ncast, qb64=qb64)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.ts.qb64 == labeler.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive ipn
    assert blinder.crew == ncrew != crew  # since naive ipn
    assert blinder.asdict == dncrew == \
    {
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': '0Missued'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # Test data with cast so not naive cast
    blinder = Blinder(data=data, cast=cast)  # not bare data has cast so use it
    assert blinder.data == data
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == cast != ncast
    assert blinder.crew == crew != ncrew
    assert blinder.asdict == dcrew == \
    {
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
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
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
        'u': 'aJte0a_x8dBbGQrBkdYRgkzvFlQss3ovVOkUz1L1YGPd',
        'td': 'EBju1o4x1Ud-z2sL-uxLC5L3iBVD77d_MYbYGGCUQgqQ',
        'ts': 'issued'
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

    # repeat tests with empty nonce and empty 'td' trans said and empty state
    sdig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    sdiger = Diger(qb64=sdig)

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
    ncast = BlindState(d=Castage(Diger),
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
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
        'u': '1AAP',
        'td': '1AAP',
        'ts': '1AAP'
    }
    assert blinder.qb64 == qb64
    assert blinder.qb64b == qb64b
    assert blinder.qb2 == qb2

    # test round trip using naive cast
    blinder = Sealer(cast=ncast, qb64=qb64)
    assert isinstance(blinder.data, BlindState)
    assert blinder.data.ts.qb64 == labeler.qb64 # not same instance but same serialization
    assert blinder.clan == clan
    assert blinder.name == name
    assert blinder.cast == ncast != cast  # since naive ipn
    assert blinder.crew == ncrew != crew  # since naive ipn
    assert blinder.asdict == dncrew == \
    {
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
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
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
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
        'd': 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
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

    """Done Test"""


if __name__ == "__main__":
    test_structor_doms()
    test_structor_class()
    test_structor()
    test_sealer_class()
    test_sealer()
    test_blinder()



