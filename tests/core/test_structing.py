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

from keri.help import helping

from keri.core import (Matter, Diger, Verfer, Number)


from keri.core import structing
from keri.core.structing import (SealDigest, SealRoot, SealBacker, SealEvent,
                                 SealLast, SealTrans)
from keri.core.structing import Structor


def test_structor():
    """
    test Structor instance
    """

    with pytest.raises(kering.InvalidValueError):
        structor = Structor()  # test default

    dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    diger = Diger(qb64=dig)
    aid = ""
    #verfer = Verfer()
    num = 14
    number = Number(num=num)


    qb64 = diger.qb64
    qb2 = diger.qb2

    data = SealDigest(d=diger)
    clan = SealDigest
    cast = SealDigest(d=Diger)
    crew = SealDigest(d=dig)

    dcast = cast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealDigest._fields
    klas = data.__class__
    assert klas == clan

    # Test data
    structor = Structor(data=data)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.asdict == data._asdict()
    assert structor.asdict == {'d': diger}
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test cast
    structor = Structor(cast=cast, crew=crew)
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64)
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode())
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb2=qb2)
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test clan and cast
    structor = Structor(clan=clan, cast=cast, crew=crew)
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64)
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64.encode())
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    #assert structor.data == data  # not same diger object so no ==
    assert structor.clan == clan
    assert structor.cast == cast
    # assert structor.asdict == {'d': diger} # not same diger object so no ==
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test clan with cast and crew as dicts


    # Test no clan but with one or the other of cast and crew as dict or namedtuple


    # repeat all tests with multiple field clan so can test strip and not strip


    """End Test"""


if __name__ == "__main__":
    test_structor()


