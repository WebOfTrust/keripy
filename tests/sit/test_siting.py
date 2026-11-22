# -*- encoding: utf-8 -*-
"""
tests.sit.test_siting module

"""
import random
import math
from collections import deque

import pytest
from keri import Versionage
from keri.core import NumDex, Number, DigDex, Diger, Noncer, Verser, Ilker
from keri.sit import (Version, MaxSpan, MaxSpanBytes, Kithage, Kiths,
                      NodeSaidage, Nodage, LeafSaidage, Leafage, Partage,
                      Siter, Emptier, EmptyQb2, EmptyQb64)


def test_siting_siter_class():
    """Test of siting module and siter class methods"""

    assert Version == Versionage(0, 0)
    assert MaxSpan == 256
    assert MaxSpanBytes == 32
    assert MaxSpan == 2 ** 3 * MaxSpanBytes

    assert isinstance(Kiths, Kithage)
    assert Kiths._asdict() == {'node': 'nod', 'leaf': 'lea'}

    assert EmptyQb64 == '1AAP'
    assert EmptyQb2 == b'\xd4\x00\x0f'

    assert Siter.Code == DigDex.Blake3_256
    assert Siter.Dummy == '#'
    assert Diger._rawSize(Siter.Code) == MaxSpanBytes


    # test saidify
    # tree wide
    # noncer = Noncer(nonce=None)  # creates random 16 bytes for nonce
    tuid = '0AAKbe-QRrZVxTMgs7gVAfp1'
    tuider = Noncer(nonce=tuid)
    assert tuider.nonce == tuid

    # test node saidify
    # node type specific
    nither = Ilker(ilk=Kiths.node, strict=False)
    assert nither.tag == Kiths.node
    assert nither.qb64 == 'Xnod'

    # per node
    nepther = Number(num=0)  # root
    assert nepther.qb64 == 'MAAA'
    nimber = Diger(num=0, code=Siter.Code)
    assert nimber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    # create NodeSaidage and saidify with matter primitive instances
    saidage = NodeSaidage(kith=nither,
                          tuid=tuider,
                          said=Emptier, # placeholder
                          span=nepther,
                          limb=nimber,
                          left=Emptier,
                          right=Emptier)

    assert saidage._asdict() == \
    {
        'kith': nither,
        'tuid': tuider,
        'said': Emptier,
        'span': nepther,
        'limb': nimber,
        'left': Emptier,
        'right': Emptier,
     }

    # replace saidage with SAIDed copy
    saidage = Siter.saidify(saidage=saidage)
    assert saidage.said.qb64 == 'EEg3acFSwntGOgT81WZPlcqup7ix1w9GTqDnVsXK3Mgr'
    dqb64 = {l: v.qb64 for l, v in saidage._asdict().items()}
    assert dqb64 == \
    {
        'kith': 'Xnod',
        'tuid': '0AAKbe-QRrZVxTMgs7gVAfp1',
        'said': 'EEg3acFSwntGOgT81WZPlcqup7ix1w9GTqDnVsXK3Mgr',
        'span': 'MAAA',
        'limb': 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'left': '1AAP',
        'right': '1AAP'
    }

    # create nodage with qb2 values
    nodage = Nodage(span=saidage.span.qb2,
                    limb=saidage.limb.qb2,
                    left=saidage.left.qb2,
                    right=saidage.right.qb2)


    assert nodage._asdict() == \
    {
        'span': b'0\x00\x00',
        'limb': b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00',
         'left': b'\xd4\x00\x0f',
         'right': b'\xd4\x00\x0f'
    }

    # create node Partage of nodage with qb2 values
    part = Partage(said=saidage.said.qb2, part=nodage)
    assert part._asdict() == \
    {
        'said': b'\x10H7i\xc1R\xc2{F:\x04\xfc\xd5fO\x95\xca\xae\xa7\xb8\xb1\xd7\x0fF'
                b'N\xa0\xe7V\xc5\xca\xdc\xc8+',
        'part': Nodage(span=b'0\x00\x00',
                       limb=b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                       left=b'\xd4\x00\x0f',
                       right=b'\xd4\x00\x0f')
    }

    # test leaf saidify
    # leaf specific
    # leaf type specific
    lither = Ilker(ilk=Kiths.leaf, strict=False)
    assert lither.tag == Kiths.leaf
    assert lither.qb64 == 'Xlea'

    # per leaf
    lepther = Number(num=256)  # leaf
    assert lepther.qb64 == 'MAEA'
    infoer = Diger(ser=b"Leaf Info Here", code=DigDex.Blake2b_256) # not default SIT code
    assert infoer.qb64 == 'FAZi0qhemPCKISh8cvUK5z3iDHlcPsPz18SJCRHS0qnH'
    limber = Diger(ser=infoer.qb64b, code=Siter.Code)
    assert limber.qb64 == 'EKE_SPb9j35_FOnE649CPQfWNRYAq4JaklV-08uPpGP5'

    # create LeafSaidage and saidify with matter primitive instances
    saidage = LeafSaidage(kith=lither,
                          tuid=tuider,
                          said=Emptier, # placeholder
                          span=lepther,
                          limb=limber)

    assert saidage._asdict() == \
    {
        'kith': lither,
        'tuid': tuider,
        'said': Emptier,
        'span': lepther,
        'limb': limber
     }

    # replace saidage with SAIDed copy
    saidage = Siter.saidify(saidage=saidage)
    assert saidage.said.qb64 == 'EKKDHvefxLQO_OGhjDAxf22fJVDsvTOYZqzo5mBhskbR'
    dqb64 = {l: v.qb64 for l, v in saidage._asdict().items()}
    assert dqb64 == \
    {
        'kith': 'Xlea',
        'tuid': '0AAKbe-QRrZVxTMgs7gVAfp1',
        'said': 'EKKDHvefxLQO_OGhjDAxf22fJVDsvTOYZqzo5mBhskbR',
        'span': 'MAEA',
        'limb': 'EKE_SPb9j35_FOnE649CPQfWNRYAq4JaklV-08uPpGP5'
    }


    # create leafage with qb2 values
    leafage = Leafage(span=saidage.span.qb2,
                      limb=saidage.limb.qb2)

    assert leafage._asdict() == \
    {
        'span': b'0\x01\x00',
        'limb': b'\x10\xa1?H\xf6\xfd\x8f~\x7f\x14\xe9\xc4\xeb\x8fB=\x07\xd65\x16'
                b'\x00\xab\x82Z\x92U~\xd3\xcb\x8f\xa4c\xf9',
    }

    # create leaf Partage of leafage with qb2 values
    part = Partage(said=saidage.said.qb2, part=leafage)
    assert part._asdict() == \
    {
        'said': b'\x10\xa2\x83\x1e\xf7\x9f\xc4\xb4\x0e\xfc\xe1\xa1\x8c01\x7fm\x9f%P'
                b'\xec\xbd3\x98f\xac\xe8\xe6`a\xb2F\xd1',
         'part': Leafage(span=b'0\x01\x00',
                         limb=b'\x10\xa1?H\xf6\xfd\x8f~\x7f\x14\xe9\xc4\xeb\x8fB=\x07\xd65\x16\x00\xab\x82Z\x92U~\xd3\xcb\x8f\xa4c\xf9')
    }


    # test staticmethods
    # .rightAtSpan() and .rightAtSpanInt()
    limber = Diger(num=0, code=Siter.Code)  # use default code
    spanner = Number(num=0)
    with pytest.raises(ValueError):
        Siter.rightAtSpan(limber, spanner)  # span of zero

    limb = limber.num  # get int
    span = spanner.num
    assert limb == 0
    span = 0
    with pytest.raises(ValueError):
        Siter.rightAtSpanInt(limb, span)  # span of zero

    limb = 0
    assert f"{limb:0256b}"[:8] == '00000000'
    span = 1
    assert not Siter.rightAtSpanInt(limb, span)  # left at span=1

    limb = 4 << 252
    assert f"{limb:0256b}"[:8] == '01000000'
    span = 2
    assert Siter.rightAtSpanInt(limb, span)  # right at span=2

    limb = 6 << 252
    assert f"{limb:0256b}"[:8] == '01100000'
    span = 3
    assert Siter.rightAtSpanInt(limb, span)  # right at span=3

    limber = Diger(qb64=nimber.qb64)
    assert limber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    spanner = Number(num=1)
    assert spanner.qb64 == 'MAAB'
    assert not Siter.rightAtSpan(limber, spanner)  # left at span=1
    limb = int.from_bytes(limber.raw)
    assert f"{limb:0256b}"[:8] == '00000000'
    assert spanner.num == 1
    assert not Siter.rightAtSpanInt(limb, spanner.num)  # left at span=1

    limber = Diger(qb64='EEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    spanner = Number(qb64='MAAC')
    assert Siter.rightAtSpan(limber, spanner)  # right at span=2
    limb = int.from_bytes(limber.raw)
    assert f"{limb:0256b}"[:8] == '01000000'
    assert spanner.num == 2
    assert Siter.rightAtSpanInt(limb, spanner.num)  # right at span=2

    limber = Diger(qb64='EGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    spanner = Number(qb64='MAAD')
    assert Siter.rightAtSpan(limber, spanner)  # right at span=2
    limb = int.from_bytes(limber.raw)
    assert f"{limb:0256b}"[:8] == '01100000'
    assert spanner.num == 3
    assert Siter.rightAtSpanInt(limb, spanner.num)  # right at span=2


    # Test twigAtSpan staticmethods
    limber = Diger(num=(1 << 255))
    assert limber.numh == '8000000000000000000000000000000000000000000000000000000000000000'
    assert len(limber.numh) == 64
    limb=limber.num
    spanner = Number(num=1)
    span=spanner.num
    assert span == 1

    twig = Siter.twigAtSpanInt(limb, span)
    assert twig == 1

    twigger = Siter.twigAtSpan(limber, spanner)
    assert twigger.num == twig

    limber = Diger(num=(1 << 254))
    assert limber.numh == '4000000000000000000000000000000000000000000000000000000000000000'
    assert len(limber.numh) == 64
    limb=limber.num

    twig = Siter.twigAtSpanInt(limb, span)
    assert twig == 0

    twigger = Siter.twigAtSpan(limber, spanner)
    assert twigger.num == twig

    spanner = Number(num=2)
    span=spanner.num
    assert span == 2

    twig = Siter.twigAtSpanInt(limb, span)
    assert twig == 1

    twigger = Siter.twigAtSpan(limber, spanner)
    assert twigger.num == twig

    spanner = Number(num=3)
    span=spanner.num
    assert span == 3

    twig = Siter.twigAtSpanInt(limb, span)
    assert twig == 2

    twigger = Siter.twigAtSpan(limber, spanner)
    assert twigger.num == twig

    limber = Diger(num=( 10 << 252))
    assert limber.numh == 'a000000000000000000000000000000000000000000000000000000000000000'
    assert len(limber.numh) == 64
    limb=limber.num

    spanner = Number(num=4)
    span=spanner.num
    assert span == 4

    twig = Siter.twigAtSpanInt(limb, span)
    assert twig == 10

    twigger = Siter.twigAtSpan(limber, spanner)
    assert twigger.num == twig

    # test fitLeafNode(leaf, node, span)
    leafer = Diger(num=(11 << 252))
    assert leafer.numh == 'b000000000000000000000000000000000000000000000000000000000000000'

    noder = Diger(num=(10 << 252))
    assert noder.numh == 'a000000000000000000000000000000000000000000000000000000000000000'

    span = 1
    spanner = Number(num=span)
    assert Siter.fitLeafNodeInt(leafer.num, noder.num, spanner.num)
    assert Siter.fitLeafNode(leafer, noder, spanner)

    span += 1
    spanner = Number(num=span)
    assert Siter.fitLeafNodeInt(leafer.num, noder.num, spanner.num)
    assert Siter.fitLeafNode(leafer, noder, spanner)

    span += 1
    spanner = Number(num=span)
    assert Siter.fitLeafNodeInt(leafer.num, noder.num, spanner.num)
    assert Siter.fitLeafNode(leafer, noder, spanner)

    span += 1
    spanner = Number(num=span)
    assert not Siter.fitLeafNodeInt(leafer.num, noder.num, spanner.num)
    assert not Siter.fitLeafNode(leafer, noder, spanner)

    # test forkSpanSwapInt(left, right)
    lefter = Diger(num = (11 << 252))
    assert lefter.numh == 'b000000000000000000000000000000000000000000000000000000000000000'
    righter = Diger(num = (10 << 252))
    assert righter.numh == 'a000000000000000000000000000000000000000000000000000000000000000'

    span, swap = Siter.forkSpanSwapInt(lefter.num, righter.num)
    assert span == 4
    assert swap

    spanner, swap = Siter.forkSpanSwap(lefter, righter)
    assert spanner.num == 4
    assert swap

    lefter = Diger(num = (10 << 252))
    assert lefter.numh == 'a000000000000000000000000000000000000000000000000000000000000000'
    righter = Diger(num = (11 << 252))
    assert righter.numh == 'b000000000000000000000000000000000000000000000000000000000000000'

    span, swap = Siter.forkSpanSwapInt(lefter.num, righter.num)
    assert span == 4
    assert not swap

    spanner, swap = Siter.forkSpanSwap(lefter, righter)
    assert spanner.num == 4
    assert not swap

    with pytest.raises(ValueError):
        span, swap = Siter.forkSpanSwapInt(lefter.num, lefter.num)

    with pytest.raises(ValueError):
        span, swap = Siter.forkSpanSwap(lefter, lefter)

    """Done Test"""


def test_siter_basic():
    """Test basic siter instance creation and methods"""
    siter = Siter()  # default Siter
    assert len(siter.tuider.qb64) == 24  # random tuid
    assert siter.code == DigDex.Blake3_256
    assert siter.root
    assert len(siter.nodes) == 1
    assert siter.leaves == {}
    assert siter.infos == {}

    tuid = '0ACiicCYoKAqao8qDdnlFVrY'
    siter = Siter(tuid=tuid)  # Siter with known tuid
    assert siter.tuider.qb64 == tuid
    assert siter.code == DigDex.Blake3_256
    assert siter.root
    rqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert rqb64._asdict() == \
    {
        'said': 'ENtWb6xykmkwzn3hiDmfCOS_crgAI6oQ6jLmHR_HlrF0',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='1AAP',
                       right='1AAP')
    }
    assert len(siter.nodes) == 1
    nodage = siter.getNode(siter.root.said)
    nqb64 = Nodage(span=nodage.span.qb64,
                   limb=nodage.limb.qb64,
                   left=nodage.left.qb64,
                   right=nodage.right.qb64)
    assert nqb64 == rqb64.part  # round trips

    assert siter.leaves == {}
    assert siter.infos == {}

    # test .sayNode(self, nodage)   (compute said)
    spanner = Number(num=1)
    limb = 2 ** 254
    limber = Diger(num=limb, code=Siter.Code)  # limb all 0s
    assert limber.qb64 == 'EEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    nodage = Nodage(span=spanner,
                    limb=limber,
                    left=Noncer(nonce=""),
                    right=Noncer(nonce=""))
    saider = siter.sayNode(nodage)
    assert saider.qb64 == 'ECD_U3STi9BvTJc5RSsBJubJtAFD-UTtS10biijM1hLE'

    # test node storage functions
    assert not siter.hasNode(saider)
    assert not siter.getNode(saider)
    assert siter.putNode(saider, nodage)  # put node
    assert siter.hasNode(saider)
    assert siter.isNode(saider)
    result = siter.getNode(saider)  # round trip
    assert isinstance(result, Nodage)
    assert result.span.qb64 == nodage.span.qb64
    assert result.limb.qb64 == nodage.limb.qb64
    assert result.left.qb64 == nodage.left.qb64
    assert result.right.qb64 == nodage.right.qb64
    assert not siter.putNode(saider, nodage)  # idempotent so second try fails
    siter.pinNode(saider, nodage)

    # getNode fails is not in db
    badsaider = Diger(ser=b"Bad one", code=siter.code)
    assert not siter.getNode(badsaider)

    # remNode
    assert siter.remNode(saider)
    assert not siter.hasNode(saider)
    assert not siter.getNode(saider)
    assert not siter.isNode(saider)

    # pin node round trip
    spanner = Number(num=2)
    nodage = Nodage(span=spanner,
                    limb=limber,
                    left=Noncer(nonce=""),
                    right=Noncer(nonce=""))
    saider = siter.sayNode(nodage)
    assert saider.qb64 == 'ELljrgeKAYxXg0YW3jR3lGRZ7sBSZU6JCq6VgvBO4rmF'

    assert not siter.hasNode(saider)
    assert not siter.getNode(saider)
    siter.pinNode(saider, nodage)
    assert siter.hasNode(saider)
    assert siter.isNode(saider)
    result = siter.getNode(saider)
    assert isinstance(result, Nodage)
    assert result.span.qb64 == nodage.span.qb64
    assert result.limb.qb64 == nodage.limb.qb64
    assert result.left.qb64 == nodage.left.qb64
    assert result.right.qb64 == nodage.right.qb64


    # test .sayLeaf(self, leafage)
    spanner = Number(num=256)  # leaf
    infoer = Diger(ser=b"Leaf Info get it?", code=DigDex.Blake2b_256) # not default SIT code
    limber = Diger(ser=infoer.qb64b, code=Siter.Code)
    assert limber.qb64 == 'ECxPASxNTXD8J_qHJGxwvLqzjCNto7bJtIBivJNCJLS2'
    leafage = Leafage(span=spanner, limb=limber)
    saider = siter.sayLeaf(leafage)
    assert saider.qb64 == 'EMOv2iXtQ43LBLXVs6xXrlH5ldjGCAHF-tMc0UqWA4sB'

    # test leaf storage functions
    assert not siter.hasLeaf(saider)
    assert not siter.getLeaf(saider)
    assert siter.putLeaf(saider, leafage)  # put leaf
    assert siter.hasLeaf(saider)
    assert siter.isLeaf(saider)
    result = siter.getLeaf(saider)  # round trip
    assert isinstance(result, Leafage)
    assert result.span.qb64 == leafage.span.qb64
    assert result.limb.qb64 == leafage.limb.qb64
    assert not siter.putLeaf(saider, leafage)  # idempotent so second try fails
    siter.pinLeaf(saider, leafage)

    # getLeaf fails is not in db
    badsaider = Diger(ser=b"Bad one", code=siter.code)
    assert not siter.getLeaf(badsaider)

    # remLeaf
    assert siter.remLeaf(saider)
    assert not siter.hasLeaf(saider)
    assert not siter.getLeaf(saider)
    assert not siter.isLeaf(saider)

    # pin leaf round trip
    infoer = Diger(ser=b"Leaf Info got it", code=DigDex.Blake2b_256) # not default SIT code
    limber = Diger(ser=infoer.qb64b, code=Siter.Code)
    assert limber.qb64 == 'ECtlvjd2t7cqCsuJa8mmU8osQ6CkbuhRX-vcCPPvjN8y'
    leafage = Leafage(span=spanner, limb=limber)
    saider = siter.sayLeaf(leafage)
    assert saider.qb64 == 'ECHQjWDNTZw2V4pwnEOzNP_kxVW6LY2jr6t8huDu-mCY'

    assert not siter.hasLeaf(saider)
    assert not siter.getLeaf(saider)
    siter.pinLeaf(saider, leafage)
    assert siter.hasLeaf(saider)
    assert siter.isLeaf(saider)
    result = siter.getLeaf(saider)
    assert isinstance(result, Leafage)
    assert result.span.qb64 == leafage.span.qb64
    assert result.limb.qb64 == leafage.limb.qb64
    """Done Test"""


def setup_limbers_vectors(code=DigDex.Blake3_256):
    """Creates a dict of limbers used to test ._insert logic
    """
    limbers = {}

    limb = 0  # all 0s
    limber = Diger(num=limb, code=code)
    key = f"{(limb >> 248):08b}"  # 8 MSbs
    limbers[key] = limber

    for i in range(1, 16): # MSByte is 1 .. 15
        limb = i << 252
        limber = Diger(num=limb, code=code)
        key = f"{(limb >> 248):08b}"  # 8 MSbs
        limbers[key] = limber

    limb = 1 << 251  # 00001000
    limber = Diger(num=limb, code=code)
    key = f"{(limb >> 248):08b}"
    assert key == '00001000'  # 8 MSbs
    limbers[key] = limber

    limb = 2 ** 256 - 1  # all 1s
    limber = Diger(num=limb, code=code)
    key = f"{(limb >> 248):08b}"
    assert key == '11111111'  # 8 MSbs
    limbers[key] = limber

    return limbers


def test_setup_limber_vectors():
    code = DigDex.Blake3_256
    limbers = setup_limbers_vectors(code=code)

    show = [{key: val.numh} for key, val in limbers.items()]
    assert show == \
    [
        {'00000000': '0'},
        {'00010000': '1000000000000000000000000000000000000000000000000000000000000000'},
        {'00100000': '2000000000000000000000000000000000000000000000000000000000000000'},
        {'00110000': '3000000000000000000000000000000000000000000000000000000000000000'},
        {'01000000': '4000000000000000000000000000000000000000000000000000000000000000'},
        {'01010000': '5000000000000000000000000000000000000000000000000000000000000000'},
        {'01100000': '6000000000000000000000000000000000000000000000000000000000000000'},
        {'01110000': '7000000000000000000000000000000000000000000000000000000000000000'},
        {'10000000': '8000000000000000000000000000000000000000000000000000000000000000'},
        {'10010000': '9000000000000000000000000000000000000000000000000000000000000000'},
        {'10100000': 'a000000000000000000000000000000000000000000000000000000000000000'},
        {'10110000': 'b000000000000000000000000000000000000000000000000000000000000000'},
        {'11000000': 'c000000000000000000000000000000000000000000000000000000000000000'},
        {'11010000': 'd000000000000000000000000000000000000000000000000000000000000000'},
        {'11100000': 'e000000000000000000000000000000000000000000000000000000000000000'},
        {'11110000': 'f000000000000000000000000000000000000000000000000000000000000000'},
        {'00001000': '800000000000000000000000000000000000000000000000000000000000000'},
        {'11111111': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'}
    ]

    #limb = 1 << 252 # 1 followed by all zeros
    #limber = Diger(num=limb, code=code)
    #assert limber.num == limb
    #assert limber.numh == '1000000000000000000000000000000000000000000000000000000000000000'
    #key = f"{(limb >> 248):08b}"
    #assert key == '00010000'  # 8 MSbs
    #limbers[key] = limber


def test_insert_logic():
    """Test insert logic"""
    # create made up leaf limbs for testing
    code = DigDex.Blake3_256

    limbers = setup_limbers_vectors(code=code)

    # Basic Tests
    tuid = '0ACiicCYoKAqao8qDdnlFVrY'
    siter = Siter(tuid=tuid)  # create Siter with known tuid
    assert siter.tuider.qb64 == tuid
    assert siter.code == code == DigDex.Blake3_256
    assert siter.root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'ENtWb6xykmkwzn3hiDmfCOS_crgAI6oQ6jLmHR_HlrF0',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='1AAP',
                       right='1AAP')
    }
    assert len(siter.nodes) == 1

    trace, metrics = siter.trace()
    assert trace == \
    [
        'left#1=empty@root',
        'right#1=empty@root'
    ]
    assert metrics == \
    {
        'depthmax': 0,
        'depthmin': 0,
        'depthsum': 0,
        'depthave': 0.0,
        'leafcount': 0
    }

    # test ._siter
    # test insert leaves on empty node children


    # test left child
    # manually create leaf using  limber '01000000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['01000000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-'
    leaf = Partage(said=saider, part=leafage)  # matter primitives
    leaf0 = leaf  # save for latrer

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.left.qb64 == saider.qb64  # leaf said at left child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'EJWd2kyB2GwB7o0YYt6S_hYlzE6G_ju20ats0h3ho8xQ',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       right='1AAP')
    }
    trace, metrics = siter.trace()
    assert trace == ['left#1=01000000@root', 'right#1=empty@root']
    metrics == {'depthmax': 1, 'depthmin': 1, 'depthsum': 1}

    # test right child
    # manually create leaf using  limber '10000000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['10000000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.right.qb64 == saider.qb64  # leaf said at right child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'EBxJZyJZiHIEdh_LYAGXsiI4211HjgGtn5ktEafekbft',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')
    }
    trace, metrics = siter.trace()
    assert trace == \
    [
        'left#1=01000000@root',
        'right#1=10000000@root'
    ]
    metrics['depthave'] = metrics['depthsum'] / metrics['leafcount']
    assert metrics == \
    {
        'depthmax': 1,
        'depthmin': 1,
        'depthsum': 2,
        'depthave': 1.0,
        'leafcount': 2
    }


    # test fork left child  where MSb of leaf is 0
    # manually create leaf using  limber '01010000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['01010000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EKzxoQ2y54I_iwOJOlavCEnq52673S9oSKoBOkUAeWyD'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 2  # new forking node
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.left.qb64 != saider.qb64  # leaf said not at left child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'EN24QEyfLygm18upXb5y4yDX6FfRRjbCN1GwvfMCkEKe',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EArbnstk0UD1VExNPdcgyNMXI9OGKb340wUhqilbcfP6',
                       right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')
    }
    trace, metrics = siter.trace()
    assert trace == \
    [
        'left#2=01000000@010@root',
        'right#2=01010000@010@root',
        'right#1=10000000@root'
    ]
    metrics['depthave'] = metrics['depthsum'] / metrics['leafcount']
    assert metrics == \
    {
        'depthmax': 2,
        'depthmin': 1,
        'depthsum': 5,
        'depthave': 1.6666666666666667,
        'leafcount': 3
    }
    assert math.log2(metrics["leafcount"]) == 1.584962500721156

    # walk down
    assert siter.isNode(siter.root.part.left)
    nodage = siter.getNode(siter.root.part.left)
    assert siter.isLeaf(nodage.left)
    assert siter.isLeaf(nodage.right)

    # test fork right child  where MSb of leaf is 1
    # manually create leaf using  limber '10100000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['10100000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EKJiinLOmPefFZf41HHgHRBR7qaX5gzdyq6MKuFIbC3O'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 3  # new forking node
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.right.qb64 != saider.qb64  # leaf said not at right child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'ECNZXtp5rJ6AbUnpYgrCMtw6_I3fwcBQlcHorSOYK6dh',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EArbnstk0UD1VExNPdcgyNMXI9OGKb340wUhqilbcfP6',
                       right='EG-4J3gbg5ok_XNVHxEizVRL6SclilBLf4O971f4DeYn')}

    trace, metrics = siter.trace()
    assert trace == \
    [
        'left#2=01000000@010@root',
        'right#2=01010000@010@root',
        'left#2=10000000@10@root',
        'right#2=10100000@10@root'
    ]
    metrics['depthave'] = metrics['depthsum'] / metrics['leafcount']
    assert metrics == \
    {
        'depthmax': 2,
        'depthmin': 2,
        'depthsum': 8,
        'depthave': 2.0,
        'leafcount': 4
    }
    assert math.log2(metrics["leafcount"]) == 2.0

    # walk down
    assert siter.isNode(siter.root.part.right)
    nodage = siter.getNode(siter.root.part.right)
    assert siter.isLeaf(nodage.left)
    assert siter.isLeaf(nodage.right)

    rootsaid0 = siter.root.said.qb64  # keep around to compare later

    # test attempt to insert same leaf a second time
    with pytest.raises(ValueError):
        root = siter._insert(leaf, siter.root)

    with pytest.raises(ValueError):
        root = siter._insert(leaf0, siter.root)

    assert siter.root.said.qb64 == rootsaid0  # no change to siter

    siter0 = siter  # keep around to compare root later

    ##########################
    # Refresh siter start over with new sequence of leaf inserts
    siter = Siter(tuid=tuid)  # create Siter with known tuid
    # New siter  ._siter
    # test insert leaves on empty node children

    # test right child
    # manually create leaf using  limber '10000000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['10000000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.right.qb64 == saider.qb64  # leaf said at right child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'EM0NjOCHy__YVpM2axo0mqVj8_Enzferzedr7cBxH9T1',
        'part': Nodage(span='MAAA', limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='1AAP',
                       right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')
    }

    # test left child
    # manually create leaf using  limber '01000000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['01000000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.left.qb64 == saider.qb64  # leaf said at left child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'EBxJZyJZiHIEdh_LYAGXsiI4211HjgGtn5ktEafekbft',
        'part': Nodage(span='MAAA', limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')}

    # test fork right child  where MSb of leaf is 1
    # manually create leaf using  limber '10100000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['10100000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EKJiinLOmPefFZf41HHgHRBR7qaX5gzdyq6MKuFIbC3O'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 2  # new forking node
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.right.qb64 != saider.qb64  # leaf said not at right child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'EKS_3YmKF5Wgw1RzPAT12DiO1dJnC0ACuRbdsY3e0QXk',
        'part': Nodage(span='MAAA', limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       right='EG-4J3gbg5ok_XNVHxEizVRL6SclilBLf4O971f4DeYn')}

    # walk down
    assert siter.isNode(siter.root.part.right)
    nodage = siter.getNode(siter.root.part.right)
    assert siter.isLeaf(nodage.left)
    assert siter.isLeaf(nodage.right)


    # test fork left child  where MSb of leaf is 0
    # manually create leaf using  limber '01010000'
    leafage = Leafage(span=Number(num=256),
                            limb=limbers['01010000'])
    saider = siter.sayLeaf(leafage)  # compute leaf said
    assert saider.qb64 == 'EKzxoQ2y54I_iwOJOlavCEnq52673S9oSKoBOkUAeWyD'
    leaf = Partage(said=saider, part=leafage)  # matter primitives

    root = siter._insert(leaf, siter.root)
    siter.pinLeaf(leaf.said, leaf.part)
    assert root.said.qb64 != siter.root.said.qb64  # changed value
    assert len(siter.nodes) == 3  # new forking node
    assert not siter.hasNode(siter.root.said)  # old root node was removed
    assert siter.hasNode(root.said)  # new root node was inserted
    assert root.part.left.qb64 != saider.qb64  # leaf said not at left child

    siter.root = root # update root with new root
    nqb64 = Partage(said=siter.root.said.qb64,
                    part=Nodage(span=siter.root.part.span.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert nqb64._asdict() == \
    {
        'said': 'ECNZXtp5rJ6AbUnpYgrCMtw6_I3fwcBQlcHorSOYK6dh',
        'part': Nodage(span='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='EArbnstk0UD1VExNPdcgyNMXI9OGKb340wUhqilbcfP6',
                       right='EG-4J3gbg5ok_XNVHxEizVRL6SclilBLf4O971f4DeYn')
    }


    # walk down
    assert siter.isNode(siter.root.part.left)
    nodage = siter.getNode(siter.root.part.left)
    assert siter.isLeaf(nodage.left)
    assert siter.isLeaf(nodage.right)
    siter1 = siter

    # Test if trees are equal despite different order of adding leafs
    assert siter1.root.said.qb64 == siter0.root.said.qb64  # !!!! root saids match


    # already inserted '10000000', '01000000', '10100000', '01010000'
    # insert a bunch more in siter1
    leaf = siter1.leafFromLimber(limbers['11100000'])
    siter1.root = siter1._insert(leaf, siter1.root)
    siter1.pinLeaf(leaf.said, leaf.part)

    leaf = siter1.leafFromLimber(limbers['11110000'])
    siter1.root = siter1._insert(leaf, siter1.root)
    siter1.pinLeaf(leaf.said, leaf.part)

    leaf = siter1.leafFromLimber(limbers['01100000'])
    siter1.root = siter1._insert(leaf, siter1.root)
    siter1.pinLeaf(leaf.said, leaf.part)

    leaf = siter1.leafFromLimber(limbers['01110000'])
    siter1.root = siter1._insert(leaf, siter1.root)
    siter1.pinLeaf(leaf.said, leaf.part)

    assert len(siter1.nodes) == 7

    # insert same but in different order into siter0
    leaf = siter0.leafFromLimber(limbers['01100000'])
    siter0.root = siter0._insert(leaf, siter0.root)
    siter0.pinLeaf(leaf.said, leaf.part)

    leaf = siter0.leafFromLimber(limbers['11100000'])
    siter0.root = siter0._insert(leaf, siter0.root)
    siter0.pinLeaf(leaf.said, leaf.part)

    leaf = siter0.leafFromLimber(limbers['01110000'])
    siter0.root = siter0._insert(leaf, siter0.root)
    siter0.pinLeaf(leaf.said, leaf.part)

    leaf = siter0.leafFromLimber(limbers['11110000'])
    siter0.root = siter0._insert(leaf, siter0.root)
    siter0.pinLeaf(leaf.said, leaf.part)

    assert len(siter0.nodes) == 7

    # Test if trees are equal despite different order of adding leafs
    assert siter1.root.said.qb64 == siter0.root.said.qb64  # !!!! root saids match

    trace0, metrics0 = siter0.trace()
    assert trace0 == \
    [
        'left#3=01000000@010@01@root',
        'right#3=01010000@010@01@root',
        'left#3=01100000@011@01@root',
        'right#3=01110000@011@01@root',
        'left#3=10000000@10@1@root',
        'right#3=10100000@10@1@root',
        'left#3=11100000@111@1@root',
        'right#3=11110000@111@1@root'
    ]
    assert metrics0 == \
    {
        'depthmax': 3,
        'depthmin': 3,
        'depthsum': 24,
        'depthave': 3.0,
        'leafcount': 8
    }
    assert math.log2(metrics0["leafcount"]) == 3.0


    trace1, metrics1 = siter1.trace()
    metrics1['depthave'] = metrics1['depthsum'] / metrics1['leafcount']
    assert trace1 == trace0
    assert metrics1 == metrics0


    # Verity that order of insertion does not change root. I.e. structrure of
    # tree is stable for same set of leaves

    # Test special set known to fail for old rules when change order
    # test forward  order
    leaves = [limbers['01000000'],
              limbers['00100000'],
              limbers['00010000'],
              limbers['00001000']]

    siter = Siter(tuid=tuid)  # create Siter with known tuid
    for limber in leaves:
        leaf = siter.leafFromLimber(limber)
        siter.root = siter._insert(leaf, siter.root)
        siter.pinLeaf(leaf.said, leaf.part)

    assert len(siter.leaves) == len(leaves)
    assert len(siter.nodes) == len(leaves)

    siterT0 = siter
    traceT0, metricsT0 = siter.trace()
    assert traceT0 == \
    [
        'left#4=00001000@000@00@0@root',
        'right#4=00010000@000@00@0@root',
        'right#3=00100000@00@0@root',
        'right#2=01000000@0@root',
        'right#1=empty@root'
    ]
    assert metricsT0 == \
    {
        'depthmax': 4,
        'depthmin': 2,
        'depthsum': 13,
        'depthave': 3.25,
        'leafcount': 4
    }

    # test reverse  order
    leaves = [limbers['00001000'],
              limbers['00010000'],
              limbers['00100000'],
              limbers['01000000']]

    siter = Siter(tuid=tuid)  # create Siter with known tuid
    for limber in leaves:
        leaf = siter.leafFromLimber(limber)
        siter.root = siter._insert(leaf, siter.root)
        siter.pinLeaf(leaf.said, leaf.part)

    assert len(siter.leaves) == len(leaves)
    assert len(siter.nodes) == len(leaves)

    siterT1 = siter
    traceT1, metricsT1 = siter.trace()
    assert traceT1 == traceT0
    assert metricsT1 == metricsT0
    assert siterT1.root.said.qb64 == siterT0.root.said.qb64 # !yes equiv


    # do random sample insertions of all limbers to compare
    size = len(limbers)
    assert size == 18
    values = list(limbers.values())

    #sample = random.sample(range(0, size), k=size)
    sample = [10, 2, 8, 0, 9, 7, 1, 12, 16, 6, 5, 13, 17, 11, 4, 14, 3, 15]
    assert len(sample) == size

    siter = Siter(tuid=tuid)  # create Siter with known tuid
    for i in sample:
        leaf = siter.leafFromLimber(values[i])
        siter.root = siter._insert(leaf, siter.root)
        siter.pinLeaf(leaf.said, leaf.part)

    assert len(siter.leaves) == size
    assert len(siter.nodes) == size - 1

    siterA = siter

    #sample = random.sample(range(0, size), k=size)
    sample = [14, 11, 6, 4, 2, 9, 15, 12, 8, 13, 7, 3, 0, 16, 10, 5, 1, 17]
    assert len(sample) == size

    siter = Siter(tuid=tuid)  # create Siter with known tuid
    for i in sample:
        leaf = siter.leafFromLimber(values[i])
        siter.root = siter._insert(leaf, siter.root)
        siter.pinLeaf(leaf.said, leaf.part)

    assert len(siter.leaves) == size
    assert len(siter.nodes) == size - 1

    siterB = siter

    #sample = random.sample(range(0, size), k=size)
    sample =[16, 3, 7, 2, 4, 12, 8, 0, 14, 13, 10, 6, 15, 5, 9, 1, 17, 11]
    assert len(sample) == size

    siter = Siter(tuid=tuid)  # create Siter with known tuid
    for i in sample:
        leaf = siter.leafFromLimber(values[i])
        siter.root = siter._insert(leaf, siter.root)
        siter.pinLeaf(leaf.said, leaf.part)

    assert len(siter.leaves) == size
    assert len(siter.nodes) == size - 1

    siterC = siter

    # verify order independent
    assert siterB.root.said.qb64 == siterA.root.said.qb64
    assert siterC.root.said.qb64 == siterB.root.said.qb64
    assert siterC.root.said.qb64 == siterA.root.said.qb64


    traceA, metricsA = siterA.trace()
    assert traceA == \
    [
        'left#5=00000000@0000@000@00@0@root',
        'right#5=00001000@0000@000@00@0@root',
        'right#4=00010000@000@00@0@root',
        'left#4=00100000@001@00@0@root',
        'right#4=00110000@001@00@0@root',
        'left#4=01000000@010@01@0@root',
        'right#4=01010000@010@01@0@root',
        'left#4=01100000@011@01@0@root',
        'right#4=01110000@011@01@0@root',
        'left#4=10000000@100@10@1@root',
        'right#4=10010000@100@10@1@root',
        'left#4=10100000@101@10@1@root',
        'right#4=10110000@101@10@1@root',
        'left#4=11000000@110@11@1@root',
        'right#4=11010000@110@11@1@root',
        'left#4=11100000@111@11@1@root',
        'left#5=11110000@1111@111@11@1@root',
        'right#5=11111111@1111@111@11@1@root'
    ]
    assert metricsA == \
    {
        'depthmax': 5,
        'depthmin': 4,
        'depthsum': 76,
        'depthave': 4.222222222222222,
        'leafcount': 18
    }
    assert math.log2(metricsA['leafcount']) == 4.169925001442312

    # test dense key space (limbs are densly packed at lower elevations)
    assert code == DigDex.Blake3_256
    limbers = [Diger(num=limb, code=code) for limb in range(16)]

    limbs = [limber.numh for limber in limbers]
    assert limbs == \
    ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

    siter = Siter(tuid=tuid, code=code)  # create Siter with known tuid
    for limber in limbers:
        leaf = siter.leafFromLimber(limber)
        siter.root = siter._insert(leaf, siter.root)
        siter.pinLeaf(leaf.said, leaf.part)

    trace, metrics = siter.trace(terse=False)
    assert trace == \
    [
        'left#5=0@0@0@0@0@root',
        'right#5=1@0@0@0@0@root',
        'left#5=2@2@0@0@0@root',
        'right#5=3@2@0@0@0@root',
        'left#5=4@4@4@0@0@root',
        'right#5=5@4@4@0@0@root',
        'left#5=6@6@4@0@0@root',
        'right#5=7@6@4@0@0@root',
        'left#5=8@8@8@8@0@root',
        'right#5=9@8@8@8@0@root',
        'left#5=a@a@8@8@0@root',
        'right#5=b@a@8@8@0@root',
        'left#5=c@c@c@8@0@root',
        'right#5=d@c@c@8@0@root',
        'left#5=e@e@c@8@0@root',
        'right#5=f@e@c@8@0@root',
        'right#1=empty@root'
    ]  # notice SIT tree compression to low elevation subtree
    assert metrics == \
    {
        'depthmax': 5,
        'depthmin': 5,
        'depthsum': 80,
        'depthave': 5.0,
        'leafcount': 16
    }
    assert math.log2(metrics['leafcount']) == 4.0  # worst case depthave only 1 more than optimal

    """Done Test"""


def siter_insert():
    """Test .insert method of Siter"""
    code = DigDex.Blake3_256
    tuid = '0ACiicCYoKAqao8qDdnlFVrY'

    # make leafers
    count = 8
    leafers = {}
    for i in range(0, count):
        key = f"info_{i:04x}"
        val = Noncer(ser=key.encode(), code=code)
        leafers[key] = val

    leafersqb64 = {key: val.qb64 for key, val in leafers.items()}
    assert leafersqb64 == \
    {
        'info_0000': 'EPEyrH2H4BwnYnoBMa1f_BgOUGkjbgb4401f74WkXiq9',
        'info_0001': 'EBg0nWFi_-_5S_qmdHAMuHEN5S5lR3BWRmX9q27O8Sdj',
        'info_0002': 'EBnVf13snqclzWJ6TRZJ2IpBu_YlHBMD0v4urifXoCNF',
        'info_0003': 'ECwvvGbzhpdbKnM-PCYaDFi984QYP5jH_1nto6O8xSzR',
        'info_0004': 'EHFqFW8w0TUZTs53RdI5CH5nLMGDN_laoKTqJd444tK-',
        'info_0005': 'EPgOUHTHcRHuY4uaQ2UMr0SgWWe_i8Vw0LX4tGmNpbCm',
        'info_0006': 'ENlDE5eJ-HfSSdURrQ8P313-ymKScOeadQEc7T6GSqHj',
        'info_0007': 'EAkFX_ou2tauGDzxd7rRGehYiq3xRjL5TW7wVzDQ6TAe'
    }


    vals = list(leafers.values())

    siter = Siter(tuid=tuid, code=code)  # create Siter with known tuid
    for val in vals:  # leafers
        siter.insert(val)

    assert len(siter.leaves) == count
    assert len(siter.nodes) == count - 1
    assert siter.infos == \
    {
        'EMvv-63b4v1XWIV-fitjNZb-nFxB2uZvrTaPq6KDcqmI': 'EPEyrH2H4BwnYnoBMa1f_BgOUGkjbgb4401f74WkXiq9',
        'EHLw2bpH6U2JjDdC84LjO5vIiLL5glKUt6whyHFeFqWP': 'EBg0nWFi_-_5S_qmdHAMuHEN5S5lR3BWRmX9q27O8Sdj',
        'EAsnChbkFJFgbiHys3j16WVf9RnebUqqSFtk12LqO0UH': 'EBnVf13snqclzWJ6TRZJ2IpBu_YlHBMD0v4urifXoCNF',
        'EAb318FbH_kvubLWdYTvw8k_oQYXOggjWwbB9QGrT_Eg': 'ECwvvGbzhpdbKnM-PCYaDFi984QYP5jH_1nto6O8xSzR',
        'EFgOCYefLxUz-oTzPpGXJZfiFANExtgn-5tnrWxQWEDI': 'EHFqFW8w0TUZTs53RdI5CH5nLMGDN_laoKTqJd444tK-',
        'EA1YwV2fa3KyI5geqkiXYzQPsWoUMfSSNaTdOY7w4U9z': 'EPgOUHTHcRHuY4uaQ2UMr0SgWWe_i8Vw0LX4tGmNpbCm',
        'ECa221FTFyhjXW_q1xwkDyg3pU4Fw1r1x8oEbdJnEzu3': 'ENlDE5eJ-HfSSdURrQ8P313-ymKScOeadQEc7T6GSqHj',
        'EOmlLKztmVgPxMx7qopoLsbC_Ddi6ZgWNP9WBBOEC8hF': 'EAkFX_ou2tauGDzxd7rRGehYiq3xRjL5TW7wVzDQ6TAe'
    }

    assert list(siter.infos.values()) == list(leafersqb64.values())  # ordering is serendipitous

    trace, metrics = siter.trace(terse=False)
    assert trace == \
    [
        'left#4=6f7d7c15b1ff92fb9b2d67584efc3c93fa106173a08235b06c1f501ab4ff120@0@0@0@root',
        'left#5=b270a16e41491606e21f2b378f5e9655ff519de6d4aaa485b64d762ea3b4507@800000000000000000000000000000000000000000000000000000000000000@0@0@0@root',
        'right#5=d58c15d9f6b72b223981eaa489763340fb16a1431f49235a4dd398ef0e14f73@800000000000000000000000000000000000000000000000000000000000000@0@0@0@root',
        'right#3=26b6db51531728635d6fead71c240f2837a54e05c35af5c7ca046dd267133bb7@0@0@root',
        'left#3=580e09879f2f1533fa84f33e91972597e2140344c6d827fb9b67ad6c505840c8@4000000000000000000000000000000000000000000000000000000000000000@0@root',
        'right#3=72f0d9ba47e94d898c3742f382e33b9bc888b2f9825294b7ac21c8715e16a58f@4000000000000000000000000000000000000000000000000000000000000000@0@root',
        'left#2=cbeffbaddbe2fd5758857e7e2b633596fe9c5c41dae66fad368faba28372a988@c000000000000000000000000000000000000000000000000000000000000000@root',
        'right#2=e9a52caced99580fc4cc7baa8a682ec6c2fc3762e9981634ff560413840bc845@c000000000000000000000000000000000000000000000000000000000000000@root'
    ]

    assert metrics == \
    {
        'depthmax': 5,
        'depthmin': 2,
        'depthsum': 27,
        'depthave': 3.375,
        'leafcount': 8
    }
    assert math.log2(metrics['leafcount']) == 3.0


    # make leafers
    count = 1024
    leafers = {}
    for i in range(0, count):
        key = f"info_{i:04x}"
        val = Noncer(ser=key.encode(), code=code)
        leafers[key] = val


    sample = random.sample(range(0, count), k=count)
    assert len(sample) == count
    vals = list(leafers.values())

    roots = set()
    runs = 4
    for i in range(0, runs):
        siter = Siter(tuid=tuid, code=code)  # create Siter with known tuid
        for i in sample:
            siter.insert(vals[i])
        roots.add(siter.root.said.qb64)

    assert len(roots) == 1  # set only adds unique values


    # test metrics
    # make leafers
    count = 1024
    leafers = {}
    for i in range(0, count):
        key = f"info_{i:04x}"
        val = Noncer(ser=key.encode(), code=code)
        leafers[key] = val

    vals = list(leafers.values())

    siter = Siter(tuid=tuid, code=code)  # create Siter with known tuid
    for val in vals:
        siter.insert(val)

    leaves, metrics =siter.trace(terse=False, leafive=False)
    assert not leaves
    assert metrics == \
    {
        'depthmax': 13,
        'depthmin': 8,
        'depthsum': 10543,
        'depthave': 10.2958984375,
        'leafcount': 1024
    }
    assert math.log2(metrics["leafcount"]) == 10.0
    # good metrics well balanced tree
    # depthave ~= log2(leafcount)
    # depthmax only 3 greater than log2(leafcount)
    # depthmin only 2 less than log2(leafcount)
    """Done Test"""


def test_delete():
    """Test .delete and ._delete logic"""
    code = DigDex.Blake3_256

    # Basic Tests
    tuid = '0ACiicCYoKAqao8qDdnlFVrY'
    siter = Siter(tuid=tuid)  # create Siter with known tuid
    emptyroot = siter.root

    # try to delete empty from empty tree (root with empty children)
    leafer = Noncer(nonce="")  # empty leafer
    assert siter.delete(leafer) is None

    limbers = setup_limbers_vectors(code=code)
    # test ._delete logic
    leaf0 = siter.leafFromLimber(limbers['01000000'])
    leaf1 = siter.leafFromLimber(limbers['10000000'])

    # try to delete leaf not in tree
    assert siter._delete(leaf=leaf0, node=siter.root) == None
    assert siter._delete(leaf=leaf1, node=siter.root) == None

    # insert and delete left leaf on empty root
    siter.root = siter._insert(leaf0, siter.root)
    siter.pinLeaf(leaf0.said, leaf0.part)
    assert siter.hasNode(siter.root.said)
    rootleft = siter.root
    assert rootleft.said.qb64 != emptyroot.said.qb64

    siter.root = siter._delete(leaf=leaf0, node=siter.root)
    assert siter.hasNode(siter.root.said)
    siter.remLeaf(leaf0.said)
    assert siter.root.said.qb64 == emptyroot.said.qb64

    # insert and delete right leaf on empty root
    siter.root = siter._insert(leaf1, siter.root)
    siter.pinLeaf(leaf1.said, leaf1.part)
    rootright = siter.root
    assert rootright.said.qb64 != emptyroot.said.qb64 != rootleft.said.qb64

    siter.root = siter._delete(leaf=leaf1, node=siter.root)
    assert siter.hasNode(siter.root.said)
    siter.remLeaf(leaf1.said)
    assert siter.root.said.qb64 == emptyroot.said.qb64

    # siter back to empty
    assert len(siter.nodes) == 1
    assert siter.hasNode(siter.root.said)
    assert siter.root.said.qb64 == emptyroot.said.qb64

    # ok add enough leaves so have nodes
    leaf2 = siter.leafFromLimber(limbers['00100000'])
    leaf3 = siter.leafFromLimber(limbers['11000000'])
    leaf4 = siter.leafFromLimber(limbers['01100000'])
    leaf5 = siter.leafFromLimber(limbers['10100000'])

    siter.root = siter._insert(leaf0, node=siter.root)
    siter.pinLeaf(leaf0.said, leaf0.part)
    assert siter.hasNode(siter.root.said)

    siter.root = siter._insert(leaf1, node=siter.root)
    siter.pinLeaf(leaf1.said, leaf1.part)
    assert siter.hasNode(siter.root.said)

    siter.root = siter._insert(leaf2, node=siter.root)
    siter.pinLeaf(leaf2.said, leaf2.part)
    assert siter.hasNode(siter.root.said)

    siter.root = siter._insert(leaf3, node=siter.root)
    siter.pinLeaf(leaf3.said, leaf3.part)
    assert siter.hasNode(siter.root.said)
    rootA = siter.root

    siter.root = siter._insert(leaf4, node=siter.root)
    siter.pinLeaf(leaf4.said, leaf4.part)
    rootB = siter.root

    siter.root = siter._insert(leaf5, node=siter.root)
    siter.pinLeaf(leaf5.said, leaf5.part)
    rootC = siter.root

    leaves, metrics = siter.trace()
    assert leaves == \
    [
        'left#2=00100000@0@root',
        'left#3=01000000@01@0@root',
        'right#3=01100000@01@0@root',
        'left#3=10000000@10@1@root',
        'right#3=10100000@10@1@root',
        'right#2=11000000@1@root'
    ]

    root = siter._delete(leaf=leaf5, node=siter.root)
    siter.remLeaf(leaf5.said)
    siter.root = root
    assert siter.root.said.qb64 == rootB.said.qb64

    root = siter._delete(leaf=leaf4, node=siter.root)
    siter.remLeaf(leaf4.said)
    siter.root = root
    assert siter.root.said.qb64 == rootA.said.qb64

    # reinsert in different order to see if get same root as before
    siter.root = siter._insert(leaf5, node=siter.root)
    siter.pinLeaf(leaf5.said, leaf5.part)

    siter.root = siter._insert(leaf4, node=siter.root)
    siter.pinLeaf(leaf4.said, leaf4.part)
    assert siter.root.said.qb64 == rootC.said.qb64  # get same root as before


    # Test .delete
    # make leafers and insert so can delete
    count = 8
    leafers = {}
    for i in range(0, count):
        key = f"info_{i:04x}"
        val = Noncer(ser=key.encode(), code=code)
        leafers[key] = val

    vals = list(leafers.values())
    roots = deque()  # roots after every insert

    siter = Siter(tuid=tuid, code=code)  # create Siter with known tuid
    roots.appendleft(siter.root)
    for val in vals:  # leafers
        siter.insert(val)
        roots.appendleft(siter.root)

    assert len(siter.leaves) == count
    assert len(siter.infos) == count
    assert len(siter.nodes) == count - 1

    leaves = []
    roots.popleft()
    vals.reverse()  # delete in opposite order of insert
    for val in vals:
        leaves.append(siter.delete(val))
        assert roots.popleft().said.qb64 == siter.root.said.qb64

    assert len(siter.leaves) == 0
    assert len(siter.infos) == 0
    assert len(siter.nodes) == 1

    for leaf, val in zip(leaves, vals):
        assert leaf.said.qb64 == siter.leafFromLeafer(val).said.qb64

    """Done Test"""



if __name__ == "__main__":
    test_siting_siter_class()
    test_siter_basic()
    test_setup_limber_vectors()
    test_insert_logic()
    siter_insert()
    test_delete()
