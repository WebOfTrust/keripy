# -*- encoding: utf-8 -*-
"""
tests.sit.test_siting module

"""
import random
import pytest
from keri import Versionage
from keri.core import NumDex, Number, DigDex, Diger, Noncer, Verser, Ilker
from keri.sit.sitingOld import (Version, MaxDepth, MaxDepthBytes, Kithage, Kiths,
                      NodeSaidage, Nodage, LeafSaidage, Leafage, Partage,
                      Siter, Emptier, EmptyQb2, EmptyQb64)


def test_siting_siter_class():
    """Test of siting module and siter class methods"""

    assert Version == Versionage(0, 0)
    assert MaxDepth == 256
    assert MaxDepthBytes == 32
    assert MaxDepth == 2 ** 3 * MaxDepthBytes

    assert isinstance(Kiths, Kithage)
    assert Kiths._asdict() == {'node': 'nod', 'leaf': 'lea'}

    assert EmptyQb64 == '1AAP'
    assert EmptyQb2 == b'\xd4\x00\x0f'

    assert Siter.Code == DigDex.Blake3_256
    assert Siter.Dummy == '#'
    assert Diger._rawSize(Siter.Code) == MaxDepthBytes


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
                          depth=nepther,
                          limb=nimber,
                          left=Emptier,
                          right=Emptier)

    assert saidage._asdict() == \
    {
        'kith': nither,
        'tuid': tuider,
        'said': Emptier,
        'depth': nepther,
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
        'depth': 'MAAA',
        'limb': 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'left': '1AAP',
        'right': '1AAP'
    }

    # create nodage with qb2 values
    nodage = Nodage(depth=saidage.depth.qb2,
                    limb=saidage.limb.qb2,
                    left=saidage.left.qb2,
                    right=saidage.right.qb2)


    assert nodage._asdict() == \
    {
        'depth': b'0\x00\x00',
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
        'part': Nodage(depth=b'0\x00\x00',
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
                          depth=lepther,
                          limb=limber)

    assert saidage._asdict() == \
    {
        'kith': lither,
        'tuid': tuider,
        'said': Emptier,
        'depth': lepther,
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
        'depth': 'MAEA',
        'limb': 'EKE_SPb9j35_FOnE649CPQfWNRYAq4JaklV-08uPpGP5'
    }


    # create leafage with qb2 values
    leafage = Leafage(depth=saidage.depth.qb2,
                      limb=saidage.limb.qb2)

    assert leafage._asdict() == \
    {
        'depth': b'0\x01\x00',
        'limb': b'\x10\xa1?H\xf6\xfd\x8f~\x7f\x14\xe9\xc4\xeb\x8fB=\x07\xd65\x16'
                b'\x00\xab\x82Z\x92U~\xd3\xcb\x8f\xa4c\xf9',
    }

    # create leaf Partage of leafage with qb2 values
    part = Partage(said=saidage.said.qb2, part=leafage)
    assert part._asdict() == \
    {
        'said': b'\x10\xa2\x83\x1e\xf7\x9f\xc4\xb4\x0e\xfc\xe1\xa1\x8c01\x7fm\x9f%P'
                b'\xec\xbd3\x98f\xac\xe8\xe6`a\xb2F\xd1',
         'part': Leafage(depth=b'0\x01\x00',
                         limb=b'\x10\xa1?H\xf6\xfd\x8f~\x7f\x14\xe9\xc4\xeb\x8fB=\x07\xd65\x16\x00\xab\x82Z\x92U~\xd3\xcb\x8f\xa4c\xf9')
    }


    # test staticmethods
    # .extendLimb() and .extendLimbInt()
    # .rightAtSpan() and .rightAtSpanInt()
    limber = Diger(num=0, code=Siter.Code)  # use default code
    spanner = Number(num=0)
    with pytest.raises(ValueError):
        Siter.rightAtSpan(limber, spanner)  # depth of zero

    limb = limber.num  # get int
    span = spanner.num
    assert limb == 0
    span = 0
    with pytest.raises(ValueError):
        Siter.rightAtSpanInt(limb, span)  # span/depth of zero

    limb, span = Siter.extendLimbInt(limb=limb, span=span)  # default side left
    assert limb == 0
    assert f"{limb:0256b}"[:8] == '00000000'
    assert span == 1
    assert not Siter.rightAtSpanInt(limb, span)  # left at depth=span=1

    limb, span = Siter.extendLimbInt(limb=limb, span=span, side=True)  # side right
    assert limb == 2 ** (MaxDepth - span)
    assert f"{limb:0256b}"[:8] == '01000000'
    assert span == 2
    assert Siter.rightAtSpanInt(limb, span)  # right at depth=span=2

    limb, span = Siter.extendLimbInt(limb=limb, span=span, side=True)  # side right
    assert f"{limb:0256b}"[:8] == '01100000'
    assert span == 3
    assert Siter.rightAtSpanInt(limb, span)  # right at depth=span=3

    #test staticmethod .extendLimb(limber, spanner, right=False)
    limber = Diger(qb64=nimber.qb64)
    assert limber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    spanner = Number(num=0)
    assert spanner.qb64 == 'MAAA'

    limber, spanner = Siter.extendLimb(limber=limber, spanner=spanner)  # default side left
    assert not Siter.rightAtSpan(limber, spanner)  # left at depth=span=1
    assert limber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    assert spanner.qb64 == 'MAAB'
    limb = int.from_bytes(limber.raw)
    assert f"{limb:0256b}"[:8] == '00000000'
    assert spanner.num == 1
    assert not Siter.rightAtSpanInt(limb, spanner.num)  # left at depth=span=1

    limber, spanner = Siter.extendLimb(limber=limber, spanner=spanner, side=True)  # side right
    assert Siter.rightAtSpan(limber, spanner)  # right at depth=span=2
    assert limber.qb64 == 'EEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    assert spanner.qb64 == 'MAAC'
    limb = int.from_bytes(limber.raw)
    assert f"{limb:0256b}"[:8] == '01000000'
    assert spanner.num == 2
    assert Siter.rightAtSpanInt(limb, spanner.num)  # right at depth=span=2

    limber, spanner = Siter.extendLimb(limber=limber, spanner=spanner, side=True)  # side right
    assert Siter.rightAtSpan(limber, spanner)  # right at depth=span=2
    assert limber.qb64 == 'EGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    limb = int.from_bytes(limber.raw)
    assert f"{limb:0256b}"[:8] == '01100000'
    assert spanner.qb64 == 'MAAD'
    assert spanner.num == 3
    assert Siter.rightAtSpanInt(limb, spanner.num)  # right at depth=span=2


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
                    part=Nodage(depth=siter.root.part.depth.qb64,
                                limb=siter.root.part.limb.qb64,
                                  left=siter.root.part.left.qb64,
                                  right=siter.root.part.right.qb64))
    assert rqb64._asdict() == \
    {
        'said': 'ENtWb6xykmkwzn3hiDmfCOS_crgAI6oQ6jLmHR_HlrF0',
        'part': Nodage(depth='MAAA',
                       limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       left='1AAP',
                       right='1AAP')
    }
    assert len(siter.nodes) == 1
    nodage = siter.getNode(siter.root.said)
    nqb64 = Nodage(depth=nodage.depth.qb64,
                   limb=nodage.limb.qb64,
                   left=nodage.left.qb64,
                   right=nodage.right.qb64)
    assert nqb64 == rqb64.part  # round trips

    assert siter.leaves == {}
    assert siter.infos == {}

    # test .sayNode(self, nodage)   (compute said)
    depther = Number(num=1)
    limb = 2 ** 254
    limber = Diger(num=limb, code=Siter.Code)  # limb all 0s
    assert limber.qb64 == 'EEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    nodage = Nodage(depth=depther,
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
    assert result.depth.qb64 == nodage.depth.qb64
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
    depther = Number(num=2)
    nodage = Nodage(depth=depther,
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
    assert result.depth.qb64 == nodage.depth.qb64
    assert result.limb.qb64 == nodage.limb.qb64
    assert result.left.qb64 == nodage.left.qb64
    assert result.right.qb64 == nodage.right.qb64


    # test .sayLeaf(self, leafage)
    depther = Number(num=256)  # leaf
    infoer = Diger(ser=b"Leaf Info get it?", code=DigDex.Blake2b_256) # not default SIT code
    limber = Diger(ser=infoer.qb64b, code=Siter.Code)
    assert limber.qb64 == 'ECxPASxNTXD8J_qHJGxwvLqzjCNto7bJtIBivJNCJLS2'
    leafage = Leafage(depth=depther, limb=limber)
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
    assert result.depth.qb64 == leafage.depth.qb64
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
    leafage = Leafage(depth=depther, limb=limber)
    saider = siter.sayLeaf(leafage)
    assert saider.qb64 == 'ECHQjWDNTZw2V4pwnEOzNP_kxVW6LY2jr6t8huDu-mCY'

    assert not siter.hasLeaf(saider)
    assert not siter.getLeaf(saider)
    siter.pinLeaf(saider, leafage)
    assert siter.hasLeaf(saider)
    assert siter.isLeaf(saider)
    result = siter.getLeaf(saider)
    assert isinstance(result, Leafage)
    assert result.depth.qb64 == leafage.depth.qb64
    assert result.limb.qb64 == leafage.limb.qb64
    """Done Test"""


def setup_insert_limbers(code=DigDex.Blake3_256):
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

    limb = 2 ** 256 - 1  # all 1s
    limber = Diger(num=limb, code=code)
    key = f"{(limb >> 248):08b}"
    assert key == '11111111'  # 8 MSbs
    limbers[key] = limber

    return limbers


def test_insert_limbers():
    code = DigDex.Blake3_256
    limbers = setup_insert_limbers(code=code)

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
        {'11111111': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'}
    ]

    #limb = 0  # all 0s
    #limber = Diger(num=limb, code=code)
    #assert limber.num == limb
    #assert limber.numh == '0'
    #key = f"{(limb >> 248):08b}"
    #assert key == '00000000'  # 8 MSbs
    #limbers[key] = limber

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

    limbers = setup_insert_limbers(code=code)

    ## Basic Tests
    #tuid = '0ACiicCYoKAqao8qDdnlFVrY'
    #siter = Siter(tuid=tuid)  # create Siter with known tuid
    #assert siter.tuider.qb64 == tuid
    #assert siter.code == code == DigDex.Blake3_256
    #assert siter.root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'ENtWb6xykmkwzn3hiDmfCOS_crgAI6oQ6jLmHR_HlrF0',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='1AAP',
                       #right='1AAP')
    #}
    #assert len(siter.nodes) == 1

    #trace = siter.trace()
    #assert trace == ['left: empty @ root', 'right: empty @ root']

    ## test ._siter
    ## test insert leaves on empty node children


    ## test left child
    ## manually create leaf using  limber '01000000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['01000000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives
    #leaf0 = leaf  # save for latrer

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.left.qb64 == saider.qb64  # leaf said at left child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'EJWd2kyB2GwB7o0YYt6S_hYlzE6G_ju20ats0h3ho8xQ',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       #right='1AAP')
    #}
    #trace = siter.trace()
    #assert trace == ['left: 01000000 @ root', 'right: empty @ root']

    ## test right child
    ## manually create leaf using  limber '10000000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['10000000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.right.qb64 == saider.qb64  # leaf said at right child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'EBxJZyJZiHIEdh_LYAGXsiI4211HjgGtn5ktEafekbft',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       #right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')
    #}
    #trace = siter.trace()
    #assert trace == ['left: 01000000 @ root', 'right: 10000000 @ root']

    ## test fork left child  where MSb of leaf is 0
    ## manually create leaf using  limber '01010000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['01010000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EKzxoQ2y54I_iwOJOlavCEnq52673S9oSKoBOkUAeWyD'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 2  # new forking node
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.left.qb64 != saider.qb64  # leaf said not at left child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'ECSw2uvc9WNVRChsOWbfAfuqWLqUNchqSHaK-aZ9y7VS',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EKaoMFUP92J_l0NtUTpUGYnaaZ1zBI5wuKllGmMnxjQH',
                       #right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')
    #}
    #trace = siter.trace()
    #assert trace == ['left: 01000000 @ 0', 'right: 01010000 @ 0', 'right: 10000000 @ root']

    ## walk down
    #assert siter.isNode(siter.root.part.left)
    #nodage = siter.getNode(siter.root.part.left)
    #assert siter.isLeaf(nodage.left)
    #assert siter.isLeaf(nodage.right)

    ## test fork right child  where MSb of leaf is 1
    ## manually create leaf using  limber '10100000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['10100000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EKJiinLOmPefFZf41HHgHRBR7qaX5gzdyq6MKuFIbC3O'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 3  # new forking node
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.right.qb64 != saider.qb64  # leaf said not at right child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'ENImcliK7x2rEj3K7yQTjlu8dRpqQaLoxRNdo-J-LqrV',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EKaoMFUP92J_l0NtUTpUGYnaaZ1zBI5wuKllGmMnxjQH',
                       #right='EP2xCuT1JxunHvjB0skYAta2RbZr5G9RVyoa6eS7eiqt')
    #}
    #trace = siter.trace()
    #assert trace == \
    #[
        #'left: 01000000 @ 0',
        #'right: 01010000 @ 0',
        #'left: 10000000 @ 1',
        #'right: 10100000 @ 1'
    #]

    ## walk down
    #assert siter.isNode(siter.root.part.right)
    #nodage = siter.getNode(siter.root.part.right)
    #assert siter.isLeaf(nodage.left)
    #assert siter.isLeaf(nodage.right)

    #rootsaid0 = siter.root.said.qb64  # keep around to compare later

    ## test attempt to insert same leaf a second time
    #with pytest.raises(ValueError):
        #root = siter._insert(leaf, siter.root)

    #with pytest.raises(ValueError):
        #root = siter._insert(leaf0, siter.root)

    #assert siter.root.said.qb64 == rootsaid0  # no change to siter

    #siter0 = siter  # keep around to compare root later

    ###########################
    ## Refresh siter start over with new sequence of leaf inserts
    #siter = Siter(tuid=tuid)  # create Siter with known tuid
    ## New siter  ._siter
    ## test insert leaves on empty node children

    ## test right child
    ## manually create leaf using  limber '10000000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['10000000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.right.qb64 == saider.qb64  # leaf said at right child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'EM0NjOCHy__YVpM2axo0mqVj8_Enzferzedr7cBxH9T1',
        #'part': Nodage(depth='MAAA', limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='1AAP',
                       #right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')
    #}

    ## test left child
    ## manually create leaf using  limber '01000000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['01000000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 1  # no new nodes just filled in leaf
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.left.qb64 == saider.qb64  # leaf said at left child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'EBxJZyJZiHIEdh_LYAGXsiI4211HjgGtn5ktEafekbft',
        #'part': Nodage(depth='MAAA', limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       #right='EDLbCF6fGry4Bsi8bIX8ZsQ0UNTPP4zQxmQciUfEjROE')}

    ## test fork right child  where MSb of leaf is 1
    ## manually create leaf using  limber '10100000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['10100000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EKJiinLOmPefFZf41HHgHRBR7qaX5gzdyq6MKuFIbC3O'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 2  # new forking node
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.right.qb64 != saider.qb64  # leaf said not at right child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'EFLPHG5ITOiBuldDjsoHbPpWdKo_PyQTuhQ5MgT3FlqE',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EJznHYoQUmXOV9q1BhUc7TzgsiAlxX-8Kow3_I_8PCC-',
                       #right='EP2xCuT1JxunHvjB0skYAta2RbZr5G9RVyoa6eS7eiqt')
    #}

    ## walk down
    #assert siter.isNode(siter.root.part.right)
    #nodage = siter.getNode(siter.root.part.right)
    #assert siter.isLeaf(nodage.left)
    #assert siter.isLeaf(nodage.right)


    ## test fork left child  where MSb of leaf is 0
    ## manually create leaf using  limber '01010000'
    #leafage = Leafage(depth=Number(num=256),
                            #limb=limbers['01010000'])
    #saider = siter.sayLeaf(leafage)  # compute leaf said
    #assert saider.qb64 == 'EKzxoQ2y54I_iwOJOlavCEnq52673S9oSKoBOkUAeWyD'
    #leaf = Partage(said=saider, part=leafage)  # matter primitives

    #root = siter._insert(leaf, siter.root)
    #siter.pinLeaf(leaf.said, leaf.part)
    #assert root.said.qb64 != siter.root.said.qb64  # changed value
    #assert len(siter.nodes) == 3  # new forking node
    #assert not siter.hasNode(siter.root.said)  # old root node was removed
    #assert siter.hasNode(root.said)  # new root node was inserted
    #assert root.part.left.qb64 != saider.qb64  # leaf said not at left child

    #siter.root = root # update root with new root
    #nqb64 = Partage(said=siter.root.said.qb64,
                    #part=Nodage(depth=siter.root.part.depth.qb64,
                                #limb=siter.root.part.limb.qb64,
                                  #left=siter.root.part.left.qb64,
                                  #right=siter.root.part.right.qb64))
    #assert nqb64._asdict() == \
    #{
        #'said': 'ENImcliK7x2rEj3K7yQTjlu8dRpqQaLoxRNdo-J-LqrV',
        #'part': Nodage(depth='MAAA',
                       #limb='EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                       #left='EKaoMFUP92J_l0NtUTpUGYnaaZ1zBI5wuKllGmMnxjQH',
                       #right='EP2xCuT1JxunHvjB0skYAta2RbZr5G9RVyoa6eS7eiqt')
    #}

    ## walk down
    #assert siter.isNode(siter.root.part.left)
    #nodage = siter.getNode(siter.root.part.left)
    #assert siter.isLeaf(nodage.left)
    #assert siter.isLeaf(nodage.right)
    #siter1 = siter

    ## Test if trees are equal despite different order of adding leafs
    #assert siter1.root.said.qb64 == siter0.root.said.qb64  # !!!! root saids match


    ## already inserted '10000000', '01000000', '10100000', '01010000'
    ## insert a bunch more in siter1
    #leaf = siter1.leafFromLimber(limbers['11100000'])
    #siter1.root = siter1._insert(leaf, siter1.root)
    #siter1.pinLeaf(leaf.said, leaf.part)

    #leaf = siter1.leafFromLimber(limbers['11110000'])
    #siter1.root = siter1._insert(leaf, siter1.root)
    #siter1.pinLeaf(leaf.said, leaf.part)

    #leaf = siter1.leafFromLimber(limbers['01100000'])
    #siter1.root = siter1._insert(leaf, siter1.root)
    #siter1.pinLeaf(leaf.said, leaf.part)

    #leaf = siter1.leafFromLimber(limbers['01110000'])
    #siter1.root = siter1._insert(leaf, siter1.root)
    #siter1.pinLeaf(leaf.said, leaf.part)

    #assert len(siter1.nodes) == 7

    ## insert same but in different order into siter0
    #leaf = siter0.leafFromLimber(limbers['01100000'])
    #siter0.root = siter0._insert(leaf, siter0.root)
    #siter0.pinLeaf(leaf.said, leaf.part)

    #leaf = siter0.leafFromLimber(limbers['11100000'])
    #siter0.root = siter0._insert(leaf, siter0.root)
    #siter0.pinLeaf(leaf.said, leaf.part)

    #leaf = siter0.leafFromLimber(limbers['01110000'])
    #siter0.root = siter0._insert(leaf, siter0.root)
    #siter0.pinLeaf(leaf.said, leaf.part)

    #leaf = siter0.leafFromLimber(limbers['11110000'])
    #siter0.root = siter0._insert(leaf, siter0.root)
    #siter0.pinLeaf(leaf.said, leaf.part)

    #assert len(siter0.nodes) == 7

    ## Test if trees are equal despite different order of adding leafs
    #assert siter1.root.said.qb64 == siter0.root.said.qb64  # !!!! root saids match

    #trace0 = siter0.trace()
    #assert trace0 == \
    #[
        #'left: 01000000 @ 0',
        #'left: 01010000 @ 01',
        #'left: 01100000 @ 011',
        #'right: 01110000 @ 011',
        #'left: 10000000 @ 1',
        #'left: 10100000 @ 11',
        #'left: 11100000 @ 111',
        #'right: 11110000 @ 111'
    #]

    #trace1 = siter1.trace()
    #assert trace1 == trace0


    ## Is Siter SIT is a set? Suth that order of insert does not matter.
    ## always makes same tree structure for same set of leaves?
    ## and therefore same root said (hash)?

    ## do random sample insertions of all limbers to compare
    #size = len(limbers)
    #assert size == 17
    #values = list(limbers.values())

    ##sample = random.sample(range(0, size), k=size)
    #sample = [3, 0, 14, 7, 6, 2, 5, 8, 4, 1, 13, 16, 10, 9, 12, 15, 11]
    #assert len(sample) == size

    #siter = Siter(tuid=tuid)  # create Siter with known tuid
    #for i in sample:
        #leaf = siter.leafFromLimber(values[i])
        #siter.root = siter._insert(leaf, siter.root)
        #siter.pinLeaf(leaf.said, leaf.part)

    #assert len(siter.leaves) == 17
    #assert len(siter.nodes) == 16


    #siterA = siter

    ##sample = random.sample(range(0, size), k=size)
    #sample = [9, 2, 1, 8, 13, 3, 16, 10, 12, 15, 7, 4, 6, 0, 5, 11, 14]
    #assert len(sample) == size

    #siter = Siter(tuid=tuid)  # create Siter with known tuid
    #for i in sample:
        #leaf = siter.leafFromLimber(values[i])
        #siter.root = siter._insert(leaf, siter.root)
        #siter.pinLeaf(leaf.said, leaf.part)

    #assert len(siter.leaves) == 17
    #assert len(siter.nodes) == 16

    #siterB = siter



    ##sample = random.sample(range(0, size), k=size)
    #sample = [14, 6, 5, 8, 9, 0, 16, 4, 11, 12, 2, 3, 13, 7, 10, 15, 1]
    #assert len(sample) == size

    #siter = Siter(tuid=tuid)  # create Siter with known tuid
    #for i in sample:
        #leaf = siter.leafFromLimber(values[i])
        #siter.root = siter._insert(leaf, siter.root)
        #siter.pinLeaf(leaf.said, leaf.part)

    #assert len(siter.leaves) == 17
    #assert len(siter.nodes) == 16

    #siterC = siter

    #assert siterB.root.said.qb64 != siterA.root.said.qb64
    #assert siterC.root.said.qb64 != siterB.root.said.qb64
    #assert siterC.root.said.qb64 != siterA.root.said.qb64

    ## so current logic is not a set. Was just serindipoudous with few leaves
    ## so need to analyze to see if it can be fixed or its not possible

    #traceA = siterA.trace()
    #assert traceA == \
    #[
        #'left: 00000000 @ 000',
        #'right: 00010000 @ 000',
        #'right: 00100000 @ 00',
        #'left: 00110000 @ 010',
        #'left: 01000000 @ 0101',
        #'right: 01010000 @ 0101',
        #'left: 01100000 @ 011',
        #'right: 01110000 @ 011',
        #'left: 10000000 @ 100',
        #'right: 10010000 @ 100',
        #'left: 10100000 @ 101',
        #'right: 10110000 @ 101',
        #'left: 11000000 @ 110',
        #'right: 11010000 @ 110',
        #'left: 11100000 @ 111',
        #'left: 11110000 @ 1111',
        #'right: 11111111 @ 1111'
    #]  # note lexicographic order
    #traceB = siterB.trace()
    #assert traceB == \
    #[
        #'left: 00000000 @ 00',
        #'right: 00010000 @ 00',
        #'left: 00100000 @ 010',
        #'left: 01000000 @ 0101',
        #'right: 01010000 @ 0101',
        #'left: 00110000 @ 011',
        #'left: 01100000 @ 0111',
        #'right: 01110000 @ 0111',
        #'left: 10000000 @ 10',
        #'left: 10100000 @ 101',
        #'right: 10110000 @ 101',
        #'left: 10010000 @ 110',
        #'right: 11000000 @ 110',
        #'left: 11010000 @ 1110',
        #'right: 11100000 @ 1110',
        #'left: 11110000 @ 1111',
        #'right: 11111111 @ 1111'
    #]  # not lexocographic looks like error in logic
    #traceC = siterC.trace()
    #assert traceC == \
    #[
        #'left: 00100000 @ 000',
        #'left: 00010000 @ 0001',
        #'right: 00110000 @ 0001',
        #'right: 01010000 @ 00',
        #'left: 00000000 @ 01',
        #'left: 01000000 @ 011',
        #'left: 01100000 @ 0111',
        #'right: 01110000 @ 0111',
        #'left: 10000000 @ 10',
        #'left: 10010000 @ 101',
        #'left: 10100000 @ 1011',
        #'right: 10110000 @ 1011',
        #'left: 11010000 @ 110',
        #'right: 11100000 @ 110',
        #'left: 11000000 @ 111',
        #'left: 11110000 @ 1111',
        #'right: 11111111 @ 1111'
    #]  # not lexocograpic  show error in logic



    # create leaf limbs as valid saids of leaf info
    #sn = 0
    #info = f"Leaf Info {sn:x}"
    #leafer = Diger(ser=info.encode(), code=DigDex.Blake2b_256) # not default SIT code
    #assert leafer.qb64 == 'FBQuXQPYcNMz3S1I6Ye6ByGd_R1VJkLcllZ92Au5JUK4'

    #result = siter.insert(leafer=leafer)
    #assert result is None

    """Done Test"""

if __name__ == "__main__":
    pass
