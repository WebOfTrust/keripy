# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""
import os

import pytest

import pysodium

from keri.core import coring, eventing
from keri.db import dbing, subing
from keri.app import keeping
from keri.help import helping


def test_suber():
    """
    Test Suber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.Suber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.Suber)
        assert not sdb.sdb.flags()["dupsort"]

        sue = "Hello sailer!"

        keys = ("test_key", "0001")
        sdb.put(keys=keys, val=sue)
        actual = sdb.get(keys=keys)
        assert actual == sue

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=sue)
        actual = sdb.get(keys=keys)
        assert actual == sue

        kip = "Hey gorgeous!"
        result = sdb.put(keys=keys, val=kip)
        assert not result
        actual = sdb.get(keys=keys)
        assert actual == sue

        result = sdb.pin(keys=keys, val=kip)
        assert result
        actual = sdb.get(keys=keys)
        assert actual == kip

        # test with keys as string not tuple
        keys = "keystr"

        bob = "Shove off!"

        sdb.put(keys=keys, val=bob)
        actual = sdb.get(keys=keys)
        assert actual == bob

        sdb.rem(keys)

        actual = sdb.get(keys=keys)
        assert actual is None


        liz =  "May life is insane."
        keys = ("test_key", "0002")

        sdb.put(keys=keys, val=liz)
        actual = sdb.get(("not_found", "0002"))
        assert actual is None

        w = "Blue dog"
        x = "Green tree"
        y = "Red apple"
        z = "White snow"

        sdb = subing.Suber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.Suber)

        sdb.put(keys=("a","1"), val=w)
        sdb.put(keys=("a","2"), val=x)
        sdb.put(keys=("a","3"), val=y)
        sdb.put(keys=("a","4"), val=z)

        items = [(keys, val) for keys, val in sdb.getAllItemIter()]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

        sdb.put(keys=("b","1"), val=w)
        sdb.put(keys=("b","2"), val=x)
        sdb.put(keys=("bc","3"), val=y)
        sdb.put(keys=("ac","4"), val=z)

        topkeys = ("b","")  # last element empty to force trailing separator
        items = [(keys, val) for keys, val in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('b', '1'), w),
                         (('b', '2'), x)]

        topkeys = ("a","")  # last element empty to force trailing separator
        items = [(keys, val) for keys, val in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

    assert not os.path.exists(db.path)
    assert not db.opened


def test_dup_suber():
    """
    Test DubSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.DupSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.DupSuber)
        assert sdb.sdb.flags()["dupsort"]

        sue = "Hello sailer!"
        sal = "Not my type."

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")
        sdb.put(keys=keys0, vals=[sue, sal])
        actual = sdb.get(keys=keys0)
        assert actual == [sue, sal]  # lexicographic order
        assert sdb.cnt(keys0) == 2

        sdb.rem(keys0)
        actual = sdb.get(keys=keys0)
        assert not actual
        assert actual == []
        assert sdb.cnt(keys0) == 0

        sdb.put(keys=keys0, vals=[sal, sue])
        actual = sdb.get(keys=keys0)
        assert actual == [sue, sal]  # lexicographic order
        actual = sdb.getLast(keys=keys0)
        assert actual == sal

        sam = "A real charmer!"
        result = sdb.add(keys=keys0, val=sam)
        assert result
        actual = sdb.get(keys=keys0)
        assert actual == [sam, sue, sal]   # lexicographic order

        zoe = "See ya later."
        zia = "Hey gorgeous!"

        result = sdb.pin(keys=keys0, vals=[zoe, zia])
        assert result
        actual = sdb.get(keys=keys0)
        assert actual == [zia, zoe]  # lexi order

        sdb.put(keys=keys1, vals=[sal, sue, sam])
        actual = sdb.get(keys=keys1)
        assert actual == [sam, sue, sal]  # lexicographic order

        for i, val in enumerate(sdb.getIter(keys=keys1)):
            assert val == actual[i]

        items = [(keys, val) for keys, val in sdb.getAllItemIter()]
        assert items == [(('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0002'), 'A real charmer!'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'Not my type.')]


        assert sdb.put(keys=("test", "blue"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('test', 'blue'), 'A real charmer!'),
                         (('test', 'blue'), 'Hello sailer!'),
                         (('test', 'blue'), 'Not my type.')]

        # test with keys as string not tuple
        keys2 = "keystr"
        bob = "Shove off!"
        sdb.put(keys=keys2, vals=[bob])
        actual = sdb.get(keys=keys2)
        assert actual == [bob]
        assert sdb.cnt(keys2) == 1
        sdb.rem(keys2)
        actual = sdb.get(keys=keys2)
        assert actual == []
        assert sdb.cnt(keys2) == 0

        sdb.put(keys=keys2, vals=[bob])
        actual = sdb.get(keys=keys2)
        assert actual == [bob]

        bil = "Go away."
        sdb.pin(keys=keys2, vals=[bil])
        actual = sdb.get(keys=keys2)
        assert actual == [bil]

        sdb.add(keys=keys2, val=bob)
        actual = sdb.get(keys=keys2)
        assert actual == [bil, bob]

    assert not os.path.exists(db.path)
    assert not db.opened


def test_ioset_suber():
    """
    Test IoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.IoSetSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.IoSetSuber)
        assert not sdb.sdb.flags()["dupsort"]

        sue = "Hello sailer!"
        sal = "Not my type."

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")

        sdb.put(keys=keys0, vals=[sal, sue])
        actuals = sdb.get(keys=keys0)
        assert actuals == [sal, sue]  # insertion order not lexicographic
        assert sdb.cnt(keys0) == 2
        actual = sdb.getLast(keys=keys0)
        assert actual == sue

        sdb.rem(keys0)
        actuals = sdb.get(keys=keys0)
        assert not actuals
        assert actuals == []
        assert sdb.cnt(keys0) == 0

        sdb.put(keys=keys0, vals=[sue, sal])
        actuals = sdb.get(keys=keys0)
        assert actuals == [sue, sal]  # insertion order
        actual = sdb.getLast(keys=keys0)
        assert actual == sal

        sam = "A real charmer!"
        result = sdb.add(keys=keys0, val=sam)
        assert result
        actuals = sdb.get(keys=keys0)
        assert actuals == [sue, sal, sam]   # insertion order

        zoe = "See ya later."
        zia = "Hey gorgeous!"

        result = sdb.pin(keys=keys0, vals=[zoe, zia])
        assert result
        actuals = sdb.get(keys=keys0)
        assert actuals == [zoe, zia]  # insertion order

        sdb.put(keys=keys1, vals=[sal, sue, sam])
        actuals = sdb.get(keys=keys1)
        assert actuals == [sal, sue, sam]

        #  Need test of remove with a specific val not just remove all.
        # XXX

        for i, val in enumerate(sdb.getIter(keys=keys1)):
            assert val == actuals[i]

        items = [(keys, val) for keys, val in sdb.getAllItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'A real charmer!')]


        items = list(sdb.getAllIoItemIter())
        assert items ==  [(('test_key', '0001', 'AAAAAAAAAAAAAAAAAAAAAA'), 'See ya later.'),
                        (('test_key', '0001', 'AAAAAAAAAAAAAAAAAAAAAB'), 'Hey gorgeous!'),
                        (('test_key', '0002', 'AAAAAAAAAAAAAAAAAAAAAA'), 'Not my type.'),
                        (('test_key', '0002', 'AAAAAAAAAAAAAAAAAAAAAB'), 'Hello sailer!'),
                        (('test_key', '0002', 'AAAAAAAAAAAAAAAAAAAAAC'), 'A real charmer!')]

        items = sdb.getIoItem(keys=keys1)
        assert items == [(('test_key', '0002', 'AAAAAAAAAAAAAAAAAAAAAA'), 'Not my type.'),
                         (('test_key', '0002', 'AAAAAAAAAAAAAAAAAAAAAB'), 'Hello sailer!'),
                         (('test_key', '0002', 'AAAAAAAAAAAAAAAAAAAAAC'), 'A real charmer!')]

        items = [(iokeys, val) for iokeys,  val in  sdb.getIoItemIter(keys=keys0)]
        assert items == [(('test_key', '0001', 'AAAAAAAAAAAAAAAAAAAAAA'), 'See ya later.'),
                         (('test_key', '0001', 'AAAAAAAAAAAAAAAAAAAAAB'), 'Hey gorgeous!')]

        assert sdb.put(keys=("test", "pop"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        items = list(sdb.getTopIoItemIter(keys=topkeys))
        assert items == [(('test', 'pop', 'AAAAAAAAAAAAAAAAAAAAAA'), 'Not my type.'),
                         (('test', 'pop', 'AAAAAAAAAAAAAAAAAAAAAB'), 'Hello sailer!'),
                         (('test', 'pop', 'AAAAAAAAAAAAAAAAAAAAAC'), 'A real charmer!')]

        for iokeys, val in sdb.getAllIoItemIter():
            assert sdb.remIokey(iokeys=iokeys)

        assert sdb.cnt(keys=keys0) == 0
        assert sdb.cnt(keys=keys1) == 0


        # test with keys as string not tuple
        keys2 = "keystr"
        bob = "Shove off!"
        sdb.put(keys=keys2, vals=[bob])
        actuals = sdb.get(keys=keys2)
        assert actuals == [bob]
        assert sdb.cnt(keys2) == 1
        sdb.rem(keys2)
        actuals = sdb.get(keys=keys2)
        assert actuals == []
        assert sdb.cnt(keys2) == 0

        sdb.put(keys=keys2, vals=[bob])
        actuals = sdb.get(keys=keys2)
        assert actuals == [bob]

        bil = "Go away."
        sdb.pin(keys=keys2, vals=[bil])
        actuals = sdb.get(keys=keys2)
        assert actuals == [bil]

        sdb.add(keys=keys2, val=bob)
        actuals = sdb.get(keys=keys2)
        assert actuals == [bil, bob]

    assert not os.path.exists(db.path)
    assert not db.opened


def test_serder_suber():
    """
    Test SerderSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.SerderSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.SerderSuber)
        assert not sdb.sdb.flags()["dupsort"]

        pre = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        srdr0 = eventing.incept(keys=[pre])

        keys = (pre, srdr0.dig)
        sdb.put(keys=keys, val=srdr0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr0.dig

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=srdr0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr0.dig

        srdr1 = eventing.rotate(pre=pre, keys=[pre], dig=srdr0.dig)
        result = sdb.put(keys=keys, val=srdr1)
        assert not result
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr0.dig

        result = sdb.pin(keys=keys, val=srdr1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr1.dig

        # test with keys as string not tuple
        keys = "{}.{}".format(pre, srdr1.dig)

        sdb.put(keys=keys, val=srdr1)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr1.dig

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        # test missing entry at keys
        badkey = "badkey"
        actual = sdb.get(badkey)
        assert actual is None

        # test iteritems
        sdb = subing.SerderSuber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.SerderSuber)
        sdb.put(keys=("a","1"), val=srdr0)
        sdb.put(keys=("a","2"), val=srdr1)

        items = [(keys, srdr.dig) for keys, srdr in sdb.getAllItemIter()]
        assert items == [(('a', '1'), srdr0.dig),
                         (('a', '2'), srdr1.dig)]

        assert sdb.put(keys=("b","1"), val=srdr0)
        assert sdb.put(keys=("b","2"), val=srdr1)
        assert sdb.put(keys=("bc","1"), val=srdr0)

        topkeys =  ("b", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.dig) for keys, srdr in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('b', '1'), srdr0.dig),
                         (('b', '2'), srdr1.dig)]

    assert not os.path.exists(db.path)
    assert not db.opened


def test_serder_dup_suber():
    """
    Test SerderDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.SerderDupSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.SerderDupSuber)
        assert sdb.sdb.flags()["dupsort"]

        pre0 = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        srdr0 = eventing.incept(keys=[pre0])
        assert srdr0.raw == (b'{"v":"KERI10JSON0000c1_","i":"BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc",'
                             b'"s":"0","t":"icp","kt":"1","k":["BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhc'
                             b'c"],"n":"","bt":"0","b":[],"c":[],"a":[]}')
        pre1 = "BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA"
        srdr1 = eventing.incept(keys=[pre1])
        assert srdr1.raw == (b'{"v":"KERI10JSON0000c1_","i":"BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA",'
                             b'"s":"0","t":"icp","kt":"1","k":["BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhc'
                             b'A"],"n":"","bt":"0","b":[],"c":[],"a":[]}')
        pre2 = "BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-b"
        srdr2 = eventing.incept(keys=[pre2])
        assert srdr2.raw == (b'{"v":"KERI10JSON0000c1_","i":"BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y",'
                             b'"s":"0","t":"icp","kt":"1","k":["BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-'
                             b'b"],"n":"","bt":"0","b":[],"c":[],"a":[]}')
        pre3 = "B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-z"
        srdr3 = eventing.incept(keys=[pre3])
        assert srdr3.raw == (b'{"v":"KERI10JSON0000c1_","i":"B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w",'
                             b'"s":"0","t":"icp","kt":"1","k":["B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-'
                             b'z"],"n":"","bt":"0","b":[],"c":[],"a":[]}')

        keys0 = ("blue", "fore")
        keys1 = ("blue", "back")

        sdb.put(keys=keys0, vals=[srdr0, srdr1])
        actual = sdb.get(keys=keys0)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr1.ked, srdr0.ked]  # lexicographic order
        assert sdb.cnt(keys0) == 2
        actual = sdb.getLast(keys=keys0)
        assert actual.ked == srdr0.ked

        sdb.rem(keys0)
        actual = sdb.get(keys=keys0)
        assert not actual
        assert actual == []
        assert sdb.cnt(keys0) == 0

        sdb.put(keys=keys0, vals=[srdr1, srdr0])
        actual = sdb.get(keys=keys0)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr1.ked, srdr0.ked]  # lexicographic order

        assert sdb.add(keys=keys0, val=srdr2)
        actual = sdb.get(keys=keys0)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr2.ked, srdr1.ked, srdr0.ked]  # lexicographic order

        assert sdb.pin(keys=keys0, vals=[srdr3])
        actual = sdb.get(keys=keys0)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr3.ked]  # lexi order

        sdb.put(keys=keys1, vals=[srdr0, srdr1, srdr2])
        actual = sdb.get(keys=keys1)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr2.ked, srdr1.ked, srdr0.ked]  # lexicographic order

        for i, val in enumerate(sdb.getIter(keys=keys1)):
            assert val.ked == keds[i]

        items = [(keys, val.ked) for keys, val in sdb.getAllItemIter()]
        assert items == [(('blue', 'back'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-b'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('blue', 'back'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('blue', 'back'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('blue', 'fore'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-z'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []})]


        keys3 = ("red", "top")
        assert sdb.put(keys=keys3, vals=[srdr0, srdr1, srdr2])
        keys4 = ("red", "side")
        assert sdb.put(keys=keys4, vals=[srdr0, srdr1, srdr2])

        topkeys =  ("red", "")  # append empty str to force trailing .sep
        items = [(keys, val.ked) for keys, val in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('red', 'side'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-b'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('red', 'side'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('red', 'side'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('red', 'top'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-b'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('red', 'top'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []}),
                       (('red', 'top'),
                        {'v': 'KERI10JSON0000c1_',
                         'i': 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc',
                         's': '0',
                         't': 'icp',
                         'kt': '1',
                         'k': ['BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'],
                         'n': '',
                         'bt': '0',
                         'b': [],
                         'c': [],
                         'a': []})]

        # test with keys as string not tuple
        keys2 = "keystr"

        sdb.put(keys=keys2, vals=[srdr0])
        actual = sdb.get(keys=keys2)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr0.ked]
        assert sdb.cnt(keys2) == 1
        sdb.rem(keys2)
        actual = sdb.get(keys=keys2)
        assert actual == []
        assert sdb.cnt(keys2) == 0

        sdb.put(keys=keys2, vals=[srdr0])
        actual = sdb.get(keys=keys2)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr0.ked]

        sdb.pin(keys=keys2, vals=[srdr1])
        actual = sdb.get(keys=keys2)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr1.ked]

        sdb.add(keys=keys2, val=srdr2)
        actual = sdb.get(keys=keys2)
        keds = [srdr.ked for srdr in actual]
        assert keds == [srdr2.ked, srdr1.ked]  # lexi order

    assert not os.path.exists(db.path)
    assert not db.opened


def test_cesr_suber():
    """
    Test CesrSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CesrSuber(db=db, subkey='bags.')  # default klas is Matter
        assert isinstance(sdb, subing.CesrSuber)
        assert issubclass(sdb.klas, coring.Matter)
        assert not sdb.sdb.flags()["dupsort"]

        pre0 = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        val0 = coring.Matter(qb64=pre0)

        keys = ("alpha", "dog")
        assert sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val0.qb64

        assert sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val0.qb64

        pre1 = "BHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        val1 = coring.Matter(qb64=pre1)
        assert not sdb.put(keys=keys, val=val1)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val0.qb64

        assert sdb.pin(keys=keys, val=val1)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val1.qb64

        # test with keys as string not tuple
        keys = "{}.{}".format("beta", "fish")

        assert sdb.put(keys=keys, val=val1)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val1.qb64

        assert sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        # test missing entry at keys
        badkey = "badkey"
        actual = sdb.get(badkey)
        assert actual is None

        # test iteritems
        sdb = subing.CesrSuber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.CesrSuber)
        assert sdb.put(keys=("a","1"), val=val0)
        assert sdb.put(keys=("a","2"), val=val1)

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getAllItemIter()]
        assert items == [(('a', '1'), val0.qb64),
                         (('a', '2'), val1.qb64)]

        #  Try other classs
        sdb = subing.CesrSuber(db=db, subkey='pigs.', klas=coring.Diger)
        assert isinstance(sdb, subing.CesrSuber)
        assert issubclass(sdb.klas, coring.Diger)

        dig0 = "EQPYGGwTmuupWzwEHHzq7K0gzUhPx5_yZ-Wk1x4ejhcc"
        val0 = coring.Diger(qb64=dig0)

        keys = ("alpha", "dog")
        assert sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val0.qb64

        assert sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        assert sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val0.qb64

        pre1 = "EHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        val1 = coring.Matter(qb64=pre1)
        assert not sdb.put(keys=keys, val=val1)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val0.qb64

        result = sdb.pin(keys=keys, val=val1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val1.qb64

        # test iteritems
        sdb = subing.CesrSuber(db=db, subkey='figs.')
        assert isinstance(sdb, subing.CesrSuber)
        assert sdb.put(keys=("a","1"), val=val0)
        assert sdb.put(keys=("a","2"), val=val1)

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getAllItemIter()]
        assert items == [(('a', '1'), val0.qb64),
                         (('a', '2'), val1.qb64)]

        assert sdb.put(keys=("b","1"), val=val0)
        assert sdb.put(keys=("b","2"), val=val1)
        assert sdb.put(keys=("bc","1"), val=val0)

        topkeys =  ("b", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.qb64) for keys, srdr in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('b', '1'), val0.qb64),
                         (('b', '2'), val1.qb64)]

        # Try Siger Indexer Subclass
        sdb = subing.CesrSuber(db=db, subkey='pigs.', klas=coring.Siger)
        assert isinstance(sdb, subing.CesrSuber)
        assert issubclass(sdb.klas, coring.Siger)
        sig0 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = coring.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Siger)
        assert actual.qb64 == val0.qb64


    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""


def test_multi_suber():
    """
    Test MultiSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        # Test Single klas
        sdb = subing.CatSuber(db=db, subkey='bags.')  # default klas is [Matter]
        assert isinstance(sdb, subing.CatSuber)
        assert len(sdb.klas) == 1
        assert issubclass(sdb.klas[0], coring.Matter)
        assert not sdb.sdb.flags()["dupsort"]

        matb0 = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        matter0 = coring.Matter(qb64=matb0)
        vals0 = [matter0]

        matb1 = "BHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        matter1 = coring.Matter(qb64=matb1)
        vals1 = [matter1]

        keys0 = ("alpha", "dog")
        sdb.put(keys=keys0, val=vals0)
        actuals = sdb.get(keys=keys0)
        assert isinstance(actuals[0], coring.Matter)
        assert actuals[0].qb64 == matter0.qb64

        sdb.rem(keys0)
        actuals = sdb.get(keys=keys0)
        assert actuals is None

        sdb.put(keys=keys0, val=vals0)
        actuals = sdb.get(keys=keys0)
        assert isinstance(actuals[0], coring.Matter)
        assert actuals[0].qb64 == vals0[0].qb64

        result = sdb.put(keys=keys0, val=vals1)
        assert not result

        result = sdb.pin(keys=keys0, val=vals1)
        assert result
        actuals = sdb.get(keys=keys0)
        assert isinstance(actuals[0], coring.Matter)
        assert actuals[0].qb64 == matter1.qb64

        sdb.rem(keys0)
        actuals = sdb.get(keys=keys0)
        assert actuals is None

        # test with keys as string not tuple
        keys1 = "{}.{}".format("beta", "fish")

        sdb.put(keys=keys1, val=vals1)
        actuals = sdb.get(keys=keys1)
        assert isinstance(actuals[0], coring.Matter)
        assert actuals[0].qb64 == matter1.qb64

        sdb.rem(keys1)
        actuals = sdb.get(keys=keys1)
        assert actuals is None

        # test missing entry at keys
        badkey = "badkey"
        actuals = sdb.get(badkey)
        assert actuals is None

        # test iteritems
        assert sdb.put(keys0, vals0)
        assert sdb.put(keys1, vals1)

        items = [(keys, [val.qb64 for val in vals])
                                       for keys, vals in sdb.getAllItemIter()]
        assert items == [(('alpha', 'dog'), [matter0.qb64]),
                         (('beta', 'fish'), [matter1.qb64])]

        sdb.put(keys=("b","1"), val=vals0)
        sdb.put(keys=("b","2"), val=vals1)
        sdb.put(keys=("c","1"), val=vals0)
        sdb.put(keys=("c","2"), val=vals1)

        topkeys = ("b","")  # last element empty to force trailing separator
        items = [(keys, [val.qb64 for val in vals])
                            for keys, vals in  sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('b', '1'), [matter0.qb64]),
                         (('b', '2'), [matter1.qb64])]

        # Test multiple klases
        klases = (coring.Dater, coring.Seqner, coring.Diger)
        sdb = subing.CatSuber(db=db, subkey='bags.', klas=klases)
        assert isinstance(sdb, subing.CatSuber)
        for klas, sklas in zip(klases, sdb.klas):
            assert klas == sklas
        assert not sdb.sdb.flags()["dupsort"]

        # test .toval and tovals  needs .klas to work
        dater = coring.Dater(dts="2021-01-01T00:00:00.000000+00:00")
        datb = dater.qb64b
        assert datb == b'1AAG2021-01-01T00c00c00d000000p00c00'

        seqner = coring.Seqner(sn=20)
        seqb = seqner.qb64b
        assert seqb == b'0AAAAAAAAAAAAAAAAAAAAAFA'

        diger = coring.Diger(ser=b"Hello Me Maties.")
        digb = diger.qb64b
        assert digb == b'Eurq5IDrYVpYoBB_atyW3gPXBEB5XBDuEG5wMbjcauwk'

        vals = (dater, seqner, diger)
        valb = sdb._cat(objs=vals)
        assert  valb == datb + seqb + digb

        vals = sdb._uncat(val=valb)
        assert b"".join(val.qb64b for val in vals) == valb
        for val, klas in zip(vals, sdb.klas):
            assert isinstance(val, klas)

        # Try Siger Indexer Subclass
        sdb = subing.CatSuber(db=db, subkey='pigs.', klas=(coring.Siger, ))
        assert isinstance(sdb, subing.CatSuber)
        assert issubclass(sdb.klas[0], coring.Siger)
        sig0 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = coring.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, val=[val0])
        actual = sdb.get(keys=keys)
        assert isinstance(actual[0], coring.Siger)
        assert actual[0].qb64 == val0.qb64

    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""


def test_cat_ioset_suber():
    """
    Test CatIoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CatIoSetSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.CatIoSetSuber)
        assert sdb.klas == (coring.Matter, )  # default
        assert not sdb.sdb.flags()["dupsort"]
        assert isinstance(sdb, subing.CatSuberBase)
        assert isinstance(sdb, subing.IoSetSuber)

        klases = (coring.Seqner, coring.Diger)
        sdb = subing.CatIoSetSuber(db=db, subkey='bags.', klas=klases)
        assert isinstance(sdb, subing.CatIoSetSuber)
        for klas, sklas in zip(klases, sdb.klas):
            assert klas == sklas
        assert not sdb.sdb.flags()["dupsort"]

        # test .toval and tovals  needs .klas to work
        sqr0 = coring.Seqner(sn=20)
        sqr0.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAFA'

        dgr0 = coring.Diger(ser=b"Hello Me Maties.")
        assert dgr0.qb64b == b'Eurq5IDrYVpYoBB_atyW3gPXBEB5XBDuEG5wMbjcauwk'

        vals0 = (sqr0, dgr0)

        val0b = sdb._cat(objs=vals0)
        assert val0b == sqr0.qb64b + dgr0.qb64b
        vals = sdb._uncat(val=val0b)
        assert b"".join(val.qb64b for val in vals0) == val0b
        for val, klas in zip(vals, sdb.klas):
            assert isinstance(val, klas)

        sqr1 = coring.Seqner(sn=32)
        sqr1.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAIA'

        dgr1 = coring.Diger(ser=b"Hi Guy.")
        assert dgr1.qb64b == b'EB1-ycv6SjyV3Ehn0kv4oFMPh4wKoACQTDgeYoWxPjkI'

        vals1 = (sqr1, dgr1)

        sqr2 = coring.Seqner(sn=1534)
        sqr2.qb64b == b'0AAAAAAAAAAAAAAAAAAAAF_g'

        dgr2 = coring.Diger(ser=b"Bye Bye Birdie.")
        assert dgr2.qb64b == b'EA7hRVxJ-9-gadLMnJwyKKHKQnJg6yGzK9T-XxTlOs7Y'

        vals2 = (sqr2, dgr2)

        keys0 = ("a", "front")
        keys1 = ("ab", "side")
        keys2 = ("ac", "back")

        assert sdb.put(keys=keys0, vals=[vals0, vals1])
        assert sdb.cnt(keys0) == 2
        actuals = sdb.get(keys=keys0)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        assert valss == [
                        [sqr0.qb64, dgr0.qb64],
                        [sqr1.qb64, dgr1.qb64],
                       ]

        actual = sdb.getLast(keys=keys0)
        assert [actual[0].qb64, actual[1].qb64] == [sqr1.qb64, dgr1.qb64]

        sdb.rem(keys0)
        assert sdb.get(keys=keys0) == []
        assert sdb.cnt(keys0) == 0

        sdb.put(keys=keys0, vals=[vals1, vals0])
        actuals = sdb.get(keys=keys0)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        assert valss == [
                        [sqr1.qb64, dgr1.qb64],
                        [sqr0.qb64, dgr0.qb64],
                       ]
        actual = sdb.getLast(keys=keys0)
        assert [actual[0].qb64, actual[1].qb64] == [sqr0.qb64, dgr0.qb64]


        assert sdb.add(keys=keys0, val=vals2)
        assert sdb.cnt(keys0) == 3
        actuals = sdb.get(keys=keys0)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        assert valss == [
                        [sqr1.qb64, dgr1.qb64],
                        [sqr0.qb64, dgr0.qb64],
                        [sqr2.qb64, dgr2.qb64],
            ]
        actual = sdb.getLast(keys=keys0)
        assert [actual[0].qb64, actual[1].qb64] == [sqr2.qb64, dgr2.qb64]


        assert sdb.pin(keys=keys0, vals=[vals0, vals1])
        assert sdb.cnt(keys0) == 2
        actuals = sdb.get(keys=keys0)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        assert valss == [
                        [sqr0.qb64, dgr0.qb64],
                        [sqr1.qb64, dgr1.qb64],
                       ]

        assert sdb.put(keys=keys1, vals=[vals2, vals1])
        assert sdb.cnt(keys1) == 2
        actuals = sdb.get(keys=keys1)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        assert valss == [
                        [sqr2.qb64, dgr2.qb64],
                        [sqr1.qb64, dgr1.qb64],
                       ]

        valss = [[val.qb64 for val in vals] for vals in sdb.getIter(keys=keys1)]
        assert valss == [
                          [sqr2.qb64, dgr2.qb64],
                          [sqr1.qb64, dgr1.qb64],
                        ]

        #  test remove with a specific val not just remove all.
        assert sdb.rem(keys=keys1, val=vals1)
        assert sdb.cnt(keys1) == 1
        actuals = sdb.get(keys=keys1)
        vals = [[val.qb64 for val in actual] for actual in actuals]
        assert vals == [
                        [sqr2.qb64, dgr2.qb64],
                       ]

        assert sdb.put(keys=keys2, vals=[vals0, vals2])

        items = [(keys, [val.qb64 for val in  vals])
                                         for keys, vals in sdb.getAllItemIter()]
        assert items == [
                         (keys0, [sqr0.qb64, dgr0.qb64]),
                         (keys0, [sqr1.qb64, dgr1.qb64]),
                         (keys1, [sqr2.qb64, dgr2.qb64]),
                         (keys2, [sqr0.qb64, dgr0.qb64]),
                         (keys2, [sqr2.qb64, dgr2.qb64])
                        ]

        items = [(iokeys, [val.qb64 for val in  vals])
                                      for iokeys, vals in sdb.getAllIoItemIter()]
        assert items ==  [
                          (keys0 + ('AAAAAAAAAAAAAAAAAAAAAA', ), [sqr0.qb64, dgr0.qb64]),
                          (keys0 + ('AAAAAAAAAAAAAAAAAAAAAB', ), [sqr1.qb64, dgr1.qb64]),
                          (keys1 + ('AAAAAAAAAAAAAAAAAAAAAA', ), [sqr2.qb64, dgr2.qb64]),
                          (keys2 + ('AAAAAAAAAAAAAAAAAAAAAA', ), [sqr0.qb64, dgr0.qb64]),
                          (keys2 + ('AAAAAAAAAAAAAAAAAAAAAB', ), [sqr2.qb64, dgr2.qb64])
                         ]

        items = [(iokeys, [val.qb64 for val in vals])
                                 for iokeys, vals in sdb.getIoItem(keys=keys1)]
        assert items == [(keys1 +  ('AAAAAAAAAAAAAAAAAAAAAA', ), [sqr2.qb64, dgr2.qb64])]

        items = [(iokeys, [val.qb64 for val in vals])
                             for iokeys, vals in  sdb.getIoItemIter(keys=keys0)]
        assert items == [
                        (keys0 + ('AAAAAAAAAAAAAAAAAAAAAA', ), [sqr0.qb64, dgr0.qb64]),
                        (keys0 + ('AAAAAAAAAAAAAAAAAAAAAB', ), [sqr1.qb64, dgr1.qb64]),
                        ]


        topkeys = ("a", "")
        items = [(keys, [val.qb64 for val in vals])
                            for keys, vals in sdb.getTopItemIter(keys=topkeys)]
        assert items == [
                          (keys0, [sqr0.qb64, dgr0.qb64]),
                          (keys0, [sqr1.qb64, dgr1.qb64]),
                        ]

        items = [(iokeys, [val.qb64 for val in vals])
                             for iokeys, vals in sdb.getTopIoItemIter(keys=topkeys)]

        assert items == [
                        (keys0 + ('AAAAAAAAAAAAAAAAAAAAAA', ), [sqr0.qb64, dgr0.qb64]),
                        (keys0 + ('AAAAAAAAAAAAAAAAAAAAAB', ), [sqr1.qb64, dgr1.qb64]),
                        ]

        for iokeys, val in sdb.getAllIoItemIter():
            assert sdb.remIokey(iokeys=iokeys)

        assert sdb.cnt(keys=keys0) == 0
        assert sdb.cnt(keys=keys1) == 0
        assert sdb.cnt(keys=keys2) == 0

        # Try Siger Indexer Subclass
        sdb = subing.CatIoSetSuber(db=db, subkey='pigs.', klas=(coring.Siger, ))
        assert isinstance(sdb, subing.CatIoSetSuber)
        assert issubclass(sdb.klas[0], coring.Siger)
        sig0 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = coring.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, vals=[[val0]])
        actuals = sdb.get(keys=keys)
        assert isinstance(actuals[0][0], coring.Siger)
        assert actuals[0][0].qb64 == val0.qb64

    assert not os.path.exists(db.path)
    assert not db.opened


def test_cesr_dup_suber():
    """
    Test CesrDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CesrDupSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.CesrDupSuber)
        assert issubclass(sdb.klas, coring.Matter)
        assert sdb.sdb.flags()["dupsort"]

        pre0 = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        val0 = coring.Matter(qb64=pre0)
        assert val0.qb64 == pre0

        pre1 = "BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA"
        val1 = coring.Matter(qb64=pre1)
        assert val1.qb64 == pre1

        pre2 = "BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y"
        val2 = coring.Matter(qb64=pre2)
        assert val2.qb64 == pre2

        pre3 = "B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w"
        val3 = coring.Matter(qb64=pre3)
        assert val3.qb64 == pre3

        keys0 = ("alpha", "dog")
        keys1 = ("beta", "cat")
        keys2 = ("betagamma", "squirrel")

        sdb.put(keys=keys0, vals=[val0, val1])
        actual = sdb.get(keys=keys0)
        pres = [val.qb64 for val in actual]
        assert pres == [val1.qb64, val0.qb64] == [pre1, pre0]  # lexicographic order
        assert sdb.cnt(keys0) == 2
        actual = sdb.getLast(keys=keys0)
        assert actual.qb64 == pre0

        sdb.rem(keys0)
        actual = sdb.get(keys=keys0)
        assert not actual
        assert actual == []
        assert sdb.cnt(keys0) == 0

        sdb.put(keys=keys0, vals=[val1, val0])
        actual = sdb.get(keys=keys0)
        pres = [val.qb64 for val in actual]
        assert pres == [val1.qb64, val0.qb64] == [pre1, pre0]  # lexicographic order

        assert sdb.add(keys=keys0, val=val2)
        actual = sdb.get(keys=keys0)
        pres = [val.qb64 for val in actual]
        assert pres == [val2.qb64, val1.qb64, val0.qb64] == [pre2, pre1, pre0]  # lexicographic order

        assert sdb.pin(keys=keys0, vals=[val3])
        actual = sdb.get(keys=keys0)
        pres = [val.qb64 for val in actual]
        assert pres == [val3.qb64] == [pre3]  # lexicographic order

        sdb.put(keys=keys1, vals=[val0, val1, val2])
        actual = sdb.get(keys=keys1)
        pres = [val.qb64 for val in actual]   # lexicographic order
        assert pres == [val2.qb64, val1.qb64, val0.qb64] == [pre2, pre1, pre0]

        for i, val in enumerate(sdb.getIter(keys=keys1)):
            assert val.qb64 == pres[i]


        assert sdb.pin(keys=keys2, vals=[val3])
        actual = sdb.get(keys=keys2)
        pres = [val.qb64 for val in actual]
        assert pres == [val3.qb64] == [pre3]  # lexicographic order


        items = [(keys, val.qb64) for keys, val in sdb.getAllItemIter()]
        assert items == [(('alpha', 'dog'), 'B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w'),
                         (('beta', 'cat'), 'BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y'),
                         (('beta', 'cat'), 'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'),
                         (('beta', 'cat'), 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'),
                         (('betagamma', 'squirrel'), 'B7K0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w')]


        topkeys = ("beta", "")  # append empty str to force trailing .sep
        items = [(keys, val.qb64) for keys, val in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(('beta', 'cat'), 'BGzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y'),
                         (('beta', 'cat'), 'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'),
                         (('beta', 'cat'), 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc')]

        # test with keys as string not tuple
        keys2 = "keystr"

        sdb.put(keys=keys2, vals=[val0])
        actual = sdb.get(keys=keys2)
        pres = [val.qb64 for val in actual]
        assert pres == [val0.qb64]
        assert sdb.cnt(keys2) == 1
        sdb.rem(keys2)
        actual = sdb.get(keys=keys2)
        assert actual == []
        assert sdb.cnt(keys2) == 0

        sdb.put(keys=keys2, vals=[val0])
        actual = sdb.get(keys=keys2)
        pres = [val.qb64 for val in actual]
        assert pres == [val0.qb64]

        sdb.pin(keys=keys2, vals=[val1])
        actual = sdb.get(keys=keys2)
        pres = [val.qb64 for val in actual]
        assert pres == [val1.qb64]

        sdb.add(keys=keys2, val=val2)
        actual = sdb.get(keys=keys2)
        pres = [val.qb64 for val in actual]
        assert pres == [val2.qb64, val1.qb64]  # lexi order

        # Try Siger Indexer Subclass
        sdb = subing.CesrDupSuber(db=db, subkey='pigs.', klas=coring.Siger)
        assert isinstance(sdb, subing.CesrDupSuber)
        assert issubclass(sdb.klas, coring.Siger)
        sig0 = 'AAmdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = coring.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, vals=[val0])
        actuals = sdb.get(keys=keys)
        assert isinstance(actuals[0], coring.Siger)
        assert actuals[0].qb64 == val0.qb64


    assert not os.path.exists(db.path)
    assert not db.opened


def test_signer_suber():
    """
    Test SignerSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.SignerSuber(db=db, subkey='bags.')  # default klas is Signer
        assert isinstance(sdb, subing.SignerSuber)
        assert issubclass(sdb.klas, coring.Signer)
        assert not sdb.sdb.flags()["dupsort"]

        # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
        seed0 = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
                           b'\xde\x06\xc0+')
        signer0 = coring.Signer(raw=seed0, code=coring.MtrDex.Ed25519_Seed)
        assert signer0.verfer.code == coring.MtrDex.Ed25519
        assert signer0.verfer.transferable  # default
        assert signer0.qb64b == b'AGDswxA8qdkb646JFZWUflm_OKUeF41iG2gTw3N4GwCs'
        assert signer0.verfer.qb64b == b'DhixhZjC1Wj2bLR1QdADT79kS2zwHld29ekca0elxHiE'

        # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
        seed1 = (b'`\x05\x93\xb9\x9b6\x1e\xe0\xd7\x98^\x94\xc8Et\xf2\xc4\xcd\x94\x18'
                 b'\xc6\xae\xb9\xb6m\x12\xc4\x80\x03\x07\xfc\xf7')

        signer1 = coring.Signer(raw=seed1, code=coring.MtrDex.Ed25519_Seed)
        assert signer1.verfer.code == coring.MtrDex.Ed25519
        assert signer1.verfer.transferable  # default
        assert signer1.qb64b == b'AYAWTuZs2HuDXmF6UyEV08sTNlBjGrrm2bRLEgAMH_Pc'
        assert signer1.verfer.qb64b == b'Dgekf6SB_agwx96mVSZI6PTC09j4Sp8qUbgKglN8uLjY'

        keys = (signer0.verfer.qb64, )  # must be verfer as key to get transferable
        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  try put different val when already put
        result = sdb.put(keys=keys, val=signer1)
        assert not result
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  now overwrite with pin. Key is wrong but transferable property is
        #  the same so that is all that matters to get back signer
        result = sdb.pin(keys=keys, val=signer1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer1.qb64
        assert actual.verfer.qb64 == signer1.verfer.qb64

        # test with keys as string not tuple
        keys = signer0.verfer.qb64

        sdb.pin(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        assert not  sdb.get(keys=keys)

        # test missing entry at keys
        badkey = b'D1QdADT79kS2zwHld29hixhZjC1Wj2bLRekca0elxHiE'
        assert not  sdb.get(badkey)

        # test iteritems
        sdb = subing.SignerSuber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.SignerSuber)
        assert sdb.put(keys=signer0.verfer.qb64b, val=signer0)
        assert sdb.put(keys=signer1.verfer.qb64b, val=signer1)

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getAllItemIter()]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                         ((signer0.verfer.qb64, ), signer0.qb64)]

        assert sdb.put(keys=("a", signer0.verfer.qb64), val=signer0)
        assert sdb.put(keys=("a", signer1.verfer.qb64), val=signer1)
        assert sdb.put(keys=("ab", signer0.verfer.qb64), val=signer0)
        assert sdb.put(keys=("ab", signer1.verfer.qb64), val=signer1)

        topkeys = ("a", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.qb64) for keys, srdr in sdb.getTopItemIter(keys=topkeys)]
        assert items == [(("a", signer1.verfer.qb64), signer1.qb64),
                         (("a", signer0.verfer.qb64, ), signer0.qb64)]


    assert not os.path.exists(db.path)
    assert not db.opened


def test_crypt_signer_suber():
    """
    test Manager class with aeid
    """
    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed0 = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
                       b'\xde\x06\xc0+')
    signer0 = coring.Signer(raw=seed0, code=coring.MtrDex.Ed25519_Seed)
    assert signer0.verfer.code == coring.MtrDex.Ed25519
    assert signer0.verfer.transferable  # default
    assert signer0.qb64b == b'AGDswxA8qdkb646JFZWUflm_OKUeF41iG2gTw3N4GwCs'
    assert signer0.verfer.qb64b == b'DhixhZjC1Wj2bLR1QdADT79kS2zwHld29ekca0elxHiE'

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'`\x05\x93\xb9\x9b6\x1e\xe0\xd7\x98^\x94\xc8Et\xf2\xc4\xcd\x94\x18'
             b'\xc6\xae\xb9\xb6m\x12\xc4\x80\x03\x07\xfc\xf7')

    signer1 = coring.Signer(raw=seed1, code=coring.MtrDex.Ed25519_Seed)
    assert signer1.verfer.code == coring.MtrDex.Ed25519
    assert signer1.verfer.transferable  # default
    assert signer1.qb64b == b'AYAWTuZs2HuDXmF6UyEV08sTNlBjGrrm2bRLEgAMH_Pc'
    assert signer1.verfer.qb64b == b'Dgekf6SB_agwx96mVSZI6PTC09j4Sp8qUbgKglN8uLjY'


    # rawsalt =pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    rawsalt = b'0123456789abcdef'
    salter = coring.Salter(raw=rawsalt)
    salt = salter.qb64
    assert salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    stem = "blue"

    # cryptseed0 = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    cryptseed0 = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner0 = coring.Signer(raw=cryptseed0, code=coring.MtrDex.Ed25519_Seed,
                           transferable=False)
    seed0 = cryptsigner0.qb64
    aeid0 = cryptsigner0.verfer.qb64
    assert aeid0 == 'BJruYr3oXDGRTRN0XnhiqDeoENdRak6FD8y2vsTvvJkE'

    decrypter = coring.Decrypter(seed=seed0)
    encrypter = coring.Encrypter(verkey=aeid0)
    assert encrypter.verifySeed(seed=seed0)

    # cryptseed1 = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    cryptseed1 = (b"\x89\xfe{\xd9'\xa7\xb3\x89#\x19\xbec\xee\xed\xc0\xf9\x97\xd0\x8f9\x1dyNI"
               b'I\x98\xbd\xa4\xf6\xfe\xbb\x03')
    cryptsigner1 = coring.Signer(raw=cryptseed1, code=coring.MtrDex.Ed25519_Seed,
                           transferable=False)


    with dbing.openLMDB() as db,  keeping.openKS() as ks:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CryptSignerSuber(db=db, subkey='bags.')  # default klas is Signer
        assert isinstance(sdb, subing.CryptSignerSuber)
        assert issubclass(sdb.klas, coring.Signer)
        assert not sdb.sdb.flags()["dupsort"]

        # Test without encrypter or decrypter
        keys = (signer0.verfer.qb64, )  # must be verfer as key to get transferable
        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  try put different val when already put
        result = sdb.put(keys=keys, val=signer1)
        assert not result
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  now overwrite with pin. Key is wrong but transferable property is
        #  the same so that is all that matters to get back signer
        result = sdb.pin(keys=keys, val=signer1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer1.qb64
        assert actual.verfer.qb64 == signer1.verfer.qb64

        # test with keys as string not tuple
        keys = signer0.verfer.qb64

        sdb.pin(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        assert not  sdb.get(keys=keys)

        # test missing entry at keys
        badkey = b'D1QdADT79kS2zwHld29hixhZjC1Wj2bLRekca0elxHiE'
        assert not  sdb.get(badkey)

        # test iteritems
        sdb = subing.CryptSignerSuber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.CryptSignerSuber)
        assert sdb.put(keys=signer0.verfer.qb64b, val=signer0)
        assert sdb.put(keys=signer1.verfer.qb64b, val=signer1)

        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getAllItemIter()]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                         ((signer0.verfer.qb64, ), signer0.qb64)]


        # now test with encrypter and decrypter
        encrypter0 = coring.Encrypter(verkey=cryptsigner0.verfer.qb64)
        decrypter0 = coring.Decrypter(seed=cryptsigner0.qb64b)

        # first pin with encrypter
        assert sdb.pin(keys=signer0.verfer.qb64b, val=signer0, encrypter=encrypter0)
        assert sdb.pin(keys=signer1.verfer.qb64b, val=signer1, encrypter=encrypter0)

        # now get
        actual0 = sdb.get(keys=signer0.verfer.qb64b, decrypter=decrypter0)
        assert isinstance(actual0, coring.Signer)
        assert actual0.qb64 == signer0.qb64
        assert actual0.verfer.qb64 == signer0.verfer.qb64

        actual1 = sdb.get(keys=signer1.verfer.qb64b, decrypter=decrypter0)
        assert isinstance(actual1, coring.Signer)
        assert actual1.qb64 == signer1.qb64
        assert actual1.verfer.qb64 == signer1.verfer.qb64

        # now get without decrypter
        with  pytest.raises(ValueError):
            actual0 = sdb.get(keys=signer0.verfer.qb64b)

        with  pytest.raises(ValueError):
            actual1 = sdb.get(keys=signer1.verfer.qb64b)

        # remove and test put
        sdb.rem(keys=signer0.verfer.qb64b)
        assert not  sdb.get(keys=signer0.verfer.qb64b)
        sdb.rem(keys=signer1.verfer.qb64b)
        assert not sdb.get(keys=signer1.verfer.qb64b)

        assert sdb.put(keys=signer0.verfer.qb64b, val=signer0, encrypter=encrypter0)
        assert sdb.put(keys=signer1.verfer.qb64b, val=signer1, encrypter=encrypter0)

        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getAllItemIter(decrypter=decrypter0)]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                             ((signer0.verfer.qb64, ), signer0.qb64)]

        assert sdb.put(keys=("a", signer0.verfer.qb64), val=signer0, encrypter=encrypter0)
        assert sdb.put(keys=("a", signer1.verfer.qb64), val=signer1, encrypter=encrypter0)
        assert sdb.put(keys=("ab", signer0.verfer.qb64), val=signer0, encrypter=encrypter0)
        assert sdb.put(keys=("ab", signer1.verfer.qb64), val=signer1, encrypter=encrypter0)

        topkeys = ("a", "")  # append empty str to force trailing .sep
        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getTopItemIter(keys=topkeys,
                                                            decrypter=decrypter0)]
        assert items == [(("a", signer1.verfer.qb64 ), signer1.qb64),
                          (("a", signer0.verfer.qb64 ), signer0.qb64)]


        # test re-encrypt
        encrypter1 = coring.Encrypter(verkey=cryptsigner1.verfer.qb64)
        decrypter1 = coring.Decrypter(seed=cryptsigner1.qb64b)
        for keys, sgnr in sdb.getAllItemIter(decrypter=decrypter0):
            sdb.pin(keys, sgnr, encrypter=encrypter1)

        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getAllItemIter(decrypter=decrypter1)]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                         ((signer0.verfer.qb64, ), signer0.qb64),
                         (("a", signer1.verfer.qb64, ), signer1.qb64),
                         (("a", signer0.verfer.qb64, ), signer0.qb64),
                         (("ab", signer1.verfer.qb64, ), signer1.qb64),
                         (("ab", signer0.verfer.qb64, ), signer0.qb64),
                         ]


        # now test with manager
        manager = keeping.Manager(ks=ks, seed=seed0, salt=salt, aeid=aeid0, )
        assert manager.ks.opened
        assert manager.inited
        assert manager._inits == {'aeid': 'BJruYr3oXDGRTRN0XnhiqDeoENdRak6FD8y2vsTvvJkE',
                                  'salt': '0AMDEyMzQ1Njc4OWFiY2RlZg'}
        assert manager.encrypter.qb64 == encrypter.qb64  #  aeid provided
        assert manager.decrypter.qb64 == decrypter.qb64  # aeid and seed provided
        assert manager.seed == seed0  # in memory only
        assert manager.aeid == aeid0  # on disk only
        assert manager.algo == keeping.Algos.salty
        assert manager.salt == salt  # encrypted on disk but property decrypts if seed
        assert manager.pidx == 0
        assert manager.tier == coring.Tiers.low
        saltCipher0 = coring.Cipher(qb64=manager.ks.gbls.get('salt'))
        assert saltCipher0.decrypt(seed=seed0).qb64 == salt


        manager.updateAeid(aeid=cryptsigner1.verfer.qb64, seed=cryptsigner1.qb64)
        assert manager.aeid == cryptsigner1.verfer.qb64 == 'BRw6sysb_uv81ZouXqHxQlqnAh9BYiSOsg9eQJmbZ8Uw'
        assert manager.salt == salt
        saltCipher1 = coring.Cipher(qb64=manager.ks.gbls.get('salt'))
        assert not saltCipher0.qb64 == saltCipher1.qb64  # old cipher different

    """End Test"""



if __name__ == "__main__":
    test_cat_ioset_suber()
