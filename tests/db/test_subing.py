# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""
import os

import pytest

import pysodium

from keri import help

from keri import core
from keri.core import coring, eventing, serdering, indexing, scheming

from keri.db import dbing, subing
from keri.app import keeping





def test_suber():
    """
    Test Suber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        suber = subing.Suber(db=db, subkey='bags.')
        assert isinstance(suber, subing.Suber)
        assert not suber.sdb.flags()["dupsort"]

        sue = "Hello sailer!"

        keys = ("test_key", "0001")
        suber.put(keys=keys, val=sue)
        actual = suber.get(keys=keys)
        assert actual == sue

        suber.rem(keys)
        actual = suber.get(keys=keys)
        assert actual is None

        suber.put(keys=keys, val=sue)
        actual = suber.get(keys=keys)
        assert actual == sue

        kip = "Hey gorgeous!"
        result = suber.put(keys=keys, val=kip)
        assert not result
        actual = suber.get(keys=keys)
        assert actual == sue

        result = suber.pin(keys=keys, val=kip)
        assert result
        actual = suber.get(keys=keys)
        assert actual == kip

        suber.rem(keys)
        actual = suber.get(keys=keys)
        assert actual is None

        suber.put(keys=keys, val=sue)
        actual = suber.get(keys=keys)
        assert actual == sue

        # test with keys as tuple of bytes
        keys = (b"test_key", b"0001")
        suber.rem(keys)
        actual = suber.get(keys=keys)
        assert actual is None

        suber.put(keys=keys, val=sue)
        actual = suber.get(keys=keys)
        assert actual == sue

        # test with keys as mixed tuple of bytes
        keys = (b"test_key", "0001")
        suber.rem(keys)
        actual = suber.get(keys=keys)
        assert actual is None

        suber.put(keys=keys, val=sue)
        actual = suber.get(keys=keys)
        assert actual == sue


        # test with keys as string not tuple
        keys = "keystr"

        bob = "Shove off!"

        suber.put(keys=keys, val=bob)
        actual = suber.get(keys=keys)
        assert actual == bob

        suber.rem(keys)

        actual = suber.get(keys=keys)
        assert actual is None


        liz =  "May life is insane."
        keys = ("test_key", "0002")

        suber.put(keys=keys, val=liz)
        actual = suber.get(("not_found", "0002"))
        assert actual is None

        w = "Blue dog"
        x = "Green tree"
        y = "Red apple"
        z = "White snow"

        suber = subing.Suber(db=db, subkey='pugs.')
        assert isinstance(suber, subing.Suber)

        suber.put(keys=("a","1"), val=w)
        suber.put(keys=("a","2"), val=x)
        suber.put(keys=("a","3"), val=y)
        suber.put(keys=("a","4"), val=z)

        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

        suber.put(keys=("b","1"), val=w)
        suber.put(keys=("b","2"), val=x)
        suber.put(keys=("bc","3"), val=y)
        suber.put(keys=("ac","4"), val=z)

        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == [(('a', '1'), 'Blue dog'),
                        (('a', '2'), 'Green tree'),
                        (('a', '3'), 'Red apple'),
                        (('a', '4'), 'White snow'),
                        (('ac', '4'), 'White snow'),
                        (('b', '1'), 'Blue dog'),
                        (('b', '2'), 'Green tree'),
                        (('bc', '3'), 'Red apple')]


        # test with top keys for partial tree
        topkeys = ("b","")  # last element empty to force trailing separator
        items = [(keys, val) for keys, val in suber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), w),
                         (('b', '2'), x)]

        topkeys = ("a","")  # last element empty to force trailing separator
        items = [(keys, val) for keys, val in suber.getItemIter(keys=topkeys)]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

        # test with top parameter
        keys = ("b", )  # last element empty to force trailing separator
        items = [(keys, val) for keys, val in suber.getItemIter(keys=keys, topive=True)]
        assert items == [(('b', '1'), w),
                         (('b', '2'), x)]

        keys = ("a", )  # last element empty to force trailing separator
        items = [(keys, val) for keys, val in suber.getItemIter(keys=keys, topive=True)]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

        # Test trim
        assert suber.trim(keys=("b", ""))
        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == [(('a', '1'), 'Blue dog'),
                        (('a', '2'), 'Green tree'),
                        (('a', '3'), 'Red apple'),
                        (('a', '4'), 'White snow'),
                        (('ac', '4'), 'White snow'),
                        (('bc', '3'), 'Red apple')]

        assert suber.trim(keys=("a", ""))
        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == [(('ac', '4'), 'White snow'), (('bc', '3'), 'Red apple')]

        # Test trim with top parameters
        suber.put(keys=("a","1"), val=w)
        suber.put(keys=("a","2"), val=x)
        suber.put(keys=("a","3"), val=y)
        suber.put(keys=("a","4"), val=z)
        suber.put(keys=("b","1"), val=w)
        suber.put(keys=("b","2"), val=x)

        assert suber.trim(keys=("b",), topive=True)
        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == [(('a', '1'), 'Blue dog'),
                        (('a', '2'), 'Green tree'),
                        (('a', '3'), 'Red apple'),
                        (('a', '4'), 'White snow'),
                        (('ac', '4'), 'White snow'),
                        (('bc', '3'), 'Red apple')]

        assert suber.trim(keys=("a",), topive=True)
        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == [(('ac', '4'), 'White snow'),
                         (('bc', '3'), 'Red apple')]

        assert suber.trim()
        items = [(keys, val) for keys, val in suber.getItemIter()]
        assert items == []

        assert not suber.trim()

    assert not os.path.exists(db.path)
    assert not db.opened


def test_on_suber():
    """
    Test OnSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        onsuber = subing.OnSuber(db=db, subkey='bags.')
        assert isinstance(onsuber, subing.OnSuber)
        assert not onsuber.sdb.flags()["dupsort"]

        w = "Blue dog"
        x = "Green tree"
        y = "Red apple"
        z = "White snow"

        # test append
        assert 0 == onsuber.appendOn(keys=("a",), val=w)
        assert 1 == onsuber.appendOn(keys=("a",), val=x)
        assert 2 == onsuber.appendOn(keys=("a",), val=y)
        assert 3 == onsuber.appendOn(keys=("a",), val=z)

        assert onsuber.cntOnAll(keys=("a",)) == 4
        assert onsuber.cntOnAll(keys=("a",), on=2) == 2
        assert onsuber.cntOnAll(keys=("a",), on=4) == 0
        assert onsuber.cntOnAll() == 4
        assert onsuber.cntOn() == 0
        assert onsuber.cntOn(keys='a') == 4
        assert onsuber.cntOn(keys=("a",), on=2) == 2
        assert onsuber.cntOn(keys=("a",), on=4) == 0

        items = [(keys, val) for keys, val in onsuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), 'Blue dog'),
                        (('a', '00000000000000000000000000000001'), 'Green tree'),
                        (('a', '00000000000000000000000000000002'), 'Red apple'),
                        (('a', '00000000000000000000000000000003'), 'White snow')]

        items = [(keys, on, val) for keys, on, val in onsuber.getOnTopItemIter()]
        assert items == [
                            (('a',), 0, 'Blue dog'),
                            (('a',), 1, 'Green tree'),
                            (('a',), 2, 'Red apple'),
                            (('a',), 3, 'White snow')
                        ]

        # test getOnAllItemIter
        items = [item for item in onsuber.getOnAllItemIter()]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow')]

        items = [item for item in onsuber.getOnAllItemIter(keys='a')]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow')]

        items = [item for item in onsuber.getOnAllItemIter(keys='a', on=2)]
        assert items == [(('a',), 2, 'Red apple'),
                         (('a',), 3, 'White snow')]

        # test getOnIterAll
        vals = [val for val in onsuber.getOnIterAll()]
        assert vals == ['Blue dog',
                        'Green tree',
                        'Red apple',
                        'White snow']

        vals = [val for val in onsuber.getOnIterAll(keys='a')]
        assert vals == ['Blue dog',
                        'Green tree',
                        'Red apple',
                        'White snow']

        vals = [val for val in onsuber.getOnIterAll(keys='a', on=2)]
        assert vals == ['Red apple',
                        'White snow']


        assert 0 == onsuber.appendOn(keys=("b",), val=w)
        assert 1 == onsuber.appendOn(keys=("b",), val=x)
        assert 0 == onsuber.appendOn(keys=("bc",), val=y)
        assert 0 == onsuber.appendOn(keys=("ac",), val=z)

        assert onsuber.cntOnAll(keys=("b",)) == 2
        assert onsuber.cntOnAll(keys=("ac",), on=2) == 0
        assert onsuber.cntOnAll(keys="") == 8

        items = [(keys, val) for keys, val in onsuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), 'Blue dog'),
                        (('a', '00000000000000000000000000000001'), 'Green tree'),
                        (('a', '00000000000000000000000000000002'), 'Red apple'),
                        (('a', '00000000000000000000000000000003'), 'White snow'),
                        (('ac', '00000000000000000000000000000000'), 'White snow'),
                        (('b', '00000000000000000000000000000000'), 'Blue dog'),
                        (('b', '00000000000000000000000000000001'), 'Green tree'),
                        (('bc', '00000000000000000000000000000000'), 'Red apple')]

        #assert onsuber.getOnItemIter == onsuber.getOnTopItemIter

        items = [(keys, on, val) for keys, on, val in onsuber.getOnTopItemIter()]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow'),
                        (('ac',), 0, 'White snow'),
                        (('b',), 0, 'Blue dog'),
                        (('b',), 1, 'Green tree'),
                        (('bc',), 0, 'Red apple')]


        items = [(keys, on, val) for keys, on, val in onsuber.getOnTopItemIter(keys="b")]  # top
        assert items == [(('b',), 0, 'Blue dog'),
                         (('b',), 1, 'Green tree'),
                         (('bc',), 0, 'Red apple')]

        # test getOnAllItemIter
        items = [item for item in onsuber.getOnAllItemIter(keys='b')]
        assert items == [(('b',), 0, 'Blue dog'),
                         (('b',), 1, 'Green tree')]

        items = [item for item in onsuber.getOnAllItemIter(keys=('b', ))]
        assert items == [(('b',), 0, 'Blue dog'),
                         (('b',), 1, 'Green tree')]

        items = [item for item in onsuber.getOnAllItemIter(keys=('b', ""))]
        assert items == []

        items = [item for item in onsuber.getOnAllItemIter(keys='')]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow'),
                        (('ac',), 0, 'White snow'),
                        (('b',), 0, 'Blue dog'),
                        (('b',), 1, 'Green tree'),
                        (('bc',), 0, 'Red apple')]

        items = [item for item in onsuber.getOnAllItemIter()]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow'),
                        (('ac',), 0, 'White snow'),
                        (('b',), 0, 'Blue dog'),
                        (('b',), 1, 'Green tree'),
                        (('bc',), 0, 'Red apple')]

        assert onsuber.remOn(keys='a', on=1)
        assert not onsuber.remOn(keys='a', on=1)
        assert onsuber.remOn(keys='a', on=3)
        assert not onsuber.remOn(keys='a', on=3)

        assert onsuber.cntOnAll(keys=("a",)) == 2
        assert onsuber.cntOnAll() == 6
        assert onsuber.cntOn() == 0
        assert onsuber.cntOn(keys='a') == 2
        assert onsuber.cntOn(keys=("a",), on=2) == 1
        assert onsuber.cntOn(keys=("a",), on=4) == 0

        items = [item for item in onsuber.getOnAllItemIter(keys='a')]
        assert items == [(('a',), 0, 'Blue dog'),
                         (('a',), 2, 'Red apple')]

        # test putOn and pinOn and getOn getOnItem
        assert onsuber.putOn(keys='d', on=0, val='moon')
        assert onsuber.getOn(keys='d', on=0) == 'moon'
        assert onsuber.getOnItem(keys='d', on=0) == (("d", ), 0, "moon")
        assert not onsuber.putOn(keys='d', on=0, val='moon')
        assert onsuber.pinOn(keys='d', on=0, val='sun')
        assert onsuber.getOn(keys='d', on=0) == 'sun'
        assert onsuber.getOnItem(keys='d', on=0) == (("d", ), 0, "sun")
        assert onsuber.remOn(keys='d', on=0)
        assert onsuber.getOn(keys='d', on=0) == None
        assert onsuber.getOnItem(keys='d', on=0) == None

        # test remOnAll
        assert onsuber.putOn(keys='d', on=0, val='moon')
        assert onsuber.putOn(keys='d', on=1, val='sun')
        assert onsuber.putOn(keys='d', on=2, val='stars')
        assert onsuber.putOn(keys='e', on=0, val='stars')
        assert onsuber.putOn(keys='e', on=1, val='moon')
        assert onsuber.putOn(keys='e', on=2, val='sun')

        assert onsuber.cntOnAll(keys='d') == 3
        assert onsuber.cntOnAll(keys='e') == 3
        assert onsuber.cntOnAll() == 12

        assert onsuber.remOnAll(keys='d', on=1)
        assert onsuber.cntOnAll(keys='d') == 1
        assert onsuber.cntOnAll(keys='e') == 3
        assert onsuber.cntOnAll() == 10

        assert onsuber.remOnAll(keys='d')
        assert onsuber.cntOnAll(keys='d') == 0
        assert onsuber.cntOnAll(keys='e') == 3
        assert onsuber.cntOnAll() == 9

        assert onsuber.remOnAll()
        assert onsuber.cntOnAll(keys='d') == 0
        assert onsuber.cntOnAll(keys='e') == 0
        assert onsuber.cntOnAll() == 0


    assert not os.path.exists(db.path)
    assert not db.opened


def test_b64_suber():
    """
    Test B64Suber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        # Test Single klas
        buber = subing.B64Suber(db=db, subkey='bags.')  # default klas is [Matter]
        assert isinstance(buber, subing.B64Suber)
        assert not buber.sdb.flags()["dupsort"]

        vals0 = ("alpha", "beta")
        vals1 = ("gamma", )

        keys0 = ("cat", "dog")
        assert buber.put(keys=keys0, val=vals0)
        actuals = buber.get(keys=keys0)
        assert actuals == vals0

        assert buber.rem(keys0)
        assert not buber.get(keys=keys0)

        assert buber.put(keys=keys0, val=vals0)
        actuals = buber.get(keys=keys0)
        assert actuals == vals0

        assert not buber.put(keys=keys0, val=vals1)

        assert buber.pin(keys=keys0, val=vals1)
        actuals = buber.get(keys=keys0)
        assert actuals == vals1

        assert buber.rem(keys0)
        assert not buber.get(keys=keys0)

        # test with vals as non Iterable or put but Iterable on get
        assert buber.put(keys=keys0, val="gamma")
        actuals = buber.get(keys=keys0)
        assert actuals == vals1

        assert buber.rem(keys0)

        # test val as already joined string
        with pytest.raises(ValueError):
            assert buber.put(keys=keys0, val="alpha.beta")

        # test bytes for val
        assert buber.put(keys=keys0, val=(b"alpha", b"beta"))
        actuals = buber.get(keys=keys0)
        assert actuals == vals0
        assert buber.rem(keys0)

        # test with keys as string not tuple
        keys1 = "{}.{}".format("bird", "fish")

        assert buber.put(keys=keys1, val=vals1)
        actuals = buber.get(keys=keys1)
        assert actuals == vals1

        assert buber.rem(keys1)
        assert not buber.get(keys=keys1)

        # test missing entry at keys
        badkey = "badkey"
        assert not buber.get(badkey)

        # test iteritems
        assert buber.put(keys0, vals0)
        assert buber.put(keys1, vals1)

        items = [ items for items in buber.getItemIter()]
        assert items == [(('bird', 'fish'), ('gamma',)), (('cat', 'dog'), ('alpha', 'beta'))]

        buber.put(keys=("b","1"), val=vals0)
        buber.put(keys=("b","2"), val=vals1)
        buber.put(keys=("c","1"), val=vals0)
        buber.put(keys=("c","2"), val=vals1)

        topkeys = ("b","")  # last element empty to force trailing separator
        items = [items for items in  buber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), ('alpha', 'beta')),
                         (('b', '2'), ('gamma',))]

    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""


def test_dup_suber():
    """
    Test DubSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        dupber = subing.DupSuber(db=db, subkey='bags.')
        assert isinstance(dupber, subing.DupSuber)
        assert dupber.sdb.flags()["dupsort"]

        sue = "Hello sailer!"
        sal = "Not my type."

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")
        dupber.put(keys=keys0, vals=[sue, sal])
        actual = dupber.get(keys=keys0)
        assert actual == [sue, sal]  # lexicographic order
        assert dupber.cnt(keys0) == 2

        dupber.rem(keys0)
        actual = dupber.get(keys=keys0)
        assert not actual
        assert actual == []
        assert dupber.cnt(keys0) == 0

        dupber.put(keys=keys0, vals=[sal, sue])
        actual = dupber.get(keys=keys0)
        assert actual == [sue, sal]  # lexicographic order
        actual = dupber.getLast(keys=keys0)
        assert actual == sal

        sam = "A real charmer!"
        result = dupber.add(keys=keys0, val=sam)
        assert result
        actual = dupber.get(keys=keys0)
        assert actual == [sam, sue, sal]   # lexicographic order

        zoe = "See ya later."
        zia = "Hey gorgeous!"

        result = dupber.pin(keys=keys0, vals=[zoe, zia])
        assert result
        actual = dupber.get(keys=keys0)
        assert actual == [zia, zoe]  # lexi order

        dupber.put(keys=keys1, vals=[sal, sue, sam])
        actual = dupber.get(keys=keys1)
        assert actual == [sam, sue, sal]  # lexicographic order

        for i, val in enumerate(dupber.getIter(keys=keys1)):
            assert val == actual[i]

        items = [(keys, val) for keys, val in dupber.getItemIter()]
        assert items == [(('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0002'), 'A real charmer!'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'Not my type.')]


        assert dupber.put(keys=("test", "blue"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in dupber.getItemIter(keys=topkeys)]
        assert items == [(('test', 'blue'), 'A real charmer!'),
                         (('test', 'blue'), 'Hello sailer!'),
                         (('test', 'blue'), 'Not my type.')]

        # test with keys as string not tuple
        keys2 = "keystr"
        bob = "Shove off!"
        dupber.put(keys=keys2, vals=[bob])
        actual = dupber.get(keys=keys2)
        assert actual == [bob]
        assert dupber.cnt(keys2) == 1
        dupber.rem(keys2)
        actual = dupber.get(keys=keys2)
        assert actual == []
        assert dupber.cnt(keys2) == 0

        dupber.put(keys=keys2, vals=[bob])
        actual = dupber.get(keys=keys2)
        assert actual == [bob]

        bil = "Go away."
        dupber.pin(keys=keys2, vals=[bil])
        actual = dupber.get(keys=keys2)
        assert actual == [bil]

        dupber.add(keys=keys2, val=bob)
        actual = dupber.get(keys=keys2)
        assert actual == [bil, bob]


        # test cntpre
        vals = ["hi", "me", "my"]
        for i, val in enumerate(vals):
            assert dupber.put(keys=dbing.onKey("bob", i), vals=val)

        vals = ["bye", "guy", "gal"]
        for i, val in enumerate(vals):
            assert dupber.put(keys=dbing.onKey("bob", i), vals=val)

        items = [(keys, val) for keys, val in dupber.getItemIter(keys="bob")]
        assert items == [
            (('bob', '00000000000000000000000000000000'), 'bye'),
            (('bob', '00000000000000000000000000000000'), 'hi'),
            (('bob', '00000000000000000000000000000001'), 'guy'),
            (('bob', '00000000000000000000000000000001'), 'me'),
            (('bob', '00000000000000000000000000000002'), 'gal'),
            (('bob', '00000000000000000000000000000002'), 'my')
        ]

        assert dupber.cnt(keys=dbing.onKey("bob", 1)) == 2

        vals = [val for val in dupber.getIter(keys=dbing.onKey("bob", 2))]
        assert vals == ["gal", "my"]


    assert not os.path.exists(db.path)
    assert not db.opened


def test_iodup_suber():
    """
    Test IoDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        ioduber = subing.IoDupSuber(db=db, subkey='bags.')
        assert isinstance(ioduber, subing.IoDupSuber)
        assert ioduber.sdb.flags()["dupsort"]

        sue = "Hello sailer!"
        sal = "Not my type."

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")

        sue = "Hello sailer!"
        sal = "Not my type."

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")

        assert ioduber.put(keys=keys0, vals=[sal, sue])
        actuals = ioduber.get(keys=keys0)
        assert actuals == [sal, sue]  # insertion order not lexicographic
        assert ioduber.cnt(keys0) == 2
        assert ioduber.cnt() == 2  # cntAll
        actual = ioduber.getLast(keys=keys0)
        assert actual == sue

        assert ioduber.cnt(keys=keys0) == 2

        assert ioduber.rem(keys0)
        actuals = ioduber.get(keys=keys0)
        assert not actuals
        assert actuals == []
        assert ioduber.cnt(keys0) == 0

        assert ioduber.put(keys=keys0, vals=[sue, sal])
        actuals = ioduber.get(keys=keys0)
        assert actuals == [sue, sal]  # insertion order
        actual = ioduber.getLast(keys=keys0)
        assert actual == sal

        sam = "A real charmer!"
        result = ioduber.add(keys=keys0, val=sam)
        assert result
        actuals = ioduber.get(keys=keys0)
        assert actuals == [sue, sal, sam]   # insertion order

        zoe = "See ya later."
        zia = "Hey gorgeous!"

        result = ioduber.pin(keys=keys0, vals=[zoe, zia])
        assert result
        actuals = ioduber.get(keys=keys0)
        assert actuals == [zoe, zia]  # insertion order

        assert ioduber.put(keys=keys1, vals=[sal, sue, sam])
        actuals = ioduber.get(keys=keys1)
        assert actuals == [sal, sue, sam]

        for i, val in enumerate(ioduber.getIter(keys=keys1)):
            assert val == actuals[i]

        items = [(keys, val) for keys, val in ioduber.getItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'A real charmer!')]

        items = list(ioduber.getFullItemIter())
        assert items ==  [(('test_key', '0001'), '00000000000000000000000000000000.See ya later.'),
                        (('test_key', '0001'), '00000000000000000000000000000001.Hey gorgeous!'),
                        (('test_key', '0002'), '00000000000000000000000000000000.Not my type.'),
                        (('test_key', '0002'), '00000000000000000000000000000001.Hello sailer!'),
                        (('test_key', '0002'), '00000000000000000000000000000002.A real charmer!')]

        items = [(keys, val) for keys,  val in ioduber.getItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), 'Not my type.'),
                         (('test_key', '0002'), 'Hello sailer!'),
                         (('test_key', '0002'), 'A real charmer!')]

        items = [(keys, val) for keys,  val in  ioduber.getItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                         (('test_key', '0001'), 'Hey gorgeous!')]




        # Test with top keys
        assert ioduber.put(keys=("test", "pop"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in ioduber.getItemIter(keys=topkeys)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        # test with top parameter
        keys = ("test", )
        items = [(keys, val) for keys, val in ioduber.getItemIter(keys=keys, topive=True)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        # IoItems
        items = list(ioduber.getFullItemIter(keys=topkeys))
        assert items == [(('test', 'pop'), '00000000000000000000000000000000.Not my type.'),
                         (('test', 'pop'), '00000000000000000000000000000001.Hello sailer!'),
                         (('test', 'pop'), '00000000000000000000000000000002.A real charmer!')]

        # test remove with a specific val
        assert ioduber.rem(keys=("test_key", "0002"), val=sue)
        items = [(keys, val) for keys, val in ioduber.getItemIter()]
        assert items == [(('test', 'pop'), 'Not my type.'),
                        (('test', 'pop'), 'Hello sailer!'),
                        (('test', 'pop'), 'A real charmer!'),
                        (('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'A real charmer!')]

        assert ioduber.trim(keys=("test", ""))
        items = [(keys, val) for keys, val in ioduber.getItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'A real charmer!')]

        assert ioduber.cnt(keys=keys0) == 2
        assert ioduber.cnt(keys=keys1) == 2

        # test with keys as string not tuple
        keys2 = "keystr"
        bob = "Shove off!"
        assert ioduber.put(keys=keys2, vals=[bob])
        actuals = ioduber.get(keys=keys2)
        assert actuals == [bob]
        assert ioduber.cnt(keys2) == 1
        assert ioduber.rem(keys2)
        actuals = ioduber.get(keys=keys2)
        assert actuals == []
        assert ioduber.cnt(keys2) == 0

        assert ioduber.put(keys=keys2, vals=[bob])
        actuals = ioduber.get(keys=keys2)
        assert actuals == [bob]

        bil = "Go away."
        assert ioduber.pin(keys=keys2, vals=[bil])
        actuals = ioduber.get(keys=keys2)
        assert actuals == [bil]

        assert ioduber.add(keys=keys2, val=bob)
        actuals = ioduber.get(keys=keys2)
        assert actuals == [bil, bob]

        # Test trim
        assert ioduber.trim()  # default trims whole database
        assert ioduber.put(keys=keys1, vals=[bob, bil])
        assert ioduber.get(keys=keys1) == [bob, bil]


    assert not os.path.exists(db.path)
    assert not db.opened


def test_b64_iodup_suber():
    """
    Test B64IoDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        # Test Single klas
        iobuber = subing.B64IoDupSuber(db=db, subkey='bags.')
        assert isinstance(iobuber, subing.B64IoDupSuber)
        assert iobuber.sdb.flags()["dupsort"]
        assert iobuber.sep == '.'
        assert not help.Reb64.match(iobuber.sep.encode())

        # val as joined iterator
        vals0 = ("alpha", "beta")
        vals1 = ("gamma", )

        keys0 = ("cat", "dog")  # keys as tuple
        keys1 = "{}.{}".format("bird", "fish")  # keys as string not tuple


        assert iobuber.put(keys=keys0, vals=(vals0,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0]

        assert iobuber.rem(keys0)
        assert not iobuber.get(keys=keys0)

        assert iobuber.put(keys=keys0, vals=(vals0,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0]

        assert iobuber.put(keys=keys0, vals=(vals1,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0, vals1]

        assert iobuber.pin(keys=keys0, vals=(vals1,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals1]

        assert iobuber.rem(keys0)
        assert not iobuber.get(keys=keys0)

        # test with vals as non Iterable on put but Iterable on get
        assert iobuber.put(keys=keys0, vals=["gamma"])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals1]

        assert iobuber.rem(keys0)

        # test val as already joined string since has non Base64
        with pytest.raises(ValueError):
            assert iobuber.put(keys=keys0, vals=["alpha.beta"])

        # test bytes for val
        assert iobuber.put(keys=keys0, vals=[(b"alpha", b"beta")])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0]
        assert iobuber.rem(keys0)

        # test with keys1
        assert iobuber.put(keys=keys1, vals=[vals1])
        actuals = iobuber.get(keys=keys1)
        assert actuals == [vals1]

        assert iobuber.rem(keys1)
        assert not iobuber.get(keys=keys1)

        # test missing entry at keys
        badkey = "badkey"
        assert not iobuber.get(badkey)

        # test iteritems
        assert iobuber.put(keys0, [vals0])
        assert iobuber.put(keys1, [vals1])

        items = [ items for items in iobuber.getItemIter()]
        assert items == [(('bird', 'fish'), ('gamma',)), (('cat', 'dog'), ('alpha', 'beta'))]

        keys3 = ("b","1")
        keys4 = ("b","2")
        keys5 = ("c","1")
        keys6 = ("c","2")

        iobuber.put(keys=keys3, vals=[vals0])
        iobuber.put(keys=keys4, vals=[vals1])
        iobuber.put(keys=keys5, vals=[vals0])
        iobuber.put(keys=keys6, vals=[vals1])

        topkeys = ("b","")  # last element empty to force trailing separator
        items = [items for items in  iobuber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), ('alpha', 'beta')),
                         (('b', '2'), ('gamma',))]

        assert iobuber.rem(keys0)
        assert iobuber.rem(keys1)
        assert iobuber.rem(keys3)
        assert iobuber.rem(keys4)
        assert iobuber.rem(keys5)
        assert iobuber.rem(keys6)


        # iodup testing
        # singular values B64
        sue = "Hello"
        sal = "Toodles"
        sam = "Bye"

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")

        assert iobuber.put(keys=keys0, vals=[sal, sue])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [(sal,), (sue,)]  # insertion order not lexicographic
        assert iobuber.cnt(keys0) == 2
        actual = iobuber.getLast(keys=keys0)
        assert actual == (sue,)

        assert iobuber.rem(keys0)
        actuals = iobuber.get(keys=keys0)
        assert not actuals
        assert actuals == []
        assert iobuber.cnt(keys0) == 0

        assert iobuber.put(keys=keys0, vals=[sue, sal])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [(sue,), (sal, )]  # insertion order
        actual = iobuber.getLast(keys=keys0)
        assert actual == (sal,)


        assert iobuber.add(keys=keys0, val=sam)
        actuals = iobuber.get(keys=keys0)
        assert actuals == [(sue,), (sal,), (sam,)]   # insertion order


        sue = ("Hello",)
        sal = ("Toodles",)
        sam = ("Bye",)
        zoe = ('later', 'alligator')
        zia = ('soon', 'baboon')

        assert iobuber.pin(keys=keys0, vals=[zoe, zia])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [zoe, zia]  # insertion order

        assert iobuber.put(keys=keys1, vals=[sal, sue, sam])
        actuals = iobuber.get(keys=keys1)
        assert actuals == [sal, sue, sam]

        for i, val in enumerate(iobuber.getIter(keys=keys1)):
            assert val == actuals[i]

        items = [(keys, val) for keys, val in iobuber.getItemIter()]
        assert items == [(('test_key', '0001'), ('later', 'alligator')),
                         (('test_key', '0001'), ('soon', 'baboon')),
                         (('test_key', '0002'), ('Toodles',)),
                         (('test_key', '0002'), ('Hello',)),
                         (('test_key', '0002'), ('Bye',))]

        items = list(iobuber.getFullItemIter())
        assert items ==  [
            (('test_key', '0001'), ('00000000000000000000000000000000', 'later', 'alligator')),
            (('test_key', '0001'), ('00000000000000000000000000000001', 'soon', 'baboon')),
            (('test_key', '0002'), ('00000000000000000000000000000000', 'Toodles')),
            (('test_key', '0002'), ('00000000000000000000000000000001', 'Hello')),
            (('test_key', '0002'), ('00000000000000000000000000000002', 'Bye'))
        ]

        items = [(keys, val) for keys,  val in iobuber.getItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), ('Toodles',)),
                         (('test_key', '0002'), ('Hello',)),
                         (('test_key', '0002'), ('Bye',))]

        items = [(keys, val) for keys,  val in  iobuber.getItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), ('later', 'alligator')),
                         (('test_key', '0001'), ('soon', 'baboon'))]

        # Test with top keys
        assert iobuber.put(keys=("test", "pop"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in iobuber.getItemIter(keys=topkeys)]
        assert items == [(('test', 'pop'), ('Toodles',)),
                         (('test', 'pop'), ('Hello',)),
                         (('test', 'pop'), ('Bye',))]

        # test with top parameter
        keys = ("test", )
        items = [(keys, val) for keys, val in iobuber.getItemIter(keys=keys, topive=True)]
        assert items == [(('test', 'pop'), ('Toodles',)),
                         (('test', 'pop'), ('Hello',)),
                         (('test', 'pop'), ('Bye',))]

        # IoItems
        items = list(iobuber.getFullItemIter(keys=topkeys))
        assert items == [(('test', 'pop'), ('00000000000000000000000000000000', 'Toodles')),
                         (('test', 'pop'), ('00000000000000000000000000000001', 'Hello')),
                         (('test', 'pop'), ('00000000000000000000000000000002', 'Bye'))]

        # test remove with a specific val
        assert iobuber.rem(keys=("test_key", "0002"), val=sue)
        items = [(keys, val) for keys, val in iobuber.getItemIter()]
        assert items ==[(('test', 'pop'), ('Toodles',)),
                        (('test', 'pop'), ('Hello',)),
                        (('test', 'pop'), ('Bye',)),
                        (('test_key', '0001'), ('later', 'alligator')),
                        (('test_key', '0001'), ('soon', 'baboon')),
                        (('test_key', '0002'), ('Toodles',)),
                        (('test_key', '0002'), ('Bye',))]


        assert iobuber.trim(keys=("test", ""))
        items = [(keys, val) for keys, val in iobuber.getItemIter()]
        assert items == [(('test_key', '0001'), ('later', 'alligator')),
                         (('test_key', '0001'), ('soon', 'baboon')),
                         (('test_key', '0002'), ('Toodles',)),
                         (('test_key', '0002'), ('Bye',))]


        assert iobuber.cnt(keys=keys0) == 2
        assert iobuber.cnt(keys=keys1) == 2

        # test with keys as string not tuple
        keys2 = "keystr"
        bob = ("go", "figure")
        assert iobuber.put(keys=keys2, vals=[bob])
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bob]
        assert iobuber.cnt(keys2) == 1
        assert iobuber.rem(keys2)
        actuals = iobuber.get(keys=keys2)
        assert actuals == []
        assert iobuber.cnt(keys2) == 0

        assert iobuber.put(keys=keys2, vals=[bob])
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bob]

        bil = ("Go", "away")
        assert iobuber.pin(keys=keys2, vals=[bil])
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bil]

        assert iobuber.add(keys=keys2, val=bob)
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bil, bob]

        # Test trim
        assert iobuber.trim()  # default trims whole database
        assert iobuber.put(keys=keys1, vals=[bob, bil])
        assert iobuber.get(keys=keys1) == [bob, bil]


    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""


def test_on_iodup_suber():
    """
    Test OnIoDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        oidsuber = subing.OnIoDupSuber(db=db, subkey='bags.')
        assert isinstance(oidsuber, subing.OnIoDupSuber)
        assert oidsuber.sdb.flags()["dupsort"]

        w = "Blue dog"
        x = "Green tree"
        y = "Red apple"
        z = "White snow"

        # test addOn remOn
        assert oidsuber.addOn(keys="z", on=0, val=w)
        assert oidsuber.getOn(keys="z", on=0) == [w, ]
        assert oidsuber.addOn(keys="z", on=0, val=x)
        assert oidsuber.getOn(keys="z", on=0) == [w, x]
        assert oidsuber.addOn(keys="z", on=1, val=y)
        assert oidsuber.getOn(keys="z", on=1) == [y, ]
        assert oidsuber.addOn(keys="z", on=1, val=z)
        assert oidsuber.getOn(keys="z", on=1) == [y, z]

        assert oidsuber.getOn(keys="z", on=0) == [w, x]  # only get for on=0

        assert oidsuber.cntOn(keys="z", on=0) == 2
        assert oidsuber.cntOn(keys="z", on=1) == 2
        assert oidsuber.getOnLast(keys="z", on=0) == x
        assert oidsuber.getOnLast(keys="z", on=1) == z

        assert [val for val in oidsuber.getOnIter(keys="z", on=0)] == [w, x]
        assert [val for val in oidsuber.getOnIter(keys="z", on=1)] == [y, z]

        assert oidsuber.cntOnAll(keys=("z",)) == 4
        assert oidsuber.cntOnAll() == 4

        items = [item for item in oidsuber.getOnItemIterAll(keys='z')]
        assert items == [(('z',), 0, 'Blue dog'),
                        (('z',), 0, 'Green tree'),
                        (('z',), 1, 'Red apple'),
                        (('z',), 1, 'White snow')]

        assert oidsuber.remOn(keys='z', on=0, val=w)
        assert oidsuber.remOn(keys='z', on=1)
        items = [item for item in oidsuber.getOnItemIterAll(keys='z')]
        assert items == [(('z',), 0, 'Green tree')]
        assert oidsuber.remOn(keys='z', on=0, val=x)

        assert oidsuber.cntOnAll(keys=("z",)) == 0


        # test append
        assert 0 == oidsuber.appendOn(keys=("a",), val=w)
        assert 1 == oidsuber.appendOn(keys=("a",), val=x)
        assert 2 == oidsuber.appendOn(keys=("a",), val=y)
        assert 3 == oidsuber.appendOn(keys=("a",), val=z)

        assert oidsuber.cntOnAll(keys=("a",)) == 4
        assert oidsuber.cntOnAll(keys=("a",), on=2) == 2
        assert oidsuber.cntOnAll(keys=("a",), on=4) == 0
        assert oidsuber.cntOnAll() == 4

        items = [(keys, val) for keys, val in oidsuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), 'Blue dog'),
                        (('a', '00000000000000000000000000000001'), 'Green tree'),
                        (('a', '00000000000000000000000000000002'), 'Red apple'),
                        (('a', '00000000000000000000000000000003'), 'White snow')]


        # test getOnIterAll
        vals = [val for val in oidsuber.getOnIterAll(keys='a')]
        assert vals == ['Blue dog',
                        'Green tree',
                        'Red apple',
                        'White snow']

        vals = [val for val in oidsuber.getOnIterAll(keys='a', on=2)]
        assert vals == ['Red apple',
                        'White snow']

        # test getOnItemIterAll
        items = [item for item in oidsuber.getOnItemIterAll(keys='a')]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow')]

        items = [item for item in oidsuber.getOnItemIterAll(keys='a', on=2)]
        assert items == [(('a',), 2, 'Red apple'),
                         (('a',), 3, 'White snow')]

        # test add duplicates
        assert oidsuber.add(keys=dbing.onKey("b", 0), val=w)
        assert oidsuber.add(keys=dbing.onKey("b", 1), val=x)
        assert oidsuber.add(keys=dbing.onKey("bc", 0), val=y)
        assert oidsuber.add(keys=dbing.onKey("ac", 0), val=z)

        assert oidsuber.cntOnAll(keys=("b",)) == 2
        assert oidsuber.cntOnAll(keys=("ac",), on=2) == 0
        assert oidsuber.cntOnAll(keys="") == 8

        items = [(keys, val) for keys, val in oidsuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), 'Blue dog'),
                        (('a', '00000000000000000000000000000001'), 'Green tree'),
                        (('a', '00000000000000000000000000000002'), 'Red apple'),
                        (('a', '00000000000000000000000000000003'), 'White snow'),
                        (('ac', '00000000000000000000000000000000'), 'White snow'),
                        (('b', '00000000000000000000000000000000'), 'Blue dog'),
                        (('b', '00000000000000000000000000000001'), 'Green tree'),
                        (('bc', '00000000000000000000000000000000'), 'Red apple')]


        # test getOnItemIterAll   getOnIterAll
        items = [item for item in oidsuber.getOnItemIterAll(keys='b')]
        assert items == [(('b',), 0, 'Blue dog'),
                         (('b',), 1, 'Green tree')]

        vals = [val for val in oidsuber.getOnIterAll(keys='b')]
        assert vals == ['Blue dog', 'Green tree']

        vals = [val for val in oidsuber.getOnIterAll(keys=('b', ))]
        assert vals == ['Blue dog', 'Green tree']

        items = [item for item in oidsuber.getOnItemIterAll(keys=('b', ))]
        assert items == [(('b',), 0, 'Blue dog'),
                         (('b',), 1, 'Green tree')]

        items = [item for item in oidsuber.getOnItemIterAll(keys=('b', ""))]
        assert items == []

        vals = [val for val in oidsuber.getOnIterAll(keys=('b', ""))]
        assert vals == []

        items = [item for item in oidsuber.getOnItemIterAll(keys='')]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow'),
                        (('ac',), 0, 'White snow'),
                        (('b',), 0, 'Blue dog'),
                        (('b',), 1, 'Green tree'),
                        (('bc',), 0, 'Red apple')]

        vals = [val for val in oidsuber.getOnIterAll(keys='')]
        assert vals == ['Blue dog',
                        'Green tree',
                        'Red apple',
                        'White snow',
                        'White snow',
                        'Blue dog',
                        'Green tree',
                        'Red apple']

        items = [item for item in oidsuber.getOnItemIterAll()]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 3, 'White snow'),
                        (('ac',), 0, 'White snow'),
                        (('b',), 0, 'Blue dog'),
                        (('b',), 1, 'Green tree'),
                        (('bc',), 0, 'Red apple')]

        vals = [val for val in oidsuber.getOnIterAll()]
        assert vals == ['Blue dog',
                        'Green tree',
                        'Red apple',
                        'White snow',
                        'White snow',
                        'Blue dog',
                        'Green tree',
                        'Red apple']

        # test with duplicates
        assert oidsuber.add(keys=dbing.onKey("a", 0), val=z)
        assert oidsuber.add(keys=dbing.onKey("a", 1), val=y)
        assert oidsuber.add(keys=dbing.onKey("a", 2), val=x)
        assert oidsuber.add(keys=dbing.onKey("a", 3), val=w)

        assert oidsuber.cntOnAll(keys=("a",)) == 8
        assert oidsuber.cntOnAll(keys=("a",), on=2) == 4
        assert oidsuber.cntOnAll(keys=("a",), on=4) == 0

        items = [(keys, val) for keys, val in oidsuber.getItemIter(keys=("a", ""))]
        assert items == [(('a', '00000000000000000000000000000000'), 'Blue dog'),
                        (('a', '00000000000000000000000000000000'), 'White snow'),
                        (('a', '00000000000000000000000000000001'), 'Green tree'),
                        (('a', '00000000000000000000000000000001'), 'Red apple'),
                        (('a', '00000000000000000000000000000002'), 'Red apple'),
                        (('a', '00000000000000000000000000000002'), 'Green tree'),
                        (('a', '00000000000000000000000000000003'), 'White snow'),
                        (('a', '00000000000000000000000000000003'), 'Blue dog')]

        # test getOnItemIterAll getOnIterAll getOnItemBackIter getOnBackIter
        items = [item for item in oidsuber.getOnItemIterAll(keys='a')]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 0, 'White snow'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 1, 'Red apple'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 2, 'Green tree'),
                        (('a',), 3, 'White snow'),
                        (('a',), 3, 'Blue dog')]

        vals = [val for val in oidsuber.getOnIterAll(keys='a')]
        assert vals == ['Blue dog',
                        'White snow',
                        'Green tree',
                        'Red apple',
                        'Red apple',
                        'Green tree',
                        'White snow',
                        'Blue dog',
                        ]


        items = [item for item in oidsuber.getOnItemBackIter(keys='a', on=4)]
        assert items == [(('a',), 3, 'Blue dog'),
                        (('a',), 3, 'White snow'),
                        (('a',), 2, 'Green tree'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 1, 'Red apple'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 0, 'White snow'),
                        (('a',), 0, 'Blue dog')]


        vals = [val for val in oidsuber.getOnBackIter(keys='a', on=4)]
        assert vals == ['Blue dog',
                        'White snow',
                        'Green tree',
                        'Red apple',
                        'Red apple',
                        'Green tree',
                        'White snow',
                        'Blue dog']

        items = [item for item in oidsuber.getOnItemIterAll(keys='a', on=2)]
        assert items ==[(('a',), 2, 'Red apple'),
                        (('a',), 2, 'Green tree'),
                        (('a',), 3, 'White snow'),
                        (('a',), 3, 'Blue dog')]

        vals = [val for val in oidsuber.getOnIterAll(keys='a', on=2)]
        assert vals == [
                        'Red apple',
                        'Green tree',
                        'White snow',
                        'Blue dog',
                        ]

        items = [item for item in oidsuber.getOnItemBackIter(keys='a', on=1)]
        assert items ==[(('a',), 1, 'Red apple'),
                        (('a',), 1, 'Green tree'),
                        (('a',), 0, 'White snow'),
                        (('a',), 0, 'Blue dog')]


        vals = [val for val in oidsuber.getOnBackIter(keys='a', on=1)]
        assert vals == ['Red apple',
                        'Green tree',
                        'White snow',
                        'Blue dog']

        # test append with duplicates
        assert 4 == oidsuber.appendOn(keys=("a",), val=x)
        assert oidsuber.cntOnAll(keys=("a",)) == 9

        # test remove
        assert oidsuber.remOn(keys='a', on=1)
        assert not oidsuber.remOn(keys='a', on=1)
        assert oidsuber.remOn(keys='a', on=3)
        assert not oidsuber.remOn(keys='a', on=3)

        assert oidsuber.cntOnAll(keys=("a",)) == 5

        items = [item for item in oidsuber.getOnItemIterAll(keys='a')]
        assert items == [(('a',), 0, 'Blue dog'),
                        (('a',), 0, 'White snow'),
                        (('a',), 2, 'Red apple'),
                        (('a',), 2, 'Green tree'),
                        (('a',), 4, 'Green tree')]

        vals = [val for val in oidsuber.getOnIterAll(keys='a')]
        assert vals == [
                        'Blue dog',
                        'White snow',
                        'Red apple',
                        'Green tree',
                        'Green tree',
                        ]

        # test putOn and pinOn
        t = "stars"
        u = "moon"
        v = "sun"

        assert oidsuber.putOn(keys='d', on=0, vals='stars')
        assert oidsuber.getOn(keys='d', on=0) == ['stars', ]
        assert not oidsuber.putOn(keys='d', on=0, vals='stars')
        assert oidsuber.putOn(keys='d', on=0, vals=('moon', 'sun'))
        assert oidsuber.getOn(keys='d', on=0) == ['stars', 'moon', 'sun']
        assert not oidsuber.putOn(keys='d', on=0, vals=('sun', 'moon', 'stars'))
        assert oidsuber.pinOn(keys='d', on=0, vals='sun')
        assert oidsuber.getOn(keys='d', on=0) == ['sun', ]
        assert oidsuber.remOn(keys='d', on=0)
        assert oidsuber.getOn(keys='d', on=0) == []


    assert not os.path.exists(db.path)
    assert not db.opened


def test_b64_oniodup_suber():
    """
    Test B64OnIoDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        oidbuber = subing.B64OnIoDupSuber(db=db, subkey='bags.')
        assert isinstance(oidbuber, subing.B64OnIoDupSuber)
        assert oidbuber.sdb.flags()["dupsort"]

        k = "a"
        j = "b"

        w = ("Blue", "dog")
        x = ("Green", "tree")
        y = "Red"
        z = ("White",)

        # test addOn remOn
        assert oidbuber.addOn(keys=k, on=0, val=w)
        assert oidbuber.getOn(keys=k, on=0) == [w, ]
        assert oidbuber.getOn(keys=k, on=0) == [('Blue', 'dog'),]
        assert oidbuber.addOn(keys=k, on=0, val=x)
        assert oidbuber.getOn(keys=k, on=0) == [w, x]
        assert oidbuber.getOn(keys=k, on=0) == [('Blue', 'dog'), ('Green', 'tree')]
        assert oidbuber.addOn(keys=k, on=1, val=y)
        assert oidbuber.getOn(keys=k, on=1) == [(y,), ]
        assert oidbuber.getOn(keys=k, on=1) == [('Red',),]
        assert oidbuber.addOn(keys=k, on=1, val=z)
        assert oidbuber.getOn(keys=k, on=1) == [(y,), z]
        assert oidbuber.getOn(keys=k, on=1) == [('Red',), ('White',)]

        assert oidbuber.getOn(keys=k, on=0) == [w, x]

        assert oidbuber.cntOnAll(keys=(k,)) == 4

        items = [item for item in oidbuber.getOnItemIterAll(keys=k)]
        assert items == [(('a',), 0, ('Blue', 'dog')),
                            (('a',), 0, ('Green', 'tree')),
                            (('a',), 1, ('Red',)),
                            (('a',), 1, ('White',))]

        assert oidbuber.remOn(keys=k, on=0, val=w)
        assert oidbuber.remOn(keys=k, on=1)
        items = [item for item in oidbuber.getOnItemIterAll(keys=k)]
        assert items == [(('a',), 0, ('Green', 'tree'))]

        assert oidbuber.remOn(keys=k, on=0, val=x)
        assert oidbuber.cntOnAll(keys=(k,)) == 0

        # test append
        assert 0 == oidbuber.appendOn(keys=(j,), val=w)
        assert 1 == oidbuber.appendOn(keys=(j,), val=x)
        assert 2 == oidbuber.appendOn(keys=(j,), val=y)
        assert 3 == oidbuber.appendOn(keys=(j,), val=z)

        assert oidbuber.cntOnAll(keys=(j,)) == 4
        assert oidbuber.cntOnAll(keys=(j,), on=2) == 2
        assert oidbuber.cntOnAll(keys=(j,), on=4) == 0

        items = [(keys, val) for keys, val in oidbuber.getItemIter()]
        assert items == [(('b', '00000000000000000000000000000000'), ('Blue', 'dog')),
                         (('b', '00000000000000000000000000000001'), ('Green', 'tree')),
                         (('b', '00000000000000000000000000000002'), ('Red',)),
                         (('b', '00000000000000000000000000000003'), ('White',))]



        # test getOnIterAll
        vals = [val for val in oidbuber.getOnIterAll(keys=j)]
        assert vals == [w, x, (y,), z]

        vals = [val for val in oidbuber.getOnIterAll(keys=j, on=2)]
        assert vals == [(y,), z]

        # test getOnItemIterAll
        items = [item for item in oidbuber.getOnItemIterAll(keys=j)]
        assert items == [(('b',), 0, ('Blue', 'dog')),
                            (('b',), 1, ('Green', 'tree')),
                            (('b',), 2, ('Red',)),
                            (('b',), 3, ('White',))]


        items = [item for item in oidbuber.getOnItemIterAll(keys=j, on=2)]
        assert items == [(('b',), 2, ('Red',)), (('b',), 3, ('White',))]

        # test add duplicates
        assert oidbuber.add(keys=dbing.onKey(k, 0), val=w)
        assert oidbuber.add(keys=dbing.onKey(k, 1), val=x)
        assert oidbuber.add(keys=dbing.onKey("bc", 0), val=y)
        assert oidbuber.add(keys=dbing.onKey("ac", 0), val=z)

        assert oidbuber.cntOnAll(keys=(k,)) == 2
        assert oidbuber.cntOnAll(keys=("bc",), on=2) == 0
        assert oidbuber.cntOnAll(keys="") == 8

        items = [(keys, val) for keys, val in oidbuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), ('Blue', 'dog')),
                        (('a', '00000000000000000000000000000001'), ('Green', 'tree')),
                        (('ac', '00000000000000000000000000000000'), ('White',)),
                        (('b', '00000000000000000000000000000000'), ('Blue', 'dog')),
                        (('b', '00000000000000000000000000000001'), ('Green', 'tree')),
                        (('b', '00000000000000000000000000000002'), ('Red',)),
                        (('b', '00000000000000000000000000000003'), ('White',)),
                        (('bc', '00000000000000000000000000000000'), ('Red',))]

        # test getOnItemIterAll   getOnIterAll
        items = [item for item in oidbuber.getOnItemIterAll(keys=k)]
        assert items == [(('a',), 0, ('Blue', 'dog')), (('a',), 1, ('Green', 'tree'))]

        vals = [val for val in oidbuber.getOnIterAll(keys=k)]
        assert vals == [('Blue', 'dog'), ('Green', 'tree')]

        vals = [val for val in oidbuber.getOnIterAll(keys=(k, ))]
        assert vals == [('Blue', 'dog'), ('Green', 'tree')]

        items = [item for item in oidbuber.getOnItemIterAll(keys=(k, ))]
        assert items == [(('a',), 0, ('Blue', 'dog')),
                         (('a',), 1, ('Green', 'tree'))]

        items = [item for item in oidbuber.getOnItemIterAll(keys=(k, ""))]
        assert items == []

        vals = [val for val in oidbuber.getOnIterAll(keys=(k, ""))]
        assert vals == []

        items = [item for item in oidbuber.getOnItemIterAll(keys='')]
        assert items == [(('a',), 0, ('Blue', 'dog')),
                            (('a',), 1, ('Green', 'tree')),
                            (('ac',), 0, ('White',)),
                            (('b',), 0, ('Blue', 'dog')),
                            (('b',), 1, ('Green', 'tree')),
                            (('b',), 2, ('Red',)),
                            (('b',), 3, ('White',)),
                            (('bc',), 0, ('Red',))]


        vals = [val for val in oidbuber.getOnIterAll(keys='')]
        assert vals == [('Blue', 'dog'),
                        ('Green', 'tree'),
                        ('White',),
                        ('Blue', 'dog'),
                        ('Green', 'tree'),
                        ('Red',),
                        ('White',),
                        ('Red',)]

        items = [item for item in oidbuber.getOnItemIterAll()]
        assert items == [(('a',), 0, ('Blue', 'dog')),
                            (('a',), 1, ('Green', 'tree')),
                            (('ac',), 0, ('White',)),
                            (('b',), 0, ('Blue', 'dog')),
                            (('b',), 1, ('Green', 'tree')),
                            (('b',), 2, ('Red',)),
                            (('b',), 3, ('White',)),
                            (('bc',), 0, ('Red',))]


        vals = [val for val in oidbuber.getOnIterAll()]
        assert vals == [('Blue', 'dog'),
                        ('Green', 'tree'),
                        ('White',),
                        ('Blue', 'dog'),
                        ('Green', 'tree'),
                        ('Red',),
                        ('White',),
                        ('Red',)]

        # test with duplicates
        assert oidbuber.add(keys=dbing.onKey(j, 0), val=z)
        assert oidbuber.add(keys=dbing.onKey(j, 1), val=y)
        assert oidbuber.add(keys=dbing.onKey(j, 2), val=x)
        assert oidbuber.add(keys=dbing.onKey(j, 3), val=w)

        assert oidbuber.cntOnAll(keys=(j,)) == 8
        assert oidbuber.cntOnAll(keys=(j,), on=2) == 4
        assert oidbuber.cntOnAll(keys=(j,), on=4) == 0

        items = [(keys, val) for keys, val in oidbuber.getItemIter(keys=(j, ""))]
        assert items == [(('b', '00000000000000000000000000000000'), ('Blue', 'dog')),
                        (('b', '00000000000000000000000000000000'), ('White',)),
                        (('b', '00000000000000000000000000000001'), ('Green', 'tree')),
                        (('b', '00000000000000000000000000000001'), ('Red',)),
                        (('b', '00000000000000000000000000000002'), ('Red',)),
                        (('b', '00000000000000000000000000000002'), ('Green', 'tree')),
                        (('b', '00000000000000000000000000000003'), ('White',)),
                        (('b', '00000000000000000000000000000003'), ('Blue', 'dog'))]


        # test getOnItemIterAll getOnIterAll getOnItemBackIter getOnBackIter
        items = [item for item in oidbuber.getOnItemIterAll(keys=j)]
        assert items == [(('b',), 0, ('Blue', 'dog')),
                            (('b',), 0, ('White',)),
                            (('b',), 1, ('Green', 'tree')),
                            (('b',), 1, ('Red',)),
                            (('b',), 2, ('Red',)),
                            (('b',), 2, ('Green', 'tree')),
                            (('b',), 3, ('White',)),
                            (('b',), 3, ('Blue', 'dog'))]

        vals = [val for val in oidbuber.getOnIterAll(keys=j)]
        assert vals == [('Blue', 'dog'),
                        ('White',),
                        ('Green', 'tree'),
                        ('Red',),
                        ('Red',),
                        ('Green', 'tree'),
                        ('White',),
                        ('Blue', 'dog')]


        items = [item for item in oidbuber.getOnItemBackIter(keys=j, on=4)]
        assert items == [(('b',), 3, ('Blue', 'dog')),
                        (('b',), 3, ('White',)),
                        (('b',), 2, ('Green', 'tree')),
                        (('b',), 2, ('Red',)),
                        (('b',), 1, ('Red',)),
                        (('b',), 1, ('Green', 'tree')),
                        (('b',), 0, ('White',)),
                        (('b',), 0, ('Blue', 'dog'))]


        vals = [val for val in oidbuber.getOnBackIter(keys=j, on=4)]
        assert vals == [('Blue', 'dog'),
                        ('White',),
                        ('Green', 'tree'),
                        ('Red',),
                        ('Red',),
                        ('Green', 'tree'),
                        ('White',),
                        ('Blue', 'dog')]


        items = [item for item in oidbuber.getOnItemIterAll(keys=j, on=2)]
        assert items ==[(('b',), 2, ('Red',)),
                        (('b',), 2, ('Green', 'tree')),
                        (('b',), 3, ('White',)),
                        (('b',), 3, ('Blue', 'dog'))]

        vals = [val for val in oidbuber.getOnIterAll(keys=j, on=2)]
        assert vals == [('Red',), ('Green', 'tree'), ('White',), ('Blue', 'dog')]


        items = [item for item in oidbuber.getOnItemBackIter(keys=j, on=1)]
        assert items ==[(('b',), 1, ('Red',)),
                        (('b',), 1, ('Green', 'tree')),
                        (('b',), 0, ('White',)),
                        (('b',), 0, ('Blue', 'dog'))]

        vals = [val for val in oidbuber.getOnBackIter(keys=j, on=1)]
        assert vals == [('Red',), ('Green', 'tree'), ('White',), ('Blue', 'dog')]

        # test append with duplicates
        assert 4 == oidbuber.appendOn(keys=(j,), val=x)
        assert oidbuber.cntOnAll(keys=(j,)) == 9

        # test remove
        assert oidbuber.remOn(keys=j, on=1)
        assert not oidbuber.remOn(keys=j, on=1)
        assert oidbuber.remOn(keys=j, on=3)
        assert not oidbuber.remOn(keys=j, on=3)

        assert oidbuber.cntOnAll(keys=(j,)) == 5

        items = [item for item in oidbuber.getOnItemIterAll(keys=j)]
        assert items == [(('b',), 0, ('Blue', 'dog')),
                        (('b',), 0, ('White',)),
                        (('b',), 2, ('Red',)),
                        (('b',), 2, ('Green', 'tree')),
                        (('b',), 4, ('Green', 'tree'))]

        vals = [val for val in oidbuber.getOnIterAll(keys=j)]
        assert vals == [('Blue', 'dog'),
                        ('White',),
                        ('Red',),
                        ('Green', 'tree'),
                        ('Green', 'tree')]

        # test putOn and pinOn
        o = ("moon", "beam")
        p = ("sun", "spot")
        q = [("moon", "beam"), ]
        r = ("stars", )
        s = ("moon", )
        t = ("sun",)
        u = (("sun", "spot"), "sun")
        v = ("moon", ("stars", ))


        assert oidbuber.putOn(keys='d', on=0, vals=q)
        assert oidbuber.getOn(keys='d', on=0) == [("moon", "beam"), ]
        assert oidbuber.getOn(keys='d', on=0) == q
        assert not oidbuber.putOn(keys='d', on=0, vals=q)
        assert oidbuber.putOn(keys='d', on=0, vals=r)
        assert oidbuber.putOn(keys='d', on=0, vals=s)
        assert oidbuber.putOn(keys='d', on=0, vals=t)
        assert oidbuber.getOn(keys='d', on=0) == [('moon', 'beam'), ('stars',), ('moon',), ('sun',)]
        assert oidbuber.getOn(keys='d', on=0) == [o, r, s, t]
        assert not oidbuber.putOn(keys='d', on=0, vals=(o, r, s, t))
        assert oidbuber.pinOn(keys='d', on=0, vals=u)
        assert oidbuber.getOn(keys='d', on=0) == [('sun', 'spot'), ('sun',)]
        assert oidbuber.getOn(keys='d', on=0) == [p, t]
        assert oidbuber.putOn(keys='d', on=0, vals=v)
        assert oidbuber.getOn(keys='d', on=0) == [('sun', 'spot'), ('sun',), ('moon',), ('stars',)]
        assert oidbuber.getOn(keys='d', on=0) == [p, t, s, r]
        assert oidbuber.remOn(keys='d', on=0)
        assert oidbuber.getOn(keys='d', on=0) == []

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

        iosuber = subing.IoSetSuber(db=db, subkey='bags.')
        assert isinstance(iosuber, subing.IoSetSuber)
        assert not iosuber.sdb.flags()["dupsort"]


        # test empty keys
        assert iosuber.cntAll() == 0
        assert iosuber.cnt(keys="") == 0
        assert iosuber.get(keys="") == []
        assert [val for val in iosuber.getIter(keys="")] == []
        assert iosuber.getLastItem(keys=()) == ()
        assert iosuber.getLast(keys=()) == None
        assert iosuber.getLastItem(keys="") == ()
        assert iosuber.getLast(keys="") == None

        sue = "Hello sailer!"
        sal = "Not my type."
        sam = "A real charmer!"
        zoe = "See ya later."
        zia = "Hey gorgeous!"
        zul = "get lost"
        bob = "Shove off!"

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")
        keys2 = "keystr"

        vals0 = [sue, sal, sam]
        vals1 = [zoe, zia, zul]

        # fill database
        assert iosuber.put(keys=keys0, vals=vals0)
        assert iosuber.put(keys=keys1, vals=vals1)

        assert iosuber.cntAll() == 6
        assert iosuber.cnt(keys="") == 6

        assert iosuber.cnt(keys=keys0) == 3
        assert iosuber.cnt(keys=keys1) == 3

        # keys0
        # ion default 0
        assert [val for val in iosuber.getIter(keys=keys0)] == vals0
        assert iosuber.get(keys=keys0) == vals0
        assert iosuber.cnt(keys=keys0) == 3
        assert iosuber.getLastItem(keys=keys0) == (keys0, sam)
        assert iosuber.getLast(keys=keys0) == sam

        # ion = 0
        assert [val for val in iosuber.getIter(keys=keys0, ion=0)] == [sue, sal, sam]
        assert iosuber.get(keys=keys0, ion=0) == [sue, sal, sam]
        assert iosuber.cnt(keys=keys0, ion=0) == 3

        # ion = 1
        assert [val for val in iosuber.getIter(keys=keys0, ion=1)] == [sal, sam]
        assert iosuber.get(keys=keys0, ion=1) == [sal, sam]
        assert iosuber.cnt(keys=keys0, ion=1) == 2

        # ion = 2
        assert [val for val in iosuber.getIter(keys=keys0, ion=2)] == [sam]
        assert iosuber.get(keys=keys0, ion=2) == [sam]
        assert iosuber.cnt(keys=keys0, ion=2) == 1

        # ion = 3  past end of keys0 set
        assert [val for val in iosuber.getIter(keys=keys0, ion=3)] == []
        assert iosuber.get(keys=keys0, ion=3) == []
        assert iosuber.cnt(keys=keys0, ion=3) == 0

        # keys1
        # ion default 0
        assert [val for val in iosuber.getIter(keys=keys1)] == vals1
        assert iosuber.get(keys=keys1) == vals1
        assert iosuber.cnt(keys=keys1) == 3
        assert iosuber.getLastItem(keys=keys1) == (keys1, zul)
        assert iosuber.getLast(keys=keys1) == zul

        # ion = 0
        assert [val for val in iosuber.getIter(keys=keys1, ion=0)] == [zoe, zia, zul]
        assert iosuber.get(keys=keys1, ion=0) == [zoe, zia, zul]
        assert iosuber.cnt(keys=keys1, ion=0) == 3

        # ion = 1
        assert [val for val in iosuber.getIter(keys=keys1, ion=1)] == [zia, zul]
        assert iosuber.get(keys=keys1, ion=1) == [zia, zul]
        assert iosuber.cnt(keys=keys1, ion=1) == 2

        # ion = 2
        assert [val for val in iosuber.getIter(keys=keys1, ion=2)] == [zul]
        assert iosuber.get(keys=keys1, ion=2) == [zul]
        assert iosuber.cnt(keys=keys1, ion=2) == 1

        # ion = 3  past end of keys1 set
        assert [val for val in iosuber.getIter(keys=keys1, ion=3)] == []
        assert iosuber.get(keys=keys0, ion=3) == []
        assert iosuber.cnt(keys=keys0, ion=3) == 0

        # keys0 make gap keys0
        assert iosuber.rem(keys=keys0, val=sal)

        # ion default 0
        assert [val for val in iosuber.getIter(keys=keys0)] == [sue, sam]
        assert iosuber.get(keys=keys0) == [sue, sam]
        assert iosuber.cnt(keys=keys0) == 2
        assert iosuber.getLastItem(keys=keys0) == (keys0, sam)
        assert iosuber.getLast(keys=keys0) == sam

        # ion = 0
        assert [val for val in iosuber.getIter(keys=keys0, ion=0)] == [sue, sam]
        assert iosuber.get(keys=keys0, ion=0) == [sue, sam]
        assert iosuber.cnt(keys=keys0, ion=0) == 2

        # ion = 1
        assert [val for val in iosuber.getIter(keys=keys0, ion=1)] == [ sam]
        assert iosuber.get(keys=keys0, ion=1) == [sam]
        assert iosuber.cnt(keys=keys0, ion=1) == 1

        # ion = 2
        assert [val for val in iosuber.getIter(keys=keys0, ion=2)] == [sam]
        assert iosuber.get(keys=keys0, ion=2) == [sam]
        assert iosuber.cnt(keys=keys0, ion=2) == 1

        # ion = 3  past end of keys0 set
        assert [val for val in iosuber.getIter(keys=keys0, ion=3)] == []
        assert iosuber.get(keys=keys0, ion=3) == []
        assert iosuber.cnt(keys=keys0, ion=3) == 0

        # keys1 make gap keys1
        assert iosuber.rem(keys=keys1, val=zoe)

        # ion default 0
        assert [val for val in iosuber.getIter(keys=keys1)] == [zia, zul]
        assert iosuber.get(keys=keys1) == [zia, zul]
        assert iosuber.cnt(keys=keys1) == 2
        assert iosuber.getLastItem(keys=keys1) == (keys1, zul)
        assert iosuber.getLast(keys=keys1) == zul

        # ion = 0
        assert [val for val in iosuber.getIter(keys=keys1, ion=0)] == [zia, zul]
        assert iosuber.get(keys=keys1, ion=0) == [zia, zul]
        assert iosuber.cnt(keys=keys1, ion=0) == 2

        # ion = 1
        assert [val for val in iosuber.getIter(keys=keys1, ion=1)] == [zia, zul]
        assert iosuber.get(keys=keys1, ion=1) == [zia, zul]
        assert iosuber.cnt(keys=keys1, ion=1) == 2

        # ion = 2
        assert [val for val in iosuber.getIter(keys=keys1, ion=2)] == [zul]
        assert iosuber.get(keys=keys1, ion=2) == [zul]
        assert iosuber.cnt(keys=keys1, ion=2) == 1

        # ion = 3  past end of keys1 set
        assert [val for val in iosuber.getIter(keys=keys1, ion=3)] == []
        assert iosuber.get(keys=keys1, ion=3) == []
        assert iosuber.cnt(keys=keys1, ion=3) == 0

        # clear db
        assert iosuber.rem(keys=keys0)
        assert iosuber.rem(keys=keys1)
        assert iosuber.cntAll() == 0
        assert iosuber.cnt() == 0

        # more tests
        assert iosuber.put(keys=keys0, vals=[sal, sue])
        assert iosuber.get(keys=keys0) == [sal, sue]  # insertion order not lexicographic
        assert iosuber.cnt(keys0) == 2
        assert iosuber.getLastItem(keys=keys0) == (keys0, sue)
        assert iosuber.getLast(keys=keys0) == sue

        assert iosuber.rem(keys0)
        assert iosuber.get(keys=keys0) == []
        assert iosuber.cnt(keys0) == 0

        assert iosuber.put(keys=keys0, vals=[sue, sal])
        actuals = iosuber.get(keys=keys0)
        assert actuals == [sue, sal]  # insertion order
        assert iosuber.getLastItem(keys=keys0) == (keys0, sal)
        assert iosuber.getLast(keys=keys0) == sal

        result = iosuber.add(keys=keys0, val=sam)
        assert result
        actuals = iosuber.get(keys=keys0)
        assert actuals == [sue, sal, sam]   # insertion order

        result = iosuber.pin(keys=keys0, vals=[zoe, zia])
        assert result
        actuals = iosuber.get(keys=keys0)
        assert actuals == [zoe, zia]  # insertion order

        assert iosuber.put(keys=keys1, vals=[sal, sue, sam])
        actuals = iosuber.get(keys=keys1)
        assert actuals == [sal, sue, sam]

        for i, val in enumerate(iosuber.getIter(keys=keys1)):
            assert val == actuals[i]

        items = [(keys, val) for keys, val in iosuber.getItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'A real charmer!')]

        items = [(keys, val) for keys, val in iosuber.getLastItemIter()]
        assert items == [(('test_key', '0001'), 'Hey gorgeous!'),
                         (('test_key', '0002'), 'A real charmer!')]

        lasts = [val for val in iosuber.getLastIter()]
        assert lasts == ['Hey gorgeous!', 'A real charmer!']

        items = list(iosuber.getFullItemIter())
        assert items ==  [(('test_key', '0001', '00000000000000000000000000000000'), 'See ya later.'),
                        (('test_key', '0001', '00000000000000000000000000000001'), 'Hey gorgeous!'),
                        (('test_key', '0002', '00000000000000000000000000000000'), 'Not my type.'),
                        (('test_key', '0002', '00000000000000000000000000000001'), 'Hello sailer!'),
                        (('test_key', '0002', '00000000000000000000000000000002'), 'A real charmer!')]


        items = [(keys, val) for keys,  val in  iosuber.getItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                         (('test_key', '0001'), 'Hey gorgeous!')]

        items = [(keys, val) for keys, val in iosuber.getLastItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), 'Hey gorgeous!'),
                         (('test_key', '0002'), 'A real charmer!')]

        lasts = [val for val in iosuber.getLastIter(keys=keys0)]
        assert lasts == ['Hey gorgeous!', 'A real charmer!']

        items = [(keys, val) for keys,  val in iosuber.getItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'Hello sailer!'),
                        (('test_key', '0002'), 'A real charmer!')]

        items = [(keys, val) for keys, val in iosuber.getLastItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), 'A real charmer!')]

        lasts = [val for val in iosuber.getLastIter(keys=keys1)]
        assert lasts == ['A real charmer!']


        # Test with top keys
        assert iosuber.put(keys=("test", "pop"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in iosuber.getItemIter(keys=topkeys)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        # test with top parameter
        keys = ("test", )
        items = [(keys, val) for keys, val in iosuber.getItemIter(keys=keys, topive=True)]
        assert items == [(('test', 'pop'), 'Not my type.'),
                         (('test', 'pop'), 'Hello sailer!'),
                         (('test', 'pop'), 'A real charmer!')]

        # IoItems
        items = list(iosuber.getFullItemIter(keys=topkeys))
        assert items == [(('test', 'pop', '00000000000000000000000000000000'), 'Not my type.'),
                         (('test', 'pop', '00000000000000000000000000000001'), 'Hello sailer!'),
                         (('test', 'pop', '00000000000000000000000000000002'), 'A real charmer!')]

        # test remove with a specific val
        assert iosuber.rem(keys=("test_key", "0002"), val=sue)
        items = [(keys, val) for keys, val in iosuber.getItemIter()]
        assert items == [(('test', 'pop'), 'Not my type.'),
                        (('test', 'pop'), 'Hello sailer!'),
                        (('test', 'pop'), 'A real charmer!'),
                        (('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'A real charmer!')]

        assert iosuber.trim(keys=("test", ""))
        items = [(keys, val) for keys, val in iosuber.getItemIter()]
        assert items == [(('test_key', '0001'), 'See ya later.'),
                        (('test_key', '0001'), 'Hey gorgeous!'),
                        (('test_key', '0002'), 'Not my type.'),
                        (('test_key', '0002'), 'A real charmer!')]

        assert iosuber.put(keys=keys0, vals=vals0)
        assert iosuber.put(keys=keys1, vals=vals1)
        assert iosuber.cnt() == 10
        assert iosuber.cnt(keys=keys0) == 5
        assert iosuber.cnt(keys=keys1) == 5
        assert iosuber.rem(keys=keys0)
        assert iosuber.cnt(keys=keys0) == 0
        assert iosuber.trim()  # removes whole db
        assert iosuber.cnt() == 0


        # test with keys as string not tuple
        keys2 = "keystr"
        bob = "Shove off!"
        assert iosuber.put(keys=keys2, vals=[bob])
        actuals = iosuber.get(keys=keys2)
        assert actuals == [bob]
        assert iosuber.cnt(keys2) == 1
        assert iosuber.rem(keys2)
        actuals = iosuber.get(keys=keys2)
        assert actuals == []
        assert iosuber.cnt(keys2) == 0

        assert iosuber.put(keys=keys2, vals=[bob])
        actuals = iosuber.get(keys=keys2)
        assert actuals == [bob]

        bil = "Go away."
        assert iosuber.pin(keys=keys2, vals=[bil])
        actuals = iosuber.get(keys=keys2)
        assert actuals == [bil]

        assert iosuber.add(keys=keys2, val=bob)
        actuals = iosuber.get(keys=keys2)
        assert actuals == [bil, bob]

        # Test trim and append
        assert iosuber.trim()  # default trims whole database
        assert iosuber.put(keys=keys1, vals=[bob, bil])
        assert iosuber.get(keys=keys1) == [bob, bil]

    assert not os.path.exists(db.path)
    assert not db.opened


def test_b64_ioset_suber():
    """
    Test B64IoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        # Test Single klas
        iobuber = subing.B64IoSetSuber(db=db, subkey='bags.')
        assert isinstance(iobuber, subing.B64IoSetSuber)
        assert not iobuber.sdb.flags()["dupsort"]
        assert iobuber.sep == '.'
        assert not help.Reb64.match(iobuber.sep.encode())

        # val as joined iterator
        vals0 = ("alpha", "beta")
        vals1 = ("gamma", )

        keys0 = ("cat", "dog")  # keys as tuple
        keys1 = "{}.{}".format("bird", "fish")  # keys as string not tuple

        assert iobuber.put(keys=keys0, vals=(vals0,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0]

        assert iobuber.rem(keys0)
        assert not iobuber.get(keys=keys0)

        assert iobuber.put(keys=keys0, vals=(vals0,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0]

        assert iobuber.put(keys=keys0, vals=(vals1,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0, vals1]

        assert iobuber.pin(keys=keys0, vals=(vals1,))
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals1]

        assert iobuber.rem(keys0)
        assert not iobuber.get(keys=keys0)

        # test with vals as non Iterable on put but Iterable on get
        assert iobuber.put(keys=keys0, vals=["gamma"])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals1]

        assert iobuber.rem(keys0)

        # test val as already joined string since has non Base64
        with pytest.raises(ValueError):
            assert iobuber.put(keys=keys0, vals=["alpha.beta"])

        # test bytes for val
        assert iobuber.put(keys=keys0, vals=[(b"alpha", b"beta")])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [vals0]
        assert iobuber.rem(keys0)

        # test with keys1
        assert iobuber.put(keys=keys1, vals=[vals1])
        actuals = iobuber.get(keys=keys1)
        assert actuals == [vals1]

        assert iobuber.rem(keys1)
        assert not iobuber.get(keys=keys1)

        # test missing entry at keys
        badkey = "badkey"
        assert not iobuber.get(badkey)

        # test iteritems
        assert iobuber.put(keys0, [vals0])
        assert iobuber.put(keys1, [vals1])

        items = [ items for items in iobuber.getItemIter()]
        assert items == [(('bird', 'fish'), ('gamma',)), (('cat', 'dog'), ('alpha', 'beta'))]

        keys3 = ("b","1")
        keys4 = ("b","2")
        keys5 = ("c","1")
        keys6 = ("c","2")

        iobuber.put(keys=keys3, vals=[vals0])
        iobuber.put(keys=keys4, vals=[vals1])
        iobuber.put(keys=keys5, vals=[vals0])
        iobuber.put(keys=keys6, vals=[vals1])

        topkeys = ("b","")  # last element empty to force trailing separator
        items = [items for items in  iobuber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), ('alpha', 'beta')),
                         (('b', '2'), ('gamma',))]

        assert iobuber.rem(keys0)
        assert iobuber.rem(keys1)
        assert iobuber.rem(keys3)
        assert iobuber.rem(keys4)
        assert iobuber.rem(keys5)
        assert iobuber.rem(keys6)


        # iodup testing
        # singular values B64
        sue = "Hello"
        sal = "Toodles"
        sam = "Bye"

        keys0 = ("test_key", "0001")
        keys1 = ("test_key", "0002")

        assert iobuber.put(keys=keys0, vals=[sal, sue])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [(sal,), (sue,)]  # insertion order not lexicographic
        assert iobuber.cnt(keys0) == 2
        actual = iobuber.getLast(keys=keys0)
        assert actual == (sue,)

        assert iobuber.rem(keys0)
        actuals = iobuber.get(keys=keys0)
        assert not actuals
        assert actuals == []
        assert iobuber.cnt(keys0) == 0

        assert iobuber.put(keys=keys0, vals=[sue, sal])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [(sue,), (sal, )]  # insertion order
        actual = iobuber.getLast(keys=keys0)
        assert actual == (sal,)


        assert iobuber.add(keys=keys0, val=sam)
        actuals = iobuber.get(keys=keys0)
        assert actuals == [(sue,), (sal,), (sam,)]   # insertion order


        sue = ("Hello",)
        sal = ("Toodles",)
        sam = ("Bye",)
        zoe = ('later', 'alligator')
        zia = ('soon', 'baboon')

        assert iobuber.pin(keys=keys0, vals=[zoe, zia])
        actuals = iobuber.get(keys=keys0)
        assert actuals == [zoe, zia]  # insertion order

        assert iobuber.put(keys=keys1, vals=[sal, sue, sam])
        actuals = iobuber.get(keys=keys1)
        assert actuals == [sal, sue, sam]

        for i, val in enumerate(iobuber.getIter(keys=keys1)):
            assert val == actuals[i]

        items = [(keys, val) for keys, val in iobuber.getItemIter()]
        assert items == [(('test_key', '0001'), ('later', 'alligator')),
                         (('test_key', '0001'), ('soon', 'baboon')),
                         (('test_key', '0002'), ('Toodles',)),
                         (('test_key', '0002'), ('Hello',)),
                         (('test_key', '0002'), ('Bye',))]

        items = list(iobuber.getFullItemIter())
        assert items ==  \
        [
            (('test_key', '0001', '00000000000000000000000000000000'),('later', 'alligator')),
           (('test_key', '0001', '00000000000000000000000000000001'), ('soon', 'baboon')),
           (('test_key', '0002', '00000000000000000000000000000000'), ('Toodles',)),
           (('test_key', '0002', '00000000000000000000000000000001'), ('Hello',)),
           (('test_key', '0002', '00000000000000000000000000000002'), ('Bye',))
        ]

        items = [(keys, val) for keys,  val in iobuber.getItemIter(keys=keys1)]
        assert items == [(('test_key', '0002'), ('Toodles',)),
                         (('test_key', '0002'), ('Hello',)),
                         (('test_key', '0002'), ('Bye',))]

        items = [(keys, val) for keys,  val in  iobuber.getItemIter(keys=keys0)]
        assert items == [(('test_key', '0001'), ('later', 'alligator')),
                         (('test_key', '0001'), ('soon', 'baboon'))]

        # Test with top keys
        assert iobuber.put(keys=("test", "pop"), vals=[sal, sue, sam])
        topkeys = ("test", "")
        items = [(keys, val) for keys, val in iobuber.getItemIter(keys=topkeys)]
        assert items == [(('test', 'pop'), ('Toodles',)),
                         (('test', 'pop'), ('Hello',)),
                         (('test', 'pop'), ('Bye',))]

        # test with top parameter
        keys = ("test", )
        items = [(keys, val) for keys, val in iobuber.getItemIter(keys=keys, topive=True)]
        assert items == [(('test', 'pop'), ('Toodles',)),
                         (('test', 'pop'), ('Hello',)),
                         (('test', 'pop'), ('Bye',))]

        # IoItems
        items = list(iobuber.getFullItemIter(keys=topkeys))
        assert items == \
        [
            (('test', 'pop', '00000000000000000000000000000000'), ('Toodles',)),
            (('test', 'pop', '00000000000000000000000000000001'), ('Hello',)),
            (('test', 'pop', '00000000000000000000000000000002'), ('Bye',))
        ]
                   # test remove with a specific val
        assert iobuber.rem(keys=("test_key", "0002"), val=sue)
        items = [(keys, val) for keys, val in iobuber.getItemIter()]
        assert items ==[(('test', 'pop'), ('Toodles',)),
                        (('test', 'pop'), ('Hello',)),
                        (('test', 'pop'), ('Bye',)),
                        (('test_key', '0001'), ('later', 'alligator')),
                        (('test_key', '0001'), ('soon', 'baboon')),
                        (('test_key', '0002'), ('Toodles',)),
                        (('test_key', '0002'), ('Bye',))]


        assert iobuber.trim(keys=("test", ""))
        items = [(keys, val) for keys, val in iobuber.getItemIter()]
        assert items == [(('test_key', '0001'), ('later', 'alligator')),
                         (('test_key', '0001'), ('soon', 'baboon')),
                         (('test_key', '0002'), ('Toodles',)),
                         (('test_key', '0002'), ('Bye',))]


        assert iobuber.cnt(keys=keys0) == 2
        assert iobuber.cnt(keys=keys1) == 2

        # test with keys as string not tuple
        keys2 = "keystr"
        bob = ("go", "figure")
        assert iobuber.put(keys=keys2, vals=[bob])
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bob]
        assert iobuber.cnt(keys2) == 1
        assert iobuber.rem(keys2)
        actuals = iobuber.get(keys=keys2)
        assert actuals == []
        assert iobuber.cnt(keys2) == 0

        assert iobuber.put(keys=keys2, vals=[bob])
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bob]

        bil = ("Go", "away")
        assert iobuber.pin(keys=keys2, vals=[bil])
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bil]

        assert iobuber.add(keys=keys2, val=bob)
        actuals = iobuber.get(keys=keys2)
        assert actuals == [bil, bob]

        # Test trim
        assert iobuber.trim()  # default trims whole database
        assert iobuber.put(keys=keys1, vals=[bob, bil])
        assert iobuber.get(keys=keys1) == [bob, bil]


    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""

def test_cesr_ioset_suber():
    """
    Test CesrIoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        cisuber = subing.CesrIoSetSuber(db=db, subkey='bags.', klas=coring.Saider)
        assert isinstance(cisuber, subing.CesrIoSetSuber)
        assert issubclass(cisuber.klas, coring.Saider)
        assert not cisuber.sdb.flags()["dupsort"]

        seqner0 = coring.Seqner(sn=20)
        seq0 = seqner0.qb64
        assert seq0 == '0AAAAAAAAAAAAAAAAAAAAAAU'

        seqner1 = coring.Seqner(sn=10)
        seq1 = seqner1.qb64
        assert seq1 == '0AAAAAAAAAAAAAAAAAAAAAAK'

        diger0 = coring.Diger(ser=b"Hello Me Maties.")
        dig0 = diger0.qb64
        assert dig0 == 'ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ'

        diger1 = coring.Diger(ser=b"Bye Y'all.")
        dig1 = diger1.qb64
        assert dig1 == 'EK--ZWfMjPZ8R90eDBuwy9umo1CnxpF95H550OGv65ry'

        keys0 = (seq0, dig0)
        keys1 = (seq1, dig1)


        sad = dict(
                       v= 'KERI10JSON000000_',
                       t="rpy",
                       d= "",  # vacuous said
                       dt="2020-08-22T17:50:12.988921+00:00",
                       r="/help/me",
                       a=dict(
                                name="John Jones",
                                role= "Founder",
                             ),
                   )
        saider0, sad0 = coring.Saider.saidify(sad=sad)
        said0 = saider0.qb64
        assert said0 == 'EKwVGsUU1sUlYRq_g2Z3_3GOIREYtlQ3kPSNjpg8w4j0'
        assert sad0 == {'v': 'KERI10JSON0000b8_',
                        't': 'rpy',
                        'd': 'EKwVGsUU1sUlYRq_g2Z3_3GOIREYtlQ3kPSNjpg8w4j0',
                        'dt': '2020-08-22T17:50:12.988921+00:00',
                        'r': '/help/me',
                        'a': {'name': 'John Jones', 'role': 'Founder'}}

        sad = dict(
                       v= 'KERI10JSON000000_',
                       t="rpy",
                       d= "",  # vacuous said
                       dt="2020-08-22T17:50:12.988921+00:00",
                       r="/help/you",
                       a=dict(
                                name="Sue Swan",
                                role= "Creator",
                             ),
                   )
        saider1, sad1 = coring.Saider.saidify(sad=sad)
        said1 = saider1.qb64
        assert said1 == 'EPl1dMAs2RDsZ12K3yxA0fTHP6dRJzDkStf65VVeFxne'


        sad = dict(
                       v= 'KERI10JSON000000_',
                       t="rpy",
                       d= "",  # vacuous said
                       dt="2020-08-22T17:50:30.988921+00:00",
                       r="/find/out",
                       a=dict(
                                name="Zoe Zigler",
                                role= "Maven",
                             ),
                   )
        saider2, sad2 = coring.Saider.saidify(sad=sad)
        said2 = saider2.qb64
        assert said2 == 'EJxOaEsBSObrcmrsnlfHOdVAowGhUBKoE2Ce3TZ4Mhgu'

        assert cisuber.put(keys=keys0, vals=[saider1, saider0])
        assert cisuber.cnt(keys0) == 2
        actuals = cisuber.get(keys=keys0)  # insertion order not lexicographic
        assert len(actuals) ==  2
        sers = [actual.qb64 for actual in actuals]
        assert sers == [said1, said0]
        actual = cisuber.getLast(keys=keys0)
        assert actual.qb64 == said0

        assert cisuber.rem(keys0)
        actuals = cisuber.get(keys=keys0)
        assert not actuals
        assert actuals == []
        assert cisuber.cnt(keys0) == 0

        assert cisuber.put(keys=keys0, vals=[saider0, saider1])
        assert cisuber.cnt(keys0) == 2
        actuals = cisuber.get(keys=keys0)  # insertion order not lexicographic
        assert len(actuals) ==  2
        sers = [actual.qb64 for actual in actuals]
        assert sers == [said0, said1]
        actual = cisuber.getLast(keys=keys0)
        assert actual.qb64 == said1

        assert cisuber.add(keys=keys0, val=saider2)
        assert cisuber.cnt(keys0) == 3
        actuals = cisuber.get(keys=keys0)  # insertion order not lexicographic
        assert len(actuals) ==  3
        sers = [actual.qb64 for actual in actuals]
        assert sers == [said0, said1, said2]
        actual = cisuber.getLast(keys=keys0)
        assert actual.qb64 == said2

        assert cisuber.pin(keys=keys0, vals=[saider1, saider2])
        assert cisuber.cnt(keys0) == 2
        actuals = cisuber.get(keys=keys0)  # insertion order not lexicographic
        assert len(actuals) ==  2
        sers = [actual.qb64 for actual in actuals]
        assert sers == [said1, said2]

        assert cisuber.put(keys=keys1, vals=[saider2, saider1, saider0])
        assert cisuber.cnt(keys1) == 3
        actuals = cisuber.get(keys=keys1)  # insertion order not lexicographic
        assert len(actuals) ==  3
        sers = [actual.qb64 for actual in actuals]
        assert sers == [said2, said1, said0]

        assert cisuber.rem(keys=keys1, val=saider1)
        assert cisuber.cnt(keys1) == 2
        actuals = cisuber.get(keys=keys1)  # insertion order not lexicographic
        sers = [actual.qb64 for actual in actuals]
        assert sers == [said2, said0]

        sers = [val.qb64 for val in cisuber.getIter(keys=keys1)]
        assert sers == [said2, said0]

        items = [(keys, val.qb64) for keys, val in cisuber.getItemIter()]
        assert items == [
                            (keys1, said2),
                            (keys1, said0),
                            (keys0, said1),
                            (keys0, said2),
                        ]


        items = [(iokeys, val.qb64) for iokeys, val in cisuber.getFullItemIter()]
        assert items == [
                            ((*keys1, '00000000000000000000000000000000'), said2),
                            ((*keys1, '00000000000000000000000000000002'), said0),
                            ((*keys0, '00000000000000000000000000000000'), said1),
                            ((*keys0, '00000000000000000000000000000001'), said2),
                        ]

        items = [(iokeys, val.qb64) for iokeys,  val in  cisuber.getItemIter(keys=keys0)]
        assert items == [(keys0, said1), (keys0, said2)]

        items = [(iokeys, val.qb64) for iokeys, val in cisuber.getItemIter(keys=keys1)]
        assert items == [
                            (keys1, said2),
                            (keys1, said0),
                        ]


        topkeys = (seq1, "")
        items = [(keys, val.qb64) for keys, val in cisuber.getItemIter(keys=topkeys)]
        assert items == [
                            (keys1, said2),
                            (keys1, said0),
                        ]

        topkeys = (seq0, "")
        items = [(iokeys, val.qb64) for iokeys, val in cisuber.getFullItemIter(keys=topkeys)]
        assert items == [
                            ((*keys0, '00000000000000000000000000000000'), said1),
                            ((*keys0, '00000000000000000000000000000001'), said2),
                        ]



    assert not os.path.exists(db.path)
    assert not db.opened


def test_on_ioset_suber():
    """
    Test OnIoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        niosuber = subing.OnIoSetSuber(db=db, subkey='bags.')
        assert isinstance(niosuber, subing.OnIoSetSuber)
        assert not niosuber.sdb.flags()["dupsort"]

        # test empty keys
        assert niosuber.cntAll() == 0
        assert niosuber.cnt() == 0
        assert niosuber.cntOn(keys="") == 0
        assert niosuber.cntOnAll(keys="") == 0
        assert niosuber.getOn(keys="") == []
        assert [val for val in niosuber.getOnIter(keys="")] == []
        assert niosuber.getLastItem(keys=()) == ()
        assert niosuber.getLast(keys=()) == None
        assert niosuber.getLastItem(keys="") == ()
        assert niosuber.getLast(keys="") == None

        keys0 = ('A', 'B')
        keys1 = ('B', 'C')
        keys2 = ('C', 'D')
        keys3 = ('E', 'F')
        keys4 = ('Z', 'Z')
        keys5 = ('A', 'A')

        vals0 = ["z", "m", "x", "a"]
        vals1 = ["w", "n", "y", "d"]
        vals2 = ["p", "o", "h", "f"]
        vals3 = ["k", "j", "l"]

        # fill database
        assert niosuber.putOn(keys=keys0, vals=vals0)  # default on = 0
        assert niosuber.putOn(keys=keys1, vals=vals1)  # default on = 0
        assert niosuber.putOn(keys=keys2, vals=vals2)  # default on = 0

        assert niosuber.cnt() == 12
        assert niosuber.cntOnAll(keys="") == 12
        assert niosuber.cntOnAll(keys1) == 4
        assert niosuber.cntOnAll(keys1, on=2) == 0
        assert niosuber.cntOn(keys='') == 0
        assert niosuber.cntOn(keys=keys0) == 4
        assert niosuber.cntOn(keys=keys0, on=0, ion=2) == 2
        assert niosuber.cntOn(keys=keys1) == 4
        assert niosuber.cntOn(keys=keys2) == 4

        # keys0
        # ion default 0
        assert [val for val in niosuber.getOnIter(keys=keys0)] == vals0
        assert niosuber.getOn(keys=keys0) == vals0
        assert niosuber.getOnItem(keys=keys0) == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]
        assert niosuber.cntOn(keys=keys0) == 4
        assert niosuber.getOnLastItem(keys=keys0) == (keys0, 0, "a")
        assert niosuber.getOnLast(keys=keys0) == "a"

        # ion = 0
        assert [val for val in niosuber.getOnIter(keys=keys0, ion=0)] == vals0
        assert niosuber.getOn(keys=keys0, ion=0) == vals0
        assert niosuber.getOnItem(keys=keys0, ion=0) == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]
        assert niosuber.cntOn(keys=keys0, ion=0) == 4

        # ion = 1
        assert [val for val in niosuber.getOnIter(keys=keys0, ion=1)] == ["m", "x", "a"]
        assert niosuber.getOn(keys=keys0, ion=1) == ["m", "x", "a"]
        assert niosuber.getOnItem(keys=keys0, ion=1) == \
        [
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]
        assert niosuber.cntOn(keys=keys0, ion=1) == 3

        # ion = 2
        assert [val for val in niosuber.getOnIter(keys=keys0, ion=2)] == ["x", "a"]
        assert niosuber.getOn(keys=keys0, ion=2) == ["x", "a"]
        assert niosuber.cntOn(keys=keys0, ion=2) == 2

        # ion = 3
        assert [val for val in niosuber.getOnIter(keys=keys0, ion=3)] == ["a"]
        assert niosuber.getOn(keys=keys0, ion=3) == ["a"]
        assert niosuber.cntOn(keys=keys0, ion=3) == 1

        # ion = 4  past end of keys0 set
        assert [val for val in niosuber.getOnIter(keys=keys0, ion=4)] == []
        assert niosuber.getOn(keys=keys0, ion=4) == []
        assert niosuber.cntOn(keys=keys0, ion=4) == 0

        # keys1
        # ion default 0
        assert [val for val in niosuber.getOnIter(keys=keys1)] == vals1
        assert niosuber.getOn(keys=keys1) == vals1
        assert niosuber.cntOn(keys=keys1) == 4
        assert niosuber.getOnLastItem(keys=keys1) == (keys1, 0, "d")
        assert niosuber.getOnLast(keys=keys1) == "d"

        # ion = 2
        assert [val for val in niosuber.getOnIter(keys=keys1, ion=2)] == ["y", "d"]
        assert niosuber.getOn(keys=keys1, ion=2) == ["y", "d"]
        assert niosuber.cntOn(keys=keys1, ion=2) == 2

        # keys0 make gap keys0
        assert niosuber.remOn(keys=keys0, val="m")

        # ion default 0, on default 0
        assert [val for val in niosuber.getOnIter(keys=keys0)] == ["z", "x", "a"]
        assert niosuber.getOn(keys=keys0) == ["z", "x", "a"]
        assert niosuber.cntOn(keys=keys0) == 3
        assert niosuber.getOnLastItem(keys=keys0) == (keys0, 0, "a")
        assert niosuber.getOnLast(keys=keys0) == "a"

        # ion = 1
        assert [val for val in niosuber.getOnIter(keys=keys0, on=0, ion=1)] == ["x", "a"]
        assert niosuber.getOn(keys=keys0,on=0, ion=1) == ["x", "a"]
        assert niosuber.cntOn(keys=keys0, on=0, ion=1) == 2

        # clear keys0 and keys1
        assert niosuber.remOn(keys=keys0) # default on = 0
        assert niosuber.remOn(keys=keys1, on=0)
        assert niosuber.cntOn(keys=keys0) == 0
        assert niosuber.cntOn(keys=keys1) == 0

        # restore key0, keys1 using add
        for val in vals0:
            assert niosuber.addOn(keys0, val=val)  # default on=0
        assert niosuber.getOn(keys0, on=0) == vals0

        for val in vals1:
            assert niosuber.addOn(keys1, on=0, val=val)
        assert niosuber.getOn(keys1, on=0) == vals1

        # test pinOn and appendOn
        assert not niosuber.getOn(keys3, on=0)
        assert niosuber.putOn(keys3, vals=vals3)  # default on = 0
        assert niosuber.getOn(keys3, on=0) == vals3
        assert not niosuber.addOn(keys3, val='k')  # idempotent wont add if already there
        assert niosuber.getOn(keys3, on=0) == vals3
        assert niosuber.addOn(keys3, on=0, val='g')
        assert niosuber.getOn(keys3, on=0) == ['k', 'j', 'l', 'g']
        assert niosuber.pinOn(keys3, vals=vals3)  # default on=0
        assert niosuber.getOn(keys3, on=0) == vals3

        assert niosuber.addOn(keys3, on=1, val='z')
        assert niosuber.addOn(keys3, on=1, val='y')
        assert niosuber.putOn(keys3, on=2, vals=["x", "w"])
        assert niosuber.appendOn(keys3, vals=["v", "u"]) == 3  # on = 3
        assert niosuber.appendOn(keys3, vals="t") == 4  # on = 4

        assert niosuber.cntOnAll(keys3, on=0) == 10
        assert niosuber.cntOnAll(keys3, on=2) == 5

        assert [item for item in niosuber.getOnAllItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [item for item in niosuber.getOnAllItemIter(keys3, on=3)] == \
        [
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        # getOnItemIter
        with pytest.raises(TypeError):
            [item for item in niosuber.getOnItemIter()]

        assert [item for item in niosuber.getOnItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
        ]

        assert [item for item in niosuber.getOnItemIter(keys3, on=3)] == \
        [
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
        ]

        assert niosuber.remOnAll(keys3, on=2)

        assert [item for item in niosuber.getOnItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
        ]

        assert niosuber.remOnAll(keys3, on=0)
        assert [item for item in niosuber.getOnAllItemIter(keys3)] == []

        assert niosuber.putOn(keys3, vals=vals3)  # default on = 0
        assert niosuber.putOn(keys3, on=1, vals=['z', 'y'])
        assert niosuber.putOn(keys3, on=2, vals=["x", "w"])
        assert niosuber.appendOn(keys3, vals=["v", "u"]) == 3  # on = 3
        assert niosuber.appendOn(keys3, vals="t") == 4  # on = 4

        assert [item for item in niosuber.getOnAllItemIter()] == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a'),
            (('B', 'C'), 0, 'w'),
            (('B', 'C'), 0, 'n'),
            (('B', 'C'), 0, 'y'),
            (('B', 'C'), 0, 'd'),
            (('C', 'D'), 0, 'p'),
            (('C', 'D'), 0, 'o'),
            (('C', 'D'), 0, 'h'),
            (('C', 'D'), 0, 'f'),
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in niosuber.getOnAllIter()] == \
        ['z','m','x','a','w','n','y','d','p','o','h','f','k','j','l','z','y','x','w','v','u','t']

        assert [item for item in niosuber.getOnAllItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in niosuber.getOnAllIter(keys3)] == \
        ['k', 'j', 'l', 'z', 'y', 'x', 'w', 'v', 'u', 't']

        assert [item for item in niosuber.getOnAllItemIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in niosuber.getOnAllIter(keys3, on=2)] == \
        ['x', 'w', 'v', 'u', 't']


        assert [item for item in niosuber.getOnTopItemIter()] == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a'),
            (('B', 'C'), 0, 'w'),
            (('B', 'C'), 0, 'n'),
            (('B', 'C'), 0, 'y'),
            (('B', 'C'), 0, 'd'),
            (('C', 'D'), 0, 'p'),
            (('C', 'D'), 0, 'o'),
            (('C', 'D'), 0, 'h'),
            (('C', 'D'), 0, 'f'),
            (('E', 'F'), 0, 'k'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [item for item in niosuber.getOnTopItemIter(keys=("A", ))] == \
        [
            (('A', 'B'), 0, 'z'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'a')
        ]

        # Test last iter   getOnAllLastItemIter
        # whole db
        assert [item for item in niosuber.getOnAllLastItemIter()] == \
        [
            (('A', 'B'), 0, 'a'),
            (('B', 'C'), 0, 'd'),
            (('C', 'D'), 0, 'f'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in niosuber.getOnAllLastIter()] == \
        ['a', 'd', 'f', 'l', 'y', 'w', 'u', 't']

        # all on for keys3
        assert [item for item in niosuber.getOnAllLastItemIter(keys3)] == \
        [
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in niosuber.getOnAllLastIter(keys3)] == \
        ['l', 'y', 'w', 'u', 't']

        # all on>=2 for keys3
        assert [item for item in niosuber.getOnAllLastItemIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 4, 't')
        ]

        assert [val for val in niosuber.getOnAllLastIter(keys3, on=2)] == \
        ['w', 'u', 't']


        # Test back iter
        # whole db
        assert [item for item in niosuber.getOnAllItemBackIter()] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'k'),
            (('C', 'D'), 0, 'f'),
            (('C', 'D'), 0, 'h'),
            (('C', 'D'), 0, 'o'),
            (('C', 'D'), 0, 'p'),
            (('B', 'C'), 0, 'd'),
            (('B', 'C'), 0, 'y'),
            (('B', 'C'), 0, 'n'),
            (('B', 'C'), 0, 'w'),
            (('A', 'B'), 0, 'a'),
            (('A', 'B'), 0, 'x'),
            (('A', 'B'), 0, 'm'),
            (('A', 'B'), 0, 'z')
        ]

        assert [val for val in niosuber.getOnAllBackIter()] == \
        ['t','u','v','w','x','y','z','l','j','k','f','h','o','p','d','y','n','w','a','x','m','z']

        # keys3  all on
        assert [item for item in niosuber.getOnAllItemBackIter(keys3)] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 3, 'v'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'k'),
        ]

        assert [val for val in niosuber.getOnAllBackIter(keys3)] == \
        ['t','u','v','w','x','y','z','l','j','k']

        # keys3  on <= 2
        assert [item for item in niosuber.getOnAllItemBackIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 2, 'x'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 1, 'z'),
            (('E', 'F'), 0, 'l'),
            (('E', 'F'), 0, 'j'),
            (('E', 'F'), 0, 'k'),
        ]

        assert [val for val in niosuber.getOnAllBackIter(keys3, on=2)] == \
        ['w','x','y','z','l','j','k']


        # Test last back iter
        # whole db
        assert [item for item in niosuber.getOnAllLastItemBackIter()] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 0, 'l'),
            (('C', 'D'), 0, 'f'),
            (('B', 'C'), 0, 'd'),
            (('A', 'B'), 0, 'a')
        ]

        assert [val for val in niosuber.getOnAllLastBackIter()] == \
        ['t', 'u', 'w', 'y', 'l', 'f', 'd', 'a']

        # keys3  all on
        assert [item for item in niosuber.getOnAllLastItemBackIter(keys3)] == \
        [
            (('E', 'F'), 4, 't'),
            (('E', 'F'), 3, 'u'),
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 0, 'l')
        ]

        assert [val for val in niosuber.getOnAllLastBackIter(keys3)] == \
        ['t', 'u', 'w', 'y', 'l']

        # keys3  on <= 2
        assert [item for item in niosuber.getOnAllLastItemBackIter(keys3, on=2)] == \
        [
            (('E', 'F'), 2, 'w'),
            (('E', 'F'), 1, 'y'),
            (('E', 'F'), 0, 'l')
        ]

        assert [val for val in niosuber.getOnAllLastBackIter(keys3, on=2)] == \
        ['w', 'y', 'l']


        """Done Test"""


def test_b64_onioset_suber():
    """
    Test B64OnIoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        oisbuber = subing.B64OnIoSetSuber(db=db, subkey='bags.')
        assert isinstance(oisbuber, subing.B64OnIoSetSuber)
        assert not oisbuber.sdb.flags()["dupsort"]

        k = "a"
        j = "b"

        w = ("Blue", "dog")
        x = ("Green", "tree")
        y = "Red"
        z = ("White",)

        # test addOn remOn
        assert oisbuber.addOn(keys=k, on=0, val=w)
        assert oisbuber.getOn(keys=k, on=0) == [w, ]
        assert oisbuber.getOn(keys=k, on=0) == [('Blue', 'dog'),]
        assert oisbuber.addOn(keys=k, on=0, val=x)
        assert oisbuber.getOn(keys=k, on=0) == [w, x]
        assert oisbuber.getOn(keys=k, on=0) == [('Blue', 'dog'), ('Green', 'tree')]
        assert oisbuber.addOn(keys=k, on=1, val=y)
        assert oisbuber.getOn(keys=k, on=1) == [(y,), ]
        assert oisbuber.getOn(keys=k, on=1) == [('Red',),]
        assert oisbuber.addOn(keys=k, on=1, val=z)
        assert oisbuber.getOn(keys=k, on=1) == [(y,), z]
        assert oisbuber.getOn(keys=k, on=1) == [('Red',), ('White',)]

        assert oisbuber.getOn(keys=k, on=0) == [w, x]

        assert oisbuber.cntOnAll(keys=(k,)) == 4

        items = [item for item in oisbuber.getOnAllItemIter(keys=k)]
        assert items == [(('a',), 0, ('Blue', 'dog')),
                            (('a',), 0, ('Green', 'tree')),
                            (('a',), 1, ('Red',)),
                            (('a',), 1, ('White',))]

        assert oisbuber.remOn(keys=k, on=0, val=w)
        assert oisbuber.remOn(keys=k, on=1)
        items = [item for item in oisbuber.getOnAllItemIter(keys=k)]
        assert items == [(('a',), 0, ('Green', 'tree'))]

        assert oisbuber.remOn(keys=k, on=0, val=x)
        assert oisbuber.cntOnAll() == 0
        assert oisbuber.cntOnAll(keys=k) == 0
        assert oisbuber.cntOnAll(keys=(k,)) == 0

        # test append
        assert 0 == oisbuber.appendOn(keys=(j,), vals=(w, ))
        assert 1 == oisbuber.appendOn(keys=(j,), vals=(x, ))
        assert 2 == oisbuber.appendOn(keys=(j,), vals=(y, ))
        assert 3 == oisbuber.appendOn(keys=(j,), vals=(z, ))

        assert oisbuber.cntOnAll() == 4
        assert oisbuber.cntOnAll(keys=j) == 4
        assert oisbuber.cntOnAll(keys=(j,)) == 4
        assert oisbuber.cntOnAll(keys=(j,), on=2) == 2
        assert oisbuber.cntOnAll(keys=(j,), on=4) == 0

        items = [(keys, on, val) for keys, on, val in oisbuber.getOnTopItemIter()]
        assert items == \
        [
            (('b',), 0, ('Blue', 'dog')),
            (('b',), 1, ('Green', 'tree')),
            (('b',), 2, ('Red',)),
            (('b',), 3, ('White',))
        ]

        # test getOnAllIter
        vals = [val for val in oisbuber.getOnAllIter(keys=j)]
        assert vals == [w, x, (y,), z]

        vals = [val for val in oisbuber.getOnAllIter(keys=j, on=2)]
        assert vals == [(y,), z]

        # test getOnAllItemIter
        items = [item for item in oisbuber.getOnAllItemIter(keys=j)]
        assert items == [(('b',), 0, ('Blue', 'dog')),
                            (('b',), 1, ('Green', 'tree')),
                            (('b',), 2, ('Red',)),
                            (('b',), 3, ('White',))]


        items = [item for item in oisbuber.getOnAllItemIter(keys=j, on=2)]
        assert items == [(('b',), 2, ('Red',)), (('b',), 3, ('White',))]

        # test add (add a value already in db)
        assert oisbuber.addOn(keys=k, on=0, val=w)
        assert not oisbuber.addOn(keys=k, on=0, val=w)
        assert oisbuber.addOn(keys=k, on=1, val=x)
        assert not oisbuber.addOn(keys=k, on=1, val=x)
        assert oisbuber.addOn(keys="ac",on=0, val=z)
        assert not oisbuber.addOn(keys="ac",on=0, val=z)
        assert oisbuber.addOn(keys="bc", on=0, val=y)
        assert not oisbuber.addOn(keys="bc", on=0, val=y)
        assert oisbuber.addOn(keys="bc",on=1, val=z)
        assert not oisbuber.addOn(keys="bc",on=1, val=z)

        # test getOnAllItemIter
        items = [item for item in oisbuber.getOnAllItemIter(keys=k)]
        assert items == \
        [
            (('a',), 0, ('Blue', 'dog')),
            (('a',), 1, ('Green', 'tree'))
        ]

        assert oisbuber.cntOnAll(keys=k) == 2
        assert oisbuber.cntOnAll(keys=(k,)) == 2
        assert oisbuber.cntOnAll(keys=("bc",), on=2) == 0
        assert oisbuber.cntOnAll(keys="") == 9

        items = [(keys, on, val) for keys, on, val in oisbuber.getOnTopItemIter()]
        assert items == \
        [
            (('a',), 0, ('Blue', 'dog')),
            (('a',), 1, ('Green', 'tree')),
            (('ac',), 0, ('White',)),
            (('b',), 0, ('Blue', 'dog')),
            (('b',), 1, ('Green', 'tree')),
            (('b',), 2, ('Red',)),
            (('b',), 3, ('White',)),
            (('bc',), 0, ('Red',)),
            (('bc',), 1, ('White',))
        ]

        items = [(keys, val) for keys, val in oisbuber.getFullItemIter()]
        assert items == \
        [
            (('a', '00000000000000000000000000000000', '00000000000000000000000000000000'), ('Blue', 'dog')),
            (('a', '00000000000000000000000000000001', '00000000000000000000000000000000'), ('Green', 'tree')),
            (('ac', '00000000000000000000000000000000', '00000000000000000000000000000000'), ('White',)),
            (('b', '00000000000000000000000000000000', '00000000000000000000000000000000'), ('Blue', 'dog')),
            (('b', '00000000000000000000000000000001', '00000000000000000000000000000000'), ('Green', 'tree')),
            (('b', '00000000000000000000000000000002', '00000000000000000000000000000000'), ('Red',)),
            (('b', '00000000000000000000000000000003', '00000000000000000000000000000000'), ('White',)),
            (('bc', '00000000000000000000000000000000', '00000000000000000000000000000000'), ('Red',)),
            (('bc', '00000000000000000000000000000001', '00000000000000000000000000000000'), ('White',))]

        # test getOnAllItemIter   getOnIterAll
        items = [item for item in oisbuber.getOnAllItemIter(keys=k)]
        assert items == [(('a',), 0, ('Blue', 'dog')), (('a',), 1, ('Green', 'tree'))]

        vals = [val for val in oisbuber.getOnAllIter(keys=k)]
        assert vals == [('Blue', 'dog'), ('Green', 'tree')]

        vals = [val for val in oisbuber.getOnAllIter(keys=(k, ))]
        assert vals == [('Blue', 'dog'), ('Green', 'tree')]

        items = [item for item in oisbuber.getOnAllItemIter(keys=(k, ))]
        assert items == [(('a',), 0, ('Blue', 'dog')),
                         (('a',), 1, ('Green', 'tree'))]

        items = [item for item in oisbuber.getOnAllItemIter(keys=(k, ""))]
        assert items == []

        vals = [val for val in oisbuber.getOnAllIter(keys=(k, ""))]
        assert vals == []

        items = [item for item in oisbuber.getOnAllItemIter(keys='')]
        assert items == \
        [
            (('a',), 0, ('Blue', 'dog')),
            (('a',), 1, ('Green', 'tree')),
            (('ac',), 0, ('White',)),
            (('b',), 0, ('Blue', 'dog')),
            (('b',), 1, ('Green', 'tree')),
            (('b',), 2, ('Red',)),
            (('b',), 3, ('White',)),
            (('bc',), 0, ('Red',)),
            (('bc',), 1, ('White',))
        ]

        vals = [val for val in oisbuber.getOnAllIter(keys='')]
        assert vals == \
        [
            ('Blue', 'dog'),
            ('Green', 'tree'),
            ('White',),
            ('Blue', 'dog'),
            ('Green', 'tree'),
            ('Red',),
            ('White',),
            ('Red',),
            ('White',)
        ]


        # test with sets ordinal
        assert oisbuber.addOn(keys=j, on=0, val=z)
        assert oisbuber.addOn(keys=j, on=1, val=y)
        assert oisbuber.addOn(keys=j, on=2, val=x)
        assert oisbuber.addOn(keys=j, on=3, val=w)

        assert oisbuber.cntOnAll(keys=j) == 8
        assert oisbuber.cntOnAll(keys=j, on=2) == 4
        assert oisbuber.cntOnAll(keys=j, on=4) == 0

        items = [(keys, on, val) for keys, on, val in oisbuber.getOnTopItemIter(keys=j)]
        assert items == \
        [
            (('b',), 0, ('Blue', 'dog')),
            (('b',), 0, ('White',)),
            (('b',), 1, ('Green', 'tree')),
            (('b',), 1, ('Red',)),
            (('b',), 2, ('Red',)),
            (('b',), 2, ('Green', 'tree')),
            (('b',), 3, ('White',)),
            (('b',), 3, ('Blue', 'dog')),
            (('bc',), 0, ('Red',)),
            (('bc',), 1, ('White',))
        ]

        # test getOnAllItemIter getOnIterAll getOnItemBackIter getOnBackIter
        items = [item for item in oisbuber.getOnAllItemIter(keys=j)]
        assert items == [(('b',), 0, ('Blue', 'dog')),
                            (('b',), 0, ('White',)),
                            (('b',), 1, ('Green', 'tree')),
                            (('b',), 1, ('Red',)),
                            (('b',), 2, ('Red',)),
                            (('b',), 2, ('Green', 'tree')),
                            (('b',), 3, ('White',)),
                            (('b',), 3, ('Blue', 'dog'))]

        vals = [val for val in oisbuber.getOnAllIter(keys=j)]
        assert vals == [('Blue', 'dog'),
                        ('White',),
                        ('Green', 'tree'),
                        ('Red',),
                        ('Red',),
                        ('Green', 'tree'),
                        ('White',),
                        ('Blue', 'dog')]

        items = [item for item in oisbuber.getOnAllItemIter(keys=j, on=2)]
        assert items ==[(('b',), 2, ('Red',)),
                        (('b',), 2, ('Green', 'tree')),
                        (('b',), 3, ('White',)),
                        (('b',), 3, ('Blue', 'dog'))]


        vals = [val for val in oisbuber.getOnAllIter(keys=j, on=2)]
        assert vals == [('Red',), ('Green', 'tree'), ('White',), ('Blue', 'dog')]

        items = [item for item in oisbuber.getOnAllItemBackIter(keys=j, on=4)]
        assert items == [(('b',), 3, ('Blue', 'dog')),
                        (('b',), 3, ('White',)),
                        (('b',), 2, ('Green', 'tree')),
                        (('b',), 2, ('Red',)),
                        (('b',), 1, ('Red',)),
                        (('b',), 1, ('Green', 'tree')),
                        (('b',), 0, ('White',)),
                        (('b',), 0, ('Blue', 'dog'))]


        vals = [val for val in oisbuber.getOnAllBackIter(keys=j, on=4)]
        assert vals == [('Blue', 'dog'),
                        ('White',),
                        ('Green', 'tree'),
                        ('Red',),
                        ('Red',),
                        ('Green', 'tree'),
                        ('White',),
                        ('Blue', 'dog')]


        items = [item for item in oisbuber.getOnAllItemBackIter(keys=j, on=1)]
        assert items ==[(('b',), 1, ('Red',)),
                        (('b',), 1, ('Green', 'tree')),
                        (('b',), 0, ('White',)),
                        (('b',), 0, ('Blue', 'dog'))]

        vals = [val for val in oisbuber.getOnAllBackIter(keys=j, on=1)]
        assert vals == [('Red',), ('Green', 'tree'), ('White',), ('Blue', 'dog')]

        # test append with duplicates
        assert 4 == oisbuber.appendOn(keys=j, vals=(x, ))
        assert oisbuber.cntOnAll(keys=j) == 9

        # test remove
        assert oisbuber.remOn(keys=j, on=1)
        assert not oisbuber.remOn(keys=j, on=1)
        assert oisbuber.remOn(keys=j, on=3)
        assert not oisbuber.remOn(keys=j, on=3)

        assert oisbuber.cntOnAll(keys=j) == 5

        items = [item for item in oisbuber.getOnAllItemIter(keys=j)]
        assert items == [(('b',), 0, ('Blue', 'dog')),
                        (('b',), 0, ('White',)),
                        (('b',), 2, ('Red',)),
                        (('b',), 2, ('Green', 'tree')),
                        (('b',), 4, ('Green', 'tree'))]

        vals = [val for val in oisbuber.getOnAllIter(keys=j)]
        assert vals == [('Blue', 'dog'),
                        ('White',),
                        ('Red',),
                        ('Green', 'tree'),
                        ('Green', 'tree')]

        # test putOn and pinOn
        o = ("moon", "beam")
        p = ("sun", "spot")
        q = [("moon", "beam"), ]
        r = ("stars", )
        s = ("moon", )
        t = ("sun",)
        u = (("sun", "spot"), "sun")
        v = ("moon", ("stars", ))


        assert oisbuber.putOn(keys='d', on=0, vals=q)
        assert oisbuber.getOn(keys='d', on=0) == [("moon", "beam"), ]
        assert oisbuber.getOn(keys='d', on=0) == q
        assert not oisbuber.putOn(keys='d', on=0, vals=q)
        assert oisbuber.putOn(keys='d', on=0, vals=r)
        assert oisbuber.putOn(keys='d', on=0, vals=s)
        assert oisbuber.putOn(keys='d', on=0, vals=t)
        assert oisbuber.getOn(keys='d', on=0) == [('moon', 'beam'), ('stars',), ('moon',), ('sun',)]
        assert oisbuber.getOn(keys='d', on=0) == [o, r, s, t]
        assert not oisbuber.putOn(keys='d', on=0, vals=(o, r, s, t))
        assert oisbuber.pinOn(keys='d', on=0, vals=u)
        assert oisbuber.getOn(keys='d', on=0) == [('sun', 'spot'), ('sun',)]
        assert oisbuber.getOn(keys='d', on=0) == [p, t]
        assert oisbuber.putOn(keys='d', on=0, vals=v)
        assert oisbuber.getOn(keys='d', on=0) == [('sun', 'spot'), ('sun',), ('moon',), ('stars',)]
        assert oisbuber.getOn(keys='d', on=0) == [p, t, s, r]
        assert oisbuber.remOn(keys='d', on=0)
        assert oisbuber.getOn(keys='d', on=0) == []

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

        serber = subing.SerderSuber(db=db, subkey='bags.')
        assert isinstance(serber, subing.SerderSuber)
        assert not serber.sdb.flags()["dupsort"]
        assert serber.klas == serdering.SerderKERI

        pre = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        srdr0 = eventing.incept(keys=[pre])

        keys = (pre, srdr0.said)
        serber.put(keys=keys, val=srdr0)
        actual = serber.get(keys=keys)
        assert isinstance(actual, serdering.SerderKERI)
        assert actual.said == srdr0.said

        assert serber.rem(keys)
        actual = serber.get(keys=keys)
        assert actual is None

        serber.put(keys=keys, val=srdr0)
        actual = serber.get(keys=keys)
        assert isinstance(actual, serdering.SerderKERI)
        assert actual.said == srdr0.said

        srdr1 = eventing.rotate(pre=pre, keys=[pre], dig=srdr0.said)
        result = serber.put(keys=keys, val=srdr1)
        assert not result
        actual = serber.get(keys=keys)
        assert isinstance(actual, serdering.SerderKERI)
        assert actual.said == srdr0.said

        result = serber.pin(keys=keys, val=srdr1)
        assert result
        actual = serber.get(keys=keys)
        assert isinstance(actual, serdering.SerderKERI)
        assert actual.said == srdr1.said

        # test with keys as string not tuple
        keys = "{}.{}".format(pre, srdr1.said)

        serber.put(keys=keys, val=srdr1)
        actual = serber.get(keys=keys)
        assert isinstance(actual, serdering.SerderKERI)
        assert actual.said == srdr1.said

        assert serber.rem(keys)
        actual = serber.get(keys=keys)
        assert actual is None

        # test missing entry at keys
        badkey = "badkey"
        actual = serber.get(badkey)
        assert actual is None

        # test iteritems
        serber = subing.SerderSuber(db=db, subkey='pugs.')
        assert isinstance(serber, subing.SerderSuber)
        serber.put(keys=("a","1"), val=srdr0)
        serber.put(keys=("a","2"), val=srdr1)

        items = [(keys, srdr.said) for keys, srdr in serber.getItemIter()]
        assert items == [(('a', '1'), srdr0.said),
                         (('a', '2'), srdr1.said)]

        assert serber.put(keys=("b","1"), val=srdr0)
        assert serber.put(keys=("b","2"), val=srdr1)
        assert serber.put(keys=("bc","1"), val=srdr0)

        topkeys =  ("b", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.said) for keys, srdr in serber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), srdr0.said),
                         (('b', '2'), srdr1.said)]

    assert not os.path.exists(db.path)
    assert not db.opened

def test_serder_ioset_suber():
    """
    Test SerderIoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        serber = subing.SerderIoSetSuber(db=db, subkey='bags.')
        assert isinstance(serber, subing.SerderIoSetSuber)
        assert not serber.sdb.flags()["dupsort"]
        assert serber.klas == serdering.SerderKERI

        pre = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        srdr0 = eventing.incept(keys=[pre])

        keys = (pre, srdr0.said)
        serber.put(keys=keys, vals=(srdr0, ))
        actuals = serber.get(keys=keys)
        for actual in actuals:
            assert isinstance(actual, serdering.SerderKERI)
            assert actual.said == srdr0.said

        assert serber.rem(keys)
        actuals = serber.get(keys=keys)
        assert not actuals  # empty list

        serber.put(keys=keys, vals=(srdr0, ))
        actuals = serber.get(keys=keys)
        for actual in actuals:
            assert isinstance(actual, serdering.SerderKERI)
            assert actual.said == srdr0.said

        srdr1 = eventing.rotate(pre=pre, keys=[pre], dig=srdr0.said)

        result = serber.put(keys=keys, vals=(srdr1, ))
        assert result
        actuals = serber.get(keys=keys)
        assert isinstance(actuals[0], serdering.SerderKERI)
        assert actuals[0].said == srdr0.said
        assert isinstance(actuals[1], serdering.SerderKERI)
        assert actuals[1].said == srdr1.said


        result = serber.pin(keys=keys, vals=(srdr1, ))
        assert result
        actuals = serber.get(keys=keys)
        for actual in actuals:
            assert isinstance(actual, serdering.SerderKERI)
            assert actual.said == srdr1.said


        # test rem a specific value
        serber.put(keys=keys, vals=(srdr0, ))
        actuals = serber.get(keys=keys)
        assert isinstance(actuals[0], serdering.SerderKERI)
        assert actuals[0].said == srdr1.said
        assert isinstance(actuals[1], serdering.SerderKERI)
        assert actuals[1].said == srdr0.said

        assert serber.rem(keys=keys, val=srdr1)
        actuals = serber.get(keys=keys)
        assert len(actuals) == 1
        assert isinstance(actuals[0], serdering.SerderKERI)
        assert actuals[0].said == srdr0.said


        # test with keys as string not tuple
        keys = "{}.{}".format(pre, srdr1.said)

        serber.put(keys=keys, vals=(srdr1, ))
        actuals = serber.get(keys=keys)
        for actual in actuals:
            assert isinstance(actual, serdering.SerderKERI)
            assert actual.said == srdr1.said

        assert serber.rem(keys)
        actuals = serber.get(keys=keys)
        assert not actuals

        # test missing entry at keys
        badkey = "badkey"
        actuals = serber.get(badkey)
        assert not actuals

        # test iteritems
        serber = subing.SerderIoSetSuber(db=db, subkey='pugs.')
        assert isinstance(serber, subing.SerderIoSetSuber)
        serber.put(keys=("a","1"), vals=(srdr0, ))
        serber.put(keys=("a","1"), vals=(srdr1, ))
        serber.put(keys=("a","2"), vals=(srdr1, ))

        items = [(keys, srdr.said) for keys, srdr in serber.getItemIter()]
        assert items == [
                            (('a', '1'), srdr0.said),
                            (('a', '1'), srdr1.said),
                            (('a', '2'), srdr1.said),
                        ]

        assert serber.put(keys=("b","1"), vals=(srdr0, ))
        assert serber.put(keys=("b","2"), vals=(srdr1, ))
        assert serber.put(keys=("bc","1"), vals=(srdr0, ))

        topkeys =  ("b", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.said) for keys, srdr in serber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), srdr0.said),
                         (('b', '2'), srdr1.said)]

    assert not os.path.exists(db.path)
    assert not db.opened


def test_schemer_suber():
    """
    Test SchemerSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        scmber = subing.SchemerSuber(db=db, subkey='bags.')
        assert isinstance(scmber, subing.SchemerSuber)
        assert not scmber.sdb.flags()["dupsort"]
        assert scmber.klas == scheming.Schemer

        pre = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"

        raw0 = (b'{"$id":"EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw","$schema":"http://json'
                b'-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"str'
                b'ing"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}')

        scmr0 = scheming.Schemer(raw=raw0)

        keys = (pre, scmr0.said)
        scmber.put(keys=keys, val=scmr0)
        actual = scmber.get(keys=keys)
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == scmr0.said

        assert scmber.rem(keys)
        actual = scmber.get(keys=keys)
        assert actual is None

        scmber.put(keys=keys, val=scmr0)
        actual = scmber.get(keys=keys)
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == scmr0.said

        raw1 = (b'{"$id":"ENQKl3r1Z6HiLXOD-050aVvKziCWJtXWg3vY2FWUGSxG","$schema":"http://json'
         b'-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"obj'
         b'ect","properties":{"b":{"type":"number"},"c":{"type":"string","format":"date'
         b'-time"}}}}}')
        scmr1 = scheming.Schemer(raw=raw1)

        result = scmber.put(keys=keys, val=scmr1)
        assert not result
        actual = scmber.get(keys=keys)
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == scmr0.said

        result = scmber.pin(keys=keys, val=scmr1)
        assert result
        actual = scmber.get(keys=keys)
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == scmr1.said

        # test with keys as string not tuple
        keys = "{}.{}".format(pre, scmr1.said)

        scmber.put(keys=keys, val=scmr1)
        actual = scmber.get(keys=keys)
        assert isinstance(actual, scheming.Schemer)
        assert actual.said == scmr1.said

        assert scmber.rem(keys)
        actual = scmber.get(keys=keys)
        assert actual is None

        # test missing entry at keys
        badkey = "badkey"
        actual = scmber.get(badkey)
        assert actual is None

        # test iteritems
        scmber = subing.SchemerSuber(db=db, subkey='pugs.')
        assert isinstance(scmber, subing.SchemerSuber)
        scmber.put(keys=("a","1"), val=scmr0)
        scmber.put(keys=("a","2"), val=scmr1)

        items = [(keys, srdr.said) for keys, srdr in scmber.getItemIter()]
        assert items == [(('a', '1'), scmr0.said),
                         (('a', '2'), scmr1.said)]

        assert scmber.put(keys=("b","1"), val=scmr0)
        assert scmber.put(keys=("b","2"), val=scmr1)
        assert scmber.put(keys=("bc","1"), val=scmr0)

        topkeys =  ("b", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.said) for keys, srdr in scmber.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), scmr0.said),
                         (('b', '2'), scmr1.said)]

        with pytest.raises(TypeError):
            scmber = subing.SchemerSuber(db=db, subkey='bags.', klas=coring.Matter)


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

        pre0 = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
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

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter()]
        assert items == [(('a', '1'), val0.qb64),
                         (('a', '2'), val1.qb64)]

        #  Try other classs
        sdb = subing.CesrSuber(db=db, subkey='pigs.', klas=coring.Diger)
        assert isinstance(sdb, subing.CesrSuber)
        assert issubclass(sdb.klas, coring.Diger)

        dig0 = "EAPYGGwTmuupWzwEHHzq7K0gzUhPx5_yZ-Wk1x4ejhcc"
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

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter()]
        assert items == [(('a', '1'), val0.qb64),
                         (('a', '2'), val1.qb64)]

        assert sdb.put(keys=("b","1"), val=val0)
        assert sdb.put(keys=("b","2"), val=val1)
        assert sdb.put(keys=("bc","1"), val=val0)

        topkeys =  ("b", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), val0.qb64),
                         (('b', '2'), val1.qb64)]

        # Try Siger Indexer Subclass
        sdb = subing.CesrSuber(db=db, subkey='pigs.', klas=indexing.Siger)
        assert isinstance(sdb, subing.CesrSuber)
        assert issubclass(sdb.klas, indexing.Siger)
        sig0 = 'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = indexing.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, indexing.Siger)
        assert actual.qb64 == val0.qb64


    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""


def test_cesr_suber_strict_subclass_enforcement():
    """
    Test CesrSuber strict mode enforces subclass checks in _ser
    """
    with dbing.openLMDB() as db:
        sdb = subing.CesrSuber(db=db, subkey='bags.', klas=coring.Diger, strict=True)
        assert isinstance(sdb, subing.CesrSuber)
        assert sdb.strict is True

        diger = coring.Diger(ser=b"strict cesr")
        keys = ("alpha", "dog")

        assert sdb.put(keys=keys, val=diger)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == diger.qb64

        wrong = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        with pytest.raises(TypeError):
            sdb.pin(keys=keys, val=wrong)

        with pytest.raises(TypeError):
            sdb.pin(keys=keys, val=diger.qb64b)

        with pytest.raises(TypeError):
            sdb.pin(keys=keys, val=diger.qb64)

        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == diger.qb64

    assert not os.path.exists(db.path)
    assert not db.opened


def test_cesr_on_suber():
    """
    Test CesrOnSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        onsuber = subing.CesrOnSuber(db=db, subkey='bags.')
        assert isinstance(onsuber, subing.CesrOnSuber)
        assert not onsuber.sdb.flags()["dupsort"]

        prew = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        w = coring.Matter(qb64=prew)
        prex = "BHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        x = coring.Matter(qb64=prex)
        prey = "EHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        y = coring.Matter(qb64=prey)
        prez = "EAPYGGwTmuupWzwEHHzq7K0gzUhPx5_yZ-Wk1x4ejhcc"
        z = coring.Matter(qb64=prez)


        # test append
        assert 0 == onsuber.appendOn(keys=("a",), val=w)
        assert 1 == onsuber.appendOn(keys=("a",), val=x)
        assert 2 == onsuber.appendOn(keys=("a",), val=y)
        assert 3 == onsuber.appendOn(keys=("a",), val=z)

        assert onsuber.cntOnAll(keys=("a",)) == 4
        assert onsuber.cntOnAll(keys=("a",), on=2) == 2
        assert onsuber.cntOnAll(keys=("a",), on=4) == 0

        items = [(keys, val.qb64) for keys, val in onsuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), w.qb64),
                        (('a', '00000000000000000000000000000001'), x.qb64),
                        (('a', '00000000000000000000000000000002'), y.qb64),
                        (('a', '00000000000000000000000000000003'), z.qb64)]

        # test getOnItemIterAll
        items = [(keys, on, val.qb64) for keys, on, val in onsuber.getOnItemIterAll(keys='a')]
        assert items == [(('a',), 0, w.qb64),
                        (('a',), 1, x.qb64),
                        (('a',), 2, y.qb64),
                        (('a',), 3, z.qb64)]

        items = [(keys, on, val.qb64) for keys, on, val in onsuber.getOnItemIterAll(keys='a', on=2)]
        assert items == [(('a',), 2, y.qb64),
                         (('a',), 3, z.qb64)]

        assert 0 == onsuber.appendOn(keys=("ac",), val=z)
        assert 0 == onsuber.appendOn(keys=("b",), val=w)
        assert 1 == onsuber.appendOn(keys=("b",), val=x)
        assert 0 == onsuber.appendOn(keys=("bc",), val=y)


        assert onsuber.cntOnAll(keys=("b",)) == 2
        assert onsuber.cntOnAll(keys=("ac",), on=2) == 0
        assert onsuber.cntOnAll(keys="") == 8

        items = [(keys, val.qb64) for keys, val in onsuber.getItemIter()]
        assert items == [(('a', '00000000000000000000000000000000'), w.qb64),
                        (('a', '00000000000000000000000000000001'), x.qb64),
                        (('a', '00000000000000000000000000000002'), y.qb64),
                        (('a', '00000000000000000000000000000003'), z.qb64),
                        (('ac', '00000000000000000000000000000000'), z.qb64),
                        (('b', '00000000000000000000000000000000'), w.qb64),
                        (('b', '00000000000000000000000000000001'), x.qb64),
                        (('bc', '00000000000000000000000000000000'), y.qb64)]

        # test getOnItemIterAll
        items = [(keys, on, val.qb64) for keys, on, val in onsuber.getOnItemIterAll(keys='b')]
        assert items == [(('b',), 0, w.qb64),
                         (('b',), 1, x.qb64)]

        items = [(keys, on, val.qb64) for keys, on, val in onsuber.getOnItemIterAll(keys=('b', ))]
        assert items == [(('b',), 0, w.qb64),
                         (('b',), 1, x.qb64)]

        items = [item for item in onsuber.getOnItemIterAll(keys=('b', ""))]
        assert items == []

        items = [(keys, on, val.qb64) for keys, on, val in onsuber.getOnItemIterAll(keys='')]
        assert items == [(('a',), 0, w.qb64),
                        (('a',), 1, x.qb64),
                        (('a',), 2, y.qb64),
                        (('a',), 3, z.qb64),
                        (('ac',), 0, z.qb64),
                        (('b',), 0, w.qb64),
                        (('b',), 1, x.qb64),
                        (('bc',), 0, y.qb64)]

        items = [(keys, on, val.qb64) for keys, on, val in onsuber.getOnItemIterAll()]
        assert items == [(('a',), 0, w.qb64),
                        (('a',), 1, x.qb64),
                        (('a',), 2, y.qb64),
                        (('a',), 3, z.qb64),
                        (('ac',), 0, z.qb64),
                        (('b',), 0, w.qb64),
                        (('b',), 1, x.qb64),
                        (('bc',), 0, y.qb64)]

    assert not os.path.exists(db.path)
    assert not db.opened



def test_cat_cesr_suber():
    """
    Test CatCesrSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        # Test Single klas
        sdb = subing.CatCesrSuber(db=db, subkey='bags.')  # default klas is [Matter]
        assert isinstance(sdb, subing.CatCesrSuber)
        assert len(sdb.klas) == 1
        assert issubclass(sdb.klas[0], coring.Matter)
        assert not sdb.sdb.flags()["dupsort"]

        matb0 = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
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
                                       for keys, vals in sdb.getItemIter()]
        assert items == [(('alpha', 'dog'), [matter0.qb64]),
                         (('beta', 'fish'), [matter1.qb64])]

        sdb.put(keys=("b","1"), val=vals0)
        sdb.put(keys=("b","2"), val=vals1)
        sdb.put(keys=("c","1"), val=vals0)
        sdb.put(keys=("c","2"), val=vals1)

        topkeys = ("b","")  # last element empty to force trailing separator
        items = [(keys, [val.qb64 for val in vals])
                            for keys, vals in  sdb.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), [matter0.qb64]),
                         (('b', '2'), [matter1.qb64])]

        # Test multiple klases
        klases = (coring.Dater, coring.Seqner, coring.Diger)
        sdb = subing.CatCesrSuber(db=db, subkey='bags.', klas=klases)
        assert isinstance(sdb, subing.CatCesrSuber)
        for klas, sklas in zip(klases, sdb.klas):
            assert klas == sklas
        assert not sdb.sdb.flags()["dupsort"]


        dater = coring.Dater(dts="2021-01-01T00:00:00.000000+00:00")
        datb = dater.qb64b
        assert datb == b'1AAG2021-01-01T00c00c00d000000p00c00'

        seqner = coring.Seqner(sn=20)
        seqb = seqner.qb64b
        assert seqb == b'0AAAAAAAAAAAAAAAAAAAAAAU'

        diger = coring.Diger(ser=b"Hello Me Maties.")
        digb = diger.qb64b
        assert digb == b'ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ'

        vals = (dater, seqner, diger)
        valb = sdb._ser(val=vals)
        assert  valb == datb + seqb + digb

        vals = sdb._des(val=valb)
        assert b"".join(val.qb64b for val in vals) == valb
        for val, klas in zip(vals, sdb.klas):
            assert isinstance(val, klas)

        # Try Siger Indexer Subclass
        sdb = subing.CatCesrSuber(db=db, subkey='pigs.', klas=(indexing.Siger, ))
        assert isinstance(sdb, subing.CatCesrSuber)
        assert issubclass(sdb.klas[0], indexing.Siger)
        sig0 = 'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = indexing.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, val=[val0])
        actual = sdb.get(keys=keys)
        assert isinstance(actual[0], indexing.Siger)
        assert actual[0].qb64 == val0.qb64

    assert not os.path.exists(db.path)
    assert not db.opened
    """Done Test"""


def test_cat_cesr_suber_strict_subclass_enforcement():
    """
    Test CatCesrSuber strict mode enforces ordered subclass checks in _ser
    """
    with dbing.openLMDB() as db:
        klases = (coring.Seqner, coring.Saider)
        sdb = subing.CatCesrSuber(db=db, subkey='bags.', klas=klases, strict=True)
        assert isinstance(sdb, subing.CatCesrSuber)
        assert sdb.strict is True

        seqner = coring.Seqner(sn=1)
        saider = coring.Saider(qb64b=b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E')
        keys = ("alpha", "dog")

        assert sdb.put(keys=keys, val=(seqner, saider))
        actuals = sdb.get(keys=keys)
        assert isinstance(actuals[0], coring.Seqner)
        assert isinstance(actuals[1], coring.Saider)
        assert actuals[0].qb64 == seqner.qb64
        assert actuals[1].qb64 == saider.qb64

        with pytest.raises(ValueError):
            sdb.pin(keys=keys, val=(seqner, ))

        actuals = sdb.get(keys=keys)
        assert actuals[0].qb64 == seqner.qb64
        assert actuals[1].qb64 == saider.qb64

        wrong = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        with pytest.raises(TypeError):
            sdb.pin(keys=keys, val=(wrong, saider))

        with pytest.raises(TypeError):
            sdb.pin(keys=keys, val=(seqner.qb64b, saider.qb64))

        actuals = sdb.get(keys=keys)
        assert actuals[0].qb64 == seqner.qb64
        assert actuals[1].qb64 == saider.qb64

    assert not os.path.exists(db.path)
    assert not db.opened


def test_cat_cesr_ioset_suber():
    """
    Test CatIoSetSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CatCesrIoSetSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.CatCesrIoSetSuber)
        assert sdb.klas == (coring.Matter, )  # default
        assert not sdb.sdb.flags()["dupsort"]
        assert isinstance(sdb, subing.CatCesrSuberBase)
        assert isinstance(sdb, subing.IoSetSuber)

        klases = (coring.Seqner, coring.Diger)
        sdb = subing.CatCesrIoSetSuber(db=db, subkey='bags.', klas=klases)
        assert isinstance(sdb, subing.CatCesrIoSetSuber)
        for klas, sklas in zip(klases, sdb.klas):
            assert klas == sklas
        assert not sdb.sdb.flags()["dupsort"]

        # test .toval and tovals  needs .klas to work
        sqr0 = coring.Seqner(sn=20)
        assert sqr0.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAAU'

        dgr0 = coring.Diger(ser=b"Hello Me Maties.")
        assert dgr0.qb64b == b'ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ'

        vals0 = (sqr0, dgr0)

        val0b = sdb._ser(val=vals0)
        assert val0b == sqr0.qb64b + dgr0.qb64b
        vals = sdb._des(val=val0b)
        assert b"".join(val.qb64b for val in vals0) == val0b
        for val, klas in zip(vals, sdb.klas):
            assert isinstance(val, klas)

        sqr1 = coring.Seqner(sn=32)
        sqr1.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAIA'

        dgr1 = coring.Diger(ser=b"Hi Guy.")
        assert dgr1.qb64b == b'EAdfsnL-ko8ldxIZ9JL-KBTD4eMCqAAkEw4HmKFsT45C'

        vals1 = (sqr1, dgr1)

        sqr2 = coring.Seqner(sn=1534)
        assert sqr2.qb64b == b'0AAAAAAAAAAAAAAAAAAAAAX-'

        dgr2 = coring.Diger(ser=b"Bye Bye Birdie.")
        assert dgr2.qb64b == b'EAO4UVcSfvfoGnSzJycMiihykJyYOshsyvU_l8U5TrO2'

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
                                         for keys, vals in sdb.getItemIter()]
        assert items == [
                         (keys0, [sqr0.qb64, dgr0.qb64]),
                         (keys0, [sqr1.qb64, dgr1.qb64]),
                         (keys1, [sqr2.qb64, dgr2.qb64]),
                         (keys2, [sqr0.qb64, dgr0.qb64]),
                         (keys2, [sqr2.qb64, dgr2.qb64])
                        ]

        items = [(iokeys, [val.qb64 for val in  vals])
                                      for iokeys, vals in sdb.getFullItemIter()]
        assert items ==  [
                          (keys0 + ('00000000000000000000000000000000', ), [sqr0.qb64, dgr0.qb64]),
                          (keys0 + ('00000000000000000000000000000001', ), [sqr1.qb64, dgr1.qb64]),
                          (keys1 + ('00000000000000000000000000000000', ), [sqr2.qb64, dgr2.qb64]),
                          (keys2 + ('00000000000000000000000000000000', ), [sqr0.qb64, dgr0.qb64]),
                          (keys2 + ('00000000000000000000000000000001', ), [sqr2.qb64, dgr2.qb64])
                         ]

        items = [(keys, [val.qb64 for val in vals])
                                 for keys, vals in sdb.getItemIter(keys=keys1)]
        assert items == [(keys1, [sqr2.qb64, dgr2.qb64])]

        items = [(keys, [val.qb64 for val in vals])
                             for keys, vals in  sdb.getItemIter(keys=keys0)]
        assert items == [
                        (keys0, [sqr0.qb64, dgr0.qb64]),
                        (keys0, [sqr1.qb64, dgr1.qb64]),
                        ]


        topkeys = ("a", "")
        items = [(keys, [val.qb64 for val in vals])
                            for keys, vals in sdb.getItemIter(keys=topkeys)]
        assert items == [
                          (keys0, [sqr0.qb64, dgr0.qb64]),
                          (keys0, [sqr1.qb64, dgr1.qb64]),
                        ]

        items = [(iokeys, [val.qb64 for val in vals])
                             for iokeys, vals in sdb.getFullItemIter(keys=topkeys)]

        assert items == [
                        (keys0 + ('00000000000000000000000000000000', ), [sqr0.qb64, dgr0.qb64]),
                        (keys0 + ('00000000000000000000000000000001', ), [sqr1.qb64, dgr1.qb64]),
                        ]


        # Try Siger Indexer Subclass
        sdb = subing.CatCesrIoSetSuber(db=db, subkey='pigs.', klas=(indexing.Siger, ))
        assert isinstance(sdb, subing.CatCesrIoSetSuber)
        assert issubclass(sdb.klas[0], indexing.Siger)
        sig0 = 'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = indexing.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, vals=[[val0]])
        actuals = sdb.get(keys=keys)
        assert isinstance(actuals[0][0], indexing.Siger)
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

        pre0 = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        val0 = coring.Matter(qb64=pre0)
        assert val0.qb64 == pre0

        pre1 = "BBPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA"
        val1 = coring.Matter(qb64=pre1)
        assert val1.qb64 == pre1

        pre2 = "BAzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y"
        val2 = coring.Matter(qb64=pre2)
        assert val2.qb64 == pre2

        pre3 = "BEK0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w"
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


        items = [(keys, val.qb64) for keys, val in sdb.getItemIter()]
        assert items == [(('alpha', 'dog'), 'BEK0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w'),
                         (('beta', 'cat'), 'BAzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y'),
                         (('beta', 'cat'), 'BBPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'),
                         (('beta', 'cat'), 'BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'),
                         (('betagamma', 'squirrel'), 'BEK0gzhcQPYGGwTmuupUhWk1x4ejWzwEHHzqPx5_yZ-w')]


        topkeys = ("beta", "")  # append empty str to force trailing .sep
        items = [(keys, val.qb64) for keys, val in sdb.getItemIter(keys=topkeys)]
        assert items == [(('beta', 'cat'), 'BAzhcQPYGGwTmuupUhWk1x4ejWzwEHHzq7K0Px5_yZ-Y'),
                         (('beta', 'cat'), 'BBPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcA'),
                         (('beta', 'cat'), 'BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc')]

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
        sdb = subing.CesrDupSuber(db=db, subkey='pigs.', klas=indexing.Siger)
        assert isinstance(sdb, subing.CesrDupSuber)
        assert issubclass(sdb.klas, indexing.Siger)
        sig0 = 'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = indexing.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, vals=[val0])
        actuals = sdb.get(keys=keys)
        assert isinstance(actuals[0], indexing.Siger)
        assert actuals[0].qb64 == val0.qb64


    assert not os.path.exists(db.path)
    assert not db.opened


def test_cat_cesr_dup_suber():
    """
    Test CatCesrDupSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CatCesrDupSuber(db=db, subkey='bags.')
        assert isinstance(sdb, subing.CatCesrDupSuber)
        assert sdb.klas == (coring.Matter, )  # default
        assert sdb.sdb.flags()["dupsort"]
        assert isinstance(sdb, subing.CatCesrSuberBase)
        assert isinstance(sdb, subing.DupSuber)

        klases = (coring.Number, coring.Diger)
        sdb = subing.CatCesrDupSuber(db=db, subkey='bags.', klas=klases)
        assert isinstance(sdb, subing.CatCesrDupSuber)
        for klas, sklas in zip(klases, sdb.klas):
            assert klas == sklas
        assert sdb.sdb.flags()["dupsort"]

        # test .toval and tovals  needs .klas to work
        sqr0 = coring.Number(num=20)
        assert sqr0.qb64b == b'MAAU'

        dgr0 = coring.Diger(ser=b"Hello Me Maties.")
        assert dgr0.qb64b == b'ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ'

        vals0 = (sqr0, dgr0)

        val0b = sdb._ser(val=vals0)
        assert val0b == sqr0.qb64b + dgr0.qb64b
        vals = sdb._des(val=val0b)
        assert b"".join(val.qb64b for val in vals0) == val0b
        for val, klas in zip(vals, sdb.klas):
            assert isinstance(val, klas)

        sqr1 = coring.Number(num=32)
        sqr1.qb64b == b'MAAg'

        dgr1 = coring.Diger(ser=b"Hi Guy.")
        assert dgr1.qb64b == b'EAdfsnL-ko8ldxIZ9JL-KBTD4eMCqAAkEw4HmKFsT45C'

        vals1 = (sqr1, dgr1)

        sqr2 = coring.Number(num=1534)
        assert sqr2.qb64b == b'MAX-'

        dgr2 = coring.Diger(ser=b"Bye Bye Birdie.")
        assert dgr2.qb64b == b'EAO4UVcSfvfoGnSzJycMiihykJyYOshsyvU_l8U5TrO2'

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

        sdb.put(keys=keys0, vals=[vals1, vals0])  # reverse order
        actuals = sdb.get(keys=keys0)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        # since dup order is not insertion order but lexicographic order of values
        assert valss == [
                        [sqr0.qb64, dgr0.qb64],
                        [sqr1.qb64, dgr1.qb64],
                       ]
        actual = sdb.getLast(keys=keys0)
        assert [actual[0].qb64, actual[1].qb64] == [sqr1.qb64, dgr1.qb64]

        assert sdb.add(keys=keys0, val=vals2)
        assert sdb.cnt(keys0) == 3
        actuals = sdb.get(keys=keys0)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        assert valss == [
                        [sqr0.qb64, dgr0.qb64],
                        [sqr1.qb64, dgr1.qb64],
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

        assert sdb.put(keys=keys1, vals=[vals2, vals1])  # change order
        assert sdb.cnt(keys1) == 2
        actuals = sdb.get(keys=keys1)
        valss = [[val.qb64 for val in actual] for actual in actuals]
        # not insertion order dup is lexicographic
        assert valss == [
                        [sqr1.qb64, dgr1.qb64],
                        [sqr2.qb64, dgr2.qb64],
                       ]

        valss = [[val.qb64 for val in vals] for vals in sdb.getIter(keys=keys1)]
        assert valss == [
                          [sqr1.qb64, dgr1.qb64],
                          [sqr2.qb64, dgr2.qb64],
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
                                         for keys, vals in sdb.getItemIter()]
        assert items == [
                         (keys0, [sqr0.qb64, dgr0.qb64]),
                         (keys0, [sqr1.qb64, dgr1.qb64]),
                         (keys1, [sqr2.qb64, dgr2.qb64]),
                         (keys2, [sqr0.qb64, dgr0.qb64]),
                         (keys2, [sqr2.qb64, dgr2.qb64])
                        ]

        items = [(iokeys, [val.qb64 for val in  vals])
                                      for iokeys, vals in sdb.getFullItemIter()]
        assert items ==  [
                          (keys0 , [sqr0.qb64, dgr0.qb64]),
                          (keys0 , [sqr1.qb64, dgr1.qb64]),
                          (keys1 , [sqr2.qb64, dgr2.qb64]),
                          (keys2, [sqr0.qb64, dgr0.qb64]),
                          (keys2 , [sqr2.qb64, dgr2.qb64])
                         ]

        items = [(keys, [val.qb64 for val in vals])
                                 for keys, vals in sdb.getItemIter(keys=keys1)]
        assert items == [(keys1, [sqr2.qb64, dgr2.qb64])]

        items = [(keys, [val.qb64 for val in vals])
                             for keys, vals in  sdb.getItemIter(keys=keys0)]
        assert items == [
                        (keys0, [sqr0.qb64, dgr0.qb64]),
                        (keys0, [sqr1.qb64, dgr1.qb64]),
                        ]


        topkeys = ("a", "")
        items = [(keys, [val.qb64 for val in vals])
                            for keys, vals in sdb.getItemIter(keys=topkeys)]
        assert items == [
                          (keys0, [sqr0.qb64, dgr0.qb64]),
                          (keys0, [sqr1.qb64, dgr1.qb64]),
                        ]

        items = [(iokeys, [val.qb64 for val in vals])
                             for iokeys, vals in sdb.getFullItemIter(keys=topkeys)]

        assert items == [
                        (keys0, [sqr0.qb64, dgr0.qb64]),
                        (keys0, [sqr1.qb64, dgr1.qb64]),
                        ]


        # Try Siger Indexer Subclass
        sdb = subing.CatCesrDupSuber(db=db, subkey='pigs.', klas=(indexing.Siger, ))
        assert isinstance(sdb, subing.CatCesrDupSuber)
        assert issubclass(sdb.klas[0], indexing.Siger)
        sig0 = 'AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ'
        val0 = indexing.Siger(qb64=sig0)
        keys = ("zeta", "cat")
        assert sdb.put(keys=keys, vals=[[val0]])
        actuals = sdb.get(keys=keys)
        assert isinstance(actuals[0][0], indexing.Siger)
        assert actuals[0][0].qb64 == val0.qb64


    assert not os.path.exists(db.path)
    assert not db.opened



def test_cat_cesr_suber_strict_inherited_subers():
    """
    Test strict behavior inherited by CatCesrIoSetSuber and CatCesrDupSuber
    """
    with dbing.openLMDB() as db:
        wrong = coring.Prefixer(qb64="BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        isdb = subing.CatCesrIoSetSuber(db=db,
                                        subkey='ibags.',
                                        klas=(coring.Seqner, coring.Saider),
                                        strict=True)
        seqner = coring.Seqner(sn=1)
        saider = coring.Saider(qb64b=b'EALkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E')
        assert isdb.put(keys=("a", "1"), vals=[(seqner, saider)])
        with pytest.raises(TypeError):
            isdb.put(keys=("a", "2"), vals=[(wrong, saider)])

        dsdb = subing.CatCesrDupSuber(db=db,
                                      subkey='dbags.',
                                      klas=(coring.Number, coring.Diger),
                                      strict=True)
        number = coring.Number(num=1)
        diger = coring.Diger(ser=b"strict cat dup")
        assert dsdb.put(keys=("b", "1"), vals=[(number, diger)])
        with pytest.raises(TypeError):
            dsdb.put(keys=("b", "2"), vals=[(wrong, diger)])

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
        assert issubclass(sdb.klas, core.Signer)
        assert not sdb.sdb.flags()["dupsort"]

        # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
        seed0 = (b'\x18;0\xc4\x0f*vF\xfa\xe3\xa2Eee\x1f\x96o\xce)G\x85\xe3X\x86\xda\x04\xf0\xdc'
                           b'\xde\x06\xc0+')
        signer0 = core.Signer(raw=seed0, code=coring.MtrDex.Ed25519_Seed)
        assert signer0.verfer.code == coring.MtrDex.Ed25519
        assert signer0.verfer.transferable  # default
        assert signer0.qb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'
        assert signer0.verfer.qb64b == b'DIYsYWYwtVo9my0dUHQA0-_ZEts8B5XdvXpHGtHpcR4h'

        # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
        seed1 = (b'`\x05\x93\xb9\x9b6\x1e\xe0\xd7\x98^\x94\xc8Et\xf2\xc4\xcd\x94\x18'
                 b'\xc6\xae\xb9\xb6m\x12\xc4\x80\x03\x07\xfc\xf7')

        signer1 = core.Signer(raw=seed1, code=coring.MtrDex.Ed25519_Seed)
        assert signer1.verfer.code == coring.MtrDex.Ed25519
        assert signer1.verfer.transferable  # default
        assert signer1.qb64b == b'AGAFk7mbNh7g15helMhFdPLEzZQYxq65tm0SxIADB_z3'
        assert signer1.verfer.qb64b == b'DIHpH-kgf2oMMfeplUmSOj0wtPY-EqfKlG4CoJTfLi42'

        keys = (signer0.verfer.qb64, )  # must be verfer as key to get transferable
        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  try put different val when already put
        result = sdb.put(keys=keys, val=signer1)
        assert not result
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  now overwrite with pin. Key is wrong but transferable property is
        #  the same so that is all that matters to get back signer
        result = sdb.pin(keys=keys, val=signer1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer1.qb64
        assert actual.verfer.qb64 == signer1.verfer.qb64

        # test with keys as string not tuple
        keys = signer0.verfer.qb64

        sdb.pin(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        assert not  sdb.get(keys=keys)

        # test missing entry at keys
        badkey = b'DAQdADT79kS2zwHld29hixhZjC1Wj2bLRekca0elxHiE'
        assert not  sdb.get(badkey)

        # test iteritems
        sdb = subing.SignerSuber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.SignerSuber)
        assert sdb.put(keys=signer0.verfer.qb64b, val=signer0)
        assert sdb.put(keys=signer1.verfer.qb64b, val=signer1)

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter()]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                         ((signer0.verfer.qb64, ), signer0.qb64)]

        assert sdb.put(keys=("a", signer0.verfer.qb64), val=signer0)
        assert sdb.put(keys=("a", signer1.verfer.qb64), val=signer1)
        assert sdb.put(keys=("ab", signer0.verfer.qb64), val=signer0)
        assert sdb.put(keys=("ab", signer1.verfer.qb64), val=signer1)

        topkeys = ("a", "")  # append empty str to force trailing .sep
        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter(keys=topkeys)]
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
    signer0 = core.Signer(raw=seed0, code=coring.MtrDex.Ed25519_Seed)
    assert signer0.verfer.code == coring.MtrDex.Ed25519
    assert signer0.verfer.transferable  # default
    assert signer0.qb64b == b'ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr'
    assert signer0.verfer.qb64b == b'DIYsYWYwtVo9my0dUHQA0-_ZEts8B5XdvXpHGtHpcR4h'

    # preseed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    seed1 = (b'`\x05\x93\xb9\x9b6\x1e\xe0\xd7\x98^\x94\xc8Et\xf2\xc4\xcd\x94\x18'
             b'\xc6\xae\xb9\xb6m\x12\xc4\x80\x03\x07\xfc\xf7')

    signer1 = core.Signer(raw=seed1, code=coring.MtrDex.Ed25519_Seed)
    assert signer1.verfer.code == coring.MtrDex.Ed25519
    assert signer1.verfer.transferable  # default
    assert signer1.qb64b == b'AGAFk7mbNh7g15helMhFdPLEzZQYxq65tm0SxIADB_z3'
    assert signer1.verfer.qb64b == b'DIHpH-kgf2oMMfeplUmSOj0wtPY-EqfKlG4CoJTfLi42'


    # rawsalt =pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    rawsalt = b'0123456789abcdef'
    salter = core.Salter(raw=rawsalt)
    salt = salter.qb64
    assert salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
    stem = "blue"

    # cryptseed0 = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    cryptseed0 = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner0 = core.Signer(raw=cryptseed0, code=coring.MtrDex.Ed25519_Seed,
                           transferable=False)
    seed0 = cryptsigner0.qb64
    aeid0 = cryptsigner0.verfer.qb64
    assert aeid0 == 'BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB'

    decrypter = core.Decrypter(seed=seed0)
    encrypter = core.Encrypter(verkey=aeid0)
    assert encrypter.verifySeed(seed=seed0)

    # cryptseed1 = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    cryptseed1 = (b"\x89\xfe{\xd9'\xa7\xb3\x89#\x19\xbec\xee\xed\xc0\xf9\x97\xd0\x8f9\x1dyNI"
               b'I\x98\xbd\xa4\xf6\xfe\xbb\x03')
    cryptsigner1 = core.Signer(raw=cryptseed1, code=coring.MtrDex.Ed25519_Seed,
                           transferable=False)


    with dbing.openLMDB() as db,  keeping.openKS() as ks:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.CryptSignerSuber(db=db, subkey='bags.')  # default klas is Signer
        assert isinstance(sdb, subing.CryptSignerSuber)
        assert issubclass(sdb.klas, core.Signer)
        assert not sdb.sdb.flags()["dupsort"]

        # Test without encrypter or decrypter
        keys = (signer0.verfer.qb64, )  # must be verfer as key to get transferable
        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  try put different val when already put
        result = sdb.put(keys=keys, val=signer1)
        assert not result
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer0.qb64
        assert actual.verfer.qb64 == signer0.verfer.qb64

        #  now overwrite with pin. Key is wrong but transferable property is
        #  the same so that is all that matters to get back signer
        result = sdb.pin(keys=keys, val=signer1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
        assert actual.qb64 == signer1.qb64
        assert actual.verfer.qb64 == signer1.verfer.qb64

        # test with keys as string not tuple
        keys = signer0.verfer.qb64

        sdb.pin(keys=keys, val=signer0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, core.Signer)
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

        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getItemIter()]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                         ((signer0.verfer.qb64, ), signer0.qb64)]


        # now test with encrypter and decrypter
        encrypter0 = core.Encrypter(verkey=cryptsigner0.verfer.qb64)
        decrypter0 = core.Decrypter(seed=cryptsigner0.qb64b)

        # first pin with encrypter
        assert sdb.pin(keys=signer0.verfer.qb64b, val=signer0, encrypter=encrypter0)
        assert sdb.pin(keys=signer1.verfer.qb64b, val=signer1, encrypter=encrypter0)

        # now get
        actual0 = sdb.get(keys=signer0.verfer.qb64b, decrypter=decrypter0)
        assert isinstance(actual0, core.Signer)
        assert actual0.qb64 == signer0.qb64
        assert actual0.verfer.qb64 == signer0.verfer.qb64

        actual1 = sdb.get(keys=signer1.verfer.qb64b, decrypter=decrypter0)
        assert isinstance(actual1, core.Signer)
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

        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getItemIter(decrypter=decrypter0)]
        assert items == [((signer1.verfer.qb64, ), signer1.qb64),
                             ((signer0.verfer.qb64, ), signer0.qb64)]

        assert sdb.put(keys=("a", signer0.verfer.qb64), val=signer0, encrypter=encrypter0)
        assert sdb.put(keys=("a", signer1.verfer.qb64), val=signer1, encrypter=encrypter0)
        assert sdb.put(keys=("ab", signer0.verfer.qb64), val=signer0, encrypter=encrypter0)
        assert sdb.put(keys=("ab", signer1.verfer.qb64), val=signer1, encrypter=encrypter0)

        topkeys = ("a", "")  # append empty str to force trailing .sep
        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getItemIter(keys=topkeys,
                                                            decrypter=decrypter0)]
        assert items == [(("a", signer1.verfer.qb64 ), signer1.qb64),
                          (("a", signer0.verfer.qb64 ), signer0.qb64)]


        # test re-encrypt
        encrypter1 = core.Encrypter(verkey=cryptsigner1.verfer.qb64)
        decrypter1 = core.Decrypter(seed=cryptsigner1.qb64b)
        for keys, sgnr in sdb.getItemIter(decrypter=decrypter0):
            sdb.pin(keys, sgnr, encrypter=encrypter1)

        items = [(keys, sgnr.qb64) for keys, sgnr in sdb.getItemIter(decrypter=decrypter1)]
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
        assert manager._inits == {'salt': '0AAwMTIzNDU2Nzg5YWJjZGVm',
                                  'aeid': 'BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB'}

        assert manager.encrypter.qb64 == encrypter.qb64  #  aeid provided
        assert manager.decrypter.qb64 == decrypter.qb64  # aeid and seed provided
        assert manager.seed == seed0  # in memory only
        assert manager.aeid == aeid0  # on disk only
        assert manager.algo == keeping.Algos.salty
        assert manager.salt == salt  # encrypted on disk but property decrypts if seed
        assert manager.pidx == 0
        assert manager.tier == core.Tiers.low
        saltCipher0 = core.Cipher(qb64=manager.ks.gbls.get('salt'))
        assert saltCipher0.decrypt(seed=seed0).qb64 == salt


        manager.updateAeid(aeid=cryptsigner1.verfer.qb64, seed=cryptsigner1.qb64)
        assert manager.aeid == cryptsigner1.verfer.qb64 == 'BEcOrMrG_7r_NWaLl6h8UJapwIfQWIkjrIPXkCZm2fFM'
        assert manager.salt == salt
        saltCipher1 = core.Cipher(qb64=manager.ks.gbls.get('salt'))
        assert not saltCipher0.qb64 == saltCipher1.qb64  # old cipher different

    """End Test"""



if __name__ == "__main__":
    test_suber()
    test_on_suber()
    test_b64_suber()
    test_dup_suber()
    test_iodup_suber()
    test_b64_iodup_suber()
    test_on_iodup_suber()
    test_b64_oniodup_suber()
    test_ioset_suber()
    test_b64_ioset_suber()
    test_on_ioset_suber()
    test_b64_onioset_suber()
    test_cat_cesr_suber()
    test_cat_cesr_suber_strict_subclass_enforcement()
    test_cesr_suber()
    test_cesr_suber_strict_subclass_enforcement()
    test_cesr_on_suber()
    test_cesr_ioset_suber()
    test_cat_cesr_ioset_suber()
    test_cesr_dup_suber()
    test_cat_cesr_dup_suber()
    test_cat_cesr_suber_strict_inherited_subers()
    test_serder_suber()
    test_serder_ioset_suber()
    test_schemer_suber()
    test_signer_suber()
    test_crypt_signer_suber()
