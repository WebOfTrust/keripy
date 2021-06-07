# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""
import os

import pytest

from keri.core import coring, eventing
from keri.db import dbing, subing
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

        sue = "Hello sailer!"

        keys = ("test_key", "0001")
        sdb.put(keys=keys, val=sue)
        actual = sdb.get(keys=keys)
        assert actual == sue.encode("utf-8")

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=sue)
        actual = sdb.get(keys=keys)
        assert actual == sue.encode("utf-8")

        kip = "Hey gorgeous!"
        result = sdb.put(keys=keys, val=kip)
        assert not result
        actual = sdb.get(keys=keys)
        assert actual == sue.encode("utf-8")

        result = sdb.pin(keys=keys, val=kip)
        assert result
        actual = sdb.get(keys=keys)
        assert actual == kip.encode("utf-8")

        # test with keys as string not tuple
        keys = "keystr"

        bob = "Shove off!"

        sdb.put(keys=keys, val=bob)
        actual = sdb.get(keys=keys)
        assert actual == bob.encode("utf-8")

        sdb.rem(keys)

        actual = sdb.get(keys=keys)
        assert actual is None


        liz =  "May live is insane."
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

        items = [(keys, data.decode("utf-8")) for keys, data in sdb.getItemIter()]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

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

        pre = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        srdr0 = eventing.incept(keys=[pre])

        keys = (pre, srdr0.dig)
        sdb.put(keys=keys, srdr=srdr0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr0.dig

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, srdr=srdr0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr0.dig

        srdr1 = eventing.rotate(pre=pre, keys=[pre], dig=srdr0.dig)
        result = sdb.put(keys=keys, srdr=srdr1)
        assert not result
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr0.dig

        result = sdb.pin(keys=keys, srdr=srdr1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Serder)
        assert actual.dig == srdr1.dig

        # test with keys as string not tuple
        keys = "{}.{}".format(pre, srdr1.dig)

        sdb.put(keys=keys, srdr=srdr1)
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
        sdb.put(keys=("a","1"), srdr=srdr0)
        sdb.put(keys=("a","2"), srdr=srdr1)

        items = [(keys, srdr.dig) for keys, srdr in sdb.getItemIter()]
        assert items == [(('a', '1'), srdr0.dig),
                         (('a', '2'), srdr1.dig)]

    assert not os.path.exists(db.path)
    assert not db.opened



def test_matter_suber():
    """
    Test MatterSuber LMDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subing.MatterSuber(db=db, subkey='bags.')  # default klas is Matter
        assert isinstance(sdb, subing.MatterSuber)
        assert issubclass(sdb.klas, coring.Matter)

        pre0 = "BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc"
        val0 = coring.Matter(qb64=pre0)

        keys = ("alpha", "dog")
        sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val0.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val0.qb64

        pre1 = "BHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        val1 = coring.Matter(qb64=pre1)
        result = sdb.put(keys=keys, val=val1)
        assert not result
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val0.qb64

        result = sdb.pin(keys=keys, val=val1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val1.qb64

        # test with keys as string not tuple
        keys = "{}.{}".format("beta", "fish")

        sdb.put(keys=keys, val=val1)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Matter)
        assert actual.qb64 == val1.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        # test missing entry at keys
        badkey = "badkey"
        actual = sdb.get(badkey)
        assert actual is None

        # test iteritems
        sdb = subing.MatterSuber(db=db, subkey='pugs.')
        assert isinstance(sdb, subing.MatterSuber)
        sdb.put(keys=("a","1"), val=val0)
        sdb.put(keys=("a","2"), val=val1)

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter()]
        assert items == [(('a', '1'), val0.qb64),
                         (('a', '2'), val1.qb64)]

        #  Try other classs
        sdb = subing.MatterSuber(db=db, subkey='pigs.', klas=coring.Diger)
        assert isinstance(sdb, subing.MatterSuber)
        assert issubclass(sdb.klas, coring.Diger)

        dig0 = "EQPYGGwTmuupWzwEHHzq7K0gzUhPx5_yZ-Wk1x4ejhcc"
        val0 = coring.Diger(qb64=dig0)

        keys = ("alpha", "dog")
        sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val0.qb64

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, val=val0)
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val0.qb64

        pre1 = "EHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc"
        val1 = coring.Matter(qb64=pre1)
        result = sdb.put(keys=keys, val=val1)
        assert not result
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val0.qb64

        result = sdb.pin(keys=keys, val=val1)
        assert result
        actual = sdb.get(keys=keys)
        assert isinstance(actual, coring.Diger)
        assert actual.qb64 == val1.qb64

        # test iteritems
        sdb = subing.MatterSuber(db=db, subkey='figs.')
        assert isinstance(sdb, subing.MatterSuber)
        sdb.put(keys=("a","1"), val=val0)
        sdb.put(keys=("a","2"), val=val1)

        items = [(keys, srdr.qb64) for keys, srdr in sdb.getItemIter()]
        assert items == [(('a', '1'), val0.qb64),
                         (('a', '2'), val1.qb64)]



    assert not os.path.exists(db.path)
    assert not db.opened


if __name__ == "__main__":
    test_matter_suber()
