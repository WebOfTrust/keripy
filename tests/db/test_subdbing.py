# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import json
import os
from dataclasses import dataclass, asdict

import pytest

from keri.app import apping, habbing, keeping
from keri.core import coring, eventing
from keri.core.coring import Serials
from keri.db import dbing, subdbing
from keri.help import helping


def test_subdber():
    """
    Test SubDBer sub database class
    """

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subdbing.SubDBer(db=db, subkey='bags.')
        assert isinstance(sdb, subdbing.SubDBer)

        sue = "Hello sailer!"

        keys = ("test_key", "0001")
        sdb.put(keys=keys, data=sue)
        actual = sdb.get(keys=keys)
        assert actual == sue.encode("utf-8")

        sdb.rem(keys)
        actual = sdb.get(keys=keys)
        assert actual is None

        sdb.put(keys=keys, data=sue)
        actual = sdb.get(keys=keys)
        assert actual == sue.encode("utf-8")

        kip = "Hey gorgeous!"
        result = sdb.put(keys=keys, data=kip)
        assert not result
        actual = sdb.get(keys=keys)
        assert actual == sue.encode("utf-8")

        result = sdb.pin(keys=keys, data=kip)
        assert result
        actual = sdb.get(keys=keys)
        assert actual == kip.encode("utf-8")

        # test with keys as string not tuple
        keys = "keystr"

        bob = "Shove off!"

        sdb.put(keys=keys, data=bob)
        actual = sdb.get(keys=keys)
        assert actual == bob.encode("utf-8")

        sdb.rem(keys)

        actual = sdb.get(keys=keys)
        assert actual is None


        liz =  "May live is insane."
        keys = ("test_key", "0002")

        sdb.put(keys=keys, data=liz)
        actual = sdb.get(("not_found", "0002"))
        assert actual is None



    assert not os.path.exists(db.path)
    assert not db.opened


def test_subdber_get_item_iter():
    """
    Test Komer object class
    """

    w = "Big Blue"
    x = "Tall Red"
    y = "Fat Green"
    z = "Eat White"


    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        sdb = subdbing.SubDBer(db=db, subkey='bags.')
        assert isinstance(sdb, subdbing.SubDBer)

        sdb.put(keys=("a","1"), data=w)
        sdb.put(keys=("a","2"), data=x)
        sdb.put(keys=("a","3"), data=y)
        sdb.put(keys=("a","4"), data=z)

        items = [(keys, data.decode("utf-8")) for keys, data in sdb.getItemIter()]
        assert items == [(('a', '1'), w),
                        (('a', '2'), x),
                        (('a', '3'), y),
                        (('a', '4'), z)]

    assert not os.path.exists(db.path)
    assert not db.opened




if __name__ == "__main__":
    test_subdber()
