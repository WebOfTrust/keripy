# -*- encoding: utf-8 -*-
"""
tests.db.dbing module

"""
import pytest

import os
from dataclasses import dataclass, asdict, field

import json

from keri.base import basing
from keri.db import dbing
from keri.help import helping

def test_komer():
    """
    Test Komer object class
    """


    @dataclass
    class Record():
        first: str  # first name
        last: str   # last name
        street: str  # street address
        city: str   # city name
        state: str  # state code
        zip: int    # zip code

        def __iter__(self):
            return iter(asdict(self))

    jim = Record(first="Jim",
                 last="Black",
                 street="100 Main Street",
                 city="Riverton",
                 state="UT",
                 zip=84058)

    jimser = json.dumps(asdict(jim)).encode("utf-8")
    jim = helping.datify(Record, json.loads(bytes(jimser).decode("utf-8")))
    assert isinstance(jim, Record)

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        mydb = basing.Komer(db=db, schema=Record, subdb='records.')
        assert isinstance(mydb, basing.Komer)

        sue = Record(first="Susan",
                     last="Black",
                     street="100 Main Street",
                     city="Riverton",
                     state="UT",
                     zip=84058)

        mydb.put(keys=("skskjgoshkdh","0001"), data=sue)




    assert not os.path.exists(db.path)
    assert not db.opened


if __name__ == "__main__":
    test_komer()

