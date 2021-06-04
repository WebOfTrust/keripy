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
from keri.db import dbing, koming
from keri.help import helping


def test_kom_happy_path():
    """
    Test Komer object class
    """

    @dataclass
    class Record:
        first: str  # first name
        last: str  # last name
        street: str  # street address
        city: str  # city name
        state: str  # state code
        zip: int  # zip code

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

        mydb = koming.Komer(db=db, schema=Record, subdb='records.')
        assert isinstance(mydb, koming.Komer)

        sue = Record(first="Susan",
                     last="Black",
                     street="100 Main Street",
                     city="Riverton",
                     state="UT",
                     zip=84058)

        keys = ("test_key", "0001")
        mydb.put(keys=keys, data=sue)
        actual = mydb.get(keys=keys)

        assert actual.first == "Susan"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058

        mydb.rem(keys)

        actual = mydb.get(keys=keys)
        assert actual is None

        # test with keys as string not tuple
        keys = "keystr"

        bob = Record(first="Bob",
                     last="Brown",
                     street="100 Center Street",
                     city="Bluffdale",
                     state="UT",
                     zip=84043)

        mydb.put(keys=keys, data=bob)
        actual = mydb.get(keys=keys)

        assert actual.first == "Bob"
        assert actual.last == "Brown"
        assert actual.street == "100 Center Street"
        assert actual.city == "Bluffdale"
        assert actual.state == "UT"
        assert actual.zip == 84043

        mydb.rem(keys)

        actual = mydb.get(keys=keys)
        assert actual is None


    assert not os.path.exists(db.path)
    assert not db.opened


def test_kom_get_item_iter():
    """
    Test Komer object class
    """

    @dataclass
    class Stuff:
        a: str  # dummy
        b: str  # dummy too

        def __iter__(self):
            return iter(asdict(self))

    w = Stuff(a="Big", b="Blue")
    x = Stuff(a="Tall", b="Red")
    y = Stuff(a="Fat", b="Green")
    z = Stuff(a="Eat", b="White")


    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        mydb = koming.Komer(db=db, schema=Stuff, subdb='recs.')
        assert isinstance(mydb, koming.Komer)


        mydb.put(keys=("a","1"), data=w)
        mydb.put(keys=("a","2"), data=x)
        mydb.put(keys=("a","3"), data=y)
        mydb.put(keys=("a","4"), data=z)

        items = [(keys, asdict(data)) for keys, data in mydb.getItemIter()]
        assert items == [(('a', '1'), {'a': 'Big', 'b': 'Blue'}),
                        (('a', '2'), {'a': 'Tall', 'b': 'Red'}),
                        (('a', '3'), {'a': 'Fat', 'b': 'Green'}),
                        (('a', '4'), {'a': 'Eat', 'b': 'White'})]

    assert not os.path.exists(db.path)
    assert not db.opened



def test_put_invalid_dataclass():
    @dataclass
    class Record:
        first: str

        def __iter__(self):
            return iter(asdict(self))

    @dataclass
    class AnotherClass:
        age: int

    with dbing.openLMDB() as db:
        mydb = koming.Komer(db=db, schema=AnotherClass, subdb='records.')
        sue = Record(first="Susan")
        keys = ("test_key", "0001")

        with pytest.raises(ValueError):
            mydb.put(keys=keys, data=sue)


def test_get_invalid_dataclass():
    @dataclass
    class Record:
        first: str

        def __iter__(self):
            return iter(asdict(self))

    @dataclass
    class AnotherClass:
        age: int

    with dbing.openLMDB() as db:
        mydb = koming.Komer(db=db, schema=Record, subdb='records.')
        sue = Record(first="Susan")
        keys = ("test_key", "0001")
        mydb.put(keys=keys, data=sue)

        mydb = koming.Komer(db=db, schema=AnotherClass, subdb='records.')
        with pytest.raises(ValueError):
            mydb.get(keys)


def test_not_found_entity():
    @dataclass
    class Record:
        first: str

        def __iter__(self):
            return iter(asdict(self))

    with dbing.openLMDB() as db:
        mydb = koming.Komer(db=db, schema=Record, subdb='records.')
        sue = Record(first="Susan")
        keys = ("test_key", "0001")

        mydb.put(keys=keys, data=sue)
        actual = mydb.get(("not_found", "0001"))
        assert actual is None


def test_serialization():
    @dataclass
    class Record:
        first: str  # first name
        last: str  # last name
        street: str  # street address
        city: str  # city name
        state: str  # state code
        zip: int  # zip code

    jim = Record(first="Jim",
                 last="Black",
                 street="100 Main Street",
                 city="Riverton",
                 state="UT",
                 zip=84058)

    with dbing.openLMDB() as db:
        k = koming.Komer(db=db, schema=Record, subdb='records.')
        srl = k._serializer(Serials.mgpk)

        expected = b'\x86\xa5first\xa3Jim\xa4last\xa5Black\xa6street\xaf100 Main Street\xa4city\xa8Riverton\xa5state\xa2UT\xa3zip\xce\x00\x01HZ'
        assert srl(jim) == expected

        srl = k._serializer(Serials.cbor)
        expected = b'\xa6efirstcJimdlasteBlackfstreeto100 Main StreetdcityhRivertonestatebUTczip\x1a\x00\x01HZ'
        assert srl(jim) == expected

        srl = k._serializer(Serials.json)
        expected = b'{"first":"Jim","last":"Black","street":"100 Main Street","city":"Riverton","state":"UT","zip":84058}'
        assert srl(jim) == expected


def test_deserialization():
    @dataclass
    class Record:
        first: str  # first name
        last: str  # last name
        street: str  # street address
        city: str  # city name
        state: str  # state code
        zip: int  # zip code

    msgp = b'\x86\xa5first\xa3Jim\xa4last\xa5Black\xa6street\xaf100 Main Street\xa4city\xa8Riverton\xa5state\xa2UT\xa3zip\xce\x00\x01HZ'
    cbor = b'\xa6efirstcJimdlasteBlackfstreeto100 Main StreetdcityhRivertonestatebUTczip\x1a\x00\x01HZ'
    json = b'{"first": "Jim", "last": "Black", "street": "100 Main Street", "city": "Riverton", "state": "UT", "zip": 84058}'

    with dbing.openLMDB() as db:
        k = koming.Komer(db=db, schema=Record, subdb='records.')

        desrl = k._deserializer(Serials.mgpk)
        actual = helping.datify(Record, desrl(msgp))
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058

        desrl = k._deserializer(Serials.json)
        actual = helping.datify(Record, desrl(json))
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058

        desrl = k._deserializer(Serials.cbor)
        actual = helping.datify(Record, desrl(cbor))
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058



if __name__ == "__main__":
    test_kom_happy_path()
