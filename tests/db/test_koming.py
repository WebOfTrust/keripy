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



# Komer tests
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

# End Komer tests

def test_clean():
    """
    Test Baser db clean clone function
    """
    with dbing.openDB(name="nat") as natDB, keeping.openKS(name="nat") as natKS:
        # setup Nat's habitat using default salt multisig already incepts
        natHab = habbing.Habitat(name='nat', ks=natKS, db=natDB,
                                isith=2, icount=3, temp=True)
        assert natHab.name == 'nat'
        assert natHab.ks == natKS
        assert natHab.db == natDB
        assert natHab.kever.prefixer.transferable
        assert natHab.db.opened
        assert natHab.pre in natHab.kevers
        assert natHab.db.path.endswith("/keri/db/nat")
        path = natHab.db.path  # save for later

        # Create series of events for Nat
        natHab.interact()
        natHab.rotate()
        natHab.interact()
        natHab.interact()
        natHab.interact()
        natHab.interact()

        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.dig == 'En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI'
        ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
        assert ldig == natHab.kever.serder.digb
        serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
        assert serder.dig == natHab.kever.serder.dig
        assert natHab.db.env.stat()['entries'] == 19

        # test reopenDB with reuse  (because temp)
        with dbing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
            assert ldig == natHab.kever.serder.digb
            serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
            assert serder.dig == natHab.kever.serder.dig
            assert natHab.db.env.stat()['entries'] == 19

            # verify name pre kom in db
            kdb = koming.Komer(db=natHab.db, schema=habbing.HabitatRecord, subdb='habs.')
            data = kdb.get(keys=(natHab.name, ))
            assert data.prefix == natHab.pre
            assert data.name == natHab.name

            # add garbage event to corrupt database
            badsrdr = eventing.rotate(pre=natHab.pre,
                                       keys=[verfer.qb64 for verfer in natHab.kever.verfers],
                                       dig=natHab.kever.serder.dig,
                                       sn=natHab.kever.sn+1,
                                       sith=2,
                                       nxt=natHab.kever.nexter.qb64)
            fn = natHab.kever.logEvent(serder=badsrdr, first=True)
            assert fn == 7
            # verify garbage event in database
            assert natHab.db.getEvt(dbing.dgKey(natHab.pre,badsrdr.dig))
            assert natHab.db.getFe(dbing.fnKey(natHab.pre, 7))


        # test openDB copy db with clean
        with dbing.openDB(name=natHab.db.name,
                          temp=natHab.db.temp,
                          headDirPath=natHab.db.headDirPath,
                          dirMode=natHab.db.dirMode,
                          clean=True) as copy:
            assert copy.path.endswith("/keri/clean/db/nat")
            assert copy.env.stat()['entries'] >= 18

        # now clean it
        natHab.kevers.clear()  # clear kevers dict in place
        assert not natHab.kevers
        kvy = eventing.Kevery(kevers=natHab.kevers)  # use inplace kevers & promiscuous mode
        apping.clean(orig=natHab.db, kvy=kvy)

        # see if kevers dict is back to what it was before
        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.dig == 'En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI'

        # see if database is back where it belongs
        with dbing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
            assert ldig == natHab.kever.serder.digb
            serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
            assert serder.dig == natHab.kever.serder.dig
            assert natHab.db.env.stat()['entries'] >= 18

            # confirm bad event missing from database
            assert not natHab.db.getEvt(dbing.dgKey(natHab.pre,badsrdr.dig))
            assert not natHab.db.getFe(dbing.fnKey(natHab.pre, 7))

            # verify name pre kom in db
            kdb = koming.Komer(db=natHab.db, schema=habbing.HabitatRecord, subdb='habs.')
            data = kdb.get(keys=(natHab.name, ))
            assert data.prefix == natHab.pre
            assert data.name == natHab.name


    assert not os.path.exists(natKS.path)
    assert not os.path.exists(natDB.path)

    """End Test"""


if __name__ == "__main__":
    test_clean()
