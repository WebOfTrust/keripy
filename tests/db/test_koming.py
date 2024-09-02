# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import json
import os
from dataclasses import dataclass, asdict

import pytest

from keri.core.coring import Kinds
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

        mydb = koming.Komer(db=db, schema=Record, subkey='records.')
        assert isinstance(mydb, koming.Komer)
        assert not mydb.sdb.flags()["dupsort"]

        sue = Record(first="Susan",
                     last="Black",
                     street="100 Main Street",
                     city="Riverton",
                     state="UT",
                     zip=84058)

        keys = ("test_key", "0001")
        assert mydb.sep == mydb.Sep == "."
        key = mydb._tokey(keys)
        assert key == b"test_key.0001"
        assert mydb._tokeys(key) == keys

        mydb.put(keys=keys, val=sue)
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

        keys = ("test_key", "0001")
        mydb.put(keys=keys, val=sue)
        actual = mydb.get(keys=keys)
        assert actual == sue

        kip = Record(first="Kip",
                     last="Thorne",
                     street="200 Center Street",
                     city="Bluffdale",
                     state="UT",
                     zip=84043)
        result = mydb.put(keys=keys, val=kip)
        assert not result
        actual = mydb.get(keys=keys)
        assert actual == sue

        assert mydb.getDict(keys=keys) == asdict(actual)

        result = mydb.pin(keys=keys, val=kip)
        assert result
        actual = mydb.get(keys=keys)
        assert actual == kip

        # test with keys as string not tuple
        keys = "keystr"

        bob = Record(first="Bob",
                     last="Brown",
                     street="100 Center Street",
                     city="Bluffdale",
                     state="UT",
                     zip=84043)

        mydb.put(keys=keys, val=bob)
        actual = mydb.get(keys=keys)

        assert actual.first == "Bob"
        assert actual.last == "Brown"
        assert actual.street == "100 Center Street"
        assert actual.city == "Bluffdale"
        assert actual.state == "UT"
        assert actual.zip == 84043

        assert mydb.getDict(keys=keys) == asdict(actual)

        # test None
        assert mydb.getDict(keys=("bla, bal")) == None

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

        mydb = koming.Komer(db=db, schema=Stuff, subkey='recs.')
        assert isinstance(mydb, koming.Komer)


        mydb.put(keys=("a","1"), val=w)
        mydb.put(keys=("a","2"), val=x)
        mydb.put(keys=("a","3"), val=y)
        mydb.put(keys=("a","4"), val=z)

        items = [(keys, asdict(data)) for keys, data in mydb.getItemIter()]
        assert items == [(('a', '1'), {'a': 'Big', 'b': 'Blue'}),
                        (('a', '2'), {'a': 'Tall', 'b': 'Red'}),
                        (('a', '3'), {'a': 'Fat', 'b': 'Green'}),
                        (('a', '4'), {'a': 'Eat', 'b': 'White'})]

        mydb.put(keys=("b","1"), val=w)
        mydb.put(keys=("b","2"), val=x)
        mydb.put(keys=("bc","3"), val=y)
        mydb.put(keys=("bc","4"), val=z)

        topkeys = ("b", "")  # append empty str to force trailing .sep
        items = [(keys, asdict(data)) for keys, data in mydb.getItemIter(keys=topkeys)]
        assert items == [(('b', '1'), {'a': 'Big', 'b': 'Blue'}),
                         (('b', '2'), {'a': 'Tall', 'b': 'Red'})]


        items = [(keys, asdict(data)) for keys, data in mydb.getItemIter()]
        assert items == [(('a', '1'), {'a': 'Big', 'b': 'Blue'}),
                        (('a', '2'), {'a': 'Tall', 'b': 'Red'}),
                        (('a', '3'), {'a': 'Fat', 'b': 'Green'}),
                        (('a', '4'), {'a': 'Eat', 'b': 'White'}),
                        (('b', '1'), {'a': 'Big', 'b': 'Blue'}),
                        (('b', '2'), {'a': 'Tall', 'b': 'Red'}),
                        (('bc', '3'), {'a': 'Fat', 'b': 'Green'}),
                        (('bc', '4'), {'a': 'Eat', 'b': 'White'})]

        assert mydb.cntAll() == 8

        assert mydb.trim(keys=("b", ""))
        items = [(keys, asdict(data)) for keys, data in mydb.getItemIter()]
        assert items == [(('a', '1'), {'a': 'Big', 'b': 'Blue'}),
                        (('a', '2'), {'a': 'Tall', 'b': 'Red'}),
                        (('a', '3'), {'a': 'Fat', 'b': 'Green'}),
                        (('a', '4'), {'a': 'Eat', 'b': 'White'}),
                        (('bc', '3'), {'a': 'Fat', 'b': 'Green'}),
                        (('bc', '4'), {'a': 'Eat', 'b': 'White'})]

        assert mydb.trim()
        items = [(keys, asdict(data)) for keys, data in mydb.getItemIter()]
        assert items == []

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
        mydb = koming.Komer(db=db, schema=AnotherClass, subkey='records.')
        sue = Record(first="Susan")
        keys = ("test_key", "0001")

        with pytest.raises(ValueError):
            mydb.put(keys=keys, val=sue)


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
        mydb = koming.Komer(db=db, schema=Record, subkey='records.')
        sue = Record(first="Susan")
        keys = ("test_key", "0001")
        mydb.put(keys=keys, val=sue)

        mydb = koming.Komer(db=db, schema=AnotherClass, subkey='records.')
        with pytest.raises(ValueError):
            mydb.get(keys)


def test_not_found_entity():
    @dataclass
    class Record:
        first: str

        def __iter__(self):
            return iter(asdict(self))

    with dbing.openLMDB() as db:
        mydb = koming.Komer(db=db, schema=Record, subkey='records.')
        sue = Record(first="Susan")
        keys = ("test_key", "0001")

        mydb.put(keys=keys, val=sue)
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
        k = koming.Komer(db=db, schema=Record, subkey='records.')
        srl = k._serializer(Kinds.mgpk)

        expected = b'\x86\xa5first\xa3Jim\xa4last\xa5Black\xa6street\xaf100 Main Street\xa4city\xa8Riverton\xa5state\xa2UT\xa3zip\xce\x00\x01HZ'
        assert srl(jim) == expected

        srl = k._serializer(Kinds.cbor)
        expected = b'\xa6efirstcJimdlasteBlackfstreeto100 Main StreetdcityhRivertonestatebUTczip\x1a\x00\x01HZ'
        assert srl(jim) == expected

        srl = k._serializer(Kinds.json)
        expected = b'{"first":"Jim","last":"Black","street":"100 Main Street","city":"Riverton","state":"UT","zip":84058}'
        assert srl(jim) == expected


def test_custom_serialization():
    @dataclass
    class Record:
        first: str  # first name
        last: str  # last name
        street: str  # street address
        city: str  # city name
        state: str  # state code
        zip: int  # zip code

        @staticmethod
        def _der(d):
            name = d["name"].split()
            street = d["address1"]
            city, state, z = d["address2"].split()

            return Record(first=name[0],
                          last=name[1],
                          street=street,
                          city=city,
                          state=state,
                          zip=int(z, 10)
                          )

        def _ser(self):
            d = dict(
                name="{} {}".format(self.first, self.last),
                address1="{}".format(self.street),
                address2="{} {} {}".format(self.city, self.state, self.zip)
            )

            return d


    jim = Record(first="Jim",
                 last="Black",
                 street="100 Main Street",
                 city="Riverton",
                 state="UT",
                 zip=84058)

    with dbing.openLMDB() as db:
        mydb = koming.Komer(db=db, schema=Record, subkey='records.')

        keys = ("test_key", "0001")
        mydb.put(keys=keys, val=jim)

        actual = mydb.get(keys=keys)
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058

        ser = db.getVal(mydb.sdb, mydb._tokey(keys))
        assert ser == b'{"name":"Jim Black","address1":"100 Main Street","address2":"Riverton UT 84058"}'


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
        k = koming.Komer(db=db, schema=Record, subkey='records.')

        desrl = k._deserializer(Kinds.mgpk)
        actual = helping.datify(Record, desrl(msgp))
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058

        desrl = k._deserializer(Kinds.json)
        actual = helping.datify(Record, desrl(json))
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058

        desrl = k._deserializer(Kinds.cbor)
        actual = helping.datify(Record, desrl(cbor))
        assert actual.first == "Jim"
        assert actual.last == "Black"
        assert actual.street == "100 Main Street"
        assert actual.city == "Riverton"
        assert actual.state == "UT"
        assert actual.zip == 84058



def test_dup_komer():
    """
    Test DupKomer object class
    """
    @dataclass
    class Endpoint: # ends
        """
        Service Endpoint ID Record with fields and keys to manage endpoints by role.
        Database Keys are (cid, role) where cid is endpoint controller identifier
        prefix and role is endpoint role such as watcher, witness etc
        """
        eid: str  # identifier prefix of endpoint
        name: str  # user friendly name of endpoint
        dts: str  # ISO-8601 datetime string of latest update

        def __iter__(self):
            return iter(asdict(self))

    @dataclass
    class Location:  # locs
        """
        Service Endpoint Record with fields and keys to compose endpoint location
        and cross reference to entry in Endpoint database.
        Database Keys are (eid, scheme) where eid is endpoint identifier prefix
        and the protocol scheme (tcp, https). The eid is usually nontransferable.
        """
        host: str  # hostname or host ip addresss string
        port: int  # port
        path: str  # path string
        cid: str  # identifier prefix of controller that authorizes endpoint
        role: str  # endpoint role such as watcher, witness etc
        dts: str  # ISO-8601 datetime string of latest update

        def __iter__(self):
            return iter(asdict(self))


    cid0 = "EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY"  # "EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY"
    cid1 = "EBLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E"  # "EsLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E"
    dts = '2021-01-01T00:00:00.000000+00:00'
    role = "witness"
    scheme = "https"

    wit0 = 'BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68'  # 'B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68'
    wit0end = Endpoint(eid=wit0, name='wit0', dts=dts)
    wit0loc = Location(host="localhost",
                    port="8080",
                    path="/witnesses/wit0",
                    cid=cid0,
                    role=role,
                    dts=dts)

    wit1 = 'BBd2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I'  # 'Bed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I'
    wit1end = Endpoint(eid=wit1, name='wit1', dts=dts)
    wit1loc = Location(host="localhost",
                port="8080",
                path="/witnesses/wit1",
                cid=cid0,
                role=role,
                dts=dts)

    wit2 = 'BCjDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts'  # BljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts'
    wit2end = Endpoint(eid=wit2, name='wit2', dts=dts)
    wit2loc = Location(host="localhost",
                port="8080",
                path="/witnesses/wit2",
                cid=cid0,
                role=role,
                dts=dts)

    wit3 = 'BD_esBko3sppQ0iH5HvMjtGfzJDVe_zH8ajywhjps804'  # 'B-_esBko3sppQ0iH5HvMjtGfzJDVe_zH8ajywhjps804'
    wit3end = Endpoint(eid=wit3, name='wit3', dts=dts)
    wit3loc = Location(host="localhost",
                port="8080",
                path="/witnesses/wit3",
                cid=cid1,
                role=role,
                dts=dts)

    locser = json.dumps(asdict(wit0loc)).encode("utf-8")
    endpnt = helping.datify(Location, json.loads(bytes(locser).decode("utf-8")))
    assert isinstance(endpnt, Location)

    locser = json.dumps(asdict(wit0loc)).encode("utf-8")
    endpnt = helping.datify(Location, json.loads(bytes(locser).decode("utf-8")))
    assert isinstance(endpnt, Location)

    ends = [wit0end, wit1end, wit2end]
    eids = [wit0, wit1, wit2]
    locs = [wit0loc, wit1loc, wit2loc]

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        endDB = koming.DupKomer(db=db, schema=Endpoint, subkey='ends.')
        assert isinstance(endDB, koming.DupKomer)
        assert endDB.sdb.flags()["dupsort"]
        assert endDB.sep == endDB.Sep == "."

        locDB = koming.Komer(db=db, schema=Location, subkey='locs.')
        assert isinstance(locDB, koming.Komer)
        assert not locDB.sdb.flags()["dupsort"]
        assert locDB.sep == locDB.Sep == "."

        keys0 = (cid0, role)
        key = endDB._tokey(keys0)
        assert key == f"{cid0}.witness".encode("utf-8")  # b'EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY.witness'
        assert endDB._tokeys(key) == keys0
        keys1 = (cid1, role)

        assert endDB.put(keys=keys0, vals=[wit2end, wit1end, wit0end])  # reverse lex order
        assert endDB.cnt(keys0) == 3
        actuals = endDB.get(keys=keys0)
        assert len(actuals) == 3
        assert actuals == [wit0end, wit1end, wit2end]  # lex order
        actual = endDB.getLast(keys=keys0)
        assert actual == wit2end

        for i, end in enumerate(endDB.getIter(keys0)):
            assert end == ends[i]

        assert endDB.cnt(keys0) == 3

        assert endDB.pin(keys=keys0, vals=[wit3end])
        assert endDB.cnt(keys0) == 1
        actuals = endDB.get(keys=keys0)
        assert len(actuals) == 1
        assert actuals == [wit3end]

        assert endDB.rem(keys0)
        assert endDB.cnt(keys0) == 0
        assert not endDB.rem(keys0)
        assert endDB.cnt(keys0) == 0
        actuals = endDB.get(keys=keys0)
        assert len(actuals) == 0
        assert not endDB.get(keys=keys0)

        for i, end in enumerate(ends):  # fill both dbs
            assert endDB.put(keys=(cid0, role), vals=[end])
            assert locDB.put(keys=(eids[i], scheme), val=locs[i])

        assert endDB.put(keys=(cid1, role), vals=[wit3end])
        assert locDB.put(keys=(wit3, scheme), val=wit3loc)

        for i, end in enumerate(endDB.getIter(keys=(cid0, role))):
            loc = locDB.get(keys=(end.eid, scheme))
            assert loc == locs[i]

        for end in endDB.getIter(keys=(cid1, role)):
            loc = locDB.get(keys=(end.eid, scheme))
            assert loc == wit3loc


        ends = ends + [wit3end]
        i = 0
        for keys, end in endDB.getItemIter():
            assert end == ends[i]
            i += 1

        i = 0
        for keys, end in endDB.getItemIter(keys=(cid0, "" )):
            assert end == ends[i]
            i += 1

        alllocs =  locs +  [wit3loc]
        i = 0
        for keys, loc in locDB.getItemIter():
            assert loc == alllocs[i]
            i += 1

        i = 0
        for keys, loc in locDB.getItemIter(keys=(eids[0], "" )):
            assert loc == locs[i]
            i += 1


    assert not os.path.exists(db.path)
    assert not db.opened



def test_ioset_komer():
    """
    Test IoSetKomer object class
    """
    @dataclass
    class Endpoint: # ends
        """
        Service Endpoint ID Record with fields and keys to manage endpoints by role.
        Database Keys are (cid, role) where cid is endpoint controller identifier
        prefix and role is endpoint role such as watcher, witness etc
        """
        eid: str  # identifier prefix of endpoint
        name: str  # user friendly name of endpoint
        dts: str  # ISO-8601 datetime string of latest update

        def __iter__(self):
            return iter(asdict(self))

    @dataclass
    class Location:  # locs
        """
        Service Endpoint Record with fields and keys to compose endpoint location
        and cross reference to entry in Endpoint database.
        Database Keys are (eid, scheme) where eid is endpoint identifier prefix
        and the protocol scheme (tcp, https). The eid is usually nontransferable.
        """
        host: str  # hostname or host ip addresss string
        port: int  # port
        path: str  # path string
        cid: str  # identifier prefix of controller that authorizes endpoint
        role: str  # endpoint role such as watcher, witness etc
        dts: str  # ISO-8601 datetime string of latest update

        def __iter__(self):
            return iter(asdict(self))


    cid0 = "EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY"
    cid1 = "EBLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E"
    dts = '2021-01-01T00:00:00.000000+00:00'
    role = "witness"
    scheme = "https"

    wit0 = 'BA89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68'
    wit0end = Endpoint(eid=wit0, name='wit0', dts=dts)
    wit0loc = Location(host="localhost",
                    port="8080",
                    path="/witnesses/wit0",
                    cid=cid0,
                    role=role,
                    dts=dts)

    wit1 = 'BBd2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I'
    wit1end = Endpoint(eid=wit1, name='wit1', dts=dts)
    wit1loc = Location(host="localhost",
                port="8080",
                path="/witnesses/wit1",
                cid=cid0,
                role=role,
                dts=dts)

    wit2 = 'BCjDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts'
    wit2end = Endpoint(eid=wit2, name='wit2', dts=dts)
    wit2loc = Location(host="localhost",
                port="8080",
                path="/witnesses/wit2",
                cid="EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY",
                role=role,
                dts=dts)

    wit3 = 'BD_esBko3sppQ0iH5HvMjtGfzJDVe_zH8ajywhjps804'
    wit3end = Endpoint(eid=wit3, name='wit3', dts=dts)
    wit3loc = Location(host="localhost",
                port="8080",
                path="/witnesses/wit3",
                cid=cid1,
                role=role,
                dts=dts)

    locser = json.dumps(asdict(wit0loc)).encode("utf-8")
    endpnt = helping.datify(Location, json.loads(bytes(locser).decode("utf-8")))
    assert isinstance(endpnt, Location)

    locser = json.dumps(asdict(wit0loc)).encode("utf-8")
    endpnt = helping.datify(Location, json.loads(bytes(locser).decode("utf-8")))
    assert isinstance(endpnt, Location)

    ends = [wit0end, wit1end, wit2end]  #  lex order
    rends = [wit2end, wit1end, wit0end]  # reverse lex order
    eids = [wit0, wit1, wit2]
    locs = [wit0loc, wit1loc, wit2loc]

    with dbing.openLMDB() as db:
        assert isinstance(db, dbing.LMDBer)
        assert db.name == "test"
        assert db.opened

        endDB = koming.IoSetKomer(db=db, schema=Endpoint, subkey='ends.')
        assert isinstance(endDB, koming.IoSetKomer)
        assert not endDB.sdb.flags()["dupsort"]
        assert endDB.sep == endDB.Sep == "."

        locDB = koming.Komer(db=db, schema=Location, subkey='locs.')
        assert isinstance(locDB, koming.Komer)
        assert not locDB.sdb.flags()["dupsort"]
        assert locDB.sep == locDB.Sep == "."

        keys0 = (cid0, role)
        key = endDB._tokey(keys0)
        assert key == f"{cid0}.witness".encode("utf-8")  #  b'EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY.witness'
        assert endDB._tokeys(key) == keys0

        keys1 = (cid1, role)

        assert endDB.put(keys=keys0, vals=[wit2end, wit1end, wit0end])  # reverse lex order
        assert endDB.cnt(keys0) == 3
        actuals = endDB.get(keys=keys0)
        assert len(actuals) == 3
        assert actuals == [wit2end, wit1end, wit0end]  # insertion order
        actual = endDB.getLast(keys=keys0)
        assert actual == wit0end

        for i, end in enumerate(endDB.getIter(keys0)):
            assert end == rends[i]

        assert endDB.cnt(keys0) == 3

        assert endDB.pin(keys=keys0, vals=[wit3end])
        assert endDB.cnt(keys0) == 1
        actuals = endDB.get(keys=keys0)
        assert len(actuals) == 1
        assert actuals == [wit3end]

        assert endDB.rem(keys0)
        assert endDB.cnt(keys0) == 0
        assert not endDB.rem(keys0)
        assert endDB.cnt(keys0) == 0
        actuals = endDB.get(keys=keys0)
        assert len(actuals) == 0
        assert not endDB.get(keys=keys0)

        # fill both dbs
        for i, end in enumerate(ends):  # keys0
            assert endDB.put(keys=keys0, vals=[end])
            assert locDB.put(keys=(eids[i], scheme), val=locs[i])

        assert endDB.put(keys=keys1, vals=[wit3end])  # keys1
        assert locDB.put(keys=(wit3, scheme), val=wit3loc)

        for i, end in enumerate(endDB.getIter(keys=(cid0, role))):
            loc = locDB.get(keys=(end.eid, scheme))
            assert loc == locs[i]

        for end in endDB.getIter(keys=(cid1, role)):
            loc = locDB.get(keys=(end.eid, scheme))
            assert loc == wit3loc

        ## test IoItem methods
        iokeys0 = [f'{cid0}.witness.00000000000000000000000000000000'.encode("utf-8"),
                  f'{cid0}.witness.00000000000000000000000000000001'.encode("utf-8"),
                  f'{cid0}.witness.00000000000000000000000000000002'.encode("utf-8")]
        iokeys0 = [endDB._tokeys(iokey) for iokey in iokeys0]
        assert iokeys0 == [('EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                    'witness',
                    '00000000000000000000000000000000'),
                   ('EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                    'witness',
                    '00000000000000000000000000000001'),
                   ('EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                    'witness',
                    '00000000000000000000000000000002')]

        # test getItemIter
        i = 0
        for keys, end in endDB.getItemIter(keys=keys0):
            assert end == ends[i]
            assert keys == keys0
            i += 1

        ends = ends + [wit3end]
        i = 0
        for keys, end in endDB.getItemIter():
            assert end == ends[i]
            assert keys in  (keys0, keys1)
            i += 1

        i = 0
        for keys, end in endDB.getItemIter(keys=(cid0, "")):
            assert end == ends[i]
            i += 1

        alllocs = locs + [wit3loc]
        i = 0
        for keys, loc in locDB.getItemIter():
            assert loc == alllocs[i]
            i += 1

        i = 0
        for keys, loc in locDB.getItemIter(keys=(eids[0], "")):
            assert loc == locs[i]
            i += 1


        # test getAllIoItem
        iokeys1 = [f'{cid1}.witness.00000000000000000000000000000000'.encode("utf-8")]
        iokeys1 = [endDB._tokeys(iokey) for iokey in iokeys1]
        iokeysall = iokeys0 + iokeys1
        assert iokeysall ==  [('EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                            'witness',
                            '00000000000000000000000000000000'),
                           ('EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                            'witness',
                            '00000000000000000000000000000001'),
                           ('EAB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY',
                            'witness',
                            '00000000000000000000000000000002'),
                           ('EBLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E',
                            'witness',
                            '00000000000000000000000000000000')]

        i = 0
        for iokeys, end in endDB.getFullItemIter(keys=(cid0, "")):
            assert end == ends[i]
            assert iokeys == iokeysall[i]
            i += 1

        #for iokeys, val in endDB.getFullItemIter():
            #assert endDB.remIokey(iokeys=iokeys)

        #assert endDB.cnt(keys=keys0) == 0
        #assert endDB.cnt(keys=keys1) == 0

    assert not os.path.exists(db.path)
    assert not db.opened


if __name__ == "__main__":
    test_kom_happy_path()
    test_kom_get_item_iter()
    test_put_invalid_dataclass()
    test_get_invalid_dataclass()
    test_not_found_entity()
    test_serialization()
    test_custom_serialization()
    test_deserialization()
    test_dup_komer()
    test_ioset_komer()
