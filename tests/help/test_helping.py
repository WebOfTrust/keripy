# -*- encoding: utf-8 -*-
"""
tests.help.test_helping module

"""
import pytest

import datetime
import pysodium
import fractions

from dataclasses import dataclass, asdict

from keri.help import helping
from keri.help.helping import isign, sceil
from keri.help.helping import extractValues
from keri.help.helping import dictify, datify, klasify

def test_utilities():
    """
    Test utility functions
    """
    assert isign(1) == 1
    assert isign(-1) == -1
    assert isign(0) == 0
    assert isign(2) == 1
    assert isign(-1) == -1

    assert isign(1.0) == 1
    assert isign(-1.0) == -1
    assert isign(0.0) == 0

    assert isign(1.5) == 1
    assert isign(-1.5) == -1
    assert isign(0.5) == 1
    assert isign(-0.5) == -1


    assert sceil(0.5) == 1
    assert sceil(-0.5) == -1
    assert sceil(1) == 1
    assert sceil(-1) == -1
    assert sceil(0) == 0
    assert sceil(0.0) == 0

    assert sceil(1.1) == 2
    assert sceil(-1.1) == -2
    assert sceil(2.8) == 3
    assert sceil(-2.8) == -3

    assert sceil(fractions.Fraction(3, 2)) == 2
    assert sceil(fractions.Fraction(-3, 2)) == -2
    assert sceil(fractions.Fraction(0)) == 0



def test_datify():
    """
    Test convert dict to dataclass

    dataclass, astuple, asdict, fields,
    """
    @dataclass
    class Point:
        x: float
        y: float

    @dataclass
    class Line:
        a: Point
        b: Point

    line = Line(Point(1,2), Point(3,4))
    assert line == datify(Line, asdict(line))

    assert asdict(line) == {'a': {'x': 1, 'y': 2}, 'b': {'x': 3, 'y': 4}}

    pdict = dict(x=3, y=4)
    pdata = datify(Point, pdict)
    assert isinstance(pdata, Point)

    @dataclass
    class Circle:
        radius: float

        @staticmethod
        def _der(d):
            p = d["perimeter"]
            r = p / 2 / 3.14

            return Circle(radius=r)

    d = {'area': 50.24, 'perimeter': 25.12}
    c = datify(Circle, d)
    assert c.radius == 4

    """End Test"""


def test_dictify():
    """
    Test convert dataclass to dict
    """

    @dataclass
    class Point:
        x: float
        y: float

    @dataclass
    class Line:
        a: Point
        b: Point

    line = Line(Point(1, 2), Point(3, 4))
    assert dictify(line) == {'a': {'x': 1, 'y': 2}, 'b': {'x': 3, 'y': 4}}

    @dataclass
    class Circle:
        radius: float

        def _ser(self):
            d = dict(
                area=self.radius**2*3.14,
                perimeter=2*self.radius*3.14
            )

            return d

    c = Circle(radius=4)
    assert dictify(c) == {'area': 50.24, 'perimeter': 25.12}


def test_klasify():
    """
    Test klasify utility function
    """
    from keri.core.coring import Dater, Seqner, Diger

    dater = Dater(dts="2021-01-01T00:00:00.000000+00:00")
    assert dater.qb64 == '1AAG2021-01-01T00c00c00d000000p00c00'

    seqner = Seqner(sn=20)
    assert seqner.qb64 == '0AAAAAAAAAAAAAAAAAAAAAAU'

    diger = Diger(ser=b"Hello Me Maties.")
    assert diger.qb64 == 'ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ'

    sers = (dater.qb64, seqner.qb64, diger.qb64)
    klases = (Dater, Seqner, Diger)
    triple = klasify(sers=sers, klases=klases)
    results = tuple(val.qb64 for val in triple)
    assert sers == results

    args = ("qb64", "snh", "qb64")
    sers = (dater.qb64, seqner.snh, diger.qb64)
    triple = klasify(sers=sers, klases=klases, args=args)
    results = tuple(val.qb64 for val in triple)
    assert results == (dater.qb64, seqner.qb64, diger.qb64)

    klases = (str, Seqner, Diger)
    args = (None, "snh", "qb64")
    sers = (25, f"{seqner.sn:032x}", diger.qb64)
    assert sers == (25,
                    '00000000000000000000000000000014',
                    'ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ')
    t, s, d = klasify(sers=sers, klases=klases, args=args)
    assert t == "25"
    assert s.sn == 20
    assert d.qb64 == diger.qb64


    klases = (None, Seqner, Diger)
    args = (None, "snh", "qb64")
    sers = ("hello", f"{seqner.sn:032x}", diger.qb64)
    t, s, d = klasify(sers=sers, klases=klases, args=args)
    assert t == "hello"
    assert s.sn == 20
    assert d.qb64 == diger.qb64

    """Done Test"""




def test_extractvalues():
    """
    Test function extractValues
    """

    ked = dict(vs="KERI10JSON0000fb_",
               pre="DAuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
               sn="0",
               ilk="icp",
               sith="1",
               keys=["DAuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],
               nxt="EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4",
               toad="0",
               wits=[],  # list of qb64 may be empty
               cnfg=["EO"],
               )

    labels = ["vs", "ilk", "sith", "keys", "nxt", "toad", "wits", "cnfg"]

    values = extractValues(ked=ked, labels=labels)

    assert values == [  'KERI10JSON0000fb_',
                        'icp',
                        '1',
                        'DAuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4',
                        '0',
                        'EO'
                    ]


    ser = "".join(values)

    assert ser == ('KERI10JSON0000fb_icp1DAuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtW'
                   'TOunRAEGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_40EO')
    """End Test"""

def test_iso8601():
    """
    Test datetime ISO 8601 helpers
    """
    # dts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    dts = '2020-08-22T20:34:41.687702+00:00'
    dt = helping.fromIso8601(dts)
    assert dt.year == 2020
    assert dt.month == 8
    assert dt.day == 22

    dtb = b'2020-08-22T20:34:41.687702+00:00'
    dt = helping.fromIso8601(dts)
    assert dt.year == 2020
    assert dt.month == 8
    assert dt.day == 22


    dts1 = helping.nowIso8601()
    dt1 = helping.fromIso8601(dts1)
    dts2 = helping.nowIso8601()
    dt2 = helping.fromIso8601(dts2)

    assert dt2 > dt1

    assert dts1 == helping.toIso8601(dt1)
    assert dts2 == helping.toIso8601(dt2)

    dts3 = helping.toIso8601()
    dt3 = helping.fromIso8601(dts3)

    assert dt3 > dt2

    td = dt3 - dt2  # timedelta
    assert td.microseconds > 0.0

    dt4 = dt + datetime.timedelta(seconds=25.0)
    dts4 = helping.toIso8601(dt4)
    assert dts4 == '2020-08-22T20:35:06.687702+00:00'
    dt4 = helping.fromIso8601(dts4)
    assert (dt4 - dt).seconds == 25.0

    # test for microseconds zero
    dts = "2021-01-01T00:00:00.000000+00:00"
    dt = helping.fromIso8601(dts)
    dts1 = helping.toIso8601(dt)
    assert dts1 == dts



    """ End Test """


if __name__ == "__main__":
    test_klasify()
