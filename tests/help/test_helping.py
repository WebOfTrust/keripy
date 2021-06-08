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
from keri.help.helping import mdict
from keri.help.helping import extractValues
from keri.help.helping import datify

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

    """End Test"""


def test_mdict():
    """
    Test mdict multiple value dict
    """
    from multidict import MultiDict
    from collections.abc import MutableMapping

    m = mdict()
    assert isinstance(m, MultiDict)
    assert isinstance(m, MutableMapping)
    assert not isinstance(m, dict)

    m = mdict(a=1, b=2, c=3)

    m.add("a", 7)
    m.add("b", 8)
    m.add("c", 9)

    assert m.getone("a") == 1
    assert m.nabone("a") == 7

    assert m.get("a") == 1
    assert m.nab("a") == 7

    assert m.getall("a") == [1, 7]
    assert m.naball("a") == [7, 1]

    assert m.nabone("z", 5) == 5
    with pytest.raises(KeyError):
        m.nabone("z")

    assert m.nab("z", 5) == 5
    assert m.nab("z") == None

    assert m.naball("z", []) == []
    with pytest.raises(KeyError):
        m.naball("z")

    assert list(m.keys()) == ['a', 'b', 'c', 'a', 'b', 'c']

    assert m.firsts() == [('a', 1), ('b', 2), ('c', 3)]

    assert m.lasts() == [('a', 7), ('b', 8), ('c', 9)]

    """End Test"""

def test_extractvalues():
    """
    Test function extractValues
    """
    (b'{"vs":"KERI10JSON0000fb_","pre":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_'
                                b'ZOoeKtWTOunRA","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                                b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbR'
                                b'byAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}-AABA'
                                b'A8yMYsLXbmnwXWIsdZ7Uzw3Q7ppynI1xYCf-43hsf7XIgp5NZ-HlZbDC3o0lwWEF'
                                b'nk4O6glvxx3bJ8Zfgg606DA')

    ked = dict(vs="KERI10JSON0000fb_",
               pre="DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
               sn="0",
               ilk="icp",
               sith="1",
               keys=["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],
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
                        'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4',
                        '0',
                        'EO'
                    ]


    ser = "".join(values)

    assert ser == ('KERI10JSON0000fb_icp1DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtW'
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
    test_utilities()
