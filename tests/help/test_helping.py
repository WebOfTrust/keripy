# -*- encoding: utf-8 -*-
"""
tests.help.test_helping module

"""
import pytest

import pysodium


from keri.help.helping import mdict
from keri.help.helping import extractValues


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
    (b'{"vs":"KERI10JSON0000fb_","aid":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_'
                                b'ZOoeKtWTOunRA","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                                b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbR'
                                b'byAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}-AABA'
                                b'A8yMYsLXbmnwXWIsdZ7Uzw3Q7ppynI1xYCf-43hsf7XIgp5NZ-HlZbDC3o0lwWEF'
                                b'nk4O6glvxx3bJ8Zfgg606DA')

    ked = dict(vs="KERI10JSON0000fb_",
               aid="DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
               sn="0",
               ilk="icp",
               sith="1",
               keys=["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],
               nxt="EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4",
               toad="0",
               wits=[],  # list of qb64 may be empty
               cnfg=[dict(trait="EstOnly")],
               )

    labels = ["vs", "ilk", "sith", "keys", "nxt", "toad", "wits", "cnfg"]

    values = extractValues(ked=ked, labels=labels)

    assert values == [  'KERI10JSON0000fb_',
                        'icp',
                        '1',
                        'DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA',
                        'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4',
                        '0',
                        'EstOnly'
                    ]


    ser = "".join(values)

    assert ser == ('KERI10JSON0000fb_icp1DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtW'
                   'TOunRAEGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_40EstOnly')
    """End Test"""

def test_conversions():
    """
    Test conversion helpers
    """




if __name__ == "__main__":
    test_extractvalues()
