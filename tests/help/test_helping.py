# -*- encoding: utf-8 -*-
"""
tests.help.test_helping module

"""
import pytest

import pysodium


from keri.help.helping import mdict


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

def test_conversions():
    """
    Test conversion helpers
    """




if __name__ == "__main__":
    test_mdict()
