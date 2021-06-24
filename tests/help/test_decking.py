# -*- encoding: utf-8 -*-
"""
tests.help.test_decking module

"""
import pytest

from keri.help.decking import Deck

def test_deck():
    """
    Test Deck class
    """
    deck = Deck()
    assert len(deck) == 0
    assert not deck  # empty

    with pytest.raises(IndexError):
        deck.pull()

    assert deck.pull(emptive=True) is None

    deck.push("A")
    assert deck.pull() == "A"
    deck.push("B")
    assert deck.pull(emptive=True) == "B"
    assert not deck

    deck.push(None)
    assert not deck

    deck = Deck(["A", "B", "C"])
    assert "A" in  deck
    assert "B" in  deck
    assert "C" in  deck

    assert repr(deck) == "Deck(['A', 'B', 'C'])"
    assert str(deck) == "Deck(['A', 'B', 'C'])"

    deck.clear()
    assert not deck
    deck.extend(["A", "B", "C"])
    assert len(deck) == 3

    stuff = []
    while deck:
        stuff.append(deck.pull())
    assert stuff == ["A", "B", "C"]
    assert not deck
    deck.extend(stuff)
    assert len(deck) == 3

    stuff = []
    for x in deck:
        stuff.append(x)
    assert deck == Deck(['A', 'B', 'C'])
    assert stuff == ['A', 'B', 'C']

    stuff = [x for x in deck]
    assert stuff == ["A", "B", "C"]

    stuff = []
    while x := deck.pull(emptive=True):
        stuff.append(x)
    assert stuff == ["A", "B", "C"]
    assert not deck

    deck.extend(stuff)
    stuff = []
    while (x := deck.pull(emptive=True)) is not None:
        stuff.append(x)
    assert stuff == ["A", "B", "C"]
    assert not deck

    deck.extend([False, "", []])  # falsy elements but not None
    stuff = []
    while (x := deck.pull(emptive=True)) is not None:
        stuff.append(x)
    assert stuff == [False, "", []]
    assert not deck


    """End Test"""


if __name__ == "__main__":
    test_deck()
