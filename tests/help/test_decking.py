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

    deck = Deck(["A", "B", "C"])
    assert "A" in  deck
    assert "B" in  deck
    assert "C" in  deck

    assert repr(deck) == "Deck(['A', 'B', 'C'])"
    assert str(deck) == "Deck(['A', 'B', 'C'])"

    """End Test"""


if __name__ == "__main__":
    test_deck()
