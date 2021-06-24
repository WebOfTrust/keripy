# -*- encoding: utf-8 -*-
"""
keri.help.decking module

Support for Deck class

"""
from collections import deque
from typing import Any

class Deck(deque):
    """
    Extends deque to support deque access convenience methods .push and .pull
    to remove confusion  about which side of the deque to use (left or right).

    Extends deque with .push an .pull methods to support a different pattern for
    access. .push does not allow  a value of None to be added to the Deck. This
    enables retrieval  with .pull(emptive=True) which returns None when empty
    instead of raising IndexError. This allows use of the walrus operator on
    a pull to both assign and check for empty. For example:

    while x := deck.pull(emptive=True):
        stuff.append(x)

    Local methods:
    .push(x) = add x if x is not None to the right side of deque (like append)
    .pull(x) = remove and return element from left side of deque (like popleft)


    Inherited methods from deque:
    .append(x)             = add x to right side of deque
    .appendleft(x)         = add x to left side of deque
    .clear()               = clear all items from deque leaving it a length 0
    .count(x)              = count the number of deque elements equal to x.
    .extend(iterable)      = append elements of iterable to right side
    .extendleft(iterable)  = append elemets of iterable to left side
                             (this reverses iterable)
    .pop()                 = remove and return element from right side
                              if empty then raise IndexError
    .popleft()             = remove and return element from left side
                              if empty then raise IndexError
    .remove(x)             = remove first occurence of x left to right
                              if not found raise ValueError
    .rotate(n)             = rotate n steps to right if neg rotate to left

    Built in methods supported:
    len(d)
    reversed(d)
    copy.copy(d)
    copy.deepcopy(d)
    subscripts d[0] d[-1]

    Attributes:
    .maxlen  = maximum size of Deck or None if unbounded

    """
    def __repr__(self):
        """
        Custome repr for Deck
        """
        itemreprs = repr(list(self))

        return ("Deck({0})".format(itemreprs))


    def push(self, elem: Any):
        """
        If not None, add elem to right side of deque, Otherwise ignore
        Parameters:
            elem (Any): element to be appended to deck (deque)
        """
        if elem is not None:
            self.append(elem)


    def pull(self, emptive=False):
        """
        Remove and return elem from left side of deque,
        If empty and emptive return None else raise IndexError

        Parameters:
            emptive (Boolean): True means return None instead of raise IndexError
               when attempt to pull
               False means normal behavior of deque
        """
        try:
            return self.popleft()
        except IndexError:
            if not emptive:
                raise
            return None
