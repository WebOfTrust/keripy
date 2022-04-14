# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
from hio.base import doing
from hio.help import decking


class Funneler(doing.Doer):
    """ Cue message funnel

    Funnler represents a cue message funnel taking messages from any number
    of destination cues and funneling them into one destination cue.

    """

    def __init__(self, srcs, dest=None, **kwa):
        """ Create a Funneler attached to provided sources (srcs) that routes messages to dest

        The destination cue can be provided or an empty local one will be created

        Parameters:
           srcs (list): list of cue Decks representing the collection of messages to funnel
           dest (Optional[Deck]): optional destination for messages from all srcs

        """

        self.srcs = srcs
        self.dest = dest if dest is not None else decking.Deck()

        super(Funneler, self).__init__(**kwa)

    def processCues(self):
        """ Take one pass through source cues, popping messages and cue'ing them to destination """
        for src in self.srcs:
            if src:
                msg = src.popleft()
                self.dest.append(msg)

    def do(self, tymth, tock=0.0, **opts):
        """ Process cues from incoming srcs and route them to dest

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            self.processCues()
            yield self.tock
