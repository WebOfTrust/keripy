# -*- encoding: utf-8 -*-
"""
KERI
keri.app.cli module

command line utility support
"""

from hio import help
from hio.base import doing

from keri.help import decking

logger = help.ogler.getLogger()


class Dispatching(doing.DoDoer):
    """
    Dispatching
    inq Commands
    outputs
    """

    def __init__(self, inq: decking.Deck = None, oqu: decking.Deck = None, doers=None, **kwa):
        self.always = True
        self.inq = inq if inq is not None else decking.Deck()
        self.oqu = oqu if oqu is not None else decking.Deck()

        self.doers = doers if doers is not None else [self.dispatchDo]

        super(Dispatching, self).__init__(doers=self.doers, **kwa)

    @doing.doize()
    def dispatchDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatible generator method (doer dog) to process
            command input

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters

        Usage:
            add to doers list
        """
        while True:
            if self.inq:
                i = self.inq.popleft()

                doer = i.handler(i.opts)
                print(doer)
                self.doers.extend(doer)
                for o in doer.oqu:
                    print(o)

            yield self.tock
