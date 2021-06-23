# -*- encoding: utf-8 -*-
"""
KERI
keri.app.cli module

command line utility support
"""
from typing import Type

import multicommand
from hio import help
from hio.base import doing
from hio.core.serial import serialing

from . import commands
from ...help.decking import Deck

logger = help.ogler.getLogger()


class Consoling(doing.DoDoer):
    """
    Consoling
    inq console line input
    oqu Commands
    """

    def __init__(self, name, inq: Type[Deck] = None, oqu: Type[Deck] = None, doers=None, console=None, **kwa):
        self.always = True
        self.console = console if console is not None else serialing.Console()
        self.console.reopen()
        self.parser = multicommand.create_parser(commands)
        self.inq = inq if inq is not None else Deck()
        self.oqu = oqu if oqu is not None else Deck()
        self.name = name

        self.doers = doers if doers is not None else [self.parserDo]

        super(Consoling, self).__init__(doers=self.doers, **kwa)
        self.displayPrompt()

    @doing.doize()
    def parserDo(self, tymth=None, tock=0.0, **opts):
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
            line = self.console.get().decode('utf-8')  # process one line of input
            if not line:
                yield self.tock
                continue

            chunks = line.lower().split()
            self.displayPrompt()

            if not chunks:  # empty list
                yield self.tock
                continue

            args = self.parser.parse_args(chunks)
            setattr(args, "name", self.name)

            if hasattr(args, "parser"):
                self.oqu.push(args.parser(args))
                yield self.tock
                continue

            self.displayPrompt()
            yield self.tock

    def displayPrompt(self):
        self.console.put(f'{self.name}: '.encode('utf-8'))

    def send(self, s):
        self.console.put(s.encode('-utf-8'))
