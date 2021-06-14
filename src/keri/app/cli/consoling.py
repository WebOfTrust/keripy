# -*- encoding: utf-8 -*-
"""
KERI
keri.app.cli module

command line utility support
"""
import multicommand
from hio import help
from hio.base import doing
from hio.core.serial import serialing

from . import commands
from .. import keeping
from ..habbing import Habitat
from ...db import basing

logger = help.ogler.getLogger()


class Consoling(doing.DoDoer):
    """
    Manages command console
    """

    def __init__(self, name: str, console=None, **kwa):
        """

        """
        super(Consoling, self).__init__(**kwa)
        self.always = True
        self.console = console if console is not None else serialing.Console()
        self.name = name
        # Transferable from config

        db = basing.openDB(name=name, temp=False)
        ks = keeping.openKS(name=name, temp=False)

        self.hab = Habitat(name=name, db=db, ks=ks, temp=False)

        self.doers.extend([basing.BaserDoer(baser=db),
                           keeping.KeeperDoer(keeper=ks),
                           self.parserDo])

    @doing.doize()
    def parserDo(self):
        """
         Returns Doist compatible generator method (doer dog) to process
            .kevery.cues deque????

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
        line = self.console.get().decode('utf-8')  # process one line of input
        if not line:
            return False

        chunks = line.lower().split()
        self.displayPrompt()

        if not chunks:  # empty list
            self.send("Print CLI help")
            return False

        parser = multicommand.create_parser(commands)
        args = parser.parse_args(chunks)

        if hasattr(args, "handler"):
            ah = args.handler(args)
            print(ah)
            print("hasattr")

    def displayPrompt(self):
        self.console.put(f'{self.name}: '.encode('utf-8'))

    def send(self, s):
        self.console.put(s.encode('-utf-8'))
        self.displayPrompt()
