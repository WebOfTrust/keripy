# -*- encoding: utf-8 -*-
"""
KERI
keri.app.cli.parsing module

command line parsing support
"""
import multicommand
from hio.base import doing
from hio.core.serial import serialing

from keri.app.cli import commands


class ParserDoer(doing.Doer):

    def __init__(self, parser, **kwa):
        super(ParserDoer, self).__init__(**kwa)

        self.parser = parser


class Parser(doing.Doer):
    """
    Manages command console
    """

    def __init__(self, name=None, console=None, **kwa):
        """

        """
        super(Parser, self).__init__(**kwa)
        self.currentCommand = None
        self.name = name
        self.console = console if console is not None else serialing.Console()

    def enter(self):
        """"""
        if not self.console.reopen():
            raise IOError("Unable to open serial console.")

        print("Interactive KERI Console (KLI)")
        self.displayPrompt()

    def recur(self, tyme):
        """
        Do 'recur' context actions. Override in subclass.
        Regular method that perform repetitive actions once per invocation.
        Assumes resource setup in .enter() and resource takedown in .exit()
        (see ReDoer below for example of .recur that is a generator method)

        Returns completion state of recurrence actions.
           True means done False means continue

        Parameters:
            Doist feeds its .tyme through .send to .do yield which passes it here.


        .recur maybe implemented by a subclass either as a non-generator method
        or a generator method. This stub here is as a non-generator method.
        The base class .do detects which type:
            If non-generator .do method runs .recur method once per iteration
                until .recur returns (True)
            If generator .do method runs .recur with (yield from) until .recur
                returns (see ReDoer for example of generator .recur)

        """
        line = self.console.get().decode('utf-8')  # process one line of input
        if not line:
            return False

        chunks = line.lower().split()
        self.displayPrompt()

        if not chunks:  # empty list
            self.send("Try one of: l[eft] r[ight] w[alk] s[top]\n")
            return False

        parser = multicommand.create_parser(commands)
        args = parser.parse_args(chunks)
        if hasattr(args, "handler"):
            ah = args.handler(args)
            print(ah)

        return False

    def displayPrompt(self):
        self.console.put(f'{self.name}: '.encode('utf-8'))

    def send(self, s):
        self.console.put(s.encode('-utf-8'))
        self.displayPrompt()

    def exit(self):
        """"""
        self.console.close()
