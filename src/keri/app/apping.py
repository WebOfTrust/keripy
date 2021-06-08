# -*- encoding: utf-8 -*-
"""
KERI
keri.app.apping module

"""
import os
import shutil
# -*- encoding: utf-8 -*-
"""
KERI
keri.app.apping module

application utility support
"""


import json
from dataclasses import dataclass, asdict
from typing import Type

import cbor2
import msgpack
import lmdb

from hio.base import doing
from hio.core.serial import serialing

from .. import kering
from .. import help
from ..help import helping
from ..db import dbing, basing, koming
from . import keeping
from ..core import coring, eventing, parsing
from . import habbing


logger = help.ogler.getLogger()


class Consoler(doing.Doer):
    """
    Manages command console
    """

    def __init__(self, db=None, console=None,  **kwa):
        """

        """
        super(Consoler, self).__init__(**kwa)
        self.db = db if db is not None else basing.Baser()
        self.console = console if console is not None else serialing.Console()


    def enter(self):
        """"""
        if not self.console.reopen():
            raise IOError("Unable to open serial console.")



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
        line = self.console.get()  # process one line of input
        if not line:
            return False
        chunks = line.lower().split()

        #args = parser.parse_args(chunks)
        #if hasattr(args, "handler"):
            #args.handler(args)




        if not chunks:  # empty list
            self.console.put("Try one of: l[eft] r[ight] w[alk] s[top]\n")
            return False
        command = None
        verb = chunks[0]

        if verb.startswith('r'):
            command = ('turn', 'right')

        elif verb.startswith('l'):
            command = ('turn', 'left')

        elif verb.startswith('w'):
            command = ('walk', 1)

        elif verb.startswith('s'):
            command = ('stop', '')

        else:
            self.console.put("Invalid command: {0}\n".format(verb))
            self.console.put("Try one of: t[urn] s[top] w[alk]\n")
            return False

        self.console.put("Did: {} {}\n".format(command[0], command[1]))

        return (False)


    def exit(self):
        """"""
        self.console.close()
