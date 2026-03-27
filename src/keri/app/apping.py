# -*- encoding: utf-8 -*-
"""
KERI
keri.app.apping module

"""

from hio.base import doing
from hio.core.serial import serialing
from hio.help import ogler

from ..db import Baser

logger = ogler.getLogger()


class Consoler(doing.Doer):
    """Manages a command-line serial console

    Reads lines from a serial console, parses simple movement commands,
    and echoes feedback. Inherits lifecycle management (enter/recur/exit)
    from :class:`hio.base.doing.Doer`.

    Attributes:
        db (Baser): Database instance used by this doer.
        console (serialing.Console): Serial console for input/output.
    """

    def __init__(self, db=None, console=None, **kwa):
        """Initializes Consoler with optional database and console.

        Args:
            db (Baser, optional): Database instance. Defaults to a new
                :class:`~keri.db.basing.Baser` instance if None.
            console (serialing.Console, optional): Serial console instance.
                Defaults to a new :class:`~hio.core.serial.serialing.Console`
                instance if None.
            **kwa: Additional keyword arguments passed to
                :class:`~hio.base.doing.Doer`.
        """
        super(Consoler, self).__init__(**kwa)
        self.db = db if db is not None else Baser()
        self.console = console if console is not None else serialing.Console()

    def enter(self, *, temp=None):
        """Opens the serial console resource.

        Called by the Doer framework when entering the task context.

        Args:
            temp (bool, optional): Unused. Reserved for interface compatibility.

        Raises:
            IOError: If the console cannot be opened.
        """
        if not self.console.reopen():
            raise IOError("Unable to open serial console.")

    def recur(self, tyme):
        """Reads one line from the console and dispatches a movement command.

        Recognized commands (matched on the first character, case-insensitive):

        - ``r`` / ``right``: turn right
        - ``l`` / ``left``: turn left
        - ``w`` / ``walk``: walk 1 step
        - ``s`` / ``stop``: stop

        Args:
            tyme (float): Current loop time provided by the Doist scheduler.

        Returns:
            bool: Always ``False``; signals the Doer to continue recurring.
        """
        line = self.console.get()
        if not line:
            return False
        chunks = line.lower().split()

        if not chunks:
            self.console.put("Try one of: l[eft] r[ight] w[alk] s[top]\n")
            return False
        verb = chunks[0]

        if verb.startswith(b'r'):
            command = ('turn', 'right')

        elif verb.startswith(b'l'):
            command = ('turn', 'left')

        elif verb.startswith(b'w'):
            command = ('walk', 1)

        elif verb.startswith(b's'):
            command = ('stop', '')

        else:
            self.console.put("Invalid command: {0}\n".format(verb))
            self.console.put("Try one of: t[urn] s[top] w[alk]\n")
            return False

        self.console.put("Did: {} {}\n".format(command[0], command[1]).encode("utf-8"))

        return False

    def exit(self):
        """Closes the serial console resource.

        Called by the Doer framework when leaving the task context.
        """
        self.console.close()
