# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import os
import sys

from hio import help
from hio.base import doing

from keri.app.cli.serving import Serving

logger = help.ogler.getLogger()


def main():
    # do the UNIX double-fork magic, see Stevens' "Advanced
    # Programming in the UNIX Environment" for details (ISBN 0201563177)
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError as e:
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent, print eventual PID before
            print("Daemon PID", pid)
            sys.exit(0)
    except OSError as e:
        sys.exit(1)

    print("starting serving...")

    doist = doing.Doist(tock=0.03125, real=True)
    serving = Serving(tymth=doist.tymen())
    doist.do(doers=[serving])


if __name__ == "__main__":
    main()
