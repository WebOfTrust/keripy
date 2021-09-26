# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse
import json
import sys
from dataclasses import dataclass
from json import JSONDecodeError

from hio.base import doing

from keri import help
from keri.app import directing, delegating

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a seal for creating a delegated identifier')
parser.set_defaults(handler=lambda args: incept(args))
parser.add_argument('--name', '-n', help='Human readable environment reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--seal', '-s', help='Filename to write seal', default="", required=False)


@dataclass
class DelegateOptions:
    """
    Options dataclass loaded from the file parameter to this command line function.
    Represents all the options needed to create a delegated identifier

    """
    delpre: str
    salt: str
    transferable: bool
    wits: list
    icount: int
    isith: str
    ncount: int
    nsith: str


def incept(args):
    """
    Reads the config file into a CreateDelegateOptions dataclass and creates
    delegated identifier prefixes and events

    Parameters:
        args: Parsed arguments from the command line

    """
    try:
        f = open(args.file)
        config = json.load(f)
        opts = DelegateOptions(**config)

    except FileNotFoundError:
        print("config file", args.file, "not found")
        sys.exit(-1)
    except JSONDecodeError:
        print("config file", args.file, "not valid JSON")
        sys.exit(-1)

    name = args.name
    sealFile = args.seal

    kwa = opts.__dict__
    icpDoer = DelegateInceptDoer(name=name, sealFile=sealFile, **kwa)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class DelegateInceptDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a delegated identifier.
    """

    def __init__(self, name, sealFile, **kwa):
        """
        Creates the DoDoer needed to create the seal for a delegated identifier.

        Parameters
            name (str): Name of the local identifier environment

        """

        self.name = name
        self.msg = kwa

        self.dcptr = delegating.InceptDoer(name=name)
        doers = [doing.doify(self.inceptDo), self.dcptr]
        self.toRemove = list(doers)
        super(DelegateInceptDoer, self).__init__(doers=doers, **kwa)

    def inceptDo(self, tymth, tock=0.0, **kwa):
        yield self.tock
        self.dcptr.msgs.append(self.msg)

        while not self.dcptr.cues:
            yield self.tock

        rep = self.dcptr.cues.popleft()
        print(f'Successfully delegated:')
        print(f'\tPrefix: {rep["pre"]}')
        print(f'\tDelegator: {rep["delegator"]}')

        self.remove(self.toRemove)

        return
