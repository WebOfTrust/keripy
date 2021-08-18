# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.delegate module

"""
import argparse
import json
import sys
from json import JSONDecodeError

from hio import help
from hio.base import doing

from keri import kering
from keri.app import directing, keeping, habbing, agenting
from keri.app.cli.commands.delegate.create import DelegateOptions
from keri.core import eventing, coring, parsing
from keri.db import basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a seal for creating a delegated identifier')
parser.set_defaults(handler=lambda args: rotate(args))
parser.add_argument('--name', '-n', help='Human readable environment reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=None, action="store", required=False)


def rotate(args):
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

    if args.data is not None:
        try:
            if args.data.startswith("@"):
                f = open(args.data[1:], "r")
                data = json.load(f)
            else:
                data = json.loads(args.data)
        except json.JSONDecodeError:
            raise kering.ConfigurationError("data supplied must be value JSON to anchor in a seal")

        if not isinstance(data, list):
            data = [data]

    else:
        data = None

    kwa = opts.__dict__
    icpDoer = DelegateRotateDoer(name=name, data=data, **kwa)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class DelegateRotateDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a delegated identifier.
    """

    def __init__(self, name, data, **kwa):
        """
        Creates the DoDoer needed to create the seal for a delegated identifier.

        Parameters
            name (str): Name of the local identifier environment

        """

        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=hab)

        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.rotateDo, **kwa)]
        self.hab = hab

        super(DelegateRotateDoer, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0, **kwa):
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        return
