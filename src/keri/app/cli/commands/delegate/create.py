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

from hio import help
from hio.base import doing

from keri.app import directing, keeping, habbing
from keri.core import eventing, coring
from keri.db import basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a seal for creating a delegated identifier')
parser.set_defaults(handler=lambda args: create(args))
parser.add_argument('--name', '-n', help='Human readable environment reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)


@dataclass
class DelegateCreateOptions:
    """
    Options dataclass loaded from the file parameter to this command line function.
    Represents all the options needed to create a delegated identifier

    """
    delegateeSalt: str
    delegateeName: str
    delegatorPrefix: str


def create(args):
    """
    Reads the config file into a CreateDelegateOptions dataclass and creates
    delegated identifier prefixes and events

    Parameters:
        args: Parsed arguments from the command line

    """
    try:
        f = open(args.file)
        config = json.load(f)
        opts = DelegateCreateOptions(**config)

    except FileNotFoundError:
        print("config file", args.file, "not found")
        sys.exit(-1)
    except JSONDecodeError:
        print("config file", args.file, "not valid JSON")
        sys.exit(-1)

    name = args.name

    kwa = opts.__dict__
    icpDoer = DelegateCreateDoer(name=name, **kwa)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class DelegateCreateDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a delegated identifier.
    """

    def __init__(self, name, **kwa):
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

        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.createDo, **kwa)]
        self.hab = hab
        self.delegateeSalt = kwa["delegateeSalt"]
        self.delegateeName = kwa["delegateeName"]
        self.delegatorPrefix = kwa["delegatorPrefix"]

        super(DelegateCreateDoer, self).__init__(doers=doers)

    def createDo(self, tymth, tock=0.0, **kwa):
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        with keeping.openKS(name=self.delegateeName) as delKS:
            delSalt = coring.Salter(raw=self.delegateeSalt.encode('utf-8')).qb64
            delMgr = keeping.Manager(ks=delKS, salt=delSalt)

            verfers, digers, cst, nst = delMgr.incept(stem=self.delegateeName, temp=True)

            delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                       delpre=self.delegatorPrefix,
                                       nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

            seal = eventing.SealEvent(i=self.hab.pre,
                                      s=delSrdr.ked["s"],
                                      d=delSrdr.dig)

            print(seal)

            self.remove([self.ksDoer, self.dbDoer, self.habDoer])

        return
