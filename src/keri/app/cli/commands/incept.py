# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json
import sys
from dataclasses import dataclass
from json import JSONDecodeError

from hio import help
from hio.base import doing

from keri.app import habbing, keeping, directing, agenting, indirecting
from keri.core import coring
from keri.db import basing, dbing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="http")


@dataclass
class InceptOptions:
    salt: str
    transferable: bool
    witnesses: list
    icount: int
    isith: int
    ncount: int
    nsith: int


def handler(args):
    try:
        f = open(args.file)
        config = json.load(f)

        opts = InceptOptions(**config)
    except FileNotFoundError:
        print("config file", args.file, "not found")
        sys.exit(-1)
    except JSONDecodeError:
        print("config file", args.file, "not valid JSON")
        sys.exit(-1)

    name = args.name

    icpDoer = InceptDoer(name=name, proto=args.proto, opts=opts)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)



class InceptDoer(doing.DoDoer):

    def __init__(self, name, proto, opts, **kwa):

        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        salt = coring.Salter(raw=opts.salt.encode("utf-8")).qb64
        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, transferable=opts.transferable,
                              isith=opts.isith, icount=opts.icount, nsith=opts.nsith, ncount=opts.ncount,
                              wits=opts.witnesses, salt=salt)
        self.habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer
        doers = [doing.doify(self.inceptDo), self.ksDoer, self.dbDoer, self.habDoer]

        if proto == "tcp":
            self.mbx = None
            self.witDoer = agenting.WitnessReceiptor(hab=hab, klas=agenting.TCPWitnesser)
            doers.extend([self.witDoer])
        else:  # "http"
            self.mbx = indirecting.MailboxDirector(hab=hab)
            self.witDoer = agenting.WitnessReceiptor(hab=hab, klas=agenting.HTTPWitnesser)
            doers.extend([self.mbx, self.witDoer])

        self.hab = hab
        super(InceptDoer, self).__init__(doers=doers, **kwa)


    def inceptDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.witDoer.done:
            _ = yield self.tock


        print(f'Prefix  {self.hab.pre}')
        for idx, verfer in enumerate(self.hab.kever.verfers):
            print(f'\tPublic key {idx+1}:  {verfer.qb64}')
        print()

        toRemove = [self.ksDoer, self.dbDoer, self.habDoer, self.witDoer]
        if self.mbx:
            toRemove.append(self.mbx)

        self.remove(toRemove)

        return
