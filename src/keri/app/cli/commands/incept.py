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

from keri.app import habbing, keeping, directing, agenting
from keri.core import coring
from keri.db import basing, dbing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)


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

    icpDoer = InceptDoer(name=name, opts=opts)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)



class InceptDoer(doing.DoDoer):

    def __init__(self, name, opts, **kwa):

        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, transferable=opts.transferable,
                              isith=opts.isith, icount=opts.icount, nsith=opts.nsith, ncount=opts.ncount,
                              wits=opts.witnesses)
        self.habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer
        self.witDoer = agenting.WitnessReceiptor(hab=hab)

        doers = [self.inceptDo, self.ksDoer, self.dbDoer, self.habDoer, self.witDoer]
        self.hab = hab
        super(InceptDoer, self).__init__(doers=doers, **kwa)


    @doing.doize()
    def inceptDo(self, tymth, tock=0.0, **opts):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        ser = self.hab.kever.serder
        wits = self.hab.kever.wits

        while True:
            dgkey = dbing.dgKey(ser.preb, ser.digb)

            rcts = self.hab.db.getWigs(dgkey)
            if len(rcts) == len(wits):
                break
            _ = yield self.tock

        print(f'Prefix\t\t{self.hab.pre}')
        for idx, verfer in enumerate(self.hab.kever.verfers):
            print(f'Public key {idx+1}:\t{verfer.qb64}')
        print()

        toRemove = [self.ksDoer, self.dbDoer, self.habDoer, self.witDoer]
        self.remove(toRemove)

        return
