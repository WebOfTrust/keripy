# -*- encoding: utf-8 -*-
"""
keri.kli.commands.multisig module

"""

import argparse
import json
import sys
from dataclasses import dataclass
from json import JSONDecodeError

import blake3
from hio import help
from hio.base import doing

from keri.app import habbing, keeping, directing, agenting, indirecting
from keri.core import coring, eventing
from keri.db import basing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="http")


@dataclass
class MultiSigInceptOptions:
    aids: list
    transferable: bool
    witnesses: list
    toad: int
    icount: int
    isith: int
    ncount: int
    nsith: int
    sigs: list


def handler(args):
    try:
        f = open(args.file)
        config = json.load(f)

        opts = MultiSigInceptOptions(**config)

    except FileNotFoundError:
        print("config file", args.file, "not found")
        sys.exit(-1)
    except JSONDecodeError:
        print("config file", args.file, "not valid JSON")
        sys.exit(-1)

    name = args.name

    icpDoer = MultiSigInceptDoer(name=name, proto=args.proto, opts=opts)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class MultiSigInceptDoer(doing.DoDoer):

    def __init__(self, name, opts, **kwa):

        self.iopts = opts
        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=hab)

        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.TCPWitnesser)

        # doers = [self.ksDoer, self.dbDoer, self.habDoer, self.witq, self.inceptDo]
        doers = [self.ksDoer, self.dbDoer, self.habDoer, self.witq, doing.doify(self.inceptDo)]
        self.hab = hab
        super(MultiSigInceptDoer, self).__init__(doers=doers, **kwa)


    def inceptDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        aids = list(self.iopts.aids)
        if self.hab.pre not in aids:
            raise ConfigurationError("Local identifer {} must be member of aids ={}".format(self.hab.pre, aids))

        idx = aids.index(self.hab.pre)

        mskeys = []
        msdigers = []
        for aid in aids:
            if aid not in self.hab.kevers:
                self.witq.query(aid)
                while aid not in self.hab.kevers:
                    _ = (yield self.tock)

            kever = self.hab.kevers[aid]
            keys = kever.verfers
            if len(keys) > 1:
                raise ConfigurationError("Identifier must have only one key, {} has {}".format(aid, len(keys)))

            diger = self._extract(nexter=kever.nexter, tholder=kever.tholder)

            mskeys.append(keys[0])
            msdigers.append(diger)

        wits = self.iopts.witnesses if self.iopts.witnesses is not None else self.hab.kever.wits

        mssrdr = eventing.incept(keys=[mskey.qb64 for mskey in mskeys],
                                 sith=self.iopts.isith,
                                 toad=self.iopts.toad,
                                 wits=wits,
                                 nxt=coring.Nexter(sith=self.iopts.nsith,
                                                   digs=[diger.qb64 for diger in msdigers]).qb64,
                                 code=coring.MtrDex.Blake3_256)

        sigers = []
        sigers.extend([coring.Siger(qb64=sig) for sig in self.iopts.sigs])

        mine = self.hab.mgr.sign(ser=mssrdr.raw, verfers=self.hab.kever.verfers, indices=[idx])
        sigers.extend(mine)

        msg = eventing.messagize(mssrdr, sigers=sigers)
        self.hab.prefixes.add(mssrdr.pre)  # make this prefix one of my own
        self.hab.psr.parseOne(ims=bytearray(msg))  # make copy as kvr deletes

        if self.iopts.sigs:

            mbx = indirecting.MailboxDirector(hab=self.hab)
            witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg, klas=agenting.TCPWitnesser)
            self.extend([mbx, witRctDoer])

            while not witRctDoer.done:
                _ = yield self.tock

            toRemove = [self.ksDoer, self.dbDoer, self.habDoer, self.witq, witRctDoer, mbx]
            self.remove(toRemove)

            print(f'Prefix  {mssrdr.pre}')
            for idx, verfer in enumerate(mskeys):
                print(f'\tPublic key {idx+1}:  {verfer.qb64}')
            print()

        else:

            print(mssrdr.pretty())
            for siger in sigers:
                print(siger.qb64)

            toRemove = [self.ksDoer, self.dbDoer, self.habDoer, self.witq]
            self.remove(toRemove)

        return


    @staticmethod
    def _extract(nexter, tholder):
        dint = int.from_bytes(nexter.raw, 'big')

        limen = tholder.limen
        ldig = blake3.blake3(limen.encode("utf-8")).digest()
        sint = int.from_bytes(ldig, 'big')
        kint = sint ^ dint

        diger = coring.Diger(raw=kint.to_bytes(coring.Matter._rawSize(coring.MtrDex.Blake3_256), 'big'))
        return diger
