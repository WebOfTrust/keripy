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

from keri import help
from hio.base import doing

from keri import kering
from keri.app import directing, keeping, habbing, agenting
from keri.core import eventing, coring
from keri.db import basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a seal for creating a delegated identifier')
parser.set_defaults(handler=lambda args: incept(args))
parser.add_argument('--name', '-n', help='Human readable environment reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--seal', '-s', help='Filename to write seal', default="", required=True)


@dataclass
class DelegateOptions:
    """
    Options dataclass loaded from the file parameter to this command line function.
    Represents all the options needed to create a delegated identifier

    """
    delegatorPrefix: str
    delegatorWits: list
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
        self.ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=self.ks)  # doer do reopens if not opened and closes
        self.db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=self.db)  # doer do reopens if not opened and closes
        self.kvy = eventing.Kevery(db=self.db, lax=True, local=True)

        # hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        # self.habDoer = habbing.HabitatDoer(habitat=hab)

        doers = [self.ksDoer, self.dbDoer, doing.doify(self.inceptDo, **kwa)]
        # self.hab = hab
        self.sealFile = sealFile

        super(DelegateInceptDoer, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0, **kwa):
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context


        salt = coring.Salter(raw=kwa["salt"].encode("utf-8")).qb64
        seed = kwa["seed"] if "seed" in kwa else None
        wits = kwa["wits"] if "wits" in kwa else None
        toad = kwa["toad"] if "toad" in kwa else None
        icount = kwa["icount"] if "icount" in kwa else None
        isith = kwa["isith"] if "isith" in kwa else None
        ncount = kwa["ncount"] if "ncount" in kwa else None
        nsith = kwa["nsith"] if "nsith" in kwa else None

        mgr = keeping.Manager(ks=self.ks, seed=seed, salt=salt, tier=None)

        verfers, digers, cst, nst = mgr.incept(salt=salt, icount=icount, isith=isith, ncount=ncount, nsith=nsith)

        # build and consume delcept
        delegatorWitness = kwa["delegatorWits"]
        delegatorPrefix = kwa["delegatorPrefix"]
        icpSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   delpre=delegatorPrefix, wits=wits, toad=toad,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)
        pre = icpSrdr.pre
        mgr.move(old=verfers[0].qb64, new=pre)

        hr = basing.HabitatRecord(prefix=pre, watchers=[])
        self.db.habs.put(keys=self.name, val=hr)

        sigers = mgr.sign(ser=icpSrdr.raw, verfers=verfers)

        self.db.prefixes.add(pre)
        self.kvy.processEvent(serder=icpSrdr, sigers=sigers)

        if pre not in self.kvy.kevers:
            raise kering.ConfigurationError("Improper Delegated inception for "
                                            "pre={}.".format(pre))

        hab = habbing.Habitat(name=self.name, ks=self.ks, db=self.db, temp=False, create=False)
        hab.prefixes.add(pre)

        seal = dict(i=icpSrdr.pre,
                    s=icpSrdr.ked["s"],
                    d=icpSrdr.dig)

        with open(self.sealFile, "w") as f:
            f.write(json.dumps(seal, indent=4))

        witq = agenting.WitnessInquisitor(hab=hab, wits=delegatorWitness, klas=agenting.TCPWitnesser)
        self.extend([witq])

        print("Hello, could someone approve my delegated identifier inception, please?")
        while True:
            if delegatorPrefix in hab.kevers:
                kever = hab.kevers[delegatorPrefix]
                if "a" in kever.serder.ked:
                    seals = kever.serder.ked["a"]
                    if seal in seals:
                        break
            witq.query(delegatorPrefix)
            yield self.tock


        msg = bytearray(icpSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                 count=1)
        msg.extend(counter.qb64b)

        event = hab.kevers[delegatorPrefix]
        seqner = coring.Seqner(sn=event.sn)
        msg.extend(seqner.qb64b)
        msg.extend(event.serder.diger.qb64b)

        hab.psr.parseOne(ims=bytearray(msg))
        while icpSrdr.pre not in hab.kevers:
            yield self.tock

        witDoer = agenting.WitnessReceiptor(hab=hab, klas=agenting.TCPWitnesser, msg=msg)
        self.extend([witDoer])

        while not witDoer.done:
            yield self.tock

        print("Successfully created delegate identifier", icpSrdr.pre)
        print("Public key", icpSrdr.verfers[0].qb64)

        self.remove([self.ksDoer, self.dbDoer, witq, witDoer])

        return
