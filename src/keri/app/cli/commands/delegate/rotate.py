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
from keri.app.cli.commands.delegate.incept import DelegateOptions
from keri.core import eventing, coring, parsing
from keri.db import basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a seal for creating a delegated identifier')
parser.set_defaults(handler=lambda args: rotate(args))
parser.add_argument('--name', '-n', help='Human readable environment reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--seal', '-s', help='Filename to write seal', default="", required=True)
parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=None, action="store", required=True)


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
    sealFile = args.seal

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
    icpDoer = DelegateRotateDoer(name=name, sealFile=sealFile, data=data, **kwa)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class DelegateRotateDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a delegated identifier.
    """

    def __init__(self, name, sealFile, data, **kwa):
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
        self.data = data
        self.sealFile = sealFile
        self.delegatorPrefix = kwa["delegatorPrefix"]

        super(DelegateRotateDoer, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0, **kwa):
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        delPre = self.data[0]["i"]
        delK = self.hab.kevers[delPre]

        verfers, digers, cst, nst = self.hab.mgr.rotate(pre=delK.prefixer.qb64, temp=False)
        rotSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delK.serder.diger.qb64,
                                   sn=delK.sn + 1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        print(rotSrdr.pretty())

        seal = dict(i=rotSrdr.pre,
                    s=rotSrdr.ked["s"],
                    d=rotSrdr.dig)

        with open(self.sealFile, "w") as f:
            f.write(json.dumps(seal, indent=4))

        witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.TCPWitnesser)
        self.extend([witq])

        print("Hello, could someone approve my delegated rotation, please?")

        while self.delegatorPrefix not in self.hab.kevers or self.hab.kevers[self.delegatorPrefix].sn < 2:
            witq.query(self.delegatorPrefix)
            yield self.tock

        sigers = self.hab.mgr.sign(ser=rotSrdr.raw, verfers=verfers)
        msg = bytearray(rotSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                 count=1)
        msg.extend(counter.qb64b)

        event = self.hab.kevers[rotSrdr.pre]
        seqner = coring.Seqner(sn=event.sn)
        msg.extend(seqner.qb64b)
        msg.extend(event.serder.diger.qb64b)

        delKvy = eventing.Kevery(db=self.hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(msg), kvy=delKvy)

        while rotSrdr.pre not in delKvy.kevers:
            yield self.tock

        print("Successfully rotated delegate identifier keys", rotSrdr.pre)
        print("Public key", rotSrdr.verfers[0].qb64)

        self.remove([self.ksDoer, self.dbDoer, self.habDoer, witq])

        return
