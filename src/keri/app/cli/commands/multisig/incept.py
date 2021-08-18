# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.multisig module

"""

import argparse
import json
import sys
from dataclasses import dataclass
from json import JSONDecodeError

from hio import help
from hio.base import doing
from keri.app import habbing, keeping, directing, agenting, indirecting
from keri.app.cli.common import grouping, displaying
from keri.core import coring, eventing
from keri.db import basing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a group identifier prefix')
parser.set_defaults(handler=lambda args: inceptMultisig(args))
parser.add_argument('--name', '-n', help='Human readable environment reference', required=True)
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="", required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="http")


@dataclass
class MultiSigInceptOptions:
    """
    Options dataclass loaded fromt he file parameter to this command line function.
    Represents all the options needed to incept a multisig group identifier

    """
    aids: list
    transferable: bool
    witnesses: list
    toad: int
    icount: int
    isith: int
    ncount: int
    nsith: int
    sigs: list


def inceptMultisig(args):
    """
    Reads the config file into a MultiSigInceptOptions dataclass and creates and signs the inception
    event for the group identifier.  If signatures are provided in the options file, the event is submitted
    to its witnesses and receipts are collected.

    Parameters:
        args: Parsed arguments from the command line

    """
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

    kwa = opts.__dict__
    icpDoer = MultiSigInceptDoer(name=name, proto=args.proto, **kwa)

    doers = [icpDoer]
    directing.runController(doers=doers, expire=0.0)


class MultiSigInceptDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a multisig group identifier.  The identifier of the environment loaded from `name`
    must be a member of the group of identifiers listed in the configuration file.

    """

    def __init__(self, name, **kwa):
        """
        Creates the DoDoer needed to incept a multisig group identifier.  Requires the
        name of the environment whose identifier is a member of the group being created.
        All other arguments are passed to the inceptDo generator method as parameters to create
        the inception event.

        Parameters
            name (str): Name of the local identifier environment

        """

        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=hab)

        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.TCPWitnesser)

        doers = [self.ksDoer, self.dbDoer, self.habDoer, self.witq, doing.doify(self.inceptDo, **kwa)]
        self.hab = hab
        super(MultiSigInceptDoer, self).__init__(doers=doers)


    def inceptDo(self, tymth, tock=0.0, **kwa):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        aids = list(kwa['aids'])
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

            diger = grouping.extractDig(nexter=kever.nexter, tholder=kever.tholder)

            mskeys.append(keys[0])
            msdigers.append(diger)

        wits = kwa["witnesses"] if kwa["witnesses"] is not None else self.hab.kever.wits

        mssrdr = eventing.incept(keys=[mskey.qb64 for mskey in mskeys],
                                 sith=kwa["isith"],
                                 toad=kwa["toad"],
                                 wits=wits,
                                 nxt=coring.Nexter(sith=kwa["nsith"],
                                                   digs=[diger.qb64 for diger in msdigers]).qb64,
                                 code=coring.MtrDex.Blake3_256)

        sigers = []
        sigers.extend([coring.Siger(qb64=sig) for sig in kwa["sigs"]])

        mine = self.hab.mgr.sign(ser=mssrdr.raw, verfers=self.hab.kever.verfers, indices=[idx])
        sigers.extend(mine)

        msg = eventing.messagize(mssrdr, sigers=sigers)
        self.hab.prefixes.add(mssrdr.pre)  # make this prefix one of my own
        self.hab.psr.parseOne(ims=bytearray(msg))  # make copy as kvr deletes

        toRemove = [self.ksDoer, self.dbDoer, self.habDoer, self.witq]
        if kwa["sigs"]:

            mbx = indirecting.MailboxDirector(hab=self.hab)
            witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg, klas=agenting.TCPWitnesser)
            self.extend([mbx, witRctDoer])
            toRemove.extend([mbx, witRctDoer])

            while not witRctDoer.done:
                _ = yield self.tock

            displaying.printIdentifier(self.hab, mssrdr.pre)

        else:
            print(mssrdr.pretty())
            for siger in sigers:
                print(siger.qb64)

        #  Add this group identifier prefix to my list of group identifiers I participate in
        bid = basing.GroupIdentifier(lid=self.hab.pre, aids=aids)
        self.hab.db.gids.put(mssrdr.pre, bid)

        self.remove(toRemove)

        return
