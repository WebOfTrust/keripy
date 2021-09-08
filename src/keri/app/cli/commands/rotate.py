# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from hio.base import doing

from keri import kering
from keri.app.cli.common import rotating
from keri.db import basing
from ... import habbing, keeping, agenting, indirecting, directing

parser = argparse.ArgumentParser(description='Rotate keys')
parser.set_defaults(handler=lambda args: rotate(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="tcp")
parser.add_argument('--erase', '-e', help='if this option is provided stale keys will be erased', default=False)
parser.add_argument('--next-count', '-C', help='Count of pre-rotated keys (signing keys after next rotation).', 
                    default=None, type=int, required=False)
rotating.addRotationArgs(parser)


def rotate(args):
    """
    Performs a rotation of the identifier of the environment represented by the provided name parameter

        args (parseargs):  Command line argument

    """
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


    rotDoer = RotateDoer(name=name, proto=args.proto, wits=args.witnesses, cuts=args.witness_cut, adds=args.witness_add,
                         sith=args.sith, count=args.next_count, toad=args.toad, erase=args.erase, data=data)

    doers = [rotDoer]

    try:
        directing.runController(doers=doers, expire=0.0)
    except kering.ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1



class RotateDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to perform a rotation and publication of the rotation event
    to all appropriate witnesses
    """

    def __init__(self, name, proto, sith=None, count=None, erase=None,
                 toad=None, wits=None, cuts=None, adds=None, data: list = None):
        """
        Returns DoDoer with all registered Doers needed to perform rotation.

        Parameters:
            name is human readable str of identifier
            proto is tcp or http method for communicating with Witness
            sith is next signing threshold as int or str hex or list of str weights
            count is int next number of signing keys
            erase is Boolean True means erase stale keys
            toad is int or str hex of witness threshold after cuts and adds
            cuts is list of qb64 pre of witnesses to be removed from witness list
            adds is list of qb64 pre of witnesses to be added to witness list
            data is list of dicts of committed data such as seals
       """

        self.name = name
        self.proto = proto
        self.sith = sith
        self.count = count
        self.erase = erase
        self.toad = toad
        self.data = data

        self.wits = wits if wits is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        ks = keeping.Keeper(name=self.name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=self.name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        self.hab = habbing.Habitat(name=self.name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=self.hab)  # setup doer
        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.rotateDo)]

        super(RotateDoer, self).__init__(doers=doers)


    def rotateDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.wits:
            if self.adds or self.cuts:
                raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
            ewits = self.hab.kever.lastEst.wits

            # wits= [a,b,c]  wits=[b, z]
            self.cuts = set(self.wits) & set(ewits)
            self.adds = set(self.wits) - set(ewits)


        msg = self.hab.rotate(sith=self.sith, count=self.count, erase=self.erase, toad=self.toad,
                              cuts=list(self.cuts), adds=list(self.adds), data=self.data)

        if self.proto == "tcp":
            mbx = None
            witDoer = agenting.WitnessReceiptor(hab=self.hab, klas=agenting.TCPWitnesser, msg=msg)
            self.extend(doers=[witDoer])
            yield self.tock
        else:  # "http"
            mbx = indirecting.MailboxDirector(hab=self.hab, topics="/receipt")
            witDoer = agenting.WitnessReceiptor(hab=self.hab, klas=agenting.HttpWitnesser, msg=msg)
            self.extend(doers=[mbx, witDoer])
            yield self.tock

        while not witDoer.done:
            _ = yield self.tock


        print(f'Prefix  {self.hab.pre}')
        print(f'New Sequence No.  {self.hab.kever.sn}')
        for idx, verfer in enumerate(self.hab.kever.verfers):
            print(f'\tPublic key {idx+1}:  {verfer.qb64}')

        toRemove = [self.ksDoer, self.dbDoer, self.habDoer, witDoer]
        if mbx:
            toRemove.append(mbx)

        self.remove(toRemove)

        return
