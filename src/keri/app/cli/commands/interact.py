# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from hio.base import doing
from keri import kering
from keri.db import basing

from ... import habbing, keeping, agenting, indirecting, directing

parser = argparse.ArgumentParser(description='Rotate keys')
parser.set_defaults(handler=lambda args: interact(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="tcp")
parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=[], action="store", required=False)


def interact(args):
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

    ixnDoer = InteractDoer(name=name, proto=args.proto, data=data)

    doers = [ixnDoer]

    try:
        directing.runController(doers=doers, expire=0.0)
    except kering.ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1



class InteractDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to create an interaction event and publication of the event
    to all appropriate witnesses
    """

    def __init__(self, name, proto, data: list = None):
        """
        Returns DoDoer with all registered Doers needed to perform interaction event.

        Parameters:
            name is human readable str of identifier
            proto is tcp or http method for communicating with Witness
            data is list of dicts of committed data such as seals
       """

        self.name = name
        self.proto = proto
        self.data = data

        ks = keeping.Keeper(name=self.name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=self.name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        self.hab = habbing.Habitat(name=self.name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=self.hab)  # setup doer
        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.interactDo)]

        super(InteractDoer, self).__init__(doers=doers)


    def interactDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)


        msg = self.hab.interact(data=self.data)

        if self.proto == "tcp":
            mbx = None
            witDoer = agenting.WitnessReceiptor(hab=self.hab, klas=agenting.TCPWitnesser, msg=msg)
            self.extend(doers=[witDoer])
            yield self.tock
        else:  # "http"
            mbx = indirecting.MailboxDirector(hab=self.hab)
            witDoer = agenting.WitnessReceiptor(hab=self.hab, klas=agenting.HTTPWitnesser, msg=msg)
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
