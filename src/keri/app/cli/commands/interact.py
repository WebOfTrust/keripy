# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json
from ordered_set import OrderedSet as oset

from hio.base import doing

from keri import kering
from ..common import existing
from ... import habbing, agenting, indirecting

parser = argparse.ArgumentParser(description='Create and publish an interaction event')
parser.set_defaults(handler=lambda args: interact(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=None, action="store", required=False)


def interact(args):
    """
    Performs a rotation of the identifier of the environment represented by the provided name parameter

        args (parseargs):  Command line argument

    """
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran

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

    ixnDoer = InteractDoer(name=name, base=base, alias=alias, bran=bran, data=data)

    return [ixnDoer]


class InteractDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to create an interaction event and publication of the event
    to all appropriate witnesses
    """

    def __init__(self, name, base, bran, alias, data: list = None):
        """
        Returns DoDoer with all registered Doers needed to perform interaction event.

        Parameters:
            name is human readable str of identifier
            proto is tcp or http method for communicating with Witness
            data is list of dicts of committed data such as seals
       """

        self.alias = alias
        self.data = data

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', "/replay", "/reply"])
        doers = [self.hbyDoer, self.mbx, doing.doify(self.interactDo)]

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

        hab = self.hby.habByName(name=self.alias)
        hab.interact(data=self.data)

        witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.extend(doers=[witDoer])

        if hab.kever.wits:
            witDoer.msgs.append(dict(pre=hab.pre))
            while not witDoer.cues:
                _ = yield self.tock

        print(f'Prefix  {hab.pre}')
        print(f'New Sequence No.  {hab.kever.sn}')
        for idx, verfer in enumerate(hab.kever.verfers):
            print(f'\tPublic key {idx+1}:  {verfer.qb64}')

        toRemove = [self.hbyDoer, witDoer, self.mbx]
        self.remove(toRemove)

        return
