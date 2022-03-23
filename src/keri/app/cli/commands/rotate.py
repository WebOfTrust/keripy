# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing

from keri import kering
from keri.app.cli.common import rotating, existing
from ... import habbing, agenting, indirecting, directing, delegating

parser = argparse.ArgumentParser(description='Rotate keys')
parser.set_defaults(handler=lambda args: rotate(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--next-count', '-C', help='Count of pre-rotated keys (signing keys after next rotation).',
                    default=None, type=int, required=False)
rotating.addRotationArgs(parser)


def rotate(args):
    """
    Performs a rotation of the identifier of the environment represented by the provided name parameter

        args (parseargs):  Command line argument

    """
    data = rotating.loadData(args)
    rotDoer = RotateDoer(name=args.name, base=args.base, alias=args.alias, bran=args.bran, wits=args.witnesses,
                         cuts=args.cuts, adds=args.witness_add, sith=args.sith, count=args.next_count, toad=args.toad,
                         data=data)

    doers = [rotDoer]

    return doers


class RotateDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to perform a rotation and publication of the rotation event
    to all appropriate witnesses
    """

    def __init__(self, name, base, bran, alias, sith=None, count=None,
                 toad=None, wits=None, cuts=None, adds=None, data: list = None):
        """
        Returns DoDoer with all registered Doers needed to perform rotation.

        Parameters:
            name is human readable str of identifier
            sith is next signing threshold as int or str hex or list of str weights
            count is int next number of signing keys
            toad is int or str hex of witness threshold after cuts and adds
            cuts is list of qb64 pre of witnesses to be removed from witness list
            adds is list of qb64 pre of witnesses to be added to witness list
            data is list of dicts of committed data such as seals
       """

        self.alias = alias
        self.sith = sith
        self.count = count
        self.toad = toad
        self.data = data

        self.wits = wits if wits is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.swain = delegating.Boatswain(hby=self.hby)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt"])
        doers = [self.hbyDoer, self.mbx, self.swain, doing.doify(self.rotateDo)]

        super(RotateDoer, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            raise kering.ConfigurationError(f"Alias {self.alias} is invalid")

        if self.wits:
            if self.adds or self.cuts:
                raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
            ewits = hab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            self.cuts = set(ewits) - set(self.wits)
            self.adds = set(self.wits) - set(ewits)

        hab.rotate(sith=self.sith, count=self.count, toad=self.toad,
                   cuts=list(self.cuts), adds=list(self.adds),
                   data=self.data)

        if hab.kever.delegator:
            self.swain.msgs.append(dict(alias=self.alias, pre=hab.pre, sn=hab.kever.sn))
            print("Waiting for delegation approval...")
            while not self.swain.cues:
                yield self.tock

        witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.extend(doers=[witDoer])
        yield self.tock

        if hab.kever.wits:
            witDoer.msgs.append(dict(pre=hab.pre))
            while not witDoer.cues:
                _ = yield self.tock

        print(f'Prefix  {hab.pre}')
        print(f'New Sequence No.  {hab.kever.sn}')
        for idx, verfer in enumerate(hab.kever.verfers):
            print(f'\tPublic key {idx + 1}:  {verfer.qb64}')

        toRemove = [self.hbyDoer, witDoer, self.swain, self.mbx]
        self.remove(toRemove)

        return
