# -*- encoding: utf-8 -*-
"""
keri.kli.commands.multisig module

"""

import argparse

from hio import help
from hio.base import doing

from keri import kering
from keri.app import grouping, indirecting, habbing
from keri.app.cli.common import rotating, existing, displaying
from keri.core import coring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Begin or join a rotation of a group identifier')
parser.set_defaults(handler=lambda args: rotateGroupIdentifier(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the local identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--aids", "-g", help="List of other participant qb64 identifiers to include in interaction event",
                    action="append", required=False, default=None)

rotating.addRotationArgs(parser)


def rotateGroupIdentifier(args):
    """
    Performs a rotation on the group identifier specified as an argument.  The identifier prefix of the environment
    represented by the name parameter must be a member of the group identifier.  This command will perform a rotation
    of the local identifier if the sequence number of the local identifier is the same as the group identifier sequence
    number.  It will wait for all other members of the group to acheive the same sequence number (group + 1) and then
    publish the signed rotation event for the group identifier to all witnesses and wait for receipts.

    Parameters:
        args (parseargs):  command line parameters

    """

    data = rotating.loadData(args)

    rotDoer = GroupMultisigRotate(name=args.name, base=args.base, alias=args.alias, aids=args.aids, bran=args.bran,
                                  wits=args.witnesses, cuts=args.cuts, adds=args.witness_add, sith=args.sith,
                                  nsith=args.nsith, toad=args.toad, data=data)

    doers = [rotDoer]
    return doers


class GroupMultisigRotate(doing.DoDoer):
    """
    Command line DoDoer to launch the needed coroutines to run launch Multisig rotation.
       This DoDoer will remove the multisig coroutine and exit when it recieves a message
       that the multisig coroutine has successfully completed a cooperative rotation.

    """

    def __init__(self, name, base, bran, alias, aids=None, sith=None, nsith=None, toad=None, wits=None, cuts=None,
                 adds=None, data: list = None):

        self.alias = alias
        self.sith = sith
        self.nsith = nsith
        self.toad = toad
        self.aids = aids
        self.data = data

        self.wits = wits if wits is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer

        mbd = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', '/multisig'])
        self.counselor = grouping.Counselor(hby=self.hby)

        doers = [mbd, self.hbyDoer, self.counselor]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.rotateDo)])

        super(GroupMultisigRotate, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0, **opts):
        """ Create or participate in an rotation event for a distributed multisig identifier

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        ghab = self.hby.habByName(name=self.alias)
        if ghab is None:
            raise kering.ConfigurationError(f"Alias {self.alias} is invalid")

        if self.wits:
            if self.adds or self.cuts:
                raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
            ewits = ghab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            self.cuts = set(ewits) - set(self.wits)
            self.adds = set(self.wits) - set(ewits)

        seqner = coring.Seqner(sn=ghab.kever.sn+1)
        self.counselor.rotate(ghab=ghab, aids=self.aids, sith=self.sith, toad=self.toad,
                              cuts=list(self.cuts), adds=list(self.adds),
                              data=self.data)
        while True:
            saider = self.hby.db.cgms.get(keys=(ghab.pre, seqner.qb64))
            if saider is not None:
                break

            yield self.tock

        print()
        displaying.printIdentifier(self.hby, ghab.pre)
        self.remove(self.toRemove)
