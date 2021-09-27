# -*- encoding: utf-8 -*-
"""
keri.kli.commands.multisig module

"""

import argparse

from hio import help
from hio.base import doing

from keri.app import directing, grouping, indirecting
from keri.app.cli.common import rotating, existing, displaying

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Begin or join a rotation of a group identifier')
parser.set_defaults(handler=lambda args: interactGroupIdentifier(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--group', '-g', help="Human readable environment reference for group identifier", required=True)
parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=None, action="store", required=False)


def interactGroupIdentifier(args):
    """
    Performs an interaction event on the group identifier specified as an argument.  The identifier prefix of the
    environment represented by the name parameter must be a member of the group identifier.  This command will
    perform an interaction of the local identifier if the sequence number of the local identifier is the same as the
    group identifier sequence number.  It will wait for all other members of the group to acheive the same sequence
    number (group + 1) and then publish the signed interaction event for the group identifier to all witnesses and
    wait for receipts.

    Parameters:
        args (parseargs):  command line parameters

    """

    kwa = args.__dict__
    ixnDoer = GroupMultisigInteract(**kwa)

    doers = [ixnDoer]
    directing.runController(doers=doers, expire=0.0)


class GroupMultisigInteract(doing.DoDoer):
    """
    Command line DoDoer to launch the needed coroutines to run launch Multisig interaction.
       This DoDoer will remove the multisig coroutine and exit when it recieves a message
       that the multisig coroutine has successfully completed a cooperative rotation.

    """

    def __init__(self, name, **kwa):
        self.hab, doers = existing.openHabitat(name=name)
        self.rotr = grouping.MultiSigGroupDoer(hab=self.hab)
        self.msg = kwa

        mbd = indirecting.MailboxDirector(hab=self.hab, topics=['/receipt', '/multisig'])
        doers.extend([self.rotr, mbd])
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.rotateDo)])

        super(GroupMultisigInteract, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0, **opts):
        # enter context
        yield self.tock

        msg = dict(op=grouping.Ops.ixn, reason="Standard Interaction")
        msg["group"] = self.msg["group"]
        msg["data"] = self.msg["data"]

        self.rotr.msgs.append(msg)

        while not self.rotr.cues:
            yield self.tock

        rep = self.rotr.cues.popleft()
        print(rep)
        print()
        print("Group Identifier Rotation Complete:")
        displaying.printIdentifier(self.hab, rep["pre"])

        self.remove(self.toRemove)
