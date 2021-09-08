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
parser.set_defaults(handler=lambda args: rotateGroupIdentifier(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--group', '-g', help="Human readable environment reference for group identifier", required=True)

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

    kwa = args.__dict__
    rotDoer = GroupMultisigRotate(**kwa)

    doers = [rotDoer]
    directing.runController(doers=doers, expire=0.0)



class GroupMultisigRotate(doing.DoDoer):
    """
    Command line DoDoer to launch the needed coroutines to run launch Multisig rotation.
       This DoDoer will remove the multisig coroutine and exit when it recieves a message
       that the multisig coroutine has successfully completed a cooperative rotation.

    """

    def __init__(self, name, **kwa):
        self.hab, doers = existing.openHabitat(name=name)
        self.rotr = grouping.MultiSigRotateDoer(hab=self.hab)
        self.msg = kwa

        mbd = indirecting.MailboxDirector(hab=self.hab, topics=['/receipt', '/multisig'])
        doers.extend([self.rotr, mbd])
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.rotateDo)])

        super(GroupMultisigRotate, self).__init__(doers=doers)


    def rotateDo(self, tymth, tock=0.0, **opts):
        # enter context
        yield self.tock

        self.rotr.msgs.append(self.msg)

        while not self.rotr.cues:
            yield self.tock

        rep = self.rotr.cues.popleft()

        print()
        print("Group Identifier Rotation Complete:")
        displaying.printIdentifier(self.hab, rep["pre"])


        self.remove(self.toRemove)
