# -*- encoding: utf-8 -*-
"""
keri.kli.commands.multisig module

"""

import argparse
from ordered_set import OrderedSet as oset

from hio import help
from hio.base import doing

from keri import kering
from keri.app import grouping, indirecting, habbing, forwarding
from keri.app.cli.common import existing, displaying, config
from keri.app.notifying import Notifier
from keri.core import coring, serdering
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Begin or join a rotation of a group identifier')
parser.set_defaults(handler=lambda args: interactGroupIdentifier(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the local identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=[], action="store", required=True)
parser.add_argument("--aids", "-g", help="List of other participant qb64 identifiers to include in interaction event",
                    action="append", required=False, default=None)


def interactGroupIdentifier(args):
    """
    Performs an interaction event on the group identifier specified as an argument.  The identifier prefix of the
    environment represented by the name parameter must be a member of the group identifier.  This command will
    perform an interaction of the local identifier if the sequence number of the local identifier is the same as the
    group identifier sequence number.  It will wait for all other members of the group to achieve the same sequence
    number (group + 1) and then publish the signed interaction event for the group identifier to all witnesses and
    wait for receipts.

    Parameters:
        args (parseargs):  command line parameters

    """

    data = config.parseData(args.data) if args.data is not None else None
    ixnDoer = GroupMultisigInteract(name=args.name, alias=args.alias, aids=args.aids, base=args.base, bran=args.bran,
                                    data=data)

    doers = [ixnDoer]
    return doers


class GroupMultisigInteract(doing.DoDoer):
    """
    Command line DoDoer to launch the needed coroutines to run launch Multisig interaction.
       This DoDoer will remove the multisig coroutine and exit when it receives a message
       that the multisig coroutine has successfully completed a cooperative rotation.

       ToDo: NRR
       Add .rmids and .smids

    """

    def __init__(self, name, alias, aids, base, bran, data):
        self.base = base
        self.bran = bran
        self.alias = alias
        self.aids = aids
        self.data = data

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.postman = forwarding.Poster(hby=self.hby)

        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(exc, mux)

        mbd = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', '/multisig'], exc=exc)
        self.counselor = grouping.Counselor(hby=self.hby)

        doers = [self.hbyDoer, self.postman, mbd, self.counselor]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.interactDo)])

        super(GroupMultisigInteract, self).__init__(doers=doers)

    def interactDo(self, tymth, tock=0.0):
        """ Create or participate in an interaction event for a distributed multisig identifier

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
            raise kering.ConfigurationError(f"invalid alias {self.alias} specified for database {self.hby.name}")

        aids = self.aids if self.aids is not None else ghab.smids

        ixn = ghab.interact(data=self.data)
        serder = serdering.SerderKERI(raw=ixn)

        exn, ims = grouping.multisigInteractExn(ghab=ghab, aids=aids, ixn=ixn)
        others = list(oset(ghab.smids + (ghab.rmids or [])))
        others.remove(ghab.mhab.pre)

        for recpt in others:  # send notification to other participants as a signalling mechanism
            self.postman.send(src=ghab.mhab.pre, dest=recpt, topic="multisig", serder=exn, attachment=ims)

        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=serder.sn)
        saider = coring.Saider(qb64b=serder.saidb)
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider, ghab=ghab)

        while True:
            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, seqner.qb64))
            if saider is not None:
                break

            yield self.tock

        print()
        displaying.printIdentifier(self.hby, ghab.pre)
        self.remove(self.toRemove)
