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
from keri.app.cli.common import rotating, existing, displaying, config
from keri.app.notifying import Notifier
from keri.core import coring, serdering
from keri.db import dbing
from keri.peer import exchanging

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Begin or join a rotation of a group identifier')
parser.set_defaults(handler=lambda args: rotateGroupIdentifier(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the local identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--smids", "-s", help="List of other participant qb64 identifiers with signing authority in "
                                          "rotation event",
                    action="append", required=False, default=None)
parser.add_argument("--rmids", help="List of other participant qb64 identifiers with rotation authority in rotation "
                                    "event",
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

    data = config.parseData(args.data) if args.data is not None else None
    hby = existing.setupHby(name=args.name, base=args.base, bran=args.bran)
    rotDoer = GroupMultisigRotate(hby=hby, alias=args.alias, smids=args.smids, rmids=args.rmids,
                                  wits=args.witnesses, cuts=args.cuts, adds=args.witness_add,
                                  isith=args.isith, nsith=args.nsith, toad=args.toad, data=data)

    doers = [rotDoer]
    return doers


class GroupMultisigRotate(doing.DoDoer):
    """
    Command line DoDoer to launch the needed coroutines to run launch Multisig rotation.
       This DoDoer will remove the multisig coroutine and exit when it recieves a message
       that the multisig coroutine has successfully completed a cooperative rotation.

    """

    def __init__(self, hby, alias, smids=None, rmids=None, isith=None, nsith=None,
                 toad=None, wits=None, cuts=None, adds=None, data: list = None):

        self.alias = alias
        self.isith = isith
        self.nsith = nsith
        self.toad = toad
        self.smids = smids
        self.rmids = rmids
        self.data = data
        self.hby = hby

        self.wits = wits if wits is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(exc, mux)

        mbd = indirecting.MailboxDirector(hby=self.hby, topics=['/receipt', '/multisig', '/replay'], exc=exc)
        self.counselor = grouping.Counselor(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)

        doers = [mbd, self.hbyDoer, self.counselor, self.postman]
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

        if self.smids is None:
            self.smids = ghab.smids

        if self.rmids is None:
            self.rmids = self.smids

        if self.wits:
            if self.adds or self.cuts:
                raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
            ewits = ghab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            self.cuts = set(ewits) - set(self.wits)
            self.adds = set(self.wits) - set(ewits)

        smids = []
        merfers = []
        for smid in self.smids:
            match smid.split(':'):
                case [mid]:  # Only prefix provided, assume latest event
                    if mid not in self.hby.kevers:
                        raise kering.ConfigurationError(f"unknown signing member {mid}")

                    mkever = self.hby.kevers[mid]  # get key state for given member
                    merfers.append(mkever.verfers[0])
                    smids.append(mid)

                case [mid, sn]:
                    if mid not in self.hby.kevers:
                        raise kering.ConfigurationError(f"unknown signing member {mid}")

                    dig = self.hby.db.getKeLast(dbing.snKey(mid, int(sn)))
                    if dig is None:
                        raise kering.ConfigurationError(f"non-existant event {sn} for signing member {mid}")

                    evt = self.hby.db.getEvt(dbing.dgKey(mid, bytes(dig)))
                    serder = serdering.SerderKERI(raw=bytes(evt))
                    if not serder.estive:
                        raise kering.ConfigurationError(f"invalid event {sn} for signing member {mid}")

                    merfers.append(serder.verfers[0])
                    smids.append(mid)

                case _:
                    raise kering.ConfigurationError(f"invalid smid representation {smid}")

        migers = []
        rmids = []
        for rmid in self.rmids:
            match rmid.split(':'):
                case [mid]:  # Only prefix provided, assume latest event
                    if mid not in self.hby.kevers:
                        raise kering.ConfigurationError(f"unknown rotation member {mid}")

                    mkever = self.hby.kevers[mid]  # get key state for given member
                    migers.append(mkever.ndigers[0])
                    rmids.append(mid)

                case [mid, sn]:
                    if mid not in self.hby.kevers:
                        raise kering.ConfigurationError(f"unknown rotation member {mid}")

                    dig = self.hby.db.getKeLast(dbing.snKey(mid, int(sn)))
                    if dig is None:
                        raise kering.ConfigurationError(f"non-existant event {sn} for rotation member {mid}")

                    evt = self.hby.db.getEvt(dbing.dgKey(mid, bytes(dig)))
                    serder = serdering.SerderKERI(raw=bytes(evt))
                    if not serder.estive:
                        raise kering.ConfigurationError(f"invalid event {sn} for rotation member {mid}")

                    migers.append(serder.ndigers[0])
                    rmids.append(mid)

                case _:
                    raise kering.ConfigurationError(f"invalid rmid representation {rmid}")

        if ghab.mhab.pre not in smids:
            raise kering.ConfigurationError(f"{ghab.mhab.pre} not in signing members {smids} for this event")

        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=ghab.kever.sn+1)
        rot = ghab.rotate(isith=self.isith, nsith=self.nsith,
                          toad=self.toad, cuts=list(self.cuts), adds=list(self.adds), data=self.data,
                          verfers=merfers, digers=migers, smids=smids, rmids=rmids)

        rserder = serdering.SerderKERI(raw=rot)
        # Create a notification EXN message to send to the other agents
        exn, ims = grouping.multisigRotateExn(ghab=ghab,
                                              smids=smids,
                                              rmids=rmids,
                                              rot=bytearray(rot))
        others = list(oset(smids + (rmids or [])))

        others.remove(ghab.mhab.pre)

        for recpt in others:  # Send event AND notification message to others
            self.postman.send(src=ghab.mhab.pre,
                              dest=recpt,
                              topic="multisig",
                              serder=exn,
                              attachment=bytearray(ims))

        self.counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

        while True:
            saider = self.hby.db.cgms.get(keys=(ghab.pre, seqner.qb64))
            if saider is not None:
                break

            yield self.tock

        if ghab.kever.delpre:
            yield from self.postman.sendEventToDelegator(hab=ghab, sender=ghab.mhab, fn=ghab.kever.sn)

        print()
        displaying.printIdentifier(self.hby, ghab.pre)
        self.remove(self.toRemove)
