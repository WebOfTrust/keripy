# -*- encoding: utf-8 -*-
"""
keri.kli.commands.multisig module

"""

import argparse

import math
from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import habbing, keeping, directing, agenting, indirecting, forwarding
from keri.app.cli.commands import multisig
from keri.app.cli.common import grouping, rotating, displaying
from keri.core import coring, eventing, parsing
from keri.db import basing, dbing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Begin or join a rotation of a group identifier')
parser.set_defaults(handler=lambda args: rotateGroupIdentifier(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--group', '-g', help="Human readable environment reference for group identifier", required=True)
parser.add_argument('--proto', '-p', help='Protocol to use when propagating ICP to witnesses [tcp|http] (defaults '
                                          'http)', default="http")
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

    name = args.name

    rotDoer = MultiSigRotateDoer(name=name, groupName=args.group, proto=args.proto, wits=args.witnesses,
                                 cuts=args.witness_cut, adds=args.witness_add, sith=args.sith, toad=args.toad)

    doers = [rotDoer]
    directing.runController(doers=doers, expire=0.0)


class MultiSigRotateDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to query all other group identifiers and perform a rotation of the group
    identifier.  Also publishes to the witnesses when the rotation is complete.

    """

    def __init__(self, name, groupName, proto, sith=None, toad=None, wits=None, cuts=None, adds=None, data=None):
        """
        Returns the DoDoer and registers all doers needed for multisig rotation

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
        self.toad = toad
        self.data = data

        self.wits = wits if wits is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        self.groupName = groupName
        self.msgs = decking.Deck()
        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.hab = hab
        self.kvy = eventing.Kevery(db=hab.db,
                                   lax=False,
                                   local=False)

        self.habDoer = habbing.HabitatDoer(habitat=self.hab)
        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.TCPWitnesser)

        mbd = indirecting.MailboxDirector(hab=hab, topics=['/receipt', '/multisig'])
        self.postman = forwarding.Postman(hab=hab)

        self.runningDoers: list = [self.ksDoer, self.dbDoer, self.habDoer, self.witq, self.postman, mbd]

        doers = self.runningDoers + [doing.doify(self.rotateDo)]
        super(MultiSigRotateDoer, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0):
        """
        Main doified method that processes the rotation event for either initiating a rotation
        or participating in an existing rotation proposed by another member of the group

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        group = self.hab.db.gids.get(keys=self.groupName)
        if group is None or group.lid != self.hab.pre:
            print("invalid group identifier {}\n".format(self.groupName))
            return

        if self.sith is None:
            self.sith = "{:x}".format(max(0, math.ceil(len(group.aids) / 2)))

        if self.wits:
            if self.adds or self.cuts:
                raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
            ewits = self.hab.kever.lastEst.wits

            self.cuts = set(self.wits) & set(ewits)
            self.adds = set(self.wits) - set(ewits)


        self.witq.query(group.gid)
        while group.gid not in self.hab.kevers:
            _ = (yield self.tock)

        gkev = self.hab.kevers[group.gid]
        sno = gkev.sn + 1

        if self.hab.kever.sn == gkev.sn:  # We are equal to the current group identifier, need to rotate
            rot = self.hab.rotate()
            witDoer = agenting.WitnessReceiptor(hab=self.hab, klas=agenting.HttpWitnesser, msg=rot)
            self.extend(doers=[witDoer])
            self.runningDoers.append(witDoer)
            while not witDoer.done:
                _ = yield self.tock

        print("Local identifier rotated, checking other group members:")
        idx = group.aids.index(self.hab.pre)

        mskeys = []
        msdigers = []
        for aid in group.aids:
            kever = self.hab.kevers[aid]
            if aid != self.hab.pre:
                if kever.sn < self.hab.kever.sn:
                    print("waiting for {} to join rotation...".format(aid))
                while kever.sn < self.hab.kever.sn:
                    self.witq.query(aid)
                    _ = (yield self.tock)

            keys = kever.verfers
            if len(keys) > 1:
                raise kering.ConfigurationError("Identifier must have only one key, {} has {}".format(aid, len(keys)))

            diger = grouping.extractDig(nexter=kever.nexter, tholder=kever.tholder)

            mskeys.append(keys[0])
            msdigers.append(diger)

        wits = gkev.wits
        mssrdr = eventing.rotate(pre=gkev.prefixer.qb64,
                                 dig=gkev.serder.dig,
                                 sn=sno,
                                 keys=[mskey.qb64 for mskey in mskeys],
                                 sith=group.cst,  # the previously committed to signing threshold
                                 toad=self.toad,
                                 wits=wits,
                                 cuts=self.cuts,
                                 adds=self.adds,
                                 nxt=coring.Nexter(sith=self.sith,
                                                   digs=[diger.qb64 for diger in msdigers]).qb64)

        # the next digest previous calculated
        sigers = self.hab.mgr.sign(ser=mssrdr.raw, verfers=self.hab.kever.verfers, indices=[idx])
        msg = eventing.messagize(mssrdr, sigers=sigers)
        parsing.Parser().parseOne(ims=bytearray(msg), kvy=self.kvy)

        for aid in group.aids:
            if aid == self.hab.pre:
                continue
            self.postman.send(recipient=aid, topic="multisig", msg=bytearray(msg))
            yield self.tock


        # Wait until we receive the multisig rotation event from all parties
        dgkey = dbing.dgKey(mssrdr.preb, mssrdr.digb)
        sigs = self.hab.db.getSigs(dgkey)
        while len(sigs) != len(group.aids):
            sigs = self.hab.db.getSigs(dgkey)
            _ = (yield self.tock)


        if idx == 0:  # We are the first in the list, elected to send to witnesses
            sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
            msg = eventing.messagize(mssrdr, sigers=sigers)

            witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg, klas=agenting.TCPWitnesser)
            self.extend([witRctDoer])
            self.runningDoers.extend([witRctDoer])

            while not witRctDoer.done:
                _ = yield self.tock

        else:  # We are one of the first, so we wait for the last to run and get the receipts
            while self.hab.kevers[mssrdr.pre].sn < sno:
                self.witq.query(mssrdr.pre)
                _ = (yield self.tock)

        group.cst = self.sith
        self.hab.db.gids.pin(self.groupName, group)

        print()
        print("Group Identifier Rotation Complete:")
        displaying.printIdentifier(self.hab, mssrdr.pre)

        self.remove(self.runningDoers)
