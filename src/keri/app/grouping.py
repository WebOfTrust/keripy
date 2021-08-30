# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""

import blake3
import math
from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import agenting, forwarding, indirecting
from keri.core import coring, eventing, parsing
from keri.db import dbing, basing

logger = help.ogler.getLogger()


class MultiSigInceptDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a multisig group identifier.  The identifier of the environment loaded from `name`
    must be a member of the group of identifiers listed in the configuration file.

    """

    def __init__(self, hab, msgs=None, cues=None):
        """
        Creates the DoDoer needed to incept a multisig group identifier.  Requires the
        name of the environment whose identifier is a member of the group being created.
        All other arguments are passed to the inceptDo generator method as parameters to create
        the inception event.

        Parameters
            name (str): Name of the local identifier environment

        """
        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.kvy = eventing.Kevery(db=hab.db,
                                   lax=False,
                                   local=False)

        mbd = indirecting.MailboxDirector(hab=hab, topics=['/receipt', '/multisig'])
        self.postman = forwarding.Postman(hab=hab)
        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.TCPWitnesser)

        doers = [mbd, self.postman,
                 self.witq,
                 doing.doify(self.inceptDo)]

        super(MultiSigInceptDoer, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                if "group" not in msg:
                    print("group name is missing from multisig incept message")
                    continue

                group = msg["group"]

                aids = list(msg['aids'])
                if self.hab.pre not in aids:
                    raise kering.ConfigurationError("Local identifer {} must be member of aids ={}".format(self.hab.pre, aids))

                idx = aids.index(self.hab.pre)

                mskeys = []
                msdigers = []
                for aid in aids:
                    if aid not in self.hab.kevers:
                        self.witq.query(aid)
                        while aid not in self.hab.kevers:
                            _ = (yield self.tock)

                    kever = self.hab.kevers[aid]
                    keys = kever.verfers
                    if len(keys) > 1:
                        raise kering.ConfigurationError("Identifier must have only one key, {} has {}".format(aid, len(keys)))

                    diger = extractDig(nexter=kever.nexter, tholder=kever.tholder)

                    mskeys.append(keys[0])
                    msdigers.append(diger)

                wits = msg["witnesses"] if msg["witnesses"] is not None else self.hab.kever.wits

                nsith = msg["nsith"]
                mssrdr = eventing.incept(keys=[mskey.qb64 for mskey in mskeys],
                                         sith=msg["isith"],
                                         toad=msg["toad"],
                                         wits=wits,
                                         nxt=coring.Nexter(sith=nsith,
                                                           digs=[diger.qb64 for diger in msdigers]).qb64,
                                         code=coring.MtrDex.Blake3_256)

                sigers = self.hab.mgr.sign(ser=mssrdr.raw, verfers=self.hab.kever.verfers, indices=[idx])

                msg = eventing.messagize(mssrdr, sigers=sigers)
                parsing.Parser().parseOne(ims=bytearray(msg), kvy=self.kvy)

                for aid in aids:
                    if aid == self.hab.pre:
                        continue
                    self.postman.send(recipient=aid, topic='multisig', msg=bytearray(msg))
                    _ = yield self.tock

                # Wait until we receive the multisig rotation event from all parties
                dgkey = dbing.dgKey(mssrdr.preb, mssrdr.digb)
                sigs = self.hab.db.getSigs(dgkey)
                while len(sigs) != len(aids):
                    sigs = self.hab.db.getSigs(dgkey)
                    _ = (yield self.tock)

                if idx == 0:  # We are the first in the list, elected to send to witnesses
                    sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]
                    msg = eventing.messagize(mssrdr, sigers=sigers)

                    witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg, klas=agenting.TCPWitnesser)
                    self.extend([witRctDoer])

                    while not witRctDoer.done:
                        _ = yield self.tock

                    self.remove([witRctDoer])

                else:  # We are one of the first, so we wait for the last to run and get the receipts
                    while mssrdr.pre not in self.hab.kevers:
                        self.witq.query(mssrdr.pre)
                        _ = (yield self.tock)

                #  Add this group identifier prefix to my list of group identifiers I participate in
                bid = basing.GroupIdentifier(lid=self.hab.pre, gid=mssrdr.pre, cst=nsith, aids=aids)
                self.hab.db.gids.pin(group, bid)

                self.cues.append(dict(
                    group=group,
                    pre=mssrdr.pre,
                    sn=0
                ))

                yield self.tock

            yield self.tock


class MultiSigRotateDoer(doing.DoDoer):
    """
    DoDoer that launches Doers needed to query all other group identifiers and perform a rotation of the group
    identifier.  Also publishes to the witnesses when the rotation is complete.

    """

    def __init__(self, hab, msgs=None, cues=None):
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

        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()


        self.kvy = eventing.Kevery(db=hab.db,
                                   lax=False,
                                   local=False)

        self.witq = agenting.WitnessInquisitor(hab=hab, klas=agenting.TCPWitnesser)
        self.postman = forwarding.Postman(hab=hab)

        doers = [self.witq, self.postman, doing.doify(self.rotateDo)]
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

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                groupName = msg["group"]
                sith = msg["sith"]
                toad = msg["toad"]
                data = msg["data"]
                wits = msg["witnesses"]
                cuts = msg["witness_cut"]
                adds = msg["witness_add"]
                wits = wits if wits is not None else []
                cuts = cuts if cuts is not None else []
                adds = adds if adds is not None else []

                group = self.hab.db.gids.get(keys=groupName)
                if group is None or group.lid != self.hab.pre:
                    print("invalid group identifier {}\n".format(groupName))
                    continue

                if sith is None:
                    sith = "{:x}".format(max(0, math.ceil(len(group.aids) / 2)))

                if wits:
                    if adds or cuts:
                        raise kering.ConfigurationError("you can only specify witnesses or cuts and add")
                    ewits = self.hab.kever.lastEst.wits

                    cuts = set(wits) & set(ewits)
                    adds = set(wits) - set(ewits)


                self.witq.query(group.gid)
                while group.gid not in self.hab.kevers:
                    _ = (yield self.tock)

                gkev = self.hab.kevers[group.gid]
                sno = gkev.sn + 1

                if self.hab.kever.sn == gkev.sn:  # We are equal to the current group identifier, need to rotate
                    rot = self.hab.rotate()
                    witDoer = agenting.WitnessReceiptor(hab=self.hab, klas=agenting.HttpWitnesser, msg=rot)
                    self.extend([witDoer])
                    while not witDoer.done:
                        _ = yield self.tock

                    self.remove([witDoer])

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
                        raise kering.ConfigurationError("Identifier must have only one key, {} has {}"
                                                        .format(aid, len(keys)))

                    diger = extractDig(nexter=kever.nexter, tholder=kever.tholder)

                    mskeys.append(keys[0])
                    msdigers.append(diger)

                wits = gkev.wits
                mssrdr = eventing.rotate(pre=gkev.prefixer.qb64,
                                         dig=gkev.serder.dig,
                                         sn=sno,
                                         keys=[mskey.qb64 for mskey in mskeys],
                                         sith=group.cst,  # the previously committed to signing threshold
                                         toad=toad,
                                         wits=wits,
                                         cuts=cuts,
                                         adds=adds,
                                         data=data,
                                         nxt=coring.Nexter(sith=sith,
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

                    while not witRctDoer.done:
                        _ = yield self.tock

                    self.remove([witRctDoer])

                else:  # We are one of the first, so we wait for the last to run and get the receipts
                    while self.hab.kevers[mssrdr.pre].sn < sno:
                        self.witq.query(mssrdr.pre)
                        _ = (yield self.tock)

                group.cst = sith
                self.hab.db.gids.pin(groupName, group)

                self.cues.append(dict(
                    group=groupName,
                    pre=mssrdr.pre,
                    sn=mssrdr.ked["s"]
                ))

                yield self.tock

            yield self.tock




def extractDig(nexter, tholder):
    """
    Extracts the original digest of the public key from the digest created by XORing the
    key with the signing threshold.  This is used in group identifier event creation to enable
    creation of the next digest with the combined keys and the group signing threshold.

    Parameters:
        nexter is Nexter instance of next sith and next signing keys
        tholder is Tholder instance for event sith

    """
    dint = int.from_bytes(nexter.raw, 'big')

    limen = tholder.limen
    ldig = blake3.blake3(limen.encode("utf-8")).digest()
    sint = int.from_bytes(ldig, 'big')
    kint = dint ^ sint

    diger = coring.Diger(raw=kint.to_bytes(coring.Matter._rawSize(coring.MtrDex.Blake3_256), 'big'))
    return diger
