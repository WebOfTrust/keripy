# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""
import json
import logging
from collections import namedtuple

import blake3
import math
from hio import help
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import agenting, forwarding
from keri.core import coring, eventing, parsing
from keri.db import dbing, basing

logger = help.ogler.getLogger()

Opage = namedtuple("Opage", 'icp rot ixn')

Ops = Opage(icp='icp', rot='rot', ixn='ixn')


class Groupy:

    def __init__(self, hab, msgs=None, cues=None):
        self.msgs = msgs if msgs is not None else decking.Deck()  # subclass of deque
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque
        self.hab = hab
        self.db = hab.db

        self.kvy = eventing.Kevery(db=hab.db,
                                   lax=False,
                                   local=False)

    def processMessages(self, msgs=None):
        """
        Process message dicts in msgs or if msgs is None in .msgs
        Parameters:
            msgs (Deck): each entry is dict that matches call signature of
                .processMessage
        """
        if msgs is None:
            msgs = self.msgs

        while msgs:
            self.processMessage(**msgs.pull())

    def processMessage(self, name, msg, mssrdr=None, sigers=None):

        op = msg["op"]
        if op in (Ops.icp,):
            aids = list(msg['aids'])
            if self.hab.pre not in aids:
                raise kering.ConfigurationError("Local identifer {} must be member of aids ={}"
                                                .format(self.hab.pre, aids))

            sith = msg["isith"]
            toad = msg["toad"]
            nsith = msg["nsith"]
            wits = msg["witnesses"] if msg["witnesses"] is not None else self.hab.kever.wits
            data = msg["data"] if "data" in msg else None

            idx = aids.index(self.hab.pre)
            if mssrdr is None:
                for aid in aids:
                    if aid not in self.hab.kevers:
                        self.cues.append(dict(kin="query", aid=aid))
                        self.escrowPAE(name, msg)
                        raise kering.MissingAidError(
                            "group {} missing AID {}".format(name, aid))

                mskeys, msdigers = self.extractKeysDigs(aids)
                mssrdr = eventing.incept(keys=[mskey.qb64 for mskey in mskeys],
                                         sith=sith,
                                         toad=toad,
                                         wits=wits,
                                         nxt=coring.Nexter(sith=nsith,
                                                           digs=[diger.qb64 for diger in msdigers]).qb64,
                                         code=coring.MtrDex.Blake3_256,
                                         data=data)

                sigers = self.hab.mgr.sign(ser=mssrdr.raw, verfers=self.hab.kever.verfers, indices=[idx])

                mmsg = eventing.messagize(mssrdr, sigers=sigers)
                parsing.Parser().parseOne(ims=bytearray(mmsg), kvy=self.kvy)

                for aid in aids:
                    if aid == self.hab.pre:
                        continue
                    self.cues.append(dict(kin="send", recipient=aid, topic='multisig', msg=bytearray(mmsg)))

            indices = [siger.index for siger in sigers]
            tholder = coring.Tholder(sith=sith)
            if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
                self.escrowPSE(name, msg, mssrdr)
                raise kering.MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                                   " for evt = {}.".format(tholder.sith,
                                                                           [siger.qb64 for siger in sigers],
                                                                           mssrdr.ked))

            #  Add this group identifier prefix to my list of group identifiers I participate in
            group = basing.GroupIdRecord(lid=self.hab.pre, gid=mssrdr.pre, dig=mssrdr.dig, cst=nsith, aids=aids)
            self.db.gids.pin(name, group)

            self.cues.append(dict(
                kin="logEvent",
                group=group,
                pre=mssrdr.pre,
                mssrdr=mssrdr,
                sigers=sigers,
                sn=0
            ))

        elif op in (Ops.rot,):
            groupName = msg["group"]
            sith = msg["sith"]
            toad = msg["toad"]
            data = msg["data"]
            wits = msg["witnesses"] if "witnesses" in msg else []
            cuts = msg["witness_cut"] if "witnesse_cut" in msg else []
            adds = msg["witness_add"] if "witnesse_add" in msg else []

            group = self.hab.db.gids.get(keys=groupName)
            if group is None or group.lid != self.hab.pre:
                print("invalid group identifier {}\n".format(groupName))
                raise kering.InvalidGroupError("invalid group identifier {}".format(groupName))

            if sith is None:
                sith = "{:x}".format(max(0, math.ceil(len(group.aids) / 2)))

            if wits:
                if adds or cuts:
                    raise kering.ConfigurationError("you can only specify witnesses or cuts and adds")
                ewits = self.hab.kever.lastEst.wits

                cuts = set(wits) & set(ewits)
                adds = set(wits) - set(ewits)

            gkev = self.hab.kevers[group.gid]
            sno = gkev.sn + 1

            if self.hab.kever.sn == gkev.sn:  # We are equal to the current group identifier, need to rotate
                rot = self.hab.rotate()
                self.cues.append(dict(kin="witness", msg=bytearray(rot)))

                for aid in group.aids:
                    if aid == self.hab.pre:
                        continue
                    self.cues.append(dict(kin="send", recipient=aid, topic='multisig', msg=bytearray(rot)))

            print("Local identifier rotated, checking other group members:")
            idx = group.aids.index(self.hab.pre)

            for aid in group.aids:
                kever = self.hab.kevers[aid]
                if aid != self.hab.pre:
                    if kever.sn < self.hab.kever.sn:
                        print("waiting for {} to join rotation...".format(aid))
                        self.cues.append(dict(kin="query", aid=aid))
                        self.escrowPAE(name, msg)
                        raise kering.MissingAidError(
                            "Group {} - AID {} not at sn={}".format(name, aid, self.hab.kever.sn))

            if mssrdr is None:
                mskeys, msdigers = self.extractKeysDigs(group.aids)
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
                    self.cues.append(dict(kin="send", recipient=aid, topic='multisig', msg=bytearray(msg)))

            indices = [siger.index for siger in sigers]
            tholder = coring.Tholder(sith=sith)
            if not tholder.satisfy(indices):  # We still don't have all the sigers, need to escrow
                self.escrowPSE(name, msg, mssrdr)
                raise kering.MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                                   " for evt = {}.".format(tholder.sith,
                                                                           [siger.qb64 for siger in sigers],
                                                                           mssrdr.ked))

            group.cst = sith
            group.dig = mssrdr.dig
            self.hab.db.gids.pin(groupName, group)

            self.cues.append(dict(
                kin="logEvent",
                group=group,
                pre=mssrdr.pre,
                mssrdr=mssrdr,
                sigers=sigers,
                sn=mssrdr.ked["s"]
            ))

    def escrowPAE(self, name, msg):
        dat = json.dumps(msg).encode("utf-8")
        self.db.gpae.put(name, dat)

    def escrowPSE(self, name, msg, mssrdr):
        msg["pre"] = mssrdr.pre
        msg["dig"] = mssrdr.dig
        dat = json.dumps(msg).encode("utf-8")
        self.db.gpse.put(name, dat)

    def processEscrows(self):
        self.processPartialAidEscrow()
        self.processPartialSignedEscrow()

    def processPartialAidEscrow(self):
        """
        """
        for (name,), mraw in self.db.gpae.getItemIter():
            try:
                msg = json.loads(mraw)
                self.processMessage(name=name, msg=msg)
            except kering.MissingAidError as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Groupy unescrow failed: %s\n", ex.args[0])
                else:
                    logger.error("Groupy unescrow failed: %s\n", ex.args[0])
            except Exception as ex:  # log diagnostics errors etc
                # error other than missing AID so remove from PA escrow
                self.db.gpae.rem(name)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Groupy unescrowed: %s\n", ex.args[0])
                else:
                    logger.error("Groupy unescrowed: %s\n", ex.args[0])
            else:
                self.db.gpae.rem(name)
                logger.info("Groupy unescrow succeeded in valid group op: "
                            "msg=\n%s\n", json.dumps(msg, indent=1))

    def processPartialSignedEscrow(self):
        """
        """

        for (name,), dat in self.db.gpse.getItemIter():
            msg = json.loads(dat)

            gid = msg["pre"]
            dig = msg["dig"]

            dgkey = dbing.dgKey(gid, dig)
            eraw = self.db.getEvt(dgkey)
            mssrdr = coring.Serder(raw=bytes(eraw))  # escrowed event

            dgkey = dbing.dgKey(mssrdr.preb, mssrdr.digb)
            sigs = self.hab.db.getSigs(dgkey)
            sigers = [coring.Siger(qb64b=bytes(sig)) for sig in sigs]

            try:
                self.processMessage(name, msg, mssrdr=mssrdr, sigers=sigers)
            except kering.MissingSignatureError as ex:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Groupy unescrow failed: %s\n", ex.args[0])
                else:
                    logger.error("Groupy unescrow failed: %s\n", ex.args[0])
            except Exception as ex:  # log diagnostics errors etc
                # error other than missing sigs so remove from PA escrow
                self.db.gpse.rem(name)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Groupy unescrowed: %s\n", ex.args[0])
                else:
                    logger.error("Groupy unescrowed: %s\n", ex.args[0])
            else:
                self.db.gpse.rem(name)
                logger.info("Groupy unescrow succeeded in valid group op: "
                            "msg=\n%s\n", json.dumps(msg, indent=1))

    def extractKeysDigs(self, aids):
        mskeys = []
        msdigers = []
        for aid in aids:
            kever = self.hab.kevers[aid]
            keys = kever.verfers
            if len(keys) > 1:
                raise kering.ConfigurationError("Identifier must have only one key, {} has {}"
                                                .format(aid, len(keys)))

            diger = self.extractDig(nexter=kever.nexter, tholder=kever.tholder)

            mskeys.append(keys[0])
            msdigers.append(diger)

        return mskeys, msdigers

    @staticmethod
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


class MultiSigGroupDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a multisig group identifier.  The identifier of the environment loaded from `name`
    must be a member of the group of identifiers listed in the configuration file.

    """

    def __init__(self, hab, msgs=None, cues=None):
        """
        Creates the DoDoer needed to modify a multisig group identifier.  Requires the
        name of the environment whose identifier is a member of the group being created.
        All other arguments are passed to the inceptDo generator method as parameters to create
        the inception event.

        Parameters
            name (str): Name of the local identifier environment

        """
        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.groupy = Groupy(hab=self.hab)
        self.kvy = eventing.Kevery(db=hab.db,
                                   lax=False,
                                   local=False)

        self.postman = forwarding.Postman(hab=self.hab)
        self.witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.TCPWitnesser)

        doers = [self.postman,
                 self.witq,
                 doing.doify(self.msgDo),
                 doing.doify(self.cueDo),
                 doing.doify(self.escrowDo),
                 ]

        super(MultiSigGroupDoer, self).__init__(doers=doers)

    def msgDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list

        Message Parameters:
            group: str group name
            aids: list of qb64 identifier prefixes of participants in the group
            witnesses: list of qb64 identifier prefixes of witnesses for the group
            toad: str of witness receipt threshold for group KEL
            isith str of current signing threshold for group
            nsith str of next signing threshold for group
            data is list of dicts or anchors for the inception event of the group KEL

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
                try:
                    self.groupy.processMessage(name=group, msg=msg)
                except (kering.ValidationError, Exception) as ex:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("Multisig message error: %s\n", ex)
                    else:
                        logger.error("Multisig message error: %s\n", ex)
                yield self.tock

            yield self.tock

    def cueDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list

        Processes the cues coming out of the Groupy.  Performs queries, message
        delivery and receipting based on the cues from the Groupy processing of
        group requests.

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        while True:
            while self.groupy.cues:  # iteratively process each cue in cues
                cue = self.groupy.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue

                if cueKin == "query":
                    self.witq.query(cue["aid"])
                elif cueKin == "send":
                    self.postman.send(recipient=cue["recipient"],
                                      topic=cue["topic"],
                                      msg=cue["msg"])
                elif cueKin == "witness":
                    msg = cue["msg"]
                    witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg, klas=agenting.TCPWitnesser)
                    self.extend([witRctDoer])

                    while not witRctDoer.done:
                        _ = yield self.tock

                    self.remove([witRctDoer])

                elif cueKin == "logEvent":
                    group = cue["group"]
                    mssrdr = cue["mssrdr"]
                    sigers = cue["sigers"]
                    idx = group.aids.index(self.hab.pre)

                    if idx == sigers[0].index:  # We are the first signer, elected to send to witnesses
                        msg = eventing.messagize(mssrdr, sigers=sigers)

                        witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg, klas=agenting.TCPWitnesser)
                        self.extend([witRctDoer])

                        while not witRctDoer.done:
                            _ = yield self.tock

                        self.remove([witRctDoer])

                    else:  # We are not the first signer, so we wait for the sigs and processed receipts
                        while mssrdr.pre not in self.hab.kevers:
                            self.witq.query(mssrdr.pre)
                            _ = (yield self.tock)
                    self.cues.append(cue)

                yield self.tock

            yield self.tock

    def escrowDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list

        Processes the Groupy escrow for group icp, rot and ixn request messages.

        """
        # start enter context
        yield  # enter context
        while True:
            self.groupy.processEscrows()
            yield
