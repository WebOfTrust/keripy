# -*- encoding: utf-8 -*-
"""
keri.app.storing module

"""
import itertools
import random

from hio.base import doing
from hio.help import decking
from ordered_set import OrderedSet as oset

from . import httping, agenting, forwarding
from .. import help
from ..core import coring
from ..core.coring import MtrDex
from ..db import dbing, subing
from ..peer import exchanging

logger = help.ogler.getLogger()


class Mailboxer(dbing.LMDBer):
    """
    Mailboxer stores exn messages in order and provider iterator access at an index.

    """
    TailDirPath = "keri/mbx"
    AltTailDirPath = ".keri/mbx"
    TempPrefix = "keri_mbx_"

    def __init__(self, name="mbx", headDirPath=None, reopen=True, **kwa):
        """

        Parameters:
            headDirPath:
            perm:
            reopen:
            kwa:
        """
        self.tpcs = None
        self.msgs = None

        super(Mailboxer, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """

        :param kwa:
        :return:
        """
        super(Mailboxer, self).reopen(**kwa)

        self.tpcs = self.env.open_db(key=b'tpcs.', dupsort=True)
        self.msgs = subing.Suber(db=self, subkey='msgs.')  # key states

        return self.env

    def delTopic(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delIoSetVals(self.tpcs, key)

    def appendToTopic(self, topic, val):
        """
        Return first seen order number int, fn, of appended entry.
        Computes fn as next fn after last entry.

        Append val to end of db entries with same topic but with fn incremented by
        1 relative to last preexisting entry at pre.

        Parameters:
            topic is bytes identifier prefix/topic for message
            val is event digest
        """
        return self.appendIoSetVal(db=self.tpcs, key=topic, val=val)

    def getTopicMsgs(self, topic, fn=0):
        """
        Returns:
             ioset (oset): the insertion ordered set of values at same apparent
             effective key.
             Uses hidden ordinal key suffix for insertion ordering.
             The suffix is appended and stripped transparently.

         Parameters:
             topic (Option(bytes|str)): Apparent effective key
             fn (int) starting index
        """
        if hasattr(topic, "encode"):
            topic = topic.encode("utf-8")

        digs = self.getIoSetVals(db=self.tpcs, key=topic, ion=fn)
        msgs = []
        for dig in digs:
            if msg := self.msgs.get(keys=dig):
                msgs.append(msg.encode("utf-8"))
        return msgs

    def storeMsg(self, topic, msg):
        """
        Add exn event to mailbox of dest identifier

        Parameters:
            msg (bytes):
            topic (qb64b):

        """
        if hasattr(topic, "encode"):
            topic = topic.encode("utf-8")

        if hasattr(msg, "encode"):
            msg = msg.encode("utf-8")

        digb = coring.Diger(ser=msg, code=MtrDex.Blake3_256).qb64b
        self.appendToTopic(topic=topic, val=digb)
        return self.msgs.pin(keys=digb, val=msg)

    def cloneTopicIter(self, topic, fn=0):
        """
        Returns iterator of first seen exn messages with attachments for the
        identifier prefix pre starting at first seen order number, fn.

        """
        if hasattr(topic, 'encode'):
            topic = topic.encode("utf-8")

        for (key, dig) in self.getIoSetItemsIter(self.tpcs, key=topic, ion=fn):
            topic, ion = dbing.unsuffix(key)
            if msg := self.msgs.get(keys=dig):
                yield ion, topic, msg.encode("utf-8")


class Respondant(doing.DoDoer):
    """
    Respondant processes buffer of response messages from inbound 'exn' messages and
    routes them to the appropriate mailbox.  If destination has witnesses, send response to
    one of the (randomly selected) witnesses.  Otherwise store the response in the recipients
    mailbox locally.

    """

    def __init__(self, hby, reps=None, cues=None, mbx=None, **kwa):
        """
        Creates Respondant that uses local environment to find the destination KEL and stores
        peer to peer messages in mbx, the mailboxer

        Parameters:
            hab (Habitat):  local environment
            mbx (Mailboxer): storage for local messages

        """
        self.reps = reps if reps is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.hby = hby
        self.mbx = mbx if mbx is not None else Mailboxer(name=self.hby.name)
        self.postman = forwarding.Postman(hby=self.hby)

        doers = [self.postman, doing.doify(self.responseDo), doing.doify(self.cueDo)]
        super(Respondant, self).__init__(doers=doers, **kwa)

    def responseDo(self, tymth=None, tock=0.0):
        """
        Doifiable Doist compatibile generator method to process response messages from `exn` handlers.
        If dest is not in local environment, ignore the response (for now).  If dest has witnesses,
        pick one at random and send the response to that witness for storage in the recipients mailbox
        on that witness.  Otherwise this is a peer to peer HTTP message and should be stored in a mailbox
        locally for the recipient.

        Usage:
            add result of doify on this method to doers list
        """

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.reps:
                rep = self.reps.popleft()
                sender = rep["src"]
                recipient = rep["dest"]
                exn = rep["rep"]
                topic = rep["topic"]

                if recipient not in self.hby.kevers:
                    logger.error("unable to reply, dest {} not found".format(recipient))
                    continue
                recpkev = self.hby.kevers[recipient]

                senderHab = self.hby.habs[sender]
                if senderHab.mhab:
                    forwardHab = senderHab.mhab
                else:
                    forwardHab = senderHab

                if len(recpkev.wits) == 0:
                    msg = senderHab.endorse(exn, last=True)
                    self.mbx.storeMsg(topic=recipient, msg=msg)
                else:
                    wit = random.choice(recpkev.wits)
                    client, clientDoer = agenting.httpClient(senderHab, wit)

                    self.extend([clientDoer])

                    # sign the exn to get the signature
                    eattach = senderHab.endorse(exn, last=True, pipelined=False)
                    # TODO: switch to the following and test that outbound events are persisted:
                    #    eattach = senderHab.exchange(exn, save=True)
                    del eattach[:exn.size]

                    # create and sign the forward exn that will contain the exn
                    fwd = exchanging.exchange(route='/fwd',
                                              modifiers=dict(pre=recipient, topic=topic), payload=exn.ked)
                    ims = forwardHab.endorse(serder=fwd, last=True, pipelined=False)

                    # Attach pathed exn signature to end of message
                    atc = bytearray()
                    pather = coring.Pather(path=["a"])
                    atc.extend(pather.qb64b)
                    atc.extend(eattach)
                    ims.extend(coring.Counter(code=coring.CtrDex.PathedMaterialQuadlets,
                                              count=(len(atc) // 4)).qb64b)
                    ims.extend(atc)

                    httping.createCESRRequest(ims, client)

                    while not client.responses:
                        yield self.tock

                    self.remove([clientDoer])

                yield  # throttle just do one cue at a time
            yield

    def cueDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            Kevery and Tevery cues deque

        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.cues:  # iteratively process each cue in cues
                msg = bytearray()
                cue = self.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue

                if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                    serder = cue["serder"]  # Serder of received event for other pre
                    cuedKed = serder.ked
                    cuedPrefixer = coring.Prefixer(qb64=cuedKed["i"])
                    if cuedPrefixer.qb64 in self.hby.kevers:
                        kever = self.hby.kevers[cuedPrefixer.qb64]
                        owits = oset(kever.wits)
                        if match := owits.intersection(self.hby.prefixes):
                            pre = match.pop()
                            hab = self.hby.habs[pre]
                            msg.extend(hab.receipt(serder))
                            self.mbx.storeMsg(topic=serder.preb + b'/receipt', msg=msg)

                elif cueKin in ("replay",):
                    src = cue["src"]
                    dest = cue["dest"]
                    msgs = cue["msgs"]
                    hab = self.hby.habs[src]

                    if dest not in self.hby.kevers:
                        continue

                    kever = self.hby.kevers[dest]
                    owits = oset(kever.wits)

                    if owits.intersection(self.hby.prefixes):
                        bmsgs = bytearray(itertools.chain(*msgs))
                        self.mbx.storeMsg(topic=kever.prefixer.qb64b + b'/receipt', msg=bmsgs)

                    else:
                        events = list()
                        atc = bytearray()
                        for i, msg in enumerate(msgs):
                            evt = coring.Serder(raw=msg)
                            events.append(evt.ked)
                            pather = coring.Pather(path=["a", i])
                            btc = pather.qb64b + msg[evt.size:]
                            atc.extend(coring.Counter(code=coring.CtrDex.PathedMaterialQuadlets,
                                                      count=(len(btc) // 4)).qb64b)
                            atc.extend(btc)

                        fwd = exchanging.exchange(route='/fwd',
                                                  modifiers=dict(pre=dest, topic="replay"), payload=events)
                        msg = hab.endorse(fwd, last=True, pipelined=False)
                        msg.extend(atc)
                        wit = random.choice(kever.wits)
                        client, clientDoer = agenting.httpClient(hab, wit)
                        self.extend([clientDoer])

                        httping.createCESRRequest(msg, client)

                        while not client.responses:
                            yield self.tock

                        self.remove([clientDoer])

                elif cueKin in ("reply",):
                    src = cue["src"]
                    serder = cue["serder"]
                    route = cue["route"]
                    dest = cue["dest"]

                    if dest not in self.hby.kevers:
                        continue

                    kever = self.hby.kevers[dest]
                    owits = oset(kever.wits)
                    if match := owits.intersection(self.hby.prefixes):
                        pre = match.pop()
                        hab = self.hby.habs[pre]
                        msg.extend(hab.endorse(serder))
                        self.mbx.storeMsg(topic=serder.preb + b'/receipt', msg=msg)

                    else:
                        hab = self.hby.habs[src]
                        atc = hab.endorse(serder)
                        del atc[:serder.size]
                        self.postman.send(src=src, dest=dest, topic="reply", serder=serder, attachment=atc)

            yield self.tock
