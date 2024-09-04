# -*- encoding: utf-8 -*-
"""
keri.app.storing module

"""

from hio.base import doing
from hio.help import decking
from ordered_set import OrderedSet as oset

from . import forwarding
from .. import help
from ..core import coring, serdering
from ..core.coring import MtrDex
from ..db import dbing, subing

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

        Mailboxer uses two dbs for mailbox messages these are .tpcs and .msgs.
        The message index is in .tpcs (topics).
            Each .tpcs index key consists of topic.on where topic is bytes
                identifier or prefix/topic for message and on is serialized
                ordinal number to orders the appearance of a topic message.
            Eash .tpcs val is the digest of the message.
        The message itself is stored in .msgs where the key is the msg digest
            and the value is the serialized messag itself.
        Multiple messages can share the same topic but with a different ordinal.

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
        self.tpcs = subing.OnSuber(db=self, subkey='tpcs.')
        self.msgs = subing.Suber(db=self, subkey='msgs.')  # key states

        return self.env

    def delTopic(self, key, on=0):
        """Removes topic index from .tpcs without deleting message from .msgs

        Returns:
            result (boo): True if full key consisting of key and serialized on
                             exists in database so removed
                          False otherwise (not removed)
        """
        return self.tpcs.remOn(keys=key, on=on)

    def appendToTopic(self, topic, val):
        """Appends val to end of db entries with same topic but with on
        incremented by 1 relative to last preexisting entry at topic.

        Returns:
            on (int): order number int, on, of appended entry.
                      Computes on as next on after last entry.

        Parameters:
            topic (bytes):  topic identifier for message
            val (bytes): msg digest
        """
        return self.tpcs.appendOn(key=topic, val=val)


    def getTopicMsgs(self, topic, fn=0):
        """
        Returns:
            msgs (Iterable[bytes]): belonging to topic indices with same topic but all
                on >= fn i.e. all topic.on beginning with fn

         Parameters:
             topic (Option(bytes|str)): key prefix combined with serialized on
                    to form full actual key.  When key is empty then retrieves
                    whole database.
             fn (int): starting index ordinal number used with onKey(pre,on)
                    to form key at at which to initiate retrieval
        """
        msgs = []
        for keys, on, dig in self.tpcs.getOnItemIter(keys=topic, on=fn):
            if msg := self.msgs.get(keys=dig):
                msgs.append(msg.encode())  # want bytes not str
        return msgs


    def storeMsg(self, topic, msg):
        """
        Add exn event to mailbox topic and on that is 1 greater than last msg
        at topic.

        Returns:
            result (bool): True if msg successfully stored and indexed at topic
                           False otherwise

        Parameters:
            topic (str | bytes):  topic (Option(bytes|str)): key prefix combined
                with serialized on to form full actual key.
            msg (bytes): serialized message

        """
        if hasattr(msg, "encode"):
            msg = msg.encode("utf-8")

        digb = coring.Diger(ser=msg, code=MtrDex.Blake3_256).qb64b
        on = self.tpcs.appendOn(keys=topic, val=digb)
        return self.msgs.pin(keys=digb, val=msg)


    def cloneTopicIter(self, topic, fn=0):
        """
        Returns:
            triple (Iterator[(on, topic, msg): iterator of messages at topic
            beginning with ordinal fn.

        topic (Option(bytes|str)): key prefix combined with serialized on
                    to form full actual key.  When key is empty then retrieves
                    whole database.
             fn (int): starting index ordinal number used with onKey(pre,on)
                    to form key at at which to initiate retrieval



        ToDo looks like misuse of IoSet this should not be IoSet but simply
        Ordinal Numbered db.  since should not be using hidden ion has not
        hidden.

        """
        for keys, on, dig in self.tpcs.getOnItemIter(keys=topic, on=fn):
            if msg := self.msgs.get(keys=dig):
                yield (on, topic, msg.encode("utf-8"))



class Respondant(doing.DoDoer):
    """
    Respondant processes buffer of response messages from inbound 'exn' messages and
    routes them to the appropriate mailbox.  If destination has witnesses, send response to
    one of the (randomly selected) witnesses.  Otherwise store the response in the recipients
    mailbox locally.

    """

    def __init__(self, hby, reps=None, cues=None, mbx=None, aids=None, **kwa):
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
        self.aids = aids
        self.mbx = mbx if mbx is not None else Mailboxer(name=self.hby.name)
        self.postman = forwarding.Poster(hby=self.hby, mbx=self.mbx)

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

                senderHab = self.hby.habs[sender]
                if senderHab.mhab:
                    forwardHab = senderHab.mhab
                else:
                    forwardHab = senderHab

                # sign the exn to get the signature
                eattach = senderHab.endorse(exn, last=False, pipelined=False)
                del eattach[:exn.size]
                self.postman.send(recipient, topic=topic, serder=exn, hab=forwardHab, attachment=eattach)

                yield self.tock  # throttle just do one cue at a time

            yield self.tock

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
            while not self.cues:
                yield self.tock

            cue = self.cues.pull() # self.cues.popleft()
            cueKin = cue["kin"]  # type or kind of cue
            if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                serder = cue["serder"]  # Serder of received event for other pre
                cuedKed = serder.ked
                cuedPrefixer = coring.Prefixer(qb64=cuedKed["i"])

                # If respondant configured with list of acceptable AIDs to witness for, check them here
                if self.aids is not None and cuedPrefixer.qb64 not in self.aids:
                    continue

                if cuedPrefixer.qb64 in self.hby.kevers:
                    kever = self.hby.kevers[cuedPrefixer.qb64]
                    owits = oset(kever.wits)
                    if match := owits.intersection(self.hby.prefixes):
                        pre = match.pop()
                        hab = self.hby.habByPre(pre)
                        if hab is None:
                            continue

                        raw = hab.receipt(serder)
                        rserder = serdering.SerderKERI(raw=raw)
                        del raw[:rserder.size]
                        self.postman.send(serder.pre, topic="receipt", serder=rserder, hab=hab, attachment=raw)

            elif cueKin in ("replay",):
                src = cue["src"]
                dest = cue["dest"]
                msgs = cue["msgs"]

                hab = self.hby.habByPre(src)
                if hab is None:
                    continue

                if dest not in self.hby.kevers:
                    continue

                for msg in msgs:
                    raw = bytearray(msg)
                    serder = serdering.SerderKERI(raw=raw)
                    del raw[:serder.size]
                    self.postman.send(dest, topic="replay", serder=serder, hab=hab, attachment=raw)

            elif cueKin in ("reply",):
                src = cue["src"]
                serder = cue["serder"]

                dest = cue["dest"]

                if dest not in self.hby.kevers:
                    continue

                hab = self.hby.habByPre(src)
                if hab is None:
                    continue

                atc = hab.endorse(serder)
                del atc[:serder.size]
                self.postman.send(hab=hab, dest=dest, topic="reply", serder=serder, attachment=atc)

            else:
                self.cues.push(cue)

            yield self.tock
