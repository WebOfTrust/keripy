# -*- encoding: utf-8 -*-
"""
keri.app.storing module

"""
import random
from urllib.parse import urlparse

from hio.base import doing
from hio.core import http
from hio.help import decking, helping, Hict
from orderedset import OrderedSet as oset

from . import forwarding, httping
from .. import help, kering
from ..core import coring
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
             topic (bytes): Apparent effective key
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


class MailEnd(doing.DoDoer):
    """
    Message storage for Witnesses.  Provides an inbox service for storing messages for an identifier.

    """

    def __init__(self, mbx: Mailboxer, **kwa):
        """
        Create Mailbox server for storing messages on a Witness for a witnessed
        identifier.

        Parameters:
            mbx (Mailboxer): message storage for store and forward

        """

        self.mbx = mbx
        doers = []

        super(MailEnd, self).__init__(doers=doers, **kwa)

    def on_get(self, req, rep):
        """
        Handles GET requests as a stream of SSE events

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        pre = req.params["i"]
        pt = req.params["topics"]

        topics = dict()
        for t in pt:
            key, val = t.split("=")
            topics[key] = int(val)

        rep.stream = self.mailboxGenerator(pre=pre, topics=topics, resp=rep)

    def on_post(self, req, rep):
        """
        Handles GET requests as a stream of SSE events

        Parameters:
              req (Request) Falcon HTTP request
              rep (Response) Falcon HTTP response

        """
        cr = httping.parseCesrHttpRequest(req=req)

        query = cr.payload['q']
        topics = query['topics']
        pre = query["pre"]

        rep.stream = self.mailboxGenerator(pre=pre, topics=topics, resp=rep)

    @helping.attributize
    def mailboxGenerator(self, me, pre=None, topics=None, resp=None):
        """

        Parameters:
            me:
            pre:
            topics:
            resp:

        """
        me._status = http.httping.OK

        headers = Hict()
        headers['Content-Type'] = "text/event-stream"
        headers['Cache-Control'] = "no-cache"
        headers['Connection'] = "keep-alive"
        me._headers = headers

        yield b'retry: 1000\n'
        while True:
            for topic, idx in topics.items():
                key = pre + topic
                for fn, _, msg in self.mbx.cloneTopicIter(key, idx):
                    data = bytearray("id: {}\nevent: {}\ndata: ".format(fn, topic).encode("utf-8"))
                    data.extend(msg)
                    data.extend(b'\n\n')
                    idx = idx + 1
                    yield data
                topics[topic] = idx

            yield b''


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

        doers = [doing.doify(self.responseDo), doing.doify(self.cueDo)]
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
                # TODO: ADD SENDER TO ALL EXN RESPONSES
                sender = rep["sender"]
                recipient = rep["dest"]
                exn = rep["rep"]
                topic = rep["topic"]

                kever = self.hby.kevers[recipient]
                if kever is None:
                    logger.Error("unable to reply, dest {} not found".format(recipient))
                    continue

                hab = self.hby.habs[sender]
                if len(kever.wits) == 0:
                    msg = hab.endorse(exn, last=True)
                    self.mbx.storeMsg(topic=recipient, msg=msg)
                else:
                    wit = random.choice(kever.wits)
                    urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http)
                    if not urls:
                        raise kering.ConfigurationError(f"unable to query witness {wit}, no http endpoint")

                    up = urlparse(urls[kering.Schemes.http])
                    client = http.clienting.Client(hostname=up.hostname, port=up.port)
                    clientDoer = http.clienting.ClientDoer(client=client)

                    self.extend([clientDoer])

                    fwd = forwarding.forward(pre=recipient, serder=exn, topic=topic)
                    msg = bytearray(fwd.raw)
                    atc = hab.endorse(exn, last=True)
                    del atc[:exn.size]
                    msg.extend(atc)

                    httping.createCESRRequest(msg, client, date=exn.ked["dt"])

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
                            self.mbx.storeMsg(topic=serder.preb+b'/receipt', msg=msg)

                elif cueKin in ("replay",):
                    dest = cue["dest"]
                    msgs = cue["msgs"]

                    self.mbx.storeMsg(topic=dest+'/replay', msg=msgs)
                elif cueKin in ("reply", ):
                    data = cue["data"]
                    route = cue["route"]
                    dest = cue["dest"]

                    msg = hab.reply(data=data, route=route+"/"+hab.pre)
                    self.mbx.storeMsg(topic=dest+"/replay", msg=msg)

                yield self.tock

            yield self.tock
