# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""

from datetime import timedelta

from hio.base import doing
from hio.help import decking

from .. import help
from ..core import eventing, coring
from ..core.coring import MtrDex
from ..db import subing, dbing
from ..help import helping
from ..kering import ValidationError, MissingSignatureError, MissingDestinationError, AuthZError, ExchangeError

ExchangeMessageTimeWindow = timedelta(seconds=1010000)

logger = help.ogler.getLogger()


class Exchanger(doing.DoDoer):
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, hab, handlers, controller=None, cues=None, delta=ExchangeMessageTimeWindow, **kwa):
        """
        Initialize instance

        Parameters:
            hab (Habitat): instance of local controller's context
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        self.hab = hab
        self.controller = controller
        self.kevers = hab.kvy.kevers
        self.delta = delta
        self.routes = dict()
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque

        doers = []
        for handler in handlers:
            if handler.resource in self.routes:
                raise ValidationError("unable to register behavior {}, it has already been registered"
                                      "".format(handler.resource))

            self.routes[handler.resource] = handler
            doers.append(handler)

        super(Exchanger, self).__init__(doers=doers, **kwa)

    def processEvent(self, serder, source, sigers):
        """
        Process one serder event with attached indexed signatures representing
        a Peer to Peer exchange message.

        Parameters:
            serder (Serder) instance of event to process
            source (Prefixer) identifier prefix of event sender
            sigers (list) of Siger instances of attached controller indexed sigs

        """

        route = serder.ked["r"]
        payload = serder.ked["d"]
        dts = serder.ked["dt"]

        if route not in self.routes:
            raise AttributeError("unregistered route {} for exchange message = {}"
                                 "".format(route, serder.pretty()))

        behavior = self.routes[route]

        # delta = behavior.delta if behavior.delta is not None else self.delta
        delta = self.delta
        msgDt = helping.fromIso8601(dts)
        now = helping.nowUTC()

        if now - msgDt > delta:
            raise ValidationError("message received outside time window with delta {} message={}"
                                  "".format(delta, serder.pretty()))

        sever = self.kevers[source.qb64]

        if self.controller is not None and self.controller != source.qb64:
            raise AuthZError("Message {} is from invalid source {}"
                             "".format(payload, source.qb64))

        #  Verify provided sigers using verfers
        sigers, indices = eventing.verifySigs(serder=serder, sigers=sigers, verfers=sever.verfers)
        if not sever.tholder.satisfy(indices):  # at least one but not enough
            self.escrowPSEvent(serder=serder, sigers=sigers)
            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                        " for evt = {}.".format(sever.tholder.sith,
                                                                [siger.qb64 for siger in sigers],
                                                                serder.ked))

        msg = dict(
            payload=payload,
            pre=source,
            sigers=sigers,
            verfers=sever.verfers,
        )

        behavior.msgs.append(msg)

    def processResponseIter(self):
        """
        Iterate through cues and yields one or more responses for each cue.

        Parameters:
            cues is deque of cues

        """
        responses = []
        for _, behavior in self.routes.items():  # get responses from all behaviors
            while behavior.cues:
                excSrdr = behavior.cues.popleft()
                msg = self.hab.sanction(excSrdr)
                responses.append(dict(dest=excSrdr.ked["i"], msg=msg))

        while responses:  # iteratively process each response in responses
            msg = responses.pop(0)
            yield msg

    def escrowPSEvent(self, serder, sigers):
        """
        Escrow event that does not have enough signatures.

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controller sigs
        """
        pass


def exchange(route, payload, recipient=None, date=None, modifiers=None, version=coring.Version,
             kind=coring.Serials.json):
    """
    Create an `exn` message with the specified route and payload
    Parameters:
        route (string) to destination route of the message
        payload (dict) body of message to deliver to route
        recipient (str) qb64 identifier prefix of target of message
        date (str) Iso8601 formatted date string to use for this request
        modifiers (dict) equivalent of query string of uri, modifiers for the request that are not
                         part of the payload
        version (Version) is Version instance
        kind (Serials) is serialization kind

    """
    vs = coring.Versify(version=version, kind=kind, size=0)
    ilk = eventing.Ilks.exn
    dt = date if date is not None else helping.nowIso8601()

    ked = dict(v=vs,
               t=ilk,
               i=recipient,
               dt=dt,
               r=route,
               d=payload,
               q=modifiers
               )

    if recipient is None:
        del ked["i"]

    if modifiers is None:
        del ked["q"]

    return eventing.Serder(ked=ked)  # return serialized ked


class StoreExchanger:
    """
    StoreExchanger receives exn messages and stores them indexed by prefix identifier of the target.

    """

    def __init__(self, hab, mbx=None, exc=None):
        self.hab = hab
        self.kevers = self.hab.kevers
        self.db = mbx if mbx is not None else Mailboxer(name=hab.name)
        self.exc = exc if exc is not None else Exchanger(hab=hab, handlers=[])


    @property
    def routes(self):
        return self.exc.routes

    def processEvent(self, serder, source, sigers):
        """
        Process one serder event with attached indexed signatures representing
        a Peer to Peer exchange message.

        Parameters:
            serder (Serder) instance of event to process
            source (Prefixer) identifier prefix of event sender
            sigers (list) of Siger instances of attached controller indexed sigs

        """

        sever = self.kevers[source.qb64]

        #  Verify provided sigers using verfers
        sigers, indices = eventing.verifySigs(serder=serder, sigers=sigers, verfers=sever.verfers)
        if not sever.tholder.satisfy(indices):  # at least one but not enough
            self.escrowPSEvent(serder=serder, source=source, sigers=sigers)
            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                        " for evt = {}.".format(sever.tholder.sith,
                                                                [siger.qb64 for siger in sigers],
                                                                serder.ked))
        if "i" not in serder.ked:
            raise MissingDestinationError("Failure saving evt = {} from = {} in mailbox, missing destination"
                                          "".format(serder.ked, source.qb64))

        if serder.pre == self.hab.pre:
            self.exc.processEvent(serder=serder, source=source, sigers=sigers)
        elif self.hab.pre in sever.wits:
            dest = eventing.Prefixer(qb64=serder.pre)
            msg = self._reconstruct(serder=serder, source=source, sigers=sigers)
            self.db.storeMsg(dest=dest.qb64b, msg=msg)
        else:
            raise ExchangeError("Event recipient {} is neither this witness {} nor a prefix for whom this"
                                "witness is a witness {}".format(serder.pre, self.hab.pre, sever.wits))

    def processResponseIter(self):
        yield from self.exc.processResponseIter()

    def escrowPSEvent(self, serder, source, sigers):
        """
        Escrow event that does not have enough signatures.

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controller sigs
        """
        pass


    @staticmethod
    def _reconstruct(serder, source, sigers):
        msg = bytearray()  # message

        msg.extend(serder.raw)

        msg.extend(coring.Counter(coring.CtrDex.SignerSealCouples, count=1).qb64b)
        msg.extend(source.qb64b)

        if sigers:
            msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers)).qb64b)

            for sig in sigers:
                msg.extend(sig.qb64b)
        return msg



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
            dirMode:
            reopen:
            kwa:
        """
        self.fels = None
        self.msgs = None

        super(Mailboxer, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """

        :param kwa:
        :return:
        """
        super(Mailboxer, self).reopen(**kwa)

        self.fels = self.env.open_db(key=b'fels.')
        self.msgs = subing.Suber(db=self, subkey='msgs.')  # key states

        return self.env

    def delFe(self, key):
        """
        Use snKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.fels, key)

    def appendFe(self, pre, val):
        """
        Return first seen order number int, fn, of appended entry.
        Computes fn as next fn after last entry.
        Uses fnKey(pre, fn) for entries.

        Append val to end of db entries with same pre but with fn incremented by
        1 relative to last preexisting entry at pre.

        Parameters:
            pre is bytes identifier prefix for event
            val is event digest
        """
        return self.appendOrdValPre(db=self.fels, pre=pre, val=val)

    def _getFelItemPreIter(self, pre, fn=0):
        """
        Returns iterator of all (fn, dig) duples in first seen order for all events
        with same prefix, pre, in database. Items are sorted by fnKey(pre, fn)
        where fn is first seen order number int.
        Returns a First Seen Event Log FEL.
        Returned items are duples of (fn, dig): Where fn is first seen order
        number int and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0
        """
        return self.getAllOrdItemPreIter(db=self.fels, pre=pre, on=fn)

    def getFelItemAllPreIter(self, key=b''):
        """
        Returns iterator of all (pre, fn, dig) triples in first seen order for
        all events for all prefixes in database. Items are sorted by
        fnKey(pre, fn) where fn is first seen order number int.
        Returns all First Seen Event Logs FELs.
        Returned items are tripes of (pre, fn, dig): Where pre is identifier prefix,
        fn is first seen order number int and dig is event digest for lookup
        in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            key is key location in db to resume replay, If empty then start at
                first key in database
        """
        return self.getAllOrdItemAllPreIter(db=self.fels, key=key)


    def storeMsg(self, dest, msg):
        """
        Add exn event to mailbox of dest identifier

        Parameters:
            msg (bytes):
            dest (qb64b):

        """
        if hasattr(dest, "encode"):
            dest = dest.encode("utf-8")

        if hasattr(msg, "encode"):
            msg = msg.encode("utf-8")

        digb = coring.Diger(ser=msg, code=MtrDex.Blake3_256).qb64b
        self.appendFe(dest, digb)
        self.msgs.pin(keys=digb, val=msg)


    def clonePreIter(self, pre, fn=0):
        """
        Returns iterator of first seen exn messages with attachments for the
        identifier prefix pre starting at first seen order number, fn.

        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for fn, dig in self._getFelItemPreIter(pre, fn=fn):
            if msg := self.msgs.get(keys=dig):
                yield fn, msg

