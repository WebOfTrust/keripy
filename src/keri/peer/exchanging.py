# -*- encoding: utf-8 -*-
"""
keri.peer.exchanging module

"""

from datetime import timedelta

from hio.base import doing

from .. import kering
from ..core import eventing, coring
from ..db import subing, dbing
from ..help import decking, helping
from ..kering import ValidationError, MissingSignatureError, MissingDestinationError

ExchangeMessageTimeWindow = timedelta(seconds=1010)


class Exchanger(doing.DoDoer):
    """
     Peer to Peer KERI message Exchanger.
    """

    def __init__(self, hab, cues=None, delta=ExchangeMessageTimeWindow, **kwa):
        """
        Initialize instance

        Parameters:
            hab (Habitat): instance of local controller's context
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window
        """

        super(Exchanger, self).__init__(doers=[], **kwa)

        self.hab = hab
        self.kevers = hab.kvy.kevers
        self.delta = delta
        self.routes = dict()
        self.cues = cues if cues is not None else decking.Deck()  # subclass of deque


    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Exchanger, self).wind(tymth)


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
        payload = serder.ked["q"]
        dts = serder.ked["dt"]

        behavior = self.routes[route]
        if behavior is None:
            raise AttributeError("unregistered route {} for exchange message = {}"
                                 "".format(route, serder.pretty()))

        delta = behavior.delta if behavior.delta is not None else self.delta
        msgDt = helping.fromIso8601(dts)
        now = helping.nowUTC()

        if now - msgDt > delta:
            raise ValidationError("message received outside time window with delta {} message={}"
                                  "".format(delta, serder.pretty()))


        msg = dict(
            source=source,
            payload=payload,
            serder=serder,
            sigers=sigers,
        )

        behavior.msgs.append(msg)


    def registerBehavior(self, route, behave):
        """
        Creates and registers a behavior for the specified route that
        executes the provide func.  The func needs to have the following
        signature:

           func(payload, pre, sigers, verfers)

        func must return a route and return message if a response is required
        or (None, None)


        Parameters:
            route (string) is the route to register
            behave (Behavior) is the code to execute for this behavior
        """

        if route in self.routes:
            return ValidationError("unable to register behavior {}, it has already been registered"
                                   "".format(route))

        behave.exc = self
        self.routes[route] = behave


    def enter(self, doers=None):
        doers = list(doers) if doers is not None else []
        for route, behavior in self.routes.items():
            doers.extend([behavior.msgDo])

        super(Exchanger, self).enter(doers)



    def processMsgsIter(self, msgs):
        """
        Loop over msgs processing them one at a time.  Verifies signatures against the
        current signing keys of the controller of pre, the identifier prefix

        Parameters:
            msgs (list) of incoming messages to process
        """
        while msgs:
            msg = msgs.popleft()
            #  load the signers kever

            pre = msg['source']
            payload = msg['payload']
            serder = msg['serder']
            sigers = msg['sigers']

            sever = self.kevers[pre.qb64]

            #  Verify provided sigers using verfers
            sigers, indices = eventing.verifySigs(serder=serder, sigers=sigers, verfers=sever.verfers)
            if not sever.tholder.satisfy(indices):  # at least one but not enough
                self.escrowPSEvent(serder=serder, sigers=sigers)
                raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                            " for evt = {}.".format(sever.tholder.sith,
                                                                    [siger.qb64 for siger in sigers],
                                                                    serder.ked))

            yield payload, pre, sigers, sever.verfers


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
                responses.append(msg)


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


class Behavior:
    """
    A Behavior encapsulates the execution environment for an exchange message endpoint.


    """

    def __init__(self, func, cues=None, delta=None):
        """
        Creates a behavior for that executes the provide func.  The func needs
        to have the following signature:

           func(payload, pre, sigers, verfers)

        func must return a route and return payload if a response is required
        or (None, None)

        Parameters:
            func (function) code to execute when messages arrive for this behavior
            cues (Deck):  of Cues i.e. notices of requests needing response
            delta (timedelta): message timeout window for this behavior.  Orderrides
              delta for Exchanger


        """
        self.msgs = decking.Deck()
        self.delta = delta
        self.cues = cues if cues is not None else decking.Deck()
        self.func = func


    @property
    def exc(self):
        return self._exc

    @exc.setter
    def exc(self, exc):
        self._exc = exc


    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .msgs deque

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters

        Usage:
            add to doers list
        """
        while True:
            for payload, pre, sigers, verfers in self._exc.processMsgsIter(self.msgs):
                rr, resp = self.func(payload, pre, sigers, verfers)
                if rr is not None:
                    self.cueResponse(rr, resp)
                yield  # throttle just do one msg at a time
            yield
        return False  # should never get here except forced close


    def cueResponse(self, rr, resp):
        """
        Create a response message from the response of a behavior,
        signs it and cues it for return

        Parameters:
              rr (string) is the return route for the response
              resp (dict) is the response payload
        """

        excSrdr = exchange(route=rr, payload=resp)
        self.cues.append(excSrdr)



def exchange(route, payload, recipient=None, date=None, version=coring.Version, kind=coring.Serials.json):
    """
    Create an `exn` message with the specified route and payload
    Parameters:
        route (string) to destination route of the message
        payload (dict) body of message to deliver to route
        recipient (str) qb64 identifier prefix of target of message
        date (str) Iso8601 formatted date string to use for this request
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
               q=payload
               )

    if recipient is None:
        del ked["i"]

    return eventing.Serder(ked=ked)  # return serialized ked


class StoreExchanger:
    """
    StoreExchanger receives exn messages and stores them indexed by prefix identifier of the target.

    """

    def __init__(self, hab, mbx=None):
        self.hab = hab
        self.kevers = self.hab.kevers
        self.db = mbx if mbx is not None else Mailboxer()


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
            self.escrowPSEvent(serder=serder, sigers=sigers)
            raise MissingSignatureError("Failure satisfying sith = {} on sigs for {}"
                                        " for evt = {}.".format(sever.tholder.sith,
                                                                [siger.qb64 for siger in sigers],
                                                                serder.ked))
        if "i" not in serder.ked:
            raise MissingDestinationError("Failure saving evt = {} from = {} in mailbox, missing destination"
                                          "".format(serder.ked, source.qb64))

        dest = eventing.Prefixer(qb64=serder.pre)

        self.db.storeEvent(serder, source, dest, sigers)


    @staticmethod
    def processResponseIter():
        return []


    def escrowPSEvent(self, serder, sigers):
        """
        Escrow event that does not have enough signatures.

        Parameters:
            serder is Serder instance of event
            sigers is list of Siger instances of indexed controller sigs
        """
        pass



class Mailboxer(dbing.LMDBer):
    """
    Mailboxer stores exn messages in order and provider iterator access at an index.


    """
    TailDirPath = "keri/mbx"
    AltTailDirPath = ".keri/mbx"
    TempPrefix = "keri_mbx_"

    def __init__(self, headDirPath=None, reopen=True, **kwa):
        """

        Parameters:
            headDirPath:
            dirMode:
            reopen:
            kwa:
        """
        self.fels = None
        self.exns = None
        self.sigs = None
        self.srcs = None

        super(Mailboxer, self).__init__(headDirPath=headDirPath, reopen=reopen, **kwa)



    def reopen(self, **kwa):
        """

        :param kwa:
        :return:
        """
        super(Mailboxer, self).reopen(**kwa)

        self.fels = self.env.open_db(key=b'fels.')
        self.exns = subing.SerderSuber(db=self, subkey='exns.')  # key states
        self.sigs = self.env.open_db(key=b'sigs.', dupsort=True)
        self.srcs = subing.MatterSuber(db=self, subkey='srcs.', klas=coring.Prefixer)

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


    def putSigs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes receipt couplets vals to key
        Couple is pre+cig (non indexed signature)
        Adds to existing receipts at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.sigs, key, vals)


    def getSigs(self, key):
        """
        Use dgKey()
        Return list of receipt couplets at key
        Couple is pre+cig (non indexed signature)
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.sigs, key)


    def delSigs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.sigs, key, val)


    def storeEvent(self, serder, source, dest, sigers):
        """
        Add exn event to mailbox of dest identifier

        Parameters:
            serder:
            source (Prefixer):
            dest (Prefixer):
            sigers:

        """


        self.appendFe(dest.qb64b, serder.digb)
        self.exns.pin(keys=serder.digb, val=serder)
        self.srcs.pin(keys=serder.digb, val=source)
        if sigers:
            self.putSigs(serder.digb, [siger.qb64b for siger in sigers])  # idempotent


    def clonePreIter(self, pre, fn=0):
        """
        Returns iterator of first seen exn messages with attachments for the
        identifier prefix pre starting at first seen order number, fn.

        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for fn, dig in self._getFelItemPreIter(pre, fn=fn):
            try:
                msg = self.cloneEvtMsg(dig=dig)
            except Exception as e:
                print(e)
                continue  # skip this event
            yield msg


    def cloneEvtMsg(self, dig):
        """
        Clones Event as Serialized CESR Message with Body and attached Foot

        Parameters:
            dig (bytes): digest of event

        Returns:
            bytearray: message body with attachments
        """
        msg = bytearray()  # message

        if not (serder := self.exns.get(keys=dig)):
            raise kering.MissingEntryError("Missing event for dig={}.".format(dig))
        msg.extend(serder.raw)

        if not (pre := self.srcs.get(keys=dig)):
            raise kering.MissingEntryError("Missing source for dig={}.".format(dig))

        msg.extend(coring.Counter(coring.CtrDex.SignerSealCouples, count=1).qb64b)
        msg.extend(pre.qb64b)

        # add indexed signatures to attachments
        if not (sigs := self.getSigs(key=dig)):
            raise kering.MissingEntryError("Missing sigs for dig={}.".format(dig))
        msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigs)).qb64b)
        for sig in sigs:
            msg.extend(sig)

        return msg
