# -*- encoding: utf-8 -*-
"""
KERI
keri.base.directing module

simple direct mode demo support classes
"""
import os
import json

from hio.base import doing, tyming
from hio.core import wiring
from hio.core.tcp import clienting, serving

from .. import kering
from ..db import dbing
from ..core import coring, eventing
from . import keeping

from .. import help

logger = help.ogler.getLogger()


def setupController(name="who", sith=None, count=1, temp=False,
                    remotePort=5621, localPort=5620):
    """
    Setup and return doers list to run controller
    """
    # setup habitat
    hab = Habitat(name=name, sith=sith, count=count, temp=temp)
    logger.info("\nDirect Mode controller %s:\nNamed %s on TCP port %s to port %s.\n\n",
                 hab.pre, hab.name, localPort, remotePort)

    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)   # doer do reopens if not opened and closes
    dbDoer = dbing.BaserDoer(baser=hab.db)   # doer do reopens if not opened and closes

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')

    wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='keri',
                        reopen=True, headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)

    client = clienting.Client(host='127.0.0.1', port=remotePort, wl=wl)
    clientDoer = doing.ClientDoer(client=client)
    director = Director(hab=hab, client=client, tock=0.125)
    reactor = Reactor(hab=hab, client=client)

    server = serving.Server(host="", port=localPort, wl=wl)
    serverDoer = doing.ServerDoer(server=server)
    directant = Directant(hab=hab, server=server)
    # Reactants created on demand by directant

    return [ksDoer, dbDoer, wireDoer, clientDoer, director, reactor, serverDoer, directant]


class Habitat():
    """
    Habitat class provides direct mode controller's local shared habitat
       e.g. context or environment

    Attributes:
        .name is str alias of controller
        .transferable is Boolean True means pre is transferable (default)
                    False means pre is nontransferable
        .temp is Boolean True for testing it modifies tier of salty key
            generation algorithm and persistence of db and ks
        .erase is Boolean, If True erase old private keys, Otherwise not.
        .ks is lmdb key store keeping.Keeper instance
        .mgr is keeping.Manager instance
        .ridx is int rotation index (inception == 0)
        .kevers is dict of eventing.Kever(s) keyed by qb64 prefix
        .db is lmdb data base dbing.Baser instance
        .kvy is eventing.Kevery instance for local processing of local msgs
        .sith is default key signing threshold
        .count is number public keys in key list
        .ncount is number of public keys in next key list
        .inception is Serder of inception event
        .pre is qb64 prefix of local controller

    Properties:
        .kever is Kever instance of key state of local controller

    """

    def __init__(self, name='test', ks=None, db=None, kevers=None,
                 code=coring.MtrDex.Blake3_256, secrecies=None,
                 sith=None, count=1, ncount=None, salt=None, tier=None,
                 transferable=True, temp=False, erase=True):
        """
        Initialize instance.

        Parameters:
            name is str alias name for local controller of habitat
            ks is keystore lmdb Keeper instance
            db is database lmdb Baser instance
            kevers is dict of Kever instance keyed by qb64 prefix
            code is prefix derivation code
            secrecies is list of list of secrets to preload key pairs if any
            sith is str (hex) of signing threshold int or list expression for
                    for fractionally weighted signing threshold
            count is key count for number of keys
            salt is qb64 salt for creating key pairs
            tier is security tier for generating keys from salt
            transferable is Boolean True means pre is transferable (default)
                    False means pre is nontransferable
            temp is Boolean used for persistance of lmdb ks and db directories
                and mode for key generation
            erase is Boolean True means erase private keys once stale
        """
        self.name = name
        self.transferable = transferable
        self.temp = temp
        self.erase = erase

        self.ks = ks if ks is not None else keeping.Keeper(name=name,
                                                           temp=self.temp)
        if salt is None:
            salt = coring.Salter(raw=b'0123456789abcdef').qb64
        self.mgr = keeping.Manager(keeper=self.ks, salt=salt, tier=tier)
        self.ridx = 0  # rotation index of latest establishment event
        self.kevers = kevers if kevers is not None else dict()
        self.db = db if db is not None else dbing.Baser(name=name,
                                                        temp=self.temp)
        self.sith = sith
        self.count = count
        if not self.transferable:
            self.ncount = 0
            code = coring.MtrDex.Ed25519N
        else:
            self.ncount = ncount if ncount is not None else self.count

        if secrecies:
            verferies, digers = self.mgr.ingest(secrecies,
                                                ncount=self.ncount,
                                                stem=self.name,
                                                transferable=self.transferable,
                                                temp=self.temp)
            opre = verferies[0][0].qb64  # old pre default needed for .replay
            verfers, digers = self.mgr.replay(pre=opre, ridx=self.ridx)
        else:
            verfers, digers = self.mgr.incept(icount=self.count,
                                              ncount=self.ncount,
                                              stem=self.name,
                                              transferable=self.transferable,
                                              temp=self.temp)

        opre = verfers[0].qb64  # old pre default move below to new pre from incept
        if digers:
            nxt = coring.Nexter(sith=self.sith,
                                digs=[diger.qb64 for diger in digers]).qb64
        else:
            nxt = ""

        self.iserder = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                         sith=self.sith,
                                         nxt=nxt,
                                         code=code)

        self.pre = self.iserder.ked["i"]  # new pre
        self.mgr.move(old=opre, new=self.pre)

        self.kvy = eventing.Kevery(kevers=self.kevers, db=self.db, framed=True,
                                   opre=self.pre, local=True)

        sigers = self.mgr.sign(ser=self.iserder.raw, verfers=verfers)
        msg = eventing.messagize(self.iserder, sigers=sigers)
        self.kvy.processOne(ims=msg)
        if self.pre not in self.kevers:
            raise kering.ConfigurationError("Improper Habitat inception for "
                                            "pre={}.".format(self.pre))

    @property
    def kever(self):
        """
        Returns kever for its .pre
        """
        return self.kevers[self.pre]


    def incept(self):
        """
        Perform inception operation. Register inception in database.
        Returns: bytearray inception message with attached signatures.
        """


    def rotate(self, sith=None, count=None, erase=None):
        """
        Perform rotation operation. Register rotation in database.
        Returns: bytearrayrotation message with attached signatures.
        """
        if sith is not None:
            self.sith = sith
        count = count if count is not None else self.ncount
        erase = erase if erase is not None else self.erase

        try:
            verfers, digers = self.mgr.replay(pre=self.pre,
                                              ridx=self.ridx+1,
                                              erase=erase)

        except IndexError as ex:
            verfers, digers = self.mgr.rotate(pre=self.pre,
                                              count=count,
                                              temp=self.temp,
                                              erase=erase)

        kever = self.kever  # kever.pre == self.pre
        if digers:
            nxt = coring.Nexter(sith=self.sith,
                                    digs=[diger.qb64 for diger in digers]).qb64
        else:
            nxt = ""

        serder = eventing.rotate(pre=kever.prefixer.qb64,
                                 keys=[verfer.qb64 for verfer in verfers],
                                 dig=kever.serder.diger.qb64,
                                 sith=self.sith,
                                 nxt=nxt,
                                 sn=kever.sn+1)
        sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
        msg = eventing.messagize(serder, sigers=sigers)

        # update ownkey event verifier state
        self.kvy.processOne(ims=bytearray(msg))  # make copy as kvr deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat rotation for "
                                         "pre={}.".format(self.pre))

        self.ridx += 1  # successful rotate so increment for next time
        return msg


    def interact(self):
        """
        Perform interaction operation. Register interaction in database.
        Returns: bytearray interaction message with attached signatures.
        """
        kever = self.kever
        serder = eventing.interact(pre=kever.prefixer.qb64,
                                   dig=kever.serder.diger.qb64,
                                   sn=kever.sn+1)

        sigers = self.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        msg = eventing.messagize(serder, sigers=sigers)

        # update ownkey event verifier state
        self.kvy.processOne(ims=bytearray(msg))  # make copy as kvy deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat interaction for "
                                         "pre={}.".format(self.pre))

        return msg


    def chit(self, serder):
        """
        Returns own chit, vrc, message of serder with count code and signatures
        Builds msg and then processes it into own db to validate.
        """
        # create seal of own last est event
        seal = eventing.SealEvent(i=self.pre,
                                  s="{:x}".format(self.kever.lastEst.s),
                                  d=self.kever.lastEst.d)
        ked = serder.ked
        # create validator receipt for serder event
        reserder = eventing.chit(pre=ked["i"],
                                 sn=int(ked["s"], 16),
                                 dig=serder.dig,
                                 seal=seal)
        # sign serder event
        sigers = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=True)
        msg = eventing.messagize(serder=reserder, sigers=sigers)
        self.kvy.processOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def receipt(self, serder):
        """
        Returns own receipt, rct, message of serder with count code and receipt
        couples (pre+cig)
        Builds msg and then processes it into own db to validate
        """
        if self.kever.prefixer.transferable:  # not non-transferable prefix
            raise ValueError("Attempt to create non-transferable receipt with"
                             " transferable pre={}.".format(self.pre))
        ked = serder.ked
        reserder = eventing.receipt(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    dig=serder.dig)
        # sign serder event
        cigars = self.mgr.sign(ser=serder.raw,
                               verfers=self.kever.verfers,
                               indexed=False)
        msg = eventing.messagize(reserder, cigars=cigars)
        self.kvy.processOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def witness(self, serder):
        """
        Returns own receipt, rct, message of serder with count code and witness
        indexed receipt signatures if key state of serder.pre shows that own pre
        is a current witness of event in serder
        """
        if self.kever.prefixer.transferable:  # not non-transferable prefix
            raise ValueError("Attempt to create witness receipt with"
                             " transferable pre={}.".format(self.pre))
        ked = serder.ked

        if serder.pre not in self.kvy.kevers:
            raise ValueError("Attempt by {} to witness event with missing key "
                             "state.".format(self.pre))
        kever = self.kvy.kevers[serder.pre]
        if self.pre not in kever.wits:
            raise ValueError("Attempt by {} to witness event of {} when not a "
                             "witness in wits={}.".format(self.pre,
                                                          serder.pre,
                                                          kever.wits))
        index = kever.wits.index(self.pre)

        reserder = eventing.receipt(pre=ked["i"],
                                    sn=int(ked["s"], 16),
                                    dig=serder.dig)
        # sign serder event
        wigers = self.mgr.sign(ser=serder.raw,
                               pubs=[self.pre],
                               indices=[index])

        msg = eventing.messagize(reserder, wigers=wigers, pipelined=True)
        self.kvy.processOne(ims=bytearray(msg))  # process local copy into db
        return msg


    def endorse(self, serder):
        """
        Returns msg with own endorsement of msg from serder with attached signature
        groups based on own pre transferable or non-transferable.
        Useful for endorsing key state message when provided via serder from
        Kever.state()
        Future add support for processing into db once have support for storing
           key state in db.
        """
        if self.kever.prefixer.transferable:
            # create SealEvent for endorsers est evt whose keys use to sign
            seal = eventing.SealEvent(i=self.kever.prefixer.qb64,
                             s=self.kever.lastEst.sn,
                             d=self.kever.lastEst.dig)
            # sign serder event
            sigers = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=True)
            msg = eventing.messagize(serder=serder,
                                     sigers=sigers,
                                     seal=seal,
                                     pipelined=True)

        else:
            # sign serder event
            cigars = self.mgr.sign(ser=serder.raw,
                                   verfers=self.kever.verfers,
                                   indexed=False)
            msg = eventing.messagize(serder=serder,
                                     cigars=cigars,
                                     pipelined=True)

        return msg


    def replay(self, pre=None, fn=0):
        """
        Returns replay of FEL first seen event log for pre starting from fn
        Default pre is own .pre

        Parameters:
            pre is qb64 str or bytes of identifier prefix.
                default is own .pre
            fn is int first seen ordering number

        """
        if not pre:
            pre = self.pre
        msgs = bytearray()
        for msg in self.db.cloneIter(pre=pre, fn=fn):
            msgs.extend(msg)
        return msgs


    def makeOwnEvent(self, sn):
        """
        Returns: messagized bytearray message with attached signatures of
                 own event at sequence number sn from retrieving event at sn
                 and associated signatures from database.

        Parameters:
            sn is int sequence number of event
        """
        msg = bytearray()
        dig = self.db.getKeLast(dbing.snKey(self.pre, sn))
        if dig is None:
            raise kering.MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(self.pre, sn))
        dig = bytes(dig)
        key = dbing.dgKey(self.pre, dig)  # digest key
        msg.extend(self.db.getEvt(key))
        msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=self.db.cntSigs(key)).qb64b) # attach cnt
        for sig in self.db.getSigsIter(key):
            msg.extend(sig) # attach sig
        return (msg)


    def makeOwnInception(self):
        """
        Returns: messagized bytearray message with attached signatures of
                 own inception event by retrieving event and signatures
                 from database.
        """
        return self.makeOwnEvent(sn=0)


    def processCues(self, cues):
        """
        Returns bytearray of messages as a result of processing all cues

        Parameters:
           cues is deque of cues
        """
        msgs = bytearray()  # outgoing messages
        for msg in self.processCuesIter(cues):
            msgs.extend(msg)
        return msgs


    def processCuesIter(self, cues):
        """
        Iterate through cues and yields one or more msgs for each cue.

        Parameters:
            cues is deque of cues

        """
        while cues:  # iteratively process each cue in cues
            msgs = bytearray()
            cue = cues.popleft()
            cueKin = cue["kin"]  # type or kind of cue
            cuedSerder = cue["serder"]  # Serder of received event for other pre
            cuedKed = cuedSerder.ked
            cuedPrefixer = coring.Prefixer(qb64=cuedKed["i"])
            logger.info("%s got cue: kin=%s\n%s\n\n", self.pre, cueKin,
                                             json.dumps(cuedKed, indent=1))
            if cueKin in ("receipt", ):  # received event from other cued pre
                if  cuedKed["t"] == coring.Ilks.icp:
                    dgkey = dbing.dgKey(self.pre, self.iserder.dig)
                    found = False
                    if cuedPrefixer.transferable:  # find if already vrcs of own icp
                        for quadruple in self.db.getVrcsIter(dgkey):
                            if bytes(quadruple).decode("utf-8").startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception
                    else:  # find if already rcts of own icp
                        for couple in self.db.getRctsIter(dgkey):
                            if bytes(couple).decode("utf-8").startswith(cuedKed["i"]):
                                found = True  # yes so don't send own inception

                    if not found:  # no receipt from remote so send own inception
                        # no vrcs or rct of own icp from remote so send own inception
                        msgs.extend(self.makeOwnInception())

                if self.kever.prefixer.transferable:  #  send trans receipt chit
                    msgs.extend(self.chit(cuedSerder))
                else:  # send nontrans receipt
                    msgs.extend(self.receipt(cuedSerder))
                yield msgs


class Director(doing.Doer):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:

    Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, client,  **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            hab is Habitat instance
            client is TCP Client instance

        """
        super(Director, self).__init__(**kwa)
        self.hab = hab
        self.client = client  # use client for tx only
        if self.tymth:
            self.client.wind(self.tymth)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Director, self).wind(tymth)
        self.client.wind(tymth)


    def do(self, tymth=None, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymth)  # change tymist and dependencies
            self.tock = tock
            # tyme = self.tyme

            while (True):  # recur context
                tyme = (yield (tock))  # yields tock then waits for next send

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


    def sendOwnEvent(self, sn):
        """
        Utility to send own event at sequence number sn
        """
        msg = self.hab.makeOwnEvent(sn=sn)
        # send to connected remote
        self.client.tx(msg)
        logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msg))


    def sendOwnInception(self):
        """
        Utility to send own inception on client
        """
        self.sendOwnEvent(sn=0)


class Reactor(doing.DoDoer):
    """
    Reactor Subclass of DoDoer with doers list from do generator methods:
        .msgDo, .cueDo, and  .escrowDo.
    Enables continuous scheduling of doers (do generator instances or functions)

    Implements Doist like functionality to allow nested scheduling of doers.
    Each DoDoer runs a list of doers like a Doist but using the tyme from its
       injected tymist as injected by its parent DoDoer or Doist.

    Scheduling hierarchy: Doist->DoDoer...->DoDoer->Doers

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.
        .opts is dict of injected options for its generator .do
        .doers is list of Doers or Doer like generator functions

    Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP Client instance.
        .kevery is Kevery instance


    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .clean is clean context action method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Overidden Methods:

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property

    """


    def __init__(self, hab, client, doers=None, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            doers is list of doers (do generator instances, functions or methods)

        Parameters:
            hab is Habitat instance of local controller's context
            client is TCP Client instance

        """
        self.hab = hab
        self.client = client  # use client for both rx and tx
        self.kevery = eventing.Kevery(ims=self.client.rxbs,
                                      kevers=self.hab.kevers,
                                      db=self.hab.db,
                                      framed=True,
                                      opre=self.hab.pre,
                                      local=False)
        doers = doers if doers is not None else []
        doers.extend([self.msgDo, self.cueDo, self.escrowDo])
        super(Reactor, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.client.wind(self.tymth)


    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Reactor, self).wind(tymth)
        self.client.wind(tymth)


    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns Doist compatibile generator method (doer dog) to process
            incoming message stream of .kevery

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
        if self.kevery.ims:
            logger.info("Client %s received:\n%s\n...\n", self.hab.pre, self.kevery.ims[:1024])
        done = yield from self.kevery.processor()  # process messages continuously
        return done  # should nover get here except forced close


    @doing.doize()
    def cueDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .kevery.cues deque

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
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield  # throttle just do one cue at a time
            yield
        return False  # should never get here except forced close


    @doing.doize()
    def escrowDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .kevery escrows.

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
            self.kevery.processEscrows()
            yield
        return False  # should never get here except forced close


    def sendMessage(self, msg, label=""):
        """
        Sends message msg and loggers label if any
        """
        self.client.tx(msg)  # send to remote
        logger.info("%s sent %s:\n%s\n\n", self.hab.pre, label, bytes(msg))


class Directant(doing.DoDoer):
    """
    Directant class with TCP Server.
    Responds to initiated connections from a remote Director by creating and
    running a Reactant per connection. Each Reactant has TCP remoter.

    Directant Subclass of DoDoer with doers list from do generator methods:
        .serviceDo

    Enables continuous scheduling of doers (do generator instances or functions)

    Implements Doist like functionality to allow nested scheduling of doers.
    Each DoDoer runs a list of doers like a Doist but using the tyme from its
       injected tymist as injected by its parent DoDoer or Doist.

    Scheduling hierarchy: Doist->DoDoer...->DoDoer->Doers

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.
        .opts is dict of injected options for its generator .do
        .doers is list of Doers or Doer like generator functions

    Attributes:
        .hab is Habitat instance of local controller's context
        .server is TCP client instance. Assumes operated by another doer.
        .rants is dict of Reactants indexed by connection address

    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .clean is clean context action method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Methods:

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, server, doers=None, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            hab is Habitat instance of local controller's context
            server is TCP Server instance
        """
        self.hab = hab
        self.server = server  # use server for cx
        self.rants = dict()
        doers = doers if doers is not None else []
        doers.extend([self.serviceDo])
        super(Directant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.server.wind(self.tymth)


    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Directant, self).wind(tymth)
        self.server.wind(tymth)


    @doing.doize()
    def serviceDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns Doist compatibile generator method (doer dog) to service
            connections on .server. Creates remoter and rant (Reactant) for each
            open connection and adds rant to running doers.

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
            for ca, ix in list(self.server.ixes.items()):
                if ix.cutoff:
                    self.closeConnection(ca)
                    continue

                if ca not in self.rants:  # create Reactant and extend doers with it
                    rant = Reactant(tymth=self.tymth, hab=self.hab, remoter=ix)
                    self.rants[ca] = rant
                    # add Reactant (rant) doer to running doers
                    self.extend(doers=[rant])  # open and run rant as doer

                if ix.timeout > 0.0 and ix.tymer.expired:
                    self.closeConnection(ca)  # also removes rant

            yield
        return False  # should never get here

    def closeConnection(self, ca):
        """
        Close and remove connection given by ca and remove associated rant at ca.
        """
        if ca in self.server.ixes:  # remoter still there
            self.server.ixes[ca].serviceSends()  # send final bytes to socket
        self.server.removeIx(ca)
        if ca in self.rants:  # remove rant (Reactant) if any
            self.remove([self.rants[ca]])  # close and remove rant from doers list
            del self.rants[ca]


class Reactant(doing.DoDoer):
    """
    Reactant Subclass of DoDoer with doers list from do generator methods:
        .msgDo, .cueDo, and .escrowDo.
    Enables continuous scheduling of doers (do generator instances or functions)

    Implements Doist like functionality to allow nested scheduling of doers.
    Each DoDoer runs a list of doers like a Doist but using the tyme from its
       injected tymist as injected by its parent DoDoer or Doist.

    Scheduling hierarchy: Doist->DoDoer...->DoDoer->Doers

    Attributes:
        .hab is Habitat instance of local controller's context
        .kevery is Kevery instance
        .remoter is TCP Remoter instance for connection from remote TCP client.

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.
        .opts is dict of injected options for its generator .do
        .doers is list of Doers or Doer like generator functions


    Inherited Properties:
        .tyme is float relative cycle time of associated Tymist .tyme obtained
            via injected .tymth function wrapper closure.
        .tymth is function wrapper closure returned by Tymist .tymeth() method.
            When .tymth is called it returns associated Tymist .tyme.
            .tymth provides injected dependency on Tymist tyme base.
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .wind  injects ._tymth dependency from associated Tymist to get its .tyme
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .clean is clean context action method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Overidden Methods:

    Hidden:
       ._tymth is injected function wrapper closure returned by .tymen() of
            associated Tymist instance that returns Tymist .tyme. when called.
       ._tock is hidden attribute for .tock property

    """

    def __init__(self, hab, remoter, doers=None, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            doers is list of doers (do generator instancs or functions)

        Parameters:
            hab is Habitat instance of local controller's context
            remoter is TCP Remoter instance
            doers is list of doers (do generator instances, functions or methods)

        """
        self.hab = hab
        self.remoter = remoter  # use remoter for both rx and tx
        #  neeeds unique kevery with ims per remoter connnection
        self.kevery = eventing.Kevery(ims=self.remoter.rxbs,
                                      kevers=self.hab.kevers,
                                      db=self.hab.db,
                                      framed=True,
                                      opre=self.hab.pre,
                                      local=False)
        doers = doers if doers is not None else []
        doers.extend([self.msgDo, self.cueDo, self.escrowDo])
        super(Reactant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.remoter.wind(self.tymth)


    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(Reactant, self).wind(tymth)
        self.remoter.wind(tymth)


    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns Doist compatibile generator method (doer dog) to process
            incoming message stream of .kevery

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
        if self.kevery.ims:
            logger.info("Server %s: %s received:\n%s\n...\n", self.hab.name,
                        self.hab.pre, self.kevery.ims[:1024])
        done = yield from self.kevery.processor()  # process messages continuously
        return done  # should nover get here except forced close


    @doing.doize()
    def cueDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .kevery.cues deque

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
            for msg in self.hab.processCuesIter(self.kevery.cues):
                self.sendMessage(msg, label="chit or receipt")
                yield  # throttle just do one cue at a time
            yield
        return False  # should never get here except forced close


    @doing.doize()
    def escrowDo(self, tymth=None, tock=0.0, **opts):
        """
         Returns Doist compatibile generator method (doer dog) to process
            .kevery escrows.

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
            self.kevery.processEscrows()
            yield
        return False  # should never get here except forced close



    def sendMessage(self, msg, label=""):
        """
        Sends message msg and loggers label if any
        """
        self.remoter.tx(msg)  # send to remote
        logger.info("Server %s: %s sent %s:\n%s\n\n", self.hab.name,
                    self.hab.pre, label, bytes(msg))



def runController(doers, expire=0.0):
    """
    Utiitity Function to create doist to run doers
    """
    tock = 0.03125
    doist = doing.Doist(limit=expire, tock=tock, real=True)
    doist.do(doers=doers)
