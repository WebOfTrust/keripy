# -*- encoding: utf-8 -*-
"""
KERI
keri.base.directing module

simple direct mode demo support classes
"""
from hio.base import doing, tyming
from hio.core.tcp import clienting, serving
from .. import kering
from ..db import dbing
from ..core import coring, eventing
from . import keeping


from ..help import ogling

blogger, flogger = ogling.ogler.getLoggers()

class Habitat():
    """
    Habitat class provides direct mode controller's local shared habitat
       e.g. context or environment

     Attributes:
        .name is str alias of controller
        .ks is lmdb key store keeping.Keeper instance
        .mgr is keeping.Manager instance
        .ridx is int rotation index (inception == 0)
        .kevers is dict of eventing.Kever(s) keyed by qb64 prefix
        .db is lmdb data base dbing.Baser instance
        .kvy is eventing.Kevery instance
        .signers is dict  of signers for each secret indexed by verfer qb64
        .inception is Serder of inception event
        .pre is qb64 prefix of local controller
        .temp is Boolean True for testing it modifies tier of salty key
            generation algorithm and persistence of db and ks
    """

    def __init__(self, name='test', ks=None, db=None, kevers=None, secrets=None,
                 sith=None, kcount=1, salt=None, tier=None, temp=False):
        """
        Initialize instance.

        Parameters:
            name is str alias name for local controller of habitat
            ks is keystore lmdb Keeper instance
            db is database lmdb Baser instance
            kevers is dict of Kever instance keyed by qb64 prefix
            secrets is list of secrets (replace later with keeper interface)
            temp is Boolean used for persistance of lmdb ks and db directories
                and mode for key generation


        """
        self.temp = temp
        self.name = name
        self.ks = ks if ks is not None else keeping.Keeper(name=name, temp=self.temp)
        if salt is None:
            salt = coring.Salter(raw=b'0123456789abcdef').qb64
        self.mgr = keeping.Manager(keeper=self.ks, salt=salt, tier=tier)
        self.ridx = 0  # rotation index of latest establishment event
        self.kevers = kevers if kevers is not None else dict()
        self.db = db if db is not None else dbing.Baser(name=name, temp=self.temp)
        self.kvy = eventing.Kevery(kevers=self.kevers, baser=self.db, framed=False)
        self.sith = sith
        self.count = kcount

        if secrets:
            secrecies = []
            for secret in secrets:
                secrecies.append([secret])
            verferies, digers = self.mgr.ingest(secrecies,
                                                ncount=kcount,
                                                stem=self.name,
                                                temp=self.temp)
            opre = verferies[0][0].qb64  # old pre default needed for .replay
            verfers, digers = self.mgr.replay(pre=opre, ridx=self.ridx)
        else:
            verfers, digers = self.mgr.incept(icount=kcount,
                                              ncount=kcount,
                                              stem=self.name,
                                              temp=self.temp)

        opre = verfers[0].qb64 # old pre default move below to new pre from incept

        # get rid of signers and then convert secrets to secrecies
        self.signers = [coring.Signer(qb64=secret) for secret in secrets]
        self.inception = eventing.incept(keys=[verfers[0].qb64],
                                         sith=sith,
                                         nxt=coring.Nexter(sith=sith,
                                                           digs=[digers[0].qb64]).qb64,
                                         code=coring.MtrDex.Blake3_256)

        self.pre = self.inception.ked["i"]  # new pre
        self.mgr.move(old=opre, new=self.pre)

        sigers = self.mgr.sign(ser=self.inception.raw, verfers=verfers)
        msg = eventing.messagize(self.inception, sigers)
        self.kvy.processOne(ims=msg)
        if self.pre not in self.kevers:
            raise kering.ValidationError("Improper Habitat inception for pre={}.".format(pre))


    def incept(self):
        """
        Perform inception operation. Register inception in database.
        Returns: bytearray rotation message with attached signatures.
        """

    def rotate(self, count=1, erase=True):
        """
        Perform rotation operation. Register rotation in database.
        Returns: bytearrayrotation message with attached signatures.
        """
        try:
            verfers, digers = self.mgr.replay(pre=self.pre,
                                              ridx=self.ridx+1,
                                              erase=erase)

        except IndexError as ex:
            verfers, digers = self.mgr.rotate(count=count,
                                              stem=self.name,
                                              temp=self.temp,
                                              erase=erase)

        kever = self.kevers[self.pre]
        serder = eventing.rotate(pre=kever.prefixer.qb64,
                                 keys=[verfer.qb64 for verfer in verfers],
                                 dig=kever.serder.diger.qb64,
                                 nxt=coring.Nexter(sith=self.sith, digers=digers).qb64,
                                 sn=kever.sn+1)
        sigers = self.mgr.sign(ser=serder.raw, verfers=verfers)
        msg = eventing.messagize(serder, sigers)

        # update ownkey event verifier state
        self.kvy.processOne(ims=bytearray(msg))  # make copy as kvr deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat rotation for pre={}.".format(pre))

        self.ridx += 1  # successful rotate so increment for next time
        return msg


    def interact(self):
        """
        Perform interaction operation. Register interaction in database.
        Returns: bytearray interaction message with attached signatures.
        """
        kever = self.kevers[self.pre]
        serder = eventing.interact(pre=kever.prefixer.qb64,
                                   dig=kever.serder.diger.qb64,
                                   sn=kever.sn+1)

        sigers = self.mgr.sign(ser=serder.raw, verfers=kever.verfers)
        msg = eventing.messagize(serder, sigers)

        # update ownkey event verifier state
        self.kvy.processOne(ims=bytearray(msg))  # make copy as kvr deletes
        if kever.serder.dig != serder.dig:
            raise kering.ValidationError("Improper Habitat interaction for pre={}.".format(pre))

        return msg


    def messagizeOwnEvent(self, sn):
        """
        Retrieve inception and signatures from database.
        Returns: bytearray message with attached signatures of own event at
            sequence number sn.

        Parameters:
            sn is int sequence number of event
        """
        msg = bytearray()
        dig = self.db.getKeLast(dbing.snKey(self.pre, sn))
        if dig is None:
            raise kering.MissingEntryError("Missing event for pre={} at sn={}."
                                           "".format(pre, sn))
        dig = bytes(dig)
        key = dbing.dgKey(self.pre, dig)  # digest key
        raw = self.db.getEvt(key)
        msg.extend(self.db.getEvt(key))
        msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=self.db.cntSigs(key)).qb64b) # attach cnt
        for sig in self.db.getSigsIter(key):
            msg.extend(sig) # attach sig
        return (msg)


class Director(doing.Doer):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:

    Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.
        .kevery is Kevery instance

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
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
        self.kevery = eventing.Kevery(kevers=self.hab.kevers,
                                      baser=self.hab.db)

    def do(self, tymist, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymist)  # change tymist and dependencies
            self.tock = tock
            tyme = self.tyme

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
        msg = self.hab.messagizeOwnEvent(sn=sn)
        # send to connected remote
        self.client.tx(msg)
        blogger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))


    def sendOwnInception(self):
        """
        Utility to send own inception on client
        """
        self.sendOwnEvent(sn=0)




class Reactor(doing.Doer):
    """
    Direct Mode KERI Reactor (Contextor, Doer) class with TCP Client and Kevery
    Generator logic is to react to events/receipts from remote Reactant with receipts

    Inherited Attributes:

    Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP Client instance.
        .kevery is Kevery instance

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, client,  **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            hab is Habitat instance of local controller's context
            client is TCP Client instance
        """
        super(Reactor, self).__init__(**kwa)
        self.hab = hab
        self.client = client  # use client for both rx and tx
        self.kevery = eventing.Kevery(ims=self.client.rxbs,
                                      kevers=self.hab.kevers,
                                      baser=self.hab.db,
                                      framed=False)


    def do(self, tymist, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymist)  # change tymist and dependencies
            self.tock = tock
            tyme = self.tyme

            while (True):  # recur context
                tyme = (yield (tock))  # yields tock then waits for next send
                self.service()

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


    def service(self):
        """
        Service responses
        """
        if self.kevery:
            if self.kevery.ims:
                blogger.info("%s received:\n%s\n\n", self.hab.pre, self.kevery.ims)
            self.kevery.processAll()
            self.processCues()


    def processCues(self):
        """
        Process all cues in .kevery
        """
        while self.kevery.cues:  # process any cues
            # process each cue
            cue = self.kevery.cues.popleft()
            blogger.info("{} sent cue:\n{}\n\n", self.hab.pre, cue)
            self.processCue(cue=cue)


    def processCue(self, cue):
        """
        Process a cue in direct mode assumes chits
        """
        cueKin = cue["kin"]  # type or kind of cue
        if cueKin in ("receipt", ):
            cuedSerder = cue["serder"]
            cuedKed = cuedSerder.ked

            if  cuedKed["t"] == coring.Ilks.icp:
                # check for chit or recipt from remote pre for own inception
                # need to add check for recipt based on type of cuedpre.
                dgkey = dbing.dgKey(self.hab.pre, self.hab.inception.dig)
                found = False
                for quadruple in self.hab.db.getVrcsIter(dgkey):
                    if bytes(quadruple).decode("utf-8").startswith(cuedKed["i"]):
                        found = True
                        break

                if not found:  # no chit from remote so send own inception
                    self.sendOwnInception()

            self.sendOwnChit(cuedSerder)


    def processCuesIter(self):
        """
        Iterate through cues in .cues
        This is a stub  for future iterator/generator based processing

        For each cue yield one or more msgs to send out
        """
        while self.kevery.cues:  # process any cues
            # popleft each cue in .cues deque and process
            cue = self.kevery.cues.popleft()
            blogger.info("%s sent cue:\n%s\n\n", self.hab.pre, cue)
            cueKin = cue["kin"]  # type or kind of cue

            if cueKin in ("receipt", ):
                cuedSerder = cue["serder"]
                cuedKed = cuedSerder.ked

                if cuedKed["t"] == coring.Ilks.icp:
                    # check for chit or recipt from remote pre for own inception
                    # need to add check for recipt based on type of cuedpre.
                    dgkey = dbing.dgKey(self.hab.pre, self.hab.inception.dig)
                    found = False
                    for quadruple in self.hab.db.getVrcsIter(dgkey):
                        if bytes(quadruple).decode("utf-8").startswith(cuedKed["i"]):
                            found = True
                            break

                    if not found:  # no chit from remote so send own inception
                        yield self.prepareOwnInception()

                yield self.prepareOwnChit(cuedSerder)



    def sendOwnChit(self, cuedSerder):
        """
        Send chit of event indicated by cuedSerder
        """
        # send own chit of event
        # create seal of own last est event
        kever = self.hab.kevers[self.hab.pre]
        seal = eventing.SealEvent(i=self.hab.pre,
                                  s="{:x}".format(kever.lastEst.s),
                                  d=kever.lastEst.d)

        cuedKed = cuedSerder.ked
        # create validator receipt
        reserder = eventing.chit(pre=cuedKed["i"],
                                 sn=int(cuedKed["s"], 16),
                                 dig=cuedSerder.dig,
                                 seal=seal)
        # sign cueSerder event not receipt
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs)
        # use signer that matcher current verfer  # not multisig
        verfer = kever.verfers[0]
        siger = None
        for signer in self.hab.signers:
            if signer.verfer.qb64 == verfer.qb64:
                siger = signer.sign(ser=cuedSerder.raw, index=0)  # return Siger if index
                break
        if siger:
            # process own chit so have copy in own log
            msg = bytearray(reserder.raw)
            msg.extend(counter.qb64b)
            msg.extend(siger.qb64b)
            self.kevery.processOne(ims=bytearray(msg), framed=True)  # make copy

            # send to remote
            self.client.tx(bytes(msg))  # make copy because tx uses deque
            blogger.info("%s sent chit:\n%s\n\n", self.hab.pre, bytes(msg))
            del msg[:]


    def sendOwnEvent(self, sn):
        """
        Utility to send own event at sequence number sn
        """
        msg = self.hab.messagizeOwnEvent(sn=sn)
        # send to connected remote
        self.client.tx(msg)
        blogger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))


    def sendOwnInception(self):
        """
        Utility to send own inception on client
        """
        self.sendOwnEvent(sn=0)



class Directant(doing.Doer):
    """
    Direct Mode KERI Directant (Contextor, Doer) class with TCP Server
    Logic is to respond to initiated events by remote Director by running
    a Reactant per connection.

    Inherited Attributes:

    Attributes:
        .hab is Habitat instance of local controller's context
        .server is TCP client instance. Assumes operated by another doer.
        .rants is dict of Reactants indexed by connection address

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, hab, server,  **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            hab is Habitat instance of local controller's context
            server is TCP Server instance
        """
        super(Directant, self).__init__(**kwa)
        self.hab = hab
        self.server = server  # use server for cx
        self.rants = dict()


    def do(self, tymist, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymist)  # change tymist and dependencies
            self.tock = tock
            tyme = self.tyme

            while (True):  # recur context
                tyme = (yield (tock))  # yields tock then waits for next send
                self.serviceConnects()
                self.serviceRants()

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


    def closeConnection(self, ca):
        """
        Close and remove connection given by ca
        """
        if ca in self.rants:
            del self.rants[ca]
        if ca in self.server.ixes:  # incomer still there
            self.server.ixes[ca].serviceTxes()  # send final bytes to socket
        self.server.removeIx(ca)


    def serviceConnects(self):
        """
        New connections get Reactant added to .rants
        """
        for ca, ix in list(self.server.ixes.items()):
            if ix.cutoff:
                self.closeConnection(ca)
                continue

            if ca not in self.rants:  # create Reactant
                self.rants[ca] = Reactant(hab=self.hab, incomer=ix)

            if ix.timeout > 0.0 and ix.tymer.expired:
                self.closeConnection(ca)


    def serviceRants(self):
        """
        Service pending reactants
        """
        for ca, reactant in self.rants.items():
            if reactant.kevery:
                if reactant.kevery.ims:
                    blogger.info("%s received:\n%s\n\n", self.hab.pre, reactant.kevery.ims)

                reactant.kevery.processAll()
                reactant.processCues()

            if not reactant.persistent:  # not persistent so close and remove
                ix = self.server.ixes[ca]
                if not ix.txes:  # wait for outgoing txes to be empty
                    self.closeConnection(ca)


class Reactant(tyming.Tymee):
    """
    Direct Mode KERI Reactant (Contextor) class with TCP Incomer and Kevery
    Purpose is to react to received events from remote Director with receipts/events

    Inherited Attributes:

    Attributes:
        .hab is Habitat instance of local controller's context
        .incomer is TCP Incomer instance.
        .kevery is Kevery instance
        .persistent is boolean, True means keep connection open. Otherwise close

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time

    Properties:

    Inherited Methods:

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
    """

    def __init__(self, hab, incomer,  persistent=True, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance

        Parameters:
            hab is Habitat instance of local controller's context
            incomer is TCP Incomer instance
        """
        super(Reactant, self).__init__(**kwa)
        self.hab = hab
        self.incomer = incomer  # use incomer for both rx and tx
        self.kevery = eventing.Kevery(ims=self.incomer.rxbs,
                                      kevers=self.hab.kevers,
                                      baser=self.hab.db,
                                      framed=False)
        self.persistent = True if persistent else False

    def processCues(self):
        """
        Process any cues in .kevery
        """

        while self.kevery.cues:  # process any cues
            # process each cue
            cue = self.kevery.cues.popleft()
            blogger.info("%s sent cue:\n%s\n\n", self.hab.pre, cue)
            self.processCue(cue=cue)


    def processCue(self, cue):
        """
        Process a cue in direct mode assumes chits
        """
        cueKin = cue["kin"]  # type or kind of cue

        cuedSerder = cue["serder"]
        cuedKed = cuedSerder.ked
        cuedPre = cuedKed["i"]
        cuedIlk = cuedKed["t"]

        if cuedIlk == coring.Ilks.icp:
            # check for chit from remote pre for own inception
            dgkey = dbing.dgKey(self.hab.pre, self.hab.inception.dig)
            found = False
            for quadruple in self.hab.db.getVrcsIter(dgkey):
                if quadruple.startswith(bytes(cuedPre)):
                    found = True
                    break

            if not found:  # no chit from remote so send own inception
                self.sendOwnInception()

        self.sendOwnChit(cuedSerder)


    def sendOwnChit(self, cuedSerder):
        """
        Send chit of event indicated by cuedSerder
        """
        # send own chit of event
        # create seal of own last est event
        kever = self.hab.kevers[self.hab.pre]
        seal = eventing.SealEvent(i=self.hab.pre,
                                  s="{:x}".format(kever.lastEst.s),
                                  d=kever.lastEst.d)

        cuedKed = cuedSerder.ked
        # create validator receipt
        reserder = eventing.chit(pre=cuedKed["i"],
                                 sn=int(cuedKed["s"], 16),
                                 dig=cuedSerder.dig,
                                 seal=seal)
        # sign cueSerder event not receipt
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs)
        # use signer that matcher current verfer  # not multisig
        verfer = kever.verfers[0]
        siger = None
        for signer in self.hab.signers:
            if signer.verfer.qb64 == verfer.qb64:
                siger = signer.sign(ser=cuedSerder.raw, index=0)  # return Siger if index
                break
        if siger:
            # process own chit so have copy in own log
            msg = bytearray(reserder.raw)
            msg.extend(counter.qb64b)
            msg.extend(siger.qb64b)
            self.kevery.processOne(ims=bytearray(msg), framed=True)  # process copy

            # send to remote
            self.incomer.tx(bytes(msg))  # tx copy because tx uses deque
            blogger.info("%s sent chit:\n%s\n\n", self.hab.pre, bytes(msg))
            del msg[:]  # maybe superfluous here


    def sendOwnEvent(self, sn):
        """
        Utility to send own event at sequence number sn
        """
        msg = self.hab.messagizeOwnEvent(sn=sn)
        # send to connected remote
        self.incomer.tx(msg)
        blogger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))


    def sendOwnInception(self):
        """
        Utility to send own inception on client
        """
        self.sendOwnEvent(sn=0)



class BobDirector(Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.
        .kevery is Kevery instance


    Attributes:

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def do(self, tymist, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymist)  # change tymist and dependencies
            self.tock = tock
            tyme = self.tyme

            # recur context
            tyme = (yield (self.tock))  # yields tock then waits for next send

            blogger.info("**** %s:\nWaiting for connection to remote  %s.\n\n", self.hab.pre, self.client.ha)
            while (not self.client.connected):
                tyme = (yield (self.tock))

            blogger.info("**** %s:\nConnected to %s.\n\n", self.hab.pre, self.client.ha)

            # Inception Event 0
            sn =  0
            esn = 0

            self.sendOwnInception()  # assumes habitat already logged it
            tyme = (yield (self.tock))

            # Rotation Event 1
            sn += 1
            esn += 1

            kever = self.hab.kevers[self.hab.pre]  # have to do here after own inception

            serder = eventing.rotate(pre=kever.prefixer.qb64,
                        keys=[self.hab.signers[esn].verfer.qb64],
                        dig=kever.serder.diger.qb64,
                        nxt=coring.Nexter(keys=[self.hab.signers[esn+1].verfer.qb64]).qb64,
                        sn=sn)
            # create sig counter
            counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs)  # default is count = 1
            # sign serialization
            siger = self.hab.signers[esn].sign(serder.raw, index=0)  # returns siger

            #  create serialized message
            msg = bytearray(serder.raw)
            msg.extend(counter.qb64b)
            msg.extend(siger.qb64b)

            # update ownkey event verifier state
            self.kevery.processOne(ims=bytearray(msg))  # make copy

            # send to connected remote
            self.client.tx(bytes(msg))  # make copy for now fix later
            blogger.info("**** %s:\nSent event:\n%s\n\n", self.hab.pre, bytes(msg))
            del msg[:]  #  clear msg
            tyme = (yield (self.tock))

            # Next Event 2 Interaction
            sn += 1  # do not increment esn

            serder = eventing.interact(pre=kever.prefixer.qb64,
                                       dig=kever.serder.diger.qb64,
                                       sn=sn)

            # create sig counter
            counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs)  # default is count = 1
            # sign serialization
            siger = self.hab.signers[esn].sign(serder.raw, index=0)  # returns siger

            # create msg
            msg = bytearray(serder.raw)
            msg.extend(counter.qb64b)
            msg.extend(siger.qb64b)

            # update ownkey event verifier state
            self.kevery.processOne(ims=bytearray(msg))  # make copy

            # send to connected remote
            self.client.tx(bytes(msg))  # make copy for now fix later
            blogger.info("**** %s:\nSent event:\n%s\n\n", self.hab.pre, bytes(msg))
            del msg[:]  #  clear msg
            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True # return value of yield from, or yield ex.value of StopIteration


class SamDirector(Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.
        .kevery is Kevery instance


    Attributes:

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def do(self, tymist, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymist)  # change tymist and dependencies
            self.tock = tock
            tyme = self.tyme

            # recur context
            tyme = (yield (self.tock))  # yields tock then waits for next send

            while (not self.client.connected):
                blogger.info("%s:\n waiting for connection to remote %s.\n\n", self.hab.pre, self.client.ha)
                tyme = (yield (self.tock))

            blogger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)

            # Inception Event 0
            sn =  0
            esn = 0

            self.sendOwnInception()  # assumes habitat already logged it
            tyme = (yield (self.tock))

            # Next Event 1 Interaction
            sn += 1  # do not increment esn

            kever = self.hab.kevers[self.hab.pre]

            serder = eventing.interact(pre=kever.prefixer.qb64,
                                       dig=kever.serder.diger.qb64,
                                       sn=sn)

            # create sig counter
            counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs)  # default is count = 1
            # sign serialization
            siger = self.hab.signers[esn].sign(serder.raw, index=0)  # returns siger

            # create msg
            msg = bytearray(serder.raw)
            msg.extend(counter.qb64b)
            msg.extend(siger.qb64b)

            # update ownkey event verifier state
            self.kevery.processOne(ims=bytearray(msg))  # make copy

            # send to connected remote
            self.client.tx(bytes(msg))  # make copy for now fix later
            blogger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            del msg[:]  # clear msg

            tyme = (yield (self.tock))

            # Rotation Event 2
            sn += 1
            esn += 1

            serder = eventing.rotate(pre=kever.prefixer.qb64,
                                             keys=[self.hab.signers[esn].verfer.qb64],
                                dig=kever.serder.diger.qb64,
                                nxt=coring.Nexter(keys=[self.hab.signers[esn+1].verfer.qb64]).qb64,
                                sn=sn)
            # create sig counter
            counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs)  # default is count = 1
            # sign serialization
            siger = self.hab.signers[esn].sign(serder.raw, index=0)  # returns siger

            #  create serialized message
            msg = bytearray(serder.raw)
            msg.extend(counter.qb64b)
            msg.extend(siger.qb64b)

            # update ownkey event verifier state
            self.kevery.processOne(ims=bytearray(msg))  # make copy

            # send to connected remote
            self.client.tx(bytes(msg))  # make copy for now fix later
            blogger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            del msg[:]  # clear msg

            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


class EveDirector(Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.
        .kevery is Kevery instance


    Attributes:

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Inherited Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def do(self, tymist, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymist)  # change tymist and dependencies
            self.tock = tock
            tyme = self.tyme

            # recur context after first yield
            tyme = (yield (tock))

            while (not self.client.connected):
                blogger.info("%s:\n waiting for connection to remote %s.\n\n", self.hab.pre, self.client.ha)
                tyme = (yield (self.tock))

            blogger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)
            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


def setupController(secrets,  name="who", remotePort=5621, localPort=5620):
    """
    Setup and return doers list to run controller
    """
    # setup habitat
    hab = Habitat(name=name, secrets=secrets, temp=True)
    blogger.info("\nDirect Mode demo of %s:\nNamed %s on TCP port %s to port %s.\n\n",
                 hab.pre, hab.name, localPort, remotePort)

    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)
    dbDoer = dbing.BaserDoer(baser=hab.db)

    client = clienting.Client(host='127.0.0.1', port=remotePort)
    clientDoer = doing.ClientDoer(client=client)

    if name == 'bob':
        director = BobDirector(hab=hab, client=client, tock=0.125)
    elif name == "sam":
        director = SamDirector(hab=hab, client=client, tock=0.125)
    elif name == 'eve':
        director = EveDirector(hab=hab, client=client, tock=0.125)
    else:
        raise ValueError("Invalid director name={}.".format(name))

    reactor = Reactor(hab=hab, client=client)

    server = serving.Server(host="", port=localPort)
    serverDoer = doing.ServerDoer(server=server)
    directant = Directant(hab=hab, server=server)
    # Reactants created on demand by directant

    return [ksDoer, dbDoer, clientDoer, director, reactor, serverDoer, directant]


def runController(doers, limit=0.0):
    """
    run the doers for limit time. 0.0 means no limit.
    """
    # run components
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock, real=True, doers=doers)
    doist.do()
