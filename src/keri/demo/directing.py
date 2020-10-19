# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.directing module

simple direct mode demo support classes
"""
import hio
from hio.base import doing, tyming
from keri.db import dbing
from keri.core import coring, eventing


class Habitat():
    """
    Habitat class provides direct mode controller's local shared habitat
       e.g. context or environment

     Attributes:
        .secrets is list of secrets (replace later with keeper interface)
        .kevers is dict of Kevers keyed by qb64 prefix
        .db is s lmdb db Logger instance
        .signers is dict  of signers for each secret indexed by verfer qb64
        .inception is Serder of inception event
        .pre is qb64 prefix of local controller
    """
    def __init__(self, secrets, kevers, db):
        """
        Initialize instance.

        Parameters:
            secrets is list of secrets (replace later with keeper interface)
            kevers is dict of Kever instance keyed by qb64 prefix
            db is lmdb db Logger instance
        """
        self.secrets = secrets
        self.kevers = kevers
        self.db = db
        self.signers = [coring.Signer(qb64=secret) for secret in self.secrets]
        self.inception = eventing.incept(keys=[self.signers[0].verfer.qb64],
                        nxt=coring.Nexter(keys=[self.signers[1].verfer.qb64]).qb64,
                        code=coring.CryOneDex.Blake3_256)
        self.pre = self.inception.ked['pre']


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
        self.client = client  #  use client for tx only
        self.kevery = eventing.Kevery(kevers=self.hab.kevers,
                                      logger=self.hab.db)


    def do(self, tymist, tock=0.0):
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

        return True # return value of yield from, or yield ex.value of StopIteration


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
        self.client = client  #  use client for both rx and tx
        self.kevery = eventing.Kevery(ims=self.client.rxbs,
                                      kevers=self.hab.kevers,
                                      logger=self.hab.db,
                                      framed=False)


    def do(self, tymist, tock=0.0):
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

        return True # return value of yield from, or yield ex.value of StopIteration



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
        self.server = server  #  use server for cx
        self.rants = dict()


    def do(self, tymist, tock=0.0):
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

        return True # return value of yield from, or yield ex.value of StopIteration


class Reactant(tyming.Tymee):
    """
    Direct Mode KERI Reactant (Contextor) class with TCP Incomer and Kevery
    Purpose is to react to received events from remote Director with receipts/events

    Inherited Attributes:

    Attributes:
        .hab is Habitat instance of local controller's context
        .incomer is TCP Incomer instance.
        .kevery is Kevery instance

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time

    Properties:

    Inherited Methods:

    Methods:

    Hidden:
       ._tymist is Tymist instance reference
    """

    def __init__(self, hab, incomer,  **kwa):
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
        self.incomer = incomer  #  use incomer for both rx and tx
        self.kevery = eventing.Kevery(ims=self.incomer.rxbs,
                                      kevers=self.hab.kevers,
                                      logger=self.hab.db,
                                      framed=False)



def setupDemo():
    """
    Setup the demo
    """
    print("Setting up Direct Mode demo.\n")



    # coe and zoe

    coeDB = dbing.Logger(name='coe', temp=True)
    coeClient = ''


    zoeDB = dbing.Logger(name='zoe', temp=True)

    coeDB.clearDirPath()
    coeDB.clearDirPath()

if __name__ == "__main__":
    setupDemo()
