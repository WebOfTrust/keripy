# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.direcmode module

simple directmode demo
"""

import hio
from hio.base import doing
from keri.db import dbing
from keri.core import eventing


class Director(doing.Doer):
    """
    Direct Mode KERI Controller Doer class with lmdb Logger as .db

    Attributes:

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Attributes:
        .tymist is Tymist instance that provides relative cycle time as .tymist.tyme

    Properties:

    Attributes:
        .pre is qb64 prefix of local controller
        .kevers is dict of Kevers keyed by qb64 prefix
        .db is s lmdb db Logger instance


    Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, pre, kevers, db,  **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            pre is qb64 prefix of local controller
            db is lmdb db Logger instance
            kevers is dict of Kever instance keyed by qb64 prefix
        """
        super(Director, self).__init__(**kwa)
        self.pre = pre
        self.kevers = kevers
        self.db = db


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send


        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True # return value of yield from, or yield ex.value of StopIteration


class ServerDirector(Director):
    """
    Direct Mode KERI Controller Doer class with TCP Server for comms

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Attributes:
        .tymist is Tymist instance that provides relative cycle time as .tymist.tyme
        .pre is qb64 prefix of local controller
        .kevers is dict of Kevers keyed by qb64 prefix
        .db is s lmdb db Logger instance


    Attributes:
        .server is TCP Server instance. Assumes run elsewhere
        .keveries is dict of Kevery instances keyed by connection address

    Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, server, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            pre is qb64 prefix of local controller
            db is lmdb db Logger instance
            kevers is dict of Kever instance keyed by qb64 prefix

        Parameters:
            server is TCP server instance. Assumes run elsewhere
        """
        super(ServerDirector, self).__init__(**kwa)
        self.server = server
        self.keveries = dict()


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
           pass

        return True # return value of yield from, or yield ex.value of StopIteration


class ServerReactant(ServerDirector):
    """
    Direct Mode KERI Controller Doer class with TCP Server for comms

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Attributes:
        .tymist is Tymist instance that provides relative cycle time as .tymist.tyme
        .pre is qb64 prefix of local controller
        .kevers is dict of Kevers keyed by qb64 prefix
        .db is s lmdb db Logger instance
        .server is TCP Server instance. Assumes run elsewhere
        .keveries is dict of Kevery instances keyed by connection address

    Attributes:


    Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            pre is qb64 prefix of local controller
            db is lmdb db Logger instance
            kevers is dict of Kever instance keyed by qb64 prefix
            server is TCP server instance. Assumes run elsewhere
        Parameters:


        """
        super(ServerReactant, self).__init__(**kwa)



    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
           pass

        return True # return value of yield from, or yield ex.value of StopIteration



class ClientDirector(Director):
    """
    Direct Mode KERI Controller Doer class with TCP Client for comms

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Attributes:
        .tymist is Tymist instance that provides relative cycle time as .tymist.tyme
        .pre is qb64 prefix of local controller
        .kevers is dict of Kevers keyed by qb64 prefix
        .db is s lmdb db Logger instance

    Attributes:
        .client is TCP Client instance. Assumes run elsewhere
        .kevery is Kevery instance

    Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, client, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            pre is qb64 prefix of local controller
            db is lmdb db Logger instance

        Parameters:
            client is TCP client instance. Assumes run elsewhere

        """
        super(ClientDirector, self).__init__(**kwa)
        self.client = client
        self.kevery = eventing.Kevery(ims=self.client.rxbs,
                                      kevers=self.kevers,
                                      logger=self.db,
                                      framed=False)


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True # return value of yield from, or yield ex.value of StopIteration



class ClientReactant(ClientDirector):
    """
    Direct Mode KERI Controller Doer class with TCP Server for comms

    Inherited Properties:
        .tyme is float relative cycle time, .tyme is artificial time
        .tock is desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Inherited Attributes:
        .tymist is Tymist instance that provides relative cycle time as .tymist.tyme
        .pre is qb64 prefix of local controller
        .kevers is dict of Kevers keyed by qb64 prefix
        .db is s lmdb db Logger instance
        .client is TCP Client instance. Assumes run elsewhere
        .kevery is Kevery instance

    Attributes:


    Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock
            db is lmdb db Logger instance
            kevers is dict of Kever instance keyed by qb64 prefix
            name is str unique name alias of director
            client is TCP client instance. Assumes run elsewhere

        Parameters:

        """
        super(ClientReactant, self).__init__(**kwa)


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send
                self.kevery.processAll()  # kevery.ims is connected to client.rxbs
                # handle notices in self.kevery.cues here

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
           pass

        return True # return value of yield from, or yield ex.value of StopIteration


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
