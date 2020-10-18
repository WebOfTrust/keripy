# -*- encoding: utf-8 -*-
"""
KERI
keri.demo.direcmode module

simple directmode demo
"""

import hio
from hio.base import doing



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
        .name is str unique name for database path
        .temp is boolean temporary database if True
        .db is lmdb Logger instance

    Methods:
        .__call__ makes instance callable return generator
        .do is generator function returns generator

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, name="bob", temp=True, **kwa):
        """
        Initialize instance.

        Inherited Parameters:
            tymist is  Tymist instance
            tock is float seconds initial value of .tock

        Parameters:
            name is str unique name of director
            temp is boolen, True means db dir is temporary, otherwise permanent
        """
        super(Director, self).__init__(**kwa)
        self.name = name
        self.temp = True if temp else False
        self.db = None  # create and open in enter


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.db = dbing.Logger(name=self.name, temp=self.temp)

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send


        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            self.db.clearDirPath()

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
        .name is str unique name for database path
        .temp is boolean temporary database if True
        .db is lmdb Logger instance

    Attributes:
        .server is TCP Server instance. Assumes run elsewhere

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
            name is str unique name of director
            temp is boolen, True means db dir is temporary, otherwise permanent

        Parameters:
            server is TCP server instance. Assumes run elsewhere

        """
        super(ServerDirector, self).__init__(**kwa)
        self.server = server


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.db = dbing.Logger(name=self.name, temp=self.temp)

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send


        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            self.db.clearDirPath()

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
        .name is str unique name for database path
        .temp is boolean temporary database if True
        .db is lmdb Logger instance

    Attributes:
        .client is TCP Client instance. Assumes run elsewhere

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
            name is str unique name of director
            temp is boolen, True means db dir is temporary, otherwise permanent

        Parameters:
            client is TCP client instance. Assumes run elsewhere

        """
        super(ServerDirector, self).__init__(**kwa)
        self.client = client


    def do(self, tymist, tock=0.0):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.db = dbing.Logger(name=self.name, temp=self.temp)

            while (True):  # recur context
                feed = (yield (tock))  # yields tock then waits for next send


        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            self.db.clearDirPath()

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
