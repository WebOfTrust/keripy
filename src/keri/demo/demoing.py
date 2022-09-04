# -*- encoding: utf-8 -*-
"""
KERI
keri.app.directing module

simple direct mode demo support classes
"""

import os

from hio.core import wiring
from hio.core.serial import serialing
from hio.core.tcp import clienting, serving

from .. import help
from ..app import habbing, keeping, directing
from ..core import scheming
from ..db import basing
from ..help import helping
from ..peer import exchanging
from ..vc import proving, protocoling

logger = help.ogler.getLogger()


def setupDemoController(secrecies, name="who", remotePort=5621, localPort=5620,
                        indirect=False, remotePre=""):
    """
    Setup and return doers list to run controller
    """

    # setup habery with resources
    hby = habbing.Habery(name=name, base="demo", temp=True, free=True)
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    # make hab
    hab = hby.makeHab(name=name, secrecies=secrecies)

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')

    wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='demo', reopen=True,
                        headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)

    client = clienting.Client(host='127.0.0.1', port=remotePort, wl=wl)
    clientDoer = clienting.ClientDoer(client=client)

    if name == 'bob':
        director = BobDirector(hab=hab, client=client, tock=0.125)
    elif name == "sam":
        director = SamDirector(hab=hab, client=client, tock=0.125)
    elif name == 'eve':
        director = EveDirector(hab=hab, client=client, tock=0.125)
    else:
        raise ValueError("Invalid director name={}.".format(name))

    reactor = directing.Reactor(hab=hab, client=client, indirect=indirect)

    server = serving.Server(host="", port=localPort, wl=wl)
    serverDoer = serving.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)
    # Reactants created on demand by directant

    logger.info("\nDirect Mode demo of %s:\nNamed %s on TCP port %s to port %s.\n\n",
                hab.pre, hab.name, localPort, remotePort)

    return [hbyDoer, wireDoer, clientDoer, director, reactor, serverDoer, directant]


class BobDirector(directing.Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.

    Attributes:

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

    def do(self, tymth=None, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymth)  # change tymist dependencies
            self.tock = tock
            # tyme = self.tyme

            # recur context
            tyme = (yield (self.tock))  # yields tock then waits for next send

            logger.info("%s:\nWaiting for connection to remote  %s.\n\n", self.hab.pre, self.client.ha)
            while (not self.client.connected):
                tyme = (yield (self.tock))

            logger.info("%s:\nConnected to %s.\n\n", self.hab.pre, self.client.ha)

            self.sendOwnInception()  # Inception Event
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.interact()  # Interaction event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            # create a bunch of out of order messages to test out of order escrow
            msgs = []
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.interact())  # Interaction event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.interact())  # Interaction event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.interact())

            msgs.reverse()  # reverse the order

            for msg in msgs:
                self.client.tx(msg)  # send to connected remote
                logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
                tyme = (yield (self.tock))

            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


class SamDirector(directing.Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.

    Attributes:

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

            # recur context
            tyme = (yield (self.tock))  # yields tock then waits

            while (not self.client.connected):
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.client.ha)
                tyme = (yield (self.tock))

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)

            self.sendOwnInception()  # Inception Event
            tyme = (yield (self.tock))

            msg = self.hab.interact()  # Interaction Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.interact()  # Interaction Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


class CamDirector(directing.Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.

    Attributes:

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

    def __init__(self, remotePre, hab, client, **kwa):
        super().__init__(hab, client, **kwa)
        self.remotePre = remotePre

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

            # recur context
            tyme = (yield (self.tock))  # yields tock then waits

            while (not self.client.connected):
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.client.ha)
                tyme = (yield (self.tock))

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)

            msg = self.hab.query(self.remotePre, src=self.remotePre, route="logs")  # Query for remote pre Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))



        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


class EveDirector(directing.Director):
    """
    Direct Mode KERI Director (Contextor, Doer) with TCP Client and Kevery
    Generator logic is to iterate through initiation of events for demo

    Inherited Attributes:
        .hab is Habitat instance of local controller's context
        .client is TCP client instance. Assumes operated by another doer.

    Attributes:

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

            # recur context after first yield
            tyme = (yield (tock))

            while (not self.client.connected):
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.client.ha)
                tyme = (yield (self.tock))

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)
            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration
