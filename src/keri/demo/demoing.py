# -*- encoding: utf-8 -*-
"""
KERI
keri.app.directing module

simple direct mode demo support classes
"""

import json
import os
from urllib import parse

from hio.core import wiring
from hio.core.serial import serialing
from hio.core.tcp import clienting, serving

from .. import help
from ..app import habbing, keeping, directing
from ..core import coring, scheming
from ..core.scheming import CacheResolver
from ..db import basing
from ..help import helping
from ..peer import exchanging
from ..vc import proving, handling, walleting
from ..vc.handling import RequestHandler

logger = help.ogler.getLogger()


def setupDemoController(secrets, name="who", remotePort=5621, localPort=5620,
                        indirect=False, remotePre=""):
    """
    Setup and return doers list to run controller
    """
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])

    # setup databases for dependency injection
    ks = keeping.Keeper(name=name, temp=True)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=True)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=True, secrecies=secrecies)
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

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

    return [ksDoer, dbDoer, habDoer, wireDoer, clientDoer, director, reactor,
            serverDoer, directant]


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


class IanDirector(directing.Director):
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

    def __init__(self, recipientIdentifier, lei, hab, issuer, witnessClient, peerClient, **kwa):
        super().__init__(hab, witnessClient, **kwa)
        self.peerClient = peerClient
        self.recipientIdentifier = recipientIdentifier
        self.issuer = issuer
        self.lei = lei
        if self.tymth:
            self.peerClient.wind(self.tymth)

    def wind(self, tymth):
        """
        Inject new tymist.tymth as new ._tymth. Changes tymist.tyme base.
        Updates winds .tymer .tymth
        """
        super(IanDirector, self).wind(tymth)
        self.peerClient.wind(tymth)

    def do(self, tymth=None, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymth)  # change tymist and dependencies
            self.tock = tock

            # recur context
            tyme = (yield self.tock)  # yields tock then waits

            while not self.client.connected:
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.client.ha)
                tyme = (yield self.tock)

            while not self.peerClient.connected:
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.peerClient.ha)
                tyme = (yield self.tock)

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)

            self.sendOwnInception()  # Inception Event
            tyme = (yield self.tock)

            msg = self.issuer.ianchor
            # send to connected remote
            self.client.tx(msg)
            logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msg))
            tyme = (yield self.tock)

            tevt = self.issuer.incept
            self.client.tx(tevt)
            logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(tevt))
            tyme = (yield self.tock)

            msg = self.hab.interact()  # Interaction Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield self.tock)

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield self.tock)

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield self.tock)

            now = helping.nowIso8601()
            jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)
            ref = scheming.jsonSchemaCache.resolve("EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY")
            schemer = scheming.Schemer(raw=ref)

            # Build the credential subject and then the Credentialer for the full credential
            credSubject = dict(
                id=self.recipientIdentifier,  # this needs to be generated from a KEL
                lei=self.lei
            )

            creder = proving.credential(issuer=self.hab.pre,
                                        schema=schemer.said,
                                        subject=credSubject,
                                        typ=jsonSchema)

            msg = self.hab.endorse(serder=creder)

            tevt, kevt = self.issuer.issue(vcdig=creder.said)
            self.client.tx(kevt)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(kevt))
            tyme = (yield self.tock)

            self.client.tx(tevt)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(tevt))
            tyme = (yield self.tock)

            pl = dict(
                vc=[handling.envelope(msg, typ=jsonSchema)]
            )


            cloner = self.hab.db.clonePreIter(pre=self.hab.pre, fn=0)  # create iterator at 0
            msgs = bytearray()  # outgoing messages
            for msg in cloner:
                msgs.extend(msg)

            # send to connected peer remote
            self.peerClient.tx(msgs)
            logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msgs))
            tyme = (yield self.tock)

            excSrdr = exchanging.exchange(route="/credential/issue", payload=pl)
            excMsg = self.hab.sanction(excSrdr)

            self.peerClient.tx(excMsg)
            logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(excMsg))
            tyme = (yield self.tock)

            logger.info("%s:\n\n\n Sent Verifiable Credential for LEI: %s to %s.\n\n",
                        self.hab.pre, self.lei, self.recipientIdentifier)

            console = serialing.Console()
            console.reopen()
            while console.get().decode('utf-8') != "r":
                (yield self.tock)

            tevt, kevt = self.issuer.revoke(vcdig=creder.said)
            logger.info("%s:\n\n\n Revoked Verifiable Credential for LEI: %s.\n\n",
                        self.hab.pre, self.lei)
            (yield self.tock)

            self.client.tx(kevt)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(kevt))
            (yield self.tock)

            self.client.tx(tevt)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(tevt))
            (yield self.tock)

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


class HanDirector(directing.Director):
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

    issuerpre = "ExwBAYqvPpaPpGmBCixIiC_xpcDto8YUxLoNJgE2FOKo"

    def __init__(self, wallet, hab, client, exchanger, **kwa):
        super().__init__(hab, client, **kwa)
        self.wallet = wallet
        self.exchanger = exchanger

    def do(self, tymth=None, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymth)  # change tymist and dependencies
            self.tock = tock
            tyme = (yield self.tock)  # yields tock then waits

            while not self.client.connected:
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.client.ha)
                tyme = (yield self.tock)

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)
            print(f'{self.hab.name}\'s Wallet ({self.hab.pre}) ')
            print()

            msg = self.hab.query(self.issuerpre, res="logs")  # Query for remote pre Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            (yield self.tock)


        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True  # return value of yield from, or yield ex.value of StopIteration


class VicDirector(directing.Director):
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

    def __init__(self, hab, witnessClient, peerClient, verifier, exchanger, jsonSchema, proofs, **kwa):
        """

            verifier is Verifier instance of local controller's TEL context
        """
        super().__init__(hab, witnessClient, **kwa)
        self.peerClient = peerClient
        self.verifier = verifier
        self.exchanger = exchanger
        self.jsonSchema = jsonSchema
        self.proofs = proofs
        if self.tymth:
            self.peerClient.wind(self.tymth)


    def do(self, tymth=None, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            # enter context
            self.wind(tymth)  # change tymist and dependencies
            self.tock = tock

            tyme = (yield self.tock)  # yields tock then waits

            while not self.client.connected:
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.client.ha)
                tyme = (yield self.tock)

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)

            while not self.peerClient.connected:
                logger.info("%s:\n waiting for connection to remote %s.\n\n",
                            self.hab.pre, self.peerClient.ha)
                tyme = (yield self.tock)

            logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.peerClient.ha)

            msg = self.hab.makeOwnEvent(sn=0)
            # send to connected remote
            self.peerClient.tx(msg)
            logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msg))
            tyme = (yield self.tock)

            ref = scheming.jsonSchemaCache.resolve("EeCCZi1R5xHUlhsyQNm_7NrUQTEKZH5P9vBomnc9AihY")
            schemer = scheming.Schemer(raw=ref)

            pl = dict(
                input_descriptors=[
                    dict(x=schemer.said)
                ]
            )

            logger.info("%s: \n requesting presentation for schema %s\n\n", self.hab.pre, schemer.said)

            excSrdr = exchanging.exchange(route="/presentation/request", payload=pl)
            excMsg = self.hab.sanction(excSrdr)

            self.peerClient.tx(excMsg)
            tyme = (yield self.tock)

            while not self.proofs:
                logger.info("%s:\n waiting for proof presentation from %s.\n\n",
                            self.hab.pre, self.peerClient.ha)
                tyme = (yield self.tock)

            _, presentation = self.proofs.pop()

            vc = presentation["vc"]
            body = vc["d"]
            proof = bytearray(presentation["proof"].encode("utf-8"))

            creder = proving.Credentialer(crd=vc, typ=self.jsonSchema)
            prefixer, seqner, diger, isigers = walleting.parseProof(proof)

            vcid = creder.said

            issuerPre = creder.issuer
            issuerpre = issuerPre.removeprefix("did:keri:")

            regk = creder.status["id"]

            msg = self.hab.query(issuerpre, res="logs")  # Query for remote pre Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            logger.info("Loading Registry and Credential TEL")
            msg = self.verifier.query(regk,
                                      vcid,
                                      res="tels")
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            while regk not in self.verifier.tevers:
                logger.info("%s:\n waiting for retrieval of TEL %s.\n\n",
                            self.hab.pre, regk)
                tyme = (yield (self.tock))

            valid = self.hab.verify(creder, prefixer, seqner, diger, isigers)
            if valid is True:
                sub = creder.subject
                logger.info("%s:\n\n\n Valid vLEI credential for LEI: %s.\n\n",
                            self.hab.pre, sub["lei"])
            else:
                logger.error("%s:\n\n\n Invalid vLEI credential.\n\n",
                             self.hab.pre)

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

            msg = self.hab.query(self.remotePre, res="logs")  # Query for remote pre Event
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
