# -*- encoding: utf-8 -*-
"""
KERI
keri.app.directing module

simple direct mode demo support classes
"""

import os
import json
from urllib import parse

from hio.base import doing
from hio.core import wiring
from hio.core.tcp import clienting, serving

from .. import kering
from ..core.coring import Matter, MtrDex, Diger
from ..db import dbing, basing
from ..core import coring, eventing
from ..app import habbing, keeping, directing

from .. import help
from ..help import helping
from ..vdr.issuing import Issuer

logger = help.ogler.getLogger()


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
            self.client.tx(msg)   # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.interact()  # Interaction event
            self.client.tx(msg)   # send to connected remote
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
            msgs.append(self.hab.interact()) # Interaction event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.rotate())  # Rotation event
            msgs.append(self.hab.interact())

            msgs.reverse()  # reverse the order

            for msg in msgs:
                self.client.tx(msg)   # send to connected remote
                logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
                tyme = (yield (self.tock))


            tyme = (yield (self.tock))

        except GeneratorExit:  # close context, forced exit due to .close
            pass

        except Exception:  # abort context, forced exit due to uncaught exception
            raise

        finally:  # exit context,  unforced exit due to normal exit of try
            pass

        return True # return value of yield from, or yield ex.value of StopIteration


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
    def __init__(self, vcfile, recipientIdentifier, lei, hab, issuer, client, **kwa):
        super().__init__(hab, client, **kwa)
        self.issuer = issuer
        self.vcfile=vcfile
        self.recipientIdentifier = recipientIdentifier
        self.lei = lei

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
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            msg = self.hab.rotate()  # Rotation Event
            self.client.tx(msg)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
            tyme = (yield (self.tock))

            now = helping.nowIso8601()
            vlei = dict(
                type=[
                    "VerifiableCredential",
                    "vLEIGLEIFCredential"
                ],
            )
            cred = dict(vlei)
            cred['id'] = "{}".format("#" * Matter.Codes[MtrDex.Blake3_256].fs)
            cred['issuer'] = f"did:keri:{self.hab.pre}"
            cred['issuanceDate'] = now
            cred['credentialSubject'] = dict(
                id=f"did:keri:{self.recipientIdentifier}",
                lei=self.lei
            )

            vcdig = Diger(raw=json.dumps(cred).encode("utf-8"))
            cred['id'] = f"did:keri:{vcdig.qb64}"
            msg = json.dumps(cred).encode("utf-8")

            cigers = self.hab.mgr.sign(ser=msg, verfers=self.hab.kever.verfers, indexed=False)

            cred['proof'] = dict(
                type=[
                    "KERISignature2021"
                ],
                created=now,
                jws=cigers[0].qb64,
                verificationMethod=f"did:keri:{self.hab.pre}/{self.issuer.regk}#0",
                proofPurpose="assertionMethod"
            )

            tevt, kevt = self.issuer.issue(vcdig=vcdig.qb64)
            self.client.tx(kevt)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(kevt))
            tyme = (yield (self.tock))

            self.client.tx(tevt)  # send to connected remote
            logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(tevt))
            tyme = (yield (self.tock))

            with open(self.vcfile, "w") as f:
                f.write(json.dumps(cred, indent=4))

            logger.info("%s:\n\n\n Wrote Verifiable Credential for LEI: %s to file %s.\n\n",
                        self.hab.pre, self.lei, self.vcfile)

            input("wait for verification")
            (yield self.tock)

            tevt, kevt = self.issuer.revoke(vcdig=vcdig.qb64)
            logger.info("%s:\n\n\n Revoked Verifiable Credential for LEI: %s to file %s.\n\n",
                        self.hab.pre, self.lei, self.vcfile)
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

    def __init__(self, vcfile, hab, client, verifier, **kwa):
        """

            verifier is Verifier instance of local controller's TEL context
        """
        super().__init__(hab, client, **kwa)
        self.vcfile=vcfile
        self.verifier = verifier

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

            with open(self.vcfile, "r") as f:
                vc = json.load(fp=f)
                vcid = vc["id"]
                vcid = vcid.removeprefix("did:keri:")

                issuerPre = vc["issuer"]
                issuerpre = issuerPre.removeprefix("did:keri:")

                msg = self.hab.query(issuerpre, res="logs")  # Query for remote pre Event
                self.client.tx(msg)  # send to connected remote
                logger.info("%s sent event:\n%s\n\n", self.hab.pre, bytes(msg))
                tyme = (yield (self.tock))

                # extract proof from VC
                proof = vc.pop("proof")
                vcdata = json.dumps(vc).encode("utf-8")
                vcsig = proof["jws"]
                method = proof["verificationMethod"]
                url = parse.urlsplit(method)

                if url.scheme != "did":
                    logger.error("%s:\n Invalid verification method scheme %s.\n\n",
                                 self.hab.pre, url.scheme)

                (pre, regk) = url.path.removeprefix("keri:").split("/")

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

                tyme = (yield (self.tock))
                sidx = int(url.fragment)

                valid = self.verifier.verify(pre=pre,
                                             sidx=sidx,
                                             regk=regk,
                                             vcid=vcid,
                                             vcdata=vcdata,
                                             vcsig=vcsig)

                if valid is True:
                    sub = vc["credentialSubject"]
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


def setupDemoController(secrets, name="who", remotePort=5621, localPort=5620, indirect=False, remotePre=""):
    """
    Setup and return doers list to run controller
    """
    secrecies = []
    for secret in secrets:  # convert secrets to secrecies
        secrecies.append([secret])

    # setup habitat
    hab = habbing.Habitat(name=name, secrecies=secrecies, temp=True)
    logger.info("\nDirect Mode demo of %s:\nNamed %s on TCP port %s to port %s.\n\n",
                 hab.pre, hab.name, localPort, remotePort)

    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)  # doer do reopens if not opened and closes
    dbDoer = basing.BaserDoer(baser=hab.db)  # doer do reopens if not opened and closes

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

    return [ksDoer, dbDoer, wireDoer, clientDoer, director, reactor, serverDoer, directant]

