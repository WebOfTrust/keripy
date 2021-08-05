# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import random

from hio.base import doing
from hio.core import http
from hio.core.tcp import clienting
from hio.help import decking

from keri import kering
from .. import help
from ..app import obtaining
from ..core import eventing, parsing, scheming, coring
from ..db import dbing
from ..help import helping
from ..peer import exchanging, httping
from ..vc import proving, handling
from ..vdr import issuing

logger = help.ogler.getLogger()


class WitnessReceiptor(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propogates those receipts to each
    of the other witnesses after receiving the complete set.

    Removes all Doers and exits as Done once all witnesses have been sent the entire
    receipt set.  Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hab, msg=None, klas=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses
            msg: is the message to send to all witnesses.
                 Defaults to sending the latest KEL event if msg is None

        """
        self.hab = hab
        self.msg = msg
        self.klas = klas if klas is not None else HTTPWitnesser
        super(WitnessReceiptor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)


    def receiptDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        sn = self.hab.kever.sn
        wits = self.hab.kever.wits

        if len(wits) == 0:
            return True

        msg = self.msg if self.msg is not None else self.hab.makeOwnEvent(sn=sn)
        ser = coring.Serder(raw=msg)

        witers = []
        for wit in wits:
            witer = self.klas(hab=self.hab, wit=wit)
            witers.append(witer)
            witer.msgs.append(bytearray(msg))  # make a copy
            self.extend([witer])

            _ = (yield self.tock)


        while True:
            dgkey = dbing.dgKey(ser.preb, ser.digb)
            wigs = self.hab.db.getWigs(dgkey)
            if len(wigs) == len(wits):
                break
            _ = yield self.tock

        # generate all rct msgs to send to all witnesses
        wigers = [coring.Siger(qb64b=bytes(wig)) for wig in wigs]
        rserder = eventing.receipt(pre=ser.pre,
                                   sn=sn,
                                   dig=ser.dig)
        rctMsg = eventing.messagize(serder=rserder, wigers=wigers)

        # this is a little brute forcey and can be improved by gathering receipts
        # along the way and passing them out as we go and only sending the
        # required ones here
        for witer in witers:
            witer.msgs.append(bytearray(rctMsg))
            _ = (yield self.tock)

        total = len(witers) * 2
        count = 0
        while count < total:
            for witer in witers:
                count += len(witer.sent)
            _ = (yield self.tock)

        self.remove(witers)

        return True


class WitnessInquisitor(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propogates those receipts to each
    of the other witnesses after receiving the complete set.

    Removes all Doers and exits as Done once all witnesses have been sent the entire
    receipt set.  Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hab, msgs=None, klas=None, **kwa):
        """
        For all msgs, select a random witness from Habitat's current set of witnesses
        send the msg and process all responses (KEL replays, RCTs, etc)

        Parameters:
            hab: Habitat of the identifier to use to identify witnesses
            msgs: is the message buffer to process and send to one random witness.

        """
        self.hab = hab
        self.klas = klas if klas is not None else HTTPWitnesser
        self.msgs = msgs if msgs is not None else decking.Deck()

        super(WitnessInquisitor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)


    def receiptDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        wits = self.hab.kever.wits
        if len(wits) == 0:
            raise kering.ConfigurationError("Must be used with an identifier that has witnesses")

        witers = []
        for wit in wits:
            witer = self.klas(hab=self.hab, wit=wit, lax=True, local=False)
            witers.append(witer)

        self.extend(witers)

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()

            witer = random.choice(witers)
            witer.msgs.append(msg)

            yield

    def query(self, pre, res="logs"):
        msg = self.hab.query(pre, res=res)  # Query for remote pre Event
        self.msgs.append(msg)


class WitnessSender(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and exits.

    Removes all Doers and exits as Done once all witnesses have been sent the message.
    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hab, msg, klas=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses
            msg: is the message to send to all witnesses.
                 Defaults to sending the latest KEL event if msg is None

        """
        self.hab = hab
        self.msg = msg
        self.klas = klas if klas is not None else HTTPWitnesser
        super(WitnessSender, self).__init__(doers=[doing.doify(self.sendDo)], **kwa)


    def sendDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        wits = self.hab.kever.wits

        if len(wits) == 0:
            return True

        witers = []
        for wit in wits:
            witer = self.klas(hab=self.hab, wit=wit)
            witers.append(witer)
            witer.msgs.append(bytearray(self.msg))  # make a copy so every munges their own
            self.extend([witer])

            _ = (yield self.tock)

        total = len(witers)
        count = 0
        while count < total:
            for witer in witers:
                count += len(witer.sent)
            _ = (yield self.tock)

        self.remove(witers)
        return True


class TCPWitnesser(doing.DoDoer):
    """

    """

    def __init__(self, hab, wit, msgs=None, sent=None, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        self.wit = wit
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.receiptDo), doing.doify(self.escrowDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      **kwa)

        super(TCPWitnesser, self).__init__(doers=doers)


    def receiptDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        loc = obtaining.getwitnessbyprefix(self.wit)
        client = clienting.Client(host=loc.ip4, port=loc.tcp)
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

        clientDoer = clienting.ClientDoer(client=client)
        self.extend([clientDoer, doing.doify(self.msgDo)])

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()

            client.tx(msg)  # send to connected remote

            while client.txbs:
                yield self.tock

            self.sent.append(msg)
            yield self.tock


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
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
            add result of doify on this method to doers list
        """
        yield from self.parser.parsator()  # process messages continuously

    def escrowDo(self, tymth=None, tock=0.0, **opts):
        yield  # enter context
        while True:
            self.kevery.processEscrows()
            yield



class HTTPWitnesser(doing.DoDoer):
    """
    Interacts with Witnesses on HTTP and SSE for sending events and receiving receipts

    """

    def __init__(self, hab, wit, msgs=None, sent=None, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        self.wit = wit
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.msgDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        super(HTTPWitnesser, self).__init__(doers=doers, **kwa)


    def msgDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        loc = obtaining.getwitnessbyprefix(self.wit)

        client = http.clienting.Client(hostname=loc.ip4, port=loc.http)
        clientDoer = http.clienting.ClientDoer(client=client)

        self.extend([clientDoer])

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()

            httping.createCESRRequest(msg, client)
            while client.requests:
                yield self.tock

            self.sent.append(msg)
            yield self.tock


class RotateHandler(doing.DoDoer):
    """
        Processor for a performing a key rotate in an agent.
        {
            sith=3,
            count=5,
            erase=False,
            toad=1,
            cuts=[],
            adds=[],
            data=[
               {}
            ]
        }
    """

    resource = "/cmd/rotate"

    def __init__(self, hab, cues=None, **kwa):
        self.hab = hab
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.msgDo)]

        super(RotateHandler, self).__init__(doers=doers, **kwa)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Rotate identifier.

        Messages:
            payload is dict representing the body of a /presentation/request message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/request message
            verfers is list of Verfers of the keys used to sign the message

        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]

                if "count" not in payload:
                    logger.info("unable to rotate without a count of next signing keys")
                    return

                count = payload["count"]

                sith = payload["sith"] if "sith" in payload else None
                erase = payload["erase"] if "erase" in payload else None
                toad = payload["toad"] if "toad" in payload else None
                cuts = payload["cuts"] if "cuts" in payload else None
                adds = payload["adds"] if "adds" in payload else None
                data = payload["data"] if "data" in payload else None

                # start a witnesser to take care of sending receipts
                witDoer = WitnessReceiptor(hab=self.hab)
                self.extend([witDoer])

                self.hab.rotate(count=count, sith=sith, erase=erase, toad=toad, cuts=cuts, adds=adds, data=data)

                ser = self.hab.kever.serder
                wits = self.hab.kever.wits

                while True:
                    dgkey = dbing.dgKey(ser.preb, ser.digb)

                    rcts = self.hab.db.getWigs(dgkey)
                    if len(rcts) == len(wits):
                        break
                    yield

                self.remove(doers=[witDoer])

                logger.info('Prefix\t\t{%s}', self.hab.pre)
                for idx, verfer in enumerate(self.hab.kever.verfers):
                    logger.info('Public key %d:\t%s', idx + 1, verfer.qb64)
                logger.info("")

                yield

            yield


class IssueCredentialHandler(doing.DoDoer):
    """
        IssueCredentialHandler - exn behavior for issuing a credential

        Validates payload against specified JSON-Schema
        Receipts KEL event and propagates TEL event to witnesses
        Errors will be placed in the corresponding issuer
    """

    resource = "/cmd/credential/issue"

    def __init__(self, hab, cues=None, **kwa):
        self.hab = hab
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.issuer = issuing.Issuer(hab=hab, name=self.hab.name, noBackers=True)
        self.issuerDoer = issuing.IssuerDoer(issuer=self.issuer)

        doers = [doing.doify(self.msgDo), self.issuerDoer]

        super(IssueCredentialHandler, self).__init__(doers=doers, **kwa)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """

        while not self.issuer.incept:
            yield self.tock

        kevt = self.issuer.incept
        tevt = self.issuer.ianchor

        witDoer = WitnessReceiptor(hab=self.hab, msg=kevt)
        self.extend([witDoer])

        witSender = WitnessSender(hab=self.hab, msg=tevt)
        self.extend([witSender])


        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]

                recipientIdentifier = payload["recipient"]
                credSubject = payload["data"]
                schema = payload["schema"]
                # not all credentials have a source
                source = payload.get("source")

                ref = scheming.jsonSchemaCache.resolve(schema)
                schemer = scheming.Schemer(raw=ref)
                jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)

                if type(credSubject) is dict:
                    credSubject |= dict(si=recipientIdentifier,
                                        credentialStatus=self.issuer.regk,
                                        issuanceDate=helping.nowIso8601())

                # Build the credential subject and then the Credentialer for the full credential
                creder = proving.credential(issuer=self.hab.pre,
                                            schema=schemer.said,
                                            subject=credSubject,
                                            typ=jsonSchema,
                                            source=source)

                msg = self.hab.endorse(serder=creder)

                tevt, kevt = self.issuer.issue(vcdig=creder.said)

                witDoer = WitnessReceiptor(hab=self.hab, msg=kevt)
                self.extend([witDoer])

                witSender = WitnessSender(hab=self.hab, msg=tevt)
                self.extend([witSender])

                pl = dict(
                    vc=[handling.envelope(msg, typ=jsonSchema)]
                )

                self.cues.append(
                    exchanging.exchange(route="/credential/issue", payload=pl, recipient=recipientIdentifier))
                yield

            yield


class PresentationRequestHandler(doing.DoDoer):
    """
    """

    resource = "/cmd/presentation/request"

    def __init__(self, hab, cues=None, **kwa):
        self.hab = hab
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.msgDo)]

        super(PresentationRequestHandler, self).__init__(doers=doers, **kwa)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]

                recipientIdentifier = payload["recipient"]
                schema = payload["schema"]

                ref = scheming.jsonSchemaCache.resolve(schema)
                schemer = scheming.Schemer(raw=ref)

                pl = dict(
                    input_descriptors=[
                        dict(x=schemer.said)
                    ]
                )

                self.cues.append(
                    exchanging.exchange(route="/presentation/request", payload=pl, recipient=recipientIdentifier))
                yield

            yield


class EchoHandler(doing.DoDoer):
    """
        Processor for testing end to end HTTP with mailbox
        {
            msg="",
        }
    """

    resource = "/cmd/echo"

    def __init__(self, cues=None, **kwa):
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.msgDo)]

        super(EchoHandler, self).__init__(doers=doers, **kwa)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Echo the proviced message back to the sender

        Messages:
            payload is dict representing the body of a /presentation/request message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/request message
            verfers is list of Verfers of the keys used to sign the message

        Returns doifiable Doist compatibile generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                rcp = msg["pre"]

                msg = payload["msg"]

                resp = dict(
                    echo=msg
                )

                serder = exchanging.exchange(route="/cmd/message", payload=resp, recipient=rcp.qb64)
                self.cues.append(serder)

                yield

            yield
