# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
from hio.base import doing
from hio.core.tcp import clienting
from hio.core import http
from hio.help import decking
from keri.core import coring
from keri.peer import httping

from .. import help
from ..app import obtaining
from ..core import eventing, parsing, scheming
from ..db import dbing
from ..peer import exchanging
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
        super(WitnessReceiptor, self).__init__(doers=[self.receiptDo], **kwa)

    @doing.doize()
    def receiptDo(self, tymth=None, tock=0.0, **opts):
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        ser = self.hab.kever.serder
        sn = self.hab.kever.sn
        wits = self.hab.kever.wits

        if len(wits) == 0:
            return True

        msg = self.msg if self.msg is not None else self.hab.makeOwnEvent(sn=sn)

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
        super(WitnessSender, self).__init__(doers=[self.sendDo], **kwa)

    @doing.doize()
    def sendDo(self, tymth=None, tock=0.0, **opts):
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
            witer.msgs.append(self.msg)
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
        doers.extend([self.receiptDo])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        super(TCPWitnesser, self).__init__(doers=doers, **kwa)

    @doing.doize()
    def receiptDo(self, tymth=None, tock=0.0):

        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()

            loc = obtaining.getwitnessbyprefix(self.wit)
            client = clienting.Client(host=loc.ip4, port=loc.tcp)
            self.parser = parsing.Parser(ims=client.rxbs,
                                         framed=True,
                                         kvy=self.kevery)

            clientDoer = clienting.ClientDoer(client=client)
            self.extend([clientDoer, self.msgDo])

            client.tx(msg)  # send to connected remote

            while client.txbs:
                yield self.tock

            self.sent.append(msg)
            yield self.tock

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
        yield from self.parser.parsator()  # process messages continuously


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
        doers.extend([self.msgDo])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        super(HTTPWitnesser, self).__init__(doers=doers, **kwa)

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0):

        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()

            loc = obtaining.getwitnessbyprefix(self.wit)

            client = http.clienting.Client(hostname=loc.ip4, port=loc.http)
            clientDoer = http.clienting.ClientDoer(client=client)

            self.extend([clientDoer])

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

        doers = [self.msgDo]

        super(RotateHandler, self).__init__(doers=doers, **kwa)

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Rotate identifier.

        Messages:
            payload is dict representing the body of a /presentation/request message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/request message
            verfers is list of Verfers of the keys used to sign the message

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

    resource = "/cmd/credential/issue"

    def __init__(self, hab, cues=None, **kwa):
        self.hab = hab
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        self.issuer = issuing.Issuer(hab=hab, name=self.hab.name, noBackers=True)
        issuerDoer = issuing.IssuerDoer(issuer=self.issuer)

        doers = [self.msgDo, issuerDoer]

        super(IssueCredentialHandler, self).__init__(doers=doers, **kwa)

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Rotate identifier.

        Messages:
            payload is dict representing the body of a /presentation/request message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/request message
            verfers is list of Verfers of the keys used to sign the message

        """
        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]

                recipientIdentifier = payload["recipient"]
                credSubject = payload["data"]
                schema = payload["schema"]
                # not all credentials have a source
                source = payload.get("source")

                recptAddy = obtaining.getendpointbyprefix(recipientIdentifier)
                rcptClient = clienting.Client(host=recptAddy.ip4, port=recptAddy.tcp)
                rcptClientDoer = clienting.ClientDoer(client=rcptClient)

                self.extend([rcptClientDoer])

                ref = scheming.jsonSchemaCache.resolve(schema)
                schemer = scheming.Schemer(raw=ref)
                jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)

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

                excSrdr = exchanging.exchange(route="/credential/issue", payload=pl, recipient=recipientIdentifier)
                excMsg = self.hab.sanction(excSrdr)

                rcptClient.tx(excMsg)

                yield

            yield
