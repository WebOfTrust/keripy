# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
from hio.base import doing
from hio.core.tcp import clienting

from ..app import obtaining
from ..core import eventing, parsing, scheming
from ..db import dbing
from ..help import decking, helping
from ..peer import exchanging
from ..vc import proving, handling
from ..vdr import issuing
from .. import help

logger = help.ogler.getLogger()


class AgentController:
    """

    """

    def __init__(self, hab, issuer, **kwa):
        """

        Parameters:
            hab (Habitat):
            issuer (Issuer):

        """
        self.hab = hab
        self.issuer = issuer



class WitnessReceiptor(doing.DoDoer):

    def __init__(self, hab, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        super(WitnessReceiptor, self).__init__(doers=[self.receiptDo], **kwa)


    @doing.doize()
    def receiptDo(self, tymth=None, tock=0.0, **opts):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        sn = self.hab.kever.sn
        wits = self.hab.kever.wits

        msg = self.hab.makeOwnEvent(sn=sn)

        for wit in wits:
            witer = Witnesser(hab=self.hab, wit=wit, msg=msg)
            self.extend([witer])
            _ = (yield self.tock)


class Witnesser(doing.DoDoer):
    def __init__(self, hab, wit, msg, doers=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab: Habitat of the identifier to populate witnesses

        """
        self.hab = hab
        self.wit = wit
        self.msg = msg
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([self.receiptDo])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        super(Witnesser, self).__init__(doers=doers, **kwa)


    @doing.doize()
    def receiptDo(self, tymth=None, tock=0.0, **opts):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        loc = obtaining.getwitnessbyprefix(self.wit)
        client = clienting.Client(host=loc.ip4, port=loc.tcp)
        self.parser = parsing.Parser(ims=client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

        clientDoer = clienting.ClientDoer(client=client)
        self.extend([clientDoer, self.msgDo])

        client.tx(self.msg)   # send to connected remote


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
        done = yield from self.parser.parsator()  # process messages continuously
        return done  # should nover get here except forced close


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
                    logger.info('Public key %d:\t%s', idx+1, verfer.qb64)
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

                recptAddy = obtaining.getendpointbyprefix(recipientIdentifier)
                rcptClient = clienting.Client(host=recptAddy.ip4, port=recptAddy.tcp)
                rcptClientDoer = clienting.ClientDoer(client=rcptClient)

                self.extend([rcptClientDoer])

                now = helping.nowIso8601()

                ref = scheming.jsonSchemaCache.resolve(schema)
                schemer = scheming.Schemer(raw=ref)
                jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)

                # Build the credential subject and then the Credentialer for the full credential
                creder = proving.credential(issuer=self.hab.pre,
                                            schema=schemer.said,
                                            subject=credSubject,
                                            issuance=now,
                                            regk=self.issuer.regk,
                                            typ=jsonSchema)

                msg = self.hab.endorse(serder=creder)

                tevt, kevt = self.issuer.issue(vcdig=creder.said)

                # # TODO: figure out how to send these to my witnesses
                # self.client.tx(kevt)  # send to connected remote
                # tyme = (yield self.tock)
                #
                # self.client.tx(tevt)  # send to connected remote
                # tyme = (yield self.tock)

                pl = dict(
                    vc=[handling.envelope(msg, typ=jsonSchema)]
                )

                excSrdr = exchanging.exchange(route="/credential/issue", payload=pl, recipient=recipientIdentifier)
                excMsg = self.hab.sanction(excSrdr)

                rcptClient.tx(excMsg)

                yield

            yield
