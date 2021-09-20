# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json
import random

import falcon
from falcon import media
from hio.base import doing
from hio.core import http
from hio.core.tcp import clienting
from hio.help import decking

from . import httping, grouping
from .. import help
from .. import kering
from ..app import obtaining
from ..core import eventing, parsing, scheming, coring
from ..db import dbing
from ..help import helping
from ..help.helping import nowIso8601
from ..peer import exchanging
from ..vc import proving, handling
from ..vdr import registering, viring, issuing

logger = help.ogler.getLogger()


class WitnessReceiptor(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propagates those receipts to each
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
        self.klas = klas if klas is not None else HttpWitnesser
        super(WitnessReceiptor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)


    def receiptDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters

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

        dgkey = dbing.dgKey(ser.preb, ser.digb)
        while True:
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
    for receipts from each of those witnesses and propagates those receipts to each
    of the other witnesses after receiving the complete set.

    Removes all Doers and exits as Done once all witnesses have been sent the entire
    receipt set.  Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hab, msgs=None, wits=None, klas=None, **kwa):
        """
        For all msgs, select a random witness from Habitat's current set of witnesses
        send the msg and process all responses (KEL replays, RCTs, etc)

        Parameters:
            hab: Habitat of the identifier to use to identify witnesses
            msgs: is the message buffer to process and send to one random witness.

        """
        self.hab = hab
        self.wits = wits
        self.klas = klas if klas is not None else HttpWitnesser
        self.msgs = msgs if msgs is not None else decking.Deck()

        super(WitnessInquisitor, self).__init__(doers=[doing.doify(self.receiptDo)], **kwa)

    def receiptDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        wits = self.wits if self.wits is not None else self.hab.kever.wits
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

    def query(self, pre, r="logs", sn=0):
        msg = self.hab.query(pre, res=r, query=dict())  # Query for remote pre Event
        self.msgs.append(msg)


class WitnessPublisher(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and exits.

    Removes all Doers and exits as Done once all witnesses have been sent the message.
    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.

    """

    def __init__(self, hab, msg, wits=None, klas=None, **kwa):
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
        self.wits = wits if wits is not None else self.hab.kever.wits
        self.klas = klas if klas is not None else HttpWitnesser
        super(WitnessPublisher, self).__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if len(self.wits) == 0:
            return True

        witers = []
        for wit in self.wits:
            witer = self.klas(hab=self.hab, wit=wit)
            witers.append(witer)
            witer.msgs.append(bytearray(self.msg))  # make a copy so everyone munges their own
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
        Returns doifiable Doist compatible generator method (doer dog)

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
        Returns doifiable Doist compatible generator method (doer dog) to process
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


class HttpWitnesser(doing.DoDoer):
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
        doers.extend([doing.doify(self.msgDo), doing.doify(self.responseDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      lax=False,
                                      local=True)

        loc = obtaining.getwitnessbyprefix(self.wit)

        self.client = http.clienting.Client(hostname=loc.ip4, port=loc.http)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        doers.extend([clientDoer])

        super(HttpWitnesser, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.msgs:
                yield self.tock

            msg = self.msgs.popleft()

            httping.createCESRRequest(msg, self.client)
            while self.client.requests:
                yield self.tock

            yield self.tock

    def responseDo(self, tymth=None, tock=0.0):
        """
        Processes responses from client and adds them to sent cue

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.client.responses:
                rep = self.client.respond()

                self.sent.append(rep)
                yield
            yield


class KiwiServer(doing.DoDoer):
    """
    Routes for handling UI requests for Credential issuance/revocation and presentation requests

    """

    def __init__(self, hab, controller, rep, verifier, issuers=None, cues=None, app=None, insecure=False, **kwa):
        """
        Create a KIWI web server for Agents capable of performing KERI and ACDC functions for the controller
        of an identifier.

        Parameters:
            hab Habitat is the environment of the identifier prefix
            controller qb64 is the identifier prefix that can send commands to this web server:
            rep Respondant that routes responses to the appropriate mailboxes
            issuers is dict of credential Issuers keyed by regk of credential Registry
            wallet is Wallet for local storage of credentials
            cues is Deck from Kevery handling key events:
            app falcon.App to register handlers with:
            insecure bool is True to allow requests without verifying KERI Http Signature Header,
                defaults to False

        """
        self.hab = hab
        self.controller = controller
        self.rep = rep
        self.verifier = verifier
        self.issuerCues = decking.Deck()
        self.app = app if app is not None else falcon.App(cors_enable=True)
        self.issuers = issuers if issuers is not None else dict()
        self.typ = scheming.JSONSchema()

        if insecure:
            self.app.add_middleware(httping.InsecureSignatureComponent())
        else:
            self.app.add_middleware(httping.SignatureValidationComponent(hab=hab, pre=controller))

        self.app.req_options.media_handlers.update(media.Handlers())
        self.app.resp_options.media_handlers.update(media.Handlers())
        self.cues = cues if cues is not None else decking.Deck()

        self.app.add_route("/id", self, suffix="id")
        self.app.add_route("/registry/incept", self, suffix="registry_incept")
        self.registryIcpr = registering.RegistryInceptDoer(hab=hab)
        self.app.add_route("/credential/issue", self, suffix="issue")
        self.app.add_route("/credential/revoke", self, suffix="revoke")

        self.app.add_route("/credentials/issued", self, suffix="credentials_issued")

        self.app.add_route("/presentation/request", self, suffix="request")

        self.app.add_route("/multisig/incept", self, suffix="multisig_incept")
        self.app.add_route("/multisig/rotate", self, suffix="multisig_rotate")
        self.app.add_route("/multisig", self, suffix="multisig")
        self.gdoer = grouping.MultiSigGroupDoer(hab=hab)

        self.witq = WitnessInquisitor(hab=hab, klas=TCPWitnesser)

        doers = [self.witq, self.registryIcpr, self.gdoer, doing.doify(self.verifierDo), doing.doify(
            self.issuerDo), doing.doify(self.groupCueDo)]

        super(KiwiServer, self).__init__(doers=doers, **kwa)


    def verifierDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from Verifier coroutine

            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.verifier.cues:
                cue = self.verifier.cues.popleft()
                cueKin = cue["kin"]

                if cueKin == "saved":
                    creder = cue["creder"]
                    proof = cue["proof"]

                    recpt = creder.subject["si"].encode("utf-8")

                    craw = bytearray(creder.raw)
                    craw.extend(proof)

                    pl = dict(
                        vc=[handling.envelope(craw, typ=self.typ)]
                    )

                    exn = exchanging.exchange(route="/credential/issue", payload=pl)
                    self.rep.reps.append(dict(dest=recpt, rep=exn, topic="credential"))

                    logger.info("Credential: %s, Schema: %s,  Saved", creder.said, creder.schema)
                    logger.info(creder.pretty())
                    print()

                elif cueKin == "query":
                    qargs = cue["q"]
                    self.witq.query(**qargs)

                yield self.tock
            yield self.tock


    def issuerDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from credential issue coroutine

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters
        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.issuerCues:
                cue = self.issuerCues.popleft()
                cueKin = cue['kin'] 
                if cueKin == "send":
                    tevt = cue["tevt"]
                    witSender = WitnessPublisher(hab=self.hab, msg=tevt)
                    self.extend([witSender])
    
                    while not witSender.done:
                        _ = yield self.tock
    
                    self.remove([witSender])
                elif cueKin == "kevt":
                    kevt = cue["kevt"]
                    witDoer = WitnessReceiptor(hab=self.hab, msg=kevt)
                    self.extend([witDoer])
    
                    while not witDoer.done:
                        yield self.tock
    
                    self.remove([witDoer])
                elif cueKin == "multisig":
                    msg = dict(
                        op=cue["op"],
                        group=cue["group"],
                        data=cue["data"],
                        reason=cue["reason"]
                    )
                    self.gdoer.msgs.append(msg)

                yield self.tock
            yield self.tock


    def groupCueDo(self, tymth, tock=0.0, **opts):
        """
        Process cues from multisig group coroutine

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value
            opts is dict of injected optional additional parameters

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.gdoer.cues:
                cue = self.gdoer.cues.popleft()
                # exn = exchanging.exchange(route="/multisig/results", payload=cue, date=helping.nowIso8601())
                # self.rep.reps.append(dict(dest=self.controller, rep=exn, topic="multisig"))

                yield self.tock

            yield self.tock


    def on_post_issue(self, req, rep):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        Body:
            name: The human readable name of the new registry to create

        """
        body = json.loads(req.context.raw)
        registry = body.get("registry")
        schema = body.get("schema")
        source = body.get("source")
        recipientIdentifier = body.get("recipient")

        issuer = self.getIssuer(name=registry)
        if issuer is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(registry)
            return

        types = ["VerifiableCredential", body.get("type")]

        data = body.get("credentialData")

        d = dict(
            i="",
            type=types,
            si=recipientIdentifier,
            dt=nowIso8601()
        )

        d |= data

        saider = scheming.Saider(sad=d, code=coring.MtrDex.Blake3_256, label=scheming.Ids.i)
        d["i"] = saider.qb64

        ref = scheming.jsonSchemaCache.resolve(schema)
        schemer = scheming.Schemer(raw=ref)
        jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)

        creder = proving.credential(issuer=self.hab.pre,
                                    schema=schemer.said,
                                    subject=d,
                                    typ=jsonSchema,
                                    source=source,
                                    status=issuer.regk)



        try:
            issuer.issue(creder=creder)
        except kering.MissingAnchorError:
            logger.info("Missing anchor from credential issuance due to multisig identifier")

        craw = self.hab.endorse(creder)
        proving.parseCredential(ims=craw, verifier=self.verifier, typ=self.typ)

        rep.status = falcon.HTTP_200
        rep.data = creder.pretty().encode("utf-8")


    def on_post_revoke(self, req, rep):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        Body:
            name: The human readable name of the new registry to create

        """
        body = json.loads(req.context.raw)
        registry = body.get("registry")
        said = body.get("said")

        issuer = self.getIssuer(name=registry)
        if issuer is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(registry)
            return

        try:
            issuer.revoke(vcdig=said)
        except kering.ValidationError as ex:
            rep.status = falcon.HTTP_CONFLICT
            rep.text = ex.args[0]
            return

        rep.status = falcon.HTTP_202

    def on_post_request(self, req, rep):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        Body:
            recipient: SCID of recipient of credential to request
            schema:  SAID of schema

        """
        body = json.loads(req.context.raw)
        recipientIdentifier = body.get("recipient")
        schema = body.get("schema")

        ref = scheming.jsonSchemaCache.resolve(schema)
        schemer = scheming.Schemer(raw=ref)

        pl = dict(
            input_descriptors=[
                dict(x=schemer.said)
            ]
        )

        exn = exchanging.exchange(route="/presentation/request", payload=pl)
        self.rep.reps.append(dict(dest=recipientIdentifier, rep=exn, topic="credential"))

        rep.status = falcon.HTTP_202

    def on_post_multisig_rotate(self, req, rep):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        Body:
            name: The human readable name of the new registry to create

        """
        body = json.loads(req.context.raw)

        if "group" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group rotate request, 'group' is required'"
            return

        msg = dict(
            sith=None,
            toad=None,
            data=None,
            witnesses=[],
            witness_cuts=[],
            witness_adds=[],
        )

        for key in msg:
            if key in body:
                msg[key] = body[key]

        msg["op"] = grouping.Ops.rot
        msg["group"] = body["group"]

        self.gdoer.msgs.append(msg)

        rep.status = falcon.HTTP_202

    def on_post_multisig_incept(self, req, rep):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        Body:
            name: The human readable name of the new registry to create

        """
        body = json.loads(req.context.raw)

        if "group" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group inception request, 'group' is required'"
            return

        if "aids" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group inception request, 'aids' is required'"
            return

        aids = body["aids"]

        notify = body["notify"] if "notify" in body else True

        msg = dict(
            aids=aids,
            toad=None,
            witnesses=[],
            isith=None,
            nsith=None)

        for key in msg:
            if key in body:
                msg[key] = body[key]


        if notify:
            for aid in aids:
                if aid != self.hab.pre:
                    if aid not in self.hab.kevers:
                        self.witq.query(aid)
                    exn = exchanging.exchange(route="/multisig/incept", payload=dict(msg), date=helping.nowIso8601())
                    self.rep.reps.append(dict(dest=aid, rep=exn, topic="multisig"))

        msg["op"] = grouping.Ops.icp
        msg["group"] = body["group"]

        self.gdoer.msgs.append(msg)

        rep.status = falcon.HTTP_202

    def on_get_multisig(self, req, rep):
        """
        Return the groups this environment is a part of

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        """
        res = []

        groups = self.hab.db.gids.getItemIter()
        for (name,), group in groups:
            kever = self.hab.kevers[group.gid]
            ser = kever.serder
            dgkey = dbing.dgKey(ser.preb, ser.digb)
            wigs = self.hab.db.getWigs(dgkey)


            gd = dict(
                name=name,
                prefix=group.gid,
                seq_no=kever.sn,
                aids=group.aids,
                witnesses=kever.wits,
                public_keys=[verfer.qb64 for verfer in kever.verfers],
                toad=kever.toad,
                isith=kever.tholder.sith,
                receipts=len(wigs)
            )

            res.append(gd)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_get_credentials_issued(self, req, rep):
        """
        Return the credntials issued by this agent

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        """
        registry = req.params["registry"]
        issuer = self.getIssuer(registry)

        groups = self.hab.db.gids.getItemIter()
        group = next(groups, None)

        if group is None:
            pre = self.hab.pre
        else:
            name, group = group
            pre = group.gid

        saids = issuer.reger.issus.get(keys=pre)
        creds = []
        for saider in saids:
            key = saider.qb64b
            creder = issuer.reger.creds.get(keys=key)

            # TODO:  de-dupe the seals here and extract the signatures
            seals = issuer.reger.seals.get(keys=key)
            prefixer = None
            seqner = None
            diger = None
            sigers = []
            for seal in seals:
                (prefixer, seqner, diger, siger) = seal
                sigers.append(siger)

            cred = dict(
                sad=creder.crd,
                pre=prefixer.qb64,
                sn=seqner.sn,
                dig=diger.qb64,
                sigers=[sig.qb64 for sig in sigers],
                status=issuer.tevers[issuer.regk].vcState(key)
            )

            creds.append(cred)



        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(creds).encode("utf-8")


    def on_post_registry_incept(self, req, rep):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        Body:
            name: The human readable name of the new registry to create

        """
        body = json.loads(req.context.raw)

        if "name" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "name is a required parameter to create a verifiable credential registry"
            return

        msg = dict(name=body["name"])
        self.registryIcpr.msgs.append(msg)

        rep.status = falcon.HTTP_202


    def getIssuer(self, name):
        if name in self.issuers:
            issuer = self.issuers[name]
        else:
            reger = viring.Registry(name=name)
            regr = reger.regs.get(name)
            if regr is None:
                return None

            issuer = issuing.Issuer(hab=self.hab, name=name, reger=reger, cues=self.issuerCues)
            self.issuers[name] = issuer
        return issuer


    def on_get_id(self, req, rep):
        """
        Return the groups this environment is a part of

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        """
        res = []

        habs = self.hab.db.habs.getItemIter()
        for (name,), habr in habs:
            kever = self.hab.kevers[habr.prefix]
            ser = kever.serder
            dgkey = dbing.dgKey(ser.preb, ser.digb)
            wigs = self.hab.db.getWigs(dgkey)


            gd = dict(
                name=name,
                prefix=habr.prefix,
                seq_no=kever.sn,
                witnesses=kever.wits,
                public_keys=[verfer.qb64 for verfer in kever.verfers],
                toad=kever.toad,
                isith=kever.tholder.sith,
                receipts=len(wigs)
            )

            res.append(gd)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")
