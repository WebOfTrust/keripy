# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json

import falcon
from apispec import APISpec
from hio.base import doing
from hio.core import http
from hio.help import decking
from keri.app import specing, forwarding, agenting, signing
from keri.db import dbing
from keri.help import helping
from keri.peer import exchanging
from keri.vc import proving, handling
from keri.vdr import registering, issuing, viring, verifying

from . import grouping
from .. import help
from .. import kering
from ..core import parsing

logger = help.ogler.getLogger()


def loadEnds(app, *, path, hab, rep, witq, verifier, gdoer, issuerCues, issuers):
    """
    Load endpoints for KIWI admin interface into the provided Falcon app

    Args:
        app (falcon.App): falcon.App to register handlers with:
        path (str): directory location of UI web app files to be served with this API server
        hab (Habitat): the environment of the identifier prefix
        rep (Respondant): that routes responses to the appropriate mailboxes
        witq (WitnessInquisitor): used to request KEL resolution
        verifier (Verifier): that process credentials
        gdoer (Union(decking.Deck,None)): of msgs to send to a MultisigDoer
        issuers (Union(dict,None)): of credential Issuers keyed by regk of credential Registry
        issuerCues (Deck): from Kevery handling key events:

    Returns:
        array: doers from registering endpoints

    """
    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    swagsink = http.serving.StaticSink(staticDirPath="./static")
    app.add_sink(swagsink, prefix="/swaggerui")

    identifierEnd = IdentifierEnd(hab=hab)
    app.add_route("/id", identifierEnd)

    registryEnd = RegistryEnd(hab=hab)
    app.add_route("/registries", registryEnd)

    credentialsEnd = CredentialsEnd(hab=hab, rep=rep,
                                    verifier=verifier, witq=witq, issuers=issuers,
                                    cues=issuerCues)
    app.add_route("/credentials", credentialsEnd)

    applicationsEnd = ApplicationsEnd(rep=rep)
    app.add_route("/applications", applicationsEnd)

    presentationEnd = PresentationEnd(rep=rep)
    app.add_route("/presentation", presentationEnd)

    multisigEnd = MultisigEnd(hab=hab, rep=rep, gdoer=gdoer)
    app.add_route("/multisig", multisigEnd)

    resources = [identifierEnd, registryEnd, applicationsEnd, credentialsEnd,
                 presentationEnd, multisigEnd]

    app.add_route("/spec.yaml", SpecResource(app=app, title='KERI Interactive Web Interface API',
                                             resources=resources))

    return [identifierEnd, registryEnd]


class IdentifierEnd(doing.DoDoer):
    """
    ReST API for admin of Identifiers
    """

    def __init__(self, hab, **kwa):
        self.hab = hab

        self.postman = forwarding.Postman(hab=self.hab)
        doers = [self.postman]

        super(IdentifierEnd, self).__init__(doers=doers, **kwa)

    def on_get(self, _, rep):
        """ Identifier GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary:  Get list of agent identfiers
        description:  Get the list of identfiers associated with this agent
        tags:
           - Identifiers
        responses:
            200:
              description: An array of Identifier key state information
              content:
                  application/json:
                    schema:
                        description: Key state information for current identifiers
                        type: array
                        items:
                           type: object
                           properties:
                              name:
                                 description: habitat local alias
                                 type: string
                              prefix:
                                 description: qualified base64 identifier prefix
                                 type: string
                              seq_no:
                                 description: current key event sequence number
                                 type: integer
                              delegated:
                                 description: Flag indicating whether this identifier is delegated
                                 type: boolean
                              delegator:
                                 description: qualified base64 identifier prefix of delegator
                                 type: string
                              witnesses:
                                 description: list of qualified base64 identfier prefixes of witnesses
                                 type: string
                              public_keys:
                                 description: list of current public keys
                                 type: array
                                 items:
                                    type: string
                              toad:
                                 description: Current witness threshold
                                 type: integer
                              isith:
                                 description: Current signing threshold
                                 type: string
                              receipts:
                                 description:  Count of witness receipts received for last key event
                                 type: integer
        """
        res = []

        habs = self.hab.db.habs.getItemIter()
        for (name,), habr in habs:
            kever = self.hab.kevers[habr.prefix]
            ser = kever.serder
            dgkey = dbing.dgKey(ser.preb, ser.saidb)
            wigs = self.hab.db.getWigs(dgkey)

            gd = dict(
                name=name,
                prefix=habr.prefix,
                seq_no=kever.sn,
                delegated=kever.delegated,
                delegator=kever.delegator,
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

    def on_post(self, req, rep):
        """  Identifier POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary:  Rotate agent identifier
        description:  Perform a rotation on the agent's current identifier
        tags:
           - Identifiers
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 properties:
                   wits:
                     type: array
                     description: list of witness identifiers
                     items:
                        type: string
                   toad:
                     type: integer
                     description: withness threshold
                     default: 1
                   isith:
                     type: string
                     description: signing threshold
                   count:
                     type: integer
                     description: count of next key commitment.
        responses:
           200:
              description: Non-delegated rotation successful with message indicating new event sequence number
           202:
              description: Delegated rotation request initiated

        """
        body = req.media
        wits = body.get("wits")
        toad = int(body.get("toad")) if "toad" in body else None
        isith = int(body.get("isith")) if "isith" in body else None
        count = int(body.get("count")) if "count" in body else None
        cuts = set()
        adds = set()

        if wits:
            ewits = self.hab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            cuts = set(ewits) - set(wits)
            adds = set(wits) - set(ewits)

        try:
            rot = self.hab.rotate(sith=isith, count=count, toad=toad, cuts=list(cuts), adds=list(adds))

            if self.hab.kever.delegator is None:

                witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=rot)
                self.extend(doers=[witDoer])

                rep.status = falcon.HTTP_200
                rep.text = "Successful rotate to event number {}".format(self.hab.kever.sn)

            else:
                cloner = self.hab.db.clonePreIter(pre=self.hab.pre, fn=0)  # create iterator at 0
                for msg in cloner:
                    self.postman.send(recipient=self.hab.kever.delegator, topic="delegate", msg=msg)

                self.postman.send(recipient=self.hab.kever.delegator, topic="delegate", msg=rot)
                rep.status = falcon.HTTP_202


        except (ValueError, TypeError) as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]


class RegistryEnd(doing.DoDoer):
    """
    ReST API for admin of credential issuance and revocation registries

    """

    def __init__(self, hab, **kwa):
        self.registryIcpr = registering.RegistryInceptDoer(hab=hab)

        super(RegistryEnd, self).__init__(doers=[self.registryIcpr], **kwa)

    def on_post(self, req, rep):
        """  Registries POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Request to create a credential issuance and revocation registry
        description: Request to create a credential issuance and revocation registry
        tags:
           - Registries
        requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    name:
                      type: string
                      description: name of the new registry
        responses:
           202:
              description:  registry inception request has been submitted

        """
        body = req.media

        if "name" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "name is a required parameter to create a verifiable credential registry"
            return

        msg = dict(name=body["name"])
        self.registryIcpr.msgs.append(msg)

        rep.status = falcon.HTTP_202

    def on_get(self, req, rep):
        """  Registries GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: List credential issuance and revocation registies
        description: List credential issuance and revocation registies
        tags:
           - Registries
        responses:
           200:
              description:  array of current credential issuance and revocation registies

        """


class CredentialsEnd:
    """
    ReST API for admin of credentials

    """
    def __init__(self, hab, rep, verifier, witq, issuers, cues=None):

        self.hab = hab
        self.rep = rep
        self.witq = witq

        self.verifier = verifier
        self.issuers = issuers
        self.cues = cues if cues is not None else decking.Deck()

    def on_get(self, req, rep):
        """ Credentials GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
        ---
        summary:  List credentials in credential store (wallet)
        description: List issued or received credentials current verified
        tags:
           - Credentials
        parameters:
           - in: query
             name: type
             schema:
                type: string
             description:  type of credential to return, [issued|received]
             required: true

        """
        typ = req.params("type")

        group = self.hab.group()
        if group is None:
            pre = self.hab.pre
        else:
            pre = group.gid

        creds = []
        if typ == "issued":
            registry = req.params["registry"]
            issuer = self.getIssuer(registry)

            saids = issuer.reger.issus.get(keys=pre)
            creds = self.verifier.reger.cloneCreds(saids)

        elif typ == "received":
            saids = self.verifier.reger.subjs.get(keys=pre)
            creds = self.verifier.reger.cloneCreds(saids)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(creds).encode("utf-8")

    def on_post(self, req, rep):
        """ Initiate a credential issuance from this agent's identifier

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Issue credential
        description: Submit a credential issuance peer to peer message for credential with specific schema and field
                     values
        tags:
           - Credentials
        requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    registry:
                      type: string
                      description: AID of credential issuance/revocation registry (aka status)
                    schema:
                      type: string
                      description: SAID of credential schema being issued
                    recipient:
                      type: string
                      description: AID of recipient of credential
                    source:
                      type: array
                      description: list of credential chain sources (ACDC)
                      items:
                         type: object
                         properties:
                            d:
                               type: string
                               description: SAID of reference chain
                            s:
                               type: string
                               description: SAID of reference chain schema
                    credentialData:
                      type: object
                      description: dynamic map of values specific to the schema
        responses:
           200:
              description: Credential issued.
              content:
                  application/json:
                    schema:
                        description: Credential
                        type: object


        """
        body = req.media
        registry = body.get("registry")
        schema = body.get("schema")
        source = body.get("source")
        recipientIdentifier = body.get("recipient")
        notify = body["notify"] if "notify" in body else True

        if recipientIdentifier not in self.hab.kevers:
            self.witq.query(recipientIdentifier)

        issuer = self.getIssuer(name=registry)
        if issuer is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(registry)
            return

        data = body.get("credentialData")
        dt = data["dt"] if "dt" in data else helping.nowIso8601()

        d = dict(
            d="",
            i=recipientIdentifier,
            dt=dt,
        )

        d |= data

        group = self.hab.group()
        if group is None:
            pre = self.hab.pre
        else:
            pre = group.gid

        creder = proving.credential(issuer=pre,
                                    schema=schema,
                                    subject=d,
                                    source=source,
                                    status=issuer.regk)
        try:
            issuer.issue(creder=creder, dt=dt)
        except kering.MissingAnchorError:
            logger.info("Missing anchor from credential issuance due to multisig identifier")

        print()
        print(creder.raw)
        craw = signing.ratify(hab=self.hab, serder=creder)
        parsing.Parser().parse(ims=craw, vry=self.verifier)

        if notify and group:
            for aid in group.aids:
                if aid != self.hab.pre:
                    if aid not in self.hab.kevers:
                        self.witq.query(aid)
                    msg = dict(
                        schema=schema,
                        source=source,
                        recipient=recipientIdentifier,
                        typ=body.get("type"),
                        data=d,
                    )
                    exn = exchanging.exchange(route="/multisig/issue", payload=msg)
                    self.rep.reps.append(dict(dest=aid, rep=exn, topic="multisig"))

        rep.status = falcon.HTTP_200
        rep.data = creder.pretty().encode("utf-8")

    def on_delete(self, req, rep):
        """ Credential DELETE endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Revoke credential
        description: Create a revocation entry in the provided registry for the specified credential
        tags:
           - Credentials
        parameters:
           - in: query
             name: registry
             schema:
                type: string
             description:  SAID of credential registry
             required: true
           - in: query
             name: said
             schema:
                type: string
             description: SAID of credential to revoke
             required: true

        responses:
           202:
              description: credential successfully revoked.

        """
        registry = req.get_param("registry")
        said = req.get_param("said")

        issuer = self.getIssuer(name=registry)
        if issuer is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(registry)
            return

        try:
            creder = self.verifier.reger.creds.get(keys=said)
            if creder is None:
                rep.status = falcon.HTTP_NOT_FOUND
                rep.text = "credential not found"
                return

            issuer.revoke(creder=creder)
        except kering.ValidationError as ex:
            print()
            print(ex)
            rep.status = falcon.HTTP_CONFLICT
            rep.text = ex.args[0]
            return

        rep.status = falcon.HTTP_202

    def getIssuer(self, name):
        """ returns an existing Issuer by name or creates a new one

        Parameters:
            name (str): name of registry to find or create

        Returns:
            Issuer:  issuer object for credential registry
        """
        if name in self.issuers:
            issuer = self.issuers[name]
        else:
            issuer = issuing.Issuer(hab=self.hab, name=name, reger=self.verifier.reger, cues=self.cues)
            self.issuers[name] = issuer

        return issuer


class ApplicationsEnd:
    """
    ReST API for admin of credential applications (apply requests)

    """

    def __init__(self, rep):
        """

        """
        self.rep = rep

    def on_post(self, req, rep):
        """ Apply for a credential with the given credential fields.

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
        ---
        summary: Apply for credential
        description: Submit a credential apply peer to peer message for credential with specific schema and field
                     values
        tags:
           - Applications
        requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    schema:
                      type: string
                      description: SAID of credential schema being requested
                    issuer:
                      type: string
                      description: AID of requested issuer of credential
                    values:
                      type: object
                      description: dynamic list of values specific to the schema


        responses:
           202:
              description: Credential Apply request submitted.

        """
        body = json.loads(req.context.raw)
        schema = body.get("schema")
        issuer = body.get("issuer")
        values = body.get("values")

        apply = handling.credential_apply(issuer=issuer, schema=schema, formats=[], body=values)

        exn = exchanging.exchange(route="/credential/apply", payload=apply)
        self.rep.reps.append(dict(dest=issuer, rep=exn, topic="credential"))

        rep.status = falcon.HTTP_202


class PresentationEnd:
    """
    ReST API for admin of credential presentation requests

    """

    def __init__(self, rep):
        self.rep = rep

    def on_post(self, req, rep):
        """  Presentation POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Request credential presentation
        description: Send a credential presentation request peer to peer (exn) message to recipient
        tags:
           - Presentation
        responses:
           202:
              description:  credential presentation request message sent

        """
        body = json.loads(req.context.raw)
        recipientIdentifier = body.get("recipient")
        if recipientIdentifier is None:
            rep.status = falcon.HTTP_400
            rep.text = "recipient is required, none provided"
            return

        schema = body.get("schema")
        if schema is None:
            rep.status = falcon.HTTP_400
            rep.text = "schema is required, none provided"
            return

        pl = dict(
            input_descriptors=[
                dict(x=schema)
            ]
        )

        exn = exchanging.exchange(route="/presentation/request", payload=pl)
        self.rep.reps.append(dict(dest=recipientIdentifier, rep=exn, topic="credential"))

        rep.status = falcon.HTTP_202


class MultisigEnd:
    """
    ReST API for admin of distributed multisig groups

    """
    def __init__(self, hab, gdoer, rep):

        self.hab = hab
        self.gdoer = gdoer
        self.rep = rep


    def on_put(self, req, rep):
        """  Multisig PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Initiaite or participate in a multisig group rotation
        description: Initiaite or participate in a multisig group rotation
        tags:
           - Multisig
        responses:
           202:
              description:  rotation participation initiated

        """
        body = req.media

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

        self.gdoer.msgs.append(msg)

        rep.status = falcon.HTTP_202

    def on_post(self, req, rep):
        """  Multisig POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Initiate a multisig group inception
        description: Initiate a multisig group inception with the participants identified by the  provided AIDs
        tags:
           - Multisig
        responses:
           202:
              description:  multisig group inception initiated

        """
        body = req.media

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
                exn = exchanging.exchange(route="/multisig/incept", payload=dict(msg), date=helping.nowIso8601())
                self.rep.reps.append(dict(dest=aid, rep=exn, topic="multisig"))

        msg["op"] = grouping.Ops.icp
        self.gdoer.msgs.append(msg)

        rep.status = falcon.HTTP_202

    def on_get(self, _, rep):
        """  Multisig GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: List multisig groups this agent is currently participating in
        description: List multisig groups this agent is currently participating in
        tags:
           - Multisig
        responses:
           200:
              description:  array of multisig groups

        """
        res = []

        group = self.hab.group()
        if group:
            kever = self.hab.kevers[group.gid]
            ser = kever.serder
            dgkey = dbing.dgKey(ser.preb, ser.saidb)
            wigs = self.hab.db.getWigs(dgkey)

            gd = dict(
                prefix=group.gid,
                seq_no=kever.sn,
                aids=group.aids,
                delegated=kever.delegated,
                delegator=kever.delegator,
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


class SpecResource:
    """
    Resource for OpenAPI spec

    """

    def __init__(self, app, title, resources, version='1.0.0', openapiVersion="3.0.2"):
        self.spec = APISpec(
            title=title,
            version=version,
            openapi_version=openapiVersion,
            plugins=[
                specing.FalconPlugin(app),
                # MarshmallowPlugin(),
            ],
        )

        for r in resources:
            self.spec.path(resource=r)

    def on_get(self, _, rep):
        """
        GET endpoint for OpenAPI spec

        Args:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response


        """
        rep.status = falcon.HTTP_200
        rep.content_type = "application/yaml"
        rep.data = self.spec.to_yaml().encode("utf-8")


class KiwiDoer(doing.DoDoer):
    """
    Routes for handling UI requests for Credential issuance/revocation and presentation requests

    """

    def __init__(self, hab, rep, verifier, gdoer, witq, issuers=None, issuerCues=None, cues=None, **kwa):
        """
        Create a KIWI web server for Agents capable of performing KERI and ACDC functions for the controller
        of an identifier.

        Parameters:
            hab Habitat is the environment of the identifier prefix
            controller qb64 is the identifier prefix that can send commands to this web server:
            rep Respondant that routes responses to the appropriate mailboxes
            verifier is Verifier that process credentials
            gdoe is decking.Deck of msgs to send to a MultisigDoer
            issuers is dict of credential Issuers keyed by regk of credential Registry
            wallet is Wallet for local storage of credentials
            cues is Deck from Kevery handling key events:
            app falcon.App to register handlers with:
            insecure bool is True to allow requests without verifying KERI Http Signature Header,
                defaults to False

        """
        self.hab = hab
        self.rep = rep
        self.witq = witq
        self.verifier = verifier if verifier is not None else verifying.Verifier(hab=self.hab)
        self.issuers = issuers if issuers is not None else dict()

        self.cues = cues if cues is not None else decking.Deck()
        self.issuerCues = issuerCues if issuerCues is not None else decking.Deck()
        self.gdoer = gdoer

        self.postman = forwarding.Postman(hab=self.hab)

        doers = [self.postman, doing.doify(self.verifierDo), doing.doify(self.issuerDo),
                 doing.doify(self.escrowDo)]

        super(KiwiDoer, self).__init__(doers=doers, **kwa)

    def verifierDo(self, tymth, tock=0.0):
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
                    craw = cue["msg"]

                    print("Credential: {}, Schema: {},  Saved".format(creder.said, creder.schema))
                    print(creder.pretty())

                    if creder.crd["i"] == self.hab.pre:
                        recpt = creder.subject["i"]
                        said = creder.said
                        regk = creder.status
                        vci = viring.nsKey([regk, said])
                        issr = creder.crd["i"]

                        msgs = bytearray()
                        for msg in self.hab.db.clonePreIter(pre=issr):
                            msgs.extend(msg)

                        for msg in self.verifier.reger.clonePreIter(pre=regk):
                            msgs.extend(msg)

                        for msg in self.verifier.reger.clonePreIter(pre=vci):
                            msgs.extend(msg)

                        vcs = [handling.envelope(msg=craw)]

                        sources = self.verifier.reger.sources(self.hab.db, creder)
                        for craw, smsgs in sources:
                            self.postman.send(recipient=recpt, topic="credential", msg=smsgs)
                            vcs.extend([handling.envelope(msg=craw)])

                        pl = dict(
                            vc=vcs
                        )

                        self.postman.send(recipient=recpt, topic="credential", msg=msgs)
                        exn = exchanging.exchange(route="/credential/issue", payload=pl)
                        #  TODO:  Respondant must accept transposable signatures to add to the endorsed message
                        self.rep.reps.append(dict(dest=recpt, rep=exn, topic="credential"))

                elif cueKin == "query":
                    qargs = cue["q"]
                    self.witq.backoffQuery(**qargs)

                elif cueKin == "telquery":
                    qargs = cue["q"]
                    self.witq.backoffTelQuery(**qargs)

                elif cueKin == "proof":
                    pass
                    # nodeSaid = cue["said"]
                    # creder = self.verifier.reger.creds.get(keys=nodeSaid)

                yield self.tock
            yield self.tock

    def escrowDo(self, tymth, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list

        Processes the Groupy escrow for group icp, rot and ixn request messages.

        """
        # start enter context
        yield  # enter context
        while True:
            issuers = dict(self.issuers)
            for _, issuer in issuers.items():
                issuer.processEscrows()
                yield self.tock

            self.verifier.processEscrows()
            yield self.tock

    def issuerDo(self, tymth, tock=0.0):
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
                    tevt = cue["msg"]
                    sub = cue["sub"]
                    witSender = agenting.WitnessPublisher(hab=self.hab, msg=bytearray(tevt))
                    self.extend([witSender])

                    while not witSender.done:
                        _ = yield self.tock

                    self.remove([witSender])

                    if sub is not None:
                        self.postman.send(recipient=sub["i"], topic="credential", msg=bytearray(tevt))
                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=bytearray(kevt))
                    self.extend([witDoer])

                    while not witDoer.done:
                        yield self.tock

                    self.remove([witDoer])
                elif cueKin == "multisig":
                    msg = dict(
                        op=cue["op"],
                        data=cue["data"],
                        reason=cue["reason"]
                    )
                    self.gdoer.append(msg)
                elif cueKin == "logEvent":
                    pass

                yield self.tock
            yield self.tock
