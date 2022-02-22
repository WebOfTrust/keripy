# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json
import mnemonic
from urllib.parse import urlparse
from hio.help import helping, decking

import falcon
from apispec import APISpec
from falcon import media
from hio.base import doing
from hio.core import http
from hio.core.tcp import serving as tcpServing
from keri.app import specing, forwarding, agenting, signing, storing, indirecting, httping, habbing
from keri.db import dbing
from keri.help import helping
from keri.peer import exchanging
from keri.vc import proving, handling, walleting
from keri.vdr import registering, issuing, viring, verifying

from . import grouping
from .. import help
from .. import kering
from ..core import parsing, eventing
from ..end import ending

logger = help.ogler.getLogger()


class IdentifierEnd(doing.DoDoer):
    """
    ReST API for admin of Identifiers
    """

    def __init__(self, hby, **kwa):
        self.hby = hby

        self.postman = forwarding.Postman(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)

        doers = [self.witDoer, self.postman]

        super(IdentifierEnd, self).__init__(doers=doers, **kwa)

    def on_get(self, req, rep, alias=None):
        """ Identifier GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

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

        for pre, hab in self.hby.habs.items():
            kever = hab.kevers[pre]
            ser = kever.serder
            dgkey = dbing.dgKey(ser.preb, ser.saidb)
            wigs = hab.db.getWigs(dgkey)

            gd = dict(
                name=hab.name,
                prefix=pre,
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

    def on_post(self, req, rep, alias=None):
        """ Identifier POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for Hab

        ---
        summary:  Create agent identifier
        description:  Create agent identifier with the supplied parameters
        tags:
           - Identifiers
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the identifier to create
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 properties:
                   wits:
                     type: array
                     items:
                        type: string
                     description: human readable alias for the new identfier
        responses:
           200:
              description: identifier information

        """
        body = req.get_media()

        transferable = body.get("transferable") if "transferable" in body else True
        wits = body.get("wits") if "wits" in body else []
        toad = int(body.get("toad")) if "toad" in body else None
        isith = int(body.get("isith")) if "isith" in body else "1"
        icount = int(body.get("count")) if "count" in body else 1
        nsith = int(body.get("nsith")) if "nsith" in body else "1"
        ncount = int(body.get("ncount")) if "ncount" in body else 1
        estOnly = int(body.get("estOnly")) if "estOnly" in body else False

        kwa = dict(
            transferable=transferable,
            wits=wits,
            toad=toad,
            isith=isith,
            icount=icount,
            nsith=nsith,
            ncount=ncount,
            estOnly=estOnly
        )

        hab = self.hby.makeHab(name=alias, **kwa)
        self.witDoer.msgs.append(dict(pre=hab.pre))

        body = dict(
            pre=hab.pre,
            wits=hab.kever.wits,
            keys=[verfer.qb64 for verfer in hab.kever.verfers]
        )

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(body).encode("utf-8")

    def on_put(self, req, rep, alias):
        """  Identifier PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for Hab

        ---
        summary:  Rotate agent identifier
        description:  Perform a rotation on the agent's current identifier
        tags:
           - Identifiers
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the identifier to create
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
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.data = f"no matching Hab for alias {alias}"
            return

        body = req.get_media()
        wits = body.get("wits")
        toad = int(body.get("toad")) if "toad" in body else None
        isith = int(body.get("isith")) if "isith" in body else None
        count = int(body.get("count")) if "count" in body else None
        cuts = set()
        adds = set()

        if wits:
            ewits = hab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            cuts = set(ewits) - set(wits)
            adds = set(wits) - set(ewits)

        try:
            rot = hab.rotate(sith=isith, count=count, toad=toad, cuts=list(cuts), adds=list(adds))

            if hab.kever.delegator is None:

                self.witDoer.msgs.append(dict(pre=hab.pre))

                rep.status = falcon.HTTP_200
                rep.text = "Successful rotate to event number {}".format(hab.kever.sn)

            else:
                cloner = hab.db.clonePreIter(pre=hab.pre, fn=0)  # create iterator at 0
                for msg in cloner:
                    self.postman.send(src=hab.pre, dest=hab.kever.delegator, topic="delegate", msg=msg)

                self.postman.send(src=hab.pre, dest=hab.kever.delegator, topic="delegate", msg=rot)
                rep.status = falcon.HTTP_202

        except (ValueError, TypeError) as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]


class RegistryEnd(doing.DoDoer):
    """
    ReST API for admin of credential issuance and revocation registries

    """

    def __init__(self, hby, **kwa):
        self.registryIcpr = registering.RegistryInceptDoer(hby=hby)

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
        body = req.get_media()

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

    def __init__(self, hby, rep, verifier, issuers, cues=None):

        self.hby = hby
        self.rep = rep

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
        alias = req.params("alias")

        hab = self.hby.habByName(name=alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credentials" \
                       "".format(alias)
            return

        group = hab.group()
        if group is None:
            pre = hab.pre
        else:
            pre = group.gid

        creds = []
        if typ == "issued":
            registry = req.params["registry"]
            issuer = self.getIssuer(registry, hab=hab)

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
        body = req.get_media()
        alias = body.get("alias")
        registry = body.get("registry")
        schema = body.get("schema")
        source = body.get("source")
        recipientIdentifier = body.get("recipient")
        notify = body["notify"] if "notify" in body else True

        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credentials" \
                       "".format(alias)
            return

        if recipientIdentifier not in hab.kevers:
            rep.status = falcon.HTTP_400
            rep.text = "Unable to issue credential to {}.  A connection to that identifier must already " \
                       "be established".format(recipientIdentifier)
            return

        issuer = self.getIssuer(name=registry, hab=hab)
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

        group = hab.group()
        if group is None:
            pre = hab.pre
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
        craw = signing.ratify(hab=hab, serder=creder)
        parsing.Parser().parse(ims=craw, vry=self.verifier)

        if notify and group:
            for aid in group.aids:
                if aid != hab.pre:
                    msg = dict(
                        schema=schema,
                        source=source,
                        recipient=recipientIdentifier,
                        typ=body.get("type"),
                        data=d,
                    )
                    exn = exchanging.exchange(route="/multisig/issue", payload=msg)
                    self.rep.reps.append(dict(src=hab.pre, dest=aid, rep=exn, topic="multisig"))

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
        alias = req.get_param("alias")
        registry = req.get_param("registry")
        said = req.get_param("said")
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = f"unknown local alias {alias}"
            return

        issuer = self.getIssuer(hab=hab, name=registry)
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
            rep.status = falcon.HTTP_CONFLICT
            rep.text = ex.args[0]
            return

        rep.status = falcon.HTTP_202

    def getIssuer(self, name, hab):
        """ returns an existing Issuer by name or creates a new one

        Parameters:
            name (str): name of registry to find or create
            hab (Habitat): environment for issuer

        Returns:
            Issuer:  issuer object for credential registry
        """
        if name in self.issuers:
            issuer = self.issuers[name]
        else:
            issuer = issuing.Issuer(hab=hab, name=name, reger=self.verifier.reger, cues=self.cues)
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
        body = req.get_media()
        schema = body.get("schema")
        issuer = body.get("issuer")
        values = body.get("values")

        apply = handling.credential_apply(issuer=issuer, schema=schema, formats=[], body=values)

        exn = exchanging.exchange(route="/credential/apply", payload=apply)
        self.rep.reps.append(dict(src="", dest=issuer, rep=exn, topic="credential"))

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
        body = req.get_media()
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

    def __init__(self, hby, gdoer, rep):

        self.hby = hby
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
        body = req.get_media()

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
        body = req.get_media()

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

        for hab in self.hby.habs.values():
            group = hab.group()
            if group:
                kever = self.hby.kevers[group.gid]
                ser = kever.serder
                dgkey = dbing.dgKey(ser.preb, ser.saidb)
                wigs = self.hby.db.getWigs(dgkey)

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


class OobiResource(doing.DoDoer):
    """
    Resource for managing OOBIs

    """

    def __init__(self, hby):
        self.hby = hby

        self.oobiery = ending.Oobiery(db=self.hby.db)

        doers = [self.oobiery, doing.doify(self.loadDo)]

        super(OobiResource, self).__init__(doers=doers)

    def on_get(self, req, rep, alias):
        """ Identifier GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

        ---
        summary:  Get OOBI for specific identifier
        description:  Generate OOBI for the identifier of the specified alias and role
        tags:
           - OOBIs
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: human readable alias for the identifier generate OOBI for
          - in: query
            name: role
            schema:
              type: string
            required: true
            description: role for which to generate OOBI
        responses:
            200:
              description: An array of Identifier key state information
              content:
                  application/json:
                    schema:
                        description: Key state information for current identifiers
                        type: object
        """

        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias to generate OOBI"
            return

        role = req.params["role"]

        res = dict(role=role)
        if role in (kering.Roles.witness,):  # Fetch URL OOBIs for all witnesses
            oobis = []
            for wit in hab.kever.wits:
                urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http)
                if not urls:
                    raise kering.ConfigurationError(f"unable to query witness {wit}, no http endpoint")

                up = urlparse(urls[kering.Schemes.http])
                oobis.append(f"http://{up.hostname}:{up.port}/oobi/{hab.pre}/witness/{wit}")
            res["oobis"] = oobis
        elif role in (kering.Roles.controller,):  # Fetch any controller URL OOBIs
            oobis = []
            urls = hab.fetchUrls(eid=hab.pre, scheme=kering.Schemes.http)
            up = urlparse(urls[kering.Schemes.http])
            oobis.append(f"http://{up.hostname}:{up.port}/oobi/{hab.pre}/controller")
        else:
            rep.status = falcon.HTTP_404
            return

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_post(self, req, rep, alias):
        """ Resolve OOBI endpoint.

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

        ---
        summary: Resolve OOBI
        description: Resolve OOBI URL or `rpy` message by process results of request
        tags:
           - OOBIs
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the oobi to resolve
        requestBody:
            required: true
            content:
              application/json:
                schema:
                    description: OOBI
                    properties:
                        url:
                          type: string
                          description:  URL OOBI
                        rpy:
                          type: object
                          description: unsigned KERI `rpy` event message with endpoints
        responses:
           202:
              description: OOBI resolution to key state successful

        """
        body = req.get_media()
        if "url" in body:
            oobi = body["url"]
            self.oobiery.oobis.append(oobi)
        elif "rpy" in body:
            pass
        else:
            rep.status = falcon.HTTP_400
            rep.data = "invalid OOBI request body, either 'rpy' or 'url' is required"

    def loadDo(self, tymth, tock=0.0):
        """ Load oobis

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method for loading oobis using
        the Oobiery
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            if self.oobiery.cues:
                cue = self.oobiery.cues.popleft()
                kin = cue["kin"]
                oobi = cue["oobi"]
                if kin in ("resolved",):
                    pass
                if kin in ("failed",):
                    pass

                break

            yield 1.0


class ChallengeEnd:
    """ Resource for Challange/Response Endpoints """

    def __init__(self, hby, rep):
        """ Initialize Challenge/Response Endpoint

        Parameters:
            hby (Habery): database and keystore environment
            rep (Respondant): Doer capable of processing responses from endpoints

        """
        self.hby = hby
        self.rep = rep

    @staticmethod
    def on_get(req, rep, alias=None):
        """ Challenge GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of identifier to use to sign the challange/response

        ---
        summary:  Get list of agent identfiers
        description:  Get the list of identfiers associated with this agent
        tags:
           - Challenge/Response
        parameters:
           - in: query
             name: strength
             schema:
                type: int
             description:  cryptographic strength of word list
             required: false
        responses:
            200:
              description: An array of Identifier key state information
              content:
                  application/json:
                    schema:
                        description: Randon word list
                        type: object
                        properties:
                            words:
                                type: array
                                description: random challange word list
                                items:
                                    type: string

        """
        mnem = mnemonic.Mnemonic(language='english')
        strength = int(req.params["strength"]) if "stength" in req.params else 128

        words = mnem.generate(strength=strength)
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        msg = dict(words=words.split(" "))
        rep.data = json.dumps(msg).encode("utf-8")

    def on_post(self, req, rep, alias):
        """ Challenge GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of identifier to use to sign the challange/response
        ---
        summary:  Sign challange message and forward to peer identfiier
        description:  Sign a challenge word list received out of bands and send `exn` peer to peer message
                      to recipient
        tags:
           - Challenge/Response
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the identifier to create
        requestBody:
            required: true
            content:
              application/json:
                schema:
                    description: Challenge response
                    properties:
                        recipient:
                          type: string
                          description: human readable alias recipient identifier to send signed challenge to
                        words:
                          type: array
                          description:  challenge in form of word list
                          items:
                              type: string
        responses:
           202:
              description: Success submission of signed challenge/response
        """
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.data = f"no matching Hab for alias {alias}"
            return

        body = req.get_media()
        if "words" not in body or "recipient" not in body:
            rep.status = falcon.HTTP_400
            rep.data = "challenge response requires 'words' and 'recipient'"
            return

        words = body["words"]
        recpt = body["recipient"]
        payload = dict(i=hab.pre, words=words)
        exn = exchanging.exchange(route="/challange/response", payload=payload)
        self.rep.reps.append(dict(dest=recpt, rep=exn, topic="challange"))


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

    def __init__(self, hby, rep, verifier, gdoer, issuers=None, issuerCues=None, cues=None, **kwa):
        """
        Create a KIWI web server for Agents capable of performing KERI and ACDC functions for the controller
        of an identifier.

        Parameters:
            hby (Habery): is the environment of the identifier prefix
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
        self.hby = hby
        self.rep = rep
        self.verifier = verifier if verifier is not None else verifying.Verifier(hby=self.hby)
        self.issuers = issuers if issuers is not None else dict()

        self.cues = cues if cues is not None else decking.Deck()
        self.issuerCues = issuerCues if issuerCues is not None else decking.Deck()
        self.gdoer = gdoer

        self.postman = forwarding.Postman(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=hby)

        doers = [self.postman, self.witDoer, doing.doify(self.verifierDo), doing.doify(self.issuerDo),
                 doing.doify(self.escrowDo)]

        super(KiwiDoer, self).__init__(doers=doers, **kwa)

    def verifierDo(self, tymth, tock=0.0):
        """
        Process cues from Verifier coroutine

            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

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
                    hab = self.hby.habs[creder.issuer]

                    if hab is not None:
                        recpt = creder.subject["i"]
                        said = creder.said
                        regk = creder.status
                        vci = viring.nsKey([regk, said])
                        issr = creder.crd["i"]

                        msgs = bytearray()
                        for msg in hab.db.clonePreIter(pre=issr):
                            msgs.extend(msg)

                        for msg in self.verifier.reger.clonePreIter(pre=regk):
                            msgs.extend(msg)

                        for msg in self.verifier.reger.clonePreIter(pre=vci):
                            msgs.extend(msg)

                        vcs = [handling.envelope(msg=craw)]

                        sources = self.verifier.reger.sources(self.hby.db, creder)
                        for craw, smsgs in sources:
                            self.postman.send(src=issr, dest=recpt, topic="credential", msg=smsgs)
                            vcs.extend([handling.envelope(msg=craw)])

                        pl = dict(
                            vc=vcs
                        )

                        self.postman.send(src=issr, dest=recpt, topic="credential", msg=msgs)
                        exn = exchanging.exchange(route="/credential/issue", payload=pl)
                        #  TODO:  Respondant must accept transposable signatures to add to the endorsed message
                        self.rep.reps.append(dict(dest=recpt, rep=exn, topic="credential"))

                elif cueKin == "query":
                    qargs = cue["q"]
                    self.witq.query(**qargs)

                elif cueKin == "telquery":
                    qargs = cue["q"]
                    self.witq.telquery(**qargs)

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
                pre = cue["pre"]
                hab = self.hby.habs[pre]

                if cueKin == "send":
                    tevt = cue["msg"]
                    sub = cue["sub"]

                    witSender = agenting.WitnessPublisher(hab=hab, msg=bytearray(tevt))
                    self.extend([witSender])

                    while not witSender.done:
                        _ = yield self.tock

                    self.remove([witSender])

                    if sub is not None:
                        self.postman.send(src=pre, dest=sub["i"], topic="credential", msg=bytearray(tevt))
                elif cueKin == "kevt":
                    kevt = cue["msg"]
                    serder = eventing.Serder(raw=bytearray(kevt))
                    self.witDoer.msgs.append(dict(pre=pre, sn=serder.sn))

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


def loadEnds(app, *, path, hby, rep, mbx, verifier, gdoer, issuerCues, issuers):
    """
    Load endpoints for KIWI admin interface into the provided Falcon app

    Args:
        app (falcon.App): falcon.App to register handlers with:
        path (str): directory location of UI web app files to be served with this API server
        hby (Habery): database environment for all endpoints
        rep (Respondant): that routes responses to the appropriate mailboxes
        mbx (Mailboxer): mailbox storage class
        verifier (Verifier): that process credentials
        gdoer (Union(decking.Deck,None)): of msgs to send to a MultisigDoer
        issuers (Union(dict,None)): of credential Issuers keyed by regk of credential Registry
        issuerCues (Deck): from Kevery handling key events:

    Returns:
        list: doers from registering endpoints

    """
    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    swagsink = http.serving.StaticSink(staticDirPath="./static")
    app.add_sink(swagsink, prefix="/swaggerui")

    identifierEnd = IdentifierEnd(hby=hby)
    app.add_route("/ids", identifierEnd)
    app.add_route("/ids/{alias}", identifierEnd)

    registryEnd = RegistryEnd(hby=hby)
    app.add_route("/registries", registryEnd)

    credentialsEnd = CredentialsEnd(hby=hby, rep=rep,
                                    verifier=verifier,
                                    issuers=issuers,
                                    cues=issuerCues)
    app.add_route("/credentials", credentialsEnd)

    applicationsEnd = ApplicationsEnd(rep=rep)
    app.add_route("/applications", applicationsEnd)

    presentationEnd = PresentationEnd(rep=rep)
    app.add_route("/presentation", presentationEnd)

    multisigEnd = MultisigEnd(hby=hby, rep=rep, gdoer=gdoer)
    app.add_route("/multisig", multisigEnd)

    oobiEnd = OobiResource(hby=hby)
    app.add_route("/oobi/{alias}", oobiEnd)

    chacha = ChallengeEnd(hby=hby, rep=rep)
    app.add_route("/challenge", chacha)
    app.add_route("/challenge/{alias}", chacha)

    resources = [identifierEnd, registryEnd, oobiEnd, applicationsEnd, credentialsEnd,
                 presentationEnd, multisigEnd, chacha]

    app.add_route("/spec.yaml", SpecResource(app=app, title='KERI Interactive Web Interface API',
                                             resources=resources))

    return [identifierEnd, registryEnd]


def setup(hby, servery, *, controller="", insecure=False, tcp=5621, staticPath=""):
    """ Setup and run a KIWI agent

    Parameters:
        hby (Habery):
        servery (Servery): HTTP server manager for stopping and restarting HTTP servers
        controller:
        insecure:
        tcp:
        staticPath:

    Returns:

    """

    # setup doers
    doers = [habbing.HaberyDoer(habery=hby)]

    tcpServer = tcpServing.Server(host="", port=tcp)
    tcpServerDoer = tcpServing.ServerDoer(server=tcpServer)

    reger = viring.Registry(name=hby.name, temp=False, db=hby.db)
    verifier = verifying.Verifier(hby=hby, reger=reger)
    wallet = walleting.Wallet(reger=verifier.reger, name=hby.name)

    handlers = []

    proofs = decking.Deck()
    issuerCues = decking.Deck()

    issueHandler = handling.IssueHandler(hby=hby, verifier=verifier)
    requestHandler = handling.RequestHandler(hby=hby, wallet=wallet)
    applyHandler = handling.ApplyHandler(hby=hby, verifier=verifier, name=hby.name, issuerCues=issuerCues)
    proofHandler = handling.ProofHandler(proofs=proofs)

    mbx = storing.Mailboxer(name=hby.name)
    mih = grouping.MultisigInceptHandler(controller=controller, mbx=mbx)
    ish = grouping.MultisigIssueHandler(controller=controller, mbx=mbx)
    meh = grouping.MultisigEventHandler(hby=hby, verifier=verifier)

    handlers.extend([issueHandler, requestHandler, proofHandler, applyHandler, mih, ish, meh])

    exchanger = exchanging.Exchanger(hby=hby, handlers=handlers)

    rep = storing.Respondant(hby=hby, mbx=mbx)
    cues = decking.Deck()
    mbd = indirecting.MailboxDirector(hby=hby,
                                      exc=exchanger,
                                      verifier=verifier,
                                      rep=rep,
                                      topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate"],
                                      cues=cues)
    # configure a kevery
    doers.extend([exchanger, tcpServerDoer, mbd, rep])
    doers.extend(adminInterface(servery=servery,
                                controller=controller,
                                hby=hby,
                                insecure=insecure,
                                proofs=proofs,
                                cues=cues,
                                issuerCues=issuerCues,
                                verifier=verifier,
                                mbx=mbx,
                                mbd=mbd,
                                staticPath=staticPath))

    return doers


def adminInterface(servery, controller, hby, insecure, proofs, cues, issuerCues, mbx, mbd, verifier,
                   staticPath=""):
    """ create admin interface for KIWI agent

    Parameters:
        servery (Servery): HTTP server manager for stopping and restarting HTTP servers
        controller:
        hby:
        insecure:
        proofs:
        cues:
        issuerCues:
        mbx:
        mbd:
        verifier:
        staticPath:

    Returns:

    """

    rep = storing.Respondant(hby=hby, mbx=mbx)
    gdoer = grouping.MultiSigGroupDoer(hby=hby, ims=mbd.ims)

    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    if not insecure:
        app.add_middleware(httping.SignatureValidationComponent(hby=hby, pre=controller))
    app.req_options.media_handlers.update(media.Handlers())
    app.resp_options.media_handlers.update(media.Handlers())

    issuers = dict()
    endDoers = loadEnds(app, path=staticPath, hby=hby, rep=rep, mbx=mbx, verifier=verifier, gdoer=gdoer,
                        issuerCues=issuerCues, issuers=issuers)

    servery.msgs.append(dict(app=app))
    kiwiServer = KiwiDoer(hby=hby,
                          rep=rep,
                          verifier=verifier,
                          gdoer=gdoer.msgs,
                          issuers=issuers,
                          issuerCues=issuerCues)

    proofHandler = AdminProofHandler(hby=hby, controller=controller, mbx=mbx, verifier=verifier, proofs=proofs,
                                     ims=mbd.ims)
    cuery = Cuery(hby=hby, controller=controller, mbx=mbx, cues=cues)

    doers = [rep, proofHandler, cuery, gdoer, kiwiServer]
    doers.extend(endDoers)

    return doers


class AdminProofHandler(doing.DoDoer):
    def __init__(self, hby, controller, mbx, verifier, proofs=None, ims=None, **kwa):
        self.hby = hby
        self.controller = controller
        self.mbx = mbx
        self.verifier = verifier
        self.presentations = proofs if proofs is not None else decking.Deck()
        self.parsed = decking.Deck()

        self.ims = ims if ims is not None else bytearray()

        doers = [doing.doify(self.presentationDo), doing.doify(self.parsedDo)]

        super(AdminProofHandler, self).__init__(doers=doers, **kwa)

    def presentationDo(self, tymth, tock=0.0, **opts):
        """

        Handle proofs presented externally

        Parameters:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        yield  # enter context

        while True:
            while self.presentations:
                (pre, presentation) = self.presentations.popleft()
                vc = presentation["vc"]
                vcproof = bytearray(presentation["proof"].encode("utf-8"))
                msgs = bytearray(presentation["msgs"].encode("utf-8"))
                self.ims.extend(msgs)
                yield

                creder = proving.Credentialer(ked=vc)

                # Remove credential from database so we revalidate it fully
                self.verifier.reger.saved.rem(creder.said)

                msg = bytearray(creder.raw)
                msg.extend(vcproof)
                parsing.Parser().parse(ims=msg, vry=self.verifier)

                c = self.verifier.reger.saved.get(creder.said)
                while c is None:
                    c = self.verifier.reger.saved.get(creder.said)
                    yield

                self.parsed.append((creder, vcproof))

                yield

            yield

    def parsedDo(self, tymth, tock=0.0, **opts):
        """

        Handle proofs presented externally

        Parameters:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        yield  # enter context

        while True:
            while self.parsed:
                (creder, vcproof) = self.parsed.popleft()
                hab = self.hby.habs[creder.issuer]

                c = self.verifier.reger.saved.get(creder.said)
                if c is None:
                    self.parsed.append((creder, vcproof))

                else:
                    creders = self.verifier.reger.cloneCreds([creder.saider])
                    cred = creders[0]

                    ser = exchanging.exchange(route="/cmd/presentation/proof", payload=cred)
                    msg = bytearray(ser.raw)
                    msg.extend(hab.endorse(ser))

                    self.mbx.storeMsg(self.controller + "/presentation", msg)

                yield
            yield


class Cuery(doing.DoDoer):
    """ Handle cues from the admin

    """

    def __init__(self, controller, hby, mbx, cues=None, **kwa):
        """

        Parameters:
            mbx is Mailboxer for saving messages for controller
            cues is cues Deck from external mailbox to process

        """
        self.controller = controller
        self.hby = hby
        self.mbx = mbx
        self.cues = cues if cues is not None else decking.Deck()
        self.postman = forwarding.Postman(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=hby)

        super(Cuery, self).__init__(doers=[self.postman, self.witDoer, doing.doify(self.cueDo)], **kwa)

    def cueDo(self, tymth, tock=0.0, **opts):
        """

        Handle cues coming out of our external Mailbox listener and forward to controller
        mailbox if appropriate

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.cues:
                cue = self.cues.popleft()
                cueKin = cue["kin"]  # type or kind of cue
                pre = cue["pre"]
                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]
                if cueKin in ("challenge",):
                    signer = cue["signer"]
                    words = cue["words"]
                    ser = exchanging.exchange(route="/cmd/challenge/responsee",
                                              payload=dict(signer=signer, words=words))
                    msg = bytearray(ser.raw)
                    msg.extend(hab.endorse(ser))

                    self.mbx.storeMsg(self.controller + "/challenge", msg)

                yield self.tock
            yield self.tock
