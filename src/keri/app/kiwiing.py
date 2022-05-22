# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json
from urllib.parse import urlparse

import falcon
import mnemonic
from falcon import media
from hio.base import doing
from hio.core import http
from hio.help import decking

from . import grouping, challenging, connecting
from .. import help
from .. import kering
from ..app import specing, forwarding, agenting, storing, indirecting, httping, habbing, delegating, booting
from ..core import coring, eventing, cueing
from ..db import dbing
from ..db.dbing import dgKey
from ..end import ending
from ..peer import exchanging
from ..vc import proving, protocoling, walleting
from ..vdr import verifying, credentialing

logger = help.ogler.getLogger()


class LockEnd(doing.DoDoer):
    """
    ReST API for locking
    """

    def __init__(self, servery, bootConfig):
        self.servery = servery
        self.bootConfig = bootConfig

        super(LockEnd, self).__init__(doers=[])

    def on_get(self, _, rep):
        """ Lock POST endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary:  Lock
        description:  Reloads the API to the boot version
        tags:
           - Lock
        responses:
            200:
              description: locked


        """
        doers = booting.setup(servery=self.servery, controller=self.bootConfig["controller"],
                              configFile=self.bootConfig["configFile"],
                              configDir=self.bootConfig["configDir"],
                              insecure=self.bootConfig["insecure"],
                              tcp=self.bootConfig["tcp"],
                              adminHttpPort=self.bootConfig["adminHttpPort"],
                              path=self.bootConfig["staticPath"],
                              headDirPath=self.bootConfig["headDirPath"])
        self.extend(doers)

        rep.status = falcon.HTTP_200
        body = dict(msg="locked")
        rep.content_type = "application/json"
        rep.data = json.dumps(body).encode("utf-8")


class IdentifierEnd(doing.DoDoer):
    """
    ReST API for admin of Identifiers
    """

    def __init__(self, hby, **kwa):
        self.hby = hby

        self.postman = forwarding.Postman(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.swain = delegating.Boatswain(hby=hby)
        self.org = connecting.Organizer(hby=hby)
        self.cues = decking.Deck()

        doers = [self.witDoer, self.postman, self.swain, doing.doify(self.eventDo)]

        super(IdentifierEnd, self).__init__(doers=doers, **kwa)

    def on_get(self, _, rep):
        """ Identifier GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary:  Get list of agent identifiers
        description:  Get the list of identifiers associated with this agent
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
            info = self.info(hab)
            res.append(info)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_get_alias(self, _, rep, alias=None):
        """ Identifier GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

        ---
        summary:  Get list of agent identifiers
        description:  Get identifier information associated with alias
        tags:
           - Identifiers
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the identifier to get
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
        hab = self.hby.habByName(alias)
        info = self.info(hab)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(info).encode("utf-8")

    def info(self, hab):
        data = dict(
            name=hab.name,
            prefix=hab.pre,
        )

        if hab.phab:
            data["group"] = dict(
                pid=hab.phab.pre,
                accepted=hab.accepted
            )

        if hab.accepted:
            kever = hab.kevers[hab.pre]
            ser = kever.serder
            dgkey = dbing.dgKey(ser.preb, ser.saidb)
            wigs = hab.db.getWigs(dgkey)
            data |= dict(
                seq_no=kever.sn,
                isith=kever.tholder.sith,
                public_keys=[verfer.qb64 for verfer in kever.verfers],
                nsith=kever.ntholder.sith,
                next_keys=kever.nexter.digs,
                toad=kever.toad,
                witnesses=kever.wits,
                receipts=len(wigs)
            )

            if kever.delegated:
                data["delegated"] = kever.delegated
                data["delegator"] = kever.delegator
                dgkey = dgKey(pre=hab.kever.prefixer.qb64, dig=hab.kever.serder.saidb)
                anchor = self.hby.db.getAes(dgkey)
                data["anchored"] = anchor is not None

        md = self.org.get(hab.pre)
        if md is not None:
            del md["id"]
            data["metadata"] = md

        return data

    def on_put_alias(self, req, rep, alias):
        """ Identifier PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of identifier to update contact information

        ---
        summary:  Update metadata associated with the identfier of the alias
        description:  Update metadata associated with the identfier of the alias
        tags:
           - Identifiers
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: human readable name of identifier prefix to add metadata
        requestBody:
            required: true
            content:
              application/json:
                schema:
                    description: Contact information
                    type: object

        responses:
           200:
              description: Updated contact information for remote identifier
           400:
              description: Invalid identfier used to update contact information
           404:
              description: Prefix not found in identifier contact information
        """
        body = req.get_media()
        hab = self.hby.habByName(name=alias)

        if hab is None:
            rep.status = falcon.HTTP_404
            rep.text = f"{alias} does not represent a known identifier."
            return

        if "id" in body:
            del body["id"]

        self.org.update(alias, hab.pre, body)
        contact = self.org.get(hab.pre)

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(contact).encode("utf-8")

    def on_post_alias(self, req, rep, alias):
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
        hab = self.hby.habByName(name=alias)
        if hab is not None:
            rep.status = falcon.HTTP_400
            body = dict(code=falcon.HTTP_400, msg="fInvalid incept request, {alias} already used")
            rep.content_type = "application/json"
            rep.data = json.dumps(body).encode("utf-8")
            return

        body = req.get_media()

        isith = None
        if "isith" in body:
            isith = body["isith"]
            if isinstance(isith, str) and "," in isith:
                isith = isith.split(",")

        nsith = None
        if "nsith" in body:
            nsith = body["nsith"]
            if isinstance(nsith, str) and "," in nsith:
                nsith = nsith.split(",")

        transferable = body.get("transferable") if "transferable" in body else True
        wits = body.get("wits") if "wits" in body else []
        toad = int(body.get("toad")) if "toad" in body else None
        icount = int(body.get("count")) if "count" in body else 1
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
        if "delpre" in body:
            kwa["delpre"] = body["delpre"]

        hab = self.hby.makeHab(name=alias, **kwa)
        self.cues.append(dict(pre=hab.pre))

        icp = hab.makeOwnInception()
        serder = coring.Serder(raw=icp)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = serder.raw

    def on_put_rot(self, req, rep, alias):
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
            description: Human readable alias for the identifier to rotate
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
                   adds:
                     type: array
                     description: list of witness identifiers to add
                     items:
                        type: string
                   cuts:
                     type: array
                     description: list of witness identifiers to remove
                     items:
                        type: string
                   toad:
                     type: integer
                     description: witness threshold
                     default: 1
                   isith:
                     type: string
                     description: signing threshold
                   count:
                     type: integer
                     description: count of next key commitment.
                   data:
                     type: array
                     description: list of data objects to anchor to this rotation event
                     items:
                        type: object
        responses:
           200:
              description: Rotation successful with KEL event returned
           400:
              description: Error creating rotation event

        """
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.data = f"no matching Hab for alias {alias}"
            return

        body = req.get_media()
        isith = None
        if "isith" in body:
            isith = body["isith"]
            if isinstance(isith, str) and "," in isith:
                isith = isith.split(",")

        wits = body.get("wits")
        toad = int(body.get("toad")) if "toad" in body else None
        count = int(body.get("count")) if "count" in body else None
        data = body["data"] if "data" in body else None
        cuts = set()
        adds = set()

        if wits:
            ewits = hab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            cuts = set(ewits) - set(wits)
            adds = set(wits) - set(ewits)

        try:
            rot = hab.rotate(sith=isith, count=count, toad=toad, cuts=list(cuts), adds=list(adds), data=data)
            self.cues.append(dict(pre=hab.pre))

            serder = coring.Serder(raw=rot)
            rep.status = falcon.HTTP_200
            rep.content_type = "application/json"
            rep.data = serder.raw

        except (ValueError, TypeError, Exception) as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]

    def on_put_ixn(self, req, rep, alias):
        """  Identifier PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for Hab

        ---
        summary:  Interaction event for agent identifier
        description:  Perform an interaction event on the agent's current identifier
        tags:
           - Identifiers
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the identifier to ineract
        requestBody:
           required: true
           content:
             application/json:
               schema:
                 type: object
                 properties:
                   data:
                     type: array
                     description: list of data objects to anchor to this rotation event
                     items:
                        type: object
        responses:
           200:
              description: Interaction successful with KEL event returned
           400:
              description: Error creating interaction event

        """
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.data = f"no matching Hab for alias {alias}"
            return

        body = req.get_media()
        data = body["data"] if "data" in body else None

        try:
            ixn = hab.interact(data=data)
            self.cues.append(dict(pre=hab.pre))

            serder = coring.Serder(raw=ixn)
            rep.status = falcon.HTTP_200
            rep.content_type = "application/json"
            rep.data = serder.raw

        except (ValueError, TypeError, Exception) as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]

    def eventDo(self, tymth, tock=0.0):
        """ Check for accepted Habs that have not been delegated or receipted and do so

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while not self.cues:
                yield self.tock

            cue = self.cues.popleft()
            pre = cue["pre"]
            hab = self.hby.habs[pre]

            if hab.phab:  # Skip if group, they are handled elsewhere
                yield self.tock
                continue

            if hab.kever.delegator and hab.kever.ilk in (coring.Ilks.dip, coring.Ilks.drt):
                dgkey = dgKey(pre=hab.kever.prefixer.qb64, dig=hab.kever.serder.saidb)
                anchor = self.hby.db.getAes(dgkey)
                if not anchor:
                    self.swain.msgs.append(dict(alias=hab.name, pre=hab.pre, sn=hab.kever.sn))
                    print("Waiting for delegation approval...")
                    while not self.swain.cues:
                        yield self.tock

                    self.swain.cues.popleft()
                    print("Delegation anchored")

            dgkey = dbing.dgKey(hab.kever.serder.preb, hab.kever.serder.saidb)
            wigs = hab.db.getWigs(dgkey)
            if len(wigs) != len(hab.kever.wits):
                self.witDoer.msgs.append(dict(pre=hab.pre))
                while True:
                    yield self.tock
                    wigs = hab.db.getWigs(dgkey)
                    if len(wigs) == len(hab.kever.wits):
                        break

            if hab.kever.delegator:
                yield from self.postman.sendEvent(hab=hab, fn=hab.kever.sn)

            yield self.tock


class KeyStateEnd:

    def __init__(self, hby):
        self.hby = hby

    def on_get(self, _, rep, prefix):
        """

        Parameters:
            _ (Request): falcon.Request HTTP request
            rep (Response): falcon.Response HTTP response
            prefix (str): qb64 identifier prefix to load key state and key event log

        ---
        summary:  Display key event log (KEL) for given identifier prefix
        description:  If provided qb64 identifier prefix is in Kevers, return the current state of the
                      identifier along with the KEL and all associated signatures and receipts
        tags:
           - Ket Event Log
        parameters:
          - in: path
            name: prefix
            schema:
              type: string
            required: true
            description: qb64 identifier prefix of KEL to load
        responses:
           200:
              description: Key event log and key state of identifier
           404:
              description: Identifier not found in Key event database


        """
        if prefix not in self.hby.kevers:
            rep.status = falcon.HTTP_404
            rep.text = f"no information found for {prefix}"
            return

        kever = self.hby.kevers[prefix]
        pre = kever.prefixer.qb64
        preb = kever.prefixer.qb64b

        res = dict(
            pre=pre,
            state=kever.state().ked
        )

        kel = []
        for fn, dig in self.hby.db.getFelItemPreIter(preb, fn=0):
            try:
                event = loadEvent(self.hby.db, preb, dig)
            except ValueError as e:
                rep.status = falcon.HTTP_400
                rep.text = e.args[0]
                return

            kel.append(event)

        res["kel"] = kel

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")


class RegistryEnd(doing.DoDoer):
    """
    ReST API for admin of credential issuance and revocation registries

    """

    def __init__(self, hby, rgy, registrar, **kwa):
        self.hby = hby
        self.rgy = rgy
        self.registrar = registrar

        super(RegistryEnd, self).__init__(doers=[], **kwa)

    def on_get(self, _, rep):
        """  Registries GET endpoint

        Parameters:
            _: falcon.Request HTTP request
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
        res = []
        for name, registry in self.rgy.regs.items():
            rd = dict(
                name=registry.name,
                regk=registry.regk,
                pre=registry.hab.pre,
                state=registry.tever.state().ked
            )
            res.append(rd)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

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
                    alias:
                      type: string
                      description: name of identifier to associate as the issuer of the new credential registry
                    toad:
                      type: integer
                      description: Backer receipt threshold
                    nonce:
                      type: string
                      description: qb64 encoded ed25519 random seed for registry
                    noBackers:
                      type: boolean
                      required: False
                      description: True means to not allow seperate backers from identifier's witnesses.
                    baks:
                      type: array
                      items:
                         type: string
                      description: List of qb64 AIDs of witnesses to be used for the new group identfier.
                    estOnly:
                      type: boolean
                      required: false
                      default: false
                      description: True means to not allow interaction events to anchor credential events.
        responses:
           202:
              description:  registry inception request has been submitted

        """
        body = req.get_media()

        if "name" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "name is a required parameter to create a verifiable credential registry"
            return

        if "alias" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "alias is a required parameter to create a verifiable credential registry"
            return

        alias = body["alias"]
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_404
            rep.text = "alias is not a valid reference to an identfier"
            return

        c = dict()
        if "noBackers" in body:
            c["noBackers"] = body["noBackers"]
        if "baks" in body:
            c["baks"] = body["baks"]
        if "toad" in body:
            c["toad"] = body["toad"]
        if "estOnly" in body:
            c["estOnly"] = body["estOnly"]
        if "nonce" in body:
            c["nonce"] = body["nonce"]

        self.registrar.incept(name=body["name"], pre=hab.pre, conf=c)

        rep.status = falcon.HTTP_202


class CredentialEnd(doing.DoDoer):
    """
    ReST API for admin of credentials

    """

    def __init__(self, hby, rgy, registrar, credentialer, verifier, cues=None):
        """ Create endpoint for issuing and listing credentials

        Endpoints for issuing and listing credentials from non-group identfiers only

        Parameters:
            hby (Habery): identifier database environment
            rgy (Regery): credential registry database environment
            verifier (Verifier): credential verifier
            registrar (Registrar): credential registry protocol manager
            credentialer: (Credentialer): credential protocol manager
            cues (Deck): outbound notifications

        """
        self.hby = hby
        self.rgy = rgy
        self.credentialer = credentialer
        self.registrar = registrar
        self.verifier = verifier
        self.postman = forwarding.Postman(hby=self.hby)
        self.cues = cues if cues is not None else decking.Deck()
        self.evts = decking.Deck()

        super(CredentialEnd, self).__init__(doers=[self.postman, doing.doify(self.evtDo)])

    def on_get(self, req, rep, alias):
        """ Credentials GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name of identifier to load credentials for

        ---
        summary:  List credentials in credential store (wallet)
        description: List issued or received credentials current verified
        tags:
           - Credentials
        parameters:
           - in: path
             name: alias
             schema:
               type: string
             required: true
             description: Human readable alias for the identifier to create
           - in: query
             name: type
             schema:
                type: string
             description:  type of credential to return, [issued|received]
             required: true
        responses:
           200:
              description: Credential list.
              content:
                  application/json:
                    schema:
                        description: Credentials
                        type: array
                        items:
                           type: object

        """
        typ = req.params.get("type")

        hab = self.hby.habByName(name=alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credentials" \
                       "".format(alias)
            return

        creds = []
        if typ == "issued":
            saids = self.rgy.reger.issus.get(keys=hab.pre)
            creds = self.rgy.reger.cloneCreds(saids)

        elif typ == "received":
            saids = self.verifier.reger.subjs.get(keys=hab.pre)
            creds = self.verifier.reger.cloneCreds(saids)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(creds).encode("utf-8")

    def on_post(self, req, rep, alias):
        """ Initiate a credential issuance

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: qb64 identfier prefix of issuer of credential

        ---
        summary: Perform credential issuance
        description: Perform credential issuance
        tags:
           - Credentials
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
                    registry:
                      type: string
                      description: AID of credential issuance/revocation registry (aka status)
                    recipient:
                      type: string
                      description: AID of credential issuance/revocation recipient
                    schema:
                      type: string
                      description: SAID of credential schema being issued
                    source:
                      type: object
                      description: ACDC edge or edge group for chained credentials
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
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credential issuance" \
                       "".format(alias)
            return None

        regname = body.get("registry")
        recp = body.get("recipient")
        schema = body.get("schema")
        source = body.get("source")
        rules = body.get("rules")
        data = body.get("credentialData")

        try:
            creder = self.credentialer.create(regname, recp, schema, source, rules, data)
            self.credentialer.issue(creder=creder)
        except kering.ConfigurationError as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]
            return

        # cue up an event to send notification when complete
        self.evts.append(dict(topic="/credential", r="/iss/complete", d=creder.said))

        rep.status = falcon.HTTP_200
        rep.data = creder.pretty().encode("utf-8")

    def on_post_iss(self, req, rep, alias=None):
        """ Initiate a credential issuance from a group multisig identfier

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: qb64 identfier prefix of issuer of credential

        ---
        summary: Initiate credential issuance from a group multisig identifier
        description: Initiate credential issuance from a group multisig identifier
        tags:
           - Group Credentials
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
                    registry:
                      type: string
                      description: AID of credential issuance/revocation registry (aka status)
                    recipient:
                      type: string
                      description: AID of credential issuance/revocation recipient
                    schema:
                      type: string
                      description: SAID of credential schema being issued
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
        hab = self.hby.habByName(alias)
        if hab is None or hab.phab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for group credentials" \
                       "".format(alias)
            return

        regname = body.get("registry")
        recp = body.get("recipient")
        schema = body.get("schema")
        source = body.get("source")
        rules = body.get("rules")
        data = body.get("credentialData")
        try:
            creder = self.credentialer.create(regname, recp, schema, source, rules, data)
            self.credentialer.issue(creder=creder)
        except kering.ConfigurationError as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]
            return

        exn, atc = grouping.multisigIssueExn(hab=hab, creder=creder)
        others = list(hab.aids)
        others.remove(hab.phab.pre)

        for recpt in others:
            self.postman.send(src=hab.phab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

        # cue up an event to send notification when complete
        self.evts.append(dict(topic="/multisig", r="/iss/complete", d=creder.said))

        rep.status = falcon.HTTP_200
        rep.data = creder.pretty().encode("utf-8")

    def on_put_iss(self, req, rep, alias=None):
        """ Participate in a credential issuance from a group identfier

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: qb64 identfier prefix of issuer of credential

        ---
        summary: Participate in a credential issuance from a group multisig identifier
        description: Participate in a credential issuance from a group multisig identifier
        tags:
           - Group Credentials
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
                    credential:
                      type: object
                      description: Fully populated ACDC credential to issue
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
        hab = self.hby.habByName(alias)
        if hab is None or hab.phab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for group credentials" \
                       "".format(alias)
            return None

        if "credential" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "credential required in body"
            return None

        data = body["credential"]
        creder = proving.Creder(ked=data)

        try:
            self.credentialer.validate(creder=creder)
            self.credentialer.issue(creder=creder)
        except kering.ConfigurationError as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]
            return

        # cue up an event to send notification when complete
        self.evts.append(dict(topic="/multisig", r="/iss/complete", d=creder.said))

        rep.status = falcon.HTTP_200
        rep.data = creder.pretty().encode("utf-8")

    def revoke(self, req, rep, said):
        regname = req.get_param("registry")

        registry = self.rgy.registryByName(regname)
        if registry is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(regname)
            return False

        try:
            creder = self.verifier.reger.creds.get(keys=(said,))
            if creder is None:
                rep.status = falcon.HTTP_NOT_FOUND
                rep.text = "credential not found"
                return False

            self.registrar.revoke(regk=registry.regk, said=creder.said)
        except kering.ValidationError as ex:
            rep.status = falcon.HTTP_CONFLICT
            rep.text = ex.args[0]
            return False

        return True

    def on_delete(self, req, rep, alias=None):
        """ Credential DELETE endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: qb64 identfier prefix of issuer of credential

        ---
        summary: Revoke credential
        description: PArticipate in a credential revocation for a group multisig issuer
        tags:
           - Credentials
        parameters:
           - in: query
             name: registry
             schema:
                type: string
             description:  SAID of credential registry
             required: true
           - in: path
             name: alias
             schema:
                type: string
             description: human readable alias for issuer identifier
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
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credential revocation" \
                       "".format(alias)
            return None

        said = req.params.get("said")

        if self.revoke(req=req, rep=rep, said=said):
            # cue up an event to send notification when complete
            self.evts.append(dict(topic="/credential", r="/rev/complete", d=said))

            rep.status = falcon.HTTP_202

        # Else the revoke method handled the status

    def on_post_rev(self, req, rep, alias=None, said=None):
        """ Credential DELETE endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: qb64 identfier prefix of issuer of credential
            said: qb64 SAID of the credential to be revoked

        ---
        summary: Revoke credential
        description: Initiate a credential revocation for a group multisig issuer
        tags:
           - Group Credentials
        parameters:
           - in: query
             name: registry
             schema:
                type: string
             description:  SAID of credential registry
             required: true
           - in: path
             name: alias
             schema:
                type: string
             description: human readable alias for issuer identifier
             required: true
           - in: path
             name: said
             schema:
                type: string
             description: SAID of credential to revoke
             required: true

        responses:
           202:
              description: credential successfully revoked.

        """
        hab = self.hby.habByName(alias)
        if hab is None or hab.phab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for group credentials" \
                       "".format(alias)
            return None

        if self.revoke(req=req, rep=rep, said=said):
            # TODO: SEND revocation proposal exn to others!

            # cue up an event to send notification when complete
            self.evts.append(dict(topic="/multisig", r="/rev/complete", d=said))

            rep.status = falcon.HTTP_202

        # Else the revoke method handled the status

    def on_put_rev(self, req, rep, alias=None, said=None):
        """ Credential DELETE endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: qb64 identfier prefix of issuer of credential
            said: qb64 identifier prefix of recipient of credential

        ---
        summary: Revoke credential
        description: PArticipate in a credential revocation for a group multisig issuer
        tags:
           - Group Credentials
        parameters:
           - in: query
             name: registry
             schema:
                type: string
             description:  SAID of credential registry
             required: true
           - in: path
             name: alias
             schema:
                type: string
             description: human readable alias for issuer identifier
             required: true
           - in: path
             name: said
             schema:
                type: string
             description: SAID of credential to revoke
             required: true

        responses:
           202:
              description: credential successfully revoked.

        """
        hab = self.hby.habByName(alias)
        if hab is None or hab.phab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for group credentials" \
                       "".format(alias)
            return None

        if self.revoke(req=req, rep=rep, said=said):
            # cue up an event to send notification when complete
            self.evts.append(dict(topic="/multisig", r="/rev/complete", d=said))

            rep.status = falcon.HTTP_202

        # Else the revoke method handled the status

    def evtDo(self, tymth, tock=0.5):
        """ Monitor results of inception initiation and raise a cue when one completes

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method for monitoring events

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            if not self.evts:
                yield self.tock
                continue

            evt = self.evts.popleft()
            tpc = evt["topic"]
            said = evt["d"]
            route = evt["r"]

            if route == "/iss/complete":
                if self.credentialer.complete(said=said):
                    self.cues.append(dict(
                        kin="notification",
                        topic=tpc,
                        msg=dict(
                            r=route,
                            a=dict(d=said)
                        )
                    ))
                else:
                    self.evts.append(evt)

            elif route == "/rev/complete":
                if self.registrar.complete(pre=said, sn=1):
                    self.cues.append(dict(
                        kin="notification",
                        topic=tpc,
                        msg=dict(
                            r=route,
                            a=dict(d=said)
                        )
                    ))
                else:
                    self.evts.append(evt)

            yield self.tock


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


class MultisigEndBase(doing.DoDoer):

    def __init__(self, counselor, cues, doers):

        self.cues = cues
        self.counselor = counselor
        self.evts = decking.Deck()
        doers.extend([doing.doify(self.evtDo)])

        super(MultisigEndBase, self).__init__(doers=doers)

    def evtDo(self, tymth, tock=0.5):
        """ Monitor results of inception initiation and raise a cue when one completes

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method for monitoring events

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            if not self.evts:
                yield self.tock
                continue

            evt = self.evts.popleft()
            pre = evt["i"]
            sn = evt["s"]
            saider = coring.Saider(qb64=evt["d"]) if "d" in evt else None

            route = evt["r"]
            prefixer = coring.Prefixer(qb64=pre)
            seqner = coring.Seqner(sn=sn)

            if self.counselor.complete(prefixer, seqner, saider):
                self.cues.append(dict(
                    kin="notification",
                    topic="/multisig",
                    msg=dict(
                        r=route,
                        a=dict(i=pre, s=sn)
                    )
                ))
            else:
                self.evts.append(evt)

            yield self.tock


class MultisigInceptEnd(MultisigEndBase):
    """
    ReST API for admin of distributed multisig groups

    """

    def __init__(self, hby, counselor, cues=None):
        """ Create an endpoint resource for creating or participating in multisig group identfiiers

        Parameters:
            hby (Habery): identifier database environment
            counselor (Counselor): multisig group communication management

        """

        self.hby = hby
        self.counselor = counselor
        self.cues = cues if cues is not None else decking.Deck()
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(MultisigInceptEnd, self).__init__(cues=self.cues, counselor=counselor, doers=doers)

    def initialize(self, body, rep, alias):
        if "aids" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group inception request, 'aids' is required'"
            return None, None

        aids = body["aids"]
        hab = None
        for aid in aids:
            if aid in self.hby.habs:
                hab = self.hby.habs[aid]
                break

        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group inception request, aid list must contain a local identifier'"
            return None, None

        if self.hby.habByName(alias) is not None:
            rep.status = falcon.HTTP_400
            rep.text = f"Identifier alias {alias} is already in use"
            return None, None

        inits = dict(
            aids=aids
        )

        isith = None
        if "isith" in body:
            isith = body["isith"]
            if isinstance(isith, str) and "," in isith:
                isith = isith.split(",")

        inits["isith"] = isith
        
        nsith = None
        if "nsith" in body:
            nsith = body["nsith"]
            if isinstance(nsith, str) and "," in nsith:
                nsith = nsith.split(",")

        inits["nsith"] = nsith

        inits["toad"] = body["toad"] if "toad" in body else None
        inits["wits"] = body["wits"] if "wits" in body else []
        inits["delpre"] = body["delpre"] if "delpre" in body else None

        ghab = self.hby.makeGroupHab(group=alias, phab=hab, **inits)
        return hab, ghab

    def icp(self, hab, ghab, aids):
        """

        Args:
            ghab (Hab): Group Hab to start processing
            hab (Hab): Local participant Hab
            aids (list) Other group participant qb64 identifier prefixes

        """
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)
        self.counselor.start(aids=aids, pid=hab.pre, prefixer=prefixer, seqner=seqner, saider=saider)

    def on_post(self, req, rep, alias):
        """  Multisig POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for new multisig identifier from path

        ---
        summary: Initiate a multisig group inception
        description: Initiate a multisig group inception with the participants identified by the  provided AIDs
        tags:
           - Groups
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
                   aids:
                     type: array
                     items:
                        type: string
                     description: List of qb64 AIDs of participants in multisig group
                   notify:
                     type: boolean
                     required: False
                     description: True means to send mutlsig incept exn message to other participants
                   toad:
                     type: integer
                     description: Witness receipt threshold
                   wits:
                     type: array
                     items:
                        type: string
                     description: List of qb64 AIDs of witnesses to be used for the new group identfier
                   isith:
                     type: string
                     description: Signing threshold for the new group identifier
                   nsith:
                     type: string
                     description: Next signing threshold for the new group identifier

        responses:
           200:
              description: Multisig group AID inception initiated.

        """
        body = req.get_media()

        hab, ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        if not ghab.accepted:
            # Create /multig/incept exn message with icp event and witness oobis as payload events
            evt = grouping.getEscrowedEvent(db=self.hby.db, pre=ghab.pre, sn=0)
        else:
            evt = ghab.makeOwnInception()

        serder = coring.Serder(raw=evt)

        # Create a notification EXN message to send to the other agents
        exn, ims = grouping.multisigInceptExn(hab, aids=ghab.aids, ked=serder.ked)

        others = list(ghab.aids)
        others.remove(hab.pre)

        for recpt in others:  # this goes to other participants only as a signalling mechanism
            self.postman.send(src=hab.pre, dest=recpt, topic="multisig", serder=exn, attachment=ims)

        #  signal to the group counselor to start the inception
        self.icp(hab=hab, ghab=ghab, aids=ghab.aids)

        # cue up an event to send notification when complete
        self.evts.append(dict(r="/icp/complete", i=serder.pre, s=serder.sn, d=serder.said))

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = serder.raw

    def on_put(self, req, rep, alias):
        """  Multisig PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for new multisig identifier from path

        ---
        summary: Participate in a multisig group inception
        description: Participate in a multisig group rotation
        tags:
           - Groups
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
                   aids:
                     type: array
                     items:
                        type: string
                     description: List of qb64 AIDs of participants in multisig group
                   notify:
                     type: boolean
                     required: False
                     description: True means to send mutlsig incept exn message to other participants
                   toad:
                     type: integer
                     description: Witness receipt threshold
                   wits:
                     type: array
                     items:
                        type: string
                     description: List of qb64 AIDs of witnesses to be used for the new group identfier
                   isith:
                     type: string
                     description: Signing threshold for the new group identifier
                   nsith:
                     type: string
                     description: Next signing threshold for the new group identifier

        responses:
           200:
              description: Multisig group AID inception initiated.

        """
        body = req.get_media()
        hab, ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        if not ghab.accepted:
            # Create /multig/incept exn message with icp event and witness oobis as payload events
            evt = grouping.getEscrowedEvent(db=self.hby.db, pre=ghab.pre, sn=0)
        else:
            evt = ghab.makeOwnInception()

        serder = coring.Serder(raw=evt)

        aids = body["aids"]
        self.icp(hab=hab, ghab=ghab, aids=aids)

        # Monitor the final creation of this identifier and send out notification
        self.evts.append(dict(r="/icp/complete", i=serder.pre, s=serder.sn, d=serder.said))

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = serder.raw


class MultisigEventEnd(MultisigEndBase):
    """
    ReST API for admin of distributed multisig group rotations

    """

    def __init__(self, hby, counselor, cues=None):

        self.hby = hby
        self.counselor = counselor
        self.cues = cues if cues is not None else decking.Deck()
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(MultisigEventEnd, self).__init__(cues=self.cues, counselor=counselor, doers=doers)

    def initialize(self, body, rep, alias):
        if "aids" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group rotation request, 'aids' is required"
            return None

        ghab = self.hby.habByName(alias)
        if ghab is None:
            rep.status = falcon.HTTP_404
            rep.text = "Invalid multisig group rotation request alias {alias} not found"
            return None

        aids = body["aids"]
        if ghab.phab.pre not in aids:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group rotation request, aid list must contain a local identifier"
            return None

        return ghab

    def on_post_rot(self, req, rep, alias):
        """  Multisig POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): path parameter human readable name for identifier to rotate

        ---
        summary:  Initiate multisig group rotatation
        description:  Initiate a multisig group rotation with the participants identified by the provided AIDs
        tags:
           - Groups
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
                   aids:
                     type: array
                     description: list of particiant identifiers for this rotation
                     items:
                        type: string
                   wits:
                     type: array
                     description: list of witness identifiers
                     items:
                        type: string
                   adds:
                     type: array
                     description: list of witness identifiers to add
                     items:
                        type: string
                   cuts:
                     type: array
                     description: list of witness identifiers to remove
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
                   data:
                     type: array
                     description: list of data objects to anchor to this rotation event
                     items:
                        type: object
        responses:
           200:
              description: Rotation successful with KEL event returned
           400:
              description: Error creating rotation event

        """
        body = req.get_media()

        ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        isith = None
        if "isith" in body:
            isith = body["isith"]
            if isinstance(isith, str) and "," in isith:
                isith = isith.split(",")

        aids = body["aids"] if "aids" in body else ghab.aids
        toad = body["toad"] if "toad" in body else None
        wits = body["wits"] if "wits" in body else []
        adds = body["adds"] if "adds" in body else []
        cuts = body["cuts"] if "cuts" in body else []
        data = body["data"] if "data" in body else None

        if wits:
            if cuts or adds:
                rep.status = falcon.HTTP_400
                rep.text = "you can only specify wits or cuts and add"
                return

            ewits = ghab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            cuts = set(ewits) - set(wits)
            adds = set(wits) - set(ewits)

        sn = ghab.kever.sn
        # begin the rotation process
        self.counselor.rotate(ghab=ghab, aids=aids, sith=isith, toad=toad, cuts=list(cuts), adds=list(adds), data=data)

        # Create `exn` peer to peer message to notify other participants UI
        exn, atc = grouping.multisigRotateExn(ghab, aids, isith, toad, cuts, adds, data)
        others = list(ghab.aids)
        others.remove(ghab.phab.pre)

        for recpt in others:  # send notification to other participants as a signalling mechanism
            self.postman.send(src=ghab.phab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

        # cue up an event to send notification when complete
        self.evts.append(dict(r="/rot/complete", i=ghab.pre, s=sn))

        rep.status = falcon.HTTP_202

    def on_put_rot(self, req, rep, alias):
        """  Multisig PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for new multisig identifier from path

        ---
        summary:  Participate in multisig group rotatation
        description:  Participate in a multisig group rotation with the participants identified by the provided AIDs
        tags:
           - Groups
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
                   aids:
                     type: array
                     description: list of particiant identifiers for this rotation
                     items:
                        type: string
                   wits:
                     type: array
                     description: list of witness identifiers
                     items:
                        type: string
                   adds:
                     type: array
                     description: list of witness identifiers to add
                     items:
                        type: string
                   cuts:
                     type: array
                     description: list of witness identifiers to remove
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
                   data:
                     type: array
                     description: list of data objects to anchor to this rotation event
                     items:
                        type: object
        responses:
           200:
              description: Rotation successful with KEL event returned
           400:
              description: Error creating rotation event

        """
        body = req.get_media()

        ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        isith = None
        if "isith" in body:
            isith = body["isith"]
            if isinstance(isith, str) and "," in isith:
                isith = isith.split(",")

        aids = body["aids"] if "aids" in body else ghab.aids
        toad = body["toad"] if "toad" in body else None
        wits = body["wits"] if "wits" in body else []
        adds = body["adds"] if "adds" in body else []
        cuts = body["cuts"] if "cuts" in body else []
        data = body["data"] if "data" in body else None

        if wits:
            if adds or cuts:
                rep.status = falcon.HTTP_400
                rep.text = "you can only specify wits or cuts and add"
                return

            ewits = ghab.kever.wits

            # wits= [a,b,c]  wits=[b, z]
            cuts = set(ewits) - set(wits)
            adds = set(wits) - set(ewits)

        sn = ghab.kever.sn
        self.counselor.rotate(ghab=ghab, aids=aids, sith=isith, toad=toad, cuts=list(cuts), adds=list(adds), data=data)

        # cue up an event to send notification when complete
        self.evts.append(dict(r="/rot/complete", i=ghab.pre, s=sn))

        rep.status = falcon.HTTP_202

    def on_post_ixn(self, req, rep, alias):
        """  Multisig Interaction POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for new multisig identifier from path

        ---
        summary:  Initiate multisig group interaction event
        description:  Initiate a multisig group interaction event
        tags:
           - Groups
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
                   aids:
                     type: array
                     description: list of particiant identifiers for this rotation
                     items:
                        type: string
                   data:
                     type: array
                     description: list of data objects to anchor to this rotation event
                     items:
                        type: object
        responses:
           200:
              description: Interaction successful with KEL event returned
           400:
              description: Error creating rotation event
        """
        body = req.get_media()

        ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        aids = body["aids"] if "aids" in body else ghab.aids
        data = body["data"] if "data" in body else None

        exn, atc = grouping.multisigInteractExn(ghab, aids, data)
        others = list(ghab.aids)
        others.remove(ghab.phab.pre)

        for recpt in others:  # send notification to other participants as a signalling mechanism
            self.postman.send(src=ghab.phab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

        serder = self.ixn(ghab=ghab, data=data, aids=aids)
        # cue up an event to send notification when complete
        self.evts.append(dict(r="/ixn/complete", i=serder.pre, s=serder.sn, d=serder.said))

        rep.status = falcon.HTTP_202

    def on_put_ixn(self, req, rep, alias):
        """  Multisig Interaction PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for new multisig identifier from path

        ---
        summary:  Participate in multisig group interaction event
        description:  Participate in a multisig group interaction event
        tags:
           - Groups
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
                   aids:
                     type: array
                     description: list of particiant identifiers for this rotation
                     items:
                        type: string
                   data:
                     type: array
                     description: list of data objects to anchor to this rotation event
                     items:
                        type: object
        responses:
           200:
              description: Interaction successful with KEL event returned
           400:
              description: Error creating rotation event
        """
        body = req.get_media()

        ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        aids = body["aids"] if "aids" in body else ghab.aids
        data = body["data"] if "data" in body else None

        serder = self.ixn(ghab=ghab, data=data, aids=aids)
        # cue up an event to send notification when complete
        self.evts.append(dict(r="/ixn/complete", i=serder.pre, s=serder.sn, d=serder.said))

        rep.status = falcon.HTTP_202

    def ixn(self, ghab, data, aids):
        ixn = ghab.interact(data=data)

        serder = coring.Serder(raw=ixn)

        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=serder.sn)
        saider = coring.Saider(qb64b=serder.saidb)
        self.counselor.start(aids=aids, pid=ghab.phab.pre, prefixer=prefixer, seqner=seqner, saider=saider)
        return serder


class OobiResource(doing.DoDoer):
    """
    Resource for managing OOBIs

    """

    def __init__(self, hby, oobiery=None):
        """ Create Endpoints for discovery and resolution of OOBIs

        Parameters:
            hby (Habery): identifier database environment
            oobiery (Optioanl[Oobiery]): optional OOBI loader
        """
        self.hby = hby

        self.oobiery = oobiery if oobiery is not None else ending.Oobiery(hby=self.hby)
        doers = [self.oobiery, doing.doify(self.loadDo)]

        super(OobiResource, self).__init__(doers=doers)

    def on_get_alias(self, req, rep, alias=None):
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
                    rep.status = falcon.HTTP_404
                    rep.text = f"unable to query witness {wit}, no http endpoint"
                    return

                up = urlparse(urls[kering.Schemes.http])
                oobis.append(f"http://{up.hostname}:{up.port}/oobi/{hab.pre}/witness/{wit}")
            res["oobis"] = oobis
        elif role in (kering.Roles.controller,):  # Fetch any controller URL OOBIs
            oobis = []
            urls = hab.fetchUrls(eid=hab.pre, scheme=kering.Schemes.http)
            if not urls:
                rep.status = falcon.HTTP_404
                rep.text = f"unable to query controller {hab.pre}, no http endpoint"
                return
            up = urlparse(urls[kering.Schemes.http])
            oobis.append(f"http://{up.hostname}:{up.port}/oobi/{hab.pre}/controller")
            res["oobis"] = oobis
        else:
            rep.status = falcon.HTTP_404
            return

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_post_alias(self, req, rep, alias):
        """ Resolve OOBI endpoint.

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of the local identifier context for resolving this OOBI

        ---
        summary: Resolve OOBI and assign an alias for the remote identifier
        description: Resolve OOBI URL or `rpy` message by process results of request and assign 'alias' in contact
                     data for resolved identifier
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
                        oobialias:
                          type: string
                          description: alias to assign to the identifier resolved from this OOBI
                          required: true
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

        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_404
            rep.text = "invalid alias, not found"
            return

        if "oobialias" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "invalid request, oobialias is required"
            return

        if "url" in body:
            oobi = body["url"]
            oobialias = body["oobialias"]
            self.oobiery.oobis.append(dict(alias=alias, oobialias=oobialias, url=oobi))
        elif "rpy" in body:
            pass
        else:
            rep.status = falcon.HTTP_400
            rep.text = "invalid OOBI request body, either 'rpy' or 'url' is required"
            return

        rep.status = falcon.HTTP_202

    def on_post(self, req, rep):
        """ Resolve OOBI endpoint.

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

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
            self.oobiery.oobis.append(dict(url=oobi))
        elif "rpy" in body:
            pass
        else:
            rep.status = falcon.HTTP_400
            rep.text = "invalid OOBI request body, either 'rpy' or 'url' is required"
            return

        rep.status = falcon.HTTP_202

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
                if kin in ("resolved",):
                    pass
                if kin in ("failed",):
                    pass

                break

            yield 1.0


class ChallengeEnd:
    """ Resource for Challenge/Response Endpoints """

    def __init__(self, hby, rep):
        """ Initialize Challenge/Response Endpoint

        Parameters:
            hby (Habery): database and keystore environment
            rep (Respondant): Doer capable of processing responses from endpoints

        """
        self.hby = hby
        self.rep = rep

    @staticmethod
    def on_get(req, rep):
        """ Challenge GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

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
        s = req.params.get("strength")
        strength = int(s) if s is not None else 128

        words = mnem.generate(strength=strength)
        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        msg = dict(words=words.split(" "))
        rep.data = json.dumps(msg).encode("utf-8")

    def on_post_resolve(self, req, rep, alias):
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
            rep.text = f"no matching Hab for alias {alias}"
            return

        body = req.get_media()
        if "words" not in body or "recipient" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "challenge response requires 'words' and 'recipient'"
            return

        words = body["words"]
        recpt = body["recipient"]
        payload = dict(i=hab.pre, words=words)
        exn = exchanging.exchange(route="/challenge/response", payload=payload)
        self.rep.reps.append(dict(src=hab.pre, dest=recpt, rep=exn, topic="challenge"))

        rep.status = falcon.HTTP_202


class ContactEnd:

    def __init__(self, hby, org):
        """

        Parameters:
            hby (Habery): identifier environment database
            org (Organizer): contact database
        """

        self.hby = hby
        self.org = org

    def on_get_list(self, req, rep):
        """ Contact plural GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
        ---
        summary:  Get list of contact information associated with remote identfiers
        description:  Get list of contact information associated with remote identfiers.  All
                      information is metadata and kept in local storage only
        tags:
           - Contacts
        parameters:
          - in: query
            name: group
            schema:
              type: string
            required: false
            description: field name to group results by
          - in: query
            name: filter_field
            schema:
               type: string
            description: field name to search
            required: false
          - in: query
            name: filter_value
            schema:
               type: string
            description: value to search for
            required: false
        responses:
           200:
              description: List of contact information for remote identifiers
        """
        # TODO:  Add support for sorting

        group = req.params.get("group")
        field = req.params.get("filter_field")
        if group is not None:
            data = dict()
            values = self.org.values(group)
            for value in values:
                contacts = self.org.find(group, value)
                data[value] = contacts

            rep.status = falcon.HTTP_200
            rep.data = json.dumps(data).encode("utf-8")

        elif field is not None:
            val = req.params.get("filter_value")
            if val is None:
                rep.status = falcon.HTTP_400
                rep.text = "filter_value if required if field_field is specified"
                return

            contacts = self.org.find(field=field, val=val)
            rep.status = falcon.HTTP_200
            rep.data = json.dumps(contacts).encode("utf-8")

        else:
            data = []
            contacts = self.org.list()

            for contact in contacts:
                aid = contact["id"]
                if aid in self.hby.kevers and aid not in self.hby.prefixes:
                    data.append(contact)

            rep.status = falcon.HTTP_200
            rep.data = json.dumps(data).encode("utf-8")

    def on_post_alias(self, req, rep, prefix, alias):
        """ Contact plural GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of identifier to use to sign the contact data
            prefix: human readable name of identifier to replace contact information

       ---
        summary:  Create new contact information for an identifier
        description:  Creates new information for an identifier, overwriting all existing
                      information for that identifier
        tags:
           - Contacts
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias identifier to sign contact with
          - in: path
            name: prefix
            schema:
              type: string
            required: true
            description: qb64 identifier prefix to add contact metadata to
        requestBody:
            required: true
            content:
              application/json:
                schema:
                    description: Contact information
                    type: object

        responses:
           200:
              description: Updated contact information for remote identifier
           400:
              description: Invalid identfier used to update contact information
           404:
              description: Prefix not found in identifier contact information
        """
        body = req.get_media()
        if prefix not in self.hby.kevers:
            rep.status = falcon.HTTP_404
            rep.text = f"{prefix} is not a known identifier.  oobi required before contact information"
            return

        if prefix in self.hby.prefixes:
            rep.status = falcon.HTTP_400
            rep.text = f"{prefix} is a local identifier, contact information only for remote identifiers"
            return

        if "id" in body:
            del body["id"]

        self.org.replace(alias, prefix, body)
        contact = self.org.get(prefix)

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(contact).encode("utf-8")

    def on_post_img(self, req, rep, prefix):
        """

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: qb64 identifier prefix of contact to associate with image

        ---
         summary: Uploads an image to associate with identfier.
         description: Uploads an image to associate with identfier.
         tags:
            - Contacts
         parameters:
           - in: path
             name: prefix
             schema:
                type: string
             description: identifier prefix to associate image to
         requestBody:
             required: true
             content:
                image/jpg:
                  schema:
                    type: string
                    format: binary
                image/png:
                  schema:
                    type: string
                    format: binary
         responses:
           200:
              description: Image successfully uploaded

        """
        if prefix not in self.hby.kevers:
            rep.status = falcon.HTTP_404
            rep.text = f"{prefix} is not a known identifier."
            return

        if req.content_length > 1000000:
            rep.status = falcon.HTTP_400
            rep.text = "image too big to save"
            return

        self.org.setImg(pre=prefix, typ=req.content_type, stream=req.bounded_stream)
        rep.status = falcon.HTTP_202

    def on_get_img(self, _, rep, prefix):
        """ Contact image GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: qb64 identifier prefix of contact information to get

       ---
        summary:  Get contact image for identifer prefix
        description:  Get contact image for identifer prefix
        tags:
           - Contacts
        parameters:
          - in: path
            name: prefix
            schema:
              type: string
            required: true
            description: qb64 identifier prefix of contact image to get
        responses:
           200:
              description: Contact information successfully retrieved for prefix
              content:
                  image/jpg:
                    schema:
                        description: Image
                        type: binary
           404:
              description: No contact information found for prefix
        """
        if prefix not in self.hby.kevers:
            rep.status = falcon.HTTP_404
            rep.text = f"{prefix} is not a known identifier."
            return

        data = self.org.getImgData(pre=prefix)
        if data is None:
            rep.status = falcon.HTTP_404
            rep.text = f"no image available for {prefix}."
            return

        rep.status = falcon.HTTP_200
        rep.set_header('Content-Type', data["type"])
        rep.set_header('Content-Length', data["length"])
        rep.stream = self.org.getImg(pre=prefix)

    def on_get(self, _, rep, prefix):
        """ Contact GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: qb64 identifier prefix of contact information to get

       ---
        summary:  Get contact information associated with single remote identfier
        description:  Get contact information associated with single remote identfier.  All
                      information is meta-data and kept in local storage only
        tags:
           - Contacts
        parameters:
          - in: path
            name: prefix
            schema:
              type: string
            required: true
            description: qb64 identifier prefix of contact to get
        responses:
           200:
              description: Contact information successfully retrieved for prefix
           404:
              description: No contact information found for prefix
        """
        if prefix not in self.hby.kevers:
            rep.status = falcon.HTTP_404
            rep.text = f"{prefix} is not a known identifier."
            return

        contact = self.org.get(prefix)
        if contact is None:
            rep.status = falcon.HTTP_404
            rep.text = "NOT FOUND"
            return

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(contact).encode("utf-8")

    def on_put_alias(self, req, rep, prefix, alias):
        """ Contact PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: qb64 identifier to update contact information
            alias (str): human readable name of identifier to use to sign the challange/response

        ---
        summary:  Update provided fields in contact information associated with remote identfier prefix
        description:  Update provided fields in contact information associated with remote identfier prefix.  All
                      information is metadata and kept in local storage only
        tags:
           - Contacts
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias identifier to sign contact with
          - in: path
            name: prefix
            schema:
              type: string
            required: true
            description: qb64 identifier prefix to add contact metadata to
        requestBody:
            required: true
            content:
              application/json:
                schema:
                    description: Contact information
                    type: object

        responses:
           200:
              description: Updated contact information for remote identifier
           400:
              description: Invalid identfier used to update contact information
           404:
              description: Prefix not found in identifier contact information
        """
        body = req.get_media()
        if prefix not in self.hby.kevers:
            rep.status = falcon.HTTP_404
            rep.text = f"{prefix} is not a known identifier.  oobi required before contact information"
            return

        if prefix in self.hby.prefixes:
            rep.status = falcon.HTTP_400
            rep.text = f"{prefix} is a local identifier, contact information only for remote identifiers"
            return

        if "id" in body:
            del body["id"]

        self.org.update(alias, prefix, body)
        contact = self.org.get(prefix)

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(contact).encode("utf-8")

    def on_delete(self, _, rep, prefix):
        """ Contact plural GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: qb64 identifier prefix to delete contact information

        ---
        summary:  Delete contact information associated with remote identfier
        description:  Delete contact information associated with remote identfier
        tags:
           - Contacts
        parameters:
          - in: path
            name: prefix
            schema:
              type: string
            required: true
            description: qb64 identifier prefix of contact to delete
        responses:
           202:
              description: Contact information successfully deleted for prefix
           404:
              description: No contact information found for prefix
        """
        deleted = self.org.rem(prefix)
        if not deleted:
            rep.status = falcon.HTTP_404
            rep.text = f"no contact information to delete for {prefix}"
            return

        rep.status = falcon.HTTP_202


class SchemaEnd:

    def __init__(self, db):
        self.db = db

    def on_get(self, _, rep, said):
        """ Schema GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            said: qb64 self-addressing identifier of schema to load

       ---
        summary:  Get schema JSON of specified schema
        description:  Get schema JSON of specified schema
        tags:
           - Schema
        parameters:
          - in: path
            name: said
            schema:
              type: string
            required: true
            description: qb64 self-addressing identifier of schema to get
        responses:
           200:
              description: Schema JSON successfully returned
           404:
              description: No schema found for SAID
        """
        schemer = self.db.schema.get(keys=(said,))
        if schemer is None:
            rep.status = falcon.HTTP_404
            rep.text = "Schema not found"
            return

        data = schemer.sed
        rep.status = falcon.HTTP_200
        rep.data = json.dumps(data).encode("utf-8")

    def on_get_list(self, _, rep):
        """ Schema GET plural endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response

       ---
        summary:  Get schema JSON of all schema
        description:  Get schema JSON of all schema
        tags:
           - Schema
        responses:
           200:
              description: Array of all schema JSON
        """
        data = []
        for said, schemer in self.db.schema.getItemIter():
            data.append(schemer.sed)

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(data).encode("utf-8")


class EscrowEnd:

    def __init__(self, db):
        """ Create endpoint for retrieving escrow status

        Parameters:
            db (Baser): escrow database

        """
        self.db = db

    def on_get(self, req, rep):
        """

        Parameters:
            req (Request): falcon.Request HTTP request
            rep (Response): falcon.Response HTTP response

        ---
        summary:  Display escrow status for entire database or search for single identifier in escrows
        description:  Display escrow status for entire database or search for single identifier in escrows
        tags:
           - Escrows
        parameters:
          - in: query
            name: pre
            schema:
              type: string
            required: false
            description: qb64 identifier prefix to search for in escrows
          - in: query
            name: escrow
            schema:
              type: string
            required: false
            description: name of escrow to load, ignoring others
        responses:
           200:
              description: Escrow information
           404:
              description: Prefix not found in any escrow


        """
        rpre = req.params.get("pre")
        if rpre is not None:
            rpre = rpre.encode("utf-8")
        escrow = req.params.get("escrow")

        escrows = dict()

        if (not escrow) or escrow == "out-of-order-events":
            oots = list()
            key = ekey = b''  # both start same. when not same means escrows found
            while True:
                for ekey, edig in self.db.getOoeItemsNextIter(key=key):
                    pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                    if rpre and pre != rpre:
                        continue

                    try:
                        oots.append(loadEvent(self.db, pre, edig))
                    except ValueError as e:
                        rep.status = falcon.HTTP_400
                        rep.text = e.args[0]
                        return

                if ekey == key:  # still same so no escrows found on last while iteration
                    break
                key = ekey  # setup next while iteration, with key after ekey

            escrows["out-of-order-events"] = oots

        if (not escrow) or escrow == "partially-witnessed-events":
            pwes = list()
            key = ekey = b''  # both start same. when not same means escrows found
            while True:  # break when done
                for ekey, edig in self.db.getPweItemsNextIter(key=key):
                    pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                    if rpre and pre != rpre:
                        continue

                    try:
                        pwes.append(loadEvent(self.db, pre, edig))
                    except ValueError as e:
                        rep.status = falcon.HTTP_400
                        rep.text = e.args[0]
                        return

                if ekey == key:  # still same so no escrows found on last while iteration
                    break
                key = ekey  # setup next while iteration, with key after ekey

            escrows["partially-witnessed-events"] = pwes

        if (not escrow) or escrow == "partially-signed-events":
            pses = list()
            key = ekey = b''  # both start same. when not same means escrows found
            while True:  # break when done
                for ekey, edig in self.db.getPseItemsNextIter(key=key):
                    pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                    if rpre and pre != rpre:
                        continue

                    try:
                        pses.append(loadEvent(self.db, pre, edig))
                    except ValueError as e:
                        rep.status = falcon.HTTP_400
                        rep.text = e.args[0]
                        return

                if ekey == key:  # still same so no escrows found on last while iteration
                    break
                key = ekey  # setup next while iteration, with key after ekey

            escrows["partially-signed-events"] = pses

        if (not escrow) or escrow == "likely-duplicitous-events":
            ldes = list()
            key = ekey = b''  # both start same. when not same means escrows found
            while True:  # break when done
                for ekey, edig in self.db.getLdeItemsNextIter(key=key):
                    pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
                    if rpre and pre != rpre:
                        continue

                    try:
                        ldes.append(loadEvent(self.db, pre, edig))
                    except ValueError as e:
                        rep.status = falcon.HTTP_400
                        rep.text = e.args[0]
                        return

                if ekey == key:  # still same so no escrows found on last while iteration
                    break
                key = ekey  # setup next while iteration, with key after ekey

            escrows["likely-duplicitous-events"] = ldes

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(escrows, indent=2).encode("utf-8")


def loadEnds(app, *,
             path,
             hby,
             rgy,
             rep,
             mbx,
             verifier,
             counselor,
             registrar,
             credentialer,
             servery,
             bootConfig,
             notifications=None,
             rxbs=None,
             queries=None,
             oobiery=None,
             **kwargs):
    """
    Load endpoints for KIWI admin interface into the provided Falcon app

    Parameters:
        app (falcon.App): falcon.App to register handlers with:
        path (str): directory location of UI web app files to be served with this API server
        hby (Habery): database environment for all endpoints
        rgy (Regery): database environment for credentials
        rep (Respondant): that routes responses to the appropriate mailboxes
        mbx (Mailboxer): mailbox storage class
        verifier (Verifier): that process credentials
        registrar (Registrar): credential registry protocol manager
        counselor (Counselor): group multisig identifier communication manager
        credentialer (Credentialer): credential issuance protocol manager
        notifications (Deck): cue to forward agent notifications to controller
        rxbs (bytearray): output queue of bytes for message processing
        queries (Deck): query cues for HttpEnd to start mailbox stream
        oobiery (Optioanl[Oobiery]): optional OOBI loader

    Returns:
        list: doers from registering endpoints

    """
    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    swagsink = http.serving.StaticSink(staticDirPath="./static")
    app.add_sink(swagsink, prefix="/swaggerui")

    lockEnd = LockEnd(servery=servery, bootConfig=bootConfig)
    app.add_route("/lock", lockEnd)

    identifierEnd = IdentifierEnd(hby=hby)
    app.add_route("/ids", identifierEnd)
    app.add_route("/ids/{alias}", identifierEnd, suffix="alias")
    app.add_route("/ids/{alias}/rot", identifierEnd, suffix="rot")
    app.add_route("/ids/{alias}/ixn", identifierEnd, suffix="ixn")

    keyEnd = KeyStateEnd(hby=hby)
    app.add_route("/keystate/{prefix}", keyEnd)

    registryEnd = RegistryEnd(hby=hby, rgy=rgy, registrar=registrar)
    app.add_route("/registries", registryEnd)

    presentationEnd = PresentationEnd(rep=rep)
    app.add_route("/presentation", presentationEnd)

    multiIcpEnd = MultisigInceptEnd(hby=hby, counselor=counselor)
    app.add_route("/groups/{alias}/icp", multiIcpEnd)
    multiEvtEnd = MultisigEventEnd(hby=hby, counselor=counselor)
    app.add_route("/groups/{alias}/rot", multiEvtEnd, suffix="rot")
    app.add_route("/groups/{alias}/ixn", multiEvtEnd, suffix="ixn")

    credsEnd = CredentialEnd(hby=hby, rgy=rgy, verifier=verifier, registrar=registrar, credentialer=credentialer)
    app.add_route("/credentials/{alias}", credsEnd)
    app.add_route("/groups/{alias}/credentials", credsEnd, suffix="iss")
    app.add_route("/groups/{alias}/credentials/{said}/rev", credsEnd, suffix="rev")

    oobiEnd = OobiResource(hby=hby, oobiery=oobiery)
    app.add_route("/oobi/{alias}", oobiEnd, suffix="alias")
    app.add_route("/oobi", oobiEnd)

    chacha = ChallengeEnd(hby=hby, rep=rep)
    app.add_route("/challenge", chacha)
    app.add_route("/challenge/{alias}", chacha, suffix="resolve")

    org = connecting.Organizer(hby=hby)
    contact = ContactEnd(hby=hby, org=org)

    app.add_route("/contacts/{prefix}/{alias}", contact, suffix="alias")
    app.add_route("/contacts/{prefix}/img", contact, suffix="img")
    app.add_route("/contacts/{prefix}", contact)
    app.add_route("/contacts", contact, suffix="list")

    schemaEnd = SchemaEnd(db=hby.db)
    app.add_route("/schema", schemaEnd, suffix="list")
    app.add_route("/schema/{said}", schemaEnd)

    escrowEnd = EscrowEnd(db=hby.db)
    app.add_route("/escrows", escrowEnd)

    httpEnd = indirecting.HttpEnd(rxbs=rxbs, mbx=mbx, qrycues=queries)
    app.add_route("/mbx", httpEnd, suffix="mbx")

    resources = [identifierEnd, MultisigInceptEnd, registryEnd, oobiEnd, credsEnd, keyEnd,
                 presentationEnd, multiIcpEnd, multiEvtEnd, chacha, contact, escrowEnd, lockEnd]

    app.add_route("/spec.yaml", specing.SpecResource(app=app, title='KERI Interactive Web Interface API',
                                                     resources=resources))
    notifications = notifications if notifications is not None else decking.Deck()
    funnel = cueing.Funneler(srcs=[multiIcpEnd.cues, multiEvtEnd.cues, credsEnd.cues], dest=notifications)

    return [identifierEnd, registryEnd, oobiEnd, multiIcpEnd, multiEvtEnd, credsEnd, funnel, lockEnd]


def setup(hby, rgy, servery, bootConfig, *, controller="", insecure=False, staticPath="", **kwargs):
    """ Setup and run a KIWI agent

    Parameters:
        hby (Habery): database environment for identifiers
        rgy (Regery): database environment for credentials
        servery (Servery): HTTP server manager for stopping and restarting HTTP servers
        bootConfig (dict): original configuration at launch, used to reset during lock
        controller (str): qb64 identifier prefix of the controller of this agent
        insecure (bool): allow unsigned HTTP requests to the admin interface (non-production ONLY)
        tcp (int): TCP port for agent to listen on for incoming direct connections
        staticPath (str): path to static content for this agent

    Returns:
        list: Endpoint Doers to execute in Doist for agent.

    """

    # setup doers
    doers = [habbing.HaberyDoer(habery=hby)]

    verifier = verifying.Verifier(hby=hby, reger=rgy.reger)
    wallet = walleting.Wallet(reger=verifier.reger, name=hby.name)

    handlers = []

    proofs = decking.Deck()

    mbx = storing.Mailboxer(name=hby.name)
    counselor = grouping.Counselor(hby=hby)
    registrar = credentialing.Registrar(hby=hby, rgy=rgy, counselor=counselor)
    credentialer = credentialing.Credentialer(hby=hby, rgy=rgy, registrar=registrar, verifier=verifier)

    issueHandler = protocoling.IssueHandler(hby=hby, rgy=rgy, mbx=mbx, controller=controller)
    requestHandler = protocoling.PresentationRequestHandler(hby=hby, wallet=wallet)
    applyHandler = protocoling.ApplyHandler(hby=hby, rgy=rgy, verifier=verifier, name=hby.name)
    proofHandler = protocoling.PresentationProofHandler(proofs=proofs)

    handlers.extend([issueHandler, requestHandler, proofHandler, applyHandler])

    exchanger = exchanging.Exchanger(hby=hby, handlers=handlers)
    challenging.loadHandlers(hby=hby, exc=exchanger, mbx=mbx, controller=controller)
    grouping.loadHandlers(hby=hby, exc=exchanger, mbx=mbx, controller=controller)
    delegating.loadHandlers(hby=hby, exc=exchanger, mbx=mbx, controller=controller)

    rep = storing.Respondant(hby=hby, mbx=mbx)
    cues = decking.Deck()
    mbd = indirecting.MailboxDirector(hby=hby,
                                      exc=exchanger,
                                      verifier=verifier,
                                      rep=rep,
                                      topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate",
                                              "/challenge"],
                                      cues=cues)
    # configure a kevery
    doers.extend([exchanger, mbd, rep])

    # Load admin interface
    rep = storing.Respondant(hby=hby, mbx=mbx)

    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    if not insecure:
        app.add_middleware(httping.SignatureValidationComponent(hby=hby, pre=controller))
    app.req_options.media_handlers.update(media.Handlers())
    app.resp_options.media_handlers.update(media.Handlers())

    notifier = storing.Notifier(controller=controller, mbx=mbx)
    queries = decking.Deck()
    endDoers = loadEnds(app, path=staticPath, hby=hby, rgy=rgy, rep=rep, mbx=mbx, notifications=notifier.notifs,
                        verifier=verifier, counselor=counselor, registrar=registrar, credentialer=credentialer,
                        servery=servery, bootConfig=bootConfig, rxbs=mbd.ims, queries=queries, **kwargs)

    servery.msgs.append(dict(app=app))
    doers.extend([rep, counselor, registrar, credentialer, notifier])
    doers.extend(endDoers)

    return doers


def loadEvent(db, preb, dig):
    event = dict()
    dgkey = dbing.dgKey(preb, dig)  # get message
    if not (raw := db.getEvt(key=dgkey)):
        raise ValueError("Missing event for dig={}.".format(dig))

    srdr = coring.Serder(raw=bytes(raw))
    event["ked"] = srdr.ked

    # add indexed signatures to attachments
    sigs = db.getSigs(key=dgkey)
    dsigs = []
    for s in sigs:
        sig = coring.Siger(qb64b=bytes(s))
        dsigs.append(dict(index=sig.index, signature=sig.qb64))
    event["signatures"] = dsigs

    # add indexed witness signatures to attachments
    dwigs = []
    if wigs := db.getWigs(key=dgkey):
        for w in wigs:
            sig = coring.Siger(qb64b=bytes(w))
            dwigs.append(dict(index=sig.index, signature=sig.qb64))
    event["witness_signatures"] = dwigs

    # add authorizer (delegator/issuer) source seal event couple to attachments
    couple = db.getAes(dgkey)
    if couple is not None:
        raw = bytearray(couple)
        seqner = coring.Seqner(qb64b=raw, strip=True)
        saider = coring.Saider(qb64b=raw)
        event["source_seal"] = dict(sequence=seqner.sn, said=saider.qb64)

    receipts = dict()
    # add trans receipts quadruples
    if quads := db.getVrcs(key=dgkey):
        trans = []
        for quad in quads:
            raw = bytearray(quad)
            trans.append(dict(
                prefix=coring.Prefixer(qb64b=raw, strip=True).qb64,
                sequence=coring.Seqner(qb64b=raw, strip=True).qb64,
                said=coring.Saider(qb64b=raw, strip=True).qb64,
                signature=coring.Siger(qb64b=raw, strip=True).qb64,
            ))

        receipts["transferable"] = trans

    # add nontrans receipts couples
    if coups := db.getRcts(key=dgkey):
        nontrans = []
        for coup in coups:
            raw = bytearray(coup)
            (prefixer, cigar) = eventing.deReceiptCouple(raw, strip=True)
            nontrans.append(dict(prefix=prefixer.qb64, signature=cigar.qb64))
        receipts["nontransferable"] = nontrans

    event["receipts"] = receipts
    # add first seen replay couple to attachments
    if not (dts := db.getDts(key=dgkey)):
        raise ValueError("Missing datetime for dig={}.".format(dig))

    event["timestamp"] = coring.Dater(dts=bytes(dts)).dts
    return event
