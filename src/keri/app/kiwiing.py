# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json
from ordered_set import OrderedSet as oset

import falcon
import mnemonic
from falcon import media
from hio.base import doing
from hio.core import http
from hio.help import decking

import keri.app.oobiing
from . import grouping, challenging, connecting, notifying, signaling, oobiing
from .. import help
from .. import kering
from ..app import specing, forwarding, agenting, storing, indirecting, httping, habbing, delegating, booting
from ..core import coring, eventing
from ..db import dbing
from ..db.dbing import dgKey
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

    def on_post(self, _, rep):
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
        booting.setup(servery=self.servery, controller=self.bootConfig["controller"],
                      configFile=self.bootConfig["configFile"],
                      configDir=self.bootConfig["configDir"],
                      insecure=self.bootConfig["insecure"],
                      path=self.bootConfig["staticPath"],
                      headDirPath=self.bootConfig["headDirPath"])

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
        if hab is None:
            raise falcon.HTTPNotFound(description=f"no identifier for alias {alias}")

        info = self.info(hab)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(info).encode("utf-8")

    def info(self, hab):
        data = dict(
            name=hab.name,
            prefix=hab.pre,
        )

        if hab.mhab:
            data["group"] = dict(
                pid=hab.mhab.pre,
                aids=hab.smids,
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
                toad=kever.toader.num,
                witnesses=kever.wits,
                estOnly=kever.estOnly,
                DnD=kever.doNotDelegate,
                receipts=len(wigs)
            )

            if kever.delegated:
                data["delegated"] = kever.delegated
                data["delegator"] = kever.delegator
                dgkey = dbing.dgKey(hab.kever.prefixer.qb64b, hab.kever.lastEst.d)
                anchor = self.hby.db.getAes(dgkey)
                data["anchored"] = anchor is not None

        md = self.org.get(hab.pre)
        if md is not None:
            del md["id"]
            data["metadata"] = md
        else:
            data["metadata"] = {}

        return data

    def on_put_metadata(self, req, rep, alias):
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

        if "alias" in body:
            newAlias = body["alias"]
            del body["alias"]
            if not newAlias:
                rep.status = falcon.HTTP_400
                rep.text = f"invalid new alias for identifier {hab.pre}."
                return

            habord = hab.db.habs.get(keys=alias)
            hab.db.habs.put(keys=newAlias,
                            val=habord)
            hab.db.habs.rem(keys=alias)
            self.hby.loadHabs()

        self.org.update(hab.pre, body)
        contact = self.org.get(hab.pre)

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(contact).encode("utf-8")

    def on_post_metadata(self, req, rep, alias):
        """ Identifier Metadata POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of identifier to replace contact information

        ---
        summary:  Replace metadata associated with the identfier of the alias
        description:  Replace metadata associated with the identfier of the alias
        tags:
           - Identifiers
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: human readable name of identifier prefix to replace metadata
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

        if "alias" in body:
            newAlias = body["alias"]
            if not newAlias:
                rep.status = falcon.HTTP_400
                rep.text = f"invalid new alias for identifier {hab.pre}."
                return

            del body["alias"]
            habord = hab.db.habs.get(keys=alias)
            hab.db.habs.put(keys=newAlias,
                            val=habord)
            hab.db.habs.rem(keys=alias)
            self.hby.loadHabs()

        self.org.replace(hab.pre, body)
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
        DnD = int(body.get("DnD")) if "DnD" in body else False

        kwa = dict(
            transferable=transferable,
            wits=wits,
            toad=toad,
            isith=isith,
            icount=icount,
            nsith=nsith,
            ncount=ncount,
            estOnly=estOnly,
            DnD=DnD,
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
            rot = hab.rotate(isith=isith, ncount=count, toad=toad, cuts=list(cuts), adds=list(adds), data=data)
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

            if hab.mhab:  # Skip if group, they are handled elsewhere
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

    def __init__(self, hby, counselor):
        self.hby = hby
        self.counselor = counselor

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
                event = eventing.loadEvent(self.hby.db, preb, dig)
            except ValueError as e:
                rep.status = falcon.HTTP_400
                rep.text = e.args[0]
                return

            kel.append(event)

        key = dbing.snKey(pre=pre, sn=0)
        # load any partially witnesses events for this prefix
        for ekey, edig in self.hby.db.getPweItemsNextIter(key=key):
            pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
            try:
                kel.append(eventing.loadEvent(self.hby.db, pre, edig))
            except ValueError as e:
                rep.status = falcon.HTTP_400
                rep.text = e.args[0]
                return

        # load any partially signed events from this prefix
        for ekey, edig in self.hby.db.getPseItemsNextIter(key=key):
            pre, sn = dbing.splitKeySN(ekey)  # get pre and sn from escrow item
            try:
                kel.append(eventing.loadEvent(self.hby.db, pre, edig))
            except ValueError as e:
                rep.status = falcon.HTTP_400
                rep.text = e.args[0]
                return

        res["kel"] = kel

        # Check to see if we have any pending distributed multisig events
        evts = []
        if pre in self.hby.habs:
            hab = self.hby.habs[pre]
            if hab.mhab:
                evts = self.counselor.pendingEvents(pre)
        res["pending"] = evts

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_get_pubkey(self, _, rep, pubkey):
        """

        Parameters:
            _ (Request): falcon.Request HTTP request
            rep (Response): falcon.Response HTTP response
            pubkey (str): qb64 public key for which to search

        ---
        summary:  Display key event log (KEL) for given identifier prefix
        description:  If provided qb64 identifier prefix is in Kevers, return the current state of the
                      identifier along with the KEL and all associated signatures and receipts
        tags:
           - Ket Event Log
        parameters:
          - in: path
            name: pubkey
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
        found = None
        for pre, digb, raw in self.hby.db.getAllItemIter(db=self.hby.db.evts):
            serder = coring.Serder(raw=bytes(raw))
            if len(serder.ked['k']) == 1 and pubkey in serder.ked['k']:
                found = serder

        if found is None:
            rep.status = falcon.HTTP_404
            rep.data = json.dumps(dict(msg="Public key not found")).encode("utf-8")
            return

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(found.ked).encode("utf-8")


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

    def __init__(self, hby, rgy, registrar, credentialer, verifier, notifier):
        """ Create endpoint for issuing and listing credentials

        Endpoints for issuing and listing credentials from non-group identfiers only

        Parameters:
            hby (Habery): identifier database environment
            rgy (Regery): credential registry database environment
            verifier (Verifier): credential verifier
            registrar (Registrar): credential registry protocol manager
            credentialer: (Credentialer): credential protocol manager
            notifier (Notifier): outbound notifications

        """
        self.hby = hby
        self.rgy = rgy
        self.credentialer = credentialer
        self.registrar = registrar
        self.verifier = verifier
        self.postman = forwarding.Postman(hby=self.hby)
        self.notifier = notifier
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
           - in: query
             name: schema
             schema:
                type: string
             description:  schema to filter by if provided
             required: false
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
        schema = req.params.get("schema")

        hab = self.hby.habByName(name=alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credentials" \
                       "".format(alias)
            return

        creds = []
        if typ == "issued":
            saids = self.rgy.reger.issus.get(keys=hab.pre)
        elif typ == "received":
            saids = self.rgy.reger.subjs.get(keys=hab.pre)
        else:
            rep.status = falcon.HTTP_400
            rep.text = f"Invalid type {typ}"
            return

        if schema is not None:
            scads = self.rgy.reger.schms.get(keys=schema)
            saids = [saider for saider in saids if saider.qb64 in [saider.qb64 for saider in scads]]

        creds = self.rgy.reger.cloneCreds(saids)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(creds).encode("utf-8")

    def on_get_export(self, _, rep, alias, said):
        """ Credentials GET endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name of identifier to load credentials for
            said (str): SAID of credential to export

        ---
        summary:  Export credential and all supporting cryptographic material
        description: Export credential and all supporting cryptographic material
        tags:
           - Credentials
        parameters:
           - in: path
             name: alias
             schema:
               type: string
             required: true
             description: Human readable alias for the identifier to create
           - in: path
             name: said
             schema:
               type: string
             required: true
             description: SAID of credential to export
        responses:
           200:
              description: Credential export.
              content:
                  application/json+cesr:
                    schema:
                        description: Credential
                        type: object

        """
        hab = self.hby.habByName(name=alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credentials".format(alias)
            return

        data = self.outputCred(hab, said)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json+cesr"
        rep.data = bytes(data)

    def outputCred(self, hab, said):
        out = bytearray()
        creder, sadsigers, sadcigars = self.rgy.reger.cloneCred(said=said)
        chains = creder.chains
        saids = []
        for key, source in chains.items():
            if key == 'd':
                continue

            if not isinstance(source, dict):
                continue

            saids.append(source['n'])

        for said in saids:
            out.extend(self.outputCred(hab, said))

        issr = creder.issuer
        for msg in self.hby.db.clonePreIter(pre=issr):
            serder = coring.Serder(raw=msg)
            atc = msg[serder.size:]
            out.extend(serder.raw)
            out.extend(atc)

        if creder.status is not None:
            for msg in self.rgy.reger.clonePreIter(pre=creder.status):
                serder = coring.Serder(raw=msg)
                atc = msg[serder.size:]
                out.extend(serder.raw)
                out.extend(atc)

            for msg in self.rgy.reger.clonePreIter(pre=creder.said):
                serder = coring.Serder(raw=msg)
                atc = msg[serder.size:]
                out.extend(serder.raw)
                out.extend(atc)

        out.extend(creder.raw)
        out.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars, pipelined=True))

        return out

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
                      description: Alias of credential issuance/revocation registry (aka status)
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
                    private:
                      type: boolean
                      description: flag to inidicate this credential should support privacy preserving presentations
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
        private = body.get("private") is not None and body.get("private") is True

        edges = None
        if source is not None:
            try:
                _, edges = coring.Saider.saidify(sad=source)
            except KeyError:
                edges = source

        try:
            creder = self.credentialer.create(regname, recp, schema, edges, rules, data, private=private)
            self.credentialer.issue(creder=creder)

        except kering.ConfigurationError as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]
            return

        # cue up an event to send notification when complete
        self.evts.append(dict(topic="/credential", r="/iss/complete", d=creder.said))

        rep.status = falcon.HTTP_200
        rep.data = creder.raw

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
                    rules:
                      type: array
                      description: list of credential chain sources (ACDC)
                    credentialData:
                      type: object
                      description: dynamic map of values specific to the schema
                    private:
                      type: boolean
                      description: flag to inidicate this credential should support privacy preserving presentations
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
        if hab is None or hab.mhab is None:
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
        private = body.get("private") is not None and body.get("private") is True

        edges = None
        if source is not None:
            try:
                _, edges = coring.Saider.saidify(sad=source)
            except KeyError:
                edges = source

        try:
            creder = self.credentialer.create(regname, recp, schema, edges, rules, data, private=private)
            self.credentialer.issue(creder=creder)
        except kering.ConfigurationError as e:
            rep.status = falcon.HTTP_400
            rep.text = e.args[0]
            return

        exn, atc = grouping.multisigIssueExn(hab=hab, creder=creder)

        others = list(oset(hab.smids + (hab.rmids or [])))
        #others = list(hab.smids)
        others.remove(hab.mhab.pre)

        for recpt in others:
            self.postman.send(src=hab.mhab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

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
        if hab is None or hab.mhab is None:
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
        if hab is None or hab.mhab is None:
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
        if hab is None or hab.mhab is None:
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
                    self.notifier.add(dict(
                        r=f"{tpc}{route}",
                        a=dict(d=said),
                    ))
                else:
                    self.evts.append(evt)

            elif route == "/rev/complete":
                if self.registrar.complete(pre=said, sn=1):
                    self.notifier.add(dict(
                        r=f"{tpc}{route}",
                        a=dict(d=said),
                    ))
                else:
                    self.evts.append(evt)

            yield self.tock


class PresentationEnd(doing.DoDoer):
    """
    ReST API for admin of credential presentation requests

    """

    def __init__(self, hby, reger):
        """ Create endpoint handler for credential presentations and requests

        Parameters:
            hby (Habery): database environment for identifiers
            reger (Reger): database environment for credentials

        """
        self.hby = hby
        self.reger = reger
        self.org = connecting.Organizer(hby=hby)
        self.postman = forwarding.Postman(hby=self.hby)

        super(PresentationEnd, self).__init__(doers=[self.postman])

    def on_post_request(self, req, rep, alias):
        """  Presentation Request POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for Hab

        ---
        summary: Request credential presentation
        description: Send a credential presentation request peer to peer (exn) message to recipient
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
                    recipient:
                      type: string
                      required: true
                      description: qb64 AID to send presentation request to
                    schema:
                      type: string
                      required: true
                      description: qb64 SAID of schema for credential being requested
                    issuer:
                      type: string
                      required: false
                      description: qb64 AID of issuer of credential being requested
        responses:
           202:
              description:  credential presentation request message sent

        """
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = f"Invalid alias {alias} for credential request"
            return None

        body = req.get_media()
        recp = body.get("recipient")
        if recp is None:
            rep.status = falcon.HTTP_400
            rep.text = "recp is required, none provided"
            return

        schema = body.get("schema")
        if schema is None:
            rep.status = falcon.HTTP_400
            rep.text = "schema is required, none provided"
            return

        pl = dict(
            s=schema
        )

        issuer = body.get("issuer")
        if issuer is not None:
            pl['i'] = issuer

        exn = exchanging.exchange(route="/presentation/request", payload=pl)
        ims = hab.endorse(serder=exn, last=True, pipelined=False)
        del ims[:exn.size]
        self.postman.send(src=hab.pre, dest=recp, topic="credential", serder=exn, attachment=ims)

        rep.status = falcon.HTTP_202

    def on_post_present(self, req, rep, alias):
        """  Presentation POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias (str): human readable name for Hab

        ---
        summary: Send credential presentation
        description: Send a credential presentation peer to peer (exn) message to recipient
        tags:
           - Credentials
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for the holder of credential
        requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    said:
                      type: string
                      required: true
                      description: qb64 SAID of credential to send
                    recipient:
                      type: string
                      required: true
                      description: qb64 AID to send credential presentation to
                    include:
                      type: boolean
                      required: true
                      default: true
                      description: flag indicating whether to stream credential alongside presentation exn
        responses:
           202:
              description:  credential presentation message sent

        """
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = f"Invalid alias {alias} for credential presentation"
            return None

        body = req.get_media()
        said = body.get("said")
        if said is None:
            rep.status = falcon.HTTP_400
            rep.text = "said is required, none provided"
            return

        creder = self.reger.creds.get(said)
        if creder is None:
            rep.status = falcon.HTTP_404
            rep.text = f"credential {said} not found"
            return

        recipient = body.get("recipient")
        if recipient is None:
            rep.status = falcon.HTTP_400
            rep.text = "recipient is required, none provided"
            return

        if recipient in self.hby.kevers:
            recp = recipient
        else:
            recp = self.org.find("alias", recipient)
            if len(recp) != 1:
                raise ValueError(f"invalid recipient {recipient}")
            recp = recp[0]['id']

        include = body.get("include")
        if include:
            credentialing.sendCredential(self.hby, hab=hab, reger=self.reger, postman=self.postman, creder=creder,
                                         recp=recp)

        exn, atc = protocoling.presentationExchangeExn(hab=hab, reger=self.reger, said=said)
        self.postman.send(src=hab.pre, dest=recp, topic="credential", serder=exn, attachment=atc)

        rep.status = falcon.HTTP_202


class MultisigEndBase(doing.DoDoer):

    def __init__(self, hby, counselor, notifier, doers):
        self.hby = hby
        self.notifier = notifier
        self.counselor = counselor
        self.postman = forwarding.Postman(hby=hby)

        self.evts = decking.Deck()
        doers.extend([self.postman, doing.doify(self.evtDo)])

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
            hab = self.hby.habs[pre]

            if self.counselor.complete(prefixer, seqner, saider):
                if hab.kever.delegator:
                    yield from self.postman.sendEvent(hab=hab, fn=hab.kever.sn)

                self.notifier.add(attrs=dict(
                    r=f"/multisig{route}",
                    a=dict(i=pre, s=sn),
                ))
            else:
                self.evts.append(evt)

            yield self.tock


class MultisigInceptEnd(MultisigEndBase):
    """
    ReST API for admin of distributed multisig groups

    """

    def __init__(self, hby, counselor, notifier):
        """ Create an endpoint resource for creating or participating in multisig group identifiers

        Parameters:
            hby (Habery): identifier database environment
            counselor (Counselor): multisig group communication management

        """

        self.hby = hby
        self.counselor = counselor
        self.notifier = notifier
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(MultisigInceptEnd, self).__init__(hby=hby, notifier=notifier,
                                                counselor=counselor, doers=doers)

    def initialize(self, body, rep, alias):
        """Incept group multisig

        ToDo: NRR


        """

        if "aids" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group inception request, 'aids' is required'"
            return None, None

        smids = body["aids"]  # change body aids to smids for group member ids
        rmids = body["rmids"] if "rmids" in body else None
        both = list(oset(smids + (rmids or [])))

        mhab = None
        for mid in both:
            if mid in self.hby.habs:
                mhab = self.hby.habs[mid]
                break

        if mhab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid multisig group inception request, aid list must contain a local identifier'"
            return None, None

        if self.hby.habByName(alias) is not None:
            rep.status = falcon.HTTP_400
            rep.text = f"Identifier alias {alias} is already in use"
            return None, None

        inits = dict()

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

        if "estOnly" in body:
            inits["estOnly"] = body["estOnly"]
        if "DnD" in body:
            inits["DnD"] = body["DnD"]

        inits["toad"] = body["toad"] if "toad" in body else None
        inits["wits"] = body["wits"] if "wits" in body else []
        inits["delpre"] = body["delpre"] if "delpre" in body else None

        try:
            ghab = self.hby.makeGroupHab(group=alias,
                                         mhab=mhab,
                                         smids=smids,
                                         rmids=rmids,
                                         **inits)
        except ValueError as ex:
            rep.status = falcon.HTTP_400
            rep.data = json.dumps(dict(msg=ex.args[0])).encode("utf-8")
            return None, None

        return mhab, ghab


    def icp(self, hab, ghab, aids, rmids=None):
        """

        Args:
            ghab (Hab): Group Hab to start processing
            hab (Hab): Local participant Hab
            aids (list): Other group signing member qb64 ids
            rmids (list | None) Other group rotating member qb64 ids

        """
        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=0)
        saider = coring.Saider(qb64=prefixer.qb64)
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider,
                              mid=hab.pre, smids=aids, rmids=rmids)


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
                   estOnly:
                     type: boolean
                     required: False
                     description: True means this identifier will not allow interaction events.

        responses:
           200:
              description: Multisig group AID inception initiated.

        """
        body = req.get_media()

        mhab, ghab = self.initialize(body, rep, alias)
        if ghab is None:
            return

        if not ghab.accepted:
            evt = grouping.getEscrowedEvent(db=self.hby.db, pre=ghab.pre, sn=0)
        else:
            evt = ghab.makeOwnInception()

        serder = coring.Serder(raw=evt)

        # Create a notification EXN message to send to the other agents
        exn, ims = grouping.multisigInceptExn(mhab, aids=ghab.smids, ked=serder.ked)

        others = list(oset(ghab.smids + (ghab.rmids or [])))
        #others = list(ghab.smids)
        others.remove(mhab.pre)

        for recpt in others:  # this goes to other participants only as a signalling mechanism
            self.postman.send(src=mhab.pre, dest=recpt, topic="multisig", serder=exn, attachment=ims)

        #  signal to the group counselor to start the inception
        self.icp(hab=mhab, ghab=ghab, aids=ghab.smids, rmids=ghab.rmids)

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
                   estOnly:
                     type: boolean
                     required: False
                     description: True means this identifier will not allow interaction events.

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

    def __init__(self, hby, counselor, notifier):

        self.hby = hby
        self.counselor = counselor
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(MultisigEventEnd, self).__init__(hby=hby, notifier=notifier, counselor=counselor, doers=doers)

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
        if ghab.mhab.pre not in aids:
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

        nsith = None
        if "nsith" in body:
            nsith = body["nsith"]
            if isinstance(nsith, str) and "," in nsith:
                nsith = nsith.split(",")

        aids = body["aids"] if "aids" in body else ghab.smids
        rmids = body["rmids"] if "rmids" in body else ghab.rmids
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
        self.counselor.rotate(ghab=ghab, smids=aids, rmids=rmids,
                              isith=isith, nsith=nsith,
                              toad=toad, cuts=list(cuts), adds=list(adds),
                              data=data)

        # Create `exn` peer to peer message to notify other participants UI
        exn, atc = grouping.multisigRotateExn(ghab, aids, isith, toad, cuts, adds, data)
        others = list(oset(ghab.smids + (ghab.rmids or [])))
        #others = list(ghab.smids)
        others.remove(ghab.mhab.pre)

        for recpt in others:  # send notification to other participants as a signalling mechanism
            self.postman.send(src=ghab.mhab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

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

        nsith = None
        if "nsith" in body:
            nsith = body["nsith"]
            if isinstance(nsith, str) and "," in nsith:
                nsith = nsith.split(",")

        aids = body["aids"] if "aids" in body else ghab.smids
        rmids = body["rmids"] if "rmids" in body else ghab.rmids
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
        self.counselor.rotate(ghab=ghab, smids=aids, rmids=rmids,
                              isith=isith, nsith=nsith,
                              toad=toad, cuts=list(cuts), adds=list(adds),
                              data=data)

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

        aids = body["aids"] if "aids" in body else ghab.smids
        rmids = body["rmids"] if "rmids" in body else ghab.rmids
        data = body["data"] if "data" in body else None

        exn, atc = grouping.multisigInteractExn(ghab, aids, data)

        others = list(oset(ghab.smids + (ghab.rmids or [])))
        #others = list(ghab.smids)
        others.remove(ghab.mhab.pre)

        for recpt in others:  # send notification to other participants as a signalling mechanism
            self.postman.send(src=ghab.mhab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

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

        aids = body["aids"] if "aids" in body else ghab.smids
        rmids = body["rmids"] if "rmids" in body else ghab.rmids

        data = body["data"] if "data" in body else None

        serder = self.ixn(ghab=ghab, data=data, aids=aids)
        # cue up an event to send notification when complete
        self.evts.append(dict(r="/ixn/complete", i=serder.pre, s=serder.sn, d=serder.said))

        rep.status = falcon.HTTP_202


    def ixn(self, ghab, data, aids, rmids=None):
        """Todo Document this method

        Parameters
        """
        ixn = ghab.interact(data=data)

        serder = coring.Serder(raw=ixn)

        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=serder.sn)
        saider = coring.Saider(qb64b=serder.saidb)
        self.counselor.start(prefixer=prefixer, seqner=seqner, saider=saider,
                             mid=ghab.mhab.pre, smids=aids, rmids=rmids)
        return serder


class ChallengeEnd(doing.DoDoer):
    """ Resource for Challenge/Response Endpoints """

    def __init__(self, hby):
        """ Initialize Challenge/Response Endpoint

        Parameters:
            hby (Habery): database and keystore environment

        """
        self.hby = hby
        self.postman = forwarding.Postman(hby=self.hby)

        super(ChallengeEnd, self).__init__(doers=[self.postman])

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
        """ Challenge POST endpoint

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
        ims = hab.endorse(serder=exn, last=True, pipelined=False)
        del ims[:exn.size]

        senderHab = hab.mhab if hab.mhab else hab
        self.postman.send(src=senderHab.pre, dest=recpt, topic="challenge", serder=exn, attachment=ims)

        rep.status = falcon.HTTP_202

    def on_post_accept(self, req, rep, alias):
        """ Challenge POST accept endpoint

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
                        aid:
                          type: string
                          description: aid of signer of accepted challenge response
                        said:
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
        if "aid" not in body or "said" not in body:
            rep.status = falcon.HTTP_400
            rep.text = "challenge response acceptance requires 'aid' and 'said'"
            return

        aid = body["aid"]
        said = body["said"]
        saider = coring.Saider(qb64=said)
        self.hby.db.chas.add(keys=(aid,), val=saider)

        rep.status = falcon.HTTP_202


class NotificationEnd:
    def __init__(self, notifier):
        """
        REST APIs for Notifications

        Args:
            notifier (Notifier): notifier database containing notifications for the controller of the agent

        """
        self.notifier = notifier

    def on_get(self, req, rep):
        """ Notification GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
        ---
        summary:  Get list of notifcations for the controller of the agent
        description:  Get list of notifcations for the controller of the agent.  Notifications will
                       be sorted by creation date/time
        parameters:
          - in: query
            name: last
            schema:
              type: string
            required: false
            description: qb64 SAID of last notification seen
          - in: query
            name: limit
            schema:
              type: integer
            required: false
            description: size of the result list.  Defaults to 25
        tags:
           - Notifications

        responses:
           200:
              description: List of contact information for remote identifiers
        """
        last = req.params.get("last")
        limit = req.params.get("limit")

        limit = int(limit) if limit is not None else 25

        if last is not None:
            lastNote = self.notifier.get(last)
            if lastNote is not None:
                start = lastNote.datetime
            else:
                start = ""
        else:
            start = ""

        notes = self.notifier.getNotes(start=start, limit=limit)
        out = [note.pad for note in notes]

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(out).encode("utf-8")

    def on_put_said(self, _, rep, said):
        """ Notification PUT endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            said: qb64 SAID of notification to mark as read

        ---
        summary:  Mark notification as read
        description:  Mark notification as read
        tags:
           - Notifications
        parameters:
          - in: path
            name: said
            schema:
              type: string
            required: true
            description: qb64 said of note to mark as read
        responses:
           202:
              description: Notification successfully marked as read for prefix
           404:
              description: No notification information found for SAID
        """
        mared = self.notifier.mar(said)
        if not mared:
            rep.status = falcon.HTTP_404
            rep.data = json.dumps(dict(msg=f"no notification to mark as read for {said}")).encode("utf-8")
            return

        rep.status = falcon.HTTP_202

    def on_delete_said(self, _, rep, said):
        """ Notification DELETE endpoint

        Parameters:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            said: qb64 SAID of notification to delete

        ---
        summary:  Delete notification
        description:  Delete notification
        tags:
           - Notifications
        parameters:
          - in: path
            name: said
            schema:
              type: string
            required: true
            description: qb64 said of note to delete
        responses:
           202:
              description: Notification successfully deleted for prefix
           404:
              description: No notification information found for prefix
        """
        deleted = self.notifier.noter.rem(said)
        if not deleted:
            rep.status = falcon.HTTP_404
            rep.text = f"no notification to delete for {said}"
            return

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
        val = req.params.get("filter_value")

        if group is not None:
            data = dict()
            values = self.org.values(group, val)
            for value in values:
                contacts = self.org.find(group, value)
                self.authn(contacts)
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
            self.authn(contacts)
            rep.status = falcon.HTTP_200
            rep.data = json.dumps(contacts).encode("utf-8")

        else:
            data = []
            contacts = self.org.list()

            for contact in contacts:
                aid = contact["id"]
                if aid in self.hby.kevers and aid not in self.hby.prefixes:
                    data.append(contact)

            self.authn(data)
            rep.status = falcon.HTTP_200
            rep.data = json.dumps(data).encode("utf-8")

    def authn(self, contacts):
        for contact in contacts:
            aid = contact['id']
            accepted = [saider.qb64 for saider in self.hby.db.chas.get(keys=(aid,))]
            received = [saider.qb64 for saider in self.hby.db.reps.get(keys=(aid,))]

            challenges = []
            for said in received:
                exn = self.hby.db.exns.get(keys=(said,))
                challenges.append(dict(dt=exn.ked['dt'], words=exn.ked['a']['words'], said=said,
                                       authenticated=said in accepted))

            contact["challenges"] = challenges

            wellKnowns = []
            wkans = self.hby.db.wkas.get(keys=(aid,))
            for wkan in wkans:
                wellKnowns.append(dict(url=wkan.url, dt=wkan.dt))

            contact["wellKnowns"] = wellKnowns

    def on_post(self, req, rep, prefix):
        """ Contact plural GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: human readable name of identifier to replace contact information

       ---
        summary:  Create new contact information for an identifier
        description:  Creates new information for an identifier, overwriting all existing
                      information for that identifier
        tags:
           - Contacts
        parameters:
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

        self.org.replace(prefix, body)
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

    def on_put(self, req, rep, prefix):
        """ Contact PUT endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            prefix: qb64 identifier to update contact information

        ---
        summary:  Update provided fields in contact information associated with remote identfier prefix
        description:  Update provided fields in contact information associated with remote identfier prefix.  All
                      information is metadata and kept in local storage only
        tags:
           - Contacts
        parameters:
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

        self.org.update(prefix, body)
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
                        oots.append(eventing.loadEvent(self.db, pre, edig))
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
                        pwes.append(eventing.loadEvent(self.db, pre, edig))
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
                        pses.append(eventing.loadEvent(self.db, pre, edig))
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
                        ldes.append(eventing.loadEvent(self.db, pre, edig))
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

    def on_get_partial(self, req, rep, pre, dig):
        """

        Parameters:
            req (Request): falcon.Request HTTP request
            rep (Response): falcon.Response HTTP response
            pre (str): qb64 identifier prefix of event to load
            dig (str) qb64 SAID of the event to load

        ---
        summary:  Display escrow status for entire database or search for single identifier in escrows
        description:  Display escrow status for entire database or search for single identifier in escrows
        tags:
           - Escrows
        parameters:
          - in: path
            name: pre
            schema:
              type: string
            required: true
            description: qb64 identifier prefix of event to load
          - in: path
            name: dig
            schema:
              type: string
            required: true
            description: qb64 SAID of the event to load
        responses:
           200:
              description: Event information
           404:
              description: Event match pre and dig not found


        """
        try:
            event = eventing.loadEvent(self.db, pre, dig)
        except ValueError:
            rep.status = falcon.HTTP_404
            rep.text = "Event not found"
            return

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(event, indent=2).encode("utf-8")


class AeidEnd:

    def __init__(self, hby):
        """ Initialize endpoint for updating the passcode for this Habery

        Parameters:
            hby (Habery): identifier environment database
        """

        self.hby = hby

    @staticmethod
    def on_get(req, rep):
        """ GET endpoint for passcode resource

        Args:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Generate random 22 digit passcode for use in securing and encrypting keystore
        description: Generate random 22 digit passcode for use in securing and encrypting keystore
        tags:
           - Passcode
        responses:
           200:
              description: Randomly generated 22 character passcode formatted as xxxx-xxxxx-xxxx-xxxxx-xxxx

        """
        return booting.PasscodeEnd.on_get(req, rep)

    def on_post(self, req, rep):
        """ AEID POST endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

       ---
        summary:  Create new contact information for an identifier
        description:  Creates new information for an identifier, overwriting all existing
                      information for that identifier
        tags:
           - Passcode
        parameters:
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
           202:
              description: AEID successfully updated
           400:
              description: Invalid new passcode
           401:
              description: Original passcode incorrect
        """
        body = req.get_media()
        if "current" in body:
            cbran = body["current"]
            cbran = cbran.replace("-", "")
        else:
            rep.status = falcon.HTTP_400
            rep.data = json.dumps(dict(msg="Current passcode missing from body")).encode("utf-8")
            return

        cbran = coring.MtrDex.Salt_128 + 'A' + cbran[:21]  # qb64 salt for seed
        csigner = coring.Salter(qb64=cbran).signer(transferable=False,
                                                   temp=self.hby.temp, tier=None)
        if not self.hby.mgr.encrypter.verifySeed(csigner.qb64):
            rep.status = falcon.HTTP_401
            rep.data = json.dumps(dict(msg="Incorrect current passcode")).encode("utf-8")
            return

        if "passcode" in body:
            bran = body["passcode"]
            bran = bran.replace("-", "")
        else:
            rep.status = falcon.HTTP_400
            rep.data = json.dumps(dict(msg="Passcode missing from body")).encode("utf-8")
            return

        if len(bran) < 21:
            rep.status = falcon.HTTP_400
            rep.data = json.dumps(dict(msg="Invalid passcode, too short")).encode("utf-8")
            return

        bran = coring.MtrDex.Salt_128 + 'A' + bran[:21]  # qb64 salt for seed
        signer = coring.Salter(qb64=bran).signer(transferable=False,
                                                 temp=self.hby.temp)
        seed = signer.qb64
        aeid = signer.verfer.qb64

        self.hby.mgr.updateAeid(aeid, seed)

        rep.status = falcon.HTTP_202


def loadEnds(app, *,
             path,
             hby,
             rgy,
             verifier,
             counselor,
             signaler,
             notifier,
             registrar,
             credentialer,
             servery,
             bootConfig):
    """
    Load endpoints for KIWI admin interface into the provided Falcon app

    Parameters:
        app (falcon.App): falcon.App to register handlers with:
        path (str): directory location of UI web app files to be served with this API server
        hby (Habery): database environment for all endpoints
        rgy (Regery): database environment for credentials
        rep (Respondant): that routes responses to the appropriate mailboxes
        verifier (Verifier): that process credentials
        registrar (Registrar): credential registry protocol manager
        counselor (Counselor): group multisig identifier communication manager
        signaler (Signaler):  generator of transient signals to controller of agent
        notifier (Notifier):  generator of messages for review by controller of agent
        credentialer (Credentialer): credential issuance protocol manager
        servery (Servery):
        bootConfig: (dict): original launch configuration of Servery

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
    app.add_route("/ids/{alias}/metadata", identifierEnd, suffix="metadata")
    app.add_route("/ids/{alias}/rot", identifierEnd, suffix="rot")
    app.add_route("/ids/{alias}/ixn", identifierEnd, suffix="ixn")

    keyEnd = KeyStateEnd(hby=hby, counselor=counselor)
    app.add_route("/keystate/{prefix}", keyEnd)
    app.add_route("/keystate/pubkey/{pubkey}", keyEnd, suffix="pubkey")

    registryEnd = RegistryEnd(hby=hby, rgy=rgy, registrar=registrar)
    app.add_route("/registries", registryEnd)

    multiIcpEnd = MultisigInceptEnd(hby=hby, counselor=counselor, notifier=notifier)
    app.add_route("/groups/{alias}/icp", multiIcpEnd)
    multiEvtEnd = MultisigEventEnd(hby=hby, counselor=counselor, notifier=notifier)
    app.add_route("/groups/{alias}/rot", multiEvtEnd, suffix="rot")
    app.add_route("/groups/{alias}/ixn", multiEvtEnd, suffix="ixn")

    credsEnd = CredentialEnd(hby=hby, rgy=rgy, verifier=verifier, registrar=registrar, credentialer=credentialer,
                             notifier=notifier)
    app.add_route("/credentials/{alias}", credsEnd)
    app.add_route("/credentials/{alias}/{said}", credsEnd, suffix="export")
    app.add_route("/groups/{alias}/credentials", credsEnd, suffix="iss")
    app.add_route("/groups/{alias}/credentials/{said}/rev", credsEnd, suffix="rev")

    presentationEnd = PresentationEnd(hby=hby, reger=rgy.reger)
    app.add_route("/credentials/{alias}/presentations", presentationEnd, suffix="present")
    app.add_route("/credentials/{alias}/requests", presentationEnd, suffix="request")

    oobiEnd = oobiing.OobiResource(hby=hby)
    app.add_route("/oobi/{alias}", oobiEnd, suffix="alias")
    app.add_route("/oobi", oobiEnd)
    app.add_route("/oobi/groups/{alias}/share", oobiEnd, suffix="share")

    chacha = ChallengeEnd(hby=hby)
    app.add_route("/challenge", chacha)
    app.add_route("/challenge/{alias}", chacha, suffix="resolve")
    app.add_route("/challenge/accept/{alias}", chacha, suffix="accept")

    org = connecting.Organizer(hby=hby)
    contact = ContactEnd(hby=hby, org=org)

    app.add_route("/contacts/{prefix}/img", contact, suffix="img")
    app.add_route("/contacts/{prefix}", contact)
    app.add_route("/contacts", contact, suffix="list")

    notes = NotificationEnd(notifier=notifier)
    app.add_route("/notifications", notes)
    app.add_route("/notifications/{said}", notes, suffix="said")

    schemaEnd = SchemaEnd(db=hby.db)
    app.add_route("/schema", schemaEnd, suffix="list")
    app.add_route("/schema/{said}", schemaEnd)

    escrowEnd = EscrowEnd(db=hby.db)
    app.add_route("/escrows", escrowEnd)
    app.add_route("/escrows/{pre}/{dig}", escrowEnd, suffix="partial")

    aeidEnd = AeidEnd(hby=hby)
    app.add_route("/codes", aeidEnd)

    signalEnd = signaling.loadEnds(app, signals=signaler.signals)
    resources = [identifierEnd, MultisigInceptEnd, registryEnd, oobiEnd, credsEnd, keyEnd, signalEnd,
                 presentationEnd, multiIcpEnd, multiEvtEnd, chacha, contact, escrowEnd, lockEnd, aeidEnd]

    app.add_route("/spec.yaml", specing.SpecResource(app=app, title='KERI Interactive Web Interface API',
                                                     resources=resources))
    return [identifierEnd, registryEnd, oobiEnd, multiIcpEnd, multiEvtEnd, credsEnd, presentationEnd, lockEnd, chacha]


def setup(hby, rgy, servery, bootConfig, *, controller="", insecure=False, staticPath="", **kwargs):
    """ Setup and run a KIWI agent

    Parameters:
        hby (Habery): database environment for identifiers
        rgy (Regery): database environment for credentials
        servery (Servery): HTTP server manager for stopping and restarting HTTP servers
        bootConfig (dict): original configuration at launch, used to reset during lock
        controller (str): qb64 identifier prefix of the controller of this agent
        insecure (bool): allow unsigned HTTP requests to the admin interface (non-production ONLY)
        staticPath (str): path to static content for this agent

    Returns:
        list: Endpoint Doers to execute in Doist for agent.

    """

    # setup doers
    doers = [habbing.HaberyDoer(habery=hby), credentialing.RegeryDoer(rgy=rgy)]

    signaler = signaling.Signaler()
    notifier = notifying.Notifier(hby=hby, signaler=signaler)
    verifier = verifying.Verifier(hby=hby, reger=rgy.reger)
    wallet = walleting.Wallet(reger=verifier.reger, name=hby.name)

    handlers = []

    mbx = storing.Mailboxer(name=hby.name)
    counselor = grouping.Counselor(hby=hby)
    registrar = credentialing.Registrar(hby=hby, rgy=rgy, counselor=counselor)
    credentialer = credentialing.Credentialer(hby=hby, rgy=rgy, registrar=registrar, verifier=verifier)

    issueHandler = protocoling.IssueHandler(hby=hby, rgy=rgy, notifier=notifier)
    requestHandler = protocoling.PresentationRequestHandler(hby=hby, notifier=notifier)
    applyHandler = protocoling.ApplyHandler(hby=hby, rgy=rgy, verifier=verifier, name=hby.name)
    proofHandler = protocoling.PresentationProofHandler(notifier=notifier)

    handlers.extend([issueHandler, requestHandler, proofHandler, applyHandler])

    exchanger = exchanging.Exchanger(db=hby.db, handlers=handlers)
    challenging.loadHandlers(db=hby.db, signaler=signaler, exc=exchanger)
    grouping.loadHandlers(hby=hby, exc=exchanger, notifier=notifier)
    oobiery = keri.app.oobiing.Oobiery(hby=hby)
    authn = oobiing.Authenticator(hby=hby)

    delegating.loadHandlers(hby=hby, exc=exchanger, notifier=notifier)
    oobiing.loadHandlers(hby=hby, exc=exchanger, notifier=notifier)

    rep = storing.Respondant(hby=hby, mbx=mbx)
    cues = decking.Deck()
    mbd = indirecting.MailboxDirector(hby=hby,
                                      exc=exchanger,
                                      verifier=verifier,
                                      rep=rep,
                                      topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate",
                                              "/challenge", "/oobi"],
                                      cues=cues)
    # configure a kevery
    doers.extend([exchanger, mbd, rep])

    # Load admin interface
    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    if not insecure:
        app.add_middleware(httping.SignatureValidationComponent(hby=hby, pre=controller))
    app.req_options.media_handlers.update(media.Handlers())
    app.resp_options.media_handlers.update(media.Handlers())

    endDoers = loadEnds(app, path=staticPath, hby=hby, rgy=rgy, verifier=verifier,
                        counselor=counselor, registrar=registrar, credentialer=credentialer,
                        servery=servery, bootConfig=bootConfig, notifier=notifier, signaler=signaler)

    obi = dict(oobiery=oobiery)
    doers.extend([rep, counselor, registrar, credentialer, *oobiery.doers, *authn.doers, doing.doify(oobiCueDo, **obi)])
    doers.extend(endDoers)
    servery.msgs.append(dict(app=app, doers=doers))


def oobiCueDo(tymth, tock=0.0, **opts):
    """ Process Client responses by parsing the messages and removing the client/doer

    Parameters:
        tymth (function): injected function wrapper closure returned by .tymen() of
            Tymist instance. Calling tymth() returns associated Tymist .tyme.
        tock (float): injected initial tock value

    """
    obi = opts["oobiery"]
    _ = (yield tock)

    while True:
        while obi.cues:
            cue = obi.cues.popleft()
            kin = cue["kin"]
            oobi = cue["oobi"]
            if kin in ("resolved",):
                print(oobi, "succeeded")
            elif kin in ("failed",):
                print(oobi, "failed")

            yield 0.25
        yield tock
