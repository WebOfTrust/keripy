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
from hio.core.tcp import serving as tcpServing
from hio.help import helping, decking

from . import grouping, challenging, connecting
from .. import help
from .. import kering
from ..app import specing, forwarding, agenting, signing, storing, indirecting, httping, habbing, delegating
from ..core import parsing, coring, eventing
from ..db import dbing
from ..db.dbing import dgKey
from ..end import ending
from ..help import helping
from ..peer import exchanging
from ..vc import proving, handling, walleting
from ..vdr import viring, verifying, credentialing

logger = help.ogler.getLogger()


class IdentifierEnd(doing.DoDoer):
    """
    ReST API for admin of Identifiers
    """

    def __init__(self, hby, **kwa):
        self.hby = hby

        self.postman = forwarding.Postman(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=self.hby)
        self.swain = delegating.Boatswain(hby=hby)
        self.org = connecting.Organizer(db=hby.db)
        self.cues = decking.Deck()

        doers = [self.witDoer, self.postman, self.swain, doing.doify(self.eventDo)]

        super(IdentifierEnd, self).__init__(doers=doers, **kwa)

    def on_get(self, req, rep):
        """ Identifier GET endpoint

        Parameters:
            req: falcon.Request HTTP request
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

        for pre, hab in self.hby.habs.items():
            info = self.info(hab)
            res.append(info)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_get_alias(self, req, rep, alias=None):
        """ Identifier GET endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

        ---
        summary:  Get list of agent identfiers
        description:  Get identfier information associated with alias
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

        self.org.update(hab.pre, body)
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
                print(f"witnessing for {hab.pre}")
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

    def on_get(self, req, rep, prefix):
        """

        Parameters:
            req (Request): falcon.Request HTTP request
            rep (Response): falcon.Response HTTP response
            prefix (str): human readable name of identifier to replace contact information

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
              description: Updated contact information for remote identifier
           400:
              description: Invalid identfier used to update contact information
           404:
              description: Prefix not found in identifier contact information


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
            event = dict()
            dgkey = dbing.dgKey(preb, dig)  # get message
            if not (raw := self.hby.db.getEvt(key=dgkey)):
                rep.status = falcon.HTTP_400
                rep.text = "Missing event for dig={}.".format(dig)
                return
            srdr = coring.Serder(raw=bytes(raw))
            event["ked"] = srdr.ked

            # add indexed signatures to attachments
            if not (sigs := self.hby.db.getSigs(key=dgkey)):
                rep.status = falcon.HTTP_400
                rep.text = "Missing sigs for dig={}.".format(dig)
                return

            dsigs = []
            for s in sigs:
                sig = coring.Siger(qb64b=bytes(s))
                dsigs.append(dict(index=sig.index, signature=sig.qb64))
            event["signatures"] = dsigs

            # add indexed witness signatures to attachments
            dwigs = []
            if wigs := self.hby.db.getWigs(key=dgkey):
                for w in wigs:
                    sig = coring.Siger(qb64b=bytes(w))
                    dwigs.append(dict(index=sig.index, signature=sig.qb64))
            event["witness_signatures"] = dwigs

            # add authorizer (delegator/issure) source seal event couple to attachments
            couple = self.hby.db.getAes(dgkey)
            if couple is not None:
                raw = bytearray(couple)
                seqner = coring.Seqner(qb64b=raw, strip=True)
                saider = coring.Saider(qb64b=raw)
                event["source_seal"] = dict(sequence=seqner.sn, said=saider.qb64)

            receipts = dict()
            # add trans receipts quadruples
            if quads := self.hby.db.getVrcs(key=dgkey):
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
            if coups := self.hby.db.getRcts(key=dgkey):
                nontrans = []
                for coup in coups:
                    raw = bytearray(coup)
                    (prefixer, cigar) = eventing.deReceiptCouple(raw, strip=True)
                    nontrans.append(dict(prefix=prefixer.qb64, signature=cigar.qb64))
                receipts["nontransferable"] = nontrans

            event["receipts"] = receipts
            # add first seen replay couple to attachments
            if not (dts := self.hby.db.getDts(key=dgkey)):
                rep.status = falcon.HTTP_400
                rep.text = "Missing datetime for dig={}.".format(dig)
                return

            event["timestamp"] = coring.Dater(dts=bytes(dts)).dts

            kel.append(event)

        res["kel"] = kel

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")



class RegistryEnd(doing.DoDoer):
    """
    ReST API for admin of credential issuance and revocation registries

    """

    def __init__(self, hby, rgy, counselor, **kwa):
        self.hby = hby
        self.rgy = rgy
        self.registryIcpr = credentialing.RegistryInceptDoer(hby=hby, rgy=rgy, counselor=counselor)

        super(RegistryEnd, self).__init__(doers=[self.registryIcpr], **kwa)

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

        msg = dict(name=body["name"], pre=hab.pre)
        c = dict()
        if "noBackers" in body:
            c["noBackers"] = body["noBackers"]
        if "baks" in body:
            c["baks"] = body["baks"]
        if "toad" in body:
            c["toad"] = body["toad"]
        if "estOnly" in body:
            c["estOnly"] = body["estOnly"]
        msg['c'] = c

        self.registryIcpr.msgs.append(msg)
        rep.status = falcon.HTTP_202


class CredentialsEnd:
    """
    ReST API for admin of credentials

    """

    def __init__(self, hby, rep, verifier, rgy, cues=None):
        """ Create endpoint for issuing and listing credentials

        Endpoints for issuing and listing credentials from non-group identfiers only

        Args:
            hby (Habery):
            rep (Respondant):
            verifier (Verifier):
            rgy (Regery):
            cues (Deck):
        """

        self.hby = hby
        self.rep = rep

        self.verifier = verifier
        self.rgy = rgy
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
        typ = req.params.get("type")
        alias = req.params.get("alias")

        hab = self.hby.habByName(name=alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias {} for credentials" \
                       "".format(alias)
            return

        creds = []
        if typ == "issued":
            regname = req.params.get("registry")
            registry = self.rgy.registryByName(regname)

            saids = registry.reger.issus.get(keys=hab.pre)
            creds = self.verifier.reger.cloneCreds(saids)

        elif typ == "received":
            saids = self.verifier.reger.subjs.get(keys=hab.pre)
            creds = self.verifier.reger.cloneCreds(saids)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(creds).encode("utf-8")

    def on_post(self, req, rep, alias=None):
        """ Initiate a credential issuance from a group multisig identfier

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

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
        regname = body.get("registry")
        schema = body.get("schema")
        source = body.get("source")
        rules = body.get("rules")
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

        registry = self.rgy.registryByName(regname)
        if registry is None:
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

        creder = proving.credential(issuer=hab.pre,
                                    schema=schema,
                                    subject=d,
                                    source=source,
                                    rules=rules,
                                    status=registry.regk)
        print(creder.raw)
        try:
            registry.issue(creder=creder, dt=dt)
        except kering.MissingAnchorError:
            logger.info("Missing anchor from credential issuance due to multisig identifier")

        craw = signing.ratify(hab=hab, serder=creder)
        parsing.Parser().parse(ims=craw, vry=self.verifier)

        group = []
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
        description: Create a revocation entry in the provided registry for the specified credential from a group
                     identifier
        tags:
           - Group Credentials
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

        registry = self.rgy.registryByName(registry)
        if registry is None:
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

            registry.revoke(creder=creder)
        except kering.ValidationError as ex:
            rep.status = falcon.HTTP_CONFLICT
            rep.text = ex.args[0]
            return

        rep.status = falcon.HTTP_202


class MultisigCredentialIssuanceEnd:

    def __init__(self, hby, rgy, verifier):
        self.hby = hby
        self.rgy = rgy
        self.verifier = verifier

    def on_post(self, req, rep, alias=None):
        """ Initiate a credential issuance from a group multisig identfier

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

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
        regname = body.get("registry")
        schema = body.get("schema")
        source = body.get("source")
        rules = body.get("rules")
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

        regname = self.rgy.registryByName(regname)
        if regname is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(regname)
            return

        data = body.get("credentialData")
        dt = data["dt"] if "dt" in data else helping.nowIso8601()

        d = dict(
            d="",
            i=recipientIdentifier,
            dt=dt,
        )

        d |= data

        creder = proving.credential(issuer=hab.pre,
                                    schema=schema,
                                    subject=d,
                                    source=source,
                                    rules=rules,
                                    status=regname.regk)
        print(creder.raw)
        try:
            regname.issue(creder=creder, dt=dt)
        except kering.MissingAnchorError:
            logger.info("Missing anchor from credential issuance due to multisig identifier")

        craw = signing.ratify(hab=hab, serder=creder)
        parsing.Parser().parse(ims=craw, vry=self.verifier)

        group = []
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

    def on_put(self, req, rep, alias=None):
        """ Participate in a credential issuance from a group identfier

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: option route parameter for specific identifier to get

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
        rules = body.get("rules")
        recipientIdentifier = body.get("recipient")
        notify = body["notify"] if "notify" in body else True
        print(self.hby.habs)

    def on_delete(self, req, rep):
        """ Credential DELETE endpoint

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Revoke credential
        description: Create a revocation entry in the provided registry for the specified credential from a group
                     identifier
        tags:
           - Group Credentials
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
        regname = req.get_param("registry")
        said = req.get_param("said")
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = f"unknown local alias {alias}"
            return

        registry = self.rgy.registryByName(regname)
        if registry is None:
            rep.status = falcon.HTTP_400
            rep.text = "Credential registry {} does not exist.  It must be created before issuing " \
                       "credentials".format(regname)
            return

        try:
            creder = self.verifier.reger.creds.get(keys=said)
            if creder is None:
                rep.status = falcon.HTTP_NOT_FOUND
                rep.text = "credential not found"
                return

            registry.revoke(creder=creder)
        except kering.ValidationError as ex:
            rep.status = falcon.HTTP_CONFLICT
            rep.text = ex.args[0]
            return

        rep.status = falcon.HTTP_202


class ApplicationsEnd:
    """
    ReST API for admin of credential applications (apply requests)

    """

    def __init__(self, hby, rep):
        """

        """
        self.hby = hby
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
        alias = body.get("alias")
        schema = body.get("schema")
        issuer = body.get("issuer")
        values = body.get("values")

        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = f"unknown local alias {alias}"
            return

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


class MultisigInceptEnd(doing.DoDoer):
    """
    ReST API for admin of distributed multisig groups

    """

    def __init__(self, hby, counselor):
        """ Create an endpoint resource for creating or participating in multisig group identfiiers

        Parameters:
            hby (Habery): identifier database environment
            counselor (Counselor): multisig group communication management

        """

        self.hby = hby
        self.counselor = counselor
        self.cues = decking.Deck()
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(MultisigInceptEnd, self).__init__(doers=doers)

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

        inits["toad"] = body["toad"] if "toad" in body else None
        inits["wits"] = body["wits"] if "wits" in body else []
        inits["isith"] = body["isith"] if "isith" in body else None
        inits["nsith"] = body["nsith"] if "nsith" in body else None
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

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = serder.raw


class MultisigEventEnd(doing.DoDoer):
    """
    ReST API for admin of distributed multisig group rotations

    """

    def __init__(self, hby, counselor):

        self.hby = hby
        self.counselor = counselor
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(MultisigEventEnd, self).__init__(doers=doers)

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

        aids = body["aids"] if "aids" in body else ghab.aids
        toad = body["toad"] if "toad" in body else None
        wits = body["wits"] if "wits" in body else []
        adds = body["adds"] if "adds" in body else []
        cuts = body["cuts"] if "cuts" in body else []
        isith = body["isith"] if "isith" in body else None
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

        # begin the rotation process
        self.counselor.rotate(ghab=ghab, aids=aids, sith=isith, toad=toad, cuts=list(cuts), adds=list(adds), data=data)

        # Create `exn` peer to peer message to notify other participants UI
        exn, atc = grouping.multisigRotateExn(ghab, aids, isith, toad, cuts, adds, data)
        others = list(ghab.aids)
        others.remove(ghab.phab.pre)

        for recpt in others:  # send notification to other participants as a signalling mechanism
            self.postman.send(src=ghab.phab.pre, dest=recpt, topic="multisig", serder=exn, attachment=atc)

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

        aids = body["aids"] if "aids" in body else ghab.aids
        toad = body["toad"] if "toad" in body else None
        wits = body["wits"] if "wits" in body else []
        adds = body["adds"] if "adds" in body else []
        cuts = body["cuts"] if "cuts" in body else []
        isith = body["isith"] if "isith" in body else None
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

        self.counselor.rotate(ghab=ghab, aids=aids, sith=isith, toad=toad, cuts=list(cuts), adds=list(adds), data=data)

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

        self.ixn(ghab=ghab, data=data, aids=aids)

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

        self.ixn(ghab=ghab, data=data, aids=aids)
        rep.status = falcon.HTTP_202

    def ixn(self, ghab, data, aids):
        ixn = ghab.interact(data=data)

        serder = coring.Serder(raw=ixn)

        prefixer = coring.Prefixer(qb64=ghab.pre)
        seqner = coring.Seqner(sn=serder.sn)
        saider = coring.Saider(qb64b=serder.saidb)
        self.counselor.start(aids=aids, pid=ghab.phab.pre, prefixer=prefixer, seqner=seqner, saider=saider)


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

        self.oobiery = oobiery if oobiery is not None else ending.Oobiery(db=self.hby.db)
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
            self.oobiery.oobis.append(dict(alias=alias, url=oobi))
        elif "rpy" in body:
            pass
        else:
            rep.status = falcon.HTTP_400
            rep.data = "invalid OOBI request body, either 'rpy' or 'url' is required"
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
        self.rep.reps.append(dict(dest=recpt, rep=exn, topic="challenge"))

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

    def on_get_img(self, req, rep, prefix):
        """ Contact image GET endpoint

        Parameters:
            req: falcon.Request HTTP request
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

    def on_get(self, req, rep, prefix):
        """ Contact GET endpoint

        Parameters:
            req: falcon.Request HTTP request
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

    def on_delete(self, req, rep, prefix):
        """ Contact plural GET endpoint

        Parameters:
            req: falcon.Request HTTP request
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


class KiwiDoer(doing.DoDoer):
    """
    Routes for handling UI requests for Credential issuance/revocation and presentation requests

    """

    def __init__(self, hby, rep, verifier, cues=None, queries=None, **kwa):
        """
        Create a KIWI web server for Agents capable of performing KERI and ACDC functions for the controller
        of an identifier.

        Parameters:
            hby (Habery): is the environment of the identifier prefix
            controller qb64 is the identifier prefix that can send commands to this web server:
            rep Respondant that routes responses to the appropriate mailboxes
            verifier is Verifier that process credentials
            gdoe is decking.Deck of msgs to send to a MultisigDoer
            wallet is Wallet for local storage of credentials
            cues is Deck from Kevery handling key events:
            app falcon.App to register handlers with:
            insecure bool is True to allow requests without verifying KERI Http Signature Header,
                defaults to False

        """
        self.hby = hby
        self.rep = rep
        self.verifier = verifier if verifier is not None else verifying.Verifier(hby=self.hby)

        self.cues = cues if cues is not None else decking.Deck()
        self.queries = queries if queries is not None else decking.Deck()

        self.postman = forwarding.Postman(hby=self.hby)
        self.witDoer = agenting.WitnessReceiptor(hby=hby)

        doers = [self.postman, self.witDoer, doing.doify(self.verifierDo), doing.doify(self.cueDo)]

        super(KiwiDoer, self).__init__(doers=doers, **kwa)

    def cueDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            .kevery.cues deque

        Doist Injected Attributes:
            g.tock = tock  # default tock attributes
            g.done = None  # default done state
            g.opts

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.cues:
                cue = self.cues.popleft()
                cueKin = cue["kin"]
                if cueKin == "stream":
                    self.queries.append(cue)
                yield self.tock
            yield self.tock

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

                yield self.tock
            yield self.tock


def loadEnds(app, *, path, hby, rgy, rep, mbx, verifier, counselor, rxbs=None, queries=None, oobiery=None):
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
        counselor (Counselor): group multisig identifier communication manager
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

    identifierEnd = IdentifierEnd(hby=hby)
    app.add_route("/ids", identifierEnd)
    app.add_route("/ids/{alias}", identifierEnd, suffix="alias")
    app.add_route("/ids/{alias}/rot", identifierEnd, suffix="rot")
    app.add_route("/ids/{alias}/ixn", identifierEnd, suffix="ixn")

    keyEnd = KeyStateEnd(hby=hby)
    app.add_route("/keystate/{prefix}", keyEnd)

    registryEnd = RegistryEnd(hby=hby, rgy=rgy, counselor=counselor)
    app.add_route("/registries", registryEnd)

    credentialsEnd = CredentialsEnd(hby=hby, rgy=rgy,
                                    rep=rep,
                                    verifier=verifier)
    app.add_route("/credentials", credentialsEnd)

    applicationsEnd = ApplicationsEnd(hby=hby, rep=rep)
    app.add_route("/applications", applicationsEnd)

    presentationEnd = PresentationEnd(rep=rep)
    app.add_route("/presentation", presentationEnd)

    multiIcpEnd = MultisigInceptEnd(hby=hby, counselor=counselor)
    app.add_route("/groups/{alias}/icp", multiIcpEnd)
    multiEvtEnd = MultisigEventEnd(hby=hby, counselor=counselor)
    app.add_route("/groups/{alias}/rot", multiEvtEnd, suffix="rot")
    app.add_route("/groups/{alias}/ixn", multiEvtEnd, suffix="ixn")
    multiCredIss = MultisigCredentialIssuanceEnd(hby=hby, rgy=rgy, verifier=verifier)
    app.add_route("/groups/{alias}/credentials/issue", multiCredIss)

    oobiEnd = OobiResource(hby=hby, oobiery=oobiery)
    app.add_route("/oobi/{alias}", oobiEnd)

    chacha = ChallengeEnd(hby=hby, rep=rep)
    app.add_route("/challenge", chacha)
    app.add_route("/challenge/{alias}", chacha, suffix="resolve")

    org = connecting.Organizer(db=hby.db)
    contact = ContactEnd(hby=hby, org=org)

    app.add_route("/contacts/{prefix}", contact)
    app.add_route("/contacts/{prefix}/img", contact, suffix="img")
    app.add_route("/contacts", contact, suffix="list")

    httpEnd = indirecting.HttpEnd(rxbs=rxbs, mbx=mbx, qrycues=queries)
    app.add_route("/mbx", httpEnd, suffix="mbx")

    resources = [identifierEnd, MultisigInceptEnd, registryEnd, oobiEnd, applicationsEnd, credentialsEnd,
                 presentationEnd, multiIcpEnd, multiEvtEnd, chacha, contact]

    app.add_route("/spec.yaml", specing.SpecResource(app=app, title='KERI Interactive Web Interface API',
                                                     resources=resources))

    return [identifierEnd, registryEnd, oobiEnd, multiIcpEnd, multiEvtEnd]


def setup(hby, rgy, servery, *, controller="", insecure=False, tcp=5621, staticPath=""):
    """ Setup and run a KIWI agent

    Parameters:
        hby (Habery): database environment for identifiers
        rgy (Regery): database environment for credentials
        servery (Servery): HTTP server manager for stopping and restarting HTTP servers
        controller (str): qb64 identifier prefix of the controller of this agent
        insecure (bool): allow unsigned HTTP requests to the admin interface (non-production ONLY)
        tcp (int): TCP port for agent to listen on for incoming direct connections
        staticPath (str): path to static content for this agent

    Returns:
        list: Endpoint Doers to execute in Doist for agent.

    """

    # setup doers
    doers = [habbing.HaberyDoer(habery=hby)]

    tcpServer = tcpServing.Server(host="", port=tcp)
    tcpServerDoer = tcpServing.ServerDoer(server=tcpServer)

    reger = viring.Reger(name=hby.name, temp=False, db=hby.db)
    verifier = verifying.Verifier(hby=hby, reger=reger)
    wallet = walleting.Wallet(reger=verifier.reger, name=hby.name)

    handlers = []

    proofs = decking.Deck()

    issueHandler = handling.IssueHandler(hby=hby, verifier=verifier)
    requestHandler = handling.RequestHandler(hby=hby, wallet=wallet)
    applyHandler = handling.ApplyHandler(hby=hby, rgy=rgy, verifier=verifier, name=hby.name)
    proofHandler = handling.ProofHandler(proofs=proofs)

    mbx = storing.Mailboxer(name=hby.name)

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
    doers.extend([exchanger, tcpServerDoer, mbd, rep])

    # Load admin interface
    rep = storing.Respondant(hby=hby, mbx=mbx)

    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    if not insecure:
        app.add_middleware(httping.SignatureValidationComponent(hby=hby, pre=controller))
    app.req_options.media_handlers.update(media.Handlers())
    app.resp_options.media_handlers.update(media.Handlers())

    counselor = grouping.Counselor(hby=hby)

    queries = decking.Deck()
    endDoers = loadEnds(app, path=staticPath, hby=hby, rgy=rgy, rep=rep, mbx=mbx, verifier=verifier,
                        counselor=counselor, rxbs=mbd.ims, queries=queries)

    servery.msgs.append(dict(app=app))
    kiwiDoer = KiwiDoer(hby=hby,
                        rep=rep,
                        mbx=mbx,
                        verifier=verifier,
                        queries=queries,
                        rgy=rgy)

    proofHandler = AdminProofHandler(hby=hby, controller=controller, mbx=mbx, verifier=verifier, proofs=proofs,
                                     ims=mbd.ims)

    doers.extend([rep, proofHandler, counselor, kiwiDoer])
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
