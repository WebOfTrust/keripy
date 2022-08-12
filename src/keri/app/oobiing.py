# -*- encoding: utf-8 -*-
"""
keri.kli.common.oobiing module

"""
import json
from urllib.parse import urlparse

import falcon
from hio.base import doing

from keri import kering
from keri.app import forwarding, delegating
from keri.db import basing
from keri.help import helping


def loadEnds(app, *, hby, prefix=""):
    oobiEnd = OobiResource(hby=hby)
    app.add_route(prefix+"/oobi", oobiEnd)
    app.add_route(prefix+"/oobi/groups/{alias}/share", oobiEnd, suffix="share")

    return [oobiEnd]


class OobiResource(doing.DoDoer):
    """
    Resource for managing OOBIs

    """

    def __init__(self, hby):
        """ Create Endpoints for discovery and resolution of OOBIs

        Parameters:
            hby (Habery): identifier database environment
            oobiery (Optioanl[Oobiery]): optional OOBI loader
        """
        self.hby = hby

        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.postman]

        super(OobiResource, self).__init__(doers=doers)

    def on_get_alias(self, req, rep, alias=None):
        """ OOBI GET endpoint

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

    def on_post(self, req, rep):
        """ Resolve OOBI endpoint.

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response

        ---
        summary: Resolve OOBI and assign an alias for the remote identifier
        description: Resolve OOBI URL or `rpy` message by process results of request and assign 'alias' in contact
                     data for resolved identifier
        tags:
           - OOBIs
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
                          required: false
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

            obr = basing.OobiRecord(date=helping.nowIso8601())
            if "oobialias" in body:
                obr.oobialias = body["oobialias"]

            self.hby.db.oobis.pin(keys=(oobi,), val=obr)

        elif "rpy" in body:
            rep.status = falcon.HTTP_501
            rep.text = "'rpy' support not implemented yet'"
            return

        else:
            rep.status = falcon.HTTP_400
            rep.text = "invalid OOBI request body, either 'rpy' or 'url' is required"
            return

        rep.status = falcon.HTTP_202

    def on_post_share(self, req, rep, alias):
        """ Share OOBI endpoint.

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            alias: human readable name of the local identifier context for resolving this OOBI

        ---
        summary: Share OOBI and alias for remote identifier with other aids
        description: Send all other participants in a group AID a copy of the OOBI with suggested alias
        tags:
           - OOBIs
        parameters:
          - in: path
            name: alias
            schema:
              type: string
            required: true
            description: Human readable alias for AID to use to sign exn message
        requestBody:
            required: true
            content:
              application/json:
                schema:
                    description: OOBI
                    properties:
                        oobis:
                            type: array
                            items:
                               type: object
                               properties:
                                  alias:
                                    type: string
                                    description: alias to assign to the identifier resolved from this OOBI
                                    required: true
                                  url:
                                    type: string
                                    description:  URL OOBI
        responses:
           202:
              description: OOBI resolution to key state successful

        """
        body = req.get_media()
        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_404
            rep.text = f"Unknown identifier {alias}"
            return

        if hab.phab is None:
            rep.status = falcon.HTTP_400
            rep.text = f"Identifer for {alias} is not a group hab, not supported"
            return

        oobis = body["oobis"]
        for aid in hab.aids:
            if aid == hab.phab.pre:
                continue

            for oobi in oobis:
                exn, atc = delegating.oobiRequestExn(hab.phab, aid, oobi["alias"], oobi["url"])
                self.postman.send(src=hab.phab.pre, dest=aid, topic="delegate", serder=exn, attachment=atc)

        rep.status = falcon.HTTP_200
        return
