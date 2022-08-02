# -*- encoding: utf-8 -*-
"""
keri.kli.common.oobiing module

"""
import json
from urllib.parse import urlparse

import falcon
from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import forwarding, delegating
from keri.end import ending


def loadEnds(app, *, hby, oobiery, prefix=""):
    oobiEnd = OobiResource(hby=hby, oobiery=oobiery)
    app.add_route(prefix+"/oobi/{alias}", oobiEnd, suffix="alias")
    app.add_route(prefix+"/oobi", oobiEnd)
    app.add_route(prefix+"/oobi/groups/{alias}/share", oobiEnd, suffix="share")

    return [oobiEnd]


class OobiLoader(doing.DoDoer):
    """ DoDoer for loading oobis and waiting for the results """

    def __init__(self, hby, oobis=None, auto=False):
        """

        Parameters:
            hby (Habery) database environment with preloaded oobis:
            oobis (list): optional list of oobis to load
            auto (bool): True means load oobis from database
        """

        self.processed = 0
        self.db = hby.db
        self.oobis = oobis if oobis is not None else decking.Deck()

        self.oobiery = ending.Oobiery(hby=hby)
        if auto:
            for ((oobi,), _) in self.db.oobis.getItemIter():
                self.oobiery.oobis.append(dict(url=oobi))
                self.oobis.append(oobi)

        doers = [self.oobiery, doing.doify(self.loadDo)]

        super(OobiLoader, self).__init__(doers=doers)

    def queue(self, oobis):
        """ Queue up a list of oobis to process, then exit

        Parameters:
            oobis (list): list of OOBIs to resolve.

        """
        for oobi in oobis:
            self.oobiery.oobis.append(oobi)
            self.oobis.append(oobi["url"])

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

        while not self.oobis:  # wait until we have some OOBIs to process
            yield self.tock

        while True:
            if not self.oobis:
                yield self.tock
                break

            while self.oobiery.cues:
                cue = self.oobiery.cues.popleft()
                kin = cue["kin"]
                oobi = cue["oobi"]
                if kin in ("resolved",):
                    print(oobi, "succeeded")
                    self.oobis.remove(oobi)
                if kin in ("failed",):
                    print(oobi, "failed")
                    self.oobis.remove(oobi)

                self.db.oobis.rem(keys=(oobi, ))

                yield 0.25

            yield self.tock

        self.remove([self.oobiery])


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
        self.postman = forwarding.Postman(hby=self.hby)
        doers = [self.oobiery, self.postman, doing.doify(self.loadDo)]

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
            # oobialias is alias name for new identifier, alias is local hab that will sign the data
            self.oobiery.oobis.append(dict(alias=alias, oobialias=oobialias, url=oobi))
        elif "rpy" in body:
            pass
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
