# -*- encoding: utf-8 -*-
"""
keri.kli.common.oobiing module

"""
import datetime
import json
import logging
from collections import namedtuple
from urllib import parse
from urllib.parse import urlparse

import falcon
from hio.base import doing
from hio.help import decking

from keri.core import coring
from . import httping
from .. import help
from .. import kering
from ..core import routing, eventing, parsing, scheming, serdering
from ..db import basing
from ..end import ending
from ..end.ending import OOBI_RE, DOOBI_RE
from ..help import helping
from ..kering import Ilks, ValidationError, UnverifiedReplyError, ConfigurationError
from ..peer import exchanging

logger = help.ogler.getLogger()

Resultage = namedtuple("Resultage", 'resolved failed')  # stream cold start status
Result = Resultage(resolved='resolved', failed='failed')


def loadEnds(app, *, hby, prefix=""):
    oobiEnd = OobiResource(hby=hby)
    app.add_route(prefix + "/oobi", oobiEnd)
    return []


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the peer-to-peer delegation protocols

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Outbound notifications

    """
    oobireq = OobiRequestHandler(hby=hby, notifier=notifier)
    exc.addHandler(oobireq)


class OobiResource:
    """
    Resource for managing OOBIs

    """

    def __init__(self, hby):
        """ Create Endpoints for discovery and resolution of OOBIs

        Parameters:
            hby (Habery): identifier database environment

        """
        self.hby = hby

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
                urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) \
                       or hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
                if not urls:
                    rep.status = falcon.HTTP_404
                    rep.text = f"unable to query witness {wit}, no http endpoint"
                    return

                url = urls[kering.Schemes.https] if kering.Schemes.https in urls else urls[kering.Schemes.http]
                oobis.append(f"{url.rstrip("/")}/oobi/{hab.pre}/witness/{wit}")
            res["oobis"] = oobis
        elif role in (kering.Roles.controller,):  # Fetch any controller URL OOBIs
            oobis = []
            urls = hab.fetchUrls(eid=hab.pre, scheme=kering.Schemes.http) or hab.fetchUrls(eid=hab.pre,
                                                                                           scheme=kering.Schemes.https)
            if not urls:
                rep.status = falcon.HTTP_404
                rep.text = f"unable to query controller {hab.pre}, no http endpoint"
                return
            url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
            oobis.append(f"{url.rstrip("/")}/oobi/{hab.pre}/controller")
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
        description: Resolve OOBI URL or `rpy` message by process results of request and assign 'alias' in contact data
                      for resolved identifier
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


class OobiRequestHandler:
    """
    Handler for oobi notification EXN messages

    """
    resource = "/oobis"

    def __init__(self, hby, notifier):
        """

        Parameters:
            hby (Habery) database environment of the controller
            notifier (Notifier) notifier to convert OOBI request exn messages to controller notifications

        """
        self.hby = hby
        self.notifier = notifier

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of OOBI request messages

        Parameters:
            serder (Serder): Serder of the exn OOBI request message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        src = serder.pre
        pay = serder.ked['a']
        if "oobi" not in pay:
            print(f"invalid oobi message, missing oobi.  evt={serder.ked}")
            return
        oobi = pay["oobi"]

        obr = basing.OobiRecord(date=helping.nowIso8601())
        self.hby.db.oobis.pin(keys=(oobi,), val=obr)

        data = dict(
            r="/oobi",
            src=src,
            oobi=oobi
        )

        purl = parse.urlparse(oobi)
        params = parse.parse_qs(purl.query)
        if "name" in params:
            data["oobialias"] = params["name"][0]

        self.notifier.add(attrs=data)


def oobiRequestExn(hab, dest, oobi):
    data = dict(
        dest=dest,
        oobi=oobi
    )

    # Create `exn` peer to peer message to notify other participants UI
    exn, _ = exchanging.exchange(route=OobiRequestHandler.resource, modifiers=dict(),
                                 payload=data, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]

    return exn, ims


class Oobiery:
    """ Resolver for OOBIs

    """

    RetryDelay = 30

    def __init__(self, hby, rvy=None, clienter=None, cues=None):
        """  DoDoer to handle the request and parsing of OOBIs

        Parameters:
            hby (Habery): database environment
            clienter (Clienter): DoDoer client provider responsible for managing HTTP client requests
            cues (decking.Deck): outbound cues from processing oobis
        """

        self.hby = hby
        self.rvy = rvy
        if self.rvy is not None:
            self.registerReplyRoutes(self.rvy.rtr)

        self.clienter = clienter or httping.Clienter()

        # Set up a local parser for returned events from OOBI queries.
        rtr = routing.Router()
        rvy = routing.Revery(db=self.hby.db, rtr=rtr)
        kvy = eventing.Kevery(db=self.hby.db, lax=True, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        self.parser = parsing.Parser(framed=True, kvy=kvy, rvy=rvy)

        self.cues = cues if cues is not None else decking.Deck()
        self.clients = dict()
        self.doers = [self.clienter, doing.doify(self.scoobiDo)]

    def registerReplyRoutes(self, router):
        """ Register the routes for processing messages embedded in `rpy` event messages

        The Oobiery handles rpy messages with the /introduce route by processing the contained oobi

        Parameters:
            router(Router): reply message router

        """
        router.addRoute("/introduce", self)

    def processReply(self, *, serder, saider, route, cigars=None, tsgs=None, **kwargs):
        """
        Process one reply message for route = /introduce
        with either attached nontrans receipt couples in cigars or attached trans
        indexed sig groups in tsgs.
        Assumes already validated saider, dater, and route from serder.ked

        Parameters:
            serder (SerderKERI): instance of reply msg (SAD)
            saider (Saider): instance  from said in serder (SAD)
            route (str): reply route
            cigars (list): of Cigar instances that contain nontrans signing couple
                          signature in .raw and public key in .verfer
            tsgs (list): tuples (quadruples) of form
                (prefixer, seqner, diger, [sigers]) where:
                prefixer is pre of trans endorser
                seqner is sequence number of trans endorser's est evt for keys for sigs
                diger is digest of trans endorser's est evt for keys for sigs
                [sigers] is list of indexed sigs from trans endorser's keys from est evt

        OobiRecord:
            date: str = date time of reply message of the introduction

        Reply Message:
        {
          "v" : "KERI10JSON00011c_",
          "t" : "rpy",
          "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
          "dt": "2020-08-22T17:50:12.988921+00:00",
          "r" : "/introduce",
          "a" :
          {
             "cid": "ENcOes8_t2C7tck4X4j61fSm0sWkLbZrEZffq7mSn8On",
             "oobi":  "http://localhost:5632/oobi/ENcOes8_t2C7tck4X4j61fSm0sWkLbZrEZffq7mSn8On/witness",
          }
        }

        """
        if route != "/introduce":
            raise ValidationError(f"Usupported route={route} in {Ilks.rpy} "
                                  f"msg={serder.ked}.")

        data = serder.ked['a']
        dt = serder.ked["dt"]

        for k in ("cid", "oobi"):
            if k not in data:
                raise ValidationError(f"Missing element={k} from attributes in"
                                      f" {Ilks.rpy} msg={serder.ked}.")

        cider = coring.Prefixer(qb64=data["cid"])  # raises error if unsupported code
        cid = cider.qb64  # controller authorizing eid at role
        aid = cid  # authorizing attribution id

        oobi = data["oobi"]
        url = urlparse(oobi)
        if url.scheme not in ("http", "https"):
            raise ValidationError(f"Invalid url scheme for introduced OOBI scheme={url.scheme}")

        if self.rvy is None:
            raise ConfigurationError("this oobiery is not configured to handle rpy introductions")

        # Process BADA RUN but with no previous reply message, always process introductions
        accepted = self.rvy.acceptReply(serder=serder, saider=saider, route=route,
                                        aid=aid, osaider=None, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified introduction reply. {serder.ked}")

        obr = basing.OobiRecord(cid=cid, date=dt)
        self.hby.db.oobis.put(keys=(oobi,), val=obr)

    def scoobiDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            .exc responses and pass them on to the HTTPRespondant

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        _ = (yield tock)

        while True:
            self.processFlows()
            yield tock

    def processFlows(self):
        """
        Process OOBI URLs by requesting from the endpoint and parsing the results

        """
        self.processOobis()
        self.processClients()
        self.processRetries()
        self.processMOOBIs()

    def processOobis(self):
        """ Process OOBI records loaded for discovery

        There should be only one OOBIERY that minds the OOBI table, this should read from the table like an escrow

        """
        for (url,), obr in self.hby.db.oobis.getItemIter():
            try:
                # Don't process OOBIs we've already resolved or are in escrow being retried
                if ((fnd := self.hby.db.roobi.get(keys=(url,))) is not None and fnd.state == Result.resolved) and \
                        self.hby.db.eoobi.get(keys=(url,)) is not None:
                    logging.info(f"OOBI {url} already resolved, skipping")
                    self.hby.db.oobis.rem(keys=(url,))
                    continue

                purl = parse.urlparse(url)

                if purl.path == "/oobi":  # Self and Blinded Introductions
                    params = parse.parse_qs(purl.query)

                    # If name is hinted in query string, use it as alias if not provided in OOBIRecord
                    if "name" in params and obr.oobialias is None:
                        obr.oobialias = params["name"][0]

                    self.request(url, obr)

                elif (match := OOBI_RE.match(purl.path)) is not None:  # Full CID and optional EID
                    obr.cid = match.group("cid")
                    obr.eid = match.group("eid")
                    obr.role = match.group("role")
                    params = parse.parse_qs(purl.query)

                    # If name is hinted in query string, use it as alias if not provided in OOBIRecord
                    if "name" in params and obr.oobialias is None:
                        obr.oobialias = params["name"][0]

                    self.request(url, obr)

                elif (match := DOOBI_RE.match(purl.path)) is not None:  # Full CID and optional EID
                    obr.said = match.group("said")
                    self.request(url, obr)

                elif (match := ending.WOOBI_RE.match(purl.path)) is not None:  # Well Known
                    obr.cid = match.group("cid")
                    params = parse.parse_qs(purl.query)

                    # If name is hinted in query string, use it as alias if not provided in OOBIRecord
                    if "name" in params and obr.oobialias is None:
                        obr.oobialias = params["name"][0]

                    self.request(url, obr)

            except ValueError as ex:
                print(f"error requesting invalid OOBI URL {ex}", url)

    def processClients(self):
        """ Process Client responses by parsing the messages and removing the client/doer

        """
        for (url,), obr in self.hby.db.coobi.getItemIter():
            if url not in self.clients:
                self.request(url, obr)
                continue

            client = self.clients[url]

            if client.responses:
                response = client.responses.popleft()
                self.clienter.remove(client)

                if response["status"] == 404:
                    print(f"{url} not found")
                    self.hby.db.coobi.rem(keys=(url,))
                    self.hby.db.eoobi.pin(keys=(url,), val=obr)
                    continue

                elif not response["status"] == 200:
                    print("invalid status for oobi response: {}".format(response["status"]))
                    self.hby.db.coobi.rem(keys=(url,))
                    obr.state = Result.failed
                    self.hby.db.roobi.put(keys=(url,), val=obr)

                elif response["headers"]["Content-Type"] == "application/json+cesr":  # CESR Stream response to OOBI
                    self.parser.parse(ims=bytearray(response["body"]))
                    if ending.OOBI_AID_HEADER in response["headers"]:
                        obr.cid = response["headers"][ending.OOBI_AID_HEADER]

                    self.hby.db.coobi.rem(keys=(url,))
                    obr.state = Result.resolved
                    self.hby.db.roobi.put(keys=(url,), val=obr)

                elif response["headers"]["Content-Type"] == "application/schema+json":  # Schema response to data OOBI
                    try:
                        schemer = scheming.Schemer(raw=bytearray(response["body"]))
                        if schemer.said == obr.said:
                            self.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
                            result = Result.resolved
                        else:
                            result = Result.failed

                    except (kering.ValidationError, ValueError):
                        result = Result.failed

                    obr.state = result
                    self.hby.db.coobi.rem(keys=(url,))
                    self.hby.db.roobi.put(keys=(url,), val=obr)

                elif response["headers"]["Content-Type"].startswith("application/json"):  # Unsigned rpy OOBI or Schema

                    try:
                        schemer = scheming.Schemer(raw=bytearray(response["body"]))
                        if schemer.said == obr.said:
                            self.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
                            result = Result.resolved
                        else:
                            result = Result.failed

                        obr.state = result
                        self.hby.db.coobi.rem(keys=(url,))
                        self.hby.db.roobi.put(keys=(url,), val=obr)
                        continue

                    except (kering.ValidationError, ValueError):
                        pass

                    try:
                        serder = serdering.SerderKERI(raw=bytearray(response["body"]))
                    except ValueError:
                        obr.state = Result.failed
                        self.hby.db.coobi.rem(keys=(url,))
                        self.hby.db.roobi.put(keys=(url,), val=obr)
                        continue
                    if not serder.ked['t'] == coring.Ilks.rpy:
                        obr.state = Result.failed
                        self.hby.db.coobi.rem(keys=(url,))
                        self.hby.db.roobi.put(keys=(url,), val=obr)

                    elif serder.ked['r'] in ('/oobi/witness', '/oobi/controller'):
                        self.processMultiOobiRpy(url, serder, obr)

                    else:
                        obr.state = Result.failed
                        self.hby.db.coobi.rem(keys=(url,))
                        self.hby.db.roobi.put(keys=(url,), val=obr)

                else:
                    self.hby.db.coobi.rem(keys=(url,))
                    obr.state = Result.failed
                    self.hby.db.roobi.put(keys=(url,), val=obr)
                    logger.error("invalid content type for oobi response: {}"
                                 .format(response["headers"]["Content-Type"]))

                self.cues.append(dict(kin=obr.state, oobi=url))

    def processMOOBIs(self):
        """ Process Client responses by parsing the messages and removing the client/doer

        """
        for (url,), obr in self.hby.db.moobi.getItemIter():
            result = Result.resolved
            complete = True
            for oobi in obr.urls:
                robr = self.hby.db.roobi.get(keys=(oobi,))
                if not robr:
                    complete = False
                    break
                if robr.state == Result.failed:
                    result = Result.failed

            if complete:
                obr.state = result
                self.hby.db.coobi.rem(keys=(url,))
                self.hby.db.roobi.put(keys=(url,), val=obr)

    def processRetries(self):
        """ Process Client responses by parsing the messages and removing the client/doer

        """
        for (url,), obr in self.hby.db.eoobi.getItemIter():
            last = helping.fromIso8601(obr.date)
            now = helping.nowUTC()
            if (now - last) > datetime.timedelta(seconds=self.RetryDelay):
                obr.date = helping.toIso8601(now)
                self.hby.db.eoobi.rem(keys=(url,))
                self.hby.db.oobis.pin(keys=(url,), val=obr)

    def request(self, url, obr):
        client = self.clienter.request("GET", url=url)
        if client is None:
            self.hby.db.oobis.rem(keys=(url,))
            print(f"error getting client for {url}, aborting OOBI")
            return

        self.clients[url] = client
        self.hby.db.oobis.rem(keys=(url,))
        self.hby.db.coobi.pin(keys=(url,), val=obr)

    def processMultiOobiRpy(self, url, serder, mobr):
        data = serder.ked["a"]
        cid = data["aid"]

        if cid != mobr.cid:
            return Result.failed

        urls = data["urls"]
        mobr.urls = urls

        for murl in urls:
            obr = basing.OobiRecord(date=helping.nowIso8601())
            obr.oobialias = mobr.oobialias
            obr.cid = mobr.cid
            self.hby.db.oobis.put(keys=(murl,), val=obr)

        self.hby.db.coobi.rem(keys=(url,))
        self.hby.db.moobi.put(keys=(url,), val=mobr)


class Authenticator:

    def __init__(self, hby, clienter=None):
        """

        Parameters:
            hby (Habery): Identifier database environment
            clienter (Clienter): DoDoer client provider responsible for managing HTTP client requests
        """
        self.hby = hby
        self.clienter = clienter if clienter is not None else httping.Clienter()
        self.clients = dict()
        self.doers = [self.clienter, doing.doify(self.authzDo)]

    def request(self, wurl, obr):
        client = self.clienter.request("GET", wurl)

        self.clients[wurl] = client
        self.hby.db.woobi.rem(keys=(wurl,))
        self.hby.db.mfa.pin(keys=(wurl,), val=obr)

    def addAuthToAid(self, cid, url):
        now = help.nowIso8601()
        wkan = basing.WellKnownAuthN(url=url, dt=now)
        self.hby.db.wkas.add(keys=(cid,), val=wkan)

    def authzDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatibile generator method (doer dog) to process
            .exc responses and pass them on to the HTTPRespondant

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Usage:
            add result of doify on this method to doers list
        """
        _ = (yield tock)

        while True:
            self.processFlows()
            yield tock

    def processFlows(self):
        """ Process well-known authentication URLs """

        self.processWoobis()
        self.processMultiFactorAuth()

    def processWoobis(self):
        """ Process well-known OOBIs saved as multi-factor auth records

        Process wOOBI URLs by requesting from the endpoint and confirming the results

        """
        for (wurl,), obr in self.hby.db.woobi.getItemIter():
            # Find any woobis that match and can be used to perform MFA for this resolved AID
            purl = urlparse(wurl)
            if (match := ending.WOOBI_RE.match(purl.path)) is not None:
                cid = match.group("cid")
                # print(cid, cid in self.hby.kevers)
                if cid in self.hby.kevers:
                    obr.cid = match.group("cid")
                    self.request(wurl, obr)
            else:
                logging.error(f"wurl {wurl} is not a valid well known OOBI for multi-factor auth")
                self.hby.db.woobi.rem(keys=(wurl,))

    def processMultiFactorAuth(self):
        """ Process Client responses by parsing the messages and removing the client

        """
        for (wurl,), obr in self.hby.db.mfa.getItemIter():
            if wurl not in self.clients:
                self.request(wurl, obr)
                continue

            client = self.clients[wurl]
            if client.responses:
                response = client.responses.popleft()

                if 200 >= response["status"] <= 399:
                    print(wurl, "succeeded")
                    self.addAuthToAid(obr.cid, wurl)
                    state = Result.resolved
                else:
                    state = Result.failed

                obr.state = state
                self.clienter.remove(client)
                self.hby.db.mfa.rem(keys=(wurl,))
                self.hby.db.rmfa.pin(keys=(wurl,), val=obr)
