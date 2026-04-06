# -*- encoding: utf-8 -*-
"""
keri.app.oobiing module

Provides OOBI (Out-Of-Band Introduction) endpoint resources, handlers,
and resolution workflows for discovering and verifying remote identifiers.
"""
import datetime
import json
import logging
from collections import namedtuple
from urllib import parse
from urllib.parse import urlparse

import falcon
from hio.base import doing
from hio.help import decking, ogler

from .httping import Clienter, CESR_CONTENT_TYPE
from .organizing import Organizer
from .. import (Vrsn_1_0, Roles, Schemes, Ilks,
                ValidationError, UnverifiedReplyError,
                ConfigurationError)
from ..help import nowIso8601, fromIso8601, toIso8601, nowUTC
from ..core import (Prefixer, Router, Revery, Kevery,
                    Parser, Schemer, SerderKERI)
from ..end import OOBI_RE, DOOBI_RE, WOOBI_RE, OOBI_AID_HEADER
from ..peer import exchange
from ..recording import OobiRecord, WellKnownAuthN

logger = ogler.getLogger()

Resultage = namedtuple("Resultage", 'resolved failed')  # stream cold start status
Result = Resultage(resolved='resolved', failed='failed')


def loadEnds(app, *, hby, prefix=""):
    """Register OOBI HTTP endpoints on the Falcon application.

    Parameters:
        app (falcon.App): Falcon WSGI application instance.
        hby (Habery): Identifier database environment.
        prefix (str): Route prefix for mounting endpoints.

    Returns:
        list: Empty list (no doers registered).
    """
    oobiEnd = OobiResource(hby=hby)
    app.add_route(prefix + "/oobi", oobiEnd)
    return []


def loadHandlers(hby, exc, notifier):
    """Load handlers for the peer-to-peer delegation protocols

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Outbound notifications
    """
    oobireq = OobiRequestHandler(hby=hby, notifier=notifier)
    exc.addHandler(oobireq)


class OobiResource:
    """Falcon resource for managing OOBI generation and resolution."""

    def __init__(self, hby):
        """Initialize OOBI resource endpoints.

        Parameters:
            hby (Habery): Identifier database environment.
        """
        self.hby = hby

    def on_get_alias(self, req, rep, alias=None):
        """Handle GET requests to generate OOBIs for an identifier.

        Parameters:
            req (falcon.Request): HTTP request object.
            rep (falcon.Response): HTTP response object.
            alias (str): Human-readable alias of the identifier.

        Query Parameters:
            role (str): Role for which to generate OOBIs. Supported values
                include witness and controller.

        Behavior:
            - Resolves the identifier associated with the alias.
            - Generates OOBI URLs for the requested role.
            - Returns URLs for witnesses or controller endpoints.

        Responses:
            200: JSON object containing generated OOBIs.
            400: Invalid alias.
            404: Missing endpoints or unsupported role.
        """

        hab = self.hby.habByName(alias)
        if hab is None:
            rep.status = falcon.HTTP_400
            rep.text = "Invalid alias to generate OOBI"
            return

        role = req.params["role"]

        res = dict(role=role)
        if role in (Roles.witness,):  # Fetch URL OOBIs for all witnesses
            oobis = []
            for wit in hab.kever.wits:
                urls = hab.fetchUrls(eid=wit, scheme=Schemes.http) \
                       or hab.fetchUrls(eid=wit, scheme=Schemes.https)
                if not urls:
                    rep.status = falcon.HTTP_404
                    rep.text = f"unable to query witness {wit}, no http endpoint"
                    return

                url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
                oobis.append(f"{url.rstrip("/")}/oobi/{hab.pre}/witness/{wit}")
            res["oobis"] = oobis
        elif role in (Roles.controller,):  # Fetch any controller URL OOBIs
            oobis = []
            urls = hab.fetchUrls(eid=hab.pre, scheme=Schemes.https) or hab.fetchUrls(eid=hab.pre,
                                                                                           scheme=Schemes.http)
            if not urls:
                rep.status = falcon.HTTP_404
                rep.text = f"unable to query controller {hab.pre}, no http endpoint"
                return
            url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
            oobis.append(f"{url.rstrip("/")}/oobi/{hab.pre}/controller")
            res["oobis"] = oobis
        else:
            rep.status = falcon.HTTP_404
            return

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.data = json.dumps(res).encode("utf-8")

    def on_post(self, req, rep):
        """Handle POST requests to resolve an OOBI.

        Parameters:
            req (falcon.Request): HTTP request object.
            rep (falcon.Response): HTTP response object.

        Request Body:
            application/json:
                url (str): OOBI URL to resolve.
                rpy (dict): Unsigned KERI reply message (not implemented).
                oobialias (str): Alias to assign to resolved identifier.

        Behavior:
            - Stores OOBI URL for asynchronous resolution.
            - Optionally associates an alias with the resolved identifier.

        Responses:
            202: OOBI accepted for processing.
            400: Invalid request body.
            501: `rpy` support not implemented.
        """
        body = req.get_media()

        if "url" in body:
            oobi = body["url"]

            obr = OobiRecord(date=nowIso8601())
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
    """Handler for processing OOBI request EXN messages."""
    resource = "/oobis"

    def __init__(self, hby, notifier):
        """Initialize OOBI request handler.

        Parameters:
            hby (Habery): Identifier database environment.
            notifier (Notifier): Notification dispatcher for outbound events.
        """
        self.hby = hby
        self.notifier = notifier

    def handle(self, serder, attachments=None):
        """Process an incoming OOBI request EXN message.

        Parameters:
            serder (Serder): Serialized EXN message.
            attachments (list): CESR attachments associated with the message.

        Behavior:
            - Extracts OOBI URL from the message payload.
            - Stores the OOBI for later resolution.
            - Emits a notification for UI or downstream processing.

        Notes:
            Invalid messages missing an ``oobi`` field are ignored.
        """
        src = serder.pre
        pay = serder.ked['a']
        if "oobi" not in pay:
            print(f"invalid oobi message, missing oobi.  evt={serder.ked}")
            return
        oobi = pay["oobi"]

        obr = OobiRecord(date=nowIso8601())
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
    """Create an EXN message requesting OOBI resolution.

    Parameters:
        hab (Hab): Local habitat initiating the request.
        dest (str): Recipient identifier prefix.
        oobi (str): OOBI URL.

    Returns:
        tuple:
            - Serder: Constructed EXN message.
            - bytearray: Attachments for transmission.

    Behavior:
        - Constructs a peer-to-peer EXN message.
        - Endorses the message for sending.
    """
    data = dict(
        dest=dest,
        oobi=oobi
    )

    # Create `exn` peer to peer message to notify other participants UI
    exn, _ = exchange(route=OobiRequestHandler.resource, modifiers=dict(),
                                 payload=data, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]

    return exn, ims


class Oobiery:
    """Resolver and processor for OOBIs.

    Coordinates retrieval, parsing, verification, and persistence
    of OOBI data from remote endpoints.
    """

    RetryDelay = 30

    def __init__(self, hby, rvy=None, clienter=None, cues=None):
        """Initialize OOBI resolver.

        Parameters:
            hby (Habery): Identifier database environment.
            rvy (Revery): Reply verifier for processing `rpy` messages.
            clienter (Clienter): HTTP client manager.
            cues (decking.Deck): Output queue for resolution events.

        Behavior:
            - Sets up HTTP client handling.
            - Initializes parser for CESR and KERI message streams.
            - Registers reply routes if a verifier is provided.
        """

        self.hby = hby
        self.rvy = rvy
        if self.rvy is not None:
            self.registerReplyRoutes(self.rvy.rtr)

        self.clienter = clienter or Clienter()
        self.org = Organizer(hby=self.hby)

        # Set up a local parser for returned events from OOBI queries.
        rtr = Router()
        rvy = Revery(db=self.hby.db, rtr=rtr)
        kvy = Kevery(db=self.hby.db, lax=True, local=False, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        self.parser = Parser(framed=True, kvy=kvy, rvy=rvy, version=Vrsn_1_0)

        self.cues = cues if cues is not None else decking.Deck()
        self.clients = dict()
        self.doers = [self.clienter, doing.doify(self.scoobiDo)]

    def registerReplyRoutes(self, router):
        """Register reply routes for OOBI-related messages.

        Parameters:
            router (Router): Reply message router.

        Behavior:
            Adds support for processing ``/introduce`` reply messages.
        """
        router.addRoute("/introduce", self)

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None, **kwargs):
        """Process a reply message for OOBI introduction.

        Parameters:
            serder (SerderKERI): Parsed reply message.
            diger (Diger): Digest of the message.
            route (str): Reply route (must be ``/introduce``).
            cigars (list): Non-transferable signature attachments.
            tsgs (list): Transferable signature groups.

        Raises:
            ValidationError: Invalid route or missing required fields.
            ConfigurationError: Resolver not configured for reply handling.
            UnverifiedReplyError: Reply signature verification failed.

        Behavior:
            - Validates message structure and required fields.
            - Verifies signatures using the reply verifier.
            - Stores OOBI record if verification succeeds.

        Reply Message::

            .. code-block:: json

                {
                "v" : "KERI10JSON00011c_",
                "t" : "rpy",
                "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
                "dt": "2020-08-22T17:50:12.988921+00:00",
                "r" : "/introduce",
                "a" :
                {
                    "cid": "ENcOes8_t2C7tck4X4j61fSm0sWkLbZrEZffq7mSn8On",
                    "oobi":  "http://localhost:5632/oobi/ENcOes8_t2C7tck4X4j61fSm0sWkLbZrEZffq7mSn8On/witness"
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

        cider = Prefixer(qb64=data["cid"])  # raises error if unsupported code
        cid = cider.qb64  # controller authorizing eid at role
        aid = cid  # authorizing attribution id

        oobi = data["oobi"]
        url = urlparse(oobi)
        if url.scheme not in ("http", "https"):
            raise ValidationError(f"Invalid url scheme for introduced OOBI scheme={url.scheme}")

        if self.rvy is None:
            raise ConfigurationError("this oobiery is not configured to handle rpy introductions")

        # Process BADA RUN but with no previous reply message, always process introductions
        accepted = self.rvy.acceptReply(serder=serder, saider=diger, route=route,
                                        aid=aid, osaider=None, cigars=cigars,
                                        tsgs=tsgs)
        if not accepted:
            raise UnverifiedReplyError(f"Unverified introduction reply. {serder.ked}")

        obr = OobiRecord(cid=cid, date=dt)
        self.hby.db.oobis.put(keys=(oobi,), val=obr)

    def scoobiDo(self, tymth=None, tock=0.0, **kwa):
        """Generator for periodic OOBI processing.

        Parameters:
            tymth (Callable): Time function from scheduler.
            tock (float): Scheduling interval.

        Yields:
            float: Next scheduling interval.

        Behavior:
            Continuously processes OOBI workflows.
        """
        _ = (yield tock)

        while True:
            self.processFlows()
            yield tock

    def processFlows(self):
        """Execute all OOBI processing stages.

        Stages include:
            - OOBI discovery
            - Client response handling
            - Retry scheduling
            - Multi-OOBI resolution
        """
        self.processOobis()
        self.processClients()
        self.processRetries()
        self.processMOOBIs()

    def processOobis(self):
        """Process pending OOBI records for discovery.

        Behavior:
            - Iterates over stored OOBIs.
            - Determines type (standard, data, well-known).
            - Initiates HTTP requests for resolution.

        Notes:
            Acts as the primary escrow processor for OOBI records.
        """
        for (url,), obr in self.hby.db.oobis.getTopItemIter():
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

                elif (match := WOOBI_RE.match(purl.path)) is not None:  # Well Known
                    obr.cid = match.group("cid")
                    params = parse.parse_qs(purl.query)

                    # If name is hinted in query string, use it as alias if not provided in OOBIRecord
                    if "name" in params and obr.oobialias is None:
                        obr.oobialias = params["name"][0]

                    self.request(url, obr)

            except ValueError as ex:
                print(f"error requesting invalid OOBI URL {ex}", url)

    def processClients(self):
        """Process HTTP client responses for OOBI requests.

        Behavior:
            - Parses responses based on content type.
            - Handles CESR streams, schema responses, and JSON replies.
            - Updates resolution state and persists results.
        """
        for (url,), obr in self.hby.db.coobi.getTopItemIter():
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

                elif response["headers"]["Content-Type"] in (
                    CESR_CONTENT_TYPE,
                    "application/json+cesr",
                    "application/cesr+json",
                ):  # CESR Stream response to OOBI (canonical + legacy variants)
                    self.parser.parse(ims=bytearray(response["body"]))
                    if OOBI_AID_HEADER in response["headers"]:
                        obr.cid = response["headers"][OOBI_AID_HEADER]

                    if obr.oobialias is not None and obr.cid:
                        self.org.update(pre=obr.cid, data=dict(alias=obr.oobialias, oobi=url))

                    self.hby.db.coobi.rem(keys=(url,))
                    obr.state = Result.resolved
                    self.hby.db.roobi.put(keys=(url,), val=obr)

                elif response["headers"]["Content-Type"] == "application/schema+json":  # Schema response to data OOBI
                    try:
                        schemer = Schemer(raw=bytearray(response["body"]))
                        if schemer.said == obr.said:
                            self.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
                            result = Result.resolved
                        else:
                            result = Result.failed

                    except (ValidationError, ValueError):
                        result = Result.failed

                    obr.state = result
                    self.hby.db.coobi.rem(keys=(url,))
                    self.hby.db.roobi.put(keys=(url,), val=obr)

                elif response["headers"]["Content-Type"].startswith("application/json"):  # Unsigned rpy OOBI or Schema

                    try:
                        schemer = Schemer(raw=bytearray(response["body"]))
                        if schemer.said == obr.said:
                            self.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
                            result = Result.resolved
                        else:
                            result = Result.failed

                        obr.state = result
                        self.hby.db.coobi.rem(keys=(url,))
                        self.hby.db.roobi.put(keys=(url,), val=obr)
                        continue

                    except (ValidationError, ValueError):
                        pass

                    try:
                        serder = SerderKERI(raw=bytearray(response["body"]))
                    except ValueError:
                        obr.state = Result.failed
                        self.hby.db.coobi.rem(keys=(url,))
                        self.hby.db.roobi.put(keys=(url,), val=obr)
                        continue
                    if not serder.ked['t'] == Ilks.rpy:
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
        """Process multi-OOBI (MOOBI) resolution results.

        Behavior:
            - Aggregates results from multiple OOBI URLs.
            - Marks overall resolution state when complete.
        """
        for (url,), obr in self.hby.db.moobi.getTopItemIter():
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
        """Retry failed OOBI resolutions after delay.

        Behavior:
            - Moves expired retry records back into active processing.
        """
        for (url,), obr in self.hby.db.eoobi.getTopItemIter():
            last = fromIso8601(obr.date)
            now = nowUTC()
            if (now - last) > datetime.timedelta(seconds=self.RetryDelay):
                obr.date = toIso8601(now)
                self.hby.db.eoobi.rem(keys=(url,))
                self.hby.db.oobis.pin(keys=(url,), val=obr)

    def request(self, url, obr):
        """Initiate HTTP request for an OOBI.

        Parameters:
            url (str): OOBI URL.
            obr (OobiRecord): Associated OOBI record.

        Behavior:
            - Creates HTTP client request.
            - Moves record into client-processing escrow.
        """
        client = self.clienter.request("GET", url=url)
        if client is None:
            self.hby.db.oobis.rem(keys=(url,))
            print(f"error getting client for {url}, aborting OOBI")
            return

        self.clients[url] = client
        self.hby.db.oobis.rem(keys=(url,))
        self.hby.db.coobi.pin(keys=(url,), val=obr)

    def processMultiOobiRpy(self, url, serder, mobr):
        """Process multi-OOBI reply message.

        Parameters:
            url (str): Source OOBI URL.
            serder (SerderKERI): Parsed reply message.
            mobr (OobiRecord): Multi-OOBI record.

        Returns:
            str: Resolution result state.

        Behavior:
            - Validates identifier consistency.
            - Expands into multiple OOBI requests.
        """
        data = serder.ked["a"]
        cid = data["aid"]

        if cid != mobr.cid:
            return Result.failed

        urls = data["urls"]
        mobr.urls = urls

        for murl in urls:
            obr = OobiRecord(date=nowIso8601())
            obr.oobialias = mobr.oobialias
            obr.cid = mobr.cid
            self.hby.db.oobis.put(keys=(murl,), val=obr)

        self.hby.db.coobi.rem(keys=(url,))
        self.hby.db.moobi.put(keys=(url,), val=mobr)


class Authenticator:
    """Handler for well-known OOBI-based authentication workflows."""

    def __init__(self, hby, clienter=None):
        """Initialize authenticator.

        Parameters:
            hby (Habery): Identifier database environment.
            clienter (Clienter): HTTP client manager.
        """
        self.hby = hby
        self.clienter = clienter if clienter is not None else Clienter()
        self.clients = dict()
        self.doers = [self.clienter, doing.doify(self.authzDo)]

    def request(self, wurl, obr):
        """Initiate request for well-known OOBI authentication.

        Parameters:
            wurl (str): Well-known OOBI URL.
            obr (OobiRecord): Associated record.
        """
        client = self.clienter.request("GET", wurl)

        self.clients[wurl] = client
        self.hby.db.woobi.rem(keys=(wurl,))
        self.hby.db.mfa.pin(keys=(wurl,), val=obr)

    def addAuthToAid(self, cid, url):
        """Associate authentication URL with an identifier.

        Parameters:
            cid (str): Controller identifier prefix.
            url (str): Authentication endpoint URL.
        """
        now = nowIso8601()
        wkan = WellKnownAuthN(url=url, dt=now)
        self.hby.db.wkas.add(keys=(cid,), val=wkan)

    def authzDo(self, tymth=None, tock=0.0, **kwa):
        """Generator for authentication processing loop.

        Parameters:
            tymth (Callable): Time function from scheduler.
            tock (float): Scheduling interval.

        Yields:
            float: Next scheduling interval.
        """
        _ = (yield tock)

        while True:
            self.processFlows()
            yield tock

    def processFlows(self):
        """Process well-known authentication URLs """

        self.processWoobis()
        self.processMultiFactorAuth()

    def processWoobis(self):
        """Process well-known OOBI records for authentication.

        Behavior:
            - Filters valid well-known OOBIs.
            - Initiates authentication requests for known identifiers.
        """
        for (wurl,), obr in self.hby.db.woobi.getTopItemIter():
            # Find any woobis that match and can be used to perform MFA for this resolved AID
            purl = urlparse(wurl)
            if (match := WOOBI_RE.match(purl.path)) is not None:
                cid = match.group("cid")
                # print(cid, cid in self.hby.kevers)
                if cid in self.hby.kevers:
                    obr.cid = match.group("cid")
                    self.request(wurl, obr)
            else:
                logging.error(f"wurl {wurl} is not a valid well known OOBI for multi-factor auth")
                self.hby.db.woobi.rem(keys=(wurl,))

    def processMultiFactorAuth(self):
        """Processes responses for multi-factor authentication requests.

        Iterates through pending MFA items, matches them with client responses,
        and updates the database state based on the HTTP status code.

        Note:
            This method modifies the internal `hby.db` and `clients` collection.
        """
        for (wurl,), obr in self.hby.db.mfa.getTopItemIter():
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
