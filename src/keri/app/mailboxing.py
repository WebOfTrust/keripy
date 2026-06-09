# -*- encoding: utf-8 -*-
"""
KERI
keri.app.mailboxing module

Mailbox host support classes and helpers.

Maintainer notes:
    This module factors the mailbox-host-specific composition out of
    ``indirecting``.  The mailbox host is still built from the normal KERIpy
    parser / kevery / revery / exchanger stack, but it differs from witness
    hosting in two important ways:

    1. forwarded mailbox storage is explicitly gated by mailbox authorization
       state through ``AuthorizedForwardHandler``; witness hosting used to carry
       that trust boundary implicitly.
    2. mailbox query service depends on shared runtime cues.  ``MailboxStart``
       must drain the same cue deck used by ``Kevery`` / ``Revery`` so ``mbx``
       queries can surface ``stream`` cues to the SSE layer.
"""
import json
import platform
from urllib.parse import urlparse

import falcon

from hio.base import doing
from hio.core import http
from hio.help import decking

from ..kering import Vrsn_1_0, Roles, Ilks, Schemes
from ..core import Kevery, parsing, routing, serdering
from ..end import loadEnds as loadEndingEnds
from ..peer import Exchanger

from .forwarding import AuthorizedForwardHandler
from .storing import Mailboxer, Respondant


def _mediaType(contentType):
    """Return one normalized media type without content-type parameters."""
    return (contentType or "").split(";", 1)[0].strip().lower()


def _readMultipart(req):
    """Read the legacy mailbox-admin multipart envelope.

    KERIpy intentionally keeps mailbox add/remove conservative: this endpoint
    accepts the existing ``multipart/form-data`` wrapper with explicit
    ``kel``, optional ``delkel``, and ``rpy`` fields instead of reparsing a raw
    multi-message CESR body just to rediscover the terminal reply.
    """
    if _mediaType(req.content_type) != "multipart/form-data":
        raise falcon.HTTPError(falcon.HTTP_NOT_ACCEPTABLE,
                               title="Content type error",
                               description="Unacceptable content type.")

    form = req.get_media()
    parts = {}
    for part in form:
        if part.name is None:
            continue
        parts[part.name] = part.text

    kel = parts.get("kel")
    delkel = parts.get("delkel")
    rpy = parts.get("rpy")
    if not kel:
        raise falcon.HTTPBadRequest(description="Mailbox authorization request is missing kel")
    if not rpy:
        raise falcon.HTTPBadRequest(description="Mailbox authorization request is missing rpy")

    return dict(kel=kel, delkel=delkel, rpy=rpy)


def _assembleStream(parts):
    """Assemble multipart mailbox-admin fields into one ingestible CESR stream.

    The multipart wrapper is only the HTTP envelope.  Runtime validation and
    acceptance still happen by ingesting one combined CESR stream through the
    normal parser / reply pipeline.
    """
    raw = bytearray(parts["kel"].encode("utf-8"))
    if parts.get("delkel"):
        raw.extend(parts["delkel"].encode("utf-8"))
    raw.extend(parts["rpy"].encode("utf-8"))
    return bytes(raw)


def _parseReply(raw):
    """Parse the explicit multipart ``rpy`` field as one KERI reply message."""
    try:
        return serdering.SerderKERI(raw=raw)
    except Exception as ex:
        raise falcon.HTTPBadRequest(description=f"invalid mailbox authorization reply: {ex}")


def _validateReply(serder, mailboxAid):
    """Validate the mailbox authorization reply before full-stream ingest.

    This is request-shape validation, not acceptance.  Acceptance is determined
    only after the assembled CESR stream has been ingested and the resulting
    ``ends.`` state for the hosted mailbox matches the requested add/remove
    outcome.
    """
    if serder.ilk != Ilks.rpy:
        raise falcon.HTTPBadRequest(description="Mailbox authorization reply must be rpy")

    route = serder.ked.get("r", "")
    if route not in ("/end/role/add", "/end/role/cut"):
        raise falcon.HTTPBadRequest(description="Unsupported mailbox authorization route")

    data = serder.ked.get("a", {})
    cid = data.get("cid")
    role = data.get("role")
    eid = data.get("eid")

    if not cid or not role or not eid:
        raise falcon.HTTPBadRequest(description="Mailbox authorization reply is missing cid/role/eid")
    if role != Roles.mailbox:
        raise falcon.HTTPBadRequest(description="Mailbox authorization reply must use role=mailbox")
    if eid != mailboxAid:
        raise falcon.HTTPForbidden(description="Mailbox authorization target does not match hosted mailbox")

    return cid, role, route == "/end/role/add"


def _confirmRoleAuth(hby, cid, mailboxAid, expected):
    """Confirm post-ingest mailbox authorization state in ``ends.``.

    This is the authoritative acceptance check for mailbox add/remove.  The
    signed reply alone is not enough; the reply must survive normal KERI
    processing and leave the hosted mailbox authorization record in the
    expected state.
    """
    end = hby.db.ends.get(keys=(cid, Roles.mailbox, mailboxAid))
    accepted = bool(end and (end.allowed if expected else not end.allowed))
    if not accepted:
        raise falcon.HTTPForbidden(description="Mailbox authorization reply was not accepted")


def _ingestCesr(raw, *, kvy, rvy, exc, tvy=None):
    """Synchronously ingest CESR bytes through the KERIpy runtime stack."""
    parser = parsing.Parser(
        framed=True,
        kvy=kvy,
        tvy=tvy,
        exc=exc,
        rvy=rvy,
        version=Vrsn_1_0,
    )
    parser.parse(ims=bytearray(raw), local=False)
    kvy.processEscrows()
    rvy.processEscrowReply()
    if tvy is not None:
        tvy.processEscrows()
    if exc is not None:
        exc.processEscrow()


def _mailboxAdminPath(hab):
    """Return the served mailbox-admin route for one hosted mailbox habitat.

    The route follows the historical KERIpy mailbox-admin convention: append
    ``/mailboxes`` relative to the stored mailbox endpoint URL path.

    This helper is intentionally strict:
        - mailbox admin routing must come from the loaded self ``/loc/scheme``
        - this path-relative rule applies only to mailbox admin, not to every
          other mailbox-host surface
    """
    urls = hab.fetchUrls(eid=hab.pre, scheme=Schemes.https) or hab.fetchUrls(
        eid=hab.pre,
        scheme=Schemes.http,
    )
    if not urls:
        raise ValueError("mailbox admin requires a loaded self HTTP(S) location record")

    url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
    path = urlparse(url).path.rstrip("/")
    return f"{path}/mailboxes"


def _roleEnabled(hby, cid, role, eid):
    """Return True when one endpoint role record is active for startup use."""
    end = hby.db.ends.get(keys=(cid, role, eid))
    return bool(end and (end.allowed or end.enabled))


def _requireMailboxIdentity(hby, hab):
    """Require authoritative self mailbox identity state before host startup.

    Boot-time invariant:
        - the hosted non-transferable mailbox AID must already advertise at
          least one self HTTP(S) location
        - it must already authorize itself as both controller and mailbox

    This prevents the mailbox host from booting with an invented admin route or
    an incomplete self-description. Mailbox start is responsible for creating
    or reconciling this accepted self state before hosting begins; startup here
    still refuses to serve if that reconciliation did not actually land in the
    local database.
    """
    urls = hab.fetchUrls(eid=hab.pre, scheme=Schemes.https) or hab.fetchUrls(
        eid=hab.pre,
        scheme=Schemes.http,
    )
    if not urls:
        raise ValueError("mailbox host startup requires a loaded self HTTP(S) location record")
    if not _roleEnabled(hby, hab.pre, Roles.controller, hab.pre):
        raise ValueError("mailbox host startup requires self controller authorization state")
    if not _roleEnabled(hby, hab.pre, Roles.mailbox, hab.pre):
        raise ValueError("mailbox host startup requires self mailbox authorization state")


def setupMailbox(hby, alias="mailbox", mbx=None, aids=None, httpPort=5632,
                 keypath=None, certpath=None, cafilepath=None):
    """Set up one mailbox host around an existing local habitat.

    Composition:
        - one non-transferable local habitat provides the hosted mailbox AID
        - ``AuthorizedForwardHandler`` gates ``/fwd`` storage by mailbox authz
        - ``Respondant`` owns reply emission for non-stream cues
        - ``MailboxStart`` runs parser ingress, escrow replay, and cue routing
        - mailbox admin is served at ``<stored-mailbox-url-path>/mailboxes``

    Because mailbox hosting here is separate from witness hosting, ``/fwd``
    storage is gated through ``AuthorizedForwardHandler`` so the host stores
    traffic only for recipients that currently authorize the hosted mailbox
    AID. Only mailbox admin follows the stored location URL path in this
    module; served OOBIs still come from ``loadEndingEnds(...)`` at their
    normal root routes.
    """
    from .indirecting import createHttpServer, HttpEnd

    host = "0.0.0.0"
    if platform.system() == "Windows":
        host = "127.0.0.1"

    cues = decking.Deck()
    doers = []

    hab = hby.habByName(name=alias)
    if hab is None:
        raise ValueError(f"missing local mailbox alias {alias!r}")
    if hab.kever.prefixer.transferable:
        raise ValueError("mailbox host requires a non-transferable identifier")
    _requireMailboxIdentity(hby, hab)

    mbx = mbx if mbx is not None else Mailboxer(name=alias, temp=hby.temp)
    forwarder = AuthorizedForwardHandler(hby=hby, mbx=mbx, mailboxAid=hab.pre)
    exchanger = Exchanger(hby=hby, handlers=[forwarder])
    rep = Respondant(hby=hby, mbx=mbx, aids=aids)

    rvy = routing.Revery(db=hby.db, cues=cues)
    kvy = Kevery(db=hby.db,
                 lax=True,
                 local=False,
                 rvy=rvy,
                 cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)

    parser = parsing.Parser(framed=True,
                            kvy=kvy,
                            exc=exchanger,
                            rvy=rvy,
                            version=Vrsn_1_0)

    app = falcon.App(cors_enable=True)
    loadEndingEnds(app=app, hby=hby, default=hab.pre)

    httpEnd = HttpEnd(rxbs=parser.ims, mbx=mbx)
    app.add_route("/", httpEnd)
    app.add_route("/health", HealthEnd())
    app.add_route(_mailboxAdminPath(hab),
                  MailboxAddRemoveEnd(hby=hby, hab=hab, kvy=kvy, rvy=rvy, exc=exchanger))

    server = createHttpServer(host, httpPort, app, keypath, certpath, cafilepath)
    if not server.reopen():
        raise RuntimeError(f"cannot create http server on port {httpPort}")
    httpServerDoer = http.ServerDoer(server=server)

    mailboxStart = MailboxStart(hab=hab,
                                parser=parser,
                                kvy=kvy,
                                rvy=rvy,
                                exc=exchanger,
                                cues=cues,
                                replies=rep.reps,
                                responses=rep.cues,
                                queries=httpEnd.qrycues)

    doers.extend([httpServerDoer, rep, mailboxStart])
    return doers


class MailboxStart(doing.DoDoer):
    """Long-lived mailbox host doer built from the normal KERIpy runtime stack.

    Responsibilities:
        - drain CESR ingress already appended to the shared parser buffer
        - replay KEL / reply / exchange escrows
        - split runtime cues between mailbox-query streaming and normal reply
          handling

    ``self.cues`` must be the same shared deck passed to ``Kevery`` / ``Revery``.
    If that wiring is broken, mailbox storage will function while ``mbx`` query
    streaming silently stops working.
    """

    def __init__(self, hab, parser, kvy, rvy, exc, cues=None, replies=None, responses=None, queries=None, **opts):
        self.hab = hab
        self.parser = parser
        self.kvy = kvy
        self.rvy = rvy
        self.exc = exc
        self.queries = queries if queries is not None else decking.Deck()
        self.replies = replies if replies is not None else decking.Deck()
        self.responses = responses if responses is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [
            doing.doify(self.start),
            doing.doify(self.msgDo),
            doing.doify(self.escrowDo),
            doing.doify(self.cueDo),
        ]
        super(MailboxStart, self).__init__(doers=doers, **opts)

    def start(self, tymth=None, tock=0.0, **kwa):
        """Wait for habitat initialization, then announce the hosted mailbox AID."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.hab.inited:
            yield self.tock

        print("Mailbox", self.hab.name, ":", self.hab.pre)

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """Continuously parse CESR ingress appended by ``HttpEnd``."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        done = yield from self.parser.parsator(local=True)
        return done

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Continuously replay the same escrows used by witness hosting."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.kvy.processEscrows()
            self.rvy.processEscrowReply()
            self.exc.processEscrow()
            yield

    def cueDo(self, tymth=None, tock=0.0, **kwa):
        """Route shared runtime cues to the correct mailbox-host consumer.

        ``stream`` cues are mailbox-query service signals and must go to the
        HTTP query iterable.  Everything else stays on the normal ``Respondant``
        path.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.cues:
                cue = self.cues.pull()
                cueKin = cue["kin"]
                if cueKin == "stream":
                    self.queries.append(cue)
                else:
                    self.responses.append(cue)
                yield self.tock
            yield self.tock


class HealthEnd:
    """Simple liveness/readiness endpoint for long-lived mailbox hosts."""

    def on_get(self, req, rep):
        """Report basic process liveness for harnesses and operators."""
        rep.status = falcon.HTTP_200
        rep.content_type = "text/plain"
        rep.text = "ok"


class MailboxAddRemoveEnd:
    """Handle mailbox add/remove authorization requests for one hosted mailbox AID.

    This is an admin-ingest endpoint, not a peer protocol.  It accepts the
    controller KEL plus the signed mailbox ``/end/role/add`` or
    ``/end/role/cut`` reply, ingests that material through the normal KERI
    processing stack, and then verifies that accepted ``ends.`` state for the
    hosted mailbox AID matches the requested add/remove outcome.
    """

    def __init__(self, hby, hab, kvy, rvy, exc):
        self.hby = hby
        self.hab = hab
        self.kvy = kvy
        self.rvy = rvy
        self.exc = exc

    def on_post(self, req, rep):
        """Accept one mailbox add/remove authorization request.

        Parameters:
            req (falcon.Request): ``multipart/form-data`` request carrying
                mailbox admin fields.
            rep (falcon.Response): response populated with either a 200 JSON
                confirmation or an HTTP error.

        Expected multipart fields:
            ``kel``:
                controller KEL replay
            ``delkel``:
                optional delegation replay
            ``rpy``:
                terminal signed mailbox authorization reply

        Expected ``rpy`` message shape:
            ilk: ``rpy``
            route: ``/end/role/add`` or ``/end/role/cut``
            payload ``a.cid``: controller AID granting or removing mailbox role
            payload ``a.role``: must be ``mailbox``
            payload ``a.eid``: must be this hosted mailbox AID

        Processing rule:
            - read the explicit multipart ``rpy`` field
            - assemble ``kel`` + optional ``delkel`` + ``rpy`` into one CESR stream
            - ingest that stream through the normal parser / reply pipeline
            - confirm that accepted ``ends.`` state for
              ``(cid, Roles.mailbox, self.hab.pre)`` matches the requested
              add/remove outcome

        Maintainer note:
            The explicit multipart ``rpy`` field is validated before ingest so
            request-shape errors return clear HTTP failures.  Final acceptance
            still depends on full-stream ingest plus the resulting ``ends.``
            state.
        """
        parts = _readMultipart(req)
        raw = _assembleStream(parts)
        serder = _parseReply(parts["rpy"].encode("utf-8"))
        cid, role, expected = _validateReply(serder, self.hab.pre)
        _ingestCesr(raw, kvy=self.kvy, rvy=self.rvy, exc=self.exc)
        _confirmRoleAuth(self.hby, cid, self.hab.pre, expected)

        rep.status = falcon.HTTP_200
        rep.content_type = "application/json"
        rep.text = json.dumps({
            "cid": cid,
            "role": role,
            "eid": self.hab.pre,
            "allowed": expected,
        })
