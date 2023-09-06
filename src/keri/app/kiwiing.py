# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json

import falcon
from falcon import media
from hio.base import doing
from hio.core import http
from hio.help import decking

import keri.app.oobiing
from . import grouping, challenging, notifying, signaling, oobiing
from .. import help
from ..app import specing, storing, indirecting, httping, habbing, delegating, booting
from ..core import coring
from ..peer import exchanging
from ..vc import protocoling
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


class AeidEnd:
    """
    aeid (str): qb64 of non-transferable identifier prefix for authentication and encryption of
                secrets in keeper.
    """

    def __init__(self, hby):
        """ Initialize endpoint for updating the passcode (AEID) for this Habery

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
        summary:  Update the passcode (AEID) used to decrypt and unlock the local keystore
        description:  Update the passcode (AEID) used to decrypt and unlock the local keystore
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

    aeidEnd = AeidEnd(hby=hby)
    app.add_route("/codes", aeidEnd)

    signalEnd = signaling.loadEnds(app, signals=signaler.signals)
    resources = [signalEnd, lockEnd, aeidEnd]

    app.add_route("/spec.yaml", specing.SpecResource(app=app, title='KERI Interactive Web Interface API',
                                                     resources=resources))
    return [lockEnd]


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

    exchanger = exchanging.Exchanger(hby=hby, handlers=handlers)
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
