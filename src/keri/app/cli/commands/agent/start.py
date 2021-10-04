# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse
import logging
import os
import sys

import falcon
from hio.base import doing
from hio.core import http
from hio.core.tcp import serving as tcpServing
from hio.help import decking

from keri import help
from keri import kering
from keri.app import directing, agenting, indirecting, storing, grouping
from keri.app.cli.common import existing
from keri.core import scheming, coring
from keri.peer import exchanging
from keri.vc import walleting, handling, proving
from keri.vdr import verifying, viring


WEB_DIR_PATH = os.path.dirname(
                os.path.abspath(
                    sys.modules.get(__name__).__file__))
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')


d = "Runs KERI Agent controller.\n"
d += "Example:\nagent -t 5621\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument('-T', '--tcp',
                    action='store',
                    default=5621,
                    help="Local port number the HTTP server listens on. Default is 5621.")
parser.add_argument('-a', '--admin-http-port',
                    action='store',
                    default=5623,
                    help="Admin port number the HTTP server listens on. Default is 5623.")
parser.add_argument('-n', '--name',
                    action='store',
                    default="agent",
                    help="Name of controller. Default is agent.")
parser.add_argument('-c', '--controller',
                    action='store',
                    default=None,
                    help="Identifier prefix to accept control messages from.")
parser.add_argument("-I", '--insecure',
                    action='store_true',
                    help="Run admin HTTP server without checking signatures on controlling requests")
parser.add_argument("-p", "--path",
                    action="store",
                    default=STATIC_DIR_PATH,
                    help="Location of the KIWI app bundle for this agent")


def launch(args):
    help.ogler.level = logging.CRITICAL
    help.ogler.reopen(name="keri", temp=True, clear=True)
    logger = help.ogler.getLogger()

    logger.info("\n******* Starting Agent for %s listening: http/%s, tcp/%s "
                ".******\n\n", args.name, args.admin_http_port, args.tcp)
    print("Starting agent", args.name)
    doers = runAgent(controller=args.controller, name=args.name, insecure=args.insecure,
                     tcp=int(args.tcp),
                     adminHttpPort=int(args.admin_http_port), path=args.path)
    try:
        tock = 0.03125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except kering.ConfigurationError:
        print(f"prefix for {args.name} does not exist, incept must be run first", )


    logger.info("\n******* Ended Agent for %s listening: http/%s, tcp/%s"
                ".******\n\n", args.name, args.admin_http_port, args.tcp)


def runAgent(controller, name="agent", insecure=False, tcp=5621, adminHttpPort=5623, path=STATIC_DIR_PATH):
    """
    Setup and run one agent
    """

    hab, doers = existing.openHabitat(name=name)

    # setup doers
    server = tcpServing.Server(host="", port=tcp)
    tcpServerDoer = tcpServing.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)

    reger = viring.Registry(name=hab.name, temp=False)
    verifier = verifying.Verifier(hab=hab, name=hab.name, reger=reger)
    wallet = walleting.Wallet(db=verifier.reger, name=name)

    handlers = []

    proofs = decking.Deck()
    issuerCues = decking.Deck()

    jsonSchema = scheming.JSONSchema(resolver=scheming.jsonSchemaCache)
    issueHandler = handling.IssueHandler(hab=hab, verifier=verifier, typ=jsonSchema)
    requestHandler = handling.RequestHandler(wallet=wallet, typ=jsonSchema)
    applyHandler = handling.ApplyHandler(hab=hab, verifier=verifier, name=name, issuerCues=issuerCues)
    proofHandler = handling.ProofHandler(proofs=proofs)

    mbx = storing.Mailboxer(name=hab.name)
    mih = grouping.MultisigInceptHandler(hab=hab, controller=controller, mbx=mbx)
    ish = grouping.MultisigIssueHandler(hab=hab, controller=controller, mbx=mbx)
    meh = grouping.MultisigEventHandler(hab=hab, verifier=verifier)

    handlers.extend([issueHandler, requestHandler, proofHandler, applyHandler, mih, ish, meh])

    exchanger = exchanging.Exchanger(hab=hab, handlers=handlers)

    rep = storing.Respondant(hab=hab, mbx=mbx)
    cues = decking.Deck()
    mbd = indirecting.MailboxDirector(hab=hab,
                                      exc=exchanger,
                                      verifier=verifier,
                                      rep=rep,
                                      topics=["/receipt", "/replay", "/multisig", "/credential", "/delegate"],
                                      cues=cues)
    # configure a kevery
    doers.extend([exchanger, directant, tcpServerDoer, mbd])
    doers.extend(adminInterface(controller=controller,
                                hab=hab,
                                insecure=insecure,
                                proofs=proofs,
                                cues=cues,
                                issuerCues=issuerCues,
                                verifier=verifier,
                                mbx=mbx,
                                mbd=mbd,
                                adminHttpPort=adminHttpPort,
                                path=path))

    return doers


def adminInterface(controller, hab, insecure, proofs, cues, issuerCues, mbx, mbd, verifier, adminHttpPort=5623,
                   path=STATIC_DIR_PATH):
    app = falcon.App(middleware=falcon.CORSMiddleware(
        allow_origins='*', allow_credentials='*', expose_headers=['cesr-attachment', 'cesr-date', 'content-type']))
    print("creating static sink for", path)
    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    rep = storing.Respondant(hab=hab, mbx=mbx)

    httpHandler = indirecting.HttpMessageHandler(hab=hab, app=app, rep=rep)
    gdoer = grouping.MultiSigGroupDoer(hab=hab, ims=mbd.ims)

    kiwiServer = agenting.KiwiServer(hab=hab, controller=controller, verifier=verifier, gdoer=gdoer.msgs, app=app,
                                     rep=rep, issuerCues=issuerCues, insecure=insecure)

    mbxer = storing.MailboxServer(app=app, hab=hab, mbx=mbx)
    wiq = agenting.WitnessInquisitor(hab=hab)

    proofHandler = AdminProofHandler(hab=hab, controller=controller, mbx=mbx, verifier=verifier, wiq=wiq, proofs=proofs)
    cueHandler = AdminCueHandler(hab=hab, controller=controller, mbx=mbx, cues=cues)
    server = http.Server(port=adminHttpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    doers = [httpServerDoer, httpHandler, rep, mbxer, wiq, proofHandler, cueHandler, gdoer, kiwiServer]

    return doers


class AdminProofHandler(doing.Doer):
    def __init__(self, hab, controller, mbx, verifier, wiq, proofs=None, **kwa):
        self.hab = hab
        self.controller = controller
        self.mbx = mbx
        self.verifier = verifier
        self.presentations = proofs if proofs is not None else decking.Deck()
        self.wiq = wiq
        super(AdminProofHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
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

                creder = proving.Credentialer(crd=vc)

                prefixer, seqner, diger, isigers = proving.parseProof(vcproof)
                status = self.verifier.verify(pre, creder, prefixer, seqner, diger, isigers)
                pl = dict(
                    pre=pre.qb64,
                    vc=vc,
                    status=status,
                )

                print("STORING VC PROOF FOR MY CONTROLLER", self.controller, pl)

                # TODO: Add SAID signature on exn, then sanction `fwd` envelope
                ser = exchanging.exchange(route="/cmd/presentation/proof", payload=pl)
                msg = bytearray(ser.raw)
                msg.extend(self.hab.sanction(ser))

                self.mbx.storeMsg(self.controller + "/credential", msg)

                yield

            yield


class AdminCueHandler(doing.DoDoer):
    """

    """

    def __init__(self, controller, hab, mbx, cues=None, **kwa):
        """

        Parameters:
            mbx is Mailboxer for saving messages for controller
            cues is cues Deck from external mailbox to process

        """
        self.controller = controller
        self.hab = hab
        self.mbx = mbx
        self.cues = cues if cues is not None else decking.Deck()

        super(AdminCueHandler, self).__init__(doers=[doing.doify(self.cueDo)], **kwa)

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
                if cueKin in ("delegating",):
                    srdr = cue["serder"]
                    msg = self.hab.interact(data=[
                        dict(i=srdr.pre, s=srdr.ked["s"], d=srdr.dig)
                    ])
                    witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg)
                    self.extend([witRctDoer])

                    while not witRctDoer.done:
                        yield self.tock

                    self.remove([witRctDoer])
                elif cueKin in ("psUnescrow",):
                    srdr = cue["serder"]
                    wits = srdr.ked["b"]
                    witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.HttpWitnesser, wits=wits)
                    self.extend([witq])

                    while srdr.pre not in self.hab.kevers:
                        witq.query(pre=srdr.pre)
                        yield 1.0

                    print("Successfully deletated to", srdr.pre)


                yield self.tock
            yield self.tock

