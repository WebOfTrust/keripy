# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.agent module

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
from keri.app import directing, agenting, indirecting, storing, grouping, forwarding
from keri.app.cli.common import existing
from keri.core import parsing
from keri.help import helping
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
    help.ogler.level = logging.INFO
    help.ogler.reopen(name="keri", temp=True, clear=True)

    print("\n******* Starting Agent for {} listening: http/{}, tcp/{} "
          ".******\n\n".format(args.name, args.admin_http_port, args.tcp))

    doers = runAgent(controller=args.controller, name=args.name, insecure=args.insecure,
                     tcp=int(args.tcp),
                     adminHttpPort=int(args.admin_http_port), path=args.path)
    try:
        tock = 0.03125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except kering.ConfigurationError:
        print(f"prefix for {args.name} does not exist, incept must be run first", )

    print("\n******* Ended Agent for {} listening: http/{}, tcp/{}"
          ".******\n\n".format(args.name, args.admin_http_port, args.tcp))


def runAgent(controller, name="agent", insecure=False, tcp=5621, adminHttpPort=5623, path=STATIC_DIR_PATH):
    """
    Setup and run one agent
    """

    hab, doers = existing.openHabitat(name=name)

    # setup doers
    server = tcpServing.Server(host="", port=tcp)
    tcpServerDoer = tcpServing.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)

    reger = viring.Registry(name=hab.name, temp=False, db=hab.db)
    verifier = verifying.Verifier(hab=hab, name=hab.name, reger=reger)
    wallet = walleting.Wallet(reger=verifier.reger, name=name)

    handlers = []

    proofs = decking.Deck()
    issuerCues = decking.Deck()

    ims = bytearray()
    issueHandler = handling.IssueHandler(hab=hab, verifier=verifier, ims=ims)
    requestHandler = handling.RequestHandler(hab=hab, wallet=wallet)
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
    doers.extend([exchanger, directant, tcpServerDoer, mbd, rep])
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
    sink = http.serving.StaticSink(staticDirPath=path)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    rep = storing.Respondant(hab=hab, mbx=mbx)
    gdoer = grouping.MultiSigGroupDoer(hab=hab, ims=mbd.ims)

    kiwiServer = agenting.KiwiServer(hab=hab, controller=controller, verifier=verifier, gdoer=gdoer.msgs, app=app,
                                     rep=rep, issuerCues=issuerCues, insecure=insecure)

    mbxer = storing.MailboxServer(app=app, hab=hab, mbx=mbx)

    proofHandler = AdminProofHandler(hab=hab, controller=controller, mbx=mbx, verifier=verifier, proofs=proofs,
                                     ims=mbd.ims)
    cueHandler = AdminCueHandler(hab=hab, controller=controller, mbx=mbx, cues=cues)
    server = http.Server(port=adminHttpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    doers = [httpServerDoer, rep, mbxer, proofHandler, cueHandler, gdoer, kiwiServer]

    return doers


class AdminProofHandler(doing.DoDoer):
    def __init__(self, hab, controller, mbx, verifier, proofs=None, ims=None, **kwa):
        self.hab = hab
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

                c = self.verifier.reger.saved.get(creder.said)
                if c is None:
                    self.parsed.append((creder, vcproof))

                else:
                    creders = self.verifier.reger.cloneCreds([creder.saider])
                    cred = creders[0]

                    ser = exchanging.exchange(route="/cmd/presentation/proof", payload=cred)
                    msg = bytearray(ser.raw)
                    msg.extend(self.hab.endorse(ser))

                    self.mbx.storeMsg(self.controller + "/presentation", msg)

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
        self.witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.HttpWitnesser)
        self.postman = forwarding.Postman(hab=self.hab)



        super(AdminCueHandler, self).__init__(doers=[self.postman, self.witq, doing.doify(self.cueDo)], **kwa)

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
                        dict(i=srdr.pre, s=srdr.ked["s"], d=srdr.said)
                    ])
                    witRctDoer = agenting.WitnessReceiptor(hab=self.hab, msg=msg)
                    self.extend([witRctDoer])

                    while not witRctDoer.done:
                        yield self.tock

                    self.remove([witRctDoer])
                if cue["kin"] == "delegatage":
                    delpre = cue["delpre"]
                    self.witq.query(pre=delpre)

                elif cue["kin"] == "query":
                    qargs = cue["q"]
                    self.witq.backoffQuery(**qargs)

                elif cueKin in ("psUnescrow",):
                    srdr = cue["serder"]
                    if self.hab.kever.delegator is None:
                        if srdr.pre in self.hab.kevers:
                            kever = self.hab.kevers[srdr.pre]
                            delpre = kever.delegator
                        else:
                            delpre = srdr.ked["di"]

                        if delpre != self.hab.pre:
                            continue

                        if srdr.pre not in self.hab.kevers:  # TODO: check sn here.
                            self.witq.query(pre=srdr.pre)

                        print("Successfully deletated to", srdr.pre, "for", srdr.ked["t"], ":", srdr.ked["s"])
                    else:
                        self.hab.delegatedRotationAccepted()
                        evt = self.hab.makeOwnEvent(sn=self.hab.kever.sn)
                        witDoer = agenting.WitnessReceiptor(hab=self.hab, msg=bytearray(evt),
                                                            klas=agenting.TCPWitnesser)
                        self.extend([witDoer])
                        while not witDoer.done:
                            yield self.tock

                        self.remove([witDoer])
                        self.postman.send(recipient=self.hab.kever.delegator, topic="delegate", msg=bytearray(evt))

                        print("Successfully received delegation", "for", self.hab.kever.ilk, ":", self.hab.kever.sn)
                        payload = dict(
                            delegator=self.hab.kever.delegator,
                            t=self.hab.kever.ilk,
                            s=self.hab.kever.sn,
                            dt=helping.nowIso8601())
                        ser = exchanging.exchange(route="/delegate", payload=payload)
                        msg = bytearray(ser.raw)
                        msg.extend(self.hab.endorse(serder=ser))
                        self.mbx.storeMsg(self.controller + "/delegate", msg)

                yield self.tock
            yield self.tock
