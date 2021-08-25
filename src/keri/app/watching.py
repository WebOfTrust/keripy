# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json

import falcon
from hio.base import doing
from hio.help import decking

from keri.app import keeping, forwarding
from keri.core import coring, eventing
from .. import help
from ..end import ending

logger = help.ogler.getLogger()


class KiwiServer(doing.DoDoer):
    """
    Routes for handling UI requests for Watcher Control

    """

    def __init__(self, hab, controller, cues=None, app=None, **kwa):
        self.hab = hab
        self.controller = controller
        self.app = app if app is not None else falcon.App(cors_enable=True)
        app.add_middleware(SignatureValidationComponent(hab=self.hab, pre=self.controller))
        self.cues = cues if cues is not None else decking.Deck()

        self.app.add_route("/rotate", self, suffix="rotate")

        doers = []

        super(KiwiServer, self).__init__(doers=doers, **kwa)

    def on_post_rotate(self, req, rep):
        pre = req.context.pre
        print(pre)
        prms = self.hab.ks.prms.get(self.hab.pre)

        aeid = self.hab.mgr.aeid
        cur = self.hab.kever

        algo = prms.algo
        salt = prms.salt
        tier = prms.tier
        pidx = prms.pidx

        ncount = 0  # next count
        code = coring.MtrDex.Ed25519N

        mgr = keeping.Manager(ks=self.hab.ks, aeid=aeid, pidx=pidx,
                              algo=algo, salt=salt, tier=tier)

        verfers, digers, cst, nst = mgr.incept(icount=1,
                                               ncount=ncount,
                                               isith=cur.tholder.sith,
                                               algo=keeping.Algos.randy,
                                               transferable=False,
                                               temp=False)


        opre = verfers[0].qb64  # old pre default move below to new pre from incept
        if digers:
            nxt = coring.Nexter(sith=nst,
                                digs=[diger.qb64 for diger in digers]).qb64
        else:
            nxt = ""

        serder = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 sith=cst,
                                 nxt=nxt,
                                 toad=cur.toad,
                                 wits=cur.wits,
                                 code=code)

        icpMsg = bytearray(serder.raw)
        sigers = mgr.sign(ser=serder.raw, verfers=verfers)
        icpMsg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                  count=len(sigers)).qb64b)  # attach cnt
        for sig in sigers:
            icpMsg.extend(sig.qb64b)  # attach sig


        sigers = self.hab.mgr.sign(ser=bytes(icpMsg),
                                   verfers=self.hab.kever.verfers,
                                   indexed=False)

        signage = ending.Signage(markers=sigers, indexed=False)
        sheaders = ending.signature([signage])

        self.hab.recreate(serder, opre, verfers)

        for key, val in sheaders.items():
            rep.append_header(key, val)

        rep.content_type = "application/json+CESR"
        rep.content_length = len(icpMsg)
        rep.data = icpMsg
        rep.status = falcon.HTTP_200


class SignatureValidationComponent(object):

    def __init__(self, hab, pre):
        self.hab = hab
        self.pre = pre

    def process_request(self, req, resp):
        sig = req.headers.get("SIGNATURE")

        ser = req.bounded_stream.read()
        if not self.validate(sig=sig, ser=ser):
            resp.complete = True
            resp.status = falcon.HTTP_401
            return
        data = json.loads(ser.decode("utf-8"))
        req.context.pre = data["pre"]

    def validate(self, sig, ser):
        signages = ending.designature(sig)
        markers = signages[0].markers

        if self.pre not in self.hab.kevers:
            return False

        verfers = self.hab.kevers[self.pre].verfers
        for idx, verfer in enumerate(verfers):
            key = str(idx)
            if key not in markers:
                return False
            siger = markers[key]
            siger.verfer = verfer

            if not verfer.verify(siger.raw, ser):
                return False

        return True
