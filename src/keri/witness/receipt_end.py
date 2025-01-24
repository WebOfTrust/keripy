# -*- encoding: utf-8 -*-
"""
KERI
keri.app.indirecting module

simple indirect mode demo support classes
"""

import falcon
from hio.base import doing
from hio.help import decking
from .. import help, kering
from ..app import httping
from ..core import (eventing, parsing, serdering,
                    Counter, Codens)
from ..core.coring import Ilks
from ..db import dbing

logger = help.ogler.getLogger()

class ReceiptEnd(doing.DoDoer):
    """ Endpoint class for Witnessing receipting functionality

     Most times a witness will be able to return its receipt for an event inband.  This API
     will provide that functionality.  When an event needs to be escrowed, this POST API
     will return a 202 and also provides a generic GET API for retrieving a receipt for any
     event.

     """

    def __init__(self, hab, inbound=None, outbound=None, aids=None):
        self.hab = hab
        self.inbound = inbound if inbound is not None else decking.Deck()
        self.outbound = outbound if outbound is not None else decking.Deck()
        self.aids = aids
        self.receipts = set()
        self.psr = parsing.Parser(framed=True,
                                  kvy=self.hab.kvy)

        super(ReceiptEnd, self).__init__(doers=[doing.doify(self.interceptDo)])

    def on_post(self, req, rep):
        """  Receipt POST endpoint handler

        Parameters:
            req (Request): Falcon HTTP request object
            rep (Response): Falcon HTTP response object

        """

        if req.method == "OPTIONS":
            rep.status = falcon.HTTP_200
            return

        rep.set_header('Cache-Control', "no-cache")
        rep.set_header('connection', "close")

        cr = httping.parseCesrHttpRequest(req=req)
        serder = serdering.SerderKERI(sad=cr.payload, kind=eventing.Kinds.json)

        pre = serder.ked["i"]
        if self.aids is not None and pre not in self.aids:
            raise falcon.HTTPBadRequest(description=f"invalid AID={pre} for witnessing receipting")

        ilk = serder.ked["t"]
        if ilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt):
            raise falcon.HTTPBadRequest(description=f"invalid event type ({ilk})for receipting")

        msg = bytearray(serder.raw)
        msg.extend(cr.attachments.encode("utf-8"))

        self.psr.parseOne(ims=msg, local=True)

        if pre in self.hab.kevers:
            kever = self.hab.kevers[pre]
            wits = kever.wits

            if self.hab.pre not in wits:
                raise falcon.HTTPBadRequest(description=f"{self.hab.pre} is not a valid witness for {pre} event at "
                                                        f"{serder.sn}: wits={wits}")

            rct = self.hab.receipt(serder)

            self.psr.parseOne(bytes(rct))

            rep.set_header('Content-Type', "application/json+cesr")
            rep.status = falcon.HTTP_200
            rep.data = rct
        else:
            rep.status = falcon.HTTP_202

    def on_get(self, req, rep):
        """  Receipt GET endpoint handler

        Parameters:
            req (Request): Falcon HTTP request object
            rep (Response): Falcon HTTP response object

        """
        pre = req.get_param("pre")
        sn = req.get_param_as_int("sn")
        said = req.get_param("said")

        if pre is None:
            raise falcon.HTTPBadRequest(description="query param 'pre' is required")

        preb = pre.encode("utf-8")

        if sn is None and said is None:
            raise falcon.HTTPBadRequest(description="either 'sn' or 'said' query param is required")

        if sn is not None:
            said = self.hab.db.getKeLast(key=dbing.snKey(pre=preb,
                                                         sn=sn))

        if said is None:
            raise falcon.HTTPNotFound(description=f"event for {pre} at {sn} ({said}) not found")

        said = bytes(said)
        dgkey = dbing.dgKey(preb, said)  # get message
        if not (raw := self.hab.db.getEvt(key=dgkey)):
            raise falcon.HTTPNotFound(description="Missing event for dig={}.".format(said))

        serder = serdering.SerderKERI(raw=bytes(raw))
        if serder.sn > 0:
            wits = [wit.qb64 for wit in self.hab.kvy.fetchWitnessState(pre, serder.sn)]
        else:
            wits = serder.ked["b"]

        if self.hab.pre not in wits:
            raise falcon.HTTPBadRequest(description=f"{self.hab.pre} is not a valid witness for {pre} event at "
                                                    f"{serder.sn}, {wits}")
        rserder = eventing.receipt(pre=pre,
                                   sn=sn,
                                   said=said.decode("utf-8"))
        rct = bytearray(rserder.raw)
        if wigs := self.hab.db.getWigs(key=dgkey):
            rct.extend(Counter(Codens.WitnessIdxSigs, count=len(wigs),
                               gvrsn=kering.Vrsn_1_0).qb64b)
            for wig in wigs:
                rct.extend(wig)

        rep.set_header('Content-Type', "application/json+cesr")
        rep.status = falcon.HTTP_200
        rep.data = rct

    def interceptDo(self, tymth=None, tock=0.0):
        """
         Returns doifiable Doist compatibile generator method (doer dog) to process
            Kevery and Tevery cues deque

        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.inbound:  # iteratively process each cue in cues
                cue = self.inbound.popleft()
                cueKin = cue["kin"]  # type or kind of cue

                if cueKin in ("receipt",):  # cue to receipt a received event from other pre
                    serder = cue["serder"]  # Serder of received event for other pre
                    if serder.saidb in self.receipts:
                        self.receipts.remove(serder.saidb)
                    else:
                        self.outbound.append(cue)

                else:
                    self.outbound.append(cue)

                yield self.tock

            yield self.tock
