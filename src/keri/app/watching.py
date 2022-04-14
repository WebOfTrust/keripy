# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json

import falcon
from hio.base import doing
from hio.help import decking

from keri.app import keeping, agenting
from keri.core import coring, eventing, parsing
from .. import help, kering
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
        self.cues = cues if cues is not None else decking.Deck()

        self.app.add_route("/rotate", self, suffix="rotate")

        doers = []

        super(KiwiServer, self).__init__(doers=doers, **kwa)

    def on_post_rotate(self, req, rep):
        pre = self.controller
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

        serder = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 sith=cst,
                                 nsith=nst,
                                 nkeys=[diger.qb64 for diger in digers],
                                 toad=cur.toad,
                                 wits=cur.wits,
                                 code=code)

        icpMsg = bytearray(serder.raw)
        sigers = mgr.sign(ser=serder.raw, verfers=verfers)
        icpMsg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                     count=len(sigers)).qb64b)  # attach cnt
        for sig in sigers:
            icpMsg.extend(sig.qb64b)  # attach sig

        sigers = self.hab.sign(ser=bytes(icpMsg),
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


class WatcherClientRotateDoer(doing.DoDoer):
    """
    Sends KERI Auth'ed HTTP request to specified watcher to rotate identifer.  Current
    watcher set is then updated by removing the old watcher idenfitier and adding the
    new watcher identifier.

    """

    def __init__(self, hab, msgs=None, cues=None, **kwa):
        """
        Create doer to rotate remote watcher identifier prefix

        Parameters:
            name: is str name of Habitat
            watcher:
            kwa:
        """
        self.hab = hab
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.rotateDo)]
        super(WatcherClientRotateDoer, self).__init__(doers=doers, **kwa)

    def rotateDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                watcher = self.msgs.popleft()
                habr = self.hab.db.habs.get(self.hab.name)
                if watcher not in habr.watchers:
                    raise kering.ValidationError("identifier {} is not a current watcher {}"
                                                 "".format(watcher, habr.watchers))

                payload = dict(pre=self.hab.pre)
                raw = json.dumps(payload)
                sigers = self.hab.sign(ser=raw.encode("utf-8"),
                                       verfers=self.hab.kever.verfers,
                                       indexed=True)

                signage = ending.Signage(markers=sigers, indexed=True)
                headers = ending.signature([signage])

                client, clientDoer = agenting.httpClient(self.hab, watcher)
                self.extend([clientDoer])

                client.request(method="POST", path="/rotate", headers=headers, body=raw)
                while not client.responses:
                    yield self.tock

                resp = client.respond()
                if resp.status != 200:
                    print("Invalid status from watcher:", type(resp.status))
                    return

                if not self.authenticate(watcher=watcher, resp=resp):
                    print("Invalid response from watcher")
                    return

                wat = self.processWatcherResponse(watcher=watcher, icp=bytes(resp.body))

                self.remove([clientDoer])

                self.cues.append(dict(old=watcher, new=wat))

                yield self.tock

            yield self.tock

    def processWatcherResponse(self, watcher, icp):
        ctrlKvy = eventing.Kevery(db=self.hab.db)
        parsing.Parser().parse(ims=bytearray(icp), kvy=ctrlKvy)

        srdr = coring.Serder(raw=bytearray(icp))
        wat = srdr.pre

        habr = self.hab.db.habs.get(self.hab.name)
        ewats = set(habr.watchers)

        ewats.remove(watcher)
        ewats.add(wat)

        habr.watchers = list(ewats)

        self.hab.db.habs.pin(self.hab.name, habr)
        return wat

    @staticmethod
    def authenticate(watcher, resp):
        if "Signature" not in resp.headers:
            return False

        signages = ending.designature(resp.headers["Signature"])

        cigar = signages[0].markers[watcher]
        verfer = coring.Verfer(qb64=watcher)
        if not verfer.verify(cigar.raw, bytes(resp.body)):
            return False

        return True
