# -*- encoding: utf-8 -*-
"""
KERI
keri.app.delegating module

module for enveloping and forwarding KERI message
"""
import json
import logging
import random

from hio import help
from hio.base import doing
from hio.help import decking

from . import keeping, habbing, agenting, obtaining
from .forwarding import forward
from .habbing import Habitat
from .. import kering
from ..core import eventing, coring, parsing
from ..db import basing

logger = help.ogler.getLogger()


class Delegatey:
    def __init__(self, name, db, ks, msgs=None, posts=None):
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.posts = posts if posts is not None else decking.Deck()
        self.name = name
        self.db = db
        self.ks = ks
        self.hab = None
        self.notified = False

    def processMessage(self, msg):
        salt = coring.Salter(raw=msg["salt"].encode("utf-8")).qb64
        seed = msg["seed"] if "seed" in msg else None
        wits = msg["wits"] if "wits" in msg else None
        toad = msg["toad"] if "toad" in msg else None
        icount = msg["icount"] if "icount" in msg else None
        isith = msg["isith"] if "isith" in msg else None
        ncount = msg["ncount"] if "ncount" in msg else None
        nsith = msg["nsith"] if "nsith" in msg else None
        delpre = msg["delpre"] if "delpre" in msg else None

        if self.hab is None:
            self.hab = Habitat(name=self.name, db=self.db, ks=self.ks, seed=seed, salt=salt, icount=icount, isith=isith,
                               ncount=ncount, nsith=nsith, toad=toad, wits=wits, delpre=delpre, )

        self.posts.append(dict(srdr=self.hab.delserder, sigers=self.hab.delsigers))

    def genQuery(self, pre):
        query = dict()
        query['i'] = pre
        serder = eventing.query(res="logs", qry=query)

        msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
        msg.extend(coring.Counter(coring.CtrDex.TransLastIdxSigGroups, count=1).qb64b)
        msg.extend(pre.encode("utf-8"))

        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(self.hab.delsigers))
        msg.extend(counter.qb64b)
        for siger in self.hab.delsigers:
            msg.extend(siger.qb64b)
        return msg


class InceptDoer(doing.DoDoer):
    def __init__(self, name, msgs=None, cues=None, ):
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=self.ks)  # doer do reopens if not opened and closes
        self.db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=self.db)  # doer do reopens if not opened and closes

        doers = [
            self.ksDoer,
            self.dbDoer,
            doing.doify(self.msgDo),
            doing.doify(self.postDo),
        ]
        self.delegatey = Delegatey(name=name, db=self.db, ks=self.ks, msgs=self.msgs)
        super(InceptDoer, self).__init__(doers=doers)

    def escrowDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            self.delegatey.hab.kvy.processEscrows()
            yield self.tock

    def processKvyCues(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.delegatey.hab.kvy.cues:
                cue = self.delegatey.hab.kvy.cues.popleft()
                if cue["kin"] == "delegatage":
                    delpre = cue["delpre"]
                    delwits = obtaining.getwitnessesforprefix(delpre)

                    qry = self.delegatey.genQuery(pre=delpre)
                    witer = agenting.TCPWitnesser(self.delegatey.hab, random.choice(delwits), lax=True, local=False)
                    witer.msgs.append(qry)
                    self.extend([witer])
                elif cue["kin"] == "psUnescrow":
                    self.delegatey.hab.delegationAccepted()
                    evt = self.delegatey.hab.makeOwnEvent(sn=0)
                    witDoer = agenting.WitnessReceiptor(hab=self.delegatey.hab, msg=evt, klas=agenting.TCPWitnesser)
                    self.extend([witDoer])
                    while not witDoer.done:
                        yield self.tock

                    self.remove([witDoer])
                    self.cues.append(dict(delegator=self.delegatey.hab.delpre, pre=self.delegatey.hab.pre))


                yield self.tock
            yield self.tock

    def msgDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.delegatey.msgs:
                msg = self.delegatey.msgs.popleft()
                try:
                    if "name" not in msg:
                        msg["name"] = self.delegatey.name

                    self.delegatey.processMessage(msg=msg)
                except (kering.MissingAnchorError, Exception) as ex:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("delegation incept message error: %s\n", ex)
                    else:
                        logger.error("delegation incept message error: %s\n", ex)
                yield self.tock
            yield self.tock


    def postDo(self, tymth, tock=0.0):
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.delegatey.posts:
                post = self.delegatey.posts.popleft()
                delsrdr = post["srdr"]
                fwd = forward(pre=delsrdr.ked["di"], topic="delegate", serder=delsrdr)
                evt = eventing.messagize(serder=fwd, sigers=post["sigers"])

                delwits = obtaining.getwitnessesforprefix(delsrdr.ked["di"])
                wit = random.choice(delwits)

                witer = agenting.HttpWitnesser(hab=self.delegatey.hab, wit=wit)
                witer.msgs.append(bytearray(evt))
                self.extend([witer])

                while len(witer.sent) == 0:
                    yield self.tock

                self.extend([doing.doify(self.processKvyCues), doing.doify(self.escrowDo), ])
                # self.remove([witer])

                yield self.tock
            yield self.tock


class RotateDoer(doing.DoDoer):
    """
    DoDoer instance that launches the environment and dependencies needed to create and disseminate
    the inception event for a delegated identifier.
    """

    def __init__(self, name, sealFile, data, **kwa):
        """
        Creates the DoDoer needed to create the seal for a delegated identifier.

        Parameters
            name (str): Name of the local identifier environment

        """

        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=hab)

        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.rotateDo, **kwa)]
        self.hab = hab
        self.data = data
        self.sealFile = sealFile
        self.delegatorPrefix = kwa["delegatorPrefix"]

        super(RotateDoer, self).__init__(doers=doers)

    def rotateDo(self, tymth, tock=0.0, **kwa):
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        delPre = self.data[0]["i"]
        delK = self.hab.kevers[delPre]

        verfers, digers, cst, nst = self.hab.mgr.rotate(pre=delK.prefixer.qb64, temp=False)
        rotSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delK.serder.diger.qb64,
                                   sn=delK.sn + 1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        seal = dict(i=rotSrdr.pre,
                    s=rotSrdr.ked["s"],
                    d=rotSrdr.dig)

        with open(self.sealFile, "w") as f:
            f.write(json.dumps(seal, indent=4))

        witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.TCPWitnesser)
        self.extend([witq])

        print("Hello, could someone approve my delegated rotation, please?")

        while self.delegatorPrefix not in self.hab.kevers or self.hab.kevers[self.delegatorPrefix].sn < 2:
            witq.query(self.delegatorPrefix)
            yield self.tock

        sigers = self.hab.mgr.sign(ser=rotSrdr.raw, verfers=verfers)
        msg = bytearray(rotSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)
        counter = coring.Counter(code=coring.CtrDex.SealSourceCouples,
                                 count=1)
        msg.extend(counter.qb64b)

        event = self.hab.kevers[rotSrdr.pre]
        seqner = coring.Seqner(sn=event.sn)
        msg.extend(seqner.qb64b)
        msg.extend(event.serder.diger.qb64b)

        delKvy = eventing.Kevery(db=self.hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(msg), kvy=delKvy)

        while rotSrdr.pre not in delKvy.kevers:
            yield self.tock

        print("Successfully rotated delegate identifier keys", rotSrdr.pre)
        print("Public key", rotSrdr.verfers[0].qb64)

        self.remove([self.ksDoer, self.dbDoer, self.habDoer, witq])

        return
