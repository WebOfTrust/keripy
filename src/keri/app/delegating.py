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

from . import keeping, habbing, agenting, indirecting
from .forwarding import forward
from .. import kering
from ..core import eventing, coring, parsing
from ..db import basing

logger = help.ogler.getLogger()


class InceptDoer(doing.DoDoer):
    """ Delegating inception DoDoer

    """

    def __init__(self, hby, msgs=None, cues=None, ):
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.hby = hby

        doers = [
            doing.doify(self.msgDo),
        ]
        super(InceptDoer, self).__init__(doers=doers)

    def msgDo(self, tymth, tock=0.0):
        """ Process messages to ikncept delegated identfiier

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                try:
                    alias = msg["alias"] if "alias" in msg else None
                    msg.pop("alias")

                    hab = self.hby.makeHab(name=alias, **msg)

                    delsrdr = hab.kever.serder
                    fwd = forward(pre=delsrdr.ked["di"], topic="delegate", serder=delsrdr)
                    evt = hab.endorse(serder=fwd)
                    dkever = hab.kevers[delsrdr.ked["di"]]
                    wit = random.choice(dkever.wits)

                    urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http)
                    witer = agenting.HttpWitnesser(hab=hab, wit=wit, url=urls[kering.Schemes.http])
                    witer.msgs.append(bytearray(evt))
                    self.extend([witer])

                    while len(witer.sent) == 0:
                        yield self.tock

                    self.remove([witer])

                    mbx = indirecting.MailboxDirector(hab=hab, topics=['/receipt'])
                    witDoer = agenting.WitnessReceiptor(hab=hab, klas=agenting.HttpWitnesser)
                    self.extend([mbx, witDoer])

                    while not witDoer.done:
                        yield 1.0

                    self.remove([mbx, witDoer])


                except (kering.MissingAnchorError, Exception) as ex:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.exception("delegation incept message error: %s\n", ex)
                    else:
                        logger.error("delegation incept message error: %s\n", ex)
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
        db = basing.Baser(name=name, temp=False)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=hab)

        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.rotateDo, **kwa)]
        self.hab = hab
        self.data = data
        self.sealFile = sealFile
        self.delegatorPrefix = kwa["delegatorPrefix"]

        super(RotateDoer, self).__init__(doers=doers)


    def rotateDo(self, tymth, tock=0.0):
        """ Co-routine for performing delegated rotation

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)  # finish enter context

        delPre = self.data[0]["i"]
        delK = self.hab.kevers[delPre]

        verfers, digers, cst, nst = self.hab.mgr.rotate(pre=delK.prefixer.qb64, temp=False)
        rotSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delK.serder.saider.qb64,
                                   sn=delK.sn + 1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        seal = dict(i=rotSrdr.pre,
                    s=rotSrdr.ked["s"],
                    d=rotSrdr.said)

        with open(self.sealFile, "w") as f:
            f.write(json.dumps(seal, indent=4))

        witq = agenting.WitnessInquisitor(hab=self.hab, klas=agenting.TCPWitnesser)
        self.extend([witq])

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
        msg.extend(event.serder.saider.qb64b)

        delKvy = eventing.Kevery(db=self.hab.db, lax=True)
        parsing.Parser().parseOne(ims=bytearray(msg), kvy=delKvy)

        while rotSrdr.pre not in delKvy.kevers:
            yield self.tock

        print("Successfully rotated delegate identifier keys", rotSrdr.pre)
        print("Public key", rotSrdr.verfers[0].qb64)

        self.remove([self.ksDoer, self.dbDoer, self.habDoer, witq])

        return
