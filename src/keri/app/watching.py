# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""

from hio.base import doing
from hio.help import decking
from keri.app import keeping, forwarding
from keri.core import coring, eventing
from keri.peer import exchanging

from .. import help

logger = help.ogler.getLogger()


class RotateIdentifierHandler(doing.DoDoer):
    """
        Processor for a performing a identifier rotate in of a Watcher
        {
        }
    """

    resource = "/cmd/watcher/rotate"

    def __init__(self, hab, reps=None, cues=None, **kwa):
        self.hab = hab
        self.msgs = decking.Deck()
        self.reps = reps if reps is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.msgDo)]

        super(RotateIdentifierHandler, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Rotate identifier.

        Messages:
            payload is dict representing the body of a /presentation/request message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /presentation/request message
            verfers is list of Verfers of the keys used to sign the message

        Returns doifiable Doist compatible generator method that dumps the Watcher's current identifier and
        creates a new one.  (doer dog)

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pre = msg["pre"]

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

                msg = bytearray(serder.raw)
                sigers = self.hab.mgr.sign(ser=serder.raw, verfers=verfers)
                msg.extend(coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                          count=len(sigers)).qb64b)  # attach cnt
                for sig in sigers:
                    msg.extend(sig.qb64b)  # attach sig


                pl = dict(icp=msg.decode("utf-8"))
                exn = exchanging.exchange("/cmd/watcher/rotate", payload=pl)
                fwd = forwarding.forward(pre=pre.qb64, serder=exn)

                # TODO: Add SAID signature on exn, then sanction `fwd` envelope
                act = self.hab.sanction(exn)
                msg = bytearray(fwd.raw)
                msg.extend(act)

                self.reps.append(dict(dest=pre.qb64, msg=msg))
                self.hab.recreate(serder, opre, verfers)

                yield

            yield

