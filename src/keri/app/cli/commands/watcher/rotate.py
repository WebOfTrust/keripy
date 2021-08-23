# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse

from hio.base import doing
from hio.help import decking

from keri import help, kering
from keri.app import directing, agenting, indirecting, forwarding
from keri.app.cli.common import existing
from keri.core import eventing, parsing, coring
from keri.peer import exchanging

parser = argparse.ArgumentParser(description='Rotate watcher prefix')
parser.set_defaults(handler=lambda args: rotateWatcher(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument("--watcher", "-w", help="QB64 identifier prefix of watcher to rotate", default="", required=True)

logger = help.ogler.getLogger()


def rotateWatcher(args):
    name = args.name
    wat = args.watcher

    rotr = WatcherRotateDoer(name=name, watcher=wat)
    directing.runController(doers=[rotr], expire=0.0)


class WatcherRotateDoer(doing.DoDoer):


    def __init__(self, name, watcher, **kwa):
        hab, doers = existing.openHabitat(name=name)
        self.hab = hab
        self.watcher = watcher
        self.reps = decking.Deck()

        rotateHandler = RotateResponseHandler(hab=hab, reps=self.reps, watcher=self.watcher)
        exchanger = exchanging.Exchanger(hab=hab, handlers=[rotateHandler])

        mbx = indirecting.MailboxDirector(hab=hab, exc=exchanger)

        self.toRemove = doers + [exchanger, mbx]
        doers.extend([exchanger, mbx, doing.doify(self.rotateDo)])
        super(WatcherRotateDoer, self).__init__(doers=doers, **kwa)


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

        habr = self.hab.db.habs.get(self.hab.name)
        if self.watcher not in habr.watchers:
            raise kering.ValidationError("identifier {} is not a current watcher {}"
                                         "".format(self.watcher, habr.watchers))


        payload = dict()

        srdr = exchanging.exchange(route="/cmd/watcher/rotate", payload=payload)
        fwd = forwarding.forward(serder=srdr, pre=self.watcher)
        msg = bytearray(fwd.raw)
        msg.extend(self.hab.sanction(srdr))

        witer = agenting.HttpWitnesser(hab=self.hab, wit=self.watcher)
        witer.msgs.append(bytearray(msg))  # make a copy so every munges their own
        self.extend([witer])
        self.toRemove.extend([witer])

        while not self.reps:
            yield self.tock


        habr = self.hab.db.habs.get(self.hab.name)
        print("New Watcher Set:")
        for wat in habr.watchers:
            print("\t{}".format(wat))

        self.remove(self.toRemove)



class RotateResponseHandler(doing.DoDoer):
    """
        Processor for a performing a identifier rotate in of a Watcher
        {
        }
    """

    resource = "/cmd/watcher/rotate"

    def __init__(self, hab, watcher, reps=None, cues=None, **kwa):
        self.hab = hab
        self.watcher = watcher
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.reps = reps if reps is not None else decking.Deck()

        doers = [doing.doify(self.msgDo)]

        super(RotateResponseHandler, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Rotate identifier response.  Swap out the old watcher identifier for the new one.

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
                payload = msg["payload"]
                pre = msg["pre"]

                if pre.qb64 != self.watcher:
                    raise kering.ValidationError("watcher rotation response from {} is from incorrect watcher {}"
                                                 "".format(pre.qb64, self.watcher))

                icp = payload["icp"]

                ctrlKvy = eventing.Kevery(db=self.hab.db)
                parsing.Parser().parse(ims=bytearray(icp.encode("utf-8")), kvy=ctrlKvy)

                srdr = coring.Serder(raw=bytearray(icp.encode("utf-8")))
                wat = srdr.pre

                habr = self.hab.db.habs.get(self.hab.name)
                ewats = set(habr.watchers)

                ewats.remove(self.watcher)
                ewats.add(wat)

                habr.watchers = list(ewats)

                self.hab.db.habs.pin(self.hab.name, habr)

                self.reps.append("ok")
                yield
            yield
