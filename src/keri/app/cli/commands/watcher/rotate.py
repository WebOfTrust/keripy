# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse
import json

from hio.base import doing
from hio.core.http import clienting
from hio.help import decking

from keri import help, kering
from keri.app import directing, obtaining
from keri.app.cli.common import existing
from keri.core import eventing, parsing, coring
from keri.end import ending

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

        self.toRemove = doers
        doers.extend([doing.doify(self.rotateDo)])
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


        payload = dict(pre=self.hab.pre)
        raw = json.dumps(payload)
        sigers = self.hab.mgr.sign(ser=raw.encode("utf-8"),
                                   verfers=self.hab.kever.verfers,
                                   indexed=True)

        signage = ending.Signage(markers=sigers, indexed=True)
        headers = ending.signature([signage])

        loc = obtaining.getwitnessbyprefix(self.watcher)
        client = clienting.Client(hostname=loc.ip4, port=loc.http)
        clientDoer = clienting.ClientDoer(client=client)
        self.extend([clientDoer])
        self.toRemove.extend([clientDoer])

        client.request(method="POST", path="/rotate", headers=headers, body=raw)
        while not client.responses:
            yield self.tock

        resp = client.respond()
        if resp.status != 200:
            print("Invalid status from watcher:", type(resp.status))
            return

        if not self.authenticate(resp):
            print("Invalid response from watcher")
            return

        self.processWatcherResponse(bytes(resp.body))

        habr = self.hab.db.habs.get(self.hab.name)
        print("New Watcher Set:")
        for wat in habr.watchers:
            print("\t{}".format(wat))

        self.remove(self.toRemove)

    def processWatcherResponse(self, icp):
        ctrlKvy = eventing.Kevery(db=self.hab.db)
        parsing.Parser().parse(ims=bytearray(icp), kvy=ctrlKvy)

        srdr = coring.Serder(raw=bytearray(icp))
        wat = srdr.pre

        habr = self.hab.db.habs.get(self.hab.name)
        ewats = set(habr.watchers)

        ewats.remove(self.watcher)
        ewats.add(wat)

        habr.watchers = list(ewats)

        self.hab.db.habs.pin(self.hab.name, habr)

    def authenticate(self, resp):
        if "Signature" not in resp.headers:
            return False

        signages = ending.designature(resp.headers["Signature"])

        cigar = signages[0].markers[self.watcher]
        verfer = coring.Verfer(qb64=self.watcher)
        if not verfer.verify(cigar.raw, bytes(resp.body)):
            return False

        return True
