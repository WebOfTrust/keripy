# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import dataclasses
from multiprocessing import Process

import daemon
from daemon import pidfile
from hio import help
from hio.base import doing
from hio.core.http import clienting

from keri.app.cli.serving import Serving
from keri.db import koming, basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize the KLI server process')
parser.set_defaults(handler=lambda args: handle(args=args),
                    foreground=False)
parser.add_argument('--foreground', '-f', dest='foreground', action='store_true')


@dataclasses.dataclass
class KLIRecord:
    exists: bool


def handle(args):
    daemonDoer(name='kli-serving')

    initist = Initist(name='kli-serving', foreground=args.foreground, tyme=0.03125)
    initist.do()


def daemonDoer(name):
    db = basing.Baser(name, temp=False)
    klis = koming.Komer(db=db, schema=KLIRecord, subkey='klis.')
    klis.put((name,), KLIRecord(
        exists=True
    ))

    print("Initializing KLI Server")
    serving = Serving(tyme=0.03125)

    p = Process(target=serving.do)
    p.start()
    print("p started")


class Initist(doing.Doist):
    def __init__(self, name: str, foreground: bool, **kwa):
        super(Initist, self).__init__(**kwa)
        self.name = name
        self.foreground = foreground

        self.client = clienting.Client(port=5678)
        clientDoer = clienting.ClientDoer(client=self.client)

        self.extend([clientDoer, self.connectionCheckDoer])

    def do(self, doers=None, limit=None, tyme=None):
        print(doers)
        return super().do(doers, limit, tyme)

    @doing.doize()
    def connectionCheckDoer(self, tymth=None, tock=0.0, **opts):
        print("dodododo", self.client)
        if self.client is not None:
            print(self.client, self.client.connector, self.client.connector.connected)
            while not self.client.connector.connected:
                logger.info("waiting for connection to remote\n\n")
                yield self.tock
