# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import dataclasses
import daemonocle

from hio import help
from hio.base import doing
from hio.core.tcp import clienting

from keri.app.cli.serving import Serving
from keri.db import koming, basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize the KLI server process')
parser.set_defaults(handler=lambda args: handle(args=args),
                    foreground=False)
parser.add_argument('--foreground', '-f', dest='foreground', action='store_false')


@dataclasses.dataclass
class KLIRecord:
    exists: bool


def handle(args):
    daemonDoer(name='kli-serving', detach=args.foreground)
    Initist(name='kli-serving', foreground=args.foreground, tyme=0.03125).do()


def daemonDoer(name, detach):
    db = basing.Baser(name, temp=False)
    klis = koming.Komer(db=db, schema=KLIRecord, subkey='klis.')
    klis.put((name,), KLIRecord(
        exists=True
    ))

    print("Initializing KLI Server")
    serving = Serving(tyme=0.03125)

    daemon = daemonocle.Daemon(
        worker=serving.do,
        pid_file='/tmp/klid.pid',
        # detach=detach,
    )
    daemon.do_action('start')


class Initist(doing.Doist):
    def __init__(self, name: str, foreground: bool, **kwa):
        super(Initist, self).__init__(**kwa)
        self.name = name
        self.foreground = foreground

        self.client = clienting.Client(tymth=self.tymen(), port=5678)
        clientDoer = clienting.ClientDoer(tymth=self.tymen(), client=self.client)

        self.extend([clientDoer, self.connectionCheckDoer])

    @doing.doize()
    def connectionCheckDoer(self, tymth=None, tock=0.0, **opts):
        if self.client is not None:
            while not self.client.connected:
                logger.info("waiting for connection to remote\n\n")
                yield self.tock

        self.client.tx('poop')
