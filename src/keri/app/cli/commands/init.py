# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
from dataclasses import dataclass

import daemonocle

from keri.app import habbing
from keri.app.cli.serving import Serving
from keri.db import koming

# logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize the KLI server process')
parser.set_defaults(handler=lambda args: handle(args=args),
                    foreground=False)
parser.add_argument('--foreground', '-f', dest='foreground', action='store_false')


@dataclass
class KLIRecord:
    publicKey: str
    host: str
    port: int


def handle(args):
    print(args)

    hab = habbing.Habitat(name='kli', temp=False)

    pk = hab.kever.verfers[0].qb64
    serving = Serving(tyme=0.03125, publicKey=pk)
    pidPath = serving.getPIDPath()

    klis = koming.Komer(db=hab.db, schema=KLIRecord, subkey='kli.')
    klis.put((hab.pre,), KLIRecord(
        publicKey=pk,
        host='127.0.0.1',
        port=5678,
    ))

    print(pidPath, pk)

    daemon = daemonocle.Daemon(
        worker=serving.do,
        # update to keri path
        pid_file='/tmp/klid.pid',
        # detach=detach,
    )
    daemon.do_action('start')
