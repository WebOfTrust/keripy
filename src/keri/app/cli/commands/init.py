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

parser = argparse.ArgumentParser(description='Initialize the KLI Daemon')
parser.set_defaults(handler=lambda args: handle(args=args), foreground=False)
parser.add_argument('--foreground', '-f', dest='foreground', action='store_false')
parser.add_argument('-p', '--port', action='store', default=5678)


@dataclass
class KLIRecord:
    host: str
    port: int


def handle(args):
    print(args)

    hab = habbing.Habitat(name='kli', temp=False)

    serving = Serving(tyme=0.03125, verfers=hab.kever.verfers)

    klis = koming.Komer(db=hab.db, schema=KLIRecord, subkey='kli.')
    klis.put((hab.pre,), KLIRecord(
        host='127.0.0.1',
        port=args.port,
    ))

    daemon = daemonocle.Daemon(
        worker=serving.do,
        # update to use pidPath serving.getPIDPath()
        pid_file='/tmp/klid.pid',
        # detach=detach,
    )
    daemon.do_action('start')
