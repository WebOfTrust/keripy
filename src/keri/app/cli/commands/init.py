# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
from dataclasses import dataclass

import daemonocle
from hio.base import doing
# logger = help.ogler.getLogger()
from hio.core.tcp import serving

from keri.app import habbing
from keri.app.cli.serving import Serving
from keri.db import koming

parser = argparse.ArgumentParser(description='Initialize the KLI Daemon')
parser.set_defaults(handler=lambda args: handle(args=args), foreground=False)
parser.add_argument('--foreground', '-f', dest='foreground', action='store_false')
parser.add_argument('-p', '--port', action='store', default=5678)


@dataclass
class KLIRecord:
    host: str
    port: int


EX_OK = 0
EX_GENERIC = 1


def handle(args):
    print(args)

    hab = habbing.Habitat(name='kli', temp=False)
    tock = 0.03125
    host = '127.0.0.1'
    port = args.port

    klis = koming.Komer(db=hab.db, schema=KLIRecord, subkey='kli.')
    klis.put((hab.pre,), KLIRecord(
        host=host,
        port=port,
    ))

    # doist = doing.Doist(tock=tock, real=True)
    # print("client", host, port)
    # client = clienting.Client(host=host, port=port, tymth=doist.tymen())
    # clientDoer = clienting.ClientDoer(client=client)
    # initDoer = InitDoer(client=client, tymth=doist.tymen())
    #
    # doist.doers = [clientDoer, initDoer]
    # doist.do()

    doist = doing.Doist(tock=tock, real=True)

    server = serving.Server(host='127.0.0.1', port=5678)
    serverDoer = serving.ServerDoer(server=server)

    servingDoDoer = Serving(server=server, doers=doist.doers)

    doist.extend([serverDoer, servingDoDoer])

    daemon = daemonocle.Daemon(
        worker=doist.do,
        # update to use pidPath serving.getPIDPath()
        pid_file='/tmp/klid.pid',
        # detach=detach,
    )
    daemon.do_action('start')


class InitDoer(doing.Doer):
    def __init__(self, client, tock=0.0, **kwa):
        super().__init__(tock, **kwa)
        print("init doer")
        self.client = client

    def do(self, tymth, tock=0.0, **opts):
        print("do")
        while not self.client.connected:
            print("not connected")
            (yield self.tock)

        self.client.tx(b'foo')

# def handle_daemon():
#     # do the UNIX double-fork magic, see Stevens' "Advanced
#     # Programming in the UNIX Environment" for details (ISBN 0201563177)
#     try:
#         pid = os.fork()
#         if pid > 0:
#             # exit first parent
#             sys.exit(0)
#     except OSError as e:
#         print("fork #1 failed")
#         sys.exit(1)
#
#     # decouple from parent environment
#     os.chdir("/")
#     os.setsid()
#     os.umask(0)
#
#     # do second fork
#     try:
#         pid = os.fork()
#         if pid > 0:
#             # exit from second parent, print eventual PID before
#             print("Daemon PID", pid)
#             sys.exit(0)
#     except OSError as e:
#         print("fork #2 failed")
#         sys.exit(1)
#
#     print("starting serving...")
#     # daemon
#     doist = doing.Doist(tock=0.03125, real=True)
#     serving = Serving(tymth=doist.tymen())
#     doist.do(doers=[serving])
