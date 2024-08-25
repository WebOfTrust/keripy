# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import os
import os.path

import falcon
from hio import help
from hio.core.uxd import Server, ServerDoer
from hio.help import decking

from keri import kering
from keri.app import habbing, directing
from keri.app.cli.common import existing

from keri.app.listening import Authenticator, IdentifiersHandler, UnlockHandler, SignHandler
logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Run Unix domain sockets server listening for browser support')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
# parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
# parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def loadHandlers(hby, cues):
    ids = IdentifiersHandler(cues=cues, base=hby.base)
    hby.exc.addHandler(ids)
    unlock = UnlockHandler(cues=cues, base=hby.base)
    hby.exc.addHandler(unlock)
    sign = SignHandler(cues=cues, base=hby.base)
    hby.exc.addHandler(sign)

def handler(args):
    """ Command line list handler

    """
    hby = existing.setupHby(name="listener", base=args.base, bran=args.bran)
    hab = hby.habByName("listener")

    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    cues = decking.Deck()
    loadHandlers(hby, cues)

    if os.path.exists("/tmp/keripy_kli.s"):
        os.remove("/tmp/keripy_kli.s")

    server = Server(path="/tmp/keripy_kli.s",
                            bufsize=8069)
    serverDoer = ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server, exchanger=hby.exc, cues=cues)

    return [directant, serverDoer, hbyDoer]