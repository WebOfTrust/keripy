# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing
from hio.core.tcp import clienting

from keri.app import habbing, keeping, directing
from keri.db import basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--target', '-t', help='Target port to send KEL to', default="", required=True)


def handler(args):
    name = args.name

    ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

    client = clienting.Client(host="", port=int(args.target))
    clientDoer = clienting.ClientDoer(client=client)
    sendDoer = SenderDoer(hab=hab, client=client)

    doers = [ksDoer, dbDoer, habDoer, sendDoer, clientDoer]
    directing.runController(doers=doers, expire=0.0)


class SenderDoer(doing.Doer):

    def __init__(self, client, hab: habbing.Habitat = None, **kwa):
        self.hab = hab
        self.client = client

        super(SenderDoer, self).__init__(**kwa)
        if self.tymth:
            self.client.wind(self.tymth)

    def do(self, tymth, tock=0.0, **opts):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        cloner = self.hab.db.clonePreIter(pre=self.hab.pre, fn=0)  # create iterator at 0
        msgs = bytearray()  # outgoing messages
        for msg in cloner:
            msgs.extend(msg)

        # send to connected peer remote
        self.client.tx(msgs)
        logger.info("%s: %s sent event:\n%s\n\n", self.hab.name, self.hab.pre, bytes(msgs))
        _ = (yield self.tock)

        return
