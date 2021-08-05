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

parser = argparse.ArgumentParser(description='Send KEL to a target tcp endpoint')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--target', '-t', help='Target port to send KEL to', default="", required=True)


def handler(args):
    name = args.name

    sendDoer = SenderDoer(name=name, target=int(args.target))
    directing.runController(doers=[sendDoer], expire=0.0)


class SenderDoer(doing.DoDoer):

    def __init__(self, name, target: int, **kwa):
        ks = keeping.Keeper(name=name, temp=False)  # not opened by default, doer opens
        self.ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
        db = basing.Baser(name=name, temp=False, reload=True)  # not opened by default, doer opens
        self.dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

        self.hab = habbing.Habitat(name=name, ks=ks, db=db, temp=False, create=False)
        self.habDoer = habbing.HabitatDoer(habitat=self.hab)  # setup doer

        self.target = target
        self.client = clienting.Client(host="", port=self.target)
        self.clientDoer = clienting.ClientDoer(client=self.client)

        doers = [self.ksDoer, self.dbDoer, self.habDoer, doing.doify(self.sendDo), self.clientDoer]
        super(SenderDoer, self).__init__(doers=doers, **kwa)


    def sendDo(self, tymth, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
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
        _ = (yield self.tock)

        while not self.client.rxbs:
            yield self.tock

        print("KEL for {} sent to {}".format(self.hab.pre, self.target))

        self.remove([self.ksDoer, self.dbDoer, self.habDoer, self.clientDoer])

        return
