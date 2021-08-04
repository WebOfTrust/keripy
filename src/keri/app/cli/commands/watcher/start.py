# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse
import sys

from hio.base import doing
from hio.core.tcp import clienting

from keri.app import habbing
from keri.app.cli.commands.init import KLIRecord
from keri.db import koming
from keri.peer import exchanging

parser = argparse.ArgumentParser(description='Start watcher')
parser.set_defaults(handler=lambda args: handler())


def handler():
    startIst = StartIst(tock=0.03125)
    startIst.do()

    return


class StartIst(doing.Doist):

    def __init__(self, real=False, limit=None, doers=None, **kwa):
        self.hab = habbing.Habitat(name='kli', temp=False)
        kli = koming.Komer(db=self.hab.db, schema=KLIRecord, subkey='kli.').get((self.hab.pre,))

        super().__init__(real, limit, doers, **kwa)

        self.client = clienting.Client(tymth=self.tymen(), host='127.0.0.1', port=5678)
        clientDoer = clienting.ClientDoer(client=self.client)

        self.extend([clientDoer, doing.doify(self.infoDoer)])


    def infoDoer(self, tymth=None, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        while not self.client.connected:
            (yield self.tock)

        print("connected")
        payload = dict(
            cmd='watcher',
            args=('start',),
        )

        srdr = exchanging.exchange(route="/cmd/", payload=payload)
        excMsg = self.hab.sanction(srdr)

        self.client.tx(excMsg)
        self.client.close()

        print("watcher start command sent")
        sys.exit(0)
