# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse

from hio.base import doing
from hio.core.tcp import clienting

from keri.app import habbing
from keri.app.cli.commands.init import KLIRecord
from keri.db import koming

parser = argparse.ArgumentParser(description='Start watcher')
parser.set_defaults(handler=lambda args: handler())


def handler():
    infoIst = InfoIst(tock=0.03125)
    infoIst.do()

    return


class InfoIst(doing.Doist):

    def __init__(self, real=False, limit=None, doers=None, **kwa):
        self.hab = habbing.Habitat(name='kli', temp=False)
        kli = koming.Komer(db=self.hab.db, schema=KLIRecord, subkey='kli.').get((self.hab.pre,))

        print(kli.host, kli.port)

        super().__init__(real, limit, doers, **kwa)

        self.client = clienting.Client(tymth=self.tymen(), host='127.0.0.1', port=5678)
        clientDoer = clienting.ClientDoer(client=self.client)

        self.extend([clientDoer, self.infoDoer])

    @doing.doize()
    def infoDoer(self, tymth=None, tock=0.0, **opts):
        while not self.client.connected:
            (yield self.tock)

        msg = dict(
            cmd='watcher',
            args=('start',),
        )

        self.hab.endorse(msg)

        self.client.tx(msg)

        self.client.close()
