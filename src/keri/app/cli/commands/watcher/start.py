# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse

from hio.base import doing
from hio.core.tcp import clienting

from keri.app import habbing, keeping
from keri.app.cli.commands.init import KLIRecord
from keri.core import eventing, coring
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

        self.client = clienting.Client(tymth=self.tymen(), host=kli.host, port=kli.port)
        clientDoer = clienting.ClientDoer(client=self.client)

        self.extend([clientDoer, self.infoDoer])

    @doing.doize()
    def infoDoer(self, tymth=None, tock=0.0, **opts):
        while not self.client.connected:
            (yield self.tock)

        mgr = keeping.Manager(keeper=self.hab.ks)
        kvy = eventing.Kevery(db=self.hab.db)
        payload = dict(
            cmd='watcher',
            args=('start',),
        )

        exc = exchanging.Exchanger(kevers=kvy.kevers, tymth=self.tymen())
        behave = exchanging.Behavior(lambda payload, pre, sigers, verfers: None, None)
        exc.registerBehavior(route="/cmd", behave=behave)

        srdr = exchanging.exchange(route="/cmd/", payload=payload)
        sigers = mgr.sign(ser=srdr.raw, verfers=self.hab.kever.verfers)

        excMsg = bytearray(srdr.raw)
        excMsg.extend(coring.Counter(coring.CtrDex.SignerSealCouples, count=1).qb64b)
        excMsg.extend(self.hab.pre.encode("utf-8"))

        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        excMsg.extend(counter.qb64b)
        for siger in sigers:
            excMsg.extend(siger.qb64b)

        self.client.tx(excMsg)

        self.client.close()
