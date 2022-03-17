# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""

import argparse

from hio.base import doing

from keri.app import habbing, indirecting, configing
from keri.core.coring import Salter

parser = argparse.ArgumentParser(description="Run a demo collection of witnesses")
parser.set_defaults(handler=lambda args: demo(args))


# help.ogler.level = logging.INFO
# logger = help.ogler.getLogger()


def demo(_):
    """
    Run set of three witnesses for demo

    """

    wancf = configing.Configer(name="wan", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wilcf = configing.Configer(name="wil", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wescf = configing.Configer(name="wes", headDirPath="scripts", temp=False, reopen=True, clear=False)

    wanHby = habbing.Habery(name="wan", salt=Salter(raw=b'wann-the-witness').qb64, temp=False, cf=wancf)
    wilHby = habbing.Habery(name="wil", salt=Salter(raw=b'will-the-witness').qb64, temp=False, cf=wilcf)
    wesHby = habbing.Habery(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=False, cf=wescf)

    doers = [InitDoer(wan=wanHby, wil=wilHby, wes=wesHby)]

    return doers


class InitDoer(doing.DoDoer):

    def __init__(self, wan, wil, wes):
        self.wan = wan
        self.wil = wil
        self.wes = wes
        super(InitDoer, self).__init__(doers=[doing.doify(self.initialize)])

    def initialize(self, tymth, tock=0.0):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        wanDoers = indirecting.setupWitness(alias="wan", hby=self.wan, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=self.wil, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=self.wes, tcpPort=5634, httpPort=5644)

        self.extend(wanDoers + wilDoers + wesDoers)
