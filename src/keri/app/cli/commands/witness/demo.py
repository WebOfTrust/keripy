# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""

import argparse
import logging

from hio.base import doing

from keri import help

from keri.app import habbing, indirecting, configing

from keri.core import Salter


parser = argparse.ArgumentParser(description="Run a demo collection of witnesses")
parser.set_defaults(handler=lambda args: demo(args))


help.ogler.level = logging.INFO
logger = help.ogler.getLogger()


def demo(_):
    """
    Run set of three witnesses for demo

    """

    wancf = configing.Configer(name="wan", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wilcf = configing.Configer(name="wil", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wescf = configing.Configer(name="wes", headDirPath="scripts", temp=False, reopen=True, clear=False)
    witcf = configing.Configer(name="wit", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wubcf = configing.Configer(name="wub", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wyzcf = configing.Configer(name="wyz", headDirPath="scripts", temp=False, reopen=True, clear=False)

    wanHby = habbing.Habery(name="wan", salt=Salter(raw=b'wann-the-witness').qb64, temp=False, cf=wancf)
    wilHby = habbing.Habery(name="wil", salt=Salter(raw=b'will-the-witness').qb64, temp=False, cf=wilcf)
    wesHby = habbing.Habery(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=False, cf=wescf)
    witHby = habbing.Habery(name="wit", salt=Salter(raw=b'witn-the-witness').qb64, temp=False, cf=witcf)
    wubHby = habbing.Habery(name="wub", salt=Salter(raw=b'wubl-the-witness').qb64, temp=False, cf=wubcf)
    wyzHby = habbing.Habery(name="wyz", salt=Salter(raw=b'wyzs-the-witness').qb64, temp=False, cf=wyzcf)

    doers = [InitDoer(wan=wanHby, wil=wilHby, wes=wesHby, wit=witHby, wub=wubHby, wyz=wyzHby)]

    return doers


class InitDoer(doing.DoDoer):

    def __init__(self, wan, wil, wes, wit, wub, wyz):
        self.wan = wan
        self.wil = wil
        self.wes = wes
        self.wit = wit
        self.wub = wub
        self.wyz = wyz

        super(InitDoer, self).__init__(doers=[doing.doify(self.initialize)])

    def initialize(self, tymth, tock=0.0):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        wanDoers = indirecting.setupWitness(alias="wan", hby=self.wan, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=self.wil, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=self.wes, tcpPort=5634, httpPort=5644)

        witDoers = indirecting.setupWitness(alias="wit", hby=self.wit, tcpPort=5635, httpPort=5645)
        wubDoers = indirecting.setupWitness(alias="wub", hby=self.wub, tcpPort=5636, httpPort=5646)
        wyzDoers = indirecting.setupWitness(alias="wyz", hby=self.wyz, tcpPort=5637, httpPort=5647)

        self.extend(wanDoers + wilDoers + wesDoers + witDoers + wubDoers + wyzDoers)
