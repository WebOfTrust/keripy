# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""

import argparse

from keri.app import habbing, indirecting, directing, configing
from keri.app.cli.common import oobiing
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

    with habbing.openHby(name="wan", salt=Salter(raw=b'wann-the-witness').qb64, temp=False, cf=wancf) as wanHby, \
            habbing.openHby(name="wil", salt=Salter(raw=b'will-the-witness').qb64, temp=False, cf=wilcf) as wilHby, \
            habbing.openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, temp=False, cf=wescf) as wesHby:
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        doers = wanDoers + wilDoers + wesDoers

        directing.runController(doers, expire=0.0)
