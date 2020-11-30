# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""

import pytest

from keri import kering
from keri.help import ogling
from keri.db import dbing
from keri.base import keeping
from keri.core import coring
from keri.core import eventing

blogger, flogger = ogling.ogler.getLoggers()


def test_delegation():
    """
    Test creation and validation of delegated identifer prefixes and events

    """
    # bob, and zoe are remote parties  del is delegated identifier
    # bob is the delegator del is the delegate


    with openDB("bob") as bobDB, openDB("zoe") as zoeDB:
        #  init Keverys
        bobKevery = Kevery(baser=bobDB)
        zoeKevery = Kevery(baser=zoeDB)


        #  init sequence numbers for all identifiers
        bsn = besn = 0  # sn and last establishment sn = esn
        zsn = zesn = 0  # sn and last establishment sn = esn
        dsn = desn = 0  # sn and last establishment sn = esn

        #
