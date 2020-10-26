# -*- encoding: utf-8 -*-
"""
tests.db.doing module

"""
import pytest

import os

from hio.base import doing
from keri.db import dbing




def test_loggerdoer():
    """
    Test LoggerDoer


    """
    lgr0 = dbing.Logger(name='test0', temp=True, reopen=False)
    assert lgr0.opened == False
    assert lgr0.path == None
    assert lgr0.env == None

    lgrDoer0 = dbing.LoggerDoer(logger=lgr0)
    assert lgrDoer0.logger == lgr0
    assert lgrDoer0.logger.opened == False

    lgr1 = dbing.Logger(name='test1', temp=True, reopen=False)
    assert lgr1.opened == False
    assert lgr1.path == None
    assert lgr1.env == None

    lgrDoer1 = dbing.LoggerDoer(logger=lgr1)
    assert lgrDoer1.logger == lgr1
    assert lgrDoer1.logger.opened == False

    limit = 0.25
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock)

    doers = [lgrDoer0, lgrDoer1]

    dogs = doist.ready(doers=doers)
    assert len(dogs) == 2
    assert [val[1] for val in dogs] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer._tymist == doist
        assert doer.logger.opened
        assert "_test/keri/db/test" in doer.logger.path

    doist.once(dogs)
    assert doist.tyme == 0.03125  # on next cycle
    assert len(dogs) == 2
    for doer in doers:
        assert doer.logger.opened == True

    for dog, retyme in dogs:
        dog.close()

    for doer in doers:
        assert doer.logger.opened == False
        assert doer.logger.env == None
        assert not os.path.exists(doer.logger.path)



    #start over
    doist.tyme = 0.0
    doist.do(doers=doers)
    assert doist.tyme == limit
    for doer in doers:
        assert doer.logger.opened == False
        assert doer.logger.env == None
        assert not os.path.exists(doer.logger.path)

    """End Test"""



if __name__ == "__main__":
    test_loggerdoer()
