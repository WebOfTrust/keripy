# -*- encoding: utf-8 -*-
"""
tests.help.test_ogling module

"""
import pytest

import os
import logging
from keri.help import ogling

def test_oglery():
    """
    Test  Loggery class instance builds loggers
    """

    oglery = ogling.Oglery(name="test")
    assert oglery.path is None

    blogger, flogger = oglery.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    oglery.level = logging.DEBUG
    blogger, flogger = oglery.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    oglery = ogling.Oglery(name="test", level=logging.DEBUG, temp=True, reopen=True)
    assert oglery.path.endswith("_test/keri/log/test.log")
    blogger, flogger = oglery.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    oglery.close()
    assert not os.path.exists(oglery.path)

    oglery.reopen(temp=True)
    assert oglery.path.endswith("_test/keri/log/test.log")
    blogger, flogger = oglery.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    oglery.close()
    assert not os.path.exists(oglery.path)

    """End Test"""


if __name__ == "__main__":
    test_oglery()

