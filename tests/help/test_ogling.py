# -*- encoding: utf-8 -*-
"""
tests.help.test_ogling module

"""
import pytest

import logging
from keri.help import ogling

def test_oglery():
    """
    Test  Loggery class instance builds loggers
    """

    oglery = ogling.Oglery()

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

    """End Test"""


if __name__ == "__main__":
    test_oglery()

