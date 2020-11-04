# -*- encoding: utf-8 -*-
"""
tests.help.test_ogling module

"""
import pytest

import logging
from keri.help import ogling

def test_loggery():
    """
    Test  Loggery class instance builds loggers
    """

    loggery = ogling.Loggery()

    blogger, flogger = loggery.getLoggers()
    blogger.debug("Test wooding standard logger at debug level")
    flogger.debug("Test wooding failure logger at debug level")
    blogger.info("Test wooding standard logger at info level")
    flogger.info("Test wooding failure logger at info level")
    blogger.error("Test wooding standard logger at error level")
    flogger.error("Test wooding failure logger at error level")

    loggery.level = logging.DEBUG
    blogger, flogger = loggery.getLoggers()
    blogger.debug("Test wooding standard logger at debug level")
    flogger.debug("Test wooding failure logger at debug level")
    blogger.info("Test wooding standard logger at info level")
    flogger.info("Test wooding failure logger at info level")
    blogger.error("Test wooding standard logger at error level")
    flogger.error("Test wooding failure logger at error level")

    #tlogger = logging.getLogger('Test_Wooding\n')
    #tlogger.setLevel(logging.DEBUG)
    #basicformatter = logging.Formatter('%(message)s')  # standard format
    #basicConsoleHandler = logging.StreamHandler()  # sys.stderr
    #basicConsoleHandler.setFormatter(basicformatter)
    #tlogger.addHandler(basicConsoleHandler)

    #tlogger.debug("Running Tests.")
    """End Test"""


if __name__ == "__main__":
    test_loggery()

