# -*- encoding: utf-8 -*-
"""
tests.help.test_ogling module

"""
import pytest

import os
import logging
from keri.help import ogling

def test_ogler():
    """
    Test Ogler class instance that builds loggers
    """

    ogler = ogling.Ogler(name="test")
    assert ogler.path is None
    assert ogler.opened == False

    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    ogler.level = logging.DEBUG
    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    ogler = ogling.Ogler(name="test", level=logging.DEBUG, temp=True, reopen=True)
    assert ogler.path.endswith("_test/keri/log/test.log")
    assert ogler.opened == True
    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    ogler.close()
    assert not os.path.exists(ogler.path)
    assert ogler.opened == False

    ogler.reopen(temp=True)
    assert ogler.path.endswith("_test/keri/log/test.log")
    assert ogler.opened == True
    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    ogler.close()
    assert not os.path.exists(ogler.path)
    assert ogler.opened == False

    """End Test"""

def test_init_ogler():
    """
    Test initOgler function for ogler global
    """
    #defined by default in help.__init__ on import of ogling
    assert isinstance(ogling.ogler, ogling.Ogler)
    assert not ogling.ogler.opened
    assert ogling.ogler.level == logging.CRITICAL  # default

    # nothing should log
    blogger, flogger = ogling.ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    # force reinit
    ogling.ogler =  None
    ogler = ogling.initOgler(name="test", level=logging.DEBUG, temp=True, reopen=True)
    assert ogler == ogling.ogler
    assert ogler.opened
    assert ogler.path.endswith("_test/keri/log/test.log")

    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    ogler.close()
    assert not os.path.exists(ogler.path)
    ogler.level = logging.CRITICAL  # restore
    """End Test"""


if __name__ == "__main__":
    test_init_ogler()

