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
    assert ogler.level == logging.ERROR  # default is ERROR
    assert ogler.path == None

    # nothing should log to file because .path not created
    # nothing should log to console because level critical
    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")

    # console should log because error is at ogler.level == ERROR
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")  # flogger override level is error

    # nothing should log  to file because .path still not created
    # but all blogger should log to console because because logging level is now DEBUG
    #  only flogger error should log to console because flogger override level is ERROR
    ogler.level = logging.DEBUG
    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")  # flogger override level is error not log
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")  # flogger override level is error not log
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")  # flogger override level is error so log

    ogler = ogling.Ogler(name="test", level=logging.DEBUG, temp=True,
                         reopen=True, clear=True)
    assert ogler.level == logging.DEBUG
    assert ogler.path.endswith("_test/keri/log/test.log")
    assert ogler.opened == True
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # Should log to both file and console since path created flogger still uses ERRROR
    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")  # flogger override level is error not log
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")  # flogger override level is error not log
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")  # flogger override level is error so log

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('Test blogger at debug level\n'
                            'Test blogger at info level\n'
                            'Test blogger at error level\n'
                            '***Fail: Test flogger at error level\n')

    ogler.close()  # but do not clear
    assert os.path.exists(ogler.path)
    assert ogler.opened == False

    ogler.reopen(temp=True)
    assert ogler.path.endswith("_test/keri/log/test.log")
    assert ogler.opened == True
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('Test blogger at debug level\n'
                            'Test blogger at info level\n'
                            'Test blogger at error level\n'
                            '***Fail: Test flogger at error level\n')

    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")  # flogger override level is error not log
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")  # flogger override level is error not log
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")  # flogger override level is error so log

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('Test blogger at debug level\n'
                            'Test blogger at info level\n'
                            'Test blogger at error level\n'
                            '***Fail: Test flogger at error level\n'
                            'Test blogger at debug level\n'
                            'Test blogger at info level\n'
                            'Test blogger at error level\n'
                            '***Fail: Test flogger at error level\n')

    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)
    assert ogler.opened == False
    ogling.ogler.level = logging.CRITICAL
    """End Test"""

def test_init_ogler():
    """
    Test initOgler function for ogler global
    """
    #defined by default in help.__init__ on import of ogling
    assert isinstance(ogling.ogler, ogling.Ogler)
    assert not ogling.ogler.opened
    assert ogling.ogler.level == logging.CRITICAL  # default
    assert ogling.ogler.path == None

    # nothing should log to file because .path not created and level critical
    # # nothing should log to console because level critical
    blogger, flogger = ogling.ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    ogling.ogler.level = logging.DEBUG
    # nothing should log because .path not created despite loggin level debug
    blogger, flogger = ogling.ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")  # flogger override level is error not log
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")  # flogger override level is error not log
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")  # flogger override level is error so log

    #reopen ogler to create path
    ogling.ogler.reopen(temp=True, clear=True)
    assert ogling.ogler.opened
    assert ogling.ogler.level == logging.DEBUG
    assert ogling.ogler.path.endswith("_test/keri/log/main.log")
    blogger, flogger = ogling.ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")  # flogger override level is error not log
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")  # flogger override level is error not log
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")  # flogger override level is error so log

    with open(ogling.ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('Test blogger at debug level\n'
                            'Test blogger at info level\n'
                            'Test blogger at error level\n'
                            '***Fail: Test flogger at error level\n')


    # force reinit
    ogling.ogler =  None
    ogler = ogling.initOgler(name="test", level=logging.DEBUG, temp=True,
                             reopen=True, clear=True)
    assert ogler == ogling.ogler
    assert ogler.opened
    assert ogler.level == logging.DEBUG
    assert ogler.path.endswith("_test/keri/log/test.log")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    blogger, flogger = ogler.getLoggers()
    blogger.debug("Test blogger at debug level")
    flogger.debug("Test flogger at debug level")
    blogger.info("Test blogger at info level")
    flogger.info("Test flogger at info level")
    blogger.error("Test blogger at error level")
    flogger.error("Test flogger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('Test blogger at debug level\n'
                            'Test blogger at info level\n'
                            'Test blogger at error level\n'
                            '***Fail: Test flogger at error level\n')

    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)
    ogler.level = logging.CRITICAL  # restore
    """End Test"""


if __name__ == "__main__":
    test_init_ogler()

