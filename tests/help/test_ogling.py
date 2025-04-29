# -*- encoding: utf-8 -*-
"""
tests.help.test_ogling module

"""
import tempfile

import pytest

import os
import platform
import logging

from hio.help import ogling

from keri import help


def test_openogler():
    """
    Test context manager openOgler
    """
    # used context manager to directly open an ogler  Because loggers are singletons
    # it still affects loggers.

    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()

    with ogling.openOgler(prefix='keri', level=logging.DEBUG) as ogler:  # default is temp = True
        assert isinstance(ogler, ogling.Ogler)
        assert ogler.name == "test"
        assert ogler.level == logging.DEBUG
        assert ogler.temp == True
        assert ogler.prefix == 'keri'
        assert ogler.headDirPath == ogler.HeadDirPath == os.path.join(os.path.sep, "usr", "local", "var")
        assert ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
        assert ogler.dirPath.endswith("_temp")
        assert ogler.path.endswith(os.path.join(os.path.sep, "test.log"))
        assert ogler.opened

        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        if platform.system() == "Windows":
            assert len(logger.handlers) == 2
        else:
            assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")


        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('keri: Test logger at debug level\n'
                                'keri: Test logger at info level\n'
                                'keri: Test logger at error level\n')


        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        if platform.system() == "Windows":
            assert len(logger.handlers) == 2
        else:
            assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")

        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('keri: Test logger at debug level\n'
                                'keri: Test logger at info level\n'
                                'keri: Test logger at error level\n'
                                'keri: Test logger at debug level\n'
                                'keri: Test logger at info level\n'
                                'keri: Test logger at error level\n')

    assert not ogler.opened
    help.ogler.resetLevel(level=help.ogler.level)


    with ogling.openOgler(name='mine', prefix='keri', temp=False, level=logging.DEBUG) as ogler:
        assert isinstance(ogler, ogling.Ogler)
        assert ogler.name == "mine"
        assert ogler.level == logging.DEBUG
        assert ogler.temp == False
        assert ogler.prefix == 'keri'
        assert ogler.headDirPath == ogler.HeadDirPath == os.path.join(os.path.sep, "usr", "local", "var")
        assert ogler.dirPath.endswith(os.path.join("keri", "logs"))
        assert ogler.path.endswith(os.path.join(os.path.sep, 'mine.log'))
        assert ogler.opened

        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        if platform.system() == "Windows":
            assert len(logger.handlers) == 2
        else:
            assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")


        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('keri: Test logger at debug level\n'
                                'keri: Test logger at info level\n'
                                'keri: Test logger at error level\n')


        # logger console: All should log  because level DEBUG
        # logger file: All should log because path created and DEBUG
        logger = ogler.getLogger()
        if platform.system() == "Windows":
            assert len(logger.handlers) == 2
        else:
            assert len(logger.handlers) == 3
        logger.debug("Test logger at debug level")
        logger.info("Test logger at info level")
        logger.error("Test logger at error level")

        with open(ogler.path, 'r') as logfile:
            contents = logfile.read()
            assert contents == ('keri: Test logger at debug level\n'
                                'keri: Test logger at info level\n'
                                'keri: Test logger at error level\n'
                                'keri: Test logger at debug level\n'
                                'keri: Test logger at info level\n'
                                'keri: Test logger at error level\n')

    assert not ogler.opened
    assert os.path.exists(ogler.path)
    os.remove(ogler.path)
    assert not os.path.exists(ogler.path)
    help.ogler.resetLevel(level=help.ogler.level)

    """End Test"""


def test_ogler():
    """
    Test Ogler class instance that builds loggers
    """
    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()
    ogler = ogling.Ogler(name="test", prefix="keri")
    assert ogler.path is None
    assert ogler.opened == False
    assert ogler.level == logging.ERROR  # default is ERROR
    assert ogler.dirPath == None
    assert ogler.path == None

    # logger console: Only Error should log  because level ERROR
    # logger file: Nothing should log because .path not created
    logger = ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 1
    else:
        assert len(logger.handlers) == 2
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")


    ogler.level = logging.DEBUG
    # logger console: All should log  because level DEBUG
    # logger file: nothing should log because .path still not created
    logger = ogler.getLogger()
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    # create ogler with opened path
    ogler = ogling.Ogler(name="test", level=logging.DEBUG, temp=True,
                         prefix='keri', reopen=True, clear=True)
    assert ogler.level == logging.DEBUG
    assert ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith(os.path.join(os.path.sep, "test.log"))
    assert ogler.opened == True
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # logger console: All should log  because level DEBUG
    # logger file: All should log because path created and DEBUG
    logger = ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')

    ogler.temp = False  # trick it to not clear on close
    ogler.close()  # but do not clear
    assert os.path.exists(ogler.path)
    assert ogler.opened == False
    ogler.temp = True  # restore state

    # Test reopen but not clear so file still there
    ogler.reopen(temp=True)
    assert ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith(os.path.join(os.path.sep, "test.log"))
    assert ogler.opened == True
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')

    # logger console: All should log  because level DEBUG
    # logger file: All should log because path created and DEBUG
    logger = ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n'
                            'keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')


    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)
    assert ogler.opened == False

    help.ogler = ogling.initOgler(prefix='keri')  # reset help.ogler to defaults
    """End Test"""


def test_init_ogler():
    """
    Test initOgler function for ogler global
    """
    #defined by default in help.__init__ on import of ogling
    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()
    assert isinstance(help.ogler, ogling.Ogler)
    assert not help.ogler.opened
    assert help.ogler.level == logging.CRITICAL  # default
    assert help.ogler.dirPath == None
    assert help.ogler.path == None
    logger = help.ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 1
    else:
        assert len(logger.handlers) == 2

    # nothing should log to file because .path not created and level critical
    # # nothing should log to console because level critical
    logger = help.ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 1
    else:
        assert len(logger.handlers) == 2
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    help.ogler.level = logging.DEBUG
    # nothing should log because .path not created despite loggin level debug
    logger = help.ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 1
    else:
        assert len(logger.handlers) == 2
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    #reopen ogler to create path
    help.ogler.reopen(temp=True, clear=True)
    assert help.ogler.opened
    assert help.ogler.level == logging.DEBUG
    assert help.ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
    assert help.ogler.dirPath.endswith("_temp")
    assert help.ogler.path.endswith(os.path.join(os.path.sep, "main.log"))
    logger = help.ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(help.ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')

    ogler = help.ogler = ogling.initOgler(name="test", level=logging.DEBUG,
                        temp=True, prefix='keri', reopen=True, clear=True)
    assert ogler.opened
    assert ogler.level == logging.DEBUG
    assert ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith(os.path.join(os.path.sep, "test.log"))
    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    logger = ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3

    # logger console: All should log  because level DEBUG
    # logger file: All should log because new path on file handler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')

    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)

    help.ogler = ogling.initOgler(prefix='keri')  # reset help.ogler to defaults
    """End Test"""


def test_reset_levels():
    """
    Test resetLevel on preexisting loggers
    """
    #defined by default in help.__init__ on import of ogling
    tempDirPath = os.path.join(os.path.sep, "tmp") if platform.system() == "Darwin" else tempfile.gettempdir()
    assert isinstance(help.ogler, ogling.Ogler)
    assert not help.ogler.opened
    assert help.ogler.level == logging.CRITICAL  # default
    assert help.ogler.path == None
    logger = help.ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 1
    else:
        assert len(logger.handlers) == 2

    # logger console: nothing should log  because level CRITICAL
    # logger file: nothing should log because .path not created
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    # test reset levels without recreating logger
    help.ogler.resetLevel(level=logging.DEBUG, globally=True)

    # logger console: All should log  because level DEBUG
    # logger file: Nothing should log because .path not created
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    # reopen ogler to create path
    help.ogler.reopen(temp=True, clear=True)
    assert help.ogler.opened
    assert help.ogler.level == logging.DEBUG
    assert help.ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
    assert help.ogler.dirPath.endswith("_temp")
    assert help.ogler.path.endswith(os.path.join(os.path.sep, "main.log"))
    # recreate loggers to pick up file handler
    logger = help.ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3

    # logger console: All should log  because level DEBUG
    # logger file: All should log because .path created
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(help.ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')


    # force reinit on different path
    ogler = help.ogler = ogling.initOgler(name="test", level=logging.DEBUG,
                            temp=True, prefix='keri', reopen=True, clear=True)
    assert ogler.opened
    assert ogler.level == logging.DEBUG
    assert ogler.path.startswith(os.path.join(tempDirPath, "keri", "logs", "test_"))
    assert ogler.dirPath.endswith("_temp")
    assert ogler.path.endswith(os.path.join(os.path.sep, "test.log"))
    # Still have 3 handlers
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # logger console: All should log  because level DEBUG
    # logger file: None should log because old path on file handler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ''

    # recreate loggers to pick up new path
    logger = ogler.getLogger()
    if platform.system() == "Windows":
        assert len(logger.handlers) == 2
    else:
        assert len(logger.handlers) == 3

    # logger console: All should log  because level DEBUG
    # logger file: All should log because new path on file handler
    logger.debug("Test logger at debug level")
    logger.info("Test logger at info level")
    logger.error("Test logger at error level")

    with open(ogler.path, 'r') as logfile:
        contents = logfile.read()
        assert contents == ('keri: Test logger at debug level\n'
                            'keri: Test logger at info level\n'
                            'keri: Test logger at error level\n')

    path = ogler.path
    ogler.close(clear=True)
    assert not os.path.exists(path)

    help.ogler = ogling.initOgler(prefix='keri')  # reset help.ogler to defaults
    """End Test"""


if __name__ == "__main__":
    test_openogler()
    test_ogler()
    test_init_ogler()
    test_reset_levels()

