"""
Configure PyTest

Use this module to configure pytest
https://docs.pytest.org/en/latest/pythonpath.html

"""

import os

import pytest

from keri.help.helping import cleanupBaseDir

#@pytest.fixture(autouse=True)
#def setupTeardown():
    #"""
    #Pytest runs this function before every test when autouse=True
    #Without autouse=True you would have to add a setupTeardown parameter
    #to each test function
    #"""
    ##setup
    #DB_DIR_PATH = "/tmp/keri_db_setup_test"
    #yield DB_DIR_PATH  # this allows the test to run

    ## teardown
    #cleanupBaseDir(DB_DIR_PATH)
    #assert not os.path.exists(DB_DIR_PATH)
