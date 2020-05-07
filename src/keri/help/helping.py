# -*- encoding: utf-8 -*-
"""
keri.help.helping module

"""


import os
import shutil
import tempfile


def cleanupBaseDir(baseDirPath):
    """
    Remove baseDirPath
    """
    if os.path.exists(baseDirPath):
        shutil.rmtree(baseDirPath)


def setupTmpBaseDir(baseDirPath=""):
    """
    Create temporary directory
    """
    if not baseDirPath: # create temp directory at /tmp/keri...test
        baseDirPath = tempfile.mkdtemp(prefix="keri",  suffix="test", dir="/tmp")
    baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
    return baseDirPath

def cleanupTmpBaseDir(baseDirPath):
    """
    Remove temporary root of baseDirPath
    Ascend tree to find temporary root directory
    """
    if os.path.exists(baseDirPath):
        while baseDirPath.startswith("/tmp/keri"):
            if baseDirPath.endswith("test"):
                shutil.rmtree(baseDirPath)
                break
            baseDirPath = os.path.dirname(baseDirPath)


import pytest

@pytest.fixture(autouse=True)
def setupTeardown():
    """
    Pytest runs this function before every test when autouse=True
    Without autouse=True you would have to add a setupTeardown parameter
    to each test function
    """
    #setup
    DB_DIR_PATH = "/tmp/db_setup_test"
    yield DB_DIR_PATH  # this allows the test to run

    # teardown
    cleanupBaseDir(DB_DIR_PATH)
    assert not os.path.exists(DB_DIR_PATH)
