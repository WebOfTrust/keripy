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

