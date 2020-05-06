# -*- encoding: utf-8 -*-
"""
keri.core.dbing module

"""
import os
import lmdb


try:
    import simplejson as json
except ImportError:
    import json



MAX_DB_COUNT = 8

DATABASE_DIR_PATH = "/var/keri/db"  # default
ALT_DATABASE_DIR_PATH = os.path.join('~', '.keri/db')  #  when /var not permitted

DB_KEY_EVENT_LOG_NAME = b'kel'


keriDbDirPath = None   # database directory location has not been set up yet
keriDB = None    # database environment has not been set up yet

from  ..help.helping import setupTmpBaseDir

from  ..kering import  KeriError

class DatabaseError(KeriError):
    """
    Database related errors
    Usage:
        raise DatabaseError("error message")
    """



def setupDbEnv(baseDirPath=None, port=8080):
    """
    Setup the module globals keriDbDirPath, and keriDB using baseDirPath
    if provided otherwise use DATABASE_DIR_PATH
    Fallback is ALT_DATABASE_DIR_PATH
    :param port: int
        used to differentiate dbs for multiple servers running on the same computer
    :param baseDirPath: string
        directory where the database is located
    """
    global keriDbDirPath, keriDB

    if not baseDirPath:
        baseDirPath = "{}{}".format(DATABASE_DIR_PATH, port)

    baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
    if not os.path.exists(baseDirPath):
        try:
            os.makedirs(baseDirPath)
        except OSError as ex:
            baseDirPath = "{}{}".format(ALT_DATABASE_DIR_PATH, port)
            baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
            if not os.path.exists(baseDirPath):
                os.makedirs(baseDirPath)
    else:
        if not os.access(baseDirPath, os.R_OK | os.W_OK):
            baseDirPath = "{}{}".format(ALT_DATABASE_DIR_PATH, port)
            baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
            if not os.path.exists(baseDirPath):
                os.makedirs(baseDirPath)

    keriDbDirPath = baseDirPath  # set global db directory path

    # open lmdb database
    # creates files data.mdb and lock.mdb in dbBaseDirPath
    keriDB = lmdb.open(keriDbDirPath, max_dbs=MAX_DB_COUNT)  # set global

    # create named dbs  (core and tables)
    keriDB.open_db(DB_KEY_EVENT_LOG_NAME)  #  open KEL

    return keriDB


def setupTestDbEnv():
    """
    Return dbEnv resulting from baseDirpath in temporary directory
    and then setupDbEnv
    """
    baseDirPath = setupTmpBaseDir()
    baseDirPath = os.path.join(baseDirPath, "db/keri")
    os.makedirs(baseDirPath)
    return setupDbEnv(baseDirPath=baseDirPath)
