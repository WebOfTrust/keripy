# -*- encoding: utf-8 -*-
"""
keri.core.dbing module


import lmdb
db = lmdb.open("/tmp/keri_db_setup_test")
db.max_key_size()
511

# create named dbs  (core and tables)
    gDbEnv.open_db(b'core')
    gDbEnv.open_db(b'hid2did')  # table of dids keyed by hids
    gDbEnv.open_db(b'did2offer', dupsort=True)  # table of offer expirations keyed by offer relative dids
    gDbEnv.open_db(b'anon', dupsort=True)  # anonymous messages
    gDbEnv.open_db(b'expire2uid', dupsort=True)  # expiration to uid anon

The dupsort, integerkey, integerdup, and dupfixed parameters are ignored
if the database already exists.
The state of those settings are persistent and immutable per database.
See _Database.flags() to view the state of those options for an opened database.
A consequence of the immutability of these flags is that the default non-named
database will never have these flags set.

So only need to set dupsort first time opened each other opening does not
need to call it


May want to use buffers for reads of immutable serializations such as events
and sigs. Anything not read modify write but read only.

"{:032x}".format(1024)
'00000000000000000000000000000400'

h = ["00", "01", "02", "0a", "0f", "10", "1a", "11", "1f", "f0", "a0"]
h.sort()
h
['00', '01', '02', '0a', '0f', '10', '11', '1a', '1f', 'a0', 'f0']

l
['a', 'aa', 'b', 'ba', 'aaa', 'baa']
l.sort()
l
['a', 'aa', 'aaa', 'b', 'ba', 'baa']

"""
import os
import lmdb


try:
    import simplejson as json
except ImportError:
    import json



MAX_DB_COUNT = 8

DB_DIR_PATH = "/var/keri/db"  # default
ALT_DB_DIR_PATH = os.path.join('~', '.keri/db')  #  when /var not permitted

DB_KEY_EVENT_LOG_NAME = b'kel'


keriDbDirPath = None   # database directory location has not been set up yet
keriDBEnv = None    # database environment has not been set up yet

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

    Parameters:
        port is int used to differentiate dbs for multiple servers running
                    on the same computer
        baseDirPath is string pathname of directory where the database is located
    """
    global keriDbDirPath, keriDBEnv

    if not baseDirPath:
        baseDirPath = "{}{}".format(DB_DIR_PATH, port)

    baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
    if not os.path.exists(baseDirPath):
        try:
            os.makedirs(baseDirPath)
        except OSError as ex:
            baseDirPath = "{}{}".format(ALT_DB_DIR_PATH, port)
            baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
            if not os.path.exists(baseDirPath):
                os.makedirs(baseDirPath)
    else:
        if not os.access(baseDirPath, os.R_OK | os.W_OK):
            baseDirPath = "{}{}".format(ALT_DB_DIR_PATH, port)
            baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
            if not os.path.exists(baseDirPath):
                os.makedirs(baseDirPath)

    keriDbDirPath = baseDirPath  # set global db directory path

    # open lmdb major database instance
    # creates files data.mdb and lock.mdb in dbBaseDirPath
    keriDBEnv = lmdb.open(keriDbDirPath, max_dbs=MAX_DB_COUNT)  # set global

    # create named sub dbs  within major db  instance(core and tables)
    keriDBEnv.open_db(DB_KEY_EVENT_LOG_NAME)  #  open KEL

    return keriDBEnv



def setupTestDbEnv():
    """
    Return dbEnv resulting from baseDirpath in temporary directory
    and then setupDbEnv
    """
    baseDirPath = setupTmpBaseDir()
    baseDirPath = os.path.join(baseDirPath, "db/keri")
    os.makedirs(baseDirPath)
    return setupDbEnv(baseDirPath=baseDirPath)

