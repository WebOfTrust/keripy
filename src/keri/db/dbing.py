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
import shutil
import tempfile

from contextlib import contextmanager

import lmdb

try:
    import simplejson as json
except ImportError:
    import json


from  ..kering import  KeriError

class DatabaseError(KeriError):
    """
    Database related errors
    Usage:
        raise DatabaseError("error message")
    """

def clearDatabaserDir(path):
    """
    Remove directory path
    """
    if os.path.exists(path):
        shutil.rmtree(path)


@contextmanager
def openDatabaser(name="test"):
    """
    Wrapper to enable temporary (test) Databaser instances
    When used in with statement calls .clearDirPath() on exit of with block

    Parameters:
        name is str name of temporary Databaser dirPath  extended name so
                 can have multiple temporary databasers is use differen name

    Usage:

    with openDatabaser(name="gen1") as baser1:
        baser1.env  ....

    """
    try:
        databaser = Databaser(name=name, temp=True)

        yield databaser

    finally:

        databaser.clearDirPath()

class Databaser:
    """
    Databaser instances create and use a specific instance of an LMDB database
    with associate directory for use with KERI

    Sets up named sub databases within main database

    Attributes:
        .name is LMDB database name did2offer
        .env is LMDB main (super) database environment
        .path is LMDB main (super) database directory path

        .kels is named sub DB of key event logs indexed by identifier prefix and
                 then by digest of serialized key event

    Properties:


    """
    HeadDirPath = "/var"  # default in /var
    TailDirPath = "keri/db"
    AltHeadDirPath = "~"  #  put in ~ when /var not permitted
    AltTailDirPath = ".keri/db"
    MaxNamedDBs = 8

    def __init__(self, headDirPath=None, name='main', temp=False):
        """
        Setup main database directory at .dirpath.
        Create main database environment at .env using .dirpath.
        Setup named sub databases.

        Parameters:
            headDirPath is str head of the pathname of directory for main database
                If not provided use default headDirpath
            name is str pathname differentiator for directory for main database
                When system employs more than one keri databse name allows
                differentiating each instance by name
            temp is boolean If True then use temporary head pathname  instead of
                headDirPath if any or default headDirPath
        """
        self.name = name

        if temp:
            headDirPath = tempfile.mkdtemp(prefix="keri_lmdb_", suffix="_test", dir="/tmp")
            self.path = os.path.abspath(
                                os.path.join(headDirPath,
                                             self.TailDirPath,
                                             self.name))
            os.makedirs(self.path)

        else:
            if not headDirPath:
                headDirPath = self.HeadDirPath

            self.path = os.path.abspath(
                                os.path.expanduser(
                                    os.path.join(headDirPath,
                                                 self.TailDirPath,
                                                 self.name)))

            if not os.path.exists(self.path):
                try:
                    os.makedirs(self.path)
                except OSError as ex:
                    headDirPath = self.AltHeadDirPath
                    self.path = os.path.abspath(
                                        os.path.expanduser(
                                            os.path.join(headDirPath,
                                                         self.AltTailDirPath,
                                                         self.name)))
                    if not os.path.exists(self.path):
                        os.makedirs(self.path)
            else:
                if not os.access(self.path, os.R_OK | os.W_OK):
                    headDirPath = self.AltHeadDirPath
                    self.path = os.path.abspath(
                                        os.path.expanduser(
                                            os.path.join(headDirPath,
                                                         self.AltTailDirPath,
                                                         self.name)))
                    if not os.path.exists(self.path):
                        os.makedirs(self.path)

        # open lmdb major database instance
        # creates files data.mdb and lock.mdb in .dbDirPath
        self.env = lmdb.open(self.path, max_dbs=self.MaxNamedDBs)

        # create named sub dbs  within main DB instance
        # sub db name must include a non Base64 character to avoid namespace
        # collisions with Base64 aid prefixes. So use "."
        self.kels = self.env.open_db(key=b'kels.', dupsort=True)  #  open named sub db 'KELs'
        self.kelds = self.env.open_db(key=b'kelds.')  #  open named sub db 'KELDs'


    def clearDirPath(self):
        """
        Remove .dirPath
        """
        if self.env:
            try:
                self.env.close()
            except:
                pass

        if os.path.exists(self.path):
            shutil.rmtree(self.path)


