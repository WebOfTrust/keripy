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
def openDatabaser(name="test", cls=None):
    """
    Wrapper to enable temporary (test) Databaser instances
    When used in with statement calls .clearDirPath() on exit of with block

    Parameters:
        name is str name of temporary Databaser dirPath  extended name so
                 can have multiple temporary databasers is use differen name
        cls is Class instance of subclass instance

    Usage:

    with openDatabaser(name="gen1") as baser1:
        baser1.env  ....

    with openDatabaser(name="gen2, cls=Logger)

    """
    if cls is None:
        cls = Databaser
    try:
        databaser = cls(name=name, temp=True)

        yield databaser

    finally:

        databaser.clearDirPath()


class Databaser:
    """
    Databaser base class for LMDB instances.
    Creates a specific instance of an LMDB database directory and environment.

    Attributes:
        .name is LMDB database name did2offer
        .env is LMDB main (super) database environment
        .path is LMDB main (super) database directory path

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


    @staticmethod
    def dgKey(pre, dig):
        """
        Returns bytes DB key from concatenation of qualified Base64 prefix
        bytes pre and qualified Base64 str digest of serialized event
        """
        return (b'%s.%s' %  (pre, dig))

    @staticmethod
    def snKey(pre, sn):
        """
        Returns bytes DB key from concatenation of qualified Base64 prefix
        bytes pre and  int sn (sequence number) of event
        """
        return (b'%s.%032x' % (pre, sn))


class Logger(Databaser):
    """
    Logger sets up named sub databases with Keri Event Logs within main database

    Attributes:
        see superclass Databaser for inherited attributes

        .evts is named sub DB whose values are serialized events
            DB is keyed by identifer prefix plus digest of serialized event
            Only one value per DB key is allowed

        .sigs is named sub DB of full qualified event signatures
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .rcts is named sub DB of event receipt couplets. Each couplet is
            concatenation of fully qualified witness or validator prefix plus
            fully qualified event signature by witness or validator
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .kels is named sub DB of key event log tables that map sequence numbers
            to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pses is named sub DB of partially signed escrowed event tables
            that map sequence numbers to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ooes is named sub DB of out of order escrowed event tables
            that map sequence numbers to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .dels is named sub DB of deplicitous event log tables that map sequence numbers
            to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pdes is named sub DB of potentially deplicitous escrowed event tables
            that map sequence numbers to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed


    Properties:


    """
    def __init__(self, **kwa):
        """
        Setup named sub databases.

        Parameters:

        """
        super(Logger, self).__init__(**kwa)

        # create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.
        # dupsort=True means allow duplicates for sn indexed

        self.evts = self.env.open_db(key=b'evts.')
        self.sigs = self.env.open_db(key=b'sigs.', dupsort=True)
        self.rcts = self.env.open_db(key=b'rcts.', dupsort=True)
        self.kels = self.env.open_db(key=b'kels.', dupsort=True)
        self.pses = self.env.open_db(key=b'pses.', dupsort=True)
        self.ooes = self.env.open_db(key=b'ooes.', dupsort=True)
        self.dels = self.env.open_db(key=b'dels.', dupsort=True)
        self.pdes = self.env.open_db(key=b'pdes.', dupsort=True)


    def getEvt(self, key):
        """
        Return event at key
        Returns None if no entry at key

        """
        with self.env.begin(db=self.evts, write=False, buffers=True) as txn:
            val = txn.get(key)

        return val


    def putEvt(self, key, val):
        """
        Write serialized event bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        with self.env.begin(db=self.evts, write=True, buffers=True) as txn:
            result = txn.put(key, val)

        return result


    def delEvt(self, key):
        """
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        with self.env.begin(db=self.evts, write=True, buffers=True) as txn:
            result = txn.delete(key)

        return result


    def getSigs(self, key):
        """
        Return list of signatures at key
        Returns empty list if no entry at key

        """
        with self.env.begin(db=self.sigs, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []

            if cursor.set_key(key):  # moves to first_dup
                vals.append(cursor.value())

                while cursor.next_dup():
                    vals.append(cursor.value())

        return vals


    def putSigs(self, key, vals):
        """
        Write each entry from list of bytes signatures vals to key
        Adds to existing signatures if any
        Returns True If only one first written val in vals Else False
        """
        with self.env.begin(db=self.sigs, write=True, buffers=True) as txn:
            for val in vals:
                result = txn.put(key, val, dupdata=True, )

        return result


    def delSigs(self, key, dupdata=True, buffers=True):
        """
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        with self.env.begin(db=self.sigs, write=True) as txn:
            result = txn.delete(key)

        return result


class Dupler(Databaser):
    """
    Dupler sets up named sub databases with Duplicitous Event Logs within main database

    Attributes:
        see superclass Databaser for inherited attributes

        .evts is named sub DB whose values are serialized events
            DB is keyed by identifer prefix plus digest of serialized event
            Only one value per DB key is allowed

        .dels is named sub DB of deplicitous event log tables that map sequence numbers
            to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pdes is named sub DB of potentially deplicitous escrowed event tables
            that map sequence numbers to serialized event digests.
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed


    Properties:


    """
    def __init__(self, **kwa):
        """
        Setup named sub databases.

        Parameters:

        """
        super(Dupler, self).__init__(**kwa)

        # create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.
        # dupsort=True means allow duplicates for sn indexed

        self.evts = self.env.open_db(key=b'evts.')  #  open named sub db
        self.dels = self.env.open_db(key=b'dels.', dupsort=True)
        self.pdes = self.env.open_db(key=b'pdes.', dupsort=True)


