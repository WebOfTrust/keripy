# -*- encoding: utf-8 -*-
"""
KERI
keri.db.koming module

"""
import json
from dataclasses import dataclass, asdict
from typing import Type, Union, Iterable

import cbor2
import msgpack

from . import dbing
from .. import help
from ..core import coring
from ..help import helping

logger = help.ogler.getLogger()


class Komer:
    """
    Keyspace Object Mapper factory class
    """
    Sep = '.'  # separator for combining key iterables

    def __init__(self,
                 db: dbing.LMDBer, *,
                 subkey: str = 'docs.',
                 schema: Type[dataclass],  # class not instance
                 kind: str = coring.Serials.json):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subdb (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"))
        self.schema = schema
        self.kind = kind
        self.serializer = self._serializer(kind)
        self.deserializer = self._deserializer(kind)


    def put(self, keys: Union[str, Iterable], val: dataclass):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            data (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (Boolean): True If successful, False otherwise, such as key
                              already in database.
        """
        if not isinstance(val, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(val), val, self.schema))
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(val)))


    def pin(self, keys: Union[str, Iterable], val: dataclass):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            data (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (Boolean): True If successful. False otherwise.
        """
        if not isinstance(val, self.schema):
            raise ValueError("Invalid schema type={} of val={}, expected {}."
                             "".format(type(val), val, self.schema))
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(val)))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets val at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (dataclass):
            None if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (data := mydb.get(keys)) is None:
                raise ExceptionHere
            use data here
        """
        val = helping.datify(self.schema,
                              self.deserializer(
                                  self.db.getVal(db=self.sdb,
                                                 key=self._tokey(keys))))

        if val and not isinstance(val, self.schema):
            raise ValueError("Invalid schema type={} of val={}, expected {}."
                             "".format(type(val), val, self.schema))
        return val


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (Boolean): True if key exists so delete successful. False otherwise
        """
        return (self.db.delVal(db=self.sdb, key=self._tokey(keys)))


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            val = helping.datify(self.schema, self.deserializer(val))

            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of data={}, expected {}."
                                 "".format(type(val), val, self.schema))
            keys = tuple(key.decode("utf-8").split('.'))  # tuple
            yield (keys, val)


    def _tokey(self, keys: Union[str, bytes, Iterable]):
        """
        Converts key to key str with proper separators and returns key bytes.
        If key is already str then returns. Else If key is iterable (non-str)
        of strs then joins with separator converts to bytes and returns

        Parameters:
           keys (Union[str, Iterable]): str or Iterable of str.

        """
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")
        elif hasattr(keys, "decode"): # bytes
            return keys
        return (self.Sep.join(keys).encode("utf-8"))  # iterable


    def _serializer(self, kind):
        """
        Parameters:
            kind (str): serialization
        """
        if kind == coring.Serials.mgpk:
            return self.__serializeMGPK
        elif kind == coring.Serials.cbor:
            return self.__serializeCBOR
        else:
            return self.__serializeJSON


    def _deserializer(self, kind):
        """
        Parameters:
            kind (str): deserialization
        """
        if kind == coring.Serials.mgpk:
            return self.__deserializeMGPK
        elif kind == coring.Serials.cbor:
            return self.__deserializeCBOR
        else:
            return self.__deserializeJSON


    @staticmethod
    def __deserializeJSON(val):
        if val is None:
            return
        return json.loads(bytes(val).decode("utf-8"))


    @staticmethod
    def __deserializeMGPK(val):
        if val is None:
            return
        return msgpack.loads(bytes(val))


    @staticmethod
    def __deserializeCBOR(val):
        if val is None:
            return
        return cbor2.loads(bytes(val))


    @staticmethod
    def __serializeJSON(val):
        if val is None:
            return
        return (json.dumps(helping.dictify(val), separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8"))


    @staticmethod
    def __serializeMGPK(val):
        if val is None:
            return
        return msgpack.dumps(helping.dictify(val))


    @staticmethod
    def __serializeCBOR(val):
        if val is None:
            return
        return cbor2.dumps(helping.dictify(val))




class Domer:
    """
    Duplicate Keyspace Object Mapper factory class that supports multiple entries
    a given database key (lmdb dupsort == True).
    """

    def __init__(self, db: dbing.LMDBer, *,
                 subkey: str = 'docs.',
                 schema: Type[dataclass],  # class not instance
                 kind: str = coring.Serials.json):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subdb (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=True)
        self.schema = schema
        self.kind = kind
        self.serializer = self._serializer(kind)
        self.deserializer = self._deserializer(kind)



    # For subdbs that support duplicates at each key (dupsort==True)
    def putVals(self, db, key, vals):
        """
        Write each entry from list of bytes vals to key in db
        Adds to existing values at key if any
        Returns True If only one first written val in vals Else False
        Apparently always returns True (is this how .put works with dupsort=True)

        Duplicates are inserted in lexocographic order not insertion order.
        Lmdb does not insert a duplicate unless it is a unique value for that
        key.

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            vals is list of bytes of values to be written
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            result = True
            for val in vals:
                result = result and txn.put(key, val, dupdata=True)
            return result


    def addVal(self, db, key, val):
        """
        Add val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists

        Duplicates are inserted in lexocographic order not insertion order.
        Lmdb does not insert a duplicate unless it is a unique value for that
        key.

        Does inclusion test to dectect of duplicate already exists
        Uses a python set for the duplicate inclusion test. Set inclusion scales
        with O(1) whereas list inclusion scales with O(n).

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is bytes of value to be written
        """
        dups = set(self.getVals(db, key))  #get preexisting dups if any
        result = False
        if val not in dups:
            with self.env.begin(db=db, write=True, buffers=True) as txn:
                result = txn.put(key, val, dupdata=True)
        return result


    def getVals(self, db, key):
        """
        Return list of values at key in db
        Returns empty list if no entry at key

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                vals = [val for val in cursor.iternext_dup()]
            return vals


    def getValsIter(self, db, key):
        """
        Return iterator of all dup values at key in db
        Raises StopIteration error when done or if empty

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                for val in cursor.iternext_dup():
                    yield val


    def cntVals(self, db, key):
        """
        Return count of dup values at key in db, or zero otherwise

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            count = 0
            if cursor.set_key(key):  # moves to first_dup
                count = cursor.count()
            return count


    def cntValsAllPre(self, db, pre, on=0):
        """
        Returns (int): count of of all vals with same pre in key but different
            on in key in db starting at ordinal number on of pre

        Does not count dups

        Parameters:
            db is opened named sub db
            pre is bytes of key within sub db's keyspace pre.on
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            key = onKey(pre, on)  # start replay at this enty 0 is earliest
            count = 0
            if not cursor.set_range(key):  #  moves to val at key >= key
                return count # no values end of db

            for val in cursor.iternext(values=False):  # get key, val at cursor
                cpre, cn = splitKeyON(key)
                if cpre != pre:  # prev is now the last event for pre
                    break  # done
                count = count+1

            return count

    def delVals(self, db, key, val=b''):
        """
        Deletes all values at key in db if val=b'' else deletes the dup
        that equals val
        Returns True If key (and val if not empty) exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is bytes of dup val at key to delete
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.delete(key, val))


    def put(self, keys: Union[str, Iterable], data: dataclass):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            data (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (Boolean): True If successful, False otherwise, such as key
                              already in database.
        """
        if not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(data)))

    def pin(self, keys: Union[str, Iterable], data: dataclass):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            data (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (Boolean): True If successful. False otherwise.
        """
        if not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(data)))

    def get(self, keys: Union[str, Iterable]):
        """
        Gets val at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            data (dataclass):
            None if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (data := mydb.get(keys)) is None:
                raise ExceptionHere
            use data here
        """
        data = helping.datify(self.schema,
                              self.deserializer(
                                  self.db.getVal(db=self.sdb,
                                                 key=self._tokey(keys))))

        if data and not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))
        return data

    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (Boolean): True if key exists so delete successful. False otherwise
        """
        return (self.db.delVal(db=self.sdb, key=self._tokey(keys)))

    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            data = helping.datify(self.schema, self.deserializer(val))

            if not isinstance(data, self.schema):
                raise ValueError("Invalid schema type={} of data={}, expected {}."
                                 "".format(type(data), data, self.schema))
            keys = tuple(key.decode("utf-8").split('.'))  # tuple
            yield (keys, data)

    def _tokey(self, keys: Union[str, bytes, Iterable]):
        """
        Converts key to key str with proper separators and returns key bytes.
        If key is already str then returns. Else If key is iterable (non-str)
        of strs then joins with separator converts to bytes and returns

        Parameters:
           keys (Union[str, Iterable]): str or Iterable of str.

        """
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")
        elif hasattr(keys, "decode"): # bytes
            return keys
        return (self.Sep.join(keys).encode("utf-8"))  # iterable

    def _serializer(self, kind):
        """
        Parameters:
            kind (str): serialization
        """
        if kind == coring.Serials.mgpk:
            return self.__serializeMGPK
        elif kind == coring.Serials.cbor:
            return self.__serializeCBOR
        else:
            return self.__serializeJSON

    def _deserializer(self, kind):
        """
        Parameters:
            kind (str): deserialization
        """
        if kind == coring.Serials.mgpk:
            return self.__deserializeMGPK
        elif kind == coring.Serials.cbor:
            return self.__deserializeCBOR
        else:
            return self.__deserializeJSON

    @staticmethod
    def __deserializeJSON(val):
        if val is None:
            return
        return json.loads(bytes(val).decode("utf-8"))

    @staticmethod
    def __deserializeMGPK(val):
        if val is None:
            return
        return msgpack.loads(bytes(val))

    @staticmethod
    def __deserializeCBOR(val):
        if val is None:
            return
        return cbor2.loads(bytes(val))

    @staticmethod
    def __serializeJSON(val):
        if val is None:
            return
        return json.dumps(helping.dictify(val), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def __serializeMGPK(val):
        if val is None:
            return
        return msgpack.dumps(helping.dictify(val))

    @staticmethod
    def __serializeCBOR(val):
        if val is None:
            return
        return cbor2.dumps(helping.dictify(val))
