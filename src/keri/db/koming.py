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



class KomerBase():
    """
    KomerBase is a base class for Komer (Keyspace Object Mapper) subclasses that
    each use a dataclass as the object mapped via serialization to an dber LMDB
    database subclass.
    Each Komer .schema is a dataclass class reference that is used to define
    the fields in each database entry. The base class is not meant to be instantiated.
    Use an instance of one of the subclasses instead.
    """
    Sep = '.'  # separator for combining key iterables

    def __init__(self, db: dbing.LMDBer, *,
                 subkey: str = 'docs.',
                 schema: Type[dataclass],  # class not instance
                 kind: str = coring.Serials.json,
                 dupsort: bool = False,
                 sep: str = None,
                 **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
        """
        super(KomerBase, self).__init__(**kwa)  # Mixin for Multi-inheritance MRO
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=dupsort)
        self.schema = schema
        self.kind = kind
        self.serializer = self._serializer(kind)
        self.deserializer = self._deserializer(kind)
        self.sep = sep if sep is not None else self.Sep


    def _tokey(self, keys: Union[str, bytes, Iterable]):
        """
        Converts key to key str with proper separators and returns key bytes.
        If key is already str then returns. Else If key is iterable (non-str)
        of strs then joins with separator converts to bytes and returns

        Parameters:
           keys (Union[str, bytes, Iterable]): str, bytes, or Iterable of str.

        """
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")
        elif hasattr(keys, "decode"): # bytes
            return keys
        return (self.sep.join(keys).encode("utf-8"))  # iterable


    def _tokeys(self, key: Union[str, bytes]):
        """
        Converts key bytes to keys tuple of strs by decoding and then splitting
        at separator.

        Returns:
           keys (iterable): of str

        Parameters:
           key (Union[str, bytes]): str or bytes.

        """
        return tuple(key.decode("utf-8").split(self.sep))


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


    def __deserializeJSON(self, val):
        if val is not None:
            val = helping.datify(self.schema, json.loads(bytes(val).decode("utf-8")))
            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.schema))
        return val


    def __deserializeMGPK(self, val):
        if val is not None:
            val = helping.datify(self.schema, msgpack.loads(bytes(val)))
            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.schema))
        return val


    def __deserializeCBOR(self, val):
        if val is not None:
            val = helping.datify(self.schema, cbor2.loads(bytes(val)))
            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.schema))
        return val


    def __serializeJSON(self, val):
        if val is not None:
            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.schema))
            val = json.dumps(helping.dictify(val),
                          separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        return val


    def __serializeMGPK(self, val):
        if val is not None:
            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.schema))
            val = msgpack.dumps(helping.dictify(val))
        return val


    def __serializeCBOR(self, val):
        if val is not None:
            if not isinstance(val, self.schema):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.schema))
            val = cbor2.dumps(helping.dictify(val))
        return val



class Komer(KomerBase):
    """
    Keyspace Object Mapper factory class.
    """
    def __init__(self,
                 db: dbing.LMDBer, *,
                 subkey: str = 'docs.',
                 schema: Type[dataclass],  # class not instance
                 kind: str = coring.Serials.json,
                 **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        super(Komer, self).__init__(db=db, subkey=subkey, schema=schema,
                                    kind=kind, dupsort=False, **kwa)


    def put(self, keys: Union[str, Iterable], val: dataclass):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(val)))


    def pin(self, keys: Union[str, Iterable], val: dataclass):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (bool): True If successful. False otherwise.
        """
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
            if (val := mydb.get(keys)) is None:
                raise ExceptionHere
            use val here
        """
        return (self.deserializer(self.db.getVal(db=self.sdb,
                                key=self._tokey(keys))))


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return (self.db.delVal(db=self.sdb, key=self._tokey(keys)))


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db. Raises StopIteration when done

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.deserializer(val))




class DupKomer(KomerBase):
    """
    Duplicate Keyspace Object Mapper factory class that supports multiple entries
    a given database key (lmdb dupsort == True).

    Do not use if Komer schema instance serialized is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB
    """
    def __init__(self,
             db: dbing.LMDBer, *,
             subkey: str = 'recs.',
             schema: Type[dataclass],  # class not instance
             kind: str = coring.Serials.json,
             **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        super(DupKomer, self).__init__(db=db, subkey=subkey, schema=schema,
                                       kind=kind, dupsort=True, **kwa)



    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        vals = [self.serializer(val) for val in vals]
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=vals))


    def add(self, keys: Union[str, Iterable], val: dataclass):
        """
        Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass): instance of type self.schema

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(val)))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        vals = [self.serializer(val) for val in vals]
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=vals))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is instance of type self.schema
                          empty list if no entry at keys

        """
        vals = self.db.getVals(db=self.sdb, key=self._tokey(keys))
        vals = [self.deserializer(val) for val in vals]
        return vals


    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            iterator:  vals each of type self.schema. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield self.deserializer(val)


    def cnt(self, keys: Union[str, Iterable]):
        """
        Return count of dup values at key made from keys, zero otherwise

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        return (self.db.cntVals(db=self.sdb, key=self._tokey(keys)))


    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass):  instance of dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = self.serializer(val)
        else:
            val = b''
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=val))


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db. Raises StopIteration when done

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.deserializer(val))



class MultiKomer(KomerBase):
    """
    Multiple Insertion Ordered Keyspace Object Mapper factory class that supports
    multiple distinct entries at a given effective database key but with dupsort==False.
    This works similarly to the duplicates of  LMDB (dupsort==True) but without
    the size limitation of 512 bytes for each value when dupsort==True.
    Here the key is augmented with a hidden numbered suffix that provides a
    duplicate like list of values at each effective key. The suffix is appended
    and stripped transparently. The multiple items (duplicates) at each effective
    key here are retrieved in insertion order. This is unlike dupsort==True
    duplicates which are retrieved in lexocographic order.
    """
    def __init__(self,
             db: dbing.LMDBer, *,
             subkey: str = 'recs.',
             schema: Type[dataclass],  # class not instance
             kind: str = coring.Serials.json,
             **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        super(DupKomer, self).__init__(db=db, subkey=subkey, schema=schema,
                                       kind=kind, dupsort=False, **kwa)


    def putIoVals(self, db, key, vals):
        """
        Write each entry from list of bytes vals to key in db in insertion order
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Assumes DB opened with dupsort=False

        Duplicates at a given key preserve insertion order of duplicate.
        Because lmdb is lexocographic an insertion ordering proem is prepended to
        all values that makes lexocographic order that same as insertion order
        Duplicates are ordered as a pair of key plus value so prepending proem
        to each value changes duplicate ordering. Proem is 33 characters long.
        With 32 character hex string followed by '.' for essentiall unlimited
        number of values which will be limited by memory.
        With prepended proem ordinal must explicity check for duplicate values
        before insertion. Uses a python set for the duplicate inclusion test.
        Set inclusion scales with O(1) whereas list inclusion scales with O(n).

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            vals is list of bytes of values to be written
        """

        result = False
        dups = set(self.getIoVals(db, key))  #get preexisting dups if any
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            idx = 0
            cursor = txn.cursor()
            if cursor.set_key(key): # move to key if any
                if cursor.last_dup(): # move to last dup
                    idx = 1 + int(bytes(cursor.value()[:32]), 16)  # get last index as int

            for val in vals:
                if val not in dups:
                    val = (b'%032x.' % (idx)) +  val  # prepend ordering proem
                    txn.put(key, val, dupdata=True)
                    idx += 1
                    result = True
        return result


    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        vals = [self.serializer(val) for val in vals]
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=vals))


    def addIoVal(self, db, key, val):
        """
        Add val bytes as dup in insertion order to key in db
        Adds to existing values at key if any
        Returns True if written else False if val is already a dup
        Actual value written include prepended proem ordinal
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be written
        """
        return self.putIoVals(db, key, [val])




    def add(self, keys: Union[str, Iterable], val: dataclass):
        """
        Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass): instance of type self.schema

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self.serializer(val)))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        vals = [self.serializer(val) for val in vals]
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=vals))


    def getIoVals(self, db, key):
        """
        Return list of duplicate values at key in db in insertion order
        Returns empty list if no entry at key
        Removes prepended proem ordinal from each val  before returning
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                # slice off prepended ordering proem
                vals = [val[33:] for val in cursor.iternext_dup()]
            return vals


    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is instance of type self.schema
                          empty list if no entry at keys

        """
        vals = self.db.getVals(db=self.sdb, key=self._tokey(keys))
        vals = [self.deserializer(val) for val in vals]
        return vals


    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            iterator:  vals each of type self.schema. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield self.deserializer(val)


    def cntIoVals(self, db, key):
        """
        Return count of dup values at key in db, or zero otherwise
        Assumes DB opened with dupsort=True

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





    def cnt(self, keys: Union[str, Iterable]):
        """
        Return count of dup values at key made from keys, zero otherwise

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        return (self.db.cntVals(db=self.sdb, key=self._tokey(keys)))


    def delIoVals(self,db, key):
        """
        Deletes all values at key in db if key present.
        Returns True If key exists and dups deleted Else False
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.delete(key))


    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass):  instance of dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = self.serializer(val)
        else:
            val = b''
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=val))


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db. Raises StopIteration when done

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.deserializer(val))





    def getIoValsIter(self, db, key):
        """
        Return iterator of all duplicate values at key in db in insertion order
        Raises StopIteration Error when no remaining dup items = empty.
        Removes prepended proem ordinal from each val before returning
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                for val in cursor.iternext_dup():
                    yield val[33:]  # slice off prepended ordering proem


    def getIoValLast(self, db, key):
        """
        Return last added dup value at key in db in insertion order
        Returns None no entry at key
        Removes prepended proem ordinal from val before returning
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            val = None
            if cursor.set_key(key):  # move to first_dup
                if cursor.last_dup(): # move to last_dup
                    val = cursor.value()[33:]  # slice off prepended ordering proem
            return val


    def getIoItemsNext(self, db, key=b"", skip=True):
        """
        Return list of all dup items at next key after key in db in insertion order.
        Item is (key, val) with proem stripped from val stored in db.
        If key == b'' then returns list of dup items at first key in db.
        If skip is False and key is not empty then returns dup items at key
        Returns empty list if no entries at next key after key

        If key is empty then gets io items (key, io value) at first key in db
        Use the return key from items as next key for next call to function in
        order to iterate through the database

        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace or empty string
            skip is Boolean If True skips to next key if key is not empty string
                    Othewise don't skip for first pass
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            items = []
            if cursor.set_range(key):  # moves to first_dup at key
                found = True
                if skip and key and cursor.key() == key:  # skip to next key
                    found = cursor.next_nodup()  # skip to next key not dup if any
                if found:
                    # slice off prepended ordering prefix on value in item
                    items = [(key, val[33:]) for key, val in cursor.iternext_dup(keys=True)]
            return items


    def getIoItemsNextIter(self, db, key=b"", skip=True):
        """
        Return iterator of all dup items at next key after key in db in insertion order.
        Item is (key, val) with proem stripped from val stored in db.
        If key = b'' then returns list of dup items at first key in db.
        If skip is False and key is not empty then returns dup items at key
        Raises StopIteration Error when no remaining dup items = empty.

        If key is empty then gets io items (key, io value) at first key in db
        Use the return key from items as next key for next call to function in
        order to iterate through the database

        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace or empty
            skip is Boolean If True skips to next key if key is not empty string
                    Othewise don't skip for first pass
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            if cursor.set_range(key):  # moves to first_dup at key
                found = True
                if skip and key and cursor.key() == key:  # skip to next key
                    found = cursor.next_nodup()  # skip to next key not dup if any
                if found:
                    for key, val in cursor.iternext_dup(keys=True):
                        yield (key, val[33:]) # slice off prepended ordering prefix



    def delIoVal(self, db, key, val):
        """
        Deletes dup io val at key in db. Performs strip search to find match.
        Strips proems and then searches.
        Returns True if delete else False if val not present
        Assumes DB opened with dupsort=True

        Duplicates at a given key preserve insertion order of duplicate.
        Because lmdb is lexocographic an insertion ordering proem is prepended to
        all values that makes lexocographic order that same as insertion order
        Duplicates are ordered as a pair of key plus value so prepending proem
        to each value changes duplicate ordering. Proem is 33 characters long.
        With 32 character hex string followed by '.' for essentially unlimited
        number of values which will be limited by memory.

        Does a linear search so not very efficient when not deleting from the front.
        This is hack for supporting escrow which needs to delete individual dup.
        The problem is that escrow is not fixed buts stuffs gets added and
        deleted which just adds to the value of the proem. 2**16 is an impossibly
        large number so the proem will not max out practically. But its not
        and elegant solution. So maybe escrows need to use a different approach.
        But really didn't want to add another database just for escrows.

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be deleted without intersion ordering proem
        """

        with self.env.begin(db=db, write=True, buffers=True) as txn:
            cursor = txn.cursor()
            if cursor.set_key(key):  # move to first_dup
                for proval in cursor.iternext_dup():  #  value with proem
                    if val == proval[33:]:  #  strip of proem
                        return cursor.delete()
        return False



    # For subdbs with no duplicate values allowed at each key. (dupsort==False)
    # and use keys with ordinal as monotonically increasing number part
    # such as sn or fn
    def appendOrdValPre(self, db, pre, val):
        """
        Appends val in order after last previous key with same pre in db.
        Returns ordinal number in, on, of appended entry. Appended on is 1 greater
        than previous latest on.
        Uses snKey(pre, on) for entries.

        Append val to end of db entries with same pre but with on incremented by
        1 relative to last preexisting entry at pre.

        Parameters:
            db is opened named sub db with dupsort=False
            pre is bytes identifier prefix for event
            val is event digest
        """
        # set key with fn at max and then walk backwards to find last entry at pre
        # if any otherwise zeroth entry at pre
        key = snKey(pre, MaxON)
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            on = 0  # unless other cases match then zeroth entry at pre
            cursor = txn.cursor()
            if not cursor.set_range(key):  # max is past end of database
                #  so either empty database or last is earlier pre or
                #  last is last entry  at same pre
                if cursor.last():  # not empty db. last entry earlier than max
                    ckey = cursor.key()
                    cpre, cn = splitKeyON(ckey)
                    if cpre == pre:  # last is last entry for same pre
                        on = cn + 1  # increment
            else:  # not past end so not empty either later pre or max entry at pre
                ckey = cursor.key()
                cpre, cn = splitKeyON(ckey)
                if cpre == pre:  # last entry for pre is already at max
                    raise ValueError("Number part of key {}  exceeds maximum"
                                     " size.".format(ckey))
                else:  # later pre so backup one entry
                    # either no entry before last or earlier pre with entry
                    if cursor.prev():  # prev entry, maybe same or earlier pre
                        ckey = cursor.key()
                        cpre, cn = splitKeyON(ckey)
                        if cpre == pre:  # last entry at pre
                            on = cn + 1  # increment

            key = onKey(pre, on)

            if not cursor.put(key, val, overwrite=False):
                raise  ValueError("Failed appending {} at {}.".format(val, key))
            return on


    def getAllOrdItemPreIter(self, db, pre, on=0):
        """
        Returns iterator of duple item, (on, dig), at each key over all ordinal
        numbered keys with same prefix, pre, in db. Values are sorted by
        snKey(pre, on) where on is ordinal number int.
        Returned items are duples of (on, dig) where on is ordinal number int
        and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            db is opened named sub db with dupsort=False
            pre is bytes of itdentifier prefix
            on is int ordinal number to resume replay
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            key = onKey(pre, on)  # start replay at this enty 0 is earliest
            if not cursor.set_range(key):  #  moves to val at key >= key
                return  # no values end of db

            for key, val in cursor.iternext():  # get key, val at cursor
                cpre, cn = splitKeyON(key)
                if cpre != pre:  # prev is now the last event for pre
                    break  # done
                yield (cn, bytes(val))  # (on, dig) of event


    def getAllOrdItemAllPreIter(self, db, key=b''):
        """
        Returns iterator of triple item, (pre, on, dig), at each key over all
        ordinal numbered keys for all prefixes in db. Values are sorted by
        snKey(pre, on) where on is ordinal number int.
        Each returned item is triple (pre, on, dig) where pre is identifier prefix,
        on is ordinal number int and dig is event digest for lookup in .evts sub db.

        Raises StopIteration Error when empty.

        Parameters:
            db is opened named sub db with dupsort=False
            key is key location in db to resume replay,
                   If empty then start at first key in database
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            if not cursor.set_range(key):  #  moves to val at key >= key, first if empty
                return  # no values end of db

            for key, val in cursor.iternext():  # return key, val at cursor
                cpre, cn = splitKeyON(key)
                yield (cpre, cn, bytes(val))  # (pre, on, dig) of event
