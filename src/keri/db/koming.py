# -*- encoding: utf-8 -*-
"""
KERI
keri.db.koming module

"""
import types
import json
from dataclasses import dataclass
from typing import Type, Union
from collections.abc import Iterable

import cbor2
import msgpack
import lmdb


from . import dbing
from .. import help
from ..core import coring
from ..help import helping

logger = help.ogler.getLogger()



class KomerBase:
    """
    KomerBase is a base class for Komer (Keyspace Object Mapper) subclasses that
    each use a dataclass as the object mapped via serialization to an dber LMDB
    database subclass.
    Each Komer .schema is a dataclass class reference that is used to define
    the fields in each database entry. The base class is not meant to be instantiated.
    Use an instance of one of the subclasses instead.

    Attributes:
        db (dbing.LMDBer): instance of LMDB database manager class
        sdb (lmdb._Database): instance of named sub db lmdb for this Komer
        schema (Type[dataclass]): class reference of dataclass subclass
        kind (str): serialization/deserialization type from coring.Serials
        serializer (types.MethodType): serializer method
        deserializer (types.MethodType): deserializer method
        sep (str): separator for combining keys tuple of strs into key bytes
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
        super(KomerBase, self).__init__()
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=dupsort)
        self.schema = schema
        self.kind = kind
        self.serializer = self._serializer(kind)
        self.deserializer = self._deserializer(kind)
        self.sep = sep if sep is not None else self.Sep


    def _tokey(self, keys: Union[str, bytes, memoryview, Iterable]):
        """
        Converts key to key str with proper separators and returns key bytes.
        If key is already str then returns. Else If key is iterable (non-str)
        of strs then joins with separator converts to bytes and returns

        Parameters:
           keys (Union[str, bytes, Iterable]): str, bytes, or Iterable of str.

        """
        if isinstance(keys, memoryview):  # memoryview of bytes
            return bytes(keys)  # return bytes
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")  # convert to bytes
        elif hasattr(keys, "decode"): # bytes
            return keys  # return as is
        return (self.sep.join(keys).encode("utf-8"))  # iterable so join


    def _tokeys(self, key: Union[str, bytes, memoryview]):
        """
        Converts key bytes to keys tuple of strs by decoding and then splitting
        at separator.

        Returns:
           keys (iterable): of str

        Parameters:
           key (Union[str, bytes]): str or bytes.

        """
        if isinstance(key, memoryview):  # memoryview of bytes
            key = bytes(key)
        return tuple(key.decode("utf-8").split(self.sep))


    def getItemIter(self, keys: Union[str, Iterable]=b""):
        """
        Returns:
            items (Iterator): of (key, val) tuples  over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.

        """
        for key, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield (self._tokeys(key), self.deserializer(val))


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

    def getDict(self, keys: Union[str, Iterable]):
        """
        Gets dictified val at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (dict):
            None if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (val := mydb.get(keys)) is None:
                raise ExceptionHere
            use val here
        """
        val = self.get(keys)
        return helping.dictify(val) if val is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return (self.db.delVal(db=self.sdb, key=self._tokey(keys)))


    def trim(self, keys: Union[str, Iterable]=b""):
        """
        Removes all entries whose keys startswith keys. Enables removal of whole
        branches of db key space. To ensure that proper separation of a branch
        include empty string as last key in keys. For example ("a","") deletes
        'a.1'and 'a.2' but not 'ab'

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delTopVal(db=self.sdb, key=self._tokey(keys)))


    def cntAll(self):
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
        return self.db.cnt(db=self.sdb)


class IoSetKomer(KomerBase):
    """
    Insertion Ordered Set Keyspace Object Mapper factory class that supports
    a set of distinct entries at a given effective database key but with
    dupsort==False. Effective data model is that there are multiple values in a
    set of values where every member of the set has the same key (duplicate key).
    The set of values is an ordered set using insertion order. Any given value
    may appear only once in the set (not a list).

    This works similarly to the IO value duplicates for the LMDBer class with a
    sub db  of LMDB (dupsort==True) but without its size limitation of 511 bytes
    for each value when dupsort==True.
    Here the key is augmented with a hidden numbered suffix that provides a
    an ordered set of values at each effective key (duplicate key). The suffix
    is appended and stripped transparently. The set of multiple items with
    duplicate keys are retrieved in insertion order when iterating or as a list
    of the set elements.

    Attributes:
        db (dbing.LMDBer): instance of LMDB database manager class
        sdb (lmdb._Database): instance of named sub db lmdb for this Komer
        schema (Type[dataclass]): class reference of dataclass subclass
        kind (str): serialization/deserialization type from coring.Serials
        serializer (types.MethodType): serializer method
        deserializer (types.MethodType): deserializer method
        sep (str): separator for combining keys tuple of strs into key bytes
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
        super(IoSetKomer, self).__init__(db=db, subkey=subkey, schema=schema,
                                       kind=kind, dupsort=False, **kwa)


    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at key made from keys. Does not overwrite. Puts all vals
        at effective key made from keys and hidden ordinal suffix.
        that are not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        vals = [self.serializer(val) for val in vals]
        return (self.db.putIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=vals,
                                     sep=self.sep))


    def add(self, keys: Union[str, Iterable], val: dataclass):
        """
        Add val to vals at effective key made from keys and hidden ordinal suffix.
        that is not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass): instance of type self.schema

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addIoSetVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self.serializer(val),
                                    sep=self.sep))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at effective key made from keys and hidden ordinal suffix.
        Overwrites. Removes all pre-existing vals that share same effective keys
        and replaces them with vals

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delIoSetVals(db=self.sdb, key=key)  # delete all values
        vals = [self.serializer(val) for val in vals]
        return (self.db.setIoSetVals(db=self.sdb,
                                     key=key,
                                     vals=vals,
                                     sep=self.sep))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is instance of type self.schema
                          empty list if no entry at keys

        """
        return [self.deserializer(val) for val in
                    self.db.getIoSetValsIter(db=self.sdb,
                                             key=self._tokey(keys),
                                             sep=self.sep)]


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last effective dup val at effective dup key made from keys

        Parameters:
            keys (tuple): of key strs to be combined to form effective key

        Returns:
            val (Type[dataclass]):  instance of type self.schema
                          None if no entry at keys

        """
        val = self.db.getIoSetValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = self.deserializer(val)
        return val


    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets vals iterator at effecive key made from keys and hidden ordinal suffix.
        All vals in set of vals that share same effecive key are retrieved in
        insertion order.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            vals (Iterator):  str values. Raises StopIteration when done

        """
        for val in self.db.getIoSetValsIter(db=self.sdb,
                                            key=self._tokey(keys),
                                            sep=self.sep):
            yield self.deserializer(val)



    def cnt(self, keys: Union[str, Iterable]):
        """
        Return count of effective dup values at key made from keys, zero otherwise

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        return (self.db.cntIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     sep=self.sep))


    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (dataclass):  instance of effective dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = self.serializer(val)
            return self.db.delIoSetVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=val,
                                       sep=self.sep)
        else:
            return self.db.delIoSetVals(db=self.sdb,
                                       key=self._tokey(keys),
                                       sep=self.sep)


    def getItemIter(self, keys: Union[str, Iterable]=b""):
        """Get items iterator
        Returns:
            items (Iterator): of (key, val) tuples over the all the items in
            subdb whose effective key startswith key made from keys.
            Keys may be keyspace prefix in order to return branches of key space.
            When keys is empty then returns all items in subdb.
            Returned key in each item has ordinal suffix removed.

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database. Append "" to end of keys Iterable to
                ensure get properly separated top branch key.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            key, ion = dbing.unsuffix(iokey, sep=self.sep)
            yield (self._tokeys(key), self.deserializer(val))


    def getIoSetItem(self, keys: Union[str, Iterable]):
        """
        Gets (iokeys, val) ioitems list at key made from keys where key is
        apparent effective key and ioitems all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            ioitems (Iterable):  each item in list is tuple (iokeys, val) where each
                    iokeys is actual key tuple including hidden suffix and
                    each val is str
                    empty list if no entry at keys


        """
        return ([(self._tokeys(iokey), self.deserializer(val)) for iokey, val
                    in self.db.getIoSetItems(db=self.sdb,
                                             key=self._tokey(keys),
                                             sep=self.sep)])


    def getIoSetItemIter(self, keys: Union[str, Iterable]):
        """
        Gets (iokeys, val) ioitems  iterator at key made from keys where key is
        apparent effective key and items all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            ioitems (Iterator):  each item iterated is tuple (iokeys, val) where
                each iokeys is actual keys tuple including hidden suffix and
                each val is str
                empty list if no entry at keys.
                Raises StopIteration when done

        """
        for iokey, val in self.db.getIoSetItemsIter(db=self.sdb,
                                                    key=self._tokey(keys),
                                                    sep=self.sep):
            yield (self._tokeys(iokey), self.deserializer(val))


    def getIoItemIter(self, keys: Union[str, Iterable]=b""):
        """
        Returns:
            items (Iterator): tuple (key, val) over the all the items in
            subdb whose key startswith effective key made from keys.
            Keys may be keyspace prefix to return branches of key space.
            When keys is empty then returns all items in subdb.


        Parameters:
            keys (Iterable): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database. Append "" to end of keys Iterable to
                ensure get properly separated top branch key.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield (self._tokeys(iokey), self.deserializer(val))


    def remIokey(self, iokeys: Union[str, bytes, memoryview, Iterable]):
        """
        Removes entry at iokeys

        Parameters:
            iokeys (tuple): of key str or tuple of key strs to be combined in
                            order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        return self.db.delIoSetIokey(db=self.sdb, iokey=self._tokey(iokeys))



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
        return ([self.deserializer(val) for val in
                self.db.getValsIter(db=self.sdb, key=self._tokey(keys))])


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last dup val at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (Type[dataclass]):  instance of type self.schema
                          None if no entry at keys

        """
        val = self.db.getValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = self.deserializer(val)
        return val


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

