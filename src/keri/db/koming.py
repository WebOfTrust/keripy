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


