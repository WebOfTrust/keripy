# -*- encoding: utf-8 -*-
"""
KERI
keri.db.subdbing module

"""
from typing import Type, Union
from collections.abc import Iterable, Iterator

from hio.help.helping import nonStringIterable

from .. import help
from ..core import coring
from . import dbing


logger = help.ogler.getLogger()

class SuberBase():
    """
    Base class for Sub DBs of LMDBer
    Provides common methods for subclasses
    Do not instantiate but use a subclass

    Attributes:
        db (dbing.LMDBer): base LMDB db
        sdb (lmdb._Database): instance of lmdb named sub db for this Suber
        sep (str): separator for combining keys tuple of strs into key bytes
    """
    Sep = '.'  # separator for combining key iterables

    def __init__(self, db: Type[dbing.LMDBer], *,
                       subkey: str='docs.',
                       dupsort: bool=False,
                       sep: str=None,
                       **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
        """
        super(SuberBase, self).__init__()
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=dupsort)
        self.sep = sep if sep is not None else self.Sep


    def _tokey(self, keys: Union[str, bytes, memoryview, Iterable],
                top: bool=False):
        """
        Converts keys to key str with proper separators and returns key bytes.
        If keys is already str then returns. Else If keys is iterable (non-str)
        of strs then joins with separator converts to bytes and returns.
        top allows partial key from top branch of key space given by partial keys

        Returns:
           key (bytes): each element of keys is joined by .sep. If top then last
                        char of key is also .sep

        Parameters:
           keys (Union[str, bytes, Iterable]): str, bytes, or Iterable of str.
           top (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep

        """
        if isinstance(keys, memoryview):  # memoryview of bytes
            return bytes(keys)  # return bytes
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")
        elif hasattr(keys, "decode"): # bytes
            return keys
        return (self.sep.join(keys).encode("utf-8"))


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


    @staticmethod
    def _encode(val):
        return (val.encode("utf-8") if hasattr(val, "encode") else val)


    @staticmethod
    def _decode(val):
        return (val.decode("utf-8") if hasattr(val, "decode") else val)



    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val bytes for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), bytes(val).decode("utf-8"))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iterator): tuple (key, val) over the all the items in
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
            yield (self._tokeys(key), bytes(val).decode("utf-8"))


class Suber(SuberBase):
    """
    Sub DB of LMDBer. Subclass of SuberBase
    """

    def __init__(self, db: Type[dbing.LMDBer], *,
                       subkey: str = 'docs.',
                       dupsort: bool=False, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(Suber, self).__init__(db=db, subkey=subkey, dupsort=False, **kwa)


    def put(self, keys: Union[str, Iterable], val: Union[bytes, str]):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (bytes): value

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        if hasattr(val, "encode"):
            val = val.encode("utf-8")
        return (self.db.putVal(db=self.sdb, key=self._tokey(keys), val=val))


    def pin(self, keys: Union[str, Iterable], val: Union[bytes, str]):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (bytes): value

        Returns:
            result (bool): True If successful. False otherwise.
        """
        if hasattr(val, "encode"):
            val = val.encode("utf-8")
        return (self.db.setVal(db=self.sdb, key=self._tokey(keys), val=val))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets val at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            data (str):  decoded as utf-8
            None if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (data := mydb.get(keys)) is None:
                raise ExceptionHere
            use data here

        """
        data = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return bytes(data).decode("utf=8") if data is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delVal(db=self.sdb, key=self._tokey(keys)))



class DupSuber(SuberBase):
    """
    Sub DB of LMDBer. Subclass of SuberBase that supports multiple entries at
    each key (duplicates) with dupsort==True

    Do not use if  serialized value is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB
    """

    def __init__(self, db: Type[dbing.LMDBer], *,
                       subkey: str='docs.',
                       dupsort: bool=True,
                       **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(DupSuber, self).__init__(db=db, subkey=subkey, dupsort=True, **kwa)


    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): str or bytes of each value to be written at key

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=[self._encode(val) for val in vals]))


    def add(self, keys: Union[str, Iterable], val: Union[bytes, str]):
        """
        Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Union[str, bytes]): value

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._encode(val)))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): str or bytes values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=[self._encode(val) for val in vals]))



    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is str
                          empty list if no entry at keys

        """
        return [self._decode(bytes(val)) for val in
                        self.db.getValsIter(db=self.sdb, key=self._tokey(keys))]


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last dup val at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (str):  value else None if no value at key

        """
        val = self.db.getValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = self._decode(bytes(val))
        return val


    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            iterator:  vals each of str. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield self._decode(bytes(val))


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
            val (Union[str, bytes]):  instance of dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = self._encode(val)
        else:
            val = b''
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=val))


class IoSetSuber(SuberBase):
    """
    Insertion Ordered Set Suber factory class that supports
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
        db (dbing.LMDBer): base LMDB db
        sdb (lmdb._Database): instance of lmdb named sub db for this Suber
        sep (str): separator for combining keys tuple of strs into key bytes
    """
    def __init__(self, db: Type[dbing.LMDBer], *,
                       subkey: str='docs.',
                       dupsort: bool=False, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
        """
        super(IoSetSuber, self).__init__(db=db, subkey=subkey, dupsort=False, **kwa)


    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at effective key made from keys and hidden ordinal suffix.
        Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            vals (Iterable): of str serializations

        Returns:
            result (bool): True If successful, False otherwise.

        """
        return (self.db.putIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._encode(val) for val in vals],
                                     sep=self.sep))


    def add(self, keys: Union[str, Iterable], val: Union[bytes, str]):
        """
        Add val to vals at effective key made from keys and hidden ordinal suffix.
        Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (Union[bytes, str]): serialization

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addIoSetVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._encode(val),
                                    sep=self.sep))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at effective key made from keys and hidden ordinal suffix.
        Overwrites. Removes all pre-existing vals that share same effective keys
        and replaces them with vals

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            vals (Iterable): str serializations

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delIoSetVals(db=self.sdb, key=key)  # delete all values
        return (self.db.setIoSetVals(db=self.sdb,
                                     key=key,
                                     vals=[self._encode(val) for val in vals],
                                     sep=self.sep))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets vals set list at key made from effective keys

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            vals (Iterable):  each item in list is str
                          empty list if no entry at keys

        """
        return ([self._decode(bytes(val)) for val in
                    self.db.getIoSetValsIter(db=self.sdb,
                                             key=self._tokey(keys),
                                             sep=self.sep)])


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last val inserted at effecive key made from keys and hidden ordinal
        suffix.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            val (str):  value str, None if no entry at keys

        """
        val = self.db.getIoSetValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = self._decode(bytes(val))
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
            yield self._decode(bytes(val))



    def cnt(self, keys: Union[str, Iterable]):
        """
        Return count of  values at effective key made from keys and hidden ordinal
        suffix. Zero otherwise

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
        """
        return (self.db.cntIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     sep=self.sep))


    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at effective key made from keys and hidden ordinal suffix
        that matches val is any. Otherwise delets all values at effective key.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (str):  value at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if effective key with val exists so delete successful.
                           False otherwise

        """
        if val is not None:
            val = self._encode(val)
            return self.db.delIoSetVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=val,
                                       sep=self.sep)
        else:
            return self.db.delIoSetVals(db=self.sdb,
                                       key=self._tokey(keys),
                                       sep=self.sep)


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb. Each entry at a
        given key including all io set members is yielded as a separate item.

        Returns:
            iterator (Iterator): of tuples of keys tuple and val str for
                           each entry in db. Raises StopIteration when done
        """
        for iokey, val in self.db.getAllItemIter(db=self.sdb, split=False):
            key, ion = dbing.unsuffix(iokey, sep=self.sep)
            yield (self._tokeys(key), self._decode(bytes(val)))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Return iterator over all the items in top branch defined by keys where
        keys may be truncation of full branch.

        Returns:
            iterator (Iterator): tuple (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database. Append "" to end of keys Iterable to
                ensure get properly separated top branch key.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            key, ion = dbing.unsuffix(iokey, sep=self.sep)
            yield (self._tokeys(key), self._decode(bytes(val)))



    def getIoItem(self, keys: Union[str, Iterable]):
        """
        Gets (iokeys, val) ioitems list at key made from keys where key is
        apparent effective key  and ioitems all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            items (Itearable):  each item in list is tuple (iokeys, val) where each
                    iokeys is actual key tuple with hidden suffix and
                    each val is str
                    empty list if no entry at keys

        """
        return ([(self._tokeys(iokey), self._decode(bytes(val))) for iokey, val in
                        self.db.getIoSetItemsIter(db=self.sdb,
                                                  key=self._tokey(keys),
                                                  sep=self.sep)])


    def getIoItemIter(self, keys: Union[str, Iterable]):
        """
        Gets (iokeys, val) ioitems  iterator at key made from keys where key is
        apparent effective key and items all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            iterator (Iterator):  each item iterated is tuple (iokeys, val) where each
                    iokeys is actual keys tuple with hidden suffix and
                    each val is str
                    empty list if no entry at keys.
                    Raises StopIteration when done

        """
        for iokey, val in self.db.getIoSetItemsIter(db=self.sdb,
                                                    key=self._tokey(keys),
                                                    sep=self.sep):
            yield (self._tokeys(iokey), self._decode(bytes(val)))


    def getAllIoItemIter(self):
        """
        Return iterator over the all the items in subdb. Each entry at a
        given key including set members is yielded as a separate item.

        Returns:
            iterator (Iterator): of tuples of (iokey, val) where iokey is actual key with
            ion ordinal and val is str for each entry in db.
            Raises StopIteration when done
        """
        # getAllItemIter converts both key and val memoryviews to bytes
        for iokey, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(iokey), self._decode(bytes(val)))


    def getTopIoItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iterator): tuple (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb.


        Parameters:
            keys (Iterable): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database. Append "" to end of keys Iterable to
                ensure get properly separated top branch key.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield (self._tokeys(iokey), self._decode(bytes(val)))


    def remIokey(self, iokeys: Union[str, bytes, memoryview, Iterable]):
        """
        Removes entry at keys

        Parameters:
            iokeys (Iterable): of key str or tuple of key strs to be combined
                            in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        return self.db.delIoSetIokey(db=self.sdb, iokey=self._tokey(iokeys))


class SerderSuber(Suber):
    """
    Sub class of Suber where data is serialized Serder instance
    Automatically serializes and deserializes using Serder methods

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(SerderSuber, self).__init__(*pa, **kwa)


    def put(self, keys: Union[str, Iterable], val: coring.Serder):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Serder): instance

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))


    def pin(self, keys: Union[str, Iterable], val: coring.Serder):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Serder): instance

        Returns:
            result (bool): True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets Serder at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            Serder:
            None: if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (srder := mydb.get(keys)) is None:
                raise ExceptionHere
            use srdr here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return coring.Serder(raw=bytes(val)) if val is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delVal(db=self.sdb, key=self._tokey(keys)))


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), coring.Serder(raw=bytes(val)))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iterator): tuple (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield (self._tokeys(iokey), coring.Serder(raw=bytes(val)))


class SerderDupSuber(DupSuber):
    """
    Sub class of DupSuber that supports multiple entries at each key (duplicates)
    with dupsort==True, where data is serialized Serder instance.
    Automatically serializes and deserializes using Serder methods

    Do not use if  serialized value is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(SerderDupSuber, self).__init__(*pa, **kwa)


    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): instances of coring.Serder

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=[val.raw for val in vals]))


    def add(self, keys: Union[str, Iterable], val: coring.Serder):
        """
        Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (coring.Serder): value

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): instances of coring.Serder

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=[val.raw for val in vals]))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is instance of coring.Serder
                          empty list if no entry at keys

        """
        return [coring.Serder(raw=bytes(val)) for val in
                        self.db.getValsIter(db=self.sdb, key=self._tokey(keys))]


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last dup val at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (coring.Serder):  instance of Serder else None if no value at key

        """
        val = self.db.getValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = coring.Serder(raw=bytes(val))
        return val



    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            iterator:  vals each of coring.Serder. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield coring.Serder(raw=bytes(val))


    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (coring.Serder):  instance of coring.Serder dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = val.raw
        else:
            val = b''
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=val))


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder instance for
            each entry in db. Raises StopIteration when done

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), coring.Serder(raw=bytes(val)))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iteratore: tuple (key, val) over the all the items in
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
            yield (self._tokeys(key), coring.Serder(raw=bytes(val)))



class CesrSuber(Suber):
    """
    Sub class of Suber where data is CESR encode/decode ducktyped subclass
    instance such as Matter, Indexer, Counter with .qb64b property when provided
    as fully qualified serialization
    Automatically serializes and deserializes from qb64b to/from CESR instances

    """

    def __init__(self, *pa, klas: Type[coring.Matter] = coring.Matter, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter
        """
        if not (issubclass(klas, coring.Matter) or
                issubclass(klas, coring.Indexer) or
                issubclass(kas, coring.Counter)):
            raise ValueError("Invalid klas type={}.".format(klas))
        super(CesrSuber, self).__init__(*pa, **kwa)
        self.klas = klas


    def put(self, keys: Union[str, Iterable], val: coring.Matter):
        """
        Puts qb64b of Matter instance val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Matter): instance of self.klas

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))


    def pin(self, keys: Union[str, Iterable], val: coring.Matter):
        """
        Pins (sets) qb64b of Matter instance val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Matter): instance of self.klas

        Returns:
            result (bool): True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets Matter instance at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (Matter): instance of self.klas
            None if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (matter := mydb.get(keys)) is None:
                raise ExceptionHere
            use matter here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return self.klas(qb64b=bytes(val)) if val is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delVal(db=self.sdb, key=self._tokey(keys)))


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val Matter for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.klas(qb64b=bytes(val)))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iteratore: tuple (key, val) over the all the items in
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
            yield (self._tokeys(key), self.klas(qb64b=bytes(val)))


class CatSuberBase(SuberBase):
    """
    Base Class whose values stored in db are a concatenation of the  .qb64b property
    from one or more  subclass instances (qb64b is bytes of fully qualified
    serialization) that support CESR encode/decode ducktyped subclass instance
    such as Matter, Indexer, Counter
    Automatically serializes and deserializes from qb64b to/from CESR instances

     Attributes:
        db (dbing.LMDBer): base LMDB db
        sdb (lmdb._Database): instance of lmdb named sub db for this Suber
        sep (str): separator for combining keys tuple of strs into key bytes
        klas (Iterable): of Class references to subclasses of CESR compatible
                , each of to Type[coring.Matter etc]
    """

    def __init__(self, *pa, klas: Iterable = None, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            klas (Iterable): of Class references to subclasses of Matter, each
                of to Type[coring.Matter]

        """
        if klas is None:
            klas = (coring.Matter, )  # set default to tuple of single Matter
        if not nonStringIterable(klas):  # not iterable
            klas = (klas, )  # make it so
        for k in klas:
            if not (issubclass(k, coring.Matter) or
                    issubclass(k, coring.Indexer) or
                     issubclass(k, coring.Counter)):
                raise ValueError("Invalid klas type={}".format(k))
        super(CatSuberBase, self).__init__(*pa, **kwa)
        self.klas = klas


    def _cat(self, objs: Iterable):
        """
        Concatenates .qb64b of each instance in objs and returns val bytes

        Returns:
           val (bytes): concatenation of .qb64b of each object instance in vals

        Parameters:
           subs (Iterable): of subclass instances.

        """
        return (b''.join(val.qb64b for val in objs))


    def _uncat(self, val: Union[bytes, memoryview]):
        """
        Converts val bytes to vals tuple of subclass instances by deserializing
        .qb64b  concatenation in order of each instance in .klas

        Returns:
           vals (tuple): subclass instances

        Parameters:
           val (Union[bytes, memoryview]):  of concatenation of .qb64b

        """
        if not isinstance(val, bytearray):  # memoryview or bytes
            val = bytearray(val)  #  so may strip
        return tuple(klas(qb64b=val, strip=True) for klas in self.klas)


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and vals Iterable of Matter instances
                      in order from self.klas for each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self._uncat(val))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iterator): of tuples of keys tuple and vals Iterable of
                    Matter instances in order fromfrom .klas for each entry
                    in db for each entry in db all
                      the items in subdb whose key startswith key made from keys.
                      Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.

        """
        for key, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield (self._tokeys(key), self._uncat(val))


class CatSuber(CatSuberBase):
    """
    Class whose values stored in db are a concatenation of the  .qb64b property
    from one or more  subclass instances (qb64b is bytes of fully qualified
    serialization) that support CESR encode/decode ducktyped subclass instance
    such as Matter, Indexer, Counter
    Automatically serializes and deserializes from qb64b to/from CESR instances

     Attributes:
        db (dbing.LMDBer): base LMDB db
        sdb (lmdb._Database): instance of lmdb named sub db for this Suber
        sep (str): separator for combining keys tuple of strs into key bytes
        klas (Iterable): of Class references to subclasses of CESR compatible
                , each of to Type[coring.Matter etc]
    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            klas (Iterable): of Class references to subclasses of Matter, each
                of to Type[coring.Matter]

        """
        super(CatSuber, self).__init__(*pa, **kwa)


    def put(self, keys: Union[str, Iterable], val: Iterable):
        """
        Puts concatenation of qb64b of Matter instances in iterable val
           at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Iterable): instances in order from .klas

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._cat(val)))


    def pin(self, keys: Union[str, Iterable], val: Iterable):
        """
        Pins (sets) qb64 of concatenation of Matter instances vals at key
        made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Iterable): instances in order from .klas

        Returns:
            result (bool): True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._cat(val)))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets Iterable of Matter instances at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (Iterable): instances in order from self.klas
            None if no entry at keys

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return self._uncat(val) if val is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delVal(db=self.sdb, key=self._tokey(keys)))


class CatIoSetSuber(CatSuberBase, IoSetSuber):
    """
    Sub class of CatSuberBase and IoSetSuber where values stored in db are a
    concatenation of .qb64b property from one or more Cesr compatible subclass
    instances that automatically serializes and deserializes to/from qb64b .
    (qb64b is bytes of fully qualified serialization)
    In addition stored at each effective key may be a set of distinct values that
    share that same effective key where each member of the set is retrieved in
    insertion order (dupsort==False)
    The methods allows an Iterable (set valued) of Iterables of Matter subclass
    instances to be stored at a given effective key in insertion order.

    Actual keys include a hidden ordinal key suffix that tracks insertion order.
    The suffix is appended and stripped transparently from the keys. The set of
    items with duplicate effective keys are retrieved in insertion order when
    iterating or as a list of the set elements. The actual iokey for any item
    includes the ordinal suffix.

    Attributes:
        db (dbing.LMDBer): base LMDB db
        sdb (lmdb._Database): instance of lmdb named sub db for this Suber
        sep (str): separator for combining keys tuple of strs into key bytes
        klas (Iterable): of Class references to subclasses of Matter, each
                of to Type[coring.Matter]


    """
    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                            False (default) means do not enable duplicates at
                            each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            klas (Iterable): of Class references to subclasses of Matter, each
                of to Type[coring.Matter]

        """
        super(CatIoSetSuber, self).__init__(*pa, **kwa)


    def put(self, keys: Union[str, Iterable], vals: Iterable):
        """
        Puts concatenation of qb64b of Matter instances in iterable of iterable
        vals at effecive key made from keys and hidden ordinal suffix.
        Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form effective key
            vals (Iterable): of iterables of Matter subclass instances in order
                             of .klas.

        Returns:
            result (bool): True If successful, False otherwise.


        """
        return (self.db.putIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._cat(mvals) for mvals in vals],
                                     sep=self.sep))


    def add(self, keys: Union[str, Iterable], val: Iterable):
        """
        Add val to vals at effective key made from keys and hidden ordinal suffix.
        Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form effective key
            val (Iterable): of Matter subclass instances

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.
        """
        return (self.db.addIoSetVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._cat(val),
                                    sep=self.sep))


    def pin(self, keys: Union[str, Iterable], vals: Iterable):
        """
        Pins (sets) qb64 of concatenation of Matter instances vals at key
        made from keys. Overwrites.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form effective key
            vals (Iterable): of iterables of Matter subclass instances in order
                             of .klas.

        Pins (sets) vals at effective key made from keys and hidden ordinal suffix.
        Overwrites. Each val in vals is Iterable of instances of Matter subclasses
        in order of .klas. Removes all pre-existing vals that share same effective keys
        and replaces them with vals

        Returns:
            result (bool): True If successful, False otherwise.
        """
        key = self._tokey(keys)
        self.db.delIoSetVals(db=self.sdb, key=key)  # delete all values
        return (self.db.setIoSetVals(db=self.sdb,
                                     key=key,
                                     vals=[self._cat(mvals) for mvals in vals],
                                     sep=self.sep))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets Iterable of Iterable of Matter subclass instances at keys

        Parameters:
            keys (Iterable): of key strs to be combined in order to form effective key

        Returns:
            vals (Iterable): of iterables of Matter subclass instances in order
                             of .klas.
                             Empty Iterable if no entry at keys



        """
        return ([self._uncat(val) for val in
                    self.db.getIoSetValsIter(db=self.sdb,
                                             key=self._tokey(keys),
                                             sep=self.sep)])


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last Iterable of vals inserted at effecive key made from keys and
        hidden ordinal suffix.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form effective key

        Returns:
            vals (Iterable): of Matter subclass instances in order
                             of .klas.
                             None if no entry at keys

        """
        val = self.db.getIoSetValLast(db=self.sdb, key=self._tokey(keys))
        return (self._uncat(val) if val is not None else val)



    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets vals Iterator of Iteratables at effecive key made from keys and
        hidden ordinal suffix. All vals in set of vals that share same effecive
        key are retrieved in insertion order. Each val in set is Iterable of
        Matter subclass instances.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form effective key

        Returns:
            vals (Iterator): of iterables of Matter subclass instances in order
                             of .klas.
                             Raises StopIteration when done

        """
        for val in self.db.getIoSetValsIter(db=self.sdb,
                                            key=self._tokey(keys),
                                            sep=self.sep):
            yield self._uncat(val)



    def cnt(self, keys: Union[str, Iterable]):
        """
        Return count of  values at effective key made from keys and hidden ordinal
        suffix. Zero otherwise

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        return (self.db.cntIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     sep=self.sep))




    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at effective key made from keys and hidden ordinal suffix
        that matches val is any. Otherwise delets all values at effective key.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (Iterable):  at key to delete where val is Iterable
                              of Matter subclass instances.
                              if val is None then remove all values at key

        Returns:
           result (bool): True if effective key with val exists so delete successful.
                           False otherwise

        """
        if val is not None:
            val = self._cat(val)
            return self.db.delIoSetVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=val,
                                       sep=self.sep)
        else:
            return self.db.delIoSetVals(db=self.sdb,
                                       key=self._tokey(keys),
                                       sep=self.sep)


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb. Each entry at a
        given key including all io set members is yielded as a separate item.

        Returns:
            iterator (Iterator):  of tuple (keys, vals) of  keys Iterable and
                vals Iterable for each entry in db.

        Raises StopIteration when done
        """
        for iokey, val in self.db.getAllItemIter(db=self.sdb, split=False):
            key, ion = dbing.unsuffix(iokey, sep=self.sep)
            yield (self._tokeys(key), self._uncat(val))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iterator): tuple (keys, vals) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb. Vals is Iterable of vals.

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            key, ion = dbing.unsuffix(iokey, sep=self.sep)
            yield (self._tokeys(key), self._uncat(val))



    def getIoItem(self, keys: Union[str, Iterable]):
        """
        Gets (iokeys, vals) ioitems list at key made from keys where key is
        apparent effective key  and ioitems all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            items (Iterable):  each item in list is tuple (iokeys, vals) where each
                    iokeys is actual key tuple with hidden suffix and
                    each vals is Iterable of Matter subclass instances.
                    empty list if no entry at keys

        """
        return ([(self._tokeys(iokey), self._uncat(val)) for iokey, val in
                        self.db.getIoSetItemsIter(db=self.sdb,
                                                  key=self._tokey(keys),
                                                  sep=self.sep)])


    def getIoItemIter(self, keys: Union[str, Iterable]):
        """
        Gets (iokeys, val) ioitems  iterator at key made from keys where key is
        apparent effective key and items all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            iterator (Iterator):  each item iterated is tuple (iokeys, vals)
                    each item in list is tuple (iokeys, vals) where each
                    iokeys is actual key tuple with hidden suffix and
                    each vals is Iterable of Matter subclass instances.

                    Raises StopIteration when done

        """
        for iokey, val in self.db.getIoSetItemsIter(db=self.sdb,
                                                    key=self._tokey(keys),
                                                    sep=self.sep):
            yield (self._tokeys(iokey), self._uncat(val))


    def getAllIoItemIter(self):
        """
        Return iterator over the all the items in subdb. Each entry at a
        given key including set members is yielded as a separate item.

        Returns:
            iterator (Iterator):  each item iterated is tuple (iokeys, vals)
                    each item in list is tuple (iokeys, vals) where each
                    iokeys is actual key tuple with hidden suffix and
                    each vals is Iterable of Matter subclass instances.
            Raises StopIteration when done
        """
        for iokey, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(iokey), self._uncat(val))


    def getTopIoItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iterator): each item iterated is tuple (iokeys, vals)
                    each item in list is tuple (iokeys, vals) where each
                    iokeys is actual key tuple with hidden suffix and
                    each vals is Iterable of Matter subclass instances.
                    Keys may be key space trancation of top branch of key space.
                    When keys is empty then returns all items in subdb

            Raises StopIteration when done

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield (self._tokeys(iokey), self._uncat(val))


    def remIokey(self, iokeys: Union[str, bytes, memoryview, Iterable]):
        """
        Removes entry at keys

        Parameters:
            iokeys (tuple): of key str or tuple of key strs to be combined
                            in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        return self.db.delIoSetIokey(db=self.sdb, iokey=self._tokey(iokeys))


class CesrDupSuber(DupSuber):
    """
    Sub class of DupSuber that supports multiple entries at each key (duplicates)
    with dupsort==True, where data where data is Matter.qb64b property
    which is a fully qualified serialization of matter subclass instance
    Automatically serializes and deserializes from qb64b to/from Matter instances

    Do not use if  serialized value is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB
    """
    def __init__(self, *pa, klas: Type[coring.Matter] = coring.Matter, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter
        """
        if not (issubclass(klas, coring.Matter) or
                issubclass(klas, coring.Indexer) or
                issubclass(kas, coring.Counter)):
            raise ValueError("Invalid klas type={}".format(klas))
        super(CesrDupSuber, self).__init__(*pa, **kwa)
        self.klas = klas


    def put(self, keys: Union[str, Iterable], vals: list):
        """
        Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): instances of coring.Matter (subclass)

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=[val.qb64b for val in vals]))


    def add(self, keys: Union[str, Iterable], val: coring.Matter):
        """
        Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (coring.Matter): instance (subclass)

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))


    def pin(self, keys: Union[str, Iterable], vals: list):
        """
        Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            vals (list): instances of coring.Matter (subclass)

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=[val.qb64b for val in vals]))


    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is instance of self.klas
                          empty list if no entry at keys

        """
        return [self.klas(qb64b=bytes(val)) for val in
                        self.db.getValsIter(db=self.sdb, key=self._tokey(keys))]


    def getLast(self, keys: Union[str, Iterable]):
        """
        Gets last dup val at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (str):  instance of self.klas else None if no value at key

        """
        val = self.db.getValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = self.klas(qb64b=bytes(val))
        return val



    def getIter(self, keys: Union[str, Iterable]):
        """
        Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            iterator:  vals each of self.klas. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield self.klas(qb64b=bytes(val))


    def rem(self, keys: Union[str, Iterable], val=None):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (coring.Matter):  instance of coring.Matter subclass dup val
                at key to delete
                if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = val.qb64b
        else:
            val = b''
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=val))


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val self.klas instance for
            each entry in db. Raises StopIteration when done

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.klas(qb64b=bytes(val)))


    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iteratore: tuple (key, val) over the all the items in
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
            yield (self._tokeys(key), self.klas(qb64b=bytes(val)))


class SignerSuber(CesrSuber):
    """
    Sub class of MatterSuber where data is Signer subclass instance .qb64b propery
    which is a fully qualified serialization and uses the key which is the qb64b
    of the signer.verfer to get the transferable property of the verfer
    Automatically serializes and deserializes from qb64b to/from Signer instances

    Assumes that last or only element of db key from keys for all entries is the qb64
    of a public key for the associated Verfer instance. This allows returned
    Signer instance to have its .transferable property set correctly.
    """

    def __init__(self, *pa, klas: Type[coring.Signer] = coring.Signer, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter
        """
        if not (issubclass(klas, coring.Signer)):
            raise ValueError("Invalid klas type={}, expected {}."
                             "".format(klas, coring.Signer))
        super(SignerSuber, self).__init__(*pa, **kwa)
        self.klas = klas


    def get(self, keys: Union[str, Iterable]):
        """
        Gets Signer instance at keys

        Returns:
            val (Signer):  transferable determined by key which is verfer
            None if no entry at keys

        Parameters:
            keys (Union[str, iterable]): key strs to be combined in order to
                form key. Last element of keys is verkey used to determin
                .transferable for Signer

        Usage:
            Use walrus operator to catch and raise missing entry
            if (signer := mydb.get(keys)) is None:
                raise ExceptionHere
            use signer here

        """
        key = self._tokey(keys)  # keys maybe string or tuple
        val = self.db.getVal(db=self.sdb, key=key)
        keys = self._tokeys(key)  # verkey is last split if any
        verfer = coring.Verfer(qb64b=keys[-1])  # last split
        return (self.klas(qb64b=bytes(val), transferable=verfer.transferable)
                if val is not None else None)


    def getAllItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val Signer for
                each entry in db
        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            keys = self._tokeys(key)  # verkey is last split if any
            verfer = coring.Verfer(qb64b=keys[-1])   # last split
            yield (keys, self.klas(qb64b=bytes(val),
                                   transferable=verfer.transferable))



    def getTopItemIter(self, keys: Union[str, Iterable]):
        """
        Returns:
            iterator (Iteratore: tuple (key, val) over the all the items in
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
            ikeys = self._tokeys(key)  # verkey is last split if any
            verfer = coring.Verfer(qb64b=ikeys[-1])   # last split
            yield (ikeys, self.klas(qb64b=bytes(val),
                                   transferable=verfer.transferable))


class CryptSignerSuber(SignerSuber):
    """
    Sub class of SignerSuber where data is Signer subclass instance .qb64b property
    that has been encrypted if encrypter provided.
    which is a fully qualified serialization and uses the key which is the qb64b
    of the signer.verfer to get the transferable property of the verfer
    Automatically serializes and deserializes from qb64b to/from Signer instances

    Assumes that last or only element of db key from keys for all entries is the qb64
    of a public key for the associated Verfer instance. This allows returned
    Signer instance to have its .transferable property set correctly.
    """

    def put(self, keys: Union[str, Iterable], val: coring.Matter,
            encrypter: coring.Encrypter = None):
        """
        Puts qb64 of Matter instance val at key made from keys. Does not overwrite
        If encrypter provided then encrypts first

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Signer): instance of self.klas
            encrypter (coring.Encrypter): optional

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        if encrypter:
            val = encrypter.encrypt(matter=val)  # returns Cipher instance
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))


    def pin(self, keys: Union[str, Iterable], val: coring.Matter,
            encrypter: coring.Encrypter = None):
        """
        Pins (sets) qb64 of Matter instance val at key made from keys. Overwrites.
        If encrypter provided then encrypts first

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Signer): instance of self.klas
            encrypter (coring.Encrypter): optional

        Returns:
            result (bool): True If successful. False otherwise.
        """
        if encrypter:
            val = encrypter.encrypt(matter=val)  # returns Cipher instance
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))



    def get(self, keys: Union[str, Iterable], decrypter: coring.Decrypter = None):
        """
        Gets Signer instance at keys. If decrypter then assumes value in db was
        encrypted and so decrypts value in db before converting to Signer.


        Returns:
            val (Signer):  transferable determined by key which is verfer
            None if no entry at keys

        Parameters:
            keys (Union[str, iterable]): key strs to be combined in order to
                form key. Last element of keys is verkey used to determin
                .transferable for Signer
            decrypter (coring.Decrypter): optional. If provided assumes value in
                db was encrypted and so decrypts before converting to Signer.

        Usage:
            Use walrus operator to catch and raise missing entry
            if (signer := mydb.get(keys)) is None:
                raise ExceptionHere
            use signer here

        """
        key = self._tokey(keys)  # keys maybe string or tuple
        val = self.db.getVal(db=self.sdb, key=key)
        if val is None:
            return None
        keys = self._tokeys(key)  # verkey is last split if any
        verfer = coring.Verfer(qb64b=keys[-1])  # last split
        if decrypter:
            return (decrypter.decrypt(ser=bytes(val),
                                      transferable=verfer.transferable))
        return (self.klas(qb64b=bytes(val), transferable=verfer.transferable))


    def getAllItemIter(self, decrypter: coring.Decrypter = None):
        """
        Return iterator over the all the items in subdb. If decrypter then
        assumes values in db were encrypted and so decrypts each before
        converting to Signer.

        Returns:
            iterator: of tuples of keys tuple and val Signer for each entry in db

        Parameters:
            decrypter (coring.Decrypter): optional. If provided assumes value in
                db was encrypted and so decrypts before converting to Signer.

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            keys = self._tokeys(key)  # verkey is last split if any
            verfer = coring.Verfer(qb64b=keys[-1])   # last split
            if decrypter:
                yield (keys, decrypter.decrypt(ser=bytes(val),
                                               transferable=verfer.transferable))
            else:
                yield (keys, self.klas(qb64b=bytes(val),
                                   transferable=verfer.transferable))



    def getTopItemIter(self, keys: Union[str, Iterable],
                       decrypter: coring.Decrypter = None):
        """
        Returns:
            iterator (Iterator): of tuples (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        decrypter (coring.Decrypter): optional. If provided assumes value in
                db was encrypted and so decrypts before converting to Signer.

        Parameters:
            keys (Iterator): tuple of bytes or strs that may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.

        """
        for key, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            ikeys = self._tokeys(key)  # verkey is last split if any
            verfer = coring.Verfer(qb64b=ikeys[-1])   # last split
            if decrypter:
                yield (ikeys, decrypter.decrypt(ser=bytes(val),
                                            transferable=verfer.transferable))
            else:
                yield (ikeys, self.klas(qb64b=bytes(val),
                                            transferable=verfer.transferable))
