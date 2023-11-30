# -*- encoding: utf-8 -*-
"""
KERI
keri.db.subing module

Provide variety of mixin classes for LMDB sub-dbs with various behaviors.

Principally:

Suber class provides put, pin, get, rem and getItemIter method for managing
a serialized value in a sub db with an iterable set of keys defining the key space

CesrSuber class extends Suber for values that are serializations of CESR serializable
object instances. Ducktyped subclasses of Matter, Indexer, and Counter or the like.

IoSetSuber class extends Suber to allow a set of values to be stored in insertion
order at each effective key. Only one copy of a unique value is allowed in the
set at a given effective key. The effective key suffixes an ordinal to the key
space to track insertion ordering. IoSetSuber adds additional methods to manage
IoSets of values.

CatCesrSuber adds the ability to store multiple concatenated serializations at
a value

CatCesrIoSetSuber combines the capabilities

Other special classer for special values

SerderSuber stores Serialized Serder Instances of in JSON, CBOR, or MGPK

Also for Secrets private keys
SignerSuber
CryptSignerSuber

Also for using the dupsort==true mechanism is
DupSuber
CesrDupSuber


"""
from typing import Type, Union
from collections.abc import Iterable, Iterator

from .. import help
from ..help.helping import nonStringIterable
from ..core import coring, scheming, serdering
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

    def __init__(self, db: dbing.LMDBer, *,
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
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")
        if isinstance(keys, memoryview):  # memoryview of bytes
            return bytes(keys)  # return bytes
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
        if hasattr(key, "decode"):  # bytes
            key = key.decode("utf-8")  # convert to str
        return tuple(key.split(self.sep))


    def _ser(self, val: Union[str, memoryview, bytes]):
        """
        Serialize value to bytes to store in db
        Parameters:
            val (Union[str, memoryview, bytes]): encodable as bytes
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # return bytes
        return (val.encode("utf-8") if hasattr(val, "encode") else val)


    def _des(self, val: Union[str, memoryview, bytes]):
        """
        Deserialize val to str
        Parameters:
            val (Union[str, memoryview, bytes]): decodable as str
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # convert to bytes
        return (val.decode("utf-8") if hasattr(val, "decode") else val)


    def getItemIter(self, keys: Union[str, Iterable]=b""):
        """
        Returns:
            items (Iterator): if (key, val) tuples over the all the items in
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
            yield (self._tokeys(key), self._des(val))


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


class Suber(SuberBase):
    """
    Sub DB of LMDBer. Subclass of SuberBase
    """

    def __init__(self, db: dbing.LMDBer, *,
                       subkey: str = 'docs.',
                       dupsort: bool=False, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(Suber, self).__init__(db=db, subkey=subkey, dupsort=False, **kwa)


    def put(self, keys: Union[str, Iterable], val: Union[bytes, str, any]):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (bytes): value

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._ser(val)))


    def pin(self, keys: Union[str, Iterable], val: Union[bytes, str]):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (bytes): value

        Returns:
            result (bool): True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._ser(val)))


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
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return (self._des(val) if val is not None else None)


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delVal(db=self.sdb, key=self._tokey(keys)))



class CesrSuberBase(SuberBase):
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
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter
        """
        super(CesrSuberBase, self).__init__(*pa, **kwa)
        self.klas = klas


    def _ser(self, val: coring.Matter):
        """
        Serialize value to bytes to store in db
        Parameters:
            val (coring.Matter): instance Matter ducktype with .qb64b attribute
        """
        return val.qb64b


    def _des(self, val: Union[str, memoryview, bytes]):
        """
        Deserialize val to str
        Parameters:
            val (Union[str, memoryview, bytes]): convertable to coring.matter
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # convert to bytes
        return self.klas(qb64b=val)  # converts to bytes


class CesrSuber(CesrSuberBase, Suber):
    """
    Sub class of Suber where data is CESR encode/decode ducktyped subclass
    instance such as Matter, Indexer, Counter with .qb64b property when provided
    as fully qualified serialization.
    Extents Suber to support val that are ducktyped CESR serializable .qb64 .qb64b
    subclasses such as coring.Matter, coring.Indexer, coring.Counter.
    Automatically serializes and deserializes from qb64b to/from CESR instances

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter
        """
        super(CesrSuber, self).__init__(*pa, **kwa)


class CatCesrSuberBase(CesrSuberBase):
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
        super(CatCesrSuberBase, self).__init__(*pa, klas=klas, **kwa)
        # self.klas = klas


    def _ser(self, val: Union[Iterable, coring.Matter]):
        """
        Serialize val to bytes to store in db
        Concatenates .qb64b of each instance in objs and returns val bytes

        Returns:
           val (bytes): concatenation of .qb64b of each object instance in vals

        Parameters:
           subs (Union[Iterable, coring.Matter]): of subclass instances.

        """
        if not nonStringIterable(val):  # not iterable
            val = (val, )  # make iterable
        return (b''.join(obj.qb64b for obj in val))


    def _des(self, val: Union[str, memoryview, bytes]):
        """
        Converts val bytes to vals tuple of subclass instances by deserializing
        .qb64b  concatenation in order of each instance in .klas

        Returns:
           vals (tuple): subclass instances

        Parameters:
           val (Union[bytes, memoryview]):  of concatenation of .qb64b

        """
        if not isinstance(val, bytearray):  # is memoryview or bytes
            val = bytearray(val)  # convert so may strip
        return tuple(klas(qb64b=val, strip=True) for klas in self.klas)


class CatCesrSuber(CatCesrSuberBase, Suber):
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
        super(CatCesrSuber, self).__init__(*pa, **kwa)


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
    def __init__(self, db: dbing.LMDBer, *,
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


    def put(self, keys: Union[str, Iterable], vals: Iterable):
        """
        Puts all vals at effective key made from keys and hidden ordinal suffix.
        that are not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            vals (Iterable): of str serializations

        Returns:
            result (bool): True If successful, False otherwise.

        """
        return (self.db.putIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._ser(val) for val in vals],
                                     sep=self.sep))


    def add(self, keys: Union[str, Iterable], val: Union[bytes, str, memoryview]):
        """
        Add val to vals at effective key made from keys and hidden ordinal suffix.
        that is not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (Union[bytes, str]): serialization

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addIoSetVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._ser(val),
                                    sep=self.sep))


    def pin(self, keys: Union[str, Iterable], vals: Iterable):
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
                                     vals=[self._ser(val) for val in vals],
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
        return ([self._des(val) for val in
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
        return (self._des(val) if val is not None else val)



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
            yield self._des(val)



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


    def rem(self, keys: Union[str, Iterable], val: Union[str, bytes, memoryview]=b''):
        """
        Removes entry at effective key made from keys and hidden ordinal suffix
        that matches val if any. Otherwise deletes all values at effective key.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (str):  value at key to delete
                              if val is empty then remove all values at key

        Returns:
           result (bool): True if effective key with val exists so delete successful.
                           False otherwise

        """
        if val:
            return self.db.delIoSetVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=self._ser(val),
                                       sep=self.sep)
        else:
            return self.db.delIoSetVals(db=self.sdb,
                                       key=self._tokey(keys),
                                       sep=self.sep)


    def getItemIter(self, keys: Union[str, Iterable]=b""):
        """
        Return iterator over all the items in top branch defined by keys where
        keys may be truncation of full branch.

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
            yield (self._tokeys(key), self._des(val))


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
        return ([(self._tokeys(iokey), self._des(val)) for iokey, val in
                        self.db.getIoSetItemsIter(db=self.sdb,
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
            yield (self._tokeys(iokey), self._des(val))


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
            yield (self._tokeys(iokey), self._des(val))


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


class CesrIoSetSuber(CesrSuberBase, IoSetSuber):
    """
    Subclass of CesrSuber and IoSetSuber.
    Class whose values stored in db are a concatenation of the  .qb64b property
    from one or more  subclass instances (qb64b is bytes of fully qualified
    serialization) that support CESR encode/decode ducktyped subclass instance
    such as Matter, Indexer, Counter
    Automatically serializes and deserializes from qb64b to/from CESR instances

    Extends IoSetSuber with mixin methods ._ser and ._des from CesrSuberBase
    so that all IoSetSuber methods now work with CESR subclass for each val.

    IoSetSuber stores at each effective key a set of distinct values that
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
        super(CesrIoSetSuber, self).__init__(*pa, **kwa)



class CatCesrIoSetSuber(CatCesrSuberBase, IoSetSuber):
    """
    Sub class of CatSuberBase and IoSetSuber where values stored in db are a
    concatenation of .qb64b property from one or more Cesr compatible subclass
    instances that automatically serializes and deserializes to/from qb64b .
    (qb64b is bytes of fully qualified serialization).

    Extends IoSetSuber with mixin methods ._ser and ._des from CatSuberBase
    so that all IoSetSuber methods now work with an Iterable of CESR subclass
    for each val.

    IoSetSuber stores at each effective key a set of distinct values that
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
        super(CatCesrIoSetSuber, self).__init__(*pa, **kwa)



class SignerSuber(CesrSuber):
    """
    Sub class of CesrSuber where data is Signer subclass instance .qb64b propery
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


    def getItemIter(self, keys: Union[str, Iterable]=b""):
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



    def getItemIter(self, keys: Union[str, Iterable]=b"",
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


class SerderSuber(Suber):
    """
    Sub class of Suber where data is serialized Serder Subclass instance
    given by .klas
    Automatically serializes and deserializes using .klas Serder methods

    """

    def __init__(self, *pa,
                 klas: Type[serdering.Serder] = serdering.SerderKERI,
                 **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key

        Parameters:
            klas (Type[serdering.Serder]): Class reference to subclass of Serder
        """
        super(SerderSuber, self).__init__(*pa, **kwa)
        self.klas = klas


    def put(self, keys: Union[str, Iterable], val: serdering.SerderKERI):
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


    def pin(self, keys: Union[str, Iterable], val: serdering.SerderKERI):
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
        return self.klas(raw=bytes(val)) if val is not None else None


    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.delVal(db=self.sdb, key=self._tokey(keys)))


    def getItemIter(self, keys: Union[str, Iterable]=b""):
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
            yield self._tokeys(iokey), self.klas(raw=bytes(val))


class SchemerSuber(Suber):
    """
    Sub class of Suber where data is serialized Schemer instance
    Automatically serializes and deserializes using Schemer methods

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(SchemerSuber, self).__init__(*pa, **kwa)

    def put(self, keys: Union[str, Iterable], val: scheming.Schemer):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Schemer): instance

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def pin(self, keys: Union[str, Iterable], val: scheming.Schemer):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Schemer): instance

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
            Schemer:
            None: if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (srder := mydb.get(keys)) is None:
                raise ExceptionHere
            use srdr here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return scheming.Schemer(raw=bytes(val)) if val is not None else None

    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return self.db.delVal(db=self.sdb, key=self._tokey(keys))

    def getItemIter(self, keys: Union[str, Iterable]=b""):
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
            yield self._tokeys(iokey), scheming.Schemer(raw=bytes(val))


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
                                vals=[self._ser(val) for val in vals]))


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
                               val=self._ser(val)))


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
                                vals=[self._ser(val) for val in vals]))



    def get(self, keys: Union[str, Iterable]):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            vals (list):  each item in list is str
                          empty list if no entry at keys

        """
        return [self._des(val) for val in
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
        return self._des(val) if val is not None else val


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
            yield self._des(val)


    def cnt(self, keys: Union[str, Iterable]):
        """
        Return count of dup values at key made from keys, zero otherwise

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        return (self.db.cntVals(db=self.sdb, key=self._tokey(keys)))


    def rem(self, keys: Union[str, Iterable], val=b''):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Union[str, bytes]):  instance of dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=self._ser(val)))


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


    def getItemIter(self, keys: Union[str, Iterable]=b""):
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
