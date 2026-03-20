# -*- encoding: utf-8 -*-
"""
KERI
keri.db.koming module

"""
import json
from dataclasses import dataclass
from collections.abc import Iterable

from hio.help import ogler

import cbor2
import msgpack

from .dbing import LMDBer
from ..help import helping

logger = ogler.getLogger()


class KomerBase:
    """
    KomerBase is a base class for Komer (Keyspace Object Mapper) subclasses that
    each use a dataclass as the object mapped via serialization to an dber LMDB
    database subclass.
    Each Komer .schema is a dataclass class reference that is used to define
    the fields in each database entry. The base class is not meant to be instantiated.
    Use an instance of one of the subclasses instead.

    Attributes:
        db (LMDBer): instance of LMDB database manager class
        sdb (lmdb._Database): instance of named sub db lmdb for this Komer
        schema (Type[dataclass]): class reference of dataclass subclass
        kind (str): serialization/deserialization type from coring.Serials
        serializer (types.MethodType): serializer method
        deserializer (types.MethodType): deserializer method
        sep (str): separator for combining keys tuple of strs into key bytes
    """
    Sep = '.'  # separator for combining key iterables

    def __init__(self, db: LMDBer, *,
                 subkey: str = 'docs.',
                 klas: type[dataclass],  # class not instance
                 kind: str|None = None,
                 dupsort: bool = False,
                 sep: str = None,
                 **kwa):
        """
        Parameters:
            db (LMDBer): base db
            klas (type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
        """
        super(KomerBase, self).__init__()
        if kind is None:
            from ..core.coring import Kinds
            kind = Kinds.json
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=dupsort)
        self.klas = klas
        self.sep = sep if sep is not None else self.Sep
        self.kind = kind
        self._ser = self._serializer(kind)
        self._des = self._deserializer(kind)


    def _tokey(self, keys: str|bytes|memoryview|Iterable, topive: bool=False):
        """Converts keys Iterable to key bytes with proper separators and returns key bytes.
        If keys is already str or bytes or memoryview then returns key bytes.
        Else If keys is iterable (non-str) of strs or bytes then joins with
        separator converts to key bytes and returns. When keys is iterable and
        topive is True then enables partial key from top branch of key space given
        by partial keys by appending separator to end of partial key

        Returns:
           key (bytes): each element of keys is joined by .sep. If top then last
                        char of key is also .sep

        Parameters:
           keys (str | bytes | memoryview | Iterable[str | bytes]): db key or
                        Iterable of (str | bytes) to form key.
           topive (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of top value

        """
        if hasattr(keys, "encode"):  # str
            return keys.encode("utf-8")
        if isinstance(keys, memoryview):  # memoryview of bytes
            return bytes(keys)  # return bytes
        elif hasattr(keys, "decode"): # bytes
            return keys
        if topive and keys[-1]:  # topive and keys is not already partial
            keys = tuple(keys) + ('',)  # cat empty str so join adds trailing sep
        return (self.sep.join(key.decode() if hasattr(key, "decode") else key
                              for key in keys).encode("utf-8"))


    def _tokeys(self, key: str|bytes|memoryview):
        """Converts key bytes|memoryview to keys tuple of strs by decoding and
        then splitting at separator .sep.

        Returns:
           keys (Iterable): keyspace elements

        Parameters:
           key (bytes|memoryview): keyspace index

        """
        if isinstance(key, memoryview):  # memoryview of bytes
            key = bytes(key)
        return tuple(key.decode("utf-8").split(self.sep))


    def _serializer(self, kind):
        """
        Parameters:
            kind (str): serialization
        """
        from ..core.coring import Kinds

        if kind == Kinds.mgpk:
            return self.__serializeMGPK
        elif kind == Kinds.cbor:
            return self.__serializeCBOR
        else:
            return self.__serializeJSON


    def _deserializer(self, kind):
        """
        Parameters:
            kind (str): deserialization
        """
        from ..core.coring import Kinds

        if kind == Kinds.mgpk:
            return self.__deserializeMGPK
        elif kind == Kinds.cbor:
            return self.__deserializeCBOR
        else:
            return self.__deserializeJSON


    def __deserializeJSON(self, val):
        if val is not None:
            val = helping.datify(self.klas, json.loads(bytes(val).decode("utf-8")))
            if not isinstance(val, self.klas):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.klas))
        return val


    def __deserializeMGPK(self, val):
        if val is not None:
            val = helping.datify(self.klas, msgpack.loads(bytes(val)))
            if not isinstance(val, self.klas):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.klas))
        return val


    def __deserializeCBOR(self, val):
        if val is not None:
            val = helping.datify(self.klas, cbor2.loads(bytes(val)))
            if not isinstance(val, self.klas):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.klas))
        return val


    def __serializeJSON(self, val):
        if val is not None:
            if not isinstance(val, self.klas):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.klas))
            val = json.dumps(helping.dictify(val),
                          separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        return val


    def __serializeMGPK(self, val):
        if val is not None:
            if not isinstance(val, self.klas):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.klas))
            val = msgpack.dumps(helping.dictify(val))
        return val


    def __serializeCBOR(self, val):
        if val is not None:
            if not isinstance(val, self.klas):
                raise ValueError("Invalid schema type={} of value={}, expected {}."
                                 "".format(type(val), val, self.klas))
            val = cbor2.dumps(helping.dictify(val))
        return val


    def trim(self, keys: str|bytes|memoryview|Iterable=b"", *, topive=False):
        """Removes all entries whose keys startswith keys. Enables removal of whole
        branches of db key space. To ensure that proper separation of a branch
        include empty string as last key in keys. For example ("a","") deletes
        'a.1'and 'a.2' but not 'ab'

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key space elements to be
                    combined in order to form key
            topive (bool): True means treat as partial key tuple from top branch of
                key space given by partial keys. Resultant key ends in .sep
                character.
                False means treat as full branch in key space. Resultant key
                does not end in .sep character.
                When last item in keys is empty str then will treat as
                partial ending in sep regardless of top value

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return(self.db.remTop(db=self.sdb, top=self._tokey(keys, topive=topive)))

    remTop = trim  # convenience alias


    def getTopItemIter(self, keys: str|bytes|memoryview|Iterable=b"", *, topive=False):
        """Iterator over items in top branch of db given by keys.
        Subclasses that do special hidden transforms on either the keyspace or
        valuespace should override this method to hide hidden parts from the
        returned items.

        For example, adding either a hidden key space suffix or hidden val
        space proem to ensure insertion order.

        To return full items with hidden parts shown for debugging or testing,
        use getFullItemIter instead.

        Returns:
            items (Iterator): of (key, val) tuples  over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (str|bytes|memoryview|Iterable): tuple of bytes or strs that
                may be a truncation of a full keys tuple in  in order to get
                all the items from multiple branches of the key space.
                If keys is empty then gets
                all items in database.
            topive (bool): True means treat as partial key tuple from top branch of
                key space given by partial keys. Resultant key ends in .sep
                character.
                False means treat as full branch in key space. Resultant key
                does not end in .sep character.
                When last item in keys is empty str then will treat as
                partial ending in sep regardless of top value

        """
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                        top=self._tokey(keys, topive=topive)):
            yield (self._tokeys(key), self._des(val))


    def getFullItemIter(self, keys: str|bytes|memoryview|Iterable=b"",  *, topive=False):
        """Iterator over items in top branch of db that returns full items
        with subclass specific special hidden parts shown for debugging or testing.

        Returns:
            items (Iterator): of (key, val) tuples  over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (str|bytes|memoryview|Iterable):  may be a truncation of
                a full keys tuple in  in order to get all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.
            topive (bool): True means treat as partial key tuple from top branch of
                key space given by partial keys. Resultant key ends in .sep
                character.
                False means treat as full branch in key space. Resultant key
                does not end in .sep character.
                When last item in keys is empty str then will treat as
                partial ending in sep regardless of top value

        """
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                    top=self._tokey(keys, topive=topive)):
            yield (self._tokeys(key), self._des(val))



class Komer(KomerBase):
    """Keyspace dataclass Object Mapper factory class. Maps (serializes and
    deserializes) dataclass to/from database entry at key made from keys
    """

    def __init__(self,
                 db: LMDBer, *,
                 subkey: str = 'docs.',
                 klas: type[dataclass],  # class not instance
                 kind: str | None = None,
                 **kwa):
        """Initialize instance
        Parameters:
            db (LMDBer): base db
            klas (Type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        super(Komer, self).__init__(db=db, subkey=subkey, klas=klas,
                                    kind=kind, dupsort=False, **kwa)

    def put(self, keys: str|bytes|memoryview|Iterable, val: dataclass):
        """Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            val (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._ser(val)))


    def pin(self, keys: str|bytes|memoryview|Iterable, val: dataclass):
        """Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            val (dataclass): instance of dataclass of type self.schema as value

        Returns:
            result (bool): True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._ser(val)))

    def get(self, keys: str|bytes|memoryview|Iterable):
        """Gets val at keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
            val (dataclass):
            None if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (val := mydb.get(keys)) is None:
                raise ExceptionHere
            use val here
        """
        return (self._des(self.db.getVal(db=self.sdb,
                                  key=self._tokey(keys))))

    def getDict(self, keys: str|bytes|memoryview|Iterable):
        """Gets dictified val at keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

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


    def rem(self, keys: str|bytes|memoryview|Iterable):
        """Removes entry at keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return (self.db.remVal(db=self.sdb, key=self._tokey(keys)))


    def cnt(self):
        """Count all items in db

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db. Raises StopIteration when done

        Example:
            if key in database is "a.b" and val is serialization of dataclass
               with attributes x and y then returns
               (("a","b"), dataclass(x=1,y=2))
        """
        return self.db.cntAll(db=self.sdb)

    cntAll = cnt  # alias that matches suber interface


class IoSetKomer(KomerBase):
    """Insertion Ordered Set Keyspace Object Mapper factory class that supports
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
        db (LMDBer): instance of LMDB database manager class
        sdb (lmdb._Database): instance of named sub db lmdb for this Komer
        schema (Type[dataclass]): class reference of dataclass subclass
        kind (str): serialization/deserialization type from coring.Serials
        serializer (types.MethodType): serializer method
        deserializer (types.MethodType): deserializer method
        sep (str): separator for combining keys tuple of strs into key bytes
    """
    def __init__(self,
             db: LMDBer, *,
             subkey: str = 'recs.',
             klas: type[dataclass],  # class not instance
             kind: str | None = None,
             **kwa):
        """
        Parameters:
            db (LMDBer): base db
            clas (type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        super(IoSetKomer, self).__init__(db=db, subkey=subkey, klas=klas,
                                       kind=kind, dupsort=False, **kwa)


    def put(self, keys: str|bytes|memoryview|Iterable, vals: list):
        """Puts all vals at key made from keys. Does not overwrite. Puts all vals
        at effective key made from keys and hidden ordinal suffix.
        that are not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        vals = [self._ser(val) for val in vals]
        return (self.db.putIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=vals,
                                     sep=self.sep))


    def add(self, keys: str|bytes|memoryview|Iterable, val: dataclass):
        """Add val to vals at effective key made from keys and hidden ordinal suffix.
        that is not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            val (dataclass): instance of type self.schema

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addIoSetVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._ser(val),
                                    sep=self.sep))


    def pin(self, keys: str|bytes|memoryview|Iterable, vals: list):
        """Pins (sets) vals at effective key made from keys and hidden ordinal suffix.
        Overwrites. Removes all pre-existing vals that share same effective keys
        and replaces them with vals

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        return (self.db.pinIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._ser(val) for val in vals],
                                     sep=self.sep))


    def get(self, keys: str|bytes|memoryview|Iterable):
        """Gets dup vals list at key made from keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
            vals (list):  each item in list is instance of type self.schema
                          empty list if no entry at keys

        """
        return [self._des(val) for key, val in
                    self.db.getIoSetItemIter(db=self.sdb,
                                             key=self._tokey(keys),
                                             sep=self.sep)]


    def getLast(self, keys: str|bytes|memoryview|Iterable):
        """Gets last effective dup val at effective dup key made from keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                to form effective key

        Returns:
            val (Type[dataclass]):  instance of type self.schema
                                   None if no entry at keys

        """
        if last := self.db.getIoSetLastItem(db=self.sdb, key=self._tokey(keys)):
            key, val = last
            return self._des(val)
        return None


    def getIter(self, keys: str|bytes|memoryview|Iterable):
        """Gets vals iterator at effecive key made from keys and hidden ordinal suffix.
        All vals in set of vals that share same effecive key are retrieved in
        insertion order.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
            vals (Iterator):  str values. Raises StopIteration when done

        """
        for key, val in self.db.getIoSetItemIter(db=self.sdb,
                                            key=self._tokey(keys),
                                            sep=self.sep):
            yield self._des(val)


    def cnt(self, keys: str|bytes|memoryview|Iterable = ""):
        """Count of effective dup values at key made from keys. If keys is empty
        then returns count of all entries in db

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key. If
                empty then returns coutn of all entries in db.
        """
        if not keys:
            return self.db.cntAll(db=self.sdb)

        return (self.db.cntIoSet(db=self.sdb,
                                     key=self._tokey(keys),
                                     sep=self.sep))


    def rem(self, keys: str|bytes|memoryview|Iterable, val=None):
        """Removes entry at keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            val (dataclass):  instance of effective dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        return self.db.remIoSetVal(db=self.sdb,
                                   key=self._tokey(keys),
                                   val=self._ser(val) if val is not None else val,
                                   sep=self.sep)


    def getTopItemIter(self, keys: str|bytes|memoryview|Iterable=b"", *,
                             topive=False):
        """Get items iterator over top branch of db given by keys.

        Returns:
            items (Iterator): of (key, val) tuples over the all the items in
            subdb whose effective key startswith key made from keys.
            Keys may be keyspace prefix in order to return branches of key space.
            When keys is empty then returns all items in subdb.
            Returned key in each item has ordinal suffix removed.

        Parameters:
            keys (str|bytes|memoryview|Iterable): may be a truncation of
                a full keys tuple in  in order to address all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.
                Either append "" to end of keys Iterable to ensure get properly
                separated top branch key or use top=True.
                In Python str.startswith('') always returns True so if branch
                key is empty string it matches all keys in db with startswith.

            topive (bool): True means treat as partial key tuple from top branch of
                key space given by partial keys. Resultant key ends in .sep
                character.
                False means treat as full branch in key space. Resultant key
                does not end in .sep character.
                When last item in keys is empty str then will treat as
                partial ending in sep regardless of top value
        """
        for iokey, val in self.db.getTopIoSetItemIter(db=self.sdb,
                                            top=self._tokey(keys, topive=topive),
                                            sep=self.sep.encode()):
            yield (self._tokeys(iokey), self._des(val))

class DupKomer(KomerBase):
    """Duplicate Keyspace Object Mapper factory class that supports multiple entries
    a given database key (lmdb dupsort == True).

    Do not use if Komer dataclass instance serializes to greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB
    """
    def __init__(self,
             db: LMDBer, *,
             subkey: str = 'recs.',
             klas: type[dataclass],  # class not instance
             kind: str | None = None,
             **kwa):
        """
        Parameters:
            db (LMDBer): base db
            schema (Type[dataclass]):  reference to Class definition for dataclass sub class
            subkey (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        super(DupKomer, self).__init__(db=db, subkey=subkey, klas=klas,
                                       kind=kind, dupsort=True, **kwa)


    def put(self, keys: str|bytes|memoryview|Iterable, vals: list):
        """Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        vals = [self._ser(val) for val in vals]
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=vals))


    def add(self, keys: str|bytes|memoryview|Iterable, val: dataclass):
        """Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            val (dataclass): instance of type self.schema

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._ser(val)))


    def pin(self, keys: str|bytes|memoryview|Iterable, vals: list):
        """Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            vals (list): dataclass instances each of type self.schema as values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        vals = [self._ser(val) for val in vals]
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=vals))


    def get(self, keys: str|bytes|memoryview|Iterable):
        """Gets dup vals list at key made from keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
            vals (list):  each item in list is instance of type self.schema
                          empty list if no entry at keys

        """
        return ([self._des(val) for val in
                self.db.getValsIter(db=self.sdb, key=self._tokey(keys))])


    def getLast(self, keys: str|bytes|memoryview|Iterable):
        """Gets last dup val at key made from keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
            val (Type[dataclass]):  instance of type self.schema
                          None if no entry at keys

        """
        val = self.db.getValLast(db=self.sdb, key=self._tokey(keys))
        if val is not None:
            val = self._des(val)
        return val


    def getIter(self, keys: str|bytes|memoryview|Iterable):
        """Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key

        Returns:
            iterator:  vals each of type self.schema. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield self._des(val)


    def cnt(self, keys: str|bytes|memoryview|Iterable):
        """Count entries (dups) at key made from keys.

        Returns:
            count (int): dup values at key made from keys, zero otherwise

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
        """
        return (self.db.cntVals(db=self.sdb, key=self._tokey(keys)))


    def rem(self, keys: str|bytes|memoryview|Iterable, val=None):
        """Removes entry at key made from keys

        Parameters:
            keys (str|bytes|memoryview|Iterable): of key strs to be combined
                in order to form key
            val (dataclass):  instance of dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val is not None:
            val = self._ser(val)
        else:
            val = b''
        return (self.db.delVals(db=self.sdb, key=self._tokey(keys), val=val))
