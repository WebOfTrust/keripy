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

Class Architecture

Suber is simple lexographic database with only one value per key
OnSuber is simple lexographic database where trailing part of key is serialized
    ordinal number so that the ordering within each key prefix is monotonically
    increasing numeric

The term 'set' of values means that no value may appear more than once in the set.
Sets support idempotent adds and puts to db. This means one can add or put the same
(key, val) pair multiple times and not change the db.

DupSuber provides set of lexicographic ordered values at each key. Each value has
    a limited size (key + value <= 511 byes). The set is performant. Good for indices.

IoDupSuber provides set of insertion ordered values at each key. Each value has
    a limited size (key + value <= 511 byes). The set is less perfromant than DupSuber
    but more performant than IoSetSuber. Good for insertion ordered indices

IoSetSuber proves set of insertion ordered values at each key. Value size is not limited
    Good for any insertion ordered set where size may be too large for IoDupSuber

OnIoDupSuber provides set of insertion ordered values where the where trailing
    part of key is serialized ordinal number so that the ordering within each
    key prefix is monotonically increasing numeric.

Each of these base types for managing the key space may be mixed with other
Classes that provide different types of values these include.

Cesr
CatCesr
Serder
etc.


"""
from typing import Type, Union
from collections.abc import Iterable, Iterator

from .. import help
from ..help.helping import nonStringIterable, Reb64
from .. import core
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
        verify (bool): True means reverify when ._des from db when applicable
                       False means do not reverify. Default False
    """
    Sep = '.'  # separator for combining key iterables

    def __init__(self, db: dbing.LMDBer, *,
                       subkey: str='docs.',
                       dupsort: bool=False,
                       sep: str=None,
                       verify: bool=False,
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
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
        """
        super(SuberBase, self).__init__()  # for multi inheritance
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=dupsort)
        self.sep = sep if sep is not None else self.Sep
        self.verify = True if verify else False



    def _tokey(self, keys: str|bytes|memoryview|Iterable[str|bytes|memoryview],
                topive: bool=False):
        """
        Converts keys to key bytes with proper separators and returns key bytes.
        If keys is already str or bytes or memoryview then returns key bytes.
        Else If keys is iterable (non-str) of strs or bytes then joins with
        separator converts to key bytes and returns. When keys is iterable and
        topive is True then enables partial key from top branch of key space given
        by partial keys by appending separator to end of partial key

        Returns:
           key (bytes): each element of keys is joined by .sep. If topive then
                        last char of key is .sep

        Parameters:
           keys (str | bytes | memoryview | Iterable[str | bytes]): db key or
                        Iterable of (str | bytes) to form key.
           topive (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of topive value

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


    def _tokeys(self, key: str | bytes | memoryview):
        """
        Converts key bytes to keys tuple of strs by decoding and then splitting
        at separator .sep.

        Returns:
           keys (tuple[str]): makes tuple by splitting key at sep

        Parameters:
           key (str | bytes | memoryview): db key.

        """
        if isinstance(key, memoryview):  # memoryview of bytes
            key = bytes(key)
        if hasattr(key, "decode"):  # bytes
            key = key.decode("utf-8")  # convert to str
        return tuple(key.split(self.sep))


    def _ser(self, val: str | bytes | memoryview):
        """
        Serialize value to bytes to store in db
        Parameters:
            val (str | bytes | memoryview): encodable as bytes
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # return bytes
        return (val.encode("utf-8") if hasattr(val, "encode") else val)


    def _des(self, val: bytes | memoryview):
        """
        Deserialize val to str
        Parameters:
            val (bytes | memoryview): decodable as str
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # convert to bytes
        return (val.decode("utf-8") if hasattr(val, "decode") else val)


    def trim(self, keys: str|bytes|memoryview|Iterable=b"", *, topive=False):
        """
        Removes all entries whose keys startswith keys. Enables removal of whole
        branches of db key space. To ensure that proper separation of a branch
        include empty string as last key in keys. For example ("a","") deletes
        'a.1'and 'a.2' but not 'ab'

        Parameters:
            keys (Iteratabke[str | bytes | memoryview]): of key parts that may be
                a truncation of a full keys tuple in  in order to address all the
                items from multiple branches of the key space.
                If keys is empty then trims all items in database.
                Either append "" to end of keys Iterable to ensure get properly
                separated top branch key or use top=True.

            topive (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of top value


        Returns:
           result (bool): True if val at key exists so delete successful. False otherwise
        """
        return(self.db.delTopVal(db=self.sdb, top=self._tokey(keys, topive=topive)))


    def getFullItemIter(self, keys: str|bytes|memoryview|Iterable[str|bytes]="",
                       *, topive=False):
        """Iterator over items in .db that returns full items with subclass
        specific special hidden parts shown for debugging or testing.

        Returns:
            items (Iterator[tuple[key,val]]): (key, val) tuples of each item
            over the all the items in subdb whose key startswith key made from
            keys. Keys may be keyspace prefix to return branches of key space.
            When keys is empty then returns all items in subdb.
            This is meant to return full parts of items in both keyspace and
            valuespace which may be useful in debugging or testing.

        Parameters:
            keys (str|bytes|memoryview|Iteratable[str | bytes | memoryview]):
                of key parts that may be
                a truncation of a full keys tuple in  in order to address all the
                items from multiple branches of the key space.
                If keys is empty then gets all items in database.
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
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                               top=self._tokey(keys, topive=topive)):
            yield (self._tokeys(key), self._des(val))


    def getItemIter(self, keys: str|bytes|memoryview|Iterable="",
                       *, topive=False):
        """Iterator over items in .db subclasses that do special hidden transforms
        on either the keyspace or valuespace should override this method to hide
        hidden parts from the returned items. For example, adding either
        a hidden key space suffix or hidden val space proem to ensure insertion
        order. Use getFullItemIter instead to return full items with hidden parts
        shown for debugging or testing.

        Returns:
            items (Iterator[tuple[key,val]]): (key, val) tuples of each item
            over the all the items in subdb whose key startswith key made from
            keys. Keys may be keyspace prefix to return branches of key space.
            When keys is empty then returns all items in subdb



        Parameters:
            keys (str|bytes|memoryview|Iterable[str|bytes|memoryview]): of key
                parts that may be
                a truncation of a full keys tuple in  in order to address all the
                items from multiple branches of the key space.
                If keys is empty then gets all items in database.
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
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                               top=self._tokey(keys, topive=topive)):
            yield (self._tokeys(key), self._des(val))


class Suber(SuberBase):
    """
    Subclass of SuberBase with no LMDB duplicates (i.e. multiple values at same key).
    """

    def __init__(self, db: dbing.LMDBer, *,
                       subkey: str = 'docs.',
                       dupsort: bool=False, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key. Set to False
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False

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


class OnSuberBase(SuberBase):
    """
    Subclass of SuberBase that adds methods for keys with  exposed key part suffix
    that is 32 byte serializaton of monotonically increasing ordinal number on
    such as sn or fn.
    Each key consistes of top key joined with .sep to ordinal suffix
    Works with dupsort==True or False

    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key. Default False
            sep (str): separator to convert keys iterator to key bytes for db key
                       Default '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
        """
        super(OnSuberBase, self).__init__(*pa, **kwa)


    def putOn(self, keys: str | bytes | memoryview, on: int=0,
                    val: str | bytes | memoryview=''):
        """
        Returns
            result (bool): True if onkey made from key+sep+serialized on is
                               not found in database so value is written
                               idempotently.
                           False otherwise

        Parameters:
            keys (str | bytes | memoryview | Iterable): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
            on (int): ordinal number used with onKey(key ,on) to form key.
            val (str | bytes | memoryview): serialization
        """
        return (self.db.putOnVal(db=self.sdb,
                                 key=self._tokey(keys),
                                 on=on,
                                 val=self._ser(val),
                                 sep=self.sep.encode()))

    def pinOn(self, keys: str | bytes | memoryview, on: int=0,
                    val: str | bytes | memoryview=''):
        """
        Returns
            result (bool): True if value is written or overwritten at onkey
                           False otherwise

        Parameters:
            keys (str | bytes | memoryview | Iterable): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
            on (int): ordinal number used with onKey(key ,on) to form key.
            val (str | bytes | memoryview): serialization
        """
        return (self.db.setOnVal(db=self.sdb,
                                 key=self._tokey(keys),
                                 on=on,
                                 val=self._ser(val),
                                 sep=self.sep.encode()))


    def appendOn(self, keys: str | bytes | memoryview,
                       val: str | bytes | memoryview):
        """
        Returns:
            on (int): ordinal number of newly appended val

        Parameters:
            keys (str | bytes | memoryview | Iterable): top keys as prefix to be
                combined with serialized on suffix and sep to form key
            val (str | bytes | memoryview): serialization
        """
        return (self.db.appendOnVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=self._ser(val),
                                       sep=self.sep.encode()))


    def getOn(self, keys: str | bytes | memoryview, on: int=0):
        """
        Returns
            val (str): serialization at onkey if any
                       None if no entry at onkey

        Parameters:
            keys (str | bytes | memoryview | Iterable): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
            on (int): ordinal number used with onKey(key ,on) to form key.
        """
        val = self.db.getOnVal(db=self.sdb,
                                key=self._tokey(keys),
                                on=on,
                                sep=self.sep.encode())
        return (self._des(val) if val is not None else None)



    def remOn(self, keys: str | bytes | memoryview, on: int=0):
        """
        Returns
            result (bool): True if onkey made from key+sep+serialized on is
                               found in database so value is removed
                               Removes all duplicates if any at onkey.
                           False otherwise

        Parameters:
            keys (str | bytes | memoryview | Iterable): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
            on (int): ordinal number used with onKey(key ,on) to form key.
        """
        return (self.db.delOnVal(db=self.sdb,
                                     key=self._tokey(keys),
                                     on=on,
                                     sep=self.sep.encode()))


    def cntOn(self, keys: str | bytes | memoryview = "", on: int=0):
        """
        Returns
            cnt (int): count of of all ordinal suffix keyed vals with same
                key prefix but different on in onkey in db starting at ordinal
                number on where key is formed with onKey(key,on). Count at
                each onkey includes duplicates if any.


        Parameters:
            keys (str | bytes | memoryview | Iterable): top keys as prefix to be
                combined with serialized on suffix and sep to form top key
                When keys is empty then counts whole database including
                duplicates if any.
            on (int): ordinal number used with onKey(key,on) to form key.
        """
        return (self.db.cntOnVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     on=on,
                                     sep=self.sep.encode()))


    def getOnIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns:
            items (Iterator[bytes]): of val with same key but increments of
                                on >= on i.e. all key.on beginning with on

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form actual key
                When keys is empty then retrieves whole database including
                duplicates if any
            on (int): ordinal number used with onKey(pre,on) to form key at at
                      which to initiate retrieval
            sep (bytes): separator character for split
        """
        for val in (self.db.getOnValIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._des(val))


    def getOnItemIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns:
            items (Iterator[(key, on, val)]): triples of key, on, val with same
                key but increments of on >= on i.e. all key.on beginning with on

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form actual key
                When keys is empty then retrieves whole database including
                duplicates if any
            on (int): ordinal number used with onKey(pre,on) to form key at at
                      which to initiate retrieval
            sep (bytes): separator character for split
        """
        for keys, on, val in (self.db.getOnItemIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._tokeys(keys), on, self._des(val))



class OnSuber(OnSuberBase, Suber):
    """
    Subclass of OnSuberBase andSuber that adds methods for keys with ordinal
    numbered suffixes.
    Each key consistes of pre joined with .sep to ordinal suffix

    Assumes dupsort==False

    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key. Set to False
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
        """
        super(OnSuber, self).__init__(*pa, **kwa)


class B64SuberBase(SuberBase):
    """
    Base Class whose values are Iterables of Base64 str or bytes that are stored
    in db as .sep joined Base64 bytes. Separator character must not be valid
    Base64 character so the split will work unambiguously.

    Automatically joins and splits along separator to Iterable (tuple) of Base64

     Attributes:
        db (dbing.LMDBer): base LMDB db
        sdb (lmdb._Database): instance of lmdb named sub db for this Suber
        sep (str): separator for combining keys tuple of strs into key bytes
    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
                       Must not be Base64 character.
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False

        """
        super(B64SuberBase, self).__init__(*pa, **kwa)
        if Reb64.match(self.sep.encode()):
            raise ValueError("Invalid sep={self.sep}, must not be Base64 char.")


    def _toval(self, vals: str|bytes|memoryview|Iterable[str|bytes|memoryview]):
        """
        Converts vals to val bytes with proper separators and returns val bytes.
        If vals is already str or bytes or memoryview then returns val bytes.
        Else If vals is iterable (non-str) of strs or bytes or memoryview then
        joins with .sep and converts to val bytes and returns.

        Returns:
           val (bytes): each element of vals is joined by .sep.

        Parameters:
           vals (str | bytes | memoryview | Iterable[str | bytes]): db val or
                        Iterable of (str | bytes | memoryview) to form val.
                        Note, join of bytes sep works with memoryview.

        """
        if hasattr(vals, "encode"):  # str
            val = vals.encode("utf-8")
            if not (Reb64.match(val)):
                raise ValueError(f"Non Base64 {val=}.")
            return val
        if isinstance(vals, memoryview):  # memoryview of bytes
            val = bytes(vals)  # return bytes
            if not (Reb64.match(val)):
                raise ValueError(f"Non Base64 {val=}.")
            return val
        elif hasattr(vals, "decode"): # bytes
            val = vals
            if not (Reb64.match(val)):
                raise ValueError(f"Non Base64 {val=}.")
            return val
        vals = tuple(v.encode() if hasattr(v, "encode") else v for v in vals)  # make bytes
        for val in vals:
            if not (Reb64.match(val)):
                raise ValueError(f"Non Base64 {val=}.")
        return (self.sep.encode().join(vals))

        #return (self.sep.join(val.decode() if hasattr(val, "decode") else val
                              #for val in vals).encode("utf-8"))


    def _tovals(self, val: bytes | memoryview):
        """
        Converts val bytes to vals tuple of strs by decoding and then splitting
        at separator .sep.

        Returns:
           vals (tuple[str]): makes tuple by splitting val at .sep

        Parameters:
           val (bytes | memoryview): db Base64 val.

        """
        if isinstance(val, memoryview):  # memoryview of bytes
            val = bytes(val)
        if hasattr(val, "decode"):  # bytes
            val = val.decode("utf-8")  # convert to str
        return tuple(val.split(self.sep))


    def _ser(self, val: Union[Iterable, str, bytes]):
        """
        Serialize val to bytes to store in db
        When val is Iterable then joins each elements with .sep returns val bytes

        Returns:
           val (bytes): .sep join of each Base64 bytes in val

        Parameters:
           val (Union[Iterable, bytes]): of Base64 bytes

        """
        if not nonStringIterable(val):  # not iterable
            val = (val, )  # make iterable
        return (self._toval(val))


    def _des(self, val: memoryview | bytes):
        """
        Converts val bytes to vals tuple of subclass instances by deserializing
        .qb64b  concatenation in order of each instance in .klas

        Returns:
           vals (tuple): subclass instances

        Parameters:
           val (Union[bytes, memoryview]):  of concatenation of .qb64b

        """
        return self._tovals(val)


class B64Suber(B64SuberBase, Suber):
    """
    Subclass of B64SuberBase and Suber that serializes and deserializes values
    as .sep joined strings of Base64 components.

    .sep must not be Base64 character.

    Each key consistes of pre joined with .sep to ordinal suffix

    Assumes dupsort==False

    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key. Set to False
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
                       Must not be Base64 character.
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
        """
        super(B64Suber, self).__init__(*pa, **kwa)



class CesrSuberBase(SuberBase):
    """
    Sub class of SuberBase where data is CESR encode/decode ducktyped subclass
    instance such as Matter, Indexer, Counter with .qb64b property when provided
    as fully qualified serialization
    Automatically serializes and deserializes from qb64b to/from CESR instance

    """

    def __init__(self, *pa, klas: Type[coring.Matter] = coring.Matter, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
        Parameters:
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


    def _des(self, val: memoryview | bytes):
        """
        Deserialize val to str
        Parameters:
            val (memoryview | bytes): convertable to coring.matter
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # convert to bytes
        return self.klas(qb64b=val)  # qb64b parameter accepts str


class CesrSuber(CesrSuberBase, Suber):
    """
    Sub class of Suber where data is CESR encode/decode ducktyped subclass
    instance such as Matter, Indexer, Counter with .qb64b property when provided
    as fully qualified serialization.
    Extends Suber to support val that are ducktyped CESR serializable .qb64 .qb64b
    subclasses such as coring.Matter, coring.Indexer, coring.Counter.
    Automatically serializes and deserializes from qb64b to/from CESR instances

    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter
        """
        super(CesrSuber, self).__init__(*pa, **kwa)


class CesrOnSuber(CesrSuberBase, OnSuberBase, Suber):
    """
    Subclass of CesrSuberBase, OnSuberBase, and Suber that adds methods for
    keys with ordinal numbered suffixes and values that are Cesr serializations
    of Matter subclass ducktypes.

    Each key consistes of pre joined with .sep to ordinal suffix

    Assumes dupsort==False
    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key. Set to False
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
        """
        super(CesrOnSuber, self).__init__(*pa, **kwa)


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
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter

        """
        if klas is None:
            klas = (coring.Matter, )  # set default to tuple of single Matter
        if not nonStringIterable(klas):  # not iterable
            klas = (klas, )  # make it so
        super(CatCesrSuberBase, self).__init__(*pa, klas=klas, **kwa)


    def _ser(self, val: Union[Iterable, coring.Matter]):
        """
        Serialize val to bytes to store in db
        Concatenates .qb64b of each instance in val and returns val bytes

        Returns:
           cat (bytes): concatenation of .qb64b of each object instance in vals

        Parameters:
           val (Union[Iterable, coring.Matter]): of subclass instances.

        """
        if not nonStringIterable(val):  # not iterable
            val = (val, )  # make iterable
        return (b''.join(obj.qb64b for obj in val))


    def _des(self, val: memoryview | bytes | bytearray):
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
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter

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
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter
        """
        super(IoSetSuber, self).__init__(db=db, subkey=subkey, dupsort=False, **kwa)


    def put(self, keys: str | bytes | memoryview | Iterable,
                  vals: str | bytes | memoryview | Iterable):
        """
        Puts all vals at effective key made from keys and hidden ordinal suffix.
        that are not already in set of vals at key. Does not overwrite.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key parts to be
                    combined in order to form key
            vals (str | bytes | memoryview | Iterable): of str serializations

        Returns:
            result (bool): True If successful, False otherwise.

        """
        if not nonStringIterable(vals):  # not iterable
            vals = (vals, )  # make iterable
        return (self.db.putIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._ser(val) for val in vals],
                                     sep=self.sep))


    def add(self, keys: str | bytes | memoryview | Iterable,
            val: str | bytes | memoryview):
        """
        Add val idempotently to vals at effective key made from keys and hidden
        ordinal suffix. Idempotent means that added value is not already in set
        of vals at key. Does not overwrite or add same value at same key more
        than once.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key parts to be
                    combined in order to form key
            val (str | bytes | memoryview): serialization

        Returns:
            result (bool): True means unique value added among duplications,
                            False means duplicate of same value already exists.

        """
        return (self.db.addIoSetVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._ser(val),
                                    sep=self.sep))


    def pin(self, keys: str | bytes | memoryview | Iterable,
                  vals: str | bytes | memoryview | Iterable):
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
        if not nonStringIterable(vals):  # not iterable
            vals = (vals, )  # make iterable
        return (self.db.setIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._ser(val) for val in vals],
                                     sep=self.sep))


    def get(self, keys: str | bytes | memoryview | Iterable):
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


    def getIter(self, keys: str | bytes | memoryview | Iterable):
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


    def getLast(self, keys: str | bytes | memoryview | Iterable):
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



    def rem(self, keys: str | bytes | memoryview | Iterable,
                   val: str | bytes | memoryview = b''):
        """
        Removes entry at effective key made from keys and hidden ordinal suffix
        that matches val if any. Otherwise deletes all values at effective key.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (str):  value at key to delete. Subclass ._ser method may
                        accept different value types
                        if val is empty then remove all values at key

        Returns:
           result (bool): True if effective key with val exists so rem successful.
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


    def cnt(self, keys: str | bytes | memoryview | Iterable):
        """
        Return count of  values at effective key made from keys and hidden ordinal
        suffix. Zero otherwise

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
        """
        return (self.db.cntIoSetVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     sep=self.sep))


    def getItemIter(self, keys: str | bytes | memoryview | Iterable = "",
                    *, topive=False):
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
            keys (Iterable): tuple of bytes or strs that may be a truncation of
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
        for key, val in self.db.getTopIoSetItemIter(db=self.sdb,
                top=self._tokey(keys, topive=topive), sep=self.sep.encode()):
            yield (self._tokeys(key), self._des(val))


class CesrIoSetSuber(CesrSuberBase, IoSetSuber):
    """
    Subclass of CesrSuber and IoSetSuber.
    Sub class of Suber where data is CESR encode/decode ducktyped subclass
    instance such as Matter, Indexer, Counter with .qb64b property when provided
    as fully qualified serialization
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
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter

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
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[coring.Matter]): Class reference to subclass of Matter or
                Indexer or Counter or any ducktyped class of Matter

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

    def __init__(self, *pa, klas: Type[core.Signer] = core.Signer, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter
        """
        if not (issubclass(klas, core.Signer)):
            raise ValueError("Invalid klas type={}, expected {}."
                             "".format(klas, core.Signer))
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


    def getItemIter(self, keys: str | bytes | memoryview | Iterable = "",
                    *, topive=False):
        """
        Returns:
            iterator (Iteratore: tuple (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        Parameters:
            keys (Iterable): tuple of bytes or strs that may be a truncation of
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
            encrypter: core.Encrypter = None):
        """
        Puts qb64 of Matter instance val at key made from keys. Does not overwrite
        If encrypter provided then encrypts first

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Signer): instance of self.klas
            encrypter (core.Encrypter): optional

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        if encrypter:
            val = encrypter.encrypt(prim=val)  # returns Cipher instance
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))


    def pin(self, keys: Union[str, Iterable], val: coring.Matter,
            encrypter: core.Encrypter = None):
        """
        Pins (sets) qb64 of Matter instance val at key made from keys. Overwrites.
        If encrypter provided then encrypts first

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Signer): instance of self.klas
            encrypter (core.Encrypter): optional

        Returns:
            result (bool): True If successful. False otherwise.
        """
        if encrypter:
            val = encrypter.encrypt(prim=val)  # returns Cipher instance
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.qb64b))



    def get(self, keys: Union[str, Iterable], decrypter: core.Decrypter = None):
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
            decrypter (core.Decrypter): optional. If provided assumes value in
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
            return (decrypter.decrypt(qb64=bytes(val),
                                      transferable=verfer.transferable))
        return (self.klas(qb64b=bytes(val), transferable=verfer.transferable))



    def getItemIter(self, keys: str|bytes|memoryview|Iterable= "",
                       decrypter: core.Decrypter = None, *, topive=False):
        """
        Returns:
            items (Iterator): of tuples (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        decrypter (core.Decrypter): optional. If provided assumes value in
                db was encrypted and so decrypts before converting to Signer.

        Parameters:
            keys (Iterable): tuple of bytes or strs that may be a truncation of
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
            ikeys = self._tokeys(key)  # verkey is last split if any
            verfer = coring.Verfer(qb64b=ikeys[-1])   # last split
            if decrypter:
                yield (ikeys, decrypter.decrypt(qb64=bytes(val),
                                            transferable=verfer.transferable))
            else:
                yield (ikeys, self.klas(qb64b=bytes(val),
                                            transferable=verfer.transferable))

class SerderSuberBase(SuberBase):
    """
    Sub class of SuberBase where data is serialized Serder Subclass instance
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
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False

        Overridden Parameters:
            klas (Type[serdering.Serder]): Class reference to subclass of Serder
        """
        super(SerderSuberBase, self).__init__(*pa, **kwa)
        self.klas = klas


    def _ser(self, val: serdering.Serder):
        """
        Serialize value to bytes to store in db
        Parameters:
            val (serdering.Serder): instance Serder subclass like SerderKERI
        """
        return val.raw


    def _des(self, val: (str | memoryview | bytes)):
        """
        Deserialize val to str
        Parameters:
            val (Union[str, memoryview, bytes]): convertable to coring.matter
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # convert to bytes
        elif hasattr(val, "encode"):  # str
            val = val.encode()  # convert to bytes
        return self.klas(raw=val, verify=self.verify)


class SerderSuber(SerderSuberBase, Suber):
    """
    Sub class of SerderSuberBase, Suber where data is serialized Serder Subclass
    instance given by .klas
    Automatically serializes and deserializes using .klas Serder methods
    """

    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[serdering.Serder]): Class reference to subclass of Serder
        """
        super(SerderSuber, self).__init__(*pa, **kwa)


class SerderIoSetSuber(SerderSuberBase, IoSetSuber):
    """
    Sub class of SerderSuberBase and IoSetSuber that allows multiple Serder
    instances to be stored at the same db key in insertion order.
    Example use case would be an escrow where the key is a sequence number
    based index (such as snKey).

    Sub class of SerderSuberBase where data is serialized Serder Subclass instance
    given by .klas
    Automatically serializes and deserializes using .klas Serder methods

    Extends IoSetSuber so that all IoSetSuber methods now work with Serder
    subclass for each val.

    IoSetSuber stores at each effective key a set of distinct values that
    share that same effective key where each member of the set is retrieved in
    insertion order (dupsort==False)
    The methods allows an Iterable (set valued) of Iterables of separation subclass
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
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[serdering.Serder]): Class reference to subclass of Serder

        """
        super(SerderIoSetSuber, self).__init__(*pa, **kwa)




class SchemerSuber(SerderSuberBase, Suber):
    """
    Sub class of SerderSuberBase and Suber where data is serialized Schemer instance
    Schemer ser/des is ducktype of Serder using .raw
    Automatically serializes and deserializes using Schemer methods
    """

    def __init__(self, *pa,
                 klas: Type[ scheming.Schemer] = scheming.Schemer,
                 **kwa):
        """
        Inherited Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            dupsort (bool): True means enable duplicates at each key
                               False (default) means do not enable duplicates at
                               each key
            sep (str): separator to convert keys iterator to key bytes for db key
                       default is self.Sep == '.'
            verify (bool): True means reverify when ._des from db when applicable
                           False means do not reverify. Default False
            klas (Type[scheming.Schemer]): Class reference to ducktyped subclass
                of Serder

        Overridden Parameters:
            klas (Type[scheming.Schemer]): Class reference to ducktyped subclass
                of Serder  intercepts passed in klas and forces it to Schemer
        """
        if not issubclass(klas, scheming.Schemer):
            raise TypeError(f"Invalid {klas=}, not subclass of {scheming.Schemer}.")
        super(SchemerSuber, self).__init__(*pa, klas=klas, **kwa)


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


    def put(self, keys: str | bytes | memoryview | Iterable,
                  vals: str | bytes | memoryview | Iterable):
        """
        Puts all vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be
                combined in order to form key
            vals (str | bytes | memoryview | Iterable): str or bytes of each
                value to be written at key

        Returns:
            result (bool): True If successful, False otherwise.

        Apparently always returns True (how .put works with dupsort=True)

        """
        if not nonStringIterable(vals):  # not iterable
            vals = (vals, )  # make iterable
        return (self.db.putVals(db=self.sdb,
                                key=self._tokey(keys),
                                vals=[self._ser(val) for val in vals]))


    def add(self, keys: str | bytes | memoryview | Iterable,
                  val: str | bytes | memoryview ):
        """
        Add val to vals at key made from keys. Does not overwrite. Adds to existing
        dup values at key if any. Duplicate means another entry at the same key
        but the entry is still a unique value. Duplicates are inserted in
        lexocographic order not insertion order. Lmdb does not insert a duplicate
        unless it is a unique value for that key.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be combined in order to form key
            val (str | bytes | memoryview): value

        Returns:
            result (bool): True means unique value among duplications,
                              False means duplicte of same value already exists.

        """
        return (self.db.addVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=self._ser(val)))


    def pin(self, keys: str | bytes | memoryview | Iterable,
                  vals: str | bytes | memoryview | Iterable):
        """
        Pins (sets) vals at key made from keys. Overwrites. Removes all
        pre-existing dup vals and replaces them with vals

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be
                combined in order to form key
            vals (str | bytes | memoryview | Iterable): str or bytes values

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delVals(db=self.sdb, key=key)  # delete all values
        if not nonStringIterable(vals):  # not iterable
            vals = (vals, )  # make iterable
        return (self.db.putVals(db=self.sdb,
                                key=key,
                                vals=[self._ser(val) for val in vals]))



    def get(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be
                combined in order to form key

        Returns:
            vals (list):  each item in list is str
                          empty list if no entry at keys

        """
        return [self._des(val) for val in
                        self.db.getValsIter(db=self.sdb, key=self._tokey(keys))]


    def getLast(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets last dup val at key made from keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            val (str):  value else None if no value at key

        """
        val = self.db.getValLast(db=self.sdb, key=self._tokey(keys))
        return self._des(val) if val is not None else val


    def getIter(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets dup vals iterator at key made from keys

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be
                combined in order to form key

        Returns:
            iterator:  vals each of str. Raises StopIteration when done

        """
        for val in self.db.getValsIter(db=self.sdb, key=self._tokey(keys)):
            yield self._des(val)


    def cnt(self, keys: str | bytes | memoryview | Iterable):
        """
        Return count of dup values at key made from keys, zero otherwise

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be
                combined in order to form key
        """
        return (self.db.cntVals(db=self.sdb, key=self._tokey(keys)))


    def rem(self, keys: str | bytes | memoryview | Iterable,
            val: str | bytes | memoryview = b''):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Union[str, bytes]):  instance of dup val at key to delete
                              if val is None then remove all values at key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        if val:
            return (self.db.delVals(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._ser(val)))
        else:
            return (self.db.delVals(db=self.sdb,
                                    key=self._tokey(keys)))



class CesrDupSuber(CesrSuberBase, DupSuber):
    """
    Sub class of DupSuber whose values are CESR ducktypes of Matter subclasses.
    serialized to and deserialied from val instance .qb64b property
    which is a fully qualified serialization.
    Automatically serializes and deserializes from qb64b to/from Matter ducktyped
    instances
    DupSuber supports multiple entries at each key (duplicates) with dupsort==True

    Do not use if  serialized value is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB
    """
    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:

        """
        super(CesrDupSuber, self).__init__(*pa, **kwa)


class IoDupSuber(DupSuber):
    """
    Sub class of DupSuber that supports Insertion Ordering (IoDup) of duplicates
    By automagically prepending and stripping  ordinal proem to/from each
    duplicate value at a given key.

    IoDupSuber supports  insertion ordered multiple entries at each key
    (duplicates) with dupsort==True

    Do not use if  serialized length key + proem + value, is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB

    IoDupSuber may be more performant then IoSetSuber for values that are indices
    to other sub dbs that fit the size constraint because LMDB support for
    duplicates is more space efficient and code performant.

    Duplicates at a given key preserve insertion order of duplicate.
    Because lmdb is lexocographic an insertion ordering proem is prepended to
    all values that makes lexocographic order that same as insertion order.

    Duplicates are ordered as a pair of key plus value so prepending proem
    to each value changes duplicate ordering. Proem is 33 characters long.
    With 32 character hex string followed by '.' for essentiall unlimited
    number of values which will be limited by memory.

    With prepended proem ordinal must explicity check for duplicate values
    before insertion. Uses a python set for the duplicate inclusion test.
    Set inclusion scales with O(1) whereas list inclusion scales with O(n).
    """
    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:

        """
        super(IoDupSuber, self).__init__(*pa, **kwa)


    def put(self, keys: str | bytes | memoryview | Iterable,
                  vals: str | bytes | memoryview | Iterable):
        """
        Puts all vals idempotently at key made from keys in insertion order using
        hidden ordinal proem. Idempotently means do not put any val in vals that is
        already in dup vals at key. Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            vals (Iterable): of str serializations

        Returns:
            result (bool): True If successful, False otherwise.

        """
        if not nonStringIterable(vals):  # not iterable
            vals = (vals, )  # make iterable
        return (self.db.putIoDupVals(db=self.sdb,
                                     key=self._tokey(keys),
                                     vals=[self._ser(val) for val in vals]))


    def add(self, keys: str | bytes | memoryview | Iterable,
                  val: str | bytes | memoryview):
        """
        Add val idempotently  at key made from keys in insertion order using hidden
        ordinal proem. Idempotently means do not add val that is already in
        dup vals at key. Does not overwrite.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            val (str | bytes | memoryview): serialization

        Returns:
            result (bool): True means unique value added among duplications,
                            False means duplicate of same value already exists.

        """
        return (self.db.addIoDupVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    val=self._ser(val)))


    def pin(self, keys: str | bytes | memoryview | Iterable,
            vals: str | bytes | memoryview | Iterable):
        """
        Pins (sets) vals at key made from keys in insertion order using hidden
        ordinal proem. Overwrites. Removes all pre-existing vals that share
        same keys and replaces them with vals

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            vals (Iterable): str serializations

        Returns:
            result (bool): True If successful, False otherwise.

        """
        key = self._tokey(keys)
        self.db.delIoDupVals(db=self.sdb, key=key)  # delete all values
        if not nonStringIterable(vals):  # not iterable
            vals = (vals, )  # make iterable
        return self.db.putIoDupVals(db=self.sdb,
                                     key=key,
                                     vals=[self._ser(val) for val in vals])


    def get(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets vals dup list in insertion order using key made from keys and
        hidden ordinal proem on dups.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            vals (Iterable):  each item in list is str
                          empty list if no entry at keys

        """
        return ([self._des(val) for val in
                    self.db.getIoDupVals(db=self.sdb, key=self._tokey(keys))])


    def getIter(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets vals dup iterator in insertion order using key made from keys and
        hidden ordinal proem on dups.
        All vals in dups that share same key are retrieved in insertion order.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key parts

        Returns:
            vals (Iterator):  str values. Raises StopIteration when done

        """
        for val in self.db.getIoDupValsIter(db=self.sdb,
                                            key=self._tokey(keys)):
            yield self._des(val)


    def getLast(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets last val inserted at key made from keys in insertion order using
        hidden ordinal proem.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            val (str):  value str, None if no entry at keys

        """
        val = self.db.getIoDupValLast(db=self.sdb, key=self._tokey(keys))
        return (self._des(val) if val is not None else val)


    def rem(self, keys: str | bytes | memoryview | Iterable,
                   val: str | bytes | memoryview = ''):
        """
        Removes entry at key made from keys and dup val that matches val if any,
        notwithstanding hidden ordinal proem. Otherwise deletes all dup values
        at key if any.

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key parts to be
                combined in order to form key
            val (str):  value at key to delete. Subclass ._ser method may
                        accept different value types
                        if val is empty then remove all values at key

        Returns:
           result (bool): True if key with dup val exists so rem successful.
                           False otherwise

        """
        if val:
            return self.db.delIoDupVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=self._ser(val))
        else:
            return self.db.delIoDupVals(db=self.sdb, key=self._tokey(keys))


    def cnt(self, keys: str | bytes | memoryview | Iterable):
        """
        Return count of dup values at key made from keys with hidden ordinal
        proem. Zero otherwise

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key parts to be
                combined in order to form key
        """
        return (self.db.cntIoDupVals(db=self.sdb, key=self._tokey(keys)))


    def getItemIter(self, keys: str | bytes | memoryview | Iterable = "",
                    *, topive=False):
        """
        Return iterator over all the items including dup items for all keys
        in top branch defined by keys where keys may be truncation of full branch.

        Returns:
            items (Iterator): of (key, val) tuples over the all the items in
            subdb whose key startswith key made from keys and val has its hidden
            dup ordinal proem removed.
            Keys may be keyspace prefix in order to return branches of key space.
            When keys is empty then returns all items in subdb.

        Parameters:
            keys (str | bytes | memoryview | Iterable): key or key parts that
                may be a truncation of a full keys tuple in  in order to address
                all the items from multiple branches of the key space.
                If keys is empty then gets all items in database.
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

        for key, val in self.db.getTopIoDupItemIter(db=self.sdb,
                                         top=self._tokey(keys, topive=topive)):
            yield (self._tokeys(key), self._des(val))


class OnIoDupSuber(OnSuberBase, IoDupSuber):
    """
    Sub class of IoDupSuber and OnSuberBase that supports Insertion Ordering
    (IoDup) of duplicates but where the trailing part of the key space is
    a serialized monotonically increasing ordinal number. This is useful for
    escrows of key events etc where duplicates of likely events are maintained
    in insertion order.
    Insertion order is maintained by automagically prepending and stripping an
    ordinal ordering proem to/from each duplicate value at a given key.

    OnIoDupSuber adds the convenience methods from OnSuberBase to IoDupSuber for
    those cases where the keyspace has a trailing ordinal part.

    There are two ordinals, one in the key space and a hidden one in the duplicate
    data value space.

    OnIoDupSuber supports  insertion ordered multiple entries at each key
    (duplicates) with dupsort==True

    Do not use if  serialized length key + proem + value, is greater than 511 bytes.
    This is a limitation of dupsort==True sub dbs in LMDB

    OnIoDupSuber may be more performant then IoSetSuber for values that are indices
    to other sub dbs that fit the size constraint because LMDB support for
    duplicates is more space efficient and code performant.

    Duplicates at a given key preserve insertion order of duplicate.
    Because lmdb is lexocographic an insertion ordering proem is prepended to
    all values that makes lexocographic order that same as insertion order.

    Duplicates are ordered as a pair of key plus value so prepending proem
    to each value changes duplicate ordering. Proem is 33 characters long.
    With 32 character hex string followed by '.' for essentiall unlimited
    number of values which will be limited by memory.

    With prepended proem ordinal must explicity check for duplicate values
    before insertion. Uses a python set for the duplicate inclusion test.
    Set inclusion scales with O(1) whereas list inclusion scales with O(n).
    """
    def __init__(self, *pa, **kwa):
        """
        Inherited Parameters:

        """
        super(OnIoDupSuber, self).__init__(*pa, **kwa)


    def addOn(self, keys: str | bytes | memoryview | Iterable, on: int=0,
                  val: str | bytes | memoryview = ''):
        """
        Add val idempotently  at key made from keys in insertion order using hidden
        ordinal proem. Idempotently means do not add val that is already in
        dup vals at key. Does not overwrite.

        Parameters:
            keys (str | bytes | memoryview | Iterable): top keys as prefix to be
                combined with serialized on suffix and sep to form onkey
            on (int): ordinal number used with onKey(pre,on) to form onkey.
            val (str | bytes | memoryview): serialization

        Returns:
            result (bool): True means unique value added among duplications,
                            False means duplicate of same value already exists.

        """
        return (self.db.addOnIoDupVal(db=self.sdb,
                                    key=self._tokey(keys),
                                    on=on,
                                    val=self._ser(val),
                                    sep=self.sep.encode()))



    def appendOn(self, keys: str | bytes | memoryview,
                       val: str | bytes | memoryview):
        """
        Returns:
            on (int): ordinal number of newly appended val

        Parameters:
            keys (str | bytes | memoryview | Iterable): top keys as prefix to be
                combined with serialized on suffix and sep to form key
            val (str | bytes | memoryview): serialization
        """
        return (self.db.appendOnIoDupVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       val=self._ser(val),
                                       sep=self.sep.encode()))


    def getOn(self, keys: str | bytes | memoryview | Iterable, on: int = 0):
        """
        Gets dup vals list at key made from keys

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key strs to be
                combined in order to form key
            on (int): ordinal number used with onKey(pre,on) to form key.

        Returns:
            vals (list):  each item in list is str
                          empty list if no entry at keys

        """
        return [self._des(val) for val in
                        self.db.getOnIoDupValIter(db=self.sdb,
                                                  key=self._tokey(keys),
                                                  on=on,
                                                  sep=self.sep.encode())]


    def remOn(self, keys: str | bytes | memoryview | Iterable, on: int=0,
                   val: str | bytes | memoryview = ''):
        """
        Removes entry at key made from keys and dup val that matches val if any,
        notwithstanding hidden ordinal proem. Otherwise deletes all dup values
        at key if any.

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form onkey

            on (int): ordinal number used with onKey(pre,on) to form key.
            val (str):  value at key to delete. Subclass ._ser method may
                        accept different value types
                        if val is empty then remove all values at key

        Returns:
           result (bool): True if onkey with dup val exists so rem successful.
                           False otherwise

        """
        if val:
            return self.db.delOnIoDupVal(db=self.sdb,
                                       key=self._tokey(keys),
                                       on=on,
                                       val=self._ser(val),
                                       sep=self.sep.encode())
        else:
            return self.db.delOnIoDupVals(db=self.sdb,
                                          key=self._tokey(keys),
                                          on=on,
                                          sep=self.sep.encode())



    def getOnIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns
            val (Iterator[bytes]):  deserialized val of of each
                onkey

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
                When keys is empty then retrieves whole database including duplicates
            on (int): ordinal number used with onKey(pre,on) to form key.
            sep (bytes): separator character for split
        """
        for val in (self.db.getOnIoDupValIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._des(val))


    def getOnItemIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns:
            items (Iterator[(top keys, on, val)]): triples of (onkeys, on int,
                  deserialized val)

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
                When keys is empty then retrieves whole database including duplicates
            on (int): ordinal number used with onKey(pre,on) to form key.
            sep (bytes): separator character for split
        """
        for keys, on, val in (self.db.getOnIoDupItemIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._tokeys(keys), on, self._des(val))


    def getOnLastIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns
            last (Iterator[bytes]):  deserialized last duplicate val of of each
                onkey

        Parameters:
            keys (str | bytes | memoryview | iterator): top keys as prefix to be
                combined with serialized on suffix and sep to form key
                When keys is empty then retrieves whole database including duplicates
            on (int): ordinal number used with onKey(pre,on) to form key.
            sep (bytes): separator character for split
        """
        for val in (self.db.getOnIoDupLastValIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._des(val))



    def getOnLastItemIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns
            items (Iterator[(top keys, on, val)]): triples of (keys, on int,
                  deserialized val) last duplicate item as each onkey where onkey
                  is the key+serialized on

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form key
                When keys is empty then retrieves whole database including duplicates
            on (int): ordinal number used with onKey(pre,on) to form key.
            sep (bytes): separator character for split
        """
        for keys, on, val in (self.db.getOnIoDupLastItemIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._tokeys(keys), on, self._des(val))


    def getOnBackIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns
            val (Iterator[bytes]):  deserialized val of of each
                onkey in reverse order

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
                When keys is empty then retrieves whole database including duplicates
            on (int): ordinal number used with onKey(pre,on) to form key.
            sep (bytes): separator character for split
        """
        for val in (self.db.getOnIoDupValBackIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._des(val))


    def getOnItemBackIter(self, keys: str|bytes|memoryview|Iterable = "", on: int=0):
        """
        Returns:
            items (Iterator[(top keys, on, val)]): triples of (onkeys, on int,
                  deserialized val) in reverse order

        Parameters:
            keys (str | bytes | memoryview | iterator): keys as prefix to be
                combined with serialized on suffix and sep to form onkey
                When keys is empty then retrieves whole database including duplicates
            on (int): ordinal number used with onKey(pre,on) to form key.
            sep (bytes): separator character for split
        """
        for keys, on, val in (self.db.getOnIoDupItemBackIter(db=self.sdb,
                        key=self._tokey(keys), on=on, sep=self.sep.encode())):
            yield (self._tokeys(keys), on, self._des(val))
