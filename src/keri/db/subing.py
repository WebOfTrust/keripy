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



    def _tokey(self, keys: str | bytes | memoryview | Iterable[str | bytes],
                top: bool=False):
        """
        Converts keys to key bytes with proper separators and returns key bytes.
        If keys is already str or bytes then returns key bytes.
        Else If keys is iterable (non-str) of strs or bytes then joins with
        separator converts to key bytes and returns. When keys is iterable and
        top is True then enables partial key from top branch of key space given
        by partial keys by appending separator to end of partial key

        Returns:
           key (bytes): each element of keys is joined by .sep. If top then last
                        char of key is also .sep

        Parameters:
           keys (str | bytes | memoryview | Iterable[str | bytes]): db key or
                        Iterable of (str | bytes) to form key.
           top (bool): True means treat as partial key tuple from top branch of
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
        if top and keys[-1]:  # top and keys is not already partial
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


    def _des(self, val: str | bytes | memoryview):
        """
        Deserialize val to str
        Parameters:
            val (str | bytes | memoryview): decodable as str
        """
        if isinstance(val, memoryview):  # memoryview is always bytes
            val = bytes(val)  # convert to bytes
        return (val.decode("utf-8") if hasattr(val, "decode") else val)


    def getItemIter(self, keys: str|bytes|memoryview|Iterable[str|bytes]=b"",
                       *, top=False):
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
            keys (Iterator[str | bytes | memoryview]): of key parts that may be
                a truncation of a full keys tuple in  in order to address all the
                items from multiple branches of the key space.
                If keys is empty then gets all items in database.
                Either append "" to end of keys Iterable to ensure get properly
                separated top branch key or use top=True.


            top (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of top value

        """
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                               key=self._tokey(keys, top=top)):
            yield (self._tokeys(key), self._des(val))


    def getFullItemIter(self, keys: str|bytes|memoryview|Iterable[str|bytes]=b"",
                       *, top=False):
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
            keys (Iterator[str | bytes | memoryview]): of key parts that may be
                a truncation of a full keys tuple in  in order to address all the
                items from multiple branches of the key space.
                If keys is empty then gets all items in database.
                Either append "" to end of keys Iterable to ensure get properly
                separated top branch key or use top=True.


            top (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of top value

        """
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                               key=self._tokey(keys, top=top)):
            yield (self._tokeys(key), self._des(val))


    def trim(self, keys: str|bytes|memoryview|Iterable[str|bytes]=b"",
                *, top=False):
        """
        Removes all entries whose keys startswith keys. Enables removal of whole
        branches of db key space. To ensure that proper separation of a branch
        include empty string as last key in keys. For example ("a","") deletes
        'a.1'and 'a.2' but not 'ab'

        Parameters:
            keys (Iterator[str | bytes | memoryview]): of key parts that may be
                a truncation of a full keys tuple in  in order to address all the
                items from multiple branches of the key space.
                If keys is empty then gets all items in database.
                Either append "" to end of keys Iterable to ensure get properly
                separated top branch key or use top=True.

            top (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of top value


        Returns:
           result (bool): True if val at key exists so delete successful. False otherwise
        """
        return(self.db.delTopVal(db=self.sdb, key=self._tokey(keys, top=top)))


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





class OrdSuber(Suber):
    """
    Subclass of Suber that adds methods for keys with ordinal numbered suffixes.
    Each key consistes of pre joined with .sep to ordinal suffix

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
        super(Suber, self).__init__(*pa, **kwa)


    def cntOrdPre(self, pre: str | bytes | memoryview, on: int=0):
        """
        Returns
            cnt (int): count of of all ordinal suffix keyed vals with same pre
                in key but different on in key in db starting at ordinal number
                on of pre where key is formed with onKey(pre,on)
                       Does not count dups at same on for a given pre, only
                       unique on at a given pre.

        Parameters:
            pre (str | bytes | memoryview): prefix to  to be combined with on
                to form key
            on (int): ordinal number used with onKey(pre,on) to form key.
        """
        return (self.db.cntAllOrdValsPre(db=self.sdb, pre=self._tokey(pre), on=on))

    # appendOrdPre

    #def appendOrdValPre(self, db, pre, val):
        #"""
        #Appends val in order after last previous key with same pre in db.
        #Returns ordinal number in, on, of appended entry. Appended on is 1 greater
        #than previous latest on.
        #Uses onKey(pre, on) for entries.

        #Append val to end of db entries with same pre but with on incremented by
        #1 relative to last preexisting entry at pre.

        #Parameters:
            #db is opened named sub db with dupsort=False
            #pre is bytes identifier prefix for event
            #val is event digest
        #"""

    # getAllOrdItemPreIter
    #def getAllOrdItemPreIter(self, db, pre, on=0):
        #"""
        #Returns iterator of duple item, (on, dig), at each key over all ordinal
        #numbered keys with same prefix, pre, in db. Values are sorted by
        #onKey(pre, on) where on is ordinal number int.
        #Returned items are duples of (on, dig) where on is ordinal number int
        #and dig is event digest for lookup in .evts sub db.

        #Raises StopIteration Error when empty.

        #Parameters:
            #db is opened named sub db with dupsort=False
            #pre is bytes of itdentifier prefix
            #on is int ordinal number to resume replay
        #"""


    #def getAllOrdItemAllPreIter(self, db, key=b''):
        #"""
        #Returns iterator of triple item, (pre, on, dig), at each key over all
        #ordinal numbered keys for all prefixes in db. Values are sorted by
        #onKey(pre, on) where on is ordinal number int.
        #Each returned item is triple (pre, on, dig) where pre is identifier prefix,
        #on is ordinal number int and dig is event digest for lookup in .evts sub db.

        #Raises StopIteration Error when empty.

        #Parameters:
            #db is opened named sub db with dupsort=False
            #key is key location in db to resume replay,
                   #If empty then start at first key in database
        #"""


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


    def _des(self, val: Union[str, memoryview, bytes]):
        """
        Deserialize val to str
        Parameters:
            val (Union[str, memoryview, bytes]): convertable to coring.matter
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


    def append(self, keys: str | bytes | memoryview | Iterable,
                     val: str | bytes | memoryview):
        """Append val non-idempotently to insertion ordered set of values all with
        the same apparent effective key.  If val already in set at key then
        after append there will be multiple entries in database with val at key
        each with different insertion order (iokey).
        Uses hidden ordinal key suffix for insertion ordering.
        The suffix is appended and stripped transparently.

        Works by walking backward to find last iokey for key instead of reading
        all vals for iokey.

        Returns:
           ion (int): hidden insertion ordering ordinal of appended val

        Parameters:
            keys (str | bytes | memoryview | Iterable): of key parts to be
                    combined in order to form key
            val (str | bytes | memoryview): serialization


        """
        return (self.db.appendIoSetVal(db=self.sdb,
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


    def remIokey(self, iokeys: str | bytes | memoryview | Iterable):
        """
        Removes entries at iokeys

        Parameters:
            iokeys (str | bytes | memoryview | Iterable): of key str or
                    tuple of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise

        """
        return self.db.delIoSetIokey(db=self.sdb, iokey=self._tokey(iokeys))


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


    def getIoSetItem(self, keys: str | bytes | memoryview | Iterable,
                     *, ion=0):
        """
        Gets (iokeys, val) ioitems list at key made from keys where key is
        apparent effective key and ioitems all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            ion (int): starting ordinal value, default 0

        Returns:
            ioitems (Iterable):  each item in list is tuple (iokeys, val) where each
                    iokeys is actual key tuple including hidden suffix and
                    each val is str
                    empty list if no entry at keys

        """
        return ([(self._tokeys(iokey), self._des(val)) for iokey, val in
                        self.db.getIoSetItemsIter(db=self.sdb,
                                                  key=self._tokey(keys),
                                                  ion=ion,
                                                  sep=self.sep)])


    def getIoSetItemIter(self, keys: str | bytes | memoryview | Iterable,
                         *, ion=0):
        """
        Gets (iokeys, val) ioitems  iterator at key made from keys where key is
        apparent effective key and items all have same apparent effective key

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key
            ion (int): starting ordinal value, default 0

        Returns:
            ioitems (Iterator):  each item iterated is tuple (iokeys, val) where
                each iokeys is actual keys tuple including hidden suffix and
                each val is str
                empty list if no entry at keys.
                Raises StopIteration when done

        """
        for iokey, val in self.db.getIoSetItemsIter(db=self.sdb,
                                                    key=self._tokey(keys),
                                                    ion=ion,
                                                    sep=self.sep):
            yield (self._tokeys(iokey), self._des(val))



    def getItemIter(self, keys: str | bytes | memoryview | Iterable = b"",
                    *, top=False):
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
                a full keys tuple in  in order to address all the items from
                multiple branches of the key space. If keys is empty then gets
                all items in database.
                Either append "" to end of keys Iterable to ensure get properly
                separated top branch key or use top=True.

            top (bool): True means treat as partial key tuple from top branch of
                       key space given by partial keys. Resultant key ends in .sep
                       character.
                       False means treat as full branch in key space. Resultant key
                       does not end in .sep character.
                       When last item in keys is empty str then will treat as
                       partial ending in sep regardless of top value

        """
        for iokey, val in self.db.getTopItemIter(db=self.sdb,
                                                 key=self._tokey(keys, top=top)):
            key, ion = dbing.unsuffix(iokey, sep=self.sep)
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



    def getItemIter(self, keys: Union[str, Iterable]=b"",
                       decrypter: core.Decrypter = None):
        """
        Returns:
            iterator (Iterator): of tuples (key, val) over the all the items in
            subdb whose key startswith key made from keys. Keys may be keyspace
            prefix to return branches of key space. When keys is empty then
            returns all items in subdb

        decrypter (core.Decrypter): optional. If provided assumes value in
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




class SchemerSuber(Suber):
    """
    Sub class of Suber where data is serialized Schemer instance
    Automatically serializes and deserializes using Schemer methods

    ToDo XXXX make this a subclass of SerderSuber since from a ser des interface
    Schemer is duck type of Serder, Then can get rid of the redundant put, add,
    pin, get etc definitions

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
            val (Union[bytes, str]): serialization

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
                                     key=keys,
                                     vals=[self._ser(val) for val in vals])


    def get(self, keys: str | bytes | memoryview | Iterable):
        """
        Gets vals set list at key made from keys in insertion order using
        hidden ordinal proem.

        Parameters:
            keys (Iterable): of key strs to be combined in order to form key

        Returns:
            vals (Iterable):  each item in list is str
                          empty list if no entry at keys

        """
        return ([self._des(val) for val in
                    self.db.getIoDupVals(db=self.sdb, key=self._tokey(keys))])


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
