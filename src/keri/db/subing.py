# -*- encoding: utf-8 -*-
"""
KERI
keri.db.subdbing module

"""
from typing import Type, Union, Iterable

from .. import help
from ..core import coring
from . import dbing


logger = help.ogler.getLogger()

class SuberBase():
    """
    Base class for Sub DBs of LMDBer
    Provides common methods for subclasses
    Do not instantiate but use a subclass
    """
    Sep = '.'  # separator for combining key iterables

    def __init__(self, db: Type[dbing.LMDBer], *,
                       subkey: str = 'docs.',
                       dupsort: bool = False,
                       sep: str = None,
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
        super(SuberBase, self).__init__(**kwa)  # Mixin for Multi-inheritance MRO
        self.db = db
        self.sdb = self.db.env.open_db(key=subkey.encode("utf-8"), dupsort=dupsort)
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


class Suber(SuberBase):
    """
    Sub DB of LMDBer. Subclass of SuberBase
    """

    def __init__(self, db: Type[dbing.LMDBer], *, subkey: str = 'docs.', **kwa):
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


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val bytes for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), bytes(val).decode("utf-8"))


class DupSuber(SuberBase):
    """
    Sub DB of LMDBer. Subclass of SuberBase that supports multiple entries at
    each key (duplicates) with dupsort==True
    """

    def __init__(self, db: Type[dbing.LMDBer], *, subkey: str = 'docs.', **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(DupSuber, self).__init__(db=db, subkey=subkey, dupsort=True, **kwa)

    @staticmethod
    def _encode(val):
        return (val.encode("utf-8") if hasattr(val, "encode") else val)

    @staticmethod
    def _decode(val):
        return (val.decode("utf-8") if hasattr(val, "decode") else val)


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
                        self.db.getVals(db=self.sdb, key=self._tokey(keys))]


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


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val dataclass instance for
            each entry in db. Raises StopIteration when done

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self._decode(bytes(val)))


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


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), coring.Serder(raw=bytes(val)))


class SerderDupSuber(DupSuber):
    """
    Sub class of DupSuber that supports multiple entries at each key (duplicates)
    with dupsort==True, where data is serialized Serder instance.
    Automatically serializes and deserializes using Serder methods

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
                        self.db.getVals(db=self.sdb, key=self._tokey(keys))]


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


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder instance for
            each entry in db. Raises StopIteration when done

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), coring.Serder(raw=bytes(val)))


class MatterSuber(Suber):
    """
    Sub class of Suber where data is Matter subclass instance .qb64b property
    which is a fully qualified serialization
    Automatically serializes and deserializes from qb64b to/from Matter instances

    """

    def __init__(self, *pa, klas: Type[coring.Matter] = coring.Matter, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter
        """
        if not (issubclass(klas, coring.Matter)):
            raise ValueError("Invalid klas type={}, expected {}."
                             "".format(klas, coring.Matter))
        super(MatterSuber, self).__init__(*pa, **kwa)
        self.klas = klas


    def put(self, keys: Union[str, Iterable], val: coring.Matter):
        """
        Puts qb64 of Matter instance val at key made from keys. Does not overwrite

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
        Pins (sets) qb64 of Matter instance val at key made from keys. Overwrites.

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


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val Serder for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.klas(qb64b=bytes(val)))



class MatterDupSuber(DupSuber):
    """
    Sub class of DupSuber that supports multiple entries at each key (duplicates)
    with dupsort==True, where data where data is Matter.qb64b property
    which is a fully qualified serialization of matter subclass instance
    Automatically serializes and deserializes from qb64b to/from Matter instances

    """
    def __init__(self, *pa, klas: Type[coring.Matter] = coring.Matter, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
            klas (Type[coring.Matter]): Class reference to subclass of Matter
        """
        if not (issubclass(klas, coring.Matter)):
            raise ValueError("Invalid klas type={}, expected {}."
                             "".format(klas, coring.Matter))
        super(MatterDupSuber, self).__init__(*pa, **kwa)
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
                        self.db.getVals(db=self.sdb, key=self._tokey(keys))]


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


    def getItemIter(self):
        """
        Return iterator over the all the items in subdb. Each duplicate at a
        given key is yielded as a separate item.

        Returns:
            iterator: of tuples of keys tuple and val self.klas instance for
            each entry in db. Raises StopIteration when done

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, split=False):
            yield (self._tokeys(key), self.klas(qb64b=bytes(val)))


class SignerSuber(MatterSuber):
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


    def getItemIter(self):
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


class CryptSignerSuber(SignerSuber):
    """
    Sub class of MatterSuber where data is Signer subclass instance .qb64b propery
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


    def getItemIter(self, decrypter: coring.Decrypter = None):
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
