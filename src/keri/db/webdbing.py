# -*- encoding: utf-8 -*-
"""
keri.db.webdbing module

Browser-safe plain-value DBer backed by PyScript storage.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

try:
    from pyscript import storage
except ImportError:  # pragma: no cover
    storage = None

from ordered_set import OrderedSet as oset
from sortedcontainers import SortedDict

from ..recording import (KeyStateRecord, EventSourceRecord, HabitatRecord)

# The following are necessary to define in this file 
# to prevent non wasm compatible imports (importing from dbing)
# MaxON, onKey, splitKey, splitOnKey

MaxON = int("f"*32, 16)  # max ordinal number, same as kering.MaxON


def onKey(top, on, *, sep=b'.'):
    """
    Returns:
        onkey (bytes): key formed by joining top key and hex str conversion of
                       int ordinal number on with sep character.

    Parameters:
        top (str | bytes): top key prefix to be joined with hex version of on using sep
        on (int): ordinal number to be converted to 32 hex bytes
        sep (bytes): separator character for join
    """
    if hasattr(top, "encode"):
        top = top.encode("utf-8")
    return (b'%s%s%032x' % (top, sep, on))


def splitKey(key, sep=b'.'):
    """
    Returns duple of pre and either dig or on, sn, fn str or dts datetime str by
    splitting key at bytes sep
    Accepts either bytes or str key and returns same type
    Raises ValueError if key does not split into exactly two elements

    Parameters:
       key is database key with split at sep
       sep is bytes separator character. default is b'.'
    """
    if isinstance(key, memoryview):
        key = bytes(key)
    if hasattr(key, "encode"):  # str not bytes
        if hasattr(sep, 'decode'):  # make sep match bytes or str
            sep = sep.decode("utf-8")
    else:
        if hasattr(sep, 'encode'):  # make sep match bytes or str
            sep = sep.encode("utf-8")
    splits = key.rsplit(sep, 1)
    if len(splits) != 2:
        raise  ValueError(f"Unsplittable {key=} at {sep=}.")
    return tuple(splits)


def splitOnKey(key, *, sep=b'.'):
    """
    Returns list of pre and int on from key
    Accepts either bytes or str key
    ordinal number  appears in key in hex format
    """
    if isinstance(key, memoryview):
        key = bytes(key)
    top, on = splitKey(key, sep=sep)
    on = int(on, 16)
    return (top, on)


def suffix(key: Union[bytes, str, memoryview], ion: int, *, sep: Union[bytes, str]=b'.'):
    """
    Returns:
       iokey (bytes): actual DB key after concatenating suffix as hex version
       of insertion ordering ordinal int ion using separator sep.

    Parameters:
        key (Union[bytes, str]): apparent effective database key (unsuffixed)
        ion (int)): insertion ordering ordinal for set of vals
        sep (bytes): separator character(s) for concatenating suffix
    """
    if isinstance(key, memoryview):
        key = bytes(key)
    elif hasattr(key, "encode"):
        key = key.encode("utf-8")  # encode str to bytes
    if hasattr(sep, "encode"):
        sep = sep.encode("utf-8")
    ion =  b"%032x" % ion
    return sep.join((key, ion))


def unsuffix(iokey: Union[bytes, str, memoryview], *, sep: Union[bytes, str]=b'.'):
    """
    Returns:
       result (tuple): (key, ion) by splitting iokey at rightmost separator sep
            strip off suffix, where key is bytes apparent effective DB key and
            ion is the insertion ordering int converted from stripped of hex
            suffix

    Parameters:
        iokey (Union[bytes, str]): apparent effective database key (unsuffixed)
        sep (bytes): separator character(s) for concatenating suffix
    """
    if isinstance(iokey, memoryview):
        iokey = bytes(iokey)
    elif hasattr(iokey, "encode"):
        iokey = iokey.encode("utf-8")  # encode str to bytes
    if hasattr(sep, "encode"):
        sep = sep.encode("utf-8")
    key, ion = iokey.rsplit(sep=sep, maxsplit=1)
    ion = int(ion, 16)
    return (key, ion)


def isNonStringIterable(obj):
    """
    Returns:
        (bool): True if obj is non-string iterable, False otherwise

    Future proof way that is compatible with both Python3 and Python2 to check
    for non string iterables.

    Faster way that is less future proof
    return (hasattr(x, '__iter__') and not isinstance(x, (str, bytes)))
    """
    return (not isinstance(obj, (str, bytes)) and isinstance(obj, Iterable))


_RECORDS_KEY = "__records__"
_META_KEY = "__meta__"


@dataclass
class SubDb:
    """
    One declared browser-backed subdb.

    Attributes:
        name: Logical store name used by wrappers, for example "bags.".
        namespace: Backing storage namespace, for example "wallet:bags.".
        handle: PyScript storage handle bound to namespace.
        dupsort: Effective dupsort flag for this named store.
        flags_persisted: True once dupsort has been loaded from or flushed to
            backing storage.
        dirty: True when items differs from the last flushed payload.
        opened: True after the first env.open_db(...).
        items: Live ordered ``bytes -> bytes`` map used by sync CRUD methods.
    """

    name: str
    namespace: str
    handle: Any
    dupsort: bool = False
    flags_persisted: bool = False
    dirty: bool = False
    opened: bool = False
    items: Any = field(default_factory=lambda: SortedDict() if SortedDict else dict())

    def flags(self) -> dict[str, bool]:
        """Return the subdb flags used by upstream wrapper tests."""
        return {"dupsort": self.dupsort}


class WebEnv:
    """Minimal named-subdb opener used by upstream wrappers."""

    def __init__(self, owner: "WebDBer"):
        self.owner = owner

    def open_db(self, key: bytes | str, dupsort: bool = False) -> SubDb:
        """
        Open a preconfigured named subdb handle.

        Parameters:
            key: Subdb name as bytes or UTF-8 text.
            dupsort: Requested duplicate flag. Applied only when the named
                store has not yet persisted its dupsort metadata.

        Returns:
            The stable `SubDb` handle for the requested store.

        Raises:
            KeyError: If the store was not declared when the DBer was opened.
        """
        name = self.owner._storify(key)
        if name not in self.owner._stores:
            raise KeyError(f"Store not configured in WebDBer: {name}")
        subdb = self.owner._stores[name]
        if not subdb.opened:
            if not subdb.flags_persisted:
                subdb.dupsort = bool(dupsort)
                subdb.flags_persisted = True
                subdb.dirty = True
            subdb.opened = True
        return subdb


class WebDBer:
    """
    Browser-backed plain-value DBer.

    In-memory SortedDict backing each named store with an async flush()
    boundary that persists to browser storage (PyScript/IndexedDB).
    Sync callers see immediate reads/writes against the in-memory mirror.
    Persistence only happens at explicit flush points.

    Attributes:
        name: Base namespace prefix shared by all declared stores.
        env: Sync open_db(...) adapter used by upstream wrappers.
        _stores: Authoritative mapping of store name to SubDb.
        stores: Declared store names exposed for inspection and tests.
    """

    def __init__(self, *, name: str, stores: dict[str, SubDb]):
        self.name = name
        self.env = WebEnv(self)
        self._stores = stores
        self.stores = list(stores)

    @classmethod
    async def open(
        cls,
        name: str,
        stores: list[str],
        *,
        clear: bool = False,
        storageOpener: Callable[[str], Awaitable[Any]] | None = None,
    ) -> "WebDBer":
        """
        Open a storage-backed WebDBer instance with a fixed set of stores.

        Parameters:
            name: Base namespace used to derive per-store persistence names.
            stores: Declared subdb names available through `env.open_db`.
            clear: When `True`, reset all persisted store payloads before
                loading them into memory, including per-store metadata.
            storageOpener: Async callable that returns a storage handle for a
                namespace. Defaults to `pyscript.storage`.

        Returns:
            A storage-backed `WebDBer` ready for sync CRUD and async `flush()`.

        Raises:
            RuntimeError: If no storage opener is available.
        """

        opener = storageOpener if storageOpener is not None else storage
        if opener is None:
            raise RuntimeError("pyscript.storage is unavailable in this environment")

        opened: dict[str, SubDb] = {}
        for store_name in [cls._storify(store) for store in stores]:
            namespace = f"{name}:{store_name}"
            handle = await opener(namespace)
            if clear:
                handle[_RECORDS_KEY] = "{}"
                handle[_META_KEY] = "{}"
                await handle.sync()
            items = SortedDict(_deserialize_records(handle.get(_RECORDS_KEY)))
            meta = _deserialize_meta(handle.get(_META_KEY))
            flags_persisted = "dupsort" in meta
            if items and not flags_persisted:
                raise ValueError(
                    "Persisted store metadata missing for non-empty store: "
                    f"{namespace}. Clear storage to recreate it."
                )
            opened[store_name] = SubDb(
                name=store_name,
                namespace=namespace,
                handle=handle,
                dupsort=bool(meta.get("dupsort", False)),
                flags_persisted=flags_persisted,
                items=items,
            )

        return cls(name=name, stores=opened)

    @staticmethod
    def _storify(key: bytes | str) -> str:
        if isinstance(key, str):
            return key
        if isinstance(key, bytes):
            return key.decode("utf-8")
        raise TypeError(f"Unsupported store handle type: {type(key)}")

    async def flush(self) -> int:
        """
        Persist dirty stores to their backing storage handles.

        Stores are synced one at a time. If sync fails partway through,
        already-synced stores will have dirty=False and will NOT be
        re-flushed on retry. This is acceptable because browser IndexedDB
        is BASE (not ACID) and keripy's KEL verification model recovers
        from lost unflushed writes on startup via KEL cleaning.

        Returns:
            The number of stores whose serialized payload and metadata
            were synced.
        """
        count = 0
        for subdb in self._stores.values():
            if not subdb.dirty:
                continue
            subdb.handle[_RECORDS_KEY] = _serialize_records(subdb.items)
            subdb.handle[_META_KEY] = _serialize_meta({"dupsort": subdb.dupsort})
            await subdb.handle.sync()
            subdb.dirty = False
            count += 1
        return count

    def putVal(self, db: SubDb, key: bytes, val: bytes) -> bool:
        """
        Insert `val` at `key` without overwriting an existing value.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            key: Exact bytes key within the subdb keyspace.
            val: Serialized bytes value to store.

        Returns:
            `True` when the value is inserted. `False` when `key` already exists.

        Raises:
            KeyError: If `key` is empty.
        """
        if not key:
            raise KeyError(
                f"Key: `{key}` is either empty, too big (for lmdb), "
                "or wrong DUPFIXED size. ref) lmdb.BadValsizeError"
            )

        if key in db.items:
            return False

        db.items[key] = val
        db.dirty = True
        return True

    def setVal(self, db: SubDb, key: bytes, val: bytes) -> bool:
        """
        Insert or overwrite `val` at `key`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            key: Exact bytes key within the subdb keyspace.
            val: Serialized bytes value to store.

        Returns:
            `True` after the write succeeds.

        Raises:
            KeyError: If `key` is empty.
        """
        if not key:
            raise KeyError(
                f"Key: `{key}` is either empty, too big (for lmdb), "
                "or wrong DUPFIXED size. ref) lmdb.BadValsizeError"
            )

        db.items[key] = val
        db.dirty = True
        return True

    def getVal(self, db: SubDb, key: bytes) -> bytes | None:
        """
        Return the stored value at `key`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            key: Exact bytes key within the subdb keyspace.

        Returns:
            Stored bytes value, or `None` when `key` is missing.

        Raises:
            KeyError: If `key` is empty.
        """
        if not key:
            raise KeyError(
                f"Key: `{key}` is either empty, too big (for lmdb), "
                "or wrong DUPFIXED size. ref) lmdb.BadValsizeError"
            )

        return db.items.get(key)

    def remVal(self, db: SubDb, key: bytes) -> bool:
        """
        Remove the exact entry at `key`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            key: Exact bytes key within the subdb keyspace.

        Returns:
            `True` when an entry existed and was removed. `False` when
            `key` is empty or missing from the subdb.
        """
        if not key:
            return False

        if key not in db.items:
            return False

        del db.items[key]
        db.dirty = True
        return True

    delVal = remVal  # backwards compat alias for refactoring

    def putOnVal(
        self,
        db: SubDb,
        key: bytes,
        on: int = 0,
        val: bytes | None = None,
        *,
        sep: bytes = b".",
    ) -> bool:
        """
        Write serialized bytes val to location at onkey consisting of
        key + sep + serialized on in db.
        Does not overwrite.

        Returns:
            result (bool): True if successful write, i.e. onkey not already
                in db. False otherwise, including when val is None.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key within the sub db
                keyspace to which the ordinal tail is added.
            on (int): ordinal number at which to write.
            val (bytes | None): serialized value to be
                written at onkey. When None returns False.
            sep (bytes): separator character for join.
        """
        if val is None:
            return False

        return self.putVal(db=db, key=onKey(key, on, sep=sep), val=val)

    def pinOnVal(
        self,
        db: SubDb,
        key: bytes,
        on: int = 0,
        val: bytes | None = None,
        *,
        sep: bytes = b".",
    ) -> bool:
        """
        Replace value if any at location onkey = key + sep + on with val.
        Replaces pre-existing value at onkey if any or different.
        When key is empty or val is None returns False.

        Returns:
            result (bool): True if successful replacement.
                False if key is empty or val is None.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key within the sub db
                keyspace to which the ordinal tail is added.
            on (int): ordinal number at which to write.
            val (bytes | None): serialized value to be
                written at onkey. When None returns False.
            sep (bytes): separator character for split.
        """
        if val is None or not key:
            return False

        return self.setVal(db=db, key=onKey(key, on, sep=sep), val=val)

    def appendOnVal(
        self,
        db: SubDb,
        key: bytes,
        val: bytes,
        *,
        sep: bytes = b".",
    ) -> int:
        """
        Append val in order after the last previous onkey = key + sep + on
        as a new entry at a new onkey. New on for the new onkey is one
        greater than the last prior on for the given key in db.
        The onkey of the appended entry is one greater than the last prior
        onkey for key in db.

        Returns:
            on (int): ordinal number of the new onkey for newly appended val.

        Parameters:
            db (SubDb): named browser-backed sub db whose effective keys use
                a hidden ordinal tail for insertion ordering.
            key (bytes): base key within the sub db
                keyspace. If empty raises ValueError.
            val (bytes): serialized value to append.
                If None raises ValueError.
            sep (bytes): separator character for split.

        Raises:
            ValueError: If key is empty, val is None, the next ordinal
                would exceed the maximum 32-hex-width ordinal, or the final
                insert at the computed onkey does not succeed.
        """
        if not key or val is None:
            raise ValueError(f"Bad append parameter: {key=} or {val=}")

        onkey = onKey(key, MaxON, sep=sep)
        idx = db.items.bisect_right(onkey)
        if idx:
            ponkey, _ = db.items.peekitem(idx - 1)
            ckey, cn = splitOnKey(ponkey, sep=sep)
            if ckey == key:
                if cn >= MaxON:
                    raise ValueError(f"Number part {cn=} for key part {key=} exceeds maximum size.")
                on = cn + 1
            else:
                on = 0
        else:
            on = 0

        if not self.putVal(db=db, key=onKey(key, on, sep=sep), val=val):
            raise ValueError(f"Failed appending {val=} at {key=}.")
        return on

    def getOnItem(
        self,
        db: SubDb,
        key: bytes,
        on: int = 0,
        *,
        sep: bytes = b".",
    ) -> tuple[bytes, int, bytes] | None:
        """
        Get item `(key, on, val)` at `onkey = key + sep + on`.
        When `onkey` is missing from `db` or `key` is empty returns `None`.

        Returns:
            item (tuple[bytes, int, bytes] | None): entry item at `onkey`,
                tuple of form `(key, on, val)`. `None` if no entry at `onkey`.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key.
            on (int): ordinal number at which to retrieve.
            sep (bytes): separator character for split.
        """
        if not key:
            return None

        if (val := self.getVal(db=db, key=onKey(key, on, sep=sep))) is None:
            return None

        return key, on, val

    def getOnVal(
        self,
        db: SubDb,
        key: bytes,
        on: int = 0,
        *,
        sep: bytes = b".",
    ) -> bytes | None:
        """
        Get value at `onkey = key + sep + on`.
        When `onkey` is missing from `db` or `key` is empty returns `None`.

        Returns:
            val (bytes | None): entry at `onkey = key + sep + on`.
                `None` if `onkey` is missing from `db` or `key` is empty.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key within the sub db
                keyspace to which the ordinal tail is added.
            on (int): ordinal number at which to retrieve.
            sep (bytes): separator character for split.
        """
        if not key:
            return None

        return self.getVal(db=db, key=onKey(key, on, sep=sep))

    def remOn(
        self,
        db: SubDb,
        key: bytes,
        on: int = 0,
        *,
        sep: bytes = b".",
    ) -> bool:
        """
        Remove entry if any at `onkey = key + sep + on`.
        When `key` is missing or empty returns `False`.

        Returns:
            result (bool): `True` if entry at `onkey` was removed.
                `False` otherwise if no entry at `onkey` or `key` is empty.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key within the sub db
                keyspace to which the ordinal tail is added.
            on (int): ordinal number at which to delete.
            sep (bytes): separator character for split.
        """
        if not key:
            return False

        return self.remVal(db=db, key=onKey(key, on, sep=sep))

    def remOnAll(
        self,
        db: SubDb,
        key: bytes = b"",
        on: int = 0,
        *,
        sep: bytes = b".",
    ) -> bool:
        """
        Remove entry at each `onkey` for all `on >= on` where for each `on`,
        `onkey = key + sep + on`.
        When `on` is `0`, default, then deletes all `on` at `key`.
        When `key` is empty then deletes whole `db`.

        Returns:
            result (bool): `True` if any entries were deleted.
                `False` otherwise.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key. When empty removes all
                entries in the whole sub db.
            on (int): ordinal number at which to add to `key` to form
                effective key. `0` means to delete all `on` at `key`.
            sep (bytes): separator character for split.

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed.
        """
        if not key:
            return self.remTop(db=db, top=b"")

        doomed = []
        for okey in db.items.irange(minimum=onKey(key, on, sep=sep)):
            ckey, _ = splitOnKey(okey, sep=sep)
            if ckey != key:
                break
            doomed.append(okey)

        if not doomed:
            return False

        for okey in doomed:
            del db.items[okey]
        db.dirty = True
        return True

    def cntOnAll(
        self,
        db: SubDb,
        key: bytes = b"",
        on: int = 0,
        *,
        sep: bytes = b".",
    ) -> int:
        """
        Count all entries one for each `onkey` for all `on >= on` where for
        each `on`, `onkey = key + sep + on`.
        When `key` is empty then count whole sub db.

        Returns:
            count (int): count of all ordinal-keyed values with base `key` but
                different ordinal tail in `db`, starting at ordinal number `on`
                for `on >= on`. Full key is composed of `key + sep + on`.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key within the sub db
                keyspace. When empty counts whole sub db.
            on (int): ordinal number at which to initiate count.
            sep (bytes): separator character for split.
        """
        start = onKey(key, on, sep=sep) if key else b""
        count = 0

        for okey in db.items.irange(minimum=start):
            try:
                ckey, _ = splitOnKey(okey, sep=sep)
            except ValueError:
                break

            if key and ckey != key:
                break
            count += 1

        return count

    def getOnTopItemIter(
        self,
        db: SubDb,
        top: bytes = b"",
        *,
        sep: bytes = b".",
    ) -> Iterator[tuple[bytes, int, bytes]]:
        """
        Iterate over top branch of all entries where each top key startswith
        `top`.
        Assumes every effective key in `db` has trailing `on` element,
        `onkey = key + sep + on`, so can return `on` in each item.
        When top key is empty, gets all items in database.

        Returns:
            items (Iterator[tuple[bytes, int, bytes]]): iterator of triples
                `(key, on, val)`.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            top (bytes): truncated top key, a keyspace
                prefix to get all items from multiple branches of the keyspace.
                If empty gets all items in database.
            sep (bytes): separator character for split.
        """
        prefix = top

        for okey, val in self.getTopItemIter(db=db, top=prefix):
            key, on = splitOnKey(okey, sep=sep)
            yield key, on, val

    def getOnAllItemIter(
        self,
        db: SubDb,
        key: bytes = b"",
        on: int = 0,
        *,
        sep: bytes = b".",
    ) -> Iterator[tuple[bytes, int, bytes]]:
        """
        Get iterator of triples `(key, on, val)`, at each key over all ordinal
        numbered keys with same `key` and `on >= on`.
        When `on = 0`, default, then iterates over all `on` at `key`.
        When `key` is empty then iterates over all `on` for all keys, whole
        db. Returned items are triples of `(key, on, val)`.

        Entries are sorted by `onKey(key, on)` where `on` is ordinal number
        int and `key` is prefix sans `on`.

        Returns:
            items (Iterator[tuple[bytes, int, bytes]]): triples of
                `(key, on, val)` for `onkey = key + sep + on` for `on >= on`
                at `key`.

        Parameters:
            db (SubDb): named browser-backed sub db with one value per
                effective key.
            key (bytes): base key. When empty retrieves the
                whole sub db.
            on (int): ordinal number at which to initiate retrieval.
            sep (bytes): separator character for split.
        """
        yield from _iterOnItems(db=db, key=key if key else None, on=on, sep=sep)

    def getTopItemIter(self, db: SubDb, top: bytes = b"") -> Iterator[tuple[bytes, bytes]]:
        """
        Iterate over `(key, val)` pairs whose keys start with `top`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            top (bytes): prefix bytes used to select a branch of the keyspace. Empty
                prefix yields the entire subdb in lexical order.

        Returns:
            Iterator of `(key, val)` tuples in lexical key order.
        """
        prefix = top

        if not prefix:
            for key, val in db.items.items():
                yield key, val
            return

        try:
            raw = db.items.irange(minimum=prefix)
        except IndexError:
            return iter(())

        try:
            keys = list(raw)
        except IndexError:
            return iter(())


        for key in keys:
            if not key.startswith(prefix):
                break
            yield key, db.items[key]

    def remTop(self, db: SubDb, top: bytes = b"") -> bool:
        """
        Remove all entries whose keys start with `top`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            top (bytes): prefix bytes used to select the branch to delete. Empty prefix
                deletes the whole subdb.

        Returns:
            `True` when at least one entry is deleted. `False` when nothing
            matched the requested prefix.
        """
        prefix = top

        if not prefix:
            if not db.items:
                return False
            db.items.clear()
            db.dirty = True
            return True

        doomed = [key for key, _ in self.getTopItemIter(db=db, top=prefix)]
        if not doomed:
            return False

        for key in doomed:
            del db.items[key]
        db.dirty = True
        return True

    delTop = remTop  # backwards compat alias matching LMDBer

    def cntTop(self, db: SubDb, top: bytes = b"") -> int:
        """
        Count all entries whose keys start with `top`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.
            top (bytes): prefix bytes used to select a branch of the keyspace.
                Empty prefix counts the entire subdb.

        Returns:
            Number of entries in the branch.
        """
        if not top:
            return len(db.items)  # O(1) for empty prefix

        count = 0
        for key in db.items.irange(minimum=top):
            if not key.startswith(top):
                break
            count += 1
        return count

    def cntAll(self, db: SubDb) -> int:
        """
        Count all values stored in `db`.

        Parameters:
            db: Named subdb handle returned by `env.open_db`.

        Returns:
            Total number of stored entries.
        """
        return len(db.items)


    def putIoSetVals(self, db, key, vals, *, sep=b'.'):
        """Add each val in vals to insertion ordered set of values all with the
        same apparent effective key for each val that is not already in set of
        vals at key.
        Uses hidden ordinal key suffix for insertion ordering.
        The suffix is appended and stripped transparently.

        Returns:
            result (bool): True if any val in vals is added to set.
                          False otherwise including key not in db, empty or None
                          or vals empty or None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): Apparent effective key
            vals (NonStrIterable|None): serialized values to add to set of vals at key
            sep (bytes): separator character for split

        """
        # 1. Empty key or empty vals so no-op
        if not key or not vals:
            return False

        # Normalize to insertion-ordered set
        vals = oset(vals)  # preserves order, removes duplicates

        # 2. Prepare prefix and initial ordinal key
        iokey = suffix(key, 0, sep=sep)

        # 3. Scan existing entries
        pvals = oset()
        maxIon = -1

        # Iterate through all values per prefix and add them to pvals
        for iokey in db.items.irange(minimum=iokey):

            ckey, cion = unsuffix(iokey, sep=sep)
            if ckey != key:
                break

            val = db.items[iokey]
            pvals.add(val)
            if cion > maxIon:
                maxIon = cion

        # 4. Remove already-present values
        newVals = [v for v in vals if v not in pvals]
        
        # If no new values return False
        if not newVals:
            return False

        # 5. Insert new values at sequential ordinals
        # Append-only behavior, new values are always appended at the next ordinal 
        start = maxIon + 1
        for offset, val in enumerate(newVals):
            ion = start + offset
            iokey = suffix(key, ion, sep=sep)
            db.items[iokey] = val

        db.dirty = True
        return True


    def pinIoSetVals(self, db, key, vals, *, sep=b'.'):
        """Replace all vals at key with vals as insertion ordered set of
        values all with the same apparent effective key. Does not replace if
        key is empty or None or vals is empty or None

        Uses hidden ordinal key suffix for insertion ordering.
        The suffix is appended and stripped transparently.

        Returns:
           result (bool): True if vals replaced set.
                          False otherwise including key not in db, empty or None
                          or vals empty or None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): Apparent effective key
            vals (NonStrIterable|None): serialized values to add to set of vals at key
            sep (bytes): separator character for split
        """
        # 1. No-op if key or vals are empty
        if not key or not vals:
            return False

        # Normalize to insertion-ordered unique list
        vals = oset(vals)
        if not vals:
            return False

        # 2. Remove all existing entries for this key
        self.remIoSet(db=db, key=key, sep=sep)

        # 3. Insert new values
        for ion, val in enumerate(vals):
            iokey = suffix(key, ion, sep=sep)
            db.items[iokey] = val

        # 4. Mark dirty
        db.dirty = True

        return True


    def addIoSetVal(self, db, key, val, *, sep=b'.'):
        """Add val to insertion ordered set of values all with the
        same apparent effective key if val not already in set of vals at key.
        When val None returns False

        Uses hidden ordinal key suffix for insertion ordering.
        The suffix is appended and stripped transparently.

        Returns:
           result (bool): True if val added to set.
                          False if already in set or key is empty or None or val
                          is None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): Apparent effective key
            val (bytes|None): serialized value to add
            sep (bytes): separator character for split

        """
        # 1. Exit on empty key or missing value 
        if not key or val is None:
            return False
        
        iokey = suffix(key, 0, sep=sep)

        # 2. Scan existing entries
        pvals = set()
        maxIon = -1

        for iokey in db.items.irange(minimum=iokey):

            ckey, cion = unsuffix(iokey, sep=sep)
            if ckey != key:
                break

            cval = db.items[iokey]
            pvals.add(cval)

            if cion > maxIon:
                maxIon = cion

        # 3. If value already present then no-op
        if val in pvals:
            return False

        # 4. Insert at next ordinal
        ion = maxIon + 1
        iokey = suffix(key, ion, sep=sep)

        db.items[iokey] = val
        db.dirty = True
        return True


    def getIoSetItemIter(self, db, key, *, ion=0, sep=b'.'):
        """Get iterator over items in IoSet at effecive key.
        When key is empty then returns empty iterator

        Raises StopIterationError when done.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            items (Iterator): iterator over insertion ordered set
                              items at same apparent effective key.
                              Empty iterator when key is empty

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): Apparent effective key. raises StopIterationError when
                         key is empty
            ion (int): starting ordinal value, default 0
            sep (bytes): separator character for split
        """
        # If empty returns empty iterator
        if not key:
            return iter(())

        # Get the prefix 
        iokey = suffix(key, ion, sep=sep)

        try:
            raw = db.items.irange(minimum=iokey)
        except IndexError:
            return iter(())

        try:
            keys = list(raw)
        except IndexError:
            return iter(())


        # Iterate through items from the starting key
        for iokey in keys:
            ckey, cion = unsuffix(iokey, sep=sep)
            # Stop when we leave this IoSet
            if ckey != key:
                break
            
            yield (ckey, db.items[iokey])


    def getIoSetLastItem(self, db, key, *, sep=b'.'):
        """Gets last added ioset entry item at effective key if any else empty
        tuple.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            last ((bytes, bytes)): last added entry item at apparent
                effective key if any, otherwise empty tuple if no entry at key
                or if key empty

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): Apparent effective key (unsuffixed)
            sep (bytes): separator character for split
        """
        # No key, return empty tuple
        if not key:
            return ()

        # Get the prefix and initialize last
        iokey = suffix(key, 0, sep=sep)
        last = ()

        # Iterate forward and keep the last matching entry
        for iokey in db.items.irange(minimum=iokey):
            
            baseKey, ion = unsuffix(iokey, sep=sep)
            if baseKey != key:
                break

            last = (baseKey, db.items[iokey])

        return last


    def remIoSet(self, db, key, *, sep=b'.'):
        """Removes all set values at apparent effective key.
        When key is empty or None or missing returns False.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            result (bool): True if values were deleted at key.
                           False otherwise including key empty or None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): Apparent effective key
            sep (bytes): separator character for split
        """
        # If no key return false
        if not key:
            return False

        # Get the prefix
        iokey = suffix(key, 0, sep=sep)
        
        # Initialize a list for values to delete
        delVals = []

        # Collect all matching keys
        for iokey in db.items.irange(minimum=iokey):
            ckey, cion = unsuffix(iokey, sep=sep)
            # Stop when we leave this IoSet
            if ckey != key:
                break

            delVals.append(iokey)

        # If no values are found return False
        if not delVals:
            return False

        # Delete them
        for iokey in delVals:
            del db.items[iokey]

        db.dirty = True
        return True


    def remIoSetVal(self, db, key, val=None, *, sep=b'.'):
        """Removes val if any as member of set at key if any.
        When value is None then removes all set members at key
        When key is empty or missing returns False.
        Uses hidden ordinal key suffix for insertion ordering.
           The suffix is suffixed and unsuffixed transparently.

        Because the insertion order of val is not provided must perform a linear
        search over set of values.

        Another problem is that vals may get added and deleted in any order so
        the max suffix ion may creep up over time. The suffix ordinal max > 2**16
        is an impossibly large number, however, so the suffix will not max out
        practically.But its not the most elegant solution.

        In some cases a better approach would be to use getIoSetItemsIter which
        returns the actual iokey not the apparent effective key so can delete
        using the iokey without searching for the value. This is most applicable
        when processing escrows where all the escrowed items are processed linearly
        and one needs to delete some of them in stride with their processing.

        Returns:
            result (bool): True if val at key removed when val not None
                           or all entries at key removed when val None.
                           False otherwise if no values at key or key is empty
                           or val not found.

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): val(int|None): value to remove if any.
                           None means remove all entries at onkey
            val (bytes|None): value to delete
            sep (bytes): separator character for split
        """
        # If val None remove all entries at key
        if val is None:
            return self.remIoSet(db=db, key=key, sep=sep)

        # No-op on empty key
        if not key:
            return False

        # Get prefix and prefix length
        iokey = suffix(key, 0, sep=sep)

        # Iterate for matching value
        for iokey in db.items.irange(minimum=iokey):
            ckey, cion = unsuffix(iokey, sep=sep)
            # Stop when we leave this IoSet
            if ckey != key:
                break

            cval = db.items[iokey]
            if cval == val:
                del db.items[iokey]
                db.dirty = True
                return True

        return False


    def cntIoSet(self, db, key, *, ion=0, sep=b'.'):
        """Count set entries at onkey = key + sep + on for ion >= ion.
        Count beginning with entry at insertion offset ion.
        Count is zero if key not in db or ion greater than whats in set.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            count (int): count values in set at apparent effective key

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): Apparent effective key
            ion (int): starting ordinal value, default 0
            sep (bytes): separator character for split
        """
        if not key:
            return 0

        iokey = suffix(key, ion, sep=sep)

        count = 0

        # Iterate over all keys in prefix range
        for iokey in db.items.irange(minimum=iokey):

            ckey, cion = unsuffix(iokey, sep=sep)

            # Stop when leaving this IoSet
            if ckey != key:
                break

            # Only count ordinals >= ion
            count += 1

        return count


    def getTopIoSetItemIter(self, db, top=b'', *, sep=b'.'):
        """Iterates over top branch of all insertion ordered set values where each
        effective key has hidden suffix of serialization of insertion
        ordering ordinal ion. When top is empty then iterates over whole db.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            items (Iterator[(key,val)]): iterator of tuples (key, val) where
                                         key is apparent key with hidden
                                         insertion ordering suffixe removed
                                         from effective key.

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            top (bytes): truncated top key, a key space prefix to get all the items
                        from multiple branches of the key space. If top key is
                        empty then gets all items in database.
            sep (bytes): sep character for attached io suffix

        Uses python .startswith to match which always returns True if top is
        empty string so empty will matches all keys in db.
        """
        for iokey, val in self.getTopItemIter(db=db, top=top):
            key, ion = unsuffix(iokey, sep=sep)
            yield (key, val)

    
    def getIoSetLastItemIterAll(self, db, key=b'', *, sep=b'.'):
        """Iterates over every last added ioset entry at every effective key
        starting at key greater or equal to key.
        When key is empty then iterates over whole db.

        Raises StopIterationError when done.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            last (Iterator): last added entry item at tuple (key, val)
                             at apparent effective key for all
                             key >= key. When key empty then iterates
                             over all keys in db

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): Apparent effective key
            sep (bytes): separator character for split
        """
        items = db.items

        # Determine starting point
        if not key:
            # Start at the first key in the DB
            try:
                first_key = next(iter(items))
            except StopIteration:
                return iter(())  # empty DB
            startKey = first_key
        else:
            # Start at key.sep.0
            startKey = suffix(key, 0, sep=sep)

        # State for tracking last item per apparent key
        last = None
        currKey = None

        # Iterate forward through the DB
        for iokey in items.irange(startKey, None):
            # Split into (apparent_key, ordinal)
            apparent, ion = unsuffix(iokey, sep=sep)

            # If we moved to a new apparent key, yield the previous one
            if currKey is not None and apparent != currKey:
                if last is not None:
                    yield last
                last = None

            # Update tracking
            currKey = apparent
            last = (apparent, items[iokey])

        # Yield the final group
        if last is not None:
            yield last


    def getIoSetLastIterAll(self, db, key=b'', *, sep=b'.'):
        """Iterates over every last added ioset entry at every effective key
        starting at key greater or equal to key.
        When key is empty then iterates over whole db.

        Raises StopIterationError when done.

        Uses hidden ordinal key suffix for insertion ordering.
            The suffix is suffixed and unsuffixed transparently.

        Returns:
            last (Iterator): last added entry val at apparent effective
                        key for all key >= key. When key empty then iterates
                        over all keys in db

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): Apparent effective key
            sep (bytes): separator character for split
        """
        for key, val in self.getIoSetLastItemIterAll(db=db, key=key, sep=sep):
            yield val


    # methods for OnIoSet that adds IoSet key suffix after On ordinal numbered
    # tail to support external ordinal order key space with hidden insertion ordered
    # sets of values at each effective key.

    # this is so we do the suffix add/strip here not in some higher level class
    # like suber

    def putOnIoSetVals(self, db, key, *, on=0, vals=None, sep=b'.'):
        """Add idempotently each val from list of bytes vals to set of entries
        at onkey = key + sep + on.  Does not add if key is empty or None
        Each unique entry in set at each on is serialized in db in insertion order
        using hidden IO suffix for each onkey.

        Returns:
            result (bool): True if any val in vals is added to set.
                           False otherwise including key not in db, empty or None
                           or vals empty or None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): base key
            on (int): ordinal number to add to key form onkey
            vals (NonStrIterable|None): serialized values to add to set of vals at
                                    effective key if any. None returns False
            sep (bytes): separator character for split

        Set of values at a given effective key preserve insertion order.
        Because lmdb is lexocographic an insertion ordering suffix is appended to
        all keys that makes lexocographic order the same as insertion order.

        Suffix is 33 characters long consisting of sep '.' followed by 32 char
        hex string for essentially unlimited number of values in each set
        only limited by memory.

        With appended suffix ordinal must explicity check for duplicate values
        in set before insertion. Uses a python set for the duplicate inclusion test.
        Set inclusion scales with O(1) whereas list inclusion scales with O(n).

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        if not key:
            return False
        return self.putIoSetVals(db=db,
                                 key=onKey(key, on, sep=sep),
                                 vals=vals, sep=sep)


    def pinOnIoSetVals(self, db, key, *, on=0, vals=None, sep=b'.'):
        """Replace all vals if any at onkey = key + sep + one with vals as
        insertion ordered set of values all with the same onkey.
        Does not replace if key is empty or None or vals is empty or None

        Returns:
           result (bool): True if vals replaced set.
                          False otherwise including key not in db, empty or None
                          or vals empty or None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): base key
            vals (NonStrIterable|None): serialized values to replace vals at key
            on (int): ordinal number to add to key form onkey
            sep (bytes): separator character for split

        Assumes DB opened with dupsort=False

        Set of values at a given effective key preserve insertion order.
        Because lmdb is lexocographic an insertion ordering suffix is appended to
        all keys that makes lexocographic order the same as insertion order.

        Suffix is 33 characters long consisting of sep '.' followed by 32 char
        hex string for essentially unlimited number of values in each set
        only limited by memory.

        With appended suffix ordinal must explicity check for duplicate values
        in set before insertion. Uses a python set for the duplicate inclusion test.
        Set inclusion scales with O(1) whereas list inclusion scales with O(n).

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        if not key:
            return False
        return self.pinIoSetVals(db=db, key=onKey(key, on, sep=sep), vals=vals, sep=sep)


    def appendOnIoSetVals(self, db, key, vals, *, sep=b'.'):
        """Appends set vals in order after last previous onkey = key + sep + on
        as new entry at at new onkey. New on for new onkey is one greater than
        last prior on for given key in db.
        The onkey of the appended entry is one greater than last prior on for
        key in db.

        Returns:
            on (int): ordinal number of new onkey for newly appended set of vals.
                    Raises ValueError when unsuccessful append including when
                    key is empty or None or vals is empty or None

        Parameters:
            db (SubDb): named sub db
            key (bytes): key within sub db's keyspace plus trailing part on
            vals (NonStrIterable): values to append as set at new on
            sep (bytes): separator character for split

        Starts at onkey = key + MaxOn and then walks backwards to find last
        prior entry at key. Then increments on and appends new entry with val
        Otherwise create new zeroth on entry at key.

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        if not key or not vals or not isNonStringIterable(vals):
            raise ValueError(f"Bad append parameter: {key=} or {vals=}")

        # Compute the maximum ON prefix for this key
        maxOnkey = onKey(key, on=MaxON, sep=sep)
        maxIokey = suffix(maxOnkey, ion=MaxON, sep=sep)

        items = db.items

        # 1. Find the last key <= maxIokey

        # irange with maximum gives us all keys <= maxIokey
        # The last of those is the LMDB cursor.last() equivalent.
        lastIokey = next(items.irange(maximum=maxIokey, reverse=True), None)

        if lastIokey is None:
            # No entries at all → ON = 0
            on = 0
        else:
            lastOnkey, _ = unsuffix(lastIokey, sep=sep)
            lastKey, lastOn = splitOnKey(lastOnkey, sep=sep)

            if lastKey == key:
                # Same logical key
                if lastOn == MaxON:
                    raise ValueError(
                        f"Failed append entry to {key=}, would exceed max on at {MaxON=}"
                    )
                on = lastOn + 1
            else:
                # Last key belongs to a different logical key -> ON = 0
                on = 0

        # 2. Insert new ON-group 

        onkey = onKey(key, on, sep=sep)

        for ion, val in enumerate(vals):
            iokey = suffix(onkey, ion=ion, sep=sep)
            if iokey in items:
                raise ValueError(
                    f"Failed appending {val=} at {key=} {on=} offset {ion=}."
                )
            items[iokey] = val

        return on


    def addOnIoSetVal(self, db, key, *, on=0, val=None, sep=b'.'):
        """Add val to insertion ordered set of values at onkey = key + on,
        when val not already in set of vals at key and key is not empty or None
        and val is not None.

        Returns:
           result (bool): True if val added to set.
                          False if already in set or key is empty or None or val
                          is None

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes|None): base key
            on (int): ordinal number at which to add to key form effective key
            val (bytes|None): serialized value to add
            sep (bytes): separator character for split

        With appended suffix ordinal must explicity check for duplicate values
        in set before insertion. Uses a python set for the duplicate inclusion test.
        Set inclusion scales with O(1) whereas list inclusion scales with O(n).

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        # val of None will return False
        return self.addIoSetVal(db=db, key=onKey(key, on, sep=sep), val=val, sep=sep)


    def getOnIoSetItemIter(self, db, key, *, on=0, ion=0, sep=b'.'):
        """Get iterator of all set vals at onkey = key + sep + on in db starting
        at insertion order ion within set This provides ordinal ordering of
        keys and inserion ordering of set vals.
        When key is empty then returns empty iterator

        Returns:
            ioset (Iterator): iterator over insertion ordered set of values
                             at same apparent effective key made from key + on.
                             Uses hidden ordinal key suffix for insertion ordering.
                             The suffix is appended and stripped transparently.
                             When key is empty then returns empty iterator

        Raises StopIteration Error when empty.

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): base key. When key is empty then returns empty iterator
            on (int): ordinal number at which to add to key form effective key
            ion (int): starting insertion ordinal value, default 0
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        for onkey, val in self.getIoSetItemIter(db=db,
                                         key=onKey(key, on, sep=sep),
                                         ion=ion,
                                         sep=sep):
            k, o = splitOnKey(onkey, sep=sep)
            yield (k, o, val)


    def getOnIoSetLastItem(self, db, key, on=0, *, sep=b'.'):
        """Gets item (key, val) of last member of the insertion ordered set
        at key + sep + on

        Returns:
            last (tuple[tuple, int, str]): last set item triple at onkey
                 (keys, on, val)
                 Empty tuple () if onkey not in db or key empty.

        Parameters:
            db (SubDb): named sub db
            key (bytes): key within sub db's keyspace plus trailing part on
                when key is empty then retrieves whole db
            on (int): ordinal number at which to initiate retrieval
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        if last := self.getIoSetLastItem(db=db,
                                         key=onKey(key, on, sep=sep),
                                         sep=sep):
            onkey, val = last
            key, on = splitOnKey(onkey, sep=sep)
            return (key, on, val)
        return ()


    def remOnIoSetVal(self, db, key, *, on=0, val=None, sep=b'.'):
        """Removes val if any as member of set at onkey = key + sep + on.
        When val is None then removes all set members at onkey.
        When key is empty or None or missing returns False.

        Uses hidden ordinal key suffix for insertion ordering.
        The suffix is suffixed and unsuffixed transparently.

        Because the insertion order of val is not provided must perform a linear
        search over set of values.

        Another problem is that vals may get added and deleted in any order so
        the max suffix ion may creep up over time. The suffix ordinal max > 2**16
        is an impossibly large number, however, so the suffix will not max out
        practically.But its not the most elegant solution.

        In some cases a better approach would be to use getIoSetItemsIter which
        returns the actual iokey not the apparent effective key so can delete
        using the iokey without searching for the value. This is most applicable
        when processing escrows where all the escrowed items are processed linearly
        and one needs to delete some of them in stride with their processing.

        Returns:
            result (bool): True if val at onkey removed when val not None
                           or all entries at onkey removed when val None.
                           False otherwise if no values at onkey or key is empty
                           or val not found.

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): base key. When key is empty returns False
            on (int): ordinal number at which to add to key form effective key
            val(int|None): value to remove if any.
                           None means remove all entries at onkey
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        return self.remIoSetVal(db, key=onKey(key, on, sep=sep), val=val, sep=sep)


    def remOnAllIoSet(self, db, key=b"", on=0, *, sep=b'.'):
        """Removes all set members at onkey for all on >= on where for each on,
        onkey = key + sep + on
        When on is 0, default, then deletes all on at key.
        When key is empty then deletes whole db.

        Returns:
           result (bool): True if any entries deleted
                          False otherwise

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): base key
            on (int): ordinal number at which to add to key form effective key
                      0 means to delete all on
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        items = db.items

        # If key empty then delete whole DB
        if not key:
            return self.remTop(db=db, top=b'')

        # Compute starting ON-key
        startOnkey = onKey(key, on, sep=sep)

        # We need to scan from the first ON >= on
        # That means: all keys >= startOnkey
        toDelete = []

        for iokey in items.irange(minimum=startOnkey):
            # Extract (key, on, ion)
            onkey, ion = unsuffix(iokey, sep=sep)
            ckey, con = splitOnKey(onkey, sep=sep)

            # Stop when we leave this logical key
            if ckey != key:
                break

            # This ON >= requested ON so add it to delete
            toDelete.append(iokey)

        # Perform deletions
        result = False
        for iokey in toDelete:
            del items[iokey]
            result = True

        return result


    def cntOnIoSet(self, db, key, *, on=0, ion=0, sep=b'.'):
        """Count set values at onkey made from onkey = key + on starting at
        ion offset within set at onkey.
        Count = 0 if onkey not in db.

        Returns:
            count (int): count values in set at effective onkey

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): base key
            on (int|None): ordinal number at which to add to key form onkey
            ion (int): starting ordinal value, default 0
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        return self.cntIoSet(db=db, key=onKey(key, on, sep=sep), ion=ion, sep=sep)


    def cntOnAllIoSet(self, db, key=b"", *, on=0, sep=b'.'):
        """Counts all entries of each set at each onkey for all on >= on
        where for each on, onkey = key + sep + on.
        Count includes all set members at all matching onkeys.
        When on = 0, default, then count all set members for all on for key
        When key is empty then count all on for all key i.e. whole db

        Returns:
            count (int): count of set members for onkey for on >= on. When on is
                         None then count of all on for key. When key is empty
                         then count of all on for all key for whole db.

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            key (bytes): base key
            on (int): ordinal number at which to add to key form onkey
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        """
        items = db.items

        # If key empty so count whole DB
        if not key:
            return self.cntAll(db)

        # Compute starting ON-key
        startOnkey = onKey(key, on, sep=sep)

        count = 0

        # Iterate from first ON >= on
        for iokey in items.irange(minimum=startOnkey):
            # Extract (key, on, ion)
            onkey, ion = unsuffix(iokey, sep=sep)
            ckey, con = splitOnKey(onkey, sep=sep)

            # Stop when we leave this logical key
            if ckey != key:
                break

            count += 1

        return count


    def getOnTopIoSetItemIter(self, db, top=b'', *, sep=b'.'):
        """Iterates over top branch of all insertion ordered set values where
        each key startwith top. When top is empty then iterates over whole db.
        Assumes every effective key in db has trailing on element,
        onkey = key + sep + on, so can return on in item.
        Also assumes every effective key includes hiddion insertion ordinal ion
        suffix that is suffixed and unsuffixed transparently.

        Items are triples of (keys, on, val)

        Returns:
            items (Iterator[(str, int, bytes)]): iterator of triples (key, on, val)
                where key base key, on is int, and val is entry value of
                with insertion ordering suffix removed from effective key.

        Parameters:
            db (SubDb): instance of named sub db with dupsort==False
            top (bytes): truncated top key, a key space prefix to get all the items
                        from multiple branches of the key space. If top key is
                        empty then gets all items in database.
            key (bytes): base key
            sep (bytes): separator character for split

        Uses python .startswith to match which always returns True if top is
        empty string so empty will matches all keys in db.

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        for onkey, val in self.getTopIoSetItemIter(db=db, top=top, sep=sep):
            key, on = splitOnKey(onkey, sep=sep)
            yield (key, on, val)

            
    def getOnAllIoSetItemIter(self, db, key=b'', on=0, *, sep=b'.'):
        """Iterates over each item of each set for all on >= on for key.
        When on == 0, default, then iterates over all items for all on for key.
        When key is empty then iterates over all items for whole db.

        Each effecive onkey = key + sep + on.
        Items are triples of (key, on, val)

        Entries are sorted by onKey(key, on) where on
        is ordinal number int and key is prefix sans on.

        The set at each entry is sorted internally by hidden suffixed insertion
        ordering ordinal

        Raises StopIteration Error when done.

        Returns:
            items (Iterator[(key, int, bytes)]): iterator of triples
                (key, on, val)
                where key forms base key, on is int, and val is entry value at
                with insertion ordering suffix removed from effective key.

        Parameters:
            db (SubDb): named sub db
            key (bytes): key within sub db's keyspace plus trailing part on
                when key is empty then retrieves whole db
            on (int): ordinal number at which to initiate retrieval
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        items = db.items

        # Case 1: key empty so iterate whole DB
        if not key:
            yield from self.getOnTopIoSetItemIter(db=db, top=b'', sep=sep)
            return

        # Case 2: iterate ON >= requested ON for this key
        startOnkey = onKey(key, on, sep=sep)
        startIokey = suffix(startOnkey, ion=0, sep=sep)

        for iokey in items.irange(minimum=startIokey):
            # Extract (onkey, ion)
            onkey, ion = unsuffix(iokey, sep=sep)

            # Extract (ckey, con)
            ckey, con = splitOnKey(onkey, sep=sep)

            # Stop when we leave this logical key
            if ckey != key:
                break

            # Yield LMDB‑accurate triple
            yield (ckey, con, items[iokey])


    def getOnAllIoSetLastItemIter(self, db, key=b'', on=0, *, sep=b'.'):
        """Iterates over last items of each set for all on >= on at key
        When on ==0, default, iterates over last items of each set for all on at key
        When key is empty then iterates over last items of all sets  in whole db

        Each effecive onkey = key + sep + on.
        Items are triples of (key, on, val)

        Entries are sorted by onKey(key, on) where on
        is ordinal number int and key is prefix sans on.

        The set at each entry is sorted internally by hidden suffixed insertion
        ordering ordinal

        Raises StopIteration Error when done.

        Returns:
            last (Iterator[(bytes, int, bytes)]): triples of (key, on, val)

        Parameters:
            db (SubDb): named sub db
            key (bytes): base key, empty defaults to whole database
            on (int): ordinal number at which to initiate retrieval
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        items = db.items

        # Case 1: key empty so delegate to top-level iterator
        if not key:
            for onkey, val in self.getIoSetLastItemIterAll(db=db, key=b'', sep=sep):
                key, on = splitOnKey(onkey, sep=sep)
                yield (key, on, val)
            return

        # Case 2: iterate ON >= requested ON for this key
        startOnkey = onKey(key, on, sep=sep)
        startIokey = suffix(startOnkey, ion=0, sep=sep)

        last = None
        currentOn = None

        for iokey in items.irange(minimum=startIokey):
            # Extract (conkey, cion)
            conkey, cion = unsuffix(iokey, sep=sep)

            # Extract (ckey, con)
            ckey, con = splitOnKey(conkey, sep=sep)

            # Stop when we leave this logical key
            if ckey != key:
                break

            # If ON changes, yield the last item of the previous ON
            if currentOn is not None and con != currentOn:
                yield last
                last = None

            # Update tracking
            currentOn = con
            last = (ckey, con, items[iokey])

        # After iteration, yield the last ON-group's last item
        if last:
            yield last


    def getOnAllIoSetItemBackIter(self, db, key=b"", on=None, *, sep=b'.'):
        """Iterates backwards over all set items for all on <= on for key.
        When on is None, iterates backwards over all set items for all on for key
        When key is empty then iterates backwards over whole db

        Returned items are triples of (key, on, val)

        Raises StopIterationError when done or when key empty or None

        Backwards means decreasing numerical value of ion, for each on and
        decreasing numerical value on for each key and decreasing lexocographic
        order of each key.

        Returns:
            items (Iterator[(bytes, int, bytes)]): triples of (key, on, val)

        Parameters:
            db (SubDb): named sub db
            key (bytes): base key. When empty then whole db
            on (int|None): ordinal number at which to initiate retrieval
                           when on is None then all on starting at greatest
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        items = db.items

        # Empty DB so nothing
        if not items:
            return
            yield  # make generator

        # Case 1: key empty so iterate whole DB backwards
        if not key:
            for ciokey in items.irange(reverse=True):
                conkey, cion = unsuffix(ciokey, sep=sep)
                ckey, con = splitOnKey(conkey, sep=sep)
                yield (ckey, con, items[ciokey])
            return

        # Case 2: key non-empty

        # Determine starting ON
        if on is None:
            on = MaxON

        # Build upper-bound search key
        onkey = onKey(key, on, sep=sep)
        iokey = suffix(onkey, ion=MaxON, sep=sep)

        # Collect all matching entries up to this bound
        candidates = []
        for ciokey in items.irange(maximum=iokey, reverse=True):
            conkey, cion = unsuffix(ciokey, sep=sep)
            ckey, con = splitOnKey(conkey, sep=sep)

            # Must match logical key
            if ckey != key:
                continue

            # Must satisfy ON <= requested ON
            if con > on:
                continue

            yield (ckey, con, items[ciokey])


    def getOnAllIoSetLastItemBackIter(self, db, key=b"", on=None, *, sep=b'.'):
        """Iterates backwards over last set items for all on <= on for key.
        When on is None iterates backwards over last set items for all on for key
        When key is empty then iterates backwards over last set items for whole db
        starting at last item in db

        Returned items are triples of (key, on, val)

        Raises StopIterationError when done or when key empty or None

        Backwards means decreasing numerical value of each ion, for each on and
        decreasing numerical value of each on for each key and decreasing lexocographic
        value of each key.

        Returns:
            items (Iterator[(bytes, int, bytes)]): triples of (key, on, val)

        Parameters:
            db (SubDb): named sub db
            key (bytes): base key. When empty then whole db
            on (int|None): ordinal number at which to initiate retrieval
                           when on is None then all on starting at greatest
            sep (bytes): separator character for split

        Uses hidden ordinal key suffix for insertion ordering which is
        transparently suffixed and unsuffixed
        Assumes DB opened with dupsort=False
        """
        items = db.items

        # Empty DB do nothing
        if not items:
            return
            yield  # make generator

        # Case 1: key empty do whole DB backwards 
        if not key:
            # We must yield the *last item of each ON-group* for all keys, backwards.
            #   1. Walk all items backwards
            #   2. Detect ON-group boundaries
            #   3. Yield only the last item of each ON-group
            last = None
            lkey = None
            lon = None

            for ciokey in items.irange(reverse=True):
                conkey, cion = unsuffix(ciokey, sep=sep)
                ckey, con = splitOnKey(conkey, sep=sep)
                cval = items[ciokey]

                if last is None:
                    # First item encountered (largest key/on/ion)
                    last = (ckey, con, cval)
                    lkey = ckey
                    lon = con
                    continue

                # New key so yield previous ON-group's last item
                if ckey != lkey:
                    yield last
                    last = (ckey, con, cval)
                    lkey = ckey
                    lon = con
                    continue

                # Same key, new ON so yield previous ON-group's last item
                if con != lon:
                    yield last
                    last = (ckey, con, cval)
                    lkey = ckey
                    lon = con
                    continue

                # Same key, same ON so keep scanning backward

            # Yield final group
            if last:
                yield last

            return


        # Case 2: key non-empty 

        # Determine starting ON
        if on is None:
            on = MaxON

        # Build upper-bound search key
        onkey = onKey(key, on, sep=sep)
        iokey = suffix(onkey, ion=MaxON, sep=sep)

        lcon = None
        lval = None

        # Collect all matching entries up to this bound
        for ciokey in items.irange(maximum=iokey, reverse=True):
            conkey, cion = unsuffix(ciokey, sep=sep)
            ckey, con = splitOnKey(conkey, sep=sep)

            # Must match logical key
            if ckey != key:
                continue

            # Must satisfy ON <= requested ON
            if con > on:
                continue

            cval = items[ciokey]

            if lcon is None:
                # First matching ON-group
                lcon, lval = con, cval
                continue

            # New ON-group so yield previous ON-group's last item
            if con != lcon:
                yield (key, lcon, lval)
                lcon, lval = con, cval
                continue
        
        if lcon is not None:
            yield (key, lcon, lval)


    #  End OnIoSet support methods


def _serialize_records(records: dict | Any) -> str:
    """Serialize a bytes->bytes map as JSON with hex-encoded keys and values.

    Hex encoding doubles the byte size (1 KB value -> ~2.1 KB in JSON) but
    browser IndexedDB handles strings natively, not ArrayBuffer, so this is
    the simplest correct representation for PyScript storage.
    """
    return json.dumps({key.hex(): val.hex() for key, val in records.items()}, sort_keys=True)


def _serialize_meta(meta: dict[str, Any]) -> str:
    return json.dumps(meta, sort_keys=True)


def _iterOnItems(
    *,
    db: SubDb,
    key: bytes | None = None,
    on: int = 0,
    sep: bytes = b".",
) -> Iterator[tuple[bytes, int, bytes]]:
    """
    Get iterator of triples `(key, on, val)` at each base key over all ordinal
    numbered keys with same `key` and `on >= on`.
    When `on = 0`, default, then iterates over all `on` at `key`.
    When `key` is `None` then iterates over all `on` for all keys in whole db.
    Returned items are triples of `(key, on, val)`.

    Entries are sorted by `onKey(key, on)` where `on` is ordinal number int
    and `key` is prefix sans `on`.

    Returns:
        items (Iterator[tuple[bytes, int, bytes]]): triples of `(key, on, val)`
            for `onkey = key + sep + on` for `on >= on` at `key`. When `key`
            is `None` iterates over the whole sub db.

    Parameters:
        db (SubDb): named browser-backed sub db whose effective keys are
            ordinal keys.
        key (bytes | None): base key. `None` means whole sub db.
        on (int): ordinal number at which to initiate retrieval.
        sep (bytes): separator character for split.

    Raises:
        ValueError: If an encountered effective key in `db` is not splittable
            as an ordinal key with the provided separator.
    """
    start = onKey(key, on, sep=sep) if key else b""

    # Fixed-width ordinal suffixes make lexical order match ordinal order.
    for okey in db.items.irange(minimum=start):
        ckey, cn = splitOnKey(okey, sep=sep)
        if key and ckey != key:
            break
        yield ckey, cn, db.items[okey]


def _deserialize_records(raw: Any) -> dict[bytes, bytes]:
    if raw in (None, ""):
        return {}
    if isinstance(raw, (bytes, memoryview)):
        raw = bytes(raw).decode("utf-8")
    if isinstance(raw, str):
        payload = json.loads(raw)
    elif isinstance(raw, dict):
        payload = raw
    else:
        raise TypeError(f"Unsupported persisted record payload type: {type(raw)}")

    return {
        bytes.fromhex(str(key_hex)): bytes.fromhex(str(val_hex))
        for key_hex, val_hex in payload.items()
    }


def _deserialize_meta(raw: Any) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    if isinstance(raw, (bytes, memoryview)):
        raw = bytes(raw).decode("utf-8")
    if isinstance(raw, str):
        payload = json.loads(raw)
    elif isinstance(raw, dict):
        payload = raw
    else:
        raise TypeError(f"Unsupported persisted metadata payload type: {type(raw)}")

    if not isinstance(payload, dict):
        raise TypeError(f"Unsupported persisted metadata payload type: {type(payload)}")

    return dict(payload)


class statedict(dict):
    """
    Subclass of dict that has db as attribute and employs read through cache
    from db Baser.stts of kever states to reload kever from state in database
    when not found in memory as dict item.
    """
    __slots__ = ('db')  # no .__dict__ just for db reference

    def __init__(self, *pa, **kwa):
        super(statedict, self).__init__(*pa, **kwa)
        self.db = None

    def __getitem__(self, k):
        try:
            return super(statedict, self).__getitem__(k)
        except KeyError as ex:
            if not self.db:
                raise ex  # reraise KeyError
            if (ksr := self.db.states.get(keys=k)) is None:
                raise ex  # reraise KeyError
            try:
                from ..core.eventing import Kever
                kever = Kever(state=ksr, db=self.db)
            except MissingEntryError:  # no kel event for keystate
                raise ex  # reraise KeyError
            self.__setitem__(k, kever)
            return kever

    def __contains__(self, k):
        if not super(statedict, self).__contains__(k):
            try:
                self.__getitem__(k)
                return True
            except KeyError:
                return False
        else:
            return True

    def get(self, k, default=None):
        """Override of dict get method

        Parameters:
            k (str): key for dict
            default: default value to return if not found

        Returns:
            kever: converted from underlying dict or database

        """
        if not super(statedict, self).__contains__(k):
            return default
        else:
            return self.__getitem__(k)


class WebBaser(WebDBer):
    def __init__(self, name="main", reopen=False, **kwa):
        """
        Setup named sub databases.

        Parameters:
            name is str directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp is boolean, assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath is optional str head directory pathname for main database
                If not provided use default .HeadDirpath
            mode is int numeric os dir permissions for database directory
            reopen (bool): True means database will be reopened by this init


        """
        SubDbNames = [
            "evts.", "sigs.", "wigs.", "dtss.", "aess.", "rcts.", "vrcs.", "vres.",
            "kels.", "fels.", "ooes.", "pses.", "dels.", "ldes.",
            "ures.", "esrs.", "states.", "habs.", "names.",
            "imgs.", "iimgs.",
        ]
        self.SubDbNames = SubDbNames

        self.prefixes = oset()  # should change to hids for hab ids
        self.groups = oset()  # group hab ids
        self._kevers = statedict()
        self._kevers.db = self  # assign db for read through cache of kevers

        self.name = name
        self.opened = False

        # Store reopen flag (async)
        self._should_reopen = reopen

    @property
    def kevers(self):
        """
        Returns .db.kevers
        """
        return self._kevers

    async def reopen(self, clear=False, storageOpener=None):
        self.db = await WebDBer.open(
            name=self.name,
            stores=self.SubDbNames,
            clear=clear,
            storageOpener=storageOpener,
        )

        self.env = self.db.env

        self._bindSubDbs()
        self.reload()
        self.opened = True


    async def close(self, *, clear: bool = False):
            """
            Flush pending writes and optionally clear backing storage.

            In a browser environment, "clear" is typically used only for tests or
            explicit reset flows.
            """

            if not self.opened or self.db is None:
                return

            await self.db.flush()

            if clear:
                await self._clearIndexedDB()

            self.db = None
            self.env = None
            self.opened = False

    
    async def _clearIndexedDB(self):
        """
        Clear all backing storage namespaces for this baser.

        Each SubDb in WebDBer has a `handle` that behaves like a dict-like
        IndexedDB wrapper. Clearing the handle removes all persisted records.
        """
        if self.db is None:
            return

        # Clear each store's persisted payload
        for subdb in self.db._stores.values():
            handle = subdb.handle
            handle.clear()        # remove all keys from IndexedDB
            await handle.sync()   # persist the deletion


    def _bindSubDbs(self):
        from . import koming, subing
        from ..core import coring, indexing

        self.evts = subing.SerderSuber(db=self, subkey='evts.')
        self.sigs = subing.CesrIoSetSuber(db=self, subkey='sigs.', klas=(indexing.Siger))
        self.wigs = subing.CesrIoSetSuber(db=self, subkey='wigs.', klas=(indexing.Siger))
        self.dtss = subing.CesrSuber(db=self, subkey='dtss.', klas=coring.Dater)
        self.aess = subing.CatCesrSuber(db=self, subkey='aess.', klas=(coring.Number, coring.Diger))
        self.rcts = subing.CatCesrIoSetSuber(db=self, subkey='rcts.',
                                            klas=(coring.Prefixer, coring.Cigar))
        self.vrcs = subing.CatCesrIoSetSuber(db=self, subkey='vrcs.',
                                            klas=(coring.Prefixer, coring.Number, coring.Diger, indexing.Siger))
        self.vres = subing.CatCesrIoSetSuber(db=self, subkey='vres.',
                        klas=(coring.Diger, coring.Prefixer, coring.Number, coring.Diger, indexing.Siger))
        self.kels = subing.OnIoSetSuber(db=self, subkey='kels.')
        self.fels = subing.OnSuber(db=self, subkey='fels.')
        self.ooes = subing.OnIoSetSuber(db=self, subkey='ooes.')
        self.pses = subing.OnIoSetSuber(db=self, subkey='pses.')
        self.dels = subing.OnIoSetSuber(db=self, subkey='dels.')
        self.ldes = subing.OnIoSetSuber(db=self, subkey='ldes.')
        self.ures = subing.CatCesrIoSetSuber(db=self, subkey='ures.',
                                            klas=(coring.Diger, coring.Prefixer, coring.Cigar))

        self.esrs = koming.Komer(db=self, subkey='esrs.', klas=EventSourceRecord)
        self.states = koming.Komer(db=self, subkey='states.', klas=KeyStateRecord)
        self.habs = koming.Komer(db=self, subkey='habs.', klas=HabitatRecord)
        self.names = subing.Suber(db=self, subkey='names.', sep="^")

        self.imgs = subing.CesrSuber(db=self, subkey='imgs.')
        self.iimgs = subing.CesrSuber(db=self, subkey='iimgs.')


    def reload(self):
        self.prefixes.clear()
        self.groups.clear()
        self._kevers.clear()

        for keys, hab in self.habs.getTopItemIter():
            state = self.states.get(keys=hab.hid)
            if state is None:
                continue

            try:
                from ..core.eventing import Kever
                kever = Kever(state=state, db=self, local=True)
            except Exception:
                continue

            self._kevers[kever.prefixer.qb64] = kever
            self.prefixes.add(kever.prefixer.qb64)

            if hab.mid:
                self.groups.add(hab.hid)


    
    def migrate(self):
        """ Run all migrations required

        Run all migrations  that are required from the current version of database up to the current version
         of the software that have not already been run.

         Sets the version of the database to the current version of the software after successful completion
         of required migrations

        """
        from ..core import coring

        escrows_cleared = False

        for (version, migrations) in MIGRATIONS:
            # Only run migration if current source code version is at or below the migration version
            ver = semver.VersionInfo.parse(keri.__version__)
            ver_no_prerelease = semver.Version(ver.major, ver.minor, ver.patch)
            if self.version is not None and semver.compare(version, str(ver_no_prerelease)) > 0:
                print(
                    f"Skipping migration {version} as higher than the current KERI version {keri.__version__}")
                continue
            # Skip migrations already run - where version less than (-1) or equal to (0) database version
            # Strip prerelease from DB version to avoid lexicographic comparison bugs (#820)
            if self.version is not None and semver.compare(version, _strip_prerelease(self.version)) != 1:
                continue

            # Clear all escrows before first migration to prevent old key
            # format crashes (e.g. qnfs keys without insertion-order suffix).
            # Uses .trim() which bypasses key parsing. See #863.
            if not escrows_cleared:
                self._trimAllEscrows()
                escrows_cleared = True

            print(f"Migrating database v{self.version} --> v{version}")
            for migration in migrations:
                modName = f"keri.db.migrations.{migration}"
                if self.migs.get(keys=(migration,)) is not None:
                    continue

                mod = importlib.import_module(modName)
                try:
                    print(f"running migration {modName}")
                    mod.migrate(self)
                except Exception as e:
                    print(f"\nAbandoning migration {migration} at version {version} with error: {e}")
                    return

                self.migs.pin(keys=(migration,), val=coring.Dater())

            # update database version after successful migration
            self.version = version

        self.version = keri.__version__

    
    def _trimAllEscrows(self):
        """Trim all escrow databases via low-level .trim().

        Safe for old key formats that would crash higher-level iterators
        (e.g., qnfs keys without insertion-order suffix from pre-1.2.0).
        Called at the beginning of migration per spec call guidance.
        See: https://github.com/WebOfTrust/keripy/issues/863
        """
        escrows = [
            self.ures, self.vres, self.pses, self.pwes, self.ooes,
            self.qnfs, self.uwes, self.misfits, self.delegables,
            self.pdes, self.udes, self.rpes, self.ldes, self.epsd,
            self.eoobi, self.dpub, self.gpwe, self.gdee, self.dpwe,
            self.gpse, self.epse, self.dune,
        ]
        total = 0
        for escrow in escrows:
            count = escrow.cnt()
            if count > 0:
                escrow.trim()
                total += count
        if total > 0:
            print(f"Cleared {total} escrow entries before migration")

    def clearEscrows(self):
        """
        Clear all escrows
        """
        for escrow in [self.ures, self.vres, self.pses, self.pwes, self.ooes,
                       self.qnfs, self.uwes,
                       self.qnfs, self.misfits, self.delegables, self.pdes,
                       self.udes, self.rpes, self.ldes, self.epsd, self.eoobi,
                       self.dpub, self.gpwe, self.gdee, self.dpwe, self.gpse,
                       self.epse, self.dune]:
            count = escrow.cntAll()
            escrow.trim()
            logger.info(f"KEL: Cleared {count} escrows from ({escrow}")

    @property
    def current(self):
        """ Current property determines if we are at the current database migration state.

         If the database version matches the library version return True
         If the current database version is behind the current library version, check for migrations
            - If there are migrations to run, return False
            - If there are no migrations to run, reset database version to library version and return True
         If the current database version is ahead of the current library version, raise exception

         """
        if self.version == keri.__version__:
            return True

        ver = semver.VersionInfo.parse(keri.__version__)
        ver_no_prerelease = semver.Version(ver.major, ver.minor, ver.patch)
        # Strip prerelease from DB version to avoid lexicographic comparison bugs (#820)
        if self.version is not None and semver.compare(_strip_prerelease(self.version), str(ver_no_prerelease)) == 1:
            raise ConfigurationError(
                f"Database version={self.version} is ahead of library version={keri.__version__}")

        last = MIGRATIONS[-1]
        # If we aren't at latest version, but there are no outstanding migrations,
        # reset version to latest (rightmost (-1) migration is latest)
        if self.migs.get(keys=(last[1][-1],)) is not None:
            return True

        # We have migrations to run
        return False

    def complete(self, name=None):
        """ Returns list of tuples of migrations completed with date of completion

        Parameters:
            name(str): optional name of migration to check completeness

        Returns:
            list: tuples of migration,date of completed migration names and the date of completion

        """
        migrations = []
        if not name:
            for version, migs in MIGRATIONS:
                # Print entries only for migrations that have been run
                # Strip prerelease from DB version to avoid lexicographic comparison bugs (#820)
                if self.version is not None and semver.compare(version, _strip_prerelease(self.version)) <= 0:
                    for mig in migs:
                        dater = self.migs.get(keys=(mig,))
                        migrations.append((mig, dater))
        else:
            for version, migs in MIGRATIONS:  # check all migrations for each version
                if name not in migs or not self.migs.get(keys=(name,)):
                    raise ValueError(f"No migration named {name}")
            migrations.append((name, self.migs.get(keys=(name,))))

        return migrations
    
    async def _replaceIndexedDB(self, clean):
        """
        Replace this WebBaser's IndexedDB database with the clean clone.

        Steps:
        1. Close both DBs
        2. Delete the old IndexedDB database
        3. Rename the clean DB to the original name
        4. Reopen this WebBaser
        """

        old_name = self.name
        new_name = clean.name

        # 1. Close both DBs (flush + close IDB connections)
        await self.close()
        await clean.close()

        # 2. Delete the old IndexedDB database
        #    Equivalent to LMDB's: rm -rf old
        delete_req = indexedDB.deleteDatabase(old_name)
        await delete_req

        # 3. Rename clean DB to original name
        #    IndexedDB has no rename primitive, so we:
        #    - open clean DB under old_name
        #    - copy all object stores
        #    - delete the clean DB
        open_req = indexedDB.open(new_name)
        clean_db = await open_req

        # Create new DB under old_name
        open_req2 = indexedDB.open(old_name)
        new_db = await open_req2

        # Copy all object stores from clean_db → new_db
        for store_name in clean_db.objectStoreNames:
            if store_name not in new_db.objectStoreNames:
                version = new_db.version + 1
                new_db.close()
                upgrade_req = indexedDB.open(old_name, version)
                new_db = await upgrade_req
                new_db.createObjectStore(store_name)

            tx_src = clean_db.transaction(store_name, "readonly")
            tx_dst = new_db.transaction(store_name, "readwrite")

            src_store = tx_src.objectStore(store_name)
            dst_store = tx_dst.objectStore(store_name)

            get_all_req = src_store.getAll()
            values = await get_all_req

            get_keys_req = src_store.getAllKeys()
            keys = await get_keys_req

            for key, val in zip(keys, values):
                dst_store.put(val, key)

            await tx_dst.done

        clean_db.close()

        # Delete the temporary clean DB
        delete_clean_req = indexedDB.deleteDatabase(new_name)
        await delete_clean_req

        # 4. Reopen this WebBaser using the new DB
        await self.reopen()

    async def clean(self):
        """
        Clean WebDB database by cloning into a new WebBaser instance,
        reprocessing events, copying non-event subdbs, and replacing
        the old IndexedDB database.
        """

        from ..core import parsing
        from ..core.eventing import Kevery

        # -------------------------------------------------------------
        # 1. Create a fresh empty WebBaser clone
        # -------------------------------------------------------------
        clean_name = f"{self.name}_clean"
        copy = WebBaser(name=clean_name, headDirPath=self.headDirPath)

        # -------------------------------------------------------------
        # 2. Replay all events into the clean DB
        # -------------------------------------------------------------
        kvy = Kevery(db=copy)
        psr = parsing.Parser(kvy=kvy, version=Vrsn_1_0)

        for msg in self.cloneAllPreIter():
            psr.parseOne(ims=msg)

        # -------------------------------------------------------------
        # 3. Copy non-event subdbs (same logic as LMDB version)
        # -------------------------------------------------------------
        unsecured = [
            "hbys", "schema", "states", "rpys", "eans", "tops", "cgms", "exns",
            "erpy", "kdts", "ksns", "knas", "oobis", "roobi", "woobi", "moobi",
            "mfa", "rmfa", "cfld", "cons", "ccigs", "cdel", "migs",
            "ifld", "sids", "icigs"
        ]

        for name in unsecured:
            src = getattr(self, name, None)
            dst = getattr(copy, name, None)
            if src is None or dst is None:
                continue
            for keys, val in src.getTopItemIter():
                dst.put(keys=keys, val=val)

        # -------------------------------------------------------------
        # 4. Copy set-based subdbs
        # -------------------------------------------------------------
        sets = ["esigs", "ecigs", "epath", "chas", "reps", "wkas", "meids", "maids"]

        for name in sets:
            src = getattr(self, name, None)
            dst = getattr(copy, name, None)
            if src is None or dst is None:
                continue
            for keys, val in src.getTopItemIter():
                dst.add(keys=keys, val=val)

        # -------------------------------------------------------------
        # 5. Copy imgs and iimgs
        # -------------------------------------------------------------
        for keys, val in self.imgs.getTopItemIter():
            copy.imgs.pin(keys=keys, val=val)

        for keys, val in self.iimgs.getTopItemIter():
            copy.iimgs.pin(keys=keys, val=val)

        # -------------------------------------------------------------
        # 6. Clone .habs and .names and prefix/group sets
        # -------------------------------------------------------------
        for keys, val in self.habs.getTopItemIter():
            if val.hid in copy.kevers:  # only copy verified habitats
                copy.habs.put(keys=keys, val=val)
                ns = "" if val.domain is None else val.domain
                copy.names.put(keys=(ns, val.name), val=val.hid)
                copy.prefixes.add(val.hid)
                if val.mid:
                    copy.groups.add(val.hid)

        # -------------------------------------------------------------
        # 7. Clone .ends and .locs
        # -------------------------------------------------------------
        for (cid, role, eid), val in self.ends.getTopItemIter():
            exists = False
            for scheme in ("https", "http", "tcp"):
                lval = self.locs.get(keys=(eid, scheme))
                if lval:
                    exists = True
                    copy.locs.put(keys=(eid, scheme), val=lval)
            if exists:
                copy.ends.put(keys=(cid, role, eid), val=val)

        # -------------------------------------------------------------
        # 8. Replace kevers, prefixes, groups in self with cloned ones
        # -------------------------------------------------------------
        self.kevers.clear()
        for pre, kever in copy.kevers.items():
            self.kevers[pre] = kever

        self.prefixes.clear()
        self.prefixes.update(copy.prefixes)

        self.groups.clear()
        self.groups.update(copy.groups)

        # -------------------------------------------------------------
        # 9. Replace old IndexedDB database with the clean clone
        # -------------------------------------------------------------
        await self._replaceIndexedDB(copy)

        # -------------------------------------------------------------
        # 10. Reopen this WebBaser using the new DB
        # -------------------------------------------------------------
        await self.reopen()


    def clonePreIter(self, pre, fn=0):
        """
        Returns iterator of first seen event messages with attachments for the
        identifier prefix pre starting at first seen order number, fn.
        Essentially a replay in first seen order with attachments

        Parameters:
            pre is bytes of itdentifier prefix
            fn is int fn to resume replay. Earliset is fn=0

        Returns:
           msgs (Iterator): over all items with pre starting at fn
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for keys, fn, dig in self.fels.getAllItemIter(keys=pre, on=fn):
            try:
                msg = self.cloneEvtMsg(pre=pre, fn=fn, dig=dig)
            except Exception:
                continue  # skip this event
            yield msg


    def cloneAllPreIter(self):
        """
        Returns iterator of first seen event messages with attachments for all
        identifier prefixes starting at key. If key == b'' then start at first
        key in databse. Use key to resume replay.
        Essentially a replay in first seen order with attachments of entire
        set of FELs.

        Returns:
           msgs (Iterator): over all items in db

        """
        for keys, fn, dig in self.fels.getAllItemIter(keys=b'', on=0):
            pre = keys[0].encode() if isinstance(keys[0], str) else keys[0]
            try:
                msg = self.cloneEvtMsg(pre=pre, fn=fn, dig=dig)
            except Exception:
                continue  # skip this event
            yield msg


    def cloneEvtMsg(self, pre, fn, dig):
        """
        Clones Event as Serialized CESR Message with Body and attached Foot

        Parameters:
            pre (bytes): identifier prefix of event
            fn (int): first seen number (ordinal) of event
            dig (bytes): digest of event

        Returns:
            bytearray: message body with attachments
        """
        from ..core import coring
        from ..core.counting import Counter, Codens

        msg = bytearray()  # message
        atc = bytearray()  # attachments
        dgkey = dgKey(pre, dig)  # get message
        if not (serder := self.evts.get(keys=(pre, dig))):
            raise MissingEntryError("Missing event for dig={}.".format(dig))
        msg.extend(serder.raw)

        # add indexed signatures to attachments
        if not (sigers := self.sigs.get(keys=dgkey)):
            raise MissingEntryError("Missing sigs for dig={}.".format(dig))
        atc.extend(Counter(code=Codens.ControllerIdxSigs,
                           count=len(sigers), version=Vrsn_1_0).qb64b)
        for siger in sigers:
            atc.extend(siger.qb64b)

        # add indexed witness signatures to attachments
        if wigers := self.wigs.get(keys=dgkey):
            atc.extend(Counter(code=Codens.WitnessIdxSigs,
                               count=len(wigers), version=Vrsn_1_0).qb64b)
            for wiger in wigers:
                atc.extend(wiger.qb64b)

        # add authorizer (delegator/issuer) source seal event couple to attachments
        if (duple := self.aess.get(keys=(pre, dig))) is not None:
            number, diger = duple
            atc.extend(Counter(code=Codens.SealSourceCouples,
                               count=1, version=Vrsn_1_0).qb64b)
            atc.extend(number.qb64b + diger.qb64b)

        # add trans endorsement quadruples to attachments not controller
        # may have been originally key event attachments or receipted endorsements
        if quads := self.vrcs.get(keys=dgkey):
            atc.extend(Counter(code=Codens.TransReceiptQuadruples,
                               count=len(quads), version=Vrsn_1_0).qb64b)
            for pre, snu, diger, siger in quads:    # adapt to CESR
                atc.extend(pre.qb64b)
                atc.extend(snu.qb64b)
                atc.extend(diger.qb64b)
                atc.extend(siger.qb64b)

        # add nontrans endorsement couples to attachments not witnesses
        # may have been originally key event attachments or receipted endorsements
        if coups := self.rcts.get(keys=dgkey):
            atc.extend(Counter(code=Codens.NonTransReceiptCouples,
                               count=len(coups), version=Vrsn_1_0).qb64b)
            for prefixer, cigar in coups:
                atc.extend(prefixer.qb64b)
                atc.extend(cigar.qb64b)

        # add first seen replay couple to attachments
        if not (dater := self.dtss.get(keys=dgkey)):
            raise MissingEntryError("Missing datetime for dig={}.".format(dig))
        atc.extend(Counter(code=Codens.FirstSeenReplayCouples,
                           count=1, version=Vrsn_1_0).qb64b)
        atc.extend(coring.Number(num=fn, code=coring.NumDex.Huge).qb64b)  # may not need to be Huge
        atc.extend(dater.qb64b)

        # prepend pipelining counter to attachments
        if len(atc) % 4:
            raise ValueError("Invalid attachments size={}, nonintegral"
                             " quadlets.".format(len(atc)))
        pcnt = Counter(code=Codens.AttachmentGroup,
                       count=(len(atc) // 4), version=Vrsn_1_0).qb64b
        msg.extend(pcnt)
        msg.extend(atc)
        return msg

    def cloneDelegation(self, kever):
        """
        Recursively clone delegation chain from AID of Kever if one exits.

        Parameters:
            kever (Kever): Kever from which to clone the delegator's AID.

        """
        if kever.delegated and kever.delpre in self.kevers:
            dkever = self.kevers[kever.delpre]
            yield from self.cloneDelegation(dkever)

            for dmsg in self.clonePreIter(pre=kever.delpre, fn=0):
                yield dmsg

    def fetchAllSealingEventByEventSeal(self, pre, seal, sn=0):
        """
        Search through a KEL for the event that contains a specific anchored
        SealEvent type of provided seal but in dict form and is also fully
        witnessed. Searchs from sn forward (default = 0).Searches all events in
        KEL of pre including disputed and/or superseded events.
        Returns the Serder of the first event with the anchored SealEvent seal,
            None if not found


        Parameters:
            pre (bytes|str): identifier of the KEL to search
            seal (dict): dict form of Seal of any type SealEvent to find in anchored
                seals list of each event
            sn (int): beginning sn to search

        """
        from ..core.structing import SealEvent

        if tuple(seal) != SealEvent._fields:  # wrong type of seal
            return None

        seal = SealEvent(**seal)  #convert to namedtuple

        for srdr in self.getEvtPreIter(pre=pre, sn=sn):  # includes disputed & superseded
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == SealEvent._fields:
                    eseal = SealEvent(**eseal)  # convert to namedtuple
                    if seal == eseal and self.fullyWitnessed(srdr):
                        return srdr
        return None

    # use alias here until can change everywhere for  backwards compatibility
    findAnchoringSealEvent = fetchAllSealingEventByEventSeal  # alias

    def fetchLastSealingEventByEventSeal(self, pre, seal, sn=0):
        """
        Search through a KEL for the last event at any sn but that contains a
        specific anchored event seal of namedtuple SealEvent type that matches
        the provided seal in dict form and is also fully witnessed.
        Searchs from provided sn forward (default = 0).
        Searches only last events in KEL of pre so does not include disputed
        and/or superseded events.

        Returns:
            srdr (Serder): instance of the first event with the matching
                           anchoring SealEvent seal,
                        None if not found

        Parameters:
            pre (bytes|str): identifier of the KEL to search
            seal (dict): dict form of Seal of any type SealEvent to find in anchored
                seals list of each event
            sn (int): beginning sn to search

        """
        from ..core.structing import SealEvent

        if tuple(seal) != SealEvent._fields:  # wrong type of seal
            return None

        seal = SealEvent(**seal)  #convert to namedtuple

        for srdr in self.getEvtLastPreIter(pre=pre, sn=sn):  # no disputed or superseded
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == SealEvent._fields:
                    eseal = SealEvent(**eseal)  # convert to namedtuple
                    if seal == eseal and self.fullyWitnessed(srdr):
                        return srdr
        return None



    def fetchLastSealingEventBySeal(self, pre, seal, sn=0):
        """Only searches last event at any sn therefore does not search
        any disputed or superseded events.
        Search through last event at each sn in KEL for the event that contains
        an anchored Seal with same Seal type as provided seal but in dict form.
        Searchs from sn forward (default = 0).
        Returns the Serder of the first found event with the anchored Seal seal,
            None if not found

        Parameters:
            pre (bytes|str): identifier of the KEL to search
            seal (dict): dict form of Seal of any type to find in anchored
                seals list of each event
            sn (int): beginning sn to search

        """
        # create generic Seal namedtuple class using keys from provided seal dict
        Seal = namedtuple('Seal', list(seal))  # matching type

        for srdr in self.getEvtLastPreIter(pre=pre, sn=sn):  # only last evt at sn
            for eseal in srdr.seals or []:  # or [] for seals 'a' field missing
                if tuple(eseal) == Seal._fields:  # same type of seal
                    eseal = Seal(**eseal)  #convert to namedtuple
                    if seal == eseal and self.fullyWitnessed(srdr):
                        return srdr
        return None

    def signingMembers(self, pre: str):
        """ Find signing members of a multisig group aid.

        Using the pubs index to find members of a signing group

        Parameters:
            pre (str): qb64 identifier prefix to find members

        Returns:
            list: qb64 identifier prefixes of signing members for provided aid

        """
        if (habord := self.habs.get(keys=(pre,))) is None:
            return None

        return habord.smids

    def rotationMembers(self, pre: str):
        """ Find rotation members of a multisig group aid.

        Using the digs index to lookup member pres of a group aid

        Parameters:
            pre (str): qb64 identifier prefix to find members

        Returns:
            list: qb64 identifier prefixes of rotation members for provided aid
        """
        if (habord := self.habs.get(keys=(pre,))) is None:
            return None

        return habord.rmids

    def fullyWitnessed(self, serder):
        """ Verify the witness threshold on the event

        Parameters:
            serder (Serder): event serder to validate witness threshold

        Returns:

        """
        # Verify fully receipted, because this witness may have persisted before all receipts
        # have been gathered if this ius a witness for serder.pre
        # get unique verified wigers and windices lists from wigers list
        wigers = self.wigs.get(keys=(serder.preb, serder.saidb))
        kever = self.kevers[serder.pre]
        toad = kever.toader.num

        return not len(wigers) < toad

    def resolveVerifiers(self, pre=None, sn=0, dig=None):
        """
        Returns the Tholder and Verfers for the provided identifier prefix.
        Default pre is own .pre

        Parameters:
            pre(str) is qb64 str of bytes of identifier prefix.
            sn(int) is the sequence number of the est event
            dig(str) is qb64 str of digest of est event

        """
        from ..core import coring

        prefixer = coring.Prefixer(qb64=pre)
        if prefixer.transferable:
            # receipted event and receipter in database so get receipter est evt
            # retrieve dig of last event at sn of est evt of receipter.
            sdig = self.kels.getLast(keys=prefixer.qb64b, on=sn)
            if sdig is None:
                # receipter's est event not yet in receipters's KEL
                raise ValidationError("key event sn {} for pre {} is not yet in KEL"
                                             "".format(sn, pre))
            sdig = sdig.encode("utf-8")
            # retrieve last event itself of receipter est evt from sdig
            sserder = self.evts.get(keys=(prefixer.qb64b, bytes(sdig)))
            # assumes db ensures that sserder must not be none because sdig was in KE
            if dig is not None and not sserder.compare(said=dig):  # endorser's dig not match event
                raise ValidationError("Bad proof sig group at sn = {}"
                                             " for ksn = {}."
                                             "".format(sn, sserder.sad))

            verfers = sserder.verfers
            tholder = sserder.tholder

        else:
            verfers = [coring.Verfer(qb64=pre)]
            tholder = coring.Tholder(sith="1")

        return tholder, verfers

    def getEvtPreIter(self, pre, sn=0):
        """
        Returns iterator of event messages without attachments
        in sn order from the KEL of identifier prefix pre.
        Essentially a replay of all event messages without attachments
        for each sn from the KEL of pre including superseded duplicates

        Parameters:
            pre (bytes|str): identifier prefix
            sn (int): sequence number (default 0) to begin interation
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for dig in self.kels.getAllIter(keys=pre, on=sn):
            try:
                if not (serder := self.evts.get(keys=(pre, dig))):
                    raise MissingEntryError("Missing event for dig={}.".format(dig))

            except Exception:
                continue  # skip this event

            yield serder  # event as Serder


    def getEvtLastPreIter(self, pre, sn=0):
        """
        Returns iterator of event messages without attachments
        in sn order from the KEL of identifier prefix pre.
        Essentially a replay of all event messages without attachments
        for each sn from the KEL of pre including superseded duplicates

        Parameters:
            pre (bytes|str): identifier prefix
            sn (int): sequence number (default 0) to begin interation
        """
        if hasattr(pre, 'encode'):
            pre = pre.encode("utf-8")

        for dig in self.kels.getLastIter(keys=pre, on=sn):
            try:

                if not (serder := self.evts.get(keys=(pre, dig) )):
                    raise MissingEntryError("Missing event for dig={}.".format(dig))

            except Exception:
                continue  # skip this event

            yield serder  # event as Serder