# -*- encoding: utf-8 -*-
"""
keri.db.memoring module

In-memory database backend implementing the Dber abstract interface.
Useful for testing and as a reference implementation documenting exact
method semantics.

"""
import bisect
from collections import OrderedDict
from dataclasses import dataclass, field

from ordered_set import OrderedSet as oset

from . import dbing
from .dbing import (Dber, DatabaseError, BadKeySizeError,
                    onKey, splitOnKey, suffix, unsuffix, ProemSize, MaxProem,
                    SuffixSize, MaxSuffix)
from ..kering import MaxON


@dataclass
class SubDb:
    """Descriptor for an in-memory sub-database partition.

    Attributes:
        dupsort (bool): whether this sub-db allows duplicate values per key
        data (dict): the actual key-value store
            For dupsort==False: dict[bytes, bytes]
            For dupsort==True: dict[bytes, list[bytes]] where list is sorted
    """
    dupsort: bool = False
    data: dict = field(default_factory=dict)


class MemoryDber(Dber):
    """In-memory database backend implementing the Dber interface.

    Maps the 3-level partitioning hierarchy to nested dicts:
      1. Environment (name + base) -> this instance
      2. Sub-database (subkey) -> SubDb descriptor
      3. Record key -> bytes value(s)

    Attributes:
        name (str): unique partition name
        base (str): partition prefix
        temp (bool): True means temporary (cleared on close)
        opened (bool): True means database is open
    """

    def __init__(self, *, name="test", base="", temp=True,
                 reopen=True, **kwa):
        """
        Parameters:
            name (str): database name
            base (str): base path component
            temp (bool): True means temporary
            reopen (bool): True means open on init
        """
        self.name = name
        self.base = base
        self.temp = temp
        self.opened = False
        self._subdbs = {}  # subkey -> SubDb
        self._version = None
        # default sub-db for version storage etc (unnamed db in LMDB)
        self._default_db = SubDb(dupsort=False)

        if reopen:
            self.reopen(**kwa)

    @property
    def path(self):
        """Return a virtual path for compatibility."""
        return f"memory://{self.base}/{self.name}"

    def reopen(self, **kwa):
        """Open or reopen the database."""
        self.opened = True
        return self.opened

    def close(self, clear=False):
        """Close the database."""
        if clear:
            self._subdbs.clear()
            self._default_db = SubDb(dupsort=False)
        self.opened = False

    def open_sub(self, subkey, dupsort=False):
        """Create or open a named sub-database partition.

        Returns:
            SubDb: sub-database descriptor
        """
        if subkey not in self._subdbs:
            self._subdbs[subkey] = SubDb(dupsort=dupsort)
        return self._subdbs[subkey]

    # Helper: sorted keys in a sub-db (non-dupsort data dict)
    def _sorted_keys(self, db):
        """Return sorted list of keys in db."""
        return sorted(db.data.keys())

    def _set_range_keys(self, db, start):
        """Return sorted keys >= start."""
        keys = self._sorted_keys(db)
        idx = bisect.bisect_left(keys, start)
        return keys[idx:]

    # ---- Universal methods ----

    def delTop(self, db, top=b''):
        result = False
        keys_to_delete = []
        for key in db.data:
            if not top or key.startswith(top) if isinstance(key, bytes) else True:
                if not top or bytes(key).startswith(top):
                    keys_to_delete.append(key)
        for key in keys_to_delete:
            del db.data[key]
            result = True
        return result

    def cntAll(self, db):
        if not db.dupsort:
            return len(db.data)
        # For dupsort, count all dup entries
        count = 0
        for key in db.data:
            count += len(db.data[key])
        return count

    def getTopItemIter(self, db, top=b''):
        for key in self._set_range_keys(db, top):
            if top and not key.startswith(top):
                break
            if db.dupsort:
                for val in db.data[key]:
                    yield (key, val)
            else:
                yield (key, db.data[key])

    # ---- Val family (dupsort==False) ----

    def putVal(self, db, key, val):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        if key in db.data:
            return False
        db.data[key] = val if isinstance(val, bytes) else bytes(val)
        return True

    def setVal(self, db, key, val):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        db.data[key] = val if isinstance(val, bytes) else bytes(val)
        return True

    def getVal(self, db, key):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        return db.data.get(key)

    def delVal(self, db, key):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        if key in db.data:
            del db.data[key]
            return True
        return False

    # ---- OnVal family ----

    def putOnVal(self, db, key, on=0, val=b'', *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key
        return self.putVal(db, onkey, val)

    def setOnVal(self, db, key, on=0, val=b'', *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key
        return self.setVal(db, onkey, val)

    def appendOnVal(self, db, key, val, *, sep=b'.'):
        onkey = onKey(key, MaxON, sep=sep)
        on = 0
        keys = self._sorted_keys(db)

        if not keys:
            # empty db
            pass
        else:
            idx = bisect.bisect_right(keys, onkey)
            if idx >= len(keys):
                # max is past end of database
                # last key is either at same key prefix or earlier prefix
                last_key = keys[-1]
                try:
                    ckey, cn = splitOnKey(last_key, sep=sep)
                except ValueError:
                    pass
                else:
                    if ckey == key:
                        on = cn + 1
            else:
                # not past end
                found_key = keys[idx]
                try:
                    ckey, cn = splitOnKey(found_key, sep=sep)
                except ValueError:
                    pass
                else:
                    if ckey == key:
                        raise ValueError(f"Number part {cn=} for key part {ckey=}"
                                         f"exceeds maximum size.")
                    else:
                        # backup one entry
                        if idx > 0:
                            prev_key = keys[idx - 1]
                            try:
                                ckey, cn = splitOnKey(prev_key, sep=sep)
                            except ValueError:
                                pass
                            else:
                                if ckey == key:
                                    on = cn + 1

        # Actually we need set_range behavior. Let me redo with proper logic.
        # Reset on
        on = 0
        onkey_start = onKey(key, MaxON, sep=sep)

        # Find keys >= onkey_start
        range_keys = self._set_range_keys(db, onkey_start)

        if not range_keys:
            # past end of database
            if keys:
                last_key = keys[-1]
                try:
                    ckey, cn = splitOnKey(last_key, sep=sep)
                except ValueError:
                    pass
                else:
                    if ckey == key:
                        on = cn + 1
        else:
            found_key = range_keys[0]
            try:
                ckey, cn = splitOnKey(found_key, sep=sep)
            except ValueError:
                pass
            else:
                if ckey == key:
                    raise ValueError(f"Number part {cn=} for key part {ckey=}"
                                     f"exceeds maximum size.")
                else:
                    # Find prev entry
                    all_idx = bisect.bisect_left(keys, found_key)
                    if all_idx > 0:
                        prev_key = keys[all_idx - 1]
                        try:
                            ckey, cn = splitOnKey(prev_key, sep=sep)
                        except ValueError:
                            pass
                        else:
                            if ckey == key:
                                on = cn + 1

        onkey = onKey(key, on, sep=sep)
        if not self.putVal(db, onkey, val):
            raise ValueError(f"Failed appending {val=} at {key=}.")
        return on

    def getOnVal(self, db, key, on=0, *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key
        return self.getVal(db, onkey)

    def delOnVal(self, db, key, on=0, *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key
        return self.delVal(db, onkey)

    def cntOnAll(self, db, key=b'', on=0, *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key
        count = 0
        for ckey_full in self._set_range_keys(db, onkey):
            try:
                ckey, cn = splitOnKey(ckey_full, sep=sep)
            except ValueError:
                break
            if key and ckey != key:
                break
            count += 1
        return count

    def getOnIterAll(self, db, key=b'', on=0, *, sep=b'.'):
        for (ckey, cn, val) in self.getOnItemIterAll(db=db, key=key, on=on, sep=sep):
            yield val

    def getOnItemIterAll(self, db, key=b'', on=0, *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key
        for ckey_full in self._set_range_keys(db, onkey):
            try:
                ckey, cn = splitOnKey(ckey_full, sep=sep)
            except ValueError:
                break
            if key and ckey != key:
                break
            yield (ckey, cn, db.data[ckey_full])

    # ---- IoSet family (dupsort==False with hidden suffix) ----

    def putIoSetVals(self, db, key, vals, *, sep=b'.'):
        result = False
        if not key:
            return result
        vals = oset(vals) if vals else oset()
        ion = 0
        iokey = suffix(key, ion, sep=sep)

        # Find existing vals and next ion
        pvals = oset()
        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey == key:
                pvals.add(db.data[ckey_full] if isinstance(db.data[ckey_full], bytes)
                          else bytes(db.data[ckey_full]))
                ion = cion + 1
            else:
                break

        vals -= pvals
        for i, val in enumerate(vals):
            iokey = suffix(key, ion + i, sep=sep)
            val = val if isinstance(val, bytes) else bytes(val)
            if iokey not in db.data:
                db.data[iokey] = val
                result = True
        return result

    def pinIoSetVals(self, db, key, vals, *, sep=b'.'):
        self.delIoSet(db=db, key=key, sep=sep)
        result = False
        if not key:
            return result
        vals = oset(vals)
        for i, val in enumerate(vals):
            iokey = suffix(key, i, sep=sep)
            val = val if isinstance(val, bytes) else bytes(val)
            db.data[iokey] = val
            result = True
        return result

    def addIoSetVal(self, db, key, val, *, sep=b'.'):
        if not key:
            return False
        vals = oset()
        ion = 0
        iokey = suffix(key, ion, sep=sep)

        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey == key:
                cval = db.data[ckey_full]
                vals.add(cval if isinstance(cval, bytes) else bytes(cval))
                ion = cion + 1
            else:
                break

        val = val if isinstance(val, bytes) else bytes(val)
        if val in vals:
            return False

        iokey = suffix(key, ion, sep=sep)
        db.data[iokey] = val
        return True

    def getIoSet(self, db, key, *, ion=0, sep=b'.'):
        vals = []
        if not key:
            return vals
        iokey = suffix(key, ion, sep=sep)
        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey != key:
                break
            vals.append(db.data[ckey_full])
        return vals

    def getIoSetIter(self, db, key, *, ion=0, sep=b'.'):
        if not key:
            return
        iokey = suffix(key, ion, sep=sep)
        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey != key:
                break
            yield db.data[ckey_full]

    def getIoSetLastItem(self, db, key, *, sep=b'.'):
        last = ()
        if not key:
            return last
        iokey = suffix(key, 0)
        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey != key:
                break
            last = (ckey, db.data[ckey_full])
        return last

    def getIoSetLast(self, db, key, *, sep=b'.'):
        val = None
        if result := self.getIoSetLastItem(db=db, key=key, sep=sep):
            _, val = result
        return val

    def delIoSet(self, db, key, *, sep=b'.'):
        result = False
        if not key:
            return result
        iokey = suffix(key, 0, sep=sep)
        keys_to_delete = []
        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey != key:
                break
            keys_to_delete.append(ckey_full)
        for k in keys_to_delete:
            del db.data[k]
            result = True
        return result

    def delIoSetVal(self, db, key, val, *, sep=b'.'):
        if not key:
            return False
        val = val if isinstance(val, bytes) else bytes(val)
        iokey = suffix(key, 0, sep=sep)
        for ckey_full in self._set_range_keys(db, iokey):
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey != key:
                break
            cval = db.data[ckey_full]
            if isinstance(cval, memoryview):
                cval = bytes(cval)
            if val == cval:
                del db.data[ckey_full]
                return True
        return False

    def cntIoSet(self, db, key, *, ion=0, sep=b'.'):
        return len(self.getIoSet(db=db, key=key, ion=ion, sep=sep))

    def getTopIoSetItemIter(self, db, top=b'', *, sep=b'.'):
        for iokey, val in self.getTopItemIter(db=db, top=top):
            key, ion = unsuffix(iokey, sep=sep)
            yield (key, val)

    def getIoSetLastItemIterAll(self, db, key=b'', *, sep=b'.'):
        keys = self._sorted_keys(db)
        if not keys:
            return

        if not key:
            # start at first key
            first_key = keys[0]
            try:
                key_start, _ = unsuffix(first_key, sep=sep)
            except ValueError:
                return
        else:
            key_start = key

        iokey = suffix(key_start, 0)
        start_idx = bisect.bisect_left(keys, iokey)
        if start_idx >= len(keys):
            return

        last = None
        current_key = None
        for i in range(start_idx, len(keys)):
            ckey_full = keys[i]
            try:
                ckey, cion = unsuffix(ckey_full, sep=sep)
            except ValueError:
                break
            if ckey != current_key:
                if last is not None:
                    yield last
                current_key = ckey
            last = (ckey, db.data[ckey_full])
        if last is not None:
            yield last

    # ---- Vals/Dup family (dupsort==True) ----

    def _ensure_dup_list(self, db, key):
        """Ensure key has a sorted list for dupsort storage."""
        if key not in db.data:
            db.data[key] = []

    def putVals(self, db, key, vals):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        self._ensure_dup_list(db, key)
        result = True
        for val in vals:
            val = val if isinstance(val, bytes) else bytes(val)
            if val not in db.data[key]:
                bisect.insort(db.data[key], val)
            result = result and True
        return result

    def addVal(self, db, key, val):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        val = val if isinstance(val, bytes) else bytes(val)
        self._ensure_dup_list(db, key)
        if val in db.data[key]:
            return False
        bisect.insort(db.data[key], val)
        return True

    def getVals(self, db, key):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        return list(db.data.get(key, []))

    def getValsIter(self, db, key):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        for val in db.data.get(key, []):
            yield val

    def getValLast(self, db, key):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        vals = db.data.get(key, [])
        if vals:
            return vals[-1]
        return None

    def cntVals(self, db, key):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        return len(db.data.get(key, []))

    def delVals(self, db, key, val=b''):
        if not key:
            raise KeyError(f"Key: `{key}` is either empty, too big,"
                           " or wrong DUPFIXED size.")
        if key not in db.data:
            return False
        if val:
            val = val if isinstance(val, bytes) else bytes(val)
            try:
                db.data[key].remove(val)
                if not db.data[key]:
                    del db.data[key]
                return True
            except ValueError:
                return False
        else:
            del db.data[key]
            return True

    # ---- IoDup family (dupsort==True with proem) ----

    def putIoDupVals(self, db, key, vals):
        result = False
        dups = set(self.getIoDupVals(db, key))
        self._ensure_dup_list(db, key)

        # Find current max proem index
        idx = 0
        existing = db.data.get(key, [])
        if existing:
            last_val = existing[-1]
            if isinstance(last_val, memoryview):
                last_val = bytes(last_val)
            idx = 1 + int(last_val[:32], 16)

        for val in vals:
            val = val if isinstance(val, bytes) else bytes(val)
            if val not in dups:
                proval = (b'%032x.' % idx) + val
                bisect.insort(db.data[key], proval)
                idx += 1
                result = True
        return result

    def addIoDupVal(self, db, key, val):
        return self.putIoDupVals(db, key, [val] if val is not None else [b''])

    def getIoDupVals(self, db, key):
        vals = db.data.get(key, [])
        return [val[33:] if isinstance(val, bytes) else bytes(val)[33:]
                for val in vals]

    def getIoDupValsIter(self, db, key):
        for val in db.data.get(key, []):
            yield val[33:] if isinstance(val, bytes) else bytes(val)[33:]

    def getIoDupValLast(self, db, key):
        vals = db.data.get(key, [])
        if vals:
            last = vals[-1]
            return last[33:] if isinstance(last, bytes) else bytes(last)[33:]
        return None

    def delIoDupVals(self, db, key):
        if key in db.data:
            del db.data[key]
            return True
        return False

    def delIoDupVal(self, db, key, val):
        val = val if isinstance(val, bytes) else bytes(val)
        vals = db.data.get(key, [])
        for i, proval in enumerate(vals):
            pv = proval if isinstance(proval, bytes) else bytes(proval)
            if val == pv[33:]:
                vals.pop(i)
                if not vals:
                    del db.data[key]
                return True
        return False

    def cntIoDups(self, db, key):
        return len(db.data.get(key, []))

    def getTopIoDupItemIter(self, db, top=b''):
        for key, val in self.getTopItemIter(db=db, top=top):
            yield (key, val[33:])

    # ---- OnIoDup methods that use backend-specific cursor operations ----

    def appendOnIoDupVal(self, db, key, val, *, sep=b'.'):
        val = (b'%032x.' % 0) + val
        return self.appendOnVal(db=db, key=key, val=val, sep=sep)

    def getOnIoDupLastItemIter(self, db, key=b'', on=0, *, sep=b'.'):
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key

        keys = self._sorted_keys(db)
        if not keys:
            return

        # Find start position
        start_keys = self._set_range_keys(db, onkey)
        if not start_keys:
            return

        # For each onkey, find last dup value
        current_onkey = None
        last_item = None

        for ckey_full in start_keys:
            if db.dupsort:
                try:
                    ckey, cn = splitOnKey(ckey_full, sep=sep)
                except ValueError:
                    break
                if key and ckey != key:
                    break
                # For dupsort, get last dup
                vals = db.data.get(ckey_full, [])
                if vals:
                    last_val = vals[-1]
                    if isinstance(last_val, memoryview):
                        last_val = bytes(last_val)
                    yield (ckey, cn, last_val[33:])
            else:
                # Non-dupsort with proem in value
                try:
                    ckey, cn = splitOnKey(ckey_full, sep=sep)
                except ValueError:
                    break
                if key and ckey != key:
                    break
                val = db.data[ckey_full]
                if isinstance(val, memoryview):
                    val = bytes(val)
                yield (ckey, cn, val[33:])

    def getOnIoDupItemIterAll(self, db, key=b'', on=0, *, sep=b'.'):
        for key_out, on_out, val in self.getOnItemIterAll(db=db, key=key, on=on, sep=sep):
            if isinstance(val, memoryview):
                val = bytes(val)
            yield (key_out, on_out, val[33:])

    def getOnIoDupIterAll(self, db, key=b'', on=0, *, sep=b'.'):
        for key_out, on_out, val in self.getOnIoDupItemIterAll(db=db, key=key, on=on, sep=sep):
            yield val

    def getOnIoSetItemBackIter(self, db, key=b'', on=0, *, sep=b'.'):
        # Collect all matching items then yield in reverse
        items = []
        for ckey, cn, cval in self.getOnItemIterAll(db=db, key=key, on=on, sep=sep):
            items.append((ckey, cn, cval[33:] if len(cval) > 33 else cval))
        for item in reversed(items):
            yield item

    def getOnIoDupItemBackIter(self, db, key=b'', on=0, *, sep=b'.'):
        # Collect all matching items then yield in reverse
        items = []
        if key:
            onkey = onKey(key, on, sep=sep)
        else:
            onkey = key

        for ckey_full in self._set_range_keys(db, onkey):
            try:
                ckey, cn = splitOnKey(ckey_full, sep=sep)
            except ValueError:
                break
            if key and ckey != key:
                break
            if db.dupsort:
                for val in db.data.get(ckey_full, []):
                    val_bytes = val if isinstance(val, bytes) else bytes(val)
                    items.append((ckey, cn, val_bytes[33:]))
            else:
                val = db.data[ckey_full]
                val_bytes = val if isinstance(val, bytes) else bytes(val)
                items.append((ckey, cn, val_bytes[33:]))

        for item in reversed(items):
            yield item

    def getOnIoSetItemIterAll(self, db, key=b'', on=None, *, sep=b'.'):
        if on is None:
            on = 0
        onky = onKey(key, on, sep=sep)
        iokey = suffix(onky, 0, sep=sep)

        for ckey_full in self._set_range_keys(db, iokey):
            try:
                conkey, cion = unsuffix(ckey_full, sep=sep)
                ckey, con = splitOnKey(conkey, sep=sep)
            except ValueError:
                break
            if ckey != key:
                break
            yield (ckey, con, db.data[ckey_full])

    def getOnIoSetLastItemIterAll(self, db, key=b'', on=None, *, sep=b'.'):
        if not key or on is None:
            for onkey, val in self.getIoSetLastItemIterAll(db=db,
                                                           key=key,
                                                           sep=sep):
                rkey, ron = splitOnKey(onkey, sep=sep)
                yield (rkey, ron, val)
            return

        onky = onKey(key, on, sep=sep)
        while True:
            # Get IoSet at this onkey
            last = self.getIoSetLastItem(db=db, key=onky, sep=sep)
            if not last:
                # Try next on by finding next key >= onky suffix 0
                iokey = suffix(onky, 0, sep=sep)
                found = False
                for ckey_full in self._set_range_keys(db, iokey):
                    try:
                        conkey, cion = unsuffix(ckey_full, sep=sep)
                        ckey, con = splitOnKey(conkey, sep=sep)
                    except ValueError:
                        return
                    if ckey != key:
                        return
                    # Found a new onkey
                    onky = conkey
                    found = True
                    break
                if not found:
                    return
                last = self.getIoSetLastItem(db=db, key=onky, sep=sep)
                if not last:
                    return

            lkey_full, lval = last
            try:
                lkey, lon = splitOnKey(lkey_full, sep=sep)
            except ValueError:
                return
            yield (lkey, lon, lval)
            onky = onKey(lkey, lon + 1, sep=sep)
