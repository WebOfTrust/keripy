# -*- encoding: utf-8 -*-
"""
keri.app.notifying module

Provides data structures and persistence utilities for creating, storing,
retrieving, and signaling agent notifications.
"""
import os
from collections.abc import Iterable
from typing import Union, Type

from ..kering import ValidationError
from ..help import nowIso8601
from ..core import Cigar, Dicter
from ..db import LMDBer, CesrSuber, Suber

from .signaling import Signaler


def notice(attrs, dt=None, read=False):
    """Create a Notice instance.

    Args:
        attrs (dict): Arbitrary payload describing the notification.
        dt (str | datetime, optional): Datetime for the notice. If a
            ``datetime`` object is provided it is converted to ISO 8601
            format via its ``isoformat()`` method. Defaults to the current
            time via ``nowIso8601()``.
        read (bool, optional): Whether the notice is marked as read.
            Defaults to ``False``.

    Returns:
        Notice: An initialized notice instance.
    """
    dt = dt if dt is not None else nowIso8601()

    if hasattr(dt, "isoformat"):
        dt = dt.isoformat()

    pad = dict(i="",
               dt=dt,
               r=read,
               a=attrs
               )

    return Notice(pad=pad)


class Notice(Dicter):
    """Notification message container.

    Extends :class:`Dicter` with notification-specific fields and validation.
    A notice encapsulates a timestamp, a read status, and a metadata payload.

    Attributes:
        raw (bytes): Serialized representation of the notice, inherited from
            :class:`Dicter`.
        pad (dict): Underlying structured data dictionary, inherited from
            :class:`Dicter`.
    """

    def __init__(self, raw=b'', pad=None, note=None):
        """Initialize a notice instance.

        Exactly one of ``raw``, ``pad``, or ``note`` should be provided.
        The ``note`` argument is forwarded to the base class as the
        ``dicter`` parameter.

        Args:
            raw (bytes, optional): Serialized notice data. Defaults to ``b''``.
            pad (dict, optional): Structured notice data. Must contain at least
                the key ``"a"`` (attributes). Defaults to ``None``.
            note (Dicter, optional): An existing :class:`Dicter` instance used
                to initialize the notice. Defaults to ``None``.

        Raises:
            ValueError: If the resolved data is missing the required ``"a"``
                (attributes) key.
        """
        super(Notice, self).__init__(raw=raw, pad=pad, dicter=note)

        if "a" not in self._pad:
            raise ValueError(f"invalid notice, missing attributes in {pad}")

        if "dt" not in self._pad:
            self._pad["dt"] = nowIso8601()

    @property
    def datetime(self):
        """str: The ISO 8601 formatted datetime of the notice."""
        return self._pad["dt"]

    @property
    def attrs(self):
        """dict: The notification's arbitrary attributes payload."""
        return self._pad["a"]

    @property
    def read(self):
        """bool: The read status flag of the notice."""
        return self._pad["r"]

    @read.setter
    def read(self, val):
        """Set the read status flag.

        Args:
            val (bool): The new read state to apply.
        """
        pad = self.pad
        pad["r"] = val
        self.pad = pad


class DicterSuber(Suber):
    """Sub-database for storing :class:`Dicter` instances.

    Serializes values using ``Dicter.raw`` and deserializes them back into
    instances of a configurable subclass.

    Attributes:
        klas (Type[Dicter]): The class used to wrap raw bytes during retrieval.
    """

    def __init__(self, *pa, klas: Type[Dicter] = Dicter, **kwa):
        """Initialize the sub-database.

        Args:
            *pa: Positional arguments forwarded to :class:`Suber`.
            klas (Type[Dicter], optional): Class used for deserializing stored
                bytes. Defaults to :class:`Dicter`.
            **kwa: Keyword arguments forwarded to :class:`Suber`.
        """
        super(DicterSuber, self).__init__(*pa, **kwa)
        self.klas = klas

    def put(self, keys: Union[str, Iterable], val: Dicter):
        """Store a value without overwriting an existing entry.

        Args:
            keys (str | Iterable): Components used to construct the database
                key.
            val (Dicter): The :class:`Dicter` instance to store.

        Returns:
            bool: ``True`` if the value was stored, ``False`` if the key
                already exists.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def pin(self, keys: Union[str, Iterable], val: Dicter):
        """Store a value, overwriting any existing entry.

        Args:
            keys (str | Iterable): Components used to construct the database
                key.
            val (Dicter): The :class:`Dicter` instance to store.

        Returns:
            bool: ``True`` if the operation succeeded.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def get(self, keys: Union[str, Iterable]):
        """Retrieve and deserialize a value by key.

        Args:
            keys (str | Iterable): Components used to construct the database
                key.

        Returns:
            Dicter | None: An instance of ``self.klas`` populated from the
                stored bytes, or ``None`` if the key is not found.
        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return self.klas(raw=bytes(val)) if val is not None else None

    def rem(self, keys: Union[str, Iterable]):
        """Remove an entry from the sub-database by key.

        Args:
            keys (str | Iterable): Components used to construct the database
                key.

        Returns:
            bool: ``True`` if the entry existed and was removed, ``False``
                otherwise.
        """
        return self.db.remVal(db=self.sdb, key=self._tokey(keys))

    def getTopItemIter(self, keys: Union[str, Iterable] = b""):
        """Iterate over entries whose key matches a given prefix.

        Args:
            keys (str | Iterable, optional): Prefix components used to filter
                entries. Defaults to ``b""`` which matches all entries.

        Yields:
            tuple[tuple, Dicter]: A pair of the reconstructed key tuple and
                the deserialized instance of ``self.klas``.
        """
        for key, val in self.db.getTopItemIter(db=self.sdb,
                                               top=self._tokey(keys)):
            yield self._tokeys(key), self.klas(raw=bytes(val))

    def cntAll(self):
        """Count the total number of entries in the sub-database.

        Returns:
            int: The total entry count.
        """
        return self.db.cntAll(db=self.sdb)


class Noter(LMDBer):
    """Persistent storage for :class:`Notice` objects and their signatures."""

    TailDirPath = os.path.join("keri", "not")
    AltTailDirPath = os.path.join(".keri", "not")
    TempPrefix = "keri_not_"

    def __init__(self, name="not", headDirPath=None, reopen=True, **kwa):
        """Initialize the notifier database.

        Args:
            name (str, optional): Database name. Defaults to ``"not"``.
            headDirPath (str, optional): Base directory path. Defaults to
                ``None``.
            reopen (bool, optional): Whether to open the database immediately.
                Defaults to ``True``.
            **kwa: Additional keyword arguments forwarded to :class:`LMDBer`.
        """
        self.notes = None
        self.nidx = None
        self.ncigs = None

        super(Noter, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """Open or reopen the underlying LMDB environment.

        Initializes the ``notes``, ``nidx``, and ``ncigs`` sub-databases.

        Args:
            **kwa: Additional keyword arguments forwarded to
                :meth:`LMDBer.reopen`.

        Returns:
            lmdb.Environment: The open LMDB environment.
        """
        super(Noter, self).reopen(**kwa)

        self.notes = DicterSuber(db=self, subkey='nots.', sep='/', klas=Notice)
        self.nidx = Suber(db=self, subkey='nidx.')
        self.ncigs = CesrSuber(db=self, subkey='ncigs.', klas=Cigar)

        return self.env

    def add(self, note, cigar):
        """Add a new notice.

        Indexes the notice by its ``rid`` under ``nidx``, stores the
        signature under ``ncigs``, and stores the notice itself under the
        composite key ``(dt, rid)`` in ``notes``. Does nothing if a notice
        with the same ``rid`` already exists in the index.

        Args:
            note (Notice): The notice to store.
            cigar (Cigar): Cryptographic signature over the serialized notice.

        Returns:
            bool: ``True`` if the notice was added, ``False`` if a notice with
                the same ``rid`` already exists.
        """
        dt = note.datetime
        rid = note.rid
        if self.nidx.get(keys=(rid,)) is not None:
            return False

        self.nidx.pin(keys=(rid,), val=dt.encode())
        self.ncigs.pin(keys=(rid,), val=cigar)
        return self.notes.pin(keys=(dt, rid), val=note)

    def update(self, note, cigar):
        """Update an existing notice in place.

        Overwrites the stored datetime index, signature, and notice body for
        the given ``rid``. The notice must already exist in the index.

        Args:
            note (Notice): The updated notice. Its ``rid`` must match an
                existing entry.
            cigar (Cigar): Cryptographic signature over the serialized notice.

        Returns:
            bool: ``True`` if the notice was updated, ``False`` if no notice
                with the given ``rid`` exists.
        """
        dt = note.datetime
        rid = note.rid
        if self.nidx.get(keys=(rid,)) is None:
            return False

        self.nidx.pin(keys=(rid,), val=dt.encode())
        self.ncigs.pin(keys=(rid,), val=cigar)
        return self.notes.pin(keys=(dt, rid), val=note)

    def get(self, rid):
        """Retrieve a notice and its signature by identifier.

        Args:
            rid (str): QB64 identifier of the notice.

        Returns:
            tuple[Notice, Cigar] | None: The notice and its signature, or
                ``None`` if no notice with the given ``rid`` exists in the
                index.
        """
        dt = self.nidx.get(keys=(rid,))
        if dt is None:
            return None

        note = self.notes.get(keys=(dt, rid))
        cig = self.ncigs.get(keys=(rid,))

        return note, cig

    def rem(self, rid):
        """Remove a notice by identifier.

        Removes the notice from ``notes``, its index entry from ``nidx``,
        and its signature from ``ncigs``.

        Args:
            rid (str): QB64 identifier of the notice.

        Returns:
            bool: ``True`` if the notice was found and removed, ``False`` if
                no notice with the given ``rid`` exists.
        """
        res = self.get(rid)
        if res is None:
            return False

        note, _ = res
        dt = note.datetime
        rid = note.rid
        self.nidx.rem(keys=(rid,))
        self.ncigs.rem(keys=(rid,))
        return self.notes.rem(keys=(dt, rid))

    def getNoteCnt(self):
        """Return the total number of stored notices.

        Returns:
            int: Number of notices in the database.
        """
        return self.notes.cntAll()

    def getNotes(self, start=0, end=25):
        """Retrieve a slice of stored notices ordered by datetime.

        Skips the first ``start`` entries in iteration order, then collects
        up to ``(end - start) + 1`` notices. Pass ``end=-1`` to collect all
        remaining notices after ``start``.

        Args:
            start (int, optional): Zero-based count of notices to skip before
                collecting. Defaults to ``0``.
            end (int, optional): Inclusive upper bound controlling how many
                notices are returned: ``(end - start) + 1`` notices are
                collected. Pass ``-1`` to return all remaining notices after
                ``start``. Defaults to ``25``.

        Returns:
            list[tuple[Notice, Cigar]]: Ordered list of notice/signature pairs.
        """
        if hasattr(start, "isoformat"):
            start = start.isoformat()

        notes = []
        it = self.notes.getTopItemIter(keys=())

        # Run off the items before start
        for _ in range(start):
            try:
                next(it)
            except StopIteration:
                break

        for ((_, _), note) in it:
            cig = self.ncigs.get(keys=(note.rid,))
            notes.append((note, cig))
            if (not end == -1) and len(notes) == (end - start) + 1:
                break

        return notes


class Notifier:
    """High-level interface for managing and signaling notifications."""

    def __init__(self, hby, signaler=None, noter=None):
        """Initialize the notifier.

        Args:
            hby (Habery): Habitat environment providing a ``signator`` for
                signing and verification.
            signaler (Signaler, optional): Signaling interface used to push
                notification events. Defaults to a new :class:`Signaler`
                instance.
            noter (Noter, optional): Persistent storage backend. Defaults to a
                new :class:`Noter` instance scoped to ``hby.name``.
        """
        self.hby = hby
        self.signaler = signaler if signaler is not None else Signaler()
        self.noter = noter if noter is not None else Noter(name=hby.name, temp=hby.temp)

    def add(self, attrs):
        """Create and store a new unread notice.

        Constructs a :class:`Notice` from ``attrs``, signs it with
        ``hby.signator``, and persists it via :meth:`Noter.add`. On success,
        pushes an ``"add"`` signal to the ``"/notification"`` topic.

        Args:
            attrs (dict): Notification payload.

        Returns:
            bool: ``True`` if the notice was created and stored, ``False`` if
                a notice with the same identifier already exists.
        """
        note = notice(attrs, dt=nowIso8601())
        cig = self.hby.signator.sign(ser=note.raw)
        if self.noter.add(note, cig):
            signal = dict(
                action="add",
                dt=nowIso8601(),
                note=note.pad,
            )
            self.signaler.push(attrs=signal, topic="/notification", ckey="/notification")
            return True
        else:
            return False

    def rem(self, rid):
        """Delete a notice by identifier.

        Retrieves the notice, removes it from storage, then verifies the
        stored signature before pushing a ``"rem"`` signal. The signal is
        only sent when both removal and signature verification succeed.

        Args:
            rid (str): QB64 identifier of the notice.

        Returns:
            bool: ``True`` if the notice was found and removed, ``False`` if
                no notice with the given ``rid`` exists.
        """
        res = self.noter.get(rid=rid)
        if res is None:
            return False

        note, cig = res
        if self.noter.rem(rid):
            # Verify the data has not been tampered with since saved to the database
            if self.hby.signator.verify(ser=note.raw, cigar=cig):
                signal = dict(
                    action="rem",
                    dt=nowIso8601(),
                    note=note.pad,
                )
                self.signaler.push(attrs=signal, topic="/notification", ckey="/notification")

        return True

    def mar(self, rid):
        """Mark a notice as read.

        Retrieves the notice and verifies its stored signature before mutating
        it. Sets the read flag to ``True``, re-signs the updated notice, and
        persists it via :meth:`Noter.update`. Pushes a ``"mar"`` signal on
        success.

        Args:
            rid (str): QB64 identifier of the notice.

        Returns:
            bool: ``True`` if the notice was found, verified, and marked as
                read. ``False`` if the notice does not exist, the signature
                verification fails, the notice was already marked as read, or
                the update fails.
        """
        res = self.noter.get(rid=rid)
        if res is None:
            return False

        note, cig = res

        # Verify the data has not been tampered with since saved to the database
        if not self.hby.signator.verify(ser=note.raw, cigar=cig):
            return False

        # If note has already been read, this did not change it
        if note.read:
            return False

        note.read = True
        cig = self.hby.signator.sign(ser=note.raw)
        if self.noter.update(note, cig):
            signal = dict(
                action="mar",
                dt=nowIso8601(),
                note=note.pad,
            )
            self.signaler.push(attrs=signal, topic="/notification", ckey="/notification")

            return True

        return False

    def getNoteCnt(self):
        """Return the total number of notices.

        Returns:
            int: Number of notices in the backing store.
        """
        return self.noter.getNoteCnt()

    def getNotes(self, start=0, end=24):
        """Retrieve notices with signature verification.

        Delegates to :meth:`Noter.getNotes` and verifies the signature of
        every returned notice.

        Args:
            start (int, optional): Zero-based count of notices to skip before
                collecting. Defaults to ``0``.
            end (int, optional): Inclusive upper bound passed to
                :meth:`Noter.getNotes` controlling how many notices are
                returned. Defaults to ``24``.

        Returns:
            list[Notice]: Verified notice instances.

        Raises:
            ValidationError: If the stored signature for any notice is invalid.
        """
        notesigs = self.noter.getNotes(start, end)
        notes = []
        for note, cig in notesigs:
            if not self.hby.signator.verify(ser=note.raw, cigar=cig):
                raise ValidationError("note stored without valid signature")

            notes.append(note)

        return notes
