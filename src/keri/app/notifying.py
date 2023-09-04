# -*- encoding: utf-8 -*-
"""
keri.app.notifying module

"""
import datetime
from collections.abc import Iterable
from typing import Union, Type

from keri import kering
from keri.help import helping
from keri.app import signaling
from keri.core import coring
from keri.db import dbing, subing


def notice(attrs, dt=None, read=False):
    """

    Parameters:
        attrs (dict): payload of the notice
        dt(Optional(str, datetime)): iso8601 formatted datetime of notice
        read (bool): message read indicator

    Returns:
        Notice:  Notice instance

    """
    dt = dt if dt is not None else helping.nowIso8601()

    if hasattr(dt, "isoformat"):
        dt = dt.isoformat()

    pad = dict(i="",
               dt=dt,
               r=read,
               a=attrs
               )

    return Notice(pad=pad)


class Notice(coring.Dicter):
    """ Notice is for creating notification messages for the controller of the agent

    Sub class of Sadder that adds notification specific validation and properties

    Inherited Properties:
        .raw is bytes of serialized event only
        .pad is key event dict

    Properties:
        .datetime (str): ISO8601 formatted datetime of notice
        .pad (dict): payload of the notice

    """

    def __init__(self, raw=b'', pad=None, note=None):
        """ Creates a serializer/deserializer for a ACDC Verifiable Credential in CESR Proof Format

        Requires either raw or (crd and kind) to load credential from serialized form or in memory

        Parameters:
            raw (bytes): is raw credential
            pad (dict): is populated data

        """
        super(Notice, self).__init__(raw=raw, pad=pad, sad=note)

        if "a" not in self._pad:
            raise ValueError(f"invalid notice, missing attributes in {pad}")

        if "dt" not in self._pad:
            self._pad["dt"] = datetime.datetime.now().isoformat()

    @property
    def datetime(self):
        """ issuer property getter"""
        return self._pad["dt"]

    @property
    def attrs(self):
        """ pad property getter"""
        return self._pad["a"]

    @property
    def read(self):
        """ read property getter """
        return self._pad["r"]

    @read.setter
    def read(self, val):
        """ read property setter """
        pad = self.pad
        pad["r"] = val
        self.pad = pad


class DicterSuber(subing.Suber):
    """ Data serialization for Sadder and subclasses

    Sub class of Suber where data is serialized Sadder instance or subclass
    Automatically serializes and deserializes using Sadder methods

    """

    def __init__(self, *pa, klas: Type[coring.Dicter] = coring.Dicter, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key

        """
        super(DicterSuber, self).__init__(*pa, **kwa)
        self.klas = klas

    def put(self, keys: Union[str, Iterable], val: coring.Dicter):
        """ Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Sadder): instance

        Returns:
            bool: True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def pin(self, keys: Union[str, Iterable], val: coring.Dicter):
        """ Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Sadder): instance

        Returns:
            bool: True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def get(self, keys: Union[str, Iterable]):
        """ Gets Sadder at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            Sadder: instance at keys
            None: if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (creder := mydb.get(keys)) is None:
                raise ExceptionHere
            use creder here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return self.klas(raw=bytes(val)) if val is not None else None

    def rem(self, keys: Union[str, Iterable]):
        """ Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           bool: True if key exists so delete successful. False otherwise
        """
        return self.db.delVal(db=self.sdb, key=self._tokey(keys))

    def getItemIter(self, keys: Union[str, Iterable] = b""):
        """ Return iterator over the all the items in subdb

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder for
            each entry in db

        """
        for key, val in self.db.getAllItemIter(db=self.sdb, key=self._tokey(keys), split=False):
            yield self._tokeys(key), self.klas(raw=bytes(val))

    def cntAll(self):
        """
        Return count over the all the items in subdb

        Returns:
            count of all items
        """
        return self.db.cnt(db=self.sdb)


class Noter(dbing.LMDBer):
    """
    Noter stores Notifications generated by the agent that are
    intended to be read and dismissed by the controller of the agent.

    """
    TailDirPath = "keri/not"
    AltTailDirPath = ".keri/not"
    TempPrefix = "keri_not_"

    def __init__(self, name="not", headDirPath=None, reopen=True, **kwa):
        """

        Parameters:
            headDirPath:
            perm:
            reopen:
            kwa:
        """
        self.notes = None
        self.nidx = None
        self.ncigs = None

        super(Noter, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """

        :param kwa:
        :return:
        """
        super(Noter, self).reopen(**kwa)

        self.notes = DicterSuber(db=self, subkey='nots.', sep='/', klas=Notice)
        self.nidx = subing.Suber(db=self, subkey='nidx.')
        self.ncigs = subing.CesrSuber(db=self, subkey='ncigs.', klas=coring.Cigar)

        return self.env

    def add(self, note, cigar):
        """
        Adds note to database, keyed by the datetime and said of the note.

        Parameters:
            note (Notice): sad message content
            cigar (Cigar): non-transferable signature over note

        """
        dt = note.datetime
        rid = note.rid
        if self.nidx.get(keys=(rid,)) is not None:
            return False

        self.nidx.pin(keys=(rid,), val=dt.encode())
        self.ncigs.pin(keys=(rid,), val=cigar)
        return self.notes.pin(keys=(dt, rid), val=note)

    def update(self, note, cigar):
        """
        Adds note to database, keyed by the datetime and said of the note.

        Parameters:
            note (Notice): sad message content
            cigar (Cigar): non-transferable signature over note

        """
        dt = note.datetime
        rid = note.rid
        if self.nidx.get(keys=(rid,)) is None:
            return False

        self.nidx.pin(keys=(rid,), val=dt.encode())
        self.ncigs.pin(keys=(rid,), val=cigar)
        return self.notes.pin(keys=(dt, rid), val=note)

    def get(self, rid):
        """
        Adds note to database, keyed by the datetime and said of the note.

        Parameters:
            rid (str): qb64 random ID of note to get

        Returns:
            (Notice, Cigar) = couple of notice object and accompanying signature

        """
        dt = self.nidx.get(keys=(rid,))
        if dt is None:
            return None

        note = self.notes.get(keys=(dt, rid))
        cig = self.ncigs.get(keys=(rid,))

        return note, cig

    def rem(self, rid):
        """
        Remove note from database if it exists

        Parameters:
            rid (str): qb64 random ID of note to remove

        Returns:
            bool:  True if deleted
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
        """
        Return count over the all Notes

        Returns:
            int: count of all items

        """
        return self.notes.cntAll()

    def getNotes(self, start=0, end=25):
        """
        Returns list of tuples (note, cigar) of notes for controller of agent

        Parameters:
            start (int): number of item to start
            end (int): number of last item to return

        """
        if hasattr(start, "isoformat"):
            start = start.isoformat()

        notes = []
        it = self.notes.getItemIter(keys=())

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
    """ Class for sending notifications to the controller of an agent.

    The notifications are not just signals to reload data and not persistent messages that can be reread

    """

    def __init__(self, hby, signaler=None, noter=None):
        """

        Parameters:
            hby (Habery): habery database environment with Signator
            noter (Noter): database
            signaler (Signaler): signaler for sending signals to controller that new data is available

        """
        self.hby = hby
        self.signaler = signaler if signaler is not None else signaling.Signaler()
        self.noter = noter if noter is not None else Noter(name=hby.name, temp=hby.temp)

    def add(self, attrs):
        """  Add unread notice to the end of the current list of notices

        Args:
            attrs (dict): body of a new unread notice to append to the current list of notices

        Returns:
            bool: returns True if the notice was added

        """

        note = notice(attrs, dt=datetime.datetime.now())
        cig = self.hby.signator.sign(ser=note.raw)
        if self.noter.add(note, cig):
            signal = dict(
                action="add",
                dt=helping.nowIso8601(),
                note=note.pad,
            )
            self.signaler.push(attrs=signal, topic="/notification", ckey="/notification")
            return True
        else:
            return False

    def rem(self, rid):
        """ Mark as Read

        Delete the note identified by the provided random ID

        Parameters:
            rid (str): qb64 random ID of the Note to delete

        Returns:
            bool: True means the note was deleted, False otherwise
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
                    dt=helping.nowIso8601(),
                    note=note.pad,
                )
                self.signaler.push(attrs=signal, topic="/notification", ckey="/notification")

        return True

    def mar(self, rid):
        """ Mark as Read

        Mark the note identified by the provided SAID as having been read by the controller of the agent

        Parameters:
            rid (str): qb64 random ID of the Note to mark as read

        Returns:
            bool: True means the note was marked as read, False otherwise

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
                dt=helping.nowIso8601(),
                note=note.pad,
            )
            self.signaler.push(attrs=signal, topic="/notification", ckey="/notification")

            return True

        return False

    def getNoteCnt(self):
        """
        Return count over the all Notes

        Returns:
            int: count of all items

        """
        return self.noter.getNoteCnt()

    def getNotes(self, start=0, end=24):
        """
        Returns list of tuples (note, cigar) of notes for controller of agent

        Parameters:
            start (int): number of item to start
            end (int): number of last item to return

        """
        notesigs = self.noter.getNotes(start, end)
        notes = []
        for note, cig in notesigs:
            if not self.hby.signator.verify(ser=note.raw, cigar=cig):
                raise kering.ValidationError("note stored without valid signature")

            notes.append(note)

        return notes
