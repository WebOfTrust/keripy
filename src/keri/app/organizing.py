# -*- encoding: utf-8 -*-
"""
KERI
keri.app.organizing module

"""
import re
import json

from ordered_set import OrderedSet as oset

from ..kering import ValidationError


class BaseOrganizer:
    """Base class for organizing contact or identifier information."""

    def __init__(self, hby, cigsdb, datadb, fielddb, imgsdb):
        """Create base Organizer.

        Args:
            hby (Habery): database environment.
            cigsdb (SuberBase): database for storing signatures.
            datadb (SuberBase): database for storing main data.
            fielddb (SuberBase): database for storing individual fields.
            imgsdb (SuberBase): database for storing images.
        """
        self.hby = hby
        self.cigsdb = cigsdb
        self.datadb = datadb
        self.fielddb = fielddb
        self.imgsdb = imgsdb

    def update(self, pre, data):
        """Merge data into existing record for identifier prefix.

        If no record exists for ``pre``, a new one is created. Existing
        fields not present in ``data`` are preserved.

        Args:
            pre (str): qb64 identifier prefix of the record to update.
            data (dict): fields to add or overwrite in the existing record.
        """
        existing = self.get(pre)
        if existing is None:
            existing = dict()

        existing |= data

        raw = json.dumps(existing).encode("utf-8")
        cigar = self.hby.signator.sign(ser=raw)

        self.cigsdb.pin(keys=(pre,), val=cigar)
        self.datadb.pin(keys=(pre,), val=raw)

        for field, val in data.items():
            self.fielddb.pin(keys=(pre, field), val=val)

    def replace(self, pre, data):
        """Replace all stored data for identifier prefix with data.

        Removes the existing record entirely before writing ``data``,
        so fields absent from ``data`` will no longer exist.

        Args:
            pre (str): qb64 identifier prefix of the record to replace.
            data (dict): fields to write as the new record.
        """
        self.rem(pre)
        self.update(pre, data)

    def set(self, pre, field, val):
        """Set a single field value for identifier prefix.

        Retrieves the current record, updates the specified field, then
        replaces the full record.

        Args:
            pre (str): qb64 identifier prefix of the record to update.
            field (str): field name to set.
            val (str | bytes): value to assign to the field.
        """
        data = self.get(pre) or dict()
        data[field] = val
        self.replace(pre, data)
        self.fielddb.pin(keys=(pre, field), val=val)

    def unset(self, pre, field):
        """Remove a single field from the record for identifier prefix.

        Args:
            pre (str): qb64 identifier prefix of the record to modify.
            field (str): field name to remove.
        """
        data = self.get(pre)
        del data[field]
        self.replace(pre, data)
        self.fielddb.rem(keys=(pre, field))

    def rem(self, pre):
        """Remove all stored data for identifier prefix.

        Deletes the signature, main data record, and all field index entries
        associated with ``pre``.

        Args:
            pre (str): qb64 identifier prefix of the record to remove.

        Returns:
            bool: True if field entries were removed, False otherwise.
        """
        self.cigsdb.rem(keys=(pre,))
        self.datadb.rem(keys=(pre,))
        return self.fielddb.trim(keys=(pre,))

    def get(self, pre, field=None):
        """Retrieve stored data for identifier prefix.

        Verifies the stored signature before returning data. Raises
        ``ValidationError`` if verification fails.

        Args:
            pre (str): qb64 identifier prefix of the record to retrieve.
            field (str | None): if provided, return only the value for this
                field rather than the full record.

        Returns:
            dict | str | None: the full data dict (with ``"id"`` set to
            ``pre``) when ``field`` is ``None``; the value of the named field
            when ``field`` is given; or ``None`` if no record exists for
            ``pre`` or the named field is absent.

        Raises:
            ValidationError: if the stored signature does not verify against
                the stored data.
        """
        raw = self.datadb.get(keys=(pre,))
        if raw is None:
            return None
        cigar = self.cigsdb.get(keys=(pre,))

        if not self.hby.signator.verify(ser=raw.encode("utf-8"), cigar=cigar):
            raise ValidationError(f"failed signature on {pre} contact data")

        data = json.loads(raw)
        if data is None:
            return None

        if field is not None:
            return data[field] if field in data else None

        data["id"] = pre
        return data

    def list(self):
        """Return all records for all known identifier prefixes.

        Iterates the field index to reconstruct each record. Records are
        assembled from individual field entries and do not undergo signature
        verification.

        Returns:
            list[dict]: all records, each containing at minimum ``"id"``.
        """
        key = ""
        data = None
        contacts = []
        for (pre, field), val in self.fielddb.getTopItemIter():
            if pre != key:
                if data is not None:
                    contacts.append(data)
                data = dict(id=pre)
                key = pre

            data[field] = val

        if data is not None:
            contacts.append(data)

        return contacts

    def find(self, field, val):
        """Find all records where field contains val as a case-insensitive substring.

        Args:
            field (str): field name to search.
            val (str): substring pattern to match against field values.

        Returns:
            list[dict]: all records whose ``field`` value matches the pattern.
        """
        pres = []
        prog = re.compile(f".*{val}.*", re.I)
        for (pre, f), v in self.fielddb.getTopItemIter():
            if f == field and prog.match(v):
                pres.append(pre)

        return [self.get(pre) for pre in pres]

    def findExact(self, field, val):
        """Find all records where field is an exact case-sensitive match for val.

        Unlike :meth:`find`, which uses a substring regex, this performs strict
        equality comparison suitable for alias lookups where similar names
        (e.g. ``"sally"`` vs ``"sally-direct"``) must not collide.

        Args:
            field (str): field name to search.
            val (str): exact value to match (case-sensitive).

        Returns:
            list[dict]: all records whose ``field`` value equals ``val`` exactly.
        """
        pres = []
        for (pre, f), v in self.fielddb.getTopItemIter():
            if f == field and v == val:
                pres.append(pre)

        return [self.get(pre) for pre in pres]

    def values(self, field, val=None):
        """Return unique values for field across all records.

        Args:
            field (str): field name whose values are collected.
            val (str | None): optional case-insensitive substring filter;
                when provided, only values matching the pattern are included.

        Returns:
            list[str]: deduplicated values found for ``field``, in insertion order.
        """
        prog = re.compile(f".*{val}.*", re.I) if val is not None else None

        vals = oset()
        for (pre, f), v in self.fielddb.getTopItemIter():
            if f == field and (prog is None or prog.match(v)):
                vals.add(v)

        return list(vals)

    def setImg(self, pre, typ, stream):
        """Store image data for identifier prefix.

        Streams image data in 4 KiB chunks into the database. Any previously
        stored image for ``pre`` is removed before writing begins. Content type
        and content length metadata are persisted alongside the chunk data.

        Args:
            pre (str): qb64 identifier prefix the image is associated with.
            typ (str): MIME type of the image (e.g. ``"image/jpeg"``).
            stream (IO[bytes]): readable file-like object yielding image bytes.
        """
        self.hby.db.remTop(db=self.imgsdb.sdb, top=pre.encode("utf-8"))

        key = f"{pre}.content-type".encode("utf-8")
        self.hby.db.setVal(db=self.imgsdb.sdb, key=key, val=typ.encode("utf-8"))

        idx = 0
        size = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            key = f"{pre}.{idx}".encode("utf-8")
            self.hby.db.setVal(db=self.imgsdb.sdb, key=key, val=chunk)
            idx += 1
            size += len(chunk)

        key = f"{pre}.content-length".encode("utf-8")
        self.hby.db.setVal(db=self.imgsdb.sdb, key=key, val=size.to_bytes(4, "big"))

    def getImgData(self, pre):
        """Return image metadata for identifier prefix if an image exists.

        Args:
            pre (str): qb64 identifier prefix of the image to query.

        Returns:
            dict | None: a dict with keys ``"type"`` (str, MIME type) and
            ``"length"`` (int, byte length), or ``None`` if no image is stored
            for ``pre``.
        """
        key = f"{pre}.content-length".encode("utf-8")
        size = self.hby.db.getVal(db=self.imgsdb.sdb, key=key)
        if size is None:
            return None

        key = f"{pre}.content-type".encode("utf-8")
        typ = self.hby.db.getVal(db=self.imgsdb.sdb, key=key)
        if typ is None:
            return None

        return dict(
            type=bytes(typ).decode("utf-8"),
            length=int.from_bytes(size, "big")
        )

    def getImg(self, pre):
        """Yield image data in 4 KiB chunks for identifier prefix.

        Args:
            pre (str): qb64 identifier prefix of the image to retrieve.

        Yields:
            bytes: successive 4 KiB chunks of image data.
        """
        idx = 0
        while True:
            key = f"{pre}.{idx}".encode("utf-8")
            chunk = self.hby.db.getVal(db=self.imgsdb.sdb, key=key)
            if not chunk:
                break
            yield bytes(chunk)
            idx += 1


class Organizer(BaseOrganizer):
    """Organizes contact information relating it to remote AIDs."""

    def __init__(self, hby):
        """Create contact Organizer.

        Args:
            hby (Habery): database environment for contact information.
        """
        super().__init__(
            hby=hby,
            cigsdb=hby.db.ccigs,
            datadb=hby.db.cons,
            fielddb=hby.db.cfld,
            imgsdb=hby.db.imgs
        )


class IdentifierOrganizer(BaseOrganizer):
    """Organizes metadata for local identifiers."""

    def __init__(self, hby):
        """Create identifier Organizer.

        Args:
            hby (Habery): database environment for identifier information.
        """
        super().__init__(
            hby=hby,
            cigsdb=hby.db.icigs,
            datadb=hby.db.sids,
            fielddb=hby.db.ifld,
            imgsdb=hby.db.iimgs
        )
