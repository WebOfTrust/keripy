# -*- encoding: utf-8 -*-
"""
keri.app.connecting module

"""
import re
import json

from ordered_set import OrderedSet as oset

from keri import kering


class Organizer:
    """ Organizes contacts relating contact information to AIDs """

    def __init__(self, hby):
        """ Create contact Organizer

        Parameters:
            hby (Habery): database environment for contact information
        """
        self.hby = hby

    def update(self, pre, data):
        """ Add or update contact information in data for the identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix of contact information to update
            data (dict): data to add to or update in contact information

        """
        existing = self.get(pre)
        if existing is None:
            existing = dict()

        existing |= data

        raw = json.dumps(existing).encode("utf-8")
        cigar = self.hby.signator.sign(ser=raw)

        self.hby.db.ccigs.pin(keys=(pre,), val=cigar)
        self.hby.db.cons.pin(keys=(pre,), val=raw)

        for field, val in data.items():
            self.hby.db.cfld.pin(keys=(pre, field), val=val)

    def replace(self, pre, data):
        """ Replace all contact information for identifier prefix with data

        Parameters:
            pre (str): qb64 identifier prefix of contact information to replace
            data (dict): data to replace contact information with

        """
        self.rem(pre)
        self.update(pre, data)

    def set(self, pre, field, val):
        """ Add or replace one value in contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact
            field (str): field to set
            val (Union[str,bytes]): data value

        """
        data = self.get(pre) or dict()
        data[field] = val
        self.replace(pre, data)
        self.hby.db.cfld.pin(keys=(pre, field), val=val)

    def unset(self, pre, field):
        """ Remove field from contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact
            field (str): field to remove

        """
        data = self.get(pre)
        del data[field]
        self.replace(pre, data)
        self.hby.db.cfld.rem(keys=(pre, field))

    def rem(self, pre):
        """ Remove all contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact to remove

        Returns:

        """
        self.hby.db.ccigs.rem(keys=(pre,))
        self.hby.db.cons.rem(keys=(pre,))
        return self.hby.db.cfld.trim(keys=(pre,))

    def get(self, pre, field=None):
        """ Retrieve all contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact
            field (str): optional field name to retrieve a single field value

        Returns:
            dict: Contact data

        """
        raw = self.hby.db.cons.get(keys=(pre,))
        if raw is None:
            return None
        cigar = self.hby.db.ccigs.get(keys=(pre,))

        if not self.hby.signator.verify(ser=raw.encode("utf-8"), cigar=cigar):
            raise kering.ValidationError(f"failed signature on {pre} contact data")

        data = json.loads(raw)
        if data is None:
            return None

        if field is not None:
            return data[field] if field in data else None

        data["id"] = pre
        return data

    def list(self):
        """ Return list of all contact information for all remote identifiers

        Returns:
            list: All contact information

        """
        key = ""
        data = None
        contacts = []
        for (pre, field), val in self.hby.db.cfld.getItemIter():
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
        """ Find all contact information for all contacts that have the val in field

        Parameters:
            field (str): field name to search for
            val (Union[str,bytes,list]): value to search for

        Returns:
            list: All contacts that match the val in field

        """
        pres = []
        prog = re.compile(f".*{val}.*", re.I)
        for (pre, f), v in self.hby.db.cfld.getItemIter():
            if f == field and prog.match(v):
                pres.append(pre)

        return [self.get(pre) for pre in pres]

    def values(self, field, val=None):
        """ Find unique values for field in all contacts

        Args:
            field (str): field to load values for
            val (Optional(str|None): optional filter for the value of the grouped field

        Returns:
            list: Unique values from all contacts for field

        """
        prog = re.compile(f".*{val}.*", re.I) if val is not None else None

        vals = oset()
        for (pre, f), v in self.hby.db.cfld.getItemIter():
            if f == field:
                if prog is None or prog.match(v):
                    vals.add(v)

        return list(vals)

    def setImg(self, pre, typ, stream):
        """ Upload image for identifier prefix

        Streams image data in 4k chunks into database and sets content type and content length.
        Performs a full replace of all data for image of specified identifier

        Parameters:
            pre (str): qb64 identifier prefix for image
            typ (str): image content mime type
            stream (file): file-like stream of image data

        """
        self.hby.db.delTopVal(db=self.hby.db.imgs, top=pre.encode("utf-8"))

        key = f"{pre}.content-type".encode("utf-8")
        self.hby.db.setVal(db=self.hby.db.imgs, key=key, val=typ.encode("utf-8"))

        idx = 0
        size = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            key = f"{pre}.{idx}".encode("utf-8")
            self.hby.db.setVal(db=self.hby.db.imgs, key=key, val=chunk)
            idx += 1
            size += len(chunk)

        key = f"{pre}.content-length".encode("utf-8")
        self.hby.db.setVal(db=self.hby.db.imgs, key=key, val=size.to_bytes(4, "big"))

    def getImgData(self, pre):
        """ Get image metadata for identifier image if one exists

            Parameters:
                pre (str): qb64 identifier prefix for image

            Returns:
                dict: image metadata including length and type

        """
        key = f"{pre}.content-length".encode("utf-8")
        size = self.hby.db.getVal(db=self.hby.db.imgs, key=key)
        if size is None:
            return None

        key = f"{pre}.content-type".encode("utf-8")
        typ = self.hby.db.getVal(db=self.hby.db.imgs, key=key)
        if typ is None:
            return None

        return dict(
            type=bytes(typ).decode("utf-8"),
            length=int.from_bytes(size, "big")
        )

    def getImg(self, pre):
        """ Generator that yields image data in 4k chunks for identifier

        Parameters:
            pre (str): qb64 identifier prefix for image

        """
        idx = 0
        while True:
            key = f"{pre}.{idx}".encode("utf-8")
            chunk = self.hby.db.getVal(db=self.hby.db.imgs, key=key)
            if not chunk:
                break
            yield bytes(chunk)
            idx += 1
