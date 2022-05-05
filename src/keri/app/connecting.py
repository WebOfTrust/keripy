import json

from  ordered_set import OrderedSet as oset

from keri import kering
from keri.core import coring, eventing


class Organizer:
    """ Organizes contacts relating contact information to AIDs """

    def __init__(self, hby):
        """ Create contact Organizer

        Parameters:
            db (Baser): database for contact information
        """
        self.hby = hby

    def update(self, alias, pre, data):
        """ Add or update contact information in data for the identfier prefix

        Parameters:
            pre (str): qb64 identifier prefix of contact information to update
            data (dict): data to add to or update in contact information
            alias (str): human readable name of identifier to use to sign the challange/response

        """
        hab = self.hby.habByName(alias)
        if hab is None:
            raise kering.ValidationError(f"alias {alias} is not a valid identifier alias")

        existing = self.get(pre)
        if existing is None:
            existing = dict()

        existing |= data

        raw = json.dumps(existing).encode("utf-8")
        sigers = hab.sign(ser=raw, indexed=True)

        seq = coring.Seqner(sn=hab.kever.lastEst.s)
        self.hby.db.csds.pin(keys=(pre,), val=(hab.kever.prefixer, seq))
        self.hby.db.csigs.pin(keys=(pre,), vals=sigers)
        self.hby.db.cons.pin(keys=(pre,), val=raw)

        for field, val in data.items():
            self.hby.db.cfld.pin(keys=(pre, field), val=val)

    def replace(self, alias, pre, data):
        """ Replace all contact information for identifier prefix with data

        Parameters:
            alias (str): human readable name of identifier to use to sign the challange/response
            pre (str): qb64 identifier prefix of contact information to replace
            data (dict): data to replace contact information with

        """
        self.rem(pre)
        self.update(alias, pre, data)

    def set(self, alias, pre, field, val):
        """ Add or replace one value in contact information for identifier prefix

        Parameters:
            alias (str): human readable name of identifier to use to sign the challange/response
            pre (str): qb64 identifier prefix for contact
            field (str): field to set
            val (Union[str,bytes]): data value

        """
        data = self.get(pre)
        data[field] = val
        self.replace(alias, pre, data)
        self.hby.db.cfld.pin(keys=(pre, field), val=val)

    def unset(self, alias, pre, field):
        """ Remove field from contact information for identifier prefix

        Parameters:
            alias (str): human readable name of identifier to use to sign the challange/response
            pre (str): qb64 identifier prefix for contact
            field (str): field to remove

        """
        data = self.get(pre)
        del data[field]
        self.replace(alias, pre, data)
        self.hby.db.cfld.rem(keys=(pre, field))

    def rem(self, pre):
        """ Remove all contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact to remove

        Returns:

        """
        self.hby.db.csds.rem(keys=(pre,))
        self.hby.db.csigs.rem(keys=(pre,))
        self.hby.db.cons.rem(keys=(pre,))
        return self.hby.db.cfld.trim(keys=(pre,))

    def get(self, pre):
        """ Retrieve all contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact

        Returns:
            dict: Contact data

        """
        raw = self.hby.db.cons.get(keys=(pre,))
        if raw is None:
            return None
        prefixer, seqner = self.hby.db.csds.get(keys=(pre,))
        sigers = self.hby.db.csigs.get(keys=(pre,))

        tholder, verfers = self.hby.resolveVerifiers(pre=prefixer.qb64, sn=seqner.sn)
        ssigers, indices = eventing.verifySigs(raw=raw.encode("utf-8"), sigers=sigers, verfers=verfers)
        if not tholder.satisfy(indices):  # at least one but not enough
            raise kering.ValidationError(f"failed signature on {pre} contact data")

        data = json.loads(raw)
        if data is None:
            return None
        data["id"] = pre

        return data

    def list(self):
        """ Return list of all contact information for all remote identfiers

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
        if not isinstance(val, list):
            val = [val]

        pres = []
        for (pre, f), v in self.hby.db.cfld.getItemIter():
            if f == field and v in val:
                pres.append(pre)

        return [self.get(pre) for pre in pres]

    def values(self, field):
        """ Find unique values for field in all contacts

        Args:
            field (str): field to load values for

        Returns:
            list: Unique values from all contacts for field

        """
        vals = oset()
        for (pre, f), v in self.hby.db.cfld.getItemIter():
            if f == field:
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
        self.hby.db.delTopVal(db=self.hby.db.imgs, key=pre.encode("utf-8"))

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


