from orderedset import OrderedSet as oset


class Organizer:
    """ Organizes contacts relating contact information to AIDs """

    def __init__(self, db):
        """ Create contact Organizer

        Parameters:
            db (Baser): database for contact information
        """
        self.db = db

    def update(self, pre, data):
        """ Add or update contact information in data for the identfier prefix

        Parameters:
            pre (str): qb64 identifier prefix of contact information to update
            data (dict): data to add to or update in contact information

        """
        for field, val in data.items():
            self.db.cons.pin(keys=(pre, field), val=val)

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
        self.db.cons.pin(keys=(pre, field), val=val)

    def unset(self, pre, field):
        """ Remove field from contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact
            field (str): field to remove

        """
        self.db.cons.rem(keys=(pre, field))

    def rem(self, pre):
        """ Remove all contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact to remove

        Returns:

        """
        return self.db.cons.trim(keys=(pre,))

    def get(self, pre):
        """ Retrieve all contact information for identifier prefix

        Parameters:
            pre (str): qb64 identifier prefix for contact

        Returns:
            dict: Contact data

        """
        data = dict()
        for (pre, field), val in self.db.cons.getItemIter(keys=(pre,)):
            data[field] = val

        if len(data) == 0:
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
        for (pre, field), val in self.db.cons.getItemIter():
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
            val (Union[str,bytes]): value to search for

        Returns:
            list: All contacts that match the val in field

        """
        pres = []
        for (pre, f), v in self.db.cons.getItemIter():
            if f == field and v == val:
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
        for (pre, f), v in self.db.cons.getItemIter():
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
        self.db.delTopVal(db=self.db.imgs, key=pre.encode("utf-8"))

        key = f"{pre}.content-type".encode("utf-8")
        self.db.setVal(db=self.db.imgs, key=key, val=typ.encode("utf-8"))

        idx = 0
        size = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            key = f"{pre}.{idx}".encode("utf-8")
            self.db.setVal(db=self.db.imgs, key=key, val=chunk)
            idx += 1
            size += len(chunk)

        key = f"{pre}.content-length".encode("utf-8")
        self.db.setVal(db=self.db.imgs, key=key, val=size.to_bytes(4, "big"))

    def getImgData(self, pre):
        """ Get image metadata for identifier image if one exists

            Parameters:
                pre (str): qb64 identifier prefix for image

            Returns:
                dict: image metadata including length and type

        """
        key = f"{pre}.content-length".encode("utf-8")
        size = self.db.getVal(db=self.db.imgs, key=key)
        if size is None:
            return None

        key = f"{pre}.content-type".encode("utf-8")
        typ = self.db.getVal(db=self.db.imgs, key=key)
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
            chunk = self.db.getVal(db=self.db.imgs, key=key)
            if not chunk:
                break
            yield bytes(chunk)
            idx += 1


