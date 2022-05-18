# -*- encoding: utf-8 -*-
"""
keri.vc.proving module

"""

from collections.abc import Iterable
from typing import Union

from .. import help
from ..core import coring
from ..core.coring import (Serials, Versify)
from ..db import subing
from ..kering import Version

KERI_REGISTRY_TYPE = "KERICredentialRegistry"

logger = help.ogler.getLogger()


def credential(schema,
               issuer,
               subject,
               status=None,
               source=None,
               rules=None,
               version=Version,
               kind=Serials.json):
    """ Returns Credentialer of new credential

    Creates SAD for credential and Saidifyies it before creation.

    Parameters:
        schema (SAID): of schema for this credential
        issuer (str): qb64 identifier prefix of the issuer
        status (str): qb64 said of the credential registry
        subject (dict): of the values being assigned to the subject of this credential
        source (Optional[dict,list]): of source credentials to which this credential is chained
        rules (list): ACDC rules section for credential
        version (Version): version instance
        kind (Serials): serialization kind

    Returns:
        Creder: credential instance

    """
    vs = Versify(ident=coring.Idents.acdc, version=version, kind=kind, size=0)

    source = source if source is not None else {}

    vc = dict(
        v=vs,
        d="",
        i=issuer,
    )

    if status is not None:
        vc["ri"] = status

    vc |= dict(
        s=schema,
        a={},
        e=source,
    )

    if rules is not None:
        vc["r"] = rules

    _, sad = coring.Saider.saidify(sad=subject, kind=kind, label=coring.Ids.d)
    vc["a"] = sad

    _, vc = coring.Saider.saidify(sad=vc)

    return Creder(ked=vc)


class Creder(coring.Sadder):
    """ Creder is for creating ACDC chained credentials

    Sub class of Sadder that adds credential specific validation and properties

    Inherited Properties:
        .raw is bytes of serialized event only
        .ked is key event dict
        .kind is serialization kind string value (see namedtuple coring.Serials)
        .version is Versionage instance of event version
        .size is int of number of bytes in serialed event only
        .diger is Diger instance of digest of .raw
        .dig  is qb64 digest from .diger
        .digb is qb64b digest from .diger
        .verfers is list of Verfers converted from .ked["k"]
        .werfers is list of Verfers converted from .ked["b"]
        .tholder is Tholder instance from .ked["kt'] else None
        .sn is int sequence number converted from .ked["s"]
        .pre is qb64 str of identifier prefix from .ked["i"]
        .preb is qb64b bytes of identifier prefix from .ked["i"]
        .said is qb64 of .ked['d'] if present
        .saidb is qb64b of .ked['d'] of present

    Properties:
        .crd (dict): synonym for .ked
        .issuer (str): qb64 identifier prefix of credential issuer
        .schema (str): qb64 SAID of JSONSchema for credential
        .subject (str): qb64 identfier prefix of credential subject
        .status (str): qb64 identfier prefix of issuance / revocation registry

    """

    def __init__(self, raw=b'', ked=None, kind=None, sad=None, code=coring.MtrDex.Blake3_256):
        """ Creates a serializer/deserializer for a ACDC Verifiable Credential in CESR Proof Format

        Requires either raw or (crd and kind) to load credential from serialized form or in memory

        Parameters:
            raw (bytes): is raw credential
            ked (dict): is populated credential
            kind (is serialization kind
            sad (Sadder): is clonable base class
            code (MtrDex): is hashing codex

        """
        super(Creder, self).__init__(raw=raw, ked=ked, kind=kind, sad=sad, code=code)

        if self._ident != coring.Idents.acdc:
            raise ValueError("Invalid ident {}, must be ACDC".format(self._ident))

    @property
    def crd(self):
        """ issuer property getter"""
        return self._ked

    @property
    def issuer(self):
        """ issuer property getter"""
        return self._ked["i"]

    @property
    def schema(self):
        """ schema property getter"""
        return self._ked["s"]

    @property
    def subject(self):
        """ subject property getter"""
        return self._ked["a"]

    @property
    def status(self):
        """ status property getter"""
        if "ri" in self._ked:
            return self._ked["ri"]
        else:
            return None


class CrederSuber(subing.Suber):
    """ Data serialization for Creder

    Sub class of Suber where data is serialized Creder instance
    Automatically serializes and deserializes using Creder methods

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key

        """
        super(CrederSuber, self).__init__(*pa, **kwa)

    def put(self, keys: Union[str, Iterable], val: Creder):
        """ Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Creder): instance

        Returns:
            bool: True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def pin(self, keys: Union[str, Iterable], val: Creder):
        """ Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Creder): instance

        Returns:
            bool: True If successful. False otherwise.
        """
        return (self.db.setVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def get(self, keys: Union[str, Iterable]):
        """ Gets Credentialer at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
            Creder: instance at keys
            None: if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (creder := mydb.get(keys)) is None:
                raise ExceptionHere
            use creder here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return Creder(raw=bytes(val)) if val is not None else None

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
        for key, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield self._tokeys(key), Creder(raw=bytes(val))
