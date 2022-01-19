# -*- encoding: utf-8 -*-
"""
keri.vc.proving module

"""

import json
from collections.abc import Iterable
from typing import Union

import cbor2 as cbor
import msgpack

from .. import help, kering
from ..core import coring
from ..core.coring import (Serials, sniff, Versify, Deversify, Rever, Saider, Ids)
from ..db import subing
from ..kering import Version, VersionError, ShortageError, DeserializationError

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
    """
    Returns Credentialer of new credential
        schema is SAID of schema for this credential
        issuer is the identifier prefix of the issuer
        subject is dict of the values being assigned to the subject of this credential
        source is list of source credentials to which this credential is chained
        version is Version instance
        kind is serialization kind

    """
    vs = Versify(ident=coring.Idents.acdc, version=version, kind=kind, size=0)

    source = source if source is not None else []

    vc = dict(
        v=vs,
        d="",
        s=schema,
        i=issuer,
        a={},
        p=source
    )

    if status is not None:
        subject["ri"] = status

    if rules is not None:
        vc["r"] = rules

    _, sad = coring.Saider.saidify(sad=subject, kind=kind, label=coring.Ids.d)
    vc["a"] = sad

    _, vc = coring.Saider.saidify(sad=vc)

    return Credentialer(ked=vc)


class Credentialer(coring.Sadder):
    """
    Credentialer is for creating a W3C Verifiable Credential embedded in a CESR Proof Format
    proof

    """

    def __init__(self, raw=b'', ked=None, kind=None, sad=None, code=coring.MtrDex.Blake3_256):
        """
        Creates a serializer/deserializer for a Verifiable Credential in CESR Proof Format

        requires either raw or (crd and kind) to load credential from serialized form or in memory

        Parameters:
            raw (bytes) is raw credential
            ked (dict) is populated credential
            sad (Sadder) is clonable base class
            typ is schema type
            version is Version instance
            kind is serialization kind

        """
        super(Credentialer, self).__init__(raw=raw, ked=ked, kind=kind, sad=sad, code=code)

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
        return self._ked["a"]["ri"]


class CrederSuber(subing.Suber):
    """
    Sub class of Suber where data is serialized Credentialer instance
    Automatically serializes and deserializes using Credentialer methods

    """

    def __init__(self, *pa, **kwa):
        """
        Parameters:
            db (dbing.LMDBer): base db
            subkey (str):  LMDB sub database key
        """
        super(CrederSuber, self).__init__(*pa, **kwa)

    def put(self, keys: Union[str, Iterable], val: Credentialer):
        """
        Puts val at key made from keys. Does not overwrite

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Credentialer): instance

        Returns:
            result (bool): True If successful, False otherwise, such as key
                              already in database.
        """
        return (self.db.putVal(db=self.sdb,
                               key=self._tokey(keys),
                               val=val.raw))

    def pin(self, keys: Union[str, Iterable], val: Credentialer):
        """
        Pins (sets) val at key made from keys. Overwrites.

        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            val (Credentialer): instance

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
            Credentialer:
            None: if no entry at keys

        Usage:
            Use walrus operator to catch and raise missing entry
            if (creder := mydb.get(keys)) is None:
                raise ExceptionHere
            use creder here

        """
        val = self.db.getVal(db=self.sdb, key=self._tokey(keys))
        return Credentialer(raw=bytes(val)) if val is not None else None

    def rem(self, keys: Union[str, Iterable]):
        """
        Removes entry at keys

        Parameters:
            keys (tuple): of key strs to be combined in order to form key

        Returns:
           result (bool): True if key exists so delete successful. False otherwise
        """
        return self.db.delVal(db=self.sdb, key=self._tokey(keys))

    def getItemIter(self, keys: Union[str, Iterable] = b""):
        """
        Return iterator over the all the items in subdb

        Returns:
            iterator: of tuples of keys tuple and val coring.Serder for
            each entry in db

        """
        for key, val in self.db.getTopItemIter(db=self.sdb, key=self._tokey(keys)):
            yield self._tokeys(key), Credentialer(raw=bytes(val))


def findPath(said, sad):
    if not isinstance(sad, dict) or 'd' not in sad:
        raise kering.ValidationError("Not valid SAD")

    if said == sad:
        return "-"
