# -*- encoding: utf-8 -*-
"""
KERI
keri.base.basing module
Support for application data via an LMDB keyspace object mapper (KOM)
"""

import json
from dataclasses import dataclass, asdict
from typing import Type

import cbor2
import msgpack

from ..core.coring import Serials
from ..db import dbing
from ..help import helping


class Komer:
    """
    Keyspace Object Mapper factory class
    """

    def __init__(self,
                 db: Type[dbing.LMDBer],
                 schema: Type[dataclass],
                 subdb: str = 'docs.',
                 kind: str = Serials.json):
        """
        Parameters:
            db (dbing.LMDBer): base db
            schema (dataclass):  reference to Class definition for dataclass sub class
            subdb (str):  LMDB sub database key
            kind (str): serialization/deserialization type
        """
        self.db = db
        self.schema = schema
        self.sdb = self.db.env.open_db(key=subdb.encode("utf-8"))
        self.kind = kind
        self.serializer = self._serializer(kind)
        self.deserializer = self._deserializer(kind)

    def put(self, keys: tuple, data: dataclass):
        """
        Parameters:
            keys (tuple): of key strs to be combined in order to form key
            data (dataclass): instance of dataclass of type self.schema as value
        """
        if not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))

        self.db.putVal(db=self.sdb,
                       key=":".join(keys).encode("utf-8"),
                       val=self.serializer(data))

    def get(self, keys: tuple):
        """
        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """

        data = helping.datify(self.schema, self.deserializer(self.db.getVal(db=self.sdb,
                                                                            key=":".join(keys).encode("utf-8"))))

        if data is None:
            return

        if not isinstance(data, self.schema):
            raise ValueError("Invalid schema type={} of data={}, expected {}."
                             "".format(type(data), data, self.schema))

        return data

    def rem(self, keys: tuple):
        """
        Parameters:
            keys (tuple): of key strs to be combined in order to form key
        """
        self.db.delVal(db=self.sdb,
                       key=":".join(keys).encode("utf-8"))

    def _serializer(self, kind):
        """
        Parameters:
            kind (str): serialization
        """
        if kind == Serials.mgpk:
            return self.__serializeMGPK
        elif kind == Serials.cbor:
            return self.__serializeCBOR
        else:
            return self.__serializeJSON

    def _deserializer(self, kind):
        """
        Parameters:
            kind (str): deserialization
        """
        if kind == Serials.mgpk:
            return self.__deserializeMGPK
        elif kind == Serials.cbor:
            return self.__deserializeCBOR
        else:
            return self.__deserializeJSON

    @staticmethod
    def __deserializeJSON(val):
        if val is None:
            return
        return json.loads(bytes(val).decode("utf-8"))

    @staticmethod
    def __deserializeMGPK(val):
        if val is None:
            return
        return msgpack.loads(bytes(val))

    @staticmethod
    def __deserializeCBOR(val):
        if val is None:
            return
        return cbor2.loads(bytes(val))

    @staticmethod
    def __serializeJSON(val):
        if val is None:
            return
        return json.dumps(asdict(val), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def __serializeMGPK(val):
        if val is None:
            return
        return msgpack.dumps(asdict(val))

    @staticmethod
    def __serializeCBOR(val):
        if val is None:
            return
        return cbor2.dumps(asdict(val))
