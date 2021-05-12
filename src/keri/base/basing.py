# -*- encoding: utf-8 -*-
"""
KERI
keri.base.basing module
Support for application data via an LMDB keyspace object mapper (KOM)
"""

import json
import msgpack

from typing import Type
from dataclasses import dataclass, asdict, field

from ..help import helping
from ..db import dbing


class Komer():
    """
    Keyspace Object Mapper factory class
    """
    def __init__(self,
                 db: Type[dbing.LMDBer],
                 schema: Type[dataclass],
                 subdb: str='docs.',
                 kind: str='JSON'):
        """
        Parameters:
            schema (dataclass):  reference to Class definition for dataclass sub class
            subdb (str):  LMDB sub database key
        """
        self.db = db
        self.schema = schema
        self.sdb = self.db.env.open_db(key=subdb.encode("utf-8"))
        self.kind = kind

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
                       val=json.dumps(asdict(data)).encode("utf-8") )
