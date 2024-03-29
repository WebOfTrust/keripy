# -*- encoding: utf-8 -*-
"""
keri.db.dbing module


"""
from keri.db import koming
from keri.db.basing import HabitatRecord


class Upgrader:

    def __init__(self, db):
        self.db = db

        # habitat application state keyed by habitat name, includes prefix
        self.habs = koming.Komer(db=self.db,
                                 subkey='habs.',
                                 schema=HabitatRecord, )

        # habitat application state keyed by habitat namespace + b'\x00' + name, includes prefix
        self.nmsp = koming.Komer(db=self.db,
                                 subkey='nmsp.',
                                 schema=HabitatRecord, )
