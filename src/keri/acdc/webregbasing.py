# -*- encoding: utf-8 -*-
"""
keri.acdc.webregbasing module

Support for WebRegBaser(WebDBer)


"""

import asyncio

from ..core import Diger, Number, Saider, SerderACDC
from ..db import (WebDBer, B64OnIoSetSuber, CatCesrSuber, CesrOnSuber,
                  CesrSuber, SerderSuber)


class WebRegBaser(WebDBer):
    """
    WebRegBaser sets up browser sub databases for public ACDC registry TELs.

    Attributes:
        see superclass WebDBer for inherited attributes

        .evts is named subDB instance of SerderSuber (klas=SerderACDC)
            whose values are serialized ACDC registry events.
            subkey 'evts.'
            Key: registry event SAID.
            Value: SerderACDC instance for a rip or bup event.
            Only one value per DB key is allowed.
            Contains both accepted and escrowed event bodies. Membership does
            not indicate acceptance.

        .ancs is named subDB instance of CatCesrSuber
            (klas=(Number, Diger)) for KEL source seal couples.
            subkey 'ancs.'
            Key: registry event SAID.
            Value: Number and Diger of the KEL event that anchors the registry
            event.
            Only one value per DB key is allowed.

        .tels is named subDB instance of CesrOnSuber (klas=Saider) for the
            accepted transaction event log.
            subkey 'tels.'
            onKey (registry SAID + registry event sequence number)
            Value: SAID of the accepted registry event in .evts.
            Only one value per DB key is allowed.
            Membership is the acceptance commit marker.

        .heads is named subDB instance of CesrSuber (klas=Saider) for the
            current accepted registry heads.
            subkey 'heads.'
            Key: registry SAID.
            Value: SAID of the latest accepted registry event.
            Only one value per DB key is allowed.
            This cache is rebuildable from .tels.

        .maes is named subDB instance of B64OnIoSetSuber for registry events
            escrowed because the KEL anchor is missing.
            subkey 'maes.'
            onKey (registry SAID + registry event sequence number)
            Value: registry event SAID.
            More than one value per effective DB key is allowed in insertion
            order without dupsort.

        .ooes is named subDB instance of B64OnIoSetSuber for out-of-order
            registry event escrows.
            subkey 'ooes.'
            onKey (registry SAID + registry event sequence number)
            Value: registry event SAID.
            More than one value per effective DB key is allowed in insertion
            order without dupsort.

    """

    StoragePrefix = "acdc-reg"

    def __init__(self, name="main", reopen=False, temp=False, **kwa):
        """
        Setup names for browser sub databases.

        Parameters:
            name (str): registry database name
            reopen (bool): retained for interface parity with LMDBer
            temp (bool): True means clear database on close
            **kwa (dict): retained for interface parity with LMDBer

        """
        SubDbNames = [
            "evts.",
            "ancs.",
            "tels.",
            "heads.",
            "maes.",
            "ooes.",
        ]
        self.SubDbNames = SubDbNames

        self.name = name
        self._version = None
        self.opened = False
        self.temp = temp
        self.db = None
        self.env = None

    async def reopen(self, *, clear=False, storageOpener=None):
        """
        Open browser database and setup named sub databases.

        Parameters:
            clear (bool): True means clear persisted data before opening
            storageOpener (callable | None): async browser storage opener

        """
        if storageOpener is not None:
            self._storageOpener = storageOpener
        opener = getattr(self, "_storageOpener", None)

        adapterName = f"{self.StoragePrefix}:{self.name}"
        self.db = await WebDBer.open(
            name=adapterName,
            stores=self.SubDbNames,
            clear=clear or self.temp,
            storageOpener=opener,
        )
        self.env = self.db.env

        _before = set(self.__dict__)
        # Create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.
        self.evts = SerderSuber(db=self, subkey='evts.', klas=SerderACDC)
        self.ancs = CatCesrSuber(db=self, subkey='ancs.',
                                klas=(Number, Diger))
        self.tels = CesrOnSuber(db=self, subkey='tels.', klas=Saider)
        self.heads = CesrSuber(db=self, subkey='heads.', klas=Saider)
        self.maes = B64OnIoSetSuber(db=self, subkey='maes.')
        self.ooes = B64OnIoSetSuber(db=self, subkey='ooes.')
        self._subdb_names = set(self.__dict__) - _before

        self.opened = True

    def close(self, *, clear=False):
        """
        Close browser database and schedule pending writes for persistence.

        Parameters:
            clear (bool): True means clear persisted data before close

        """
        if not self.opened or self.db is None:
            return

        if clear or self.temp:
            for subdb in self.db._stores.values():
                subdb.items.clear()
                subdb.dirty = True

        db = self.db
        self.db = None
        self.env = None
        self.opened = False

        for name in getattr(self, "_subdb_names", ()):
            try:
                delattr(self, name)
            except AttributeError:
                pass

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(db.flush())
        except RuntimeError:
            pass

    async def aclose(self, *, clear=False):
        """
        Flush pending writes and close browser database.

        Parameters:
            clear (bool): True means clear persisted data before close

        """
        if not self.opened or self.db is None:
            return

        if clear or self.temp:
            for subdb in self.db._stores.values():
                subdb.items.clear()
                subdb.dirty = True

        await self.db.flush()
        self.db = None
        self.env = None
        self.opened = False

        for name in getattr(self, "_subdb_names", ()):
            try:
                delattr(self, name)
            except AttributeError:
                pass
