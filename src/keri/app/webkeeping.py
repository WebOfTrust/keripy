# -*- encoding: utf-8 -*-
"""
keri.app.webkeeping module

Browser-safe keeper backed by WebDBer storage.
"""

import asyncio
from uuid import uuid4

from ..core import Cipher, Prefixer, Number
from ..db import (WebDBer, Suber, CryptSignerSuber, CesrSuber,
                  CatCesrIoSetSuber, Komer)

from .basekeeping import PrePrm, PreSit, PubSet


class WebKeeper(WebDBer):
    """
    WebKeeper sets up named browser stores for key pair storage.
    Methods provide key pair creation, storage, and data signing through Manager.

    Attributes:
        name (str): storage namespace differentiator
        temp (bool): True means clear persisted data on close
        env (WebEnv): named store opener used by Subers
        opened (bool): True when the browser stores are open
        gbls (Suber): global parameters keyed by parameter label
        pris (CryptSignerSuber): private signers keyed by public key
        prxs (CesrSuber): encrypted current private keys keyed by public key
        nxts (CesrSuber): encrypted next private keys keyed by public key
        smids (CatCesrIoSetSuber): signing member identifiers keyed by prefix
        rmids (CatCesrIoSetSuber): rotation member identifiers keyed by prefix
        pres (CesrSuber): identifier prefixes keyed by first public key
        prms (Komer): PrePrm prefix parameters keyed by identifier prefix
        sits (Komer): PreSit key state keyed by identifier prefix
        pubs (Komer): PubSet public keys keyed by prefix and rotation index
    """

    def __init__(self, name="main", temp=False, reopen=False,
                 storageOpener=None, **kwa):
        """
        Setup browser-backed key storage.

        Inherited Parameters:
            name is str storage namespace differentiator. Default name='main'.
            temp is boolean, True means clear persisted data on close.
            reopen is boolean. WebKeeper does not support synchronous reopen.

        Parameters:
            storageOpener (callable): async browser storage namespace opener
        """
        if kwa:
            names = ", ".join(sorted(kwa))
            raise TypeError(f"Unsupported WebKeeper parameters: {names}")
        if reopen:
            raise RuntimeError("WebKeeper uses async open; use await reopen().")

        self.name = name
        self._storageName = f"__keripy_temp__:{name}:{uuid4().hex}" if temp else name
        self.temp = temp
        self.env = None
        self.opened = False
        self._storageOpener = storageOpener

    async def reopen(self, clear=False, storageOpener=None):
        """
        Open browser-backed key stores and bind their Subers.

        Parameters:
            clear (bool): True means clear persisted data before opening
            storageOpener (callable): optional async storage namespace opener

        Returns:
            env (WebEnv): named store opener used by Subers
        """
        if self.opened:
            await self.aclose(clear=clear)

        if storageOpener is not None:
            self._storageOpener = storageOpener
        opener = self._storageOpener

        try:
            db = await WebDBer.open(
                name=self._storageName if self.temp else self.name,
                stores=[
                    'gbls.',
                    'pris.',
                    'prxs.',
                    'nxts.',
                    'smids.',
                    'rmids.',
                    'pres.',
                    'prms.',
                    'sits.',
                    'pubs.',
                ],
                clear=clear,
                storageOpener=opener,
                versioned=False,
            )
        except RuntimeError as ex:
            if opener is None:
                raise RuntimeError(
                    "No storage opener available. "
                    "Provide storageOpener=FakeStorageBackend.open in CPython, "
                    "or run under PyScript for IndexedDB."
                ) from ex
            raise

        WebDBer.__init__(self, name=self.name, stores=db._stores)

        self.gbls = Suber(db=self, subkey='gbls.')
        self.pris = CryptSignerSuber(db=self, subkey='pris.')
        self.prxs = CesrSuber(db=self,
                             subkey='prxs.',
                             klas=Cipher)
        self.nxts = CesrSuber(db=self,
                             subkey='nxts.',
                             klas=Cipher)
        self.smids = CatCesrIoSetSuber(db=self,
                                      subkey='smids.',
                                      klas=(Prefixer, Number))
        self.rmids = CatCesrIoSetSuber(db=self,
                                      subkey='rmids.',
                                      klas=(Prefixer, Number))
        self.pres = CesrSuber(db=self,
                             subkey='pres.',
                             klas=Prefixer)
        self.prms = Komer(db=self,
                          subkey='prms.',
                          klas=PrePrm)
        self.sits = Komer(db=self,
                          subkey='sits.',
                          klas=PreSit)
        self.pubs = Komer(db=self,
                          subkey='pubs.',
                          klas=PubSet)

        self._subdb_names = (
            'gbls',
            'pris',
            'prxs',
            'nxts',
            'smids',
            'rmids',
            'pres',
            'prms',
            'sits',
            'pubs',
        )
        self.opened = True
        return self.env

    def close(self, *, clear=False):
        """Flush pending state and close the keeper.

        This synchronous path runs the flush to completion. Callers inside an
        active event loop must use ``await aclose()``.
        """
        if not self.opened:
            return

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "WebKeeper.close() cannot flush inside an active event loop; "
                "use await aclose()."
            )

        if clear or self.temp:
            self.clear()
        asyncio.run(self.flush())
        WebDBer.close(self)

        self.env = None
        self.opened = False

        for name in self._subdb_names:
            try:
                delattr(self, name)
            except AttributeError:
                pass

    async def aclose(self, *, clear=False):
        """Close the keeper and wait for pending writes to flush."""
        if not self.opened:
            return

        if clear or self.temp:
            self.clear()
        await self.flush()
        WebDBer.close(self)

        self.env = None
        self.opened = False

        for name in self._subdb_names:
            try:
                delattr(self, name)
            except AttributeError:
                pass
