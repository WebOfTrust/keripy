# -*- encoding: utf-8 -*-
"""
keri.acdc.regbasing module

Support for RegBaser(LMDBer)

"""

import os

from ..core import Diger, Number, Saider, SerderACDC
from ..db import (LMDBer, B64OnIoSetSuber, CatCesrSuber, CesrOnSuber,
                  CesrSuber, SerderSuber)


class RegBaser(LMDBer):
    """
    RegBaser sets up named sub databases for public ACDC registry TELs.

    Attributes:
        see superclass LMDBer for inherited attributes

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
            subkey 'heds.'
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

    TailDirPath = os.path.join("keri", "acdc", "reg")
    AltTailDirPath = os.path.join(".keri", "acdc", "reg")
    TempPrefix = "keri_acdc_reg_"

    def __init__(self, headDirPath=None, reopen=True, **kwa):
        """
        Setup named sub databases.

        Inherited Parameters:
            name (str): directory path name differentiator for main database
            temp (bool): True means use a temporary directory and clear on close
            headDirPath (str | None): optional head directory path for database
            mode (int): numeric permissions for database directory
            reopen (bool): True means reopen database during initialization

        """
        super(RegBaser, self).__init__(headDirPath=headDirPath,
                                      reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """
        Open database and setup named sub databases.

        Parameters:
            **kwa (dict): keyword arguments passed to LMDBer.reopen

        Returns:
            opened (bool): True when database is opened

        """
        super(RegBaser, self).reopen(**kwa)

        self.evts = SerderSuber(db=self, subkey='evts.', klas=SerderACDC)
        self.ancs = CatCesrSuber(db=self, subkey='ancs.',
                                klas=(Number, Diger))
        self.tels = CesrOnSuber(db=self, subkey='tels.', klas=Saider)
        self.heads = CesrSuber(db=self, subkey='heds.', klas=Saider)
        self.maes = B64OnIoSetSuber(db=self, subkey='maes.')
        self.ooes = B64OnIoSetSuber(db=self, subkey='ooes.')

        return self.opened
