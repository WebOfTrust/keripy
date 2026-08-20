# -*- encoding: utf-8 -*-
"""
keri.acdc.registering module

Register database to store registry events. High level abstraction of
RegBaser(lmdb) and WebRegBaser(IndexedDB)

"""

from dataclasses import dataclass

from ..db import Komer
from ..kering import ConfigurationError
from ..core import Saider
from .regbasing import RegBaser
from .webregbasing import WebRegBaser


@dataclass
class RegistryRecord:
    """Persisted local registry data."""

    registryKey: str


def openRegistry(*, web=False, reopen=True, **kwa):
    """Open the backing store used by the V2 ACDC registry service."""
    if web:
        raise ConfigurationError("web registry backend is not yet supported by V2 Regery")
    return RegBaser(reopen=reopen, **kwa)


class RegistryStore:
    """Small convenience wrapper around RegBaser/WebRegBaser."""

    def __init__(self, baser):
        if isinstance(baser, WebRegBaser):
            raise ConfigurationError("web registry backend is not yet supported by V2 Regery")
        self.baser = baser
        self.records = Komer(db=self.baser, subkey='regs.', klas=RegistryRecord)

    @property
    def opened(self):
        return self.baser.opened

    def close(self):
        self.baser.close()

    def event(self, said):
        return self.baser.evts.get(keys=said)

    def putEvent(self, serder):
        return self.baser.evts.pin(keys=serder.said, val=serder)

    def anchor(self, said):
        return self.baser.ancs.get(keys=said)

    def putAnchor(self, said, number, diger):
        return self.baser.ancs.pin(keys=said, val=(number, diger))

    def head(self, regk):
        return self.baser.heads.get(keys=regk)

    def headEvent(self, regk):
        saider = self.head(regk)
        return self.event(saider.qb64) if saider is not None else None

    def seqSaider(self, regk, sn):
        return self.baser.tels.get(keys=regk, on=sn)

    def seqEvent(self, regk, sn):
        saider = self.seqSaider(regk, sn)
        return self.event(saider.qb64) if saider is not None else None

    def accept(self, regk, sn, serder):
        saider = Saider(qb64=serder.said)
        self.putEvent(serder)
        self.baser.tels.put(keys=regk, on=sn, val=saider)
        self.baser.heads.pin(keys=regk, val=saider)

    def escrowMissingAnchor(self, regk, sn, said):
        return self.baser.maes.add(keys=regk, on=sn, val=said)

    def escrowOutOfOrder(self, regk, sn, said):
        return self.baser.ooes.add(keys=regk, on=sn, val=said)

    def clearEscrows(self, regk, sn, said):
        self.baser.maes.rem(keys=regk, on=sn, val=said)
        self.baser.ooes.rem(keys=regk, on=sn, val=said)
