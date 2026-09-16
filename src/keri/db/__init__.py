# -*- encoding: utf-8 -*-
"""
KERI
keri.db Package
"""
# ruff: noqa: E402, F401

import sys


IS_PYODIDE = "emscripten" in sys.platform

if IS_PYODIDE:
    from . import basebasing, koming, subing, webdbing
    from .basebasing import (BaserBase, statedict, fetchTsgs, onKey, snKey,
                             dgKey)
    from .webdbing import WebDBer
else:
    from . import basing, dbing, escrowing, koming, subing, webdbing

    from .basing import Baser, BaserDoer, openDB, reopenDB, statedict
    from .dbing import (LMDBer, clearDatabaserDir, openLMDB, onKey,
                        snKey, fnKey, dgKey, dtKey, splitKey, splitOnKey,
                        splitKeyDT, fetchTsgs, suffix, unsuffix,
                        splitKeyFN, SuffixSize, splitSnKey, MaxSuffix)
    from .webdbing import WebDBer
    from .escrowing import Broker

from .koming import KomerBase, Komer, IoSetKomer, DupKomer
from .subing import (SuberBase, Suber, OnSuberBase, OnSuber,
                     B64SuberBase, B64Suber, CesrSuberBase, CesrSuber,
                     CesrOnSuber, CatCesrSuberBase, CatCesrSuber,
                     IoSetSuber, B64IoSetSuber, CesrIoSetSuber,
                     CatCesrIoSetSuber, SignerSuber, CryptSignerSuber,
                     SerderSuberBase, SerderSuber, SerderIoSetSuber,
                     SchemerSuber, DupSuber, CesrDupSuber,
                     CatCesrDupSuber, IoDupSuber, B64IoDupSuber,
                     OnIoDupSuber, B64OnIoDupSuber, OnIoSetSuber,
                     B64OnIoSetSuber)
