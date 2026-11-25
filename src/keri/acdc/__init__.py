# -*- encoding: utf-8 -*-
"""
KERI
keri.acdc Package
"""

import sys

from .messaging import (regcept, blindate, update, acdcmap, acdcatt, acdcagg,
                       sectschema, sectattr, sectaggr, sectedge, sectrule,
                       sectionate,
                       actSchemaDefault, acgSchemaDefault, acmSchemaDefault)

from .ipexing import (Ipex, IpexHandler, loadHandlers, apply, offer, agree,
                      grant, admit, spurn)

from .chaining import (Verdicts, EdgeVerdict, valid, invalid, unknown,
                       reduceAnd, reduceOr, reduce, MAryReducers)
from .evaluating import EdgeEvaluator, SchemaEvaluator

from .webregbasing import WebRegBaser

IS_PYODIDE = "emscripten" in sys.platform

if not IS_PYODIDE:
    from .regbasing import RegBaser
    from .registering import RegistryStore, openRegistry
    from .registraring import Regery, Registry, Registrar
