# -*- encoding: utf-8 -*-
"""
KERI
keri.end package

ReST endpoints

"""

from .ending import (Signage, Inputage, signature,
                     designature, normalize, siginput,
                     desiginput, PointEnd, LocationEnd,
                     AdminEnd, OOBIEnd, loadEndingEnds, setup,
                     OOBI_RE, DOOBI_RE, Mimes, KeriMimes,
                     WOOBI_RE, OOBI_AID_HEADER)
from .priming import parseArgs
