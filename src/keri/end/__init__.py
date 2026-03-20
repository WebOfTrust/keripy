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
                     OOBI_RE, DOOBI_RE, Mimes, KeriMimes)
