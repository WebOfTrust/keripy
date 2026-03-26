# -*- encoding: utf-8 -*-
"""
KERI
keri.end package
ReST endpoints
"""

def __getattr__(name):
    _ending = {
        'Signage', 'Inputage', 'signature', 'designature', 'normalize',
        'siginput', 'desiginput', 'PointEnd', 'LocationEnd', 'AdminEnd',
        'OOBIEnd', 'loadEndingEnds', 'setup', 'OOBI_RE', 'DOOBI_RE',
        'Mimes', 'KeriMimes', 'WOOBI_RE', 'OOBI_AID_HEADER',
    }
    _priming = {'parseArgs'}

    if name in _ending:
        from . import ending
        return getattr(ending, name)
    if name in _priming:
        from . import priming
        return getattr(priming, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
