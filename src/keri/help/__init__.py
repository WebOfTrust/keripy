# -*- encoding: utf-8 -*-
"""
KERI
keri.help package

utility functions

"""
import logging

# Setup module global ogler as package logger factory. This must be done on
#  import to ensure global is defined so all modules in package have access to
#  logggers via ogling.ogler.getLoggers(). May always change level and reopen log file
#  if need be

from hio.help import ogling

# Custom TRACE log level configuration
TRACE = 5              # TRACE (5) logging level value between DEBUG (10) and NOTSET (0)
logging.TRACE = TRACE  # add TRACE logging level to logging module
logging.addLevelName(logging.TRACE, "TRACE")
def trace(self, message, *args, **kwargs):
    """Trace logging function - logs message if TRACE (5) level enabled"""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)
logging.Logger.trace = trace

#  want help.ogler always defined by default
ogler = ogling.initOgler(prefix='keri', syslogged=False)  # inits once only on first import

from .helping import (nowIso8601, toIso8601, fromIso8601,
                      NonStringSequence, NonStringIterable,
                      isNonStringSequence, isNonStringIterable,
                      Reb64, Reatt, Repath)
