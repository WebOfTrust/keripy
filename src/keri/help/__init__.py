# -*- encoding: utf-8 -*-
"""
KERI
keri.help package

utility functions

"""
# Setup module global ogler as package logger factory. This must be done on
#  import to ensure global is defined so all modules in package have access to
#  logggers via ogling.ogler.getLoggers(). May always change level and reopen log file
#  if need be

from hio.help import ogling

#  want help.ogler always defined by default
ogler = ogling.initOgler(prefix='keri', syslogged=False)  # inits once only on first import

from .helping import (nowIso8601, toIso8601, fromIso8601,
                      nonStringSequence, nonStringIterable)
