# -*- encoding: utf-8 -*-
"""
KERI
keri.help package

utility functions

"""
# Setup module global oglery as package logger factory. This must be done on
#  import to ensure global is defined so all modules in package have access to
#  logggers via ogling.oglery.getLoggers(). May always change level and reopen log file
#  if need be

from . import ogling

ogling.initOglery()  # inits once on import so ogling.oglery always defined by default
