# -*- encoding: utf-8 -*-
"""
keri.kli.commands.import module

Expose `kli import` while keeping the implementation in import_.py.
"""

from keri.app.cli.commands import import_

parser = import_.importParser
