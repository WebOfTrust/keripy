# -*- encoding: utf-8 -*-
"""
keri.kli.commands.vc.schema.import module

Expose `kli vc schema import` while keeping the implementation in import_.py.
"""

from keri.app.cli.commands.vc.schema import import_

parser = import_.importParser
