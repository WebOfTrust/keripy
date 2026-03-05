# -*- encoding: utf-8 -*-
"""
KERI
keri.app.cli.commands.escrow Package

"""

import argparse

from .clear import clear
from .list import escrows



parser = argparse.ArgumentParser(description="A collection of escrow operations")