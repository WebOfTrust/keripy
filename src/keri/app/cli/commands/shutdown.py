# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import os
import signal

import daemonocle
from hio import help

from keri.app.cli.commands.init import KLIRecord
from keri.db import koming, basing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Terminate the KLI server process')
parser.set_defaults(handler=lambda args: handle())


def handle():
    db = basing.Baser(name='kli-serving', temp=False)
    klis = koming.Komer(db=db, schema=KLIRecord, subkey='klis.')
    klis.rem(('kli-serving',))

    daemon = daemonocle.Daemon(
        pid_file='/tmp/klid.pid',
    )
    daemon.do_action('stop')


def __bye():
    logger.info("Byee!")
