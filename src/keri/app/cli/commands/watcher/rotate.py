# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
import argparse

from hio.base import doing

from keri import help
from keri.app import watching, configing
from keri.app.cli.common import existing

parser = argparse.ArgumentParser(description='Rotate watcher prefix')
parser.set_defaults(handler=lambda args: rotateWatcher(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument("--watcher", "-w", help="QB64 identifier prefix of watcher to rotate", default="", required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument("--config-dir", "-c", help="directory override for configuration data", default=None)

logger = help.ogler.getLogger()


def rotateWatcher(args):
    name = args.name
    wat = args.watcher
    base = args.base
    config_dir = args.config_dir

    watr = WatcherRotate(name=name, wat=wat, base=base, config_dir=config_dir)
    return [watr]


class WatcherRotate(doing.DoDoer):

    def __init__(self, name, wat, base, config_dir, **kwa):
        self.watcher = wat
        cf = None
        if config_dir is not None:
            cf = configing.Configer(name=name,
                                    base=base,
                                    headDirPath=config_dir,
                                    temp=False,
                                    reopen=True,
                                    clear=False)
        self.hab, doers = existing.setupHby(name=name, base=base, cf=cf)
        self.rotr = watching.WatcherClientRotateDoer(hab=self.hab)
        doers.extend([self.rotr])
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.rotateDo)])

        super(WatcherRotate, self).__init__(doers=doers, **kwa)


    def rotateDo(self, tymth, tock=0.0, **opts):
        # enter context
        yield self.tock

        self.rotr.msgs.append(self.watcher)

        while not self.rotr.cues:
            yield self.tock

        habr = self.hab.db.habs.get(self.hab.name)
        print("New Watcher Set:")
        for wat in habr.watchers:
            print("\t{}".format(wat))

        self.remove(self.toRemove)
