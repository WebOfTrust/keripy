import argparse

from hio.base import doing

from keri import kering
from keri.app import configing
from keri.app.cli.common import existing

parser = argparse.ArgumentParser(description='List set of watchers for this environment (Habitat)')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument("--config-dir", "-c", help="directory override for configuration data", default=None)

def handler(args):
    kwa = dict(args=args)
    return [doing.doify(listWatchers, **kwa)]


def listWatchers(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    config_dir = args.config_dir
    alias = args.alias

    cf = None
    if config_dir is not None:
        cf = configing.Configer(name=name,
                                base=base,
                                headDirPath=config_dir,
                                temp=False,
                                reopen=True,
                                clear=False)

    try:
        with existing.existingHab(name=name, base=base, cf=cf, alias=alias) as hab:
            habr = hab.db.habs.get(name)
            print("Watcher Set:")
            for wat in habr.watchers:
                print("\t{}".format(wat))

    except kering.ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

