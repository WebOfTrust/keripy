import argparse

from hio.base import doing

from keri import kering
from keri.app.cli.common import existing

parser = argparse.ArgumentParser(description='List set of watchers for this environment (Habitat)')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(listWatchers, **kwa)]


def listWatchers(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias

    try:
        with existing.existingHab(name=name, alias=alias) as hab:
            habr = hab.db.habs.get(name)
            print("Watcher Set:")
            for wat in habr.watchers:
                print("\t{}".format(wat))

    except kering.ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

