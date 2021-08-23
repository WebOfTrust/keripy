import argparse

from keri import kering
from keri.app import habbing

parser = argparse.ArgumentParser(description='List set of watchers for this environment (Habitat)')
parser.set_defaults(handler=lambda args: listWatchers(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)


def listWatchers(args):
    name = args.name

    try:
        with habbing.existingHab(name=name) as hab:
            habr = hab.db.habs.get(name)
            print("Watcher Set:")
            for wat in habr.watchers:
                print("\t{}".format(wat))

    except kering.ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1

